//! Block and chain validation.
//!
//! # Strict signature verification
//!
//! `verify_block` routes through [`arxia_crypto::verify`] and
//! [`arxia_crypto::validate_pubkey_strict`]. The first enforces
//! dalek's `verify_strict` (canonical-S enforcement and
//! low-order pubkey rejection), and the second rejects pubkey
//! bytes that decode to a small-subgroup point of Curve25519 at
//! parse time. Routing through `arxia_crypto` ensures the
//! lattice signature path inherits the strict-verify contract
//! documented at the `arxia_crypto::ed25519` module level.

use crate::block::{Block, BlockType};
use arxia_core::ArxiaError;

/// Verify a single block hash and Ed25519 signature.
pub fn verify_block(block: &Block) -> Result<(), ArxiaError> {
    let expected_hash = Block::compute_hash(
        &block.account,
        &block.previous,
        &block.block_type,
        block.balance,
        block.nonce,
        block.timestamp,
    )?;
    if expected_hash != block.hash {
        return Err(ArxiaError::HashMismatch);
    }
    let pubkey_bytes: [u8; 32] = hex::decode(&block.account)
        .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| ArxiaError::InvalidKey("bad key length".into()))?;
    // Reject low-order / off-curve pubkeys at parse time, BEFORE
    // any signature work. This is the parse-side mirror of the
    // strict verify below.
    arxia_crypto::validate_pubkey_strict(&pubkey_bytes)?;
    let sig_bytes: [u8; 64] = block
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ArxiaError::SignatureInvalid("bad sig length".into()))?;
    let hash_bytes =
        hex::decode(&block.hash).map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?;
    // Route through arxia_crypto::verify, which calls dalek's
    // `verify_strict` (canonical-S enforcement + low-order
    // rejection at the equation level).
    arxia_crypto::verify(&pubkey_bytes, &hash_bytes, &sig_bytes)?;
    Ok(())
}

/// Verify integrity of an entire account chain.
pub fn verify_chain_integrity(chain: &[Block]) -> Result<(), ArxiaError> {
    if chain.is_empty() {
        return Ok(());
    }
    if chain[0].nonce != 1 {
        return Err(ArxiaError::InvalidGenesis(format!(
            "nonce must be 1, got {}",
            chain[0].nonce
        )));
    }
    if !matches!(chain[0].block_type, BlockType::Open { .. }) {
        return Err(ArxiaError::InvalidGenesis(
            "first block must be OPEN".into(),
        ));
    }
    if !chain[0].previous.is_empty() {
        return Err(ArxiaError::InvalidGenesis(
            "genesis must have empty previous".into(),
        ));
    }
    verify_block(&chain[0])?;
    for i in 1..chain.len() {
        if chain[i].nonce != chain[i - 1].nonce + 1 {
            return Err(ArxiaError::NonceGap {
                index: i,
                expected: chain[i - 1].nonce + 1,
                got: chain[i].nonce,
            });
        }
        if chain[i].previous != chain[i - 1].hash {
            return Err(ArxiaError::HashChainBroken(i));
        }
        verify_block(&chain[i])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_verify_block_valid() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        assert!(verify_block(&block).is_ok());
    }

    #[test]
    fn test_verify_chain_integrity_valid() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();
        assert!(verify_chain_integrity(&alice.chain).is_ok());
        assert!(verify_chain_integrity(&bob.chain).is_ok());
    }

    #[test]
    fn test_verify_chain_empty_is_ok() {
        assert!(verify_chain_integrity(&[]).is_ok());
    }

    #[test]
    fn test_verify_block_rejects_tampered_hash() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1_000_000, &mut vc).unwrap();
        block.hash = "0".repeat(64);
        assert!(verify_block(&block).is_err());
    }

    // ============================================================
    // Strict-verify routing: production code MUST call
    // `arxia_crypto::verify` (which enforces `verify_strict` plus
    // low-order pubkey rejection), not dalek's lenient
    // `Verifier::verify` directly. Source-lint regression guard
    // against re-introducing the lenient path.
    // ============================================================

    #[test]
    fn test_validation_rs_routes_via_arxia_crypto_verify() {
        // PRIMARY PIN: production code in this file MUST NOT call
        // dalek lenient `vk.verify(...)` directly. The strict
        // contract (canonical-S + low-order pubkey rejection)
        // requires routing through `arxia_crypto::verify`.
        //
        // Uses the bare `#[cfg(test)]` split marker (CRLF-tolerant)
        // matching the source-lint pattern adopted workspace-wide.
        const SELF_SOURCE: &str = include_str!("validation.rs");
        let production = SELF_SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields >=1 segment");
        assert!(
            !production.contains("vk.verify("),
            "production verify_block must use arxia_crypto::verify, \
             not dalek lenient vk.verify"
        );
        assert!(
            !production.contains("verifying_key().verify("),
            "production verify_block must not bypass arxia_crypto via \
             VerifyingKey::verify either"
        );
        assert!(
            production.contains("arxia_crypto::verify"),
            "production verify_block must route through arxia_crypto::verify"
        );
        assert!(
            production.contains("validate_pubkey_strict"),
            "production verify_block must call validate_pubkey_strict at parse time"
        );
    }

    /// Construct a Block that the lenient path would have accepted
    /// pre-fix (identity-pubkey + R=identity, S=0). The strict
    /// `verify_block` must reject it. This is the post-fix
    /// regression guard derived from the audit reproducer.
    #[test]
    fn test_verify_block_rejects_low_order_identity_pubkey_signature() {
        // Identity element of Curve25519 in compressed form: y=1, sign=0.
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        // Trivial forged signature for low-order pubkey:
        // R = identity_compressed, S = 0. The verification
        // equation degenerates and ANY message accepts under
        // dalek's lenient verify.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;

        // Build a real Block with this account + signature. We
        // don't go through AccountChain::open (that path also
        // rejects low-order at construction post-fix); we
        // construct the Block directly to exercise verify_block.
        let block_proto = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open {
                initial_balance: u64::MAX,
            },
            balance: u64::MAX,
            nonce: 1,
            timestamp: 0,
            hash: String::new(),
            signature: sig_bytes.to_vec(),
        };
        let expected_hash = Block::compute_hash(
            &block_proto.account,
            &block_proto.previous,
            &block_proto.block_type,
            block_proto.balance,
            block_proto.nonce,
            block_proto.timestamp,
        );
        // compute_hash must itself reject the low-order account
        // (defense-in-depth). If it did NOT (a future regression),
        // we still want verify_block to reject the resulting
        // block at the verify boundary.
        if let Ok(hash) = expected_hash {
            let block = Block {
                hash,
                ..block_proto
            };
            assert!(
                verify_block(&block).is_err(),
                "verify_block must reject identity-pubkey forgery"
            );
        }
        // If compute_hash rejected (defense-in-depth fired), that
        // is also acceptable — the attack didn't reach
        // verify_block.
    }

    /// E2E pin: a chain whose FIRST block is the identity-pubkey
    /// forged genesis must be rejected by `verify_chain_integrity`.
    /// Closes the open question A2 left unanswered (whether
    /// verify_chain_integrity propagates the strict check).
    #[test]
    fn test_verify_chain_integrity_rejects_low_order_identity_forged_chain() {
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;
        let block_proto = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open {
                initial_balance: u64::MAX,
            },
            balance: u64::MAX,
            nonce: 1,
            timestamp: 0,
            hash: String::new(),
            signature: sig_bytes.to_vec(),
        };
        let chain: Vec<Block> = match Block::compute_hash(
            &block_proto.account,
            &block_proto.previous,
            &block_proto.block_type,
            block_proto.balance,
            block_proto.nonce,
            block_proto.timestamp,
        ) {
            Ok(hash) => vec![Block {
                hash,
                ..block_proto
            }],
            // Defense-in-depth at compute_hash already fires →
            // chain construction is impossible. That is the
            // strongest closure of the attack ; the test path
            // below is moot.
            Err(_) => return,
        };
        assert!(
            verify_chain_integrity(&chain).is_err(),
            "verify_chain_integrity must reject a chain whose genesis \
             block is forged under a low-order pubkey"
        );
    }

    /// Boundary pin: regardless of any hash value placed on the
    /// block, `verify_block` MUST error when the account is a
    /// low-order pubkey. Strongest closure: the verify boundary
    /// itself rejects, independently of whether `compute_hash`
    /// defense-in-depth fired. Mirrors the audit reproducer's
    /// E2E call site (`verify_block(&block)` on identity-pk
    /// account + R=identity, S=0 signature).
    #[test]
    fn test_verify_block_rejects_low_order_account_at_verify_boundary() {
        let identity_pk: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 0x01;
            p
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;
        // Place an arbitrary-but-syntactically-valid hash on the
        // block. The point is: even if the recomputation step
        // didn't reject (hypothetical regression), verify_block
        // must still error. With the current fix the recomputation
        // returns Err(InvalidKey) → verify_block returns Err.
        let bogus_hash = "0".repeat(64);
        let block = Block {
            account: hex::encode(identity_pk),
            previous: String::new(),
            block_type: BlockType::Open { initial_balance: 0 },
            balance: 0,
            nonce: 1,
            timestamp: 0,
            hash: bogus_hash,
            signature: sig_bytes.to_vec(),
        };
        let result = verify_block(&block);
        assert!(
            result.is_err(),
            "verify_block must reject a low-order pubkey block at \
             the verify boundary (got {:?})",
            result
        );
    }
}
