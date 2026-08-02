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
use arxia_core::{ArxiaError, GenesisRule, KeyFault, SignatureFault};

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
        .map_err(|_| ArxiaError::InvalidKey {
            fault: KeyFault::HexEncoding,
        })?
        .try_into()
        .map_err(|v: Vec<u8>| ArxiaError::InvalidKey {
            fault: KeyFault::Length { got: v.len() },
        })?;
    // Reject low-order / off-curve pubkeys at parse time, BEFORE
    // any signature work. This is the parse-side mirror of the
    // strict verify below.
    arxia_crypto::validate_pubkey_strict(&pubkey_bytes)?;
    let sig_bytes: [u8; 64] =
        block
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ArxiaError::SignatureInvalid {
                fault: SignatureFault::Length {
                    got: block.signature.len(),
                },
            })?;
    let hash_bytes = hex::decode(&block.hash).map_err(|_| ArxiaError::SignatureInvalid {
        fault: SignatureFault::HashEncoding,
    })?;
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
        return Err(ArxiaError::InvalidGenesis {
            rule: GenesisRule::NonceMustBeOne {
                got: chain[0].nonce,
            },
        });
    }
    if !matches!(chain[0].block_type, BlockType::Open { .. }) {
        return Err(ArxiaError::InvalidGenesis {
            rule: GenesisRule::FirstBlockMustBeOpen,
        });
    }
    if !chain[0].previous.is_empty() {
        return Err(ArxiaError::InvalidGenesis {
            rule: GenesisRule::PreviousMustBeEmpty,
        });
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
        // Trait-method form bypass guard: a code-toucher could
        // import `Verifier` and call `Verifier::verify(&vk, ...)`
        // or `<VerifyingKey as Verifier>::verify(&vk, ...)`. The
        // earlier two checks would not match this form, so they
        // are extended here.
        assert!(
            !production.contains("Verifier::verify("),
            "production verify_block must not call Verifier::verify directly"
        );
        assert!(
            !production.contains("as Verifier>::verify"),
            "production verify_block must not call <VerifyingKey as Verifier>::verify"
        );
        // Aliased import bypass guard: forbid bringing dalek's
        // `Verifier` trait into scope at all in production.
        assert!(
            !production.contains("ed25519_dalek::Verifier"),
            "production verify_block must not import ed25519_dalek::Verifier; \
             route through arxia_crypto::verify instead"
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

    /// R3 of the typed-error rework: three different genesis
    /// violations must surface as three distinct `GenesisRule`
    /// discriminants. A change that merges two rules into one — or
    /// flattens them back into prose — fails one of these asserts;
    /// that falsifiability is the point, because downstream peer
    /// scoring will route on the discriminant.
    ///
    /// Field tampering is deliberate and sufficient here: the genesis
    /// rules fire before any signature check, which is itself part of
    /// the contract (a malformed genesis is reported as such, not as
    /// a signature failure).
    #[test]
    fn each_genesis_violation_has_its_own_discriminant() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 1_000, &mut vc).unwrap();

        // Cause 1: first block's nonce is not 1.
        let mut tampered = alice.chain.clone();
        tampered[0].nonce = 2;
        assert!(matches!(
            verify_chain_integrity(&tampered),
            Err(ArxiaError::InvalidGenesis {
                rule: GenesisRule::NonceMustBeOne { got: 2 }
            })
        ));

        // Cause 2: first block is a Send (nonce forced to 1 so the
        // nonce rule cannot mask the type rule).
        let mut not_open = send.clone();
        not_open.nonce = 1;
        assert!(matches!(
            verify_chain_integrity(&[not_open]),
            Err(ArxiaError::InvalidGenesis {
                rule: GenesisRule::FirstBlockMustBeOpen
            })
        ));

        // Cause 3: genesis with a non-empty previous.
        let mut bad_prev = alice.chain[0].clone();
        bad_prev.previous = "deadbeef".to_string();
        assert!(matches!(
            verify_chain_integrity(&[bad_prev]),
            Err(ArxiaError::InvalidGenesis {
                rule: GenesisRule::PreviousMustBeEmpty
            })
        ));
    }

    /// R3 of the typed-error rework, signature family: a structural
    /// failure (wrong length, unparseable hash) and the cryptographic
    /// failure (equation does not hold) are different adversarial
    /// signals, and each must surface under its own discriminant.
    /// A change collapsing them fails one of these asserts.
    #[test]
    fn each_signature_failure_has_its_own_discriminant() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();

        // Cause 1: signature of the wrong length — structurally
        // malformed, never reaches the verify equation.
        let mut short_sig = chain.chain[0].clone();
        short_sig.signature = vec![0xAA; 63];
        assert!(matches!(
            verify_block(&short_sig),
            Err(ArxiaError::SignatureInvalid {
                fault: SignatureFault::Length { got: 63 }
            })
        ));

        // A tampered hash cannot reach the HashEncoding path: the
        // recompute-and-compare fires first, and the recomputed hash
        // is always valid hex, so a block that passes the mismatch
        // check has a decodable hash by construction. HashEncoding is
        // therefore defense-in-depth on the decode that follows —
        // asserted here so the day the check order changes, this
        // stops being true loudly rather than silently.
        let mut bad_hash = chain.chain[0].clone();
        bad_hash.hash = "zzzz-not-hex".to_string();
        assert!(matches!(
            verify_block(&bad_hash),
            Err(ArxiaError::HashMismatch)
        ));

        // Cause 3: well-formed 64-byte signature that simply does not
        // verify — the cryptographic failure.
        let mut forged = chain.chain[0].clone();
        forged.signature = vec![0x01; 64];
        assert!(matches!(
            verify_block(&forged),
            Err(ArxiaError::SignatureInvalid {
                fault: SignatureFault::Verification
            })
        ));
    }
}
