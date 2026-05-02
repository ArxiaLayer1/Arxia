//! Global ledger indexing all account chains.

use crate::block::{Block, BlockType};
use crate::validation::verify_block;
use arxia_core::ArxiaError;
use std::collections::HashMap;

/// Global ledger index of all account chains.
pub struct Ledger {
    /// Map from account hex public key to block list.
    pub chains: HashMap<String, Vec<Block>>,
}

impl Ledger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    /// Add a block to the ledger, after verifying its Ed25519 signature
    /// and recomputed Blake3 hash AND its position in the per-account
    /// chain (HIGH-003, closed in commit 031).
    ///
    /// The chain-continuity check enforces incrementally what
    /// [`crate::validation::verify_chain_integrity`] enforces post-hoc:
    ///
    /// - On an empty chain (genesis): the block MUST be
    ///   [`BlockType::Open`], MUST have `nonce == 1`, and MUST have
    ///   an empty `previous` field. Otherwise
    ///   [`ArxiaError::NonceGap`] (for the nonce mismatch) or
    ///   [`ArxiaError::InvalidGenesis`] (for the variant / previous).
    /// - On a non-empty chain: the block MUST have
    ///   `nonce == last.nonce + 1` (otherwise
    ///   [`ArxiaError::NonceGap`]) and `previous == last.hash`
    ///   (otherwise [`ArxiaError::HashChainBroken`]).
    ///
    /// The check fires BEFORE the chain is mutated, so a rejected
    /// block leaves the per-account chain exactly as it was. Pinned
    /// by `test_add_block_chain_state_unchanged_on_rejection`.
    ///
    /// # Errors
    ///
    /// In addition to the [`verify_block`] errors:
    /// - [`ArxiaError::HashMismatch`] if the stored hash does not match.
    /// - [`ArxiaError::SignatureInvalid`] if the signature does not verify
    ///   against the account public key.
    /// - [`ArxiaError::InvalidKey`] if the account hex is not a valid
    ///   Ed25519 public key.
    ///
    /// the chain-continuity check may also return:
    /// - [`ArxiaError::NonceGap`] — `nonce` is not the expected value.
    /// - [`ArxiaError::HashChainBroken`] — `previous` does not match
    ///   the last block's hash.
    /// - [`ArxiaError::InvalidGenesis`] — the first block of an account
    ///   is not a valid OPEN with `previous == ""`.
    pub fn add_block(&mut self, block: Block) -> Result<(), ArxiaError> {
        verify_block(&block)?;

        let chain = self.chains.entry(block.account.clone()).or_default();

        // HIGH-003 (commit 031): incremental chain-continuity check.
        // Mirrors `verify_chain_integrity` but per-block, so the ledger
        // never accepts orphan blocks or parallel history within one
        // chain.
        if let Some(last) = chain.last() {
            let expected_nonce = last.nonce + 1;
            if block.nonce != expected_nonce {
                return Err(ArxiaError::NonceGap {
                    index: chain.len(),
                    expected: expected_nonce,
                    got: block.nonce,
                });
            }
            if block.previous != last.hash {
                return Err(ArxiaError::HashChainBroken(chain.len()));
            }
        } else {
            // Genesis block requirements.
            if block.nonce != 1 {
                return Err(ArxiaError::NonceGap {
                    index: 0,
                    expected: 1,
                    got: block.nonce,
                });
            }
            if !matches!(block.block_type, BlockType::Open { .. }) {
                return Err(ArxiaError::InvalidGenesis(
                    "first block must be OPEN".into(),
                ));
            }
            if !block.previous.is_empty() {
                return Err(ArxiaError::InvalidGenesis(
                    "genesis must have empty previous".into(),
                ));
            }
        }

        chain.push(block);
        Ok(())
    }

    /// Get the chain for a specific account.
    pub fn get_chain(&self, account: &str) -> Option<&Vec<Block>> {
        self.chains.get(account)
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_add_block_accepts_signed_block() {
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let block = alice.open(1_000_000, &mut vc).unwrap();
        assert!(ledger.add_block(block).is_ok());
        assert!(ledger.get_chain(alice.id()).is_some());
    }

    #[test]
    fn test_add_block_rejects_tampered_hash() {
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
        block.hash = "0".repeat(64);
        let result = ledger.add_block(block);
        assert!(matches!(result, Err(ArxiaError::HashMismatch)));
        assert!(ledger.get_chain(alice.id()).is_none());
    }

    #[test]
    fn test_add_block_rejects_tampered_signature() {
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
        block.signature[0] ^= 0xFF;
        let result = ledger.add_block(block);
        assert!(
            matches!(result, Err(ArxiaError::SignatureInvalid(_))),
            "expected SignatureInvalid, got {:?}",
            result
        );
        assert!(ledger.get_chain(alice.id()).is_none());
    }

    #[test]
    fn test_add_block_rejects_wrong_signer() {
        // Block signed by Alice's key but with Bob's pubkey recorded as account.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
        block.account = bob.id().to_string();
        // The hash now no longer matches the account field baked into the
        // Blake3 input, so verify_block catches it on HashMismatch first.
        let result = ledger.add_block(block);
        assert!(
            matches!(
                result,
                Err(ArxiaError::HashMismatch)
                    | Err(ArxiaError::SignatureInvalid(_))
                    | Err(ArxiaError::InvalidKey(_))
            ),
            "expected verification failure, got {:?}",
            result
        );
        assert!(ledger.get_chain(bob.id()).is_none());
    }

    #[test]
    fn test_add_block_rejects_zero_signature() {
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
        block.signature = vec![0u8; 64];
        let result = ledger.add_block(block);
        assert!(matches!(result, Err(ArxiaError::SignatureInvalid(_))));
        assert!(ledger.get_chain(alice.id()).is_none());
    }

    // ========================================================================
    // Adversarial tests for HIGH-003 (ledger chain-continuity)
    //
    // `Ledger::add_block` must enforce per-block chain continuity:
    //   - genesis: nonce==1, OPEN variant, previous==""
    //   - subsequent: nonce==last.nonce+1, previous==last.hash
    // Mirrors `verify_chain_integrity` but per-block. Without these
    // checks, the ledger accepts orphan blocks and parallel history
    // within a single account chain.
    // ========================================================================

    use crate::block::BlockType;
    use ed25519_dalek::Signer;

    /// Forge a block with arbitrary `previous` while keeping the
    /// signature / hash valid (so `verify_block` passes — the
    /// adversarial scenario is "attacker holds the signing key and
    /// produces a block whose `previous` doesn't extend the
    /// honest chain").
    fn forge_block_with_previous(
        alice: &AccountChain,
        previous: String,
        nonce: u64,
        balance: u64,
        block_type: BlockType,
    ) -> Block {
        let timestamp = arxia_core::now_millis();
        let hash = Block::compute_hash(
            alice.id(),
            &previous,
            &block_type,
            balance,
            nonce,
            timestamp,
        )
        .expect("test helper: canonical BlockType always serializes");
        let hash_bytes = hex::decode(&hash).expect("valid hex hash");
        let signature = alice.signing_key().sign(&hash_bytes);
        Block {
            account: alice.id().to_string(),
            previous,
            block_type,
            balance,
            nonce,
            timestamp,
            hash,
            signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn test_add_block_rejects_nonce_gap() {
        // Chain has [open@1, send@2]. Attacker submits a block at
        // nonce=5 (gap of 2 missing). Ledger must reject with
        // NonceGap and leave the chain unchanged.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let open = alice.open(1_000_000, &mut vc).unwrap();
        let send2 = alice.send(bob.id(), 100, &mut vc).unwrap();
        ledger.add_block(open).unwrap();
        ledger.add_block(send2.clone()).unwrap();

        // Forge a block at nonce=5 with valid signature/hash but
        // wrong nonce (the chain has length 2; expected next nonce
        // is 3).
        let forged = forge_block_with_previous(
            &alice,
            send2.hash.clone(),
            5,
            alice.balance - 100,
            BlockType::Send {
                destination: bob.id().to_string(),
                amount: 100,
            },
        );
        let result = ledger.add_block(forged);
        assert!(
            matches!(
                result,
                Err(ArxiaError::NonceGap {
                    expected: 3,
                    got: 5,
                    ..
                })
            ),
            "expected NonceGap{{expected:3, got:5}}, got {:?}",
            result
        );
        assert_eq!(
            ledger.get_chain(alice.id()).unwrap().len(),
            2,
            "chain must not have grown"
        );
    }

    #[test]
    fn test_add_block_rejects_prev_mismatch() {
        // Chain has [open@1, send@2]. Attacker forges a block at
        // nonce=3 with valid hash/signature but wrong `previous`
        // (not equal to send@2.hash). Ledger must reject with
        // HashChainBroken.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let open = alice.open(1_000_000, &mut vc).unwrap();
        let send2 = alice.send(bob.id(), 100, &mut vc).unwrap();
        ledger.add_block(open).unwrap();
        ledger.add_block(send2.clone()).unwrap();

        let wrong_prev = "ab".repeat(32); // 64 hex chars, not send2.hash
        assert_ne!(wrong_prev, send2.hash);

        let forged = forge_block_with_previous(
            &alice,
            wrong_prev,
            3,
            alice.balance - 50,
            BlockType::Send {
                destination: bob.id().to_string(),
                amount: 50,
            },
        );
        let result = ledger.add_block(forged);
        assert!(
            matches!(result, Err(ArxiaError::HashChainBroken(2))),
            "expected HashChainBroken(2), got {:?}",
            result
        );
        assert_eq!(ledger.get_chain(alice.id()).unwrap().len(), 2);
    }

    #[test]
    fn test_add_block_rejects_duplicate_nonce_with_different_hash() {
        // Chain has [open@1, send@2]. Attacker tries to add a SECOND
        // block also at nonce=2 (a forked SEND with a different
        // destination, hence different hash). Strict monotonicity
        // catches this as NonceGap (expected=3, got=2).
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let open = alice.open(1_000_000, &mut vc).unwrap();
        let send_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        ledger.add_block(open.clone()).unwrap();
        ledger.add_block(send_bob.clone()).unwrap();

        // Rewind alice's local state and produce a competing SEND to
        // carol (also nonce=2, previous=open.hash, different hash).
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let send_carol = alice.send(carol.id(), 100, &mut vc).unwrap();
        assert_eq!(send_carol.nonce, send_bob.nonce);
        assert_ne!(send_carol.hash, send_bob.hash);

        let result = ledger.add_block(send_carol);
        assert!(
            matches!(
                result,
                Err(ArxiaError::NonceGap {
                    expected: 3,
                    got: 2,
                    ..
                })
            ),
            "expected NonceGap{{expected:3, got:2}}, got {:?}",
            result
        );
        assert_eq!(ledger.get_chain(alice.id()).unwrap().len(), 2);
    }

    #[test]
    fn test_add_block_rejects_genesis_with_send_block() {
        // Empty chain + first block is a SEND (not OPEN). Must reject
        // with InvalidGenesis. The nonce check fires AFTER the
        // OPEN-variant check would normally catch this — but the
        // check order is `nonce-then-variant`, so a SEND with
        // nonce=1 fails on the variant check.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        // Build alice with [open, send], then take just the SEND
        // and feed it to a fresh ledger as if it were the first block.
        alice.open(1_000_000, &mut vc).unwrap();
        let send2 = alice.send(bob.id(), 100, &mut vc).unwrap();
        // Forge a "send" block with nonce=1 and previous="" so the
        // nonce / previous parts pass; the variant check should
        // catch it.
        let forged_send_genesis = forge_block_with_previous(
            &AccountChain::new(), // throw-away alice for forging context
            String::new(),
            1,
            send2.balance,
            BlockType::Send {
                destination: bob.id().to_string(),
                amount: 100,
            },
        );
        let result = ledger.add_block(forged_send_genesis);
        assert!(
            matches!(result, Err(ArxiaError::InvalidGenesis(_))),
            "expected InvalidGenesis (variant check), got {:?}",
            result
        );
    }

    #[test]
    fn test_add_block_rejects_genesis_with_nonce_other_than_1() {
        // Empty chain + OPEN block but nonce=5. Must reject with
        // NonceGap (expected=1, got=5) — the nonce check fires before
        // the variant check.
        let mut ledger = Ledger::new();
        let alice = AccountChain::new();
        let forged_high_nonce_open = forge_block_with_previous(
            &alice,
            String::new(),
            5,
            1_000_000,
            BlockType::Open {
                initial_balance: 1_000_000,
            },
        );
        let result = ledger.add_block(forged_high_nonce_open);
        assert!(
            matches!(
                result,
                Err(ArxiaError::NonceGap {
                    expected: 1,
                    got: 5,
                    ..
                })
            ),
            "expected NonceGap{{expected:1, got:5}}, got {:?}",
            result
        );
    }

    #[test]
    fn test_add_block_accepts_valid_chain_extension() {
        // Regression guard: the happy path (open@1 → send@2 → send@3)
        // continues to work after the new checks land.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let open = alice.open(1_000_000, &mut vc).unwrap();
        let send2 = alice.send(bob.id(), 100, &mut vc).unwrap();
        let send3 = alice.send(bob.id(), 200, &mut vc).unwrap();
        ledger.add_block(open).expect("genesis ok");
        ledger.add_block(send2).expect("send@2 ok");
        ledger.add_block(send3).expect("send@3 ok");
        assert_eq!(ledger.get_chain(alice.id()).unwrap().len(), 3);
    }

    #[test]
    fn test_add_block_chain_state_unchanged_on_rejection() {
        // Pin the no-state-mutation invariant: a rejected block leaves
        // the per-account chain bit-identical to the pre-call state.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let open = alice.open(1_000_000, &mut vc).unwrap();
        let send2 = alice.send(bob.id(), 100, &mut vc).unwrap();
        ledger.add_block(open).unwrap();
        ledger.add_block(send2.clone()).unwrap();

        let chain_before: Vec<Block> = ledger.get_chain(alice.id()).unwrap().clone();
        let chain_len_before = chain_before.len();
        let last_hash_before = chain_before.last().unwrap().hash.clone();

        // Try several pathological inputs.
        let _ = ledger.add_block(forge_block_with_previous(
            &alice,
            "00".repeat(32),
            3,
            alice.balance - 50,
            BlockType::Send {
                destination: bob.id().to_string(),
                amount: 50,
            },
        )); // HashChainBroken — wrong prev

        let _ = ledger.add_block(forge_block_with_previous(
            &alice,
            send2.hash.clone(),
            99,
            alice.balance - 50,
            BlockType::Send {
                destination: bob.id().to_string(),
                amount: 50,
            },
        )); // NonceGap — wrong nonce

        let chain_after = ledger.get_chain(alice.id()).unwrap();
        assert_eq!(chain_after.len(), chain_len_before);
        assert_eq!(chain_after.last().unwrap().hash, last_hash_before);
    }
}
