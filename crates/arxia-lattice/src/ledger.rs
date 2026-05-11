//! Global ledger indexing all account chains.
//!
//! # Global supply ceiling
//!
//! `Ledger` maintains `total_supply: u64`, the running sum of
//! `initial_balance` across every accepted `Open` block. `add_block`
//! refuses any `Open` whose `initial_balance` would push this sum
//! above [`arxia_core::TOTAL_SUPPLY_MICRO_ARX`]. The check fires
//! BEFORE chain-state mutation, so a rejected Open leaves
//! `total_supply` untouched.
//!
//! Send and Receive do not change the total supply (they are
//! conservation-preserving — Alice balance −amount, Bob balance
//! +amount nets to 0). Only Open mints. There is no current burn
//! path ; if one is added later it should decrement the
//! accumulator at the same boundary.
//!
//! Combined with the per-account ceiling
//! [`arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT`] enforced at
//! `AccountChain::open` and `AccountChain::receive`, the two caps
//! form a layered guard : the global cap bounds total supply
//! across all accounts, the per-account cap bounds concentration
//! within any single account.
//!
//! # Threading
//!
//! `Ledger` is single-threaded by design. The two ingest indices
//! (`send_index`, `consumed_sends`) are maintained inside
//! `add_block` as a sequential read-then-write pattern (existence
//! check → destination match → not-consumed check → insert) ; the
//! sequence is correct under exclusive `&mut self` access but is
//! NOT safe under concurrent `add_block` calls. Callers that share
//! a `Ledger` across threads must serialize access externally
//! (e.g. wrap in `Mutex`).
//!
//! # Receive referential integrity
//!
//! A `Receive` block carries a `source_hash` that is supposed to point
//! at the matching `Send` block on the sender's chain. Without an
//! integrity check at ingest time, a signed `Receive` citing any
//! 64-hex `source_hash` — including one that points at no real `Send`
//! anywhere in the lattice — would be accepted by `add_block`,
//! creating balance out of nothing.
//!
//! `add_block` enforces three conditions on every `Receive`, in
//! order :
//!
//! 1. the `source_hash` is the hash of an accepted `Send` block in
//!    the ledger (`UnknownSourceSend` if not) ;
//! 2. that `Send`'s `destination` equals the `Receive`'s `account`
//!    (`WrongDestination` if not) ;
//! 3. the `source_hash` has not already been consumed by another
//!    `Receive` anywhere in the lattice (`DuplicateReceive` if it
//!    has).
//!
//! The ledger maintains two indices to keep the check O(1) :
//! `send_index` maps `Send` block hashes to their `(destination,
//! amount)` pair ; `consumed_sends` is the set of `source_hash`es
//! already credited. Inserts to both indices happen only AFTER all
//! checks (referential + chain-continuity) have passed, so a
//! rejected block never pollutes them.

use crate::block::{Block, BlockType};
use crate::validation::verify_block;
use arxia_core::ArxiaError;
use std::collections::{HashMap, HashSet};

/// Compact summary of an accepted `Send` block, kept in
/// [`Ledger::send_index`] for O(1) lookup at `Receive` ingest time.
#[derive(Debug, Clone)]
struct SendInfo {
    destination: String,
    /// Reserved for the supply-accumulator follow-up (PHASE2-013-B).
    /// Kept here so the index has the data already at hand when the
    /// global cap check lands.
    #[allow(dead_code)]
    amount: u64,
}

/// Global ledger index of all account chains.
pub struct Ledger {
    /// Map from account hex public key to block list.
    pub chains: HashMap<String, Vec<Block>>,
    /// Index of all accepted `Send` block hashes → destination + amount.
    /// Maintained incrementally on every accepted `Send` so a `Receive`
    /// referential check is O(1).
    send_index: HashMap<String, SendInfo>,
    /// Set of `source_hash`es already credited by an accepted `Receive`
    /// somewhere in the lattice. The per-chain `AccountChain.consumed_sources`
    /// is local to each receiver ; this set is the cross-chain
    /// counterpart preventing the same `Send` from funding two
    /// different `Receive`s on different chains.
    consumed_sends: HashSet<String>,
    /// Running sum of `initial_balance` across every accepted
    /// `Open` block. Compared against
    /// [`arxia_core::TOTAL_SUPPLY_MICRO_ARX`] before each new Open
    /// is accepted, so the ledger refuses to mint past the
    /// protocol-wide ceiling. See module docstring.
    total_supply: u64,
}

impl Ledger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            send_index: HashMap::new(),
            consumed_sends: HashSet::new(),
            total_supply: 0,
        }
    }

    /// Read-only access to the running total supply (sum of every
    /// accepted Open's `initial_balance`).
    pub fn total_supply(&self) -> u64 {
        self.total_supply
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

        // Open blocks must not push the cumulative supply past the
        // protocol-wide ceiling. See module docstring (Global supply
        // ceiling). Checked here, before any chain mutation, so a
        // rejected Open leaves `total_supply` untouched.
        if let BlockType::Open { initial_balance } = &block.block_type {
            let projected = self.total_supply.checked_add(*initial_balance).ok_or(
                ArxiaError::SupplyCapExceeded {
                    requested: u64::MAX,
                    max: arxia_core::TOTAL_SUPPLY_MICRO_ARX,
                },
            )?;
            if projected > arxia_core::TOTAL_SUPPLY_MICRO_ARX {
                return Err(ArxiaError::SupplyCapExceeded {
                    requested: projected,
                    max: arxia_core::TOTAL_SUPPLY_MICRO_ARX,
                });
            }
        }

        // Receive blocks must reference an accepted Send block whose
        // destination matches this account and which has not already
        // been consumed elsewhere in the lattice. See module docstring.
        if let BlockType::Receive { source_hash } = &block.block_type {
            let send_info =
                self.send_index
                    .get(source_hash)
                    .ok_or_else(|| ArxiaError::UnknownSourceSend {
                        source_hash: source_hash.clone(),
                    })?;
            if send_info.destination != block.account {
                return Err(ArxiaError::WrongDestination);
            }
            if self.consumed_sends.contains(source_hash) {
                return Err(ArxiaError::DuplicateReceive {
                    source_hash: source_hash.clone(),
                });
            }
        }

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

        // Maintain the cross-chain indices. Both inserts happen after
        // every other check has passed, so a rejected block never
        // pollutes them.
        match &block.block_type {
            BlockType::Send {
                destination,
                amount,
            } => {
                self.send_index.insert(
                    block.hash.clone(),
                    SendInfo {
                        destination: destination.clone(),
                        amount: *amount,
                    },
                );
            }
            BlockType::Receive { source_hash } => {
                self.consumed_sends.insert(source_hash.clone());
            }
            BlockType::Open { initial_balance } => {
                // The cap check at the top of this function already
                // proved this addition cannot overflow nor exceed
                // TOTAL_SUPPLY_MICRO_ARX. `checked_add` here is
                // belt-and-braces.
                self.total_supply = self
                    .total_supply
                    .checked_add(*initial_balance)
                    .expect("total_supply addition pre-validated by cap check above");
            }
            BlockType::Revoke { .. } => {}
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
        let hash_bytes = hex::decode(&hash).expect("test helper: blake3 hex always decodes");
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

    // ========================================================================
    // Adversarial tests for the Receive referential-integrity check.
    //
    // `Ledger::add_block` must enforce that every accepted `Receive`
    // block points at a real `Send` whose destination matches the
    // receiver and which has not already been credited. Without these
    // checks, a signed `Receive` citing a fabricated source_hash mints
    // balance from nothing.
    // ========================================================================

    #[test]
    fn test_add_block_accepts_legitimate_send_then_receive() {
        // Happy path : alice opens, alice sends to bob, bob opens,
        // bob receives. Each block accepted in order. Pin against
        // any future regression that would over-tighten the new
        // referential check and reject legitimate flows.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();

        let alice_open = alice.open(1_000_000, &mut vc).unwrap();
        let bob_open = bob.open(0, &mut vc).unwrap();
        let alice_send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        let bob_receive = bob.receive(&alice_send, &mut vc).unwrap();

        ledger.add_block(alice_open).expect("alice open");
        ledger.add_block(bob_open).expect("bob open");
        ledger.add_block(alice_send).expect("alice send");
        ledger.add_block(bob_receive).expect("bob receive");

        assert_eq!(ledger.get_chain(alice.id()).unwrap().len(), 2);
        assert_eq!(ledger.get_chain(bob.id()).unwrap().len(), 2);
    }

    #[test]
    fn test_add_block_rejects_phantom_receive_no_matching_send() {
        // Bob opens his chain, then signs a Receive whose source_hash
        // is a fabricated 64-hex string corresponding to no real Send
        // anywhere in the lattice. Pre-fix this was accepted ; post-fix
        // the ledger rejects with UnknownSourceSend.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut bob = AccountChain::new();
        let bob_open = bob.open(0, &mut vc).unwrap();
        ledger.add_block(bob_open.clone()).unwrap();

        let phantom_source = "ff".repeat(32);
        let phantom_receive = forge_block_with_previous(
            &bob,
            bob_open.hash.clone(),
            2,
            1_000_000, // balance the attacker hopes to mint
            BlockType::Receive {
                source_hash: phantom_source.clone(),
            },
        );

        let result = ledger.add_block(phantom_receive);
        assert!(
            matches!(
                result,
                Err(ArxiaError::UnknownSourceSend { ref source_hash })
                    if source_hash == &phantom_source
            ),
            "expected UnknownSourceSend, got {:?}",
            result
        );
        // Bob's chain stays at length 1 (just the open).
        assert_eq!(ledger.get_chain(bob.id()).unwrap().len(), 1);
    }

    #[test]
    fn test_add_block_rejects_receive_with_wrong_destination() {
        // Alice sends to Bob ; Carol forges a Receive citing the
        // Send's hash. The Send's destination is Bob, not Carol —
        // post-fix the ledger rejects with WrongDestination.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let mut carol = AccountChain::new();

        let alice_open = alice.open(1_000_000, &mut vc).unwrap();
        let carol_open = carol.open(0, &mut vc).unwrap();
        let alice_send_to_bob = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        ledger.add_block(alice_open).unwrap();
        ledger.add_block(carol_open.clone()).unwrap();
        ledger.add_block(alice_send_to_bob.clone()).unwrap();

        // Carol forges a Receive with Alice's Send hash. The destination
        // recorded in the Send is Bob's pubkey ; Carol's pubkey doesn't
        // match.
        let stolen_receive = forge_block_with_previous(
            &carol,
            carol_open.hash.clone(),
            2,
            100_000,
            BlockType::Receive {
                source_hash: alice_send_to_bob.hash.clone(),
            },
        );

        let result = ledger.add_block(stolen_receive);
        assert!(
            matches!(result, Err(ArxiaError::WrongDestination)),
            "expected WrongDestination, got {:?}",
            result
        );
        // Carol's chain stays at length 1 ; the legitimate Send was
        // already credited and is still in the index awaiting Bob.
        assert_eq!(ledger.get_chain(carol.id()).unwrap().len(), 1);
    }

    #[test]
    fn test_add_block_rejects_double_receive_across_chains() {
        // Alice sends to Bob, Bob receives (legitimate). A second
        // chain (Eve, who happens to also have Bob's pubkey would
        // be impossible, so we forge a Receive on Bob's chain
        // again — same source_hash, different nonce). Post-fix the
        // ledger's cross-chain `consumed_sends` set rejects with
        // DuplicateReceive.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();

        let alice_open = alice.open(1_000_000, &mut vc).unwrap();
        let bob_open = bob.open(0, &mut vc).unwrap();
        let alice_send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        let bob_receive = bob.receive(&alice_send, &mut vc).unwrap();
        ledger.add_block(alice_open).unwrap();
        ledger.add_block(bob_open).unwrap();
        ledger.add_block(alice_send.clone()).unwrap();
        ledger.add_block(bob_receive.clone()).unwrap();

        // Forge a SECOND Receive on Bob's chain with the same
        // source_hash but a fabricated nonce / previous to bypass
        // chain continuity. (The cross-chain consumed_sends check
        // fires before chain continuity, so we use forge to give
        // it a syntactically valid block.)
        let double_receive = forge_block_with_previous(
            &bob,
            bob_receive.hash.clone(),
            3,
            bob.balance + 100_000,
            BlockType::Receive {
                source_hash: alice_send.hash.clone(),
            },
        );

        let result = ledger.add_block(double_receive);
        assert!(
            matches!(
                result,
                Err(ArxiaError::DuplicateReceive { ref source_hash })
                    if source_hash == &alice_send.hash
            ),
            "expected DuplicateReceive, got {:?}",
            result
        );
        // Bob's chain stays at length 2.
        assert_eq!(ledger.get_chain(bob.id()).unwrap().len(), 2);
    }

    // ========================================================================
    // Adversarial tests for the global supply accumulator.
    //
    // `Ledger::add_block` must refuse any `Open` whose `initial_balance`
    // would push the cumulative supply above
    // `arxia_core::TOTAL_SUPPLY_MICRO_ARX`. Send and Receive must NOT
    // affect the running total (they are conservation-preserving).
    // ========================================================================

    #[test]
    fn test_add_block_open_increments_total_supply() {
        // Each accepted Open adds its initial_balance to the running
        // total. Pin the accumulator's incremental behaviour.
        let mut ledger = Ledger::new();
        assert_eq!(ledger.total_supply(), 0);
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let alice_open = alice.open(1_000_000, &mut vc).unwrap();
        let bob_open = bob.open(2_500_000, &mut vc).unwrap();
        ledger.add_block(alice_open).unwrap();
        assert_eq!(ledger.total_supply(), 1_000_000);
        ledger.add_block(bob_open).unwrap();
        assert_eq!(ledger.total_supply(), 3_500_000);
    }

    #[test]
    fn test_add_block_send_and_receive_leave_total_supply_unchanged() {
        // Send and Receive are conservation-preserving (Alice
        // -amount, Bob +amount nets to zero). Only Open mints.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let alice_open = alice.open(1_000_000, &mut vc).unwrap();
        let bob_open = bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        let recv = bob.receive(&send, &mut vc).unwrap();
        ledger.add_block(alice_open).unwrap();
        ledger.add_block(bob_open).unwrap();
        let supply_before = ledger.total_supply();
        ledger.add_block(send).unwrap();
        ledger.add_block(recv).unwrap();
        assert_eq!(
            ledger.total_supply(),
            supply_before,
            "send + receive must not change total supply"
        );
    }

    #[test]
    fn test_add_block_accepts_open_at_exact_supply_ceiling() {
        // Boundary : the very last Open whose initial_balance brings
        // the running total to exactly TOTAL_SUPPLY_MICRO_ARX must
        // be accepted (=, not <).
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        // Open 10 chains at the per-account cap ; 10 × cap = total
        // supply exactly.
        for _ in 0..10 {
            let mut acct = AccountChain::new();
            let open = acct
                .open(arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT, &mut vc)
                .unwrap();
            ledger.add_block(open).expect("each open at cap is fine");
        }
        assert_eq!(ledger.total_supply(), arxia_core::TOTAL_SUPPLY_MICRO_ARX);
    }

    #[test]
    fn test_add_block_rejects_open_that_would_exceed_supply_ceiling() {
        // Open the protocol to its full capacity, then attempt one
        // more Open. The eleventh Open must be rejected with
        // SupplyCapExceeded against the global ceiling.
        let mut ledger = Ledger::new();
        let mut vc = VectorClock::new();
        for _ in 0..10 {
            let mut acct = AccountChain::new();
            let open = acct
                .open(arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT, &mut vc)
                .unwrap();
            ledger.add_block(open).unwrap();
        }
        let mut overflow_acct = AccountChain::new();
        let overflow_open = overflow_acct.open(1, &mut vc).unwrap();
        let result = ledger.add_block(overflow_open);
        assert!(
            matches!(
                result,
                Err(ArxiaError::SupplyCapExceeded { requested, max })
                    if requested == arxia_core::TOTAL_SUPPLY_MICRO_ARX + 1
                        && max == arxia_core::TOTAL_SUPPLY_MICRO_ARX
            ),
            "expected SupplyCapExceeded against TOTAL_SUPPLY ceiling, got {:?}",
            result
        );
        // Total supply is unchanged after the rejected Open.
        assert_eq!(ledger.total_supply(), arxia_core::TOTAL_SUPPLY_MICRO_ARX);
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
