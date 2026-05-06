//! AccountChain manages a single account block chain and keypair.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashSet};

use crate::block::{Block, BlockType};
use arxia_core::ArxiaError;

/// Vector clock for causal ordering. Uses BTreeMap for deterministic iteration.
///
/// **NOT the same as `arxia_crdt::CrdtVectorClock`** (LOW-006,
/// commit 077). This lattice form is used at block-creation time
/// and is capped at [`arxia_core::MAX_VECTOR_CLOCK_ENTRIES`]
/// (commit 061) to bound adversarial peers' memory impact at the
/// hot path. The CRDT form has no cap (CRDTs absorb arbitrary
/// participation). Pick by use case ; the names are deliberately
/// similar but the semantics differ.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct VectorClock {
    /// Map from node ID to logical clock value.
    pub clocks: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock.
    pub fn new() -> Self {
        Self {
            clocks: BTreeMap::new(),
        }
    }

    /// Increment the clock for the given node.
    ///
    /// MED-018 (commit 060): uses `saturating_add` against
    /// u64::MAX wrap.
    ///
    /// MED-019 (commit 061): refuses NEW entries beyond
    /// `arxia_core::MAX_VECTOR_CLOCK_ENTRIES` (256). Existing
    /// entries continue to tick normally.
    pub fn tick(&mut self, node_id: &str) {
        let key = node_id.to_string();
        if !self.clocks.contains_key(&key)
            && self.clocks.len() >= arxia_core::MAX_VECTOR_CLOCK_ENTRIES
        {
            return;
        }
        let counter = self.clocks.entry(key).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    /// Merge with another vector clock (element-wise max).
    ///
    /// MED-019 (commit 061): same cap as `tick` — merging in
    /// a new node ID beyond
    /// `arxia_core::MAX_VECTOR_CLOCK_ENTRIES` is silently
    /// dropped. Existing entries always merge.
    pub fn merge(&mut self, other: &VectorClock) {
        for (node_id, &other_val) in &other.clocks {
            if !self.clocks.contains_key(node_id)
                && self.clocks.len() >= arxia_core::MAX_VECTOR_CLOCK_ENTRIES
            {
                continue;
            }
            let entry = self.clocks.entry(node_id.clone()).or_insert(0);
            *entry = (*entry).max(other_val);
        }
    }

    /// Returns true if self causally happened before other.
    pub fn happened_before(&self, other: &VectorClock) -> bool {
        let mut at_least_one_less = false;
        for (node_id, &self_val) in &self.clocks {
            let other_val = other.clocks.get(node_id).copied().unwrap_or(0);
            if self_val > other_val {
                return false;
            }
            if self_val < other_val {
                at_least_one_less = true;
            }
        }
        for (nid, &other_val) in &other.clocks {
            if !self.clocks.contains_key(nid) && other_val > 0 {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }

    /// Returns true if self and other are concurrent.
    pub fn is_concurrent(&self, other: &VectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self) && self != other
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages a single account chain of blocks.
pub struct AccountChain {
    signing_key: SigningKey,
    /// The Ed25519 verifying key.
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Hex-encoded public key.
    pub public_key_hex: String,
    /// The chain of blocks.
    pub chain: Vec<Block>,
    /// Current balance in micro-ARX.
    pub balance: u64,
    /// Current nonce.
    pub nonce: u64,
    /// Hashes of SEND blocks already consumed by `receive`. Prevents
    /// replaying the same SEND to mint the balance multiple times.
    pub consumed_sources: HashSet<String>,
}

impl AccountChain {
    /// Create a new account with a fresh Ed25519 keypair.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        Self {
            signing_key,
            verifying_key,
            public_key_hex,
            chain: Vec::new(),
            balance: 0,
            nonce: 0,
            consumed_sources: HashSet::new(),
        }
    }

    /// Full hex-encoded public key.
    pub fn id(&self) -> &str {
        &self.public_key_hex
    }

    /// Short identifier (first 8 hex chars of the public-key hex
    /// encoding).
    ///
    /// LOW-004 (commit 075): defensive slice. The invariant is
    /// that `public_key_hex` is always 64 chars (`hex::encode` of
    /// a 32-byte Ed25519 pubkey) so the unchecked `[..8]` never
    /// panics in production. We still use `get(..8)` and fall back
    /// to the full string so a future refactor that loosens the
    /// invariant (e.g. lazy-init or partial-fill) cannot trigger
    /// a panic at this site.
    pub fn short_id(&self) -> &str {
        self.public_key_hex.get(..8).unwrap_or(&self.public_key_hex)
    }

    /// Reference to the signing key (for consensus voting).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Open an account with an initial balance (genesis block).
    ///
    /// # Errors
    ///
    /// - [`ArxiaError::AccountAlreadyOpen`] if the chain already contains
    ///   any block. `open` is idempotent-by-rejection.
    /// - [`ArxiaError::SupplyCapExceeded`] if `initial_balance` is greater
    ///   than [`arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT`]. The per-account
    ///   cap defends against unbounded self-mint at account creation.
    pub fn open(
        &mut self,
        initial_balance: u64,
        vclock: &mut VectorClock,
    ) -> Result<Block, ArxiaError> {
        if !self.chain.is_empty() {
            return Err(ArxiaError::AccountAlreadyOpen);
        }
        if initial_balance > arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT {
            return Err(ArxiaError::SupplyCapExceeded {
                requested: initial_balance,
                max: arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT,
            });
        }
        let sid = self.public_key_hex[..8].to_string();
        vclock.tick(&sid);
        self.balance = initial_balance;
        self.nonce = 1;
        let timestamp = arxia_core::now_millis();
        let block_type = BlockType::Open { initial_balance };
        let hash = Block::compute_hash(
            &self.public_key_hex,
            "",
            &block_type,
            self.balance,
            self.nonce,
            timestamp,
        )?;
        // CRITICAL: sign raw Blake3 bytes (32 bytes), NOT hex string
        // MED-002 (commit 055): typed-error on internal hex
        // decode. `compute_hash` (commit 050) returns a
        // 64-char lowercase hex string by construction; the
        // decode is unreachable today. Defense-in-depth: a
        // future refactor that swaps the hash algorithm or
        // its formatting surfaces the failure as
        // `HexDecode` instead of an `unwrap` panic.
        let hash_bytes = hex::decode(&hash).map_err(ArxiaError::HexDecode)?;
        let signature = self.signing_key.sign(&hash_bytes);
        let block = Block {
            account: self.public_key_hex.clone(),
            previous: String::new(),
            block_type,
            balance: self.balance,
            nonce: self.nonce,
            timestamp,
            hash,
            signature: signature.to_bytes().to_vec(),
        };
        self.chain.push(block.clone());
        Ok(block)
    }

    /// Send funds to a destination account.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArxiaError::ZeroAmount`] if `amount == 0`.
    /// - [`ArxiaError::SelfSendNotAllowed`] if `destination` equals
    ///   the sender's own public key hex (HIGH-002, closed in commit 029).
    ///   Self-sends inflate the nonce without an economic effect and,
    ///   combined with any dedup-bypass on the receive path, would
    ///   become a free-mint vector.
    /// - [`ArxiaError::InsufficientBalance`] if `self.balance < amount`.
    pub fn send(
        &mut self,
        destination: &str,
        amount: u64,
        vclock: &mut VectorClock,
    ) -> Result<Block, ArxiaError> {
        if amount == 0 {
            return Err(ArxiaError::ZeroAmount);
        }
        // HIGH-002 (commit 029): reject self-sends BEFORE any state
        // mutation. The check fires before `balance < amount` so a
        // self-send always reports the structural error, not the
        // semantic one (insufficient balance), regardless of the
        // sender's funds.
        if destination == self.public_key_hex {
            return Err(ArxiaError::SelfSendNotAllowed);
        }
        if self.balance < amount {
            return Err(ArxiaError::InsufficientBalance {
                available: self.balance,
                required: amount,
            });
        }
        let sid = self.public_key_hex[..8].to_string();
        vclock.tick(&sid);
        self.balance -= amount;
        self.nonce += 1;
        let previous = self
            .chain
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        let timestamp = arxia_core::now_millis();
        let block_type = BlockType::Send {
            destination: destination.to_string(),
            amount,
        };
        let hash = Block::compute_hash(
            &self.public_key_hex,
            &previous,
            &block_type,
            self.balance,
            self.nonce,
            timestamp,
        )?;
        // MED-002 (commit 055): typed-error on internal hex
        // decode. `compute_hash` (commit 050) returns a
        // 64-char lowercase hex string by construction; the
        // decode is unreachable today. Defense-in-depth: a
        // future refactor that swaps the hash algorithm or
        // its formatting surfaces the failure as
        // `HexDecode` instead of an `unwrap` panic.
        let hash_bytes = hex::decode(&hash).map_err(ArxiaError::HexDecode)?;
        let signature = self.signing_key.sign(&hash_bytes);
        let block = Block {
            account: self.public_key_hex.clone(),
            previous,
            block_type,
            balance: self.balance,
            nonce: self.nonce,
            timestamp,
            hash,
            signature: signature.to_bytes().to_vec(),
        };
        self.chain.push(block.clone());
        Ok(block)
    }

    /// Receive funds from a SEND block.
    ///
    /// # Errors
    ///
    /// - [`ArxiaError::NotSendBlock`] if `send_block` is not of type Send.
    /// - [`ArxiaError::WrongDestination`] if the send's destination is not
    ///   this account.
    /// - [`ArxiaError::DuplicateReceive`] if the SEND's hash has already
    ///   been consumed by a previous `receive` on this chain. This blocks
    ///   the infinite-mint attack where a single SEND is replayed as many
    ///   RECEIVEs against the recipient.
    pub fn receive(
        &mut self,
        send_block: &Block,
        vclock: &mut VectorClock,
    ) -> Result<Block, ArxiaError> {
        let amount = match &send_block.block_type {
            BlockType::Send {
                amount,
                destination,
            } => {
                if destination != &self.public_key_hex {
                    return Err(ArxiaError::WrongDestination);
                }
                *amount
            }
            _ => return Err(ArxiaError::NotSendBlock),
        };
        if self.consumed_sources.contains(&send_block.hash) {
            return Err(ArxiaError::DuplicateReceive {
                source_hash: send_block.hash.clone(),
            });
        }
        // CRIT-018 guard: reject overflowing receives BEFORE bumping
        // vclock, balance, or nonce. A silent wrap would make the
        // account's recorded balance smaller than the truth and the
        // block would still hash-verify (the hash is computed over
        // the wrapped value), allowing the attacker to destroy a
        // victim's balance or to manufacture a supply-conservation
        // violation across partitions.
        let new_balance = self
            .balance
            .checked_add(amount)
            .ok_or(ArxiaError::BalanceOverflow {
                current: self.balance,
                incoming: amount,
            })?;
        let sid = self.public_key_hex[..8].to_string();
        vclock.tick(&sid);
        self.balance = new_balance;
        self.nonce += 1;
        let previous = self
            .chain
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        let timestamp = arxia_core::now_millis();
        let block_type = BlockType::Receive {
            source_hash: send_block.hash.clone(),
        };
        let hash = Block::compute_hash(
            &self.public_key_hex,
            &previous,
            &block_type,
            self.balance,
            self.nonce,
            timestamp,
        )?;
        // MED-002 (commit 055): typed-error on internal hex
        // decode. `compute_hash` (commit 050) returns a
        // 64-char lowercase hex string by construction; the
        // decode is unreachable today. Defense-in-depth: a
        // future refactor that swaps the hash algorithm or
        // its formatting surfaces the failure as
        // `HexDecode` instead of an `unwrap` panic.
        let hash_bytes = hex::decode(&hash).map_err(ArxiaError::HexDecode)?;
        let signature = self.signing_key.sign(&hash_bytes);
        let block = Block {
            account: self.public_key_hex.clone(),
            previous,
            block_type,
            balance: self.balance,
            nonce: self.nonce,
            timestamp,
            hash,
            signature: signature.to_bytes().to_vec(),
        };
        self.chain.push(block.clone());
        self.consumed_sources.insert(send_block.hash.clone());
        Ok(block)
    }
}

impl Default for AccountChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_account() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        assert_eq!(block.balance, 1_000_000);
        assert_eq!(block.nonce, 1);
        assert!(block.previous.is_empty());
        assert!(!block.hash.is_empty());
        assert_eq!(block.signature.len(), 64);
    }

    #[test]
    fn test_send_and_receive() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(500_000, &mut vc).unwrap();
        let send = alice.send(bob.id(), 200_000, &mut vc).unwrap();
        assert_eq!(alice.balance, 800_000);
        let recv = bob.receive(&send, &mut vc).unwrap();
        assert_eq!(bob.balance, 700_000);
        assert_eq!(recv.nonce, 2);
    }

    #[test]
    fn test_send_insufficient_balance() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(100, &mut vc).unwrap();
        let result = alice.send("deadbeef", 200, &mut vc);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_zero_amount() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000, &mut vc).unwrap();
        assert!(alice.send("dest", 0, &mut vc).is_err());
    }

    #[test]
    fn test_vector_clock_btreemap_ordering() {
        let mut vc = VectorClock::new();
        vc.tick("charlie");
        vc.tick("alice");
        vc.tick("bob");
        let keys: Vec<&String> = vc.clocks.keys().collect();
        assert_eq!(keys, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_vector_clock_merge() {
        let mut vc1 = VectorClock::new();
        vc1.tick("a");
        vc1.tick("a");
        let mut vc2 = VectorClock::new();
        vc2.tick("a");
        vc2.tick("b");
        vc1.merge(&vc2);
        assert_eq!(vc1.clocks["a"], 2);
        assert_eq!(vc1.clocks["b"], 1);
    }

    #[test]
    fn test_vector_clock_happened_before() {
        let mut vc1 = VectorClock::new();
        vc1.tick("a");
        let mut vc2 = vc1.clone();
        vc2.tick("a");
        assert!(vc1.happened_before(&vc2));
        assert!(!vc2.happened_before(&vc1));
    }

    #[test]
    fn test_vector_clock_concurrent() {
        let mut vc1 = VectorClock::new();
        vc1.tick("a");
        let mut vc2 = VectorClock::new();
        vc2.tick("b");
        assert!(vc1.is_concurrent(&vc2));
    }

    // ========================================================================
    // Adversarial tests for Bug 2 (open idempotence)
    // ========================================================================

    #[test]
    fn test_open_cannot_be_called_twice() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();
        let result = chain.open(9_999_999, &mut vc);
        assert!(result.is_err());
        assert_eq!(chain.balance, 1_000_000);
        assert_eq!(chain.nonce, 1);
        assert_eq!(chain.chain.len(), 1);
    }

    #[test]
    fn test_open_returns_account_already_open() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();
        let err = chain.open(1, &mut vc).unwrap_err();
        assert!(
            matches!(err, ArxiaError::AccountAlreadyOpen),
            "expected AccountAlreadyOpen, got {:?}",
            err
        );
    }

    #[test]
    fn test_open_after_send_rejected() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        alice.send(bob.id(), 100, &mut vc).unwrap();
        // chain now has 2 blocks; open must still be rejected
        let result = alice.open(5_000_000, &mut vc);
        assert!(matches!(result, Err(ArxiaError::AccountAlreadyOpen)));
        assert_eq!(alice.chain.len(), 2);
    }

    #[test]
    fn test_open_after_receive_rejected() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 200_000, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();
        // bob has 2 blocks now
        let result = bob.open(u64::MAX, &mut vc);
        assert!(matches!(result, Err(ArxiaError::AccountAlreadyOpen)));
        assert_eq!(bob.chain.len(), 2);
    }

    #[test]
    fn test_open_does_not_modify_state_on_second_attempt() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();
        let snapshot_balance = chain.balance;
        let snapshot_nonce = chain.nonce;
        let snapshot_hash = chain.chain[0].hash.clone();
        // Adversary tries every pathological balance. All rejected
        // either by the idempotence check (first) or the supply cap.
        for malicious in [0u64, 1, u64::MAX, u64::MAX - 1, 1_000_000_001] {
            let _ = chain.open(malicious, &mut vc);
        }
        assert_eq!(chain.balance, snapshot_balance);
        assert_eq!(chain.nonce, snapshot_nonce);
        assert_eq!(chain.chain.len(), 1);
        assert_eq!(chain.chain[0].hash, snapshot_hash);
    }

    // ========================================================================
    // Adversarial tests for Bug 3 (supply cap)
    // ========================================================================

    #[test]
    fn test_open_rejects_u64_max() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let result = chain.open(u64::MAX, &mut vc);
        assert!(matches!(result, Err(ArxiaError::SupplyCapExceeded { .. })));
        assert!(chain.chain.is_empty());
        assert_eq!(chain.balance, 0);
        assert_eq!(chain.nonce, 0);
    }

    #[test]
    fn test_open_rejects_above_per_account_cap() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let over = arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT + 1;
        let err = chain.open(over, &mut vc).unwrap_err();
        match err {
            ArxiaError::SupplyCapExceeded { requested, max } => {
                assert_eq!(requested, over);
                assert_eq!(max, arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT);
            }
            other => panic!("expected SupplyCapExceeded, got {:?}", other),
        }
    }

    #[test]
    fn test_open_accepts_exactly_at_cap() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let at_cap = arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT;
        let block = chain.open(at_cap, &mut vc).unwrap();
        assert_eq!(block.balance, at_cap);
        assert_eq!(chain.balance, at_cap);
    }

    #[test]
    fn test_open_accepts_well_below_cap() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let modest = 1_000_000u64; // 1 ARX
        assert!(chain.open(modest, &mut vc).is_ok());
    }

    #[test]
    fn test_open_rejects_total_supply() {
        // Attacker tries to mint the entire protocol supply into a single
        // account. Must be rejected by the per-account cap even though it
        // is technically <= TOTAL_SUPPLY.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let result = chain.open(arxia_core::TOTAL_SUPPLY_MICRO_ARX, &mut vc);
        assert!(matches!(result, Err(ArxiaError::SupplyCapExceeded { .. })));
    }

    #[test]
    fn test_open_cap_is_not_total_supply() {
        // Sanity: the per-account cap is strictly less than total supply.
        // Otherwise a single open call could drain the entire supply.
        const _: () = assert!(
            arxia_core::MAX_INITIAL_BALANCE_PER_ACCOUNT < arxia_core::TOTAL_SUPPLY_MICRO_ARX
        );
    }

    // ========================================================================
    // Adversarial tests for Bug 4 (receive dedup)
    // ========================================================================

    #[test]
    fn test_receive_rejects_duplicate_send() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();

        // Legit first receive
        bob.receive(&send, &mut vc).unwrap();
        assert_eq!(bob.balance, 100_000);

        // Adversary replays — must be rejected, balance unchanged
        let err = bob.receive(&send, &mut vc).unwrap_err();
        match err {
            ArxiaError::DuplicateReceive { source_hash } => {
                assert_eq!(source_hash, send.hash);
            }
            other => panic!("expected DuplicateReceive, got {:?}", other),
        }
        assert_eq!(bob.balance, 100_000);
        // Chain unchanged after the rejected replay
        assert_eq!(bob.chain.len(), 2); // open + first receive
    }

    #[test]
    fn test_receive_replay_does_not_mint_infinite() {
        // Adversary replays the same SEND 1000 times. Every replay must
        // be rejected; balance stays at the legitimate amount.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();
        for _ in 0..1000 {
            let _ = bob.receive(&send, &mut vc);
        }
        assert_eq!(bob.balance, 100_000);
        assert_eq!(bob.nonce, 2);
        assert_eq!(bob.chain.len(), 2);
    }

    #[test]
    fn test_receive_two_different_sends_both_accepted() {
        // Regression: two legit SENDs from same sender must both be
        // consumable; dedup must key on source hash, not on sender.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let s1 = alice.send(bob.id(), 100, &mut vc).unwrap();
        let s2 = alice.send(bob.id(), 200, &mut vc).unwrap();
        assert_ne!(s1.hash, s2.hash);
        bob.receive(&s1, &mut vc).unwrap();
        bob.receive(&s2, &mut vc).unwrap();
        assert_eq!(bob.balance, 300);
        assert_eq!(bob.chain.len(), 3);
    }

    #[test]
    fn test_receive_consumed_source_is_tracked_per_account() {
        // Alice sends to Bob, then sends an IDENTICAL amount to Carol.
        // Bob consumes his SEND; Carol consuming HERS must still succeed
        // because consumed_sources is per-account.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let mut carol = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        carol.open(0, &mut vc).unwrap();
        let to_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        let to_carol = alice.send(carol.id(), 100, &mut vc).unwrap();
        bob.receive(&to_bob, &mut vc).unwrap();
        carol.receive(&to_carol, &mut vc).unwrap();
        assert_eq!(bob.balance, 100);
        assert_eq!(carol.balance, 100);
    }

    #[test]
    fn test_receive_rejects_wrong_destination_before_dedup() {
        // Error ordering: WrongDestination takes priority over
        // DuplicateReceive. Otherwise an attacker could probe
        // consumed_sources state by measuring error codes.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let mut eve = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        eve.open(0, &mut vc).unwrap();
        let to_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        bob.receive(&to_bob, &mut vc).unwrap();
        // Eve tries to receive Bob's SEND
        let err = eve.receive(&to_bob, &mut vc).unwrap_err();
        assert!(matches!(err, ArxiaError::WrongDestination));
    }

    // ========================================================================
    // CRIT-018 adversarial tests — balance overflow
    // ========================================================================

    #[test]
    fn test_receive_overflow_returns_error_and_leaves_state_unchanged() {
        // Bob's chain is (somehow) already near u64::MAX. An incoming
        // SEND of a non-trivial amount MUST return BalanceOverflow and
        // MUST NOT mutate balance, nonce, chain length, or vclock.
        //
        // Without the checked_add guard in receive(), `self.balance +=
        // amount` wraps silently to a small value and the block still
        // hash-verifies because the hash is computed over the wrapped
        // balance. That is the CRIT-018 attack: a sender can destroy a
        // victim's recorded balance or manufacture a supply-
        // conservation violation across partitions.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        // Forcibly park Bob near u64::MAX. The supply cap prevents
        // reaching this state via open(), but an attacker-influenced
        // accumulation over many receives could.
        bob.balance = u64::MAX - 10;
        let pre_balance = bob.balance;
        let pre_nonce = bob.nonce;
        let pre_chain_len = bob.chain.len();
        let pre_vc_clocks = vc.clocks.clone();

        let send = alice.send(bob.id(), 100, &mut vc).unwrap();
        let err = bob.receive(&send, &mut vc).unwrap_err();
        match err {
            ArxiaError::BalanceOverflow { current, incoming } => {
                assert_eq!(current, pre_balance);
                assert_eq!(incoming, 100);
            }
            other => panic!("expected BalanceOverflow, got {:?}", other),
        }
        assert_eq!(bob.balance, pre_balance, "balance must be untouched");
        assert_eq!(bob.nonce, pre_nonce, "nonce must be untouched");
        assert_eq!(bob.chain.len(), pre_chain_len, "chain must be untouched");
        // vclock must NOT have ticked for Bob's shard on the overflow path.
        let bob_sid = bob.id()[..8].to_string();
        assert_eq!(
            vc.clocks.get(&bob_sid),
            pre_vc_clocks.get(&bob_sid),
            "vclock must not tick on a rejected receive"
        );
    }

    #[test]
    fn test_receive_at_exact_u64_max_is_accepted() {
        // Boundary: if current + amount == u64::MAX the result still
        // fits, so receive MUST succeed and balance MUST be exactly
        // u64::MAX.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        bob.balance = u64::MAX - 100;
        let send = alice.send(bob.id(), 100, &mut vc).unwrap();
        bob.receive(&send, &mut vc).expect("exact-fit receive");
        assert_eq!(bob.balance, u64::MAX);
    }

    #[test]
    fn test_receive_overflow_then_legit_receive_from_other_sender_still_works() {
        // A rejected overflowing receive must not poison subsequent
        // receives. Bob refuses Alice's overflowing SEND, then
        // legitimately accepts a SEND from Carol with an amount that
        // fits.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let mut carol = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        carol.open(1_000, &mut vc).unwrap();
        bob.balance = u64::MAX - 5;

        let bad = alice.send(bob.id(), 100, &mut vc).unwrap();
        assert!(matches!(
            bob.receive(&bad, &mut vc),
            Err(ArxiaError::BalanceOverflow { .. })
        ));
        // Bob is still accepting smaller amounts that fit.
        bob.balance = 1_000; // return to a sensible state
        let good = carol.send(bob.id(), 500, &mut vc).unwrap();
        bob.receive(&good, &mut vc).expect("legit receive");
        assert_eq!(bob.balance, 1_500);
    }

    // ========================================================================
    // Adversarial tests for HIGH-002 (self-send rejection)
    //
    // AccountChain::send must reject `destination == self.public_key_hex`
    // BEFORE any state mutation. Self-sends inflate the nonce without
    // an economic effect and, combined with any future dedup-bypass on
    // receive, become a free-mint vector.
    // ========================================================================

    #[test]
    fn test_send_rejects_self_destination() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let nonce_before = alice.nonce;
        let balance_before = alice.balance;
        let chain_len_before = alice.chain.len();

        // Self-send: alice → alice. Use a local for the destination
        // because `alice.send(alice.id(), ...)` would cross-borrow.
        let alice_id = alice.id().to_string();
        let result = alice.send(&alice_id, 100, &mut vc);
        assert!(
            matches!(result, Err(ArxiaError::SelfSendNotAllowed)),
            "self-send must be rejected with SelfSendNotAllowed, got {:?}",
            result
        );

        // No state was mutated (the rejection fires BEFORE any tick /
        // balance update / nonce increment / chain push).
        assert_eq!(alice.nonce, nonce_before, "nonce must not change");
        assert_eq!(alice.balance, balance_before, "balance must not change");
        assert_eq!(
            alice.chain.len(),
            chain_len_before,
            "chain must not gain a block"
        );
    }

    #[test]
    fn test_send_self_check_fires_before_balance_check() {
        // Even with zero balance, a self-send must report
        // SelfSendNotAllowed (the structural error), NOT
        // InsufficientBalance (the semantic error). Pinned because the
        // priority is checked in the implementation.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(0, &mut vc).unwrap();
        assert_eq!(alice.balance, 0);

        let alice_id = alice.id().to_string();
        let result = alice.send(&alice_id, 1_000_000, &mut vc);
        assert!(
            matches!(result, Err(ArxiaError::SelfSendNotAllowed)),
            "structural self-send check must take priority over balance, got {:?}",
            result
        );
    }

    #[test]
    fn test_send_self_check_fires_before_zero_amount_check() {
        // Order of checks: amount=0 fires FIRST (it's even more
        // structural — 0-amount sends are nonsense regardless of
        // destination). Pin this so the implementation order is
        // documented.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();

        // Both pathological inputs at once: amount = 0 AND self-send.
        // The earlier check (ZeroAmount) wins.
        let alice_id = alice.id().to_string();
        let result = alice.send(&alice_id, 0, &mut vc);
        assert!(
            matches!(result, Err(ArxiaError::ZeroAmount)),
            "ZeroAmount must take priority over SelfSendNotAllowed when both apply, got {:?}",
            result
        );
    }

    #[test]
    fn test_send_to_other_destination_unaffected() {
        // Regression guard: legitimate alice → bob still works.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();

        let block = alice
            .send(bob.id(), 100, &mut vc)
            .expect("legitimate cross-account send must succeed");
        assert!(matches!(block.block_type, BlockType::Send { .. }));
        assert_eq!(alice.balance, 999_900);
        assert_eq!(alice.nonce, 2);
    }

    #[test]
    fn test_send_destination_one_byte_different_from_self_succeeds() {
        // The self-check is exact equality, not prefix or substring.
        // A destination that DIFFERS from self.public_key_hex by even
        // one character must not trigger SelfSendNotAllowed; the
        // function falls through to the InsufficientBalance check
        // (or to a successful send, depending on funds).
        //
        // We construct a "near-self" destination by flipping the
        // last hex digit of alice's pubkey. This is not a valid
        // pubkey for any real account, but `send` does not validate
        // the destination's structure — that's the receive side's
        // job.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();

        let mut near_self = alice.id().to_string();
        let last = near_self.pop().unwrap();
        let flipped = if last == 'f' { '0' } else { 'f' };
        near_self.push(flipped);
        assert_ne!(near_self, alice.id());

        let result = alice.send(&near_self, 100, &mut vc);
        // Self-check must NOT fire. The send proceeds and either
        // succeeds or fails the balance check; either way, NOT
        // SelfSendNotAllowed.
        assert!(
            !matches!(result, Err(ArxiaError::SelfSendNotAllowed)),
            "destination one byte different from self must not trigger SelfSendNotAllowed"
        );
    }

    // ============================================================
    // MED-002 (commit 055) — typed-error on internal hex decode.
    // ============================================================

    #[test]
    fn test_chain_rs_no_unguarded_expect_on_hex_decode() {
        // STRUCTURAL PIN: production code must NOT contain
        // `.expect("valid hex hash")`. Source-lint via
        // include_str!. A future regression reintroducing the
        // panic-prone form fails this test before reaching CI.
        const SELF_SOURCE: &str = include_str!("chain.rs");
        let test_marker = "#[cfg(test)]\nmod tests";
        let production = SELF_SOURCE
            .split(test_marker)
            .next()
            .expect("split always yields >=1 segment");
        assert!(
            !production.contains(".expect(\"valid hex hash\")"),
            "MED-002: production code must use `?` propagation \
             for internal hex::decode failures"
        );
    }

    // ============================================================
    // MED-018 (commit 060) — VectorClock tick saturating_add
    // defends against u64::MAX wrap.
    // ============================================================

    #[test]
    fn test_vector_clock_tick_saturates_at_u64_max() {
        // PRIMARY MED-018 PIN: a vector clock counter pre-loaded
        // at u64::MAX must NOT panic on tick.
        let mut vc = VectorClock::new();
        vc.clocks.insert("node-overflow".to_string(), u64::MAX);
        vc.tick("node-overflow"); // must not panic
        assert_eq!(vc.clocks["node-overflow"], u64::MAX);
        // Repeated ticks remain at the saturated value.
        vc.tick("node-overflow");
        assert_eq!(vc.clocks["node-overflow"], u64::MAX);
    }

    #[test]
    fn test_vector_clock_tick_increments_normally_when_far_from_wrap() {
        // Regression: the saturating change doesn't break the
        // common case.
        let mut vc = VectorClock::new();
        for _ in 0..10 {
            vc.tick("node-a");
        }
        assert_eq!(vc.clocks["node-a"], 10);
    }

    #[test]
    fn test_vector_clock_tick_just_below_max_saturates_on_one_tick() {
        // Boundary: counter = u64::MAX - 1, one tick brings
        // it to u64::MAX (no saturation triggered yet, just
        // the last representable value).
        let mut vc = VectorClock::new();
        vc.clocks.insert("node-edge".to_string(), u64::MAX - 1);
        vc.tick("node-edge");
        assert_eq!(vc.clocks["node-edge"], u64::MAX);
        // Next tick saturates.
        vc.tick("node-edge");
        assert_eq!(vc.clocks["node-edge"], u64::MAX);
    }

    // ============================================================
    // MED-019 (commit 061) — VectorClock enforces
    // MAX_VECTOR_CLOCK_ENTRIES cap on tick + merge.
    // ============================================================

    #[test]
    fn test_vc_tick_caps_new_entries_at_max() {
        // PRIMARY MED-019 PIN: a vector clock at MAX entries
        // refuses to add a new node-id but still allows
        // existing entries to tick.
        let mut vc = VectorClock::new();
        for i in 0..arxia_core::MAX_VECTOR_CLOCK_ENTRIES {
            vc.tick(&format!("n-{i:04}"));
        }
        assert_eq!(vc.clocks.len(), arxia_core::MAX_VECTOR_CLOCK_ENTRIES);
        // Try to add an extra new node — should be silently
        // dropped.
        vc.tick("n-new-node");
        assert_eq!(
            vc.clocks.len(),
            arxia_core::MAX_VECTOR_CLOCK_ENTRIES,
            "tick must NOT add a new entry beyond MAX"
        );
        assert!(!vc.clocks.contains_key("n-new-node"));
        // Existing entries can still tick.
        let val_before = vc.clocks["n-0000"];
        vc.tick("n-0000");
        assert_eq!(vc.clocks["n-0000"], val_before + 1);
    }

    #[test]
    fn test_vc_merge_caps_new_entries_at_max() {
        // PRIMARY MED-019 PIN (merge side): merging in a
        // vector clock with new node IDs while at MAX
        // silently drops the new ones.
        let mut a = VectorClock::new();
        for i in 0..arxia_core::MAX_VECTOR_CLOCK_ENTRIES {
            a.tick(&format!("a-{i:04}"));
        }
        // b has 5 NEW node IDs that aren't in a.
        let mut b = VectorClock::new();
        for i in 0..5 {
            b.tick(&format!("b-{i:04}"));
        }
        a.merge(&b);
        assert_eq!(
            a.clocks.len(),
            arxia_core::MAX_VECTOR_CLOCK_ENTRIES,
            "merge must NOT exceed MAX"
        );
        for i in 0..5 {
            assert!(!a.clocks.contains_key(&format!("b-{i:04}")));
        }
    }

    #[test]
    fn test_vc_merge_overlapping_nodes_always_works() {
        // Boundary: if `b` only has node IDs already in `a`,
        // merge succeeds regardless of capacity (no new
        // entries added).
        let mut a = VectorClock::new();
        for i in 0..arxia_core::MAX_VECTOR_CLOCK_ENTRIES {
            a.tick(&format!("n-{i:04}"));
        }
        let mut b = VectorClock::new();
        b.tick("n-0001");
        b.tick("n-0001");
        b.tick("n-0001"); // n-0001 in b is at 3
        a.merge(&b);
        assert_eq!(a.clocks.len(), arxia_core::MAX_VECTOR_CLOCK_ENTRIES);
        // a's n-0001 was 1 ; merge with 3 makes it 3 (max).
        assert_eq!(a.clocks["n-0001"], 3);
    }

    #[test]
    fn test_vc_grows_normally_below_max() {
        // Regression: standard usage (few nodes) is unaffected.
        let mut vc = VectorClock::new();
        vc.tick("alice");
        vc.tick("bob");
        vc.tick("carol");
        assert_eq!(vc.clocks.len(), 3);
    }

    // ============================================================
    // LOW-004 (commit 075) — short_id defensive slice. The
    // invariant is that public_key_hex is always 64 chars
    // (hex::encode of 32 bytes), so the original [..8] never
    // panicked in production. The post-fix `get(..8)` keeps
    // that behaviour for the canonical case and falls back to
    // the full string if the invariant is ever loosened.
    // ============================================================

    #[test]
    fn test_short_id_returns_first_8_chars_of_full_id() {
        // PRIMARY LOW-004 PIN: for a fresh AccountChain (canonical
        // 64-char hex pubkey), short_id() returns exactly the
        // first 8 characters of id().
        let alice = AccountChain::new();
        let full = alice.id();
        assert_eq!(full.len(), 64, "id is 64 hex chars");
        let short = alice.short_id();
        assert_eq!(short.len(), 8);
        assert_eq!(short, &full[..8]);
    }

    #[test]
    fn test_short_id_stable_across_calls() {
        // Sanity: short_id is a pure projection of public_key_hex
        // and must return the same slice across calls. Pin
        // against a future refactor that introduces caching
        // with a stale-read bug.
        let alice = AccountChain::new();
        let s1 = alice.short_id().to_string();
        let s2 = alice.short_id().to_string();
        let s3 = alice.short_id().to_string();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn test_short_id_different_accounts_differ_with_high_probability() {
        // Two fresh accounts have different pubkeys → different
        // short_ids (with 1 - 1/2^32 ≈ 1.0 probability).
        let alice = AccountChain::new();
        let bob = AccountChain::new();
        assert_ne!(
            alice.short_id(),
            bob.short_id(),
            "two random pubkeys collide on first 8 hex chars (≈ 1 in 4 billion)"
        );
    }
}
