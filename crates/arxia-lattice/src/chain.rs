//! AccountChain manages a single account block chain and keypair.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

use crate::block::{Block, BlockType};
use arxia_core::ArxiaError;

/// Vector clock for causal ordering. Uses BTreeMap for deterministic iteration.
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
    pub fn tick(&mut self, node_id: &str) {
        let counter = self.clocks.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Merge with another vector clock (element-wise max).
    pub fn merge(&mut self, other: &VectorClock) {
        for (node_id, &other_val) in &other.clocks {
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
        }
    }

    /// Full hex-encoded public key.
    pub fn id(&self) -> &str {
        &self.public_key_hex
    }

    /// Short identifier (first 8 hex chars).
    pub fn short_id(&self) -> &str {
        &self.public_key_hex[..8]
    }

    /// Reference to the signing key (for consensus voting).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Open an account with an initial balance (genesis block).
    ///
    /// # Errors
    ///
    /// Returns [`ArxiaError::AccountAlreadyOpen`] if the chain already
    /// contains any block. `open` is idempotent-by-rejection: a second
    /// call leaves the existing state untouched.
    pub fn open(
        &mut self,
        initial_balance: u64,
        vclock: &mut VectorClock,
    ) -> Result<Block, ArxiaError> {
        if !self.chain.is_empty() {
            return Err(ArxiaError::AccountAlreadyOpen);
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
        );
        // CRITICAL: sign raw Blake3 bytes (32 bytes), NOT hex string
        let hash_bytes = hex::decode(&hash).expect("valid hex hash");
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
    pub fn send(
        &mut self,
        destination: &str,
        amount: u64,
        vclock: &mut VectorClock,
    ) -> Result<Block, ArxiaError> {
        if amount == 0 {
            return Err(ArxiaError::ZeroAmount);
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
        );
        let hash_bytes = hex::decode(&hash).expect("valid hex hash");
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
        let sid = self.public_key_hex[..8].to_string();
        vclock.tick(&sid);
        self.balance += amount;
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
        );
        let hash_bytes = hex::decode(&hash).expect("valid hex hash");
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
        // Adversary tries every pathological balance.
        for malicious in [0u64, 1, u64::MAX, u64::MAX - 1, 1_000_000_001] {
            let _ = chain.open(malicious, &mut vc);
        }
        assert_eq!(chain.balance, snapshot_balance);
        assert_eq!(chain.nonce, snapshot_nonce);
        assert_eq!(chain.chain.len(), 1);
        assert_eq!(chain.chain[0].hash, snapshot_hash);
    }
}
