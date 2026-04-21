//! Global ledger indexing all account chains.

use crate::block::Block;
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
    /// and recomputed Blake3 hash.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`ArxiaError`] from [`verify_block`]:
    /// - [`ArxiaError::HashMismatch`] if the stored hash does not match.
    /// - [`ArxiaError::SignatureInvalid`] if the signature does not verify
    ///   against the account public key.
    /// - [`ArxiaError::InvalidKey`] if the account hex is not a valid
    ///   Ed25519 public key.
    pub fn add_block(&mut self, block: Block) -> Result<(), ArxiaError> {
        verify_block(&block)?;
        self.chains
            .entry(block.account.clone())
            .or_default()
            .push(block);
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
}
