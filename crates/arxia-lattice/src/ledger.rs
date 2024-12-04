//! Global ledger indexing all account chains.

use crate::block::Block;
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

    /// Add a block to the ledger.
    pub fn add_block(&mut self, block: Block) {
        self.chains
            .entry(block.account.clone())
            .or_default()
            .push(block);
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
