//! Relay receipts for proving message forwarding.

use serde::{Deserialize, Serialize};

/// A receipt proving that a relay node forwarded a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReceipt {
    /// The relay node public key (hex-encoded).
    pub relay_id: String,
    /// Hash of the relayed block or message.
    pub message_hash: String,
    /// Unix timestamp when the relay occurred.
    pub timestamp: u64,
    /// Ed25519 signature by the relay node.
    pub signature: Vec<u8>,
    /// Number of hops this message has traversed.
    pub hop_count: u8,
}

/// A batch of relay receipts for efficient transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayBatch {
    /// Receipts in this batch.
    pub receipts: Vec<RelayReceipt>,
    /// Batch identifier.
    pub batch_id: u64,
}

impl RelayBatch {
    /// Create a new empty batch.
    pub fn new(batch_id: u64) -> Self {
        Self {
            receipts: Vec::new(),
            batch_id,
        }
    }

    /// Add a receipt to the batch.
    pub fn add(&mut self, receipt: RelayReceipt) {
        self.receipts.push(receipt);
    }

    /// Number of receipts in the batch.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}
