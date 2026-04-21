//! Gossip node implementation.

use crate::nonce_registry::{merge_nonce_registries, sync_nonces_before_l1, SyncResult};
use arxia_core::ArxiaError;
use arxia_lattice::block::Block;
use arxia_lattice::validation::verify_block;
use std::collections::BTreeMap;

/// A gossip node that participates in the mesh network.
pub struct GossipNode {
    /// This node identifier.
    pub node_id: String,
    /// Blocks known to this node.
    pub known_blocks: Vec<Block>,
    /// Nonce registry for L1 finality tracking.
    pub nonce_registry: BTreeMap<[u8; 32], (u64, [u8; 32])>,
    /// Connected peer node IDs.
    pub peers: Vec<String>,
}

impl GossipNode {
    /// Create a new gossip node.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            known_blocks: Vec::new(),
            nonce_registry: BTreeMap::new(),
            peers: Vec::new(),
        }
    }

    /// Add a block to the known set and register its nonce, after verifying
    /// its Ed25519 signature and Blake3 hash.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`ArxiaError`] from
    /// [`arxia_lattice::validation::verify_block`].
    pub fn add_block(&mut self, block: Block) -> Result<(), ArxiaError> {
        verify_block(&block)?;

        // Conversions below cannot fail: verify_block has already validated
        // that block.hash is a 64-char hex string and block.account is a
        // valid 32-byte Ed25519 public key.
        let hash_bytes: [u8; 32] = hex::decode(&block.hash)
            .map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?
            .try_into()
            .map_err(|_| ArxiaError::HashMismatch)?;
        let account_bytes: [u8; 32] = hex::decode(&block.account)
            .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| ArxiaError::InvalidKey("bad key length".into()))?;

        self.nonce_registry
            .insert(hash_bytes, (block.nonce, account_bytes));
        self.known_blocks.push(block);
        Ok(())
    }

    /// Merge a remote nonce registry into this node registry.
    pub fn merge_registry(&mut self, remote: &BTreeMap<[u8; 32], (u64, [u8; 32])>) {
        merge_nonce_registries(&mut self.nonce_registry, remote);
    }

    /// Check sync status against a peer registry.
    pub fn check_sync(&self, peer_registry: &BTreeMap<[u8; 32], (u64, [u8; 32])>) -> SyncResult {
        sync_nonces_before_l1(&self.nonce_registry, peer_registry)
    }

    /// Add a peer.
    pub fn add_peer(&mut self, peer_id: String) {
        if !self.peers.contains(&peer_id) {
            self.peers.push(peer_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_lattice::chain::{AccountChain, VectorClock};

    #[test]
    fn test_gossip_add_block_accepts_signed() {
        let mut node = GossipNode::new("n1".into());
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let block = alice.open(1_000_000, &mut vc);
        assert!(node.add_block(block).is_ok());
        assert_eq!(node.known_blocks.len(), 1);
        assert_eq!(node.nonce_registry.len(), 1);
    }

    #[test]
    fn test_gossip_add_block_rejects_unsigned() {
        let mut node = GossipNode::new("n1".into());
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc);
        block.signature = vec![0u8; 64];
        let result = node.add_block(block);
        assert!(matches!(result, Err(ArxiaError::SignatureInvalid(_))));
        assert!(node.known_blocks.is_empty());
        assert!(node.nonce_registry.is_empty());
    }

    #[test]
    fn test_gossip_add_block_rejects_tampered_hash() {
        let mut node = GossipNode::new("n1".into());
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc);
        block.hash = "0".repeat(64);
        let result = node.add_block(block);
        assert!(matches!(result, Err(ArxiaError::HashMismatch)));
        assert!(node.known_blocks.is_empty());
        assert!(node.nonce_registry.is_empty());
    }
}
