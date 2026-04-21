//! Gossip node implementation.

use crate::nonce_registry::{
    merge_nonce_registries, sync_nonces_before_l1, NonceConflict, NonceRegistry, SyncResult,
};
use arxia_core::ArxiaError;
use arxia_lattice::block::Block;
use arxia_lattice::validation::verify_block;

/// A gossip node that participates in the mesh network.
pub struct GossipNode {
    /// This node identifier.
    pub node_id: String,
    /// Blocks known to this node.
    pub known_blocks: Vec<Block>,
    /// Nonce registry for L1 finality tracking. Keyed by (account, nonce),
    /// value is the block hash that claimed that (account, nonce).
    pub nonce_registry: NonceRegistry,
    /// Connected peer node IDs.
    pub peers: Vec<String>,
}

impl GossipNode {
    /// Create a new gossip node.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            known_blocks: Vec::new(),
            nonce_registry: NonceRegistry::new(),
            peers: Vec::new(),
        }
    }

    /// Add a block to the known set and register its (account, nonce) →
    /// hash entry.
    ///
    /// # Errors
    ///
    /// Propagates [`verify_block`] errors. Additionally returns
    /// [`ArxiaError::DoubleSpend`] if the registry already holds a
    /// different hash for the same `(account, nonce)` — i.e., this block
    /// would silently replace a conflicting one.
    pub fn add_block(&mut self, block: Block) -> Result<(), ArxiaError> {
        verify_block(&block)?;

        let hash_bytes: [u8; 32] = hex::decode(&block.hash)
            .map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?
            .try_into()
            .map_err(|_| ArxiaError::HashMismatch)?;
        let account_bytes: [u8; 32] = hex::decode(&block.account)
            .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| ArxiaError::InvalidKey("bad key length".into()))?;

        let key = (account_bytes, block.nonce);
        match self.nonce_registry.get(&key) {
            Some(existing) if *existing == hash_bytes => {
                // Already known, idempotent.
            }
            Some(_) => {
                return Err(ArxiaError::DoubleSpend { nonce: block.nonce });
            }
            None => {
                self.nonce_registry.insert(key, hash_bytes);
            }
        }
        self.known_blocks.push(block);
        Ok(())
    }

    /// Merge a remote nonce registry into this node registry.
    /// Returns the list of conflicts encountered (same `(account, nonce)`,
    /// different hash). An empty vector means the merge was clean.
    pub fn merge_registry(&mut self, remote: &NonceRegistry) -> Vec<NonceConflict> {
        merge_nonce_registries(&mut self.nonce_registry, remote)
    }

    /// Check sync status against a peer registry.
    pub fn check_sync(&self, peer_registry: &NonceRegistry) -> SyncResult {
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
        let block = alice.open(1_000_000, &mut vc).unwrap();
        assert!(node.add_block(block).is_ok());
        assert_eq!(node.known_blocks.len(), 1);
        assert_eq!(node.nonce_registry.len(), 1);
    }

    #[test]
    fn test_gossip_add_block_rejects_unsigned() {
        let mut node = GossipNode::new("n1".into());
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
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
        let mut block = alice.open(1_000_000, &mut vc).unwrap();
        block.hash = "0".repeat(64);
        let result = node.add_block(block);
        assert!(matches!(result, Err(ArxiaError::HashMismatch)));
    }

    #[test]
    fn test_gossip_add_block_detects_double_spend_on_same_account_nonce() {
        // Alice signs two SENDs at the same nonce with two destinations.
        // The first add_block succeeds; the second must return
        // DoubleSpend because the registry already has (alice, N) → hash1.
        let mut node = GossipNode::new("n1".into());
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let send_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        // Rewind alice as if the SEND never happened on her partition
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let send_carol = alice.send(carol.id(), 100, &mut vc).unwrap();
        assert_eq!(send_bob.nonce, send_carol.nonce);
        assert_ne!(send_bob.hash, send_carol.hash);

        let open_block = alice.chain[0].clone();
        node.add_block(open_block).unwrap();
        node.add_block(send_bob).unwrap();
        let err = node.add_block(send_carol).unwrap_err();
        assert!(matches!(err, ArxiaError::DoubleSpend { nonce } if nonce == 2));
    }

    #[test]
    fn test_merge_registry_returns_conflicts() {
        let mut node = GossipNode::new("n1".into());
        let acc = [0xAAu8; 32];
        node.nonce_registry.insert((acc, 1), [0xB0; 32]);
        let mut remote = NonceRegistry::new();
        remote.insert((acc, 1), [0xCA; 32]);
        let conflicts = node.merge_registry(&remote);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].key, (acc, 1));
    }
}
