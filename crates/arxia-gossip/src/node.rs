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
    /// Conflicts accumulated across all `merge_registry` calls. A caller
    /// who ignores the return value of `merge_registry` still finds every
    /// detected conflict here, available for later ORV-based resolution.
    ///
    /// The field is drained by [`GossipNode::drain_pending_conflicts`];
    /// consumers are expected to poll this from the consensus layer on
    /// every L1-sync cycle.
    pub pending_conflicts: Vec<NonceConflict>,
}

impl GossipNode {
    /// Create a new gossip node.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            known_blocks: Vec::new(),
            nonce_registry: NonceRegistry::new(),
            peers: Vec::new(),
            pending_conflicts: Vec::new(),
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
    ///
    /// Returns the list of conflicts encountered during this merge (same
    /// `(account, nonce)` in both sides with different hashes). The same
    /// conflicts are also appended to [`Self::pending_conflicts`] so that
    /// a caller which ignores the return value does not silently lose
    /// double-spend detection — a CRIT-009 regression guard.
    ///
    /// Callers SHOULD drain [`Self::pending_conflicts`] on every L1-sync
    /// cycle and route the entries to ORV-based conflict resolution.
    pub fn merge_registry(&mut self, remote: &NonceRegistry) -> Vec<NonceConflict> {
        let conflicts = merge_nonce_registries(&mut self.nonce_registry, remote);
        // Defense-in-depth: even if the immediate caller drops the return
        // value, the conflicts survive in pending_conflicts for later
        // consumption by the consensus layer.
        self.pending_conflicts.extend(conflicts.iter().cloned());
        conflicts
    }

    /// Drain and return every conflict accumulated since the last drain.
    /// Intended to be polled by the consensus / ORV layer; the internal
    /// buffer is emptied on every call.
    pub fn drain_pending_conflicts(&mut self) -> Vec<NonceConflict> {
        std::mem::take(&mut self.pending_conflicts)
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

    // ========================================================================
    // Adversarial tests for Bug CRIT-009 (merge_registry silently drops Vec)
    //
    // These tests pin the defense-in-depth property: conflicts are
    // observable even when the immediate caller ignores the Vec returned
    // by merge_registry.
    // ========================================================================

    #[test]
    fn test_gossip_merge_registry_returns_conflicts_to_caller() {
        // Canonical scenario: local has (Alice, 1) -> hash_bob; remote
        // has (Alice, 1) -> hash_carol. Caller merges and receives the
        // NonceConflict. Pre-008 behavior silently dropped the Vec.
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        let hash_bob = [0xB0u8; 32];
        let hash_carol = [0xCAu8; 32];
        node.nonce_registry.insert((alice, 1), hash_bob);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), hash_carol);

        let conflicts = node.merge_registry(&remote);
        assert_eq!(conflicts.len(), 1, "merge_registry must surface conflicts");
        let c = &conflicts[0];
        assert_eq!(c.key, (alice, 1));
        assert_eq!(c.local_hash, hash_bob);
        assert_eq!(c.remote_hash, hash_carol);
        // Local entry preserved (lattice-level handled by merge_nonce_registries)
        assert_eq!(node.nonce_registry[&(alice, 1)], hash_bob);
    }

    #[test]
    fn test_gossip_merge_registry_conflicts_survive_dropped_return() {
        // Defense-in-depth: a caller that discards the Vec (the exact
        // CRIT-009 pattern: `let _ = node.merge_registry(...)`) still
        // finds every conflict in node.pending_conflicts, because
        // merge_registry mirrors them into that field.
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        node.nonce_registry.insert((alice, 1), [0xB0; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), [0xCA; 32]);

        // Caller throws the return value on the floor.
        let _ = node.merge_registry(&remote);

        // Conflicts still accessible.
        let drained = node.drain_pending_conflicts();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].key, (alice, 1));

        // Second drain returns empty (idempotent by design).
        assert!(node.drain_pending_conflicts().is_empty());
    }

    #[test]
    fn test_gossip_merge_registry_pending_conflicts_accumulate_across_merges() {
        // Multiple merges with different conflicts accumulate in
        // pending_conflicts until drained.
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        node.nonce_registry.insert((alice, 1), [0x01; 32]);
        node.nonce_registry.insert((bob, 2), [0x02; 32]);

        let mut r1 = NonceRegistry::new();
        r1.insert((alice, 1), [0x11; 32]);
        let mut r2 = NonceRegistry::new();
        r2.insert((bob, 2), [0x22; 32]);

        let _ = node.merge_registry(&r1);
        let _ = node.merge_registry(&r2);

        let drained = node.drain_pending_conflicts();
        assert_eq!(drained.len(), 2, "both conflicts must be retained");
    }

    #[test]
    fn test_gossip_merge_registry_no_conflict_no_pending_entry() {
        // Clean merge (remote has only new entries, no overlap) must not
        // pollute pending_conflicts with spurious entries.
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        node.nonce_registry.insert((alice, 1), [0x01; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert(([0xBBu8; 32], 5), [0x22; 32]);

        let conflicts = node.merge_registry(&remote);
        assert!(conflicts.is_empty());
        assert!(node.pending_conflicts.is_empty());
    }

    #[test]
    fn test_gossip_merge_registry_idempotent_same_entry_no_conflict() {
        // Identical (key, value) in local and remote is a no-op, not a
        // conflict. Pending_conflicts must stay empty.
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        node.nonce_registry.insert((alice, 1), [0x01; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), [0x01; 32]);

        let conflicts = node.merge_registry(&remote);
        assert!(conflicts.is_empty());
        assert!(node.pending_conflicts.is_empty());
    }
}
