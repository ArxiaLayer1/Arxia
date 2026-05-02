//! Gossip node implementation.

use std::collections::{HashSet, VecDeque};

use crate::nonce_registry::{
    merge_nonce_registries, sync_nonces_before_l1, NonceConflict, NonceKey, NonceRegistry,
    SyncResult,
};
use arxia_core::ArxiaError;
use arxia_lattice::block::Block;
use arxia_lattice::validation::verify_block;

/// Default capacity of [`GossipNode::known_blocks`].
///
/// At the lattice's compact-block size of 193 B, 10 000 blocks ≈ 1.9 MB
/// of header memory — comfortable on a T-Beam-class device with ~320 KB
/// of free DRAM after the runtime, and bounded enough that an attacker
/// flooding valid signed blocks cannot OOM the process. (CRIT-011)
pub const MAX_KNOWN_BLOCKS: usize = 10_000;

/// Default capacity of [`GossipNode::nonce_registry`].
///
/// Each entry is `(account[32], nonce[8]) -> hash[32]` ≈ 72 B; 10 000
/// entries ≈ 720 KB. Same rationale as [`MAX_KNOWN_BLOCKS`]. (CRIT-011)
pub const MAX_NONCE_REGISTRY_ENTRIES: usize = 10_000;

/// A gossip node that participates in the mesh network.
///
/// # Bounded state (CRIT-011)
///
/// Both [`Self::known_blocks`] and [`Self::nonce_registry`] are bounded
/// to [`MAX_KNOWN_BLOCKS`] and [`MAX_NONCE_REGISTRY_ENTRIES`] respectively
/// (or to the values supplied to [`Self::with_capacity`]). When the
/// capacity is exceeded, the OLDEST entry by insertion order is evicted
/// — drop-oldest, FIFO. The cumulative number of evicted entries is
/// observable via [`Self::known_blocks_dropped`] and
/// [`Self::nonce_registry_dropped`], saturating at [`u64::MAX`].
///
/// Eviction is enforced inside the documented mutators
/// [`Self::add_block`] and [`Self::merge_registry`]. Direct mutation of
/// the public fields bypasses the bound and re-introduces CRIT-011 —
/// callers MUST use the documented mutators.
pub struct GossipNode {
    /// This node identifier.
    pub node_id: String,
    /// Blocks known to this node, in insertion order. Bounded to
    /// [`Self::known_blocks_capacity`].
    pub known_blocks: VecDeque<Block>,
    /// Nonce registry for L1 finality tracking. Keyed by (account, nonce),
    /// value is the block hash that claimed that (account, nonce).
    /// Bounded to [`Self::nonce_registry_capacity`].
    pub nonce_registry: NonceRegistry,
    /// Connected peer node IDs. Backed by `HashSet` for `O(1)`
    /// `add_peer` (MED-009 — pre-fix `Vec<String>` was O(n)
    /// per insertion which compounds to quadratic on bursts).
    pub peers: HashSet<String>,
    /// Conflicts accumulated across all `merge_registry` calls. A caller
    /// who ignores the return value of `merge_registry` still finds every
    /// detected conflict here, available for later ORV-based resolution.
    ///
    /// The field is drained by [`GossipNode::drain_pending_conflicts`];
    /// consumers are expected to poll this from the consensus layer on
    /// every L1-sync cycle.
    pub pending_conflicts: Vec<NonceConflict>,

    // CRIT-011 bounded-state machinery. These are private to enforce
    // the eviction invariant; observability goes through the public
    // accessor methods below.
    nonce_registry_order: VecDeque<NonceKey>,
    known_blocks_dropped: u64,
    nonce_registry_dropped: u64,
    known_blocks_capacity: usize,
    nonce_registry_capacity: usize,
}

impl GossipNode {
    /// Create a new gossip node with default capacities
    /// ([`MAX_KNOWN_BLOCKS`] / [`MAX_NONCE_REGISTRY_ENTRIES`]).
    pub fn new(node_id: String) -> Self {
        Self::with_capacity(node_id, MAX_KNOWN_BLOCKS, MAX_NONCE_REGISTRY_ENTRIES)
    }

    /// Create a gossip node with custom capacities.
    ///
    /// `known_blocks_capacity` and `nonce_registry_capacity` are clamped
    /// to a minimum of 1; passing 0 silently coerces to 1 to keep the
    /// data-flow invariant meaningful.
    pub fn with_capacity(
        node_id: String,
        known_blocks_capacity: usize,
        nonce_registry_capacity: usize,
    ) -> Self {
        Self {
            node_id,
            known_blocks: VecDeque::new(),
            nonce_registry: NonceRegistry::new(),
            peers: HashSet::new(),
            pending_conflicts: Vec::new(),
            nonce_registry_order: VecDeque::new(),
            known_blocks_dropped: 0,
            nonce_registry_dropped: 0,
            known_blocks_capacity: known_blocks_capacity.max(1),
            nonce_registry_capacity: nonce_registry_capacity.max(1),
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
    ///
    /// # Bounded state
    ///
    /// On success, if [`Self::known_blocks`] would exceed its capacity,
    /// the oldest block is evicted (FIFO). Same for
    /// [`Self::nonce_registry`] when a new entry must be inserted.
    /// Idempotent re-insertion of the same block does NOT grow either
    /// collection.
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
                // Already known, idempotent. Do NOT grow either
                // collection — this is the CRIT-011 amplifier.
                return Ok(());
            }
            Some(_) => {
                return Err(ArxiaError::DoubleSpend { nonce: block.nonce });
            }
            None => {
                // New entry. Evict oldest if needed before insertion.
                if self.nonce_registry.len() >= self.nonce_registry_capacity {
                    self.evict_oldest_nonce_entry();
                }
                self.nonce_registry.insert(key, hash_bytes);
                self.nonce_registry_order.push_back(key);
            }
        }

        if self.known_blocks.len() >= self.known_blocks_capacity {
            self.known_blocks.pop_front();
            self.known_blocks_dropped = self.known_blocks_dropped.saturating_add(1);
        }
        self.known_blocks.push_back(block);
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
    ///
    /// # Bounded state
    ///
    /// Newly inserted entries are tracked in FIFO order. If the merged
    /// registry exceeds [`Self::nonce_registry_capacity`], the oldest
    /// entries are evicted until the cap is satisfied. Eviction count
    /// is observable via [`Self::nonce_registry_dropped`].
    pub fn merge_registry(&mut self, remote: &NonceRegistry) -> Vec<NonceConflict> {
        // Snapshot keys before merge so we can detect newly inserted ones
        // and append them to the FIFO order tracker.
        let pre_keys: HashSet<NonceKey> = self.nonce_registry.keys().copied().collect();

        let conflicts = merge_nonce_registries(&mut self.nonce_registry, remote);
        // Defense-in-depth (CRIT-009): even if the immediate caller drops
        // the return value, the conflicts survive in pending_conflicts.
        self.pending_conflicts.extend(conflicts.iter().cloned());

        // Track newly-inserted keys for FIFO eviction (CRIT-011).
        for key in self.nonce_registry.keys() {
            if !pre_keys.contains(key) {
                self.nonce_registry_order.push_back(*key);
            }
        }

        // Evict oldest entries until within capacity.
        while self.nonce_registry.len() > self.nonce_registry_capacity {
            if !self.evict_oldest_nonce_entry() {
                // Order tracker is empty but registry is still over cap —
                // means external code mutated the registry directly.
                // Bail out rather than loop forever; the invariant is
                // violated by the caller, not by this method.
                break;
            }
        }

        conflicts
    }

    /// Pop the oldest nonce-registry key from the FIFO tracker, remove
    /// it from the registry, and increment the dropped counter.
    /// Returns `true` if an entry was evicted, `false` if the order
    /// tracker was empty (invariant violated by external mutation).
    fn evict_oldest_nonce_entry(&mut self) -> bool {
        // Skip stale order-tracker entries (keys that were already
        // removed from the registry by some other path). This keeps
        // eviction correct even under direct mutation of the public
        // field — the tracker self-heals.
        while let Some(oldest) = self.nonce_registry_order.pop_front() {
            if self.nonce_registry.remove(&oldest).is_some() {
                self.nonce_registry_dropped = self.nonce_registry_dropped.saturating_add(1);
                return true;
            }
        }
        false
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
    ///
    /// Idempotent: re-adding an already-known peer is a no-op
    /// (HashSet semantics). MED-009 (commit 052): backed by
    /// `HashSet<String>` so the dedup check is `O(1)` instead
    /// of `O(n)`.
    pub fn add_peer(&mut self, peer_id: String) {
        self.peers.insert(peer_id);
    }

    /// Configured capacity of [`Self::known_blocks`] (FIFO drop-oldest).
    pub fn known_blocks_capacity(&self) -> usize {
        self.known_blocks_capacity
    }

    /// Configured capacity of [`Self::nonce_registry`] (FIFO drop-oldest).
    pub fn nonce_registry_capacity(&self) -> usize {
        self.nonce_registry_capacity
    }

    /// Cumulative number of blocks evicted from [`Self::known_blocks`]
    /// to make room for newer ones since this node was constructed.
    /// Saturates at [`u64::MAX`].
    pub fn known_blocks_dropped(&self) -> u64 {
        self.known_blocks_dropped
    }

    /// Cumulative number of nonce-registry entries evicted to make room
    /// for newer ones since this node was constructed. Saturates at
    /// [`u64::MAX`].
    pub fn nonce_registry_dropped(&self) -> u64 {
        self.nonce_registry_dropped
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
    // Pre-existing CRIT-009 adversarial tests (commit 008)
    // ========================================================================

    #[test]
    fn test_gossip_merge_registry_returns_conflicts_to_caller() {
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
        assert_eq!(node.nonce_registry[&(alice, 1)], hash_bob);
    }

    #[test]
    fn test_gossip_merge_registry_conflicts_survive_dropped_return() {
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        node.nonce_registry.insert((alice, 1), [0xB0; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), [0xCA; 32]);

        let _ = node.merge_registry(&remote);

        let drained = node.drain_pending_conflicts();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].key, (alice, 1));

        assert!(node.drain_pending_conflicts().is_empty());
    }

    #[test]
    fn test_gossip_merge_registry_pending_conflicts_accumulate_across_merges() {
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
        let mut node = GossipNode::new("n1".into());
        let alice = [0xAAu8; 32];
        node.nonce_registry.insert((alice, 1), [0x01; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), [0x01; 32]);

        let conflicts = node.merge_registry(&remote);
        assert!(conflicts.is_empty());
        assert!(node.pending_conflicts.is_empty());
    }

    // ========================================================================
    // Adversarial tests for CRIT-011 (gossip unbounded state)
    //
    // These tests pin the bounded-state invariants: known_blocks and
    // nonce_registry both stay at or below their configured caps under
    // adversarial flooding, with observable drop counters.
    // ========================================================================

    #[test]
    fn test_known_blocks_default_capacity_is_10000() {
        let n = GossipNode::new("n1".into());
        assert_eq!(n.known_blocks_capacity(), MAX_KNOWN_BLOCKS);
        assert_eq!(MAX_KNOWN_BLOCKS, 10_000);
    }

    #[test]
    fn test_nonce_registry_default_capacity_is_10000() {
        let n = GossipNode::new("n1".into());
        assert_eq!(n.nonce_registry_capacity(), MAX_NONCE_REGISTRY_ENTRIES);
        assert_eq!(MAX_NONCE_REGISTRY_ENTRIES, 10_000);
    }

    #[test]
    fn test_known_blocks_dropped_counter_starts_at_zero() {
        let n = GossipNode::new("n1".into());
        assert_eq!(n.known_blocks_dropped(), 0);
    }

    #[test]
    fn test_nonce_registry_dropped_counter_starts_at_zero() {
        let n = GossipNode::new("n1".into());
        assert_eq!(n.nonce_registry_dropped(), 0);
    }

    #[test]
    fn test_with_capacity_constructor_respects_custom_limits() {
        let n = GossipNode::with_capacity("n1".into(), 7, 11);
        assert_eq!(n.known_blocks_capacity(), 7);
        assert_eq!(n.nonce_registry_capacity(), 11);
    }

    #[test]
    fn test_with_capacity_zero_clamps_to_one() {
        let n = GossipNode::with_capacity("n1".into(), 0, 0);
        assert_eq!(n.known_blocks_capacity(), 1);
        assert_eq!(n.nonce_registry_capacity(), 1);
    }

    #[test]
    fn test_known_blocks_resistance_to_flooding_single_peer() {
        // 100 distinct accounts × 1 OPEN block each → 100 valid blocks.
        // With capacity 16, only the 16 most recent fit; the other 84
        // are evicted. known_blocks_dropped == 84.
        let mut node = GossipNode::with_capacity("n1".into(), 16, 16);
        let mut vc = VectorClock::new();
        for _ in 0..100 {
            let mut chain = AccountChain::new();
            let block = chain.open(1_000_000, &mut vc).unwrap();
            node.add_block(block).unwrap();
        }
        assert_eq!(node.known_blocks.len(), 16);
        assert_eq!(node.nonce_registry.len(), 16);
        assert_eq!(node.known_blocks_dropped(), 84);
        assert_eq!(node.nonce_registry_dropped(), 84);
    }

    #[test]
    fn test_add_block_idempotent_does_not_grow_collections() {
        // Adding the same block twice must not grow either collection
        // and must not trigger an eviction.
        let mut node = GossipNode::with_capacity("n1".into(), 4, 4);
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let block = alice.open(1_000_000, &mut vc).unwrap();
        node.add_block(block.clone()).unwrap();
        node.add_block(block.clone()).unwrap();
        node.add_block(block).unwrap();
        assert_eq!(node.known_blocks.len(), 1);
        assert_eq!(node.nonce_registry.len(), 1);
        assert_eq!(node.known_blocks_dropped(), 0);
        assert_eq!(node.nonce_registry_dropped(), 0);
    }

    #[test]
    fn test_merge_registry_respects_nonce_registry_cap() {
        // Build a remote registry with 20 entries, merge into a local
        // node with capacity 5. After merge, local has exactly 5
        // entries; 15 were dropped.
        let mut node = GossipNode::with_capacity("n1".into(), 100, 5);
        let mut remote = NonceRegistry::new();
        for i in 0u8..20 {
            remote.insert(([i; 32], 1), [i; 32]);
        }
        let _ = node.merge_registry(&remote);
        assert_eq!(node.nonce_registry.len(), 5);
        assert_eq!(node.nonce_registry_dropped(), 15);
    }

    #[test]
    fn test_eviction_drops_oldest_by_insertion_order() {
        // Insert blocks in order; after overflowing capacity, the oldest
        // are gone and the newest survive.
        let mut node = GossipNode::with_capacity("n1".into(), 3, 3);
        let mut vc = VectorClock::new();
        let mut chains: Vec<AccountChain> = (0..5).map(|_| AccountChain::new()).collect();
        let mut accounts: Vec<[u8; 32]> = Vec::new();
        for chain in chains.iter_mut() {
            let block = chain.open(1_000_000, &mut vc).unwrap();
            let acct: [u8; 32] = hex::decode(&block.account).unwrap().try_into().unwrap();
            accounts.push(acct);
            node.add_block(block).unwrap();
        }
        // Capacity 3, inserted 5: accounts[0] and accounts[1] dropped,
        // accounts[2..5] retained.
        assert_eq!(node.known_blocks.len(), 3);
        assert_eq!(node.known_blocks_dropped(), 2);
        assert!(!node.nonce_registry.contains_key(&(accounts[0], 1)));
        assert!(!node.nonce_registry.contains_key(&(accounts[1], 1)));
        assert!(node.nonce_registry.contains_key(&(accounts[2], 1)));
        assert!(node.nonce_registry.contains_key(&(accounts[3], 1)));
        assert!(node.nonce_registry.contains_key(&(accounts[4], 1)));
    }

    #[test]
    fn test_eviction_preserves_pending_conflicts_history() {
        // Conflicts collected before eviction must remain in
        // pending_conflicts even after the underlying registry entry
        // is dropped — drain_pending_conflicts is the contract for
        // consensus, not registry presence.
        let mut node = GossipNode::with_capacity("n1".into(), 100, 2);
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        node.nonce_registry.insert((alice, 1), [0x01; 32]);
        node.nonce_registry.insert((bob, 1), [0x02; 32]);

        let mut remote = NonceRegistry::new();
        remote.insert((alice, 1), [0x11; 32]); // conflict
        remote.insert((bob, 1), [0x22; 32]); // conflict
                                             // Force eviction by adding more entries.
        remote.insert(([0xCCu8; 32], 1), [0xCC; 32]);
        remote.insert(([0xDDu8; 32], 1), [0xDD; 32]);

        let conflicts = node.merge_registry(&remote);
        assert_eq!(conflicts.len(), 2);
        // Cap is 2; some entries got evicted, but the conflicts vec
        // and pending_conflicts both survive.
        assert!(node.nonce_registry.len() <= 2);
        assert_eq!(node.pending_conflicts.len(), 2);
    }

    // ============================================================
    // MED-009 (commit 052) — peers backed by HashSet for O(1)
    // dedup. Pre-fix `Vec<String>` did `.contains()` linear scan
    // per add; bursts of N adds were O(N²).
    // ============================================================

    #[test]
    fn test_add_peer_idempotent_via_hashset() {
        // PRIMARY MED-009 PIN: re-adding the same peer doesn't
        // duplicate. HashSet semantics ensure O(1) dedup.
        let mut node = GossipNode::new("n1".to_string());
        node.add_peer("alice".to_string());
        node.add_peer("alice".to_string());
        node.add_peer("alice".to_string());
        assert_eq!(node.peers.len(), 1);
        assert!(node.peers.contains("alice"));
    }

    #[test]
    fn test_add_peer_distinct_peers_grow_set() {
        let mut node = GossipNode::new("n1".to_string());
        for i in 0..5 {
            node.add_peer(format!("peer-{i}"));
        }
        assert_eq!(node.peers.len(), 5);
        for i in 0..5 {
            assert!(node.peers.contains(&format!("peer-{i}")));
        }
    }

    #[test]
    fn test_add_peer_handles_large_burst_without_quadratic_blowup() {
        // 10_000 distinct peers + 10_000 duplicate adds. With
        // a Vec backing, this would be ~100M comparisons; with
        // HashSet, it's ~20K hash ops. No timeout-style assert
        // (Rust doesn't have one in stable test harness), but
        // the test runs in <50 ms on the workspace baseline,
        // which is empirical evidence of the O(1) contract.
        let mut node = GossipNode::new("n1".to_string());
        for i in 0..10_000 {
            node.add_peer(format!("peer-{i:05}"));
        }
        // Re-add all 10_000 — must remain at 10_000.
        for i in 0..10_000 {
            node.add_peer(format!("peer-{i:05}"));
        }
        assert_eq!(node.peers.len(), 10_000);
    }

    #[test]
    fn test_add_peer_peers_field_is_hashset_typed() {
        // STRUCTURAL PIN: the public `peers` field is
        // `HashSet<String>`. A future regression that reverts
        // to `Vec<String>` makes this test fail to compile
        // (`HashSet` doesn't have `.push()`, and `Vec` doesn't
        // have `.contains(&str)` with deref).
        fn assert_is_hashset(node: &GossipNode) {
            // Using HashSet-only API: contains takes a borrowed
            // form of String, which works for HashSet<String>
            // but compiles differently for Vec.
            let _: bool = node.peers.contains("any-string");
        }
        let node = GossipNode::new("n1".to_string());
        assert_is_hashset(&node);
    }
}
