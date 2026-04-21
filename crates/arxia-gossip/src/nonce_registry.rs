//! Nonce registry for L1 finality synchronization.
//!
//! The registry maps `(account, nonce)` to the hash of the block that
//! asserted that nonce. Keying on the hash itself (the previous design)
//! missed a whole class of double-spends: two blocks with the same
//! `(account, nonce)` but different destinations produce different
//! hashes, so both would be recorded and the conflict would go
//! undetected until reconciliation. The new key guarantees that any
//! attempt to register a second hash for the same `(account, nonce)`
//! surfaces as a conflict.

use std::collections::BTreeMap;

/// Key used by the nonce registry: (account public key, nonce).
pub type NonceKey = ([u8; 32], u64);

/// Registry value: the hash of the block that claimed this `(account, nonce)`.
pub type NonceEntry = [u8; 32];

/// Main registry type.
pub type NonceRegistry = BTreeMap<NonceKey, NonceEntry>;

/// A detected conflict: same `(account, nonce)`, divergent hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceConflict {
    /// The `(account, nonce)` the conflict is about.
    pub key: NonceKey,
    /// The hash already stored locally.
    pub local_hash: NonceEntry,
    /// The hash offered by the remote registry.
    pub remote_hash: NonceEntry,
}

/// Result of a nonce synchronization attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResult {
    /// Registries are fully synchronized.
    Success,
    /// Registries differ; contains the number of mismatched entries.
    Mismatch(usize),
    /// No neighbors available for synchronization.
    NoNeighbors,
}

/// Merge `remote` into `local`.
///
/// Conflict policy: if both registries know about the same
/// `(account, nonce)` but disagree on the block hash, neither is
/// silently overwritten. The local entry is preserved, and the
/// conflict is returned to the caller for resolution (typically via
/// ORV stake-weighted voting; see `arxia-consensus::conflict`). New
/// entries from `remote` (unknown to `local`) are inserted as usual.
pub fn merge_nonce_registries(
    local: &mut NonceRegistry,
    remote: &NonceRegistry,
) -> Vec<NonceConflict> {
    let mut conflicts = Vec::new();
    for (key, remote_hash) in remote {
        match local.get(key) {
            Some(local_hash) if local_hash == remote_hash => { /* identical, no-op */ }
            Some(local_hash) => {
                conflicts.push(NonceConflict {
                    key: *key,
                    local_hash: *local_hash,
                    remote_hash: *remote_hash,
                });
            }
            None => {
                local.insert(*key, *remote_hash);
            }
        }
    }
    conflicts
}

/// Returns `true` if `registry` already has an entry for `(account, nonce)`
/// with a hash different from `candidate_hash` — i.e., registering
/// `candidate_hash` would create a conflict.
pub fn has_conflict(
    registry: &NonceRegistry,
    account: [u8; 32],
    nonce: u64,
    candidate_hash: [u8; 32],
) -> bool {
    matches!(registry.get(&(account, nonce)), Some(h) if *h != candidate_hash)
}

/// Checks whether nonce registries are synchronized for L1 finality.
pub fn sync_nonces_before_l1(local: &NonceRegistry, remote: &NonceRegistry) -> SyncResult {
    if remote.is_empty() {
        return SyncResult::NoNeighbors;
    }

    let mut mismatches = 0;

    for (key, local_hash) in local {
        match remote.get(key) {
            Some(remote_hash) if remote_hash == local_hash => {}
            _ => mismatches += 1,
        }
    }

    for key in remote.keys() {
        if !local.contains_key(key) {
            mismatches += 1;
        }
    }

    if mismatches == 0 {
        SyncResult::Success
    } else {
        SyncResult::Mismatch(mismatches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn test_merge_inserts_new_entries() {
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        let mut remote = NonceRegistry::new();
        remote.insert((acc(2), 3), h(0xBB));
        let conflicts = merge_nonce_registries(&mut local, &remote);
        assert!(conflicts.is_empty());
        assert_eq!(local[&(acc(1), 5)], h(0xAA));
        assert_eq!(local[&(acc(2), 3)], h(0xBB));
    }

    #[test]
    fn test_merge_identical_entries_noop() {
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        let mut remote = NonceRegistry::new();
        remote.insert((acc(1), 5), h(0xAA));
        let conflicts = merge_nonce_registries(&mut local, &remote);
        assert!(conflicts.is_empty());
        assert_eq!(local[&(acc(1), 5)], h(0xAA));
    }

    #[test]
    fn test_merge_detects_conflict_same_account_same_nonce_different_hash() {
        // Core regression for Bug 5: two blocks with identical
        // (account, nonce) but different destinations — and therefore
        // different hashes — must surface as a conflict.
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        let mut remote = NonceRegistry::new();
        remote.insert((acc(1), 5), h(0xBB));
        let conflicts = merge_nonce_registries(&mut local, &remote);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].key, (acc(1), 5));
        assert_eq!(conflicts[0].local_hash, h(0xAA));
        assert_eq!(conflicts[0].remote_hash, h(0xBB));
        // Local entry NOT overwritten
        assert_eq!(local[&(acc(1), 5)], h(0xAA));
    }

    #[test]
    fn test_merge_conflict_does_not_corrupt_other_entries() {
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        local.insert((acc(2), 1), h(0xCC));
        let mut remote = NonceRegistry::new();
        remote.insert((acc(1), 5), h(0xBB)); // conflict
        remote.insert((acc(3), 7), h(0xDD)); // new
        let conflicts = merge_nonce_registries(&mut local, &remote);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(local[&(acc(1), 5)], h(0xAA));
        assert_eq!(local[&(acc(2), 1)], h(0xCC));
        assert_eq!(local[&(acc(3), 7)], h(0xDD));
    }

    #[test]
    fn test_has_conflict_detects_divergent_hash() {
        let mut registry = NonceRegistry::new();
        registry.insert((acc(1), 5), h(0xAA));
        assert!(has_conflict(&registry, acc(1), 5, h(0xBB)));
    }

    #[test]
    fn test_has_conflict_false_for_same_hash() {
        let mut registry = NonceRegistry::new();
        registry.insert((acc(1), 5), h(0xAA));
        assert!(!has_conflict(&registry, acc(1), 5, h(0xAA)));
    }

    #[test]
    fn test_has_conflict_false_for_unknown_key() {
        let registry = NonceRegistry::new();
        assert!(!has_conflict(&registry, acc(1), 5, h(0xAA)));
    }

    #[test]
    fn test_sync_success() {
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        let remote = local.clone();
        assert_eq!(sync_nonces_before_l1(&local, &remote), SyncResult::Success);
    }

    #[test]
    fn test_sync_mismatch_counts_distinct_hashes() {
        let mut local = NonceRegistry::new();
        local.insert((acc(1), 5), h(0xAA));
        let mut remote = NonceRegistry::new();
        remote.insert((acc(1), 5), h(0xBB));
        assert_eq!(
            sync_nonces_before_l1(&local, &remote),
            SyncResult::Mismatch(1)
        );
    }

    #[test]
    fn test_sync_no_neighbors() {
        let local = NonceRegistry::new();
        let remote = NonceRegistry::new();
        assert_eq!(
            sync_nonces_before_l1(&local, &remote),
            SyncResult::NoNeighbors
        );
    }

    #[test]
    fn test_adversarial_double_spend_two_partitions() {
        // Alice signs two SENDs at nonce=1 — one to Bob, one to Carol.
        // Each partition records its own hash. Merging must surface
        // the conflict rather than silently overwriting.
        let alice = acc(0xAA);
        let to_bob_hash = h(0xB0);
        let to_carol_hash = h(0xCA);

        let mut partition_a = NonceRegistry::new();
        partition_a.insert((alice, 1), to_bob_hash);

        let mut partition_b = NonceRegistry::new();
        partition_b.insert((alice, 1), to_carol_hash);

        let conflicts = merge_nonce_registries(&mut partition_a, &partition_b);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].key, (alice, 1));
        assert_ne!(conflicts[0].local_hash, conflicts[0].remote_hash);
    }
}
