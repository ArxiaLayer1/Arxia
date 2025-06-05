//! Nonce registry for L1 finality synchronization.

use std::collections::BTreeMap;

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

/// Merges two nonce registries, keeping the entry with the higher nonce.
pub fn merge_nonce_registries(
    local: &mut BTreeMap<[u8; 32], (u64, [u8; 32])>,
    remote: &BTreeMap<[u8; 32], (u64, [u8; 32])>,
) {
    for (key, (remote_nonce, remote_account)) in remote {
        let entry = local.entry(*key).or_insert((0, *remote_account));
        if *remote_nonce > entry.0 {
            entry.0 = *remote_nonce;
            entry.1 = *remote_account;
        }
    }
}

/// Checks whether nonce registries are synchronized for L1 finality.
pub fn sync_nonces_before_l1(
    local: &BTreeMap<[u8; 32], (u64, [u8; 32])>,
    remote: &BTreeMap<[u8; 32], (u64, [u8; 32])>,
) -> SyncResult {
    if remote.is_empty() {
        return SyncResult::NoNeighbors;
    }

    let mut mismatches = 0;

    for (key, (local_nonce, _)) in local {
        match remote.get(key) {
            Some((remote_nonce, _)) if remote_nonce == local_nonce => {}
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

    #[test]
    fn test_merge_nonce_registries() {
        let mut local = BTreeMap::new();
        local.insert([1u8; 32], (5u64, [0xAA; 32]));
        local.insert([2u8; 32], (10u64, [0xBB; 32]));

        let mut remote = BTreeMap::new();
        remote.insert([1u8; 32], (3u64, [0xAA; 32]));
        remote.insert([2u8; 32], (15u64, [0xBB; 32]));
        remote.insert([3u8; 32], (7u64, [0xCC; 32]));

        merge_nonce_registries(&mut local, &remote);

        assert_eq!(local[&[1u8; 32]].0, 5);
        assert_eq!(local[&[2u8; 32]].0, 15);
        assert_eq!(local[&[3u8; 32]].0, 7);
    }

    #[test]
    fn test_sync_nonces_success() {
        let mut local = BTreeMap::new();
        local.insert([1u8; 32], (5u64, [0xAA; 32]));
        let remote = local.clone();
        assert_eq!(sync_nonces_before_l1(&local, &remote), SyncResult::Success);
    }

    #[test]
    fn test_sync_nonces_mismatch() {
        let mut local = BTreeMap::new();
        local.insert([1u8; 32], (5u64, [0xAA; 32]));
        let mut remote = BTreeMap::new();
        remote.insert([1u8; 32], (10u64, [0xAA; 32]));
        assert_eq!(
            sync_nonces_before_l1(&local, &remote),
            SyncResult::Mismatch(1)
        );
    }

    #[test]
    fn test_sync_nonces_no_neighbors() {
        let local = BTreeMap::new();
        let remote = BTreeMap::new();
        assert_eq!(
            sync_nonces_before_l1(&local, &remote),
            SyncResult::NoNeighbors
        );
    }
}
