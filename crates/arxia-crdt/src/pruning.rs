//! Vector Clock pruning for the Arxia CRDT layer.
//!
//! Arxia Vector Clocks are bounded to [`MAX_VECTOR_CLOCK_ENTRIES`] active
//! entries. Two pruning mechanisms keep the clock manageable:
//!
//! - **Expired pruning**: removes entries for nodes that have been silent for
//!   more than [`EXPIRY_DAYS`] days. Applied periodically during normal
//!   operation.
//! - **Forced pruning**: when the entry count exceeds the hard cap, the entries
//!   with the lowest counter values are evicted immediately. This may create
//!   causal ambiguity — callers must handle `PruningResult::ForcedPruning` by
//!   falling back to the hash tiebreaker in conflict resolution.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of active entries in a single Vector Clock.
/// Entries beyond this limit trigger forced pruning.
pub const MAX_VECTOR_CLOCK_ENTRIES: usize = 256;

/// Number of days of silence after which a node's entry is considered expired.
pub const EXPIRY_DAYS: u64 = 7;

/// Seconds in a day.
const SECS_PER_DAY: u64 = 86_400;

/// Result of a pruning operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruningResult {
    /// No pruning was necessary.
    Clean,
    /// One or more expired entries were removed. Causal ordering is preserved.
    ExpiredRemoved {
        /// Number of expired entries that were removed.
        count: usize,
    },
    /// The entry cap was exceeded. Low-counter entries were evicted.
    /// Causal ordering may be ambiguous for evicted nodes — use hash
    /// tiebreaker in conflict resolution.
    ForcedPruning {
        /// Number of entries that were forcibly evicted.
        evicted: usize,
    },
}

/// A timestamped Vector Clock entry.
///
/// `last_seen_unix` records when this node last produced a block or gossip
/// message, used to determine expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorClockEntry {
    /// Lamport counter for this node.
    pub counter: u64,
    /// Unix timestamp (seconds) of the last observed event from this node.
    pub last_seen_unix: u64,
}

/// Returns the current Unix timestamp in seconds.
///
/// Falls back to 0 on platforms where `SystemTime` is unavailable.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Removes entries from `clock` whose `last_seen_unix` is older than
/// `expiry_days` days relative to `reference_time_unix`.
///
/// This is the standard pruning path. It preserves causal ordering for all
/// remaining entries.
///
/// # Arguments
///
/// * `clock` - Mutable reference to the Vector Clock entry map.
/// * `expiry_days` - Age threshold in days. Entries older than this are removed.
/// * `reference_time_unix` - The timestamp to measure expiry against. Pass
///   `now_unix()` for live operation, or a fixed value for deterministic tests.
///
/// # Returns
///
/// [`PruningResult::Clean`] if nothing was removed,
/// [`PruningResult::ExpiredRemoved`] with the count of evicted entries otherwise.
pub fn prune_expired(
    clock: &mut BTreeMap<[u8; 32], VectorClockEntry>,
    expiry_days: u64,
    reference_time_unix: u64,
) -> PruningResult {
    let expiry_threshold_secs = expiry_days.saturating_mul(SECS_PER_DAY);

    let before = clock.len();

    clock.retain(|_node_id, entry| {
        let age_secs = reference_time_unix.saturating_sub(entry.last_seen_unix);
        age_secs < expiry_threshold_secs
    });

    let removed = before.saturating_sub(clock.len());

    if removed == 0 {
        PruningResult::Clean
    } else {
        PruningResult::ExpiredRemoved { count: removed }
    }
}

/// Enforces the hard entry cap on `clock`.
///
/// If `clock.len() > MAX_VECTOR_CLOCK_ENTRIES`, evicts entries with the
/// smallest counter values until the count is within the cap. In case of
/// counter ties, eviction order follows lexicographic node ID order
/// (BTreeMap iteration order — deterministic).
///
/// # Warning
///
/// Forced pruning may create causal ambiguity for evicted nodes. Callers
/// that receive [`PruningResult::ForcedPruning`] MUST fall back to the
/// hash tiebreaker in ORV conflict resolution rather than relying on
/// Vector Clock ordering alone.
///
/// # Returns
///
/// [`PruningResult::Clean`] if no cap was exceeded,
/// [`PruningResult::ForcedPruning`] with the eviction count otherwise.
pub fn prune_to_cap(
    clock: &mut BTreeMap<[u8; 32], VectorClockEntry>,
    cap: usize,
) -> PruningResult {
    if clock.len() <= cap {
        return PruningResult::Clean;
    }

    let to_evict = clock.len() - cap;

    // Collect entries sorted by counter ascending (lowest counter evicted first).
    // BTreeMap gives deterministic iteration order on node_id, so ties are
    // broken consistently across all nodes.
    let mut entries: Vec<([u8; 32], u64)> = clock
        .iter()
        .map(|(id, entry)| (*id, entry.counter))
        .collect();

    // Sort by counter ascending, then by node_id for deterministic tie-breaking.
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let evicted_ids: Vec<[u8; 32]> =
        entries.iter().take(to_evict).map(|(id, _)| *id).collect();

    for id in &evicted_ids {
        clock.remove(id);
    }

    PruningResult::ForcedPruning {
        evicted: evicted_ids.len(),
    }
}

/// Applies both pruning strategies in sequence:
///
/// 1. Remove expired entries (older than `expiry_days`).
/// 2. If still over cap, apply forced pruning.
///
/// This is the standard call site for periodic maintenance. The return value
/// reflects the most severe pruning action taken.
pub fn prune_all(
    clock: &mut BTreeMap<[u8; 32], VectorClockEntry>,
    expiry_days: u64,
    cap: usize,
    reference_time_unix: u64,
) -> PruningResult {
    let expired_result = prune_expired(clock, expiry_days, reference_time_unix);
    let forced_result = prune_to_cap(clock, cap);

    // Return the most severe result.
    match forced_result {
        PruningResult::ForcedPruning { evicted } => PruningResult::ForcedPruning { evicted },
        _ => expired_result,
    }
}

// ─── Convenience wrappers using protocol defaults ──────────────────────────

/// Prune expired entries using the default 7-day expiry and the current time.
pub fn prune_expired_default(
    clock: &mut BTreeMap<[u8; 32], VectorClockEntry>,
) -> PruningResult {
    prune_expired(clock, EXPIRY_DAYS, now_unix())
}

/// Apply full pruning using protocol defaults (`EXPIRY_DAYS`, `MAX_VECTOR_CLOCK_ENTRIES`).
pub fn prune_all_default(
    clock: &mut BTreeMap<[u8; 32], VectorClockEntry>,
) -> PruningResult {
    prune_all(clock, EXPIRY_DAYS, MAX_VECTOR_CLOCK_ENTRIES, now_unix())
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(counter: u64, last_seen_unix: u64) -> VectorClockEntry {
        VectorClockEntry {
            counter,
            last_seen_unix,
        }
    }

    fn node_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    /// Reference timestamp: 2026-01-01 00:00:00 UTC
    const REF_TIME: u64 = 1_767_225_600;

    #[test]
    fn test_prune_expired_removes_old_entries() {
        let mut clock = BTreeMap::new();
        // Active node: last seen 3 days ago
        clock.insert(node_id(1), make_entry(10, REF_TIME - 3 * 86_400));
        // Expired node: last seen 8 days ago
        clock.insert(node_id(2), make_entry(5, REF_TIME - 8 * 86_400));

        let result = prune_expired(&mut clock, EXPIRY_DAYS, REF_TIME);

        assert_eq!(result, PruningResult::ExpiredRemoved { count: 1 });
        assert!(clock.contains_key(&node_id(1)));
        assert!(!clock.contains_key(&node_id(2)));
    }

    #[test]
    fn test_prune_expired_clean_when_all_fresh() {
        let mut clock = BTreeMap::new();
        clock.insert(node_id(1), make_entry(10, REF_TIME - 1 * 86_400));
        clock.insert(node_id(2), make_entry(5, REF_TIME - 2 * 86_400));

        let result = prune_expired(&mut clock, EXPIRY_DAYS, REF_TIME);

        assert_eq!(result, PruningResult::Clean);
        assert_eq!(clock.len(), 2);
    }

    #[test]
    fn test_prune_expired_removes_all_when_all_stale() {
        let mut clock = BTreeMap::new();
        clock.insert(node_id(1), make_entry(10, REF_TIME - 10 * 86_400));
        clock.insert(node_id(2), make_entry(5, REF_TIME - 14 * 86_400));

        let result = prune_expired(&mut clock, EXPIRY_DAYS, REF_TIME);

        assert_eq!(result, PruningResult::ExpiredRemoved { count: 2 });
        assert!(clock.is_empty());
    }

    #[test]
    fn test_prune_to_cap_evicts_lowest_counters() {
        let mut clock = BTreeMap::new();
        clock.insert(node_id(1), make_entry(100, REF_TIME));
        clock.insert(node_id(2), make_entry(5, REF_TIME));   // lowest — evicted
        clock.insert(node_id(3), make_entry(50, REF_TIME));

        let result = prune_to_cap(&mut clock, 2);

        assert_eq!(result, PruningResult::ForcedPruning { evicted: 1 });
        assert!(!clock.contains_key(&node_id(2))); // lowest counter evicted
        assert!(clock.contains_key(&node_id(1)));
        assert!(clock.contains_key(&node_id(3)));
    }

    #[test]
    fn test_prune_to_cap_clean_when_under_cap() {
        let mut clock = BTreeMap::new();
        clock.insert(node_id(1), make_entry(10, REF_TIME));

        let result = prune_to_cap(&mut clock, 256);

        assert_eq!(result, PruningResult::Clean);
        assert_eq!(clock.len(), 1);
    }

    #[test]
    fn test_prune_to_cap_tie_broken_by_node_id() {
        let mut clock = BTreeMap::new();
        // Both have counter 0 — eviction order determined by node_id
        clock.insert(node_id(0x01), make_entry(0, REF_TIME));
        clock.insert(node_id(0x02), make_entry(0, REF_TIME));
        clock.insert(node_id(0x03), make_entry(10, REF_TIME));

        let result = prune_to_cap(&mut clock, 2);

        assert_eq!(result, PruningResult::ForcedPruning { evicted: 1 });
        // node_id(0x01) has smaller byte value — evicted first
        assert!(!clock.contains_key(&node_id(0x01)));
        assert!(clock.contains_key(&node_id(0x02)));
        assert!(clock.contains_key(&node_id(0x03)));
    }

    #[test]
    fn test_prune_all_prefers_expired_over_forced() {
        let mut clock = BTreeMap::new();
        // Fresh node
        clock.insert(node_id(1), make_entry(100, REF_TIME - 1 * 86_400));
        // Expired node
        clock.insert(node_id(2), make_entry(50, REF_TIME - 10 * 86_400));

        // Cap of 2 — no forced pruning needed after expired removal
        let result = prune_all(&mut clock, EXPIRY_DAYS, 2, REF_TIME);

        assert_eq!(result, PruningResult::ExpiredRemoved { count: 1 });
        assert_eq!(clock.len(), 1);
    }

    #[test]
    fn test_prune_all_forced_takes_precedence() {
        let mut clock = BTreeMap::new();
        // All fresh but over cap
        for i in 0u8..5 {
            clock.insert(node_id(i), make_entry(i as u64 * 10, REF_TIME - 86_400));
        }

        let result = prune_all(&mut clock, EXPIRY_DAYS, 3, REF_TIME);

        assert!(matches!(result, PruningResult::ForcedPruning { evicted: 2 }));
        assert_eq!(clock.len(), 3);
    }

    #[test]
    fn test_max_entries_constant() {
        // Protocol constant must not be changed without an AIP
        assert_eq!(MAX_VECTOR_CLOCK_ENTRIES, 256);
    }

    #[test]
    fn test_expiry_days_constant() {
        // Protocol constant must not be changed without an AIP
        assert_eq!(EXPIRY_DAYS, 7);
    }
}
