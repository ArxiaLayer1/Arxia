//! Vector Clock pruning: 7-day expiry and forced pruning at 256 entries.

use crate::vector_clock::CrdtVectorClock;
use arxia_core::MAX_VECTOR_CLOCK_ENTRIES;

/// Prune vector clock entries older than 7 days.
pub fn prune_expired(_vc: &mut CrdtVectorClock) {
    // TODO(M6-M12): Implement timestamp-based pruning.
    // Each VC entry needs an associated last-update timestamp.
}

/// Force-prune if entries exceed MAX_VECTOR_CLOCK_ENTRIES (256).
pub fn force_prune(vc: &mut CrdtVectorClock) {
    if vc.clocks.len() <= MAX_VECTOR_CLOCK_ENTRIES {
        return;
    }
    let mut entries: Vec<(String, u64)> = vc.clocks.iter().map(|(k, &v)| (k.clone(), v)).collect();
    entries.sort_by_key(|(_, v)| *v);
    let to_remove = entries.len() - MAX_VECTOR_CLOCK_ENTRIES;
    for (key, _) in entries.into_iter().take(to_remove) {
        vc.clocks.remove(&key);
    }
}
