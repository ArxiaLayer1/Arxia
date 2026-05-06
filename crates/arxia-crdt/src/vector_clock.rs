//! Canonical Vector Clock with BTreeMap for deterministic ordering.
//!
//! # LOW-006 (commit 077): two VC types, deliberately distinct
//!
//! The Arxia workspace has **two** vector-clock types with
//! near-identical names. They are NOT interchangeable:
//!
//! - [`CrdtVectorClock`] (this file, `arxia_crdt`) — used by the
//!   CRDT reconciliation layer. **No cap** on entries (CRDTs
//!   absorb arbitrary participation: any peer that has ever
//!   spoken to us is in the clock and stays there).
//! - `arxia_lattice::VectorClock` — used at block-creation time.
//!   **Capped** at `arxia_core::MAX_VECTOR_CLOCK_ENTRIES` (commit
//!   061) to bound adversarial peers' memory impact at the hot
//!   block-write path.
//!
//! Both use `BTreeMap` for deterministic key iteration ; the
//! distinction is the cap, not the data structure. Pick the type
//! by use case: serialise/reconcile → CRDT form ;
//! tick-on-block-creation → lattice form. The two-name choice is
//! deliberate and preserved (LOW-006 documents the contract).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Vector clock using BTreeMap for deterministic key ordering.
///
/// **NOT the same as `arxia_lattice::VectorClock`.** See module
/// docstring for the deliberate two-type split (LOW-006).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrdtVectorClock {
    /// Ordered map from node ID to clock value.
    pub clocks: BTreeMap<String, u64>,
}

impl CrdtVectorClock {
    /// Create a new empty vector clock.
    pub fn new() -> Self {
        Self {
            clocks: BTreeMap::new(),
        }
    }
    /// Increment the clock for a node.
    pub fn tick(&mut self, node_id: &str) {
        let c = self.clocks.entry(node_id.to_string()).or_insert(0);
        *c += 1;
    }
    /// Merge with another vector clock (element-wise max).
    pub fn merge(&mut self, other: &CrdtVectorClock) {
        for (k, &v) in &other.clocks {
            let e = self.clocks.entry(k.clone()).or_insert(0);
            *e = (*e).max(v);
        }
    }
    /// Returns true if self causally happened before other.
    pub fn happened_before(&self, other: &CrdtVectorClock) -> bool {
        let mut at_least_one_less = false;
        for (k, &sv) in &self.clocks {
            let ov = other.clocks.get(k).copied().unwrap_or(0);
            if sv > ov {
                return false;
            }
            if sv < ov {
                at_least_one_less = true;
            }
        }
        for (k, &ov) in &other.clocks {
            if !self.clocks.contains_key(k) && ov > 0 {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }
    /// Returns true if concurrent with other.
    pub fn is_concurrent(&self, other: &CrdtVectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self) && self != other
    }
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.clocks.len()
    }
    /// Whether the clock is empty.
    pub fn is_empty(&self) -> bool {
        self.clocks.is_empty()
    }
}

impl Default for CrdtVectorClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crdt_vector_clock_tick_and_merge() {
        let mut vc1 = CrdtVectorClock::new();
        vc1.tick("node_a");
        vc1.tick("node_a");
        let mut vc2 = CrdtVectorClock::new();
        vc2.tick("node_a");
        vc2.tick("node_b");
        vc2.tick("node_b");
        vc1.merge(&vc2);
        assert_eq!(vc1.clocks["node_a"], 2);
        assert_eq!(vc1.clocks["node_b"], 2);
    }

    #[test]
    fn test_crdt_vector_clock_happened_before() {
        let mut vc1 = CrdtVectorClock::new();
        vc1.tick("a");
        let mut vc2 = vc1.clone();
        vc2.tick("a");
        assert!(vc1.happened_before(&vc2));
        assert!(!vc2.happened_before(&vc1));
    }

    #[test]
    fn test_crdt_vector_clock_concurrent() {
        let mut vc1 = CrdtVectorClock::new();
        vc1.tick("a");
        let mut vc2 = CrdtVectorClock::new();
        vc2.tick("b");
        assert!(vc1.is_concurrent(&vc2));
    }

    #[test]
    fn test_crdt_vector_clock_btreemap_deterministic_order() {
        let mut vc = CrdtVectorClock::new();
        vc.tick("z");
        vc.tick("a");
        vc.tick("m");
        let keys: Vec<&String> = vc.clocks.keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    // ============================================================
    // LOW-006 (commit 077) — pin the deliberate two-VC-types
    // distinction. The CRDT form uses BTreeMap (deterministic
    // ordering for serialisation) ; the lattice form uses
    // HashMap with a cap (commit 061) for fast block-creation
    // ticks. Both names are similar by design but the
    // semantic split must remain visible in tests.
    // ============================================================

    #[test]
    fn test_crdt_vc_uses_btreemap_for_ordering() {
        // PRIMARY LOW-006 PIN: keys iterate in sorted order on
        // CrdtVectorClock. This is the property that
        // distinguishes it from the lattice form.
        let mut vc = CrdtVectorClock::new();
        for k in &["delta", "alpha", "echo", "bravo", "charlie"] {
            vc.tick(k);
        }
        let keys: Vec<&String> = vc.clocks.keys().collect();
        assert_eq!(
            keys,
            vec!["alpha", "bravo", "charlie", "delta", "echo"],
            "CRDT form must iterate keys in sorted order"
        );
    }

    #[test]
    fn test_crdt_vc_round_trip_via_serde_preserves_order() {
        // BTreeMap-backed serialization is order-stable. Pin
        // that JSON-serialising and re-deserialising gives the
        // same key order.
        let mut vc = CrdtVectorClock::new();
        vc.tick("c");
        vc.tick("a");
        vc.tick("b");
        let json = serde_json::to_string(&vc).unwrap();
        let restored: CrdtVectorClock = serde_json::from_str(&json).unwrap();
        let restored_keys: Vec<&String> = restored.clocks.keys().collect();
        assert_eq!(restored_keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_crdt_vc_distinct_from_lattice_vc_struct_name() {
        // Compile-time pin: the type name `CrdtVectorClock` is
        // not the same as `arxia_lattice::VectorClock`. We
        // can't import the lattice form from this crate
        // (would create a circular dep), but we CAN pin that
        // the CRDT form's name is `CrdtVectorClock` and not
        // accidentally renamed to `VectorClock` in a
        // refactor.
        let _ty: CrdtVectorClock = CrdtVectorClock::new();
        // The intentional name disambiguation is the whole
        // LOW-006 contract — this test exists as a tripwire
        // for any future refactor that tries to consolidate.
    }
}
