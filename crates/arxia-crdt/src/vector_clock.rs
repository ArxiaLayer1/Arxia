//! Canonical Vector Clock with BTreeMap for deterministic ordering.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Vector clock using BTreeMap for deterministic key ordering.
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
}
