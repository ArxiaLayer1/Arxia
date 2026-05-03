//! OR-Set (Observed-Remove Set) CRDT with add-wins semantics.
//!
//! # Serializable for replica transmission (MED-015, commit 054)
//!
//! [`ORSet`] derives `Serialize` / `Deserialize`. CRDTs travel
//! between replicas to converge state — without serde derives,
//! the type couldn't be sent over the wire, defeating the
//! purpose of being a CRDT. The audit (MED-015):
//!
//! > Can't be sent over the wire — defeats the CRDT purpose
//! > if it's intended to travel between replicas.
//! > Suggested fix direction: derive `Serialize`/`Deserialize`;
//! > add round-trip tests.
//!
//! # `remove` returns existence (MED-014, commit 053)
//!
//! Pre-fix [`ORSet::remove`] returned `()`, so callers couldn't
//! distinguish "removed an element that was present" from
//! "tried to remove an element that wasn't there". The audit
//! (MED-014):
//!
//! > Remove an element that doesn't exist; silent no-op.
//! > Callers can't distinguish "removed" from "wasn't there"
//! > — state-machine logic based on that distinction is unsafe.
//! > Suggested fix direction: `Result<bool, Error>` return.
//!
//! Post-fix [`ORSet::remove`] returns `bool`: `true` if the
//! element was present and removed, `false` if it was already
//! absent. There's no error case for this CRDT operation, so
//! `bool` is more precise than `Result<bool, _>`. The pattern
//! parallels HIGH-021 / commit 039 (`StorageBackend::delete`)
//! at the storage layer; this commit closes the same
//! existence-signal gap at the CRDT layer.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// OR-Set with unique tags for add-wins conflict resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ORSet<T: Ord + Eq + Clone> {
    elements: BTreeMap<T, BTreeSet<String>>,
    tag_counter: u64,
    node_id: String,
}

impl<T: Ord + Eq + Clone> ORSet<T> {
    /// Create a new empty OR-Set for a given node.
    pub fn new(node_id: &str) -> Self {
        Self {
            elements: BTreeMap::new(),
            tag_counter: 0,
            node_id: node_id.to_string(),
        }
    }
    /// Add an element with a unique tag.
    ///
    /// MED-013 (commit 057): uses `saturating_add` instead of
    /// `+=` to defend against `u64::MAX` wrap. At wrap, the
    /// counter sticks at `u64::MAX` and subsequent adds reuse
    /// the last tag — duplicate-tag detection is up to the
    /// `BTreeSet` (which dedups via `insert`). Practical
    /// wrap-time on a single node is ~292 billion years at
    /// 1 add/ns; defense-in-depth only.
    pub fn add(&mut self, element: T) {
        self.tag_counter = self.tag_counter.saturating_add(1);
        let tag = format!("{}:{}", self.node_id, self.tag_counter);
        self.elements.entry(element).or_default().insert(tag);
    }
    /// Remove an element (drops all observed tags).
    ///
    /// Returns `true` if the element was present and was
    /// removed; `false` if it was already absent. See MED-014
    /// in the module docstring.
    pub fn remove(&mut self, element: &T) -> bool {
        self.elements.remove(element).is_some()
    }
    /// Check if an element is in the set.
    pub fn contains(&self, element: &T) -> bool {
        self.elements
            .get(element)
            .is_some_and(|tags| !tags.is_empty())
    }
    /// Merge with another OR-Set (union of tags).
    pub fn merge(&mut self, other: &ORSet<T>) {
        for (elem, other_tags) in &other.elements {
            let tags = self.elements.entry(elem.clone()).or_default();
            for tag in other_tags {
                tags.insert(tag.clone());
            }
        }
    }
    /// Number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_or_set_add_then_contains() {
        let mut s: ORSet<String> = ORSet::new("node-a");
        s.add("alice".to_string());
        assert!(s.contains(&"alice".to_string()));
        assert_eq!(s.len(), 1);
    }

    // ============================================================
    // MED-014 (commit 053) — remove returns bool indicating
    // whether the element existed.
    // ============================================================

    #[test]
    fn test_remove_returns_true_when_element_was_present() {
        // PRIMARY MED-014 PIN: the canonical positive case.
        let mut s: ORSet<String> = ORSet::new("node-a");
        s.add("alice".to_string());
        let removed = s.remove(&"alice".to_string());
        assert!(removed, "removing a present element returns true");
        assert!(!s.contains(&"alice".to_string()));
    }

    #[test]
    fn test_remove_returns_false_when_element_was_absent() {
        // PRIMARY MED-014 PIN: callers can now distinguish
        // "wasn't there" from "successfully removed".
        let mut s: ORSet<String> = ORSet::new("node-a");
        let removed = s.remove(&"never-added".to_string());
        assert!(!removed, "removing an absent element returns false");
    }

    #[test]
    fn test_remove_then_redelete_signals_existence_then_absence() {
        // Sequence pin: first remove true, second on the same
        // (now-absent) element returns false.
        let mut s: ORSet<String> = ORSet::new("node-a");
        s.add("alice".to_string());
        assert!(s.remove(&"alice".to_string()));
        assert!(!s.remove(&"alice".to_string()));
    }

    #[test]
    fn test_remove_signals_existence_independently_per_element() {
        // Per-element signal: removing one absent element doesn't
        // affect another present element's count or signal.
        let mut s: ORSet<String> = ORSet::new("node-a");
        s.add("alice".to_string());
        assert!(!s.remove(&"bob".to_string()));
        assert_eq!(s.len(), 1);
        assert!(s.contains(&"alice".to_string()));
        assert!(s.remove(&"alice".to_string()));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn test_remove_after_merge_signals_existence_of_merged_element() {
        // CRDT semantics: an element merged in from another
        // replica counts as "present" for the existence
        // signal. Pin against any future regression that
        // gates `remove`'s signal on local-add-only.
        let mut a: ORSet<String> = ORSet::new("node-a");
        let mut b: ORSet<String> = ORSet::new("node-b");
        b.add("carol".to_string());
        a.merge(&b);
        assert!(a.contains(&"carol".to_string()));
        assert!(a.remove(&"carol".to_string()));
        assert!(!a.contains(&"carol".to_string()));
    }

    // ============================================================
    // MED-015 (commit 054) — ORSet derives Serialize/Deserialize
    // for replica transmission.
    // ============================================================

    #[test]
    fn test_or_set_serializes_to_json_round_trip() {
        // PRIMARY MED-015 PIN: an OR-Set populated with state
        // round-trips through serde_json with `PartialEq`
        // equality. This is the canonical "wire-transmissible
        // CRDT" property the audit asked to pin.
        let mut s: ORSet<String> = ORSet::new("node-a");
        s.add("alice".to_string());
        s.add("bob".to_string());
        s.add("carol".to_string());
        let _removed = s.remove(&"bob".to_string());
        let json = serde_json::to_string(&s).expect("serialize");
        let decoded: ORSet<String> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, decoded);
    }

    #[test]
    fn test_or_set_round_trip_preserves_contains_and_len() {
        // Defense-in-depth: PartialEq is one signal; explicitly
        // pin the API surface (contains / len / is_empty) on
        // the round-tripped value.
        let mut s: ORSet<String> = ORSet::new("node-z");
        for n in 0..5 {
            s.add(format!("element-{n}"));
        }
        let json = serde_json::to_string(&s).unwrap();
        let decoded: ORSet<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 5);
        for n in 0..5 {
            assert!(decoded.contains(&format!("element-{n}")));
        }
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_or_set_empty_round_trips() {
        // Boundary: an empty OR-Set serializes and deserializes
        // without losing the node_id.
        let s: ORSet<String> = ORSet::new("node-empty");
        let json = serde_json::to_string(&s).unwrap();
        let decoded: ORSet<String> = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(s, decoded);
    }

    #[test]
    fn test_or_set_round_trip_then_merge_converges() {
        // CRDT-flavored property: if a replica receives a
        // serialized OR-Set, deserializes it, and merges it
        // into its own, the result is equivalent to merging
        // the original directly. Wire-transmissible CRDT
        // semantics pinned end-to-end.
        let mut a: ORSet<String> = ORSet::new("node-a");
        a.add("x".to_string());
        let mut b: ORSet<String> = ORSet::new("node-b");
        b.add("y".to_string());
        let json = serde_json::to_string(&b).unwrap();
        let decoded_b: ORSet<String> = serde_json::from_str(&json).unwrap();
        let mut a_via_wire = a.clone();
        a_via_wire.merge(&decoded_b);
        let mut a_direct = a.clone();
        a_direct.merge(&b);
        // The two replicas converge to the same state
        // regardless of whether b traveled over the wire.
        assert_eq!(a_via_wire, a_direct);
    }

    // ============================================================
    // MED-013 (commit 057) — tag_counter saturating_add defends
    // against u64::MAX wrap.
    // ============================================================

    /// Build an OR-Set with the tag counter pre-loaded close
    /// to u64::MAX. Used by the saturating-arithmetic tests
    /// without spinning 2^64 iterations.
    fn or_set_at_counter(node: &str, start: u64) -> ORSet<String> {
        // Fields are private; serde round-trip from a
        // manually-constructed JSON is the in-test pre-load
        // path.
        let json = format!(
            r#"{{"elements":{{}},"tag_counter":{},"node_id":"{}"}}"#,
            start, node
        );
        serde_json::from_str(&json).expect("manually-built ORSet json")
    }

    #[test]
    fn test_tag_counter_saturates_at_u64_max() {
        // PRIMARY MED-013 PIN: an OR-Set whose counter has
        // somehow reached u64::MAX must NOT panic on add. The
        // counter saturates and subsequent adds reuse the
        // last tag (BTreeSet dedups). State remains consistent.
        let mut s = or_set_at_counter("node-overflow", u64::MAX);
        // The first add should NOT panic (the +=  in the
        // pre-fix version would).
        s.add("alice".to_string());
        // Counter saturated.
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(&format!("{}", u64::MAX)));
        assert!(s.contains(&"alice".to_string()));
    }

    #[test]
    fn test_tag_counter_increments_normally_when_far_from_wrap() {
        // Regression: the saturating change doesn't break the
        // common case of counter incrementing 0 → 1 → 2 ...
        let mut s: ORSet<String> = ORSet::new("node-a");
        for i in 0..5 {
            s.add(format!("e-{i}"));
        }
        // Round-trip and pin the counter at exactly 5.
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"tag_counter\":5"));
    }

    #[test]
    fn test_tag_counter_just_below_max_saturates_on_one_add() {
        // Boundary: counter = u64::MAX - 1, one add brings it
        // to u64::MAX (no saturation triggered yet, just the
        // last representable value).
        let mut s = or_set_at_counter("node-edge", u64::MAX - 1);
        s.add("x".to_string());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(&format!("\"tag_counter\":{}", u64::MAX)));
        // One more add — saturates (no panic).
        s.add("y".to_string());
        let json2 = serde_json::to_string(&s).unwrap();
        assert!(json2.contains(&format!("\"tag_counter\":{}", u64::MAX)));
    }
}
