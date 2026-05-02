//! OR-Set (Observed-Remove Set) CRDT with add-wins semantics.
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

/// OR-Set with unique tags for add-wins conflict resolution.
#[derive(Debug, Clone, PartialEq)]
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
    pub fn add(&mut self, element: T) {
        self.tag_counter += 1;
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
}
