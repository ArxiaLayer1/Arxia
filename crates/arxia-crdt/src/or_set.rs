//! OR-Set (Observed-Remove Set) CRDT with add-wins semantics.

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
    /// Remove an element (removes all observed tags).
    pub fn remove(&mut self, element: &T) {
        self.elements.remove(element);
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
