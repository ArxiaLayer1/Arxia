//! Storage backends for Arxia.
//!
//! # Delete signals existence (HIGH-021, commit 039)
//!
//! [`StorageBackend::delete`] returns `Result<bool, ArxiaError>`,
//! where `Ok(true)` means "the key existed and was removed" and
//! `Ok(false)` means "the key was already absent". Pre-fix the
//! return type was `Result<(), ArxiaError>` — a no-op on a missing
//! key was indistinguishable from a successful removal of a present
//! key. The audit (HIGH-021):
//!
//! > Code path calls `delete("x")` expecting the key existed; it
//! > didn't; the caller proceeds as if the deletion meant
//! > something. Silent no-op on "should-have-existed" keys masks
//! > upstream state corruption.
//!
//! Callers that don't care about the existence signal can simply
//! discard the bool with `let _ = store.delete(...)?;` or
//! `.delete(...).map(|_| ())`. Callers that DO care now have a
//! typed signal at the trust boundary.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use arxia_core::ArxiaError;
use std::collections::HashMap;

/// Trait for key-value storage backends.
pub trait StorageBackend {
    /// Store a value under the given key.
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError>;
    /// Retrieve a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError>;
    /// Delete a key-value pair. Returns `Ok(true)` if the key
    /// existed and was removed, `Ok(false)` if the key was already
    /// absent. See HIGH-021 in the module docstring for the
    /// rationale.
    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError>;
    /// Check if a key exists.
    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError>;
}

/// In-memory storage backend for testing.
pub struct MemoryStorage {
    data: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryStorage {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        Ok(self.data.get(key).cloned())
    }
    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
        // `HashMap::remove` returns `Option<V>` — `Some` iff the
        // key was present. Map to the existence-signaling bool.
        Ok(self.data.remove(key).is_some())
    }
    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        Ok(self.data.contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_put_get() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        let result = store.get(b"key1").unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_memory_storage_get_missing() {
        let store = MemoryStorage::new();
        let result = store.get(b"missing").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_memory_storage_delete() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        // Delete now returns a bool — still discardable for
        // callers that don't care, preserving the original
        // behavioural intent of this test.
        let _ = store.delete(b"key1").unwrap();
        assert_eq!(store.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_memory_storage_contains() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        assert!(store.contains(b"key1").unwrap());
        assert!(!store.contains(b"key2").unwrap());
    }

    // ============================================================
    // HIGH-021 (commit 039) — delete returns Ok(true) iff the key
    // existed; Ok(false) iff it was already absent.
    // ============================================================

    #[test]
    fn test_delete_returns_true_when_key_existed() {
        // PRIMARY HIGH-021 PIN: present key → Ok(true).
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        let removed = store.delete(b"key1").unwrap();
        assert!(removed, "delete on present key must signal existence");
        // And the key really is gone.
        assert_eq!(store.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_delete_returns_false_when_key_absent() {
        // PRIMARY HIGH-021 PIN: absent key → Ok(false). Pre-fix
        // this returned Ok(()) and the caller had no signal.
        let mut store = MemoryStorage::new();
        let removed = store.delete(b"never-inserted").unwrap();
        assert!(
            !removed,
            "delete on absent key must signal non-existence (Ok(false))"
        );
    }

    #[test]
    fn test_delete_then_redelete_signals_existence_then_absence() {
        // Sequence pin: first delete returns true; second delete
        // on the same key (now absent) returns false. This is the
        // exact attacker-detectable signal that pre-fix was
        // silently identical between the two cases.
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        let first = store.delete(b"key1").unwrap();
        let second = store.delete(b"key1").unwrap();
        assert!(first, "first delete: key existed");
        assert!(!second, "second delete: key was already removed");
    }

    #[test]
    fn test_delete_distinguishes_two_keys_independently() {
        // Pin that delete's existence signal is per-key, not
        // global. Inserting key1 and deleting key2 returns false;
        // then deleting key1 returns true.
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        let absent = store.delete(b"key2").unwrap();
        assert!(!absent, "deleting absent key2 returns false");
        // key1 still present.
        assert_eq!(store.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        let present = store.delete(b"key1").unwrap();
        assert!(present, "deleting present key1 returns true");
    }

    #[test]
    fn test_delete_signals_existence_after_overwrite() {
        // put-overwrite-delete: the second put replaces the first
        // value; delete still returns true (the key existed).
        // Pin against any future implementation that mistakenly
        // returns false after an overwrite.
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"v1").unwrap();
        store.put(b"key1", b"v2").unwrap();
        assert_eq!(store.get(b"key1").unwrap(), Some(b"v2".to_vec()));
        let removed = store.delete(b"key1").unwrap();
        assert!(removed, "delete after overwrite still signals existence");
    }
}
