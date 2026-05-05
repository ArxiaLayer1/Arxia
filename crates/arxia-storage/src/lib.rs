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
//!
//! # Concurrent access (MED-020, commit 071)
//!
//! [`MemoryStorage`] takes `&mut self` on mutating methods and is
//! NOT safe to share across threads — Rust's borrow checker will
//! refuse the second mutable borrow at compile time, but a caller
//! using `unsafe`/raw pointers or wrapping in `Arc<Mutex<…>>`
//! manually could still introduce torn reads or data races. The
//! audit (MED-020):
//!
//! > Spawn two threads, each with a `MemoryStorage` reference;
//! > race put/get. Torn reads ; trait contract undefined for
//! > concurrency. Suggested fix direction: trait takes `&self`
//! > with internal `Mutex` / `DashMap` ; document thread-safety
//! > contract.
//!
//! Rather than break every existing `&mut self`-using caller, this
//! commit adds a separate [`ConcurrentMemoryStorage`] type whose
//! methods take `&self` and synchronise internally via
//! [`std::sync::Mutex`]. Callers that need to share a storage
//! handle across threads use `Arc<ConcurrentMemoryStorage>` and
//! call methods directly without external locking.
//!
//! `MemoryStorage` is preserved unchanged for single-threaded
//! callers (it remains the default and avoids the lock-acquisition
//! cost on the hot path).

use arxia_core::ArxiaError;
use std::collections::HashMap;
use std::sync::Mutex;

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

/// Thread-safe in-memory storage backend.
///
/// MED-020 (commit 071): all mutating methods take `&self` and
/// synchronise internally via [`std::sync::Mutex`]. Designed for
/// `Arc<ConcurrentMemoryStorage>` sharing across threads ; the
/// `Arc` provides the shared ownership, the internal `Mutex`
/// provides exclusion on the underlying `HashMap`. Each operation
/// is atomic with respect to every other operation.
///
/// This is **not** an implementation of [`StorageBackend`] (whose
/// trait methods take `&mut self`) ; converting the trait to
/// `&self` would break every existing single-threaded caller. The
/// concrete API surface mirrors the trait's methods so callers
/// that need both can use either type interchangeably at call
/// sites.
///
/// # Example
///
/// ```
/// use arxia_storage::ConcurrentMemoryStorage;
/// use std::sync::Arc;
/// use std::thread;
///
/// let store = Arc::new(ConcurrentMemoryStorage::new());
/// let mut handles = Vec::new();
/// for i in 0..4 {
///     let s = Arc::clone(&store);
///     handles.push(thread::spawn(move || {
///         let key = format!("key-{i}");
///         s.put(key.as_bytes(), b"value").unwrap();
///     }));
/// }
/// for h in handles { h.join().unwrap(); }
/// assert_eq!(store.len().unwrap(), 4);
/// ```
pub struct ConcurrentMemoryStorage {
    data: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl ConcurrentMemoryStorage {
    /// Create a new empty thread-safe in-memory store.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    /// Store a value under the given key. Atomic w.r.t. every
    /// other call.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        let mut guard = self.data.lock().map_err(|e| {
            ArxiaError::InvalidKey(format!("ConcurrentMemoryStorage poisoned: {e}"))
        })?;
        guard.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Retrieve a value by key. Returns a clone of the stored
    /// bytes (so the lock can be released before the caller
    /// reads). Atomic w.r.t. every other call.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        let guard = self.data.lock().map_err(|e| {
            ArxiaError::InvalidKey(format!("ConcurrentMemoryStorage poisoned: {e}"))
        })?;
        Ok(guard.get(key).cloned())
    }

    /// Delete a key-value pair. Same existence-signaling
    /// semantics as [`StorageBackend::delete`] (HIGH-021).
    /// Atomic w.r.t. every other call.
    pub fn delete(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        let mut guard = self.data.lock().map_err(|e| {
            ArxiaError::InvalidKey(format!("ConcurrentMemoryStorage poisoned: {e}"))
        })?;
        Ok(guard.remove(key).is_some())
    }

    /// Check if a key exists. Atomic w.r.t. every other call.
    pub fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        let guard = self.data.lock().map_err(|e| {
            ArxiaError::InvalidKey(format!("ConcurrentMemoryStorage poisoned: {e}"))
        })?;
        Ok(guard.contains_key(key))
    }

    /// Number of keys currently stored. Useful for tests and for
    /// observability of concurrent fill / drain patterns.
    pub fn len(&self) -> Result<usize, ArxiaError> {
        let guard = self.data.lock().map_err(|e| {
            ArxiaError::InvalidKey(format!("ConcurrentMemoryStorage poisoned: {e}"))
        })?;
        Ok(guard.len())
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, ArxiaError> {
        Ok(self.len()? == 0)
    }
}

impl Default for ConcurrentMemoryStorage {
    fn default() -> Self {
        Self::new()
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

    // ============================================================
    // MED-020 (commit 071) — ConcurrentMemoryStorage thread-safety.
    // The pre-fix MemoryStorage takes &mut self and is unshare-
    // able. This new type takes &self, locks internally, and is
    // safe to share via Arc across threads.
    // ============================================================

    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_concurrent_storage_basic_put_get() {
        // Smoke test on the single-thread path before the
        // concurrent stress.
        let store = ConcurrentMemoryStorage::new();
        store.put(b"k", b"v").unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));
        assert!(store.contains(b"k").unwrap());
        assert!(store.delete(b"k").unwrap());
        assert!(!store.contains(b"k").unwrap());
    }

    #[test]
    fn test_concurrent_storage_share_across_threads_no_panic() {
        // PRIMARY MED-020 PIN: spawn 8 threads each doing 50
        // put/get pairs on distinct keys. No panic, no torn
        // read, all 400 keys present at the end.
        let store = Arc::new(ConcurrentMemoryStorage::new());
        let mut handles = Vec::new();
        for tid in 0..8u32 {
            let s = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..50u32 {
                    let key = format!("t{tid}-k{i}");
                    let val = format!("v{tid}-{i}");
                    s.put(key.as_bytes(), val.as_bytes()).unwrap();
                    let read = s.get(key.as_bytes()).unwrap();
                    assert_eq!(read.as_deref(), Some(val.as_bytes()));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.len().unwrap(), 8 * 50);
    }

    #[test]
    fn test_concurrent_storage_no_torn_read_under_overwrite() {
        // Two threads: one repeatedly puts the same key with
        // alternating values, the other repeatedly reads. The
        // reader must always see ONE of the two values — never
        // a torn intermediate (which would not actually be
        // possible for an atomic Vec-clone, but the test pins
        // the contract for any future change).
        let store = Arc::new(ConcurrentMemoryStorage::new());
        store.put(b"k", b"AAAAAAAA").unwrap();
        let writer_store = Arc::clone(&store);
        let writer = thread::spawn(move || {
            for i in 0..200 {
                let v: &[u8] = if i % 2 == 0 { b"AAAAAAAA" } else { b"BBBBBBBB" };
                writer_store.put(b"k", v).unwrap();
            }
        });
        let reader = thread::spawn(move || {
            for _ in 0..200 {
                let read = store.get(b"k").unwrap().unwrap();
                assert!(
                    read.as_slice() == b"AAAAAAAA" || read.as_slice() == b"BBBBBBBB",
                    "read torn intermediate: {:?}",
                    read
                );
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn test_concurrent_storage_delete_existence_signal_under_concurrency() {
        // HIGH-021 existence signal preserved under concurrency:
        // 4 threads race to delete the same key ; exactly one
        // sees Ok(true), the others see Ok(false). No double-
        // delete, no missed signal.
        let store = Arc::new(ConcurrentMemoryStorage::new());
        store.put(b"hot", b"v").unwrap();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&store);
            handles.push(thread::spawn(move || s.delete(b"hot").unwrap()));
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let trues = results.iter().filter(|b| **b).count();
        let falses = results.iter().filter(|b| !**b).count();
        assert_eq!(
            trues, 1,
            "exactly one thread sees Ok(true) for the existing key"
        );
        assert_eq!(falses, 3, "the other three see Ok(false)");
    }

    #[test]
    fn test_concurrent_storage_implements_send_and_sync() {
        // Compile-time pin: Arc<ConcurrentMemoryStorage> can
        // be moved into a thread (Send) and shared by reference
        // across threads (Sync). This test compiles iff both
        // bounds hold.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ConcurrentMemoryStorage>();
        assert_sync::<ConcurrentMemoryStorage>();
        assert_send::<Arc<ConcurrentMemoryStorage>>();
        assert_sync::<Arc<ConcurrentMemoryStorage>>();
    }

    #[test]
    fn test_concurrent_storage_default_equivalent_to_new() {
        let a = ConcurrentMemoryStorage::default();
        let b = ConcurrentMemoryStorage::new();
        assert!(a.is_empty().unwrap());
        assert!(b.is_empty().unwrap());
    }
}
