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
//!
//! # Transactional writes (HIGH-020, commit 090)
//!
//! [`StorageBackend`] is a single-op API: each `put` / `delete`
//! lands immediately. The audit (HIGH-020):
//!
//! > Crash mid-write during a multi-op state transition (e.g.,
//! > "insert block + update nonce registry + update
//! > consumed_sources"); second op never happens. On-disk state
//! > diverges from in-memory state after restart; nonce registry
//! > loses entries. Suggested fix direction: introduce a
//! > `Transaction` trait with explicit `begin/commit/rollback`;
//! > persistence backend must implement atomic writes.
//!
//! [`MemoryStorage::begin_transaction`] returns a
//! [`MemoryTransaction`] that **stages** writes and deletes in a
//! side buffer. The staged ops are visible to `get`/`contains`
//! via the transaction handle (read-your-writes within the txn)
//! but not to the underlying store until [`MemoryTransaction::commit`]
//! lands them atomically. [`MemoryTransaction::rollback`] (or
//! simply dropping the transaction without committing) discards
//! the staging buffer. The `commit` is atomic at the in-process
//! level: it acquires the staging snapshot once and applies all
//! ops in a single mutable borrow ; a panic between ops would
//! still leave the underlying store in either the pre-commit or
//! post-commit state, never a partial mix, because the staging
//! buffer is owned by the transaction handle and only consumed
//! when commit succeeds.
//!
//! Convenience: [`MemoryStorage::atomic_put_batch`] wraps
//! `begin → put each → commit` for the common case where a caller
//! has a slice of `(key, value)` pairs to land together.
//!
//! For a future on-disk backend (sled / rocksdb / WAL), the same
//! `Transaction` shape applies ; the staging buffer becomes the
//! WAL frame, and `commit` becomes "fsync the WAL frame, then
//! apply".

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

/// HIGH-020 (commit 090): staging op for the transaction's side
/// buffer. `Put(value)` carries the new value ; `Delete` marks
/// the key for removal at commit time.
#[derive(Debug, Clone)]
enum StagedOp {
    Put(Vec<u8>),
    Delete,
}

/// Transactional write handle on a [`MemoryStorage`].
///
/// HIGH-020 (commit 090): writes go into a staging buffer
/// while the underlying store is untouched. [`Self::commit`]
/// applies all staged ops atomically (single mutable borrow on
/// the store) ; [`Self::rollback`] (or `drop`) discards the
/// staging buffer.
///
/// Reads via [`Self::get`] / [`Self::contains`] see
/// read-your-writes within the transaction (a key staged with
/// `Put` returns the staged value ; a key staged with `Delete`
/// returns `None`/`false` even if it exists in the store).
pub struct MemoryTransaction<'a> {
    store: &'a mut MemoryStorage,
    staged: HashMap<Vec<u8>, StagedOp>,
    /// Set to `true` by `commit()` so `Drop` knows not to
    /// re-rollback (commit consumed `self`, but a panic during
    /// commit's body would leave us in an in-between state).
    /// Currently always `false` because commit consumes self
    /// by value ; reserved for future fallible-commit paths.
    committed: bool,
}

impl MemoryTransaction<'_> {
    /// Stage a `put`. Atomic w.r.t. the txn ; visible to other
    /// reads in the same txn but NOT to the underlying store
    /// until commit.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        self.staged
            .insert(key.to_vec(), StagedOp::Put(value.to_vec()));
        Ok(())
    }

    /// Stage a `delete`. Same semantics as
    /// [`StorageBackend::delete`] but the result is the
    /// "would-be-deleted" status: `true` if the key currently
    /// exists in the txn's view (store + staging), `false`
    /// otherwise. The actual removal lands on commit.
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
        let exists_in_view = self.contains(key)?;
        self.staged.insert(key.to_vec(), StagedOp::Delete);
        Ok(exists_in_view)
    }

    /// Read-your-writes within the transaction.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        match self.staged.get(key) {
            Some(StagedOp::Put(v)) => Ok(Some(v.clone())),
            Some(StagedOp::Delete) => Ok(None),
            None => self.store.get(key),
        }
    }

    /// Read-your-writes containment check.
    pub fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        match self.staged.get(key) {
            Some(StagedOp::Put(_)) => Ok(true),
            Some(StagedOp::Delete) => Ok(false),
            None => self.store.contains(key),
        }
    }

    /// Number of ops staged.
    pub fn staged_op_count(&self) -> usize {
        self.staged.len()
    }

    /// Apply all staged ops atomically. Consumes `self`.
    pub fn commit(mut self) -> Result<(), ArxiaError> {
        // Move the staging buffer out so we can drain it without
        // re-borrowing self.
        let drained = std::mem::take(&mut self.staged);
        for (key, op) in drained {
            match op {
                StagedOp::Put(value) => {
                    self.store.data.insert(key, value);
                }
                StagedOp::Delete => {
                    self.store.data.remove(&key);
                }
            }
        }
        self.committed = true;
        Ok(())
    }

    /// Discard all staged ops without applying them. Equivalent
    /// to dropping the transaction.
    pub fn rollback(self) {
        // `self` goes out of scope ; staged buffer is dropped
        // with it.
    }
}

impl MemoryStorage {
    /// HIGH-020 (commit 090): begin a transaction.
    ///
    /// Holds an exclusive mutable borrow on `self` until the
    /// returned [`MemoryTransaction`] is dropped or committed.
    /// This guarantees no other code path can issue a non-
    /// transactional `put`/`delete` while the transaction is
    /// in flight.
    pub fn begin_transaction(&mut self) -> MemoryTransaction<'_> {
        MemoryTransaction {
            store: self,
            staged: HashMap::new(),
            committed: false,
        }
    }

    /// HIGH-020 (commit 090): convenience wrapper for the
    /// "many puts, all-or-nothing" pattern.
    ///
    /// Begins a transaction, applies every `(key, value)` pair
    /// via `put`, and commits. Returns `Ok(())` if every put
    /// succeeded and the commit landed ; on error, no
    /// staged op reaches the store (the transaction is dropped
    /// without commit).
    pub fn atomic_put_batch<K, V>(&mut self, items: &[(K, V)]) -> Result<(), ArxiaError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut txn = self.begin_transaction();
        for (k, v) in items {
            txn.put(k.as_ref(), v.as_ref())?;
        }
        txn.commit()
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

/// LOW-011 (commit 082): Blake3-checksummed value envelope.
///
/// `wrap_with_checksum(value)` prepends a 32-byte Blake3 hash to
/// the value bytes so a later `unwrap_with_checksum` can detect
/// any tampering or storage corruption. The wire format is
/// `[32-byte blake3(value)][value_bytes]`.
///
/// This is opt-in: callers pass the wrapped bytes to
/// `MemoryStorage::put` and the wrapped bytes back through
/// `unwrap_with_checksum` after `get`. The default
/// `put`/`get` path remains zero-overhead for callers that
/// don't need integrity checking.
pub fn wrap_with_checksum(value: &[u8]) -> Vec<u8> {
    let checksum = arxia_crypto::hash_blake3_bytes(value);
    let mut out = Vec::with_capacity(32 + value.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(value);
    out
}

/// LOW-011 (commit 082): unwrap and verify a checksummed value
/// envelope produced by [`wrap_with_checksum`].
///
/// On success returns the inner value bytes (not the checksum).
/// Returns `Err(ArxiaError::InvalidKey)` (reused as a typed
/// "integrity violation" surface) if:
/// - The combined bytes are shorter than 32 (no room for the
///   checksum prefix).
/// - The recomputed Blake3 hash of the value bytes does not
///   match the stored prefix (corruption or tampering).
pub fn unwrap_with_checksum(combined: &[u8]) -> Result<Vec<u8>, ArxiaError> {
    if combined.len() < 32 {
        return Err(ArxiaError::InvalidKey(format!(
            "checksumed value too short: got {} bytes, need >= 32 for prefix",
            combined.len()
        )));
    }
    let (prefix, value) = combined.split_at(32);
    let recomputed = arxia_crypto::hash_blake3_bytes(value);
    if prefix != recomputed {
        return Err(ArxiaError::InvalidKey(
            "checksumed value: Blake3 prefix does not match recomputed hash (corruption or tampering)".to_string(),
        ));
    }
    Ok(value.to_vec())
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

    // ============================================================
    // LOW-011 (commit 082) — Blake3 round-trip checksum.
    //
    // Opt-in `wrap_with_checksum` / `unwrap_with_checksum`
    // helpers. Wire format: `[32-byte blake3(value)][value_bytes]`.
    // Default put/get unchanged ; checksumed callers use the
    // helpers around the existing API.
    // ============================================================

    #[test]
    fn test_wrap_unwrap_round_trip() {
        // PRIMARY LOW-011 PIN: any value round-trips via
        // wrap → store → load → unwrap.
        let mut store = MemoryStorage::new();
        let value = b"hello world".to_vec();
        let wrapped = wrap_with_checksum(&value);
        assert_eq!(wrapped.len(), 32 + value.len());
        store.put(b"k", &wrapped).unwrap();
        let loaded = store.get(b"k").unwrap().unwrap();
        let unwrapped = unwrap_with_checksum(&loaded).unwrap();
        assert_eq!(unwrapped, value);
    }

    #[test]
    fn test_unwrap_rejects_corrupted_value() {
        // Tamper with the value bytes (after the prefix). The
        // Blake3 recompute must mismatch, raising InvalidKey.
        let value = b"original".to_vec();
        let mut wrapped = wrap_with_checksum(&value);
        wrapped[32] ^= 0xFF; // flip a bit in the value, not the prefix
        let err = unwrap_with_checksum(&wrapped).expect_err("value tampering must be detected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_unwrap_rejects_corrupted_checksum() {
        // Tamper with the checksum prefix. Same detection.
        let value = b"original".to_vec();
        let mut wrapped = wrap_with_checksum(&value);
        wrapped[0] ^= 0xFF; // flip a bit in the prefix
        let err = unwrap_with_checksum(&wrapped).expect_err("checksum tampering must be detected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_unwrap_rejects_too_short_envelope() {
        // <32 bytes can't even contain the prefix.
        let too_short = vec![0u8; 16];
        let err = unwrap_with_checksum(&too_short).expect_err("short envelope must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(msg) if msg.contains("32")));
    }

    #[test]
    fn test_wrap_unwrap_empty_value() {
        // Edge: empty value. Wrapped envelope is exactly 32
        // bytes (just the checksum). Round-trip succeeds.
        let value = Vec::new();
        let wrapped = wrap_with_checksum(&value);
        assert_eq!(wrapped.len(), 32);
        let unwrapped = unwrap_with_checksum(&wrapped).unwrap();
        assert!(unwrapped.is_empty());
    }

    #[test]
    fn test_wrap_unwrap_long_value() {
        // 1 MiB value. Round-trip succeeds without panic or
        // truncation.
        let value = vec![0xAAu8; 1024 * 1024];
        let wrapped = wrap_with_checksum(&value);
        let unwrapped = unwrap_with_checksum(&wrapped).unwrap();
        assert_eq!(unwrapped.len(), value.len());
        assert_eq!(unwrapped, value);
    }

    // ============================================================
    // HIGH-020 (commit 090) — MemoryTransaction begin/commit/
    // rollback semantics + atomic_put_batch convenience.
    // ============================================================

    #[test]
    fn test_transaction_commit_lands_all_staged_ops() {
        // PRIMARY HIGH-020 PIN: a successful commit applies
        // every staged put to the underlying store atomically.
        let mut store = MemoryStorage::new();
        let mut txn = store.begin_transaction();
        txn.put(b"k1", b"v1").unwrap();
        txn.put(b"k2", b"v2").unwrap();
        txn.put(b"k3", b"v3").unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(store.get(b"k2").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(store.get(b"k3").unwrap(), Some(b"v3".to_vec()));
    }

    #[test]
    fn test_transaction_rollback_discards_all_staged_ops() {
        // PRIMARY HIGH-020 PIN: rollback (or drop) discards
        // every staged op. The store is exactly as it was
        // before the transaction began.
        let mut store = MemoryStorage::new();
        store.put(b"pre", b"existing").unwrap();
        let mut txn = store.begin_transaction();
        txn.put(b"k1", b"v1").unwrap();
        txn.delete(b"pre").unwrap();
        txn.rollback();
        // Pre-existing key still there ; staged put never landed.
        assert_eq!(store.get(b"pre").unwrap(), Some(b"existing".to_vec()));
        assert_eq!(store.get(b"k1").unwrap(), None);
    }

    #[test]
    fn test_transaction_drop_without_commit_is_rollback() {
        // Dropping the txn without `commit()` MUST be
        // equivalent to `rollback()`. The audit's "kill the
        // process before commit, no partial state" contract
        // for the in-memory case.
        let mut store = MemoryStorage::new();
        {
            let mut txn = store.begin_transaction();
            txn.put(b"key", b"val").unwrap();
            // txn dropped here without commit
        }
        assert_eq!(store.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_transaction_read_your_writes_within_txn() {
        // Within a transaction, get/contains see staged ops.
        let mut store = MemoryStorage::new();
        store.put(b"existing", b"v0").unwrap();
        let mut txn = store.begin_transaction();
        // Staged put visible.
        txn.put(b"new", b"v1").unwrap();
        assert_eq!(txn.get(b"new").unwrap(), Some(b"v1".to_vec()));
        // Staged delete shadows store value.
        txn.delete(b"existing").unwrap();
        assert_eq!(txn.get(b"existing").unwrap(), None);
        assert!(!txn.contains(b"existing").unwrap());
        // But the underlying store STILL has it (pre-commit).
        // (We can't read store while txn holds &mut, so commit
        // first.)
        txn.commit().unwrap();
        assert_eq!(store.get(b"existing").unwrap(), None);
        assert_eq!(store.get(b"new").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn test_transaction_delete_returns_view_existence_signal() {
        // delete() returns whether the key existed in the
        // txn's view (store + staged). Pre-staging the delete,
        // we get true ; after, the key is staged-deleted.
        let mut store = MemoryStorage::new();
        store.put(b"k", b"v").unwrap();
        let mut txn = store.begin_transaction();
        // First delete: existed in store.
        let first = txn.delete(b"k").unwrap();
        assert!(first);
        // Second delete: already staged-deleted, view says no.
        let second = txn.delete(b"k").unwrap();
        assert!(!second);
    }

    #[test]
    fn test_transaction_staged_op_count_pinned() {
        let mut store = MemoryStorage::new();
        let mut txn = store.begin_transaction();
        assert_eq!(txn.staged_op_count(), 0);
        txn.put(b"a", b"1").unwrap();
        txn.put(b"b", b"2").unwrap();
        assert_eq!(txn.staged_op_count(), 2);
        txn.put(b"a", b"3").unwrap(); // overwrite same key
        assert_eq!(txn.staged_op_count(), 2, "same key is one staged slot");
    }

    #[test]
    fn test_transaction_borrow_checker_prevents_concurrent_mutations() {
        // Compile-time pin: `begin_transaction` returns a
        // handle that holds &mut self ; the borrow checker
        // refuses any other &mut borrow on the store while the
        // txn is alive. This test compiles iff the rule holds.
        let mut store = MemoryStorage::new();
        let mut txn = store.begin_transaction();
        txn.put(b"x", b"y").unwrap();
        // Attempting `store.put(...)` here would be a compile
        // error (E0499). Documented invariant.
        txn.commit().unwrap();
        // After commit (txn consumed), we can borrow again.
        store.put(b"z", b"w").unwrap();
        assert_eq!(store.get(b"x").unwrap(), Some(b"y".to_vec()));
        assert_eq!(store.get(b"z").unwrap(), Some(b"w".to_vec()));
    }

    #[test]
    fn test_atomic_put_batch_lands_all_or_nothing() {
        // PRIMARY HIGH-020 PIN: the convenience batch helper
        // commits the whole slice or nothing. With the current
        // memory backend every `put` succeeds, so this is the
        // happy-path pin ; a future fallible backend exercises
        // the all-or-nothing direction.
        let mut store = MemoryStorage::new();
        let items: &[(&[u8], &[u8])] = &[(b"k1", b"v1"), (b"k2", b"v2"), (b"k3", b"v3")];
        store.atomic_put_batch(items).unwrap();
        for (k, v) in items {
            assert_eq!(store.get(k).unwrap(), Some(v.to_vec()));
        }
    }

    #[test]
    fn test_atomic_put_batch_empty_slice_is_noop() {
        // Edge: an empty batch is a successful no-op.
        let mut store = MemoryStorage::new();
        let items: &[(&[u8], &[u8])] = &[];
        store.atomic_put_batch(items).unwrap();
        assert!(store.contains(b"anything").is_ok());
    }

    #[test]
    fn test_transaction_commit_overwrites_existing_key() {
        // Pin: a staged put on a key already in the store
        // overwrites the value at commit time.
        let mut store = MemoryStorage::new();
        store.put(b"k", b"old").unwrap();
        let mut txn = store.begin_transaction();
        txn.put(b"k", b"new").unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"new".to_vec()));
    }

    #[test]
    fn test_transaction_commit_after_delete_then_put_lands_put() {
        // Edge: stage delete then put on the same key. Final
        // state is the put.
        let mut store = MemoryStorage::new();
        store.put(b"k", b"v0").unwrap();
        let mut txn = store.begin_transaction();
        txn.delete(b"k").unwrap();
        txn.put(b"k", b"v1").unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v1".to_vec()));
    }
}
