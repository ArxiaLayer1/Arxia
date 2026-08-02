//! Conformance tests for the `StorageBackend` contract.
//!
//! Every check is a generic function over `B: StorageBackend`; the
//! `#[test]` items below are thin wrappers that apply them to
//! `MemoryStorage`. A future persistent backend is held to the same
//! expectations by adding its own wrappers calling the same functions —
//! anything that passes here and fails against redb or a flash backend
//! is a real difference in behaviour, not a test artefact.

use arxia_core::ArxiaError;
use arxia_storage::{BatchOp, MemoryStorage, StorageBackend};

fn collect_prefix<B: StorageBackend>(b: &B, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    b.scan_prefix(prefix, &mut |k, v| {
        out.push((k.to_vec(), v.to_vec()));
        true
    })
    .unwrap();
    out
}

fn pair(k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (k.to_vec(), v.to_vec())
}

/// Seeds a backend with two adjacent prefixes and a high-byte key.
///
/// Insertion is deliberately out of order: the scan must sort, not the
/// caller. `c:acct:` and `c:acctZzz` differ only past the shared
/// `c:acct` stem, so a scan bounded by string comparison rather than by
/// byte comparison picks up the neighbour. `d:\xFF\xFF` sits above every
/// ASCII key, so a backend treating key bytes as signed sorts it first.
fn seed<B: StorageBackend>(b: &mut B) {
    b.put(b"c:acct:0010", b"ten").unwrap();
    b.put(b"c:acct:0001", b"one").unwrap();
    b.put(b"d:\xFF\xFF", b"high").unwrap();
    b.put(b"c:acct:0002", b"two").unwrap();
    b.put(b"a:other", b"skip").unwrap();
    b.put(b"c:acctZzz", b"neighbour").unwrap();
}

// ------------------------------------------------------------- scanning

fn check_scan_returns_pairs_in_ascending_key_order<B: StorageBackend>(b: &mut B) {
    seed(b);
    // Values are asserted, not just keys: a backend pairing the right
    // keys with the wrong values would otherwise pass every scan test.
    assert_eq!(
        collect_prefix(b, b"c:acct:"),
        vec![
            pair(b"c:acct:0001", b"one"),
            pair(b"c:acct:0002", b"two"),
            pair(b"c:acct:0010", b"ten"),
        ],
        "ordering is lexicographic by key byte, regardless of insertion order"
    );
}

fn check_scan_excludes_neighbouring_prefixes<B: StorageBackend>(b: &mut B) {
    seed(b);
    let got = collect_prefix(b, b"c:acct:");
    assert!(
        !got.iter().any(|(k, _)| k.as_slice() == b"c:acctZzz"),
        "a key sharing the stem but not the prefix must not be visited"
    );
    assert_eq!(got.len(), 3);
}

fn check_empty_prefix_visits_everything_in_byte_order<B: StorageBackend>(b: &mut B) {
    seed(b);
    assert_eq!(
        collect_prefix(b, b""),
        vec![
            pair(b"a:other", b"skip"),
            pair(b"c:acct:0001", b"one"),
            pair(b"c:acct:0002", b"two"),
            pair(b"c:acct:0010", b"ten"),
            pair(b"c:acctZzz", b"neighbour"),
            // Last, not first: key bytes are unsigned.
            pair(b"d:\xFF\xFF", b"high"),
        ]
    );
}

fn check_scan_agrees_with_point_lookup<B: StorageBackend>(b: &mut B) {
    seed(b);
    // Pins the two read paths together, so a backend cannot serve a
    // stale or separate index from `scan_prefix`.
    for (k, v) in collect_prefix(b, b"") {
        assert_eq!(
            b.get(&k).unwrap().as_deref(),
            Some(v.as_slice()),
            "scan and get disagree on {k:?}"
        );
    }
}

fn check_scan_ignores_deleted_keys<B: StorageBackend>(b: &mut B) {
    seed(b);
    // Both removal paths, since a backend may implement them separately.
    assert!(b.delete(b"c:acct:0002").unwrap());
    b.apply_batch(&[BatchOp::Delete {
        key: b"c:acct:0010",
    }])
    .unwrap();

    assert_eq!(
        collect_prefix(b, b"c:acct:"),
        vec![pair(b"c:acct:0001", b"one")],
        "a tombstoned key must not remain visible to a scan"
    );
}

fn check_scan_sees_a_key_reinserted_after_delete<B: StorageBackend>(b: &mut B) {
    seed(b);
    assert!(b.delete(b"c:acct:0002").unwrap());
    b.put(b"c:acct:0002", b"restored").unwrap();

    assert_eq!(
        collect_prefix(b, b"c:acct:"),
        vec![
            pair(b"c:acct:0001", b"one"),
            pair(b"c:acct:0002", b"restored"),
            pair(b"c:acct:0010", b"ten"),
        ],
        "the key must reappear once, in position, with the new value"
    );
}

fn check_prefix_matching_nothing_is_not_an_error<B: StorageBackend>(b: &mut B) {
    seed(b);
    assert!(collect_prefix(b, b"zzz").is_empty());
}

fn check_returning_false_stops_the_scan<B: StorageBackend>(b: &mut B) {
    seed(b);
    let mut seen = 0usize;
    let res = b.scan_prefix(b"c:acct:", &mut |_, _| {
        seen += 1;
        seen < 2 // stop after the second entry
    });
    assert!(res.is_ok(), "early exit is not a failure");
    assert_eq!(seen, 2, "the visitor must not be called again after false");
}

// -------------------------------------------------------------- batching

fn check_batch_applies_every_operation<B: StorageBackend>(b: &mut B) {
    b.put(b"untouched", b"keep-me").unwrap();
    b.put(b"gone", b"x").unwrap();

    b.apply_batch(&[
        BatchOp::Put {
            key: b"added",
            value: b"v",
        },
        BatchOp::Delete { key: b"gone" },
    ])
    .unwrap();

    assert_eq!(b.get(b"added").unwrap().as_deref(), Some(b"v".as_slice()));
    assert!(!b.contains(b"gone").unwrap());
    // A batch must touch only the keys it names.
    assert_eq!(
        b.get(b"untouched").unwrap().as_deref(),
        Some(b"keep-me".as_slice()),
        "a key absent from the batch must survive it"
    );
}

fn check_later_operations_win_on_the_same_key<B: StorageBackend>(b: &mut B) {
    // A backend grouping puts and deletes instead of honouring slice
    // order would resolve these differently.
    b.apply_batch(&[
        BatchOp::Put {
            key: b"k",
            value: b"first",
        },
        BatchOp::Put {
            key: b"k",
            value: b"second",
        },
    ])
    .unwrap();
    assert_eq!(b.get(b"k").unwrap().as_deref(), Some(b"second".as_slice()));

    b.apply_batch(&[
        BatchOp::Put {
            key: b"k",
            value: b"third",
        },
        BatchOp::Delete { key: b"k" },
    ])
    .unwrap();
    assert!(
        !b.contains(b"k").unwrap(),
        "the delete must win, being last"
    );
}

fn check_a_delete_then_put_on_one_key_lands_the_put<B: StorageBackend>(b: &mut B) {
    b.put(b"k", b"v0").unwrap();
    b.apply_batch(&[
        BatchOp::Delete { key: b"k" },
        BatchOp::Put {
            key: b"k",
            value: b"v1",
        },
    ])
    .unwrap();

    assert_eq!(b.get(b"k").unwrap().as_deref(), Some(b"v1".as_slice()));
    assert_eq!(
        collect_prefix(b, b"k"),
        vec![pair(b"k", b"v1")],
        "the scan must agree that the put won"
    );
}

fn check_interleaved_ops_resolve_in_slice_order<B: StorageBackend>(b: &mut B) {
    b.apply_batch(&[
        BatchOp::Put {
            key: b"k",
            value: b"a",
        },
        BatchOp::Delete { key: b"k" },
        BatchOp::Put {
            key: b"k",
            value: b"b",
        },
        BatchOp::Delete { key: b"k" },
        BatchOp::Put {
            key: b"k",
            value: b"c",
        },
    ])
    .unwrap();
    assert_eq!(b.get(b"k").unwrap().as_deref(), Some(b"c".as_slice()));
}

fn check_deleting_an_absent_key_in_a_batch_is_not_an_error<B: StorageBackend>(b: &mut B) {
    assert!(b
        .apply_batch(&[BatchOp::Delete {
            key: b"never-existed"
        }])
        .is_ok());
}

fn check_an_empty_batch_is_a_no_op<B: StorageBackend>(b: &mut B) {
    b.put(b"k", b"v").unwrap();
    b.apply_batch(&[]).unwrap();
    assert_eq!(b.get(b"k").unwrap().as_deref(), Some(b"v".as_slice()));
}

// ---------------------------------------------------- the atomicity contract

/// Reports whether `b` honoured the all-or-nothing guarantee, instead of
/// asserting it.
///
/// Returning a `bool` is what makes the check itself testable: a
/// conformance check for a failure path is worthless unless something
/// proves it can actually fail, and
/// [`the_atomicity_check_rejects_a_backend_that_writes_as_it_goes`] does
/// exactly that.
///
/// The batch covers all three observable effects — a key added, a key
/// removed, a key overwritten — because a backend that rolled back only
/// its insertions would pass a check watching insertions alone.
fn batch_atomicity_holds<B: StorageBackend>(b: &mut B) -> bool {
    b.put(b"overwritten", b"original").unwrap();
    b.put(b"removed", b"original").unwrap();

    let res = b.apply_batch(&[
        BatchOp::Put {
            key: b"added",
            value: b"new",
        },
        BatchOp::Delete { key: b"removed" },
        BatchOp::Put {
            key: b"overwritten",
            value: b"new",
        },
    ]);

    // A batch that succeeded proves nothing about the failure path, so
    // treat it as a failed check rather than pass silently.
    if res.is_ok() {
        return false;
    }

    !b.contains(b"added").unwrap()
        && b.get(b"removed").unwrap().as_deref() == Some(b"original".as_slice())
        && b.get(b"overwritten").unwrap().as_deref() == Some(b"original".as_slice())
}

/// The sequential fallback the trait documentation warns about: it
/// writes each operation to the live store as it goes, then fails.
/// Deliberately non-compliant — the atomicity check must reject it.
struct AppliesThenFails {
    inner: MemoryStorage,
    fail_at: usize,
}

/// Compliant counterpart: the same per-operation work, but into a
/// staging buffer abandoned on fault, so the live store is never
/// written. The two fixtures differ only in *where* they write, which is
/// precisely the property under test.
struct StagesThenFails {
    inner: MemoryStorage,
    fail_at: usize,
}

fn fault() -> ArxiaError {
    // NOTE: the crate has no dedicated storage-fault variant and reuses
    // InvalidKey. A persistent backend will need a proper one for I/O
    // and corruption; it is added when it has a consumer.
    ArxiaError::InvalidKey("simulated mid-batch fault".into())
}

macro_rules! delegate_non_batch_methods {
    () => {
        fn put(&mut self, k: &[u8], v: &[u8]) -> Result<(), ArxiaError> {
            self.inner.put(k, v)
        }
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
            self.inner.get(k)
        }
        fn delete(&mut self, k: &[u8]) -> Result<bool, ArxiaError> {
            self.inner.delete(k)
        }
        fn contains(&self, k: &[u8]) -> Result<bool, ArxiaError> {
            self.inner.contains(k)
        }
        fn scan_prefix(
            &self,
            p: &[u8],
            visit: &mut dyn FnMut(&[u8], &[u8]) -> bool,
        ) -> Result<(), ArxiaError> {
            self.inner.scan_prefix(p, visit)
        }
    };
}

impl StorageBackend for AppliesThenFails {
    delegate_non_batch_methods!();

    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        for (i, op) in ops.iter().enumerate() {
            if i == self.fail_at {
                return Err(fault());
            }
            match op {
                BatchOp::Put { key, value } => self.inner.put(key, value)?,
                BatchOp::Delete { key } => {
                    self.inner.delete(key)?;
                }
            }
        }
        Ok(())
    }
}

impl StorageBackend for StagesThenFails {
    delegate_non_batch_methods!();

    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        let mut staged: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            if i == self.fail_at {
                // The staging buffer is dropped here; `inner` was never
                // written, so there is nothing to undo.
                return Err(fault());
            }
            match op {
                BatchOp::Put { key, value } => staged.push((key.to_vec(), Some(value.to_vec()))),
                BatchOp::Delete { key } => staged.push((key.to_vec(), None)),
            }
        }
        for (k, v) in staged {
            match v {
                Some(v) => self.inner.put(&k, &v)?,
                None => {
                    self.inner.delete(&k)?;
                }
            }
        }
        Ok(())
    }
}

#[test]
fn the_atomicity_check_rejects_a_backend_that_writes_as_it_goes() {
    // Fault on the third operation, so the first two have already been
    // attempted: a backend writing as it goes has landed them.
    assert!(
        batch_atomicity_holds(&mut StagesThenFails {
            inner: MemoryStorage::new(),
            fail_at: 2,
        }),
        "a backend that stages before writing must satisfy the contract"
    );

    assert!(
        !batch_atomicity_holds(&mut AppliesThenFails {
            inner: MemoryStorage::new(),
            fail_at: 2,
        }),
        "a backend that writes as it goes must be caught; without this \
         half the check above could be vacuous and we would not know"
    );
}

#[test]
fn a_failing_batch_rolls_back_before_the_first_operation_too() {
    // `MemoryStorage::apply_batch` is infallible by construction — it
    // stages against a clone and swaps, with no fallible step — so its
    // own error path is unreachable and is not exercised here. The
    // guarantee is pinned by the fixtures above; the success path of
    // the real implementation is pinned by the batching checks.
    assert!(batch_atomicity_holds(&mut StagesThenFails {
        inner: MemoryStorage::new(),
        fail_at: 0,
    }));
}

// ------------------------------------------------------- object safety

#[test]
fn the_trait_is_object_safe_including_the_new_methods() {
    // The node will hold whichever backend it was configured with
    // behind a trait object, so losing object safety would be a
    // breaking design change. Pinned here rather than discovered later.
    let mut store = MemoryStorage::new();
    let b: &mut dyn StorageBackend = &mut store;

    // Exercised through the trait object, not merely coerced into one.
    b.apply_batch(&[BatchOp::Put {
        key: b"p:1",
        value: b"v",
    }])
    .unwrap();

    let mut seen = 0usize;
    b.scan_prefix(b"p:", &mut |k, v| {
        assert_eq!(k, b"p:1");
        assert_eq!(v, b"v");
        seen += 1;
        true
    })
    .unwrap();
    assert_eq!(seen, 1);
}

// ------------------------------------------- MemoryStorage conformance

macro_rules! memory_storage_conformance {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                super::$name(&mut MemoryStorage::new());
            }
        )*
    };
}

mod memory_storage {
    use super::*;

    memory_storage_conformance!(
        check_scan_returns_pairs_in_ascending_key_order,
        check_scan_excludes_neighbouring_prefixes,
        check_empty_prefix_visits_everything_in_byte_order,
        check_scan_agrees_with_point_lookup,
        check_scan_ignores_deleted_keys,
        check_scan_sees_a_key_reinserted_after_delete,
        check_prefix_matching_nothing_is_not_an_error,
        check_returning_false_stops_the_scan,
        check_batch_applies_every_operation,
        check_later_operations_win_on_the_same_key,
        check_a_delete_then_put_on_one_key_lands_the_put,
        check_interleaved_ops_resolve_in_slice_order,
        check_deleting_an_absent_key_in_a_batch_is_not_an_error,
        check_an_empty_batch_is_a_no_op,
    );
}
