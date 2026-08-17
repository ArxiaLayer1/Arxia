//! `MemoryStorage`'s wrappers over the shared conformance suite, plus
//! the fixtures proving the atomicity check can actually fail.
//!
//! The checks themselves live in `arxia_storage::conformance` behind
//! the `conformance` feature, so backend crates run the identical
//! suite instead of a copy that could drift. This file holds what must
//! run exactly once: the fixture pair validating
//! `conformance::batch_atomicity_holds` discriminates, and the
//! object-safety pin.

use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::conformance;
use arxia_storage::{BatchOp, MemoryStorage, StorageBackend};

// ---------------------------------------------------- the atomicity contract

/// The sequential fallback the trait documentation warns about: it
/// writes each operation to the live store as it goes, then fails.
/// Deliberately non-compliant — the atomicity check must reject it.
struct AppliesThenFails {
    inner: MemoryStorage,
    fail_at: usize,
}

/// Compliant counterpart: the same per-operation work, but into a
/// staging buffer abandoned on fault, so the live store is never
/// written. The two fixtures differ only in *where* they write, which
/// is precisely the property under test.
struct StagesThenFails {
    inner: MemoryStorage,
    fail_at: usize,
}

fn fault() -> ArxiaError {
    ArxiaError::Storage {
        fault: StorageFault::Backend {
            detail: "simulated mid-batch fault".into(),
        },
    }
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
        conformance::batch_atomicity_holds(&mut StagesThenFails {
            inner: MemoryStorage::new(),
            fail_at: 2,
        }),
        "a backend that stages before writing must satisfy the contract"
    );

    assert!(
        !conformance::batch_atomicity_holds(&mut AppliesThenFails {
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
    assert!(conformance::batch_atomicity_holds(&mut StagesThenFails {
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
                conformance::$name(&mut MemoryStorage::new());
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
        check_a_batch_carries_a_protocol_sized_block,
        check_a_transfer_sized_batch_applies_atomically,
        check_unstorable_keys_read_as_absent,
    );

    /// Belt-and-braces: iterate `all_checks` too, so a check added to
    /// the conformance module but missing from the wrapper list above
    /// still runs here — and a drift between the two shows up as a
    /// count mismatch.
    #[test]
    fn every_registered_check_passes() {
        let checks = conformance::all_checks::<MemoryStorage>();
        assert_eq!(checks.len(), 17, "wrapper list above may be stale");
        for (_name, check) in checks {
            let mut fresh = MemoryStorage::new();
            check(&mut fresh);
        }
    }
}
