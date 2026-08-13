//! `RedbStorage` held to the shared `StorageBackend` conformance suite.
//!
//! These are the same generic checks `MemoryStorage` passes in
//! `arxia-storage/tests/trait_contract.rs` — imported, not copied, so
//! the two backends cannot drift apart. Each wrapper supplies a fresh
//! database in its own temporary directory; the directory (and the
//! database file with it) is removed when the guard drops.

use arxia_storage::conformance;
use arxia_storage_redb::RedbStorage;

/// Fresh backend in a fresh temp dir. The `TempDir` guard is returned
/// so the caller keeps it alive for the duration of the check.
fn fresh() -> (tempfile::TempDir, RedbStorage) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let store = RedbStorage::open(dir.path().join("conformance.redb")).expect("open database");
    (dir, store)
}

macro_rules! redb_conformance {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let (_dir, mut store) = fresh();
                conformance::$name(&mut store);
            }
        )*
    };
}

redb_conformance!(
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

/// Same drift guard as the in-memory suite: every check registered in
/// the conformance module runs, so one added there but missing from
/// the wrapper list above cannot be silently skipped for this backend.
#[test]
fn every_registered_check_passes() {
    let checks = conformance::all_checks::<RedbStorage>();
    assert_eq!(checks.len(), 17, "wrapper list above may be stale");
    for (_name, check) in checks {
        let (_dir, mut store) = fresh();
        check(&mut store);
    }
}

/// Persistence across a clean close and reopen — the one behaviour the
/// in-memory backend cannot have, so it lives here rather than in the
/// shared suite.
#[test]
fn data_survives_a_clean_reopen() {
    use arxia_storage::{BatchOp, StorageBackend};

    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("reopen.redb");

    {
        let mut store = RedbStorage::open(&path).expect("first open");
        store.put(b"k:point", b"via-put").expect("put");
        store
            .apply_batch(&[
                BatchOp::Put {
                    key: b"k:batch",
                    value: b"via-batch",
                },
                BatchOp::Put {
                    key: b"k:gone",
                    value: b"temp",
                },
                BatchOp::Delete { key: b"k:gone" },
            ])
            .expect("batch");
        // `store` drops here; the Database closes with it.
    }

    let store = RedbStorage::open(&path).expect("reopen");
    assert_eq!(
        store.get(b"k:point").expect("get").as_deref(),
        Some(b"via-put".as_slice())
    );
    assert_eq!(
        store.get(b"k:batch").expect("get").as_deref(),
        Some(b"via-batch".as_slice())
    );
    assert!(!store.contains(b"k:gone").expect("contains"));
    assert_eq!(conformance::collect_prefix(&store, b"k:").len(), 2);
}
/// The backend fault path, pinned through the public API: opening a
/// database in a directory that does not exist surfaces the engine's
/// I/O diagnostic as StorageFault::Backend, detail preserved.
#[test]
fn engine_faults_surface_as_backend_with_detail() {
    use arxia_core::{ArxiaError, StorageFault};

    let dir = tempfile::tempdir().expect("create temp dir");
    let bad = dir.path().join("no-such-parent").join("db.redb");
    let err = match RedbStorage::open(&bad) {
        Err(e) => e,
        Ok(_) => panic!("missing parent dir must fail"),
    };
    match err {
        ArxiaError::Storage {
            fault: StorageFault::Backend { detail },
        } => assert!(!detail.is_empty(), "engine diagnostic must be preserved"),
        other => panic!("expected Storage Backend fault, got {other:?}"),
    }
}
