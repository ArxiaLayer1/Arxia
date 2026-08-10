//! `FlashStorage` held to the shared `StorageBackend` conformance
//! suite, plus the fixtures that judge this backend's own machinery.
//!
//! The conformance checks are imported, not copied: the same generic
//! functions `MemoryStorage` and `RedbStorage` pass. What is extra
//! here judges the parts of this backend that have no counterpart
//! elsewhere — the ordered scan built on an unordered log, the
//! duplicate resolution the log forces, and the erase accounting the
//! hardware bench will compare against.

use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::conformance;
use arxia_storage::StorageBackend;
use arxia_storage_flash::{FlashStorage, SCAN_WINDOW};
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};

/// 16 pages of 4 KiB, single-byte words — the closest the mock gets to
/// the T-Beam's 4 KiB-sector NOR part.
type Flash = MockFlashBase<16, 1, 4096>;

const RANGE: core::ops::Range<u32> = 0..(16 * 4096);

fn fresh() -> FlashStorage<Flash> {
    let flash = Flash::new(WriteCountCheck::Twice, None, true);
    FlashStorage::<Flash>::mount(flash, RANGE).expect("mount")
}

macro_rules! flash_conformance {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                conformance::$name(&mut fresh());
            }
        )*
    };
}

flash_conformance!(
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
);

/// The same drift guard the other backends carry: a check added to
/// the shared module but missing from the wrapper list above shows up
/// as a count mismatch here.
#[test]
fn every_registered_check_passes() {
    let checks = conformance::all_checks::<FlashStorage<Flash>>();
    assert_eq!(checks.len(), 16, "wrapper list above may be stale");
    for (_name, check) in checks {
        let mut store = fresh();
        check(&mut store);
    }
}

// ------------------------------------------------- the log's own hazards

/// The log yields every version of an overwritten key, oldest first
/// (measured against sequential-storage 8.0.1, recorded with the
/// dependency-risk entry). A scan must emit the key once, carrying the
/// live value. A window that kept the first occurrence would serve
/// stale data from a scan while point lookups returned the current
/// value — the two read paths would disagree.
#[test]
fn an_overwritten_key_is_emitted_once_with_the_live_value() {
    let mut s = fresh();
    s.put(b"k:1", b"first").unwrap();
    s.put(b"k:1", b"second").unwrap();

    let got = conformance::collect_prefix(&s, b"k:");
    assert_eq!(
        got,
        vec![(b"k:1".to_vec(), b"second".to_vec())],
        "one entry, the live one"
    );
    assert_eq!(
        s.get(b"k:1").unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}

/// Several overwrites of several keys, interleaved: every key appears
/// once, in order, with its last value. This is the case where a
/// first-occurrence-wins window and a last-occurrence-wins window
/// disagree on more than one key at a time.
#[test]
fn interleaved_overwrites_all_resolve_to_their_last_value() {
    let mut s = fresh();
    s.put(b"k:a", b"a1").unwrap();
    s.put(b"k:b", b"b1").unwrap();
    s.put(b"k:a", b"a2").unwrap();
    s.put(b"k:c", b"c1").unwrap();
    s.put(b"k:b", b"b2").unwrap();
    s.put(b"k:a", b"a3").unwrap();

    assert_eq!(
        conformance::collect_prefix(&s, b"k:"),
        vec![
            (b"k:a".to_vec(), b"a3".to_vec()),
            (b"k:b".to_vec(), b"b2".to_vec()),
            (b"k:c".to_vec(), b"c1".to_vec()),
        ]
    );
}

/// A deleted key never appears in a scan.
///
/// On 8.0.1 the iterator does not yield removed keys at all (measured),
/// so this currently passes without the window doing anything. It is
/// pinned regardless: that behaviour is an implementation detail of the
/// pinned version, not a documented contract, and a future bump that
/// starts surfacing tombstones must fail here rather than start
/// serving deleted blocks from a scan.
#[test]
fn a_deleted_key_never_appears_in_a_scan() {
    let mut s = fresh();
    s.put(b"k:1", b"one").unwrap();
    s.put(b"k:2", b"two").unwrap();
    s.put(b"k:3", b"three").unwrap();
    assert!(s.delete(b"k:2").unwrap());

    assert_eq!(
        conformance::collect_prefix(&s, b"k:"),
        vec![
            (b"k:1".to_vec(), b"one".to_vec()),
            (b"k:3".to_vec(), b"three".to_vec()),
        ]
    );
    assert!(!s.contains(b"k:2").unwrap());
}

// ------------------------------------------------ the window's mechanics

/// More keys than one window holds, so the scan must cross the
/// multi-pass boundary and stitch the passes in order.
///
/// A window that re-emitted its last key each pass (a `>=` instead of
/// `>` comparison against the last key emitted) would duplicate one
/// key per boundary; a window that skipped one would lose it.
#[test]
fn a_result_set_larger_than_the_window_crosses_passes_cleanly() {
    let mut s = fresh();
    let count = SCAN_WINDOW * 3 + 1;
    // Insert in reverse order so nothing about the log order helps.
    for i in (0..count).rev() {
        let key = alloc_key(i);
        s.put(&key, &[i as u8]).unwrap();
    }

    let got = conformance::collect_prefix(&s, b"w:");
    assert_eq!(got.len(), count, "every key exactly once");
    let expected: Vec<Vec<u8>> = (0..count).map(alloc_key).collect();
    let keys: Vec<Vec<u8>> = got.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, expected, "ascending across the pass boundaries");
    for (i, (_, v)) in got.iter().enumerate() {
        assert_eq!(v, &[i as u8], "each key keeps its own value");
    }
}

/// The `0xFF` key sorts last, not first: key bytes are unsigned, and a
/// window comparing them as signed would place it before everything.
#[test]
fn the_high_byte_key_sorts_last() {
    let mut s = fresh();
    s.put(b"w:\x01", b"low").unwrap();
    s.put(b"w:\xFF", b"high").unwrap();
    s.put(b"w:\x7F", b"mid").unwrap();

    let got = conformance::collect_prefix(&s, b"w:");
    assert_eq!(
        got.last().map(|(k, _)| k.clone()),
        Some(b"w:\xFF".to_vec()),
        "0xFF is the largest byte"
    );
    assert_eq!(got.len(), 3);
}

/// Exactly one window's worth: the boundary where a pass fills without
/// spilling. An off-by-one in the fill or the emit shows up here.
#[test]
fn a_result_set_of_exactly_one_window_is_complete() {
    let mut s = fresh();
    for i in 0..SCAN_WINDOW {
        s.put(&alloc_key(i), &[i as u8]).unwrap();
    }
    assert_eq!(conformance::collect_prefix(&s, b"w:").len(), SCAN_WINDOW);
}

fn alloc_key(i: usize) -> Vec<u8> {
    // Fixed width so byte order and numeric order agree.
    format!("w:{i:04}").into_bytes()
}

// -------------------------------------------------------- erase counting

/// Erase accounting, instrumented from the start rather than added
/// when the bench needs it.
///
/// This asserts only the shape the endurance model depends on — that
/// writes eventually erase, and that the count is observable — because
/// the absolute number belongs to the hardware, not the mock. The
/// M3-6 bench compares real erases against the model's predictions;
/// this test exists so the counter is wired and cannot silently stop
/// counting.
#[test]
fn erases_are_observable_and_grow_with_write_volume() {
    let flash = Flash::new(WriteCountCheck::Twice, None, true);
    let before = flash.stats_snapshot();
    let mut s = FlashStorage::<Flash>::mount(flash, RANGE).expect("mount");

    // Repeatedly overwrite a small live set: the dead versions pile
    // up until the log wraps and reclaims pages. Writing 400 *distinct*
    // keys would instead fill the region with live data and fail with
    // FullStorage, which is a capacity result, not a wear one.
    let payload = [0xA5u8; 200];
    for round in 0..40 {
        for i in 0..8 {
            let key = format!("e:{i:02}").into_bytes();
            let mut v = payload;
            v[0] = round as u8;
            s.put(&key, &v).unwrap();
        }
    }

    let after = s.flash().stats_snapshot();
    let erases = before.compare_to(after).erases;
    assert!(
        erases > 0,
        "a wrapping log must have erased pages; counter read {erases}"
    );
}
// --------------------------------------------- the reserved namespace

/// A key in the reserved namespace is refused with a typed fault —
/// never accepted and then lost.
///
/// The probe that motivated this: before the guard existed, a put of a
/// key beginning with 0x00 was accepted, hidden from every read, and
/// silently discarded by the next mount as uncommitted journal debris.
/// An accepted write that evaporates is the worst outcome a store can
/// produce, so the write must be refused up front, typed, on every
/// write path — and the data that was legitimately stored must survive
/// a remount untouched.
#[test]
fn a_reserved_key_is_refused_typed_and_nothing_is_lost() {
    let flash = Flash::new(WriteCountCheck::Twice, None, true);
    let mut s = FlashStorage::<Flash>::mount(flash, RANGE).expect("mount");
    s.put(b"u:real", b"kept").unwrap();

    let refused = |r: Result<(), ArxiaError>| {
        matches!(
            r,
            Err(ArxiaError::Storage {
                fault: StorageFault::ReservedKey
            })
        )
    };
    assert!(
        refused(s.put(b"\x00evil", b"data")),
        "put must refuse, typed"
    );
    assert!(
        refused(s.apply_batch(&[arxia_storage::BatchOp::Put {
            key: b"\x00evil",
            value: b"data",
        }])),
        "the batch path must refuse too"
    );
    assert!(
        refused(s.apply_batch(&[arxia_storage::BatchOp::Delete { key: b"\x00evil" }])),
        "a batched delete of a reserved key is refused as well"
    );
    assert!(
        s.get(b"\x00evil").is_err(),
        "reads do not reach the namespace"
    );

    // The remount that used to destroy the evidence: the legitimate
    // key survives, and nothing under 0x00 ever existed.
    let s2 = FlashStorage::<Flash>::mount(s.into_flash(), RANGE).expect("remount");
    assert_eq!(
        s2.get(b"u:real").unwrap().as_deref(),
        Some(b"kept".as_slice())
    );
}

// ------------------------------------------------------ reentrant reads

/// The visit callback may read the store it is scanning.
///
/// The struct documents that no internal borrow is held across a call
/// into user code; before the fix, this test panicked on a RefCell
/// already borrowed. A node iterating an account chain and resolving
/// each block's source on the spot is exactly this shape.
#[test]
fn a_scan_callback_may_read_the_store_it_scans() {
    let mut s = fresh();
    s.put(b"k:1", b"one").unwrap();
    s.put(b"k:2", b"two").unwrap();
    s.put(b"k:3", b"three").unwrap();

    let mut checked = 0;
    s.scan_prefix(b"k:", &mut |k, v| {
        // A reentrant point lookup from inside the visitor.
        assert_eq!(
            s.get(k).unwrap().as_deref(),
            Some(v),
            "the reentrant read must agree with the scan"
        );
        assert!(s.contains(k).unwrap());
        checked += 1;
        true
    })
    .unwrap();
    assert_eq!(checked, 3, "every entry was visited and cross-checked");
}
/// The degenerate window, exercised rather than assumed safe.
///
/// At `W = 1` every key needs its own pass, so pass-stitching runs
/// under maximum pressure: any off-by-one in the strictly-greater
/// resume comparison duplicates or drops a key immediately. Mutating
/// `SCAN_WINDOW` to 1 is expected to *survive* the mutation suite -
/// the setting is slow, not wrong - which is exactly why the size is a
/// const generic: correctness must not depend on it, and this test is
/// where that claim is exercised.
#[test]
fn a_window_of_one_still_scans_correctly() {
    let flash = Flash::new(WriteCountCheck::Twice, None, true);
    let mut s: FlashStorage<Flash, 1> =
        FlashStorage::<Flash, 1>::mount(flash, RANGE).expect("mount");
    for i in (0..5).rev() {
        s.put(&alloc_key(i), &[i as u8]).unwrap();
    }
    s.put(b"w:0002", b"rewritten").unwrap(); // a duplicate to resolve

    let got = conformance::collect_prefix(&s, b"w:");
    let keys: Vec<Vec<u8>> = got.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, (0..5).map(alloc_key).collect::<Vec<_>>());
    assert_eq!(
        got[2].1,
        b"rewritten".to_vec(),
        "last occurrence wins at W=1 too"
    );
}
