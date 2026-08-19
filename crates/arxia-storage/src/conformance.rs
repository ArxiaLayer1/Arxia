//! Conformance checks for the [`StorageBackend`](crate::StorageBackend)
//! contract, reusable by every backend crate.
//!
//! Each check is a generic function over `B: StorageBackend` that
//! panics on violation, in the style of a test assertion. A backend
//! crate declares a dev-dependency on `arxia-storage` with the
//! `conformance` feature and wraps each check in a thin `#[test]`
//! supplying a fresh instance of its backend. `MemoryStorage`'s own
//! wrappers live in this crate's `tests/trait_contract.rs`; a
//! persistent backend adds identical wrappers and is thereby held to
//! exactly the same expectations — anything that passes against
//! `MemoryStorage` and fails against redb or a flash backend is a real
//! behavioural difference, not a test artefact.
//!
//! The checks live behind a feature (rather than in a test file)
//! because Rust test targets are not importable across crates, and
//! duplicating the suite per backend would let the copies drift apart
//! — which is precisely what a conformance suite exists to prevent.
//!
//! # What is deliberately not here
//!
//! The two fault-injection fixtures proving that
//! [`batch_atomicity_holds`] can actually fail (a backend that writes
//! as it goes must be rejected, one that stages must pass) remain in
//! `tests/trait_contract.rs`: they validate the *check*, not a
//! backend, and need to run only once.

use crate::{BatchOp, StorageBackend};
use arxia_core::{ArxiaError, StorageFault};

use alloc::vec;
use alloc::vec::Vec;

/// Collect every `(key, value)` under `prefix`, in visit order.
pub fn collect_prefix<B: StorageBackend>(b: &B, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
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
/// byte comparison picks up the neighbour. `d:\xFF\xFF` sits above
/// every ASCII key, so a backend treating key bytes as signed sorts it
/// first.
fn seed<B: StorageBackend>(b: &mut B) {
    b.put(b"c:acct:0010", b"ten").unwrap();
    b.put(b"c:acct:0001", b"one").unwrap();
    b.put(b"d:\xFF\xFF", b"high").unwrap();
    b.put(b"c:acct:0002", b"two").unwrap();
    b.put(b"a:other", b"skip").unwrap();
    b.put(b"c:acctZzz", b"neighbour").unwrap();
}

// ------------------------------------------------------------- scanning

/// Scan yields full pairs, ascending by key byte, insertion order be
/// damned. Values are asserted, not just keys: a backend pairing the
/// right keys with the wrong values would otherwise pass every scan
/// check.
pub fn check_scan_returns_pairs_in_ascending_key_order<B: StorageBackend>(b: &mut B) {
    seed(b);
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

/// A key sharing the stem but not the prefix must not be visited.
pub fn check_scan_excludes_neighbouring_prefixes<B: StorageBackend>(b: &mut B) {
    seed(b);
    let got = collect_prefix(b, b"c:acct:");
    assert!(
        !got.iter().any(|(k, _)| k.as_slice() == b"c:acctZzz"),
        "a key sharing the stem but not the prefix must not be visited"
    );
    assert_eq!(got.len(), 3);
}

/// The empty prefix visits the whole store, still in byte order, with
/// the `0xFF` key last — key bytes are unsigned.
pub fn check_empty_prefix_visits_everything_in_byte_order<B: StorageBackend>(b: &mut B) {
    seed(b);
    assert_eq!(
        collect_prefix(b, b""),
        vec![
            pair(b"a:other", b"skip"),
            pair(b"c:acct:0001", b"one"),
            pair(b"c:acct:0002", b"two"),
            pair(b"c:acct:0010", b"ten"),
            pair(b"c:acctZzz", b"neighbour"),
            pair(b"d:\xFF\xFF", b"high"),
        ]
    );
}

/// Pins the two read paths together, so a backend cannot serve a stale
/// or separate index from `scan_prefix`.
pub fn check_scan_agrees_with_point_lookup<B: StorageBackend>(b: &mut B) {
    seed(b);
    for (k, v) in collect_prefix(b, b"") {
        assert_eq!(
            b.get(&k).unwrap().as_deref(),
            Some(v.as_slice()),
            "scan and get disagree on {k:?}"
        );
    }
}

/// A tombstoned key must not remain visible to a scan — through either
/// removal path, since a backend may implement them separately.
pub fn check_scan_ignores_deleted_keys<B: StorageBackend>(b: &mut B) {
    seed(b);
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

/// A deleted-then-reinserted key reappears once, in position, with the
/// new value — the classic tombstone-shadowing bug in log-structured
/// stores.
pub fn check_scan_sees_a_key_reinserted_after_delete<B: StorageBackend>(b: &mut B) {
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

/// A prefix matching nothing visits nothing and is not an error.
pub fn check_prefix_matching_nothing_is_not_an_error<B: StorageBackend>(b: &mut B) {
    seed(b);
    assert!(collect_prefix(b, b"zzz").is_empty());
}

/// Returning `false` stops the walk after the current entry and is not
/// an error.
pub fn check_returning_false_stops_the_scan<B: StorageBackend>(b: &mut B) {
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

/// A successful batch applies every operation, and touches only the
/// keys it names.
pub fn check_batch_applies_every_operation<B: StorageBackend>(b: &mut B) {
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
    assert_eq!(
        b.get(b"untouched").unwrap().as_deref(),
        Some(b"keep-me".as_slice()),
        "a key absent from the batch must survive it"
    );
}

/// Later operations override earlier ones on the same key. A backend
/// grouping puts and deletes instead of honouring slice order would
/// resolve these differently.
pub fn check_later_operations_win_on_the_same_key<B: StorageBackend>(b: &mut B) {
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

/// A Delete followed by a Put of the same key lands the Put — and the
/// scan agrees.
pub fn check_a_delete_then_put_on_one_key_lands_the_put<B: StorageBackend>(b: &mut B) {
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

/// Interleaved operations on one key resolve strictly in slice order.
pub fn check_interleaved_ops_resolve_in_slice_order<B: StorageBackend>(b: &mut B) {
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

/// Deleting an absent key inside a batch is not an error.
pub fn check_deleting_an_absent_key_in_a_batch_is_not_an_error<B: StorageBackend>(b: &mut B) {
    assert!(b
        .apply_batch(&[BatchOp::Delete {
            key: b"never-existed"
        }])
        .is_ok());
}

/// The empty batch succeeds and changes nothing.
pub fn check_an_empty_batch_is_a_no_op<B: StorageBackend>(b: &mut B) {
    b.put(b"k", b"v").unwrap();
    b.apply_batch(&[]).unwrap();
    assert_eq!(b.get(b"k").unwrap().as_deref(), Some(b"v".as_slice()));
}

// ---------------------------------------------------- the atomicity contract

/// Reports whether `b` honoured the all-or-nothing guarantee on a
/// failing batch, instead of asserting it.
///
/// Returning a `bool` is what makes the check itself testable: a
/// conformance check for a failure path is worthless unless something
/// proves it can actually fail. The fixture pair in this crate's
/// `tests/trait_contract.rs` does exactly that — a backend that stages
/// before writing must satisfy it, a backend that writes as it goes
/// must be caught by it.
///
/// Only meaningful for a backend whose `apply_batch` can be made to
/// fail (a fault-injection wrapper, a full disk, a closed file). A
/// backend that cannot fail here — `MemoryStorage` is infallible by
/// construction — has nothing for this check to observe; its atomicity
/// is exercised under real faults instead (the redb backend does so by
/// killing a writer process mid-batch).
///
/// The batch covers all three observable effects — a key added, a key
/// removed, a key overwritten — because a backend that rolled back only
/// its insertions would pass a check watching insertions alone.
pub fn batch_atomicity_holds<B: StorageBackend>(b: &mut B) -> bool {
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

/// A registered conformance check: the name reported on failure, and
/// the generic function to run against a fresh backend instance.
pub type NamedCheck<B> = (&'static str, fn(&mut B));

/// A protocol-sized value: the compact block is 193 bytes, and a
/// backend test anywhere in the workspace should reach for this
/// instead of minting its own copy - the sizes are part of what the
/// suite tests, and copies drift.
///
/// Original rationale: a
/// backend that only ever sees three-byte test payloads can hide a
/// capacity bug that fires on the very first real block. Every batch
/// check below carries one.
pub fn realistic_value(tag: u8) -> Vec<u8> {
    let mut v = vec![tag; 193];
    v[0] = 0xAB; // a marker so a truncated write is visible
    v
}

/// A protocol-sized key: `c:` plus a 64-hex-char account plus a nonce
/// suffix is what an account-chain key actually looks like.
pub fn realistic_key(suffix: &str) -> Vec<u8> {
    let mut k = b"c:".to_vec();
    k.extend_from_slice(&[b'a'; 64]);
    k.push(b':');
    k.extend_from_slice(suffix.as_bytes());
    k
}

/// A batch carrying a protocol-sized block under a protocol-sized key.
///
/// This is the crate's whole reason to exist, and it is exactly the
/// case a backend can fail while passing every toy-sized check: an
/// embedded backend that journals a batch operation as
/// `tag + key + value` needs room for more than one payload, and a cap
/// applied to the whole record rather than to the payload rejects the
/// first real block it ever sees.
pub fn check_a_batch_carries_a_protocol_sized_block<B: StorageBackend>(b: &mut B) {
    let key = realistic_key("0001");
    let value = realistic_value(0x11);
    b.apply_batch(&[BatchOp::Put {
        key: &key,
        value: &value,
    }])
    .expect("a batch must accept a protocol-sized block under a chain key");

    assert_eq!(
        b.get(&key).unwrap().as_deref(),
        Some(value.as_slice()),
        "the block must come back byte-for-byte"
    );
    assert_eq!(
        collect_prefix(b, b"c:"),
        vec![(key, value)],
        "and be visible to a scan"
    );
}

/// A whole transfer's worth of writes in one batch, at real sizes: two
/// blocks and the index maintenance that accompanies them.
pub fn check_a_transfer_sized_batch_applies_atomically<B: StorageBackend>(b: &mut B) {
    let send = realistic_key("0007");
    let recv = realistic_key("0008");
    let index = b"s:0123456789abcdef".to_vec();
    let sv = realistic_value(0x22);
    let rv = realistic_value(0x33);

    b.apply_batch(&[
        BatchOp::Put {
            key: &send,
            value: &sv,
        },
        BatchOp::Put {
            key: &recv,
            value: &rv,
        },
        BatchOp::Put {
            key: &index,
            value: b"destination+amount",
        },
    ])
    .expect("a transfer-sized batch must apply");

    assert_eq!(b.get(&send).unwrap().as_deref(), Some(sv.as_slice()));
    assert_eq!(b.get(&recv).unwrap().as_deref(), Some(rv.as_slice()));
    assert!(b.contains(&index).unwrap());
}

/// A key no realistic schema stores must read as absent, never as an
/// error.
///
/// A bounded backend cannot store a 200-byte key; the truthful answer
/// to "what does it hold?" is still "nothing", exactly as an
/// unbounded backend answers for a key nobody wrote. A read that
/// errs on an unstorable key splits the backends' behaviour on the
/// reads the trait promises are total, and callers start needing
/// backend-specific error handling on the lookup path.
pub fn check_unstorable_keys_read_as_absent<B: StorageBackend>(b: &mut B) {
    let oversized = vec![b'k'; 200];
    assert_eq!(
        b.get(&oversized).expect("get is total"),
        None,
        "a key that cannot exist reads as absent"
    );
    assert!(
        !b.contains(&oversized).expect("contains is total"),
        "and is not contained"
    );
    assert!(
        !b.delete(&oversized)
            .expect("delete of an absent key is total"),
        "and deleting it deletes nothing"
    );
}

/// A write the backend refuses leaves the store byte-for-byte
/// unchanged, and reads keep answering; a write it does not refuse
/// lands in full. Either way, the refusal classes are the two the
/// trait licenses and no other.
///
/// The probe is a value larger than any bounded backend stores (a
/// 4 KiB payload under a valid key). An unbounded backend accepts it -
/// the check then holds it to full round-trip. A bounded backend
/// refuses it - the check then holds the refusal to the licensed
/// class, the store to unchanged, and reads to answering. Both
/// branches are exercised on every backend the suite runs against, so
/// a backend that refused with a foreign class, or that partially
/// wrote before refusing, or that stopped answering reads after a
/// refusal, fails here regardless of which side of the bound it sits.
pub fn check_write_refusals_are_typed_and_leave_the_store_intact<B: StorageBackend>(b: &mut B) {
    b.put(b"w:anchor", b"anchor").unwrap();
    let key = b"w:probe";
    let huge = vec![0xC7u8; 4096];

    match b.put(key, &huge) {
        Ok(()) => {
            assert_eq!(
                b.get(key).unwrap().as_deref(),
                Some(huge.as_slice()),
                "an accepted write lands in full"
            );
        }
        Err(e) => {
            assert!(
                matches!(
                    e,
                    ArxiaError::Storage {
                        fault: StorageFault::CapacityExceeded { .. }
                    } | ArxiaError::Storage {
                        fault: StorageFault::ReservedKey
                    }
                ),
                "a write refusal must be one of the two licensed classes, got: {e}"
            );
            assert_eq!(
                b.get(key).unwrap(),
                None,
                "a refused write leaves nothing behind"
            );
        }
    }
    // The store around the probe is untouched either way, and reads
    // still answer.
    assert_eq!(
        b.get(b"w:anchor").unwrap().as_deref(),
        Some(b"anchor".as_slice()),
        "a refusal never disturbs neighbouring keys"
    );

    // The same contract through the batch path: a batch carrying the
    // probe is accepted whole or refused whole.
    let before = collect_prefix(b, b"w:");
    match b.apply_batch(&[
        BatchOp::Put {
            key: b"w:batch-a",
            value: b"a",
        },
        BatchOp::Put {
            key: b"w:batch-probe",
            value: &huge,
        },
    ]) {
        Ok(()) => {
            assert!(b.contains(b"w:batch-a").unwrap());
            assert_eq!(
                b.get(b"w:batch-probe").unwrap().as_deref(),
                Some(huge.as_slice())
            );
        }
        Err(e) => {
            assert!(
                matches!(
                    e,
                    ArxiaError::Storage {
                        fault: StorageFault::CapacityExceeded { .. }
                    } | ArxiaError::Storage {
                        fault: StorageFault::ReservedKey
                    }
                ),
                "a batch refusal must be one of the two licensed classes, got: {e}"
            );
            assert_eq!(
                collect_prefix(b, b"w:"),
                before,
                "a refused batch leaves the store byte-for-byte as it was"
            );
        }
    }
}

/// Every scan/batch check in this module, as `(name, function)` pairs,
/// so a backend crate can also run the whole suite in one loop if it
/// prefers that over per-check wrappers. Kept in one place so a check
/// added here cannot be silently missing from a backend that iterates.
pub fn all_checks<B: StorageBackend>() -> Vec<NamedCheck<B>> {
    vec![
        (
            "scan_returns_pairs_in_ascending_key_order",
            check_scan_returns_pairs_in_ascending_key_order::<B>,
        ),
        (
            "scan_excludes_neighbouring_prefixes",
            check_scan_excludes_neighbouring_prefixes::<B>,
        ),
        (
            "empty_prefix_visits_everything_in_byte_order",
            check_empty_prefix_visits_everything_in_byte_order::<B>,
        ),
        (
            "scan_agrees_with_point_lookup",
            check_scan_agrees_with_point_lookup::<B>,
        ),
        (
            "scan_ignores_deleted_keys",
            check_scan_ignores_deleted_keys::<B>,
        ),
        (
            "scan_sees_a_key_reinserted_after_delete",
            check_scan_sees_a_key_reinserted_after_delete::<B>,
        ),
        (
            "prefix_matching_nothing_is_not_an_error",
            check_prefix_matching_nothing_is_not_an_error::<B>,
        ),
        (
            "returning_false_stops_the_scan",
            check_returning_false_stops_the_scan::<B>,
        ),
        (
            "batch_applies_every_operation",
            check_batch_applies_every_operation::<B>,
        ),
        (
            "later_operations_win_on_the_same_key",
            check_later_operations_win_on_the_same_key::<B>,
        ),
        (
            "a_delete_then_put_on_one_key_lands_the_put",
            check_a_delete_then_put_on_one_key_lands_the_put::<B>,
        ),
        (
            "interleaved_ops_resolve_in_slice_order",
            check_interleaved_ops_resolve_in_slice_order::<B>,
        ),
        (
            "deleting_an_absent_key_in_a_batch_is_not_an_error",
            check_deleting_an_absent_key_in_a_batch_is_not_an_error::<B>,
        ),
        (
            "an_empty_batch_is_a_no_op",
            check_an_empty_batch_is_a_no_op::<B>,
        ),
        (
            "a_batch_carries_a_protocol_sized_block",
            check_a_batch_carries_a_protocol_sized_block::<B>,
        ),
        (
            "a_transfer_sized_batch_applies_atomically",
            check_a_transfer_sized_batch_applies_atomically::<B>,
        ),
        (
            "unstorable_keys_read_as_absent",
            check_unstorable_keys_read_as_absent::<B>,
        ),
        (
            "write_refusals_are_typed_and_leave_the_store_intact",
            check_write_refusals_are_typed_and_leave_the_store_intact::<B>,
        ),
    ]
}
