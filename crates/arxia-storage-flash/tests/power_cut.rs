//! The commit-marker seal, tested by cutting power mid-batch.
//!
//! `sequential-storage` is power-fail safe per item; the trait demands
//! it per batch. The seal closes that gap, and this file is what makes
//! the closure falsifiable: a flash that dies after a chosen number of
//! writes stands in for the plug being pulled, and every cut point
//! across a batch is walked.
//!
//! The two outcomes the trait allows are the only two accepted here.
//! Cut before the marker: the batch never happened, and no journal
//! bookkeeping survives into user-visible reads. Cut after it: mount
//! replays the journal and the batch happened in full. A partial batch
//! is a failure at any cut point.
//!
//! This is the software half of the guarantee. The hardware half — a
//! real plug pull, where the OS page cache and the flash chip's own
//! buffers are in play — belongs to the T-Beam bench, and no test on a
//! host can stand in for it.

use arxia_storage::{BatchOp, StorageBackend};
use arxia_storage_flash::FlashStorage;
use core::cell::Cell;
use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};

type Mock = MockFlashBase<16, 1, 4096>;
const RANGE: core::ops::Range<u32> = 0..(16 * 4096);

/// A flash that stops accepting writes after a budget is spent.
///
/// Standing in for a power cut rather than a fault: once the budget is
/// gone every write fails, exactly as a dead board writes nothing more.
/// Reads keep working so the same instance can be remounted and
/// inspected, which is what a board does when power returns.
struct DyingFlash {
    inner: Mock,
    writes_left: Cell<usize>,
}

impl DyingFlash {
    fn new(writes_left: usize) -> Self {
        Self {
            inner: Mock::new(WriteCountCheck::Twice, None, true),
            writes_left: Cell::new(writes_left),
        }
    }

    /// Power returns: the same flash contents, no write budget limit.
    fn revive(self) -> Self {
        Self {
            inner: self.inner,
            writes_left: Cell::new(usize::MAX),
        }
    }

    fn spend(&self) -> Result<(), DeadError> {
        let left = self.writes_left.get();
        if left == 0 {
            return Err(DeadError);
        }
        self.writes_left.set(left - 1);
        Ok(())
    }
}

#[derive(Debug)]
struct DeadError;

impl NorFlashError for DeadError {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}

impl ErrorType for DyingFlash {
    type Error = DeadError;
}

impl ReadNorFlash for DyingFlash {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.read(offset, bytes).await.map_err(|_| DeadError)
    }

    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl NorFlash for DyingFlash {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.spend()?;
        self.inner.erase(from, to).await.map_err(|_| DeadError)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.spend()?;
        self.inner.write(offset, bytes).await.map_err(|_| DeadError)
    }
}

impl MultiwriteNorFlash for DyingFlash {}

/// Run a batch against a flash that dies after `budget` writes, then
/// bring the power back and return the remounted store.
fn cut_power_during_batch(budget: usize, ops: &[BatchOp<'_>]) -> FlashStorage<DyingFlash> {
    let mut store =
        FlashStorage::<DyingFlash>::mount(DyingFlash::new(usize::MAX), RANGE).expect("first mount");
    // Seed state the batch will modify, so a partial application is
    // observable as a mixture rather than as mere absence.
    store.put(b"u:keep", b"original").expect("seed keep");
    store.put(b"u:doomed", b"original").expect("seed doomed");

    // The cut: from here the flash accepts `budget` more writes.
    store.flash().writes_left.set(budget);
    let _ = store.apply_batch(ops); // may fail; that is the point

    let flash = store.into_flash().revive();
    FlashStorage::<DyingFlash>::mount(flash, RANGE).expect("a cut batch must not brick the store")
}

fn batch<'a>() -> [BatchOp<'a>; 3] {
    [
        BatchOp::Put {
            key: b"u:added",
            value: b"new",
        },
        BatchOp::Delete { key: b"u:doomed" },
        BatchOp::Put {
            key: b"u:keep",
            value: b"rewritten",
        },
    ]
}

/// Every cut point across a batch leaves the store in one of the two
/// states the trait allows — never in between.
///
/// The budget sweeps from "dies before the first journal write" to
/// "survives the whole batch", so the marker write, the journal writes
/// and the apply writes each get to be the last thing that happened.
#[test]
fn every_cut_point_leaves_all_or_nothing() {
    for budget in 0..60 {
        let store = cut_power_during_batch(budget, &batch());

        let added = store.get(b"u:added").expect("get added");
        let doomed = store.get(b"u:doomed").expect("get doomed");
        let keep = store.get(b"u:keep").expect("get keep");

        let applied = added.as_deref() == Some(b"new".as_slice())
            && doomed.is_none()
            && keep.as_deref() == Some(b"rewritten".as_slice());
        let untouched = added.is_none()
            && doomed.as_deref() == Some(b"original".as_slice())
            && keep.as_deref() == Some(b"original".as_slice());

        assert!(
            applied || untouched,
            "budget {budget}: partial batch after recovery — \
             added={added:?} doomed={doomed:?} keep={keep:?}"
        );
    }
}

/// A cut batch never leaves journal bookkeeping visible to a reader.
///
/// The journal lives under a reserved prefix that reads and scans hide,
/// and an uncommitted journal is discarded at mount. A backend that let
/// those keys through would hand the ledger records that are not
/// blocks.
#[test]
fn no_journal_key_is_ever_visible_after_a_cut() {
    for budget in 0..60 {
        let store = cut_power_during_batch(budget, &batch());

        let mut seen: Vec<Vec<u8>> = Vec::new();
        store
            .scan_prefix(b"", &mut |k, _| {
                seen.push(k.to_vec());
                true
            })
            .expect("scan");

        for key in &seen {
            assert!(
                key.first() != Some(&0x00),
                "budget {budget}: reserved journal key {key:?} leaked into a scan"
            );
            assert!(
                key.starts_with(b"u:"),
                "budget {budget}: unexpected key {key:?} visible to a reader"
            );
        }
    }
}

/// A batch that completes normally leaves nothing behind: no journal,
/// no marker, only the data.
#[test]
fn a_completed_batch_leaves_no_bookkeeping() {
    let store = cut_power_during_batch(usize::MAX, &batch());

    let mut count = 0;
    store
        .scan_prefix(b"", &mut |k, _| {
            assert!(k.starts_with(b"u:"), "leftover key {k:?}");
            count += 1;
            true
        })
        .expect("scan");
    assert_eq!(count, 2, "u:added and u:keep survive; u:doomed was deleted");
    assert_eq!(
        store.get(b"u:keep").unwrap().as_deref(),
        Some(b"rewritten".as_slice())
    );
}
