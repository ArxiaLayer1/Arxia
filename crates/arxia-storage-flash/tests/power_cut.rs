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
//! Two cut families are walked, because the seal makes promises about
//! both: cuts during the batch itself, and cuts during the *recovery*
//! of an earlier cut batch — the documentation says a cut inside
//! recovery simply replays, and that claim is exercised here rather
//! than trusted. The batch payloads are protocol-sized (193-byte
//! blocks under chain keys): the journal-capacity bug was invisible to
//! toy payloads and found by review, not by this file, precisely
//! because everything here used three-byte values.
//!
//! This is the software half of the guarantee. The hardware half — a
//! real plug pull, where the OS page cache and the flash chip's own
//! buffers are in play — belongs to the T-Beam bench, and no test on a
//! host can stand in for it.

use arxia_storage::{BatchOp, StorageBackend};
use arxia_storage_flash::FlashStorage;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};
use std::rc::Rc;

type Mock = MockFlashBase<16, 1, 4096>;
const RANGE: core::ops::Range<u32> = 0..(16 * 4096);

/// A flash that stops accepting writes after a budget is spent.
///
/// Standing in for a power cut rather than a fault: once the budget is
/// gone every write fails, exactly as a dead board writes nothing more.
/// Reads keep working so the same instance can be remounted and
/// inspected, which is what a board does when power returns.
///
/// Contents and budget live behind `Rc`, so a clone is another handle
/// on the *same* flash. That is what lets a test survive a failed
/// mount: `mount` consumes the flash and does not give it back on
/// error, but a handle taken beforehand still reaches the medium —
/// exactly as the physical chip outlives the software that died on it.
#[derive(Clone)]
struct DyingFlash {
    inner: Rc<RefCell<Mock>>,
    writes_left: Rc<Cell<usize>>,
}

/// Complete a mock-flash future on its first poll, without awaiting.
///
/// Awaiting would hold the `RefCell` borrow across an await point,
/// which clippy rightly rejects. There is no need to await at all:
/// the single-poll property this whole backend is built on applies to
/// the mock too, so the test driver asserts it instead of working
/// around it. A pend here would mean the mock stopped completing
/// synchronously, which no test in this file could survive anyway.
fn complete<F: Future>(future: F) -> Result<F::Output, DeadError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(DeadError),
    }
}

impl DyingFlash {
    fn new(writes_left: usize) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true))),
            writes_left: Rc::new(Cell::new(writes_left)),
        }
    }

    /// Power returns: the same flash contents, no write budget limit.
    fn revive(self) -> Self {
        self.writes_left.set(usize::MAX);
        self
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
        let mut inner = self.inner.borrow_mut();
        complete(inner.read(offset, bytes))?.map_err(|_| DeadError)
    }

    fn capacity(&self) -> usize {
        self.inner.borrow().capacity()
    }
}

impl NorFlash for DyingFlash {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.spend()?;
        let mut inner = self.inner.borrow_mut();
        complete(inner.erase(from, to))?.map_err(|_| DeadError)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.spend()?;
        let mut inner = self.inner.borrow_mut();
        complete(inner.write(offset, bytes))?.map_err(|_| DeadError)
    }
}

impl MultiwriteNorFlash for DyingFlash {}

/// Protocol-sized batch material: 193-byte blocks under chain keys.
///
/// The sizes are the point, not a flourish. The journal-capacity bug
/// (a cap meant for one payload applied to a whole journal record)
/// passed every toy-sized test in this file and was caught by review;
/// these fixtures fail on any backend that cannot journal a real
/// block under a real key.
struct Fixture {
    added: Vec<u8>,
    doomed: Vec<u8>,
    keep: Vec<u8>,
    original: Vec<u8>,
    new_v: Vec<u8>,
    rewritten: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            added: chain_key(b'a', "0003"),
            doomed: chain_key(b'a', "0001"),
            keep: chain_key(b'a', "0002"),
            original: block(0x10),
            new_v: block(0x20),
            rewritten: block(0x30),
        }
    }

    fn ops(&self) -> [BatchOp<'_>; 3] {
        [
            BatchOp::Put {
                key: &self.added,
                value: &self.new_v,
            },
            BatchOp::Delete { key: &self.doomed },
            BatchOp::Put {
                key: &self.keep,
                value: &self.rewritten,
            },
        ]
    }

    /// True iff the batch is fully applied.
    fn applied(&self, s: &FlashStorage<DyingFlash>) -> bool {
        s.get(&self.added).unwrap().as_deref() == Some(self.new_v.as_slice())
            && s.get(&self.doomed).unwrap().is_none()
            && s.get(&self.keep).unwrap().as_deref() == Some(self.rewritten.as_slice())
    }

    /// True iff the store looks exactly as seeded.
    fn untouched(&self, s: &FlashStorage<DyingFlash>) -> bool {
        s.get(&self.added).unwrap().is_none()
            && s.get(&self.doomed).unwrap().as_deref() == Some(self.original.as_slice())
            && s.get(&self.keep).unwrap().as_deref() == Some(self.original.as_slice())
    }
}

/// A realistic account-chain key: `c:` + 64 hex chars + `:` + nonce.
fn chain_key(fill: u8, suffix: &str) -> Vec<u8> {
    let mut k = b"c:".to_vec();
    k.extend_from_slice(&[fill; 64]);
    k.push(b':');
    k.extend_from_slice(suffix.as_bytes());
    k
}

/// A compact-block-sized value.
fn block(tag: u8) -> Vec<u8> {
    let mut v = vec![tag; 193];
    v[0] = 0xAB;
    v
}

fn seeded_store(fx: &Fixture) -> FlashStorage<DyingFlash> {
    let mut store =
        FlashStorage::<DyingFlash>::mount(DyingFlash::new(usize::MAX), RANGE).expect("first mount");
    // Seed state the batch will modify, so a partial application is
    // observable as a mixture rather than as mere absence.
    store.put(&fx.keep, &fx.original).expect("seed keep");
    store.put(&fx.doomed, &fx.original).expect("seed doomed");
    store
}

/// How many flash writes one full batch costs, measured rather than
/// assumed, so the sweeps below cover every cut point even if the
/// storage library changes its write pattern.
fn writes_for_a_full_batch(fx: &Fixture) -> usize {
    let mut store = seeded_store(fx);
    const PROBE: usize = 1_000_000;
    store.flash().writes_left.set(PROBE);
    store.apply_batch(&fx.ops()).expect("uncut batch applies");
    let left = store.flash().writes_left.get();
    PROBE - left
}

/// Run a batch against a flash that dies after `budget` writes, then
/// bring the power back and return the remounted store.
fn cut_power_during_batch(budget: usize, fx: &Fixture) -> FlashStorage<DyingFlash> {
    let mut store = seeded_store(fx);
    // The cut: from here the flash accepts `budget` more writes.
    store.flash().writes_left.set(budget);
    let _ = store.apply_batch(&fx.ops()); // may fail; that is the point

    let flash = store.into_flash().revive();
    FlashStorage::<DyingFlash>::mount(flash, RANGE).expect("a cut batch must not brick the store")
}

/// Every cut point across a batch leaves the store in one of the two
/// states the trait allows — never in between.
///
/// The budget sweeps from "dies before the first journal write" to
/// "survives the whole batch", so the marker write, the journal writes
/// and the apply writes each get to be the last thing that happened.
#[test]
fn every_cut_point_leaves_all_or_nothing() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    for budget in 0..=total {
        let store = cut_power_during_batch(budget, &fx);
        assert!(
            fx.applied(&store) || fx.untouched(&store),
            "budget {budget}/{total}: partial batch after recovery"
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
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    for budget in 0..=total {
        let store = cut_power_during_batch(budget, &fx);
        store
            .scan_prefix(b"", &mut |k, _| {
                assert!(
                    k.first() != Some(&0x00),
                    "budget {budget}: reserved journal key {k:?} leaked into a scan"
                );
                assert!(
                    k.starts_with(b"c:"),
                    "budget {budget}: unexpected key {k:?} visible to a reader"
                );
                true
            })
            .expect("scan");
    }
}

/// A batch that completes normally leaves nothing behind: no journal,
/// no marker, only the data.
#[test]
fn a_completed_batch_leaves_no_bookkeeping() {
    let fx = Fixture::new();
    let store = cut_power_during_batch(usize::MAX, &fx);

    let mut count = 0;
    store
        .scan_prefix(b"", &mut |k, _| {
            assert!(k.starts_with(b"c:"), "leftover key {k:?}");
            count += 1;
            true
        })
        .expect("scan");
    assert_eq!(count, 2, "added and keep survive; doomed was deleted");
    assert!(fx.applied(&store));
}

/// The smallest cut budget whose recovery lands the batch — i.e. the
/// cut fell just after the marker, leaving recovery the whole apply
/// phase to redo. The interesting starting point for recovery cuts.
fn smallest_committing_budget(fx: &Fixture, total: usize) -> usize {
    (0..=total)
        .find(|&b| fx.applied(&cut_power_during_batch(b, fx)))
        .expect("some cut point must commit")
}

/// Cuts *inside recovery* leave the store in the same all-or-nothing
/// states as cuts inside the batch. The crate documentation says a cut
/// during recovery simply replays; here that claim is exercised rather
/// than trusted. The batch is cut right after its commit point, then
/// recovery itself is cut at every budget, then power returns for good
/// — and the final mount must land the whole batch, because with the
/// marker on flash "never happened" stopped being an option.
#[test]
fn a_cut_during_recovery_still_lands_the_whole_batch() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    let committing = smallest_committing_budget(&fx, total);

    for recovery_budget in 0..=total {
        // Cut the batch just past its commit point.
        let mut store = seeded_store(&fx);
        store.flash().writes_left.set(committing);
        let _ = store.apply_batch(&fx.ops());

        // Power returns, but not for long: recovery is cut too. The
        // handle keeps the medium reachable when the mount dies on it.
        let crippled = store.into_flash();
        let handle = crippled.clone();
        handle.writes_left.set(recovery_budget);
        let flash = match FlashStorage::<DyingFlash>::mount(crippled, RANGE) {
            Ok(recovered) => recovered.into_flash(),
            Err(_) => handle, // the chip outlives the software
        };

        // Power returns for good.
        let store = FlashStorage::<DyingFlash>::mount(flash.revive(), RANGE)
            .expect("a cut recovery must not brick the store");
        assert!(
            fx.applied(&store),
            "recovery budget {recovery_budget}: the marker was on flash, \
             the batch must land in full"
        );
    }
}

/// A marker left by an interrupted replay is finished before the next
/// batch writes its own — otherwise the committed batch would be
/// stranded half applied for ever.
///
/// The review's scenario: replay fails transiently (here the flash
/// refuses writes), a second batch is submitted, then power cycles.
/// The second batch must refuse while the first is unfinished, and the
/// final mount must land the first batch whole.
#[test]
fn a_pending_marker_is_finished_before_a_new_batch_starts() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    let committing = smallest_committing_budget(&fx, total);

    // First batch: cut just past its commit point.
    let mut store = seeded_store(&fx);
    store.flash().writes_left.set(committing);
    let _ = store.apply_batch(&fx.ops());

    // Second batch on the same store while the flash still refuses
    // writes: recovery of the first batch cannot finish, so the second
    // batch must refuse rather than overwrite the pending marker.
    let second_key = chain_key(b'b', "0001");
    let second = [BatchOp::Put {
        key: &second_key,
        value: b"second",
    }];
    assert!(
        store.apply_batch(&second).is_err(),
        "a batch must not start while its predecessor cannot be finished"
    );

    // The transient failure clears; the same store retries the second
    // batch. The pending first batch must be finished before the new
    // marker is written — a backend that skips that step lets the new
    // marker bury the old one, and the committed first batch is
    // stranded half applied for ever. Nothing may be lost.
    store.flash().writes_left.set(usize::MAX);
    store
        .apply_batch(&second)
        .expect("with the flash healthy, the retried batch applies");
    assert!(
        fx.applied(&store),
        "finishing the pending batch comes first: batch one lands in full"
    );
    assert_eq!(
        store.get(&second_key).unwrap().as_deref(),
        Some(b"second".as_slice()),
        "and the retried batch lands too"
    );

    // Power cycles: the state survives a remount.
    let store = FlashStorage::<DyingFlash>::mount(store.into_flash().revive(), RANGE)
        .expect("mount after recovery");
    assert!(fx.applied(&store), "batch one is still whole after remount");
    assert_eq!(
        store.get(&second_key).unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}
/// Journal debris from a failed batch is invisible WITHOUT a remount.
///
/// Between a failed `apply_batch` and the next mount, abandoned
/// journal entries are still physically in the log — the mount-time
/// discard has not run yet. The scan-side namespace filter is the
/// only thing standing between them and a reader during that window,
/// which makes it load-bearing, not cosmetic: every other journal
/// test in this file remounts first, and a remount cleans the log
/// before the scan ever looks.
#[test]
fn journal_debris_is_invisible_before_any_remount() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    for budget in 0..=total {
        let mut store = seeded_store(&fx);
        store.flash().writes_left.set(budget);
        let _ = store.apply_batch(&fx.ops()); // may fail; that is the point
        store.flash().writes_left.set(usize::MAX);

        // No remount. Whatever state the failure left, no reserved
        // key reaches a reader.
        store
            .scan_prefix(b"", &mut |k, _| {
                assert!(
                    k.first() != Some(&0x00),
                    "budget {budget}: journal debris {k:?} visible without a remount"
                );
                assert!(
                    k.starts_with(b"c:"),
                    "budget {budget}: unexpected key {k:?} visible without a remount"
                );
                true
            })
            .expect("scan after a failed batch");
    }
}
