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
//! Three fault families are walked, because the seal makes promises
//! about all of them: power cuts (writes stop for good until power
//! returns), *transient* faults (a write fails, the flash answers
//! again afterwards - the family the third review found untested, and
//! where all three of its blocking findings lived), and *torn* writes
//! (power dies mid-write, leaving partial bytes the CRC must catch).
//! Cuts are walked during the batch itself and during the *recovery*
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

use arxia_core::{ArxiaError, FlashFault, JournalPart, StorageFault};
use arxia_storage::conformance::{realistic_key, realistic_value};
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

/// A flash that faults on command: a power cut, a transient fault,
/// or a torn write, depending on how it is armed.
///
/// One knob models the first two: after `skip` successful writes, the
/// next `faults` write attempts fail *cleanly* (nothing reaches the
/// medium). `faults = usize::MAX` is a power cut - writes stop for
/// good until [`Self::heal`] - and a finite `faults` is a transient
/// fault: the flash answers again once they are consumed, no heal
/// call needed, exactly as a marginal supply rail behaves. Torn
/// writes use the mock's own byte-level shutoff instead, armed with
/// [`Self::arm_torn`]: the write dies mid-item, partial bytes land,
/// and the next write succeeds.
///
/// Contents and knobs live behind `Rc`, so a clone is another handle
/// on the *same* flash. That is what lets a test survive a failed
/// mount: `mount` consumes the flash and does not give it back on
/// error, but a handle taken beforehand still reaches the medium —
/// exactly as the physical chip outlives the software that died on it.
#[derive(Clone)]
struct FaultyFlash {
    inner: Rc<RefCell<Mock>>,
    skip: Rc<Cell<usize>>,
    lies: Rc<Cell<usize>>,
    faults: Rc<Cell<usize>>,
    read_faults: Rc<Cell<usize>>,
    read_faults_after_lie: Rc<Cell<usize>>,
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

impl FaultyFlash {
    fn healthy() -> Self {
        Self {
            inner: Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true))),
            skip: Rc::new(Cell::new(usize::MAX)),
            lies: Rc::new(Cell::new(0)),
            faults: Rc::new(Cell::new(0)),
            read_faults: Rc::new(Cell::new(0)),
            read_faults_after_lie: Rc::new(Cell::new(0)),
        }
    }

    /// Power cut: after `after` more writes, everything fails until
    /// [`Self::heal`].
    fn arm_cut(&self, after: usize) {
        self.skip.set(after);
        self.faults.set(usize::MAX);
    }

    /// Transient fault: after `after` more writes, the next `count`
    /// attempts fail, then the flash answers again on its own.
    fn arm_transient(&self, after: usize, count: usize) {
        self.skip.set(after);
        self.faults.set(count);
    }

    /// Torn write: the write in progress dies after `bytes` more
    /// bytes, leaving what landed on the medium.
    fn arm_torn(&self, bytes: u32) {
        self.inner.borrow_mut().bytes_until_shutoff = Some(bytes);
    }

    /// A lying driver: after `after` more writes, the next `count`
    /// writes SUCCEED physically but report failure - the real-NOR
    /// behaviour of a status-poll timeout, a bus error during the
    /// acknowledgement, or supply droop while reading back status.
    /// The fifth review's third blocker lived exactly here, and no
    /// clean-failure knob can reach it: the fault the software must
    /// survive is a medium that disagrees with its own driver.
    fn arm_lying(&self, after: usize, count: usize) {
        self.skip.set(after);
        self.lies.set(count);
    }

    /// The sixth review's window: the moment the driver lies, READS
    /// start failing too - the bus fault that corrupted the write
    /// acknowledgement is still corrupting traffic when the read-back
    /// arrives. The next `count` reads after the first lie fail.
    fn arm_dead_reads_after_lie(&self, count: usize) {
        self.read_faults_after_lie.set(count);
    }

    /// Power returns / the fault clears.
    fn heal(&self) {
        self.skip.set(usize::MAX);
        self.lies.set(0);
        self.faults.set(0);
        self.read_faults.set(0);
        self.read_faults_after_lie.set(0);
        self.inner.borrow_mut().bytes_until_shutoff = None;
    }

    fn spend(&self) -> Spend {
        let skip = self.skip.get();
        if skip > 0 {
            self.skip.set(skip.saturating_sub(1));
            return Spend::Pass;
        }
        let lies = self.lies.get();
        if lies > 0 {
            self.lies.set(lies.saturating_sub(1));
            return Spend::Lie;
        }
        let faults = self.faults.get();
        if faults > 0 {
            self.faults.set(faults.saturating_sub(1));
            return Spend::Fail;
        }
        Spend::Pass
    }
}

/// What the fault knobs decided for one write attempt.
enum Spend {
    /// The write proceeds and reports honestly.
    Pass,
    /// The write does not touch the medium and reports failure.
    Fail,
    /// The write reaches the medium AND reports failure.
    Lie,
}

#[derive(Debug)]
struct DeadError;

impl NorFlashError for DeadError {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}

impl ErrorType for FaultyFlash {
    type Error = DeadError;
}

impl ReadNorFlash for FaultyFlash {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let read_faults = self.read_faults.get();
        if read_faults > 0 {
            self.read_faults.set(read_faults - 1);
            return Err(DeadError);
        }
        let mut inner = self.inner.borrow_mut();
        complete(inner.read(offset, bytes))?.map_err(|_| DeadError)
    }

    fn capacity(&self) -> usize {
        self.inner.borrow().capacity()
    }
}

impl NorFlash for FaultyFlash {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        match self.spend() {
            Spend::Fail => return Err(DeadError),
            Spend::Pass => {}
            Spend::Lie => {
                let mut inner = self.inner.borrow_mut();
                let _ = complete(inner.erase(from, to));
                return Err(DeadError);
            }
        }
        let mut inner = self.inner.borrow_mut();
        complete(inner.erase(from, to))?.map_err(|_| DeadError)
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        match self.spend() {
            Spend::Fail => return Err(DeadError),
            Spend::Pass => {}
            Spend::Lie => {
                let pending_dead_reads = self.read_faults_after_lie.take();
                if pending_dead_reads > 0 {
                    self.read_faults.set(pending_dead_reads);
                }
                let mut inner = self.inner.borrow_mut();
                let _ = complete(inner.write(offset, bytes));
                return Err(DeadError);
            }
        }
        let mut inner = self.inner.borrow_mut();
        complete(inner.write(offset, bytes))?.map_err(|_| DeadError)
    }
}

impl MultiwriteNorFlash for FaultyFlash {}

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
            added: realistic_key("0003"),
            doomed: realistic_key("0001"),
            keep: realistic_key("0002"),
            original: realistic_value(0x10),
            new_v: realistic_value(0x20),
            rewritten: realistic_value(0x30),
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
    fn applied(&self, s: &FlashStorage<FaultyFlash>) -> bool {
        s.get(&self.added).unwrap().as_deref() == Some(self.new_v.as_slice())
            && s.get(&self.doomed).unwrap().is_none()
            && s.get(&self.keep).unwrap().as_deref() == Some(self.rewritten.as_slice())
    }

    /// True iff the store looks exactly as seeded.
    fn untouched(&self, s: &FlashStorage<FaultyFlash>) -> bool {
        s.get(&self.added).unwrap().is_none()
            && s.get(&self.doomed).unwrap().as_deref() == Some(self.original.as_slice())
            && s.get(&self.keep).unwrap().as_deref() == Some(self.original.as_slice())
    }
}

fn seeded_store(fx: &Fixture) -> FlashStorage<FaultyFlash> {
    let mut store =
        FlashStorage::<FaultyFlash>::mount(FaultyFlash::healthy(), RANGE).expect("first mount");
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
    store.flash_mut().skip.set(PROBE);
    store
        .apply_batch(&fx.ops())
        .expect("unfaulted batch applies");
    let left = store.flash_mut().skip.get();
    PROBE - left
}

/// Bytes one full batch writes, for the torn-write sweep.
fn bytes_for_a_full_batch(fx: &Fixture) -> u64 {
    let mut store = seeded_store(fx);
    let before = store.flash_mut().inner.borrow().stats_snapshot();
    store
        .apply_batch(&fx.ops())
        .expect("unfaulted batch applies");
    let after = store.flash_mut().inner.borrow().stats_snapshot();
    before.compare_to(after).bytes_written
}

/// Run a batch against a flash that dies after `budget` writes, then
/// bring the power back and return apply_batch's verdict together
/// with the remounted store - so every sweep can hold the CLASS of
/// the error to the OUTCOME it predicts, not just the outcome.
fn cut_power_during_batch(
    budget: usize,
    fx: &Fixture,
) -> (Result<(), ArxiaError>, FlashStorage<FaultyFlash>) {
    let mut store = seeded_store(fx);
    // The cut: from here the flash accepts `budget` more writes.
    store.flash_mut().arm_cut(budget);
    let verdict = store.apply_batch(&fx.ops()); // may fail; that is the point

    let flash = store.into_flash();
    flash.heal();
    let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE)
        .expect("a cut batch must not brick the store");
    (verdict, store)
}

/// The trait's carve-out, held at every fault point: the class of the
/// value apply_batch returned must PREDICT the state after recovery.
/// Ok and BatchCommitted mean the batch landed; any other error means
/// it never happened. A regression where a generic error hides an
/// applied batch - the double-application class - fails here and
/// nowhere else: outcome-only sweeps cannot see it.
fn assert_class_predicts_outcome(
    verdict: &Result<(), ArxiaError>,
    store: &FlashStorage<FaultyFlash>,
    fx: &Fixture,
    context: &str,
) {
    match verdict {
        Ok(()) => assert!(fx.applied(store), "{context}: Ok must mean applied"),
        Err(ArxiaError::Storage {
            fault: StorageFault::BatchCommitted,
        }) => assert!(
            fx.applied(store),
            "{context}: BatchCommitted must converge to applied"
        ),
        Err(_) => assert!(
            fx.untouched(store),
            "{context}: a non-BatchCommitted error must mean a real rollback"
        ),
    }
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
        let (verdict, store) = cut_power_during_batch(budget, &fx);
        assert_class_predicts_outcome(&verdict, &store, &fx, &format!("budget {budget}/{total}"));
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
        let (_, store) = cut_power_during_batch(budget, &fx);
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
    let (verdict, store) = cut_power_during_batch(usize::MAX, &fx);
    assert!(verdict.is_ok(), "an unfaulted batch reports its success");

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
        .find(|&b| fx.applied(&cut_power_during_batch(b, fx).1))
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
        store.flash_mut().arm_cut(committing);
        let _ = store.apply_batch(&fx.ops());

        // Power returns, but not for long: recovery is cut too. The
        // handle keeps the medium reachable when the mount dies on it.
        let crippled = store.into_flash();
        let handle = crippled.clone();
        handle.arm_cut(recovery_budget);
        let flash = match FlashStorage::<FaultyFlash>::mount(crippled, RANGE) {
            Ok(recovered) => recovered.into_flash(),
            Err(_) => handle, // the chip outlives the software
        };

        // Power returns for good.
        flash.heal();
        let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE)
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
    store.flash_mut().arm_cut(committing);
    let _ = store.apply_batch(&fx.ops());

    // Second batch on the same store while the flash still refuses
    // writes: recovery of the first batch cannot finish, so the second
    // batch must refuse rather than overwrite the pending marker.
    let second_key = realistic_key("9999");
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
    store.flash_mut().heal();
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
    let flash = store.into_flash();
    flash.heal();
    let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("mount after recovery");
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
        store.flash_mut().arm_cut(budget);
        let _ = store.apply_batch(&fx.ops()); // may fail; that is the point
        store.flash_mut().heal();

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
// ------------------------------------------------- transient faults

/// A single transient write fault, at every write position in a
/// batch, leaves all-or-nothing - and the batch survives faults that
/// land after its commit point, because the inline recovery retry
/// finishes what the fault interrupted.
///
/// This is the family the third review found untested: the sweeps
/// above cut power (writes stop for good), which can never exercise
/// the path where a write fails and the NEXT write succeeds. All
/// three blocking findings of that review lived in exactly that path.
#[test]
fn a_transient_fault_at_every_position_leaves_all_or_nothing() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);

    let mut recovered_inline = 0usize;
    let mut refused_before_commit = 0usize;
    for position in 0..=total {
        let mut store = seeded_store(&fx);
        store.flash_mut().arm_transient(position, 1);
        let result = store.apply_batch(&fx.ops());
        let fault_fired = store.flash_mut().faults.get() == 0;

        assert_class_predicts_outcome(&result, &store, &fx, &format!("position {position}"));
        match &result {
            Ok(()) => {
                if fault_fired {
                    // The fault hit the replay phase and the inline
                    // retry finished the batch: an Err here would have
                    // left a committed batch half applied.
                    recovered_inline += 1;
                }
            }
            Err(_) => {
                refused_before_commit += 1;
            }
        }
    }
    assert!(
        recovered_inline > 0,
        "the sweep must exercise the inline-recovery path"
    );
    assert!(
        refused_before_commit > 0,
        "the sweep must exercise the refusal path"
    );
}

/// While a committed batch cannot be finished, reads refuse rather
/// than serve a mixture; the first access after the flash heals
/// converges the store.
///
/// The dirty gate under test is what upholds the contract between a
/// failed replay and its eventual completion: without it, `get` on
/// one key of the batch would show the new value while another still
/// held the old one.
#[test]
fn reads_gate_on_an_unfinished_batch_and_converge() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    let committing = smallest_committing_budget(&fx, total);

    // The marker lands, then every further write faults - including
    // the ones the inline recovery retry issues.
    let mut store = seeded_store(&fx);
    store.flash_mut().arm_transient(committing, 1_000_000);
    // The error is the typed BatchCommitted signal, not a generic
    // fault: the caller must know the batch is past its commit point
    // and WILL apply, because reading this as a rollback and
    // resubmitting would double-apply. The trait documents this as
    // its one carve-out from "on Err, nothing changed".
    assert!(
        matches!(
            store.apply_batch(&fx.ops()),
            Err(ArxiaError::Storage {
                fault: StorageFault::BatchCommitted
            })
        ),
        "a committed batch that cannot finish must say so, typed"
    );

    // The batch is committed but unfinished. No read may show the
    // in-between state: they fail until recovery can run.
    assert!(
        store.get(&fx.added).is_err(),
        "a read on an unfinished batch must refuse, not serve a mixture"
    );
    assert!(store.contains(&fx.keep).is_err());
    assert!(
        store.scan_prefix(b"c:", &mut |_, _| true).is_err(),
        "a scan must refuse too"
    );

    // The fault clears; the first access finishes the batch.
    store.flash_mut().heal();
    assert_eq!(
        store.get(&fx.added).unwrap().as_deref(),
        Some(fx.new_v.as_slice()),
        "the first read after healing converges the store"
    );
    assert!(
        fx.applied(&store),
        "the committed batch landed in full, nothing in between was ever served"
    );
}

// ---------------------------------------------------- capacity limits

/// A batch that cannot fit fails BEFORE its commit point, and a store
/// with barely enough room applies a batch that a naive replay order
/// would strand.
///
/// The capacity guarantee under test is structural: the journal is
/// the reservation. An applied item is strictly smaller than its
/// journal entry and the entry is erased as its item lands, so a
/// replay never holds more live data than the journaling phase
/// already fit (plus one item in flight). An earlier replay order -
/// apply everything, then erase - needed journal and application
/// live simultaneously, and on this store it would commit a batch it
/// can never finish: marker on flash, no space to apply, every mount
/// failing. That is the bricked store the review described.
#[test]
fn a_near_full_store_refuses_before_commit_and_lands_when_it_fits() {
    let filler_value = [0x5Au8; 200];

    // Fill until genuinely full: live data the store cannot shed.
    let mut store =
        FlashStorage::<FaultyFlash>::mount(FaultyFlash::healthy(), RANGE).expect("mount");
    let mut fillers: Vec<Vec<u8>> = Vec::new();
    loop {
        let key = format!("f:{:04}", fillers.len()).into_bytes();
        match store.put(&key, &filler_value) {
            Ok(()) => fillers.push(key),
            Err(_) => break, // FullStorage: the store is at capacity
        }
    }
    assert!(fillers.len() > 100, "the fill must have actually filled");

    // Part 1: a batch on a full store is refused before its commit
    // point - the store stays mountable and nothing is disturbed.
    let fx = Fixture::new();
    assert!(
        store.apply_batch(&fx.ops()).is_err(),
        "no room to journal: the batch must refuse before committing"
    );
    assert!(
        store.get(&fx.added).unwrap().is_none(),
        "nothing of the refused batch is visible"
    );
    let flash = store.into_flash();
    flash.heal();
    let mut store =
        FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("a refused batch must not brick");

    // Part 2: free enough room that the journal fits but the journal
    // PLUS a fully-applied copy would not, then land a batch big
    // enough that the two orders differ by far more than any page
    // rounding. A ten-block batch journals to roughly 2.8 KB and
    // applies to roughly 2.7 KB more; twenty freed fillers make
    // roughly 4.3 KB of room. Erase-as-you-go peaks near the journal
    // size and lands; the old apply-all-then-erase order needs both
    // at once - about 5.5 KB - and would commit a batch it can never
    // finish: marker on flash, no room to apply, every mount failing.
    for key in fillers.iter().take(20) {
        assert!(store.delete(key).expect("delete filler"));
    }
    let big_keys: Vec<Vec<u8>> = (0..10)
        .map(|i| realistic_key(&format!("b{i:03}")))
        .collect();
    let big_value = realistic_value(0x77);
    let big_ops: Vec<BatchOp<'_>> = big_keys
        .iter()
        .map(|k| BatchOp::Put {
            key: k,
            value: &big_value,
        })
        .collect();
    store
        .apply_batch(&big_ops)
        .expect("with room for the journal, the batch lands");
    for k in &big_keys {
        assert_eq!(
            store.get(k).unwrap().as_deref(),
            Some(big_value.as_slice()),
            "every block of the batch landed"
        );
    }

    // And the store survives a power cycle with everything intact.
    let flash = store.into_flash();
    flash.heal();
    let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("still mountable");
    for k in &big_keys {
        assert_eq!(store.get(k).unwrap().as_deref(), Some(big_value.as_slice()));
    }
    assert_eq!(
        store.get(&fillers[25]).unwrap().as_deref(),
        Some(filler_value.as_slice()),
        "surviving fillers are untouched"
    );
}

// ------------------------------------------------------- torn writes

/// A write torn at every byte offset across a batch leaves
/// all-or-nothing after the next mount.
///
/// A power cut does not stop between writes; it stops mid-write,
/// leaving however many bytes reached the die. The CRC on every item
/// is what turns those partial bytes into "no item" instead of wrong
/// data - a torn marker in particular must read as NO commit. The
/// write-count sweeps above cannot reach any of this; the byte-level
/// shutoff of the mock can.
#[test]
fn a_torn_write_at_every_byte_leaves_all_or_nothing() {
    let fx = Fixture::new();
    let total_bytes = bytes_for_a_full_batch(&fx);

    let mut applied = 0u64;
    let mut untouched = 0u64;
    for cut in 0..total_bytes {
        let mut store = seeded_store(&fx);
        store.flash_mut().arm_torn(cut as u32);
        let verdict = store.apply_batch(&fx.ops()); // may fail; that is the point

        let flash = store.into_flash();
        flash.heal();
        let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE)
            .expect("a torn write must not brick the store");
        assert_class_predicts_outcome(&verdict, &store, &fx, &format!("torn at byte {cut}"));
        if fx.applied(&store) {
            applied += 1;
        } else {
            untouched += 1;
        }
    }
    assert!(applied > 0, "some tears must land after the commit point");
    assert!(untouched > 0, "some tears must land before it");
}
// ------------------------------------- foreign reserved-namespace items

/// A key type that serializes exactly like the backend's own bounded
/// key - a one-byte length prefix, then the bytes - so a test can
/// plant an item the backend's iteration will parse, without going
/// through the backend's own (guarded) write path.
#[derive(Clone, PartialEq, Eq, Debug)]
struct RawKey(Vec<u8>);

impl sequential_storage::map::Key for RawKey {
    fn serialize_into(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, sequential_storage::map::SerializationError> {
        if buffer.len() < self.0.len() + 1 {
            return Err(sequential_storage::map::SerializationError::BufferTooSmall);
        }
        buffer[0] = self.0.len() as u8;
        buffer[1..1 + self.0.len()].copy_from_slice(&self.0);
        Ok(self.0.len() + 1)
    }

    fn deserialize_from(
        buffer: &[u8],
    ) -> Result<(Self, usize), sequential_storage::map::SerializationError> {
        let len = buffer[0] as usize;
        Ok((RawKey(buffer[1..1 + len].to_vec()), len + 1))
    }

    fn get_len(buffer: &[u8]) -> Result<usize, sequential_storage::map::SerializationError> {
        Ok(buffer[0] as usize + 1)
    }
}

/// Plant raw items on a flash through the storage library directly,
/// bypassing every backend write guard - as corruption, torn-write
/// garbage or a foreign writer would.
fn plant(flash: FaultyFlash, items: &[(&[u8], &[u8])]) {
    let config = sequential_storage::map::MapConfig::try_new(RANGE).expect("config");
    type RawCache = sequential_storage::cache::Cache<
        sequential_storage::cache::Uncached,
        sequential_storage::cache::Uncached,
        sequential_storage::cache::Uncached,
        RawKey,
    >;
    let mut map: sequential_storage::map::MapStorage<RawKey, FaultyFlash, RawCache> =
        sequential_storage::map::MapStorage::new(
            flash,
            config,
            sequential_storage::cache::Cache::new_uncached(),
        );
    let mut buffer = [0u8; 512];
    for (key, value) in items {
        complete(map.store_item(&mut buffer, &RawKey(key.to_vec()), value))
            .expect("poll")
            .expect("plant item");
    }
}

/// Plant raw items on any flash, returning it - for regions the
/// shared 16-page mock cannot model.
fn plant_raw<S: MultiwriteNorFlash>(
    flash: S,
    range: core::ops::Range<u32>,
    items: &[(&[u8], &[u8])],
) -> S {
    let config = sequential_storage::map::MapConfig::try_new(range).expect("config");
    type RawCache = sequential_storage::cache::Cache<
        sequential_storage::cache::Uncached,
        sequential_storage::cache::Uncached,
        sequential_storage::cache::Uncached,
        RawKey,
    >;
    let mut map: sequential_storage::map::MapStorage<RawKey, S, RawCache> =
        sequential_storage::map::MapStorage::new(
            flash,
            config,
            sequential_storage::cache::Cache::new_uncached(),
        );
    let mut buffer = [0u8; 512];
    for (key, value) in items {
        let raw = RawKey(key.to_vec());
        let outcome = {
            let mut fut = pin!(map.store_item(&mut buffer, &raw, value));
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(r) => r,
                Poll::Pending => panic!("mock flash must complete on one poll"),
            }
        };
        outcome.expect("plant item");
    }
    map.destroy().0
}

/// A foreign item in the reserved namespace never reaches a reader,
/// even though recovery does not recognise it.
///
/// Recovery cleans what it knows: journal entries and the marker. A
/// reserved-namespace item that is neither - garbage from a torn
/// write that still passed CRC at some other shape, or bookkeeping
/// from a future format - survives every mount. The scan-side
/// namespace filter is the only thing standing between such an item
/// and the ledger, which is why the filter guards the whole prefix
/// rather than the two shapes recovery happens to know today.
#[test]
fn a_foreign_reserved_item_never_reaches_a_reader() {
    // Plant the foreign item through the storage library directly,
    // bypassing the backend's write guards - as torn-write garbage or
    // a newer format would.
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    plant(flash, &[(b"\x00foreign", b"gunk")]);

    let mut store =
        FlashStorage::<FaultyFlash>::mount(handle, RANGE).expect("mount over the foreign item");
    store
        .put(b"u:real", b"data")
        .expect("normal writes still work");

    // The foreign item is invisible through every read path.
    assert_eq!(store.get(b"\x00foreign").unwrap(), None);
    assert!(!store.contains(b"\x00foreign").unwrap());
    store
        .scan_prefix(b"", &mut |k, _| {
            assert!(
                k.first() != Some(&0x00),
                "foreign reserved item {k:?} leaked into a scan"
            );
            true
        })
        .expect("scan");
}
// ----------------------------------------- journal corruption exit path

/// A corrupt journal entry under a valid marker is a typed error and
/// a returned flash driver - never a brick loop.
///
/// The fourth review's blocking finding: a malformed MARKER had an
/// exit path (discard), but a malformed ENTRY had none - replay
/// failed, mount failed, identically, for ever. Same corruption
/// class, asymmetric treatment. Now the parse failure surfaces as
/// JournalCorrupted with the entry index, mount hands the flash
/// driver back with the error, and the caller holds every option.
/// The system answer is a re-sync - the ledger is a cache of
/// consensus state - and this fixture walks it to the end: erase the
/// region, remount, resume.
#[test]
fn a_corrupt_journal_entry_is_a_typed_error_and_a_returned_driver() {
    // Plant a valid marker (count = 1) and a garbage entry at index 0
    // through the storage library directly, as corruption would.
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    // Journal entry 0: a single byte, shorter than any valid encoding
    // (tag + key length need two). Then a valid marker claiming one
    // operation.
    plant(
        flash,
        &[
            (&[0x00, 0x6A, 0x00, 0x00], &[0xFFu8]),
            (&[0x00, 0x63], &1u16.to_be_bytes()),
        ],
    );

    // Mount reports the corruption, typed to the entry, and returns
    // the driver. Deterministically: a second attempt says the same
    // thing - the caller is in a loop only if it chooses to be.
    let failure = FlashStorage::<FaultyFlash>::mount(handle.clone(), RANGE)
        .expect_err("a corrupt committed journal must not mount");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::Entry(0)
                    }
                }
            }
        ),
        "the error names the corrupt entry, got: {}",
        failure.error
    );
    let failure2 = FlashStorage::<FaultyFlash>::mount(failure.flash, RANGE)
        .expect_err("the same corruption reports the same way");

    // The re-sync path: erase the region and start over. The flash
    // came back with the error, so the caller CAN.
    let mut flash = failure2.flash;
    complete(NorFlash::erase(&mut flash, RANGE.start, RANGE.end))
        .expect("poll")
        .expect("erase the region");
    let mut store =
        FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("an erased region mounts fresh");
    store
        .put(b"u:resynced", b"block")
        .expect("and serves again");
    assert_eq!(
        store.get(b"u:resynced").unwrap().as_deref(),
        Some(b"block".as_slice())
    );
}

// ------------------------------------- read availability over debris

/// Markerless journal debris never costs read availability.
///
/// A batch that failed BEFORE its commit point left nothing a reader
/// can see - the debris is invisible by namespace - so gating reads
/// on it would trade availability for no consistency at all: with
/// the flash still refusing writes, the cleanup gate would turn
/// every read into an error on a store whose visible state is
/// perfectly sound. Reads pass over debris; only the next batch,
/// whose journal keys would collide with it, cleans first.
#[test]
fn reads_stay_available_over_debris_while_the_flash_is_down() {
    let fx = Fixture::new();
    let mut store = seeded_store(&fx);

    // Cut two writes into journaling: pre-commit failure, debris on
    // flash, and the flash is still refusing writes.
    store.flash_mut().arm_cut(2);
    assert!(
        store.apply_batch(&fx.ops()).is_err(),
        "the cut batch refuses before committing"
    );

    // No heal. Reads serve the seeded state, whole, right now.
    assert_eq!(
        store.get(&fx.keep).unwrap().as_deref(),
        Some(fx.original.as_slice()),
        "reads must not pay an availability price for invisible debris"
    );
    assert!(store.contains(&fx.doomed).unwrap());
    assert!(store.get(&fx.added).unwrap().is_none());
    store
        .scan_prefix(b"c:", &mut |k, _| {
            assert!(k.first() != Some(&0x00));
            true
        })
        .expect("scans stay available too");

    // Power returns; the next batch cleans the debris and lands.
    store.flash_mut().heal();
    store
        .apply_batch(&fx.ops())
        .expect("the next batch cleans the debris and applies");
    assert!(fx.applied(&store));
}

// --------------------------------------------- oversized foreign value

/// A foreign value longer than the backend's cap faults the scan,
/// typed - it is never silently truncated.
///
/// Only a foreign write can produce such an item (our own writes are
/// capped), and before this guard the scan clipped it to
/// MAX_VALUE_LEN while get() served all of it: the two read paths
/// the conformance suite promises agree diverged, silently. Now the
/// scan surfaces the out-of-spec store with CapacityExceeded, and
/// the point lookup - which needs no window - serves the value whole.
#[test]
fn an_oversized_foreign_value_faults_the_scan_instead_of_truncating() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    let oversized = vec![0xEEu8; 300];
    plant(flash, &[(b"u:big", &oversized)]);

    let store = FlashStorage::<FaultyFlash>::mount(handle, RANGE).expect("mount");

    // The point lookup needs no window and serves the value whole.
    assert_eq!(
        store.get(b"u:big").unwrap().map(|v| v.len()),
        Some(300),
        "get serves the whole value"
    );

    // The scan cannot hold it whole, so it faults, typed - never a
    // silent 256-byte prefix.
    let result = store.scan_prefix(b"u:", &mut |_, _| true);
    assert!(
        matches!(
            result,
            Err(ArxiaError::Storage {
                fault: StorageFault::CapacityExceeded { got: 300, .. }
            })
        ),
        "the scan surfaces the out-of-spec item, got: {result:?}"
    );
}

// ------------------------------------------------- final-pass economy

/// The final partial pass ends the scan without a termination read
/// of the whole log.
///
/// A pass that collected fewer keys than the window holds has proved
/// there is nothing above it; reading the log once more to find an
/// empty window would double the cost of every scan on its dominant
/// path, and the endurance model would be wrong by a whole pass. The
/// probe: a scan matching nothing costs exactly one full-log read,
/// and a five-key scan (one partial pass) must cost about the same -
/// not twice it.
#[test]
fn a_final_partial_pass_ends_the_scan_without_a_termination_read() {
    let mut store =
        FlashStorage::<FaultyFlash>::mount(FaultyFlash::healthy(), RANGE).expect("mount");
    for i in 0..5u8 {
        store.put(&realistic_key(&format!("00{i}")), &[i]).unwrap();
    }

    let reads_of = |s: &FlashStorage<FaultyFlash>, prefix: &[u8]| {
        let before = s.flash_mut().inner.borrow().stats_snapshot();
        s.scan_prefix(prefix, &mut |_, _| true).expect("scan");
        let after = s.flash_mut().inner.borrow().stats_snapshot();
        before.compare_to(after).reads
    };

    // One full-log iteration, no matches, empty window: the floor.
    let one_iteration = reads_of(&store, b"zzz");
    // Five keys fit one partial window: one iteration, then stop.
    let partial_pass = reads_of(&store, b"c:");

    assert!(
        partial_pass < one_iteration + one_iteration / 2,
        "a final partial pass must not re-read the log to terminate:          {partial_pass} reads vs {one_iteration} for one iteration"
    );
}
// ---------------------------- untrusted journal entries (fifth review)

/// A corrupt entry that parses as a DELETE of a journal key is
/// corruption, refused - never applied.
///
/// The fifth review's first blocker: OP_PUT re-entered the write path
/// and its guards, but OP_DELETE went straight to the engine. A
/// CRC-valid corrupt entry parsing as "delete journal entry 1" would
/// have erased the seal's own bookkeeping mid-replay - the replay
/// then finds entry 1 absent, treats it as already applied, and
/// reports Ok with an operation silently dropped: the strict subset
/// the seal exists to forbid. Aimed at the marker instead, a cut
/// before the end would strand a committed batch half applied for
/// ever.
#[test]
fn a_forged_delete_of_a_journal_key_is_corruption_not_applied() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    // Entry 0: OP_DELETE (0x01), key_len 4, key = journal entry 1's
    // own key. Entry 1: a valid-looking PUT. Marker: count = 2.
    let forged = [0x01u8, 4, 0x00, 0x6A, 0x00, 0x01];
    let mut valid_put = vec![0x00u8, 5];
    valid_put[0] = 0x00; // OP_PUT tag
    valid_put.extend_from_slice(b"u:ok!");
    valid_put.extend_from_slice(b"value");
    plant(
        flash,
        &[
            (&[0x00, 0x6A, 0x00, 0x00], &forged),
            (&[0x00, 0x6A, 0x00, 0x01], &valid_put),
            (&[0x00, 0x63], &2u16.to_be_bytes()),
        ],
    );

    let failure = FlashStorage::<FaultyFlash>::mount(handle, RANGE)
        .expect_err("a forged reserved-key delete must refuse, not apply");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::Entry(0)
                    }
                }
            }
        ),
        "typed to the corrupt entry, got: {}",
        failure.error
    );
}

/// A corrupt entry whose clobbered key length yields an oversized
/// value is corruption - never CapacityExceeded.
///
/// The class matters twice over. The documented routing (transient =
/// retry, corrupted = re-sync) classifies a user error in neither
/// branch, so every mount fails identically for ever; and the
/// inline-retry path in apply_batch matches on JournalCorrupted, so a
/// user-classed error there becomes BatchCommitted - "will apply on
/// the next access" - for a batch that can never apply.
#[test]
fn a_clobbered_key_length_yielding_an_oversized_value_is_corruption() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    // A structurally parsable PUT: tag, key_len = 5, then 309 more
    // bytes - so the "value" is 304 bytes, over MAX_VALUE_LEN. This
    // is exactly what a key_len byte clobbered LOW does to a
    // legitimate large entry.
    let mut forged = vec![0x00u8, 5];
    forged.extend_from_slice(b"u:big");
    forged.extend_from_slice(&[0xBBu8; 304]);
    plant(
        flash,
        &[
            (&[0x00, 0x6A, 0x00, 0x00], &forged),
            (&[0x00, 0x63], &1u16.to_be_bytes()),
        ],
    );

    let failure = FlashStorage::<FaultyFlash>::mount(handle, RANGE)
        .expect_err("an oversized journalled value must refuse as corruption");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::Entry(0)
                    }
                }
            }
        ),
        "corruption class, never CapacityExceeded, got: {}",
        failure.error
    );
}

/// A corrupt entry whose clobbered key length yields a reserved key
/// is corruption - never ReservedKey.
#[test]
fn a_clobbered_key_length_yielding_a_reserved_key_is_corruption() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    // Tag, key_len = 3, then a key that begins with 0x00 - the other
    // shape a clobbered key_len produces (probed in the review).
    let mut forged = vec![0x00u8, 3];
    forged.extend_from_slice(&[0x00, 0x41, 0x42]);
    forged.extend_from_slice(b"payload");
    plant(
        flash,
        &[
            (&[0x00, 0x6A, 0x00, 0x00], &forged),
            (&[0x00, 0x63], &1u16.to_be_bytes()),
        ],
    );

    let failure = FlashStorage::<FaultyFlash>::mount(handle, RANGE)
        .expect_err("a reserved journalled key must refuse as corruption");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::Entry(0)
                    }
                }
            }
        ),
        "corruption class, never ReservedKey, got: {}",
        failure.error
    );
}

/// A marker count beyond the region's physical capacity is corruption
/// refused in one read - never sixty-five thousand log searches.
///
/// 0xFFFF is the erased-flash pattern: precisely the most likely
/// garbage. Un-bounded, it drove one full-log search per claimed
/// entry at every mount - a multi-hour boot indistinguishable from a
/// hang. No genuine batch can hold more entries than the region
/// could physically store.
#[test]
fn an_impossible_marker_count_is_corruption_not_a_boot_long_scan() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    plant(flash, &[(&[0x00, 0x63], &[0xFFu8, 0xFF])]);

    let failure = FlashStorage::<FaultyFlash>::mount(handle, RANGE)
        .expect_err("an impossible count must refuse as corruption");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::MarkerCount(0xFFFF)
                    }
                }
            }
        ),
        "typed to the impossible count, got: {}",
        failure.error
    );
}
// ---------------------------------------- the driver that lies (review 5)

/// A marker write that lands physically while the driver reports
/// failure is a COMMIT, and the caller is told so - never a rollback
/// it might act on.
///
/// The double-application scenario this forbids: told "nothing
/// changed", the caller submits an alternative batch for the same
/// logical transition; that batch's pre-batch recovery finds the
/// lied-about marker valid, replays the first batch, then applies the
/// second - both land, and the ledger carries writes the caller was
/// told were rolled back. The read-back on the commit write's error
/// path is what stands between the wire's claim and the medium's
/// truth.
#[test]
fn a_lying_marker_write_is_a_commit_not_a_rollback() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    let committing = smallest_committing_budget(&fx, total);

    // Case 1: the driver lies once, on the marker write, and the
    // flash is otherwise healthy. The read-back sees the marker, the
    // inline recovery finishes the batch, and the caller hears the
    // success it actually got.
    let mut store = seeded_store(&fx);
    store.flash_mut().arm_lying(committing - 1, 1);
    store
        .apply_batch(&fx.ops())
        .expect("a lied-about commit on a healthy flash finishes inline");
    assert!(fx.applied(&store), "and the batch landed in full");

    // Case 2: the driver lies on the marker write and then fails
    // honestly. The commit happened; nothing can finish it yet; the
    // caller must hear BatchCommitted - the one signal that says
    // "do not resubmit".
    let mut store = seeded_store(&fx);
    store.flash_mut().arm_lying(committing - 1, 1);
    store.flash_mut().faults.set(1_000_000);
    let err = store
        .apply_batch(&fx.ops())
        .expect_err("nothing can finish the batch while the flash refuses writes");
    assert!(
        matches!(
            err,
            ArxiaError::Storage {
                fault: StorageFault::BatchCommitted
            }
        ),
        "a lied-about commit must say BatchCommitted, got: {err}"
    );
    // And it converges once the flash heals, exactly as the signal
    // promised.
    store.flash_mut().heal();
    assert_eq!(
        store.get(&fx.added).unwrap().as_deref(),
        Some(fx.new_v.as_slice())
    );
    assert!(fx.applied(&store));
}

/// A lying JOURNAL write is honestly a rollback: no marker exists, the
/// phantom entry is invisible debris, and an alternative batch applies
/// alone - the control case proving the read-back distinguishes the
/// commit write from every other.
#[test]
fn a_lying_journal_write_is_still_a_rollback() {
    let fx = Fixture::new();

    // Lie on the second journal-entry write: it lands physically, the
    // driver reports failure, no marker is ever written.
    let mut store = seeded_store(&fx);
    store.flash_mut().arm_lying(2, 1);
    let err = store
        .apply_batch(&fx.ops())
        .expect_err("a failed journal write refuses the batch");
    assert!(
        !matches!(
            err,
            ArxiaError::Storage {
                fault: StorageFault::BatchCommitted
            }
        ),
        "no marker means no commit: the error must NOT claim one"
    );
    assert!(fx.untouched(&store), "and the rollback is real");

    // The caller acts on the rollback and submits an alternative
    // batch: it applies alone; the lied-about first batch never
    // resurrects.
    let alt_key = realistic_key("7777");
    let alt = [BatchOp::Put {
        key: &alt_key,
        value: b"alternative",
    }];
    store
        .apply_batch(&alt)
        .expect("the alternative batch applies");
    assert!(
        fx.untouched(&store) || store.get(&fx.added).unwrap().is_none(),
        "the first batch must not resurrect"
    );
    assert_eq!(
        store.get(&alt_key).unwrap().as_deref(),
        Some(b"alternative".as_slice())
    );

    // And a power cycle changes nothing: still no resurrection.
    let flash = store.into_flash();
    flash.heal();
    let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("remount");
    assert!(store.get(&fx.added).unwrap().is_none());
    assert_eq!(
        store.get(&alt_key).unwrap().as_deref(),
        Some(b"alternative".as_slice())
    );
}
// -------------------------------------- the unknown window (review 6)

/// When the marker write lies AND the read-back dies, the store
/// treats its own state as unknown - and unknown is never served.
///
/// The sixth review's probe: classified as debris, reads kept
/// serving the pre-batch state over a zombie marker, a put was
/// accepted on top, and the next batch's recovery replayed the old
/// batch OVER it - an acknowledged write silently overwritten. As
/// Pending, every access runs recovery before observing: while the
/// flash is dead the store faults rather than serve the pre-batch
/// lie, and the first access after healing settles the question from
/// the medium - here, the marker landed, so the batch replays before
/// anything else is observed or written.
#[test]
fn an_unreadable_readback_is_unknown_never_served() {
    let fx = Fixture::new();
    let total = writes_for_a_full_batch(&fx);
    let committing = smallest_committing_budget(&fx, total);

    // The marker write lies; from that instant every read dies too.
    let mut store = seeded_store(&fx);
    store.flash_mut().arm_lying(committing - 1, 1);
    store.flash_mut().arm_dead_reads_after_lie(1_000_000);
    let err = store
        .apply_batch(&fx.ops())
        .expect_err("with the read-back dead, the batch cannot report success");
    assert!(
        !matches!(
            err,
            ArxiaError::Storage {
                fault: StorageFault::BatchCommitted
            }
        ),
        "unknown must not claim commitment it cannot verify"
    );

    // While the flash is unreadable, no read serves the pre-batch
    // state: unknown faults, it does not lie.
    assert!(
        store.get(&fx.keep).is_err(),
        "a read in the unknown window must fault, never serve pre-batch state"
    );
    assert!(store.get(&fx.added).is_err());

    // The flash heals. The first access settles the question from
    // the medium: the marker landed, so the batch replays FIRST -
    // the re-verification sees the post-batch state, and nothing
    // written after it can be overwritten by a later replay.
    store.flash_mut().heal();
    assert_eq!(
        store.get(&fx.added).unwrap().as_deref(),
        Some(fx.new_v.as_slice()),
        "the first read after healing sees the post-batch state"
    );
    assert!(fx.applied(&store));

    // And the probe's original victim: a put after healing lands on
    // the converged state and stays - no later recovery resurrects
    // the old batch over it.
    store
        .put(&fx.keep, b"written-after")
        .expect("puts resume after convergence");
    let alt_key = realistic_key("6666");
    store
        .apply_batch(&[BatchOp::Put {
            key: &alt_key,
            value: b"next",
        }])
        .expect("the next batch runs its recovery and applies");
    assert_eq!(
        store.get(&fx.keep).unwrap().as_deref(),
        Some(b"written-after".as_slice()),
        "an acknowledged put is never overwritten by a zombie replay"
    );
}

/// The count bound holds at every region size.
///
/// The physical ceiling divides the region by the true minimum
/// journal-item footprint; an earlier bound capped at u16::MAX waved
/// 0xFFFF through on any region of 512 KiB or more - the T-Beam's
/// 4 MiB part included. On a 1 MiB region, 65535 entries would
/// physically fit, so only the sentinel rule catches the
/// erased-flash pattern there: apply_batch never writes a count of
/// u16::MAX, which keeps 0xFFFF unambiguous garbage at every size.
#[test]
fn an_impossible_count_is_corruption_at_every_region_size() {
    // Small region (64 KiB): a count far below the sentinel but
    // beyond the physical ceiling is caught by arithmetic.
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    plant(flash, &[(&[0x00, 0x63], &0x2000u16.to_be_bytes())]);
    let failure = FlashStorage::<FaultyFlash>::mount(handle, RANGE)
        .expect_err("8192 entries cannot fit a 64 KiB region");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::MarkerCount(0x2000)
                    }
                }
            }
        ),
        "physical bound, got: {}",
        failure.error
    );

    // Large region (1 MiB): the sentinel alone rejects 0xFFFF.
    type BigMock = MockFlashBase<256, 1, 4096>;
    const BIG: core::ops::Range<u32> = 0..(256 * 4096);
    let big = BigMock::new(WriteCountCheck::Twice, None, true);
    let big = plant_raw(big, BIG, &[(&[0x00, 0x63], &[0xFFu8, 0xFF])]);
    let failure = FlashStorage::<BigMock>::mount(big, BIG)
        .expect_err("the erased-flash pattern is garbage at any size");
    assert!(
        matches!(
            failure.error,
            ArxiaError::Storage {
                fault: StorageFault::Flash {
                    fault: FlashFault::JournalCorrupted {
                        part: JournalPart::MarkerCount(0xFFFF)
                    }
                }
            }
        ),
        "sentinel bound, got: {}",
        failure.error
    );
}

/// A failed batch's debris never pins put() on FullStorage: a caller
/// that only ever puts has no batch and no remount to clean it, so
/// put cleans once and retries once.
#[test]
fn a_failed_batch_never_pins_put_on_a_full_store() {
    let filler_value = [0x5Au8; 200];
    let mut store =
        FlashStorage::<FaultyFlash>::mount(FaultyFlash::healthy(), RANGE).expect("mount");

    // Fill to genuine FullStorage, then free a sliver: enough for a
    // couple of journal entries, not for a whole batch.
    let mut fillers: Vec<Vec<u8>> = Vec::new();
    loop {
        let key = format!("f:{:04}", fillers.len()).into_bytes();
        match store.put(&key, &filler_value) {
            Ok(()) => fillers.push(key),
            Err(_) => break,
        }
    }
    for key in fillers.iter().take(3) {
        assert!(store.delete(key).expect("delete filler"));
    }

    // The batch journals what fits and dies pre-commit: its debris
    // now holds the freed space.
    let fx = Fixture::new();
    assert!(
        store.apply_batch(&fx.ops()).is_err(),
        "no room for the whole journal: the batch refuses before committing"
    );

    // A put-only caller must not be pinned: put cleans the debris
    // once and retries - no batch, no remount required.
    store
        .put(b"u:after", &filler_value)
        .expect("put must reclaim debris space and land");
    assert_eq!(
        store.get(b"u:after").unwrap().as_deref(),
        Some(filler_value.as_slice())
    );
}
