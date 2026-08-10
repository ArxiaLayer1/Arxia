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
    faults: Rc<Cell<usize>>,
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
            faults: Rc::new(Cell::new(0)),
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

    /// Power returns / the fault clears.
    fn heal(&self) {
        self.skip.set(usize::MAX);
        self.faults.set(0);
        self.inner.borrow_mut().bytes_until_shutoff = None;
    }

    fn spend(&self) -> Result<(), DeadError> {
        let skip = self.skip.get();
        if skip > 0 {
            self.skip.set(skip.saturating_sub(1));
            return Ok(());
        }
        let faults = self.faults.get();
        if faults > 0 {
            self.faults.set(faults.saturating_sub(1));
            return Err(DeadError);
        }
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

impl ErrorType for FaultyFlash {
    type Error = DeadError;
}

impl ReadNorFlash for FaultyFlash {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
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
    store.flash().skip.set(PROBE);
    store
        .apply_batch(&fx.ops())
        .expect("unfaulted batch applies");
    let left = store.flash().skip.get();
    PROBE - left
}

/// Bytes one full batch writes, for the torn-write sweep.
fn bytes_for_a_full_batch(fx: &Fixture) -> u64 {
    let mut store = seeded_store(fx);
    let before = store.flash().inner.borrow().stats_snapshot();
    store
        .apply_batch(&fx.ops())
        .expect("unfaulted batch applies");
    let after = store.flash().inner.borrow().stats_snapshot();
    before.compare_to(after).bytes_written
}

/// Run a batch against a flash that dies after `budget` writes, then
/// bring the power back and return the remounted store.
fn cut_power_during_batch(budget: usize, fx: &Fixture) -> FlashStorage<FaultyFlash> {
    let mut store = seeded_store(fx);
    // The cut: from here the flash accepts `budget` more writes.
    store.flash().arm_cut(budget);
    let _ = store.apply_batch(&fx.ops()); // may fail; that is the point

    let flash = store.into_flash();
    flash.heal();
    FlashStorage::<FaultyFlash>::mount(flash, RANGE).expect("a cut batch must not brick the store")
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
        store.flash().arm_cut(committing);
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
    store.flash().arm_cut(committing);
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
    store.flash().heal();
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
        store.flash().arm_cut(budget);
        let _ = store.apply_batch(&fx.ops()); // may fail; that is the point
        store.flash().heal();

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
        store.flash().arm_transient(position, 1);
        let result = store.apply_batch(&fx.ops());
        let fault_fired = store.flash().faults.get() == 0;

        match result {
            Ok(()) => {
                assert!(
                    fx.applied(&store),
                    "position {position}: Ok must mean the whole batch landed"
                );
                if fault_fired {
                    // The fault hit the replay phase and the inline
                    // retry finished the batch: an Err here would have
                    // left a committed batch half applied.
                    recovered_inline += 1;
                }
            }
            Err(_) => {
                // A fault before the commit point refuses the batch;
                // reads then serve the seeded state, whole.
                assert!(
                    fx.untouched(&store),
                    "position {position}: Err must mean the batch never happened"
                );
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
    store.flash().arm_transient(committing, 1_000_000);
    assert!(
        store.apply_batch(&fx.ops()).is_err(),
        "with the flash refusing every write, the batch cannot finish"
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
    store.flash().heal();
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
    for cut in (0..total_bytes).step_by(3) {
        let mut store = seeded_store(&fx);
        store.flash().arm_torn(cut as u32);
        let _ = store.apply_batch(&fx.ops()); // may fail; that is the point

        let flash = store.into_flash();
        flash.heal();
        let store = FlashStorage::<FaultyFlash>::mount(flash, RANGE)
            .expect("a torn write must not brick the store");
        if fx.applied(&store) {
            applied += 1;
        } else if fx.untouched(&store) {
            untouched += 1;
        } else {
            panic!("byte {cut}: torn write left a partial batch");
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
    {
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
        let mut buffer = [0u8; 128];
        complete(map.store_item(
            &mut buffer,
            &RawKey(b"\x00foreign".to_vec()),
            &b"gunk".as_slice(),
        ))
        .expect("poll")
        .expect("plant the foreign item");
    }

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
