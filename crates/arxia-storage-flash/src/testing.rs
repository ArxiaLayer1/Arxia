//! A fault-injecting flash for tests, shared by every crate that
//! judges the flash backend or builds on it.
//!
//! Lives in the library behind the `testing` feature for the same
//! reason the conformance checks live in `arxia-storage`: Rust test
//! targets cannot be imported across crates, and a copy of the mock in
//! each crate would drift - exactly what a shared fault model exists
//! to prevent. Enabled only by test builds; nothing on the target
//! compiles it.
//!
//! One `FaultyFlash` can be armed as a power cut (writes stop until
//! healed), a transient fault (fail N times, then answer), a torn write
//! (the mock's byte-level shutoff), a lying driver (the write lands
//! physically and reports failure), or dead reads from the moment a
//! write lies. Contents and knobs live behind `Rc`, so a clone is
//! another handle on the same medium: a failed mount does not lose it,
//! as the physical chip outlives the software that died on it.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::mock_flash::{MockFlashBase, WriteCountCheck};
use std::rc::Rc;

/// The mock part: 16 pages of 4 KiB, single-byte words.
pub type Mock = MockFlashBase<16, 1, 4096>;
/// The whole mock as one region.
pub const RANGE: core::ops::Range<u32> = 0..(16 * 4096);

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
pub struct FaultyFlash {
    /// The mock medium.
    pub inner: Rc<RefCell<Mock>>,
    /// Writes to pass before the armed fault engages.
    pub skip: Rc<Cell<usize>>,
    /// Remaining lying writes.
    pub lies: Rc<Cell<usize>>,
    /// Remaining clean-failing writes.
    pub faults: Rc<Cell<usize>>,
    /// Remaining failing reads.
    pub read_faults: Rc<Cell<usize>>,
    /// Reads to fail once the first lie fires.
    pub read_faults_after_lie: Rc<Cell<usize>>,
}

/// Complete a mock-flash future on its first poll, without awaiting.
///
/// Awaiting would hold the `RefCell` borrow across an await point,
/// which clippy rightly rejects. There is no need to await at all:
/// the single-poll property this whole backend is built on applies to
/// the mock too, so the test driver asserts it instead of working
/// around it. A pend here would mean the mock stopped completing
/// synchronously, which no test in this file could survive anyway.
pub fn complete<F: Future>(future: F) -> Result<F::Output, DeadError> {
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
    /// A flash with no fault armed.
    pub fn healthy() -> Self {
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
    pub fn arm_cut(&self, after: usize) {
        self.skip.set(after);
        self.faults.set(usize::MAX);
    }

    /// Transient fault: after `after` more writes, the next `count`
    /// attempts fail, then the flash answers again on its own.
    pub fn arm_transient(&self, after: usize, count: usize) {
        self.skip.set(after);
        self.faults.set(count);
    }

    /// Torn write: the write in progress dies after `bytes` more
    /// bytes, leaving what landed on the medium.
    pub fn arm_torn(&self, bytes: u32) {
        self.inner.borrow_mut().bytes_until_shutoff = Some(bytes);
    }

    /// A lying driver: after `after` more writes, the next `count`
    /// writes SUCCEED physically but report failure - the real-NOR
    /// behaviour of a status-poll timeout, a bus error during the
    /// acknowledgement, or supply droop while reading back status.
    /// The fifth review's third blocker lived exactly here, and no
    /// clean-failure knob can reach it: the fault the software must
    /// survive is a medium that disagrees with its own driver.
    pub fn arm_lying(&self, after: usize, count: usize) {
        self.skip.set(after);
        self.lies.set(count);
    }

    /// The sixth review's window: the moment the driver lies, READS
    /// start failing too - the bus fault that corrupted the write
    /// acknowledgement is still corrupting traffic when the read-back
    /// arrives. The next `count` reads after the first lie fail.
    pub fn arm_dead_reads_after_lie(&self, count: usize) {
        self.read_faults_after_lie.set(count);
    }

    /// Power returns / the fault clears.
    pub fn heal(&self) {
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

/// The mock driver's error: it carries no information beyond "failed".
#[derive(Debug)]
pub struct DeadError;

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
