//! Flash-backed [`StorageBackend`] for Arxia nodes on embedded targets.
//!
//! Built on `sequential-storage`, which stores key-value items in a
//! log across a NOR flash range. Three properties of that library
//! shape this crate, and each was established by running it rather
//! than by reading its documentation (the probes and their output are
//! recorded with the dependency-risk entries):
//!
//! 1. **Its API is async, and it never pends on its own.** No
//!    `Poll::Pending`, `Waker`, or `poll_fn` appears anywhere in its
//!    source; its futures await only the flash driver. Over a
//!    synchronous driver — which is what an ESP32 SPI flash is — every
//!    future completes on the first poll, measured. This crate
//!    therefore bridges to the synchronous trait with [`poll_once`],
//!    which polls **exactly once** and never loops.
//! 2. **It has no batch or transaction primitive.** Every operation is
//!    per-item and power-fail safe per item, which is a weaker
//!    guarantee than [`StorageBackend::apply_batch`] requires. The
//!    commit-marker seal below supplies the missing atomicity.
//! 3. **It iterates in write order, not key order**, and an
//!    overwritten key is yielded once per version. The trait requires
//!    ascending lexicographic key order with one entry per live key,
//!    so [`FlashStorage::scan_prefix`] sorts — see the windowed scan.
//!
//! # The single-poll bridge
//!
//! `Poll::Pending` here can only mean the flash driver stopped
//! completing synchronously — an assumption break, never a wait.
//! Spinning on it would hang a node in silence, so it surfaces as
//! [`StorageFault::WouldBlock`] on the spot. That the assumption still
//! holds is not taken on faith: it is a property of the pinned
//! dependency version and is re-validated on every bump, exactly like
//! the redb crash-window protocol.
//!
//! # The windowed ordered scan
//!
//! The trait promises ascending key order; the log gives write order.
//! Sorting the whole range would need memory proportional to the
//! store, which a 520 KB device does not have. Instead the scan makes
//! repeated passes, each collecting the [`SCAN_WINDOW`] smallest keys
//! strictly greater than the last key emitted, resolving duplicates
//! last-occurrence-wins, then emitting that window in order. Memory is
//! fixed; the cost is passes.
//!
//! **Cost, in flash reads:** every pass reads the entire log —
//! including dead versions of overwritten keys — so a scan of `n_live`
//! matching keys costs `ceil(n_live / SCAN_WINDOW) * n_log` item
//! reads, where `n_log` grows with every overwrite until compaction
//! reclaims it. The realistic access pattern is one account's chain
//! under its own prefix (tens of keys, one or two passes); a
//! whole-store scan is a conformance exercise, not a node operation.
//! The M3-6 bench measures `n_log` directly, since it is the term that
//! drifts.
//!
//! # The commit-marker seal
//!
//! `sequential-storage` is power-fail safe per item; the trait demands
//! it per batch. The gap is closed with a journal and a marker, the
//! same construction the redb kill-nine harness validates:
//!
//! 1. every operation of the batch is written under the reserved
//!    journal prefix, keyed by its index;
//! 2. a marker naming the operation count (with its complement, so
//!    a torn marker is malformed by construction rather than a
//!    plausible small count) is written - this single item is the
//!    commit point;
//! 3. each operation is applied to its real key and its journal
//!    entry erased, in order - from the caller's operations still in
//!    RAM on the in-process path, from the journal on recovery - safe
//!    because the count in the marker makes an already-erased entry
//!    a no-op, not an early stop;
//! 4. the marker is cleared last of all.
//!
//! A power cut before step 2 leaves a journal with no marker, which
//! mount discards: the batch never happened. A cut after step 2 leaves
//! a marker, and mount replays the journal to completion: the batch
//! happened in full. A cut during step 3 is the same case - replay is
//! idempotent, because a put and a delete both are. There is no window
//! where a proper subset of the batch is visible after recovery.
//!
//! The journal doubles as the capacity reservation. An applied item
//! is strictly smaller than its journal entry, and the entry dies as
//! its item lands, so the replay never holds more live data than the
//! journaling phase already fit: a batch that cannot fit fails
//! *before* its commit point, and a committed batch cannot run out
//! of space while applying. The price is one extra write per
//! operation, which the endurance model counts: a batch costs twice
//! its payload in flash appends.
//!
//! # Failure policy
//!
//! A batch that fails before its commit point never happened; its
//! journal debris is invisible to every read and discarded by the
//! next recovery. A transient fault after the commit point gets one
//! inline retry; if that fails too, the store is marked dirty and
//! every subsequent operation - reads included - runs recovery
//! before touching it. A reader therefore observes a batch before or
//! after, never in between: while the flash refuses recovery, reads
//! fail rather than serve a mixture, and the first operation after
//! the flash heals converges the store.
//!
//! # Known limits
//!
//! - Keys are bounded at [`MAX_KEY_LEN`] and values at
//!   [`MAX_VALUE_LEN`]; larger ones are rejected on WRITE with
//!   [`StorageFault::CapacityExceeded`] rather than truncated, while
//!   reads stay total: a key that cannot exist in this store -
//!   over-long or reserved - is truthfully absent, exactly as the
//!   other backends answer.
//! - The scan window lives in the store, not on the stack: the ESP32
//!   main task has an 8 KB budget and a windowed scan must not consume
//!   a third of it in locals.
//! - The flash must implement `MultiwriteNorFlash`: deleting a key
//!   writes a tombstone over an already-written word, which a
//!   write-once NOR part cannot do. The ESP32's SPI NOR flash
//!   qualifies; the bound makes a part that does not a compile error
//!   rather than a runtime surprise.
//! - Keys beginning with [`RESERVED_PREFIX`] belong to the journal.
//!   Reads are total there - `get` answers `None`, `contains` and
//!   scans answer as if the key does not exist, matching the other
//!   backends - while writes refuse with
//!   [`StorageFault::ReservedKey`], because only a write into the
//!   namespace could lose data. Arxia's own keys are printable ASCII
//!   (`c:`, `s:`), so the namespace is free.
//! - A flash that keeps faulting after a batch committed leaves the
//!   store refusing every operation until it heals; the batch then
//!   lands on the first access. Nothing can be served in between -
//!   that is the fail-safe choice for a ledger, not an optimisation
//!   target.
//! - The commit-point write distrusts the driver's error report: a
//!   marker that reads back valid is a commit, whatever the wire
//!   claimed, and the caller hears [`StorageFault::BatchCommitted`],
//!   never a rollback it might act on. When the read-back itself
//!   fails the store treats its own state as unknown: every
//!   subsequent access runs recovery before observing anything, so a
//!   caller that re-checks after the flash heals sees the medium's
//!   truth - post-batch if the marker landed, pre-batch if it did
//!   not - and never a pre-batch state that a later recovery
//!   resurrects the batch over. The error returned in that window is
//!   the original fault; a caller seeing faults in bursts re-checks
//!   before resubmitting, which is exactly the power-loss bench's
//!   audit discipline.
//! - Nothing in the node is wired to this backend yet.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(feature = "testing")]
pub mod testing;

use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::Ordering;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use arxia_core::{
    ArxiaError, CapacityKind, DriverFaultKind, FlashFault, JournalPart, RegionFaultKind,
    SerializationFaultKind, StorageFault,
};
use arxia_storage::{BatchOp, StorageBackend};
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlashError, NorFlashErrorKind};
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::{Key, MapConfig, MapConfigError, MapStorage, SerializationError};

/// Longest key this backend stores. Arxia's longest key today is a
/// per-account chain key (`c:` + 64 hex chars + `:` + nonce), which
/// fits with room to spare.
pub const MAX_KEY_LEN: usize = 96;

/// Longest value this backend stores. A compact block is 193 bytes;
/// index entries are smaller.
pub const MAX_VALUE_LEN: usize = 256;

/// How many keys one ordered-scan pass collects.
///
/// The whole memory cost of ordering is `SCAN_WINDOW * (MAX_KEY_LEN +
/// MAX_VALUE_LEN)`, held in the store rather than on the stack. Eight
/// keeps that near 2.8 KB while cutting a typical account-chain scan
/// to one or two passes.
pub const SCAN_WINDOW: usize = 8;

// ----------------------------------------------------- single-poll bridge

/// Drive a future to completion with **exactly one poll**.
///
/// Returns [`StorageFault::WouldBlock`] if the future pends. There is
/// deliberately no retry loop: on this target a pend cannot mean
/// "try again later", only that the flash driver stopped completing
/// synchronously, and a loop would turn a broken assumption into a
/// silent hang.
pub fn poll_once<F: Future>(future: F) -> Result<F::Output, ArxiaError> {
    let mut future = pin!(future);
    // `Waker::noop` has been stable since 1.85 and the workspace
    // pins 1.89, so the crate needs no hand-rolled vtable and
    // therefore no `unsafe` at all.
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => Ok(value),
        Poll::Pending => Err(ArxiaError::Storage {
            fault: StorageFault::WouldBlock,
        }),
    }
}

// ------------------------------------------------------------- key type

/// A bounded byte-string key, ordered lexicographically.
#[derive(Clone, Copy, Debug)]
pub struct FlashKey {
    bytes: [u8; MAX_KEY_LEN],
    len: u8,
}

impl PartialEq for FlashKey {
    fn eq(&self, other: &Self) -> bool {
        // On the live bytes only, matching `Ord`. A derived
        // `PartialEq` would compare the padding too, and while every
        // constructor today zeroes it, one that did not would break
        // the scan window's duplicate detection silently: two equal
        // keys with different padding would be held twice.
        self.as_slice() == other.as_slice()
    }
}

impl Eq for FlashKey {}

impl FlashKey {
    fn new(key: &[u8]) -> Result<Self, ArxiaError> {
        if key.len() > MAX_KEY_LEN {
            return Err(capacity(CapacityKind::Key, key.len(), MAX_KEY_LEN));
        }
        let mut bytes = [0u8; MAX_KEY_LEN];
        bytes[..key.len()].copy_from_slice(key);
        Ok(Self {
            bytes,
            len: key.len() as u8,
        })
    }

    /// The key bytes actually in use.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Ord for FlashKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Unsigned byte comparison, matching the trait's stated
        // ordering. Deriving would compare the padding too.
        self.as_slice().cmp(other.as_slice())
    }
}

impl PartialOrd for FlashKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Key for FlashKey {
    fn serialize_into(&self, buffer: &mut [u8]) -> Result<usize, SerializationError> {
        let n = self.len as usize;
        if buffer.len() < n + 1 {
            return Err(SerializationError::BufferTooSmall);
        }
        buffer[0] = self.len;
        buffer[1..=n].copy_from_slice(self.as_slice());
        Ok(n + 1)
    }

    fn deserialize_from(buffer: &[u8]) -> Result<(Self, usize), SerializationError> {
        let len = *buffer.first().ok_or(SerializationError::BufferTooSmall)? as usize;
        if len > MAX_KEY_LEN || buffer.len() < len + 1 {
            return Err(SerializationError::InvalidData);
        }
        let mut bytes = [0u8; MAX_KEY_LEN];
        bytes[..len].copy_from_slice(&buffer[1..=len]);
        Ok((
            Self {
                bytes,
                len: len as u8,
            },
            len + 1,
        ))
    }

    fn get_len(buffer: &[u8]) -> Result<usize, SerializationError> {
        let len = *buffer.first().ok_or(SerializationError::BufferTooSmall)? as usize;
        Ok(len + 1)
    }
}

fn capacity(what: CapacityKind, got: usize, limit: usize) -> ArxiaError {
    ArxiaError::Storage {
        fault: StorageFault::CapacityExceeded { what, got, limit },
    }
}

/// Corruption never converges, so it must never be reported as
/// [`StorageFault::BatchCommitted`] - "will apply on the next
/// access" would be a lie.
fn is_journal_corrupted(e: &ArxiaError) -> bool {
    matches!(
        e,
        ArxiaError::Storage {
            fault: StorageFault::Flash {
                fault: FlashFault::JournalCorrupted { .. },
            }
        }
    )
}

fn flash_fault(fault: FlashFault) -> ArxiaError {
    ArxiaError::Storage {
        fault: StorageFault::Flash { fault },
    }
}

/// Mirror an engine error into the typed fault surface.
///
/// No allocation happens on this path: an embedded target may be
/// failing precisely because memory or storage is what broke, and the
/// error report must not depend on either. Every discriminant the
/// engine can produce has a typed counterpart, so consumers route on
/// data - the `Backend {{ detail }}` string variant stays with the
/// std-class backends.
fn engine_fault<E: NorFlashError>(e: sequential_storage::Error<E>) -> ArxiaError {
    use sequential_storage::Error as Se;
    let fault = match e {
        Se::Storage { value, .. } => FlashFault::Driver {
            kind: match value.kind() {
                NorFlashErrorKind::NotAligned => DriverFaultKind::NotAligned,
                NorFlashErrorKind::OutOfBounds => DriverFaultKind::OutOfBounds,
                _ => DriverFaultKind::Other,
            },
        },
        Se::FullStorage => FlashFault::FullStorage,
        Se::Corrupted { .. } => FlashFault::Corrupted,
        Se::LogicBug { .. } => FlashFault::EngineBug,
        Se::BufferTooBig => FlashFault::BufferTooBig,
        Se::BufferTooSmall(needed) => FlashFault::BufferTooSmall { needed },
        Se::SerializationError(kind) => match kind {
            SerializationError::BufferTooSmall => FlashFault::Serialization {
                kind: SerializationFaultKind::BufferTooSmall,
            },
            SerializationError::InvalidData => FlashFault::Serialization {
                kind: SerializationFaultKind::InvalidData,
            },
            SerializationError::InvalidFormat => FlashFault::Serialization {
                kind: SerializationFaultKind::InvalidFormat,
            },
            SerializationError::Custom(code) => FlashFault::Serialization {
                kind: SerializationFaultKind::Custom(code),
            },
            // The enum is non-exhaustive upstream: an unknown variant
            // means the pinned engine changed shape, which the pin
            // test forces through review before it can land.
            _ => FlashFault::EngineBug,
        },
        Se::ItemTooBig => FlashFault::ItemTooBig,
        // The engine's error enum is not marked non-exhaustive today;
        // if a bump adds a variant, the pin test forces this match to
        // be revisited before the bump lands.
        _ => FlashFault::EngineBug,
    };
    flash_fault(fault)
}

/// Key prefix reserved for the batch journal. Reads and scans never
/// surface a key beginning with this byte.
pub const RESERVED_PREFIX: u8 = 0x00;

const JOURNAL_TAG: u8 = 0x6A;
const MARKER_TAG: u8 = 0x63;
const OP_PUT: u8 = 0x00;
const OP_DELETE: u8 = 0x01;
const MARKER_KEY: [u8; 2] = [RESERVED_PREFIX, MARKER_TAG];

/// The marker payload: the operation count and its bitwise complement.
///
/// The engine's CRC catches most torn writes, but a torn marker that
/// happens to collide the CRC at exactly two bytes would parse as a
/// small, legitimate-looking count - and recovery would then replay a
/// STRICT PREFIX of a batch that never committed: partial application,
/// the one state the seal exists to forbid. The complement makes any
/// two-byte payload malformed by construction (it must be four bytes)
/// and any four-byte payload self-checking: a torn write that
/// collides the CRC must also produce a complement pair, which halves
/// nothing - it multiplies the collision requirement by 2^16. Zero
/// runtime cost, no format migration: nothing is deployed.
fn encode_marker(count: u16) -> [u8; 4] {
    let c = count.to_be_bytes();
    let n = (!count).to_be_bytes();
    [c[0], c[1], n[0], n[1]]
}

/// A marker payload is valid only at four bytes with a matching
/// complement; anything else is malformed and discarded.
fn decode_marker(b: &[u8]) -> Option<u16> {
    if b.len() != 4 {
        return None;
    }
    let count = u16::from_be_bytes([b[0], b[1]]);
    let check = u16::from_be_bytes([b[2], b[3]]);
    (check == !count).then_some(count)
}

/// Largest journal entry: an operation tag, a key length, the key and
/// a full-sized value. Deliberately larger than [`MAX_VALUE_LEN`],
/// which bounds one user payload rather than one journal record.
pub const JOURNAL_ENTRY_MAX: usize = 2 + MAX_KEY_LEN + MAX_VALUE_LEN;

/// Refuse a key in the reserved namespace.
///
/// The journal lives under [`RESERVED_PREFIX`] and reads hide it, so a
/// user key starting with that byte would be written, then hidden, then
/// discarded by the next mount as uncommitted journal debris. Silently
/// losing an accepted write is the worst outcome available, so the
/// write is refused instead.
fn reject_reserved(key: &[u8]) -> Result<(), ArxiaError> {
    if key.first() == Some(&RESERVED_PREFIX) {
        return Err(ArxiaError::Storage {
            fault: StorageFault::ReservedKey,
        });
    }
    Ok(())
}

fn journal_key(index: u16) -> [u8; 4] {
    let i = index.to_be_bytes();
    [RESERVED_PREFIX, JOURNAL_TAG, i[0], i[1]]
}

/// Journal entry key length, shared by the writer and the discard scan.
const JOURNAL_KEY_LEN: usize = 4;

/// The working buffer every engine call receives: room for the largest
/// journal record plus a serialized key plus header slack. One name,
/// so the four sites that size it cannot drift apart.
const ITEM_BUFFER_LEN: usize = JOURNAL_ENTRY_MAX + MAX_KEY_LEN + 32;

/// The smallest flash footprint a journal item can have: the engine's
/// 8-byte item header (measured in its source at the pinned version),
/// the serialized journal key (length prefix + [`JOURNAL_KEY_LEN`]),
/// and the 2-byte minimum of a structurally valid entry. The marker
/// count's physical ceiling divides the region by this.
const JOURNAL_ITEM_MIN_BYTES: usize = 8 + 1 + JOURNAL_KEY_LEN + 2;

// ------------------------------------------------------ the scan window

/// One pass's worth of keys, held sorted ascending.
///
/// Generic over the window size so the degenerate setting can be
/// exercised rather than merely assumed safe: correctness must not
/// depend on `W`, and `W == 1` puts every key on its own pass, which
/// is where pass-stitching is under the most pressure.
struct ScanWindow<const W: usize> {
    keys: [FlashKey; W],
    values: [[u8; MAX_VALUE_LEN]; W],
    value_lens: [u16; W],
    len: usize,
}

impl<const W: usize> ScanWindow<W> {
    /// A window of zero would make every pass empty and the scan
    /// return nothing, silently. Refused at compile time.
    const NON_ZERO: () = assert!(W > 0, "SCAN_WINDOW must be at least 1");

    fn new() -> Self {
        let () = Self::NON_ZERO;
        Self {
            keys: [FlashKey {
                bytes: [0u8; MAX_KEY_LEN],
                len: 0,
            }; W],
            values: [[0u8; MAX_VALUE_LEN]; W],
            value_lens: [0u16; W],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    /// Offer one log item to the window.
    ///
    /// Last occurrence wins: an item whose key is already held
    /// **replaces** the held value, because the log yields older
    /// versions of an overwritten key before the live one. Keeping the
    /// first occurrence would serve stale data from a scan while point
    /// lookups returned the current value.
    fn offer(&mut self, key: &FlashKey, value: &[u8]) {
        if let Some(slot) = (0..self.len).find(|&i| self.keys[i] == *key) {
            self.store_value(slot, value);
            return;
        }
        // Insert in sorted position, dropping the largest if full.
        let pos = (0..self.len)
            .find(|&i| self.keys[i] > *key)
            .unwrap_or(self.len);
        if pos == W {
            return; // larger than everything held, and the window is full
        }
        let end = if self.len == W { W - 1 } else { self.len };
        let mut i = end;
        while i > pos {
            self.keys[i] = self.keys[i - 1];
            self.values[i] = self.values[i - 1];
            self.value_lens[i] = self.value_lens[i - 1];
            i -= 1;
        }
        self.keys[pos] = *key;
        self.store_value(pos, value);
        if self.len < W {
            self.len += 1;
        }
    }

    fn store_value(&mut self, slot: usize, value: &[u8]) {
        // The scan rejects oversized values before offering, so this
        // index cannot overflow; truncating here instead would let
        // the scan serve a different byte string than get() for the
        // same key, which the conformance suite forbids.
        self.values[slot][..value.len()].copy_from_slice(value);
        self.value_lens[slot] = value.len() as u16;
    }

    fn entry(&self, i: usize) -> (&FlashKey, &[u8]) {
        (
            &self.keys[i],
            &self.values[i][..self.value_lens[i] as usize],
        )
    }
}

// --------------------------------------------------------- the backend

type FlashCache = Cache<Uncached, Uncached, Uncached, FlashKey>;

struct Inner<S: MultiwriteNorFlash, const W: usize> {
    map: MapStorage<FlashKey, S, FlashCache>,
    /// Item buffer for the library. Sized for the longest key plus the
    /// longest value plus their framing.
    buffer: [u8; ITEM_BUFFER_LEN],
    window: ScanWindow<W>,
}

/// Flash-backed key-value store over a NOR flash range.
///
/// Held behind a `RefCell` internally because the trait's read methods
/// take `&self` while the underlying library needs `&mut`; the cell is
/// never held across a call into user code.
pub struct FlashStorage<S: MultiwriteNorFlash, const W: usize = SCAN_WINDOW> {
    inner: RefCell<Inner<S, W>>,
    /// What the journal may currently hold, and therefore who must
    /// clean it. On the clean path both gates cost one RAM read;
    /// recovery scans the log only after an actual failure, which
    /// keeps it out of the per-batch cost model.
    health: core::cell::Cell<Health>,
}

impl<S: MultiwriteNorFlash, const W: usize> core::fmt::Debug for FlashStorage<S, W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The driver is deliberately not required to be Debug; the
        // store's own observable state is its health.
        f.debug_struct("FlashStorage")
            .field(
                "health",
                match self.health.get() {
                    Health::Clean => &"clean",
                    Health::Debris => &"debris",
                    Health::Pending => &"pending",
                },
            )
            .finish_non_exhaustive()
    }
}

/// The journal's condition, tracked in RAM.
///
/// The distinction the two dirty states draw is who is affected.
/// Markerless debris ([`Health::Debris`]) is invisible to every read
/// path already, so gating reads on it would cost availability -
/// reads on a store whose flash is refusing writes would fail for no
/// consistency gain - and only the next batch, whose journal keys
/// would collide with the debris, must clean first. A committed but
/// unfinished batch ([`Health::Pending`]) is the opposite: readers
/// would see a half-applied batch, so everything runs recovery first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    /// No journal state exists.
    Clean,
    /// Markerless journal debris may exist: invisible to readers,
    /// cleaned before the next batch journals.
    Debris,
    /// A committed batch is not fully applied: every operation
    /// converges the store before touching it.
    Pending,
}

/// A failed [`FlashStorage::mount`], carrying the flash driver back.
///
/// The medium outlives the software that failed on it, and the caller
/// keeps every option: retry, or erase the region and re-sync the
/// ledger from peers.
pub struct MountFailure<S> {
    /// The flash driver, returned to the caller.
    pub flash: S,
    /// Why the mount failed.
    pub error: ArxiaError,
}

impl<S> core::fmt::Debug for MountFailure<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The flash driver is deliberately not required to be Debug.
        f.debug_struct("MountFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<S: MultiwriteNorFlash, const W: usize> FlashStorage<S, W> {
    /// Mount a store over `flash_range` of `flash`.
    ///
    /// The range must be page-aligned and at least two pages long;
    /// `sequential-storage` validates that and this constructor
    /// surfaces the failure rather than panicking.
    ///
    /// On failure the flash driver comes back with the error, exactly
    /// as [`Self::into_flash`] returns it on success: the medium
    /// outlives a failed mount, and the caller keeps every option -
    /// retry after a transient fault, or erase the region and re-sync
    /// after [`FlashFault::JournalCorrupted`]. A mount that swallowed
    /// the driver would leave a recoverable device with no path to
    /// recovery.
    pub fn mount(flash: S, flash_range: core::ops::Range<u32>) -> Result<Self, MountFailure<S>> {
        let config = match MapConfig::try_new(flash_range) {
            Ok(config) => config,
            Err(e) => {
                let kind = match e {
                    MapConfigError::StartRangeNotAtPageBoundary => {
                        RegionFaultKind::StartNotPageAligned
                    }
                    MapConfigError::EndRangeNotAtPageBoundary => RegionFaultKind::EndNotPageAligned,
                    _ => RegionFaultKind::TooSmall,
                };
                return Err(MountFailure {
                    flash,
                    error: flash_fault(FlashFault::BadRegion { kind }),
                });
            }
        };
        let store = Self {
            inner: RefCell::new(Inner {
                map: MapStorage::new(flash, config, Cache::new_uncached()),
                buffer: [0u8; ITEM_BUFFER_LEN],
                window: ScanWindow::new(),
            }),
            health: core::cell::Cell::new(Health::Clean),
        };
        if let Err(error) = store.recover() {
            return Err(MountFailure {
                flash: store.into_flash(),
                error,
            });
        }
        Ok(store)
    }

    /// Exclusive, MUTABLE access to the underlying flash, for erase
    /// accounting and bench instrumentation.
    ///
    /// Two truths the old name and doc hid. The guard is a full write
    /// handle on the medium, not a read-only view - the storage
    /// engine only exposes its flash mutably. And it holds the
    /// store's internal cell: any store method called while the guard
    /// lives panics on the borrow, so take the guard, read the
    /// numbers, and drop it before touching the store again.
    pub fn flash_mut(&self) -> core::cell::RefMut<'_, S> {
        core::cell::RefMut::map(self.inner.borrow_mut(), |i| i.map.flash())
    }

    /// Converge a committed-but-unfinished batch before an operation
    /// observes the store. Reads pass over markerless debris - it is
    /// invisible to them and cleaning it here would trade
    /// availability for nothing.
    fn ensure_converged(&self) -> Result<(), ArxiaError> {
        if self.health.get() != Health::Pending {
            return Ok(());
        }
        self.recover()?;
        self.health.set(Health::Clean);
        Ok(())
    }

    /// Clean the journal completely before a batch writes into it:
    /// debris would collide with the new batch's journal keys, and a
    /// pending batch must land before a new marker exists.
    fn ensure_clean(&self) -> Result<(), ArxiaError> {
        if self.health.get() == Health::Clean {
            return Ok(());
        }
        self.recover()?;
        self.health.set(Health::Clean);
        Ok(())
    }

    /// Finish or discard any batch interrupted by a power cut or an
    /// earlier failure.
    ///
    /// Called by [`Self::mount`] and by [`Self::ensure_clean`], so a
    /// store is consistent before anything reads it. A well-formed
    /// marker means the batch committed and its journal must be
    /// replayed. A journal without a marker means the batch never
    /// reached its commit point and is discarded. A *malformed*
    /// marker (a torn write the CRC let through at some other length)
    /// never named a replayable batch, so it is discarded along with
    /// the journal - leaving it behind would make every future
    /// recovery re-read garbage for ever.
    fn recover(&self) -> Result<(), ArxiaError> {
        match self.fetch_raw(&MARKER_KEY)? {
            Some(b) if decode_marker(&b).is_some() => {
                let count = decode_marker(&b).expect("guarded above");
                // The count is untrusted too. A corrupt count would
                // otherwise drive one full-log search per claimed
                // entry at every mount: a multi-hour boot,
                // indistinguishable from a hang. Two bounds refuse
                // it. Physically, no batch can hold more entries than
                // the region could store: a journal item costs at
                // least JOURNAL_ITEM_MIN_BYTES of flash (the engine's
                // 8-byte item header, measured in its source, plus
                // the 5-byte serialized journal key and the 2-byte
                // minimum entry), so `region / that` is the ceiling -
                // held in usize, because an earlier version capped it
                // at u16::MAX and thereby waved 0xFFFF through on any
                // region of 512 KiB or more, the T-Beam's 4 MiB part
                // included. And 0xFFFF specifically - the
                // erased-flash pattern, the most likely garbage - can
                // never be legitimate at any region size, because
                // apply_batch refuses batches of u16::MAX operations
                // for exactly this reason: the sentinel stays
                // unambiguous.
                let region = {
                    let inner = self.inner.borrow();
                    let range = inner.map.flash_range();
                    (range.end - range.start) as usize
                };
                let max_entries = region / JOURNAL_ITEM_MIN_BYTES;
                if count == u16::MAX || count as usize > max_entries {
                    return Err(flash_fault(FlashFault::JournalCorrupted {
                        part: JournalPart::MarkerCount(count),
                    }));
                }
                self.replay_journal(count)
            }
            Some(_) => {
                self.discard_journal()?;
                self.erase(&MARKER_KEY)
            }
            None => self.discard_journal(),
        }
    }

    /// Apply a committed journal in order, then clear the marker.
    ///
    /// Each entry is applied and then erased before the next one is
    /// touched. That order is safe only because the marker carries
    /// the operation count: an early version without the count
    /// stopped replaying at the first missing index and declared a
    /// half-applied batch finished, which the power-cut sweep caught.
    /// With the count, a gap is just an entry that already landed.
    ///
    /// Erase-as-you-go is also what makes the replay immune to
    /// running out of space. An applied item is strictly smaller than
    /// its journal entry (same key and value, minus the journal
    /// framing), and the entry dies as soon as its item lands, so the
    /// live set during replay never exceeds what the journaling phase
    /// already fit. The journal IS the capacity reservation: a batch
    /// whose journal and marker landed cannot fail to apply for
    /// space, and a batch that cannot fit fails before its commit
    /// point with nothing to clean but invisible debris.
    ///
    /// Every error propagates. The storage library returns Ok when
    /// asked to remove an absent key (verified in its source at the
    /// pinned version), so any error out of an erase here is a real
    /// fault - swallowing it would let a transient fault end a replay
    /// early, report success, and strand the rest of the batch with
    /// the journal cleared: an unrecoverable partial application.
    ///
    /// Both phases are idempotent, and the marker goes last: while it
    /// exists recovery repeats, so a cut or a fault anywhere inside
    /// recovery is retried by the next one.
    fn replay_journal(&self, count: u16) -> Result<(), ArxiaError> {
        for index in 0..count {
            let jkey = journal_key(index);
            if let Some(entry) = self.fetch_raw(&jkey)? {
                apply_encoded_op(self, &entry, index)?;
                self.erase(&jkey)?;
            }
        }
        self.erase(&MARKER_KEY)?;
        Ok(())
    }

    /// Apply a committed batch from the operations still in RAM.
    ///
    /// The happy path's twin of [`Self::replay_journal`]. Recovery
    /// must re-read the journal because RAM is gone; the in-process
    /// path still holds the caller's operations, already validated
    /// before the first journal write, so re-fetching each entry from
    /// flash and re-parsing it would spend `k` log searches to learn
    /// what it already knows. Same discipline otherwise: apply one
    /// operation, erase its journal entry, move on, marker last -
    /// the erase-as-you-go capacity profile is unchanged, and so is
    /// idempotence, since a cut anywhere in here leaves a marked
    /// journal that [`Self::replay_journal`] finishes from flash.
    ///
    /// The ops slice and the journal are the same batch by
    /// construction (this is called only from `apply_batch`, right
    /// after that batch's own journaling), so entry `i` on flash and
    /// `ops[i]` in RAM describe one operation.
    fn apply_from_ram(&self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        for (index, op) in ops.iter().enumerate() {
            match op {
                BatchOp::Put { key, value } => self.store_raw(key, value)?,
                BatchOp::Delete { key } => self.erase(key)?,
            }
            self.erase(&journal_key(index as u16))?;
        }
        self.erase(&MARKER_KEY)?;
        Ok(())
    }

    /// Remove journal entries left by a batch that never committed.
    fn discard_journal(&self) -> Result<(), ArxiaError> {
        let mut stale: Vec<[u8; JOURNAL_KEY_LEN]> = Vec::new();
        {
            let mut inner = self.inner.borrow_mut();
            let Inner { map, buffer, .. } = &mut *inner;
            let mut iter_buffer = [0u8; ITEM_BUFFER_LEN];
            let mut iter =
                poll_once(map.fetch_all_items(&mut iter_buffer))?.map_err(engine_fault)?;
            while let Some((key, _)) =
                poll_once(iter.next::<&[u8]>(buffer))?.map_err(engine_fault)?
            {
                let k = key.as_slice();
                if k.len() == JOURNAL_KEY_LEN && k[0] == RESERVED_PREFIX && k[1] == JOURNAL_TAG {
                    let mut owned = [0u8; JOURNAL_KEY_LEN];
                    owned.copy_from_slice(k);
                    if !stale.contains(&owned) {
                        stale.push(owned);
                    }
                }
            }
        }
        for k in stale {
            self.erase(&k)?;
        }
        Ok(())
    }

    /// Consume the store and return the flash, so a caller can
    /// remount the same medium — which is what a board does when power
    /// comes back.
    pub fn into_flash(self) -> S {
        self.inner.into_inner().map.destroy().0
    }

    /// Read a user key. Reads are total: a key in the reserved
    /// namespace can never hold user data, so it is simply absent -
    /// `Ok(None)` - exactly as it is on the other backends. Only
    /// writes refuse the namespace, because only a write there could
    /// lose data.
    fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        self.ensure_converged()?;
        if key.first() == Some(&RESERVED_PREFIX) || key.len() > MAX_KEY_LEN {
            // Total reads, both ways a key can be unstorable: a key
            // that cannot exist in this store is truthfully absent,
            // exactly as the other backends answer. Only writes
            // refuse.
            return Ok(None);
        }
        self.fetch_raw(key)
    }

    /// Presence without materialising the value: `delete` and
    /// `contains` only need the answer, and a 193-byte block copied
    /// onto the heap to be dropped immediately is waste a 520 KB
    /// device notices.
    fn exists(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        self.ensure_converged()?;
        if key.first() == Some(&RESERVED_PREFIX) || key.len() > MAX_KEY_LEN {
            return Ok(false);
        }
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        let found = poll_once(map.fetch_item::<&[u8]>(buffer, &k))?.map_err(engine_fault)?;
        Ok(found.is_some())
    }

    fn fetch_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        let found = poll_once(map.fetch_item::<&[u8]>(buffer, &k))?.map_err(engine_fault)?;
        Ok(found.map(|v| v.to_vec()))
    }

    /// Store a user value: the payload cap and the reserved-namespace
    /// rule both apply here, and only here.
    fn store(&self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(capacity(CapacityKind::Value, value.len(), MAX_VALUE_LEN));
        }
        reject_reserved(key)?;
        self.store_raw(key, value)
    }

    /// Store without the user-facing checks.
    ///
    /// The journal needs this: a journal entry is a whole operation —
    /// tag, key and value — so it is necessarily larger than the value
    /// cap that bounds one user payload. Capping the entry at
    /// MAX_VALUE_LEN would reject a batch carrying a 193-byte block
    /// under a chain key, which is the crate's whole reason to exist.
    /// Journal keys are also reserved by construction, so the
    /// namespace check must not fire on them.
    fn store_raw(&self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        poll_once(map.store_item(buffer, &k, &value))?.map_err(engine_fault)
    }

    fn erase(&self, key: &[u8]) -> Result<(), ArxiaError> {
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        poll_once(map.remove_item(buffer, &k))?.map_err(engine_fault)
    }
}

impl<S: MultiwriteNorFlash, const W: usize> StorageBackend for FlashStorage<S, W> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        self.ensure_converged()?;
        match self.store(key, value) {
            // Pre-commit debris is cleaned by the next batch or the
            // next mount - but a caller that only ever puts has
            // neither, and the debris holds real space: without this
            // retry, one failed batch could pin every subsequent
            // put on FullStorage for the life of the process. Clean
            // once, retry once; a second FullStorage is then a
            // genuinely full store.
            Err(e)
                if self.health.get() == Health::Debris
                    && matches!(
                        e,
                        ArxiaError::Storage {
                            fault: StorageFault::Flash {
                                fault: FlashFault::FullStorage,
                            }
                        }
                    ) =>
            {
                self.recover()?;
                self.health.set(Health::Clean);
                self.store(key, value)
            }
            r => r,
        }
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        self.fetch(key)
    }

    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
        reject_reserved(key)?;
        let existed = self.exists(key)?;
        if existed {
            self.erase(key)?;
        }
        Ok(existed)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        self.exists(key)
    }

    fn scan_prefix(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<(), ArxiaError> {
        self.ensure_converged()?;
        let mut last_emitted: Option<FlashKey> = None;
        loop {
            {
                let mut inner = self.inner.borrow_mut();
                let Inner {
                    map,
                    buffer,
                    window,
                } = &mut *inner;
                window.clear();

                let mut iter_buffer = [0u8; ITEM_BUFFER_LEN];
                let mut iter =
                    poll_once(map.fetch_all_items(&mut iter_buffer))?.map_err(engine_fault)?;
                while let Some((key, value)) =
                    poll_once(iter.next::<&[u8]>(buffer))?.map_err(engine_fault)?
                {
                    if key.as_slice().first() == Some(&RESERVED_PREFIX) {
                        continue; // journal bookkeeping is not user data
                    }
                    if !key.as_slice().starts_with(prefix) {
                        continue;
                    }
                    // A value the window cannot hold whole is never
                    // truncated: a scan serving 256 bytes of a
                    // 300-byte value while get() served all 300 would
                    // split the two read paths the conformance suite
                    // promises agree. Only a foreign write can
                    // produce such an item - our own writes are
                    // capped - and an out-of-spec store is surfaced,
                    // not silently reshaped.
                    if value.len() > MAX_VALUE_LEN {
                        return Err(capacity(CapacityKind::Value, value.len(), MAX_VALUE_LEN));
                    }
                    // Strictly greater than the last key emitted, so a
                    // pass never re-emits what the previous one did.
                    if let Some(last) = last_emitted {
                        if key <= last {
                            continue;
                        }
                    }
                    window.offer(&key, value);
                }
            }

            // Copy the window out before calling `visit`: the callback
            // is user code and may read this very store, which would
            // panic on a RefCell already borrowed here. The struct's
            // own documentation promises the cell is never held across
            // a call into user code, and this is what keeps it true.
            let (batch, final_key) = {
                let inner = self.inner.borrow();
                if inner.window.len == 0 {
                    return Ok(());
                }
                let count = inner.window.len;
                let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(count);
                for i in 0..count {
                    let (k, v) = inner.window.entry(i);
                    out.push((k.as_slice().to_vec(), v.to_vec()));
                }
                (out, inner.window.keys[count - 1])
            };

            // Termination is an invariant, not an accident: every pass
            // must advance strictly past the last key emitted, because
            // the pass filter collects only strictly-greater keys. If
            // a pass ever fails to advance, looping on it would hang
            // the node — a liveness failure no assertion can catch —
            // so it surfaces as a fault instead. The mutation log
            // records the non-strict-comparison mutant hanging the
            // suite before this guard existed.
            if let Some(last) = last_emitted {
                if final_key <= last {
                    return Err(flash_fault(FlashFault::ScanStalled));
                }
            }

            for (k, v) in &batch {
                if !visit(k, v) {
                    return Ok(());
                }
            }

            // A pass that collected fewer keys than the window holds
            // proved there is nothing left above it: reading the log
            // once more to find an empty window would double the cost
            // of every scan on its dominant path, and the endurance
            // model would be wrong by a whole pass.
            if batch.len() < W {
                return Ok(());
            }
            last_emitted = Some(final_key);
        }
    }

    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        if ops.is_empty() {
            return Ok(());
        }
        // Strictly below u16::MAX: a batch of exactly 65535 operations
        // would write a marker count equal to the erased-flash pattern,
        // and recovery deliberately treats that value as corruption at
        // any region size. Refusing it here keeps the sentinel
        // unambiguous instead of trading it for a one-in-65536
        // misclassification.
        if ops.len() >= u16::MAX as usize {
            return Err(capacity(
                CapacityKind::BatchOperations,
                ops.len(),
                u16::MAX as usize - 1,
            ));
        }

        // Validate every operation BEFORE writing anything: a batch
        // that cannot be completed must not leave a journal behind.
        for op in ops {
            match op {
                BatchOp::Put { key, value } => {
                    FlashKey::new(key)?;
                    reject_reserved(key)?;
                    if value.len() > MAX_VALUE_LEN {
                        return Err(capacity(CapacityKind::Value, value.len(), MAX_VALUE_LEN));
                    }
                }
                BatchOp::Delete { key } => {
                    FlashKey::new(key)?;
                    reject_reserved(key)?;
                }
            }
        }

        // A pending marker means an earlier batch committed but its
        // replay did not finish. Writing a new marker over it - and
        // new journal entries over its journal - would strand that
        // batch half applied for ever, so it is finished first. If it
        // cannot be finished, this batch does not start.
        self.ensure_clean()?;

        // Step 1: journal every operation. A failure here leaves only
        // markerless debris: invisible to every read, discarded by
        // the next recovery, and the batch never happened.
        let mut encoded = [0u8; JOURNAL_ENTRY_MAX];
        for (index, op) in ops.iter().enumerate() {
            let n = encode_op(op, &mut encoded);
            if let Err(e) = self.store_raw(&journal_key(index as u16), &encoded[..n]) {
                self.health.set(Health::Debris);
                return Err(e);
            }
        }

        // Step 2: the commit point. Before this single write the
        // batch does not exist; after it, the batch is guaranteed to
        // land. The marker carries the operation count: replay must
        // know how many entries the batch had, because it cannot
        // infer that from what is still on flash.
        //
        // The driver's error report is NOT trusted on this one write.
        // Real NOR parts can program successfully and still report
        // failure - a status-poll timeout, a bus error during the
        // acknowledgement, supply droop while the driver reads back
        // its status - and this is the single write where believing a
        // false failure is catastrophic: the caller, told nothing
        // changed, may submit an alternative batch for the same
        // logical transition; that batch's pre-batch recovery then
        // finds the marker VALID, replays the first batch, and
        // journals the second on top - both apply, and the ledger
        // carries writes the caller was told were rolled back. So the
        // error path reads the marker back: if it is on flash and
        // names this batch, the commit happened, whatever the driver
        // said, and the caller is told the truth of the medium, not
        // the claim of the wire.
        let count = ops.len() as u16;
        let marker = encode_marker(count);
        if let Err(e) = self.store_raw(&MARKER_KEY, &marker) {
            match self.fetch_raw(&MARKER_KEY) {
                Ok(Some(b)) if b == marker => {
                    // Committed despite the report. Try to finish it
                    // inline, exactly as a replay fault would be
                    // retried; failing that, the caller hears
                    // BatchCommitted, never a rollback it might act
                    // on.
                    self.health.set(Health::Pending);
                    match self.recover() {
                        Ok(()) => {
                            self.health.set(Health::Clean);
                            return Ok(());
                        }
                        Err(second) => {
                            if is_journal_corrupted(&second) {
                                return Err(second);
                            }
                            return Err(ArxiaError::Storage {
                                fault: StorageFault::BatchCommitted,
                            });
                        }
                    }
                }
                // Absent, or not this batch's marker: the commit
                // truly did not happen and the driver's report was
                // honest - the rollback is real, the leftovers are
                // debris.
                Ok(_) => {
                    self.health.set(Health::Debris);
                }
                // The read-back itself failed: UNKNOWN, and unknown
                // is not rollback. Classified as Debris, reads would
                // keep serving the pre-batch state over a possibly
                // committed marker, a put would be accepted on top,
                // and the next batch's recovery would replay the old
                // batch OVER it - an acknowledged write silently
                // overwritten. Pending instead: every subsequent
                // access runs recovery before observing anything, so
                // the first operation after the flash heals settles
                // the question from the medium - marker present, the
                // batch replays first; absent, the debris clears -
                // and nothing acknowledged is ever built on sand.
                //
                // Pending protects the STORE; the return class must
                // protect the CALLER. A generic driver fault here is
                // contractually a rollback, and a caller acting on it
                // - resubmitting an alternative batch after the flash
                // heals - would have the next recovery replay the
                // first batch and then apply the second: double
                // application. Rollback-certain and unknown are two
                // distinguishable causes, so they never share a
                // class: this arm alone emits CommitUncertain.
                Err(_read) => {
                    self.health.set(Health::Pending);
                    return Err(ArxiaError::Storage {
                        fault: StorageFault::CommitUncertain,
                    });
                }
            }
            return Err(e);
        }

        // Steps 3 and 4, applied from the ops still in RAM (recovery
        // re-reads the journal; the in-process path has no need to).
        // A transient fault mid-apply gets one inline retry through
        // recovery, so this method never leaves a committed batch half
        // applied while the flash is answering: either the retry
        // finishes the batch and this call reports the success it is,
        // or the store is marked pending and every subsequent
        // operation runs recovery before touching it - a reader can
        // observe the batch before or after, never in between.
        //
        // When the retry fails too, the error is the typed
        // BatchCommitted signal, not the underlying fault: the batch
        // is past its commit point and WILL apply on the next access,
        // and a caller that read a generic error as a rollback would
        // resubmit and double-apply. The one exception is journal
        // corruption, which no retry will ever fix - that fault
        // propagates as itself, because "will converge" would be a
        // lie.
        match self.apply_from_ram(ops) {
            Ok(()) => Ok(()),
            Err(_first) => {
                self.health.set(Health::Pending);
                match self.recover() {
                    Ok(()) => {
                        self.health.set(Health::Clean);
                        Ok(())
                    }
                    Err(second) => {
                        if is_journal_corrupted(&second) {
                            return Err(second);
                        }
                        Err(ArxiaError::Storage {
                            fault: StorageFault::BatchCommitted,
                        })
                    }
                }
            }
        }
    }
}

/// Encode one batch operation into `out`, returning its length.
///
/// Layout: tag byte, key length, key, then the value for a put.
fn encode_op(op: &BatchOp<'_>, out: &mut [u8]) -> usize {
    match op {
        BatchOp::Put { key, value } => {
            out[0] = OP_PUT;
            out[1] = key.len() as u8;
            out[2..2 + key.len()].copy_from_slice(key);
            let start = 2 + key.len();
            out[start..start + value.len()].copy_from_slice(value);
            start + value.len()
        }
        BatchOp::Delete { key } => {
            out[0] = OP_DELETE;
            out[1] = key.len() as u8;
            out[2..2 + key.len()].copy_from_slice(key);
            2 + key.len()
        }
    }
}

/// Re-validate a journalled operation against every write-path
/// invariant, then apply it to its real key.
///
/// The parsed entry is UNTRUSTED. The CRC catches torn writes, not
/// all corruption, and an entry that parses structurally can still
/// violate every invariant the write path enforces - so the replay
/// re-checks all of them: known op tag, key outside the reserved
/// namespace (for BOTH ops - an earlier version guarded OP_PUT
/// through the write path while OP_DELETE went straight to the
/// engine, and a corrupt entry parsing as a delete of a journal key
/// could erase the seal's own bookkeeping mid-replay: a later entry
/// silently skipped as "already applied", or the marker itself gone
/// with the batch half done), key within [`MAX_KEY_LEN`], value
/// within [`MAX_VALUE_LEN`].
///
/// Every violation is [`FlashFault::JournalCorrupted`] - never a
/// user-facing class. A corrupt entry that surfaced as
/// `CapacityExceeded` or `ReservedKey` would fit neither branch of
/// the documented routing (transient = retry, corrupted = re-sync),
/// and worse, the inline-retry path in `apply_batch` would miss it
/// and report `BatchCommitted` - "will apply on the next access" -
/// for a batch that can never apply.
///
/// Every flash error propagates, the delete arm included: the storage
/// library already returns Ok when asked to remove an absent key
/// (verified in its source at the pinned version), so an error out of
/// the erase can only be a real fault.
fn apply_encoded_op<S: MultiwriteNorFlash, const W: usize>(
    store: &FlashStorage<S, W>,
    entry: &[u8],
    index: u16,
) -> Result<(), ArxiaError> {
    let corrupt = || {
        flash_fault(FlashFault::JournalCorrupted {
            part: JournalPart::Entry(index),
        })
    };
    if entry.len() < 2 {
        return Err(corrupt());
    }
    let key_len = entry[1] as usize;
    if entry.len() < 2 + key_len {
        return Err(corrupt());
    }
    let key = &entry[2..2 + key_len];
    if key.len() > MAX_KEY_LEN {
        return Err(corrupt());
    }
    if key.first() == Some(&RESERVED_PREFIX) {
        return Err(corrupt());
    }
    match entry[0] {
        OP_PUT => {
            let value = &entry[2 + key_len..];
            if value.len() > MAX_VALUE_LEN {
                return Err(corrupt());
            }
            // The user-facing checks were just re-run above in the
            // corruption class, so the write goes through the raw
            // path: running them again through store() would resurface
            // a violation as a user error.
            store.store_raw(key, value)
        }
        OP_DELETE => store.erase(key),
        _ => Err(corrupt()),
    }
}
