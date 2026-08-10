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
//!    journal prefix, keyed by sequence and index;
//! 2. a marker naming that sequence is written - this single item is
//!    the commit point;
//! 3. every operation is applied to its real key - all of them,
//!    before any journal entry is removed;
//! 4. the journal is cleared, and the marker last of all.
//!
//! A power cut before step 2 leaves a journal with no marker, which
//! mount discards: the batch never happened. A cut after step 2 leaves
//! a marker, and mount replays the journal to completion: the batch
//! happened in full. A cut during step 3 is the same case - replay is
//! idempotent, because a put and a delete both are. There is no window
//! where a proper subset of the batch is visible after recovery.
//!
//! The price is one extra write per operation, which the endurance
//! model counts: a batch costs twice its payload in flash appends.
//!
//! # Known limits
//!
//! - Keys are bounded at [`MAX_KEY_LEN`] and values at
//!   [`MAX_VALUE_LEN`]; larger ones are rejected with
//!   [`StorageFault::CapacityExceeded`] rather than truncated.
//! - The scan window lives in the store, not on the stack: the ESP32
//!   main task has an 8 KB budget and a windowed scan must not consume
//!   a third of it in locals.
//! - The flash must implement `MultiwriteNorFlash`: deleting a key
//!   writes a tombstone over an already-written word, which a
//!   write-once NOR part cannot do. The ESP32's SPI NOR flash
//!   qualifies; the bound makes a part that does not a compile error
//!   rather than a runtime surprise.
//! - Keys beginning with [`RESERVED_PREFIX`] belong to the journal
//!   and are invisible to reads and scans. Arxia's own keys are
//!   printable ASCII (`c:`, `s:`), so the namespace is free.
//! - Nothing in the node is wired to this backend yet.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::Ordering;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use arxia_core::{ArxiaError, CapacityKind, StorageFault};
use arxia_storage::{BatchOp, StorageBackend};
use embedded_storage_async::nor_flash::MultiwriteNorFlash;
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::{Key, MapConfig, MapStorage, SerializationError};

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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlashKey {
    bytes: [u8; MAX_KEY_LEN],
    len: u8,
}

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

fn backend_fault<E: core::fmt::Debug>(e: E) -> ArxiaError {
    use alloc::format;
    ArxiaError::Storage {
        fault: StorageFault::Backend {
            detail: format!("{e:?}"),
        },
    }
}

/// Key prefix reserved for the batch journal. Reads and scans never
/// surface a key beginning with this byte.
pub const RESERVED_PREFIX: u8 = 0x00;

const JOURNAL_TAG: u8 = 0x6A;
const MARKER_TAG: u8 = 0x63;
const OP_PUT: u8 = 0x00;
const OP_DELETE: u8 = 0x01;
const MARKER_KEY: [u8; 2] = [RESERVED_PREFIX, MARKER_TAG];

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

fn journal_key(seq: u32, index: u16) -> [u8; 8] {
    let s = seq.to_be_bytes();
    let i = index.to_be_bytes();
    [
        RESERVED_PREFIX,
        JOURNAL_TAG,
        s[0],
        s[1],
        s[2],
        s[3],
        i[0],
        i[1],
    ]
}

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
        let n = value.len().min(MAX_VALUE_LEN);
        self.values[slot][..n].copy_from_slice(&value[..n]);
        self.value_lens[slot] = n as u16;
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
    buffer: [u8; JOURNAL_ENTRY_MAX + MAX_KEY_LEN + 32],
    window: ScanWindow<W>,
}

/// Flash-backed key-value store over a NOR flash range.
///
/// Held behind a `RefCell` internally because the trait's read methods
/// take `&self` while the underlying library needs `&mut`; the cell is
/// never held across a call into user code.
pub struct FlashStorage<S: MultiwriteNorFlash, const W: usize = SCAN_WINDOW> {
    inner: RefCell<Inner<S, W>>,
}

impl<S: MultiwriteNorFlash, const W: usize> FlashStorage<S, W> {
    /// Mount a store over `flash_range` of `flash`.
    ///
    /// The range must be page-aligned and at least two pages long;
    /// `sequential-storage` validates that and this constructor
    /// surfaces the failure rather than panicking.
    pub fn mount(flash: S, flash_range: core::ops::Range<u32>) -> Result<Self, ArxiaError> {
        let config = MapConfig::try_new(flash_range).map_err(backend_fault)?;
        let mut store = Self {
            inner: RefCell::new(Inner {
                map: MapStorage::new(flash, config, Cache::new_uncached()),
                buffer: [0u8; JOURNAL_ENTRY_MAX + MAX_KEY_LEN + 32],
                window: ScanWindow::new(),
            }),
        };
        store.recover()?;
        Ok(store)
    }

    /// Read-only access to the underlying flash, for erase accounting
    /// and bench instrumentation.
    pub fn flash(&self) -> core::cell::RefMut<'_, S> {
        core::cell::RefMut::map(self.inner.borrow_mut(), |i| i.map.flash())
    }

    /// Finish or discard any batch interrupted by a power cut.
    ///
    /// Called by [`Self::mount`], so a store is consistent before its
    /// first read. A marker means the batch committed and its journal
    /// must be replayed; a journal without a marker means the batch
    /// never reached its commit point and is discarded.
    fn recover(&mut self) -> Result<(), ArxiaError> {
        match self.fetch_raw(&MARKER_KEY)? {
            Some(b) if b.len() == 6 => {
                let seq = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let count = u16::from_be_bytes([b[4], b[5]]);
                self.replay_journal(seq, count)
            }
            _ => self.discard_journal(),
        }
    }

    /// Apply a committed journal in order, then clear it and the
    /// marker.
    ///
    /// Every entry is applied before any entry is erased. Erasing as
    /// the replay went would lose the batch: a cut after entry 0 was
    /// applied and erased leaves a journal whose first index is absent,
    /// and a replay that stopped at the first gap would call the batch
    /// finished with operations 1 and 2 never applied. That is a
    /// partial batch, which the trait forbids — and it is what the
    /// power-cut sweep caught before this ordering was fixed.
    ///
    /// Both phases are idempotent: re-applying a put or a delete
    /// reaches the same state, and erasing an absent key is not an
    /// error. The marker goes last, so while it exists recovery
    /// repeats, and a cut anywhere inside recovery simply replays.
    fn replay_journal(&mut self, seq: u32, count: u16) -> Result<(), ArxiaError> {
        for index in 0..count {
            let jkey = journal_key(seq, index);
            if let Some(entry) = self.fetch_raw(&jkey)? {
                apply_encoded_op(self, &entry)?;
            }
        }
        for index in 0..count {
            self.erase(&journal_key(seq, index))?;
        }
        self.erase(&MARKER_KEY)?;
        Ok(())
    }

    /// Remove journal entries left by a batch that never committed.
    fn discard_journal(&mut self) -> Result<(), ArxiaError> {
        let mut stale: Vec<[u8; 8]> = Vec::new();
        {
            let mut inner = self.inner.borrow_mut();
            let Inner { map, buffer, .. } = &mut *inner;
            let mut iter_buffer = [0u8; JOURNAL_ENTRY_MAX + MAX_KEY_LEN + 32];
            let mut iter =
                poll_once(map.fetch_all_items(&mut iter_buffer))?.map_err(backend_fault)?;
            while let Some((key, _)) =
                poll_once(iter.next::<&[u8]>(buffer))?.map_err(backend_fault)?
            {
                let k = key.as_slice();
                if k.len() == 8 && k[0] == RESERVED_PREFIX && k[1] == JOURNAL_TAG {
                    let mut owned = [0u8; 8];
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

    /// The next batch sequence: one past whatever the marker last
    /// named, so a replayed journal never collides with a new one.
    fn next_sequence(&self) -> Result<u32, ArxiaError> {
        Ok(match self.fetch_raw(&MARKER_KEY)? {
            Some(b) if b.len() >= 4 => u32::from_be_bytes([b[0], b[1], b[2], b[3]]).wrapping_add(1),
            _ => 1,
        })
    }

    /// Consume the store and return the flash, so a caller can
    /// remount the same medium — which is what a board does when power
    /// comes back.
    pub fn into_flash(self) -> S {
        self.inner.into_inner().map.destroy().0
    }

    /// Read a user key. Journal bookkeeping is invisible here, exactly
    /// as it is to a scan: a failed batch may leave entries behind
    /// until the next mount discards them, and no reader may see them.
    fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        reject_reserved(key)?;
        self.fetch_raw(key)
    }

    /// Presence without materialising the value: `delete` and
    /// `contains` only need the answer, and a 193-byte block copied
    /// onto the heap to be dropped immediately is waste a 520 KB
    /// device notices.
    fn exists(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        reject_reserved(key)?;
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        let found = poll_once(map.fetch_item::<&[u8]>(buffer, &k))?.map_err(backend_fault)?;
        Ok(found.is_some())
    }

    fn fetch_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        let k = FlashKey::new(key)?;
        let mut inner = self.inner.borrow_mut();
        let Inner { map, buffer, .. } = &mut *inner;
        let found = poll_once(map.fetch_item::<&[u8]>(buffer, &k))?.map_err(backend_fault)?;
        Ok(found.map(|v| v.to_vec()))
    }

    /// Store a user value: the payload cap and the reserved-namespace
    /// rule both apply here, and only here.
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
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
    fn store_raw(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        let k = FlashKey::new(key)?;
        let inner = self.inner.get_mut();
        let Inner { map, buffer, .. } = inner;
        poll_once(map.store_item(buffer, &k, &value))?.map_err(backend_fault)
    }

    fn erase(&mut self, key: &[u8]) -> Result<(), ArxiaError> {
        let k = FlashKey::new(key)?;
        let inner = self.inner.get_mut();
        let Inner { map, buffer, .. } = inner;
        poll_once(map.remove_item(buffer, &k))?.map_err(backend_fault)
    }
}

impl<S: MultiwriteNorFlash, const W: usize> StorageBackend for FlashStorage<S, W> {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        self.store(key, value)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        self.fetch(key)
    }

    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
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

                let mut iter_buffer = [0u8; JOURNAL_ENTRY_MAX + MAX_KEY_LEN + 32];
                let mut iter =
                    poll_once(map.fetch_all_items(&mut iter_buffer))?.map_err(backend_fault)?;
                while let Some((key, value)) =
                    poll_once(iter.next::<&[u8]>(buffer))?.map_err(backend_fault)?
                {
                    if key.as_slice().first() == Some(&RESERVED_PREFIX) {
                        continue; // journal bookkeeping is not user data
                    }
                    if !key.as_slice().starts_with(prefix) {
                        continue;
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

            for (k, v) in &batch {
                if !visit(k, v) {
                    return Ok(());
                }
            }
            last_emitted = Some(final_key);
        }
    }

    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        if ops.is_empty() {
            return Ok(());
        }
        if ops.len() > u16::MAX as usize {
            return Err(capacity(
                CapacityKind::BatchOperations,
                ops.len(),
                u16::MAX as usize,
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

        // A marker still on flash means an earlier batch committed but
        // its replay did not finish - a transient failure, or a cut.
        // Writing a new marker over it would strand that batch half
        // applied for ever, so it is finished first. If it cannot be
        // finished, this batch does not start.
        self.recover()?;

        let seq = self.next_sequence()?;

        // Step 1: journal every operation.
        let mut encoded = [0u8; JOURNAL_ENTRY_MAX];
        for (index, op) in ops.iter().enumerate() {
            let n = encode_op(op, &mut encoded);
            self.store_raw(&journal_key(seq, index as u16), &encoded[..n])?;
        }

        // Step 2: the commit point. Before this single write the batch
        // does not exist; after it, the batch is guaranteed to land.
        // The marker carries the operation count as well as the
        // sequence: replay must know how many entries the batch had,
        // because it cannot infer that from what is still on flash.
        let count = ops.len() as u16;
        let mut marker = [0u8; 6];
        marker[..4].copy_from_slice(&seq.to_be_bytes());
        marker[4..].copy_from_slice(&count.to_be_bytes());
        self.store_raw(&MARKER_KEY, &marker)?;

        // Steps 3 and 4.
        self.replay_journal(seq, count)
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

/// Apply a journalled operation to its real key.
fn apply_encoded_op<S: MultiwriteNorFlash, const W: usize>(
    store: &mut FlashStorage<S, W>,
    entry: &[u8],
) -> Result<(), ArxiaError> {
    if entry.len() < 2 {
        return Err(backend_fault("journal entry truncated"));
    }
    let key_len = entry[1] as usize;
    if entry.len() < 2 + key_len {
        return Err(backend_fault("journal entry key truncated"));
    }
    let key = &entry[2..2 + key_len];
    match entry[0] {
        OP_PUT => store.store(key, &entry[2 + key_len..]),
        OP_DELETE => {
            // A delete of an absent key is not an error, and replay
            // may well hit exactly that case.
            let _ = store.erase(key);
            Ok(())
        }
        _ => Err(backend_fault("journal entry has an unknown op tag")),
    }
}
