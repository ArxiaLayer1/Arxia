//! The power-loss bench protocol for the flash backend, as code.
//!
//! `docs/architecture/POWER_LOSS_PROTOCOL.md` fixes what the plug-pull
//! bench does and what counts as failure. This crate is that protocol
//! made executable, in the only place it can be held to the same
//! standard as the backend it judges: a `no_std` library, generic over
//! the flash driver and the output sink, testable on a host against
//! the same fault-injecting mock the backend's own suite uses, and
//! compiled for the bare-metal target by the same CI job.
//!
//! The firmware that runs on the board is a thin adapter around this
//! crate: it supplies the flash driver and a serial sink, then calls
//! [`boot`]. Every decision - the shape of a batch, the sequence tag
//! inside every value, the audit walk, the failure criteria - lives
//! here, where it can be reviewed and mutated, not in board code.
//!
//! # The three things the protocol asks of the firmware
//!
//! **Tagged batches.** Every value the bench writes carries the batch's
//! sequence number in its first four bytes, big-endian; the store
//! itself has no sequence facility. A batch is two protocol-sized
//! blocks under chain keys plus one index entry - the same shape as
//! the shared conformance fixture - so the bench measures the seal on
//! the traffic it exists for.
//!
//! **The boot-time audit, before any traffic.** Mount; walk every key
//! under the bench prefixes; for every sequence present, all three
//! keys must carry that sequence's bytes exactly, or the batch is
//! partial; no reserved-namespace key may be visible; the highest
//! complete sequence must not be lower than the one persisted before
//! the cut. Each of those is a failure criterion of the protocol, in
//! code, and the audit report names which one fired.
//!
//! **Counters.** The adapter wraps the driver in a counting shim and
//! the loop reports erases, writes and reads periodically, so the
//! endurance model meets its numbers.
//!
//! # Bounded slots, unbounded run
//!
//! Batch keys rotate over a bounded window of [`SLOTS`] slots
//! (`slot = seq % SLOTS`) while values stay tagged with the full,
//! monotonically increasing sequence. Per-sequence keys would only
//! append: the live set would grow by roughly a kibibyte per batch
//! until the region returned `FullStorage` a few minutes in - and an
//! append-only bench barely touches page reclamation, which is the
//! wear mechanism the endurance model prices in wraps. Rotation keeps
//! the live set tens of times smaller than the region, so the log
//! wraps and reclaims indefinitely, and the seal is what makes the
//! rotation sound: a slot overwrite is one batch, so a cut leaves the
//! slot wholly on its old sequence or wholly on its new one, never
//! mixed - and the audit checks exactly that.
//!
//! # What "highest sequence never decreases" needs
//!
//! The firmware loses RAM at every cut, so "recorded before" must be
//! on the medium: the bench persists its own high-water mark under a
//! dedicated key after every successful batch, and the audit compares
//! against it. The serial line carries the same number so an operator
//! logging boots can cross-check off-device, as the protocol says.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write;

use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::{BatchOp, StorageBackend};
use arxia_storage_flash::{FlashStorage, MountFailure};
use embedded_storage_async::nor_flash::MultiwriteNorFlash;

/// Prefix of the two chain keys a bench batch writes.
pub const CHAIN_PREFIX: &[u8] = b"c:";
/// Prefix of the index entry a bench batch writes.
pub const INDEX_PREFIX: &[u8] = b"s:";
/// The bench's own bookkeeping: the persisted high-water mark of
/// completed sequences. Outside the store's reserved namespace, and
/// outside every prefix the audit walks as batch data.
pub const HIGH_WATER_KEY: &[u8] = b"b:high";

/// The rotation window: how many distinct key sets the bench rewrites.
///
/// The live set is `SLOTS` batches plus the high-water mark; with
/// protocol-sized values that is a few tens of kibibytes against a
/// region of a mebibyte, which leaves the engine a deep log to wrap
/// through - reclamation traffic, not just storage.
pub const SLOTS: u32 = 64;

/// The slot a sequence lands in.
pub const fn slot_of(seq: u32) -> u32 {
    seq % SLOTS
}

/// Size of a bench block value: the compact block, 193 bytes.
pub const BLOCK_LEN: usize = 193;
/// Size of a bench index value.
pub const INDEX_LEN: usize = 32;

/// One bench batch: two blocks and an index entry, all tagged with the
/// same sequence.
///
/// Keys derive from the batch's SLOT ([`slot_of`]), values from the
/// full sequence: sequence `s` and `s + SLOTS` write the same three
/// keys with different bytes. The overwrite is one batch, so the seal
/// makes it atomic under a cut.
pub struct BenchBatch {
    /// The sequence this batch carries.
    pub seq: u32,
    /// The three keys, in the order the batch writes them.
    pub keys: [Vec<u8>; 3],
    /// The three values, sequence-tagged.
    pub values: [Vec<u8>; 3],
}

impl BenchBatch {
    /// Build the batch for `seq`.
    pub fn new(seq: u32) -> Self {
        let slot = slot_of(seq);
        Self {
            seq,
            keys: [chain_key(slot, 0), chain_key(slot, 1), index_key(slot)],
            values: [
                tagged_value(seq, BLOCK_LEN, 0x10),
                tagged_value(seq, BLOCK_LEN, 0x20),
                tagged_value(seq, INDEX_LEN, 0x30),
            ],
        }
    }

    /// The batch as operations, borrowing this batch.
    pub fn ops(&self) -> [BatchOp<'_>; 3] {
        [
            BatchOp::Put {
                key: &self.keys[0],
                value: &self.values[0],
            },
            BatchOp::Put {
                key: &self.keys[1],
                value: &self.values[1],
            },
            BatchOp::Put {
                key: &self.keys[2],
                value: &self.values[2],
            },
        ]
    }
}

/// A chain key for `slot`, block `n`: `c:` + a 64-hex-char account
/// derived from the slot + `:` + the block index. Protocol-sized,
/// like the conformance fixture's.
pub fn chain_key(slot: u32, n: u8) -> Vec<u8> {
    let mut k = Vec::with_capacity(72);
    k.extend_from_slice(CHAIN_PREFIX);
    let hex = b"0123456789abcdef";
    // 64 hex chars: the slot spread across them so keys differ,
    // deterministic so the audit can recompute them.
    for i in 0..64u32 {
        let nibble = (slot.wrapping_mul(0x9E37_79B9).rotate_left(i % 32) >> (i % 28)) & 0xF;
        k.push(hex[nibble as usize]);
    }
    k.push(b':');
    k.extend_from_slice(&slot.to_be_bytes());
    k.push(n);
    k
}

/// The index key for `slot`.
pub fn index_key(slot: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(8);
    k.extend_from_slice(INDEX_PREFIX);
    k.extend_from_slice(&slot.to_be_bytes());
    k
}

/// A value of `len` bytes tagged with `seq`: the sequence big-endian
/// in the first four bytes, then a deterministic fill derived from the
/// sequence and `salt` - so a torn or mixed value is detectable byte
/// for byte, not just by its tag.
pub fn tagged_value(seq: u32, len: usize, salt: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&seq.to_be_bytes());
    let mut x = seq ^ (u32::from(salt) << 24) ^ 0xA5A5_5A5A;
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push((x & 0xFF) as u8);
    }
    v
}

/// The sequence tag of a value, if it has one.
pub fn tag_of(value: &[u8]) -> Option<u32> {
    if value.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

/// What the boot-time audit found. Every field maps to a line of the
/// protocol; [`AuditReport::verdict`] maps to its failure criteria.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// Slots holding any data at all.
    pub slots_occupied: usize,
    /// Slots whose three keys all carry one sequence's exact bytes.
    pub complete: usize,
    /// Slots in any other occupied state - a missing key, a foreign
    /// or mixed tag, a wrong body: the states the seal exists to
    /// forbid, identified by slot index.
    pub partial: Vec<u32>,
    /// Keys visible to the walk that begin with the reserved byte.
    pub reserved_visible: usize,
    /// The highest complete sequence found on the medium.
    pub highest_complete: Option<u32>,
    /// The high-water mark persisted before this boot, if any.
    pub persisted_high_water: Option<u32>,
}

/// The audit's verdict, one variant per protocol failure criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every criterion held.
    Pass,
    /// A slot holds a torn state: a missing key, a mixed or foreign
    /// tag, or a wrong body - partial batch.
    PartialBatch,
    /// A reserved-namespace key reached the audit walk.
    ReservedVisible,
    /// The highest complete sequence is lower than the persisted
    /// high-water mark - a committed batch was lost.
    CommittedBatchLost,
}

impl AuditReport {
    /// The verdict, by the protocol's criteria, worst first.
    pub fn verdict(&self) -> Verdict {
        if !self.partial.is_empty() {
            return Verdict::PartialBatch;
        }
        if self.reserved_visible > 0 {
            return Verdict::ReservedVisible;
        }
        if let (Some(high), Some(persisted)) = (self.highest_complete, self.persisted_high_water) {
            if high < persisted {
                return Verdict::CommittedBatchLost;
            }
        }
        if self.highest_complete.is_none() && self.persisted_high_water.is_some() {
            return Verdict::CommittedBatchLost;
        }
        Verdict::Pass
    }
}

/// Walk the store and judge it. Runs on every boot BEFORE any traffic.
///
/// The walk over the empty prefix is what the protocol literally
/// says: no key under the reserved `0x00` namespace visible to the
/// audit. The slots are then judged by direct reads: each occupied
/// slot must hold ONE sequence's three exact values - the sequence
/// claimed by the newest tag any of its keys carries, and that
/// sequence must map to this slot. A missing key, a mixed or foreign
/// tag, or a wrong body all make the slot partial: under the seal a
/// slot is wholly on its old sequence or wholly on its new one, and
/// anything else is the torn state the bench exists to detect.
pub fn audit<S: MultiwriteNorFlash, const W: usize>(
    store: &FlashStorage<S, W>,
) -> Result<AuditReport, ArxiaError> {
    let mut reserved_visible = 0usize;
    store.scan_prefix(b"", &mut |k, _| {
        if k.first() == Some(&0x00) {
            reserved_visible += 1;
        }
        true
    })?;

    let mut slots_occupied = 0usize;
    let mut complete = 0usize;
    let mut partial: Vec<u32> = Vec::new();
    let mut highest_complete: Option<u32> = None;
    for slot in 0..SLOTS {
        let keys = [chain_key(slot, 0), chain_key(slot, 1), index_key(slot)];
        let values = [
            store.get(&keys[0])?,
            store.get(&keys[1])?,
            store.get(&keys[2])?,
        ];
        if values.iter().all(|v| v.is_none()) {
            continue;
        }
        slots_occupied += 1;
        // The sequence this slot claims: the newest tag on any of its
        // keys - under a torn overwrite, the batch being judged.
        let claimed = values.iter().flatten().filter_map(|v| tag_of(v)).max();
        let coherent = match claimed {
            Some(seq) if slot_of(seq) == slot => {
                let expected = BenchBatch::new(seq);
                values
                    .iter()
                    .zip(expected.values.iter())
                    .all(|(got, want)| got.as_deref() == Some(want.as_slice()))
            }
            // A tag that does not belong to this slot never came from
            // the bench's write path: corruption, judged partial.
            _ => false,
        };
        if coherent {
            complete += 1;
            let seq = claimed.expect("coherent implies a claimed sequence");
            highest_complete = Some(highest_complete.map_or(seq, |h| h.max(seq)));
        } else {
            partial.push(slot);
        }
    }

    let persisted_high_water = store.get(HIGH_WATER_KEY)?.and_then(|v| tag_of(&v));

    Ok(AuditReport {
        slots_occupied,
        complete,
        partial,
        reserved_visible,
        highest_complete,
        persisted_high_water,
    })
}

/// Write the audit report as one parseable serial line.
pub fn report_audit<O: Write>(out: &mut O, report: &AuditReport) -> core::fmt::Result {
    write!(
        out,
        "AUDIT slots={} complete={} partial={} reserved_visible={} highest={} persisted={} verdict=",
        report.slots_occupied,
        report.complete,
        report.partial.len(),
        report.reserved_visible,
        report.highest_complete.map_or(-1i64, i64::from),
        report.persisted_high_water.map_or(-1i64, i64::from),
    )?;
    match report.verdict() {
        Verdict::Pass => writeln!(out, "PASS"),
        Verdict::PartialBatch => writeln!(out, "FAIL:partial_batch slots={:?}", report.partial),
        Verdict::ReservedVisible => writeln!(out, "FAIL:reserved_visible"),
        Verdict::CommittedBatchLost => writeln!(out, "FAIL:committed_batch_lost"),
    }
}

/// The class of one batch's outcome, as the serial line names it. The
/// three classes of the trait contract, plus the ordinary refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// Applied in full.
    Ok,
    /// Past its commit point; will apply on the next access.
    Committed,
    /// Commit could not be verified; the next access converges.
    Uncertain,
    /// Never happened.
    Refused,
}

/// Classify an `apply_batch` result by the trait's three-class contract.
pub fn classify(result: &Result<(), ArxiaError>) -> BatchOutcome {
    match result {
        Ok(()) => BatchOutcome::Ok,
        Err(ArxiaError::Storage {
            fault: StorageFault::BatchCommitted,
        }) => BatchOutcome::Committed,
        Err(ArxiaError::Storage {
            fault: StorageFault::CommitUncertain,
        }) => BatchOutcome::Uncertain,
        Err(_) => BatchOutcome::Refused,
    }
}

/// Run one batch: apply, then - on `Ok` - persist the high-water mark.
///
/// The high-water write is a separate `put` AFTER the batch reports
/// success: a cut between the two leaves a complete batch whose
/// sequence is above the persisted mark, which the audit accepts (the
/// mark is a floor, never a ceiling). Persisting it inside the batch
/// would tie the bench's bookkeeping to the seal it is measuring.
pub fn run_one<S: MultiwriteNorFlash, const W: usize, O: Write>(
    store: &mut FlashStorage<S, W>,
    out: &mut O,
    seq: u32,
) -> BatchOutcome {
    let batch = BenchBatch::new(seq);
    let result = store.apply_batch(&batch.ops());
    let outcome = classify(&result);
    let _ = match outcome {
        BatchOutcome::Ok => writeln!(out, "BATCH seq={seq} ok"),
        BatchOutcome::Committed => writeln!(out, "BATCH seq={seq} committed"),
        BatchOutcome::Uncertain => writeln!(out, "BATCH seq={seq} uncertain"),
        BatchOutcome::Refused => writeln!(out, "BATCH seq={seq} refused"),
    };
    if outcome == BatchOutcome::Ok {
        // Best effort: a failed high-water write only lowers the floor
        // the next audit compares against, never raises it.
        let _ = store.put(HIGH_WATER_KEY, &seq.to_be_bytes());
    }
    outcome
}

/// What a boot decides after the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDecision {
    /// Audit passed; traffic resumes from `next_seq`.
    Resume {
        /// The first sequence the resumed loop should write.
        next_seq: u32,
    },
    /// Audit failed; the run stops here, as the protocol requires,
    /// until the failure is attributed. No traffic.
    Halt(Verdict),
}

/// The protocol's boot: mount, audit, report, decide. Traffic never
/// starts before the audit line is written.
///
/// A mount failure is itself a protocol failure ("an unmountable
/// store"), reported as such; the flash driver comes back to the
/// caller with it, per the backend's contract.
pub fn boot<S: MultiwriteNorFlash, O: Write>(
    flash: S,
    range: core::ops::Range<u32>,
    out: &mut O,
) -> Result<(FlashStorage<S>, BootDecision), MountFailure<S>> {
    let store = match FlashStorage::<S>::mount(flash, range) {
        Ok(s) => s,
        Err(f) => {
            let _ = writeln!(out, "AUDIT verdict=FAIL:unmountable error={}", f.error);
            return Err(f);
        }
    };
    let report = match audit(&store) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(out, "AUDIT verdict=FAIL:audit_error error={e}");
            return Ok((store, BootDecision::Halt(Verdict::PartialBatch)));
        }
    };
    let _ = report_audit(out, &report);
    let decision = match report.verdict() {
        Verdict::Pass => BootDecision::Resume {
            next_seq: report.highest_complete.map_or(0, |h| h.wrapping_add(1)),
        },
        v => BootDecision::Halt(v),
    };
    Ok((store, decision))
}
