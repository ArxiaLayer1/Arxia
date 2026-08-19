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

/// Size of a bench block value: the compact block, 193 bytes.
pub const BLOCK_LEN: usize = 193;
/// Size of a bench index value.
pub const INDEX_LEN: usize = 32;

/// One bench batch: two blocks and an index entry, all tagged with the
/// same sequence.
///
/// Keys are derived from the sequence so every batch has its own; the
/// store therefore grows with traffic exactly as a ledger does, and
/// the log's dead-version growth - the `n_log` term the endurance
/// model tracks - is exercised for real.
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
        Self {
            seq,
            keys: [chain_key(seq, 0), chain_key(seq, 1), index_key(seq)],
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

/// A chain key for `seq`, block `n`: `c:` + a 64-hex-char account
/// derived from the sequence + `:` + the block index. Protocol-sized,
/// like the conformance fixture's.
pub fn chain_key(seq: u32, n: u8) -> Vec<u8> {
    let mut k = Vec::with_capacity(72);
    k.extend_from_slice(CHAIN_PREFIX);
    let hex = b"0123456789abcdef";
    // 64 hex chars: the sequence spread across them so keys differ,
    // deterministic so the audit can recompute them.
    for i in 0..64u32 {
        let nibble = (seq.wrapping_mul(0x9E37_79B9).rotate_left(i % 32) >> (i % 28)) & 0xF;
        k.push(hex[nibble as usize]);
    }
    k.push(b':');
    k.extend_from_slice(&seq.to_be_bytes());
    k.push(n);
    k
}

/// The index key for `seq`.
pub fn index_key(seq: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(8);
    k.extend_from_slice(INDEX_PREFIX);
    k.extend_from_slice(&seq.to_be_bytes());
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
    /// Distinct sequences seen under the batch prefixes.
    pub sequences_seen: usize,
    /// Sequences whose three keys all carry the exact tagged bytes.
    pub complete: usize,
    /// Sequences with some but not all keys carrying the new state -
    /// the state the seal exists to forbid.
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
    /// A sequence has some but not all of its keys - partial batch.
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
/// The walk is one scan per prefix; the per-sequence check recomputes
/// the expected keys and values from the sequence alone and compares
/// byte for byte, so a value that carries the right tag but the wrong
/// body counts as partial. A key that parses to no sequence (foreign,
/// or from another bench build) is counted as seen-but-unjudged rather
/// than partial: the audit judges bench batches, and refuses to call
/// something it did not write a failure of the seal.
pub fn audit<S: MultiwriteNorFlash, const W: usize>(
    store: &FlashStorage<S, W>,
) -> Result<AuditReport, ArxiaError> {
    let mut seqs: Vec<u32> = Vec::new();
    let mut reserved_visible = 0usize;
    for prefix in [CHAIN_PREFIX, INDEX_PREFIX] {
        store.scan_prefix(prefix, &mut |k, v| {
            if k.first() == Some(&0x00) {
                reserved_visible += 1;
                return true;
            }
            if let Some(seq) = tag_of(v) {
                if !seqs.contains(&seq) {
                    seqs.push(seq);
                }
            }
            true
        })?;
    }
    // A reserved key can never match a bench prefix, but the walk over
    // the empty prefix is what the protocol literally says: no key
    // under 0x00 visible to the audit walk.
    store.scan_prefix(b"", &mut |k, _| {
        if k.first() == Some(&0x00) {
            reserved_visible += 1;
        }
        true
    })?;

    let mut complete = 0usize;
    let mut partial: Vec<u32> = Vec::new();
    let mut highest_complete: Option<u32> = None;
    for &seq in &seqs {
        let expected = BenchBatch::new(seq);
        let mut present = 0u8;
        for (key, value) in expected.keys.iter().zip(expected.values.iter()) {
            match store.get(key)? {
                Some(got) if got == *value => present += 1,
                Some(_) => {
                    // A key that exists with other bytes: it belongs
                    // to this sequence by tag but not by body - partial
                    // by the strictest reading, which is the one the
                    // seal must satisfy.
                }
                None => {}
            }
        }
        if present == 3 {
            complete += 1;
            highest_complete = Some(highest_complete.map_or(seq, |h| h.max(seq)));
        } else if present > 0 {
            partial.push(seq);
        }
    }

    let persisted_high_water = store.get(HIGH_WATER_KEY)?.and_then(|v| tag_of(&v));

    Ok(AuditReport {
        sequences_seen: seqs.len(),
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
        "AUDIT seen={} complete={} partial={} reserved_visible={} highest={} persisted={} verdict=",
        report.sequences_seen,
        report.complete,
        report.partial.len(),
        report.reserved_visible,
        report.highest_complete.map_or(-1i64, i64::from),
        report.persisted_high_water.map_or(-1i64, i64::from),
    )?;
    match report.verdict() {
        Verdict::Pass => writeln!(out, "PASS"),
        Verdict::PartialBatch => writeln!(out, "FAIL:partial_batch seqs={:?}", report.partial),
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
