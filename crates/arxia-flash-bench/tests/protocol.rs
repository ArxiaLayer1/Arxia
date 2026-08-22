//! The bench protocol, held to its own criteria on a host.
//!
//! The same fault-injecting mock the flash backend's suite uses drives
//! these: batches run, power is cut or the driver lies at chosen
//! points, the board "reboots" (remount + audit), and the audit must
//! say exactly what the protocol says - PASS when the seal held, and
//! the named FAIL criterion when it did not. A protocol that cannot
//! fail is not a protocol; several fixtures plant the failure states
//! directly and require the audit to name them.
//!
//! The rotation is walked with the same rigor: sequence `s + SLOTS`
//! rewrites sequence `s`'s keys, and a cut at every write position of
//! that overwrite must leave the slot wholly old or wholly new.

use arxia_flash_bench::{
    audit, boot, report_audit, run_one, slot_of, tag_of, AuditReport, BatchOutcome, BenchBatch,
    BootDecision, Verdict, HIGH_WATER_KEY, SLOTS,
};
use arxia_storage::StorageBackend;
use arxia_storage_flash::testing::{FaultyFlash, RANGE};

/// A String is a fine serial line on a host.
fn sink() -> String {
    String::new()
}

// ------------------------------------------------------ the batch itself

/// Every value the bench writes carries its sequence; sequences in
/// different slots have disjoint keys; and a sequence one rotation
/// later writes the SAME keys with different bytes - the properties
/// the slot audit depends on.
#[test]
fn values_carry_their_sequence_and_keys_rotate_over_slots() {
    let a = BenchBatch::new(7);
    let b = BenchBatch::new(8);
    let a_next_lap = BenchBatch::new(7 + SLOTS);
    for v in &a.values {
        assert_eq!(tag_of(v), Some(7));
    }
    for v in &a_next_lap.values {
        assert_eq!(tag_of(v), Some(7 + SLOTS));
    }
    for ka in &a.keys {
        for kb in &b.keys {
            assert_ne!(ka, kb, "different slots, disjoint keys");
        }
    }
    assert_eq!(
        a.keys, a_next_lap.keys,
        "one rotation later, the same keys are rewritten"
    );
    assert_ne!(
        a.values, a_next_lap.values,
        "with that sequence's own bytes"
    );
    assert_eq!(slot_of(7 + SLOTS), slot_of(7));
    assert_eq!(a.values[0].len(), 193, "blocks are protocol-sized");
    assert!(a.keys[0].len() <= 96, "chain keys fit the backend's bound");
    // Deterministic: the audit recomputes the batch from the sequence.
    assert_eq!(BenchBatch::new(7).values, a.values);
    assert_eq!(BenchBatch::new(7).keys, a.keys);
}

// -------------------------------------------- the audit on clean state

/// A fresh store passes; a store with completed batches passes and
/// reports the highest sequence, which the boot resumes after.
#[test]
fn a_clean_run_passes_and_resumes_after_the_highest_sequence() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    let mut out = sink();

    let (mut store, decision) = boot(flash, RANGE, &mut out).expect("mount");
    assert_eq!(decision, BootDecision::Resume { next_seq: 0 });
    assert!(out.contains("verdict=PASS"), "{out}");

    for seq in 0..5 {
        assert_eq!(run_one(&mut store, &mut out, seq), BatchOutcome::Ok);
    }
    let report = audit(&store).unwrap();
    assert_eq!(report.slots_occupied, 5);
    assert_eq!(report.complete, 5);
    assert!(report.partial.is_empty());
    assert_eq!(report.highest_complete, Some(4));
    assert_eq!(report.persisted_high_water, Some(4));
    assert_eq!(report.verdict(), Verdict::Pass);

    // "Reboot": the same medium, a fresh mount, the audit first.
    drop(store);
    let mut out = sink();
    let (_store, decision) = boot(handle, RANGE, &mut out).expect("remount");
    assert_eq!(decision, BootDecision::Resume { next_seq: 5 });
    assert!(out.contains("verdict=PASS"), "{out}");
    assert!(
        !out.contains("BATCH"),
        "no traffic line before the audit line"
    );
}

// --------------------------------------- the seal under power cuts

/// Power cut at every write of a batch, then reboot: the audit passes
/// at every cut point, because the seal leaves all-or-nothing and the
/// audit's criteria are exactly all-or-nothing.
#[test]
fn a_cut_at_every_write_position_still_audits_pass() {
    // Measure a batch's write cost on this store.
    let total = {
        let flash = FaultyFlash::healthy();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        const PROBE: usize = 1_000_000;
        store.flash_mut().skip.set(PROBE);
        run_one(&mut store, &mut out, 1);
        let left = store.flash_mut().skip.get();
        PROBE - left
    };
    assert!(total > 5, "a batch must cost several writes to sweep");

    for budget in 0..=total {
        let flash = FaultyFlash::healthy();
        let handle = flash.clone();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        store.flash_mut().arm_cut(budget);
        let _ = run_one(&mut store, &mut out, 1); // may fail; that is the point
        drop(store);

        // Power returns; the board boots and audits before anything.
        handle.heal();
        let mut out = sink();
        let (store, decision) = boot(handle, RANGE, &mut out).expect("a cut must not brick");
        let report = audit(&store).unwrap();
        assert_eq!(report.verdict(), Verdict::Pass, "budget {budget}: {out}");
        // Sequence 0 always survives; sequence 1 is complete or absent.
        assert!(report.complete >= 1);
        assert!(
            report.partial.is_empty(),
            "budget {budget}: partial {:?}",
            report.partial
        );
        match decision {
            BootDecision::Resume { next_seq } => assert!(next_seq == 1 || next_seq == 2),
            other => panic!("budget {budget}: {other:?}"),
        }
    }
}

/// The rotation's own sweep: sequence `SLOTS` overwrites sequence 0's
/// keys, and a cut at every write position of that overwrite leaves
/// the slot wholly on one sequence - old bytes with the old tag, or
/// new bytes with the new tag, never a mixture. This is the fixture
/// that makes the rotation a sound bench shape rather than a wish.
#[test]
fn a_slot_overwrite_is_atomic_at_every_cut_position() {
    let total = {
        let flash = FaultyFlash::healthy();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        const PROBE: usize = 1_000_000;
        store.flash_mut().skip.set(PROBE);
        run_one(&mut store, &mut out, SLOTS);
        let left = store.flash_mut().skip.get();
        PROBE - left
    };

    for budget in 0..=total {
        let flash = FaultyFlash::healthy();
        let handle = flash.clone();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        store.flash_mut().arm_cut(budget);
        let _ = run_one(&mut store, &mut out, SLOTS);
        drop(store);

        handle.heal();
        let (store, _) = boot(handle, RANGE, &mut sink()).expect("a cut must not brick");
        let report = audit(&store).unwrap();
        assert_eq!(
            report.verdict(),
            Verdict::Pass,
            "budget {budget}: {report:?}"
        );
        assert_eq!(report.slots_occupied, 1, "budget {budget}");
        assert_eq!(report.complete, 1, "budget {budget}");
        assert!(
            report.highest_complete == Some(0) || report.highest_complete == Some(SLOTS),
            "budget {budget}: wholly old or wholly new, got {:?}",
            report.highest_complete
        );
    }
}

/// A landed overwrite supersedes: one slot occupied, complete, and the
/// highest sequence is the new lap's - the store did not grow.
#[test]
fn a_landed_overwrite_supersedes_its_slot() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    assert_eq!(run_one(&mut store, &mut out, 0), BatchOutcome::Ok);
    assert_eq!(run_one(&mut store, &mut out, SLOTS), BatchOutcome::Ok);

    let report = audit(&store).unwrap();
    assert_eq!(report.slots_occupied, 1, "same keys, not new ones");
    assert_eq!(report.complete, 1);
    assert_eq!(report.highest_complete, Some(SLOTS));
    assert_eq!(report.persisted_high_water, Some(SLOTS));
    assert_eq!(report.verdict(), Verdict::Pass);
}

// ------------------------------- the criteria, each one made to fire

/// A partial batch - planted directly, since the seal never produces
/// one - is named by the audit. This is the failure the whole bench
/// exists to detect; an audit that could not see it would be
/// worthless.
#[test]
fn a_planted_partial_batch_fails_the_audit_by_name() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);

    // Write two of sequence 1's three keys through plain puts: the
    // state a torn seal would leave in slot 1.
    let b = BenchBatch::new(1);
    store.put(&b.keys[0], &b.values[0]).unwrap();
    store.put(&b.keys[2], &b.values[2]).unwrap();

    let report = audit(&store).unwrap();
    assert_eq!(report.partial, vec![1]);
    assert_eq!(report.verdict(), Verdict::PartialBatch);
    let mut line = sink();
    report_audit(&mut line, &report).unwrap();
    assert!(line.contains("FAIL:partial_batch"), "{line}");
}

/// A torn OVERWRITE - one key already on the new lap, the others still
/// on the old - is the rotation's partial state, and the audit names
/// it even though every individual value is a perfectly valid batch
/// fragment.
#[test]
fn a_mixed_lap_slot_is_partial() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);

    // One key of slot 0 jumps to the next lap by a plain put.
    let next = BenchBatch::new(SLOTS);
    store.put(&next.keys[1], &next.values[1]).unwrap();

    let report = audit(&store).unwrap();
    assert_eq!(report.partial, vec![0]);
    assert_eq!(report.verdict(), Verdict::PartialBatch);
}

/// A value carrying the right tag but the wrong body is partial too:
/// the audit compares byte for byte, not tag for tag.
#[test]
fn a_right_tag_wrong_body_value_is_partial() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);

    // Corrupt one value of sequence 0 in place: same tag, one body
    // byte flipped.
    let b = BenchBatch::new(0);
    let mut bad = b.values[1].clone();
    bad[100] ^= 0xFF;
    store.put(&b.keys[1], &bad).unwrap();

    let report = audit(&store).unwrap();
    assert_eq!(report.partial, vec![0]);
    assert_eq!(report.verdict(), Verdict::PartialBatch);
}

/// A slot whose values claim a sequence belonging to a DIFFERENT slot
/// never came from the bench's write path: partial, not complete -
/// even when the values themselves are internally coherent.
#[test]
fn a_slot_carrying_a_foreign_sequence_is_partial() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");

    // Slot 0's keys, sequence 1's values (slot_of(1) == 1, not 0).
    let keys = BenchBatch::new(0).keys;
    let foreign = BenchBatch::new(1).values;
    for (k, v) in keys.iter().zip(foreign.iter()) {
        store.put(k, v).unwrap();
    }

    let report = audit(&store).unwrap();
    assert_eq!(report.partial, vec![0]);
    assert_eq!(report.complete, 0);
    assert_eq!(report.verdict(), Verdict::PartialBatch);
}

/// A committed batch that vanished - the persisted high-water mark
/// above what the medium holds - is named. Planted by deleting a
/// completed batch's keys after the mark was written.
#[test]
fn a_lost_committed_batch_fails_the_audit_by_name() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);
    run_one(&mut store, &mut out, 1);
    assert_eq!(
        store.get(HIGH_WATER_KEY).unwrap().and_then(|v| tag_of(&v)),
        Some(1)
    );

    // Sequence 1 disappears entirely (all three keys), mark stays.
    let b = BenchBatch::new(1);
    for k in &b.keys {
        store.delete(k).unwrap();
    }
    let report = audit(&store).unwrap();
    assert_eq!(report.highest_complete, Some(0));
    assert_eq!(report.persisted_high_water, Some(1));
    assert_eq!(report.verdict(), Verdict::CommittedBatchLost);
}

/// The high-water mark is a floor, not a ceiling: a batch that landed
/// after the mark's last write (a cut between the two puts) is above
/// the mark, and the audit accepts that.
#[test]
fn a_batch_above_the_persisted_mark_is_not_a_failure() {
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);
    // Sequence 1 lands but the mark write is "cut": simulate by
    // writing the batch directly and leaving the mark at 0.
    let b = BenchBatch::new(1);
    store.apply_batch(&b.ops()).unwrap();
    let report = audit(&store).unwrap();
    assert_eq!(report.highest_complete, Some(1));
    assert_eq!(report.persisted_high_water, Some(0));
    assert_eq!(report.verdict(), Verdict::Pass);
}

/// The audit judges by the protocol's priority: partial beats
/// reserved beats lost.
#[test]
fn verdict_priority_is_partial_then_reserved_then_lost() {
    let r = AuditReport {
        slots_occupied: 2,
        complete: 0,
        partial: vec![3],
        reserved_visible: 1,
        highest_complete: None,
        persisted_high_water: Some(9),
    };
    assert_eq!(r.verdict(), Verdict::PartialBatch);
    let r = AuditReport {
        partial: vec![],
        ..r
    };
    assert_eq!(r.verdict(), Verdict::ReservedVisible);
    let r = AuditReport {
        reserved_visible: 0,
        ..r
    };
    assert_eq!(r.verdict(), Verdict::CommittedBatchLost);
}

// ------------------------------------------- the boot halts on failure

/// A boot whose audit fails HALTS: no traffic resumes, the decision
/// names the criterion. The protocol says a failed run stops until the
/// failure is attributed - a bench that kept writing over a partial
/// batch would destroy the evidence it exists to preserve.
#[test]
fn a_failing_audit_halts_the_boot_and_names_the_criterion() {
    let flash = FaultyFlash::healthy();
    let handle = flash.clone();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);
    // Plant a partial slot 1.
    let b = BenchBatch::new(1);
    store.put(&b.keys[0], &b.values[0]).unwrap();
    drop(store);

    let mut out = sink();
    let (_store, decision) = boot(handle, RANGE, &mut out).expect("mount");
    assert_eq!(
        decision,
        BootDecision::Halt(Verdict::PartialBatch),
        "a failing audit must halt, naming the criterion: {out}"
    );
    assert!(out.contains("FAIL:partial_batch"), "{out}");
}

/// The serial line tells the three classes apart: a batch that is
/// past its commit point but could not finish says "committed" - the
/// operator logging boots must not read it as a refusal, because the
/// next boot WILL find it applied and the audit's high-water logic
/// depends on knowing that.
#[test]
fn a_committed_but_unfinished_batch_is_reported_committed_not_refused() {
    // Find the smallest cut budget at which sequence 1 lands: one past
    // the marker write.
    let total = {
        let flash = FaultyFlash::healthy();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        const PROBE: usize = 1_000_000;
        store.flash_mut().skip.set(PROBE);
        run_one(&mut store, &mut out, 1);
        let left = store.flash_mut().skip.get();
        PROBE - left
    };
    let mut committing = None;
    for budget in 0..=total {
        let f = FaultyFlash::healthy();
        let h = f.clone();
        let mut o = sink();
        let (mut s, _) = boot(f, RANGE, &mut o).expect("mount");
        run_one(&mut s, &mut o, 0);
        s.flash_mut().arm_cut(budget);
        let _ = run_one(&mut s, &mut o, 1);
        drop(s);
        h.heal();
        let (s2, _) = boot(h, RANGE, &mut sink()).expect("remount");
        if audit(&s2).unwrap().highest_complete == Some(1) {
            committing = Some(budget);
            break;
        }
    }
    let committing = committing.expect("some cut commits");

    // Marker lands, then every further write faults: committed but
    // unfinished, and the retry cannot finish it either.
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);
    let mut out = sink();
    store.flash_mut().arm_transient(committing, 1_000_000);
    let outcome = run_one(&mut store, &mut out, 1);
    assert_eq!(outcome, BatchOutcome::Committed, "{out}");
    assert!(out.contains("BATCH seq=1 committed"), "{out}");
    assert!(!out.contains("refused"), "{out}");
}

/// A lying commit on an otherwise healthy flash finishes inline and
/// says "ok", and the audit finds the batch complete.
#[test]
fn a_lying_commit_finishes_inline_and_audits_complete() {
    // Find the committing budget, as above.
    let total = {
        let flash = FaultyFlash::healthy();
        let mut out = sink();
        let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
        run_one(&mut store, &mut out, 0);
        run_one(&mut store, &mut out, 1);
        const PROBE: usize = 1_000_000;
        store.flash_mut().skip.set(PROBE);
        run_one(&mut store, &mut out, 2);
        let left = store.flash_mut().skip.get();
        PROBE - left
    };
    let mut committing = None;
    for budget in 0..=total {
        let f = FaultyFlash::healthy();
        let h = f.clone();
        let mut o = sink();
        let (mut s, _) = boot(f, RANGE, &mut o).expect("mount");
        run_one(&mut s, &mut o, 0);
        run_one(&mut s, &mut o, 1);
        s.flash_mut().arm_cut(budget);
        let _ = run_one(&mut s, &mut o, 2);
        drop(s);
        h.heal();
        let (s2, _) = boot(h, RANGE, &mut sink()).expect("remount");
        if audit(&s2).unwrap().highest_complete == Some(2) {
            committing = Some(budget);
            break;
        }
    }
    let committing = committing.expect("some cut commits");

    // Now the marker write LIES on a healthy flash: inline recovery
    // finishes the batch and the loop reports the success it is.
    let flash = FaultyFlash::healthy();
    let mut out = sink();
    let (mut store, _) = boot(flash, RANGE, &mut out).expect("mount");
    run_one(&mut store, &mut out, 0);
    run_one(&mut store, &mut out, 1);
    let mut out = sink();
    store.flash_mut().arm_lying(committing - 1, 1);
    let outcome = run_one(&mut store, &mut out, 2);
    assert_eq!(outcome, BatchOutcome::Ok, "{out}");
    assert!(out.contains("BATCH seq=2 ok"), "{out}");
    let report = audit(&store).unwrap();
    assert_eq!(report.highest_complete, Some(2));
    assert_eq!(report.verdict(), Verdict::Pass);
}
