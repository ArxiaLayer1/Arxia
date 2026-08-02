//! Regression guards for value conservation across a partition merge.
//!
//! `reconcile_partitions` derives a RECEIVE's credit from the source
//! SEND, which is correct, but previously nothing stopped two RECEIVEs
//! from citing the same source — each one credited the account and the
//! merge created value. These tests pin the cross-merge dedup and the
//! legitimate single-credit path.

use arxia_crdt::reconciliation::reconcile_partitions;
use arxia_lattice::block::{Block, BlockType};
use arxia_lattice::chain::{AccountChain, VectorClock};

/// A raw RECEIVE citing `source_hash`. The merge path verifies neither
/// signatures nor hashes — it operates on already-authenticated blocks —
/// so this is representative of what a malicious peer contributes to a
/// merge set.
fn raw_receive(
    account: &str,
    previous: &str,
    nonce: u64,
    balance: u64,
    source_hash: &str,
) -> Block {
    Block {
        account: account.to_string(),
        previous: previous.to_string(),
        block_type: BlockType::Receive {
            source_hash: source_hash.to_string(),
        },
        balance,
        nonce,
        timestamp: 0,
        hash: format!("{nonce:064x}"),
        signature: vec![0u8; 64],
    }
}

#[test]
fn one_source_send_credits_at_most_once() {
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    bob.open(0, &mut vc).unwrap();

    let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
    let recv1 = bob.receive(&send, &mut vc).unwrap();
    let recv2 = raw_receive(bob.id(), &recv1.hash, 3, 200_000, &send.hash);

    let partition = vec![
        alice.chain[0].clone(),
        send.clone(),
        bob.chain[0].clone(),
        recv1.clone(),
        recv2,
    ];
    let report = reconcile_partitions(&partition, &[]).unwrap();

    assert_eq!(
        report.balances[bob.id()],
        100_000,
        "a single source SEND must credit the receiver exactly once"
    );
    assert!(
        report
            .rejected_receives
            .iter()
            .any(|r| r.reason == "source_already_consumed"),
        "the repeat RECEIVE must be reported as rejected"
    );
    // Value conservation across the merge: what leaves Alice equals what
    // reaches Bob.
    assert_eq!(
        1_000_000 - report.balances[alice.id()],
        report.balances[bob.id()],
        "the merge must neither create nor destroy value"
    );
}

#[test]
fn three_receives_of_one_source_still_credit_once() {
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    bob.open(0, &mut vc).unwrap();

    let send = alice.send(bob.id(), 50_000, &mut vc).unwrap();
    let recv1 = bob.receive(&send, &mut vc).unwrap();
    let recv2 = raw_receive(bob.id(), &recv1.hash, 3, 100_000, &send.hash);
    let recv3 = raw_receive(bob.id(), &recv1.hash, 4, 150_000, &send.hash);

    let partition = vec![
        alice.chain[0].clone(),
        send.clone(),
        bob.chain[0].clone(),
        recv1,
        recv2,
        recv3,
    ];
    let report = reconcile_partitions(&partition, &[]).unwrap();

    assert_eq!(report.balances[bob.id()], 50_000);
    assert_eq!(
        report
            .rejected_receives
            .iter()
            .filter(|r| r.reason == "source_already_consumed")
            .count(),
        2,
        "both repeats must be rejected"
    );
}

#[test]
fn two_distinct_sends_each_credit_normally() {
    // The dedup must key on the source hash, not on the receiver: two
    // different SENDs to the same account both credit.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    bob.open(0, &mut vc).unwrap();

    let send1 = alice.send(bob.id(), 30_000, &mut vc).unwrap();
    let recv1 = bob.receive(&send1, &mut vc).unwrap();
    let send2 = alice.send(bob.id(), 70_000, &mut vc).unwrap();
    let recv2 = bob.receive(&send2, &mut vc).unwrap();

    let partition = vec![
        alice.chain[0].clone(),
        send1,
        send2,
        bob.chain[0].clone(),
        recv1,
        recv2,
    ];
    let report = reconcile_partitions(&partition, &[]).unwrap();

    assert_eq!(report.balances[bob.id()], 100_000);
    assert_eq!(report.balances[alice.id()], 900_000);
    assert!(report.rejected_receives.is_empty());
}
