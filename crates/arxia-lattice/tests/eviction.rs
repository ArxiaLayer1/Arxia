//! A consumed Send is dropped from `send_index`. These pin that the
//! eviction does not blur the two rejection reasons a replayed Receive
//! and a phantom Receive must keep producing.

use arxia_core::ArxiaError;
use arxia_lattice::block::{Block, BlockType};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::ledger::Ledger;
use ed25519_dalek::Signer;

fn forge(owner: &AccountChain, previous: &str, nonce: u64, balance: u64, bt: BlockType) -> Block {
    let hash = Block::compute_hash(owner.id(), previous, &bt, balance, nonce, 0).unwrap();
    let sig = owner.signing_key().sign(&hex::decode(&hash).unwrap());
    Block {
        account: owner.id().to_string(),
        previous: previous.to_string(),
        block_type: bt,
        balance,
        nonce,
        timestamp: 0,
        hash,
        signature: sig.to_bytes().to_vec(),
    }
}

/// alice opens, sends to bob, bob opens and receives. Returns the ledger
/// plus the send hash and bob's chain.
fn settled() -> (Ledger, String, AccountChain, Block) {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    ledger
        .add_block(alice.open(1_000_000, &mut vc).unwrap())
        .unwrap();
    let b_open = bob.open(0, &mut vc).unwrap();
    ledger.add_block(b_open).unwrap();
    let send = alice.send(bob.id(), 500, &mut vc).unwrap();
    ledger.add_block(send.clone()).unwrap();
    let recv = bob.receive(&send, &mut vc).unwrap();
    ledger.add_block(recv.clone()).unwrap();
    (ledger, send.hash.clone(), bob, recv)
}

#[test]
fn a_replayed_receive_still_reports_duplicate_not_unknown() {
    // This is the regression the eviction could have introduced: once
    // the Send is gone from `send_index`, a naive lookup-first order
    // would answer UnknownSourceSend and make a double-spend attempt
    // look like a phantom one.
    let (mut ledger, send_hash, bob, recv) = settled();
    let replay = forge(
        &bob,
        &recv.hash,
        3,
        1_000,
        BlockType::Receive {
            source_hash: send_hash.clone(),
        },
    );
    let res = ledger.add_block(replay);
    assert!(
        matches!(res, Err(ArxiaError::DuplicateReceive { ref source_hash }) if *source_hash == send_hash),
        "a replay must stay DuplicateReceive, got {res:?}"
    );
}

#[test]
fn a_phantom_receive_still_reports_unknown_source() {
    // The other side of the same distinction.
    let (mut ledger, _, bob, recv) = settled();
    let phantom = "ff".repeat(32);
    let evil = forge(
        &bob,
        &recv.hash,
        3,
        1_000,
        BlockType::Receive {
            source_hash: phantom.clone(),
        },
    );
    let res = ledger.add_block(evil);
    assert!(
        matches!(res, Err(ArxiaError::UnknownSourceSend { ref source_hash }) if *source_hash == phantom),
        "a phantom must stay UnknownSourceSend, got {res:?}"
    );
}

#[test]
fn an_unconsumed_send_is_still_receivable() {
    // Eviction must only fire on consumption, never earlier.
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    ledger
        .add_block(alice.open(1_000_000, &mut vc).unwrap())
        .unwrap();
    ledger.add_block(bob.open(0, &mut vc).unwrap()).unwrap();

    let s1 = alice.send(bob.id(), 100, &mut vc).unwrap();
    let s2 = alice.send(bob.id(), 200, &mut vc).unwrap();
    ledger.add_block(s1.clone()).unwrap();
    ledger.add_block(s2.clone()).unwrap();

    // Consume the first; the second must remain fully usable.
    let r1 = bob.receive(&s1, &mut vc).unwrap();
    ledger.add_block(r1).unwrap();
    let r2 = bob.receive(&s2, &mut vc).unwrap();
    ledger
        .add_block(r2)
        .expect("the untouched Send must still resolve");

    assert_eq!(
        ledger.get_chain(bob.id()).unwrap().last().unwrap().balance,
        300
    );
}

#[test]
fn wrong_destination_is_unaffected_by_the_reordering() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let bob = AccountChain::new();
    let mut carol = AccountChain::new();
    ledger
        .add_block(alice.open(1_000_000, &mut vc).unwrap())
        .unwrap();
    let c_open = carol.open(0, &mut vc).unwrap();
    ledger.add_block(c_open.clone()).unwrap();
    let send = alice.send(bob.id(), 100, &mut vc).unwrap();
    ledger.add_block(send.clone()).unwrap();

    let stolen = forge(
        &carol,
        &c_open.hash,
        2,
        100,
        BlockType::Receive {
            source_hash: send.hash.clone(),
        },
    );
    assert!(
        matches!(ledger.add_block(stolen), Err(ArxiaError::WrongDestination)),
        "destination mismatch must still be reported as such"
    );
}
