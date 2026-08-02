//! Regression guards for value conservation at `Ledger::add_block`.
//!
//! Before this suite the ledger trusted each block's self-declared
//! `balance`, so a peer could sign a block that created value. Each
//! test drives only the PUBLIC API — what any peer can do — and asserts
//! the ledger now derives the balance from chain history and rejects
//! anything that disagrees, while still accepting legitimate flows.

use arxia_core::ArxiaError;
use arxia_lattice::block::{Block, BlockType};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::ledger::Ledger;
use ed25519_dalek::Signer;

/// A block with an arbitrary `balance` but a VALID hash and signature
/// under `owner`'s own key — what an attacker who controls their own
/// account can produce without stealing anything.
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

#[test]
fn receive_cannot_credit_more_than_the_cited_send() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut whale = AccountChain::new();
    let mut attacker = AccountChain::new();
    ledger
        .add_block(whale.open(1_000_000, &mut vc).unwrap())
        .unwrap();
    let send = whale.send(attacker.id(), 1, &mut vc).unwrap();
    ledger.add_block(send.clone()).unwrap();
    let a_open = attacker.open(0, &mut vc).unwrap();
    ledger.add_block(a_open.clone()).unwrap();

    let evil = forge(
        &attacker,
        &a_open.hash,
        2,
        1_000_000_000_000,
        BlockType::Receive {
            source_hash: send.hash.clone(),
        },
    );
    let res = ledger.add_block(evil);
    assert!(
        matches!(res, Err(ArxiaError::BalanceMismatch { expected: 1, .. })),
        "inflated receive must be rejected, got {res:?}"
    );
    assert_eq!(
        ledger
            .get_chain(attacker.id())
            .unwrap()
            .last()
            .unwrap()
            .balance,
        0,
        "rejected block must not mutate chain state"
    );
}

#[test]
fn send_cannot_overspend_prior_balance() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut attacker = AccountChain::new();
    let victim = AccountChain::new();
    let a_open = attacker.open(100, &mut vc).unwrap();
    ledger.add_block(a_open.clone()).unwrap();

    let evil = forge(
        &attacker,
        &a_open.hash,
        2,
        100,
        BlockType::Send {
            destination: victim.id().to_string(),
            amount: 1_000_000_000_000,
        },
    );
    assert!(
        matches!(
            ledger.add_block(evil),
            Err(ArxiaError::InsufficientBalance {
                available: 100,
                required: 1_000_000_000_000
            })
        ),
        "over-spend must be rejected"
    );
}

#[test]
fn send_must_debit_exactly() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut attacker = AccountChain::new();
    let victim = AccountChain::new();
    let a_open = attacker.open(1_000, &mut vc).unwrap();
    ledger.add_block(a_open.clone()).unwrap();

    // Affordable amount (500 <= 1000) but the declared post-balance
    // (900) is not prior - amount (500): an under-debit.
    let evil = forge(
        &attacker,
        &a_open.hash,
        2,
        900,
        BlockType::Send {
            destination: victim.id().to_string(),
            amount: 500,
        },
    );
    assert!(
        matches!(
            ledger.add_block(evil),
            Err(ArxiaError::BalanceMismatch {
                expected: 500,
                got: 900,
                ..
            })
        ),
        "under-debit must be rejected"
    );
}

#[test]
fn second_open_on_existing_chain_is_rejected() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut attacker = AccountChain::new();
    let a_open = attacker.open(1_000, &mut vc).unwrap();
    ledger.add_block(a_open.clone()).unwrap();

    let evil = forge(
        &attacker,
        &a_open.hash,
        2,
        1_000_000_000_000,
        BlockType::Open {
            initial_balance: 1_000_000_000_000,
        },
    );
    assert!(
        matches!(
            ledger.add_block(evil),
            Err(ArxiaError::OpenNotGenesis { .. })
        ),
        "a second Open must be rejected"
    );
}

#[test]
fn legitimate_send_then_receive_is_accepted_and_conserves_value() {
    let mut ledger = Ledger::new();
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();

    ledger
        .add_block(alice.open(1_000_000, &mut vc).unwrap())
        .unwrap();
    ledger.add_block(bob.open(0, &mut vc).unwrap()).unwrap();
    let send = alice.send(bob.id(), 250_000, &mut vc).unwrap();
    ledger.add_block(send.clone()).unwrap();
    let recv = bob.receive(&send, &mut vc).unwrap();
    ledger
        .add_block(recv)
        .expect("a legitimate receive must still be accepted");

    let alice_bal = ledger
        .get_chain(alice.id())
        .unwrap()
        .last()
        .unwrap()
        .balance;
    let bob_bal = ledger.get_chain(bob.id()).unwrap().last().unwrap().balance;
    assert_eq!(alice_bal, 750_000);
    assert_eq!(bob_bal, 250_000);
    // Total equals the single minted Open — Bob opened at zero.
    assert_eq!(alice_bal + bob_bal, 1_000_000);
}
