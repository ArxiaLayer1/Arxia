//! What the type system guarantees about sharing a `Ledger`, and what
//! actually happens when several threads ingest at once.
//!
//! `Ledger::add_block` takes `&mut self`, so two concurrent calls are
//! rejected at compile time — the borrow checker, not a convention,
//! enforces the serialisation. What remains worth proving is that the
//! ledger is safe to *move* behind a lock and that its economic
//! invariants survive genuine multi-threaded ingestion.

use std::sync::{Arc, Mutex};
use std::thread;

use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::ledger::Ledger;

#[test]
fn ledger_is_send_and_sync() {
    // Compile-time pin: `Arc<Mutex<Ledger>>` is only sound if `Ledger`
    // is both. If a future field (an `Rc`, a raw pointer, a `Cell`)
    // breaks this, the documented sharing pattern silently stops
    // compiling for downstream callers — better to fail here.
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Ledger>();
    assert_sync::<Ledger>();
}

#[test]
fn concurrent_ingestion_preserves_total_supply() {
    const THREADS: usize = 8;
    const TRANSFERS_PER_THREAD: usize = 12;
    const OPEN_AMOUNT: u64 = 1_000_000;

    let ledger = Arc::new(Mutex::new(Ledger::new()));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let ledger = Arc::clone(&ledger);
            thread::spawn(move || {
                // Each thread owns its accounts, so per-chain nonce
                // ordering is intact; only ledger access is shared.
                let mut vc = VectorClock::new();
                let mut alice = AccountChain::new();
                let mut bob = AccountChain::new();

                let a_open = alice.open(OPEN_AMOUNT, &mut vc).unwrap();
                let b_open = bob.open(0, &mut vc).unwrap();
                ledger.lock().unwrap().add_block(a_open).unwrap();
                ledger.lock().unwrap().add_block(b_open).unwrap();

                for _ in 0..TRANSFERS_PER_THREAD {
                    let send = alice.send(bob.id(), 1_000, &mut vc).unwrap();
                    let recv = bob.receive(&send, &mut vc).unwrap();
                    // Lock released between the two, so other threads
                    // genuinely interleave here.
                    ledger.lock().unwrap().add_block(send).unwrap();
                    ledger.lock().unwrap().add_block(recv).unwrap();
                }
                (alice.id().to_string(), bob.id().to_string())
            })
        })
        .collect();

    let pairs: Vec<(String, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let guard = ledger.lock().unwrap();

    // Total minted equals what the Opens declared, nothing more.
    assert_eq!(
        guard.total_supply(),
        OPEN_AMOUNT * THREADS as u64,
        "interleaved ingestion must not inflate the supply accumulator"
    );

    // Every pair conserves value across its own transfers.
    let moved = 1_000 * TRANSFERS_PER_THREAD as u64;
    for (a, b) in &pairs {
        let a_bal = guard.get_chain(a).unwrap().last().unwrap().balance;
        let b_bal = guard.get_chain(b).unwrap().last().unwrap().balance;
        assert_eq!(a_bal, OPEN_AMOUNT - moved, "sender balance");
        assert_eq!(b_bal, moved, "receiver balance");
        assert_eq!(a_bal + b_bal, OPEN_AMOUNT, "pair conserves value");
    }

    // And in aggregate.
    let sum: u64 = pairs
        .iter()
        .map(|(a, b)| {
            guard.get_chain(a).unwrap().last().unwrap().balance
                + guard.get_chain(b).unwrap().last().unwrap().balance
        })
        .sum();
    assert_eq!(sum, OPEN_AMOUNT * THREADS as u64, "global conservation");
}

#[test]
fn concurrent_double_receive_of_one_source_is_still_rejected() {
    // The cross-chain dedup is per-Ledger state. Under a lock it must
    // hold exactly as it does single-threaded: two threads racing to
    // spend the same source SEND, only one wins.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();

    let ledger = Arc::new(Mutex::new(Ledger::new()));
    {
        let mut g = ledger.lock().unwrap();
        g.add_block(alice.open(1_000_000, &mut vc).unwrap())
            .unwrap();
        g.add_block(bob.open(0, &mut vc).unwrap()).unwrap();
    }
    let send = alice.send(bob.id(), 500, &mut vc).unwrap();
    ledger.lock().unwrap().add_block(send.clone()).unwrap();

    // Two identical receives built from the same source.
    let recv = bob.receive(&send, &mut vc).unwrap();
    let duplicate = recv.clone();

    let l1 = Arc::clone(&ledger);
    let l2 = Arc::clone(&ledger);
    let h1 = thread::spawn(move || l1.lock().unwrap().add_block(recv).is_ok());
    let h2 = thread::spawn(move || l2.lock().unwrap().add_block(duplicate).is_ok());
    let (a, b) = (h1.join().unwrap(), h2.join().unwrap());

    assert!(
        a ^ b,
        "exactly one of the racing receives must be accepted, got {a} and {b}"
    );
    let guard = ledger.lock().unwrap();
    assert_eq!(
        guard.get_chain(bob.id()).unwrap().last().unwrap().balance,
        500,
        "the receiver is credited once, not twice"
    );
}
