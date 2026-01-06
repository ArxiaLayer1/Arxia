//! Offline payment example.

use arxia_finality::{assess_finality, FinalityLevel};
use arxia_gossip::SyncResult;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::validation::{verify_block, verify_chain_integrity};

fn main() {
    println!("=== Arxia Offline Payment Example ===");
    println!();

    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    let mut vclock = VectorClock::new();

    println!("Alice: {}", alice.short_id());
    println!("Bob:   {}", bob.short_id());
    println!();

    let alice_genesis = alice.open(100_000_000, &mut vclock);
    let _bob_genesis = bob.open(0, &mut vclock);

    println!(
        "Alice opened with 100 ARX (genesis: {}...)",
        &alice_genesis.hash[..16]
    );

    let send_block = alice
        .send(bob.id(), 5_000_000, &mut vclock)
        .expect("send should succeed");
    println!(
        "Alice sends 5 ARX to Bob (block: {}...)",
        &send_block.hash[..16]
    );
    assert!(verify_block(&send_block).is_ok());

    let recv_block = bob
        .receive(&send_block, &mut vclock)
        .expect("receive should succeed");
    println!("Bob receives 5 ARX (block: {}...)", &recv_block.hash[..16]);
    assert!(verify_block(&recv_block).is_ok());

    assert!(verify_chain_integrity(&alice.chain).is_ok());
    assert!(verify_chain_integrity(&bob.chain).is_ok());

    let finality = assess_finality(5_000_000, 1, &SyncResult::Mismatch(0), 0.0);
    println!("Finality level: {}", finality);
    assert_eq!(finality, FinalityLevel::L0);

    println!();
    println!("Alice balance: {} micro-ARX", alice.balance);
    println!("Bob balance:   {} micro-ARX", bob.balance);
    println!();
    println!("=== Example complete ===");
}
