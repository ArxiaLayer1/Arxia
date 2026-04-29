//! Offline payment example.
//!
//! Demonstrates the canonical end-to-end flow for an offline-first
//! payment on Arxia: open accounts, send funds, receive funds,
//! verify each block, then assess finality with an authenticated
//! L0 confirmation.
//!
//! # Error-propagation pattern (HIGH-023, commit 046)
//!
//! Pre-fix this example used `.unwrap()` and `.expect(...)` for
//! every fallible call. The audit (HIGH-023):
//!
//! > External dev copies the example verbatim into a product,
//! > panics on first error. Every example becomes a footgun for
//! > anyone learning from the repo. Examples must propagate
//! > errors with `?` inside `fn main() -> Result<(), …>`; add
//! > doc comments pointing out security-critical handling.
//!
//! Post-fix the production-style logic lives in [`run`] and uses
//! `?` end-to-end. `main()` is a thin wrapper that prints a
//! one-line error if `run()` returns Err. External developers
//! copying this example inherit the canonical pattern by
//! construction.
//!
//! Two unit tests pin the canonical pattern against future
//! regressions:
//!
//! 1. `tests::test_run_succeeds` — `run()` returns `Ok(())`
//!    on the happy path.
//! 2. `tests::test_main_source_does_not_use_unwrap_outside_tests`
//!    — a static source lint: the production-code portion of this
//!    file (everything before `#[cfg(test)]`) must contain zero
//!    `.unwrap()` calls. A future "simplification" reintroducing
//!    `.unwrap()` fails the test before reaching CI.
//!
//! `assert!(...)` on invariants like `verify_block(&block).is_ok()`
//! is preserved in the body — those are demonstration assertions
//! that highlight what the protocol guarantees, not error handling.
//! External devs copying the pattern get to see WHICH calls return
//! `Result` and where the meaningful checkpoints live.

use std::error::Error;

use arxia_crypto::{generate_keypair, sign};
use arxia_finality::{assess_finality, FinalityLevel, SignedConfirmation, ValidatorRegistry};
use arxia_gossip::SyncResult;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::validation::{verify_block, verify_chain_integrity};

/// End-to-end offline-payment flow with `?` error propagation.
///
/// Returns `Ok(())` on success. Any failure (insufficient
/// balance, signature mismatch, finality assessment error,
/// malformed hex, etc.) is propagated to the caller as a
/// boxed error — the canonical Rust pattern for examples that
/// touch multiple error types.
pub fn run() -> Result<(), Box<dyn Error>> {
    println!("=== Arxia Offline Payment Example ===");
    println!();

    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    let mut vclock = VectorClock::new();

    println!("Alice: {}", alice.short_id());
    println!("Bob:   {}", bob.short_id());
    println!();

    let alice_genesis = alice.open(100_000_000, &mut vclock)?;
    let _bob_genesis = bob.open(0, &mut vclock)?;

    println!(
        "Alice opened with 100 ARX (genesis: {}...)",
        &alice_genesis.hash[..16]
    );

    let send_block = alice.send(bob.id(), 5_000_000, &mut vclock)?;
    println!(
        "Alice sends 5 ARX to Bob (block: {}...)",
        &send_block.hash[..16]
    );
    // Demonstration assertion: the produced block is valid by
    // construction. In production code the equivalent line is
    // `verify_block(&send_block)?;`.
    assert!(verify_block(&send_block).is_ok());

    let recv_block = bob.receive(&send_block, &mut vclock)?;
    println!("Bob receives 5 ARX (block: {}...)", &recv_block.hash[..16]);
    assert!(verify_block(&recv_block).is_ok());

    assert!(verify_chain_integrity(&alice.chain).is_ok());
    assert!(verify_chain_integrity(&bob.chain).is_ok());

    // Build a one-node validator registry for the example: a fresh
    // keypair signs an L0 confirmation over the send block. In a real
    // deployment the registry is populated from the consensus layer
    // and confirmations come from BLE-attached peers.
    //
    // Security-critical handling: the hex decode + length check
    // below is what binds the L0 confirmation to the exact send
    // block. A real implementation MUST never accept an
    // arbitrary-length hash from an untrusted source — the
    // `.try_into()` on the 32-byte array is the parse-time gate.
    let send_block_hash_vec = hex::decode(&send_block.hash)?;
    let send_block_hash: [u8; 32] = send_block_hash_vec
        .as_slice()
        .try_into()
        .map_err(|_| "block hash is not 32 bytes")?;
    let (witness_sk, witness_vk) = generate_keypair();
    let witness_pk = witness_vk.to_bytes();
    let canonical = SignedConfirmation::canonical_bytes(&witness_pk, &send_block_hash);
    let confirmation = SignedConfirmation {
        confirmer_pubkey: witness_pk,
        block_hash: send_block_hash,
        signature: sign(&witness_sk, &canonical).to_vec(),
    };
    let mut registry = ValidatorRegistry::new();
    registry.insert(witness_pk, 1);

    let finality = assess_finality(
        5_000_000,
        send_block_hash,
        &[confirmation],
        &SyncResult::Mismatch(0),
        &[],
        &registry,
    )?;
    println!("Finality level: {}", finality);
    assert_eq!(finality, FinalityLevel::L0);

    println!();
    println!("Alice balance: {} micro-ARX", alice.balance);
    println!("Bob balance:   {} micro-ARX", bob.balance);
    println!();
    println!("=== Example complete ===");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source of this very file at compile time, used by the
    /// lint-style tests below to grep for `.unwrap()` /
    /// `.expect(` outside the test module.
    const SELF_SOURCE: &str = include_str!("main.rs");

    /// HIGH-023 happy path: `run()` returns `Ok(())`. Pin against
    /// any future regression that breaks the canonical flow.
    #[test]
    fn test_run_succeeds() {
        let result = run();
        assert!(
            result.is_ok(),
            "run() should succeed on the happy path; got {result:?}"
        );
    }

    /// Helper: line-by-line scan of `production_code` for
    /// `pattern`, skipping lines whose first non-whitespace
    /// characters are `//` (line comment, doc comment, inner
    /// doc comment). Returns the first offending line if any.
    fn scan_production_for(pattern: &str) -> Option<(usize, String)> {
        // Use a 2-line marker that only appears at the actual
        // test-module boundary (not in any docstring mention of
        // `#[cfg(test)]`).
        let test_marker = "#[cfg(test)]\nmod tests";
        let production_code = SELF_SOURCE
            .split(test_marker)
            .next()
            .expect("split always yields >=1 segment");
        for (i, line) in production_code.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains(pattern) {
                return Some((i + 1, line.to_string()));
            }
        }
        None
    }

    /// HIGH-023 PRIMARY PIN: the production-code portion of this
    /// file (everything before the `#[cfg(test)]` marker) must
    /// contain zero `.unwrap()` calls outside of comment lines.
    /// A future "simplification" reintroducing `.unwrap()` in
    /// real code fails this test before reaching CI.
    #[test]
    fn test_main_source_does_not_use_unwrap_outside_tests() {
        if let Some((lineno, line)) = scan_production_for(".unwrap()") {
            panic!(
                "HIGH-023: production code at line {lineno} uses .unwrap(): {line}\n\
                 Use `?` propagation instead."
            );
        }
    }

    /// HIGH-023 PIN: same lint for `.expect(`. Both `.unwrap()`
    /// and `.expect(...)` panic on Err; the audit calls them out
    /// together.
    #[test]
    fn test_main_source_does_not_use_expect_outside_tests() {
        if let Some((lineno, line)) = scan_production_for(".expect(") {
            panic!(
                "HIGH-023: production code at line {lineno} uses .expect(): {line}\n\
                 Use `?` propagation with a typed error instead."
            );
        }
    }

    /// Pin that the example's `main()` returns Result. A future
    /// regression that changes `main` back to `fn main()` (no
    /// return type) fails this test.
    #[test]
    fn test_main_source_returns_result() {
        // Use a 2-line marker that only appears at the actual
        // test-module boundary (not in any docstring mention of
        // `#[cfg(test)]`).
        let test_marker = "#[cfg(test)]\nmod tests";
        let production_code = SELF_SOURCE
            .split(test_marker)
            .next()
            .expect("split always yields ≥1 segment");
        assert!(
            production_code.contains("fn main() -> Result<"),
            "HIGH-023: main() must return Result for `?` propagation"
        );
    }
}
