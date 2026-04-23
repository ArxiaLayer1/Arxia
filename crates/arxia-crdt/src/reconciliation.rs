//! Partition reconciliation using CRDTs and Block Lattice data.
//!
//! Invariants enforced:
//!
//! 1. At most one block per `(account, nonce)` contributes to the
//!    reconciled state. When two partitions disagree, a deterministic
//!    tie-break (lexicographically smallest hash) picks the winner, and
//!    the caller is informed via [`ReconciliationReport::conflicts`].
//! 2. No account balance may be negative after reconciliation. If the
//!    invariant breaks, `reconcile_partitions` returns
//!    [`ArxiaError::NegativeBalance`] instead of silently yielding a bad
//!    map.
//! 3. A `BlockType::Receive` block only contributes to balance if its
//!    `source_hash` references a `BlockType::Send` block that won its
//!    own `(account, nonce)` conflict AND whose `destination` matches
//!    the receiver's account. RECEIVEs that reference unknown SENDs
//!    ("phantom receives") or mismatched destinations are surfaced in
//!    [`ReconciliationReport::rejected_receives`] and do NOT credit the
//!    receiver's balance.

use crate::pn_counter::PNCounter;
use arxia_core::ArxiaError;
use arxia_lattice::block::{Block, BlockType};
use std::collections::{HashMap, HashSet};

/// Info on a conflict resolved during reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConflict {
    /// Hex-encoded account public key.
    pub account: String,
    /// The nonce at which the conflict occurred.
    pub nonce: u64,
    /// Hash of the block that was applied (winner).
    pub winner_hash: String,
    /// Hashes of all blocks that were rejected (losers).
    pub loser_hashes: Vec<String>,
    /// How the winner was chosen.
    pub method: &'static str,
}

/// Info on a `BlockType::Receive` block that was rejected because its
/// `source_hash` did not match an applied SEND, or the destination of
/// the matching SEND did not match the receiver's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedReceive {
    /// The receiver's account.
    pub account: String,
    /// Nonce of the rejected RECEIVE block.
    pub nonce: u64,
    /// Hash of the rejected RECEIVE block.
    pub receive_hash: String,
    /// The `source_hash` the RECEIVE pointed at (may be bogus).
    pub source_hash: String,
    /// Why the rejection happened.
    pub reason: &'static str,
}

/// Full outcome of a `reconcile_partitions` call.
#[derive(Debug, Clone)]
pub struct ReconciliationReport {
    /// Final per-account balance map. Values are guaranteed non-negative.
    pub balances: HashMap<String, i64>,
    /// Conflicts encountered and how they were resolved.
    pub conflicts: Vec<ResolvedConflict>,
    /// RECEIVE blocks that could not be matched to an applied SEND and
    /// therefore did NOT credit the receiver.
    pub rejected_receives: Vec<RejectedReceive>,
}

/// Reconcile two partitions into merged balances via PNCounter CRDT.
///
/// # Errors
///
/// Returns [`ArxiaError::NegativeBalance`] if any reconciled account
/// balance ends up below zero. Returns [`ArxiaError::NonceConflict`]
/// if an unresolvable conflict is encountered (currently unreachable
/// with the hash-tiebreak fallback, reserved for future stricter modes).
pub fn reconcile_partitions(
    partition_a: &[Block],
    partition_b: &[Block],
) -> Result<ReconciliationReport, ArxiaError> {
    // 1. Deduplicate by block hash.
    let mut seen_hashes: HashSet<String> = HashSet::new();
    let all: Vec<&Block> = partition_a
        .iter()
        .chain(partition_b.iter())
        .filter(|b| seen_hashes.insert(b.hash.clone()))
        .collect();

    // 2. Group by (account, nonce). Any group with more than one block
    //    is a conflict.
    let mut by_key: HashMap<(String, u64), Vec<&Block>> = HashMap::new();
    for b in &all {
        by_key
            .entry((b.account.clone(), b.nonce))
            .or_default()
            .push(b);
    }

    // 3. Pick a winner per (account, nonce) using hash tiebreaker.
    let mut winners: HashMap<(String, u64), &Block> = HashMap::new();
    let mut conflicts: Vec<ResolvedConflict> = Vec::new();
    for (key, group) in &by_key {
        if group.len() == 1 {
            winners.insert(key.clone(), group[0]);
            continue;
        }
        let mut sorted: Vec<&&Block> = group.iter().collect();
        sorted.sort_by(|a, b| a.hash.cmp(&b.hash));
        let winner = *sorted[0];
        let losers: Vec<String> = sorted[1..].iter().map(|b| b.hash.clone()).collect();
        winners.insert(key.clone(), winner);
        conflicts.push(ResolvedConflict {
            account: key.0.clone(),
            nonce: key.1,
            winner_hash: winner.hash.clone(),
            loser_hashes: losers,
            method: "hash_tiebreaker",
        });
    }

    // 4. Pre-pass: index every APPLIED (winning) SEND by its hash, so
    //    RECEIVE blocks can validate their source_hash references. Only
    //    winners are indexed — a SEND that lost its conflict does not
    //    count as a valid source.
    let mut applied_sends: HashMap<String, &Block> = HashMap::new();
    for block in winners.values() {
        if matches!(block.block_type, BlockType::Send { .. }) {
            applied_sends.insert(block.hash.clone(), block);
        }
    }

    // 5. Apply the winning blocks to CRDT counters. Deterministic order
    //    by (account, nonce).
    let mut crdts: HashMap<String, PNCounter> = HashMap::new();
    let mut rejected_receives: Vec<RejectedReceive> = Vec::new();
    let mut ordered_keys: Vec<(String, u64)> = by_key.keys().cloned().collect();
    ordered_keys.sort();
    for key in ordered_keys {
        let block = winners.get(&key).expect("winner recorded per key");
        match &block.block_type {
            BlockType::Open { initial_balance } => {
                crdts
                    .entry(block.account.clone())
                    .or_default()
                    .increment(&block.account[..8], *initial_balance);
            }
            BlockType::Send { amount, .. } => {
                crdts
                    .entry(block.account.clone())
                    .or_default()
                    .decrement(&block.account[..8], *amount);
            }
            BlockType::Receive { source_hash } => {
                // Phantom-RECEIVE guard (CRIT-017):
                //
                // A RECEIVE is only applied if:
                //   (a) its source_hash matches an APPLIED (winning) SEND, AND
                //   (b) that SEND's destination matches this account.
                //
                // Otherwise the block is rejected; the receiver does NOT
                // gain balance.
                let source = match applied_sends.get(source_hash) {
                    Some(s) => s,
                    None => {
                        rejected_receives.push(RejectedReceive {
                            account: block.account.clone(),
                            nonce: block.nonce,
                            receive_hash: block.hash.clone(),
                            source_hash: source_hash.clone(),
                            reason: "source_not_found",
                        });
                        continue;
                    }
                };
                let destination_ok = match &source.block_type {
                    BlockType::Send { destination, .. } => {
                        destination.as_str() == block.account.as_str()
                    }
                    _ => false,
                };
                if !destination_ok {
                    rejected_receives.push(RejectedReceive {
                        account: block.account.clone(),
                        nonce: block.nonce,
                        receive_hash: block.hash.clone(),
                        source_hash: source_hash.clone(),
                        reason: "destination_mismatch",
                    });
                    continue;
                }

                // Apply the receive by deriving the credit amount from
                // the source SEND itself (source-of-truth) rather than
                // from the RECEIVE's balance field. This is tighter
                // than the pre-011 balance-delta heuristic.
                if let BlockType::Send { amount, .. } = &source.block_type {
                    crdts
                        .entry(block.account.clone())
                        .or_default()
                        .increment(&block.account[..8], *amount);
                }
            }
            BlockType::Revoke { .. } => {
                // Revoke blocks do not affect balance.
            }
        }
    }

    // 6. Materialize balances and enforce the non-negative invariant.
    let mut balances = HashMap::new();
    for (account, counter) in &crdts {
        let value = counter.value();
        if value < 0 {
            return Err(ArxiaError::NegativeBalance {
                account: account.clone(),
                balance: value,
            });
        }
        balances.insert(account.clone(), value);
    }

    Ok(ReconciliationReport {
        balances,
        conflicts,
        rejected_receives,
    })
}

/// Legacy-style helper: returns only the balance map, panicking on error.
#[doc(hidden)]
pub fn reconcile_partitions_balances_only(
    partition_a: &[Block],
    partition_b: &[Block],
) -> Result<HashMap<String, i64>, ArxiaError> {
    reconcile_partitions(partition_a, partition_b).map(|r| r.balances)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_lattice::chain::{AccountChain, VectorClock};

    // ========================================================================
    // Baseline tests (inherited from 007)
    // ========================================================================

    #[test]
    fn test_reconcile_identical_partitions() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let report = reconcile_partitions(&alice.chain, &alice.chain).unwrap();
        assert_eq!(report.balances[alice.id()], 1_000_000);
        assert!(report.conflicts.is_empty());
        assert!(report.rejected_receives.is_empty());
    }

    #[test]
    fn test_reconcile_empty_partitions() {
        let report = reconcile_partitions(&[], &[]).unwrap();
        assert!(report.balances.is_empty());
        assert!(report.conflicts.is_empty());
        assert!(report.rejected_receives.is_empty());
    }

    #[test]
    fn test_reconcile_disjoint_partitions() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(500_000, &mut vc).unwrap();
        let report = reconcile_partitions(&alice.chain, &bob.chain).unwrap();
        assert_eq!(report.balances[alice.id()], 1_000_000);
        assert_eq!(report.balances[bob.id()], 500_000);
        assert!(report.conflicts.is_empty());
        assert!(report.rejected_receives.is_empty());
    }

    #[test]
    fn test_reconcile_double_spend_same_nonce_resolves_winner() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();

        let send_bob = alice.send(bob.id(), 600_000, &mut vc).unwrap();
        let partition_a = vec![alice.chain[0].clone(), send_bob.clone()];

        alice.chain.pop();
        alice.balance += 600_000;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let send_carol = alice.send(carol.id(), 600_000, &mut vc).unwrap();
        let partition_b = vec![alice.chain[0].clone(), send_carol.clone()];

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.balances[alice.id()], 400_000);
        assert!(report.rejected_receives.is_empty());
    }

    #[test]
    fn test_reconcile_deterministic_winner_by_hash() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let s1 = alice.send(bob.id(), 100, &mut vc).unwrap();
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let s2 = alice.send(carol.id(), 100, &mut vc).unwrap();
        let p_a = vec![alice.chain[0].clone(), s1.clone()];
        let p_b = vec![alice.chain[0].clone(), s2.clone()];
        let r1 = reconcile_partitions(&p_a, &p_b).unwrap();
        let r2 = reconcile_partitions(&p_a, &p_b).unwrap();
        assert_eq!(r1.conflicts[0].winner_hash, r2.conflicts[0].winner_hash);
        let expected = if s1.hash < s2.hash {
            &s1.hash
        } else {
            &s2.hash
        };
        assert_eq!(&r1.conflicts[0].winner_hash, expected);
    }

    #[test]
    fn test_reconcile_never_goes_negative_on_double_spend() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let s1 = alice.send(bob.id(), 900_000, &mut vc).unwrap();
        alice.chain.pop();
        alice.balance += 900_000;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let s2 = alice.send(carol.id(), 900_000, &mut vc).unwrap();
        let p_a = vec![alice.chain[0].clone(), s1];
        let p_b = vec![alice.chain[0].clone(), s2];
        let report = reconcile_partitions(&p_a, &p_b).unwrap();
        assert_eq!(report.balances[alice.id()], 100_000);
    }

    #[test]
    fn test_reconcile_hashset_dedup_is_o_of_1() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let genesis = alice.chain[0].clone();
        let bob = AccountChain::new();
        let mut sends = Vec::new();
        for _ in 0..10 {
            sends.push(alice.send(bob.id(), 1, &mut vc).unwrap());
        }
        let mut partition: Vec<Block> = vec![genesis];
        partition.extend(sends);
        let r = reconcile_partitions(&partition, &partition).unwrap();
        assert!(r.conflicts.is_empty());
        assert_eq!(r.balances[alice.id()], 1_000_000 - 10);
    }

    #[test]
    fn test_reconcile_three_way_conflict() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let dave = AccountChain::new();
        let s_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let s_carol = alice.send(carol.id(), 100, &mut vc).unwrap();
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let s_dave = alice.send(dave.id(), 100, &mut vc).unwrap();
        let genesis = alice.chain[0].clone();
        let p_a = vec![genesis.clone(), s_bob.clone()];
        let p_b = vec![genesis.clone(), s_carol.clone(), s_dave.clone()];
        let report = reconcile_partitions(&p_a, &p_b).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        let mut hashes: [&String; 3] = [&s_bob.hash, &s_carol.hash, &s_dave.hash];
        hashes.sort();
        assert_eq!(&report.conflicts[0].winner_hash, hashes[0]);
        assert_eq!(report.conflicts[0].loser_hashes.len(), 2);
    }

    #[test]
    fn test_reconcile_report_conflicts_preserve_both_sides() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let s1 = alice.send(bob.id(), 100, &mut vc).unwrap();
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let s2 = alice.send(carol.id(), 100, &mut vc).unwrap();
        let p_a = vec![alice.chain[0].clone(), s1.clone()];
        let p_b = vec![alice.chain[0].clone(), s2.clone()];
        let report = reconcile_partitions(&p_a, &p_b).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        let c = &report.conflicts[0];
        let loser = if c.winner_hash == s1.hash {
            &s2.hash
        } else {
            &s1.hash
        };
        assert!(c.loser_hashes.contains(loser));
    }

    // ========================================================================
    // Adversarial tests for CRIT-017 (phantom RECEIVE credits receiver)
    // ========================================================================

    /// Helper: build a Receive block with an attacker-chosen source_hash
    /// for a specific receiver. The block is signed by `receiver` so
    /// structural-level checks (if any) pass; only reconciliation's
    /// phantom-receive guard should stop it.
    fn craft_receive_pointing_to(
        receiver: &mut AccountChain,
        bogus_source_hash: &str,
        vc: &mut VectorClock,
    ) -> Block {
        use arxia_lattice::block::BlockType;
        use ed25519_dalek::Signer;

        let previous = receiver
            .chain
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        let timestamp = arxia_core::now_millis();
        let new_balance = receiver.balance + 1_000_000; // attacker claims 1M credit
        let new_nonce = receiver.nonce + 1;
        let block_type = BlockType::Receive {
            source_hash: bogus_source_hash.to_string(),
        };
        let hash = Block::compute_hash(
            &receiver.public_key_hex,
            &previous,
            &block_type,
            new_balance,
            new_nonce,
            timestamp,
        );
        let hash_bytes = hex::decode(&hash).unwrap();
        let signature = receiver.signing_key().sign(&hash_bytes).to_bytes().to_vec();
        let block = Block {
            account: receiver.public_key_hex.clone(),
            previous,
            block_type,
            balance: new_balance,
            nonce: new_nonce,
            timestamp,
            hash,
            signature,
        };
        // Reflect local state only so subsequent tests can build on top
        // if needed.
        receiver.balance = new_balance;
        receiver.nonce = new_nonce;
        receiver.chain.push(block.clone());
        let _ = vc; // vc tick skipped for adversarial test; not material
        block
    }

    #[test]
    fn test_reconcile_rejects_receive_pointing_to_unknown_send() {
        // Bob crafts a RECEIVE block citing a source_hash that no SEND
        // in either partition actually has. The pre-011 code silently
        // credited bob's balance by the block's balance-delta. The
        // post-011 code rejects it.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();

        let bogus_hash = "ff".repeat(32);
        let phantom = craft_receive_pointing_to(&mut bob, &bogus_hash, &mut vc);

        let partition_a = alice.chain.clone();
        let mut partition_b = bob.chain.clone();
        partition_b.remove(partition_b.len() - 1); // drop local state of the phantom
        partition_b.push(phantom.clone());

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        // The phantom RECEIVE must NOT credit Bob.
        let bob_bal = report.balances.get(bob.id()).copied().unwrap_or(0);
        assert_eq!(
            bob_bal, 0,
            "phantom receive credited bob: bal = {}",
            bob_bal
        );

        // Report must surface the rejection.
        assert_eq!(report.rejected_receives.len(), 1);
        let rr = &report.rejected_receives[0];
        assert_eq!(rr.account, bob.id());
        assert_eq!(rr.source_hash, bogus_hash);
        assert_eq!(rr.reason, "source_not_found");
    }

    #[test]
    fn test_reconcile_accepts_legit_receive() {
        // Regression guard: legitimate SEND→RECEIVE must still be
        // accepted and must credit the correct amount.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();
        let send = alice.send(bob.id(), 100, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();

        let partition_a = alice.chain.clone();
        let partition_b = bob.chain.clone();
        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        assert_eq!(report.balances[alice.id()], 1_000_000 - 100);
        assert_eq!(report.balances[bob.id()], 100);
        assert!(report.rejected_receives.is_empty());
    }

    #[test]
    fn test_reconcile_rejects_receive_when_send_lost_the_conflict() {
        // Subtle case: Alice signs two SENDs at the same nonce (to Bob
        // and to Carol). Bob builds a RECEIVE for his SEND. After
        // reconciliation, the hash tiebreaker may pick Carol's SEND as
        // the winner — in which case Bob's SEND is a LOSER and his
        // RECEIVE cites a source that is not in `applied_sends`. Bob
        // must NOT get credited.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        let carol = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();

        let send_bob = alice.send(bob.id(), 100, &mut vc).unwrap();
        // Rewind Alice and double-spend to Carol
        alice.chain.pop();
        alice.balance += 100;
        alice.nonce -= 1;
        alice.consumed_sources.clear();
        let send_carol = alice.send(carol.id(), 100, &mut vc).unwrap();

        // Bob creates the RECEIVE for send_bob.
        bob.receive(&send_bob, &mut vc).unwrap();

        // Partition A has Alice's open + send_bob + Bob's open+receive.
        // Partition B has Alice's open + send_carol.
        let partition_a = vec![
            alice.chain[0].clone(),
            send_bob.clone(),
            bob.chain[0].clone(),
            bob.chain[1].clone(),
        ];
        let partition_b = vec![alice.chain[0].clone(), send_carol.clone()];

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        // Whichever SEND wins, alice balance is 1_000_000 - 100 = 999_900
        assert_eq!(report.balances[alice.id()], 999_900);

        // If send_bob LOST (send_carol has smaller hash), Bob's RECEIVE
        // references a non-applied SEND → rejected_receives grows, Bob
        // stays at 0. If send_bob WON, Bob is credited 100, no
        // rejection.
        let bob_won = send_bob.hash < send_carol.hash;
        if bob_won {
            assert_eq!(report.balances[bob.id()], 100);
            assert!(report.rejected_receives.is_empty());
        } else {
            let bob_bal = report.balances.get(bob.id()).copied().unwrap_or(0);
            assert_eq!(bob_bal, 0);
            assert_eq!(report.rejected_receives.len(), 1);
            assert_eq!(report.rejected_receives[0].reason, "source_not_found");
        }
    }

    #[test]
    fn test_reconcile_rejects_receive_with_destination_mismatch() {
        // Alice sends 100 to Bob. Eve crafts a RECEIVE that cites Alice's
        // legit SEND hash but claims the receiver is Eve (i.e., Eve's
        // account). Since the SEND's destination is Bob, not Eve, the
        // RECEIVE must be rejected for destination_mismatch.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let bob = AccountChain::new();
        let mut eve = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        eve.open(0, &mut vc).unwrap();
        let send_to_bob = alice.send(bob.id(), 100, &mut vc).unwrap();

        // Eve crafts a RECEIVE with source = send_to_bob.hash
        let eve_phantom = craft_receive_pointing_to(&mut eve, &send_to_bob.hash, &mut vc);

        let partition_a = alice.chain.clone();
        // eve.chain includes the phantom; include from alice and eve
        let mut partition_b = eve.chain.clone();
        partition_b.remove(partition_b.len() - 1);
        partition_b.push(eve_phantom.clone());

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        let eve_bal = report.balances.get(eve.id()).copied().unwrap_or(0);
        assert_eq!(eve_bal, 0, "eve stole funds via phantom receive");
        assert_eq!(report.rejected_receives.len(), 1);
        assert_eq!(report.rejected_receives[0].account, eve.id());
        assert_eq!(report.rejected_receives[0].reason, "destination_mismatch");
    }

    #[test]
    fn test_reconcile_rejects_many_phantoms_same_receiver() {
        // A receiver crafting 100 phantom RECEIVEs must see ZERO credit
        // from reconciliation, and 100 entries in rejected_receives.
        //
        // This also exercises the (account, nonce) dedup: because all
        // 100 phantoms would have increasing nonces, each lands in a
        // unique (account, nonce) bucket and goes through the
        // rejection path individually.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(0, &mut vc).unwrap();

        let bogus = "de".repeat(32);
        for _ in 0..100 {
            let _ = craft_receive_pointing_to(&mut bob, &bogus, &mut vc);
        }

        let partition_a = alice.chain.clone();
        // Take only bob's genesis and skip the garbage local state;
        // feed the 100 phantoms through the partition directly.
        let mut partition_b = vec![bob.chain[0].clone()];
        partition_b.extend(bob.chain.iter().skip(1).cloned());

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        let bob_bal = report.balances.get(bob.id()).copied().unwrap_or(0);
        assert_eq!(bob_bal, 0);
        assert_eq!(report.rejected_receives.len(), 100);
        for rr in &report.rejected_receives {
            assert_eq!(rr.reason, "source_not_found");
        }
    }
}
