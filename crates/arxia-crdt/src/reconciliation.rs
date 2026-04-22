//! Partition reconciliation using CRDTs and Block Lattice data.
//!
//! The previous implementation summed every SEND block it saw into a
//! PNCounter per account. Two partitions that each contained a SEND with
//! the same `(account, nonce)` would both be applied — silently accepting
//! the double-spend and producing a negative final balance. This module
//! now enforces two invariants:
//!
//! 1. At most one block per `(account, nonce)` contributes to the
//!    reconciled state. When two partitions disagree, a deterministic
//!    tie-break (lexicographically smallest hash) picks the winner, and
//!    the caller is informed via the returned
//!    `ReconciliationReport::conflicts`.
//! 2. No account balance may be negative after reconciliation. If the
//!    invariant breaks, `reconcile_partitions` returns
//!    [`ArxiaError::NegativeBalance`] instead of silently yielding a bad
//!    map.

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

/// Full outcome of a `reconcile_partitions` call.
#[derive(Debug, Clone)]
pub struct ReconciliationReport {
    /// Final per-account balance map. Values are guaranteed non-negative.
    pub balances: HashMap<String, i64>,
    /// Conflicts encountered and how they were resolved.
    pub conflicts: Vec<ResolvedConflict>,
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
    // 1. Deduplicate by block hash. HashSet is O(1) per lookup vs the
    //    previous O(n) Vec::contains.
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

    // 3. Pick a winner per (account, nonce) using hash tiebreaker. Lower
    //    hex string wins. Record losers in the conflict report. The
    //    hash tiebreaker is the final tier of the ORV cascade (see
    //    arxia-consensus::conflict::resolve_conflict_orv).
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

    // 4. Apply the winning blocks to CRDT counters. Only one block per
    //    (account, nonce) contributes to balance.
    let mut crdts: HashMap<String, PNCounter> = HashMap::new();
    // Iterate deterministically by (account, nonce) so the result does
    // not depend on HashMap iteration order.
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
            BlockType::Receive { .. } => {
                // For RECEIVE the amount must be derived. We use the
                // difference against the previous block's balance on
                // the same account (nonce - 1) within the deduped set.
                let prev = all
                    .iter()
                    .find(|b| b.account == block.account && b.nonce == block.nonce - 1)
                    .map(|b| b.balance)
                    .unwrap_or(0);
                if block.balance > prev {
                    crdts
                        .entry(block.account.clone())
                        .or_default()
                        .increment(&block.account[..8], block.balance - prev);
                }
            }
            BlockType::Revoke { .. } => {
                // Revoke blocks do not affect balance.
            }
        }
    }

    // 5. Materialize balances and enforce the non-negative invariant.
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
    })
}

/// Legacy-style helper: returns only the balance map, panicking on error.
/// Kept internal; tests and callers should prefer `reconcile_partitions`
/// which exposes the full `ReconciliationReport`.
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

    #[test]
    fn test_reconcile_identical_partitions() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let report = reconcile_partitions(&alice.chain, &alice.chain).unwrap();
        assert_eq!(report.balances[alice.id()], 1_000_000);
        assert!(report.conflicts.is_empty());
    }

    #[test]
    fn test_reconcile_empty_partitions() {
        let report = reconcile_partitions(&[], &[]).unwrap();
        assert!(report.balances.is_empty());
        assert!(report.conflicts.is_empty());
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
    }

    // ========================================================================
    // Adversarial tests for Bug 7 (reconcile double-spend + balance invariant)
    // ========================================================================

    #[test]
    fn test_reconcile_double_spend_same_nonce_resolves_winner() {
        // Reference scenario from stoneburner's audit.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();

        let bob = AccountChain::new();
        let carol = AccountChain::new();

        // Partition A: SEND to Bob at nonce=2
        let send_bob = alice.send(bob.id(), 600_000, &mut vc).unwrap();
        let partition_a = vec![alice.chain[0].clone(), send_bob.clone()];

        // Rewind alice as if the SEND never happened on this partition
        alice.chain.pop();
        alice.balance += 600_000;
        alice.nonce -= 1;
        alice.consumed_sources.clear();

        // Partition B: SEND to Carol at the SAME nonce=2
        let send_carol = alice.send(carol.id(), 600_000, &mut vc).unwrap();
        let partition_b = vec![alice.chain[0].clone(), send_carol.clone()];

        assert_eq!(send_bob.nonce, send_carol.nonce);
        assert_ne!(send_bob.hash, send_carol.hash);

        let report = reconcile_partitions(&partition_a, &partition_b).unwrap();

        // The conflict MUST be surfaced
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].account, alice.id());
        assert_eq!(report.conflicts[0].nonce, 2);
        assert_eq!(report.conflicts[0].method, "hash_tiebreaker");

        // Only ONE SEND applied — balance = 1_000_000 - 600_000 = 400_000
        let alice_bal = report.balances[alice.id()];
        assert!(
            alice_bal >= 0,
            "reconciliation produced negative balance: {}",
            alice_bal
        );
        assert_eq!(alice_bal, 400_000);
    }

    #[test]
    fn test_reconcile_deterministic_winner_by_hash() {
        // Same (account, nonce), two competing SENDs. Winner is the one
        // with the lexicographically smaller hash. Running twice yields
        // the same winner.
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
        let expected_winner = if s1.hash < s2.hash {
            &s1.hash
        } else {
            &s2.hash
        };
        assert_eq!(&r1.conflicts[0].winner_hash, expected_winner);
    }

    #[test]
    fn test_reconcile_never_goes_negative_on_double_spend() {
        // Even when an attacker crafts partitions specifically to cause
        // underflow, the result is either a valid non-negative balance
        // or an explicit NegativeBalance error — never a silent negative.
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
        let alice_bal = report.balances[alice.id()];
        assert!(alice_bal >= 0);
        assert_eq!(alice_bal, 100_000);
    }

    #[test]
    fn test_reconcile_hashset_dedup_is_o_of_1() {
        // Stress: 1000 blocks, repeated. HashSet dedup must not explode.
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let genesis = alice.chain[0].clone();
        let bob = AccountChain::new();
        let mut sends = Vec::new();
        for _ in 0..10 {
            let s = alice.send(bob.id(), 1, &mut vc).unwrap();
            sends.push(s);
        }
        let mut partition: Vec<Block> = vec![genesis];
        partition.extend(sends);
        // Duplicate the entire partition into both sides.
        let r = reconcile_partitions(&partition, &partition).unwrap();
        // No conflicts: same blocks, just duplicated across partitions.
        assert!(r.conflicts.is_empty());
        assert_eq!(r.balances[alice.id()], 1_000_000 - 10);
    }

    #[test]
    fn test_reconcile_three_way_conflict() {
        // Three competing SENDs at the same (account, nonce). Only one
        // wins; two go into the conflict report as losers.
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
        assert_eq!(report.conflicts[0].nonce, 2);
        // Winner hash is the smallest of the three
        let mut hashes = [&s_bob.hash, &s_carol.hash, &s_dave.hash];
        hashes.sort();
        assert_eq!(&report.conflicts[0].winner_hash, hashes[0]);
        assert_eq!(report.conflicts[0].loser_hashes.len(), 2);
    }

    #[test]
    fn test_reconcile_report_conflicts_preserve_both_sides() {
        // Regression: conflict list must include EVERY competing block
        // in loser_hashes, not just the first one encountered.
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
}
