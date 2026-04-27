//! Conflict resolution with 3-tier ORV cascade.
//!
//! # Block-type gate (HIGH-025, commit 035)
//!
//! [`resolve_conflict_orv`] is the *monetary / chain-continuity*
//! adjudicator. It decides which of two competing blocks at the same
//! `(account, nonce)` is the canonical chain extension by running a
//! 3-tier cascade: stake-weighted majority → hash tiebreaker.
//!
//! Pre-fix the function accepted any [`BlockType`] including
//! `Revoke` (DID credential revocation). The audit (HIGH-025):
//!
//! > Feed it a `BlockType::Revoke` (DID credential revocation) as
//! > one side of a "double-spend"; stake-weighted resolution treats
//! > the Revoke as a monetary block. Semantics of consensus and DID
//! > conflated; Revoke "wins" against a Send and is applied by the
//! > reconciliation pipeline.
//!
//! Fix: only `{Open, Send, Receive}` are eligible. Any block whose
//! type is `Revoke` is rejected with
//! [`ArxiaError::IneligibleConflictBlockType`] before any stake
//! computation. Combined with HIGH-006 (commit 034,
//! [`crate::vote::verify_vote_known`]), this closes the CROSS-05
//! cascade: a vote can no longer steer a Revoke into the cascade,
//! and a Revoke can no longer enter the cascade in the first place.
//!
//! # Double-spend reporting (HIGH-005, commit 033)
//!
//! [`detect_double_spend`] scans a slice of blocks for `(account, nonce)`
//! collisions. Each collision group is reported as a tuple
//! `(winner: Block, losers: Vec<Block>, reason: &'static str)`:
//!
//! - **All competitors are surfaced.** A group of N ≥ 2 blocks at the same
//!   `(account, nonce)` produces exactly one tuple with `1 + losers.len() == N`.
//!   Pre-fix the function returned only `(group[0], group[1])` and silently
//!   dropped the third (and beyond) competitor.
//! - **Winner is the first block in input order** for that
//!   `(account, nonce)`. It is *not* a semantic choice — the caller is
//!   expected to feed the conflict into [`resolve_conflict_orv`] which
//!   applies the 3-tier ORV cascade (stake-weighted → hash tiebreaker)
//!   to pick the actual canonical block. `detect_double_spend`'s job is
//!   *enumeration*, not resolution.
//! - **Iteration order is sorted by `(account, nonce)`.** Implementation
//!   uses a `BTreeMap` so the returned `Vec` is deterministic across
//!   runs. Callers can index into it stably for tests and logs.
//!
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-005, HIGH-025 (and CROSS-05).

use crate::vote::VoteORV;
use arxia_core::ArxiaError;
use arxia_lattice::block::{Block, BlockType};
use std::collections::BTreeMap;

/// A block candidate paired with its supporting votes.
#[derive(Debug)]
pub struct BlockCandidate<'a> {
    /// The candidate block.
    pub block: &'a Block,
    /// Votes supporting this block.
    pub votes: &'a [VoteORV],
}

/// Returns the variant tag of a `BlockType` as a static string, for
/// logging and error payloads. Stays in sync with `BlockType` by
/// being exhaustive (the `match` will fail to compile if a new
/// variant is added without updating this table).
fn block_type_tag(block: &Block) -> &'static str {
    match block.block_type {
        BlockType::Open { .. } => "Open",
        BlockType::Send { .. } => "Send",
        BlockType::Receive { .. } => "Receive",
        BlockType::Revoke { .. } => "Revoke",
    }
}

/// Returns `true` iff the block's type is eligible to enter the ORV
/// cascade. Only monetary / chain-continuity types qualify;
/// `Revoke` is excluded by HIGH-025.
fn is_eligible_for_orv(block: &Block) -> bool {
    matches!(
        block.block_type,
        BlockType::Open { .. } | BlockType::Send { .. } | BlockType::Receive { .. }
    )
}

/// Resolves a conflict between two competing blocks using 3-tier ORV cascade.
///
/// Both blocks must have an ORV-eligible type
/// (`{Open, Send, Receive}`). A `Revoke` block on either side is
/// rejected with [`ArxiaError::IneligibleConflictBlockType`] before
/// any stake computation — see HIGH-025 in the module docstring.
pub fn resolve_conflict_orv<'a>(
    block_a: &'a Block,
    block_b: &'a Block,
    votes_a: &[VoteORV],
    votes_b: &[VoteORV],
) -> Result<(&'a Block, &'static str), ArxiaError> {
    // HIGH-025 gate: reject ineligible block types BEFORE any stake
    // computation. Order: block_a first, block_b second — the error
    // payload identifies which side carried the offending type.
    if !is_eligible_for_orv(block_a) {
        return Err(ArxiaError::IneligibleConflictBlockType {
            block_hash: block_a.hash.clone(),
            block_type: block_type_tag(block_a).to_string(),
        });
    }
    if !is_eligible_for_orv(block_b) {
        return Err(ArxiaError::IneligibleConflictBlockType {
            block_hash: block_b.hash.clone(),
            block_type: block_type_tag(block_b).to_string(),
        });
    }

    let stake_a: u64 = votes_a.iter().map(|v| v.delegated_stake).sum();
    let stake_b: u64 = votes_b.iter().map(|v| v.delegated_stake).sum();
    let total_stake = stake_a.saturating_add(stake_b);

    if total_stake > 0 {
        // `u64::abs_diff` (stable since Rust 1.60) returns the absolute
        // difference without the if/else stake_a > stake_b dance and
        // without any risk of underflow. Equivalent to:
        //     if stake_a > stake_b { stake_a - stake_b }
        //     else                  { stake_b - stake_a }
        // — but clippy >= 1.91 (manual_abs_diff lint) flags the
        // hand-rolled form, and `abs_diff` is more readable.
        let gap = stake_a.abs_diff(stake_b);
        if gap.saturating_mul(20) > total_stake {
            if stake_a > stake_b {
                return Ok((block_a, "stake_weighted"));
            } else {
                return Ok((block_b, "stake_weighted"));
            }
        }
    }

    if block_a.hash <= block_b.hash {
        Ok((block_a, "hash_tiebreaker"))
    } else {
        Ok((block_b, "hash_tiebreaker"))
    }
}

/// Detects double-spend conflicts among a set of blocks.
///
/// Returns one tuple per `(account, nonce)` collision group, with shape
/// `(winner, losers, reason)`. `winner` is the first block at that
/// `(account, nonce)` in input order; `losers` contains every other
/// block at the same `(account, nonce)` (length `N - 1` for a group of
/// `N` competitors). The reason string is currently always `"same_nonce"`.
///
/// Iteration is sorted by `(account, nonce)` for deterministic output.
///
/// See module-level doc for the design rationale and HIGH-005 fix history.
pub fn detect_double_spend(blocks: &[Block]) -> Vec<(Block, Vec<Block>, &'static str)> {
    let mut nonce_map: BTreeMap<(String, u64), Vec<&Block>> = BTreeMap::new();
    let mut conflicts = Vec::new();
    for block in blocks {
        nonce_map
            .entry((block.account.clone(), block.nonce))
            .or_default()
            .push(block);
    }
    for group in nonce_map.values() {
        if group.len() > 1 {
            let winner = group[0].clone();
            let losers: Vec<Block> = group[1..].iter().map(|b| (*b).clone()).collect();
            conflicts.push((winner, losers, "same_nonce"));
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cast_vote;
    use arxia_crypto::generate_keypair;
    use arxia_lattice::chain::{AccountChain, VectorClock};

    #[test]
    fn test_resolve_conflict_stake_weighted() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let ha: [u8; 32] = hex::decode(&ba.hash).unwrap().try_into().unwrap();
        let hb: [u8; 32] = hex::decode(&bb.hash).unwrap().try_into().unwrap();
        let va = vec![
            cast_vote(&sk1, ha, 10_000_000, 1),
            cast_vote(&sk2, ha, 10_000_000, 1),
        ];
        let vb = vec![cast_vote(&sk1, hb, 1_000_000, 2)];
        let (w, m) = resolve_conflict_orv(&ba, &bb, &va, &vb).unwrap();
        assert_eq!(m, "stake_weighted");
        assert_eq!(w.hash, ba.hash);
    }

    #[test]
    fn test_detect_double_spend() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        let conflicts = detect_double_spend(&[ba, bb]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].2, "same_nonce");
    }

    #[test]
    fn test_detect_no_double_spend() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let b1 = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        let b2 = alice.send(bob.id(), 20_000, &mut vclock).unwrap();
        assert!(detect_double_spend(&[b1, b2]).is_empty());
    }

    /// Regression guard for commit 024 (`clippy::manual_abs_diff`).
    /// Pins the symmetry of the gap computation in
    /// [`resolve_conflict_orv`]: regardless of which side has more
    /// stake, the absolute gap drives the same decision branch. If a
    /// future refactor reintroduces the hand-rolled `if/else` form,
    /// `cargo clippy --workspace -- -D warnings` (Gate 2) will flag
    /// it on a sufficiently recent rustc; this test is a behavioral
    /// double-check that exercises both stake_a > stake_b and
    /// stake_b > stake_a branches and asserts the same winner-by-
    /// stake outcome.
    #[test]
    fn test_resolve_conflict_orv_gap_is_symmetric_in_stake_swap() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let ha: [u8; 32] = hex::decode(&ba.hash).unwrap().try_into().unwrap();
        let hb: [u8; 32] = hex::decode(&bb.hash).unwrap().try_into().unwrap();
        let va_bigger = vec![
            cast_vote(&sk1, ha, 10_000_000, 1),
            cast_vote(&sk2, ha, 10_000_000, 1),
        ];
        let vb_smaller = vec![cast_vote(&sk1, hb, 1_000_000, 2)];
        let (w, m) = resolve_conflict_orv(&ba, &bb, &va_bigger, &vb_smaller).unwrap();
        assert_eq!(m, "stake_weighted");
        assert_eq!(w.hash, ba.hash);
        // Swap the vote assignments: stake_b is now bigger. The gap is
        // computed via abs_diff so the same threshold check fires; the
        // winner is now block_b.
        let va_smaller = vec![cast_vote(&sk1, ha, 1_000_000, 2)];
        let vb_bigger = vec![
            cast_vote(&sk1, hb, 10_000_000, 1),
            cast_vote(&sk2, hb, 10_000_000, 1),
        ];
        let (w2, m2) = resolve_conflict_orv(&ba, &bb, &va_smaller, &vb_bigger).unwrap();
        assert_eq!(m2, "stake_weighted");
        assert_eq!(w2.hash, bb.hash);
    }

    // ============================================================
    // HIGH-005 (commit 033) — detect_double_spend reports ALL
    // competitors per (account, nonce) group, not just the first
    // pair.
    // ============================================================

    /// Forge `n` SENDs from `alice` at the SAME nonce to `n` distinct
    /// destinations.
    fn forge_n_way_same_nonce(
        alice: &mut AccountChain,
        n: usize,
        vclock: &mut VectorClock,
    ) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let dest = AccountChain::new();
            let amount = 10_000u64 + i as u64;
            let b = alice.send(dest.id(), amount, vclock).unwrap();
            out.push(b);
            // Roll back so the next .send() reuses the same nonce.
            alice.chain.pop();
            alice.balance += amount;
            alice.nonce -= 1;
        }
        out
    }

    #[test]
    fn test_detect_double_spend_3way_returns_all_competitors() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let blocks = forge_n_way_same_nonce(&mut alice, 3, &mut vclock);
        let conflicts = detect_double_spend(&blocks);
        assert_eq!(conflicts.len(), 1, "3-way collision = 1 group");
        assert_eq!(conflicts[0].2, "same_nonce");
        assert_eq!(
            conflicts[0].1.len(),
            2,
            "HIGH-005: must report 2 losers for a 3-way collision, not 1"
        );
    }

    #[test]
    fn test_detect_double_spend_4way_returns_all_competitors() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let blocks = forge_n_way_same_nonce(&mut alice, 4, &mut vclock);
        let conflicts = detect_double_spend(&blocks);
        assert_eq!(conflicts.len(), 1, "4-way collision = 1 group");
        assert_eq!(
            conflicts[0].1.len(),
            3,
            "HIGH-005: must report 3 losers for a 4-way collision"
        );
        assert_eq!(1 + conflicts[0].1.len(), blocks.len());
    }

    #[test]
    fn test_detect_double_spend_2way_pins_single_loser() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let blocks = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let conflicts = detect_double_spend(&blocks);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].1.len(), 1, "2-way collision = 1 loser");
        assert_eq!(conflicts[0].2, "same_nonce");
    }

    #[test]
    fn test_detect_double_spend_two_distinct_groups_each_complete() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let n1_3way = forge_n_way_same_nonce(&mut alice, 3, &mut vclock);
        let dest = AccountChain::new();
        alice.send(dest.id(), 10_000, &mut vclock).unwrap();
        let n2_2way = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let mut all = n1_3way.clone();
        all.extend_from_slice(&n2_2way);
        let conflicts = detect_double_spend(&all);
        assert_eq!(conflicts.len(), 2, "two distinct (account, nonce) groups");
        let total_competitors: usize = conflicts
            .iter()
            .map(|(_, losers, _)| 1 + losers.len())
            .sum();
        assert_eq!(total_competitors, 5);
        for (_, _, reason) in &conflicts {
            assert_eq!(*reason, "same_nonce");
        }
    }

    #[test]
    fn test_detect_double_spend_winner_plus_losers_equals_total_competitors() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let blocks = forge_n_way_same_nonce(&mut alice, 5, &mut vclock);
        let conflicts = detect_double_spend(&blocks);
        assert_eq!(conflicts.len(), 1);
        let (winner, losers, reason) = &conflicts[0];
        assert_eq!(*reason, "same_nonce");
        assert_eq!(losers.len(), 4, "5-way → 4 losers");
        let mut hashes: std::collections::HashSet<&str> = std::collections::HashSet::new();
        hashes.insert(&winner.hash);
        for l in losers {
            assert!(hashes.insert(&l.hash), "duplicate hash in losers");
        }
        assert_eq!(hashes.len(), 5);
        let input_hashes: std::collections::HashSet<&str> =
            blocks.iter().map(|b| b.hash.as_str()).collect();
        assert_eq!(hashes, input_hashes);
    }

    #[test]
    fn test_detect_double_spend_ordering_is_deterministic_across_runs() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let n1 = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let dest = AccountChain::new();
        alice.send(dest.id(), 10_000, &mut vclock).unwrap();
        let n2 = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let nonce_lo = n1[0].nonce;
        let nonce_hi = n2[0].nonce;
        assert!(nonce_lo < nonce_hi, "test setup invariant");
        let mut input_a = n1.clone();
        input_a.extend_from_slice(&n2);
        let conflicts_a = detect_double_spend(&input_a);
        let mut input_b: Vec<Block> = n2.clone();
        input_b.extend_from_slice(&n1);
        let conflicts_b = detect_double_spend(&input_b);
        assert_eq!(conflicts_a.len(), 2);
        assert_eq!(conflicts_b.len(), 2);
        assert_eq!(conflicts_a[0].0.nonce, nonce_lo);
        assert_eq!(conflicts_a[1].0.nonce, nonce_hi);
        assert_eq!(conflicts_b[0].0.nonce, nonce_lo);
        assert_eq!(conflicts_b[1].0.nonce, nonce_hi);
    }

    // ============================================================
    // HIGH-025 (commit 035) — resolve_conflict_orv block-type gate.
    // Only {Open, Send, Receive} are eligible. Revoke is rejected
    // before any stake computation.
    // ============================================================

    /// Mutate a block's `block_type` to `Revoke` while leaving the
    /// rest of its fields intact. The hash is left in the original
    /// state because the gate fires BEFORE any hash check; this is
    /// the exact attacker shape (a Revoke block with valid-looking
    /// metadata fed into the cascade as if it were monetary).
    fn make_revoke_variant(mut b: Block) -> Block {
        b.block_type = BlockType::Revoke {
            credential_hash: "ab".repeat(32),
        };
        b
    }

    /// Build a fresh Send-vs-Send conflict pair for the gate tests.
    /// Returns `(ba, bb)`, both Send blocks at the same `(account,
    /// nonce)` to distinct destinations.
    fn build_send_conflict_pair() -> (Block, Block) {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        (ba, bb)
    }

    #[test]
    fn test_resolve_conflict_orv_rejects_revoke_as_block_a() {
        // PRIMARY HIGH-025 PIN: a Revoke on side A must be rejected
        // BEFORE any stake math. Pre-fix the function would accept
        // it and run the cascade as if it were monetary.
        let (ba, bb) = build_send_conflict_pair();
        let revoke_a = make_revoke_variant(ba);
        let result = resolve_conflict_orv(&revoke_a, &bb, &[], &[]);
        let err = result.expect_err("Revoke on side A must be rejected");
        match err {
            ArxiaError::IneligibleConflictBlockType {
                block_hash,
                block_type,
            } => {
                assert_eq!(block_hash, revoke_a.hash);
                assert_eq!(block_type, "Revoke");
            }
            other => panic!("expected IneligibleConflictBlockType, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_conflict_orv_rejects_revoke_as_block_b() {
        // Side-B Revoke must also be rejected. Order of arguments
        // does not let an attacker bypass the gate.
        let (ba, bb) = build_send_conflict_pair();
        let revoke_b = make_revoke_variant(bb);
        let result = resolve_conflict_orv(&ba, &revoke_b, &[], &[]);
        let err = result.expect_err("Revoke on side B must be rejected");
        match err {
            ArxiaError::IneligibleConflictBlockType {
                block_hash,
                block_type,
            } => {
                assert_eq!(block_hash, revoke_b.hash);
                assert_eq!(block_type, "Revoke");
            }
            other => panic!("expected IneligibleConflictBlockType, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_conflict_orv_rejects_when_both_sides_are_revoke() {
        // Both sides Revoke: still rejected. The error reports
        // side-A first (the first ineligibility encountered), so the
        // gate is order-deterministic and easy to interpret in
        // logs.
        let (ba, bb) = build_send_conflict_pair();
        let revoke_a = make_revoke_variant(ba);
        let revoke_b = make_revoke_variant(bb);
        let result = resolve_conflict_orv(&revoke_a, &revoke_b, &[], &[]);
        let err = result.expect_err("both-Revoke must be rejected");
        match err {
            ArxiaError::IneligibleConflictBlockType {
                block_hash,
                block_type,
            } => {
                // First ineligible encountered = block_a.
                assert_eq!(block_hash, revoke_a.hash);
                assert_eq!(block_type, "Revoke");
            }
            other => panic!("expected IneligibleConflictBlockType, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_conflict_orv_accepts_send_vs_send() {
        // Boundary: both sides Send (the canonical case) succeeds.
        // Pins that the gate does not over-reject. This is also the
        // shape exercised by the pre-existing
        // test_resolve_conflict_stake_weighted, but explicit here as
        // a regression guard against an over-broad gate.
        let (ba, bb) = build_send_conflict_pair();
        let result = resolve_conflict_orv(&ba, &bb, &[], &[]);
        assert!(result.is_ok(), "Send-vs-Send must succeed");
        let (_, reason) = result.unwrap();
        // No votes ⇒ falls through to hash_tiebreaker.
        assert_eq!(reason, "hash_tiebreaker");
    }

    #[test]
    fn test_resolve_conflict_orv_accepts_open_vs_open() {
        // Boundary: two Open blocks (genesis re-attempts at the
        // same account, e.g. after a partition merge race) must be
        // ORV-eligible. Pins that Open is in the allowlist.
        let mut alice = AccountChain::new();
        let mut vclock_a = VectorClock::new();
        alice.open(100_000_000, &mut vclock_a).unwrap();
        let oa = alice.chain[0].clone();
        let mut alice2 = AccountChain::new();
        let mut vclock_b = VectorClock::new();
        alice2.open(50_000_000, &mut vclock_b).unwrap();
        let ob = alice2.chain[0].clone();
        let result = resolve_conflict_orv(&oa, &ob, &[], &[]);
        assert!(result.is_ok(), "Open-vs-Open must succeed");
    }

    #[test]
    fn test_resolve_conflict_orv_gate_fires_before_stake_math() {
        // Stake fed in but the gate must still reject. Pins the
        // ordering: gate runs FIRST, even when votes are present
        // and would otherwise produce a stake_weighted decision.
        // Pre-fix the function would have run the cascade and
        // returned a (Revoke, "stake_weighted") tuple — silent
        // semantic corruption.
        let (ba, bb) = build_send_conflict_pair();
        let revoke_a = make_revoke_variant(ba);
        let (sk1, _) = generate_keypair();
        let ha: [u8; 32] = hex::decode(&revoke_a.hash).unwrap().try_into().unwrap();
        let hb: [u8; 32] = hex::decode(&bb.hash).unwrap().try_into().unwrap();
        let va = vec![cast_vote(&sk1, ha, 100_000_000, 1)]; // overwhelming stake
        let vb = vec![cast_vote(&sk1, hb, 1, 2)];
        let result = resolve_conflict_orv(&revoke_a, &bb, &va, &vb);
        assert!(
            matches!(result, Err(ArxiaError::IneligibleConflictBlockType { .. })),
            "gate must fire before stake math runs"
        );
    }
}
