//! Conflict resolution with 3-tier ORV cascade.
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
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-005.

use crate::vote::VoteORV;
use arxia_lattice::block::Block;
use std::collections::BTreeMap;

/// A block candidate paired with its supporting votes.
#[derive(Debug)]
pub struct BlockCandidate<'a> {
    /// The candidate block.
    pub block: &'a Block,
    /// Votes supporting this block.
    pub votes: &'a [VoteORV],
}

/// Resolves a conflict between two competing blocks using 3-tier ORV cascade.
pub fn resolve_conflict_orv<'a>(
    block_a: &'a Block,
    block_b: &'a Block,
    votes_a: &[VoteORV],
    votes_b: &[VoteORV],
) -> (&'a Block, &'static str) {
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
                return (block_a, "stake_weighted");
            } else {
                return (block_b, "stake_weighted");
            }
        }
    }

    if block_a.hash <= block_b.hash {
        (block_a, "hash_tiebreaker")
    } else {
        (block_b, "hash_tiebreaker")
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
        let (w, m) = resolve_conflict_orv(&ba, &bb, &va, &vb);
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
        let (w, m) = resolve_conflict_orv(&ba, &bb, &va_bigger, &vb_smaller);
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
        let (w2, m2) = resolve_conflict_orv(&ba, &bb, &va_smaller, &vb_bigger);
        assert_eq!(m2, "stake_weighted");
        assert_eq!(w2.hash, bb.hash);
    }

    // ============================================================
    // HIGH-005 (commit 033) — detect_double_spend reports ALL
    // competitors per (account, nonce) group, not just the first
    // pair. The pre-fix function returned `(group[0], group[1])`
    // and silently dropped the third+ block. The new contract is
    // `(winner, Vec<losers>, reason)` with `1 + losers.len() == N`
    // for an N-way collision.
    // ============================================================

    /// Forge `n` SENDs from `alice` at the SAME nonce to `n` distinct
    /// destinations. Each block is independently valid (signed,
    /// well-formed) — they only collide on `(account, nonce)`. Used
    /// by the new HIGH-005 adversarial tests below.
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
        // The fix: ALL 3 competitors are surfaced.
        // 1 winner + 2 losers == 3 total, NOT just the first pair.
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
        // Pin the invariant: 1 winner + N-1 losers == N total competitors.
        assert_eq!(1 + conflicts[0].1.len(), blocks.len());
    }

    #[test]
    fn test_detect_double_spend_2way_pins_single_loser() {
        // Boundary: the 2-way case (the original "first pair") must
        // still produce exactly 1 loser under the new shape. This
        // pins the API change against accidental over-reporting.
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
        // Two independent collisions: a 3-way at nonce=1, a 2-way at
        // nonce=2. Both must be fully reported. Pre-fix, the 3-way
        // would silently drop one block.
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let n1_3way = forge_n_way_same_nonce(&mut alice, 3, &mut vclock);
        // Advance: commit one block at nonce=1 to move nonce forward,
        // then re-collide at nonce=2.
        let dest = AccountChain::new();
        alice.send(dest.id(), 10_000, &mut vclock).unwrap();
        let n2_2way = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let mut all = n1_3way.clone();
        all.extend_from_slice(&n2_2way);
        let conflicts = detect_double_spend(&all);
        assert_eq!(conflicts.len(), 2, "two distinct (account, nonce) groups");
        // Sum of competitors across all groups must equal total
        // colliding inputs (3 + 2 = 5).
        let total_competitors: usize = conflicts
            .iter()
            .map(|(_, losers, _)| 1 + losers.len())
            .sum();
        assert_eq!(total_competitors, 5);
        // Every group must report "same_nonce".
        for (_, _, reason) in &conflicts {
            assert_eq!(*reason, "same_nonce");
        }
    }

    #[test]
    fn test_detect_double_spend_winner_plus_losers_equals_total_competitors() {
        // Stress: a 5-way collision. The pre-fix version silently
        // dropped 3 of the 5 competitors. This test pins the
        // 1 + N-1 == N invariant at scale.
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let blocks = forge_n_way_same_nonce(&mut alice, 5, &mut vclock);
        let conflicts = detect_double_spend(&blocks);
        assert_eq!(conflicts.len(), 1);
        let (winner, losers, reason) = &conflicts[0];
        assert_eq!(*reason, "same_nonce");
        assert_eq!(losers.len(), 4, "5-way → 4 losers");
        // Winner ⊕ losers must enumerate all 5 inputs (no duplicates,
        // no omissions).
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
        // BTreeMap-backed iteration: the order of returned groups is
        // sorted by (account, nonce). Re-running the same inputs in
        // different shuffles must produce the same sequence of
        // (winner, losers, reason) tuples (modulo the within-group
        // winner-vs-loser assignment, which is input-order dependent).
        // This test pins the sort-by-key contract documented at the
        // top of the file.
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let n1 = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        let dest = AccountChain::new();
        alice.send(dest.id(), 10_000, &mut vclock).unwrap();
        let n2 = forge_n_way_same_nonce(&mut alice, 2, &mut vclock);
        // Capture the actual nonces — we don't rely on a hardcoded
        // value because that depends on AccountChain::open's internal
        // counter convention. We just pin the *ordering*: the smaller
        // nonce comes first regardless of input shuffle.
        let nonce_lo = n1[0].nonce;
        let nonce_hi = n2[0].nonce;
        assert!(nonce_lo < nonce_hi, "test setup invariant");
        // Run 1: lo group first, hi group second.
        let mut input_a = n1.clone();
        input_a.extend_from_slice(&n2);
        let conflicts_a = detect_double_spend(&input_a);
        // Run 2: same blocks, reversed.
        let mut input_b: Vec<Block> = n2.clone();
        input_b.extend_from_slice(&n1);
        let conflicts_b = detect_double_spend(&input_b);
        // Both must list the lo-nonce group first (sorted by
        // (account, nonce)), then hi-nonce — regardless of input order.
        assert_eq!(conflicts_a.len(), 2);
        assert_eq!(conflicts_b.len(), 2);
        assert_eq!(conflicts_a[0].0.nonce, nonce_lo);
        assert_eq!(conflicts_a[1].0.nonce, nonce_hi);
        assert_eq!(conflicts_b[0].0.nonce, nonce_lo);
        assert_eq!(conflicts_b[1].0.nonce, nonce_hi);
    }
}
