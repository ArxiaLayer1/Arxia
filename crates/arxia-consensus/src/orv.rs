//! ORV vote collection and eligibility filtering.

use crate::vote::VoteORV;

/// Minimum stake denominator for representative eligibility.
///
/// MED-005 (commit 063): integer denominator replacing the old
/// `f64` constant `0.001`. `min_stake = total_supply / 1000`
/// is the integer-equivalent of "≥ 0.1 % of total supply" and
/// avoids the boundary indeterminism of `f64` multiplication.
pub const MIN_REPRESENTATIVE_STAKE_DENOM: u64 = 1_000;

/// Audit record for vote collection.
///
/// MED-005 (commit 063): pre-fix `collect_votes` returned only
/// the accepted set ; ineligible votes were silently dropped.
/// The audit form returns both buckets and the threshold so a
/// caller (or downstream observability) can tell *why* a vote
/// was excluded without having to recompute the threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct CollectedVotes {
    /// Votes from eligible representatives.
    pub accepted: Vec<VoteORV>,
    /// Votes filtered out for insufficient stake.
    pub filtered: Vec<VoteORV>,
    /// Effective minimum stake threshold used (micro-ARX).
    pub min_stake: u64,
}

/// Collects votes with an audit trail of filtered votes.
///
/// Returns both the accepted votes and the votes filtered out
/// for insufficient stake, plus the effective threshold. The
/// threshold is `total_supply / MIN_REPRESENTATIVE_STAKE_DENOM`
/// (integer division ; MED-005 replaces the old `f64` form).
pub fn collect_votes_with_audit(votes: &[VoteORV], total_supply: u64) -> CollectedVotes {
    let min_stake = total_supply / MIN_REPRESENTATIVE_STAKE_DENOM;
    let mut accepted = Vec::new();
    let mut filtered = Vec::new();
    for v in votes {
        if v.delegated_stake >= min_stake {
            accepted.push(v.clone());
        } else {
            filtered.push(v.clone());
        }
    }
    CollectedVotes {
        accepted,
        filtered,
        min_stake,
    }
}

/// Collects votes from eligible representatives (>= 0.1% of total supply).
///
/// Backward-compatible shim ; for the audit form (filtered set
/// + threshold) call [`collect_votes_with_audit`].
pub fn collect_votes(votes: &[VoteORV], total_supply: u64) -> Vec<VoteORV> {
    collect_votes_with_audit(votes, total_supply).accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cast_vote;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_collect_votes_filters() {
        let total = 1_000_000_000u64;
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let bh = [0xAA; 32];
        let v1 = cast_vote(&sk1, bh, min, 1);
        let v2 = cast_vote(&sk2, bh, min - 1, 2);
        let eligible = collect_votes(&[v1.clone(), v2], total);
        assert_eq!(eligible.len(), 1);
        assert!(eligible.contains(&v1));
    }

    #[test]
    fn test_minimum_stake_calculation() {
        let total = 1_000_000_000u64;
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        assert_eq!(min, 1_000_000);
    }

    // ============================================================
    // MED-005 (commit 063) — collect_votes_with_audit
    // (pre-fix dropped ineligible votes silently). Pin the
    // partition (accepted + filtered = input) and the integer
    // threshold.
    // ============================================================

    #[test]
    fn test_collect_votes_with_audit_returns_filtered_set() {
        // PRIMARY MED-005 PIN: ineligible votes appear in
        // `filtered`, not silently dropped. Caller sees why a
        // vote was excluded.
        let total = 1_000_000_000u64;
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let (sk3, _) = generate_keypair();
        let bh = [0xCC; 32];
        let big = cast_vote(&sk1, bh, min, 1);
        let small_a = cast_vote(&sk2, bh, min - 1, 2);
        let small_b = cast_vote(&sk3, bh, 0, 3);
        let audit =
            collect_votes_with_audit(&[big.clone(), small_a.clone(), small_b.clone()], total);
        assert_eq!(audit.accepted.len(), 1);
        assert!(audit.accepted.contains(&big));
        assert_eq!(audit.filtered.len(), 2);
        assert!(audit.filtered.contains(&small_a));
        assert!(audit.filtered.contains(&small_b));
        assert_eq!(audit.min_stake, min);
    }

    #[test]
    fn test_collect_votes_with_audit_partition_invariant() {
        // accepted.len() + filtered.len() == input.len(). No
        // vote is duplicated, none silently dropped.
        let total = 5_000_000_000u64;
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let (sk3, _) = generate_keypair();
        let (sk4, _) = generate_keypair();
        let bh = [0xDD; 32];
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        let votes = vec![
            cast_vote(&sk1, bh, min * 2, 1),
            cast_vote(&sk2, bh, min, 2),
            cast_vote(&sk3, bh, min - 1, 3),
            cast_vote(&sk4, bh, 0, 4),
        ];
        let audit = collect_votes_with_audit(&votes, total);
        assert_eq!(audit.accepted.len() + audit.filtered.len(), votes.len());
    }

    #[test]
    fn test_collect_votes_integer_threshold_no_f64_drift() {
        // MED-005: integer threshold = total / 1000 ; no f64
        // multiplication. For total_supply not divisible by
        // 1000, integer truncates *down* — accepting at the
        // truncated boundary is the documented contract.
        let total = 1_000_000_999u64; // not div by 1000
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        assert_eq!(min, 1_000_000); // truncated
        let (sk, _) = generate_keypair();
        let bh = [0xEE; 32];
        // Vote at exactly min: accepted (>=, integer).
        let v_at = cast_vote(&sk, bh, min, 1);
        let audit = collect_votes_with_audit(std::slice::from_ref(&v_at), total);
        assert_eq!(audit.accepted.len(), 1);
        assert!(audit.filtered.is_empty());
        assert_eq!(audit.min_stake, min);
    }

    #[test]
    fn test_collect_votes_backward_compat_shim() {
        // Pin: legacy `collect_votes` returns only accepted —
        // matches the audit form's `accepted` field exactly.
        let total = 1_000_000_000u64;
        let min = total / MIN_REPRESENTATIVE_STAKE_DENOM;
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let bh = [0xFF; 32];
        let v1 = cast_vote(&sk1, bh, min, 1);
        let v2 = cast_vote(&sk2, bh, min - 1, 2);
        let votes = vec![v1, v2];
        let legacy = collect_votes(&votes, total);
        let audit = collect_votes_with_audit(&votes, total);
        assert_eq!(legacy, audit.accepted);
    }

    #[test]
    fn test_collect_votes_zero_total_supply_filters_all_nonzero() {
        // Edge: total_supply == 0 → min_stake == 0. All votes
        // with delegated_stake >= 0 are accepted (any u64 >=
        // 0). No votes go to `filtered`. This pins the
        // documented behaviour and rules out a panic on the
        // division.
        let (sk1, _) = generate_keypair();
        let bh = [0x11; 32];
        let v1 = cast_vote(&sk1, bh, 0, 1);
        let audit = collect_votes_with_audit(std::slice::from_ref(&v1), 0);
        assert_eq!(audit.accepted.len(), 1);
        assert!(audit.filtered.is_empty());
        assert_eq!(audit.min_stake, 0);
    }
}
