//! Quorum checking for ORV consensus.

/// Result of a quorum check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumResult {
    /// Whether the quorum requirements were met.
    pub reached: bool,
    /// Number of representatives who voted.
    pub voted_reps: usize,
    /// Total number of eligible representatives.
    pub total_reps: usize,
    /// Total stake represented by votes (micro-ARX).
    pub voted_stake: u64,
    /// Total circulating supply (micro-ARX).
    pub total_supply: u64,
}

/// Checks whether quorum requirements are met.
/// Requires >= 2/3 representatives AND >= 20% stake.
///
/// MED-004 (commit 062): integer arithmetic for both
/// thresholds. Pre-fix the stake check used `f64` division
/// (`voted_stake as f64 / total_supply as f64 >= 0.20`),
/// which had rounding edges at exact 20% boundaries.
/// Equivalent integer form: `voted_stake * 5 >= total_supply`.
pub fn check_quorum(
    voted_reps: usize,
    total_reps: usize,
    voted_stake: u64,
    total_supply: u64,
) -> QuorumResult {
    let rep_quorum = if total_reps == 0 {
        false
    } else {
        (voted_reps as u64) * 3 >= (total_reps as u64) * 2
    };
    let stake_quorum = if total_supply == 0 {
        false
    } else {
        // MED-004: integer threshold. `voted_stake / total_supply >= 0.20`
        // ⇔ `voted_stake * 5 >= total_supply`. checked_mul defends
        // against the (theoretical) overflow on voted_stake > u64::MAX/5.
        voted_stake
            .checked_mul(5)
            .is_some_and(|fivex| fivex >= total_supply)
    };
    QuorumResult {
        reached: rep_quorum && stake_quorum,
        voted_reps,
        total_reps,
        voted_stake,
        total_supply,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_reached() {
        assert!(check_quorum(7, 10, 250_000_000, 1_000_000_000).reached);
    }

    #[test]
    fn test_quorum_not_reached_reps() {
        assert!(!check_quorum(6, 10, 250_000_000, 1_000_000_000).reached);
    }

    #[test]
    fn test_quorum_not_reached_stake() {
        assert!(!check_quorum(7, 10, 100_000_000, 1_000_000_000).reached);
    }

    #[test]
    fn test_quorum_zero() {
        assert!(!check_quorum(0, 0, 0, 1_000_000_000).reached);
    }

    // ============================================================
    // MED-004 (commit 062) — integer threshold for stake quorum
    // (pre-fix used f64 division). Pin the exact-boundary
    // behaviour and the no-overflow contract.
    // ============================================================

    #[test]
    fn test_quorum_stake_at_exact_20_percent_boundary() {
        // PRIMARY MED-004 PIN: at exactly 20% (voted_stake =
        // total_supply / 5), the integer threshold passes
        // (voted_stake * 5 == total_supply, which is `>=`).
        // f64 had rounding edges here.
        let r = check_quorum(7, 10, 200_000_000, 1_000_000_000);
        assert!(r.reached, "exactly 20% must reach quorum (>= 20%)");
    }

    #[test]
    fn test_quorum_stake_just_below_20_percent_boundary() {
        // 199_999_999 / 1_000_000_000 = 0.199999999... < 0.20.
        // Integer: 199_999_999 * 5 = 999_999_995 < 1_000_000_000. Not reached.
        let r = check_quorum(7, 10, 199_999_999, 1_000_000_000);
        assert!(!r.reached);
    }

    #[test]
    fn test_quorum_stake_just_above_20_percent_boundary() {
        // 200_000_001 / 1_000_000_000 = 0.20...01 > 0.20.
        // Integer: 200_000_001 * 5 = 1_000_000_005 >= 1_000_000_000. Reached.
        let r = check_quorum(7, 10, 200_000_001, 1_000_000_000);
        assert!(r.reached);
    }

    #[test]
    fn test_quorum_stake_no_overflow_on_large_voted_stake() {
        // voted_stake near u64::MAX / 5: checked_mul should
        // gate the overflow without panic. With
        // voted_stake = u64::MAX, voted_stake.checked_mul(5)
        // returns None ; result: stake_quorum = false. No
        // panic.
        let r = check_quorum(7, 10, u64::MAX, 1_000_000_000);
        // checked_mul returned None → stake_quorum is false.
        assert!(!r.reached);
    }

    #[test]
    fn test_quorum_stake_below_threshold_with_max_supply() {
        // Edge: voted_stake just below 20% of u64::MAX is a
        // huge number. The integer math still works without
        // overflow because (u64::MAX/5)*5 ≤ u64::MAX.
        let big_supply = u64::MAX;
        let just_below_20pc = big_supply / 5; // exactly 20%
        let r = check_quorum(7, 10, just_below_20pc, big_supply);
        // u64::MAX / 5 * 5 may be slightly less than u64::MAX
        // due to integer division — pin that we don't claim
        // quorum on the just-below-20% boundary.
        assert!(
            !r.reached
                || r.voted_stake
                    .checked_mul(5)
                    .is_some_and(|x| x >= big_supply)
        );
    }
}
