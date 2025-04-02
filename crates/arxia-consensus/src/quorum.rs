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
        (voted_stake as f64 / total_supply as f64) >= 0.20
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
}
