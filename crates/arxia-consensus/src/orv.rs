//! ORV vote collection and eligibility filtering.

use crate::vote::VoteORV;

const MIN_REPRESENTATIVE_STAKE_PERCENT: f64 = 0.001;

/// Collects votes from eligible representatives (>= 0.1% of total supply).
pub fn collect_votes(votes: &[VoteORV], total_supply: u64) -> Vec<VoteORV> {
    let min_stake = (total_supply as f64 * MIN_REPRESENTATIVE_STAKE_PERCENT) as u64;
    votes
        .iter()
        .filter(|v| v.delegated_stake >= min_stake)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cast_vote;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_collect_votes_filters() {
        let total = 1_000_000_000u64;
        let min = (total as f64 * MIN_REPRESENTATIVE_STAKE_PERCENT) as u64;
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
        let min = (total as f64 * MIN_REPRESENTATIVE_STAKE_PERCENT) as u64;
        assert_eq!(min, 1_000_000);
    }
}
