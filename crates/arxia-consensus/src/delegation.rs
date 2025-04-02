//! Stake delegation to representatives (future M12-M18).

/// A delegation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The account delegating its stake.
    pub delegator: String,
    /// The representative receiving the delegation.
    pub representative: String,
    /// The amount of stake delegated (micro-ARX).
    pub amount: u64,
    /// Unix timestamp when the delegation was created.
    pub created_at: u64,
}

/// Compute total delegated stake for a representative.
pub fn total_delegated_stake(representative: &str, delegations: &[Delegation]) -> u64 {
    delegations
        .iter()
        .filter(|d| d.representative == representative)
        .map(|d| d.amount)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_delegated_stake() {
        let ds = vec![
            Delegation {
                delegator: "a".into(),
                representative: "r1".into(),
                amount: 1_000_000,
                created_at: 0,
            },
            Delegation {
                delegator: "b".into(),
                representative: "r1".into(),
                amount: 2_000_000,
                created_at: 0,
            },
            Delegation {
                delegator: "c".into(),
                representative: "r2".into(),
                amount: 5_000_000,
                created_at: 0,
            },
        ];
        assert_eq!(total_delegated_stake("r1", &ds), 3_000_000);
        assert_eq!(total_delegated_stake("r2", &ds), 5_000_000);
        assert_eq!(total_delegated_stake("r3", &ds), 0);
    }
}
