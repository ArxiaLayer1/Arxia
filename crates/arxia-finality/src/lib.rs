//! Transaction finality assessment for Arxia.
//!
//! Arxia uses a 4-level finality model:
//! - PENDING: >10 ARX, no confirmations
//! - L0: <=10 ARX, local BLE confirmation
//! - L1: Nonce registry sync (SyncResult::Success)
//! - L2: >=67% validator confirmation

#![deny(unsafe_code)]
#![warn(missing_docs)]

use arxia_core::constants::L0_CAP_MICRO_ARX;
use arxia_gossip::SyncResult;

/// Finality level for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinalityLevel {
    /// Transaction is pending confirmation (>10 ARX).
    Pending,
    /// Instant local confirmation via BLE (<=10 ARX).
    L0,
    /// Gossip-level finality (nonce sync confirmed).
    L1,
    /// Full validator consensus (>=67% stake confirmation).
    L2,
}

impl std::fmt::Display for FinalityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::L0 => write!(f, "L0 (instant)"),
            Self::L1 => write!(f, "L1 (gossip)"),
            Self::L2 => write!(f, "L2 (full)"),
        }
    }
}

/// Assesses the finality level of a transaction.
pub fn assess_finality(
    amount_micro_arx: u64,
    local_confirmations: u32,
    sync_result: &SyncResult,
    validator_pct: f64,
) -> FinalityLevel {
    if validator_pct >= 0.67 {
        return FinalityLevel::L2;
    }
    if *sync_result == SyncResult::Success {
        return FinalityLevel::L1;
    }
    if amount_micro_arx <= L0_CAP_MICRO_ARX && local_confirmations > 0 {
        return FinalityLevel::L0;
    }
    FinalityLevel::Pending
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_l2() {
        let level = assess_finality(100_000_000, 0, &SyncResult::NoNeighbors, 0.70);
        assert_eq!(level, FinalityLevel::L2);
    }

    #[test]
    fn test_finality_l1() {
        let level = assess_finality(100_000_000, 0, &SyncResult::Success, 0.10);
        assert_eq!(level, FinalityLevel::L1);
    }

    #[test]
    fn test_finality_l0_small_amount() {
        let level = assess_finality(5_000_000, 1, &SyncResult::Mismatch(3), 0.0);
        assert_eq!(level, FinalityLevel::L0);
    }

    #[test]
    fn test_finality_pending_large_amount() {
        let level = assess_finality(50_000_000, 1, &SyncResult::Mismatch(3), 0.0);
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_finality_pending_no_confirmations() {
        let level = assess_finality(5_000_000, 0, &SyncResult::Mismatch(1), 0.0);
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_finality_ordering() {
        assert!(FinalityLevel::Pending < FinalityLevel::L0);
        assert!(FinalityLevel::L0 < FinalityLevel::L1);
        assert!(FinalityLevel::L1 < FinalityLevel::L2);
    }

    #[test]
    fn test_finality_l2_takes_priority() {
        let level = assess_finality(1_000_000, 5, &SyncResult::Success, 0.80);
        assert_eq!(level, FinalityLevel::L2);
    }
}
