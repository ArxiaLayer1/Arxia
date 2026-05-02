//! Token locking contract for vesting and staking.
//!
//! # Linear vesting with cliff (HIGH-022, commit 047)
//!
//! [`VestingSchedule`] implements the canonical "cliff + linear"
//! token-vesting pattern (e.g. the whitepaper's "6 mo cliff + 24
//! mo linear" team allocation):
//!
//! - **Pre-cliff**: 0 tokens vested.
//! - **Cliff to end**: linear vesting with formula
//!   `total * (now - start) / (end - start)`, computed in
//!   `u128` intermediate to avoid `u64` overflow.
//! - **Post-end**: full `total_amount` vested.
//!
//! `vested_at(t)` is **monotonically non-decreasing** in `t`:
//! pinned by a randomized property test
//! (`test_vested_is_monotonic`). Once tokens are vested they
//! cannot become un-vested by clock adjustments — a critical
//! invariant for any caller (UI, treasury, audit).
//!
//! [`TokenLock`] (the legacy "all-or-nothing at unlock_at" type)
//! is preserved unchanged for use cases that genuinely want
//! deadline semantics (e.g. emergency-key claim windows).
//! Vesting and lock-with-deadline are distinct contracts; both
//! are useful and neither is a strict generalization of the
//! other.
//!
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-022.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// A token lock entry with deadline-style ("all-or-nothing at
/// unlock_at") semantics. For linear vesting use
/// [`VestingSchedule`] instead.
#[derive(Debug, Clone)]
pub struct TokenLock {
    /// Owner account.
    pub owner: String,
    /// Amount locked (micro-ARX).
    pub amount: u64,
    /// Unlock timestamp (unix ms).
    pub unlock_at: u64,
    /// Whether claimed.
    pub claimed: bool,
}

impl TokenLock {
    /// Create a new token lock.
    pub fn new(owner: String, amount: u64, unlock_at: u64) -> Self {
        Self {
            owner,
            amount,
            unlock_at,
            claimed: false,
        }
    }

    /// Attempt to claim the locked tokens.
    pub fn claim(&mut self, current_time: u64) -> Result<u64, &'static str> {
        if self.claimed {
            return Err("tokens already claimed");
        }
        if current_time < self.unlock_at {
            return Err("lock period has not elapsed");
        }
        self.claimed = true;
        Ok(self.amount)
    }

    /// Check if the lock has expired.
    pub fn is_unlocked(&self, current_time: u64) -> bool {
        current_time >= self.unlock_at
    }
}

/// Errors returned by [`VestingSchedule`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VestingError {
    /// `claim()` was called but no tokens are currently
    /// claimable (either pre-cliff or all already claimed).
    NothingToClaim,
    /// The schedule's parameters are inconsistent (e.g.
    /// `cliff_at < start_at`, `end_at <= start_at`,
    /// `cliff_at > end_at`). Returned by
    /// [`VestingSchedule::new_checked`].
    InvalidSchedule,
}

impl std::fmt::Display for VestingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingToClaim => f.write_str("no tokens currently claimable"),
            Self::InvalidSchedule => f.write_str(
                "invalid vesting schedule: cliff_at must be in [start_at, end_at] and \
                 end_at > start_at",
            ),
        }
    }
}

impl std::error::Error for VestingError {}

/// A linear vesting schedule with cliff. See the module docstring
/// for HIGH-022 rationale and the canonical formula.
#[derive(Debug, Clone)]
pub struct VestingSchedule {
    /// Owner account (hex-encoded pubkey or label).
    pub owner: String,
    /// Total amount that vests over the schedule (micro-ARX).
    pub total_amount: u64,
    /// Vesting epoch start (unix ms). Linear elapsed time is
    /// measured from this point.
    pub start_at: u64,
    /// Cliff timestamp (unix ms). Before `cliff_at`,
    /// `vested_at` returns 0 regardless of schedule otherwise.
    /// At and after `cliff_at`, vesting follows the linear
    /// formula `total * (now - start) / (end - start)`.
    pub cliff_at: u64,
    /// End of vesting (unix ms). At and after `end_at`,
    /// `vested_at` returns `total_amount`.
    pub end_at: u64,
    /// Amount already claimed by the owner. Monotonically
    /// non-decreasing across `claim()` calls.
    pub claimed: u64,
}

impl VestingSchedule {
    /// Construct a schedule without validation. Caller is
    /// responsible for ensuring the parameters are consistent;
    /// use [`Self::new_checked`] for typed validation.
    pub fn new(
        owner: String,
        total_amount: u64,
        start_at: u64,
        cliff_at: u64,
        end_at: u64,
    ) -> Self {
        Self {
            owner,
            total_amount,
            start_at,
            cliff_at,
            end_at,
            claimed: 0,
        }
    }

    /// Construct a schedule with parameter validation.
    ///
    /// # Errors
    ///
    /// Returns `Err(VestingError::InvalidSchedule)` if any of:
    /// - `cliff_at < start_at`
    /// - `cliff_at > end_at`
    /// - `end_at <= start_at`
    pub fn new_checked(
        owner: String,
        total_amount: u64,
        start_at: u64,
        cliff_at: u64,
        end_at: u64,
    ) -> Result<Self, VestingError> {
        if cliff_at < start_at || cliff_at > end_at || end_at <= start_at {
            return Err(VestingError::InvalidSchedule);
        }
        Ok(Self::new(owner, total_amount, start_at, cliff_at, end_at))
    }

    /// Total amount vested at `current_time`. Monotonically
    /// non-decreasing: once a value is reached, no later call
    /// returns less.
    ///
    /// - `current_time < cliff_at` → `0`
    /// - `current_time >= end_at` → `total_amount`
    /// - between cliff and end → linear:
    ///   `total_amount * (current_time - start_at) /
    ///   (end_at - start_at)`, computed in `u128` to avoid
    ///   `u64` overflow on `total_amount * elapsed`.
    pub fn vested_at(&self, current_time: u64) -> u64 {
        if current_time < self.cliff_at {
            return 0;
        }
        if current_time >= self.end_at {
            return self.total_amount;
        }
        let elapsed = current_time.saturating_sub(self.start_at);
        let duration = self.end_at.saturating_sub(self.start_at);
        if duration == 0 {
            // Degenerate: end_at == start_at. Treat as fully
            // vested at any time >= cliff_at. (Validation in
            // `new_checked` rejects this case.)
            return self.total_amount;
        }
        // u128 intermediate avoids u64 overflow on
        // total_amount * elapsed. Result fits in u64 because
        // it is bounded by total_amount.
        let result =
            (self.total_amount as u128).saturating_mul(elapsed as u128) / (duration as u128);
        result.try_into().unwrap_or(u64::MAX)
    }

    /// Amount claimable now (vested minus already claimed).
    /// Saturates at 0 if `claimed` somehow exceeds `vested_at`
    /// (defensive against bookkeeping bugs).
    pub fn claimable_at(&self, current_time: u64) -> u64 {
        self.vested_at(current_time).saturating_sub(self.claimed)
    }

    /// Claim all currently-claimable tokens. Advances `claimed`
    /// by the returned amount.
    ///
    /// # Errors
    ///
    /// Returns `Err(VestingError::NothingToClaim)` if
    /// `claimable_at(current_time) == 0` (pre-cliff, or all
    /// vested-so-far has already been claimed).
    pub fn claim(&mut self, current_time: u64) -> Result<u64, VestingError> {
        let claimable = self.claimable_at(current_time);
        if claimable == 0 {
            return Err(VestingError::NothingToClaim);
        }
        // saturating_add defensively bounds an arithmetic edge
        // case where claimed + claimable > u64::MAX (cannot
        // happen given vested_at <= total_amount: u64, but keep
        // the saturation for defense-in-depth).
        self.claimed = self.claimed.saturating_add(claimable);
        Ok(claimable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_lock_claim() {
        let mut lock = TokenLock::new("alice".into(), 1_000_000, 1000);
        assert!(lock.claim(500).is_err());
        assert!(!lock.is_unlocked(500));
        let amount = lock.claim(1000).unwrap();
        assert_eq!(amount, 1_000_000);
        assert!(lock.claimed);
    }

    #[test]
    fn test_token_lock_double_claim() {
        let mut lock = TokenLock::new("alice".into(), 1_000_000, 1000);
        lock.claim(1000).unwrap();
        assert!(lock.claim(2000).is_err());
    }

    // ============================================================
    // VestingSchedule — HIGH-022 (commit 047) — linear vesting
    // with cliff. The whitepaper's canonical "6mo cliff + 24mo
    // linear" pattern.
    //
    // Throughout these tests the schedule is normalized:
    // start_at = 0, cliff_at = 6_000_000 ms (6 mo at 1ms/mo
    // for test convenience), end_at = 24_000_000 ms,
    // total_amount = 24_000_000 micro-ARX. The 1ms/mo scale
    // makes the math obvious: at month N, vested = N micro-ARX.
    // ============================================================

    fn six_mo_cliff_24_mo_linear() -> VestingSchedule {
        VestingSchedule::new(
            "team-allocation".to_string(),
            24_000_000,
            0,
            6_000_000,
            24_000_000,
        )
    }

    #[test]
    fn test_vested_at_pre_cliff_returns_zero() {
        // PRIMARY HIGH-022 BOUNDARY: month 0, 1, 5 → 0.
        let s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.vested_at(0), 0);
        assert_eq!(s.vested_at(1_000_000), 0);
        assert_eq!(s.vested_at(5_999_999), 0);
    }

    #[test]
    fn test_vested_at_exactly_cliff_returns_cliff_fraction() {
        // At cliff (month 6 of 24): 6/24 = 25% vested.
        let s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.vested_at(6_000_000), 6_000_000);
    }

    #[test]
    fn test_vested_at_midway_returns_half() {
        // Month 12 of 24: 50% vested.
        let s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.vested_at(12_000_000), 12_000_000);
    }

    #[test]
    fn test_vested_at_end_returns_total() {
        let s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.vested_at(24_000_000), 24_000_000);
    }

    #[test]
    fn test_vested_at_post_end_stays_at_total() {
        // Once fully vested, subsequent reads stay at total.
        let s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.vested_at(30_000_000), 24_000_000);
        assert_eq!(s.vested_at(u64::MAX), 24_000_000);
    }

    #[test]
    fn test_vested_is_monotonic() {
        // PRIMARY HIGH-022 PIN: across 1000 (t1, t2) pairs
        // with t1 < t2, vested_at(t1) <= vested_at(t2).
        // The audit's "monotonicity property test".
        let s = six_mo_cliff_24_mo_linear();
        // Deterministic xorshift PRNG so the test is
        // reproducible.
        let mut state: u64 = 0xCAFE_BABE_DEAD_BEEF;
        for _ in 0..1000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let t1 = state % 30_000_000;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let t2 = (state % 30_000_000).max(t1);
            let v1 = s.vested_at(t1);
            let v2 = s.vested_at(t2);
            assert!(
                v1 <= v2,
                "monotonicity violated: vested_at({t1}) = {v1} > vested_at({t2}) = {v2}"
            );
        }
    }

    #[test]
    fn test_vested_no_overflow_on_max_total_amount() {
        // total_amount = u64::MAX, large duration. The
        // u128 intermediate must NOT overflow into u64::MAX
        // and the panic-free contract holds.
        let s = VestingSchedule::new("huge".into(), u64::MAX, 0, 0, 10_000_000_000);
        // Mid-vesting: should not panic, returns roughly
        // u64::MAX / 2.
        let mid = s.vested_at(5_000_000_000);
        assert!(mid > 0);
        assert!(mid < u64::MAX);
        // Post-end: full amount.
        assert_eq!(s.vested_at(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_claimable_subtracts_already_claimed() {
        let mut s = six_mo_cliff_24_mo_linear();
        // Vest to 50% (12 of 24 mo).
        let claimed = s.claim(12_000_000).unwrap();
        assert_eq!(claimed, 12_000_000);
        // Now nothing more is claimable until time advances.
        assert_eq!(s.claimable_at(12_000_000), 0);
        // Advance to 75% (18 of 24).
        let claimable_18 = s.claimable_at(18_000_000);
        assert_eq!(claimable_18, 18_000_000 - 12_000_000);
    }

    #[test]
    fn test_claim_advances_claimed_amount() {
        let mut s = six_mo_cliff_24_mo_linear();
        assert_eq!(s.claimed, 0);
        s.claim(12_000_000).unwrap();
        assert_eq!(s.claimed, 12_000_000);
        s.claim(18_000_000).unwrap();
        assert_eq!(s.claimed, 18_000_000);
        s.claim(24_000_000).unwrap();
        assert_eq!(s.claimed, 24_000_000);
    }

    #[test]
    fn test_claim_returns_error_when_nothing_claimable() {
        let mut s = six_mo_cliff_24_mo_linear();
        // Pre-cliff.
        assert_eq!(s.claim(1_000_000), Err(VestingError::NothingToClaim));
        // Already-claimed-everything-vested-so-far.
        s.claim(12_000_000).unwrap();
        assert_eq!(s.claim(12_000_000), Err(VestingError::NothingToClaim));
    }

    #[test]
    fn test_new_checked_rejects_cliff_before_start() {
        let r = VestingSchedule::new_checked("x".into(), 100, 1000, 500, 2000);
        assert_eq!(r.unwrap_err(), VestingError::InvalidSchedule);
    }

    #[test]
    fn test_new_checked_rejects_cliff_after_end() {
        let r = VestingSchedule::new_checked("x".into(), 100, 0, 3000, 2000);
        assert_eq!(r.unwrap_err(), VestingError::InvalidSchedule);
    }

    #[test]
    fn test_new_checked_rejects_end_at_or_before_start() {
        let r = VestingSchedule::new_checked("x".into(), 100, 1000, 1000, 1000);
        assert_eq!(r.unwrap_err(), VestingError::InvalidSchedule);
        let r = VestingSchedule::new_checked("x".into(), 100, 1000, 800, 500);
        assert_eq!(r.unwrap_err(), VestingError::InvalidSchedule);
    }

    #[test]
    fn test_new_checked_accepts_valid_schedule() {
        let r = VestingSchedule::new_checked("x".into(), 100, 0, 100, 1000);
        assert!(r.is_ok());
    }

    #[test]
    fn test_vested_at_zero_total_amount_is_always_zero() {
        // Edge case: a schedule with 0 tokens. vested_at
        // returns 0 at every time without panic.
        let s = VestingSchedule::new("zero".into(), 0, 0, 100, 1000);
        assert_eq!(s.vested_at(0), 0);
        assert_eq!(s.vested_at(500), 0);
        assert_eq!(s.vested_at(2000), 0);
    }
}
