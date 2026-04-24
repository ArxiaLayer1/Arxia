//! PN-Counter CRDT for convergent balance tracking across partitions.
//!
//! # Overflow safety
//!
//! All arithmetic is overflow-safe:
//!
//! - [`PNCounter::increment`] / [`PNCounter::decrement`] use
//!   [`u64::saturating_add`]. An attacker-crafted sequence of
//!   increments cannot wrap a per-node counter past `u64::MAX` —
//!   once the cap is hit, further increments are silently clamped.
//!   This preserves CRDT monotonicity (merge-of-max stays correct)
//!   and closes CRIT-015.
//! - [`PNCounter::value`] sums P and N via saturating_add and then
//!   computes the signed difference without the `u64 as i64` wrap
//!   that CRIT-016 describes. When `|p - n|` exceeds `i64` range,
//!   the return saturates to `i64::MAX` / `i64::MIN` rather than
//!   producing a wrapped (sign-flipped) value.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Positive-Negative Counter CRDT. Commutative, associative,
/// idempotent. All arithmetic is saturating — see module docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PNCounter {
    /// Positive counts (credits).
    pub p: BTreeMap<String, u64>,
    /// Negative counts (debits).
    pub n: BTreeMap<String, u64>,
}

impl PNCounter {
    /// Create a new zero counter.
    pub fn new() -> Self {
        Self {
            p: BTreeMap::new(),
            n: BTreeMap::new(),
        }
    }
    /// Increment (credit) for a node. Saturates at `u64::MAX` — an
    /// attacker cannot wrap the per-node counter silently.
    pub fn increment(&mut self, node_id: &str, amount: u64) {
        let e = self.p.entry(node_id.to_string()).or_insert(0);
        *e = e.saturating_add(amount);
    }
    /// Decrement (debit) for a node. Saturates at `u64::MAX`.
    pub fn decrement(&mut self, node_id: &str, amount: u64) {
        let e = self.n.entry(node_id.to_string()).or_insert(0);
        *e = e.saturating_add(amount);
    }
    /// Net value (total_p - total_n), computed without the
    /// `u64 as i64` wrap that CRIT-016 described. When the true
    /// signed difference exceeds `i64::MAX` (resp. is below
    /// `i64::MIN`), the return saturates to the boundary.
    pub fn value(&self) -> i64 {
        let tp: u64 = self.p.values().copied().fold(0u64, u64::saturating_add);
        let tn: u64 = self.n.values().copied().fold(0u64, u64::saturating_add);
        if tp >= tn {
            // Positive or zero result; saturate to i64::MAX if it
            // doesn't fit.
            i64::try_from(tp - tn).unwrap_or(i64::MAX)
        } else {
            // Negative result; saturate to i64::MIN if its absolute
            // value doesn't fit in i64.
            let magnitude = tn - tp; // u64, no underflow since tn > tp
            match i64::try_from(magnitude) {
                Ok(m) => -m,
                Err(_) => i64::MIN,
            }
        }
    }
    /// Merge with another counter (element-wise max).
    pub fn merge(&mut self, other: &PNCounter) {
        for (k, &v) in &other.p {
            let e = self.p.entry(k.clone()).or_insert(0);
            *e = (*e).max(v);
        }
        for (k, &v) in &other.n {
            let e = self.n.entry(k.clone()).or_insert(0);
            *e = (*e).max(v);
        }
    }
}

impl Default for PNCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pn_counter_increment_decrement() {
        let mut c = PNCounter::new();
        c.increment("a", 100);
        c.decrement("a", 30);
        assert_eq!(c.value(), 70);
    }

    #[test]
    fn test_pn_counter_merge() {
        let mut c1 = PNCounter::new();
        c1.increment("a", 50);
        c1.decrement("a", 10);
        let mut c2 = PNCounter::new();
        c2.increment("a", 80);
        c2.decrement("a", 5);
        c1.merge(&c2);
        assert_eq!(c1.value(), 80 - 10); // max(50,80) - max(10,5)
    }

    #[test]
    fn test_pn_counter_zero() {
        let c = PNCounter::new();
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn test_pn_counter_multiple_nodes() {
        let mut c = PNCounter::new();
        c.increment("a", 100);
        c.increment("b", 200);
        c.decrement("a", 50);
        assert_eq!(c.value(), 250); // (100+200) - 50
    }

    // ---- CRIT-015 adversarial regression guards ----

    #[test]
    fn test_pncounter_increment_does_not_wrap() {
        // The audit's exact scenario: drive a per-node counter to
        // u64::MAX - 1, then increment by 2. Without saturating_add,
        // `*e += 2` would wrap to 0 and the reported balance would
        // flip to a small positive (or via value() cast-wrap to
        // nonsense negative).
        let mut c = PNCounter::new();
        c.increment("a", u64::MAX - 1);
        assert_eq!(c.p["a"], u64::MAX - 1);
        c.increment("a", 2);
        assert_eq!(
            c.p["a"],
            u64::MAX,
            "increment past u64::MAX MUST saturate, never wrap"
        );
    }

    #[test]
    fn test_pncounter_decrement_does_not_wrap() {
        // Same shape on the negative side.
        let mut c = PNCounter::new();
        c.decrement("a", u64::MAX - 1);
        c.decrement("a", 5);
        assert_eq!(
            c.n["a"],
            u64::MAX,
            "decrement past u64::MAX MUST saturate, never wrap"
        );
    }

    #[test]
    fn test_pncounter_increment_many_overflows_still_saturates() {
        // Hammering past saturation must remain monotone.
        let mut c = PNCounter::new();
        for _ in 0..10 {
            c.increment("a", u64::MAX);
        }
        assert_eq!(c.p["a"], u64::MAX);
    }

    // ---- CRIT-016 adversarial regression guards ----

    #[test]
    fn test_pncounter_value_handles_large_p_sum_without_cast_wrap() {
        // Two legitimately large P counters on different shards can
        // sum to a u64 that exceeds i64::MAX. Without the fix,
        // `tp as i64` wraps to negative and the balance for a solvent
        // account flips sign. After the fix, value() saturates to
        // i64::MAX.
        let mut c = PNCounter::new();
        c.increment("a", u64::MAX / 2 + 10);
        c.increment("b", u64::MAX / 2 + 10);
        // Sum is (u64::MAX / 2 + 10) * 2 ≈ u64::MAX, well above
        // i64::MAX.
        assert_eq!(c.value(), i64::MAX);
    }

    #[test]
    fn test_pncounter_value_handles_large_n_sum_without_cast_wrap() {
        // Symmetric: N dominates beyond i64::MAX — value saturates
        // to i64::MIN rather than flipping sign.
        let mut c = PNCounter::new();
        c.decrement("a", u64::MAX / 2 + 10);
        c.decrement("b", u64::MAX / 2 + 10);
        assert_eq!(c.value(), i64::MIN);
    }

    #[test]
    fn test_pncounter_value_at_cross_saturation_returns_zero() {
        // When P and N are both saturated at u64::MAX, tp == tn, so
        // the signed difference is zero. This is the single-shard
        // corner case where CRIT-015 saturation and CRIT-016 signed
        // difference interact.
        let mut c = PNCounter::new();
        c.increment("a", u64::MAX);
        c.decrement("a", u64::MAX);
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn test_pncounter_value_near_i64_max_is_exact() {
        // Boundary: tp - tn == i64::MAX exactly. Must return
        // i64::MAX, NOT saturate prematurely.
        let mut c = PNCounter::new();
        c.increment("a", i64::MAX as u64);
        assert_eq!(c.value(), i64::MAX);
    }

    #[test]
    fn test_pncounter_value_negative_near_i64_min_is_exact() {
        // Boundary on the negative side: tn - tp == i64::MAX exactly,
        // so value == -i64::MAX (NOT i64::MIN). Pinning this makes
        // sure we don't saturate one past the boundary.
        let mut c = PNCounter::new();
        c.decrement("a", i64::MAX as u64);
        assert_eq!(c.value(), -i64::MAX);
    }

    #[test]
    fn test_pncounter_value_large_sum_saturates_preserved_across_merge() {
        // Two replicas each at saturation; merge takes element-wise
        // max, and value() still saturates correctly.
        let mut c1 = PNCounter::new();
        c1.increment("a", u64::MAX);
        let mut c2 = PNCounter::new();
        c2.increment("b", u64::MAX);
        c1.merge(&c2);
        assert_eq!(c1.value(), i64::MAX);
    }
}
