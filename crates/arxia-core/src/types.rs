//! Fundamental types shared across the Arxia workspace.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ed25519 public key (32 bytes).
pub type AccountId = [u8; 32];

/// Balance / amount in micro-ARX (1 ARX = 1_000_000 micro-ARX).
pub type Amount = u64;

/// Monotonically increasing nonce per account chain.
pub type Nonce = u64;

/// Blake3 hash output (32 bytes).
pub type BlockHash = [u8; 32];

/// Ed25519 signature (64 bytes).
pub type SignatureBytes = [u8; 64];

/// Block type discriminant for compact serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlockTypeTag {
    /// Genesis block opening an account.
    Open = 0x00,
    /// Send funds to another account.
    Send = 0x01,
    /// Receive funds from a SEND block.
    Receive = 0x02,
    /// Revoke a DID credential.
    Revoke = 0x03,
}

impl BlockTypeTag {
    /// Convert from a byte to a block type tag.
    pub fn from_byte(b: u8) -> Result<Self, crate::ArxiaError> {
        match b {
            0x00 => Ok(Self::Open),
            0x01 => Ok(Self::Send),
            0x02 => Ok(Self::Receive),
            0x03 => Ok(Self::Revoke),
            _ => Err(crate::ArxiaError::InvalidBlockType(b)),
        }
    }
}

/// Returns current time as milliseconds since UNIX epoch.
///
/// # No-panic contract (HIGH-026, commit 043)
///
/// Pre-fix this function used `.expect("system clock before UNIX
/// epoch")`, which DoSed any node whose clock read pre-1970 — most
/// notably an ESP32 whose battery-backed RTC hadn't been set or had
/// been NVS-wiped. The audit (HIGH-026):
///
/// > Attack: on an ESP32 whose RTC hasn't been set (or after NVS
/// > wipe), clock reads pre-1970; node panics on any block creation.
/// > Impact: DoS — node cannot produce any block.
///
/// Post-fix the function saturates at 0 if the system clock is
/// pre-epoch. The node can produce blocks immediately; callers that
/// need to detect a misconfigured RTC should compare against a
/// reasonable lower bound (e.g. the protocol genesis timestamp) and
/// reject `0` as a sentinel.
///
/// The `SystemTime::now()` call itself never panics on supported
/// platforms (Windows, Linux, macOS, ESP-IDF). Only the
/// `duration_since(UNIX_EPOCH)` step could fail pre-fix, and that
/// failure mode is now absorbed.
pub fn now_millis() -> u64 {
    millis_since_epoch_or_zero(SystemTime::now())
}

/// Pure-function helper: convert a [`SystemTime`] to milliseconds
/// since [`UNIX_EPOCH`], saturating at `0` for pre-epoch inputs.
///
/// Exposed for testability — call with a synthesized
/// `UNIX_EPOCH - Duration::from_secs(1)` to verify the no-panic
/// contract without an actual broken RTC.
pub fn millis_since_epoch_or_zero(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_block_type_tag_round_trip() {
        assert_eq!(BlockTypeTag::from_byte(0x00).unwrap(), BlockTypeTag::Open);
        assert_eq!(BlockTypeTag::from_byte(0x01).unwrap(), BlockTypeTag::Send);
        assert_eq!(
            BlockTypeTag::from_byte(0x02).unwrap(),
            BlockTypeTag::Receive
        );
        assert_eq!(BlockTypeTag::from_byte(0x03).unwrap(), BlockTypeTag::Revoke);
    }

    #[test]
    fn test_block_type_tag_invalid() {
        assert!(BlockTypeTag::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_now_millis_not_zero() {
        // Existing positive sanity: on a developer machine running
        // these tests, the system clock IS post-epoch, so
        // now_millis() returns a nonzero current-time-in-millis.
        assert!(now_millis() > 0);
    }

    // ============================================================
    // HIGH-026 (commit 043) — no-panic contract on pre-epoch RTC.
    // The pure helper `millis_since_epoch_or_zero` is exercised
    // with synthesized SystemTime values around UNIX_EPOCH so the
    // test runs identically on any host clock state.
    // ============================================================

    #[test]
    fn test_millis_since_epoch_or_zero_at_epoch() {
        // Boundary: exactly UNIX_EPOCH → 0 ms.
        assert_eq!(millis_since_epoch_or_zero(UNIX_EPOCH), 0);
    }

    #[test]
    fn test_millis_since_epoch_or_zero_one_second_post_epoch() {
        // 1 s post-epoch → 1000 ms.
        let t = UNIX_EPOCH + Duration::from_secs(1);
        assert_eq!(millis_since_epoch_or_zero(t), 1000);
    }

    #[test]
    fn test_millis_since_epoch_or_zero_does_not_panic_pre_epoch() {
        // PRIMARY HIGH-026 PIN: pre-epoch input must NOT panic.
        // The audit's exact attack scenario — an ESP32 RTC not
        // yet set reads ~1970-01-01 minus some delta. We
        // reproduce by constructing UNIX_EPOCH - 1 second.
        let t = UNIX_EPOCH - Duration::from_secs(1);
        // The call itself must complete without panicking. We
        // wrap in catch_unwind only as a meta-assertion; the
        // primary guard is "this test compiles to a passing
        // assertion" (a panic would propagate and fail the test
        // anyway).
        let result = std::panic::catch_unwind(|| millis_since_epoch_or_zero(t));
        assert!(result.is_ok(), "HIGH-026: pre-epoch input must not panic");
    }

    #[test]
    fn test_millis_since_epoch_or_zero_pre_epoch_saturates_to_zero() {
        // Boundary: 1 s pre-epoch → saturates to 0.
        let t = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(millis_since_epoch_or_zero(t), 0);
    }

    #[test]
    fn test_millis_since_epoch_or_zero_far_pre_epoch_saturates_to_zero() {
        // Stress: 10 years pre-epoch (well into the "RTC was
        // never set" range). Still 0, no panic.
        let t = UNIX_EPOCH - Duration::from_secs(10 * 365 * 24 * 3600);
        assert_eq!(millis_since_epoch_or_zero(t), 0);
    }

    #[test]
    fn test_millis_since_epoch_or_zero_far_future() {
        // Sanity: far-future SystemTime does NOT overflow the
        // u64 cast. 100 years post-epoch ~ 3.15e12 ms, well
        // within u64 range (max ~1.84e19).
        let t = UNIX_EPOCH + Duration::from_secs(100 * 365 * 24 * 3600);
        let ms = millis_since_epoch_or_zero(t);
        assert!(ms > 0);
        assert!(
            ms > 3_000_000_000_000,
            "100 years should be > 3e12 ms, got {ms}"
        );
    }
}
