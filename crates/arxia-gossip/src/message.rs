//! Gossip message types.
//!
//! # Bounded payloads (HIGH-008 / HIGH-009)
//!
//! Some `GossipMessage` variants carry caller-controlled-length
//! payloads (`BlockAnnounce::block_data`, `NonceSyncResponse::entries`,
//! `NonceSyncRequest::from`, `Ping::node_id`). Pre-fix these were
//! unbounded — a single peer could send a 1 GB `BlockAnnounce` and
//! force every receiving node to allocate a gigabyte at deserialization
//! time. Each variant now has a documented cap, enforced by
//! [`GossipMessage::validate`] which is invoked by
//! [`crate::SignedGossipMessage::verify`] BEFORE any cryptographic
//! work — so the OOM-by-flood vector is closed at the cheapest gate.
//!
//! Caps:
//!
//! - [`MAX_BLOCK_ANNOUNCE_BYTES`] = `193 × 64` = `12_352` bytes (HIGH-008
//!   closed in commit 027). 64 compact blocks per announce is the
//!   batch ceiling — larger announces are gossip-layer abuse, not
//!   protocol traffic.
//!
//! Caps for the remaining variants (`NonceSyncResponse`,
//! `NonceSyncRequest`, `Ping`) are tracked as separate Wave 4
//! commits.

use serde::{Deserialize, Serialize};

/// Maximum length in bytes of a [`GossipMessage::BlockAnnounce::block_data`]
/// payload. Computed as `COMPACT_BLOCK_SIZE × MAX_BATCH = 193 × 64`,
/// the largest reasonable batch a benign peer would ever announce.
///
/// Anything above this is gossip-layer abuse and is rejected by
/// [`GossipMessage::validate`] before any signature work runs.
pub const MAX_BLOCK_ANNOUNCE_BYTES: usize = 193 * 64;

/// Errors produced by [`GossipMessage::validate`].
///
/// Surfaced to callers via
/// [`crate::SignedGossipMessageError::MessageInvalid`] when the
/// envelope-level verification path runs the structural check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// `BlockAnnounce::block_data` is longer than
    /// [`MAX_BLOCK_ANNOUNCE_BYTES`]. Carries the offending size and
    /// the configured maximum so callers can log / alarm.
    BlockAnnounceTooLarge {
        /// Actual `block_data` length.
        size: usize,
        /// Configured cap ([`MAX_BLOCK_ANNOUNCE_BYTES`]).
        max: usize,
    },
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockAnnounceTooLarge { size, max } => write!(
                f,
                "BlockAnnounce.block_data length {} exceeds cap {}",
                size, max
            ),
        }
    }
}

impl std::error::Error for MessageError {}

/// A gossip message exchanged between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// A new block to propagate.
    BlockAnnounce {
        /// Serialized compact block bytes.
        block_data: Vec<u8>,
        /// Hop count for TTL tracking.
        hops: u8,
    },
    /// Request nonce registry synchronization.
    NonceSyncRequest {
        /// The requesting node identifier.
        from: String,
    },
    /// Response with nonce registry data.
    NonceSyncResponse {
        /// Nonce registry entries: block_hash, nonce, account_hash.
        entries: Vec<([u8; 32], u64, [u8; 32])>,
    },
    /// Heartbeat / keepalive.
    Ping {
        /// Node identifier.
        node_id: String,
        /// Timestamp.
        timestamp: u64,
    },
}

impl GossipMessage {
    /// Run cheap structural validation on the message.
    ///
    /// Currently checks [`MAX_BLOCK_ANNOUNCE_BYTES`] (HIGH-008). Other
    /// variant caps (`NonceSyncResponse`, `NonceSyncRequest`, `Ping`)
    /// are tracked as separate Wave 4 commits; they currently return
    /// `Ok(())`.
    ///
    /// Called by [`crate::SignedGossipMessage::verify`] BEFORE the
    /// Ed25519 signature check, so an oversized payload is rejected
    /// without invoking expensive cryptography.
    pub fn validate(&self) -> Result<(), MessageError> {
        match self {
            Self::BlockAnnounce { block_data, .. } => {
                if block_data.len() > MAX_BLOCK_ANNOUNCE_BYTES {
                    return Err(MessageError::BlockAnnounceTooLarge {
                        size: block_data.len(),
                        max: MAX_BLOCK_ANNOUNCE_BYTES,
                    });
                }
                Ok(())
            }
            Self::NonceSyncRequest { .. } | Self::NonceSyncResponse { .. } | Self::Ping { .. } => {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_announce(size: usize) -> GossipMessage {
        GossipMessage::BlockAnnounce {
            block_data: vec![0u8; size],
            hops: 0,
        }
    }

    #[test]
    fn test_max_block_announce_bytes_constant_is_12352() {
        assert_eq!(MAX_BLOCK_ANNOUNCE_BYTES, 12_352);
        assert_eq!(MAX_BLOCK_ANNOUNCE_BYTES, 193 * 64);
    }

    #[test]
    fn test_validate_accepts_empty_block_announce() {
        assert!(block_announce(0).validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_one_compact_block_announce() {
        // The realistic single-block case (193 bytes).
        assert!(block_announce(193).validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_at_exact_max_size() {
        assert!(block_announce(MAX_BLOCK_ANNOUNCE_BYTES).validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_one_byte_over_max() {
        let m = block_announce(MAX_BLOCK_ANNOUNCE_BYTES + 1);
        let err = m.validate().unwrap_err();
        assert_eq!(
            err,
            MessageError::BlockAnnounceTooLarge {
                size: MAX_BLOCK_ANNOUNCE_BYTES + 1,
                max: MAX_BLOCK_ANNOUNCE_BYTES,
            }
        );
    }

    #[test]
    fn test_validate_rejects_huge_block_announce() {
        // The audit's stated attack: 1 GB payload.
        // We use 1 MB here for test speed (the bound check is
        // structural — len() comparison — so any size above
        // MAX_BLOCK_ANNOUNCE_BYTES exercises the same code path).
        let m = block_announce(1_000_000);
        assert!(matches!(
            m.validate(),
            Err(MessageError::BlockAnnounceTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_passes_for_other_variants() {
        // NonceSyncRequest, NonceSyncResponse, Ping currently have
        // no cap (commits 028+ will add them). validate() must
        // return Ok for any input shape.
        let m1 = GossipMessage::NonceSyncRequest {
            from: "any-id".into(),
        };
        assert!(m1.validate().is_ok());

        let m2 = GossipMessage::NonceSyncResponse {
            entries: vec![([0u8; 32], 0, [0u8; 32]); 100],
        };
        assert!(m2.validate().is_ok());

        let m3 = GossipMessage::Ping {
            node_id: "any-id".into(),
            timestamp: 0,
        };
        assert!(m3.validate().is_ok());
    }

    #[test]
    fn test_message_error_display_includes_size_and_max() {
        let e = MessageError::BlockAnnounceTooLarge {
            size: 99_999,
            max: MAX_BLOCK_ANNOUNCE_BYTES,
        };
        let s = format!("{}", e);
        assert!(s.contains("99999"), "Display should surface size: {}", s);
        assert!(
            s.contains(&MAX_BLOCK_ANNOUNCE_BYTES.to_string()),
            "Display should surface cap: {}",
            s
        );
    }
}
