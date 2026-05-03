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
//! - [`MAX_NONCE_SYNC_RESPONSE_ENTRIES`] = `10_000` entries (HIGH-009
//!   closed in commit 028). Aligned with
//!   [`crate::MAX_NONCE_REGISTRY_ENTRIES`] (the receiver's bounded
//!   local registry from commit 020): a peer cannot push more
//!   `NonceSyncResponse` entries than the receiver can store.
//!   Each entry is `([u8; 32], u64, [u8; 32])` = 72 B; 10 000
//!   entries ≈ 720 KB worst-case bytes-on-wire.
//!
//! Caps for the remaining variants (`NonceSyncRequest`, `Ping`)
//! are smaller surfaces and tracked as later Wave 4 cleanup.

use serde::{Deserialize, Serialize};

/// Maximum length in bytes of a [`GossipMessage::BlockAnnounce::block_data`]
/// payload. Computed as `COMPACT_BLOCK_SIZE × MAX_BATCH = 193 × 64`,
/// the largest reasonable batch a benign peer would ever announce.
///
/// Anything above this is gossip-layer abuse and is rejected by
/// [`GossipMessage::validate`] before any signature work runs.
pub const MAX_BLOCK_ANNOUNCE_BYTES: usize = 193 * 64;

/// Maximum initial value of [`GossipMessage::BlockAnnounce::hops`].
///
/// MED-008 (commit 056) — pre-fix `hops` was caller-controlled
/// with no upper bound; a block could circulate forever as
/// `hops = 255`. The cap rejects oversized initial values and
/// pairs with [`GossipMessage::decrement_hops_for_relay`]
/// (relayer-side TTL helper).
///
/// Set at 16 — well above realistic mesh depths and well below
/// `u8::MAX`. Same value as `arxia_relay::receipt::MAX_HOPS_PER_RECEIPT`
/// (HIGH-014).
pub const MAX_BLOCK_ANNOUNCE_HOPS: u8 = 16;

/// Maximum number of entries in a [`GossipMessage::NonceSyncResponse::entries`]
/// payload. Aligned with [`crate::MAX_NONCE_REGISTRY_ENTRIES`] (the
/// receiver's bounded local registry, commit 020): a peer cannot
/// push more entries in one `NonceSyncResponse` than the receiver
/// can store anyway.
///
/// Each entry is `([u8; 32], u64, [u8; 32])` = **72 bytes**; the
/// cap therefore bounds the wire payload at **≈ 720 KB**.
///
/// Anything above this is gossip-layer abuse and is rejected by
/// [`GossipMessage::validate`] before any signature work runs.
pub const MAX_NONCE_SYNC_RESPONSE_ENTRIES: usize = 10_000;

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
    /// `NonceSyncResponse::entries` has more elements than
    /// [`MAX_NONCE_SYNC_RESPONSE_ENTRIES`]. Carries the offending
    /// count and the configured maximum.
    NonceSyncResponseTooLarge {
        /// Actual `entries` count.
        count: usize,
        /// Configured cap ([`MAX_NONCE_SYNC_RESPONSE_ENTRIES`]).
        max: usize,
    },
    /// `BlockAnnounce::hops` exceeds [`MAX_BLOCK_ANNOUNCE_HOPS`].
    /// MED-008: rejected at validate() time so a flooding-prone
    /// initial value never enters the gossip pipeline.
    BlockAnnounceHopsExceeded {
        /// Actual `hops` value.
        hops: u8,
        /// Configured cap ([`MAX_BLOCK_ANNOUNCE_HOPS`]).
        max: u8,
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
            Self::NonceSyncResponseTooLarge { count, max } => write!(
                f,
                "NonceSyncResponse.entries count {} exceeds cap {}",
                count, max
            ),
            Self::BlockAnnounceHopsExceeded { hops, max } => {
                write!(f, "BlockAnnounce.hops {} exceeds cap {}", hops, max)
            }
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
    /// Checks [`MAX_BLOCK_ANNOUNCE_BYTES`] (HIGH-008) and
    /// [`MAX_NONCE_SYNC_RESPONSE_ENTRIES`] (HIGH-009). The remaining
    /// variants (`NonceSyncRequest`, `Ping`) carry only short
    /// strings and have no cap yet — they currently return `Ok(())`.
    ///
    /// Called by [`crate::SignedGossipMessage::verify`] BEFORE the
    /// Ed25519 signature check, so an oversized payload is rejected
    /// without invoking expensive cryptography.
    pub fn validate(&self) -> Result<(), MessageError> {
        match self {
            Self::BlockAnnounce { block_data, hops } => {
                if *hops > MAX_BLOCK_ANNOUNCE_HOPS {
                    return Err(MessageError::BlockAnnounceHopsExceeded {
                        hops: *hops,
                        max: MAX_BLOCK_ANNOUNCE_HOPS,
                    });
                }
                if block_data.len() > MAX_BLOCK_ANNOUNCE_BYTES {
                    return Err(MessageError::BlockAnnounceTooLarge {
                        size: block_data.len(),
                        max: MAX_BLOCK_ANNOUNCE_BYTES,
                    });
                }
                Ok(())
            }
            Self::NonceSyncResponse { entries } => {
                if entries.len() > MAX_NONCE_SYNC_RESPONSE_ENTRIES {
                    return Err(MessageError::NonceSyncResponseTooLarge {
                        count: entries.len(),
                        max: MAX_NONCE_SYNC_RESPONSE_ENTRIES,
                    });
                }
                Ok(())
            }
            Self::NonceSyncRequest { .. } | Self::Ping { .. } => Ok(()),
        }
    }

    /// Decrement the `hops` field on a `BlockAnnounce` and report
    /// whether the message can still be forwarded.
    ///
    /// MED-008 (commit 056) — relayer-side TTL helper. The
    /// canonical relayer flow:
    ///
    /// ```text
    /// receive(msg) → validate() → decrement_hops_for_relay() → broadcast if true
    /// ```
    ///
    /// Returns `true` iff the caller may relay the message:
    /// - Pre-decrement `hops > 0` AND post-decrement `hops > 0`.
    /// - For non-`BlockAnnounce` variants, returns `false`
    ///   (other message types are not relay-decremented).
    ///
    /// Returns `false` (and does NOT decrement) when:
    /// - Pre-decrement `hops == 0` (terminal — block has expired
    ///   its TTL; this receiver can ingest it but must not
    ///   re-broadcast).
    /// - Variant is not `BlockAnnounce`.
    pub fn decrement_hops_for_relay(&mut self) -> bool {
        match self {
            Self::BlockAnnounce { hops, .. } => {
                if *hops == 0 {
                    return false;
                }
                *hops -= 1;
                *hops > 0
            }
            _ => false,
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
        // NonceSyncRequest and Ping currently have no cap (string
        // fields, smaller surface — separate cleanup commit). They
        // validate ok for any input shape.
        let m1 = GossipMessage::NonceSyncRequest {
            from: "any-id".into(),
        };
        assert!(m1.validate().is_ok());

        // NonceSyncResponse: well-below the 10 000-entry cap from
        // commit 028 passes without issue.
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

    // --- HIGH-009: NonceSyncResponse entries cap ---

    fn nonce_sync_response(n: usize) -> GossipMessage {
        GossipMessage::NonceSyncResponse {
            entries: vec![([0u8; 32], 0, [0u8; 32]); n],
        }
    }

    #[test]
    fn test_max_nonce_sync_response_entries_constant_is_10000() {
        assert_eq!(MAX_NONCE_SYNC_RESPONSE_ENTRIES, 10_000);
    }

    #[test]
    fn test_validate_accepts_empty_nonce_sync_response() {
        assert!(nonce_sync_response(0).validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_at_max_nonce_sync_response_entries() {
        // The boundary case: exactly the cap is accepted.
        // 10 000 × 72 B ≈ 720 KB — within reasonable LoRa /
        // Linux-server gossip budgets per
        // `MAX_NONCE_REGISTRY_ENTRIES`.
        let m = nonce_sync_response(MAX_NONCE_SYNC_RESPONSE_ENTRIES);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_one_over_max_nonce_sync_response_entries() {
        let m = nonce_sync_response(MAX_NONCE_SYNC_RESPONSE_ENTRIES + 1);
        let err = m.validate().unwrap_err();
        assert_eq!(
            err,
            MessageError::NonceSyncResponseTooLarge {
                count: MAX_NONCE_SYNC_RESPONSE_ENTRIES + 1,
                max: MAX_NONCE_SYNC_RESPONSE_ENTRIES,
            }
        );
    }

    #[test]
    fn test_validate_rejects_huge_nonce_sync_response() {
        // The audit's stated attack: 10M entries.
        // We use 50 000 here (5× the cap) for test speed; the
        // bound check is structural, so any size above
        // MAX_NONCE_SYNC_RESPONSE_ENTRIES exercises the same path.
        let m = nonce_sync_response(50_000);
        assert!(matches!(
            m.validate(),
            Err(MessageError::NonceSyncResponseTooLarge { .. })
        ));
    }

    #[test]
    fn test_message_error_display_for_nonce_sync_response() {
        let e = MessageError::NonceSyncResponseTooLarge {
            count: 99_999,
            max: MAX_NONCE_SYNC_RESPONSE_ENTRIES,
        };
        let s = format!("{}", e);
        assert!(s.contains("99999"), "Display should surface count: {}", s);
        assert!(
            s.contains(&MAX_NONCE_SYNC_RESPONSE_ENTRIES.to_string()),
            "Display should surface cap: {}",
            s
        );
        assert!(s.contains("NonceSyncResponse"));
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

    // ============================================================
    // MED-008 (commit 056) — BlockAnnounce hops cap +
    // decrement-on-relay TTL helper.
    // ============================================================

    #[test]
    fn test_max_block_announce_hops_constant() {
        // Pin: 16 (parallel to MAX_HOPS_PER_RECEIPT in
        // arxia-relay).
        assert_eq!(MAX_BLOCK_ANNOUNCE_HOPS, 16);
    }

    #[test]
    fn test_validate_rejects_hops_above_cap() {
        // PRIMARY MED-008 PIN: a flooding-prone initial value
        // is rejected at the cheapest gate (validate, before
        // crypto).
        let m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; 100],
            hops: 255,
        };
        let err = m.validate().expect_err("hops=255 must reject");
        match err {
            MessageError::BlockAnnounceHopsExceeded { hops, max } => {
                assert_eq!(hops, 255);
                assert_eq!(max, MAX_BLOCK_ANNOUNCE_HOPS);
            }
            other => panic!("expected BlockAnnounceHopsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_accepts_hops_at_max() {
        // Boundary inclusive: hops == MAX is accepted.
        let m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; 100],
            hops: MAX_BLOCK_ANNOUNCE_HOPS,
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_hops_zero_terminal_block() {
        // Boundary: hops == 0 (terminal block) is accepted by
        // validate. The receiver may still ingest the block;
        // only the relayer's decrement_hops_for_relay refuses
        // to forward it.
        let m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; 100],
            hops: 0,
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_validate_hops_check_fires_before_block_data_check() {
        // Order pin: hops cap is the first check in validate.
        // An oversized AND over-hopped message returns
        // HopsExceeded, not BlockAnnounceTooLarge — pinned for
        // log clarity.
        let m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; MAX_BLOCK_ANNOUNCE_BYTES + 1],
            hops: 255,
        };
        let err = m.validate().unwrap_err();
        assert!(
            matches!(err, MessageError::BlockAnnounceHopsExceeded { .. }),
            "expected hops-cap diagnostic first, got {err:?}"
        );
    }

    #[test]
    fn test_decrement_hops_decrements_and_returns_relayability() {
        let mut m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; 100],
            hops: 3,
        };
        // Decrement 3 → 2: still relayable.
        assert!(m.decrement_hops_for_relay());
        if let GossipMessage::BlockAnnounce { hops, .. } = &m {
            assert_eq!(*hops, 2);
        }
        // 2 → 1: still relayable.
        assert!(m.decrement_hops_for_relay());
        // 1 → 0: NOT relayable (post-decrement is 0).
        assert!(!m.decrement_hops_for_relay());
        if let GossipMessage::BlockAnnounce { hops, .. } = &m {
            assert_eq!(*hops, 0);
        }
    }

    #[test]
    fn test_decrement_hops_returns_false_when_already_zero() {
        // Pre-decrement hops == 0: don't decrement (no
        // u8-wrap-to-255), don't relay.
        let mut m = GossipMessage::BlockAnnounce {
            block_data: vec![0u8; 100],
            hops: 0,
        };
        assert!(!m.decrement_hops_for_relay());
        if let GossipMessage::BlockAnnounce { hops, .. } = &m {
            assert_eq!(*hops, 0, "no wrap-to-255 on already-zero hops");
        }
    }

    #[test]
    fn test_decrement_hops_returns_false_for_non_block_announce() {
        // Other variants aren't relay-decremented; helper
        // returns false sentinel.
        let mut m = GossipMessage::Ping {
            node_id: "n1".to_string(),
            timestamp: 0,
        };
        assert!(!m.decrement_hops_for_relay());
    }

    #[test]
    fn test_block_announce_hops_exceeded_display_format() {
        let e = MessageError::BlockAnnounceHopsExceeded { hops: 99, max: 16 };
        let s = format!("{e}");
        assert!(s.contains("99"));
        assert!(s.contains("16"));
    }
}
