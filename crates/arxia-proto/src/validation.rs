//! Pre-decode and post-decode validation for `arxia-proto` wire
//! bytes.
//!
//! - HIGH-010 cap: [`validate_transport_frame_bytes`] —
//!   pre-decode size guard (commit 040).
//! - HIGH-011 oneof gate: [`require_envelope_payload`] —
//!   post-decode "unknown variant must reject" guard
//!   (commit 041).
//!
//! See the crate-level docstring for the protocol-level
//! rationale.

/// Maximum nesting depth a protobuf-encoded message is allowed to
/// reach when decoded via a depth-aware consumer.
///
/// MED-012 (commit 070): pre-emptive guard. The current `.proto`
/// files do not contain recursive message structures, but the
/// wire protocol permits them via `Any`-style extensibility ; a
/// future definition that introduces recursion (deliberately or
/// accidentally) would expose a stack-overflow attack surface
/// where an attacker crafts a message with thousands of levels
/// of nesting.
///
/// Consumers that decode such message types MUST track decode
/// recursion depth (typically via a counter incremented on each
/// nested call) and abort decode when the counter exceeds this
/// constant. See [`validate_proto_decode_depth`] for the helper.
///
/// The value `64` is deliberately conservative: realistic Arxia
/// protocol messages never exceed ~6 levels (envelope → payload
/// → field → primitive), so 64 leaves room for an order-of-
/// magnitude growth in protocol expressiveness while still
/// catching adversarial blow-ups long before any host's default
/// stack runs out.
pub const MAX_PROTO_DECODE_DEPTH: usize = 64;

/// Maximum acceptable size in bytes of a single TransportFrame on
/// the wire, measured BEFORE prost decode.
///
/// 1 MiB. Aligned with the audit's batch-frame ceiling. The cap is
/// defensive: even a perfectly-formed batch frame (e.g.
/// `NonceSyncResponse` near its 10 000-entry cap from commit 028,
/// ~720 KB) fits comfortably; an attacker sending a 4 GB payload is
/// rejected without any prost allocation.
///
/// A future per-link tightening (e.g. `MAX_LORA_FRAME_BYTES = 512`)
/// can be added on top of this protocol-level ceiling without
/// loosening the global guard.
pub const MAX_TRANSPORT_FRAME_BYTES: usize = 1_048_576;

/// Errors returned by the pre/post-decode validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// The wire bytes claim a TransportFrame that exceeds
    /// [`MAX_TRANSPORT_FRAME_BYTES`]. Rejected before any prost
    /// allocation.
    TransportFrameTooLarge {
        /// Size of the wire bytes received.
        size: usize,
        /// The protocol cap, [`MAX_TRANSPORT_FRAME_BYTES`].
        max: usize,
    },
    /// A decoded GossipEnvelope (or any prost `oneof`-bearing
    /// message) has no variant set. HIGH-011: prost silently
    /// drops unknown `oneof` field numbers, leaving the parsed
    /// message with `payload: None`. Callers that don't gate on
    /// this either treat the empty envelope as a no-op or panic
    /// on `.unwrap()`. Reject loudly instead.
    EnvelopePayloadEmpty {
        /// Human-readable label of the envelope type that was
        /// missing its `oneof` variant (e.g. `"GossipEnvelope"`).
        envelope_kind: &'static str,
    },
    /// MED-012 (commit 070): the depth-aware consumer detected
    /// a nested message structure exceeding
    /// [`MAX_PROTO_DECODE_DEPTH`]. Pre-emptive guard against
    /// stack-overflow attacks via deeply-nested messages.
    DecodeDepthExceeded {
        /// Depth the consumer reached before aborting.
        depth: usize,
        /// The cap, [`MAX_PROTO_DECODE_DEPTH`].
        max: usize,
    },
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportFrameTooLarge { size, max } => {
                write!(
                    f,
                    "transport frame {size} bytes exceeds protocol cap {max} bytes"
                )
            }
            Self::EnvelopePayloadEmpty { envelope_kind } => {
                write!(
                    f,
                    "{envelope_kind} decoded with empty oneof payload (unknown or missing variant)"
                )
            }
            Self::DecodeDepthExceeded { depth, max } => {
                write!(
                    f,
                    "proto decode depth {depth} exceeds cap {max} (MED-012 stack-overflow guard)"
                )
            }
        }
    }
}

impl std::error::Error for ProtoError {}

/// Validate that wire bytes are within the TransportFrame size cap
/// BEFORE handing them to `prost::Message::decode`.
///
/// Cheapest possible rejection: a single `len()` comparison against
/// [`MAX_TRANSPORT_FRAME_BYTES`]. Returns
/// `Err(ProtoError::TransportFrameTooLarge { size, max })` if the
/// slice is too long; `Ok(())` otherwise (including empty slice,
/// which is structurally valid even if semantically useless — let
/// the prost decoder produce its own diagnostic for an empty
/// frame).
///
/// Callers MUST invoke this on every wire-byte slice before
/// calling decode — it is the protocol-level OOM guard.
pub fn validate_transport_frame_bytes(bytes: &[u8]) -> Result<(), ProtoError> {
    if bytes.len() > MAX_TRANSPORT_FRAME_BYTES {
        return Err(ProtoError::TransportFrameTooLarge {
            size: bytes.len(),
            max: MAX_TRANSPORT_FRAME_BYTES,
        });
    }
    Ok(())
}

/// HIGH-011 gate: assert that a decoded prost message's `oneof`
/// payload is `Some(_)` and not `None`.
///
/// Prost's default decode of a message with a `oneof` field
/// **silently drops** unknown field numbers — the parsed message
/// arrives with `payload: None`. Callers that don't gate on this
/// either treat the empty envelope as a no-op (corruption) or
/// panic on `.unwrap()` (DoS). The audit:
///
/// > **Attack:** send a gossip envelope with a oneof field number
/// > that isn't in the proto definition.
/// > **Impact:** prost's default behavior drops the variant
/// > silently; caller sees an envelope with no variant set and
/// > may treat it as a no-op or panic on `.unwrap()`.
/// > **Suggested fix direction:** explicit `match envelope.payload
/// > { None => return Err(Malformed), ... }` on every envelope
/// > decode site; deny unknown variants.
///
/// This helper is generic over the inner variant type so it can
/// be reused for `GossipEnvelope.payload`, future
/// `TransportEnvelope.body`, etc. Callers do:
///
/// ```ignore
/// let envelope = GossipEnvelope::decode(&bytes)?;
/// let variant = require_envelope_payload(envelope.payload.as_ref(), "GossipEnvelope")?;
/// match variant { /* dispatch known variants ... */ }
/// ```
///
/// The `envelope_kind` label is purely cosmetic (for log /
/// error-message readability); it does not change semantics.
pub fn require_envelope_payload<'a, T>(
    payload: Option<&'a T>,
    envelope_kind: &'static str,
) -> Result<&'a T, ProtoError> {
    payload.ok_or(ProtoError::EnvelopePayloadEmpty { envelope_kind })
}

/// MED-012 (commit 070): assert that a depth-aware consumer's
/// decode-depth counter has not exceeded [`MAX_PROTO_DECODE_DEPTH`].
///
/// Returns `Ok(())` if `depth <= MAX_PROTO_DECODE_DEPTH`, else
/// `Err(ProtoError::DecodeDepthExceeded { depth, max })`. Designed
/// to be called at the top of any recursive decode helper:
///
/// ```ignore
/// fn decode_recursive(bytes: &[u8], depth: usize) -> Result<T, ProtoError> {
///     validate_proto_decode_depth(depth)?;
///     // ... decode children with `decode_recursive(.., depth + 1)?` ...
/// }
/// ```
///
/// This is a **pre-emptive** guard: the current Arxia `.proto`
/// definitions do not contain recursive structures, so the helper
/// has no in-tree caller yet. It is exposed now so that any future
/// recursion-introducing schema change can opt into the cap with a
/// single function call instead of re-deriving the constant or
/// re-implementing the comparison.
pub fn validate_proto_decode_depth(depth: usize) -> Result<(), ProtoError> {
    if depth > MAX_PROTO_DECODE_DEPTH {
        return Err(ProtoError::DecodeDepthExceeded {
            depth,
            max: MAX_PROTO_DECODE_DEPTH,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // HIGH-010 (commit 040) — TransportFrame size cap.
    // ============================================================

    #[test]
    fn test_max_transport_frame_bytes_constant() {
        assert_eq!(MAX_TRANSPORT_FRAME_BYTES, 1_048_576);
        assert_eq!(MAX_TRANSPORT_FRAME_BYTES, 1024 * 1024);
    }

    #[test]
    fn test_validate_accepts_empty_frame() {
        assert!(validate_transport_frame_bytes(&[]).is_ok());
    }

    #[test]
    fn test_validate_accepts_small_frame() {
        assert!(validate_transport_frame_bytes(&[0u8; 64]).is_ok());
    }

    #[test]
    fn test_validate_accepts_realistic_batch_frame() {
        let bytes = vec![0u8; 720 * 1024];
        assert!(validate_transport_frame_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_validate_accepts_at_max() {
        let bytes = vec![0u8; MAX_TRANSPORT_FRAME_BYTES];
        assert!(validate_transport_frame_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_validate_rejects_just_above_max() {
        let bytes = vec![0u8; MAX_TRANSPORT_FRAME_BYTES + 1];
        let err = validate_transport_frame_bytes(&bytes).expect_err("MAX+1 must be rejected");
        match err {
            ProtoError::TransportFrameTooLarge { size, max } => {
                assert_eq!(size, MAX_TRANSPORT_FRAME_BYTES + 1);
                assert_eq!(max, MAX_TRANSPORT_FRAME_BYTES);
            }
            other => panic!("expected TransportFrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_rejects_attacker_scale_frame() {
        let bytes = vec![0u8; 10 * 1024 * 1024];
        let err = validate_transport_frame_bytes(&bytes).expect_err("10 MiB must be rejected");
        assert!(matches!(
            err,
            ProtoError::TransportFrameTooLarge { size, max }
                if size == 10 * 1024 * 1024 && max == MAX_TRANSPORT_FRAME_BYTES
        ));
    }

    #[test]
    fn test_proto_error_too_large_display_format() {
        let err = ProtoError::TransportFrameTooLarge {
            size: 2_000_000,
            max: MAX_TRANSPORT_FRAME_BYTES,
        };
        let s = format!("{err}");
        assert!(s.contains("2000000"));
        assert!(s.contains(&MAX_TRANSPORT_FRAME_BYTES.to_string()));
    }

    // ============================================================
    // HIGH-011 (commit 041) — require_envelope_payload gate.
    // Generic over inner variant type so it can be reused for
    // any oneof-bearing prost message.
    // ============================================================

    /// Stand-in for the prost-generated `GossipEnvelope::Payload`
    /// enum (which we can't compile without protoc). The shape is
    /// what matters: a sum-type-of-known-variants. The
    /// `require_envelope_payload` helper is generic over `T` so
    /// it accepts this stand-in identically to a real prost-built
    /// type.
    #[derive(Debug, PartialEq, Eq)]
    enum TestPayload {
        BlockAnnounce(u32),
        Ping,
    }

    #[test]
    fn test_require_envelope_payload_accepts_some() {
        // Positive path: an envelope with a known variant set.
        let payload = Some(TestPayload::BlockAnnounce(42));
        let v = require_envelope_payload(payload.as_ref(), "TestEnvelope").unwrap();
        assert_eq!(v, &TestPayload::BlockAnnounce(42));
    }

    #[test]
    fn test_require_envelope_payload_accepts_other_known_variant() {
        // Multiple variants — gate is purely "Some vs None", does
        // not pick which variant is "right".
        let payload = Some(TestPayload::Ping);
        let v = require_envelope_payload(payload.as_ref(), "TestEnvelope").unwrap();
        assert_eq!(v, &TestPayload::Ping);
    }

    #[test]
    fn test_require_envelope_payload_rejects_none() {
        // PRIMARY HIGH-011 PIN: `payload: None` — the exact shape
        // a prost decode produces when the wire bytes carry an
        // unknown / missing oneof field number — must reject.
        let payload: Option<TestPayload> = None;
        let err = require_envelope_payload(payload.as_ref(), "GossipEnvelope")
            .expect_err("None must reject");
        match err {
            ProtoError::EnvelopePayloadEmpty { envelope_kind } => {
                assert_eq!(envelope_kind, "GossipEnvelope");
            }
            other => panic!("expected EnvelopePayloadEmpty, got {other:?}"),
        }
    }

    #[test]
    fn test_require_envelope_payload_carries_envelope_kind_label() {
        // The `envelope_kind` parameter is propagated into the
        // error variant so log output identifies WHICH envelope
        // type was empty. Pin this contract: caller's label
        // travels through unchanged.
        let payload: Option<TestPayload> = None;
        let err = require_envelope_payload(payload.as_ref(), "TransportEnvelope")
            .expect_err("None must reject");
        assert!(matches!(
            err,
            ProtoError::EnvelopePayloadEmpty {
                envelope_kind: "TransportEnvelope"
            }
        ));
    }

    #[test]
    fn test_proto_error_envelope_payload_empty_display_format() {
        let err = ProtoError::EnvelopePayloadEmpty {
            envelope_kind: "GossipEnvelope",
        };
        let s = format!("{err}");
        assert!(s.contains("GossipEnvelope"));
        assert!(s.contains("oneof") || s.contains("payload") || s.contains("variant"));
    }

    #[test]
    fn test_two_failure_modes_are_distinguishable() {
        // Sanity: the two ProtoError variants carry distinct
        // Display output and distinct discriminants. Pin against
        // any future refactor that accidentally collapses them.
        let too_large = ProtoError::TransportFrameTooLarge {
            size: 100,
            max: MAX_TRANSPORT_FRAME_BYTES,
        };
        let empty = ProtoError::EnvelopePayloadEmpty { envelope_kind: "X" };
        assert_ne!(format!("{too_large}"), format!("{empty}"));
        assert_ne!(too_large, empty);
    }

    // ============================================================
    // MED-012 (commit 070) — proto decode-depth cap.
    //
    // Pre-emptive guard. Current `.proto` files don't have
    // recursion, so there is no in-tree caller yet ; these
    // tests pin the helper's contract so any future recursion-
    // introducing schema change can opt in with one call.
    // ============================================================

    #[test]
    fn test_max_proto_decode_depth_constant() {
        // PRIMARY MED-012 PIN: the symbolic depth cap. Future
        // refactors changing it (e.g. raising to 256, which
        // could be unsafe for some host stack sizes) fail this
        // test.
        assert_eq!(MAX_PROTO_DECODE_DEPTH, 64);
    }

    #[test]
    fn test_validate_proto_decode_depth_accepts_zero() {
        // Edge: depth 0 (top-level decode, no nesting yet) is
        // always within the cap. No off-by-one.
        assert!(validate_proto_decode_depth(0).is_ok());
    }

    #[test]
    fn test_validate_proto_decode_depth_accepts_at_cap() {
        // Boundary: depth == cap is accepted (`<=`, inclusive).
        assert!(validate_proto_decode_depth(MAX_PROTO_DECODE_DEPTH).is_ok());
    }

    #[test]
    fn test_validate_proto_decode_depth_rejects_just_above_cap() {
        // Boundary: depth == cap + 1 is rejected.
        let err = validate_proto_decode_depth(MAX_PROTO_DECODE_DEPTH + 1)
            .expect_err("cap+1 must be rejected");
        match err {
            ProtoError::DecodeDepthExceeded { depth, max } => {
                assert_eq!(depth, MAX_PROTO_DECODE_DEPTH + 1);
                assert_eq!(max, MAX_PROTO_DECODE_DEPTH);
            }
            other => panic!("expected DecodeDepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_proto_decode_depth_rejects_attacker_scale() {
        // Attacker submits a deliberately huge depth.
        let err = validate_proto_decode_depth(10_000).expect_err("10_000 levels must be rejected");
        assert!(matches!(
            err,
            ProtoError::DecodeDepthExceeded { depth, max }
                if depth == 10_000 && max == MAX_PROTO_DECODE_DEPTH
        ));
    }

    #[test]
    fn test_proto_error_decode_depth_exceeded_display_format() {
        let err = ProtoError::DecodeDepthExceeded {
            depth: 200,
            max: MAX_PROTO_DECODE_DEPTH,
        };
        let s = format!("{err}");
        assert!(s.contains("200"));
        assert!(s.contains(&MAX_PROTO_DECODE_DEPTH.to_string()));
        assert!(s.contains("depth") || s.contains("nest"));
    }

    #[test]
    fn test_three_failure_modes_are_all_distinguishable() {
        // Strengthen the prior 2-mode pin to 3 modes now that
        // MED-012 adds a third variant. Each must be distinct
        // in PartialEq and in Display.
        let too_large = ProtoError::TransportFrameTooLarge {
            size: 1,
            max: MAX_TRANSPORT_FRAME_BYTES,
        };
        let empty = ProtoError::EnvelopePayloadEmpty { envelope_kind: "X" };
        let too_deep = ProtoError::DecodeDepthExceeded {
            depth: 200,
            max: MAX_PROTO_DECODE_DEPTH,
        };
        assert_ne!(too_large, empty);
        assert_ne!(empty, too_deep);
        assert_ne!(too_large, too_deep);
        assert_ne!(format!("{too_large}"), format!("{empty}"));
        assert_ne!(format!("{empty}"), format!("{too_deep}"));
        assert_ne!(format!("{too_large}"), format!("{too_deep}"));
    }
}
