//! Pre-decode validation for `arxia-proto` wire bytes.
//!
//! HIGH-010 cap. See the crate-level docstring for the rationale.

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

/// Errors returned by the pre-decode validators.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_transport_frame_bytes_constant() {
        // Pin the cap at 1 MiB. Future deliberate revision must
        // update this assertion alongside the const.
        assert_eq!(MAX_TRANSPORT_FRAME_BYTES, 1_048_576);
        assert_eq!(MAX_TRANSPORT_FRAME_BYTES, 1024 * 1024);
    }

    #[test]
    fn test_validate_accepts_empty_frame() {
        // Boundary: empty slice is structurally valid for the
        // length check (the prost decoder will reject it on its
        // own with a different error if the protocol requires
        // non-empty content).
        assert!(validate_transport_frame_bytes(&[]).is_ok());
    }

    #[test]
    fn test_validate_accepts_small_frame() {
        // Realistic short message (e.g. a Ping).
        assert!(validate_transport_frame_bytes(&[0u8; 64]).is_ok());
    }

    #[test]
    fn test_validate_accepts_realistic_batch_frame() {
        // Realistic large frame (e.g. ~720 KB NonceSyncResponse
        // near commit 028's cap). Must fit under the 1 MiB ceiling.
        let bytes = vec![0u8; 720 * 1024];
        assert!(validate_transport_frame_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_validate_accepts_at_max() {
        // Boundary: exactly MAX_TRANSPORT_FRAME_BYTES is accepted
        // (cap is INCLUSIVE — `> MAX`, not `>= MAX`).
        let bytes = vec![0u8; MAX_TRANSPORT_FRAME_BYTES];
        assert!(validate_transport_frame_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_validate_rejects_just_above_max() {
        // PRIMARY HIGH-010 PIN at the boundary: MAX + 1 must be
        // rejected. Off-by-one guard.
        let bytes = vec![0u8; MAX_TRANSPORT_FRAME_BYTES + 1];
        let err = validate_transport_frame_bytes(&bytes).expect_err("MAX+1 must be rejected");
        match err {
            ProtoError::TransportFrameTooLarge { size, max } => {
                assert_eq!(size, MAX_TRANSPORT_FRAME_BYTES + 1);
                assert_eq!(max, MAX_TRANSPORT_FRAME_BYTES);
            }
        }
    }

    #[test]
    fn test_validate_rejects_attacker_scale_frame() {
        // PRIMARY HIGH-010 PIN: 10 MiB attacker scenario. The
        // audit describes 4 GB; we use 10 MB to keep test memory
        // tractable while still well above the 1 MiB cap.
        // Allocating a 10 MB Vec is fast; the validator returns
        // before any prost decode would be attempted.
        let bytes = vec![0u8; 10 * 1024 * 1024];
        let err = validate_transport_frame_bytes(&bytes).expect_err("10 MiB must be rejected");
        assert!(matches!(
            err,
            ProtoError::TransportFrameTooLarge { size, max }
                if size == 10 * 1024 * 1024 && max == MAX_TRANSPORT_FRAME_BYTES
        ));
    }

    #[test]
    fn test_proto_error_display_format() {
        let err = ProtoError::TransportFrameTooLarge {
            size: 2_000_000,
            max: MAX_TRANSPORT_FRAME_BYTES,
        };
        let s = format!("{err}");
        assert!(s.contains("2000000"));
        assert!(s.contains(&MAX_TRANSPORT_FRAME_BYTES.to_string()));
    }
}
