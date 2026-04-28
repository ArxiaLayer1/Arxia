//! Protobuf definitions for the Arxia wire protocol.
//!
//! # Pre-decode validation (HIGH-010, commit 040)
//!
//! Wire bytes that arrive on a transport (LoRa / BLE / SMS / TCP /
//! satellite) MUST be validated against
//! [`MAX_TRANSPORT_FRAME_BYTES`] BEFORE being handed to
//! `prost::Message::decode`. The audit (HIGH-010):
//!
//! > Send a 4 GB `bytes payload` in a frame. prost decoder
//! > allocates; OOM. Wrap decode in a length-prefixed reader with
//! > a hard cap (e.g., 2 × LoRa MTU for a single frame; 1 MB for a
//! > batch frame), reject larger.
//!
//! The cap lives at the `arxia-proto` crate boundary so every
//! transport binding (`arxia-transport`, future LoRa / BLE
//! adapters) inherits the same protocol-level limit. Callers
//! invoke [`validate_transport_frame_bytes`] on the wire `&[u8]`
//! before calling `decode`. Out-of-range frames are rejected with
//! [`ProtoError::TransportFrameTooLarge`] without ever allocating
//! a `prost::Message` for them — the cheapest possible OOM-vector
//! closure.
//!
//! `MAX_TRANSPORT_FRAME_BYTES` = 1 MiB (1 048 576 bytes), aligned
//! with the audit's batch-frame ceiling. This is well above any
//! realistic single-message envelope size (largest known:
//! `NonceSyncResponse` capped at ~720 KB by commit 028) and well
//! below the 4 GB attack surface the audit describes.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod validation;

pub use validation::{validate_transport_frame_bytes, ProtoError, MAX_TRANSPORT_FRAME_BYTES};

/// Generated protobuf types for the Arxia protocol.
#[allow(missing_docs)]
pub mod arxia {
    include!(concat!(env!("OUT_DIR"), "/arxia.rs"));
}
