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
//! > a hard cap, reject larger.
//!
//! Callers invoke [`validate_transport_frame_bytes`] on the wire
//! `&[u8]` before calling `decode`. Out-of-range frames are
//! rejected with [`ProtoError::TransportFrameTooLarge`] without
//! any prost allocation — the cheapest possible OOM-vector
//! closure.
//!
//! `MAX_TRANSPORT_FRAME_BYTES` = 1 MiB (1 048 576 bytes), aligned
//! with the audit's batch-frame ceiling.
//!
//! # Post-decode oneof gate (HIGH-011, commit 041)
//!
//! Prost's default decode of a message with a `oneof` field
//! **silently drops** unknown field numbers — the parsed message
//! arrives with `payload: None`. The audit (HIGH-011):
//!
//! > Send a gossip envelope with a oneof field number that isn't
//! > in the proto definition. Prost's default behavior drops the
//! > variant silently; caller sees an envelope with no variant
//! > set and may treat it as a no-op or panic on `.unwrap()`.
//!
//! Callers MUST gate the decoded envelope on
//! [`require_envelope_payload`] before dispatch. The helper is
//! generic over the inner variant type so it works for
//! `GossipEnvelope.payload`, future `TransportEnvelope.body`,
//! etc. Empty envelopes are rejected with
//! [`ProtoError::EnvelopePayloadEmpty { envelope_kind }`] where
//! `envelope_kind` is the caller-supplied label for log
//! readability.
//!
//! Together the two validators close the prost-side OOM and
//! silent-drop attack surfaces at the `arxia-proto` crate
//! boundary. Every transport binding (`arxia-transport`, future
//! LoRa / BLE / SMS adapters) inherits both checks transparently.

//! # Protoc availability flag (LOW-008, commit 080)
//!
//! `build.rs` checks for `protoc` and either compiles the
//! `.proto` definitions normally OR writes a stub
//! (`// protoc not found - stub generated`) and emits a
//! `cargo:warning`. To make the stub mode runtime-detectable,
//! `build.rs` also sets one of two cfg flags:
//!
//! - `arxia_proto_real` — protoc was found, real types exist.
//! - `arxia_proto_stub` — protoc was missing, stub generated.
//!
//! The constant [`PROTO_STUB_ACTIVE`] mirrors the cfg as a
//! const bool so callers can introspect at runtime without
//! using `cfg!()` macros.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod validation;

pub use validation::{
    require_envelope_payload, validate_proto_decode_depth, validate_transport_frame_bytes,
    ProtoError, MAX_PROTO_DECODE_DEPTH, MAX_TRANSPORT_FRAME_BYTES,
};

/// Whether the `protoc`-stub fallback was active at build time.
///
/// LOW-008 (commit 080): `true` means `protoc` was missing and
/// the generated protobuf module is a stub ; `false` means the
/// real types are available. Callers that depend on real
/// prost-generated types should assert `!PROTO_STUB_ACTIVE` (or
/// gate at the cfg level via `#[cfg(arxia_proto_real)]`).
#[cfg(arxia_proto_real)]
pub const PROTO_STUB_ACTIVE: bool = false;

/// Whether the `protoc`-stub fallback was active at build time.
///
/// See the `arxia_proto_real` variant above for details.
#[cfg(arxia_proto_stub)]
pub const PROTO_STUB_ACTIVE: bool = true;

/// Generated protobuf types for the Arxia protocol.
#[allow(missing_docs)]
pub mod arxia {
    include!(concat!(env!("OUT_DIR"), "/arxia.rs"));
}
