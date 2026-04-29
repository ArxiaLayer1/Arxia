//! Transport layer abstraction for Arxia.
//!
//! Provides a trait-based transport interface with a simulated
//! implementation for testing. Production transports (LoRa, BLE,
//! SMS, Satellite) will implement the same trait.
//!
//! # Authenticated `from` (HIGH-012, commit 045)
//!
//! [`TransportMessage`] carries a `from: String` field that is
//! pre-fix purely informational. A peer can set
//! `from = "alice"` while actually being eve, undermining any
//! per-peer scoring (relay) or rate limiting that uses `from` as
//! an identity key. The audit (HIGH-012):
//!
//! > Peer sends a message with `from = "alice"` while actually
//! > being eve. Peer identity spoofing at the transport layer.
//!
//! [`SignedTransportMessage`] is the secure variant: it wraps a
//! `TransportMessage` with an Ed25519 signature over a
//! domain-separated canonical encoding, AND requires `from` to
//! be the hex-encoded pubkey of the signing key. A
//! `SignedTransportMessage::verify()` call fails if:
//!
//! - the signature does not verify under the pubkey decoded
//!   from `from`,
//! - the `from` field is not a 64-char hex 32-byte pubkey,
//! - any field (`from`, `to`, `payload`, `timestamp`) has been
//!   tampered.
//!
//! Production transports (LoRa, BLE, SMS, satellite — currently
//! stubs) and the gossip ingress will adopt
//! `SignedTransportMessage` at the wire boundary.
//! [`SimulatedTransport`] keeps `TransportMessage` unchanged for
//! the existing test surface (which uses arbitrary `from`
//! strings); the signed variant is opt-in until adoption lands.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sim;
pub mod traits;

pub use sim::simulated::{SimulatedTransport, DEFAULT_INBOX_CAPACITY, DEFAULT_OUTBOX_CAPACITY};
pub use traits::{
    SignedTransportMessage, TransportError, TransportMessage, TransportTrait,
    TRANSPORT_MESSAGE_DOMAIN,
};
