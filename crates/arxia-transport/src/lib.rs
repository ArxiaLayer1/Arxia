//! Transport layer abstraction for Arxia.
//!
//! Provides a trait-based transport interface with a simulated
//! implementation for testing. Production transports (LoRa, BLE,
//! SMS, Satellite) will implement the same trait.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sim;
pub mod traits;

pub use sim::simulated::{SimulatedTransport, DEFAULT_INBOX_CAPACITY, DEFAULT_OUTBOX_CAPACITY};
pub use traits::{TransportError, TransportMessage, TransportTrait};
