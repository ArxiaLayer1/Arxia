//! Relay node management for Arxia.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod receipt;
pub mod scoring;
pub mod slashing;

pub use receipt::RelayReceipt;
pub use scoring::RelayScore;
pub use slashing::{SlashingError, SlashingProof};
