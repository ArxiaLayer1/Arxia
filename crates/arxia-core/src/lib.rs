//! Core types, constants, and error handling for the Arxia protocol.
//!
//! This crate provides the foundational types shared across all Arxia crates:
//! `AccountId`, `Amount`, `Nonce`, `BlockHash`, `SignatureBytes`, and the
//! unified `ArxiaError` enum.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod constants;
pub mod error;
pub mod types;

pub use constants::*;
pub use error::ArxiaError;
pub use types::*;
