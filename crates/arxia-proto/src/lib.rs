//! Protobuf definitions for the Arxia wire protocol.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Generated protobuf types for the Arxia protocol.
#[allow(missing_docs)]
pub mod arxia {
    include!(concat!(env!("OUT_DIR"), "/arxia.rs"));
}
