//! Gossip protocol for block propagation and nonce synchronization.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod message;
pub mod node;
pub mod nonce_registry;

pub use message::GossipMessage;
pub use node::{GossipNode, MAX_KNOWN_BLOCKS, MAX_NONCE_REGISTRY_ENTRIES};
pub use nonce_registry::{merge_nonce_registries, sync_nonces_before_l1, SyncResult};
