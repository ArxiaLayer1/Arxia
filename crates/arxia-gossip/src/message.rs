//! Gossip message types.

use serde::{Deserialize, Serialize};

/// A gossip message exchanged between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// A new block to propagate.
    BlockAnnounce {
        /// Serialized compact block bytes.
        block_data: Vec<u8>,
        /// Hop count for TTL tracking.
        hops: u8,
    },
    /// Request nonce registry synchronization.
    NonceSyncRequest {
        /// The requesting node identifier.
        from: String,
    },
    /// Response with nonce registry data.
    NonceSyncResponse {
        /// Nonce registry entries: block_hash, nonce, account_hash.
        entries: Vec<([u8; 32], u64, [u8; 32])>,
    },
    /// Heartbeat / keepalive.
    Ping {
        /// Node identifier.
        node_id: String,
        /// Timestamp.
        timestamp: u64,
    },
}
