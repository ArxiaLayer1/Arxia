//! Unified error type for the Arxia protocol.

use thiserror::Error;

/// Unified error type across all Arxia crates.
#[derive(Debug, Error)]
pub enum ArxiaError {
    /// Invalid block type tag byte.
    #[error("invalid block type tag: 0x{0:02x}")]
    InvalidBlockType(u8),

    /// Data too short for deserialization.
    #[error("data too short: {got} bytes (need {expected})")]
    DataTooShort {
        /// Bytes received.
        got: usize,
        /// Bytes expected.
        expected: usize,
    },

    /// Hash does not match recomputed value.
    #[error("hash mismatch")]
    HashMismatch,

    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Insufficient balance for the operation.
    #[error("insufficient balance: {available} < {required}")]
    InsufficientBalance {
        /// Available balance.
        available: u64,
        /// Required balance.
        required: u64,
    },

    /// Cannot send zero amount.
    #[error("cannot send zero amount")]
    ZeroAmount,

    /// Nonce gap detected in account chain.
    #[error("nonce gap at block {index}: expected {expected}, got {got}")]
    NonceGap {
        /// Block index in the chain.
        index: usize,
        /// Expected nonce value.
        expected: u64,
        /// Actual nonce value.
        got: u64,
    },

    /// Hash chain is broken between consecutive blocks.
    #[error("hash chain broken at block {0}")]
    HashChainBroken(usize),

    /// Genesis block validation error.
    #[error("invalid genesis block: {0}")]
    InvalidGenesis(String),

    /// SEND block destination mismatch.
    #[error("SEND block not addressed to this account")]
    WrongDestination,

    /// Expected a SEND block but got a different type.
    #[error("can only RECEIVE from a SEND block")]
    NotSendBlock,

    /// Double-spend detected (same nonce, different block hash).
    #[error("double-spend detected for account at nonce {nonce}")]
    DoubleSpend {
        /// The conflicting nonce.
        nonce: u64,
    },

    /// Transport-level error.
    #[error("transport error: {0}")]
    Transport(String),

    /// Sync timed out.
    #[error("sync timeout")]
    SyncTimeout,

    /// No neighbors available for gossip.
    #[error("no neighbors available")]
    NoNeighbors,

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid cryptographic key.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Attempt to Open an account that already has blocks in its chain.
    #[error("account already open: chain is not empty")]
    AccountAlreadyOpen,

    /// Attempt to Open an account with an initial balance that exceeds
    /// the per-account ceiling or the remaining protocol supply.
    #[error("supply cap exceeded: requested {requested} > max {max}")]
    SupplyCapExceeded {
        /// Requested initial balance in micro-ARX.
        requested: u64,
        /// Maximum allowed initial balance in micro-ARX.
        max: u64,
    },

    /// Attempt to RECEIVE from a SEND block whose hash has already been
    /// consumed by this account.
    #[error("duplicate receive: source hash {source_hash} already consumed")]
    DuplicateReceive {
        /// The hash of the SEND block that was already received.
        source_hash: String,
    },

    /// Two or more blocks with the same (account, nonce) seen during
    /// reconciliation or registry merge. Distinct from `DoubleSpend` in
    /// that this variant carries the competing block hashes for downstream
    /// ORV resolution.
    #[error("nonce conflict: account {account} nonce {nonce} has {count} competing blocks")]
    NonceConflict {
        /// Hex-encoded account public key.
        account: String,
        /// The conflicting nonce.
        nonce: u64,
        /// How many distinct blocks claimed this (account, nonce).
        count: usize,
    },

    /// Reconciliation produced a negative balance for an account. This
    /// signals that a double-spend or underflow was silently accepted
    /// earlier in the merge and is the last-line defense against
    /// corrupt state after partition merge.
    #[error("negative balance after reconciliation: account {account} balance {balance}")]
    NegativeBalance {
        /// Hex-encoded account public key.
        account: String,
        /// The (negative) balance computed.
        balance: i64,
    },

    /// An arithmetic operation on a balance would exceed `u64::MAX`.
    /// Returned by code paths that refuse to silently wrap an
    /// attacker-influenced addition (CRIT-018: `AccountChain::receive`).
    #[error("balance overflow: current {current} + incoming {incoming} > u64::MAX")]
    BalanceOverflow {
        /// Current balance on the account.
        current: u64,
        /// Amount that would have been added.
        incoming: u64,
    },
}
