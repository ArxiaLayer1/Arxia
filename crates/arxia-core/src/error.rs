//! Unified error type for the Arxia protocol.
//!
//! # Errors are data, not text
//!
//! Variants carry typed fields — discriminant enums, counts, the
//! actual nonce or byte length — so that consumers route on data
//! rather than parse messages. The first consumer this serves is
//! relay slashing: deciding how to treat a peer requires knowing
//! *which* rule was broken (a stale timestamp is a replay signal, a
//! bad signature is an impersonation signal, a non-Open genesis is an
//! attempted mint), and that distinction must survive any rewording
//! of a human-facing message. `Display` still renders an operator-
//! readable sentence for every variant; the sentence is derived from
//! the fields, never the other way around.
//!
//! Consequences for contributors:
//!
//! - Adding a failure mode means adding a variant or a discriminant,
//!   not formatting a new message into an existing `String`.
//! - Two different causes must never map to the same variant with
//!   the same fields — if code can tell them apart, the error must.
//!   Each discriminant family has a test asserting exactly that, and
//!   those tests are mutation-verified.

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

    /// Ed25519 signature verification failed, structurally or
    /// cryptographically. The fault says which — the two are
    /// different adversarial signals and must stay routable.
    #[error("signature invalid: {fault}")]
    SignatureInvalid {
        /// What exactly failed.
        fault: SignatureFault,
    },

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

    /// The first block of an account chain violates a genesis rule.
    ///
    /// Carries the violated rule as a typed discriminant rather than
    /// prose, so a consumer (finality scoring, relay slashing) can
    /// route on *which* rule was broken instead of parsing a message.
    #[error("invalid genesis block: {rule}")]
    InvalidGenesis {
        /// The specific rule the block broke.
        rule: GenesisRule,
    },

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

    /// Transport-level fault, with the transport crate's own typed
    /// error mirrored across the crate boundary so its payloads
    /// survive the conversion instead of being flattened to prose.
    #[error("transport error: {fault}")]
    Transport {
        /// The specific transport fault.
        fault: TransportFault,
    },

    /// Sync timed out.
    #[error("sync timeout")]
    SyncTimeout,

    /// No neighbors available for gossip.
    #[error("no neighbors available")]
    NoNeighbors,

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// A protocol item failed to serialize.
    #[error("serialization failed for {item}")]
    Serialization {
        /// Which item was being serialized.
        item: SerializedItem,
    },

    /// A 32-byte Ed25519 public key failed structural or curve
    /// validation.
    #[error("invalid key: {fault}")]
    InvalidKey {
        /// What exactly is wrong with the key.
        fault: KeyFault,
    },

    /// A DID string failed to parse. Split from [`ArxiaError::InvalidKey`]:
    /// a malformed identifier string and a cryptographically unusable
    /// key are different signals, and only the latter concerns the
    /// curve.
    #[error("invalid DID: {fault}")]
    InvalidDid {
        /// What exactly is wrong with the DID string.
        fault: DidFault,
    },

    /// A storage backend failed: an I/O error, a corrupted database,
    /// or a poisoned lock. Introduced with the first persistent
    /// backend — before that, storage faults had no variant of their
    /// own and were shoehorned into [`ArxiaError::InvalidKey`].
    #[error("storage backend error: {0}")]
    Storage(String),

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

    /// `AccountChain::send` was called with a destination equal to the
    /// sender's own public key (HIGH-002). Self-sends inflate the
    /// nonce without an economic effect and, combined with any
    /// dedup-bypass on the receive path, become a free-mint vector.
    /// Refused at `send()` time before any state mutation.
    #[error("send rejected: destination equals sender (self-send not allowed)")]
    SelfSendNotAllowed,

    /// A vote was received whose `block_hash` is not in the local
    /// block store. HIGH-006 defence: votes pointing at phantom blocks
    /// would otherwise allow stake to be "spent" on nothing,
    /// poisoning `resolve_conflict_orv` weights. Returned by
    /// `arxia_consensus::vote::verify_vote_known` on ingress.
    #[error("vote rejected: block hash {block_hash} not in local block store")]
    UnknownVoteTarget {
        /// Hex-encoded block hash that the vote targets.
        block_hash: String,
    },

    /// `resolve_conflict_orv` was called with a block whose
    /// `block_type` is not eligible for ORV conflict resolution.
    /// HIGH-025 defence: the cascade is the *monetary* / chain-
    /// continuity adjudicator; conflating a `Revoke` (DID credential
    /// revocation) with a `Send` would let a non-monetary block win
    /// an economic conflict and be applied by the reconciliation
    /// pipeline as if it had balance implications. Only
    /// `{Open, Send, Receive}` are accepted on this path.
    #[error(
        "ORV conflict resolution rejected: block {block_hash} has ineligible type {block_type}"
    )]
    IneligibleConflictBlockType {
        /// Hex-encoded block hash.
        block_hash: String,
        /// Debug-formatted block type tag (e.g. `"Revoke"`).
        block_type: String,
    },

    /// A block's self-declared `balance` disagrees with the value the
    /// ledger derives from the account's prior balance and the block's
    /// operation. `Ledger::add_block` derives balances from chain
    /// history (Open mints `initial_balance`; Send debits `amount`;
    /// Receive credits the cited Send's `amount`; Revoke is
    /// balance-neutral) and rejects any block that disagrees. Without
    /// this check a signed block could declare an arbitrary balance and
    /// create value from nothing.
    #[error("balance mismatch on account {account}: declared {got}, expected {expected}")]
    BalanceMismatch {
        /// Hex-encoded account public key.
        account: String,
        /// The balance derived from history plus the operation.
        expected: u64,
        /// The balance the block declared.
        got: u64,
    },

    /// An `Open` block was submitted on a chain that already exists.
    /// Only the first block of a chain may be an `Open`; a second one
    /// would re-run the supply accumulator and overwrite the running
    /// balance.
    #[error("open rejected: account {account} already has an open chain")]
    OpenNotGenesis {
        /// Hex-encoded account public key.
        account: String,
    },

    /// A `Receive` block references a `source_hash` that does not
    /// correspond to any accepted `Send` block in the ledger.
    /// Phantom-receive defense: prevents a forged `Receive` citing
    /// a fabricated 64-hex `source_hash` from minting balance out
    /// of nothing.
    #[error("receive references unknown source send: {source_hash}")]
    UnknownSourceSend {
        /// Hex-encoded `source_hash` from the `Receive` block.
        source_hash: String,
    },
}

/// The specific genesis rule an [`ArxiaError::InvalidGenesis`] reports.
///
/// A typed discriminant, not prose: two different violations must stay
/// distinguishable by code, because a consumer deciding how to treat a
/// peer (mere malformation vs. an attempted second mint) needs the
/// *which*, not a message to parse. `Display` still renders an
/// operator-readable sentence for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenesisRule {
    /// The first block's nonce must be exactly 1.
    #[error("nonce must be 1, got {got}")]
    NonceMustBeOne {
        /// The nonce the block actually declared.
        got: u64,
    },
    /// The first block of a chain must be an `Open`.
    #[error("first block must be OPEN")]
    FirstBlockMustBeOpen,
    /// A genesis block has no predecessor, so its `previous` field
    /// must be empty.
    #[error("genesis must have empty previous, got a non-empty hash")]
    PreviousMustBeEmpty,
}

/// The specific fault behind an [`ArxiaError::InvalidKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyFault {
    /// The bytes do not decode to a point on the Ed25519 curve.
    #[error("not a valid point on the Ed25519 curve")]
    NotOnCurve,
    /// The point is low-order (small-subgroup / weak), rejected by
    /// strict validation even though it is on the curve.
    #[error("low-order (weak) public key")]
    WeakPoint,
    /// The key is not exactly 32 bytes.
    #[error("expected 32 key bytes, got {got}")]
    Length {
        /// The byte count actually supplied.
        got: usize,
    },
    /// The account field is not valid hex, so no key bytes could be
    /// recovered at all.
    #[error("the account field is not valid hex")]
    HexEncoding,
}

/// The specific fault behind an [`ArxiaError::InvalidDid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DidFault {
    /// The string does not start with the canonical `did:arxia:`
    /// prefix.
    #[error("missing the required 'did:arxia:' prefix")]
    MissingPrefix,
    /// The identifier part is not valid base58.
    #[error("the identifier is not valid base58")]
    Base58,
    /// The identifier decodes to the wrong number of bytes.
    #[error("the identifier must decode to {expected} bytes, got {got}")]
    Length {
        /// The byte count actually decoded.
        got: usize,
        /// The byte count the DID scheme requires.
        expected: usize,
    },
}

/// The specific fault behind an [`ArxiaError::SignatureInvalid`].
///
/// `Verification` is the cryptographic failure: well-formed inputs,
/// equation does not hold (dalek `verify_strict`, canonical-S and
/// low-order rejection included). The other two are structural: the
/// bytes never reached the equation. A peer submitting well-formed
/// blocks that fail verification looks like tampering or key
/// confusion; a peer submitting structurally malformed blocks looks
/// like a broken or hostile serializer. Scoring may weigh them
/// differently, so the discriminant keeps them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureFault {
    /// The Ed25519 equation did not verify under the account key.
    #[error("the signature does not verify under the account key")]
    Verification,
    /// The signature is not exactly 64 bytes.
    #[error("expected a 64-byte signature, got {got} bytes")]
    Length {
        /// The length actually supplied.
        got: usize,
    },
    /// The block's hash field is not valid hex, so there was nothing
    /// well-formed to verify against.
    ///
    /// Defense-in-depth: on the current verify path this cannot fire,
    /// because the recompute-and-compare check runs first and the
    /// recomputed hash is always valid hex. It exists so the decode
    /// that follows maps to a typed fault instead of a panic path,
    /// and so a future reordering of the checks fails loudly into a
    /// meaningful variant.
    #[error("the block hash field is not valid hex")]
    HashEncoding,
}

/// The specific fault behind an [`ArxiaError::Transport`].
///
/// Mirrors the transport crate's own error type field-for-field; the
/// `From` conversion over there is an exhaustive match, so adding a
/// transport error variant without mapping it here is a compile
/// error, not a silent flattening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportFault {
    /// Message exceeds the MTU for this transport.
    #[error("payload too large: {size} > {max}")]
    PayloadTooLarge {
        /// Size of the payload.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// The transport channel is disconnected.
    #[error("transport disconnected")]
    Disconnected,
    /// The message was lost in transit.
    #[error("message lost")]
    MessageLost,
    /// The send-side outbox is at capacity; the caller must drain
    /// before retrying.
    #[error("transport outbox full (capacity {capacity})")]
    BackPressure {
        /// Configured outbox capacity, in messages.
        capacity: usize,
    },
    /// The message's `from` field is not a 64-char hex pubkey.
    #[error("transport message `from` is not a 64-char hex 32-byte pubkey")]
    InvalidFromField,
    /// The message signature does not verify under `from`.
    #[error("transport message signature does not verify under `from`")]
    SignatureInvalid,
    /// The message timestamp falls outside the freshness window.
    #[error(
        "message timestamp {timestamp} outside freshness window (now {now}, max skew {max_skew} ms)"
    )]
    TimestampStale {
        /// Message timestamp, ms since epoch.
        timestamp: u64,
        /// Verifier clock, ms since epoch.
        now: u64,
        /// Accepted deviation either side, ms.
        max_skew: u64,
    },
}

/// Which protocol item an [`ArxiaError::Serialization`] was
/// serializing when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SerializedItem {
    /// The `BlockType` payload of a block being hashed.
    #[error("block type")]
    BlockType,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2 of the typed-error rework: `Display` must stay operator-
    /// readable. Each rule renders a sentence carrying its payload,
    /// not a bare variant name.
    /// R2 for the key and DID families.
    #[test]
    fn key_and_did_display_are_operator_readable() {
        let k = ArxiaError::InvalidKey {
            fault: KeyFault::Length { got: 31 },
        };
        let msg = k.to_string();
        assert!(
            msg.contains("invalid key") && msg.contains("got 31"),
            "wrapper must carry family and payload: {msg}"
        );
        assert!(KeyFault::WeakPoint.to_string().contains("weak"));

        let d = ArxiaError::InvalidDid {
            fault: DidFault::Length {
                got: 30,
                expected: 32,
            },
        };
        let msg = d.to_string();
        assert!(
            msg.contains("invalid DID") && msg.contains("30") && msg.contains("32"),
            "wrapper must carry family and both payloads: {msg}"
        );
        assert!(DidFault::MissingPrefix.to_string().contains("did:arxia:"));
    }

    /// R2 for the signature family.
    #[test]
    fn signature_fault_display_is_operator_readable() {
        let l = ArxiaError::SignatureInvalid {
            fault: SignatureFault::Length { got: 63 },
        };
        let msg = l.to_string();
        assert!(
            msg.contains("signature invalid") && msg.contains("got 63 bytes"),
            "wrapper must carry family and payload: {msg}"
        );
        let v = SignatureFault::Verification.to_string();
        assert!(v.contains("does not verify"));
        let h = SignatureFault::HashEncoding.to_string();
        assert!(h.contains("hex"));
    }

    /// R2 for the transport and serialization families.
    #[test]
    fn transport_and_serialization_display_are_operator_readable() {
        let f = TransportFault::BackPressure { capacity: 128 };
        assert_eq!(f.to_string(), "transport outbox full (capacity 128)");
        let wrapped = ArxiaError::Transport { fault: f };
        assert!(wrapped.to_string().starts_with("transport error:"));

        let s = ArxiaError::Serialization {
            item: SerializedItem::BlockType,
        };
        assert_eq!(s.to_string(), "serialization failed for block type");
    }

    #[test]
    fn genesis_rule_display_is_operator_readable() {
        let nonce = GenesisRule::NonceMustBeOne { got: 7 };
        let open = GenesisRule::FirstBlockMustBeOpen;
        let prev = GenesisRule::PreviousMustBeEmpty;

        assert_eq!(nonce.to_string(), "nonce must be 1, got 7");
        assert!(open.to_string().contains("OPEN"));
        assert!(prev.to_string().contains("previous"));

        // The wrapper composes the rule into its own message.
        let wrapped = ArxiaError::InvalidGenesis { rule: nonce };
        let msg = wrapped.to_string();
        assert!(
            msg.contains("invalid genesis block") && msg.contains("got 7"),
            "wrapper must carry both the family and the payload: {msg}"
        );
    }
}
