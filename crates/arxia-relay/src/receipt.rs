//! Relay receipts for proving message forwarding.
//!
//! A [`RelayReceipt`] binds `(relay_id, message_hash, timestamp,
//! hop_count)` under an Ed25519 signature produced by the relay node.
//! [`RelayReceipt::verify`] checks the signature against the pubkey
//! encoded in `relay_id` over the domain-separated canonical message.
//!
//! Callers MUST call [`RelayReceipt::verify`] (directly, or indirectly
//! via [`crate::scoring::RelayScore::record_success`]) before trusting
//! any field of the receipt for a state change — this is the core
//! mitigation for CRIT-004 (forged-receipt reputation inflation).
//!
//! # Hop-count bound (HIGH-014, commit 036)
//!
//! `hop_count` is capped at [`MAX_HOPS_PER_RECEIPT`]. A receipt whose
//! `hop_count` exceeds the cap is rejected with
//! [`RelayReceiptError::HopCountTooHigh`] BEFORE any Ed25519 work —
//! cheap rejection of attacker-inflated values. The audit (HIGH-014):
//!
//! > Attack: relay claims `hop_count = 255` to inflate scoring or to
//! > confuse scoring logic that expects a small range.
//! > Impact: score manipulation; distance/range stats corrupt.
//!
//! The cap is set at 16, which is well above realistic mesh-relay
//! depths (typical LoRa mesh: 2-5 hops; pathological: ~10) but well
//! below the `u8::MAX` worst case. A future protocol revision can
//! raise it via a deprecation cycle.

use serde::{Deserialize, Serialize};

use arxia_core::ArxiaError;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`RelayReceipt`].
///
/// Any future change to the signed layout MUST bump the `-v1` suffix
/// so old and new signatures are mutually incompatible. This also
/// prevents a signature minted over the same raw bytes in a different
/// protocol context (e.g. a block hash) from being replayed here.
pub const RELAY_RECEIPT_DOMAIN: &[u8] = b"arxia-relay-receipt-v1";

/// Maximum number of hops a receipt may declare. HIGH-014 cap.
///
/// Receipts with `hop_count > MAX_HOPS_PER_RECEIPT` are rejected by
/// [`RelayReceipt::verify`] BEFORE any Ed25519 work. Set well above
/// realistic mesh depths (LoRa mesh typically 2-5 hops) and well
/// below `u8::MAX` to leave headroom for hardened scoring math
/// without admitting attacker-inflated values.
pub const MAX_HOPS_PER_RECEIPT: u8 = 16;

/// Errors returned by [`RelayReceipt::verify`] and the scoring calls
/// that wrap it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReceiptError {
    /// `relay_id` is not a 64-character lowercase-hex string of a
    /// 32-byte Ed25519 public key.
    InvalidRelayId,
    /// `message_hash` is not a 64-character lowercase-hex string of a
    /// 32-byte hash.
    InvalidMessageHash,
    /// `signature` is not exactly 64 bytes.
    InvalidSignatureLength,
    /// The Ed25519 public key encoded in `relay_id` is structurally
    /// invalid (e.g. low-order point, non-canonical encoding).
    InvalidPublicKey,
    /// The signature does not match the domain-separated canonical
    /// message under the declared relay pubkey. This is the exploit
    /// surface for CRIT-004 and for any tampering of receipt fields.
    SignatureInvalid,
    /// The receipt belongs to a different relay than the one being
    /// credited. Returned by
    /// [`crate::scoring::RelayScore::record_success`] when the caller
    /// tries to route a receipt minted for another relay.
    WrongRelayId,
    /// A receipt with this `message_hash` has already been credited
    /// to this [`crate::scoring::RelayScore`]. Returned when the same
    /// authentic receipt — or a differently-timestamped/hop-counted
    /// but same-message receipt — is replayed. Closes CRIT-005
    /// (duplicate-receipt reputation inflation).
    DuplicateReceipt,
    /// `hop_count` exceeds [`MAX_HOPS_PER_RECEIPT`]. HIGH-014: a
    /// relay claiming `hop_count = 255` would inflate scoring or
    /// confuse range-bounded stats. Rejected at ingress before any
    /// Ed25519 work.
    HopCountTooHigh {
        /// The hop_count declared in the receipt.
        got: u8,
        /// The protocol cap, [`MAX_HOPS_PER_RECEIPT`].
        max: u8,
    },
}

impl std::fmt::Display for RelayReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRelayId => {
                f.write_str("relay_id is not a 64-char lowercase hex 32-byte pubkey")
            }
            Self::InvalidMessageHash => {
                f.write_str("message_hash is not a 64-char lowercase hex 32-byte hash")
            }
            Self::InvalidSignatureLength => f.write_str("signature must be exactly 64 bytes"),
            Self::InvalidPublicKey => f.write_str("relay_id is not a valid Ed25519 public key"),
            Self::SignatureInvalid => {
                f.write_str("signature does not verify against the relay pubkey")
            }
            Self::WrongRelayId => f.write_str("receipt relay_id does not match the scored relay"),
            Self::DuplicateReceipt => {
                f.write_str("receipt with this message_hash has already been credited")
            }
            Self::HopCountTooHigh { got, max } => {
                write!(f, "hop_count {got} exceeds protocol cap {max}")
            }
        }
    }
}

impl std::error::Error for RelayReceiptError {}

/// A receipt proving that a relay node forwarded a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReceipt {
    /// The relay node public key as 64 lowercase hex chars (32 raw
    /// bytes). This is both an identifier and the verifying key for
    /// [`signature`](Self::signature).
    pub relay_id: String,
    /// Hash of the relayed block or message as 64 lowercase hex chars
    /// (32 raw bytes, typically a Blake3 digest).
    pub message_hash: String,
    /// Unix timestamp (seconds) when the relay occurred.
    pub timestamp: u64,
    /// Ed25519 signature by the relay node over the canonical message
    /// produced by [`RelayReceipt::canonical_message`]. MUST be exactly
    /// 64 bytes when the receipt is considered valid.
    pub signature: Vec<u8>,
    /// Number of hops this message has traversed. MUST be at most
    /// [`MAX_HOPS_PER_RECEIPT`]; values above the cap are rejected
    /// by [`RelayReceipt::verify`] (HIGH-014).
    pub hop_count: u8,
}

impl RelayReceipt {
    /// Build the canonical message bytes that the relay node signs.
    ///
    /// Layout (total = 22 + 32 + 32 + 8 + 1 = **95 bytes**):
    ///
    /// - `RELAY_RECEIPT_DOMAIN` (22 bytes)
    /// - relay pubkey           (32 bytes, raw)
    /// - message hash           (32 bytes, raw)
    /// - timestamp              (8 bytes, big-endian)
    /// - hop_count              (1 byte)
    ///
    /// Both binary fields (`relay_id`, `message_hash`) are decoded
    /// from hex here so that the bytes-to-sign are deterministic and
    /// independent of hex casing. Any decode failure is a structural
    /// error, not a signature error, and is reported as such.
    pub fn canonical_message(&self) -> Result<Vec<u8>, RelayReceiptError> {
        let relay_pub =
            decode_hex_32(&self.relay_id).map_err(|_| RelayReceiptError::InvalidRelayId)?;
        let msg_hash =
            decode_hex_32(&self.message_hash).map_err(|_| RelayReceiptError::InvalidMessageHash)?;
        let mut buf = Vec::with_capacity(RELAY_RECEIPT_DOMAIN.len() + 32 + 32 + 8 + 1);
        buf.extend_from_slice(RELAY_RECEIPT_DOMAIN);
        buf.extend_from_slice(&relay_pub);
        buf.extend_from_slice(&msg_hash);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.hop_count);
        Ok(buf)
    }

    /// Verify the Ed25519 signature on this receipt against the pubkey
    /// encoded in [`relay_id`](Self::relay_id).
    ///
    /// Order of checks:
    /// 1. **`hop_count` cap** ([`MAX_HOPS_PER_RECEIPT`], HIGH-014) —
    ///    cheap rejection of attacker-inflated values.
    /// 2. Canonical-message construction (hex decode of `relay_id`
    ///    and `message_hash`).
    /// 3. Signature length check.
    /// 4. Ed25519 verify.
    ///
    /// Must be called before any state change (scoring, payout,
    /// slashing-waiver) trusts the receipt. See the CRIT-004 regression
    /// guards in `crate::scoring::tests` (compiled under `#[cfg(test)]`).
    pub fn verify(&self) -> Result<(), RelayReceiptError> {
        // HIGH-014 cap: cheapest possible rejection. Fires before any
        // hex decode or Ed25519 work.
        if self.hop_count > MAX_HOPS_PER_RECEIPT {
            return Err(RelayReceiptError::HopCountTooHigh {
                got: self.hop_count,
                max: MAX_HOPS_PER_RECEIPT,
            });
        }
        let msg = self.canonical_message()?;
        let pk = decode_hex_32(&self.relay_id).map_err(|_| RelayReceiptError::InvalidRelayId)?;
        if self.signature.len() != 64 {
            return Err(RelayReceiptError::InvalidSignatureLength);
        }
        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RelayReceiptError::InvalidSignatureLength)?;
        arxia_crypto::verify(&pk, &msg, &sig).map_err(|e| match e {
            ArxiaError::InvalidKey(_) => RelayReceiptError::InvalidPublicKey,
            _ => RelayReceiptError::SignatureInvalid,
        })
    }
}

/// Decode a 64-char hex string into a 32-byte array. Returns `Err(())`
/// on any failure (not hex, wrong length).
fn decode_hex_32(s: &str) -> Result<[u8; 32], ()> {
    let v = hex::decode(s).map_err(|_| ())?;
    v.as_slice().try_into().map_err(|_| ())
}

/// A batch of relay receipts for efficient transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayBatch {
    /// Receipts in this batch.
    pub receipts: Vec<RelayReceipt>,
    /// Batch identifier.
    pub batch_id: u64,
}

impl RelayBatch {
    /// Create a new empty batch.
    pub fn new(batch_id: u64) -> Self {
        Self {
            receipts: Vec::new(),
            batch_id,
        }
    }

    /// Add a receipt to the batch.
    pub fn add(&mut self, receipt: RelayReceipt) {
        self.receipts.push(receipt);
    }

    /// Number of receipts in the batch.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    /// Build a correctly-signed receipt plus return the relay pubkey
    /// bytes (useful for cross-relay-identity tests).
    fn signed_receipt(timestamp: u64, hop_count: u8) -> (RelayReceipt, [u8; 32]) {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let message_hash_bytes = [0x11u8; 32];
        let mut r = RelayReceipt {
            relay_id: hex::encode(pk),
            message_hash: hex::encode(message_hash_bytes),
            timestamp,
            signature: Vec::new(),
            hop_count,
        };
        let msg = r.canonical_message().unwrap();
        r.signature = sign(&sk, &msg).to_vec();
        (r, pk)
    }

    #[test]
    fn test_canonical_message_layout_is_95_bytes() {
        let (r, _) = signed_receipt(12345, 7);
        let m = r.canonical_message().unwrap();
        assert_eq!(m.len(), 95, "22 + 32 + 32 + 8 + 1 = 95");
        assert_eq!(&m[0..RELAY_RECEIPT_DOMAIN.len()], RELAY_RECEIPT_DOMAIN);
        assert_eq!(*m.last().unwrap(), 7, "hop_count trails");
    }

    #[test]
    fn test_verify_accepts_correctly_signed_receipt() {
        let (r, _) = signed_receipt(1, 3);
        assert!(r.verify().is_ok());
    }

    #[test]
    fn test_verify_rejects_zero_signature() {
        // CRIT-004 core attack: attacker builds a struct literal with
        // `signature: vec![0; 64]`. That is a well-formed byte string
        // but not a valid Ed25519 signature over any message under any
        // pubkey, so verify() MUST reject.
        let (mut r, _) = signed_receipt(1, 3);
        r.signature = vec![0u8; 64];
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_timestamp() {
        let (mut r, _) = signed_receipt(100, 3);
        r.timestamp = 200;
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_message_hash() {
        let (mut r, _) = signed_receipt(1, 3);
        r.message_hash = hex::encode([0xFFu8; 32]);
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_hop_count() {
        let (mut r, _) = signed_receipt(1, 3);
        r.hop_count = r.hop_count.wrapping_add(1);
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_signature_swapped_to_different_relay() {
        // Receipt correctly signed by relay A; attacker swaps in
        // relay B's pubkey and hopes the old signature still
        // verifies. It must not.
        let (r1, _) = signed_receipt(1, 3);
        let (_, vk2) = generate_keypair();
        let mut r = r1;
        r.relay_id = hex::encode(vk2.to_bytes());
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_wrong_length_signature() {
        let (mut r, _) = signed_receipt(1, 3);
        r.signature = vec![0u8; 32];
        assert_eq!(r.verify(), Err(RelayReceiptError::InvalidSignatureLength));
    }

    #[test]
    fn test_verify_rejects_non_hex_relay_id() {
        let (mut r, _) = signed_receipt(1, 3);
        r.relay_id = "not hex at all".to_string();
        assert_eq!(r.verify(), Err(RelayReceiptError::InvalidRelayId));
    }

    #[test]
    fn test_verify_rejects_wrong_length_relay_id() {
        let (mut r, _) = signed_receipt(1, 3);
        r.relay_id = hex::encode([0u8; 16]); // 16 bytes, not 32
        assert_eq!(r.verify(), Err(RelayReceiptError::InvalidRelayId));
    }

    #[test]
    fn test_verify_rejects_non_hex_message_hash() {
        let (mut r, _) = signed_receipt(1, 3);
        r.message_hash = "ZZZZ".to_string();
        assert_eq!(r.verify(), Err(RelayReceiptError::InvalidMessageHash));
    }

    #[test]
    fn test_domain_separation_prevents_replay_of_non_receipt_signature() {
        // A signature minted over the same binary fields without the
        // domain-separation prefix must NOT verify as a receipt.
        // Attack scenario: attacker finds a signature they control on
        // `pk || hash || ts || hop` (e.g. from some other subsystem)
        // and tries to re-package it as a relay receipt.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut raw = Vec::new();
        raw.extend_from_slice(&pk);
        raw.extend_from_slice(&[0x11u8; 32]);
        raw.extend_from_slice(&5u64.to_be_bytes());
        raw.push(3);
        let sig_without_domain = sign(&sk, &raw);
        let r = RelayReceipt {
            relay_id: hex::encode(pk),
            message_hash: hex::encode([0x11u8; 32]),
            timestamp: 5,
            signature: sig_without_domain.to_vec(),
            hop_count: 3,
        };
        assert_eq!(r.verify(), Err(RelayReceiptError::SignatureInvalid));
    }

    // ============================================================
    // HIGH-014 (commit 036) — hop_count cap.
    // Receipts with `hop_count > MAX_HOPS_PER_RECEIPT` are rejected
    // BEFORE any Ed25519 work.
    // ============================================================

    #[test]
    fn test_max_hops_per_receipt_constant() {
        // Pin the cap. If the protocol revisits this value, the test
        // becomes a deliberate gate: changing 16 here forces a
        // conscious update.
        assert_eq!(MAX_HOPS_PER_RECEIPT, 16);
    }

    #[test]
    fn test_verify_rejects_hop_count_above_max() {
        // PRIMARY HIGH-014 PIN: hop_count = 255 (the audit's exact
        // attacker shape) must reject with HopCountTooHigh, NOT
        // succeed and NOT degrade to SignatureInvalid.
        let (r, _) = signed_receipt(1, 255);
        let err = r.verify().expect_err("hop_count=255 must be rejected");
        match err {
            RelayReceiptError::HopCountTooHigh { got, max } => {
                assert_eq!(got, 255);
                assert_eq!(max, MAX_HOPS_PER_RECEIPT);
            }
            other => panic!("expected HopCountTooHigh, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_hop_count_just_above_max() {
        // Boundary: hop_count = MAX + 1 must reject. Pins the
        // off-by-one edge.
        let (r, _) = signed_receipt(1, MAX_HOPS_PER_RECEIPT + 1);
        let err = r.verify().expect_err("hop_count = MAX+1 must be rejected");
        assert!(matches!(
            err,
            RelayReceiptError::HopCountTooHigh { got, max }
                if got == MAX_HOPS_PER_RECEIPT + 1 && max == MAX_HOPS_PER_RECEIPT
        ));
    }

    #[test]
    fn test_verify_accepts_hop_count_at_max() {
        // Boundary: hop_count = MAX is accepted (signature must be
        // valid for that hop_count). Pins that the cap is
        // INCLUSIVE — the cap value itself is allowed.
        let (r, _) = signed_receipt(1, MAX_HOPS_PER_RECEIPT);
        assert!(
            r.verify().is_ok(),
            "hop_count = MAX must be accepted with valid signature"
        );
    }

    #[test]
    fn test_verify_accepts_hop_count_zero() {
        // Boundary: hop_count = 0 is accepted (e.g. originator's
        // receipt before any forwarding). Pins that there's no
        // implicit lower bound on hop_count.
        let (r, _) = signed_receipt(1, 0);
        assert!(r.verify().is_ok(), "hop_count = 0 must be accepted");
    }

    #[test]
    fn test_verify_hop_count_check_fires_before_signature_verify() {
        // ORDER PIN: even if the signature is structurally invalid,
        // the hop_count cap must fire first (cheap rejection). This
        // ensures an attacker cannot probe Ed25519 verify timing
        // with hop_count = 255 + garbage signature.
        let (mut r, _) = signed_receipt(1, 255);
        r.signature = vec![0u8; 64]; // invalid signature
        let err = r.verify().expect_err("must reject");
        match err {
            RelayReceiptError::HopCountTooHigh { .. } => {} // expected
            RelayReceiptError::SignatureInvalid => {
                panic!("hop_count cap must fire before signature verify")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_hop_count_too_high_display_format() {
        let err = RelayReceiptError::HopCountTooHigh {
            got: 200,
            max: MAX_HOPS_PER_RECEIPT,
        };
        let s = format!("{err}");
        assert!(s.contains("200"));
        assert!(s.contains(&MAX_HOPS_PER_RECEIPT.to_string()));
    }
}
