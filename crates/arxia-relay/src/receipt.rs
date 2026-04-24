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
    /// Number of hops this message has traversed.
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
    /// Must be called before any state change (scoring, payout,
    /// slashing-waiver) trusts the receipt. See the CRIT-004 regression
    /// guards in `crate::scoring::tests` (compiled under `#[cfg(test)]`).
    pub fn verify(&self) -> Result<(), RelayReceiptError> {
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
}
