//! Transport trait definition.

use arxia_core::ArxiaError;
use ed25519_dalek::SigningKey;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`SignedTransportMessage`].
///
/// Any future change to the signed layout MUST bump the `-v1`
/// suffix so old and new signatures are mutually incompatible.
/// Distinct from every other Arxia signing domain
/// (`arxia-relay-receipt-v1`, `arxia-relay-slash-v1`,
/// `arxia-gossip-msg-v1`, `arxia-finality-confirmation-v1`,
/// `arxia-finality-validator-vote-v1`) so a signature minted in
/// any other context cannot be replayed as a transport message.
pub const TRANSPORT_MESSAGE_DOMAIN: &[u8] = b"arxia-transport-msg-v1";

/// A message sent over the transport layer.
#[derive(Debug, Clone)]
pub struct TransportMessage {
    /// Sender identifier (hex-encoded public key).
    pub from: String,
    /// Recipient identifier (hex-encoded public key, or empty for broadcast).
    pub to: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Timestamp when the message was created (ms since epoch).
    pub timestamp: u64,
}

/// A [`TransportMessage`] paired with an Ed25519 signature that
/// authenticates the `from` field. See HIGH-012 in the
/// crate-level docstring.
///
/// Construct via [`SignedTransportMessage::sign`]; verify on the
/// receive side via [`SignedTransportMessage::verify`].
#[derive(Debug, Clone)]
pub struct SignedTransportMessage {
    /// The underlying transport message. `from` is the
    /// hex-encoded pubkey of the signer; tampering with any
    /// field invalidates [`Self::signature`].
    pub message: TransportMessage,
    /// Ed25519 signature over the domain-separated canonical
    /// bytes of `message`. Exactly 64 bytes.
    pub signature: [u8; 64],
}

impl SignedTransportMessage {
    /// Build the canonical signed bytes for a transport message.
    ///
    /// Layout (`from_pubkey` is the hex-decoded 32-byte form of
    /// `msg.from`):
    ///
    /// ```text
    /// TRANSPORT_MESSAGE_DOMAIN (22 B)
    /// || from_pubkey (32 B)
    /// || to.len() as u32 little-endian (4 B)
    /// || to (variable)
    /// || payload.len() as u32 little-endian (4 B)
    /// || payload (variable)
    /// || timestamp (8 B big-endian)
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Err(TransportError::InvalidFromField)` if
    /// `msg.from` is not a 64-char lowercase hex string of a
    /// 32-byte pubkey. The signed layout requires the raw
    /// pubkey bytes, so a malformed `from` cannot be signed.
    pub fn canonical_bytes(msg: &TransportMessage) -> Result<Vec<u8>, TransportError> {
        let from_pk_vec = hex::decode(&msg.from).map_err(|_| TransportError::InvalidFromField)?;
        if from_pk_vec.len() != 32 {
            return Err(TransportError::InvalidFromField);
        }
        let to_len = u32::try_from(msg.to.len()).map_err(|_| TransportError::InvalidFromField)?;
        let payload_len =
            u32::try_from(msg.payload.len()).map_err(|_| TransportError::InvalidFromField)?;
        let mut buf = Vec::with_capacity(
            TRANSPORT_MESSAGE_DOMAIN.len() + 32 + 4 + msg.to.len() + 4 + msg.payload.len() + 8,
        );
        buf.extend_from_slice(TRANSPORT_MESSAGE_DOMAIN);
        buf.extend_from_slice(&from_pk_vec);
        buf.extend_from_slice(&to_len.to_le_bytes());
        buf.extend_from_slice(msg.to.as_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&msg.payload);
        buf.extend_from_slice(&msg.timestamp.to_be_bytes());
        Ok(buf)
    }

    /// Sign a transport message. The `from` field is auto-
    /// populated from `signing_key`'s pubkey — callers cannot
    /// spoof it.
    pub fn sign(signing_key: &SigningKey, to: String, payload: Vec<u8>, timestamp: u64) -> Self {
        let pk = signing_key.verifying_key().to_bytes();
        let message = TransportMessage {
            from: hex::encode(pk),
            to,
            payload,
            timestamp,
        };
        // canonical_bytes only fails on malformed `from`; we
        // just constructed it from a valid pubkey, so unwrap is
        // safe here. (Documented invariant.)
        let canonical =
            Self::canonical_bytes(&message).expect("from is hex of a valid 32-byte pubkey");
        let signature = arxia_crypto::sign(signing_key, &canonical);
        Self { message, signature }
    }

    /// Verify the signature on a received transport message.
    ///
    /// Returns `Ok(())` iff:
    /// 1. `message.from` decodes to a valid 32-byte Ed25519
    ///    pubkey.
    /// 2. `signature` is a valid Ed25519 signature over the
    ///    domain-separated canonical encoding of `message`,
    ///    under that pubkey.
    ///
    /// Any tampering with `from`, `to`, `payload`, or
    /// `timestamp` post-signing invalidates the verification.
    /// The `from` field is bound to the signer's pubkey by the
    /// signature, so a peer cannot claim
    /// `from = "alice"` while actually being eve.
    ///
    /// # Errors
    ///
    /// - [`TransportError::InvalidFromField`] — `from` is not a
    ///   64-char hex 32-byte pubkey.
    /// - [`TransportError::SignatureInvalid`] — signature does
    ///   not verify under the pubkey decoded from `from`.
    pub fn verify(&self) -> Result<(), TransportError> {
        let from_pk_vec =
            hex::decode(&self.message.from).map_err(|_| TransportError::InvalidFromField)?;
        let from_pk: [u8; 32] = from_pk_vec
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::InvalidFromField)?;
        let canonical = Self::canonical_bytes(&self.message)?;
        arxia_crypto::verify(&from_pk, &canonical, &self.signature)
            .map_err(|_| TransportError::SignatureInvalid)?;
        Ok(())
    }
}

/// Errors specific to the transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Message exceeds the MTU for this transport.
    PayloadTooLarge {
        /// Size of the payload.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// The transport channel is disconnected.
    Disconnected,
    /// The message was lost (simulated packet loss).
    MessageLost,
    /// The send-side buffer is at capacity. The caller MUST slow down or
    /// drain its outbox before retrying. Returned by transports that bound
    /// their outbox to prevent unbounded memory growth (CRIT-012).
    BackPressure {
        /// Configured capacity of the outbox (messages, not bytes).
        capacity: usize,
    },
    /// The `from` field of a [`SignedTransportMessage`] is not a
    /// 64-char lowercase hex 32-byte pubkey. HIGH-012 structural
    /// guard: a non-pubkey `from` cannot be signature-bound to
    /// any identity, so it is rejected at parse time.
    InvalidFromField,
    /// The Ed25519 signature on a [`SignedTransportMessage`]
    /// does not verify under the pubkey decoded from `from`.
    /// HIGH-012 PRIMARY: tampered or spoofed `from` triggers
    /// this variant; a peer cannot claim someone else's
    /// identity at the transport layer.
    SignatureInvalid,
    /// Generic transport error.
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {} > {}", size, max)
            }
            Self::Disconnected => write!(f, "transport disconnected"),
            Self::MessageLost => write!(f, "message lost"),
            Self::BackPressure { capacity } => {
                write!(f, "transport outbox full (capacity {})", capacity)
            }
            Self::InvalidFromField => {
                write!(
                    f,
                    "transport message `from` is not a 64-char hex 32-byte pubkey"
                )
            }
            Self::SignatureInvalid => {
                write!(
                    f,
                    "transport message signature does not verify under `from`"
                )
            }
            Self::Other(msg) => write!(f, "transport error: {}", msg),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<TransportError> for ArxiaError {
    fn from(e: TransportError) -> Self {
        ArxiaError::Transport(e.to_string())
    }
}

/// Trait for all Arxia transport implementations.
pub trait TransportTrait {
    /// Send a message to a specific peer or broadcast.
    fn send(&mut self, msg: TransportMessage) -> Result<(), TransportError>;

    /// Try to receive a pending message (non-blocking).
    fn try_recv(&mut self) -> Option<TransportMessage>;

    /// Maximum transmission unit in bytes.
    fn mtu(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::generate_keypair;

    fn signed_msg(
        to: &str,
        payload: Vec<u8>,
        timestamp: u64,
    ) -> (SignedTransportMessage, [u8; 32]) {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let m = SignedTransportMessage::sign(&sk, to.to_string(), payload, timestamp);
        (m, pk)
    }

    #[test]
    fn test_signed_transport_from_is_pubkey_hex() {
        // The `from` field is auto-populated from the signer's
        // pubkey — callers cannot spoof it.
        let (m, pk) = signed_msg("bob", vec![1, 2, 3], 42);
        assert_eq!(m.message.from, hex::encode(pk));
    }

    #[test]
    fn test_signed_transport_verify_passes_on_correctly_signed_message() {
        let (m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        assert!(m.verify().is_ok());
    }

    #[test]
    fn test_signed_transport_rejects_spoofed_from_field() {
        // PRIMARY HIGH-012 PIN: peer signed under their own
        // key, then swapped `from` to alice's hex. Verify must
        // reject — the signature was minted under the original
        // pubkey, the new `from` decodes to a different pubkey,
        // and verify_strict fails.
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        let (_, alice_vk) = generate_keypair();
        m.message.from = hex::encode(alice_vk.to_bytes());
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_rejects_tampered_to() {
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.message.to = "carol".to_string();
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_rejects_tampered_payload() {
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.message.payload = vec![9, 9, 9];
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_rejects_tampered_timestamp() {
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.message.timestamp = 99;
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_rejects_zero_signature() {
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.signature = [0u8; 64];
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_rejects_non_hex_from() {
        // Structural guard: `from` is required to be a 64-char
        // hex 32-byte pubkey for canonical bytes to be
        // computable. Garbage `from` rejected with
        // InvalidFromField (distinct from SignatureInvalid).
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.message.from = "not hex at all".to_string();
        assert_eq!(m.verify(), Err(TransportError::InvalidFromField));
    }

    #[test]
    fn test_signed_transport_rejects_wrong_length_from() {
        // 16-byte hex (32 chars) rejected — not a 32-byte pubkey.
        let (mut m, _) = signed_msg("bob", vec![1, 2, 3], 42);
        m.message.from = hex::encode([0u8; 16]);
        assert_eq!(m.verify(), Err(TransportError::InvalidFromField));
    }

    #[test]
    fn test_signed_transport_canonical_bytes_layout() {
        // Pin the canonical layout: domain || from_pk || to_len
        // || to || payload_len || payload || ts.
        let (m, pk) = signed_msg("bob", vec![1, 2, 3], 42);
        let canon = SignedTransportMessage::canonical_bytes(&m.message).unwrap();
        assert!(canon.starts_with(TRANSPORT_MESSAGE_DOMAIN));
        let after_domain = &canon[TRANSPORT_MESSAGE_DOMAIN.len()..];
        assert_eq!(&after_domain[..32], &pk);
        let after_from = &after_domain[32..];
        assert_eq!(&after_from[..4], &(3u32).to_le_bytes()); // "bob".len() = 3
        assert_eq!(&after_from[4..7], b"bob");
        let after_to = &after_from[7..];
        assert_eq!(&after_to[..4], &(3u32).to_le_bytes()); // payload len = 3
        assert_eq!(&after_to[4..7], &[1u8, 2, 3]);
        assert_eq!(&after_to[7..15], &(42u64).to_be_bytes());
    }

    #[test]
    fn test_signed_transport_domain_prevents_replay_from_other_subsystems() {
        // A signature minted over the same binary fields without
        // the domain-separation prefix must NOT verify as a
        // transport message. Defense-in-depth: each subsystem
        // signs under its own domain; a relay-receipt signature
        // can never be replayed as a transport message.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        // Build the canonical layout WITHOUT the domain prefix
        // and sign it.
        let mut raw = Vec::new();
        raw.extend_from_slice(&pk);
        raw.extend_from_slice(&(3u32).to_le_bytes());
        raw.extend_from_slice(b"bob");
        raw.extend_from_slice(&(3u32).to_le_bytes());
        raw.extend_from_slice(&[1u8, 2, 3]);
        raw.extend_from_slice(&(42u64).to_be_bytes());
        let sig = arxia_crypto::sign(&sk, &raw);
        let m = SignedTransportMessage {
            message: TransportMessage {
                from: hex::encode(pk),
                to: "bob".to_string(),
                payload: vec![1, 2, 3],
                timestamp: 42,
            },
            signature: sig,
        };
        assert_eq!(m.verify(), Err(TransportError::SignatureInvalid));
    }

    #[test]
    fn test_signed_transport_with_empty_to_and_payload() {
        // Boundary: broadcast (empty `to`) + empty payload still
        // sign and verify.
        let (sk, _) = generate_keypair();
        let m = SignedTransportMessage::sign(&sk, String::new(), Vec::new(), 0);
        assert!(m.verify().is_ok());
    }
}
