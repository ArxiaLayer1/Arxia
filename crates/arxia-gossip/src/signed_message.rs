//! Signed gossip messages with Ed25519 sender authentication.
//!
//! Wraps [`crate::GossipMessage`] in a [`SignedGossipMessage`] envelope
//! that binds the message bytes to the sender's public key under an
//! Ed25519 signature with domain prefix [`GOSSIP_MESSAGE_DOMAIN`]. This
//! closes CRIT-010 (peer-level message forgery: any peer could
//! synthesize a `NonceSyncResponse` with attacker-chosen registry
//! entries or a `BlockAnnounce` with attacker-chosen `block_data`,
//! because the wire format had no sender authenticity at the message
//! layer).
//!
//! # Layout
//!
//! The bytes that the sender signs are
//! `GOSSIP_MESSAGE_DOMAIN || sender_pubkey || variant_tag || variant_fields`,
//! where `variant_tag` is a single byte distinguishing the four
//! [`GossipMessage`] variants. See
//! [`SignedGossipMessage::canonical_bytes`] for the exact per-variant
//! encoding. Domain separation prevents a signature minted in another
//! protocol context (e.g. a relay receipt or a slashing proof) from
//! being replayed as a gossip message.
//!
//! # Usage
//!
//! ```ignore
//! use arxia_crypto::{generate_keypair, sign};
//! use arxia_gossip::{GossipMessage, SignedGossipMessage};
//!
//! let (sk, vk) = generate_keypair();
//! let sender_pubkey = vk.to_bytes();
//! let message = GossipMessage::Ping {
//!     node_id: "n1".into(),
//!     timestamp: 1_700_000_000,
//! };
//! let canonical = SignedGossipMessage::canonical_bytes(&message, &sender_pubkey);
//! let sig = sign(&sk, &canonical);
//! let signed = SignedGossipMessage {
//!     message,
//!     sender_pubkey,
//!     signature: sig.to_vec(),
//! };
//! assert!(signed.verify().is_ok());
//! ```
//!
//! # Limitations
//!
//! This commit defines the envelope and verification path. It does NOT
//! integrate the envelope into a transport-level ingress loop (no such
//! loop exists in the workspace today — `GossipNode` consumes
//! `GossipMessage` only via direct Rust calls, not via deserialization
//! from a transport socket). Once a transport-level gossip dispatcher
//! lands, it MUST consume `SignedGossipMessage` and call
//! [`SignedGossipMessage::verify`] before any state mutation. This is
//! the structural prerequisite for that work.
//!
//! There is also no peer-pubkey registry yet: `verify` checks that the
//! signature is consistent with the carried `sender_pubkey`, but does
//! NOT check that `sender_pubkey` is in a known-good set of peers. That
//! check belongs to a future commit once the consensus layer exposes a
//! validated peer registry (paralleling the observer-registry follow-up
//! noted in commit 018).

use serde::{Deserialize, Serialize};

use arxia_core::ArxiaError;

use crate::message::GossipMessage;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`SignedGossipMessage`].
///
/// 19 bytes. Distinct from `arxia-relay-receipt-v1` and
/// `arxia-relay-slash-v1` so a signature minted in a relay context
/// cannot be replayed as a gossip envelope. Bumping the trailing `-v1`
/// invalidates every previously-minted signature.
pub const GOSSIP_MESSAGE_DOMAIN: &[u8] = b"arxia-gossip-msg-v1";

/// Variant tag bytes used inside [`SignedGossipMessage::canonical_bytes`].
/// Public so that downstream tooling can decode the canonical bytes
/// without relying on the unstable Rust enum representation.
pub mod variant_tag {
    /// Tag for the `BlockAnnounce` variant of
    /// [`crate::GossipMessage`].
    pub const BLOCK_ANNOUNCE: u8 = 0x01;
    /// Tag for the `NonceSyncRequest` variant of
    /// [`crate::GossipMessage`].
    pub const NONCE_SYNC_REQUEST: u8 = 0x02;
    /// Tag for the `NonceSyncResponse` variant of
    /// [`crate::GossipMessage`].
    pub const NONCE_SYNC_RESPONSE: u8 = 0x03;
    /// Tag for the `Ping` variant of [`crate::GossipMessage`].
    pub const PING: u8 = 0x04;
}

/// Errors returned by [`SignedGossipMessage::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedGossipMessageError {
    /// `signature` is not exactly 64 bytes.
    InvalidSignatureLength,
    /// `sender_pubkey` is structurally invalid as an Ed25519 public
    /// key (e.g. low-order point, non-canonical encoding).
    InvalidPublicKey,
    /// The signature does not match the canonical bytes under the
    /// declared `sender_pubkey`. This is the exploit surface for
    /// CRIT-010 and for any tampering of message fields.
    SignatureInvalid,
}

impl std::fmt::Display for SignedGossipMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignatureLength => f.write_str("signature must be exactly 64 bytes"),
            Self::InvalidPublicKey => {
                f.write_str("sender_pubkey is not a valid Ed25519 public key")
            }
            Self::SignatureInvalid => {
                f.write_str("signature does not verify against the sender pubkey")
            }
        }
    }
}

impl std::error::Error for SignedGossipMessageError {}

/// A [`GossipMessage`] wrapped with sender authentication.
///
/// On the wire this is what peers exchange. [`Self::verify`] MUST be
/// called before any field is trusted for state mutation (block
/// ingest, nonce-registry merge, peer reachability tracking, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGossipMessage {
    /// The application-level gossip payload.
    pub message: GossipMessage,
    /// The 32-byte Ed25519 public key that signed
    /// [`Self::canonical_bytes`].
    pub sender_pubkey: [u8; 32],
    /// Ed25519 signature over [`Self::canonical_bytes`]. MUST be
    /// exactly 64 bytes for a valid envelope.
    pub signature: Vec<u8>,
}

impl SignedGossipMessage {
    /// Build the canonical bytes that the sender signs.
    ///
    /// Layout:
    ///
    /// - [`GOSSIP_MESSAGE_DOMAIN`] (19 bytes)
    /// - `sender_pubkey`           (32 bytes, raw)
    /// - variant tag               (1 byte, see [`variant_tag`])
    /// - variant-specific payload  (length depends on the variant)
    ///
    /// Per-variant payload layout:
    ///
    /// | Variant              | Encoding |
    /// |----------------------|----------|
    /// | `BlockAnnounce`      | hops (1 byte) `||` block_data length (8 bytes BE) `||` block_data |
    /// | `NonceSyncRequest`   | from length (8 bytes BE) `||` from bytes |
    /// | `NonceSyncResponse`  | entries length (8 bytes BE) `||` for each entry: hash (32) `||` nonce (8 BE) `||` account (32) |
    /// | `Ping`               | timestamp (8 bytes BE) `||` node_id length (8 bytes BE) `||` node_id bytes |
    ///
    /// All multi-byte integers use big-endian. String fields are
    /// length-prefixed with `u64` so a deserializer can dispatch
    /// without ambiguity. The encoding is deterministic — given the
    /// same `(message, sender_pubkey)`, the output bytes are
    /// byte-for-byte identical.
    pub fn canonical_bytes(message: &GossipMessage, sender_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + estimate_message_size(message));
        buf.extend_from_slice(GOSSIP_MESSAGE_DOMAIN);
        buf.extend_from_slice(sender_pubkey);
        encode_message_into(&mut buf, message);
        buf
    }

    /// Verify the Ed25519 signature on this envelope.
    ///
    /// Must be called before any state change trusts any field. After
    /// `Ok(())` the receiver can safely consume `self.message` (its
    /// content is bound to `self.sender_pubkey` under a sender-authored
    /// signature with domain separation).
    ///
    /// `verify` does NOT check that `sender_pubkey` is a known / trusted
    /// peer — that is a separate registry concern (see module-level
    /// "Limitations").
    pub fn verify(&self) -> Result<(), SignedGossipMessageError> {
        if self.signature.len() != 64 {
            return Err(SignedGossipMessageError::InvalidSignatureLength);
        }
        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SignedGossipMessageError::InvalidSignatureLength)?;
        let canonical = Self::canonical_bytes(&self.message, &self.sender_pubkey);
        arxia_crypto::verify(&self.sender_pubkey, &canonical, &sig).map_err(|e| match e {
            ArxiaError::InvalidKey(_) => SignedGossipMessageError::InvalidPublicKey,
            _ => SignedGossipMessageError::SignatureInvalid,
        })
    }
}

/// Cheap upper bound on the canonical-bytes size for one message.
/// Used to pre-allocate the encoding buffer.
fn estimate_message_size(m: &GossipMessage) -> usize {
    match m {
        GossipMessage::BlockAnnounce { block_data, .. } => 1 + 1 + 8 + block_data.len(),
        GossipMessage::NonceSyncRequest { from } => 1 + 8 + from.len(),
        GossipMessage::NonceSyncResponse { entries } => 1 + 8 + entries.len() * (32 + 8 + 32),
        GossipMessage::Ping { node_id, .. } => 1 + 8 + 8 + node_id.len(),
    }
}

/// Append the per-variant canonical encoding of `m` to `buf`.
fn encode_message_into(buf: &mut Vec<u8>, m: &GossipMessage) {
    match m {
        GossipMessage::BlockAnnounce { block_data, hops } => {
            buf.push(variant_tag::BLOCK_ANNOUNCE);
            buf.push(*hops);
            buf.extend_from_slice(&(block_data.len() as u64).to_be_bytes());
            buf.extend_from_slice(block_data);
        }
        GossipMessage::NonceSyncRequest { from } => {
            buf.push(variant_tag::NONCE_SYNC_REQUEST);
            buf.extend_from_slice(&(from.len() as u64).to_be_bytes());
            buf.extend_from_slice(from.as_bytes());
        }
        GossipMessage::NonceSyncResponse { entries } => {
            buf.push(variant_tag::NONCE_SYNC_RESPONSE);
            buf.extend_from_slice(&(entries.len() as u64).to_be_bytes());
            for (hash, nonce, account) in entries {
                buf.extend_from_slice(hash);
                buf.extend_from_slice(&nonce.to_be_bytes());
                buf.extend_from_slice(account);
            }
        }
        GossipMessage::Ping { node_id, timestamp } => {
            buf.push(variant_tag::PING);
            buf.extend_from_slice(&timestamp.to_be_bytes());
            buf.extend_from_slice(&(node_id.len() as u64).to_be_bytes());
            buf.extend_from_slice(node_id.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    /// Sign `message` with a fresh keypair and return the envelope plus
    /// the public-key bytes for cross-key tests.
    fn signed(message: GossipMessage) -> (SignedGossipMessage, [u8; 32]) {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let canonical = SignedGossipMessage::canonical_bytes(&message, &pk);
        let sig = sign(&sk, &canonical);
        (
            SignedGossipMessage {
                message,
                sender_pubkey: pk,
                signature: sig.to_vec(),
            },
            pk,
        )
    }

    fn ping(node_id: &str, timestamp: u64) -> GossipMessage {
        GossipMessage::Ping {
            node_id: node_id.into(),
            timestamp,
        }
    }

    fn block_announce(payload: Vec<u8>, hops: u8) -> GossipMessage {
        GossipMessage::BlockAnnounce {
            block_data: payload,
            hops,
        }
    }

    fn nonce_sync_request(from: &str) -> GossipMessage {
        GossipMessage::NonceSyncRequest { from: from.into() }
    }

    fn nonce_sync_response(n: usize) -> GossipMessage {
        let mut entries = Vec::with_capacity(n);
        for i in 0..n as u64 {
            entries.push(([i as u8; 32], i, [(i + 1) as u8; 32]));
        }
        GossipMessage::NonceSyncResponse { entries }
    }

    // --- canonical bytes layout ---

    #[test]
    fn test_canonical_bytes_starts_with_domain_prefix() {
        let pk = [0xAAu8; 32];
        let bytes = SignedGossipMessage::canonical_bytes(&ping("n", 1), &pk);
        assert!(bytes.starts_with(GOSSIP_MESSAGE_DOMAIN));
        assert_eq!(GOSSIP_MESSAGE_DOMAIN.len(), 19);
    }

    #[test]
    fn test_canonical_bytes_includes_sender_pubkey_after_domain() {
        let pk = [0xBBu8; 32];
        let bytes = SignedGossipMessage::canonical_bytes(&ping("n", 1), &pk);
        let off = GOSSIP_MESSAGE_DOMAIN.len();
        assert_eq!(&bytes[off..off + 32], &pk);
    }

    #[test]
    fn test_canonical_bytes_variant_tags_are_distinct() {
        let pk = [0u8; 32];
        let b1 = SignedGossipMessage::canonical_bytes(&block_announce(vec![], 0), &pk);
        let b2 = SignedGossipMessage::canonical_bytes(&nonce_sync_request("a"), &pk);
        let b3 = SignedGossipMessage::canonical_bytes(&nonce_sync_response(0), &pk);
        let b4 = SignedGossipMessage::canonical_bytes(&ping("a", 0), &pk);
        let tag_off = GOSSIP_MESSAGE_DOMAIN.len() + 32;
        assert_eq!(b1[tag_off], variant_tag::BLOCK_ANNOUNCE);
        assert_eq!(b2[tag_off], variant_tag::NONCE_SYNC_REQUEST);
        assert_eq!(b3[tag_off], variant_tag::NONCE_SYNC_RESPONSE);
        assert_eq!(b4[tag_off], variant_tag::PING);
        // All four tags are pairwise distinct.
        let tags = [
            variant_tag::BLOCK_ANNOUNCE,
            variant_tag::NONCE_SYNC_REQUEST,
            variant_tag::NONCE_SYNC_RESPONSE,
            variant_tag::PING,
        ];
        for i in 0..tags.len() {
            for j in 0..tags.len() {
                if i != j {
                    assert_ne!(tags[i], tags[j]);
                }
            }
        }
    }

    #[test]
    fn test_canonical_bytes_is_deterministic() {
        let pk = [0xCCu8; 32];
        let m = nonce_sync_response(5);
        let a = SignedGossipMessage::canonical_bytes(&m, &pk);
        let b = SignedGossipMessage::canonical_bytes(&m, &pk);
        assert_eq!(a, b);
    }

    // --- positive-path verify per variant ---

    #[test]
    fn test_sign_then_verify_passes_for_ping() {
        let (s, _) = signed(ping("alpha", 100));
        assert!(s.verify().is_ok());
    }

    #[test]
    fn test_sign_then_verify_passes_for_block_announce() {
        let (s, _) = signed(block_announce(vec![1, 2, 3, 4, 5], 7));
        assert!(s.verify().is_ok());
    }

    #[test]
    fn test_sign_then_verify_passes_for_nonce_sync_request() {
        let (s, _) = signed(nonce_sync_request("requester-id"));
        assert!(s.verify().is_ok());
    }

    #[test]
    fn test_sign_then_verify_passes_for_nonce_sync_response() {
        let (s, _) = signed(nonce_sync_response(10));
        assert!(s.verify().is_ok());
    }

    // --- negative-path verify (CRIT-010 attack surface) ---

    #[test]
    fn test_verify_rejects_zero_signature() {
        // CRIT-010 core attack: peer constructs a struct literal with
        // signature: vec![0; 64]. Well-formed length, but not a valid
        // Ed25519 signature on any bytes under any pubkey. Must reject.
        let mut s = signed(ping("n", 0)).0;
        s.signature = vec![0u8; 64];
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_block_announce_data() {
        let mut s = signed(block_announce(vec![1, 2, 3], 1)).0;
        if let GossipMessage::BlockAnnounce { block_data, .. } = &mut s.message {
            block_data.push(99);
        } else {
            panic!("variant mismatch");
        }
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_block_announce_hops() {
        let mut s = signed(block_announce(vec![1, 2, 3], 1)).0;
        if let GossipMessage::BlockAnnounce { hops, .. } = &mut s.message {
            *hops = hops.wrapping_add(1);
        } else {
            panic!("variant mismatch");
        }
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_ping_timestamp() {
        let mut s = signed(ping("n", 100)).0;
        if let GossipMessage::Ping { timestamp, .. } = &mut s.message {
            *timestamp = 200;
        } else {
            panic!("variant mismatch");
        }
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_sender_pubkey() {
        // Replacing sender_pubkey breaks the signed binding: the
        // canonical bytes that `verify` recomputes now differ from
        // those the original signer signed.
        let (mut s, _) = signed(ping("n", 1));
        s.sender_pubkey[0] ^= 0xFF;
        // After flipping a byte the pubkey is most likely either
        // structurally invalid or not the signer's. Either error is
        // a valid CRIT-010 mitigation; we assert against the union.
        let err = s.verify().unwrap_err();
        assert!(matches!(
            err,
            SignedGossipMessageError::SignatureInvalid | SignedGossipMessageError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_verify_rejects_swap_to_different_signers_pubkey() {
        // Take a valid envelope from key A, swap `sender_pubkey` for
        // key B's pubkey. The signature is A's; B's pubkey will not
        // verify it. A direct cross-peer impersonation attempt.
        let (mut s, _) = signed(ping("n", 1));
        let (_, vk2) = generate_keypair();
        s.sender_pubkey = vk2.to_bytes();
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_short_signature() {
        let mut s = signed(ping("n", 1)).0;
        s.signature = vec![0u8; 32];
        assert_eq!(
            s.verify(),
            Err(SignedGossipMessageError::InvalidSignatureLength)
        );
    }

    #[test]
    fn test_verify_rejects_long_signature() {
        let mut s = signed(ping("n", 1)).0;
        s.signature = vec![0u8; 100];
        assert_eq!(
            s.verify(),
            Err(SignedGossipMessageError::InvalidSignatureLength)
        );
    }

    // --- domain separation (CRIT-010 cross-protocol replay) ---

    #[test]
    fn test_domain_separation_rejects_signature_minted_without_domain() {
        // An attacker who can extract a signature on a different
        // protocol object — same trailing bytes, no domain prefix —
        // tries to repackage it as a gossip envelope. The domain
        // prefix forces a bytes-difference, so the signature does
        // not verify.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let m = ping("n", 1);
        // Build the WITHOUT-domain canonical bytes.
        let mut without_domain = Vec::new();
        without_domain.extend_from_slice(&pk);
        encode_message_into(&mut without_domain, &m);
        let sig_no_domain = sign(&sk, &without_domain);
        let s = SignedGossipMessage {
            message: m,
            sender_pubkey: pk,
            signature: sig_no_domain.to_vec(),
        };
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    #[test]
    fn test_domain_separation_rejects_signature_with_other_protocol_domain() {
        // Same idea but with a competing domain prefix
        // ("arxia-relay-receipt-v1"). Signatures minted in another
        // Arxia subsystem must not collide with gossip.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let m = ping("n", 1);
        let mut other_domain = Vec::new();
        other_domain.extend_from_slice(b"arxia-relay-receipt-v1");
        other_domain.extend_from_slice(&pk);
        encode_message_into(&mut other_domain, &m);
        let sig_other = sign(&sk, &other_domain);
        let s = SignedGossipMessage {
            message: m,
            sender_pubkey: pk,
            signature: sig_other.to_vec(),
        };
        assert_eq!(s.verify(), Err(SignedGossipMessageError::SignatureInvalid));
    }

    // --- serde round-trip ---

    #[test]
    fn test_signed_gossip_message_serde_roundtrip_via_bincode_compatible_path() {
        // Use serde_json as a byte-stable serializer for the test.
        // Production callers can use whatever transport-side serializer
        // they pick (bincode, postcard, protobuf); the verify check
        // operates on the structured fields so the wire format is the
        // serializer's concern, not the envelope's.
        let (s, _) = signed(nonce_sync_response(3));
        let json = serde_json::to_string(&s).unwrap();
        let s2: SignedGossipMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(s.sender_pubkey, s2.sender_pubkey);
        assert_eq!(s.signature, s2.signature);
        assert!(s2.verify().is_ok());
    }
}
