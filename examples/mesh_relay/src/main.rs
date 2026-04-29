//! Mesh relay example.
//!
//! Demonstrates the full post-CRIT-004 flow: the relay node holds a
//! keypair, signs a receipt over the message it forwarded, and hands
//! that signed receipt to its own [`RelayScore`] to get credit.
//!
//! # HIGH-024 (commit 044) — receipt signing IS the canonical pattern
//!
//! The audit (HIGH-024):
//!
//! > External dev copies the pattern; ships relay without signatures;
//! > CRIT-004 goes live in every fork. Security-critical default
//! > pattern is absent from the canonical example. The example must
//! > sign the receipt and the receiver must verify; no sig, no
//! > success.
//!
//! This example refactors the signing logic into a testable helper
//! [`build_signed_receipt`] so a `#[cfg(test)]` test suite pins:
//!
//! 1. Every receipt the example mints carries a non-zero Ed25519
//!    signature (a struct literal with `signature: vec![]` would
//!    fail the test).
//! 2. The signature verifies against the relay's pubkey under the
//!    domain-separated canonical message — i.e. it is NOT a generic
//!    signature replayed from another protocol context.
//! 3. An unsigned receipt is **rejected** by `RelayScore::record_success`
//!    (the receiver-side verification check). "no sig, no success" —
//!    the audit's exact requirement.
//! 4. After two valid signed receipts are credited, the score
//!    increases by exactly 2 from its initial 100 baseline.
//!
//! Future external developers copying this example inherit the
//! signed-receipt pattern by construction; the test suite is the
//! pin against future regressions.

use arxia_crypto::{generate_keypair, sign};
use arxia_relay::receipt::RelayReceipt;
use arxia_relay::scoring::RelayScore;
use arxia_transport::{SimulatedTransport, TransportMessage, TransportTrait};
use ed25519_dalek::SigningKey;

/// Build a single relay receipt and sign it with `relay_sk` over the
/// domain-separated canonical message.
///
/// The returned receipt has:
/// - `relay_id` = hex-encoded pubkey of `relay_sk`
/// - `message_hash` = hex-encoded Blake3 of `message`
/// - `signature` = Ed25519 over the domain-prefixed canonical bytes
///
/// Verifying nodes call [`RelayReceipt::verify`] (or
/// [`RelayScore::record_success`] which wraps it) to check the
/// signature before crediting the relay. See HIGH-024 in the
/// module docstring.
pub fn build_signed_receipt(
    relay_sk: &SigningKey,
    relay_id: &str,
    message: &[u8],
    timestamp: u64,
    hop_count: u8,
) -> RelayReceipt {
    let mut r = RelayReceipt {
        relay_id: relay_id.to_string(),
        message_hash: arxia_crypto::hash_blake3(message),
        timestamp,
        signature: Vec::new(),
        hop_count,
    };
    let canonical = r.canonical_message().expect("canonical bytes");
    r.signature = sign(relay_sk, &canonical).to_vec();
    r
}

fn main() {
    println!("=== Arxia Mesh Relay Example ===");
    println!();

    let mut transport = SimulatedTransport::lora();
    println!(
        "LoRa transport: MTU={}, latency={}ms",
        transport.mtu(),
        transport.latency_ms()
    );

    // Every relay node owns a long-lived Ed25519 identity; the public
    // half IS the relay_id.
    let (relay_sk, relay_vk) = generate_keypair();
    let relay_pk = relay_vk.to_bytes();
    let relay_id = hex::encode(relay_pk);
    println!("Relay pubkey (relay_id): {}…", &relay_id[..16]);

    let msg = TransportMessage {
        from: "sender".to_string(),
        to: "destination".to_string(),
        payload: vec![1, 2, 3, 4, 5],
        timestamp: 1000,
    };

    match transport.send(msg) {
        Ok(()) => println!("Message sent successfully"),
        Err(e) => println!("Send failed: {}", e),
    }

    let mut score = RelayScore::new(relay_id.clone());

    // Build + sign two receipts for the two forwards this relay
    // claims to have performed. The message_hash would in practice be
    // a Blake3 hash of the message; here we use placeholder bytes.
    for (i, message_bytes) in [b"first-message".as_slice(), b"second-message".as_slice()]
        .iter()
        .enumerate()
    {
        let r = build_signed_receipt(&relay_sk, &relay_id, message_bytes, 1000 + i as u64, 1);

        match score.record_success(&r) {
            Ok(()) => println!("Credited receipt #{}", i + 1),
            Err(e) => println!("Receipt #{} rejected: {}", i + 1, e),
        }
    }

    // A failure does not need a signed counter-part: the relay observed
    // the drop locally.
    score.record_failure();

    println!(
        "Relay score: {} (trusted: {})",
        score.score,
        score.is_trusted()
    );

    println!();
    println!("=== Example complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HIGH-024 PRIMARY PIN: every receipt the example mints carries
    /// a non-zero Ed25519 signature. A struct literal with
    /// `signature: vec![]` (or `vec![0u8; 64]`) would fail this
    /// test — pinning the canonical pattern against a future
    /// regression where someone "simplifies" the example by
    /// removing the sign step.
    #[test]
    fn test_build_signed_receipt_produces_non_empty_signature() {
        let (sk, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        let r = build_signed_receipt(&sk, &relay_id, b"payload", 42, 3);
        assert!(!r.signature.is_empty(), "receipt MUST be signed");
        assert_eq!(r.signature.len(), 64, "Ed25519 signature is 64 bytes");
        assert_ne!(
            r.signature,
            vec![0u8; 64],
            "all-zero signature is not valid"
        );
    }

    /// HIGH-024 PIN: the receipt's signature verifies against the
    /// relay's pubkey under the domain-separated canonical message.
    /// Pinning that the example uses the correct domain prefix
    /// (otherwise a signature minted in another protocol context
    /// could replay).
    #[test]
    fn test_build_signed_receipt_verifies() {
        let (sk, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        let r = build_signed_receipt(&sk, &relay_id, b"payload", 42, 3);
        assert!(r.verify().is_ok(), "freshly-built receipt MUST verify");
    }

    /// HIGH-024 PIN: "no sig, no success" — the receiver-side
    /// `RelayScore::record_success` rejects an unsigned receipt.
    /// This is the audit's exact requirement: external devs
    /// copying the pattern cannot accidentally bypass the
    /// signature check.
    #[test]
    fn test_unsigned_receipt_rejected_by_score() {
        let (_, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        // Construct a receipt WITHOUT signing — the attacker's
        // shape (no `build_signed_receipt` call).
        let unsigned = RelayReceipt {
            relay_id: relay_id.clone(),
            message_hash: arxia_crypto::hash_blake3(b"payload"),
            timestamp: 42,
            signature: Vec::new(),
            hop_count: 1,
        };
        let mut score = RelayScore::new(relay_id);
        assert!(
            score.record_success(&unsigned).is_err(),
            "no sig, no success — unsigned receipt MUST be rejected"
        );
    }

    /// HIGH-024 PIN: zero-byte signature (the attacker's pattern
    /// from CRIT-004) is rejected. Defense-in-depth on top of
    /// the unsigned-vector test.
    #[test]
    fn test_zero_signature_receipt_rejected_by_score() {
        let (_, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        let zero_sig = RelayReceipt {
            relay_id: relay_id.clone(),
            message_hash: arxia_crypto::hash_blake3(b"payload"),
            timestamp: 42,
            signature: vec![0u8; 64],
            hop_count: 1,
        };
        let mut score = RelayScore::new(relay_id);
        assert!(
            score.record_success(&zero_sig).is_err(),
            "[0u8; 64] signature MUST be rejected"
        );
    }

    /// HIGH-024 PIN: legitimate signed receipts increment the
    /// score. Pin against any future regression where the score
    /// math accidentally drops valid receipts.
    #[test]
    fn test_two_signed_receipts_increment_score_by_two() {
        let (sk, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        let r1 = build_signed_receipt(&sk, &relay_id, b"first", 100, 1);
        let r2 = build_signed_receipt(&sk, &relay_id, b"second", 101, 1);
        let mut score = RelayScore::new(relay_id);
        let initial = score.score;
        score
            .record_success(&r1)
            .expect("signed receipt 1 MUST credit");
        score
            .record_success(&r2)
            .expect("signed receipt 2 MUST credit");
        assert_eq!(score.score, initial + 2);
        assert_eq!(score.messages_relayed, 2);
    }

    /// Pin that `build_signed_receipt` produces deterministic
    /// `message_hash` (Blake3 of the input). External devs reading
    /// the example must be able to reason about which payload
    /// corresponds to which receipt without rerunning.
    #[test]
    fn test_build_signed_receipt_message_hash_is_blake3_of_input() {
        let (sk, vk) = generate_keypair();
        let relay_id = hex::encode(vk.to_bytes());
        let payload = b"deterministic-payload";
        let r = build_signed_receipt(&sk, &relay_id, payload, 0, 0);
        let expected = arxia_crypto::hash_blake3(payload);
        assert_eq!(r.message_hash, expected);
    }
}
