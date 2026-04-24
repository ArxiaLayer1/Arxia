//! Mesh relay example.
//!
//! Demonstrates the full post-CRIT-004 flow: the relay node holds a
//! keypair, signs a receipt over the message it forwarded, and hands
//! that signed receipt to its own [`RelayScore`] to get credit.

use arxia_crypto::{generate_keypair, sign};
use arxia_relay::receipt::RelayReceipt;
use arxia_relay::scoring::RelayScore;
use arxia_transport::{SimulatedTransport, TransportMessage, TransportTrait};

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
        let msg_hash_hex = arxia_crypto::hash_blake3(message_bytes);
        let mut r = RelayReceipt {
            relay_id: relay_id.clone(),
            message_hash: msg_hash_hex,
            timestamp: 1000 + i as u64,
            signature: Vec::new(),
            hop_count: 1,
        };
        let canonical = r.canonical_message().expect("canonical bytes");
        r.signature = sign(&relay_sk, &canonical).to_vec();

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
