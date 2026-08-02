//! Guards for receipt freshness. `verify` authenticates a receipt but
//! never looks at a clock, so a captured receipt stays valid forever.
//! `verify_at` bounds it two-sidedly.

use arxia_relay::receipt::{RelayReceipt, RelayReceiptError, RECEIPT_FRESHNESS_WINDOW_SECS};
use ed25519_dalek::Signer;

/// Timestamps here are Unix SECONDS, not milliseconds.
fn signed(timestamp: u64) -> RelayReceipt {
    // arxia-crypto owns keypair generation; no direct rand dep needed.
    let (sk, vk) = arxia_crypto::generate_keypair();
    let relay_id = hex::encode(vk.to_bytes());
    let mut r = RelayReceipt {
        relay_id,
        message_hash: hex::encode([0xABu8; 32]),
        timestamp,
        hop_count: 1,
        signature: Vec::new(),
    };
    let msg = r.canonical_message().unwrap();
    r.signature = sk.sign(&msg).to_bytes().to_vec();
    r
}

#[test]
fn fresh_receipt_is_accepted() {
    let now = 1_000_000u64;
    let r = signed(now);
    assert!(r.verify_at(now, RECEIPT_FRESHNESS_WINDOW_SECS).is_ok());
}

#[test]
fn receipt_at_the_exact_window_edge_is_accepted() {
    let now = 1_000_000u64;
    let r = signed(now - RECEIPT_FRESHNESS_WINDOW_SECS);
    assert!(
        r.verify_at(now, RECEIPT_FRESHNESS_WINDOW_SECS).is_ok(),
        "the boundary itself must remain inside the window"
    );
}

#[test]
fn stale_receipt_is_rejected() {
    let now = 1_000_000u64;
    // One day old: authentic, but long past the window.
    let r = signed(now - 86_400);
    assert!(
        matches!(
            r.verify_at(now, RECEIPT_FRESHNESS_WINDOW_SECS),
            Err(RelayReceiptError::TimestampStale { .. })
        ),
        "a replayed receipt must be rejected"
    );
    // The signature itself is still valid — only freshness fails.
    assert!(r.verify().is_ok(), "verify alone stays signature-only");
}

#[test]
fn future_dated_receipt_is_rejected() {
    let now = 1_000_000u64;
    let r = signed(now + 86_400);
    assert!(
        matches!(
            r.verify_at(now, RECEIPT_FRESHNESS_WINDOW_SECS),
            Err(RelayReceiptError::TimestampStale { .. })
        ),
        "a pre-minted receipt must be rejected"
    );
}

#[test]
fn huge_timestamp_does_not_overflow() {
    // u64::MAX must be handled by subtraction ordering, not wraparound.
    let r = signed(u64::MAX);
    assert!(matches!(
        r.verify_at(1_000, RECEIPT_FRESHNESS_WINDOW_SECS),
        Err(RelayReceiptError::TimestampStale { .. })
    ));
}
