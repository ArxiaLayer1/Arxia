//! Guards for transport-message freshness. `verify` authenticates the
//! message but never looks at a clock, so a captured message replays
//! forever. `verify_at` bounds it two-sidedly.

use arxia_transport::traits::{
    SignedTransportMessage, TransportError, TRANSPORT_FRESHNESS_WINDOW_MS,
};
use ed25519_dalek::rand_core::UnwrapErr;
use ed25519_dalek::SigningKey;
use rand::rngs::SysRng;

/// Timestamps here are MILLISECONDS since epoch.
fn signed(timestamp_ms: u64) -> SignedTransportMessage {
    let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
    SignedTransportMessage::sign(&sk, "peer".to_string(), vec![1, 2, 3], timestamp_ms)
}

#[test]
fn fresh_message_is_accepted() {
    let now = 1_700_000_000_000u64;
    assert!(signed(now)
        .verify_at(now, TRANSPORT_FRESHNESS_WINDOW_MS)
        .is_ok());
}

#[test]
fn message_at_the_exact_window_edge_is_accepted() {
    let now = 1_700_000_000_000u64;
    let m = signed(now - TRANSPORT_FRESHNESS_WINDOW_MS);
    assert!(m.verify_at(now, TRANSPORT_FRESHNESS_WINDOW_MS).is_ok());
}

#[test]
fn replayed_message_is_rejected() {
    let now = 1_700_000_000_000u64;
    // One hour old.
    let m = signed(now - 3_600_000);
    assert!(
        matches!(
            m.verify_at(now, TRANSPORT_FRESHNESS_WINDOW_MS),
            Err(TransportError::TimestampStale { .. })
        ),
        "a replayed message must be rejected"
    );
    assert!(m.verify().is_ok(), "verify alone stays signature-only");
}

#[test]
fn future_dated_message_is_rejected() {
    let now = 1_700_000_000_000u64;
    let m = signed(now + 3_600_000);
    assert!(matches!(
        m.verify_at(now, TRANSPORT_FRESHNESS_WINDOW_MS),
        Err(TransportError::TimestampStale { .. })
    ));
}

#[test]
fn huge_timestamp_does_not_overflow() {
    let m = signed(u64::MAX);
    assert!(matches!(
        m.verify_at(1_000, TRANSPORT_FRESHNESS_WINDOW_MS),
        Err(TransportError::TimestampStale { .. })
    ));
}
