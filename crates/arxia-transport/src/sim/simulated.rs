//! Simulated transport for testing.
//!
//! Uses in-memory channels with configurable latency and packet loss.
//! The packet loss uses a deterministic xorshift64 PRNG for reproducibility.
//!
//! # Bounded queues (CRIT-012)
//!
//! Both the inbox (received messages waiting to be drained by
//! [`SimulatedTransport::try_recv`]) and the outbox (record of sent
//! messages, for test inspection) are bounded.
//!
//! - **Inbox**: drop-oldest policy. When the inbox is at capacity and a
//!   new message is injected, the oldest unread message is dropped to
//!   make room. The number of dropped messages is observable via
//!   [`SimulatedTransport::inbox_dropped`].
//! - **Outbox**: back-pressure policy. When the outbox is at capacity,
//!   [`SimulatedTransport::send`] returns [`TransportError::BackPressure`]
//!   and does NOT push the new message. The caller is expected to drain
//!   via [`SimulatedTransport::sent_messages`] (or, in production
//!   transports, by flushing) before retrying.
//!
//! Defaults are [`DEFAULT_INBOX_CAPACITY`] / [`DEFAULT_OUTBOX_CAPACITY`].
//! For custom limits use [`SimulatedTransport::with_capacity`].

use std::collections::VecDeque;

use crate::traits::{TransportError, TransportMessage, TransportTrait};

/// Default inbox capacity (messages).
///
/// 1024 messages × 256 B (LoRa MTU) ≈ 256 KB worst-case. Large enough
/// to absorb realistic bursts on a slow LoRa link, small enough to
/// bound memory under a flooding attack.
pub const DEFAULT_INBOX_CAPACITY: usize = 1024;

/// Default outbox capacity (messages).
///
/// Same rationale as [`DEFAULT_INBOX_CAPACITY`]. Outbox overflow returns
/// [`TransportError::BackPressure`] rather than silently dropping, so
/// the caller can implement explicit back-pressure handling.
pub const DEFAULT_OUTBOX_CAPACITY: usize = 1024;

/// Deterministic xorshift64 PRNG for reproducible packet loss simulation.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// A simulated transport for testing purposes.
pub struct SimulatedTransport {
    inbox: VecDeque<TransportMessage>,
    outbox: Vec<TransportMessage>,
    inbox_capacity: usize,
    outbox_capacity: usize,
    inbox_dropped: u64,
    latency_ms: u64,
    loss_rate: f64,
    mtu: usize,
    rng_state: u64,
}

impl SimulatedTransport {
    /// Create a new simulated transport with the given parameters and
    /// default queue capacities ([`DEFAULT_INBOX_CAPACITY`] /
    /// [`DEFAULT_OUTBOX_CAPACITY`]).
    pub fn new(latency_ms: u64, loss_rate: f64, mtu: usize) -> Self {
        Self::with_capacity(
            latency_ms,
            loss_rate,
            mtu,
            DEFAULT_INBOX_CAPACITY,
            DEFAULT_OUTBOX_CAPACITY,
        )
    }

    /// Create a simulated transport with custom inbox/outbox capacities.
    ///
    /// `inbox_capacity` and `outbox_capacity` are clamped to a minimum
    /// of 1; passing 0 silently coerces to 1 to keep the data structure
    /// invariants meaningful (a zero-capacity inbox could never hold a
    /// message, which would be more confusing than useful).
    pub fn with_capacity(
        latency_ms: u64,
        loss_rate: f64,
        mtu: usize,
        inbox_capacity: usize,
        outbox_capacity: usize,
    ) -> Self {
        Self {
            inbox: VecDeque::new(),
            outbox: Vec::new(),
            inbox_capacity: inbox_capacity.max(1),
            outbox_capacity: outbox_capacity.max(1),
            inbox_dropped: 0,
            latency_ms,
            loss_rate,
            mtu,
            rng_state: 0xDEAD_BEEF_CAFE_BABE,
        }
    }

    /// Create a simulated transport with LoRa-like parameters.
    pub fn lora() -> Self {
        Self::new(2000, 0.05, 256)
    }

    /// Create a simulated transport with BLE-like parameters.
    pub fn ble() -> Self {
        Self::new(50, 0.01, 512)
    }

    /// Inject a message into the inbox (for test setup).
    ///
    /// If the inbox is at capacity, the oldest message is dropped to
    /// make room. The number of messages dropped this way is observable
    /// via [`SimulatedTransport::inbox_dropped`] and acts as the
    /// back-pressure signal for the receive side.
    pub fn inject_message(&mut self, msg: TransportMessage) {
        if self.inbox.len() >= self.inbox_capacity {
            // Drop-oldest. pop_front is O(1) on VecDeque.
            self.inbox.pop_front();
            self.inbox_dropped = self.inbox_dropped.saturating_add(1);
        }
        self.inbox.push_back(msg);
    }

    /// Get all sent messages (for test assertions).
    pub fn sent_messages(&self) -> &[TransportMessage] {
        &self.outbox
    }

    /// Get the configured latency.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Number of messages currently buffered in the inbox.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Number of messages currently buffered in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Configured inbox capacity (messages).
    pub fn inbox_capacity(&self) -> usize {
        self.inbox_capacity
    }

    /// Configured outbox capacity (messages).
    pub fn outbox_capacity(&self) -> usize {
        self.outbox_capacity
    }

    /// Cumulative number of inbox messages that were dropped to make
    /// room for newer ones since this transport was constructed.
    /// Saturates at [`u64::MAX`].
    pub fn inbox_dropped(&self) -> u64 {
        self.inbox_dropped
    }
}

impl TransportTrait for SimulatedTransport {
    fn send(&mut self, msg: TransportMessage) -> Result<(), TransportError> {
        if msg.payload.len() > self.mtu {
            return Err(TransportError::PayloadTooLarge {
                size: msg.payload.len(),
                max: self.mtu,
            });
        }

        if self.outbox.len() >= self.outbox_capacity {
            return Err(TransportError::BackPressure {
                capacity: self.outbox_capacity,
            });
        }

        // Simulate packet loss with deterministic PRNG
        let rng_val = xorshift64(&mut self.rng_state);
        let loss_threshold = (self.loss_rate * u64::MAX as f64) as u64;
        if rng_val < loss_threshold {
            return Err(TransportError::MessageLost);
        }

        self.outbox.push(msg);
        Ok(())
    }

    fn try_recv(&mut self) -> Option<TransportMessage> {
        self.inbox.pop_front()
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(payload: Vec<u8>) -> TransportMessage {
        TransportMessage {
            from: "alice".to_string(),
            to: "bob".to_string(),
            payload,
            timestamp: 1000,
        }
    }

    #[test]
    fn test_simulated_transport_send_recv() {
        let mut transport = SimulatedTransport::new(100, 0.0, 256);

        let m = msg(vec![1, 2, 3]);

        transport.inject_message(m.clone());
        let received = transport.try_recv();
        assert!(received.is_some());
        assert_eq!(received.unwrap().payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_simulated_transport_mtu_enforcement() {
        let mut transport = SimulatedTransport::new(100, 0.0, 10);

        let m = msg(vec![0; 20]);

        let result = transport.send(m);
        assert!(result.is_err());
    }

    #[test]
    fn test_simulated_transport_empty_recv() {
        let mut transport = SimulatedTransport::new(100, 0.0, 256);
        assert!(transport.try_recv().is_none());
    }

    #[test]
    fn test_lora_transport_defaults() {
        let transport = SimulatedTransport::lora();
        assert_eq!(transport.mtu(), 256);
        assert_eq!(transport.latency_ms(), 2000);
    }

    #[test]
    fn test_ble_transport_defaults() {
        let transport = SimulatedTransport::ble();
        assert_eq!(transport.mtu(), 512);
        assert_eq!(transport.latency_ms(), 50);
    }

    #[test]
    fn test_xorshift64_deterministic() {
        let mut state1 = 42u64;
        let mut state2 = 42u64;
        let a = xorshift64(&mut state1);
        let b = xorshift64(&mut state2);
        assert_eq!(a, b);
    }

    #[test]
    fn test_send_captures_outbox() {
        let mut transport = SimulatedTransport::new(0, 0.0, 256);
        let m = msg(vec![42]);
        transport.send(m).unwrap();
        assert_eq!(transport.sent_messages().len(), 1);
        assert_eq!(transport.sent_messages()[0].payload, vec![42]);
    }

    // ========================================================================
    // Adversarial tests for CRIT-012 (transport inbox/outbox unbounded)
    //
    // These tests pin the bounded-queue invariants: inbox drops oldest
    // and exposes a counter; outbox returns BackPressure when full.
    // ========================================================================

    #[test]
    fn test_inbox_default_capacity_is_1024() {
        let t = SimulatedTransport::new(0, 0.0, 256);
        assert_eq!(t.inbox_capacity(), DEFAULT_INBOX_CAPACITY);
        assert_eq!(DEFAULT_INBOX_CAPACITY, 1024);
    }

    #[test]
    fn test_outbox_default_capacity_is_1024() {
        let t = SimulatedTransport::new(0, 0.0, 256);
        assert_eq!(t.outbox_capacity(), DEFAULT_OUTBOX_CAPACITY);
        assert_eq!(DEFAULT_OUTBOX_CAPACITY, 1024);
    }

    #[test]
    fn test_inbox_dropped_counter_starts_at_zero() {
        let t = SimulatedTransport::new(0, 0.0, 256);
        assert_eq!(t.inbox_dropped(), 0);
    }

    #[test]
    fn test_inbox_drop_oldest_when_full_increments_counter() {
        // Capacity 4, inject 6 → expect inbox.len() == 4, dropped == 2.
        let mut t = SimulatedTransport::with_capacity(0, 0.0, 256, 4, 64);
        for i in 0u8..6 {
            t.inject_message(msg(vec![i]));
        }
        assert_eq!(t.inbox_len(), 4, "inbox must stay bounded at capacity");
        assert_eq!(t.inbox_dropped(), 2, "two oldest must be dropped");
    }

    #[test]
    fn test_inbox_drop_oldest_preserves_newest_when_overflowing() {
        // Inject 0..6 with capacity 4. After overflow, inbox holds the
        // payload sequence [2, 3, 4, 5] in FIFO order — oldest (0, 1)
        // are dropped, newest are kept and drainable in arrival order.
        let mut t = SimulatedTransport::with_capacity(0, 0.0, 256, 4, 64);
        for i in 0u8..6 {
            t.inject_message(msg(vec![i]));
        }
        let mut drained = Vec::new();
        while let Some(m) = t.try_recv() {
            drained.push(m.payload[0]);
        }
        assert_eq!(drained, vec![2u8, 3, 4, 5]);
    }

    #[test]
    fn test_outbox_send_returns_backpressure_when_full() {
        // Capacity 3 with zero loss. After 3 successful sends, the
        // 4th must return BackPressure carrying the configured cap.
        let mut t = SimulatedTransport::with_capacity(0, 0.0, 256, 64, 3);
        for _ in 0..3 {
            t.send(msg(vec![1])).unwrap();
        }
        let err = t.send(msg(vec![1])).unwrap_err();
        match err {
            TransportError::BackPressure { capacity } => assert_eq!(capacity, 3),
            other => panic!("expected BackPressure, got {:?}", other),
        }
        assert_eq!(t.outbox_len(), 3, "outbox must NOT have grown past cap");
    }

    #[test]
    fn test_outbox_size_stays_bounded_under_attack() {
        // Adversary calls send 10_000 times. Outbox stops growing at
        // capacity, every subsequent send returns BackPressure. No OOM.
        let mut t = SimulatedTransport::with_capacity(0, 0.0, 256, 64, 16);
        let mut ok = 0usize;
        let mut backpressure = 0usize;
        for _ in 0..10_000 {
            match t.send(msg(vec![0])) {
                Ok(()) => ok += 1,
                Err(TransportError::BackPressure { .. }) => backpressure += 1,
                Err(other) => panic!("unexpected error: {:?}", other),
            }
        }
        assert_eq!(ok, 16, "exactly outbox_capacity sends should succeed");
        assert_eq!(backpressure, 10_000 - 16);
        assert_eq!(t.outbox_len(), 16);
    }

    #[test]
    fn test_with_capacity_constructor_respects_custom_limits() {
        let t = SimulatedTransport::with_capacity(100, 0.0, 256, 7, 9);
        assert_eq!(t.inbox_capacity(), 7);
        assert_eq!(t.outbox_capacity(), 9);
        assert_eq!(t.mtu(), 256);
        assert_eq!(t.latency_ms(), 100);
    }

    #[test]
    fn test_with_capacity_zero_is_clamped_to_one() {
        // A zero-capacity inbox would silently swallow every message
        // because `len() >= 0` is always true. Clamp to 1 so the
        // invariant "at least one message can be held briefly" is
        // preserved.
        let t = SimulatedTransport::with_capacity(0, 0.0, 256, 0, 0);
        assert_eq!(t.inbox_capacity(), 1);
        assert_eq!(t.outbox_capacity(), 1);
    }

    #[test]
    fn test_backpressure_error_displays_capacity() {
        let e = TransportError::BackPressure { capacity: 42 };
        let s = format!("{}", e);
        assert!(s.contains("42"), "Display must surface the capacity");
        assert!(s.contains("outbox") || s.contains("full"));
    }
}
