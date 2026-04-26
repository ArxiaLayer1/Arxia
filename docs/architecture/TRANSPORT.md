# Multi-Modal Transport Layer

## Overview

Arxia operates over multiple physical transports. The transport layer
abstracts the underlying medium behind a common trait.

## TransportTrait

```rust
pub trait TransportTrait {
    fn send(&mut self, msg: TransportMessage) -> Result<(), TransportError>;
    fn try_recv(&mut self) -> Option<TransportMessage>;
    fn mtu(&self) -> usize;
}
```

`TransportError` carries structured error variants
(`PayloadTooLarge`, `Disconnected`, `MessageLost`, `BackPressure`,
`Other`) so the caller can implement explicit retry / backoff /
abort policies. See
[`arxia-transport::traits`](../../crates/arxia-transport/src/traits.rs)
for the canonical definitions.

`latency_ms` is NOT part of the trait — it is a property of specific
implementations (e.g.
[`SimulatedTransport::latency_ms()`](../../crates/arxia-transport/src/sim/simulated.rs)).

## Supported Transports

### LoRa / Meshtastic (Primary)

- **Frequency**: EU 868 MHz (1% duty cycle), US 915 MHz
- **Spreading factors**: SF7 (short range, fast) to SF12 (long range, slow)
- **MTU**: 256 bytes (Arxia compact block = 193 bytes fits)
- **Range**: 1-15 km line-of-sight, depends on SF and terrain
- **Hardware**: SX1276/SX1278 modules, ~$5-15

### BLE (L0 Proximity)

- **Range**: ~10-30 meters
- **Use case**: Point-of-sale, face-to-face transactions
- **Finality**: L0 only (no gossip verification possible)
- **MTU**: 512 bytes (simulated)
- **Latency**: ~50ms

### SMS (Fallback)

- **Encoding**: Base64 compact block split across 2-3 SMS messages
- **Use case**: Areas with cellular but no internet
- **Latency**: 1-5 seconds per message

### Satellite DVB-S2 (Reception-only)

- **Mode**: Broadcast reception only (no uplink)
- **Use case**: Periodic state snapshots for remote nodes
- **Data**: Compressed block batches, validator set updates

## Simulated Transport

For testing,
[`SimulatedTransport`](../../crates/arxia-transport/src/sim/simulated.rs)
uses:

- Configurable MTU and latency
- xorshift64 PRNG for deterministic packet loss simulation
- In-memory `VecDeque` inbox + `Vec` outbox
- Configurable loss rate (0.0-1.0)

### Bounded queues (CRIT-012)

Both queues are bounded to defend against denial-of-service via
unbounded growth (audit finding **CRIT-012**, closed by PR #44).
Defaults are `DEFAULT_INBOX_CAPACITY = 1024` and
`DEFAULT_OUTBOX_CAPACITY = 1024` (≈ 256 KB per direction at LoRa
MTU). For custom limits use
`SimulatedTransport::with_capacity(latency_ms, loss_rate, mtu,
inbox_cap, outbox_cap)`.

| Queue   | Overflow policy              | Observability |
|---------|------------------------------|---------------|
| Inbox   | drop-oldest (silent)         | `inbox_dropped() -> u64` cumulative counter, saturating at `u64::MAX` |
| Outbox  | back-pressure (return `Err(BackPressure { capacity })`) | `outbox_len() -> usize`, configured `outbox_capacity()` |

The asymmetry is deliberate:

- **Inbox is adversary-influenced** (a flooding peer controls
  injection rate). Drop-oldest preserves recency under flood; the
  observable counter is the back-pressure signal for the receive
  side. Refusing injection would let a malicious peer DoS the
  legitimate one.
- **Outbox is caller-controlled** (we control the send rate).
  Back-pressure forces the caller to slow down with an explicit
  `Err`, preserving test-side determinism (drop-oldest on outbox
  would silently rewrite the record of "what was emitted").

Production transports (LoRa, BLE, SMS, satellite) MUST inherit
the same bounded discipline once their inbox/outbox
representations land. The simulated layer establishes the
contract first so adversarial tests can assert against it.
