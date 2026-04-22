# Multi-Modal Transport Layer

## Overview

Arxia operates over multiple physical transports. The transport layer
abstracts the underlying medium behind a common trait.

## TransportTrait

```rust
pub trait TransportTrait {
    fn send(&mut self, msg: TransportMessage) -> Result<(), String>;
    fn try_recv(&mut self) -> Option<TransportMessage>;
    fn mtu(&self) -> usize;
    fn latency_ms(&self) -> u64;
}
```

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

For testing, `SimulatedTransport` uses:
- Configurable MTU and latency
- xorshift64 PRNG for deterministic packet loss simulation
- mpsc channels for message passing
- Configurable loss rate (0.0-1.0)
