# Arxia

[![CI](https://github.com/ArxiaLayer1/Arxia/actions/workflows/ci.yml/badge.svg)](https://github.com/ArxiaLayer1/Arxia/actions/workflows/ci.yml)

Offline-first Layer 1 blockchain operating over LoRa, BLE, SMS, and satellite.

## Overview

Arxia is a block-lattice blockchain designed for environments with intermittent
or no internet connectivity. It uses Ed25519 signatures, Blake3 hashing,
CRDT-based state reconciliation, and Open Representative Voting (ORV) for
consensus.

## Quick Start

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace

# Run examples
cargo run --example offline_payment
cargo run --example did_issuance
cargo run --example mesh_relay
cargo run --example partition_reconciliation
```

## Architecture

```
Transport (LoRa/BLE/SMS/Satellite)
  -> Gossip Protocol (nonce registry, sync)
    -> Block Lattice (per-account DAG chains)
      -> CRDT Reconciliation (PN-Counter, OR-Set, Vector Clocks)
        -> ORV Consensus (stake-weighted voting)
          -> Finality (L0/L1/L2)
```

See [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) for details.

## Workspace Crates

| Crate              | Description                              |
|--------------------|------------------------------------------|
| `arxia-core`       | Types, errors, constants                 |
| `arxia-crypto`     | Ed25519, Blake3, ChaCha20, SLIP39        |
| `arxia-lattice`    | Block types, AccountChain, VectorClock   |
| `arxia-crdt`       | PN-Counter, OR-Set, reconciliation       |
| `arxia-consensus`  | ORV votes, conflict resolution, quorum   |
| `arxia-gossip`     | Nonce registry, gossip sync              |
| `arxia-finality`   | 4-level finality assessment              |
| `arxia-transport`  | Multi-modal transport abstraction        |
| `arxia-relay`      | Relay receipts, scoring, slashing        |
| `arxia-did`        | W3C Decentralized Identifiers            |
| `arxia-wasm`       | WASM smart contract runtime (stub)       |
| `arxia-storage`    | Pluggable storage backend                |
| `arxia-proto`      | Protobuf definitions                     |
| `arxia-bench`      | Criterion benchmarks                     |

## Hardware

A minimal node costs ~$31 using a TTGO T-Beam ESP32 with SX1276 LoRa.
See [docs/guides/HARDWARE_SETUP.md](docs/guides/HARDWARE_SETUP.md).

## Documentation

- [Architecture](docs/architecture/)
- [Protocol](docs/protocol/)
- [Guides](docs/guides/)
- [Research](docs/research/)
- [AIPs](docs/aips/)

## Disclaimer

Arxia is not affiliated with or endorsed by the Meshtastic project.
Meshtastic is used as one of several swappable transport layers; Arxia
is designed to operate over any compatible radio transport (raw LoRa,
Reticulum, BLE, SMS, or satellite).

## Repository History

This repository was consolidated from a private workspace in March 2026.
Commits from that point onward represent live, in-the-open development.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
