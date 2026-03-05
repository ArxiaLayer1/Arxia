# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2025-01-15

### Added

- Block lattice with per-account chains (SEND/RECEIVE/OPEN/REVOKE)
- Ed25519 signatures over raw Blake3 hash bytes
- Open Representative Voting (ORV) consensus
- 3-tier conflict resolution cascade (stake > vector_clock > hash_tiebreaker)
- CRDT reconciliation (PN-Counter, OR-Set, Vector Clocks)
- Gossip protocol with nonce registry and double-spend detection
- 4-level finality assessment (PENDING, L0, L1, L2)
- Multi-modal transport abstraction (LoRa, BLE, SMS, Satellite)
- SimulatedTransport with deterministic xorshift64 PRNG
- Relay scoring and slashing system
- W3C Decentralized Identifiers (did:arxia: method)
- 193-byte compact block serialization
- ChaCha20-Poly1305 local encryption
- Pluggable storage backend
- Protobuf message definitions
- Criterion benchmark harness
- ESP32 target (no_std stub)
- 4 example programs
- 2 example contracts (escrow, token-lock)
- CLI tools (keygen, DID generation)
