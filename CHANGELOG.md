# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Bug 1 — Double-receive prevention** ([#17](https://github.com/ArxiaLayer1/Arxia/pull/17)): track consumed SEND hashes per account to prevent a receiver from applying the same SEND block twice.
- **Bug 2 — Ed25519 signature verification in `add_block`** ([#12](https://github.com/ArxiaLayer1/Arxia/pull/12)): verify Ed25519 signatures on every insertion path, including gossip ingress, closing a missing check that allowed forged blocks to be accepted.
- **Bug 3 — Idempotent `AccountChain::open`** ([#13](https://github.com/ArxiaLayer1/Arxia/pull/13)): make `open` idempotent so that replaying an `OPEN` block on an already-opened chain is rejected cleanly instead of silently mutating state.
- **Bug 4 — NonceRegistry rekeyed from hash to `(account, nonce)`** ([#18](https://github.com/ArxiaLayer1/Arxia/pull/18)): the registry was keyed by block hash, which meant two signed blocks reusing the same nonce with different payloads were not flagged as a double-spend. Rekeying to `(account, nonce)` now returns `ArxiaError::DoubleSpend` at merge time.
- **Bug 5 — Timestamp-in-hash determinism** ([#19](https://github.com/ArxiaLayer1/Arxia/pull/19)): pin regression tests that assert the timestamp is included in the Blake3 preimage, preventing accidental removal that would make block hashes malleable.
- **Bug 6 — Per-account supply cap on `OPEN`** ([#14](https://github.com/ArxiaLayer1/Arxia/pull/14)): enforce the protocol supply cap at `open` time so a newly-created account cannot declare a genesis balance above `MAX_SUPPLY_PER_ACCOUNT`.
- **Bug 7 — CRDT conflict + non-negative balance invariant** ([#20](https://github.com/ArxiaLayer1/Arxia/pull/20)): `reconcile` now detects `(account, nonce)` conflicts and enforces `balance >= 0` post-merge, preventing partition reconciliation from producing negative balances.
- **RUSTSEC-2026-0097** ([#25](https://github.com/ArxiaLayer1/Arxia/pull/25)): bump `rand` from `0.8.5` to `0.8.6`. Arxia uses `OsRng` (not `ThreadRng`), so the project is not believed to be affected in practice, but the patched release is taken for a clean audit baseline.

### Added

- CI badge, Meshtastic disclaimer, and repository history note in `README.md` ([#22](https://github.com/ArxiaLayer1/Arxia/pull/22)).
- First real LoRa transaction on T-Beam hardware (`2026-04-18`): SEND + RECEIVE over mesh transport with offline finality assessment.

### Changed

- Bump `criterion` from `0.5.1` to `0.7.0` via workspace dependency ([#24](https://github.com/ArxiaLayer1/Arxia/pull/24)). Held at `0.7` because `0.8.x` requires Rust `1.86` while the workspace MSRV is pinned to `1.85.0`.
- `arxia-bench` now consumes `criterion` through `[workspace.dependencies]` instead of an inline version.

### Fixed

- `.gitignore` was silently excluding the `docs/` tree on case-insensitive filesystems; restored tracking and re-synced `docs/architecture/GOSSIP.md` and `docs/aips/AIP-0001-gossip-protocol.md` with the post-#18 API ([#21](https://github.com/ArxiaLayer1/Arxia/pull/21)).

### CI

- `Security Audit` workflow rewritten ([#23](https://github.com/ArxiaLayer1/Arxia/pull/23)): explicit `permissions:` block (`checks: write`, `issues: write`), toolchain pinned to `1.85.0`, `rustsec/audit-check@v2` replaced with a direct `cargo install --locked cargo-audit && cargo audit --deny warnings` invocation, and a `pull_request` trigger scoped to `Cargo.toml` / `Cargo.lock` / the workflow file itself.

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
