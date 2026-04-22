# Cryptographic Primitives

## Ed25519

- **Purpose**: Block signing, vote signing, DID authentication
- **Library**: ed25519-dalek
- **Key size**: 32-byte public key, 64-byte signature
- **Why**: Fast on constrained devices (ESP32), well-studied, deterministic

### Critical Invariant

Signatures are computed over **raw Blake3 hash bytes** (32 bytes), NOT
over hex-encoded strings (64 bytes). This was a bug in PoC v0.2 and
is enforced by the API design.

## Blake3

- **Purpose**: Block hashing, DID derivation, contract addressing
- **Output**: 32 bytes (256 bits)
- **Why**: Faster than SHA-256, SIMD-optimized, tree-hashable for parallelism

## ChaCha20-Poly1305

- **Purpose**: Local encryption of private keys and wallet data
- **Library**: chacha20poly1305
- **Nonce**: 12 bytes (96 bits)
- **Why**: Constant-time, no padding oracle attacks, efficient in software

## SLIP39 (Shamir Secret Sharing)

- **Purpose**: Seed backup and recovery
- **Threshold**: Configurable k-of-n (e.g., 2-of-3)
- **Encoding**: Mnemonic word shares
- **Status**: Stub in v0.1.0

## ESP32 Performance

| Operation          | ESP32 (240 MHz) |
|--------------------|-----------------|
| Ed25519 sign       | ~15 ms          |
| Ed25519 verify     | ~40 ms          |
| Blake3 (1 KB)      | ~0.1 ms         |
| ChaCha20 (1 KB)    | ~0.05 ms        |
