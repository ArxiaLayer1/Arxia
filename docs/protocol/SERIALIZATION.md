# Compact Block Serialization

## Overview

Blocks are serialized into a 193-byte compact format to fit within
the LoRa 256-byte MTU.

## Byte Layout

| Offset | Size | Field                |
|--------|------|----------------------|
| 0      | 32   | account (pubkey)     |
| 32     | 32   | previous (hash)      |
| 64     | 1    | block_type tag       |
| 65     | 32   | destination/source   |
| 97     | 8    | amount (LE u64)      |
| 105    | 8    | balance (LE u64)     |
| 113    | 8    | nonce (LE u64)       |
| 121    | 8    | timestamp (LE u64)   |
| 129    | 64   | signature            |
| **193**| **total** |                 |

## Block Type Tags

| Tag | Type    |
|-----|---------|
| 0   | Open    |
| 1   | Send    |
| 2   | Receive |
| 3   | Revoke  |

## Serialization

```rust
pub fn to_compact_bytes(block: &Block) -> Result<[u8; 193], ArxiaError>
pub fn from_compact_bytes(bytes: &[u8; 193]) -> Result<Block, ArxiaError>
```

Roundtrip property: `from_compact_bytes(to_compact_bytes(block)) == block`

## LoRa MTU Compliance

LoRa maximum payload at SF7/125kHz is 256 bytes. The 193-byte compact
format leaves 63 bytes of headroom for LoRa/Meshtastic framing headers.
