# Finality Levels

## Overview

Arxia defines four levels of transaction finality, designed for progressive
confidence as network connectivity improves.

## Levels

| Level   | Condition                        | Use Case                      |
|---------|----------------------------------|-------------------------------|
| PENDING | >10 ARX or 0 confirmations      | Awaiting further verification |
| L0      | <=10 ARX, BLE proximity only     | Small face-to-face payments   |
| L1      | >=1 LoRa node, gossip sync OK    | Medium transactions <=50 USD  |
| L2      | >=67% validator stake confirmed  | High-value, full consensus    |

## Assessment Logic

```rust
pub fn assess_finality(
    amount: u64,
    confirmations: u32,
    sync_result: &SyncResult,
    validator_pct: f64,
) -> FinalityLevel {
    // L2 takes priority if validator threshold met
    if validator_pct >= 0.67 { return FinalityLevel::L2; }
    // L1 requires gossip sync success
    if confirmations >= 1 && matches!(sync_result, SyncResult::Success) {
        return FinalityLevel::L1;
    }
    // L0 for small amounts
    if amount <= L0_CAP_MICRO_ARX && confirmations >= 1 {
        return FinalityLevel::L0;
    }
    FinalityLevel::Pending
}
```

## L0 Cap

L0_CAP_MICRO_ARX = 10,000,000 (10 ARX). Transactions above this amount
cannot achieve L0 finality and must wait for L1 or L2.

## L1 Gossip Requirement

L1 finality is conditioned on `SyncResult::Success` from the gossip
protocol. If gossip sync returns `Mismatch` or `NoNeighbors`, finality
falls back to L0 (if amount qualifies) or PENDING.
