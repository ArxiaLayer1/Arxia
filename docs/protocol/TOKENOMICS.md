# Arxia Tokenomics

> **Status:** Pre-mainnet. ARX does not exist on-chain yet. This document describes
> the planned token economics for the Arxia protocol. All parameters are subject
> to change prior to TGE.

---

## Table of Contents

1. [Overview](#overview)
2. [Supply](#supply)
3. [Allocation](#allocation)
4. [Vesting Schedule](#vesting-schedule)
5. [Node Operator Rewards](#node-operator-rewards)
6. [Fee Mechanism](#fee-mechanism)
7. [Staking](#staking)
8. [Slashing](#slashing)
9. [TGE and IDO](#tge-and-ido)
10. [Governance](#governance)

---

## Overview

ARX is the native utility token of the Arxia protocol. It serves four functions:

- **Transaction fees** — every transaction pays a fee in ARX, split between the
  relaying node, validators, and a burn mechanism.
- **Node staking** — relay node operators stake ARX as collateral. Stake is slashed
  for poor performance or malicious behavior.
- **Governance** — ARX holders vote on protocol parameter changes, treasury
  allocations, and the transition to full DAO governance.
- **Node rewards** — operators earn ARX proportional to their relay score over
  monthly emission cycles.

ARX is **not** a security token. It does not represent equity, profit sharing, or
any claim against the Arxia Foundation. Its utility is functional: paying fees,
earning rewards, and participating in governance.

---

## Supply

| Parameter        | Value                          |
|------------------|-------------------------------|
| Total supply     | 1,000,000,000 ARX (1 billion) |
| Inflation        | Zero — fixed supply at genesis |
| Decimals         | 18                             |
| Token standard   | ERC-20 on Base (pre-mainnet)  |
| Native token     | ARX on Arxia L1 (post-mainnet)|

The supply is fixed at genesis. No additional ARX can ever be minted. The only
supply-side mechanic is the burn component of transaction fees, which is
deflationary over time.

---

## Allocation

```
Total Supply: 1,000,000,000 ARX
│
├── Node Operators      250,000,000 ARX  (25%)
├── Ecosystem Fund      200,000,000 ARX  (20%)
├── Team                150,000,000 ARX  (15%)
├── Public IDO          150,000,000 ARX  (15%)
├── Treasury            130,000,000 ARX  (13%)
└── Seed Investors      120,000,000 ARX  (12%)
```

### Node Operators — 250,000,000 ARX (25%)

Distributed to relay node operators over 60 months according to a decreasing
emission schedule. Rewards are proportional to each node's relay score relative
to the total network score.

| Period     | Monthly Emission  | Total          |
|------------|-------------------|----------------|
| M1–M12     | 6,250,000 ARX     | 75,000,000 ARX |
| M13–M24    | 4,583,333 ARX     | 55,000,000 ARX |
| M25–M60    | 3,333,334 ARX     | 120,000,000 ARX|
| **Total**  |                   | **250,000,000 ARX** |

### Ecosystem Fund — 200,000,000 ARX (20%)

Controlled by the Arxia Foundation multi-sig (5/9). Used for:
- Developer grants and hackathons
- ONG deployment subsidies
- Bug bounty program (250,000 USD equivalent ARX at testnet launch)
- Community incentives

### Team — 150,000,000 ARX (15%)

Cliff 12 months, linear vesting over 36 months (48 months total).
Held in a 3/5 founder multi-sig. Vesting executed via Sablier V2 on Base,
publicly visible on-chain in real time.

### Public IDO — 150,000,000 ARX (15%)

Distributed via Liquidity Bootstrapping Pool (LBP) on Fjord Foundry (Base).
See [TGE and IDO](#tge-and-ido).

### Treasury — 130,000,000 ARX (13%)

Vesting over 48 months. Governed by DAO vote (5% quorum of circulating supply).
Used for long-term protocol development, audits, and operational continuity
post-DAO transition.

### Seed Investors — 120,000,000 ARX (12%)

Price: 0.02 USDC/ARX. Cliff 6 months, linear vesting over 24 months (30 months
total). Structured as SAFT (Simple Agreement for Future Tokens) — no tokens are
delivered until TGE. Vesting via Sablier V2 on Base post-TGE.

---

## Vesting Schedule

```
                 Cliff     Vesting     Total Lock
Team             12 mo  +  36 mo    =  48 months
Seed Investors    6 mo  +  24 mo    =  30 months
Treasury          0 mo  +  48 mo    =  48 months
Node Operators    0 mo  +  60 mo    =  60 months (emission schedule)
Ecosystem Fund    0 mo  +  governance-controlled
Public IDO        0 mo  (delivered at TGE)
```

All vesting is enforced on-chain via Sablier V2 streaming contracts on Base,
publicly auditable in real time. No party can accelerate their vesting.

---

## Node Operator Rewards

Node operators earn ARX monthly based on their **relay score**:

```
reward = (node_score / total_network_score) × monthly_emission
```

Where:

```
node_score = valid_relay_receipts / transactions_in_range (30-day window)
```

A `RelayReceipt` is a cryptographic proof (`Ed25519` signed) that a node relayed
a specific transaction. Receipts are collected in batches (`RelayBatch`) separate
from transaction payloads to respect the LoRa 256-byte MTU constraint.

### Geographic Multiplier

Nodes operating in active conflict zones (ACLED classification) receive a
**×2 multiplier** on their relay score. This counteracts the centralizing
incentive of deploying nodes in well-connected urban areas rather than
high-need regions.

The ACLED zone list is distributed weekly via satellite broadcast (<500 KB),
signed by the Arxia Foundation Ed25519 key, and verified offline by each node.

### Minimum Stake to Activate

A node must stake a minimum of **500 ARX** to be eligible for rewards.
This threshold is recalibrable by governance if ARX price exceeds ~2 USD
(to prevent the stake from becoming prohibitive for operators in low-income
regions).

---

## Fee Mechanism

Every transaction pays a fee computed as:

```
fee = ceil(tx_bytes / 100) × BASE_FEE_ARX
```

Where `BASE_FEE_ARX = 0.001 ARX` (fixed at genesis, adjustable by governance
every 6 months via the `fee_arx_per_usd_cent` parameter).

### Fee Distribution

| Destination            | Share |
|------------------------|-------|
| LoRa relay node        | 60%   |
| Burned (deflationary)  | 30%   |
| Validator (L2)         | 10%   |

For **L0 transactions** (BLE only, no LoRa node involved):

| Destination            | Share |
|------------------------|-------|
| Burned                 | 100%  |

---

## Staking

### Node Staking

| Parameter              | Value                                      |
|------------------------|--------------------------------------------|
| Minimum stake          | 500 ARX                                    |
| Governance adjustment  | If ARX > ~2 USD, threshold recalibrated    |
| Lock period            | Active while node is registered            |
| Reward eligibility     | Requires score ≥ 85% over 30-day window   |

### Representative Delegation (ORV)

ARX holders can delegate their stake to a representative for ORV consensus votes.
Delegation rules:

- Minimum delegation age: **7 days** before taking effect (anti-stake-grinding)
- Stake delegated after a partition begins is ignored for that ORV round
- Delegation is revocable at any time, with a 7-day delay before the new
  assignment activates

Representative eligibility: minimum **0.1% of total supply** delegated.

---

## Slashing

Node operators are subject to slashing for poor relay performance:

| Condition                         | Penalty                              |
|-----------------------------------|--------------------------------------|
| Score < 85% over 30 days          | −10% of staked ARX                   |
| Score < 60% over 7 days           | −25% of staked ARX + node exclusion  |
| Cooldown after exclusion          | 30 days before re-registration       |

Slashed ARX is burned, not redistributed. This prevents perverse incentives
where validators benefit from slashing competitors.

---

## TGE and IDO

### Phase 1 — Seed Round (Pre-TGE)

- Instrument: SAFT
- Price: **0.02 USDC/ARX**
- Allocation: 120,000,000 ARX (12% of supply)
- Target raise: **2,400,000 USDC**
- Vesting: cliff 6 months + linear 24 months via Sablier V2

### Phase 2 — TGE / Public IDO (M24+)

- Platform: **Fjord Foundry LBP** on Base
- Allocation: 150,000,000 ARX (15% of supply)
- Starting price: **0.08 USDC/ARX**
- Price floor: **0.03 USDC/ARX**
- Duration: **72 hours**
- Post-IDO liquidity: Uniswap V3 on Base

#### Seed Round Return Scenarios

| Scenario | IDO Price    | Multiple |
|----------|--------------|----------|
| Bear     | 0.03 USDC    | 1.5×     |
| Base     | 0.10 USDC    | 5×       |
| Bull     | 0.30 USDC    | 15×      |
| Ultra    | 1.00 USDC    | 50×      |

The 30-month total vesting (cliff 6m + linear 24m) prevents seed investors from
dumping at IDO open. Zero seed ARX is liquid at the moment the LBP begins.

### Phase 3 — Migration to Arxia L1 (Post-Mainnet)

- Bridge: Lock-and-Mint, **unidirectional** (Base → Arxia L1 only)
- Ratio: 1:1 ARX ERC-20 → ARX native
- Migration window: 24 months post-mainnet
- Custody: Arxia Foundation multi-sig (5/9) + 72-hour timelock
- Bridge risk isolation: a bridge compromise does not affect L1 operation

---

## Governance

### Voting Mechanics

- Model: stake-weighted (1 ARX = 1 vote)
- Cap: `min(balance, 0.10 × total_votes_cast)` — no single wallet exceeds 10%
  of effective quorum
- Votes are signed on-chain; duplicates deduplicated by hash at reconciliation
- Offline votes: nonce-signed, deduplicated at network sync; oldest vector clock
  wins if the same wallet votes in two partitions

### Quorum Thresholds

| Decision Type                          | Quorum Required              |
|----------------------------------------|------------------------------|
| Standard parameter changes             | 5% of circulating supply     |
| Critical (supply, protocol upgrades)   | 15% of circulating supply    |
| Absolute floor                         | 50,000,000 ARX               |
| Escalation (>400M ARX in circulation)  | 25% of circulating supply    |

Critical decisions additionally require **Arxia Foundation multi-sig (5/9)**
approval in parallel. This dual-key mechanism protects against governance
attacks during early circulation phases.

### DAO Transition

The Arxia Foundation transfers governance to a full on-chain DAO when all four
conditions are met simultaneously:

1. Mainnet live for ≥ 6 months
2. Circulating supply ≥ 40% of total
3. ≥ 1,000 active relay nodes
4. ≥ 3 independent security audits published

Once conditions are met, the Foundation has a 6-month window to execute the
transfer. There is no automatic enforcement mechanism — the Foundation's
obligation is contractual and reputational.

---

## Notes and Caveats

- All figures are subject to change prior to TGE.
- The ARX token does not exist on-chain at this stage. No purchases, pre-sales,
  or token transfers of any kind are currently open.
- This document is for informational purposes only and does not constitute a
  financial offer or investment advice.
- The Arxia Foundation is incorporated in Zug, Switzerland. Token classification
  is subject to ongoing legal review under Swiss law and the EU MiCA framework.

---

*Last updated: 2026-03-19 — v29*
