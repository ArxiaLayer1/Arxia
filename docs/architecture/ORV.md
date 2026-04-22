# Open Representative Voting (ORV) Specification

## Overview

ORV is Arxia's consensus mechanism, adapted from Nano's design with
modifications for offline operation. Representatives vote on blocks
weighted by delegated stake.

## Vote Structure

```rust
pub struct VoteORV {
    pub voter_pubkey: [u8; 32],
    pub block_hash: [u8; 32],
    pub delegated_stake: u64,
    pub round: u32,
    pub signature: [u8; 64],
}
```

## Vote Hash Computation

The vote hash is computed over an 80-byte input:
- bytes 0..32: block_hash
- bytes 32..40: delegated_stake (little-endian)
- bytes 40..44: round (little-endian)
- bytes 44..76: voter_pubkey
- bytes 76..80: padding (zeros)

This is then Blake3-hashed and Ed25519-signed.

## 3-Tier Conflict Resolution Cascade

When two blocks conflict (same account, same nonce):

1. **Stake-weighted**: Sum delegated stake for each candidate. If the gap
   exceeds 5% of total stake, the higher-stake candidate wins.
2. **Vector clock**: (Reserved for future implementation.) Compare causal
   ordering via vector clocks.
3. **Hash tiebreaker**: Lexicographically smaller block hash wins.
   Deterministic and requires no additional communication.

## Quorum Requirements

- At least 2/3 of known representatives must have voted
- At least 20% of total stake must be represented
- Both conditions must be met simultaneously

## Minimum Delegation

A vote is only counted if delegated_stake >= 0.1% of total stake in that
round. This prevents Sybil attacks via many low-stake voters.

## Delegation

Stake holders delegate to representatives. A representative's voting power
equals the sum of all delegations to them plus their own stake.
