# Governance

## Arxia Improvement Proposals (AIPs)

All protocol changes go through the AIP process:

1. **Draft**: Author writes proposal using `docs/aips/TEMPLATE.md`
2. **Review**: Community discussion (minimum 14 days)
3. **Vote**: ORV-based on-chain vote by stake holders
4. **Implementation**: Code changes merged after vote passes
5. **Activation**: Protocol upgrade at specified block height

## Voting Mechanism

- Votes are cast through the ORV system
- Quorum: >= 2/3 of representatives, >= 20% of total stake
- Supermajority (>= 67%) required for protocol changes
- Simple majority for parameter adjustments

## Voting Power Cap

No single entity may control more than 10% of total voting power,
enforced by delegation limits.

## DAO Transition

The project starts with a core contributor multisig for emergency
protocol upgrades. Transition to full DAO governance is planned for
after mainnet stabilization.

## AIP Categories

| Category     | Description                        | Threshold |
|--------------|------------------------------------|-----------|
| Core         | Consensus, block format changes    | 67%       |
| Transport    | New transport protocols            | 67%       |
| Parameter    | Fee adjustments, limits            | 50%       |
| Informational| Best practices, guidelines         | N/A       |
