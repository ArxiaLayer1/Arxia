# Threat Model

## 1. Sybil Attacks

**Threat**: Attacker creates many identities to influence consensus.

**Mitigation**: ORV is stake-weighted. Creating identities without stake
provides no voting power. Minimum delegation threshold (0.1% of total
stake per round) prevents dust-stake attacks.

## 2. Double-Spend Attacks

**Threat**: User creates two conflicting Send blocks with the same nonce.

**Detection**: Gossip protocol detects nonce collisions with different
block hashes. Nonce registry stores (account, nonce, block_hash) tuples.

**Resolution**: 3-tier ORV cascade determines the canonical block.
The rejected block is discarded, and the attacker's reputation is damaged.

## 3. Eclipse Attacks

**Threat**: Attacker surrounds a target node, controlling all its peers.

**Mitigation**: Multi-transport redundancy. Even if LoRa peers are
controlled, BLE proximity with the counterparty provides an independent
channel. Satellite broadcast provides another independent data source.

## 4. Relay Gaming

**Threat**: Relay operators selectively forward or withhold transactions.

**Mitigation**:
- Relay scoring tracks success/failure ratio
- Trusted threshold: score >= 0.8
- Stake slashing for provably malicious behavior
- Cryptographic relay receipts provide evidence of forwarding

## 5. Partition Manipulation

**Threat**: Attacker deliberately partitions the network to exploit
inconsistency.

**Mitigation**: CRDTs guarantee eventual consistency. After partition heals,
state converges deterministically. Finality levels (L0-L2) communicate the
confidence level to users. High-value transactions wait for L2 (67% validator
confirmation).

## 6. Long-Range Attacks

**Threat**: Attacker uses old keys to create alternative history.

**Mitigation**: Block lattice structure makes long-range attacks difficult
because each account chain is independent. Rewriting one chain does not
affect others. Nonce monotonicity prevents replaying old blocks.

## 7. Transaction Censorship

**Threat**: Validators refuse to vote on certain transactions.

**Mitigation**: ORV does not require specific validators. Any representative
with sufficient stake can vote. Multi-transport ensures transaction
propagation through alternative paths.

## 8. Key Compromise

**Threat**: An attacker obtains a user's private key.

**Mitigation**:
- ChaCha20-Poly1305 encryption for local key storage *(planned;
  `arxia_crypto::chacha20` currently returns `Err(Unimplemented)`
  post-CRIT-002 / PR #41 — no on-disk encryption is active until the
  real implementation lands)*
- SLIP39 seed backup for recovery *(planned; `arxia_crypto::slip39`
  also returns `Err(Unimplemented)` post-CRIT-003 / PR #41)*
- Users should rotate keys periodically
- REVOKE blocks invalidate compromised DID credentials

## 9. Carrington Event (Solar Storm)

**Threat**: Massive solar storm destroys electronic infrastructure over
a wide area.

**Mitigation**: Arxia nodes are cheap ($31) and widely distributed.
Satellite reception provides state snapshots for recovering nodes.
Battery-operated nodes with solar panels can survive grid failures.
The offline-first design means the network continues operating with
reduced connectivity.

## 10. Denial of Service

**Threat**: Attacker floods the network with transactions.

**Mitigation**: Transaction fees (100 micro-ARX base) make flooding
expensive. LoRa duty cycle limits (1% EU) naturally rate-limit individual
nodes. Transport layer can enforce per-peer rate limits.
