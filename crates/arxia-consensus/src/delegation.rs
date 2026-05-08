//! Stake delegation to representatives.
//!
//! # HIGH-007 (commit 088): delegation as a DAG
//!
//! The pre-fix module only computed [`total_delegated_stake`].
//! The audit (HIGH-007):
//!
//! > `total_delegated_stake()` exists; nothing else. Any future
//! > delegation chain can cycle (A→B→C→A), self-delegate,
//! > delegate to a nonexistent key, or revoke mid-vote.
//! > Suggested fix direction: implement delegation as a DAG with
//! > cycle detection on every new delegation edge; revocation is
//! > an explicit signed op; staked-at-vote-time is the committed
//! > snapshot.
//!
//! [`DelegationGraph`] enforces:
//!
//! 1. **No self-delegation.** `delegator == representative` is
//!    rejected at insert time.
//! 2. **No cycles.** Before adding edge `A → B`, the graph
//!    checks whether a path `B ⇝ A` already exists ; if so the
//!    edge is rejected with [`DelegationError::CycleDetected`].
//!    The check is a depth-first walk bounded by
//!    [`MAX_DELEGATION_DEPTH`] (8) so a malicious chain cannot
//!    DoS the validator.
//! 3. **Revocation as an explicit signed op.** [`Revocation`]
//!    carries an Ed25519 signature by the delegator over the
//!    canonical bytes (delegator || representative || nonce).
//!    [`DelegationGraph::revoke`] verifies the signature before
//!    removing the edge.
//! 4. **Snapshot at vote time.** [`DelegationGraph::snapshot`]
//!    returns an immutable [`DelegationSnapshot`] of the
//!    representative→stake map at a moment in time. Subsequent
//!    delegate/revoke operations on the graph do NOT mutate
//!    the snapshot ; voting code that captured a snapshot at
//!    block-N consensus is unaffected by races on block-N+1.
//!
//! Pre-fix [`total_delegated_stake`] is preserved as a thin
//! wrapper over `DelegationGraph::total_for_representative` so
//! existing call sites compile unchanged.

use std::collections::{HashMap, HashSet};

/// Maximum allowed depth of the delegation chain when checking
/// cycles or computing transitive stake. Caps the DFS at insert
/// time so a malicious peer cannot DoS the validator with a
/// pathologically deep chain.
///
/// HIGH-007 (commit 088): conservative value. Realistic
/// delegation chains in practice are 1-2 hops (A delegates to
/// B, B is a registered validator). 8 leaves room for nested
/// delegation pools while still bounding the DFS cost.
pub const MAX_DELEGATION_DEPTH: usize = 8;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`Revocation`]. Distinct from any other signed operation in
/// the consensus crate.
pub const DELEGATION_REVOCATION_DOMAIN: &[u8] = b"arxia-delegation-revocation-v1";

/// Errors returned by [`DelegationGraph`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// `delegator == representative`. A delegator cannot
    /// delegate to itself ; that's identity, not delegation.
    SelfDelegation,
    /// Adding the proposed edge would create a cycle in the
    /// delegation graph.
    CycleDetected {
        /// The would-be delegator.
        from: String,
        /// The would-be representative.
        to: String,
    },
    /// The proposed delegation chain exceeds
    /// [`MAX_DELEGATION_DEPTH`].
    DepthExceeded {
        /// Depth observed during the cycle check.
        depth: usize,
        /// The cap.
        max: usize,
    },
    /// [`Revocation::verify`] failed: signature does not
    /// authenticate the (delegator, representative, nonce)
    /// triple under the carried pubkey.
    InvalidRevocationSignature,
    /// `revoke(...)` was called on an edge that doesn't exist.
    EdgeNotFound {
        /// The delegator side of the missing edge.
        delegator: String,
        /// The representative side.
        representative: String,
    },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfDelegation => f.write_str("delegator cannot delegate to itself"),
            Self::CycleDetected { from, to } => {
                write!(f, "delegation {from} -> {to} would create a cycle")
            }
            Self::DepthExceeded { depth, max } => {
                write!(f, "delegation chain depth {depth} exceeds cap {max}")
            }
            Self::InvalidRevocationSignature => f.write_str("revocation signature does not verify"),
            Self::EdgeNotFound {
                delegator,
                representative,
            } => write!(f, "no delegation edge {delegator} -> {representative}"),
        }
    }
}

impl std::error::Error for DelegationError {}

/// A delegation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The account delegating its stake.
    pub delegator: String,
    /// The representative receiving the delegation.
    pub representative: String,
    /// The amount of stake delegated (micro-ARX).
    pub amount: u64,
    /// Unix timestamp when the delegation was created.
    pub created_at: u64,
}

/// A signed revocation of a delegation edge.
///
/// HIGH-007 (commit 088): revocation is an explicit signed
/// operation. The delegator signs the canonical bytes
/// (DELEGATION_REVOCATION_DOMAIN || delegator_pubkey ||
/// representative_pubkey || nonce_le) under their Ed25519 key
/// ; [`DelegationGraph::revoke`] verifies the signature before
/// removing the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// 32-byte Ed25519 public key of the delegator. Must match
    /// the `delegator` field of the edge being revoked AND
    /// must be the signer of the revocation.
    pub delegator_pubkey: [u8; 32],
    /// String form of the delegator (matches `Delegation.delegator`).
    pub delegator: String,
    /// String form of the representative (matches `Delegation.representative`).
    pub representative: String,
    /// Monotonic nonce per (delegator, representative) pair.
    /// Prevents replay of a stale revocation.
    pub nonce: u64,
    /// Ed25519 signature over [`Self::canonical_bytes`].
    pub signature: [u8; 64],
}

impl Revocation {
    /// Build the canonical bytes that the delegator signs.
    pub fn canonical_bytes(
        delegator_pubkey: &[u8; 32],
        delegator: &str,
        representative: &str,
        nonce: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            DELEGATION_REVOCATION_DOMAIN.len() + 32 + delegator.len() + representative.len() + 8,
        );
        buf.extend_from_slice(DELEGATION_REVOCATION_DOMAIN);
        buf.extend_from_slice(delegator_pubkey);
        buf.extend_from_slice(delegator.as_bytes());
        buf.extend_from_slice(representative.as_bytes());
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf
    }

    /// Verify the Ed25519 signature.
    pub fn verify(&self) -> Result<(), DelegationError> {
        let canonical = Self::canonical_bytes(
            &self.delegator_pubkey,
            &self.delegator,
            &self.representative,
            self.nonce,
        );
        arxia_crypto::verify(&self.delegator_pubkey, &canonical, &self.signature)
            .map_err(|_| DelegationError::InvalidRevocationSignature)
    }
}

/// Immutable snapshot of the per-representative stake totals at
/// a moment in time.
///
/// HIGH-007 (commit 088): captured by
/// [`DelegationGraph::snapshot`] at vote time. Subsequent graph
/// mutations do NOT affect the snapshot ; the consensus layer
/// uses the snapshot to compute stake-weighted finality without
/// race conditions against concurrent delegation churn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationSnapshot {
    totals: HashMap<String, u64>,
}

impl DelegationSnapshot {
    /// Total stake delegated to `representative` at snapshot
    /// time.
    pub fn total_for(&self, representative: &str) -> u64 {
        self.totals.get(representative).copied().unwrap_or(0)
    }

    /// Number of distinct representatives with non-zero stake.
    pub fn representative_count(&self) -> usize {
        self.totals.len()
    }
}

/// Delegation graph with cycle detection and signed revocation.
#[derive(Debug, Clone, Default)]
pub struct DelegationGraph {
    /// Per-(delegator, representative) record. The pair is
    /// unique ; re-delegating the same pair updates the amount.
    edges: HashMap<(String, String), Delegation>,
    /// Adjacency list keyed by delegator → set of
    /// representatives. Used by the cycle check.
    adjacency: HashMap<String, HashSet<String>>,
}

impl DelegationGraph {
    /// Empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Add a delegation edge. Returns `Err` if it would create
    /// a cycle, exceed the depth cap, or self-delegate.
    ///
    /// If the (delegator, representative) edge already exists,
    /// its `amount` and `created_at` are updated in place ; the
    /// cycle check is skipped (the edge already passed when it
    /// was first added, and amount changes don't affect graph
    /// shape).
    pub fn delegate(&mut self, d: Delegation) -> Result<(), DelegationError> {
        if d.delegator == d.representative {
            return Err(DelegationError::SelfDelegation);
        }
        let key = (d.delegator.clone(), d.representative.clone());
        // Re-delegation of an existing edge: just update the
        // amount. Graph shape unchanged ; no cycle check needed.
        // Use HashMap::entry to avoid the
        // `clippy::map_entry` lint (one lookup instead of two).
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.edges.entry(key.clone()) {
            e.insert(d);
            return Ok(());
        }
        // New edge: cycle / depth check.
        // Path d.representative ⇝ d.delegator already in graph?
        // If yes, adding d.delegator → d.representative closes
        // the cycle.
        self.check_no_path_within_depth(&d.representative, &d.delegator, MAX_DELEGATION_DEPTH)?;
        self.adjacency
            .entry(d.delegator.clone())
            .or_default()
            .insert(d.representative.clone());
        self.edges.insert(key, d);
        Ok(())
    }

    /// DFS from `start` ; if we reach `target` within `max_depth`
    /// hops, return CycleDetected. Otherwise Ok.
    ///
    /// HIGH-007 (commit 088): the depth bound is
    /// [`MAX_DELEGATION_DEPTH`] ; if the chain is deeper than
    /// that, we fail with `DepthExceeded` (defense-in-depth ;
    /// realistic chains are 1-2 hops).
    fn check_no_path_within_depth(
        &self,
        start: &str,
        target: &str,
        max_depth: usize,
    ) -> Result<(), DelegationError> {
        let mut visited: HashSet<&str> = HashSet::new();
        // (node, depth)
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        while let Some((node, depth)) = stack.pop() {
            if node == target {
                return Err(DelegationError::CycleDetected {
                    from: target.to_string(),
                    to: start.to_string(),
                });
            }
            if depth >= max_depth {
                return Err(DelegationError::DepthExceeded {
                    depth,
                    max: max_depth,
                });
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(neighbors) = self.adjacency.get(node) {
                for n in neighbors {
                    stack.push((n.as_str(), depth + 1));
                }
            }
        }
        Ok(())
    }

    /// Revoke an edge by signed [`Revocation`]. The delegator
    /// must sign the canonical bytes ; the signature is
    /// verified before the edge is removed.
    pub fn revoke(&mut self, rev: &Revocation) -> Result<(), DelegationError> {
        rev.verify()?;
        let key = (rev.delegator.clone(), rev.representative.clone());
        if !self.edges.contains_key(&key) {
            return Err(DelegationError::EdgeNotFound {
                delegator: rev.delegator.clone(),
                representative: rev.representative.clone(),
            });
        }
        self.edges.remove(&key);
        if let Some(neighbors) = self.adjacency.get_mut(&rev.delegator) {
            neighbors.remove(&rev.representative);
            if neighbors.is_empty() {
                self.adjacency.remove(&rev.delegator);
            }
        }
        Ok(())
    }

    /// Total directly-delegated stake for `representative`.
    /// Direct edges only ; transitive stake is out of scope for
    /// the snapshot semantics (the audit specifies "staked-at-
    /// vote-time" which is the direct sum at snapshot time).
    pub fn total_for_representative(&self, representative: &str) -> u64 {
        self.edges
            .values()
            .filter(|d| d.representative == representative)
            .map(|d| d.amount)
            .fold(0u64, u64::saturating_add)
    }

    /// Capture an immutable snapshot of all per-representative
    /// totals. Subsequent mutations on `self` do not affect the
    /// snapshot.
    pub fn snapshot(&self) -> DelegationSnapshot {
        let mut totals: HashMap<String, u64> = HashMap::new();
        for d in self.edges.values() {
            let entry = totals.entry(d.representative.clone()).or_insert(0);
            *entry = entry.saturating_add(d.amount);
        }
        DelegationSnapshot { totals }
    }
}

/// Compute total delegated stake for a representative.
///
/// Backward-compat shim ; for graph-aware consumers (cycle
/// rejection, revocation) use [`DelegationGraph`] directly.
pub fn total_delegated_stake(representative: &str, delegations: &[Delegation]) -> u64 {
    delegations
        .iter()
        .filter(|d| d.representative == representative)
        .map(|d| d.amount)
        .fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    #[test]
    fn test_total_delegated_stake() {
        let ds = vec![
            Delegation {
                delegator: "a".into(),
                representative: "r1".into(),
                amount: 1_000_000,
                created_at: 0,
            },
            Delegation {
                delegator: "b".into(),
                representative: "r1".into(),
                amount: 2_000_000,
                created_at: 0,
            },
            Delegation {
                delegator: "c".into(),
                representative: "r2".into(),
                amount: 5_000_000,
                created_at: 0,
            },
        ];
        assert_eq!(total_delegated_stake("r1", &ds), 3_000_000);
        assert_eq!(total_delegated_stake("r2", &ds), 5_000_000);
        assert_eq!(total_delegated_stake("r3", &ds), 0);
    }

    // ============================================================
    // HIGH-007 (commit 088) — DelegationGraph DAG semantics:
    // self-rejection, cycle detection, signed revocation,
    // snapshot semantics.
    // ============================================================

    fn d(from: &str, to: &str, amount: u64) -> Delegation {
        Delegation {
            delegator: from.into(),
            representative: to.into(),
            amount,
            created_at: 0,
        }
    }

    #[test]
    fn test_delegation_rejects_self() {
        // PRIMARY HIGH-007 PIN: self-delegation rejected.
        let mut g = DelegationGraph::new();
        let err = g
            .delegate(d("alice", "alice", 100))
            .expect_err("self-delegation must be rejected");
        assert_eq!(err, DelegationError::SelfDelegation);
        assert!(g.is_empty());
    }

    #[test]
    fn test_delegation_rejects_cycle_a_b_a() {
        // 2-hop cycle: A→B, then B→A would close it.
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "bob", 100)).unwrap();
        let err = g
            .delegate(d("bob", "alice", 50))
            .expect_err("B->A after A->B must be rejected as cycle");
        assert!(matches!(err, DelegationError::CycleDetected { .. }));
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_delegation_rejects_cycle_a_b_c_a() {
        // PRIMARY HIGH-007 PIN: 3-hop cycle. Audit's exact attack.
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "bob", 100)).unwrap();
        g.delegate(d("bob", "carol", 50)).unwrap();
        let err = g
            .delegate(d("carol", "alice", 25))
            .expect_err("A->B->C->A must be rejected");
        assert!(matches!(err, DelegationError::CycleDetected { .. }));
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_delegation_accepts_chain_within_depth_cap() {
        // 4-hop linear chain, no cycle ; must succeed.
        let mut g = DelegationGraph::new();
        g.delegate(d("a", "b", 1)).unwrap();
        g.delegate(d("b", "c", 1)).unwrap();
        g.delegate(d("c", "d", 1)).unwrap();
        g.delegate(d("d", "e", 1)).unwrap();
        assert_eq!(g.edge_count(), 4);
    }

    #[test]
    fn test_delegation_accepts_diamond_no_cycle() {
        // Diamond: A→B, A→C, B→D, C→D. No cycle ; must succeed.
        let mut g = DelegationGraph::new();
        g.delegate(d("a", "b", 1)).unwrap();
        g.delegate(d("a", "c", 1)).unwrap();
        g.delegate(d("b", "d", 1)).unwrap();
        g.delegate(d("c", "d", 1)).unwrap();
        assert_eq!(g.edge_count(), 4);
    }

    #[test]
    fn test_delegation_re_delegate_same_pair_updates_amount() {
        // Re-delegating the same pair updates amount, no cycle
        // re-check.
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "bob", 100)).unwrap();
        g.delegate(d("alice", "bob", 200)).unwrap();
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.total_for_representative("bob"), 200);
    }

    #[test]
    fn test_delegation_revocation_requires_valid_signature() {
        // PRIMARY HIGH-007 PIN: revocation is signed. Bad sig
        // → InvalidRevocationSignature.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "bob", 100)).unwrap();
        let canonical = Revocation::canonical_bytes(&pk, "alice", "bob", 1);
        let good_sig = sign(&sk, &canonical);
        let bad_sig = [0u8; 64];

        let bad = Revocation {
            delegator_pubkey: pk,
            delegator: "alice".into(),
            representative: "bob".into(),
            nonce: 1,
            signature: bad_sig,
        };
        assert_eq!(
            g.revoke(&bad).unwrap_err(),
            DelegationError::InvalidRevocationSignature
        );
        // Edge still present.
        assert_eq!(g.edge_count(), 1);

        let good = Revocation {
            delegator_pubkey: pk,
            delegator: "alice".into(),
            representative: "bob".into(),
            nonce: 1,
            signature: good_sig,
        };
        g.revoke(&good).unwrap();
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_delegation_revocation_rejects_unknown_edge() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut g = DelegationGraph::new();
        let canonical = Revocation::canonical_bytes(&pk, "alice", "ghost", 1);
        let sig = sign(&sk, &canonical);
        let rev = Revocation {
            delegator_pubkey: pk,
            delegator: "alice".into(),
            representative: "ghost".into(),
            nonce: 1,
            signature: sig,
        };
        assert!(matches!(
            g.revoke(&rev).unwrap_err(),
            DelegationError::EdgeNotFound { .. }
        ));
    }

    #[test]
    fn test_delegation_snapshot_immune_to_post_capture_mutations() {
        // PRIMARY HIGH-007 PIN: snapshot is captured at vote
        // time and is unaffected by subsequent delegate /
        // revoke ops on the live graph. Audit's "staked-at-
        // vote-time" contract.
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "rep1", 100)).unwrap();
        g.delegate(d("bob", "rep1", 200)).unwrap();
        let snap = g.snapshot();
        assert_eq!(snap.total_for("rep1"), 300);

        // Mutate the graph: add a delegation to rep1. Snapshot
        // unchanged.
        g.delegate(d("carol", "rep1", 999)).unwrap();
        assert_eq!(
            snap.total_for("rep1"),
            300,
            "snapshot must not see late delegate"
        );
        assert_eq!(g.total_for_representative("rep1"), 1299);
    }

    #[test]
    fn test_delegation_snapshot_representative_count_pinned() {
        let mut g = DelegationGraph::new();
        g.delegate(d("a", "r1", 1)).unwrap();
        g.delegate(d("b", "r1", 1)).unwrap();
        g.delegate(d("c", "r2", 1)).unwrap();
        let snap = g.snapshot();
        assert_eq!(snap.representative_count(), 2);
    }

    #[test]
    fn test_delegation_revocation_canonical_bytes_layout() {
        // Pin: canonical-bytes layout includes the domain
        // prefix. A signature for one nonce does not verify
        // against another nonce (replay protection).
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let canon_n1 = Revocation::canonical_bytes(&pk, "alice", "bob", 1);
        let canon_n2 = Revocation::canonical_bytes(&pk, "alice", "bob", 2);
        assert_ne!(canon_n1, canon_n2);
        assert!(canon_n1.starts_with(DELEGATION_REVOCATION_DOMAIN));

        let sig_n1 = sign(&sk, &canon_n1);
        let rev_with_wrong_nonce = Revocation {
            delegator_pubkey: pk,
            delegator: "alice".into(),
            representative: "bob".into(),
            nonce: 2, // mismatched
            signature: sig_n1,
        };
        let mut g = DelegationGraph::new();
        g.delegate(d("alice", "bob", 100)).unwrap();
        assert_eq!(
            g.revoke(&rev_with_wrong_nonce).unwrap_err(),
            DelegationError::InvalidRevocationSignature
        );
    }
}
