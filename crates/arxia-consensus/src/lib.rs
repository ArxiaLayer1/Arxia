//! ORV consensus and conflict resolution for the Arxia protocol.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod conflict;
pub mod delegation;
pub mod orv;
pub mod quorum;
pub mod vote;

pub use conflict::{detect_double_spend, resolve_conflict_orv, BlockCandidate};
pub use orv::collect_votes;
pub use quorum::check_quorum;
pub use vote::{cast_vote, compute_vote_hash, verify_vote, verify_vote_known, VoteORV};
