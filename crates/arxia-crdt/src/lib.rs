//! CRDTs (Conflict-free Replicated Data Types) and Vector Clocks for Arxia.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod or_set;
pub mod pn_counter;
pub mod pruning;
pub mod reconciliation;
pub mod vector_clock;

pub use or_set::ORSet;
pub use pn_counter::PNCounter;
pub use reconciliation::{
    reconcile_partitions, reconcile_partitions_balances_only, ReconciliationReport,
    RejectedReceive, ResolvedConflict,
};
pub use vector_clock::CrdtVectorClock;
