//! Protocol constants for the Arxia network.

/// Maximum number of entries in a Vector Clock before forced pruning.
pub const MAX_VECTOR_CLOCK_ENTRIES: usize = 256;

/// L0 finality cap in micro-ARX (10 ARX).
pub const L0_CAP_MICRO_ARX: u64 = 10_000_000;

/// L1 finality cap in USD equivalent.
pub const L1_CAP_USD: f64 = 50.0;

/// Compact block serialization size in bytes.
pub const COMPACT_BLOCK_SIZE: usize = 193;

/// LoRa maximum transmission unit in bytes.
pub const LORA_MTU: usize = 256;

/// Minimum delegation threshold as a fraction of total supply (0.1%).
pub const MIN_DELEGATION_FRACTION: f64 = 0.001;

/// Quorum threshold for L2 finality (2/3 of representatives).
pub const QUORUM_FRACTION: f64 = 2.0 / 3.0;

/// Minimum stake fraction for quorum (20%).
pub const MIN_STAKE_FRACTION: f64 = 0.20;

/// Relay scoring window in days.
pub const RELAY_SCORING_WINDOW_DAYS: u64 = 30;

/// Relay penalty threshold (below 85% over 30 days = -10% stake).
pub const RELAY_PENALTY_THRESHOLD: f64 = 0.85;

/// Relay exclusion threshold (below 60% over 7 days = exclusion + -25% stake).
pub const RELAY_EXCLUSION_THRESHOLD: f64 = 0.60;

/// Vector clock pruning age in days.
pub const VC_PRUNING_AGE_DAYS: u64 = 7;

/// One ARX in micro-ARX.
pub const ONE_ARX: u64 = 1_000_000;

/// Total protocol supply in micro-ARX (1,000,000,000 ARX).
///
/// Matches the tokenomics spec in the whitepaper. Used as the hard upper
/// bound on what any single Open block can mint and, in a future commit,
/// as the global supply accumulator ceiling.
pub const TOTAL_SUPPLY_MICRO_ARX: u64 = 1_000_000_000 * ONE_ARX;

/// Maximum `initial_balance` accepted by `AccountChain::open` for
/// a single account, in micro-ARX (100,000,000 ARX = 10% of total supply).
///
/// This is a per-account ceiling applied statelessly at Open-time. A
/// follow-up commit will add a global supply accumulator so that the sum
/// of every live Open cannot exceed [`TOTAL_SUPPLY_MICRO_ARX`] either.
/// Until then, the per-account cap is the first line of defense against
/// unbounded self-mint (TODO Bug 3).
pub const MAX_INITIAL_BALANCE_PER_ACCOUNT: u64 = 100_000_000 * ONE_ARX;
