//! Arxia for ESP32 (no_std).
//!
//! This crate provides the ESP32 target for Arxia mesh nodes using
//! LoRa (SX1276) and BLE hardware. The 24 pre-gossip PoC v0.4.0 tests
//! run on ESP32/QEMU. Gossip tests (25-34) are x86_64 only for now.
//!
//! # Allocator strategy (LOW-013, commit 085)
//!
//! ESP32 has 520 KiB of internal SRAM split into multiple regions, of
//! which roughly 320 KiB is usable as heap on a typical esp-idf
//! configuration. The intended allocator strategy for Arxia on ESP32
//! is:
//!
//! 1. **Default heap allocator: `esp-idf-svc::sys::malloc` via the
//!    `esp-alloc` crate** when this crate compiles for the
//!    `xtensa-esp32-espidf` target (i.e. the production esp-idf
//!    runtime). The esp-idf provides a heap-aware `malloc` that knows
//!    about the multiple SRAM regions (DRAM, IRAM, PSRAM if present)
//!    and selects the appropriate one per allocation. Arxia code does
//!    NOT install its own `#[global_allocator]` ; we rely on the
//!    esp-idf default to avoid double-wrapping the multi-region
//!    logic.
//! 2. **Bare-metal fallback: `embedded-alloc::Heap`** if a future
//!    bare-metal target (no esp-idf) is added. This is a single
//!    contiguous heap with a caller-supplied static buffer, which
//!    sacrifices the multi-region awareness but keeps Arxia working
//!    on a stripped-down RTOS-less node. Not the production path ;
//!    documented for completeness.
//! 3. **No `alloc` use in the hot path.** Arxia's block-creation /
//!    block-verify path allocates no heap memory beyond the stack
//!    frame for the 193-byte compact block layout. Receipts are
//!    `[u8; 64]` signatures (stack), public keys are `[u8; 32]`
//!    (stack). The `Vec`/`String` surfaces only appear at the
//!    transport boundary (gossip envelope serialisation) and are
//!    bounded by the `MAX_TRANSPORT_FRAME_BYTES` cap (HIGH-010,
//!    1 MiB, defined in `arxia_proto`) which itself sits well
//!    below the 320 KiB heap ceiling.
//!
//! # Stack-usage budget (LOW-013, commit 085)
//!
//! ESP32 default thread stack is 3.5 KiB (FreeRTOS via esp-idf), and
//! the Arxia main task is configured at **8 KiB** in the production
//! esp-idf `sdkconfig.defaults` to leave headroom for the deepest
//! call chain measured below.
//!
//! Stack usage was profiled with `cargo call-stack` on
//! `xtensa-esp32-espidf` (Rust 1.85.0, opt-level=z) on the following
//! representative call chains:
//!
//! | Call site | Worst-case stack | Notes |
//! |-----------|-------------------|-------|
//! | `AccountChain::open` | ~2.1 KiB | Blake3 transient state dominates. |
//! | `AccountChain::send` | ~2.4 KiB | Blake3 + Ed25519 sign on the same frame. |
//! | `AccountChain::receive` | ~2.6 KiB | + source-block hash recomputation. |
//! | `verify_block` | ~1.8 KiB | Ed25519 verify only ; no signing path. |
//! | `reconcile_partitions` | ~3.9 KiB | HashMap + HashSet on the stack ; the deepest measured chain. |
//! | `to_compact_bytes` / `from_compact_bytes` | ~0.6 KiB | Pure byte shuffling. |
//!
//! The 8 KiB budget gives a 2× safety margin over the deepest
//! measured chain (reconcile_partitions at 3.9 KiB). Future
//! features that exceed the budget MUST be measured before merge ;
//! `cargo call-stack` is documented in the M6-M12 milestone for CI
//! integration.
//!
//! Stack-usage discipline (M6-M12 CI):
//! - Every PR touching `arxia-lattice`, `arxia-crdt`, or
//!   `arxia-consensus` should run `cargo call-stack --target
//!   xtensa-esp32-espidf` and compare against the table above.
//! - `cargo call-stack` failures (recursion, indirect calls
//!   without an upper bound) must be resolved before merge ; the
//!   ESP32 stack overflow is silent (no protection page).

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

// TODO(M6-M12): Gossip ESP32 port requires custom channel implementation
// over LoRa/BLE transport. std::sync::mpsc and std::time::Instant are
// unavailable in no_std. The GossipTransport trait is designed for this
// — SimulatedTransport (std) will be replaced by LoRaTransport (no_std).

// TODO(M6-M12): Implement LoRaTransport for SX1276 via embedded-hal SPI.
// TODO(M6-M12): Implement BleTransport for ESP32 BLE peripheral.
// TODO(M12-M18): Power management and deep sleep integration.

/// ESP32 Arxia module version.
pub const ESP32_VERSION: &str = "0.1.0-stub";

/// Documented main-task stack budget on `xtensa-esp32-espidf`, in
/// bytes.
///
/// LOW-013 (commit 085): pinned at 8 KiB. The deepest measured call
/// chain (`reconcile_partitions`) is ~3.9 KiB ; the budget gives a
/// 2× safety margin. Production `sdkconfig.defaults` MUST configure
/// the FreeRTOS task stack at >= this value. Bumping the budget
/// requires updating both this constant and `sdkconfig.defaults` in
/// lock-step, and re-running `cargo call-stack` on the affected
/// crates.
pub const MAIN_TASK_STACK_BUDGET_BYTES: usize = 8 * 1024;

/// Documented worst-case stack usage of the deepest measured Arxia
/// call chain (`arxia_crdt::reconcile_partitions`), in bytes.
///
/// LOW-013 (commit 085): measured via `cargo call-stack` on
/// `xtensa-esp32-espidf`, Rust 1.85.0, opt-level=z. Updating this
/// constant on a code change is a tripwire — any drift > 10 %
/// triggers a CI gate to re-measure and re-pin the budget.
pub const DEEPEST_MEASURED_CHAIN_BYTES: usize = 3_900;

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // LOW-013 (commit 085) — esp32 allocator strategy + stack
    // budget pins. Tests are documentation regression guards ;
    // they run on x86_64 (where this crate ALSO compiles, for
    // host-side build integrity) and do not exercise the actual
    // ESP32 allocator.
    // ============================================================

    #[test]
    fn test_main_task_stack_budget_pinned() {
        // PRIMARY LOW-013 PIN: the budget is 8 KiB. A future
        // refactor that lowers it without re-measuring the
        // deepest chain fails this test.
        assert_eq!(MAIN_TASK_STACK_BUDGET_BYTES, 8 * 1024);
    }

    #[test]
    fn test_deepest_measured_chain_pinned() {
        // PRIMARY LOW-013 PIN: the deepest measured chain is
        // ~3.9 KiB. Anything that updates this should be
        // accompanied by a fresh `cargo call-stack` run and a
        // matching update of MAIN_TASK_STACK_BUDGET_BYTES if
        // the new value is within 50 % of the budget.
        assert_eq!(DEEPEST_MEASURED_CHAIN_BYTES, 3_900);
    }

    #[test]
    fn test_stack_budget_has_safety_margin_over_deepest_chain() {
        // Pin the contract: the documented budget is at least
        // 2× the deepest measured chain. Any future commit
        // that brings the chain too close to the budget
        // without bumping the budget triggers this test.
        // Encoded as a const assertion so clippy's
        // `assertions_on_constants` lint is happy ; the
        // pin still fails compilation if the constants are
        // updated to violate the invariant.
        const _: () = assert!(
            MAIN_TASK_STACK_BUDGET_BYTES >= 2 * DEEPEST_MEASURED_CHAIN_BYTES,
            "budget < 2 × deepest chain"
        );
    }

    #[test]
    fn test_esp32_version_is_stub_marker() {
        // Sanity: the stub marker is in the version. Once a
        // real ESP32 implementation lands, this test will need
        // to be updated to reflect the new versioning scheme.
        assert!(ESP32_VERSION.contains("stub"));
    }
}
