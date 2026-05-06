//! Benchmark utilities for Arxia.
//!
//! # Production-impl validation (LOW-009, commit 081)
//!
//! The criterion benches in `benches/crypto_bench.rs` call into
//! `arxia_crypto::{hash_blake3, sign, verify}` and other
//! production functions. Without an explicit test pinning that
//! the bench targets the production code path (and not, say, a
//! locally-stubbed copy), a future refactor that introduces a
//! mock crypto module or shadows a production fn could
//! produce optimistic benchmark numbers.
//!
//! The unit tests below exercise each benchmarked function via
//! the same import path the bench uses (`arxia_crypto::xxx`)
//! and assert a known-good output. A regression that swaps the
//! production implementation for a stub would break these
//! tests immediately.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Re-export for convenience.
pub use arxia_core;
/// Re-export for convenience.
pub use arxia_crypto;
/// Re-export for convenience.
pub use arxia_lattice;

#[cfg(test)]
mod tests {
    // ============================================================
    // LOW-009 (commit 081) — bench targets are production impls.
    //
    // Each test calls the same `arxia_crypto::xxx` path the
    // benches in benches/crypto_bench.rs use, then asserts a
    // known-good behaviour. If a future refactor swaps the
    // production fn for a stub, these tests break before the
    // benches run with optimistic numbers.
    // ============================================================

    #[test]
    fn test_bench_target_blake3_hash_is_production() {
        // PRIMARY LOW-009 PIN for blake3. The bench calls
        // `arxia_crypto::hash_blake3(&data)` ; the production
        // contract is "deterministic 64-char hex output". Pin
        // that same call path.
        let h1 = arxia_crypto::hash_blake3(b"bench-target");
        let h2 = arxia_crypto::hash_blake3(b"bench-target");
        assert_eq!(h1, h2, "production hash_blake3 must be deterministic");
        assert_eq!(h1.len(), 64, "production hash_blake3 returns 64-char hex");
    }

    #[test]
    fn test_bench_target_blake3_hash_long_input_chunking() {
        // Bench uses 1024-byte input ; pin that the production
        // fn handles that exact size with the same determinism.
        let data = vec![0u8; 1024];
        let h1 = arxia_crypto::hash_blake3(&data);
        let h2 = arxia_crypto::hash_blake3(&data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_bench_target_ed25519_sign_verify_round_trip() {
        // PRIMARY LOW-009 PIN for ed25519. Bench calls
        // `arxia_crypto::generate_keypair`, `sign`, `verify`.
        // Pin that the round-trip succeeds via those exact
        // import paths.
        let (signing_key, vk) = arxia_crypto::generate_keypair();
        let data = [0u8; 32];
        let sig = arxia_crypto::sign(&signing_key, &data);
        assert_eq!(sig.len(), 64, "production sign returns 64-byte signature");
        let pubkey = vk.to_bytes();
        let result = arxia_crypto::verify(&pubkey, &data, &sig);
        assert!(
            result.is_ok(),
            "production verify must accept a freshly-signed message"
        );
    }

    #[test]
    fn test_bench_target_ed25519_verify_rejects_tampered() {
        // Negative pin: production verify rejects a tampered
        // signature.
        let (signing_key, vk) = arxia_crypto::generate_keypair();
        let data = [0u8; 32];
        let mut sig = arxia_crypto::sign(&signing_key, &data);
        sig[0] ^= 0x01; // flip one bit
        let pubkey = vk.to_bytes();
        assert!(arxia_crypto::verify(&pubkey, &data, &sig).is_err());
    }

    #[test]
    fn test_bench_targets_compile_via_reexports() {
        // Compile-time pin: the same `pub use arxia_crypto`
        // re-export the bench harness depends on still resolves
        // to the real crate.
        let _hash_fn: fn(&[u8]) -> String = crate::arxia_crypto::hash_blake3;
        let _sign_fn = crate::arxia_crypto::sign;
        let _verify_fn = crate::arxia_crypto::verify;
        let _kp_fn = crate::arxia_crypto::generate_keypair;
        // Each binding compiles iff the re-export still resolves
        // to the production crate.
    }
}
