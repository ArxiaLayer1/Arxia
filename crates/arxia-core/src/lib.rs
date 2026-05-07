//! Core types, constants, and error handling for the Arxia protocol.
//!
//! This crate provides the foundational types shared across all Arxia crates:
//! `AccountId`, `Amount`, `Nonce`, `BlockHash`, `SignatureBytes`, and the
//! unified `ArxiaError` enum.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod constants;
pub mod error;
pub mod types;

pub use constants::*;
pub use error::ArxiaError;
pub use types::*;

// ============================================================
// LOW-014 (commit 084) — workspace deny.toml / clippy.toml
// pinned policies. The structural tests below read the
// workspace-level config files via `include_str!` and assert
// the audit-acknowledged baseline. Any future weakening of
// these policies (e.g. allowing GPL or wildcard versions)
// surfaces as a test failure here, not as a silent config
// drift.
// ============================================================
#[cfg(test)]
mod cfg_pin_tests {
    /// Read deny.toml from the workspace root via relative path.
    const DENY_TOML: &str = include_str!("../../../deny.toml");
    /// Read clippy.toml from the workspace root.
    const CLIPPY_TOML: &str = include_str!("../../../clippy.toml");

    #[test]
    fn test_deny_toml_pins_vulnerability_deny() {
        // PRIMARY LOW-014 PIN for deny.toml: the advisories
        // policy rejects any dependency with a known RUSTSEC
        // vulnerability.
        assert!(
            DENY_TOML.contains("vulnerability = \"deny\""),
            "deny.toml must keep `vulnerability = \"deny\"` (LOW-014)"
        );
    }

    #[test]
    fn test_deny_toml_pins_unlicensed_deny_and_copyleft_deny() {
        assert!(
            DENY_TOML.contains("unlicensed = \"deny\""),
            "deny.toml must reject unlicensed deps"
        );
        assert!(
            DENY_TOML.contains("copyleft = \"deny\""),
            "deny.toml must reject copyleft licenses (Arxia is dual-licensed Apache-2.0 / MIT)"
        );
    }

    #[test]
    fn test_deny_toml_pins_wildcards_deny() {
        assert!(
            DENY_TOML.contains("wildcards = \"deny\""),
            "deny.toml must reject wildcard version requirements"
        );
    }

    #[test]
    fn test_deny_toml_pins_unknown_registry_and_git_deny() {
        assert!(DENY_TOML.contains("unknown-registry = \"deny\""));
        assert!(DENY_TOML.contains("unknown-git = \"deny\""));
        assert!(
            DENY_TOML.contains("crates.io-index"),
            "deny.toml must allow crates.io as the only registry"
        );
    }

    #[test]
    fn test_clippy_toml_pins_msrv() {
        // PRIMARY LOW-014 PIN for clippy.toml.
        assert!(
            CLIPPY_TOML.contains("msrv = \"1.85.0\""),
            "clippy.toml must pin MSRV at 1.85.0 (LOW-014, ESP32 toolchain alignment)"
        );
    }

    #[test]
    fn test_deny_toml_allows_required_licenses() {
        // The 9 audit-approved licenses must remain in the
        // allow list. A regression that removes one would
        // break a downstream dep build.
        for required in &[
            "\"MIT\"",
            "\"Apache-2.0\"",
            "\"BSD-2-Clause\"",
            "\"BSD-3-Clause\"",
            "\"ISC\"",
            "\"Unicode-3.0\"",
            "\"CC0-1.0\"",
            "\"Zlib\"",
            "\"BSL-1.0\"",
        ] {
            assert!(
                DENY_TOML.contains(required),
                "deny.toml must allow license {required} (LOW-014)"
            );
        }
    }
}
