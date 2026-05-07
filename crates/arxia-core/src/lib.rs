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

    // ============================================================
    // LOW-015 (commit 086) — workspace dependency pinning audit.
    //
    // Every entry in `[workspace.dependencies]` MUST be
    // `major.minor` pinned. No `"*"` wildcards, no floating
    // `git = "..."` deps, no version-less specs.
    // ============================================================

    /// Read the workspace root Cargo.toml (3 levels up from this
    /// file: arxia-core → crates → workspace root).
    const WORKSPACE_CARGO_TOML: &str = include_str!("../../../Cargo.toml");

    #[test]
    fn test_workspace_deps_no_wildcard_version() {
        // PRIMARY LOW-015 PIN: a `"*"` dependency would let
        // cargo pick any version including pre-release
        // breaking changes. Reject the pattern at the
        // text-level. The substring matched is the exact
        // wildcard form, so e.g. `"1.0"` does not match.
        assert!(
            !WORKSPACE_CARGO_TOML.contains("= \"*\""),
            "workspace deps must not use wildcard `*` versions (LOW-015)"
        );
    }

    #[test]
    fn test_workspace_deps_no_floating_git_deps() {
        // PRIMARY LOW-015 PIN: a `git = "..."` dependency
        // pinned only by branch/HEAD bypasses semver entirely
        // and is a supply-chain risk. The workspace deps must
        // all come from crates.io (allowed by deny.toml).
        // Workspace MEMBERS use `path = "..."` which is fine
        // and unrelated.
        let in_workspace_deps = WORKSPACE_CARGO_TOML
            .split("[workspace.dependencies]")
            .nth(1)
            .expect("workspace.dependencies section is present")
            .split("\n[")
            .next()
            .expect("section ends at next [...] header");
        assert!(
            !in_workspace_deps.contains("git ="),
            "workspace.dependencies must not contain git deps (LOW-015)"
        );
    }

    #[test]
    fn test_workspace_critical_deps_have_minor_pin() {
        // The 5 deps that the audit (commit 086) explicitly
        // upgraded from major-only to major.minor must keep
        // the minor pin. Pre-fix: `"1"` ; post-fix: `"1.0"`
        // (or higher minor). A regression that drops the
        // minor breaks this test.
        for (dep_name, must_contain) in &[
            ("ed25519-dalek", "version = \"2.2"),
            ("blake3", "blake3 = \"1.8"),
            ("serde", "version = \"1.0"),
            ("serde_json", "serde_json = \"1.0"),
            ("bincode", "bincode = \"1.3"),
            ("tokio", "version = \"1.44"),
            ("thiserror", "thiserror = \"2.0"),
        ] {
            assert!(
                WORKSPACE_CARGO_TOML.contains(must_contain),
                "workspace dep {dep_name} must be major.minor pinned (looking for `{must_contain}`)"
            );
        }
    }

    #[test]
    fn test_workspace_low015_marker_present() {
        // The audit-acknowledgement comment is part of the
        // documented contract. Removing it (or losing the
        // commit-086 reference) signals a regression.
        assert!(
            WORKSPACE_CARGO_TOML.contains("LOW-015"),
            "workspace Cargo.toml must reference LOW-015 in the deps comment"
        );
    }
}
