//! Arxia full node.
//!
//! # HIGH-027 (commit 087): security-interfaces gating
//!
//! This binary is currently a STUB. The production implementation
//! is gated by `docs/SECURITY_INTERFACES.md` — every subsystem
//! (argv parsing, signal handling, storage init, network bind,
//! consensus boot, logging, privilege drop) must satisfy the
//! requirements listed there before its code lands here.
//!
//! Operators running the stub will see a startup log line
//! pointing to the security-interfaces doc so the gating
//! contract is explicit at runtime.

use tracing::{info, warn};

/// HIGH-027 (commit 087) gate: relative path to the security
/// interfaces doc. Pinned by the structural test below so a
/// future move of the doc surfaces as a CI failure rather than
/// a silent dead-link in the startup banner.
pub const SECURITY_INTERFACES_DOC_PATH: &str = "docs/SECURITY_INTERFACES.md";

fn main() {
    tracing_subscriber::fmt::init();
    info!("Arxia Node v{}", env!("CARGO_PKG_VERSION"));
    warn!(
        "STUB BINARY — production implementation gated by {} \
         (HIGH-027). Do not run in production until each \
         section of that document has a linked test.",
        SECURITY_INTERFACES_DOC_PATH
    );
    info!("Initializing...");
    info!("Node ready (stub - full implementation in M6-M12)");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read the security-interfaces doc via include_str! so a
    /// move/delete surfaces here.
    const SECURITY_INTERFACES_DOC: &str = include_str!("../../../docs/SECURITY_INTERFACES.md");

    // ============================================================
    // HIGH-027 (commit 087) — security-interfaces doc structural
    // pins. The doc is the gating contract for the production
    // implementation ; these tests verify each required section
    // is present and the doc path constant is consistent.
    // ============================================================

    #[test]
    fn test_security_interfaces_doc_path_pinned() {
        // PRIMARY HIGH-027 PIN: the path constant matches the
        // actual file location. Loaded via include_str!, so the
        // file must exist at the path the binary advertises.
        // We compare doc length against a small lower bound
        // rather than `!is_empty()` because the latter is
        // recognised by clippy 1.85 as a constant (the const
        // string is non-empty by construction) and rejected
        // under -D warnings.
        assert_eq!(SECURITY_INTERFACES_DOC_PATH, "docs/SECURITY_INTERFACES.md");
        assert!(SECURITY_INTERFACES_DOC.len() > 100);
    }

    #[test]
    fn test_security_interfaces_doc_has_all_required_sections() {
        // Each subsystem boundary must have a section. A
        // future commit that drops one (or renames it without
        // updating this test) fails immediately.
        let required_sections = [
            "## 1. Argument parsing & configuration loading",
            "## 2. Signal handling & shutdown",
            "## 3. Storage backend initialization",
            "## 4. Network binding & transport listen",
            "## 5. Consensus & finality boot",
            "## 6. Logging, telemetry & secrets hygiene",
            "## 7. Privilege & runtime hardening",
        ];
        for section in &required_sections {
            assert!(
                SECURITY_INTERFACES_DOC.contains(section),
                "SECURITY_INTERFACES.md missing required section: {section}"
            );
        }
    }

    #[test]
    fn test_security_interfaces_doc_references_audit_id() {
        // Pin: HIGH-027 fiche ID is in the doc, so a reader
        // can cross-reference the audit register.
        assert!(SECURITY_INTERFACES_DOC.contains("HIGH-027"));
    }

    #[test]
    fn test_security_interfaces_doc_lists_required_tests() {
        // Each section MUST have a "Tests required" sub-list
        // so the implementation PR knows what to write.
        let test_marker_count = SECURITY_INTERFACES_DOC.matches("**Tests required").count()
            + SECURITY_INTERFACES_DOC
                .matches("Tests required (some")
                .count();
        assert!(
            test_marker_count >= 6,
            "expected >=6 'Tests required' markers (one per main section), got {test_marker_count}"
        );
    }

    #[test]
    fn test_security_interfaces_doc_pins_stub_disclaimer() {
        // The doc MUST tell a reader the stub binary
        // references it. This is the runtime ↔ doc bridge.
        assert!(
            SECURITY_INTERFACES_DOC.contains("stub") || SECURITY_INTERFACES_DOC.contains("STUB"),
            "doc must explain the stub-binary gating contract"
        );
    }
}
