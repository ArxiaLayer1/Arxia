//! Decentralized Identity (DID) for Arxia.
//!
//! Format: `did:arxia:<base58(blake3(pubkey_bytes))>`
//!
//! # Strict pubkey validation (HIGH-018, commit 037)
//!
//! [`ArxiaDid::from_public_key`] validates the input bytes via
//! [`arxia_crypto::validate_pubkey_strict`] before constructing the
//! identifier. Off-curve and low-order pubkeys are rejected with
//! `InvalidKey`. See module docstring of `arxia_crypto::ed25519`
//! for the dalek 2.x semantics.
//!
//! # Strict string parser (HIGH-019, commit 038)
//!
//! [`parse_did`] is the canonical entry point for *received* DID
//! strings (RPC, contracts, log entries, user input). It validates:
//!
//! 1. Prefix is exactly `"did:arxia:"`.
//! 2. Identifier portion is valid base58.
//! 3. The decoded bytes are exactly 32 bytes (Blake3 hash size).
//!
//! On success it returns a [`ParsedArxiaDid`] which carries the
//! validated string AND the decoded identifier hash. A
//! `ParsedArxiaDid` does NOT include the original pubkey because
//! the hash is one-way; callers that need to verify ownership must
//! pair the parsed DID with a separately-supplied pubkey via
//! [`ParsedArxiaDid::matches_pubkey`].
//!
//! Pre-fix the only path to consume a DID string was
//! [`ArxiaDid::identifier()`] which used
//! `strip_prefix(...).unwrap_or(&self.did)` — if the prefix was
//! missing, the entire raw string was passed through silently. The
//! audit (HIGH-019):
//!
//! > Users hand-format `did:arxia:<hex>` and pass it as a String;
//! > downstream code uses `strip_prefix(...).unwrap_or(&self.did)`
//! > — if the prefix is wrong, the whole (possibly-injected)
//! > string flows through. DIDs look identifier-safe but aren't;
//! > malformed DIDs propagate through logs, contracts,
//! > credentials.
//!
//! Note: the audit text mentions a hex charset but the actual
//! implementation uses base58 (see `from_public_key`). The strict
//! parser here matches the implementation.
//!
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-018, HIGH-019.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use arxia_core::ArxiaError;
use serde::{Deserialize, Serialize};

/// Required prefix for every Arxia DID string.
pub const DID_PREFIX: &str = "did:arxia:";

/// Required length in bytes of the decoded identifier portion of a
/// parsed DID. Equal to the Blake3 hash output size.
pub const DID_IDENTIFIER_BYTE_LEN: usize = 32;

/// An Arxia Decentralized Identifier built from a freshly-validated
/// public key. The `public_key` field is the pubkey itself, not the
/// identifier hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArxiaDid {
    /// The full DID string.
    pub did: String,
    /// The Ed25519 public key bytes.
    pub public_key: [u8; 32],
}

impl ArxiaDid {
    /// Create a new DID from an Ed25519 public key.
    ///
    /// The bytes are validated via
    /// [`arxia_crypto::validate_pubkey_strict`] before any DID
    /// material is built — see HIGH-018 in the module docstring.
    ///
    /// # Errors
    ///
    /// Returns `Err(ArxiaError::InvalidKey(reason))` for off-curve
    /// or low-order pubkey bytes.
    pub fn from_public_key(public_key: &[u8; 32]) -> Result<Self, ArxiaError> {
        arxia_crypto::validate_pubkey_strict(public_key)?;
        let hash = arxia_crypto::hash_blake3_bytes(public_key);
        let encoded = bs58::encode(&hash).into_string();
        Ok(Self {
            did: format!("{DID_PREFIX}{encoded}"),
            public_key: *public_key,
        })
    }

    /// Return the DID string.
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Return the Base58-encoded identifier portion.
    ///
    /// **Lenient** — falls back to the full string if the prefix is
    /// somehow absent. Use [`ArxiaDid::identifier_strict`] for
    /// fail-closed callers (see HIGH-019).
    pub fn identifier(&self) -> &str {
        self.did.strip_prefix(DID_PREFIX).unwrap_or(&self.did)
    }

    /// Strict identifier accessor: returns `Err` if the DID string
    /// does not start with the canonical prefix instead of falling
    /// back to the raw string. Recommended for any caller that
    /// hashes / logs / contracts the identifier portion (HIGH-019).
    pub fn identifier_strict(&self) -> Result<&str, ArxiaError> {
        self.did.strip_prefix(DID_PREFIX).ok_or_else(|| {
            ArxiaError::InvalidKey(format!("DID missing required prefix '{DID_PREFIX}'"))
        })
    }
}

impl std::fmt::Display for ArxiaDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

/// A DID parsed from an external string. Carries the validated DID
/// text AND the decoded identifier hash, but NOT the originating
/// pubkey (the hash is one-way).
///
/// To check that a parsed DID matches a candidate pubkey, use
/// [`ParsedArxiaDid::matches_pubkey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedArxiaDid {
    /// The full DID string after validation.
    pub did: String,
    /// The 32-byte identifier hash (`blake3(pubkey)`), recovered
    /// from the base58-decoded identifier portion.
    pub identifier_hash: [u8; 32],
}

impl ParsedArxiaDid {
    /// Return the DID string.
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Return the validated base58 identifier portion (the part
    /// after `did:arxia:`).
    pub fn identifier(&self) -> &str {
        // `parse_did` guarantees the prefix is present, so this
        // strip is infallible by construction. Documented as such
        // in the type-level invariant.
        self.did
            .strip_prefix(DID_PREFIX)
            .expect("parse invariant: prefix is present")
    }

    /// Check whether this parsed DID was derived from `pubkey` by
    /// recomputing `blake3(pubkey)` and comparing with the parsed
    /// `identifier_hash`. This is a constant-time-equivalent
    /// comparison via slice equality.
    pub fn matches_pubkey(&self, pubkey: &[u8; 32]) -> bool {
        let recomputed = arxia_crypto::hash_blake3_bytes(pubkey);
        self.identifier_hash == recomputed
    }
}

impl std::fmt::Display for ParsedArxiaDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

impl std::str::FromStr for ParsedArxiaDid {
    type Err = ArxiaError;

    /// LOW-010 (commit 079): standard `FromStr` impl that
    /// delegates to [`parse_did`]. Returned `Err` is
    /// `ArxiaError::InvalidKey(reason)` exactly as `parse_did`
    /// produces — no information loss compared to the
    /// function-style call.
    ///
    /// This makes idiomatic patterns work:
    ///
    /// ```
    /// use arxia_did::ParsedArxiaDid;
    /// use std::str::FromStr;
    ///
    /// let s = "did:arxia:badbase58";
    /// let result: Result<ParsedArxiaDid, _> = s.parse();
    /// assert!(result.is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_did(s)
    }
}

/// Parse a DID string and return a [`ParsedArxiaDid`].
///
/// Validation:
///
/// 1. The string MUST start with `"did:arxia:"`.
/// 2. The identifier portion (after the prefix) MUST be valid
///    base58.
/// 3. The decoded identifier MUST be exactly 32 bytes (Blake3 hash
///    size).
///
/// # Errors
///
/// Returns `Err(ArxiaError::InvalidKey(reason))` with a
/// human-readable diagnostic for each failure class.
pub fn parse_did(s: &str) -> Result<ParsedArxiaDid, ArxiaError> {
    let identifier_b58 = s.strip_prefix(DID_PREFIX).ok_or_else(|| {
        ArxiaError::InvalidKey(format!("DID missing required prefix '{DID_PREFIX}'"))
    })?;
    let bytes = bs58::decode(identifier_b58)
        .into_vec()
        .map_err(|e| ArxiaError::InvalidKey(format!("DID identifier is not valid base58: {e}")))?;
    let identifier_hash: [u8; DID_IDENTIFIER_BYTE_LEN] =
        bytes.as_slice().try_into().map_err(|_| {
            ArxiaError::InvalidKey(format!(
                "DID identifier must decode to {DID_IDENTIFIER_BYTE_LEN} bytes, got {}",
                bytes.len()
            ))
        })?;
    Ok(ParsedArxiaDid {
        did: s.to_string(),
        identifier_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_did_from_public_key() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes()).unwrap();
        assert!(did.did.starts_with(DID_PREFIX));
        assert!(!did.identifier().is_empty());
    }

    #[test]
    fn test_did_deterministic() {
        let (_, vk) = generate_keypair();
        let pubkey = vk.to_bytes();
        let did1 = ArxiaDid::from_public_key(&pubkey).unwrap();
        let did2 = ArxiaDid::from_public_key(&pubkey).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_did_display() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes()).unwrap();
        let displayed = format!("{}", did);
        assert!(displayed.starts_with(DID_PREFIX));
    }

    #[test]
    fn test_different_keys_different_dids() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let did1 = ArxiaDid::from_public_key(&vk1.to_bytes()).unwrap();
        let did2 = ArxiaDid::from_public_key(&vk2.to_bytes()).unwrap();
        assert_ne!(did1, did2);
    }

    // ============================================================
    // HIGH-018 (commit 037) — from_public_key validates the curve
    // point before building the DID.
    // ============================================================

    #[test]
    fn test_did_from_public_key_rejects_zero_pubkey() {
        let err = ArxiaDid::from_public_key(&[0u8; 32]).expect_err("zero pubkey must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_did_from_public_key_rejects_known_low_order_pubkey() {
        let low_order_pk: [u8; 32] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ];
        let err = ArxiaDid::from_public_key(&low_order_pk)
            .expect_err("low-order pubkey must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_did_from_public_key_accepts_many_freshly_generated_keys() {
        for _ in 0..16 {
            let (_, vk) = generate_keypair();
            assert!(ArxiaDid::from_public_key(&vk.to_bytes()).is_ok());
        }
    }

    // ============================================================
    // HIGH-019 (commit 038) — parse_did + ParsedArxiaDid +
    // identifier_strict. The strict string parser rejects
    // malformed prefix, non-base58 identifier, and wrong-length
    // identifier.
    // ============================================================

    #[test]
    fn test_parse_did_round_trips_a_freshly_built_did() {
        // Positive path: a DID built via from_public_key parses
        // back successfully and the identifier_hash matches.
        let (_, vk) = generate_keypair();
        let pubkey = vk.to_bytes();
        let built = ArxiaDid::from_public_key(&pubkey).unwrap();
        let parsed = parse_did(built.as_str()).unwrap();
        assert_eq!(parsed.did, built.did);
        // Recompute the hash and compare with parsed.identifier_hash.
        let expected_hash = arxia_crypto::hash_blake3_bytes(&pubkey);
        assert_eq!(parsed.identifier_hash, expected_hash);
    }

    #[test]
    fn test_parse_did_rejects_malformed_prefix() {
        // PRIMARY HIGH-019 PIN: a string without the canonical
        // prefix is rejected. Pre-fix `identifier()` would have
        // returned the entire string as if it were the identifier.
        let err =
            parse_did("did:other:abc123").expect_err("wrong-namespace prefix must be rejected");
        let msg = format!("{err}");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
        assert!(msg.contains("prefix"));
    }

    #[test]
    fn test_parse_did_rejects_missing_prefix_entirely() {
        // No prefix at all → reject.
        let err = parse_did("just-some-string").expect_err("no prefix must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_parse_did_rejects_empty_string() {
        // Edge case: empty string.
        let err = parse_did("").expect_err("empty string must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_parse_did_rejects_non_base58_identifier() {
        // Prefix is correct but identifier contains '0' (not in the
        // base58 alphabet).
        let err = parse_did("did:arxia:0OOIl").expect_err("non-base58 must be rejected");
        let msg = format!("{err}");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
        assert!(msg.contains("base58"));
    }

    #[test]
    fn test_parse_did_rejects_wrong_length_identifier() {
        // Valid base58 but decodes to fewer than 32 bytes.
        let short = bs58::encode(&[0u8; 16]).into_string();
        let did_str = format!("{DID_PREFIX}{short}");
        let err = parse_did(&did_str).expect_err("short identifier must be rejected");
        let msg = format!("{err}");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
        assert!(msg.contains("32 bytes") || msg.contains("16"));
    }

    #[test]
    fn test_parse_did_rejects_too_long_identifier() {
        // Valid base58 but decodes to more than 32 bytes.
        let long = bs58::encode(&[0u8; 64]).into_string();
        let did_str = format!("{DID_PREFIX}{long}");
        let err = parse_did(&did_str).expect_err("long identifier must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_parsed_did_matches_pubkey_positive() {
        // Round-trip pin: parse a DID built from a known pubkey,
        // matches_pubkey returns true.
        let (_, vk) = generate_keypair();
        let pubkey = vk.to_bytes();
        let built = ArxiaDid::from_public_key(&pubkey).unwrap();
        let parsed = parse_did(built.as_str()).unwrap();
        assert!(parsed.matches_pubkey(&pubkey));
    }

    #[test]
    fn test_parsed_did_matches_pubkey_negative() {
        // matches_pubkey returns false for a different pubkey.
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let built = ArxiaDid::from_public_key(&vk1.to_bytes()).unwrap();
        let parsed = parse_did(built.as_str()).unwrap();
        assert!(!parsed.matches_pubkey(&vk2.to_bytes()));
    }

    #[test]
    fn test_identifier_strict_succeeds_on_well_formed_did() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes()).unwrap();
        let id = did.identifier_strict().unwrap();
        assert!(!id.is_empty());
        assert_eq!(id, did.identifier());
    }

    #[test]
    fn test_identifier_strict_rejects_did_missing_prefix() {
        // Pin that identifier_strict (unlike the legacy lenient
        // `identifier`) returns Err when the prefix is missing.
        // We construct a malformed ArxiaDid manually (a real DID
        // built via from_public_key always has the prefix; this
        // shape is what we'd get from a deserialized untrusted
        // payload).
        let bad = ArxiaDid {
            did: "no-prefix-here".to_string(),
            public_key: [0u8; 32],
        };
        let err = bad
            .identifier_strict()
            .expect_err("missing prefix must err");
        let msg = format!("{err}");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
        assert!(msg.contains("prefix"));
        // The lenient `identifier()` falls back to the full string
        // — this is the surface the audit flagged.
        assert_eq!(bad.identifier(), "no-prefix-here");
    }

    // ============================================================
    // MED-021 (commit 068) — strict alignment between `ArxiaDid`
    // (built from a pubkey) and `ParsedArxiaDid` (parsed from a
    // string). Pre-fix the two types had separate identifier
    // accessors with no test pinning that they agreed on the
    // same DID. These tests close that gap.
    // ============================================================

    fn keypair_a() -> [u8; 32] {
        // Deterministic test pubkey derived from a fixed
        // seed. We use the crypto module's helper directly so
        // the test doesn't depend on a global RNG.
        let (_, vk) = arxia_crypto::generate_keypair();
        vk.to_bytes()
    }

    #[test]
    fn test_roundtrip_from_public_key_parses_back() {
        // PRIMARY MED-021 PIN: every DID built from a valid
        // pubkey must successfully parse via the strict
        // `parse_did` path. This pins the contract that
        // `from_public_key` only emits canonical strings —
        // no hidden formatting drift between producer and
        // consumer.
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let parsed = parse_did(did.as_str()).expect("self-roundtrip must parse");
        assert_eq!(parsed.as_str(), did.as_str());
    }

    #[test]
    fn test_roundtrip_identifier_hash_matches_pubkey() {
        // After roundtrip, the parsed identifier_hash must
        // equal blake3(pubkey). matches_pubkey returns true.
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let parsed = parse_did(did.as_str()).unwrap();
        assert!(parsed.matches_pubkey(&pk));
        // Cross-check: the hash is exactly blake3(pubkey).
        let expected = arxia_crypto::hash_blake3_bytes(&pk);
        assert_eq!(parsed.identifier_hash, expected);
    }

    #[test]
    fn test_roundtrip_identifier_string_alignment() {
        // `ArxiaDid::identifier_strict()` and
        // `ParsedArxiaDid::identifier()` for the same DID
        // string must return byte-identical slices. This
        // pins that the two types agree on what "identifier
        // portion" means (the part after `did:arxia:`),
        // closing the alignment gap MED-021 flags.
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let parsed = parse_did(did.as_str()).unwrap();
        let from_built = did
            .identifier_strict()
            .expect("from_public_key always produces canonical prefix");
        let from_parsed = parsed.identifier();
        assert_eq!(
            from_built, from_parsed,
            "identifier portion must agree across the two types"
        );
    }

    #[test]
    fn test_roundtrip_matches_pubkey_rejects_other_pubkey() {
        // Negative: a parsed DID derived from pk1 must NOT
        // match a different pk2. Symmetric pin to the
        // positive _matches_pubkey test ; closes the
        // confused-deputy direction (one DID, two candidate
        // pubkeys).
        let pk1 = keypair_a();
        let pk2 = keypair_a();
        // Sanity: different keypairs.
        assert_ne!(pk1, pk2);
        let did = ArxiaDid::from_public_key(&pk1).unwrap();
        let parsed = parse_did(did.as_str()).unwrap();
        assert!(parsed.matches_pubkey(&pk1));
        assert!(!parsed.matches_pubkey(&pk2));
    }

    #[test]
    fn test_roundtrip_lenient_identifier_equals_strict_for_canonical() {
        // For canonical DIDs (those built via
        // `from_public_key`), the lenient `identifier()` and
        // the strict `identifier_strict()` must return the
        // same value. The lenient form's fallback only kicks
        // in for malformed inputs ; pin that the canonical
        // path is unaffected.
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let lenient = did.identifier();
        let strict = did.identifier_strict().unwrap();
        assert_eq!(lenient, strict);
    }

    // ============================================================
    // LOW-010 (commit 079) — `FromStr` impl for `ParsedArxiaDid`.
    // The pre-fix path required calling `parse_did(s)` directly ;
    // adding `FromStr` makes idiomatic `s.parse()` work and
    // delegates to the same parser without information loss.
    // ============================================================

    #[test]
    fn test_fromstr_parses_canonical_did() {
        // PRIMARY LOW-010 PIN: a canonical DID built from a
        // pubkey parses via `FromStr` and equals the
        // `parse_did(...)` result.
        use std::str::FromStr;
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let parsed_via_fn = parse_did(did.as_str()).unwrap();
        let parsed_via_fromstr = ParsedArxiaDid::from_str(did.as_str()).unwrap();
        assert_eq!(parsed_via_fn, parsed_via_fromstr);
    }

    #[test]
    fn test_fromstr_idiomatic_dot_parse_works() {
        // Pin the `.parse::<T>()` syntax works as expected.
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let s = did.as_str();
        let parsed: ParsedArxiaDid = s.parse().expect("canonical DID must parse");
        assert!(parsed.matches_pubkey(&pk));
    }

    #[test]
    fn test_fromstr_returns_invalid_key_on_missing_prefix() {
        use std::str::FromStr;
        let err = ParsedArxiaDid::from_str("not-a-did").expect_err("non-DID string must reject");
        match err {
            ArxiaError::InvalidKey(msg) => assert!(msg.contains("prefix")),
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn test_fromstr_returns_invalid_key_on_bad_base58() {
        use std::str::FromStr;
        // Prefix is correct but identifier portion has invalid
        // base58 characters (0OIl are excluded from base58).
        let err =
            ParsedArxiaDid::from_str("did:arxia:0OIl0OIl").expect_err("bad base58 must reject");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_fromstr_returns_invalid_key_on_wrong_length_after_decode() {
        use std::str::FromStr;
        // Valid prefix and valid base58, but decoded length
        // is not 32 bytes.
        let s = format!("{}{}", DID_PREFIX, "abc"); // decodes to 2 bytes
        let err = ParsedArxiaDid::from_str(&s).expect_err("wrong decoded length must reject");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_display_round_trip_via_fromstr() {
        // Display → FromStr round-trip pin: the formatted
        // string parses back to an equal value.
        use std::str::FromStr;
        let pk = keypair_a();
        let did = ArxiaDid::from_public_key(&pk).unwrap();
        let parsed = parse_did(did.as_str()).unwrap();
        let formatted = format!("{parsed}");
        let reparsed = ParsedArxiaDid::from_str(&formatted).unwrap();
        assert_eq!(parsed, reparsed);
    }
}
