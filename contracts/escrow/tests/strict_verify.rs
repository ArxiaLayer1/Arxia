//! Regression guards: escrow authorization must reject small-subgroup
//! public keys.
//!
//! For the Curve25519 identity element the verification equation
//! degenerates and R = identity, S = 0 satisfies it for ANY message.
//! Under the lenient `verify` a release or refund could therefore be
//! authorized by anyone, with a 64-byte signature assembled by hand and
//! no private key. `verify_strict` rejects the key at the equation.

use escrow::Escrow;

/// Curve25519 identity element, compressed (y = 1, sign = 0).
fn identity_pk() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 0x01;
    p
}

/// R = identity (compressed), S = 0.
fn degenerate_sig() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 0x01;
    s
}

#[test]
fn release_rejects_identity_recipient_forgery() {
    let pk = identity_pk();
    let mut escrow = Escrow::new(hex::encode([0x11u8; 32]), hex::encode(pk), 1_000_000, 1000);
    assert_eq!(
        escrow.release(&pk, &degenerate_sig()),
        Err("invalid signature"),
        "a low-order recipient key must not authorize a release"
    );
}

#[test]
fn refund_rejects_identity_sender_forgery() {
    let pk = identity_pk();
    let mut escrow = Escrow::new(hex::encode(pk), hex::encode([0x22u8; 32]), 1_000_000, 1000);
    // Timeout elapsed, so only the signature check stands between the
    // caller and the funds.
    assert_eq!(
        escrow.refund(&pk, &degenerate_sig(), 2000),
        Err("invalid signature"),
        "a low-order sender key must not authorize a refund"
    );
}

#[test]
fn production_uses_strict_verification_only() {
    // Source-lint guard: both authorization sites must route through
    // verify_strict. Reverting either to the lenient `verify` reopens
    // the small-subgroup forgery above.
    const SELF: &str = include_str!("../src/lib.rs");
    let production = SELF
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields at least one segment");
    assert_eq!(
        production.matches("verify_strict(").count(),
        2,
        "release and refund must each call verify_strict"
    );
    assert!(
        !production.contains(".verify(&msg"),
        "escrow must not use the lenient verify on an authorization message"
    );
    assert!(
        !production.contains("Verifier"),
        "escrow must not import the lenient Verifier trait"
    );
}
