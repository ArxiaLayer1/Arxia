//! DID issuance example.

use arxia_crypto::generate_keypair;
use arxia_did::ArxiaDid;

fn main() {
    println!("=== Arxia DID Issuance Example ===");
    println!();

    for i in 1..=3 {
        let (_, vk) = generate_keypair();
        // generate_keypair always emits a valid Ed25519 pubkey, so
        // from_public_key returns Ok in practice. Unwrap is safe and
        // expressive here (a panic would indicate a dalek regression).
        let did = ArxiaDid::from_public_key(&vk.to_bytes())
            .expect("generate_keypair output must validate");
        println!("Identity {}: {}", i, did);
    }

    println!();
    println!("=== Example complete ===");
}
