//! DID issuance example.

use arxia_crypto::generate_keypair;
use arxia_did::ArxiaDid;

fn main() {
    println!("=== Arxia DID Issuance Example ===");
    println!();

    for i in 1..=3 {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes());
        println!("Identity {}: {}", i, did);
    }

    println!();
    println!("=== Example complete ===");
}
