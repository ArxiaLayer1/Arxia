//! Blake3 hashing utilities.

/// Compute Blake3 hash and return the hex-encoded string.
pub fn hash_blake3(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Compute Blake3 hash and return raw 32-byte array.
pub fn hash_blake3_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash_deterministic() {
        let a = hash_blake3(b"hello");
        let b = hash_blake3(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_blake3_hash_different_inputs() {
        let a = hash_blake3(b"hello");
        let b = hash_blake3(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn test_blake3_hex_length() {
        let h = hash_blake3(b"test");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_blake3_bytes_length() {
        let h = hash_blake3_bytes(b"test");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_blake3_hex_and_bytes_consistent() {
        let data = b"consistency check";
        let hex_str = hash_blake3(data);
        let bytes = hash_blake3_bytes(data);
        assert_eq!(hex::encode(bytes), hex_str);
    }

    // ============================================================
    // LOW-003 (commit 074) — Blake3 edge inputs.
    //
    // The pre-fix suite covered "hello" / "world" / "test" /
    // "consistency check" (4 short, ASCII, non-empty inputs).
    // Three classes of edge input were not exercised:
    // - empty input
    // - very long input (≥ 1 MiB, exercising Blake3's
    //   internal chunking)
    // - all-zero input (a byte pattern that some hash
    //   implementations have historically miscompiled)
    // ============================================================

    #[test]
    fn test_blake3_empty_input_known_vector() {
        // PRIMARY LOW-003 PIN: Blake3 of empty input is a
        // well-defined hash. The official Blake3 test vector
        // for the empty string is:
        //   af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        // Pin this exactly. A future implementation drift
        // (e.g. accidentally emitting the all-zero output for
        // empty input) fails this test immediately.
        let hex = hash_blake3(&[]);
        assert_eq!(
            hex, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "Blake3 of empty input must match the official test vector"
        );
        let bytes = hash_blake3_bytes(&[]);
        assert_eq!(bytes.len(), 32);
        assert_eq!(hex::encode(bytes), hex);
    }

    #[test]
    fn test_blake3_empty_input_distinct_from_zero_input() {
        // Edge: empty input and a single zero byte produce
        // distinct hashes. Pre-image distinguishability pin.
        let empty = hash_blake3_bytes(&[]);
        let zero_byte = hash_blake3_bytes(&[0u8]);
        assert_ne!(empty, zero_byte);
    }

    #[test]
    fn test_blake3_all_zero_input_distinct_from_short_inputs() {
        // Edge: an all-zero 1024-byte input must produce a
        // hash distinct from short non-zero inputs and from
        // empty input.
        let zeros = vec![0u8; 1024];
        let h_zeros = hash_blake3_bytes(&zeros);
        let h_empty = hash_blake3_bytes(&[]);
        let h_hello = hash_blake3_bytes(b"hello");
        assert_ne!(h_zeros, h_empty);
        assert_ne!(h_zeros, h_hello);
        assert_eq!(h_zeros.len(), 32);
    }

    #[test]
    fn test_blake3_all_zero_inputs_of_different_lengths_differ() {
        // Sanity: zeros of length 100 and zeros of length 200
        // produce different hashes. Length is part of the
        // pre-image (Blake3 is a length-preserving function),
        // not a bug.
        let h100 = hash_blake3_bytes(&[0u8; 100]);
        let h200 = hash_blake3_bytes(&[0u8; 200]);
        assert_ne!(h100, h200);
    }

    #[test]
    fn test_blake3_long_input_1_mib_no_panic_no_truncation() {
        // Edge: 1 MiB of input. Exercises Blake3's internal
        // chunking (default chunk size 1 KiB). No panic ;
        // output is still 32 bytes.
        let long = vec![0xAAu8; 1024 * 1024];
        let h = hash_blake3_bytes(&long);
        assert_eq!(h.len(), 32);
        // And the hash is determined by the input pattern.
        let h2 = hash_blake3_bytes(&long);
        assert_eq!(h, h2);
    }

    #[test]
    fn test_blake3_one_byte_diff_avalanches() {
        // Sanity: Blake3 has the avalanche property — flipping
        // one bit of the input changes ~half the output bits.
        // We can't measure exact bit-flip count here without
        // depending on Blake3's internals, but we can pin
        // that the outputs are *unequal*.
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        b[0] = 1; // flip the lowest bit of the first byte
        let ha = hash_blake3_bytes(&a);
        let hb = hash_blake3_bytes(&b);
        assert_ne!(ha, hb);
        // Flip the LAST byte to confirm position-independence
        // of the property.
        a[255] = 0xFF;
        let ha2 = hash_blake3_bytes(&a);
        assert_ne!(ha, ha2);
    }
}
