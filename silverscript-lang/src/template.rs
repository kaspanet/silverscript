use blake3::Hasher as Blake3Hasher;
use kaspa_txscript::serialize_i64;

const TEMPLATE_PART_LENGTH_BYTES: usize = 8;

/// Calculate the canonical hash of a state-bearing contract template.
///
/// The fixed-width part lengths bind the boundary where serialized state is
/// inserted between the template prefix and suffix.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let prefix_len = i64::try_from(prefix.len()).unwrap();
    let suffix_len = i64::try_from(suffix.len()).unwrap();
    let encoded_prefix_len = serialize_i64(prefix_len, Some(TEMPLATE_PART_LENGTH_BYTES)).unwrap();
    let encoded_suffix_len = serialize_i64(suffix_len, Some(TEMPLATE_PART_LENGTH_BYTES)).unwrap();

    Blake3Hasher::new().update(&encoded_prefix_len).update(prefix).update(&encoded_suffix_len).update(suffix).finalize().into()
}

#[cfg(test)]
mod tests {
    use super::template_hash;
    use faster_hex::hex_string;

    #[test]
    fn binds_template_part_boundary() {
        assert_ne!(template_hash(b"a", b"bc"), template_hash(b"ab", b"c"));
    }

    #[test]
    fn golden_empty_parts() {
        assert_eq!(hex_string(&template_hash(&[], &[])), "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e");
    }

    #[test]
    fn golden_classic() {
        assert_eq!(
            hex_string(&template_hash(b"\x00\xff", b"\x10\x00\x80")),
            "6616a66757315de0221cb2acba729113cebde31f8d3ca7fa93878a0584b96905"
        );
    }
}
