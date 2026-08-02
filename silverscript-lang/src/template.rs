use blake2b_simd::Params as Blake2bParams;
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

    Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(encoded_prefix_len.as_ref())
        .update(prefix)
        .update(encoded_suffix_len.as_ref())
        .update(suffix)
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::template_hash;

    #[test]
    fn binds_template_part_boundary() {
        assert_ne!(template_hash(b"a", b"bc"), template_hash(b"ab", b"c"));
    }
}
