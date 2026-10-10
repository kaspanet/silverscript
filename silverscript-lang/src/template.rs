pub use silverscript_core::utils::template_hash;

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
