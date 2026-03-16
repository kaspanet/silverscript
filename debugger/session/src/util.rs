/// Decodes a txscript script number (little-endian sign-magnitude, max 8 bytes).
/// Mirrors txscript's internal numeric decode logic; kept local because txscript
/// exposes this helper only as crate-private internals today.
pub fn decode_i64(bytes: &[u8]) -> Result<i64, String> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err("numeric value is longer than 8 bytes".to_string());
    }
    let msb = bytes[bytes.len() - 1];
    let sign = 1 - 2 * ((msb >> 7) as i64);
    let first_byte = (msb & 0x7f) as i64;
    let mut value = first_byte;
    for byte in bytes[..bytes.len() - 1].iter().rev() {
        value = (value << 8) + (*byte as i64);
    }
    Ok(value * sign)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = vec![0u8; bytes.len() * 2];
    if faster_hex::hex_encode(bytes, &mut out).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}

pub fn fixed_array_element_size(type_name: &str) -> Option<usize> {
    match type_name {
        "int" => Some(8),
        "bool" => Some(1),
        "byte" => Some(1),
        other => other.strip_prefix("bytes").and_then(|value| value.parse::<usize>().ok()).or_else(|| {
            other.strip_prefix("byte[").and_then(|value| value.strip_suffix(']')).and_then(|value| value.parse::<usize>().ok())
        }),
    }
}
