pub(super) fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub(super) fn is_value_terminator(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b',' | b';' | b'}' | b']' | b')' | b'\'' | b'"' | b'\n' | b'\r' | b'\t'
        )
}

pub(super) fn is_field_name_boundary(bytes: &[u8], start: usize, len: usize) -> bool {
    let before_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
    let after = start + len;
    let after_ok = after >= bytes.len() || !is_identifier_byte(bytes[after]);
    before_ok && after_ok
}

