use super::{has_disallowed_protocol_chars, normalize_protocol_field};

pub(super) fn normalize_protocol_input(value: Option<&str>) -> Option<String> {
    let normalized = normalize_protocol_field(value)?;
    if has_disallowed_protocol_chars(&normalized) || normalized.len() > 128 {
        return None;
    }
    Some(normalized)
}

pub(super) fn build_protocol_alias_key(normalized: &str) -> String {
    let alias_key: String = normalized
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    alias_key
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .to_string()
}
