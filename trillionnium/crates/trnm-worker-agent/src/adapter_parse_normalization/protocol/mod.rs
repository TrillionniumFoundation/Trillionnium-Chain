use super::common::{is_invisible_filler, normalized_optional_field};

#[path = "a2a_aliases.rs"]
mod a2a_aliases;
#[path = "mcp_aliases.rs"]
mod mcp_aliases;
#[path = "sanitization.rs"]
mod sanitization;

use self::sanitization::{build_protocol_alias_key, normalize_protocol_input};

pub(crate) fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
    let normalized = normalize_protocol_input(value)?;
    let alias_key = build_protocol_alias_key(&normalized);
    if mcp_aliases::is_mcp_alias(&alias_key) {
        Some("mcp".to_string())
    } else if a2a_aliases::is_a2a_alias(&alias_key) {
        Some("a2a".to_string())
    } else {
        None
    }
}

pub(super) fn has_disallowed_protocol_chars(normalized: &str) -> bool {
    normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii())
}

pub(super) fn normalize_protocol_field(value: Option<&str>) -> Option<String> {
    normalized_optional_field(value).map(|v| v.to_ascii_lowercase())
}
