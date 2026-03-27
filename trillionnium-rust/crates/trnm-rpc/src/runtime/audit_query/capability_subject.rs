use super::*;
use crate::envpaths::normalize_wrapped_env_value;

pub(crate) fn normalize_capability_subject_lookup(raw: &str) -> Option<String> {
    let normalized = normalize_wrapped_env_value(raw)
        .chars()
        .filter_map(|ch| match ch {
            '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}' => None,
            _ if ch.is_control() => None,
            _ => Some(ch),
        })
        .collect::<String>();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn resolve_capability_token_subject_or_token(
    registry: &IdentityRegistry,
    subject_or_token: &str,
) -> Option<u64> {
    let normalized = normalize_capability_subject_lookup(subject_or_token)?;
    if let Ok(token_id) = normalized.parse::<u64>() {
        return Some(token_id);
    }

    if !IdentityRegistry::is_canonical_did(&normalized) {
        return None;
    }

    let mut subject_tokens = registry
        .capability_ids_by_subject(&normalized)
        .into_iter()
        .filter(|token_id| {
            registry
                .capability(*token_id)
                .map(|token| token.subject_did == normalized)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    subject_tokens.sort_unstable();
    subject_tokens.last().copied()
}
