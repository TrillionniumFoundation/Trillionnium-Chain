use super::common::{is_invisible_filler, normalized_optional_field, trim_boundary_audit_fillers};

pub(crate) fn normalized_provider_request_id(value: Option<&str>) -> Option<String> {
    let normalized =
        trim_boundary_audit_fillers(normalized_optional_field(value)?.as_str()).to_string();
    if normalized.is_empty() {
        return None;
    }
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    let starts_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_alphanumeric() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    if is_allowed && starts_and_ends_alnum && normalized.len() <= 128 {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_provenance_label(value: Option<&str>, max_len: usize) -> Option<String> {
    let normalized = normalized_optional_field(value)?;
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii() || c.is_ascii_control());
    if !has_disallowed_chars && normalized.len() <= max_len {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_compliance_profile(value: Option<&str>) -> Option<String> {
    let raw = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = raw
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars {
        return None;
    }

    let normalized: String = raw
        .chars()
        .map(|c| if c.is_ascii_whitespace() { '-' } else { c })
        .collect();
    let is_allowed = normalized.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/' | '\\')
    });
    let starts_with_alpha_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_lowercase() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    let has_adjacent_separators = normalized
        .chars()
        .fold((false, false), |(found, prev_sep), c| {
            let is_sep = matches!(c, '-' | '_' | '.' | '/' | '\\');
            (found || (prev_sep && is_sep), is_sep)
        })
        .0;
    let has_alpha = normalized.chars().any(|c| c.is_ascii_lowercase());
    let has_separator = normalized
        .chars()
        .any(|c| matches!(c, '-' | '_' | '.' | '/' | '\\'));
    if is_allowed
        && starts_with_alpha_and_ends_alnum
        && !has_adjacent_separators
        && normalized.len() <= 64
        && has_alpha
        && has_separator
    {
        Some(
            normalized
                .chars()
                .map(|c| {
                    if matches!(c, '_' | '.' | '/' | '\\') {
                        '-'
                    } else {
                        c
                    }
                })
                .collect(),
        )
    } else {
        None
    }
}
