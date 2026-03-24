use super::*;

pub(crate) fn actor_id_has_hidden_or_zero_width_chars(token: &str) -> bool {
    token.chars().any(|c| {
        matches!(
            c,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{206a}'
                | '\u{206b}'
                | '\u{206c}'
                | '\u{206d}'
                | '\u{206e}'
                | '\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
        )
    })
}

pub(crate) fn actor_id_has_forbidden_separator_alias(token: &str) -> bool {
    token.chars().any(|c| {
        matches!(
            c,
            ',' | ';'
                | ':'
                | '|'
                | '/'
                | '\\'
                | '，'
                | '；'
                | '：'
                | '｜'
                | '／'
                | '＼'
                | '、'
                | '﹐'
                | '﹑'
                | '﹔'
                | '﹕'
                | '︐'
                | '︔'
                | '︓'
                | '⼁'
                | '∕'
                | '⁄'
                | '╱'
                | '╲'
        )
    })
}

pub(crate) fn is_canonical_actor_id(token: &str) -> bool {
    !token.is_empty()
        && token == token.trim()
        && token.is_ascii()
        && !token.chars().any(|c| c.is_whitespace())
        && !token.chars().any(|c| c.is_control())
        && !actor_id_has_hidden_or_zero_width_chars(token)
        && !actor_id_has_forbidden_separator_alias(token)
}

pub(crate) fn require_canonical_actor_id(token: &str) -> Result<(), PouwError> {
    if is_canonical_actor_id(token) {
        Ok(())
    } else {
        Err(PouwError::Unauthorized)
    }
}

pub(crate) fn require_canonical_actor_id_state(
    token: &str,
    field_name: &str,
) -> Result<(), PouwError> {
    if is_canonical_actor_id(token) {
        Ok(())
    } else {
        Err(PouwError::State(format!("non-canonical {}", field_name)))
    }
}

pub(crate) fn parse_governed_bool_param(raw: &str, param_name: &str) -> Result<bool, PouwError> {
    if raw.trim() != raw {
        return Err(PouwError::State(format!(
            "invalid boolean governance value for {}: {}",
            param_name, raw
        )));
    }

    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(PouwError::State(format!(
            "invalid boolean governance value for {}: {}",
            param_name, other
        ))),
    }
}

pub(crate) fn unresolved_challenge_slash_on_timeout(st: &StateStore) -> Result<bool, PouwError> {
    st.gov_param_string("default_slash_on_unresolved_challenge")
        .map(|v| parse_governed_bool_param(&v, "default_slash_on_unresolved_challenge"))
        .unwrap_or(Ok(DEFAULT_UNRESOLVED_CHALLENGE_SLASH_ON_TIMEOUT))
}
