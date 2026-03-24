fn collapse_contract_match_delimiters(value: &str) -> String {
    value
        .chars()
        .filter_map(|ch| match ch {
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{2063}' | '\u{feff}' => None,
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => Some('-'),
            other => Some(other),
        })
        .collect()
}

pub(crate) fn context_matches_token(context: &str, token: &str) -> bool {
    fn normalize_for_contract_match(value: &str) -> String {
        let lowered = collapse_contract_match_delimiters(value).to_ascii_lowercase();
        let mut out = String::with_capacity(lowered.len());
        let mut prev_space = false;
        for ch in lowered.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch);
                prev_space = false;
            } else if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        }
        out.trim().to_string()
    }

    let normalized_context = collapse_contract_match_delimiters(context).to_ascii_lowercase();
    let normalized_token = collapse_contract_match_delimiters(token).to_ascii_lowercase();
    let context_with_spaces = normalized_context.replace(['-', '_'], " ");
    let token_with_spaces = normalized_token.replace(['-', '_'], " ");
    let normalized_context_relaxed = normalize_for_contract_match(context);
    let normalized_token_relaxed = normalize_for_contract_match(token);
    let normalized_context_compact = normalized_context_relaxed.replace(' ', "");
    let normalized_token_compact = normalized_token_relaxed.replace(' ', "");

    normalized_context.contains(&normalized_token)
        || normalized_context.contains(&normalized_token.replace('-', "_"))
        || normalized_context.contains(&normalized_token.replace('_', "-"))
        || context_with_spaces.contains(&token_with_spaces)
        || (!normalized_token_relaxed.is_empty()
            && normalized_context_relaxed.contains(&normalized_token_relaxed))
        || (!normalized_token_compact.is_empty()
            && normalized_context_compact.contains(&normalized_token_compact))
}
