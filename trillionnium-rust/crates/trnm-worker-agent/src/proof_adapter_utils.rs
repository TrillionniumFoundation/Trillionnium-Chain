use crate::LlmAdapterResponse;
use serde_json;

pub(crate) fn last_balanced_json_object(input: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut last: Option<String> = None;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        last = Some(input[s..=idx].to_string());
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }

    last
}

pub(crate) fn is_invisible_receipt_filler(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{00ad}'
            | '\u{034f}'
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
            | '\u{fe0e}'
            | '\u{fe0f}'
            | '\u{feff}'
    )
}

pub(crate) fn collapse_adapter_delimiters(raw: &str) -> String {
    let mut collapsed = String::with_capacity(raw.len());
    let mut last_was_delimiter = false;

    for ch in raw.chars() {
        let mapped = match ch {
            other if is_invisible_receipt_filler(other) => None,
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => Some('-'),
            '_' | '/' | '\\' | ':' | '.' => Some('-'),
            other if other.is_whitespace() => Some('-'),
            other => Some(other),
        };

        match mapped {
            Some('-') => {
                if !last_was_delimiter {
                    collapsed.push('-');
                    last_was_delimiter = true;
                }
            }
            Some(other) => {
                collapsed.push(other);
                last_was_delimiter = false;
            }
            None => {}
        }
    }

    collapsed
}

pub(crate) fn peel_outer_quote_wrappers(value: &str) -> &str {
    const QUOTE_WRAPPERS: [(&str, &str); 12] = [
        ("'", "'"),
        ("\"", "\""),
        ("`", "`"),
        ("“", "”"),
        ("‘", "’"),
        ("«", "»"),
        ("‹", "›"),
        ("「", "」"),
        ("『", "』"),
        ("〈", "〉"),
        ("《", "》"),
        ("⟨", "⟩"),
    ];
    const ESCAPED_QUOTE_WRAPPERS: [(&str, &str); 12] = [
        (r#"\'"#, r#"\'"#),
        (r#"\""#, r#"\""#),
        (r#"\`"#, r#"\`"#),
        ("\\“", "\\”"),
        ("\\‘", "\\’"),
        ("\\«", "\\»"),
        ("\\‹", "\\›"),
        ("\\「", "\\」"),
        ("\\『", "\\』"),
        ("\\〈", "\\〉"),
        ("\\《", "\\》"),
        ("\\⟨", "\\⟩"),
    ];

    let mut current = value.trim().trim_start_matches('\u{feff}').trim();

    for _ in 0..16 {
        let mut changed = false;

        for (prefix, suffix) in QUOTE_WRAPPERS {
            if let Some(stripped) = current
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            {
                current = stripped.trim().trim_start_matches('\u{feff}').trim();
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        for (prefix, suffix) in ESCAPED_QUOTE_WRAPPERS {
            if let Some(stripped) = current
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            {
                current = stripped.trim().trim_start_matches('\u{feff}').trim();
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        break;
    }

    current
}

pub(crate) fn normalize_adapter_label(label: &str) -> String {
    collapse_adapter_delimiters(peel_outer_quote_wrappers(label))
        .trim_matches('-')
        .to_ascii_lowercase()
}

pub(crate) fn normalize_adapter_value(value: &str) -> String {
    collapse_adapter_delimiters(peel_outer_quote_wrappers(value))
        .trim_matches('-')
        .to_ascii_lowercase()
}

pub(crate) fn has_non_empty_auditable_value(value: Option<&str>) -> bool {
    value
        .map(strip_terminal_control_sequences)
        .map(|v| {
            v.chars()
                .filter(|c| !is_invisible_receipt_filler(*c))
                .collect::<String>()
        })
        .map(|v| peel_outer_quote_wrappers(v.as_str()).to_string())
        .map(|v| {
            v.chars()
                .filter(|c| !is_invisible_receipt_filler(*c))
                .collect::<String>()
        })
        .map(|v| v.chars().any(|c| !c.is_whitespace() && !c.is_control()))
        .unwrap_or(false)
}

pub(crate) fn strip_terminal_control_sequences(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                continue;
            }
            sanitized.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                while let Some(next) = chars.next() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                let mut saw_esc = false;
                while let Some(next) = chars.next() {
                    if saw_esc && next == '\\' {
                        break;
                    }
                    saw_esc = next == '\u{1b}';
                    if !saw_esc && next == '\u{7}' {
                        break;
                    }
                }
            }
            Some('P' | '^' | '_') => {
                chars.next();
                let mut saw_esc = false;
                while let Some(next) = chars.next() {
                    if saw_esc && next == '\\' {
                        break;
                    }
                    saw_esc = next == '\u{1b}';
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }

    sanitized
}

pub(crate) fn parse_response_with_standard_rules(
    stdout: &str,
) -> Result<LlmAdapterResponse, String> {
    let sanitized = strip_terminal_control_sequences(stdout);
    let normalized = sanitized
        .trim_start()
        .trim_start_matches(is_invisible_receipt_filler);
    let starts_with_json_object = normalized.starts_with('{');

    if let Ok(parsed) = serde_json::from_str(normalized) {
        return Ok(parsed);
    }

    for line in normalized.lines().rev().map(str::trim) {
        if line.starts_with('{') && line.ends_with('}') {
            if let Ok(parsed) = serde_json::from_str(line) {
                return Ok(parsed);
            }
        }

        if let (Some(start), Some(end)) = (line.find('{'), line.rfind('}')) {
            if start < end {
                let candidate = &line[start..=end];
                if let Ok(parsed) = serde_json::from_str(candidate) {
                    return Ok(parsed);
                }
            }
        }
    }

    if let Some(candidate) = last_balanced_json_object(normalized) {
        if let Ok(parsed) = serde_json::from_str::<LlmAdapterResponse>(&candidate) {
            return Ok(parsed);
        }
    }

    if starts_with_json_object {
        return Err("invalid-json".to_string());
    }

    Err("no-json-line".to_string())
}
