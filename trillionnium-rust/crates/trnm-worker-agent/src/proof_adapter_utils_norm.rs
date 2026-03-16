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
        .map(super::proof_adapter_utils_json::strip_terminal_control_sequences)
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
