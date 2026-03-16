use crate::LlmAdapterResponse;

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
        .trim_start_matches(|c| super::proof_adapter_utils_norm::is_invisible_receipt_filler(c));
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
