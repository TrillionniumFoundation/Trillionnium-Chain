pub(super) fn normalize_revert_reason(reason: String) -> String {
    let mut canonical = String::with_capacity(reason.len());
    let mut prev_sep = false;

    for ch in reason.trim().chars() {
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            canonical.push(lowered);
            prev_sep = false;
        } else if !prev_sep {
            canonical.push('-');
            prev_sep = true;
        }
    }

    while canonical.ends_with('-') {
        canonical.pop();
    }

    match canonical.as_str() {
        "fraud-proof" | "fraudproof" => "fraud-proof".to_string(),
        "tee-receipt" | "tee-attestation" => "tee-receipt".to_string(),
        "zk-receipt" | "zk-proof" => "zk-receipt".to_string(),
        _ => reason,
    }
}

pub(super) fn is_disallowed_invisible_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2060}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}'
    )
}

pub(super) fn canonical_path_segment(raw: &str) -> String {
    let sanitized: String = raw
        .trim()
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '<' | '"' | '|' | '?' | '*' => '_',
            c if c.is_whitespace() || c.is_control() || is_disallowed_invisible_char(c) => '_',
            c => c,
        })
        .collect();

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return "_".to_string();
    }

    let canonical = sanitized.trim_end_matches(['.', ' ']);
    if canonical.is_empty() || canonical == "." || canonical == ".." {
        return "_".to_string();
    }

    let lowered = canonical.to_ascii_lowercase();
    let windows_basename = lowered.split('.').next().unwrap_or("");
    let is_windows_reserved = matches!(
        windows_basename,
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    );

    if is_windows_reserved {
        format!("{canonical}_")
    } else {
        canonical.to_string()
    }
}
