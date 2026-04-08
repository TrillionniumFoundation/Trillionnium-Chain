pub(crate) fn is_invisible_filler(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZERO WIDTH NON-JOINER
            | '\u{200D}' // ZERO WIDTH JOINER
            | '\u{200E}' // LEFT-TO-RIGHT MARK
            | '\u{200F}' // RIGHT-TO-LEFT MARK
            | '\u{061C}' // ARABIC LETTER MARK (bidi/invisible)
            | '\u{2060}' // WORD JOINER
            | '\u{2061}' // FUNCTION APPLICATION (invisible operator)
            | '\u{2062}' // INVISIBLE TIMES
            | '\u{2063}' // INVISIBLE SEPARATOR
            | '\u{2064}' // INVISIBLE PLUS
            | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
            | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
            | '\u{2068}' // FIRST STRONG ISOLATE
            | '\u{2069}' // POP DIRECTIONAL ISOLATE
            | '\u{00AD}' // SOFT HYPHEN
            | '\u{034F}' // COMBINING GRAPHEME JOINER (non-rendering)
            | '\u{180E}' // MONGOLIAN VOWEL SEPARATOR (historically zero-width)
            | '\u{FE0E}' // VARIATION SELECTOR-15 (text presentation)
            | '\u{FE0F}' // VARIATION SELECTOR-16 (emoji presentation)
            | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
    )
}

pub(crate) fn verify_model_output(output: &str, max_chars: usize) -> (&'static str, &'static str) {
    let trimmed = output.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .any(|c| !c.is_whitespace() && !c.is_control() && !is_invisible_filler(c))
    {
        return ("rejected", "empty_output");
    }

    let normalized_char_count = trimmed
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_filler(*c))
        .count();
    if normalized_char_count > max_chars {
        return ("rejected", "output_too_long");
    }
    ("accepted", "ok")
}

pub(crate) fn normalized_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn trim_boundary_audit_fillers(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || c.is_control() || is_invisible_filler(c))
}
