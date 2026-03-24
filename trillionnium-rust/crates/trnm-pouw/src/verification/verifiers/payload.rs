pub(super) fn strip_utf8_bom(payload: &[u8]) -> &[u8] {
    if payload.starts_with(&[0xef, 0xbb, 0xbf]) {
        &payload[3..]
    } else {
        payload
    }
}

pub(super) fn has_visible_payload_bytes(payload: &[u8]) -> bool {
    std::str::from_utf8(payload)
        .map(|s| {
            s.chars().any(|c| {
                !c.is_whitespace()
                    && !c.is_control()
                    && !matches!(
                        c,
                        '\u{180e}'
                            | '\u{200b}'
                            | '\u{200c}'
                            | '\u{200d}'
                            | '\u{2060}'
                            | '\u{2063}'
                            | '\u{feff}'
                            | '\u{200e}'
                            | '\u{200f}'
                            | '\u{202a}'
                            | '\u{202b}'
                            | '\u{202c}'
                            | '\u{202d}'
                            | '\u{202e}'
                            | '\u{2066}'
                            | '\u{2067}'
                            | '\u{2068}'
                            | '\u{2069}'
                    )
            })
        })
        .unwrap_or_else(|_| {
            payload
                .iter()
                .any(|b| !b.is_ascii_whitespace() && !b.is_ascii_control())
        })
}

