use super::scanner::{is_field_name_boundary, is_value_terminator};

pub(super) fn find_numeric_field(body: &str, field: &str) -> Option<u64> {
    let lower = body.to_ascii_lowercase();
    let body_bytes = body.as_bytes();
    let mut cursor = 0usize;
    while let Some(found) = lower[cursor..].find(field) {
        let idx = cursor + found;
        if !is_field_name_boundary(body_bytes, idx, field.len()) {
            cursor = idx + 1;
            continue;
        }
        let mut i = idx + field.len();
        let bytes = body.as_bytes();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        if i >= bytes.len() || (bytes[i] != b':' && bytes[i] != b'=') {
            cursor = idx + 1;
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let quote = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let q = bytes[i];
            i += 1;
            Some(q)
        } else {
            None
        };
        if quote.is_some() && i < bytes.len() && bytes[i].is_ascii_whitespace() {
            cursor = idx + 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i > start {
            if let Some(q) = quote {
                if i >= bytes.len() || bytes[i] != q {
                    cursor = idx + 1;
                    continue;
                }
                i += 1;
            }
            if i < bytes.len() && !is_value_terminator(bytes[i]) {
                cursor = idx + 1;
                continue;
            }
            if let Ok(v) = body[start..(if quote.is_some() { i - 1 } else { i })].parse::<u64>() {
                return Some(v);
            }
        }
        cursor = idx + 1;
    }
    None
}

pub(super) fn has_duplicate_numeric_field(body: &str, field: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let body_bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut seen = 0usize;
    let mut saw_binding_attempt = false;
    while let Some(found) = lower[cursor..].find(field) {
        let idx = cursor + found;
        if !is_field_name_boundary(body_bytes, idx, field.len()) {
            cursor = idx + 1;
            continue;
        }
        let mut i = idx + field.len();
        let bytes = body.as_bytes();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        if i >= bytes.len() {
            cursor = idx + 1;
            continue;
        }

        let has_ascii_separator = bytes[i] == b':' || bytes[i] == b'=';
        let has_confusable_fullwidth_separator = bytes
            .get(i..i + 3)
            .map(|seq| seq == [0xEF, 0xBC, 0x9A] || seq == [0xEF, 0xBC, 0x9D])
            .unwrap_or(false);

        if !has_ascii_separator {
            if has_confusable_fullwidth_separator {
                if saw_binding_attempt {
                    return true;
                }
                saw_binding_attempt = true;
            }
            cursor = idx + 1;
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let quote = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let q = bytes[i];
            i += 1;
            Some(q)
        } else {
            None
        };
        if quote.is_some() && i < bytes.len() && bytes[i].is_ascii_whitespace() {
            // Fail closed: malformed quoted numeric duplicate attempts are still
            // ambiguous secondary bindings and must trip the duplicate gate.
            return true;
        }
        if saw_binding_attempt {
            // Fail closed: any second binding attempt for the same numeric
            // field is ambiguous, even if the first attempt was malformed.
            return true;
        }
        saw_binding_attempt = true;
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i > start {
            if let Some(q) = quote {
                if i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    // Fail closed: quoted numeric duplicate attempts with
                    // trailing space before the closing quote are still
                    // ambiguous secondary bindings.
                    return true;
                }
                if i >= bytes.len() || bytes[i] != q {
                    cursor = idx + 1;
                    continue;
                }
                i += 1;
            }
            if i < bytes.len() && !is_value_terminator(bytes[i]) {
                cursor = idx + 1;
                continue;
            }
            if body[start..(if quote.is_some() { i - 1 } else { i })]
                .parse::<u64>()
                .is_ok()
            {
                seen += 1;
                if seen > 1 {
                    return true;
                }
            }
        }
        cursor = idx + 1;
    }
    false
}

