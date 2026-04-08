use super::scanner::{is_field_name_boundary, is_value_terminator};

pub(super) fn find_token_field(body: &str, field: &str) -> Option<String> {
    find_token_field_with_case(body, field, true)
}

pub(super) fn find_token_field_raw(body: &str, field: &str) -> Option<String> {
    find_token_field_with_case(body, field, false)
}

pub(super) fn has_duplicate_token_field(body: &str, field: &str) -> bool {
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
            return true;
        }
        if saw_binding_attempt {
            // Fail closed: any second binding attempt for the same token
            // field is ambiguous, even when the first attempt was malformed
            // (e.g. empty/unterminated quoted values).
            return true;
        }
        saw_binding_attempt = true;
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
        {
            i += 1;
        }
        if i > start {
            if let Some(q) = quote {
                if i < bytes.len() && bytes[i].is_ascii_whitespace() {
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
            seen += 1;
            if seen > 1 {
                return true;
            }
        }
        cursor = idx + 1;
    }
    false
}

pub(super) fn has_token_field_binding_attempt(body: &str, field: &str) -> bool {
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

        if i < bytes.len() && (bytes[i] == b':' || bytes[i] == b'=') {
            return true;
        }

        // Fail closed on confusable fullwidth separators so malformed bindings
        // still trip unexpected-binding gates when context is absent.
        if bytes
            .get(i..i + 3)
            .map(|seq| seq == [0xEF, 0xBC, 0x9A] || seq == [0xEF, 0xBC, 0x9D])
            .unwrap_or(false)
        {
            return true;
        }

        cursor = idx + 1;
    }

    false
}

pub(super) fn find_token_field_with_case(body: &str, field: &str, lowercase_value: bool) -> Option<String> {
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

        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
        {
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
            let token = &body[start..(if quote.is_some() { i - 1 } else { i })];
            return Some(if lowercase_value {
                token.to_ascii_lowercase()
            } else {
                token.to_string()
            });
        }
        cursor = idx + 1;
    }
    None
}

