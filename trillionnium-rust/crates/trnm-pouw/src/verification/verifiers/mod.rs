pub mod fraud;
pub mod tee;
pub mod zk;

use crate::verification::{normalize_receipt_proof_type, proof_type_key, VerificationResult};
use trnm_types::TaskObject;

pub use fraud::FraudVerifier;
pub use tee::TeeVerifier;
pub use zk::ZkVerifier;

fn strip_utf8_bom(payload: &[u8]) -> &[u8] {
    if payload.starts_with(&[0xef, 0xbb, 0xbf]) {
        &payload[3..]
    } else {
        payload
    }
}

fn has_visible_payload_bytes(payload: &[u8]) -> bool {
    std::str::from_utf8(payload)
        .map(|s| {
            s.chars().any(|c| {
                !c.is_whitespace()
                    && !c.is_control()
                    && !matches!(
                        c,
                        '\u{200b}'
                            | '\u{200c}'
                            | '\u{200d}'
                            | '\u{2060}'
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

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_value_terminator(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b',' | b'}' | b']' | b')' | b'\'' | b'"' | b'\n' | b'\r' | b'\t'
        )
}

fn is_field_name_boundary(bytes: &[u8], start: usize, len: usize) -> bool {
    let before_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
    let after = start + len;
    let after_ok = after >= bytes.len() || !is_identifier_byte(bytes[after]);
    before_ok && after_ok
}

fn find_numeric_field(body: &str, field: &str) -> Option<u64> {
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
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'"') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i > start {
            if i < bytes.len() && !is_value_terminator(bytes[i]) {
                cursor = idx + 1;
                continue;
            }
            if let Ok(v) = body[start..i].parse::<u64>() {
                return Some(v);
            }
        }
        cursor = idx + 1;
    }
    None
}

fn find_token_field(body: &str, field: &str) -> Option<String> {
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
        if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            i += 1;
        }

        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-' | b'.'))
        {
            i += 1;
        }
        if i > start {
            if i < bytes.len() && !is_value_terminator(bytes[i]) {
                cursor = idx + 1;
                continue;
            }
            return Some(body[start..i].trim().to_ascii_lowercase());
        }
        cursor = idx + 1;
    }
    None
}

pub(super) fn verify_bound_envelope(
    task: &TaskObject,
    proof_data: &[u8],
    prefix: &[u8],
    kind_name: &str,
) -> VerificationResult {
    if proof_data.is_empty() {
        return VerificationResult::Invalid(format!("{kind_name} payload is empty"));
    }

    let payload = strip_utf8_bom(proof_data);
    let has_prefix = payload
        .get(..prefix.len())
        .map(|p| p.eq_ignore_ascii_case(prefix))
        .unwrap_or(false);
    let body = payload.get(prefix.len()..).unwrap_or_default();

    if !has_prefix || !has_visible_payload_bytes(body) {
        return VerificationResult::Invalid(format!("Invalid {kind_name} envelope"));
    }

    let body_text = String::from_utf8_lossy(body);

    let payload_task_id = find_numeric_field(&body_text, "task_id");
    match payload_task_id {
        Some(id) if id == task.task_id => {}
        Some(_) => {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: task_id mismatch"
            ))
        }
        None => {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: missing task_id binding"
            ))
        }
    }

    if let Some(worker) = find_token_field(&body_text, "worker") {
        if let Some(expected_worker) = task.worker.as_deref() {
            if !expected_worker.eq_ignore_ascii_case(worker.trim()) {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: worker mismatch"
                ));
            }
        }
    }

    if let Some(expected_result_hash) = task.result_hash {
        let expected_hex = hex::encode(expected_result_hash);
        match find_token_field(&body_text, "result_hash") {
            Some(result_hash) if result_hash.trim_start_matches("0x") == expected_hex => {}
            Some(_) => {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: result_hash mismatch"
                ))
            }
            None => {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: missing result_hash binding"
                ))
            }
        }
    }

    let expected = proof_type_key(task.proof_type);
    match find_token_field(&body_text, "proof_type") {
        Some(proof_type) if normalize_receipt_proof_type(&proof_type) == expected => {}
        Some(_) => {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: proof_type mismatch"
            ))
        }
        None => {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: missing proof_type binding"
            ))
        }
    }

    VerificationResult::Valid
}

#[cfg(test)]
mod tests {
    use super::{find_numeric_field, find_token_field};

    #[test]
    fn find_numeric_field_rejects_identifier_suffix_spoof() {
        let body = r#"{"not_task_id":7,"task_idx":9}"#;
        assert_eq!(find_numeric_field(body, "task_id"), None);
    }

    #[test]
    fn find_numeric_field_accepts_exact_field_name() {
        let body = r#"{"task_id":7,"worker":"w1"}"#;
        assert_eq!(find_numeric_field(body, "task_id"), Some(7));
    }

    #[test]
    fn find_numeric_field_rejects_trailing_non_delimiter_bytes() {
        let body = r#"{"task_id":7oops,"worker":"w1"}"#;
        assert_eq!(find_numeric_field(body, "task_id"), None);
    }

    #[test]
    fn find_token_field_rejects_identifier_prefix_spoof() {
        let body = "xproof_type=zk,proof_type=tee";
        assert_eq!(
            find_token_field(body, "proof_type"),
            Some("tee".to_string())
        );
    }

    #[test]
    fn find_token_field_rejects_trailing_non_delimiter_bytes() {
        let body = "proof_type=tee%2Cfraud";
        assert_eq!(find_token_field(body, "proof_type"), None);
    }
}
