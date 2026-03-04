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

fn has_duplicate_numeric_field(body: &str, field: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let body_bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut seen = 0usize;
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
            if body[start..i].parse::<u64>().is_ok() {
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

fn find_token_field(body: &str, field: &str) -> Option<String> {
    find_token_field_with_case(body, field, true)
}

fn find_token_field_raw(body: &str, field: &str) -> Option<String> {
    find_token_field_with_case(body, field, false)
}

fn has_duplicate_token_field(body: &str, field: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let body_bytes = body.as_bytes();
    let mut cursor = 0usize;
    let mut seen = 0usize;
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
            seen += 1;
            if seen > 1 {
                return true;
            }
        }
        cursor = idx + 1;
    }
    false
}

fn find_token_field_with_case(body: &str, field: &str, lowercase_value: bool) -> Option<String> {
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
            let token = body[start..i].trim();
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

    if has_duplicate_numeric_field(&body_text, "task_id") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate task_id binding"
        ));
    }

    if let Some(expected_worker) = task.worker.as_deref() {
        if expected_worker.trim().is_empty() || expected_worker.trim() != expected_worker {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: non-canonical worker binding context"
            ));
        }

        match find_token_field_raw(&body_text, "worker") {
            Some(worker)
                if !worker.trim().is_empty()
                    && worker.trim() == worker
                    && expected_worker == worker => {}
            Some(_) => {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: worker mismatch"
                ))
            }
            None => {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: missing worker binding"
                ))
            }
        }

        if has_duplicate_token_field(&body_text, "worker") {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: duplicate worker binding"
            ));
        }
    }

    if let Some(expected_result_hash) = task.result_hash {
        let expected_hex = hex::encode(expected_result_hash);
        match find_token_field(&body_text, "result_hash") {
            Some(result_hash) => {
                let normalized = result_hash
                    .strip_prefix("0x")
                    .unwrap_or(result_hash.as_str());
                if normalized != expected_hex {
                    return VerificationResult::Invalid(format!(
                        "Invalid {kind_name} envelope: result_hash mismatch"
                    ));
                }
            }
            None => {
                return VerificationResult::Invalid(format!(
                    "Invalid {kind_name} envelope: missing result_hash binding"
                ))
            }
        }

        if has_duplicate_token_field(&body_text, "result_hash") {
            return VerificationResult::Invalid(format!(
                "Invalid {kind_name} envelope: duplicate result_hash binding"
            ));
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

    if has_duplicate_token_field(&body_text, "proof_type") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate proof_type binding"
        ));
    }

    VerificationResult::Valid
}

#[cfg(test)]
mod tests {
    use super::{find_numeric_field, find_token_field, verify_bound_envelope};
    use crate::verification::VerificationResult;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

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
    fn find_token_field_rejects_identifier_suffix_spoof() {
        let body = "proof_typex=zk,proof_type=tee";
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

    #[test]
    fn verify_bound_envelope_rejects_noncanonical_worker_binding_context_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(" worker1 ".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
                b"TEE:",
                "TEE receipt"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("non-canonical worker binding context")
        ));
    }

    #[test]
    fn verify_bound_envelope_rejects_result_hash_with_repeated_hex_prefix_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=0x0xabababababababababababababababababababababababababababababababab,proof=ok",
                b"ZK:",
                "ZK receipt"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn verify_bound_envelope_rejects_duplicate_task_id_binding_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,task_id=42,quote=ok",
                b"TEE:",
                "TEE receipt"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn verify_bound_envelope_rejects_duplicate_worker_binding_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=ok",
                b"TEE:",
                "TEE receipt"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn verify_bound_envelope_rejects_duplicate_result_hash_binding_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,proof=ok",
                b"ZK:",
                "ZK receipt"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn verify_bound_envelope_rejects_duplicate_proof_type_binding_fail_closed() {
        let task = TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };

        assert!(matches!(
            verify_bound_envelope(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,proof_type=tee,quote=ok",
                b"TEE:",
                "TEE receipt"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }
}
