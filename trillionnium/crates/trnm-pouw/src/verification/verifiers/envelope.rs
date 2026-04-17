use super::payload::{has_visible_payload_bytes, strip_utf8_bom};
use super::numeric::{find_numeric_field, has_duplicate_numeric_field};
use super::token::{
    find_token_field, find_token_field_raw, has_duplicate_token_field, has_token_field_binding_attempt,
};
use crate::verification::{proof_type_key, VerificationResult};
use trnm_types::TaskObject;

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
        .map(|p: &[u8]| p.eq_ignore_ascii_case(prefix))
        .unwrap_or(false);
    let body = payload.get(prefix.len()..).unwrap_or_default();

    if !has_prefix || !has_visible_payload_bytes(body) {
        return VerificationResult::Invalid(format!("Invalid {kind_name} envelope"));
    }

    let body_text = String::from_utf8_lossy(body);

    if has_duplicate_numeric_field(&body_text, "task_id") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate task_id binding"
        ));
    }

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

    if has_duplicate_token_field(&body_text, "worker") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate worker binding"
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
    } else if find_token_field_raw(&body_text, "worker").is_some()
        || has_token_field_binding_attempt(&body_text, "worker")
    {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: unexpected worker binding"
        ));
    }

    if has_duplicate_token_field(&body_text, "result_hash") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate result_hash binding"
        ));
    }

    if let Some(expected_result_hash) = task.result_hash {
        let expected_hex = hex::encode(expected_result_hash);
        match find_token_field(&body_text, "result_hash") {
            Some(result_hash) => {
                let normalized = result_hash
                    .strip_prefix("0x")
                    .or_else(|| result_hash.strip_prefix("0X"))
                    .unwrap_or(result_hash.as_str());
                if !normalized.eq_ignore_ascii_case(&expected_hex) {
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
    } else if find_token_field(&body_text, "result_hash").is_some()
        || has_token_field_binding_attempt(&body_text, "result_hash")
    {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: unexpected result_hash binding"
        ));
    }

    if has_duplicate_token_field(&body_text, "proof_type") {
        return VerificationResult::Invalid(format!(
            "Invalid {kind_name} envelope: duplicate proof_type binding"
        ));
    }

    let expected = proof_type_key(task.proof_type);
    match find_token_field(&body_text, "proof_type") {
        Some(proof_type) if proof_type.trim().eq_ignore_ascii_case(expected) => {}
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
