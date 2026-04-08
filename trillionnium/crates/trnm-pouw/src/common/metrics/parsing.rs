use super::*;

pub(crate) fn validate_llm_token_meter_receipt_for_reveal(
    proof_type: ProofType,
    task_id: u64,
    worker: &str,
    result_hash: &Hash32,
    proof_payload: &[u8],
) -> Result<LlmTokenMeterV1Receipt, PouwError> {
    let payload = std::str::from_utf8(proof_payload)
        .map(|payload| payload.trim_matches(is_ignorable_proof_payload_char))
        .map_err(|_| {
            PouwError::State(format!(
                "unexpected proof payload for non-verifiable proof type: {:?}",
                proof_type
            ))
        })?;

    if !payload.starts_with('{') {
        return Err(PouwError::State(format!(
            "unexpected proof payload for non-verifiable proof type: {:?}",
            proof_type
        )));
    }

    let receipt = parse_and_validate_llm_token_meter_v1_receipt_json(
        payload.as_bytes(),
        DEFAULT_LLM_TOKEN_METER_JITTER_BUDGET_MS,
    )
    .map_err(|err| PouwError::State(format!("invalid llm token meter receipt: {}", err)))?;

    if receipt.task_id != task_id {
        return Err(PouwError::State(format!(
            "llm token meter receipt task_id mismatch: expected {}, got {}",
            task_id, receipt.task_id
        )));
    }

    if receipt.worker_id != worker {
        return Err(PouwError::State(format!(
            "llm token meter receipt worker mismatch: expected {}, got {}",
            worker, receipt.worker_id
        )));
    }

    let expected_result_hash = hex::encode(result_hash);
    let actual_result_hash = normalize_hex_string(&receipt.output_hash);
    if actual_result_hash != expected_result_hash {
        return Err(PouwError::State(format!(
            "llm token meter receipt output_hash mismatch: expected {}, got {}",
            expected_result_hash, actual_result_hash
        )));
    }

    Ok(receipt)
}
