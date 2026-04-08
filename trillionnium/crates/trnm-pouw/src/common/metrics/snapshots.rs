use super::*;

pub(crate) fn build_task_metering_snapshot(
    receipt: &LlmTokenMeterV1Receipt,
    policy: &LlmTokenMeterPolicy,
) -> TaskMeteringSnapshot {
    TaskMeteringSnapshot {
        workload_class: receipt.workload_class.clone(),
        metering_schema: receipt.metering_schema.clone(),
        policy_snapshot_version: CURRENT_LLM_METER_POLICY_SNAPSHOT_VERSION,
        receipt_hash: receipt.receipt_hash.clone(),
        prompt_tokens: receipt.prompt_tokens,
        generated_tokens: receipt.generated_tokens,
        decode_steps: receipt.decode_steps,
        kv_bytes_moved: receipt.kv_bytes_moved,
        normalized_work_units: policy.normalized_work_units_for_receipt(receipt),
        prompt_token_weight: policy.coefficients.prompt_tokens,
        generated_token_weight: policy.coefficients.generated_tokens,
        decode_step_weight: policy.coefficients.decode_steps,
        kv_byte_weight: policy.coefficients.kv_bytes_moved,
        min_accept_work_units: policy.min_accept_work_units,
        challenge_success_bounty_base: policy.challenge_success_bounty_base,
        challenge_success_bounty_per_work_unit_num: policy
            .challenge_success_bounty_per_work_unit_num,
        challenge_success_bounty_per_work_unit_den: policy
            .challenge_success_bounty_per_work_unit_den,
        worker_completion_bonus_per_work_unit_num: policy.worker_completion_bonus_per_work_unit_num,
        worker_completion_bonus_per_work_unit_den: policy.worker_completion_bonus_per_work_unit_den,
        worker_slash_rebate_per_work_unit_num: policy.worker_slash_rebate_per_work_unit_num,
        worker_slash_rebate_per_work_unit_den: policy.worker_slash_rebate_per_work_unit_den,
    }
}

pub(crate) fn validate_task_metering_snapshot(
    task: &TaskObject,
) -> Result<Option<TaskMeteringSnapshot>, PouwError> {
    let Some(metadata) = task.metadata.as_ref() else {
        return Ok(None);
    };
    let Some(snapshot) = metadata.metering.as_ref() else {
        return Ok(None);
    };

    if snapshot.workload_class != LLM_INFERENCE_WORKLOAD_CLASS {
        return Err(PouwError::State(format!(
            "invalid task metering workload_class: {}",
            snapshot.workload_class
        )));
    }
    if snapshot.metering_schema != LLM_TOKEN_METER_V1_SCHEMA {
        return Err(PouwError::State(format!(
            "invalid task metering schema: {}",
            snapshot.metering_schema
        )));
    }
    if snapshot.receipt_hash.trim().is_empty() {
        return Err(PouwError::State(
            "task metering snapshot missing receipt_hash".into(),
        ));
    }

    if let Some(policy) = llm_token_meter_policy_from_snapshot(snapshot)? {
        let recomputed = policy.normalized_work_units_for_snapshot(snapshot);
        if recomputed != snapshot.normalized_work_units {
            return Err(PouwError::State(format!(
                "task metering snapshot normalized_work_units mismatch: expected {}, got {}",
                recomputed, snapshot.normalized_work_units
            )));
        }
    } else {
        let coefficients = LlmTokenMeterV1WorkUnitCoefficients {
            prompt_tokens: snapshot.prompt_token_weight,
            generated_tokens: snapshot.generated_token_weight,
            decode_steps: snapshot.decode_step_weight,
            kv_bytes_moved: snapshot.kv_byte_weight,
        };
        let recomputed = coefficients
            .prompt_tokens
            .saturating_mul(snapshot.prompt_tokens as u128)
            .saturating_add(
                coefficients
                    .generated_tokens
                    .saturating_mul(snapshot.generated_tokens as u128),
            )
            .saturating_add(
                coefficients
                    .decode_steps
                    .saturating_mul(snapshot.decode_steps as u128),
            )
            .saturating_add(
                coefficients
                    .kv_bytes_moved
                    .saturating_mul(snapshot.kv_bytes_moved as u128),
            );
        if recomputed != snapshot.normalized_work_units {
            return Err(PouwError::State(format!(
                "task metering snapshot normalized_work_units mismatch: expected {}, got {}",
                recomputed, snapshot.normalized_work_units
            )));
        }
    }

    Ok(Some(snapshot.clone()))
}

pub(crate) fn enforce_llm_meter_resolve_acceptance_floor(
    st: &StateStore,
    metering_snapshot: Option<&TaskMeteringSnapshot>,
    slash_worker: bool,
) -> Result<(), PouwError> {
    if slash_worker {
        return Ok(());
    }
    let Some(snapshot) = metering_snapshot else {
        return Ok(());
    };
    let Some(policy) = llm_token_meter_policy_for_snapshot_or_state(st, Some(snapshot))? else {
        return Ok(());
    };
    if snapshot.normalized_work_units < policy.min_accept_work_units {
        return Err(PouwError::State(format!(
            "llm token meter normalized_work_units {} below governance minimum {}",
            snapshot.normalized_work_units, policy.min_accept_work_units
        )));
    }
    Ok(())
}
