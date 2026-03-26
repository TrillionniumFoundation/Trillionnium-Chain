use super::*;

pub(crate) fn trim_wrapped_log_numeric(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | ':' | '.' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
}

pub(crate) fn parse_u64_kv_value(raw: &str) -> Option<u64> {
    trim_wrapped_log_numeric(raw).parse::<u64>().ok()
}

pub(crate) fn parse_u128_kv_value(raw: &str) -> Option<u128> {
    trim_wrapped_log_numeric(raw).parse::<u128>().ok()
}

pub(crate) fn parse_i128_kv_value(raw: &str) -> Option<i128> {
    trim_wrapped_log_numeric(raw).parse::<i128>().ok()
}

pub(crate) fn normalize_opt_kv(kv: &BTreeMap<String, String>, key: &str) -> Option<String> {
    kv.get(key).and_then(|v| {
        if v.is_empty() || v == "-" {
            None
        } else {
            Some(v.clone())
        }
    })
}

pub(crate) fn ceil_mul_div_u128(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    if value == 0 || numerator == 0 {
        return Some(0);
    }
    let product = value.checked_mul(numerator)?;
    let adjusted = product.checked_add(denominator.checked_sub(1)?)?;
    Some(adjusted / denominator)
}

pub(crate) fn task_metering_derived_query_response(
    path: String,
    normalized_work_units: u128,
    policy: &TaskMeteringPolicyQueryResponse,
) -> TaskMeteringDerivedQueryResponse {
    let challenge_metered_bonus = ceil_mul_div_u128(
        normalized_work_units,
        policy.challenge_success_bounty_per_work_unit_num,
        policy.challenge_success_bounty_per_work_unit_den,
    )
    .unwrap_or(0);
    let worker_completion_bonus = ceil_mul_div_u128(
        normalized_work_units,
        policy.worker_completion_bonus_per_work_unit_num,
        policy.worker_completion_bonus_per_work_unit_den,
    )
    .unwrap_or(0);
    let worker_slash_rebate = ceil_mul_div_u128(
        normalized_work_units,
        policy.worker_slash_rebate_per_work_unit_num,
        policy.worker_slash_rebate_per_work_unit_den,
    )
    .unwrap_or(0);

    TaskMeteringDerivedQueryResponse {
        path,
        accept_floor_pass: normalized_work_units >= policy.min_accept_work_units,
        challenge_metered_bonus,
        challenge_bonus_total: policy
            .challenge_success_bounty_base
            .saturating_add(challenge_metered_bonus),
        worker_completion_bonus,
        worker_slash_rebate,
    }
}

pub(crate) fn build_task_metering_query_response(
    path: String,
    workload_class: String,
    metering_schema: String,
    receipt_hash: String,
    prompt_tokens: u64,
    generated_tokens: u64,
    decode_steps: u64,
    kv_bytes_moved: u64,
    normalized_work_units: u128,
    prompt_token_weight: u128,
    generated_token_weight: u128,
    decode_step_weight: u128,
    kv_byte_weight: u128,
    policy: TaskMeteringPolicyQueryResponse,
) -> TaskMeteringQueryResponse {
    let derived = task_metering_derived_query_response(path, normalized_work_units, &policy);
    TaskMeteringQueryResponse {
        workload_class,
        metering_schema,
        receipt_hash,
        prompt_tokens,
        generated_tokens,
        decode_steps,
        kv_bytes_moved,
        normalized_work_units,
        prompt_token_weight,
        generated_token_weight,
        decode_step_weight,
        kv_byte_weight,
        policy,
        derived,
    }
}

pub(crate) fn parse_event_metering_query_response(
    kv: &BTreeMap<String, String>,
) -> Option<TaskMeteringQueryResponse> {
    let workload_class = normalize_opt_kv(kv, "metering_workload_class")?;
    let metering_schema = normalize_opt_kv(kv, "metering_schema")?;
    let receipt_hash = normalize_opt_kv(kv, "metering_receipt_hash")?;
    let policy_snapshot_version = kv
        .get("metering_policy_snapshot_version")
        .and_then(|v| parse_u128_kv_value(v))
        .and_then(|v| u8::try_from(v).ok())?;

    let normalized_work_units = kv
        .get("metering_normalized_work_units")
        .and_then(|v| parse_u128_kv_value(v))?;
    let policy = TaskMeteringPolicyQueryResponse {
        snapshot_version: policy_snapshot_version,
        min_accept_work_units: kv
            .get("metering_min_accept_work_units")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_base: kv
            .get("metering_challenge_success_bounty_base")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_per_work_unit_num: kv
            .get("metering_challenge_success_bounty_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_per_work_unit_den: kv
            .get("metering_challenge_success_bounty_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_completion_bonus_per_work_unit_num: kv
            .get("metering_worker_completion_bonus_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_completion_bonus_per_work_unit_den: kv
            .get("metering_worker_completion_bonus_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_slash_rebate_per_work_unit_num: kv
            .get("metering_worker_slash_rebate_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_slash_rebate_per_work_unit_den: kv
            .get("metering_worker_slash_rebate_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
    };

    Some(build_task_metering_query_response(
        normalize_opt_kv(kv, "to_status").unwrap_or_else(|| "-".into()),
        workload_class,
        metering_schema,
        receipt_hash,
        kv.get("metering_prompt_tokens")
            .and_then(|v| parse_u128_kv_value(v))? as u64,
        kv.get("metering_generated_tokens")
            .and_then(|v| parse_u128_kv_value(v))? as u64,
        kv.get("metering_decode_steps")
            .and_then(|v| parse_u128_kv_value(v))? as u64,
        kv.get("metering_kv_bytes_moved")
            .and_then(|v| parse_u128_kv_value(v))? as u64,
        normalized_work_units,
        kv.get("metering_prompt_token_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_generated_token_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_decode_step_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_kv_byte_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        policy,
    ))
}

pub(crate) fn task_status_path(status: TaskStatus) -> String {
    match status {
        TaskStatus::Open => "Open",
        TaskStatus::Assigned => "Assigned",
        TaskStatus::Committed => "Committed",
        TaskStatus::Revealed => "Revealed",
        TaskStatus::Challenged => "Challenged",
        TaskStatus::Completed => "Completed",
        TaskStatus::Slashed => "Slashed",
    }
    .to_string()
}

pub(crate) fn task_metering_query_response(
    snapshot: &TaskMeteringSnapshot,
    path: String,
) -> TaskMeteringQueryResponse {
    let policy = TaskMeteringPolicyQueryResponse {
        snapshot_version: snapshot.policy_snapshot_version,
        min_accept_work_units: snapshot.min_accept_work_units,
        challenge_success_bounty_base: snapshot.challenge_success_bounty_base,
        challenge_success_bounty_per_work_unit_num: snapshot
            .challenge_success_bounty_per_work_unit_num,
        challenge_success_bounty_per_work_unit_den: snapshot
            .challenge_success_bounty_per_work_unit_den,
        worker_completion_bonus_per_work_unit_num: snapshot
            .worker_completion_bonus_per_work_unit_num,
        worker_completion_bonus_per_work_unit_den: snapshot
            .worker_completion_bonus_per_work_unit_den,
        worker_slash_rebate_per_work_unit_num: snapshot.worker_slash_rebate_per_work_unit_num,
        worker_slash_rebate_per_work_unit_den: snapshot.worker_slash_rebate_per_work_unit_den,
    };
    build_task_metering_query_response(
        path,
        snapshot.workload_class.clone(),
        snapshot.metering_schema.clone(),
        snapshot.receipt_hash.clone(),
        snapshot.prompt_tokens,
        snapshot.generated_tokens,
        snapshot.decode_steps,
        snapshot.kv_bytes_moved,
        snapshot.normalized_work_units,
        snapshot.prompt_token_weight,
        snapshot.generated_token_weight,
        snapshot.decode_step_weight,
        snapshot.kv_byte_weight,
        policy,
    )
}

pub(crate) fn query_task_from_state_snapshot(
    task_id: u64,
    tasks: &[TaskObject],
) -> Option<TaskQueryResponse> {
    let task = tasks
        .iter()
        .filter(|task| task.task_id == task_id)
        .max_by_key(|task| task.version)?;

    Some(TaskQueryResponse {
        task_id: task.task_id,
        status: task.status,
        worker: task.worker.clone(),
        bounty: task.bounty,
        result_hash_hex: task.result_hash.map(hex::encode),
        version: task.version,
        metadata_compatibility: task
            .metadata
            .as_ref()
            .map(|metadata| metadata.compatibility_profile()),
        metadata_runtime_compatible: task
            .metadata
            .as_ref()
            .map(|metadata| metadata.compatibility_profile().is_runtime_compatible()),
        metadata_requires_governance_upgrade: task
            .metadata
            .as_ref()
            .map(|metadata| metadata.requires_runtime_metadata_upgrade()),
        metadata_primary_compatibility_finding: task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.primary_compatibility_finding()),
        metadata_compatibility_findings: task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.compatibility_findings_nonempty()),
        metering: task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.metering.as_ref())
            .map(|snapshot| task_metering_query_response(snapshot, task_status_path(task.status))),
    })
}
