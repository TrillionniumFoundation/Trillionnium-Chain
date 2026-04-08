use std::collections::BTreeMap;

use trnm_rpc::{
    TaskMeteringDerivedQueryResponse, TaskMeteringPolicyQueryResponse, TaskMeteringQueryResponse,
};

fn trim_wrapped_log_numeric(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | ':' | '.' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
}

fn trim_wrapped_log_text(raw: &str) -> &str {
    let mut value = raw.trim();
    loop {
        let trimmed = value.trim();
        let next = if trimmed.len() >= 2 {
            match (trimmed.as_bytes().first().copied(), trimmed.as_bytes().last().copied()) {
                (Some(b'"'), Some(b'"'))
                | (Some(b'\''), Some(b'\''))
                | (Some(b'`'), Some(b'`'))
                | (Some(b'('), Some(b')'))
                | (Some(b'['), Some(b']'))
                | (Some(b'{'), Some(b'}')) => &trimmed[1..trimmed.len() - 1],
                _ => break,
            }
        } else {
            break;
        };
        if next == value {
            break;
        }
        value = next;
    }
    value.trim()
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
        let normalized = trim_wrapped_log_text(v);
        let placeholder = normalized.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized == "-"
            || matches!(placeholder.as_str(), "null" | "none" | "n/a" | "na")
        {
            None
        } else {
            Some(normalized.to_string())
        }
    })
}

fn ceil_mul_div_u128(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
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

fn parse_required_u64_kv_value(kv: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    kv.get(key)
        .and_then(|v| parse_u128_kv_value(v))
        .and_then(|v| u64::try_from(v).ok())
}

fn metering_policy_is_structurally_valid(policy: &TaskMeteringPolicyQueryResponse) -> bool {
    policy.snapshot_version != 0
        && policy.challenge_success_bounty_per_work_unit_den != 0
        && policy.worker_completion_bonus_per_work_unit_den != 0
        && policy.worker_slash_rebate_per_work_unit_den != 0
}

fn task_metering_derived_query_response(
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

    let metering_path = normalize_opt_kv(kv, "to_status")?;
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
    if !metering_policy_is_structurally_valid(&policy) {
        return None;
    }

    Some(build_task_metering_query_response(
        metering_path,
        workload_class,
        metering_schema,
        receipt_hash,
        parse_required_u64_kv_value(kv, "metering_prompt_tokens")?,
        parse_required_u64_kv_value(kv, "metering_generated_tokens")?,
        parse_required_u64_kv_value(kv, "metering_decode_steps")?,
        parse_required_u64_kv_value(kv, "metering_kv_bytes_moved")?,
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

pub(crate) fn parse_event_log_kv(line: &str) -> BTreeMap<String, String> {
    let mut kv = BTreeMap::<String, String>::new();
    let mut i = 0usize;
    let bytes = line.as_bytes();
    let len = bytes.len();

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }

        let key_start = i;
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= len || bytes[i] != b'=' {
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let key_end = i;
        i += 1;

        if key_end <= key_start {
            continue;
        }
        let key = &line[key_start..key_end];

        let value = if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let quote = bytes[i];
            i += 1;
            let mut out = String::new();
            while i < len {
                let b = bytes[i];
                i += 1;
                if b == quote {
                    break;
                }
                if b == b'\\' && i < len {
                    out.push(bytes[i] as char);
                    i += 1;
                } else {
                    out.push(b as char);
                }
            }
            out
        } else {
            let val_start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            line[val_start..i].to_string()
        };

        kv.insert(key.to_string(), value);
    }

    kv
}
