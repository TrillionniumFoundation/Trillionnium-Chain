use super::*;

fn scalar_summary(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}

fn scalar_summary_u128(value: Option<&serde_json::Value>) -> Option<u128> {
    let value = value?;
    match value {
        serde_json::Value::Number(n) => n.as_u64().map(|v| v as u128),
        serde_json::Value::String(s) => s.parse::<u128>().ok(),
        _ => None,
    }
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

fn push_metering_summary_lines(
    lines: &mut Vec<String>,
    indent: &str,
    metering: &serde_json::Value,
    event: Option<&serde_json::Value>,
) {
    let normalized_work_units_str =
        scalar_summary(metering.get("normalized_work_units")).unwrap_or_else(|| "-".into());
    let normalized_work_units = scalar_summary_u128(metering.get("normalized_work_units"));
    let workload_class =
        scalar_summary(metering.get("workload_class")).unwrap_or_else(|| "-".into());
    let metering_schema =
        scalar_summary(metering.get("metering_schema")).unwrap_or_else(|| "-".into());
    let receipt_hash = scalar_summary(metering.get("receipt_hash")).unwrap_or_else(|| "-".into());
    lines.push(format!(
        "{}metering work_units={} class={} schema={} receipt_hash={}",
        indent, normalized_work_units_str, workload_class, metering_schema, receipt_hash
    ));

    if let Some(policy) = metering.get("policy") {
        let floor_str =
            scalar_summary(policy.get("min_accept_work_units")).unwrap_or_else(|| "-".into());
        let floor = scalar_summary_u128(policy.get("min_accept_work_units"));
        let bounty_base_str = scalar_summary(policy.get("challenge_success_bounty_base"))
            .unwrap_or_else(|| "-".into());
        let bounty_base = scalar_summary_u128(policy.get("challenge_success_bounty_base"));
        let chall_num_str =
            scalar_summary(policy.get("challenge_success_bounty_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let chall_den_str =
            scalar_summary(policy.get("challenge_success_bounty_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let chall_num =
            scalar_summary_u128(policy.get("challenge_success_bounty_per_work_unit_num"));
        let chall_den =
            scalar_summary_u128(policy.get("challenge_success_bounty_per_work_unit_den"));
        let worker_bonus_num_str =
            scalar_summary(policy.get("worker_completion_bonus_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let worker_bonus_den_str =
            scalar_summary(policy.get("worker_completion_bonus_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let worker_bonus_num =
            scalar_summary_u128(policy.get("worker_completion_bonus_per_work_unit_num"));
        let worker_bonus_den =
            scalar_summary_u128(policy.get("worker_completion_bonus_per_work_unit_den"));
        let worker_rebate_num_str =
            scalar_summary(policy.get("worker_slash_rebate_per_work_unit_num"))
                .unwrap_or_else(|| "-".into());
        let worker_rebate_den_str =
            scalar_summary(policy.get("worker_slash_rebate_per_work_unit_den"))
                .unwrap_or_else(|| "-".into());
        let worker_rebate_num =
            scalar_summary_u128(policy.get("worker_slash_rebate_per_work_unit_num"));
        let worker_rebate_den =
            scalar_summary_u128(policy.get("worker_slash_rebate_per_work_unit_den"));

        lines.push(format!(
            "{}policy snapshot={} floor={} bounty_base={} chall_bonus={}/{} worker_bonus={}/{} worker_rebate={}/{}",
            indent,
            scalar_summary(policy.get("snapshot_version")).unwrap_or_else(|| "-".into()),
            floor_str,
            bounty_base_str,
            chall_num_str,
            chall_den_str,
            worker_bonus_num_str,
            worker_bonus_den_str,
            worker_rebate_num_str,
            worker_rebate_den_str,
        ));

        let path = metering
            .get("derived")
            .and_then(|derived| scalar_summary(derived.get("path")))
            .or_else(|| event.and_then(|e| scalar_summary(e.get("to_status"))))
            .unwrap_or_else(|| "-".into());
        let accept_floor_status = if let Some(derived) = metering.get("derived") {
            match scalar_summary(derived.get("accept_floor_pass")).as_deref() {
                Some("true") => match (normalized_work_units, floor) {
                    (Some(work_units), Some(floor)) => format!("pass({}>={})", work_units, floor),
                    _ => "pass".into(),
                },
                Some("false") => match (normalized_work_units, floor) {
                    (Some(work_units), Some(floor)) => format!("fail({}<{})", work_units, floor),
                    _ => "fail".into(),
                },
                _ => "-".into(),
            }
        } else if let Some(work_units) = normalized_work_units {
            match floor {
                Some(floor) => {
                    if work_units >= floor {
                        format!("pass({}>={})", work_units, floor)
                    } else {
                        format!("fail({}<{})", work_units, floor)
                    }
                }
                None => "-".into(),
            }
        } else {
            "-".into()
        };
        let challenge_metered_bonus = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("challenge_metered_bonus")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (chall_num, chall_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let challenge_total = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("challenge_bonus_total")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (bounty_base, chall_num, chall_den) {
                (Some(base), Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .and_then(|bonus| base.checked_add(bonus))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let worker_completion_bonus = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("worker_completion_bonus")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (worker_bonus_num, worker_bonus_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        let worker_slash_rebate = if let Some(derived) = metering.get("derived") {
            scalar_summary(derived.get("worker_slash_rebate")).unwrap_or_else(|| "-".into())
        } else if let Some(work_units) = normalized_work_units {
            match (worker_rebate_num, worker_rebate_den) {
                (Some(num), Some(den)) => ceil_mul_div_u128(work_units, num, den)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                _ => "-".into(),
            }
        } else {
            "-".into()
        };
        lines.push(format!(
            "{}derived path={} accept_floor={} challenge_bonus_total={} (metered={}) worker_completion_bonus={} worker_slash_rebate={}",
            indent,
            path,
            accept_floor_status,
            challenge_total,
            challenge_metered_bonus,
            worker_completion_bonus,
            worker_slash_rebate,
        ));
    }
}

pub(crate) fn render_events_query_summary(parsed: &serde_json::Value) -> Result<String> {
    let events = parsed
        .as_array()
        .ok_or_else(|| anyhow!("events summary requires a json array"))?;
    let mut lines = vec![format!("events_total={}", events.len())];
    for (idx, event) in events.iter().enumerate() {
        lines.push(format!(
            "[{}] {} {}->{} tx_id={} block_height={} actor={} resolution={} bond_disposition={}",
            idx,
            scalar_summary(event.get("event_type")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("from_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("to_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("tx_id")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("block_height")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("actor")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("resolution_code")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("bond_disposition")).unwrap_or_else(|| "-".into()),
        ));
        if let Some(metering) = event.get("metering") {
            push_metering_summary_lines(&mut lines, "  ", metering, Some(event));
        }
    }
    Ok(lines.join("\n"))
}

pub(crate) fn render_request_full_query_summary(parsed: &serde_json::Value) -> Result<String> {
    let request = parsed
        .get("request")
        .ok_or_else(|| anyhow!("request-full summary missing request"))?;
    let request_id = scalar_summary(request.get("request_id"))
        .ok_or_else(|| anyhow!("request-full summary missing request_id"))?;
    let task_id = scalar_summary(request.get("task_id"))
        .ok_or_else(|| anyhow!("request-full summary missing task_id"))?;
    let status = scalar_summary(request.get("status")).unwrap_or_else(|| "-".into());
    let channel = scalar_summary(request.get("channel")).unwrap_or_else(|| "-".into());
    let session_id = scalar_summary(request.get("session_id")).unwrap_or_else(|| "-".into());
    let verifier_status =
        scalar_summary(parsed.get("verifier_status")).unwrap_or_else(|| "-".into());
    let resolution_code =
        scalar_summary(parsed.get("resolution_code")).unwrap_or_else(|| "-".into());
    let result_hash = scalar_summary(parsed.get("result_hash")).unwrap_or_else(|| "-".into());
    let commit_tx_hash = scalar_summary(parsed.get("commit_tx_hash")).unwrap_or_else(|| "-".into());
    let reveal_tx_hash = scalar_summary(parsed.get("reveal_tx_hash")).unwrap_or_else(|| "-".into());
    let events = parsed
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("request-full summary missing events"))?;

    let mut lines = vec![
        format!("request_id={}", request_id),
        format!("task_id={}", task_id),
        format!(
            "status={} verifier_status={} resolution_code={}",
            status, verifier_status, resolution_code
        ),
        format!("channel={} session_id={}", channel, session_id),
        format!(
            "commit_tx_hash={} reveal_tx_hash={} result_hash={}",
            commit_tx_hash, reveal_tx_hash, result_hash
        ),
        format!("events_total={}", events.len()),
    ];
    for (idx, event) in events.iter().enumerate() {
        lines.push(format!(
            "[{}] {} {}->{} tx_id={} actor={} resolution={} bond_disposition={}",
            idx,
            scalar_summary(event.get("event_type")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("from_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("to_status")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("tx_id")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("actor")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("resolution_code")).unwrap_or_else(|| "-".into()),
            scalar_summary(event.get("bond_disposition")).unwrap_or_else(|| "-".into()),
        ));
        if let Some(metering) = event.get("metering") {
            push_metering_summary_lines(&mut lines, "  ", metering, Some(event));
        }
    }
    Ok(lines.join("\n"))
}
