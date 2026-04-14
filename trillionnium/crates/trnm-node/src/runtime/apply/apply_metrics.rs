use super::*;

pub(crate) fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub(crate) fn percentile(mut vals: Vec<u128>, p: f64) -> u128 {
    if vals.is_empty() {
        return 0;
    }
    vals.sort_unstable();
    let idx = ((vals.len() - 1) as f64 * p).round() as usize;
    vals[idx.min(vals.len() - 1)]
}

pub(crate) fn max_or_zero(vals: &[u128]) -> u128 {
    vals.iter().copied().max().unwrap_or(0)
}

pub(crate) fn average_or_zero(vals: &[u128]) -> u128 {
    if vals.is_empty() {
        0
    } else {
        vals.iter().copied().sum::<u128>() / vals.len() as u128
    }
}

pub(crate) fn ratio_ppm(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000_000) / denominator
    }
}

pub(crate) fn ratio_percent_bps(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

pub(crate) fn ratio_milli_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000) / denominator
    }
}

pub(crate) fn finality_budget_share_ppm(density_avg_milli: u64, finality_avg_ms: u128) -> u64 {
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let finality_budget_milli = finality_avg_ms_u64.saturating_mul(1_000);
    ratio_ppm_u64(density_avg_milli, finality_budget_milli)
}

pub(crate) fn wall_time_share_ppm(
    total_ms: u64,
    committed_heights: u64,
    finality_avg_ms: u128,
) -> u64 {
    if committed_heights == 0 {
        return 0;
    }
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let total_budget_ms = committed_heights.saturating_mul(finality_avg_ms_u64);
    ratio_ppm_u64(total_ms, total_budget_ms)
}

pub(crate) fn gap_percent_bps(total: u128, component_a: u128, component_b: u128) -> u128 {
    if total == 0 {
        return 0;
    }
    total
        .saturating_sub(component_a.saturating_add(component_b))
        .saturating_mul(10_000)
        / total
}

pub(crate) fn treasury_total(st: &StateStore) -> u128 {
    st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        .saturating_add(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT))
        .saturating_add(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT))
}

pub(crate) fn diff_u128_to_i128(after: u128, before: u128) -> Option<i128> {
    let after_i = i128::try_from(after).ok()?;
    let before_i = i128::try_from(before).ok()?;
    Some(after_i - before_i)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventDelta {
    pub(crate) numeric: Option<i128>,
    pub(crate) text: String,
}

pub(crate) fn classify_apply_error(err: &anyhow::Error) -> &'static str {
    if let Some(pouw) = err.downcast_ref::<trnm_pouw::PouwError>() {
        return match pouw {
            trnm_pouw::PouwError::VersionConflict => "version_conflict",
            trnm_pouw::PouwError::InvalidTransition => "invalid_transition",
            trnm_pouw::PouwError::DeadlineExceeded => "deadline_exceeded",
            trnm_pouw::PouwError::ResolveApprovalStaged => "resolve_approval_staged",
            _ => "semantic_fail",
        };
    }

    let e = err.to_string().to_ascii_lowercase();
    if e.contains("version conflict") {
        "version_conflict"
    } else if e.contains("invalid transition") {
        "invalid_transition"
    } else if e.contains("deadline exceeded") {
        "deadline_exceeded"
    } else if e.contains("preexec") {
        "preexec_conflict_miss"
    } else {
        "semantic_fail"
    }
}

pub(crate) fn format_delta_fallback(after: u128, before: u128) -> String {
    if after >= before {
        format!("u128:+{}", after - before)
    } else {
        format!("u128:-{}", before - after)
    }
}

pub(crate) fn event_delta_from_balances(after: u128, before: u128) -> EventDelta {
    let numeric = diff_u128_to_i128(after, before);
    let text = numeric
        .map(|v| v.to_string())
        .unwrap_or_else(|| format_delta_fallback(after, before));
    EventDelta { numeric, text }
}

pub(crate) fn balance_deltas_for_transition(
    before: &StateStore,
    after: &StateStore,
    task_id: u64,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_delta = event_delta_from_balances(treasury_total(after), treasury_total(before));
    let challenger_delta = challenger.map(|acct| {
        let before_bal = before.balance_of(acct);
        let after_bal = after.balance_of(acct);
        event_delta_from_balances(after_bal, before_bal)
    });

    let _ = task_id;
    (treasury_delta, challenger_delta)
}

pub(crate) fn format_task_metering_event_fields(snapshot: &TaskMeteringSnapshot) -> String {
    format!(
        " metering_workload_class={} metering_schema={} metering_receipt_hash={} metering_policy_snapshot_version={} metering_prompt_tokens={} metering_generated_tokens={} metering_decode_steps={} metering_kv_bytes_moved={} metering_normalized_work_units={} metering_prompt_token_weight={} metering_generated_token_weight={} metering_decode_step_weight={} metering_kv_byte_weight={} metering_min_accept_work_units={} metering_challenge_success_bounty_base={} metering_challenge_success_bounty_per_work_unit_num={} metering_challenge_success_bounty_per_work_unit_den={} metering_worker_completion_bonus_per_work_unit_num={} metering_worker_completion_bonus_per_work_unit_den={} metering_worker_slash_rebate_per_work_unit_num={} metering_worker_slash_rebate_per_work_unit_den={}",
        snapshot.workload_class,
        snapshot.metering_schema,
        snapshot.receipt_hash,
        snapshot.policy_snapshot_version,
        snapshot.prompt_tokens,
        snapshot.generated_tokens,
        snapshot.decode_steps,
        snapshot.kv_bytes_moved,
        snapshot.normalized_work_units,
        snapshot.prompt_token_weight,
        snapshot.generated_token_weight,
        snapshot.decode_step_weight,
        snapshot.kv_byte_weight,
        snapshot.min_accept_work_units,
        snapshot.challenge_success_bounty_base,
        snapshot.challenge_success_bounty_per_work_unit_num,
        snapshot.challenge_success_bounty_per_work_unit_den,
        snapshot.worker_completion_bonus_per_work_unit_num,
        snapshot.worker_completion_bonus_per_work_unit_den,
        snapshot.worker_slash_rebate_per_work_unit_num,
        snapshot.worker_slash_rebate_per_work_unit_den,
    )
}

pub(crate) fn format_task_consumption_summary_event_fields(
    summary: &trnm_state::TaskConsumptionSummary,
) -> String {
    format!(
        " settlement_receipt_count={} settlement_accepted_receipt_count={} settlement_challenged_receipt_count={} settlement_total_consumed_tokens={} settlement_total_claimed_consumption_units={} settlement_total_credited_consumption_units={} settlement_last_settlement_height={}",
        summary.receipt_count,
        summary.accepted_receipt_count,
        summary.challenged_receipt_count,
        summary.total_consumed_tokens,
        summary.total_claimed_consumption_units,
        summary.total_credited_consumption_units,
        summary
            .last_settlement_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "-".to_string()),
    )
}

pub(crate) fn task_metering_event_suffix(st: &StateStore, task_id: u64) -> String {
    st.get_task(task_id)
        .and_then(|task| task.metadata)
        .and_then(|metadata| metadata.metering)
        .map(|snapshot| format_task_metering_event_fields(&snapshot))
        .unwrap_or_default()
}

pub(crate) fn task_settlement_event_suffix(st: &StateStore, task_id: u64) -> String {
    let mut suffix = task_metering_event_suffix(st, task_id);

    if let Some(summary) = st.task_consumption_summary(task_id) {
        suffix.push_str(&format_task_consumption_summary_event_fields(&summary));
    }

    suffix
}

pub(crate) fn emit_event(
    st: &StateStore,
    tx: &MockTx,
    signer: &str,
    tx_id: u64,
    block_height: u64,
    from_status: &str,
    to_status: &str,
    state_root: &str,
    treasury_delta: &EventDelta,
    challenger_delta: Option<&EventDelta>,
    challenger: Option<&str>,
    err_kind: Option<&str>,
) {
    let task_id = task_id_of(tx);
    let event_type = event_type_for_apply_outcome(tx, err_kind);
    let actor = actor_of(st, tx);
    let challenger = challenger
        .map(|s| s.to_string())
        .or_else(|| challenger_of(tx))
        .unwrap_or_else(|| "-".to_string());
    let tx_hash = tx_hash_of(tx_id);
    let ts_unix_ms = now_unix_ms();

    let bond_disposition = match tx {
        MockTx::Challenge { .. } => Some("posted"),
        MockTx::Resolve { slash_worker, .. } => Some(if *slash_worker {
            "refunded"
        } else {
            "forfeited"
        }),
        _ => None,
    };

    let treasury_delta_str = match tx {
        MockTx::Challenge { .. } => "0",
        _ => treasury_delta.text.as_str(),
    };
    let challenger_delta_str = challenger_delta.map(|d| d.text.as_str()).unwrap_or("-");
    let bond_disposition_str = bond_disposition.unwrap_or("-");
    let metering_suffix = match tx {
        MockTx::Reveal { .. } | MockTx::Resolve { .. } => task_settlement_event_suffix(st, task_id),
        _ => String::new(),
    };

    match tx {
        MockTx::Resolve { slash_worker, .. } => {
            let resolution_code = if *slash_worker {
                "slashed"
            } else {
                "completed"
            };
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                signer,
                challenger,
                tx_hash,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms,
                slash_worker,
                resolution_code,
                treasury_delta_str,
                challenger_delta_str,
                bond_disposition_str,
                metering_suffix,
            );
        }
        _ => {
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                signer,
                challenger,
                tx_hash,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms,
                treasury_delta_str,
                challenger_delta_str,
                bond_disposition_str,
                metering_suffix,
            );
        }
    }
}

fn timeout_outcome_fields(to_status: &str) -> (&'static str, &'static str) {
    match to_status {
        "Slashed" => ("true", "slashed"),
        "Completed" => ("false", "completed"),
        _ => ("false", "unknown"),
    }
}

pub(crate) fn emit_timeout_event(
    st: &StateStore,
    task_id: u64,
    tx_id: u64,
    tx_ordinal: u64,
    tx_id_overflow: bool,
    tx_ordinal_overflow: bool,
    block_height: u64,
    from_status: &str,
    to_status: &str,
    state_root: &str,
    treasury_delta: &EventDelta,
    challenger_delta: Option<&EventDelta>,
    challenger: Option<&str>,
    bond_disposition: Option<&str>,
) {
    let tx_hash = tx_hash_of(tx_id);
    let ts_unix_ms = now_unix_ms();
    let treasury_delta_str = treasury_delta.text.as_str();
    let challenger_delta_str = challenger_delta.map(|d| d.text.as_str()).unwrap_or("-");
    let bond_disposition_str = bond_disposition.unwrap_or("-");
    let metering_suffix = task_settlement_event_suffix(st, task_id);
    let (slash_worker, resolution_code) = timeout_outcome_fields(to_status);

    println!(
        "[event] event_schema=v1 event_type=timeout task_id={} from_status={} to_status={} actor=system signer=system challenger={} tx_hash={} tx_id={} tx_ordinal={} tx_id_overflow={} tx_ordinal_overflow={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
        task_id,
        from_status,
        to_status,
        challenger.unwrap_or("-"),
        tx_hash,
        tx_id,
        tx_ordinal,
        tx_id_overflow,
        tx_ordinal_overflow,
        block_height,
        state_root,
        ts_unix_ms,
        slash_worker,
        resolution_code,
        treasury_delta_str,
        challenger_delta_str,
        bond_disposition_str,
        metering_suffix,
    );
}

#[cfg(test)]
mod tests {
    use super::format_task_consumption_summary_event_fields;
    use super::timeout_outcome_fields;

    #[test]
    fn timeout_outcome_fields_marks_slashed_terminal_status() {
        assert_eq!(timeout_outcome_fields("Slashed"), ("true", "slashed"));
    }

    #[test]
    fn timeout_outcome_fields_only_marks_actual_terminal_statuses() {
        assert_eq!(timeout_outcome_fields("Completed"), ("false", "completed"));
        assert_eq!(timeout_outcome_fields("Slashed"), ("true", "slashed"));
    }

    #[test]
    fn timeout_outcome_fields_marks_stale_or_unexpected_statuses_unknown_for_visibility() {
        assert_eq!(timeout_outcome_fields("Resolved"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("Challenged"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("Assigned"), ("false", "unknown"));
    }

    #[test]
    fn timeout_outcome_fields_stays_unknown_for_noncanonical_terminal_labels() {
        assert_eq!(timeout_outcome_fields("completed"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("slashed"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields(" Completed"), ("false", "unknown"));
    }

    #[test]
    fn format_task_consumption_summary_event_fields_renders_stable_receipt_counters() {
        let line =
            format_task_consumption_summary_event_fields(&trnm_state::TaskConsumptionSummary {
                task_id: 42,
                receipt_count: 3,
                accepted_receipt_count: 2,
                challenged_receipt_count: 1,
                total_consumed_tokens: 55,
                total_claimed_consumption_units: 55,
                total_credited_consumption_units: 49,
                last_settlement_height: Some(88),
            });

        assert!(line.contains("settlement_receipt_count=3"));
        assert!(line.contains("settlement_accepted_receipt_count=2"));
        assert!(line.contains("settlement_challenged_receipt_count=1"));
        assert!(line.contains("settlement_total_consumed_tokens=55"));
        assert!(line.contains("settlement_total_claimed_consumption_units=55"));
        assert!(line.contains("settlement_total_credited_consumption_units=49"));
        assert!(line.contains("settlement_last_settlement_height=88"));
    }
}
