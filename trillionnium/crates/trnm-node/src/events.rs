use trnm_state::StateStore;
use trnm_types::TaskMeteringSnapshot;

use crate::accounting::EventDelta;
use crate::txmeta::{actor_of, challenger_of, now_unix_ms, task_id_of, tx_hash_of};
use crate::types::MockTx;

pub(crate) fn event_type_of(tx: &MockTx) -> &'static str {
    match tx {
        MockTx::CreateTask { .. } => "create",
        MockTx::AcceptTask { .. } => "accept",
        MockTx::Commit { .. } => "commit",
        MockTx::Reveal { .. } => "reveal",
        MockTx::Challenge { .. } => "challenge",
        MockTx::Resolve { .. } => "resolve",
    }
}

pub(crate) fn event_type_for_apply_outcome(tx: &MockTx, err_kind: Option<&str>) -> &'static str {
    if matches!(tx, MockTx::Resolve { .. }) && err_kind == Some("resolve_approval_staged") {
        "resolve_approval_staged"
    } else {
        event_type_of(tx)
    }
}

pub(crate) fn status_name(st: &StateStore, task_id: u64) -> String {
    st.get_task(task_id)
        .map(|t| format!("{:?}", t.status))
        .unwrap_or_else(|| "NONE".to_string())
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

fn task_metering_event_suffix(st: &StateStore, task_id: u64) -> String {
    st.get_task(task_id)
        .and_then(|task| task.metadata)
        .and_then(|metadata| metadata.metering)
        .map(|snapshot| format_task_metering_event_fields(&snapshot))
        .unwrap_or_default()
}

fn task_settlement_event_suffix(st: &StateStore, task_id: u64) -> String {
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
        // PR5 reconcile contract treats challenge as escrow-only movement;
        // event-level treasury_delta must stay neutral for challenge events.
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
    fn timeout_outcome_fields_stays_unknown_for_trailing_whitespace_terminal_labels() {
        assert_eq!(timeout_outcome_fields("Completed "), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("Slashed\n"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("Slashed\t"), ("false", "unknown"));
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
