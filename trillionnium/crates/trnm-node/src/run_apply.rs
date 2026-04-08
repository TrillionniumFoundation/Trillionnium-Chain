use std::collections::HashSet;
use std::time::Instant;

use trnm_state::StateStore;

use crate::accounting::EventDelta;
use crate::apply::{apply_one, verified_signer_of};
use crate::error_kind::classify_apply_error;
use crate::events::{emit_event, event_type_of, status_name};
use crate::risk::is_rejected_by_emergency_pause;
use crate::rollback::{
    balance_deltas_from_snapshot, capture_rollback_snapshot, rollback_tx_snapshot,
};
use crate::timeout::{scan_and_apply_timeouts, TIMEOUT_SCAN_MAX_TASK_ID};
use crate::txmeta::task_id_of;
use crate::types::MockTx;

#[derive(Debug, Clone, Default)]
pub(crate) struct ApplyRuntimeTelemetry {
    pub(crate) apply_error_total: u64,
    pub(crate) apply_error_preexec_conflict_miss_total: u64,
    pub(crate) apply_error_version_conflict_total: u64,
    pub(crate) apply_error_invalid_transition_total: u64,
    pub(crate) apply_error_deadline_exceeded_total: u64,
    pub(crate) apply_error_semantic_fail_total: u64,
    pub(crate) rollback_total: u64,
    pub(crate) timeout_migrated_total: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct AppliedHeightOutcome {
    pub(crate) applied: u64,
    pub(crate) rollback_count: u64,
    pub(crate) state_root_total_ms: u128,
    pub(crate) root: String,
}

pub(crate) fn apply_committed_height(
    state: &mut StateStore,
    picked: &[MockTx],
    ordered_ids: &[u64],
    height: u64,
    known_task_ids: &mut HashSet<u64>,
    telemetry: &mut ApplyRuntimeTelemetry,
    timeout_scan_enabled: bool,
    timeout_scan_every_blocks: u64,
) -> AppliedHeightOutcome {
    let mut applied = 0u64;
    let mut last_state_root_hex: Option<String> = None;
    let mut state_root_total_ms = 0u128;
    let mut rollback_count = 0u64;

    for &id in ordered_ids {
        let idx = (id - 1) as usize;
        let tx = picked[idx].clone();
        let task_id = task_id_of(&tx);
        let from_status = status_name(state, task_id);

        if is_rejected_by_emergency_pause(state.is_emergency_paused(), &tx) {
            println!(
                "[tx] rejected_by_pause height={} tx_id={} event_type={} emergency_pause=true",
                height,
                id,
                event_type_of(&tx)
            );
            continue;
        }

        let before = capture_rollback_snapshot(state, &tx);
        if let Err(e) = apply_one(state, tx.clone(), height) {
            let err_kind = classify_apply_error(&e);
            let err_text = e.to_string();
            if err_kind == "resolve_approval_staged" {
                applied += 1;
                known_task_ids.insert(task_id);
                let to_status = status_name(state, task_id);
                let state_root_start = Instant::now();
                let root = hex::encode(state.state_root());
                state_root_total_ms += state_root_start.elapsed().as_millis();
                last_state_root_hex = Some(root.clone());
                let challenger_account: Option<String> = match &tx {
                    MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
                    MockTx::Resolve { .. } => {
                        before.task.as_ref().and_then(|t| t.challenger.clone())
                    }
                    _ => None,
                };
                let treasury_delta = EventDelta {
                    numeric: Some(0),
                    text: "0".to_string(),
                };
                let challenger_delta = challenger_account.as_ref().map(|_| EventDelta {
                    numeric: Some(0),
                    text: "0".to_string(),
                });
                let signer = verified_signer_of(state, &tx);
                emit_event(
                    state,
                    &tx,
                    &signer,
                    id,
                    height,
                    &from_status,
                    &to_status,
                    &root,
                    &treasury_delta,
                    challenger_delta.as_ref(),
                    challenger_account.as_deref(),
                    Some(err_kind),
                );
            } else {
                rollback_tx_snapshot(state, before);
                telemetry.apply_error_total = telemetry.apply_error_total.saturating_add(1);
                telemetry.rollback_total = telemetry.rollback_total.saturating_add(1);
                rollback_count = rollback_count.saturating_add(1);
                match err_kind {
                    "version_conflict" => {
                        telemetry.apply_error_version_conflict_total = telemetry
                            .apply_error_version_conflict_total
                            .saturating_add(1)
                    }
                    "preexec_conflict_miss" => {
                        telemetry.apply_error_preexec_conflict_miss_total = telemetry
                            .apply_error_preexec_conflict_miss_total
                            .saturating_add(1)
                    }
                    "invalid_transition" => {
                        telemetry.apply_error_invalid_transition_total = telemetry
                            .apply_error_invalid_transition_total
                            .saturating_add(1)
                    }
                    "deadline_exceeded" => {
                        telemetry.apply_error_deadline_exceeded_total = telemetry
                            .apply_error_deadline_exceeded_total
                            .saturating_add(1)
                    }
                    _ => {
                        telemetry.apply_error_semantic_fail_total = telemetry
                            .apply_error_semantic_fail_total
                            .saturating_add(1)
                    }
                }
                println!(
                    "[tx] apply_error height={} tx_id={} err_kind={} err={} rollback=true",
                    height, id, err_kind, err_text
                );
            }
        } else {
            applied += 1;
            known_task_ids.insert(task_id);
            let to_status = status_name(state, task_id);
            let state_root_start = Instant::now();
            let root = hex::encode(state.state_root());
            state_root_total_ms += state_root_start.elapsed().as_millis();
            last_state_root_hex = Some(root.clone());
            let challenger_account: Option<String> = match &tx {
                MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
                MockTx::Resolve { .. } => before.task.as_ref().and_then(|t| t.challenger.clone()),
                _ => None,
            };
            let (treasury_delta, challenger_delta) =
                balance_deltas_from_snapshot(&before, state, challenger_account.as_deref());
            let signer = verified_signer_of(state, &tx);
            emit_event(
                state,
                &tx,
                &signer,
                id,
                height,
                &from_status,
                &to_status,
                &root,
                &treasury_delta,
                challenger_delta.as_ref(),
                challenger_account.as_deref(),
                None,
            );
        }
    }

    let scan_every = timeout_scan_every_blocks.max(1);
    if timeout_scan_enabled && height % scan_every == 0 {
        let migrated = scan_and_apply_timeouts(state, known_task_ids, height, TIMEOUT_SCAN_MAX_TASK_ID);
        telemetry.timeout_migrated_total = telemetry.timeout_migrated_total.saturating_add(migrated);
        if migrated > 0 {
            last_state_root_hex = None;
            println!(
                "[timeout] height={} migrated={} cumulative_migrated={}",
                height, migrated, telemetry.timeout_migrated_total
            );
        }
    }

    let root = if let Some(root) = last_state_root_hex {
        root
    } else {
        let state_root_start = Instant::now();
        let root = hex::encode(state.state_root());
        state_root_total_ms += state_root_start.elapsed().as_millis();
        root
    };

    AppliedHeightOutcome {
        applied,
        rollback_count,
        state_root_total_ms,
        root,
    }
}
