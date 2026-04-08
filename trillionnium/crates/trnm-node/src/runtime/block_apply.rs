use super::*;

pub(crate) struct BlockApplyOutcome {
    pub(crate) applied: u64,
    pub(crate) rollback_count: u64,
    pub(crate) state_root_total_ms: u128,
    pub(crate) last_state_root_hex: Option<String>,
}

pub(crate) fn apply_ordered_block(
    runtime: &mut RuntimeState,
    metrics: &mut RuntimeMetrics,
    picked: &[MockTx],
    ordering_decision: &OrderingDecision,
) -> BlockApplyOutcome {
    let mut applied = 0u64;
    let mut last_state_root_hex: Option<String> = None;
    let mut state_root_total_ms = 0u128;
    let mut rollback_count = 0u64;
    for id in ordering_decision.ordered_ids.iter().copied() {
        let idx = (id - 1) as usize;
        let tx = picked[idx].clone();
        let task_id = task_id_of(&tx);
        let from_status = status_name(&runtime.state, task_id);

        if is_rejected_by_emergency_pause(runtime.state.is_emergency_paused(), &tx) {
            println!(
                "[tx] rejected_by_pause height={} tx_id={} event_type={} emergency_pause=true",
                runtime.height,
                id,
                event_type_of(&tx)
            );
            continue;
        }

        let before = capture_rollback_snapshot(&runtime.state, &tx);
        if let Err(e) = apply_one(&mut runtime.state, tx.clone(), runtime.height) {
            let err_kind = classify_apply_error(&e);
            let err_text = e.to_string();
            if err_kind == "resolve_approval_staged" {
                applied += 1;
                runtime.known_task_ids.insert(task_id);
                let to_status = status_name(&runtime.state, task_id);
                let state_root_start = Instant::now();
                let root = hex::encode(runtime.state.state_root());
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
                let signer = verified_signer_of(&runtime.state, &tx);
                emit_event(
                    &runtime.state,
                    &tx,
                    &signer,
                    id,
                    runtime.height,
                    &from_status,
                    &to_status,
                    &root,
                    &treasury_delta,
                    challenger_delta.as_ref(),
                    challenger_account.as_deref(),
                    Some(err_kind),
                );
            } else {
                rollback_tx_snapshot(&mut runtime.state, before);
                metrics.apply_error_total += 1;
                metrics.rollback_total += 1;
                rollback_count += 1;
                match err_kind {
                    "version_conflict" => metrics.apply_error_version_conflict_total += 1,
                    "preexec_conflict_miss" => metrics.apply_error_preexec_conflict_miss_total += 1,
                    "invalid_transition" => metrics.apply_error_invalid_transition_total += 1,
                    "deadline_exceeded" => metrics.apply_error_deadline_exceeded_total += 1,
                    _ => metrics.apply_error_semantic_fail_total += 1,
                }
                println!(
                    "[tx] apply_error height={} tx_id={} err_kind={} err={} rollback=true",
                    runtime.height, id, err_kind, err_text
                );
            }
        } else {
            applied += 1;
            runtime.known_task_ids.insert(task_id);
            let to_status = status_name(&runtime.state, task_id);
            let state_root_start = Instant::now();
            let root = hex::encode(runtime.state.state_root());
            state_root_total_ms += state_root_start.elapsed().as_millis();
            last_state_root_hex = Some(root.clone());
            let challenger_account: Option<String> = match &tx {
                MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
                MockTx::Resolve { .. } => before.task.as_ref().and_then(|t| t.challenger.clone()),
                _ => None,
            };
            let (treasury_delta, challenger_delta) = balance_deltas_from_snapshot(
                &before,
                &runtime.state,
                challenger_account.as_deref(),
            );
            let signer = verified_signer_of(&runtime.state, &tx);
            emit_event(
                &runtime.state,
                &tx,
                &signer,
                id,
                runtime.height,
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

    BlockApplyOutcome {
        applied,
        rollback_count,
        state_root_total_ms,
        last_state_root_hex,
    }
}

pub(crate) fn record_ordering_metrics(
    metrics: &mut RuntimeMetrics,
    state: &StateStore,
    picked: &[MockTx],
    ordering_decision: &OrderingDecision,
    scheduler_elapsed_ms: u128,
) {
    metrics.scheduler_samples_ms.push(scheduler_elapsed_ms);
    metrics
        .preexec_samples_ms
        .push(ordering_decision.preexec_elapsed_ms);
    metrics
        .critical_wait_blocks_samples
        .push(ordering_decision.critical_wait_blocks as u128);
    metrics.critical_wait_total += ordering_decision.critical_wait_blocks;
    if ordering_decision.critical_wait_blocks > 0 {
        metrics.critical_wait_active_heights += 1;
    }
    metrics.preexec_reject_total += ordering_decision.rejected;
    if ordering_decision.rejected > 0 {
        metrics.preexec_reject_active_heights += 1;
    }
    let group_count = ordering_decision.group_count;
    let avg_group_size = if group_count == 0 {
        0u128
    } else {
        ((picked.len() as u128) * 1000) / (group_count as u128)
    };
    metrics.avg_group_size_samples.push(avg_group_size);
    let hot_object_summary = summarize_hot_objects(state, picked);
    let hot_object_share_ppm = if picked.is_empty() {
        0u128
    } else {
        ((hot_object_summary.hot_tx_count as u128) * 1_000_000) / (picked.len() as u128)
    };
    let hot_object_top_label_share_ppm = hot_object_top_label_share_ppm(&hot_object_summary);
    let hot_object_tail_share_ppm = hot_object_tail_share_ppm(&hot_object_summary);
    metrics
        .hot_object_share_samples_ppm
        .push(hot_object_share_ppm);
    metrics
        .hot_object_top_label_share_samples_ppm
        .push(hot_object_top_label_share_ppm);
    metrics
        .hot_object_tail_share_samples_ppm
        .push(hot_object_tail_share_ppm);
    if hot_object_summary.hot_tx_count > 0 {
        metrics.hot_object_active_heights += 1;
        metrics.hot_object_active_top_label_share_total_ppm = metrics
            .hot_object_active_top_label_share_total_ppm
            .saturating_add(hot_object_top_label_share_ppm);
        metrics.hot_object_active_tail_share_total_ppm = metrics
            .hot_object_active_tail_share_total_ppm
            .saturating_add(hot_object_tail_share_ppm);
    }
}
