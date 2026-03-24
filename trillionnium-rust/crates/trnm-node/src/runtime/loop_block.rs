use super::*;

pub(crate) fn execute_runtime_height(
    args: &Args,
    runtime: &mut RuntimeState,
    metrics: &mut RuntimeMetrics,
) -> Result<bool> {
    let block_start = Instant::now();
    let txs_per_block = args.txs_per_block.max(1);
    let picked = pick_txs_with_critical_guard(&mut runtime.mempool, txs_per_block);

    let bft = run_bft_step(args, runtime, metrics, picked.len());
    if !bft.result.committed {
        return handle_uncommitted_bft(args, runtime, metrics, picked, &bft);
    }
    record_bft_commit(runtime, args, metrics, &bft);

    let scheduler_start = Instant::now();
    let ordering_decision = decide_order_for_commit(
        &runtime.state,
        &picked,
        args.parallel_workers,
        args.enable_da_ordering_decouple,
        runtime.height,
    );
    let scheduler_elapsed_ms = scheduler_start.elapsed().as_millis();
    record_ordering_metrics(
        metrics,
        &runtime.state,
        &picked,
        &ordering_decision,
        scheduler_elapsed_ms,
    );

    let rl_advisor: Box<dyn RlAdvisor> = if args.rl_advisor_shadow {
        Box::new(ShadowOnlyRlAdvisor {
            topk: args.rl_advisor_shadow_topk,
        })
    } else {
        Box::new(DisabledRlAdvisor)
    };
    if let Some(advice) = rl_advisor.advise(&RlAdviceContext {
        height: runtime.height,
        ordered_ids: ordering_decision.ordered_ids.clone(),
    }) {
        println!(
            "[rl-shadow] height={} enabled=true reason={} baseline_ids={:?} suggested_ids={:?} applied=false",
            runtime.height,
            advice.reason,
            ordering_decision.ordered_ids,
            advice.suggested_ids
        );
    }

    let commit_start = Instant::now();
    let mut apply_outcome = apply_ordered_block(runtime, metrics, &picked, &ordering_decision);
    maybe_apply_timeouts(
        args,
        runtime,
        metrics,
        &mut apply_outcome.last_state_root_hex,
    );

    let root = if let Some(root) = apply_outcome.last_state_root_hex.clone() {
        root
    } else {
        let state_root_start = Instant::now();
        let root = hex::encode(runtime.state.state_root());
        apply_outcome.state_root_total_ms += state_root_start.elapsed().as_millis();
        root
    };
    let commit_elapsed_ms = commit_start.elapsed().as_millis();
    metrics.commit_samples_ms.push(commit_elapsed_ms);
    metrics
        .state_root_total_samples_ms
        .push(apply_outcome.state_root_total_ms);
    metrics
        .block_txs_samples
        .push(apply_outcome.applied as u128);
    metrics
        .block_groups_samples
        .push(ordering_decision.group_count as u128);
    metrics
        .rollback_samples
        .push(apply_outcome.rollback_count as u128);
    if apply_outcome.rollback_count > 0 {
        metrics.rollback_block_total += 1;
    }
    let elapsed_ms = block_start.elapsed().as_millis();
    metrics.finality_samples_ms.push(elapsed_ms);
    println!(
        "[block] node={} height={} txs={} groups={} rollback_count={} critical_wait_blocks={} scheduler_elapsed_ms={} preexec_elapsed_ms={} commit_elapsed_ms={} state_root_total_ms={} state_root={} elapsed_ms={}",
        runtime.cfg.node_id,
        runtime.height,
        apply_outcome.applied,
        ordering_decision.group_count,
        apply_outcome.rollback_count,
        ordering_decision.critical_wait_blocks,
        scheduler_elapsed_ms,
        ordering_decision.preexec_elapsed_ms,
        commit_elapsed_ms,
        apply_outcome.state_root_total_ms,
        root,
        elapsed_ms
    );

    persist_height_wal(
        runtime,
        &bft.proposal_hash,
        Some(root),
        bft.result.committed_round,
        true,
    )?;
    persist_checkpoint_if_needed(args, runtime)?;

    advance_or_stop(args, runtime, StopCondition::MaxBlocksOrEmpty)
}
