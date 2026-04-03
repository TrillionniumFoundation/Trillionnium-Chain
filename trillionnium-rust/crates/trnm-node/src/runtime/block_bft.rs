use super::*;

pub(crate) struct BftStep {
    pub(crate) proposal_hash: String,
    pub(crate) result: BftHeightResult,
}

pub(crate) fn run_bft_step(
    args: &Args,
    runtime: &mut RuntimeState,
    metrics: &mut RuntimeMetrics,
    picked_len: usize,
) -> BftStep {
    let proposal_hash = hash32_hex(format!("h:{}:txs:{}", runtime.height, picked_len).as_bytes());
    let result = simulate_bft_height(
        runtime.height,
        &proposal_hash,
        args.validators,
        args.byzantine,
        args.bft_max_rounds,
        args.bft_fault_rounds,
        runtime.restored_lock.take(),
        &mut runtime.bft_jitter,
    );
    metrics.bft_observed_heights += 1;
    BftStep {
        proposal_hash,
        result,
    }
}

pub(crate) fn handle_uncommitted_bft(
    args: &Args,
    runtime: &mut RuntimeState,
    metrics: &mut RuntimeMetrics,
    picked: Vec<MockTx>,
    bft: &BftStep,
) -> Result<bool> {
    record_bft_common(metrics, &bft.result);
    println!(
        "[block] node={} height={} skipped reason=bft_no_commit proposal_hash={} prevote={} precommit={} rounds={} round_backoff_ms={} leader_missed={:?}",
        runtime.cfg.node_id,
        runtime.height,
        bft.proposal_hash,
        bft.result.prevote_count,
        bft.result.precommit_count,
        args.bft_max_rounds,
        bft.result.round_change_backoff_total_ms,
        bft.result.leader_missed_snapshot
    );
    requeue_uncommitted_txs(&mut runtime.mempool, picked);
    persist_height_wal(
        runtime,
        &bft.proposal_hash,
        None,
        bft.result.committed_round,
        false,
    )?;
    runtime.restored_lock = Some(bft.proposal_hash.clone());
    advance_or_stop(args, runtime, StopCondition::MaxBlocksOnly)
}

pub(crate) fn record_bft_commit(
    runtime: &RuntimeState,
    args: &Args,
    metrics: &mut RuntimeMetrics,
    bft: &BftStep,
) {
    record_bft_common(metrics, &bft.result);
    println!(
        "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} round_backoff_ms={} leader_missed={:?} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}",
        runtime.height,
        bft.result.committed_round,
        bft.result.prevote_count,
        bft.result.precommit_count,
        bft.result.round_changes,
        bft.result.round_change_backoff_total_ms,
        bft.result.leader_missed_snapshot,
        bft.result.double_vote_events,
        bft.result.auth_reject_bad_sig,
        bft.result.auth_reject_replay,
        bft.result.auth_reject_stale_nonce,
        bft.result.auth_reject_stale_nonce
    );
    let _ = args;
    metrics.bft_committed_heights += 1;
}

pub(crate) fn record_bft_common(metrics: &mut RuntimeMetrics, bft: &BftHeightResult) {
    metrics.bft_round_change_total += bft.round_changes;
    if bft.round_changes > 0 {
        metrics.bft_round_change_active_heights += 1;
    }
    metrics.bft_double_vote_total += bft.double_vote_events as u64;
    metrics.bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
    metrics.bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
    metrics.bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
    metrics.bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
    if bft.round_change_backoff_total_ms > 0 {
        metrics.bft_round_change_backoff_active_heights += 1;
    }
    metrics.bft_round_change_backoff_max_ms = metrics
        .bft_round_change_backoff_max_ms
        .max(bft.round_change_backoff_max_ms);
    let leader_missed_added = missed_proposals_added_since(
        &metrics.bft_leader_missed_previous_snapshot,
        &bft.leader_missed_snapshot,
    );
    if leader_missed_added > 0 {
        metrics.bft_leader_missed_active_heights += 1;
    }
    metrics.bft_leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
}
