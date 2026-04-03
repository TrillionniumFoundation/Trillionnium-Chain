use anyhow::Result;
use std::{collections::HashSet, collections::VecDeque, path::Path};
use trnm_state::{CheckpointMeta, StateStore, WalMeta};

use crate::args::Args;
use crate::bft::height::simulate_bft_height;
use crate::bft::model::BftJitterControl;
use crate::hash::hash32_hex;
use crate::mempool::{pick_txs_with_critical_guard, requeue_uncommitted_txs};
use crate::ordering::decide_order_for_commit;
use crate::rl::build_rl_advisor;
use crate::run_apply::{apply_committed_height, ApplyRuntimeTelemetry};
use crate::run_bft::BftHeightTelemetry;
use crate::run_metrics::RuntimeMetrics;
use crate::run_persist::{persist_committed_height, persist_uncommitted_height};
use crate::types::{MockTx, RlAdviceContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeightLoopControl {
    Continue,
    Exit,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_height_step(
    args: &Args,
    node_id: &str,
    height: u64,
    restored_lock: &mut Option<String>,
    state: &mut StateStore,
    mempool: &mut VecDeque<MockTx>,
    known_task_ids: &mut HashSet<u64>,
    wal_dir: &Path,
    wal_entries: &mut Vec<WalMeta>,
    checkpoints: &mut Vec<CheckpointMeta>,
    bft_jitter: &mut BftJitterControl,
    runtime_metrics: &mut RuntimeMetrics,
    apply_telemetry: &mut ApplyRuntimeTelemetry,
    bft_telemetry: &mut BftHeightTelemetry,
) -> Result<HeightLoopControl> {
    let block_start = std::time::Instant::now();
    let txs_per_block = args.txs_per_block.max(1);
    let picked = pick_txs_with_critical_guard(mempool, txs_per_block);

    let proposal_hash = hash32_hex(format!("h:{}:txs:{}", height, picked.len()).as_bytes());
    let bft = simulate_bft_height(
        height,
        &proposal_hash,
        args.validators,
        args.byzantine,
        args.bft_max_rounds,
        args.bft_fault_rounds,
        restored_lock.take(),
        bft_jitter,
    );
    bft_telemetry.record(&bft);
    if !bft.committed {
        println!(
            "[block] node={} height={} skipped reason=bft_no_commit proposal_hash={} prevote={} precommit={} rounds={} round_backoff_ms={} leader_missed={:?}",
            node_id,
            height,
            proposal_hash,
            bft.prevote_count,
            bft.precommit_count,
            args.bft_max_rounds,
            bft.round_change_backoff_total_ms,
            bft.leader_missed_snapshot
        );
        requeue_uncommitted_txs(mempool, picked);
        persist_uncommitted_height(
            wal_dir,
            wal_entries,
            height,
            bft.committed_round,
            &proposal_hash,
            hex::encode(state.state_root()),
        )?;
        if args.max_blocks > 0 && height >= args.max_blocks {
            println!("[node] reached max_blocks={}, exiting", args.max_blocks);
            return Ok(HeightLoopControl::Exit);
        }
        return Ok(HeightLoopControl::Continue);
    }
    println!(
        "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} round_backoff_ms={} leader_missed={:?} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}",
        height,
        bft.committed_round,
        bft.prevote_count,
        bft.precommit_count,
        bft.round_changes,
        bft.round_change_backoff_total_ms,
        bft.leader_missed_snapshot,
        bft.double_vote_events,
        bft.auth_reject_bad_sig,
        bft.auth_reject_replay,
        bft.auth_reject_stale_nonce,
        bft.auth_reject_stale_nonce
    );

    let scheduler_start = std::time::Instant::now();
    let ordering_decision = decide_order_for_commit(
        state,
        &picked,
        args.parallel_workers,
        args.enable_da_ordering_decouple,
        height,
    );
    let scheduler_elapsed_ms = scheduler_start.elapsed().as_millis();
    runtime_metrics.record_ordering(state, &picked, &ordering_decision, scheduler_elapsed_ms);
    let group_count = ordering_decision.group_count;

    let rl_advisor = build_rl_advisor(args.rl_advisor_shadow, args.rl_advisor_shadow_topk);
    if let Some(advice) = rl_advisor.advise(&RlAdviceContext {
        height,
        ordered_ids: ordering_decision.ordered_ids.clone(),
    }) {
        println!(
            "[rl-shadow] height={} enabled=true reason={} baseline_ids={:?} suggested_ids={:?} applied=false",
            height,
            advice.reason,
            ordering_decision.ordered_ids,
            advice.suggested_ids
        );
    }

    let commit_start = std::time::Instant::now();
    let apply_outcome = apply_committed_height(
        state,
        &picked,
        &ordering_decision.ordered_ids,
        height,
        known_task_ids,
        apply_telemetry,
        args.pouw_timeout_scan,
        args.pouw_timeout_scan_every_blocks,
    );
    let commit_elapsed_ms = commit_start.elapsed().as_millis();
    let elapsed_ms = block_start.elapsed().as_millis();
    runtime_metrics.record_commit(&apply_outcome, group_count, elapsed_ms, commit_elapsed_ms);
    println!(
        "[block] node={} height={} txs={} groups={} rollback_count={} critical_wait_blocks={} scheduler_elapsed_ms={} preexec_elapsed_ms={} commit_elapsed_ms={} state_root_total_ms={} state_root={} elapsed_ms={}",
        node_id,
        height,
        apply_outcome.applied,
        group_count,
        apply_outcome.rollback_count,
        ordering_decision.critical_wait_blocks,
        scheduler_elapsed_ms,
        ordering_decision.preexec_elapsed_ms,
        commit_elapsed_ms,
        apply_outcome.state_root_total_ms,
        apply_outcome.root,
        elapsed_ms
    );

    persist_committed_height(
        wal_dir,
        wal_entries,
        checkpoints,
        height,
        bft.committed_round,
        &proposal_hash,
        &apply_outcome.root,
        args.bft_checkpoint_interval,
    )?;

    if args.max_blocks > 0 && height >= args.max_blocks {
        println!("[node] reached max_blocks={}, exiting", args.max_blocks);
        return Ok(HeightLoopControl::Exit);
    }
    if mempool.is_empty() {
        println!("[node] mempool empty, exiting");
        return Ok(HeightLoopControl::Exit);
    }

    Ok(HeightLoopControl::Continue)
}
