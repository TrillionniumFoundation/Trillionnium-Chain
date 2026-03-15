use anyhow::Result;
use std::{
    collections::HashSet,
    thread,
    time::{Duration, Instant},
};
use crate::args::Args;
use crate::bft::height::simulate_bft_height;
use crate::run_apply::{apply_committed_height, ApplyRuntimeTelemetry};
use crate::run_bft::BftHeightTelemetry;
use crate::run_bootstrap::{bootstrap_node_runtime, BootstrappedNodeRuntime};
use crate::run_metrics::RuntimeMetrics;
use crate::run_persist::{persist_committed_height, persist_uncommitted_height};
use crate::hash::hash32_hex;
use crate::mempool::{pick_txs_with_critical_guard, requeue_uncommitted_txs};
use crate::ordering::decide_order_for_commit;
use crate::rl::build_rl_advisor;
use crate::types::RlAdviceContext;

pub(crate) fn run_node(args: Args) -> Result<()> {
    let boot = bootstrap_node_runtime(&args)?;
    let BootstrappedNodeRuntime {
        cfg,
        wal_dir,
        restored_lock,
        height,
        state,
        mempool,
        wal_entries,
        checkpoints,
        bft_jitter,
    } = boot;

    let mut restored_lock = restored_lock;
    let mut height = height;
    let mut state = state;
    let mut mempool = mempool;
    let mut wal_entries = wal_entries;
    let mut checkpoints = checkpoints;
    let mut bft_jitter = bft_jitter;
    let mut known_task_ids: HashSet<u64> = HashSet::new();
    let mut runtime_metrics = RuntimeMetrics::default();
    let mut apply_telemetry = ApplyRuntimeTelemetry::default();
    let mut bft_telemetry = BftHeightTelemetry::new(args.validators);

    loop {
        let block_start = Instant::now();
        let txs_per_block = args.txs_per_block.max(1);
        let picked = pick_txs_with_critical_guard(&mut mempool, txs_per_block);

        let proposal_hash = hash32_hex(format!("h:{}:txs:{}", height, picked.len()).as_bytes());
        let bft = simulate_bft_height(
            height,
            &proposal_hash,
            args.validators,
            args.byzantine,
            args.bft_max_rounds,
            args.bft_fault_rounds,
            restored_lock.take(),
            &mut bft_jitter,
        );
        bft_telemetry.record(&bft);
        if !bft.committed {
            println!(
                "[block] node={} height={} skipped reason=bft_no_commit proposal_hash={} prevote={} precommit={} rounds={} round_backoff_ms={} leader_missed={:?}",
                cfg.node_id,
                height,
                proposal_hash,
                bft.prevote_count,
                bft.precommit_count,
                args.bft_max_rounds,
                bft.round_change_backoff_total_ms,
                bft.leader_missed_snapshot
            );
            requeue_uncommitted_txs(&mut mempool, picked);
            persist_uncommitted_height(
                &wal_dir,
                &mut wal_entries,
                height,
                bft.committed_round,
                &proposal_hash,
                hex::encode(state.state_root()),
            )?;
            if args.max_blocks > 0 && height >= args.max_blocks {
                println!("[node] reached max_blocks={}, exiting", args.max_blocks);
                break;
            }
            height += 1;
            thread::sleep(Duration::from_millis(args.block_ms));
            continue;
        }
        println!(
            "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} round_backoff_ms={} leader_missed={:?} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale_nonce={}",
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
            bft.auth_reject_stale_nonce
        );

        let scheduler_start = Instant::now();
        let ordering_decision = decide_order_for_commit(
            &state,
            &picked,
            args.parallel_workers,
            args.enable_da_ordering_decouple,
            height,
        );
        let scheduler_elapsed_ms = scheduler_start.elapsed().as_millis();
        runtime_metrics.record_ordering(&state, &picked, &ordering_decision, scheduler_elapsed_ms);
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

        let commit_start = Instant::now();
        let apply_outcome = apply_committed_height(
            &mut state,
            &picked,
            &ordering_decision.ordered_ids,
            height,
            &mut known_task_ids,
            &mut apply_telemetry,
            args.pouw_timeout_scan,
            args.pouw_timeout_scan_every_blocks,
        );
        let commit_elapsed_ms = commit_start.elapsed().as_millis();
        let elapsed_ms = block_start.elapsed().as_millis();
        runtime_metrics.record_commit(&apply_outcome, group_count, elapsed_ms, commit_elapsed_ms);
        println!(
            "[block] node={} height={} txs={} groups={} rollback_count={} critical_wait_blocks={} scheduler_elapsed_ms={} preexec_elapsed_ms={} commit_elapsed_ms={} state_root_total_ms={} state_root={} elapsed_ms={}",
            cfg.node_id,
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
            &wal_dir,
            &mut wal_entries,
            &mut checkpoints,
            height,
            bft.committed_round,
            &proposal_hash,
            &apply_outcome.root,
            args.bft_checkpoint_interval,
        )?;

        if args.max_blocks > 0 && height >= args.max_blocks {
            println!("[node] reached max_blocks={}, exiting", args.max_blocks);
            break;
        }
        if mempool.is_empty() {
            println!("[node] mempool empty, exiting");
            break;
        }

        height += 1;
        thread::sleep(Duration::from_millis(args.block_ms));
    }

    runtime_metrics.emit_summary(&apply_telemetry, &bft_telemetry, &bft_jitter.leader_health);

    Ok(())
}
