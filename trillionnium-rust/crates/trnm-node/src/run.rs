use anyhow::Result;
use std::{
    collections::HashSet,
    thread,
    time::{Duration, Instant},
};
use crate::args::Args;
use crate::bft::height::simulate_bft_height;
use crate::bft::model::{BftJitterControl, LeaderHealth};
use crate::run_apply::{apply_committed_height, ApplyRuntimeTelemetry};
use crate::run_bft::BftHeightTelemetry;
use crate::run_persist::{persist_committed_height, persist_uncommitted_height};
use crate::config::load_config;
use crate::demo::init_demo_state_and_mempool;
use crate::hash::hash32_hex;
use crate::hot::{
    hot_object_tail_share_ppm, hot_object_top_label_share_ppm, summarize_hot_objects,
};
use crate::mempool::{pick_txs_with_critical_guard, requeue_uncommitted_txs};
use crate::ordering::decide_order_for_commit;
use crate::recovery::{ensure_recoverable_wal_state, recover_wal_state};
use crate::rl::build_rl_advisor;
use crate::summary::{emit_consensus_summary, ConsensusSummaryInputs};
use crate::types::RlAdviceContext;
use crate::wal::{load_checkpoint_meta, load_wal_meta_entries, resolve_wal_dir};

pub(crate) fn run_node(args: Args) -> Result<()> {
    let cfg = load_config(&args.config)?;

    println!("[node] start");
    println!(
        "[node] id={} rpc={} p2p={}",
        cfg.node_id, cfg.rpc_addr, cfg.p2p_addr
    );
    println!(
        "[node] block_ms={} max_blocks={}",
        args.block_ms, args.max_blocks
    );
    println!(
        "[node] load demo_tasks={} demo_keys={}",
        args.demo_tasks, args.demo_keys
    );
    println!("[node] parallel_workers={}", args.parallel_workers);
    println!(
        "[node] bft validators={} byzantine={} max_rounds={} fault_rounds={} missed_threshold={} penalty_rounds={} rc_backoff_ms={} rc_backoff_cap_ms={} wal_dir={} wal_mode={:?} checkpoint_interval={} timeout_scan={} timeout_scan_every_blocks={} da_ordering_decouple={} rl_shadow={} rl_shadow_topk={}",
        args.validators,
        args.byzantine,
        args.bft_max_rounds,
        args.bft_fault_rounds,
        args.bft_missed_proposal_threshold,
        args.bft_leader_penalty_rounds,
        args.bft_round_change_backoff_ms,
        args.bft_round_change_backoff_max_ms,
        args.bft_wal_dir,
        args.bft_wal_mode,
        args.bft_checkpoint_interval,
        args.pouw_timeout_scan,
        args.pouw_timeout_scan_every_blocks,
        args.enable_da_ordering_decouple,
        args.rl_advisor_shadow,
        args.rl_advisor_shadow_topk
    );

    let (wal_dir, wal_notice) = resolve_wal_dir(&args)?;
    if let Some(notice) = wal_notice {
        println!("{}", notice);
    }
    println!("[bft-wal] using wal_dir={}", wal_dir.display());
    let recovered = recover_wal_state(&wal_dir)?;
    let mut restored_lock: Option<String> = recovered.restored_lock.clone();
    let mut height: u64 = recovered.next_height.max(1);
    println!(
        "[bft-recover] restored height={} lock={} checkpoint={} truncated={} metadata_only_recovery={}",
        height,
        restored_lock.clone().unwrap_or_else(|| "none".to_string()),
        recovered
            .last_checkpoint
            .as_ref()
            .map(|cp| cp.height.to_string())
            .unwrap_or_else(|| "none".to_string()),
        recovered.truncated,
        recovered.metadata_only_recovery
    );
    ensure_recoverable_wal_state(&wal_dir, &recovered)?;

    let (mut state, mut mempool) = init_demo_state_and_mempool(args.demo_tasks, args.demo_keys);
    let mut known_task_ids: HashSet<u64> = HashSet::new();
    let mut finality_samples_ms: Vec<u128> = Vec::new();
    let mut scheduler_samples_ms: Vec<u128> = Vec::new();
    let mut preexec_samples_ms: Vec<u128> = Vec::new();
    let mut commit_samples_ms: Vec<u128> = Vec::new();
    let mut state_root_total_samples_ms: Vec<u128> = Vec::new();
    let mut critical_wait_blocks_samples: Vec<u128> = Vec::new();
    let mut critical_wait_active_heights: u64 = 0;
    let mut critical_wait_total: u64 = 0;
    let mut block_txs_samples: Vec<u128> = Vec::new();
    let mut block_groups_samples: Vec<u128> = Vec::new();
    let mut rollback_samples: Vec<u128> = Vec::new();
    let mut avg_group_size_samples: Vec<u128> = Vec::new();
    let mut hot_object_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_top_label_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_tail_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_active_heights: u64 = 0;
    let mut hot_object_active_top_label_share_total_ppm: u128 = 0;
    let mut hot_object_active_tail_share_total_ppm: u128 = 0;
    let mut preexec_reject_total: u64 = 0;
    let mut preexec_reject_active_heights: u64 = 0;
    let mut apply_telemetry = ApplyRuntimeTelemetry::default();
    let mut rollback_block_total: u64 = 0;
    let mut bft_telemetry = BftHeightTelemetry::new(args.validators);
    let mut wal_entries = load_wal_meta_entries(&wal_dir)?;
    let mut checkpoints = load_checkpoint_meta(&wal_dir)?;
    let mut bft_jitter = BftJitterControl {
        missed_threshold: args.bft_missed_proposal_threshold,
        penalty_rounds: args.bft_leader_penalty_rounds,
        round_change_backoff_ms: args.bft_round_change_backoff_ms,
        round_change_backoff_cap_ms: args.bft_round_change_backoff_max_ms,
        leader_health: vec![LeaderHealth::default(); args.validators.max(1)],
    };

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
        scheduler_samples_ms.push(scheduler_elapsed_ms);
        preexec_samples_ms.push(ordering_decision.preexec_elapsed_ms);
        critical_wait_blocks_samples.push(ordering_decision.critical_wait_blocks as u128);
        critical_wait_total += ordering_decision.critical_wait_blocks;
        if ordering_decision.critical_wait_blocks > 0 {
            critical_wait_active_heights += 1;
        }
        preexec_reject_total += ordering_decision.rejected;
        if ordering_decision.rejected > 0 {
            preexec_reject_active_heights += 1;
        }
        let group_count = ordering_decision.group_count;
        let avg_group_size = if group_count == 0 {
            0u128
        } else {
            ((picked.len() as u128) * 1000) / (group_count as u128)
        };
        avg_group_size_samples.push(avg_group_size);
        let hot_object_summary = summarize_hot_objects(&state, &picked);
        let hot_object_share_ppm = if picked.is_empty() {
            0u128
        } else {
            ((hot_object_summary.hot_tx_count as u128) * 1_000_000) / (picked.len() as u128)
        };
        let hot_object_top_label_share_ppm = hot_object_top_label_share_ppm(&hot_object_summary);
        let hot_object_tail_share_ppm = hot_object_tail_share_ppm(&hot_object_summary);
        hot_object_share_samples_ppm.push(hot_object_share_ppm);
        hot_object_top_label_share_samples_ppm.push(hot_object_top_label_share_ppm);
        hot_object_tail_share_samples_ppm.push(hot_object_tail_share_ppm);
        if hot_object_summary.hot_tx_count > 0 {
            hot_object_active_heights += 1;
            hot_object_active_top_label_share_total_ppm =
                hot_object_active_top_label_share_total_ppm
                    .saturating_add(hot_object_top_label_share_ppm);
            hot_object_active_tail_share_total_ppm =
                hot_object_active_tail_share_total_ppm.saturating_add(hot_object_tail_share_ppm);
        }

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
        commit_samples_ms.push(commit_elapsed_ms);
        state_root_total_samples_ms.push(apply_outcome.state_root_total_ms);
        block_txs_samples.push(apply_outcome.applied as u128);
        block_groups_samples.push(group_count as u128);
        rollback_samples.push(apply_outcome.rollback_count as u128);
        if apply_outcome.rollback_count > 0 {
            rollback_block_total += 1;
        }
        let elapsed_ms = block_start.elapsed().as_millis();
        finality_samples_ms.push(elapsed_ms);
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

    emit_consensus_summary(ConsensusSummaryInputs {
        finality_samples_ms: &finality_samples_ms,
        scheduler_samples_ms: &scheduler_samples_ms,
        preexec_samples_ms: &preexec_samples_ms,
        commit_samples_ms: &commit_samples_ms,
        state_root_total_samples_ms: &state_root_total_samples_ms,
        critical_wait_blocks_samples: &critical_wait_blocks_samples,
        block_txs_samples: &block_txs_samples,
        block_groups_samples: &block_groups_samples,
        rollback_samples: &rollback_samples,
        avg_group_size_samples: &avg_group_size_samples,
        hot_object_share_samples_ppm: &hot_object_share_samples_ppm,
        hot_object_top_label_share_samples_ppm: &hot_object_top_label_share_samples_ppm,
        hot_object_tail_share_samples_ppm: &hot_object_tail_share_samples_ppm,
        hot_object_active_heights,
        hot_object_active_top_label_share_total_ppm,
        hot_object_active_tail_share_total_ppm,
        critical_wait_active_heights,
        critical_wait_total,
        preexec_reject_total,
        preexec_reject_active_heights,
        apply_error_total: apply_telemetry.apply_error_total,
        apply_error_preexec_conflict_miss_total: apply_telemetry.apply_error_preexec_conflict_miss_total,
        apply_error_version_conflict_total: apply_telemetry.apply_error_version_conflict_total,
        apply_error_invalid_transition_total: apply_telemetry.apply_error_invalid_transition_total,
        apply_error_deadline_exceeded_total: apply_telemetry.apply_error_deadline_exceeded_total,
        apply_error_semantic_fail_total: apply_telemetry.apply_error_semantic_fail_total,
        rollback_total: apply_telemetry.rollback_total,
        rollback_block_total,
        timeout_migrated_total: apply_telemetry.timeout_migrated_total,
        bft_observed_heights: bft_telemetry.observed_heights,
        bft_committed_heights: bft_telemetry.committed_heights,
        bft_round_change_total: bft_telemetry.round_change_total,
        bft_round_change_active_heights: bft_telemetry.round_change_active_heights,
        bft_round_change_backoff_total_ms: bft_telemetry.round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights: bft_telemetry.round_change_backoff_active_heights,
        bft_round_change_backoff_max_ms: bft_telemetry.round_change_backoff_max_ms,
        bft_leader_missed_active_heights: bft_telemetry.leader_missed_active_heights,
        leader_health: &bft_jitter.leader_health,
        bft_double_vote_total: bft_telemetry.double_vote_total,
        bft_auth_reject_bad_sig_total: bft_telemetry.auth_reject_bad_sig_total,
        bft_auth_reject_replay_total: bft_telemetry.auth_reject_replay_total,
        bft_auth_reject_stale_nonce_total: bft_telemetry.auth_reject_stale_nonce_total,
    });

    Ok(())
}
