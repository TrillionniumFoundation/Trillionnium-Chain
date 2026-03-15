use anyhow::Result;
use std::{
    collections::HashSet,
    thread,
    time::{Duration, Instant},
};
use trnm_state::{CheckpointMeta, WalMeta};

use crate::accounting::EventDelta;
use crate::apply::{apply_one, verified_signer_of};
use crate::args::Args;
use crate::bft::height::simulate_bft_height;
use crate::bft::model::{BftJitterControl, LeaderHealth};
use crate::config::load_config;
use crate::demo::init_demo_state_and_mempool;
use crate::error_kind::classify_apply_error;
use crate::events::{emit_event, event_type_of, status_name};
use crate::hash::hash32_hex;
use crate::hot::{
    hot_object_tail_share_ppm, hot_object_top_label_share_ppm, missed_proposals_added_since,
    summarize_hot_objects,
};
use crate::mempool::{pick_txs_with_critical_guard, requeue_uncommitted_txs};
use crate::ordering::decide_order_for_commit;
use crate::recovery::{ensure_recoverable_wal_state, recover_wal_state};
use crate::risk::is_rejected_by_emergency_pause;
use crate::rl::build_rl_advisor;
use crate::rollback::{
    balance_deltas_from_snapshot, capture_rollback_snapshot, rollback_tx_snapshot,
};
use crate::summary::{emit_consensus_summary, ConsensusSummaryInputs};
use crate::timeout::scan_and_apply_timeouts;
use crate::txmeta::task_id_of;
use crate::types::{ConsensusWal, MockTx, RlAdviceContext};
use crate::wal::{
    load_checkpoint_meta, load_wal_meta_entries, persist_checkpoint_meta, persist_consensus_wal,
    persist_wal_meta_entries, resolve_wal_dir,
};

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
    let mut apply_error_total: u64 = 0;
    let mut apply_error_preexec_conflict_miss_total: u64 = 0;
    let mut apply_error_version_conflict_total: u64 = 0;
    let mut apply_error_invalid_transition_total: u64 = 0;
    let mut apply_error_deadline_exceeded_total: u64 = 0;
    let mut apply_error_semantic_fail_total: u64 = 0;
    let mut rollback_total: u64 = 0;
    let mut rollback_block_total: u64 = 0;
    let mut timeout_migrated_total: u64 = 0;
    let mut bft_observed_heights: u64 = 0;
    let mut bft_committed_heights: u64 = 0;
    let mut bft_round_change_total: u64 = 0;
    let mut bft_round_change_active_heights: u64 = 0;
    let mut bft_round_change_backoff_active_heights: u64 = 0;
    let mut bft_double_vote_total: u64 = 0;
    let mut bft_auth_reject_bad_sig_total: u64 = 0;
    let mut bft_auth_reject_replay_total: u64 = 0;
    let mut bft_auth_reject_stale_nonce_total: u64 = 0;
    let mut bft_round_change_backoff_total_ms: u64 = 0;
    let mut bft_round_change_backoff_max_ms: u64 = 0;
    let mut bft_leader_missed_active_heights: u64 = 0;
    let mut bft_leader_missed_previous_snapshot: Vec<u64> = vec![0; args.validators.max(1)];
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
        bft_observed_heights += 1;
        if !bft.committed {
            bft_round_change_total += bft.round_changes;
            if bft.round_changes > 0 {
                bft_round_change_active_heights += 1;
            }
            bft_double_vote_total += bft.double_vote_events as u64;
            bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
            bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
            bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
            bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
            if bft.round_change_backoff_total_ms > 0 {
                bft_round_change_backoff_active_heights += 1;
            }
            bft_round_change_backoff_max_ms =
                bft_round_change_backoff_max_ms.max(bft.round_change_backoff_max_ms);
            let leader_missed_added = missed_proposals_added_since(
                &bft_leader_missed_previous_snapshot,
                &bft.leader_missed_snapshot,
            );
            if leader_missed_added > 0 {
                bft_leader_missed_active_heights += 1;
            }
            bft_leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
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
            let wal_entry = WalMeta {
                height,
                round: bft.committed_round,
                proposal_hash: proposal_hash.clone(),
                committed: false,
                state_root_hex: hex::encode(state.state_root()),
                prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
            };
            wal_entries.push(wal_entry);
            persist_wal_meta_entries(&wal_dir, &wal_entries)?;
            persist_consensus_wal(
                &wal_dir,
                &ConsensusWal {
                    next_height: height + 1,
                    last_round: bft.committed_round,
                    locked_block_hash: Some(proposal_hash.clone()),
                },
            )?;
            if args.max_blocks > 0 && height >= args.max_blocks {
                println!("[node] reached max_blocks={}, exiting", args.max_blocks);
                break;
            }
            height += 1;
            thread::sleep(Duration::from_millis(args.block_ms));
            continue;
        }
        bft_round_change_total += bft.round_changes;
        if bft.round_changes > 0 {
            bft_round_change_active_heights += 1;
        }
        bft_double_vote_total += bft.double_vote_events as u64;
        bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
        bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
        bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
        bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
        if bft.round_change_backoff_total_ms > 0 {
            bft_round_change_backoff_active_heights += 1;
        }
        bft_round_change_backoff_max_ms =
            bft_round_change_backoff_max_ms.max(bft.round_change_backoff_max_ms);
        let leader_missed_added = missed_proposals_added_since(
            &bft_leader_missed_previous_snapshot,
            &bft.leader_missed_snapshot,
        );
        if leader_missed_added > 0 {
            bft_leader_missed_active_heights += 1;
        }
        bft_leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
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
        bft_committed_heights += 1;

        let mut applied = 0u64;
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
        let mut last_state_root_hex: Option<String> = None;
        let mut state_root_total_ms = 0u128;
        let mut rollback_count = 0u64;
        for id in ordering_decision.ordered_ids {
            let idx = (id - 1) as usize;
            let tx = picked[idx].clone();
            let task_id = task_id_of(&tx);
            let from_status = status_name(&state, task_id);

            if is_rejected_by_emergency_pause(state.is_emergency_paused(), &tx) {
                println!(
                    "[tx] rejected_by_pause height={} tx_id={} event_type={} emergency_pause=true",
                    height,
                    id,
                    event_type_of(&tx)
                );
                continue;
            }

            let before = capture_rollback_snapshot(&state, &tx);
            if let Err(e) = apply_one(&mut state, tx.clone(), height) {
                let err_kind = classify_apply_error(&e);
                let err_text = e.to_string();
                if err_kind == "resolve_approval_staged" {
                    applied += 1;
                    known_task_ids.insert(task_id);
                    let to_status = status_name(&state, task_id);
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
                    let signer = verified_signer_of(&state, &tx);
                    emit_event(
                        &state,
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
                    rollback_tx_snapshot(&mut state, before);
                    apply_error_total += 1;
                    rollback_total += 1;
                    rollback_count += 1;
                    match err_kind {
                        "version_conflict" => apply_error_version_conflict_total += 1,
                        "preexec_conflict_miss" => apply_error_preexec_conflict_miss_total += 1,
                        "invalid_transition" => apply_error_invalid_transition_total += 1,
                        "deadline_exceeded" => apply_error_deadline_exceeded_total += 1,
                        _ => apply_error_semantic_fail_total += 1,
                    }
                    println!(
                        "[tx] apply_error height={} tx_id={} err_kind={} err={} rollback=true",
                        height, id, err_kind, err_text
                    );
                }
            } else {
                applied += 1;
                known_task_ids.insert(task_id);
                let to_status = status_name(&state, task_id);
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
                let (treasury_delta, challenger_delta) =
                    balance_deltas_from_snapshot(&before, &state, challenger_account.as_deref());
                let signer = verified_signer_of(&state, &tx);
                emit_event(
                    &state,
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

        let scan_every = args.pouw_timeout_scan_every_blocks.max(1);
        if args.pouw_timeout_scan && height % scan_every == 0 {
            let migrated = scan_and_apply_timeouts(&mut state, &known_task_ids, height, 9_000_000);
            timeout_migrated_total += migrated;
            if migrated > 0 {
                last_state_root_hex = None;
                println!(
                    "[timeout] height={} migrated={} cumulative_migrated={}",
                    height, migrated, timeout_migrated_total
                );
            }
        }

        let root = if let Some(root) = last_state_root_hex.clone() {
            root
        } else {
            let state_root_start = Instant::now();
            let root = hex::encode(state.state_root());
            state_root_total_ms += state_root_start.elapsed().as_millis();
            root
        };
        let commit_elapsed_ms = commit_start.elapsed().as_millis();
        commit_samples_ms.push(commit_elapsed_ms);
        state_root_total_samples_ms.push(state_root_total_ms);
        block_txs_samples.push(applied as u128);
        block_groups_samples.push(group_count as u128);
        rollback_samples.push(rollback_count as u128);
        if rollback_count > 0 {
            rollback_block_total += 1;
        }
        let elapsed_ms = block_start.elapsed().as_millis();
        finality_samples_ms.push(elapsed_ms);
        println!(
            "[block] node={} height={} txs={} groups={} rollback_count={} critical_wait_blocks={} scheduler_elapsed_ms={} preexec_elapsed_ms={} commit_elapsed_ms={} state_root_total_ms={} state_root={} elapsed_ms={}",
            cfg.node_id,
            height,
            applied,
            group_count,
            rollback_count,
            ordering_decision.critical_wait_blocks,
            scheduler_elapsed_ms,
            ordering_decision.preexec_elapsed_ms,
            commit_elapsed_ms,
            state_root_total_ms,
            root,
            elapsed_ms
        );

        let wal_entry = WalMeta {
            height,
            round: bft.committed_round,
            proposal_hash: proposal_hash.clone(),
            committed: true,
            state_root_hex: root.clone(),
            prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
        };
        let wal_hash = wal_entry.content_hash_hex();
        wal_entries.push(wal_entry);
        persist_wal_meta_entries(&wal_dir, &wal_entries)?;

        if args.bft_checkpoint_interval > 0 && height % args.bft_checkpoint_interval == 0 {
            checkpoints.push(CheckpointMeta {
                height,
                state_root_hex: root.clone(),
                wal_entry_hash_hex: wal_hash,
            });
            persist_checkpoint_meta(&wal_dir, &checkpoints)?;
            println!("[bft-checkpoint] height={} state_root={}", height, root);
        }

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: height + 1,
                last_round: bft.committed_round,
                locked_block_hash: Some(proposal_hash.clone()),
            },
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
        apply_error_total,
        apply_error_preexec_conflict_miss_total,
        apply_error_version_conflict_total,
        apply_error_invalid_transition_total,
        apply_error_deadline_exceeded_total,
        apply_error_semantic_fail_total,
        rollback_total,
        rollback_block_total,
        timeout_migrated_total,
        bft_observed_heights,
        bft_committed_heights,
        bft_round_change_total,
        bft_round_change_active_heights,
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights,
        bft_round_change_backoff_max_ms,
        bft_leader_missed_active_heights,
        leader_health: &bft_jitter.leader_health,
        bft_double_vote_total,
        bft_auth_reject_bad_sig_total,
        bft_auth_reject_replay_total,
        bft_auth_reject_stale_nonce_total,
    });

    Ok(())
}
