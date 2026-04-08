use crate::bft::model::LeaderHealth;
use crate::metrics::{
    average_or_zero, finality_budget_share_ppm, gap_percent_bps, max_or_zero, percentile,
    ratio_milli_u64, ratio_percent_bps, ratio_ppm, ratio_ppm_u64, wall_time_share_ppm,
};

pub(crate) struct ConsensusSummaryInputs<'a> {
    pub(crate) finality_samples_ms: &'a [u128],
    pub(crate) scheduler_samples_ms: &'a [u128],
    pub(crate) preexec_samples_ms: &'a [u128],
    pub(crate) commit_samples_ms: &'a [u128],
    pub(crate) state_root_total_samples_ms: &'a [u128],
    pub(crate) critical_wait_blocks_samples: &'a [u128],
    pub(crate) block_txs_samples: &'a [u128],
    pub(crate) block_groups_samples: &'a [u128],
    pub(crate) rollback_samples: &'a [u128],
    pub(crate) avg_group_size_samples: &'a [u128],
    pub(crate) hot_object_share_samples_ppm: &'a [u128],
    pub(crate) hot_object_top_label_share_samples_ppm: &'a [u128],
    pub(crate) hot_object_tail_share_samples_ppm: &'a [u128],
    pub(crate) hot_object_active_heights: u64,
    pub(crate) hot_object_active_top_label_share_total_ppm: u128,
    pub(crate) hot_object_active_tail_share_total_ppm: u128,
    pub(crate) critical_wait_active_heights: u64,
    pub(crate) critical_wait_total: u64,
    pub(crate) preexec_reject_total: u64,
    pub(crate) preexec_reject_active_heights: u64,
    pub(crate) apply_error_total: u64,
    pub(crate) apply_error_preexec_conflict_miss_total: u64,
    pub(crate) apply_error_version_conflict_total: u64,
    pub(crate) apply_error_invalid_transition_total: u64,
    pub(crate) apply_error_deadline_exceeded_total: u64,
    pub(crate) apply_error_semantic_fail_total: u64,
    pub(crate) rollback_total: u64,
    pub(crate) rollback_block_total: u64,
    pub(crate) timeout_migrated_total: u64,
    pub(crate) bft_observed_heights: u64,
    pub(crate) bft_committed_heights: u64,
    pub(crate) bft_round_change_total: u64,
    pub(crate) bft_round_change_active_heights: u64,
    pub(crate) bft_round_change_backoff_total_ms: u64,
    pub(crate) bft_round_change_backoff_active_heights: u64,
    pub(crate) bft_round_change_backoff_max_ms: u64,
    pub(crate) bft_leader_missed_active_heights: u64,
    pub(crate) leader_health: &'a [LeaderHealth],
    pub(crate) bft_double_vote_total: u64,
    pub(crate) bft_auth_reject_bad_sig_total: u64,
    pub(crate) bft_auth_reject_replay_total: u64,
    pub(crate) bft_auth_reject_stale_nonce_total: u64,
}

pub(crate) fn emit_consensus_summary(inputs: ConsensusSummaryInputs<'_>) {
    // Preserve the legacy `bft_auth_reject_stale_total` operator field as an
    // alias of the canonical stale-nonce counter until the metrics contract is
    // frozen across node/rpc/worker surfaces.
    let bft_auth_reject_stale_total = inputs.bft_auth_reject_stale_nonce_total;

    let finality_p50 = percentile(inputs.finality_samples_ms.to_vec(), 0.50);
    let finality_p95 = percentile(inputs.finality_samples_ms.to_vec(), 0.95);
    let scheduler_p50 = percentile(inputs.scheduler_samples_ms.to_vec(), 0.50);
    let scheduler_p95 = percentile(inputs.scheduler_samples_ms.to_vec(), 0.95);
    let preexec_p50 = percentile(inputs.preexec_samples_ms.to_vec(), 0.50);
    let preexec_p95 = percentile(inputs.preexec_samples_ms.to_vec(), 0.95);
    let commit_p50 = percentile(inputs.commit_samples_ms.to_vec(), 0.50);
    let commit_p95 = percentile(inputs.commit_samples_ms.to_vec(), 0.95);
    let state_root_total_p50 = percentile(inputs.state_root_total_samples_ms.to_vec(), 0.50);
    let state_root_total_p95 = percentile(inputs.state_root_total_samples_ms.to_vec(), 0.95);
    let critical_wait_blocks_p50 = percentile(inputs.critical_wait_blocks_samples.to_vec(), 0.50);
    let critical_wait_blocks_p95 = percentile(inputs.critical_wait_blocks_samples.to_vec(), 0.95);
    let block_txs_p50 = percentile(inputs.block_txs_samples.to_vec(), 0.50);
    let block_txs_p95 = percentile(inputs.block_txs_samples.to_vec(), 0.95);
    let block_groups_p50 = percentile(inputs.block_groups_samples.to_vec(), 0.50);
    let block_groups_p95 = percentile(inputs.block_groups_samples.to_vec(), 0.95);
    let rollback_p50 = percentile(inputs.rollback_samples.to_vec(), 0.50);
    let rollback_p95 = percentile(inputs.rollback_samples.to_vec(), 0.95);
    let avg_group_size_p50 = percentile(inputs.avg_group_size_samples.to_vec(), 0.50);
    let avg_group_size_p95 = percentile(inputs.avg_group_size_samples.to_vec(), 0.95);
    let hot_object_share_p50_ppm = percentile(inputs.hot_object_share_samples_ppm.to_vec(), 0.50);
    let hot_object_share_p95_ppm = percentile(inputs.hot_object_share_samples_ppm.to_vec(), 0.95);
    let hot_object_top_label_share_p50_ppm =
        percentile(inputs.hot_object_top_label_share_samples_ppm.to_vec(), 0.50);
    let hot_object_top_label_share_p95_ppm =
        percentile(inputs.hot_object_top_label_share_samples_ppm.to_vec(), 0.95);
    let hot_object_tail_share_p50_ppm =
        percentile(inputs.hot_object_tail_share_samples_ppm.to_vec(), 0.50);
    let hot_object_tail_share_p95_ppm =
        percentile(inputs.hot_object_tail_share_samples_ppm.to_vec(), 0.95);
    let finality_max = max_or_zero(inputs.finality_samples_ms);
    let scheduler_max = max_or_zero(inputs.scheduler_samples_ms);
    let preexec_max = max_or_zero(inputs.preexec_samples_ms);
    let commit_max = max_or_zero(inputs.commit_samples_ms);
    let state_root_total_max = max_or_zero(inputs.state_root_total_samples_ms);
    let critical_wait_blocks_max = max_or_zero(inputs.critical_wait_blocks_samples);
    let block_txs_max = max_or_zero(inputs.block_txs_samples);
    let block_groups_max = max_or_zero(inputs.block_groups_samples);
    let rollback_max = max_or_zero(inputs.rollback_samples);
    let avg_group_size_max = max_or_zero(inputs.avg_group_size_samples);
    let hot_object_share_max_ppm = max_or_zero(inputs.hot_object_share_samples_ppm);
    let hot_object_top_label_share_max_ppm =
        max_or_zero(inputs.hot_object_top_label_share_samples_ppm);
    let hot_object_tail_share_max_ppm = max_or_zero(inputs.hot_object_tail_share_samples_ppm);
    let finality_avg = average_or_zero(inputs.finality_samples_ms);
    let scheduler_avg = average_or_zero(inputs.scheduler_samples_ms);
    let preexec_avg = average_or_zero(inputs.preexec_samples_ms);
    let commit_avg = average_or_zero(inputs.commit_samples_ms);
    let state_root_total_avg = average_or_zero(inputs.state_root_total_samples_ms);
    let critical_wait_blocks_avg = average_or_zero(inputs.critical_wait_blocks_samples);
    let rollback_avg = average_or_zero(inputs.rollback_samples);
    let avg_group_size_avg = average_or_zero(inputs.avg_group_size_samples);
    let hot_object_share_avg_ppm = average_or_zero(inputs.hot_object_share_samples_ppm);
    let hot_object_top_label_share_avg_ppm =
        average_or_zero(inputs.hot_object_top_label_share_samples_ppm);
    let hot_object_tail_share_avg_ppm = average_or_zero(inputs.hot_object_tail_share_samples_ppm);
    let hot_object_active_top_label_share_avg_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        inputs.hot_object_active_top_label_share_total_ppm
            / inputs.hot_object_active_heights as u128
    };
    let hot_object_active_tail_share_avg_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        inputs.hot_object_active_tail_share_total_ppm / inputs.hot_object_active_heights as u128
    };
    let hot_object_active_height_rate_ppm = ratio_ppm_u64(
        inputs.hot_object_active_heights,
        inputs.finality_samples_ms.len() as u64,
    );
    let hot_object_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.hot_object_active_heights,
        inputs.bft_observed_heights,
    );
    let hot_object_active_height_share_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        (inputs.hot_object_active_top_label_share_total_ppm
            + inputs.hot_object_active_tail_share_total_ppm)
            / inputs.hot_object_active_heights as u128
    };
    let scheduler_share_avg_ppm = ratio_ppm(scheduler_avg, finality_avg);
    let scheduler_peak_share_ppm = ratio_ppm(scheduler_max, finality_max);
    let preexec_share_avg_ppm = ratio_ppm(preexec_avg, finality_avg);
    let commit_share_avg_ppm = ratio_ppm(commit_avg, finality_avg);
    let commit_peak_share_ppm = ratio_ppm(commit_max, finality_max);
    let state_root_total_share_avg_ppm = ratio_ppm(state_root_total_avg, finality_avg);
    let state_root_total_peak_share_ppm = ratio_ppm(state_root_total_max, finality_max);
    let rollback_share_avg_ppm = ratio_ppm(rollback_avg, finality_avg);
    let rollback_peak_share_ppm = ratio_ppm(rollback_max, finality_max);
    let preexec_peak_share_ppm = ratio_ppm(preexec_max, finality_max);
    let rollback_block_rate_ppm = ratio_ppm_u64(
        inputs.rollback_block_total,
        inputs.finality_samples_ms.len() as u64,
    );
    let rollback_active_heights = inputs.rollback_block_total;
    let rollback_active_height_rate_ppm = rollback_block_rate_ppm;
    let rollback_active_observed_height_rate_ppm =
        ratio_ppm_u64(rollback_active_heights, inputs.bft_observed_heights);
    let rollback_density_avg = if inputs.rollback_block_total == 0 {
        0
    } else {
        inputs.rollback_total / inputs.rollback_block_total
    };
    let rollback_density_avg_milli =
        ratio_milli_u64(inputs.rollback_total, inputs.rollback_block_total);
    let rollback_active_height_share_ppm =
        finality_budget_share_ppm(rollback_density_avg_milli, finality_avg);
    let preexec_conflict_miss_share_bps = ratio_percent_bps(
        inputs.apply_error_preexec_conflict_miss_total as u128,
        inputs.preexec_reject_total as u128,
    );
    let preexec_reject_density_avg = if inputs.preexec_reject_active_heights == 0 {
        0
    } else {
        inputs.preexec_reject_total / inputs.preexec_reject_active_heights
    };
    let preexec_reject_density_avg_milli = ratio_milli_u64(
        inputs.preexec_reject_total,
        inputs.preexec_reject_active_heights,
    );
    let preexec_reject_active_height_rate_ppm = ratio_ppm_u64(
        inputs.preexec_reject_active_heights,
        inputs.bft_committed_heights,
    );
    let preexec_reject_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.preexec_reject_active_heights,
        inputs.bft_observed_heights,
    );
    let preexec_reject_active_height_share_ppm =
        finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);
    let apply_error_rollback_share_bps = ratio_percent_bps(
        inputs.rollback_total as u128,
        inputs.apply_error_total as u128,
    );
    let rollback_block_rate = if inputs.finality_samples_ms.is_empty() {
        0.0
    } else {
        inputs.rollback_block_total as f64 / inputs.finality_samples_ms.len() as f64
    };
    let critical_wait_density_ppm = ratio_ppm(critical_wait_blocks_avg, finality_avg);
    let critical_wait_peak_density_ppm = ratio_ppm(critical_wait_blocks_max, finality_max);
    let critical_wait_active_height_rate_ppm = ratio_ppm_u64(
        inputs.critical_wait_active_heights,
        inputs.finality_samples_ms.len() as u64,
    );
    let critical_wait_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.critical_wait_active_heights,
        inputs.bft_observed_heights,
    );
    let critical_wait_density_avg = if inputs.critical_wait_active_heights == 0 {
        0
    } else {
        inputs.critical_wait_total / inputs.critical_wait_active_heights
    };
    let critical_wait_density_avg_milli = ratio_milli_u64(
        inputs.critical_wait_total,
        inputs.critical_wait_active_heights,
    );
    let critical_wait_active_height_share_ppm =
        finality_budget_share_ppm(critical_wait_density_avg_milli, finality_avg);
    let preexec_reject_share_bps = ratio_percent_bps(
        inputs.preexec_reject_total as u128,
        inputs.apply_error_total as u128,
    );
    let unprofiled_finality_share_bps = gap_percent_bps(
        finality_avg,
        scheduler_avg
            .saturating_add(preexec_avg)
            .saturating_add(commit_avg),
        state_root_total_avg,
    );
    let bft_round_change_per_height_ppm =
        ratio_ppm_u64(inputs.bft_round_change_total, inputs.bft_committed_heights);
    let bft_round_change_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_active_heights,
        inputs.bft_committed_heights,
    );
    let bft_round_change_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_active_heights,
        inputs.bft_observed_heights,
    );
    let bft_round_change_density_avg = if inputs.bft_round_change_active_heights == 0 {
        0
    } else {
        inputs.bft_round_change_total / inputs.bft_round_change_active_heights
    };
    let bft_round_change_density_avg_milli = ratio_milli_u64(
        inputs.bft_round_change_total,
        inputs.bft_round_change_active_heights,
    );
    let bft_round_change_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg);
    let bft_round_change_backoff_avg_ms = if inputs.bft_round_change_total == 0 {
        0
    } else {
        inputs.bft_round_change_backoff_total_ms / inputs.bft_round_change_total
    };
    let bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_backoff_active_heights,
        inputs.bft_committed_heights,
    );
    let bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_backoff_active_heights,
        inputs.bft_observed_heights,
    );
    let bft_round_change_backoff_density_avg_ms = if inputs.bft_round_change_backoff_active_heights
        == 0
    {
        0
    } else {
        inputs.bft_round_change_backoff_total_ms / inputs.bft_round_change_backoff_active_heights
    };
    let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        inputs.bft_round_change_backoff_total_ms,
        inputs.bft_round_change_backoff_active_heights,
    );
    let bft_round_change_backoff_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);
    let bft_round_change_backoff_wall_share_ppm = wall_time_share_ppm(
        inputs.bft_round_change_backoff_total_ms,
        inputs.bft_committed_heights,
        finality_avg,
    );
    let bft_round_change_backoff_share_ppm = bft_round_change_backoff_wall_share_ppm;
    let bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(inputs.bft_committed_heights, inputs.bft_observed_heights);
    let bft_skipped_height_total = inputs
        .bft_observed_heights
        .saturating_sub(inputs.bft_committed_heights);
    let bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(bft_skipped_height_total, inputs.bft_observed_heights);
    let recovery_error_rate = if inputs.finality_samples_ms.is_empty() {
        0.0
    } else {
        inputs.apply_error_total as f64 / inputs.finality_samples_ms.len() as f64
    };
    let leader_missed_final: Vec<u64> = inputs
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .collect();
    let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
    let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
    let bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
    let bft_leader_missed_active_validators = leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        bft_leader_missed_active_validators,
        leader_missed_final.len() as u64,
    );
    let bft_leader_missed_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_leader_missed_active_heights,
        inputs.bft_committed_heights,
    );
    let bft_leader_missed_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_leader_missed_active_heights,
        inputs.bft_observed_heights,
    );
    let bft_leader_missed_density_avg = if inputs.bft_leader_missed_active_heights == 0 {
        0
    } else {
        bft_leader_missed_total / inputs.bft_leader_missed_active_heights
    };
    let bft_leader_missed_density_avg_milli = ratio_milli_u64(
        bft_leader_missed_total,
        inputs.bft_leader_missed_active_heights,
    );
    let bft_leader_missed_active_height_share_ppm =
        finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg);

    println!(
        "[consensus] finality_avg_ms={} finality_p50_ms={} finality_p95_ms={} finality_max_ms={} scheduler_elapsed_avg_ms={} scheduler_elapsed_p50_ms={} scheduler_elapsed_p95_ms={} scheduler_elapsed_max_ms={} scheduler_share_avg_ppm={} scheduler_peak_share_ppm={} preexec_elapsed_avg_ms={} preexec_elapsed_p50_ms={} preexec_elapsed_p95_ms={} preexec_elapsed_max_ms={} preexec_share_avg_ppm={} preexec_peak_share_ppm={} commit_elapsed_avg_ms={} commit_elapsed_p50_ms={} commit_elapsed_p95_ms={} commit_elapsed_max_ms={} commit_share_avg_ppm={} commit_peak_share_ppm={} state_root_total_avg_ms={} state_root_total_p50_ms={} state_root_total_p95_ms={} state_root_total_max_ms={} state_root_total_share_avg_ppm={} state_root_total_peak_share_ppm={} unprofiled_finality_share_bps={} critical_wait_blocks_avg={} critical_wait_blocks_p50={} critical_wait_blocks_p95={} critical_wait_blocks_max={} critical_wait_density_ppm={} critical_wait_peak_density_ppm={} critical_wait_active_heights={} critical_wait_active_height_rate_ppm={} critical_wait_active_observed_height_rate_ppm={} critical_wait_density_avg={} critical_wait_density_avg_milli={} critical_wait_active_height_share_ppm={} block_txs_p50={} block_txs_p95={} block_txs_max={} block_groups_p50={} block_groups_p95={} block_groups_max={} avg_group_size_avg_milli={} avg_group_size_p50_milli={} avg_group_size_p95_milli={} avg_group_size_max_milli={} hot_object_share_avg_ppm={} hot_object_share_p50_ppm={} hot_object_share_p95_ppm={} hot_object_share_max_ppm={} hot_object_active_heights={} hot_object_active_height_rate_ppm={} hot_object_active_observed_height_rate_ppm={} hot_object_active_height_share_ppm={} hot_object_top_label_share_avg_ppm={} hot_object_top_label_share_p50_ppm={} hot_object_top_label_share_p95_ppm={} hot_object_top_label_share_max_ppm={} hot_object_active_top_label_share_avg_ppm={} hot_object_tail_share_avg_ppm={} hot_object_tail_share_p50_ppm={} hot_object_tail_share_p95_ppm={} hot_object_tail_share_max_ppm={} hot_object_active_tail_share_avg_ppm={} rollback_count_avg={} rollback_count_p50={} rollback_count_p95={} rollback_count_max={} rollback_share_avg_ppm={} rollback_peak_share_ppm={} rollback_block_total={} rollback_active_heights={} rollback_block_rate={:.6} rollback_block_rate_ppm={} rollback_active_height_rate_ppm={} rollback_active_observed_height_rate_ppm={} rollback_density_avg={} rollback_density_avg_milli={} rollback_active_height_share_ppm={} preexec_reject_total={} preexec_reject_active_heights={} preexec_reject_density_avg={} preexec_reject_density_avg_milli={} preexec_reject_active_height_rate_ppm={} preexec_reject_active_observed_height_rate_ppm={} preexec_reject_active_height_share_ppm={} preexec_reject_share_bps={} apply_error_total={} apply_error_preexec_conflict_miss_total={} preexec_conflict_miss_share_bps={} apply_error_version_conflict_total={} apply_error_invalid_transition_total={} apply_error_deadline_exceeded_total={} apply_error_semantic_fail_total={} rollback_total={} apply_error_rollback_share_bps={} timeout_migrated_total={} recovery_error_rate={:.6} bft_observed_heights={} bft_committed_heights={} bft_commit_observed_height_rate_ppm={} bft_skipped_height_total={} bft_skipped_observed_height_rate_ppm={} bft_round_change_total={} bft_round_change_per_height_ppm={} bft_round_change_active_heights={} bft_round_change_active_height_rate_ppm={} bft_round_change_active_observed_height_rate_ppm={} bft_round_change_density_avg={} bft_round_change_density_avg_milli={} bft_round_change_active_height_share_ppm={} bft_round_change_backoff_total_ms={} bft_round_change_backoff_avg_ms={} bft_round_change_backoff_active_heights={} bft_round_change_backoff_active_height_rate_ppm={} bft_round_change_backoff_active_observed_height_rate_ppm={} bft_round_change_backoff_density_avg_ms={} bft_round_change_backoff_density_avg_milli={} bft_round_change_backoff_active_height_share_ppm={} bft_round_change_backoff_max_ms={} bft_round_change_backoff_wall_share_ppm={} bft_round_change_backoff_share_ppm={} bft_leader_missed_total={} bft_leader_missed_max={} bft_leader_missed_top_share_ppm={} bft_leader_missed_active_validators={} bft_leader_missed_active_validator_share_ppm={} bft_leader_missed_active_heights={} bft_leader_missed_active_height_rate_ppm={} bft_leader_missed_active_observed_height_rate_ppm={} bft_leader_missed_density_avg={} bft_leader_missed_density_avg_milli={} bft_leader_missed_active_height_share_ppm={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_total={} bft_auth_reject_stale_nonce_total={}",
        finality_avg,
        finality_p50,
        finality_p95,
        finality_max,
        scheduler_avg,
        scheduler_p50,
        scheduler_p95,
        scheduler_max,
        scheduler_share_avg_ppm,
        scheduler_peak_share_ppm,
        preexec_avg,
        preexec_p50,
        preexec_p95,
        preexec_max,
        preexec_share_avg_ppm,
        preexec_peak_share_ppm,
        commit_avg,
        commit_p50,
        commit_p95,
        commit_max,
        commit_share_avg_ppm,
        commit_peak_share_ppm,
        state_root_total_avg,
        state_root_total_p50,
        state_root_total_p95,
        state_root_total_max,
        state_root_total_share_avg_ppm,
        state_root_total_peak_share_ppm,
        unprofiled_finality_share_bps,
        critical_wait_blocks_avg,
        critical_wait_blocks_p50,
        critical_wait_blocks_p95,
        critical_wait_blocks_max,
        critical_wait_density_ppm,
        critical_wait_peak_density_ppm,
        inputs.critical_wait_active_heights,
        critical_wait_active_height_rate_ppm,
        critical_wait_active_observed_height_rate_ppm,
        critical_wait_density_avg,
        critical_wait_density_avg_milli,
        critical_wait_active_height_share_ppm,
        block_txs_p50,
        block_txs_p95,
        block_txs_max,
        block_groups_p50,
        block_groups_p95,
        block_groups_max,
        avg_group_size_avg,
        avg_group_size_p50,
        avg_group_size_p95,
        avg_group_size_max,
        hot_object_share_avg_ppm,
        hot_object_share_p50_ppm,
        hot_object_share_p95_ppm,
        hot_object_share_max_ppm,
        inputs.hot_object_active_heights,
        hot_object_active_height_rate_ppm,
        hot_object_active_observed_height_rate_ppm,
        hot_object_active_height_share_ppm,
        hot_object_top_label_share_avg_ppm,
        hot_object_top_label_share_p50_ppm,
        hot_object_top_label_share_p95_ppm,
        hot_object_top_label_share_max_ppm,
        hot_object_active_top_label_share_avg_ppm,
        hot_object_tail_share_avg_ppm,
        hot_object_tail_share_p50_ppm,
        hot_object_tail_share_p95_ppm,
        hot_object_tail_share_max_ppm,
        hot_object_active_tail_share_avg_ppm,
        rollback_avg,
        rollback_p50,
        rollback_p95,
        rollback_max,
        rollback_share_avg_ppm,
        rollback_peak_share_ppm,
        inputs.rollback_block_total,
        rollback_active_heights,
        rollback_block_rate,
        rollback_block_rate_ppm,
        rollback_active_height_rate_ppm,
        rollback_active_observed_height_rate_ppm,
        rollback_density_avg,
        rollback_density_avg_milli,
        rollback_active_height_share_ppm,
        inputs.preexec_reject_total,
        inputs.preexec_reject_active_heights,
        preexec_reject_density_avg,
        preexec_reject_density_avg_milli,
        preexec_reject_active_height_rate_ppm,
        preexec_reject_active_observed_height_rate_ppm,
        preexec_reject_active_height_share_ppm,
        preexec_reject_share_bps,
        inputs.apply_error_total,
        inputs.apply_error_preexec_conflict_miss_total,
        preexec_conflict_miss_share_bps,
        inputs.apply_error_version_conflict_total,
        inputs.apply_error_invalid_transition_total,
        inputs.apply_error_deadline_exceeded_total,
        inputs.apply_error_semantic_fail_total,
        inputs.rollback_total,
        apply_error_rollback_share_bps,
        inputs.timeout_migrated_total,
        recovery_error_rate,
        inputs.bft_observed_heights,
        inputs.bft_committed_heights,
        bft_commit_observed_height_rate_ppm,
        bft_skipped_height_total,
        bft_skipped_observed_height_rate_ppm,
        inputs.bft_round_change_total,
        bft_round_change_per_height_ppm,
        inputs.bft_round_change_active_heights,
        bft_round_change_active_height_rate_ppm,
        bft_round_change_active_observed_height_rate_ppm,
        bft_round_change_density_avg,
        bft_round_change_density_avg_milli,
        bft_round_change_active_height_share_ppm,
        inputs.bft_round_change_backoff_total_ms,
        bft_round_change_backoff_avg_ms,
        inputs.bft_round_change_backoff_active_heights,
        bft_round_change_backoff_active_height_rate_ppm,
        bft_round_change_backoff_active_observed_height_rate_ppm,
        bft_round_change_backoff_density_avg_ms,
        bft_round_change_backoff_density_avg_milli,
        bft_round_change_backoff_active_height_share_ppm,
        inputs.bft_round_change_backoff_max_ms,
        bft_round_change_backoff_wall_share_ppm,
        bft_round_change_backoff_share_ppm,
        bft_leader_missed_total,
        bft_leader_missed_max,
        bft_leader_missed_top_share_ppm,
        bft_leader_missed_active_validators,
        bft_leader_missed_active_validator_share_ppm,
        inputs.bft_leader_missed_active_heights,
        bft_leader_missed_active_height_rate_ppm,
        bft_leader_missed_active_observed_height_rate_ppm,
        bft_leader_missed_density_avg,
        bft_leader_missed_density_avg_milli,
        bft_leader_missed_active_height_share_ppm,
        leader_missed_final,
        inputs.bft_double_vote_total,
        inputs.bft_auth_reject_bad_sig_total,
        inputs.bft_auth_reject_replay_total,
        bft_auth_reject_stale_total,
        inputs.bft_auth_reject_stale_nonce_total
    );
}
