use super::*;

pub(crate) fn format_runtime_summary_line(
    metrics: &RuntimeMetrics,
    stats: &RuntimeSummaryStats,
) -> String {
    format!(
        "[consensus] finality_avg_ms={} finality_p50_ms={} finality_p95_ms={} finality_max_ms={} scheduler_elapsed_avg_ms={} scheduler_elapsed_p50_ms={} scheduler_elapsed_p95_ms={} scheduler_elapsed_max_ms={} scheduler_share_avg_ppm={} scheduler_peak_share_ppm={} preexec_elapsed_avg_ms={} preexec_elapsed_p50_ms={} preexec_elapsed_p95_ms={} preexec_elapsed_max_ms={} preexec_share_avg_ppm={} preexec_peak_share_ppm={} commit_elapsed_avg_ms={} commit_elapsed_p50_ms={} commit_elapsed_p95_ms={} commit_elapsed_max_ms={} commit_share_avg_ppm={} commit_peak_share_ppm={} state_root_total_avg_ms={} state_root_total_p50_ms={} state_root_total_p95_ms={} state_root_total_max_ms={} state_root_total_share_avg_ppm={} state_root_total_peak_share_ppm={} unprofiled_finality_share_bps={} critical_wait_blocks_avg={} critical_wait_blocks_p50={} critical_wait_blocks_p95={} critical_wait_blocks_max={} critical_wait_density_ppm={} critical_wait_peak_density_ppm={} critical_wait_active_heights={} critical_wait_active_height_rate_ppm={} critical_wait_active_observed_height_rate_ppm={} critical_wait_density_avg={} critical_wait_density_avg_milli={} critical_wait_active_height_share_ppm={} block_txs_p50={} block_txs_p95={} block_txs_max={} block_groups_p50={} block_groups_p95={} block_groups_max={} avg_group_size_avg_milli={} avg_group_size_p50_milli={} avg_group_size_p95_milli={} avg_group_size_max_milli={} hot_object_share_avg_ppm={} hot_object_share_p50_ppm={} hot_object_share_p95_ppm={} hot_object_share_max_ppm={} hot_object_active_heights={} hot_object_active_height_rate_ppm={} hot_object_active_observed_height_rate_ppm={} hot_object_active_height_share_ppm={} hot_object_top_label_share_avg_ppm={} hot_object_top_label_share_p50_ppm={} hot_object_top_label_share_p95_ppm={} hot_object_top_label_share_max_ppm={} hot_object_active_top_label_share_avg_ppm={} hot_object_tail_share_avg_ppm={} hot_object_tail_share_p50_ppm={} hot_object_tail_share_p95_ppm={} hot_object_tail_share_max_ppm={} hot_object_active_tail_share_avg_ppm={} rollback_count_avg={} rollback_count_p50={} rollback_count_p95={} rollback_count_max={} rollback_share_avg_ppm={} rollback_peak_share_ppm={} rollback_block_total={} rollback_active_heights={} rollback_block_rate={:.6} rollback_block_rate_ppm={} rollback_active_height_rate_ppm={} rollback_active_observed_height_rate_ppm={} rollback_density_avg={} rollback_density_avg_milli={} rollback_active_height_share_ppm={} preexec_reject_total={} preexec_reject_active_heights={} preexec_reject_density_avg={} preexec_reject_density_avg_milli={} preexec_reject_active_height_rate_ppm={} preexec_reject_active_observed_height_rate_ppm={} preexec_reject_active_height_share_ppm={} preexec_reject_share_bps={} apply_error_total={} apply_error_preexec_conflict_miss_total={} preexec_conflict_miss_share_bps={} apply_error_version_conflict_total={} apply_error_invalid_transition_total={} apply_error_deadline_exceeded_total={} apply_error_semantic_fail_total={} rollback_total={} apply_error_rollback_share_bps={} timeout_migrated_total={} recovery_error_rate={:.6} bft_observed_heights={} bft_committed_heights={} bft_commit_observed_height_rate_ppm={} bft_skipped_height_total={} bft_skipped_observed_height_rate_ppm={} bft_round_change_total={} bft_round_change_per_height_ppm={} bft_round_change_active_heights={} bft_round_change_active_height_rate_ppm={} bft_round_change_active_observed_height_rate_ppm={} bft_round_change_density_avg={} bft_round_change_density_avg_milli={} bft_round_change_active_height_share_ppm={} bft_round_change_backoff_total_ms={} bft_round_change_backoff_avg_ms={} bft_round_change_backoff_active_heights={} bft_round_change_backoff_active_height_rate_ppm={} bft_round_change_backoff_active_observed_height_rate_ppm={} bft_round_change_backoff_density_avg_ms={} bft_round_change_backoff_density_avg_milli={} bft_round_change_backoff_active_height_share_ppm={} bft_round_change_backoff_max_ms={} bft_round_change_backoff_wall_share_ppm={} bft_round_change_backoff_share_ppm={} bft_leader_missed_total={} bft_leader_missed_max={} bft_leader_missed_top_share_ppm={} bft_leader_missed_active_validators={} bft_leader_missed_active_validator_share_ppm={} bft_leader_missed_active_heights={} bft_leader_missed_active_height_rate_ppm={} bft_leader_missed_active_observed_height_rate_ppm={} bft_leader_missed_density_avg={} bft_leader_missed_density_avg_milli={} bft_leader_missed_active_height_share_ppm={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_nonce_total={}",
        stats.finality_avg, stats.finality_p50, stats.finality_p95, stats.finality_max, stats.scheduler_avg, stats.scheduler_p50,
        stats.scheduler_p95, stats.scheduler_max, stats.scheduler_share_avg_ppm, stats.scheduler_peak_share_ppm,
        stats.preexec_avg, stats.preexec_p50, stats.preexec_p95, stats.preexec_max, stats.preexec_share_avg_ppm,
        stats.preexec_peak_share_ppm, stats.commit_avg, stats.commit_p50, stats.commit_p95, stats.commit_max,
        stats.commit_share_avg_ppm, stats.commit_peak_share_ppm, stats.state_root_total_avg, stats.state_root_total_p50,
        stats.state_root_total_p95, stats.state_root_total_max, stats.state_root_total_share_avg_ppm,
        stats.state_root_total_peak_share_ppm, stats.unprofiled_finality_share_bps, stats.critical_wait_blocks_avg,
        stats.critical_wait_blocks_p50, stats.critical_wait_blocks_p95, stats.critical_wait_blocks_max,
        stats.critical_wait_density_ppm, stats.critical_wait_peak_density_ppm, metrics.critical_wait_active_heights,
        stats.critical_wait_active_height_rate_ppm, stats.critical_wait_active_observed_height_rate_ppm,
        stats.critical_wait_density_avg, stats.critical_wait_density_avg_milli, stats.critical_wait_active_height_share_ppm,
        stats.block_txs_p50, stats.block_txs_p95, stats.block_txs_max, stats.block_groups_p50, stats.block_groups_p95,
        stats.block_groups_max, stats.avg_group_size_avg, stats.avg_group_size_p50, stats.avg_group_size_p95,
        stats.avg_group_size_max, stats.hot_object_share_avg_ppm, stats.hot_object_share_p50_ppm,
        stats.hot_object_share_p95_ppm, stats.hot_object_share_max_ppm, metrics.hot_object_active_heights,
        stats.hot_object_active_height_rate_ppm, stats.hot_object_active_observed_height_rate_ppm,
        stats.hot_object_active_height_share_ppm, stats.hot_object_top_label_share_avg_ppm,
        stats.hot_object_top_label_share_p50_ppm, stats.hot_object_top_label_share_p95_ppm,
        stats.hot_object_top_label_share_max_ppm, stats.hot_object_active_top_label_share_avg_ppm,
        stats.hot_object_tail_share_avg_ppm, stats.hot_object_tail_share_p50_ppm, stats.hot_object_tail_share_p95_ppm,
        stats.hot_object_tail_share_max_ppm, stats.hot_object_active_tail_share_avg_ppm, stats.rollback_avg,
        stats.rollback_p50, stats.rollback_p95, stats.rollback_max, stats.rollback_share_avg_ppm, stats.rollback_peak_share_ppm,
        metrics.rollback_block_total, stats.rollback_active_heights, stats.rollback_block_rate,
        stats.rollback_block_rate_ppm, stats.rollback_active_height_rate_ppm,
        stats.rollback_active_observed_height_rate_ppm, stats.rollback_density_avg, stats.rollback_density_avg_milli,
        stats.rollback_active_height_share_ppm, metrics.preexec_reject_total,
        metrics.preexec_reject_active_heights, stats.preexec_reject_density_avg,
        stats.preexec_reject_density_avg_milli, stats.preexec_reject_active_height_rate_ppm,
        stats.preexec_reject_active_observed_height_rate_ppm, stats.preexec_reject_active_height_share_ppm,
        stats.preexec_reject_share_bps, metrics.apply_error_total,
        metrics.apply_error_preexec_conflict_miss_total, stats.preexec_conflict_miss_share_bps,
        metrics.apply_error_version_conflict_total, metrics.apply_error_invalid_transition_total,
        metrics.apply_error_deadline_exceeded_total, metrics.apply_error_semantic_fail_total,
        metrics.rollback_total, stats.apply_error_rollback_share_bps, metrics.timeout_migrated_total,
        stats.recovery_error_rate, metrics.bft_observed_heights, metrics.bft_committed_heights,
        stats.bft_commit_observed_height_rate_ppm, stats.bft_skipped_height_total,
        stats.bft_skipped_observed_height_rate_ppm, metrics.bft_round_change_total,
        stats.bft_round_change_per_height_ppm, metrics.bft_round_change_active_heights,
        stats.bft_round_change_active_height_rate_ppm, stats.bft_round_change_active_observed_height_rate_ppm,
        stats.bft_round_change_density_avg, stats.bft_round_change_density_avg_milli,
        stats.bft_round_change_active_height_share_ppm, metrics.bft_round_change_backoff_total_ms,
        stats.bft_round_change_backoff_avg_ms, metrics.bft_round_change_backoff_active_heights,
        stats.bft_round_change_backoff_active_height_rate_ppm,
        stats.bft_round_change_backoff_active_observed_height_rate_ppm,
        stats.bft_round_change_backoff_density_avg_ms, stats.bft_round_change_backoff_density_avg_milli,
        stats.bft_round_change_backoff_active_height_share_ppm, metrics.bft_round_change_backoff_max_ms,
        stats.bft_round_change_backoff_wall_share_ppm, stats.bft_round_change_backoff_share_ppm,
        stats.bft_leader_missed_total, stats.bft_leader_missed_max, stats.bft_leader_missed_top_share_ppm,
        stats.bft_leader_missed_active_validators, stats.bft_leader_missed_active_validator_share_ppm,
        metrics.bft_leader_missed_active_heights, stats.bft_leader_missed_active_height_rate_ppm,
        stats.bft_leader_missed_active_observed_height_rate_ppm, stats.bft_leader_missed_density_avg,
        stats.bft_leader_missed_density_avg_milli, stats.bft_leader_missed_active_height_share_ppm,
        stats.leader_missed_final, metrics.bft_double_vote_total, metrics.bft_auth_reject_bad_sig_total,
        metrics.bft_auth_reject_replay_total, metrics.bft_auth_reject_stale_nonce_total
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_summary_line_keeps_state_root_fields_linked_into_consensus_surface() {
        let metrics = RuntimeMetrics::new(4);
        let mut stats = RuntimeSummaryStats::zeroed();
        stats.state_root_total_avg = 11;
        stats.state_root_total_p50 = 12;
        stats.state_root_total_p95 = 13;
        stats.state_root_total_max = 14;
        stats.state_root_total_share_avg_ppm = 15;
        stats.state_root_total_peak_share_ppm = 16;
        stats.unprofiled_finality_share_bps = 17;

        let line = format_runtime_summary_line(&metrics, &stats);

        assert!(line.starts_with("[consensus] "));
        assert!(line.contains("state_root_total_avg_ms=11"));
        assert!(line.contains("state_root_total_p50_ms=12"));
        assert!(line.contains("state_root_total_p95_ms=13"));
        assert!(line.contains("state_root_total_max_ms=14"));
        assert!(line.contains("state_root_total_share_avg_ppm=15"));
        assert!(line.contains("state_root_total_peak_share_ppm=16"));
        assert!(line.contains("unprofiled_finality_share_bps=17"));

        let state_root_idx = line
            .find("state_root_total_avg_ms=11")
            .expect("state_root_total_avg_ms should be present in the summary line");
        let unprofiled_idx = line
            .find("unprofiled_finality_share_bps=17")
            .expect("unprofiled_finality_share_bps should be present in the summary line");
        assert!(
            state_root_idx < unprofiled_idx,
            "state root evidence metrics must precede the unprofiled share field so downstream DA/light-verifier parsers see the canonical linkage"
        );
        assert!(
            line.contains(
                "state_root_total_avg_ms=11 state_root_total_p50_ms=12 state_root_total_p95_ms=13 state_root_total_max_ms=14 state_root_total_share_avg_ppm=15 state_root_total_peak_share_ppm=16 unprofiled_finality_share_bps=17"
            ),
            "state root evidence metrics and the unprofiled share field should remain a contiguous canonical block for DA/light-verifier summary parsers"
        );
    }
}
