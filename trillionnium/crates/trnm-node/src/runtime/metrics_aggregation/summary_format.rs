use super::*;

pub(crate) fn format_runtime_summary_line(
    metrics: &RuntimeMetrics,
    stats: &RuntimeSummaryStats,
) -> String {
    // Keep the legacy operator-facing `bft_auth_reject_stale_total` field stable
    // until the broader metrics contract is frozen. Today it aliases the only
    // stale-auth counter we collect: stale nonce rejects.
    let bft_auth_reject_stale_total = metrics.bft_auth_reject_stale_nonce_total;

    format!(
        "[consensus] finality_avg_ms={} finality_p50_ms={} finality_p95_ms={} finality_max_ms={} scheduler_elapsed_avg_ms={} scheduler_elapsed_p50_ms={} scheduler_elapsed_p95_ms={} scheduler_elapsed_max_ms={} scheduler_share_avg_ppm={} scheduler_peak_share_ppm={} preexec_elapsed_avg_ms={} preexec_elapsed_p50_ms={} preexec_elapsed_p95_ms={} preexec_elapsed_max_ms={} preexec_share_avg_ppm={} preexec_peak_share_ppm={} commit_elapsed_avg_ms={} commit_elapsed_p50_ms={} commit_elapsed_p95_ms={} commit_elapsed_max_ms={} commit_share_avg_ppm={} commit_peak_share_ppm={} state_root_total_avg_ms={} state_root_total_p50_ms={} state_root_total_p95_ms={} state_root_total_max_ms={} state_root_total_share_avg_ppm={} state_root_total_peak_share_ppm={} unprofiled_finality_share_bps={} critical_wait_blocks_avg={} critical_wait_blocks_p50={} critical_wait_blocks_p95={} critical_wait_blocks_max={} critical_wait_density_ppm={} critical_wait_peak_density_ppm={} critical_wait_active_heights={} critical_wait_active_height_rate_ppm={} critical_wait_active_observed_height_rate_ppm={} critical_wait_density_avg={} critical_wait_density_avg_milli={} critical_wait_active_height_share_ppm={} block_txs_p50={} block_txs_p95={} block_txs_max={} block_groups_p50={} block_groups_p95={} block_groups_max={} avg_group_size_avg_milli={} avg_group_size_p50_milli={} avg_group_size_p95_milli={} avg_group_size_max_milli={} hot_object_share_avg_ppm={} hot_object_share_p50_ppm={} hot_object_share_p95_ppm={} hot_object_share_max_ppm={} hot_object_active_heights={} hot_object_active_height_rate_ppm={} hot_object_active_observed_height_rate_ppm={} hot_object_active_height_share_ppm={} hot_object_top_label_share_avg_ppm={} hot_object_top_label_share_p50_ppm={} hot_object_top_label_share_p95_ppm={} hot_object_top_label_share_max_ppm={} hot_object_active_top_label_share_avg_ppm={} hot_object_tail_share_avg_ppm={} hot_object_tail_share_p50_ppm={} hot_object_tail_share_p95_ppm={} hot_object_tail_share_max_ppm={} hot_object_active_tail_share_avg_ppm={} rollback_count_avg={} rollback_count_p50={} rollback_count_p95={} rollback_count_max={} rollback_share_avg_ppm={} rollback_peak_share_ppm={} rollback_block_total={} rollback_active_heights={} rollback_block_rate={:.6} rollback_block_rate_ppm={} rollback_active_height_rate_ppm={} rollback_active_observed_height_rate_ppm={} rollback_density_avg={} rollback_density_avg_milli={} rollback_active_height_share_ppm={} preexec_reject_total={} preexec_reject_active_heights={} preexec_reject_density_avg={} preexec_reject_density_avg_milli={} preexec_reject_active_height_rate_ppm={} preexec_reject_active_observed_height_rate_ppm={} preexec_reject_active_height_share_ppm={} preexec_reject_share_bps={} apply_error_total={} apply_error_preexec_conflict_miss_total={} preexec_conflict_miss_share_bps={} apply_error_version_conflict_total={} apply_error_invalid_transition_total={} apply_error_deadline_exceeded_total={} apply_error_semantic_fail_total={} rollback_total={} apply_error_rollback_share_bps={} timeout_migrated_total={} recovery_error_rate={:.6} bft_observed_heights={} bft_committed_heights={} bft_commit_observed_height_rate_ppm={} bft_skipped_height_total={} bft_skipped_observed_height_rate_ppm={} bft_round_change_total={} bft_round_change_per_height_ppm={} bft_round_change_active_heights={} bft_round_change_active_height_rate_ppm={} bft_round_change_active_observed_height_rate_ppm={} bft_round_change_density_avg={} bft_round_change_density_avg_milli={} bft_round_change_active_height_share_ppm={} bft_round_change_backoff_total_ms={} bft_round_change_backoff_avg_ms={} bft_round_change_backoff_active_heights={} bft_round_change_backoff_active_height_rate_ppm={} bft_round_change_backoff_active_observed_height_rate_ppm={} bft_round_change_backoff_density_avg_ms={} bft_round_change_backoff_density_avg_milli={} bft_round_change_backoff_active_height_share_ppm={} bft_round_change_backoff_max_ms={} bft_round_change_backoff_wall_share_ppm={} bft_round_change_backoff_share_ppm={} bft_leader_missed_total={} bft_leader_missed_max={} bft_leader_missed_top_share_ppm={} bft_leader_missed_active_validators={} bft_leader_missed_active_validator_share_ppm={} bft_leader_missed_active_heights={} bft_leader_missed_active_height_rate_ppm={} bft_leader_missed_active_observed_height_rate_ppm={} bft_leader_missed_density_avg={} bft_leader_missed_density_avg_milli={} bft_leader_missed_active_height_share_ppm={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_total={} bft_auth_reject_stale_nonce_total={}",
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
        metrics.bft_auth_reject_replay_total, bft_auth_reject_stale_total,
        metrics.bft_auth_reject_stale_nonce_total
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_summary_line_keeps_alertable_bft_auth_and_recovery_counters_visible() {
        let mut metrics = RuntimeMetrics::new(4);
        metrics.apply_error_total = 9;
        metrics.apply_error_preexec_conflict_miss_total = 2;
        metrics.apply_error_version_conflict_total = 3;
        metrics.apply_error_invalid_transition_total = 4;
        metrics.apply_error_deadline_exceeded_total = 5;
        metrics.apply_error_semantic_fail_total = 6;
        metrics.rollback_total = 2;
        metrics.timeout_migrated_total = 3;
        metrics.bft_observed_heights = 11;
        metrics.bft_committed_heights = 7;
        metrics.bft_round_change_total = 5;
        metrics.bft_round_change_active_heights = 4;
        metrics.bft_round_change_backoff_total_ms = 33;
        metrics.bft_round_change_backoff_active_heights = 2;
        metrics.bft_round_change_backoff_max_ms = 21;
        metrics.bft_double_vote_total = 1;
        metrics.bft_auth_reject_bad_sig_total = 4;
        metrics.bft_auth_reject_replay_total = 6;
        metrics.bft_auth_reject_stale_nonce_total = 8;
        metrics.bft_leader_missed_active_heights = 2;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.rollback_block_rate = 0.25;
        stats.preexec_conflict_miss_share_bps = 2_222;
        stats.apply_error_rollback_share_bps = 2_222;
        stats.recovery_error_rate = 0.5;
        stats.bft_commit_observed_height_rate_ppm = 636_363;
        stats.bft_skipped_height_total = 4;
        stats.bft_skipped_observed_height_rate_ppm = 363_636;
        stats.bft_round_change_per_height_ppm = 714_285;
        stats.bft_round_change_active_height_rate_ppm = 571_428;
        stats.bft_round_change_active_observed_height_rate_ppm = 363_636;
        stats.bft_round_change_backoff_avg_ms = 6;
        stats.bft_round_change_backoff_active_height_rate_ppm = 285_714;
        stats.bft_round_change_backoff_active_observed_height_rate_ppm = 181_818;
        stats.bft_round_change_backoff_density_avg_ms = 16;
        stats.bft_round_change_backoff_density_avg_milli = 16_500;
        stats.bft_round_change_backoff_wall_share_ppm = 125_000;
        stats.bft_round_change_backoff_share_ppm = 125_000;
        stats.bft_leader_missed_total = 3;
        stats.bft_leader_missed_max = 2;
        stats.bft_leader_missed_top_share_ppm = 666_666;
        stats.bft_leader_missed_active_validators = 2;
        stats.bft_leader_missed_active_validator_share_ppm = 500_000;
        stats.bft_leader_missed_active_height_rate_ppm = 181_818;
        stats.bft_leader_missed_active_observed_height_rate_ppm = 181_818;
        stats.bft_leader_missed_density_avg = 1;
        stats.bft_leader_missed_density_avg_milli = 1_500;
        stats.bft_leader_missed_active_height_share_ppm = 500_000;
        stats.leader_missed_final = vec![0, 2, 0, 1];

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert!(summary.contains("apply_error_total=9"));
        assert!(summary.contains("apply_error_preexec_conflict_miss_total=2"));
        assert!(summary.contains("preexec_conflict_miss_share_bps=2222"));
        assert!(summary.contains("apply_error_version_conflict_total=3"));
        assert!(summary.contains("apply_error_invalid_transition_total=4"));
        assert!(summary.contains("apply_error_deadline_exceeded_total=5"));
        assert!(summary.contains("apply_error_semantic_fail_total=6"));
        assert!(summary.contains("rollback_total=2"));
        assert!(summary.contains("apply_error_rollback_share_bps=2222"));
        assert!(summary.contains("timeout_migrated_total=3"));
        assert!(summary.contains("recovery_error_rate=0.500000"));
        assert!(summary.contains("bft_commit_observed_height_rate_ppm=636363"));
        assert!(summary.contains("bft_skipped_height_total=4"));
        assert!(summary.contains("bft_skipped_observed_height_rate_ppm=363636"));
        assert!(summary.contains("bft_round_change_total=5"));
        assert!(summary.contains("bft_round_change_per_height_ppm=714285"));
        assert!(summary.contains("bft_round_change_active_heights=4"));
        assert!(summary.contains("bft_round_change_active_height_rate_ppm=571428"));
        assert!(summary.contains("bft_round_change_active_observed_height_rate_ppm=363636"));
        assert!(summary.contains("bft_round_change_backoff_total_ms=33"));
        assert!(summary.contains("bft_round_change_backoff_avg_ms=6"));
        assert!(summary.contains("bft_round_change_backoff_active_heights=2"));
        assert!(summary.contains("bft_round_change_backoff_active_height_rate_ppm=285714"));
        assert!(summary.contains("bft_round_change_backoff_active_observed_height_rate_ppm=181818"));
        assert!(summary.contains("bft_round_change_backoff_density_avg_ms=16"));
        assert!(summary.contains("bft_round_change_backoff_density_avg_milli=16500"));
        assert!(summary.contains("bft_round_change_backoff_max_ms=21"));
        assert!(summary.contains("bft_round_change_backoff_wall_share_ppm=125000"));
        assert!(summary.contains("bft_round_change_backoff_share_ppm=125000"));
        assert!(summary.contains("bft_leader_missed_total=3"));
        assert!(summary.contains("bft_leader_missed_max=2"));
        assert!(summary.contains("bft_leader_missed_top_share_ppm=666666"));
        assert!(summary.contains("bft_leader_missed_active_validators=2"));
        assert!(summary.contains("bft_leader_missed_active_validator_share_ppm=500000"));
        assert!(summary.contains("bft_leader_missed_active_height_rate_ppm=181818"));
        assert!(summary.contains("bft_leader_missed_active_observed_height_rate_ppm=181818"));
        assert!(summary.contains("bft_leader_missed_density_avg=1"));
        assert!(summary.contains("bft_leader_missed_density_avg_milli=1500"));
        assert!(summary.contains("bft_leader_missed_active_height_share_ppm=500000"));
        assert!(summary.contains("bft_double_vote_total=1"));
        assert!(summary.contains("bft_auth_reject_bad_sig_total=4"));
        assert!(summary.contains("bft_auth_reject_replay_total=6"));
        assert!(summary.contains("bft_auth_reject_stale_total=8"));
        assert!(summary.contains("bft_auth_reject_stale_nonce_total=8"));
        assert!(summary.contains("bft_leader_missed_proposals=[0, 2, 0, 1]"));
    }

    #[test]
    fn runtime_summary_line_keeps_round_change_backoff_share_aliases_operator_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(2);
        metrics.bft_committed_heights = 2;
        metrics.bft_round_change_backoff_total_ms = 17;
        metrics.bft_round_change_backoff_active_heights = 1;
        metrics.bft_round_change_backoff_max_ms = 17;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.bft_round_change_backoff_avg_ms = 17;
        stats.bft_round_change_backoff_active_height_rate_ppm = 500_000;
        stats.bft_round_change_backoff_density_avg_ms = 17;
        stats.bft_round_change_backoff_density_avg_milli = 17_000;
        stats.bft_round_change_backoff_wall_share_ppm = 340_000;
        stats.bft_round_change_backoff_share_ppm = 340_000;

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("bft_round_change_backoff_wall_share_ppm=").count(), 1);
        assert_eq!(summary.matches("bft_round_change_backoff_share_ppm=").count(), 1);
        assert!(summary.contains("bft_round_change_backoff_wall_share_ppm=340000"));
        assert!(summary.contains("bft_round_change_backoff_share_ppm=340000"));
        assert!(summary.contains("bft_round_change_backoff_density_avg_ms=17"));
        assert!(summary.contains("bft_round_change_backoff_max_ms=17"));
    }

    #[test]
    fn runtime_summary_line_keeps_stale_auth_alias_operator_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(2);
        metrics.bft_auth_reject_stale_nonce_total = 17;

        let stats = RuntimeSummaryStats::zeroed();
        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("bft_auth_reject_stale_total=").count(), 1);
        assert_eq!(summary.matches("bft_auth_reject_stale_nonce_total=").count(), 1);
        assert!(summary.contains("bft_auth_reject_stale_total=17"));
        assert!(summary.contains("bft_auth_reject_stale_nonce_total=17"));

        let alias_idx = summary.find("bft_auth_reject_stale_total=17").unwrap();
        let nonce_idx = summary
            .find("bft_auth_reject_stale_nonce_total=17")
            .unwrap();
        assert!(alias_idx < nonce_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_bft_height_counters_operator_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(2);
        metrics.bft_observed_heights = 9;
        metrics.bft_committed_heights = 6;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.bft_commit_observed_height_rate_ppm = 666_666;
        stats.bft_skipped_height_total = 3;
        stats.bft_skipped_observed_height_rate_ppm = 333_333;

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("bft_observed_heights=").count(), 1);
        assert_eq!(summary.matches("bft_committed_heights=").count(), 1);
        assert!(summary.contains("bft_observed_heights=9"));
        assert!(summary.contains("bft_committed_heights=6"));
        assert!(summary.contains("bft_commit_observed_height_rate_ppm=666666"));
        assert!(summary.contains("bft_skipped_height_total=3"));
        assert!(summary.contains("bft_skipped_observed_height_rate_ppm=333333"));

        let observed_idx = summary.find("bft_observed_heights=9").unwrap();
        let committed_idx = summary.find("bft_committed_heights=6").unwrap();
        let commit_rate_idx = summary
            .find("bft_commit_observed_height_rate_ppm=666666")
            .unwrap();
        let skipped_total_idx = summary.find("bft_skipped_height_total=3").unwrap();
        let skipped_rate_idx = summary
            .find("bft_skipped_observed_height_rate_ppm=333333")
            .unwrap();

        assert!(observed_idx < committed_idx);
        assert!(committed_idx < commit_rate_idx);
        assert!(commit_rate_idx < skipped_total_idx);
        assert!(skipped_total_idx < skipped_rate_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_rollback_height_alias_operator_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(3);
        metrics.rollback_block_total = 2;
        metrics.bft_observed_heights = 5;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.rollback_active_heights = 2;
        stats.rollback_block_rate = 0.666_667;
        stats.rollback_block_rate_ppm = 666_666;
        stats.rollback_active_height_rate_ppm = 666_666;
        stats.rollback_active_observed_height_rate_ppm = 400_000;
        stats.rollback_density_avg = 3;
        stats.rollback_density_avg_milli = 3_500;

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("rollback_block_total=").count(), 1);
        assert_eq!(summary.matches("rollback_active_heights=").count(), 1);
        assert!(summary.contains("rollback_block_total=2"));
        assert!(summary.contains("rollback_active_heights=2"));
        assert!(summary.contains("rollback_block_rate=0.666667"));
        assert!(summary.contains("rollback_block_rate_ppm=666666"));
        assert!(summary.contains("rollback_active_height_rate_ppm=666666"));
        assert!(summary.contains("rollback_active_observed_height_rate_ppm=400000"));
        assert!(summary.contains("rollback_density_avg=3"));
        assert!(summary.contains("rollback_density_avg_milli=3500"));

        let block_total_idx = summary.find("rollback_block_total=2").unwrap();
        let active_heights_idx = summary.find("rollback_active_heights=2").unwrap();
        let block_rate_idx = summary.find("rollback_block_rate=0.666667").unwrap();
        let block_rate_ppm_idx = summary.find("rollback_block_rate_ppm=666666").unwrap();
        let active_rate_idx = summary.find("rollback_active_height_rate_ppm=666666").unwrap();

        assert!(block_total_idx < active_heights_idx);
        assert!(active_heights_idx < block_rate_idx);
        assert!(block_rate_idx < block_rate_ppm_idx);
        assert!(block_rate_ppm_idx < active_rate_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_critical_wait_density_cluster_operator_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(3);
        metrics.critical_wait_active_heights = 2;
        metrics.bft_observed_heights = 5;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.critical_wait_density_ppm = 400_000;
        stats.critical_wait_peak_density_ppm = 600_000;
        stats.critical_wait_active_height_rate_ppm = 666_666;
        stats.critical_wait_active_observed_height_rate_ppm = 400_000;
        stats.critical_wait_density_avg = 3;
        stats.critical_wait_density_avg_milli = 3_500;
        stats.critical_wait_active_height_share_ppm = 666_666;

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("critical_wait_active_heights=").count(), 1);
        assert_eq!(summary.matches("critical_wait_density_ppm=").count(), 1);
        assert_eq!(summary.matches("critical_wait_peak_density_ppm=").count(), 1);
        assert!(summary.contains("critical_wait_active_heights=2"));
        assert!(summary.contains("critical_wait_density_ppm=400000"));
        assert!(summary.contains("critical_wait_peak_density_ppm=600000"));
        assert!(summary.contains("critical_wait_active_height_rate_ppm=666666"));
        assert!(summary.contains("critical_wait_active_observed_height_rate_ppm=400000"));
        assert!(summary.contains("critical_wait_density_avg=3"));
        assert!(summary.contains("critical_wait_density_avg_milli=3500"));
        assert!(summary.contains("critical_wait_active_height_share_ppm=666666"));

        let density_idx = summary.find("critical_wait_density_ppm=400000").unwrap();
        let peak_idx = summary.find("critical_wait_peak_density_ppm=600000").unwrap();
        let active_idx = summary.find("critical_wait_active_heights=2").unwrap();
        let rate_idx = summary.find("critical_wait_active_height_rate_ppm=666666").unwrap();
        let observed_rate_idx = summary
            .find("critical_wait_active_observed_height_rate_ppm=400000")
            .unwrap();
        let avg_idx = summary.find("critical_wait_density_avg=3").unwrap();
        let avg_milli_idx = summary.find("critical_wait_density_avg_milli=3500").unwrap();

        assert!(density_idx < peak_idx);
        assert!(peak_idx < active_idx);
        assert!(active_idx < rate_idx);
        assert!(rate_idx < observed_rate_idx);
        assert!(observed_rate_idx < avg_idx);
        assert!(avg_idx < avg_milli_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_recovery_and_bft_auth_signal_cluster_in_operator_order() {
        let mut metrics = RuntimeMetrics::new(2);
        metrics.apply_error_total = 4;
        metrics.rollback_total = 1;
        metrics.timeout_migrated_total = 2;
        metrics.bft_observed_heights = 5;
        metrics.bft_committed_heights = 3;
        metrics.bft_double_vote_total = 7;
        metrics.bft_auth_reject_bad_sig_total = 11;
        metrics.bft_auth_reject_replay_total = 13;
        metrics.bft_auth_reject_stale_nonce_total = 17;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.recovery_error_rate = 0.25;
        stats.bft_commit_observed_height_rate_ppm = 600_000;
        stats.bft_skipped_height_total = 2;
        stats.bft_skipped_observed_height_rate_ppm = 400_000;

        let summary = format_runtime_summary_line(&metrics, &stats);

        let recovery_idx = summary.find("rollback_total=1").unwrap();
        let timeout_idx = summary.find("timeout_migrated_total=2").unwrap();
        let error_rate_idx = summary.find("recovery_error_rate=0.250000").unwrap();
        let double_vote_idx = summary.find("bft_double_vote_total=7").unwrap();
        let bad_sig_idx = summary.find("bft_auth_reject_bad_sig_total=11").unwrap();
        let replay_idx = summary.find("bft_auth_reject_replay_total=13").unwrap();
        let stale_alias_idx = summary.find("bft_auth_reject_stale_total=17").unwrap();
        let stale_nonce_idx = summary.find("bft_auth_reject_stale_nonce_total=17").unwrap();

        assert!(recovery_idx < timeout_idx);
        assert!(timeout_idx < error_rate_idx);
        assert!(double_vote_idx < bad_sig_idx);
        assert!(bad_sig_idx < replay_idx);
        assert!(replay_idx < stale_alias_idx);
        assert!(stale_alias_idx < stale_nonce_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_leader_missed_cluster_ahead_of_bft_auth_cluster() {
        let mut metrics = RuntimeMetrics::new(4);
        metrics.bft_leader_missed_active_heights = 3;
        metrics.bft_double_vote_total = 7;
        metrics.bft_auth_reject_bad_sig_total = 11;
        metrics.bft_auth_reject_replay_total = 13;
        metrics.bft_auth_reject_stale_nonce_total = 17;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.bft_leader_missed_total = 5;
        stats.bft_leader_missed_max = 3;
        stats.bft_leader_missed_top_share_ppm = 600_000;
        stats.bft_leader_missed_active_validators = 2;
        stats.bft_leader_missed_active_validator_share_ppm = 500_000;
        stats.bft_leader_missed_density_avg = 1;
        stats.bft_leader_missed_active_height_share_ppm = 400_000;
        stats.leader_missed_final = vec![0, 3, 2, 0];

        let summary = format_runtime_summary_line(&metrics, &stats);

        let leader_missed_idx = summary.find("bft_leader_missed_total=5").unwrap();
        let leader_missed_proposals_idx = summary
            .find("bft_leader_missed_proposals=[0, 3, 2, 0]")
            .unwrap();
        let double_vote_idx = summary.find("bft_double_vote_total=7").unwrap();
        let bad_sig_idx = summary.find("bft_auth_reject_bad_sig_total=11").unwrap();
        let replay_idx = summary.find("bft_auth_reject_replay_total=13").unwrap();
        let stale_alias_idx = summary.find("bft_auth_reject_stale_total=17").unwrap();

        assert!(leader_missed_idx < leader_missed_proposals_idx);
        assert!(leader_missed_proposals_idx < double_vote_idx);
        assert!(double_vote_idx < bad_sig_idx);
        assert!(bad_sig_idx < replay_idx);
        assert!(replay_idx < stale_alias_idx);
    }

    #[test]
    fn runtime_summary_line_keeps_bft_leader_missed_health_cluster_visible_once_each() {
        let mut metrics = RuntimeMetrics::new(4);
        metrics.bft_leader_missed_active_heights = 3;
        metrics.bft_observed_heights = 8;

        let mut stats = RuntimeSummaryStats::zeroed();
        stats.bft_leader_missed_total = 5;
        stats.bft_leader_missed_max = 3;
        stats.bft_leader_missed_top_share_ppm = 600_000;
        stats.bft_leader_missed_active_validators = 2;
        stats.bft_leader_missed_active_validator_share_ppm = 500_000;
        stats.bft_leader_missed_active_height_rate_ppm = 375_000;
        stats.bft_leader_missed_active_observed_height_rate_ppm = 375_000;
        stats.bft_leader_missed_density_avg = 1;
        stats.bft_leader_missed_density_avg_milli = 1_666;
        stats.bft_leader_missed_active_height_share_ppm = 400_000;
        stats.leader_missed_final = vec![0, 3, 2, 0];

        let summary = format_runtime_summary_line(&metrics, &stats);

        assert_eq!(summary.matches("bft_leader_missed_total=").count(), 1);
        assert_eq!(summary.matches("bft_leader_missed_max=").count(), 1);
        assert_eq!(summary.matches("bft_leader_missed_active_validators=").count(), 1);
        assert_eq!(summary.matches("bft_leader_missed_proposals=").count(), 1);
        assert!(summary.contains("bft_leader_missed_total=5"));
        assert!(summary.contains("bft_leader_missed_max=3"));
        assert!(summary.contains("bft_leader_missed_top_share_ppm=600000"));
        assert!(summary.contains("bft_leader_missed_active_validators=2"));
        assert!(summary.contains("bft_leader_missed_active_validator_share_ppm=500000"));
        assert!(summary.contains("bft_leader_missed_active_heights=3"));
        assert!(summary.contains("bft_leader_missed_active_height_rate_ppm=375000"));
        assert!(summary.contains("bft_leader_missed_active_observed_height_rate_ppm=375000"));
        assert!(summary.contains("bft_leader_missed_density_avg=1"));
        assert!(summary.contains("bft_leader_missed_density_avg_milli=1666"));
        assert!(summary.contains("bft_leader_missed_active_height_share_ppm=400000"));
        assert!(summary.contains("bft_leader_missed_proposals=[0, 3, 2, 0]"));

        let total_idx = summary.find("bft_leader_missed_total=5").unwrap();
        let max_idx = summary.find("bft_leader_missed_max=3").unwrap();
        let top_share_idx = summary.find("bft_leader_missed_top_share_ppm=600000").unwrap();
        let active_validator_idx = summary
            .find("bft_leader_missed_active_validators=2")
            .unwrap();
        let active_height_idx = summary.find("bft_leader_missed_active_heights=3").unwrap();
        let density_idx = summary.find("bft_leader_missed_density_avg=1").unwrap();
        let proposals_idx = summary
            .find("bft_leader_missed_proposals=[0, 3, 2, 0]")
            .unwrap();

        assert!(total_idx < max_idx);
        assert!(max_idx < top_share_idx);
        assert!(top_share_idx < active_validator_idx);
        assert!(active_validator_idx < active_height_idx);
        assert!(active_height_idx < density_idx);
        assert!(density_idx < proposals_idx);
    }
}
