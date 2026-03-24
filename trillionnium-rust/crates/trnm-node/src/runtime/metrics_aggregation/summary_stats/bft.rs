use super::*;

pub(crate) fn fill_bft_stats(
    stats: &mut RuntimeSummaryStats,
    runtime: &RuntimeState,
    metrics: &RuntimeMetrics,
) {
    stats.bft_round_change_per_height_ppm = ratio_ppm_u64(
        metrics.bft_round_change_total,
        metrics.bft_committed_heights,
    );
    stats.bft_round_change_active_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_round_change_active_heights,
        metrics.bft_committed_heights,
    );
    stats.bft_round_change_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_round_change_active_heights,
        metrics.bft_observed_heights,
    );
    stats.bft_round_change_density_avg = if metrics.bft_round_change_active_heights == 0 {
        0
    } else {
        metrics.bft_round_change_total / metrics.bft_round_change_active_heights
    };
    stats.bft_round_change_density_avg_milli = ratio_milli_u64(
        metrics.bft_round_change_total,
        metrics.bft_round_change_active_heights,
    );
    stats.bft_round_change_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            metrics.bft_round_change_total,
            metrics.bft_round_change_active_heights,
        ),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.bft_round_change_backoff_avg_ms = if metrics.bft_round_change_total == 0 {
        0
    } else {
        metrics.bft_round_change_backoff_total_ms / metrics.bft_round_change_total
    };
    stats.bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_round_change_backoff_active_heights,
        metrics.bft_committed_heights,
    );
    stats.bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_round_change_backoff_active_heights,
        metrics.bft_observed_heights,
    );
    stats.bft_round_change_backoff_density_avg_ms =
        if metrics.bft_round_change_backoff_active_heights == 0 {
            0
        } else {
            metrics.bft_round_change_backoff_total_ms
                / metrics.bft_round_change_backoff_active_heights
        };
    stats.bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        metrics.bft_round_change_backoff_total_ms,
        metrics.bft_round_change_backoff_active_heights,
    );
    stats.bft_round_change_backoff_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            metrics.bft_round_change_backoff_total_ms,
            metrics.bft_round_change_backoff_active_heights,
        ),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.bft_round_change_backoff_wall_share_ppm = wall_time_share_ppm(
        metrics.bft_round_change_backoff_total_ms,
        metrics.bft_committed_heights,
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.bft_round_change_backoff_share_ppm = wall_time_share_ppm(
        metrics.bft_round_change_backoff_total_ms,
        metrics.bft_committed_heights,
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(metrics.bft_committed_heights, metrics.bft_observed_heights);
    stats.bft_skipped_height_total = metrics
        .bft_observed_heights
        .saturating_sub(metrics.bft_committed_heights);
    stats.bft_skipped_observed_height_rate_ppm = ratio_ppm_u64(
        metrics
            .bft_observed_heights
            .saturating_sub(metrics.bft_committed_heights),
        metrics.bft_observed_heights,
    );
    stats.recovery_error_rate = if metrics.finality_samples_ms.is_empty() {
        0.0
    } else {
        metrics.apply_error_total as f64 / metrics.finality_samples_ms.len() as f64
    };

    let leader_missed_total = runtime
        .bft_jitter
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .sum::<u64>();
    let leader_missed_max = runtime
        .bft_jitter
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .max()
        .unwrap_or(0);
    stats.leader_missed_final = runtime
        .bft_jitter
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .collect();
    stats.bft_leader_missed_total = leader_missed_total;
    stats.bft_leader_missed_max = leader_missed_max;
    stats.bft_leader_missed_top_share_ppm = ratio_ppm_u64(leader_missed_max, leader_missed_total);
    stats.bft_leader_missed_active_validators = runtime
        .bft_jitter
        .leader_health
        .iter()
        .filter(|missed| missed.missed_proposals > 0)
        .count() as u64;
    stats.bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        stats.bft_leader_missed_active_validators,
        runtime.bft_jitter.leader_health.len() as u64,
    );
    stats.bft_leader_missed_active_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_leader_missed_active_heights,
        metrics.bft_committed_heights,
    );
    stats.bft_leader_missed_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.bft_leader_missed_active_heights,
        metrics.bft_observed_heights,
    );
    stats.bft_leader_missed_density_avg = if metrics.bft_leader_missed_active_heights == 0 {
        0
    } else {
        leader_missed_total / metrics.bft_leader_missed_active_heights
    };
    stats.bft_leader_missed_density_avg_milli = ratio_milli_u64(
        leader_missed_total,
        metrics.bft_leader_missed_active_heights,
    );
    stats.bft_leader_missed_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            leader_missed_total,
            metrics.bft_leader_missed_active_heights,
        ),
        average_or_zero(&metrics.finality_samples_ms),
    );
}
