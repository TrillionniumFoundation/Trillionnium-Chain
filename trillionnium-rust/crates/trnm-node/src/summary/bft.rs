use super::*;

pub(super) fn fill_bft_stats(
    stats: &mut ConsensusSummaryStats,
    inputs: &ConsensusSummaryInputs<'_>,
) {
    stats.bft_round_change_per_height_ppm =
        ratio_ppm_u64(inputs.bft_round_change_total, inputs.bft_committed_heights);
    stats.bft_round_change_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_active_heights,
        inputs.bft_committed_heights,
    );
    stats.bft_round_change_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_active_heights,
        inputs.bft_observed_heights,
    );
    stats.bft_round_change_density_avg = if inputs.bft_round_change_active_heights == 0 {
        0
    } else {
        inputs.bft_round_change_total / inputs.bft_round_change_active_heights
    };
    stats.bft_round_change_density_avg_milli = ratio_milli_u64(
        inputs.bft_round_change_total,
        inputs.bft_round_change_active_heights,
    );
    stats.bft_round_change_active_height_share_ppm = finality_budget_share_ppm(
        stats.bft_round_change_density_avg_milli,
        stats.finality_avg,
    );
    stats.bft_round_change_backoff_avg_ms = if inputs.bft_round_change_total == 0 {
        0
    } else {
        inputs.bft_round_change_backoff_total_ms / inputs.bft_round_change_total
    };
    stats.bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_backoff_active_heights,
        inputs.bft_committed_heights,
    );
    stats.bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_round_change_backoff_active_heights,
        inputs.bft_observed_heights,
    );
    stats.bft_round_change_backoff_density_avg_ms =
        if inputs.bft_round_change_backoff_active_heights == 0 {
            0
        } else {
            inputs.bft_round_change_backoff_total_ms / inputs.bft_round_change_backoff_active_heights
        };
    stats.bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        inputs.bft_round_change_backoff_total_ms,
        inputs.bft_round_change_backoff_active_heights,
    );
    stats.bft_round_change_backoff_active_height_share_ppm = finality_budget_share_ppm(
        stats.bft_round_change_backoff_density_avg_milli,
        stats.finality_avg,
    );
    stats.bft_round_change_backoff_wall_share_ppm = wall_time_share_ppm(
        inputs.bft_round_change_backoff_total_ms,
        inputs.bft_committed_heights,
        stats.finality_avg,
    );
    stats.bft_round_change_backoff_share_ppm = stats.bft_round_change_backoff_wall_share_ppm;
    stats.bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(inputs.bft_committed_heights, inputs.bft_observed_heights);
    stats.bft_skipped_height_total = inputs
        .bft_observed_heights
        .saturating_sub(inputs.bft_committed_heights);
    stats.bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(stats.bft_skipped_height_total, inputs.bft_observed_heights);
    stats.recovery_error_rate = if inputs.finality_samples_ms.is_empty() {
        0.0
    } else {
        inputs.apply_error_total as f64 / inputs.finality_samples_ms.len() as f64
    };

    stats.leader_missed_final = inputs
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .collect();
    stats.bft_leader_missed_total = stats.leader_missed_final.iter().copied().sum();
    stats.bft_leader_missed_max = stats.leader_missed_final.iter().copied().max().unwrap_or(0);
    stats.bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(stats.bft_leader_missed_max, stats.bft_leader_missed_total);
    stats.bft_leader_missed_active_validators = stats
        .leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    stats.bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        stats.bft_leader_missed_active_validators,
        stats.leader_missed_final.len() as u64,
    );
    stats.bft_leader_missed_active_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_leader_missed_active_heights,
        inputs.bft_committed_heights,
    );
    stats.bft_leader_missed_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.bft_leader_missed_active_heights,
        inputs.bft_observed_heights,
    );
    stats.bft_leader_missed_density_avg = if inputs.bft_leader_missed_active_heights == 0 {
        0
    } else {
        stats.bft_leader_missed_total / inputs.bft_leader_missed_active_heights
    };
    stats.bft_leader_missed_density_avg_milli = ratio_milli_u64(
        stats.bft_leader_missed_total,
        inputs.bft_leader_missed_active_heights,
    );
    stats.bft_leader_missed_active_height_share_ppm = finality_budget_share_ppm(
        stats.bft_leader_missed_density_avg_milli,
        stats.finality_avg,
    );
}
