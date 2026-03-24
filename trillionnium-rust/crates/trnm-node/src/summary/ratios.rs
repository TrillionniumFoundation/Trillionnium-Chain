use super::*;

pub(super) fn fill_ratio_stats(
    stats: &mut ConsensusSummaryStats,
    inputs: &ConsensusSummaryInputs<'_>,
) {
    stats.hot_object_active_top_label_share_avg_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        inputs.hot_object_active_top_label_share_total_ppm / inputs.hot_object_active_heights as u128
    };
    stats.hot_object_active_tail_share_avg_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        inputs.hot_object_active_tail_share_total_ppm / inputs.hot_object_active_heights as u128
    };
    stats.hot_object_active_height_rate_ppm = ratio_ppm_u64(
        inputs.hot_object_active_heights,
        inputs.finality_samples_ms.len() as u64,
    );
    stats.hot_object_active_observed_height_rate_ppm =
        ratio_ppm_u64(inputs.hot_object_active_heights, inputs.bft_observed_heights);
    stats.hot_object_active_height_share_ppm = if inputs.hot_object_active_heights == 0 {
        0
    } else {
        (inputs.hot_object_active_top_label_share_total_ppm
            + inputs.hot_object_active_tail_share_total_ppm)
            / inputs.hot_object_active_heights as u128
    };

    stats.scheduler_share_avg_ppm = ratio_ppm(stats.scheduler_avg, stats.finality_avg);
    stats.scheduler_peak_share_ppm = ratio_ppm(stats.scheduler_max, stats.finality_max);
    stats.preexec_share_avg_ppm = ratio_ppm(stats.preexec_avg, stats.finality_avg);
    stats.commit_share_avg_ppm = ratio_ppm(stats.commit_avg, stats.finality_avg);
    stats.commit_peak_share_ppm = ratio_ppm(stats.commit_max, stats.finality_max);
    stats.state_root_total_share_avg_ppm = ratio_ppm(stats.state_root_total_avg, stats.finality_avg);
    stats.state_root_total_peak_share_ppm = ratio_ppm(stats.state_root_total_max, stats.finality_max);
    stats.rollback_share_avg_ppm = ratio_ppm(stats.rollback_avg, stats.finality_avg);
    stats.rollback_peak_share_ppm = ratio_ppm(stats.rollback_max, stats.finality_max);
    stats.preexec_peak_share_ppm = ratio_ppm(stats.preexec_max, stats.finality_max);

    stats.rollback_block_rate_ppm = ratio_ppm_u64(
        inputs.rollback_block_total,
        inputs.finality_samples_ms.len() as u64,
    );
    stats.rollback_active_heights = inputs.rollback_block_total;
    stats.rollback_active_height_rate_ppm = stats.rollback_block_rate_ppm;
    stats.rollback_active_observed_height_rate_ppm =
        ratio_ppm_u64(inputs.rollback_block_total, inputs.bft_observed_heights);
    stats.rollback_density_avg = if inputs.rollback_block_total == 0 {
        0
    } else {
        inputs.rollback_total / inputs.rollback_block_total
    };
    stats.rollback_density_avg_milli = ratio_milli_u64(inputs.rollback_total, inputs.rollback_block_total);
    stats.rollback_active_height_share_ppm = finality_budget_share_ppm(
        stats.rollback_density_avg_milli,
        stats.finality_avg,
    );

    stats.preexec_conflict_miss_share_bps = ratio_percent_bps(
        inputs.apply_error_preexec_conflict_miss_total as u128,
        inputs.preexec_reject_total as u128,
    );
    stats.preexec_reject_density_avg = if inputs.preexec_reject_active_heights == 0 {
        0
    } else {
        inputs.preexec_reject_total / inputs.preexec_reject_active_heights
    };
    stats.preexec_reject_density_avg_milli = ratio_milli_u64(
        inputs.preexec_reject_total,
        inputs.preexec_reject_active_heights,
    );
    stats.preexec_reject_active_height_rate_ppm = ratio_ppm_u64(
        inputs.preexec_reject_active_heights,
        inputs.bft_committed_heights,
    );
    stats.preexec_reject_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.preexec_reject_active_heights,
        inputs.bft_observed_heights,
    );
    stats.preexec_reject_active_height_share_ppm = finality_budget_share_ppm(
        stats.preexec_reject_density_avg_milli,
        stats.finality_avg,
    );
    stats.apply_error_rollback_share_bps = ratio_percent_bps(
        inputs.rollback_total as u128,
        inputs.apply_error_total as u128,
    );
    stats.rollback_block_rate = if inputs.finality_samples_ms.is_empty() {
        0.0
    } else {
        inputs.rollback_block_total as f64 / inputs.finality_samples_ms.len() as f64
    };

    stats.critical_wait_density_ppm = ratio_ppm(stats.critical_wait_blocks_avg, stats.finality_avg);
    stats.critical_wait_peak_density_ppm = ratio_ppm(stats.critical_wait_blocks_max, stats.finality_max);
    stats.critical_wait_active_height_rate_ppm = ratio_ppm_u64(
        inputs.critical_wait_active_heights,
        inputs.finality_samples_ms.len() as u64,
    );
    stats.critical_wait_active_observed_height_rate_ppm = ratio_ppm_u64(
        inputs.critical_wait_active_heights,
        inputs.bft_observed_heights,
    );
    stats.critical_wait_density_avg = if inputs.critical_wait_active_heights == 0 {
        0
    } else {
        inputs.critical_wait_total / inputs.critical_wait_active_heights
    };
    stats.critical_wait_density_avg_milli = ratio_milli_u64(
        inputs.critical_wait_total,
        inputs.critical_wait_active_heights,
    );
    stats.critical_wait_active_height_share_ppm = finality_budget_share_ppm(
        stats.critical_wait_density_avg_milli,
        stats.finality_avg,
    );
    stats.preexec_reject_share_bps = ratio_percent_bps(
        inputs.preexec_reject_total as u128,
        inputs.apply_error_total as u128,
    );
    stats.unprofiled_finality_share_bps = gap_percent_bps(
        stats.finality_avg,
        stats.scheduler_avg
            .saturating_add(stats.preexec_avg)
            .saturating_add(stats.commit_avg),
        stats.state_root_total_avg,
    );
}
