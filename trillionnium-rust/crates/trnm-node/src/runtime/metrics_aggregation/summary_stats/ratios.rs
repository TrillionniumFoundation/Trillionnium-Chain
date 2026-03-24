use super::*;

pub(crate) fn fill_ratio_stats(stats: &mut RuntimeSummaryStats, metrics: &RuntimeMetrics) {
    stats.hot_object_active_top_label_share_avg_ppm = if metrics.hot_object_active_heights == 0 {
        0
    } else {
        metrics.hot_object_active_top_label_share_total_ppm
            / metrics.hot_object_active_heights as u128
    };
    stats.hot_object_active_tail_share_avg_ppm = if metrics.hot_object_active_heights == 0 {
        0
    } else {
        metrics.hot_object_active_tail_share_total_ppm / metrics.hot_object_active_heights as u128
    };
    stats.hot_object_active_height_rate_ppm = ratio_ppm_u64(
        metrics.hot_object_active_heights,
        metrics.finality_samples_ms.len() as u64,
    );
    stats.hot_object_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.hot_object_active_heights,
        metrics.bft_observed_heights,
    );
    stats.hot_object_active_height_share_ppm = if metrics.hot_object_active_heights == 0 {
        0
    } else {
        (metrics.hot_object_active_top_label_share_total_ppm
            + metrics.hot_object_active_tail_share_total_ppm)
            / metrics.hot_object_active_heights as u128
    };
    stats.scheduler_share_avg_ppm = ratio_ppm(
        average_or_zero(&metrics.scheduler_samples_ms),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.scheduler_peak_share_ppm = ratio_ppm(
        max_or_zero(&metrics.scheduler_samples_ms),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.preexec_share_avg_ppm = ratio_ppm(
        average_or_zero(&metrics.preexec_samples_ms),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.commit_share_avg_ppm = ratio_ppm(
        average_or_zero(&metrics.commit_samples_ms),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.commit_peak_share_ppm = ratio_ppm(
        max_or_zero(&metrics.commit_samples_ms),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.state_root_total_share_avg_ppm = ratio_ppm(
        average_or_zero(&metrics.state_root_total_samples_ms),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.state_root_total_peak_share_ppm = ratio_ppm(
        max_or_zero(&metrics.state_root_total_samples_ms),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.rollback_share_avg_ppm = ratio_ppm(
        average_or_zero(&metrics.rollback_samples),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.rollback_peak_share_ppm = ratio_ppm(
        max_or_zero(&metrics.rollback_samples),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.preexec_peak_share_ppm = ratio_ppm(
        max_or_zero(&metrics.preexec_samples_ms),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.rollback_block_rate_ppm = ratio_ppm_u64(
        metrics.rollback_block_total,
        metrics.finality_samples_ms.len() as u64,
    );
    stats.rollback_active_heights = metrics.rollback_block_total;
    stats.rollback_active_height_rate_ppm = ratio_ppm_u64(
        metrics.rollback_block_total,
        metrics.finality_samples_ms.len() as u64,
    );
    stats.rollback_active_observed_height_rate_ppm =
        ratio_ppm_u64(metrics.rollback_block_total, metrics.bft_observed_heights);
    stats.rollback_density_avg = if metrics.rollback_block_total == 0 {
        0
    } else {
        metrics.rollback_total / metrics.rollback_block_total
    };
    stats.rollback_density_avg_milli =
        ratio_milli_u64(metrics.rollback_total, metrics.rollback_block_total);
    stats.rollback_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(metrics.rollback_total, metrics.rollback_block_total),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.preexec_conflict_miss_share_bps = ratio_percent_bps(
        metrics.apply_error_preexec_conflict_miss_total as u128,
        metrics.preexec_reject_total as u128,
    );
    stats.preexec_reject_density_avg = if metrics.preexec_reject_active_heights == 0 {
        0
    } else {
        metrics.preexec_reject_total / metrics.preexec_reject_active_heights
    };
    stats.preexec_reject_density_avg_milli = ratio_milli_u64(
        metrics.preexec_reject_total,
        metrics.preexec_reject_active_heights,
    );
    stats.preexec_reject_active_height_rate_ppm = ratio_ppm_u64(
        metrics.preexec_reject_active_heights,
        metrics.bft_committed_heights,
    );
    stats.preexec_reject_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.preexec_reject_active_heights,
        metrics.bft_observed_heights,
    );
    stats.preexec_reject_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            metrics.preexec_reject_total,
            metrics.preexec_reject_active_heights,
        ),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.apply_error_rollback_share_bps = ratio_percent_bps(
        metrics.rollback_total as u128,
        metrics.apply_error_total as u128,
    );
    stats.rollback_block_rate = if metrics.finality_samples_ms.is_empty() {
        0.0
    } else {
        metrics.rollback_block_total as f64 / metrics.finality_samples_ms.len() as f64
    };
    stats.critical_wait_density_ppm = ratio_ppm(
        average_or_zero(&metrics.critical_wait_blocks_samples),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.critical_wait_peak_density_ppm = ratio_ppm(
        max_or_zero(&metrics.critical_wait_blocks_samples),
        max_or_zero(&metrics.finality_samples_ms),
    );
    stats.critical_wait_active_height_rate_ppm = ratio_ppm_u64(
        metrics.critical_wait_active_heights,
        metrics.finality_samples_ms.len() as u64,
    );
    stats.critical_wait_active_observed_height_rate_ppm = ratio_ppm_u64(
        metrics.critical_wait_active_heights,
        metrics.bft_observed_heights,
    );
    stats.critical_wait_density_avg = if metrics.critical_wait_active_heights == 0 {
        0
    } else {
        metrics.critical_wait_total / metrics.critical_wait_active_heights
    };
    stats.critical_wait_density_avg_milli = ratio_milli_u64(
        metrics.critical_wait_total,
        metrics.critical_wait_active_heights,
    );
    stats.critical_wait_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            metrics.critical_wait_total,
            metrics.critical_wait_active_heights,
        ),
        average_or_zero(&metrics.finality_samples_ms),
    );
    stats.preexec_reject_share_bps = ratio_percent_bps(
        metrics.preexec_reject_total as u128,
        metrics.apply_error_total as u128,
    );
    stats.unprofiled_finality_share_bps = gap_percent_bps(
        average_or_zero(&metrics.finality_samples_ms),
        average_or_zero(&metrics.scheduler_samples_ms)
            .saturating_add(average_or_zero(&metrics.preexec_samples_ms))
            .saturating_add(average_or_zero(&metrics.commit_samples_ms)),
        average_or_zero(&metrics.state_root_total_samples_ms),
    );
}
