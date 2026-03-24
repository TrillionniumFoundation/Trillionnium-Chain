use super::*;

pub(crate) fn fill_distribution_stats(stats: &mut RuntimeSummaryStats, metrics: &RuntimeMetrics) {
    stats.finality_p50 = percentile(metrics.finality_samples_ms.clone(), 0.50);
    stats.finality_p95 = percentile(metrics.finality_samples_ms.clone(), 0.95);
    stats.scheduler_p50 = percentile(metrics.scheduler_samples_ms.clone(), 0.50);
    stats.scheduler_p95 = percentile(metrics.scheduler_samples_ms.clone(), 0.95);
    stats.preexec_p50 = percentile(metrics.preexec_samples_ms.clone(), 0.50);
    stats.preexec_p95 = percentile(metrics.preexec_samples_ms.clone(), 0.95);
    stats.commit_p50 = percentile(metrics.commit_samples_ms.clone(), 0.50);
    stats.commit_p95 = percentile(metrics.commit_samples_ms.clone(), 0.95);
    stats.state_root_total_p50 = percentile(metrics.state_root_total_samples_ms.clone(), 0.50);
    stats.state_root_total_p95 = percentile(metrics.state_root_total_samples_ms.clone(), 0.95);
    stats.critical_wait_blocks_p50 = percentile(metrics.critical_wait_blocks_samples.clone(), 0.50);
    stats.critical_wait_blocks_p95 = percentile(metrics.critical_wait_blocks_samples.clone(), 0.95);
    stats.block_txs_p50 = percentile(metrics.block_txs_samples.clone(), 0.50);
    stats.block_txs_p95 = percentile(metrics.block_txs_samples.clone(), 0.95);
    stats.block_groups_p50 = percentile(metrics.block_groups_samples.clone(), 0.50);
    stats.block_groups_p95 = percentile(metrics.block_groups_samples.clone(), 0.95);
    stats.rollback_p50 = percentile(metrics.rollback_samples.clone(), 0.50);
    stats.rollback_p95 = percentile(metrics.rollback_samples.clone(), 0.95);
    stats.avg_group_size_p50 = percentile(metrics.avg_group_size_samples.clone(), 0.50);
    stats.avg_group_size_p95 = percentile(metrics.avg_group_size_samples.clone(), 0.95);
    stats.hot_object_share_p50_ppm = percentile(metrics.hot_object_share_samples_ppm.clone(), 0.50);
    stats.hot_object_share_p95_ppm = percentile(metrics.hot_object_share_samples_ppm.clone(), 0.95);
    stats.hot_object_top_label_share_p50_ppm =
        percentile(metrics.hot_object_top_label_share_samples_ppm.clone(), 0.50);
    stats.hot_object_top_label_share_p95_ppm =
        percentile(metrics.hot_object_top_label_share_samples_ppm.clone(), 0.95);
    stats.hot_object_tail_share_p50_ppm =
        percentile(metrics.hot_object_tail_share_samples_ppm.clone(), 0.50);
    stats.hot_object_tail_share_p95_ppm =
        percentile(metrics.hot_object_tail_share_samples_ppm.clone(), 0.95);

    stats.finality_max = max_or_zero(&metrics.finality_samples_ms);
    stats.scheduler_max = max_or_zero(&metrics.scheduler_samples_ms);
    stats.preexec_max = max_or_zero(&metrics.preexec_samples_ms);
    stats.commit_max = max_or_zero(&metrics.commit_samples_ms);
    stats.state_root_total_max = max_or_zero(&metrics.state_root_total_samples_ms);
    stats.critical_wait_blocks_max = max_or_zero(&metrics.critical_wait_blocks_samples);
    stats.block_txs_max = max_or_zero(&metrics.block_txs_samples);
    stats.block_groups_max = max_or_zero(&metrics.block_groups_samples);
    stats.rollback_max = max_or_zero(&metrics.rollback_samples);
    stats.avg_group_size_max = max_or_zero(&metrics.avg_group_size_samples);
    stats.hot_object_share_max_ppm = max_or_zero(&metrics.hot_object_share_samples_ppm);
    stats.hot_object_top_label_share_max_ppm =
        max_or_zero(&metrics.hot_object_top_label_share_samples_ppm);
    stats.hot_object_tail_share_max_ppm = max_or_zero(&metrics.hot_object_tail_share_samples_ppm);

    stats.finality_avg = average_or_zero(&metrics.finality_samples_ms);
    stats.scheduler_avg = average_or_zero(&metrics.scheduler_samples_ms);
    stats.preexec_avg = average_or_zero(&metrics.preexec_samples_ms);
    stats.commit_avg = average_or_zero(&metrics.commit_samples_ms);
    stats.state_root_total_avg = average_or_zero(&metrics.state_root_total_samples_ms);
    stats.critical_wait_blocks_avg = average_or_zero(&metrics.critical_wait_blocks_samples);
    stats.rollback_avg = average_or_zero(&metrics.rollback_samples);
    stats.avg_group_size_avg = average_or_zero(&metrics.avg_group_size_samples);
    stats.hot_object_share_avg_ppm = average_or_zero(&metrics.hot_object_share_samples_ppm);
    stats.hot_object_top_label_share_avg_ppm =
        average_or_zero(&metrics.hot_object_top_label_share_samples_ppm);
    stats.hot_object_tail_share_avg_ppm =
        average_or_zero(&metrics.hot_object_tail_share_samples_ppm);
}
