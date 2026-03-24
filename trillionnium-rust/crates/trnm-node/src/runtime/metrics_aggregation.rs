use super::*;

#[path = "metrics_aggregation/summary_stats.rs"]
mod summary_stats;
use summary_stats::collect_runtime_summary_stats;

#[path = "metrics_aggregation/summary_format.rs"]
mod summary_format;
use summary_format::format_runtime_summary_line;

pub(crate) fn build_runtime_summary_line(
    runtime: &RuntimeState,
    metrics: &RuntimeMetrics,
) -> String {
    let stats = collect_runtime_summary_stats(runtime, metrics);
    format_runtime_summary_line(metrics, &stats)
}
