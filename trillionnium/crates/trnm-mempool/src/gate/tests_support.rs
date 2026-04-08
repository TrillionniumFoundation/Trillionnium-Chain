use super::GateMetrics;

pub(super) fn assert_metrics(
    metrics: GateMetrics,
    accepted: usize,
    duplicates: usize,
    backpressured: usize,
    backpressure_duplicates: usize,
    fairness_deferrals: usize,
) {
    assert_eq!(metrics.accepted, accepted);
    assert_eq!(metrics.duplicates, duplicates);
    assert_eq!(metrics.backpressured, backpressured);
    assert_eq!(metrics.backpressure_duplicates, backpressure_duplicates);
    assert_eq!(metrics.fairness_deferrals, fairness_deferrals);
}
