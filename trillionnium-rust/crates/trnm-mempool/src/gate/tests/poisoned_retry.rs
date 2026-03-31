use super::*;

#[test]
fn stale_retry_bookkeeping_is_cleared_before_free_ingress_admission() {
    let mut gate = AdmissionGate::new(2);

    // Simulate restored/corrupted bookkeeping: no known retries but stale
    // reservation/marker/fifo state remains.
    gate.retry_reservations = 2;
    gate.last_fairness_deferred = Some(99);
    gate.backpressured_fifo.push_back(99);

    assert_eq!(gate.admit(100), AdmitOutcome::Accepted);
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
    assert!(gate.backpressured_fifo.is_empty());
}

#[test]
fn stale_fairness_marker_without_known_retries_does_not_force_duplicate() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    // Simulate restored stale state with no known retries left.
    gate.retry_reservations = 1;
    gate.last_fairness_deferred = Some(9);
    gate.backpressured_ids.clear();

    // With no retry memory, fresh id should be treated as backpressured, not duplicate.
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.duplicates, 0);
    assert_eq!(m.backpressured, 1);
}

#[test]
fn saturated_retry_remains_idempotent_when_stale_fairness_marker_points_to_known_retry() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Simulate restored stale fairness marker while queue is still saturated.
    gate.last_fairness_deferred = Some(9);
    gate.retry_reservations = 0;

    // Retry should stay idempotent duplicate (not a fresh backpressure event), and
    // retry memory must keep tracking the tx id for later admission once capacity opens.
    assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
    assert!(gate.backpressured_ids.contains(&9));

    let m = gate.metrics();
    assert_eq!(m.backpressured, 1);
    assert_eq!(m.duplicates, 1);
    assert_eq!(m.backpressure_duplicates, 1);
}

#[test]
fn admit_fast_path_clears_stale_retry_fifo_when_retry_set_is_empty() {
    let mut gate = AdmissionGate::new(3);

    // Simulate restored-state skew: stale retry fifo markers remain, but retry
    // memory itself is empty.
    gate.backpressured_fifo.extend([7, 8, 7, 9]);
    gate.backpressured_ids.clear();
    gate.retry_reservations = 2;
    gate.last_fairness_deferred = Some(7);

    assert_eq!(gate.admit(100), AdmitOutcome::Accepted);
    assert!(gate.backpressured_fifo.is_empty());
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
}

#[test]
fn admit_fast_path_clears_stale_retry_fifo_at_compaction_threshold_when_retry_set_is_empty() {
    let mut gate = AdmissionGate::new(2);

    // Restored/churned state can leave retry FIFO markers exactly at the
    // compaction threshold even after retry ids have fully drained.
    gate.backpressured_fifo.extend([7, 8, 7, 8, 7, 8, 7, 8]);
    gate.backpressured_ids.clear();
    gate.retry_reservations = 2;
    gate.last_fairness_deferred = Some(7);
    assert_eq!(gate.backpressured_fifo.len(), gate.capacity.saturating_mul(4));

    // Fresh ingress must still take the no-retry fast path and eagerly scrub
    // the stale FIFO tail instead of carrying dead retry bookkeeping forward.
    assert_eq!(gate.admit(100), AdmitOutcome::Accepted);
    assert!(gate.backpressured_fifo.is_empty());
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
}
