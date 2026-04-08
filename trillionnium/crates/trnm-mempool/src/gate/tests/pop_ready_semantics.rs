use super::*;

#[test]
fn pop_ready_clears_stale_fairness_marker_when_retry_memory_is_empty() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    // Simulate stale/restored marker state with no known retries.
    gate.last_fairness_deferred = Some(99);
    gate.retry_reservations = 1;
    gate.backpressured_ids.clear();
    gate.backpressured_fifo.extend([42, 43, 42]);

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
    assert!(gate.backpressured_fifo.is_empty());
}

#[test]
fn pop_ready_compacts_oversized_retry_fifo_when_retry_memory_is_non_empty() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

    // Simulate restored/churned state where stale markers are oversized while
    // active retry ids still exist.
    gate.backpressured_fifo
        .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
    assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

    assert_eq!(gate.pop_ready(), Some(1));

    // Dequeue boundary should compact stale retry markers even before retry admission.
    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}

#[test]
fn empty_pop_compacts_oversized_retry_fifo_when_retry_memory_is_non_empty() {
    let mut gate = AdmissionGate::new(2);

    // Simulate restored/churned state after the queue already drained: active retry ids
    // remain, but stale FIFO markers are oversized and only idle polls are happening.
    gate.backpressured_ids.extend([10, 11]);
    gate.backpressured_fifo
        .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
    assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

    assert_eq!(gate.pop_ready(), None);

    // Empty-pop polling should still compact stale retry markers to keep bounded memory.
    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}
