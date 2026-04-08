use super::*;

#[test]
fn fairness_reservation_preserves_free_ingress_when_spare_capacity_exists() {
    let mut gate = AdmissionGate::new(4);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(4), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Two slots open while only one retry id is known.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));

    // Queue now has two free slots. Fresh ingress should proceed without deferral
    // because one slot can still remain reserved for retry traffic.
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
    assert_eq!(gate.metrics().fairness_deferrals, 0);

    // Known retry can still consume the reserved slot.
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
}

#[test]
fn fairness_armed_fresh_acceptance_keeps_known_retry_memory_intact() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Two slots open; fairness remains armed with a single known retry id.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));

    // Fresh ingress is accepted because free_slots > retry_reservations.
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
    // Retry memory must remain intact so id=9 is still admitted later.
    assert!(gate.backpressured_ids.contains(&9));
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
}

#[test]
fn burst_capacity_release_only_defers_fresh_ingress_for_known_retry_budget() {
    let mut gate = AdmissionGate::new(4);
    for tx_id in 1..=4 {
        assert_eq!(gate.admit(tx_id), AdmitOutcome::Accepted);
    }

    // Only two known retries exist.
    assert_eq!(gate.admit(90), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(91), AdmitOutcome::Backpressured);

    // Free three slots in a burst.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));

    // Spare capacity exceeds retry reservation budget, so fresh ingress should
    // proceed without additional fairness deferrals.
    assert_eq!(gate.admit(1000), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(1001), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(1002), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(1003), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 0);
}

#[test]
fn draining_last_known_retry_clears_stale_fairness_reservations() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Build up reservations by freeing slots before retry arrives.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

    // No retry ids remain; fresh ingress should not be deferred.
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 0);
}

#[test]
fn admitting_last_known_retry_clears_stale_retry_fifo_markers_immediately() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Simulate stale FIFO marker buildup around the one real retry id.
    gate.backpressured_fifo.extend([999, 9, 999]);
    assert!(gate.backpressured_fifo.len() > gate.backpressured_ids.len());

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

    assert!(gate.backpressured_ids.is_empty());
    assert_eq!(gate.retry_reservations, 0);
    assert!(
        gate.backpressured_fifo.is_empty(),
        "accepting the last known retry should cold-reset stale retry FIFO markers"
    );
}

#[test]
fn admitting_last_known_retry_does_not_leave_fresh_ingress_stuck_behind_stale_fairness_marker() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Open one slot, then fairness-defer a fresh tx while the known retry still has priority.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, Some(20));

    // Once the final known retry is accepted, the next fresh ingress should not be poisoned
    // by the stale fairness marker from the earlier deferral.
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
    assert!(gate.backpressured_ids.is_empty());
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
    assert_eq!(gate.admit(21), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 2);
    assert_eq!(m.backpressure_duplicates, 0);
}

#[test]
fn spare_capacity_after_retry_drain_accepts_new_fresh_ids_without_reviving_stale_fairness() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(90), AdmitOutcome::Backpressured);

    // Open one slot and consume it with the only known retry, which should clear
    // retry reservations and any stale fairness marker immediately.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(90), AdmitOutcome::Accepted);
    assert!(gate.backpressured_ids.is_empty());
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);

    // After another dequeue opens spare capacity, brand-new ingress should be accepted
    // directly instead of being treated like a carried-over fairness-deferred retry.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.admit(1000), AdmitOutcome::Accepted);
    assert_eq!(gate.last_fairness_deferred, None);
    assert_eq!(gate.metrics().fairness_deferrals, 0);
}
