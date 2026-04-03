use super::*;

#[test]
fn opened_capacity_is_reserved_for_known_retries_before_fresh_ingress() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(4), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 1);
}

#[test]
fn fairness_reservation_does_not_deadlock_fresh_ingress_when_retries_disappear() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

    assert_eq!(gate.pop_ready(), Some(1));
    // First fresh ingress is deferred to give retry id=2 one chance.
    assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);
    // If no retry shows up, subsequent fresh ingress must still make progress.
    assert_eq!(gate.admit(4), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 1);
}

#[test]
fn retry_reservation_is_capped_by_known_retry_population() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);

    // Only one known retry id exists.
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Open two slots before retry arrives.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));

    // With spare capacity beyond the one retry reservation, fresh ingress
    // should progress without deferral.
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 0);
}

#[test]
fn stale_retry_reservation_is_clamped_before_fairness_deferral() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Open one slot and then simulate stale/restored over-large reservation state.
    assert_eq!(gate.pop_ready(), Some(1));
    gate.retry_reservations = 99;

    // Clamp should limit deferral pressure to the one known retry id.
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 1);
}

#[test]
fn stale_retry_reservations_are_clamped_before_fresh_ingress_deferral() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    // Simulate restored/churned runtime state with one known retry id but
    // stale oversized reservation count.
    gate.backpressured_ids.insert(99);
    gate.retry_reservations = 3;

    // With free_slots=2 and retry_budget=1, stale reservations must be
    // clamped so fresh ingress is accepted instead of over-deferred.
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    // Clamp should now be observable in runtime state.
    assert_eq!(gate.retry_reservations, 0);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 0);
    assert_eq!(m.backpressured, 0);
}

#[test]
fn fresh_admission_clears_stale_fairness_marker_and_fifo_when_retry_memory_is_empty() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    // Simulate restored/churned state: no known retry ids remain, but stale
    // fairness + fifo bookkeeping survived a prior partial restore.
    gate.last_fairness_deferred = Some(777);
    gate.retry_reservations = 2;
    gate.backpressured_fifo.extend([777, 778, 777]);
    assert!(gate.backpressured_ids.is_empty());

    // Admission fast-path should self-heal stale retry/fairness state before
    // deciding whether fresh ingress can proceed.
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.last_fairness_deferred, None);
    assert_eq!(gate.retry_reservations, 0);
    assert!(gate.backpressured_fifo.is_empty());

    let m = gate.metrics();
    assert_eq!(m.accepted, 2);
    assert_eq!(m.fairness_deferrals, 0);
    assert_eq!(m.backpressured, 0);
}
