use super::*;

#[test]
fn stale_fairness_marker_is_cleared_after_successful_admission() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    // Fill bounded retry memory.
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);

    // Open one slot and fairness-defer a fresh id that cannot be remembered
    // because retry memory is already full.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);

    // A different fresh admission succeeds and must clear stale fairness marker state.
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(2));

    // If marker was stale, this would be a duplicate despite not being in retry memory.
    assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.fairness_deferrals, 2);
    assert_eq!(m.backpressure_duplicates, 0);
}

#[test]
fn fairness_marker_does_not_shadow_known_retry_id_admission() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // Open one slot to arm retry fairness, then simulate restored stale marker that
    // points to the known retry id itself.
    assert_eq!(gate.pop_ready(), Some(1));
    gate.last_fairness_deferred = Some(9);

    // Known retry must be admitted, not misclassified as fairness-duplicate.
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.accepted, 3);
    assert_eq!(m.duplicates, 0);
    assert_eq!(m.backpressure_duplicates, 0);
}

#[test]
fn stale_restored_retry_metadata_clears_before_fresh_ingress() {
    let mut gate = AdmissionGate::new(2);

    // Simulate restored/corrupted state that retained retry/fairness metadata even
    // though no retry ids remain.
    gate.retry_reservations = 2;
    gate.last_fairness_deferred = Some(77);
    gate.backpressured_fifo.extend([77, 88]);
    gate.backpressured_ids.clear();

    // Fresh ingress must stay on the no-retry fast path: admit successfully and
    // scrub stale retry bookkeeping instead of inheriting a phantom deferral.
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.queued(), 1);
    assert_eq!(gate.retry_reservations, 0);
    assert_eq!(gate.last_fairness_deferred, None);
    assert!(gate.backpressured_fifo.is_empty());

    let m = gate.metrics();
    assert_eq!(m.accepted, 1);
    assert_eq!(m.backpressured, 0);
    assert_eq!(m.duplicates, 0);
}
