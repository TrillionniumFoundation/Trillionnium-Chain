use super::*;

#[test]
fn duplicate_admission_is_idempotent() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(42), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(42), AdmitOutcome::Duplicate);

    assert_metrics(gate.metrics(), 1, 1, 0, 0, 0);
}

#[test]
fn capacity_exhaustion_triggers_backpressure() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

    assert_metrics(gate.metrics(), 1, 0, 1, 0, 0);
}

#[test]
fn released_slot_allows_new_admission() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
}

#[test]
fn zero_capacity_is_clamped_to_keep_forward_progress() {
    let mut gate = AdmissionGate::new(0);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
}

#[test]
fn zero_capacity_configuration_still_allows_progress() {
    // Capacity is clamped to 1 so a misconfigured zero-capacity gate does not
    // deadlock all ingress into permanent backpressure.
    let mut gate = AdmissionGate::new(0);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.accepted, 2);
    assert_eq!(m.backpressured, 1);
}

#[test]
fn metrics_counters_saturate_instead_of_overflowing() {
    let mut gate = AdmissionGate::new(1);
    gate.metrics.accepted = usize::MAX;
    gate.metrics.duplicates = usize::MAX;
    gate.metrics.backpressured = usize::MAX;
    gate.metrics.backpressure_duplicates = usize::MAX;
    gate.metrics.fairness_deferrals = usize::MAX;

    // Accepted path saturates accepted.
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    // Duplicate path saturates duplicates.
    assert_eq!(gate.admit(1), AdmitOutcome::Duplicate);

    // Backpressure + duplicate(backpressured) path saturates both counters.
    assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(2), AdmitOutcome::Duplicate);

    // Fairness deferral path saturates fairness_deferrals/backpressured.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.accepted, usize::MAX);
    assert_eq!(m.duplicates, usize::MAX);
    assert_eq!(m.backpressured, usize::MAX);
    assert_eq!(m.backpressure_duplicates, usize::MAX);
    assert_eq!(m.fairness_deferrals, usize::MAX);
}
