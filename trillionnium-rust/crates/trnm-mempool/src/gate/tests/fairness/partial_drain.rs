use super::*;

#[test]
fn backpressure_retry_memory_survives_partial_drain_and_resaturation() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

    // A single slot opens but is consumed by another tx before id=9 retries.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

    // Retry should be admitted ahead of fresh ingress to avoid starvation.
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

    let m = gate.metrics();
    assert_eq!(m.backpressured, 2);
    assert_eq!(m.backpressure_duplicates, 0);
    assert_eq!(m.fairness_deferrals, 1);
}
