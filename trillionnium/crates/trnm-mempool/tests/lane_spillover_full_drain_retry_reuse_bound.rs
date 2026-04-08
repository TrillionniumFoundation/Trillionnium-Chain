use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_duplicate_probe_id_can_reenter_as_fresh_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 2);

    // Fill reserved critical capacity, then spill one more critical tx into the
    // normal lane while critical pressure is still active.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (1, 2, 3));

    // Cross-class duplicate probe noise against the spillovered id must remain
    // Duplicate while the tx is queued, regardless of ingress class.
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Drain the full mixed backlog.
    let mut drained = [gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, [Some(100), Some(101), Some(102)]);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After a full drain, the old spillovered id must be reusable as fresh
    // ingress instead of staying poisoned by stale lane-local or global dedupe
    // state from the earlier duplicate probes.
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (1, 0, 1));
}
