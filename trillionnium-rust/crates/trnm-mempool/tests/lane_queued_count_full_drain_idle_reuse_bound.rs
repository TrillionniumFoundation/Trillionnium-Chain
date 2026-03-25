use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn queued_counts_reset_cleanly_after_spillover_full_drain_and_idle_poll() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill normal capacity plus the critical reserve, then spill one critical tx
    // into borrowed normal headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Cross-class duplicate probes for the spillovered tx must not perturb counts.
    assert_eq!(
        gate.admit(51, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Drain the queue completely. The spillovered tx should remain duplicate until
    // it is actually popped, then duplicate knowledge must clear on full drain.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.queued_counts(), (3, 0, 3));
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 0, 3));

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(51));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Idle dequeue polls are a self-heal boundary; once the lane is empty, the same
    // tx id should be admitted again instead of staying stuck as a ghost duplicate.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.admit(51, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 0, 1));
}
