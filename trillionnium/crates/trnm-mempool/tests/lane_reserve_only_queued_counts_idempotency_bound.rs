use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_queued_counts_stay_stable_across_borrowed_duplicates_and_recovered_retry() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Reserve-only split: normal ingress borrows critical headroom, so all queued
    // work is accounted for in the critical lane.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Cross-class duplicate retries for borrowed ids must not perturb queue counts.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Fresh ids at full global capacity must remain backpressured without changing
    // reserve-only accounting.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // After one dequeue, the previously backpressured id should recover as fresh,
    // and only then should total queue accounting increase again.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.queued_counts(), (0, 2, 2));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Once queued, the recovered id must regain global duplicate protection across
    // classes without changing queue counts.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (0, 3, 3));
}
