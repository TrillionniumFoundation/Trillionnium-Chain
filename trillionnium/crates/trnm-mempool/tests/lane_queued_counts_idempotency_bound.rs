use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn queued_counts_stay_stable_across_duplicate_and_backpressured_retries() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Fill dedicated normal capacity and reserve critical capacity.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Critical reserve is saturated, so this critical tx must spill into normal capacity.
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Duplicate retry for the spillovered tx must not perturb queue accounting.
    assert_eq!(
        gate.admit(51, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Fresh ids at full global capacity must remain backpressured without changing counts.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // After one critical dequeue, only the critical count should drop.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.queued_counts(), (3, 0, 3));

    // The spillovered tx is still queued and must remain globally deduped without
    // changing queue counts.
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 0, 3));
}
