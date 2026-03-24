use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_duplicate_probes_do_not_disturb_next_fair_normal_turn() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill the lane with active critical pressure plus normal backlog. With a
    // single reserved critical slot, later critical items spill into normal.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // While globally saturated, repeated probes should preserve classification:
    // queued ids stay Duplicate; fresh ids stay Backpressured.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Probe noise must not disturb the warmed fairness contract: once draining
    // resumes, the oldest normal item should still get a turn within one dequeue.
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    let third = gate.pop_ready();
    assert_eq!((first, second, third), (Some(101), Some(100), Some(1)));
}
