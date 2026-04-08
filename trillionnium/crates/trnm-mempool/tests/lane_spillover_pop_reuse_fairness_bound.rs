use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn popped_spillover_id_can_reenter_without_cooling_warm_fairness() {
    let mut gate = LaneAdmissionGate::new(5, 1);

    // Fill the dedicated critical reserve, then spill one critical tx into the
    // normal lane. This path warms fairness under active dual backlog.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // The spillovered critical item sits at the normal-queue head and may drain
    // first when fairness is warm.
    assert_eq!(gate.pop_ready(), Some(11));

    // Once dequeued, the same id must immediately become fresh again. Re-entering
    // it via critical ingress must not inherit stale duplicate state, and must not
    // cool the bounded fairness contract for the older real normal backlog.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Critical reserve backlog still gets its turn next.
    assert_eq!(gate.pop_ready(), Some(10));

    // Warm fairness should still give the oldest real normal item its bounded turn
    // before the re-entered spillover id can cut in line.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
}
