use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_lane_preserves_duplicate_vs_backpressure_contract() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // At full capacity, duplicate ids must stay Duplicate while fresh ids are
    // classified as Backpressured.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Backpressured);

    // After one dequeue (from either lane), the previously backpressured id
    // should admit as fresh.
    let drained = gate.pop_ready();
    assert!(drained == Some(10) || drained == Some(11));
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
}
