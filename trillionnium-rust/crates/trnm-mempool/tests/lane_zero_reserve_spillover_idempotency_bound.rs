use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_critical_spillover_retry_stays_fresh_until_drain_and_then_dedupes() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero critical reserve: critical ingress must spill into normal headroom.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Once globally saturated, a fresh critical id must remain backpressured
    // across cross-class retries instead of being poisoned into Duplicate.
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Backpressured);

    // After one dequeue opens headroom, the previously backpressured id should
    // admit immediately via critical spillover.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);

    // While queued through spillover, the same id must still dedupe globally
    // across ingress classes until it drains.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Duplicate);
}
