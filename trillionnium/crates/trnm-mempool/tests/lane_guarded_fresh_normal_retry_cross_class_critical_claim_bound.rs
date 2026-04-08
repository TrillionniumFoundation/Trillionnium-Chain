use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_fresh_normal_retry_does_not_poison_cross_class_critical_claim_on_last_reserved_slot() {
    let mut g = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity while leaving exactly one aggregate slot
    // reserved for fresh critical ingress.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), guarded_snapshot);

    // Fresh normal retries are blocked by the reserve guard, but that must remain
    // purely classificatory: the tx id stays fresh and must not be poisoned into
    // Duplicate if it later arrives via the admissible critical path.
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    // The same tx id should still be able to claim the final reserved slot through
    // critical ingress, proving reserve-guarded normal retries do not poison
    // cross-class admission.
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 2, 5));
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
}
