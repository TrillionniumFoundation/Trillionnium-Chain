use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn critical_only_spillover_headroom_keeps_normal_closed_until_real_critical_refill() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity and leave exactly one reserved critical slot
    // free under active critical backlog. At this point the final aggregate slot
    // is reachable only by fresh critical spillover into normal headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);

    let spillover_only_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);

    // Duplicate probes against the already-queued critical id and fresh normal
    // retry noise must stay classification-only. They must not fabricate normal
    // headroom or perturb the operator-facing snapshot before a real refill.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);

    // A real critical refill consumes the final reserved critical slot, after
    // which the lane must advertise itself as fully closed to fresh ingress.
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 2,
            total_queued: 5,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // The earlier fresh normal retry must still remain fail-closed until a real
    // dequeue reopens capacity.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
}
