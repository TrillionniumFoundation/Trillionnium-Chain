use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_critical_refill_duplicate_probes_keep_qos_and_queue_counts_flat() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow the last idle reserved slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // The borrowed normal tx sits in the critical lane, so it drains first.
    // Refill one reserved slot through critical ingress: normal admission should
    // reclose immediately while one aggregate slot remains reachable only by
    // critical spillover into still-free normal headroom.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    // Same-id retries from either ingress class must remain classification-only:
    // they should dedupe, not mutate queue occupancy, and not perturb the guarded
    // public QoS surface while the last reserved slot is actively owned.
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);
}
