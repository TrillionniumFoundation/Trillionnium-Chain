use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_last_reserved_slot_keeps_public_qos_surface_honest() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then leave exactly one aggregate slot
    // reserved for fresh critical ingress.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Cross-class duplicate probes against already queued normal work must stay
    // purely classificatory and must not make the guarded slot look borrowable.
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // While the final slot is guarded for critical ingress, fresh normal work
    // must fail closed even though aggregate headroom is still non-zero.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Once fresh critical work claims the final reserved slot, the public QoS
    // surface must close for both classes.
    assert_eq!(
        gate.admit(42, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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
}
