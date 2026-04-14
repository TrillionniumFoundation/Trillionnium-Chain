use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_preserves_multi_slot_refill_visibility_across_mixed_probe_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. After two occupants drain, observers should see two reopened shared
    // slots immediately. Duplicate probes against the still-queued id must remain
    // classification-only even if a drained id is re-admitted in between.
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(22, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.pop_ready(), Some(21));

    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 2,
        total_headroom: 2,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // Cross-class duplicate noise for the still-queued id must not perturb the
    // reopened sponsor/free-ingress surface.
    assert_eq!(
        gate.admit(22, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened);

    // A drained id may re-enter as fresh work and consume exactly one reopened
    // shared slot.
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // Duplicate probes for both the surviving original id and the freshly
    // re-admitted id must stay classification-only and leave the last reopened
    // shared slot visible until a truly fresh tx consumes it.
    assert_eq!(
        gate.admit(22, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    assert_eq!(gate.admit(23, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 3,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );
}
