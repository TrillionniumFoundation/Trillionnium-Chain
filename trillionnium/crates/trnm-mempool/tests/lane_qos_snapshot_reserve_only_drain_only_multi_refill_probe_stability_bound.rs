use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drain_only_qos_snapshot_preserves_multi_slot_refill_visibility_across_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the Day-1 sponsor/free-ingress boundary under a
    // drain-only sponsor revocation stance: queued survivors stay globally
    // duplicate-classified until they truly leave the shared lane.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // After two real drains, operators should see two reopened shared slots
    // immediately, but the remaining queued survivor must stay duplicate-
    // classified across ingress classes until it truly drains.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(20));

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
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // A drained id may re-enter as fresh work and consume exactly one reopened
    // shared slot.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    let reopened_once = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_once);

    // Duplicate probes for both the still-queued pre-revocation survivor and the
    // fresh refill must remain purely classificatory and leave the final reopened
    // public headroom visible until truly fresh work consumes it.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened_once);

    assert_eq!(gate.admit(40, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
}
