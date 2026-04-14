use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_refilled_shared_slot_stays_closed_under_cross_class_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary:
    // both ingress classes share one public admission surface until a real drain
    // reopens exactly one shared slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

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

    assert_eq!(gate.pop_ready(), Some(1));
    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // A fresh sponsor-backed refill may consume the only reopened shared slot.
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // Once the slot is refilled, duplicate probes from either surviving queued
    // work or the refilled id itself must stay purely classificatory and keep the
    // public sponsor/free-ingress snapshot fail-closed.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.admit(4, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);

    // Shared-lane FIFO still drains the older surviving occupants before the
    // refilled sponsor-backed work.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), Some(4));
    assert_eq!(gate.pop_ready(), None);
}
