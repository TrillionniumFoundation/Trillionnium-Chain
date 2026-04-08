use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drain_only_duplicate_retention_keeps_shared_snapshot_closed_until_survivor_drains() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. This models the launch-day sponsor/free-ingress boundary where
    // revocation falls back to drain-only: no replay probe should fabricate new
    // public headroom until the already-queued sponsored work truly drains.
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

    // One queued id drains, but surviving queued ids must remain duplicate-classified
    // across both ingress classes until they themselves leave the queue.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);

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

    // Fresh replay of the already-drained id may reuse the reopened slot, but the
    // remaining queued survivor must still stay duplicate-classified until it drains.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);

    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.pop_ready(), Some(30));

    // Only after the survivor itself drains may it re-enter as fresh work.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
}
