use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drain_only_full_drain_releases_duplicate_retention_and_restores_shared_headroom() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the Day-1 sponsor/free-ingress boundary under a
    // drain-only sponsor revocation stance: surviving queued ids must remain
    // globally duplicate-classified until they truly leave the shared lane.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

    // One real drain reopens exactly one shared slot, but already-queued ids
    // must still remain duplicate-classified across both ingress classes.
    assert_eq!(gate.pop_ready(), Some(10));
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
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened_once);

    // Even with two shared slots reopened, the final queued survivor must stay
    // duplicate-classified until the queue truly drains.
    assert_eq!(gate.pop_ready(), Some(20));
    let reopened_twice = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 2,
        total_headroom: 2,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_twice);
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened_twice);

    // Once the last queued survivor truly drains, duplicate retention must be
    // released completely so either ingress class can reuse the ids as fresh work.
    assert_eq!(gate.pop_ready(), Some(30));
    assert_eq!(gate.pop_ready(), None);

    let empty = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 3,
        total_headroom: 3,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), empty);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
}
