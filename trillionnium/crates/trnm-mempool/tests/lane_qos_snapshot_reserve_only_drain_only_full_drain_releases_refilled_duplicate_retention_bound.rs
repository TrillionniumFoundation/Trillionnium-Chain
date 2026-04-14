use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drain_only_full_drain_releases_refilled_duplicate_retention_and_restores_shared_reuse(
) {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the Day-1 sponsor/free-ingress boundary under a
    // drain-only sponsor revocation stance: already-queued survivors remain
    // globally duplicate-classified until they truly drain from the shared lane.
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

    // One real drain reopens exactly one shared slot, and a fresh post-revocation
    // refill may consume it through the opposite ingress class.
    assert_eq!(gate.pop_ready(), Some(10));
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
    assert_eq!(
        gate.admit(40, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // While queued, both the pre-revocation survivor and the post-revocation
    // refill must remain duplicate-classified across ingress classes.
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(40, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // Once the shared lane truly drains, duplicate retention must be released for
    // both ids so either ingress class can reuse them as fresh work.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.pop_ready(), Some(30));
    assert_eq!(gate.pop_ready(), Some(40));
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
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(40, IngressClass::Normal), AdmitOutcome::Accepted);
}
