use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_flips_from_borrowable_to_guarded_once_critical_backlog_claims_final_reserved_slot() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then borrow one idle critical slot to keep
    // free-ingress throughput live while the critical lane is still partially idle.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(13, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    // Once a real critical tx claims the final reserved slot, observability must
    // stop advertising any fresh admission headroom for either class.
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    let saturated = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 2,
        total_queued: 5,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // Guarded fresh-normal probe noise must not perturb the saturated snapshot.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);
}
