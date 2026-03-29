use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_stays_cold_and_reopened_across_idle_polls_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes all live work through the shared critical lane.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), None);

    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 3,
        total_headroom: 3,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // Long-lived schedulers may keep polling an already drained shared lane.
    // Those idle polls must remain classification-free no-ops and preserve the
    // reopened sponsor/free-ingress observability state.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.qos_snapshot(), reopened);

    // After the idle-poll noise, either ingress class should still be able to
    // consume freshly reopened shared capacity immediately.
    assert_eq!(gate.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot().total_queued, 1);
    assert!(gate.qos_snapshot().fresh_normal_admissible);
    assert!(gate.qos_snapshot().fresh_critical_admissible);
}
