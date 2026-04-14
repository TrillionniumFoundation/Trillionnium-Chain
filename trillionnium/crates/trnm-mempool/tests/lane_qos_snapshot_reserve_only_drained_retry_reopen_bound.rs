use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_reopen_allows_drained_id_retry_across_ingress_classes() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Once one occupant drains, the single reopened slot should be usable
    // immediately even if the drained id retries through the opposite ingress class.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
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

    // The drained id must no longer be duplicate-poisoned after dequeue; retrying
    // it via the opposite ingress class should consume the reopened shared slot.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

    // Shared-lane FIFO should keep the surviving queued work ahead of the retried id.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), None);
}
