use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn critical_spillover_only_headroom_keeps_normal_closed_across_duplicate_and_retry_noise() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Leave exactly one aggregate slot free, but make it reachable only by fresh
    // critical spillover into normal headroom while the final reserved critical
    // slot remains guarded against normal ingress.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    let spillover_only_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);

    // Cross-class retries of the already queued normal occupant must remain
    // Duplicate, and fresh normal retry noise must remain Backpressured, without
    // perturbing the operator-facing QoS contract.
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), spillover_only_snapshot);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The remaining aggregate slot is still genuinely available only to fresh
    // critical ingress. Because one dedicated critical slot is still free, the
    // next critical tx should claim that final reserved slot directly, and QoS
    // must then fail closed for both classes immediately.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
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
