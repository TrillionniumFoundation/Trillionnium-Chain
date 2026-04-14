use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn spillover_qos_snapshot_stays_stable_across_saturated_fresh_and_duplicate_probe_noise() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the reserved critical slot plus the dedicated normal headroom, then
    // force one more critical tx to spill into the normal lane so aggregate
    // admission is fully saturated.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let expected = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), expected);

    // Once spillover saturation is active, fresh retries from either class must
    // stay backpressured and must not perturb the operator-facing QoS surface.
    for (tx_id, class) in [
        (90_u64, IngressClass::Normal),
        (91_u64, IngressClass::Critical),
        (92_u64, IngressClass::Normal),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // The spillovered critical tx must remain globally deduped across classes,
    // again without mutating the saturated QoS snapshot.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(
        gate.admit(11, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
}
