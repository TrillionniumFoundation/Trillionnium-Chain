use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_stays_stable_while_last_reserved_critical_slot_is_guarded() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then leave exactly one reserved critical
    // slot guarded under active critical backlog.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    let expected = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };

    assert_eq!(gate.qos_snapshot(), expected);

    // While the final reserved slot is guard-owned, fresh normal retries must stay
    // backpressured and must not perturb the operator-facing QoS snapshot.
    for tx_id in [70_u64, 71_u64, 72_u64] {
        assert_eq!(
            gate.admit(tx_id, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Duplicate probes for the already queued critical item must also leave the
    // guarded snapshot unchanged across ingress classes.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);

    // Fresh critical ingress may still consume the guarded slot, after which the
    // snapshot should flip to fully saturated semantics.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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
