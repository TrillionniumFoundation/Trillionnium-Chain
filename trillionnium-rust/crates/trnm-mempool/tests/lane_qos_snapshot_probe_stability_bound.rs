use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_stays_stable_across_guarded_fresh_and_duplicate_probe_noise() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then activate critical backlog while one
    // aggregate slot still remains reserved for fresh critical ingress.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);

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

    // Reserve-guarded fresh normal probes must stay backpressured and must not
    // perturb observability while the final free slot remains protected for
    // critical ingress.
    for tx_id in [70_u64, 71, 72] {
        assert_eq!(gate.admit(tx_id, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Duplicate probes for the still-queued critical tx must also leave the
    // QoS snapshot untouched across ingress classes.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), expected);
}
