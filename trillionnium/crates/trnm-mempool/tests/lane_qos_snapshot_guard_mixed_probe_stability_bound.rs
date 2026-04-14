use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_stays_flat_across_mixed_probe_noise_while_last_reserved_slot_is_guarded() {
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

    let guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), guarded);

    // Repeated fresh normal probes must stay backpressured, and duplicate probes
    // for the already queued critical id must remain duplicate, without changing
    // the operator-facing snapshot while the last reserved slot is still guarded.
    for _ in 0..3 {
        assert_eq!(
            gate.admit(70, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            gate.admit(1, IngressClass::Critical),
            AdmitOutcome::Duplicate
        );
        assert_eq!(
            gate.admit(10, IngressClass::Normal),
            AdmitOutcome::Duplicate
        );
        assert_eq!(
            gate.admit(10, IngressClass::Critical),
            AdmitOutcome::Duplicate
        );
        assert_eq!(gate.queued_counts(), (3, 1, 4));
        assert_eq!(gate.qos_snapshot(), guarded);
    }

    // Fresh critical ingress may still consume the guarded slot. After that,
    // aggregate headroom closes for both classes until a dequeue reopens it.
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
