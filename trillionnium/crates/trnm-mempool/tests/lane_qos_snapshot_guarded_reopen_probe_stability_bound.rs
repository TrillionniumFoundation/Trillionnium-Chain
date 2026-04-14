use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_stays_stable_when_last_reserved_critical_slot_is_still_guarded_after_reopen() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then occupy both reserved critical slots.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Draining one critical tx reopens aggregate capacity, but fresh normal ingress
    // must stay guard-blocked while the final reserved critical slot remains live.
    let drained = gate.pop_ready().expect("one live critical tx should drain");
    let remaining = if drained == 10 { 11 } else { 10 };

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

    // Guarded fresh-normal probe noise must remain classification-only and leave
    // the externally visible QoS snapshot unchanged.
    assert_eq!(
        gate.admit(70, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(
        gate.admit(71, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), guarded);

    // Cross-class duplicate probes for the still-queued critical tx must preserve
    // the guarded snapshot, while probing the already-drained id must degrade to
    // the same guarded backpressure path without reopening observability.
    assert_eq!(
        gate.admit(remaining, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(
        gate.admit(drained, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), guarded);
}
