use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_keeps_reopened_last_reserved_critical_slot_stable_under_duplicate_and_retry_noise() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Saturate the lane with dedicated normal occupancy plus two critical txs.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
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

    // After one critical tx drains, the final reserved critical slot reopens, but
    // fresh normal ingress must remain guard-blocked while critical backlog stays live.
    let drained = gate.pop_ready().expect("one queued critical tx should drain first");
    let remaining = if drained == 10 { 11 } else { 10 };
    let reopened_guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_guarded);

    // Duplicate probes for the still-queued critical tx, and retries for the
    // already-drained critical id, must remain classification-only noise.
    assert_eq!(gate.admit(remaining, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);
    assert_eq!(gate.admit(drained, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The reopened reserved slot must still accept a fresh critical tx immediately.
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
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
