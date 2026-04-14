use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_reserve_single_slot_reopen_stays_stable_across_duplicate_probe_noise() {
    let mut gate = LaneAdmissionGate::new(1, 99);

    // Misconfigured reserve > total clamps into a one-slot reserve-only lane.
    // Borrowed normal ingress may consume the only slot while the critical side
    // remains globally deduped and fail-closed until a real drain reopens it.
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 1,
            total_queued: 1,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // A real drain must immediately reopen the single shared slot.
    assert_eq!(gate.pop_ready(), Some(41));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // Once drained, the old tx id is fresh again and may reclaim the only slot.
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // Duplicate probes against the queued single-slot occupant must stay purely
    // classificatory and must not perturb the fail-closed QoS surface.
    assert_eq!(
        gate.admit(41, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // After a second real drain, a fresh id must admit immediately into the same
    // reopened slot, proving duplicate noise did not poison or consume it.
    assert_eq!(gate.pop_ready(), Some(41));
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 1,
            total_queued: 1,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );
}
