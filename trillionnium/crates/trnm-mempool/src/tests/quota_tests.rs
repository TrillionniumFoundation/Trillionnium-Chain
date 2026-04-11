use super::*;

#[test]
fn queued_counts_track_spillover_and_drain() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.queued_counts(), (0, 0, 0));

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    // Critical reserve full; tx 51 spills into normal queue.
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    assert_eq!(g.pop_ready(), Some(50));
    assert_eq!(g.queued_counts(), (3, 0, 3));

    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(2));
    assert_eq!(g.pop_ready(), Some(51));
    assert_eq!(g.queued_counts(), (0, 0, 0));
}

#[test]
fn seen_global_len_matches_lane_queues_across_spillover_and_drain() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.seen_global.len(), 0);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.seen_global.len(), 1);

    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    // Critical reserve full; tx 51 spills into normal queue.
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.seen_global.len(), 4);

    // Backpressured ids must not inflate the queued count invariant.
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.seen_global.len(), 4);

    let (_, _, total) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total);

    assert_eq!(g.pop_ready(), Some(50));
    assert_eq!(g.pop_ready(), Some(1));
    let (_, _, total_after_drain) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total_after_drain);
}

#[test]
fn reserve_only_normal_borrow_keeps_queue_counts_and_seen_global_in_sync() {
    let mut g = LaneAdmissionGate::new(2, 2);

    assert_eq!(g.queued_counts(), (0, 0, 0));
    assert_eq!(g.seen_global.len(), 0);

    // With zero dedicated normal capacity, fresh normal ingress borrows one
    // critical slot while the critical lane is idle.
    assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 1, 1));
    assert_eq!(g.seen_global.len(), 1);

    // Cross-class duplicate probes must remain globally deduped and must not
    // perturb reserve-only queue accounting.
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.queued_counts(), (0, 1, 1));
    assert_eq!(g.seen_global.len(), 1);

    assert_eq!(g.pop_ready(), Some(41));
    assert_eq!(g.queued_counts(), (0, 0, 0));
    assert_eq!(g.seen_global.len(), 0);
}

#[test]
fn reserve_guarded_cross_class_duplicate_probe_keeps_qos_and_counts_flat() {
    let mut g = LaneAdmissionGate::new(5, 2);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), guarded_snapshot);

    // Fresh normal ingress is blocked by the final reserved critical slot, but a
    // queued normal tx retried through the critical path must still stay Duplicate
    // and must not perturb operator-facing QoS/accounting.
    assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);
    assert_eq!(g.queued_counts(), (3, 1, 4));
    assert_eq!(g.seen_global.len(), 4);

    // Once the original queued normal copy drains, the same tx id may re-enter as
    // fresh through the opposite class.
    assert_eq!(g.pop_ready(), Some(70));
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(2));
    assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.seen_global.len(), 3);
}

#[test]
fn non_reserve_only_normal_never_borrows_when_no_critical_headroom_remains() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.critical_free_slots(), 0);

    // Once the last reserved slot is actually consumed, fresh normal ingress must
    // fail closed instead of borrowing past critical anti-spam backpressure.
    assert!(!g.can_normal_borrow_critical_slot(g.critical_free_slots()));
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (2, 1, 3));
}

#[test]
fn reserve_only_mode_can_still_borrow_the_last_truly_idle_critical_slot() {
    let mut g = LaneAdmissionGate::new(2, 2);

    assert_eq!(g.critical_free_slots(), 2);
    assert!(g.can_normal_borrow_critical_slot(g.critical_free_slots()));

    // Reserve-only mode has no dedicated normal lane, so the last idle critical
    // slot remains borrowable until it is actually consumed.
    assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.critical_free_slots(), 1);
    assert!(g.can_normal_borrow_critical_slot(g.critical_free_slots()));
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.critical_free_slots(), 0);
    assert!(!g.can_normal_borrow_critical_slot(g.critical_free_slots()));
}

#[test]
fn reserve_only_saturation_reopens_cleanly_after_one_real_drain() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Saturate the shared reserve-only queue via mixed-class ingress.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // Opposite-class duplicate probes and fresh retry noise must not perturb the
    // shared reserve-only accounting surface while saturated.
    assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);

    // One real drain should immediately reopen both classes for fresh ingress.
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 1,
            total_queued: 1,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);
}

#[test]
fn reserve_only_active_backlog_duplicate_probe_keeps_reopened_shared_headroom_flat() {
    let mut g = LaneAdmissionGate::new(3, 3);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));

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
    assert_eq!(g.qos_snapshot(), reopened);

    // In reserve-only mode, duplicate probes against active backlog must stay
    // purely classificatory: they cannot consume or hide the one genuinely
    // reopened shared slot that both ingress classes may still use.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.qos_snapshot(), reopened);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);

    assert_eq!(g.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 3, 3));
    assert_eq!(g.seen_global.len(), 3);
}

#[test]
fn reserve_only_backpressured_tx_id_stays_fresh_until_headroom_reopens() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode routes both classes through the shared critical lane.
    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);

    // A fresh id rejected under aggregate saturation must stay fresh across
    // both ingress classes rather than poisoning cross-class idempotency.
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);

    assert_eq!(g.pop_ready(), Some(1));

    // Once one shared slot really reopens, the previously backpressured id
    // should admit cleanly and then become globally duplicate again.
    assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);
}

#[test]
fn borrowed_last_idle_reserved_slot_recloses_to_normal_once_critical_backlog_appears() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal headroom, then borrow the last idle reserved critical
    // slot exactly once while the critical lane is still idle.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.qos_snapshot().fresh_normal_admissible, false);
    assert_eq!(g.qos_snapshot().fresh_critical_admissible, true);

    // As soon as a real critical tx claims backlog ownership, the borrowed-slot
    // exception must snap shut for fresh normal ingress while preserving critical
    // admission on the reopened reserved slot.
    assert_eq!(g.pop_ready(), Some(3));
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    let guarded = g.qos_snapshot();
    assert!(!guarded.fresh_normal_admissible);
    assert!(guarded.fresh_critical_admissible);
    assert_eq!(guarded.normal_queued, 2);
    assert_eq!(guarded.critical_queued, 1);
    assert_eq!(guarded.total_queued, 3);

    assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.qos_snapshot(), guarded);
}
