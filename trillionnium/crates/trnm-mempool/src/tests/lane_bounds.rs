use super::*;

#[test]
fn critical_lane_makes_progress_under_flood() {
    let mut g = LaneAdmissionGate::new(4, 1);
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);

    // With an idle critical lane, one normal tx may borrow the final reserved
    // slot; fresh critical ingress then backpressures until a dequeue opens space.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.pop_ready(), Some(4));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(99));
}

#[test]
fn duplicate_is_rejected_across_ingress_classes_until_drained() {
    let mut g = LaneAdmissionGate::new(4, 1);
    assert_eq!(g.admit(7, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(7, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.pop_ready(), Some(7));
    assert_eq!(g.admit(7, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn normal_lane_gets_turn_after_bounded_critical_burst() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.pop_ready(), Some(21));
}

#[test]
fn critical_lane_spills_over_to_free_normal_capacity() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical reserved slot is full, but total capacity still has one slot.
    assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(5, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn lane_gate_enforces_global_capacity_even_when_lane_mins_apply() {
    let mut g = LaneAdmissionGate::new(1, 1);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(101, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    assert_eq!(g.pop_ready(), Some(100));
    assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn normal_lane_does_not_spill_when_critical_lane_is_busy() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(3, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn normal_lane_can_borrow_only_surplus_critical_headroom() {
    let mut g = LaneAdmissionGate::new(6, 2);

    // Fill normal lane first.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);

    // With two critical slots free, normal may borrow one for better free-ingress throughput.
    assert_eq!(g.admit(5, IngressClass::Normal), AdmitOutcome::Accepted);

    // Borrowing preserves one immediate critical slot while critical backlog is active.
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);

    // With critical backlog active and no surplus headroom left, further normal
    // spillover is blocked.
    assert_eq!(
        g.admit(6, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn normal_lane_can_borrow_last_critical_slot_when_critical_lane_idle() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Critical lane is idle with exactly one free slot; allow temporary borrow
    // instead of backpressuring fresh normal ingress.
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Once borrowed, fresh critical ingress should backpressure until dequeue.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn critical_refill_after_idle_last_slot_borrow_recloses_further_normal_spillover() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow the last free critical slot
    // while the critical lane is still idle.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Once a critical tx refills the reserved lane, further normal spillover
    // must close immediately to preserve an in-flight critical backlog bound.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(4, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn qos_snapshot_recloses_normal_admissibility_when_critical_refills_after_idle_last_slot_borrow() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill the dedicated normal lane and borrow one of the still-idle critical
    // slots so the public QoS surface advertises one last fresh normal slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // Drain one dedicated normal item to reopen shared aggregate headroom, then
    // refill the final reserved critical slot. Once critical backlog owns the last
    // reserved slot again, fresh normal ingress must fail closed immediately.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 2,
            total_queued: 3,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn qos_snapshot_stays_fail_closed_for_normal_after_critical_refill_probe_noise() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow one idle reserved slot so a
    // later critical refill can reclose fresh normal ingress against the final
    // reserved headroom.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 1,
        critical_queued: 2,
        total_queued: 3,
        normal_headroom: 1,
        critical_headroom: 0,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), guarded_snapshot);

    // Once critical backlog owns the final reserved slot again, repeated fresh
    // normal probes must stay backpressured without perturbing public QoS
    // observability, while the queued critical id still dedupes.
    assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);
    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);
    assert_eq!(g.admit(5, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);
}

#[test]
fn qos_snapshot_keeps_normal_closed_when_only_critical_spillover_headroom_remains() {
    let mut g = LaneAdmissionGate::new(5, 2);

    // Fill the dedicated normal lane and occupy one reserved critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    // One aggregate slot remains, but it is reachable only by fresh critical
    // spillover into the still-free normal headroom. Fresh normal ingress must
    // stay closed because the last reserved critical slot is guarded.
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );
}

#[test]
fn critical_refill_guarded_normal_retry_stays_fresh_until_reserved_slot_reopens() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, borrow one idle reserved slot, then drain a
    // normal item so aggregate headroom reopens before critical refills the last
    // reserved slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (1, 2, 3));

    // Fresh normal retries are reserve-guarded while critical backlog owns the
    // final reserved slot, but they must remain fresh rather than poisoning
    // duplicate tracking.
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (1, 2, 3));

    // The first critical drain still leaves one active critical occupant, so the
    // same tx id must remain fresh-but-guarded.
    assert_eq!(g.pop_ready(), Some(3));
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (1, 1, 2));

    // Once the reserved slot truly reopens, that previously guarded id should
    // admit cleanly instead of being misclassified as duplicate.
    assert_eq!(g.pop_ready(), Some(99));
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn full_critical_reserve_allows_normal_when_critical_lane_idle() {
    let mut g = LaneAdmissionGate::new(1, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(2, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.pop_ready(), Some(1));
}

#[test]
fn full_critical_reserve_allows_normal_to_use_free_headroom_while_critical_busy() {
    let mut g = LaneAdmissionGate::new(3, 3);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    // Even with critical backlog present, reserve-only configs should keep
    // free-ingress throughput live while total capacity has room.
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(4, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn oversized_critical_reserve_clamp_keeps_qos_fail_closed_once_shared_headroom_is_consumed() {
    let mut g = LaneAdmissionGate::new(2, 5);

    // reserve > total clamps to reserve-only semantics. While one shared slot
    // remains, both classes should still observe fresh admissibility.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
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

    // A normal tx may borrow the final shared slot under the reserve clamp, but
    // once that slot is consumed the public QoS surface must fail closed for both
    // classes instead of advertising phantom dedicated normal headroom.
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
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

    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(13, IngressClass::Critical), AdmitOutcome::Backpressured);
}

#[test]
fn reserve_only_normal_borrowing_does_not_preempt_critical_drain_order() {
    let mut g = LaneAdmissionGate::new(3, 3);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
    // Normal ingress borrows reserve-only headroom.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // With no dedicated normal capacity configured, borrowed normal traffic
    // should not preempt pending critical work.
    assert_eq!(g.pop_ready(), Some(100));
    assert_eq!(g.pop_ready(), Some(101));
    assert_eq!(g.pop_ready(), Some(1));
}

#[test]
fn oversized_critical_reserve_clamp_reopens_shared_headroom_immediately_after_one_drain() {
    let mut g = LaneAdmissionGate::new(2, 5);

    // reserve > total clamps into reserve-only mode, so both classes share the
    // same critical-backed headroom until the aggregate cap is consumed.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert!(!g.qos_snapshot().fresh_normal_admissible);
    assert!(!g.qos_snapshot().fresh_critical_admissible);

    // One real drain must immediately reopen fresh admission for both classes
    // under the clamp, without waiting for a full drain or idle self-heal.
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.queued_counts(), (0, 1, 1));
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

    // The previously backpressured id must still be fresh after the clamp reopens.
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(12, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn oversized_critical_reserve_clamp_reopened_slot_remains_cross_class_fresh_until_reused() {
    let mut g = LaneAdmissionGate::new(2, 5);

    // Saturate the reserve-only shared lane and confirm a fresh normal retry is
    // fail-closed rather than cached as a duplicate while no headroom exists.
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(22, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Backpressured);

    // A single real drain reopens one shared slot even though critical backlog is
    // still active. The previously backpressured id must admit as fresh through
    // either class, then immediately dedupe across the other class.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(22, IngressClass::Normal), AdmitOutcome::Duplicate);
}

#[test]
fn critical_spillover_can_fill_normal_lane_until_global_capacity() {
    let mut g = LaneAdmissionGate::new(4, 2);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

    // With reserve saturated, critical traffic should spill into free normal
    // headroom until global capacity is fully consumed.
    assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(103, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(1, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn reserve_only_normal_borrowed_admission_is_globally_idempotent_until_drained() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Normal ingress borrows critical headroom when normal lane has zero reserved capacity.
    assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);

    // Replays from either class must dedupe until the tx is drained.
    assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);

    assert_eq!(g.pop_ready(), Some(41));
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn zero_critical_reserve_preserves_normal_capacity_with_critical_spillover() {
    let mut g = LaneAdmissionGate::new(3, 0);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(4, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // With zero reserve configured, critical ingress still has a path via
    // spillover into free normal capacity once pressure clears.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
}
