use super::*;

#[test]
fn sustained_dual_lane_backlog_keeps_normal_progress_after_first_fairness_turn() {
    let mut g = LaneAdmissionGate::new(5, 2);

    // Prime both lanes.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

    // Sustain critical pressure while preserving normal backlog.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(21));
    assert_eq!(g.admit(23, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(22));
    assert_eq!(g.admit(24, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(23));

    // Fairness turn.
    assert_eq!(g.pop_ready(), Some(10));

    // Warm fairness: one critical then normal, instead of another full burst.
    assert_eq!(g.pop_ready(), Some(24));
    assert_eq!(g.pop_ready(), Some(11));
}

#[test]
fn reserve_only_mode_keeps_fairness_streak_cold_during_spillover_drains() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Zero dedicated normal capacity (reserve-only): normal ingress borrows
    // critical headroom but fairness streak should stay cold.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.critical_served_streak, 0);

    // Critical remains preferred when available and the streak remains reset.
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.critical_served_streak, 0);
    assert_eq!(g.pop_ready(), Some(11));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn oversized_reserve_clamp_keeps_reserve_only_fairness_cold() {
    let mut g = LaneAdmissionGate::new(2, 99);

    // Misconfigured reserve > total must clamp into reserve-only mode rather than
    // fabricating dedicated normal capacity or warm fairness state.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.critical_served_streak, 0);

    // Even if stale fairness state leaked in from recovery, reserve-only dequeue
    // order must not synthesize a normal turn from the misconfigured split.
    g.critical_served_streak = g.critical_burst_limit;
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.critical_served_streak, 0);
    assert_eq!(g.pop_ready(), Some(11));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn critical_spillover_warms_normal_fairness_like_direct_normal_admission() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Saturate the critical reserve first.
    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

    // The next critical ingress spills into free normal capacity while both
    // lanes stay backlogged.
    assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical spillover should arm the same fairness warmup contract as a
    // direct normal admission, so the newly occupied normal lane gets the next turn.
    assert_eq!(g.pop_ready(), Some(102));
    assert_eq!(g.pop_ready(), Some(100));
}

#[test]
fn fairness_warmup_does_not_slow_critical_when_normal_lane_drains() {
    let mut g = LaneAdmissionGate::new(4, 1);

    // Build a short mixed backlog so fairness warmup is exercised.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

    // Fairness grants one normal turn after the critical burst limit is hit.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(10));

    // Once normal backlog is drained, critical throughput should continue
    // immediately without another fairness-induced detour.
    assert_eq!(g.pop_ready(), Some(21));

    // New critical ingress should keep making progress while normal remains empty.
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(22));
}

#[test]
fn newly_arrived_normal_backlog_gets_turn_during_critical_flood() {
    let mut g = LaneAdmissionGate::new(7, 3);

    // Build critical pressure and consume a few critical turns first.
    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(100));
    assert_eq!(g.pop_ready(), Some(101));

    // Normal traffic appears while critical lane stays backlogged.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Anti-starvation target: once normal backlog appears under active
    // critical pressure, fairness should immediately grant a normal turn.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(102));
}

#[test]
fn newly_arrived_critical_backlog_preempts_normal_flood_without_waiting_for_burst_reset() {
    let mut g = LaneAdmissionGate::new(8, 2);

    // Build only normal backlog and consume one normal turn.
    for id in 1..=4 {
        assert_eq!(g.admit(id, IngressClass::Normal), AdmitOutcome::Accepted);
    }
    assert_eq!(g.pop_ready(), Some(1));

    // Critical traffic appears while normal backlog remains active.
    assert_eq!(g.admit(900, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical ingress should preempt immediately to keep high-priority
    // latency bounded even during an existing normal flood.
    assert_eq!(g.pop_ready(), Some(900));
}

#[test]
fn normal_fairness_warmup_survives_active_critical_refill() {
    let mut g = LaneAdmissionGate::new(5, 2);

    // Keep critical lane active first.
    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(100));

    // Normal backlog appears while critical pressure is still active.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Refill critical immediately so pressure remains continuous.
    assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);

    // Anti-starvation contract: fairness warmup must still force a normal turn
    // immediately (or at worst within one additional dequeue) under active
    // critical refill.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(101));
}

#[test]
fn full_drain_clears_stale_lane_local_seen_without_waiting_for_next_admit() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew: stale ghost ids exist in lane-local seen sets.
    g.normal.seen.insert(7001);
    g.critical.seen.insert(7002);

    // Drain both queued txs.
    assert!(matches!(g.pop_ready(), Some(1) | Some(2)));
    assert!(matches!(g.pop_ready(), Some(1) | Some(2)));

    // Full-drain boundary should proactively clear stale lane-local seen caches.
    assert!(g.normal.seen.is_empty());
    assert!(g.critical.seen.is_empty());
    assert_eq!(g.queued_counts(), (0, 0, 0));
}

#[test]
fn full_drain_cold_resets_fairness_even_when_pop_self_heals_seen_global() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew right before the final drain: the lane still
    // has one real queued tx, but fairness bookkeeping is stale-hot and the
    // lane-wide id cache carries an extra ghost id that post-pop self-heal must prune.
    g.critical_served_streak = g.critical_burst_limit;
    g.seen_global.insert(999);

    assert_eq!(g.pop_ready(), Some(11));
    assert_eq!(g.queued_counts(), (0, 0, 0));
    assert!(g.seen_global.is_empty());
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn idle_self_heal_resets_stale_fairness_streak_before_new_mixed_ingress() {
    let mut g = LaneAdmissionGate::new(4, 1);

    // Simulate restored idle state with stale fairness/bookkeeping counters.
    g.critical_served_streak = g.critical_burst_limit;
    g.seen_global.insert(777);

    // Trigger idle self-heal path via first admission.
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    // Then add critical ingress. This path should not arm fairness warmup because
    // normal backlog was already present before critical arrived.
    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical should not be spuriously preempted by stale fairness state.
    assert_eq!(g.pop_ready(), Some(1));
}

#[test]
fn idle_pop_ready_self_heals_stale_restored_state_without_waiting_for_admit() {
    let mut g = LaneAdmissionGate::new(4, 1);

    // Simulate restored idle state where no queued work remains but lane-local,
    // lane-wide, and fairness bookkeeping are all stale-hot.
    g.normal.seen.insert(7001);
    g.critical.seen.insert(7002);
    g.seen_global.insert(7003);
    g.critical_served_streak = g.critical_burst_limit;
    assert_eq!(g.queued_counts(), (0, 0, 0));

    // Idle dequeue polls should act as a self-heal boundary even before any new
    // ingress arrives.
    assert_eq!(g.pop_ready(), None);
    assert!(g.normal.seen.is_empty());
    assert!(g.critical.seen.is_empty());
    assert!(g.seen_global.is_empty());
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn full_drain_resets_fairness_streak_immediately_without_waiting_for_next_admit() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

    // Build non-zero fairness streak during critical service.
    assert_eq!(g.pop_ready(), Some(2));
    assert!(g.critical_served_streak > 0);

    // Drain remaining backlog completely.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(3));
    assert_eq!(g.queued_counts(), (0, 0, 0));

    // Full-drain boundary should cold-reset fairness immediately.
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn zero_reserve_shared_queue_duplicate_probes_do_not_invent_cross_domain_preemption() {
    let mut g = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode collapses both ingress classes into the shared normal lane.
    // Mixed-class retries must remain classification-only and must not synthesize
    // fairness/preemption state that perturbs shared FIFO dequeue order.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 0, 3));

    // Cross-class duplicate probes stay Duplicate while the tx ids are queued.
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);

    // The shared queue must still drain in pure FIFO order; duplicate probe noise
    // must not create synthetic critical preference or warm fairness state.
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(30));
    assert_eq!(g.queued_counts(), (0, 0, 0));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn zero_reserve_idle_self_heal_does_not_leak_stale_fairness_into_next_shared_batch() {
    let mut g = LaneAdmissionGate::new(3, 0);

    // Simulate restored idle state with stale fairness/bookkeeping. In zero-reserve
    // mode, the next mixed batch still shares one FIFO lane and must not inherit a
    // synthetic normal-vs-critical scheduling preference.
    g.critical_served_streak = g.critical_burst_limit;
    g.normal.seen.insert(7001);
    g.seen_global.insert(7002);

    assert_eq!(g.pop_ready(), None);
    assert_eq!(g.critical_served_streak, 0);
    assert!(g.normal.seen.is_empty());
    assert!(g.critical.seen.is_empty());
    assert!(g.seen_global.is_empty());

    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 0, 3));

    // Zero-reserve mode must stay pure shared-lane FIFO after idle self-heal.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.pop_ready(), Some(30));
    assert_eq!(g.critical_served_streak, 0);
}
