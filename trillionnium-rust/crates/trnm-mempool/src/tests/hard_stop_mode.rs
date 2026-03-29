use super::*;

#[test]
fn hard_stop_restored_duplicate_noise_keeps_qos_snapshot_and_queue_state_flat() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored duplicate metadata that spans lane-local and lane-wide
    // caches while ingress is temporarily hard-stopped.
    g.normal.seen.insert(41);
    g.critical.seen.insert(42);
    g.seen_global.insert(41);
    g.seen_global.insert(42);

    let expected = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(g.qos_snapshot(), expected);
    assert_eq!(g.queued_counts(), (0, 0, 0));

    for (tx_id, class, outcome) in [
        (41, IngressClass::Normal, AdmitOutcome::Duplicate),
        (42, IngressClass::Critical, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (99, IngressClass::Critical, AdmitOutcome::Backpressured),
        (41, IngressClass::Critical, AdmitOutcome::Duplicate),
        (42, IngressClass::Normal, AdmitOutcome::Duplicate),
    ] {
        assert_eq!(g.admit(tx_id, class), outcome);
        assert_eq!(g.qos_snapshot(), expected);
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.qos_snapshot(), expected);
    }
}

#[test]
fn hard_stop_mode_preserves_duplicate_semantics_for_restored_backlog() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored-state backlog under a temporary hard-stop config.
    g.seen_global.insert(42);
    g.normal.seen.insert(42);

    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(7, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn hard_stop_mode_preserves_duplicate_semantics_across_ingress_classes() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored-state backlog where duplicate knowledge spans the
    // lane-wide cache and the opposite class's local cache.
    g.seen_global.insert(42);
    g.critical.seen.insert(42);

    // Replaying the same tx through either class must stay Duplicate even
    // though the queue itself is empty under temporary hard-stop mode.
    assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Distinct fresh ids must still be backpressured while the stop is active.
    assert_eq!(
        g.admit(7, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn hard_stop_mode_lane_local_duplicate_survives_repeated_cross_class_probes_without_poisoning_fresh_ids(
) {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored-state duplicate knowledge carried only by lane-local
    // caches while the lane-wide cache is temporarily empty.
    g.normal.seen.insert(55);

    // Repeated probes through either ingress class must continue to classify
    // the restored tx id as Duplicate instead of degrading to Backpressured.
    assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(55, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);

    // Fresh ids must remain backpressured and must not become duplicate on
    // subsequent retries just because hard-stop mode observed them before.
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn hard_stop_idle_pop_preserves_restored_duplicate_metadata() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored duplicate metadata while a temporary hard-stop keeps the
    // lane queue empty. Idle scheduler polls must not erase this knowledge.
    g.normal.seen.insert(41);
    g.critical.seen.insert(42);
    g.seen_global.insert(43);
    g.critical_served_streak = 7;

    assert_eq!(g.pop_ready(), None);
    assert_eq!(g.pop_ready(), None);

    // Duplicate semantics for restored ids must survive idle polling in hard-stop
    // mode, while fairness bookkeeping still cold-resets.
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(43, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.critical_served_streak, 0);

    // Fresh ids remain backpressured rather than being poisoned into duplicate.
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn hard_stop_restored_duplicate_probes_keep_queue_accounting_flat() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored duplicate metadata in all seen caches while the lane is
    // temporarily hard-stopped. Replayed duplicates should stay Duplicate without
    // ever fabricating queue occupancy.
    g.normal.seen.insert(11);
    g.critical.seen.insert(12);
    g.seen_global.insert(13);

    assert_eq!(g.queued_counts(), (0, 0, 0));

    for _ in 0..2 {
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(13, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.queued_counts(), (0, 0, 0));
    }
}

#[test]
fn hard_stop_lane_wide_duplicates_survive_idle_polls_without_poisoning_fresh_retries() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate recovery metadata that only restored the lane-wide seen cache.
    // Idle scheduler polls and fresh retry noise must not degrade this tx back to
    // Backpressured, nor may they accidentally poison new ids into Duplicate.
    g.seen_global.insert(77);

    for _ in 0..3 {
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(404, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(404, IngressClass::Critical), AdmitOutcome::Backpressured);
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert_eq!(g.qos_snapshot().total_headroom, 0);
        assert_eq!(g.qos_snapshot().fresh_normal_admissible, false);
        assert_eq!(g.qos_snapshot().fresh_critical_admissible, false);
    }
}

#[test]
fn hard_stop_mixed_restored_duplicate_sources_stay_fail_closed_through_idle_polls() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate a restored hard-stop lane where duplicate knowledge is split across
    // lane-local caches while lane-wide metadata carries an unrelated ghost id.
    // Idle polls must preserve Duplicate classification for restored ids without
    // fabricating queue occupancy or poisoning fresh retry bursts.
    g.normal.seen.insert(41);
    g.critical.seen.insert(42);
    g.seen_global.insert(99);
    g.critical_served_streak = 5;

    let expected = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    for _ in 0..2 {
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.qos_snapshot(), expected);
        assert_eq!(g.queued_counts(), (0, 0, 0));

        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(404, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(404, IngressClass::Critical), AdmitOutcome::Backpressured);

        assert_eq!(g.qos_snapshot(), expected);
        assert_eq!(g.queued_counts(), (0, 0, 0));
    }

    // Idle self-heal may reset fairness bookkeeping, but must not change the
    // hard-stop duplicate/backpressure contract.
    assert_eq!(g.critical_served_streak, 0);
}
