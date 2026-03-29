use super::*;

#[test]
fn ghost_lane_seen_entry_does_not_misclassify_fresh_ingress_as_duplicate() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew: lane-local seen set contains a stale id
    // that is not present in either queue.
    g.normal.seen.insert(77);

    // Fresh ingress for the ghost id should still admit (not duplicate).
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn ghost_seen_global_entry_with_matching_cardinality_does_not_poison_fresh_admit() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (1, 0, 1));

    // Simulate restored-state skew where lane-wide membership drifts while
    // cardinality stays aligned with queued work.
    g.seen_global.clear();
    g.seen_global.insert(77);
    assert_eq!(g.seen_global.len(), 1);

    // Fresh ingress for the ghost id must self-heal lane-wide membership and
    // admit cleanly instead of being misclassified as a duplicate.
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (1, 1, 2));

    // The original queued id must remain globally deduped after the rebuild.
    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn idle_lane_ghost_seen_entry_is_cleared_before_first_fresh_admission() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Simulate restored idle state with stale lane-local/global seen caches.
    g.normal.seen.insert(123);
    g.critical.seen.insert(456);
    g.seen_global.insert(789);
    assert_eq!(g.queued_counts(), (0, 0, 0));

    // First fresh ingress must self-heal stale caches and admit cleanly.
    assert_eq!(g.admit(123, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn stale_seen_global_self_heals_without_dropping_duplicate_or_fresh_semantics() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate transient restored-state skew where lane-wide idempotency cache
    // is stale, but lane-local queues remain authoritative.
    g.seen_global.clear();

    // Non-saturated admission should self-heal from lane-local state first.
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Duplicate semantics for pre-existing queued ids must survive healing.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Fresh ids still admit until global capacity is reached.
    assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(5, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    let (_, _, total) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total);
}

#[test]
fn stale_seen_global_ghost_id_does_not_poison_fresh_admission_after_self_heal() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-wide cache carries a ghost id
    // that is not present in either lane queue.
    g.seen_global.insert(999);

    // Self-heal should rebuild from lane-local truth and keep fresh ingress live.
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Queue is now globally full; ghost id must not appear as a duplicate.
    assert_eq!(
        g.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the same id should admit as fresh.
    let drained = g.pop_ready();
    assert!(drained == Some(1) || drained == Some(2) || drained == Some(3));
    assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn drained_ghost_id_from_repaired_seen_global_can_reenter_as_fresh() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew with preserved cardinality: lane-wide cache
    // drops one real queued id and replaces it with a ghost id.
    g.seen_global.remove(&11);
    g.seen_global.insert(99);
    assert_eq!(g.seen_global.len(), 2);

    // The ghost id must not be treated as duplicate while the lane still has room.
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    // Repair also restores duplicate semantics for the real queued id.
    assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);

    // Once the repaired ghost-backed tx drains, the same id should be admitted
    // again as fresh instead of being poisoned by prior cache skew.
    let first = g.pop_ready();
    let second = g.pop_ready();
    let third = g.pop_ready();
    assert_eq!(first, Some(11));
    assert!(second == Some(10) || second == Some(99));
    assert!(third == Some(10) || third == Some(99));
    assert_ne!(second, third);
    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn equal_cardinality_seen_global_skew_still_preserves_duplicate_semantics() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-wide cache keeps the same
    // cardinality but drops a queued id in favor of a ghost id.
    g.seen_global.remove(&10);
    g.seen_global.insert(999);
    assert_eq!(g.seen_global.len(), 2);

    // Duplicate for tx 10 must still be detected via lane-local truth.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Ghost id should not be treated as duplicate while lane still has room.
    assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn equal_cardinality_skew_under_saturation_keeps_fresh_ids_backpressured_not_duplicated() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Restore-state skew keeps cardinality aligned while replacing a queued id
    // with a ghost id in lane-wide cache.
    g.seen_global.remove(&10);
    g.seen_global.insert(999);
    assert_eq!(g.seen_global.len(), 2);

    // With queues saturated, fresh ids must remain backpressured (not duplicate)
    // even while duplicate semantics for queued ids still hold.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the previously fresh id can admit cleanly.
    assert!(matches!(g.pop_ready(), Some(10) | Some(11)));
    assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn pop_ready_self_heals_stale_seen_global_without_new_admission() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-wide cache drops queued ids and
    // only keeps ghost entries.
    g.seen_global.clear();
    g.seen_global.insert(999);

    // pop_ready should rebuild lane-wide cache from lane-local truth even when
    // no new admission occurs.
    let drained = g.pop_ready();
    assert!(drained == Some(1) || drained == Some(2));

    let (_, _, total) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total);
    let survivor = if drained == Some(1) { 2 } else { 1 };
    assert!(g.seen_global.contains(&survivor));
    assert!(!g.seen_global.contains(&999));
}

#[test]
fn pop_ready_self_heals_when_ghost_id_survives_successful_remove() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Keep queued ids so remove(id) succeeds, but inject a ghost entry that
    // should be pruned by post-pop cardinality self-heal.
    g.seen_global.insert(999);

    let drained = g.pop_ready();
    assert!(drained == Some(1) || drained == Some(2));

    let (_, _, total) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total);
    assert!(!g.seen_global.contains(&999));
}

#[test]
fn equal_cardinality_lane_seen_skew_does_not_false_duplicate_fresh_id() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew: lane-local seen/global caches keep cardinality
    // but replace a queued id with a ghost id.
    g.normal.seen.remove(&11);
    g.normal.seen.insert(999);
    g.seen_global.remove(&11);
    g.seen_global.insert(999);

    // Fresh ghost id must not be misclassified as duplicate.
    assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn stale_cross_lane_seen_membership_self_heals_before_duplicate_classification() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-local seen membership is swapped
    // across lanes while cardinalities remain unchanged.
    g.normal.seen.remove(&200);
    g.critical.seen.remove(&100);
    g.normal.seen.insert(100);
    g.critical.seen.insert(200);

    // Duplicate for a queued tx must still be detected after inline self-heal.
    assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Fresh ingress remains admitted while global capacity is still available.
    assert_eq!(g.admit(300, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn saturated_cross_lane_seen_membership_skew_keeps_duplicate_semantics() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-local seen membership is swapped
    // across lanes while cardinalities remain unchanged under saturation.
    g.normal.seen.remove(&200);
    g.critical.seen.remove(&100);
    g.normal.seen.insert(100);
    g.critical.seen.insert(200);

    // Duplicate for a queued tx must still be preserved even on the saturated
    // fast path, and a fresh id must remain backpressured instead of duplicate.
    assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(300, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn seen_global_duplicate_without_lane_local_membership_self_heals_and_stays_duplicate() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew: lane-wide cache still carries tx 1, while
    // lane-local seen caches lose it.
    g.critical.seen.remove(&1);

    // Duplicate must still be preserved after inline self-heal.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Fresh ingress should remain admissible while global capacity has headroom.
    assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn saturated_equal_cardinality_lane_local_ghost_seen_id_stays_backpressured_not_duplicate() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew under saturation with preserved lane-local
    // cardinality: one queued normal id is replaced by a ghost id while totals
    // stay aligned.
    g.normal.seen.remove(&20);
    g.normal.seen.insert(999);
    assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 2);

    // Fresh ingress matching the ghost id must remain backpressured at full
    // capacity, not be misclassified as duplicate.
    assert_eq!(
        g.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // The real queued id must still be deduped correctly.
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn equal_cardinality_cross_lane_and_global_skew_self_heals_without_false_duplicate_or_poisoned_retry(
) {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew where lane-local membership is swapped across
    // lanes and lane-wide cache mirrors the same ghost replacement while keeping
    // total cardinality unchanged.
    g.normal.seen.remove(&200);
    g.critical.seen.remove(&100);
    g.normal.seen.insert(100);
    g.critical.seen.insert(999);
    g.seen_global.remove(&100);
    g.seen_global.remove(&200);
    g.seen_global.insert(100);
    g.seen_global.insert(999);
    assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 2);
    assert_eq!(g.seen_global.len(), 2);

    // Fresh ghost id must not be misclassified as duplicate while lane still has room.
    assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);

    // Inline self-heal must also restore duplicate semantics for the real queued ids.
    assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(200, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(g.queued_counts(), (2, 1, 3));
}

#[test]
fn pop_self_heal_prunes_ghost_seen_global_so_cross_class_retry_can_admit_after_drain() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew while globally full: lane-wide membership drops
    // one real queued id and replaces it with a ghost id, preserving cardinality.
    g.seen_global.remove(&21);
    g.seen_global.insert(99);
    assert_eq!(g.seen_global.len(), 3);

    // While saturated, the ghost id must stay fresh/backpressured rather than duplicate.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Drain once to trigger pop-side self-heal and remove the saturation boundary.
    assert!(matches!(g.pop_ready(), Some(10) | Some(20)));
    assert_eq!(g.seen_global.len(), 2);
    assert!(!g.seen_global.contains(&99));

    // After self-heal plus freed capacity, the same ghost id must admit cleanly on a
    // cross-class retry instead of remaining poisoned by stale lane-wide membership.
    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn qos_snapshot_stays_guarded_under_seen_cache_skew_until_reserved_headroom_really_reopens() {
    let mut g = LaneAdmissionGate::new(4, 2);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

    let guarded = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), guarded);

    // Simulate restored-state skew: queue contents stay authoritative, but both
    // lane-local and lane-wide seen caches drift toward a ghost id.
    g.normal.seen.remove(&2);
    g.normal.seen.insert(999);
    g.seen_global.remove(&2);
    g.seen_global.insert(999);
    assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 3);
    assert_eq!(g.seen_global.len(), 3);

    // Sponsor/free-ingress observability must remain queue-derived: stale seen
    // cache skew cannot advertise fresh normal headroom before the reserved slot
    // truly reopens.
    assert_eq!(g.qos_snapshot(), guarded);
    assert_eq!(g.admit(999, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded);

    // The real queued id must still self-heal back to duplicate semantics.
    assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
}
