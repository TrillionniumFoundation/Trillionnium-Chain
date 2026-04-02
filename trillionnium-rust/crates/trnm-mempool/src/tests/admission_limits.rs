use super::*;

#[test]
fn spillover_admission_remains_globally_idempotent_until_drained() {
    let mut g = LaneAdmissionGate::new(4, 1);

    // Keep one free total slot while saturating the critical reserve, then
    // force a critical tx to spill into normal capacity.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);

    // Even though tx 51 was admitted via spillover, duplicate admission from
    // either ingress class must still be rejected until it is drained.
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Drain until tx 51 leaves the queue, then re-admission is allowed.
    assert_eq!(g.pop_ready(), Some(50));
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(2));
    assert_eq!(g.pop_ready(), Some(51));
    assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn backpressured_tx_id_is_not_marked_seen_and_can_be_admitted_after_drain() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);

    // tx 3 is backpressured at global capacity; this must not poison global
    // idempotency tracking.
    assert_eq!(
        g.admit(3, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once a slot is freed, tx 3 should admit cleanly (not duplicate).
    assert_eq!(g.pop_ready(), Some(2));
    assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn critical_backpressured_tx_id_can_admit_from_other_class_after_drain() {
    let mut g = LaneAdmissionGate::new(3, 1);

    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);

    // Global capacity backpressures fresh critical ingress and must not poison
    // cross-class idempotency for the same tx id.
    assert_eq!(
        g.admit(30, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Drain one critical and one normal so normal class has explicit headroom.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(10));

    // The previously backpressured id must still be treated as fresh.
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_normal_borrowed_admission_stays_globally_idempotent() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Normal lane has zero dedicated capacity, so normal ingress borrows
    // free headroom from critical capacity.
    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);

    // Even though tx 42 was admitted through borrowed critical headroom,
    // it must be globally deduped across both ingress classes.
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);

    // After drain, re-admission should proceed as a fresh tx id.
    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(42));
    assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn zero_capacity_admission_gate_does_not_poison_idempotency_after_backpressure() {
    let mut g = AdmissionGate::new(0);

    // Capacity exhaustion should reject ingress without marking tx ids as seen.
    assert_eq!(g.admit(7), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(7), AdmitOutcome::Backpressured);
    assert_eq!(g.pop_ready(), None);
}

#[test]
fn zero_capacity_admission_gate_preserves_restored_duplicate_metadata_across_idle_polls() {
    let mut g = AdmissionGate::new(0);

    // Launch-day hard-stop / fee-freeze semantics must preserve restored duplicate
    // knowledge while the standalone gate stays fail-closed. Idle polls and fresh
    // retry noise must not erase that metadata or fabricate queue state.
    g.seen.insert(41);

    for _ in 0..3 {
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.admit(41), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(99), AdmitOutcome::Backpressured);
        assert!(g.queue.is_empty());
        assert!(g.seen.contains(&41));
        assert!(!g.seen.contains(&99));
    }
}

#[test]
fn full_drain_clears_stale_seen_ghosts_before_next_fresh_admission() {
    let mut g = AdmissionGate::new(2);

    assert_eq!(g.admit(21), AdmitOutcome::Accepted);
    assert_eq!(g.admit(22), AdmitOutcome::Accepted);

    // Simulate restored-state skew: metadata retains a ghost id that is not
    // actually queued. Once the authoritative queue fully drains, the next
    // batch must start fresh rather than inheriting stale duplicate poison.
    g.seen.insert(999);

    assert_eq!(g.pop_ready(), Some(21));
    assert_eq!(g.pop_ready(), Some(22));
    assert_eq!(g.pop_ready(), None);
    assert!(g.seen.is_empty());

    assert_eq!(g.admit(999), AdmitOutcome::Accepted);
    assert_eq!(g.admit(999), AdmitOutcome::Duplicate);
}

#[test]
fn zero_total_capacity_lane_gate_backpressures_all_ingress_without_poisoning_seen_ids() {
    let mut g = LaneAdmissionGate::new(0, 0);

    assert_eq!(
        g.admit(1, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(1, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(2, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.pop_ready(), None);
}

#[test]
fn zero_total_capacity_preserves_duplicate_semantics_for_restored_seen_ids() {
    let mut g = LaneAdmissionGate::new(0, 0);

    // Simulate restored-state backlog metadata while ingress remains hard-stopped.
    g.seen_global.insert(41);
    g.normal.seen.insert(41);
    g.critical.seen.insert(42);

    assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.pop_ready(), None);
}

#[test]
fn duplicate_stays_duplicate_when_lane_is_globally_full() {
    let mut g = LaneAdmissionGate::new(1, 1);

    assert_eq!(g.admit(9, IngressClass::Critical), AdmitOutcome::Accepted);
    // Full-queue fast path must still preserve duplicate semantics.
    assert_eq!(g.admit(9, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(10, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn borrowed_last_idle_critical_slot_preserves_cross_class_duplicate_and_fresh_backpressure() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first, then borrow the final idle critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));

    // The borrowed tx id must still dedupe globally across ingress classes.
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);

    // Fresh critical ingress must remain backpressured until the borrowed slot drains.
    assert_eq!(
        g.admit(88, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    assert_eq!(g.pop_ready(), Some(77));
    assert_eq!(g.admit(88, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_idle_critical_slot_preserves_same_class_duplicate_without_queue_drift() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first, then borrow the final idle critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.seen_global.len(), 3);

    // Same-class replay of the borrowed occupant must stay Duplicate and must not
    // perturb accounting while the last idle critical slot remains consumed.
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.seen_global.len(), 3);

    // Fresh same-class retry noise must also stay fail-closed until the borrowed
    // slot drains, without poisoning future admission.
    assert_eq!(g.admit(88, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.queued_counts(), (2, 1, 3));
    assert_eq!(g.seen_global.len(), 3);

    assert_eq!(g.pop_ready(), Some(77));
    assert_eq!(g.admit(88, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn duplicate_semantics_survive_stale_seen_global_under_saturation() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate transient restored-state skew: tx 1 is still queued in lane-local
    // sets, but lane-wide idempotency cache is stale.
    g.seen_global.remove(&1);

    // Duplicate must still be detected under saturated fast-path.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(3, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn stale_seen_global_ghost_id_is_healed_without_false_duplicate_under_saturation() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew with preserved cardinality: the lane-wide
    // cache contains a ghost id and misses one actually queued id.
    g.seen_global.remove(&20);
    g.seen_global.insert(99);
    assert_eq!(g.seen_global.len(), 2);

    // Fresh ingress matching the ghost id must not be misclassified as duplicate.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After the self-heal rebuild, the real queued id is deduped again.
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn stale_seen_global_ghost_id_cross_class_retry_stays_backpressured_until_drain() {
    let mut g = LaneAdmissionGate::new(2, 1);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Simulate restored-state skew with preserved saturation cardinality: the
    // lane-wide cache drops the queued normal id and replaces it with a ghost id.
    g.seen_global.remove(&20);
    g.seen_global.insert(99);
    assert_eq!(g.seen_global.len(), 2);

    // Cross-class retries for the ghost id must remain Backpressured while the
    // lane is full; the ghost cache entry must not poison classification.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once a real queued tx drains, the ghost id should admit as fresh on retry.
    assert!(matches!(g.pop_ready(), Some(10) | Some(20)));
    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}
