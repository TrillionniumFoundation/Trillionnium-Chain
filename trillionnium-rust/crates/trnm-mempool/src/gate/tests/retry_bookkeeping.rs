use super::*;

#[test]
fn repeated_backpressured_retry_is_idempotent_until_capacity_opens() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);

    assert_metrics(gate.metrics(), 1, 1, 1, 1, 0);

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
}

#[test]
fn saturated_known_retry_duplicate_does_not_churn_retry_fifo() {
    let mut gate = AdmissionGate::new(1);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
    let fifo_len_before = gate.backpressured_fifo.len();

    for _ in 0..8 {
        assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
    }

    // Repeated saturated retries should dedupe without growing retry FIFO markers.
    assert_eq!(gate.backpressured_fifo.len(), fifo_len_before);
    let m = gate.metrics();
    assert_eq!(m.backpressured, 1);
    assert_eq!(m.duplicates, 8);
    assert_eq!(m.backpressure_duplicates, 8);
}

#[test]
fn backpressure_retry_cache_is_bounded_by_capacity() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

    // 10 is evicted from the bounded retry cache once a third unique id is observed.
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);

    let m = gate.metrics();
    assert_eq!(m.backpressured, 4);
    assert_eq!(m.duplicates, 0);
    assert_eq!(m.backpressure_duplicates, 0);
    assert_eq!(m.fairness_deferrals, 0);
}

#[test]
fn stale_fifo_entries_do_not_break_bounded_retry_tracking() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

    // Admit one retry so its stale fifo marker remains but is removed from set.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
    assert!(!gate.backpressured_ids.contains(&10));

    // New retries should remain bounded by active set size despite stale markers.
    assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(13), AdmitOutcome::Backpressured);
    assert!(gate.backpressured_ids.len() <= 2);
}

#[test]
fn accepted_retry_id_is_removed_from_backpressure_set() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.admit(12), AdmitOutcome::Accepted);

    assert!(!gate.backpressured_ids.contains(&12));
}

#[test]
fn retry_acceptance_clears_tracking_even_without_active_fairness_reservations() {
    let mut gate = AdmissionGate::new(3);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

    // Simulate restored-state skew: retry memory knows about tx=9 but fairness
    // reservations are already exhausted.
    gate.backpressured_ids.insert(9);
    gate.retry_reservations = 0;

    assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
    assert!(!gate.backpressured_ids.contains(&9));
}

#[test]
fn stale_retry_fifo_is_compacted_under_high_churn() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

    for i in 0..24u64 {
        let retry_id = 100 + i;
        assert_eq!(gate.admit(retry_id), AdmitOutcome::Backpressured);
    }

    // Retry set is capacity-bounded and fifo gets compacted during churn.
    assert!(gate.backpressured_ids.len() <= 2);
    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}

#[test]
fn accepted_retry_compacts_stale_backpressure_fifo_without_new_ingress() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

    // Simulate stale marker buildup from prior churn; only 10/11 remain active retries.
    gate.backpressured_fifo
        .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
    assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.admit(10), AdmitOutcome::Accepted);

    // Retry admission should compact stale markers even without new backpressured inserts.
    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}

#[test]
fn pop_ready_compacts_oversized_retry_fifo_when_retry_memory_is_non_empty() {
    let mut gate = AdmissionGate::new(2);
    assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

    // Simulate restored/churned state where stale markers are oversized while
    // active retry ids still exist.
    gate.backpressured_fifo
        .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
    assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

    assert_eq!(gate.pop_ready(), Some(1));

    // Dequeue boundary should compact stale retry markers even before retry admission.
    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}

#[test]
fn compaction_clears_stale_fifo_immediately_when_retry_set_is_empty() {
    let mut gate = AdmissionGate::new(2);
    // Simulate restored/churned state where retry set drained but fifo still carries stale markers.
    gate.backpressured_fifo
        .extend([42, 43, 42, 43, 42, 43, 42, 43, 42]);
    gate.backpressured_ids.clear();
    assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

    gate.compact_backpressured_fifo();
    assert!(gate.backpressured_fifo.is_empty());
}

#[test]
fn compaction_triggers_at_threshold_to_bound_stale_fifo_growth() {
    let mut gate = AdmissionGate::new(2);
    // Exactly 4x stale markers should compact immediately instead of waiting
    // for an extra insert above threshold.
    gate.backpressured_fifo.extend([1, 2, 1, 2, 1, 2, 1, 2]);
    gate.backpressured_ids.clear();
    assert_eq!(
        gate.backpressured_fifo.len(),
        gate.capacity.saturating_mul(4)
    );

    gate.compact_backpressured_fifo();
    assert!(gate.backpressured_fifo.is_empty());
}

#[test]
fn fairness_only_deferral_path_compacts_stale_fifo_markers() {
    let mut gate = AdmissionGate::new(2);

    // Simulate fairness-only deferred ids being inserted and later drained,
    // which can leave stale FIFO markers behind without saturation inserts.
    gate.backpressured_ids.insert(1);
    for i in 0..32u64 {
        let deferred = 1000 + i;
        gate.remember_backpressured_without_eviction(deferred);
        gate.backpressured_ids.remove(&deferred);
    }

    assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
}

#[test]
fn fairness_only_deferral_clears_stale_fifo_before_first_new_retry_marker() {
    let mut gate = AdmissionGate::new(2);

    gate.backpressured_fifo.extend([7, 8, 9]);
    assert!(gate.backpressured_ids.is_empty());

    gate.remember_backpressured_without_eviction(42);

    assert_eq!(gate.backpressured_fifo, [42]);
    assert_eq!(gate.backpressured_ids, [42].into_iter().collect());
}

#[test]
fn restored_retry_set_without_fifo_markers_is_rebounded_to_capacity() {
    let mut gate = AdmissionGate::new(2);

    // Simulate restored/corrupted state: retry set exceeds capacity but fifo is missing.
    gate.backpressured_ids.extend([100, 101, 102]);
    gate.backpressured_fifo.clear();

    // Any new backpressure insert should rebalance retry memory to quota bounds.
    assert!(gate.remember_backpressured(103));
    assert!(gate.backpressured_ids.len() <= gate.capacity);

    // Fallback trim is deterministic: oldest/smallest ids are dropped first.
    assert!(gate.backpressured_ids.contains(&102));
    assert!(gate.backpressured_ids.contains(&103));
}

#[test]
fn restored_retry_set_trim_preserves_newly_backpressured_id_when_fifo_markers_missing() {
    let mut gate = AdmissionGate::new(2);

    // Corrupted restore: oversized retry memory with no FIFO markers.
    gate.backpressured_ids.extend([8, 9, 10]);
    gate.backpressured_fifo.clear();

    // Insert a smaller id so deterministic trimming would drop it first unless
    // we explicitly preserve the newly backpressured id.
    assert!(gate.remember_backpressured(1));

    assert!(gate.backpressured_ids.len() <= gate.capacity);
    assert!(gate.backpressured_ids.contains(&1));
}

#[test]
fn restored_retry_ids_rehydrate_fifo_before_bounded_eviction() {
    let mut gate = AdmissionGate::new(2);

    // Corrupted restore: retry ids exist but FIFO markers are missing.
    gate.backpressured_ids.extend([41, 42]);
    gate.backpressured_fifo.clear();

    assert!(gate.remember_backpressured(99));

    // Rehydrated FIFO should stay aligned with bounded retry tracking.
    assert!(!gate.backpressured_fifo.is_empty());
    assert!(gate.backpressured_fifo.len() <= gate.backpressured_ids.len());
    assert!(gate.backpressured_ids.contains(&99));
}

#[test]
fn zero_capacity_retry_insert_clears_restored_markers_instead_of_leaking_antispam_state() {
    let mut gate = AdmissionGate::new(0);

    // Hard-stop mode may restore stale retry bookkeeping from disk; a new rejected
    // probe must self-heal back to empty bounded state instead of retaining any
    // synthetic retry memory when aggregate admission capacity is zero.
    gate.backpressured_ids.extend([41, 42]);
    gate.backpressured_fifo.extend([42, 41, 42]);

    assert!(gate.remember_backpressured(99));

    assert!(gate.backpressured_ids.is_empty());
    assert!(gate.backpressured_fifo.is_empty());
}
