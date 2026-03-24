use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_idle_critical_slot_keeps_backpressured_critical_retry_fresh_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the last idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Fresh critical ingress is backpressured while the borrowed slot keeps the
    // lane globally full, and repeated probes must stay Backpressured rather than
    // poisoning the id into Duplicate.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain completely so the idle/full-drain self-heal path clears any stale
    // duplicate/backpressure bookkeeping associated with the saturated probes.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously backpressured critical id must remain fresh after the full
    // drain boundary, even when retried through the original critical class.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), None);
}

#[test]
fn borrowed_last_idle_critical_slot_preserves_duplicate_before_guard_reopens() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the last idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // A fresh critical retry stays backpressured while the borrowed slot keeps the
    // final reserved slot guarded.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // But an already queued normal id must still classify as Duplicate even though
    // the reserve guard blocks same-class headroom before any dequeue happens.
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Reopening one slot restores fresh admission for the previously backpressured id.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn borrowed_last_idle_critical_slot_keeps_cross_class_duplicate_ahead_of_guarded_fresh_retries() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // A fresh critical retry remains backpressured while the borrowed last slot
    // keeps the reserve guard shut.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Cross-class retries of the already queued borrowed id must still resolve as
    // Duplicate rather than inheriting the fresh retry's Backpressured outcome.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn borrowed_idle_tail_slot_flips_from_borrowable_to_guarded_once_critical_backlog_appears() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill normal dedicated capacity, then borrow exactly one idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(13, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // With one reserved critical slot left, fresh normal spillover must already be
    // guard-blocked, while the borrowed tx remains duplicate across classes.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(13, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Critical still owns the last reserved slot; once it fills that backlog, the
    // previously backpressured normal id must remain fresh until headroom reopens.
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    assert_eq!(gate.pop_ready(), Some(13));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_idle_critical_slot_guarded_small_retry_burst_uses_stable_lane_snapshot() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill normal capacity, then activate critical backlog without saturating the
    // lane so the final reserved critical slot stays guard-owned.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for (tx_id, class, expected) in [
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Critical, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
    ] {
        assert_eq!(gate.admit(tx_id, class), expected);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    // Once the final reserved slot is actually consumed, the same fresh id stays
    // backpressured under saturation until a dequeue reopens headroom.
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 2, 4));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    let first = gate.pop_ready();
    assert!(matches!(first, Some(10) | Some(20)));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    let second = gate.pop_ready();
    assert!(second.is_some());
    assert_ne!(first, second);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_idle_critical_slot_small_retry_burst_keeps_guard_outcomes_stable() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for class in [
        IngressClass::Critical,
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        let outcome = gate.admit(
            if matches!(class, IngressClass::Normal) {
                12
            } else {
                99
            },
            class,
        );
        assert_eq!(
            outcome,
            if matches!(class, IngressClass::Normal) {
                AdmitOutcome::Duplicate
            } else {
                AdmitOutcome::Backpressured
            }
        );
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn borrowed_last_idle_critical_slot_repeated_guard_probes_do_not_flip_fresh_retry_duplicate() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for (tx_id, class, expected) in [
        (99, IngressClass::Critical, AdmitOutcome::Backpressured),
        (12, IngressClass::Critical, AdmitOutcome::Duplicate),
        (99, IngressClass::Critical, AdmitOutcome::Backpressured),
        (12, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
    ] {
        assert_eq!(gate.admit(tx_id, class), expected);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn borrowed_last_idle_critical_slot_duplicate_retry_wins_under_open_headroom_guard() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Leave aggregate headroom open while critical backlog is active, so fresh
    // normal spillover is reserve-guarded instead of globally saturated.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Under the open-headroom reserve guard, duplicate classification must still
    // win for already queued ids while fresh normal retries stay backpressured.
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}

#[test]
fn borrowed_last_idle_critical_slot_mixed_retry_burst_keeps_fresh_and_duplicate_outcomes_partitioned(
) {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for (tx_id, class, expected) in [
        (12, IngressClass::Critical, AdmitOutcome::Duplicate),
        (99, IngressClass::Critical, AdmitOutcome::Backpressured),
        (12, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (12, IngressClass::Critical, AdmitOutcome::Duplicate),
    ] {
        assert_eq!(gate.admit(tx_id, class), expected);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn borrowed_last_idle_critical_slot_never_leaks_final_reserved_slot_once_critical_backlog_warms() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow exactly one idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // The last idle reserved slot may be borrowed once, but that borrowed id must
    // remain duplicate across classes and fresh normal retries must backpressure.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // As soon as critical backlog consumes the remaining reserved slot, the normal
    // guard must stay shut until one critical dequeue reopens genuine headroom.
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 2, 4));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn guarded_last_critical_slot_preserves_cross_class_duplicate_before_reopen() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity while leaving exactly one reserved critical
    // slot free and a live critical backlog.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The final reserved critical slot is guarded against fresh normal spillover,
    // but an already queued critical id must still classify as Duplicate even when
    // retried through the blocked normal path.
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // A fresh normal retry remains backpressured until the reserve reopens.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);

    // Once the previously backpressured id is admitted into the reopened reserved
    // slot, the guard may block fresh normal spillover again, but the recovered id
    // must immediately classify as Duplicate rather than falling back to
    // Backpressured.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn guarded_last_critical_slot_keeps_small_cross_class_retry_burst_stable_until_reopen() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    for (tx_id, class, expected) in [
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Critical, AdmitOutcome::Duplicate),
    ] {
        assert_eq!(gate.admit(tx_id, class), expected);
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn guarded_last_critical_slot_retry_burst_keeps_fresh_and_duplicate_outcomes_partitioned() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    for (tx_id, class, expected) in [
        (20, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Normal, AdmitOutcome::Duplicate),
        (99, IngressClass::Normal, AdmitOutcome::Backpressured),
        (20, IngressClass::Critical, AdmitOutcome::Duplicate),
    ] {
        assert_eq!(gate.admit(tx_id, class), expected);
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn guarded_last_critical_slot_keeps_normal_retry_guard_stable_until_critical_fill_then_dedupes() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Normal retries are guard-blocked while the final reserved critical slot is
    // still available, but the same tx id remains fresh until critical claims it.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Critical may still use the guarded slot, after which cross-class retries
    // must immediately switch from fresh/backpressured to duplicate.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn guarded_last_critical_slot_cross_class_retry_burst_flips_once_fresh_id_is_admitted() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // While the final reserved critical slot is still guarded, a fresh retry burst
    // for tx 99 stays Backpressured across classes without perturbing accounting.
    for class in [
        IngressClass::Normal,
        IngressClass::Normal,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(99, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    // Once critical claims the final reserved slot, the same tx id becomes queued
    // and repeated cross-class retries must flip immediately to Duplicate.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(99, class), AdmitOutcome::Duplicate);
        assert_eq!(gate.queued_counts(), (3, 2, 5));
    }
}

#[test]
fn guarded_last_critical_slot_duplicate_probe_wins_before_and_after_guard_block() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Under the open-headroom reserve guard, queued ids must still classify as
    // Duplicate even if fresh normal retries are concurrently backpressured.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Once critical consumes the final reserved slot, the same duplicate outcome
    // must remain stable on the saturated path rather than regressing to a retry
    // classification.
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.admit(20, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn guarded_last_critical_slot_critical_retry_stays_backpressured_until_reserved_headroom_reopens() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The final reserved critical slot remains open to critical ingress while
    // fresh normal retries are guard-blocked.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Once the guarded slot is consumed, repeated critical retries for a new id
    // must stay Backpressured rather than drifting into Duplicate.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Draining one critical item should immediately reopen the reserved slot for
    // the same fresh critical id, even while normal backlog is still present.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Once admitted, the id must flip to Duplicate across classes rather than
    // falling back to another retry classification.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}
