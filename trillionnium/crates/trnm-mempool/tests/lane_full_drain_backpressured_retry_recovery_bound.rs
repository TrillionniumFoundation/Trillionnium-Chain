use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn full_drain_after_saturated_backpressure_keeps_fresh_cross_class_retry_admissible() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh id hits saturated global capacity and must remain non-poisoned.
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(30, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain everything so idle self-heal / full-drain reset paths run completely.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Extra idle polls after the full-drain reset must stay no-op and must not
    // resurrect stale backpressure metadata for the previously rejected id.
    assert_eq!(gate.pop_ready(), None);

    // Previously backpressured id must still be fresh after full drain, even when
    // retried through the opposite class.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(30));
}

#[test]
fn saturated_retry_burst_keeps_queue_counts_stable_until_headroom_reopens() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(99, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (1, 1, 2));
    }

    assert!(matches!(gate.pop_ready(), Some(1) | Some(2)));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));
}

#[test]
fn repeated_idle_polls_after_full_drain_do_not_resurrect_backpressured_retry_metadata() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(30, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (0, 1, 1));
    assert_eq!(gate.pop_ready(), Some(30));
}

#[test]
fn repeated_same_id_saturated_retries_stay_backpressured_until_one_slot_reopens() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(30, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (1, 1, 2));
    }

    // Saturation should preserve bounded-retry semantics for fresh ids until one
    // real slot reopens, at which point the same id becomes admissible and then
    // immediately dedupes across classes.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(30, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn critical_retry_bursts_stay_backpressured_once_normal_headroom_is_exhausted() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for retry in [90_u64, 91_u64, 90_u64, 91_u64] {
        assert_eq!(
            gate.admit(retry, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    assert!(matches!(gate.pop_ready(), Some(1) | Some(2) | Some(3)));
    assert_eq!(
        gate.admit(90, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}

#[test]
fn reserved_critical_slot_keeps_unsaturated_normal_retry_burst_backpressured_until_drain() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // One lane-wide slot is still free, but it is the last reserved critical slot.
    // Fresh normal retries must stay backpressured until critical backlog drains.
    for retry in [70_u64, 71_u64, 70_u64, 71_u64] {
        assert_eq!(
            gate.admit(retry, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    assert_eq!(
        gate.admit(5, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    assert!(matches!(gate.pop_ready(), Some(4) | Some(5)));
    assert_eq!(
        gate.admit(70, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    assert!(matches!(gate.pop_ready(), Some(4) | Some(5)));
    assert_eq!(gate.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserved_critical_slot_accepts_one_critical_retry_then_rebounds_normal_retries() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    for tx_id in [80_u64, 81_u64] {
        assert_eq!(
            gate.admit(tx_id, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    // The last free slot is reserved for critical ingress while critical backlog is
    // active, so a critical retry may consume it exactly once.
    assert_eq!(
        gate.admit(80, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Once the same tx id is admitted through the reserved critical slot, retries
    // through the previously blocked normal path must flip to Duplicate rather than
    // staying Backpressured.
    assert_eq!(
        gate.admit(80, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    for (tx_id, class) in [
        (81_u64, IngressClass::Normal),
        (81_u64, IngressClass::Critical),
        (82_u64, IngressClass::Normal),
        (82_u64, IngressClass::Critical),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (3, 2, 5));
    }
}

#[test]
fn reserved_slot_reopens_normal_retry_once_critical_backlog_clears() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(5, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // While any critical backlog remains, a fresh normal retry still cannot borrow.
    assert_eq!(gate.pop_ready(), Some(4));
    assert_eq!(
        gate.admit(90, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Once the critical backlog clears, the reopened reserved headroom becomes
    // borrowable immediately for normal ingress without waiting for extra idle polls.
    assert_eq!(gate.pop_ready(), Some(5));
    assert_eq!(gate.admit(90, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));
}
