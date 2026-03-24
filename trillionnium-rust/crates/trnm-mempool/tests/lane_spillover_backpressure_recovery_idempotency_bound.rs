use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_saturation_backpressured_id_recovers_after_one_drain_and_then_dedupes_globally() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the dedicated critical slot and the normal lane, then force one more
    // critical tx to spill into normal capacity so the lane becomes globally full.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // A fresh id probed while the spillovered mixed backlog saturates the lane
    // must stay Backpressured across both classes, never Duplicate.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once one queued item drains, the previously backpressured id should admit
    // as fresh again instead of inheriting stale duplicate state.
    assert!(matches!(gate.pop_ready(), Some(100) | Some(1) | Some(101)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // After the recovered admission lands, cross-class retries must immediately
    // regain global duplicate protection even though the earlier saturated probes
    // were only Backpressured.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn spillover_saturation_preserves_duplicate_before_fresh_normal_retry_recovers() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the dedicated critical slot and the normal lane, then spill one more
    // critical tx into normal capacity so aggregate headroom closes.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // While the lane stays globally saturated, fresh normal retries must remain
    // Backpressured, but the already queued spillovered critical id must still
    // resolve as Duplicate even when probed through the normal class.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(101, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // After one drain reopens headroom, the previously backpressured id should
    // recover as fresh without disturbing the duplicate contract for queued ids.
    assert!(matches!(gate.pop_ready(), Some(100) | Some(1) | Some(101)));
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
}
