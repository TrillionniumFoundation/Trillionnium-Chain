use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_full_drain_allows_reuse_of_prior_critical_spillover_id_in_next_mixed_batch() {
    let mut gate = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode routes critical ingress through normal-lane headroom.
    // Build an initial mixed batch where the critical id drains through spillover.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After the full-drain boundary, the previously drained critical-spillover id
    // must be fresh again from the same class, and fresh mixed traffic must start
    // from a cold fairness / idempotency state.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), None);
}
