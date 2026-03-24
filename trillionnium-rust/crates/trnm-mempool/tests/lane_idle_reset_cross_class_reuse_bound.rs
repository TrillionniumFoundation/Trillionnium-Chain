use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn drained_lane_allows_cross_class_reuse_without_stale_duplicate_or_fairness_bias() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Build mixed backlog so fairness bookkeeping becomes non-zero before drain.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Exercise one critical dequeue first so the lane carries non-zero fairness state.
    assert_eq!(gate.pop_ready(), Some(20));

    // Drain the remaining backlog completely.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(21));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Reuse a previously drained id through the opposite class. Full-drain reset
    // must treat it as fresh instead of preserving stale duplicate state.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);

    // Both fresh admissions should drain cleanly after the idle reset, regardless
    // of which class is served first under the reset fairness state.
    let first = gate.pop_ready();
    assert!(first == Some(10) || first == Some(30));
    let second = gate.pop_ready();
    assert!(second == Some(10) || second == Some(30));
    assert_ne!(first, second);
    assert_eq!(gate.queued_counts(), (0, 0, 0));
}
