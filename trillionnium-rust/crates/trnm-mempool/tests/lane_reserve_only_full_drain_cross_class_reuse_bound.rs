use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_full_drain_allows_cross_class_reuse_without_stale_duplicate_poisoning() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only config: normal ingress borrows critical headroom.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // While queued, both ids must remain globally deduped across ingress classes.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Drain completely so the idle/full-drain reset path runs.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.pop_ready(), None);

    // After a true full drain, the same ids must be reusable through the opposite
    // ingress classes instead of staying poisoned as duplicates.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);

    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(11) || first == Some(10));
    assert!(second == Some(11) || second == Some(10));
    assert_ne!(first, second);
    assert_eq!(gate.pop_ready(), None);
}
