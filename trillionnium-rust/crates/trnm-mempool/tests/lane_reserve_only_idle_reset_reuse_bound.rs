use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_full_drain_resets_for_cross_class_reuse_and_fresh_critical_progress() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode keeps all capacity in the critical lane while allowing
    // normal ingress to borrow idle headroom.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain completely so idle-reset / full-drain self-heal paths run to completion.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously drained borrowed id must be reusable across classes as fresh
    // ingress after the full-drain reset boundary.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    // Fresh critical ingress must still make immediate progress after the idle
    // reset instead of being delayed by any stale fairness bookkeeping.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), None);
}
