use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_full_drain_resets_fairness_so_fresh_critical_is_not_delayed() {
    let mut gate = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode routes critical ingress through free normal headroom.
    // Build a mixed batch that exercises the shared-queue / full-drain boundary.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain fully so any warm fairness or duplicate bookkeeping from the prior
    // mixed batch must be cold-reset before the next cycle.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), None);

    // After the full drain boundary, a fresh critical item must not inherit any
    // stale fairness delay from the earlier mixed backlog.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(3));
}
