use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn repeated_empty_pop_after_spillover_full_drain_does_not_poison_cross_class_reuse_or_cold_progress(
) {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill the dedicated critical reserve, then force one critical tx to spill into
    // normal capacity behind an existing normal item.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain fully so the spillover path crosses the same full-drain self-heal
    // boundary used by long-lived schedulers between batches. Warm fairness may
    // give the older real normal item the first turn before draining the reserved
    // critical item and the spillovered critical tail.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), None);

    // Repeated idle polls after the spillover batch must stay pure no-ops and must
    // not preserve stale duplicate/fairness state into the next mixed batch.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    // The previously spilled critical id must be reusable as fresh ingress from the
    // opposite class, and the next batch should restart cold.
    assert_eq!(
        gate.admit(101, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Normal),
        AdmitOutcome::Accepted
    );

    // Cold restart contract: older critical backlog drains first, then the oldest
    // normal item gets its bounded turn without inheriting stale spillover state.
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), Some(201));
    assert_eq!(gate.pop_ready(), None);
}
