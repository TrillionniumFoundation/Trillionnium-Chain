use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn full_drain_after_warm_duplicate_probes_cold_resets_next_mixed_batch() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm fairness under active dual-lane backlog.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Duplicate probe noise against the warmed normal item must stay Duplicate
    // without perturbing the queued contract while the lane remains active.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Drain fully so the idle reset / full-drain self-heal path runs to completion.
    let mut drained = [gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, [Some(1), Some(100), Some(101)]);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Contract guard: after a true full drain, duplicate-probe noise from the
    // earlier warm cycle must not poison the next mixed batch. The new normal
    // item should still get its bounded fairness turn while the fresh critical
    // item remains queued for progress immediately after.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(2) || second == Some(2));
    assert!(first == Some(200) || second == Some(200));

    // The previously drained duplicated id must also be reusable as fresh
    // ingress after the full-drain boundary.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}
