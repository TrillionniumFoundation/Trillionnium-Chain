use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_recovered_id_re_dedupes_without_perturbing_queue_accounting() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the dedicated critical slot and normal capacity, then spill one more
    // critical tx into the normal lane so the lane is globally full.
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

    // Fresh id remains backpressured across classes while saturated.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // After one dequeue frees headroom, the same id recovers as fresh ingress.
    assert!(matches!(gate.pop_ready(), Some(100) | Some(1)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Once recovered into the lane, the same id must immediately regain global
    // duplicate protection without perturbing queue accounting.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}

#[test]
fn spillover_recovered_id_keeps_cross_class_duplicate_contract_without_queue_count_drift() {
    let mut gate = LaneAdmissionGate::new(3, 1);

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

    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert!(matches!(gate.pop_ready(), Some(100) | Some(1)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Once recovered through spillover, duplicate protection must remain global
    // across both ingress classes and must not perturb queue accounting.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}

#[test]
fn spillover_recovered_id_and_next_fresh_admit_keep_cross_class_dedup_and_queue_accounting_stable()
{
    let mut gate = LaneAdmissionGate::new(3, 1);

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

    assert!(matches!(gate.pop_ready(), Some(100) | Some(1)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // After the recovered spillover id re-dedupes, the next freed slot should still
    // admit a fresh id cleanly without disturbing lane-wide accounting, regardless
    // of whether the next dequeue serves the spillovered critical item or the
    // remaining older normal item first.
    assert!(matches!(
        gate.pop_ready(),
        Some(100) | Some(101) | Some(1) | Some(999)
    ));
    assert_eq!(
        gate.admit(555, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(
        gate.admit(555, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
}
