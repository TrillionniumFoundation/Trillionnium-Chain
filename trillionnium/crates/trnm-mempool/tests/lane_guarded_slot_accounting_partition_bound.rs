use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn guarded_last_reserved_slot_keeps_duplicate_vs_fresh_retry_accounting_flat_until_reopen() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then leave exactly one reserved critical
    // slot occupied so the final free aggregate slot remains guard-owned for
    // critical ingress.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Under the reserve guard, queued critical ids must keep class-agnostic
    // duplicate semantics while fresh normal retries stay backpressured.
    for _ in 0..3 {
        assert_eq!(
            gate.admit(10, IngressClass::Normal),
            AdmitOutcome::Duplicate
        );
        assert_eq!(
            gate.admit(70, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }

    // Once critical consumes the final reserved slot, accounting remains flat and
    // the previously fresh retry is still backpressured until real headroom reopens.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.admit(70, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));
}
