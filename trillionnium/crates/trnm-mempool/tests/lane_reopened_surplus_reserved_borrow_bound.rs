use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reopened_surplus_reserved_headroom_is_borrowable_before_final_guard_slot() {
    let mut gate = LaneAdmissionGate::new(5, 3);

    // Fill the dedicated normal lane first, then leave exactly one free reserved
    // critical slot while backlog remains active.
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 2, 4));

    // With only the final guarded reserved slot free, fresh normal ingress must stay blocked.
    assert_eq!(gate.admit(22, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.queued_counts(), (2, 2, 4));

    // After one critical dequeue, backlog is still active but one surplus reserved
    // slot reopens. Normal ingress may borrow that surplus slot only, while the
    // final reserved critical slot remains guarded.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.admit(22, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 2, 4));
    assert_eq!(gate.admit(23, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
}
