use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn stale_duplicate_memory_after_full_critical_drain_does_not_block_idle_last_slot_borrow() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(41));

    // Once the critical queue fully drains, duplicate memory from the earlier
    // critical tx must not fabricate backlog and falsely keep the final reserved
    // slot closed to fresh normal ingress.
    assert_eq!(gate.admit(7, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(8, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(9, IngressClass::Normal), AdmitOutcome::Accepted);

    // The borrowed last reserved slot is now genuinely occupied, so a fresh
    // critical tx must still fail closed until a real drain happens.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
}
