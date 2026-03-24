use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn critical_spillover_warms_fairness_for_subsequent_normal_backlog() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Fill reserved critical capacity first.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Overflow critical work into the normal lane while it is still empty. This
    // path should arm the same warm-fairness contract used by first normal ingress.
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Real normal backlog arrives under active critical pressure.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // The spillovered critical item occupies the normal queue head, so it may be
    // served first. Warm fairness must still ensure the first real normal item is
    // served within one additional dequeue instead of waiting behind another full
    // critical burst.
    assert_eq!(gate.pop_ready(), Some(102));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "fairness warmup from critical spillover should bound latency for subsequent normal backlog"
    );
}
