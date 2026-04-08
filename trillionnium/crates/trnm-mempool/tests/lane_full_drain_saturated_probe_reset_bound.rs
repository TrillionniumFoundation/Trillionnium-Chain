use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_probe_noise_before_full_drain_does_not_warm_next_batch() {
    let mut g = LaneAdmissionGate::new(4, 1);

    // Build a mixed backlog and warm fairness under active dual-lane pressure.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

    // Drain once so the lane carries non-zero fairness state with both backlogs active.
    assert_eq!(g.pop_ready(), Some(20));

    // Refill critical pressure so the lane is globally saturated again.
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);

    // Under saturation, duplicate and fresh probes must preserve classification
    // without poisoning the subsequent full-drain reset boundary.
    assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain fully so all fairness/idempotency bookkeeping crosses the cold-reset boundary.
    while g.pop_ready().is_some() {}

    // The previously backpressured fresh id must remain fresh after the full drain.
    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.pop_ready(), Some(99));

    // Fresh mixed ingress after the full drain must start cold again: critical goes first,
    // then the oldest normal item gets its bounded anti-starvation turn.
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(40, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);

    assert_eq!(g.pop_ready(), Some(40));
    assert_eq!(g.pop_ready(), Some(30));
    assert_eq!(g.pop_ready(), Some(41));
}
