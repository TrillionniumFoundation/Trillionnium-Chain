use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_warm_fairness_survives_saturated_fresh_probe_noise_before_first_real_normal_turn() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated critical reserve first, then spill one critical tx into the
    // normal lane. This path should arm the same warm-fairness contract used by
    // first normal ingress while dual backlog is active.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Add one real normal item and refill critical pressure so the lane reaches
    // global saturation before the first real normal anti-starvation turn. Tx 103
    // also spills into the normal queue, leaving three normal-queue items and two
    // items in the dedicated critical reserve.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Fresh saturated probes from either ingress class must stay backpressured
    // and must not cool the spillover-warmed fairness state.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // The spillovered critical item may still drain first from the normal queue
    // head, but the first real normal item must get a turn within one
    // additional dequeue instead of waiting behind another full critical burst.
    assert_eq!(gate.pop_ready(), Some(102));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "spillover-warmed fairness should survive saturated fresh-probe noise before the first real normal turn"
    );
}
