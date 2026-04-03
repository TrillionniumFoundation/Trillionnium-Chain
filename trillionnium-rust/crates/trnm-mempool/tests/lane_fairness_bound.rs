use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn normal_backlog_gets_service_within_one_pop_after_arrival_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Establish sustained critical pressure and consume a few critical turns.
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
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));

    // Normal traffic appears while critical backlog is still active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Anti-starvation contract: normal gets a turn no later than the next dequeue.
    // (Immediate service is acceptable and currently expected.)
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(1) || second == Some(1));
}

#[test]
fn critical_spillover_in_normal_lane_gets_turn_within_one_pop_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Saturate reserved critical capacity.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Keep some critical backlog active while admitting one overflow critical tx
    // via normal-lane spillover.
    assert_eq!(
        gate.admit(202, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Overflowed critical tx in normal lane should not wait through a full burst.
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(202) || second == Some(202));
}

#[test]
fn mixed_batch_after_full_drain_still_grants_normal_turn_within_one_pop() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm fairness with dual-lane backlog and drain everything.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(1), Some(100), Some(101)]);

    // Contract guard: after a full drain, the next mixed batch should still
    // preserve bounded normal latency under critical pressure.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(2) || second == Some(2));
}

#[test]
fn reserve_only_borrowed_normal_does_not_preempt_already_queued_critical() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(
        gate.admit(900, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(901, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // In reserve-only mode, normal ingress borrows critical headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Anti-starvation must not invert priority here: pre-existing critical work
    // should still drain first.
    assert_eq!(gate.pop_ready(), Some(900));
    assert_eq!(gate.pop_ready(), Some(901));
    assert_eq!(gate.pop_ready(), Some(1));
}

#[test]
fn sustained_critical_pressure_with_normal_backlog_keeps_normal_latency_bounded() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Build mixed backlog where normal traffic arrives while critical traffic stays active.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Contract: once fairness is warm under active critical pressure, normal backlog
    // should receive service within at most one additional dequeue.
    let p1 = gate.pop_ready();
    let p2 = gate.pop_ready();
    assert!(matches!(
        (p1, p2),
        (Some(1), _) | (_, Some(1)) | (Some(2), _) | (_, Some(2))
    ));
}

#[test]
fn full_drain_resets_fairness_streak_so_next_critical_is_not_delayed() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm a non-zero critical streak with active critical dequeues.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));

    // Drain fully so the scheduler should reset warm fairness state.
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), None);

    // After idle reset, a fresh critical item should be served immediately.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(200));
}

#[test]
fn fairness_warmup_serves_oldest_normal_first_under_active_critical_backlog() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Build active critical pressure first.
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
    assert_eq!(gate.pop_ready(), Some(100));

    // Two normals arrive while critical backlog remains active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Warm fairness must not skip the older normal entry when granting the
    // anti-starvation turn.
    assert_eq!(gate.pop_ready(), Some(1));
}

#[test]
fn duplicate_probe_noise_does_not_make_warm_fairness_skip_oldest_normal() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Keep critical pressure active, then warm fairness with two normal items.
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
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Replays of queued work across both classes should stay classificatory only:
    // they must not cool warm fairness or let the newer normal item jump ahead.
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(102, IngressClass::Normal), AdmitOutcome::Duplicate);

    // The anti-starvation turn should still serve the oldest normal item first.
    assert_eq!(gate.pop_ready(), Some(1));
    let second = gate.pop_ready();
    assert!(matches!(second, Some(101) | Some(102) | Some(103) | Some(2)));
}
