use super::*;
use serde_json::json;

fn fixture(count: usize, width: usize) -> State {
    (0..count)
        .map(|index| {
            (
                format!("root-fallback:{index:05}"),
                json!("x".repeat(width)),
            )
        })
        .collect()
}

fn equal(actual: &PreparedCommitment, reference: &PreparedCommitment) {
    assert_eq!(actual.root, reference.root);
    assert_eq!(actual.observation, reference.observation);
    assert_eq!(actual.snapshot.is_some(), reference.snapshot.is_some());
    let changes = |value: &PreparedCommitment| {
        value
            .changes
            .iter()
            .map(|change| {
                (
                    change.key.clone(),
                    change.before.clone(),
                    change.after.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(changes(actual), changes(reference));
    if let (Some(actual), Some(reference)) = (&actual.snapshot, &reference.snapshot) {
        assert_eq!(actual.root, reference.root);
        assert_eq!(actual.values, reference.values);
        assert_eq!(actual.tree.root(), reference.tree.root());
    }
}

#[test]
fn large_parent_full_root_arithmetic_rechecks_all_bytes_without_a_snapshot() {
    // Exceed the real default 8 MiB payload ceiling; no reduced protocol or
    // snapshot limit makes this a fallback. The original root is the oracle.
    let state = fixture(2100, 4080);
    let root = pon_executor::root(&state).unwrap();
    let limits = CacheLimits::default();
    let arithmetic = FullRootArithmetic::default();
    let reference = checked_snapshot(&state, root, None, limits).unwrap();
    assert_eq!(
        reference.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::PayloadBudget)
    );
    assert!(reference.observation.actual_payload_bytes > MAX_CACHE_PAYLOAD_BYTES);
    assert!(reference.snapshot.is_none());
    for _ in 0..2 {
        equal(
            &checked_snapshot_with_arithmetic(&state, root, None, limits, &arithmetic).unwrap(),
            &reference,
        );
    }
    let observed = arithmetic.0.lock().unwrap().observation();
    assert_eq!(observed.input_keys, state.len());
    assert!(observed.reused_partitions > 0);
    assert_eq!(observed.computed_partitions, 0);
    assert!(observed.retained_payload_bytes <= MAX_FULL_ROOT_ARITHMETIC_BYTES);
    let (bound, observation) = CheckedExecutionParent::check_and_bind_with_arithmetic(
        &state,
        root,
        None,
        limits,
        &arithmetic,
    )
    .unwrap();
    assert_eq!(observation, reference.observation);
    assert_eq!(*bound.actual, encode(&state).unwrap());
    assert!(bound.predecessor.is_none());
    drop(bound);

    // The warm mathematical entry cannot supply the current State or make an
    // old root authoritative after one actual, same-length value changes.
    let mut changed = state.clone();
    changed.insert("root-fallback:02099".into(), json!("y".repeat(4080)));
    assert_eq!(
        CheckedExecutionParent::check_and_bind_with_arithmetic(
            &changed,
            root,
            None,
            limits,
            &arithmetic,
        )
        .err(),
        Some("COMMITMENT_ROOT")
    );
    let changed_root = pon_executor::root(&changed).unwrap();
    equal(
        &checked_snapshot_with_arithmetic(&changed, changed_root, None, limits, &arithmetic)
            .unwrap(),
        &checked_snapshot(&changed, changed_root, None, limits).unwrap(),
    );
    equal(
        &checked_snapshot_with_arithmetic(&state, root, None, limits, &arithmetic).unwrap(),
        &reference,
    );
}

#[test]
fn full_root_arithmetic_preserves_forks_charges_and_error_order() {
    let state = fixture(32, 64);
    let root = pon_executor::root(&state).unwrap();
    let seed = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    let arithmetic = FullRootArithmetic::default();
    let mut changed = state.clone();
    changed.remove("root-fallback:00000");
    changed.insert("absent-versus-null".into(), json!(null));
    changed.insert("root-fallback:00031".into(), json!(""));
    for actual in [&state, &changed, &State::new()] {
        let expected = pon_executor::root(actual).unwrap();
        for prior in [None, seed.snapshot.as_ref()] {
            for limits in [
                CacheLimits::default(),
                CacheLimits {
                    max_keys: 0,
                    ..CacheLimits::default()
                },
                CacheLimits {
                    max_payload_bytes: 0,
                    ..CacheLimits::default()
                },
                CacheLimits {
                    max_workspace_charge_bytes: 0,
                    ..CacheLimits::default()
                },
            ] {
                equal(
                    &checked_snapshot_with_arithmetic(actual, expected, prior, limits, &arithmetic)
                        .unwrap(),
                    &checked_snapshot(actual, expected, prior, limits).unwrap(),
                );
            }
        }
    }
    let mut broken = seed.snapshot.as_ref().unwrap().clone();
    broken.tree = StateTree::default();
    equal(
        &checked_snapshot_with_arithmetic(
            &state,
            root,
            Some(&broken),
            CacheLimits::default(),
            &arithmetic,
        )
        .unwrap(),
        &checked_snapshot(&state, root, Some(&broken), CacheLimits::default()).unwrap(),
    );
    assert!(broken.tree.is_empty());
    let refused = CacheLimits {
        max_payload_bytes: 0,
        ..CacheLimits::default()
    };
    let allocation_order = |use_arithmetic| {
        ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
        let result = if use_arithmetic {
            derive_snapshot_with_arithmetic(&changed, seed.snapshot.as_ref(), refused, &arithmetic)
        } else {
            derive_snapshot(&changed, seed.snapshot.as_ref(), refused)
        }
        .unwrap();
        let stages = ALLOCATION_STAGES.with(|stages| stages.borrow().clone());
        (result, stages)
    };
    let original = allocation_order(false);
    let actual = allocation_order(true);
    equal(&actual.0, &original.0);
    assert_eq!(actual.1, original.1);
    assert_eq!(
        actual.1,
        [
            "budget-selected",
            "full-root-completed",
            "changes-allocation"
        ]
    );
    let invalid_limits = CacheLimits {
        max_keys: MAX_CACHE_KEYS + 1,
        ..CacheLimits::default()
    };
    let check_error = |actual: &State, expected: Hash, limits: CacheLimits| {
        let original = checked_snapshot(actual, expected, None, limits).err();
        assert!(original.is_some());
        assert_eq!(
            checked_snapshot_with_arithmetic(actual, expected, None, limits, &arithmetic).err(),
            original,
        );
        assert_eq!(
            CheckedExecutionParent::check_and_bind_with_arithmetic(
                actual,
                expected,
                None,
                limits,
                &arithmetic,
            )
            .err(),
            original,
        );
    };
    check_error(&state, [9; 32], refused);
    check_error(&state, root, invalid_limits);
    for invalid in [json!("非ASCII"), json!(0.0), json!(-0.0), json!({"λ":0})] {
        let actual = State::from([("a".repeat(161), json!(0)), ("zz-last".into(), invalid)]);
        check_error(&actual, root, refused);
        check_error(&actual, root, invalid_limits);
        assert_ne!(pon_executor::root(&actual), Err("LIMIT"));
    }
    let mut over = fixture(65_537, 0);
    check_error(&over, root, refused);
    over.insert("zz-last".into(), json!(-0.0));
    check_error(&over, root, invalid_limits);
    check_error(
        &State::from([("large-value".into(), json!("x".repeat(4095)))]),
        root,
        refused,
    );
    assert_eq!(
        seed.snapshot.unwrap().values.as_ref(),
        &encode(&state).unwrap()
    );
}

#[test]
fn full_root_arithmetic_contention_poison_and_retention_refusal_keep_the_original_root() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<FullRootArithmetic>();
    send_sync::<CheckedExecutionParent<'static>>();

    let state = fixture(128, 32);
    let limits = CacheLimits {
        max_payload_bytes: 0,
        ..CacheLimits::default()
    };
    let reference = derive_snapshot(&state, None, limits).unwrap();
    let arithmetic = FullRootArithmetic::default();
    equal(
        &derive_snapshot_with_arithmetic(&state, None, limits, &arithmetic).unwrap(),
        &reference,
    );
    {
        let held = arithmetic.0.lock().unwrap();
        equal(
            &derive_snapshot_with_arithmetic(&state, None, limits, &arithmetic).unwrap(),
            &reference,
        );
        assert_eq!(held.observation().input_keys, state.len());
    }
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = arithmetic.0.lock().unwrap();
        panic!("poison mathematical material only");
    }))
    .is_err());
    assert!(arithmetic.0.is_poisoned());
    equal(
        &derive_snapshot_with_arithmetic(&state, None, limits, &arithmetic).unwrap(),
        &reference,
    );
    // Only this private test construction refuses all material. The public
    // wrapper has one fixed 2 MiB cap and no limit/root/hash injection API.
    let no_retention = FullRootArithmetic(Mutex::new(StateRootArithmetic::new(0)));
    equal(
        &derive_snapshot_with_arithmetic(&state, None, limits, &no_retention).unwrap(),
        &reference,
    );
    let refused = no_retention.0.lock().unwrap();
    assert!(refused.observation().retention_refused);
    assert_eq!(refused.retained_payload_bytes(), 0);
}

#[test]
fn arithmetic_parent_keeps_execution_results_cancellation_and_unlocked_callbacks() {
    let (state, cfg, raws) = tests::preview_fixture();
    let root = pon_executor::root(&state).unwrap();
    let limits = CacheLimits {
        max_payload_bytes: 0,
        ..CacheLimits::default()
    };
    let arithmetic = FullRootArithmetic::default();
    let (reference, original_observation) =
        CheckedExecutionParent::check_and_bind(&state, root, None, limits).unwrap();
    let (actual, observation) = CheckedExecutionParent::check_and_bind_with_arithmetic(
        &state,
        root,
        None,
        limits,
        &arithmetic,
    )
    .unwrap();
    assert_eq!(observation, original_observation);
    let mut invalid = raws[0].clone();
    *invalid.last_mut().unwrap() ^= 1;
    for txs in [raws[..4].to_vec(), vec![raws[1].clone()], vec![invalid]] {
        for workers in [1, 4] {
            let request = || ExecutionRequest {
                timestamp: None,
                transactions: &txs,
                height: 1,
                miner: [3; 32],
                parent_id: [4; 32],
                workers,
            };
            match (
                actual.execute(request(), &cfg),
                reference.execute(request(), &cfg),
            ) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.output.state, b.output.state);
                    assert_eq!(a.output.receipts, b.output.receipts);
                    assert_eq!(a.output.root, b.output.root);
                    equal(&a.commitment, &b.commitment);
                }
                (Err(a), Err(b)) => assert_eq!(a, b),
                _ => panic!("arithmetic changed full signed execution"),
            }
            for stop in [
                ExecutionProgress::BeforeStateClone,
                ExecutionProgress::AfterMandatory,
                ExecutionProgress::BeforeCommitment,
                ExecutionProgress::AfterCommitment,
                ExecutionProgress::BeforeOutput,
            ] {
                let run = |parent: &CheckedExecutionParent<'_>| {
                    let trace = Mutex::new(Vec::new());
                    let result = parent.execute_with_progress(request(), &cfg, &|point| {
                        assert!(arithmetic.0.try_lock().is_ok());
                        trace.lock().unwrap().push(point);
                        if point == stop {
                            Err("cancel-original-checkpoint")
                        } else {
                            Ok(())
                        }
                    });
                    (result.err(), trace.into_inner().unwrap())
                };
                let a = run(&actual);
                let b = run(&reference);
                assert_eq!(a.0, b.0);
                if workers == 1 {
                    assert_eq!(a.1, b.1);
                }
            }
        }
    }
    assert_eq!(pon_executor::root(&state).unwrap(), root);
}
