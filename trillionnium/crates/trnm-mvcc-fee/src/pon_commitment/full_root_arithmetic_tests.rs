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
    fn unlocked_at_callback(arithmetic: &FullRootArithmetic, probes: &Mutex<()>) -> bool {
        // Worker callbacks run concurrently. A successful try_lock probe itself
        // owns a guard, so serialize only these probes, not execution/callbacks.
        // Production arithmetic never takes this gate: a real retained guard
        // must still fail the probe, including on the calling thread.
        let _probe = probes.lock().unwrap();
        let attempted = arithmetic.0.try_lock();
        let unlocked = attempted.is_ok();
        drop(attempted);
        unlocked
    }

    let (state, cfg, raws) = tests::preview_fixture();
    let root = pon_executor::root(&state).unwrap();
    let limits = CacheLimits {
        max_payload_bytes: 0,
        ..CacheLimits::default()
    };
    let arithmetic = FullRootArithmetic::default();
    let callback_probes = Mutex::new(());
    {
        let held = arithmetic.0.lock().unwrap();
        assert!(!unlocked_at_callback(&arithmetic, &callback_probes));
        drop(held);
    }
    assert!(unlocked_at_callback(&arithmetic, &callback_probes));
    let start = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                start.wait();
                assert!(unlocked_at_callback(&arithmetic, &callback_probes));
            });
        }
    });
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
                    assert_eq!(
                        a.output.metrics.workers_spawned,
                        b.output.metrics.workers_spawned
                    );
                    let expected_workers = workers.min(txs.len());
                    assert_eq!(
                        a.output.metrics.workers_spawned,
                        if expected_workers > 1 {
                            expected_workers
                        } else {
                            0
                        }
                    );
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
                        // Executor workers are joined before owner commitment;
                        // only peer probes can legitimately contend here.
                        assert!(unlocked_at_callback(&arithmetic, &callback_probes));
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

#[test]
fn arithmetic_prefix_keeps_two_signed_appends_and_cancelled_successor_rollback() {
    // Small semantic fixture with a legal forced fallback, not an 8 MiB or
    // CPU-budget experiment. The original None API is the full-root oracle.
    let (state, cfg, raws) = tests::preview_fixture();
    let parent_root = pon_executor::root(&state).unwrap();
    let limits = CacheLimits {
        max_payload_bytes: 0,
        ..CacheLimits::default()
    };
    let arithmetic = FullRootArithmetic::default();
    let make_prefix = |with_arithmetic| {
        let (parent, observation) = if with_arithmetic {
            CheckedExecutionParent::check_and_bind_with_arithmetic(
                &state,
                parent_root,
                None,
                limits,
                &arithmetic,
            )
        } else {
            CheckedExecutionParent::check_and_bind(&state, parent_root, None, limits)
        }
        .unwrap();
        assert_eq!(
            observation.method,
            CommitmentMethod::FullRoot(FullRootReason::PayloadBudget)
        );
        let progress = |_| Ok::<(), &'static str>(());
        parent
            .into_prefix_with_control(
                pon_executor::PrefixContext {
                    timestamp: None,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                },
                &cfg,
                &pon_executor::ExecutionControl::new(&progress, &()),
            )
            .unwrap()
    };
    let mut actual = make_prefix(true);
    let mut reference = make_prefix(false);
    let append = |prefix: &mut CheckedTransactionPrefix<'_>,
                  transactions: &[Vec<u8>],
                  stop: Option<ExecutionProgress>| {
        let trace = Mutex::new(Vec::new());
        let progress = |point| {
            assert!(arithmetic.0.try_lock().is_ok());
            trace.lock().unwrap().push(point);
            if Some(point) == stop {
                Err("cancel-prefix-after-original-root")
            } else {
                Ok(())
            }
        };
        let result = prefix.execute_with_control(
            transactions,
            &pon_executor::ExecutionControl::new(&progress, &()),
        );
        (result, trace.into_inner().unwrap())
    };
    let compare = |actual: &StagedOutput, reference: &StagedOutput| {
        assert_eq!(actual.output.state, reference.output.state);
        assert_eq!(actual.output.root, reference.output.root);
        assert_eq!(actual.output.receipts, reference.output.receipts);
        equal(&actual.commitment, &reference.commitment);
        assert!(actual.commitment.snapshot.is_none());
        assert_eq!(
            actual.commitment.observation.method,
            CommitmentMethod::FullRoot(FullRootReason::PayloadBudget)
        );
        assert_eq!(
            actual.output.root,
            pon_executor::root(&actual.output.state).unwrap()
        );
        assert_eq!(actual.output.metrics.signature_verifications, 1);
        assert_eq!(actual.output.metrics.committed_without_replay, 1);
    };

    let (first, first_trace) = append(&mut actual, &raws[..1], None);
    let (first_reference, reference_trace) = append(&mut reference, &raws[..1], None);
    let first = first.unwrap();
    compare(&first, &first_reference.unwrap());
    assert_eq!(first_trace, reference_trace);
    assert_eq!(actual.len(), 1);
    assert_eq!(reference.len(), 1);
    // This also catches accidentally dropping arithmetic from the prefix
    // wrapper: the parent had fewer keys than this real successor.
    assert!(first.output.state.len() > state.len());
    assert_eq!(
        arithmetic.0.lock().unwrap().observation().input_keys,
        first.output.state.len()
    );

    // Abort the second append AFTER its actual root calculation has warmed
    // the mathematical cache. Neither prefix may publish that scratch state.
    let cut = ExecutionProgress::AfterCommitment;
    let (cancelled, cancelled_trace) = append(&mut actual, &raws[..2], Some(cut));
    let (cancelled_reference, reference_trace) = append(&mut reference, &raws[..2], Some(cut));
    assert_eq!(
        cancelled.err(),
        Some(ExecutionError::Cancelled(
            "cancel-prefix-after-original-root"
        ))
    );
    assert_eq!(
        cancelled_reference.err(),
        Some(ExecutionError::Cancelled(
            "cancel-prefix-after-original-root"
        ))
    );
    assert_eq!(cancelled_trace, reference_trace);
    assert_eq!(cancelled_trace.last(), Some(&cut));
    assert_eq!(actual.len(), 1);
    assert_eq!(reference.len(), 1);

    let (second, second_trace) = append(&mut actual, &raws[..2], None);
    let (second_reference, reference_trace) = append(&mut reference, &raws[..2], None);
    compare(&second.unwrap(), &second_reference.unwrap());
    assert_eq!(second_trace, reference_trace);
    assert_eq!(actual.len(), 2);
    assert_eq!(reference.len(), 2);
    assert_eq!(pon_executor::root(&state).unwrap(), parent_root);
}

#[test]
fn configured_root_rechecks_original_grammar_context_and_current_values() {
    let cfg = Config::installed().unwrap();
    let arithmetic = FullRootArithmetic::default();
    let mut state = fixture(32, 64);
    for _ in 0..2 {
        assert_eq!(
            arithmetic.root_for_config(&state, &cfg),
            pon_executor::root_for_config(&state, &cfg)
        );
    }
    let original = pon_executor::root_for_config(&state, &cfg).unwrap();
    state.insert("root-fallback:00031".into(), json!("y".repeat(64)));
    assert_ne!(arithmetic.root_for_config(&state, &cfg).unwrap(), original);
    assert_eq!(
        arithmetic.root_for_config(&state, &cfg),
        pon_executor::root_for_config(&state, &cfg)
    );
    state.remove("root-fallback:00000");
    state.insert("absent-versus-null".into(), json!(null));
    assert_eq!(
        arithmetic.root_for_config(&state, &cfg),
        pon_executor::root_for_config(&state, &cfg)
    );
    for invalid in [json!("λ"), json!(-0.0), json!({"λ":0}), json!([1, 0.5])] {
        let actual = State::from([
            ("a".repeat(161), json!("x".repeat(4095))),
            ("z".into(), invalid),
        ]);
        let expected = pon_executor::root_for_config(&actual, &cfg);
        assert!(expected.is_err());
        assert_ne!(expected, Err("LIMIT"));
        assert_eq!(arithmetic.root_for_config(&actual, &cfg), expected);
        let mut changed = cfg.clone();
        changed.params["native_pq_accounts_profile"] = json!("unbound-context");
        assert_eq!(
            pon_executor::root_for_config(&actual, &changed),
            Err("PQ2_PROFILE_REQUIRED")
        );
        assert_eq!(
            arithmetic.root_for_config(&actual, &changed),
            Err("PQ2_PROFILE_REQUIRED")
        );
    }
}

#[test]
fn configured_root_preserves_real_pq_and_growth_validation_on_warm_arithmetic() {
    use pon_executor::pq_accounts_v2::{self, GenesisAccount};
    let arithmetic = FullRootArithmetic::default();
    let account = GenesisAccount {
        spki: include_bytes!("../../../trnm-protocol/tests/fixtures/pq_transfer/public.der")
            .to_vec(),
        balance: 10_000_000,
    };
    let (cfg, state, _) = pq_accounts_v2::genesis(&[account], 1000).unwrap();
    for _ in 0..2 {
        assert_eq!(
            arithmetic.root_for_config(&state, &cfg),
            pon_executor::root_for_config(&state, &cfg)
        );
    }
    let mut invalid = state.clone();
    let key = invalid
        .keys()
        .find(|k| k.starts_with("account:"))
        .unwrap()
        .clone();
    invalid.get_mut(&key).unwrap()["nonce"] = json!(-1);
    let expected = pon_executor::root_for_config(&invalid, &cfg);
    assert!(expected.is_err());
    assert_eq!(arithmetic.root_for_config(&invalid, &cfg), expected);
    let mut changed = cfg.clone();
    changed.network[0] ^= 1;
    assert_eq!(
        pon_executor::root_for_config(&state, &changed),
        Err("PQ2_CONFIG_CHANGED")
    );
    assert_eq!(
        arithmetic.root_for_config(&state, &changed),
        Err("PQ2_CONFIG_CHANGED")
    );
    let growth = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        crate::growth_profile_v2::PROFILE,
    )
    .unwrap();
    let state = State::from([
        (
            format!("account:{}", hex::encode([9; 32])),
            json!({"balance":7,"nonce":3}),
        ),
        ("meta:issued".into(), json!(7)),
    ]);
    for _ in 0..2 {
        let expected = pon_executor::root_for_config(&state, &growth);
        assert!(expected.is_ok());
        assert_ne!(expected, pon_executor::root(&state));
        assert_eq!(arithmetic.root_for_config(&state, &growth), expected);
    }
    let mut invalid = state.clone();
    invalid.insert("meta:issued".into(), json!(8));
    assert_eq!(
        pon_executor::root_for_config(&invalid, &growth),
        Err("CONSERVATION")
    );
    assert_eq!(
        arithmetic.root_for_config(&invalid, &growth),
        Err("CONSERVATION")
    );
    let mut changed = growth.clone();
    changed.params["growth_reference_policy_hash"] = json!(hex::encode([0; 32]));
    let expected = pon_executor::root_for_config(&state, &changed);
    assert_eq!(expected, Err("GROWTH_PROFILE"));
    assert_eq!(arithmetic.root_for_config(&state, &changed), expected);
}
