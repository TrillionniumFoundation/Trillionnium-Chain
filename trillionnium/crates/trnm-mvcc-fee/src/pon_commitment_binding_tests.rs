//! Same-operation checked parent binding versus the retained original two steps.
use super::*;
use serde_json::json;

fn original<'a>(
    state: &'a State,
    expected: Hash,
    prior: Option<&CheckedCommitment>,
    limits: CacheLimits,
) -> Result<(CheckedExecutionParent<'a>, CommitmentObservation)> {
    let checked = checked_snapshot(state, expected, prior, limits)?;
    let bound =
        CheckedExecutionParent::bind(state, checked.root, checked.snapshot.as_ref(), limits)?;
    Ok((bound, checked.observation))
}
fn fixture(count: usize, width: usize) -> State {
    (0..count)
        .map(|i| (format!("binding:{i:05}"), json!("x".repeat(width))))
        .collect()
}
fn equal(a: &CheckedExecutionParent<'_>, b: &CheckedExecutionParent<'_>) {
    assert!(std::ptr::eq(a.state, b.state));
    assert_eq!(a.actual, b.actual);
    assert_eq!(a.predecessor.is_some(), b.predecessor.is_some());
    assert_eq!(a.limits, b.limits);
    if let (Some(a), Some(b)) = (&a.predecessor, &b.predecessor) {
        assert_eq!(a.root, b.root);
        assert_eq!(a.values, b.values);
        assert_eq!(a.tree.root(), b.tree.root());
    }
}

#[test]
fn checked_binding_matches_two_steps_for_cold_warm_and_every_budget_fallback() {
    let state = fixture(33, 256);
    let root = pon_executor::root(&state).unwrap();
    let seed = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
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
            max_workspace_charge_bytes: 1,
            ..CacheLimits::default()
        },
    ] {
        for prior in [None, seed.snapshot.as_ref()] {
            let (a, ao) =
                CheckedExecutionParent::check_and_bind(&state, root, prior, limits).unwrap();
            let (b, bo) = original(&state, root, prior, limits).unwrap();
            equal(&a, &b);
            assert_eq!(ao, bo);
            if let Some(snapshot) = &a.predecessor {
                assert!(Arc::ptr_eq(&a.actual, &snapshot.values));
            }
        }
    }
    assert_eq!(seed.snapshot.as_ref().unwrap().root(), root);
}

#[test]
fn checked_binding_preserves_wrong_roots_late_errors_and_invalid_limits() {
    let state = fixture(4, 8);
    let root = pon_executor::root(&state).unwrap();
    let seed = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
    let check = |actual: &State, expected: Hash, limits: CacheLimits| {
        let a = CheckedExecutionParent::check_and_bind(
            actual,
            expected,
            seed.snapshot.as_ref(),
            limits,
        )
        .err();
        let b = original(actual, expected, seed.snapshot.as_ref(), limits).err();
        assert_eq!(a, b);
        assert!(a.is_some());
    };
    check(&state, [9; 32], CacheLimits::default());
    let mut actual = state.clone();
    actual.insert("binding:00000".into(), json!(4));
    check(&actual, root, CacheLimits::default());
    actual.insert("k".repeat(161), json!(0));
    check(&actual, root, CacheLimits::default());
    actual.insert("zz".into(), json!("非ASCII"));
    check(&actual, root, CacheLimits::default());
    actual.insert("zz".into(), json!(1.5));
    check(&actual, root, CacheLimits::default());
    check(
        &actual,
        root,
        CacheLimits {
            max_keys: MAX_CACHE_KEYS + 1,
            ..CacheLimits::default()
        },
    );
    check(
        &state,
        root,
        CacheLimits {
            max_keys: MAX_CACHE_KEYS + 1,
            ..CacheLimits::default()
        },
    );
    let too_many = fixture(65_537, 0);
    check(&too_many, root, CacheLimits::default());
    let oversize = State::from([("value".into(), json!("x".repeat(4095)))]);
    check(&oversize, root, CacheLimits::default());
}

#[test]
fn checked_binding_rechecks_actual_values_and_repairs_only_derived_material() {
    let state = fixture(8, 16);
    let root = pon_executor::root(&state).unwrap();
    let seed = checked_snapshot(&state, root, None, CacheLimits::default())
        .unwrap()
        .snapshot
        .unwrap();
    let mut broken = seed.clone();
    broken.tree = StateTree::default();
    let (a, ao) =
        CheckedExecutionParent::check_and_bind(&state, root, Some(&broken), CacheLimits::default())
            .unwrap();
    let (b, bo) = original(&state, root, Some(&broken), CacheLimits::default()).unwrap();
    equal(&a, &b);
    assert_eq!(ao, bo);
    assert_eq!(
        ao.method,
        CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch)
    );
    assert!(a.predecessor.is_none());
    assert!(broken.tree.is_empty());
    let mut changed = state.clone();
    changed.insert("binding:00000".into(), json!("changed"));
    assert_eq!(
        CheckedExecutionParent::check_and_bind(
            &changed,
            root,
            Some(&broken),
            CacheLimits::default()
        )
        .err(),
        Some("COMMITMENT_ROOT")
    );
    let changed_root = pon_executor::root(&changed).unwrap();
    let (a, ao) = CheckedExecutionParent::check_and_bind(
        &changed,
        changed_root,
        Some(&seed),
        CacheLimits::default(),
    )
    .unwrap();
    let (b, bo) = original(&changed, changed_root, Some(&seed), CacheLimits::default()).unwrap();
    equal(&a, &b);
    assert_eq!(ao, bo);
    assert_eq!(seed.root, root);
    assert_eq!(seed.values.as_ref(), &encode(&state).unwrap());
}

#[test]
fn checked_binding_actual_eight_mib_payload_fallback_keeps_all_bytes() {
    // Real default cache refusal, not a reduced protocol key/value bound.
    let state = fixture(4096, 2200);
    let root = pon_executor::root(&state).unwrap();
    let (a, ao) =
        CheckedExecutionParent::check_and_bind(&state, root, None, CacheLimits::default()).unwrap();
    let (b, bo) = original(&state, root, None, CacheLimits::default()).unwrap();
    equal(&a, &b);
    assert_eq!(ao, bo);
    assert!(ao.actual_payload_bytes > MAX_CACHE_PAYLOAD_BYTES);
    assert_eq!(
        ao.method,
        CommitmentMethod::FullRoot(FullRootReason::PayloadBudget)
    );
    assert!(a.predecessor.is_none());
    assert_eq!(a.actual.len(), state.len());
}

#[test]
#[ignore = "explicit same-operation binding cost; not Node or network throughput"]
fn checked_binding_complete_cost_observation() {
    use std::hint::black_box;
    use std::time::Instant;
    for (count, width, warm, refuse_cache) in [
        (1024, 16, false, false),
        (1024, 16, true, false),
        (1024, 16, false, true),
        (4096, 2200, false, false),
    ] {
        let state = fixture(count, width);
        let root = pon_executor::root(&state).unwrap();
        let seed = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
        let prior = if warm { seed.snapshot.as_ref() } else { None };
        let limits = if refuse_cache {
            CacheLimits {
                max_keys: 0,
                ..CacheLimits::default()
            }
        } else {
            CacheLimits::default()
        };
        for sample in 0..4 {
            for offset in 0..2 {
                let fused = (sample + offset) % 2 == 1;
                let start = Instant::now();
                let (bound, observation) = if fused {
                    CheckedExecutionParent::check_and_bind(black_box(&state), root, prior, limits)
                } else {
                    original(black_box(&state), root, prior, limits)
                }
                .unwrap();
                assert_eq!(bound.actual.len(), state.len());
                black_box(&bound);
                let method = format!("{:?}", observation.method);
                drop(bound);
                let elapsed_ns = start.elapsed().as_nanos();
                println!(
                    "{}",
                    json!({"schema":"checked-parent-single-binding-cost-v1","keys":count,"width":width,"warm":warm,
                     "forced_cache_refusal":refuse_cache,"sample":sample,"fused":fused,"elapsed_ns":elapsed_ns,"method":method,
                     "scope":"complete check+bind+drop; fixture and admitted root outside timer; not Node/WAN TPS"})
                );
            }
        }
    }
}
