//! Full fresh-State binding versus the retained full-map preparation path.
use super::*;
use serde_json::json;

// Pinned test-only implementations of both real comparison baselines.
// Function bodies are copied from the named Git sources, without algorithm
// substitutions; only module visibility changes. rustfmt skips these modules
// so their original body bytes remain auditable after removing one indent.
// Shared helper bodies and encoder/tree/wire sources were independently checked
// byte-identical across a10, 40a and the candidate before this v4 experiment.
// Full-map source: a10c39025cdc03d3265b031d6547b11e0350da2c
// Complete pon_commitment.rs SHA-256: 18ed1e6582e34bdbf9b2a376171fccf27fc59eff8b6786bd44dfd525b25e5c01
#[rustfmt::skip]
mod full_map_a10 {
    use super::*;

    pub(super) fn prepare_state_with_arithmetic(
        state: &State,
        prior: Option<&CheckedCommitment>,
        actual_before: Option<&CanonicalValues>,
        limits: CacheLimits,
        arithmetic: Option<&FullRootArithmetic>,
    ) -> Result<PreparedCommitment> {
        let (values, current) = encode_for_cache(state, limits)?;
        limits.validate()?;
        if let Some(values) = values {
            return prepare_values(values, prior, actual_before, limits);
        }
        let before = actual_before.or_else(|| prior.map(|p| p.values.as_ref()));
        let mut difference = DifferencePlan::default();
        if let Some(before) = before {
            visit_state_differences(before, state, |key, old, new| {
                difference.count = add(difference.count, 1)?;
                difference.payload = add(
                    difference.payload,
                    add(
                        key.len(),
                        add(old.map_or(0, Vec::len), new.map_or(0, Vec::len))?,
                    )?,
                )?;
                Ok(())
            })?;
        }
        let preceding = before.map(charges).transpose()?.unwrap_or(current);
        let workspace = workspace_charge(current, preceding, difference.count)?;
        let reason = fallback_reason(
            state.len(),
            current,
            workspace,
            prior.is_some(),
            difference.count,
            limits,
        )
        .ok_or("COMMITMENT_CHARGE")?;
        mark_stage("budget-selected");
        let root = match arithmetic {
            Some(arithmetic) => arithmetic.root(state),
            None => pon_executor::root(state),
        }?;
        mark_stage("full-root-completed");
        mark_stage("changes-allocation");
        let mut changes = Vec::with_capacity(difference.count);
        if let Some(before) = before {
            visit_state_differences(before, state, |key, old, new| {
                changes.push(Change {
                    key: key.to_vec(),
                    before: old.cloned(),
                    after: new.cloned(),
                });
                Ok(())
            })?;
        }
        debug_assert_eq!(changes.len(), difference.count);
        Ok(PreparedCommitment {
            root,
            snapshot: None,
            changes,
            observation: CommitmentObservation {
                method: CommitmentMethod::FullRoot(reason),
                actual_keys: state.len(),
                actual_payload_bytes: current.payload,
                changed_keys: difference.count,
                changed_payload_bytes: difference.payload,
                compressed_nodes: None,
                workspace_charge_bytes: workspace,
            },
        })
    }

    pub(super) fn checked_snapshot_with_optional_arithmetic(
        actual_state: &State,
        expected_root: Hash,
        prior: Option<&CheckedCommitment>,
        limits: CacheLimits,
        arithmetic: Option<&FullRootArithmetic>,
    ) -> Result<PreparedCommitment> {
        let prepared = prepare_state_with_arithmetic(actual_state, prior, None, limits, arithmetic)?;
        if prepared.root != expected_root {
            return Err("COMMITMENT_ROOT");
        }
        Ok(prepared)
    }
}

// Parent shared-map source: 40a5ba25e40fd5eda5b04fc1c3811320d438de11
// Complete pon_commitment.rs SHA-256: 8d1f455e74114346275b24b70c3656bc2adb7d316f40f64958c0733674f345b4
#[rustfmt::skip]
mod parent_40a {
    use super::*;
    use super::full_map_a10::prepare_state_with_arithmetic;

    pub(super) fn checked_snapshot_with_optional_arithmetic(
        actual_state: &State,
        expected_root: Hash,
        prior: Option<&CheckedCommitment>,
        limits: CacheLimits,
        arithmetic: Option<&FullRootArithmetic>,
    ) -> Result<PreparedCommitment> {
        // The freshly supplied root and key count select calculation material only.
        // A hit still canonically compares EVERY actual key/value below. Historical
        // transitions with a different root retain the original single encoding
        // pass; a misleading same-root hint takes that original path on mismatch.
        let unchanged = prior
            .filter(|previous| {
                previous.root == expected_root && previous.values.len() == actual_state.len()
            })
            .map(|previous| prepare_unchanged_snapshot(actual_state, previous, limits))
            .transpose()?
            .flatten();
        let prepared = match unchanged {
            Some(prepared) => prepared,
            None => prepare_state_with_arithmetic(actual_state, prior, None, limits, arithmetic)?,
        };
        if prepared.root != expected_root {
            return Err("COMMITMENT_ROOT");
        }
        Ok(prepared)
    }

    fn prepare_unchanged_snapshot(
        actual_state: &State,
        previous: &CheckedCommitment,
        limits: CacheLimits,
    ) -> Result<Option<PreparedCommitment>> {
        let Ok(current) = charges(&previous.values) else {
            return Ok(None);
        };
        let Ok(workspace) = workspace_charge(current, current, 0) else {
            return Ok(None);
        };
        if limits.validate().is_err()
            || fallback_reason(previous.keys(), current, workspace, true, 0, limits).is_some()
        {
            return Ok(None);
        }
        if !matches_unchanged_candidate(actual_state, &previous.values)? {
            return Ok(None);
        }
        mark_stage("budget-selected");
        let mut observation = CommitmentObservation {
            method: CommitmentMethod::CheckedApply,
            actual_keys: actual_state.len(),
            actual_payload_bytes: current.payload,
            changed_keys: 0,
            changed_payload_bytes: 0,
            compressed_nodes: Some(current.nodes),
            workspace_charge_bytes: workspace,
        };
        mark_stage("changes-allocation");
        let changes = Vec::new();
        mark_stage("tree-allocation");
        let tree = match previous.tree.apply(previous.root, &changes) {
            Ok(tree) => tree,
            Err(_) => {
                observation.method =
                    CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch);
                observation.compressed_nodes = None;
                return Ok(Some(PreparedCommitment {
                    root: state_root(&previous.values).map_err(|_| "LIMIT")?,
                    snapshot: None,
                    changes,
                    observation,
                }));
            }
        };
        let root = tree.root();
        Ok(Some(PreparedCommitment {
            root,
            snapshot: Some(CheckedCommitment {
                values: Arc::clone(&previous.values),
                tree,
                root,
                charges: current,
            }),
            changes,
            observation,
        }))
    }

    pub(super) fn matches_unchanged_candidate(state: &State, expected: &CanonicalValues) -> Result<bool> {
        if state.len() != expected.len() {
            return Ok(false);
        }
        let mut within_limits = state.len() <= 65_536;
        let mut previous = expected.iter();
        let mut actual = Vec::new();
        for (key, value) in state {
            let Some((old_key, old_value)) = previous.next() else {
                return Ok(false);
            };
            if key.as_bytes() != old_key {
                return Ok(false);
            }
            pon_executor::canonical_into(value, &mut actual)?;
            within_limits &= key.len() <= 160 && actual.len() <= 4096;
            if actual != *old_value {
                return Ok(false);
            }
        }
        if !within_limits {
            return Err("LIMIT");
        }
        Ok(true)
    }
}

use parent_40a::matches_unchanged_candidate;

fn fixture(count: usize, width: usize) -> State {
    (0..count)
        .map(|index| (format!("unchanged:{index:05}"), json!("x".repeat(width))))
        .collect()
}

// Bypass checked_snapshot's sharing selector. This is the original entry path,
// including every actual encoder allocation, budget decision and tree check.
fn original(
    state: &State,
    expected: Hash,
    prior: Option<&CheckedCommitment>,
    limits: CacheLimits,
    arithmetic: Option<&FullRootArithmetic>,
) -> Result<PreparedCommitment> {
    full_map_a10::checked_snapshot_with_optional_arithmetic(
        state, expected, prior, limits, arithmetic,
    )
}

fn equal(actual: &PreparedCommitment, reference: &PreparedCommitment) {
    assert_eq!(actual.root, reference.root);
    assert_eq!(actual.observation, reference.observation);
    let changes = |prepared: &PreparedCommitment| {
        prepared
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
    assert_eq!(actual.snapshot.is_some(), reference.snapshot.is_some());
    if let (Some(actual), Some(reference)) = (&actual.snapshot, &reference.snapshot) {
        assert_eq!(actual.values, reference.values);
        equal_capacities(&actual.values, &reference.values);
        assert_eq!(actual.tree.root(), reference.tree.root());
        assert_eq!(
            actual.retained_charge_bytes(),
            reference.retained_charge_bytes()
        );
    }
}

fn compare(
    state: &State,
    expected: Hash,
    prior: Option<&CheckedCommitment>,
    limits: CacheLimits,
    arithmetic: Option<&FullRootArithmetic>,
) -> Result<PreparedCommitment> {
    ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
    let reference = original(state, expected, prior, limits, arithmetic);
    let reference_stages = ALLOCATION_STAGES.with(|stages| stages.take());
    let actual =
        checked_snapshot_with_optional_arithmetic(state, expected, prior, limits, arithmetic);
    let actual_stages = ALLOCATION_STAGES.with(|stages| stages.take());
    assert_eq!(actual_stages, reference_stages);
    match (&actual, &reference) {
        (Ok(actual), Ok(reference)) => equal(actual, reference),
        (Err(actual), Err(reference)) => assert_eq!(actual, reference),
        _ => panic!("binding disagrees: actual={actual:?}, reference={reference:?}"),
    }
    actual
}

fn equal_capacities(actual: &CanonicalValues, reference: &CanonicalValues) {
    assert_eq!(actual.len(), reference.len());
    for ((actual_key, actual_value), (key, value)) in actual.iter().zip(reference) {
        assert_eq!(actual_key, key);
        assert_eq!(actual_value, value);
        assert_eq!(actual_key.capacity(), key.capacity());
        assert_eq!(actual_value.capacity(), value.capacity());
    }
}

fn same_charges(actual: Charges, reference: Charges) {
    assert_eq!(actual.payload, reference.payload);
    assert_eq!(actual.map, reference.map);
    assert_eq!(actual.tree, reference.tree);
    assert_eq!(actual.nodes, reference.nodes);
}

fn compare_encoder(state: &State, previous: &CanonicalValues, limits: CacheLimits) {
    let reference = encode_for_cache(state, limits);
    let actual = encode_for_cache_sharing(state, previous, limits);
    match (actual, reference) {
        (Ok((actual, charge)), Ok((reference, reference_charge))) => {
            same_charges(charge, reference_charge);
            match (actual, reference) {
                (Some(RetainedEncoding::Shared(prefix)), Some(reference)) => {
                    equal_capacities(previous, &reference);
                    assert_eq!(prefix.len(), reference.len());
                    for (encoded, reference) in prefix.iter().zip(reference.values()) {
                        assert_eq!(encoded, reference);
                        assert_eq!(encoded.capacity(), reference.capacity());
                    }
                }
                (Some(RetainedEncoding::Owned(actual)), Some(reference)) => {
                    equal_capacities(&actual, &reference);
                }
                (None, None) => (),
                _ => panic!("sharing encoder changed the original retention decision"),
            }
        }
        (Err(actual), Err(reference)) => assert_eq!(actual, reference),
        _ => panic!("sharing encoder changed the original canonical or wire error"),
    }
}

// Exercise preparation after a misleading hint without letting the enclosing
// expected-root error hide differences in changes, observations or allocation
// order. The production entry still compares its expected root afterward.
fn compare_preparation(
    state: &State,
    previous: &CheckedCommitment,
    limits: CacheLimits,
    arithmetic: Option<&FullRootArithmetic>,
) -> Result<PreparedCommitment> {
    compare_encoder(state, &previous.values, limits);
    ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
    let reference = full_map_a10::prepare_state_with_arithmetic(
        state,
        Some(previous),
        None,
        limits,
        arithmetic,
    );
    let reference_stages = ALLOCATION_STAGES.with(|stages| stages.take());
    let actual = prepare_snapshot_with_sharing(state, previous, limits, arithmetic);
    let actual_stages = ALLOCATION_STAGES.with(|stages| stages.take());
    assert_eq!(actual_stages, reference_stages);
    match (&actual, &reference) {
        (Ok(actual), Ok(reference)) => equal(actual, reference),
        (Err(actual), Err(reference)) => assert_eq!(actual, reference),
        _ => panic!("shared preparation disagrees: actual={actual:?}, reference={reference:?}"),
    }
    actual
}

fn copy_with_capacities(values: &CanonicalValues) -> CanonicalValues {
    values
        .iter()
        .map(|(key, value)| {
            let mut copied_key = Vec::with_capacity(key.capacity());
            copied_key.extend_from_slice(key);
            let mut copied_value = Vec::with_capacity(value.capacity());
            copied_value.extend_from_slice(value);
            (copied_key, copied_value)
        })
        .collect()
}

#[test]
fn unchanged_snapshot_shares_only_after_full_actual_bytes_match() {
    for state in [State::new(), fixture(1, 0), fixture(257, 512)] {
        let limits = CacheLimits::default();
        let root = pon_executor::root(&state).unwrap();
        let seed = original(&state, root, None, limits, None)
            .unwrap()
            .snapshot
            .unwrap();
        let independent_state = state.clone();
        for actual in [&state, &independent_state] {
            let prepared = compare(actual, root, Some(&seed), limits, None).unwrap();
            let snapshot = prepared.snapshot.as_ref().unwrap();
            assert!(Arc::ptr_eq(&snapshot.values, &seed.values));
            assert_eq!(prepared.observation.changed_keys, 0);
            assert_eq!(prepared.observation.method, CommitmentMethod::CheckedApply);
            let prior_path = original(actual, root, Some(&seed), limits, None).unwrap();
            assert!(!Arc::ptr_eq(
                &prior_path.snapshot.unwrap().values,
                &seed.values
            ));
        }
        assert_eq!(seed.values.as_ref(), &encode(&state).unwrap());
    }
}

#[test]
fn unchanged_snapshot_retains_exact_capacity_charges_and_all_budget_boundaries() {
    // Include canonical encoder growth boundaries and nested/escaped values.
    let mut state: State = [0, 1, 126, 127, 128, 129, 4080, 4094]
        .into_iter()
        .enumerate()
        .map(|(index, width)| (format!("capacity:{index}"), json!("x".repeat(width))))
        .collect();
    state.insert("nested".into(), json!({"array":[1,true,null,"a\"b\\c\n"]}));
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, CacheLimits::default(), None)
        .unwrap()
        .snapshot
        .unwrap();
    let current = charges(&seed.values).unwrap();
    let workspace = workspace_charge(current, current, 0).unwrap();
    let arithmetic = FullRootArithmetic::default();
    for keys in [state.len() - 1, state.len(), state.len() + 1] {
        for payload in [current.payload - 1, current.payload, current.payload + 1] {
            for bound in [workspace - 1, workspace, workspace + 1] {
                let limits = CacheLimits {
                    max_keys: keys,
                    max_payload_bytes: payload,
                    max_workspace_charge_bytes: bound,
                };
                for arithmetic in [None, Some(&arithmetic)] {
                    let prepared = compare(&state, root, Some(&seed), limits, arithmetic).unwrap();
                    if let Some(snapshot) = prepared.snapshot {
                        assert!(Arc::ptr_eq(&snapshot.values, &seed.values));
                    }
                }
            }
        }
    }
    for limits in [
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
        assert!(
            compare(&state, root, Some(&seed), limits, Some(&arithmetic))
                .unwrap()
                .snapshot
                .is_none()
        );
    }
}

#[test]
fn unchanged_snapshot_misleading_root_and_changed_bytes_take_original_repair_path() {
    let state = fixture(8, 32);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let arithmetic = FullRootArithmetic::default();
    for key in ["unchanged:00000", "unchanged:00007"] {
        let mut changed = state.clone();
        changed.insert(key.into(), json!("y".repeat(32)));
        assert_eq!(
            compare(&changed, root, Some(&seed), limits, Some(&arithmetic)).unwrap_err(),
            "COMMITMENT_ROOT"
        );
        let changed_root = pon_executor::root(&changed).unwrap();
        let updated = compare(&changed, changed_root, Some(&seed), limits, None).unwrap();
        assert_eq!(updated.observation.changed_keys, 1);
        assert!(!Arc::ptr_eq(
            &updated.snapshot.unwrap().values,
            &seed.values
        ));
        // Even an internally damaged matching root is only a hint. Actual bytes
        // differ; the original path checks/repairs the inconsistent prior tree.
        let mut misleading = seed.clone();
        misleading.root = changed_root;
        let repaired = compare(&changed, changed_root, Some(&misleading), limits, None).unwrap();
        assert_eq!(
            repaired.observation.method,
            CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch)
        );
        assert!(repaired.snapshot.is_none());
    }
    let mut inserted = state.clone();
    inserted.insert("new".into(), json!(1));
    assert_eq!(
        compare(&inserted, root, Some(&seed), limits, None).unwrap_err(),
        "COMMITMENT_ROOT"
    );
    compare(
        &inserted,
        pon_executor::root(&inserted).unwrap(),
        Some(&seed),
        limits,
        None,
    )
    .unwrap();
    let mut removed = state.clone();
    removed.remove("unchanged:00000");
    compare(
        &removed,
        pon_executor::root(&removed).unwrap(),
        Some(&seed),
        limits,
        None,
    )
    .unwrap();
    assert_eq!(seed.values.as_ref(), &encode(&state).unwrap());
    assert!(Arc::ptr_eq(
        &compare(&state, root, Some(&seed), limits, None)
            .unwrap()
            .snapshot
            .unwrap()
            .values,
        &seed.values
    ));
}

#[test]
fn unchanged_snapshot_keeps_late_canonical_errors_before_wire_and_cache_limits() {
    let state = fixture(4, 8);
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, CacheLimits::default(), None)
        .unwrap()
        .snapshot
        .unwrap();
    let invalid = CacheLimits {
        max_keys: MAX_CACHE_KEYS + 1,
        ..CacheLimits::default()
    };
    for limits in [CacheLimits::default(), invalid] {
        for expected in [root, [9; 32]] {
            let mut changed = state.clone();
            changed.insert("unchanged:00000".into(), json!("x".repeat(4095)));
            assert_eq!(
                compare(&changed, expected, Some(&seed), limits, None).unwrap_err(),
                "LIMIT"
            );
            for (malformed, error) in [(json!("非ASCII"), "NONCANONICAL"), (json!(1.5), "RANGE")] {
                changed.insert("unchanged:00003".into(), malformed);
                assert_eq!(
                    compare(&changed, expected, Some(&seed), limits, None).unwrap_err(),
                    error
                );
            }
            let mut long_key = state.clone();
            let value = long_key.remove("unchanged:00000").unwrap();
            long_key.insert("z".repeat(161), value);
            assert_eq!(
                compare(&long_key, expected, Some(&seed), limits, None).unwrap_err(),
                "LIMIT"
            );
        }
    }
    assert_eq!(
        compare(&state, root, Some(&seed), invalid, None).unwrap_err(),
        "COMMITMENT_CACHE_LIMIT"
    );
    assert_eq!(
        compare(&state, [9; 32], Some(&seed), CacheLimits::default(), None).unwrap_err(),
        "COMMITMENT_ROOT"
    );
}

#[test]
fn unchanged_candidate_early_miss_retains_complete_late_validation() {
    let state = fixture(4, 8);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let check = |actual: &State, expected_error| {
        // The candidate deliberately stops before reaching the late error.
        // Its miss is not an acceptance/rejection decision: the public entry
        // must still return the original complete preparation's final error.
        assert!(!matches_unchanged_candidate(actual, &seed.values).unwrap());
        assert_eq!(
            compare(actual, root, Some(&seed), limits, None).unwrap_err(),
            expected_error
        );
    };
    let mut actual = state.clone();
    actual.insert("unchanged:00000".into(), json!("y".repeat(8)));
    for (late, error) in [
        (json!("非ASCII"), "NONCANONICAL"),
        (json!(1.5), "RANGE"),
        (json!("x".repeat(4095)), "LIMIT"),
    ] {
        actual.insert("unchanged:00003".into(), late);
        check(&actual, error);
    }
    actual.remove("unchanged:00003");
    actual.insert("z".repeat(161), json!(0));
    check(&actual, "LIMIT");
    actual.insert("unchanged:00002".into(), json!("非ASCII"));
    check(&actual, "NONCANONICAL");

    let mut key_mismatch = state.clone();
    let value = key_mismatch.remove("unchanged:00000").unwrap();
    key_mismatch.insert("early-key-mismatch".into(), value);
    key_mismatch.insert("unchanged:00002".into(), json!("x".repeat(4095)));
    key_mismatch.insert("unchanged:00003".into(), json!(1.5));
    check(&key_mismatch, "RANGE");

    // With no earlier difference, a candidate cannot hide a late canonical error.
    let mut late_only = state.clone();
    late_only.insert("unchanged:00003".into(), json!("非ASCII"));
    assert_eq!(
        matches_unchanged_candidate(&late_only, &seed.values).unwrap_err(),
        "NONCANONICAL"
    );
    assert_eq!(
        compare(&late_only, root, Some(&seed), limits, None).unwrap_err(),
        "NONCANONICAL"
    );
}

#[test]
fn unchanged_snapshot_empty_delta_still_checks_the_original_tree_root() {
    let state = fixture(17, 64);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let mut broken = seed.clone();
    broken.tree = StateTree::default();
    let prepared = compare(&state, root, Some(&broken), limits, None).unwrap();
    assert_eq!(
        prepared.observation.method,
        CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch)
    );
    assert!(prepared.snapshot.is_none());
    assert!(broken.tree.is_empty());
    assert_eq!(broken.values, seed.values);
    let (bound, observation) =
        CheckedExecutionParent::check_and_bind(&state, root, Some(&seed), limits).unwrap();
    assert!(std::ptr::eq(bound.state, &state));
    assert!(Arc::ptr_eq(&bound.actual, &seed.values));
    assert_eq!(observation.method, CommitmentMethod::CheckedApply);
}

#[test]
fn shared_encoding_first_middle_and_last_mismatches_keep_original_preparation() {
    let state = fixture(17, 129);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let arithmetic = FullRootArithmetic::default();
    for index in [0, 8, 16] {
        for width in [0, 127, 129, 512, 4094] {
            let mut changed = state.clone();
            changed.insert(format!("unchanged:{index:05}"), json!("y".repeat(width)));
            let (encoding, _) = encode_for_cache_sharing(&changed, &seed.values, limits).unwrap();
            assert!(matches!(encoding, Some(RetainedEncoding::Owned(_))));
            for budget in [
                limits,
                CacheLimits {
                    max_payload_bytes: seed.payload_bytes(),
                    ..limits
                },
                CacheLimits {
                    max_workspace_charge_bytes: 0,
                    ..limits
                },
            ] {
                compare_preparation(&changed, &seed, budget, Some(&arithmetic)).unwrap();
                assert_eq!(
                    compare(&changed, root, Some(&seed), budget, None).unwrap_err(),
                    "COMMITMENT_ROOT"
                );
            }
        }
        // Equal-sized key sets can differ at any position, independently of
        // value equality. Copy only the preceding rows verified in this call.
        let mut changed_key = state.clone();
        let old_key = format!("unchanged:{index:05}");
        let value = changed_key.remove(&old_key).unwrap();
        changed_key.insert(format!("{old_key}x"), value);
        compare_preparation(&changed_key, &seed, limits, None).unwrap();
    }
}

#[test]
fn shared_encoding_deep_cloned_shrunk_and_grown_capacities_keep_exact_budgets() {
    let state = fixture(17, 64);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let current = charges(&seed.values).unwrap();
    let ordinary_clone = seed.clone();
    assert!(Arc::ptr_eq(&ordinary_clone.values, &seed.values));
    equal_capacities(&ordinary_clone.values, &seed.values);

    let shrunk = seed.values.as_ref().clone();
    assert!(shrunk
        .iter()
        .zip(seed.values.iter())
        .any(|((_, a), (_, b))| a.capacity() < b.capacity()));
    let mut last_value_shrunk = copy_with_capacities(&seed.values);
    last_value_shrunk
        .last_entry()
        .unwrap()
        .get_mut()
        .shrink_to_fit();
    let mut last_value_grown = copy_with_capacities(&seed.values);
    let mut last = last_value_grown.last_entry().unwrap();
    let larger = last.get().capacity() + 17;
    last.get_mut().reserve_exact(larger);
    let mut last_key_grown = copy_with_capacities(&seed.values);
    let (mut key, value) = last_key_grown.pop_last().unwrap();
    key.reserve_exact(64);
    last_key_grown.insert(key, value);

    for values in [shrunk, last_value_shrunk, last_value_grown, last_key_grown] {
        let mut altered = seed.clone();
        altered.values = Arc::new(values);
        let preceding = charges(&altered.values).unwrap();
        let workspace = workspace_charge(current, preceding, 0).unwrap();
        let (encoding, _) = encode_for_cache_sharing(&state, &altered.values, limits).unwrap();
        assert!(matches!(encoding, Some(RetainedEncoding::Owned(_))));
        for bound in [workspace - 1, workspace, workspace + 1] {
            let budget = CacheLimits {
                max_workspace_charge_bytes: bound,
                ..limits
            };
            let prepared = compare(&state, root, Some(&altered), budget, None).unwrap();
            if let Some(snapshot) = prepared.snapshot {
                assert!(!Arc::ptr_eq(&snapshot.values, &altered.values));
                equal_capacities(&snapshot.values, &seed.values);
            }
        }
        equal_capacities(&seed.values, &encode(&state).unwrap());
    }
    // The old cached charge fields are not authority for this call's budget.
    let mut wrong_charge = seed.clone();
    wrong_charge.charges = Charges {
        payload: 0,
        map: 0,
        tree: 0,
        nodes: 0,
    };
    compare(&state, root, Some(&wrong_charge), limits, None).unwrap();
}

#[test]
fn shared_encoding_suffix_errors_and_discard_keep_original_error_priority() {
    let state = fixture(17, 129);
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let arithmetic = FullRootArithmetic::default();
    for budget in [
        limits,
        CacheLimits {
            max_payload_bytes: 1,
            ..limits
        },
        CacheLimits {
            max_payload_bytes: seed.payload_bytes() / 2,
            ..limits
        },
        CacheLimits {
            max_keys: 0,
            ..limits
        },
        CacheLimits {
            max_workspace_charge_bytes: 0,
            ..limits
        },
        CacheLimits {
            max_keys: MAX_CACHE_KEYS + 1,
            ..limits
        },
    ] {
        for index in [0, 8, 15] {
            let mut changed = state.clone();
            changed.insert(format!("unchanged:{index:05}"), json!("y".repeat(129)));
            for (value, expected) in [
                (json!("z".repeat(4095)), "LIMIT"),
                (json!(1.5), "RANGE"),
                (json!({"nested":["非ASCII"]}), "NONCANONICAL"),
            ] {
                changed.insert("unchanged:00016".into(), value);
                assert_eq!(
                    compare_preparation(&changed, &seed, budget, Some(&arithmetic)).unwrap_err(),
                    expected
                );
            }
            // A later grammar error still outranks an earlier oversized value,
            // even after the original incremental budget rule discarded maps.
            changed.insert(format!("unchanged:{index:05}"), json!("z".repeat(4095)));
            changed.insert("unchanged:00016".into(), json!(1.5));
            assert_eq!(
                compare(&changed, root, Some(&seed), budget, None).unwrap_err(),
                "RANGE"
            );
        }
    }
}

#[test]
fn shared_encoding_empty_state_keeps_the_final_workspace_fallback() {
    let state = State::new();
    let limits = CacheLimits::default();
    let root = pon_executor::root(&state).unwrap();
    let seed = original(&state, root, None, limits, None)
        .unwrap()
        .snapshot
        .unwrap();
    let current = charges(&seed.values).unwrap();
    let workspace = workspace_charge(current, current, 0).unwrap();
    let arithmetic = FullRootArithmetic::default();
    for bound in [0, workspace - 1, workspace, workspace + 1] {
        let budget = CacheLimits {
            max_keys: 0,
            max_payload_bytes: 0,
            max_workspace_charge_bytes: bound,
        };
        for arithmetic in [None, Some(&arithmetic)] {
            let prepared = compare(&state, root, Some(&seed), budget, arithmetic).unwrap();
            assert_eq!(prepared.snapshot.is_some(), bound >= workspace);
        }
    }
}

#[test]
fn shared_encoding_prefix_slots_fit_the_original_workspace_reservation() {
    let limits = CacheLimits::default();
    for count in [0, 1, 2, 3, 4, 17, 257, MAX_CACHE_KEYS] {
        let state = fixture(count, 0);
        let (original, original_charge) = encode_for_cache(&state, limits).unwrap();
        let original = original.unwrap();
        let (encoded, charge) = encode_for_cache_sharing(&state, &original, limits).unwrap();
        same_charges(charge, original_charge);
        let Some(RetainedEncoding::Shared(prefix)) = encoded else {
            panic!("equal encodings must keep the share candidate");
        };
        assert_eq!(prefix.len(), count);
        assert!(prefix.capacity() >= count);
        if count == 0 {
            assert_eq!(prefix.capacity(), 0);
        }
        // Observe the actual Vec capacity on this target, rather than treating
        // reserve_exact's requested minimum as an allocator size guarantee.
        let observed_slots = prefix.capacity() * std::mem::size_of::<Vec<u8>>();
        assert!(observed_slots <= count * MAP_ENTRY_CHARGE);
        let fresh_capacities = prefix.iter().map(Vec::capacity).sum::<usize>()
            + state.keys().map(String::len).sum::<usize>();
        assert_eq!(fresh_capacities + count * MAP_ENTRY_CHARGE, charge.map);
        // Current encoding payload is unique during transfer; the slot array
        // fits another map reservation already present in the original charge.
        // This is not a bound on allocator overhead or preceding live objects.
        let current_material = charge.map + observed_slots;
        assert!(current_material <= 2 * charge.map);
        assert!(current_material <= workspace_charge(charge, charge, 0).unwrap());
    }

    // A singleton exposes the original first-row guard exactly. Below it no
    // prefix survives; at it both encoders retain the same fresh capacities.
    let state = fixture(1, 129);
    let (original, charge) = encode_for_cache(&state, limits).unwrap();
    let original = original.unwrap();
    let bound = workspace_charge(charge, charge, 0).unwrap();
    for workspace in [0, bound - 1, bound, bound + 1] {
        let budget = CacheLimits {
            max_workspace_charge_bytes: workspace,
            ..limits
        };
        compare_encoder(&state, &original, budget);
        let (encoded, actual_charge) = encode_for_cache_sharing(&state, &original, budget).unwrap();
        same_charges(actual_charge, charge);
        assert_eq!(encoded.is_some(), workspace >= bound);
    }
}

#[test]
fn shared_encoding_materializes_fresh_prefix_without_reallocating_values() {
    let state = fixture(257, 129);
    let limits = CacheLimits::default();
    let (original, _) = encode_for_cache(&state, limits).unwrap();
    let original = original.unwrap();
    for count in [0, 1, 16, 17, 256, 257] {
        let (encoded, _) = encode_for_cache_sharing(&state, &original, limits).unwrap();
        let Some(RetainedEncoding::Shared(mut prefix)) = encoded else {
            panic!("equal encodings must keep the share candidate");
        };
        prefix.truncate(count);
        let allocations: Vec<_> = prefix
            .iter()
            .map(|value| (value.as_ptr(), value.capacity()))
            .collect();
        let values = materialize_shared_prefix(&original, prefix);
        assert_eq!(values.len(), count);
        for (((key, value), (old_key, old_value)), (pointer, capacity)) in
            values.iter().zip(original.iter()).zip(allocations)
        {
            assert_eq!(key, old_key);
            assert_eq!(key.capacity(), old_key.capacity());
            assert_eq!(value, old_value);
            assert_eq!(value.as_ptr(), pointer);
            assert_eq!(value.capacity(), capacity);
            assert_ne!(value.as_ptr(), old_value.as_ptr());
        }
    }
}

#[test]
#[ignore = "explicit paired component cost, including adversarial same-root hints; no throughput qualification"]
fn unchanged_snapshot_full_binding_cost() {
    use sha2::{Digest, Sha256};
    use std::hint::black_box;
    use std::time::Instant;
    let limits = CacheLimits::default();
    // Fix all six permutations before running any v4 sample. Each occurs twice;
    // each arm occupies each position four times and precedes each peer six times.
    let order = [
        [0, 1, 2],
        [2, 1, 0],
        [1, 2, 0],
        [0, 2, 1],
        [2, 0, 1],
        [1, 0, 2],
    ];
    let decision = json!({
        "schema": "unchanged-snapshot-three-arm-decision-v1",
        "primary_targets": [
            {
                "reference": "parent_40a_shared_map_ns",
                "case": "same_root_hint_last_value_changed",
                "state_keys": [
                    128,
                    1024,
                    4096
                ],
                "minimum_paired_median_improvement_fraction": 0.05
            },
            {
                "reference": "original_full_map_ns",
                "case": "unchanged",
                "state_keys": [
                    128,
                    1024,
                    4096
                ],
                "minimum_paired_median_improvement_fraction": 0.05
            }
        ],
        "candidate": "checked_shared_map_ns",
        "all_nine_cells_against_each_reference_required": true,
        "maximum_paired_median_regression_fraction": 0.1,
        "maximum_p95_regression_fraction": 0.1,
        "paired_median_definition": "median of round-matched (reference_ns - candidate_ns) / reference_ns; midpoint of central two values for twelve samples",
        "p95_definition": "nearest rank ceil(0.95 * N); N=12 gives order statistic twelve, the maximum; no confidence or full-chain latency claim",
        "maximum_missing_or_unexpected_result_bindings": 0,
        "expected_results": {
            "unchanged": "Ok with expected root",
            "same_root_hint_first_value_changed": "COMMITMENT_ROOT",
            "same_root_hint_last_value_changed": "COMMITMENT_ROOT"
        },
        "no_cell_aggregation_or_sample_exclusion": true,
        "physical_memory_qualification": false,
        "public_business_gate_replaced": false
    });
    let source_identity = json!({
        "original_full_map_commit":"a10c39025cdc03d3265b031d6547b11e0350da2c",
        "parent_shared_map_commit":"40a5ba25e40fd5eda5b04fc1c3811320d438de11",
        "original_reference_source_sha256":"18ed1e6582e34bdbf9b2a376171fccf27fc59eff8b6786bd44dfd525b25e5c01",
        "parent_reference_source_sha256":"8d1f455e74114346275b24b70c3656bc2adb7d316f40f64958c0733674f345b4",
        "compiled_production_source_sha256":hex::encode(Sha256::digest(include_bytes!("../pon_commitment.rs"))),
        "compiled_test_source_sha256":hex::encode(Sha256::digest(include_bytes!("unchanged_snapshot_tests.rs"))),
        "scope":"pinned old function bodies in one current test binary; identical shared helpers, canonical encoder, tree and wire source"
    });
    for (keys, width) in [(128, 64), (1024, 512), (4096, 512)] {
        let state = fixture(keys, width);
        let root = pon_executor::root(&state).unwrap();
        let seed = original(&state, root, None, limits, None)
            .unwrap()
            .snapshot
            .unwrap();
        let mut first_mismatch = state.clone();
        first_mismatch.insert("unchanged:00000".into(), json!("y".repeat(width)));
        let mut last_mismatch = state.clone();
        last_mismatch.insert(
            format!("unchanged:{:05}", keys - 1),
            json!("y".repeat(width)),
        );
        for (case, actual) in [
            ("unchanged", &state),
            ("same_root_hint_first_value_changed", &first_mismatch),
            ("same_root_hint_last_value_changed", &last_mismatch),
        ] {
            let reference = original(actual, root, Some(&seed), limits, None);
            let parent = parent_40a::checked_snapshot_with_optional_arithmetic(
                actual,
                root,
                Some(&seed),
                limits,
                None,
            );
            let checked = checked_snapshot(actual, root, Some(&seed), limits);
            for result in [&parent, &checked] {
                match (&reference, result) {
                    (Ok(reference), Ok(result)) => equal(result, reference),
                    (Err(reference), Err(result)) => assert_eq!(result, reference),
                    _ => panic!("component arms disagree"),
                }
            }
            let mut samples: [Vec<u128>; 3] = [Vec::new(), Vec::new(), Vec::new()];
            let mut expected_returns = [0usize; 3];
            let mut unexpected_returns = [0usize; 3];
            for sample in 0..12 {
                for arm in order[sample % order.len()] {
                    let start = Instant::now();
                    for _ in 0..8 {
                        let result = match arm {
                            0 => original(black_box(actual), root, Some(&seed), limits, None),
                            1 => parent_40a::checked_snapshot_with_optional_arithmetic(
                                black_box(actual),
                                root,
                                Some(&seed),
                                limits,
                                None,
                            ),
                            2 => checked_snapshot(black_box(actual), root, Some(&seed), limits),
                            _ => unreachable!(),
                        };
                        let expected = match &result {
                            Ok(prepared) => case == "unchanged" && prepared.root == root,
                            Err(error) => case != "unchanged" && *error == "COMMITMENT_ROOT",
                        };
                        if expected {
                            expected_returns[arm] += 1;
                        } else {
                            unexpected_returns[arm] += 1;
                        }
                        drop(black_box(result));
                    }
                    samples[arm].push(start.elapsed().as_nanos());
                }
            }
            println!(
                "{}",
                json!({
                    "schema":"unchanged-snapshot-full-binding-cost-v4",
                    "case":case, "state_keys":keys, "value_width":width,
                    "bindings_per_sample":8, "samples_per_arm":12,
                    "original_full_map_ns":samples[0],
                    "parent_40a_shared_map_ns":samples[1],
                    "checked_shared_map_ns":samples[2],
                    "order":"fixed six-permutation rotation repeated twice",
                    "arm_order_per_six_rounds":order,
                    "arm_names":["original_full_map_ns","parent_40a_shared_map_ns","checked_shared_map_ns"],
                    "expected_returns_per_arm":expected_returns,
                    "unexpected_returns_per_arm":unexpected_returns,
                    "equal_result":unexpected_returns == [0; 3],
                    "decision":decision, "source_identity":source_identity,
                    "complete_actual_state_compared":true, "expected_root_checked":true,
                    "tree_empty_delta_check_retained":true,
                    "mismatch_path":"one fresh encoding pass; move fresh verified prefix values with exact original capacities; sequential map insertion",
                    "parent_mismatch_path":"40a candidate stops at first mismatch; pinned original full-map preparation rechecks all actual rows",
                    "scope":"full component binding, constant-time result classification and output destruction; unchanged cache limits; all planned failure returns retained",
                    "public_tps_measured":false, "node_owner_measured":false,
                    "physical_memory_bound":false
                })
            );
            assert_eq!(expected_returns, [12 * 8; 3]);
            assert_eq!(unexpected_returns, [0; 3]);
        }
    }
}
