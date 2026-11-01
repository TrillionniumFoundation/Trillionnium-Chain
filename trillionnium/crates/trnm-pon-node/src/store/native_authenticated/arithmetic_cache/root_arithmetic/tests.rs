use super::*;
use serde_json::json;

fn settings() -> Settings {
    Settings::development(Some(1000)).unwrap()
}
fn snapshot(state: &State) -> CheckedCommitment {
    let prepared = pon_commitment::derive_snapshot(state, None, CacheLimits::default()).unwrap();
    assert_eq!(prepared.root, pon_executor::root(state).unwrap());
    prepared.snapshot.unwrap()
}
fn equal(cache: &RootArithmetic, settings: &Settings, actual: &State) {
    assert_eq!(
        cache.calculate(settings, actual),
        pon_executor::root(actual)
    );
}

#[test]
fn opaque_tree_recomputes_actual_additions_removals_values_and_namespace() {
    let settings = settings();
    let cache = RootArithmetic::default();
    let mut state = settings.initial.clone();
    let seed = snapshot(&state);
    cache.offer(&settings, Some(&seed));
    equal(&cache, &settings, &state);
    assert_eq!(cache.counters.get().derived_checked_apply, 1);
    assert_eq!(cache.counters.get().actual_changed_keys, 0);
    let owner = format!("account:{}", "93".repeat(32));
    state.insert(owner.clone(), json!({"balance":0,"nonce":7}));
    equal(&cache, &settings, &state);
    state.insert(owner.clone(), json!({"balance":0,"nonce":8}));
    equal(&cache, &settings, &state);
    state.insert("current-root-claim".into(), json!(hex::encode(seed.root())));
    equal(&cache, &settings, &state);
    state.remove(&owner);
    equal(&cache, &settings, &state);
    state.remove("current-root-claim");
    equal(&cache, &settings, &state);
    assert_eq!(state, settings.initial);
    assert_eq!(cache.counters.get().actual_changed_keys, 5);
    // Same bytes under each changed namespace component may not select the
    // previous context's material, even though this root grammar is unkeyed.
    for component in 0..3 {
        let mut foreign = settings.clone();
        match component {
            0 => foreign.app.network[0] ^= 1,
            1 => foreign.app.parameters[0] ^= 1,
            _ => foreign.genesis[0] ^= 1,
        }
        let before = cache.counters.get();
        equal(&cache, &foreign, &state);
        let after = cache.counters.get();
        assert_eq!(after.context_misses, before.context_misses + 1);
        assert_eq!(after.material_uses, before.material_uses);
        assert_eq!(after.cold_roots, before.cold_roots + 1);
    }
    // A mathematically valid tree for different actual values remains only a
    // hint. It cannot return its old root for the caller's current complete State.
    cache.offer(&settings, Some(&seed));
    state.insert("untrusted-current-metadata".into(), json!([1, 2, 3]));
    assert_ne!(pon_executor::root(&state).unwrap(), seed.root());
    equal(&cache, &settings, &state);
}

#[test]
fn opaque_tree_preserves_original_canonical_and_limit_errors() {
    let settings = settings();
    let cache = RootArithmetic::default();
    let initial = snapshot(&settings.initial);
    cache.offer(&settings, Some(&initial));
    for number in [json!(0), json!(0.0), json!(-0.0), json!(u64::MAX)] {
        let mut state = settings.initial.clone();
        state.insert("arithmetic-number".into(), number);
        equal(&cache, &settings, &state);
    }
    for (key, value) in [
        ("a".repeat(161), json!(0)),
        ("z".into(), json!("x".repeat(4097))),
        ("a".repeat(161), json!(-0.0)),
    ] {
        let mut state = settings.initial.clone();
        state.insert(key, value);
        assert!(pon_executor::root(&state).is_err());
        equal(&cache, &settings, &state);
        // A later canonical error still wins over an earlier wire limit.
        state.insert("zz-canonical-failure".into(), json!(-0.0));
        assert_eq!(pon_executor::root(&state), Err("RANGE"));
        equal(&cache, &settings, &state);
    }
    assert!(cache.counters.get().original_error_fallbacks >= 8);
    equal(&cache, &settings, &settings.initial);
}

#[test]
fn opaque_tree_retention_caps_payload_charge_and_preserves_cold_borrow_behavior() {
    let settings = settings();
    let cache = RootArithmetic::default();
    let initial = snapshot(&settings.initial);
    cache.offer(&settings, Some(&initial));
    let guard = cache.material.borrow_mut();
    let before = cache.counters.get();
    equal(&cache, &settings, &settings.initial);
    cache.offer(&settings, Some(&initial));
    assert_eq!(cache.counters.get().cold_roots, before.cold_roots + 1);
    assert_eq!(cache.counters.get().offers_retained, before.offers_retained);
    assert_eq!(
        cache.counters.get().offers_borrow_conflicts,
        before.offers_borrow_conflicts + 1
    );
    assert_eq!(
        cache.observation()["retention_observation_available"],
        false
    );
    drop(guard);
    for state in [
        // 512 canonical string values of exactly 4096 bytes plus keys cross
        // the 2 MiB payload cap without violating any original wire row limit.
        (0..512)
            .map(|n| (format!("payload-{n:04}"), json!("x".repeat(4094))))
            .collect::<State>(),
        // Conservative map/tree charge, not payload, independently crosses 16 MiB.
        (0..11_000)
            .map(|n| (format!("charge-{n:05}"), json!(0)))
            .collect::<State>(),
    ] {
        let offered = snapshot(&state);
        assert!(
            offered.payload_bytes() > MAX_PAYLOAD_BYTES
                || offered.retained_charge_bytes() + ENTRY_CHARGE > MAX_RETAINED_CHARGE_BYTES
        );
        // Canonical material retains the original refusal/eviction behavior.
        // The separate partition-material case is exercised below.
        cache.offer(&settings, Some(&initial));
        let before = cache.counters.get();
        cache.offer(&settings, Some(&offered));
        assert!(cache.material.borrow().is_none());
        equal(&cache, &settings, &settings.initial);
        assert_eq!(cache.counters.get().cold_roots, before.cold_roots + 1);
    }
    cache.offer(&settings, Some(&initial));
    let guard = cache.material.borrow();
    let retained = guard.as_ref().unwrap();
    assert!(retained.payload_bytes() <= MAX_PAYLOAD_BYTES);
    assert!(retained.charged <= MAX_RETAINED_CHARGE_BYTES);
    let before = cache.counters.get();
    cache.offer(&settings, None);
    // The immutable borrow above intentionally prevents replacing optional
    // arithmetic; it cannot make a calculation trust any foreign stored bytes.
    assert_eq!(
        cache.counters.get().offers_borrow_conflicts,
        before.offers_borrow_conflicts + 1
    );
    drop(guard);
    cache.offer(&settings, None);
    assert!(cache.material.borrow().is_none());
    equal(&cache, &settings, &settings.initial);
}

#[test]
fn refused_offers_preserve_only_same_context_complete_input_partition_arithmetic() {
    let settings = settings();
    let cache = RootArithmetic::default();
    let mut state: State = (0..600)
        .map(|n| (format!("large-partition-{n:04}"), json!("x".repeat(4094))))
        .collect();
    let oversized = snapshot(&state);
    assert!(oversized.payload_bytes() > MAX_PAYLOAD_BYTES);
    equal(&cache, &settings, &state);

    for offer in [None, Some(&oversized)] {
        let before = cache.counters.get();
        let retained_before = cache.material.borrow().as_ref().unwrap().charged;
        cache.offer(&settings, offer);
        let retained = cache.material.borrow();
        let material = retained.as_ref().unwrap();
        assert!(matches!(&material.source, MaterialSource::Partitions(_)));
        assert_eq!(material.charged, retained_before);
        assert!(material.payload_bytes() <= MAX_PAYLOAD_BYTES);
        assert!(material.charged <= MAX_RETAINED_CHARGE_BYTES);
        drop(retained);
        equal(&cache, &settings, &state);
        let after = cache.counters.get();
        assert_eq!(
            after.offers_preserved_partitions,
            before.offers_preserved_partitions + 1
        );
        assert_eq!(after.cold_roots, before.cold_roots);
        assert_eq!(
            after.partition_roots_computed,
            before.partition_roots_computed
        );
        assert_eq!(
            after.partition_inputs_hashed,
            before.partition_inputs_hashed + state.len() as u64
        );
        assert!(after.partition_roots_reused > before.partition_roots_reused);
    }

    // A refused offer never promises an unchanged State. All changed, removed
    // and added actual rows still determine the independent original root.
    let initial_root = pon_executor::root(&state).unwrap();
    state.insert("large-partition-0001".into(), json!("y".repeat(4094)));
    cache.offer(&settings, None);
    equal(&cache, &settings, &state);
    assert_ne!(pon_executor::root(&state).unwrap(), initial_root);
    state.remove("large-partition-0002");
    equal(&cache, &settings, &state);
    state.insert("new-current-row".into(), json!([1, 2, 3]));
    equal(&cache, &settings, &state);

    // Preserve complete grammar before wire-limit order even after retention.
    let oversized_key = "a".repeat(161);
    state.insert(oversized_key.clone(), json!(0));
    state.insert("zz-invalid-number".into(), json!(-0.0));
    cache.offer(&settings, None);
    assert_eq!(pon_executor::root(&state), Err("RANGE"));
    equal(&cache, &settings, &state);
    state.remove("zz-invalid-number");
    assert_eq!(pon_executor::root(&state), Err("LIMIT"));
    equal(&cache, &settings, &state);
    state.remove(&oversized_key);
    equal(&cache, &settings, &state);

    // Context changes invalidate the optional entry even for absent offers.
    for component in 0..3 {
        let mut foreign = settings.clone();
        match component {
            0 => foreign.app.network[0] ^= 1,
            1 => foreign.app.parameters[0] ^= 1,
            _ => foreign.genesis[0] ^= 1,
        }
        let before = cache.counters.get();
        cache.offer(&foreign, None);
        assert!(cache.material.borrow().is_none());
        equal(&cache, &foreign, &state);
        assert_eq!(cache.counters.get().cold_roots, before.cold_roots + 1);
        assert_eq!(
            cache.counters.get().offers_preserved_partitions,
            before.offers_preserved_partitions
        );
    }
}

#[test]
fn complete_commitment_keeps_account_error_order_with_root_material() {
    let settings = settings();
    let cache = super::super::ArithmeticCache::default();
    let initial = snapshot(&settings.initial);
    cache.offer_root_material(&settings, Some(&initial));
    for marker in 0..6u64 {
        let mut state = settings.initial.clone();
        let owner = format!("account:{}", hex::encode([marker as u8 + 33; 32]));
        state.insert(owner, json!({"balance":0,"nonce":marker}));
        assert_eq!(
            cache.complete(&settings, &state).unwrap(),
            super::super::complete(&settings, &state).unwrap()
        );
    }
    for account in [
        json!(null),
        json!({"balance":0}),
        json!({"balance":0,"nonce":-0.0}),
    ] {
        let mut state = settings.initial.clone();
        state.insert("account:malformed".into(), account);
        state.insert("zz-canonical-failure".into(), json!(-0.0));
        let before = cache.root_arithmetic.counters.get();
        let warm = cache.complete(&settings, &state).unwrap_err();
        let original = super::super::complete(&settings, &state).unwrap_err();
        assert_eq!(warm.to_string(), original.to_string());
        assert_eq!(warm.kind(), original.kind());
        assert_eq!(warm.requires_owner_stop(), original.requires_owner_stop());
        assert_eq!(
            cache.root_arithmetic.counters.get().calculations,
            before.calculations
        );
    }
}
