use super::*;

fn original_rows(state: &State, prefix: &str) -> State {
    state
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn original_full_state_funds(state: &State) -> Result<u64> {
    let mut total = 0_u64;
    for (key, value) in state {
        let amount = if key.starts_with("account:") {
            field(value, "balance")?
        } else if key.starts_with("task:")
            || key.starts_with("quota:")
            || key.starts_with("release:")
        {
            field(value, "remaining")?
        } else if key.starts_with("reward:") {
            field(value, "amount")?
        } else {
            0
        };
        total = add(total, amount)?;
    }
    Ok(total)
}

#[test]
fn funds_ranges_keep_complete_supply_and_malformed_namespace_boundaries() {
    let mut state: State = (0..16_384)
        .map(|index| (format!("model:{index:05}"), json!(null)))
        .collect();
    let cases = [
        ("account", "balance"),
        ("quota", "remaining"),
        ("release", "remaining"),
        ("reward", "amount"),
        ("task", "remaining"),
    ];
    for (stem, field) in cases {
        for suffix in ["", ":", ":\0", ":a", ":a:b", ":λ", ";", ";x"] {
            state.insert(format!("{stem}{suffix}"), json!({field:7}));
        }
    }
    assert_eq!(funds(&state), Ok(5 * 5 * 7));
    assert_eq!(funds(&state), original_full_state_funds(&state));
    for (stem, field) in cases {
        for suffix in ["", ":", ":\0", ":a", ":a:b", ":λ", ";", ";x"] {
            let key = format!("{stem}{suffix}");
            let original = state[&key].clone();
            for value in [
                json!(null),
                json!({}),
                json!({field:-1}),
                json!({field:1.0}),
                json!({field:"1"}),
                json!({field:u64::MAX}),
            ] {
                state.insert(key.clone(), value);
                assert_eq!(funds(&state), original_full_state_funds(&state), "{key:?}");
            }
            state.insert(key, original);
        }
    }
}

#[test]
fn funds_ranges_keep_global_first_error_before_later_overflow_or_bad_types() {
    let mut state = State::from([
        ("account:".into(), json!({"balance":u64::MAX})),
        ("quota:a".into(), json!({"remaining":0})),
        ("release:a".into(), json!({"remaining":1})),
        ("reward:a".into(), json!({"amount":0})),
        ("task:a".into(), json!({"remaining":0})),
    ]);
    let overflow = original_full_state_funds(&state).unwrap_err();
    assert_eq!(funds(&state), Err(overflow));
    state.insert("reward:a".into(), json!(null));
    assert_eq!(funds(&state), Err(overflow));
    state.insert("quota:a".into(), json!(null));
    let first_field = original_full_state_funds(&state).unwrap_err();
    assert_ne!(first_field, overflow);
    assert_eq!(funds(&state), Err(first_field));
    state.insert("account:".into(), json!({"balance":0}));
    assert_eq!(funds(&state), original_full_state_funds(&state));
}

fn into_patch(view: View<'_>) -> Patch {
    Patch {
        writes: view.writes,
        reads: view.reads,
        scans: view.scans,
        fee: 0,
        receipt: Vec::new(),
    }
}

#[test]
fn prefix_rows_preserve_original_filter_order_values_and_all_string_boundaries() {
    let state: State = [
        "",
        "\0",
        "account",
        "account:",
        "account:a",
        "account:a\0",
        "account:aa",
        "account:b",
        "account;",
        "linear-model-v2:one:00",
        "linear-model-v3:one:00",
        "linear-model-v3:one:meta",
        "linear-model-v3:two:00",
        "model:current",
        "模",
        "模型:甲",
        "模型:乙",
        "\u{10ffff}",
        "\u{10ffff}:row",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, key)| (key.to_owned(), json!({"row":index})))
    .collect();
    let mut prefixes: BTreeSet<&str> = ["missing", "account:c", "linear-model-v1:", "模具"]
        .into_iter()
        .collect();
    for key in state.keys() {
        prefixes.insert(key);
        for (end, _) in key.char_indices() {
            prefixes.insert(&key[..end]);
        }
    }
    for prefix in prefixes {
        let original = original_rows(&state, prefix);
        assert!(
            prefix_rows(&state, prefix).eq(original.iter()),
            "{prefix:?}"
        );
        for (key, value) in prefix_rows(&state, prefix) {
            let (source_key, source_value) = state.get_key_value(key).unwrap();
            assert!(std::ptr::eq(key, source_key));
            assert!(std::ptr::eq(value, source_value));
        }
        assert!(prefix_rows(&State::new(), prefix).next().is_none());
    }
}

#[test]
fn prefix_scan_overlays_writes_and_retains_the_original_snapshot() {
    let state = State::from([
        ("model:one".into(), json!(1)),
        ("model:two".into(), json!(2)),
        ("other:one".into(), json!(3)),
    ]);
    let mut view = View::new(&state, None);
    view.put("model:one".into(), json!(10));
    view.put("other:two".into(), json!(4));
    assert_eq!(
        view.scan("model:"),
        State::from([
            ("model:one".into(), json!(10)),
            ("model:two".into(), json!(2)),
        ])
    );
    assert_eq!(view.scans["model:"], original_rows(&state, "model:"));
    view.put("model:three".into(), json!(30));
    view.put("model:one".into(), json!(11));
    let expected = State::from([
        ("model:one".into(), json!(11)),
        ("model:three".into(), json!(30)),
        ("model:two".into(), json!(2)),
    ]);
    assert_eq!(view.scan("model:"), expected);
    assert_eq!(view.scan("model:"), expected);
    assert_eq!(view.scans["model:"], original_rows(&state, "model:"));
    let patch = into_patch(view);
    assert!(patch.current(&state));
    let mut actual = state.clone();
    patch.apply(&mut actual);
    assert_eq!(original_rows(&actual, "model:"), expected);
    assert_eq!(actual["other:one"], 3);
    assert_eq!(actual["other:two"], 4);
}

#[test]
fn prefix_scan_revalidation_keeps_insert_delete_and_value_conflicts() {
    let state = State::from([
        ("model:a".into(), json!(1)),
        ("model:c".into(), json!(3)),
        ("other:a".into(), json!(7)),
    ]);
    let mut view = View::new(&state, None);
    assert_eq!(view.scan("model:"), original_rows(&state, "model:"));
    assert!(view.scan("pending:").is_empty());
    let patch = into_patch(view);
    assert!(patch.current(&state));
    let mut unrelated = state.clone();
    unrelated.insert("model".into(), json!(0));
    unrelated.insert("model;".into(), json!(4));
    unrelated.insert("other:a".into(), json!(8));
    assert!(patch.current(&unrelated));
    for key in ["model:", "model:b", "model:z", "pending:one"] {
        let mut next = state.clone();
        next.insert(key.into(), json!(9));
        assert!(!patch.current(&next), "insert {key}");
    }
    let mut removed = state.clone();
    removed.remove("model:a");
    assert!(!patch.current(&removed));
    let mut changed = state.clone();
    changed.insert("model:c".into(), json!(30));
    assert!(!patch.current(&changed));
}

#[test]
fn prefix_scan_does_not_replace_point_read_or_write_conflict_checks() {
    let state = State::from([
        ("model:one".into(), json!(1)),
        ("other:read".into(), json!(2)),
        ("other:write".into(), json!(3)),
    ]);
    let mut view = View::new(&state, None);
    assert_eq!(view.get("other:read"), Some(json!(2)));
    assert!(view.get("other:absent").is_none());
    view.put("other:write".into(), json!(4));
    view.scan("model:");
    let patch = into_patch(view);
    assert!(patch.current(&state));
    for key in ["other:read", "other:write", "other:absent"] {
        let mut next = state.clone();
        next.insert(key.into(), json!(9));
        assert!(!patch.current(&next), "point conflict {key}");
    }
}

#[test]
fn empty_and_nested_prefix_snapshots_revalidate_the_complete_observed_sets() {
    let state = State::from([
        ("task:a".into(), json!(1)),
        ("task:aa".into(), json!(2)),
        ("task:b".into(), json!(3)),
        ("other:a".into(), json!(4)),
    ]);
    let mut nested = View::new(&state, None);
    assert_eq!(nested.scan("task:a"), original_rows(&state, "task:a"));
    assert_eq!(nested.scan("task:"), original_rows(&state, "task:"));
    let nested = into_patch(nested);
    assert!(nested.current(&state));
    let mut next = state.clone();
    next.insert("task:c".into(), json!(5));
    assert!(!nested.current(&next));
    let mut all = View::new(&state, None);
    assert_eq!(all.scan(""), state);
    let all = into_patch(all);
    assert!(all.current(&state));
    next = state.clone();
    next.insert("unrelated:".into(), json!(6));
    assert!(!all.current(&next));
    let empty = State::new();
    let mut all_empty = View::new(&empty, None);
    assert!(all_empty.scan("").is_empty());
    assert!(!into_patch(all_empty).current(&state));
}

#[test]
fn mandatory_ranges_keep_expiry_priority_maturity_future_rows_and_unrelated_accounts() {
    let mut cfg = Config::installed().unwrap();
    cfg.params["mandatory_expiry_per_block"] = json!(2);
    let current = hex::encode([0; 32]);
    let owner = hex::encode([7; 32]);
    let account_key = format!("account:{owner}");
    let mut state: State = (0..8_192u64)
        .map(|index| {
            (
                format!("account:{index:064x}"),
                json!({"balance": 0, "nonce": 9}),
            )
        })
        .collect();
    state.insert("model:current".into(), json!(current));
    state.insert(account_key.clone(), json!({"balance": 1, "nonce": 12}));
    for (key, remaining, deadline) in [
        ("quota:due", 9, 10),
        ("task:due", 7, 10),
        ("release:due", 5, 9),
        ("quota:future", 4, 100),
        ("task:old-zero", 0, 9),
        ("task:today-zero", 0, 10),
        ("release:retired", 0, 100),
    ] {
        state.insert(
            key.into(),
            json!({"remaining": remaining, "deadline": deadline, "owner": owner}),
        );
    }
    let current_release = format!("release:{current}");
    state.insert(current_release.clone(), json!({"remaining":0}));
    state.insert(
        "reward:mature".into(),
        json!({"maturity":10,"amount":3,"owner":owner}),
    );
    state.insert(
        "reward:future".into(),
        json!({"maturity":11,"amount":2,"owner":owner}),
    );
    let live_artifact = format!("artifact:{current}:0:live");
    state.insert(live_artifact.clone(), json!({"retain":true}));
    state.insert("artifact:stale:0:old".into(), json!({"remove":true}));
    state.insert("account;neighbor".into(), json!("unrelated"));
    state.insert("quota;neighbor".into(), json!("unrelated"));
    state.insert("reward;neighbor".into(), json!("unrelated"));
    let before = state.clone();
    let actual = mandatory(&mut state, 10, &cfg, None, None).unwrap();
    let expected_receipts =
        ["release:due", "quota:due"].map(|key| canonical(&json!({"expiry":key})).unwrap());
    assert_eq!(actual, expected_receipts);
    let mut expected = before.clone();
    for key in [
        "task:old-zero",
        "release:retired",
        "reward:mature",
        "artifact:stale:0:old",
    ] {
        expected.remove(key);
    }
    for key in ["release:due", "quota:due"] {
        expected.get_mut(key).unwrap()["remaining"] = json!(0);
        expected.get_mut(key).unwrap()["status"] = json!("expired");
    }
    expected.get_mut(&account_key).unwrap()["balance"] = json!(18);
    assert_eq!(state, expected);
    assert_eq!(state["task:due"]["remaining"], 7);
    assert_eq!(state["quota:future"]["remaining"], 4);
    assert!(state.contains_key("reward:future"));
    assert!(state.contains_key("task:today-zero"));
    assert!(state.contains_key(&current_release));
    assert!(state.contains_key(&live_artifact));

    // The authenticated monetary projection retains all rows, including future
    // and zero obligations. It must produce the exact ordinary full-State path.
    let monetary: State = before
        .iter()
        .filter(|(key, _)| is_monetary_obligation(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut supplied = before;
    assert_eq!(
        mandatory(
            &mut supplied,
            10,
            &cfg,
            None,
            Some(&MonetaryObligationInput { rows: &monetary }),
        )
        .unwrap(),
        actual
    );
    assert_eq!(supplied, state);
}

#[test]
fn mandatory_ranges_preserve_global_cleanup_error_and_credit_failure_order() {
    let cfg = Config::installed().unwrap();
    let current = hex::encode([0; 32]);
    let mut state = State::from([
        ("model:current".into(), json!(current)),
        ("artifact:stale:0:x".into(), json!(null)),
        ("contribution:bad".into(), json!({"parent":false})),
        (
            "evaluation-archive:old".into(),
            json!({"public_evaluation":{"closed":{"closed_height":0}}}),
        ),
        ("task:old".into(), json!({"remaining":0,"deadline":0})),
    ]);
    assert!(mandatory(&mut state, 300, &cfg, None, None).is_err());
    // Artifact precedes contribution in the original whole-map order. The
    // later archive/task cleanup must not run after the contribution failure.
    assert!(!state.contains_key("artifact:stale:0:x"));
    assert!(state.contains_key("evaluation-archive:old"));
    assert!(state.contains_key("task:old"));

    let calls = std::sync::Mutex::new(Vec::new());
    let access = |who: &str| {
        calls.lock().unwrap().push(who.to_owned());
        if who == "stop" {
            Err("CREDIT_STOP")
        } else {
            Ok(())
        }
    };
    let mut state = State::from([
        ("model:current".into(), json!(current)),
        (
            "quota:later".into(),
            json!({"remaining":2,"deadline":8,"owner":"later"}),
        ),
        (
            "release:stop".into(),
            json!({"remaining":3,"deadline":7,"owner":"stop"}),
        ),
        (
            "task:first".into(),
            json!({"remaining":4,"deadline":6,"owner":"first"}),
        ),
        (
            "reward:mature".into(),
            json!({"amount":5,"maturity":1,"owner":"reward"}),
        ),
    ]);
    assert_eq!(
        mandatory(&mut state, 10, &cfg, Some(&access), None),
        Err("CREDIT_STOP")
    );
    assert_eq!(*calls.lock().unwrap(), ["first", "stop"]);
    assert_eq!(state["account:first"]["balance"], 4);
    assert_eq!(state["task:first"]["remaining"], 0);
    assert_eq!(state["release:stop"]["remaining"], 3);
    assert!(state.contains_key("reward:mature"));
    assert!(!state.contains_key("account:later"));
}

#[test]
fn mandatory_ranges_keep_new_public_archives_and_remove_only_orphan_records() {
    let cfg = Config::installed_with_evaluation_policy(public_evaluation::PROFILE).unwrap();
    let cid = [11; 32];
    let current = hex::encode([0; 32]);
    let mut contribution = json!({
        "owner":hex::encode([99;32]),"parent":current,"artifact":hex::encode([2;32]),
        "components_root":hex::encode([3;32]),"submission_round":2,"submitted_height":257,
        "status":"submitted","votes":{},"score":0
    });
    let evaluation =
        public_evaluation::freeze(&cfg, cid, &contribution, 257, &BTreeSet::new()).unwrap();
    // Freeze already returns the stored compact shape; mandatory hydrates it.
    contribution["public_evaluation"] = evaluation;
    let candidate_key = format!("contribution:{}", hex::encode(cid));
    let archive_key = format!("evaluation-archive:{}", hex::encode(cid));
    let orphan = format!(
        "{}:{}:c:unused",
        public_evaluation::RECORD_NAMESPACE,
        hex::encode([12; 32])
    );
    let stale_record = format!(
        "{}:{}:c:unused",
        public_evaluation::RECORD_NAMESPACE,
        hex::encode([13; 32])
    );
    let old_archive = format!("evaluation-archive:{}", hex::encode([13; 32]));
    let mut state = State::from([
        ("model:current".into(), json!(current)),
        (candidate_key.clone(), contribution),
        (
            old_archive.clone(),
            json!({"public_evaluation":{"closed":{"closed_height":0}}}),
        ),
        (orphan.clone(), json!({"unused":true})),
        (stale_record.clone(), json!({"unused":true})),
        (
            "evaluation-record-v2;neighbor".into(),
            json!({"retain":true}),
        ),
    ]);
    assert!(mandatory(&mut state, 304, &cfg, None, None)
        .unwrap()
        .is_empty());
    assert_eq!(state[&candidate_key]["status"], "evaluation-aborted");
    assert_eq!(
        state[&archive_key]["public_evaluation"]["closed"]["closed_height"],
        304
    );
    assert!(!state.contains_key(&old_archive));
    assert!(!state.contains_key(&orphan));
    assert!(!state.contains_key(&stale_record));
    assert!(state.contains_key("evaluation-record-v2;neighbor"));
}

mod model_cleanup_ranges {
    use super::*;
    use crate::{
        integer_factor_candidate_v2 as factor, model_composition_v4 as composition,
        model_evidence_v3 as evidence, model_evolution_v5 as evolution,
    };

    // Retain the original full-map algorithms as an independent differential
    // oracle, including mutations performed before a later validation error.
    fn original_evolution(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
        if !evolution::enabled(cfg) {
            return Ok(());
        }
        let current = state.get("model:current").cloned().ok_or("FACTOR_PARENT")?;
        let round = height
            / cfg.params["candidate_round_blocks"]
                .as_u64()
                .ok_or("CONFIG")?;
        state.retain(|key, value| {
            !key.starts_with("linear-update-v3:")
                || (value["parent"] == current && value["round"] == round)
        });
        Ok(())
    }

    fn original_factor(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
        if !factor::enabled(cfg) {
            return Ok(());
        }
        let current = state
            .get("model:current")
            .and_then(Value::as_str)
            .ok_or("FACTOR_PARENT")?
            .to_owned();
        let round = height
            / cfg.params["candidate_round_blocks"]
                .as_u64()
                .ok_or("CONFIG")?;
        let removed: Vec<_> = state
            .iter()
            .filter(|(key, _)| key.starts_with("linear-update-v2:"))
            .filter(|(_, value)| value["parent"] != current || value["round"] != round)
            .map(|(key, _)| key.clone())
            .collect();
        for key in removed {
            let id = key.strip_prefix("linear-update-v2:").ok_or("STATE")?;
            let prefix = format!("linear-normal-v2:{id}:");
            state.retain(|key, _| !key.starts_with(&prefix));
            state.remove(&key);
        }
        let mut needed = BTreeSet::new();
        needed.insert(
            cfg.params["factor_genesis_artifact"]
                .as_str()
                .ok_or("CONFIG")?
                .to_owned(),
        );
        let mut view = View::new(state, None);
        let (_, current_model) = factor::parent(&mut view, cfg)?;
        needed.insert(hex::encode(current_model.id()));
        if evidence::enabled(cfg) {
            for control in evidence::controls(cfg)? {
                needed.insert(hex::encode(control.id()));
            }
        }
        for (key, value) in state.iter() {
            if (key.starts_with("contribution:")
                || key.starts_with("evaluation-archive:")
                || key.starts_with("release:")
                || key.starts_with("linear-update-v3:"))
                && value["family"] == hex::encode(cfg.family)
            {
                for name in ["artifact", "factor_parent_artifact"] {
                    if let Some(value) = value[name].as_str() {
                        needed.insert(value.to_owned());
                    }
                }
            }
        }
        state.retain(|key, _| {
            !(key.starts_with("linear-model-v2:") || key.starts_with("linear-model-v3:"))
                || key.split(':').nth(1).is_some_and(|id| needed.contains(id))
        });
        Ok(())
    }

    fn original_evidence(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
        if !evidence::enabled(cfg) {
            return Ok(());
        }
        let round = height
            / cfg.params["candidate_round_blocks"]
                .as_u64()
                .ok_or("MODEL_EVIDENCE_STATE")?;
        let (source_prefix, evidence_prefix) = if evolution::enabled(cfg) {
            ("model-source-v5:", "model-evidence-v5:")
        } else if composition::enabled(cfg) {
            ("model-source-v4:", "model-evidence-v4:")
        } else {
            ("model-source-v3:", "model-evidence-v3:")
        };
        let removed: Vec<_> = state
            .iter()
            .filter_map(|(key, value)| {
                if key.starts_with(source_prefix) {
                    (value["round"] != round).then(|| key.clone())
                } else if let Some(cid) = key.strip_prefix(evidence_prefix) {
                    (!state.contains_key(&format!("contribution:{cid}"))
                        && !state.contains_key(&format!("evaluation-archive:{cid}")))
                    .then(|| key.clone())
                } else {
                    None
                }
            })
            .collect();
        for key in removed {
            state.remove(&key);
        }
        Ok(())
    }

    fn original(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
        original_evolution(state, height, cfg)?;
        original_factor(state, height, cfg)?;
        original_evidence(state, height, cfg)
    }
    fn actual(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
        evolution::cleanup(state, height, cfg)?;
        factor::cleanup(state, height, cfg)?;
        evidence::cleanup(state, cfg, height)
    }
    fn compare(state: &State, height: u64, cfg: &Config, expected: Result<()>) -> State {
        let mut old = state.clone();
        let mut new = state.clone();
        assert_eq!(original(&mut old, height, cfg), expected);
        assert_eq!(actual(&mut new, height, cfg), expected);
        assert_eq!(new, old);
        new
    }
    fn config(profile: &str) -> Config {
        Config::installed_with_model_profiles(
            if profile == evolution::PROFILE {
                public_evaluation::QUORUM_PROFILE
            } else {
                public_evaluation::PROFILE
            },
            LEGACY_TASK_PROFILE,
            profile,
        )
        .unwrap()
    }
    fn fixture(cfg: &Config) -> State {
        let mut state = factor::bootstrap_state(cfg).unwrap();
        let current = state["model:current"].clone();
        for index in 0..8_192u64 {
            state.insert(
                format!("account:{index:064x}"),
                json!({"balance":0,"nonce":index}),
            );
        }
        for version in [2, 3] {
            for (name, value) in [
                ("keep", json!({"parent":current,"round":2})),
                ("old", json!({"parent":current,"round":1})),
                ("wrong", json!({"parent":"different","round":2})),
                ("malformed", json!(null)),
            ] {
                state.insert(format!("linear-update-v{version}:{name}"), value);
                state.insert(format!("linear-normal-v2:{name}:00"), json!(name));
            }
            state.insert(format!("linear-update-v{version};neighbor"), json!(null));
            state.insert(format!("linear-model-v{version};neighbor"), json!(null));
            state.insert(format!("linear-model-v{version}::00"), json!(null));
            for index in 20..=25u8 {
                state.insert(
                    format!("linear-model-v{version}:{}:00", hex::encode([index; 32])),
                    json!({"opaque":index}),
                );
            }
        }
        // Preserve the original nested-prefix behavior: removing `old` also
        // removes its nested normal rows even if a nested marker is retained.
        state.insert(
            "linear-update-v2:old:keep".into(),
            json!({"parent":current,"round":2}),
        );
        state.insert("linear-normal-v2:old:keep:00".into(), json!(null));
        state.insert("linear-normal-v2:older:00".into(), json!(null));
        state.insert("linear-normal-v2:old;neighbor".into(), json!(null));
        for (key, artifact) in [
            ("contribution:active", 20u8),
            ("evaluation-archive:archived", 21),
            ("linear-update-v3:keep", 22),
            ("release:retained", 23),
        ] {
            state.insert(
                key.into(),
                json!({"family":hex::encode(cfg.family),"parent":current,"round":2,
                    "artifact":hex::encode([artifact;32]),"factor_parent_artifact":hex::encode([24;32])}),
            );
        }
        state.insert(
            "contribution:wrong-family".into(),
            json!({"family":"wrong","artifact":hex::encode([25;32])}),
        );
        for version in 3..=5 {
            for (name, value) in [
                ("keep", json!({"round":2})),
                ("old", json!({"round":1})),
                ("malformed", json!(null)),
            ] {
                state.insert(format!("model-source-v{version}:{name}"), value);
            }
            for name in ["active", "archived", "orphan"] {
                state.insert(format!("model-evidence-v{version}:{name}"), json!(null));
            }
            state.insert(format!("model-source-v{version};neighbor"), json!(null));
            state.insert(format!("model-evidence-v{version};neighbor"), json!(null));
        }
        state
    }

    #[test]
    fn original_results_match_all_profiles_rounds_and_unrelated_accounts() {
        for profile in [
            factor::PROFILE,
            evidence::PROFILE,
            composition::PROFILE,
            evolution::PROFILE,
        ] {
            let cfg = config(profile);
            let initial = fixture(&cfg);
            for height in [255, 256, 384] {
                let result = compare(&initial, height, &cfg, Ok(()));
                assert_eq!(
                    original_rows(&result, "account:"),
                    original_rows(&initial, "account:")
                );
            }
            let result = compare(&initial, 256, &cfg, Ok(()));
            assert!(result.contains_key("linear-update-v2:keep"));
            assert!(result.contains_key("linear-update-v2:old:keep"));
            assert!(!result.contains_key("linear-update-v2:old"));
            assert!(!result.contains_key("linear-normal-v2:old:keep:00"));
            assert!(result.contains_key("linear-normal-v2:older:00"));
            assert!(result.contains_key("linear-normal-v2:old;neighbor"));
            for version in [2, 3] {
                for index in 20..=24u8 {
                    assert!(result.contains_key(&format!(
                        "linear-model-v{version}:{}:00",
                        hex::encode([index; 32])
                    )));
                }
                assert!(!result.contains_key(&format!(
                    "linear-model-v{version}:{}:00",
                    hex::encode([25; 32])
                )));
                assert!(!result.contains_key(&format!("linear-model-v{version}::00")));
                assert!(result.contains_key(&format!("linear-model-v{version};neighbor")));
            }
            let selected = if profile == evolution::PROFILE {
                5
            } else if profile == composition::PROFILE {
                4
            } else {
                3
            };
            for version in 3..=5 {
                let cleaned = evidence::enabled(&cfg) && version == selected;
                assert_eq!(
                    result.contains_key(&format!("model-source-v{version}:old")),
                    !cleaned
                );
                assert_eq!(
                    result.contains_key(&format!("model-evidence-v{version}:orphan")),
                    !cleaned
                );
                for name in ["active", "archived"] {
                    assert!(result.contains_key(&format!("model-evidence-v{version}:{name}")));
                }
                assert!(result.contains_key(&format!("model-source-v{version}:keep")));
                assert!(result.contains_key(&format!("model-evidence-v{version};neighbor")));
            }
        }
    }

    #[test]
    fn original_first_errors_and_partial_cleanup_states_are_preserved() {
        for profile in [factor::PROFILE, evolution::PROFILE] {
            let cfg = config(profile);
            let initial = fixture(&cfg);
            let mut broken = cfg.clone();
            broken.params["candidate_round_blocks"] = json!(null);
            broken.params["factor_genesis_artifact"] = json!(null);
            let mut missing = initial.clone();
            missing.remove("model:current");
            assert_eq!(
                compare(&missing, 256, &broken, Err("FACTOR_PARENT")),
                missing
            );
            assert_eq!(compare(&initial, 256, &broken, Err("CONFIG")), initial);

            broken.params["candidate_round_blocks"] = cfg.params["candidate_round_blocks"].clone();
            let result = compare(&initial, 256, &broken, Err("CONFIG"));
            assert!(!result.contains_key("linear-update-v2:old"));
            assert!(!result.contains_key("linear-normal-v2:old:00"));
            assert!(result.contains_key(&format!("linear-model-v2:{}:00", hex::encode([25; 32]))));

            let mut bad_parent = initial.clone();
            bad_parent.insert("model:current".into(), json!("not-a-hash"));
            compare(&bad_parent, 256, &cfg, Err("FACTOR_HASH"));
            let version = if profile == evolution::PROFILE { 3 } else { 2 };
            let mut missing_model = initial.clone();
            missing_model.remove(&format!(
                "linear-model-v{version}:{}:meta",
                cfg.params["factor_genesis_artifact"].as_str().unwrap()
            ));
            compare(&missing_model, 256, &cfg, Err("FACTOR_MODEL_MISSING"));
        }
        let mut cfg = config(evidence::PROFILE);
        let initial = fixture(&cfg);
        cfg.params["model_evidence_tasks_hash"] = json!("wrong");
        compare(&initial, 256, &cfg, Err("MODEL_EVIDENCE_PROFILE"));

        cfg.params["candidate_round_blocks"] = json!(null);
        let mut old = initial.clone();
        let mut new = initial.clone();
        assert_eq!(
            original_evidence(&mut old, 256, &cfg),
            Err("MODEL_EVIDENCE_STATE")
        );
        assert_eq!(
            evidence::cleanup(&mut new, &cfg, 256),
            Err("MODEL_EVIDENCE_STATE")
        );
        assert_eq!(old, initial);
        assert_eq!(new, initial);
    }

    #[test]
    fn disabled_profiles_ignore_missing_parameters_and_malformed_rows() {
        let mut cfg = Config::installed().unwrap();
        cfg.params["candidate_round_blocks"] = json!(null);
        let state = State::from([
            ("linear-update-v3:invalid".into(), json!(null)),
            ("linear-model-v2:invalid".into(), json!(null)),
            ("model-source-v3:invalid".into(), json!(null)),
        ]);
        assert_eq!(compare(&state, 256, &cfg, Ok(())), state);
    }
}
