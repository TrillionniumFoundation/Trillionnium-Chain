use super::*;

fn original_rows(state: &State, prefix: &str) -> State {
    state
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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
