use super::*;
use serde_json::json;
use trnm_protocol::pon_wire::StateRootArithmetic;

fn owned_non_accounts(state: &State) -> State {
    state
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[test]
fn borrowed_non_account_partition_keeps_actual_rows_changes_and_original_roots() {
    let mut state = State::from([
        ("account:one".into(), json!({"balance":7,"nonce":2})),
        ("accounting".into(), json!("included")),
        ("meta:issued".into(), json!(7)),
        ("plain".into(), json!("x".repeat(4080))),
        ("escaped".into(), json!("\"\\\n\u{001f}")),
        ("nested".into(), json!({"a":["plain",1,null]})),
    ]);
    let mut arithmetic = StateRootArithmetic::new(16 * 1024);
    for step in 0..7 {
        match step {
            1 => state.get_mut("account:one").unwrap()["nonce"] = json!(3),
            2 => {
                state.insert("new".into(), json!("new"));
            }
            3 => {
                state.insert("plain".into(), json!("y".repeat(4080)));
            }
            4 => {
                state.remove("escaped");
            }
            5 => {
                state.insert("account:zero".into(), json!({"balance":0,"nonce":99}));
            }
            6 => state.clear(),
            _ => {}
        }
        let original = owned_non_accounts(&state);
        let view = BorrowedNonAccountState::new(&state);
        assert_eq!(view.len(), original.len());
        assert_eq!(view.is_empty(), original.is_empty());
        assert!(view.iter().eq(original.iter()));
        assert_eq!(view.get("account:one"), None);
        assert_eq!(view.get("not-present"), None);
        for (key, value) in view.iter() {
            let (source_key, source_value) = state.get_key_value(key).unwrap();
            assert!(std::ptr::eq(key, source_key));
            assert!(std::ptr::eq(value, source_value));
            assert!(std::ptr::eq(view.get(key).unwrap(), source_value));
        }
        let expected = root(&original);
        assert_eq!(view.root(), expected);
        assert_eq!(view.root_with_arithmetic(&mut arithmetic), expected);
        assert_eq!(view.root_with_arithmetic(&mut arithmetic), expected);
        assert!(arithmetic.retained_payload_bytes() <= 16 * 1024);
    }
}

#[test]
fn borrowed_non_account_partition_keeps_full_grammar_before_count_and_wire_limits() {
    let mut arithmetic = StateRootArithmetic::new(16 * 1024);
    let warm = State::from([("warm".into(), json!("prior complete material"))]);
    BorrowedNonAccountState::new(&warm)
        .root_with_arithmetic(&mut arithmetic)
        .unwrap();
    let previous = arithmetic.observation();
    let mut cases = vec![
        State::from([("a".repeat(161), json!(0)), ("z".into(), json!(0.5))]),
        State::from([
            ("a".into(), json!("x".repeat(4096))),
            ("z".into(), json!("é")),
        ]),
        State::from([("a".repeat(161), json!(0))]),
        State::from([("a".into(), json!("x".repeat(4096)))]),
    ];
    let mut too_many: State = (0..65_537)
        .map(|index| (format!("row:{index:05}"), json!(0)))
        .collect();
    cases.push(too_many.clone());
    too_many.insert("zz-late-invalid".into(), json!(0.5));
    cases.push(too_many);
    for (index, state) in cases.iter_mut().enumerate() {
        state.insert("account:excluded".into(), json!({"balance":0,"nonce":99}));
        let original = owned_non_accounts(state);
        let expected = root(&original);
        assert_eq!(
            expected,
            Err(match index {
                0 | 5 => "RANGE",
                1 => "NONCANONICAL",
                _ => "LIMIT",
            })
        );
        let view = BorrowedNonAccountState::new(state);
        assert_eq!(view.root(), expected);
        assert_eq!(view.root_with_arithmetic(&mut arithmetic), expected);
        assert_eq!(arithmetic.observation(), previous);
    }
}

fn plain_ascii_reference(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte.is_ascii() && byte >= 0x20 && byte != b'"' && byte != b'\\')
}

#[test]
fn canonical_ascii_guard_matches_exhaustive_bytes_pairs_and_borrow_chains() {
    // Every adjacent pair, including the boundary between two chunks. This is
    // exhaustive over two bytes and their positions, not over all 2^64 words.
    for length in [8, 9] {
        for position in 0..length - 1 {
            let mut bytes = vec![b'x'; length];
            for pair in 0..=u16::MAX {
                bytes[position..position + 2].copy_from_slice(&pair.to_le_bytes());
                assert_eq!(
                    unescaped_ascii_json(&bytes),
                    plain_ascii_reference(&bytes),
                    "length={length} position={position} pair={pair}"
                );
            }
        }
    }
    // Exercise each tail length and all single-byte values, including bytes
    // that cannot occur by themselves in UTF-8. Backgrounds 0x20, 0x23 and
    // 0x5d exercise long borrow chains for control, quote and backslash probes.
    for length in 0..=17 {
        assert!(unescaped_ascii_json(&vec![b'x'; length]));
        for fill in [b' ', b'#', b']', 0x7f] {
            for position in 0..length {
                let mut bytes = vec![fill; length];
                for byte in 0..=u8::MAX {
                    bytes[position] = byte;
                    assert_eq!(unescaped_ascii_json(&bytes), plain_ascii_reference(&bytes));
                }
            }
        }
    }
}

fn assert_canonical_serde_bytes_and_capacity(value: &Value) {
    let reference = serde_json::to_vec(value).unwrap();
    let actual = canonical(value).unwrap();
    assert_eq!(actual, reference);
    assert_eq!(actual.capacity(), reference.capacity());
}

#[test]
fn canonical_ascii_keeps_original_serde_bytes_and_vec_capacities() {
    for length in [
        0, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 126, 127, 128, 129, 255, 256, 257, 4078, 4080,
        4094, 4095, 4096,
    ] {
        for fill in [b'x', b' ', 0x7f] {
            let text = String::from_utf8(vec![fill; length]).unwrap();
            assert_canonical_serde_bytes_and_capacity(&Value::String(text));
        }
    }
    // Every ASCII byte, including every escape, at chunk and long-value edges.
    for byte in 0..=0x7f {
        for position in [0, 7, 8, 4079] {
            let mut text = vec![b'x'; 4080];
            text[position] = byte;
            assert_canonical_serde_bytes_and_capacity(&Value::String(
                String::from_utf8(text).unwrap(),
            ));
        }
    }
    for value in [
        json!(null),
        json!(false),
        json!(i64::MIN),
        json!(u64::MAX),
        json!(["plain", "quote\"", "backslash\\", "\u{0000}", 0]),
        json!({"z":"plain", "a\"":"escaped", "n":-1}),
    ] {
        assert_canonical_serde_bytes_and_capacity(&value);
    }
}

#[test]
fn canonical_ascii_into_keeps_reused_capacity_and_failed_input_untouched() {
    let values = [
        json!("x".repeat(4080)),
        json!(""),
        json!("\"\\\n\u{001f}\u{007f}"),
        json!("x".repeat(127)),
        json!(["nested", 1]),
        json!("x".repeat(4094)),
    ];
    for initial_capacity in [0, 1, 127, 128, 129, 4096, 8192] {
        let mut actual = Vec::with_capacity(initial_capacity);
        let mut reference = Vec::with_capacity(initial_capacity);
        for value in &values {
            reference.clear();
            serde_json::to_writer(&mut reference, value).unwrap();
            canonical_into(value, &mut actual).unwrap();
            assert_eq!(actual, reference);
            assert_eq!(actual.capacity(), reference.capacity());
        }
        for (invalid, error) in [
            (json!("λ"), "NONCANONICAL"),
            (json!(0.5), "RANGE"),
            (json!(-0.0), "RANGE"),
            (json!(["x".repeat(4080), "λ", 0.5]), "NONCANONICAL"),
            (json!({"a":0.5,"b":"λ"}), "RANGE"),
            (json!({"a":"λ","b":0.5}), "NONCANONICAL"),
        ] {
            let before = actual.clone();
            let capacity = actual.capacity();
            assert_eq!(canonical(&invalid), Err(error));
            assert_eq!(canonical_into(&invalid, &mut actual), Err(error));
            assert_eq!(actual, before);
            assert_eq!(actual.capacity(), capacity);
        }
    }
}

#[test]
fn canonical_ascii_commitment_keeps_late_grammar_before_wire_and_cache_errors() {
    use crate::pon_commitment::{derive_snapshot, CacheLimits, MAX_CACHE_KEYS};
    let limits = CacheLimits {
        max_keys: MAX_CACHE_KEYS + 1,
        ..CacheLimits::default()
    };
    let mut state = State::from([("a".repeat(161), json!("x".repeat(4095)))]);
    for (late, error) in [(json!("λ"), "NONCANONICAL"), (json!(0.5), "RANGE")] {
        state.insert("z".into(), late);
        assert_eq!(root(&state), Err(error));
        assert_eq!(derive_snapshot(&state, None, limits).unwrap_err(), error);
    }
    state.insert("z".into(), json!("x".repeat(4080)));
    assert_eq!(root(&state), Err("LIMIT"));
    assert_eq!(derive_snapshot(&state, None, limits).unwrap_err(), "LIMIT");
    state.remove(&"a".repeat(161));
    assert_eq!(
        derive_snapshot(&state, None, limits).unwrap_err(),
        "COMMITMENT_CACHE_LIMIT"
    );
}

#[test]
fn arithmetic_root_preserves_complete_grammar_before_all_wire_limits() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let valid = State::from([
        (
            "key".into(),
            json!({"array":[null,false,"ascii"],"number":-1}),
        ),
        ("unicode-key-λ".into(), json!(u64::MAX)),
    ]);
    assert_eq!(root_with_arithmetic(&valid, &mut arithmetic), root(&valid));
    let retained = arithmetic.observation();
    for invalid in [json!(0.0), json!(-0.0), json!("λ"), json!({"λ":0})] {
        for early in [
            ("a".repeat(161), json!(0)),
            ("a".into(), json!("x".repeat(4095))),
        ] {
            let state = State::from([early, ("zz-last".into(), invalid.clone())]);
            let original = root(&state);
            assert!(original.is_err() && original != Err("LIMIT"));
            assert_eq!(root_with_arithmetic(&state, &mut arithmetic), original);
            assert_eq!(arithmetic.observation(), retained);
        }
    }
    let mut over: State = (0..65_537)
        .map(|index| (format!("key-{index:05}"), Value::Null))
        .collect();
    assert_eq!(root_with_arithmetic(&over, &mut arithmetic), root(&over));
    assert_eq!(root_with_arithmetic(&over, &mut arithmetic), Err("LIMIT"));
    over.insert("zz-last".into(), json!(-0.0));
    assert_eq!(root_with_arithmetic(&over, &mut arithmetic), root(&over));
    assert_eq!(root_with_arithmetic(&over, &mut arithmetic), Err("RANGE"));
    assert_eq!(arithmetic.observation(), retained);
    assert_eq!(root_with_arithmetic(&valid, &mut arithmetic), root(&valid));
    assert_eq!(arithmetic.observation().computed_partitions, 0);
}

#[test]
fn arithmetic_root_ascii_encoding_matches_independent_serde_reference() {
    let mut state = State::new();
    for length in [
        0, 1, 7, 8, 9, 126, 127, 128, 129, 255, 256, 257, 4078, 4080, 4094,
    ] {
        for fill in [b'x', b' ', 0x7f] {
            state.insert(
                format!("ascii:{length:04}:{fill:03}"),
                json!(String::from_utf8(vec![fill; length]).unwrap()),
            );
        }
    }
    for (index, value) in [
        json!("quote\"backslash\\control\u{0000}\u{001f}\n\r\t"),
        json!(["plain", "escaped\"", null, false, 0]),
        json!({"z":"plain", "a\"":"escaped", "n":-1}),
        json!(i64::MIN),
        json!(u64::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        state.insert(format!("fallback:{index}"), value);
    }
    // The original root keeps its independent serde encoder. Check complete
    // mixed views both without retained arithmetic and with a warm cache.
    let expected = root(&state).unwrap();
    for budget in [0, 2 * 1024 * 1024] {
        let mut arithmetic = StateRootArithmetic::new(budget);
        assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
        assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
        let mut changed = state.clone();
        changed.insert("ascii:4080:120".into(), json!("z".repeat(4080)));
        let changed_expected = root(&changed).unwrap();
        assert_ne!(changed_expected, expected);
        assert_eq!(
            root_with_arithmetic(&changed, &mut arithmetic),
            Ok(changed_expected)
        );
        assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
    }
}

#[test]
fn arithmetic_root_distinguishes_exact_numeric_values_and_full_non_account_views() {
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let mut state: State = (0..80)
        .map(|index| (format!("retained:{index:03}"), json!("x".repeat(4094))))
        .collect();
    state.insert("account:one".into(), json!({"balance":0,"nonce":1}));
    for value in [
        json!(0),
        json!(0.0),
        json!(-0.0),
        json!(i64::MIN),
        json!(u64::MAX),
    ] {
        state.insert("number".into(), value);
        assert_eq!(root_with_arithmetic(&state, &mut arithmetic), root(&state));
    }
    let partition: State = state
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    assert_eq!(
        root_with_arithmetic(&partition, &mut arithmetic),
        root(&partition)
    );
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), root(&state));
    assert!(arithmetic.observation().reused_partitions > 50);
    state.remove("retained:040");
    state.insert("foreign-namespace:040".into(), json!("x".repeat(4094)));
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), root(&state));
    state.insert("over-value".into(), json!("x".repeat(4095)));
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), root(&state));
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Err("LIMIT"));
}

#[test]
fn exact_string_root_hits_keep_complete_current_grammar_and_original_miss_encoding() {
    let state = State::from([
        ("000-warm".into(), json!("x".repeat(4080))),
        ("empty".into(), json!("")),
        ("del".into(), json!("\u{007f}")),
        ("escaped".into(), json!("\n")),
        ("nested".into(), json!(["plain", 0, false])),
    ]);
    let mut arithmetic = StateRootArithmetic::new(2 * 1024 * 1024);
    let expected = root(&state).unwrap();
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
    assert_eq!(arithmetic.observation().leaf_hashes_computed, state.len());
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
    let warm = arithmetic.observation();
    assert_eq!(warm.input_keys, state.len());
    assert_eq!(warm.exact_string_hits, 3);
    assert_eq!(warm.string_encodings_reused, 3);
    assert_eq!(warm.leaf_hashes_computed, 2);
    assert_eq!(
        warm.leaf_hashes_computed + warm.exact_string_hits,
        warm.input_keys
    );

    for late in [json!(0.0), json!(-0.0), json!("λ"), json!({"λ":0})] {
        let mut invalid = state.clone();
        invalid.insert("a".repeat(161), json!("x".repeat(4095)));
        invalid.insert("zz-invalid".into(), late);
        let original = root(&invalid);
        assert!(original.is_err() && original != Err("LIMIT"));
        assert_eq!(root_with_arithmetic(&invalid, &mut arithmetic), original);
        assert_eq!(arithmetic.observation(), warm);
    }
    let mut changed = state.clone();
    changed.insert("000-warm".into(), json!(format!("{}y", "x".repeat(4079))));
    changed.insert("empty".into(), Value::Null);
    let changed_root = root(&changed).unwrap();
    assert_ne!(changed_root, expected);
    assert_eq!(
        root_with_arithmetic(&changed, &mut arithmetic),
        Ok(changed_root)
    );
    assert_eq!(arithmetic.observation().exact_string_hits, 1);
    assert_eq!(arithmetic.observation().leaf_hashes_computed, 4);
    assert_eq!(root_with_arithmetic(&state, &mut arithmetic), Ok(expected));
    assert!(arithmetic.retained_payload_bytes() <= 2 * 1024 * 1024);
}
