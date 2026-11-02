use super::*;
use serde_json::json;
use trnm_protocol::pon_wire::StateRootArithmetic;

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
