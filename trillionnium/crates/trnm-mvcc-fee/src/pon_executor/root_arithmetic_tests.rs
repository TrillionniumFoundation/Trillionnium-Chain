use super::*;
use serde_json::json;
use trnm_protocol::pon_wire::StateRootArithmetic;

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
        let state = State::from([("a".repeat(161), json!(0)), ("zz-last".into(), invalid)]);
        let original = root(&state);
        assert!(original.is_err() && original != Err("LIMIT"));
        assert_eq!(root_with_arithmetic(&state, &mut arithmetic), original);
        assert_eq!(arithmetic.observation(), retained);
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
