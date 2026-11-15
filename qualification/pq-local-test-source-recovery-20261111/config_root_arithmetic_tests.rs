use super::*;
use crate::pon_executor::pq_accounts_v2::{self, GenesisAccount};
use serde_json::json;

fn ordinary_config() -> Config {
    Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        crate::continuity_v1::PROFILE,
    )
    .unwrap()
}

fn pq_fixture() -> (Config, State) {
    // The existing public test key is sufficient for a real PQ genesis. This
    // root-only control neither generates a signing key nor signs a request.
    let (cfg, state, _) = pq_accounts_v2::genesis(
        &[GenesisAccount {
            spki: include_bytes!("../../../trnm-protocol/tests/fixtures/pq_transfer/public.der")
                .to_vec(),
            balance: 7,
        }],
        1000,
    )
    .unwrap();
    (cfg, state)
}

fn growth_fixture() -> (Config, State) {
    let cfg = Config::installed_with_profiles(
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
    (cfg, state)
}

#[test]
fn config_root_arithmetic_matches_ordinary_reference_and_error_order() {
    let cfg = ordinary_config();
    let arithmetic = FullRootArithmetic::default();
    let state = State::from([
        ("a".into(), json!({"balance":7,"nonce":3})),
        ("b".into(), json!([null, true, "ASCII"])),
    ]);
    let mut changed = state.clone();
    changed.insert("a".into(), json!({"balance":7,"nonce":4}));
    assert_ne!(pon_executor::root(&state), pon_executor::root(&changed));
    for actual in [&state, &changed, &state, &State::new()] {
        assert_eq!(
            arithmetic.root_for_config(actual, &cfg),
            pon_executor::root_for_config(actual, &cfg),
        );
    }

    // A late canonical error must remain visible before an earlier wire error,
    // including after this arithmetic object has retained a valid root.
    for (value, error) in [
        (json!(0.0), "RANGE"),
        (json!(-0.0), "RANGE"),
        (json!("非ASCII"), "NONCANONICAL"),
        (json!({"λ":0}), "NONCANONICAL"),
    ] {
        let invalid = State::from([("a".repeat(161), json!(0)), ("zz-last".into(), value)]);
        assert_eq!(pon_executor::root_for_config(&invalid, &cfg), Err(error));
        assert_eq!(arithmetic.root_for_config(&invalid, &cfg), Err(error));
    }
    for invalid in [
        State::from([("a".repeat(161), json!(0))]),
        State::from([("large-value".into(), json!("x".repeat(4095)))]),
    ] {
        assert_eq!(pon_executor::root_for_config(&invalid, &cfg), Err("LIMIT"));
        assert_eq!(arithmetic.root_for_config(&invalid, &cfg), Err("LIMIT"));
    }
}

#[test]
fn config_root_arithmetic_validates_pq_state_before_root() {
    let (cfg, state) = pq_fixture();
    let arithmetic = FullRootArithmetic::default();
    assert!(pq_accounts_v2::enabled(&cfg));
    assert_eq!(pq_accounts_v2::validate_state(&state, &cfg), Ok(()));
    assert_eq!(
        arithmetic.root_for_config(&state, &cfg),
        pon_executor::root_for_config(&state, &cfg),
    );

    let account = state
        .keys()
        .find(|key| key.starts_with("account:"))
        .unwrap()
        .clone();
    let mut invalid = state.clone();
    invalid.insert(account, json!({"balance":7,"nonce":"invalid"}));
    invalid.insert("a".repeat(161), json!(0));
    invalid.insert("zz-last".into(), json!("非ASCII"));
    assert_eq!(pon_executor::root(&invalid), Err("NONCANONICAL"));
    assert_eq!(
        pon_executor::root_for_config(&invalid, &cfg),
        Err("PQ2_ACCOUNT_STATE"),
    );
    assert_eq!(
        arithmetic.root_for_config(&invalid, &cfg),
        Err("PQ2_ACCOUNT_STATE"),
    );
}

#[test]
fn config_root_arithmetic_rejects_partial_and_changed_pq_config_first() {
    let arithmetic = FullRootArithmetic::default();
    let invalid = State::from([("a".repeat(161), json!(0)), ("zz-last".into(), json!(0.0))]);
    assert_eq!(pon_executor::root(&invalid), Err("RANGE"));

    let mut partial = ordinary_config();
    partial.params["native_pq_accounts_profile"] = json!("not-installed");
    assert!(pq_accounts_v2::enabled(&partial));
    assert_eq!(
        pon_executor::root_for_config(&invalid, &partial),
        Err("PQ2_PROFILE_REQUIRED"),
    );
    assert_eq!(
        arithmetic.root_for_config(&invalid, &partial),
        Err("PQ2_PROFILE_REQUIRED"),
    );

    let (cfg, _) = pq_fixture();
    let mut changed_selector = cfg.clone();
    changed_selector.params["native_pq_accounts_profile"] = json!("not-installed");
    let mut changed_network = cfg;
    changed_network.network[0] ^= 1;
    for changed in [&changed_selector, &changed_network] {
        assert_eq!(
            pon_executor::root_for_config(&invalid, changed),
            Err("PQ2_CONFIG_CHANGED"),
        );
        assert_eq!(
            arithmetic.root_for_config(&invalid, changed),
            Err("PQ2_CONFIG_CHANGED"),
        );
    }
}

#[test]
fn config_root_arithmetic_preserves_growth_and_pq_error_precedence() {
    let arithmetic = FullRootArithmetic::default();
    let (cfg, state) = growth_fixture();
    let expected = crate::growth_profile_v2::commitment(&state, &cfg)
        .unwrap()
        .id();
    assert_ne!(expected, pon_executor::root(&state).unwrap());
    assert_eq!(pon_executor::root_for_config(&state, &cfg), Ok(expected));
    assert_eq!(arithmetic.root_for_config(&state, &cfg), Ok(expected));

    let mut invalid_growth = cfg;
    invalid_growth.params["maximum_permanent_accounts"] =
        json!(crate::growth_profile_v2::MAX_PERMANENT_ACCOUNTS + 1);
    assert!(crate::growth_profile_v2::enabled(&invalid_growth));
    assert_eq!(
        pon_executor::root_for_config(&state, &invalid_growth),
        Err("GROWTH_PROFILE"),
    );
    assert_eq!(
        arithmetic.root_for_config(&state, &invalid_growth),
        Err("GROWTH_PROFILE"),
    );

    // Both selectors are active and the growth policy is already invalid. The
    // original PQ policy check still takes precedence over growth dispatch.
    invalid_growth.params["native_pq_accounts_profile"] = json!("not-installed");
    assert_eq!(
        pon_executor::root_for_config(&state, &invalid_growth),
        Err("PQ2_PROFILE_REQUIRED"),
    );
    assert_eq!(
        arithmetic.root_for_config(&state, &invalid_growth),
        Err("PQ2_PROFILE_REQUIRED"),
    );

    let (mut pq_growth, pq_state) = pq_fixture();
    crate::growth_profile_v2::configure(&mut pq_growth.params, "native-public-evaluation-dev-v1")
        .unwrap();
    assert!(crate::growth_profile_v2::enabled(&pq_growth));
    assert_eq!(
        pon_executor::root_for_config(&pq_state, &pq_growth),
        Err("PQ2_CONFIG_CHANGED"),
    );
    assert_eq!(
        arithmetic.root_for_config(&pq_state, &pq_growth),
        Err("PQ2_CONFIG_CHANGED"),
    );
}

#[test]
fn config_root_arithmetic_contention_and_poison_keep_profile_results() {
    let arithmetic = FullRootArithmetic::default();
    let ordinary = ordinary_config();
    let ordinary_state = State::from([("ordinary".into(), json!(7))]);
    let (pq, pq_state) = pq_fixture();
    let (growth, growth_state) = growth_fixture();
    let mut partial = ordinary.clone();
    partial.params["native_pq_accounts_profile"] = json!("not-installed");
    let invalid_state = State::from([("invalid".into(), json!(0.0))]);
    let cases = [
        (&ordinary_state, &ordinary),
        (&pq_state, &pq),
        (&growth_state, &growth),
        (&invalid_state, &ordinary),
        (&invalid_state, &partial),
    ];
    let check = || {
        for (state, cfg) in cases {
            assert_eq!(
                arithmetic.root_for_config(state, cfg),
                pon_executor::root_for_config(state, cfg),
            );
        }
    };
    check();
    {
        let _held = arithmetic.0.lock().unwrap();
        check();
    }
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = arithmetic.0.lock().unwrap();
        panic!("poison mathematical material only");
    }))
    .is_err());
    assert!(arithmetic.0.is_poisoned());
    check();
}
