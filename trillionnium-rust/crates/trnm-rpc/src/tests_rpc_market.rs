use super::*;

#[test]
fn normalize_market_status_key_collapses_hidden_and_control_separators() {
    assert_eq!(normalize_market_status_key(" matched\u{200b}"), "matched");
    assert_eq!(normalize_market_status_key("mat\u{00ad}ched"), "matched");
    assert_eq!(normalize_market_status_key("open\u{0007}"), "open");
    assert_eq!(
        normalize_market_status_key("\u{feff} matched \u{2060}"),
        "matched"
    );
}

#[test]
fn market_reputation_loader_normalizes_worker_keys() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(&path, "{\" Worker-A \": 12, \"\": 99, \"WORKER-B\": -5}")
        .expect("write reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&12));
            assert_eq!(rep.get("worker-b"), Some(&-5));
            assert!(!rep.contains_key(" Worker-A "));
            assert!(!rep.contains_key(""));
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_uses_highest_value_when_aliases_collide() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_alias_collision_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        "{\"worker-a\": 10, \" Worker-A \": 200, \"WORKER-B\": -7}",
    )
    .expect("write alias-collision reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&200));
            assert_eq!(rep.get("worker-b"), Some(&-7));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_collapses_internal_whitespace_aliases() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_internal_ws_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        r#"{" Worker   A ": 10, "worker a": 25, "WORKER   B": -3}"#,
    )
    .expect("write internal-whitespace reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker a"), Some(&25));
            assert_eq!(rep.get("worker b"), Some(&-3));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_collapses_zero_width_aliases() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_zero_width_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        "{\"worker\\u200ba\": 9, \"worker a\": 31, \"worker\\u200db\": -2, \"worker\\u2060b\": 5}",
    )
    .expect("write zero-width reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker a"), Some(&31));
            assert_eq!(rep.get("worker b"), Some(&5));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_collapses_control_character_aliases() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_control_chars_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        "{\"worker\\u0007a\": 8, \"worker a\": 17, \"worker\\u000bb\": 4}",
    )
    .expect("write control-char reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker a"), Some(&17));
            assert_eq!(rep.get("worker b"), Some(&4));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_salvages_valid_entries_when_some_values_are_non_numeric() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_partial_invalid_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        r#"{"worker-a": 7, "worker-b": "bad", "worker-c": -3}"#,
    )
    .expect("write partial-invalid reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&7));
            assert_eq!(rep.get("worker-c"), Some(&-3));
            assert!(!rep.contains_key("worker-b"));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_accepts_integer_strings_and_skips_non_integer_strings() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_string_ints_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        r#"{"worker-a": " 11 ", "worker-b": "-4", "worker-c": "3.5", "worker-d": "oops"}"#,
    )
    .expect("write string-int reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&11));
            assert_eq!(rep.get("worker-b"), Some(&-4));
            assert!(!rep.contains_key("worker-c"));
            assert!(!rep.contains_key("worker-d"));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_accepts_integral_json_numbers_and_skips_fractional_numbers() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_float_ints_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        r#"{"worker-a": 11.0, "worker-b": -4.0, "worker-c": 3.5}"#,
    )
    .expect("write float-int reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&11));
            assert_eq!(rep.get("worker-b"), Some(&-4));
            assert!(!rep.contains_key("worker-c"));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_reputation_loader_accepts_stringified_i64_and_skips_non_integral_strings() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_stringified_i64_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        r#"{"worker-a": " 11 ", "worker-b": "-4", "worker-c": "3.5", "worker-d": "oops"}"#,
    )
    .expect("write string-int reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker-a"), Some(&11));
            assert_eq!(rep.get("worker-b"), Some(&-4));
            assert!(!rep.contains_key("worker-c"));
            assert!(!rep.contains_key("worker-d"));
            assert_eq!(rep.len(), 2);
        },
    );

    let _ = fs::remove_file(path);
}

#[test]
fn market_worker_tie_break_key_normalizes_case_and_whitespace() {
    assert_eq!(market_worker_tie_break_key(" Worker-A "), "worker-a");
    assert_eq!(market_worker_tie_break_key("worker-Z"), "worker-z");
}

#[test]
fn market_effective_score_rewards_higher_reputation() {
    let low_rep = market_effective_score(100, 0);
    let high_rep = market_effective_score(100, 80);
    assert!(high_rep < low_rep);
}

#[test]
fn market_effective_score_penalizes_negative_reputation() {
    let neutral = market_effective_score(100, 0);
    let penalized = market_effective_score(100, -50);
    assert!(penalized > neutral);
}

#[test]
fn market_effective_score_applies_configured_reputation_weight() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "10"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(101, 20), 100_800);
        },
    );
}

#[test]
fn market_score_config_uses_defaults_for_empty_wrapped_env_values() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, " '' "),
            (MARKET_REPUTATION_WEIGHT_ENV, " \"\" "),
            (MARKET_REPUTATION_CLAMP_ENV, " ` ` "),
        ],
        || {
            assert_eq!(market_effective_score(10, 5), 9_500);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_clamp_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "100"),
            (MARKET_REPUTATION_CLAMP_ENV, "0"),
        ],
        || {
            assert_eq!(market_effective_score(101, 100_000), 100_900);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_clamp_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "9999999"),
        ],
        || {
            assert_eq!(market_effective_score(101, 2_000_000), 0);
        },
    );
}

#[test]
fn market_effective_score_clamps_price_weight_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 0), 2);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_weight_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 5), 1995);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_weight_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_WEIGHT_ENV, "999999999"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(1, -2000), 1_000_000_001);
        },
    );
}

#[test]
fn market_effective_score_clamps_price_weight_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "999999999"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 0), 2_000_000);
        },
    );
}

#[test]
fn market_m2_policy_gate_guards_default_drift_to_min_boundaries() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "''"),
            (MARKET_REPUTATION_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_CLAMP_ENV, "0"),
        ],
        || {
            let cfg = market_score_config();
            assert_eq!(cfg.price_weight, MARKET_PRICE_WEIGHT_DEFAULT);
            assert_eq!(cfg.reputation_weight, MARKET_WEIGHT_MIN);
            assert_eq!(cfg.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
        },
    );
}
