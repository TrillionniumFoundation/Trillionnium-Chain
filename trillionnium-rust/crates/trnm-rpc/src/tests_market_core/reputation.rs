pub(crate) use super::*;

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
