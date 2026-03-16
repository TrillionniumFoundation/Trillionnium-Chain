use super::*;

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
