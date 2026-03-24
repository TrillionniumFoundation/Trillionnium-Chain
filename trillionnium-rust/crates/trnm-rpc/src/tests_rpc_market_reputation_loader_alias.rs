use super::*;

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
fn market_reputation_loader_collapses_non_ascii_whitespace_aliases() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_market_reputation_unicode_ws_{}_{}.json",
        std::process::id(),
        now_ms()
    ));
    fs::write(
        &path,
        "{\"worker\\u00a0a\": 10, \"worker a\": 27, \"worker\\u2003b\": -4}",
    )
    .expect("write unicode-whitespace reputation fixture");

    with_market_path_env(
        &[(
            MARKET_REPUTATION_FILE_ENV,
            Some(path.to_string_lossy().as_ref()),
        )],
        || {
            let rep = load_market_reputation();
            assert_eq!(rep.get("worker a"), Some(&27));
            assert_eq!(rep.get("worker b"), Some(&-4));
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
