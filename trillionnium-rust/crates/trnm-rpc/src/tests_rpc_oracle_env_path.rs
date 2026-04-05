use super::*;

#[test]
fn normalized_path_from_env_trims_shell_wrapped_quotes() {
    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("  \"/tmp/tasks.jsonl\"  "),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[("TRNM_RPC_MARKET_TASKS_FILE", Some("'`/tmp/tasks.jsonl`'"))],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("  \"/tmp/tasks.jsonl\"   # replay note "),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("\u{feff}  \"/tmp/tasks.jsonl\"   # replay note from archived index env "),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("\r\n  \u{feff}\"/tmp/tasks.jsonl\"# replay note from archived index env after CRLF"),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("\"/tmp/tasks.jsonl\"  \u{feff}# replay note after BOM spacer"),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("\"/tmp/tasks.jsonl\"# replay note without separator space"),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(&[("TRNM_RPC_MARKET_TASKS_FILE", Some(" # comment only "))], || {
        assert_eq!(normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"), None);
    });
}

#[test]
fn market_path_file_helpers_fallback_when_env_is_empty_after_trim() {
    with_market_path_env(
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", Some("   ")),
            ("TRNM_RPC_MARKET_BIDS_FILE", Some(" \"\" ")),
            ("TRNM_RPC_INGRESS_FILE", Some(" `   ` ")),
            (MARKET_REPUTATION_FILE_ENV, Some("  ''  ")),
        ],
        || {
            assert_eq!(
                market_tasks_file(),
                run_root().join("run/market/tasks.jsonl")
            );
            assert_eq!(market_bids_file(), run_root().join("run/market/bids.jsonl"));
            assert_eq!(
                ingress_file(),
                run_root().join("run/message-gateway/requests.jsonl")
            );
            assert_eq!(
                market_reputation_file(),
                run_root().join("run/market/reputation.json")
            );
        },
    );
}

#[test]
fn rpc_state_paths_use_same_wrapped_env_and_empty_fallback_rules() {
    let _guard = lock_env();
    let keys = [
        "TRNM_RPC_ACCOUNTS_FILE",
        "TRNM_RPC_TX_FILE",
        "TRNM_RPC_FAUCET_LIMITS_FILE",
    ];
    let prev: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
        .collect();

    unsafe {
        std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"/tmp/accounts.json\"  ");
        std::env::set_var("TRNM_RPC_TX_FILE", " '`/tmp/txs.json`' ");
        std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", "  /tmp/faucet_limits.json  ");
    }
    assert_eq!(account_state_file(), PathBuf::from("/tmp/accounts.json"));
    assert_eq!(tx_lifecycle_file(), PathBuf::from("/tmp/txs.json"));
    assert_eq!(
        faucet_limits_file(),
        PathBuf::from("/tmp/faucet_limits.json")
    );

    unsafe {
        std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"\"  ");
        std::env::set_var("TRNM_RPC_TX_FILE", "  ''  ");
        std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", " `   ` ");
    }
    assert_eq!(
        account_state_file(),
        run_root().join("run/rpc/accounts.json")
    );
    assert_eq!(tx_lifecycle_file(), run_root().join("run/rpc/txs.json"));
    assert_eq!(
        faucet_limits_file(),
        run_root().join("run/rpc/faucet_limits.json")
    );

    for (k, v) in prev {
        match v {
            Some(val) => unsafe { std::env::set_var(&k, val) },
            None => unsafe { std::env::remove_var(&k) },
        }
    }
}
