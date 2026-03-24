pub(crate) use super::*;

#[test]
fn faucet_env_parsing_enforces_minimums() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "0");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "0");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, FAUCET_WINDOW_SECONDS_MIN);
    assert_eq!(max_requests, FAUCET_MAX_REQUESTS_MIN);

    clear_faucet_env();
}

#[test]
fn faucet_env_parsing_uses_defaults_for_invalid_values() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "bad");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "bad");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, FAUCET_WINDOW_SECONDS_DEFAULT);
    assert_eq!(max_requests, FAUCET_MAX_REQUESTS_DEFAULT);

    clear_faucet_env();
}

#[test]
fn faucet_env_parsing_accepts_surrounding_whitespace() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "  120  ");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "\t9\n");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, 120);
    assert_eq!(max_requests, 9);

    clear_faucet_env();
}
