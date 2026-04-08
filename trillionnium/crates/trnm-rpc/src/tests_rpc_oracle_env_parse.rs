use super::*;

#[test]
fn env_u64_with_min_accepts_wrapped_values_and_empty_fallback() {
    let _guard = lock_env();
    let key = "TRNM_RPC_TEST_ENV_U64_WITH_MIN";
    let prev = std::env::var(key).ok();

    unsafe { std::env::set_var(key, "  \"12\"  ") };
    assert_eq!(env_u64_with_min(key, 8, 1), 12);

    unsafe { std::env::set_var(key, "  ''  ") };
    assert_eq!(env_u64_with_min(key, 8, 1), 8);

    unsafe { std::env::set_var(key, "  `0`  ") };
    assert_eq!(env_u64_with_min(key, 8, 3), 3);

    match prev {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
}
