use super::*;

#[test]
fn acquire_market_file_lock_cleans_stale_lock_file() {
    let _guard = lock_env();
    let prev = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();
    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "1000") };

    let path = unique_tmp_path("market-lock", "jsonl");
    let lock_path = market_lock_path(&path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    fs::write(&lock_path, "stale").expect("seed stale lock");
    // Use extra margin above the 1000ms stale threshold to avoid filesystem
    // timestamp granularity edge-cases on slower CI runners.
    std::thread::sleep(Duration::from_millis(1200));

    {
        let _lock = acquire_market_file_lock(&path).expect("acquire cleans stale lock");
        assert!(lock_path.exists());
    }
    assert!(!lock_path.exists());

    match prev {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
    }
}

#[test]
fn acquire_market_file_lock_respects_timeout_when_lock_is_live() {
    let _guard = lock_env();
    let prev_timeout = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();
    let prev_stale = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();

    unsafe {
        // Keep timeout short for deterministic gate speed.
        std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "100");
        // Treat existing lock as live (not stale) for this check.
        std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "60000");
    }

    let path = unique_tmp_path("market-lock-timeout", "jsonl");
    let lock_path = market_lock_path(&path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    fs::write(&lock_path, "live").expect("seed live lock");

    let start = Instant::now();
    let err = match acquire_market_file_lock(&path) {
        Ok(_) => panic!("lock should time out while live lock exists"),
        Err(err) => err,
    };
    let elapsed = start.elapsed();
    let msg = err.to_string();

    assert!(msg.contains("timed out waiting for market file lock"));
    // Sleep interval is 10ms; allow scheduler jitter plus occasional heavily-loaded
    // CI runners while still catching hangs/regressions that overshoot timeout badly.
    let timeout_ms = market_lock_timeout_ms();
    let lower_bound_ms = timeout_ms.saturating_sub(10);
    let upper_bound_ms = timeout_ms.saturating_mul(8).saturating_add(200);
    assert!(elapsed >= Duration::from_millis(lower_bound_ms));
    assert!(elapsed < Duration::from_millis(upper_bound_ms));

    let _ = fs::remove_file(&lock_path);

    match prev_timeout {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
    }
    match prev_stale {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
    }
}

#[test]
fn market_lock_timeout_ms_uses_wrapped_env_with_clamp_and_fallback() {
    let _guard = lock_env();
    let prev = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();

    unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  `50`  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MIN);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  \"70000\"  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MAX);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  not-a-number  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

    match prev {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
    }
}
