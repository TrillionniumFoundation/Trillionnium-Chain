use super::*;

#[test]
fn reliability_store_mode_defaults_to_sqlite_and_keeps_memory_override() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("RELIABILITY_STORE");
    assert_eq!(
        ReliabilityStoreMode::from_env(),
        ReliabilityStoreMode::Sqlite
    );

    std::env::set_var("RELIABILITY_STORE", "memory");
    assert_eq!(
        ReliabilityStoreMode::from_env(),
        ReliabilityStoreMode::Memory
    );

    // Noisy quoted values are common in env templating; accept canonical
    // mode tokens after trimming quote wrappers.
    std::env::set_var("RELIABILITY_STORE", "  'memory'  ");
    assert_eq!(
        ReliabilityStoreMode::from_env(),
        ReliabilityStoreMode::Memory
    );

    // Mismatched quotes are malformed and should fail closed to sqlite.
    std::env::set_var("RELIABILITY_STORE", "\"memory'");
    assert_eq!(
        ReliabilityStoreMode::from_env(),
        ReliabilityStoreMode::Sqlite
    );

    std::env::remove_var("RELIABILITY_STORE");
}

#[test]
fn reliability_db_path_prefers_explicit_env_and_has_stable_fallback() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::set_var("RELIABILITY_DB_PATH", "/tmp/explicit-reliability.sqlite");
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("/tmp/explicit-reliability.sqlite")
    );

    std::env::set_var(
        "RELIABILITY_DB_PATH",
        "  \"/tmp/quoted-reliability.sqlite\"  ",
    );
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("/tmp/quoted-reliability.sqlite")
    );

    std::env::remove_var("RELIABILITY_DB_PATH");
    std::env::set_var("STATE_DIRECTORY", " /tmp/systemd-state ");
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("/tmp/systemd-state/reliability.sqlite")
    );

    // Mismatched quote wrappers are malformed and must not leak literal
    // quote characters into filesystem paths.
    std::env::set_var("RELIABILITY_DB_PATH", "\"/tmp/mixed.sqlite'");
    std::env::set_var("XDG_STATE_HOME", "/tmp/state-home");
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("/tmp/systemd-state/reliability.sqlite")
    );

    // Noisy single-quote values should be treated as invalid input and
    // fall back safely instead of slicing panic.
    std::env::set_var("RELIABILITY_DB_PATH", "'");
    std::env::set_var("STATE_DIRECTORY", "'");
    std::env::remove_var("XDG_STATE_HOME");
    std::env::remove_var("HOME");
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("run/reliability/reliability.sqlite")
    );

    std::env::remove_var("RELIABILITY_DB_PATH");
    std::env::remove_var("STATE_DIRECTORY");
    std::env::remove_var("XDG_STATE_HOME");
    std::env::remove_var("HOME");
    assert_eq!(
        default_reliability_db_path(),
        PathBuf::from("run/reliability/reliability.sqlite")
    );
}

#[test]
fn retry_config_is_sanitized_to_prevent_zero_delay_retry_spin() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 0,
            max_backoff_ms: 0,
            ..RetryConfig::default()
        },
    );

    assert_eq!(engine.retry.base_backoff_ms, 1);
    assert_eq!(engine.retry.max_backoff_ms, 1);
}

#[test]
fn retry_config_sanitizes_zero_attempt_and_circuit_thresholds() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 10,
            max_backoff_ms: 10,
            max_attempts: 0,
            circuit_breaker_threshold: 0,
            circuit_open_ms: 0,
        },
    );

    assert_eq!(engine.retry.max_attempts, 1);
    assert_eq!(engine.retry.circuit_breaker_threshold, 1);
    assert_eq!(engine.retry.circuit_open_ms, 10);
}

#[test]
fn retry_config_clamps_max_backoff_to_base_floor() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 25,
            max_backoff_ms: 5,
            ..RetryConfig::default()
        },
    );

    assert_eq!(engine.retry.base_backoff_ms, 25);
    assert_eq!(engine.retry.max_backoff_ms, 25);
}

#[test]
fn retry_config_clamps_circuit_open_window_to_base_floor() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 50,
            max_backoff_ms: 100,
            circuit_open_ms: 10,
            ..RetryConfig::default()
        },
    );

    assert_eq!(engine.retry.base_backoff_ms, 50);
    assert_eq!(engine.retry.circuit_open_ms, 50);
}

#[test]
fn retention_config_sanitizes_zero_cleanup_interval() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 1_000,
            pending_ttl_ms: 1_000,
            cleanup_interval_ms: 0,
        },
    );

    assert_eq!(engine.retention.cleanup_interval_ms, 1);
}

#[test]
fn retention_config_sanitizes_zero_ttls_to_preserve_idempotency_and_retry_state() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 0,
            pending_ttl_ms: 0,
            cleanup_interval_ms: 1_000,
        },
    );

    assert_eq!(engine.retention.dedup_ttl_ms, 1);
    assert_eq!(engine.retention.pending_ttl_ms, 1);
}
