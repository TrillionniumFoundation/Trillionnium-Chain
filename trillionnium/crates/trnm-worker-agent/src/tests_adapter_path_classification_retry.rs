use super::*;

#[test]
fn tx_retry_policy_mixes_partial_cli_overrides_with_env_fallbacks() {
    let policy = resolve_tx_retry_policy_from_sources(Some(1), None, Some(" 4\n"), Some("\t250 "));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 1,
            backoff_ms: 250,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(None, Some(0), Some(" 4\n"), Some("\t250 "));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 4,
            backoff_ms: 0,
        }
    );
}

#[test]
fn tx_retry_policy_strips_invisible_fillers_around_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\u{200b}6\u{2060}"),
        Some("\u{feff}375\u{200d}"),
    );
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 6,
            backoff_ms: 375,
        }
    );
}

#[test]
fn tx_retry_policy_treats_invisible_filler_only_env_values_as_missing() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\u{200b}\u{2060}\u{feff}"),
        Some("\u{200d}\u{200e}\u{200f}"),
    );
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_retry_policy_strips_bidi_isolates_and_variation_selectors_inside_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\u{2066}1\u{fe0f}2\u{2069}"),
        Some("\u{2068}4\u{fe0e}5\u{2067}0\u{2069}"),
    );
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 12,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_falls_back_per_field_when_other_env_value_is_invisible_filler_only() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\u{200b}\u{2060}\u{feff}"),
        Some("450"),
    );
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: 450,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("6"),
        Some("\u{200d}\u{200e}\u{200f}"),
    );
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 6,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_backoff_delay_saturates_without_overflow() {
    assert_eq!(backoff_delay_ms(25, 0), 25);
    assert_eq!(backoff_delay_ms(25, 1), 50);
    assert_eq!(backoff_delay_ms(25, 2), 100);
    assert_eq!(backoff_delay_ms(0, u32::MAX), 0);

    // Very large attempts should saturate rather than overflow/panic.
    assert_eq!(backoff_delay_ms(u64::MAX, 1), u64::MAX);
    assert_eq!(backoff_delay_ms(1_000_000, 62), u64::MAX);
    assert_eq!(backoff_delay_ms(1, 63), 1u64 << 63);
    assert_eq!(
        backoff_delay_ms(1, 64),
        u64::MAX,
        "attempts beyond the last exact shift must saturate for non-zero base"
    );
    assert_eq!(
        backoff_delay_ms(1_000_000, u32::MAX),
        u64::MAX,
        "attempts beyond the shift cap must stay saturated"
    );
}

#[test]
fn exp_backoff_delay_saturates_without_overflow() {
    assert_eq!(exp_backoff_delay_ms(25, 0), 25);
    assert_eq!(exp_backoff_delay_ms(25, 1), 50);
    assert_eq!(exp_backoff_delay_ms(25, 2), 100);
    assert_eq!(exp_backoff_delay_ms(0, u32::MAX), 0);

    // Very large attempts should saturate rather than overflow/panic.
    assert_eq!(exp_backoff_delay_ms(u64::MAX, 1), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1_000_000, 62), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1, 63), 1u64 << 63);
    assert_eq!(
        exp_backoff_delay_ms(1, 64),
        u64::MAX,
        "attempts beyond the last exact shift must saturate for non-zero base"
    );
    assert_eq!(
        exp_backoff_delay_ms(1_000_000, u32::MAX),
        u64::MAX,
        "attempts beyond the shift cap must stay saturated"
    );
}

#[test]
fn tx_backoff_delay_stays_monotonic_across_shift_cap_and_saturation() {
    let delays = [
        backoff_delay_ms(1, 62),
        backoff_delay_ms(1, 63),
        backoff_delay_ms(1, 64),
        backoff_delay_ms(3, 63),
        backoff_delay_ms(3, 64),
        backoff_delay_ms(3, u32::MAX),
    ];

    assert_eq!(delays[0], 1u64 << 62);
    assert_eq!(delays[1], 1u64 << 63);
    assert_eq!(delays[2], u64::MAX);
    assert_eq!(delays[3], 3u64.saturating_mul(1u64 << 63));
    assert_eq!(delays[4], u64::MAX);
    assert_eq!(delays[5], u64::MAX);
    assert!(
        delays.windows(2).all(|pair| pair[0] <= pair[1]),
        "backoff must remain monotonic across the shift cap: {delays:?}"
    );
}

#[test]
fn exp_backoff_delay_stays_monotonic_across_shift_cap_and_saturation() {
    let delays = [
        exp_backoff_delay_ms(1, 62),
        exp_backoff_delay_ms(1, 63),
        exp_backoff_delay_ms(1, 64),
        exp_backoff_delay_ms(3, 63),
        exp_backoff_delay_ms(3, 64),
        exp_backoff_delay_ms(3, u32::MAX),
    ];

    assert_eq!(delays[0], 1u64 << 62);
    assert_eq!(delays[1], 1u64 << 63);
    assert_eq!(delays[2], u64::MAX);
    assert_eq!(delays[3], 3u64.saturating_mul(1u64 << 63));
    assert_eq!(delays[4], u64::MAX);
    assert_eq!(delays[5], u64::MAX);
    assert!(
        delays.windows(2).all(|pair| pair[0] <= pair[1]),
        "exp backoff must remain monotonic across the shift cap: {delays:?}"
    );
}

#[test]
fn run_adapter_with_retry_prefers_latest_nonce_rejected_receipt_hash_and_stops() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-nonce-rejected-newest-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234' if count == 0 else 'tx_hash=0xBEEF5678', file=sys.stderr); raise SystemExit(1 if count == 0 else 10)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal nonce_rejected result with the latest receipt hash");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "nonce_rejected on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_nonce_rejected_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-nonce-rejected-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else (print('tx_hash=0xBEEF5678') or print('tx_hash=0xDEADBEEF', file=sys.stderr)); raise SystemExit(1 if count == 0 else 10)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should return terminal nonce_rejected result with stdout precedence",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "nonce_rejected on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_falls_back_to_stderr_tx_hash_when_stdout_nonce_rejected_hash_is_malformed(
) {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-nonce-rejected-stderr-fallback-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else (print('tx_hash=0xBAD-HASH') or print('tx_hash=0xBEEF5678', file=sys.stderr)); raise SystemExit(1 if count == 0 else 10)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should preserve stderr fallback when stdout nonce_rejected hash is malformed");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "nonce_rejected on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_latest_slo_violation_receipt_hash_and_stops() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-violation-newest-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234' if count == 0 else 'tx_hash=0xBEEF5678', file=sys.stderr); raise SystemExit(1 if count == 0 else 11)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal slo_violation result with the latest receipt hash");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "slo_violation on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_SLO_VIOLATION);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_slo_violation_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-violation-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else (print('tx_hash=0xBEEF5678') or print('tx_hash=0xDEADBEEF', file=sys.stderr)); raise SystemExit(1 if count == 0 else 11)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should return terminal slo_violation result with stdout precedence",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "slo_violation on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_SLO_VIOLATION);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_ignores_malformed_nonce_rejected_receipt_hash_and_keeps_last_seen_hash() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-nonce-malformed-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xBAD-HASH', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 10)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal nonce_rejected result while preserving the last valid receipt hash");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "nonce_rejected on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("abcd1234"),
        "malformed nonce_rejected receipt hashes must not clobber the last valid tx hash"
    );
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_zero_backoff_retries_successfully() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-zero-backoff-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); raise SystemExit(1 if count == 0 else 0)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 1, 0)
        .expect("zero-backoff retry should succeed on the second attempt");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "max_retries=1 should execute two attempts"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_stops_after_retriable_failure_followed_by_deterministic_rejection() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_adapter_with_retry_inner(
        3,
        25,
        || {
            attempt += 1;
            if attempt == 1 {
                Ok(std::process::Command::new("python3")
                    .args([
                        "-c",
                        "print('tx_hash=0xABCD1234', file=__import__('sys').stderr); raise SystemExit(1)",
                    ])
                    .output()
                    .expect("python3 retriable probe should run"))
            } else {
                Ok(std::process::Command::new("python3")
                    .args([
                        "-c",
                        "print('tx_hash=0xBEEF5678'); raise SystemExit(10)",
                    ])
                    .output()
                    .expect("python3 deterministic rejection probe should run"))
            }
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .expect("adapter execution should stop once the deterministic rejection is observed");

    assert_eq!(
        attempt, 2,
        "retry loop should stop immediately after the terminal rejection"
    );
    assert_eq!(
        slept,
        vec![25],
        "sleep should happen only before the second attempt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn llm_adapter_retry_succeeds_within_budget() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_llm_adapter_with_retry_inner(
        2,
        50,
        || {
            attempt += 1;
            if attempt < 3 {
                Err(AdapterError {
                    kind: AdapterErrorKind::Retriable,
                    context: format!("transient-{}", attempt),
                })
            } else {
                Ok(LlmAdapterResponse {
                    output_text: "ok".to_string(),
                    provider_request_id: None,
                    provider: None,
                    model: None,
                    adapter: None,
                    agent_protocol: None,
                    compliance_profile: None,
                })
            }
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap();

    assert_eq!(res.output_text, "ok");
    assert_eq!(attempt, 3);
    assert_eq!(slept, vec![50, 100]);
}

#[test]
fn llm_adapter_retry_budget_exhausted_returns_last_error() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let err = run_llm_adapter_with_retry_inner(
        2,
        20,
        || {
            attempt += 1;
            Err(AdapterError {
                kind: AdapterErrorKind::Retriable,
                context: format!("timeout-{}", attempt),
            })
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap_err();

    assert_eq!(attempt, 3);
    assert_eq!(slept, vec![20, 40]);
    assert_eq!(err.kind, AdapterErrorKind::Retriable);
    assert_eq!(err.context, "timeout-3");
}

#[test]
fn llm_adapter_non_retriable_fails_fast() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let err = run_llm_adapter_with_retry_inner(
        5,
        20,
        || {
            attempt += 1;
            Err(AdapterError {
                kind: AdapterErrorKind::NonRetriable,
                context: "invalid-json".to_string(),
            })
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap_err();

    assert_eq!(attempt, 1);
    assert!(slept.is_empty());
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert_eq!(err.context, "invalid-json");
}
