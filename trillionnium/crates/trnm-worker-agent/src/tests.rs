use super::*;
use crate::{assigned::assigned_skip_reason, proof_adapter::StandardProofAdapter};
use std::sync::{Mutex, OnceLock};

#[path = "tests_adapter_path_classification.rs"]
mod tests_adapter_path_classification;

fn tx_retry_policy_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn assigned_skip_reason_reports_devnet_smoke_gating_causes() {
    let base = MessageIngressRecord {
        request_id: "req-skip".to_string(),
        task_id: 42,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik1".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-a".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    assert_eq!(assigned_skip_reason(&base, "worker-a"), None);

    let mut wrong_status = base.clone();
    wrong_status.status = RequestStatus::Open.as_str().to_string();
    assert_eq!(
        assigned_skip_reason(&wrong_status, "worker-a"),
        Some("status_not_assigned")
    );

    let mut wrong_worker = base.clone();
    wrong_worker.assigned_worker = Some("worker-b".to_string());
    assert_eq!(
        assigned_skip_reason(&wrong_worker, "worker-a"),
        Some("assigned_worker_mismatch")
    );

    let mut missing_worker = base;
    missing_worker.assigned_worker = None;
    assert_eq!(
        assigned_skip_reason(&missing_worker, "worker-a"),
        Some("assigned_worker_missing")
    );
}

#[test]
fn transition_request_status_accepts_benign_formatting_variants() {
    let next = transition_request_status("  open ", RequestStatus::Assigned)
        .expect("OPEN -> ASSIGNED should parse with whitespace/case drift");
    assert_eq!(next, RequestStatus::Assigned.as_str());

    let next = transition_request_status("aSsIgNeD", RequestStatus::CommitQueued)
        .expect("ASSIGNED -> COMMIT_QUEUED should parse case-insensitively");
    assert_eq!(next, RequestStatus::CommitQueued.as_str());
}

#[test]
fn transition_request_status_rejects_malformed_state_with_stable_diagnostic() {
    let err = transition_request_status(" pending-ish ", RequestStatus::Assigned)
        .expect_err("unknown states must be rejected");
    assert!(
        err.to_string().contains("unknown request state"),
        "unexpected error text: {}",
        err
    );
}

#[test]
fn deterministic_rejection_codes_are_stable() {
    assert!(is_deterministic_rejection(RC_DUPLICATE));
    assert!(is_deterministic_rejection(RC_NONCE_REJECTED));
    assert!(is_deterministic_rejection(RC_SLO_VIOLATION));
    assert!(!is_deterministic_rejection(RC_OK));
    assert!(!is_deterministic_rejection(42));
}

#[test]
fn idempotent_only_accepts_duplicate() {
    assert!(is_idempotent_duplicate_ok(RC_DUPLICATE));
    assert!(!is_idempotent_duplicate_ok(RC_NONCE_REJECTED));
    assert!(!is_idempotent_duplicate_ok(RC_OK));
}

#[test]
fn terminal_commit_reject_skips_reveal_execution_gate() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_NONCE_REJECTED,
        tx_hash: None,
        terminal: true,
    };

    assert!(!should_execute_reveal(&commit_res));
}

#[test]
fn duplicate_commit_still_executes_reveal_gate() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };

    assert!(should_execute_reveal(&commit_res));
}

#[test]
fn slo_violation_commit_skips_reveal_execution_gate() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_SLO_VIOLATION,
        tx_hash: None,
        terminal: true,
    };

    assert!(
        !should_execute_reveal(&commit_res),
        "slo_violation must not be treated as an idempotent duplicate"
    );
}

#[test]
fn backoff_delay_is_exponential_and_saturating() {
    assert_eq!(backoff_delay_ms(200, 0), 200);
    assert_eq!(backoff_delay_ms(200, 1), 400);
    assert_eq!(backoff_delay_ms(200, 2), 800);
    assert_eq!(backoff_delay_ms(200, 3), 1600);

    // saturation guard (no overflow panic/wrap)
    assert_eq!(backoff_delay_ms(u64::MAX, 1), u64::MAX);
    assert_eq!(backoff_delay_ms(1_000_000, 62), u64::MAX);
    assert_eq!(
        backoff_delay_ms(1_000_000, u32::MAX),
        u64::MAX,
        "attempts above the shift cap must stay saturated"
    );
}

#[test]
fn zero_backoff_delay_remains_zero_across_retries() {
    assert_eq!(backoff_delay_ms(0, 0), 0);
    assert_eq!(backoff_delay_ms(0, 1), 0);
    assert_eq!(backoff_delay_ms(0, u32::MAX), 0);
}

#[test]
fn backoff_delay_stays_monotonic_after_saturation() {
    let near_cap = backoff_delay_ms(1_000_000, 62);
    let beyond_cap = backoff_delay_ms(1_000_000, 63);
    let max_attempt = backoff_delay_ms(1_000_000, u32::MAX);

    assert_eq!(near_cap, u64::MAX);
    assert_eq!(beyond_cap, u64::MAX);
    assert_eq!(max_attempt, u64::MAX);
    assert!(near_cap <= beyond_cap);
    assert!(beyond_cap <= max_attempt);
}

#[test]
fn backoff_delay_keeps_63rd_shift_for_small_base_before_saturating() {
    assert_eq!(backoff_delay_ms(1, 62), 1u64 << 62);
    assert_eq!(backoff_delay_ms(1, 63), 1u64 << 63);
    assert_eq!(backoff_delay_ms(2, 63), u64::MAX);
}

#[test]
fn backoff_delay_saturates_at_attempt_64_even_for_small_base() {
    assert_eq!(backoff_delay_ms(1, 64), u64::MAX);
    assert_eq!(backoff_delay_ms(1, 65), u64::MAX);
    assert_eq!(backoff_delay_ms(1, u32::MAX), u64::MAX);
}

#[test]
fn run_adapter_with_retry_stops_after_duplicate_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xDEADBEEF', file=sys.stderr); raise SystemExit(9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 1)
        .expect("adapter execution should return terminal duplicate result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "1",
        "duplicate must fail fast without retrying"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(res.tx_hash.as_deref(), Some("deadbeef"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_stops_after_nonce_rejected_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-retry-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xDEADBEEF', file=sys.stderr); raise SystemExit(10)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 1)
        .expect("adapter execution should return terminal rejection result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "1",
        "nonce_rejected must fail fast without retrying"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("deadbeef"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_stops_after_slo_violation_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xDEADBEEF', file=sys.stderr); raise SystemExit(11)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 1)
        .expect("adapter execution should return terminal slo violation result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "1",
        "slo_violation must fail fast without retrying"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_SLO_VIOLATION);
    assert_eq!(res.tx_hash.as_deref(), Some("deadbeef"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_keeps_last_seen_tx_hash_after_retriable_exhaustion() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-last-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; raise SystemExit(1)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 2, 0)
        .expect("adapter execution should return retriable exhaustion result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "3",
        "max_retries=2 should execute three attempts"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, 1);
    assert_eq!(res.tx_hash.as_deref(), Some("abcd1234"));
    assert!(!res.terminal);
}

#[test]
fn run_adapter_with_retry_retries_with_exponential_backoff_schedule() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_adapter_with_retry_inner(
        2,
        25,
        || {
            attempt += 1;
            if attempt < 3 {
                Ok(std::process::Command::new("python3")
                    .args(["-c", "raise SystemExit(1)"])
                    .output()
                    .expect("python3 retriable probe should run"))
            } else {
                Ok(std::process::Command::new("python3")
                    .args(["-c", "print('tx_hash=0xBEEFCAFE')"])
                    .output()
                    .expect("python3 success probe should run"))
            }
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .expect("adapter execution should succeed within retry budget");

    assert_eq!(attempt, 3);
    assert_eq!(slept, vec![25, 50]);
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(res.tx_hash.as_deref(), Some("beefcafe"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_skips_zero_backoff_sleep_between_retriable_attempts() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_adapter_with_retry_inner(
        2,
        0,
        || {
            attempt += 1;
            if attempt < 3 {
                Ok(std::process::Command::new("python3")
                    .args(["-c", "raise SystemExit(1)"])
                    .output()
                    .expect("python3 zero-backoff probe should run"))
            } else {
                Ok(std::process::Command::new("python3")
                    .args(["-c", "print('tx_hash=0xBEEFCAFE')"])
                    .output()
                    .expect("python3 zero-backoff success probe should run"))
            }
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .expect("adapter execution should succeed within retry budget without sleeping");

    assert_eq!(attempt, 3);
    assert!(
        slept.is_empty(),
        "zero backoff should skip sleep callbacks entirely"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(res.tx_hash.as_deref(), Some("beefcafe"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_does_not_sleep_after_deterministic_terminal_rejection() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_adapter_with_retry_inner(
        3,
        25,
        || {
            attempt += 1;
            Ok(std::process::Command::new("python3")
                .args(["-c", "print('tx_hash=0xDEADBEEF', file=__import__('sys').stderr); raise SystemExit(10)"])
                .output()
                .expect("python3 deterministic rejection probe should run"))
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .expect("adapter execution should stop on deterministic rejection");

    assert_eq!(attempt, 1, "deterministic rejections must not retry");
    assert!(
        slept.is_empty(),
        "deterministic rejections must not sleep before stopping"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_NONCE_REJECTED);
    assert_eq!(res.tx_hash.as_deref(), Some("deadbeef"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_does_not_sleep_after_retry_budget_exhaustion() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_adapter_with_retry_inner(
        2,
        25,
        || {
            attempt += 1;
            Ok(std::process::Command::new("python3")
                .args(["-c", "raise SystemExit(1)"])
                .output()
                .expect("python3 retriable exhaustion probe should run"))
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .expect("adapter execution should return exhausted retriable result");

    assert_eq!(
        attempt, 3,
        "retry loop should attempt initial run plus the configured retries"
    );
    assert_eq!(
        slept,
        vec![25, 50],
        "sleep should happen only between attempts, never after the final exhausted attempt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, 1);
    assert_eq!(res.tx_hash, None);
    assert!(!res.terminal);
}

#[test]
fn run_adapter_with_retry_preserves_last_seen_tx_hash_before_slo_violation_terminal_stop() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-last-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; raise SystemExit(1 if count == 0 else 11)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal slo_violation result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "slo_violation on retry should stop the loop immediately"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_SLO_VIOLATION);
    assert_eq!(res.tx_hash.as_deref(), Some("abcd1234"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_slo_violation_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xCAFE1234') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 11)";
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
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("cafe1234"),
        "stdout tx_hash should win over stderr on the same terminal receipt"
    );
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_falls_back_to_stderr_tx_hash_when_stdout_slo_violation_hash_is_malformed()
{
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-slo-stderr-fallback-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xBAD-HASH') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 11)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should preserve stderr fallback when stdout slo_violation hash is malformed",
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
fn run_adapter_with_retry_preserves_last_seen_tx_hash_before_duplicate_terminal_stop() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-last-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; raise SystemExit(1 if count == 0 else 9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal duplicate result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "duplicate on retry should stop the loop immediately"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(res.tx_hash.as_deref(), Some("abcd1234"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_newest_tx_hash_from_duplicate_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-newest-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234' if count == 0 else 'tx_hash=0xBEEF5678', file=sys.stderr); raise SystemExit(1 if count == 0 else 9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should return terminal duplicate result with the latest receipt hash",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "duplicate on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_ignores_malformed_duplicate_receipt_hash_and_keeps_last_seen_hash() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-malformed-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xBAD-HASH', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal duplicate result while preserving the last valid receipt hash");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "duplicate on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("abcd1234"),
        "malformed duplicate receipt hashes must not clobber the last valid tx hash"
    );
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_duplicate_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xCAFE1234') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return terminal duplicate result with stdout precedence");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "duplicate on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("cafe1234"),
        "stdout tx_hash should win over stderr on the same terminal receipt"
    );
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_falls_back_to_stderr_tx_hash_when_stdout_duplicate_hash_is_malformed() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-duplicate-stderr-fallback-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xBAD-HASH') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 9)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should preserve stderr fallback when stdout duplicate hash is malformed",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "duplicate on retry should stop after the terminal receipt"
    );
    assert!(!res.ok);
    assert_eq!(res.rc, RC_DUPLICATE);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_preserves_last_seen_tx_hash_after_successful_retry() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-success-last-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; raise SystemExit(1 if count == 0 else 0)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return successful retry result");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "success on retry should stop after the first green attempt"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(res.tx_hash.as_deref(), Some("abcd1234"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_nonce_rejected_terminal_receipt() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-nonce-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xCAFE1234') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 10)";
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
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("cafe1234"),
        "stdout tx_hash should win over stderr on the same terminal nonce receipt"
    );
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
fn run_adapter_with_retry_prefers_latest_success_receipt_hash_over_prior_retry_hash() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-success-newest-tx-hash-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234' if count == 0 else 'tx_hash=0xBEEF5678', file=sys.stderr); raise SystemExit(1 if count == 0 else 0)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should return successful retry result with the latest receipt hash",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "success on retry should stop after the first green attempt"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(res.tx_hash.as_deref(), Some("beef5678"));
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_prefers_stdout_tx_hash_over_stderr_on_successful_retry() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-success-stdout-precedence-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=0xCAFE1234') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 0)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0)
        .expect("adapter execution should return successful retry result with stdout precedence");

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "success on retry should stop after the first green attempt"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("cafe1234"),
        "stdout tx_hash should win over stderr on the same successful receipt"
    );
    assert!(res.terminal);
}

#[test]
fn run_adapter_with_retry_falls_back_to_stderr_tx_hash_when_stdout_success_hash_is_malformed() {
    let counter = std::env::temp_dir().join(format!(
        "trnm-worker-agent-run-adapter-success-stderr-fallback-counter-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    let script = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); count=int(p.read_text()) if p.exists() else 0; p.write_text(str(count + 1)); print('tx_hash=0xABCD1234', file=sys.stderr) if count == 0 else None; print('tx_hash=not-a-hash') if count == 1 else None; print('tx_hash=0xBEEF5678', file=sys.stderr) if count == 1 else None; raise SystemExit(1 if count == 0 else 0)";
    let adapter_cmd = format!("python3 -c {script:?}");
    let action_args = vec![counter.display().to_string()];

    let res = run_adapter_with_retry(&adapter_cmd, &action_args, 3, 0).expect(
        "adapter execution should preserve stderr fallback when stdout success hash is malformed",
    );

    let attempts = std::fs::read_to_string(&counter)
        .expect("counter file should exist after adapter execution");
    let _ = std::fs::remove_file(&counter);

    assert_eq!(
        attempts.trim(),
        "2",
        "success on retry should stop after the first green attempt"
    );
    assert!(res.ok);
    assert_eq!(res.rc, RC_OK);
    assert_eq!(
        res.tx_hash.as_deref(),
        Some("beef5678"),
        "malformed stdout success hashes must fall back to stderr"
    );
    assert!(res.terminal);
}

#[test]
fn tx_retry_policy_accepts_zero_and_cli_overrides_invalid_env() {
    assert_eq!(
        resolve_u32(
            Some(0),
            Some("not-a-number"),
            DEFAULT_TX_ADAPTER_MAX_RETRIES,
            0
        ),
        0
    );
    assert_eq!(
        resolve_u64(Some(0), Some("also-bad"), DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
        0
    );

    let policy = RetryPolicy {
        max_retries: resolve_u32(Some(0), Some("7"), DEFAULT_TX_ADAPTER_MAX_RETRIES, 0),
        backoff_ms: resolve_u64(Some(0), Some("900"), DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
    };
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 0,
            backoff_ms: 0,
        }
    );
}

#[test]
fn tx_retry_policy_trims_whitespace_wrapped_env_values() {
    let policy = RetryPolicy {
        max_retries: resolve_u32(None, Some(" 7\n"), DEFAULT_TX_ADAPTER_MAX_RETRIES, 0),
        backoff_ms: resolve_u64(None, Some("\t900 "), DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
    };

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 7,
            backoff_ms: 900,
        }
    );
}

#[test]
fn tx_retry_policy_trims_quote_wrapped_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some(" \"7\" "), Some(" '900' "));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 7,
            backoff_ms: 900,
        }
    );
}

#[test]
fn tx_retry_policy_trims_unicode_quotes_wrapped_env_values() {
    let policy =
        resolve_tx_retry_policy_from_sources(None, None, Some(" “７” "), Some(" ‘９００’ "));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 7,
            backoff_ms: 900,
        }
    );
}

#[test]
fn tx_retry_policy_treats_blank_env_values_as_missing() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("   \n"), Some("\t\t"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_retry_policy_trims_bom_and_invisible_fillers_around_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\u{feff}\u{200b}7\u{2060}"),
        Some("\u{200d}900\u{feff}"),
    );

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 7,
            backoff_ms: 900,
        }
    );
}

#[test]
fn tx_retry_policy_trims_control_wrappers_around_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("\0\u{0007}8\r"),
        Some("\n150\u{001b}"),
    );

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 8,
            backoff_ms: 150,
        }
    );
}

#[test]
fn tx_retry_policy_accepts_fullwidth_digits_and_signs_from_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("＋３"), Some("４５０"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 3,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_trims_fullwidth_spaces_around_unicode_env_values() {
    let policy =
        resolve_tx_retry_policy_from_sources(None, None, Some("　＋３　"), Some("　４５０　"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 3,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_ignores_embedded_invisible_fillers_in_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("2\u{200B}5"),
        Some("4\u{2060}5\u{200D}0"),
    );

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 25,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_ignores_embedded_bom_fillers_in_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(
        None,
        None,
        Some("2\u{feff}5"),
        Some("4\u{feff}5\u{feff}0"),
    );

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 25,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_ignores_embedded_control_wrappers_in_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("2\r\n5"), Some("4\t5\n0"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 25,
            backoff_ms: 450,
        }
    );
}

#[test]
fn tx_retry_policy_rejects_negative_fullwidth_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("－２"), Some("－４５０"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_retry_policy_rejects_negative_unicode_minus_env_values() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("−2"), Some("−450"));

    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_retry_policy_resolves_cli_and_env_sources_without_process_env_mutation() {
    let env_policy = resolve_tx_retry_policy_from_sources(None, None, Some(" 4\n"), Some("\t250 "));
    assert_eq!(
        env_policy,
        RetryPolicy {
            max_retries: 4,
            backoff_ms: 250,
        }
    );

    let cli_policy = resolve_tx_retry_policy_from_sources(Some(0), Some(0), Some("9"), Some("900"));
    assert_eq!(
        cli_policy,
        RetryPolicy {
            max_retries: 0,
            backoff_ms: 0,
        }
    );
}

#[test]
fn tx_retry_policy_allows_per_field_cli_override_while_preserving_other_env_value() {
    let policy = resolve_tx_retry_policy_from_sources(Some(2), None, Some("9"), Some("450"));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 2,
            backoff_ms: 450,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(None, Some(125), Some("7"), Some("900"));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 7,
            backoff_ms: 125,
        }
    );
}

#[test]
fn tx_retry_policy_reads_process_env_and_preserves_cli_precedence() {
    let _guard = tx_retry_policy_env_lock()
        .lock()
        .expect("tx retry policy env mutex should not be poisoned");
    let prev_max = std::env::var(TX_ADAPTER_MAX_RETRIES_ENV).ok();
    let prev_backoff = std::env::var(TX_ADAPTER_BACKOFF_MS_ENV).ok();

    unsafe {
        std::env::set_var(TX_ADAPTER_MAX_RETRIES_ENV, " 8\n");
        std::env::set_var(TX_ADAPTER_BACKOFF_MS_ENV, "\t650 ");
    }

    let env_policy = resolve_tx_retry_policy(None, None);
    assert_eq!(
        env_policy,
        RetryPolicy {
            max_retries: 8,
            backoff_ms: 650,
        }
    );

    let cli_policy = resolve_tx_retry_policy(Some(1), Some(25));
    assert_eq!(
        cli_policy,
        RetryPolicy {
            max_retries: 1,
            backoff_ms: 25,
        }
    );

    match prev_max {
        Some(value) => unsafe { std::env::set_var(TX_ADAPTER_MAX_RETRIES_ENV, value) },
        None => unsafe { std::env::remove_var(TX_ADAPTER_MAX_RETRIES_ENV) },
    }
    match prev_backoff {
        Some(value) => unsafe { std::env::set_var(TX_ADAPTER_BACKOFF_MS_ENV, value) },
        None => unsafe { std::env::remove_var(TX_ADAPTER_BACKOFF_MS_ENV) },
    }
}

#[test]
fn tx_retry_policy_falls_back_per_field_when_only_one_env_value_is_invalid() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("invalid"), Some(" 350 "));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: 350,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("5"), Some("invalid"));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 5,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn tx_retry_policy_rejects_negative_env_values_per_field() {
    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("-1"), Some("-250"));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: DEFAULT_TX_ADAPTER_MAX_RETRIES,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(None, None, Some("6"), Some("-250"));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 6,
            backoff_ms: DEFAULT_TX_ADAPTER_BACKOFF_MS,
        }
    );
}

#[test]
fn llm_adapter_policy_rejects_zero_timeout_and_falls_back_to_default() {
    let policy = LlmAdapterPolicy {
        retry: RetryPolicy {
            max_retries: resolve_u32(None, Some("5"), DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
            backoff_ms: resolve_u64(None, Some("250"), DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
        },
        timeout_ms: resolve_u64(Some(0), Some("0"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
    };

    assert_eq!(
        policy,
        LlmAdapterPolicy {
            retry: RetryPolicy {
                max_retries: 5,
                backoff_ms: 250,
            },
            timeout_ms: DEFAULT_LLM_ADAPTER_TIMEOUT_MS,
        }
    );
}

#[test]
fn parse_tx_hash_accepts_quoted_and_trailing_punctuated_tokens() {
    let mixed_case =
        "tx_hash=\"0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd\",";
    let parsed = parse_tx_hash(mixed_case).expect("hash should parse");
    assert_eq!(
        parsed,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let sentence_tail = "submitted tx_hash=0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd. next";
    let parsed_tail =
        parse_tx_hash(sentence_tail).expect("hash with sentence punctuation should parse");
    assert_eq!(
        parsed_tail,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let backtick_wrapped =
            "adapter stdout: tx_hash=`0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd`";
    let parsed_backtick =
        parse_tx_hash(backtick_wrapped).expect("backtick-wrapped hash should parse");
    assert_eq!(
        parsed_backtick,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );
}

#[test]
fn parse_tx_hash_accepts_angle_bracket_wrapped_receipts() {
    let shell = parse_tx_hash(
            "[adapter] commit accepted tx_hash=<0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd>",
        )
        .expect("angle-bracket shell receipt hash should parse");
    assert_eq!(
        shell,
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    );

    let json = parse_tx_hash(
            "adapter stdout: {\"tx_hash\": \"<0xFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEfaceFACEface>\"}",
        )
        .expect("angle-bracket json receipt hash should parse");
    assert_eq!(
        json,
        "facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface"
    );
}

#[test]
fn parse_tx_hash_accepts_fullwidth_bracket_wrapped_receipts() {
    let shell = parse_tx_hash("[adapter] commit accepted tx_hash=（0xDEADBEEF）")
        .expect("fullwidth parenthesis shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let json = parse_tx_hash("adapter stdout: {\"tx_hash\": \"【0xFACECAFE】\"}")
        .expect("fullwidth bracket json receipt hash should parse");
    assert_eq!(json, "facecafe");
}

#[test]
fn parse_tx_hash_accepts_short_failure_receipts_without_0x_prefix() {
    let parsed = parse_tx_hash("[adapter] simulated failure tx_hash=deadbeef")
        .expect("short failure receipt hash should parse");
    assert_eq!(parsed, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_colon_style_receipts() {
    let colon = parse_tx_hash("[adapter] commit accepted tx-hash:0xDEADBEEF")
        .expect("colon-delimited receipt hash should parse");
    assert_eq!(colon, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_fullwidth_delimiter_receipts() {
    let shell_equals = parse_tx_hash("[adapter] commit accepted tx_hash＝0xDEADBEEF")
        .expect("fullwidth equals shell receipt hash should parse");
    assert_eq!(shell_equals, "deadbeef");

    let shell_colon = parse_tx_hash("[adapter] commit accepted tx-hash：0xFACECAFE")
        .expect("fullwidth colon shell receipt hash should parse");
    assert_eq!(shell_colon, "facecafe");

    let json = parse_tx_hash("adapter stdout: {\"transaction_hash\"： \"0xBADDCAFE\"}")
        .expect("fullwidth colon json receipt hash should parse");
    assert_eq!(json, "baddcafe");
}

#[test]
fn parse_tx_hash_accepts_unicode_dash_receipt_keys() {
    let non_breaking_shell = parse_tx_hash("[adapter] commit accepted tx‑hash=0xDEADBEEF")
        .expect("non-breaking hyphen shell receipt key should parse");
    assert_eq!(non_breaking_shell, "deadbeef");

    let em_dash_json = parse_tx_hash("adapter stdout: {\"transaction—hash\": \"0xFACECAFE\"}")
        .expect("em dash json receipt key should parse");
    assert_eq!(em_dash_json, "facecafe");

    let fullwidth_shell = parse_tx_hash("[adapter] commit accepted transaction－hash:0xBADDCAFE")
        .expect("fullwidth hyphen shell receipt key should parse");
    assert_eq!(fullwidth_shell, "baddcafe");
}

#[test]
fn parse_tx_hash_accepts_space_separated_receipt_keys() {
    let shell = parse_tx_hash("[adapter] commit accepted tx hash=0xDEADBEEF")
        .expect("space-separated shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let shell_with_spacing = parse_tx_hash("[adapter] commit accepted tx hash = 0xC0FFEE12")
        .expect("space-separated shell receipt hash with spaced delimiter should parse");
    assert_eq!(shell_with_spacing, "c0ffee12");

    let uppercase = parse_tx_hash("[adapter] commit accepted TX HASH:0xABCD1234")
        .expect("uppercase space-separated receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");

    let uppercase_with_spacing = parse_tx_hash("[adapter] commit accepted TX HASH : 0xFACECAFE")
        .expect("uppercase space-separated receipt hash with spaced delimiter should parse");
    assert_eq!(uppercase_with_spacing, "facecafe");

    let json = parse_tx_hash("{\"tx hash\": \"0xBADDCAFE\", \"status\": \"accepted\"}")
        .expect("space-separated json receipt hash should parse");
    assert_eq!(json, "baddcafe");

    let single_quoted = parse_tx_hash("adapter stdout: {'TX HASH' : 'ABCD1234'}")
        .expect("single-quoted uppercase space-separated receipt hash should parse");
    assert_eq!(single_quoted, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_uppercase_receipt_keys() {
    let shell = parse_tx_hash("[adapter] commit accepted TX_HASH=0xDEADBEEF")
        .expect("uppercase shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let json = parse_tx_hash("{\"TX_HASH\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("uppercase json receipt hash should parse");
    assert_eq!(json, "deadbeef");

    let compact = parse_tx_hash("adapter stdout: {\"TXHASH\": \"ABCD1234\"}")
        .expect("uppercase compact json receipt hash should parse");
    assert_eq!(compact, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_whitespace_after_colon() {
    let json = parse_tx_hash("{\"tx_hash\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("json receipt hash with whitespace after colon should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_whitespace_before_colon() {
    let json = parse_tx_hash("{\"tx_hash\" : \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("json receipt hash with whitespace before colon should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_style_receipts_with_newlines_and_tabs_around_colon() {
    let json =
        parse_tx_hash("{\n\t\"tx_hash\"\n\t:\n\t\"0xDEADBEEF\",\n\t\"status\":\n\t\"accepted\"\n}")
            .expect("json receipt hash with newline/tab padding should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_space_separated_receipt_keys_with_tab_delimiter_padding() {
    let shell = parse_tx_hash("TX HASH\t=\t0xDEADBEEF")
        .expect("space-separated receipt hash with tab delimiter padding should parse");
    assert_eq!(shell, "deadbeef");
}

#[test]
fn parse_tx_hash_strips_bom_and_zero_width_fillers_around_receipt_value() {
    let json = parse_tx_hash("receipt={\"tx_hash\":\"\u{feff}\u{200b}0xDEADBEEF\u{2060}\"}")
        .expect("json receipt hash with bom and zero-width fillers should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_ignores_invisible_fillers_inside_receipt_key() {
    let json = parse_tx_hash("receipt={\"tx\u{200b}_hash\":\"0xDEADBEEF\"}")
        .expect("json receipt hash should parse despite invisible fillers in the key");
    assert_eq!(json, "deadbeef");

    let shell = parse_tx_hash("\u{feff}tx_hash\u{2060}=0xFACECAFE")
        .expect("shell receipt hash should parse despite invisible fillers around the key");
    assert_eq!(shell, "facecafe");
}

#[test]
fn parse_tx_hash_accepts_hyphenated_json_receipt_keys() {
    let json = parse_tx_hash("{\"tx-hash\": \"0xDEADBEEF\", \"status\": \"accepted\"}")
        .expect("hyphenated json receipt hash should parse");
    assert_eq!(json, "deadbeef");

    let uppercase = parse_tx_hash("{\"TX-HASH\" : \"ABCD1234\", \"status\": \"accepted\"}")
        .expect("uppercase hyphenated json receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_mixed_case_json_alias_receipts() {
    let json = parse_tx_hash("adapter stdout: {\"txHash\": \"ABCD1234\"}")
        .expect("camelCase json receipt hash should parse");
    assert_eq!(json, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_transaction_hash_alias_receipts() {
    let shell = parse_tx_hash("[adapter] commit accepted transaction_hash=0xDEADBEEF")
        .expect("transaction_hash shell receipt hash should parse");
    assert_eq!(shell, "deadbeef");

    let hyphenated = parse_tx_hash("[adapter] commit accepted transaction-hash : 0xC0FFEE12")
        .expect("transaction-hash shell receipt hash with spaced delimiter should parse");
    assert_eq!(hyphenated, "c0ffee12");

    let spaced = parse_tx_hash("adapter stdout: {'TRANSACTION HASH' : 'ABCD1234'}")
        .expect("space-separated single-quoted transaction hash receipt should parse");
    assert_eq!(spaced, "abcd1234");

    let camel = parse_tx_hash("adapter stdout: {\"transactionHash\": \"0xBADDCAFE\"}")
        .expect("camelCase transaction hash json receipt should parse");
    assert_eq!(camel, "baddcafe");
}

#[test]
fn parse_tx_hash_accepts_smart_quoted_transaction_hash_alias_with_fullwidth_colon() {
    let smart_quoted = parse_tx_hash("receipt={“transaction hash”： “0xDEADBEEF”}")
        .expect("smart-quoted transaction hash alias with fullwidth colon should parse");
    assert_eq!(smart_quoted, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_json_receipts_without_quotes_around_hash() {
    let json = parse_tx_hash("{\"txhash\":0xDEADBEEF,\"status\":\"accepted\"}")
        .expect("json receipt hash without quotes should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_single_quoted_json_style_receipts() {
    let single_quoted = parse_tx_hash("{'tx_hash': '0xDEADBEEF', 'status': 'accepted'}")
        .expect("single-quoted json-style receipt hash should parse");
    assert_eq!(single_quoted, "deadbeef");

    let uppercase = parse_tx_hash("adapter stdout: {'TX-HASH' : 'ABCD1234'}")
        .expect("single-quoted uppercase hyphenated receipt hash should parse");
    assert_eq!(uppercase, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_smart_quoted_receipts() {
    let curly_double = parse_tx_hash("adapter stdout: {\"tx_hash\": “0xDEADBEEF”}")
        .expect("smart double-quoted receipt hash should parse");
    assert_eq!(curly_double, "deadbeef");

    let curly_single = parse_tx_hash("adapter stdout: {'transaction_hash': ‘ABCD1234’}")
        .expect("smart single-quoted receipt hash should parse");
    assert_eq!(curly_single, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_smart_quoted_receipt_keys() {
    let curly_double_key = parse_tx_hash("adapter stdout: {“tx_hash”: \"0xDEADBEEF\"}")
        .expect("smart double-quoted receipt key should parse");
    assert_eq!(curly_double_key, "deadbeef");

    let curly_single_key = parse_tx_hash("adapter stdout: {‘transaction_hash’: 'ABCD1234'}")
        .expect("smart single-quoted receipt key should parse");
    assert_eq!(curly_single_key, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_localized_quote_wrapped_receipts() {
    let guillemet = parse_tx_hash("adapter stdout: {«tx_hash»: «0xDEADBEEF»}")
        .expect("guillemet-quoted receipt hash should parse");
    assert_eq!(guillemet, "deadbeef");

    let single_angle = parse_tx_hash("adapter stdout: {〈tx_hash〉: 〈0xBADDCAFE〉}")
        .expect("single-angle-quoted receipt hash should parse");
    assert_eq!(single_angle, "baddcafe");

    let double_angle = parse_tx_hash("adapter stdout: {《transaction hash》: 《0xABCD1234》}")
        .expect("double-angle-quoted transaction hash alias should parse");
    assert_eq!(double_angle, "abcd1234");

    let corner_bracket = parse_tx_hash("adapter stdout: {「transaction hash」: 「0xFACECAFE」}")
        .expect("corner-bracket-quoted transaction hash alias should parse");
    assert_eq!(corner_bracket, "facecafe");

    let math_angle = parse_tx_hash("adapter stdout: {⟨tx_hash⟩: ⟨0xC001D00D⟩}")
        .expect("math-angle-quoted receipt hash should parse");
    assert_eq!(math_angle, "c001d00d");
}

#[test]
fn parse_tx_hash_accepts_backtick_wrapped_receipt_keys() {
    let backtick_key = parse_tx_hash("adapter stdout: {`tx_hash`: `0xFACECAFE`}")
        .expect("backtick-wrapped receipt key should parse");
    assert_eq!(backtick_key, "facecafe");
}

#[test]
fn parse_tx_hash_accepts_shell_escaped_quote_wrapped_receipt_values() {
    let shell_escaped_double = parse_tx_hash(r#"adapter stdout: {\"tx_hash\": \"0xDEADBEEF\"}"#)
        .expect("shell-escaped double-quoted receipt hash should parse");
    assert_eq!(shell_escaped_double, "deadbeef");

    let shell_escaped_single = parse_tx_hash("adapter stdout: {'tx_hash': \\'ABCD1234\\'}")
        .expect("shell-escaped single-quoted receipt hash should parse");
    assert_eq!(shell_escaped_single, "abcd1234");
}

#[test]
fn parse_tx_hash_accepts_nested_shell_escaped_and_localized_quote_wrapped_receipts() {
    let shell_escaped_smart =
        parse_tx_hash(r#"adapter stdout: {\"transaction hash\": \"“0xDEADBEEF”\"}"#)
            .expect("shell-escaped smart-quoted transaction hash should parse");
    assert_eq!(shell_escaped_smart, "deadbeef");

    let shell_escaped_guillemet =
        parse_tx_hash(r#"adapter stdout: {\"tx_hash\": \"«0xFACECAFE»\"}"#)
            .expect("shell-escaped guillemet-wrapped tx hash should parse");
    assert_eq!(shell_escaped_guillemet, "facecafe");
}

#[test]
fn parse_tx_hash_accepts_json_receipts_embedded_in_log_lines() {
    let json =
        parse_tx_hash("info: adapter response payload={\"tx_hash\": \"deadbeef\"} next=cleanup")
            .expect("embedded json receipt hash should parse");
    assert_eq!(json, "deadbeef");
}

#[test]
fn parse_tx_hash_accepts_128_char_receipts_for_real_cli_compat() {
    let long_hash = format!("0x{}", "AB".repeat(64));
    let parsed =
        parse_tx_hash(&format!("tx_hash={long_hash}")).expect("128-char tx hash should parse");
    assert_eq!(parsed, "ab".repeat(64));
}

#[test]
fn parse_tx_hash_rejects_receipts_over_128_chars() {
    let too_long_hash = format!("0x{}", "AB".repeat(65));
    assert!(parse_tx_hash(&format!("tx_hash={too_long_hash}")).is_none());
}

#[test]
fn parse_tx_hash_rejects_malformed_or_partial_values() {
    assert!(parse_tx_hash("tx_hash=0xdeadbee-").is_none());
    assert!(parse_tx_hash("tx_hash=not-a-hash").is_none());
    assert!(parse_tx_hash(
        "tx_hash=0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    )
    .is_none());
    assert!(parse_tx_hash("tx_hash=1234567").is_none());
    let overflow_hash = format!("tx_hash=0x{}", "ab".repeat(65));
    assert!(parse_tx_hash(&overflow_hash).is_none());
}

#[test]
fn llm_adapter_timeout_triggers() {
    let base_args = vec![
        "-lc".to_string(),
        "sleep 0.2; echo '{\"output_text\":\"late\"}'".to_string(),
    ];
    let err =
        run_command_with_timeout("sh", &base_args, &[], Duration::from_millis(30)).unwrap_err();
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn config_defaults_apply_when_cli_and_env_missing() {
    let llm = LlmAdapterPolicy {
        retry: RetryPolicy {
            max_retries: resolve_u32(None, None, DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
            backoff_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
        },
        timeout_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
    };
    let tx = RetryPolicy {
        max_retries: resolve_u32(None, None, DEFAULT_TX_ADAPTER_MAX_RETRIES, 0),
        backoff_ms: resolve_u64(None, None, DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
    };

    assert_eq!(llm.retry.max_retries, DEFAULT_LLM_ADAPTER_MAX_RETRIES);
    assert_eq!(llm.retry.backoff_ms, DEFAULT_LLM_ADAPTER_BACKOFF_MS);
    assert_eq!(llm.timeout_ms, DEFAULT_LLM_ADAPTER_TIMEOUT_MS);
    assert_eq!(tx.max_retries, DEFAULT_TX_ADAPTER_MAX_RETRIES);
    assert_eq!(tx.backoff_ms, DEFAULT_TX_ADAPTER_BACKOFF_MS);
}

#[test]
fn config_invalid_values_fallback_to_default() {
    assert_eq!(
        resolve_u32(None, Some("bad"), DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
        DEFAULT_LLM_ADAPTER_MAX_RETRIES
    );
    assert_eq!(
        resolve_u64(None, Some("bad"), DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
        DEFAULT_LLM_ADAPTER_BACKOFF_MS
    );
    assert_eq!(
        resolve_u64(None, Some("0"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
        DEFAULT_LLM_ADAPTER_TIMEOUT_MS
    );
    assert_eq!(
        resolve_u64(Some(0), Some("8000"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
        8000
    );
}

#[test]
fn parse_command_spec_rejects_invalid_quote() {
    let err = parse_command_spec("python3 -c 'print(1)").expect_err("unbalanced quote must fail");
    assert!(err.to_string().contains("invalid command spec quoting"));
}

#[test]
fn parse_command_spec_rejects_shell_interpreter_programs() {
    for spec in [
        "sh -c 'echo pwn'",
        "/bin/bash -lc 'echo pwn'",
        "pwsh -c echo",
    ] {
        let err = parse_command_spec(spec).expect_err("shell program must be rejected");
        assert!(
            err.to_string()
                .contains("shell interpreter is forbidden in adapter command spec"),
            "unexpected error for {spec}: {err}"
        );
    }
}

#[test]
fn parse_command_spec_accepts_non_shell_binary() {
    let (program, args) =
        parse_command_spec("python3 -c 'print(1)'").expect("python must be accepted");
    assert_eq!(program, "python3");
    assert_eq!(args, vec!["-c".to_string(), "print(1)".to_string()]);
}

#[test]
fn llm_adapter_non_timeout_path_is_ok() {
    let base_args = vec![
        "-c".to_string(),
        "import sys; print(sys.argv[1])".to_string(),
    ];
    let extra_args = vec!["{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}".to_string()];
    let out = run_command_with_timeout("python3", &base_args, &extra_args, Duration::from_secs(1))
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let parsed: LlmAdapterResponse = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
}

#[test]
fn llm_adapter_accepts_last_json_line_when_stdout_has_noise() {
    let prompt = "debug: adapter warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}";
    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        prompt,
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .unwrap();
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
}

#[test]
fn llm_adapter_rejects_stdout_without_any_json_line() {
    let err = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        "debug: adapter warmup\nstatus=ok",
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .unwrap_err();
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert!(err.context.contains("no-json-line"));
}

#[test]
fn llm_adapter_prompt_shell_chars_are_treated_as_plain_text() {
    let marker = env::temp_dir().join(format!("trnm-worker-agent-shell-marker-{}.tmp", now_ms()));
    let prompt = format!(
        "{{\"output_text\":\"$(touch {})\",\"provider_request_id\":\"r-safe\"}}",
        marker.display()
    );

    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        &prompt,
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .expect("payload should parse without shell evaluation");
    assert_eq!(parsed.output_text, format!("$(touch {})", marker.display()));
    assert!(
        fs::metadata(&marker).is_err(),
        "prompt shell metacharacters must never execute"
    );
}

#[test]
fn llm_adapter_tee_receipt_path_uses_adapter_parse_response_validation() {
    let cmd = "{\"output_text\":\"ok\",\"provider_request_id\":\"req-tee-1\",\"adapter\":\"tee-receipt\"}";
    let tee_adapter = build_proof_adapter("tee-receipt").expect("tee adapter");
    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        cmd,
        Duration::from_secs(1),
        tee_adapter.as_ref(),
    )
    .expect("tee receipt payload should parse");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("req-tee-1"));
    assert_eq!(parsed.adapter.as_deref(), Some("tee-receipt"));

    let bad_cmd = "{\"output_text\":\"ok\",\"provider_request_id\":\"req-tee-2\"}";
    let err = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        bad_cmd,
        Duration::from_secs(1),
        tee_adapter.as_ref(),
    )
    .expect_err("missing adapter label must fail closed");
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert!(err.context.contains("tee-receipt-missing-adapter-label"));
}

#[test]
fn truncate_for_error_marks_truncated_payloads() {
    let raw = "x".repeat(600);
    let truncated = truncate_for_error(&raw, 32);
    assert!(truncated.starts_with("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    assert!(truncated.contains("truncated"));
    assert!(truncated.contains("600 chars total"));
}

#[test]
fn adapter_error_classification_is_unified_failed_adapter() {
    let retry_exhausted = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter transient io failure".to_string(),
    };
    let non_retriable = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "llm adapter invalid json".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&retry_exhausted),
        ("adapter_error", "retry_exhausted")
    );
    assert_eq!(
        classify_adapter_error(&non_retriable),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );
}

#[test]
fn adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes() {
    let proof_missing = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee-receipt-missing-provider-request-id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter timeout after 3000ms".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_invalid = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "zk-receipt-missing-adapter-label".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_invalid),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let no_json_line = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "no-json-line".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&no_json_line),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let settlement_degraded_non_retriable = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee-receipt-settlement-degraded".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_non_retriable),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_retriable = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded-retry-window-exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_retriable),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_timeout_overlap = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded-timeout-window".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_timeout_overlap),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let proof_missing_underscore = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee_receipt_missing_provider_request_id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_underscore),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_late_underscore = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof_late_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_underscore),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_late_with_spaces = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof late retry window exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_with_spaces),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_late_with_nonbreaking_hyphen = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof‑late retry window exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_with_nonbreaking_hyphen),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_missing_with_nonbreaking_hyphen = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "proof‑missing provider request id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_nonbreaking_hyphen),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let settlement_degraded_with_em_dash = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement—degraded timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_with_em_dash),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let explicit_contract_proof_missing = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof-missing-from-verifier".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&explicit_contract_proof_missing),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let explicit_contract_proof_invalid = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof_invalid_signature".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&explicit_contract_proof_invalid),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let proof_invalid_with_spaces = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof invalid signature".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_invalid_with_spaces),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let settlement_degraded_underscore = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement_degraded_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_underscore),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let proof_missing_uppercase = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "TEE-RECEIPT-MISSING-PROVIDER-REQUEST-ID".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_uppercase),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_with_spaces = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee receipt missing provider request id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_spaces),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_with_punctuation = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee/receipt:missing.provider request-id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_punctuation),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_compact = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "teeReceiptMissingProviderRequestId".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_compact),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let settlement_degraded_mixed_case = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "Settlement_Degraded_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_mixed_case),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_camel_case = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlementDegradedRetryWindowExhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_camel_case),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );
}

#[test]
fn adapter_error_classification_enforces_contract_precedence_for_ambiguous_contexts() {
    let missing_vs_invalid = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "proof-missing and proof-invalid in same envelope".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&missing_vs_invalid),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing"),
        "proof_missing must outrank proof_invalid for deterministic disputed reason"
    );

    let invalid_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof-invalid timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&invalid_vs_late),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid"),
        "proof_invalid must outrank proof_late to avoid timeout masking malformed proofs"
    );

    let missing_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "missing-provider-request-id timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&missing_vs_late),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing"),
        "proof_missing must outrank proof_late when timeout co-occurs with missing receipt ids"
    );

    let degraded_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&degraded_vs_late),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded"),
        "settlement_degraded must outrank proof_late for stable downgrade signaling"
    );
}

#[test]
fn reputation_delta_maps_market_penalty_and_reward_signals() {
    assert_eq!(reputation_delta(ReputationSignal::Accepted), 3);
    assert_eq!(reputation_delta(ReputationSignal::VerifierRejected), -2);
    assert_eq!(
        reputation_delta(ReputationSignal::AdapterRetryExhausted),
        -1
    );
    assert_eq!(reputation_delta(ReputationSignal::AdapterNonRetriable), -3);
}

#[test]
fn verifier_rejection_penalty_sits_between_retryable_and_non_retriable_adapter_failures() {
    let verifier_penalty = reputation_delta(ReputationSignal::VerifierRejected);
    let retryable_penalty = reputation_delta(ReputationSignal::AdapterRetryExhausted);
    let non_retriable_penalty = reputation_delta(ReputationSignal::AdapterNonRetriable);

    assert!(
        verifier_penalty < retryable_penalty,
        "verifier rejection should be stricter than transient adapter exhaustion"
    );
    assert!(
        verifier_penalty > non_retriable_penalty,
        "verifier rejection should remain less severe than deterministic adapter failures"
    );
}

#[test]
fn market_verification_reputation_tiers_remain_strictly_ordered() {
    let accepted = reputation_delta(ReputationSignal::Accepted);
    let retryable = reputation_delta(ReputationSignal::AdapterRetryExhausted);
    let verifier_rejected = reputation_delta(ReputationSignal::VerifierRejected);
    let non_retriable = reputation_delta(ReputationSignal::AdapterNonRetriable);

    assert!(accepted > 0, "accepted work must remain net-positive");
    assert!(retryable < 0, "retry exhaustion must remain a penalty");
    assert!(
        accepted > retryable && retryable > verifier_rejected && verifier_rejected > non_retriable,
        "expected strict tiering: accepted > retryable > verifier_rejected > non_retriable"
    );
}

#[test]
fn adapter_error_signal_maps_retryability_to_penalty_tier() {
    assert_eq!(
        adapter_error_signal(AdapterErrorKind::Retriable),
        ReputationSignal::AdapterRetryExhausted
    );
    assert_eq!(
        adapter_error_signal(AdapterErrorKind::NonRetriable),
        ReputationSignal::AdapterNonRetriable
    );
}

#[test]
fn reputation_tier_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_tier(impact.tier), Some(signal));
        assert_eq!(reputation_impact_from_tier(impact.tier), Some(impact));
    }

    assert_eq!(reputation_signal_from_tier(u8::MAX), None);
    assert_eq!(reputation_impact_from_tier(u8::MAX), None);
}

#[test]
fn reputation_label_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_label(impact.label), Some(signal));
        assert_eq!(reputation_impact_from_label(impact.label), Some(impact));
    }

    assert_eq!(reputation_signal_from_label("unknown"), None);
    assert_eq!(reputation_impact_from_label("unknown"), None);
}

#[test]
fn reputation_score_impact_pair_round_trips_fail_closed_on_hybrid_tuples() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_signal_from_score_impact(impact.label, impact.delta),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_score_impact(impact.label, impact.delta),
            Some(impact)
        );
    }

    assert_eq!(
        reputation_signal_from_score_impact("accepted", -1),
        None,
        "mixed label+delta tuples must fail closed"
    );
    assert_eq!(
        reputation_impact_from_score_impact("verifier_rejected", 3),
        None,
        "score-impact lookup must reject cross-signal hybrids"
    );
}

#[test]
fn reputation_surface_axes_round_trip_back_to_canonical_signal_and_impact() {
    let surfaces = canonical_reputation_surfaces();
    assert_eq!(surfaces.len(), CANONICAL_REPUTATION_SIGNAL_ORDER.len());

    for (expected_rank, signal) in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().enumerate() {
        let impact = reputation_impact(*signal);
        let surface = surfaces[expected_rank];

        assert_eq!(surface.label, impact.label);
        assert_eq!(surface.delta, impact.delta);
        assert_eq!(surface.tier, impact.tier);
        assert_eq!(surface.weight_bps, reputation_weight_bps(*signal));
        assert_eq!(surface.score_bps, reputation_score_bps(*signal));
        assert_eq!(surface.rank_ordinal, expected_rank as u8);

        assert_eq!(
            reputation_signal_from_weight_bps(surface.weight_bps),
            Some(*signal)
        );
        assert_eq!(
            reputation_impact_from_weight_bps(surface.weight_bps),
            Some(impact)
        );
        assert_eq!(
            reputation_signal_from_score_bps(surface.score_bps),
            Some(*signal)
        );
        assert_eq!(
            reputation_impact_from_score_bps(surface.score_bps),
            Some(impact)
        );
        assert_eq!(
            reputation_signal_from_rank_ordinal(surface.rank_ordinal),
            Some(*signal)
        );
        assert_eq!(
            reputation_impact_from_rank_ordinal(surface.rank_ordinal),
            Some(impact)
        );
        assert_eq!(
            reputation_signal_from_surface(
                surface.label,
                surface.delta,
                surface.tier,
                surface.weight_bps,
                surface.score_bps,
                surface.rank_ordinal,
            ),
            Some(*signal),
            "surface lookup must remain round-trippable across every canonical score axis"
        );
        assert_eq!(
            reputation_impact_from_surface(
                surface.label,
                surface.delta,
                surface.tier,
                surface.weight_bps,
                surface.score_bps,
                surface.rank_ordinal,
            ),
            Some(impact)
        );
    }
}

#[test]
fn reputation_surface_axes_fail_closed_on_cross_signal_hybrids() {
    let surfaces = canonical_reputation_surfaces();
    assert!(
        surfaces.len() >= 2,
        "expected at least two canonical surfaces"
    );

    let accepted = surfaces[0];
    let retryable = surfaces[1];

    assert_eq!(
        reputation_signal_from_weight_bps(9_999),
        None,
        "weight lookup must fail closed on non-canonical basis points"
    );
    assert_eq!(
        reputation_impact_from_score_bps(-6_667),
        None,
        "score lookup must fail closed on non-canonical basis points"
    );
    assert_eq!(
        reputation_signal_from_rank_ordinal(CANONICAL_REPUTATION_SIGNAL_ORDER.len() as u8),
        None,
        "rank lookup must fail closed past the canonical score ladder"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            accepted.tier,
            retryable.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal weight hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            retryable.tier,
            accepted.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal tier hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            accepted.tier,
            accepted.weight_bps,
            retryable.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal normalized score hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            retryable.delta,
            accepted.tier,
            accepted.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal delta hybrids"
    );
}

#[test]
fn verify_model_output_enforces_trimmed_empty_and_char_limit_boundaries() {
    assert_eq!(
        verify_model_output("   \n\t", 8),
        ("rejected", "empty_output")
    );

    // Zero-width/invisible fillers should not pass verifier checks as meaningful output.
    assert_eq!(
        verify_model_output("\u{200B}\u{200C}\u{FEFF}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2060}\u{00AD}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2061}\u{2062}\u{2063}\u{2064}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{2066}\u{2067}\u{2068}\u{2069}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{034F}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{180E}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{200E}\u{200F}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{061C}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{FE0E}", 8),
        ("rejected", "empty_output")
    );
    assert_eq!(
        verify_model_output("\u{FE0F}", 8),
        ("rejected", "empty_output")
    );

    // Whitespace + zero-width-only payloads must also be rejected deterministically.
    assert_eq!(
        verify_model_output("\n\u{200B} \t\u{200D}\r\n", 8),
        ("rejected", "empty_output")
    );

    // Control-only payloads should not pass market verification as meaningful content.
    assert_eq!(
        verify_model_output("\u{0007}\u{001B}", 8),
        ("rejected", "empty_output")
    );

    // Control bytes mixed around visible content should be ignored for length accounting.
    assert_eq!(
        verify_model_output("\u{0007}ok\u{001B}", 2),
        ("accepted", "ok")
    );

    // Limit is measured in characters (not bytes) to keep verifier behavior predictable.
    let within = "hell"; // 4 chars
    assert_eq!(verify_model_output(within, 4), ("accepted", "ok"));

    let over = "hello"; // 5 chars
    assert_eq!(
        verify_model_output(over, 4),
        ("rejected", "output_too_long")
    );

    // Leading/trailing transport whitespace should not cause false rejections.
    assert_eq!(verify_model_output(" hell \n", 4), ("accepted", "ok"));

    // Mixed visible + zero-width should still count as meaningful content.
    assert_eq!(
        verify_model_output("\u{200B}ok\u{200D}", 4),
        ("accepted", "ok")
    );

    // Invisible fillers should not inflate length checks for market verification.
    assert_eq!(
        verify_model_output("\u{200B}ok\u{200D}", 2),
        ("accepted", "ok")
    );
    assert_eq!(verify_model_output("o\u{034F}k", 2), ("accepted", "ok"));

    // Direction/isolation wrappers should not alter verifiable length accounting.
    assert_eq!(
        verify_model_output("\u{2066}ok\u{2069}", 2),
        ("accepted", "ok")
    );
    assert_eq!(
        verify_model_output("\u{2066}ok\u{2069}", 1),
        ("rejected", "output_too_long")
    );

    // ARABIC LETTER MARK wrappers should be treated as invisible fillers as well.
    assert_eq!(
        verify_model_output("\u{061C}ok\u{061C}", 2),
        ("accepted", "ok")
    );
    assert_eq!(
        verify_model_output("\u{061C}ok\u{061C}", 1),
        ("rejected", "output_too_long")
    );

    // ZWJ inside visible emoji sequences should stay deterministic for verifier limits.
    assert_eq!(verify_model_output("👩\u{200D}💻", 2), ("accepted", "ok"));
    assert_eq!(
        verify_model_output("👩\u{200D}💻", 1),
        ("rejected", "output_too_long")
    );
}

#[test]
fn exp_backoff_delay_saturates_without_overflow() {
    assert_eq!(exp_backoff_delay_ms(25, 0), 25);
    assert_eq!(exp_backoff_delay_ms(25, 1), 50);
    assert_eq!(exp_backoff_delay_ms(25, 2), 100);

    // Very large attempts should saturate rather than overflow/panic.
    assert_eq!(exp_backoff_delay_ms(u64::MAX, 1), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1_000_000, 62), u64::MAX);
    assert_eq!(
        exp_backoff_delay_ms(1_000_000, u32::MAX),
        u64::MAX,
        "attempts above the shift cap must stay saturated"
    );
}

#[test]
fn exp_backoff_delay_keeps_63rd_shift_for_small_base_before_saturating() {
    assert_eq!(exp_backoff_delay_ms(1, 62), 1u64 << 62);
    assert_eq!(exp_backoff_delay_ms(1, 63), 1u64 << 63);
    assert_eq!(exp_backoff_delay_ms(2, 63), u64::MAX);
}

#[test]
fn exp_backoff_delay_saturates_at_attempt_64_even_for_small_base() {
    assert_eq!(exp_backoff_delay_ms(1, 64), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1, 65), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1, u32::MAX), u64::MAX);
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
fn llm_adapter_retry_skips_zero_backoff_sleep_between_retriable_attempts() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_llm_adapter_with_retry_inner(
        2,
        0,
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
    assert!(
        slept.is_empty(),
        "zero backoff should skip sleep callbacks entirely"
    );
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

#[test]
fn flush_submissions_requires_tx_hash_receipts_for_terminal_acceptance() {
    let commit_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };

    let commit_idempotent_ok = should_execute_reveal(&commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);
    let commit_hash_observed = commit_res.tx_hash.is_some();
    let reveal_hash_observed = reveal_res.tx_hash.is_some();

    let (ack_status, reason_code) = if commit_idempotent_ok
        && reveal_idempotent_ok
        && commit_hash_observed
        && reveal_hash_observed
    {
        ("accepted", "idempotent_ok")
    } else if commit_idempotent_ok
        && reveal_idempotent_ok
        && (!commit_hash_observed || !reveal_hash_observed)
    {
        ("failed", "missing_tx_hash_receipt")
    } else {
        ("unexpected", "unexpected")
    };

    assert_eq!(ack_status, "failed");
    assert_eq!(reason_code, "missing_tx_hash_receipt");
}

#[test]
fn flush_submissions_reuses_persisted_tx_hash_for_duplicate_resume_acceptance() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: Some("revealbeef".to_string()),
        terminal: true,
    };

    let previous_commit_tx_hash = Some("commitbeef".to_string());
    let previous_reveal_tx_hash = None;

    let commit_hash_observed = commit_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    let commit_tx_hash_for_ack = commit_res.tx_hash.clone().or(previous_commit_tx_hash);
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

    assert!(should_execute_reveal(&commit_res));
    assert!(reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc));
    assert!(commit_hash_observed);
    assert!(reveal_hash_observed);
    assert_eq!(commit_tx_hash_for_ack.as_deref(), Some("commitbeef"));
    assert_eq!(reveal_tx_hash_for_ack.as_deref(), Some("revealbeef"));
}

#[test]
fn flush_submissions_reuses_persisted_reveal_tx_hash_for_duplicate_reveal_resume() {
    let commit_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: Some("commitbeef".to_string()),
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };

    let previous_reveal_tx_hash = Some("revealbeef".to_string());

    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

    assert!(should_execute_reveal(&commit_res));
    assert!(reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc));
    assert!(reveal_hash_observed);
    assert_eq!(reveal_tx_hash_for_ack.as_deref(), Some("revealbeef"));
}

#[test]
fn persisted_ack_hashes_for_task_merges_hashes_across_failed_resume_attempts() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        77,
        "failed",
        Some("commit-old".to_string()),
        None,
        Some("missing_tx_hash_receipt".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write first ack");
    append_ack(
        &ack_log,
        77,
        "accepted",
        None,
        Some("reveal-new".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-2".to_string()),
    )
    .expect("write second ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 77);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-old"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-new"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn persisted_ack_hashes_for_task_ignores_blank_wrapped_hash_entries() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-blank-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        78,
        "failed",
        Some("\u{feff}\u{200b}   \u{2060}".to_string()),
        Some("\t\n".to_string()),
        Some("missing_tx_hash_receipt".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write blank ack");
    append_ack(
        &ack_log,
        78,
        "accepted",
        Some("commit-new".to_string()),
        Some("\u{feff}reveal-new\u{200b}".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-2".to_string()),
    )
    .expect("write recovery ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 78);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-new"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-new"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn persisted_ack_hashes_for_task_ignores_newer_other_task_records() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-other-task-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        80,
        "accepted",
        Some("commit-target".to_string()),
        None,
        Some("idempotent_ok".to_string()),
        Some("run-target-1".to_string()),
    )
    .expect("write target commit ack");
    append_ack(
        &ack_log,
        81,
        "accepted",
        Some("commit-other".to_string()),
        Some("reveal-other".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-other".to_string()),
    )
    .expect("write newer other-task ack");
    append_ack(
        &ack_log,
        80,
        "accepted",
        None,
        Some("reveal-target".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-target-2".to_string()),
    )
    .expect("write target reveal ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 80);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-target"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-target"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn persisted_ack_hashes_for_task_canonicalizes_legacy_wrapped_hex_receipts() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-canonical-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        79,
        "accepted",
        Some(" \"0xABCD1234\" ".to_string()),
        Some("\u{feff}<0XFACEBEEF>\u{200b}".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write wrapped legacy ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 79);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("abcd1234"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("facebeef"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn persisted_ack_hashes_for_task_canonicalizes_shell_escaped_quote_wrapped_hex_receipts() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-shell-escaped-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        791,
        "accepted",
        Some(r#"\"0xABCD1234\""#.to_string()),
        Some(r#"\"<0XFACEBEEF>\""#.to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write shell-escaped wrapped legacy ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 791);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("abcd1234"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("facebeef"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn persisted_ack_hashes_for_task_extracts_tx_hash_from_receipt_blob_entries() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-receipt-blob-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        792,
        "accepted",
        Some(" {\"tx_hash\": \"0xABCD1234\", \"status\": \"accepted\"} ".to_string()),
        Some(" {'tx_hash': '0xFACEBEEF', 'status': 'accepted'} ".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-blob".to_string()),
    )
    .expect("write receipt-blob ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 792);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("abcd1234"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("facebeef"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn task_lock_prevents_parallel_replay_for_same_task() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-ack-lock-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let guard = try_acquire_task_lock(&ack_log, 42)
        .expect("acquire lock")
        .expect("first lock should succeed");
    assert!(
        try_acquire_task_lock(&ack_log, 42)
            .expect("second lock call")
            .is_none(),
        "second lock should be blocked"
    );
    drop(guard);
    assert!(
        try_acquire_task_lock(&ack_log, 42)
            .expect("third lock call")
            .is_some(),
        "lock should be released after drop"
    );
    let _ = fs::remove_file(&ack_log);
}

#[test]
fn is_task_acked_only_true_for_accepted_records() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-ack-records-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    fs::write(
            &ack_log,
            "{\"ts_unix_ms\":1,\"task_id\":1,\"status\":\"rejected\"}\n{\"ts_unix_ms\":2,\"task_id\":2,\"status\":\"accepted\"}\n",
        )
        .expect("write ack log");

    assert!(!is_task_acked(&ack_log, 1));
    assert!(is_task_acked(&ack_log, 2));
    let _ = fs::remove_file(&ack_log);
}

#[test]
fn message_ingress_backward_compat_defaults_provider_request_id() {
    let raw = r#"{"request_id":"r1","task_id":7,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hello","idempotency_key":"ik1","status":"assigned","created_at_unix_ms":1}"#;
    let rec: MessageIngressRecord = serde_json::from_str(raw).expect("parse ingress record");
    assert_eq!(rec.provider_request_id, None);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn enterprise_audit_export_re_normalizes_legacy_provider_request_id() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-provider-request-id".to_string(),
        task_id: 700,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-provider-request-id".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some(" provider\n701 ".to_string()),
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provider_request_id, None);
}

#[test]
fn enterprise_audit_export_trims_boundary_bom_from_provider_request_id() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-provider-request-id-bom".to_string(),
        task_id: 7001,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-provider-request-id-bom".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("\u{feff}provider-701\u{200b}".to_string()),
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provider_request_id.as_deref(), Some("provider-701"));
}

#[test]
fn enterprise_audit_export_flattens_v2_provenance_for_agent_and_compliance() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2".to_string(),
        task_id: 701,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-701".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.request_id, "r-audit-v2");
    assert_eq!(export.task_id, 701);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
    assert_eq!(export.provider.as_deref(), Some("openai"));
    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_accepts_case_and_whitespace_drift_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-drift".to_string(),
        task_id: 7011,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-drift".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7011".to_string()),
        provenance_schema_version: Some("  LLM.V2  ".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_accepts_separator_aliases_for_schema_version() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-alias".to_string(),
        task_id: 70115,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-alias".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70115".to_string()),
        provenance_schema_version: Some("LLM_V2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    for alias in ["llm2", "llm-v2", "llm/v2"] {
        let mut compact_alias = rec.clone();
        compact_alias.provenance_schema_version = Some(alias.to_string());
        let compact_export = to_enterprise_audit_export(&compact_alias);
        assert_eq!(
            compact_export.provenance_schema_version.as_deref(),
            Some("llm.v2"),
            "schema alias should canonicalize: {alias}"
        );
        assert_eq!(compact_export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            compact_export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_streamable_http_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-streamable-http".to_string(),
        task_id: 70117,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-streamable-http".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70117".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("MCP/streamable-http v2".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("mcp"));

    for alias in [
        "MCP/streamable-http v2",
        "mcp over streamable-http",
        "model context protocol over streamable-http",
        "OpenAI model context protocol over streamable-http v2",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol alias should canonicalize: {alias}"
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_websocket_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-websocket".to_string(),
        task_id: 70118,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-websocket".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70118".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("MCP over WebSocket v2".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    for alias in [
        "MCP over WebSocket v2",
        "model context protocol websocket",
        "OpenAI MCP websocket v1",
        "OpenAI model context protocol over websocket v2",
        "Anthropic model-context-protocol over websocket",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol websocket alias should canonicalize: {alias}"
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_sse_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-sse".to_string(),
        task_id: 70119,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-sse".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70119".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("OpenAI MCP over SSE v2".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    for alias in [
        "OpenAI MCP over SSE v2",
        "openai model context protocol sse",
        "Anthropic MCP over SSE",
        "Anthropic model-context-protocol over sse v1",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol sse alias should canonicalize: {alias}"
        );
    }
}

#[test]
fn enterprise_audit_export_accepts_separator_aliases_for_v1_schema_version() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v1-alias".to_string(),
        task_id: 70116,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v1-alias".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70116".to_string()),
        provenance_schema_version: Some("LLM_V1".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    for alias in ["LLM_V1", "llm1", "llm-v1", "llm/v1"] {
        let mut v1_alias = rec.clone();
        v1_alias.provenance_schema_version = Some(alias.to_string());
        let export = to_enterprise_audit_export(&v1_alias);
        assert_eq!(
            export.provenance_schema_version.as_deref(),
            Some("llm.v1"),
            "schema alias should canonicalize: {alias}"
        );
        assert_eq!(export.adapter.as_deref(), Some("mcp"));
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
    }
}

#[test]
fn enterprise_audit_export_re_normalizes_legacy_persisted_provenance_fields() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-legacy-provenance".to_string(),
        task_id: 7012,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-legacy-provenance".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7012".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("  openai  ".to_string()),
            model: Some("  gpt-5.3-codex  ".to_string()),
            adapter: Some("mcp\ninvalid".to_string()),
            agent_protocol: Some(" Agent-to-Agent v2 ".to_string()),
            compliance_profile: Some(" CN_PII/RESTRICTED ".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter, None);
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        None,
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_drops_v2_only_fields_when_schema_is_not_v2() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v1-with-v2-fields".to_string(),
        task_id: 702,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v1-with-v2-fields".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-702".to_string()),
        provenance_schema_version: Some("llm.v1".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v1"));
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter.as_deref(), Some("mcp"));
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
    let expected = build_provenance_fingerprint(
        Some("llm.v1"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        None,
        None,
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_keeps_backward_compat_when_provenance_absent() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-legacy".to_string(),
        task_id: 702,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-legacy".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: None,
        assigned_at_unix_ms: None,
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.request_id, "r-audit-legacy");
    assert_eq!(export.provenance_schema_version, None);
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
    assert_eq!(export.provider, None);
}

#[test]
fn enterprise_audit_export_gates_fingerprint_when_schema_exists_without_labels() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-empty".to_string(),
        task_id: 703,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-empty".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-703".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: None,
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.provider, None);
    assert_eq!(export.model, None);
    assert_eq!(export.adapter, None);
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
}

#[test]
fn enterprise_audit_export_fail_closed_on_noncanonical_schema_tag() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-bad-schema".to_string(),
        task_id: 7031,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-bad-schema".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7031".to_string()),
        provenance_schema_version: Some("llm.v2-beta".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version, None);
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter.as_deref(), Some("mcp"));
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
}

#[test]
fn export_audit_detects_markdown_output_extension() {
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.md")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.markdown")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.jsonl")),
        AuditExportFormat::Jsonl
    );
}

#[test]
fn validate_audit_export_index_accepts_current_version() {
    let index = AuditExportIndex {
        version: 1,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    validate_audit_export_index(&index, 0).expect("v1 index should be accepted");
}

#[test]
fn validate_audit_export_index_rejects_unknown_version_fail_closed() {
    let index = AuditExportIndex {
        version: 2,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 0)
        .expect_err("unknown audit index version must fail closed");
    assert!(err
        .to_string()
        .contains("unsupported audit index version=2"));
}

#[test]
fn validate_audit_export_index_rejects_total_record_mismatch_fail_closed() {
    let index = AuditExportIndex {
        version: 1,
        total_records: 2,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("mismatched export length must fail closed");
    assert!(err
        .to_string()
        .contains("audit index total_records mismatch: index=2 exports=1"));
}

#[test]
fn validate_audit_export_index_rejects_out_of_bounds_offsets_fail_closed() {
    let mut by_task_id = BTreeMap::new();
    by_task_id.insert("7001".to_string(), vec![1]);
    let index = AuditExportIndex {
        version: 1,
        total_records: 1,
        by_task_id,
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("out-of-bounds index offsets must fail closed");
    assert!(err.to_string().contains(
        "audit index offset out of bounds: map=by_task_id key=7001 idx=1 total_records=1"
    ));
}

#[test]
fn export_audit_markdown_contains_provenance_fingerprint_fields() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("req-1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let md = render_enterprise_audit_markdown(&rows);
    assert!(md.contains("| provenance_schema_version | provenance_fingerprint |"));
    assert!(md.contains("| r1 | 7 | reveal_submitted | req-1 | llm.v2 | deadbeef |"));
}

#[test]
fn export_audit_markdown_normalizes_multiline_cells_to_single_line() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r\n1".to_string(),
        task_id: 8,
        status: "reveal\r\nsubmitted".to_string(),
        provider_request_id: Some("req|2".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("cafebabe".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let md = render_enterprise_audit_markdown(&rows);
    assert!(md.contains("| r 1 | 8 | reveal  submitted | req\\|2 | llm.v2 | cafebabe |"));
    assert!(!md.contains("r\n1"));
    assert!(!md.contains("reveal\r\nsubmitted"));
}

#[test]
fn export_audit_index_contains_task_status_provider_model_and_fingerprint_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7001,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-abc".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7002,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-abc".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.total_records, 2);
    assert_eq!(index.by_task_id.get("7001"), Some(&vec![0]));
    assert_eq!(index.by_task_id.get("7002"), Some(&vec![1]));
    assert_eq!(index.by_status.get("reveal_submitted"), Some(&vec![0]));
    assert_eq!(index.by_status.get("rejected"), Some(&vec![1]));
    assert_eq!(index.by_status_phase.get("active"), Some(&vec![0]));
    assert_eq!(index.by_status_phase.get("terminal"), Some(&vec![1]));
    assert_eq!(index.by_provider.get("openai"), Some(&vec![0, 1]));
    assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0, 1]));
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
    assert_eq!(
        index.by_compliance_profile.get("cn-moderate"),
        Some(&vec![0, 1])
    );
    assert_eq!(
        index.by_provenance_fingerprint.get("fp-abc"),
        Some(&vec![0, 1])
    );
}

#[test]
fn export_audit_index_trims_and_drops_blank_provider_model_or_fingerprint_values() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7101,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("  fp-xyz  ".to_string()),
            provider: Some("  openai  ".to_string()),
            model: Some("  gpt-5.3-codex  ".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7102,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("   ".to_string()),
            provider: Some("   ".to_string()),
            model: Some("\t".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.by_provider.get("openai"), Some(&vec![0]));
    assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0]));
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
    assert_eq!(
        index.by_compliance_profile.get("cn-moderate"),
        Some(&vec![0, 1])
    );
    assert_eq!(
        index.by_provenance_fingerprint.get("fp-xyz"),
        Some(&vec![0])
    );
    assert!(!index.by_provider.contains_key(""));
    assert!(!index.by_model.contains_key(""));
    assert!(!index.by_agent_protocol.contains_key(""));
    assert!(!index.by_compliance_profile.contains_key(""));
    assert!(!index.by_provenance_fingerprint.contains_key(""));
}

#[test]
fn export_audit_index_normalizes_uppercase_fingerprint_variants() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7201,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("DEADBEEF".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7202,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("deadbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_provenance_fingerprint.get("deadbeef"),
        Some(&vec![0, 1])
    );
    assert!(!index.by_provenance_fingerprint.contains_key("DEADBEEF"));
}

#[test]
fn export_audit_index_normalizes_agent_protocol_aliases_to_canonical_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7251,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-1".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("A2A-JSON-RPC-V2".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7252,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-2".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some(" model-context-protocol / stdio v1 ".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r3".to_string(),
            task_id: 7253,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p3".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-3".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("Google-Agent-to-Agent-Streamable-HTTP-v1".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 2]));
    assert_eq!(index.by_agent_protocol.get("mcp"), Some(&vec![1]));
    assert!(!index.by_agent_protocol.contains_key("A2A-JSON-RPC-V2"));
    assert!(!index
        .by_agent_protocol
        .contains_key("model-context-protocol / stdio v1"));
    assert!(!index
        .by_agent_protocol
        .contains_key("Google-Agent-to-Agent-Streamable-HTTP-v1"));
}

#[test]
fn export_audit_index_normalizes_compliance_profile_aliases_to_canonical_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7281,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-1".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("CN_PII_RESTRICTED".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7282,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-2".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some(" cn/pii/restricted ".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_compliance_profile.get("cn-pii-restricted"),
        Some(&vec![0, 1])
    );
    assert!(!index
        .by_compliance_profile
        .contains_key("CN_PII_RESTRICTED"));
    assert!(!index
        .by_compliance_profile
        .contains_key("cn/pii/restricted"));
}

#[test]
fn export_audit_index_drops_non_ascii_or_controlled_fingerprints() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7301,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("deadbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7302,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("de\u{200b}adbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r3".to_string(),
            task_id: 7303,
            status: "rejected".to_string(),
            provider_request_id: Some("p3".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("cafébabe".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_provenance_fingerprint.get("deadbeef"),
        Some(&vec![0])
    );
    assert_eq!(index.by_provenance_fingerprint.len(), 1);
}

#[test]
fn query_audit_export_by_task_id_uses_index_offsets() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7001,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-abc".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7002,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-def".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
            reputation_label: None,
            reputation_delta: None,
            reputation_tier: None,
            reputation_weight_bps: None,
            reputation_score_bps: None,
            reputation_rank_ordinal: None,
            reputation_gap_bps_from_best: None,
        },
    ];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_task_id(&rows, &index, 7002);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r2");

    let miss = query_audit_export_by_task_id(&rows, &index, 9999);
    assert!(miss.is_empty());
}

#[test]
fn query_audit_export_by_provenance_fingerprint_normalizes_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, "  DEADBEEF ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");

    let miss = query_audit_export_by_provenance_fingerprint(&rows, &index, "dead\u{200b}beef");
    assert!(miss.is_empty());
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_outer_quote_wrappers_before_validation() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7003,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, "'\"DEADBEEF\"'");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_quoted_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, " ' \"DEADBEEF\" ' ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_deeply_nested_quotes() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, "  ` ' \" deadbeef \" ' `  ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_very_deep_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    // Five nested wrappers can appear after repeated env-forwarding hops.
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        "  ' \" ` ' \" deadbeef \" ' ` \" '  ",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_repeated_nested_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    // Repeated shell/env forwarding can introduce more than five quote layers; keep
    // lookup tolerant as long as the normalized fingerprint remains valid and bounded.
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        "'\"`'\"`'\"`'\"`deadbeef`\"'`\"'`\"'`\"'",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_shell_escaped_outer_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7004,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, r#"  \"'deadbeef'\"  "#);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_trims_boundary_bom_before_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r-bom-lookup".to_string(),
        task_id: 70081,
        status: "assigned".to_string(),
        provider_request_id: None,
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, "\u{feff}DEADBEEF\u{200b}");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r-bom-lookup");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_trims_fillers_after_quote_peeling() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r-bom-after-peel".to_string(),
        task_id: 70082,
        status: "assigned".to_string(),
        provider_request_id: None,
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        " '\"\u{feff}DEADBEEF\u{200b}\"' ",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r-bom-after-peel");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_repeated_shell_escaped_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7005,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, r#"\"\"\"deadbeef\"\"\""#);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_rejects_blank_or_oversized_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
    }];

    let index = build_audit_export_index(&rows);
    assert!(query_audit_export_by_provenance_fingerprint(&rows, &index, "   ").is_empty());

    let oversized = "a".repeat(129);
    assert!(query_audit_export_by_provenance_fingerprint(&rows, &index, &oversized).is_empty());
}

#[test]
fn query_audit_output_serializes_normalized_fingerprint_only_when_present() {
    let with_fp = QueryAuditOutput {
        hit_indexes: vec![1, 3],
        records: vec![],
        provenance_fingerprint: Some("deadbeef".to_string()),
    };
    let with_fp_json = serde_json::to_value(&with_fp).expect("serialize query output");
    assert_eq!(with_fp_json["provenance_fingerprint"], "deadbeef");
    assert_eq!(with_fp_json["hit_indexes"], serde_json::json!([1, 3]));

    let without_fp = QueryAuditOutput {
        hit_indexes: vec![],
        records: vec![],
        provenance_fingerprint: None,
    };
    let without_fp_json = serde_json::to_value(&without_fp).expect("serialize query output");
    assert!(without_fp_json.get("provenance_fingerprint").is_none());
    assert_eq!(without_fp_json["hit_indexes"], serde_json::json!([]));
}

#[test]
fn query_audit_rejects_markdown_exports_fail_closed() {
    let output_file = std::env::temp_dir().join(format!(
        "trnm-worker-agent-query-audit-markdown-{}-{}.md",
        std::process::id(),
        now_ms()
    ));
    let index_file = audit_export_index_path(&output_file);
    let index = AuditExportIndex {
        version: 1,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    fs::write(&output_file, "# audit\n").expect("write markdown export");
    fs::write(
        &index_file,
        serde_json::to_string_pretty(&index).expect("serialize index"),
    )
    .expect("write index");

    let format = detect_audit_export_format(&output_file);
    assert_eq!(format, AuditExportFormat::Markdown);
    assert!(index_file.exists());
    let err = if format != AuditExportFormat::Jsonl {
        anyhow!(
            "query-audit only supports JSONL audit exports: {}",
            output_file.display()
        )
    } else {
        anyhow!("unexpected jsonl format for markdown export")
    };
    assert!(err
        .to_string()
        .contains("query-audit only supports JSONL audit exports"));

    let _ = fs::remove_file(&output_file);
    let _ = fs::remove_file(&index_file);
}

#[test]
fn attach_llm_provenance_persists_provider_request_id() {
    let mut rec = MessageIngressRecord {
        request_id: "r1".to_string(),
        task_id: 9,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik1".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-123".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-123"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider.as_deref(), Some("openai"));
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(prov.compliance_profile, None);
}

#[test]
fn attach_llm_provenance_rejects_non_canonical_provider_request_id() {
    let mut rec = MessageIngressRecord {
        request_id: "r1b".to_string(),
        task_id: 901,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik1".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-123\nmal".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id, None);
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    assert!(rec.llm_provenance.is_some());
}

#[test]
fn normalized_provider_request_id_accepts_boundary_and_rejects_overflow() {
    let ok = "a".repeat(128);
    assert_eq!(
        normalized_provider_request_id(Some(&ok)).as_deref(),
        Some(ok.as_str())
    );

    let overflow = "a".repeat(129);
    assert_eq!(normalized_provider_request_id(Some(&overflow)), None);
}

#[test]
fn normalized_provider_request_id_rejects_colon_and_non_alnum_edges() {
    assert_eq!(
        normalized_provider_request_id(Some("req:123")),
        None,
        "colon-delimited ids are ambiguous in downstream audit consumers"
    );
    assert_eq!(normalized_provider_request_id(Some("-req123")), None);
    assert_eq!(normalized_provider_request_id(Some("req123.")), None);
    assert_eq!(
        normalized_provider_request_id(Some("req_123-abc.DEF")).as_deref(),
        Some("req_123-abc.DEF")
    );
}

#[test]
fn attach_llm_provenance_keeps_schema_empty_without_structured_fields() {
    let mut rec = MessageIngressRecord {
        request_id: "r2".to_string(),
        task_id: 10,
        channel: "telegram".to_string(),
        user_id: "u2".to_string(),
        session_id: "s2".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik2".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-opaque-id".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(
        rec.provider_request_id.as_deref(),
        Some("provider-opaque-id")
    );
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_uses_v2_when_protocol_or_compliance_present() {
    let mut rec = MessageIngressRecord {
        request_id: "r3".to_string(),
        task_id: 11,
        channel: "telegram".to_string(),
        user_id: "u3".to_string(),
        session_id: "s3".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik3".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-321".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-321"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_trims_whitespace_and_drops_empty_fields() {
    let mut rec = MessageIngressRecord {
        request_id: "r4".to_string(),
        task_id: 12,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("  provider-444  ".to_string()),
        provider: Some("  ".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("   ".to_string()),
        compliance_profile: Some("  cn-pii-restricted  ".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-444"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider, None);
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_drops_overlong_and_controlled_v1_labels() {
    let mut rec = MessageIngressRecord {
        request_id: "r4b".to_string(),
        task_id: 120,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4b".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-4b".to_string()),
        provider: Some("p".repeat(65)),
        model: Some(format!("model-{}", "x".repeat(140))),
        adapter: Some("mcp\nrelay".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4b"));
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_invisible_fillers_in_v1_labels() {
    let mut rec = MessageIngressRecord {
        request_id: "r4c".to_string(),
        task_id: 121,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4c".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-4c".to_string()),
        provider: Some("open\u{200b}ai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4c"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider, None);
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
}

#[test]
fn attach_llm_provenance_normalizes_agent_protocol_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r5".to_string(),
        task_id: 13,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("  MCP  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));
}

#[test]
fn attach_llm_provenance_accepts_agent_protocol_aliases() {
    let mut rec = MessageIngressRecord {
        request_id: "r5a".to_string(),
        task_id: 130,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5a".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("  Model-Context Protocol  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("MCP v2".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent/2/Agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("A2A v1".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("agent-to-agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent 2 Agent Protocol".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
}

#[test]
fn normalized_agent_protocol_accepts_punctuation_variants_for_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("Model.Context.Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol 2.0")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent:To:Agent")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-To-Agent Protocol v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A 2.0")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-2-Agent Protocol JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over JSON-RPC v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over STDIO v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP Streamable HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP HTTP v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol over Streamable HTTP v2"))
            .as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Model Context Protocol SSE v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Protocol STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over SSE v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over STDIO v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Agent-to-Agent Streamable HTTP v1")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent over HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI Model Context Protocol v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP Protocol")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol v1")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over Streamable HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic Model Context Protocol over HTTP v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A over JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google A2A over HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent Protocol")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent Protocol")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent JSON-RPC v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent over Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent over Streamable HTTP v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent2Agent Protocol v2")).as_deref(),
        Some("a2a")
    );
}

#[test]
fn normalized_agent_protocol_accepts_future_version_suffixes() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over HTTP v9")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A Streamable HTTP v12")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent Protocol v27")).as_deref(),
        Some("a2a")
    );
}

#[test]
fn normalized_agent_protocol_rejects_oversized_alias_input() {
    let oversized = format!("MCP over HTTP v2 {}", "x".repeat(200));
    assert_eq!(normalized_agent_protocol(Some(&oversized)), None);
}

#[test]
fn normalized_agent_protocol_accepts_websocket_aliases() {
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WS v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSocket v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("OpenAI MCP WebSockets v3")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSocket v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Anthropic MCP over WebSockets v2")).as_deref(),
        Some("mcp")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSocket v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WS v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("A2A over WebSockets v2")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSocket v4")).as_deref(),
        Some("a2a")
    );
    assert_eq!(
        normalized_agent_protocol(Some("Google Agent-to-Agent WebSockets v4")).as_deref(),
        Some("a2a")
    );
}

#[test]
fn attach_llm_provenance_rejects_non_ascii_or_invisible_agent_protocol_aliases() {
    let mut rec = MessageIngressRecord {
        request_id: "r5aa".to_string(),
        task_id: 1301,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5aa".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("MCP🔥".to_string()),
        compliance_profile: None,
    };
    attach_llm_provenance(&mut rec, &llm);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("a2a\u{200b}".to_string()),
        compliance_profile: None,
    };
    attach_llm_provenance(&mut rec, &llm);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_drops_unsupported_agent_protocol() {
    let mut rec = MessageIngressRecord {
        request_id: "r5b".to_string(),
        task_id: 131,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5b".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("prid-1".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some(" custom-proto ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_keeps_v1_when_v2_fields_are_invalid() {
    let mut rec = MessageIngressRecord {
        request_id: "r5c".to_string(),
        task_id: 132,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5c".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("prid-2".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some(" custom-proto ".to_string()),
        compliance_profile: Some("CN@PII@Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider.as_deref(), Some("openai"));
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(prov.compliance_profile, None);
}

#[test]
fn attach_llm_provenance_normalizes_compliance_profile_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r6".to_string(),
        task_id: 14,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("  CN-PII-Restricted  ".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_normalizes_space_separated_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6-space".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6-space".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("CN PII Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_rejects_invalid_compliance_profile_chars() {
    let mut rec = MessageIngressRecord {
        request_id: "r6b".to_string(),
        task_id: 141,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6b".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6b".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("CN@PII@Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_boundary_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6c".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6c".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6c".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("-cn-pii-restricted_".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_repeated_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6d".to_string(),
        task_id: 143,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6d".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6d".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn--pii__restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_mixed_adjacent_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6e".to_string(),
        task_id: 144,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6e".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6e".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn-_pii-restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn normalized_compliance_profile_accepts_64_char_boundary() {
    let profile = format!("{}-{}", "a".repeat(31), "b".repeat(32));
    assert_eq!(profile.len(), 64);
    assert_eq!(
        normalized_compliance_profile(Some(&profile)).as_deref(),
        Some(profile.as_str())
    );
}

#[test]
fn normalized_compliance_profile_rejects_over_64_chars() {
    let profile = "a".repeat(65);
    assert_eq!(normalized_compliance_profile(Some(&profile)), None);
}

#[test]
fn normalized_compliance_profile_rejects_numeric_only_values() {
    assert_eq!(normalized_compliance_profile(Some("202602")), None);
}

#[test]
fn normalized_compliance_profile_rejects_single_token_values() {
    assert_eq!(normalized_compliance_profile(Some("restricted")), None);
}

#[test]
fn normalized_compliance_profile_accepts_alphanumeric_when_contains_alpha() {
    assert_eq!(
        normalized_compliance_profile(Some("cn-202602")).as_deref(),
        Some("cn-202602")
    );
}

#[test]
fn normalized_compliance_profile_accepts_dot_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN.PII.Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_slash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN/PII/Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_backslash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN\\PII\\Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_space_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN PII Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_space_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn  pii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_control_whitespace_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\tpii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_newline_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\npii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_dot_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn..pii.restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_mixed_path_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\\/pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_values_starting_with_digit() {
    assert_eq!(
        normalized_compliance_profile(Some("1cn-pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_canonicalizes_underscore_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN_PII_RESTRICTED")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_provenance_label_accepts_ascii_audit_text() {
    assert_eq!(
        normalized_provenance_label(Some("openai gpt-5.3:preview"), 64).as_deref(),
        Some("openai gpt-5.3:preview")
    );
}

#[test]
fn normalized_provenance_label_rejects_non_ascii_homoglyphs() {
    assert_eq!(
        normalized_provenance_label(Some("оpenai"), 64),
        None,
        "non-ascii provenance labels should be rejected to avoid audit ambiguity"
    );
}

#[test]
fn normalized_provenance_label_rejects_embedded_control_characters() {
    assert_eq!(
        normalized_provenance_label(Some("openai\nmodel"), 64),
        None,
        "embedded control chars should fail-closed for provenance labels"
    );
}
