use super::*;
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
