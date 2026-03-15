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
    let within = "你好ab"; // 4 chars
    assert_eq!(verify_model_output(within, 4), ("accepted", "ok"));

    let over = "你好abc"; // 5 chars
    assert_eq!(
        verify_model_output(over, 4),
        ("rejected", "output_too_long")
    );

    // Leading/trailing transport whitespace should not cause false rejections.
    assert_eq!(verify_model_output(" 你好ab \n", 4), ("accepted", "ok"));

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
