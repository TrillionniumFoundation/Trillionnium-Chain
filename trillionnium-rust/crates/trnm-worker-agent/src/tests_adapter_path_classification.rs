use super::*;

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
