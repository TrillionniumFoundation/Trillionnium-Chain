use super::support::mock_task;
use super::*;

#[test]
fn fraud_verifier_rejects_worker_mismatch_when_worker_is_present() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"worker\":\"worker-x\"}"),
        VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
    ));
}

#[test]
fn fraud_verifier_rejects_missing_worker_binding_when_worker_is_present() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"proof_type\":\"fraud\"}"),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_zero_width_worker_binding_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "FRAUD:{\"task_id\":7,\"worker\":\"worke\u{200b}r-fraud\",\"proof_type\":\"fraud\"}"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_noncanonical_worker_binding_context_fail_closed() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.worker = Some(" worker-fraud ".into());

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("non-canonical worker binding context")
    ));
}

#[test]
fn fraud_verifier_rejects_unexpected_worker_binding_without_worker_context_fail_closed() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.worker = None;

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_worker_binding_with_cyrillic_homoglyph_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "FRAUD:{\"task_id\":7,\"worker\":\"wоrker-fraud\",\"proof_type\":\"fraud\"}"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"Worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud \",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\" worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",'worker':\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker:\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"WORKER\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_underscore_worker_identifier_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\xef\xbc\xbf\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_equals_then_ascii_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\"\xef\xbc\x9a\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_colon_then_ascii_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\"\xef\xbc\x9a\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x8c\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_worker_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x9b\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}
