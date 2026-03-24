use super::support::mock_task;
use super::*;

#[test]
fn fraud_verifier_rejects_prefix_without_visible_body_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"\xef\xbb\xbfFRAUD:\n\t"),
        VerificationResult::Invalid(msg) if msg.contains("Invalid fraud proof envelope")
    ));
}

#[test]
fn fraud_verifier_rejects_task_id_mismatch() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"FRAUD:{\"task_id\":8,\"worker\":\"worker-fraud\"}"),
        VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
    ));
}

#[test]
fn fraud_verifier_rejects_missing_task_id_binding() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"FRAUD:{\"challenge\":\"ok\"}"),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_proof_type_mismatch_when_present() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"tee\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
    ));
}

#[test]
fn fraud_verifier_rejects_missing_proof_type_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"}"),
        VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
    ));
}

#[test]
fn fraud_verifier_rejects_missing_result_hash_binding_when_expected() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.result_hash = Some([9u8; 32]);

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
    ));
}

#[test]
fn fraud_verifier_rejects_negative_signed_task_id_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":-7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_plus_signed_task_id_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":\xef\xbc\x8b7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_underscore_task_id_identifier_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task\xef\xbc\xbfid\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_underscore_proof_type_identifier_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof\xef\xbc\xbftype\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_underscore_result_hash_identifier_spoof_fail_closed() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.result_hash = Some([9u8; 32]);

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result\xef\xbc\xbfhash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_equals_then_ascii_proof_type_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\"\xef\xbc\x9a\"fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_equals_then_ascii_task_id_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\"\xef\xbc\x9a7,\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_colon_then_ascii_task_id_binding_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\"\xef\xbc\x9a7,\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn fraud_verifier_rejects_fullwidth_equals_then_ascii_result_hash_binding_fail_closed() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.result_hash = Some([9u8; 32]);

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\"\xef\xbc\x9a\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn fraud_verifier_rejects_result_hash_with_repeated_hex_prefix_fail_closed() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.result_hash = Some([9u8; 32]);

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0x0x0909090909090909090909090909090909090909090909090909090909090909\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
    ));
}

#[test]
fn fraud_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}
