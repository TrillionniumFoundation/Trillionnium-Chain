use super::support::mock_task;
use super::*;

#[test]
fn fraud_verifier_accepts_bound_task_id() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert_eq!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Valid
    );
}

#[test]
fn fraud_verifier_accepts_uppercase_proof_type_and_result_hash_prefix_bindings() {
    let verifier = FraudVerifier;
    let mut task = mock_task();
    task.result_hash = Some([9u8; 32]);

    assert_eq!(
        verifier.verify_proof(
            &task,
            b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"FRAUD\",\"result_hash\":\"0X0909090909090909090909090909090909090909090909090909090909090909\"}"
        ),
        VerificationResult::Valid
    );
}

#[test]
fn fraud_verifier_accepts_case_insensitive_prefix_when_bindings_match() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert_eq!(
        verifier.verify_proof(
            &task,
            b"fRaUd:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Valid
    );
}

#[test]
fn fraud_verifier_accepts_utf8_bom_prefixed_payload_when_bindings_match() {
    let verifier = FraudVerifier;
    let task = mock_task();

    assert_eq!(
        verifier.verify_proof(
            &task,
            b"\xef\xbb\xbfFRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
        ),
        VerificationResult::Valid
    );
}
