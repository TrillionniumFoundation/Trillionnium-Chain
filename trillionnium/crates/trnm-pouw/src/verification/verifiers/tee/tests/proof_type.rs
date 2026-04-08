use super::support::*;
use super::super::*;

#[test]
fn tee_verifier_rejects_proof_type_mismatch_when_present() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab"),
        VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
    ));
}

#[test]
fn tee_verifier_rejects_missing_proof_type_binding() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
        VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,Proof_Type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=\" tee\",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=\"tee \",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_trailing_space_fail_closed(
) {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type='tee ',proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_leading_space_fail_closed(
) {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=' tee',proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_equals_then_ascii_proof_type_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,worker=worker1,proof_type＝tee,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
    ));
}
