use super::support::*;
use super::super::*;

#[test]
fn tee_verifier_rejects_task_id_mismatch() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:task_id=99,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
        VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
    ));
}

#[test]
fn tee_verifier_rejects_missing_task_id_binding() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:quote=abc,nonce=1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab"),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_task_id_identifier_spoof() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:xtask_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_task_id_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=\" 42\",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=\"42 \",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_task_id_binding_with_single_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id='42',task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_equals_then_ascii_task_id_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id＝42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}
