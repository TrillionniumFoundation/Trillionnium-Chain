use super::support::*;
use super::super::*;

#[test]
fn tee_verifier_rejects_missing_worker_binding() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:task_id=42,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_worker_binding_identifier_spoof() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,networker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_underscore_worker_identifier_spoof_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,work＿er=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_worker_case_mismatch() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=Worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_worker_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Worker=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,'worker'=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_worker_binding_with_single_quoted_trailing_space_alias_fail_closed(
) {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,'worker '=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker=worker1,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_unexpected_worker_binding_without_context_fail_closed() {
    let verifier = TeeVerifier::default();
    let mut task = mock_task();
    task.worker = None;

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_equals_unexpected_worker_binding_without_context_fail_closed()
{
    let verifier = TeeVerifier::default();
    let mut task = mock_task();
    task.worker = None;

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker＝worker1,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_colon_then_ascii_worker_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,worker：worker1,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}
