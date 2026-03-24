use super::support::*;
use super::super::*;

#[test]
fn tee_verifier_rejects_missing_result_hash_binding() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=tee,quote=abc"),
        VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_result_hash_mismatch_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
    ));
}

#[test]
fn tee_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Result_Hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_result_hash_with_repeated_hex_prefix_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=0x0xabababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=\" abababababababababababababababababababababababababababababababab\",result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=\"abababababababababababababababababababababababababababababababab \",result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_result_hash_binding_with_single_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,'result_hash'=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_result_hash_binding_with_double_quoted_alias_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,\"result_hash\"=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
    let verifier = TeeVerifier::default();
    let mut task = mock_task();
    task.result_hash = None;

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_duplicate_result_hash_binding_without_context_fail_closed() {
    let verifier = TeeVerifier::default();
    let mut task = mock_task();
    task.result_hash = None;

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=aa,result_hash=bb,quote=abc"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_equals_then_ascii_result_hash_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,worker=worker1,proof_type=tee,result_hash＝abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn tee_verifier_rejects_fullwidth_colon_then_ascii_result_hash_binding_fail_closed() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            "TEE:task_id=42,worker=worker1,proof_type=tee,result_hash：abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                .as_bytes()
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}
