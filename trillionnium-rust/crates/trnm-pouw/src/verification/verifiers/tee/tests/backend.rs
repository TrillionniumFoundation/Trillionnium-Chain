use super::support::*;
use super::super::*;
use std::sync::Arc;

#[test]
fn tee_verifier_requires_cryptographic_backend_after_bound_envelope_validation() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Indeterminate(msg)
            if msg.contains("cryptographic verification backend not configured")
    ));
}

#[test]
fn tee_verifier_valid_receipt_path_with_mock_backend() {
    let verifier = verifier_with_backend(
        ZkBackendKind::Custom("mock-tee".into()),
        MockTeeSuccessBackend,
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, mock_attested_receipt()),
        VerificationResult::Valid
    ));
}

#[test]
fn tee_verifier_invalid_receipt_path_with_mock_backend() {
    let verifier = verifier_with_backend(
        ZkBackendKind::Custom("mock-tee-invalid".into()),
        MockTeeInvalidBackend,
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, mock_attested_receipt()),
        VerificationResult::Invalid(msg) if msg.contains("mock tee backend rejected proof")
    ));
}

#[test]
fn tee_verifier_backend_unavailable_maps_to_indeterminate() {
    let verifier = verifier_with_backend(
        ZkBackendKind::Custom("mock-tee-unavailable".into()),
        MockTeeUnavailableBackend,
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, mock_attested_receipt()),
        VerificationResult::Indeterminate(msg)
            if msg.contains("unavailable:")
                && msg.contains("mock-tee-unavailable")
                && msg.contains("cannot currently verify receipt")
    ));
}

#[test]
fn tee_verifier_backend_malformed_maps_to_invalid_fail_closed() {
    let verifier = verifier_with_backend(
        ZkBackendKind::Custom("mock-tee-malformed".into()),
        MockTeeMalformedBackend,
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, mock_attested_receipt()),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:") && msg.contains("mock tee receipt malformed")
    ));
}

#[test]
fn tee_verifier_backend_internal_maps_to_indeterminate_with_backend_error_prefix() {
    let verifier = verifier_with_backend(
        ZkBackendKind::Custom("mock-tee-internal".into()),
        MockTeeInternalBackend,
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(&task, mock_attested_receipt()),
        VerificationResult::Indeterminate(msg)
            if msg.contains("backend_error:")
                && msg.contains("mock-tee-internal")
                && msg.contains("mock tee backend internal failure")
    ));
}

#[test]
fn tee_verifier_selection_error_maps_to_unavailable_prefix() {
    let verifier = TeeVerifier::new(
        ZkBackendKind::Custom("missing-tee-backend".into()),
        Arc::new(ZkBackendRegistry::new()),
    );
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Indeterminate(msg)
            if msg.contains("unavailable:") && msg.contains("missing-tee-backend")
    ));
}

#[test]
fn tee_verifier_requires_cryptographic_backend_for_legacy_receipt_alias() {
    let verifier = TeeVerifier::default();
    let task = mock_task();

    assert!(matches!(
        verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee_receipt,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        ),
        VerificationResult::Indeterminate(msg)
            if msg.contains("cryptographic verification backend not configured")
    ));
}
