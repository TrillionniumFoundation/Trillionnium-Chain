use super::*;

#[test]
fn mock_verifier_response_json_codec_roundtrip() {
    let response = MockVerifierResponse {
        status: MockVerifierResponseStatus::Verified,
        backend_id: "intel-dcap-quote-verifier".into(),
        detail: Some("ok".into()),
        telemetry_event: Some(VerifierTelemetryEvent {
            kind: VerifierTelemetryEventKind::ResponseReceived,
            request_id: "req-1".into(),
            telemetry_scope: "trnm.test".into(),
            transport_mode: VerifierTransportMode::Mock,
            profile: "test-profile".into(),
            backend_id: Some("intel-dcap-quote-verifier".into()),
            status: Some(MockVerifierResponseStatus::Verified),
            detail: Some("ok".into()),
        }),
    };
    let raw = encode_mock_verifier_response_json(&response).unwrap();
    let task = mock_task();
    let decoded = decode_mock_verifier_response_json(
        &raw,
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        },
    )
    .unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn mock_verifier_response_json_codec_rejects_invalid_json() {
    let task = mock_task();
    let err = decode_mock_verifier_response_json(
        "{not-json",
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("invalid verifier response payload"))
    );
}

