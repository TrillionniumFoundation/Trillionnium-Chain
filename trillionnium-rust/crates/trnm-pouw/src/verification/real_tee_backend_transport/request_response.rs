use super::*;

pub(super) fn encode_mock_verifier_response_json(
    response: &MockVerifierResponse,
) -> Result<String, BackendExecutionError> {
    serde_json::to_string(response).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode mock verifier response json: {err}"),
    })
}

pub(super) fn decode_mock_verifier_response_json(
    raw: &str,
    request: &BackendVerificationRequest<'_>,
) -> Result<MockVerifierResponse, BackendExecutionError> {
    serde_json::from_str(raw).map_err(|err| BackendExecutionError::MalformedProof {
        backend: request.backend_label(RealTeeBackend::backend_id_static()),
        reason: format!("invalid verifier response payload: {err}"),
    })
}

fn backend_label_from_response(
    response: &MockVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> String {
    let backend_id = if response.backend_id.trim().is_empty() {
        RealTeeBackend::backend_id_static().to_string()
    } else {
        response.backend_id.clone()
    };
    request.backend_label(&backend_id)
}

fn response_detail_or_default(response: &MockVerifierResponse, default: &str) -> String {
    response
        .detail
        .clone()
        .unwrap_or_else(|| default.to_string())
}

pub(super) fn map_mock_verifier_response(
    response: MockVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> Result<BackendVerificationSuccess, BackendExecutionError> {
    match response.status {
        MockVerifierResponseStatus::Verified => Ok(BackendVerificationSuccess {
            backend_id: response.backend_id,
        }),
        MockVerifierResponseStatus::Invalid => Err(BackendExecutionError::InvalidProof {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier rejected attestation evidence",
            ),
        }),
        MockVerifierResponseStatus::Unavailable => Err(BackendExecutionError::Unavailable {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier transport is unavailable",
            ),
        }),
        MockVerifierResponseStatus::Malformed => Err(BackendExecutionError::MalformedProof {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier reported malformed request or evidence",
            ),
        }),
        MockVerifierResponseStatus::Internal => Err(BackendExecutionError::Internal {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(&response, "external verifier failed internally"),
        }),
    }
}

pub(super) fn mock_response_from_fixture_result(
    result: Result<(), BackendExecutionError>,
    backend_id: String,
) -> MockVerifierResponse {
    match result {
        Ok(()) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id,
            detail: None,
            telemetry_event: None,
        },
        Err(BackendExecutionError::InvalidProof { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Invalid,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::Unavailable { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Unavailable,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::NotConfigured { .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Unavailable,
            backend_id,
            detail: Some("external verifier backend not configured".to_string()),
            telemetry_event: None,
        },
        Err(BackendExecutionError::MalformedProof { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Malformed,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::Internal { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Internal,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
    }
}
