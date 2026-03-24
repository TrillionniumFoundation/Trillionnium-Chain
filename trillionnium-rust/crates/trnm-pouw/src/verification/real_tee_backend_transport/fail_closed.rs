use super::*;

pub(super) fn validate_transport_auth_and_profile(
    transport: &VerifierTransportConfig,
    request: &BackendVerificationRequest<'_>,
    verifier_kind: &str,
    attestation_target: &str,
) -> Result<(), BackendExecutionError> {
    let backend = request.backend_label(&format!(
        "{}-{}-client",
        attestation_target,
        verifier_kind.replace(':', "-")
    ));
    if transport.profile.trim().is_empty() {
        return Err(BackendExecutionError::NotConfigured { backend });
    }
    if transport.endpoint.trim().is_empty() {
        return Err(BackendExecutionError::NotConfigured { backend });
    }
    match transport.mode {
        VerifierTransportMode::Mock => {
            if !transport.endpoint.starts_with("mock://") {
                return Err(BackendExecutionError::MalformedProof {
                    backend,
                    reason: format!(
                        "mock verifier transport for '{}' must use mock:// endpoint",
                        attestation_target
                    ),
                });
            }
        }
        VerifierTransportMode::External => {
            let auth_scheme = transport.auth_scheme.as_deref().unwrap_or("").trim();
            let auth_ref = transport.auth_ref.as_deref().unwrap_or("").trim();
            if auth_scheme.is_empty() || auth_ref.is_empty() {
                return Err(BackendExecutionError::NotConfigured { backend });
            }
            if !transport.endpoint.starts_with("https://") {
                return Err(BackendExecutionError::MalformedProof {
                    backend,
                    reason: format!(
                        "external verifier transport for '{}' must use https:// endpoint",
                        attestation_target
                    ),
                });
            }
        }
    }
    if transport.retry_policy.max_attempts == 0 {
        return Err(BackendExecutionError::MalformedProof {
            backend,
            reason: format!(
                "verifier transport for '{}' must set retry max_attempts >= 1",
                attestation_target
            ),
        });
    }
    Ok(())
}

pub(super) fn decode_http_verifier_response(
    http_response: &HttpVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> Result<MockVerifierResponse, BackendExecutionError> {
    match http_response.status_code {
        200..=299 => decode_mock_verifier_response_json(&http_response.body, request),
        400..=499 => Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "http verifier request rejected with status {}",
                http_response.status_code
            ),
        }),
        _ => Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "http verifier transport returned status {}",
                http_response.status_code
            ),
        }),
    }
}
