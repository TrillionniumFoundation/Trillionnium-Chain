use super::*;

pub(super) fn build_request_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::RequestPrepared,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: None,
        status: None,
        detail: None,
    }
}

pub(super) fn build_response_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
    response: &MockVerifierResponse,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::ResponseReceived,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: Some(response.backend_id.clone()),
        status: Some(response.status),
        detail: response.detail.clone(),
    }
}

pub(super) fn build_mapped_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
    response: &MockVerifierResponse,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::ResponseMapped,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: Some(response.backend_id.clone()),
        status: Some(response.status),
        detail: response.detail.clone(),
    }
}

pub(super) fn validate_response_telemetry_event(
    response: &MockVerifierResponse,
    metadata: &ExternalCallMetadata,
    request: &BackendVerificationRequest<'_>,
) -> Result<(), BackendExecutionError> {
    let Some(event) = response.telemetry_event.as_ref() else {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response missing telemetry event".to_string(),
        });
    };
    if event.request_id != metadata.request_id || event.telemetry_scope != metadata.telemetry_scope
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response telemetry does not match request metadata".to_string(),
        });
    }
    if event.kind != VerifierTelemetryEventKind::ResponseReceived {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response telemetry kind is invalid".to_string(),
        });
    }
    Ok(())
}

pub(super) fn build_external_call_metadata(
    request: &BackendVerificationRequest<'_>,
    verifier_kind: &str,
    attestation_target: &str,
    transport: &VerifierTransportConfig,
) -> ExternalCallMetadata {
    ExternalCallMetadata {
        request_id: format!(
            "tee:{}:{}:task-{}:attempt-1",
            verifier_kind, attestation_target, request.task.task_id
        ),
        telemetry_scope: format!(
            "trnm.pouw.tee.{}.{}",
            verifier_kind.replace('-', "_"),
            attestation_target.replace('-', "_")
        ),
        attempt: 1,
        retry_policy: transport.retry_policy.clone(),
    }
}

pub(super) fn build_http_headers(
    profile: &ResolvedVerifierProfile,
    metadata: &ExternalCallMetadata,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("x-request-id".to_string(), metadata.request_id.clone());
    headers.insert(
        "x-telemetry-scope".to_string(),
        metadata.telemetry_scope.clone(),
    );
    headers.insert("x-transport-profile".to_string(), profile.profile.clone());
    headers
}
