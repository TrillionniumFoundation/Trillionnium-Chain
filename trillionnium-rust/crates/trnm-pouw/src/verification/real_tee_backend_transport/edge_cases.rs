use super::*;

pub(super) fn build_intel_quote_http_request(
    request_input: &IntelQuoteVerifierClientRequest,
    profile: &ResolvedVerifierProfile,
    headers: BTreeMap<String, String>,
) -> Result<HttpVerifierRequest, BackendExecutionError> {
    let payload = IntelQuoteVerifierHttpPayload {
        request_id: request_input.call_metadata.request_id.clone(),
        telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
        attestation_target: request_input.attestation_target.clone(),
        measurement_field: request_input.measurement_field.clone(),
        measurement: request_input.measurement.clone(),
        report_data_hash: request_input.report_data_hash.clone(),
        quote: request_input.quote.clone(),
        intel_collateral: request_input.intel_collateral.clone(),
        retry_policy: request_input.call_metadata.retry_policy.clone(),
    };
    let body = serde_json::to_string(&payload).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode intel verifier http payload: {err}"),
    })?;
    Ok(HttpVerifierRequest {
        method: HttpMethod::Post,
        transport_mode: profile.mode.clone(),
        profile: profile.profile.clone(),
        url: profile.endpoint.clone(),
        headers,
        body,
        timeout_ms: profile.timeout_ms,
        retry_policy: request_input.transport.retry_policy.clone(),
    })
}

pub(super) fn build_amd_report_http_request(
    request_input: &AmdReportVerifierClientRequest,
    profile: &ResolvedVerifierProfile,
    headers: BTreeMap<String, String>,
) -> Result<HttpVerifierRequest, BackendExecutionError> {
    let payload = AmdReportVerifierHttpPayload {
        request_id: request_input.call_metadata.request_id.clone(),
        telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
        attestation_target: request_input.attestation_target.clone(),
        measurement_field: request_input.measurement_field.clone(),
        measurement: request_input.measurement.clone(),
        report_data_hash: request_input.report_data_hash.clone(),
        report: request_input.report.clone(),
        amd_signer: request_input.amd_signer.clone(),
        retry_policy: request_input.call_metadata.retry_policy.clone(),
    };
    let body = serde_json::to_string(&payload).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode amd verifier http payload: {err}"),
    })?;
    Ok(HttpVerifierRequest {
        method: HttpMethod::Post,
        transport_mode: profile.mode.clone(),
        profile: profile.profile.clone(),
        url: profile.endpoint.clone(),
        headers,
        body,
        timeout_ms: profile.timeout_ms,
        retry_policy: request_input.transport.retry_policy.clone(),
    })
}

pub(super) trait IntelQuoteVerifierClient: Send + Sync {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError>;
}

pub(super) trait AmdReportVerifierClient: Send + Sync {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError>;
}

pub(super) trait IntelQuoteVerifierProvider: Send + Sync {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

pub(super) trait AmdReportVerifierProvider: Send + Sync {
    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}
