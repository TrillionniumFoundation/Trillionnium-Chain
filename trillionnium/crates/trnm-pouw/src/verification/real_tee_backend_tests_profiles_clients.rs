use super::*;

pub(super) struct PanicIntelQuoteClient;

impl IntelQuoteVerifierClient for PanicIntelQuoteClient {
    fn verify_intel_quote_request(
        &self,
        _request_input: &IntelQuoteVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        panic!("intel quote client should not be called when config validation fails")
    }
}

pub(super) struct PanicAmdReportClient;

impl AmdReportVerifierClient for PanicAmdReportClient {
    fn verify_amd_report_request(
        &self,
        _request_input: &AmdReportVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        panic!("amd report client should not be called when config validation fails")
    }
}

pub(super) struct MismatchedTelemetryIntelQuoteClient;

impl IntelQuoteVerifierClient for MismatchedTelemetryIntelQuoteClient {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "intel-dcap-quote-verifier".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: format!("{}-other", request_input.call_metadata.request_id),
                telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                transport_mode: request_input.transport.mode.clone(),
                profile: request_input.transport.profile.clone(),
                backend_id: Some("intel-dcap-quote-verifier".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        })
    }
}

pub(super) struct AssertingIntelHttpTransport;

impl VerifierHttpTransport for AssertingIntelHttpTransport {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        assert_eq!(http_request.method, HttpMethod::Post);
        assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
        assert_eq!(http_request.profile, "intel-dcap-external-default");
        assert_eq!(
            http_request.url,
            "https://intel-verifier.invalid/v1/quote/sgx-dcap"
        );
        assert_eq!(http_request.timeout_ms, 5_000);
        assert_eq!(
            http_request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            http_request.headers.get("x-request-id").map(String::as_str),
            Some("tee:quote-verifier:sgx-dcap:task-42:attempt-1")
        );
        assert_eq!(
            http_request
                .headers
                .get("x-transport-profile")
                .map(String::as_str),
            Some("intel-dcap-external-default")
        );
        assert_eq!(
            http_request
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("bearer tee.intel.external-token.sgx-dcap")
        );
        let payload: IntelQuoteVerifierHttpPayload =
            serde_json::from_str(&http_request.body).unwrap();
        assert_eq!(payload.attestation_target, "sgx-dcap");
        assert_eq!(payload.measurement_field, "mrenclave");
        assert_eq!(payload.measurement, "mrenclave:demo-sgx-v1");
        assert_eq!(payload.quote, "quote-sgx-dcap-demo-v1");
        assert_eq!(payload.retry_policy.max_attempts, 3);
        let response = MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "intel-http-transport".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: payload.request_id.clone(),
                telemetry_scope: payload.telemetry_scope.clone(),
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                backend_id: Some("intel-http-transport".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        };
        Ok(HttpVerifierResponse {
            status_code: 200,
            body: encode_mock_verifier_response_json(&response).unwrap(),
        })
    }
}

pub(super) struct AssertingAmdHttpTransport;

impl VerifierHttpTransport for AssertingAmdHttpTransport {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        assert_eq!(http_request.method, HttpMethod::Post);
        assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
        assert_eq!(http_request.profile, "amd-sev-snp-external-default");
        assert_eq!(
            http_request.url,
            "https://amd-verifier.invalid/v1/report/sev-snp"
        );
        assert_eq!(http_request.timeout_ms, 5_000);
        assert_eq!(
            http_request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            http_request.headers.get("x-request-id").map(String::as_str),
            Some("tee:report-verifier:sev-snp:task-42:attempt-1")
        );
        assert_eq!(
            http_request
                .headers
                .get("x-transport-profile")
                .map(String::as_str),
            Some("amd-sev-snp-external-default")
        );
        assert_eq!(
            http_request
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("bearer tee.amd.external-token.sev-snp")
        );
        let payload: AmdReportVerifierHttpPayload =
            serde_json::from_str(&http_request.body).unwrap();
        assert_eq!(payload.attestation_target, "sev-snp");
        assert_eq!(payload.measurement_field, "measurement");
        assert_eq!(payload.measurement, "measurement:demo-snp-v1");
        assert_eq!(payload.report, "report-sev-snp-demo-v1");
        assert_eq!(payload.retry_policy.max_attempts, 3);
        let response = MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "amd-http-transport".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: payload.request_id.clone(),
                telemetry_scope: payload.telemetry_scope.clone(),
                transport_mode: VerifierTransportMode::External,
                profile: "amd-sev-snp-external-default".into(),
                backend_id: Some("amd-http-transport".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        };
        Ok(HttpVerifierResponse {
            status_code: 200,
            body: encode_mock_verifier_response_json(&response).unwrap(),
        })
    }
}

pub(super) struct FlakyIntelHttpTransport {
    calls: Arc<Mutex<Vec<String>>>,
}

impl VerifierHttpTransport for FlakyIntelHttpTransport {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        let attempt = http_request
            .headers
            .get("x-attempt")
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        self.calls.lock().unwrap().push(attempt.clone());
        if attempt == "1" {
            Ok(HttpVerifierResponse {
                status_code: 503,
                body: "upstream unavailable".into(),
            })
        } else {
            let response = MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "intel-http-retry".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                    telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                    transport_mode: VerifierTransportMode::External,
                    profile: "intel-dcap-external-default".into(),
                    backend_id: Some("intel-http-retry".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            };
            Ok(HttpVerifierResponse {
                status_code: 200,
                body: encode_mock_verifier_response_json(&response).unwrap(),
            })
        }
    }
}


pub(super) struct AssertingExternalIntelQuoteClient;

impl IntelQuoteVerifierClient for AssertingExternalIntelQuoteClient {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        assert_eq!(
            request_input.transport.mode,
            VerifierTransportMode::External
        );
        assert_eq!(
            request_input.transport.endpoint,
            "https://intel-verifier.invalid/v1/quote/sgx-dcap"
        );
        assert_eq!(
            request_input.transport.profile,
            "intel-dcap-external-default"
        );
        assert_eq!(request_input.transport.timeout_ms, 5_000);
        assert_eq!(request_input.transport.retry_policy.max_attempts, 3);
        assert_eq!(request_input.transport.retry_policy.backoff_ms, 250);
        assert_eq!(
            request_input.transport.retry_policy.strategy,
            RetryBackoffStrategy::Exponential
        );
        assert_eq!(
            request_input.transport.auth_ref.as_deref(),
            Some("tee.intel.external-token.sgx-dcap")
        );
        assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 3);
        assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 250);
        assert_eq!(
            request_input.request_event.kind,
            VerifierTelemetryEventKind::RequestPrepared
        );
        assert_eq!(
            request_input.request_event.profile,
            "intel-dcap-external-default"
        );
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "intel-external-mock-client".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: request_input.call_metadata.request_id.clone(),
                telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                transport_mode: request_input.transport.mode.clone(),
                profile: request_input.transport.profile.clone(),
                backend_id: Some("intel-external-mock-client".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        })
    }
}

pub(super) struct AssertingExternalAmdReportClient;

impl AmdReportVerifierClient for AssertingExternalAmdReportClient {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        assert_eq!(
            request_input.transport.mode,
            VerifierTransportMode::External
        );
        assert_eq!(
            request_input.transport.endpoint,
            "https://amd-verifier.invalid/v1/report/sev-snp"
        );
        assert_eq!(
            request_input.transport.profile,
            "amd-sev-snp-external-default"
        );
        assert_eq!(request_input.transport.timeout_ms, 5_000);
        assert_eq!(request_input.transport.retry_policy.max_attempts, 3);
        assert_eq!(request_input.transport.retry_policy.backoff_ms, 250);
        assert_eq!(
            request_input.transport.retry_policy.strategy,
            RetryBackoffStrategy::Exponential
        );
        assert_eq!(
            request_input.transport.auth_ref.as_deref(),
            Some("tee.amd.external-token.sev-snp")
        );
        assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 3);
        assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 250);
        assert_eq!(
            request_input.request_event.kind,
            VerifierTelemetryEventKind::RequestPrepared
        );
        assert_eq!(
            request_input.request_event.profile,
            "amd-sev-snp-external-default"
        );
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "amd-external-mock-client".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: request_input.call_metadata.request_id.clone(),
                telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                transport_mode: request_input.transport.mode.clone(),
                profile: request_input.transport.profile.clone(),
                backend_id: Some("amd-external-mock-client".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        })
    }
}

pub(super) struct AssertingIntelQuoteClient;

impl IntelQuoteVerifierClient for AssertingIntelQuoteClient {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        assert_eq!(request_input.transport.mode, VerifierTransportMode::Mock);
        assert_eq!(
            request_input.transport.endpoint,
            "mock://intel-quote-verifier/sgx-dcap"
        );
        assert_eq!(request_input.transport.profile, "intel-dcap-mock-default");
        assert_eq!(request_input.transport.timeout_ms, 1_500);
        assert_eq!(request_input.transport.retry_policy.max_attempts, 1);
        assert_eq!(request_input.transport.retry_policy.backoff_ms, 0);
        assert_eq!(
            request_input.transport.retry_policy.strategy,
            RetryBackoffStrategy::Fixed
        );
        assert_eq!(
            request_input.transport.auth_scheme.as_deref(),
            Some("bearer")
        );
        assert_eq!(
            request_input.transport.auth_ref.as_deref(),
            Some("tee.intel.mock-token.sgx-dcap")
        );
        assert_eq!(
            request_input.call_metadata.request_id,
            "tee:quote-verifier:sgx-dcap:task-42:attempt-1"
        );
        assert_eq!(
            request_input.call_metadata.telemetry_scope,
            "trnm.pouw.tee.quote_verifier.sgx_dcap"
        );
        assert_eq!(request_input.call_metadata.attempt, 1);
        assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 1);
        assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 0);
        assert_eq!(
            request_input.request_event.kind,
            VerifierTelemetryEventKind::RequestPrepared
        );
        assert_eq!(
            request_input.request_event.profile,
            "intel-dcap-mock-default"
        );
        assert_eq!(request_input.attestation_target, "sgx-dcap");
        assert_eq!(request_input.measurement_field, "mrenclave");
        assert_eq!(request_input.measurement, "mrenclave:demo-sgx-v1");
        assert_eq!(request_input.quote, "quote-sgx-dcap-demo-v1");
        assert_eq!(
            request_input.intel_collateral.collateral,
            "intel-dcap-collateral-demo-v1"
        );
        assert_eq!(
            request_input.intel_collateral.cert_chain,
            "intel-dcap-cert-chain-demo-v1"
        );
        assert_eq!(request_input.intel_collateral.issuer, "intel");
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "intel-mock-client".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: request_input.call_metadata.request_id.clone(),
                telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                transport_mode: request_input.transport.mode.clone(),
                profile: request_input.transport.profile.clone(),
                backend_id: Some("intel-mock-client".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        })
    }
}

pub(super) struct AssertingAmdReportClient;

impl AmdReportVerifierClient for AssertingAmdReportClient {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        assert_eq!(request_input.transport.mode, VerifierTransportMode::Mock);
        assert_eq!(
            request_input.transport.endpoint,
            "mock://amd-report-verifier/sev-snp"
        );
        assert_eq!(request_input.transport.profile, "amd-sev-snp-mock-default");
        assert_eq!(request_input.transport.timeout_ms, 1_500);
        assert_eq!(request_input.transport.retry_policy.max_attempts, 1);
        assert_eq!(request_input.transport.retry_policy.backoff_ms, 0);
        assert_eq!(
            request_input.transport.retry_policy.strategy,
            RetryBackoffStrategy::Fixed
        );
        assert_eq!(
            request_input.transport.auth_scheme.as_deref(),
            Some("bearer")
        );
        assert_eq!(
            request_input.transport.auth_ref.as_deref(),
            Some("tee.amd.mock-token.sev-snp")
        );
        assert_eq!(
            request_input.call_metadata.request_id,
            "tee:report-verifier:sev-snp:task-42:attempt-1"
        );
        assert_eq!(
            request_input.call_metadata.telemetry_scope,
            "trnm.pouw.tee.report_verifier.sev_snp"
        );
        assert_eq!(request_input.call_metadata.attempt, 1);
        assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 1);
        assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 0);
        assert_eq!(
            request_input.request_event.kind,
            VerifierTelemetryEventKind::RequestPrepared
        );
        assert_eq!(
            request_input.request_event.profile,
            "amd-sev-snp-mock-default"
        );
        assert_eq!(request_input.attestation_target, "sev-snp");
        assert_eq!(request_input.measurement_field, "measurement");
        assert_eq!(request_input.measurement, "measurement:demo-snp-v1");
        assert_eq!(request_input.report, "report-sev-snp-demo-v1");
        assert_eq!(request_input.amd_signer.vcek, "amd-vcek-demo-v1");
        assert_eq!(
            request_input.amd_signer.cert_chain,
            "amd-cert-chain-demo-v1"
        );
        assert_eq!(request_input.amd_signer.report_signer, "amd");
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "amd-mock-client".into(),
            detail: None,
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: request_input.call_metadata.request_id.clone(),
                telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                transport_mode: request_input.transport.mode.clone(),
                profile: request_input.transport.profile.clone(),
                backend_id: Some("amd-mock-client".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: None,
            }),
        })
    }
}
