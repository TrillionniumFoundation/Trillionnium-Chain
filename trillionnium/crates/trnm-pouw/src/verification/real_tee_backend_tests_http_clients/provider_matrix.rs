pub(super) use super::super::*;

struct InvalidIntelQuoteClientResponse;

impl IntelQuoteVerifierClient for InvalidIntelQuoteClientResponse {
    fn verify_intel_quote_request(
        &self,
        _request_input: &IntelQuoteVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Invalid,
            backend_id: "intel-dcap-quote-verifier".into(),
            detail: Some("quote digest mismatch".into()),
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                transport_mode: VerifierTransportMode::Mock,
                profile: "intel-dcap-mock-default".into(),
                backend_id: Some("intel-dcap-quote-verifier".into()),
                status: Some(MockVerifierResponseStatus::Invalid),
                detail: Some("quote digest mismatch".into()),
            }),
        })
    }
}

struct UnavailableAmdReportClientResponse;

impl AmdReportVerifierClient for UnavailableAmdReportClientResponse {
    fn verify_amd_report_request(
        &self,
        _request_input: &AmdReportVerifierClientRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        Ok(MockVerifierResponse {
            status: MockVerifierResponseStatus::Unavailable,
            backend_id: "amd-sev-snp-report-verifier".into(),
            detail: Some("transport timeout contacting SNP verifier".into()),
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: "tee:report-verifier:sev-snp:task-42:attempt-1".into(),
                telemetry_scope: "trnm.pouw.tee.report_verifier.sev_snp".into(),
                transport_mode: VerifierTransportMode::Mock,
                profile: "amd-sev-snp-mock-default".into(),
                backend_id: Some("amd-sev-snp-report-verifier".into()),
                status: Some(MockVerifierResponseStatus::Unavailable),
                detail: Some("transport timeout contacting SNP verifier".into()),
            }),
        })
    }
}

struct AssertingIntelQuoteProvider;

impl IntelQuoteVerifierProvider for AssertingIntelQuoteProvider {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(input.attestation_target, "sgx-dcap");
        assert_eq!(input.verifier_kind, "quote-verifier");
        assert_eq!(input.measurement_field, "mrenclave");
        assert_eq!(input.quote, "quote-sgx-dcap-demo-v1");
        assert_eq!(
            input.intel_collateral.collateral,
            "intel-dcap-collateral-demo-v1"
        );
        assert_eq!(
            input.intel_collateral.cert_chain,
            "intel-dcap-cert-chain-demo-v1"
        );
        assert_eq!(input.intel_collateral.issuer, "intel");
        Ok(BackendVerificationSuccess {
            backend_id: "intel-mock-provider".into(),
        })
    }
}

struct AssertingAmdReportProvider;

impl AmdReportVerifierProvider for AssertingAmdReportProvider {
    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(input.attestation_target, "sev-snp");
        assert_eq!(input.verifier_kind, "report-verifier");
        assert_eq!(input.measurement_field, "measurement");
        assert_eq!(input.report, "report-sev-snp-demo-v1");
        assert_eq!(input.amd_signer.vcek, "amd-vcek-demo-v1");
        assert_eq!(input.amd_signer.cert_chain, "amd-cert-chain-demo-v1");
        assert_eq!(input.amd_signer.report_signer, "amd");
        Ok(BackendVerificationSuccess {
            backend_id: "amd-mock-provider".into(),
        })
    }
}

struct RejectingIntelQuoteProvider;

impl IntelQuoteVerifierProvider for RejectingIntelQuoteProvider {
    fn verify_intel_quote_bundle(
        &self,
        _input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::Internal {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "unexpected intel quote path in amd provider test".to_string(),
        })
    }
}

struct RejectingAmdReportProvider;

impl AmdReportVerifierProvider for RejectingAmdReportProvider {
    fn verify_amd_report_bundle(
        &self,
        _input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::Internal {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "unexpected amd report path in intel provider test".to_string(),
        })
    }
}
