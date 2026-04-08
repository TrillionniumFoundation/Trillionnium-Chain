use super::*;

#[test]
fn provider_backed_executor_delegates_intel_quote_bundle_to_provider() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
    let input = match SGX_DCAP_ADAPTER
        .build_verifier_input(&handoff, None)
        .unwrap()
    {
        TeeVerifierInput::Quote(input) => input,
        TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
    };
    let executor = ProviderBackedVendorVerifierExecutor::new(
        Arc::new(AssertingIntelQuoteProvider),
        Arc::new(RejectingAmdReportProvider),
    );

    let result = executor.verify_intel_quote_bundle(
        &input,
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data,
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        },
    );

    assert!(matches!(
        result,
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-provider"
    ));
}

#[test]
fn provider_backed_executor_delegates_amd_report_bundle_to_provider() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
    let input = match SEV_SNP_ADAPTER
        .build_verifier_input(&handoff, None)
        .unwrap()
    {
        TeeVerifierInput::Report(input) => input,
        TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
    };
    let executor = ProviderBackedVendorVerifierExecutor::new(
        Arc::new(RejectingIntelQuoteProvider),
        Arc::new(AssertingAmdReportProvider),
    );

    let result = executor.verify_amd_report_bundle(
        &input,
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data,
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        },
    );

    assert!(matches!(
        result,
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-provider"
    ));
}

struct AssertingIntelQuoteExecutor;

impl VendorVerifierExecutor for AssertingIntelQuoteExecutor {
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
            backend_id: "intel-mock-executor".into(),
        })
    }

    fn verify_amd_report_bundle(
        &self,
        _input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::Internal {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "unexpected amd report path in intel executor test".to_string(),
        })
    }
}

struct AssertingAmdReportExecutor;

impl VendorVerifierExecutor for AssertingAmdReportExecutor {
    fn verify_intel_quote_bundle(
        &self,
        _input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::Internal {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "unexpected intel quote path in amd executor test".to_string(),
        })
    }

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
            backend_id: "amd-mock-executor".into(),
        })
    }
}
