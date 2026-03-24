use super::*;

#[test]
fn client_backed_intel_provider_delegates_request_to_client() {
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
    let provider = ClientBackedIntelQuoteVerifierProvider::new(
        Arc::new(AssertingIntelQuoteClient),
        Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
    );

    let result = provider.verify_intel_quote_bundle(
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
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-client"
    ));
}

#[test]
fn client_backed_amd_provider_delegates_request_to_client() {
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
    let provider = ClientBackedAmdReportVerifierProvider::new(
        Arc::new(AssertingAmdReportClient),
        Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
    );

    let result = provider.verify_amd_report_bundle(
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
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-client"
    ));
}

#[test]
fn client_backed_intel_provider_fails_closed_when_external_auth_missing() {
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
    let mut vars = BTreeMap::new();
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_MODE".to_string(),
        "external".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_PROFILE".to_string(),
        "intel-dcap-external-override".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_ENDPOINT_BASE".to_string(),
        "https://override.intel.example/v2/quote".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_AUTH_SCHEME".to_string(),
        "".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_AUTH_REF_PREFIX".to_string(),
        "".to_string(),
    );
    let provider = ClientBackedIntelQuoteVerifierProvider::new(
        Arc::new(PanicIntelQuoteClient),
        Arc::new(EnvVerifierTransportConfigSource::from_vars(
            StaticVerifierTransportConfigSource::mock_defaults(),
            vars,
        )),
    );
    let result = provider.verify_intel_quote_bundle(
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
    assert!(
        matches!(result, Err(BackendExecutionError::NotConfigured { backend }) if backend.contains("sgx-dcap") && backend.contains("quote-verifier"))
    );
}

#[test]
fn client_backed_amd_provider_fails_closed_when_profile_missing() {
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
    let mut vars = BTreeMap::new();
    vars.insert(
        "TRNM_TEE_AMD_REPORT_MODE".to_string(),
        "external".to_string(),
    );
    vars.insert("TRNM_TEE_AMD_REPORT_PROFILE".to_string(), "".to_string());
    vars.insert(
        "TRNM_TEE_AMD_REPORT_ENDPOINT_BASE".to_string(),
        "https://override.amd.example/v2/report".to_string(),
    );
    vars.insert(
        "TRNM_TEE_AMD_REPORT_AUTH_REF_PREFIX".to_string(),
        "tee.amd.override-token".to_string(),
    );
    vars.insert(
        "TRNM_TEE_AMD_REPORT_AUTH_SCHEME".to_string(),
        "bearer".to_string(),
    );
    let provider = ClientBackedAmdReportVerifierProvider::new(
        Arc::new(PanicAmdReportClient),
        Arc::new(EnvVerifierTransportConfigSource::from_vars(
            StaticVerifierTransportConfigSource::mock_defaults(),
            vars,
        )),
    );
    let result = provider.verify_amd_report_bundle(
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
    assert!(
        matches!(result, Err(BackendExecutionError::NotConfigured { backend }) if backend.contains("sev-snp") && backend.contains("report-verifier"))
    );
}

#[test]
fn client_backed_intel_provider_rejects_mismatched_response_telemetry_fail_closed() {
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
    let provider = ClientBackedIntelQuoteVerifierProvider::new(
        Arc::new(MismatchedTelemetryIntelQuoteClient),
        Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
    );
    let result = provider.verify_intel_quote_bundle(
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
    assert!(
        matches!(result, Err(BackendExecutionError::MalformedProof { reason, .. }) if reason.contains("telemetry does not match request metadata"))
    );
}

