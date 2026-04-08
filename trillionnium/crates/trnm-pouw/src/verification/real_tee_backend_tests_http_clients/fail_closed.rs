use super::*;

#[test]
fn client_backed_intel_provider_maps_invalid_response_fail_closed() {
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
        Arc::new(InvalidIntelQuoteClientResponse),
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
        Err(BackendExecutionError::InvalidProof { backend, reason })
            if backend == "tee:intel-dcap-quote-verifier" && reason.contains("quote digest mismatch")
    ));
}

#[test]
fn client_backed_amd_provider_maps_unavailable_response_to_backend_unavailable() {
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
        Arc::new(UnavailableAmdReportClientResponse),
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
        Err(BackendExecutionError::Unavailable { backend, reason })
            if backend == "tee:amd-sev-snp-report-verifier" && reason.contains("transport timeout")
    ));
}
