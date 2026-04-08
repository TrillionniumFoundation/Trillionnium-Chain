use super::*;

#[test]
fn real_tee_backend_delegates_intel_quote_bundle_to_executor() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let backend = RealTeeBackend::with_executor(Arc::new(AssertingIntelQuoteExecutor));

    let result = backend.verify(BackendVerificationRequest {
        family: VerificationBackendFamily::Tee,
        task: &task,
        proof_data,
        tee_payload: Some(&payload),
        zk_payload: None,
        resolved_vk_ref: None,
    });

    assert!(matches!(
        result,
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-executor"
    ));
}

#[test]
fn real_tee_backend_delegates_amd_report_bundle_to_executor() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let backend = RealTeeBackend::with_executor(Arc::new(AssertingAmdReportExecutor));

    let result = backend.verify(BackendVerificationRequest {
        family: VerificationBackendFamily::Tee,
        task: &task,
        proof_data,
        tee_payload: Some(&payload),
        zk_payload: None,
        resolved_vk_ref: None,
    });

    assert!(matches!(
        result,
        Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-executor"
    ));
}
