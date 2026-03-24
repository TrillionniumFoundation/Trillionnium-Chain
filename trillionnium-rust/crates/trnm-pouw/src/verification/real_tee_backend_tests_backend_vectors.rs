use super::*;

#[test]
fn real_tee_backend_accepts_valid_sgx_vector() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";

    assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
}

#[test]
fn real_tee_backend_accepts_valid_tdx_vector() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-tdx-qgs-demo-v1,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel";

    assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
}

#[test]
fn real_tee_backend_accepts_valid_sev_snp_vector() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";

    assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
}

#[test]
fn real_tee_backend_rejects_unsupported_attestation_target_fail_closed() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=nitro-enclave,measurement=enclave:demo,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-demo";

    assert!(matches!(
        registry.verify(&task, receipt),
        VerificationResult::Invalid(msg)
            if msg.contains("unsupported attestation_target 'nitro-enclave'")
    ));
}

#[test]
fn real_tee_backend_rejects_missing_report_for_report_verifier_target_fail_closed() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";

    assert!(matches!(
        registry.verify(&task, receipt),
        VerificationResult::Invalid(msg)
            if msg.contains("requires report evidence")
    ));
}

#[test]
fn real_tee_backend_rejects_report_data_hash_mismatch_fail_closed() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=2222222222222222222222222222222222222222222222222222222222222222,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";

    assert!(matches!(
        registry.verify(&task, receipt),
        VerificationResult::Invalid(msg)
            if msg.contains("report_data_hash") && msg.contains("does not match task result hash")
    ));
}

#[test]
fn real_tee_backend_rejects_quote_metadata_mismatch_fail_closed() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-tdx-qgs-demo-v1,collateral=wrong-collateral,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel";

    assert!(matches!(
        registry.verify(&task, receipt),
        VerificationResult::Invalid(msg)
            if msg.contains("collateral") && msg.contains("tdx-qgs")
    ));
}

#[test]
fn real_tee_backend_rejects_report_signer_mismatch_fail_closed() {
    let registry = VerifierRegistry::with_backend_config(tee_config());
    let task = mock_task();
    let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=wrong-signer";

    assert!(matches!(
        registry.verify(&task, receipt),
        VerificationResult::Invalid(msg)
            if msg.contains("report_signer") && msg.contains("sev-snp")
    ));
}
