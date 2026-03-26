use super::*;

#[test]
fn parse_tee_attestation_payload_accepts_quote_verifier_target_matrix() {
    let payload = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap();

    assert_eq!(payload.attestation_target, "sgx-dcap");
    assert_eq!(payload.verifier_kind, "quote-verifier");
    assert_eq!(payload.measurement_field, "mrenclave");
    assert_eq!(payload.evidence_kind, TeeEvidenceKind::Quote);
    assert_eq!(payload.evidence(), Some("quote-sgx-dcap-demo-v1"));
    assert_eq!(
        payload.verifier_metadata.collateral.as_deref(),
        Some("intel-dcap-collateral-demo-v1")
    );
    assert_eq!(
        payload.verifier_metadata.cert_chain.as_deref(),
        Some("intel-dcap-cert-chain-demo-v1")
    );
    assert_eq!(payload.verifier_metadata.issuer.as_deref(), Some("intel"));
}

#[test]
fn parse_tee_attestation_payload_accepts_report_verifier_target_matrix() {
    let payload = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=abababababababababababababababababababababababababababababababab,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd"
        )
        .unwrap();

    assert_eq!(payload.attestation_target, "sev-snp");
    assert_eq!(payload.verifier_kind, "report-verifier");
    assert_eq!(payload.measurement_field, "measurement");
    assert_eq!(payload.evidence_kind, TeeEvidenceKind::Report);
    assert_eq!(payload.evidence(), Some("report-sev-snp-demo-v1"));
    assert_eq!(
        payload.verifier_metadata.vcek.as_deref(),
        Some("amd-vcek-demo-v1")
    );
    assert_eq!(
        payload.verifier_metadata.cert_chain.as_deref(),
        Some("amd-cert-chain-demo-v1")
    );
    assert_eq!(
        payload.verifier_metadata.report_signer.as_deref(),
        Some("amd")
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_quote_target_without_quote_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires quote evidence"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_quote_target_without_collateral_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires collateral metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_quote_target_with_blank_collateral_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=   ,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires collateral metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_quote_target_with_blank_cert_chain_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=   ,issuer=intel"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires cert_chain metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_quote_target_with_blank_issuer_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=   "
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires issuer metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_report_target_with_quote_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=abababababababababababababababababababababababababababababababab,report=report-sev-snp-demo-v1,collateral=wrong-shape,cert_chain=amd-cert-chain-demo-v1,issuer=intel,vcek=amd-vcek-demo-v1,report_signer=amd"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("does not accept quote verifier metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_report_target_with_blank_vcek_metadata_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=abababababababababababababababababababababababababababababababab,report=report-sev-snp-demo-v1,vcek=   ,cert_chain=amd-cert-chain-demo-v1,report_signer=amd"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires vcek metadata"))
    );
}

#[test]
fn parse_tee_attestation_payload_rejects_measurement_prefix_mismatch_fail_closed() {
    let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=tdx-qgs,measurement=mrenclave:wrong-slot,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-tdx-qgs-demo-v1,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

    assert!(
        matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires measurement prefix 'mrtd:'"))
    );
}
