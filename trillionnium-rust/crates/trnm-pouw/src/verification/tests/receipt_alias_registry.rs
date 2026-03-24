use super::*;

#[test]
fn verification_receipt_new_collapses_zero_knowledge_aliases_to_zk_router_key() {
    let spaced = VerificationReceipt::new(
        1,
        "zero knowledge receipt",
        VerificationResult::Valid,
        "v",
        1,
    );
    let underscored =
        VerificationReceipt::new(2, "ZERO_KNOWLEDGE_PROOF", VerificationResult::Valid, "v", 2);
    let compact = VerificationReceipt::new(
        3,
        "ZeroKnowledgeAttestation",
        VerificationResult::Valid,
        "v",
        3,
    );
    let snark_spaced =
        VerificationReceipt::new(4, "zero knowledge snark", VerificationResult::Valid, "v", 4);
    let snark_compact =
        VerificationReceipt::new(5, "ZeroKnowledgeSnark", VerificationResult::Valid, "v", 5);
    let versioned = VerificationReceipt::new(
        6,
        "zero-knowledge-proof-v2",
        VerificationResult::Valid,
        "v",
        6,
    );
    let receipt_versioned = VerificationReceipt::new(
        7,
        "ZeroKnowledgeReceiptV3",
        VerificationResult::Valid,
        "v",
        7,
    );

    assert_eq!(spaced.proof_type, "zk");
    assert_eq!(underscored.proof_type, "zk");
    assert_eq!(compact.proof_type, "zk");
    assert_eq!(snark_spaced.proof_type, "zk");
    assert_eq!(snark_compact.proof_type, "zk");
    assert_eq!(versioned.proof_type, "zk");
    assert_eq!(receipt_versioned.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_registry_aliases_for_tee_report_and_zk_snark() {
    let tee_report =
        VerificationReceipt::new(1, "TEE_REPORT", VerificationResult::Valid, "v", 1);
    let zk_snark = VerificationReceipt::new(2, "zk-snark", VerificationResult::Valid, "v", 2);

    assert_eq!(tee_report.proof_type, "tee");
    assert_eq!(zk_snark.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_versioned_tee_quote_and_sgx_report_aliases() {
    let tee_quote_v2 =
        VerificationReceipt::new(1, "TEE_QUOTE_V2", VerificationResult::Valid, "v", 1);
    let sgx_report_v3 =
        VerificationReceipt::new(2, "sgx-report-v3", VerificationResult::Valid, "v", 2);
    let tee_quote_compact_v1 =
        VerificationReceipt::new(3, "teequotev1", VerificationResult::Valid, "v", 3);

    assert_eq!(tee_quote_v2.proof_type, "tee");
    assert_eq!(sgx_report_v3.proof_type, "tee");
    assert_eq!(tee_quote_compact_v1.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_registry_aliases_for_tee_sgx_and_zk_evidence() {
    let tee_sgx = VerificationReceipt::new(1, "SGX_QUOTE", VerificationResult::Valid, "v", 1);
    let tee_evidence =
        VerificationReceipt::new(2, "tee-evidence", VerificationResult::Valid, "v", 2);
    let zk_evidence = VerificationReceipt::new(
        3,
        "zero knowledge evidence",
        VerificationResult::Valid,
        "v",
        3,
    );

    assert_eq!(tee_sgx.proof_type, "tee");
    assert_eq!(tee_evidence.proof_type, "tee");
    assert_eq!(zk_evidence.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_registry_aliases_for_sgx_tdx_and_short_cert_labels() {
    let tee_sgx_report =
        VerificationReceipt::new(1, "SGX_REPORT", VerificationResult::Valid, "v", 1);
    let tee_tdx_report =
        VerificationReceipt::new(2, "tdx-report", VerificationResult::Valid, "v", 2);
    let tee_short_cert =
        VerificationReceipt::new(3, "tee cert", VerificationResult::Valid, "v", 3);
    let zk_short_cert =
        VerificationReceipt::new(4, "zk cert", VerificationResult::Valid, "v", 4);

    assert_eq!(tee_sgx_report.proof_type, "tee");
    assert_eq!(tee_tdx_report.proof_type, "tee");
    assert_eq!(tee_short_cert.proof_type, "tee");
    assert_eq!(zk_short_cert.proof_type, "zk");
}

#[test]
fn verification_receipt_new_collapses_registry_aliases_for_td_snp_and_enclave_quotes() {
    let tee_enclave_quote =
        VerificationReceipt::new(1, "enclave quote", VerificationResult::Valid, "v", 1);
    let tee_td_report =
        VerificationReceipt::new(2, "td_report", VerificationResult::Valid, "v", 2);
    let tee_snp_report =
        VerificationReceipt::new(3, "AMD-SEV-SNP report", VerificationResult::Valid, "v", 3);

    assert_eq!(tee_enclave_quote.proof_type, "tee");
    assert_eq!(tee_td_report.proof_type, "tee");
    assert_eq!(tee_snp_report.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_snp_quote_aliases_to_tee_router_key() {
    let snp_quote = VerificationReceipt::new(1, "SNP_QUOTE", VerificationResult::Valid, "v", 1);
    let sev_snp_quote =
        VerificationReceipt::new(2, "SEV-SNP quote", VerificationResult::Valid, "v", 2);
    let amd_sev_snp_quote =
        VerificationReceipt::new(3, "AMD SEV SNP QUOTE", VerificationResult::Valid, "v", 3);

    assert_eq!(snp_quote.proof_type, "tee");
    assert_eq!(sev_snp_quote.proof_type, "tee");
    assert_eq!(amd_sev_snp_quote.proof_type, "tee");
}

#[test]
fn verification_receipt_new_collapses_remote_attestation_and_zero_knowledge_aliases() {
    let tee_remote =
        VerificationReceipt::new(1, "remote attestation", VerificationResult::Valid, "v", 1);
    let tee_attestation_report = VerificationReceipt::new(
        2,
        "TEE attestation report",
        VerificationResult::Valid,
        "v",
        2,
    );
    let tee_attestation_report_v2 = VerificationReceipt::new(
        3,
        "TEE attestation report v2",
        VerificationResult::Valid,
        "v",
        3,
    );
    let tee_attestation_v2 =
        VerificationReceipt::new(4, "TEE_ATTESTATION_V2", VerificationResult::Valid, "v", 4);
    let zk_bare =
        VerificationReceipt::new(5, "zero knowledge", VerificationResult::Valid, "v", 5);

    assert_eq!(tee_remote.proof_type, "tee");
    assert_eq!(tee_attestation_report.proof_type, "tee");
    assert_eq!(tee_attestation_report_v2.proof_type, "tee");
    assert_eq!(tee_attestation_v2.proof_type, "tee");
    assert_eq!(zk_bare.proof_type, "zk");
}

#[test]
fn verification_receipt_new_supports_registry_parity_aliases_and_fullwidth_delimiters() {
    let tee_fullwidth =
        VerificationReceipt::new(1, "RA：QUOTE", VerificationResult::Valid, "v", 1);
    let tee_certificate =
        VerificationReceipt::new(2, "tee-certificate", VerificationResult::Valid, "v", 2);
    let zk_short = VerificationReceipt::new(3, "zkp", VerificationResult::Valid, "v", 3);
    let zk_certificate = VerificationReceipt::new(
        4,
        "zero knowledge certificate",
        VerificationResult::Valid,
        "v",
        4,
    );
    let tee_intel_sgx_dcap =
        VerificationReceipt::new(5, "Intel SGX DCAP Quote", VerificationResult::Valid, "v", 5);
    let tee_intel_sgx_dcap_marked = VerificationReceipt::new(
        6,
        "Intel® SGX™ DCAP Quote",
        VerificationResult::Valid,
        "v",
        6,
    );
    let tee_sgx_dcap =
        VerificationReceipt::new(7, "SGX DCAP Quote", VerificationResult::Valid, "v", 7);

    assert_eq!(tee_fullwidth.proof_type, "tee");
    assert_eq!(tee_certificate.proof_type, "tee");
    assert_eq!(zk_short.proof_type, "zk");
    assert_eq!(zk_certificate.proof_type, "zk");
    assert_eq!(tee_intel_sgx_dcap.proof_type, "tee");
    assert_eq!(tee_intel_sgx_dcap_marked.proof_type, "tee");
    assert_eq!(tee_sgx_dcap.proof_type, "tee");
}
