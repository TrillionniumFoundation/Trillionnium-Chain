use super::*;

fn mock_task() -> TaskObject {
    TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: Some([0x11; 32]),
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    }
}

fn tee_config() -> VerificationBackendConfig {
    VerificationBackendConfig {
        tee_backend: VerificationBackendKind::Custom("real-tee-backend".into()),
        ..VerificationBackendConfig::default()
    }
}

fn sgx_handoff() -> TeeVerifierHandoff {
    let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
    TeeVerifierHandoff::from_payload(&payload, None).unwrap()
}

fn snp_handoff() -> TeeVerifierHandoff {
    let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd").unwrap();
    TeeVerifierHandoff::from_payload(&payload, None).unwrap()
}

fn temp_profile_registry_path(label: &str) -> String {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "trnm-tee-profile-registry-{}-{}-{}.json",
            label,
            std::process::id(),
            unique
        ))
        .display()
        .to_string()
}

#[path = "real_tee_backend_tests_profiles.rs"]
mod tests_profiles;

#[path = "real_tee_backend_tests_exchange_termination.rs"]
mod tests_exchange_termination;

#[path = "real_tee_backend_tests_exchange_transport.rs"]
mod tests_exchange_transport;

#[path = "real_tee_backend_tests_http_clients.rs"]
mod tests_http_clients;

#[path = "real_tee_backend_tests_backend_vectors.rs"]
mod tests_backend_vectors;
