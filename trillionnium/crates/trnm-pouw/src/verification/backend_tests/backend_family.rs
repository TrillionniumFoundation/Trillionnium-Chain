use super::*;

#[test]
fn backend_config_routes_backend_capable_families() {
    let config = VerificationBackendConfig {
        tee_backend: VerificationBackendKind::Custom("mock-tee".into()),
        zk_backend: VerificationBackendKind::Custom("mock-zk".into()),
        zk_features: Default::default(),
    };

    assert_eq!(
        config.kind_for_family(VerificationBackendFamily::Tee),
        &VerificationBackendKind::Custom("mock-tee".into())
    );
    assert_eq!(
        config.kind_for_family(VerificationBackendFamily::Zk),
        &VerificationBackendKind::Custom("mock-zk".into())
    );
    assert_eq!(config.kind_for_proof_type(ProofType::Fraud), None);
}

#[test]
fn noop_backend_uses_family_scoped_not_configured_error() {
    let err = NoopVerificationBackend
        .verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &mock_task(),
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        })
        .unwrap_err();

    assert_eq!(
        err,
        BackendExecutionError::NotConfigured {
            backend: "tee:noop".into()
        }
    );
}
