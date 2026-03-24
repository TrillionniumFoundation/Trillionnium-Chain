use super::*;

#[test]
fn zk_verifier_requires_explicit_backend_when_feature_enabled() {
    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg) if msg.contains("backend_version requires backend_id")
    ));
}

#[test]
fn zk_verifier_requires_non_noise_backend_when_feature_enabled() {
    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"---","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend_id '---'")
                && msg.contains("visible canonical backend token segment")
    ));
}

#[test]
fn zk_verifier_treats_noop_backend_id_with_backend_version_as_malformed_when_explicit_backend_is_required(
) {
    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg) if msg.contains("backend_version must not be provided for legacy noop backend_id")
    ));
}

#[test]
fn zk_verifier_treats_noop_backend_id_as_explicit_unavailable_selector_when_explicit_backend_is_required(
) {
    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("unavailable:")
                && msg.contains("cryptographic verification backend not configured")
    ));
}

#[test]
fn zk_verifier_rejects_non_canonical_noop_backend_id_case() {
    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"NOOP","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("canonical lowercase token 'noop'")
    ));
}

#[test]
fn zk_verifier_explicit_noop_payload_backend_remains_authoritative_without_falling_back_to_configured_backend(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16-demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("groth16-demo".into());
    config.zk_features.zk_allow_backend_fallback = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("unavailable:")
                && msg.contains("cryptographic verification backend not configured")
                && !msg.contains("groth16-demo")
    ));
}

#[test]
fn zk_verifier_treats_noop_backend_id_with_backend_version_as_malformed_for_backend_selection()
{
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg) if msg.contains("backend_version must not be provided for legacy noop backend_id")
    ));
}

#[test]
fn zk_verifier_requires_canonical_backend_system_hint_when_explicit_backend_enabled() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend_id 'mock-zk'")
                && msg.contains("canonical zk_system hint")
    ));
}

#[test]
fn zk_verifier_rejects_family_only_backend_id_when_explicit_backend_enabled() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend_id 'zk-demo'")
                && msg.contains("canonical zk_system hint")
    ));
}

#[test]
fn zk_verifier_accepts_repeated_same_system_hints_with_explicit_backend_enabled() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_features.zk_explicit_backend_required = true;
    config.zk_backend = ZkBackendKind::Custom("missing-backend".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK-GROTH16-GROTH16-DEMO","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}
