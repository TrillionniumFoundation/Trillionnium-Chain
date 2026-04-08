use super::*;

#[test]
fn zk_verifier_invalid_proof_path_with_mock_backend() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockInvalidBackend));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-invalid","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg) if msg.contains("mock zk backend rejected proof")
    ));
}

#[test]
fn zk_verifier_unavailable_backend_maps_to_indeterminate() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockUnavailableBackend));
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("mock-zk-unavailable".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("unavailable:") && msg.contains("mock zk backend unavailable")
    ));
}

#[test]
fn zk_verifier_does_not_silently_fallback_when_payload_backend_is_unknown() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("verification backend 'missing-backend' is not registered")
    ));
}

#[test]
fn zk_verifier_unknown_payload_backend_does_not_fallback_to_configured_default_backend() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    config.zk_features.zk_allow_backend_fallback = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("verification backend 'missing-backend' is not registered")
                && !msg.contains("mock-zk")
    ));
}

#[test]
fn zk_verifier_allow_backend_fallback_flag_does_not_override_explicit_payload_backend() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    config.zk_features.zk_allow_backend_fallback = true;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Indeterminate(msg)
            if msg.contains("verification backend 'missing-backend' is not registered")
                && !msg.contains("mock-zk")
    ));
}
