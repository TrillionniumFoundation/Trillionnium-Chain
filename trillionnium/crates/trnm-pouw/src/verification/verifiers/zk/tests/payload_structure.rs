use super::*;

#[test]
fn zk_verifier_valid_proof_path_with_mock_backend() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}

#[test]
fn zk_verifier_accepts_exact_configured_opaque_backend_when_payload_omits_backend_id() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}

#[test]
fn zk_verifier_rejects_missing_zk_system_before_backend_router_mismatch_checks() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16-demo",
        expected_system: "groth16",
    }));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:") && msg.contains("zk_system is required")
    ));
}

#[test]
fn zk_verifier_treats_json_shaped_payload_without_vk_ref_as_malformed_contract_error() {
    let verifier =
        ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","proof_encoding":"hex","proof":"01020304"}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:") && msg.contains("canonical JSON object")
    ));
}

#[test]
fn zk_verifier_treats_json_shaped_payload_without_public_inputs_as_malformed_contract_error() {
    let verifier =
        ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304"}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:") && msg.contains("canonical JSON object")
    ));
}
