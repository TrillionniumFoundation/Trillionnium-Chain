use super::*;

#[test]
fn zk_verifier_rejects_payload_backend_that_is_exact_tee_family_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "tee",
        expected_system: "groth16",
    }));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"tee","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend_id 'tee'")
                && msg.contains("declares tee family")
                && msg.contains("does not match zk vk_ref")
    ));
}


#[test]
fn zk_verifier_rejects_payload_backend_that_is_family_only_zk_router_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend_id 'zk-demo'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_payload_backend_that_is_exact_family_only_zk_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend_id 'zk'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_payload_backend_that_is_case_drifted_exact_family_only_zk_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend_id 'ZK'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_explicit_tee_family_prefix() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "tee-groth16-demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("tee-groth16-demo".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend 'tee-groth16-demo'")
                && msg.contains("declares tee family")
                && msg.contains("zk router semantics")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_exact_tee_family_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "tee",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("tee".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend 'tee'")
                && msg.contains("declares tee family")
                && msg.contains("zk router semantics")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_case_drifted_exact_tee_family_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "tee",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("TEE".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend 'TEE'")
                && msg.contains("declares tee family")
                && msg.contains("zk router semantics")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_family_only_zk_router_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'zk-demo'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_exact_family_only_zk_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'zk'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_case_drifted_exact_family_only_zk_token() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("ZK".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'ZK'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_selected_tee_family_backend_even_without_json_payload() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "tee-groth16-demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("tee-groth16-demo".into());
    config.zk_features.zk_payload_v0_envelope = false;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

    assert!(matches!(
        verifier.verify_proof(&task, legacy_payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend 'tee-groth16-demo'")
                && msg.contains("declares tee family")
                && msg.contains("zk router semantics")
    ));
}
