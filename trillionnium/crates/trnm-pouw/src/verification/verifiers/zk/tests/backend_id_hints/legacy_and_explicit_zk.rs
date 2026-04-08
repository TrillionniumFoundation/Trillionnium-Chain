use super::*;

#[test]
fn zk_verifier_rejects_family_only_selected_backend_even_without_json_payload() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
    config.zk_features.zk_payload_v0_envelope = false;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

    assert!(matches!(
        verifier.verify_proof(&task, legacy_payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'zk-demo'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_case_drifted_family_only_selected_backend_even_without_json_payload() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("ZK-DEMO".into());
    config.zk_features.zk_payload_v0_envelope = false;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

    assert!(matches!(
        verifier.verify_proof(&task, legacy_payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'ZK-DEMO'")
                && msg.contains("family-only zk router token")
    ));
}


#[test]
fn zk_verifier_rejects_multi_hint_selected_backend_even_without_json_payload() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16 plonk demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("groth16-plonk-demo".into());
    config.zk_features.zk_payload_v0_envelope = false;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

    assert!(matches!(
        verifier.verify_proof(&task, legacy_payload),
        VerificationResult::Invalid(msg)
            if msg.contains("backend 'groth16-plonk-demo'")
                && msg.contains("multiple zk_system hints")
                && msg.contains("fail-closed zk router semantics")
    ));
}


#[test]
fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk-groth16-demo".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 demo",
        expected_system: "groth16",
    }));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix_and_only_system_hint() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16",
        expected_system: "groth16",
    }));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_explicit_opaque_payload_backend_without_family_or_system_hint() {
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
fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 groth16 demo",
        expected_system: "groth16",
    }));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_payload_backend_with_case_drifted_explicit_zk_family_prefix_and_repeated_same_system_hint(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 groth16 demo",
        expected_system: "groth16",
    }));

    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK-GROTH16-GROTH16-DEMO","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}
