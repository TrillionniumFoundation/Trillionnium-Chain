use super::*;

#[test]
fn zk_verifier_accepts_second_system_mock_plonk_backend() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "plonk-demo",
        expected_system: "plonk",
    }));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}

#[test]
fn zk_verifier_rejects_second_system_vk_ref_mismatch_fail_closed() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "plonk-demo",
        expected_system: "plonk",
    }));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("zk_system 'plonk'") && msg.contains("does not match vk_ref")
    ));
}

#[test]
fn zk_verifier_rejects_backend_router_system_mismatch_with_vk_ref_fail_closed() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16-demo",
        expected_system: "groth16",
    }));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("zk_system 'groth16'") && msg.contains("does not match vk_ref")
    ));
}

#[test]
fn zk_verifier_rejects_vk_ref_without_canonical_system_metadata_when_payload_declares_system() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSuccessBackend));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-no-system/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("missing canonical zk_system metadata")
                && msg.contains("vk://trnm/dev/mock-no-system/v1")
    ));
}

#[test]
fn zk_verifier_rejects_backend_system_hint_when_vk_ref_lacks_canonical_system_metadata() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16-demo",
        expected_system: "groth16",
    }));
    let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-no-system/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("missing canonical zk_system metadata")
                && msg.contains("vk://trnm/dev/mock-no-system/v1")
    ));
}

#[test]
fn zk_verifier_rejects_vk_ref_metadata_with_non_canonical_system_token_drift() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16-demo",
        expected_system: "groth16",
    }));
    let mut verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));

    let mut vk_refs = crate::verification::backend::VkRefRegistry::default();
    vk_refs.register(crate::verification::backend::ResolvedVkRef {
        vk_ref: "vk://trnm/dev/mock-groth16/noncanonical".into(),
        scope: "dev".into(),
        zk_system: Some(" Groth-16 ".into()),
    });
    verifier.vk_refs = Arc::new(vk_refs);

    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/noncanonical","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("must use canonical zk_system metadata 'groth16'")
                && msg.contains("vk://trnm/dev/mock-groth16/noncanonical")
    ));
}
