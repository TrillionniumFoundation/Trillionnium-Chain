use super::*;

#[test]
fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk-groth16-groth16-demo".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_selected_backend_with_case_drifted_explicit_zk_family_prefix_and_repeated_same_system_hint(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "zk groth16 groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("ZK-GROTH16-GROTH16-DEMO".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert_eq!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint_even_without_json_payload(
) {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockLegacySuccessBackend {
        backend_id: "zk groth16 groth16 demo",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("zk-groth16-groth16-demo".into());
    config.zk_features.zk_payload_v0_envelope = false;
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

    assert_eq!(
        verifier.verify_proof(&task, legacy_payload),
        VerificationResult::Valid
    );
}


#[test]
fn zk_verifier_rejects_selected_backend_with_surrounding_whitespace_without_silent_trim() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("  groth16-demo  ".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend '  groth16-demo  '")
                && msg.contains("surrounding whitespace")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_that_is_empty_after_config_selection() {
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom(String::new());
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend must not be empty")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_non_canonical_noop_case() {
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("NOOP".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("canonical lowercase token 'noop'")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_noise_only_token() {
    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("---".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend '---'")
                && msg.contains("canonical token segment")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_embedded_control_whitespace() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("groth16-demo\nalt".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("backend 'groth16-demo")
                && msg.contains("single opaque token")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_surrounding_unicode_whitespace() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("\u{2003}groth16-demo\u{2003}".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("groth16-demo")
                && msg.contains("surrounding whitespace")
    ));
}


#[test]
fn zk_verifier_rejects_selected_backend_with_embedded_unicode_whitespace() {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(MockSystemSuccessBackend {
        backend_id: "groth16 demo",
        expected_system: "groth16",
    }));

    let mut config = router_config();
    config.zk_backend = ZkBackendKind::Custom("groth16-demo\u{2003}alt".into());
    let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
    let task = mock_task();
    let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    assert!(matches!(
        verifier.verify_proof(&task, payload),
        VerificationResult::Invalid(msg)
            if msg.contains("malformed:")
                && msg.contains("single opaque token")
                && msg.contains("embedded whitespace or control characters")
    ));
}
