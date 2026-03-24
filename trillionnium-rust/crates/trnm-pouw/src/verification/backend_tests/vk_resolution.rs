use super::*;

#[test]
fn resolve_zk_vk_ref_rejects_unknown_vk_ref_fail_closed() {
    let task = mock_task();
    let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/unknown","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
    let resolver = VkRefRegistry::new();

    let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

    assert_eq!(
        err,
        BackendExecutionError::InvalidProof {
            backend: "zk:payload".into(),
            reason: "invalid zk payload: unknown vk_ref 'vk://trnm/dev/mock-groth16/unknown'"
                .into(),
        }
    );
}

#[test]
fn resolve_zk_vk_ref_rejects_case_drift_for_opaque_vk_refs() {
    let task = mock_task();
    let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"VK://TRNM/DEV/MOCK-GROTH16/V1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
    let resolver = VkRefRegistry::new();

    let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

    assert_eq!(
        err,
        BackendExecutionError::InvalidProof {
            backend: "zk:payload".into(),
            reason: "invalid zk payload: unknown vk_ref 'VK://TRNM/DEV/MOCK-GROTH16/V1'".into(),
        }
    );
}

#[test]
fn vk_ref_registry_rejects_surrounding_whitespace_without_silent_trim() {
    let resolver = VkRefRegistry::new();

    let err = resolver
        .resolve("  vk://trnm/dev/mock-groth16/v1  ")
        .unwrap_err();

    assert_eq!(
        err,
        VkRefResolutionError::Unknown {
            vk_ref: "  vk://trnm/dev/mock-groth16/v1  ".into(),
        }
    );
}

#[test]
fn vk_ref_registry_rejects_surrounding_unicode_whitespace_without_silent_trim() {
    let resolver = VkRefRegistry::new();

    let err = resolver
        .resolve("\u{2003}vk://trnm/dev/mock-groth16/v1\u{2003}")
        .unwrap_err();

    assert_eq!(
        err,
        VkRefResolutionError::Unknown {
            vk_ref: "\u{2003}vk://trnm/dev/mock-groth16/v1\u{2003}".into(),
        }
    );
}

#[test]
fn vk_ref_registry_rejects_embedded_control_whitespace_without_silent_normalization() {
    let resolver = VkRefRegistry::new();

    let err = resolver
        .resolve("vk://trnm/dev/mock-groth16/line\nbreak")
        .unwrap_err();

    assert_eq!(
        err,
        VkRefResolutionError::Unknown {
            vk_ref: "vk://trnm/dev/mock-groth16/line\nbreak".into(),
        }
    );
}

#[test]
fn vk_ref_registry_rejects_embedded_unicode_whitespace_without_silent_normalization() {
    let resolver = VkRefRegistry::new();

    let err = resolver
        .resolve("vk://trnm/dev/mock-groth16/line\u{2003}break")
        .unwrap_err();

    assert_eq!(
        err,
        VkRefResolutionError::Unknown {
            vk_ref: "vk://trnm/dev/mock-groth16/line\u{2003}break".into(),
        }
    );
}

#[test]
fn vk_ref_registry_rejects_embedded_zero_width_format_char_without_silent_normalization() {
    let resolver = VkRefRegistry::new();

    let err = resolver
        .resolve("vk://trnm/dev/mock-groth16/line\u{200b}break")
        .unwrap_err();

    assert_eq!(
        err,
        VkRefResolutionError::Unknown {
            vk_ref: "vk://trnm/dev/mock-groth16/line\u{200b}break".into(),
        }
    );
}

#[test]
fn resolve_zk_vk_ref_rejects_payload_zk_system_mismatch_against_registered_vk_metadata() {
    let task = mock_task();
    let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
    let resolver = VkRefRegistry::new();

    let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

    assert_eq!(
            err,
            BackendExecutionError::InvalidProof {
                backend: "zk:payload".into(),
                reason: "invalid zk payload: zk_system 'groth16' does not match vk_ref 'vk://trnm/dev/mock-plonk/v1'".into(),
            }
        );
}

#[test]
fn resolve_zk_vk_ref_returns_registered_system_metadata() {
    let resolver = VkRefRegistry::new();

    for (zk_system, backend_id, vk_ref) in [
        ("plonk", "plonk-demo", "vk://trnm/dev/mock-plonk/v1"),
        ("halo2", "halo2-demo", "vk://trnm/dev/mock-halo2/v1"),
        ("stark", "stark-demo", "vk://trnm/dev/mock-stark/v1"),
        ("risc0", "risc0-demo", "vk://trnm/dev/mock-risc0/v1"),
        ("sp1", "sp1-demo", "vk://trnm/dev/mock-sp1/v1"),
    ] {
        let task = mock_task();
        let payload = parse_zk_proof_payload(
                &task,
                format!(
                    "ZK:{{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"{zk_system}\",\"backend_id\":\"{backend_id}\",\"backend_version\":\"v1\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"{vk_ref}\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}}}"
                )
                .as_bytes(),
            )
            .unwrap();

        let resolved = resolve_zk_vk_ref(&resolver, &payload).unwrap();

        assert_eq!(resolved.vk_ref, vk_ref);
        assert_eq!(resolved.scope, "dev");
        assert_eq!(resolved.zk_system.as_deref(), Some(zk_system));
    }
}

#[test]
fn resolve_zk_vk_ref_accepts_registered_reference_with_custom_metadata() {
    let mut resolver = VkRefRegistry::new();
    resolver.register(ResolvedVkRef {
        vk_ref: "vk://trnm/dev/mock-groth16/mixedcase".into(),
        scope: "dev".into(),
        zk_system: Some("groth16".into()),
    });

    let payload = ParsedZkProofPayload {
        task_id: 4242,
        worker: "worker-zk".into(),
        proof_type: "zk".into(),
        result_hash: "1111111111111111111111111111111111111111111111111111111111111111".into(),
        zk_system: Some("groth16".into()),
        backend_id: Some("mock-zk".into()),
        backend_version: Some("v1".into()),
        schema_version: "trnm.zk.payload.v0".into(),
        vk_ref: "vk://trnm/dev/mock-groth16/mixedcase".into(),
        proof_encoding: Some(ProofBytesEncoding::Hex),
        proof: "01020304".into(),
        public_inputs: ZkPublicInputs {
            order: vec![
                "task_id".into(),
                "proof_type".into(),
                "worker".into(),
                "result_hash".into(),
            ],
            values: vec![
                "4242".into(),
                "zk".into(),
                "worker-zk".into(),
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            ],
        },
        meta: ZkPayloadMeta {
            circuit_id: Some("settlement-result-v1".into()),
        },
    };

    let resolved = resolve_zk_vk_ref(&resolver, &payload).unwrap();

    assert_eq!(resolved.vk_ref, "vk://trnm/dev/mock-groth16/mixedcase");
    assert_eq!(resolved.scope, "dev");
    assert_eq!(resolved.zk_system.as_deref(), Some("groth16"));
}
