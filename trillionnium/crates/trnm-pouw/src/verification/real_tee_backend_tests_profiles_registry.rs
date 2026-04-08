use super::*;

#[test]
fn sgx_adapter_builds_quote_verifier_input() {
    let input = SGX_DCAP_ADAPTER
        .build_verifier_input(&sgx_handoff(), None)
        .unwrap();
    assert!(matches!(
        input,
        TeeVerifierInput::Quote(QuoteVerifierInput {
            attestation_target,
            verifier_kind,
            measurement_field,
            quote,
            intel_collateral,
            ..
        }) if attestation_target == "sgx-dcap"
            && verifier_kind == "quote-verifier"
            && measurement_field == "mrenclave"
            && quote == "quote-sgx-dcap-demo-v1"
            && intel_collateral.collateral == "intel-dcap-collateral-demo-v1"
            && intel_collateral.cert_chain == "intel-dcap-cert-chain-demo-v1"
            && intel_collateral.issuer == "intel"
    ));
}

#[test]
fn snp_adapter_builds_report_verifier_input() {
    let input = SEV_SNP_ADAPTER
        .build_verifier_input(&snp_handoff(), None)
        .unwrap();
    assert!(matches!(
        input,
        TeeVerifierInput::Report(ReportVerifierInput {
            attestation_target,
            verifier_kind,
            measurement_field,
            report,
            amd_signer,
            ..
        }) if attestation_target == "sev-snp"
            && verifier_kind == "report-verifier"
            && measurement_field == "measurement"
            && report == "report-sev-snp-demo-v1"
            && amd_signer.vcek == "amd-vcek-demo-v1"
            && amd_signer.cert_chain == "amd-cert-chain-demo-v1"
            && amd_signer.report_signer == "amd"
    ));
}

#[test]
fn env_transport_config_source_overrides_mock_defaults() {
    let mut vars = BTreeMap::new();
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_MODE".to_string(),
        "external".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_ENDPOINT_BASE".to_string(),
        "https://override.intel.example/v2/quote".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_TIMEOUT_MS".to_string(),
        "7000".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_PROFILE".to_string(),
        "intel-dcap-override-profile".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_AUTH_REF_PREFIX".to_string(),
        "tee.intel.override-token".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_RETRY_MAX_ATTEMPTS".to_string(),
        "4".to_string(),
    );
    vars.insert(
        "TRNM_TEE_INTEL_QUOTE_RETRY_BACKOFF_MS".to_string(),
        "900".to_string(),
    );
    let source = EnvVerifierTransportConfigSource::from_vars(
        StaticVerifierTransportConfigSource::mock_defaults(),
        vars,
    );
    let intel = source.intel_quote_transport_config("sgx-dcap");
    assert_eq!(intel.mode, VerifierTransportMode::External);
    assert_eq!(
        intel.endpoint,
        "https://override.intel.example/v2/quote/sgx-dcap"
    );
    assert_eq!(intel.timeout_ms, 7_000);
    assert_eq!(intel.profile, "intel-dcap-override-profile");
    assert_eq!(
        intel.auth_ref.as_deref(),
        Some("tee.intel.override-token.sgx-dcap")
    );
    assert_eq!(intel.retry_policy.max_attempts, 4);
    assert_eq!(intel.retry_policy.backoff_ms, 900);
    assert_eq!(intel.retry_policy.strategy, RetryBackoffStrategy::Fixed);
}

#[test]
fn static_transport_config_source_renders_external_profiles() {
    let source = StaticVerifierTransportConfigSource::external_defaults();
    let intel = source.intel_quote_transport_config("sgx-dcap");
    assert_eq!(intel.mode, VerifierTransportMode::External);
    assert_eq!(
        intel.endpoint,
        "https://intel-verifier.invalid/v1/quote/sgx-dcap"
    );
    assert_eq!(intel.timeout_ms, 5_000);
    assert_eq!(intel.profile, "intel-dcap-external-default");
    assert_eq!(intel.auth_scheme.as_deref(), Some("bearer"));
    assert_eq!(
        intel.auth_ref.as_deref(),
        Some("tee.intel.external-token.sgx-dcap")
    );
    assert_eq!(intel.retry_policy.max_attempts, 3);
    assert_eq!(intel.retry_policy.backoff_ms, 250);
    assert_eq!(
        intel.retry_policy.strategy,
        RetryBackoffStrategy::Exponential
    );

    let amd = source.amd_report_transport_config("sev-snp");
    assert_eq!(amd.mode, VerifierTransportMode::External);
    assert_eq!(
        amd.endpoint,
        "https://amd-verifier.invalid/v1/report/sev-snp"
    );
    assert_eq!(amd.timeout_ms, 5_000);
    assert_eq!(amd.profile, "amd-sev-snp-external-default");
    assert_eq!(amd.auth_scheme.as_deref(), Some("bearer"));
    assert_eq!(
        amd.auth_ref.as_deref(),
        Some("tee.amd.external-token.sev-snp")
    );
    assert_eq!(amd.retry_policy.max_attempts, 3);
    assert_eq!(amd.retry_policy.backoff_ms, 250);
    assert_eq!(amd.retry_policy.strategy, RetryBackoffStrategy::Exponential);
}

#[test]
fn env_json_profile_registry_source_overrides_builtin_entry() {
    let mut vars = BTreeMap::new();
    vars.insert(
        "TRNM_TEE_PROFILE_REGISTRY_JSON".to_string(),
        serde_json::to_string(&vec![VerifierProfileRegistryEntry {
            profile: "intel-dcap-external-default".into(),
            mode: VerifierTransportMode::External,
            endpoint_prefix: "https://override.intel.example/v9/quote/".into(),
            auth_required: true,
        }])
        .unwrap(),
    );
    let source = EnvJsonVerifierProfileRegistrySource::from_vars(
        RuntimeVerifierProfileRegistry::with_builtin_defaults(),
        vars,
    );
    let task = mock_task();
    let registry = source
        .load(&BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        })
        .unwrap();
    let entry = registry.resolve("intel-dcap-external-default").unwrap();
    assert_eq!(
        entry.endpoint_prefix,
        "https://override.intel.example/v9/quote/"
    );
    assert!(entry.auth_required);
}

#[test]
fn registry_backed_profile_resolver_rejects_unknown_profile_fail_closed() {
    let task = mock_task();
    let request = BackendVerificationRequest {
        family: VerificationBackendFamily::Tee,
        task: &task,
        proof_data: b"TEE:...",
        tee_payload: None,
        zk_payload: None,
        resolved_vk_ref: None,
    };
    let mut transport = StaticVerifierTransportConfigSource::external_defaults()
        .intel_quote_transport_config("sgx-dcap");
    transport.profile = "unknown-profile".into();
    let resolver = RegistryBackedVerifierProfileResolver::with_builtin_defaults();
    let err = resolver.resolve(&transport, &request).unwrap_err();
    assert!(matches!(err, BackendExecutionError::NotConfigured { .. }));
}

#[test]
fn file_json_profile_registry_source_overrides_builtin_entry() {
    let path = temp_profile_registry_path("file-only");
    std::fs::write(
        &path,
        serde_json::to_string(&vec![VerifierProfileRegistryEntry {
            profile: "intel-dcap-external-default".into(),
            mode: VerifierTransportMode::External,
            endpoint_prefix: "https://file.intel.example/v4/quote/".into(),
            auth_required: true,
        }])
        .unwrap(),
    )
    .unwrap();
    let source = FileJsonVerifierProfileRegistrySource::from_path(
        RuntimeVerifierProfileRegistry::with_builtin_defaults(),
        path.clone(),
    );
    let task = mock_task();
    let registry = source
        .load(&BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        })
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let entry = registry.resolve("intel-dcap-external-default").unwrap();
    assert_eq!(
        entry.endpoint_prefix,
        "https://file.intel.example/v4/quote/"
    );
}

#[test]
fn env_json_profile_registry_source_applies_file_overlay_before_json_overlay() {
    let path = temp_profile_registry_path("file-then-json");
    std::fs::write(
        &path,
        serde_json::to_string(&vec![VerifierProfileRegistryEntry {
            profile: "intel-dcap-external-default".into(),
            mode: VerifierTransportMode::External,
            endpoint_prefix: "https://file.intel.example/v4/quote/".into(),
            auth_required: true,
        }])
        .unwrap(),
    )
    .unwrap();
    let mut vars = BTreeMap::new();
    vars.insert("TRNM_TEE_PROFILE_REGISTRY_PATH".to_string(), path.clone());
    vars.insert(
        "TRNM_TEE_PROFILE_REGISTRY_JSON".to_string(),
        serde_json::to_string(&vec![VerifierProfileRegistryEntry {
            profile: "intel-dcap-external-default".into(),
            mode: VerifierTransportMode::External,
            endpoint_prefix: "https://json.intel.example/v5/quote/".into(),
            auth_required: true,
        }])
        .unwrap(),
    );
    let source = EnvJsonVerifierProfileRegistrySource::from_vars(
        RuntimeVerifierProfileRegistry::with_builtin_defaults(),
        vars,
    );
    let task = mock_task();
    let registry = source
        .load(&BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        })
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let entry = registry.resolve("intel-dcap-external-default").unwrap();
    assert_eq!(
        entry.endpoint_prefix,
        "https://json.intel.example/v5/quote/"
    );
}

