use super::*;

#[test]
fn normalize_zk_system_accepts_common_aliases() {
    assert_eq!(normalize_zk_system("groth16"), Some("groth16".into()));
    assert_eq!(normalize_zk_system(" Groth-16 "), Some("groth16".into()));
    assert_eq!(normalize_zk_system("PLONK"), Some("plonk".into()));
    assert_eq!(normalize_zk_system("mock-zk"), None);
}

#[test]
fn normalize_zk_system_rejects_reserved_custom_namespace_until_versioned_support_lands() {
    assert_eq!(normalize_zk_system("custom:acme:sumcheck"), None);
    assert_eq!(normalize_zk_system(" custom:acme:sumcheck "), None);
}

#[test]
fn normalize_backend_token_rejects_noop_aliases_as_non_explicit_backend() {
    assert_eq!(normalize_backend_token("noop"), None);
    assert_eq!(normalize_backend_token(" NOOP "), None);
    assert_eq!(normalize_backend_token("noop!!!"), None);
    assert_eq!(
        normalize_backend_token("groth16-demo"),
        Some("groth16 demo".into())
    );
}

#[test]
fn backend_token_zk_system_hints_extracts_all_canonical_system_hints() {
    assert_eq!(
        backend_token_zk_system_hints("groth16-demo"),
        vec!["groth16"]
    );
    assert_eq!(
        backend_token_zk_system_hints("groth16-plonk-demo"),
        vec!["groth16", "plonk"]
    );
    assert_eq!(
        backend_token_zk_system_hints("groth16-groth16-demo"),
        vec!["groth16"]
    );
    assert_eq!(
        backend_token_zk_system_hints("tee-groth16-demo"),
        vec!["groth16"]
    );
    assert!(backend_token_zk_system_hints("mock-zk").is_empty());
}

#[test]
fn backend_token_family_and_system_hints_canonicalize_case_drifted_alias_segments() {
    assert_eq!(
        backend_token_family_hint("ZK-Groth-16-demo"),
        Some(VerificationBackendFamily::Zk)
    );
    assert_eq!(
        backend_token_zk_system_hints("ZK-Groth-16-GROTH16-demo"),
        vec!["groth16"]
    );
    assert_eq!(
        backend_token_zk_system_hints("TEE-PLONK-Plonk-demo"),
        vec!["plonk"]
    );
}

#[test]
fn backend_registry_resolves_canonicalized_backend_aliases_fail_closed_without_guessing() {
    let mut registry = VerificationBackendRegistry::new();
    registry.register(Arc::new(MockRegistryBackend {
        backend_id: "zk groth16 demo",
    }));

    let backend = registry
        .resolve(
            VerificationBackendFamily::Zk,
            &VerificationBackendKind::Custom("zk-groth16-demo".into()),
        )
        .unwrap();
    assert_eq!(backend.backend_id(), "zk groth16 demo");

    let err = match registry.resolve(
        VerificationBackendFamily::Zk,
        &VerificationBackendKind::Custom("zk-groth16-plonk-demo".into()),
    ) {
        Ok(found) => panic!("expected unknown backend, got {}", found.backend_id()),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        BackendSelectionError::UnknownBackend { family, backend }
            if family == VerificationBackendFamily::Zk
                && backend == "zk-groth16-plonk-demo"
    ));
}

#[test]
fn backend_system_hint_only_returns_canonical_system_tokens() {
    assert_eq!(backend_system_hint("groth16-demo"), Some("groth16".into()));
    assert_eq!(
        backend_system_hint("zk-groth16-demo"),
        Some("groth16".into())
    );
    assert_eq!(backend_system_hint("zk-demo"), None);
    assert_eq!(backend_system_hint("mock-zk"), None);
}

#[test]
fn backend_token_family_hint_detects_explicit_family_prefixes() {
    assert_eq!(
        backend_token_family_hint("zk-groth16-demo"),
        Some(VerificationBackendFamily::Zk)
    );
    assert_eq!(
        backend_token_family_hint(" tee-groth16-demo "),
        Some(VerificationBackendFamily::Tee)
    );
    assert_eq!(backend_token_family_hint("groth16-demo"), None);
    assert_eq!(backend_token_family_hint("noop"), None);
}

#[test]
fn backend_execution_error_classification_matches_v0_taxonomy() {
    let cases = vec![
        (
            BackendExecutionError::NotConfigured {
                backend: "zk:noop".into(),
            },
            VerificationErrorClass::Unavailable,
        ),
        (
            BackendExecutionError::Unavailable {
                backend: "zk:groth16-demo".into(),
                reason: "registry temporarily unavailable".into(),
            },
            VerificationErrorClass::Unavailable,
        ),
        (
            BackendExecutionError::InvalidProof {
                backend: "zk:groth16-demo".into(),
                reason: "proof/vk mismatch".into(),
            },
            VerificationErrorClass::Invalid,
        ),
        (
            BackendExecutionError::MalformedProof {
                backend: "zk:payload".into(),
                reason: "public_inputs order is not canonical".into(),
            },
            VerificationErrorClass::Malformed,
        ),
        (
            BackendExecutionError::Internal {
                backend: "zk:groth16-demo".into(),
                reason: "ffi panic".into(),
            },
            VerificationErrorClass::BackendError,
        ),
    ];

    for (err, expected_class) in cases {
        assert_eq!(err.error_class(), expected_class);
    }
}
