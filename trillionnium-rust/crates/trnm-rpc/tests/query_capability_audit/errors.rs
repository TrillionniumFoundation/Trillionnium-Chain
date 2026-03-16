use super::*;

#[test]
fn query_capability_audit_not_found_maps_stable_error_code() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");
    fs::write(&registry_path, "{}").expect("write empty registry json");

    let stderr = run_fail(
        &["query-capability-audit", "--token-id", "404"],
        registry_path.to_str().expect("utf8 path"),
    );

    assert!(
        stderr.contains("\"code\": \"CAPABILITY_NOT_FOUND\""),
        "{stderr}"
    );
}

#[test]
fn query_capability_audit_rejects_noncanonical_subject_did_from_registry_snapshot() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");

    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:org:lane-xi".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .expect("register did");
    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    let mut raw: Value = serde_json::to_value(&reg).expect("registry to json");
    raw["capabilities"][token_id.to_string()]["subject_did"] =
        Value::String("did:Org:lane-xi".to_string());

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&raw).expect("serialize registry"),
    )
    .expect("write registry");

    let stderr = run_fail(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
        ],
        registry_path.to_str().expect("utf8 path"),
    );

    assert!(
        stderr.contains("\"code\": \"INVALID_REGISTRY_STATE\""),
        "{stderr}"
    );
    assert!(stderr.contains("non-canonical subject_did"), "{stderr}");
}
