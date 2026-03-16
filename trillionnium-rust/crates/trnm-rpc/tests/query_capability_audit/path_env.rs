use super::*;

#[test]
fn query_capability_audit_accepts_quoted_registry_env_path() {
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

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&reg).expect("serialize registry"),
    )
    .expect("write registry");

    let quoted = format!("\"{}\"", registry_path.to_str().expect("utf8 path"));
    let out = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
        ],
        &quoted,
    );
    let body: Value = serde_json::from_str(&out).expect("query response json");
    assert_eq!(body["token"]["token_id"].as_u64(), Some(token_id));
}

#[test]
fn query_capability_audit_accepts_nested_mixed_quotes_in_registry_env_path() {
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

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&reg).expect("serialize registry"),
    )
    .expect("write registry");

    let nested = format!("  `\"'{}'\"`  ", registry_path.to_str().expect("utf8 path"));
    let out = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
        ],
        &nested,
    );
    let body: Value = serde_json::from_str(&out).expect("query response json");
    assert_eq!(body["token"]["token_id"].as_u64(), Some(token_id));
}
