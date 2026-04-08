use super::*;

#[test]
fn query_capability_audit_reports_expired_without_revocation_fields() {
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

    let out = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
        ],
        registry_path.to_str().expect("utf8 path"),
    );
    let body: Value = serde_json::from_str(&out).expect("query response json");

    assert_eq!(body["token"]["expires_at"].as_u64(), Some(120));
    assert!(
        body["token"]["revoked_at"].is_null(),
        "expired-only token should not report revoked_at"
    );
}

#[test]
fn query_capability_audit_reports_revoked_and_expiry_fields_consistently() {
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
    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("manual-revoke".to_string()),
    )
    .expect("revoke capability");

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&reg).expect("serialize registry"),
    )
    .expect("write registry");

    let out = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
        ],
        registry_path.to_str().expect("utf8 path"),
    );
    let body: Value = serde_json::from_str(&out).expect("query response json");

    assert_eq!(body["token"]["expires_at"].as_u64(), Some(120));
    assert_eq!(body["token"]["revoked_at"].as_u64(), Some(30));
}
