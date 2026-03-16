use super::*;

#[test]
fn query_capability_audit_happy_path() {
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

    assert_eq!(body["token"]["token_id"].as_u64(), Some(token_id));
    assert_eq!(
        body["token"]["subject_did"].as_str(),
        Some("did:org:lane-xi")
    );
    assert!(
        body["owner_history"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0)
            >= 1,
        "owner_history should include DID/capability audit entries"
    );
}

#[test]
fn query_capability_audit_owner_history_is_stably_sorted_for_imported_registry() {
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
    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 20, Some(180))
        .expect("renew capability");

    let mut raw: Value = serde_json::to_value(&reg).expect("registry to json");
    let audit = raw["audit_trail"]
        .as_array_mut()
        .expect("audit_trail array");
    audit.reverse();

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&raw).expect("serialize registry"),
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
    let heights: Vec<u64> = body["owner_history"]
        .as_array()
        .expect("owner_history array")
        .iter()
        .map(|ev| ev["at_height"].as_u64().expect("audit height"))
        .collect();

    assert_eq!(heights, vec![10, 12, 20]);
}

#[test]
fn query_capability_audit_owner_history_sorts_by_height_then_seq_on_ties() {
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
    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 12, Some(130))
        .expect("renew capability at same height as issue");

    let mut raw: Value = serde_json::to_value(&reg).expect("registry to json");
    raw["audit_trail"]
        .as_array_mut()
        .expect("audit trail")
        .reverse();

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&raw).expect("serialize registry"),
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
    let same_height_events: Vec<(String, u64)> = body["owner_history"]
        .as_array()
        .expect("owner_history array")
        .iter()
        .filter(|ev| ev["at_height"].as_u64() == Some(12))
        .map(|ev| {
            (
                ev["action"].as_str().expect("action").to_string(),
                ev["seq"].as_u64().expect("seq"),
            )
        })
        .collect();

    assert_eq!(
        same_height_events,
        vec![
            ("CAPABILITY_ISSUED".to_string(), 2),
            ("CAPABILITY_RENEWED".to_string(), 3),
        ]
    );
}

#[test]
fn query_capability_audit_filters_owner_history_to_subject_did_only() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");

    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:org:lane-xi".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .expect("register lane-xi did");
    reg.register_did(
        "did:org:other-lane".to_string(),
        "org:other-lane-admin".to_string(),
        11,
    )
    .expect("register other did");

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue lane-xi capability");

    reg.issue_capability(
        "org:other-lane-admin".to_string(),
        "did:org:other-lane".to_string(),
        CapabilityScope::AuditRead,
        13,
        Some(121),
    )
    .expect("issue other capability");

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

    let leaked_foreign_subject = body["owner_history"]
        .as_array()
        .expect("owner_history array")
        .iter()
        .any(|ev| ev["subject"].as_str() == Some("did:org:other-lane"));

    assert!(
        !leaked_foreign_subject,
        "foreign DID events leaked into owner_history"
    );
}
