use super::*;

#[test]
fn resolve_capability_token_subject_or_token_strips_invisible_controls_before_lookup() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, " \u{FEFF}did:org:lane-xi\u{200B} ",),
        Some(token_id)
    );
}

#[test]
fn resolve_capability_token_subject_or_token_rejects_noncanonical_subject_alias() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, "did:org:lane-xi\n"),
        Some(token_id)
    );
    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, "did:org:lane xi"),
        None,
        "non-canonical DID aliases must fail closed"
    );
}

#[test]
fn resolve_capability_token_subject_or_token_fail_closed_without_structured_token() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    let mut raw = serde_json::to_value(&registry).expect("serialize registry");
    raw["capabilities"] = serde_json::json!({});
    if let Some(events) = raw["audit_trail"].as_array_mut() {
        if let Some(last) = events.last_mut() {
            last["note"] = serde_json::json!(format!("legacy-note token_id={token_id}"));
        }
    }
    let imported: IdentityRegistry =
        serde_json::from_value(raw).expect("deserialize mutated registry");

    assert_eq!(
        resolve_capability_token_subject_or_token(&imported, "did:org:lane-xi"),
        None,
        "subject lookup must fail-closed when structured token mapping is missing"
    );
}
