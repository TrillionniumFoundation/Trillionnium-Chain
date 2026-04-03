pub(crate) use super::*;
use trnm_types::CapabilityScope;

#[test]
fn query_capability_audit_canonicalizes_same_height_same_seq_owner_history_order() {
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
    registry
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 20, Some(140))
        .expect("renew capability");

    let mut raw = serde_json::to_value(&registry).expect("serialize registry");
    let events = raw["audit_trail"]
        .as_array_mut()
        .expect("audit trail array");
    events.swap(1, 2);
    events[1]["at_height"] = serde_json::json!(99);
    events[2]["at_height"] = serde_json::json!(99);
    events[1]["seq"] = serde_json::json!(77);
    events[2]["seq"] = serde_json::json!(77);

    let imported: IdentityRegistry = serde_json::from_value(raw).expect("deserialize registry");
    let out = query_capability_audit(&imported, token_id).expect("query capability audit");

    let actions = out
        .owner_history
        .iter()
        .map(|event| format!("{:?}", event.action))
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            "DidRegistered".to_string(),
            "CapabilityIssued".to_string(),
            "CapabilityRenewed".to_string(),
        ],
        "same-height/same-seq audit entries should sort canonically rather than preserve import order"
    );
}

#[test]
fn query_capability_audit_canonicalizes_same_action_height_seq_by_actor_then_note() {
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
    registry
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 20, Some(140))
        .expect("renew capability");

    let mut raw = serde_json::to_value(&registry).expect("serialize registry");
    let events = raw["audit_trail"]
        .as_array_mut()
        .expect("audit trail array");
    let mut duplicate_renew = events[2].clone();
    duplicate_renew["at_height"] = serde_json::json!(99);
    duplicate_renew["seq"] = serde_json::json!(77);
    duplicate_renew["actor"] = serde_json::json!("org:lane-xi-admin-a");
    duplicate_renew["note"] = serde_json::json!("audit note a");
    events[2]["at_height"] = serde_json::json!(99);
    events[2]["seq"] = serde_json::json!(77);
    events[2]["actor"] = serde_json::json!("org:lane-xi-admin-z");
    events[2]["note"] = serde_json::json!("audit note z");
    events.push(duplicate_renew);

    let imported: IdentityRegistry = serde_json::from_value(raw).expect("deserialize registry");
    let out = query_capability_audit(&imported, token_id).expect("query capability audit");

    let renewed_entries = out
        .owner_history
        .iter()
        .filter(|event| format!("{:?}", event.action) == "CapabilityRenewed")
        .map(|event| (event.actor.clone(), event.note.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        renewed_entries,
        vec![
            (
                "org:lane-xi-admin-a".to_string(),
                "audit note a".to_string(),
            ),
            (
                "org:lane-xi-admin-z".to_string(),
                "audit note z".to_string(),
            ),
        ],
        "same-action/same-height/same-seq audit entries should sort canonically by actor and note"
    );
}

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
fn resolve_capability_token_subject_or_token_accepts_wrapped_operator_input() {
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
        resolve_capability_token_subject_or_token(&registry, " \"did:org:lane-xi\" "),
        Some(token_id)
    );
    assert_eq!(
        resolve_capability_token_subject_or_token(
            &registry,
            "  \u{2066}`\"'did:org:lane-xi'\"`\u{2069}  ",
        ),
        Some(token_id),
        "mixed operator quoting plus bidi controls should still normalize to the canonical DID"
    );
    let wrapped_token = format!(" '`{token_id}`' ");
    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, &wrapped_token),
        Some(token_id),
        "quoted numeric token ids should resolve like unwrapped operator input"
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

#[test]
fn query_capability_audit_rejects_noncanonical_owner_history_subject_even_when_token_is_valid() {
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
    raw["audit_trail"][0]["subject"] = serde_json::json!("did:org:lane xi");
    let imported: IdentityRegistry = serde_json::from_value(raw).expect("deserialize registry");

    let err = query_capability_audit(&imported, token_id)
        .expect_err("noncanonical audit trail subjects must fail closed");
    assert_eq!(
        err,
        CapabilityAuditQueryError::InvalidRegistryState {
            field: "owner_history.subject",
            value: "did:org:lane xi".to_string(),
        }
    );
}

#[test]
fn capability_audit_query_error_http_status_preserves_not_found() {
    let err = CapabilityAuditQueryError::TokenNotFound(404);

    assert_eq!(err.http_status(), "404 Not Found");
    assert_eq!(err.to_rpc_error().code, "CAPABILITY_NOT_FOUND");
}

#[test]
fn capability_audit_query_error_http_status_preserves_invalid_registry_state() {
    let err = CapabilityAuditQueryError::InvalidRegistryState {
        field: "subject_did",
        value: "did:org:bad subject".to_string(),
    };

    assert_eq!(err.http_status(), "422 Unprocessable Entity");
    assert_eq!(err.to_rpc_error().code, "INVALID_REGISTRY_STATE");
}
