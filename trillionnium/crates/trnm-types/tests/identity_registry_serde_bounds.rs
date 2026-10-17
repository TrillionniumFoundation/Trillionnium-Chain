use serde_json::json;
use trnm_types::{CapabilityScope, IdentityRegistry};

fn populated_registry() -> IdentityRegistry {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did("did:trnm:serde-boundary".into(), "org:controller".into(), 10)
        .unwrap();
    registry
        .issue_capability(
            "org:controller".into(),
            "did:trnm:serde-boundary".into(),
            CapabilityScope::AuditRead,
            11,
            None,
        )
        .unwrap();
    registry
}

#[test]
fn identity_registry_serde_round_trip_preserves_valid_state() {
    let registry = populated_registry();
    let encoded = serde_json::to_vec(&registry).unwrap();
    let restored: IdentityRegistry = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored.content_hash(), registry.content_hash());
}

#[test]
fn identity_registry_rejects_snapshot_key_identity_mismatch() {
    let registry = populated_registry();
    let mut value = serde_json::to_value(&registry).unwrap();
    value["dids"]["did:trnm:attacker"]["did"] = json!("did:trnm:serde-boundary");
    assert!(serde_json::from_value::<IdentityRegistry>(value).is_err());
}

#[test]
fn identity_registry_rejects_capability_counter_rollback() {
    let registry = populated_registry();
    let mut value = serde_json::to_value(&registry).unwrap();
    value["next_capability_id"] = json!(0);
    assert!(serde_json::from_value::<IdentityRegistry>(value).is_err());
}

#[test]
fn identity_registry_rejects_unknown_snapshot_fields() {
    let registry = populated_registry();
    let mut value = serde_json::to_value(&registry).unwrap();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<IdentityRegistry>(value).is_err());
}
