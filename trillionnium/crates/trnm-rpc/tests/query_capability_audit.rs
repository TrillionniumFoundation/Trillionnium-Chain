use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use trnm_types::{CapabilityScope, IdentityRegistry};

fn run_ok(args: &[&str], registry_path: &str) -> String {
    let output = Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_IDENTITY_REGISTRY_FILE", registry_path)
        .output()
        .expect("failed to execute trnm-rpc");
    if !output.status.success() {
        panic!("RPC failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fail(args: &[&str], registry_path: &str) -> String {
    let output = Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_IDENTITY_REGISTRY_FILE", registry_path)
        .output()
        .expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

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

    // regression: config injectors may wrap env values multiple times with mixed quotes
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
fn query_capability_audit_owner_history_keeps_revocation_event_on_same_height_tie() {
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
        12,
        Some("operator-drill".to_string()),
    )
    .expect("revoke capability at same height as issue");

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
            ("CAPABILITY_REVOKED".to_string(), 3),
        ]
    );
    assert_eq!(body["token"]["revoked_at"].as_u64(), Some(12));
}

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

#[test]
fn query_capability_audit_rejects_noncanonical_owner_history_subject_from_registry_snapshot() {
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
    let audit_trail = raw["audit_trail"]
        .as_array_mut()
        .expect("audit trail array");
    let owner_event = audit_trail
        .iter_mut()
        .find(|event| event["subject"] == Value::String("did:org:lane-xi".to_string()))
        .expect("owner history event for subject did");
    owner_event["subject"] = Value::String("did:Org:lane-xi".to_string());

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
    assert!(
        stderr.contains("non-canonical owner_history.subject"),
        "{stderr}"
    );
}

#[test]
fn query_capability_audit_rejects_non_numeric_token_id() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");
    fs::write(&registry_path, "{}").expect("write empty registry json");

    let stderr = run_fail(
        &["query-capability-audit", "--token-id", "not-a-number"],
        registry_path.to_str().expect("utf8 path"),
    );

    assert!(
        stderr.contains("invalid value 'not-a-number' for '--token-id <TOKEN_ID>'"),
        "{stderr}"
    );
}

#[test]
fn query_capability_audit_rejects_missing_token_id_argument() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");
    fs::write(&registry_path, "{}").expect("write empty registry json");

    let stderr = run_fail(
        &["query-capability-audit"],
        registry_path.to_str().expect("utf8 path"),
    );

    assert!(
        stderr.contains("required arguments were not provided")
            || stderr.contains("required argument '--token-id <TOKEN_ID>' was not provided"),
        "{stderr}"
    );
}
