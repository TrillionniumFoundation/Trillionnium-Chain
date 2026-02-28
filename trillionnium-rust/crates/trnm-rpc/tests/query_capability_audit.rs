use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use trnm_types::{CapabilityScope, IdentityRegistry};

fn run_ok(args: &[&str], registry_path: &str) -> String {
    let output = Command::new("cargo")
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
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_IDENTITY_REGISTRY_FILE", registry_path)
        .output()
        .expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn query_capability_audit_happy_path_json_default_and_summary_mode() {
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
    let owner_history_count = body["owner_history"]
        .as_array()
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        owner_history_count >= 1,
        "owner_history should include DID/capability audit entries"
    );

    let summary_out = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_id.to_string(),
            "--summary",
        ],
        registry_path.to_str().expect("utf8 path"),
    );
    let summary_line = summary_out.trim();
    assert!(summary_line.contains(&format!("token_id={token_id}")));
    assert!(summary_line.contains("scope=AUDIT_READ"));
    assert!(summary_line.contains(&format!("owner_history_count={owner_history_count}")));
}

#[test]
fn query_capability_audit_not_found_maps_stable_error_code() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");
    fs::write(&registry_path, "{}").expect("write empty registry json");

    let stderr = run_fail(
        &[
            "query-capability-audit",
            "--token-id",
            "404",
            "--field",
            "owner-history-count",
        ],
        registry_path.to_str().expect("utf8 path"),
    );

    assert!(
        stderr.contains("\"code\": \"CAPABILITY_NOT_FOUND\""),
        "{stderr}"
    );
}

#[test]
fn query_capability_audit_same_did_multi_token_filters_to_exact_token_in_field_mode() {
    let tmp = tempdir().expect("tempdir");
    let registry_path = tmp.path().join("identity_registry.json");

    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:org:lane-xi-multi".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .expect("register did");

    let token_1 = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi-multi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability token1");
    let token_2 = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi-multi".to_string(),
            CapabilityScope::MarketPublish,
            14,
            Some(140),
        )
        .expect("issue capability token2");

    reg.renew_capability("org:lane-xi-admin".to_string(), token_1, 16, Some(180))
        .expect("renew token1");
    reg.renew_capability("org:lane-xi-admin".to_string(), token_2, 18, Some(200))
        .expect("renew token2");
    reg.renew_capability("org:lane-xi-admin".to_string(), token_2, 20, Some(220))
        .expect("renew token2 again");

    fs::write(
        &registry_path,
        serde_json::to_string_pretty(&reg).expect("serialize registry"),
    )
    .expect("write registry");

    let out_token_1 = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_1.to_string(),
            "--field",
            "owner-history-count",
        ],
        registry_path.to_str().expect("utf8 path"),
    );
    let out_token_2 = run_ok(
        &[
            "query-capability-audit",
            "--token-id",
            &token_2.to_string(),
            "--field",
            "owner-history-count",
        ],
        registry_path.to_str().expect("utf8 path"),
    );

    let token_1_count: usize = out_token_1
        .trim()
        .parse()
        .expect("token_1 owner-history-count parse");
    let token_2_count: usize = out_token_2
        .trim()
        .parse()
        .expect("token_2 owner-history-count parse");

    assert_eq!(token_1_count, 3, "did + token_1 issue + token_1 renew");
    assert_eq!(token_2_count, 4, "did + token_2 issue + token_2 renews");
}
