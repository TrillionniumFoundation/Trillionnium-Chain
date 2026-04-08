use super::*;

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
