use super::*;

#[test]
fn http_service_response_for_oracle_validate_snapshot_returns_structured_json() {
    let policy_path = write_json_fixture("oracle-policy-http", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-http",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/oracle/validate_snapshot?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"ok\":true"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"outcome\":\"accepted\""),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"accepted_total\":1"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn http_service_response_for_oracle_validate_snapshot_rejects_non_exact_path_prefix() {
    let response = http_service_response_for_target(Some(
        "/oracle/validate_snapshot_extra?snapshot=/tmp/s.json&policy=/tmp/p.json",
    ));

    assert!(
        response.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "unexpected response: {}",
        response
    );
}
