use super::*;

#[test]
fn http_service_response_for_oracle_metrics_returns_prometheus_text() {
    let policy_path = write_json_fixture("oracle-policy-metrics", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-metrics",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/oracle/metrics?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.starts_with(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        ),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_validation_ok{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("accepted_total{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_source_cardinality{feed_id=\"btc/usd\",outcome=\"accepted\"} 2"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_sample_count{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn http_service_response_for_oracle_metrics_rejects_unknown_query_keys() {
    let response = http_service_response_for_target(Some(
        "/oracle/metrics?snapshot=/tmp/s.json&policy=/tmp/p.json&feed_id=btc%2Fusd",
    ));

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.contains("unknown query parameter: feed_id"),
        "{response}"
    );
}

#[test]
fn http_service_response_for_metrics_rejects_empty_oracle_query_values() {
    let response = http_service_response_for_target(Some("/metrics?snapshot=&policy=/tmp/p.json"));

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.contains("\"message\":\"empty snapshot\""),
        "{response}"
    );
}

#[test]
fn http_service_response_for_metrics_rejects_empty_or_invalid_now_ts_ms() {
    for (target, expected) in [
        (
            "/metrics?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=",
            "\"message\":\"empty now_ts_ms\"",
        ),
        (
            "/metrics?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=10ms",
            "\"message\":\"invalid now_ts_ms\"",
        ),
    ] {
        let response = http_service_response_for_target(Some(target));

        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(response.contains(expected), "{response}");
    }
}

#[test]
fn http_service_response_for_metrics_returns_base_prometheus_text() {
    let response = http_service_response_for_target(Some("/metrics"));

    assert!(
        response.starts_with(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        ),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("trnm_rpc_service_up{service=\"trnm-rpc\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("trnm_rpc_service_info{service=\"trnm-rpc\",version=\"1\"} 1"),
        "unexpected response: {}",
        response
    );
}

#[test]
fn http_service_response_for_metrics_appends_oracle_metrics_when_queried() {
    let policy_path = write_json_fixture("oracle-policy-global-metrics", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-global-metrics",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/metrics?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.contains("trnm_rpc_service_up{service=\"trnm-rpc\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_validation_ok{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("accepted_total{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}
