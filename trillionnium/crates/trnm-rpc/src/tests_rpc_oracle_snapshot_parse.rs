use super::*;

const MAX_ORACLE_QUERY_PATH_LEN: usize = 4096;

#[test]
fn parse_http_query_params_decodes_percent_and_plus() {
    let params = parse_http_query_params(
            "/oracle/validate_snapshot?snapshot=%2Ftmp%2Foracle+snapshot.json&policy=%2Ftmp%2Fpolicy.json&now_ts_ms=10100",
        )
        .expect("query params");

    assert_eq!(
        params.get("snapshot").map(String::as_str),
        Some("/tmp/oracle snapshot.json")
    );
    assert_eq!(
        params.get("policy").map(String::as_str),
        Some("/tmp/policy.json")
    );
    assert_eq!(params.get("now_ts_ms").map(String::as_str), Some("10100"));
}
#[test]
fn parse_http_query_params_rejects_duplicate_keys() {
    assert!(
            parse_http_query_params(
                "/oracle/validate_snapshot?snapshot=/tmp/a.json&snapshot=/tmp/b.json&policy=/tmp/p.json"
            )
            .is_none(),
            "duplicate query keys must fail closed"
        );
}

#[test]
fn parse_http_query_params_rejects_query_smuggling_and_fragments() {
    for target in [
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&&policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&policy=/tmp/p.json#tail",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json%26policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&policy=/tmp/p.json%23tail",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&policy=/tmp/p.json%0D%0Aextra",
    ] {
        assert!(
            parse_http_query_params(target).is_none(),
            "target must fail closed: {target}"
        );
    }
}

#[test]
fn parse_http_query_params_rejects_percent_encoded_controls_and_del() {
    for target in [
        "/oracle/validate_snapshot?snapshot=/tmp/a.json%01&policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&policy=/tmp/p.json%7F",
        "/oracle/validate_snapshot?snapshot=/tmp/a.json&policy=/tmp/p.json&now_ts_ms=10100%1f",
    ] {
        assert!(
            parse_http_query_params(target).is_none(),
            "target must fail closed: {target}"
        );
    }
}

#[test]
fn parse_http_query_params_rejects_non_canonical_query_keys() {
    for target in [
        "/oracle/validate_snapshot?=value&policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&+policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy+=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&po+licy=/tmp/p.json",
    ] {
        assert!(
            parse_http_query_params(target).is_none(),
            "non-canonical query key must fail closed: {target}"
        );
    }
}
#[test]
fn parse_oracle_validate_snapshot_target_returns_stable_request_schema() {
    let request = parse_oracle_validate_snapshot_target(
            "/oracle/validate_snapshot?snapshot=%2Ftmp%2Foracle+snapshot.json&policy=%2Ftmp%2Fpolicy.json&now_ts_ms=10100",
        )
        .expect("oracle request");

    assert_eq!(request.snapshot, "/tmp/oracle snapshot.json");
    assert_eq!(request.policy, "/tmp/policy.json");
    assert_eq!(request.now_ts_ms, Some(10_100));
}

#[test]
fn parse_oracle_validate_snapshot_target_accepts_oracle_metrics_alias() {
    let request = parse_oracle_validate_snapshot_target(
        "/oracle/metrics?snapshot=/tmp/oracle.json&policy=/tmp/policy.json&now_ts_ms=10100",
    )
    .expect("oracle metrics alias should reuse the same request schema");

    assert_eq!(request.snapshot, "/tmp/oracle.json");
    assert_eq!(request.policy, "/tmp/policy.json");
    assert_eq!(request.now_ts_ms, Some(10_100));
}

#[test]
fn parse_oracle_validate_snapshot_target_accepts_global_metrics_alias() {
    let request = parse_oracle_validate_snapshot_target(
        "/metrics?snapshot=/tmp/oracle.json&policy=/tmp/policy.json&now_ts_ms=10100",
    )
    .expect("global metrics alias should preserve oracle query parsing");

    assert_eq!(request.snapshot, "/tmp/oracle.json");
    assert_eq!(request.policy, "/tmp/policy.json");
    assert_eq!(request.now_ts_ms, Some(10_100));
}
#[test]
fn parse_oracle_validate_snapshot_target_rejects_unknown_query_keys() {
    let err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&feed_id=btc%2Fusd",
    )
    .expect_err("unknown key must fail closed");

    assert!(err.contains("unknown query parameter: feed_id"), "{err}");
}
#[test]
fn parse_oracle_validate_snapshot_target_rejects_empty_snapshot_or_policy() {
    let snapshot_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=&policy=/tmp/p.json",
    )
    .expect_err("empty snapshot must fail closed");
    assert_eq!(snapshot_err, "empty snapshot");

    let policy_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=+",
    )
    .expect_err("empty policy must fail closed");
    assert_eq!(policy_err, "empty policy");
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_non_canonical_snapshot_or_policy_paths() {
    let snapshot_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=+/tmp/s.json&policy=/tmp/p.json",
    )
    .expect_err("snapshot path with leading space must fail closed");
    assert_eq!(snapshot_err, "non-canonical snapshot path");

    let policy_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json+",
    )
    .expect_err("policy path with trailing space must fail closed");
    assert_eq!(policy_err, "non-canonical policy path");
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_snapshot_path_above_bound() {
    let snapshot = format!("/tmp/{}", "a".repeat(MAX_ORACLE_QUERY_PATH_LEN + 1));
    let target = format!(
        "/oracle/validate_snapshot?snapshot={snapshot}&policy=/tmp/p.json"
    );

    let err = parse_oracle_validate_snapshot_target(&target)
        .expect_err("oversized snapshot path must fail closed");

    assert_eq!(err, "snapshot path too long");
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_policy_path_above_bound() {
    let policy = format!("/tmp/{}", "b".repeat(MAX_ORACLE_QUERY_PATH_LEN + 1));
    let target = format!(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy={policy}"
    );

    let err = parse_oracle_validate_snapshot_target(&target)
        .expect_err("oversized policy path must fail closed");

    assert_eq!(err, "policy path too long");
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_fragment_and_encoded_query_smuggling() {
    for target in [
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json#tail",
        "/oracle/validate_snapshot?snapshot=/tmp/s.json%26policy=/tmp/p.json",
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json%0d%0aextra",
    ] {
        let err = parse_oracle_validate_snapshot_target(target)
            .expect_err("smuggled oracle query must fail closed");
        assert_eq!(err, "invalid query params", "target={target}");
    }
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_empty_or_invalid_now_ts_ms() {
    for (target, expected) in [
        (
            "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=",
            "empty now_ts_ms",
        ),
        (
            "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=+",
            "empty now_ts_ms",
        ),
        (
            "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=%20",
            "empty now_ts_ms",
        ),
        (
            "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&now_ts_ms=10ms",
            "invalid now_ts_ms",
        ),
    ] {
        let err = parse_oracle_validate_snapshot_target(target)
            .expect_err("non-canonical now_ts_ms must fail closed");
        assert_eq!(err, expected, "target={target}");
    }
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_non_exact_path_prefixes() {
    for target in [
        "/oracle/validate_snapshot_extra?snapshot=/tmp/s.json&policy=/tmp/p.json",
        "/oracle/metrics_extra?snapshot=/tmp/s.json&policy=/tmp/p.json",
        "/metrics_extra?snapshot=/tmp/s.json&policy=/tmp/p.json",
    ] {
        let err = parse_oracle_validate_snapshot_target(target)
            .expect_err("non-exact oracle path prefix must fail closed");
        assert_eq!(err, "unexpected oracle target", "target={target}");
    }
}
