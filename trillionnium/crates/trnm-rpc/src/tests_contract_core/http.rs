pub(crate) use super::*;

#[test]
fn parse_http_get_path_accepts_canonical_request_line() {
    assert_eq!(
        parse_http_get_path("GET /query-task/42?verbose=1 HTTP/1.1"),
        Some("/query-task/42")
    );
}

#[test]
fn parse_http_get_path_preserves_operator_trailing_slash_for_query_routes() {
    assert_eq!(
        parse_http_get_path("GET /query-task/42/ HTTP/1.1"),
        Some("/query-task/42/")
    );
    assert_eq!(
        parse_http_get_path("GET /query-events/7/?limit=5 HTTP/1.1"),
        Some("/query-events/7/")
    );
}

#[test]
fn parse_http_request_target_accepts_head_health_probe() {
    assert_eq!(
        parse_http_request_target("HEAD /readyz HTTP/1.1"),
        Some(("HEAD", "/readyz"))
    );
    assert_eq!(
        parse_http_request_target("head /readyz HTTP/1.1"),
        Some(("head", "/readyz"))
    );
    assert_eq!(parse_http_get_path("HEAD /readyz HTTP/1.1"), None);
}

#[test]
fn head_health_probe_alias_ignores_query_string_and_preserves_content_length() {
    let request = parse_http_request_target("HEAD /-/readyz?probe=lb&from=ops HTTP/1.1")
        .expect("health alias request parses");
    let path = request.1.split('?').next().expect("path before query");
    assert!(is_health_probe_path(path));

    let response = if is_health_probe_path(path) {
        json_response_for_method(request.0, "200 OK", &health_probe_body(42))
    } else {
        unreachable!("health alias with query string should match after path split")
    };

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Length: 50\r\n"));
    assert!(response.ends_with("\r\n\r\n"));
    assert!(!response.ends_with("\"version\":1}"));
}

#[test]
fn get_health_probe_alias_ignores_query_string_and_keeps_minimum_json_contract() {
    let request = parse_http_request_target("GET /healthz?probe=lb&from=ops HTTP/1.1")
        .expect("health alias request parses");
    let path = request.1.split('?').next().expect("path before query");
    assert!(is_health_probe_path(path));

    let response = if is_health_probe_path(path) {
        json_response_for_method(request.0, "200 OK", &health_probe_body(42))
    } else {
        unreachable!("health alias with query string should match after path split")
    };

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Length: 50\r\n"));
    assert!(response.ends_with("{\"ok\":true,\"service\":\"trnm-rpc\",\"ts_unix_ms\":42,\"version\":1}"));
}

#[test]
fn get_health_probe_alias_with_trailing_slash_before_query_keeps_same_contract() {
    let request = parse_http_request_target("GET /-/statusz/?from=ops HTTP/1.1")
        .expect("health alias request parses");
    let path = request.1.split('?').next().expect("path before query");
    assert_eq!(path, "/-/statusz/");
    assert!(is_health_probe_path(path));

    let response = if is_health_probe_path(path) {
        json_response_for_method(request.0, "200 OK", &health_probe_body(42))
    } else {
        unreachable!("health alias with trailing slash and query string should match")
    };

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Content-Length: 50\r\n"));
    assert!(response.ends_with("{\"ok\":true,\"service\":\"trnm-rpc\",\"ts_unix_ms\":42,\"version\":1}"));
}

#[test]
fn live_and_status_probe_aliases_with_query_strings_stay_on_same_minimum_contract() {
    for (method, request_line, expected_path) in [
        ("GET", "GET /live?probe=lb HTTP/1.1", "/live"),
        ("HEAD", "HEAD /-/status/?from=ops HTTP/1.1", "/-/status/"),
    ] {
        let request = parse_http_request_target(request_line).expect("health alias request parses");
        assert_eq!(request.0, method);
        let path = request.1.split('?').next().expect("path before query");
        assert_eq!(path, expected_path);
        assert!(is_health_probe_path(path), "path should remain an accepted probe alias: {path}");

        let response = json_response_for_method(request.0, "200 OK", &health_probe_body(42));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 50\r\n"));
        if method == "HEAD" {
            assert!(response.ends_with("\r\n\r\n"));
            assert!(!response.ends_with("\"version\":1}"));
        } else {
            assert!(response.ends_with("{\"ok\":true,\"service\":\"trnm-rpc\",\"ts_unix_ms\":42,\"version\":1}"));
        }
    }
}

#[test]
fn parse_http_get_path_accepts_lowercase_get_method() {
    assert_eq!(
        parse_http_get_path("get /query-task/42?verbose=1 HTTP/1.1"),
        Some("/query-task/42")
    );
}

#[test]
fn parse_http_request_target_accepts_only_supported_http_versions() {
    assert_eq!(
        parse_http_request_target("GET /health HTTP/1.1"),
        Some(("GET", "/health"))
    );
    assert_eq!(
        parse_http_request_target("HEAD /readyz HTTP/1.0"),
        Some(("HEAD", "/readyz"))
    );
    assert_eq!(parse_http_request_target("GET /health HTTP/2"), None);
    assert_eq!(parse_http_request_target("GET /health HTTP/1.1junk"), None);
    assert_eq!(parse_http_request_target("GET /health http/1.1"), None);
}

#[test]
fn http_json_responses_disable_caching_for_operator_probes() {
    let get = http_json_response("200 OK", "{\"ok\":true}");
    assert!(get.contains("\r\nCache-Control: no-store\r\n"));

    let head = http_json_head_response("200 OK", 11);
    assert!(head.contains("\r\nCache-Control: no-store\r\n"));
}

#[test]
fn parse_http_get_path_rejects_fragment_suffixes_fail_closed() {
    assert_eq!(parse_http_get_path("GET /health#bridge HTTP/1.1"), None);
    assert_eq!(
        parse_http_get_path("GET /query-events/7?limit=5#tail HTTP/1.1"),
        None
    );
}

#[test]
fn parse_http_request_target_rejects_encoded_query_delimiter_fail_closed() {
    assert_eq!(
        parse_http_request_target("GET /query-task/42%3Fshadow HTTP/1.1"),
        None
    );
    assert_eq!(
        parse_http_request_target("HEAD /query-events/7%3flimit=9 HTTP/1.1"),
        None
    );
}

#[test]
fn parse_http_request_target_rejects_malformed_percent_encoding_fail_closed() {
    for first_line in [
        "GET /query-task/42% HTTP/1.1",
        "GET /query-events/7%2 HTTP/1.1",
        "HEAD /query-events/7%zz HTTP/1.1",
        "HEAD /query-capability-audit/alice%4G HTTP/1.1",
    ] {
        assert_eq!(
            parse_http_request_target(first_line),
            None,
            "malformed percent encoding must fail closed: {first_line}"
        );
    }
}

#[test]
fn parse_query_events_limit_from_path_defaults_and_accepts_explicit_limit() {
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42").expect("default limit"),
        QUERY_EVENTS_LIMIT_DEFAULT
    );
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42?limit=7").expect("explicit limit"),
        7
    );
}

#[test]
fn parse_query_events_limit_from_path_zero_uses_default_limit() {
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42?limit=0")
            .expect("zero limit should fall back to the bounded default"),
        QUERY_EVENTS_LIMIT_DEFAULT
    );
}

#[test]
fn parse_query_events_limit_from_path_rejects_unrelated_query_keys() {
    for path in [
        "/query-events/42?foo=bar&limit=9",
        "/query-events/42?limit=9&foo=bar",
        "/query-events/42?foo=bar",
        "/query-events/42?limit=9&bar=baz",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("unrelated query keys must fail closed instead of being ignored");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_invalid_limit() {
    let err = parse_query_events_limit_from_path("/query-events/42?limit=bogus")
        .expect_err("invalid limit must fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid limit"));
}

#[test]
fn parse_query_events_limit_from_path_rejects_duplicate_limit_keys() {
    for path in [
        "/query-events/42?limit=7&limit=9",
        "/query-events/42?limit=7&limit=7",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("duplicate limit keys must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("duplicate limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_uppercase_percent_encoded_query_delimiters() {
    for path in [
        "/query-events/42?limit=7%26limit=9",
        "/query-events/42?limit%3D9",
        "/query-events/42?limit=7%23tail",
        "/query-events/42?limit=7%0D%0Aextra",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("uppercase encoded delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_accepts_wrapped_numeric_limit() {
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42?limit=\"7\"")
            .expect("double-quoted numeric limit should parse"),
        7
    );
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42?limit='8'")
            .expect("single-quoted numeric limit should parse"),
        8
    );
    assert_eq!(
        parse_query_events_limit_from_path("/query-events/42?limit=  `9`  ")
            .expect("backtick-wrapped numeric limit should parse"),
        9
    );
}

#[test]
fn parse_query_events_limit_from_path_clamps_to_hardcap() {
    assert_eq!(
        parse_query_events_limit_from_path(&format!(
            "/query-events/42?limit={}",
            QUERY_EVENTS_LIMIT_MAX + 99
        ))
        .expect("oversized limit should clamp to hardcap"),
        QUERY_EVENTS_LIMIT_MAX
    );
}

#[test]
fn parse_query_events_limit_from_path_rejects_missing_limit_value() {
    let err = parse_query_events_limit_from_path("/query-events/42?limit")
        .expect_err("missing limit value must fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid limit"));
}

#[test]
fn parse_query_events_limit_from_path_rejects_empty_query_suffix() {
    let err = parse_query_events_limit_from_path("/query-events/42?")
        .expect_err("empty query suffix must fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid limit"));
}

#[test]
fn parse_query_events_limit_from_path_rejects_empty_limit_value() {
    let err = parse_query_events_limit_from_path("/query-events/42?limit=")
        .expect_err("empty limit value must fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid limit"));
}

#[test]
fn parse_query_events_limit_from_path_rejects_encoded_query_smuggling() {
    for path in [
        "/query-events/42?limit=7%26limit=9",
        "/query-events/42?limit%3d7",
        "/query-events/42?foo=bar%26limit=9",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("encoded delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_malformed_unrelated_query_pairs() {
    for path in [
        "/query-events/42?foo&limit=7",
        "/query-events/42?foo=bar&baz",
        "/query-events/42?foo=bar&limit=7&qux",
        "/query-events/42??limit=7",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("malformed unrelated query pairs must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_percent_encoded_query_delimiters() {
    for path in [
        "/query-events/42?foo=bar%26limit=9",
        "/query-events/42?limit%3d9",
        "/query-events/42?limit=7%23tail",
        "/query-events/42?foo=bar%3flimit=9",
        "/query-events/42?foo=bar%0d%0alimit=9",
        "/query-events/42?limit=7%0d%0aextra",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("encoded query delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_raw_fragment_delimiters() {
    for path in [
        "/query-events/42?limit=7#tail",
        "/query-events/42?foo=bar#tail",
        "/query-events/42?foo=bar&limit=7#tail",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("raw fragment delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_raw_query_whitespace() {
    for path in [
        "/query-events/42?limit=7 ",
        "/query-events/42?limit=7\t",
        "/query-events/42?limit= 7",
        "/query-events/42?limit=7&limit=8 ",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("raw query whitespace must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path:?} err={err}");
        assert!(err.contains("invalid limit"), "path={path:?} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_percent_encoded_null_and_del_controls() {
    for path in [
        "/query-events/42?limit=7%00tail",
        "/query-events/42?limit=7%7ftrail",
        "/query-events/%007?limit=7",
        "/query-events/42%7fjson?limit=7",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("percent-encoded null and del controls must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_events_limit_from_path_rejects_percent_encoded_path_smuggling() {
    for path in [
        "/query-events%2f42?limit=7",
        "/query-events/..%2f42?limit=7",
        "/query-events/%2e%2e/42?limit=7",
        "/query-events/42%2ejson?limit=7",
        "/query-events/%007?limit=7",
        "/query-events/42%7fjson?limit=7",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("percent encoded path delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_defaults_and_filters() {
    let out = parse_query_normalized_audit_events_query_from_path("/query-normalized-audit-events")
        .expect("default should parse");
    assert_eq!(out.limit, QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT);
    assert!(out.source.is_none());
    assert!(out.event_type.is_none());
    assert!(out.cursor.is_none());

    let out = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=trnm.task&eventType=trnm.task.commit&limit=3&cursor=2",
    )
    .expect("explicit query should parse");
    assert_eq!(out.source.as_deref(), Some("trnm.task"));
    assert_eq!(out.event_type.as_deref(), Some("trnm.task.commit"));
    assert_eq!(out.limit, 3);
    assert_eq!(out.cursor, Some(2));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_unrelated_query_keys() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=trnm.task&foo=bar",
    )
    .expect_err("unexpected keys should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid query"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_invalid_cursor() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?cursor=bad",
    )
    .expect_err("invalid cursor should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid cursor"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_accepts_wrapped_values() {
    let out = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source='trnm.task'&eventType=`trnm.task.commit`&limit=\"3\"&cursor=  '2'  ",
    )
    .expect("wrapped values should normalize");
    assert_eq!(out.source.as_deref(), Some("trnm.task"));
    assert_eq!(out.event_type.as_deref(), Some("trnm.task.commit"));
    assert_eq!(out.limit, 3);
    assert_eq!(out.cursor, Some(2));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_raw_query_whitespace() {
    for path in [
        "/query-normalized-audit-events?source=trnm.task ",
        "/query-normalized-audit-events?eventType=trnm.task.commit\t",
        "/query-normalized-audit-events?cursor= 1",
        "/query-normalized-audit-events?limit=3 ",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("raw query whitespace must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path:?} err={err}");
        assert!(err.contains("invalid query"), "path={path:?} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_prefix_shadow_paths() {
    for path in [
        "/query-normalized-audit-events-shadow?source=trnm.task",
        "/query-normalized-audit-events.v1?source=trnm.task",
        "/query-normalized-audit-events%2fshadow?source=trnm.task",
        "/query-normalized-audit-events%01shadow?source=trnm.task",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("prefix shadow paths must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path:?} err={err}");
        assert!(err.contains("invalid query"), "path={path:?} err={err}");
    }
}

#[test]
fn parse_query_capability_audit_subject_from_target_accepts_canonical_subject_path() {
    assert_eq!(
        parse_query_capability_audit_subject_from_target("/query-capability-audit/alice")
            .expect("canonical subject path should parse"),
        "alice"
    );
    assert_eq!(
        parse_query_capability_audit_subject_from_target("/query-capability-audit/alice/")
            .expect("single operator trailing slash should normalize"),
        "alice"
    );
}

#[test]
fn parse_query_capability_audit_subject_from_target_rejects_query_string() {
    let err = parse_query_capability_audit_subject_from_target(
        "/query-capability-audit/alice?limit=1",
    )
    .expect_err("capability audit route should fail closed on query strings");
    assert_eq!(err, "invalid query");
}

#[test]
fn parse_query_capability_audit_subject_from_target_distinguishes_missing_from_malformed() {
    assert_eq!(
        parse_query_capability_audit_subject_from_target("/query-capability-audit/")
            .expect_err("empty capability route should report missing subject"),
        "missing token or subject"
    );

    for target in [
        "/query-capability-audit///",
        "/query-capability-audit/alice//",
        "/query-capability-audit/alice/nested",
    ] {
        let err = parse_query_capability_audit_subject_from_target(target)
            .expect_err("malformed capability audit path must fail closed as invalid query");
        assert_eq!(err, "invalid query", "target={target}");
    }
}

#[test]
fn parse_query_capability_audit_subject_from_target_rejects_fragments_and_whitespace() {
    for target in [
        "/query-capability-audit/alice#frag",
        "/query-capability-audit/al ice",
        "/query-capability-audit/alice\textra",
    ] {
        let err = parse_query_capability_audit_subject_from_target(target)
            .expect_err("capability audit subject must stay a clean single path segment");
        assert_eq!(err, "invalid query", "target={target}");
    }
}

#[test]
fn parse_query_capability_audit_subject_from_target_rejects_encoded_query_delimiters() {
    for target in [
        "/query-capability-audit/alice%3Flimit=1",
        "/query-capability-audit/alice%23frag",
        "/query-capability-audit/alice%26cursor=1",
    ] {
        parse_query_capability_audit_subject_from_target(target).expect_err(
            "capability audit subject must fail closed on encoded query-like delimiters",
        );
    }
}

#[test]
fn parse_query_capability_audit_subject_from_target_rejects_encoded_path_ambiguity() {
    for target in [
        "/query-capability-audit/alice%2Fextra",
        "/query-capability-audit/alice%2fextra",
        "/query-capability-audit/alice%5Cextra",
        "/query-capability-audit/alice%5cextra",
        "/query-capability-audit/%2E",
        "/query-capability-audit/%2e%2E",
    ] {
        let err = parse_query_capability_audit_subject_from_target(target).expect_err(
            "capability audit subject must stay a single clean segment after decoding",
        );
        assert_eq!(err, "invalid query", "target={target}");
    }
}

#[test]
fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
    assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("post /health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health"), None);
    assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health%00 HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health%7F HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health HTTP/1.1 junk"), None);
    assert_eq!(
        parse_http_request_target("HEAD /readyz HTTP/1.1\ttrail"),
        None
    );
}

#[test]
fn read_http_request_head_times_out_on_partial_slowloris_client() {
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let client = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client
            .write_all(b"GET /health HTTP/1.1")
            .expect("write partial request");
        thread::sleep(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS + 250));
        let _ = client.shutdown(Shutdown::Both);
    });

    let (mut server_stream, _) = listener.accept().expect("accept test client");
    configure_health_stream(&server_stream).expect("configure timeouts");
    let err =
        read_http_request_head(&mut server_stream).expect_err("partial request must time out");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));

    client.join().expect("client thread join");
}

#[test]
fn read_http_request_head_rejects_premature_eof_before_terminator() {
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let client = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
            .expect("write unterminated request head");
        let _ = client.shutdown(Shutdown::Write);
    });

    let (mut server_stream, _) = listener.accept().expect("accept test client");
    configure_health_stream(&server_stream).expect("configure timeouts");
    let err = read_http_request_head(&mut server_stream)
        .expect_err("unterminated request head must fail closed on eof");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(err.to_string().contains("ended before terminator"));

    client.join().expect("client thread join");
}

#[test]
fn read_http_request_head_rejects_oversized_header_without_terminator() {
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let oversized = vec![b'a'; HEALTH_REQUEST_HEADER_MAX_BYTES + 32];

    let client = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client
            .write_all(&oversized)
            .expect("write oversized partial request head");
        let _ = client.shutdown(Shutdown::Write);
    });

    let (mut server_stream, _) = listener.accept().expect("accept test client");
    configure_health_stream(&server_stream).expect("configure timeouts");
    let err = read_http_request_head(&mut server_stream)
        .expect_err("oversized unterminated request head must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("exceeded configured max bytes before terminator"));

    client.join().expect("client thread join");
}
