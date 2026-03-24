pub(crate) use super::*;

#[test]
fn parse_http_get_path_accepts_canonical_request_line() {
    assert_eq!(
        parse_http_get_path("GET /query-task/42?verbose=1 HTTP/1.1"),
        Some("/query-task/42")
    );
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
fn parse_query_events_limit_from_path_rejects_percent_encoded_path_smuggling() {
    for path in [
        "/query-events%2f42?limit=7",
        "/query-events/..%2f42?limit=7",
        "/query-events/%2e%2e/42?limit=7",
        "/query-events/42%2ejson?limit=7",
    ] {
        let err = parse_query_events_limit_from_path(path)
            .expect_err("percent encoded path delimiters must fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid limit"), "path={path} err={err}");
    }
}

#[test]
fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
    assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health"), None);
    assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
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
