use super::*;
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
fn parse_http_get_path_accepts_canonical_request_line() {
    assert_eq!(
        parse_http_get_path("GET /query-task/42?verbose=1 HTTP/1.1"),
        Some("/query-task/42")
    );
    assert_eq!(
            parse_http_get_target("GET /oracle/validate_snapshot?snapshot=%2Ftmp%2Fs.json&policy=%2Ftmp%2Fp.json HTTP/1.1"),
            Some("/oracle/validate_snapshot?snapshot=%2Ftmp%2Fs.json&policy=%2Ftmp%2Fp.json")
        );
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
