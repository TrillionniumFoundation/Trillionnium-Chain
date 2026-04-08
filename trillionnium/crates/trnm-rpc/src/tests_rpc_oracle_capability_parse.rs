use super::*;

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
fn parse_http_request_target_accepts_head_health_probe() {
    assert_eq!(
        parse_http_request_target("HEAD /readyz HTTP/1.1"),
        Some(("HEAD", "/readyz"))
    );
    assert_eq!(parse_http_get_path("HEAD /readyz HTTP/1.1"), None);
}

#[test]
fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
    assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health"), None);
    assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health HTTP/1.1 junk"), None);
    assert_eq!(
        parse_http_request_target("HEAD /readyz HTTP/1.1\ttrail"),
        None
    );
}
