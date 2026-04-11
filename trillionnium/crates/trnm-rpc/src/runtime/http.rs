use super::*;

fn is_health_probe_path(path: &str) -> bool {
    [
        "/health",
        "/health/",
        "/healthz",
        "/healthz/",
        "/live",
        "/live/",
        "/livez",
        "/livez/",
        "/ready",
        "/ready/",
        "/readyz",
        "/readyz/",
        "/status",
        "/status/",
        "/statusz",
        "/statusz/",
        "/-/health",
        "/-/health/",
        "/-/healthz",
        "/-/healthz/",
        "/-/live",
        "/-/live/",
        "/-/livez",
        "/-/livez/",
        "/-/ready",
        "/-/ready/",
        "/-/readyz",
        "/-/readyz/",
        "/-/status",
        "/-/status/",
        "/-/statusz",
        "/-/statusz/",
    ]
    .iter()
    .any(|alias| path.eq_ignore_ascii_case(alias))
}

fn is_supported_http_version(version: &str) -> bool {
    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn contains_malformed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return true;
            }
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if hi.is_none() || lo.is_none() {
                return true;
            }
            idx += 3;
            continue;
        }
        idx += 1;
    }
    false
}

fn contains_percent_encoded_control_or_space(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx + 2 < bytes.len() {
        if bytes[idx] == b'%' {
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let decoded = ((hi << 4) | lo) as u8;
                if decoded <= 0x20 || decoded == 0x7f {
                    return true;
                }
            }
        }
        idx += 1;
    }
    false
}

pub(crate) fn http_json_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

pub(crate) fn http_json_head_response(status_line: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    )
}

pub(crate) fn configure_health_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(HEALTH_SOCKET_WRITE_TIMEOUT_MS)))?;
    Ok(())
}

fn has_complete_http_head(buf: &[u8]) -> bool {
    buf.windows(4).any(|window| window == b"\r\n\r\n")
        || buf.windows(2).any(|window| window == b"\n\n")
}

pub(crate) fn read_http_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    while buf.len() < HEALTH_REQUEST_HEADER_MAX_BYTES {
        let remaining = HEALTH_REQUEST_HEADER_MAX_BYTES - buf.len();
        let to_read = remaining.min(chunk.len());
        let n = stream.read(&mut chunk[..to_read])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if has_complete_http_head(&buf) {
            return Ok(buf);
        }
    }

    if buf.len() >= HEALTH_REQUEST_HEADER_MAX_BYTES && !has_complete_http_head(&buf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "http request header exceeded configured max bytes before terminator",
        ));
    }

    if !buf.is_empty() && !has_complete_http_head(&buf) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "http request header ended before terminator",
        ));
    }

    Ok(buf)
}

pub(crate) fn parse_http_request_target(first_line: &str) -> Option<(&str, &str)> {
    let line = first_line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }

    let first_sp = line.find(' ')?;
    let method = &line[..first_sp];
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }

    let mut rest = line[first_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return None;
    }

    let second_sp = rest.find(' ')?;
    let path = &rest[..second_sp];
    if !path.starts_with('/') {
        return None;
    }
    rest = rest[second_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() || rest.contains([' ', '\t']) || !is_supported_http_version(rest) {
        return None;
    }

    let normalized = path.to_ascii_lowercase();
    if path.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return None;
    }
    if path.contains('\\') || normalized.contains("%5c") {
        return None;
    }
    if path.contains('#') || normalized.contains("%23") {
        return None;
    }
    if contains_malformed_percent_encoding(path) || contains_percent_encoded_control_or_space(path)
    {
        return None;
    }

    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    if normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }

    Some((method, path))
}

pub(crate) fn parse_http_get_target(first_line: &str) -> Option<&str> {
    match parse_http_request_target(first_line) {
        Some((method, path)) if method.eq_ignore_ascii_case("GET") => Some(path),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn parse_http_get_path(first_line: &str) -> Option<&str> {
    parse_http_get_target(first_line).map(|path| path.split('?').next().unwrap_or(path))
}

fn json_response_for_method(method: &str, status_line: &str, body: &str) -> String {
    if method.eq_ignore_ascii_case("HEAD") {
        http_json_head_response(status_line, body.len())
    } else {
        http_json_response(status_line, body)
    }
}

fn health_probe_body(ts_unix_ms: u64) -> String {
    serde_json::json!({
        "ok": true,
        "service": "trnm-rpc",
        "ts_unix_ms": ts_unix_ms,
        "version": 1
    })
    .to_string()
}

fn fallback_response_for_request(request: Option<(&str, &str)>) -> String {
    match request {
        Some((method, _)) => {
            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
            json_response_for_method(method, "404 Not Found", body)
        }
        None => {
            let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid http request\"}";
            http_json_response("400 Bad Request", body)
        }
    }
}

fn has_ambiguous_path_segment_encoding(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || contains_percent_encoded_control_or_space(&lower)
        || is_encoded_dot_segment(&lower)
}

fn contains_percent_encoded_control_or_space(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let mut idx = 0;
    while idx + 2 < bytes.len() {
        if bytes[idx] == b'%' {
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let decoded = ((hi << 4) | lo) as u8;
                if decoded <= 0x20 || decoded == 0x7f {
                    return true;
                }
            }
        }
        idx += 1;
    }
    false
}

fn is_encoded_dot_segment(segment: &str) -> bool {
    matches!(segment, "." | ".." | "%2e" | ".%2e" | "%2e." | "%2e%2e")
}

fn parse_path_u64_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix)
        .and_then(|suffix| {
            if suffix.is_empty() {
                return None;
            }
            let trimmed = suffix.trim_end_matches('/');
            let trailing_slashes = suffix.len().saturating_sub(trimmed.len());
            if trailing_slashes > 1 {
                return None;
            }
            Some(trimmed)
        })
        .filter(|suffix| !suffix.is_empty())
        // Task/event lookups accept only a single decimal id path segment.
        // Reject raw or encoded slash-like separators so malformed operator
        // paths fail closed before numeric parsing.
        .filter(|suffix| !suffix.contains('/'))
        .filter(|suffix| !suffix.contains('\\'))
        .filter(|suffix| !has_ambiguous_path_segment_encoding(suffix))
}

fn parse_nonempty_path_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix)
        .and_then(|suffix| {
            if suffix.is_empty() {
                return None;
            }
            let trimmed = suffix.trim_end_matches('/');
            let trailing_slashes = suffix.len().saturating_sub(trimmed.len());
            if trailing_slashes > 1 {
                return None;
            }
            Some(trimmed)
        })
        .filter(|suffix| !suffix.is_empty())
        .filter(|suffix| !matches!(*suffix, "." | ".."))
        .filter(|suffix| !suffix.contains(['#', '?']))
        .filter(|suffix| !suffix.chars().any(|ch| ch.is_control() || ch.is_whitespace()))
        // Capability subjects/tokens are single path segments. Reject extra
        // slash-delimited segments so malformed operator paths fail closed
        // instead of being misread as an opaque identifier.
        .filter(|suffix| !suffix.contains('/'))
        .filter(|suffix| !suffix.contains('\\'))
        .filter(|suffix| !has_ambiguous_path_segment_encoding(suffix))
}

fn parse_query_capability_audit_subject_from_target<'a>(
    target: &'a str,
) -> std::result::Result<&'a str, &'static str> {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };

    if query.is_some() {
        return Err("invalid query");
    }

    match parse_nonempty_path_suffix(path, "/query-capability-audit/") {
        Some(subject) => Ok(subject),
        None if path == "/query-capability-audit" || path == "/query-capability-audit/" => {
            Err("missing token or subject")
        }
        None if path.starts_with("/query-capability-audit/") => Err("invalid query"),
        None => Err("missing token or subject"),
    }
}

pub(crate) fn serve_health(host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    eprintln!("[trnm-rpc] service listening on http://{addr}");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if configure_health_stream(&stream).is_err() {
            continue;
        }

        let req = match read_http_request_head(&mut stream) {
            Ok(req) => req,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => continue,
        };
        if req.is_empty() {
            continue;
        }
        let req = String::from_utf8_lossy(&req);
        let first = req.lines().next().unwrap_or("");
        let request = parse_http_request_target(first);
        let target = request.map(|(_, raw)| raw);
        let path = request.map(|(_, raw)| raw.split('?').next().unwrap_or(raw));

        let response = match (request, path, target) {
            (Some((method, _)), Some(path), _) if is_health_probe_path(path) => {
                let body = health_probe_body(now_ms());
                json_response_for_method(method, "200 OK", &body)
            }
            (Some((method, _)), Some(path), Some(_)) if path.starts_with("/query-task/") => {
                let task_id = parse_path_u64_suffix(path, "/query-task/")
                    .ok_or(())
                    .and_then(|suffix| suffix.parse::<u64>().map_err(|_| ()));
                match task_id {
                    Ok(task_id) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        match query_task_response(task_id, &node_events.events, &recs) {
                            Ok(out) => {
                                let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                    "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                });
                                json_response_for_method(method, "200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                json_response_for_method(method, "404 Not Found", &body)
                            }
                        }
                    }
                    Err(_) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            (Some((method, _)), Some(path), Some(target)) if path.starts_with("/query-events/") => {
                let task_id = parse_path_u64_suffix(path, "/query-events/")
                    .ok_or(())
                    .and_then(|suffix| suffix.parse::<u64>().map_err(|_| ()));
                let limit = parse_query_events_limit_from_path(target);
                match (task_id, limit) {
                    (Ok(task_id), Ok(limit)) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        match query_events_response(task_id, limit, &node_events.events, &recs) {
                            Ok(events) => {
                                let body = serde_json::to_string(&events).unwrap_or_else(|_| {
                                    "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                });
                                json_response_for_method(method, "200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                json_response_for_method(method, "404 Not Found", &body)
                            }
                        }
                    }
                    (_, Err(err)) => http_response_for_method(method, &err),
                    (Err(_), _) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            (Some((method, _)), Some(path), Some(target)) if path == "/query-normalized-audit-events" => {
                let query = parse_query_normalized_audit_events_query_from_path(target);
                match query {
                    Ok(query) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        let out = query_normalized_audit_events(&node_events.events, &recs, &query);
                        let body = serde_json::to_string(&out)
                            .unwrap_or_else(|_| r#"{"ok":false,"code":"SERDE_ERROR"}"#.to_string());
                        json_response_for_method(method, "200 OK", &body)
                    }
                    Err(err) => err,
                }
            }

            (Some((method, _)), Some(path), Some(target)) if path.starts_with("/query-capability-audit/") => {
                match parse_query_capability_audit_subject_from_target(target) {
                    Ok(subject_or_token) => {
                        let registry = load_identity_registry(&identity_registry_file());
                        if let Some(token_id) =
                            resolve_capability_token_subject_or_token(&registry, subject_or_token)
                        {
                            match query_capability_audit(&registry, token_id) {
                                Ok(out) => {
                                    let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                        "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                    });
                                    json_response_for_method(method, "200 OK", &body)
                                }
                                Err(err) => {
                                    let rpc_error = err.to_rpc_error();
                                    let body = serde_json::json!({
                                        "ok": false,
                                        "code": rpc_error.code,
                                        "message": rpc_error.message
                                    })
                                    .to_string();
                                    json_response_for_method(method, err.http_status(), &body)
                                }
                            }
                        } else {
                            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\",\"message\":\"token or subject not found\"}";
                            json_response_for_method(method, "404 Not Found", body)
                        }
                    }
                    Err("invalid query") => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid query\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                    Err(_) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"missing token or subject\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            _ => fallback_response_for_request(request)
        };

        let _ = stream.write_all(response.as_bytes());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        configure_health_stream, health_probe_body, http_json_head_response, http_json_response,
        is_health_probe_path, json_response_for_method, parse_nonempty_path_suffix,
        parse_path_u64_suffix, read_http_request_head, HEALTH_REQUEST_HEADER_MAX_BYTES,
    };
    use std::io::Write;


    #[test]
    fn accepts_health_probe_aliases() {
        assert!(is_health_probe_path("/health"));
        assert!(is_health_probe_path("/health/"));
        assert!(is_health_probe_path("/healthz"));
        assert!(is_health_probe_path("/healthz/"));
        assert!(is_health_probe_path("/live"));
        assert!(is_health_probe_path("/live/"));
        assert!(is_health_probe_path("/livez"));
        assert!(is_health_probe_path("/livez/"));
        assert!(is_health_probe_path("/ready"));
        assert!(is_health_probe_path("/ready/"));
        assert!(is_health_probe_path("/readyz"));
        assert!(is_health_probe_path("/readyz/"));
        assert!(is_health_probe_path("/status"));
        assert!(is_health_probe_path("/status/"));
        assert!(is_health_probe_path("/statusz"));
        assert!(is_health_probe_path("/statusz/"));
        assert!(is_health_probe_path("/HEALTHZ"));
        assert!(is_health_probe_path("/LIVE"));
        assert!(is_health_probe_path("/Ready/"));
        assert!(is_health_probe_path("/ReadyZ/"));
        assert!(is_health_probe_path("/STATUS"));
        assert!(is_health_probe_path("/STATUSZ"));
        assert!(is_health_probe_path("/-/health"));
        assert!(is_health_probe_path("/-/health/"));
        assert!(is_health_probe_path("/-/healthz"));
        assert!(is_health_probe_path("/-/healthz/"));
        assert!(is_health_probe_path("/-/live"));
        assert!(is_health_probe_path("/-/live/"));
        assert!(is_health_probe_path("/-/livez"));
        assert!(is_health_probe_path("/-/livez/"));
        assert!(is_health_probe_path("/-/ready"));
        assert!(is_health_probe_path("/-/ready/"));
        assert!(is_health_probe_path("/-/readyz"));
        assert!(is_health_probe_path("/-/readyz/"));
        assert!(is_health_probe_path("/-/status"));
        assert!(is_health_probe_path("/-/status/"));
        assert!(is_health_probe_path("/-/statusz"));
        assert!(is_health_probe_path("/-/statusz/"));
        assert!(is_health_probe_path("/-/STATUS"));
        assert!(is_health_probe_path("/-/STATUSZ/"));
        assert!(!is_health_probe_path("/healthcheck"));
        assert!(!is_health_probe_path("/-/healthcheck"));
        assert!(!is_health_probe_path("/-/readycheck"));
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
    fn parse_http_request_target_preserves_query_string_for_health_probe_aliases() {
        assert_eq!(
            parse_http_request_target("GET /healthz?probe=lb HTTP/1.1"),
            Some(("GET", "/healthz?probe=lb"))
        );
        assert_eq!(
            parse_http_request_target("HEAD /-/STATUSZ/?from=ops HTTP/1.1"),
            Some(("HEAD", "/-/STATUSZ/?from=ops"))
        );
        assert_eq!(
            parse_http_get_path("GET /-/ready?verbose=1 HTTP/1.1"),
            Some("/-/ready")
        );
    }

    #[test]
    fn query_string_is_ignored_for_health_probe_alias_matching() {
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
    fn trailing_slash_health_alias_with_query_keeps_same_head_contract() {
        let request = parse_http_request_target("HEAD /-/statusz/?from=ops HTTP/1.1")
            .expect("health alias request parses");
        let path = request.1.split('?').next().expect("path before query");
        assert_eq!(path, "/-/statusz/");
        assert!(is_health_probe_path(path));

        let response = json_response_for_method(request.0, "200 OK", &health_probe_body(42));

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 50\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.ends_with("\"version\":1}"));
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
    fn json_response_for_method_preserves_head_semantics_for_error_paths() {
        let not_found = json_response_for_method("HEAD", "404 Not Found", "{\"ok\":false}");
        assert!(not_found.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(not_found.ends_with("\r\n\r\n"));
        assert!(!not_found.ends_with("{\"ok\":false}"));
        assert!(not_found.contains("Cache-Control: no-store\r\n"));
        assert!(not_found.contains("Content-Length: 12\r\n"));

        let bad_request =
            json_response_for_method("HEAD", "400 Bad Request", "{\"ok\":false,\"code\":\"BAD_REQUEST\"}");
        assert!(bad_request.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(bad_request.ends_with("\r\n\r\n"));
        assert!(!bad_request.ends_with("BAD_REQUEST\"}"));
    }

    #[test]
    fn http_json_responses_disable_caching_for_operator_probes() {
        let get = http_json_response("200 OK", "{\"ok\":true}");
        assert!(get.contains("\r\nCache-Control: no-store\r\n"));

        let head = http_json_head_response("200 OK", 11);
        assert!(head.contains("\r\nCache-Control: no-store\r\n"));
    }

    #[test]
    fn health_probe_body_keeps_minimum_operator_contract_fields_stable() {
        let body = health_probe_body(42);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json.get("ok"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(json.get("service"), Some(&serde_json::Value::String("trnm-rpc".into())));
        assert_eq!(json.get("ts_unix_ms"), Some(&serde_json::Value::from(42u64)));
        assert_eq!(json.get("version"), Some(&serde_json::Value::from(1)));
        assert_eq!(json.as_object().map(|obj| obj.len()), Some(4));
    }

    #[test]
    fn parse_path_u64_suffix_rejects_nested_operator_suffixes() {
        assert_eq!(parse_path_u64_suffix("/query-task/42", "/query-task/"), Some("42"));
        assert_eq!(parse_path_u64_suffix("/query-task/42/", "/query-task/"), Some("42"));
        assert_eq!(
            parse_path_u64_suffix("/query-events/7/", "/query-events/"),
            Some("7")
        );
        assert_eq!(parse_path_u64_suffix("/query-task/", "/query-task/"), None);
        assert_eq!(parse_path_u64_suffix("/query-task///", "/query-task/"), None);
        assert_eq!(parse_path_u64_suffix("/query-task/42//", "/query-task/"), None);
        assert_eq!(
            parse_path_u64_suffix("/query-task/42/extra", "/query-task/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/7/history", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-task/42\\extra", "/query-task/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/7%2Fhistory", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/7%5Chistory", "/query-events/"),
            None
        );
        assert_eq!(parse_path_u64_suffix("/query-events/.", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/..", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2E", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/.%2e", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2E.", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2e%2E", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/7%0A", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/7%0d", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/7%09", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/7%20", "/query-events/"), None);
    }

    #[test]
    fn parse_nonempty_path_suffix_rejects_empty_capability_subject() {
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/alice", "/query-capability-audit/"),
            Some("alice")
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/alice/", "/query-capability-audit/"),
            Some("alice")
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice/nested",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit///", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/alice//", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%2Fextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%2fextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%5Cextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%5cextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice\\extra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/%2E",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/.%2e",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/%2E.",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/%2e%2E",
                "/query-capability-audit/"
            ),
            None
        );
    }

    #[test]
    fn ambiguous_path_segment_encoding_detects_encoded_separators_and_dot_segments() {
        assert!(has_ambiguous_path_segment_encoding("alice%2Fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%2fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5Cextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5cextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%3Fprobe"));
        assert!(has_ambiguous_path_segment_encoding("alice%23fragment"));
        assert!(has_ambiguous_path_segment_encoding("alice%0Alog"));
        assert!(has_ambiguous_path_segment_encoding("alice%0dlog"));
        assert!(has_ambiguous_path_segment_encoding("alice%09log"));
        assert!(has_ambiguous_path_segment_encoding("alice%20log"));
        assert!(has_ambiguous_path_segment_encoding("%2E"));
        assert!(has_ambiguous_path_segment_encoding(".%2e"));
        assert!(has_ambiguous_path_segment_encoding("%2E."));
        assert!(has_ambiguous_path_segment_encoding("%2e%2E"));
        assert!(has_ambiguous_path_segment_encoding("."));
        assert!(has_ambiguous_path_segment_encoding(".."));
        assert!(!has_ambiguous_path_segment_encoding("did:trn:alice"));
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

    #[test]
    fn fallback_response_returns_400_for_malformed_http_request() {
        let response = fallback_response_for_request(None);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(response.ends_with("{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid http request\"}"));
    }

    #[test]
    fn fallback_response_preserves_404_for_unknown_valid_path() {
        let response = fallback_response_for_request(Some(("HEAD", "/unknown")));
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.ends_with("NOT_FOUND\"}"));
    }
}
