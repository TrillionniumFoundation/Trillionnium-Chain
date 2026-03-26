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
    ]
    .iter()
    .any(|alias| path.eq_ignore_ascii_case(alias))
}

fn is_supported_http_version(version: &str) -> bool {
    matches!(version, "HTTP/1.0" | "HTTP/1.1")
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
        if buf.windows(4).any(|window| window == b"\r\n\r\n")
            || buf.windows(2).any(|window| window == b"\n\n")
        {
            break;
        }
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
    if method != "GET" && method != "HEAD" {
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
    if path.contains('\\') || normalized.contains("%5c") {
        return None;
    }
    if path.contains('#') || normalized.contains("%23") {
        return None;
    }
    if normalized.contains("%0d")
        || normalized.contains("%0a")
        || normalized.contains("%09")
        || normalized.contains("%0b")
        || normalized.contains("%0c")
        || normalized.contains("%20")
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
        Some(("GET", path)) => Some(path),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn parse_http_get_path(first_line: &str) -> Option<&str> {
    parse_http_get_target(first_line).map(|path| path.split('?').next().unwrap_or(path))
}

fn json_response_for_method(method: &str, status_line: &str, body: &str) -> String {
    if method == "HEAD" {
        http_json_head_response(status_line, body.len())
    } else {
        http_json_response(status_line, body)
    }
}

fn parse_nonempty_path_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix)
        .map(|suffix| suffix.trim_end_matches('/'))
        .filter(|suffix| !suffix.is_empty())
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
        let req = String::from_utf8_lossy(&req);
        let first = req.lines().next().unwrap_or("");
        let request = parse_http_request_target(first);
        let target = request.map(|(_, raw)| raw);
        let path = request.map(|(_, raw)| raw.split('?').next().unwrap_or(raw));

        let response = match (request, path, target) {
            (Some((method, _)), Some(path), _) if is_health_probe_path(path) => {
                let body = serde_json::json!({
                    "ok": true,
                    "service": "trnm-rpc",
                    "ts_unix_ms": now_ms(),
                    "version": 1
                })
                .to_string();
                json_response_for_method(method, "200 OK", &body)
            }
            (Some((method, _)), Some(path), Some(_)) if path.starts_with("/query-task/") => {
                let task_id = path.trim_start_matches("/query-task/").parse::<u64>();
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
                let task_id = path.trim_start_matches("/query-events/").parse::<u64>();
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

            (Some((method, _)), Some(path), Some(_)) if path.starts_with("/query-capability-audit/") => {
                match parse_nonempty_path_suffix(path, "/query-capability-audit/") {
                    Some(subject_or_token) => {
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
                                    let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_rpc_error().message}).to_string();
                                    json_response_for_method(method, "404 Not Found", &body)
                                }
                            }
                        } else {
                            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\",\"message\":\"token or subject not found\"}";
                            json_response_for_method(method, "404 Not Found", body)
                        }
                    }
                    None => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"missing token or subject\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            _ => {
                let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
                match request {
                    Some((method, _)) => json_response_for_method(method, "404 Not Found", body),
                    None => http_json_response("404 Not Found", body),
                }
            }
        };

        let _ = stream.write_all(response.as_bytes());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        http_json_head_response, http_json_response, is_health_probe_path,
        json_response_for_method, parse_nonempty_path_suffix,
    };

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
        assert!(!is_health_probe_path("/healthcheck"));
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
            parse_nonempty_path_suffix("/query-capability-audit/", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit///", "/query-capability-audit/"),
            None
        );
    }
}
