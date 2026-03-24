use super::*;

pub(crate) fn http_json_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
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

pub(crate) fn parse_http_get_target(first_line: &str) -> Option<&str> {
    let line = first_line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }

    let first_sp = line.find(' ')?;
    let method = &line[..first_sp];
    if method != "GET" {
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
    if rest.is_empty() || !rest.starts_with("HTTP/") {
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

    Some(path)
}

#[cfg(test)]
pub(crate) fn parse_http_get_path(first_line: &str) -> Option<&str> {
    parse_http_get_target(first_line).map(|path| path.split('?').next().unwrap_or(path))
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
        let target = parse_http_get_target(first);
        let path = target.map(|raw| raw.split('?').next().unwrap_or(raw));

        let response = match (path, target) {
            (Some("/health"), _) => {
                let body = serde_json::json!({
                    "ok": true,
                    "service": "trnm-rpc",
                    "ts_unix_ms": now_ms(),
                    "version": 1
                })
                .to_string();
                http_json_response("200 OK", &body)
            }
            (Some(path), _) if path.starts_with("/query-task/") => {
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
                                http_json_response("200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                http_json_response("404 Not Found", &body)
                            }
                        }
                    }
                    Err(_) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        http_json_response("400 Bad Request", body)
                    }
                }
            }
            (Some(path), Some(target)) if path.starts_with("/query-events/") => {
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
                                http_json_response("200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                http_json_response("404 Not Found", &body)
                            }
                        }
                    }
                    (_, Err(err)) => err,
                    (Err(_), _) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        http_json_response("400 Bad Request", body)
                    }
                }
            }
            (Some(path), Some(target)) if path == "/query-normalized-audit-events" => {
                let query = parse_query_normalized_audit_events_query_from_path(target);
                match query {
                    Ok(query) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        let out = query_normalized_audit_events(&node_events.events, &recs, &query);
                        let body = serde_json::to_string(&out)
                            .unwrap_or_else(|_| r#"{"ok":false,"code":"SERDE_ERROR"}"#.to_string());
                        http_json_response("200 OK", &body)
                    }
                    Err(err) => err,
                }
            }

            (Some(path), _) if path.starts_with("/query-capability-audit/") => {
                let subject_or_token = path.trim_start_matches("/query-capability-audit/");
                let registry = load_identity_registry(&identity_registry_file());
                if let Some(token_id) =
                    resolve_capability_token_subject_or_token(&registry, subject_or_token)
                {
                    match query_capability_audit(&registry, token_id) {
                        Ok(out) => {
                            let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                            });
                            http_json_response("200 OK", &body)
                        }
                        Err(err) => {
                            let rpc_error = err.to_rpc_error();
                            let body = serde_json::json!({"ok": false, "code": rpc_error.code, "message": rpc_error.message}).to_string();
                            http_json_response(err.http_status(), &body)
                        }
                    }
                } else {
                    let body = "{\"ok\":false,\"code\":\"NOT_FOUND\",\"message\":\"token or subject not found\"}";
                    http_json_response("404 Not Found", body)
                }
            }
            _ => {
                let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
                http_json_response("404 Not Found", body)
            }
        };

        let _ = stream.write_all(response.as_bytes());
    }

    Ok(())
}
