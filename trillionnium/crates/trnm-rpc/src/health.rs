use anyhow::Result;
use std::{io::Write, net::TcpListener};

use crate::capability::{
    load_identity_registry, query_capability_audit, resolve_capability_token_subject_or_token,
};
use crate::envpaths::identity_registry_file;
use crate::http::{
    configure_health_stream, http_json_head_response, http_json_response,
    http_response_for_method, parse_http_request_target, parse_query_events_limit_from_path,
    read_http_request_head,
};
use crate::node_events::load_node_events;
use crate::runtime::now_ms;
use crate::snapshot::load_latest_adapter_records;
use crate::taskview::{query_events_response, query_task_response};
use crate::NodeEventScanMode;

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
        .filter(|suffix| !suffix.contains(['#', '?']))
        .filter(|suffix| !suffix.chars().any(|ch| ch.is_control() || ch.is_whitespace()))
        // Capability subjects/tokens are single path segments. Reject extra
        // slash-delimited segments so malformed operator paths fail closed
        // instead of being misread as an opaque identifier.
        .filter(|suffix| !suffix.contains('/'))
        // Treat raw backslashes as ambiguous path separators too so
        // slash-like operator paths fail closed even before decoding.
        .filter(|suffix| !suffix.contains('\\'))
        // Also reject encoded slash-like separators so ambiguous operator
        // paths are not silently accepted as opaque identifiers.
        .filter(|suffix| !has_ambiguous_path_segment_encoding(suffix))
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
            _ => fallback_response_for_request(request),
        };

        let _ = stream.write_all(response.as_bytes());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        fallback_response_for_request, has_ambiguous_path_segment_encoding, health_probe_body,
        is_health_probe_path, json_response_for_method, parse_nonempty_path_suffix,
        parse_path_u64_suffix,
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
        assert!(!is_health_probe_path("/-/statuscheck"));
        assert!(!is_health_probe_path("/-/statusz//"));
        assert!(!is_health_probe_path("/-/readyz/extra"));
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
            parse_http_request_target("HEAD /-/readyz/?probe=lb&from=ops HTTP/1.1"),
            Some(("HEAD", "/-/readyz/?probe=lb&from=ops"))
        );
    }

    #[test]
    fn query_string_is_ignored_for_health_probe_alias_matching() {
        let request = parse_http_request_target("HEAD /-/STATUSZ/?from=ops HTTP/1.1").unwrap();
        let path = request.1.split('?').next().unwrap();

        assert!(is_health_probe_path(path));

        let response = if is_health_probe_path(path) {
            json_response_for_method(request.0, "200 OK", &health_probe_body(42))
        } else {
            unreachable!("health alias with query string should match after path split")
        };

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.contains("\"ok\":true"));
    }

    #[test]
    fn trailing_slash_health_alias_with_query_keeps_same_head_contract() {
        let request = parse_http_request_target("HEAD /-/statusz/?from=ops HTTP/1.1").unwrap();
        let path = request.1.split('?').next().unwrap();

        assert_eq!(path, "/-/statusz/");
        assert!(is_health_probe_path(path));

        let response = json_response_for_method(request.0, "200 OK", &health_probe_body(42));

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 50\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.ends_with("\"version\":1}"));
    }

    #[test]
    fn json_response_for_method_uses_head_headers_without_body() {
        let get = json_response_for_method("GET", "200 OK", "{\"ok\":true}");
        assert!(get.ends_with("{\"ok\":true}"));

        let head = json_response_for_method("HEAD", "200 OK", "{\"ok\":true}");
        assert!(head.ends_with("\r\n\r\n"));
        assert!(!head.ends_with("{\"ok\":true}"));
        assert!(head.contains("Content-Length: 11\r\n"));

        let lowercase_head = json_response_for_method("head", "200 OK", "{\"ok\":true}");
        assert!(lowercase_head.ends_with("\r\n\r\n"));
        assert!(!lowercase_head.ends_with("{\"ok\":true}"));
        assert!(lowercase_head.contains("Content-Length: 11\r\n"));
    }

    #[test]
    fn json_response_for_method_preserves_head_semantics_for_error_paths() {
        let not_found = json_response_for_method("HEAD", "404 Not Found", "{\"ok\":false}");
        assert!(not_found.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(not_found.ends_with("\r\n\r\n"));
        assert!(!not_found.ends_with("{\"ok\":false}"));
        assert!(not_found.contains("Content-Length: 12\r\n"));

        let bad_request =
            json_response_for_method("HEAD", "400 Bad Request", "{\"ok\":false,\"code\":\"BAD_REQUEST\"}");
        assert!(bad_request.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(bad_request.ends_with("\r\n\r\n"));
        assert!(!bad_request.ends_with("BAD_REQUEST\"}"));
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
    fn parse_path_u64_suffix_accepts_operator_trailing_slash() {
        assert_eq!(parse_path_u64_suffix("/query-task/42", "/query-task/"), Some("42"));
        assert_eq!(parse_path_u64_suffix("/query-task/42/", "/query-task/"), Some("42"));
        assert_eq!(
            parse_path_u64_suffix("/query-events/42/", "/query-events/"),
            Some("42")
        );
        assert_eq!(parse_path_u64_suffix("/query-task/", "/query-task/"), None);
        assert_eq!(parse_path_u64_suffix("/query-task///", "/query-task/"), None);
        assert_eq!(parse_path_u64_suffix("/query-task/42//", "/query-task/"), None);
        assert_eq!(
            parse_path_u64_suffix("/query-task/42/extra", "/query-task/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/42/history", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-task/42\\extra", "/query-task/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/42%2Fhistory", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/42%5Chistory", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/42%2fhistory", "/query-events/"),
            None
        );
        assert_eq!(
            parse_path_u64_suffix("/query-events/42%5chistory", "/query-events/"),
            None
        );
        assert_eq!(parse_path_u64_suffix("/query-events/.", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/..", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2E", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/.%2e", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2E.", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/%2e%2E", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/42%0A", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/42%0d", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/42%09", "/query-events/"), None);
        assert_eq!(parse_path_u64_suffix("/query-events/42%20", "/query-events/"), None);
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
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice//",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice/extra",
                "/query-capability-audit/"
            ),
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
                "/query-capability-audit/alice\\extra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/.", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/..", "/query-capability-audit/"),
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
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice#frag",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice?extra=1",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/al ice",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%3Fextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%23frag",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%0Aadmin",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%0dadmin",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%09admin",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%20admin",
                "/query-capability-audit/"
            ),
            None
        );
    }

    #[test]
    fn percent_encoded_control_or_space_is_treated_as_ambiguous_path_input() {
        assert!(contains_percent_encoded_control_or_space("alice%0Aadmin"));
        assert!(contains_percent_encoded_control_or_space("alice%0dadmin"));
        assert!(contains_percent_encoded_control_or_space("alice%09admin"));
        assert!(contains_percent_encoded_control_or_space("alice%20admin"));
        assert!(contains_percent_encoded_control_or_space("alice%7fadmin"));
        assert!(!contains_percent_encoded_control_or_space("did:trn:alice"));
    }

    #[test]
    fn ambiguous_path_segment_encoding_rejects_encoded_slashes_and_dot_segments() {
        assert!(has_ambiguous_path_segment_encoding("alice%2Fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%2fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5Cextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5cextra"));
        assert!(has_ambiguous_path_segment_encoding("%2E"));
        assert!(has_ambiguous_path_segment_encoding(".%2e"));
        assert!(has_ambiguous_path_segment_encoding("%2E."));
        assert!(has_ambiguous_path_segment_encoding("%2e%2E"));
        assert!(has_ambiguous_path_segment_encoding("alice%3Fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%23frag"));
        assert!(has_ambiguous_path_segment_encoding("."));
        assert!(has_ambiguous_path_segment_encoding(".."));
        assert!(!has_ambiguous_path_segment_encoding("did:trn:alice"));
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
