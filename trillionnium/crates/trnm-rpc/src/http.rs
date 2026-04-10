use std::{io::Read, net::TcpStream, time::Duration};

use crate::envpaths::normalize_wrapped_env_value;
use crate::rpc_util::clamp_limit;
use crate::{
    HEALTH_REQUEST_HEADER_MAX_BYTES, HEALTH_SOCKET_READ_TIMEOUT_MS, HEALTH_SOCKET_WRITE_TIMEOUT_MS,
    QUERY_EVENTS_LIMIT_DEFAULT, QUERY_EVENTS_LIMIT_MAX,
};

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

pub(crate) fn http_response_for_method(method: &str, response: &str) -> String {
    if !method.eq_ignore_ascii_case("HEAD") {
        return response.to_string();
    }

    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return response.to_string();
    };

    let mut rebuilt = String::new();
    for (idx, line) in headers.split("\r\n").enumerate() {
        if idx > 0 && line.to_ascii_lowercase().starts_with("content-length:") {
            rebuilt.push_str(&format!("Content-Length: {}\r\n", body.len()));
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str("\r\n");
    rebuilt
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
    if path.matches('?').count() > 1 {
        return None;
    }
    if path.contains('\\') || normalized.contains("%5c") {
        return None;
    }
    if path.contains('#') || normalized.contains("%23") {
        return None;
    }
    if normalized.contains("%3f") {
        return None;
    }
    if contains_malformed_percent_encoding(path) || contains_percent_encoded_control_or_space(path) {
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

pub(crate) fn parse_query_events_limit_from_path(path: &str) -> std::result::Result<usize, String> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    if !path_without_query.starts_with('/')
        || path_without_query.contains('\\')
        || path_without_query.contains('#')
        || path_without_query.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || normalized_path.contains("%5c")
        || normalized_path.contains("%23")
        || normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || contains_malformed_percent_encoding(path_without_query)
        || contains_percent_encoded_control_or_space(path_without_query)
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }

    let Some(query) = path.split_once('?').map(|(_, query)| query) else {
        return Ok(QUERY_EVENTS_LIMIT_DEFAULT);
    };

    if query.is_empty()
        || query.contains('?')
        || query.contains('#')
        || query.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }
    let normalized_query = query.to_ascii_lowercase();
    if normalized_query.contains("%26")
        || normalized_query.contains("%3d")
        || normalized_query.contains("%23")
        || normalized_query.contains("%3f")
        || contains_malformed_percent_encoding(query)
        || contains_percent_encoded_control_or_space(query)
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }

    let mut parsed_limit: Option<usize> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        };
        let normalized_key = normalize_wrapped_env_value(key);
        if !normalized_key.eq_ignore_ascii_case("limit") || key != "limit" {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }
        if parsed_limit.is_some() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"duplicate limit\"}",
            ));
        }

        let normalized = normalize_wrapped_env_value(value);
        if normalized.is_empty() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }

        let requested = normalized.parse::<usize>().map_err(|_| {
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            )
        })?;
        parsed_limit = Some(clamp_limit(
            "QueryEventsHttp",
            requested,
            QUERY_EVENTS_LIMIT_DEFAULT,
            QUERY_EVENTS_LIMIT_MAX,
        ));
    }

    Ok(parsed_limit.unwrap_or(QUERY_EVENTS_LIMIT_DEFAULT))
}

#[cfg(test)]
mod tests {
    use super::{
        contains_malformed_percent_encoding, contains_percent_encoded_control_or_space,
        http_json_response, http_response_for_method, parse_http_request_target,
        parse_query_events_limit_from_path,
    };

    #[test]
    fn http_response_for_method_preserves_get_error_bodies() {
        let response =
            http_json_response("400 Bad Request", "{\"ok\":false,\"code\":\"BAD_REQUEST\"}");
        assert_eq!(http_response_for_method("GET", &response), response);
    }

    #[test]
    fn http_response_for_method_strips_head_error_bodies() {
        let response =
            http_json_response("400 Bad Request", "{\"ok\":false,\"code\":\"BAD_REQUEST\"}");
        let head = http_response_for_method("HEAD", &response);
        assert!(head.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(!head.ends_with("BAD_REQUEST\"}"));
        assert!(head.contains("Content-Length: 33\r\n"));
        assert!(head.contains("Content-Type: application/json\r\n"));
    }

    #[test]
    fn http_response_for_method_treats_lowercase_head_as_head() {
        let response =
            http_json_response("404 Not Found", "{\"ok\":false,\"code\":\"NOT_FOUND\"}");
        let head = http_response_for_method("head", &response);
        assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(!head.ends_with("NOT_FOUND\"}"));
        assert!(head.contains("Content-Length: 30\r\n"));
    }

    #[test]
    fn http_response_for_method_preserves_non_json_head_headers() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n",
            "Cache-Control: no-store\r\n",
            "Content-Length: 4\r\n",
            "Connection: close\r\n\r\n",
            "pong"
        );
        let head = http_response_for_method("HEAD", response);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(!head.ends_with("pong"));
        assert!(head.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"));
        assert!(head.contains("Cache-Control: no-store\r\n"));
        assert!(head.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn malformed_percent_encoding_is_rejected_fail_closed() {
        assert!(contains_malformed_percent_encoding("/health%"));
        assert!(contains_malformed_percent_encoding("/health%2"));
        assert!(contains_malformed_percent_encoding("/health%zz"));
        assert!(contains_malformed_percent_encoding("/query-events/42?limit=7%4x"));
        assert!(!contains_malformed_percent_encoding("/oracle?snapshot=%2Ftmp%2Fs.json"));
        assert!(!contains_malformed_percent_encoding("/query-events/42?limit=7"));
    }

    #[test]
    fn encoded_c0_controls_and_space_are_rejected_case_insensitively() {
        assert!(contains_percent_encoded_control_or_space("/health%01check"));
        assert!(contains_percent_encoded_control_or_space("/health%1fcheck"));
        assert!(contains_percent_encoded_control_or_space("/health%20check"));
        assert!(contains_percent_encoded_control_or_space("/health%7Fcheck"));
        assert!(!contains_percent_encoded_control_or_space("/oracle?snapshot=%2Ftmp%2Fs.json"));
    }

    #[test]
    fn parse_http_request_target_rejects_other_encoded_c0_controls() {
        assert_eq!(
            parse_http_request_target("GET /health%01check HTTP/1.1"),
            None
        );
        assert_eq!(
            parse_http_request_target("HEAD /readyz%1F HTTP/1.1"),
            None
        );
    }

    #[test]
    fn parse_http_request_target_rejects_encoded_query_delimiter() {
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
    fn parse_http_request_target_rejects_multiple_raw_query_delimiters() {
        assert_eq!(
            parse_http_request_target("GET /query-task/42??shadow HTTP/1.1"),
            None
        );
        assert_eq!(
            parse_http_request_target("HEAD /query-events/7?limit=9?shadow HTTP/1.1"),
            None
        );
    }

    #[test]
    fn parse_http_request_target_rejects_raw_path_whitespace_and_controls() {
        assert_eq!(
            parse_http_request_target("GET /health\tcheck HTTP/1.1"),
            None
        );
        assert_eq!(
            parse_http_request_target("HEAD /readyz\u{000b}shadow HTTP/1.1"),
            None
        );
    }

    #[test]
    fn parse_http_request_target_rejects_malformed_percent_encoding() {
        assert_eq!(parse_http_request_target("GET /health% HTTP/1.1"), None);
        assert_eq!(parse_http_request_target("GET /health%2 HTTP/1.1"), None);
        assert_eq!(parse_http_request_target("HEAD /readyz%ZZ HTTP/1.1"), None);
    }

    #[test]
    fn parse_query_events_limit_rejects_other_encoded_c0_controls() {
        let response = parse_query_events_limit_from_path("/query-events/42?limit=1%01");
        assert!(response.is_err());
        assert_eq!(
            response.unwrap_err(),
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
            )
        );
    }

    #[test]
    fn parse_query_events_limit_rejects_malformed_percent_encoding() {
        for path in [
            "/query-events/42%?limit=7",
            "/query-events/42%2?limit=7",
            "/query-events/42?limit=7%",
            "/query-events/42?limit=7%4x",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path}"
            );
        }
    }

    #[test]
    fn parse_query_events_limit_rejects_percent_encoded_space_and_del() {
        for path in [
            "/query-events/42?limit=1%20",
            "/query-events/42?limit=1%7f",
            "/query-events/42%20?limit=1",
            "/query-events/42%7F?limit=1",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path}"
            );
        }
    }

    #[test]
    fn parse_query_events_limit_rejects_raw_path_whitespace_and_controls() {
        for path in [
            "/query-events/42\t?limit=1",
            "/query-events/42\n?limit=1",
            "/query-events/42\r?limit=1",
            "/query-events/4 2?limit=1",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path:?}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path:?}"
            );
        }
    }

    #[test]
    fn parse_query_events_limit_rejects_raw_query_whitespace() {
        for path in [
            "/query-events/42?limit=1 ",
            "/query-events/42?limit= 1",
            "/query-events/42?limit =1",
            "/query-events/42?limit=1& limit=2",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path:?}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path:?}"
            );
        }
    }

    #[test]
    fn parse_query_events_limit_rejects_wrapped_limit_keys() {
        for path in [
            "/query-events/42?%22limit%22=7",
            "/query-events/42?'limit'=7",
            "/query-events/42?`limit`=7",
            "/query-events/42?%60limit%60=7",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path:?}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path:?}"
            );
        }
    }

    #[test]
    fn parse_http_request_target_rejects_raw_and_encoded_dot_segments() {
        assert_eq!(
            parse_http_request_target("GET /query-events/../42?limit=1 HTTP/1.1"),
            None
        );
        assert_eq!(
            parse_http_request_target("GET /query-events/%2e%2e/42?limit=1 HTTP/1.1"),
            None
        );
        assert_eq!(
            parse_http_request_target("HEAD /query-events/%2E%2E/42?limit=1 HTTP/1.1"),
            None
        );
    }

    #[test]
    fn parse_query_events_limit_rejects_raw_and_encoded_dot_segments() {
        let raw = parse_query_events_limit_from_path("/query-events/../42?limit=1");
        assert!(raw.is_err());
        assert_eq!(
            raw.unwrap_err(),
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
            )
        );

        let encoded = parse_query_events_limit_from_path("/query-events/%2e%2e/42?limit=1");
        assert!(encoded.is_err());
        assert_eq!(
            encoded.unwrap_err(),
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
            )
        );

        let mixed_case = parse_query_events_limit_from_path("/query-events/%2E%2e/42?limit=1");
        assert!(mixed_case.is_err());
        assert_eq!(
            mixed_case.unwrap_err(),
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
            )
        );
    }

    #[test]
    fn parse_query_events_limit_rejects_unknown_or_duplicate_query_keys() {
        let duplicate = parse_query_events_limit_from_path("/query-events/42?limit=1&limit=2");
        assert!(duplicate.is_err());
        assert_eq!(
            duplicate.unwrap_err(),
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"duplicate limit\"}"
            )
        );

        for path in [
            "/query-events/42?foo=1",
            "/query-events/42?limit=1&foo=2",
            "/query-events/42?foo=2&limit=1",
            "/query-events/42?Limit=1",
        ] {
            let response = parse_query_events_limit_from_path(path);
            assert!(response.is_err(), "path={path}");
            assert_eq!(
                response.unwrap_err(),
                http_json_response(
                    "400 Bad Request",
                    "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}"
                ),
                "path={path}"
            );
        }
    }
}
