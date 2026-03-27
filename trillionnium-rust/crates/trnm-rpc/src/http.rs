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
        || normalized_path.contains("%5c")
        || normalized_path.contains("%23")
        || normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || normalized_path.contains("%0d")
        || normalized_path.contains("%0a")
        || normalized_path.contains("%09")
        || normalized_path.contains("%0b")
        || normalized_path.contains("%0c")
        || normalized_path.contains("%20")
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
        || query.chars().any(|ch| ch.is_control())
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
        || normalized_query.contains("%00")
        || normalized_query.contains("%0d")
        || normalized_query.contains("%0a")
        || normalized_query.contains("%09")
        || normalized_query.contains("%0b")
        || normalized_query.contains("%0c")
        || normalized_query.contains("%20")
        || normalized_query.contains("%7f")
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
    use super::{http_json_response, http_response_for_method};

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
}
