use std::{io::Read, net::TcpStream, time::Duration};

use crate::envpaths::normalize_wrapped_env_value;
use crate::rpc_util::clamp_limit;
use crate::{
    HEALTH_REQUEST_HEADER_MAX_BYTES, HEALTH_SOCKET_READ_TIMEOUT_MS, HEALTH_SOCKET_WRITE_TIMEOUT_MS,
    QUERY_EVENTS_LIMIT_DEFAULT, QUERY_EVENTS_LIMIT_MAX,
};

pub(crate) fn http_json_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

pub(crate) fn http_json_head_response(status_line: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
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
        || normalized_query.contains("%0d")
        || normalized_query.contains("%0a")
        || normalized_query.contains("%09")
        || normalized_query.contains("%0b")
        || normalized_query.contains("%0c")
        || normalized_query.contains("%20")
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
