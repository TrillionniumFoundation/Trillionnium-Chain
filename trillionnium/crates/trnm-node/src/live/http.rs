use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub fn read_request(stream: &mut TcpStream, max_body_bytes: usize) -> Result<HttpRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("set HTTP read timeout")?;
    let mut bytes = Vec::with_capacity(1024);
    let header_end = loop {
        ensure!(
            bytes.len() < MAX_HEADER_BYTES,
            "HTTP request headers exceed limit"
        );
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).context("read HTTP request")?;
        ensure!(read > 0, "unexpected EOF while reading HTTP headers");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let header = String::from_utf8(bytes[..header_end].to_vec())
        .map_err(|_| anyhow!("HTTP headers must be valid UTF-8/ASCII"))?;
    ensure!(
        !header.chars().any(|ch| ch == '\0'),
        "HTTP headers contain NUL"
    );
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing request method"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing request path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    ensure!(
        request_parts.next().is_none(),
        "request line contains extra fields"
    );
    ensure!(version == "HTTP/1.1", "only HTTP/1.1 is supported");
    ensure!(
        matches!(method, "GET" | "POST"),
        "unsupported HTTP request method"
    );
    ensure!(
        path.starts_with('/') && !path.contains(['\r', '\n', '\0', ' ']),
        "HTTP request path is not canonical"
    );

    let mut content_length = None;
    let mut host_count = 0usize;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed HTTP header"))?;
        ensure!(
            name == name.trim() && !name.is_empty(),
            "HTTP header name is not canonical"
        );
        let normalized = name.to_ascii_lowercase();
        let value = value.trim();
        match normalized.as_str() {
            "host" => host_count += 1,
            "content-length" => {
                ensure!(content_length.is_none(), "duplicate Content-Length header");
                ensure!(
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                    "Content-Length must be canonical decimal"
                );
                content_length = Some(
                    value
                        .parse::<usize>()
                        .context("Content-Length is out of range")?,
                );
            }
            "transfer-encoding" => bail!("Transfer-Encoding is not supported"),
            "connection" | "content-type" | "accept" | "user-agent" => {}
            _ => bail!("unsupported HTTP header `{name}`"),
        }
    }
    ensure!(
        host_count == 1,
        "HTTP/1.1 request must contain one Host header"
    );

    let body_len = content_length.unwrap_or(0);
    ensure!(
        body_len <= max_body_bytes,
        "HTTP request body exceeds limit"
    );
    if method == "POST" {
        ensure!(
            content_length.is_some(),
            "POST request requires Content-Length"
        );
    } else {
        ensure!(body_len == 0, "GET request body is not supported");
    }

    while bytes.len() < header_end + body_len {
        let remaining = header_end + body_len - bytes.len();
        let mut chunk = vec![0u8; remaining.min(8192)];
        let read = stream.read(&mut chunk).context("read HTTP request body")?;
        ensure!(read > 0, "unexpected EOF while reading HTTP body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    ensure!(
        bytes.len() == header_end + body_len,
        "HTTP request has trailing pipelined bytes"
    );

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        body: bytes[header_end..].to_vec(),
    })
}

fn response_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

pub fn write_json<T: Serialize>(stream: &mut TcpStream, status: u16, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("serialize HTTP JSON response")?;
    write_response(stream, status, "application/json", &body)
}

pub fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .context("set HTTP write timeout")?;
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\r\n",
        status,
        response_reason(status),
        content_type,
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .context("write HTTP response headers")?;
    stream.write_all(body).context("write HTTP response body")?;
    stream.flush().context("flush HTTP response")
}

#[derive(Debug)]
pub struct HttpJsonResponse<T> {
    pub status: u16,
    pub value: T,
}

pub fn post_json<T: Serialize, R: DeserializeOwned>(
    endpoint: &str,
    value: &T,
    timeout: Duration,
    max_response_bytes: usize,
) -> Result<HttpJsonResponse<R>> {
    let (address, path) = parse_loopback_http_endpoint(endpoint)?;
    let body = serde_json::to_vec(value).context("serialize HTTP request body")?;
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).context("connect HTTP endpoint")?;
    stream
        .set_read_timeout(Some(timeout))
        .context("set client read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("set client write timeout")?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        address,
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .context("write HTTP request headers")?;
    stream.write_all(&body).context("write HTTP request body")?;
    stream.flush().context("flush HTTP request")?;
    read_json_response(stream, max_response_bytes)
}

pub fn get_json<R: DeserializeOwned>(
    endpoint: &str,
    timeout: Duration,
    max_response_bytes: usize,
) -> Result<HttpJsonResponse<R>> {
    let (address, path) = parse_loopback_http_endpoint(endpoint)?;
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).context("connect HTTP endpoint")?;
    stream
        .set_read_timeout(Some(timeout))
        .context("set client read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("set client write timeout")?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, address
    );
    stream
        .write_all(request.as_bytes())
        .context("write HTTP GET request")?;
    stream.flush().context("flush HTTP GET request")?;
    read_json_response(stream, max_response_bytes)
}

fn read_json_response<R: DeserializeOwned>(
    stream: TcpStream,
    max_response_bytes: usize,
) -> Result<HttpJsonResponse<R>> {
    let mut response = Vec::new();
    let mut limited = stream.take((max_response_bytes + MAX_HEADER_BYTES + 1) as u64);
    limited
        .read_to_end(&mut response)
        .context("read HTTP response")?;
    ensure!(
        response.len() <= max_response_bytes + MAX_HEADER_BYTES,
        "HTTP response exceeds limit"
    );
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| anyhow!("HTTP response is missing header terminator"))?;
    let header = std::str::from_utf8(&response[..header_end])
        .map_err(|_| anyhow!("HTTP response headers are not UTF-8/ASCII"))?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| anyhow!("missing status line"))?;
    let mut status_parts = status_line.split(' ');
    ensure!(
        status_parts.next() == Some("HTTP/1.1"),
        "unsupported HTTP response version"
    );
    let status = status_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP response status"))?
        .parse::<u16>()
        .context("invalid HTTP response status")?;
    let parsed =
        serde_json::from_slice(&response[header_end..]).context("decode HTTP JSON response")?;
    Ok(HttpJsonResponse {
        status,
        value: parsed,
    })
}

fn parse_loopback_http_endpoint(endpoint: &str) -> Result<(SocketAddr, String)> {
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("endpoint must use http://"))?;
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| anyhow!("endpoint must include an absolute path"))?;
    ensure!(
        !authority.is_empty(),
        "endpoint authority must not be empty"
    );
    ensure!(
        !authority.contains('@') && !authority.contains(['?', '#']),
        "endpoint authority must not contain credentials or fragments"
    );
    let address = authority
        .parse::<SocketAddr>()
        .context("endpoint authority must be a canonical socket address")?;
    ensure!(
        authority == address.to_string(),
        "endpoint authority must be canonical"
    );
    ensure!(
        matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
            || matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback()),
        "devnet endpoint must be loopback"
    );
    let path = format!("/{path}");
    ensure!(
        !path.contains(['?', '#', '\r', '\n', '\0', ' ']),
        "endpoint path must be canonical"
    );
    Ok((address, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parser_rejects_duplicate_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(
                    b"POST /v1/vote HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(read_request(&mut stream, 1024).is_err());
        client.join().unwrap();
    }

    #[test]
    fn endpoint_parser_is_loopback_only() {
        assert!(parse_loopback_http_endpoint("http://127.0.0.1:9000/v1/vote").is_ok());
        assert!(parse_loopback_http_endpoint("https://127.0.0.1:9000/v1/vote").is_err());
        assert!(parse_loopback_http_endpoint("http://192.0.2.1:9000/v1/vote").is_err());
    }
}
