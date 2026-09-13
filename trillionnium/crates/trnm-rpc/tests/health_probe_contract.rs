use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct RpcServeProcess {
    child: Child,
}

impl Drop for RpcServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback port");
    let port = listener
        .local_addr()
        .expect("loopback listener local addr")
        .port();
    drop(listener);
    port
}

fn spawn_rpc_serve(port: u16) -> RpcServeProcess {
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-rpc"))
        .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()])
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn trnm-rpc serve");

    let mut process = RpcServeProcess { child };
    wait_for_health_server(port, &mut process);
    process
}

fn wait_for_health_server(port: u16, process: &mut RpcServeProcess) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            drop(stream);
            return;
        }

        if let Some(status) = process.child.try_wait().expect("poll serve process") {
            panic!("trnm-rpc serve exited before accepting health probes: {status}");
        }

        thread::sleep(Duration::from_millis(25));
    }

    panic!("timed out waiting for trnm-rpc serve on 127.0.0.1:{port}");
}

fn send_http_request(port: u16, request_line: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to trnm-rpc serve");
    stream
        .write_all(
            format!("{request_line}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write http request");
    stream
        .shutdown(Shutdown::Write)
        .expect("shutdown write half");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read http response");
    response
}

fn split_http_response(response: &str) -> (&str, &str) {
    response
        .split_once("\r\n\r\n")
        .expect("http response should contain header/body separator")
}

fn response_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| line.trim_end_matches('\r').strip_prefix("Content-Length: "))
        .expect("response should include Content-Length")
        .parse::<usize>()
        .expect("Content-Length should parse")
}

#[test]
fn serve_health_probe_aliases_keep_minimum_get_and_head_contracts() {
    let port = reserve_loopback_port();
    let _process = spawn_rpc_serve(port);

    let get_response = send_http_request(port, "GET /healthz?probe=lb&from=ops HTTP/1.1");
    let (get_headers, get_body) = split_http_response(&get_response);
    assert!(get_headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(get_headers.contains("Content-Type: application/json\r\n"));
    assert!(get_headers.contains("Cache-Control: no-store\r\n"));
    assert_eq!(response_content_length(get_headers), get_body.len());

    let get_json: Value = serde_json::from_str(get_body).expect("health GET body stays valid json");
    let get_object = get_json
        .as_object()
        .expect("health GET body should stay a json object");
    assert_eq!(get_object.len(), 7, "health GET body should stay bounded");
    assert_eq!(get_object.get("ok"), Some(&Value::Bool(true)));
    assert_eq!(
        get_object.get("service"),
        Some(&Value::String("trnm-rpc".into()))
    );
    assert_eq!(
        get_object.get("scope"),
        Some(&Value::String("local-file-model-harness".into()))
    );
    assert_eq!(get_object.get("development_only"), Some(&Value::Bool(true)));
    assert_eq!(
        get_object.get("production_ready"),
        Some(&Value::Bool(false))
    );
    assert!(
        get_object
            .get("ts_unix_ms")
            .and_then(Value::as_u64)
            .is_some(),
        "health GET body should expose numeric ts_unix_ms"
    );
    assert_eq!(get_object.get("version"), Some(&Value::Number(1u64.into())));

    let head_response = send_http_request(port, "HEAD /-/readyz?probe=lb&from=ops HTTP/1.1");
    let (head_headers, head_body) = split_http_response(&head_response);
    assert!(head_headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head_headers.contains("Content-Type: application/json\r\n"));
    assert!(head_headers.contains("Cache-Control: no-store\r\n"));
    assert_eq!(response_content_length(head_headers), get_body.len());
    assert!(
        head_body.is_empty(),
        "HEAD health response must stay bodyless"
    );
}

#[test]
fn serve_health_probe_negative_paths_keep_head_404_and_bad_request_json_distinct() {
    let port = reserve_loopback_port();
    let _process = spawn_rpc_serve(port);

    let head_not_found = send_http_request(port, "HEAD /missing?probe=lb HTTP/1.1");
    let (head_headers, head_body) = split_http_response(&head_not_found);
    assert!(head_headers.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(head_headers.contains("Content-Type: application/json\r\n"));
    assert!(head_headers.contains("Cache-Control: no-store\r\n"));
    assert_eq!(
        response_content_length(head_headers),
        "{\"ok\":false,\"code\":\"NOT_FOUND\"}".len()
    );
    assert!(head_body.is_empty(), "HEAD 404 response must stay bodyless");

    let lower_head_not_found = send_http_request(port, "head /missing?probe=lb HTTP/1.1");
    let (lower_head_headers, lower_head_body) = split_http_response(&lower_head_not_found);
    assert!(lower_head_headers.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(lower_head_headers.contains("Content-Type: application/json\r\n"));
    assert!(lower_head_headers.contains("Cache-Control: no-store\r\n"));
    assert_eq!(
        response_content_length(lower_head_headers),
        "{\"ok\":false,\"code\":\"NOT_FOUND\"}".len()
    );
    assert!(
        lower_head_body.is_empty(),
        "lowercase HEAD 404 response must stay bodyless"
    );

    let bad_request = send_http_request(port, "GET /health#bridge HTTP/1.1");
    let (bad_headers, bad_body) = split_http_response(&bad_request);
    assert!(bad_headers.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(bad_headers.contains("Content-Type: application/json\r\n"));
    assert!(bad_headers.contains("Cache-Control: no-store\r\n"));
    assert_eq!(response_content_length(bad_headers), bad_body.len());
    assert_eq!(
        bad_body,
        "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid http request\"}"
    );
}
