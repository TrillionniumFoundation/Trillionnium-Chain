use super::*;

#[test]
fn read_http_request_head_times_out_on_partial_slowloris_client() {
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let client = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client
            .write_all(b"GET /health HTTP/1.1")
            .expect("write partial request");
        thread::sleep(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS + 250));
        let _ = client.shutdown(Shutdown::Both);
    });

    let (mut server_stream, _) = listener.accept().expect("accept test client");
    configure_health_stream(&server_stream).expect("configure timeouts");
    let err =
        read_http_request_head(&mut server_stream).expect_err("partial request must time out");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));

    client.join().expect("client thread join");
}
