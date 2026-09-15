#![cfg(feature = "candidate-state-sync-tcp")]

// Integration-only listener/threads; the runtime accepts an already connected stream.
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    time::Instant,
};
use std::{net::TcpListener, thread, time::Duration};
use trnm_poco_node_io::AbsoluteDeadlineTcpStreamV1;
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}
#[test]
fn expired_deadline_does_not_read_or_write_ready_socket() {
    let (client, mut server) = pair();
    server.write_all(b"x").unwrap();
    assert!(AbsoluteDeadlineTcpStreamV1::new(client, Instant::now()).is_err());
    let (client, mut server) = pair();
    server.write_all(b"x").unwrap();
    let mut bounded =
        AbsoluteDeadlineTcpStreamV1::new(client, Instant::now() + Duration::from_millis(20))
            .unwrap();
    thread::sleep(Duration::from_millis(40));
    assert_eq!(
        bounded.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        bounded.write(b"y").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(bounded.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn fragmented_input_cannot_extend_absolute_deadline() {
    let (client, mut server) = pair();
    let sender = thread::spawn(move || {
        for _ in 0..20 {
            if server.write_all(b"x").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
    });
    let mut bounded =
        AbsoluteDeadlineTcpStreamV1::new(client, Instant::now() + Duration::from_millis(120))
            .unwrap();
    let error = bounded.read_exact(&mut [0; 20]).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ));
    // Even if the OS reports WouldBlock, a later retry still uses the same
    // deadline; successful partial reads never reset it.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        bounded.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(bounded);
    sender.join().unwrap();
}
#[test]
fn complete_fragmented_exchange_and_half_close_preserve_bytes() {
    let (client, mut server) = pair();
    let sender = thread::spawn(move || {
        server.write_all(b"abc").unwrap();
        server.write_all(b"def").unwrap();
        server.shutdown(Shutdown::Write).unwrap();
    });
    let mut bounded =
        AbsoluteDeadlineTcpStreamV1::new(client, Instant::now() + Duration::from_secs(5)).unwrap();
    let mut bytes = Vec::new();
    bounded.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"abcdef");
    sender.join().unwrap();
}
