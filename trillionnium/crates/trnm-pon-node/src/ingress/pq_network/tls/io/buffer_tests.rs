use super::*;
use crate::ingress::pq_network::tls_fixtures::Fixture;
use std::{net::Shutdown, thread};

fn queued_ciphertext(bytes: Vec<u8>) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sender = thread::spawn(move || {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&bytes).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let (stream, _) = listener.accept().unwrap();
    sender.join().unwrap();
    stream
}

#[test]
fn buffered_ciphertext_is_charged_before_release_and_cannot_outlive_its_deadline() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let owner = Mutex::new(
        Node::open_with_pq_network(
            directory.path(),
            fixture.settings.clone(),
            1,
            &fixture.policy,
        )
        .unwrap(),
    );
    let server = fixture.server();
    let stream = queued_ciphertext(vec![0x5a; 4096]);
    let deadline = Instant::now() + Duration::from_secs(2);
    server.inner.charge_connection(&owner, deadline).unwrap();
    let raw = DeadlineStream::new(stream, deadline, Some((&owner, &fixture.policy))).unwrap();
    let mut buffered = BufferedIo::new(raw);
    let mut first = [0_u8; 1];
    buffered.read_exact(&mut first).unwrap();
    assert_eq!(first, [0x5a]);
    let pending = buffered.reader.buffer().len();
    assert!(
        pending > 0,
        "the next read must exercise retained ciphertext"
    );
    let before = owner
        .lock()
        .unwrap()
        .pq_network_status(&fixture.policy)
        .unwrap();
    assert_eq!(before["ingress_bytes"].as_u64(), Some(1 + pending as u64));
    thread::sleep(deadline.saturating_duration_since(Instant::now()));
    assert!(Instant::now() >= deadline);
    let mut withheld = [0x7e_u8; 1];
    assert_eq!(
        buffered.read(&mut withheld).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(withheld, [0x7e]);
    assert_eq!(
        owner
            .lock()
            .unwrap()
            .pq_network_status(&fixture.policy)
            .unwrap(),
        before
    );
}

#[test]
fn buffered_ciphertext_rejects_byte_65537_and_keeps_exact_durable_debit() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let owner = Mutex::new(
        Node::open_with_pq_network(
            directory.path(),
            fixture.settings.clone(),
            1,
            &fixture.policy,
        )
        .unwrap(),
    );
    let server = fixture.server();
    let stream = queued_ciphertext(vec![0x5a; 65_537]);
    let deadline = Instant::now() + Duration::from_secs(5);
    server.inner.charge_connection(&owner, deadline).unwrap();
    let raw = DeadlineStream::new(stream, deadline, Some((&owner, &fixture.policy))).unwrap();
    let mut buffered = BufferedIo::new(raw);
    let mut received = vec![0; 65_536];
    for chunk in received.chunks_mut(2048) {
        buffered.read_exact(chunk).unwrap();
    }
    assert_eq!(received, vec![0x5a; 65_536]);
    assert!(buffered
        .read(&mut [0])
        .unwrap_err()
        .to_string()
        .contains("PQ_TLS_CIPHERTEXT_LIMIT"));
    drop(buffered);
    let before = owner
        .lock()
        .unwrap()
        .pq_network_status(&fixture.policy)
        .unwrap();
    assert_eq!(before["ingress_bytes"], 65_536);
    assert_eq!(before["tls_handshake_attempts"], 1);
    assert_eq!(before["inbound_signature_attempts"], 0);
    assert_eq!(before["records"], 0);
    drop(owner);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(reopened.pq_network_status(&fixture.policy).unwrap(), before);
}
