use super::*;
use crate::ingress::pq_network::canonical_tests::{key, setup};
use std::{
    net::Shutdown,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
};

fn fixture() -> (
    tempfile::TempDir,
    Arc<crate::ingress::pq_network::PqNetworkPolicy>,
    DurableWitness,
) {
    let directory = tempfile::tempdir().unwrap();
    let (_, policy) = setup();
    let binding =
        WitnessBinding::new(&policy, 1, key(73).public_spki(), key(74).public_spki()).unwrap();
    let owner = DurableWitness::register_new(
        &directory.path().join("witness.sqlite"),
        binding,
        Checkpoint::new(1, [1; 64]).unwrap(),
        key(73),
    )
    .unwrap();
    (directory, policy, owner)
}

struct DirectTransport {
    owner: DurableWitness,
    calls: Arc<AtomicUsize>,
    late_cas: bool,
}
impl WitnessTransport for DirectTransport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self.owner.handle(request, until)?;
        if self.late_cas && request[4] == 2 {
            self.late_cas = false;
            thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
            );
        }
        Ok(reply)
    }
}

fn client(
    policy: &crate::ingress::pq_network::PqNetworkPolicy,
    owner: DurableWitness,
    calls: Arc<AtomicUsize>,
    late_cas: bool,
) -> WitnessClient {
    WitnessClient::new(
        WitnessBinding::new(policy, 1, key(73).public_spki(), key(74).public_spki()).unwrap(),
        key(74),
        Box::new(DirectTransport {
            owner,
            calls,
            late_cas,
        }),
    )
    .unwrap()
}

#[test]
fn cancellation_after_signing_before_send_preserves_same_client() {
    let (_directory, policy, owner) = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let cuts = Arc::new(AtomicUsize::new(0));
    let mut client = client(&policy, owner, calls.clone(), false);
    let initial = Checkpoint::new(1, [1; 64]).unwrap();
    let next = Checkpoint::new(2, [2; 64]).unwrap();
    let observed_cuts = cuts.clone();
    client.before_send = Some(Box::new(move |until| {
        observed_cuts.fetch_add(1, Ordering::SeqCst);
        thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
    }));

    // The cut runs in the real request path after its ML-DSA signing. An
    // already-expired entry check would not exercise the former latch bug.
    assert_eq!(
        client.current().unwrap_err().to_string(),
        "PQ_WITNESS_DEADLINE"
    );
    assert_eq!(
        client.advance(initial, next).unwrap_err().to_string(),
        "PQ_WITNESS_DEADLINE"
    );
    assert_eq!(cuts.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    client.available().unwrap();

    client.before_send = None;
    assert_eq!(client.current().unwrap(), initial);
    client.advance(initial, next).unwrap();
    assert_eq!(client.current().unwrap(), next);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn schema_rejects_extra_sqlite_objects_and_oversized_sql_text() {
    let (_directory, _policy, owner) = fixture();
    owner.check_storage().unwrap();

    // ANALYZE adds SQLite's own sqlite_stat1. The fixed one-table witness
    // profile has no auxiliary objects; a prefix filter must not hide extras.
    owner.db.execute_batch("ANALYZE;").unwrap();
    assert_eq!(
        owner.check_storage().unwrap_err().to_string(),
        "PQ_WITNESS_SCHEMA"
    );

    let (_directory, _policy, owner) = fixture();
    // Exercise a restored valid SQL string with a noncanonical giant suffix.
    // No claim about SQLite's internal allocation follows from this test.
    owner
        .db
        .execute_batch("PRAGMA writable_schema=ON;")
        .unwrap();
    owner
        .db
        .execute(
            "UPDATE sqlite_master SET sql=sql||? WHERE name='witness_v1'",
            [" ".repeat(512 * 1024)],
        )
        .unwrap();
    assert_eq!(
        owner.check_storage().unwrap_err().to_string(),
        "PQ_WITNESS_SCHEMA"
    );
}

#[test]
fn same_keys_under_different_binding_generation_cannot_authorize_current() {
    let (_directory, policy, owner) = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut client = WitnessClient::new(
        WitnessBinding::new(&policy, 2, key(73).public_spki(), key(74).public_spki()).unwrap(),
        key(74),
        Box::new(DirectTransport {
            owner,
            calls: calls.clone(),
            late_cas: false,
        }),
    )
    .unwrap();
    assert_eq!(
        client.current().unwrap_err().to_string(),
        "PQ_WITNESS_REQUEST_CONTEXT"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.available().unwrap_err().to_string(),
        "PQ_WITNESS_UNAVAILABLE"
    );
}

#[test]
fn authenticated_matching_late_cas_is_known_success_and_client_stays_usable() {
    let (_directory, policy, owner) = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut client = client(&policy, owner, calls.clone(), true);
    let initial = Checkpoint::new(1, [1; 64]).unwrap();
    let next = Checkpoint::new(2, [2; 64]).unwrap();
    let until = Instant::now() + MAX_EXCHANGE;
    client.advance_until(initial, next, Some(until)).unwrap();
    assert!(Instant::now() >= until);
    client.available().unwrap();
    assert_eq!(client.current().unwrap(), next);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn slow_drip_read_obeys_one_absolute_deadline() {
    let (mut receiver, mut peer) = UnixStream::pair().unwrap();
    let shutdown = receiver.try_clone().unwrap();
    peer.set_write_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let peer_stop = stop.clone();
    let sender = thread::spawn(move || {
        while !peer_stop.load(Ordering::Acquire) {
            if peer.write_all(&[1]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    let (result_sender, result_receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = read_until(
            &mut receiver,
            &mut [0; 1024],
            Instant::now() + Duration::from_millis(40),
        );
        let _ = result_sender.send(result.map_err(|error| error.to_string()));
    });
    let result = result_receiver.recv_timeout(Duration::from_millis(500));
    // Cleanup precedes assertions even if a renewed per-read timeout regresses.
    stop.store(true, Ordering::Release);
    let _ = shutdown.shutdown(Shutdown::Both);
    worker.join().unwrap();
    sender.join().unwrap();
    assert!(result
        .expect("read must stop while the drip is still active")
        .is_err());
}

#[test]
fn slow_drip_write_obeys_one_absolute_deadline() {
    let (mut sender, mut peer) = UnixStream::pair().unwrap();
    let shutdown = sender.try_clone().unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let peer_stop = stop.clone();
    let reader = thread::spawn(move || {
        let mut chunk = [0; 8192];
        while !peer_stop.load(Ordering::Acquire) {
            match peer.read(&mut chunk) {
                Ok(0) => break,
                Ok(_) => thread::sleep(Duration::from_millis(2)),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
        }
    });
    let (result_sender, result_receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let bytes = vec![1; 8 * 1024 * 1024];
        let result = write_until(
            &mut sender,
            &bytes,
            Instant::now() + Duration::from_millis(40),
        );
        let _ = result_sender.send(result.map_err(|error| error.to_string()));
    });
    let result = result_receiver.recv_timeout(Duration::from_millis(500));
    stop.store(true, Ordering::Release);
    let _ = shutdown.shutdown(Shutdown::Both);
    worker.join().unwrap();
    reader.join().unwrap();
    assert!(result
        .expect("write must stop while the peer is still draining")
        .is_err());
}
