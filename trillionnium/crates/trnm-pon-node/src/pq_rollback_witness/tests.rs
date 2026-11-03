use super::*;
use crate::ingress::pq_network::canonical_tests::{key, setup};
use std::{
    net::Shutdown,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
};

fn fixture() -> (
    test_observation::Scope,
    tempfile::TempDir,
    Arc<crate::ingress::pq_network::PqNetworkPolicy>,
    DurableWitness,
) {
    let diagnostics = test_observation::Scope::new();
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
    (diagnostics, directory, policy, owner)
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
    let (_diagnostics, _directory, policy, owner) = fixture();
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
    let (_diagnostics, _directory, _policy, owner) = fixture();
    owner.check_storage().unwrap();

    // ANALYZE adds SQLite's own sqlite_stat1. The fixed one-table witness
    // profile has no auxiliary objects; a prefix filter must not hide extras.
    owner.db.execute_batch("ANALYZE;").unwrap();
    assert_eq!(
        owner.check_storage().unwrap_err().to_string(),
        "PQ_WITNESS_SCHEMA"
    );

    let (_diagnostics, _directory, _policy, owner) = fixture();
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
    let (_diagnostics, _directory, policy, owner) = fixture();
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
    let (_diagnostics, _directory, policy, owner) = fixture();
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
fn malformed_local_checkpoints_never_enter_transport_or_poison_client() {
    let (_diagnostics, _directory, policy, owner) = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut client = client(&policy, owner, calls.clone(), false);
    let first = Checkpoint::new(1, [1; 64]).unwrap();
    let second = Checkpoint::new(2, [2; 64]).unwrap();
    for (previous, next) in [
        (
            Checkpoint {
                sequence: 0,
                root: [1; 64],
            },
            first,
        ),
        (
            Checkpoint {
                sequence: 1,
                root: [0; 64],
            },
            second,
        ),
        (
            first,
            Checkpoint {
                sequence: 2,
                root: [0; 64],
            },
        ),
        (
            Checkpoint {
                sequence: i64::MAX as u64,
                root: [1; 64],
            },
            Checkpoint {
                sequence: i64::MAX as u64 + 1,
                root: [2; 64],
            },
        ),
    ] {
        assert_eq!(
            client.advance(previous, next).unwrap_err().to_string(),
            "PQ_WITNESS_CHECKPOINT"
        );
        client.available().unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(client.current().unwrap(), first);
    client.advance(first, second).unwrap();
    assert_eq!(client.current().unwrap(), second);
}

#[test]
fn signed_current_cannot_regress_or_change_an_observed_generation() {
    for observed in [
        Checkpoint::new(2, [2; 64]).unwrap(),
        Checkpoint::new(1, [2; 64]).unwrap(),
    ] {
        let (_diagnostics, _directory, policy, owner) = fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = client(&policy, owner, calls.clone(), false);
        // Set the client's trusted memory to the boundary under test. The
        // reply comes from the original native signer and unmodified fixture.
        client.last_verified = Some(observed);
        assert_eq!(
            client.current().unwrap_err().to_string(),
            "PQ_WITNESS_OBSERVATION_ROLLBACK"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            client.current().unwrap_err().to_string(),
            "PQ_WITNESS_UNAVAILABLE"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

struct SharedTransport(Arc<Mutex<DurableWitness>>);
impl WitnessTransport for SharedTransport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        self.0.lock().unwrap().handle(request, until)
    }
}

fn shared_client(
    policy: &crate::ingress::pq_network::PqNetworkPolicy,
    owner: &Arc<Mutex<DurableWitness>>,
) -> WitnessClient {
    WitnessClient::new(
        WitnessBinding::new(policy, 1, key(73).public_spki(), key(74).public_spki()).unwrap(),
        key(74),
        Box::new(SharedTransport(owner.clone())),
    )
    .unwrap()
}

#[test]
fn independent_clients_accept_other_writers_advances_and_cold_reopen() {
    let (_diagnostics, directory, policy, owner) = fixture();
    let owner = Arc::new(Mutex::new(owner));
    let mut first = shared_client(&policy, &owner);
    let mut second = shared_client(&policy, &owner);
    let initial = first.current().unwrap();
    assert_eq!(second.current().unwrap(), initial);
    let next = Checkpoint::new(2, [2; 64]).unwrap();
    let later = Checkpoint::new(3, [3; 64]).unwrap();
    let last = Checkpoint::new(4, [4; 64]).unwrap();
    first.advance(initial, next).unwrap();
    first.advance(next, later).unwrap();
    assert_eq!(second.current().unwrap(), later);
    assert_eq!(second.current().unwrap(), later);
    second.advance(later, last).unwrap();
    assert_eq!(first.current().unwrap(), last);
    drop(first);
    drop(second);
    drop(owner);
    let reopened = DurableWitness::open_existing(
        &directory.path().join("witness.sqlite"),
        WitnessBinding::new(&policy, 1, key(73).public_spki(), key(74).public_spki()).unwrap(),
        key(73),
    )
    .unwrap();
    assert_eq!(reopened.read_head().unwrap(), last);
}

#[test]
fn active_owner_requires_its_known_head_for_current_and_cas() {
    for use_cas in [false, true] {
        for known in [
            Checkpoint::new(2, [2; 64]).unwrap(),
            Checkpoint::new(1, [2; 64]).unwrap(),
        ] {
            let (_diagnostics, _directory, policy, mut owner) = fixture();
            owner.known_head = Some(known);
            let calls = Arc::new(AtomicUsize::new(0));
            let mut client = client(&policy, owner, calls.clone(), false);
            let error = if use_cas {
                client.advance(
                    Checkpoint::new(1, [1; 64]).unwrap(),
                    Checkpoint::new(2, [2; 64]).unwrap(),
                )
            } else {
                client.current().map(|_| ())
            }
            .unwrap_err();
            assert_eq!(error.to_string(), "PQ_WITNESS_STORAGE_ROLLBACK");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn failed_local_commit_fences_owner_until_explicit_reopen() {
    let (_diagnostics, directory, policy, owner) = fixture();
    owner.db.commit_hook(Some(|| true)).unwrap();
    let owner = Arc::new(Mutex::new(owner));
    let mut first = shared_client(&policy, &owner);
    let initial = first.current().unwrap();
    assert!(first
        .advance(initial, Checkpoint::new(2, [2; 64]).unwrap())
        .is_err());
    {
        let service = owner.lock().unwrap();
        assert!(service.commit_uncertain);
        service.db.commit_hook(None::<fn() -> bool>).unwrap();
    }
    let mut reconnected = shared_client(&policy, &owner);
    assert_eq!(
        reconnected.current().unwrap_err().to_string(),
        "PQ_WITNESS_COMMIT_UNCERTAIN"
    );
    drop(first);
    drop(reconnected);
    drop(owner);
    // This injected commit failure rolled back. Reopen is explicit and reads
    // the original durable state; it does not enroll or advance any checkpoint.
    let reopened = DurableWitness::open_existing(
        &directory.path().join("witness.sqlite"),
        WitnessBinding::new(&policy, 1, key(73).public_spki(), key(74).public_spki()).unwrap(),
        key(73),
    )
    .unwrap();
    assert_eq!(reopened.read_head().unwrap(), initial);
}

#[test]
fn durable_predecessor_shape_distinguishes_registration_from_advancement() {
    for (sequence, previous_sequence, previous_root, accepted) in [
        (1, 0, [0_u8; 64], true),
        (2, 1, [1; 64], true),
        (3, 2, [2; 64], true),
        (1, 1, [1; 64], false),
        (1, 0, [1; 64], false),
        (2, 0, [0; 64], false),
        (3, 1, [1; 64], false),
        (2, 1, [0; 64], false),
    ] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(DDL).unwrap();
        db.execute(
            "INSERT INTO witness_v1 VALUES(1,?,?,?,?,?)",
            params![
                [1_u8].as_slice(),
                sequence,
                [9_u8; 64].as_slice(),
                previous_sequence,
                previous_root.as_slice()
            ],
        )
        .unwrap();
        assert_eq!(validate_row(&db, 1).is_ok(), accepted);
    }
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
