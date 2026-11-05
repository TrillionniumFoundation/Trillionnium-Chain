//! Actual native replay-owner and signed socket observations. Finite histories
//! do not qualify bounded lifetime storage, anonymous access or WAN service.
use super::*;
use crate::ingress::{
    call_authenticated, now, serve_authenticated, AuthenticatedClient, AuthenticatedServer,
    DevelopmentIdentity, Metrics, Request,
};
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Instant,
};

fn frame(settings: &Settings, nonce: u64, payload: &[u8]) -> AuthenticatedPeerFrameV0 {
    let session = PeerSessionIdentityV0::new(
        IoDigest32V0::new(settings.genesis()).unwrap(),
        IoDigest32V0::new(settings.parameters()).unwrap(),
        IoDigest32V0::new([81; 32]).unwrap(),
        IoDigest32V0::new([82; 32]).unwrap(),
        IoDigest32V0::new(crate::authenticated_profile_digest()).unwrap(),
        1,
    )
    .unwrap();
    AuthenticatedPeerFrameV0::new(
        session,
        nonce,
        IoDigest32V0::new(crate::authenticated_payload_digest(payload)).unwrap(),
        payload.len(),
    )
    .unwrap()
}

fn complete(node: &mut Node, settings: &Settings, nonce: u64) {
    let payload = b"native journal request";
    let frame = frame(settings, nonce, payload);
    assert!(matches!(
        node.begin_authenticated_request(frame, payload).unwrap(),
        AuthenticatedReplayDecision::Execute
    ));
    node.finish_authenticated_request(frame, b"native journal response")
        .unwrap();
}

struct OwnedSocketServer {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<Result<Metrics>>>,
}
impl OwnedSocketServer {
    fn finish(&mut self) -> Metrics {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for OwnedSocketServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn authenticated_replay_checks_are_operation_local_and_reopen_recovers_full_history() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    for nonce in 1..=32 {
        REPLAY_RECOVERY_CHECKS.with(|calls| calls.set(0));
        complete(&mut node, &settings, nonce);
        assert_eq!(REPLAY_RECOVERY_CHECKS.with(Cell::get), 2);
    }
    let payload = b"native journal request";
    let last = frame(&settings, 32, payload);
    REPLAY_RECOVERY_CHECKS.with(|calls| calls.set(0));
    assert!(matches!(
        node.begin_authenticated_request(last, payload).unwrap(),
        AuthenticatedReplayDecision::Cached(bytes) if bytes == b"native journal response"
    ));
    assert_eq!(REPLAY_RECOVERY_CHECKS.with(Cell::get), 1);
    let next = frame(&settings, 33, payload);
    REPLAY_RECOVERY_CHECKS.with(|calls| calls.set(0));
    node.begin_authenticated_request(next, payload).unwrap();
    node.begin_authenticated_request(next, payload).unwrap();
    assert_eq!(REPLAY_RECOVERY_CHECKS.with(Cell::get), 2);
    assert_eq!(node.authenticated_replay_counts().unwrap(), (1, 1, 33));
    drop(node);
    REPLAY_RECOVERY_CHECKS.with(|calls| calls.set(0));
    let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(REPLAY_RECOVERY_CHECKS.with(Cell::get), 1);
    REPLAY_RECOVERY_CHECKS.with(|calls| calls.set(0));
    reopened
        .finish_authenticated_request(next, b"native journal response")
        .unwrap();
    assert_eq!(REPLAY_RECOVERY_CHECKS.with(Cell::get), 1);
    assert_eq!(reopened.authenticated_replay_counts().unwrap(), (1, 0, 33));
}

#[test]
fn authenticated_replay_ack_rechecks_old_gap_and_pending_bytes_after_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    for nonce in 1..=32 {
        complete(&mut node, &settings, nonce);
    }
    let payload = b"native journal request";
    let pending = frame(&settings, 33, payload);
    node.begin_authenticated_request(pending, payload).unwrap();
    for damage in [
        "DELETE FROM peer_request_audit WHERE nonce=1",
        "UPDATE peer_request_audit SET payload=X'00' WHERE nonce=33",
    ] {
        node.db.execute_batch("SAVEPOINT replay_damage").unwrap();
        node.db.execute_batch(damage).unwrap();
        let before = node.authenticated_replay_state(pending.session()).unwrap();
        let error = node
            .finish_authenticated_request(pending, b"native journal response")
            .unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(error.to_string().contains(if damage.starts_with("DELETE") {
            "AUTH_REPLAY_GAP"
        } else {
            "AUTH_PENDING_AUDIT"
        }));
        assert_eq!(
            node.authenticated_replay_state(pending.session()).unwrap(),
            before
        );
        node.db
            .execute_batch("ROLLBACK TO replay_damage; RELEASE replay_damage")
            .unwrap();
    }
    node.finish_authenticated_request(pending, b"native journal response")
        .unwrap();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.authenticated_replay_counts().unwrap(), (1, 0, 33));
}

#[test]
fn authenticated_replay_retired_digest_and_cold_gap_still_refuse() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    for nonce in 1..=32 {
        complete(&mut node, &settings, nonce);
    }
    node.db.execute_batch("SAVEPOINT replay_damage").unwrap();
    node.db
        .execute(
            "UPDATE peer_request_audit SET payload_digest=? WHERE nonce=1",
            [[83_u8; 32].as_slice()],
        )
        .unwrap();
    let payload = b"native journal request";
    let error = node
        .begin_authenticated_request(frame(&settings, 1, payload), payload)
        .unwrap_err();
    assert_eq!(error.to_string(), "AUTH_CONFLICTING_REPLAY");
    assert_eq!(node.authenticated_replay_counts().unwrap(), (1, 0, 32));
    node.db
        .execute_batch("ROLLBACK TO replay_damage; RELEASE replay_damage")
        .unwrap();
    node.db
        .execute("DELETE FROM peer_request_audit WHERE nonce=1", [])
        .unwrap();
    drop(node);
    let error = Node::open(directory.path(), settings, 1).err().unwrap();
    assert!(error.requires_owner_stop());
    assert!(error.to_string().contains("AUTH_REPLAY_GAP"));
}

#[test]
fn authenticated_replay_signed_socket_whole_request_history_cost_observation() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
    let server_key = DevelopmentIdentity::from_secret_hex(&hex::encode([84; 32])).unwrap();
    let client_key = DevelopmentIdentity::from_secret_hex(&hex::encode([85; 32])).unwrap();
    let authentication =
        AuthenticatedServer::new(server_key.clone(), [client_key.public_key().to_owned()], 1)
            .unwrap();
    let client =
        AuthenticatedClient::new(client_key, server_key.public_key().to_owned(), 1).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let mut server = OwnedSocketServer {
        stop: stop.clone(),
        thread: Some(thread::spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(60),
                server_stop,
                authentication,
            )
        })),
    };
    let mut nonce = 1;
    let mut durations = Vec::new();
    for history in 0..256 {
        let started = Instant::now();
        let response = call_authenticated(address, &Request::Head, &settings, &client, &mut nonce);
        let duration = started.elapsed().as_nanos();
        // Always stop and join the owned server before reporting a failed call.
        if response.is_err() {
            server.finish();
            panic!("signed native Head failed: {response:?}");
        }
        let response = response.unwrap();
        assert_eq!(response["height"], 0);
        assert_eq!(response["authenticated_audit_rows"], history + 1);
        assert_eq!(nonce, history + 2);
        durations.push(duration);
        if [16, 64, 256].contains(&(history + 1)) {
            let mut ordered = durations.clone();
            ordered.sort_unstable();
            let disk_bytes: u64 = fs::read_dir(directory.path())
                .unwrap()
                .map(|file| file.unwrap().metadata().unwrap().len())
                .sum();
            println!(
                "{}",
                serde_json::json!({
                    "schema":"pon-authenticated-replay-native-cost-observation-v1",
                    "scope":"actual signed loopback Head request: client encode/sign, socket, server signature/replay reserve/full recovery, native dispatch, ACK persistence, signed reply verification; cumulative samples; no WAN TPS, adversarial minimum, bounded history or timing improvement claim",
                    "completed_requests":history+1,
                    "sample_count":durations.len(),
                    "client_whole_request_p50_ns":ordered[ordered.len()/2],
                    "client_whole_request_max_ns":ordered[ordered.len()-1],
                    "last_request_ns":duration,
                    "observed_directory_entry_bytes":disk_bytes,
                    "retained_identity_rows":history+1,
                    "retained_response_limit":AUTH_RESPONSE_RETENTION,
                    "source_expected_recovery_checks_per_new_request":2,
                    "sqlite_version":rusqlite::version(),
                    "architecture":std::env::consts::ARCH,
                    "production_activation":false
                })
            );
        }
    }
    let metrics = server.finish();
    assert_eq!(metrics.authenticated_requests, 256);
    assert_eq!(metrics.completed_requests, 256);
    assert_eq!(metrics.replayed_responses, 0);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.authenticated_replay_counts().unwrap(), (1, 0, 256));
    let bodies: u64 = reopened
        .db
        .query_row(
            "SELECT COUNT(*) FROM peer_request_audit WHERE response IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bodies, AUTH_RESPONSE_RETENTION);
}
