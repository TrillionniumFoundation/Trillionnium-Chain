// Test-only real signed-socket regression. This does not change the listener,
// work relation, timeout, error producer, account or reorganization implementation.
use super::*;
use rusqlite::OptionalExtension;
use std::path::Path;

const ORIGINAL_PQ_REQUEST_SECONDS: u64 = 10;

type BlockObservationRow = (String, u64, String, u64);
type ReorgObservationRow = (String, String, u64, u64, u64);
type LifecycleObservationRow = (u64, u64, Option<u64>, String, String, String, u64);
type PeerObservationRow = (String, u64, bool);
type RequestObservationRow = (
    String,
    u64,
    String,
    u64,
    u64,
    Option<String>,
    Option<String>,
);

mod expiry {
    use super::*;
    include!("post_intent_expiry_tests.rs");
}

mod local_control_origin {
    use super::*;
    include!("local_control_origin_tests.rs");
}

struct Running {
    directory: tempfile::TempDir,
    settings: Settings,
    policy: Arc<PqNetworkPolicy>,
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<PqNetworkMetrics>>>,
    target: crate::Packet,
    honest: crate::Packet,
    initial: PreparedPqRequest,
    same_peer_head: PreparedPqRequest,
    other_peer_head: PreparedPqRequest,
    other_peer_submit: PreparedPqRequest,
    before: Value,
}

impl Running {
    fn start() -> Self {
        Self::start_with_initial_lifetime(60)
    }

    fn start_with_initial_lifetime(initial_lifetime_seconds: u64) -> Self {
        assert!((1..=60).contains(&initial_lifetime_seconds));
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let policy = policy(&settings, 1);
        let mut node =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        let base = settings.genesis_time();
        let left = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                base + 10,
                4096,
            )
            .unwrap();
        let left_id = node
            .admit(&left, super::super::super::now().unwrap())
            .unwrap();
        node.activate_observed(left_id, super::super::super::now().unwrap())
            .unwrap();
        let right = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(1).unwrap(),
                base + 11,
                4096,
            )
            .unwrap();
        let right_id = node
            .admit(&right, super::super::super::now().unwrap())
            .unwrap();
        let target = node
            .make(
                right_id,
                vec![],
                crate::development_public(1).unwrap(),
                base + 21,
                4096,
            )
            .unwrap();
        let honest = node
            .make(
                left_id,
                vec![],
                crate::development_public(2).unwrap(),
                base + 22,
                4096,
            )
            .unwrap();
        // These are complete real W1 witnesses, not a fabricated checked output.
        WorkCheckedPacket::verify(target.clone()).unwrap();
        WorkCheckedPacket::verify(honest.clone()).unwrap();
        assert!(node.public_service_cpu_domain().is_err());
        node.cancel_next_activation_intent_for_test();

        let primary = PqClient::new(policy.clone(), signer(72)).unwrap();
        let other = PqClient::new(policy.clone(), signer(73)).unwrap();
        let signed_at = super::super::super::now().unwrap();
        let expiry = signed_at + 60;
        let initial_expiry = signed_at + initial_lifetime_seconds;
        let initial = primary
            .prepare(
                1,
                initial_expiry,
                Request::Submit {
                    packet: hex::encode(target.encode().unwrap()),
                },
            )
            .unwrap();
        let same_peer_head = primary.prepare(2, expiry, Request::Head).unwrap();
        let other_peer_head = other.prepare(1, expiry, Request::Head).unwrap();
        let other_peer_submit = other
            .prepare(
                2,
                expiry,
                Request::Submit {
                    packet: hex::encode(honest.encode().unwrap()),
                },
            )
            .unwrap();
        let before = capture(directory.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let server = PqServer::new(policy.clone(), signer(71)).unwrap();
        // This is the actual production PQ listener and its original per-socket
        // ten-second deadline, not a test driver reproducing its dispatch loop.
        let worker = thread::spawn(move || {
            serve_pq_authenticated(listener, node, Duration::from_secs(60), worker_stop, server)
        });
        println!(
            "{}",
            json!({
                "schema":"pq-post-intent-plan-v1", "planned_calls":5,
                "planned_call_order":["initial-target", "same-peer-next-sequence-head", "other-peer-head", "other-peer-honest-submit", "original-exact-wire-replay"],
                "first_operation_sequence":1, "original_request_deadline_seconds":ORIGINAL_PQ_REQUEST_SECONDS,
                "signed_expiry":initial_expiry, "followup_signed_expiry":expiry,
                "initial_signed_lifetime_seconds":initial_lifetime_seconds,
                "source_of_cut":"existing test-only pause after real durable intent; actual original progress deadline or signed expiry is observed",
                "typed_error_injected":false, "classic_listener_used":false,
                "target_packet_hex":hex::encode(target.encode().unwrap()),
                "honest_packet_hex":hex::encode(honest.encode().unwrap()),
                "setup_left_packet_hex":hex::encode(left.encode().unwrap()),
                "setup_right_packet_hex":hex::encode(right.encode().unwrap()),
                "before":before, "public_paid_host_qualified":false, "whole_chain_pq":false
            })
        );
        Self {
            directory,
            settings,
            policy,
            address,
            stop,
            worker: Some(worker),
            target,
            honest,
            initial,
            same_peer_head,
            other_peer_head,
            other_peer_submit,
            before,
        }
    }

    fn call(&self, label: &str, request: &PreparedPqRequest) -> Value {
        println!(
            "{}",
            json!({"schema":"pq-post-intent-call-scheduled-v1", "label":label,
            "peer":hex::encode(request.verified.peer), "sequence":request.verified.sequence,
            "operation":hex::encode(request.operation_id()), "expiry":request.verified.expiry,
            "request_wire_hex":hex::encode(request.wire()),
            "deadline_seconds":ORIGINAL_PQ_REQUEST_SECONDS})
        );
        let started = Instant::now();
        let deadline = started + Duration::from_secs(ORIGINAL_PQ_REQUEST_SECONDS);
        let result = (|| -> Result<Vec<u8>> {
            let mut socket = TcpStream::connect_timeout(
                &self.address,
                Duration::from_secs(ORIGINAL_PQ_REQUEST_SECONDS),
            )?;
            super::super::super::write_frame_deadline(&mut socket, request.wire(), deadline)?;
            super::super::super::read_frame_deadline(&mut socket, deadline)
        })();
        let ended = Instant::now();
        let mut row = json!({"schema":"pq-post-intent-call-observed-v1", "label":label,
            "elapsed_ns":ended.duration_since(started).as_nanos(),
            "returned_before_original_deadline":ended < deadline,
            "response_wire_hex":null, "signed_response":null, "io_error":null,
            "response_verification_error":null});
        match result {
            Ok(wire) => {
                row["response_wire_hex"] = json!(hex::encode(&wire));
                match self.policy.verify_response(
                    &wire,
                    &request.verified,
                    super::super::super::now().unwrap(),
                ) {
                    Ok(response) => row["signed_response"] = json!(response),
                    Err(error) => row["response_verification_error"] = json!(error.to_string()),
                }
            }
            Err(error) => row["io_error"] = json!(error.to_string()),
        }
        println!("{row}");
        row
    }

    fn finish(&mut self) -> Value {
        self.stop.store(true, Ordering::Release);
        match self.worker.take().unwrap().join() {
            Ok(Ok(metrics)) => json!({"joined":true,"metrics":metrics}),
            Ok(Err(error)) => json!({"joined":true,"server_error":error.to_string()}),
            Err(_) => json!({"joined":true,"server_panicked":true}),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn owner_fence(directory: &Path) -> Result<Value> {
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        let mut entries = Vec::new();
        for name in ["", "native.sqlite", "owner.lock"] {
            let metadata = std::fs::metadata(directory.join(name))?;
            entries.push(json!({"name":name,"device":metadata.dev(),"inode":metadata.ino()}));
        }
        json!({"supported":true,"entries":entries})
    };
    #[cfg(not(unix))]
    let identity = json!({"supported":false,"reason":"unix_inode_device_probe_unavailable"});
    let file = std::fs::File::open(directory.join("owner.lock"))?;
    let lock = match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            fs2::FileExt::unlock(&file)?;
            json!({"held_by_original_owner":false,"error":null})
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            json!({"held_by_original_owner":true,"error":null})
        }
        Err(error) => json!({"held_by_original_owner":null,"error":error.to_string()}),
    };
    Ok(json!({"identity":identity,"exclusive_lock_probe":lock}))
}

fn snapshot(directory: &Path) -> Result<Value> {
    let mut db = rusqlite::Connection::open_with_flags(
        directory.join("native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let (tip, generation, slot): (Vec<u8>, u64, u64) = tx.query_row(
        "SELECT tip,generation,state_slot FROM active WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let state: Vec<(String, Vec<u8>)> = tx
        .prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key")?
        .query_map([slot], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let blocks: Vec<BlockObservationRow> = tx.prepare(
        "SELECT lower(hex(id)),height,lower(hex(state_root)),COALESCE(length(packet),0) FROM blocks ORDER BY height,id")?
        .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let reorg: Option<ReorgObservationRow> = tx.query_row(
        "SELECT lower(hex(old_tip)),lower(hex(new_tip)),generation,cursor,done FROM reorg WHERE singleton=1", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional()?;
    let lifecycle: Vec<LifecycleObservationRow> = tx.prepare(
        "SELECT operation,outcome,cancelled_cursor,reason,lower(hex(old_tip)),lower(hex(new_tip)),generation FROM reorg_lifecycle_v1 ORDER BY operation")?
        .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let peers: Vec<PeerObservationRow> = tx.prepare(
        "SELECT lower(hex(peer)),highest_sequence,revoked FROM pq_network_peer_v1 ORDER BY peer")?
        .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let requests: Vec<RequestObservationRow> = tx.prepare(
        "SELECT lower(hex(peer)),sequence,lower(hex(operation)),status,length(wire),CASE WHEN response IS NULL THEN NULL ELSE lower(hex(response)) END,CASE WHEN response_digest IS NULL THEN NULL ELSE lower(hex(response_digest)) END FROM pq_network_request_v1 ORDER BY peer,sequence")?
        .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let metadata: Vec<(String, String)> = tx
        .prepare("SELECT key,lower(hex(value)) FROM metadata ORDER BY key")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    tx.commit()?;
    Ok(
        json!({"active":{"tip":hex::encode(tip),"generation":generation,"slot":slot,
        "state":state,"state_digest":hex::encode(hash(b"pq-post-intent-active-state-v1",&[&serde_json::to_vec(&state)?]))},
        "blocks":blocks,"reorg":reorg,"lifecycle":lifecycle,"peers":peers,"requests":requests,
        "metadata":metadata,"owner_fence":owner_fence(directory)?}),
    )
}

fn capture(directory: &Path) -> Value {
    match snapshot(directory) {
        Ok(value) => value,
        Err(error) => json!({"capture_error":error.to_string()}),
    }
}

fn peer_sequence(snapshot: &Value, peer: Hash) -> Option<u64> {
    snapshot["peers"]
        .as_array()?
        .iter()
        .find(|row| row[0] == hex::encode(peer))
        .and_then(|row| row[1].as_u64())
}

fn recorded_response(snapshot: &Value, request: &PreparedPqRequest) -> Option<Vec<u8>> {
    let row = snapshot["requests"].as_array()?.iter().find(|row| {
        row[0] == hex::encode(request.verified.peer) && row[1] == request.verified.sequence
    })?;
    // A completed actual finish transaction, not just any retained bytes. Its
    // real PQ signature is checked against the original request by the caller.
    if row[2] != hex::encode(request.operation_id()) || row[3] != 1 {
        return None;
    }
    hex::decode(row[5].as_str()?).ok()
}

fn successful(row: &Value) -> bool {
    row["returned_before_original_deadline"] == true && row["signed_response"]["ok"] == true
}

#[test]
fn actual_pq_deadline_after_intent_preserves_owner_nonce_and_other_peer_service() {
    let mut running = Running::start();
    // Do not assert the desired cleanup before observing ALL declared honest
    // requests: current-source failure must retain the complete denominator.
    let initial = running.call("initial-target", &running.initial);
    let after_initial = capture(running.directory.path());
    let same_peer = running.call("same-peer-next-sequence-head", &running.same_peer_head);
    // A verified reply from the next socket establishes serial successor
    // handling; a client-side timeout alone does not. In the failing baseline,
    // require the first operation's real terminal record and signature in this
    // same SQLite snapshot below. finish_pq_network_request is the prior
    // handler's last mutation; socket output after it cannot change this State.
    let after_same_peer = capture(running.directory.path());
    let other_head = running.call("other-peer-head", &running.other_peer_head);
    let after_other_head = capture(running.directory.path());
    let other_submit = running.call("other-peer-honest-submit", &running.other_peer_submit);
    let after_other_submit = capture(running.directory.path());
    // Same original signed bytes and expiry. The failed operation is retained;
    // this separate socket may read its receipt, never renew/activate that request.
    let original_replay = running.call("original-exact-wire-replay", &running.initial);
    let after_replay = capture(running.directory.path());
    let retained = recorded_response(&after_same_peer, &running.initial);
    let retained_verified = retained.as_ref().map(|wire| {
        match running.policy.verify_response(
            wire,
            &running.initial.verified,
            super::super::super::now().unwrap(),
        ) {
            Ok(response) => json!({"verified":true,"response":response}),
            Err(error) => json!({"verified":false,"error":error.to_string()}),
        }
    });
    let metrics = running.finish();
    let cold = match Node::open_with_pq_network(
        running.directory.path(),
        running.settings.clone(),
        1,
        &running.policy,
    ) {
        Ok(node) => {
            let checked = node.read_active().map(
                |(tip, generation, _)| json!({"tip":hex::encode(tip),"generation":generation}),
            );
            let snapshot = capture(running.directory.path());
            json!({"opened":true,"checked_active":checked.map_err(|error|error.to_string()),"snapshot":snapshot})
        }
        Err(error) => json!({"opened":false,"error":error.to_string()}),
    };
    let target_id = hex::encode(running.target.id().unwrap());
    let honest_id = hex::encode(running.honest.id().unwrap());
    let primary = running.initial.verified.peer;
    let other = running.other_peer_head.verified.peer;
    let initial_retained = retained_verified.clone().unwrap_or(Value::Null);
    let calls = [
        &initial,
        &same_peer,
        &other_head,
        &other_submit,
        &original_replay,
    ];
    let snapshots = [
        &running.before,
        &after_initial,
        &after_same_peer,
        &after_other_head,
        &after_other_submit,
        &after_replay,
    ];
    let mut checks = vec![
        (
            "five_scheduled_calls_have_five_observations",
            calls.len() == 5,
        ),
        (
            "every_live_snapshot_known",
            snapshots
                .iter()
                .all(|row| row.get("capture_error").is_none()),
        ),
        (
            "first_actual_ten_second_deadline_elapsed",
            initial["elapsed_ns"]
                .as_u64()
                .is_some_and(|n| n >= ORIGINAL_PQ_REQUEST_SECONDS * 1_000_000_000),
        ),
        (
            "first_operation_did_not_report_success",
            initial["signed_response"]["ok"] != true,
        ),
        (
            "real_intent_for_original_target_was_terminated",
            after_same_peer["reorg"][1] == target_id && after_same_peer["reorg"][4] == 2,
        ),
        (
            "lifecycle_records_actual_pq_deadline",
            after_same_peer["lifecycle"][0][1] == 2
                && after_same_peer["lifecycle"][0][3] == "PQ_NETWORK_DEADLINE",
        ),
        (
            "cancelled_activation_did_not_change_active_state",
            after_same_peer["active"] == running.before["active"],
        ),
        (
            "retained_native_pq_failure_has_real_valid_signature",
            initial_retained["verified"] == true
                && initial_retained["response"]["ok"] == false
                && initial_retained["response"]["value"]["error"] == "PQ_NETWORK_DEADLINE",
        ),
        (
            "same_peer_new_sequence_head_succeeds",
            successful(&same_peer),
        ),
        (
            "same_peer_sequences_consumed_once",
            peer_sequence(&after_same_peer, primary) == Some(2),
        ),
        (
            "cleanup_does_not_advance_other_peer_sequence",
            peer_sequence(&after_same_peer, other) == Some(0),
        ),
        (
            "other_authorized_peer_head_succeeds",
            successful(&other_head),
        ),
        (
            "other_head_consumes_exact_first_sequence",
            peer_sequence(&after_other_head, other) == Some(1),
        ),
        (
            "other_authorized_peer_honest_submit_succeeds",
            successful(&other_submit)
                && other_submit["signed_response"]["value"]["block"] == honest_id,
        ),
        (
            "honest_submit_activates_its_original_valid_branch",
            after_other_submit["active"]["tip"] == honest_id,
        ),
        (
            "both_peers_finish_at_sequence_two",
            peer_sequence(&after_replay, primary) == Some(2)
                && peer_sequence(&after_replay, other) == Some(2),
        ),
        (
            "exact_replay_returns_same_failed_receipt",
            retained
                .as_ref()
                .is_some_and(|wire| original_replay["response_wire_hex"] == hex::encode(wire))
                && original_replay["signed_response"]["ok"] == false,
        ),
        (
            "exact_failed_replay_does_not_activate_or_advance",
            after_replay["active"] == after_other_submit["active"]
                && after_replay["requests"] == after_other_submit["requests"],
        ),
        (
            "four_distinct_signed_operations_retained",
            after_replay["requests"]
                .as_array()
                .is_some_and(|rows| rows.len() == 4),
        ),
        (
            "original_owner_lock_remains_held",
            running.before["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"] == true
                && after_same_peer["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"]
                    == true
                && after_replay["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"]
                    == true,
        ),
        (
            "no_new_metadata_credit_or_profile",
            after_replay["metadata"] == running.before["metadata"],
        ),
        (
            "cold_reopen_preserves_live_active_and_peer_ledger",
            cold["opened"] == true
                && cold["snapshot"]["active"] == after_replay["active"]
                && cold["snapshot"]["requests"] == after_replay["requests"]
                && cold["snapshot"]["peers"] == after_replay["peers"],
        ),
        (
            "actual_server_joined_without_error",
            metrics["joined"] == true && metrics.get("metrics").is_some(),
        ),
    ];
    // Only the inode/device probe is platform-specific. All five requests,
    // actual lock probes, State/nonce observations and cold reopen stay active.
    let mut checks_not_evaluated = Vec::new();
    if cfg!(unix) {
        checks.push((
            "original_namespace_and_owner_identity_preserved",
            after_replay["owner_fence"]["identity"]["supported"] == true
                && after_replay["owner_fence"]["identity"]
                    == running.before["owner_fence"]["identity"],
        ));
    } else {
        checks_not_evaluated.push("original_namespace_and_owner_identity_preserved");
    }
    let failures: Vec<_> = checks
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| *name)
        .collect();
    let honest_followups_succeeded = [&same_peer, &other_head, &other_submit]
        .iter()
        .filter(|row| successful(row))
        .count();
    println!(
        "{}",
        json!({"schema":"pq-post-intent-native-observation-v1",
        "planned_calls":5,"observed_calls":calls.len(),"honest_followups_planned":3,
        "honest_followups_succeeded":honest_followups_succeeded,
        "calls":calls,
        "before":running.before,"after_initial":after_initial,"after_same_peer":after_same_peer,
        "after_other_head":after_other_head,"after_other_submit":after_other_submit,"after_replay":after_replay,
        "retained_first_response":retained_verified,"cold":cold,"server":metrics,
        "checks":checks,"failures":failures,"checks_not_evaluated":checks_not_evaluated,
        "unix_inode_device_probe_supported":cfg!(unix),
        "scope":"real native ML-DSA and W1/M06, original production loopback PQ listener, existing injected post-intent scheduling cut and actual original ten-second deadline; no physical kill, paid-CPU, WAN or whole-chain-PQ qualification",
        "public_paid_host_qualified":false,"physical_kill_cut":false,"whole_chain_pq":false})
    );
    assert!(
        failures.is_empty(),
        "PQ post-intent cancellation violates declared recovery checks: {failures:?}"
    );
}
