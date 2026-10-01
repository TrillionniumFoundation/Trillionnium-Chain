//! Actual guest CLI -> durable pool -> shared wall-clock miner -> full native sync.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Node, PoolLimits, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::lifecycle_v3::{AtomicRenewTaskV3, PROFILE as TASK_PROFILE},
};

fn command(name: &str, store: &Path, genesis: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .arg(name)
        .args([
            "--development",
            "--genesis-time",
            &genesis.to_string(),
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            TASK_PROFILE,
        ])
        .arg("--store")
        .arg(store);
    command
}
fn successful(command: &mut Command) -> Value {
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn signature(who: u64, message: &[u8]) -> [u8; 64] {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    hex::decode(sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn envelope(settings: &Settings, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(who).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
fn key(path: &Path, byte: u8) -> String {
    let secret = hex::encode([byte; 32]);
    fs::write(path, &secret).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    public_key_hex(&signing_key_from_hex(&secret).unwrap())
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

#[test]
fn actual_v3_cli_unknown_guest_funding_and_atomic_renewal_reach_native_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        TASK_PROFILE,
    )
    .unwrap();
    let store = dir.path().join("owner");
    let receiver = dir.path().join("receiver");
    let secret = dir.path().join("server.key");
    let guest = dir.path().join("guest.key");
    let public = key(&secret, 111);
    key(&guest, 112);
    let policy = dir.path().join("pool.json");
    let limits = PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: development_public(3).unwrap(),
    };
    fs::write(&policy, serde_json::to_vec(&limits).unwrap()).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let mut payload = development_public(4).unwrap().to_vec();
    payload.extend(1000u64.to_le_bytes());
    let funding = envelope(&settings, 0, 1, 1, payload);
    let mut payload = development_public(2).unwrap().to_vec();
    payload.extend(50u64.to_le_bytes());
    let spend = envelope(&settings, 4, 1, 1, payload);
    let boot = settings.bootstrap_lifecycle_task().unwrap();
    let mut lease = boot.lease;
    lease.revision += 1;
    // V3 requires this exact containing height. The client waits for the
    // first native block below, then submits before the next paced attempt.
    // Do not relax native window checks for the fixture.
    lease.not_before = 2;
    lease.expires = 1001;
    lease.available_until = 1101;
    let mut signed = boot.signed;
    signed.lease_id = lease.id().unwrap();
    signed.manifest.source_record = lease.bound_source_record().unwrap();
    signed.manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    signed.manifest.not_before = lease.not_before;
    signed.manifest.expires = lease.expires;
    signed.manifest.available_until = lease.available_until;
    signed.manifest.demand_nonce = 2;
    signed.signature = signature(0, &signed.signing_message().unwrap());
    let renew = envelope(
        &settings,
        1,
        1,
        22,
        AtomicRenewTaskV3 {
            lease,
            signed: signed.clone(),
        }
        .encode()
        .unwrap(),
    );
    let raws = vec![funding, spend, renew];
    let file = dir.path().join("bundle.json");
    fs::write(
        &file,
        serde_json::to_vec(&raws.iter().map(hex::encode).collect::<Vec<_>>()).unwrap(),
    )
    .unwrap();
    let mut child = command("serve", &store, genesis)
        .args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
            "--mine",
            "--task-bootstrap",
            "--seconds",
            "12",
            "--blocks",
            "8",
            "--pace-ms",
            "1000",
            "--admission-bits",
            "8",
            "--listen",
            "127.0.0.1:0",
        ])
        .arg("--pool-policy")
        .arg(&policy)
        .arg("--auth-secret")
        .arg(&secret)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut running = Running(child);
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        tx.send(lines.next().unwrap().unwrap()).unwrap();
        lines.collect::<std::io::Result<Vec<_>>>().unwrap()
    });
    let ready: Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(ready["mining_enabled"], true);
    assert_eq!(ready["server_public"], public);
    let address = ready["address"].as_str().unwrap();
    let context = ready["pool_context"].as_str().unwrap();
    let client = |name: &str| {
        let mut c = command(name, &receiver, genesis);
        c.args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--peer",
            address,
            "--server-public",
            &public,
            "--admission-bits",
            "8",
        ])
        .arg("--auth-secret")
        .arg(&guest);
        c
    };
    // Atomic V3 verifies the successor statement at its actual containing
    // height. Wait for the first native block before submitting the height2
    // successor; never pretend that a future-height statement is valid in block1.
    let first_end = Instant::now() + Duration::from_secs(2);
    loop {
        let first = successful(&mut client("head"));
        let height = first["value"]["height"].as_u64().unwrap();
        if height == 1 {
            break;
        }
        assert_eq!(height, 0);
        assert!(
            Instant::now() < first_end,
            "first actual mining block missing"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let refused = client("pool-push")
        .arg("--client-observations")
        .arg("--transactions")
        .arg(&file)
        .args(["--pool-context", &"ab".repeat(32)])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    let denial: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(denial["ok"], false);
    let observation: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(observation["observations"]["failed_stage"], Value::Null);
    assert_eq!(observation["observations"]["solution_found"], true);
    assert!(denial["value"].to_string().contains("PUBLIC_POOL_CONTEXT"));
    let submitted = successful(
        client("pool-push")
            .arg("--transactions")
            .arg(&file)
            .args(["--pool-context", context]),
    );
    assert_eq!(submitted["ok"], true);
    assert_eq!(submitted["value"]["receipt"]["state"], "Queued");
    assert!(
        !receiver.exists(),
        "remote submission must not create a second local owner"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let head = loop {
        let snapshot = successful(&mut client("pool-status-remote"));
        let head = successful(&mut client("head"));
        if snapshot["value"]["sequence_consumed_groups"] == 1
            && head["value"]["height"].as_u64().unwrap() >= 3
        {
            break head;
        }
        assert!(
            Instant::now() < deadline,
            "signed bundle did not reach an actual block: snapshot={snapshot} head={head}"
        );
        thread::sleep(Duration::from_millis(40));
    };
    let tip = head["value"]["tip"].as_str().unwrap();
    let synced = successful(client("sync").args(["--tip", tip, "--pages", "16"]));
    assert_eq!(synced["result"]["verified_tip"], tip);
    assert_eq!(
        synced["result"]["state"]["state_root"],
        head["value"]["state_root"]
    );
    let receiver_node = Node::open(&receiver, settings.clone(), 1).unwrap();
    assert_eq!(
        receiver_node
            .next_nonce(development_public(4).unwrap())
            .unwrap(),
        2
    );
    let state = receiver_node
        .state_at(receiver_node.active().unwrap().0)
        .unwrap();
    assert_eq!(
        state[&trnm_mvcc_fee::qualified_task_lifecycle::slot_key(0).unwrap()]["statement"],
        hex::encode(signed.encode().unwrap())
    );
    assert_eq!(
        receiver_node.stats().unwrap()["authenticated_outbox_sessions"],
        0
    );
    drop(receiver_node);
    // A completed finite miner must leave its last block retrievable while the
    // service still has a budget. This is necessary for peer catch-up.
    let catchup_end = Instant::now() + Duration::from_secs(7);
    let final_head = loop {
        let head = successful(&mut client("head"));
        if head["value"]["height"] == 8 {
            break head;
        }
        assert!(
            Instant::now() < catchup_end,
            "miner did not reach its finite limit"
        );
        thread::sleep(Duration::from_millis(50));
    };
    let final_tip = final_head["value"]["tip"].as_str().unwrap();
    let caught_up =
        successful(client("sync").args(["--tip", final_tip, "--after", tip, "--pages", "16"]));
    assert_eq!(caught_up["result"]["verified_tip"], final_tip);
    assert_eq!(
        caught_up["result"]["state"]["state_root"],
        final_head["value"]["state_root"]
    );
    assert!(running.0.wait().unwrap().success());
    let lines = reader.join().unwrap();
    let rows: Vec<Value> = lines
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let final_row = rows.last().unwrap();
    assert_eq!(final_row["mining"]["activated_blocks"], 8);
    assert_eq!(final_row["mining"]["included_transactions"], 3);
    assert_eq!(final_row["public_network_ready"], false);
    let owner = Node::open(&store, settings, 1).unwrap();
    let mut cursor = owner.active().unwrap().0;
    let mut observed = Vec::new();
    while owner.parent_height(cursor).unwrap() > 0 {
        let p = owner.packet(cursor).unwrap();
        observed.extend(p.transactions);
        cursor = p.header.parent;
    }
    assert_eq!(observed, raws);
    assert_eq!(
        owner.stats().unwrap()["authenticated_outbox_sessions"],
        json!(0)
    );
}

#[test]
fn v3_mining_options_refuse_v2_and_unused_or_logical_clock_options() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    for (options, error) in [
        (
            vec!["--admission-profile", ingress::public_v2::PROFILE, "--mine"],
            "PUBLIC_V3_REQUIRED",
        ),
        (
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--task-bootstrap",
            ],
            "MINING_OPTIONS_REQUIRE_MINE",
        ),
        (
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--mine",
                "--logical-now",
                "1800000000",
            ],
            "NETWORK_USES_LOCAL_WALL_CLOCK",
        ),
    ] {
        let out = command("serve", &store, 1700000000)
            .args(options)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains(error));
    }
    assert!(!store.exists());
}

fn reading_service(
    mut child: Child,
) -> (
    Running,
    mpsc::Receiver<String>,
    thread::JoinHandle<Vec<String>>,
) {
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        tx.send(lines.next().unwrap().unwrap()).unwrap();
        lines.collect::<std::io::Result<Vec<_>>>().unwrap()
    });
    (Running(child), rx, reader)
}

#[test]
fn actual_pinned_peer_cli_follows_native_blocks_and_closes_shared_owner() {
    use trnm_pon_node::peer_polling::{PeerPollingConfig, PinnedPeer, PEER_POLLING_SCHEMA};
    let dir = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        TASK_PROFILE,
    )
    .unwrap();
    let source_store = dir.path().join("source");
    let receiver_store = dir.path().join("receiver");
    let source_key = dir.path().join("source.key");
    let receiver_key = dir.path().join("receiver.key");
    let source_public = key(&source_key, 121);
    key(&receiver_key, 122);
    let policy = dir.path().join("pool.json");
    fs::write(
        &policy,
        serde_json::to_vec(&PoolLimits {
            max_records: 16,
            max_bytes: 65536,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: development_public(3).unwrap(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let source_child = command("serve", &source_store, genesis)
        .args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
            "--mine",
            "--task-bootstrap",
            "--seconds",
            "6",
            "--blocks",
            "3",
            "--pace-ms",
            "1000",
            "--admission-bits",
            "8",
            "--listen",
            "127.0.0.1:0",
        ])
        .arg("--pool-policy")
        .arg(&policy)
        .arg("--auth-secret")
        .arg(&source_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let (mut source, source_rx, source_reader) = reading_service(source_child);
    let ready: Value =
        serde_json::from_str(&source_rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    let config = PeerPollingConfig {
        schema: PEER_POLLING_SCHEMA.into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        transport_profile: hex::encode(
            ingress::public_v3::PublicPolicy::new(8, Duration::from_millis(2000))
                .unwrap()
                .id(),
        ),
        bits: 8,
        lifetime_ms: 2000,
        peers: vec![PinnedPeer {
            address: ready["address"].as_str().unwrap().parse().unwrap(),
            server_public: source_public,
        }],
        poll_interval_ms: 200,
        runtime_ms: 10000,
        max_calls: 128,
        max_pages_per_cycle: 2,
    };
    let peers = dir.path().join("peers.json");
    fs::write(&peers, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&peers, fs::Permissions::from_mode(0o600)).unwrap();
    let receiver_child = command("serve", &receiver_store, genesis)
        .args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
            "--seconds",
            "5",
            "--admission-bits",
            "8",
            "--listen",
            "127.0.0.1:0",
            "--peer-pages",
            "1",
        ])
        .arg("--pool-policy")
        .arg(&policy)
        .arg("--auth-secret")
        .arg(&receiver_key)
        .arg("--peers")
        .arg(&peers)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let (mut receiver, receiver_rx, receiver_reader) = reading_service(receiver_child);
    let received_ready: Value =
        serde_json::from_str(&receiver_rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    let mut actual_config = config.clone();
    actual_config.runtime_ms = 5000;
    actual_config.max_pages_per_cycle = 1;
    assert_eq!(
        received_ready["peer_polling_context"],
        hex::encode(actual_config.context().unwrap())
    );
    assert_eq!(received_ready["mining_enabled"], false);
    assert_eq!(received_ready["peer_polling_enabled"], true);
    assert!(receiver.0.wait().unwrap().success());
    let receiver_lines = receiver_reader.join().unwrap();
    let report: Value = serde_json::from_str(receiver_lines.last().unwrap()).unwrap();
    assert_eq!(report["peer_polling"]["verified_new_packets"], 3);
    assert_eq!(report["peer_polling"]["transport_errors"], 0);
    assert_eq!(report["public_network_ready"], false);
    assert!(source.0.wait().unwrap().success());
    source_reader.join().unwrap();
    let source_node = Node::open(&source_store, settings.clone(), 1).unwrap();
    let receiver_node = Node::open(&receiver_store, settings, 1).unwrap();
    let source_state = source_node.stats().unwrap();
    let receiver_state = receiver_node.stats().unwrap();
    for key in ["height", "tip", "state_root", "chainwork_hex"] {
        assert_eq!(source_state[key], receiver_state[key]);
    }
    assert_eq!(receiver_state["height"], 3);
    assert_eq!(
        source_node
            .packet(source_node.active().unwrap().0)
            .unwrap()
            .encode()
            .unwrap(),
        receiver_node
            .packet(receiver_node.active().unwrap().0)
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn peer_cli_rejects_unused_options_and_wrong_context_before_store_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    for options in [
        vec![
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--peer-pages",
            "1",
        ],
        vec![
            "--admission-profile",
            ingress::public_v2::PROFILE,
            "--peers",
            "unused",
        ],
    ] {
        let out = command("serve", &store, 1700000000)
            .args(options)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!store.exists());
    }
    let invalid = dir.path().join("invalid.json");
    fs::write(&invalid, b"{\"schema\":\"unknown\"}").unwrap();
    let out = command("serve", &store, 1700000000)
        .args(["--admission-profile", ingress::public_v3::PROFILE])
        .arg("--peers")
        .arg(&invalid)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!store.exists());
}
