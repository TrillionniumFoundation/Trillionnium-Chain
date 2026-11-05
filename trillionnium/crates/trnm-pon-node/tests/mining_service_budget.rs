//! Finite mining runtime must leave the actual public service available for catch-up.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Node, Packet, PoolLimits, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::lifecycle_v4::PROFILE as TASK_PROFILE,
};

fn command(name: &str, store: &Path, genesis: u64) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    c.arg(name)
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
    c
}
fn key(path: &Path, byte: u8) -> String {
    let secret = hex::encode([byte; 32]);
    fs::write(path, &secret).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    public_key_hex(&signing_key_from_hex(&secret).unwrap())
}
fn successful(c: &mut Command) -> Value {
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).unwrap()
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
fn while_serving(c: &mut Command, service: &mut Running, deadline: Instant) -> Value {
    assert!(service.0.try_wait().unwrap().is_none());
    let mut child = Running(
        c.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let read = |mut stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).unwrap();
            raw
        })
    };
    let stdout = read(Box::new(child.0.stdout.take().unwrap()));
    let stderr = read(Box::new(child.0.stderr.take().unwrap()));
    let mut failure = None;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if service.0.try_wait().unwrap().is_some() {
            failure = Some("service exited during catch-up");
        } else if Instant::now() >= deadline {
            failure = Some("catch-up phase budget exhausted");
        }
        if failure.is_some() {
            child.0.kill().unwrap();
            break child.0.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let out = Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    };
    assert!(
        failure.is_none() && out.status.success(),
        "{failure:?} status={} stderr={} stdout={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn mining_runtime_ends_before_service_and_fresh_native_follower_confirms_last_chain() {
    // These finite test budgets leave time for readiness, a paced runtime-ended
    // miner, full native catch-up and natural service exit. They are not SLAs.
    let mining_seconds = 12;
    let service_seconds = 32;
    let dir = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        TASK_PROFILE,
    )
    .unwrap();
    let owner_path = dir.path().join("owner");
    let follower_path = dir.path().join("fresh-follower");
    let server_key = dir.path().join("server.key");
    let client_key = dir.path().join("guest.key");
    let server_public = key(&server_key, 151);
    key(&client_key, 152);
    let policy_path = dir.path().join("pool.json");
    fs::write(
        &policy_path,
        serde_json::to_vec(&PoolLimits {
            max_records: 32,
            max_bytes: 65536,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 32,
            preview_miner: development_public(3).unwrap(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut payload = development_public(4).unwrap().to_vec();
    payload.extend(50u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 900,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let sender_key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&sender_key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let raw = tx.encode().unwrap();
    let tx_id = tx.id().unwrap();
    let bundle_path = dir.path().join("funding.json");
    fs::write(
        &bundle_path,
        serde_json::to_vec(&[hex::encode(&raw)]).unwrap(),
    )
    .unwrap();
    let queued = successful(
        command("pool-submit", &owner_path, genesis)
            .arg("--pool-policy")
            .arg(&policy_path)
            .arg("--transactions")
            .arg(&bundle_path),
    );
    assert_eq!(queued["result"]["state"], "Queued");
    let started = Instant::now();
    let mut service = command("serve", &owner_path, genesis)
        .args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
            "--mine",
            "--task-bootstrap",
            "--seconds",
            &service_seconds.to_string(),
            "--mining-seconds",
            &mining_seconds.to_string(),
            "--blocks",
            "100",
            "--pace-ms",
            "1000",
            "--admission-bits",
            "8",
            "--listen",
            "127.0.0.1:0",
        ])
        .arg("--pool-policy")
        .arg(&policy_path)
        .arg("--auth-secret")
        .arg(&server_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = service.stdout.take().unwrap();
    let (notify, ready) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut rows = Vec::new();
        for (index, line) in BufReader::new(stdout).lines().enumerate() {
            let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
            if index == 0 {
                notify.send(row.clone()).unwrap();
            }
            rows.push(row);
        }
        rows
    });
    let mut service = Running(service);
    let ready = ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(ready["mining_enabled"], true);
    let address = ready["address"].as_str().unwrap();
    let client = |name: &str| {
        let mut c = command(name, &follower_path, genesis);
        c.args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--admission-bits",
            "8",
            "--peer",
            address,
            "--server-public",
            &server_public,
        ])
        .arg("--auth-secret")
        .arg(&client_key);
        c
    };
    // A runtime completion is checked by the final actual MiningReport below,
    // rather than inferred from this wait or a callback. Native stages remain
    // nonpreemptive, so this guard is a test allowance, not a hard stop guarantee.
    thread::sleep(Duration::from_secs(mining_seconds + 2));
    let catchup_end = started + Duration::from_secs(service_seconds - 2);
    let head = while_serving(&mut client("head"), &mut service, catchup_end);
    assert_eq!(head["ok"], true);
    let height = head["value"]["height"].as_u64().unwrap();
    assert!((7..100).contains(&height), "{head}");
    let tip = head["value"]["tip"].as_str().unwrap();
    assert!(!follower_path.exists());
    let history = while_serving(
        client("history").arg("--tip").arg(tip),
        &mut service,
        catchup_end,
    );
    assert_eq!(history["ok"], true);
    assert_eq!(history["value"]["packets"].as_array().unwrap().len(), 1);
    let caught_up = while_serving(
        client("sync").args(["--tip", tip, "--pages", "32"]),
        &mut service,
        catchup_end,
    );
    assert_eq!(caught_up["result"]["verified_tip"], tip);
    let follower = Node::open(&follower_path, settings.clone(), 1).unwrap();
    assert_eq!(
        follower.active().unwrap().0,
        trnm_pon_node::digest(tip).unwrap()
    );
    assert_eq!(
        follower.next_nonce(development_public(0).unwrap()).unwrap(),
        2
    );
    let state = follower.read_active().unwrap().2;
    assert_eq!(
        state[&format!("account:{}", hex::encode(development_public(4).unwrap()))]["balance"],
        50
    );
    let mut cursor = follower.active().unwrap().0;
    let included = loop {
        let packet = follower.packet(cursor).unwrap();
        if packet.transactions.contains(&raw) {
            break cursor;
        }
        cursor = packet.header.parent;
        assert_ne!(cursor, settings.genesis());
    };
    let confirmation = follower
        .confirmation(tx_id, included, ingress::now().unwrap())
        .unwrap();
    assert!(confirmation.confirmed && !confirmation.reorged);
    assert!(!confirmation.finalized && !confirmation.execution_authority);
    // The default History request above reads the first page. Now request the
    // actual final packet from its independently admitted native parent.
    let final_packet = follower
        .packet(trnm_pon_node::digest(tip).unwrap())
        .unwrap();
    let final_page = while_serving(
        client("history").args([
            "--tip",
            tip,
            "--after",
            &hex::encode(final_packet.header.parent),
        ]),
        &mut service,
        catchup_end,
    );
    assert_eq!(final_page["ok"], true);
    assert_eq!(final_page["value"]["complete"], true);
    assert_eq!(final_page["value"]["next"], tip);
    let returned = final_page["value"]["packets"].as_array().unwrap();
    assert_eq!(returned.len(), 1);
    let returned = hex::decode(returned[0].as_str().unwrap()).unwrap();
    assert_eq!(returned, final_packet.encode().unwrap());
    assert_eq!(
        hex::encode(Packet::decode(&returned).unwrap().id().unwrap()),
        tip
    );
    drop(follower);
    let after_sync = while_serving(&mut client("head"), &mut service, catchup_end);
    assert_eq!(after_sync["value"], head["value"]);
    let shutdown_end = started + Duration::from_secs(service_seconds + 2);
    let status = loop {
        if let Some(status) = service.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < shutdown_end, "service failed to stop");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    let rows = reader.join().unwrap();
    let report = rows.last().unwrap();
    assert_eq!(report["mining"]["stop_reason"], "runtime");
    assert_eq!(report["mining"]["activated_blocks"], height);
    assert_eq!(report["mining"]["included_transactions"], 1);
    assert_eq!(report["public_network_ready"], false);
    assert_eq!(report["production_activation"], false);
    let owner = Node::open(&owner_path, settings, 1).unwrap();
    let follower = Node::open(&follower_path, owner.settings().clone(), 1).unwrap();
    assert_eq!(
        owner.read_active().unwrap().2,
        follower.read_active().unwrap().2
    );
    assert_eq!(owner.active().unwrap().0, follower.active().unwrap().0);
    assert_eq!(
        owner.stats().unwrap()["chainwork_hex"],
        follower.stats().unwrap()["chainwork_hex"]
    );
    assert_eq!(
        owner.stats().unwrap()["authenticated_outbox_sessions"],
        json!(0)
    );
    println!(
        "{}",
        json!({"schema":"mining-service-budget-test-observation-v1",
            "mining_seconds":mining_seconds,"service_seconds":service_seconds,
            "stop_reason":report["mining"]["stop_reason"],"activated_blocks":height,
            "actual_mining_elapsed_ns":report["mining"]["actual_elapsed_ns"],
            "included_transactions":1,"fresh_native_sync_after_mining":true,
            "final_packet_history_bytes_equal":true,
            "complete_state_equal":true,"sender_next_nonce":2,"confirmed":confirmation.confirmed,
            "public_network_ready":false,"production_activation":false,
            "scope":"finite same-host actual CLI/socket control; elapsed is not CPU, a hard deadline or independent WAN acceptance"})
    );
}

#[test]
fn invalid_or_unused_mining_runtime_refuses_before_store_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("absent");
    for (name, options, error) in [
        (
            "serve",
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--mine",
                "--mining-seconds",
                "0",
            ],
            "MINING_RUNTIME",
        ),
        (
            "serve",
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--mine",
                "--seconds",
                "2",
                "--mining-seconds",
                "3",
            ],
            "MINING_RUNTIME",
        ),
        (
            "serve",
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--mine",
                "--seconds",
                "300000",
                "--mining-seconds",
                "300000",
            ],
            "MINING_RUNTIME",
        ),
        (
            "serve",
            vec![
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--mining-seconds",
                "1",
            ],
            "MINING_OPTIONS_REQUIRE_MINE",
        ),
        (
            "serve",
            vec![
                "--admission-profile",
                ingress::public_v2::PROFILE,
                "--mine",
                "--mining-seconds",
                "1",
            ],
            "PUBLIC_V3_REQUIRED",
        ),
        (
            "serve",
            vec!["--mine", "--mining-seconds", "1"],
            "PUBLIC_V3_REQUIRED",
        ),
        (
            "mine-loop",
            vec!["--mining-seconds", "1"],
            "UNKNOWN_OPTION:--mining-seconds",
        ),
    ] {
        let out = command(name, &store, 1_700_000_000)
            .args(options)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!store.exists(), "invalid runtime created a namespace");
    }
}
