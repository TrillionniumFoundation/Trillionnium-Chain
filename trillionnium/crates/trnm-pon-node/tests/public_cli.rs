//! Exercise the actual executable and its public transport, including shell failures.
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex};
use trnm_pon_node::{ingress::public_v2::PROFILE, Node, Settings};

fn command(name: &str, store: &Path, genesis: u64) -> Command {
    task_command(name, store, genesis, "signed-task-dev-v1")
}
fn task_command(name: &str, store: &Path, genesis: u64, profile: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    c.arg(name)
        .args(["--development", "--genesis-time", &genesis.to_string()])
        .arg("--store")
        .arg(store)
        .args([
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            profile,
        ]);
    c
}
fn successful(c: &mut Command) -> Value {
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn failure(out: Output, expected: &str) {
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn key(path: &Path, n: u8) -> String {
    let secret = hex::encode([n; 32]);
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
fn actual_public_cli_pins_server_denials_fail_and_sync_verifies_native_history() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 100;
    let producer = dir.path().join("producer");
    let validator = dir.path().join("validator");
    let confirmer = dir.path().join("confirmer");
    let server_secret = dir.path().join("server.key");
    let caller_secret = dir.path().join("unknown.key");
    let server_public = key(&server_secret, 83);
    key(&caller_secret, 84);
    let mut packets = Vec::new();
    for index in 0..2 {
        let packet = dir.path().join(format!("{index}.pnk1"));
        successful(
            command("mine", &producer, genesis)
                .args([
                    "--task-bootstrap",
                    "--timestamp",
                    &(genesis + 10 + index * 10).to_string(),
                ])
                .arg("--output")
                .arg(&packet),
        );
        packets.push(packet);
    }
    let expected = successful(&mut command("status", &producer, genesis))["result"].clone();
    let mut process = command("serve", &validator, genesis)
        .args([
            "--admission-profile",
            PROFILE,
            "--public-development-network",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "12",
            "--admission-bits",
            "8",
        ])
        .arg("--auth-secret")
        .arg(&server_secret)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = process.stdout.take().unwrap();
    let mut running = Running(process);
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        tx.send(lines.next().unwrap().unwrap()).unwrap();
        lines.collect::<std::io::Result<Vec<_>>>().unwrap()
    });
    let ready: Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(ready["identity_authority"], false);
    assert_eq!(ready["public_network_ready"], false);
    assert_eq!(ready["server_public"], server_public);
    let address = ready["address"].as_str().unwrap();
    let client = |name: &str, store: &Path| {
        let mut c = command(name, store, genesis);
        c.args([
            "--admission-profile",
            PROFILE,
            "--peer",
            address,
            "--server-public",
            &server_public,
            "--admission-bits",
            "8",
        ])
        .arg("--auth-secret")
        .arg(&caller_secret);
        c
    };
    let head = successful(&mut client("head", &confirmer));
    assert_eq!(head["ok"], true);
    assert_eq!(head["value"]["height"], 0);
    assert_eq!(head["identity_authority"], false);
    assert!(head["solve_trials"].as_u64().unwrap() > 0);
    for packet in &packets {
        let value = successful(client("push", &producer).arg("--packet").arg(packet));
        assert_eq!(value["ok"], true);
    }
    let tip = expected["tip"].as_str().unwrap();
    let denied = client("history", &confirmer)
        .args(["--tip", tip, "--after", &"fe".repeat(32)])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(2));
    let denial: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denial["ok"], false);
    assert!(denial["body_bytes_sent"].as_u64().unwrap() > 0);
    let synced = successful(client("sync", &confirmer).args(["--tip", tip, "--pages", "2"]));
    assert_eq!(synced["result"]["verified_tip"], tip);
    for field in [
        "tip",
        "height",
        "state_root",
        "network",
        "parameters",
        "chainwork_hex",
    ] {
        assert_eq!(synced["result"]["state"][field], expected[field]);
    }
    // A new connection with a wrong trusted key must fail before sending its body.
    let mut wrong = command("head", &confirmer, genesis);
    wrong
        .args([
            "--admission-profile",
            PROFILE,
            "--peer",
            address,
            "--server-public",
            &key(&dir.path().join("other.key"), 85),
            "--admission-bits",
            "8",
        ])
        .arg("--auth-secret")
        .arg(&caller_secret);
    let out = wrong.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    // Unknown transport identities never acquire durable authenticated authority.
    let local = Node::open(
        &confirmer,
        Settings::development_with_profiles(
            Some(genesis),
            "native-public-evaluation-dev-v1",
            "signed-task-dev-v1",
        )
        .unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(local.stats().unwrap()["authenticated_outbox_sessions"], 0);
    drop(local);
    assert!(running.0.wait().unwrap().success());
    let final_lines = reader.join().unwrap();
    let final_value: Value = serde_json::from_str(final_lines.last().unwrap()).unwrap();
    assert_eq!(final_value["public_network_ready"], false);
}
#[test]
fn public_cli_requires_explicit_profile_and_rejects_private_session_options() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let secret = dir.path().join("secret.key");
    key(&secret, 86);
    let genesis = 1_700_000_000;
    failure(
        command("serve", &store, genesis)
            .args(["--admission-profile", PROFILE])
            .arg("--auth-secret")
            .arg(&secret)
            .output()
            .unwrap(),
        "EXPLICIT_PUBLIC_DEVELOPMENT_REQUIRED",
    );
    failure(
        command("serve", &store, genesis)
            .args([
                "--admission-profile",
                PROFILE,
                "--public-development-network",
                "--session-generation",
                "1",
            ])
            .arg("--auth-secret")
            .arg(&secret)
            .output()
            .unwrap(),
        "PUBLIC_IDENTITY_OPTIONS",
    );
    failure(
        command("head", &store, genesis).output().unwrap(),
        "PUBLIC_PROFILE_REQUIRED",
    );
    failure(
        command("head", &store, genesis)
            .args(["--admission-profile", "public-protected-development-v99"])
            .output()
            .unwrap(),
        "ADMISSION_PROFILE",
    );
    failure(
        command("head", &store, genesis)
            .args([
                "--admission-profile",
                PROFILE,
                "--logical-now",
                "1700000001",
            ])
            .output()
            .unwrap(),
        "NETWORK_USES_LOCAL_WALL_CLOCK",
    );
}

#[test]
fn actual_cli_explicit_v3_bootstrap_mines_and_refuses_v2_namespace_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("v3");
    let output = dir.path().join("v3.pnk1");
    let genesis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 100;
    let value = successful(
        task_command("mine", &store, genesis, "signed-task-lifecycle-dev-v3")
            .arg("--task-bootstrap")
            .arg("--output")
            .arg(&output)
            .args(["--timestamp", &(genesis + 10).to_string()]),
    );
    assert_eq!(value["result"]["state"]["height"], 1);
    assert_eq!(value["result"]["admitted"], true);
    let before = fs::read(store.join("native.sqlite")).unwrap();
    let refused = task_command("status", &store, genesis, "signed-task-lifecycle-dev-v2")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(!refused.stderr.is_empty());
    assert_eq!(fs::read(store.join("native.sqlite")).unwrap(), before);
    let reopened = successful(&mut task_command(
        "recover",
        &store,
        genesis,
        "signed-task-lifecycle-dev-v3",
    ));
    assert_eq!(reopened["result"]["tip"], value["result"]["state"]["tip"]);
}
