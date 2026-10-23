//! Original serve process owns the native growth store and protected-v3 lanes.
#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use trnm_pon_node::{
    ingress::{
        public_v3::{self, PublicPolicy, Request},
        DevelopmentIdentity,
    },
    Settings,
};

fn command(store: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.args([
        "serve",
        "--development",
        "--public-development-network",
        "--state-backend",
        "permanent-account-growth-native-v2",
        "--admission-profile",
        public_v3::GROWTH_PROFILE,
        "--growth-namespace",
        "growth-public-cli-v1",
        "--genesis-time",
        "1",
    ])
    .arg("--store")
    .arg(store);
    cmd
}

fn client(command: &str, listening: &Value, key: &Path) -> Command {
    client_with_deadline(command, listening, key, "8000")
}
fn client_with_deadline(
    command: &str,
    listening: &Value,
    key: &Path,
    milliseconds: &str,
) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.args([
        command,
        "--development",
        "--admission-profile",
        public_v3::GROWTH_PROFILE,
        "--growth-namespace",
        "growth-public-cli-v1",
        "--genesis-time",
        "1",
        "--peer",
        listening["address"].as_str().unwrap(),
        "--server-public",
        listening["server_public"].as_str().unwrap(),
        "--resource-profile-sha256",
        listening["admission_profile_digest"].as_str().unwrap(),
        "--admission-bits",
        "8",
        "--request-deadline-ms",
        milliseconds,
    ])
    .arg("--auth-secret")
    .arg(key);
    cmd
}
fn accepted(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "pon-native-growth-remote-client-result-v1");
    assert_eq!(value["verified_signed_response"], true);
    assert_eq!(value["response"]["ok"], true, "{value}");
    value
}

fn bounded_input_exit(mut child: Child, started: Instant) -> Output {
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if started.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "growth client blocked on input: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn growth_public_cli_still_open_stdin_obeys_command_deadline_before_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("caller.secret");
    std::fs::write(&key, hex::encode([113u8; 32])).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    // No server accepts these connections. An actual attempted connect would
    // remain in this kernel listener's queue and fail the assertion below.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = DevelopmentIdentity::from_secret_hex(&hex::encode([114u8; 32])).unwrap();
    let listening = serde_json::json!({"address":listener.local_addr().unwrap().to_string(),
        "server_public":server.public_key(), "admission_profile_digest":hex::encode(policy.growth_id())});
    for operation in ["push", "packet-status"] {
        let started = Instant::now();
        let mut child = client_with_deadline(operation, &listening, &key, "150")
            .arg("--packet-stdin")
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        // Keep the pipe's write end alive through observed child exit: no EOF
        // or reader helper is available to make a blocking read finish.
        let output = bounded_input_exit(child, started);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("PUBLIC_CLIENT_DEADLINE"));
        assert!(output.stdout.is_empty());
        drop(input);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "input refusal created local store files"
        );
    }
}

#[test]
fn growth_public_cli_packet_file_rejects_fifo_symlink_and_oversize_before_dispatch() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("caller.secret");
    std::fs::write(&key, hex::encode([115u8; 32])).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = DevelopmentIdentity::from_secret_hex(&hex::encode([116u8; 32])).unwrap();
    let listening = serde_json::json!({"address":listener.local_addr().unwrap().to_string(),
        "server_public":server.public_key(), "admission_profile_digest":hex::encode(policy.growth_id())});
    let fifo = directory.path().join("packet.fifo");
    let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid nul-terminated private temporary pathname is provided.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let linked = directory.path().join("packet.link");
    symlink(&key, &linked).unwrap();
    let oversized = directory.path().join("packet.large");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(1_048_577)
        .unwrap();
    for (packet, error) in [
        (&fifo, "PUBLIC_GROWTH_PACKET_FILE"),
        (&linked, "PUBLIC_GROWTH_PACKET_FILE"),
        (&oversized, "INPUT_LIMIT"),
    ] {
        let started = Instant::now();
        let child = client_with_deadline("push", &listening, &key, "2000")
            .arg("--packet")
            .arg(packet)
            .current_dir(directory.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = bounded_input_exit(child, started);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(error));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 4);
}

#[test]
fn growth_public_cli_refuses_unsupported_owner_and_pool_before_store_creation() {
    let dir = tempfile::tempdir().unwrap();
    for (index, extra) in [
        vec!["--pool-policy", "not-read.json"],
        vec!["--mine"],
        vec!["--peers", "not-read.json"],
        vec!["--operator-task-mode", "restricted"],
        vec!["--task-profile", "legacy-task-v1"],
    ]
    .into_iter()
    .enumerate()
    {
        let store = dir.path().join(index.to_string());
        let output = command(&store).args(extra).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("PUBLIC_GROWTH_UNSUPPORTED_OPTIONS")
        );
        assert!(!store.exists(), "unsupported mode created a store");
    }
}

#[test]
fn growth_public_cli_original_serve_exposes_fixed_growth_head() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("receiver");
    let secret = dir.path().join("server.secret");
    std::fs::write(&secret, hex::encode([111u8; 32])).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("growth-public-cli-v1")
    .unwrap();
    let producer = trnm_pon_node::Node::open_with_permanent_account_growth_v2(
        &dir.path().join("producer"),
        settings.clone(),
    )
    .unwrap();
    let packet = producer
        .make_growth_consensus_maintenance(
            settings.genesis(),
            vec![],
            trnm_pon_node::development_public(3).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let bytes = packet.encode().unwrap();
    let packet_file = dir.path().join("packet.pnp2");
    std::fs::write(&packet_file, &bytes).unwrap();
    let mut child = command(&store)
        .arg("--auth-secret")
        .arg(&secret)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "10",
            "--admission-bits",
            "8",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    if line.is_empty() {
        let output = child.wait_with_output().unwrap();
        panic!(
            "serve did not listen: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let listening: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(listening["admission_profile"], public_v3::GROWTH_PROFILE);
    assert!(listening["pool_context"].is_null());
    assert_eq!(listening["mining_enabled"], false);
    assert_eq!(listening["peer_polling_enabled"], false);
    assert_eq!(listening["production_activation"], false);
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    assert_eq!(
        listening["admission_profile_digest"],
        hex::encode(policy.growth_id())
    );
    let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([112u8; 32])).unwrap();
    let reply = public_v3::call_public_protected_growth_v1(
        listening["address"].as_str().unwrap().parse().unwrap(),
        &Request::GrowthHeadV1,
        &settings,
        listening["server_public"].as_str().unwrap(),
        &caller,
        policy,
        None,
    )
    .0
    .unwrap();
    assert!(reply.ok);
    assert_eq!(reply.value["height"], 0);
    assert_eq!(reply.value["genesis"], hex::encode(settings.genesis()));
    let client_key = dir.path().join("caller.secret");
    std::fs::write(&client_key, hex::encode([112u8; 32])).unwrap();
    std::fs::set_permissions(&client_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = accepted(
        client("packet-status", &listening, &client_key)
            .arg("--packet")
            .arg(&packet_file)
            .output()
            .unwrap(),
    );
    assert_eq!(before["operation"], "growth_packet_status_v1");
    assert_eq!(before["response"]["value"]["stored_exact"], false);
    let submitted = accepted(
        client("push", &listening, &client_key)
            .arg("--packet")
            .arg(&packet_file)
            .output()
            .unwrap(),
    );
    assert_eq!(submitted["response"]["value"]["admitted"], true);
    assert_eq!(
        submitted["response"]["value"]["active"],
        hex::encode(packet.id().unwrap())
    );
    let mut status = client("packet-status", &listening, &client_key)
        .arg("--packet-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    status.stdin.take().unwrap().write_all(&bytes).unwrap();
    let observed = accepted(status.wait_with_output().unwrap());
    assert_eq!(observed["response"]["value"]["active_chain_member"], true);
    assert!(observed["response"]["value"]["accepted_task"].is_null());
    let head = accepted(client("head", &listening, &client_key).output().unwrap());
    assert_eq!(head["response"]["value"]["height"], 1);
    let unwanted = dir.path().join("must-not-open");
    let rejected = client("head", &listening, &client_key)
        .arg("--store")
        .arg(&unwanted)
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("PUBLIC_GROWTH_CLIENT_OPTIONS"));
    assert!(!unwanted.exists());
    let mut wrong_pin = listening.clone();
    wrong_pin["admission_profile_digest"] = Value::String("00".repeat(32));
    let rejected = client("head", &wrong_pin, &client_key).output().unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("PUBLIC_GROWTH_RESOURCE_PIN"));
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reopened = trnm_pon_node::Node::open_growth_packet_observer(&store, settings).unwrap();
    assert_eq!(reopened.active().unwrap().0, packet.id().unwrap());
}
