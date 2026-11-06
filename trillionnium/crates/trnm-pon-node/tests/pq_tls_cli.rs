#![cfg(all(unix, feature = "pq-native-openssl"))]
use serde_json::json;
use sha2::{Digest, Sha256};
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
use trnm_pon_node::{
    ingress::{
        pq_network::{
            tls::{PqTlsClient, PqTlsIdentity, PqTlsServer},
            PqNetworkPolicy, PqTlsPins, TLS_PROFILE,
        },
        Request,
    },
    Node, Settings,
};
#[path = "../src/ingress/pq_network/tls/fixtures.rs"]
mod fixtures;
use fixtures::Fixture;

struct Running {
    child: Child,
    reader: Option<thread::JoinHandle<Vec<String>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn put(path: &Path, bytes: &[u8], private: bool) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if private { 0o600 } else { 0o644 }),
    )
    .unwrap();
}
fn command(fixture: &Fixture, directory: &Path, listen: &str) -> Command {
    let config = serde_json::to_vec(&json!({"schema":"native-pq-tls-loopback-config-v1",
        "genesis_time":fixture.settings.genesis_time(),
        "network":hex::encode(fixture.settings.network()),
        "parameters":hex::encode(fixture.settings.parameters()),
        "genesis":hex::encode(fixture.settings.genesis()),"generation":1,
        "server_spki":hex::encode(fixture.server.key.public_key_to_der().unwrap()),
        "peer_spkis":[hex::encode(fixture.peer.key.public_key_to_der().unwrap()),
            hex::encode(fixture.other.key.public_key_to_der().unwrap())],
        "ca_certificate_sha256":hex::encode(fixture.policy.tls_pins().unwrap().ca_certificate_sha256()),
        "server_name":"localhost"})).unwrap();
    put(&directory.join("config.json"), &config, false);
    put(
        &directory.join("server.pem"),
        &fixture.server.certificate.to_pem().unwrap(),
        false,
    );
    put(
        &directory.join("server-key.pem"),
        &fixture.server.key.private_key_to_pem_pkcs8().unwrap(),
        true,
    );
    put(
        &directory.join("ca.pem"),
        &fixture.ca.to_pem().unwrap(),
        false,
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .arg("pq-tls-serve")
        .arg("--development")
        .arg("--store")
        .arg(directory.join("node"))
        .arg("--listen")
        .arg(listen)
        .arg("--seconds")
        .arg("5")
        .arg("--tls-config")
        .arg(directory.join("config.json"))
        .arg("--tls-config-sha256")
        .arg(hex::encode(Sha256::digest(&config)))
        .arg("--tls-cert")
        .arg(directory.join("server.pem"))
        .arg("--tls-key")
        .arg(directory.join("server-key.pem"))
        .arg("--tls-ca")
        .arg(directory.join("ca.pem"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn ordinary_binary_pq_tls_serve_dispatches_original_node_and_preserves_replay_after_exit() {
    let fixture = Fixture::new();
    let builder_directory = tempfile::tempdir().unwrap();
    let builder = Node::open_with_pq_network(
        builder_directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let packet = builder
        .make(
            fixture.settings.genesis(),
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let block = packet.id().unwrap();
    drop(builder);
    let directory = tempfile::tempdir().unwrap();
    let mut child = command(&fixture, directory.path(), "127.0.0.1:0")
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let output = child.stdout.take().unwrap();
    let (ready, readiness) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(output).lines() {
            let line = line.unwrap();
            assert!(line.len() <= 65_536);
            if lines.is_empty() {
                let _ = ready.send(line.clone());
            }
            lines.push(line);
        }
        lines
    });
    let mut running = Running {
        child,
        reader: Some(reader),
    };
    let ready: serde_json::Value =
        serde_json::from_str(&readiness.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(ready["event"], "pq-tls-ready");
    assert_eq!(ready["profile"], TLS_PROFILE);
    assert_eq!(ready["policy"], hex::encode(fixture.policy.id()));
    assert_eq!(ready["production_activation"], false);
    assert_eq!(ready["public_history_tls"], false);
    let address = ready["listen"].as_str().unwrap().parse().unwrap();
    let client = fixture.client();
    let expiry = trnm_pon_node::ingress::now().unwrap() + 60;
    let head = client.prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(
        client
            .send(address, &head, Duration::from_secs(5))
            .unwrap()
            .value["height"],
        0
    );
    let submit = client
        .prepare(
            2,
            expiry,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let receipt = client
        .send(address, &submit, Duration::from_secs(5))
        .unwrap();
    assert!(receipt.ok);
    assert_eq!(receipt.value["block"], hex::encode(block));
    assert_eq!(
        client
            .send(address, &submit, Duration::from_secs(5))
            .unwrap(),
        receipt
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = running.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "original bounded service must exit"
        );
        thread::sleep(Duration::from_millis(2));
    };
    assert!(status.success());
    let lines = running.reader.take().unwrap().join().unwrap();
    let final_status: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(final_status["metrics"]["accepted"], 3);
    let node = Node::open_with_pq_network(
        &directory.path().join("node"),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(node.active().unwrap().0, block);
    assert_eq!(
        node.pq_network_status(&fixture.policy).unwrap()["records"],
        2
    );
    drop(node);
    // The existing ordinary classic command cannot reopen this TLS-required
    // owner through its default backend and present a plaintext listener.
    let refused = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "serve",
            "--development",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "1",
        ])
        .arg("--store")
        .arg(directory.path().join("node"))
        .arg("--genesis-time")
        .arg(fixture.settings.genesis_time().to_string())
        .output()
        .unwrap();
    assert!(!refused.status.success());
}

#[test]
fn ordinary_binary_bad_config_pin_refuses_before_owner_creation() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut process = command(&fixture, directory.path(), "127.0.0.1:0");
    // Change actual bytes after the command's explicit root commitment.
    let path = directory.path().join("config.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    put(&path, &bytes, false);
    let output = process.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_TLS_CONFIG_PIN"));
    assert!(!directory.path().join("node").exists());
}

#[test]
fn ordinary_binary_tls_nonloopback_refuses_before_config_and_owner() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut process = command(&fixture, directory.path(), "192.0.2.1:0");
    fs::remove_file(directory.path().join("config.json")).unwrap();
    let output = process.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_NETWORK_LOOPBACK_ONLY"));
    assert!(!directory.path().join("node").exists());
}
