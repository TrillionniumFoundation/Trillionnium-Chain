use super::*;
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

pub(super) fn put(path: &Path, bytes: &[u8], private: bool) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if private { 0o600 } else { 0o644 }),
    )
    .unwrap();
}
pub(super) fn history_policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_millis(2000)).unwrap()
}
pub(super) fn command(
    fixture: &Fixture,
    files: &Path,
    store: &Path,
    name: &str,
    server: bool,
) -> Command {
    let config = serde_json::to_vec(&json!({"schema":"native-pq-tls-loopback-config-v1",
        "genesis_time":fixture.settings.genesis_time(),
        "network":hex::encode(fixture.settings.network()),
        "parameters":hex::encode(fixture.settings.parameters()),
        "genesis":hex::encode(fixture.settings.genesis()),"generation":1,
        "server_spki":hex::encode(fixture.server.key.public_key_to_der().unwrap()),
        "peer_spkis":[hex::encode(fixture.peer.key.public_key_to_der().unwrap()),
            hex::encode(fixture.other.key.public_key_to_der().unwrap())],
        "ca_certificate_sha256":hex::encode(fixture.policy.tls_pins().unwrap().ca_certificate_sha256()),
        "server_name":fixture.policy.tls_pins().unwrap().server_name()})).unwrap();
    let identity = if server {
        &fixture.server
    } else {
        &fixture.peer
    };
    put(&files.join("config.json"), &config, false);
    put(
        &files.join("identity.pem"),
        &identity.certificate.to_pem().unwrap(),
        false,
    );
    put(
        &files.join("key.pem"),
        &identity.key.private_key_to_pem_pkcs8().unwrap(),
        true,
    );
    put(&files.join("ca.pem"), &fixture.ca.to_pem().unwrap(), false);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .arg(name)
        .arg("--development")
        .arg("--store")
        .arg(store)
        .arg("--tls-config")
        .arg(files.join("config.json"))
        .arg("--tls-config-sha256")
        .arg(hex::encode(Sha256::digest(&config)))
        .arg("--tls-cert")
        .arg(files.join("identity.pem"))
        .arg("--tls-key")
        .arg(files.join("key.pem"))
        .arg("--tls-ca")
        .arg(files.join("ca.pem"))
        .args(["--admission-bits", "8", "--admission-ttl-ms", "2000"])
        .arg("--history-policy-sha256")
        .arg(hex::encode(history_policy().pq_history_id()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
pub(super) fn pair(fixture: &Fixture, files: &Path, store: &Path) -> Command {
    let mut result = command(fixture, files, store, "pq-parent-tls-serve", true);
    result.args([
        "--native-listen",
        "127.0.0.1:0",
        "--history-listen",
        "127.0.0.1:0",
        "--seconds",
        "30",
    ]);
    result
}
pub(super) fn recovery(
    fixture: &Fixture,
    files: &Path,
    store: &Path,
    campaign: &Path,
    packet: &Path,
    ready: &Value,
    resume: bool,
) -> Command {
    let mut command = command(
        fixture,
        files,
        store,
        if resume {
            "pq-parent-resume"
        } else {
            "pq-parent-create"
        },
        false,
    );
    command
        .arg("--native-peer")
        .arg(ready["native_listen"].as_str().unwrap())
        .arg("--history-peer")
        .arg(ready["history_listen"].as_str().unwrap())
        .arg("--campaign")
        .arg(campaign)
        .arg("--packet")
        .arg(packet)
        .args(["--initial-sequence", "1"]);
    command
}
pub(super) fn replace_arg(
    process: Command,
    key: &str,
    replacement: impl AsRef<std::ffi::OsStr>,
) -> Command {
    let original: Vec<_> = process.get_args().map(|arg| arg.to_os_string()).collect();
    let mut changed = 0;
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    for (index, argument) in original.iter().enumerate() {
        if index > 0 && original[index - 1] == key {
            command.arg(replacement.as_ref());
            changed += 1;
        } else {
            command.arg(argument);
        }
    }
    assert_eq!(changed, 1);
    command
}
pub(super) fn outcome(mut process: Command) -> Value {
    let output = process.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["production_activation"], false);
    assert_eq!(value["whole_directory_rollback_protection"], false);
    value
}
pub(super) struct Running {
    child: Child,
    reader: Option<thread::JoinHandle<Vec<String>>>,
}
impl Running {
    pub fn start(mut command: Command) -> (Self, Value) {
        let mut child = command.stderr(Stdio::inherit()).spawn().unwrap();
        let output = child.stdout.take().unwrap();
        let (ready, received) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = Vec::new();
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                assert!(line.len() <= 131_072);
                if lines.is_empty() {
                    let _ = ready.send(line.clone());
                }
                lines.push(line);
            }
            lines
        });
        let running = Self {
            child,
            reader: Some(reader),
        };
        let ready: Value =
            serde_json::from_str(&received.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
        assert_eq!(ready["event"], "pq-parent-pair-bound");
        assert_eq!(ready["production_activation"], false);
        assert_eq!(ready["history_transport"], PQ_RECOVERY_HISTORY_TRANSPORT);
        assert_eq!(ready["whole_node_rollback_protection"], false);
        (running, ready)
    }
    pub fn finish(mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(40);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < until,
                "original bounded services did not exit"
            );
            thread::sleep(Duration::from_millis(2));
        }
        let lines = self.reader.take().unwrap().join().unwrap();
        serde_json::from_str(lines.last().unwrap()).unwrap()
    }
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
