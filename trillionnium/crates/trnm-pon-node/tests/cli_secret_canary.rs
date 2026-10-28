//! Exercise the actual CLI sink with owner-file secrets. These bounded canaries
//! supplement source-flow review; they do not dismiss CodeQL or prove all paths.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Node, Settings};
use trnm_protocol::pon_wire::hash;

struct Canary {
    hex: String,
    raw: Vec<u8>,
    public: String,
}
impl Canary {
    fn write(path: &Path, name: &[u8]) -> Self {
        // Published disposable test material, never deployed credentials.
        let raw = hash(b"cli-owned-secret-canary-v1", &[name]).to_vec();
        let hex = hex::encode(&raw);
        let public = public_key_hex(&signing_key_from_hex(&hex).unwrap());
        fs::write(path, format!("{hex}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        Self { hex, raw, public }
    }
    fn absent(&self, output: &[u8]) {
        let upper = self.hex.to_ascii_uppercase();
        for needle in [
            self.hex.as_bytes(),
            upper.as_bytes(),
            &self.hex.as_bytes()[..32],
            &self.hex.as_bytes()[32..],
            self.raw.as_slice(),
        ] {
            assert!(
                !output.windows(needle.len()).any(|part| part == needle),
                "owner secret canary reached a CLI output stream"
            );
        }
    }
}
fn command(name: &str, store: &Path, genesis: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .arg(name)
        .args(["--development", "--genesis-time", &genesis.to_string()])
        .arg("--store")
        .arg(store);
    command
}
fn observed(output: Output, canaries: &[&Canary], success: bool) -> Value {
    for canary in canaries {
        canary.absent(&output.stdout);
        canary.absent(&output.stderr);
    }
    // Do not include output in assertion diagnostics before canary checking.
    assert_eq!(output.status.success(), success);
    if success {
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        assert_eq!(output.status.code(), Some(2));
        json!({"error":String::from_utf8(output.stderr).unwrap()})
    }
}
struct Running {
    child: Child,
    reader: Option<thread::JoinHandle<Vec<u8>>>,
    initial: Vec<u8>,
}
impl Running {
    fn start(command: &mut Command) -> (Self, Value) {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut first = Vec::new();
            reader.read_until(b'\n', &mut first).unwrap();
            tx.send(first).unwrap();
            let mut remainder = Vec::new();
            reader.read_to_end(&mut remainder).unwrap();
            remainder
        });
        let mut running = Self {
            child,
            reader: Some(reader),
            initial: Vec::new(),
        };
        running.initial = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let ready = serde_json::from_slice(&running.initial).unwrap();
        (running, ready)
    }
    fn finish(mut self, canaries: &[&Canary]) {
        let status = self.child.wait().unwrap();
        let mut output = self.initial.clone();
        output.extend(self.reader.take().unwrap().join().unwrap());
        let mut stderr = Vec::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        for canary in canaries {
            canary.absent(&output);
            canary.absent(&stderr);
        }
        assert!(status.success());
        let final_line = output
            .split(|b| *b == b'\n')
            .rfind(|s| !s.is_empty())
            .unwrap();
        let _: Value = serde_json::from_slice(final_line).unwrap();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn actual_cli_owned_keys_do_not_flow_to_normal_or_error_output() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let server_path = directory.path().join("server.key");
    let client_path = directory.path().join("client.key");
    let server_key = Canary::write(&server_path, b"server");
    let client_key = Canary::write(&client_path, b"client");
    let canaries = [&server_key, &client_key];
    let roster = directory.path().join("peers.json");
    fs::write(&roster, serde_json::to_vec(&[&client_key.public]).unwrap()).unwrap();
    let settings = Settings::development(Some(genesis)).unwrap();
    let source = Node::open(&directory.path().join("source"), settings.clone(), 1).unwrap();
    let packet = source
        .make(
            settings.genesis(),
            vec![],
            development_public(0).unwrap(),
            genesis + 10,
            4096,
        )
        .unwrap();
    let packet_id = packet.id().unwrap();
    let packet_path = directory.path().join("packet.pnk1");
    fs::write(&packet_path, packet.encode().unwrap()).unwrap();
    drop(source);

    let (server, ready) = Running::start(
        command("serve", &directory.path().join("auth-server"), genesis)
            .args([
                "--authenticated-development-network",
                "--listen",
                "127.0.0.1:0",
                "--seconds",
                "3",
            ])
            .arg("--auth-secret")
            .arg(&server_path)
            .arg("--peer-roster")
            .arg(&roster)
            .args(["--session-generation", "1"]),
    );
    assert_eq!(ready["server_public"], server_key.public);
    let pushed = observed(
        command("push", &directory.path().join("auth-client"), genesis)
            .arg("--packet")
            .arg(&packet_path)
            .args([
                "--peer",
                ready["address"].as_str().unwrap(),
                "--server-public",
                &server_key.public,
            ])
            .arg("--auth-secret")
            .arg(&client_path)
            .args(["--session-generation", "1"])
            .output()
            .unwrap(),
        &canaries,
        true,
    );
    assert_eq!(pushed["response"]["block"], hex::encode(packet_id));
    assert_eq!(pushed["state"]["authenticated_outbox_pending"], 0);
    server.finish(&canaries);

    let (server, ready) = Running::start(
        command("serve", &directory.path().join("public-server"), genesis)
            .args([
                "--admission-profile",
                ingress::public_v2::PROFILE,
                "--public-development-network",
                "--listen",
                "127.0.0.1:0",
                "--seconds",
                "3",
                "--admission-bits",
                "8",
            ])
            .arg("--auth-secret")
            .arg(&server_path),
    );
    assert_eq!(ready["server_public"], server_key.public);
    let head = observed(
        command("head", &directory.path().join("public-client"), genesis)
            .args([
                "--admission-profile",
                ingress::public_v2::PROFILE,
                "--admission-bits",
                "8",
                "--peer",
                ready["address"].as_str().unwrap(),
                "--server-public",
                &server_key.public,
            ])
            .arg("--auth-secret")
            .arg(&client_path)
            .output()
            .unwrap(),
        &canaries,
        true,
    );
    assert_eq!(head["ok"], true);
    assert_eq!(head["identity_authority"], false);
    server.finish(&canaries);

    // The secret is read before roster validation; the failure must not echo it.
    fs::write(
        &roster,
        serde_json::to_vec(&[&client_key.public, &client_key.public]).unwrap(),
    )
    .unwrap();
    let bad_roster = observed(
        command("serve", &directory.path().join("bad-roster"), genesis)
            .args([
                "--authenticated-development-network",
                "--listen",
                "127.0.0.1:0",
                "--seconds",
                "1",
            ])
            .arg("--auth-secret")
            .arg(&server_path)
            .arg("--peer-roster")
            .arg(&roster)
            .args(["--session-generation", "1"])
            .output()
            .unwrap(),
        &canaries,
        false,
    );
    assert_eq!(bad_roster["error"], "AUTH_ROSTER\n");
    let malformed = directory.path().join("malformed.key");
    fs::write(&malformed, "z".repeat(64)).unwrap();
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600)).unwrap();
    let bad_key = observed(
        command("serve", &directory.path().join("bad-key"), genesis)
            .args([
                "--admission-profile",
                ingress::public_v2::PROFILE,
                "--public-development-network",
                "--seconds",
                "1",
            ])
            .arg("--auth-secret")
            .arg(&malformed)
            .output()
            .unwrap(),
        &canaries,
        false,
    );
    assert!(!bad_key["error"].as_str().unwrap().contains(&"z".repeat(32)));
    println!(
        "{}",
        json!({"case":"actual_cli_owned_secret_canary","normal_client_paths":2,
        "normal_server_paths":2,"error_paths":2,"secret_source_relation_ids":[9,10,11],
        "private_hex_raw_or_half_hex_in_stdout_stderr":false,"all_codeql_paths_proven":false,
        "codeql_alert_dismissed":false})
    );
}
