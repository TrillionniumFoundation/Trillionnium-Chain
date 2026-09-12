// Copyright (c) Trillionnium Contributors
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};

const PROCESS_BIN: &str = env!("CARGO_BIN_EXE_trnm-poco-g1-process-host");
const VALIDATOR_KEY_HEX: &str =
    "dfd8e048bdfc0f4e0492704870bf8bf216795974a752012b2f43a7de35220460";
const VALIDATOR_ADDRESS: &str = "3d47b1df13f0d454a2234546409a421d0c2a5641";
const BRIDGE_ID_HEX: &str = "0102030405060708090a0b0c0d0e0f10";

struct ProcessV0 {
    root: PathBuf,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl ProcessV0 {
    fn spawn(root: &Path) -> Self {
        let mut child = Command::new(PROCESS_BIN)
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn process host");
        let stdin = child.stdin.take().expect("process stdin");
        let stdout = child.stdout.take().expect("process stdout");
        Self {
            root: root.to_path_buf(),
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        }
    }

    fn request(&mut self, value: Value) -> Value {
        let encoded = serde_json::to_string(&value).expect("request JSON");
        let stdin = self.stdin.as_mut().expect("request before shutdown");
        writeln!(stdin, "{encoded}").expect("write request");
        stdin.flush().expect("flush request");
        let mut response = String::new();
        self.stdout.read_line(&mut response).expect("read response");
        serde_json::from_str(response.trim_end()).expect("response JSON")
    }

    fn shutdown(mut self) -> (ExitStatus, String) {
        self.stdin.take();
        let status = self.child.wait().expect("wait process host");
        let stderr = self.child.stderr.take().expect("process stderr");
        let stderr = std::io::read_to_string(stderr).expect("read process stderr");
        (status, stderr)
    }
}

impl Drop for ProcessV0 {
    fn drop(&mut self) {
        if self.stdin.is_some() {
            self.stdin.take();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_validator_key(root: &Path) {
    fs::write(root.join("validator-key.hex"), format!("{VALIDATOR_KEY_HEX}\n"))
        .expect("validator key");
}

fn request_checktx(tx_hex: &str, now_ms: u64) -> Value {
    json!({
        "op": "checktx",
        "tx_hex": tx_hex,
        "now_ms": now_ms,
        "bridge_id_hex": BRIDGE_ID_HEX,
        "validator_address": VALIDATOR_ADDRESS,
    })
}

fn request_commit(tx_hex: &str, now_ms: u64) -> Value {
    json!({
        "op": "commit",
        "tx_hex": tx_hex,
        "now_ms": now_ms,
        "bridge_id_hex": BRIDGE_ID_HEX,
        "validator_address": VALIDATOR_ADDRESS,
    })
}

fn assert_string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("response field {field} must be a string: {value}"))
}

#[test]
fn real_process_summary_stderr_is_counter_only_after_untrusted_input() {
    let root = tempfile::tempdir().expect("temporary run root");
    let mut process = ProcessV0::spawn(&root);
    let response = process.request(json!({
        "op": "not-supported",
        "message": "untrusted-log-marker\nFORGED_PROCESS_SUMMARY",
    }));
    assert!(response.get("status").and_then(Value::as_str) == Some("rejected"));
    assert!(response.get("reason").and_then(Value::as_str) == Some("malformed_json"));

    let (status, stderr) = process.shutdown();
    assert!(
        status.success(),
        "candidate summary fixture must exit successfully"
    );
    // Exact equality rejects whole-struct Debug output, newly added fields,
    // echoed request bytes, and injected log lines. Do not print captured
    // stderr even when this negative regression fails.
    assert!(
        stderr == "G1_PROCESS_SUMMARY accepted: 0, rejected: 1, backpressure_rejected: 0\n",
        "stderr must contain only the stable bounded counter summary"
    );
}

#[test]
fn real_process_checktx_native_apphash_and_wal_commit_are_observable() {
    let root = tempfile::tempdir().expect("temporary run root");
    let mut process = ProcessV0::spawn(&root);

    let malformed = process.request(json!({ "op": "not-supported" }));
    assert_eq!(assert_string_field(&malformed, "status"), "rejected");
    assert_eq!(assert_string_field(&malformed, "reason"), "malformed_json");

    // Control envelopes use the same strict duplicate/depth policy as signed
    // transactions.  A last-key-wins parser must not reinterpret a request
    // before it reaches the canonical ingress.
    let duplicate = {
        let stdin = process.stdin.as_mut().expect("request before shutdown");
        writeln!(
            stdin,
            "{{\"op\":\"health\",\"op\":\"checktx\",\"tx_hex\":\"00\",\"now_ms\":1,\"bridge_id_hex\":\"{BRIDGE_ID_HEX}\",\"validator_address\":\"{VALIDATOR_ADDRESS}\"}}"
        )
        .expect("write duplicate-key request");
        stdin.flush().expect("flush duplicate-key request");
        let mut response = String::new();
        process
            .stdout
            .read_line(&mut response)
            .expect("read duplicate-key response");
        serde_json::from_str::<Value>(response.trim_end()).expect("duplicate-key response JSON")
    };
    assert_eq!(assert_string_field(&duplicate, "status"), "rejected");
    assert_eq!(assert_string_field(&duplicate, "reason"), "malformed_json");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        .try_into()
        .expect("millis fit u64");

    let tx = trnm_poco_node::g1_process_host::fixture_signed_tx_v0(
        [0x42; 32],
        1,
        0,
        now_ms.saturating_add(60_000),
        b"process-host-e2e",
        [0x24; 32],
    )
    .expect("fixture signed tx");
    let tx_hex = hex::encode(&tx);

    let check = process.request(request_checktx(&tx_hex, now_ms));
    assert_eq!(assert_string_field(&check, "status"), "accepted");
    assert_eq!(assert_string_field(&check, "op"), "checktx");
    let check_app_hash = assert_string_field(&check, "app_hash").to_owned();
    assert_eq!(check_app_hash.len(), 64);

    let commit = process.request(request_commit(&tx_hex, now_ms));
    assert_eq!(assert_string_field(&commit, "status"), "accepted");
    assert_eq!(assert_string_field(&commit, "op"), "commit");
    assert_eq!(assert_string_field(&commit, "app_hash"), check_app_hash);

    let (status, stderr) = process.shutdown();
    assert!(status.success(), "candidate process host must exit successfully");
    assert!(stderr.contains("G1_PROCESS_SUMMARY"));
    assert!(stderr.contains("accepted: 2"));

    let wal = fs::read_to_string(root.path().join("g1-process-host.wal"))
        .expect("candidate process host WAL must exist");
    assert!(wal.lines().count() >= 2);
    assert!(wal.contains(&check_app_hash));
}

#[test]
fn process_restarts_with_committed_state_and_rejects_stale_replay() {
    let root = tempfile::tempdir().expect("temporary run root");
    write_validator_key(root.path());
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        .try_into()
        .expect("millis fit u64");

    let tx = trnm_poco_node::g1_process_host::fixture_signed_tx_v0(
        [0x99; 32],
        7,
        0,
        now_ms.saturating_add(60_000),
        b"restart-e2e",
        [0x11; 32],
    )
    .expect("fixture signed tx");
    let tx_hex = hex::encode(&tx);

    let committed_hash = {
        let mut process = ProcessV0::spawn(root.path());
        let commit = process.request(request_commit(&tx_hex, now_ms));
        assert_eq!(assert_string_field(&commit, "status"), "accepted");
        let app_hash = assert_string_field(&commit, "app_hash").to_owned();
        let (status, _stderr) = process.shutdown();
        assert!(status.success());
        app_hash
    };

    let mut restarted = ProcessV0::spawn(root.path());
    let replay = restarted.request(request_checktx(&tx_hex, now_ms.saturating_add(1)));
    assert_eq!(assert_string_field(&replay, "status"), "rejected");
    assert_eq!(assert_string_field(&replay, "reason"), "nonce_replay");
    assert_eq!(assert_string_field(&replay, "app_hash"), committed_hash);
    let (status, _stderr) = restarted.shutdown();
    assert!(status.success());
}
