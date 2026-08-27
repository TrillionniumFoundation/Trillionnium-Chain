#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

//! Black-box tests for the candidate Core effect-driver process.  These tests
//! deliberately use pipes and a temporary run root instead of calling the
//! library, so process ownership, strict framing, durable ordering, and
//! restart fail-closed behaviour are all exercised.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use tempfile::TempDir;

struct ProcessV1 {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: std::process::ChildStderr,
}

impl ProcessV1 {
    fn spawn(root: &TempDir, fail_checkpoint: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-poco-effect-driver-process"));
        command
            .arg(root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if fail_checkpoint {
            command.env("TRNM_POCO_EFFECT_PROCESS_FAIL_CHECKPOINT", "1");
        }
        let mut child = command.spawn().expect("effect-driver process must spawn");
        Self {
            stdin: child.stdin.take().expect("stdin pipe"),
            stdout: BufReader::new(child.stdout.take().expect("stdout pipe")),
            stderr: child.stderr.take().expect("stderr pipe"),
            child,
        }
    }

    fn send(&mut self, request: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &request).expect("encode command");
        self.stdin.write_all(b"\n").expect("write command");
        self.stdin.flush().expect("flush command");
        self.read_response()
    }

    fn send_raw(&mut self, request: &[u8]) -> Value {
        self.stdin.write_all(request).expect("write raw command");
        self.stdin.write_all(b"\n").expect("write raw newline");
        self.stdin.flush().expect("flush raw command");
        self.read_response()
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).expect("read response");
        assert!(bytes > 0, "process returned EOF before response");
        serde_json::from_str(&line).expect("response is JSON")
    }

    fn shutdown(mut self) -> (std::process::ExitStatus, String) {
        let _ = self.send(json!({"op":"shutdown"}));
        drop(self.stdin);
        let status = self.child.wait().expect("wait process");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read stderr");
        (status, stderr)
    }

    fn kill(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        let _ = self.child.kill();
        self.child.wait().expect("wait killed process")
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}: {value}"))
}

#[test]
fn timeout_process_proves_ordering_authentication_backpressure_and_restart_fence() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut process = ProcessV1::spawn(&root, false);

    let duplicate = process.send_raw(br#"{"op":"status","op":"shutdown"}"#);
    assert_eq!(string_field(&duplicate, "reason"), "malformed_json");

    // Drive one timeout through the complete authority/CAS/sign/broadcast
    // path.  The process wrapper deliberately exposes no unsafe proposal or
    // finality shortcut.
    let accepted = process.send(json!({"op":"enqueue_timeout","generation":1}));
    assert_eq!(string_field(&accepted, "admission"), "accepted");
    let first = process.send(json!({"op":"drive"}));
    assert_eq!(string_field(&first, "status"), "active");
    assert_eq!(first["broadcasts"], 1);
    assert_eq!(first["processed_ingress"], 1);
    assert_eq!(first["production_activation"], false);
    assert_eq!(first["finality_verified"], false);
    assert_eq!(first["candidate_only"], true);
    let (status, _stderr) = process.shutdown();
    assert!(status.success());

    // A separate fresh process proves bounded ingress backpressure without
    // queuing invalid same-view timeouts behind the successful one.
    let backpressure_root = tempfile::tempdir().expect("backpressure root");
    let mut backpressure = ProcessV1::spawn(&backpressure_root, false);
    for generation in 1..=8 {
        let response = backpressure.send(json!({
            "op":"enqueue_timeout",
            "generation":generation
        }));
        assert_eq!(string_field(&response, "admission"), "accepted");
    }
    let full = backpressure.send(json!({"op":"enqueue_timeout","generation":9}));
    assert_eq!(string_field(&full, "admission"), "backpressure");
    let (backpressure_status, _) = backpressure.shutdown();
    assert!(backpressure_status.success());

    let outbound =
        fs::read_to_string(root.path().join("outbound.wal")).expect("durable outbound WAL");
    let fields = outbound
        .trim()
        .split('\t')
        .filter_map(|field| field.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(fields.get("kind"), Some(&"timeout_vote"));
    let root_bytes = hex::decode(fields["root"]).expect("root hex");
    let signature_bytes = hex::decode(fields["signature"]).expect("signature hex");
    let verifying =
        VerifyingKey::from_bytes(&SigningKeyFixture::new().public_key).expect("fixture public key");
    verifying
        .verify(
            &root_bytes,
            &Signature::from_slice(&signature_bytes).expect("signature"),
        )
        .expect("broadcast signature must authenticate the exact root");

    // A non-empty candidate state is not silently reopened as fresh state.
    let mut restart = Command::new(env!("CARGO_BIN_EXE_trnm-poco-effect-driver-process"));
    let output = restart.arg(root.path()).output().expect("restart process");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("recovery_required"));
}

#[test]
fn checkpoint_failure_is_fail_stop_and_never_writes_outbound_signature() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut process = ProcessV1::spawn(&root, true);
    let accepted = process.send(json!({"op":"enqueue_timeout","generation":1}));
    assert_eq!(string_field(&accepted, "admission"), "accepted");
    let failed = process.send(json!({"op":"drive"}));
    assert_eq!(string_field(&failed, "status"), "fail_stopped");
    let status = process.kill();
    assert!(!status.success());
    assert!(root.path().join("safety-transition.wal").is_file());
    assert!(root.path().join("safety-state.record").is_file());
    assert!(!root.path().join("whole-node.checkpoint").exists());
    assert!(!root.path().join("outbound.wal").exists());
}

#[test]
fn synced_proposal_application_seal_then_authority_vote_share_one_core_owner() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut process = ProcessV1::spawn(&root, false);

    // The synced route is the explicit candidate application boundary: Core
    // authenticates/retains the proposal, the fixture application seals its
    // exact body, and no signer is reachable from this step.
    let proposal = process.send(json!({
        "op":"enqueue_synced_proposal",
        "generation":1
    }));
    assert_eq!(string_field(&proposal, "admission"), "accepted");
    let validated = process.send(json!({"op":"drive"}));
    assert_eq!(string_field(&validated, "status"), "active");
    assert_eq!(validated["processed_ingress"], 1);
    assert_eq!(validated["broadcasts"], 0);
    assert!(root.path().join("application-seal.wal").is_file());
    assert!(root.path().join("safety-state.record").is_file());
    let checkpoint = fs::read_to_string(root.path().join("whole-node.checkpoint"))
        .expect("non-signing application revisions advance checkpoint predecessor");
    assert!(checkpoint.contains("revision=2"));

    // The exact same deterministic proposal now crosses the one issued
    // Core-owned SafetyRules authority. The resulting Vote must pass the
    // durable transition, whole-node CAS, signer, and authenticated broadcast
    // sequence; a caller cannot provide a free-form signing root here.
    let vote = process.send(json!({
        "op":"enqueue_authority_vote",
        "generation":2
    }));
    assert_eq!(string_field(&vote, "admission"), "accepted");
    let signed = process.send(json!({"op":"drive"}));
    assert_eq!(string_field(&signed, "status"), "active");
    assert_eq!(signed["processed_ingress"], 2);
    assert_eq!(signed["broadcasts"], 1);
    assert_eq!(signed["production_activation"], false);
    assert_eq!(signed["finality_verified"], false);

    let outbound =
        fs::read_to_string(root.path().join("outbound.wal")).expect("durable Vote outbound WAL");
    let fields = outbound
        .trim()
        .split('\t')
        .filter_map(|field| field.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(fields.get("kind"), Some(&"vote"));
    let root_bytes = hex::decode(fields["root"]).expect("Vote root hex");
    let signature_bytes = hex::decode(fields["signature"]).expect("Vote signature hex");
    let verifying =
        VerifyingKey::from_bytes(&SigningKeyFixture::new().public_key).expect("fixture public key");
    verifying
        .verify(
            &root_bytes,
            &Signature::from_slice(&signature_bytes).expect("Vote signature"),
        )
        .expect("Vote broadcast signature must authenticate the exact Core root");

    let (status, _stderr) = process.shutdown();
    assert!(status.success());
}

#[test]
fn ordinary_proposal_boundary_fail_stops_before_signer_or_broadcast() {
    let root = tempfile::tempdir().expect("temporary root");
    let mut process = ProcessV1::spawn(&root, false);
    let accepted = process.send(json!({
        "op":"enqueue_proposal",
        "generation":1
    }));
    assert_eq!(string_field(&accepted, "admission"), "accepted");
    let failed = process.send(json!({"op":"drive"}));
    assert_eq!(string_field(&failed, "status"), "fail_stopped");
    assert!(string_field(&failed, "reason").contains("normal proposal validation"));
    assert!(!root.path().join("outbound.wal").exists());
    let checkpoint = fs::read_to_string(root.path().join("whole-node.checkpoint"))
        .expect("the pre-validation Safety revision is durably checkpointed");
    assert!(checkpoint.contains("revision=1"));
    let status = process.kill();
    assert!(!status.success());
}

struct SigningKeyFixture {
    public_key: [u8; 32],
}

impl SigningKeyFixture {
    fn new() -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        Self {
            public_key: key.verifying_key().to_bytes(),
        }
    }
}
