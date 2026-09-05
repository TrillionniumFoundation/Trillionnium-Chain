#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

//! Black-box process evidence for the candidate G1 vertical slice.  The test
//! intentionally talks to the actual binary over stdin/stdout; calling the
//! library directly would not exercise framing, process ownership, or restart
//! exit behavior.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tempfile::TempDir;
use trnm_application_tx_builder_v0::{
    build_signed_canonical_tx_v0, ApplicationSignerV0, CanonicalTxBuildContextV0, TxBuilderLimitsV0,
};
use trnm_finality_types::crypto::public_key_hex;
use trnm_protocol::CanonicalCommandV1;

const CHAIN_ID_V0: &str = "trnm-g1-process-v0";
const SIGNER_ID_V0: &str = "did:operator:g1-process";
const SIGNER_ROLE_V0: &str = "operator";
const NOW_V0: u64 = 1_700_000_000_000;

struct FixtureSignerV0 {
    key: SigningKey,
    public_key_hex: String,
}

impl FixtureSignerV0 {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[0x47; 32]);
        Self {
            public_key_hex: public_key_hex(&key),
            key,
        }
    }
}

impl ApplicationSignerV0 for FixtureSignerV0 {
    fn signer_id(&self) -> &str {
        SIGNER_ID_V0
    }

    fn signer_role(&self) -> &str {
        SIGNER_ROLE_V0
    }

    fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    fn sign(&self, preimage: &[u8]) -> anyhow::Result<[u8; 64]> {
        Ok(self.key.sign(preimage).to_bytes())
    }
}

fn signed_transaction_hex_v0(nonce: u64) -> String {
    let signer = FixtureSignerV0::new();
    let transaction = build_signed_canonical_tx_v0(
        CanonicalTxBuildContextV0 {
            chain_id: CHAIN_ID_V0.to_owned(),
            sender: SIGNER_ID_V0.to_owned(),
            command_id: Some(format!("g1-process-credit-{nonce}")),
            nonce,
            issued_at_unix_ms: NOW_V0,
            expires_at_unix_ms: NOW_V0 + 100_000,
            max_gas: 100_000,
            fee_limit: 17,
            limits: TxBuilderLimitsV0::candidate_v0(),
        },
        CanonicalCommandV1::CreditAccount {
            account: "did:client:g1-process".to_owned(),
            amount: 10_000,
        },
        &signer,
    )
    .expect("fixture transaction must build");
    hex::encode(transaction.exact_outer_bytes())
}

struct ProcessV0 {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: ChildStderr,
}

impl ProcessV0 {
    fn spawn(root: &TempDir) -> Self {
        Self::spawn_with_marker_opt(root, None, None)
    }

    fn spawn_with_marker(root: &TempDir, environment: &str, marker: &Path) -> Self {
        Self::spawn_with_marker_opt(root, Some(environment), Some(marker))
    }

    fn spawn_with_marker_opt(
        root: &TempDir,
        environment: Option<&str>,
        marker: Option<&Path>,
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-poco-g1-process-host"));
        command
            .arg(root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let (Some(name), Some(path)) = (environment, marker) {
            command.env(name, path.as_os_str());
        }
        let mut child = command.spawn().expect("candidate process must spawn");
        let stdin = child.stdin.take().expect("stdin pipe");
        let stdout = BufReader::new(child.stdout.take().expect("stdout pipe"));
        let stderr = child.stderr.take().expect("stderr pipe");
        Self {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    fn send_without_wait(&mut self, request: Value) {
        serde_json::to_writer(&mut self.stdin, &request).expect("encode request");
        self.stdin.write_all(b"\n").expect("write request");
        self.stdin.flush().expect("flush request");
    }

    fn request(&mut self, request: Value) -> Value {
        serde_json::to_writer(&mut self.stdin, &request).expect("encode request");
        self.stdin.write_all(b"\n").expect("write request");
        self.stdin.flush().expect("flush request");
        self.read_response()
    }

    fn raw_request(&mut self, request: &[u8]) -> Value {
        self.stdin.write_all(request).expect("write raw request");
        self.stdin.write_all(b"\n").expect("terminate raw request");
        self.stdin.flush().expect("flush raw request");
        self.read_response()
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).expect("read response");
        if read == 0 {
            let mut stderr = String::new();
            self.stderr
                .read_to_string(&mut stderr)
                .expect("read child stderr");
            panic!(
                "candidate process returned EOF before response (status {:?}, stderr {stderr})",
                self.child.try_wait()
            );
        }
        serde_json::from_str(&line).expect("response must be JSON")
    }

    fn shutdown(mut self) -> (std::process::ExitStatus, String) {
        serde_json::to_writer(&mut self.stdin, &json!({ "op": "shutdown" }))
            .expect("encode shutdown");
        self.stdin.write_all(b"\n").expect("write shutdown");
        self.stdin.flush().expect("flush shutdown");
        drop(self.stdin);
        let status = self.child.wait().expect("candidate process must exit");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read candidate stderr");
        (status, stderr)
    }

    fn kill(mut self) -> (std::process::ExitStatus, String) {
        drop(self.stdin);
        let _ = self.child.kill();
        let status = self.child.wait().expect("candidate process must wait");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read killed candidate stderr");
        (status, stderr)
    }

    fn wait(mut self) -> (std::process::ExitStatus, String) {
        drop(self.stdin);
        let status = self.child.wait().expect("candidate process must wait");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read candidate stderr");
        (status, stderr)
    }
}

fn wait_for_marker(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "candidate process did not reach crash marker {}",
        path.display()
    );
}

fn assert_string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("response field {field} must be a string: {value}"))
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
    // after the process has recorded its raw bytes.
    let duplicate =
        process.raw_request(br#"{"op":"submit","op":"shutdown","generation":1,"tx_hex":"00"}"#);
    assert_eq!(assert_string_field(&duplicate, "status"), "rejected");
    assert_eq!(assert_string_field(&duplicate, "reason"), "malformed_json");

    // Hex/length failures occur before WAL handoff and must be ordinary
    // request rejections.  In particular, they must not terminate the host
    // or consume generation one, so a valid retry can still be admitted.
    let malformed_hex = process.request(json!({
        "op": "submit",
        "generation": 1,
        "tx_hex": "zz",
    }));
    assert_eq!(assert_string_field(&malformed_hex, "status"), "rejected");
    assert_eq!(
        assert_string_field(&malformed_hex, "reason"),
        "invalid_transaction"
    );

    let stale = process.request(json!({
        "op": "submit",
        "generation": 2,
        "tx_hex": signed_transaction_hex_v0(1),
    }));
    assert_eq!(assert_string_field(&stale, "reason"), "stale_generation");

    let accepted = process.request(json!({
        "op": "submit",
        "generation": 1,
        "tx_hex": signed_transaction_hex_v0(1),
    }));
    assert_eq!(
        assert_string_field(&accepted, "status"),
        "committed_candidate"
    );
    assert_eq!(accepted.get("generation").and_then(Value::as_u64), Some(1));
    assert_eq!(accepted.get("height").and_then(Value::as_u64), Some(1));
    assert_eq!(
        accepted
            .get("production_candidate")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        accepted.get("finality_verified").and_then(Value::as_bool),
        Some(false)
    );
    assert_ne!(assert_string_field(&accepted, "block_id"), "00".repeat(32));
    assert_ne!(
        assert_string_field(&accepted, "state_root"),
        "00".repeat(32)
    );
    assert_ne!(
        assert_string_field(&accepted, "receipt_digest"),
        "00".repeat(32)
    );

    // A second process request with the same signer/nonce must hit the durable
    // replay tombstone, proving that the WAL commit was not merely in-memory.
    let replay = process.request(json!({
        "op": "submit",
        "generation": 2,
        "tx_hex": signed_transaction_hex_v0(1),
    }));
    assert_eq!(assert_string_field(&replay, "status"), "rejected");
    assert_eq!(assert_string_field(&replay, "reason"), "replay");

    let (status, stderr) = process.shutdown();
    assert!(status.success(), "candidate stderr: {stderr}");
    assert!(
        stderr.contains("G1_PROCESS_SUMMARY"),
        "missing process summary: {stderr}"
    );
    assert!(
        stderr.contains("accepted: 1"),
        "unexpected process summary: {stderr}"
    );

    // Reopen the same durable roots in a new OS process.  The native head,
    // timestamp, generation and WAL replay tombstone must all be recovered;
    // the next nonce can then traverse the same proof/readback join at h=2.
    let mut restarted = ProcessV0::spawn(&root);
    let next = restarted.request(json!({
        "op": "submit",
        "generation": 2,
        "tx_hex": signed_transaction_hex_v0(2),
    }));
    assert_eq!(assert_string_field(&next, "status"), "committed_candidate");
    assert_eq!(next.get("generation").and_then(Value::as_u64), Some(2));
    assert_eq!(next.get("height").and_then(Value::as_u64), Some(2));
    let (status, stderr) = restarted.shutdown();
    assert!(status.success(), "restarted candidate stderr: {stderr}");
    assert!(
        stderr.contains("accepted: 1"),
        "unexpected restart summary: {stderr}"
    );
}

#[test]
fn real_process_rejects_an_oversized_frame_without_allocating_it() {
    let root = tempfile::tempdir().expect("temporary run root");
    let mut process = ProcessV0::spawn(&root);
    let oversized = format!(
        "{{\"op\":\"submit\",\"generation\":1,\"tx_hex\":\"{}\"}}",
        "a".repeat(300_000)
    );
    process
        .stdin
        .write_all(oversized.as_bytes())
        .expect("write oversized frame");
    process
        .stdin
        .write_all(b"\n")
        .expect("terminate oversized frame");
    process.stdin.flush().expect("flush oversized frame");
    let mut line = String::new();
    process
        .stdout
        .read_line(&mut line)
        .expect("read oversized response");
    let response: Value = serde_json::from_str(&line).expect("oversized response JSON");
    assert_eq!(assert_string_field(&response, "status"), "rejected");
    assert_eq!(assert_string_field(&response, "reason"), "frame_too_large");
    let (status, stderr) = process.shutdown();
    assert!(status.success(), "candidate stderr: {stderr}");
}

#[test]
fn sigkill_after_handoff_without_application_evidence_stays_fail_closed() {
    let root = tempfile::tempdir().expect("temporary run root");
    let marker = root.path().join("after-handoff.ready");
    let _ = fs::remove_file(&marker);
    let mut process =
        ProcessV0::spawn_with_marker(&root, "TRNM_G1_PROCESS_PAUSE_AFTER_HANDOFF_MARKER", &marker);
    process.send_without_wait(json!({
        "op": "submit",
        "generation": 1,
        "tx_hex": signed_transaction_hex_v0(1),
    }));
    wait_for_marker(&marker);
    let (status, _) = process.kill();
    assert!(!status.success(), "SIGKILL must not report a clean exit");

    // The application is still at genesis, so no authenticated receipt/proof
    // exists to resolve the durable handoff.  A restart must refuse startup,
    // rather than release or replay the ambiguous nonce.
    let refused = ProcessV0::spawn(&root);
    let (status, stderr) = refused.wait();
    assert!(!status.success(), "ambiguous handoff must refuse startup");
    assert!(
        stderr.contains("admission.recovery.ambiguous"),
        "restart did not report the fail-closed ambiguity: {stderr}"
    );
}

#[test]
fn sigkill_after_application_commit_recovers_exact_wal_handoff() {
    let root = tempfile::tempdir().expect("temporary run root");
    let marker = root.path().join("after-application-commit.ready");
    let _ = fs::remove_file(&marker);
    let mut process = ProcessV0::spawn_with_marker(
        &root,
        "TRNM_G1_PROCESS_PAUSE_AFTER_APPLICATION_COMMIT_MARKER",
        &marker,
    );
    process.send_without_wait(json!({
        "op": "submit",
        "generation": 1,
        "tx_hex": signed_transaction_hex_v0(1),
    }));
    wait_for_marker(&marker);
    let (status, _) = process.kill();
    assert!(!status.success(), "SIGKILL must not report a clean exit");

    // The native application commit is durable, but the WAL receipt row was
    // intentionally not acknowledged.  Restart must enumerate and validate
    // the exact transaction/receipt/proof, resolve the handoff, and continue
    // at the next generation/height.
    let mut restarted = ProcessV0::spawn(&root);
    let recovered = restarted.request(json!({
        "op": "submit",
        "generation": 2,
        "tx_hex": signed_transaction_hex_v0(2),
    }));
    assert_eq!(
        assert_string_field(&recovered, "status"),
        "committed_candidate"
    );
    assert_eq!(recovered.get("generation").and_then(Value::as_u64), Some(2));
    assert_eq!(recovered.get("height").and_then(Value::as_u64), Some(2));
    let (status, stderr) = restarted.shutdown();
    assert!(status.success(), "recovered candidate stderr: {stderr}");
}
