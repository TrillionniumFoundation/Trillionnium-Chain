#![cfg(unix)]
#![allow(clippy::zombie_processes)]

//! Candidate-only process/reopen evidence for the payload replay recovery
//! owner.  These tests deliberately exercise the external recovery binary,
//! rather than only calling the library in one process.  They model the
//! durable boundaries that are available today:
//!
//! * a head lag left by a stop before publication (a bounded R2B-01/R2B-04
//!   negative/evidence case);
//! * recovery in a fresh process followed by an acknowledgement; and
//! * a discarded acknowledgement response followed by a fresh-process retry
//!   (the R2B-06 response-loss/idempotence case).
//!
//! The fixture is not a live Core adapter.  The Core acknowledgement supplied
//! to the candidate recovery CLI is intentionally synthetic, so passing tests
//! must never be interpreted as process-kill, Core-atomic, or production
//! evidence.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use trnm_consensus_peer_lease::{
    PayloadReplayDirectionV1, PayloadReplayFrameV1, PayloadReplayNamespaceV1,
    PayloadReplayRecoveryTargetV1, PayloadReplayStoreV1,
};

const RECOVERY_BINARY: &str = env!("CARGO_BIN_EXE_trnm-payload-replay-recovery-v1");
const RECORD_BYTES_V1: usize = 380;
const HEAD_PREFIX_BYTES_V1: usize = 84;
const HEAD_BYTES_V1: usize = HEAD_PREFIX_BYTES_V1 + 32;
const HEAD_MAGIC_V1: &[u8; 8] = b"TRNPRH01";
const HEAD_VERSION_V1: u8 = 1;
const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.namespace.v1";
const HEAD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.head.v1";

fn private_tempdir() -> TempDir {
    let directory = tempfile::Builder::new()
        .prefix("trnm-payload-recovery-process-")
        .tempdir()
        .expect("create process matrix root");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect process matrix root");
    directory
}

fn namespace() -> PayloadReplayNamespaceV1 {
    PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32])
        .expect("valid process matrix namespace")
}

fn frame(namespace: PayloadReplayNamespaceV1) -> PayloadReplayFrameV1 {
    PayloadReplayFrameV1::new(
        namespace
            .scope_for([9; 32], PayloadReplayDirectionV1::Inbound)
            .expect("valid process matrix scope"),
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        [5; 32],
        1,
        0,
        2,
        11,
        [10; 32],
    )
    .expect("valid process matrix frame")
}

fn seed_case() -> (
    TempDir,
    PathBuf,
    PathBuf,
    PayloadReplayNamespaceV1,
    PayloadReplayRecoveryTargetV1,
) {
    let root = private_tempdir();
    let payload = root.path().join("frames.wal");
    let acknowledgement_root = root.path().join("core-acks");
    fs::create_dir(&acknowledgement_root).expect("create acknowledgement root");
    fs::set_permissions(&acknowledgement_root, fs::Permissions::from_mode(0o700))
        .expect("protect acknowledgement root");

    let namespace = namespace();
    let frame = frame(namespace);
    let receipt = {
        let mut store =
            PayloadReplayStoreV1::open(&payload, namespace).expect("open candidate payload store");
        store.admit(&frame).expect("admit candidate payload frame")
    };
    let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
    (root, payload, acknowledgement_root, namespace, target)
}

fn namespace_digest(namespace: PayloadReplayNamespaceV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_DOMAIN_V1);
    hasher.update(namespace.local_id());
    hasher.update(namespace.epoch().to_be_bytes());
    hasher.update(namespace.validator_set_id());
    hasher.update(namespace.run_id_hash());
    hasher.update(namespace.network_context_hash());
    hasher.finalize().into()
}

fn head_path(payload: &Path) -> PathBuf {
    let name = payload
        .file_name()
        .and_then(|value| value.to_str())
        .expect("UTF-8 payload filename");
    payload.with_file_name(format!(".{name}.head-v1"))
}

fn head_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN_V1);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

/// Replace the published head with the genesis record.  This is the exact
/// one-record lag that the recovery owner is allowed to repair.  It models a
/// stop between a durable WAL append and the head-sidecar publication; it is
/// deliberately not a SIGKILL timing proof.
fn rewind_head_to_genesis(payload: &Path, namespace: PayloadReplayNamespaceV1) {
    let wal = fs::read(payload).expect("read seeded payload WAL");
    assert_eq!(wal.len(), RECORD_BYTES_V1 * 2);
    let genesis_hash: [u8; 32] = wal[RECORD_BYTES_V1 - 32..RECORD_BYTES_V1]
        .try_into()
        .expect("genesis record hash");
    let mut prefix = Vec::with_capacity(HEAD_PREFIX_BYTES_V1);
    prefix.extend_from_slice(HEAD_MAGIC_V1);
    prefix.push(HEAD_VERSION_V1);
    prefix.extend_from_slice(&[0; 3]);
    prefix.extend_from_slice(&1_u64.to_be_bytes());
    prefix.extend_from_slice(&genesis_hash);
    prefix.extend_from_slice(&namespace_digest(namespace));
    assert_eq!(prefix.len(), HEAD_PREFIX_BYTES_V1);
    let mut bytes = prefix;
    bytes.extend_from_slice(&head_digest(&bytes));
    assert_eq!(bytes.len(), HEAD_BYTES_V1);
    fs::write(head_path(payload), bytes).expect("write one-record-lag head");
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn direction_name(direction: PayloadReplayDirectionV1) -> &'static str {
    match direction {
        PayloadReplayDirectionV1::Inbound => "inbound",
        PayloadReplayDirectionV1::Outbound => "outbound",
    }
}

fn recovery_args(
    operation: &str,
    payload: &Path,
    acknowledgement_root: &Path,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
    acknowledgement: Option<(u64, [u8; 32])>,
) -> Vec<String> {
    let mut arguments = vec![
        operation.to_owned(),
        payload.display().to_string(),
        acknowledgement_root.display().to_string(),
        hex32(namespace.local_id()),
        namespace.epoch().to_string(),
        hex32(namespace.validator_set_id()),
        hex32(namespace.run_id_hash()),
        hex32(namespace.network_context_hash()),
        target.record_index().to_string(),
        hex32(target.record_hash()),
        hex32(target.remote_id()),
        direction_name(target.direction()).to_owned(),
        hex32(target.session_id()),
        target.generation().to_string(),
        target.sequence().to_string(),
        target.frame_kind().to_string(),
        target.payload_len().to_string(),
        hex32(target.frame_fingerprint()),
    ];
    if let Some((revision, digest)) = acknowledgement {
        arguments.push(revision.to_string());
        arguments.push(hex32(digest));
    }
    arguments
}

fn run_recovery(
    operation: &str,
    payload: &Path,
    acknowledgement_root: &Path,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
    acknowledgement: Option<(u64, [u8; 32])>,
) -> Output {
    Command::new(RECOVERY_BINARY)
        .args(recovery_args(
            operation,
            payload,
            acknowledgement_root,
            namespace,
            target,
            acknowledgement,
        ))
        .output()
        .expect("spawn external payload recovery owner")
}

fn assert_success(output: &Output, stage: &str) {
    assert!(
        output.status.success(),
        "{stage} failed: status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_ack_record(acknowledgement_root: &Path) {
    let entries = fs::read_dir(acknowledgement_root)
        .expect("read acknowledgement root after negative process case")
        .map(|entry| {
            entry
                .expect("read acknowledgement directory entry")
                .file_name()
        })
        .filter(|name| {
            name.to_str()
                .map(|value| value.starts_with("ack-") || value.starts_with(".ack-"))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    assert!(
        entries.is_empty(),
        "negative process case left acknowledgement records: {entries:?}"
    );
}

#[test]
fn candidate_process_reopen_matrix_models_head_lag_and_response_loss() {
    let (_root, payload, acknowledgement_root, namespace, target) = seed_case();
    rewind_head_to_genesis(&payload, namespace);

    // R2B-01 evidence-negative boundary: before any Core call/acknowledgement,
    // a fresh process reports a recoverable pending publication and no ack.
    let pending = run_recovery(
        "status",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        None,
    );
    assert_success(&pending, "status before publication recovery");
    let pending_stdout = String::from_utf8_lossy(&pending.stdout);
    assert!(pending_stdout.contains("status=recoverable_head_lag"));
    assert!(pending_stdout.contains("core_acknowledged=false"));
    assert!(!pending_stdout.contains("status=core_acknowledged"));

    // R2B-04 candidate process boundary: a new owner repairs exactly the
    // durable one-record lag, then independently reopens the admitted state.
    let recovered = run_recovery(
        "recover",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        None,
    );
    assert_success(&recovered, "recover head lag in a fresh process");
    assert!(String::from_utf8_lossy(&recovered.stdout).contains("status=admitted_unacknowledged"));

    // R2B-06 response-loss model: discard the first process response as if it
    // were lost, then prove on a fresh process that the exact ack is durable.
    let first_ack = run_recovery(
        "ack",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        Some((9, [11; 32])),
    );
    assert_success(&first_ack, "record candidate Core acknowledgement");
    drop(first_ack);

    let reopened = run_recovery(
        "status",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        None,
    );
    assert_success(&reopened, "reopen acknowledged target after response loss");
    let reopened_stdout = String::from_utf8_lossy(&reopened.stdout);
    assert!(reopened_stdout.contains("status=core_acknowledged"));
    assert!(reopened_stdout.contains("core_safety_revision=9"));
    assert!(reopened_stdout.contains(&format!("core_ack_digest={}", hex32([11; 32]))));

    let retry = run_recovery(
        "ack",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        Some((9, [11; 32])),
    );
    assert_success(&retry, "idempotent acknowledgement retry");
    assert!(String::from_utf8_lossy(&retry.stdout).contains("idempotent_replay=true"));
}

#[test]
fn candidate_process_rejects_forged_target_without_ack() {
    let (_root, payload, acknowledgement_root, namespace, target) = seed_case();
    let forged = PayloadReplayRecoveryTargetV1::new(
        target.record_index(),
        [0x99; 32],
        target.remote_id(),
        target.direction(),
        target.session_id(),
        target.generation(),
        target.sequence(),
        target.frame_kind(),
        target.payload_len(),
        target.frame_fingerprint(),
    )
    .expect("nonzero forged target remains syntactically valid");

    // A stale/forged response must fail before an acknowledgement record can
    // be created.  This is explicit negative evidence, not a success claim.
    let rejected = run_recovery(
        "status",
        &payload,
        &acknowledgement_root,
        namespace,
        forged,
        None,
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("does not match"));
    assert_no_ack_record(&acknowledgement_root);

    let valid = run_recovery(
        "status",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        None,
    );
    assert_success(&valid, "status after forged target rejection");
    assert!(String::from_utf8_lossy(&valid.stdout).contains("status=admitted_unacknowledged"));
}

#[test]
fn candidate_process_rejects_symlinked_payload_endpoint() {
    let (root, payload, acknowledgement_root, namespace, target) = seed_case();
    let original = root.path().join("frames.original");
    fs::rename(&payload, &original).expect("retain original payload endpoint");
    std::os::unix::fs::symlink(&original, &payload).expect("install payload symlink");

    let rejected = run_recovery(
        "status",
        &payload,
        &acknowledgement_root,
        namespace,
        target,
        None,
    );
    assert!(!rejected.status.success());
    let diagnostic = format!(
        "{} {}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        diagnostic.contains("symlink")
            || diagnostic.contains("identity")
            || diagnostic.contains("corrupt")
            || diagnostic.contains("No such file"),
        "path substitution diagnostic missing: {diagnostic}"
    );
    assert_no_ack_record(&acknowledgement_root);
}
