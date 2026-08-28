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

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
        // `tempfile::tempdir` inherits the process umask and can be
        // group-writable in this workspace.  The candidate intentionally
        // rejects writable ancestors, so make the test-owned root explicit
        // before handing it to the real process.
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private process root");
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

#[cfg(unix)]
mod p2p_socket_e2e {
    use super::*;
    use std::{
        io::{Read, Write},
        net::Shutdown,
        os::unix::fs::PermissionsExt,
        os::unix::net::UnixStream,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::{
        BlockId, CanonicalSignable, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, Height, MessageKind, ProtocolVersion, SignatureBytes, Validator, ValidatorId,
        ValidatorSet, View, Vote, VotingPower,
    };

    const HANDSHAKE_MAGIC: &[u8; 4] = b"TRNH";
    const FRAME_MAGIC: &[u8; 4] = b"TRNF";
    const PROTOCOL_VERSION: u16 = 0;
    const WIRE_BODY_KIND_VOTE: u64 = 2;
    const DOMAIN_HANDSHAKE: &[u8] = b"trnm.poco.p2p.handshake.v0\0";
    const DOMAIN_SESSION_ID: &[u8] = b"trnm.poco.p2p.session-id.v0\0";
    const DOMAIN_FRAME: &[u8] = b"trnm.poco.p2p.frame.v0\0";

    struct LeaseDaemon {
        child: Child,
        socket: PathBuf,
    }

    impl LeaseDaemon {
        fn start(dir: &TempDir, name: &str) -> Self {
            let socket = dir.path().join(format!("{name}.sock"));
            let journal = dir.path().join(format!("{name}.journal"));
            let child = Command::new(env!("CARGO_BIN_EXE_trnm-poco-effect-driver-process"))
                .args([
                    "--peer-lease-daemon",
                    socket.to_str().expect("socket path UTF-8"),
                    journal.to_str().expect("journal path UTF-8"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("peer lease daemon must spawn");
            wait_for_path(&socket, true);
            Self { child, socket }
        }
    }

    impl Drop for LeaseDaemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_for_path(path: &Path, expected: bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if path.exists() == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {} (expected exists={expected})",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn make_private(dir: &TempDir) {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("socket test directory must be private");
    }

    fn connect_retry(path: &Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match UnixStream::connect(path) {
                Ok(stream) => return stream,
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out connecting to {}: {error}",
                        path.display()
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn send_socket_process(
        dir: &TempDir,
        name: &str,
        lease_socket: &Path,
        replay_path: &Path,
        handshake: &[u8],
        frame: &[u8],
        trailing_record: Option<&[u8]>,
    ) -> (std::process::ExitStatus, Value, String) {
        send_socket_process_with_generation(
            dir,
            name,
            lease_socket,
            replay_path,
            handshake,
            frame,
            trailing_record,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn send_socket_process_with_generation(
        dir: &TempDir,
        name: &str,
        lease_socket: &Path,
        replay_path: &Path,
        handshake: &[u8],
        frame: &[u8],
        trailing_record: Option<&[u8]>,
        lease_generation: u64,
    ) -> (std::process::ExitStatus, Value, String) {
        let root = dir.path().join(format!("{name}.root"));
        let socket = dir.path().join(format!("{name}.sock"));
        let lease_generation = lease_generation.to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_trnm-poco-effect-driver-process"))
            .args([
                "--p2p-socket-once",
                root.to_str().expect("root path UTF-8"),
                socket.to_str().expect("socket path UTF-8"),
                lease_socket.to_str().expect("lease path UTF-8"),
                replay_path.to_str().expect("replay path UTF-8"),
                "socket-e2e-v1",
            ])
            .arg(&lease_generation)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("socket process must spawn");
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if socket.exists() {
                break;
            }
            if let Some(status) = child.try_wait().expect("poll socket process") {
                let mut stderr = String::new();
                child
                    .stderr
                    .take()
                    .expect("socket stderr pipe")
                    .read_to_string(&mut stderr)
                    .expect("read early socket stderr");
                panic!("socket process exited before bind ({status}): {stderr}");
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {} (expected exists=true)",
                socket.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
        let mut stream = connect_retry(&socket);
        write_record(&mut stream, handshake);
        write_record(&mut stream, frame);
        if let Some(record) = trailing_record {
            write_record(&mut stream, record);
        }
        stream
            .shutdown(Shutdown::Write)
            .expect("peer half-close must succeed");
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .expect("response timeout");
        let response = read_record(&mut stream).expect("socket process response");
        let response: Value = serde_json::from_slice(&response).expect("response JSON");
        let status = child.wait().expect("wait socket process");
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("socket stderr pipe")
            .read_to_string(&mut stderr)
            .expect("read socket stderr");
        wait_for_path(&socket, false);
        (status, response, stderr)
    }

    fn write_record(stream: &mut UnixStream, bytes: &[u8]) {
        let length = u32::try_from(bytes.len()).expect("bounded test record");
        stream
            .write_all(&length.to_be_bytes())
            .expect("record length");
        stream.write_all(bytes).expect("record bytes");
        stream.flush().expect("record flush");
    }

    fn read_record(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        let mut bytes = vec![0u8; length];
        stream.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn tlv(target: &mut Vec<u8>, tag: u8, value: &[u8]) {
        target.push(tag);
        target.extend((value.len() as u32).to_be_bytes());
        target.extend(value);
    }

    fn pvarint(mut value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                return output;
            }
        }
    }

    fn pfield_varint(target: &mut Vec<u8>, field: u32, value: u64) {
        target.extend(pvarint(u64::from(field << 3)));
        target.extend(pvarint(value));
    }

    fn pfield_bytes(target: &mut Vec<u8>, field: u32, value: &[u8]) {
        target.extend(pvarint(u64::from((field << 3) | 2)));
        target.extend(pvarint(value.len() as u64));
        target.extend(value);
    }

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        fixture_for_sequence(0)
    }

    fn fixture_for_sequence(sequence: u64) -> (Vec<u8>, Vec<u8>) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let validators = (1u8..=4)
            .map(|id| {
                let validator_key = ed25519_dalek::SigningKey::from_bytes(&[40 + id; 32]);
                Validator::new(
                    ValidatorId::new([id; 32]),
                    ConsensusPublicKey::new(validator_key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("voting power"),
                )
                .expect("validator")
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::from_static("trnm-effect-driver-process-v1"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("validator set");
        let peer = ValidatorId::new([2; 32]);
        let block_id = BlockId::new([0x42; 32]);
        let unsigned_vote = Vote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            View::new(1),
            Height::new(1),
            block_id,
            set.id(),
            peer,
            SignatureBytes::from_array([0; 64]),
            &set,
        )
        .expect("vote shape");
        let vote_signature = key.sign(unsigned_vote.signing_root().as_bytes()).to_bytes();
        let vote = Vote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            View::new(1),
            Height::new(1),
            block_id,
            set.id(),
            peer,
            SignatureBytes::from_array(vote_signature),
            &set,
        )
        .expect("signed vote shape");

        let mut common = Vec::new();
        pfield_varint(&mut common, 1, 0);
        pfield_bytes(&mut common, 2, set.genesis_hash().as_bytes());
        pfield_bytes(&mut common, 3, set.chain_id().as_bytes());
        pfield_varint(&mut common, 4, 0);
        pfield_varint(&mut common, 5, set.epoch().get());
        pfield_bytes(&mut common, 6, set.id().as_bytes());
        pfield_varint(&mut common, 7, 1);
        pfield_varint(&mut common, 8, MessageKind::Vote as u64);
        pfield_bytes(&mut common, 9, set.consensus_parameters_hash().as_bytes());
        let mut vote_body = Vec::new();
        pfield_bytes(&mut vote_body, 1, &common);
        pfield_varint(&mut vote_body, 2, 1);
        pfield_bytes(&mut vote_body, 3, block_id.as_bytes());
        pfield_bytes(&mut vote_body, 4, peer.as_bytes());
        pfield_bytes(&mut vote_body, 5, vote.signature().as_bytes());

        // Frozen WireEnvelope protobuf fields, emitted in canonical order.
        // The transport session binds sender sequence zero to its first
        // replay-WAL record; the nested Vote carries the same view/context.
        let mut payload = Vec::new();
        pfield_varint(&mut payload, 1, 0);
        pfield_varint(&mut payload, 2, 0);
        pfield_bytes(&mut payload, 3, set.genesis_hash().as_bytes());
        pfield_bytes(&mut payload, 4, set.chain_id().as_bytes());
        pfield_varint(&mut payload, 5, 0);
        pfield_varint(&mut payload, 6, set.epoch().get());
        pfield_varint(&mut payload, 7, 1);
        pfield_bytes(&mut payload, 8, set.id().as_bytes());
        pfield_bytes(&mut payload, 9, set.consensus_parameters_hash().as_bytes());
        pfield_varint(&mut payload, 10, 1);
        pfield_varint(&mut payload, 11, MessageKind::Vote as u64);
        pfield_varint(&mut payload, 12, WIRE_BODY_KIND_VOTE);
        pfield_bytes(&mut payload, 13, peer.as_bytes());
        pfield_bytes(&mut payload, 14, &[0x71; 16]);
        pfield_varint(&mut payload, 15, 0);
        let body_hash: [u8; 32] = Sha256::digest(&vote_body).into();
        pfield_bytes(&mut payload, 16, &body_hash);
        pfield_bytes(&mut payload, 33, &vote_body);

        let mut handshake_unsigned = HANDSHAKE_MAGIC.to_vec();
        tlv(&mut handshake_unsigned, 1, &PROTOCOL_VERSION.to_be_bytes());
        tlv(&mut handshake_unsigned, 2, set.genesis_hash().as_bytes());
        tlv(&mut handshake_unsigned, 3, set.chain_id().as_bytes());
        tlv(&mut handshake_unsigned, 4, set.id().as_bytes());
        tlv(&mut handshake_unsigned, 5, &set.epoch().get().to_be_bytes());
        tlv(&mut handshake_unsigned, 6, peer.as_bytes());
        tlv(&mut handshake_unsigned, 7, &key.verifying_key().to_bytes());
        tlv(&mut handshake_unsigned, 8, &[0xA5; 32]);
        let handshake_root = hash_domain(DOMAIN_HANDSHAKE, &handshake_unsigned);
        let handshake_signature = key.sign(&handshake_root).to_bytes();
        let mut handshake = handshake_unsigned;
        tlv(&mut handshake, 9, &handshake_signature);

        let session_id = hash_domain(DOMAIN_SESSION_ID, &handshake);
        let mut frame_unsigned = FRAME_MAGIC.to_vec();
        tlv(&mut frame_unsigned, 1, &PROTOCOL_VERSION.to_be_bytes());
        tlv(&mut frame_unsigned, 2, &session_id);
        tlv(&mut frame_unsigned, 3, &sequence.to_be_bytes());
        tlv(&mut frame_unsigned, 4, &payload);
        let frame_root = frame_signing_root(&frame_unsigned, session_id, sequence, &payload);
        let frame_signature = key.sign(&frame_root).to_bytes();
        let mut frame = frame_unsigned;
        tlv(&mut frame, 5, &frame_signature);
        (handshake, frame)
    }

    fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn frame_signing_root(
        unsigned: &[u8],
        session_id: [u8; 32],
        sequence: u64,
        payload: &[u8],
    ) -> [u8; 32] {
        let payload_hash: [u8; 32] = Sha256::digest(payload).into();
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_FRAME);
        hasher.update(session_id);
        hasher.update(sequence.to_be_bytes());
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload_hash);
        hasher.update((unsigned.len() as u64).to_be_bytes());
        hasher.update(unsigned);
        hasher.finalize().into()
    }

    #[test]
    fn socket_valid_replay_and_malformed_paths_are_bounded() {
        let dir = tempfile::tempdir().expect("socket test dir");
        make_private(&dir);
        let replay_path = dir.path().join("payload-replay.wal");
        let (handshake, frame) = fixture();

        let daemon = LeaseDaemon::start(&dir, "lease-first");
        let (status, accepted, stderr) = send_socket_process(
            &dir,
            "valid",
            &daemon.socket,
            &replay_path,
            &handshake,
            &frame,
            None,
        );
        assert!(
            !status.success(),
            "unacknowledged Core input unexpectedly succeeded: {stderr}"
        );
        assert_eq!(accepted["status"], "uncertain");
        assert_eq!(accepted["candidate_only"], true);
        assert_eq!(accepted["production_activation"], false);
        assert_eq!(accepted["replay_commit_state"], "unknown_requires_recovery");
        assert!(accepted["reason"].as_str().is_some_and(|reason| {
            reason.contains("p2p_core_ack_missing")
                && reason.contains("did not advance SafetyState revision")
        }));
        assert!(
            replay_path
                .with_file_name(".payload-replay.wal.body-v1.wal")
                .is_file(),
            "exact authenticated body WAL must be durable beside the replay WAL"
        );
        assert!(
            dir.path()
                .join("valid.root")
                .join("p2p-replay.pending")
                .is_file(),
            "Core without a Safety revision must retain the recovery breadcrumb"
        );
        drop(daemon);

        // A fresh lease authority cannot make the exact authenticated frame
        // live again: the durable replay WAL remains the independent fence.
        let daemon = LeaseDaemon::start(&dir, "lease-replay");
        let (status, replayed, stderr) = send_socket_process(
            &dir,
            "replay",
            &daemon.socket,
            &replay_path,
            &handshake,
            &frame,
            None,
        );
        assert!(!status.success(), "replay unexpectedly succeeded: {stderr}");
        assert_eq!(replayed["status"], "uncertain");
        assert_eq!(replayed["replay_commit_state"], "unknown_requires_recovery");
        assert!(
            replayed["reason"].as_str().is_some_and(
                |reason| reason.contains("existing replay requires external Core recovery")
            ),
            "unexpected replay reason: {replayed}"
        );
        drop(daemon);

        // The handshake is framed correctly but not authenticated. It must
        // be rejected before the lease authority is touched, and the socket
        // path must still be removed on this failure path.
        let malformed = b"TRNH\x00\x00\x00\x00".to_vec();
        let daemon = LeaseDaemon::start(&dir, "lease-malformed");
        let (status, rejected, stderr) = send_socket_process(
            &dir,
            "malformed",
            &daemon.socket,
            &dir.path().join("malformed-replay.wal"),
            &malformed,
            &frame,
            None,
        );
        assert!(
            !status.success(),
            "malformed unexpectedly succeeded: {stderr}"
        );
        assert_eq!(rejected["status"], "rejected");
        assert!(
            rejected["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("p2p_handshake")),
            "unexpected malformed reason: {rejected}"
        );
    }

    #[test]
    fn socket_rejects_stale_lease_generation_without_body_append() {
        let dir = tempfile::tempdir().expect("stale-generation socket test dir");
        make_private(&dir);
        let replay_path = dir.path().join("stale-generation-replay.wal");
        let (handshake, frame) = fixture();
        let daemon = LeaseDaemon::start(&dir, "lease-stale-generation");
        let (status, rejected, stderr) = send_socket_process_with_generation(
            &dir,
            "stale-generation",
            &daemon.socket,
            &replay_path,
            &handshake,
            &frame,
            None,
            2,
        );
        assert!(
            !status.success(),
            "stale lease generation unexpectedly succeeded: {stderr}"
        );
        assert_eq!(rejected["status"], "rejected");
        assert_eq!(rejected["commit_ambiguous"], false);
        assert!(
            rejected["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("lease generation is stale")),
            "unexpected stale-generation response: {rejected}"
        );
        assert!(
            !replay_path
                .with_file_name(".stale-generation-replay.wal.body-v1.wal")
                .exists(),
            "pre-lease rejection must not create an orphan body WAL"
        );
        assert!(
            dir.path().join("stale-generation.root").is_dir(),
            "socket process should establish its private root before lease validation"
        );
        drop(daemon);
    }

    #[test]
    fn socket_rejects_trailing_record_before_lease_admission() {
        let dir = tempfile::tempdir().expect("socket trailing test dir");
        make_private(&dir);
        let replay_path = dir.path().join("trailing-replay.wal");
        let (handshake, frame) = fixture();
        let daemon = LeaseDaemon::start(&dir, "lease-trailing");
        let (status, rejected, stderr) = send_socket_process(
            &dir,
            "trailing",
            &daemon.socket,
            &replay_path,
            &handshake,
            &frame,
            Some(b"extra-record"),
        );
        assert!(
            !status.success(),
            "trailing unexpectedly succeeded: {stderr}"
        );
        assert_eq!(rejected["status"], "rejected");
        assert!(
            rejected["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("trailing")),
            "unexpected trailing reason: {rejected}"
        );
    }

    #[test]
    fn socket_parameter_rejection_precedes_root_marker_and_filesystem_work() {
        let dir = tempfile::tempdir().expect("socket parameter test dir");
        make_private(&dir);
        let root = dir.path().join("invalid.root");
        let socket = dir.path().join("invalid.sock");
        let lease = dir.path().join("missing-lease.sock");
        let replay = dir.path().join("invalid-replay.wal");
        let error = trnm_poco_node::run_p2p_socket_once_v1(
            root.clone(),
            socket,
            lease,
            replay,
            "socket-e2e-v1".to_owned(),
            0,
        )
        .expect_err("zero lease generation must be rejected");
        assert!(error.to_string().contains("generation"));
        assert!(
            !root.exists(),
            "invalid arguments must not create a root or start marker"
        );
    }
}
