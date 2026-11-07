use super::fixtures::Fixture;
#[path = "refusal_diagnostics.rs"]
mod refusal_diagnostics;
use openssl::pkey::{PKey, Private};
use rustix::net::{recv, RecvFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_pon_node::{
    ingress::pq_network::PqNetworkPolicy,
    pq_rollback_witness::{
        initial_network_checkpoint, Checkpoint, ConnectedWitnessTransport, DurableWitness,
        WitnessBinding, WitnessClient, MAX_EXCHANGE,
    },
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

fn signer(key: &PKey<Private>) -> PqNativeSigningKey {
    let spki = key.public_key_to_der().unwrap();
    PqNativeSigningKey::from_owned_key(key.clone(), ml_dsa_65_key_id_from_spki(&spki).unwrap())
        .unwrap()
}

pub(super) fn put(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) struct Witness {
    pub socket: PathBuf,
    pub writer: PKey<Private>,
    pub witness: PKey<Private>,
    pub calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Witness {
    pub fn new(fixture: &Fixture, directory: &Path) -> Self {
        let writer = super::fixtures::key(91);
        let witness = super::fixtures::key(92);
        let binding = WitnessBinding::new(
            &fixture.policy,
            1,
            &witness.public_key_to_der().unwrap(),
            &writer.public_key_to_der().unwrap(),
        )
        .unwrap();
        let initial = initial_network_checkpoint(&fixture.policy, &binding).unwrap();
        let mut owner = DurableWitness::register_new(
            &directory.join("independent-witness.sqlite"),
            binding,
            initial,
            signer(&witness),
        )
        .unwrap();
        let socket = directory.join("w.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let halted = stop.clone();
        let counted = calls.clone();
        let worker = thread::spawn(move || {
            while !halted.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => loop {
                        if halted.load(Ordering::Acquire) {
                            break;
                        }
                        let mut byte = [0_u8; 1];
                        match recv(&stream, &mut byte, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
                            Ok((0, _)) => break,
                            Ok(_) => {
                                counted.fetch_add(1, Ordering::AcqRel);
                                if owner
                                    .serve_one(&mut stream, Instant::now() + MAX_EXCHANGE)
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(rustix::io::Errno::AGAIN) => {
                                thread::sleep(Duration::from_millis(1))
                            }
                            Err(_) => break,
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("witness accept: {error}"),
                }
            }
        });
        Self {
            socket,
            writer,
            witness,
            calls,
            stop,
            worker: Some(worker),
        }
    }
    pub fn config(&self, fixture: &Fixture, mode: &str) -> Value {
        json!({"schema":"native-pq-tls-loopback-config-v2",
            "genesis_time":fixture.settings.genesis_time(),
            "network":hex::encode(fixture.settings.network()),
            "parameters":hex::encode(fixture.settings.parameters()),
            "genesis":hex::encode(fixture.settings.genesis()),"generation":1,
            "server_spki":hex::encode(fixture.server.key.public_key_to_der().unwrap()),
            "peer_spkis":[hex::encode(fixture.peer.key.public_key_to_der().unwrap()),
                hex::encode(fixture.other.key.public_key_to_der().unwrap())],
            "ca_certificate_sha256":hex::encode(fixture.policy.tls_pins().unwrap().ca_certificate_sha256()),
            "server_name":fixture.policy.tls_pins().unwrap().server_name(),
            "witness":{"generation":1,"witness_spki":hex::encode(self.witness.public_key_to_der().unwrap()),
                "writer_spki":hex::encode(self.writer.public_key_to_der().unwrap()),
                "socket":self.socket,"node_mode":mode}})
    }
    pub fn current(&self, policy: &PqNetworkPolicy) -> Checkpoint {
        let binding = WitnessBinding::new(
            policy,
            1,
            &self.witness.public_key_to_der().unwrap(),
            &self.writer.public_key_to_der().unwrap(),
        )
        .unwrap();
        WitnessClient::new(
            binding,
            signer(&self.writer),
            Box::new(ConnectedWitnessTransport::new(
                UnixStream::connect(&self.socket).unwrap(),
            )),
        )
        .unwrap()
        .current()
        .unwrap()
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

pub(super) fn command(
    fixture: &Fixture,
    directory: &Path,
    config: &Value,
    writer: Option<&PKey<Private>>,
) -> Command {
    let bytes = serde_json::to_vec(config).unwrap();
    put(&directory.join("config.json"), &bytes, 0o644);
    put(
        &directory.join("server.pem"),
        &fixture.server.certificate.to_pem().unwrap(),
        0o644,
    );
    put(
        &directory.join("server-key.pem"),
        &fixture.server.key.private_key_to_pem_pkcs8().unwrap(),
        0o600,
    );
    put(
        &directory.join("ca.pem"),
        &fixture.ca.to_pem().unwrap(),
        0o644,
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .args([
            "pq-tls-serve",
            "--development",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "2",
        ])
        .arg("--store")
        .arg(directory.join("node"))
        .arg("--tls-config")
        .arg(directory.join("config.json"))
        .arg("--tls-config-sha256")
        .arg(hex::encode(Sha256::digest(&bytes)))
        .arg("--tls-cert")
        .arg(directory.join("server.pem"))
        .arg("--tls-key")
        .arg(directory.join("server-key.pem"))
        .arg("--tls-ca")
        .arg(directory.join("ca.pem"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(key) = writer {
        put(
            &directory.join("writer.pem"),
            &key.private_key_to_pem_pkcs8().unwrap(),
            0o600,
        );
        command
            .arg("--witness-writer-key")
            .arg(directory.join("writer.pem"));
    }
    command
}

pub(super) struct Running {
    child: Child,
    reader: Option<thread::JoinHandle<Vec<String>>>,
    stderr: Option<thread::JoinHandle<Value>>,
    output: Option<Vec<String>>,
    started: Instant,
    ready_at: Option<Instant>,
    stages: Vec<Value>,
    stages_truncated: bool,
}

// Only fixed fields are reported. Never print a child command, configuration,
// key, request/response payload or arbitrary child-output string on failure.
fn stdout_observation(line: &str) -> Value {
    let value = serde_json::from_str::<Value>(line).ok();
    let number = |name| value.as_ref()?.get("metrics")?.get(name)?.as_u64();
    let flag = |name| value.as_ref()?.get(name)?.as_bool();
    json!({
        "valid_json": value.is_some(),
        "ready_event": value.as_ref().and_then(|v| v.get("event")).and_then(Value::as_str)
            == Some("pq-tls-ready"),
        "accepted": number("accepted"), "refused": number("refused"),
        "pnq2_rollback_witness_selected": flag("pnq2_rollback_witness_selected"),
        "whole_node_rollback_protection": flag("whole_node_rollback_protection"),
        "production_activation": flag("production_activation"),
        "public_wan_qualification": flag("public_wan_qualification")
    })
}

fn stderr_observation(mut stream: impl Read) -> Value {
    let mut prefix = Vec::new();
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 1024];
    let error = loop {
        match stream.read(&mut buffer) {
            Ok(0) => break None,
            Ok(count) => {
                bytes = bytes.saturating_add(count as u64);
                digest.update(&buffer[..count]);
                let retained = count.min(4096 - prefix.len());
                prefix.extend_from_slice(&buffer[..retained]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break Some(format!("{:?}", error.kind())),
        }
    };
    let text = String::from_utf8_lossy(&prefix);
    let markers: Vec<_> = [
        "PQ_NETWORK_DEADLINE",
        "PQ_WITNESS_DEADLINE",
        "PQ_WITNESS_COMMIT_UNCERTAIN",
        "PQ_WITNESS_ROLLBACK",
        "PQ_WITNESS_OBSERVATION_ROLLBACK",
        "PQ_WITNESS_UNAVAILABLE",
        "PQ_WITNESS_EOF",
        "PQ_TLS",
        "SQLITE",
        "IO:",
        "PRIVATE_ABI_UNSUPPORTED",
        "panicked at",
    ]
    .into_iter()
    .filter(|marker| text.contains(*marker))
    .collect();
    json!({"observed_bytes":bytes,"observed_sha256":hex::encode(digest.finalize()),
        "marker_scan_bytes":prefix.len(),"marker_scan_truncated":bytes > prefix.len() as u64,
        "known_markers":markers,"read_error_kind":error,"raw_text_redacted":true,
        "connection_refusals":refusal_diagnostics::records(&prefix)})
}

fn child_observation(status: std::io::Result<Option<ExitStatus>>) -> Value {
    match status {
        Ok(Some(status)) => json!({"state":"exited","success":status.success(),
            "exit_code":status.code(),"signal":status.signal()}),
        Ok(None) => json!({"state":"running"}),
        Err(error) => json!({"state":"unobserved","error_kind":format!("{:?}",error.kind())}),
    }
}

impl Running {
    pub fn start(mut command: Command) -> (Self, Value) {
        let started = Instant::now();
        let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
        let output = child.stdout.take().unwrap();
        let error_output = child.stderr.take().unwrap();
        let stderr = thread::spawn(move || stderr_observation(error_output));
        let (ready, readiness) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = Vec::new();
            let mut input = BufReader::new(output);
            loop {
                // Bound each read before allocation, including a possible CRLF.
                // The original 65,536-byte line assertion remains unchanged.
                let mut bytes = Vec::new();
                if input
                    .by_ref()
                    .take(65_539)
                    .read_until(b'\n', &mut bytes)
                    .unwrap()
                    == 0
                {
                    break;
                }
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                }
                let line = String::from_utf8(bytes)
                    .unwrap_or_else(|_| panic!("service stdout is not UTF-8"));
                assert!(line.len() <= 65_536);
                if lines.is_empty() {
                    let _ = ready.send(line.clone());
                }
                // The first event and final report suffice; drain later lines
                // without retaining an unbounded output history.
                if lines.len() == 2 {
                    lines[1] = line;
                } else {
                    lines.push(line);
                }
            }
            lines
        });
        let mut running = Self {
            child,
            reader: Some(reader),
            stderr: Some(stderr),
            output: None,
            started,
            ready_at: None,
            stages: Vec::new(),
            stages_truncated: false,
        };
        let event: Value =
            serde_json::from_str(&readiness.recv_timeout(Duration::from_secs(10)).unwrap())
                .unwrap();
        assert_eq!(event["event"], "pq-tls-ready");
        assert_eq!(event["pnq2_rollback_witness_selected"], true);
        assert_eq!(event["whole_node_rollback_protection"], false);
        assert_eq!(event["production_activation"], false);
        running.ready_at = Some(Instant::now());
        (running, event)
    }

    // This helper is also compiled by the original witness CLI harness, which
    // does not add endpoint request timings.
    #[allow(dead_code)]
    pub fn observe<T>(
        &mut self,
        stage: &'static str,
        action: impl FnOnce() -> trnm_pon_node::Result<T>,
    ) -> trnm_pon_node::Result<T> {
        let began = Instant::now();
        let result = action();
        let elapsed = began.elapsed();
        if self.stages.len() < 8 {
            self.stages.push(json!({"stage":stage,
                "start_since_ready_us":began.duration_since(self.ready_at.unwrap_or(self.started)).as_micros(),
                "elapsed_us":elapsed.as_micros(),"ok":result.is_ok(),
                "error_kind":result.as_ref().err().map(|error| format!("{:?}", error.kind())),
                "error_code":result.as_ref().err().and_then(|error| error.code()).map(|code| code.as_str())}));
        } else {
            self.stages_truncated = true;
        }
        // Return the exact original result; diagnostics never retry an action.
        result
    }

    pub fn finish(mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < until, "bounded service did not exit");
            thread::sleep(Duration::from_millis(2));
        }
        self.output = Some(self.reader.take().unwrap().join().unwrap());
        let lines = self.output.as_ref().unwrap();
        serde_json::from_str(lines.last().unwrap()).unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let panicking = thread::panicking();
        let failure_at = Instant::now();
        let before_cleanup = panicking.then(|| child_observation(self.child.try_wait()));
        let _ = self.child.kill();
        let after_cleanup = self.child.wait();
        if let Some(reader) = self.reader.take() {
            self.output = reader.join().ok();
        }
        let stderr = self.stderr.take().and_then(|reader| reader.join().ok());
        if panicking {
            let stdout = self.output.as_ref().map(|lines| {
                lines
                    .iter()
                    .map(|line| stdout_observation(line))
                    .collect::<Vec<_>>()
            });
            let observation = json!({"schema":"trnm-pq-tls-cli-failure-v1",
                "pid":self.child.id(),"failure_since_spawn_start_us":failure_at.duration_since(self.started).as_micros(),
                "cleanup_elapsed_us":failure_at.elapsed().as_micros(),
                "ready_received_us":self.ready_at.map(|ready| ready.duration_since(self.started).as_micros()),
                "child_before_cleanup":before_cleanup,
                "child_after_cleanup":child_observation(after_cleanup.map(Some)),
                "stdout":stdout,"stdout_capture":"first_and_last_only","stderr":stderr,
                "request_stages":self.stages,"request_stages_truncated":self.stages_truncated});
            // A diagnostic write failure must not replace the original panic.
            let _ = writeln!(
                std::io::stderr().lock(),
                "TRNM_PQ_TLS_CLI_DIAGNOSTIC {observation}"
            );
        }
    }
}

pub(super) fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>, u32)> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, out);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                out.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                    entry.metadata().unwrap().permissions().mode(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
