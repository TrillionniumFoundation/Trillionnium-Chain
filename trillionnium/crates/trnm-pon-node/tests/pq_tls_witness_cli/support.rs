use super::fixtures::Fixture;
use openssl::pkey::{PKey, Private};
use rustix::net::{recv, RecvFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
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
}
impl Running {
    pub fn start(mut command: Command) -> (Self, Value) {
        let mut child = command.stderr(Stdio::inherit()).spawn().unwrap();
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
        let running = Self {
            child,
            reader: Some(reader),
        };
        let event: Value =
            serde_json::from_str(&readiness.recv_timeout(Duration::from_secs(10)).unwrap())
                .unwrap();
        assert_eq!(event["event"], "pq-tls-ready");
        assert_eq!(event["pnq2_rollback_witness_selected"], true);
        assert_eq!(event["whole_node_rollback_protection"], false);
        assert_eq!(event["production_activation"], false);
        (running, event)
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
