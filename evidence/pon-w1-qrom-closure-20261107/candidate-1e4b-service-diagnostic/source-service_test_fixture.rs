//! Actual PQ signatures, Unix clock transport, and durable rows. Only the
//! root-owned provisioning path is substituted; no real deployment/Node claim.
use super::clock_contract;
use super::frontier::{Digest32, Frontier, Validity};
use super::frontier_service::Service;
use super::proof_test_keys;
use super::service_configuration::{Clock, Configuration};
use super::trust_wire as wire;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

pub(super) const NAMESPACE: Digest32 = [37; 32];
pub(super) const CLOCK_BINDING: Digest32 = [38; 32];
fn boottime_ns() -> u128 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u128::try_from(t.tv_sec).unwrap() * 1_000_000_000 + u128::try_from(t.tv_nsec).unwrap()
}
pub(super) struct Time {
    start: u128,
    pub mode: AtomicUsize,
    signed_seconds: AtomicU64,
    stop: AtomicBool,
}
impl Time {
    pub fn last_signed(&self) -> u64 {
        self.signed_seconds.load(Ordering::SeqCst)
    }
    // A real elapsed clock at exactly the declared maximum 2x rate, no steps.
    pub fn now(&self) -> u64 {
        20 + u64::try_from((boottime_ns() - self.start) * 2 / 1_000_000_000).unwrap()
    }
}
pub(super) fn write(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
pub(super) struct Fixture {
    _temp: tempfile::TempDir,
    pub configuration: Configuration,
    pub root_file: PathBuf,
    pub owner_key: PqNativeSigningKey,
    pub verifier: PqNativeVerifier,
    pub time: Arc<Time>,
    clock: Option<JoinHandle<()>>,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let clock_path = root.join("clock.sock");
        let listener = UnixListener::bind(&clock_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let owner_key = proof_test_keys::key(90);
        let frontier_key = proof_test_keys::key(91);
        let clock_key = proof_test_keys::key(92);
        let requester = PqNativeVerifier::from_pinned_spki(
            frontier_key.public_spki(),
            frontier_key.public_key_id(),
        )
        .unwrap();
        let verifier = PqNativeVerifier::from_pinned_spki(
            frontier_key.public_spki(),
            frontier_key.public_key_id(),
        )
        .unwrap();
        let signer_path = root.join("frontier.seed");
        write(&signer_path, &[91; 32]);
        let clock_contract = clock_contract::Contract {
            profile: "trnm-m15-boottime-bounded-clock-v1".into(),
            integer_seconds_are_floor: true,
            forward_steps_forbidden: true,
            monotonic_nondecreasing: true,
            maximum_rate_ppm: 2_000_000,
        };
        let owner_binding = super::frontier::hash(
            b"TRNM/M15/ProtectedOwner/Binding/v1\0",
            &wire::canonical(&(
                NAMESPACE,
                [39; 32],
                clock_key.public_key_id(),
                frontier_key.public_key_id(),
                owner_key.public_key_id(),
                &clock_contract,
            ))
            .unwrap(),
        );
        let service_uid = rustix::process::geteuid().as_raw();
        let configuration = Configuration {
            schema_version: 1,
            profile: "trnm-m15-independent-frontier-v1".into(),
            service_uid,
            owner_uid: service_uid.checked_add(1).unwrap(),
            directory: root.join("database"),
            socket: root.join("frontier.sock"),
            namespace: NAMESPACE,
            initial_root_digest: [39; 32],
            clock_contract,
            owner_binding,
            owner_key_id: owner_key.public_key_id(),
            owner_spki_hex: hex::encode(owner_key.public_spki()),
            signer_seed: signer_path.clone(),
            signer_key_id: frontier_key.public_key_id(),
            clock: Clock {
                socket: clock_path,
                server_key_id: clock_key.public_key_id(),
                server_spki_hex: hex::encode(clock_key.public_spki()),
                requester_seed: signer_path,
                requester_key_id: frontier_key.public_key_id(),
                binding: CLOCK_BINDING,
            },
            expected_frontier: None,
            expected_time_floor: 0,
        };
        let root_file = root.join("protected-component-config.json");
        write(
            &root_file,
            &super::codec::encode(&configuration, 65536).unwrap(),
        );
        let time = Arc::new(Time {
            start: boottime_ns(),
            mode: AtomicUsize::new(0),
            signed_seconds: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let clock_time = time.clone();
        let clock = std::thread::spawn(move || {
            while !clock_time.stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("fixture clock accept: {e}"),
                };
                stream.set_nonblocking(true).unwrap();
                let until = Instant::now() + Duration::from_secs(2);
                let raw = super::unix_transport::receive(&mut stream, until).unwrap();
                let request: wire::Request = wire::verify(wire::REQUEST, &raw, &requester).unwrap();
                assert_eq!(request.operation, wire::Operation::Clock);
                assert_eq!(request.namespace, NAMESPACE);
                assert_eq!(request.binding, CLOCK_BINDING);
                assert_ne!(request.challenge, [0; 32]);
                assert!(
                    request.expected.is_none()
                        && request.next.is_none()
                        && request.validity.is_none()
                );
                let mut reply = wire::Reply {
                    schema_version: 1,
                    request: wire::request_digest(&raw),
                    challenge: request.challenge,
                    operation: request.operation,
                    namespace: request.namespace,
                    now_seconds: clock_time.now(),
                    accepted: true,
                    frontier: None,
                };
                let mode = clock_time.mode.load(Ordering::SeqCst);
                match mode {
                    1 => reply.challenge[0] ^= 1,
                    2 => reply.request[0] ^= 1,
                    3 => reply.namespace[0] ^= 1,
                    4 => reply.now_seconds = 0,
                    _ => {}
                }
                clock_time
                    .signed_seconds
                    .store(reply.now_seconds, Ordering::SeqCst);
                let answer = wire::sign(wire::CLOCK_REPLY, reply, &clock_key).unwrap();
                super::unix_transport::send(&mut stream, &answer, until).unwrap();
            }
        });
        Self {
            _temp: temp,
            configuration,
            root_file,
            owner_key,
            verifier,
            time,
            clock: Some(clock),
        }
    }
    pub fn scope<T>(&self, run: impl FnOnce() -> T) -> T {
        super::service_faults::with_provisioning(self.root_file.clone(), run)
    }
    pub fn persist_config(&self) {
        write(
            &self.root_file,
            &super::codec::encode(&self.configuration, 65536).unwrap(),
        );
    }
    pub fn initialized(&mut self) -> Service {
        let path = self.root_file.clone();
        super::service_faults::with_provisioning(path, || {
            let initialized = Service::open(true).unwrap().initialization().unwrap();
            self.configuration.expected_time_floor = initialized["time_floor"].as_u64().unwrap();
            self.persist_config();
            Service::open(false).unwrap()
        })
    }
    pub fn request(
        &self,
        expected: Option<Frontier>,
        next: Option<Frontier>,
        window: Option<Validity>,
    ) -> Vec<u8> {
        wire::sign(
            wire::REQUEST,
            wire::Request {
                schema_version: 1,
                operation: if next.is_some() {
                    wire::Operation::CompareAndSet
                } else {
                    wire::Operation::Load
                },
                binding: self.configuration.owner_binding,
                namespace: NAMESPACE,
                challenge: [44; 32],
                expected,
                next,
                validity: window,
            },
            &self.owner_key,
        )
        .unwrap()
    }
    pub fn reply(&self, raw: &[u8], answer: &[u8]) -> wire::Reply {
        let reply: wire::Reply =
            wire::verify(wire::FRONTIER_REPLY, answer, &self.verifier).unwrap();
        assert_eq!(reply.request, wire::request_digest(raw));
        assert_eq!(reply.challenge, [44; 32]);
        assert_eq!(reply.namespace, NAMESPACE);
        reply
    }
    pub fn row(&self) -> Vec<u8> {
        fs::read(
            self.configuration
                .directory
                .join("independent-frontier.json"),
        )
        .unwrap()
    }
    /// Exercises exact cold equality only. Reading a row is not evidence of
    /// independent custody; real deployment provisioning remains unqualified.
    pub fn pin_retained_row(&mut self) {
        let row: serde_json::Value = serde_json::from_slice(&self.row()).unwrap();
        self.configuration.expected_frontier =
            serde_json::from_value(row["frontier"].clone()).unwrap();
        self.configuration.expected_time_floor = row["time_floor"].as_u64().unwrap();
        self.persist_config();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.time.stop.store(true, Ordering::SeqCst);
        if let Some(clock) = self.clock.take() {
            let result = clock.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}
