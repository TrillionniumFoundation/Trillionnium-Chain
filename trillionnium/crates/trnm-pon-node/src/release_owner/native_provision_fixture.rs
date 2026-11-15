//! Rootless-namespace fixture for the real production fixed-root paths. Test
//! keys and its Clock are explicit fixture custody, never deployment evidence.
use super::clock_contract;
use super::frontier::{hash, invalid, Digest32, Result};
use super::native_build_fixture::{self, Build};
use super::native_isolation_fixture::{self as isolation, Process, RUNTIME_UID, SERVICE_UID};
use super::proof_wire::Root;
use super::service_configuration::{Clock, Configuration as ServiceConfiguration};
use super::trust_client::{Configuration, Endpoint};
use super::trust_wire as wire;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

const SERVICE_PATH: &str = "/etc/trillionnium/m15-frontier-service-v1.json";
const DEPLOYMENT_PATH: &str = "/etc/trillionnium/m15-operator-deployment-v1.json";
pub(super) const NODE: &str = "/m15/bin/node";
pub(super) const WORKING: &str = "/m15/runtime/work";
pub(super) const OWNER: &str = "/m15/runtime/state";
fn boottime() -> u128 {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u128::try_from(value.tv_sec).unwrap() * 1_000_000_000 + u128::try_from(value.tv_nsec).unwrap()
}

pub(super) struct ClockServer {
    pub catalog_fault: super::native_observation_fixture::ArtifactCut,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
}
impl ClockServer {
    fn start(
        namespace: Digest32,
        owner_binding: Digest32,
        service_binding: Digest32,
        owner: &PqNativeSigningKey,
        service: &PqNativeSigningKey,
        clock: PqNativeSigningKey,
    ) -> Result<Self> {
        let listener = UnixListener::bind("/m15/clock.sock")?;
        fs::set_permissions("/m15/clock.sock", fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        let owner = PqNativeVerifier::from_pinned_spki(owner.public_spki(), owner.public_key_id())
            .map_err(std::io::Error::other)?;
        let service =
            PqNativeVerifier::from_pinned_spki(service.public_spki(), service.public_key_id())
                .map_err(std::io::Error::other)?;
        let start = boottime();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let catalog_fault = super::native_observation_fixture::ArtifactCut::default();
        let callback = catalog_fault.clone();
        let thread = std::thread::spawn(move || {
            let mut observations = Vec::new();
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let uid = rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw();
                let (key, binding) = match uid {
                    RUNTIME_UID => (&owner, owner_binding),
                    SERVICE_UID => (&service, service_binding),
                    _ => return Err(invalid("native Clock received an unexpected principal")),
                };
                stream.set_nonblocking(true)?;
                let until = Instant::now() + Duration::from_secs(2);
                let raw = super::unix_transport::receive(&mut stream, until)?;
                let request: wire::Request = wire::verify(wire::REQUEST, &raw, key)?;
                if request.schema_version != 1
                    || request.operation != wire::Operation::Clock
                    || request.binding != binding
                    || request.namespace != namespace
                    || request.challenge == [0; 32]
                    || request.expected.is_some()
                    || request.next.is_some()
                    || request.validity.is_some()
                {
                    return Err(invalid("native Clock full signed request binding"));
                }
                if uid == RUNTIME_UID {
                    callback.after_owner_clock_request()?;
                }
                let elapsed = boottime()
                    .checked_sub(start)
                    .ok_or_else(|| invalid("native clock regressed"))?;
                let now = 10_000_u64
                    .checked_add(
                        u64::try_from(elapsed / 1_000_000_000).map_err(std::io::Error::other)?,
                    )
                    .ok_or_else(|| invalid("native clock overflow"))?;
                observations.push(
                    serde_json::json!({"uid":uid,"request":hex::encode(wire::request_digest(&raw)),
                    "challenge":hex::encode(request.challenge),"signed_seconds":now}),
                );
                if observations.len() > 16384 {
                    return Err(invalid("native clock observation bound"));
                }
                let reply = wire::Reply {
                    schema_version: 1,
                    request: wire::request_digest(&raw),
                    challenge: request.challenge,
                    operation: request.operation,
                    namespace,
                    now_seconds: now,
                    accepted: true,
                    frontier: None,
                };
                super::unix_transport::send(
                    &mut stream,
                    &wire::sign(wire::CLOCK_REPLY, reply, &clock)?,
                    until,
                )?;
            }
            isolation::write(
                Path::new("/m15/evidence/clock-observations.json"),
                &serde_json::to_vec(&observations).map_err(std::io::Error::other)?,
                0,
                0o600,
            )
        });
        Ok(Self {
            catalog_fault,
            stop,
            thread: Some(thread),
        })
    }
    pub fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| invalid("native Clock thread panicked"))??;
        }
        Ok(())
    }
}
impl Drop for ClockServer {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub(super) struct Fixture {
    pub build: Build,
    pub root: Root,
    pub release_keys: Vec<PqNativeSigningKey>,
    pub namespace: Digest32,
    pub trust_pin: Digest32,
    pub clock: ClockServer,
    service_configuration: ServiceConfiguration,
    command: u64,
}
impl Fixture {
    pub fn provision() -> Result<Self> {
        let marker = isolation::require_isolation()?;
        let build = Build::read(
            Path::new("/m15/build-input.json"),
            native_build_fixture::hex_digest(&marker.build_input_sha256)?,
        )?;
        if build.program != Path::new(NODE)
            || build.program_sha256 != native_build_fixture::hex_digest(&marker.node_sha256)?
        {
            return Err(invalid("native real copied program/build pin"));
        }
        for (path, uid, mode) in [
            ("/etc/trillionnium", 0, 0o755),
            ("/m15/runtime", RUNTIME_UID, 0o700),
            (WORKING, RUNTIME_UID, 0o700),
            ("/m15/frontier", SERVICE_UID, 0o755),
            ("/m15/frontier/public", SERVICE_UID, 0o755),
            ("/m15/frontier/private", SERVICE_UID, 0o700),
        ] {
            isolation::directory(Path::new(path), uid, mode)?;
        }
        let (root, release_keys) = super::proof_test_keys::root(160, 1, 46_000, [0; 32]);
        let root_raw = super::codec::encode(&root, 1048576)?;
        let root_digest = root.kernel()?.digest().map_err(std::io::Error::other)?;
        let owner_key = super::proof_test_keys::key(90);
        let frontier_key = super::proof_test_keys::key(91);
        let clock_key = super::proof_test_keys::key(92);
        let namespace = hash(
            b"TRNM/M15/IsolatedNativeNamespace/v1\0",
            &build.run_identity,
        );
        let clock_contract = clock_contract::Contract {
            profile: "trnm-m15-boottime-bounded-clock-v1".into(),
            integer_seconds_are_floor: true,
            forward_steps_forbidden: true,
            monotonic_nondecreasing: true,
            maximum_rate_ppm: 1_000_000,
        };
        let owner_binding = hash(
            b"TRNM/M15/ProtectedOwner/Binding/v1\0",
            &wire::canonical(&(
                namespace,
                root_digest,
                clock_key.public_key_id(),
                frontier_key.public_key_id(),
                owner_key.public_key_id(),
                &clock_contract,
            ))?,
        );
        let clock_binding = hash(
            b"TRNM/M15/IsolatedNativeServiceClock/v1\0",
            &wire::canonical(&(namespace, frontier_key.public_key_id(), &clock_contract))?,
        );
        let service_configuration = ServiceConfiguration {
            schema_version: 1,
            profile: "trnm-m15-independent-frontier-v1".into(),
            service_uid: SERVICE_UID,
            owner_uid: RUNTIME_UID,
            directory: "/m15/frontier/private/state".into(),
            socket: "/m15/frontier/public/frontier.sock".into(),
            namespace,
            initial_root_digest: root_digest,
            clock_contract: clock_contract.clone(),
            owner_binding,
            owner_key_id: owner_key.public_key_id(),
            owner_spki_hex: hex::encode(owner_key.public_spki()),
            signer_seed: "/m15/frontier/private/signer.seed".into(),
            signer_key_id: frontier_key.public_key_id(),
            clock: Clock {
                socket: "/m15/clock.sock".into(),
                server_key_id: clock_key.public_key_id(),
                server_spki_hex: hex::encode(clock_key.public_spki()),
                requester_seed: "/m15/frontier/private/signer.seed".into(),
                requester_key_id: frontier_key.public_key_id(),
                binding: clock_binding,
            },
            expected_frontier: None,
            expected_time_floor: 0,
        };
        let trust = Configuration {
            schema_version: 1,
            profile: "trnm-m15-owner-trust-v1".into(),
            namespace,
            initial_root: "/m15/runtime/root.json".into(),
            initial_root_file_sha256: native_build_fixture::sha(&root_raw),
            initial_root_digest: root_digest,
            clock: Endpoint {
                socket: "/m15/clock.sock".into(),
                key_id: clock_key.public_key_id(),
                spki_hex: hex::encode(clock_key.public_spki()),
            },
            clock_contract,
            frontier: Endpoint {
                socket: service_configuration.socket.clone(),
                key_id: frontier_key.public_key_id(),
                spki_hex: hex::encode(frontier_key.public_spki()),
            },
            writer_key_id: owner_key.public_key_id(),
            writer_seed: "/m15/runtime/writer.seed".into(),
            required_packages: build.required_packages(),
        };
        let trust_raw = super::codec::encode(&trust, 128 * 1024 * 1024)?;
        let trust_pin = native_build_fixture::sha(&trust_raw);
        let deployment = super::deployment::Deployment {
            schema_version: 1,
            profile: "trnm-m15-operator-deployment-v1".into(),
            runtime_uid: RUNTIME_UID,
            namespace,
            owner_directory: OWNER.into(),
            trust_configuration: "/m15/runtime/trust.json".into(),
            trust_configuration_sha256: trust_pin,
        };
        for (path, bytes, uid, mode) in [
            ("/m15/runtime/root.json", root_raw, RUNTIME_UID, 0o600),
            ("/m15/runtime/writer.seed", vec![90; 32], RUNTIME_UID, 0o600),
            (
                "/m15/frontier/private/signer.seed",
                vec![91; 32],
                SERVICE_UID,
                0o600,
            ),
            ("/m15/runtime/trust.json", trust_raw, RUNTIME_UID, 0o600),
            (
                DEPLOYMENT_PATH,
                super::codec::encode(&deployment, 65536)?,
                0,
                0o644,
            ),
            (
                SERVICE_PATH,
                super::codec::encode(&service_configuration, 65536)?,
                0,
                0o644,
            ),
        ] {
            isolation::write(Path::new(path), &bytes, uid, mode)?;
        }
        let clock = ClockServer::start(
            namespace,
            owner_binding,
            clock_binding,
            &owner_key,
            &frontier_key,
            clock_key,
        )?;
        Ok(Self {
            build,
            root,
            release_keys,
            namespace,
            trust_pin,
            clock,
            service_configuration,
            command: 0,
        })
    }
    pub fn admin(
        &mut self,
        uid: u32,
        command: &str,
        arguments: &[String],
    ) -> Result<serde_json::Value> {
        self.command = self
            .command
            .checked_add(1)
            .ok_or_else(|| invalid("native command count"))?;
        let mut args = vec![command.to_string()];
        args.extend_from_slice(arguments);
        let mut child = Process::spawn(
            &format!("command-{}", self.command),
            uid,
            Path::new(NODE),
            &args,
            &[],
        )?;
        child.close_input();
        let until = Instant::now() + Duration::from_secs(180);
        let value = child.json(None, until)?;
        if !child.wait(until)?.success() {
            return Err(invalid(
                "real production admin command failed; raw retained",
            ));
        }
        Ok(value)
    }
    pub fn start_service(&mut self) -> Result<Process> {
        let initialized =
            self.admin(SERVICE_UID, "m15-release-owner-frontier-initialize-v1", &[])?;
        if initialized["schema"] != "trnm-m15-independent-service-initialized-v1"
            || !initialized["frontier"].is_null()
            || initialized["production_qualified"] != false
        {
            return Err(invalid("native independent service initialize observation"));
        }
        self.service_configuration.expected_time_floor = initialized["time_floor"]
            .as_u64()
            .ok_or_else(|| invalid("native initialized floor"))?;
        let next = Path::new("/etc/trillionnium/frontier-initialized.json");
        isolation::write(
            next,
            &super::codec::encode(&self.service_configuration, 65536)?,
            0,
            0o644,
        )?;
        fs::rename(next, SERVICE_PATH)?;
        File::open("/etc/trillionnium")?.sync_all()?;
        let mut child = Process::spawn(
            "frontier-service",
            SERVICE_UID,
            Path::new(NODE),
            &["m15-release-owner-frontier-serve-v1".into()],
            &[],
        )?;
        let until = Instant::now() + Duration::from_secs(180);
        while !self.service_configuration.socket.exists() {
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        child.close_input();
        Ok(child)
    }
    pub fn index(&self) -> Result<super::records::Index> {
        super::codec::decode(
            &native_build_fixture::bounded(
                &PathBuf::from(OWNER).join("index.json"),
                super::frontier::MAX_INDEX_BYTES as u64,
            )?,
            super::frontier::MAX_INDEX_BYTES,
        )
    }
    pub fn publish(&mut self, value: &super::proof_wire::Publication) -> Result<()> {
        let path = PathBuf::from(format!(
            "/m15/runtime/publication-{}.json",
            self.command + 1
        ));
        isolation::write(
            &path,
            &super::codec::encode(value, super::records::MAX_RECORD_BYTES)?,
            RUNTIME_UID,
            0o600,
        )?;
        let result = self.admin(
            RUNTIME_UID,
            "m15-release-owner-publish-v1",
            &[
                "--publication".into(),
                path.to_str()
                    .ok_or_else(|| invalid("native publication path"))?
                    .into(),
            ],
        )?;
        if result["schema"] != "trnm-m15-publication-v1" || result["execution_authorized"] != false
        {
            return Err(invalid("native actual publication observation"));
        }
        Ok(())
    }
}
