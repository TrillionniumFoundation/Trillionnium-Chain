//! Private, bounded local control/observation plane for the G3 runtime.
//!
//! External orchestration may request that the runtime expect one named fault
//! and may read status.  A request is never evidence that a fault happened.
//! Only the live runtime, after observing the corresponding network/Core/store
//! condition, may append `fault_applied` and `fault_recovered` to the signed
//! process journal.

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::ValidatorId;

use crate::{
    config::LoadedValidatorConfig,
    process_event::{RuntimeEventJournalV1, RuntimeFaultV1, RuntimeJournalObservationV1},
};

const CONTROL_SCHEMA_VERSION: u32 = 1;
const CONTROL_SOCKET_PREFIX: &str = "runtime-control";
const CONTROL_STATUS_FILE: &str = "runtime-control-status.json";
const MAX_SOCKET_PATH_BYTES: usize = 100;
const MAX_REQUEST_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 16_384;
const MAX_NONCE_CACHE: usize = 32;
const MAX_REJECTED_REQUESTS: u64 = 64;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_millis(500);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeControlStatusV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub process_id: u32,
    pub process_instance: u64,
    pub generation: u64,
    pub socket_basename: String,
    pub journal_event_sequence: u64,
    pub journal_event_sha256: String,
    pub production_activation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeControlRequestV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub process_instance: u64,
    pub generation: u64,
    pub nonce: u64,
    pub verb: String,
    pub fault: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeControlResponseV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub process_instance: u64,
    pub generation: u64,
    pub nonce: u64,
    pub verb: String,
    pub status: String,
    pub expected_fault: String,
    pub barrier_phase: String,
    pub fleet_ready_set_sha256: String,
    pub fleet_start_certificate_sha256: String,
    pub journal_event_sequence: u64,
    pub journal_event_sha256: String,
    pub finalized_height: u64,
    pub application_height: u64,
    pub restart_pending_catchup: bool,
    pub restart_completed: bool,
    pub active_faults: Vec<String>,
    pub recovered_faults: Vec<String>,
    pub final_tip_recorded: bool,
    pub clean_stop_recorded: bool,
    pub safety_halted: bool,
    pub production_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeControlPollV1 {
    Idle,
    Responded { verb: String, nonce: u64 },
    Rejected { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NonceNamespaceV1 {
    Read,
    Command,
    Restart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlVerbV1 {
    Status,
    ExpectFault,
    ClearFaultExpectation,
    PrepareRestart,
}

impl ControlVerbV1 {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "status" => Some(Self::Status),
            "expect_fault" => Some(Self::ExpectFault),
            "clear_fault_expectation" => Some(Self::ClearFaultExpectation),
            "prepare_restart" => Some(Self::PrepareRestart),
            _ => None,
        }
    }

    const fn namespace(self) -> NonceNamespaceV1 {
        match self {
            Self::Status => NonceNamespaceV1::Read,
            Self::ExpectFault | Self::ClearFaultExpectation => NonceNamespaceV1::Command,
            Self::PrepareRestart => NonceNamespaceV1::Restart,
        }
    }
}

/// Authenticated request intent retained by the runtime owner. It contains no
/// caller-selected success, height, state, cut, signer, or journal facts and
/// therefore cannot itself authorize a restart or claim a prepared cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeRestartPrepareIntentV1 {
    process_instance: u64,
    generation: u64,
    nonce: u64,
    request_sha256: [u8; 32],
}

impl RuntimeRestartPrepareIntentV1 {
    #[cfg(test)]
    pub(crate) const fn test_only_v1(
        process_instance: u64,
        generation: u64,
        nonce: u64,
        request_sha256: [u8; 32],
    ) -> Self {
        Self {
            process_instance,
            generation,
            nonce,
            request_sha256,
        }
    }

    pub(crate) const fn process_instance_v1(self) -> u64 {
        self.process_instance
    }

    pub(crate) const fn generation_v1(self) -> u64 {
        self.generation
    }

    pub(crate) const fn nonce_v1(self) -> u64 {
        self.nonce
    }

    pub(crate) const fn request_sha256_v1(self) -> [u8; 32] {
        self.request_sha256
    }
}

#[derive(Clone)]
struct CachedResponseV1 {
    namespace: NonceNamespaceV1,
    nonce: u64,
    request_sha256: [u8; 32],
    response: Vec<u8>,
}

#[derive(Clone)]
struct RuntimeControlStateV1 {
    run_id: String,
    validator_id: String,
    process_instance: u64,
    generation: u64,
    expected_fault: Option<RuntimeFaultV1>,
    restart_prepare_intent: Option<RuntimeRestartPrepareIntentV1>,
    journal_event_sequence: u64,
    journal_event_sha256: [u8; 32],
    journal: RuntimeJournalObservationV1,
    last_nonce: BTreeMap<NonceNamespaceV1, u64>,
    cache: VecDeque<CachedResponseV1>,
}

impl RuntimeControlStateV1 {
    fn from_journal(
        run_id: String,
        validator_id: ValidatorId,
        generation: u64,
        journal: &RuntimeEventJournalV1,
    ) -> Result<Self> {
        if generation == 0 {
            bail!("runtime control generation must be positive");
        }
        let observation = journal.observation();
        let (journal_event_sequence, journal_event_sha256) = journal
            .last_event_facts()
            .ok_or_else(|| anyhow!("runtime control requires signed process-start evidence"))?;
        if observation.process_instance != journal.process_instance()
            || observation.next_sequence
                != journal_event_sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("runtime control journal sequence overflow"))?
            || journal_event_sha256 == [0; 32]
        {
            bail!("runtime control initial journal observation is inconsistent");
        }
        Ok(Self {
            run_id,
            validator_id: hex::encode(validator_id.as_bytes()),
            process_instance: observation.process_instance,
            generation,
            expected_fault: None,
            restart_prepare_intent: None,
            journal_event_sequence,
            journal_event_sha256,
            journal: observation,
            last_nonce: BTreeMap::new(),
            cache: VecDeque::new(),
        })
    }

    fn refresh(&mut self, journal: &RuntimeEventJournalV1) -> Result<()> {
        let observation = journal.observation();
        let (sequence, digest) = journal
            .last_event_facts()
            .ok_or_else(|| anyhow!("runtime control lost signed journal head"))?;
        if observation.process_instance != self.process_instance
            || observation.next_sequence
                != sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("runtime control journal sequence overflow"))?
            || sequence < self.journal_event_sequence
            || observation.finalized_height < self.journal.finalized_height
            || observation.application_height < self.journal.application_height
            || barrier_phase_rank_v1(&observation.barrier_phase)
                < barrier_phase_rank_v1(&self.journal.barrier_phase)
            || self
                .journal
                .fleet_ready_set_sha256
                .is_some_and(|digest| observation.fleet_ready_set_sha256 != Some(digest))
            || self
                .journal
                .fleet_start_certificate_sha256
                .is_some_and(|digest| observation.fleet_start_certificate_sha256 != Some(digest))
            || self
                .journal
                .restart_prepare_nonce
                .is_some_and(|nonce| observation.restart_prepare_nonce != Some(nonce))
            || observation.restart_prepare_nonce.is_some_and(|nonce| {
                self.restart_prepare_intent
                    .is_none_or(|intent| intent.nonce_v1() != nonce)
            })
            || digest == [0; 32]
        {
            bail!("runtime control journal observation regressed or changed incarnation");
        }
        self.journal_event_sequence = sequence;
        self.journal_event_sha256 = digest;
        self.journal = observation;
        Ok(())
    }

    fn process(&mut self, raw: &[u8]) -> Result<(Vec<u8>, String, u64)> {
        let request: RuntimeControlRequestV1 =
            serde_json::from_slice(raw).context("decode runtime control request")?;
        if serde_json::to_vec(&request).context("re-encode runtime control request")? != raw {
            bail!("runtime control request is not canonical Rust JSON");
        }
        if request.schema_version != CONTROL_SCHEMA_VERSION
            || request.run_id != self.run_id
            || request.validator_id != self.validator_id
            || request.process_instance != self.process_instance
            || request.generation != self.generation
            || request.nonce == 0
        {
            bail!("runtime control request context is stale or foreign");
        }
        let verb = ControlVerbV1::parse(&request.verb)
            .ok_or_else(|| anyhow!("runtime control verb is unknown"))?;
        let namespace = verb.namespace();
        let request_sha256: [u8; 32] = Sha256::digest(raw).into();
        if let Some(cached) = self
            .cache
            .iter()
            .find(|cached| cached.namespace == namespace && cached.nonce == request.nonce)
        {
            if cached.request_sha256 != request_sha256 {
                bail!("runtime control nonce was reused with different bytes");
            }
            return Ok((cached.response.clone(), request.verb, request.nonce));
        }
        if self
            .last_nonce
            .get(&namespace)
            .is_some_and(|last| request.nonce <= *last)
        {
            bail!("runtime control nonce is stale outside the idempotence window");
        }

        match verb {
            ControlVerbV1::Status => {
                if !request.fault.is_empty() {
                    bail!("runtime status request fault must be empty");
                }
            }
            ControlVerbV1::ExpectFault => {
                if self.restart_prepare_intent.is_some() {
                    bail!("runtime fault command follows restart-prepare intent");
                }
                if self.journal.barrier_phase != "started" {
                    bail!("runtime fault command precedes fleet Started");
                }
                let fault = RuntimeFaultV1::parse(&request.fault)
                    .ok_or_else(|| anyhow!("runtime fault expectation is unknown"))?;
                match self.expected_fault {
                    None => self.expected_fault = Some(fault),
                    Some(current) if current == fault => {}
                    Some(_) => bail!("a different runtime fault expectation is already active"),
                }
            }
            ControlVerbV1::ClearFaultExpectation => {
                if self.restart_prepare_intent.is_some() {
                    bail!("runtime fault command follows restart-prepare intent");
                }
                if self.journal.barrier_phase != "started" {
                    bail!("runtime fault command precedes fleet Started");
                }
                let fault = RuntimeFaultV1::parse(&request.fault)
                    .ok_or_else(|| anyhow!("runtime fault expectation is unknown"))?;
                if self.expected_fault != Some(fault)
                    || !self
                        .journal
                        .recovered_faults
                        .iter()
                        .any(|recovered| recovered == fault.as_str())
                {
                    bail!("runtime fault expectation cannot clear before exact signed recovery");
                }
                self.expected_fault = None;
            }
            ControlVerbV1::PrepareRestart => {
                if !request.fault.is_empty() {
                    bail!("runtime restart-prepare request fault must be empty");
                }
                if self.process_instance != 1
                    || self.journal.barrier_phase != "started"
                    || self.expected_fault.is_some()
                    || !self.journal.active_faults.is_empty()
                    || self.journal.restart_prepare_nonce.is_some()
                    || self.journal.restart_pending_catchup
                    || self.journal.restart_completed
                    || self.journal.final_tip_recorded
                    || self.journal.clean_stop_recorded
                    || self.journal.safety_halted
                    || self.restart_prepare_intent.is_some()
                {
                    bail!("runtime restart-prepare intent is not admissible in this state");
                }
                self.restart_prepare_intent = Some(RuntimeRestartPrepareIntentV1 {
                    process_instance: self.process_instance,
                    generation: self.generation,
                    nonce: request.nonce,
                    request_sha256,
                });
            }
        }
        let response = RuntimeControlResponseV1 {
            schema_version: CONTROL_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            validator_id: self.validator_id.clone(),
            process_instance: self.process_instance,
            generation: self.generation,
            nonce: request.nonce,
            verb: request.verb.clone(),
            status: "ok".to_owned(),
            expected_fault: self
                .expected_fault
                .map_or_else(String::new, |fault| fault.as_str().to_owned()),
            barrier_phase: self.journal.barrier_phase.clone(),
            fleet_ready_set_sha256: self
                .journal
                .fleet_ready_set_sha256
                .map_or_else(String::new, |digest| hex::encode(digest)),
            fleet_start_certificate_sha256: self
                .journal
                .fleet_start_certificate_sha256
                .map_or_else(String::new, |digest| hex::encode(digest)),
            journal_event_sequence: self.journal_event_sequence,
            journal_event_sha256: hex::encode(self.journal_event_sha256),
            finalized_height: self.journal.finalized_height,
            application_height: self.journal.application_height,
            restart_pending_catchup: self.journal.restart_pending_catchup,
            restart_completed: self.journal.restart_completed,
            active_faults: self.journal.active_faults.clone(),
            recovered_faults: self.journal.recovered_faults.clone(),
            final_tip_recorded: self.journal.final_tip_recorded,
            clean_stop_recorded: self.journal.clean_stop_recorded,
            safety_halted: self.journal.safety_halted,
            production_activation: false,
        };
        let response = serde_json::to_vec(&response).context("encode runtime control response")?;
        if response.is_empty() || response.len() > MAX_RESPONSE_BYTES {
            bail!("runtime control response crosses its bound");
        }
        self.last_nonce.insert(namespace, request.nonce);
        self.cache.push_back(CachedResponseV1 {
            namespace,
            nonce: request.nonce,
            request_sha256,
            response: response.clone(),
        });
        while self.cache.len() > MAX_NONCE_CACHE {
            self.cache.pop_front();
        }
        Ok((response, request.verb, request.nonce))
    }
}

/// Single-owner local control server. It never spawns an unbounded worker and
/// processes at most one request per `poll_once` call.
pub struct RuntimeControlServerV1 {
    listener: UnixListener,
    path: PathBuf,
    socket_dev: u64,
    socket_ino: u64,
    state: RuntimeControlStateV1,
    rejected_requests: u64,
    closed: bool,
}

impl RuntimeControlServerV1 {
    pub fn bind(
        config: &LoadedValidatorConfig,
        generation: u64,
        journal: &RuntimeEventJournalV1,
    ) -> Result<Self> {
        let state = RuntimeControlStateV1::from_journal(
            config.run_id().to_owned(),
            config.local_validator(),
            generation,
            journal,
        )?;
        let path =
            exact_control_socket_path(config.run_root(), state.process_instance, state.generation)?;
        let (listener, socket_dev, socket_ino) = bind_exact_socket(config.run_root(), &path)?;
        Ok(Self {
            listener,
            path,
            socket_dev,
            socket_ino,
            state,
            rejected_requests: 0,
            closed: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn generation(&self) -> u64 {
        self.state.generation
    }

    pub const fn process_instance(&self) -> u64 {
        self.state.process_instance
    }

    pub fn expected_fault(&self) -> Option<RuntimeFaultV1> {
        self.state.expected_fault
    }

    pub(crate) const fn restart_prepare_intent_v1(&self) -> Option<RuntimeRestartPrepareIntentV1> {
        self.state.restart_prepare_intent
    }

    pub fn refresh_from_journal(&mut self, journal: &RuntimeEventJournalV1) -> Result<()> {
        self.state.refresh(journal)
    }

    pub fn poll_once(&mut self, timeout: Duration) -> Result<RuntimeControlPollV1> {
        if self.closed {
            bail!("runtime control server is closed");
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| anyhow!("runtime control poll deadline overflow"))?;
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let outcome = match handle_stream(&mut stream, &mut self.state) {
                        Ok((verb, nonce)) => RuntimeControlPollV1::Responded { verb, nonce },
                        Err(error) => {
                            self.rejected_requests =
                                self.rejected_requests.checked_add(1).ok_or_else(|| {
                                    anyhow!("runtime control reject counter overflow")
                                })?;
                            if self.rejected_requests > MAX_REJECTED_REQUESTS {
                                bail!("runtime control rejected-request bound exceeded");
                            }
                            RuntimeControlPollV1::Rejected {
                                reason: error.to_string(),
                            }
                        }
                    };
                    return Ok(outcome);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(RuntimeControlPollV1::Idle);
                    }
                    std::thread::sleep(
                        ACCEPT_POLL.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error).context("accept runtime control request"),
            }
        }
    }

    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }

    fn close_inner(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        unlink_exact_socket(&self.path, self.socket_dev, self.socket_ino)
    }
}

/// Create one fixed, private locator for the current control incarnation.
///
/// This value is not consensus or fault evidence. It exists only so a remote
/// fleet runner can discover the exact PID, process incarnation, generation,
/// and socket without globbing. A killed process deliberately leaves the file
/// behind; the runner must start the next incarnation in a fresh root or
/// explicitly remove this exact file before launch.
pub fn write_runtime_control_status_v1(
    config: &LoadedValidatorConfig,
    server: &RuntimeControlServerV1,
    journal: &RuntimeEventJournalV1,
) -> Result<PathBuf> {
    if server.process_instance() != journal.process_instance() {
        bail!("runtime control status owners differ");
    }
    let (journal_event_sequence, journal_event_sha256) = journal
        .last_event_facts()
        .ok_or_else(|| anyhow!("runtime control status requires one journal head"))?;
    let socket_basename = server
        .path()
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("runtime control socket basename is not UTF-8"))?
        .to_owned();
    if server.path()
        != exact_control_socket_path(
            config.run_root(),
            server.process_instance(),
            server.generation(),
        )?
    {
        bail!("runtime control server path differs from exact incarnation");
    }
    let status = RuntimeControlStatusV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        run_id: config.run_id().to_owned(),
        validator_id: hex::encode(config.local_validator().as_bytes()),
        process_id: std::process::id(),
        process_instance: server.process_instance(),
        generation: server.generation(),
        socket_basename,
        journal_event_sequence,
        journal_event_sha256: hex::encode(journal_event_sha256),
        production_activation: false,
    };
    validate_control_status(&status, config)?;
    let bytes = serde_json::to_vec(&status).context("encode runtime control status")?;
    let target = config.run_root().join(CONTROL_STATUS_FILE);
    let root_metadata = fs::metadata(config.run_root()).context("stat runtime control root")?;
    let directory = fs::File::open(config.run_root()).context("open runtime control root")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&target)
        .context("create runtime control status")?;
    file.write_all(&bytes)
        .context("write runtime control status")?;
    file.sync_all().context("sync runtime control status")?;
    directory
        .sync_all()
        .context("sync runtime control status parent")?;
    let metadata = file.metadata().context("stat runtime control status")?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != root_metadata.uid()
        || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        bail!("runtime control status identity differs after write");
    }
    drop(file);
    let readback = load_runtime_control_status_v1(&target)?;
    validate_control_status(&readback, config)?;
    if readback != status {
        bail!("runtime control status fresh readback differs");
    }
    Ok(target)
}

pub fn load_runtime_control_status_v1(path: &Path) -> Result<RuntimeControlStatusV1> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open runtime control status")?;
    let metadata = file.metadata().context("stat runtime control status")?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX)
    {
        bail!("runtime control status crosses its size bound");
    }
    let capacity =
        usize::try_from(metadata.len()).context("runtime control status size overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .context("read runtime control status")?;
    if bytes.len() != capacity {
        bail!("runtime control status changed length while read");
    }
    let status: RuntimeControlStatusV1 =
        serde_json::from_slice(&bytes).context("decode runtime control status")?;
    if serde_json::to_vec(&status).context("re-encode runtime control status")? != bytes {
        bail!("runtime control status is not canonical JSON");
    }
    Ok(status)
}

/// Exact, no-glob client for one runtime-control incarnation.
pub fn send_runtime_control_request_v1(
    config: &LoadedValidatorConfig,
    process_instance: u64,
    generation: u64,
    nonce: u64,
    verb: &str,
    fault: &str,
) -> Result<RuntimeControlResponseV1> {
    if nonce == 0 {
        bail!("runtime control nonce must be positive");
    }
    let request = RuntimeControlRequestV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        run_id: config.run_id().to_owned(),
        validator_id: hex::encode(config.local_validator().as_bytes()),
        process_instance,
        generation,
        nonce,
        verb: verb.to_owned(),
        fault: fault.to_owned(),
    };
    let request_bytes = serde_json::to_vec(&request).context("encode runtime control request")?;
    if request_bytes.is_empty() || request_bytes.len() > MAX_REQUEST_BYTES {
        bail!("runtime control request crosses its size bound");
    }
    let socket = exact_control_socket_path(config.run_root(), process_instance, generation)?;
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect exact runtime control socket {}", socket.display()))?;
    stream
        .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
        .context("set runtime control client read timeout")?;
    stream
        .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
        .context("set runtime control client write timeout")?;
    stream
        .write_all(&request_bytes)
        .context("write runtime control request")?;
    stream
        .write_all(b"\n")
        .context("terminate runtime control request")?;
    stream.flush().context("flush runtime control request")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("write-half close runtime control request")?;
    let mut response_bytes = Vec::new();
    stream
        .take(u64::try_from(MAX_RESPONSE_BYTES + 2).unwrap_or(u64::MAX))
        .read_to_end(&mut response_bytes)
        .context("read runtime control response")?;
    if response_bytes.len() < 3
        || response_bytes.len() > MAX_RESPONSE_BYTES + 1
        || !response_bytes.ends_with(b"\n")
    {
        bail!("runtime control response is absent or crosses its framing bound");
    }
    response_bytes.pop();
    if response_bytes.contains(&b'\n') || response_bytes.contains(&b'\r') {
        bail!("runtime control response contains trailing or embedded records");
    }
    let response: RuntimeControlResponseV1 =
        serde_json::from_slice(&response_bytes).context("decode runtime control response")?;
    if serde_json::to_vec(&response).context("re-encode runtime control response")?
        != response_bytes
    {
        bail!("runtime control response is not canonical JSON");
    }
    if response.schema_version != CONTROL_SCHEMA_VERSION
        || response.run_id != request.run_id
        || response.validator_id != request.validator_id
        || response.process_instance != process_instance
        || response.generation != generation
        || response.nonce != nonce
        || response.verb != verb
        || response.status != "ok"
        || response.production_activation
        || !is_canonical_nonzero_hex32(&response.journal_event_sha256)
        || !valid_barrier_projection_v1(
            &response.barrier_phase,
            &response.fleet_ready_set_sha256,
            &response.fleet_start_certificate_sha256,
        )
    {
        bail!("runtime control response context differs from the exact request");
    }
    Ok(response)
}

fn validate_control_status(
    status: &RuntimeControlStatusV1,
    config: &LoadedValidatorConfig,
) -> Result<()> {
    if status.schema_version != CONTROL_SCHEMA_VERSION
        || status.run_id != config.run_id()
        || status.validator_id != hex::encode(config.local_validator().as_bytes())
        || status.process_id == 0
        || status.process_instance == 0
        || status.process_instance > 2
        || status.generation == 0
        || !is_canonical_nonzero_hex32(&status.journal_event_sha256)
        || status.production_activation
        || status.socket_basename
            != format!(
                "{CONTROL_SOCKET_PREFIX}.instance-{}.generation-{}.sock",
                status.process_instance, status.generation
            )
    {
        bail!("runtime control status crosses its exact locator profile");
    }
    Ok(())
}

fn is_canonical_nonzero_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value != "0".repeat(64)
}

fn barrier_phase_rank_v1(value: &str) -> u8 {
    match value {
        "preparing" => 1,
        "ready" => 2,
        "started" => 3,
        _ => 0,
    }
}

fn valid_barrier_projection_v1(phase: &str, ready: &str, started: &str) -> bool {
    match phase {
        "preparing" => ready.is_empty() && started.is_empty(),
        "ready" => is_canonical_nonzero_hex32(ready) && started.is_empty(),
        "started" => is_canonical_nonzero_hex32(ready) && is_canonical_nonzero_hex32(started),
        _ => false,
    }
}

impl Drop for RuntimeControlServerV1 {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

fn handle_stream(
    stream: &mut UnixStream,
    state: &mut RuntimeControlStateV1,
) -> Result<(String, u64)> {
    stream
        .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
        .context("set runtime control read timeout")?;
    stream
        .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
        .context("set runtime control write timeout")?;
    let raw = read_one_request(stream)?;
    let (response, verb, nonce) = state.process(&raw)?;
    stream
        .write_all(&response)
        .context("write runtime control response")?;
    stream
        .write_all(b"\n")
        .context("terminate runtime control response")?;
    stream.flush().context("flush runtime control response")?;
    Ok((verb, nonce))
}

fn read_one_request(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        let read = stream
            .read(&mut buffer)
            .context("read runtime control request")?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > MAX_REQUEST_BYTES + 1 {
            bail!("runtime control request exceeds its framing bound");
        }
    }
    if bytes.len() < 3 || bytes.len() > MAX_REQUEST_BYTES + 1 || !bytes.ends_with(b"\n") {
        bail!("runtime control request must be one bounded JSON line and write-half closed");
    }
    bytes.pop();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        bail!("runtime control request contains trailing or embedded records");
    }
    Ok(bytes)
}

fn exact_control_socket_path(
    run_root: &Path,
    process_instance: u64,
    generation: u64,
) -> Result<PathBuf> {
    if process_instance == 0 || process_instance > 2 || generation == 0 {
        bail!("runtime control instance/generation is outside its bounded profile");
    }
    let file_name =
        format!("{CONTROL_SOCKET_PREFIX}.instance-{process_instance}.generation-{generation}.sock");
    let path = run_root.join(file_name);
    if path.as_os_str().as_encoded_bytes().len() > MAX_SOCKET_PATH_BYTES {
        bail!("runtime control socket path exceeds its portable bound");
    }
    Ok(path)
}

fn bind_exact_socket(run_root: &Path, path: &Path) -> Result<(UnixListener, u64, u64)> {
    let canonical_root = run_root
        .canonicalize()
        .context("canonicalize runtime control root")?;
    if canonical_root != run_root {
        bail!("runtime control root is not the canonical configured root");
    }
    let root_metadata = fs::metadata(&canonical_root).context("stat runtime control root")?;
    if !root_metadata.is_dir() || root_metadata.permissions().mode() & 0o777 != 0o700 {
        bail!("runtime control root must be one private 0700 directory");
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("runtime control socket lacks a file name"))?
        .to_string_lossy();
    let sidecars = [
        path.to_path_buf(),
        canonical_root.join(format!("{file_name}.tmp")),
        canonical_root.join(format!("{file_name}.lock")),
    ];
    for candidate in &sidecars {
        match fs::symlink_metadata(candidate) {
            Ok(_) => bail!(
                "runtime control refuses preexisting socket/sidecar {}",
                candidate.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect runtime control target {}", candidate.display())
                })
            }
        }
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("create-new runtime control socket {}", path.display()))?;
    let setup = (|| -> Result<(u64, u64)> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("chmod runtime control socket")?;
        let metadata = fs::symlink_metadata(path).context("lstat runtime control socket")?;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != root_metadata.uid()
        {
            bail!("runtime control socket identity/permissions differ after bind");
        }
        listener
            .set_nonblocking(true)
            .context("set runtime control listener nonblocking")?;
        Ok((metadata.dev(), metadata.ino()))
    })();
    match setup {
        Ok((dev, ino)) => Ok((listener, dev, ino)),
        Err(error) => {
            if let Ok(metadata) = fs::symlink_metadata(path) {
                if metadata.file_type().is_socket() && metadata.uid() == root_metadata.uid() {
                    let _ = fs::remove_file(path);
                }
            }
            Err(error)
        }
    }
}

fn unlink_exact_socket(path: &Path, expected_dev: u64, expected_ino: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("lstat runtime control socket at close")?;
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected_dev
        || metadata.ino() != expected_ino
        || metadata.nlink() != 1
    {
        bail!("runtime control socket changed identity; refusing unlink");
    }
    fs::remove_file(path).context("unlink exact runtime control socket")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn started_control_state_v1() -> RuntimeControlStateV1 {
        RuntimeControlStateV1 {
            run_id: "poco-g3-7-20260815T000000Z-1234abcd".to_owned(),
            validator_id: hex::encode([0x41; 32]),
            process_instance: 1,
            generation: 9,
            expected_fault: None,
            restart_prepare_intent: None,
            journal_event_sequence: 7,
            journal_event_sha256: [0x51; 32],
            journal: RuntimeJournalObservationV1 {
                process_instance: 1,
                next_sequence: 8,
                restart_prepare_nonce: None,
                restart_pending_catchup: false,
                restart_completed: false,
                barrier_phase: "started".to_owned(),
                fleet_ready_set_sha256: Some([0x52; 32]),
                fleet_start_certificate_sha256: Some([0x53; 32]),
                active_faults: Vec::new(),
                recovered_faults: Vec::new(),
                finalized_height: 4,
                application_height: 4,
                final_tip_recorded: false,
                clean_stop_recorded: false,
                safety_halted: false,
            },
            last_nonce: BTreeMap::new(),
            cache: VecDeque::new(),
        }
    }

    fn request_bytes_v1(nonce: u64, verb: &str, fault: &str) -> Vec<u8> {
        serde_json::to_vec(&RuntimeControlRequestV1 {
            schema_version: CONTROL_SCHEMA_VERSION,
            run_id: "poco-g3-7-20260815T000000Z-1234abcd".to_owned(),
            validator_id: hex::encode([0x41; 32]),
            process_instance: 1,
            generation: 9,
            nonce,
            verb: verb.to_owned(),
            fault: fault.to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn socket_path_is_instance_and_generation_qualified() {
        let temporary = TempDir::new().unwrap();
        let path = exact_control_socket_path(temporary.path(), 2, 17).unwrap();
        assert_eq!(
            path.file_name().unwrap(),
            "runtime-control.instance-2.generation-17.sock"
        );
        assert!(exact_control_socket_path(temporary.path(), 0, 17).is_err());
        assert!(exact_control_socket_path(temporary.path(), 3, 17).is_err());
        assert!(exact_control_socket_path(temporary.path(), 1, 0).is_err());
    }

    #[test]
    fn socket_bind_rejects_preexisting_exact_target_and_sidecars() {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let path = exact_control_socket_path(&root, 1, 1).unwrap();
        fs::write(&path, b"foreign").unwrap();
        assert!(bind_exact_socket(&root, &path).is_err());
        fs::remove_file(&path).unwrap();
        let sidecar = root.join(format!(
            "{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        fs::write(&sidecar, b"foreign").unwrap();
        assert!(bind_exact_socket(&root, &path).is_err());
    }

    #[test]
    fn prepare_restart_records_only_an_idempotent_intent() {
        let mut state = started_control_state_v1();
        let request = request_bytes_v1(17, "prepare_restart", "");
        let (first, verb, nonce) = state.process(&request).unwrap();
        assert_eq!(verb, "prepare_restart");
        assert_eq!(nonce, 17);
        let intent = state
            .restart_prepare_intent
            .expect("accepted request retains one intent");
        assert_eq!(intent.process_instance_v1(), 1);
        assert_eq!(intent.generation_v1(), 9);
        assert_eq!(intent.nonce_v1(), 17);
        let request_sha256: [u8; 32] = Sha256::digest(&request).into();
        assert_eq!(intent.request_sha256_v1(), request_sha256);
        assert_eq!(state.journal.restart_prepare_nonce, None);

        let decoded: RuntimeControlResponseV1 = serde_json::from_slice(&first).unwrap();
        assert_eq!(decoded.status, "ok");
        let response_object = serde_json::from_slice::<serde_json::Value>(&first)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        assert!(!response_object.contains_key("prepared"));
        assert!(!response_object.contains_key("cut"));
        assert!(!response_object.contains_key("restart_height"));

        let (replayed, _, _) = state.process(&request).unwrap();
        assert_eq!(replayed, first);
        assert_eq!(state.restart_prepare_intent, Some(intent));
        assert!(state
            .process(&request_bytes_v1(17, "prepare_restart", "leader_loss"))
            .unwrap_err()
            .to_string()
            .contains("nonce was reused with different bytes"));
        assert!(state
            .process(&request_bytes_v1(18, "prepare_restart", ""))
            .unwrap_err()
            .to_string()
            .contains("not admissible"));
        assert!(state
            .process(&request_bytes_v1(16, "prepare_restart", ""))
            .unwrap_err()
            .to_string()
            .contains("stale outside the idempotence window"));
    }

    #[test]
    fn prepare_restart_rejects_caller_selected_cut_fields_and_fault_state() {
        let mut state = started_control_state_v1();
        let mut request = serde_json::from_slice::<serde_json::Value>(&request_bytes_v1(
            3,
            "prepare_restart",
            "",
        ))
        .unwrap();
        request
            .as_object_mut()
            .unwrap()
            .insert("finalized_height".to_owned(), serde_json::json!(99));
        assert!(state
            .process(&serde_json::to_vec(&request).unwrap())
            .is_err());
        assert!(state.restart_prepare_intent.is_none());

        state.expected_fault = Some(RuntimeFaultV1::LeaderLoss);
        assert!(state
            .process(&request_bytes_v1(4, "prepare_restart", ""))
            .unwrap_err()
            .to_string()
            .contains("not admissible"));
        assert!(state.restart_prepare_intent.is_none());
    }
}
