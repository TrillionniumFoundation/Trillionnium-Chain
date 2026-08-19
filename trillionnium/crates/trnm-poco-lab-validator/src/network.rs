//! Bounded, real-TCP authenticated mesh preflight for the G3 laboratory.
//!
//! This runtime establishes one receiver-challenged session for every edge in
//! the frozen peer graph and exchanges signed health frames in both
//! directions. It proves that the candidate process, committed run material,
//! LAN endpoints, peer identities, fresh-session handshake, and strict frame
//! sequencing interoperate. It does not drive PoCO Core, SafetyStore, the
//! signer journal, application execution, or finality and therefore is not a
//! validator run or G3 consensus evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PeerConfig, PublicReportVerifierContext},
    frame::FrameKind,
    transport::{AuthenticatedConnection, RunTransportContext},
};

const HEALTH_MAGIC: &[u8; 8] = b"TRNMG3N1";
const HEALTH_VERSION: u16 = 1;
const REPORT_DOMAIN: &[u8] = b"trnm.poco-g3.network-smoke-report.v1";
const MAX_ROUNDS: u64 = 10_000;
const MAX_INVALID_INBOUND: usize = 64;
const MAX_SIGNED_REPORT_BYTES: u64 = 8 * 1024 * 1024;

struct DeadlineIo {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineIo {
    fn new(stream: TcpStream, deadline: Instant) -> Result<Self> {
        stream.set_nodelay(true).context("set TCP_NODELAY")?;
        Ok(Self { stream, deadline })
    }

    fn refresh(&self, read: bool) -> io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "network-smoke absolute deadline elapsed",
            ));
        }
        let timeout = Some(remaining.min(Duration::from_millis(250)));
        if read {
            self.stream.set_read_timeout(timeout)
        } else {
            self.stream.set_write_timeout(timeout)
        }
    }
}

impl Read for DeadlineIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.refresh(true)?;
            match self.stream.read(buffer) {
                Ok(read) => return Ok(read),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && Instant::now() < self.deadline => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "network-smoke absolute deadline elapsed",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for DeadlineIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.refresh(false)?;
            match self.stream.write(buffer) {
                Ok(written) => return Ok(written),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && Instant::now() < self.deadline => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "network-smoke absolute deadline elapsed",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            self.refresh(false)?;
            match self.stream.flush() {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && Instant::now() < self.deadline => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "network-smoke absolute deadline elapsed",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerSessionReport {
    pub remote_validator_id: String,
    pub direction: String,
    pub remote_addr: String,
    pub session_id: String,
    pub messages_sent: u64,
    pub messages_received: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSmokeReport {
    pub schema_version: u32,
    pub run_id: String,
    pub protocol_id: String,
    pub profile: String,
    pub network_scope: String,
    pub validator_id: String,
    pub validator_set_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub host_id: String,
    pub process_id: u32,
    pub listen_addr: String,
    pub started_unix_ms: u64,
    pub ended_unix_ms: u64,
    pub rounds_per_peer: u64,
    pub peer_sessions: Vec<PeerSessionReport>,
    pub authenticated_fresh_session_runtime: bool,
    pub core_runtime: bool,
    pub safety_store_runtime: bool,
    pub signer_journal_runtime: bool,
    pub native_execution_runtime: bool,
    pub validator_run_completed: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkSmokeReport {
    pub report: NetworkSmokeReport,
    pub signature: String,
}

impl SignedNetworkSmokeReport {
    fn verify_signature(&self, validator_set: &ValidatorSet) -> Result<()> {
        let author = decode_validator_id(&self.report.validator_id)?;
        if self.report.validator_set_id != hex::encode(validator_set.id().as_bytes()) {
            bail!("network-smoke report validator-set ID differs from verifier context");
        }
        let validator = validator_set
            .validator(author)
            .ok_or_else(|| anyhow!("network-smoke report author is not in the validator set"))?;
        let signature_bytes = hex::decode(&self.signature).context("decode report signature")?;
        let signature_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| anyhow!("network-smoke report signature is not 64 bytes"))?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .context("decode report public key")?;
        let body = serde_json::to_vec(&self.report).context("encode report for verification")?;
        key.verify_strict(
            &report_root(&body),
            &Signature::from_bytes(&signature_bytes),
        )
        .context("verify network-smoke report signature")
    }

    pub fn verify_for_config(&self, config: &LoadedValidatorConfig) -> Result<()> {
        let context = ExpectedReportContext::from_config(config)?;
        self.verify_with_context(config.validator_set(), &context)
    }

    pub fn verify_for_public_context(&self, context: &PublicReportVerifierContext) -> Result<()> {
        let expected = ExpectedReportContext::from_public_context(context)?;
        self.verify_with_context(context.validator_set(), &expected)
    }

    fn verify_with_context(
        &self,
        validator_set: &ValidatorSet,
        context: &ExpectedReportContext,
    ) -> Result<()> {
        self.verify_signature(validator_set)?;
        validate_report_semantics(&self.report, context)
    }
}

/// Loads one externally produced report from a pinned regular-file descriptor.
///
/// The public verifier deliberately exposes only the full frozen-config path;
/// callers cannot accidentally treat a valid signature as sufficient G3
/// evidence while skipping the report's topology and candidate semantics.
pub fn load_signed_network_smoke_report(path: &Path) -> Result<SignedNetworkSmokeReport> {
    let mut file = OpenOptions::new()
        .read(true)
        // O_NONBLOCK prevents an attacker-controlled FIFO from hanging before
        // the post-open regular-file check. It has no effect on regular files.
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open pinned network-smoke report {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect network-smoke report {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("network-smoke report is not a regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_SIGNED_REPORT_BYTES {
        bail!("network-smoke report size crosses its bounded profile");
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| anyhow!("network-smoke report length is not representable"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .context("read pinned network-smoke report")?;
    if bytes.len() != capacity {
        bail!("network-smoke report changed length while being read");
    }
    serde_json::from_slice(&bytes).context("decode strict network-smoke report")
}

struct ExpectedReportContext {
    run_id: String,
    validator_id: String,
    validator_set_sha256: String,
    topology_sha256: String,
    coordinator_manifest_sha256: String,
    candidate_source_sha256: String,
    binary_sha256: String,
    config_sha256: String,
    host_id: String,
    listen_addr: SocketAddr,
    outgoing: BTreeMap<ValidatorId, SocketAddr>,
    incoming: BTreeMap<ValidatorId, SocketAddr>,
}

impl ExpectedReportContext {
    fn from_config(config: &LoadedValidatorConfig) -> Result<Self> {
        Ok(Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            host_id: config.host_id().to_owned(),
            listen_addr: config.listen_addr(),
            outgoing: peer_map(config.peers())?,
            incoming: peer_map(config.incoming_peers())?,
        })
    }

    fn from_public_context(config: &PublicReportVerifierContext) -> Result<Self> {
        Ok(Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            host_id: config.host_id().to_owned(),
            listen_addr: config.listen_addr(),
            outgoing: peer_map(config.peers())?,
            incoming: peer_map(config.incoming_peers())?,
        })
    }
}

fn peer_map(peers: &[PeerConfig]) -> Result<BTreeMap<ValidatorId, SocketAddr>> {
    peers
        .iter()
        .map(|peer| Ok((peer.validator_id()?, peer.socket_addr()?)))
        .collect()
}

fn validate_report_semantics(
    report: &NetworkSmokeReport,
    expected: &ExpectedReportContext,
) -> Result<()> {
    if report.schema_version != 1
        || report.protocol_id != "poco-bft-v0"
        || report.profile != "frozen-v0-lab-network-smoke"
        || report.network_scope != "single-lan"
        || report.run_id != expected.run_id
        || report.validator_id != expected.validator_id
        || report.validator_set_sha256 != expected.validator_set_sha256
        || report.topology_sha256 != expected.topology_sha256
        || report.coordinator_manifest_sha256 != expected.coordinator_manifest_sha256
        || report.candidate_source_sha256 != expected.candidate_source_sha256
        || report.binary_sha256 != expected.binary_sha256
        || report.config_sha256 != expected.config_sha256
        || report.host_id != expected.host_id
        || report.listen_addr != expected.listen_addr.to_string()
        || report.process_id == 0
        || report.rounds_per_peer == 0
        || report.rounds_per_peer > MAX_ROUNDS
        || report.ended_unix_ms < report.started_unix_ms
        || report.ended_unix_ms - report.started_unix_ms > 300_000
        || !report.authenticated_fresh_session_runtime
        || report.core_runtime
        || report.safety_store_runtime
        || report.signer_journal_runtime
        || report.native_execution_runtime
        || report.validator_run_completed
        || report.g3_evidence_complete
        || report.geo_wan_evidence
        || report.production_activation
    {
        bail!("network-smoke report crosses its exact bounded semantic profile");
    }
    let expected_count = expected
        .outgoing
        .len()
        .checked_add(expected.incoming.len())
        .ok_or_else(|| anyhow!("network-smoke expected session count overflow"))?;
    if report.peer_sessions.len() != expected_count {
        bail!("network-smoke report session inventory has the wrong cardinality");
    }
    let mut identities = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for peer in &report.peer_sessions {
        let remote = decode_validator_id(&peer.remote_validator_id)?;
        if hex::encode(remote.as_bytes()) != peer.remote_validator_id
            || !matches!(peer.direction.as_str(), "inbound" | "outbound")
            || !identities.insert((remote, peer.direction.as_str()))
            || peer.messages_sent != report.rounds_per_peer
            || peer.messages_received != report.rounds_per_peer
        {
            bail!("network-smoke report contains a non-canonical peer session");
        }
        if let Some(last) = previous {
            if last >= (peer.remote_validator_id.as_str(), peer.direction.as_str()) {
                bail!("network-smoke report peer sessions are not strictly sorted");
            }
        }
        previous = Some((&peer.remote_validator_id, peer.direction.as_str()));
        let session = decode_hex32(&peer.session_id, "network-smoke session ID")?;
        if session == [0; 32] || !sessions.insert(session) {
            bail!("network-smoke report session ID is zero or duplicated");
        }
        let remote_addr = peer
            .remote_addr
            .parse::<SocketAddr>()
            .context("decode network-smoke remote address")?;
        match peer.direction.as_str() {
            "outbound" if expected.outgoing.get(&remote) == Some(&remote_addr) => {}
            "inbound"
                if expected
                    .incoming
                    .get(&remote)
                    .is_some_and(|address| address.ip() == remote_addr.ip()) => {}
            _ => bail!("network-smoke report peer direction/address differs from topology"),
        }
    }
    Ok(())
}

pub fn run_network_smoke(
    config: &LoadedValidatorConfig,
    rounds: u64,
    timeout: Duration,
) -> Result<SignedNetworkSmokeReport> {
    if rounds == 0 || rounds > MAX_ROUNDS {
        bail!("network-smoke rounds must be in 1..={MAX_ROUNDS}");
    }
    if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(300) {
        bail!("network-smoke timeout must be between 1 and 300 seconds");
    }
    let started_unix_ms = unix_ms()?;
    let listener = TcpListener::bind(config.listen_addr())
        .with_context(|| format!("bind network-smoke listener {}", config.listen_addr()))?;
    listener
        .set_nonblocking(true)
        .context("set network-smoke listener nonblocking")?;

    let local = config.local_validator();
    validate_directed_connection_plan(local, config.peers(), config.incoming_peers())?;
    let mut incoming = BTreeMap::new();
    let mut outgoing = Vec::new();
    for peer in config.peers() {
        outgoing.push(peer);
    }
    for peer in config.incoming_peers() {
        let remote = peer.validator_id()?;
        if incoming.insert(remote, peer.socket_addr()?).is_some() {
            bail!("network-smoke incoming directed peer set contains a duplicate");
        }
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("network-smoke deadline overflow"))?;
    let (incoming_result, outgoing_result) = thread::scope(|scope| {
        let incoming_handle =
            scope.spawn(|| accept_expected(config, listener, incoming, rounds, deadline));
        let outgoing_result = connect_expected(config, outgoing, rounds, deadline);
        let incoming_result = incoming_handle
            .join()
            .map_err(|_| anyhow!("network-smoke inbound worker panicked"))?;
        Ok::<_, anyhow::Error>((incoming_result, outgoing_result))
    })?;
    let mut peer_sessions = incoming_result?;
    peer_sessions.extend(outgoing_result?);
    peer_sessions.sort_by(|left, right| {
        left.remote_validator_id
            .cmp(&right.remote_validator_id)
            .then(left.direction.cmp(&right.direction))
    });
    let expected_sessions = config
        .peers()
        .len()
        .checked_add(config.incoming_peers().len())
        .ok_or_else(|| anyhow!("network-smoke peer-session count overflow"))?;
    if peer_sessions.len() != expected_sessions {
        bail!("network-smoke did not establish the exact frozen peer set");
    }
    let unique = peer_sessions
        .iter()
        .map(|peer| (peer.remote_validator_id.as_str(), peer.direction.as_str()))
        .collect::<BTreeSet<_>>();
    if unique.len() != peer_sessions.len() {
        bail!("network-smoke established a duplicate directed peer session");
    }

    let report = NetworkSmokeReport {
        schema_version: 1,
        run_id: config.run_id().to_owned(),
        protocol_id: "poco-bft-v0".to_owned(),
        profile: "frozen-v0-lab-network-smoke".to_owned(),
        network_scope: "single-lan".to_owned(),
        validator_id: hex::encode(local.as_bytes()),
        validator_set_id: hex::encode(config.validator_set().id().as_bytes()),
        validator_set_sha256: hex::encode(config.validator_set_sha256()),
        topology_sha256: hex::encode(config.topology_sha256()),
        coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
        candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
        binary_sha256: hex::encode(config.binary_sha256()),
        config_sha256: hex::encode(config.config_sha256()),
        host_id: config.host_id().to_owned(),
        process_id: std::process::id(),
        listen_addr: config.listen_addr().to_string(),
        started_unix_ms,
        ended_unix_ms: unix_ms()?,
        rounds_per_peer: rounds,
        peer_sessions,
        authenticated_fresh_session_runtime: true,
        core_runtime: false,
        safety_store_runtime: false,
        signer_journal_runtime: false,
        native_execution_runtime: false,
        validator_run_completed: false,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
    };
    if report.ended_unix_ms < report.started_unix_ms {
        bail!("network-smoke system clock regressed");
    }
    let body = serde_json::to_vec(&report).context("encode network-smoke report")?;
    let signature = config.signing_key().sign(&report_root(&body));
    Ok(SignedNetworkSmokeReport {
        report,
        signature: hex::encode(signature.to_bytes()),
    })
}

fn validate_directed_connection_plan(
    local: ValidatorId,
    outgoing: &[PeerConfig],
    incoming: &[PeerConfig],
) -> Result<()> {
    if outgoing.is_empty() || outgoing.len() != incoming.len() {
        bail!("network-smoke directed in/out degree is empty or asymmetric");
    }
    for (label, peers) in [("outgoing", outgoing), ("incoming", incoming)] {
        let mut identities = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for peer in peers {
            let remote = peer.validator_id()?;
            let endpoint = peer.socket_addr()?;
            if remote == local || !identities.insert(remote) || !endpoints.insert(endpoint) {
                bail!("network-smoke {label} directed peer plan is non-canonical");
            }
        }
    }
    Ok(())
}

fn accept_expected(
    config: &LoadedValidatorConfig,
    listener: TcpListener,
    expected: BTreeMap<ValidatorId, SocketAddr>,
    rounds: u64,
    deadline: Instant,
) -> Result<Vec<PeerSessionReport>> {
    let mut accepted = BTreeSet::new();
    let mut reports = Vec::with_capacity(expected.len());
    let mut invalid = 0usize;
    while reports.len() < expected.len() {
        if Instant::now() >= deadline {
            bail!(
                "network-smoke timed out waiting for inbound peers ({}/{})",
                reports.len(),
                expected.len()
            );
        }
        match listener.accept() {
            Ok((stream, remote_addr)) => {
                let outcome = accept_one(config, stream, remote_addr, &expected, rounds, deadline);
                match outcome {
                    Ok(report) => {
                        let remote = decode_validator_id(&report.remote_validator_id)?;
                        if !accepted.insert(remote) {
                            bail!("network-smoke accepted a duplicate inbound peer");
                        }
                        reports.push(report);
                    }
                    Err(_) => {
                        invalid = invalid
                            .checked_add(1)
                            .ok_or_else(|| anyhow!("invalid inbound counter overflow"))?;
                        if invalid > MAX_INVALID_INBOUND {
                            bail!("network-smoke exceeded its invalid inbound bound");
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).context("accept network-smoke connection"),
        }
    }
    Ok(reports)
}

fn accept_one(
    config: &LoadedValidatorConfig,
    stream: TcpStream,
    remote_addr: SocketAddr,
    expected: &BTreeMap<ValidatorId, SocketAddr>,
    rounds: u64,
    deadline: Instant,
) -> Result<PeerSessionReport> {
    let stream = DeadlineIo::new(stream, deadline)?;
    let mut connection = AuthenticatedConnection::accept(
        stream,
        config.run_id(),
        config.local_validator(),
        config.signing_key(),
        config.validator_set(),
        transport_context(config),
    )
    .context("authenticate inbound network-smoke connection")?;
    let committed_addr = expected
        .get(&connection.remote())
        .ok_or_else(|| anyhow!("inbound peer is outside the frozen direction set"))?;
    if remote_addr.ip() != committed_addr.ip() {
        bail!("inbound peer source IP differs from the frozen peer address");
    }
    exchange_server(config, &mut connection, rounds, deadline)?;
    Ok(PeerSessionReport {
        remote_validator_id: hex::encode(connection.remote().as_bytes()),
        direction: "inbound".to_owned(),
        remote_addr: remote_addr.to_string(),
        session_id: hex::encode(connection.session_id()),
        messages_sent: rounds,
        messages_received: rounds,
    })
}

fn connect_expected(
    config: &LoadedValidatorConfig,
    peers: Vec<&PeerConfig>,
    rounds: u64,
    deadline: Instant,
) -> Result<Vec<PeerSessionReport>> {
    let mut reports = Vec::with_capacity(peers.len());
    for peer in peers {
        let remote = peer.validator_id()?;
        let remote_addr = peer.socket_addr()?;
        let stream = connect_until(remote_addr, deadline)?;
        let stream = DeadlineIo::new(stream, deadline)?;
        let mut connection = AuthenticatedConnection::connect(
            stream,
            config.run_id(),
            config.local_validator(),
            remote,
            config.signing_key(),
            config.validator_set(),
            transport_context(config),
        )
        .with_context(|| format!("authenticate outbound peer {remote_addr}"))?;
        exchange_client(config, &mut connection, rounds, deadline)?;
        reports.push(PeerSessionReport {
            remote_validator_id: hex::encode(remote.as_bytes()),
            direction: "outbound".to_owned(),
            remote_addr: remote_addr.to_string(),
            session_id: hex::encode(connection.session_id()),
            messages_sent: rounds,
            messages_received: rounds,
        });
    }
    Ok(reports)
}

fn transport_context(config: &LoadedValidatorConfig) -> RunTransportContext {
    RunTransportContext::new(
        config.topology_sha256(),
        config.candidate_source_sha256(),
        config.binary_sha256(),
        config.coordinator_manifest_sha256(),
    )
}

fn connect_until(address: SocketAddr, deadline: Instant) -> Result<TcpStream> {
    loop {
        if Instant::now() >= deadline {
            bail!("network-smoke timed out connecting to {address}");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = remaining.min(Duration::from_millis(500));
        match TcpStream::connect_timeout(&address, attempt) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::AddrNotAvailable
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                ) =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error).with_context(|| format!("connect to {address}")),
        }
    }
}

fn exchange_client(
    config: &LoadedValidatorConfig,
    connection: &mut AuthenticatedConnection<DeadlineIo>,
    rounds: u64,
    deadline: Instant,
) -> Result<()> {
    for round in 0..rounds {
        refresh_connection_deadline(connection, deadline)?;
        connection
            .send(
                FrameKind::Health,
                health_payload(config.local_validator(), connection.remote(), round),
            )
            .context("send network-smoke request")?;
        let response = connection
            .receive()
            .context("receive network-smoke response")?;
        validate_health(
            response.kind,
            &response.payload,
            connection.remote(),
            config.local_validator(),
            round,
        )?;
    }
    Ok(())
}

fn exchange_server(
    config: &LoadedValidatorConfig,
    connection: &mut AuthenticatedConnection<DeadlineIo>,
    rounds: u64,
    deadline: Instant,
) -> Result<()> {
    for round in 0..rounds {
        refresh_connection_deadline(connection, deadline)?;
        let request = connection
            .receive()
            .context("receive network-smoke request")?;
        validate_health(
            request.kind,
            &request.payload,
            connection.remote(),
            config.local_validator(),
            round,
        )?;
        connection
            .send(
                FrameKind::Health,
                health_payload(config.local_validator(), connection.remote(), round),
            )
            .context("send network-smoke response")?;
    }
    Ok(())
}

fn refresh_connection_deadline(
    connection: &mut AuthenticatedConnection<DeadlineIo>,
    deadline: Instant,
) -> Result<()> {
    remaining(deadline)?;
    connection.io_mut().deadline = deadline;
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let value = deadline.saturating_duration_since(Instant::now());
    if value.is_zero() {
        bail!("network-smoke absolute deadline elapsed");
    }
    Ok(value)
}

fn health_payload(sender: ValidatorId, receiver: ValidatorId, round: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + 2 + 8 + 32 + 32);
    payload.extend_from_slice(HEALTH_MAGIC);
    payload.extend_from_slice(&HEALTH_VERSION.to_be_bytes());
    payload.extend_from_slice(&round.to_be_bytes());
    payload.extend_from_slice(sender.as_bytes());
    payload.extend_from_slice(receiver.as_bytes());
    payload
}

fn validate_health(
    kind: FrameKind,
    payload: &[u8],
    expected_sender: ValidatorId,
    expected_receiver: ValidatorId,
    expected_round: u64,
) -> Result<()> {
    if kind != FrameKind::Health || payload.len() != 8 + 2 + 8 + 32 + 32 {
        bail!("network-smoke peer returned a non-canonical health message");
    }
    if &payload[..8] != HEALTH_MAGIC
        || u16::from_be_bytes(payload[8..10].try_into().expect("health version range"))
            != HEALTH_VERSION
        || u64::from_be_bytes(payload[10..18].try_into().expect("health round range"))
            != expected_round
        || &payload[18..50] != expected_sender.as_bytes()
        || &payload[50..82] != expected_receiver.as_bytes()
    {
        bail!("network-smoke health message differs from the expected edge/round");
    }
    Ok(())
}

fn decode_validator_id(value: &str) -> Result<ValidatorId> {
    Ok(ValidatorId::new(decode_hex32(value, "validator ID")?))
}

fn decode_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{field} is not canonical lowercase 32-byte hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    Ok(bytes
        .try_into()
        .expect("64 hex characters decode to exactly 32 bytes"))
}

fn report_root(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REPORT_DOMAIN);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn unix_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("Unix millisecond timestamp overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::{
        fs,
        net::{Shutdown, TcpListener},
        os::unix::fs::symlink,
        process::Command,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    fn fixture() -> (
        SigningKey,
        SigningKey,
        ValidatorId,
        ValidatorId,
        ValidatorSet,
    ) {
        let client_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_key = SigningKey::from_bytes(&[0x42; 32]);
        let client = ValidatorId::new([0x51; 32]);
        let server = ValidatorId::new([0x52; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x53; 32]),
            ChainId::new("trnm-poco-g3-network-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![
                Validator::new(
                    client,
                    ConsensusPublicKey::new(client_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    server,
                    ConsensusPublicKey::new(server_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        (client_key, server_key, client, server, set)
    }

    #[test]
    fn health_payload_binds_edge_and_round() {
        let (_, _, client, server, _) = fixture();
        let payload = health_payload(client, server, 7);
        validate_health(FrameKind::Health, &payload, client, server, 7).unwrap();
        assert!(validate_health(FrameKind::Health, &payload, client, server, 8).is_err());
        assert!(validate_health(FrameKind::Health, &payload, server, client, 7).is_err());
        assert!(validate_health(FrameKind::Vote, &payload, client, server, 7).is_err());
    }

    #[test]
    fn signed_report_is_strictly_bound_to_author_and_body() {
        let (client_key, _, client, _, set) = fixture();
        let report = NetworkSmokeReport {
            schema_version: 1,
            run_id: "poco-g3-7-20260813T000000Z-1234abcd".to_owned(),
            protocol_id: "poco-bft-v0".to_owned(),
            profile: "frozen-v0-lab-network-smoke".to_owned(),
            network_scope: "single-lan".to_owned(),
            validator_id: hex::encode(client.as_bytes()),
            validator_set_id: hex::encode(set.id().as_bytes()),
            validator_set_sha256: hex::encode([0x11; 32]),
            topology_sha256: hex::encode([0x15; 32]),
            coordinator_manifest_sha256: hex::encode([0x16; 32]),
            candidate_source_sha256: hex::encode([0x12; 32]),
            binary_sha256: hex::encode([0x13; 32]),
            config_sha256: hex::encode([0x14; 32]),
            host_id: "local".to_owned(),
            process_id: 1,
            listen_addr: "127.0.0.1:31000".to_owned(),
            started_unix_ms: 1,
            ended_unix_ms: 2,
            rounds_per_peer: 1,
            peer_sessions: Vec::new(),
            authenticated_fresh_session_runtime: true,
            core_runtime: false,
            safety_store_runtime: false,
            signer_journal_runtime: false,
            native_execution_runtime: false,
            validator_run_completed: false,
            g3_evidence_complete: false,
            geo_wan_evidence: false,
            production_activation: false,
        };
        let body = serde_json::to_vec(&report).unwrap();
        let mut signed = SignedNetworkSmokeReport {
            report,
            signature: hex::encode(client_key.sign(&report_root(&body)).to_bytes()),
        };
        signed.verify_signature(&set).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("report.json");
        fs::write(&report_path, serde_json::to_vec(&signed).unwrap()).unwrap();
        assert_eq!(
            load_signed_network_smoke_report(&report_path).unwrap(),
            signed
        );

        let symlink_path = directory.path().join("report-link.json");
        symlink(&report_path, &symlink_path).unwrap();
        assert!(load_signed_network_smoke_report(&symlink_path).is_err());

        let fifo_path = directory.path().join("report.fifo");
        let status = Command::new("mkfifo").arg(&fifo_path).status().unwrap();
        assert!(status.success());
        let started = Instant::now();
        assert!(load_signed_network_smoke_report(&fifo_path).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        unknown.as_object_mut().unwrap().insert(
            "uncommitted_claim".to_owned(),
            serde_json::Value::Bool(true),
        );
        let unknown_path = directory.path().join("unknown.json");
        fs::write(&unknown_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(load_signed_network_smoke_report(&unknown_path).is_err());

        signed.report.rounds_per_peer = 2;
        assert!(signed.verify_signature(&set).is_err());
    }

    #[test]
    fn re_signed_semantic_drift_is_rejected_against_frozen_context() {
        let (client_key, _, client, server, set) = fixture();
        let mut outgoing = BTreeMap::new();
        outgoing.insert(server, "127.0.0.1:31002".parse().unwrap());
        let mut incoming = BTreeMap::new();
        incoming.insert(server, "127.0.0.1:31002".parse().unwrap());
        let expected = ExpectedReportContext {
            run_id: "poco-g3-7-20260813T000000Z-1234abcd".to_owned(),
            validator_id: hex::encode(client.as_bytes()),
            validator_set_sha256: hex::encode([0x11; 32]),
            topology_sha256: hex::encode([0x15; 32]),
            coordinator_manifest_sha256: hex::encode([0x16; 32]),
            candidate_source_sha256: hex::encode([0x12; 32]),
            binary_sha256: hex::encode([0x13; 32]),
            config_sha256: hex::encode([0x14; 32]),
            host_id: "local".to_owned(),
            listen_addr: "127.0.0.1:31001".parse().unwrap(),
            outgoing,
            incoming,
        };
        let report = NetworkSmokeReport {
            schema_version: 1,
            run_id: expected.run_id.clone(),
            protocol_id: "poco-bft-v0".to_owned(),
            profile: "frozen-v0-lab-network-smoke".to_owned(),
            network_scope: "single-lan".to_owned(),
            validator_id: expected.validator_id.clone(),
            validator_set_id: hex::encode(set.id().as_bytes()),
            validator_set_sha256: expected.validator_set_sha256.clone(),
            topology_sha256: expected.topology_sha256.clone(),
            coordinator_manifest_sha256: expected.coordinator_manifest_sha256.clone(),
            candidate_source_sha256: expected.candidate_source_sha256.clone(),
            binary_sha256: expected.binary_sha256.clone(),
            config_sha256: expected.config_sha256.clone(),
            host_id: expected.host_id.clone(),
            process_id: 1,
            listen_addr: expected.listen_addr.to_string(),
            started_unix_ms: 1,
            ended_unix_ms: 2,
            rounds_per_peer: 3,
            peer_sessions: vec![
                PeerSessionReport {
                    remote_validator_id: hex::encode(server.as_bytes()),
                    direction: "inbound".to_owned(),
                    remote_addr: "127.0.0.1:45000".to_owned(),
                    session_id: hex::encode([0x21; 32]),
                    messages_sent: 3,
                    messages_received: 3,
                },
                PeerSessionReport {
                    remote_validator_id: hex::encode(server.as_bytes()),
                    direction: "outbound".to_owned(),
                    remote_addr: "127.0.0.1:31002".to_owned(),
                    session_id: hex::encode([0x22; 32]),
                    messages_sent: 3,
                    messages_received: 3,
                },
            ],
            authenticated_fresh_session_runtime: true,
            core_runtime: false,
            safety_store_runtime: false,
            signer_journal_runtime: false,
            native_execution_runtime: false,
            validator_run_completed: false,
            g3_evidence_complete: false,
            geo_wan_evidence: false,
            production_activation: false,
        };
        let sign = |report: NetworkSmokeReport| {
            let body = serde_json::to_vec(&report).unwrap();
            SignedNetworkSmokeReport {
                report,
                signature: hex::encode(client_key.sign(&report_root(&body)).to_bytes()),
            }
        };
        sign(report.clone())
            .verify_with_context(&set, &expected)
            .unwrap();

        let mut mutants = Vec::new();
        let mut mutant = report.clone();
        mutant.schema_version = 2;
        mutants.push(mutant);
        let mut mutant = report.clone();
        mutant.topology_sha256 = hex::encode([0x99; 32]);
        mutants.push(mutant);
        let mut mutant = report.clone();
        mutant.core_runtime = true;
        mutants.push(mutant);
        let mut mutant = report.clone();
        mutant.peer_sessions[0].messages_sent = 0;
        mutants.push(mutant);
        let mut mutant = report.clone();
        mutant.peer_sessions.pop();
        mutants.push(mutant);
        let mut mutant = report;
        mutant.geo_wan_evidence = true;
        mutants.push(mutant);
        for mutant in mutants {
            let signed = sign(mutant);
            signed.verify_signature(&set).unwrap();
            assert!(signed.verify_with_context(&set, &expected).is_err());
        }
    }

    #[test]
    fn slow_partial_progress_cannot_extend_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in [1u8, 2, 3, 4] {
                thread::sleep(Duration::from_millis(35));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
        });
        let stream = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_millis(80);
        let mut bounded = DeadlineIo::new(stream, deadline).unwrap();
        let mut output = [0u8; 4];
        let started = Instant::now();
        let error = bounded.read_exact(&mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(250));
        thread.join().unwrap();
    }

    #[test]
    fn frozen_directed_ring_plans_cover_31_and_100_without_reciprocal_edges() {
        for count in [31usize, 100] {
            let ids = (0..count)
                .map(|index| {
                    let mut bytes = [0u8; 32];
                    bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
                    ValidatorId::new(bytes)
                })
                .collect::<Vec<_>>();
            for local_index in 0..count {
                let outgoing = (1..=8)
                    .map(|offset| peer_fixture(ids[(local_index + offset) % count], offset))
                    .collect::<Vec<_>>();
                let incoming = (1..=8)
                    .map(|offset| {
                        peer_fixture(ids[(local_index + count - offset) % count], 100 + offset)
                    })
                    .collect::<Vec<_>>();
                validate_directed_connection_plan(ids[local_index], &outgoing, &incoming).unwrap();
                assert!(outgoing.iter().all(|peer| {
                    !incoming
                        .iter()
                        .any(|other| other.validator_id == peer.validator_id)
                }));
            }
        }
    }

    fn peer_fixture(validator_id: ValidatorId, port_offset: usize) -> PeerConfig {
        PeerConfig {
            validator_id: hex::encode(validator_id.as_bytes()),
            lan_ip: "127.0.0.1".to_owned(),
            p2p_port: 20_000 + u16::try_from(port_offset).unwrap(),
            consensus_public_key: hex::encode([0x33; 32]),
        }
    }
}
