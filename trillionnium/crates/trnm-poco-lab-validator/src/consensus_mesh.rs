//! Persistent authenticated peer sessions for the bounded G3 LAN runtime.
//!
//! The frozen topology is directed. Every configured outgoing edge owns one
//! send-only session and every incoming edge owns one receive-only session.
//! Transient TCP loss may replace that exact directed session inside the same
//! process. Every individual reconnect attempt is time bounded, while an
//! unavailable edge remains isolated and may recover later within the process;
//! other peers continue carrying consensus. A saturated unavailable edge
//! reports bounded backpressure instead of stopping unrelated sessions.
//! Authentication ambiguity, replay, malformed frames, worker loss, or
//! session-generation exhaustion still fail-stop the whole mesh. Bounded
//! ingress/outbound saturation applies backpressure without allocating an
//! unbounded spill queue. There is no cross-process replay authority here; the continuous
//! driver must still submit the independently signed consensus payload to
//! Core/collector exact-dedup admission.
//!
//! This module does not own PoCO Core, SafetyStore, application state, signer
//! state, or finality. A live mesh alone is not consensus evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use trnm_consensus_peer_lease::{
    payload_replay_run_id_hash_v1, PayloadReplayDirectionV1, PayloadReplayErrorV1,
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PayloadReplayReceiptV1, PayloadReplayStoreV1,
};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PeerConfig},
    frame::{
        AuthenticatedFrame, FrameError, FrameKind, MAX_FRAME_BODY_BYTES, MAX_FRAME_PAYLOAD_BYTES,
    },
    key_roles::ValidatorKeyRoleRegistryV1,
    p2p_admission::{
        ExternalPeerDirectionV1, ExternalPeerLeaseAuthorityV1, ExternalPeerLeaseRequestV1,
        ExternalPeerLeaseScopeV1, ExternalPeerLeaseTokenV1, PeerAdmissionContextV1,
        RejectingExternalPeerLeaseAuthorityV1,
    },
    p2p_host_attestation::{
        HostAttestationAdmissionV1, HostAttestationAuthorityV1, HostAttestationErrorV1,
        HostAttestationMaterialV1, HostAttestationSessionRegistryV1,
    },
    p2p_identity::{
        P2pIdentityErrorV1, P2pIdentitySignatureProducerV1, P2pIdentitySignatureRequestV1,
    },
    transport::{
        network_context_digest_v1, AuthenticatedConnection,
        ExternallySignedAuthenticatedConnectionV1, RunTransportContext,
    },
};

const MAX_DIRECTED_PEERS: usize = 16;
const MAX_QUEUE_CAPACITY: usize = 4_096;
const MAX_OUTBOUND_QUEUE_BYTES_PER_PEER: usize = 32 * 1024 * 1024;
const MAX_OUTBOUND_QUEUE_BYTES_GLOBAL: usize = 64 * 1024 * 1024;
const MAX_INBOUND_QUEUE_BYTES_PER_PEER: usize = 32 * 1024 * 1024;
const MAX_INBOUND_QUEUE_BYTES_GLOBAL: usize = 64 * 1024 * 1024;
const QUEUED_FRAME_OVERHEAD_BYTES: usize = 256;
const MAX_SESSION_GENERATION: u64 = 1_024;
const MESH_WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;
const MESH_BASE_PROCESS_RSS_BYTES: u64 = 64 * 1024 * 1024;
const MESH_THREADS_PER_CPU_CEILING: usize = 32;
const MESH_PROCESS_FD_RESERVE: u64 = 128;
const MESH_HOST_MEMORY_NUMERATOR: u64 = 3;
const MESH_HOST_MEMORY_DENOMINATOR: u64 = 4;
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const CONNECT_POLL: Duration = Duration::from_millis(25);
const WORKER_POLL: Duration = Duration::from_millis(50);
const MAX_HANDSHAKE_ATTEMPT: Duration = Duration::from_secs(2);
const MESH_EXTERNAL_FENCE_TTL_V1: Duration = Duration::from_secs(30);

fn fence_renew_interval(ttl: Duration) -> Duration {
    // Renew well before the authority-side expiry.  The lower bound keeps a
    // short deterministic fixture TTL from turning every frame into an RPC,
    // while the saturating arithmetic keeps malformed caller durations from
    // producing a zero-length busy loop.
    let third = ttl / 3;
    third.max(Duration::from_millis(250))
}

/// Host facts supplied by the fleet readiness probe. This type deliberately
/// does not query `/proc` or platform-specific sysctls: the signed campaign
/// owner must bind the same observed limits that were admitted by the fleet
/// inventory checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshHostCapacityV0 {
    logical_cpu_threads: usize,
    memory_bytes: u64,
    per_process_open_file_soft_limit: u64,
    system_open_file_available: Option<u64>,
}

impl MeshHostCapacityV0 {
    pub fn new(
        logical_cpu_threads: usize,
        memory_bytes: u64,
        per_process_open_file_soft_limit: u64,
    ) -> Result<Self> {
        if logical_cpu_threads == 0
            || memory_bytes < MESH_BASE_PROCESS_RSS_BYTES
            || per_process_open_file_soft_limit <= MESH_PROCESS_FD_RESERVE
        {
            bail!("mesh host capacity facts are absent or below the bounded floor");
        }
        Ok(Self {
            logical_cpu_threads,
            memory_bytes,
            per_process_open_file_soft_limit,
            system_open_file_available: None,
        })
    }

    /// Adds an independently observed system-wide available-file-handle cut.
    /// The per-process soft limit remains a distinct authority and is never
    /// compared with an aggregate host estimate.
    pub fn with_system_open_file_available(
        mut self,
        system_open_file_available: u64,
    ) -> Result<Self> {
        if system_open_file_available == 0 {
            bail!("mesh system-wide available file handles are absent");
        }
        self.system_open_file_available = Some(system_open_file_available);
        Ok(self)
    }
}

/// Deterministic upper-bound estimate for one host's mesh workers, live TCP
/// descriptors, and resident memory. It is a planning gate only: passing it
/// is not runtime performance or G3 evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshHostResourcePreflightV0 {
    validator_count: usize,
    peer_degree: usize,
    validator_processes: usize,
    per_validator_threads: usize,
    per_validator_socket_fds: u64,
    per_validator_open_file_fds: u64,
    per_validator_rss_bytes: u64,
    host_threads: usize,
    host_open_file_fds: u64,
    host_rss_bytes: u64,
}

impl MeshHostResourcePreflightV0 {
    pub const fn validator_count(&self) -> usize {
        self.validator_count
    }

    pub const fn peer_degree(&self) -> usize {
        self.peer_degree
    }

    pub const fn validator_processes(&self) -> usize {
        self.validator_processes
    }

    pub const fn per_validator_threads(&self) -> usize {
        self.per_validator_threads
    }

    pub const fn per_validator_socket_fds(&self) -> u64 {
        self.per_validator_socket_fds
    }

    pub const fn per_validator_open_file_fds(&self) -> u64 {
        self.per_validator_open_file_fds
    }

    pub const fn per_validator_rss_bytes(&self) -> u64 {
        self.per_validator_rss_bytes
    }

    pub const fn host_threads(&self) -> usize {
        self.host_threads
    }

    pub const fn host_open_file_fds(&self) -> u64 {
        self.host_open_file_fds
    }

    pub const fn host_rss_bytes(&self) -> u64 {
        self.host_rss_bytes
    }
}

/// Preflights the 7/31/100 sparse/direct topology against one host placement.
/// Socket accounting includes every owned TCP stream, its shutdown-handle
/// clone, the listener, and one bounded reconnect overlap. RSS accounting
/// includes explicit worker stacks, distinct maximum send/receive scratch
/// peaks per directed worker, and both process-global queue byte budgets.
pub fn preflight_mesh_host_resources_v0(
    validator_count: usize,
    peer_degree: usize,
    validator_processes: usize,
    queue_capacity: usize,
    host: MeshHostCapacityV0,
) -> Result<MeshHostResourcePreflightV0> {
    if !matches!(validator_count, 7 | 31 | 100)
        || peer_degree != if validator_count == 7 { 6 } else { 8 }
        || validator_processes == 0
        || validator_processes > validator_count
    {
        bail!("mesh host resource preflight differs from the frozen G3 topology");
    }
    validate_limits(
        Duration::from_secs(1),
        Duration::from_millis(100),
        queue_capacity,
    )?;
    let per_validator_threads = peer_degree
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| anyhow!("mesh thread estimate overflow"))?;
    let per_validator_socket_fds = u64::try_from(peer_degree)
        .ok()
        .and_then(|degree| degree.checked_mul(4))
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| anyhow!("mesh socket estimate overflow"))?;
    let per_validator_open_file_fds = per_validator_socket_fds
        .checked_add(MESH_PROCESS_FD_RESERVE)
        .ok_or_else(|| anyhow!("mesh per-process open-file estimate overflow"))?;
    let global_outbound_queue_bytes = u64::try_from(outbound_global_queue_byte_budget_v0(
        queue_capacity,
        peer_degree,
    )?)
    .map_err(|_| anyhow!("mesh global outbound queue budget does not fit u64"))?;
    let global_inbound_queue_bytes = u64::try_from(inbound_global_queue_byte_budget_v0(
        queue_capacity,
        peer_degree,
    )?)
    .map_err(|_| anyhow!("mesh global inbound queue budget does not fit u64"))?;
    let worker_stack_bytes = u64::try_from(MESH_WORKER_STACK_BYTES)
        .map_err(|_| anyhow!("mesh worker stack bound does not fit u64"))?;
    let stack_bytes = u64::try_from(per_validator_threads)
        .ok()
        .and_then(|threads| threads.checked_mul(worker_stack_bytes))
        .ok_or_else(|| anyhow!("mesh stack estimate overflow"))?;
    let directed_workers = u64::try_from(peer_degree)
        .map_err(|_| anyhow!("mesh directed worker count does not fit u64"))?;
    let maximum_frame_body_bytes = u64::try_from(MAX_FRAME_BODY_BYTES)
        .map_err(|_| anyhow!("mesh framed-body bound does not fit u64"))?;
    let maximum_frame_payload_bytes = u64::try_from(MAX_FRAME_PAYLOAD_BYTES)
        .map_err(|_| anyhow!("mesh frame-payload bound does not fit u64"))?;
    // Sending temporarily owns the queue-backed Arc payload, a Vec copy passed
    // into AuthenticatedConnection, and the encoded framed body. The queue
    // budget accounts for the Arc; this scratch term accounts for the latter
    // two allocations without hiding them inside receive-side accounting.
    let outgoing_worker_scratch_bytes = maximum_frame_body_bytes
        .checked_add(maximum_frame_payload_bytes)
        .ok_or_else(|| anyhow!("mesh outgoing frame scratch estimate overflow"))?;
    let outgoing_frame_scratch_bytes = directed_workers
        .checked_mul(outgoing_worker_scratch_bytes)
        .ok_or_else(|| anyhow!("mesh outgoing workers scratch estimate overflow"))?;
    // read_framed retains the complete framed body while decode allocates the
    // authenticated payload. Both coexist at the decode peak. Afterwards one
    // decoded frame per inbound worker may remain held while byte admission is
    // backpressured, so this is also the correct bounded held-frame allowance.
    let incoming_worker_scratch_bytes = maximum_frame_body_bytes
        .checked_add(maximum_frame_payload_bytes)
        .ok_or_else(|| anyhow!("mesh incoming frame scratch estimate overflow"))?;
    let incoming_frame_scratch_bytes = directed_workers
        .checked_mul(incoming_worker_scratch_bytes)
        .ok_or_else(|| anyhow!("mesh incoming workers scratch estimate overflow"))?;
    let per_validator_rss_bytes = MESH_BASE_PROCESS_RSS_BYTES
        .checked_add(global_outbound_queue_bytes)
        .and_then(|value| value.checked_add(global_inbound_queue_bytes))
        .and_then(|value| value.checked_add(stack_bytes))
        .and_then(|value| value.checked_add(outgoing_frame_scratch_bytes))
        .and_then(|value| value.checked_add(incoming_frame_scratch_bytes))
        .ok_or_else(|| anyhow!("mesh RSS estimate overflow"))?;
    let host_threads = per_validator_threads
        .checked_mul(validator_processes)
        .ok_or_else(|| anyhow!("mesh host thread estimate overflow"))?;
    let host_open_file_fds = per_validator_open_file_fds
        .checked_mul(
            u64::try_from(validator_processes)
                .map_err(|_| anyhow!("validator process count does not fit u64"))?,
        )
        .ok_or_else(|| anyhow!("mesh host open-file estimate overflow"))?;
    let host_rss_bytes = per_validator_rss_bytes
        .checked_mul(
            u64::try_from(validator_processes)
                .map_err(|_| anyhow!("validator process count does not fit u64"))?,
        )
        .ok_or_else(|| anyhow!("mesh host RSS estimate overflow"))?;
    let maximum_host_threads = host
        .logical_cpu_threads
        .checked_mul(MESH_THREADS_PER_CPU_CEILING)
        .ok_or_else(|| anyhow!("mesh host thread ceiling overflow"))?;
    let usable_memory = host
        .memory_bytes
        .checked_mul(MESH_HOST_MEMORY_NUMERATOR)
        .map(|value| value / MESH_HOST_MEMORY_DENOMINATOR)
        .ok_or_else(|| anyhow!("mesh usable-memory estimate overflow"))?;
    if host_threads > maximum_host_threads
        || per_validator_open_file_fds > host.per_process_open_file_soft_limit
        || host
            .system_open_file_available
            .is_some_and(|available| host_open_file_fds > available)
        || host_rss_bytes > usable_memory
    {
        bail!(
            "mesh host placement exceeds per-process open-file, system file-handle, thread, or RSS preflight capacity"
        );
    }
    Ok(MeshHostResourcePreflightV0 {
        validator_count,
        peer_degree,
        validator_processes,
        per_validator_threads,
        per_validator_socket_fds,
        per_validator_open_file_fds,
        per_validator_rss_bytes,
        host_threads,
        host_open_file_fds,
        host_rss_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerDirectionV0 {
    Inbound,
    Outbound,
}

impl PeerDirectionV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSessionFactsV0 {
    remote: ValidatorId,
    direction: PeerDirectionV0,
    session_id: [u8; 32],
    generation: u64,
}

impl PeerSessionFactsV0 {
    pub const fn remote(&self) -> ValidatorId {
        self.remote
    }

    pub const fn direction(&self) -> PeerDirectionV0 {
        self.direction
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Builds session facts for a unit test that exercises a consumer of the
    /// authenticated mesh owner.  Production code receives these facts only
    /// from the mesh lifecycle events, never from caller-supplied scalars.
    #[cfg(test)]
    pub(crate) const fn for_test(
        remote: ValidatorId,
        direction: PeerDirectionV0,
        session_id: [u8; 32],
        generation: u64,
    ) -> Self {
        Self {
            remote,
            direction,
            session_id,
            generation,
        }
    }
}

#[derive(Debug)]
pub struct MeshInboundFrameV0 {
    remote: ValidatorId,
    direction: PeerDirectionV0,
    session_id: [u8; 32],
    session_generation: u64,
    frame: AuthenticatedFrame,
    _reservation: InboundQueueReservationV0,
}

impl MeshInboundFrameV0 {
    pub const fn remote(&self) -> ValidatorId {
        self.remote
    }

    pub const fn direction(&self) -> PeerDirectionV0 {
        self.direction
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub const fn frame(&self) -> &AuthenticatedFrame {
        &self.frame
    }

    pub fn into_frame(self) -> AuthenticatedFrame {
        self.frame
    }

    /// Durably admits this authenticated payload before a caller exposes it
    /// to Core/collector code. The mesh worker has already checked the live
    /// external peer lease for this generation; this second owner records the
    /// exact `(peer,direction,session,generation,sequence,kind,fingerprint)`
    /// in a cross-process WAL and rejects a stale session or sequence. The
    /// caller must consume this queue owner only after this method succeeds.
    pub fn admit_payload_replay_v1(
        &self,
        replay: &mut PayloadReplayStoreV1,
        run_id: &str,
    ) -> Result<PayloadReplayReceiptV1, PayloadReplayErrorV1> {
        if self.remote != self.frame.sender
            || self.session_id == [0; 32]
            || self.session_id != self.frame.session
        {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        if payload_replay_run_id_hash_v1(run_id) != replay.namespace().run_id_hash() {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        let remote_id: [u8; 32] = self
            .remote
            .as_bytes()
            .try_into()
            .map_err(|_| PayloadReplayErrorV1::ContextMismatch)?;
        let direction = match self.direction {
            PeerDirectionV0::Inbound => PayloadReplayDirectionV1::Inbound,
            PeerDirectionV0::Outbound => PayloadReplayDirectionV1::Outbound,
        };
        let namespace = replay.namespace();
        let scope = namespace.scope_for(remote_id, direction)?;
        let frame = PayloadReplayFrameV1::new(
            scope,
            namespace.run_id_hash(),
            namespace.network_context_hash(),
            self.session_id,
            self.session_generation,
            self.frame.sequence,
            self.frame.kind as u8,
            self.frame.payload.len(),
            self.frame.fingerprint(run_id),
        )?;
        replay.admit(&frame)
    }

    /// Mints a queue owner for tests in sibling modules.  The real mesh is
    /// the only production constructor; this helper remains behind the test
    /// configuration so cloneable frame data cannot forge an owner in a
    /// normal build.
    #[cfg(test)]
    pub(crate) fn for_test(facts: PeerSessionFactsV0, frame: AuthenticatedFrame) -> Self {
        let reserved_bytes = frame
            .payload
            .len()
            .saturating_add(QUEUED_FRAME_OVERHEAD_BYTES);
        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(MAX_INBOUND_QUEUE_BYTES_PER_PEER));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(MAX_INBOUND_QUEUE_BYTES_GLOBAL));
        let reservation =
            InboundQueueReservationV0::try_new(&peer_budget, &global_budget, reserved_bytes)
                .expect("test inbound frame fits the bounded queue");
        Self {
            remote: facts.remote,
            direction: facts.direction,
            session_id: facts.session_id,
            session_generation: facts.generation,
            frame,
            _reservation: reservation,
        }
    }
}

#[derive(Debug)]
pub enum MeshIngressEventV0 {
    Frame(MeshInboundFrameV0),
    SessionUnavailable(PeerSessionFactsV0),
    SessionReestablished(PeerSessionFactsV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSendDispositionV0 {
    Queued,
    Backpressured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshBroadcastOutcomeV0 {
    queued_peers: usize,
    backpressured_peers: Vec<ValidatorId>,
}

impl MeshBroadcastOutcomeV0 {
    pub const fn queued_peers(&self) -> usize {
        self.queued_peers
    }

    pub fn backpressured_peers(&self) -> &[ValidatorId] {
        &self.backpressured_peers
    }

    pub fn fully_queued(&self) -> bool {
        self.backpressured_peers.is_empty()
    }
}

#[derive(Debug, Clone)]
struct MeshTerminalFailureV0 {
    remote: ValidatorId,
    direction: PeerDirectionV0,
    reason: String,
}

#[derive(Debug)]
struct MeshFencePeerFailureV1 {
    remote: ValidatorId,
    direction: PeerDirectionV0,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshFenceRenewalOutcomeV1 {
    Missing,
    NotDue,
    Renewed,
}

impl MeshTerminalFailureV0 {
    fn render(&self) -> String {
        format!(
            "authenticated {} session {} failed: {}",
            self.direction.as_str(),
            hex::encode(self.remote.as_bytes()),
            self.reason
        )
    }
}

/// A producer shared by the bounded mesh workers.  The external signer API
/// is stateful (nonce/replay state belongs to the signer), while each
/// directed session is owned by a separate worker.  Serializing only the
/// producer call keeps that authority single-owner without copying a secret
/// into any worker or falling back to a local key.
#[derive(Clone)]
struct SharedP2pIdentityProducerV1 {
    inner: Arc<Mutex<Box<dyn P2pIdentitySignatureProducerV1>>>,
}

impl SharedP2pIdentityProducerV1 {
    fn new(producer: Box<dyn P2pIdentitySignatureProducerV1>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(producer)),
        }
    }
}

impl P2pIdentitySignatureProducerV1 for SharedP2pIdentityProducerV1 {
    fn public_key_v1(&self) -> [u8; 32] {
        self.inner
            .lock()
            .map(|producer| producer.public_key_v1())
            .unwrap_or([0u8; 32])
    }

    fn sign_v1(
        &mut self,
        request: P2pIdentitySignatureRequestV1,
    ) -> Result<[u8; 64], P2pIdentityErrorV1> {
        self.inner
            .lock()
            .map_err(|_| P2pIdentityErrorV1::Unavailable)?
            .sign_v1(request)
    }
}

#[derive(Clone)]
enum MeshIdentitySignerV1 {
    /// Secret-bearing fixture mode only.  Deployed external composition must
    /// use [`Self::External`].
    Local(SigningKey),
    External(SharedP2pIdentityProducerV1),
}

enum MeshAuthenticatedConnectionV1<T> {
    Local(AuthenticatedConnection<T>),
    External(ExternallySignedAuthenticatedConnectionV1<T>),
}

impl<T: Read + Write> MeshAuthenticatedConnectionV1<T> {
    fn remote(&self) -> ValidatorId {
        match self {
            Self::Local(connection) => connection.remote(),
            Self::External(connection) => connection.remote(),
        }
    }

    fn session_id(&self) -> [u8; 32] {
        match self {
            Self::Local(connection) => connection.session_id(),
            Self::External(connection) => connection.session_id(),
        }
    }

    fn io_mut(&mut self) -> &mut T {
        match self {
            Self::Local(connection) => connection.io_mut(),
            Self::External(connection) => connection.io_mut(),
        }
    }

    fn mark_host_attestation_admitted(
        &mut self,
        admission: Option<HostAttestationAdmissionV1>,
        direction: ExternalPeerDirectionV1,
        generation: u64,
    ) -> Result<()> {
        if let Self::External(connection) = self {
            let admission = admission
                .ok_or_else(|| anyhow!("external connection has no host-attestation receipt"))?;
            connection
                .mark_host_attestation_admitted(admission, direction, generation)
                .map_err(|error| {
                    anyhow!("host-attestation receipt does not match connection: {error}")
                })?;
        }
        Ok(())
    }

    fn send(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<(), FrameError> {
        match self {
            Self::Local(connection) => connection.send(kind, payload),
            Self::External(connection) => connection.send(kind, payload),
        }
    }

    fn receive(&mut self) -> Result<AuthenticatedFrame, FrameError> {
        match self {
            Self::Local(connection) => connection.receive(),
            Self::External(connection) => connection.receive(),
        }
    }
}

#[derive(Clone)]
struct MeshIdentityV0 {
    run_id: String,
    local: ValidatorId,
    p2p_identity_signer: MeshIdentitySignerV1,
    validator_set: ValidatorSet,
    key_roles: ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
    host_attestation: Option<MeshHostAttestationConfigV1>,
}

/// Explicit host-attestation composition for one deployed mesh.  Keeping the
/// authority and opaque evidence together prevents a caller from supplying
/// evidence for one host while commissioning another identity/context.
#[derive(Clone)]
struct MeshHostAttestationConfigV1 {
    authority: Arc<dyn HostAttestationAuthorityV1>,
    material: HostAttestationMaterialV1,
}

/// Secret-bearing fixture description used by the cross-process fencing
/// integration test.  This is deliberately a narrow transport-only seam: it
/// does not construct Core, SafetyStore, a signer, or a validator loop.  The
/// normal deployed path must continue to use [`LoadedValidatorConfig`] and
/// the default production flags remain false.
#[doc(hidden)]
#[derive(Clone)]
pub struct MeshFixtureConfigV1 {
    run_id: String,
    local: ValidatorId,
    p2p_identity_signing_key: SigningKey,
    validator_set: ValidatorSet,
    key_roles: ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
    listen_addr: SocketAddr,
    outgoing: BTreeMap<ValidatorId, SocketAddr>,
    incoming: BTreeMap<ValidatorId, SocketAddr>,
}

impl MeshFixtureConfigV1 {
    /// Builds a two-sided fixture plan.  The caller supplies already
    /// authenticated validator identities and explicit directed endpoints;
    /// no files, consensus keys, or production configuration are loaded.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        local: ValidatorId,
        p2p_identity_signing_key: SigningKey,
        validator_set: ValidatorSet,
        key_roles: ValidatorKeyRoleRegistryV1,
        transport_context: RunTransportContext,
        listen_addr: SocketAddr,
        outgoing: BTreeMap<ValidatorId, SocketAddr>,
        incoming: BTreeMap<ValidatorId, SocketAddr>,
    ) -> Result<Self> {
        let run_id = run_id.into();
        if run_id.is_empty() {
            bail!("mesh fixture run id is empty");
        }
        validate_directed_plan_maps(local, &outgoing, &incoming)?;
        if validator_set.validator(local).is_none() {
            bail!("mesh fixture local validator is absent from validator set");
        }
        if key_roles.binding(local).is_none() {
            bail!("mesh fixture local key-role binding is absent");
        }
        Ok(Self {
            run_id,
            local,
            p2p_identity_signing_key,
            validator_set,
            key_roles,
            transport_context,
            listen_addr,
            outgoing,
            incoming,
        })
    }

    #[doc(hidden)]
    pub fn admission_context_v1(&self) -> PeerAdmissionContextV1 {
        PeerAdmissionContextV1::from_validator_set(&self.validator_set)
    }

    #[doc(hidden)]
    pub fn run_id_v1(&self) -> &str {
        &self.run_id
    }

    /// Returns the immutable validator-set context used by this transport
    /// fixture.  This exposes no key material and exists only so a test can
    /// run the same strict consensus-wire decoder after a frame crosses the
    /// authenticated socket boundary.
    #[doc(hidden)]
    pub fn validator_set_v1(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Returns the exact namespace required by the candidate durable payload
    /// replay owner. The run-id and network-context digests are identical to
    /// those authenticated by the mesh handshake; callers cannot accidentally
    /// bind a replay journal to a different validator set or deployment.
    #[doc(hidden)]
    pub fn payload_replay_namespace_v1(&self) -> Result<PayloadReplayNamespaceV1> {
        let local_id: [u8; 32] = self
            .local
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow!("mesh local validator ID is not 32 bytes"))?;
        PayloadReplayNamespaceV1::new(
            local_id,
            self.validator_set.epoch().get(),
            self.validator_set.id().into_bytes(),
            payload_replay_run_id_hash_v1(&self.run_id),
            network_context_digest_v1(&self.validator_set, &self.key_roles, self.transport_context),
        )
        .map_err(|error| anyhow!("payload replay namespace: {error}"))
    }
}

impl MeshIdentityV0 {
    fn from_fixture(config: &MeshFixtureConfigV1) -> Self {
        Self {
            run_id: config.run_id.clone(),
            local: config.local,
            p2p_identity_signer: MeshIdentitySignerV1::Local(
                config.p2p_identity_signing_key.clone(),
            ),
            validator_set: config.validator_set.clone(),
            key_roles: config.key_roles.clone(),
            transport_context: config.transport_context,
            host_attestation: None,
        }
    }
}

struct OutboundMessageV0 {
    kind: FrameKind,
    payload: Arc<[u8]>,
    _reservation: OutboundQueueReservationV0,
}

struct OutboundQueueReservationV0 {
    peer_budget: Arc<MeshQueueByteBudgetV0>,
    global_budget: Arc<MeshQueueByteBudgetV0>,
    reserved_bytes: usize,
}

impl OutboundQueueReservationV0 {
    fn try_new(
        peer_budget: &Arc<MeshQueueByteBudgetV0>,
        global_budget: &Arc<MeshQueueByteBudgetV0>,
        reserved_bytes: usize,
    ) -> Option<Self> {
        if !peer_budget.try_reserve(reserved_bytes) {
            return None;
        }
        if !global_budget.try_reserve(reserved_bytes) {
            peer_budget.release(reserved_bytes);
            return None;
        }
        Some(Self {
            peer_budget: Arc::clone(peer_budget),
            global_budget: Arc::clone(global_budget),
            reserved_bytes,
        })
    }
}

impl Drop for OutboundQueueReservationV0 {
    fn drop(&mut self) {
        self.peer_budget.release(self.reserved_bytes);
        self.global_budget.release(self.reserved_bytes);
    }
}

#[derive(Debug)]
struct InboundQueueReservationV0 {
    peer_budget: Arc<MeshQueueByteBudgetV0>,
    global_budget: Arc<MeshQueueByteBudgetV0>,
    reserved_bytes: usize,
}

impl InboundQueueReservationV0 {
    fn try_new(
        peer_budget: &Arc<MeshQueueByteBudgetV0>,
        global_budget: &Arc<MeshQueueByteBudgetV0>,
        reserved_bytes: usize,
    ) -> Option<Self> {
        if !peer_budget.try_reserve(reserved_bytes) {
            return None;
        }
        if !global_budget.try_reserve(reserved_bytes) {
            peer_budget.release(reserved_bytes);
            return None;
        }
        Some(Self {
            peer_budget: Arc::clone(peer_budget),
            global_budget: Arc::clone(global_budget),
            reserved_bytes,
        })
    }
}

impl Drop for InboundQueueReservationV0 {
    fn drop(&mut self) {
        self.peer_budget.release(self.reserved_bytes);
        self.global_budget.release(self.reserved_bytes);
    }
}

#[derive(Debug)]
struct MeshQueueByteBudgetV0 {
    used_bytes: AtomicUsize,
    maximum_bytes: usize,
}

impl MeshQueueByteBudgetV0 {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            used_bytes: AtomicUsize::new(0),
            maximum_bytes,
        }
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        self.used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.maximum_bytes)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        let released = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(bytes)
            });
        debug_assert!(released.is_ok());
    }
}

struct OutboundQueueV0 {
    sender: SyncSender<OutboundMessageV0>,
    peer_budget: Arc<MeshQueueByteBudgetV0>,
    global_budget: Arc<MeshQueueByteBudgetV0>,
}

enum SetupEventV0 {
    Ready(PeerSessionFactsV0),
    Failed(String),
}

#[derive(Debug, Clone, Copy)]
enum InboundLifecycleV0 {
    TransientLoss(PeerSessionFactsV0),
}

struct InboundWorkerV0 {
    facts: PeerSessionFactsV0,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

enum ConnectAttemptFailureV0 {
    Stopped,
    WindowElapsed,
    Terminal(String),
}

#[derive(Debug)]
enum IncomingAuthFailureV0 {
    Transient,
    Terminal(String),
}

impl ConnectAttemptFailureV0 {
    fn render(&self) -> String {
        match self {
            Self::Stopped => "mesh stopped during connection establishment".to_owned(),
            Self::WindowElapsed => "bounded connection-attempt window elapsed".to_owned(),
            Self::Terminal(reason) => reason.clone(),
        }
    }
}

type ActiveControlsV0 = Arc<Mutex<BTreeMap<(PeerDirectionV0, ValidatorId), TcpStream>>>;

type ActiveFenceKeyV0 = (PeerDirectionV0, ValidatorId);

#[derive(Clone, Copy)]
struct ActiveFenceEntryV1 {
    token: ExternalPeerLeaseTokenV1,
    host_admission: Option<HostAttestationAdmissionV1>,
    next_renew_at: Instant,
    /// Set only after the external peer authority confirms release.  A
    /// session with this bit set is kept until the independent host
    /// attestation receipt is released as well; otherwise a failed host
    /// cleanup would strand that receipt while allowing a new generation to
    /// race into the same key.
    external_release_confirmed: bool,
    /// Set only after the exact host receipt has also been released.  This
    /// lets a later retry finish host cleanup without guessing whether the
    /// peer lease was already acknowledged by its authority.
    host_release_confirmed: bool,
}

/// The mesh-owned view of externally fenced sessions.  Workers must acquire a
/// token before they publish a generation, and every frame path revalidates
/// the exact token.  The authority itself remains injectable and is expected
/// to be durable/non-rollbackable outside this process.
#[derive(Clone)]
struct MeshFenceRegistryV1 {
    authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    local: ValidatorId,
    context: PeerAdmissionContextV1,
    ttl: Duration,
    host_attestation: Option<HostAttestationSessionRegistryV1>,
    tokens: Arc<Mutex<BTreeMap<ActiveFenceKeyV0, ActiveFenceEntryV1>>>,
    /// Serialize the external admit/release/renew transaction across clones
    /// so a local reconnect cannot create a late collision after an authority
    /// token has been minted but before it is installed in `tokens`.
    admission_lock: Arc<Mutex<()>>,
    /// External tokens whose compensating release failed before they could be
    /// installed as the active edge.  They remain exact, occupied state until
    /// a later retry confirms release.
    pending_releases: Arc<Mutex<BTreeMap<ActiveFenceKeyV0, Vec<ExternalPeerLeaseTokenV1>>>>,
    /// Host receipts whose exact compensating release failed before a peer
    /// lease could be installed, or while an active edge was unwinding.
    pending_host_releases: Arc<Mutex<BTreeMap<ActiveFenceKeyV0, Vec<HostAttestationAdmissionV1>>>>,
}

impl MeshFenceRegistryV1 {
    #[cfg(test)]
    fn new(
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
        local: ValidatorId,
        context: PeerAdmissionContextV1,
        ttl: Duration,
    ) -> Result<Self> {
        Self::new_with_host_attestation(authority, local, context, ttl, None)
    }

    fn new_with_host_attestation(
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
        local: ValidatorId,
        context: PeerAdmissionContextV1,
        ttl: Duration,
        host_attestation: Option<HostAttestationSessionRegistryV1>,
    ) -> Result<Self> {
        let ttl_millis = ttl.as_millis();
        if !(1_000..=120_000).contains(&ttl_millis) {
            bail!("invalid mesh external-fence TTL");
        }
        Ok(Self {
            authority,
            local,
            context,
            ttl,
            host_attestation,
            tokens: Arc::new(Mutex::new(BTreeMap::new())),
            admission_lock: Arc::new(Mutex::new(())),
            pending_releases: Arc::new(Mutex::new(BTreeMap::new())),
            pending_host_releases: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    fn preflight_host_attestation(&self) -> Result<()> {
        // The registry constructor already performs the authority preflight;
        // keeping this method explicit makes the commissioning gate visible
        // at the mesh owner boundary and gives future authorities a second
        // fresh check immediately before listener/worker creation.
        if let Some(host_attestation) = &self.host_attestation {
            host_attestation
                .preflight()
                .map_err(|error| anyhow!("host attestation preflight failed: {error}"))?;
        }
        Ok(())
    }

    fn host_attestation_admission(
        &self,
        direction: PeerDirectionV0,
        remote: ValidatorId,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<Option<HostAttestationAdmissionV1>> {
        let Some(host_attestation) = &self.host_attestation else {
            return Ok(None);
        };
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        let key = (direction, remote);
        let entry = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .get(&key)
            .copied()
            .ok_or_else(|| anyhow!("mesh host-attestation lookup has no peer lease"))?;
        if self
            .pending_releases
            .lock()
            .map_err(|_| anyhow!("mesh fence pending-release map poisoned"))?
            .contains_key(&key)
        {
            bail!("mesh host-attestation lookup has an unresolved peer release")
        }
        if self
            .pending_host_releases
            .lock()
            .map_err(|_| anyhow!("mesh pending host-release map poisoned"))?
            .contains_key(&key)
        {
            bail!("mesh host-attestation lookup has an unresolved host release")
        }
        if entry.external_release_confirmed {
            bail!("mesh host-attestation lookup is pending peer release")
        }
        if entry.host_release_confirmed {
            bail!("mesh host-attestation lookup has already released its receipt")
        }
        let expected_direction = match direction {
            PeerDirectionV0::Inbound => ExternalPeerDirectionV1::Inbound,
            PeerDirectionV0::Outbound => ExternalPeerDirectionV1::Outbound,
        };
        let scope = entry.token.scope();
        if scope.local() != self.local
            || scope.remote() != remote
            || scope.direction() != expected_direction
            || scope.session_id() != session_id
            || scope.generation() != generation
            || entry.host_admission.is_none()
        {
            bail!("mesh host-attestation receipt does not match the peer lease")
        }
        let expected_admission = entry
            .host_admission
            .ok_or_else(|| anyhow!("mesh host-attestation receipt is missing"))?;
        let current_admission = host_attestation
            .admission(expected_direction, remote, session_id, generation)
            .map_err(|error| anyhow!("host attestation receipt lookup failed: {error}"))?;
        if current_admission != expected_admission {
            bail!("mesh host-attestation receipt changed after peer admission")
        }
        Ok(Some(current_admission))
    }

    fn release_host_admission_exact(
        &self,
        key: ActiveFenceKeyV0,
        admission: Option<HostAttestationAdmissionV1>,
    ) -> Result<()> {
        match (&self.host_attestation, admission) {
            (Some(_), None) => bail!("mesh fence entry lost its host-attestation receipt"),
            (Some(host_attestation), Some(admission)) => {
                if let Err(error) = host_attestation.release_exact_v1(admission) {
                    let mut pending = self
                        .pending_host_releases
                        .lock()
                        .map_err(|_| anyhow!("mesh pending host-release map poisoned"))?;
                    let entries = pending.entry(key).or_default();
                    if !entries.contains(&admission) {
                        entries.push(admission);
                    }
                    return Err(anyhow!("host attestation release cleanup failed: {error}"));
                }
            }
            (None, None) => {}
            (None, Some(_)) => bail!("mesh fence has a host receipt without an authority"),
        }
        Ok(())
    }

    fn retry_pending_host_releases_v1(&self, key: ActiveFenceKeyV0) -> Result<()> {
        loop {
            let admission = self
                .pending_host_releases
                .lock()
                .map_err(|_| anyhow!("mesh pending host-release map poisoned"))?
                .get(&key)
                .and_then(|entries| entries.first().copied());
            let Some(admission) = admission else {
                return Ok(());
            };
            let host_attestation = self
                .host_attestation
                .as_ref()
                .ok_or_else(|| anyhow!("mesh has a pending host receipt without an authority"))?;
            host_attestation
                .release_exact_v1(admission)
                .map_err(|error| {
                    anyhow!("host attestation release pending retry failed: {error}")
                })?;
            if let Ok(mut tokens) = self.tokens.lock() {
                if let Some(entry) = tokens.get_mut(&key) {
                    if entry.host_admission == Some(admission) {
                        entry.host_release_confirmed = true;
                    }
                }
            } else {
                return Err(anyhow!("mesh fence token map poisoned after host release"));
            }
            let mut pending = self
                .pending_host_releases
                .lock()
                .map_err(|_| anyhow!("mesh pending host-release map poisoned"))?;
            let Some(entries) = pending.get_mut(&key) else {
                continue;
            };
            if let Some(index) = entries.iter().position(|candidate| *candidate == admission) {
                entries.remove(index);
            }
            if entries.is_empty() {
                pending.remove(&key);
            }
        }
    }

    fn retry_pending_releases_v1(&self, key: ActiveFenceKeyV0) -> Result<()> {
        loop {
            let token = self
                .pending_releases
                .lock()
                .map_err(|_| anyhow!("mesh fence pending-release map poisoned"))?
                .get(&key)
                .and_then(|tokens| tokens.first().copied());
            let Some(token) = token else {
                return Ok(());
            };
            // An authority error is sticky.  Even if the remote side may
            // have applied the release, uncertainty must not permit a new
            // generation to overlap this exact token.
            self.authority
                .release(token)
                .map_err(|error| anyhow!("external fence pending release failed: {error}"))?;
            let mut pending = self
                .pending_releases
                .lock()
                .map_err(|_| anyhow!("mesh fence pending-release map poisoned"))?;
            let Some(tokens) = pending.get_mut(&key) else {
                continue;
            };
            if let Some(index) = tokens.iter().position(|candidate| *candidate == token) {
                tokens.remove(index);
            }
            if tokens.is_empty() {
                pending.remove(&key);
            }
        }
    }

    fn release_or_retain_v1(
        &self,
        key: ActiveFenceKeyV0,
        token: ExternalPeerLeaseTokenV1,
    ) -> Result<()> {
        match self.authority.release(token) {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut pending = self
                    .pending_releases
                    .lock()
                    .map_err(|_| anyhow!("mesh fence pending-release map poisoned"))?;
                let entries = pending.entry(key).or_default();
                if !entries.contains(&token) {
                    entries.push(token);
                }
                Err(anyhow!(
                    "external fence release failed during cleanup: {error}"
                ))
            }
        }
    }

    fn acquire(
        &self,
        direction: PeerDirectionV0,
        remote: ValidatorId,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<ExternalPeerLeaseTokenV1> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        let host_direction = match direction {
            PeerDirectionV0::Inbound => ExternalPeerDirectionV1::Inbound,
            PeerDirectionV0::Outbound => ExternalPeerDirectionV1::Outbound,
        };
        self.retry_pending_releases_v1(key)?;
        self.retry_pending_host_releases_v1(key)?;
        // A pending host-attestation cleanup is still an occupied edge.  Do
        // not call host.acquire for a new generation while the prior receipt
        // is unresolved; doing so could overwrite the authority's active
        // receipt before the old one is released.
        if self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .contains_key(&key)
        {
            bail!("external fence key already has a live or pending token")
        }
        let scope = ExternalPeerLeaseScopeV1::new(
            self.local,
            remote,
            match direction {
                PeerDirectionV0::Inbound => ExternalPeerDirectionV1::Inbound,
                PeerDirectionV0::Outbound => ExternalPeerDirectionV1::Outbound,
            },
            self.context,
            session_id,
            generation,
        )
        .map_err(|error| anyhow!("external fence scope rejected: {error}"))?;
        let request = ExternalPeerLeaseRequestV1::new(scope, self.ttl)
            .map_err(|error| anyhow!("external fence request rejected: {error}"))?;
        // Validate the peer scope and bounded TTL before asking the host
        // authority to mint a receipt. Otherwise an invalid internal
        // generation could leave an externally live host token with no
        // corresponding mesh entry to release.
        let host_admission = self
            .host_attestation
            .as_ref()
            .map(|host_attestation| {
                host_attestation
                    .acquire(host_direction, remote, session_id, generation)
                    .map_err(|error| anyhow!("host attestation rejected session: {error}"))
            })
            .transpose()?;
        let token = match self.authority.acquire(request) {
            Ok(token) => token,
            Err(error) => {
                let cleanup = self.release_host_admission_exact(key, host_admission);
                return match cleanup {
                    Ok(()) => Err(anyhow!("external fence acquire failed: {error}")),
                    Err(cleanup_error) => Err(anyhow!(
                        "external fence acquire failed: {error}; {cleanup_error}"
                    )),
                };
            }
        };
        if token.scope() != scope {
            let external_cleanup = self.release_or_retain_v1(key, token).err();
            let host_cleanup = self.release_host_admission_exact(key, host_admission).err();
            return Err(anyhow!(
                "external fence returned a scope-mismatched token{}{}",
                external_cleanup
                    .map(|error| format!("; {error}"))
                    .unwrap_or_default(),
                host_cleanup
                    .map(|error| format!("; {error}"))
                    .unwrap_or_default(),
            ));
        }
        let mut tokens = match self.tokens.lock() {
            Ok(tokens) => tokens,
            Err(_) => {
                let external_cleanup = self.release_or_retain_v1(key, token).err();
                let host_cleanup = self.release_host_admission_exact(key, host_admission).err();
                return Err(anyhow!(
                    "mesh fence token map poisoned after admission{}{}",
                    external_cleanup
                        .map(|error| format!("; {error}"))
                        .unwrap_or_default(),
                    host_cleanup
                        .map(|error| format!("; {error}"))
                        .unwrap_or_default(),
                ));
            }
        };
        if tokens.contains_key(&key) {
            drop(tokens);
            let external_cleanup = self.release_or_retain_v1(key, token).err();
            let host_cleanup = self.release_host_admission_exact(key, host_admission).err();
            return Err(anyhow!(
                "external fence key already has a live or pending token{}{}",
                external_cleanup
                    .map(|error| format!("; {error}"))
                    .unwrap_or_default(),
                host_cleanup
                    .map(|error| format!("; {error}"))
                    .unwrap_or_default(),
            ));
        }
        tokens.insert(
            key,
            ActiveFenceEntryV1 {
                token,
                host_admission,
                next_renew_at: Instant::now() + fence_renew_interval(self.ttl),
                external_release_confirmed: false,
                host_release_confirmed: host_admission.is_none(),
            },
        );
        Ok(token)
    }

    fn revalidate(&self, direction: PeerDirectionV0, remote: ValidatorId) -> Result<()> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.revalidate_locked(key)
    }

    /// Revalidate one edge while the admission lock is already held.
    ///
    /// `revalidate_all` uses this form so its key snapshot and every lookup
    /// remain one atomic admission transaction.  Without that boundary a
    /// reconnect worker can release a token after the snapshot but before the
    /// per-key lookup, turning a legitimate transient handoff into a false
    /// frame-path failure.
    fn revalidate_locked(&self, key: ActiveFenceKeyV0) -> Result<()> {
        self.retry_pending_releases_v1(key)?;
        self.retry_pending_host_releases_v1(key)?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
        let entry = tokens
            .get(&key)
            .copied()
            .ok_or_else(|| anyhow!("mesh frame path has no admitted external lease"))?;
        if entry.external_release_confirmed {
            bail!("mesh external lease is pending host-attestation release")
        }
        let mut token = entry.token;
        if token.scope().local() != self.local || token.scope().context() != self.context {
            bail!("mesh external lease scope changed")
        }
        if let Some(host_attestation) = &self.host_attestation {
            let host_admission = entry
                .host_admission
                .ok_or_else(|| anyhow!("mesh fence entry has no host-attestation receipt"))?;
            host_attestation
                .revalidate_exact_v1(host_admission)
                .map_err(|error| anyhow!("host attestation revalidation failed: {error}"))?;
        }
        if Instant::now() >= entry.next_renew_at {
            token = self
                .authority
                .renew(token)
                .map_err(|error| anyhow!("external fence renewal failed: {error}"))?;
            if token.scope() != entry.token.scope() {
                bail!("external fence renewal changed the lease scope")
            }
            tokens.insert(
                key,
                ActiveFenceEntryV1 {
                    token,
                    host_admission: entry.host_admission,
                    next_renew_at: Instant::now() + fence_renew_interval(self.ttl),
                    external_release_confirmed: false,
                    host_release_confirmed: entry.host_release_confirmed,
                },
            );
        } else {
            self.authority
                .revalidate(token)
                .map_err(|error| anyhow!("external fence revalidation failed: {error}"))?;
        }
        Ok(())
    }

    /// Renews a lease only when its local cadence says it is due.  Idle
    /// worker polls and the mesh supervisor use this path so a no-frame
    /// period cannot let a lease expire or turn into an RPC busy loop.
    fn renew_if_due(&self, direction: PeerDirectionV0, remote: ValidatorId) -> Result<()> {
        match self.renew_if_due_inner(direction, remote)? {
            MeshFenceRenewalOutcomeV1::Missing => {
                bail!("mesh frame path has no admitted external lease")
            }
            MeshFenceRenewalOutcomeV1::NotDue | MeshFenceRenewalOutcomeV1::Renewed => Ok(()),
        }
    }

    fn renew_if_due_inner(
        &self,
        direction: PeerDirectionV0,
        remote: ValidatorId,
    ) -> Result<MeshFenceRenewalOutcomeV1> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.retry_pending_releases_v1(key)?;
        self.retry_pending_host_releases_v1(key)?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
        let Some(entry) = tokens.get(&key).copied() else {
            return Ok(MeshFenceRenewalOutcomeV1::Missing);
        };
        if entry.external_release_confirmed {
            bail!("mesh external lease is pending host-attestation release")
        }
        if entry.token.scope().local() != self.local
            || entry.token.scope().context() != self.context
        {
            bail!("mesh external lease scope changed")
        }
        if Instant::now() < entry.next_renew_at {
            return Ok(MeshFenceRenewalOutcomeV1::NotDue);
        }
        if let Some(host_attestation) = &self.host_attestation {
            if entry.host_release_confirmed {
                bail!("mesh host-attestation receipt was already released")
            }
            let host_admission = entry
                .host_admission
                .ok_or_else(|| anyhow!("mesh fence entry has no host-attestation receipt"))?;
            host_attestation
                .revalidate_exact_v1(host_admission)
                .map_err(|error| {
                    anyhow!("host attestation revalidation before renewal failed: {error}")
                })?;
        }
        let renewed = self
            .authority
            .renew(entry.token)
            .map_err(|error| anyhow!("external fence renewal failed: {error}"))?;
        if renewed.scope() != entry.token.scope() {
            bail!("external fence renewal changed the lease scope")
        }
        tokens.insert(
            key,
            ActiveFenceEntryV1 {
                token: renewed,
                host_admission: entry.host_admission,
                next_renew_at: Instant::now() + fence_renew_interval(self.ttl),
                external_release_confirmed: false,
                host_release_confirmed: entry.host_release_confirmed,
            },
        );
        Ok(MeshFenceRenewalOutcomeV1::Renewed)
    }

    /// Runs the due-only path for every currently admitted edge and retains
    /// the exact edge that failed. A worker can legitimately release a token
    /// while this snapshot is being walked, so a disappeared edge is ignored
    /// here; the next generation will acquire a fresh token on reconnect.
    fn renew_due_all(&self) -> std::result::Result<(), MeshFencePeerFailureV1> {
        let keys = self
            .tokens
            .lock()
            .map_err(|_| MeshFencePeerFailureV1 {
                remote: self.local,
                direction: PeerDirectionV0::Outbound,
                reason: "mesh fence token map poisoned".to_owned(),
            })?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for (direction, remote) in keys {
            match self.renew_if_due_inner(direction, remote) {
                Ok(MeshFenceRenewalOutcomeV1::Missing)
                | Ok(MeshFenceRenewalOutcomeV1::NotDue)
                | Ok(MeshFenceRenewalOutcomeV1::Renewed) => {}
                Err(error) => {
                    return Err(MeshFencePeerFailureV1 {
                        remote,
                        direction,
                        reason: error.to_string(),
                    })
                }
            }
        }
        Ok(())
    }

    fn revalidate_all(&self) -> Result<()> {
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        let keys = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            self.revalidate_locked(key)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn renew(&self, direction: PeerDirectionV0, remote: ValidatorId) -> Result<()> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.retry_pending_releases_v1(key)?;
        self.retry_pending_host_releases_v1(key)?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
        let entry = tokens
            .get(&key)
            .copied()
            .ok_or_else(|| anyhow!("mesh renew has no admitted external lease"))?;
        if entry.external_release_confirmed {
            bail!("mesh external lease is pending host-attestation release")
        }
        if let Some(host_attestation) = &self.host_attestation {
            if entry.host_release_confirmed {
                bail!("mesh host-attestation receipt was already released")
            }
            let host_admission = entry
                .host_admission
                .ok_or_else(|| anyhow!("mesh fence entry has no host-attestation receipt"))?;
            host_attestation
                .revalidate_exact_v1(host_admission)
                .map_err(|error| {
                    anyhow!("host attestation revalidation before renewal failed: {error}")
                })?;
        }
        let renewed = self
            .authority
            .renew(entry.token)
            .map_err(|error| anyhow!("external fence renew failed: {error}"))?;
        if renewed.scope() != entry.token.scope() {
            bail!("external fence renew changed the lease scope")
        }
        tokens.insert(
            key,
            ActiveFenceEntryV1 {
                token: renewed,
                host_admission: entry.host_admission,
                next_renew_at: Instant::now() + fence_renew_interval(self.ttl),
                external_release_confirmed: false,
                host_release_confirmed: entry.host_release_confirmed,
            },
        );
        Ok(())
    }

    fn release(&self, direction: PeerDirectionV0, remote: ValidatorId) -> Result<()> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| anyhow!("mesh fence admission lock poisoned"))?;
        self.retry_pending_releases_v1(key)?;
        self.retry_pending_host_releases_v1(key)?;
        // Keep the token in the local map until both authority boundaries
        // confirm release.  Removing it first makes a transient authority
        // failure unrecoverable: `release_all` can report the error, but a
        // retry no longer has the token needed to clear the external lease.
        let entry = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .get(&key)
            .copied();
        if let Some(entry) = entry {
            if !entry.external_release_confirmed {
                self.authority
                    .release(entry.token)
                    .map_err(|error| anyhow!("external fence release failed: {error}"))?;
                // Do not hold the local mutex across the authority call.  If
                // a reconnect replaced this key while the release was in
                // flight, compare the token before changing state so the new
                // generation is never accidentally discarded.
                let mut tokens = match self.tokens.lock() {
                    Ok(tokens) => tokens,
                    Err(_) => {
                        let host_cleanup = self
                            .release_host_admission_exact(key, entry.host_admission)
                            .err();
                        return Err(anyhow!(
                            "mesh fence token map poisoned after peer release{}",
                            host_cleanup
                                .map(|error| format!("; {error}"))
                                .unwrap_or_default(),
                        ));
                    }
                };
                let Some(current) = tokens.get_mut(&key) else {
                    return Ok(());
                };
                if current.token != entry.token || current.host_admission != entry.host_admission {
                    return Ok(());
                }
                current.external_release_confirmed = true;
            }

            // A host receipt is an independent authority.  Only the exact
            // entry whose peer lease was confirmed released may ask that
            // authority to release; a replacement generation must never be
            // torn down by a late cleanup callback.
            let still_current = match self.tokens.lock() {
                Ok(tokens) => tokens
                    .get(&key)
                    .map(|current| {
                        current.token == entry.token
                            && current.host_admission == entry.host_admission
                            && current.external_release_confirmed
                    })
                    .unwrap_or(false),
                Err(_) => {
                    let host_cleanup = self
                        .release_host_admission_exact(key, entry.host_admission)
                        .err();
                    return Err(anyhow!(
                        "mesh fence token map poisoned before host release{}",
                        host_cleanup
                            .map(|error| format!("; {error}"))
                            .unwrap_or_default(),
                    ));
                }
            };
            if !still_current {
                return Ok(());
            }
            let host_needs_release = self
                .tokens
                .lock()
                .map_err(|_| anyhow!("mesh fence token map poisoned"))?
                .get(&key)
                .map(|current| !current.host_release_confirmed)
                .unwrap_or(false);
            if host_needs_release {
                let host_admission = entry
                    .host_admission
                    .ok_or_else(|| anyhow!("mesh fence entry has no host-attestation receipt"))?;
                self.release_host_admission_exact(key, Some(host_admission))?;
                let mut tokens = self
                    .tokens
                    .lock()
                    .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
                let Some(current) = tokens.get_mut(&key) else {
                    return Ok(());
                };
                if current.token != entry.token || current.host_admission != entry.host_admission {
                    return Ok(());
                }
                current.host_release_confirmed = true;
            }

            let mut tokens = self
                .tokens
                .lock()
                .map_err(|_| anyhow!("mesh fence token map poisoned"))?;
            if tokens
                .get(&key)
                .map(|current| {
                    current.token == entry.token
                        && current.host_admission == entry.host_admission
                        && current.external_release_confirmed
                        && current.host_release_confirmed
                })
                .unwrap_or(false)
            {
                tokens.remove(&key);
            }
            return Ok(());
        }

        // Without the retained peer token there is no authenticated
        // generation with which to authorize a host-receipt release.  A
        // key-only cleanup could tear down a newer generation's receipt.
        Ok(())
    }

    fn release_all(&self) -> Result<()> {
        let mut keys = self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        keys.extend(
            self.pending_releases
                .lock()
                .map_err(|_| anyhow!("mesh fence pending-release map poisoned"))?
                .keys()
                .copied(),
        );
        keys.extend(
            self.pending_host_releases
                .lock()
                .map_err(|_| anyhow!("mesh pending host-release map poisoned"))?
                .keys()
                .copied(),
        );
        let keys = keys.into_iter().collect::<BTreeSet<_>>();
        let mut first_error = None;
        for (direction, remote) in keys {
            if let Err(error) = self.release(direction, remote) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn active_count(&self) -> Result<usize> {
        Ok(self
            .tokens
            .lock()
            .map_err(|_| anyhow!("mesh fence token map poisoned"))?
            .len())
    }
}

/// Exact-topology authenticated sessions with bounded in-process recovery.
pub struct PersistentAuthenticatedPeerMeshV0 {
    local: ValidatorId,
    outbound: BTreeMap<ValidatorId, OutboundQueueV0>,
    ingress: Receiver<MeshIngressEventV0>,
    stop: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<MeshTerminalFailureV0>>>,
    controls: ActiveControlsV0,
    fences: MeshFenceRegistryV1,
    workers: Vec<JoinHandle<()>>,
    initial_sessions: Vec<PeerSessionFactsV0>,
    closed: bool,
}

impl PersistentAuthenticatedPeerMeshV0 {
    pub fn establish(
        config: &LoadedValidatorConfig,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
    ) -> Result<Self> {
        Self::establish_with_fence(
            config,
            setup_timeout,
            io_timeout,
            queue_capacity,
            Arc::new(RejectingExternalPeerLeaseAuthorityV1),
        )
    }

    /// Establishes the exact directed mesh behind an injected external fence.
    /// The normal runtime intentionally calls [`Self::establish`], which uses
    /// a rejecting authority until a durable operator-owned service is wired.
    pub fn establish_with_fence(
        config: &LoadedValidatorConfig,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    ) -> Result<Self> {
        ensure!(
            config.has_local_p2p_identity_secret(),
            "ExternalAuthorityRequired: authenticated mesh P2P identity producer is not injected"
        );
        validate_directed_plan(
            config.local_validator(),
            config.peers(),
            config.incoming_peers(),
        )?;
        let outgoing = peer_map(config.peers())?;
        let incoming = peer_map(config.incoming_peers())?;
        let fixture = MeshFixtureConfigV1::new(
            config.run_id().to_owned(),
            config.local_validator(),
            config.p2p_identity_signing_key().clone(),
            config.validator_set().clone(),
            config.key_role_registry().clone(),
            RunTransportContext::new(
                config.topology_sha256(),
                config.candidate_source_sha256(),
                config.binary_sha256(),
                config.coordinator_manifest_sha256(),
            )
            .with_validator_set_binding(
                config.validator_set().epoch().get(),
                config.validator_set().id().into_bytes(),
            )
            .with_node_config_binding(config.coordinator_manifest_sha256()),
            config.listen_addr(),
            outgoing,
            incoming,
        )?;
        Self::establish_fixture_with_fence_v1(
            &fixture,
            setup_timeout,
            io_timeout,
            queue_capacity,
            authority,
        )
    }

    /// Establishes the deployed mesh with an explicitly owned external P2P
    /// identity producer.  This path never reads or clones the local P2P
    /// secret; the producer's public role key is checked against the committed
    /// validator binding before the listener is opened or any worker starts.
    /// It is intentionally an explicit seam and does not alter activation or
    /// production flags.
    #[allow(clippy::too_many_arguments)]
    pub fn establish_with_external_identity_and_fence(
        config: &LoadedValidatorConfig,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
        producer: Box<dyn P2pIdentitySignatureProducerV1>,
    ) -> Result<Self> {
        validate_directed_plan(
            config.local_validator(),
            config.peers(),
            config.incoming_peers(),
        )?;
        let expected_public_key = config
            .key_role_registry()
            .p2p_identity_public_key(config.local_validator())
            .ok_or_else(|| anyhow!("local validator has no committed P2P identity role"))?;
        ensure!(
            producer.public_key_v1() == expected_public_key,
            "external P2P identity producer key does not match committed validator role"
        );
        let identity = MeshIdentityV0 {
            run_id: config.run_id().to_owned(),
            local: config.local_validator(),
            p2p_identity_signer: MeshIdentitySignerV1::External(SharedP2pIdentityProducerV1::new(
                producer,
            )),
            validator_set: config.validator_set().clone(),
            key_roles: config.key_role_registry().clone(),
            transport_context: RunTransportContext::new(
                config.topology_sha256(),
                config.candidate_source_sha256(),
                config.binary_sha256(),
                config.coordinator_manifest_sha256(),
            )
            .with_validator_set_binding(
                config.validator_set().epoch().get(),
                config.validator_set().id().into_bytes(),
            )
            .with_node_config_binding(config.coordinator_manifest_sha256()),
            host_attestation: None,
        };
        Self::establish_identity_with_fence_ttl_v1(
            identity,
            config.listen_addr(),
            peer_map(config.peers())?,
            peer_map(config.incoming_peers())?,
            setup_timeout,
            io_timeout,
            queue_capacity,
            MESH_EXTERNAL_FENCE_TTL_V1,
            authority,
        )
    }

    /// Establishes the external-identity mesh only after an independent host
    /// attestation authority and exact opaque evidence bytes are supplied.
    /// The authority is called once per session generation before the peer
    /// lease is acquired, and again on every frame-path revalidation.  This is
    /// still a bounded transport seam; it does not claim a hardware/TEE
    /// verifier or enable production activation.
    #[allow(clippy::too_many_arguments)]
    pub fn establish_with_external_identity_host_attestation_and_fence(
        config: &LoadedValidatorConfig,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
        producer: Box<dyn P2pIdentitySignatureProducerV1>,
        host_attestation_authority: Arc<dyn HostAttestationAuthorityV1>,
        host_attestation_material: HostAttestationMaterialV1,
    ) -> Result<Self> {
        validate_directed_plan(
            config.local_validator(),
            config.peers(),
            config.incoming_peers(),
        )?;
        let expected_public_key = config
            .key_role_registry()
            .p2p_identity_public_key(config.local_validator())
            .ok_or_else(|| anyhow!("local validator has no committed P2P identity role"))?;
        ensure!(
            producer.public_key_v1() == expected_public_key,
            "external P2P identity producer key does not match committed validator role"
        );
        let identity = MeshIdentityV0 {
            run_id: config.run_id().to_owned(),
            local: config.local_validator(),
            p2p_identity_signer: MeshIdentitySignerV1::External(SharedP2pIdentityProducerV1::new(
                producer,
            )),
            validator_set: config.validator_set().clone(),
            key_roles: config.key_role_registry().clone(),
            transport_context: RunTransportContext::new(
                config.topology_sha256(),
                config.candidate_source_sha256(),
                config.binary_sha256(),
                config.coordinator_manifest_sha256(),
            )
            .with_validator_set_binding(
                config.validator_set().epoch().get(),
                config.validator_set().id().into_bytes(),
            )
            .with_node_config_binding(config.coordinator_manifest_sha256()),
            host_attestation: Some(MeshHostAttestationConfigV1 {
                authority: host_attestation_authority,
                material: host_attestation_material,
            }),
        };
        Self::establish_identity_with_fence_ttl_v1(
            identity,
            config.listen_addr(),
            peer_map(config.peers())?,
            peer_map(config.incoming_peers())?,
            setup_timeout,
            io_timeout,
            queue_capacity,
            MESH_EXTERNAL_FENCE_TTL_V1,
            authority,
        )
    }

    /// Transport-only fixture entry used by the cross-process external-fence
    /// integration test.  It follows the exact same worker/generation path as
    /// [`Self::establish_with_fence`], but does not require a deployment bundle
    /// or secret-bearing `LoadedValidatorConfig`.
    #[doc(hidden)]
    pub fn establish_fixture_with_fence_v1(
        config: &MeshFixtureConfigV1,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    ) -> Result<Self> {
        Self::establish_fixture_with_fence_ttl_v1(
            config,
            setup_timeout,
            io_timeout,
            queue_capacity,
            MESH_EXTERNAL_FENCE_TTL_V1,
            authority,
        )
    }

    /// Same fixture path with an explicitly bounded TTL for deterministic
    /// renewal tests.  Deployed callers remain on the fixed 30-second profile
    /// above; this does not enable a production or consensus transport flag.
    #[doc(hidden)]
    pub fn establish_fixture_with_fence_ttl_v1(
        config: &MeshFixtureConfigV1,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        fence_ttl: Duration,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    ) -> Result<Self> {
        let identity = MeshIdentityV0::from_fixture(config);
        Self::establish_identity_with_fence_ttl_v1(
            identity,
            config.listen_addr,
            config.outgoing.clone(),
            config.incoming.clone(),
            setup_timeout,
            io_timeout,
            queue_capacity,
            fence_ttl,
            authority,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn establish_identity_with_fence_ttl_v1(
        identity: MeshIdentityV0,
        listen_addr: SocketAddr,
        outgoing: BTreeMap<ValidatorId, SocketAddr>,
        incoming: BTreeMap<ValidatorId, SocketAddr>,
        setup_timeout: Duration,
        io_timeout: Duration,
        queue_capacity: usize,
        fence_ttl: Duration,
        authority: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    ) -> Result<Self> {
        validate_limits(setup_timeout, io_timeout, queue_capacity)?;
        if matches!(
            &identity.p2p_identity_signer,
            MeshIdentitySignerV1::External(_)
        ) && identity.host_attestation.is_none()
        {
            bail!(
                "HostAttestationRequired: external P2P identity cannot commission a mesh without an independent host-attestation authority"
            );
        }
        authority
            .preflight()
            .map_err(|error| anyhow!("external fencing preflight failed: {error}"))?;
        validate_directed_plan_maps(identity.local, &outgoing, &incoming)?;

        // Build and validate the independent host-attestation registry before
        // binding any network listener.  A failed platform/authority
        // preflight must not leave a briefly bound consensus socket behind;
        // commissioning is an all-or-nothing boundary.
        let host_attestation = identity
            .host_attestation
            .as_ref()
            .map(|config| {
                let p2p_key = identity
                    .key_roles
                    .p2p_identity_public_key(identity.local)
                    .ok_or(HostAttestationErrorV1::InvalidBinding)?;
                HostAttestationSessionRegistryV1::new(
                    Arc::clone(&config.authority),
                    identity.local,
                    p2p_key,
                    *identity.validator_set.genesis_hash().as_bytes(),
                    identity.validator_set.epoch().get(),
                    identity.validator_set.id().into_bytes(),
                    crate::frame::run_id_sha256_v1(&identity.run_id),
                    crate::transport::network_context_digest_v1(
                        &identity.validator_set,
                        &identity.key_roles,
                        identity.transport_context,
                    ),
                    config.material.clone(),
                )
            })
            .transpose()?;
        let admission_context = PeerAdmissionContextV1::from_validator_set(&identity.validator_set);
        let fences = MeshFenceRegistryV1::new_with_host_attestation(
            authority,
            identity.local,
            admission_context,
            fence_ttl,
            host_attestation,
        )?;
        fences.preflight_host_attestation()?;
        let listener = TcpListener::bind(listen_addr)
            .with_context(|| format!("bind consensus listener {listen_addr}"))?;
        listener
            .set_nonblocking(true)
            .context("set consensus listener nonblocking")?;

        let setup_deadline = Instant::now()
            .checked_add(setup_timeout)
            .ok_or_else(|| anyhow!("mesh setup deadline overflow"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let controls = Arc::new(Mutex::new(BTreeMap::new()));
        let (setup_tx, setup_rx) = mpsc::channel::<SetupEventV0>();
        let (ingress_tx, ingress) = mpsc::sync_channel(queue_capacity);
        let mut workers = Vec::new();
        let mut outbound = BTreeMap::new();
        let outbound_peer_budget_bytes = outbound_queue_byte_budget_v0(queue_capacity)?;
        let global_outbound_budget = Arc::new(MeshQueueByteBudgetV0::new(
            outbound_global_queue_byte_budget_v0(queue_capacity, outgoing.len())?,
        ));

        let inbound_peer_budget_bytes = inbound_queue_byte_budget_v0(queue_capacity)?;
        let global_inbound_budget = Arc::new(MeshQueueByteBudgetV0::new(
            inbound_global_queue_byte_budget_v0(queue_capacity, incoming.len())?,
        ));
        // These Arcs are keyed by authenticated remote identity and remain
        // owned by the accept loop across every session generation. A remote
        // therefore cannot recover per-peer capacity merely by reconnecting.
        let inbound_peer_budgets = incoming
            .keys()
            .copied()
            .map(|remote| {
                (
                    remote,
                    Arc::new(MeshQueueByteBudgetV0::new(inbound_peer_budget_bytes)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        // Lease renewal is an independent mesh worker rather than a side
        // effect of consensus traffic.  An idle authenticated edge must not
        // lose its external generation merely because no frame was sent or
        // received during one TTL window.
        {
            let stop = Arc::clone(&stop);
            let terminal = Arc::clone(&terminal);
            let controls = Arc::clone(&controls);
            let fences = fences.clone();
            let worker = thread::Builder::new()
                .name("trnm-g3-mesh-fence-renew".to_owned())
                .stack_size(MESH_WORKER_STACK_BYTES)
                .spawn(move || loop {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    if let Err(failure) = fences.renew_due_all() {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote: failure.remote,
                                direction: failure.direction,
                                reason: format!(
                                    "external fence renewal supervisor failed: {}",
                                    failure.reason
                                ),
                            },
                        );
                        shutdown_all(&controls);
                        return;
                    }
                    // Polling at the worker bound makes shutdown independent
                    // of the configured lease TTL while each token retains
                    // its own TTL/3 renewal cadence.
                    thread::sleep(WORKER_POLL);
                })
                .context("spawn mesh external-fence renewal worker")?;
            workers.push(worker);
        }
        {
            let accept_incoming = incoming.clone();
            let worker = thread::Builder::new()
                .name("trnm-g3-mesh-accept".to_owned())
                .stack_size(MESH_WORKER_STACK_BYTES)
                .spawn({
                    let identity = identity.clone();
                    let setup_tx = setup_tx.clone();
                    let ingress_tx = ingress_tx.clone();
                    let stop = Arc::clone(&stop);
                    let terminal = Arc::clone(&terminal);
                    let controls = Arc::clone(&controls);
                    let fences = fences.clone();
                    move || {
                        accept_loop(
                            listener,
                            accept_incoming,
                            identity,
                            setup_deadline,
                            io_timeout,
                            setup_tx,
                            ingress_tx,
                            stop,
                            terminal,
                            controls,
                            fences.clone(),
                            inbound_peer_budgets,
                            global_inbound_budget,
                        );
                    }
                })
                .context("spawn consensus acceptor")?;
            workers.push(worker);
        }

        for (&remote, &remote_addr) in &outgoing {
            let (sender, receiver) = mpsc::sync_channel(queue_capacity);
            let byte_budget = Arc::new(MeshQueueByteBudgetV0::new(outbound_peer_budget_bytes));
            if outbound
                .insert(
                    remote,
                    OutboundQueueV0 {
                        sender,
                        peer_budget: byte_budget,
                        global_budget: Arc::clone(&global_outbound_budget),
                    },
                )
                .is_some()
            {
                cleanup_failed_establish(&stop, &controls, workers, &fences);
                bail!("outgoing peer set contains a duplicate");
            }
            let worker = match thread::Builder::new()
                .name(format!("trnm-g3-mesh-send-{}", short_id(remote)))
                .stack_size(MESH_WORKER_STACK_BYTES)
                .spawn({
                    let identity = identity.clone();
                    let setup_tx = setup_tx.clone();
                    let ingress_tx = ingress_tx.clone();
                    let stop = Arc::clone(&stop);
                    let terminal = Arc::clone(&terminal);
                    let controls = Arc::clone(&controls);
                    let fences = fences.clone();
                    move || {
                        outgoing_loop(
                            remote,
                            remote_addr,
                            identity,
                            setup_deadline,
                            setup_timeout,
                            io_timeout,
                            setup_tx,
                            ingress_tx,
                            receiver,
                            stop,
                            terminal,
                            controls,
                            fences.clone(),
                        );
                    }
                }) {
                Ok(worker) => worker,
                Err(error) => {
                    cleanup_failed_establish(&stop, &controls, workers, &fences);
                    return Err(error).context("spawn consensus sender");
                }
            };
            workers.push(worker);
        }
        drop(setup_tx);
        drop(ingress_tx);

        let expected = outgoing
            .len()
            .checked_add(incoming.len())
            .ok_or_else(|| anyhow!("mesh session count overflow"))?;
        let mut seen = BTreeSet::new();
        let mut initial_sessions = Vec::with_capacity(expected);
        while initial_sessions.len() < expected {
            let remaining = setup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                cleanup_failed_establish(&stop, &controls, workers, &fences);
                bail!(
                    "mesh timed out establishing exact topology ({}/{expected})",
                    initial_sessions.len()
                );
            }
            match setup_rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
                Ok(SetupEventV0::Ready(facts)) => {
                    if facts.generation != 1 || !seen.insert((facts.direction, facts.remote)) {
                        cleanup_failed_establish(&stop, &controls, workers, &fences);
                        bail!("mesh initial directed session inventory is not canonical");
                    }
                    initial_sessions.push(facts);
                }
                Ok(SetupEventV0::Failed(reason)) => {
                    cleanup_failed_establish(&stop, &controls, workers, &fences);
                    bail!("mesh setup failed: {reason}");
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    cleanup_failed_establish(&stop, &controls, workers, &fences);
                    bail!("mesh setup workers ended before exact topology");
                }
            }
        }
        initial_sessions.sort_by(|left, right| {
            left.remote
                .cmp(&right.remote)
                .then(left.direction.cmp(&right.direction))
        });

        Ok(Self {
            local: identity.local,
            outbound,
            ingress,
            stop,
            terminal,
            controls,
            fences,
            workers,
            initial_sessions,
            closed: false,
        })
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local
    }

    pub fn initial_sessions(&self) -> &[PeerSessionFactsV0] {
        &self.initial_sessions
    }

    pub fn ensure_healthy(&self) -> Result<()> {
        let failure = self
            .terminal
            .lock()
            .map_err(|_| anyhow!("mesh terminal-state mutex poisoned"))?
            .clone();
        if let Some(failure) = failure {
            bail!(failure.render());
        }
        if self.closed || self.stop.load(Ordering::Acquire) {
            bail!("mesh is closed");
        }
        self.fences.revalidate_all()?;
        Ok(())
    }

    /// Exact bytes still reserved by messages not yet released by the
    /// outgoing workers. A healthy zero result means every queued runtime
    /// broadcast was consumed by its authenticated connection send path.
    pub fn pending_outbound_bytes_v1(&self) -> Result<usize> {
        self.ensure_healthy()?;
        self.outbound.values().try_fold(0usize, |total, queue| {
            total
                .checked_add(queue.peer_budget.used_bytes.load(Ordering::Acquire))
                .ok_or_else(|| anyhow!("mesh pending outbound byte accounting overflows"))
        })
    }

    pub fn send_to(
        &self,
        remote: ValidatorId,
        kind: FrameKind,
        payload: Vec<u8>,
    ) -> Result<MeshSendDispositionV0> {
        self.send_shared_to_v0(remote, kind, Arc::from(payload))
    }

    pub(crate) fn send_shared_to_v0(
        &self,
        remote: ValidatorId,
        kind: FrameKind,
        payload: Arc<[u8]>,
    ) -> Result<MeshSendDispositionV0> {
        self.ensure_healthy()?;
        if !is_consensus_kind(kind) {
            bail!("persistent mesh accepts only consensus/barrier/restart/relay frame kinds");
        }
        if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            bail!("persistent mesh payload exceeds the authenticated frame bound");
        }
        let queue = self
            .outbound
            .get(&remote)
            .ok_or_else(|| anyhow!("remote is outside frozen outgoing peer set"))?;
        self.fences.revalidate(PeerDirectionV0::Outbound, remote)?;
        let reserved_bytes = payload
            .len()
            .checked_add(QUEUED_FRAME_OVERHEAD_BYTES)
            .ok_or_else(|| anyhow!("mesh queued frame size overflow"))?;
        let Some(reservation) = OutboundQueueReservationV0::try_new(
            &queue.peer_budget,
            &queue.global_budget,
            reserved_bytes,
        ) else {
            return Ok(MeshSendDispositionV0::Backpressured);
        };
        let message = OutboundMessageV0 {
            kind,
            payload,
            _reservation: reservation,
        };
        match queue.sender.try_send(message) {
            Ok(()) => Ok(MeshSendDispositionV0::Queued),
            // Dropping the returned message releases its byte reservation.
            Err(TrySendError::Full(_)) => Ok(MeshSendDispositionV0::Backpressured),
            Err(TrySendError::Disconnected(_)) => {
                set_terminal(
                    &self.terminal,
                    &self.stop,
                    MeshTerminalFailureV0 {
                        remote,
                        direction: PeerDirectionV0::Outbound,
                        reason: "outgoing worker disappeared".to_owned(),
                    },
                );
                shutdown_all(&self.controls);
                bail!("mesh outgoing worker disappeared")
            }
        }
    }

    pub fn broadcast(&self, kind: FrameKind, payload: &[u8]) -> Result<MeshBroadcastOutcomeV0> {
        self.ensure_healthy()?;
        let payload: Arc<[u8]> = Arc::from(payload);
        let mut queued_peers = 0usize;
        let mut backpressured_peers = Vec::new();
        for remote in self.outbound.keys().copied() {
            match self.send_shared_to_v0(remote, kind, Arc::clone(&payload))? {
                MeshSendDispositionV0::Queued => {
                    queued_peers = queued_peers
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("mesh queued-peer count overflow"))?;
                }
                MeshSendDispositionV0::Backpressured => backpressured_peers.push(remote),
            }
        }
        Ok(MeshBroadcastOutcomeV0 {
            queued_peers,
            backpressured_peers,
        })
    }

    pub fn receive_timeout(&self, timeout: Duration) -> Result<Option<MeshIngressEventV0>> {
        self.ensure_healthy()?;
        match self.ingress.recv_timeout(timeout) {
            Ok(event) => Ok(Some(event)),
            Err(RecvTimeoutError::Timeout) => {
                self.ensure_healthy()?;
                Ok(None)
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.ensure_healthy()?;
                bail!("mesh ingress workers ended")
            }
        }
    }

    /// Receives one mesh event while installing the candidate durable payload
    /// replay fence. For a frame event, the queue owner is retained until the
    /// WAL/head fsync succeeds; any replay, prefix, context, or lease-boundary
    /// failure poisons the mesh and stops every worker. Lifecycle events pass
    /// through unchanged. The ordinary `receive_timeout` API remains intact
    /// for compatibility, but callers using a restart-safe ingress must route
    /// through this explicit method.
    pub fn receive_timeout_with_payload_replay_v1(
        &self,
        timeout: Duration,
        replay: &Mutex<PayloadReplayStoreV1>,
        run_id: &str,
    ) -> Result<Option<MeshIngressEventV0>> {
        let event = self.receive_timeout(timeout)?;
        let Some(MeshIngressEventV0::Frame(ref inbound)) = event else {
            return Ok(event);
        };
        // Revalidate the exact directed lease immediately before durable
        // payload admission. This closes the interval between the worker's
        // frame-path check and the WAL commit; a renewed/fenced generation
        // cannot race a stale payload into the replay owner.
        if let Err(error) = self.fences.revalidate(inbound.direction, inbound.remote) {
            let facts = PeerSessionFactsV0 {
                remote: inbound.remote,
                direction: inbound.direction,
                session_id: inbound.session_id,
                generation: inbound.session_generation,
            };
            let error = anyhow!("payload replay peer lease: {error}");
            set_terminal(
                &self.terminal,
                &self.stop,
                MeshTerminalFailureV0 {
                    remote: facts.remote,
                    direction: facts.direction,
                    reason: error.to_string(),
                },
            );
            shutdown_all(&self.controls);
            return Err(error);
        }
        let result = replay
            .lock()
            .map_err(|_| anyhow!("payload replay owner mutex poisoned"))
            .and_then(|mut owner| {
                inbound
                    .admit_payload_replay_v1(&mut owner, run_id)
                    .map(|_| ())
                    .map_err(|error| anyhow!("durable authenticated payload replay: {error}"))
            });
        if let Err(error) = result {
            let facts = PeerSessionFactsV0 {
                remote: inbound.remote,
                direction: inbound.direction,
                session_id: inbound.session_id,
                generation: inbound.session_generation,
            };
            set_terminal(
                &self.terminal,
                &self.stop,
                MeshTerminalFailureV0 {
                    remote: facts.remote,
                    direction: facts.direction,
                    reason: error.to_string(),
                },
            );
            shutdown_all(&self.controls);
            return Err(error);
        }
        self.ensure_healthy()?;
        Ok(event)
    }

    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }

    /// Stops and joins every mesh worker, then proves that no authenticated
    /// ingress event was already queued behind the runtime's terminal quiet
    /// check. A non-empty queue fails closed; the caller must not consume its
    /// consensus authority into a clean terminal report.
    pub fn close_if_ingress_empty_v1(mut self) -> Result<()> {
        self.close_inner()?;
        match self.ingress.try_recv() {
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(()),
            Ok(_) => bail!("consensus ingress was queued at mesh shutdown"),
        }
    }

    fn close_inner(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.stop.store(true, Ordering::Release);
        self.outbound.clear();
        shutdown_all(&self.controls);
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        self.fences.release_all()?;
        if panicked {
            bail!("mesh worker panicked during shutdown");
        }
        Ok(())
    }
}

impl Drop for PersistentAuthenticatedPeerMeshV0 {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

#[allow(clippy::too_many_arguments)]
fn outgoing_loop(
    remote: ValidatorId,
    remote_addr: SocketAddr,
    identity: MeshIdentityV0,
    initial_deadline: Instant,
    reconnect_window: Duration,
    io_timeout: Duration,
    setup_tx: mpsc::Sender<SetupEventV0>,
    ingress_tx: SyncSender<MeshIngressEventV0>,
    receiver: Receiver<OutboundMessageV0>,
    stop: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<MeshTerminalFailureV0>>>,
    controls: ActiveControlsV0,
    fences: MeshFenceRegistryV1,
) {
    let mut generation = 1u64;
    let mut connection = match connect_authenticated_until(
        remote,
        remote_addr,
        &identity,
        initial_deadline,
        io_timeout,
        &stop,
        &controls,
        &fences,
        1,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = setup_tx.send(SetupEventV0::Failed(error.render()));
            return;
        }
    };
    let mut facts = PeerSessionFactsV0 {
        remote,
        direction: PeerDirectionV0::Outbound,
        session_id: connection.session_id(),
        generation,
    };
    if setup_tx.send(SetupEventV0::Ready(facts)).is_err() {
        let _ = fences.release(PeerDirectionV0::Outbound, remote);
        return;
    }

    loop {
        if stop.load(Ordering::Acquire) {
            let _ = fences.release(PeerDirectionV0::Outbound, remote);
            return;
        }
        let message = match receiver.recv_timeout(WORKER_POLL) {
            Ok(message) => message,
            Err(RecvTimeoutError::Timeout) => {
                // A quiet outbound edge still gets a bounded fence check;
                // the registry performs the external RPC only at TTL/3.
                if let Err(error) = fences.renew_if_due(PeerDirectionV0::Outbound, remote) {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Outbound,
                            reason: format!("idle external fence revalidation failed: {error}"),
                        },
                    );
                    shutdown_all(&controls);
                    let _ = fences.release(PeerDirectionV0::Outbound, remote);
                    return;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                if !stop.load(Ordering::Acquire) {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Outbound,
                            reason: "outgoing command owner disappeared".to_owned(),
                        },
                    );
                }
                return;
            }
        };
        loop {
            if let Err(error) = fences.revalidate(PeerDirectionV0::Outbound, remote) {
                set_terminal(
                    &terminal,
                    &stop,
                    MeshTerminalFailureV0 {
                        remote,
                        direction: PeerDirectionV0::Outbound,
                        reason: error.to_string(),
                    },
                );
                shutdown_all(&controls);
                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                return;
            }
            match connection.send(message.kind, message.payload.as_ref().to_vec()) {
                Ok(()) => break,
                Err(error) if transient_frame_error(&error) => {
                    if emit_event(
                        &ingress_tx,
                        MeshIngressEventV0::SessionUnavailable(facts),
                        &terminal,
                        &stop,
                        facts,
                        None,
                    )
                    .is_err()
                    {
                        return;
                    }
                    remove_control(&controls, PeerDirectionV0::Outbound, remote);
                    if let Err(error) = fences.release(PeerDirectionV0::Outbound, remote) {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Outbound,
                                reason: error.to_string(),
                            },
                        );
                        return;
                    }
                    let next_generation = match generation.checked_add(1) {
                        Some(value) if value <= MAX_SESSION_GENERATION => value,
                        _ => {
                            set_terminal(
                                &terminal,
                                &stop,
                                MeshTerminalFailureV0 {
                                    remote,
                                    direction: PeerDirectionV0::Outbound,
                                    reason: "session generation exhausted".to_owned(),
                                },
                            );
                            return;
                        }
                    };
                    connection = loop {
                        let deadline = match Instant::now().checked_add(reconnect_window) {
                            Some(deadline) => deadline,
                            None => {
                                set_terminal(
                                    &terminal,
                                    &stop,
                                    MeshTerminalFailureV0 {
                                        remote,
                                        direction: PeerDirectionV0::Outbound,
                                        reason: "reconnect deadline overflow".to_owned(),
                                    },
                                );
                                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                                return;
                            }
                        };
                        match connect_authenticated_until(
                            remote,
                            remote_addr,
                            &identity,
                            deadline,
                            io_timeout,
                            &stop,
                            &controls,
                            &fences,
                            next_generation,
                        ) {
                            Ok(connection) => break connection,
                            Err(ConnectAttemptFailureV0::WindowElapsed) => continue,
                            Err(ConnectAttemptFailureV0::Stopped) => return,
                            Err(ConnectAttemptFailureV0::Terminal(reason)) => {
                                set_terminal(
                                    &terminal,
                                    &stop,
                                    MeshTerminalFailureV0 {
                                        remote,
                                        direction: PeerDirectionV0::Outbound,
                                        reason,
                                    },
                                );
                                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                                return;
                            }
                        }
                    };
                    generation = next_generation;
                    facts = PeerSessionFactsV0 {
                        remote,
                        direction: PeerDirectionV0::Outbound,
                        session_id: connection.session_id(),
                        generation,
                    };
                    if emit_event(
                        &ingress_tx,
                        MeshIngressEventV0::SessionReestablished(facts),
                        &terminal,
                        &stop,
                        facts,
                        None,
                    )
                    .is_err()
                    {
                        return;
                    }
                    // Retrying the same independently signed consensus bytes
                    // is intentional; Core/collector exact-dedup decides it.
                }
                Err(error) => {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Outbound,
                            reason: format!("non-recoverable frame error: {error}"),
                        },
                    );
                    return;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_loop(
    listener: TcpListener,
    expected: BTreeMap<ValidatorId, SocketAddr>,
    identity: MeshIdentityV0,
    initial_deadline: Instant,
    io_timeout: Duration,
    setup_tx: mpsc::Sender<SetupEventV0>,
    ingress_tx: SyncSender<MeshIngressEventV0>,
    stop: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<MeshTerminalFailureV0>>>,
    controls: ActiveControlsV0,
    fences: MeshFenceRegistryV1,
    inbound_peer_budgets: BTreeMap<ValidatorId, Arc<MeshQueueByteBudgetV0>>,
    global_inbound_budget: Arc<MeshQueueByteBudgetV0>,
) {
    let lifecycle_capacity = expected.len().saturating_mul(2).max(1);
    let (lifecycle_tx, lifecycle_rx) = mpsc::sync_channel(lifecycle_capacity);
    let mut generations = BTreeMap::<ValidatorId, u64>::new();
    let mut children = BTreeMap::<ValidatorId, InboundWorkerV0>::new();

    loop {
        if stop.load(Ordering::Acquire) {
            shutdown_all(&controls);
            join_children(children, &controls, &terminal, &stop, &fences);
            return;
        }
        loop {
            match lifecycle_rx.try_recv() {
                Ok(InboundLifecycleV0::TransientLoss(facts)) => {
                    if children.get(&facts.remote).map(|worker| worker.facts) == Some(facts) {
                        let worker = children
                            .remove(&facts.remote)
                            .expect("matching inbound worker exists");
                        worker.cancel.store(true, Ordering::Release);
                        remove_control(&controls, PeerDirectionV0::Inbound, facts.remote);
                        if worker.handle.join().is_err() {
                            set_terminal(
                                &terminal,
                                &stop,
                                MeshTerminalFailureV0 {
                                    remote: facts.remote,
                                    direction: PeerDirectionV0::Inbound,
                                    reason: "inbound worker panicked during transient retirement"
                                        .to_owned(),
                                },
                            );
                            let _ = fences.release(PeerDirectionV0::Inbound, facts.remote);
                            join_children(children, &controls, &terminal, &stop, &fences);
                            return;
                        }
                        if emit_event(
                            &ingress_tx,
                            MeshIngressEventV0::SessionUnavailable(facts),
                            &terminal,
                            &stop,
                            facts,
                            None,
                        )
                        .is_err()
                        {
                            join_children(children, &controls, &terminal, &stop, &fences);
                            return;
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote: identity.local,
                            direction: PeerDirectionV0::Inbound,
                            reason: "inbound lifecycle channel disappeared".to_owned(),
                        },
                    );
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                }
            }
        }
        if generations.len() < expected.len() && Instant::now() >= initial_deadline {
            let _ = setup_tx.send(SetupEventV0::Failed(format!(
                "timed out waiting for inbound peers ({}/{})",
                generations.len(),
                expected.len()
            )));
            join_children(children, &controls, &terminal, &stop, &fences);
            return;
        }

        match listener.accept() {
            Ok((stream, source)) => {
                let attempt_deadline = Instant::now()
                    .checked_add(MAX_HANDSHAKE_ATTEMPT.min(io_timeout))
                    .unwrap_or_else(Instant::now);
                let mut connection = match authenticate_incoming(
                    stream,
                    source,
                    &expected,
                    &identity,
                    attempt_deadline,
                    io_timeout,
                ) {
                    Ok(connection) => connection,
                    Err(IncomingAuthFailureV0::Transient) => continue,
                    Err(IncomingAuthFailureV0::Terminal(reason)) => {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote: identity.local,
                                direction: PeerDirectionV0::Inbound,
                                reason,
                            },
                        );
                        let _ = setup_tx.send(SetupEventV0::Failed(
                            "inbound authentication ambiguity".to_owned(),
                        ));
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                };
                let remote = connection.remote();
                let Some(inbound_peer_budget) = inbound_peer_budgets.get(&remote).cloned() else {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Inbound,
                            reason: "authenticated remote has no inbound byte budget".to_owned(),
                        },
                    );
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                };
                let generation = match generations
                    .get(&remote)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                {
                    Some(value) if value <= MAX_SESSION_GENERATION => value,
                    _ => {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: "session generation exhausted".to_owned(),
                            },
                        );
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                };
                let facts = PeerSessionFactsV0 {
                    remote,
                    direction: PeerDirectionV0::Inbound,
                    session_id: connection.session_id(),
                    generation,
                };
                if let Some(previous_worker) = children.remove(&remote) {
                    previous_worker.cancel.store(true, Ordering::Release);
                    remove_control(&controls, PeerDirectionV0::Inbound, remote);
                    let previous = previous_worker.facts;
                    if previous_worker.handle.join().is_err() {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: "superseded inbound worker panicked".to_owned(),
                            },
                        );
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                    if let Err(error) = fences.release(PeerDirectionV0::Inbound, remote) {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: error.to_string(),
                            },
                        );
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                    if emit_event(
                        &ingress_tx,
                        MeshIngressEventV0::SessionUnavailable(previous),
                        &terminal,
                        &stop,
                        previous,
                        None,
                    )
                    .is_err()
                    {
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                }
                if let Err(error) = fences.acquire(
                    PeerDirectionV0::Inbound,
                    remote,
                    connection.session_id(),
                    generation,
                ) {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Inbound,
                            reason: format!("external fence rejected inbound session: {error}"),
                        },
                    );
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                }
                let host_attestation = match fences.host_attestation_admission(
                    PeerDirectionV0::Inbound,
                    remote,
                    connection.session_id(),
                    generation,
                ) {
                    Ok(admission) => admission,
                    Err(error) => {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: error.to_string(),
                            },
                        );
                        let _ = fences.release(PeerDirectionV0::Inbound, remote);
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                };
                if let Err(error) = connection.mark_host_attestation_admitted(
                    host_attestation,
                    ExternalPeerDirectionV1::Inbound,
                    generation,
                ) {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Inbound,
                            reason: error.to_string(),
                        },
                    );
                    let _ = fences.release(PeerDirectionV0::Inbound, remote);
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                }
                let control = match connection.io_mut().try_clone() {
                    Ok(control) => control,
                    Err(error) => {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: error.to_string(),
                            },
                        );
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                };
                if let Err(error) =
                    replace_control(&controls, PeerDirectionV0::Inbound, remote, control)
                {
                    set_terminal(
                        &terminal,
                        &stop,
                        MeshTerminalFailureV0 {
                            remote,
                            direction: PeerDirectionV0::Inbound,
                            reason: error.to_string(),
                        },
                    );
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                }
                generations.insert(remote, generation);
                if generation == 1 {
                    if setup_tx.send(SetupEventV0::Ready(facts)).is_err() {
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                } else if emit_event(
                    &ingress_tx,
                    MeshIngressEventV0::SessionReestablished(facts),
                    &terminal,
                    &stop,
                    facts,
                    None,
                )
                .is_err()
                {
                    join_children(children, &controls, &terminal, &stop, &fences);
                    return;
                }
                let cancel = Arc::new(AtomicBool::new(false));
                let inbound_idle_timeout = fence_renew_interval(fences.ttl);
                let child = thread::Builder::new()
                    .name(format!("trnm-g3-mesh-recv-{}", short_id(remote)))
                    .stack_size(MESH_WORKER_STACK_BYTES)
                    .spawn({
                        let ingress_tx = ingress_tx.clone();
                        let lifecycle_tx = lifecycle_tx.clone();
                        let stop = Arc::clone(&stop);
                        let terminal = Arc::clone(&terminal);
                        let cancel = Arc::clone(&cancel);
                        let global_inbound_budget = Arc::clone(&global_inbound_budget);
                        let fences = fences.clone();
                        move || loop {
                            if stop.load(Ordering::Acquire) || cancel.load(Ordering::Acquire) {
                                let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                return;
                            }
                            if let Err(error) = fences.revalidate(PeerDirectionV0::Inbound, remote)
                            {
                                set_terminal(
                                    &terminal,
                                    &stop,
                                    MeshTerminalFailureV0 {
                                        remote,
                                        direction: PeerDirectionV0::Inbound,
                                        reason: error.to_string(),
                                    },
                                );
                                let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                return;
                            }
                            match connection
                                .io_mut()
                                .wait_readable(inbound_idle_timeout, io_timeout)
                            {
                                Ok(false) => continue,
                                Ok(true) => {}
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        io::ErrorKind::UnexpectedEof
                                            | io::ErrorKind::ConnectionReset
                                            | io::ErrorKind::ConnectionAborted
                                            | io::ErrorKind::BrokenPipe
                                            | io::ErrorKind::NotConnected
                                            | io::ErrorKind::TimedOut
                                            | io::ErrorKind::WouldBlock
                                    ) =>
                                {
                                    if !cancel.load(Ordering::Acquire)
                                        && !stop.load(Ordering::Acquire)
                                    {
                                        let _ = emit_inbound_lifecycle(
                                            &lifecycle_tx,
                                            InboundLifecycleV0::TransientLoss(facts),
                                            &terminal,
                                            &stop,
                                            facts,
                                            &cancel,
                                        );
                                    }
                                    let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                    return;
                                }
                                Err(error) => {
                                    if !stop.load(Ordering::Acquire)
                                        && !cancel.load(Ordering::Acquire)
                                    {
                                        set_terminal(
                                            &terminal,
                                            &stop,
                                            MeshTerminalFailureV0 {
                                                remote,
                                                direction: PeerDirectionV0::Inbound,
                                                reason: format!(
                                                    "inbound readiness probe failed: {error}"
                                                ),
                                            },
                                        );
                                    }
                                    let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                    return;
                                }
                            }
                            match connection.receive() {
                                Ok(frame) => {
                                    let reserved_bytes = match frame
                                        .payload
                                        .len()
                                        .checked_add(QUEUED_FRAME_OVERHEAD_BYTES)
                                    {
                                        Some(bytes) => bytes,
                                        None => {
                                            set_terminal(
                                                &terminal,
                                                &stop,
                                                MeshTerminalFailureV0 {
                                                    remote,
                                                    direction: PeerDirectionV0::Inbound,
                                                    reason: "inbound queued frame size overflow"
                                                        .to_owned(),
                                                },
                                            );
                                            let _ =
                                                fences.release(PeerDirectionV0::Inbound, remote);
                                            return;
                                        }
                                    };
                                    // The authenticated frame remains owned by
                                    // this worker while admission is full. It
                                    // neither reads another frame nor discards
                                    // this one; stop/cancel remains polled.
                                    let Some(reservation) =
                                        reserve_inbound_frame_until_available_v0(
                                            &inbound_peer_budget,
                                            &global_inbound_budget,
                                            reserved_bytes,
                                            &stop,
                                            &cancel,
                                        )
                                    else {
                                        let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                        return;
                                    };
                                    if let Err(error) =
                                        fences.revalidate(PeerDirectionV0::Inbound, remote)
                                    {
                                        set_terminal(
                                            &terminal,
                                            &stop,
                                            MeshTerminalFailureV0 {
                                                remote,
                                                direction: PeerDirectionV0::Inbound,
                                                reason: error.to_string(),
                                            },
                                        );
                                        let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                        return;
                                    }
                                    if emit_event(
                                        &ingress_tx,
                                        MeshIngressEventV0::Frame(MeshInboundFrameV0 {
                                            remote,
                                            direction: PeerDirectionV0::Inbound,
                                            session_id: facts.session_id,
                                            session_generation: facts.generation,
                                            frame,
                                            _reservation: reservation,
                                        }),
                                        &terminal,
                                        &stop,
                                        facts,
                                        Some(&cancel),
                                    )
                                    .is_err()
                                    {
                                        let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                        return;
                                    }
                                }
                                Err(error) if transient_frame_error(&error) => {
                                    if !cancel.load(Ordering::Acquire)
                                        && !stop.load(Ordering::Acquire)
                                    {
                                        let _ = emit_inbound_lifecycle(
                                            &lifecycle_tx,
                                            InboundLifecycleV0::TransientLoss(facts),
                                            &terminal,
                                            &stop,
                                            facts,
                                            &cancel,
                                        );
                                    }
                                    let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                    return;
                                }
                                Err(error) => {
                                    if !stop.load(Ordering::Acquire)
                                        && !cancel.load(Ordering::Acquire)
                                    {
                                        set_terminal(
                                            &terminal,
                                            &stop,
                                            MeshTerminalFailureV0 {
                                                remote,
                                                direction: PeerDirectionV0::Inbound,
                                                reason: format!(
                                                    "non-recoverable frame error: {error}"
                                                ),
                                            },
                                        );
                                    }
                                    let _ = fences.release(PeerDirectionV0::Inbound, remote);
                                    return;
                                }
                            }
                        }
                    });
                match child {
                    Ok(handle) => {
                        let previous = children.insert(
                            remote,
                            InboundWorkerV0 {
                                facts,
                                cancel,
                                handle,
                            },
                        );
                        debug_assert!(previous.is_none());
                    }
                    Err(error) => {
                        set_terminal(
                            &terminal,
                            &stop,
                            MeshTerminalFailureV0 {
                                remote,
                                direction: PeerDirectionV0::Inbound,
                                reason: format!("spawn inbound worker: {error}"),
                            },
                        );
                        join_children(children, &controls, &terminal, &stop, &fences);
                        return;
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) => {
                set_terminal(
                    &terminal,
                    &stop,
                    MeshTerminalFailureV0 {
                        remote: identity.local,
                        direction: PeerDirectionV0::Inbound,
                        reason: format!("accept failed: {error}"),
                    },
                );
                join_children(children, &controls, &terminal, &stop, &fences);
                return;
            }
        }
    }
}

fn connect_authenticated_until(
    remote: ValidatorId,
    address: SocketAddr,
    identity: &MeshIdentityV0,
    deadline: Instant,
    io_timeout: Duration,
    stop: &AtomicBool,
    controls: &ActiveControlsV0,
    fences: &MeshFenceRegistryV1,
    generation: u64,
) -> std::result::Result<MeshAuthenticatedConnectionV1<DeadlineIo>, ConnectAttemptFailureV0> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(ConnectAttemptFailureV0::Stopped);
        }
        if Instant::now() >= deadline {
            return Err(ConnectAttemptFailureV0::WindowElapsed);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = remaining.min(Duration::from_millis(250));
        let stream = match TcpStream::connect_timeout(&address, attempt) {
            Ok(stream) => stream,
            Err(error) if transient_connect_error(&error) => {
                thread::sleep(CONNECT_POLL);
                continue;
            }
            Err(error) => {
                return Err(ConnectAttemptFailureV0::Terminal(format!(
                    "non-recoverable connect error: {error}"
                )))
            }
        };
        let handshake_deadline = Instant::now()
            .checked_add(remaining.min(MAX_HANDSHAKE_ATTEMPT).min(io_timeout))
            .ok_or_else(|| {
                ConnectAttemptFailureV0::Terminal("handshake deadline overflow".to_owned())
            })?;
        let io = DeadlineIo::new(stream, handshake_deadline).map_err(|error| {
            ConnectAttemptFailureV0::Terminal(format!("prepare handshake socket: {error}"))
        })?;
        let mut connection = match match &identity.p2p_identity_signer {
            MeshIdentitySignerV1::Local(signing_key) => AuthenticatedConnection::connect(
                io,
                &identity.run_id,
                identity.local,
                remote,
                signing_key,
                &identity.validator_set,
                &identity.key_roles,
                identity.transport_context,
            )
            .map(MeshAuthenticatedConnectionV1::Local),
            MeshIdentitySignerV1::External(producer) => {
                ExternallySignedAuthenticatedConnectionV1::connect(
                    io,
                    &identity.run_id,
                    identity.local,
                    remote,
                    Box::new(producer.clone()),
                    &identity.validator_set,
                    &identity.key_roles,
                    identity.transport_context,
                )
                .map(MeshAuthenticatedConnectionV1::External)
            }
        } {
            Ok(connection) => connection,
            Err(error) if transient_frame_error(&error) => {
                thread::sleep(CONNECT_POLL);
                continue;
            }
            Err(error) => {
                return Err(ConnectAttemptFailureV0::Terminal(format!(
                    "authentication ambiguity: {error}"
                )))
            }
        };
        connection
            .io_mut()
            .make_persistent(None, Some(io_timeout))
            .map_err(|error| {
                ConnectAttemptFailureV0::Terminal(format!("configure persistent socket: {error}"))
            })?;
        let control = connection.io_mut().try_clone().map_err(|error| {
            ConnectAttemptFailureV0::Terminal(format!("clone shutdown handle: {error}"))
        })?;
        replace_control(controls, PeerDirectionV0::Outbound, remote, control).map_err(|error| {
            ConnectAttemptFailureV0::Terminal(format!("register shutdown handle: {error}"))
        })?;
        if let Err(error) = fences.acquire(
            PeerDirectionV0::Outbound,
            remote,
            connection.session_id(),
            generation,
        ) {
            remove_control(controls, PeerDirectionV0::Outbound, remote);
            return Err(ConnectAttemptFailureV0::Terminal(format!(
                "external fence rejected outbound session: {error}"
            )));
        }
        let host_attestation = fences
            .host_attestation_admission(
                PeerDirectionV0::Outbound,
                remote,
                connection.session_id(),
                generation,
            )
            .map_err(|error| {
                remove_control(controls, PeerDirectionV0::Outbound, remote);
                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                ConnectAttemptFailureV0::Terminal(error.to_string())
            })?;
        connection
            .mark_host_attestation_admitted(
                host_attestation,
                ExternalPeerDirectionV1::Outbound,
                generation,
            )
            .map_err(|error| {
                remove_control(controls, PeerDirectionV0::Outbound, remote);
                let _ = fences.release(PeerDirectionV0::Outbound, remote);
                ConnectAttemptFailureV0::Terminal(error.to_string())
            })?;
        return Ok(connection);
    }
}

fn authenticate_incoming(
    stream: TcpStream,
    source: SocketAddr,
    expected: &BTreeMap<ValidatorId, SocketAddr>,
    identity: &MeshIdentityV0,
    deadline: Instant,
    io_timeout: Duration,
) -> std::result::Result<MeshAuthenticatedConnectionV1<DeadlineIo>, IncomingAuthFailureV0> {
    let io = DeadlineIo::new(stream, deadline).map_err(|error| {
        IncomingAuthFailureV0::Terminal(format!("prepare inbound handshake socket: {error}"))
    })?;
    let mut connection = match match &identity.p2p_identity_signer {
        MeshIdentitySignerV1::Local(signing_key) => AuthenticatedConnection::accept(
            io,
            &identity.run_id,
            identity.local,
            signing_key,
            &identity.validator_set,
            &identity.key_roles,
            identity.transport_context,
        )
        .map(MeshAuthenticatedConnectionV1::Local),
        MeshIdentitySignerV1::External(producer) => {
            ExternallySignedAuthenticatedConnectionV1::accept(
                io,
                &identity.run_id,
                identity.local,
                Box::new(producer.clone()),
                &identity.validator_set,
                &identity.key_roles,
                identity.transport_context,
            )
            .map(MeshAuthenticatedConnectionV1::External)
        }
    } {
        Ok(connection) => connection,
        Err(error) => return Err(classify_incoming_auth_failure_v0(error)),
    };
    let committed = expected.get(&connection.remote()).ok_or_else(|| {
        IncomingAuthFailureV0::Terminal(
            "inbound identity is outside frozen direction set".to_owned(),
        )
    })?;
    if source.ip() != committed.ip() {
        return Err(IncomingAuthFailureV0::Terminal(
            "inbound source IP differs from frozen peer address".to_owned(),
        ));
    }
    connection
        .io_mut()
        .make_persistent(None, Some(io_timeout))
        .map_err(|error| {
            IncomingAuthFailureV0::Terminal(format!("configure persistent inbound socket: {error}"))
        })?;
    Ok(connection)
}

fn classify_incoming_auth_failure_v0(error: FrameError) -> IncomingAuthFailureV0 {
    if transient_frame_error(&error) {
        IncomingAuthFailureV0::Transient
    } else {
        IncomingAuthFailureV0::Terminal(format!("inbound authentication failed: {error}"))
    }
}

fn transient_frame_error(error: &FrameError) -> bool {
    matches!(error, FrameError::Io(source) if matches!(
        source.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    ))
}

fn transient_connect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::ConnectionAborted
    )
}

fn is_consensus_kind(kind: FrameKind) -> bool {
    matches!(
        kind,
        FrameKind::Proposal
            | FrameKind::Vote
            | FrameKind::TimeoutVote
            | FrameKind::QuorumCertificate
            | FrameKind::TimeoutCertificate
            | FrameKind::ConsensusRelay
            | FrameKind::FleetReady
            | FrameKind::FleetStart
            | FrameKind::RestartPrepare
            | FrameKind::RestartCut
            | FrameKind::RestartParkedAck
            | FrameKind::RestartRecoveryReady
            | FrameKind::RestartRecoveryStart
            | FrameKind::RestartCatchup
    )
}

fn reserve_inbound_frame_until_available_v0(
    peer_budget: &Arc<MeshQueueByteBudgetV0>,
    global_budget: &Arc<MeshQueueByteBudgetV0>,
    reserved_bytes: usize,
    stop: &AtomicBool,
    edge_cancel: &AtomicBool,
) -> Option<InboundQueueReservationV0> {
    loop {
        if stop.load(Ordering::Acquire) || edge_cancel.load(Ordering::Acquire) {
            return None;
        }
        if let Some(reservation) =
            InboundQueueReservationV0::try_new(peer_budget, global_budget, reserved_bytes)
        {
            return Some(reservation);
        }
        thread::sleep(WORKER_POLL);
    }
}

fn emit_event(
    sender: &SyncSender<MeshIngressEventV0>,
    mut event: MeshIngressEventV0,
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
    facts: PeerSessionFactsV0,
    edge_cancel: Option<&AtomicBool>,
) -> Result<()> {
    loop {
        if stop.load(Ordering::Acquire)
            || edge_cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire))
        {
            bail!("mesh stopped while applying bounded ingress backpressure");
        }
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(returned)) => {
                event = returned;
                thread::sleep(WORKER_POLL);
            }
            Err(TrySendError::Disconnected(_)) => {
                if !stop.load(Ordering::Acquire) {
                    set_terminal(
                        terminal,
                        stop,
                        MeshTerminalFailureV0 {
                            remote: facts.remote,
                            direction: facts.direction,
                            reason: "ingress owner disappeared".to_owned(),
                        },
                    );
                }
                bail!("mesh ingress owner disappeared")
            }
        }
    }
}

fn emit_inbound_lifecycle(
    sender: &SyncSender<InboundLifecycleV0>,
    mut event: InboundLifecycleV0,
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
    facts: PeerSessionFactsV0,
    edge_cancel: &AtomicBool,
) -> Result<()> {
    loop {
        if stop.load(Ordering::Acquire) || edge_cancel.load(Ordering::Acquire) {
            bail!("mesh stopped while applying bounded lifecycle backpressure");
        }
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(returned)) => {
                event = returned;
                thread::sleep(WORKER_POLL);
            }
            Err(TrySendError::Disconnected(_)) => {
                if !stop.load(Ordering::Acquire) {
                    set_terminal(
                        terminal,
                        stop,
                        MeshTerminalFailureV0 {
                            remote: facts.remote,
                            direction: facts.direction,
                            reason: "inbound lifecycle owner disappeared".to_owned(),
                        },
                    );
                }
                bail!("inbound lifecycle owner disappeared")
            }
        }
    }
}

fn replace_control(
    controls: &ActiveControlsV0,
    direction: PeerDirectionV0,
    remote: ValidatorId,
    stream: TcpStream,
) -> Result<()> {
    let mut controls = controls
        .lock()
        .map_err(|_| anyhow!("mesh control map mutex poisoned"))?;
    if let Some(previous) = controls.insert((direction, remote), stream) {
        let _ = previous.shutdown(Shutdown::Both);
    }
    Ok(())
}

fn remove_control(controls: &ActiveControlsV0, direction: PeerDirectionV0, remote: ValidatorId) {
    if let Ok(mut controls) = controls.lock() {
        if let Some(stream) = controls.remove(&(direction, remote)) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn shutdown_all(controls: &ActiveControlsV0) {
    if let Ok(mut controls) = controls.lock() {
        for (_, stream) in core::mem::take(&mut *controls) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn set_terminal(
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
    failure: MeshTerminalFailureV0,
) {
    if let Ok(mut slot) = terminal.lock() {
        if slot.is_none() {
            *slot = Some(failure);
        }
    }
    stop.store(true, Ordering::Release);
}

fn cleanup_failed_establish(
    stop: &Arc<AtomicBool>,
    controls: &ActiveControlsV0,
    workers: Vec<JoinHandle<()>>,
    fences: &MeshFenceRegistryV1,
) {
    stop.store(true, Ordering::Release);
    shutdown_all(controls);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = fences.release_all();
}

fn join_children(
    children: BTreeMap<ValidatorId, InboundWorkerV0>,
    controls: &ActiveControlsV0,
    terminal: &Mutex<Option<MeshTerminalFailureV0>>,
    stop: &AtomicBool,
    fences: &MeshFenceRegistryV1,
) {
    // Every terminal accept-loop path must interrupt all blocking socket
    // readers before joining them. Otherwise one unrelated healthy inbound
    // session can keep shutdown blocked forever after a different session
    // fails closed.
    for worker in children.values() {
        worker.cancel.store(true, Ordering::Release);
    }
    shutdown_all(controls);
    for (_, worker) in children {
        if worker.handle.join().is_err() && !stop.load(Ordering::Acquire) {
            set_terminal(
                terminal,
                stop,
                MeshTerminalFailureV0 {
                    remote: worker.facts.remote,
                    direction: PeerDirectionV0::Inbound,
                    reason: "inbound worker panicked".to_owned(),
                },
            );
        }
    }
    let _ = fences.release_all();
}

fn validate_limits(
    setup_timeout: Duration,
    io_timeout: Duration,
    queue_capacity: usize,
) -> Result<()> {
    if !(Duration::from_secs(1)..=Duration::from_secs(330)).contains(&setup_timeout) {
        bail!("mesh setup/reconnect timeout must be between 1 and 330 seconds");
    }
    if !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&io_timeout) {
        bail!("mesh I/O timeout must be between 100 ms and 30 seconds");
    }
    if queue_capacity == 0 || queue_capacity > MAX_QUEUE_CAPACITY {
        bail!("mesh queue capacity is outside its bounded profile");
    }
    Ok(())
}

fn outbound_queue_byte_budget_v0(queue_capacity: usize) -> Result<usize> {
    let capacity_bytes = queue_capacity
        .checked_mul(
            MAX_FRAME_PAYLOAD_BYTES
                .checked_add(QUEUED_FRAME_OVERHEAD_BYTES)
                .ok_or_else(|| anyhow!("mesh maximum frame budget overflow"))?,
        )
        .ok_or_else(|| anyhow!("mesh queue byte budget overflow"))?;
    Ok(capacity_bytes.min(MAX_OUTBOUND_QUEUE_BYTES_PER_PEER))
}

fn outbound_global_queue_byte_budget_v0(queue_capacity: usize, peer_count: usize) -> Result<usize> {
    if peer_count == 0 || peer_count > MAX_DIRECTED_PEERS {
        bail!("mesh global queue budget has an invalid peer count");
    }
    outbound_queue_byte_budget_v0(queue_capacity)?
        .checked_mul(peer_count)
        .map(|bytes| bytes.min(MAX_OUTBOUND_QUEUE_BYTES_GLOBAL))
        .ok_or_else(|| anyhow!("mesh global queue byte budget overflow"))
}

fn inbound_queue_byte_budget_v0(queue_capacity: usize) -> Result<usize> {
    let capacity_bytes = queue_capacity
        .checked_mul(
            MAX_FRAME_PAYLOAD_BYTES
                .checked_add(QUEUED_FRAME_OVERHEAD_BYTES)
                .ok_or_else(|| anyhow!("mesh maximum inbound frame budget overflow"))?,
        )
        .ok_or_else(|| anyhow!("mesh inbound queue byte budget overflow"))?;
    Ok(capacity_bytes.min(MAX_INBOUND_QUEUE_BYTES_PER_PEER))
}

fn inbound_global_queue_byte_budget_v0(queue_capacity: usize, peer_count: usize) -> Result<usize> {
    if peer_count == 0 || peer_count > MAX_DIRECTED_PEERS {
        bail!("mesh global inbound queue budget has an invalid peer count");
    }
    inbound_queue_byte_budget_v0(queue_capacity)?
        .checked_mul(peer_count)
        .map(|bytes| bytes.min(MAX_INBOUND_QUEUE_BYTES_GLOBAL))
        .ok_or_else(|| anyhow!("mesh global inbound queue byte budget overflow"))
}

fn validate_directed_plan(
    local: ValidatorId,
    outgoing: &[PeerConfig],
    incoming: &[PeerConfig],
) -> Result<()> {
    if outgoing.is_empty()
        || outgoing.len() != incoming.len()
        || outgoing.len() > MAX_DIRECTED_PEERS
    {
        bail!("mesh directed degree is empty, asymmetric, or unbounded");
    }
    for (label, peers) in [("outgoing", outgoing), ("incoming", incoming)] {
        let mut identities = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for peer in peers {
            let remote = peer.validator_id()?;
            let endpoint = peer.socket_addr()?;
            if remote == local || !identities.insert(remote) || !endpoints.insert(endpoint) {
                bail!("mesh {label} directed plan is non-canonical");
            }
        }
    }
    let outgoing = peer_map(outgoing)?;
    let incoming = peer_map(incoming)?;
    validate_directed_plan_maps(local, &outgoing, &incoming)
}

fn validate_directed_plan_maps(
    local: ValidatorId,
    outgoing: &BTreeMap<ValidatorId, SocketAddr>,
    incoming: &BTreeMap<ValidatorId, SocketAddr>,
) -> Result<()> {
    if outgoing.is_empty()
        || outgoing.len() != incoming.len()
        || outgoing.len() > MAX_DIRECTED_PEERS
    {
        bail!("mesh directed degree is empty, asymmetric, or unbounded");
    }
    for (label, peers) in [("outgoing", outgoing), ("incoming", incoming)] {
        let mut endpoints = BTreeSet::new();
        for (&remote, &endpoint) in peers {
            if remote == local || !endpoints.insert(endpoint) {
                bail!("mesh {label} directed plan is non-canonical");
            }
        }
    }
    Ok(())
}

fn peer_map(peers: &[PeerConfig]) -> Result<BTreeMap<ValidatorId, SocketAddr>> {
    peers
        .iter()
        .map(|peer| Ok((peer.validator_id()?, peer.socket_addr()?)))
        .collect()
}

fn short_id(validator: ValidatorId) -> String {
    hex::encode(&validator.as_bytes()[..4])
}

struct DeadlineIo {
    stream: TcpStream,
    deadline: Option<Instant>,
}

impl DeadlineIo {
    fn new(stream: TcpStream, deadline: Instant) -> Result<Self> {
        stream.set_nodelay(true).context("set TCP_NODELAY")?;
        Ok(Self {
            stream,
            deadline: Some(deadline),
        })
    }

    fn make_persistent(
        &mut self,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<()> {
        self.stream
            .set_read_timeout(read_timeout)
            .context("set persistent read timeout")?;
        self.stream
            .set_write_timeout(write_timeout)
            .context("set persistent write timeout")?;
        self.deadline = None;
        Ok(())
    }

    fn try_clone(&self) -> Result<TcpStream> {
        self.stream
            .try_clone()
            .context("clone session shutdown handle")
    }

    /// Waits for the first byte of a frame without consuming it.  Keeping the
    /// probe separate from `AuthenticatedConnection::receive` is important:
    /// a read timeout in the middle of a length-prefixed frame poisons that
    /// connection, while an idle timeout must merely wake the worker so it
    /// can renew its external lease.
    fn wait_readable(
        &mut self,
        idle_timeout: Duration,
        frame_timeout: Duration,
    ) -> io::Result<bool> {
        self.stream.set_read_timeout(Some(idle_timeout))?;
        let mut probe = [0u8; 1];
        let readiness = match self.stream.peek(&mut probe) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed the authenticated stream",
            )),
            Ok(_) => Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        };
        self.stream.set_read_timeout(Some(frame_timeout))?;
        readiness
    }

    fn refresh(&self, read: bool) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "authenticated handshake deadline elapsed",
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
                    if self.deadline.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
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
                    if self.deadline.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
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
                    if self.deadline.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;
    use crate::p2p_admission::{ExternalFenceError, TestExternalPeerLeaseAuthorityV1};
    use crate::p2p_host_attestation::{
        HostAttestationRequestV1, HostAttestationTokenV1, RejectingHostAttestationAuthorityV1,
    };

    const TEST_RUN_ID: &str = "poco-g3-7-20260814T000000Z-mesh0001";

    fn authenticated_identity_fixture_v0() -> (MeshIdentityV0, MeshIdentityV0) {
        let client_key = SigningKey::from_bytes(&[0x61; 32]);
        let server_key = SigningKey::from_bytes(&[0x62; 32]);
        let client_consensus_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_consensus_key = SigningKey::from_bytes(&[0x32; 32]);
        let client_operator_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_operator_key = SigningKey::from_bytes(&[0x42; 32]);
        let client = ValidatorId::new([0x71; 32]);
        let server = ValidatorId::new([0x72; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x73; 32]),
            ChainId::new("trnm-poco-g3-mesh-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![
                Validator::new(
                    client,
                    ConsensusPublicKey::new(client_consensus_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    server,
                    ConsensusPublicKey::new(server_consensus_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let key_roles = ValidatorKeyRoleRegistryV1::new(
            &validator_set,
            vec![
                crate::key_roles::ValidatorKeyRoleBindingV1::new(
                    client,
                    client_consensus_key.verifying_key().to_bytes(),
                    client_key.verifying_key().to_bytes(),
                    client_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
                crate::key_roles::ValidatorKeyRoleBindingV1::new(
                    server,
                    server_consensus_key.verifying_key().to_bytes(),
                    server_key.verifying_key().to_bytes(),
                    server_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let context = RunTransportContext::new([0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32]);
        (
            MeshIdentityV0 {
                run_id: TEST_RUN_ID.to_owned(),
                local: client,
                p2p_identity_signer: MeshIdentitySignerV1::Local(client_key),
                validator_set: validator_set.clone(),
                key_roles: key_roles.clone(),
                transport_context: context,
                host_attestation: None,
            },
            MeshIdentityV0 {
                run_id: TEST_RUN_ID.to_owned(),
                local: server,
                p2p_identity_signer: MeshIdentitySignerV1::Local(server_key),
                validator_set,
                key_roles,
                transport_context: context,
                host_attestation: None,
            },
        )
    }

    fn inbound_test_event_v0(
        facts: PeerSessionFactsV0,
        payload: Vec<u8>,
        reservation: InboundQueueReservationV0,
    ) -> MeshIngressEventV0 {
        MeshIngressEventV0::Frame(MeshInboundFrameV0 {
            remote: facts.remote,
            direction: facts.direction,
            session_id: facts.session_id,
            session_generation: facts.generation,
            frame: AuthenticatedFrame {
                sender: facts.remote,
                session: facts.session_id,
                sequence: 0,
                kind: FrameKind::Vote,
                payload,
            },
            _reservation: reservation,
        })
    }

    #[test]
    fn durable_payload_replay_admission_binds_mesh_owner_v1() {
        let (client, server) = authenticated_identity_fixture_v0();
        let local_id: [u8; 32] = server.local.as_bytes().try_into().unwrap();
        let namespace = PayloadReplayNamespaceV1::new(
            local_id,
            server.validator_set.epoch().get(),
            server.validator_set.id().into_bytes(),
            payload_replay_run_id_hash_v1(&server.run_id),
            network_context_digest_v1(
                &server.validator_set,
                &server.key_roles,
                server.transport_context,
            ),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut replay =
            PayloadReplayStoreV1::open(directory.path().join("frames.wal"), namespace).unwrap();
        let facts =
            PeerSessionFactsV0::for_test(client.local, PeerDirectionV0::Inbound, [0x55; 32], 1);
        let first = MeshInboundFrameV0::for_test(
            facts,
            AuthenticatedFrame {
                sender: client.local,
                session: [0x55; 32],
                sequence: 0,
                kind: FrameKind::Vote,
                payload: b"durable-vote".to_vec(),
            },
        );
        let receipt = first
            .admit_payload_replay_v1(&mut replay, &server.run_id)
            .unwrap();
        assert_eq!(receipt.record_index(), 1);
        assert_eq!(replay.accepted_frame_count(), 1);
        assert!(matches!(
            first.admit_payload_replay_v1(&mut replay, &server.run_id),
            Err(PayloadReplayErrorV1::Replay)
        ));
        let second = MeshInboundFrameV0::for_test(
            facts,
            AuthenticatedFrame {
                sender: client.local,
                session: [0x55; 32],
                sequence: 1,
                kind: FrameKind::Vote,
                payload: b"durable-vote-next".to_vec(),
            },
        );
        second
            .admit_payload_replay_v1(&mut replay, &server.run_id)
            .unwrap();
        assert_eq!(replay.accepted_frame_count(), 2);
    }

    struct NoopExternalIdentityProducerV1 {
        public_key: [u8; 32],
    }

    impl P2pIdentitySignatureProducerV1 for NoopExternalIdentityProducerV1 {
        fn public_key_v1(&self) -> [u8; 32] {
            self.public_key
        }

        fn sign_v1(
            &mut self,
            _request: P2pIdentitySignatureRequestV1,
        ) -> Result<[u8; 64], P2pIdentityErrorV1> {
            Err(P2pIdentityErrorV1::Unavailable)
        }
    }

    struct FailOnceReleaseAuthorityV1 {
        inner: Arc<TestExternalPeerLeaseAuthorityV1>,
        fail_next_release: AtomicBool,
        release_calls: AtomicUsize,
    }

    impl FailOnceReleaseAuthorityV1 {
        fn new(inner: Arc<TestExternalPeerLeaseAuthorityV1>) -> Self {
            Self {
                inner,
                fail_next_release: AtomicBool::new(true),
                release_calls: AtomicUsize::new(0),
            }
        }

        fn release_calls(&self) -> usize {
            self.release_calls.load(Ordering::Acquire)
        }
    }

    impl ExternalPeerLeaseAuthorityV1 for FailOnceReleaseAuthorityV1 {
        fn preflight(&self) -> Result<(), ExternalFenceError> {
            self.inner.preflight()
        }

        fn acquire(
            &self,
            request: ExternalPeerLeaseRequestV1,
        ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
            self.inner.acquire(request)
        }

        fn renew(
            &self,
            token: ExternalPeerLeaseTokenV1,
        ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
            self.inner.renew(token)
        }

        fn revalidate(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
            self.inner.revalidate(token)
        }

        fn release(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
            self.release_calls.fetch_add(1, Ordering::AcqRel);
            if self
                .fail_next_release
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(ExternalFenceError::Unavailable);
            }
            self.inner.release(token)
        }
    }

    struct FailOnceHostReleaseAuthorityV1 {
        fail_next_release: AtomicBool,
        admit_calls: AtomicUsize,
        revalidate_calls: AtomicUsize,
        release_calls: AtomicUsize,
    }

    impl FailOnceHostReleaseAuthorityV1 {
        fn new() -> Self {
            Self {
                fail_next_release: AtomicBool::new(true),
                admit_calls: AtomicUsize::new(0),
                revalidate_calls: AtomicUsize::new(0),
                release_calls: AtomicUsize::new(0),
            }
        }

        fn admit_calls(&self) -> usize {
            self.admit_calls.load(Ordering::Acquire)
        }

        fn revalidate_calls(&self) -> usize {
            self.revalidate_calls.load(Ordering::Acquire)
        }

        fn release_calls(&self) -> usize {
            self.release_calls.load(Ordering::Acquire)
        }
    }

    impl HostAttestationAuthorityV1 for FailOnceHostReleaseAuthorityV1 {
        fn preflight_v1(&self) -> Result<(), HostAttestationErrorV1> {
            Ok(())
        }

        fn admit_v1(
            &self,
            request: HostAttestationRequestV1,
        ) -> Result<HostAttestationTokenV1, HostAttestationErrorV1> {
            self.admit_calls.fetch_add(1, Ordering::AcqRel);
            HostAttestationTokenV1::new(request.binding(), request.material(), 1)
        }

        fn revalidate_v1(
            &self,
            _token: HostAttestationTokenV1,
        ) -> Result<(), HostAttestationErrorV1> {
            self.revalidate_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn release_v1(&self, _token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1> {
            self.release_calls.fetch_add(1, Ordering::AcqRel);
            if self
                .fail_next_release
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                Err(HostAttestationErrorV1::AuthorityUnavailable)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn external_identity_without_host_attestation_fails_before_listener() {
        let (mut identity, _) = authenticated_identity_fixture_v0();
        let public_key = match &identity.p2p_identity_signer {
            MeshIdentitySignerV1::Local(key) => key.verifying_key().to_bytes(),
            MeshIdentitySignerV1::External(_) => unreachable!("fixture starts in local mode"),
        };
        identity.p2p_identity_signer =
            MeshIdentitySignerV1::External(SharedP2pIdentityProducerV1::new(Box::new(
                NoopExternalIdentityProducerV1 { public_key },
            )));
        let authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(
            PeerAdmissionContextV1::new(0, [0x99; 32]).unwrap(),
        ));

        let result = PersistentAuthenticatedPeerMeshV0::establish_identity_with_fence_ttl_v1(
            identity,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            BTreeMap::new(),
            BTreeMap::new(),
            Duration::from_secs(1),
            Duration::from_millis(100),
            1,
            MESH_EXTERNAL_FENCE_TTL_V1,
            authority,
        );
        let error = result
            .err()
            .expect("external identity must be rejected without host attestation");
        assert!(error.to_string().contains("HostAttestationRequired"));
    }

    #[test]
    fn host_attestation_preflight_failure_does_not_bind_listener() {
        let (mut identity, server_identity) = authenticated_identity_fixture_v0();
        let public_key = match &identity.p2p_identity_signer {
            MeshIdentitySignerV1::Local(key) => key.verifying_key().to_bytes(),
            MeshIdentitySignerV1::External(_) => unreachable!("fixture starts in local mode"),
        };
        identity.p2p_identity_signer =
            MeshIdentitySignerV1::External(SharedP2pIdentityProducerV1::new(Box::new(
                NoopExternalIdentityProducerV1 { public_key },
            )));
        identity.host_attestation = Some(MeshHostAttestationConfigV1 {
            authority: Arc::new(RejectingHostAttestationAuthorityV1),
            material: HostAttestationMaterialV1::from_bytes(vec![0x91, 0x92]).unwrap(),
        });
        let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("allocate listener address");
        let listen_addr = occupied.local_addr().unwrap();
        drop(occupied);
        let authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(
            PeerAdmissionContextV1::new(0, [0x9a; 32]).unwrap(),
        ));

        let result = PersistentAuthenticatedPeerMeshV0::establish_identity_with_fence_ttl_v1(
            identity,
            listen_addr,
            BTreeMap::from([(
                server_identity.local,
                SocketAddr::from(([127, 0, 0, 1], 41_001)),
            )]),
            BTreeMap::from([(
                server_identity.local,
                SocketAddr::from(([127, 0, 0, 1], 41_002)),
            )]),
            Duration::from_secs(1),
            Duration::from_millis(100),
            1,
            MESH_EXTERNAL_FENCE_TTL_V1,
            authority,
        );
        let error = result
            .err()
            .expect("rejecting host authority must stop commissioning");
        assert!(error.to_string().contains("host attestation"));

        // The failed authority gate occurs before TcpListener::bind; the
        // address must remain available to a subsequent owner.
        let rebound = TcpListener::bind(listen_addr).expect("failed gate leaked listener bind");
        drop(rebound);
    }

    #[test]
    fn mesh_limits_and_frame_kinds_are_bounded() {
        assert!(validate_limits(Duration::from_secs(1), Duration::from_millis(100), 1).is_ok());
        assert!(validate_limits(
            Duration::from_secs(330),
            Duration::from_secs(30),
            MAX_QUEUE_CAPACITY
        )
        .is_ok());
        assert!(validate_limits(Duration::from_secs(331), Duration::from_secs(1), 1).is_err());
        assert!(validate_limits(Duration::from_millis(999), Duration::from_secs(1), 1).is_err());
        assert!(validate_limits(Duration::from_secs(1), Duration::from_millis(99), 1).is_err());
        assert!(validate_limits(Duration::from_secs(1), Duration::from_secs(1), 0).is_err());
        assert!(is_consensus_kind(FrameKind::Proposal));
        assert!(is_consensus_kind(FrameKind::ConsensusRelay));
        assert!(is_consensus_kind(FrameKind::FleetReady));
        assert!(is_consensus_kind(FrameKind::FleetStart));
        assert!(is_consensus_kind(FrameKind::RestartPrepare));
        assert!(is_consensus_kind(FrameKind::RestartCut));
        assert!(is_consensus_kind(FrameKind::RestartParkedAck));
        assert!(is_consensus_kind(FrameKind::RestartRecoveryReady));
        assert!(is_consensus_kind(FrameKind::RestartRecoveryStart));
        assert!(is_consensus_kind(FrameKind::RestartCatchup));
        assert!(!is_consensus_kind(FrameKind::Health));
        assert!(!is_consensus_kind(FrameKind::SubmitBatch));
        assert_eq!(
            outbound_queue_byte_budget_v0(1).unwrap(),
            MAX_FRAME_PAYLOAD_BYTES + QUEUED_FRAME_OVERHEAD_BYTES
        );
        assert_eq!(
            outbound_queue_byte_budget_v0(MAX_QUEUE_CAPACITY).unwrap(),
            MAX_OUTBOUND_QUEUE_BYTES_PER_PEER
        );
        assert_eq!(
            outbound_global_queue_byte_budget_v0(MAX_QUEUE_CAPACITY, 8).unwrap(),
            MAX_OUTBOUND_QUEUE_BYTES_GLOBAL
        );
        assert_eq!(
            inbound_queue_byte_budget_v0(1).unwrap(),
            MAX_FRAME_PAYLOAD_BYTES + QUEUED_FRAME_OVERHEAD_BYTES
        );
        assert_eq!(
            inbound_queue_byte_budget_v0(MAX_QUEUE_CAPACITY).unwrap(),
            MAX_INBOUND_QUEUE_BYTES_PER_PEER
        );
        assert_eq!(
            inbound_global_queue_byte_budget_v0(MAX_QUEUE_CAPACITY, 8).unwrap(),
            MAX_INBOUND_QUEUE_BYTES_GLOBAL
        );
        assert!(outbound_global_queue_byte_budget_v0(1, 0).is_err());
        assert!(outbound_global_queue_byte_budget_v0(1, MAX_DIRECTED_PEERS + 1).is_err());
        assert!(inbound_global_queue_byte_budget_v0(1, 0).is_err());
        assert!(inbound_global_queue_byte_budget_v0(1, MAX_DIRECTED_PEERS + 1).is_err());
    }

    #[test]
    fn outbound_byte_reservations_release_exactly_once_v0() {
        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(10));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(10));
        let reservation =
            OutboundQueueReservationV0::try_new(&peer_budget, &global_budget, 6).unwrap();
        let message = OutboundMessageV0 {
            kind: FrameKind::Vote,
            payload: Arc::from([1u8, 2, 3]),
            _reservation: reservation,
        };
        assert!(OutboundQueueReservationV0::try_new(&peer_budget, &global_budget, 5).is_none());
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 6);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 6);
        drop(message);
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
        assert!(OutboundQueueReservationV0::try_new(&peer_budget, &global_budget, 10).is_some());

        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(10));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(5));
        assert!(OutboundQueueReservationV0::try_new(&peer_budget, &global_budget, 6).is_none());
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn inbound_global_and_remote_stable_reservations_release_exactly_once_v0() {
        let remote = ValidatorId::new([0x31; 32]);
        let other = ValidatorId::new([0x32; 32]);
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(10));
        let mut remote_budgets = BTreeMap::new();
        remote_budgets.insert(remote, Arc::new(MeshQueueByteBudgetV0::new(6)));
        remote_budgets.insert(other, Arc::new(MeshQueueByteBudgetV0::new(10)));

        let generation_one_budget = Arc::clone(remote_budgets.get(&remote).unwrap());
        let generation_two_budget = Arc::clone(remote_budgets.get(&remote).unwrap());
        let generation_one =
            InboundQueueReservationV0::try_new(&generation_one_budget, &global_budget, 6).unwrap();
        assert!(
            InboundQueueReservationV0::try_new(&generation_two_budget, &global_budget, 1).is_none()
        );
        let other_reservation = InboundQueueReservationV0::try_new(
            remote_budgets.get(&other).unwrap(),
            &global_budget,
            4,
        )
        .unwrap();
        assert!(InboundQueueReservationV0::try_new(
            remote_budgets.get(&other).unwrap(),
            &global_budget,
            1
        )
        .is_none());
        assert_eq!(generation_one_budget.used_bytes.load(Ordering::Acquire), 6);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 10);

        drop(generation_one);
        assert_eq!(generation_one_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 4);
        drop(other_reservation);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
        assert!(
            InboundQueueReservationV0::try_new(&generation_two_budget, &global_budget, 6).is_some()
        );
    }

    #[test]
    fn inbound_byte_cap_precedes_count_cap_and_releases_after_consumption_v0() {
        let facts = PeerSessionFactsV0 {
            remote: ValidatorId::new([0x33; 32]),
            direction: PeerDirectionV0::Inbound,
            session_id: [0x34; 32],
            generation: 1,
        };
        let reserved_bytes = QUEUED_FRAME_OVERHEAD_BYTES + 1;
        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes));
        let first_reservation =
            InboundQueueReservationV0::try_new(&peer_budget, &global_budget, reserved_bytes)
                .unwrap();
        let (sender, receiver) = mpsc::sync_channel(2);
        sender
            .try_send(inbound_test_event_v0(facts, vec![1], first_reservation))
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn({
            let peer_budget = Arc::clone(&peer_budget);
            let global_budget = Arc::clone(&global_budget);
            let stop = Arc::clone(&stop);
            let cancel = Arc::clone(&cancel);
            move || {
                let reservation = reserve_inbound_frame_until_available_v0(
                    &peer_budget,
                    &global_budget,
                    reserved_bytes,
                    &stop,
                    &cancel,
                );
                done_tx.send(reservation).unwrap();
            }
        });
        thread::sleep(WORKER_POLL + WORKER_POLL);
        assert!(matches!(done_rx.try_recv(), Err(TryRecvError::Empty)));

        let first = receiver.recv().unwrap();
        assert!(matches!(done_rx.try_recv(), Err(TryRecvError::Empty)));
        drop(first);
        let second = done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            peer_budget.used_bytes.load(Ordering::Acquire),
            reserved_bytes
        );
        assert_eq!(
            global_budget.used_bytes.load(Ordering::Acquire),
            reserved_bytes
        );
        drop(second);
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
        worker.join().unwrap();
    }

    #[test]
    fn inbound_queue_full_cancel_and_disconnection_release_reservations_v0() {
        let facts = PeerSessionFactsV0 {
            remote: ValidatorId::new([0x35; 32]),
            direction: PeerDirectionV0::Inbound,
            session_id: [0x36; 32],
            generation: 1,
        };
        let reserved_bytes = QUEUED_FRAME_OVERHEAD_BYTES + 1;
        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes * 2));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes * 2));
        let first =
            InboundQueueReservationV0::try_new(&peer_budget, &global_budget, reserved_bytes)
                .unwrap();
        let second =
            InboundQueueReservationV0::try_new(&peer_budget, &global_budget, reserved_bytes)
                .unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(inbound_test_event_v0(facts, vec![1], first))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            let terminal = Arc::clone(&terminal);
            move || {
                done_tx
                    .send(emit_event(
                        &sender,
                        inbound_test_event_v0(facts, vec![2], second),
                        &terminal,
                        &stop,
                        facts,
                        None,
                    ))
                    .unwrap();
            }
        });
        thread::sleep(WORKER_POLL + WORKER_POLL);
        assert!(matches!(done_rx.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            global_budget.used_bytes.load(Ordering::Acquire),
            reserved_bytes * 2
        );
        stop.store(true, Ordering::Release);
        assert!(done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_err());
        assert_eq!(
            global_budget.used_bytes.load(Ordering::Acquire),
            reserved_bytes
        );
        drop(receiver.recv().unwrap());
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
        worker.join().unwrap();

        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(reserved_bytes));
        let reservation =
            InboundQueueReservationV0::try_new(&peer_budget, &global_budget, reserved_bytes)
                .unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let stop = AtomicBool::new(false);
        let terminal = Mutex::new(None);
        assert!(emit_event(
            &sender,
            inbound_test_event_v0(facts, vec![3], reservation),
            &terminal,
            &stop,
            facts,
            None,
        )
        .is_err());
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn lifecycle_events_do_not_consume_inbound_frame_byte_budget_v0() {
        let facts = PeerSessionFactsV0 {
            remote: ValidatorId::new([0x37; 32]),
            direction: PeerDirectionV0::Inbound,
            session_id: [0x38; 32],
            generation: 2,
        };
        let peer_budget = Arc::new(MeshQueueByteBudgetV0::new(1));
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(1));
        let occupied = InboundQueueReservationV0::try_new(&peer_budget, &global_budget, 1).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        let stop = AtomicBool::new(false);
        let terminal = Mutex::new(None);
        emit_event(
            &sender,
            MeshIngressEventV0::SessionUnavailable(facts),
            &terminal,
            &stop,
            facts,
            None,
        )
        .unwrap();
        assert!(matches!(
            receiver.recv().unwrap(),
            MeshIngressEventV0::SessionUnavailable(observed) if observed == facts
        ));
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 1);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 1);
        drop(occupied);
        assert_eq!(peer_budget.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global_budget.used_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn one_backpressured_peer_does_not_fail_stop_or_skip_other_peers() {
        let first = ValidatorId::new([1; 32]);
        let second = ValidatorId::new([2; 32]);
        let (first_tx, first_rx) = mpsc::sync_channel(1);
        let (second_tx, second_rx) = mpsc::sync_channel(1);
        let mut outbound = BTreeMap::new();
        let global_budget = Arc::new(MeshQueueByteBudgetV0::new(2_048));
        for (remote, sender) in [(first, first_tx), (second, second_tx)] {
            outbound.insert(
                remote,
                OutboundQueueV0 {
                    sender,
                    peer_budget: Arc::new(MeshQueueByteBudgetV0::new(1_024)),
                    global_budget: Arc::clone(&global_budget),
                },
            );
        }
        let (_ingress_tx, ingress) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let fence_authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(
            PeerAdmissionContextV1::new(0, [0x99; 32]).unwrap(),
        ));
        let fences = MeshFenceRegistryV1::new(
            fence_authority,
            ValidatorId::new([3; 32]),
            PeerAdmissionContextV1::new(0, [0x99; 32]).unwrap(),
            MESH_EXTERNAL_FENCE_TTL_V1,
        )
        .unwrap();
        fences
            .acquire(PeerDirectionV0::Outbound, first, [0x11; 32], 1)
            .unwrap();
        fences
            .acquire(PeerDirectionV0::Outbound, second, [0x12; 32], 1)
            .unwrap();
        let mut mesh = PersistentAuthenticatedPeerMeshV0 {
            local: ValidatorId::new([3; 32]),
            outbound,
            ingress,
            stop: Arc::clone(&stop),
            terminal: Arc::clone(&terminal),
            controls: Arc::new(Mutex::new(BTreeMap::new())),
            fences,
            workers: Vec::new(),
            initial_sessions: Vec::new(),
            closed: false,
        };

        assert_eq!(
            mesh.send_to(first, FrameKind::Vote, vec![1]).unwrap(),
            MeshSendDispositionV0::Queued
        );
        let outcome = mesh.broadcast(FrameKind::Vote, &[2]).unwrap();
        assert_eq!(outcome.queued_peers(), 1);
        assert_eq!(outcome.backpressured_peers(), &[first]);
        assert!(!outcome.fully_queued());
        assert!(!stop.load(Ordering::Acquire));
        assert!(terminal.lock().unwrap().is_none());
        mesh.ensure_healthy().unwrap();

        drop(first_rx.recv().unwrap());
        drop(second_rx.recv().unwrap());
        assert_eq!(
            mesh.send_to(first, FrameKind::Vote, vec![3]).unwrap(),
            MeshSendDispositionV0::Queued
        );
        mesh.close_inner().unwrap();
    }

    #[test]
    fn rejecting_external_fence_blocks_admission_before_any_worker_token_v0() {
        let context = PeerAdmissionContextV1::new(0, [0x51; 32]).unwrap();
        let fences = MeshFenceRegistryV1::new(
            Arc::new(RejectingExternalPeerLeaseAuthorityV1),
            ValidatorId::new([0x52; 32]),
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
        )
        .unwrap();
        let result = fences.acquire(
            PeerDirectionV0::Outbound,
            ValidatorId::new([0x53; 32]),
            [0x54; 32],
            1,
        );
        assert!(result.is_err());
        assert_eq!(fences.active_count().unwrap(), 0);
    }

    #[test]
    fn failed_external_release_retains_token_for_retry_v1() {
        let remote = ValidatorId::new([0x55; 32]);
        let local = ValidatorId::new([0x56; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x57; 32]).unwrap();
        let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let authority_impl = Arc::new(FailOnceReleaseAuthorityV1::new(Arc::clone(&backing)));
        let authority: Arc<dyn ExternalPeerLeaseAuthorityV1> = authority_impl.clone();
        let fences =
            MeshFenceRegistryV1::new(authority, local, context, MESH_EXTERNAL_FENCE_TTL_V1)
                .unwrap();
        let token = fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x58; 32], 1)
            .unwrap();

        let error = fences
            .release(PeerDirectionV0::Outbound, remote)
            .unwrap_err();
        assert!(error.to_string().contains("external fence release"));
        assert_eq!(authority_impl.release_calls(), 1);
        assert_eq!(fences.active_count().unwrap(), 1);
        // The failed call did not clear the authority-side lease, so the
        // retained token must remain usable for a retry.
        backing.revalidate(token).unwrap();

        fences.release(PeerDirectionV0::Outbound, remote).unwrap();
        assert_eq!(authority_impl.release_calls(), 2);
        assert_eq!(fences.active_count().unwrap(), 0);
        assert!(matches!(
            backing.revalidate(token),
            Err(ExternalFenceError::LeaseNotFound)
        ));
    }

    #[test]
    fn host_release_failure_keeps_confirmed_peer_token_for_host_retry_v1() {
        let remote = ValidatorId::new([0x59; 32]);
        let local = ValidatorId::new([0x5a; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x5b; 32]).unwrap();
        let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let host_authority = Arc::new(FailOnceHostReleaseAuthorityV1::new());
        let host_registry = HostAttestationSessionRegistryV1::new(
            host_authority.clone(),
            local,
            [0x5c; 32],
            [0x5d; 32],
            0,
            context.validator_set_id(),
            [0x5e; 32],
            [0x5f; 32],
            HostAttestationMaterialV1::from_bytes(vec![0x60]).unwrap(),
        )
        .unwrap();
        let fences = MeshFenceRegistryV1::new_with_host_attestation(
            backing.clone(),
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
            Some(host_registry.clone()),
        )
        .unwrap();
        let session = [0x61; 32];
        let generation = 1;
        let token = fences
            .acquire(PeerDirectionV0::Outbound, remote, session, generation)
            .unwrap();

        let error = fences
            .release(PeerDirectionV0::Outbound, remote)
            .unwrap_err();
        assert!(error.to_string().contains("host attestation release"));
        assert_eq!(host_authority.release_calls(), 1);
        assert_eq!(fences.active_count().unwrap(), 1);
        // The peer lease is already gone, but the host receipt remains and
        // must keep this edge occupied until its own authority succeeds.
        assert!(matches!(
            backing.revalidate(token),
            Err(ExternalFenceError::LeaseNotFound)
        ));
        assert!(host_registry
            .admission(
                ExternalPeerDirectionV1::Outbound,
                remote,
                session,
                generation,
            )
            .is_ok());
        assert!(fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x62; 32], 2)
            .is_err());

        fences.release(PeerDirectionV0::Outbound, remote).unwrap();
        assert_eq!(host_authority.release_calls(), 2);
        assert_eq!(fences.active_count().unwrap(), 0);
        assert!(matches!(
            host_registry.admission(
                ExternalPeerDirectionV1::Outbound,
                remote,
                session,
                generation,
            ),
            Err(HostAttestationErrorV1::LeaseNotFound)
        ));
    }

    #[test]
    fn invalid_peer_scope_is_rejected_before_host_attestation_admit_v1() {
        let remote = ValidatorId::new([0x63; 32]);
        let local = ValidatorId::new([0x64; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x65; 32]).unwrap();
        let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let host_authority = Arc::new(FailOnceHostReleaseAuthorityV1::new());
        let host_registry = HostAttestationSessionRegistryV1::new(
            host_authority.clone(),
            local,
            [0x66; 32],
            [0x67; 32],
            0,
            context.validator_set_id(),
            [0x68; 32],
            [0x69; 32],
            HostAttestationMaterialV1::from_bytes(vec![0x6a]).unwrap(),
        )
        .unwrap();
        let fences = MeshFenceRegistryV1::new_with_host_attestation(
            backing,
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
            Some(host_registry),
        )
        .unwrap();

        let error = fences
            .acquire(PeerDirectionV0::Outbound, remote, [0; 32], 1)
            .unwrap_err();
        assert!(error.to_string().contains("external fence scope rejected"));
        assert_eq!(host_authority.admit_calls(), 0);
        assert_eq!(fences.active_count().unwrap(), 0);
    }

    #[test]
    fn failed_peer_admission_retains_host_receipt_for_owner_cleanup_v1() {
        let remote = ValidatorId::new([0x6b; 32]);
        let local = ValidatorId::new([0x6c; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x6d; 32]).unwrap();
        let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let host_authority = Arc::new(FailOnceHostReleaseAuthorityV1::new());
        let host_registry = HostAttestationSessionRegistryV1::new(
            host_authority.clone(),
            local,
            [0x6e; 32],
            [0x6f; 32],
            0,
            context.validator_set_id(),
            [0x70; 32],
            [0x71; 32],
            HostAttestationMaterialV1::from_bytes(vec![0x72]).unwrap(),
        )
        .unwrap();
        let fences = MeshFenceRegistryV1::new_with_host_attestation(
            backing,
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
            Some(host_registry.clone()),
        )
        .unwrap();

        // The host authority admitted generation two, but the peer authority
        // rejects it as stale.  The first exact host compensation fails; the
        // mesh must retain that receipt even though no peer token was stored.
        assert!(fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x73; 32], 2)
            .is_err());
        assert_eq!(fences.active_count().unwrap(), 0);
        assert!(host_registry
            .admission(ExternalPeerDirectionV1::Outbound, remote, [0x73; 32], 2,)
            .is_ok());

        // release_all must include host-only pending keys; a peer-token-only
        // walk would permanently strand the receipt and block the edge.
        fences.release_all().unwrap();
        assert_eq!(host_authority.release_calls(), 2);
        assert!(matches!(
            host_registry.admission(ExternalPeerDirectionV1::Outbound, remote, [0x73; 32], 2,),
            Err(HostAttestationErrorV1::LeaseNotFound)
        ));
    }

    #[test]
    fn stale_external_fence_blocks_send_without_emitting_a_frame_v0() {
        let remote = ValidatorId::new([0x61; 32]);
        let local = ValidatorId::new([0x62; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x63; 32]).unwrap();
        let authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let fences = MeshFenceRegistryV1::new(
            authority.clone(),
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
        )
        .unwrap();
        fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x64; 32], 1)
            .unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut outbound = BTreeMap::new();
        let budget = Arc::new(MeshQueueByteBudgetV0::new(1_024));
        let global = Arc::new(MeshQueueByteBudgetV0::new(1_024));
        outbound.insert(
            remote,
            OutboundQueueV0 {
                sender,
                peer_budget: budget,
                global_budget: global,
            },
        );
        let (_ingress_tx, ingress) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let mesh = PersistentAuthenticatedPeerMeshV0 {
            local,
            outbound,
            ingress,
            stop,
            terminal,
            controls: Arc::new(Mutex::new(BTreeMap::new())),
            fences,
            workers: Vec::new(),
            initial_sessions: Vec::new(),
            closed: false,
        };
        authority.advance_clock_millis(31_000);
        let error = mesh.send_to(remote, FrameKind::Vote, vec![1]).unwrap_err();
        assert!(error.to_string().contains("external fence revalidation"));
        // `send_to` fails before queue reservation; no consensus frame can be
        // observed by a worker after lease expiry.
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        drop(mesh);
    }

    #[test]
    fn lease_renewal_error_fails_closed_before_frame_admission_v1() {
        let remote = ValidatorId::new([0x67; 32]);
        let local = ValidatorId::new([0x68; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x69; 32]).unwrap();
        let authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let fences =
            MeshFenceRegistryV1::new(authority.clone(), local, context, Duration::from_secs(1))
                .unwrap();
        fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x6a; 32], 1)
            .unwrap();
        // Force the authority-side lease to expire before the local renewal
        // cadence.  The next frame-path check must attempt renew and fail;
        // it may not silently fall back to a cached token.
        thread::sleep(Duration::from_millis(350));
        authority.advance_clock_millis(2_000);
        let error = fences
            .revalidate(PeerDirectionV0::Outbound, remote)
            .unwrap_err();
        assert!(error.to_string().contains("renewal"));
    }

    #[test]
    fn host_attestation_is_checked_only_on_due_peer_renewal_v1() {
        let remote = ValidatorId::new([0x74; 32]);
        let local = ValidatorId::new([0x75; 32]);
        let context = PeerAdmissionContextV1::new(0, [0x76; 32]).unwrap();
        let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let host_authority = Arc::new(FailOnceHostReleaseAuthorityV1::new());
        host_authority
            .fail_next_release
            .store(false, Ordering::Release);
        let host_registry = HostAttestationSessionRegistryV1::new(
            host_authority.clone(),
            local,
            [0x77; 32],
            [0x78; 32],
            0,
            context.validator_set_id(),
            [0x79; 32],
            [0x7a; 32],
            HostAttestationMaterialV1::from_bytes(vec![0x7b]).unwrap(),
        )
        .unwrap();
        let fences = MeshFenceRegistryV1::new_with_host_attestation(
            backing,
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
            Some(host_registry),
        )
        .unwrap();
        fences
            .acquire(PeerDirectionV0::Outbound, remote, [0x7c; 32], 1)
            .unwrap();

        for _ in 0..3 {
            assert!(matches!(
                fences.renew_if_due_inner(PeerDirectionV0::Outbound, remote),
                Ok(MeshFenceRenewalOutcomeV1::NotDue)
            ));
        }
        assert_eq!(host_authority.revalidate_calls(), 0);
        fences
            .tokens
            .lock()
            .unwrap()
            .get_mut(&(PeerDirectionV0::Outbound, remote))
            .unwrap()
            .next_renew_at = Instant::now();
        assert!(matches!(
            fences.renew_if_due_inner(PeerDirectionV0::Outbound, remote),
            Ok(MeshFenceRenewalOutcomeV1::Renewed)
        ));
        assert_eq!(host_authority.revalidate_calls(), 1);
        fences.release(PeerDirectionV0::Outbound, remote).unwrap();
    }

    #[test]
    fn only_explicit_transport_loss_is_recoverable() {
        assert!(transient_frame_error(&FrameError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        ))));
        assert!(!transient_frame_error(&FrameError::Replay));
        assert!(!transient_frame_error(&FrameError::InvalidSignature));
        assert!(!transient_frame_error(&FrameError::Malformed("bad")));
        assert!(transient_connect_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(transient_connect_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        )));
        assert!(transient_connect_error(&io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted"
        )));
        assert!(!transient_connect_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied"
        )));
        assert!(matches!(
            classify_incoming_auth_failure_v0(FrameError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "timeout"
            ))),
            IncomingAuthFailureV0::Transient
        ));
        assert!(matches!(
            classify_incoming_auth_failure_v0(FrameError::InvalidSignature),
            IncomingAuthFailureV0::Terminal(reason) if reason.contains("signature")
        ));
        assert!(matches!(
            classify_incoming_auth_failure_v0(FrameError::Replay),
            IncomingAuthFailureV0::Terminal(reason) if reason.contains("replayed")
        ));
    }

    #[test]
    fn bounded_ingress_backpressure_waits_without_fail_stopping_v0() {
        let facts = PeerSessionFactsV0 {
            remote: ValidatorId::new([0x41; 32]),
            direction: PeerDirectionV0::Inbound,
            session_id: [0x42; 32],
            generation: 1,
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(MeshIngressEventV0::SessionUnavailable(facts))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            let terminal = Arc::clone(&terminal);
            move || {
                let result = emit_event(
                    &sender,
                    MeshIngressEventV0::SessionReestablished(facts),
                    &terminal,
                    &stop,
                    facts,
                    None,
                );
                done_tx.send(result).unwrap();
            }
        });
        thread::sleep(WORKER_POLL + WORKER_POLL);
        assert!(matches!(done_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(!stop.load(Ordering::Acquire));
        assert!(terminal.lock().unwrap().is_none());
        assert!(matches!(
            receiver.recv().unwrap(),
            MeshIngressEventV0::SessionUnavailable(_)
        ));
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(matches!(
            receiver.recv().unwrap(),
            MeshIngressEventV0::SessionReestablished(_)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn disconnect_reconnect_uses_a_fresh_authenticated_session_v0() {
        let (client, server) = authenticated_identity_fixture_v0();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(client.local, "127.0.0.1:1".parse().unwrap());
        let server_thread = thread::spawn(move || {
            let mut sessions = Vec::new();
            for _ in 0..2 {
                let (stream, source) = listener.accept().unwrap();
                let connection = authenticate_incoming(
                    stream,
                    source,
                    &expected,
                    &server,
                    Instant::now() + Duration::from_secs(2),
                    Duration::from_secs(1),
                )
                .unwrap();
                sessions.push(connection.session_id());
            }
            sessions
        });
        let mut client_sessions = Vec::new();
        for _ in 0..2 {
            let stream = TcpStream::connect(address).unwrap();
            let io = DeadlineIo::new(stream, Instant::now() + Duration::from_secs(2)).unwrap();
            let connection = AuthenticatedConnection::connect(
                io,
                &client.run_id,
                client.local,
                server_thread_remote_v0(&client.validator_set, client.local),
                match &client.p2p_identity_signer {
                    MeshIdentitySignerV1::Local(signing_key) => signing_key,
                    MeshIdentitySignerV1::External(_) => unreachable!("fixture uses local key"),
                },
                &client.validator_set,
                &client.key_roles,
                client.transport_context,
            )
            .unwrap();
            client_sessions.push(connection.session_id());
        }
        let server_sessions = server_thread.join().unwrap();
        assert_eq!(client_sessions, server_sessions);
        assert_ne!(client_sessions[0], client_sessions[1]);
    }

    #[test]
    fn preflight_rss_counts_both_queue_budgets_and_distinct_double_buffers_v0() {
        let peer_degree = 6usize;
        let host = MeshHostCapacityV0::new(24, 24_781_164_544, 1_024).unwrap();
        let queue_one = preflight_mesh_host_resources_v0(7, peer_degree, 1, 1, host).unwrap();
        let queue_two = preflight_mesh_host_resources_v0(7, peer_degree, 1, 2, host).unwrap();

        let threads = peer_degree.checked_mul(2).unwrap().checked_add(1).unwrap();
        let stack_bytes = u64::try_from(threads)
            .unwrap()
            .checked_mul(MESH_WORKER_STACK_BYTES as u64)
            .unwrap();
        let per_direction_scratch = u64::try_from(peer_degree)
            .unwrap()
            .checked_mul(
                u64::try_from(MAX_FRAME_BODY_BYTES)
                    .unwrap()
                    .checked_add(u64::try_from(MAX_FRAME_PAYLOAD_BYTES).unwrap())
                    .unwrap(),
            )
            .unwrap();
        let expected_queue_one = MESH_BASE_PROCESS_RSS_BYTES
            .checked_add(
                u64::try_from(outbound_global_queue_byte_budget_v0(1, peer_degree).unwrap())
                    .unwrap(),
            )
            .unwrap()
            .checked_add(
                u64::try_from(inbound_global_queue_byte_budget_v0(1, peer_degree).unwrap())
                    .unwrap(),
            )
            .unwrap()
            .checked_add(stack_bytes)
            .unwrap()
            .checked_add(per_direction_scratch)
            .unwrap()
            .checked_add(per_direction_scratch)
            .unwrap();
        assert_eq!(queue_one.per_validator_rss_bytes(), expected_queue_one);

        let outbound_growth = outbound_global_queue_byte_budget_v0(2, peer_degree)
            .unwrap()
            .checked_sub(outbound_global_queue_byte_budget_v0(1, peer_degree).unwrap())
            .unwrap();
        let inbound_growth = inbound_global_queue_byte_budget_v0(2, peer_degree)
            .unwrap()
            .checked_sub(inbound_global_queue_byte_budget_v0(1, peer_degree).unwrap())
            .unwrap();
        assert_eq!(
            queue_two
                .per_validator_rss_bytes()
                .checked_sub(queue_one.per_validator_rss_bytes())
                .unwrap(),
            u64::try_from(outbound_growth.checked_add(inbound_growth).unwrap()).unwrap()
        );
    }

    #[test]
    fn g3_31_and_100_host_placements_pass_bounded_resource_preflight_v0() {
        let host_profiles = [
            (24, 24_781_164_544, 5usize, 20usize),
            (4, 8_012_709_888, 2, 3),
            (48, 134_923_124_736, 10, 36),
            (32, 130_456_432_640, 13, 38),
            (4, 4_008_587_264, 1, 3),
        ];
        for (cpu, memory, validators_31, validators_100) in host_profiles {
            let capacity = MeshHostCapacityV0::new(cpu, memory, 1_024).unwrap();
            preflight_mesh_host_resources_v0(31, 8, validators_31, MAX_QUEUE_CAPACITY, capacity)
                .unwrap();
            preflight_mesh_host_resources_v0(100, 8, validators_100, MAX_QUEUE_CAPACITY, capacity)
                .unwrap();
        }
        let rog = preflight_mesh_host_resources_v0(
            100,
            8,
            38,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(32, 130_456_432_640, 1_024)
                .unwrap()
                .with_system_open_file_available(6_156)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rog.per_validator_threads(), 17);
        assert_eq!(rog.per_validator_socket_fds(), 34);
        assert_eq!(rog.per_validator_open_file_fds(), 162);
        assert_eq!(rog.host_threads(), 646);
        assert_eq!(rog.host_open_file_fds(), 6_156);

        assert!(preflight_mesh_host_resources_v0(
            100,
            8,
            38,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(1, 130_456_432_640, 1_048_576).unwrap(),
        )
        .is_err());
        assert!(preflight_mesh_host_resources_v0(
            100,
            8,
            38,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(32, 1_073_741_824, 1_048_576).unwrap(),
        )
        .is_err());
        assert!(preflight_mesh_host_resources_v0(
            100,
            8,
            38,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(32, 130_456_432_640, 161).unwrap(),
        )
        .is_err());
        assert!(preflight_mesh_host_resources_v0(
            100,
            8,
            38,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(32, 130_456_432_640, 1_024)
                .unwrap()
                .with_system_open_file_available(6_155)
                .unwrap(),
        )
        .is_err());
        assert!(preflight_mesh_host_resources_v0(
            31,
            6,
            1,
            MAX_QUEUE_CAPACITY,
            MeshHostCapacityV0::new(4, 8_012_709_888, 1_048_576).unwrap(),
        )
        .is_err());
    }

    fn server_thread_remote_v0(set: &ValidatorSet, local: ValidatorId) -> ValidatorId {
        set.validators()
            .iter()
            .map(Validator::id)
            .find(|validator| *validator != local)
            .expect("two-validator mesh fixture has a remote")
    }
}
