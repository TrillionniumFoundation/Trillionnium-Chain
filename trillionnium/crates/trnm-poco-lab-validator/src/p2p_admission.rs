//! D0 authenticated peer-admission helper.
//!
//! This module is the smallest active boundary around the already-authenticated
//! transport handshake.  It adds an explicit epoch/validator-set binding,
//! process-local session replay protection, and a bounded peer lease with
//! generation fencing.  The helper deliberately stops at admission: it does
//! not send consensus frames, drive a validator loop, persist consensus
//! safety state, attest a host, or release a signer capability.
//!
//! The lease authority is intentionally process-local.  A restart, machine
//! clone, or database rollback can therefore invalidate its memory; production
//! use still needs an external append-only lease/fencing authority and host
//! attestation.  Keeping that boundary explicit is part of the D0 truth
//! contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Read, Write},
    sync::Mutex,
    time::{Duration, Instant},
};

use sha2::Digest;
use trnm_consensus_types::{ValidatorId, ValidatorSet};

#[cfg(unix)]
use trnm_consensus_peer_lease::{
    ExternalPeerLeaseAuthorityV1 as UnixPeerLeaseAuthorityV1, LeaseRejectCodeV1,
    PeerLeaseDirectionV1, PeerLeaseScopeV1, PeerLeaseTokenV1 as UnixPeerLeaseTokenV1,
    UnixPeerLeaseClientV1,
};

use crate::transport::AuthenticatedConnection;

pub const P2P_ADMISSION_PROFILE_V1: &str = "active-p2p-admission-helper-v1";
pub const P2P_ADMISSION_HELPER_ACTIVE_V1: bool = true;
pub const P2P_ADMISSION_CONSENSUS_TRANSPORT_V1: bool = false;
pub const P2P_ADMISSION_VALIDATOR_RUNTIME_V1: bool = false;
pub const P2P_ADMISSION_PRODUCTION_ACTIVATION_V1: bool = false;
pub const P2P_ADMISSION_HOST_ATTESTATION_V1: bool = false;
/// The external fencing seam is deliberately present, but no production
/// authority is selected by this laboratory crate.  A caller must inject an
/// implementation that stores the CAS/append-only record outside the node
/// before any consensus worker can be commissioned.
pub const P2P_ADMISSION_EXTERNAL_FENCING_AUTHORITY_V1: bool = false;
pub const P2P_ADMISSION_EXTERNAL_FENCING_HARD_GATE_V1: bool = true;

/// Direction is part of the external CAS scope.  A node pair may legitimately
/// own one inbound and one outbound directed session; those leases must never
/// alias in an authority shared by both hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalPeerDirectionV1 {
    Inbound,
    Outbound,
}

const MAX_LEASE_PEERS: usize = 1_024;
const MAX_SESSION_REPLAY_ENTRIES: usize = 4_096;
const MAX_LEASE_GENERATION: u64 = 1_000_000;
const MIN_LEASE_TTL: Duration = Duration::from_secs(1);
const MAX_LEASE_TTL: Duration = Duration::from_secs(120);

/// Exact context that a peer lease is allowed to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerAdmissionContextV1 {
    epoch: u64,
    validator_set_id: [u8; 32],
}

impl PeerAdmissionContextV1 {
    pub fn from_validator_set(validator_set: &ValidatorSet) -> Self {
        Self {
            epoch: validator_set.epoch().get(),
            validator_set_id: validator_set.id().into_bytes(),
        }
    }

    pub fn new(epoch: u64, validator_set_id: [u8; 32]) -> Result<Self, AdmissionError> {
        if validator_set_id == [0; 32] {
            return Err(AdmissionError::InvalidContext);
        }
        Ok(Self {
            epoch,
            validator_set_id,
        })
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }
}

/// A lease token is the only process-local authority returned by this helper.
/// It is not a consensus credential and cannot be serialized into a consensus
/// message without a separately reviewed protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLeaseTokenV1 {
    peer: ValidatorId,
    context: PeerAdmissionContextV1,
    session_id: [u8; 32],
    generation: u64,
}

impl PeerLeaseTokenV1 {
    pub const fn peer(self) -> ValidatorId {
        self.peer
    }

    pub const fn context(self) -> PeerAdmissionContextV1 {
        self.context
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseEntry {
    token: PeerLeaseTokenV1,
    expires_at: Instant,
}

/// Fail-closed admission errors.  The variants intentionally distinguish a
/// stale lease from a replay so callers cannot silently rebind an old session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidContext,
    InvalidPeer,
    InvalidSession,
    ContextMismatch,
    ConnectionContextMissing,
    RemoteMismatch,
    SessionReplay,
    NonceReplay,
    SessionWindowFull,
    NonceWindowFull,
    PeerAlreadyLeased,
    PeerCapacity,
    LeaseNotFound,
    LeaseExpired,
    LeaseFenced,
    GenerationExhausted,
    InvalidLeaseTtl,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidContext => "admission context is invalid",
            Self::InvalidPeer => "peer identity is invalid",
            Self::InvalidSession => "session identifier is invalid",
            Self::ContextMismatch => "peer lease context differs from authority context",
            Self::ConnectionContextMissing => "connection lacks explicit epoch/set binding",
            Self::RemoteMismatch => "authenticated remote differs from expected peer",
            Self::SessionReplay => "authenticated session was already admitted",
            Self::NonceReplay => "handshake nonce binding was already admitted",
            Self::SessionWindowFull => "session replay window is exhausted",
            Self::NonceWindowFull => "handshake nonce replay window is exhausted",
            Self::PeerAlreadyLeased => "peer already has a live lease",
            Self::PeerCapacity => "peer lease capacity is exhausted",
            Self::LeaseNotFound => "peer lease is not present",
            Self::LeaseExpired => "peer lease expired",
            Self::LeaseFenced => "peer lease was fenced by a newer generation",
            Self::GenerationExhausted => "peer lease generation exhausted",
            Self::InvalidLeaseTtl => "lease TTL is outside its bounded profile",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AdmissionError {}

/// The exact identity tuple fenced by an external authority.  Every field is
/// part of the CAS key; a token for one socket/session/epoch cannot be used by
/// another worker, validator, or validator-set incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExternalPeerLeaseScopeV1 {
    local: ValidatorId,
    remote: ValidatorId,
    direction: ExternalPeerDirectionV1,
    context: PeerAdmissionContextV1,
    session_id: [u8; 32],
    generation: u64,
}

impl ExternalPeerLeaseScopeV1 {
    pub fn new(
        local: ValidatorId,
        remote: ValidatorId,
        direction: ExternalPeerDirectionV1,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<Self, ExternalFenceError> {
        if local.is_zero() || remote.is_zero() || local == remote {
            return Err(ExternalFenceError::InvalidScope);
        }
        if session_id == [0; 32] || generation == 0 {
            return Err(ExternalFenceError::InvalidScope);
        }
        Ok(Self {
            local,
            remote,
            direction,
            context,
            session_id,
            generation,
        })
    }

    pub const fn local(self) -> ValidatorId {
        self.local
    }

    pub const fn remote(self) -> ValidatorId {
        self.remote
    }

    pub const fn direction(self) -> ExternalPeerDirectionV1 {
        self.direction
    }

    pub const fn context(self) -> PeerAdmissionContextV1 {
        self.context
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Acquire request passed to the external fencing service.  The service owns
/// the clock and must return an expiry in its own monotonic domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPeerLeaseRequestV1 {
    scope: ExternalPeerLeaseScopeV1,
    ttl_millis: u64,
}

impl ExternalPeerLeaseRequestV1 {
    pub fn new(scope: ExternalPeerLeaseScopeV1, ttl: Duration) -> Result<Self, ExternalFenceError> {
        let ttl_millis =
            u64::try_from(ttl.as_millis()).map_err(|_| ExternalFenceError::InvalidRequest)?;
        if !(1_000..=120_000).contains(&ttl_millis) {
            return Err(ExternalFenceError::InvalidRequest);
        }
        Ok(Self { scope, ttl_millis })
    }

    pub const fn scope(self) -> ExternalPeerLeaseScopeV1 {
        self.scope
    }

    pub const fn ttl_millis(self) -> u64 {
        self.ttl_millis
    }
}

/// Opaque grant returned by an external fencing authority.  The scope and
/// expiry are copied into the value solely so the mesh can fail closed before
/// making an authority call; the `opaque` field is what the authority must
/// authenticate.  Callers cannot manufacture a valid grant for the test
/// authority because every operation rechecks the authority-side CAS record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExternalPeerLeaseTokenV1 {
    scope: ExternalPeerLeaseScopeV1,
    expires_at_millis: u64,
    opaque: [u8; 32],
}

impl fmt::Debug for ExternalPeerLeaseTokenV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalPeerLeaseTokenV1")
            .field("scope", &self.scope)
            .field("expires_at_millis", &self.expires_at_millis)
            .field("opaque", &"<redacted>")
            .finish()
    }
}

impl ExternalPeerLeaseTokenV1 {
    /// Constructor for an authority implementation.  The opaque value must
    /// be non-zero and is never interpreted by the mesh.
    pub fn from_authority_parts(
        scope: ExternalPeerLeaseScopeV1,
        expires_at_millis: u64,
        opaque: [u8; 32],
    ) -> Result<Self, ExternalFenceError> {
        if expires_at_millis == 0 || opaque == [0; 32] {
            return Err(ExternalFenceError::InvalidGrant);
        }
        Ok(Self {
            scope,
            expires_at_millis,
            opaque,
        })
    }

    pub const fn scope(self) -> ExternalPeerLeaseScopeV1 {
        self.scope
    }

    pub const fn expires_at_millis(self) -> u64 {
        self.expires_at_millis
    }

    pub const fn opaque(self) -> [u8; 32] {
        self.opaque
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalFenceError {
    InvalidScope,
    InvalidRequest,
    InvalidGrant,
    Unavailable,
    ContextMismatch,
    LeaseConflict,
    StaleGeneration,
    TokenMismatch,
    LeaseNotFound,
    LeaseExpired,
}

impl fmt::Display for ExternalFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidScope => "external fence scope is invalid",
            Self::InvalidRequest => "external fence request is invalid",
            Self::InvalidGrant => "external fence grant is invalid",
            Self::Unavailable => "external fencing authority is unavailable",
            Self::ContextMismatch => "external fence epoch/set context mismatch",
            Self::LeaseConflict => "external fence lease conflicts with a live generation",
            Self::StaleGeneration => "external fence generation is stale",
            Self::TokenMismatch => "external fence token does not match its CAS record",
            Self::LeaseNotFound => "external fence lease is not present",
            Self::LeaseExpired => "external fence lease expired",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExternalFenceError {}

/// Injectable external fencing authority.  Implementations must make each
/// operation a durable compare-and-swap against an append-only or equivalent
/// non-rollbackable record.  The mesh treats every error as fail-stop.
pub trait ExternalPeerLeaseAuthorityV1: Send + Sync {
    /// Cheap fail-closed availability probe executed before sockets, workers,
    /// commissioning, or signer authority are created.  Implementations
    /// should verify that their durable backend is reachable and append-only.
    fn preflight(&self) -> Result<(), ExternalFenceError> {
        Ok(())
    }

    fn acquire(
        &self,
        request: ExternalPeerLeaseRequestV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError>;

    fn renew(
        &self,
        token: ExternalPeerLeaseTokenV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError>;

    fn revalidate(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError>;

    fn release(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError>;
}

/// Adapter from the durable cross-process Unix authority to the lab mesh's
/// authority seam.  It is intentionally injectable and is not selected by
/// any default runtime constructor; callers must opt in explicitly after
/// provisioning the daemon socket and journal.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct UnixExternalPeerLeaseAuthorityV1 {
    client: UnixPeerLeaseClientV1,
}

#[cfg(unix)]
impl UnixExternalPeerLeaseAuthorityV1 {
    pub fn connect(path: impl AsRef<std::path::Path>) -> Self {
        Self::from_client(UnixPeerLeaseClientV1::connect(path))
    }

    /// Wraps an explicitly constructed client so candidate callers can make
    /// transport deadlines visible at the authority-composition site.
    pub fn from_client(client: UnixPeerLeaseClientV1) -> Self {
        Self { client }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }

    pub fn socket_path(&self) -> &std::path::Path {
        self.client.socket_path()
    }
}

#[cfg(unix)]
impl ExternalPeerLeaseAuthorityV1 for UnixExternalPeerLeaseAuthorityV1 {
    fn preflight(&self) -> Result<(), ExternalFenceError> {
        self.client.preflight().map_err(map_unix_lease_error)
    }

    fn acquire(
        &self,
        request: ExternalPeerLeaseRequestV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        let local_scope = request.scope();
        let wire_scope = wire_scope(local_scope)?;
        let token = UnixPeerLeaseAuthorityV1::acquire(
            &self.client,
            wire_scope,
            local_scope.session_id(),
            local_scope.generation(),
            request.ttl_millis(),
        )
        .map_err(map_unix_lease_error)?;
        local_token(local_scope, token)
    }

    fn renew(
        &self,
        token: ExternalPeerLeaseTokenV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        let local_scope = token.scope();
        let wire = wire_token(token)?;
        // The mesh seam carries no TTL on its renew call. Keep one bounded,
        // explicit profile instead of accepting an unbounded caller value.
        let renewed = UnixPeerLeaseAuthorityV1::renew(&self.client, wire, 30_000)
            .map_err(map_unix_lease_error)?;
        local_token(local_scope, renewed)
    }

    fn revalidate(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        let wire = wire_token(token)?;
        let returned = UnixPeerLeaseAuthorityV1::revalidate(&self.client, wire)
            .map_err(map_unix_lease_error)?;
        if returned != wire {
            return Err(ExternalFenceError::TokenMismatch);
        }
        Ok(())
    }

    fn release(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        let wire = wire_token(token)?;
        UnixPeerLeaseAuthorityV1::release(&self.client, wire).map_err(map_unix_lease_error)
    }
}

#[cfg(unix)]
fn validator_id32(id: ValidatorId) -> Result<[u8; 32], ExternalFenceError> {
    let bytes = id.as_bytes();
    if bytes.len() != 32 {
        return Err(ExternalFenceError::InvalidScope);
    }
    let mut output = [0; 32];
    output.copy_from_slice(bytes);
    Ok(output)
}

#[cfg(unix)]
fn wire_scope(scope: ExternalPeerLeaseScopeV1) -> Result<PeerLeaseScopeV1, ExternalFenceError> {
    let direction = match scope.direction() {
        ExternalPeerDirectionV1::Inbound => PeerLeaseDirectionV1::Inbound,
        ExternalPeerDirectionV1::Outbound => PeerLeaseDirectionV1::Outbound,
    };
    PeerLeaseScopeV1::new(
        validator_id32(scope.local())?,
        validator_id32(scope.remote())?,
        direction,
        scope.context().epoch(),
        scope.context().validator_set_id(),
    )
    .map_err(|_| ExternalFenceError::InvalidScope)
}

#[cfg(unix)]
fn wire_token(token: ExternalPeerLeaseTokenV1) -> Result<UnixPeerLeaseTokenV1, ExternalFenceError> {
    let scope = token.scope();
    let wire_scope = wire_scope(scope)?;
    UnixPeerLeaseTokenV1::from_parts(
        wire_scope,
        scope.session_id(),
        scope.generation(),
        token.expires_at_millis(),
        token.opaque(),
    )
    .map_err(|_| ExternalFenceError::InvalidGrant)
}

#[cfg(unix)]
fn local_token(
    scope: ExternalPeerLeaseScopeV1,
    token: UnixPeerLeaseTokenV1,
) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
    let expected = wire_scope(scope)?;
    if token.scope() != expected
        || token.session_id() != scope.session_id()
        || token.generation() != scope.generation()
    {
        return Err(ExternalFenceError::TokenMismatch);
    }
    ExternalPeerLeaseTokenV1::from_authority_parts(
        scope,
        token.expires_at_ms(),
        token.record_hash(),
    )
    .map_err(|_| ExternalFenceError::InvalidGrant)
}

#[cfg(unix)]
fn map_unix_lease_error(error: trnm_consensus_peer_lease::PeerLeaseErrorV1) -> ExternalFenceError {
    match error {
        trnm_consensus_peer_lease::PeerLeaseErrorV1::InvalidRequest(_) => {
            ExternalFenceError::InvalidRequest
        }
        trnm_consensus_peer_lease::PeerLeaseErrorV1::Rejected(code) => match code {
            LeaseRejectCodeV1::AlreadyLeased => ExternalFenceError::LeaseConflict,
            LeaseRejectCodeV1::StaleGeneration => ExternalFenceError::StaleGeneration,
            LeaseRejectCodeV1::LeaseNotFound => ExternalFenceError::LeaseNotFound,
            LeaseRejectCodeV1::LeaseExpired => ExternalFenceError::LeaseExpired,
            LeaseRejectCodeV1::Fenced => ExternalFenceError::TokenMismatch,
            LeaseRejectCodeV1::ContextMismatch => ExternalFenceError::ContextMismatch,
            LeaseRejectCodeV1::InvalidRequest => ExternalFenceError::InvalidRequest,
            LeaseRejectCodeV1::AuthorityUnavailable
            | LeaseRejectCodeV1::ClockRollback
            | LeaseRejectCodeV1::AuthorityCorrupt
            | LeaseRejectCodeV1::Unsupported
            | LeaseRejectCodeV1::UnauthorizedPeer => ExternalFenceError::Unavailable,
        },
        trnm_consensus_peer_lease::PeerLeaseErrorV1::Io(_)
        | trnm_consensus_peer_lease::PeerLeaseErrorV1::Protocol(_) => {
            ExternalFenceError::Unavailable
        }
    }
}

/// A deliberately unavailable authority used by the normal bounded runtime.
/// This prevents accidental commissioning until an operator injects a real
/// external fence implementation.  It is not a production authority.
#[derive(Debug, Default)]
pub struct RejectingExternalPeerLeaseAuthorityV1;

impl ExternalPeerLeaseAuthorityV1 for RejectingExternalPeerLeaseAuthorityV1 {
    fn preflight(&self) -> Result<(), ExternalFenceError> {
        Err(ExternalFenceError::Unavailable)
    }

    fn acquire(
        &self,
        _request: ExternalPeerLeaseRequestV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        Err(ExternalFenceError::Unavailable)
    }

    fn renew(
        &self,
        _token: ExternalPeerLeaseTokenV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        Err(ExternalFenceError::Unavailable)
    }

    fn revalidate(&self, _token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        Err(ExternalFenceError::Unavailable)
    }

    fn release(&self, _token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        Err(ExternalFenceError::Unavailable)
    }
}

/// Process-local deterministic authority used only by unit/loopback tests.
/// The `advance_clock_millis` method simulates expiry and restart without
/// claiming durable anti-rollback semantics.
#[derive(Debug)]
pub struct TestExternalPeerLeaseAuthorityV1 {
    context: PeerAdmissionContextV1,
    now_millis: std::sync::atomic::AtomicU64,
    state: Mutex<TestExternalFenceStateV1>,
}

#[derive(Debug, Default)]
struct TestExternalFenceStateV1 {
    next_generation: BTreeMap<(ValidatorId, ValidatorId, ExternalPeerDirectionV1), u64>,
    leases: BTreeMap<
        (ValidatorId, ValidatorId, ExternalPeerDirectionV1),
        (ExternalPeerLeaseTokenV1, u64),
    >,
}

impl TestExternalPeerLeaseAuthorityV1 {
    pub fn new(context: PeerAdmissionContextV1) -> Self {
        Self {
            context,
            now_millis: std::sync::atomic::AtomicU64::new(1),
            state: Mutex::new(TestExternalFenceStateV1::default()),
        }
    }

    pub fn advance_clock_millis(&self, millis: u64) {
        self.now_millis
            .fetch_add(millis, std::sync::atomic::Ordering::AcqRel);
    }

    fn now(&self) -> u64 {
        self.now_millis.load(std::sync::atomic::Ordering::Acquire)
    }

    fn key(scope: ExternalPeerLeaseScopeV1) -> (ValidatorId, ValidatorId, ExternalPeerDirectionV1) {
        (scope.local(), scope.remote(), scope.direction())
    }

    fn grant(
        &self,
        scope: ExternalPeerLeaseScopeV1,
        expires_at_millis: u64,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        let mut bytes = Vec::with_capacity(8 + 32 * 4);
        bytes.extend_from_slice(&scope.generation().to_be_bytes());
        bytes.extend_from_slice(scope.local().as_bytes());
        bytes.extend_from_slice(scope.remote().as_bytes());
        bytes.push(match scope.direction() {
            ExternalPeerDirectionV1::Inbound => 0,
            ExternalPeerDirectionV1::Outbound => 1,
        });
        bytes.extend_from_slice(&scope.session_id());
        bytes.extend_from_slice(&scope.context().epoch().to_be_bytes());
        bytes.extend_from_slice(&scope.context().validator_set_id());
        bytes.extend_from_slice(&expires_at_millis.to_be_bytes());
        let digest = sha2::Sha256::digest(bytes);
        let mut opaque = [0; 32];
        opaque.copy_from_slice(&digest);
        ExternalPeerLeaseTokenV1::from_authority_parts(scope, expires_at_millis, opaque)
    }
}

impl ExternalPeerLeaseAuthorityV1 for TestExternalPeerLeaseAuthorityV1 {
    fn preflight(&self) -> Result<(), ExternalFenceError> {
        Ok(())
    }

    fn acquire(
        &self,
        request: ExternalPeerLeaseRequestV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        if request.scope().context() != self.context {
            return Err(ExternalFenceError::ContextMismatch);
        }
        let now = self.now();
        let key = Self::key(request.scope());
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFenceError::Unavailable)?;
        if let Some((existing, _)) = state.leases.get(&key).copied() {
            if existing.expires_at_millis() > now {
                return Err(ExternalFenceError::LeaseConflict);
            }
            state.leases.remove(&key);
        }
        let expected = state
            .next_generation
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ExternalFenceError::StaleGeneration)?;
        if request.scope().generation() != expected {
            return Err(ExternalFenceError::StaleGeneration);
        }
        let expires = now
            .checked_add(request.ttl_millis())
            .ok_or(ExternalFenceError::InvalidRequest)?;
        let token = self.grant(request.scope(), expires)?;
        state.next_generation.insert(key, expected);
        state.leases.insert(key, (token, request.ttl_millis()));
        Ok(token)
    }

    fn renew(
        &self,
        token: ExternalPeerLeaseTokenV1,
    ) -> Result<ExternalPeerLeaseTokenV1, ExternalFenceError> {
        if token.scope().context() != self.context {
            return Err(ExternalFenceError::ContextMismatch);
        }
        let now = self.now();
        let key = Self::key(token.scope());
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFenceError::Unavailable)?;
        let (current, ttl_millis) = state
            .leases
            .get(&key)
            .copied()
            .ok_or(ExternalFenceError::LeaseNotFound)?;
        if current != token {
            return Err(ExternalFenceError::TokenMismatch);
        }
        if current.expires_at_millis() <= now {
            state.leases.remove(&key);
            return Err(ExternalFenceError::LeaseExpired);
        }
        let renewed = self.grant(token.scope(), now.saturating_add(ttl_millis.max(1_000)))?;
        state.leases.insert(key, (renewed, ttl_millis));
        Ok(renewed)
    }

    fn revalidate(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        if token.scope().context() != self.context {
            return Err(ExternalFenceError::ContextMismatch);
        }
        let now = self.now();
        let key = Self::key(token.scope());
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFenceError::Unavailable)?;
        let (current, _) = state
            .leases
            .get(&key)
            .copied()
            .ok_or(ExternalFenceError::LeaseNotFound)?;
        if current != token {
            return Err(ExternalFenceError::TokenMismatch);
        }
        if current.expires_at_millis() <= now {
            state.leases.remove(&key);
            return Err(ExternalFenceError::LeaseExpired);
        }
        Ok(())
    }

    fn release(&self, token: ExternalPeerLeaseTokenV1) -> Result<(), ExternalFenceError> {
        let key = Self::key(token.scope());
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFenceError::Unavailable)?;
        let (current, _) = state
            .leases
            .get(&key)
            .copied()
            .ok_or(ExternalFenceError::LeaseNotFound)?;
        if current != token {
            return Err(ExternalFenceError::TokenMismatch);
        }
        state.leases.remove(&key);
        Ok(())
    }
}

/// A bounded process-local peer lease/fencing authority.
///
/// Only one generation may be live for a peer.  Reconnect after an expiry gets
/// a strictly higher generation; stale release/renew operations fail closed.
/// Session IDs remain in a bounded non-evicting replay set so an old signed
/// handshake cannot be re-admitted during this process lifetime.
#[derive(Debug)]
pub struct PeerLeaseAuthorityV1 {
    context: PeerAdmissionContextV1,
    max_peers: usize,
    max_session_entries: usize,
    ttl: Duration,
    leases: BTreeMap<ValidatorId, LeaseEntry>,
    next_generation: BTreeMap<ValidatorId, u64>,
    admitted_sessions: BTreeSet<(ValidatorId, [u8; 32])>,
    admitted_nonce_bindings: BTreeSet<(ValidatorId, [u8; 32])>,
}

impl PeerLeaseAuthorityV1 {
    pub fn new(
        context: PeerAdmissionContextV1,
        max_peers: usize,
        ttl: Duration,
    ) -> Result<Self, AdmissionError> {
        if max_peers == 0 || max_peers > MAX_LEASE_PEERS {
            return Err(AdmissionError::PeerCapacity);
        }
        if !(MIN_LEASE_TTL..=MAX_LEASE_TTL).contains(&ttl) {
            return Err(AdmissionError::InvalidLeaseTtl);
        }
        Ok(Self {
            context,
            max_peers,
            max_session_entries: MAX_SESSION_REPLAY_ENTRIES.min(max_peers.saturating_mul(8)),
            ttl,
            leases: BTreeMap::new(),
            next_generation: BTreeMap::new(),
            admitted_sessions: BTreeSet::new(),
            admitted_nonce_bindings: BTreeSet::new(),
        })
    }

    pub const fn context(&self) -> PeerAdmissionContextV1 {
        self.context
    }

    pub fn active_peer_count(&self) -> usize {
        self.leases.len()
    }

    pub fn admitted_session_count(&self) -> usize {
        self.admitted_sessions.len()
    }

    /// Admit a completed, authenticated session and issue its first lease.
    pub fn admit(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        self.admit_with_nonce_binding(peer, context, session_id, session_id, now)
    }

    /// Test/tooling boundary for a completed handshake when the caller has
    /// retained the exact challenge/hello nonce binding.  The live
    /// `admit_authenticated_connection` path obtains this value directly from
    /// `AuthenticatedConnection`.
    pub fn admit_with_nonce_binding(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        nonce_binding: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        self.admit_inner_with_nonce(peer, context, session_id, nonce_binding, now)
    }

    /// The active helper entry point around the signed transport handshake.
    /// No consensus payload is sent or accepted here.
    pub fn admit_authenticated_connection<T: Read + Write>(
        &mut self,
        connection: &AuthenticatedConnection<T>,
        expected_peer: ValidatorId,
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        if connection.remote() != expected_peer {
            return Err(AdmissionError::RemoteMismatch);
        }
        let (epoch, validator_set_id) = connection
            .validator_set_binding()
            .ok_or(AdmissionError::ConnectionContextMissing)?;
        let context = PeerAdmissionContextV1::new(epoch, validator_set_id)?;
        self.admit_inner_with_nonce(
            expected_peer,
            context,
            connection.session_id(),
            connection.handshake_nonce_binding(),
            now,
        )
    }

    fn admit_inner_with_nonce(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        nonce_binding: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        if peer.is_zero() {
            return Err(AdmissionError::InvalidPeer);
        }
        if session_id == [0; 32] {
            return Err(AdmissionError::InvalidSession);
        }
        if nonce_binding == [0; 32] {
            return Err(AdmissionError::InvalidSession);
        }
        if context != self.context {
            return Err(AdmissionError::ContextMismatch);
        }
        self.cleanup(now);
        if self.admitted_sessions.contains(&(peer, session_id)) {
            return Err(AdmissionError::SessionReplay);
        }
        if self
            .admitted_nonce_bindings
            .contains(&(peer, nonce_binding))
        {
            return Err(AdmissionError::NonceReplay);
        }
        if self.leases.contains_key(&peer) {
            return Err(AdmissionError::PeerAlreadyLeased);
        }
        if self.admitted_sessions.len() >= self.max_session_entries {
            return Err(AdmissionError::SessionWindowFull);
        }
        if self.admitted_nonce_bindings.len() >= self.max_session_entries {
            return Err(AdmissionError::NonceWindowFull);
        }
        if self.leases.len() >= self.max_peers {
            return Err(AdmissionError::PeerCapacity);
        }
        let generation = self
            .next_generation
            .get(&peer)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        if generation > MAX_LEASE_GENERATION {
            return Err(AdmissionError::GenerationExhausted);
        }
        let token = PeerLeaseTokenV1 {
            peer,
            context,
            session_id,
            generation,
        };
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or(AdmissionError::GenerationExhausted)?;
        self.next_generation.insert(peer, generation);
        self.admitted_sessions.insert((peer, session_id));
        self.admitted_nonce_bindings.insert((peer, nonce_binding));
        self.leases.insert(peer, LeaseEntry { token, expires_at });
        Ok(token)
    }

    pub fn renew(
        &mut self,
        token: PeerLeaseTokenV1,
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        let entry = self
            .leases
            .get_mut(&token.peer)
            .ok_or(AdmissionError::LeaseNotFound)?;
        if entry.token != token {
            return Err(AdmissionError::LeaseFenced);
        }
        if now >= entry.expires_at {
            self.leases.remove(&token.peer);
            return Err(AdmissionError::LeaseExpired);
        }
        entry.expires_at = now
            .checked_add(self.ttl)
            .ok_or(AdmissionError::GenerationExhausted)?;
        Ok(entry.token)
    }

    pub fn release(&mut self, token: PeerLeaseTokenV1) -> Result<(), AdmissionError> {
        let entry = self
            .leases
            .get(&token.peer)
            .ok_or(AdmissionError::LeaseNotFound)?;
        if entry.token != token {
            return Err(AdmissionError::LeaseFenced);
        }
        self.leases.remove(&token.peer);
        Ok(())
    }

    pub fn is_current(&self, token: PeerLeaseTokenV1, now: Instant) -> bool {
        self.leases
            .get(&token.peer)
            .is_some_and(|entry| entry.token == token && now < entry.expires_at)
    }

    /// Removes expired leases and returns the number of removed entries.
    pub fn cleanup(&mut self, now: Instant) -> usize {
        let before = self.leases.len();
        self.leases.retain(|_, entry| now < entry.expires_at);
        before - self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;
    use crate::{
        key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1},
        transport::{AuthenticatedConnection, RunTransportContext},
    };

    fn context() -> PeerAdmissionContextV1 {
        let consensus_key = SigningKey::from_bytes(&[0x31; 32]);
        let validator = Validator::new(
            ValidatorId::new([0x71; 32]),
            ConsensusPublicKey::new(consensus_key.verifying_key().to_bytes()),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x73; 32]),
            ChainId::new("trnm-poco-g3-admission-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(4),
            parameters.hash(),
            vec![validator],
        )
        .unwrap();
        PeerAdmissionContextV1::from_validator_set(&set)
    }

    fn transport_fixture() -> (
        SigningKey,
        SigningKey,
        ValidatorId,
        ValidatorId,
        ValidatorSet,
        ValidatorKeyRoleRegistryV1,
        PeerAdmissionContextV1,
        RunTransportContext,
    ) {
        let client_key = SigningKey::from_bytes(&[0x61; 32]);
        let server_key = SigningKey::from_bytes(&[0x62; 32]);
        let client_consensus_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_consensus_key = SigningKey::from_bytes(&[0x32; 32]);
        let client_operator_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_operator_key = SigningKey::from_bytes(&[0x42; 32]);
        let client = ValidatorId::new([0x71; 32]);
        let server = ValidatorId::new([0x72; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x73; 32]),
            ChainId::new("trnm-poco-g3-admission-transport-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(7),
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
            &set,
            vec![
                ValidatorKeyRoleBindingV1::new(
                    client,
                    client_consensus_key.verifying_key().to_bytes(),
                    client_key.verifying_key().to_bytes(),
                    client_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
                ValidatorKeyRoleBindingV1::new(
                    server,
                    server_consensus_key.verifying_key().to_bytes(),
                    server_key.verifying_key().to_bytes(),
                    server_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let admission_context = PeerAdmissionContextV1::from_validator_set(&set);
        let transport_context =
            RunTransportContext::new([0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32])
                .with_validator_set_binding(set.epoch().get(), set.id().into_bytes());
        (
            client_key,
            server_key,
            client,
            server,
            set,
            key_roles,
            admission_context,
            transport_context,
        )
    }

    #[test]
    fn lease_fences_replay_and_rebinds_after_bounded_cleanup() {
        let context = context();
        let mut authority = PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
        let peer = ValidatorId::new([0x72; 32]);
        let first_session = [0x81; 32];
        let second_session = [0x82; 32];
        let now = Instant::now();
        let first = authority.admit(peer, context, first_session, now).unwrap();
        assert!(authority.is_current(first, now + Duration::from_secs(1)));
        assert_eq!(
            authority.admit(peer, context, second_session, now),
            Err(AdmissionError::PeerAlreadyLeased)
        );
        let stale = PeerLeaseTokenV1 {
            generation: first.generation().saturating_sub(1),
            ..first
        };
        assert_eq!(authority.release(stale), Err(AdmissionError::LeaseFenced));
        assert_eq!(
            authority.admit(peer, context, first_session, now + Duration::from_secs(1)),
            Err(AdmissionError::SessionReplay)
        );
        let expired = now + Duration::from_secs(6);
        assert_eq!(authority.cleanup(expired), 1);
        let rebound = authority
            .admit(peer, context, second_session, expired)
            .unwrap();
        assert_eq!(rebound.generation(), first.generation() + 1);
        assert!(!authority.is_current(first, expired));
        assert!(authority.is_current(rebound, expired));
        assert_eq!(
            authority.admit(peer, context, first_session, expired),
            Err(AdmissionError::SessionReplay)
        );

        let mut nonce_authority =
            PeerLeaseAuthorityV1::new(context, 1, Duration::from_secs(5)).unwrap();
        let nonce = [0x91; 32];
        let nonce_first = nonce_authority
            .admit_with_nonce_binding(peer, context, [0x92; 32], nonce, expired)
            .unwrap();
        nonce_authority.release(nonce_first).unwrap();
        assert_eq!(
            nonce_authority.admit_with_nonce_binding(peer, context, [0x93; 32], nonce, expired,),
            Err(AdmissionError::NonceReplay)
        );
    }

    #[test]
    fn context_requires_nonzero_set_and_exact_epoch() {
        assert_eq!(
            PeerAdmissionContextV1::new(0, [0; 32]),
            Err(AdmissionError::InvalidContext)
        );
        let context = context();
        let wrong =
            PeerAdmissionContextV1::new(context.epoch() + 1, context.validator_set_id()).unwrap();
        let peer = ValidatorId::new([0x72; 32]);
        let mut authority = PeerLeaseAuthorityV1::new(context, 1, Duration::from_secs(5)).unwrap();
        assert_eq!(
            authority.admit(peer, wrong, [0x83; 32], Instant::now()),
            Err(AdmissionError::ContextMismatch)
        );
    }

    #[test]
    fn authenticated_connection_admission_binds_epoch_set_and_session() {
        let (client_key, server_key, client, server, set, key_roles, context, transport_context) =
            transport_fixture();
        let run_id = "poco-g3-7-20260823T070000Z-a1b2c3d4";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_roles = key_roles.clone();
        let server_context = transport_context;
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = AuthenticatedConnection::accept(
                stream,
                run_id,
                server,
                &server_key,
                &server_set,
                &server_roles,
                server_context,
            )
            .unwrap();
            let mut authority =
                PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
            let token = authority
                .admit_authenticated_connection(&connection, client, Instant::now())
                .unwrap();
            assert_eq!(token.context(), context);
            (
                connection.session_id(),
                connection.handshake_nonce_binding(),
                token,
            )
        });

        let stream = TcpStream::connect(address).unwrap();
        let connection = AuthenticatedConnection::connect(
            stream,
            run_id,
            client,
            server,
            &client_key,
            &set,
            &key_roles,
            transport_context,
        )
        .unwrap();
        assert_eq!(
            connection.validator_set_binding(),
            Some((7, set.id().into_bytes()))
        );
        let mut authority = PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
        let token = authority
            .admit_authenticated_connection(&connection, server, Instant::now())
            .unwrap();
        assert_eq!(token.context().epoch(), 7);
        let (server_session, server_nonce_binding, server_token) = server_thread.join().unwrap();
        assert_eq!(connection.session_id(), server_session);
        assert_eq!(connection.handshake_nonce_binding(), server_nonce_binding);
        assert_ne!(server_nonce_binding, [0; 32]);
        assert_eq!(token.session_id(), server_token.session_id());

        assert_eq!(
            authority.admit_authenticated_connection(&connection, client, Instant::now()),
            Err(AdmissionError::RemoteMismatch)
        );
        assert_eq!(authority.release(token), Ok(()));
        assert_eq!(
            authority.admit_authenticated_connection(&connection, server, Instant::now()),
            Err(AdmissionError::SessionReplay)
        );
        let wrong_context = PeerAdmissionContextV1::new(8, context.validator_set_id()).unwrap();
        let mut wrong_authority =
            PeerLeaseAuthorityV1::new(wrong_context, 2, Duration::from_secs(5)).unwrap();
        assert_eq!(
            wrong_authority.admit_authenticated_connection(&connection, server, Instant::now()),
            Err(AdmissionError::ContextMismatch)
        );
    }

    #[test]
    fn external_fence_cas_rejects_old_worker_expiry_and_context_mismatch() {
        let context = context();
        let authority = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
        let local = ValidatorId::new([0x81; 32]);
        let remote = ValidatorId::new([0x82; 32]);
        let first_scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Outbound,
            context,
            [0x91; 32],
            1,
        )
        .unwrap();
        let first_request =
            ExternalPeerLeaseRequestV1::new(first_scope, Duration::from_secs(1)).unwrap();
        let first = authority.acquire(first_request).unwrap();
        assert_eq!(
            authority.acquire(first_request),
            Err(ExternalFenceError::LeaseConflict)
        );
        let inbound_scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Inbound,
            context,
            [0x95; 32],
            1,
        )
        .unwrap();
        let inbound = authority
            .acquire(
                ExternalPeerLeaseRequestV1::new(inbound_scope, Duration::from_secs(1)).unwrap(),
            )
            .unwrap();
        assert_ne!(first.scope().direction(), inbound.scope().direction());
        authority.release(inbound).unwrap();

        // A process restart/rebind retains the external generation counter;
        // an old worker cannot renew or release the replacement generation.
        authority.advance_clock_millis(500);
        let renewed = authority.renew(first).unwrap();
        assert!(renewed.expires_at_millis() > first.expires_at_millis());
        authority.release(renewed).unwrap();
        let second_scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Outbound,
            context,
            [0x92; 32],
            2,
        )
        .unwrap();
        let second = authority
            .acquire(ExternalPeerLeaseRequestV1::new(second_scope, Duration::from_secs(1)).unwrap())
            .unwrap();
        assert_eq!(
            authority.revalidate(first),
            Err(ExternalFenceError::TokenMismatch)
        );
        assert_eq!(
            authority.release(first),
            Err(ExternalFenceError::TokenMismatch)
        );

        authority.advance_clock_millis(2_000);
        assert_eq!(
            authority.revalidate(second),
            Err(ExternalFenceError::LeaseExpired)
        );
        let third_scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Outbound,
            context,
            [0x93; 32],
            3,
        )
        .unwrap();
        assert!(authority
            .acquire(ExternalPeerLeaseRequestV1::new(third_scope, Duration::from_secs(1),).unwrap())
            .is_ok());

        let wrong_context =
            PeerAdmissionContextV1::new(context.epoch() + 1, context.validator_set_id()).unwrap();
        let wrong_scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Outbound,
            wrong_context,
            [0x94; 32],
            4,
        )
        .unwrap();
        assert_eq!(
            authority.acquire(
                ExternalPeerLeaseRequestV1::new(wrong_scope, Duration::from_secs(1),).unwrap()
            ),
            Err(ExternalFenceError::ContextMismatch)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_external_authority_mapping_preserves_direction_and_generation() {
        let context = context();
        let local = ValidatorId::new([0xa1; 32]);
        let remote = ValidatorId::new([0xa2; 32]);
        let scope = ExternalPeerLeaseScopeV1::new(
            local,
            remote,
            ExternalPeerDirectionV1::Inbound,
            context,
            [0xa3; 32],
            7,
        )
        .unwrap();
        let wire = wire_scope(scope).unwrap();
        assert_eq!(wire.local_id(), [0xa1; 32]);
        assert_eq!(wire.remote_id(), [0xa2; 32]);
        assert_eq!(wire.direction(), PeerLeaseDirectionV1::Inbound);
        assert_eq!(wire.epoch(), context.epoch());
        assert_eq!(wire.validator_set_id(), context.validator_set_id());

        let external =
            ExternalPeerLeaseTokenV1::from_authority_parts(scope, 123_456, [0xa4; 32]).unwrap();
        let round_trip = wire_token(external).unwrap();
        assert_eq!(round_trip.scope(), wire);
        assert_eq!(round_trip.session_id(), [0xa3; 32]);
        assert_eq!(round_trip.generation(), 7);
        assert_eq!(round_trip.expires_at_ms(), 123_456);
        assert_eq!(round_trip.record_hash(), [0xa4; 32]);

        let short_id = ValidatorId::from_bytes(&[0xa5; 31]).unwrap();
        let invalid_scope = ExternalPeerLeaseScopeV1::new(
            short_id,
            remote,
            ExternalPeerDirectionV1::Outbound,
            context,
            [0xa6; 32],
            1,
        )
        .unwrap();
        assert_eq!(
            wire_scope(invalid_scope),
            Err(ExternalFenceError::InvalidScope)
        );
    }
}
