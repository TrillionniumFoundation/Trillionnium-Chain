//! Bounded native socket ingress. Development loopback only; not Sybil-safe public P2P.
#[cfg(feature = "pq-native-openssl")]
pub mod pq_network;
use crate::{
    authenticated_payload_digest, authenticated_profile_digest, digest, ensure,
    store::{AuthenticatedReplayDecision, WorkCheckedPacket},
    Error, ErrorCode, Node, Packet, Result, Settings,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex, MutexGuard, TryLockError,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::{
    owned_ed25519::OwnedEd25519Key, verify_hex_strict, verifying_key_from_hex,
};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_transport::{
    proof_admission::bounded_ingress, AuthenticatedPeerFrameV0, IoDigest32V0, PeerSessionIdentityV0,
};
const MAX_FRAME: usize = 2 * 1024 * 1024;
const AUTH_REQUEST_SCHEMA: &str = "trnm-authenticated-request-v1";
const AUTH_RESPONSE_SCHEMA: &str = "trnm-authenticated-response-v1";
const MAX_AUTHENTICATED_PEERS: usize = 64;
const ADMISSION_CHALLENGE_SCHEMA: &str = "trnm-pon-admission-challenge-v1";
const ADMISSION_SOLUTION_SCHEMA: &str = "trnm-pon-admission-solution-v1";
const ADMISSION_HELLO_SCHEMA: &str = "trnm-pon-admission-hello-v1";
const ADMISSION_READY_SCHEMA: &str = "trnm-pon-admission-ready-v1";
const PROTECTED_PREFACE_BUDGET: Duration = Duration::from_millis(100);
const PROTECTED_ERROR_CHARS: usize = 128;
const RESERVED_READ_ONLY_BUSY: &str = "ADMISSION_BUSY_READ_ONLY_RESERVED";
const RESERVED_HELLO_YIELD: Duration = Duration::from_millis(2);
const PROOF_HANDOFF_POLL: Duration = Duration::from_millis(2);
const HELLO_HANDOFF_OPPORTUNITY: Duration = Duration::from_millis(2);
const HELLO_HANDOFF_RETRY_PAUSE: Duration = Duration::from_micros(100);
const HELLO_CLIENT_ATTEMPTS: usize = 512;
const HELLO_CLIENT_BUDGET: Duration = Duration::from_secs(5);

/// Connection-local transport CPU protection, never ledger work or a Sybil theorem.
/// The old development listeners remain separate and do not silently adopt this profile.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionPolicy {
    bits: u8,
    lifetime_ms: u64,
}
impl AdmissionPolicy {
    pub fn new(bits: u8, lifetime: Duration) -> Result<Self> {
        let lifetime_ms = u64::try_from(lifetime.as_millis()).map_err(|_| "ADMISSION_POLICY")?;
        ensure(
            (8..=20).contains(&bits) && (100..=2000).contains(&lifetime_ms),
            "ADMISSION_POLICY",
        )?;
        Ok(Self { bits, lifetime_ms })
    }
    pub fn development() -> Self {
        Self {
            bits: 16,
            lifetime_ms: 2000,
        }
    }
    fn profile(self) -> Hash {
        hash(
            b"native-transport-admission-profile-v1",
            &[
                b"hello-first/connection-local/sha256/exact-wire/monotonic-expiry/preface100ms/proof2-readonly1/readonly-no-proof-permit/hello-retry512-5s/refusal128chars-100ms/reserved-hello-yield2ms/hello-rendezvous0/handoff-opportunity2ms/poll100us/proof-recv-before-accept2ms/original-deadlines/socket-ceiling3",
                &[self.bits],
                &self.lifetime_ms.to_le_bytes(),
            ],
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionHello {
    schema: String,
    request_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionReady {
    schema: String,
    profile: String,
    request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionChallenge {
    pub schema: String,
    pub profile: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub nonce: String,
    pub request_digest: String,
    pub bits: u8,
    pub lifetime_ms: u64,
    pub expires_unix_ms: u64,
    pub server: String,
    pub signature: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSolution {
    pub schema: String,
    pub challenge_digest: String,
    pub nonce: u64,
}
fn unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "CLOCK")?
            .as_millis(),
    )
    .map_err(|_| "CLOCK".into())
}
fn admission_digest(challenge: &AdmissionChallenge) -> Result<Hash> {
    Ok(hash(
        b"native-transport-admission-challenge-v1",
        &[&serde_json::to_vec(challenge)?],
    ))
}
fn admission_authority_digest(challenge: &AdmissionChallenge) -> Result<Hash> {
    let mut authority = challenge.clone();
    authority.signature.clear();
    Ok(hash(
        b"native-transport-admission-server-sign-v1",
        &[&serde_json::to_vec(&authority)?],
    ))
}
fn admission_winner(challenge: Hash, nonce: u64, bits: u8) -> bool {
    let ticket = hash(
        b"native-transport-admission-solution-v1",
        &[&challenge, &nonce.to_le_bytes()],
    );
    let prefix = u32::from_be_bytes([ticket[0], ticket[1], ticket[2], ticket[3]]);
    prefix.leading_zeros() >= u32::from(bits)
}
/// Bound client effort and validate the destination and exact pending wire before search.
/// Returned hash trials are measured transport work; they confer no chain authority.
pub fn solve_admission_challenge(
    challenge: &AdmissionChallenge,
    request_wire: &[u8],
    settings: &Settings,
) -> Result<(AdmissionSolution, u64)> {
    let policy =
        AdmissionPolicy::new(challenge.bits, Duration::from_millis(challenge.lifetime_ms))?;
    ensure(
        challenge.schema == ADMISSION_CHALLENGE_SCHEMA
            && challenge.profile == hex::encode(policy.profile()),
        "ADMISSION_PROFILE",
    )?;
    ensure(
        challenge.network == hex::encode(settings.network())
            && challenge.parameters == hex::encode(settings.parameters())
            && challenge.genesis == hex::encode(settings.genesis()),
        "ADMISSION_CONTEXT",
    )?;
    if challenge.server.is_empty() {
        ensure(challenge.signature.is_empty(), "ADMISSION_SIGNATURE")?;
    } else {
        verify_hex_strict(
            &challenge.server,
            &admission_authority_digest(challenge)?,
            &challenge.signature,
        )
        .map_err(|e| Error::from(format!("ADMISSION_SIGNATURE:{e}")))?;
    }
    digest(&challenge.nonce)?;
    ensure(
        challenge.request_digest
            == hex::encode(hash(b"native-transport-admission-wire-v1", &[request_wire])),
        "ADMISSION_REQUEST",
    )?;
    let remaining = challenge
        .expires_unix_ms
        .checked_sub(unix_ms()?)
        .ok_or("ADMISSION_EXPIRED")?;
    ensure(
        remaining > 0 && remaining <= challenge.lifetime_ms,
        "ADMISSION_EXPIRED",
    )?;
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let challenge_digest = admission_digest(challenge)?;
    for nonce in 0..1_048_576_u64 {
        if nonce % 256 == 0 {
            ensure(Instant::now() < deadline, "ADMISSION_EXPIRED")?;
        }
        if admission_winner(challenge_digest, nonce, challenge.bits) {
            return Ok((
                AdmissionSolution {
                    schema: ADMISSION_SOLUTION_SCHEMA.into(),
                    challenge_digest: hex::encode(challenge_digest),
                    nonce,
                },
                nonce + 1,
            ));
        }
    }
    Err("ADMISSION_SEARCH_BUDGET".into())
}

#[derive(Clone)]
pub struct DevelopmentIdentity {
    signing_key: OwnedEd25519Key,
    public_hex: String,
}
impl DevelopmentIdentity {
    pub fn from_secret_hex(secret: &str) -> Result<Self> {
        let key = OwnedEd25519Key::from_canonical_hex(secret).map_err(Error::from)?;
        let public_hex = key.public_key_hex();
        Ok(Self {
            signing_key: key,
            public_hex,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_hex
    }

    fn sign(&self, message: &[u8]) -> Result<String> {
        Ok(self.signing_key.sign_hex(message))
    }
}

#[derive(Clone)]
pub struct AuthenticatedServer {
    identity: DevelopmentIdentity,
    peers: BTreeSet<String>,
    generation: u64,
}
impl AuthenticatedServer {
    pub fn new(
        identity: DevelopmentIdentity,
        peers: impl IntoIterator<Item = String>,
        generation: u64,
    ) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&generation),
            "AUTH_GENERATION",
        )?;
        let peer_list: Vec<_> = peers.into_iter().collect();
        let peers: BTreeSet<_> = peer_list.iter().cloned().collect();
        ensure(peer_list.len() == peers.len(), "AUTH_DUPLICATE_PEER")?;
        ensure(
            (1..=MAX_AUTHENTICATED_PEERS).contains(&peers.len()),
            "AUTH_PEER_LIMIT",
        )?;
        for peer in &peers {
            verifying_key_from_hex(peer).map_err(|e| Error::from(format!("AUTH_PEER:{e}")))?;
        }
        Ok(Self {
            identity,
            peers,
            generation,
        })
    }

    pub fn public_key(&self) -> &str {
        self.identity.public_key()
    }
}

#[derive(Clone)]
pub struct AuthenticatedClient {
    identity: DevelopmentIdentity,
    server_public: String,
    generation: u64,
}
impl AuthenticatedClient {
    pub fn new(
        identity: DevelopmentIdentity,
        server_public: String,
        generation: u64,
    ) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&generation),
            "AUTH_GENERATION",
        )?;
        verifying_key_from_hex(&server_public)
            .map_err(|e| Error::from(format!("AUTH_SERVER:{e}")))?;
        Ok(Self {
            identity,
            server_public,
            generation,
        })
    }

    pub fn public_key(&self) -> &str {
        self.identity.public_key()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSession {
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub profile: String,
    pub peer: String,
    pub server: String,
    pub session: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRequest {
    pub schema: String,
    pub session: AuthSession,
    pub replay_nonce: u64,
    pub request: Request,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedResponse {
    pub schema: String,
    pub session: AuthSession,
    pub replay_nonce: u64,
    pub request_digest: String,
    pub terminal: bool,
    pub ok: bool,
    pub value: Value,
    pub signature: String,
}

#[derive(Serialize)]
struct RequestAuthority<'a> {
    schema: &'static str,
    session: &'a AuthSession,
    replay_nonce: u64,
    request: &'a Request,
}
#[derive(Serialize)]
struct ResponseAuthority<'a> {
    schema: &'static str,
    session: &'a AuthSession,
    replay_nonce: u64,
    request_digest: &'a str,
    terminal: bool,
    ok: bool,
    value: &'a Value,
}

fn peer_identity(public: &str) -> Result<Hash> {
    let key = verifying_key_from_hex(public).map_err(|e| Error::from(format!("AUTH_PEER:{e}")))?;
    Ok(hash(b"native-authenticated-peer-v1", &[&key.to_bytes()]))
}

pub fn authenticated_session(
    settings: &Settings,
    peer: &str,
    server: &str,
    generation: u64,
) -> Result<AuthSession> {
    ensure(
        (1..=i64::MAX as u64).contains(&generation),
        "AUTH_GENERATION",
    )?;
    let peer_id = peer_identity(peer)?;
    let server_id = peer_identity(server)?;
    let profile = authenticated_profile_digest();
    let session = hash(
        b"native-authenticated-session-v1",
        &[
            &settings.network(),
            &settings.parameters(),
            &settings.genesis(),
            &profile,
            &peer_id,
            &server_id,
            &generation.to_le_bytes(),
        ],
    );
    Ok(AuthSession {
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        profile: hex::encode(profile),
        peer: peer.to_owned(),
        server: server.to_owned(),
        session: hex::encode(session),
        generation,
    })
}

fn request_authority_digest(
    session: &AuthSession,
    replay_nonce: u64,
    request: &Request,
) -> Result<Hash> {
    ensure(
        (1..=i64::MAX as u64).contains(&replay_nonce),
        "AUTH_REPLAY_NONCE",
    )?;
    let bytes = serde_json::to_vec(&RequestAuthority {
        schema: AUTH_REQUEST_SCHEMA,
        session,
        replay_nonce,
        request,
    })?;
    Ok(hash(b"native-authenticated-request-sign-v1", &[&bytes]))
}

fn response_authority_digest(response: &AuthenticatedResponse) -> Result<Hash> {
    let bytes = serde_json::to_vec(&ResponseAuthority {
        schema: AUTH_RESPONSE_SCHEMA,
        session: &response.session,
        replay_nonce: response.replay_nonce,
        request_digest: &response.request_digest,
        terminal: response.terminal,
        ok: response.ok,
        value: &response.value,
    })?;
    Ok(hash(b"native-authenticated-response-sign-v1", &[&bytes]))
}

fn transport_session(session: &AuthSession) -> Result<PeerSessionIdentityV0> {
    PeerSessionIdentityV0::new(
        IoDigest32V0::new(digest(&session.genesis)?)
            .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))?,
        IoDigest32V0::new(digest(&session.parameters)?)
            .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))?,
        IoDigest32V0::new(peer_identity(&session.peer)?)
            .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))?,
        IoDigest32V0::new(digest(&session.session)?)
            .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))?,
        IoDigest32V0::new(digest(&session.profile)?)
            .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))?,
        session.generation,
    )
    .map_err(|e| Error::from(format!("AUTH_SESSION:{e}")))
}

#[derive(Debug)]
struct VerifiedAuthenticatedRequest {
    wire: Vec<u8>,
    request: Request,
    session: AuthSession,
    frame: AuthenticatedPeerFrameV0,
    payload: Vec<u8>,
    request_digest: Hash,
}

pub fn authenticated_request_bytes(
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: u64,
    request: Request,
) -> Result<Vec<u8>> {
    let session = authenticated_session(
        settings,
        client.identity.public_key(),
        &client.server_public,
        client.generation,
    )?;
    let authority = request_authority_digest(&session, replay_nonce, &request)?;
    let envelope = AuthenticatedRequest {
        schema: AUTH_REQUEST_SCHEMA.into(),
        session,
        replay_nonce,
        request,
        signature: client.identity.sign(&authority)?,
    };
    Ok(serde_json::to_vec(&envelope)?)
}

fn authenticate_request(
    bytes: &[u8],
    settings: &Settings,
    server: &AuthenticatedServer,
) -> Result<VerifiedAuthenticatedRequest> {
    let envelope: AuthenticatedRequest = serde_json::from_slice(bytes)?;
    ensure(serde_json::to_vec(&envelope)? == bytes, "AUTH_NONCANONICAL")?;
    ensure(envelope.schema == AUTH_REQUEST_SCHEMA, "AUTH_SCHEMA")?;
    ensure(
        server.peers.contains(&envelope.session.peer),
        "AUTH_PEER_NOT_ALLOWED",
    )?;
    let expected = authenticated_session(
        settings,
        &envelope.session.peer,
        server.identity.public_key(),
        server.generation,
    )?;
    ensure(envelope.session == expected, "AUTH_SESSION_CONTEXT")?;
    let authority =
        request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)?;
    verify_hex_strict(&envelope.session.peer, &authority, &envelope.signature)
        .map_err(|e| Error::from(format!("AUTH_SIGNATURE:{e}")))?;
    let payload = serde_json::to_vec(&envelope.request)?;
    let frame = AuthenticatedPeerFrameV0::new(
        transport_session(&envelope.session)?,
        envelope.replay_nonce,
        IoDigest32V0::new(authenticated_payload_digest(&payload))
            .map_err(|e| Error::from(format!("AUTH_FRAME:{e}")))?,
        payload.len(),
    )
    .map_err(|e| Error::from(format!("AUTH_FRAME:{e}")))?;
    Ok(VerifiedAuthenticatedRequest {
        wire: bytes.to_vec(),
        request: envelope.request,
        session: envelope.session,
        frame,
        payload,
        request_digest: authority,
    })
}

fn signed_response(
    server: &AuthenticatedServer,
    request: &VerifiedAuthenticatedRequest,
    terminal: bool,
    outcome: Result<Value>,
) -> Result<Vec<u8>> {
    let (ok, value) = match outcome {
        Ok(value) => (true, value),
        Err(error) => (false, json!({"error":error.to_string()})),
    };
    let mut response = AuthenticatedResponse {
        schema: AUTH_RESPONSE_SCHEMA.into(),
        session: request.session.clone(),
        replay_nonce: request.frame.replay_nonce(),
        request_digest: hex::encode(request.request_digest),
        terminal,
        ok,
        value,
        signature: String::new(),
    };
    response.signature = server
        .identity
        .sign(&response_authority_digest(&response)?)?;
    Ok(serde_json::to_vec(&response)?)
}

fn begin_authenticated_dispatch(
    owner: &mut Node,
    request: &VerifiedAuthenticatedRequest,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<AuthenticatedReplayDecision> {
    match owner.begin_authenticated_request(request.frame, &request.payload) {
        Err(error) if error.is(ErrorCode::ReorgInProgress) => {
            let Request::Submit { packet } = &request.request else {
                return Err(error);
            };
            progress(0)?;
            let packet = hex_packet(packet)?;
            owner.begin_authenticated_pending_activation(
                request.frame,
                &request.payload,
                &packet,
                now()?,
                &mut || progress(0),
            )
        }
        result => result,
    }
}

fn verify_authenticated_response(
    bytes: &[u8],
    session: &AuthSession,
    replay_nonce: u64,
    request_digest: Hash,
) -> Result<(bool, bool, Value)> {
    let response: AuthenticatedResponse = serde_json::from_slice(bytes)?;
    ensure(
        serde_json::to_vec(&response)? == bytes,
        "AUTH_RESPONSE_NONCANONICAL",
    )?;
    ensure(
        response.schema == AUTH_RESPONSE_SCHEMA
            && response.session == *session
            && response.replay_nonce == replay_nonce
            && response.request_digest == hex::encode(request_digest),
        "AUTH_RESPONSE_CONTEXT",
    )?;
    verify_hex_strict(
        &session.server,
        &response_authority_digest(&response)?,
        &response.signature,
    )
    .map_err(|e| Error::from(format!("AUTH_RESPONSE_SIGNATURE:{e}")))?;
    Ok((response.terminal, response.ok, response.value))
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Head,
    Submit { packet: String },
    History { tip: String, after: String },
    Confirm { transaction: String, block: String },
    ConfirmMany { queries: Vec<ConfirmationQuery> },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationQuery {
    pub transaction: String,
    pub block: String,
}
pub fn confirmation_queries(queries: &[ConfirmationQuery]) -> Result<Vec<(Hash, Hash)>> {
    ensure((1..=256).contains(&queries.len()), "CONFIRMATION_LIMIT")?;
    queries
        .iter()
        .map(|q| Ok((digest(&q.transaction)?, digest(&q.block)?)))
        .collect()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub schema: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub tip: String,
    pub after: String,
    pub packets: Vec<String>,
    pub next: String,
    pub complete: bool,
}
#[derive(Default, Debug, Serialize)]
pub struct Metrics {
    pub socket_connections: u64,
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub busy_requests: u64,
    pub malformed_requests: u64,
    pub authenticated_requests: u64,
    pub replayed_responses: u64,
    pub pending_busy_requests: u64,
    pub admission_challenges: u64,
    pub admission_accepted: u64,
    pub admission_rejected_before_work: u64,
    pub admission_unnegotiated_requests: u64,
    pub admission_reserved_read_only_refusals: u64,
    pub admission_hello_handoffs: u64,
    pub protected_preface_refusals: u64,
    pub admission_verification_ns: u64,
    pub work_verifications: u64,
    pub work_verification_ns: u64,
    /// Known actual calling-thread CPU only; the full original W1/M05 interval.
    /// No guessed CPU is inserted when the clock is missing or moves backward.
    pub work_verification_thread_cpu_known_ns: u64,
    pub work_verification_thread_cpu_known_calls: u64,
    pub work_verification_thread_cpu_unknown_calls: u64,
}
fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
#[cfg(target_os = "linux")]
fn calling_thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let time = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let nanos = u64::try_from(time.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn calling_thread_cpu_ns() -> Option<u64> {
    None
}

fn measured_work_verify(packet: Packet, metrics: &Mutex<Metrics>) -> Result<WorkCheckedPacket> {
    let start = Instant::now();
    let start_cpu = calling_thread_cpu_ns();
    metrics
        .lock()
        .map_err(|_| "METRICS_POISONED")?
        .work_verifications += 1;
    let result = WorkCheckedPacket::verify(packet);
    let actual_cpu = start_cpu
        .zip(calling_thread_cpu_ns())
        .and_then(|(before, after)| after.checked_sub(before));
    let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
    counts.work_verification_ns = counts
        .work_verification_ns
        .saturating_add(elapsed_ns(start));
    if let Some(cpu) = actual_cpu {
        counts.work_verification_thread_cpu_known_ns = counts
            .work_verification_thread_cpu_known_ns
            .saturating_add(cpu);
        counts.work_verification_thread_cpu_known_calls = counts
            .work_verification_thread_cpu_known_calls
            .saturating_add(1);
    } else {
        counts.work_verification_thread_cpu_unknown_calls = counts
            .work_verification_thread_cpu_unknown_calls
            .saturating_add(1);
    }
    result
}

struct AdmissionHost<'a> {
    settings: &'a Settings,
    policy: Option<AdmissionPolicy>,
    authentication: Option<&'a AuthenticatedServer>,
    metrics: &'a Mutex<Metrics>,
    negotiated: bool,
}
fn protect_submit(
    socket: &mut TcpStream,
    request: &Request,
    request_wire: &[u8],
    host: AdmissionHost<'_>,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<()> {
    let AdmissionHost {
        settings,
        policy,
        authentication,
        metrics,
        negotiated,
    } = host;
    let Some(policy) = policy.filter(|_| matches!(request, Request::Submit { .. })) else {
        return Ok(());
    };
    if !negotiated {
        metrics
            .lock()
            .map_err(|_| "METRICS_POISONED")?
            .admission_unnegotiated_requests += 1;
        return Err("ADMISSION_REQUIRED".into());
    }
    progress(0)?;
    let mut nonce = [0u8; 32];
    // The native development host is Linux. Entropy failure fences protected intake.
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut challenge = AdmissionChallenge {
        schema: ADMISSION_CHALLENGE_SCHEMA.into(),
        profile: hex::encode(policy.profile()),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        nonce: hex::encode(nonce),
        request_digest: hex::encode(hash(b"native-transport-admission-wire-v1", &[request_wire])),
        bits: policy.bits,
        lifetime_ms: policy.lifetime_ms,
        expires_unix_ms: unix_ms()?.checked_add(policy.lifetime_ms).ok_or("CLOCK")?,
        server: authentication.map_or_else(String::new, |a| a.public_key().to_owned()),
        signature: String::new(),
    };
    if let Some(server) = authentication {
        challenge.signature = server
            .identity
            .sign(&admission_authority_digest(&challenge)?)?;
    }
    let deadline = Instant::now() + Duration::from_millis(policy.lifetime_ms);
    let challenge_digest = admission_digest(&challenge)?;
    write_frame_deadline(socket, &serde_json::to_vec(&challenge)?, deadline)?;
    metrics
        .lock()
        .map_err(|_| "METRICS_POISONED")?
        .admission_challenges += 1;
    let outcome = (|| -> Result<()> {
        ensure(Instant::now() < deadline, "ADMISSION_EXPIRED")?;
        // Solutions are tiny; do not allocate the ordinary 2 MiB request limit here.
        let mut prefix = [0u8; 4];
        read_exact_deadline(socket, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        ensure((1..=512).contains(&length), "ADMISSION_LENGTH")?;
        let mut bytes = vec![0; length];
        read_exact_deadline(socket, &mut bytes, deadline)?;
        progress(0)?;
        ensure(Instant::now() < deadline, "ADMISSION_EXPIRED")?;
        let start = Instant::now();
        let checked = (|| -> Result<()> {
            let solution: AdmissionSolution = serde_json::from_slice(&bytes)?;
            ensure(
                serde_json::to_vec(&solution)? == bytes,
                "ADMISSION_NONCANONICAL",
            )?;
            ensure(
                solution.schema == ADMISSION_SOLUTION_SCHEMA
                    && solution.challenge_digest == hex::encode(challenge_digest),
                "ADMISSION_REPLAY_OR_CONTEXT",
            )?;
            ensure(
                admission_winner(challenge_digest, solution.nonce, policy.bits),
                "ADMISSION_TARGET",
            )
        })();
        let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
        counts.admission_verification_ns = counts
            .admission_verification_ns
            .saturating_add(elapsed_ns(start));
        checked
    })();
    let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
    if outcome.is_ok() {
        counts.admission_accepted += 1;
    } else {
        counts.admission_rejected_before_work += 1;
    }
    outcome
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::from("CLOCK"))?
        .as_secs())
}
fn read_exact_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or("FRAME_DEADLINE")?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err("FRAME_EOF".into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    ensure(Instant::now() < deadline, "FRAME_DEADLINE")
}
fn read_frame_budget(stream: &mut TcpStream, budget: Duration) -> Result<Vec<u8>> {
    read_frame_deadline(stream, Instant::now() + budget)
}
fn read_frame_deadline(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    read_exact_deadline(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure((1..=MAX_FRAME).contains(&length), "FRAME_LIMIT")?;
    let mut bytes = vec![0; length];
    read_exact_deadline(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_frame_budget(stream, Duration::from_secs(5))
}
fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    write_frame_deadline(stream, bytes, Instant::now() + Duration::from_secs(5))
}
fn write_frame_deadline(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    ensure((1..=MAX_FRAME).contains(&bytes.len()), "FRAME_LIMIT")?;
    let prefix = (bytes.len() as u32).to_be_bytes();
    for mut part in [prefix.as_slice(), bytes] {
        while !part.is_empty() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or("FRAME_DEADLINE")?;
            stream.set_write_timeout(Some(remaining))?;
            match stream.write(part) {
                Ok(0) => return Err("FRAME_EOF".into()),
                Ok(n) => part = &part[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    ensure(Instant::now() < deadline, "FRAME_DEADLINE")
}
fn write_untrusted_error(
    stream: &mut TcpStream,
    error: &dyn std::fmt::Display,
    protected: bool,
) -> Result<()> {
    let text = error.to_string();
    let bounded = if protected {
        text.chars().take(PROTECTED_ERROR_CHARS).collect::<String>()
    } else {
        text
    };
    let budget = if protected {
        PROTECTED_PREFACE_BUDGET
    } else {
        Duration::from_secs(5)
    };
    write_frame_deadline(
        stream,
        &serde_json::to_vec(&json!({"error":bounded}))?,
        Instant::now() + budget,
    )
}
fn hex_packet(text: &str) -> Result<Packet> {
    ensure(
        text.len() <= 2_097_152
            && text.len().is_multiple_of(2)
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PACKET_HEX",
    )?;
    Packet::decode(&hex::decode(text).map_err(|_| Error::from("PACKET_HEX"))?)
}
/// Negotiate before sending Submit; legacy listeners see only a nonmutating hello.
/// Durable authenticated outbox bytes remain the exact originally signed request.
pub fn write_protected_request(
    stream: &mut TcpStream,
    request: &Request,
    wire: &[u8],
) -> Result<()> {
    write_protected_request_bound(stream, request, wire).map(|_| ())
}
fn write_protected_request_bound(
    stream: &mut TcpStream,
    request: &Request,
    wire: &[u8],
) -> Result<Option<Hash>> {
    // Multi-frame challenge negotiation must not inherit delayed small-packet writes.
    stream.set_nodelay(true)?;
    let profile = if matches!(request, Request::Submit { .. }) {
        let hello = AdmissionHello {
            schema: ADMISSION_HELLO_SCHEMA.into(),
            request_digest: hex::encode(hash(b"native-transport-admission-wire-v1", &[wire])),
        };
        let hello_wire = serde_json::to_vec(&hello)?;
        let deadline = Instant::now() + HELLO_CLIENT_BUDGET;
        let mut negotiated = None;
        for attempt in 0..HELLO_CLIENT_ATTEMPTS {
            write_frame_deadline(stream, &hello_wire, deadline)?;
            let ready_wire = read_frame_deadline(stream, deadline)?;
            if serde_json::from_slice::<Value>(&ready_wire)?["error"] == RESERVED_READ_ONLY_BUSY {
                ensure(attempt + 1 < HELLO_CLIENT_ATTEMPTS, RESERVED_READ_ONLY_BUSY)?;
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or("FRAME_DEADLINE")?;
                thread::sleep(Duration::from_millis(10).min(remaining));
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or("FRAME_DEADLINE")?;
                *stream = TcpStream::connect_timeout(&stream.peer_addr()?, remaining)?;
                stream.set_nodelay(true)?;
                continue;
            }
            let ready: AdmissionReady =
                serde_json::from_slice(&ready_wire).map_err(|_| "ADMISSION_REQUIRED")?;
            ensure(
                serde_json::to_vec(&ready)? == ready_wire
                    && ready.schema == ADMISSION_READY_SCHEMA
                    && ready.request_digest == hello.request_digest,
                "ADMISSION_REQUIRED",
            )?;
            negotiated = Some(digest(&ready.profile)?);
            break;
        }
        ensure(negotiated.is_some(), "ADMISSION_REQUIRED")?;
        negotiated
    } else {
        None
    };
    write_frame(stream, wire)?;
    Ok(profile)
}
fn admission_hello(first: &[u8]) -> Result<Option<AdmissionHello>> {
    let Ok(hello) = serde_json::from_slice::<AdmissionHello>(first) else {
        return Ok(None);
    };
    ensure(
        first.len() <= 512
            && serde_json::to_vec(&hello)? == first
            && hello.schema == ADMISSION_HELLO_SCHEMA,
        "ADMISSION_HELLO",
    )?;
    digest(&hello.request_digest)?;
    Ok(Some(hello))
}

/// An accepted socket belongs to exactly one of the three existing workers.
/// Zero-capacity channels transfer it only to a proof worker actually receiving.
/// The current reserved worker may retain this same socket for up to 2 ms of
/// additional opportunities, clamped to its original deadlines. There is no
/// pending socket queue, fresh accept time or renewed preface budget. Scheduling
/// delay can overshoot a requested sleep; every subsequent offer checks expiry.
struct PrefacedSocket {
    socket: TcpStream,
    address: SocketAddr,
    request_deadline: Instant,
    preface_deadline: Instant,
    first: Vec<u8>,
}

fn try_handoff_hello(
    mut connection: PrefacedSocket,
    senders: &[SyncSender<PrefacedSocket>],
) -> std::result::Result<(), PrefacedSocket> {
    let deadline = connection
        .preface_deadline
        .min(connection.request_deadline)
        .min(Instant::now() + HELLO_HANDOFF_OPPORTUNITY);
    loop {
        let mut receiver_exists = false;
        for sender in senders {
            match sender.try_send(connection) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(returned)) => {
                    receiver_exists = true;
                    connection = returned;
                }
                Err(TrySendError::Disconnected(returned)) => connection = returned,
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(connection);
        };
        if !receiver_exists || remaining.is_zero() {
            return Err(connection);
        }
        thread::sleep(HELLO_HANDOFF_RETRY_PAUSE.min(remaining));
        // Keep the previous immediate-offer behavior for the initial round; an
        // expired transferred socket still fails its original Ready/body IO.
        // No extra retry round can start after either original deadline.
        if Instant::now() >= deadline {
            return Err(connection);
        }
    }
}

fn receive_protected_request(
    stream: &mut TcpStream,
    first: Vec<u8>,
    policy: Option<AdmissionPolicy>,
    deadline: Instant,
    proof_enabled: bool,
) -> Result<(Vec<u8>, bool)> {
    let Some(policy) = policy else {
        return Ok((first, false));
    };
    let Some(hello) = admission_hello(&first)? else {
        return Ok((first, false));
    };
    ensure(proof_enabled, RESERVED_READ_ONLY_BUSY)?;
    let ready = AdmissionReady {
        schema: ADMISSION_READY_SCHEMA.into(),
        profile: hex::encode(policy.profile()),
        request_digest: hello.request_digest.clone(),
    };
    write_frame_deadline(stream, &serde_json::to_vec(&ready)?, deadline)?;
    let wire = read_frame_deadline(stream, deadline)?;
    ensure(
        hello.request_digest == hex::encode(hash(b"native-transport-admission-wire-v1", &[&wire])),
        "ADMISSION_REQUEST",
    )?;
    Ok((wire, true))
}
fn dispatch(
    node: &mut Node,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Value> {
    progress(0)?;
    match request {
        Request::Head => node.stats(),
        Request::Submit { .. } => Err("SUBMIT_REQUIRES_WORK_CHECK".into()),
        Request::History { tip, after } => {
            let packets =
                node.history_with_progress(digest(&tip)?, digest(&after)?, 16, progress)?;
            let next = packets
                .last()
                .map(|p| p.id().map(hex::encode))
                .transpose()?
                .unwrap_or_else(|| after.clone());
            Ok(serde_json::to_value(Page {
                schema: "pon-native-history-v1".into(),
                network: hex::encode(node.settings().network()),
                parameters: hex::encode(node.settings().parameters()),
                genesis: hex::encode(node.settings().genesis()),
                complete: next == tip,
                tip,
                after,
                next,
                packets: packets
                    .iter()
                    .map(|p| p.encode().map(hex::encode))
                    .collect::<Result<_>>()?,
            })?)
        }
        Request::Confirm { transaction, block } => {
            let batch = node.confirmations_with_progress(
                &[(digest(&transaction)?, digest(&block)?)],
                now()?,
                progress,
            )?;
            Ok(serde_json::to_value(
                batch
                    .observations
                    .into_iter()
                    .next()
                    .ok_or("EMPTY_CONFIRMATION")?,
            )?)
        }
        Request::ConfirmMany { queries } => Ok(serde_json::to_value(
            node.confirmations_with_progress(&confirmation_queries(&queries)?, now()?, progress)?,
        )?),
    }
}
fn lock_owner<'a>(
    node: &'a Mutex<Node>,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<MutexGuard<'a, Node>> {
    loop {
        progress(0)?;
        match node.try_lock() {
            Ok(owner) => return Ok(owner),
            Err(TryLockError::Poisoned(_)) => return Err("OWNER_POISONED".into()),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
        }
    }
}

fn submit_result_with_progress(
    node: &mut Node,
    id: Hash,
    clock: u64,
    progress: &mut dyn FnMut() -> Result<()>,
    termination_cpu: Option<&public_v3::ServiceMutationCpuCheckpoint>,
) -> Result<Value> {
    let active = node.activate_observed_with_termination(id, clock, progress, termination_cpu)?;
    Ok(json!({"block":hex::encode(id),"active":hex::encode(active),
        "generation":node.active()?.1,"physical_execution":false}))
}

#[path = "ingress/metered_work_facts.rs"]
mod metered_work_facts;
pub use metered_work_facts::{
    dispatch_shared_with_metered_w1, dispatch_shared_with_metered_work_facts,
    MeteredWorkFactOutcome,
};

/// Explicit local-development W1 fact-reuse entrypoint on the existing M05/M06
/// and durable owner path. This is NOT selected by V2/V3 network listeners or CLI.
/// Their pinned resource policies and ordinary full-replay behavior are unchanged.
/// The caller bounds concurrent requests and supplies one original cancellation /
/// deadline check. Current context, task/owner permit, state and commit checks run
/// on every dispatch, including cache hits; no second Node or journal is created.
#[cfg(test)]
pub(crate) fn dispatch_shared_with_work_facts(
    node: &Mutex<Node>,
    request: Request,
    facts: &trnm_crypto_primitives::pon_work::facts::WorkFactCache,
    checkpoint: &(impl Fn() -> Result<()> + Sync),
) -> Result<Value> {
    dispatch_shared_with_execution_progress(
        node,
        request,
        &mut |_| checkpoint(),
        |packet| WorkCheckedPacket::verify_with_facts(packet, facts, &mut |_| checkpoint()),
        &|_| checkpoint(),
    )
}

#[cfg(test)]
#[path = "ingress/work_fact_tests.rs"]
mod work_fact_tests;

/// The verifier runs outside the only durable owner's lock. It cannot commit a block.
/// The injected verifier is private and used only to schedule deterministic unit tests.
fn dispatch_shared_with(
    node: &Mutex<Node>,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    verify: impl FnOnce(Packet) -> Result<WorkCheckedPacket>,
) -> Result<Value> {
    dispatch_shared_with_execution_progress(node, request, progress, verify, &|_| Ok(()))
}
fn dispatch_shared_with_execution_progress(
    node: &Mutex<Node>,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    verify: impl FnOnce(Packet) -> Result<WorkCheckedPacket>,
    execution_progress: &(impl Fn(trnm_mvcc_fee::pon_executor::ExecutionProgress) -> Result<()> + Sync),
) -> Result<Value> {
    dispatch_shared_with_execution_control(
        node,
        request,
        progress,
        verify,
        &trnm_mvcc_fee::pon_executor::ExecutionControl::new(execution_progress, &()),
        None,
    )
}
fn dispatch_shared_with_execution_control(
    node: &Mutex<Node>,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    verify: impl FnOnce(Packet) -> Result<WorkCheckedPacket>,
    control: &trnm_mvcc_fee::pon_executor::ExecutionControl<'_, Error>,
    termination_cpu: Option<&public_v3::ServiceMutationCpuCheckpoint>,
) -> Result<Value> {
    dispatch_shared_with_execution_observation(
        node,
        request,
        progress,
        verify,
        control,
        SubmitDispatchContext {
            termination_cpu,
            ..SubmitDispatchContext::default()
        },
    )
}

#[derive(Default)]
struct SubmitDispatchContext<'a> {
    observation: Option<&'a public_v3::request_observation::TaskObservation>,
    public_proof_before_unowned_task: bool,
    termination_cpu: Option<&'a public_v3::ServiceMutationCpuCheckpoint>,
}

fn observe_submit_phase<T>(
    observation: Option<&public_v3::request_observation::TaskObservation>,
    phase: public_v3::SubmitPhase,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let measurement = observation.map(|record| record.phase(phase));
    let result = action();
    if let Some(measurement) = measurement {
        measurement.finish(result.is_ok());
    }
    result
}

/// Reuse the caller's original CPU operation, worker accounting and absolute
/// cancellation control. There is no reservation/refill/account construction
/// here. One bounded snapshot slot keeps M06 memory concurrency at one owner.
fn admit_shared_checked<'a>(
    node: &'a Mutex<Node>,
    checked: WorkCheckedPacket,
    permit: Option<crate::store::OwnerPacketPermit>,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    control: &trnm_mvcc_fee::pon_executor::ExecutionControl<'_, Error>,
    clock: impl Fn() -> Result<u64>,
    observation: Option<&public_v3::request_observation::TaskObservation>,
) -> Result<(MutexGuard<'a, Node>, Hash, u64)> {
    use crate::store::{DetachedExecutionLease, PreparedSharedAdmission};
    use public_v3::SubmitPhase;
    use trnm_mvcc_fee::pon_executor::ExecutionProgress;
    let wait_end = Instant::now() + Duration::from_secs(2);
    let (mut owner, lease): (MutexGuard<'a, Node>, Option<DetachedExecutionLease>) =
        observe_submit_phase(observation, SubmitPhase::AdmissionOwnerWait, || loop {
            progress(0)?;
            (control.progress)(ExecutionProgress::BeforeParentBinding)?;
            let mut acquisition = |amount| {
                progress(amount)?;
                (control.progress)(ExecutionProgress::BeforeParentBinding)?;
                ensure(Instant::now() < wait_end, "PUBLIC_QUEUE_BUSY")
            };
            let owner = lock_owner(node, &mut acquisition)?;
            acquisition(0)?;
            // Authorized non-ordinary modes keep their original verified path.
            // They cannot manufacture an unsupported detached capability.
            if !owner.detached_execution_supported() {
                return Ok((owner, None));
            }
            match owner.reserve_detached_execution() {
                Ok(lease) => return Ok((owner, Some(lease))),
                Err(error) if error.is(ErrorCode::PublicQueueBusy) => {
                    drop(owner);
                    ensure(Instant::now() < wait_end, "PUBLIC_QUEUE_BUSY")?;
                    thread::sleep(
                        Duration::from_millis(2)
                            .min(wait_end.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        })?;
    observe_submit_phase(observation, SubmitPhase::Admission, || {
        let observed_now = clock()?;
        let checked = owner.attach_owner_work(checked, permit)?;
        let Some(lease) = lease else {
            let id = owner.admit_work_checked_with_control(checked, observed_now, control)?;
            return Ok((owner, id, observed_now));
        };
        match owner.prepare_shared_admission(checked, lease, observed_now, control)? {
            PreparedSharedAdmission::Existing(id) => Ok((owner, id, observed_now)),
            PreparedSharedAdmission::HeldForSnapshotCapacity {
                checked,
                observed_payload_bytes,
            } => {
                ensure(
                    observed_payload_bytes > trnm_mvcc_fee::pon_commitment::MAX_CACHE_PAYLOAD_BYTES,
                    "OWNER_DETACHED_EXECUTION_CONTEXT",
                )?;
                // This is the identical original checked M06 schedule, with
                // its current checks and original CPU/deadline. It is not a
                // Work-primitive fallback or an accepted arbitrary output.
                let id = owner.admit_held_prepared(*checked, observed_now, control)?;
                Ok((owner, id, observed_now))
            }
            PreparedSharedAdmission::Execute(prepared) => {
                drop(owner);
                let executed = prepared.execute(control)?;
                // This wait is nested in the original Admission phase. It does
                // not overwrite the earlier seven-slot wait measurement.
                progress(0)?;
                let mut reacquisition = |amount| {
                    progress(amount)?;
                    (control.progress)(ExecutionProgress::BeforeParentBinding)
                };
                let mut owner = lock_owner(node, &mut reacquisition)?;
                let observed_now = clock()?;
                let id = owner.commit_shared_admission(executed, observed_now, control)?;
                Ok((owner, id, observed_now))
            }
        }
    })
}

/// Optional seven-slot phase observations use the existing request owner. They
/// never change a native result or mint credit; all old callers pass None.
fn dispatch_shared_with_execution_observation(
    node: &Mutex<Node>,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    verify: impl FnOnce(Packet) -> Result<WorkCheckedPacket>,
    control: &trnm_mvcc_fee::pon_executor::ExecutionControl<'_, Error>,
    context: SubmitDispatchContext<'_>,
) -> Result<Value> {
    use public_v3::SubmitPhase;
    let SubmitDispatchContext {
        observation,
        public_proof_before_unowned_task,
        termination_cpu,
    } = context;
    match request {
        Request::Submit { packet } => {
            let packet =
                observe_submit_phase(observation, SubmitPhase::Decode, || hex_packet(&packet))?;
            let owner_permit = {
                let mut owner =
                    observe_submit_phase(observation, SubmitPhase::ContextOwnerWait, || {
                        lock_owner(node, progress)
                    })?;
                let (existing, permit) =
                    observe_submit_phase(observation, SubmitPhase::Context, || {
                        let clock = now()?;
                        // Pending activation checks do not reconstruct parent State.
                        // Keep request cancellation without emitting a State progress
                        // event before the ordinary proof/task prechecks below.
                        let pending_exact =
                            owner.pending_exact_activation_replay(&packet, clock, &mut || {
                                progress(0)
                            })?;
                        let mut checkpoint = || {
                            progress(0)?;
                            (control.progress)(
                                trnm_mvcc_fee::pon_executor::ExecutionProgress::BeforeParentBinding,
                            )
                        };
                        let existing = if pending_exact.is_some() {
                            pending_exact
                        } else if public_proof_before_unowned_task {
                            owner.precheck_public_admission_context_with_progress(
                                &packet,
                                clock,
                                &mut checkpoint,
                            )?
                        } else {
                            owner.check_admission_context_with_progress(
                                &packet,
                                clock,
                                &mut checkpoint,
                            )?
                        };
                        if let Some(id) = existing {
                            return Ok((Some((id, clock)), None));
                        }
                        Ok((None, owner.begin_owner_work(&packet)?))
                    })?;
                if let Some((id, clock)) = existing {
                    return observe_submit_phase(observation, SubmitPhase::SubmitResult, || {
                        let active = owner.activate_observed_with_termination(
                            id,
                            clock,
                            &mut || {
                                progress(0)?;
                                (control.progress)(
                                    trnm_mvcc_fee::pon_executor::ExecutionProgress::BeforeOutput,
                                )
                            },
                            termination_cpu,
                        )?;
                        Ok(json!({"block":hex::encode(id),"active":hex::encode(active),
                            "generation":owner.active()?.1,"physical_execution":false}))
                    });
                }
                permit
            };
            progress(0)?;
            let checked = observe_submit_phase(observation, SubmitPhase::Work, || verify(packet))?;
            // Cancellation after work must not turn into a durable admission.
            progress(0)?;
            let (mut owner, id, clock) = admit_shared_checked(
                node,
                checked,
                owner_permit,
                progress,
                control,
                now,
                observation,
            )?;
            observe_submit_phase(observation, SubmitPhase::SubmitResult, || {
                submit_result_with_progress(
                    &mut owner,
                    id,
                    clock,
                    &mut || {
                        progress(0)?;
                        (control.progress)(
                            trnm_mvcc_fee::pon_executor::ExecutionProgress::BeforeOutput,
                        )
                    },
                    termination_cpu,
                )
            })
        }
        other => {
            let mut owner = lock_owner(node, progress)?;
            dispatch(&mut owner, other, progress)
        }
    }
}

struct ActiveRequestGuard {
    active: Arc<Mutex<BTreeSet<(Hash, u64)>>>,
    key: (Hash, u64),
}
impl ActiveRequestGuard {
    fn acquire(
        active: Arc<Mutex<BTreeSet<(Hash, u64)>>>,
        key: (Hash, u64),
    ) -> Result<Option<Self>> {
        let inserted = active
            .lock()
            .map_err(|_| Error::from("AUTH_ACTIVE_POISONED"))?
            .insert(key);
        Ok(inserted.then_some(Self { active, key }))
    }
}
impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.key);
        }
    }
}

pub fn serve(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
) -> Result<Metrics> {
    serve_inner(listener, node, lifetime, stop, None, None)
}

/// Explicit protected development transport. The challenge adds no ledger authority.
pub fn serve_protected(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    policy: AdmissionPolicy,
) -> Result<Metrics> {
    serve_inner(listener, node, lifetime, stop, None, Some(policy))
}

/// Allowlisted authenticated development transport. It provides identity, replay and
/// response integrity, but no confidentiality, discovery, Sybil theorem or production use.
pub fn serve_authenticated(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    authentication: AuthenticatedServer,
) -> Result<Metrics> {
    serve_inner(
        listener,
        node,
        lifetime,
        stop,
        Some(Arc::new(authentication)),
        None,
    )
}

pub fn serve_authenticated_protected(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    authentication: AuthenticatedServer,
    policy: AdmissionPolicy,
) -> Result<Metrics> {
    serve_inner(
        listener,
        node,
        lifetime,
        stop,
        Some(Arc::new(authentication)),
        Some(policy),
    )
}

fn serve_inner(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    authentication: Option<Arc<AuthenticatedServer>>,
    admission: Option<AdmissionPolicy>,
) -> Result<Metrics> {
    node.require_classical_network_profile()?;
    let listener_address = listener.local_addr()?;
    if authentication.is_none() {
        ensure(
            listener_address.ip().is_loopback(),
            "DEVELOPMENT_LOOPBACK_ONLY",
        )?;
    }
    // A signed allowlist still does not pay verification CPU. Remote legacy
    // authenticated listeners must choose the pre-existing bounded transport
    // AdmissionPolicy; the unpriced authenticated-only transport is local-only.
    if !listener_address.ip().is_loopback() {
        ensure(admission.is_some(), "DEVELOPMENT_REMOTE_ADMISSION_REQUIRED")?;
    }
    // An allowlisted peer is not a CPU resource owner. All remotely exposed
    // legacy authenticated listeners must join the SAME administrator-owned
    // host cgroup as public V3 before accepting a single socket. A service
    // without that parent fails closed; no fresh per-listener CPU allowance.
    let host_kernel = crate::host_kernel_parent::require_for_listener(listener_address)?;
    ensure(
        lifetime > Duration::ZERO && lifetime <= Duration::from_secs(3600),
        "SERVER_BUDGET",
    )?;
    listener.set_nonblocking(true)?;
    let listeners = (0..3)
        .map(|_| listener.try_clone())
        .collect::<std::io::Result<Vec<_>>>()?;
    let settings = node.settings().clone();
    let node = Arc::new(Mutex::new(node));
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    let active_requests = Arc::new(Mutex::new(BTreeSet::new()));
    let (public, _local_recovery) = bounded_ingress();
    let mut handoff_senders = Vec::new();
    let mut handoff_receivers = Vec::new();
    for _ in 0..2 {
        let (sender, receiver) = mpsc::sync_channel::<PrefacedSocket>(0);
        handoff_senders.push(sender);
        handoff_receivers.push(Some(receiver));
    }
    handoff_receivers.push(None);
    let deadline = Instant::now() + lifetime;
    thread::scope(|scope| -> Result<()> {
        let mut workers = Vec::new();
        for (worker_index, (listener, handoff_receiver)) in
            listeners.into_iter().zip(handoff_receivers).enumerate()
        {
            let node = node.clone();
            let metrics = metrics.clone();
            let active_requests = active_requests.clone();
            let public = public.clone();
            let stop = stop.clone();
            let authentication = authentication.clone();
            let settings = settings.clone();
            let handoff_senders = handoff_senders.clone();
            let host_kernel_for_worker = host_kernel.as_ref();
            workers.push(scope.spawn(move || -> Result<()> {
                // Membership is checked on the ACTUAL native thread, not
                // only on the listener's different parent thread.
                if let Some(kernel) = host_kernel_for_worker {
                    kernel.verify()?;
                }
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    let handed = if admission.is_some() {
                        handoff_receiver.as_ref().and_then(|receiver| {
                            receiver
                                .recv_timeout(
                                    PROOF_HANDOFF_POLL
                                        .min(deadline.saturating_duration_since(Instant::now())),
                                )
                                .ok()
                        })
                    } else {
                        None
                    };
                    if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                        break;
                    }
                    let connection = if let Some(connection) = handed {
                        connection
                    } else {
                        let (mut socket, address) = match listener.accept() {
                            Ok(pair) => pair,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(2));
                                continue;
                            }
                            Err(e) => return Err(e.into()),
                        };
                        let request_deadline =
                            deadline.min(Instant::now() + Duration::from_secs(10));
                        metrics
                            .lock()
                            .map_err(|_| "METRICS_POISONED")?
                            .socket_connections += 1;
                        socket.set_nonblocking(false)?;
                        if admission.is_some() {
                            socket.set_nodelay(true)?;
                        }
                        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                        let preface_deadline = request_deadline.min(
                            Instant::now()
                                + if admission.is_some() {
                                    PROTECTED_PREFACE_BUDGET
                                } else {
                                    Duration::from_secs(5)
                                },
                        );
                        let bytes = match read_frame_deadline(&mut socket, preface_deadline) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
                                counts.malformed_requests += 1;
                                if admission.is_some() {
                                    counts.protected_preface_refusals += 1;
                                }
                                drop(counts);
                                let _ = write_untrusted_error(&mut socket, &e, admission.is_some());
                                continue;
                            }
                        };
                        PrefacedSocket {
                            socket,
                            address,
                            request_deadline,
                            preface_deadline,
                            first: bytes,
                        }
                    };
                    let connection = if admission.is_some()
                        && worker_index == 2
                        && connection.first.len() <= 512
                        && admission_hello(&connection.first).is_ok_and(|hello| hello.is_some())
                    {
                        match try_handoff_hello(connection, &handoff_senders) {
                            Ok(()) => {
                                metrics
                                    .lock()
                                    .map_err(|_| "METRICS_POISONED")?
                                    .admission_hello_handoffs += 1;
                                continue;
                            }
                            Err(connection) => connection,
                        }
                    } else {
                        connection
                    };
                    let PrefacedSocket {
                        mut socket,
                        address,
                        request_deadline,
                        preface_deadline,
                        first: bytes,
                    } = connection;
                    let (bytes, negotiated) = match receive_protected_request(
                        &mut socket,
                        bytes,
                        admission,
                        preface_deadline,
                        admission.is_none() || worker_index < 2,
                    ) {
                        Ok(request) => request,
                        Err(error) => {
                            let reserved_refusal = error.is(ErrorCode::ReservedReadOnlyBusy);
                            let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
                            if reserved_refusal {
                                counts.admission_reserved_read_only_refusals += 1;
                            } else {
                                counts.malformed_requests += 1;
                                if admission.is_some() {
                                    counts.protected_preface_refusals += 1;
                                }
                            }
                            drop(counts);
                            let _ = write_untrusted_error(&mut socket, &error, admission.is_some());
                            if reserved_refusal {
                                // A bounded yield mitigates accept competition with
                                // proof workers; it is not anonymous scheduling fairness.
                                thread::sleep(
                                    RESERVED_HELLO_YIELD
                                        .min(deadline.saturating_duration_since(Instant::now())),
                                );
                            }
                            continue;
                        }
                    };
                    let mut progress = |_: u64| -> Result<()> {
                        if stop.load(Ordering::Acquire) {
                            return Err(Error::new(ErrorCode::LegacyRequestCancelled));
                        }
                        if Instant::now() >= request_deadline {
                            return Err(Error::new(ErrorCode::LegacyRequestDeadline));
                        }
                        Ok(())
                    };
                    if let Some(authentication) = authentication.as_ref() {
                        let request = match authenticate_request(&bytes, &settings, authentication)
                        {
                            Ok(request) => request,
                            Err(error) => {
                                metrics
                                    .lock()
                                    .map_err(|_| Error::from("METRICS_POISONED"))?
                                    .malformed_requests += 1;
                                let _ =
                                    write_untrusted_error(&mut socket, &error, admission.is_some());
                                continue;
                            }
                        };
                        if let Err(error) = protect_submit(
                            &mut socket,
                            &request.request,
                            &bytes,
                            AdmissionHost {
                                settings: &settings,
                                policy: admission,
                                authentication: Some(authentication),
                                metrics: &metrics,
                                negotiated,
                            },
                            &mut progress,
                        ) {
                            let reply =
                                signed_response(authentication, &request, false, Err(error))?;
                            let _ = write_frame(&mut socket, &reply);
                            continue;
                        }
                        let _permit = if admission.is_some()
                            && !matches!(&request.request, Request::Submit { .. })
                        {
                            None
                        } else {
                            match public.try_acquire(
                                request.frame.session().peer_id().bytes(),
                                request.frame.payload_digest().bytes(),
                            ) {
                                Ok(permit) => Some(permit),
                                Err(error) => {
                                    metrics
                                        .lock()
                                        .map_err(|_| Error::from("METRICS_POISONED"))?
                                        .busy_requests += 1;
                                    let reply = signed_response(
                                        authentication,
                                        &request,
                                        false,
                                        Err(Error::from(format!("BUSY:{error:?}"))),
                                    )?;
                                    let _ = write_frame(&mut socket, &reply);
                                    continue;
                                }
                            }
                        };
                        let decision = {
                            let mut owner = lock_owner(&node, &mut progress)?;
                            begin_authenticated_dispatch(&mut owner, &request, &mut progress)
                        };
                        let decision = match decision {
                            Ok(decision) => decision,
                            Err(error) => {
                                metrics
                                    .lock()
                                    .map_err(|_| Error::from("METRICS_POISONED"))?
                                    .rejected_requests += 1;
                                let reply =
                                    signed_response(authentication, &request, false, Err(error))?;
                                let _ = write_frame(&mut socket, &reply);
                                continue;
                            }
                        };
                        if let AuthenticatedReplayDecision::Cached(reply) = decision {
                            // Revalidate retained bytes against this exact request before
                            // returning them. Disk corruption cannot become a signed replay.
                            let (terminal, ok, _) = verify_authenticated_response(
                                &reply,
                                &request.session,
                                request.frame.replay_nonce(),
                                request.request_digest,
                            )?;
                            ensure(terminal, "AUTH_CACHED_NONTERMINAL")?;
                            let mut counts = metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?;
                            counts.authenticated_requests += 1;
                            counts.replayed_responses += 1;
                            if ok {
                                counts.completed_requests += 1;
                            } else {
                                counts.rejected_requests += 1;
                            }
                            drop(counts);
                            let _ = write_frame(&mut socket, &reply);
                            continue;
                        }
                        let key = (
                            request.frame.session().session_id().bytes(),
                            request.frame.replay_nonce(),
                        );
                        let Some(_active) =
                            ActiveRequestGuard::acquire(active_requests.clone(), key)?
                        else {
                            let mut counts = metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?;
                            counts.busy_requests += 1;
                            counts.pending_busy_requests += 1;
                            drop(counts);
                            let reply = signed_response(
                                authentication,
                                &request,
                                false,
                                Err(Error::from("AUTH_PENDING_BUSY")),
                            )?;
                            let _ = write_frame(&mut socket, &reply);
                            continue;
                        };
                        let outcome = dispatch_shared_with(
                            &node,
                            request.request.clone(),
                            &mut progress,
                            |packet| {
                                if let Some(kernel) = host_kernel_for_worker {
                                    kernel.verify()?;
                                }
                                let checked = measured_work_verify(packet, &metrics)?;
                                // Recheck the actual worker after expensive W1, so a
                                // moved thread cannot promote its observed work.
                                if let Some(kernel) = host_kernel_for_worker {
                                    kernel.verify()?;
                                }
                                Ok(checked)
                            },
                        );
                        if outcome
                            .as_ref()
                            .is_err_and(|error| error.kind() == crate::ErrorKind::Cancelled)
                        {
                            // Cancellation can leave a committed block or a
                            // partial original reorg intent. Keep its exact
                            // pending nonce: a new signed socket attempt may
                            // resume it, but this request gets no new deadline
                            // and no terminal ACK is fabricated after cancel.
                            let retry = signed_response(authentication, &request, false, outcome)?;
                            let mut counts = metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?;
                            counts.authenticated_requests += 1;
                            counts.rejected_requests += 1;
                            drop(counts);
                            let _ = write_frame(&mut socket, &retry);
                            continue;
                        }
                        let succeeded = outcome.is_ok();
                        let terminal_reply =
                            signed_response(authentication, &request, true, outcome)?;
                        let finalized = {
                            let mut owner = lock_owner(&node, &mut progress)?;
                            owner.finish_authenticated_request(request.frame, &terminal_reply)
                        };
                        if let Err(error) = finalized {
                            let retry = signed_response(
                                authentication,
                                &request,
                                false,
                                Err(Error::from(format!("AUTH_RESPONSE_NOT_COMMITTED:{error}"))),
                            )?;
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .rejected_requests += 1;
                            let _ = write_frame(&mut socket, &retry);
                            continue;
                        }
                        let mut counts = metrics
                            .lock()
                            .map_err(|_| Error::from("METRICS_POISONED"))?;
                        counts.authenticated_requests += 1;
                        if succeeded {
                            counts.completed_requests += 1;
                        } else {
                            counts.rejected_requests += 1;
                        }
                        drop(counts);
                        let _ = write_frame(&mut socket, &terminal_reply);
                        continue;
                    }
                    let request: Request = match serde_json::from_slice(&bytes) {
                        Ok(request) => request,
                        Err(error) => {
                            metrics
                                .lock()
                                .map_err(|_| "METRICS_POISONED")?
                                .malformed_requests += 1;
                            let _ = write_untrusted_error(&mut socket, &error, admission.is_some());
                            continue;
                        }
                    };
                    if let Err(error) = protect_submit(
                        &mut socket,
                        &request,
                        &bytes,
                        AdmissionHost {
                            settings: &settings,
                            policy: admission,
                            authentication: None,
                            metrics: &metrics,
                            negotiated,
                        },
                        &mut progress,
                    ) {
                        let _ = write_untrusted_error(&mut socket, &error, admission.is_some());
                        continue;
                    }
                    let peer = hash(b"native-peer-ip", &[address.ip().to_string().as_bytes()]);
                    let _permit =
                        if admission.is_some() && !matches!(&request, Request::Submit { .. }) {
                            None
                        } else {
                            match public.try_acquire(peer, hash(b"native-request", &[&bytes])) {
                                Ok(permit) => Some(permit),
                                Err(error) => {
                                    metrics
                                        .lock()
                                        .map_err(|_| Error::from("METRICS_POISONED"))?
                                        .busy_requests += 1;
                                    let _ = write_frame(
                                        &mut socket,
                                        &serde_json::to_vec(
                                            &json!({"error":format!("BUSY:{error:?}")}),
                                        )?,
                                    );
                                    continue;
                                }
                            }
                        };
                    let result = dispatch_shared_with(&node, request, &mut progress, |packet| {
                        if let Some(kernel) = host_kernel_for_worker {
                            kernel.verify()?;
                        }
                        let checked = measured_work_verify(packet, &metrics)?;
                        if let Some(kernel) = host_kernel_for_worker {
                            kernel.verify()?;
                        }
                        Ok(checked)
                    });
                    let reply = match result {
                        Ok(value) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .completed_requests += 1;
                            value
                        }
                        Err(error) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .rejected_requests += 1;
                            json!({"error":error.to_string()})
                        }
                    };
                    let _ = write_frame(&mut socket, &serde_json::to_vec(&reply)?);
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| Error::from("WORKER_PANIC"))??;
        }
        Ok(())
    })?;
    let metrics = Arc::try_unwrap(metrics).map_err(|_| Error::from("METRICS_LIFETIME"))?;
    metrics.into_inner().map_err(|_| "METRICS_POISONED".into())
}

pub fn call(address: SocketAddr, request: &Request) -> Result<Value> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut stream, &serde_json::to_vec(request)?)?;
    let bytes = read_frame(&mut stream)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = value.get("error") {
        return Err(format!("REMOTE:{error}").into());
    }
    Ok(value)
}

fn protected_response(
    stream: &mut TcpStream,
    request: &Request,
    wire: &[u8],
    settings: &Settings,
    expected_server: Option<&str>,
    expected_profile: Option<Hash>,
) -> Result<Vec<u8>> {
    let first = read_frame(stream)?;
    if !matches!(request, Request::Submit { .. }) {
        return Ok(first);
    }
    let challenge: AdmissionChallenge =
        serde_json::from_slice(&first).map_err(|_| "ADMISSION_REQUIRED")?;
    ensure(
        serde_json::to_vec(&challenge)? == first,
        "ADMISSION_NONCANONICAL",
    )?;
    ensure(
        expected_profile.is_some_and(|profile| challenge.profile == hex::encode(profile)),
        "ADMISSION_NEGOTIATION_CONTEXT",
    )?;
    if let Some(server) = expected_server {
        ensure(challenge.server == server, "ADMISSION_SERVER")?;
    }
    let (solution, _) = solve_admission_challenge(&challenge, wire, settings)?;
    write_frame(stream, &serde_json::to_vec(&solution)?)?;
    read_frame(stream)
}

/// Strict opt-in. A legacy listener's ordinary Submit response is a downgrade refusal.
pub fn call_protected(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
) -> Result<Value> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let wire = serde_json::to_vec(request)?;
    let profile = write_protected_request_bound(&mut stream, request, &wire)?;
    let value: Value = serde_json::from_slice(&protected_response(
        &mut stream,
        request,
        &wire,
        settings,
        None,
        profile,
    )?)?;
    if let Some(error) = value.get("error") {
        return Err(format!("REMOTE:{error}").into());
    }
    Ok(value)
}

fn bounded_rpc_deadline(outer: Option<Instant>) -> Result<Instant> {
    let end = Instant::now() + Duration::from_secs(5);
    let end = outer.map_or(end, |outer| end.min(outer));
    ensure(Instant::now() < end, "PUBLIC_CLIENT_DEADLINE")?;
    Ok(end)
}

/// A valid terminal response advances the caller-owned nonce. Network failures and
/// nonterminal Busy responses preserve it for exact retry.
pub fn call_authenticated(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Value> {
    call_authenticated_inner(
        address,
        request,
        settings,
        client,
        replay_nonce,
        false,
        None,
    )
}
pub fn call_authenticated_protected(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Value> {
    call_authenticated_inner(address, request, settings, client, replay_nonce, true, None)
}
fn call_authenticated_inner(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
    protected: bool,
    outer_deadline: Option<Instant>,
) -> Result<Value> {
    // Deadline-aware History uses the unprotected authenticated transport.
    ensure(!protected || outer_deadline.is_none(), "PUBLIC_OPERATION")?;
    let nonce = *replay_nonce;
    let bytes = authenticated_request_bytes(settings, client, nonce, request.clone())?;
    let envelope: AuthenticatedRequest = serde_json::from_slice(&bytes)?;
    let request_digest =
        request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)?;
    let connect_end = bounded_rpc_deadline(outer_deadline)?;
    let remaining = connect_end
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("PUBLIC_CLIENT_DEADLINE")?;
    let mut stream = TcpStream::connect_timeout(&address, remaining)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let profile = if protected {
        write_protected_request_bound(&mut stream, request, &bytes)?
    } else {
        write_frame_deadline(&mut stream, &bytes, bounded_rpc_deadline(outer_deadline)?)?;
        None
    };
    let response = if protected {
        protected_response(
            &mut stream,
            request,
            &bytes,
            settings,
            Some(&client.server_public),
            profile,
        )?
    } else {
        read_frame_deadline(&mut stream, bounded_rpc_deadline(outer_deadline)?)?
    };
    let (terminal, ok, value) =
        verify_authenticated_response(&response, &envelope.session, nonce, request_digest)?;
    if terminal {
        *replay_nonce = nonce.checked_add(1).ok_or("AUTH_REPLAY_OVERFLOW")?;
    }
    if ok {
        return Ok(value);
    }
    let error = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("AUTH_REMOTE_ERROR");
    Err(Error::authenticated_remote(terminal, error))
}

fn outbound_authenticated_request(
    bytes: &[u8],
    settings: &Settings,
    client: &AuthenticatedClient,
) -> Result<VerifiedAuthenticatedRequest> {
    let envelope: AuthenticatedRequest = serde_json::from_slice(bytes)?;
    ensure(
        serde_json::to_vec(&envelope)? == bytes,
        "AUTH_OUTBOX_NONCANONICAL",
    )?;
    ensure(envelope.schema == AUTH_REQUEST_SCHEMA, "AUTH_OUTBOX_SCHEMA")?;
    let expected = authenticated_session(
        settings,
        client.identity.public_key(),
        &client.server_public,
        client.generation,
    )?;
    ensure(envelope.session == expected, "AUTH_OUTBOX_CONTEXT")?;
    let authority =
        request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)?;
    verify_hex_strict(&envelope.session.peer, &authority, &envelope.signature)
        .map_err(|error| Error::from(format!("AUTH_OUTBOX_SIGNATURE:{error}")))?;
    let payload = serde_json::to_vec(&envelope.request)?;
    let frame = AuthenticatedPeerFrameV0::new(
        transport_session(&envelope.session)?,
        envelope.replay_nonce,
        IoDigest32V0::new(authenticated_payload_digest(&payload))
            .map_err(|error| Error::from(format!("AUTH_OUTBOX_FRAME:{error}")))?,
        payload.len(),
    )
    .map_err(|error| Error::from(format!("AUTH_OUTBOX_FRAME:{error}")))?;
    Ok(VerifiedAuthenticatedRequest {
        wire: bytes.to_vec(),
        request: envelope.request,
        session: envelope.session,
        frame,
        payload,
        request_digest: authority,
    })
}

/// Recover the exact pending request through the existing durable outbox and
/// strict session/signature verifier. This exposes no key, wire or database handle.
pub fn pending_authenticated_request(
    node: &Node,
    client: &AuthenticatedClient,
) -> Result<Option<Request>> {
    let settings = node.settings();
    let session = authenticated_session(
        settings,
        client.identity.public_key(),
        &client.server_public,
        client.generation,
    )?;
    let (nonce, pending) = node.authenticated_outbound_reservation(transport_session(&session)?)?;
    pending
        .map(|wire| {
            let verified = outbound_authenticated_request(&wire, settings, client)?;
            ensure(verified.frame.replay_nonce() == nonce, "AUTH_OUTBOX_NONCE")?;
            Ok(verified.request)
        })
        .transpose()
}

/// Persist one exact signed request before network I/O. A missing or nonterminal response
/// leaves the same bytes pending; a verified terminal response advances the durable nonce.
pub fn call_authenticated_durable(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
) -> Result<Value> {
    call_authenticated_durable_inner(node, address, request, client, false, None)
}
pub fn call_authenticated_durable_protected(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
) -> Result<Value> {
    call_authenticated_durable_inner(node, address, request, client, true, None)
}
fn call_authenticated_durable_inner(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
    protected: bool,
    outer_deadline: Option<Instant>,
) -> Result<Value> {
    // Deadline-aware History uses the unprotected authenticated transport.
    ensure(!protected || outer_deadline.is_none(), "PUBLIC_OPERATION")?;
    let settings = node.settings().clone();
    let session = authenticated_session(
        &settings,
        client.identity.public_key(),
        &client.server_public,
        client.generation,
    )?;
    let transport = transport_session(&session)?;
    let (nonce, pending) = node.authenticated_outbound_reservation(transport)?;
    let verified = match pending {
        Some(wire) => {
            let verified = outbound_authenticated_request(&wire, &settings, client)?;
            ensure(verified.frame.replay_nonce() == nonce, "AUTH_OUTBOX_NONCE")?;
            ensure(verified.request == *request, "AUTH_OUTBOX_PENDING")?;
            verified
        }
        None => {
            let wire = authenticated_request_bytes(&settings, client, nonce, request.clone())?;
            let verified = outbound_authenticated_request(&wire, &settings, client)?;
            let retained = node.reserve_authenticated_outbound(
                verified.frame,
                &verified.payload,
                &verified.wire,
            )?;
            ensure(retained == verified.wire, "AUTH_OUTBOX_WIRE")?;
            verified
        }
    };
    let connect_end = bounded_rpc_deadline(outer_deadline)?;
    let remaining = connect_end
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("PUBLIC_CLIENT_DEADLINE")?;
    let mut stream = TcpStream::connect_timeout(&address, remaining)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let profile = if protected {
        write_protected_request_bound(&mut stream, request, &verified.wire)?
    } else {
        write_frame_deadline(
            &mut stream,
            &verified.wire,
            bounded_rpc_deadline(outer_deadline)?,
        )?;
        None
    };
    let response = if protected {
        protected_response(
            &mut stream,
            request,
            &verified.wire,
            &settings,
            Some(&client.server_public),
            profile,
        )?
    } else {
        read_frame_deadline(&mut stream, bounded_rpc_deadline(outer_deadline)?)?
    };
    let (terminal, ok, value) = verify_authenticated_response(
        &response,
        &verified.session,
        verified.frame.replay_nonce(),
        verified.request_digest,
    )?;
    if terminal {
        node.finish_authenticated_outbound(verified.frame)?;
    }
    if ok {
        return Ok(value);
    }
    let error = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("AUTH_REMOTE_ERROR");
    Err(Error::authenticated_remote(terminal, error))
}

// A fixed cgroup is enforced by the kernel. Recheck current worker and
// unchanged Host limits at original W1 stage boundaries: at most 64 transcript
// tiles proceed without a physical owner recheck. These are resource checks,
// not mathematical W1 validity or blockchain authorization.
fn history_kernel_work_checkpoint(
    point: trnm_crypto_primitives::pon_work::VerificationProgress,
) -> bool {
    use trnm_crypto_primitives::pon_work::VerificationProgress;
    match point {
        VerificationProgress::BeforeReplay
        | VerificationProgress::BeforeProduct
        | VerificationProgress::BeforeVerifiedWork => true,
        VerificationProgress::Noise { counter, .. } => counter % 32 == 0,
        VerificationProgress::MatrixRow { row } => row % 32 == 0,
        VerificationProgress::TranscriptTile { column, inner, .. } => column == 0 && inner == 0,
    }
}

pub(crate) mod history_import;

// Retained native test fixtures used the old local five-argument reader.
// Keep that crate-private test surface, but route it through the same paid
// History implementation and crash fence; no production addressless bypass.
#[cfg(test)]
pub(crate) fn receive_page(
    node: &mut Node,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
) -> Result<Hash> {
    receive_page_from(
        node,
        "127.0.0.1:1".parse().expect("fixed loopback"),
        page,
        tip,
        after,
        clock,
    )
}

/// Public untrusted History import. Unlike the private local parser, this
/// entry REQUIRES a concrete original source address and checks the existing
/// fixed, administrator-owned host resource parent around every possible
/// W1 replay. A caller cannot bypass the guard by calling the addressless
/// parser from another crate or by supplying a fake already-verified work
/// token. Only the full native Node determines consensus validity.
#[cfg(test)]
pub(crate) fn receive_page_from(
    node: &mut Node,
    source: SocketAddr,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
) -> Result<Hash> {
    receive_page_from_before(
        node,
        source,
        page,
        tip,
        after,
        clock,
        Instant::now() + history_import::PAGE_BUDGET,
    )
}
fn receive_page_from_before(
    node: &mut Node,
    source: SocketAddr,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
    deadline: Instant,
) -> Result<Hash> {
    let host_kernel = crate::host_kernel_parent::require_for_listener(source)?;
    if let Some(kernel) = &host_kernel {
        kernel.verify()?;
    }
    let resource = || {
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        Ok(())
    };
    let native = history_import::receive(
        history_import::Owner::Exclusive(node),
        page,
        tip,
        after,
        clock,
        history_import::Control {
            deadline,
            resource: &resource,
        },
    );
    // A completed native admission cannot be undone by a post-verification
    // host fault. That fault still makes the overall synchronization fail.
    if let Some(kernel) = &host_kernel {
        kernel.verify()?;
    }
    native
}
/// Public History import is untrusted even when a local TCP proxy carries
/// remote packets through a loopback address. No external caller can select
/// the weaker native development compatibility wrapper.
///
/// ```compile_fail
/// use trnm_pon_node::ingress::receive_page_from;
/// fn main() {}
/// ```
pub fn receive_public_page_from(
    node: &mut Node,
    source: SocketAddr,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
) -> Result<Hash> {
    receive_public_page_from_before(
        node,
        source,
        page,
        tip,
        after,
        clock,
        Instant::now() + history_import::PAGE_BUDGET,
    )
}
/// The caller supplies one original business deadline, shared across pages.
/// Busy/expiry does not classify a proof as invalid or undo a durable commit.
pub fn receive_public_page_from_before(
    node: &mut Node,
    source: SocketAddr,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
    deadline: Instant,
) -> Result<Hash> {
    // The ORIGINAL fixed administrator-owned Host parent is required even
    // for a loopback source: a caller's socket address is not provenance.
    let kernel = crate::host_kernel_parent::require_host_kernel_budget(
        source,
        Some(crate::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
    )?
    .ok_or("PUBLIC_HOST_KERNEL_REQUIRED")?;
    kernel.verify()?;
    let native = history_import::receive(
        history_import::Owner::Exclusive(node),
        page,
        tip,
        after,
        clock,
        history_import::Control {
            deadline,
            resource: &|| kernel.verify(),
        },
    );
    // Do not convert an already committed block into an invalid work proof
    // when the last local Host owner observation fails.
    kernel.verify()?;
    native
}

/// Shared public History import: refill and full W1 never hold the Node mutex.
/// It uses the same Host parent, original CPU account and durable epoch as the
/// exclusive compatibility API; continuous imports stay denied by #498.
pub fn receive_public_page_from_shared(
    node: &Mutex<Node>,
    source: SocketAddr,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
    deadline: Instant,
) -> Result<Hash> {
    let kernel = crate::host_kernel_parent::require_host_kernel_budget(
        source,
        Some(crate::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
    )?
    .ok_or("PUBLIC_HOST_KERNEL_REQUIRED")?;
    kernel.verify()?;
    let result = history_import::receive(
        history_import::Owner::Shared(node),
        page,
        tip,
        after,
        clock,
        history_import::Control {
            deadline,
            resource: &|| kernel.verify(),
        },
    );
    kernel.verify()?;
    result
}

pub fn sync_from(
    node: &mut Node,
    address: SocketAddr,
    tip: Hash,
    mut after: Hash,
    page_budget: usize,
) -> Result<Hash> {
    let deadline = Instant::now() + history_import::SYNC_BUDGET;
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    // Every WAN page may contain 16 untrusted W1 proofs. The same fixed,
    // administrator-owned host cgroup used by V3 must already contain this
    // actual sync thread; no new per-peer budget or consensus authority.
    let host_kernel = crate::host_kernel_parent::require_for_listener(address)?;
    for _ in 0..page_budget {
        ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")?;
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        let request = Request::History {
            tip: hex::encode(tip),
            after: hex::encode(after),
        };
        let connect_end = bounded_rpc_deadline(Some(deadline))?;
        let remaining = connect_end
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or("PUBLIC_CLIENT_DEADLINE")?;
        let mut stream = TcpStream::connect_timeout(&address, remaining)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        write_frame_deadline(
            &mut stream,
            &serde_json::to_vec(&request)?,
            bounded_rpc_deadline(Some(deadline))?,
        )?;
        let page: Page = serde_json::from_slice(&read_frame_deadline(
            &mut stream,
            bounded_rpc_deadline(Some(deadline))?,
        )?)?;
        let complete = page.complete;
        after = receive_page_from_before(node, address, page, tip, after, now()?, deadline)?;
        // Resource-counter/membership failure does not roll back any already
        // admitted native block; it makes this sync result unqualified.
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        if complete {
            return Ok(after);
        }
    }
    Err(format!(
        "INCOMPLETE_HISTORY:page_budget:after={}",
        hex::encode(after)
    )
    .into())
}

pub fn sync_from_authenticated(
    node: &mut Node,
    address: SocketAddr,
    tip: Hash,
    mut after: Hash,
    page_budget: usize,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Hash> {
    let deadline = Instant::now() + history_import::SYNC_BUDGET;
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    // Every WAN page may contain 16 untrusted W1 proofs. The same fixed,
    // administrator-owned host cgroup used by V3 must already contain this
    // actual sync thread; no new per-peer budget or consensus authority.
    let host_kernel = crate::host_kernel_parent::require_for_listener(address)?;
    let settings = node.settings().clone();
    for _ in 0..page_budget {
        ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")?;
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        let value = call_authenticated_inner(
            address,
            &Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            &settings,
            client,
            replay_nonce,
            false,
            Some(deadline),
        )?;
        let page: Page = serde_json::from_value(value)?;
        let complete = page.complete;
        after = receive_page_from_before(node, address, page, tip, after, now()?, deadline)?;
        // Resource-counter/membership failure does not roll back any already
        // admitted native block; it makes this sync result unqualified.
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        if complete {
            return Ok(after);
        }
    }
    Err(format!(
        "INCOMPLETE_HISTORY:page_budget:after={}",
        hex::encode(after)
    )
    .into())
}

pub fn sync_from_authenticated_durable(
    node: &mut Node,
    address: SocketAddr,
    tip: Hash,
    mut after: Hash,
    page_budget: usize,
    client: &AuthenticatedClient,
) -> Result<Hash> {
    let deadline = Instant::now() + history_import::SYNC_BUDGET;
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    // Every WAN page may contain 16 untrusted W1 proofs. The same fixed,
    // administrator-owned host cgroup used by V3 must already contain this
    // actual sync thread; no new per-peer budget or consensus authority.
    let host_kernel = crate::host_kernel_parent::require_for_listener(address)?;
    for _ in 0..page_budget {
        ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")?;
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        let value = call_authenticated_durable_inner(
            node,
            address,
            &Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            client,
            false,
            Some(deadline),
        )?;
        let page: Page = serde_json::from_value(value)?;
        let complete = page.complete;
        after = receive_page_from_before(node, address, page, tip, after, now()?, deadline)?;
        // Resource-counter/membership failure does not roll back any already
        // admitted native block; it makes this sync result unqualified.
        if let Some(kernel) = &host_kernel {
            kernel.verify()?;
        }
        if complete {
            return Ok(after);
        }
    }
    Err(format!(
        "INCOMPLETE_HISTORY:page_budget:after={}",
        hex::encode(after)
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod authenticated_activation_recovery {
        include!("ingress/authenticated_recovery_tests.rs");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_paid_epoch_crash_cut_refuses_new_cold_credit() {
        // Simulated abrupt process exit AFTER the durable active marker but
        // BEFORE the original History CPU operation could be settled. This
        // is a local SQLite cold-reopen negative, not a physical power cut.
        let settings = crate::Settings::development(Some(now().unwrap() - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut original = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let account = original.remote_history_cpu_domain().unwrap();
        assert_eq!(account.observe().unwrap().stored_credit_ns, 0);
        assert!(original.begin_remote_history_cpu_epoch().unwrap());
        drop(original);
        let mut reopened = Node::open(dir.path(), settings, 2).unwrap();
        assert_eq!(
            reopened
                .remote_history_cpu_domain()
                .err()
                .unwrap()
                .to_string(),
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
        );
        assert!(reopened.public_service_cpu_domain().is_err());
        assert_eq!(
            reopened
                .begin_remote_history_cpu_epoch()
                .unwrap_err()
                .to_string(),
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_paid_history_rejection_closes_known_epoch_without_poisoning_cold_reopen() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let initial = node.stats().unwrap();
        let page = Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode([19; 32]),
            after: hex::encode(settings.genesis()),
            packets: vec!["00".into()],
            next: hex::encode([19; 32]),
            complete: true,
        };
        let loopback: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(receive_page_from(
            &mut node,
            loopback,
            page,
            [19; 32],
            settings.genesis(),
            observed,
        )
        .is_err());
        let account = node.public_service_cpu_domain().unwrap();
        let metered = account.observe().unwrap();
        assert_eq!(metered.in_flight, 0);
        assert!(!metered.accounting_unavailable);
        assert!(metered.stored_credit_ns >= 0);
        let marker_count: i64 = rusqlite::Connection::open(dir.path().join("native.sqlite"))
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM metadata WHERE key=?1",
                ["ordinary-public-v3-epoch-v1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker_count, 0, "paid known rejection must clean its epoch");
        assert_eq!(node.stats().unwrap(), initial);
        drop(node);
        let mut reopened = Node::open(dir.path(), settings, 2).unwrap();
        let fresh = reopened.remote_history_cpu_domain().unwrap();
        assert_eq!(fresh.observe().unwrap().stored_credit_ns, 0);
        assert_eq!(reopened.stats().unwrap(), initial);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standalone_history_does_not_steal_live_v3_listener_epoch() {
        let settings = crate::Settings::development(Some(now().unwrap() - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings, 2).unwrap();
        let public = public_v3::ServiceMutationCpuDomain::standalone();
        node.bind_public_service_cpu_domain(&public).unwrap();
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        assert!(node.begin_remote_history_cpu_epoch().unwrap());
        assert!(node
            .public_service_cpu_domain()
            .unwrap()
            .shares_domain_with(&public));
        // The importer owns one reference, never the listener's last-close
        // right. Its close must leave the original durable marker present.
        node.finish_remote_history_cpu_epoch(&public).unwrap();
        // Only the actual V3 owner holds the last-close right.
        node.finish_ordinary_public_service_epoch(true).unwrap();
        assert_eq!(
            rusqlite::Connection::open(dir.path().join("native.sqlite"))
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM metadata WHERE key=?1",
                    ["ordinary-public-v3-epoch-v1"],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn malformed_remote_history_decode_pays_original_cpu_and_preserves_state() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let start = node.stats().unwrap();
        let source: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let page = Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode([9; 32]),
            after: hex::encode(settings.genesis()),
            packets: vec!["00".into()],
            next: hex::encode([9; 32]),
            complete: true,
        };
        assert!(receive_page_from(
            &mut node,
            source,
            page,
            [9; 32],
            settings.genesis(),
            observed,
        )
        .is_err());
        let account = node.public_service_cpu_domain().unwrap().observe().unwrap();
        assert_eq!(account.in_flight, 0);
        assert!(!account.accounting_unavailable);
        assert_eq!(node.stats().unwrap(), start);
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mixed_false_then_valid_history_across_source_ports_reuses_one_cpu_owner() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let good = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10,
                4096,
            )
            .unwrap();
        let id = good.id().unwrap();
        let mut bad = good.clone();
        let cell = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
        let prior = u32::from_le_bytes(bad.proof[cell..cell + 4].try_into().unwrap());
        let altered = ((u128::from(prior) + 1) % trnm_crypto_primitives::pon_work::Q) as u32;
        bad.proof[cell..cell + 4].copy_from_slice(&altered.to_le_bytes());
        assert_eq!(bad.id().unwrap(), id);
        let make_page = |packet: &Packet| Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        };
        let first: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let initial = node.stats().unwrap();
        assert_eq!(
            receive_page_from(
                &mut node,
                first,
                make_page(&bad),
                id,
                settings.genesis(),
                observed,
            )
            .unwrap_err()
            .to_string(),
            "WORK:Product"
        );
        assert_eq!(node.stats().unwrap(), initial);
        let original_domain = node.public_service_cpu_domain().unwrap();
        assert_eq!(
            receive_page_from(
                &mut node,
                second,
                make_page(&good),
                id,
                settings.genesis(),
                observed,
            )
            .unwrap(),
            id
        );
        assert!(node
            .public_service_cpu_domain()
            .unwrap()
            .shares_domain_with(&original_domain));
        assert_eq!(node.read_active().unwrap().0, id);
        assert_eq!(original_domain.observe().unwrap().in_flight, 0);
        let success_state = node.stats().unwrap();
        // The exact block ID's stored byte identity is authoritative; the
        // previously invalid C cannot overwrite the now accepted legal proof.
        let repeated = receive_page_from(
            &mut node,
            first,
            make_page(&bad),
            id,
            settings.genesis(),
            observed,
        )
        .unwrap_err();
        assert_eq!(repeated.to_string(), "DUPLICATE_CONTENT");
        assert_eq!(node.stats().unwrap(), success_state);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn four_distinct_ticket_valid_false_history_traces_never_obtain_work() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        // The legal packet is the honest control only. Attacker proofs below
        // are synthesized by hashing arbitrary trace claims without replay.
        let honest = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10,
                4096,
            )
            .unwrap();
        let challenge = honest.header.challenge();
        let task = honest.header.work_task;
        let target = honest.header.target;
        let initial = node.stats().unwrap();
        let mut accepted_tickets = 0;
        let mut original_budget = None;
        for nonce in 0..128_u64 {
            let trace = hash(
                b"history-four-false-transcripts-v1",
                &[&challenge, &nonce.to_le_bytes()],
            );
            let ticket = hash(b"ticket", &[&challenge, &trace]);
            if target == [0; 32] || ticket > target {
                continue;
            }
            let mut fake = honest.clone();
            let product = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
            fake.proof[product..product + trnm_crypto_primitives::pon_work::CELLS * 4].fill(0);
            fake.proof[trnm_crypto_primitives::pon_work::PROOF_BYTES - 32..]
                .copy_from_slice(&trace);
            assert_eq!(
                trnm_crypto_primitives::pon_work::precheck_proof_statement(
                    challenge,
                    task,
                    target,
                    &fake.proof,
                ),
                Ok(())
            );
            let id = fake.id().unwrap();
            let page = Page {
                schema: "pon-native-history-v1".into(),
                network: hex::encode(settings.network()),
                parameters: hex::encode(settings.parameters()),
                genesis: hex::encode(settings.genesis()),
                tip: hex::encode(id),
                after: hex::encode(settings.genesis()),
                packets: vec![hex::encode(fake.encode().unwrap())],
                next: hex::encode(id),
                complete: true,
            };
            let source: SocketAddr = format!("127.0.0.1:{}", nonce + 1).parse().unwrap();
            let error =
                receive_page_from(&mut node, source, page, id, settings.genesis(), observed)
                    .unwrap_err();
            assert_eq!(error.to_string(), "WORK:Transcript");
            let domain = node.public_service_cpu_domain().unwrap();
            if let Some(previous) = &original_budget {
                assert!(domain.shares_domain_with(previous));
            } else {
                original_budget = Some(domain.clone());
            }
            assert_eq!(domain.observe().unwrap().in_flight, 0);
            assert_eq!(node.stats().unwrap(), initial);
            assert_eq!(node.read_active().unwrap().0, settings.genesis());
            accepted_tickets += 1;
            if accepted_tickets == 4 {
                break;
            }
        }
        assert_eq!(
            accepted_tickets, 4,
            "the fixed target must yield four false claims"
        );
        let id = honest.id().unwrap();
        let legal_page = Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(honest.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        };
        assert_eq!(
            receive_page_from(
                &mut node,
                "127.0.0.1:999".parse().unwrap(),
                legal_page,
                id,
                settings.genesis(),
                observed,
            )
            .unwrap(),
            id
        );
        assert_eq!(node.read_active().unwrap().0, id);
        assert_eq!(
            node.public_service_cpu_domain()
                .unwrap()
                .observe()
                .unwrap()
                .in_flight,
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_history_false_product_charges_one_cold_node_cpu_domain() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let mut packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10,
                4096,
            )
            .unwrap();
        // Keep a correct winning trace/ticket; forge only canonical C, forcing
        // a late complete W1 Product rejection, not a cheap target miss.
        let cell = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
        let original = u32::from_le_bytes(packet.proof[cell..cell + 4].try_into().unwrap());
        let forged = ((u128::from(original) + 1) % trnm_crypto_primitives::pon_work::Q) as u32;
        packet.proof[cell..cell + 4].copy_from_slice(&forged.to_le_bytes());
        let id = packet.id().unwrap();
        let page = Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        };
        assert!(node.public_service_cpu_domain().is_err());
        let state_before = node.stats().unwrap();
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let error = receive_page_from(&mut node, address, page, id, settings.genesis(), observed)
            .unwrap_err();
        assert_eq!(error.to_string(), "WORK:Product");
        let domain = node.public_service_cpu_domain().unwrap();
        let reloaded = node.remote_history_cpu_domain().unwrap();
        assert!(domain.shares_domain_with(&reloaded));
        let receipt = domain.observe().unwrap();
        assert_eq!(receipt.in_flight, 0);
        assert!(!receipt.accounting_unavailable);
        assert!(receipt.stored_credit_ns <= i128::from(receipt.burst_ns));
        assert_eq!(node.stats().unwrap(), state_before);
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
        drop(node);
        let reopened = Node::open(dir.path(), settings.clone(), 2).unwrap();
        assert_eq!(reopened.stats().unwrap(), state_before);
        assert_eq!(reopened.read_active().unwrap().0, settings.genesis());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_history_valid_work_still_accepts_under_cold_cpu_meter() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10,
                4096,
            )
            .unwrap();
        let id = packet.id().unwrap();
        let page = Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        };
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(
            receive_page_from(&mut node, address, page, id, settings.genesis(), observed).unwrap(),
            id
        );
        assert_eq!(node.read_active().unwrap().0, id);
        let receipt = node.public_service_cpu_domain().unwrap().observe().unwrap();
        assert_eq!(receipt.in_flight, 0);
        assert!(!receipt.accounting_unavailable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cold_reopen_with_durable_active_v3_epoch_cannot_mint_history_cpu() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        // Emulate a service disappearing before its original clean epoch
        // closure; the SQLite active marker is durable, not a test-only bool.
        drop(node);
        let mut reopened = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let stats = reopened.stats().unwrap();
        assert_eq!(
            reopened
                .remote_history_cpu_domain()
                .err()
                .unwrap()
                .to_string(),
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
        );
        assert!(reopened.public_service_cpu_domain().is_err());
        assert_eq!(reopened.stats().unwrap(), stats);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clean_v3_epoch_close_permits_only_one_cold_history_owner() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        node.finish_ordinary_public_service_epoch(true).unwrap();
        drop(node);
        let mut reopened = Node::open(dir.path(), settings, 2).unwrap();
        let first = reopened.remote_history_cpu_domain().unwrap();
        let next = reopened.remote_history_cpu_domain().unwrap();
        assert!(first.shares_domain_with(&next));
        let initial = first.observe().unwrap();
        assert_eq!(initial.stored_credit_ns, 0);
        assert_eq!(initial.in_flight, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unclean_public_epoch_cannot_mint_fresh_remote_history_credit() {
        let observed = now().unwrap();
        let settings = crate::Settings::development(Some(observed - 100)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), settings, 2).unwrap();
        node.mark_ordinary_public_service_epoch_unknown();
        assert_eq!(
            node.remote_history_cpu_domain().err().unwrap().to_string(),
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
        );
    }

    #[test]
    fn history_valid_w1_cannot_commit_after_m06_host_owner_rejection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use trnm_crypto_primitives::pon_work::VerificationProgress;
        use trnm_mvcc_fee::pon_executor::ExecutionProgress;
        let (dir, mutex, packet) = pending_packet();
        let mut node = mutex.lock().unwrap();
        let original = node.stats().unwrap();
        let original_active = node.read_active().unwrap();
        let id = packet.id().unwrap();
        let m06_checks = AtomicUsize::new(0);
        let mut tiles = 0_usize;
        let result = node.admit_with_work_progress(
            &packet,
            now().unwrap(),
            &mut |point| {
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    tiles += 1;
                }
                Ok(())
            },
            &|stage| {
                if stage == ExecutionProgress::BeforeDurableCommit {
                    m06_checks.fetch_add(1, Ordering::SeqCst);
                    return Err(Error::from("PUBLIC_HOST_KERNEL_LIMITS_CHANGED"));
                }
                Ok(())
            },
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_LIMITS_CHANGED"
        );
        assert_eq!(tiles, 512, "valid W1 must have completed full replay");
        assert!(m06_checks.load(Ordering::SeqCst) > 0);
        assert_eq!(node.stats().unwrap(), original);
        assert_eq!(node.read_active().unwrap(), original_active);
        let persisted: u64 = rusqlite::Connection::open(dir.path().join("native.sqlite"))
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            persisted, 0,
            "precommit owner fault must roll back all block rows"
        );
        // Host error is local, not mathematical Invalid. Later reuse of the
        // exact valid W1 must succeed after the resource owner is restored.
        assert_eq!(node.admit(&packet, now().unwrap()).unwrap(), id);
    }

    #[test]
    fn kernel_progress_rechecks_original_host_at_most_every_64_tiles() {
        use trnm_crypto_primitives::pon_work::VerificationProgress;
        let mut owner_checks = Vec::new();
        for ordinal in 0..512_usize {
            let point = VerificationProgress::TranscriptTile {
                row: ordinal / 64,
                column: (ordinal / 8) % 8,
                inner: ordinal % 8,
            };
            if history_kernel_work_checkpoint(point) {
                owner_checks.push(ordinal);
            }
        }
        assert_eq!(owner_checks, vec![0, 64, 128, 192, 256, 320, 384, 448]);
        for point in [
            VerificationProgress::BeforeReplay,
            VerificationProgress::BeforeProduct,
            VerificationProgress::BeforeVerifiedWork,
            VerificationProgress::Noise {
                label: 1,
                counter: 0,
            },
            VerificationProgress::MatrixRow { row: 0 },
        ] {
            assert!(history_kernel_work_checkpoint(point));
        }
        assert!(!history_kernel_work_checkpoint(
            VerificationProgress::Noise {
                label: 1,
                counter: 1
            }
        ));
    }

    #[test]
    fn host_owner_failure_during_w1_tile_does_not_commit_or_poison_retry() {
        // Exercise the actual Node verification path, not just the progress
        // selector. A local Host guard failure is NOT invalid chain work.
        let (_dir, owner, packet) = pending_packet();
        let mut node = owner.lock().unwrap();
        let before_stats = node.stats().unwrap();
        let before_active = node.read_active().unwrap();
        let mut tiles = 0_usize;
        let refused = node
            .admit_with_work_progress(&packet, now().unwrap(), &mut |point| {
                if matches!(
                    point,
                    trnm_crypto_primitives::pon_work::VerificationProgress::TranscriptTile { .. }
                ) {
                    tiles += 1;
                    return Err("PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into());
                }
                Ok(())
            },
            &|_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(refused.to_string(), "PUBLIC_HOST_KERNEL_LIMITS_CHANGED");
        assert_eq!(
            tiles, 1,
            "full W1 must abort cooperatively before verified work"
        );
        assert_eq!(node.stats().unwrap(), before_stats);
        assert_eq!(node.read_active().unwrap(), before_active);
        // Recovery from a LOCAL Host refusal must not poison the unchanged
        // mathematical statement or turn it into a cached invalid W1 fact.
        let admitted = node.admit(&packet, now().unwrap()).unwrap();
        assert_eq!(admitted, packet.id().unwrap());
    }

    #[test]
    fn public_loopback_history_requires_real_fixed_host_parent() {
        let loopback: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let legacy = crate::host_kernel_parent::require_for_listener(loopback).unwrap();
        assert!(
            legacy.is_none(),
            "weak local compatibility remains local only"
        );
        let strict = crate::host_kernel_parent::require_host_kernel_budget(
            loopback,
            Some(crate::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
        );
        // A real matching parent yields Some; an unprovisioned one returns an
        // operational refusal. Neither is an unguarded None for public import.
        assert!(!matches!(strict, Ok(None)));
    }

    #[test]
    fn remote_sync_without_original_host_cgroup_rejects_before_any_network_or_w1() {
        // Documentation-only network address. If this host really has the
        // registered fixed cgroup, its owner is tested by the kernel checker.
        // Otherwise remote history cannot reach a complete W1 verifier.
        let remote: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let budget = crate::host_kernel_parent::require_for_listener(remote);
        assert!(!matches!(budget, Ok(None)), "remote must never be unowned");
        if let Err(expected) = budget {
            let dir = tempfile::tempdir().unwrap();
            let settings = crate::Settings::development(Some(now().unwrap() - 100)).unwrap();
            let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
            let original = node.stats().unwrap();
            let error = sync_from(&mut node, remote, settings.genesis(), settings.genesis(), 1)
                .unwrap_err();
            assert_eq!(error.to_string(), expected.to_string());
            // Public untrusted page API refuses the same unbudgeted source
            // before it even attempts a page context/W1/State lookup.
            let unchecked_page = Page {
                schema: String::new(),
                network: String::new(),
                parameters: String::new(),
                genesis: String::new(),
                tip: String::new(),
                after: String::new(),
                packets: vec![],
                next: String::new(),
                complete: false,
            };
            let page_error = receive_page_from(
                &mut node,
                remote,
                unchecked_page,
                settings.genesis(),
                settings.genesis(),
                now().unwrap(),
            )
            .unwrap_err();
            assert_eq!(page_error.to_string(), expected.to_string());
            // Authenticating a remote service is not equivalent to a CPU
            // budget. Both signed and durable signed sync must refuse before
            // connecting, same as the unauthenticated remote sync above.
            let (_, client) = authentication_fixture(&settings);
            let mut replay_nonce = 1_u64;
            let auth_error = sync_from_authenticated(
                &mut node,
                remote,
                settings.genesis(),
                settings.genesis(),
                1,
                &client,
                &mut replay_nonce,
            )
            .unwrap_err();
            assert_eq!(auth_error.to_string(), expected.to_string());
            let durable_error = sync_from_authenticated_durable(
                &mut node,
                remote,
                settings.genesis(),
                settings.genesis(),
                1,
                &client,
            )
            .unwrap_err();
            assert_eq!(durable_error.to_string(), expected.to_string());
            assert_eq!(node.stats().unwrap(), original);
            assert_eq!(node.read_active().unwrap().0, settings.genesis());
        }
    }

    #[test]
    fn protected_hello_rendezvous_from_reserved_socket_preserves_full_native_admission() {
        let (_dir, node, packet) = pending_packet();
        let settings = node.lock().unwrap().settings().clone();
        let expected = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::sync_channel::<PrefacedSocket>(0);
        let (waiting_sender, waiting_receiver) = mpsc::channel();
        let (deadlines_sender, deadlines_receiver) = mpsc::channel();
        let policy = AdmissionPolicy::new(8, Duration::from_secs(2)).unwrap();
        let proof_settings = settings.clone();
        let proof = thread::spawn(move || {
            waiting_sender.send(()).unwrap();
            // This controlled receiver is idle before the only listener accepts.
            // The production workers use the same zero-capacity channel with a
            // 2 ms receive/accept alternation; no stub verifier is injected here.
            let mut connection = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            let (request_deadline, preface_deadline, accepted_address) =
                deadlines_receiver.recv().unwrap();
            assert_eq!(connection.request_deadline, request_deadline);
            assert_eq!(connection.preface_deadline, preface_deadline);
            assert_eq!(connection.address, accepted_address);
            let (wire, negotiated) = receive_protected_request(
                &mut connection.socket,
                connection.first,
                Some(policy),
                connection.preface_deadline,
                true,
            )
            .unwrap();
            let request: Request = serde_json::from_slice(&wire).unwrap();
            let metrics = Mutex::new(Metrics::default());
            let mut progress = |_| ensure(Instant::now() < request_deadline, "REQUEST_DEADLINE");
            protect_submit(
                &mut connection.socket,
                &request,
                &wire,
                AdmissionHost {
                    settings: &proof_settings,
                    policy: Some(policy),
                    authentication: None,
                    metrics: &metrics,
                    negotiated,
                },
                &mut progress,
            )
            .unwrap();
            let reply = dispatch_shared_with(&node, request, &mut progress, |packet| {
                measured_work_verify(packet, &metrics)
            })
            .unwrap();
            write_frame(&mut connection.socket, &serde_json::to_vec(&reply).unwrap()).unwrap();
            assert_eq!(node.lock().unwrap().stats().unwrap()["height"], 1);
            metrics.into_inner().unwrap()
        });
        waiting_receiver.recv().unwrap();
        let client = thread::spawn(move || call_protected(address, &request, &settings).unwrap());
        // This is deliberately the reserved-side first accept, not a scheduler
        // race in which a proof worker might receive the connection directly.
        let (mut socket, accepted_address) = listener.accept().unwrap();
        let request_deadline = Instant::now() + Duration::from_secs(10);
        let preface_deadline = Instant::now() + PROTECTED_PREFACE_BUDGET;
        let first = read_frame_deadline(&mut socket, preface_deadline).unwrap();
        assert!(admission_hello(&first).unwrap().is_some());
        deadlines_sender
            .send((request_deadline, preface_deadline, accepted_address))
            .unwrap();
        assert!(try_handoff_hello(
            PrefacedSocket {
                socket,
                address: accepted_address,
                request_deadline,
                preface_deadline,
                first,
            },
            &[sender],
        )
        .is_ok());
        assert_eq!(client.join().unwrap()["block"], hex::encode(expected));
        let metrics = proof.join().unwrap();
        assert_eq!(metrics.admission_challenges, 1);
        assert_eq!(metrics.admission_accepted, 1);
        assert_eq!(metrics.work_verifications, 1);
        assert_eq!(metrics.admission_rejected_before_work, 0);
    }

    #[test]
    fn protected_hello_rendezvous_has_no_pending_queue_or_refreshed_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, address) = listener.accept().unwrap();
        let (sender, _receiver) = mpsc::sync_channel::<PrefacedSocket>(0);
        let request_deadline = Instant::now() + Duration::from_secs(10);
        let preface_deadline = Instant::now() + PROTECTED_PREFACE_BUDGET;
        let first = b"exact already-read first frame".to_vec();
        let returned = try_handoff_hello(
            PrefacedSocket {
                socket,
                address,
                request_deadline,
                preface_deadline,
                first: first.clone(),
            },
            &[sender],
        )
        .err()
        .unwrap();
        assert_eq!(
            returned.socket.peer_addr().unwrap(),
            client.local_addr().unwrap()
        );
        assert_eq!(returned.address, address);
        assert_eq!(returned.request_deadline, request_deadline);
        assert_eq!(returned.preface_deadline, preface_deadline);
        assert_eq!(returned.first, first);
    }

    #[test]
    fn protected_hello_additional_opportunities_never_refresh_expired_original_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, address) = listener.accept().unwrap();
        let (sender, _receiver) = mpsc::sync_channel::<PrefacedSocket>(0);
        let expired = Instant::now() - Duration::from_millis(1);
        let returned = try_handoff_hello(
            PrefacedSocket {
                socket,
                address,
                request_deadline: Instant::now() + Duration::from_secs(10),
                preface_deadline: expired,
                first: vec![1],
            },
            &[sender],
        )
        .err()
        .unwrap();
        assert_eq!(returned.preface_deadline, expired);
        assert_eq!(HELLO_HANDOFF_OPPORTUNITY, Duration::from_millis(2));
        assert_eq!(HELLO_HANDOFF_RETRY_PAUSE, Duration::from_micros(100));
        assert_eq!(HELLO_CLIENT_BUDGET, Duration::from_secs(5));
        // A 256*10ms ceiling would end before the registered absolute budget;
        // 512 is only an additional finite ceiling, never a fresh time budget.
        assert!(HELLO_CLIENT_ATTEMPTS as u64 * 10 >= 5000);
    }

    #[test]
    fn protected_client_can_negotiate_after_260_busy_replies_then_full_native_admission() {
        let (_dir, node, packet) = pending_packet();
        let settings = node.lock().unwrap().settings().clone();
        let expected = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let proof_settings = settings.clone();
        let server = thread::spawn(move || -> Result<Metrics> {
            let server_deadline = Instant::now() + Duration::from_secs(8);
            let accept = || -> Result<TcpStream> {
                loop {
                    ensure(Instant::now() < server_deadline, "TEST_ACCEPT_DEADLINE")?;
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nodelay(true)?;
                            return Ok(stream);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_micros(100))
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            };
            for _ in 0..260 {
                let mut socket = accept()?;
                let first = read_frame_deadline(&mut socket, server_deadline)?;
                ensure(admission_hello(&first)?.is_some(), "TEST_HELLO")?;
                write_untrusted_error(&mut socket, &RESERVED_READ_ONLY_BUSY, true)?;
            }
            let mut socket = accept()?;
            let first = read_frame_deadline(&mut socket, server_deadline)?;
            let (wire, negotiated) = receive_protected_request(
                &mut socket,
                first,
                Some(AdmissionPolicy::new(8, Duration::from_secs(2))?),
                server_deadline,
                true,
            )?;
            let request: Request = serde_json::from_slice(&wire)?;
            let metrics = Mutex::new(Metrics::default());
            let mut progress =
                |_| ensure(Instant::now() < server_deadline, "TEST_REQUEST_DEADLINE");
            protect_submit(
                &mut socket,
                &request,
                &wire,
                AdmissionHost {
                    settings: &proof_settings,
                    policy: Some(AdmissionPolicy::new(8, Duration::from_secs(2))?),
                    authentication: None,
                    metrics: &metrics,
                    negotiated,
                },
                &mut progress,
            )?;
            let reply = dispatch_shared_with(&node, request, &mut progress, |packet| {
                measured_work_verify(packet, &metrics)
            })?;
            write_frame_deadline(&mut socket, &serde_json::to_vec(&reply)?, server_deadline)?;
            ensure(
                node.lock().map_err(|_| "NODE_POISONED")?.stats()?["height"] == 1,
                "TEST_HEIGHT",
            )?;
            metrics.into_inner().map_err(|_| "METRICS_POISONED".into())
        });
        let result = call_protected(address, &request, &settings);
        let metrics = server.join().unwrap().unwrap();
        assert_eq!(result.unwrap()["block"], hex::encode(expected));
        assert_eq!(metrics.admission_challenges, 1);
        assert_eq!(metrics.admission_accepted, 1);
        assert_eq!(metrics.work_verifications, 1);
        assert_eq!(metrics.admission_rejected_before_work, 0);
    }

    #[test]
    fn protected_hello_rendezvous_expired_original_preface_cannot_send_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, address) = listener.accept().unwrap();
        let first = serde_json::to_vec(&AdmissionHello {
            schema: ADMISSION_HELLO_SCHEMA.into(),
            request_digest: hex::encode([1; 32]),
        })
        .unwrap();
        let (sender, receiver) = mpsc::sync_channel::<PrefacedSocket>(0);
        let (waiting_sender, waiting_receiver) = mpsc::channel();
        let expired = Instant::now() - Duration::from_millis(1);
        let proof = thread::spawn(move || {
            waiting_sender.send(()).unwrap();
            let mut connection = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(connection.preface_deadline, expired);
            assert_eq!(
                receive_protected_request(
                    &mut connection.socket,
                    connection.first,
                    Some(AdmissionPolicy::development()),
                    connection.preface_deadline,
                    true,
                )
                .unwrap_err()
                .to_string(),
                "FRAME_DEADLINE"
            );
        });
        waiting_receiver.recv().unwrap();
        // The receive thread announces immediately before blocking. A successful
        // rendezvous is required here; it must not allocate a pending queue.
        thread::sleep(Duration::from_millis(2));
        assert!(try_handoff_hello(
            PrefacedSocket {
                socket,
                address,
                request_deadline: Instant::now() + Duration::from_secs(10),
                preface_deadline: expired,
                first,
            },
            &[sender],
        )
        .is_ok());
        proof.join().unwrap();
        assert_eq!(client.read(&mut [0u8]).unwrap(), 0);
    }

    #[test]
    fn protected_hello_rendezvous_changes_the_explicit_transport_profile() {
        let policy = AdmissionPolicy::development();
        let old = hash(
            b"native-transport-admission-profile-v1",
            &[
                b"hello-first/connection-local/sha256/exact-wire/monotonic-expiry/preface100ms/proof2-readonly1/readonly-no-proof-permit/hello-retry256-5s/refusal128chars-100ms/reserved-hello-yield2ms/hello-rendezvous0/proof-recv-before-accept2ms/original-deadlines/socket-ceiling3",
                &[policy.bits],
                &policy.lifetime_ms.to_le_bytes(),
            ],
        );
        assert_ne!(policy.profile(), old);
    }

    #[test]
    fn protected_hello_rendezvous_preserves_validation_before_reserved_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let deadline = Instant::now() + PROTECTED_PREFACE_BUDGET;
        let mut hello = AdmissionHello {
            schema: "wrong-schema".into(),
            request_digest: "not-a-digest".into(),
        };
        assert_eq!(
            receive_protected_request(
                &mut socket,
                serde_json::to_vec(&hello).unwrap(),
                Some(AdmissionPolicy::development()),
                deadline,
                false,
            )
            .unwrap_err()
            .to_string(),
            "ADMISSION_HELLO"
        );
        hello.schema = ADMISSION_HELLO_SCHEMA.into();
        let digest_error = digest(&hello.request_digest).unwrap_err().to_string();
        assert_eq!(
            receive_protected_request(
                &mut socket,
                serde_json::to_vec(&hello).unwrap(),
                Some(AdmissionPolicy::development()),
                deadline,
                false,
            )
            .unwrap_err()
            .to_string(),
            digest_error
        );
        hello.request_digest = hex::encode([1; 32]);
        assert_eq!(
            receive_protected_request(
                &mut socket,
                serde_json::to_vec(&hello).unwrap(),
                Some(AdmissionPolicy::development()),
                deadline,
                false,
            )
            .unwrap_err()
            .to_string(),
            RESERVED_READ_ONLY_BUSY
        );
    }

    #[test]
    fn test_slow_partial_frame_cannot_extend_the_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&1000u32.to_be_bytes()).unwrap();
            for _ in 0..40 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(read_frame_budget(&mut stream, Duration::from_millis(100)).is_err());
        drop(stream);
        sender.join().unwrap();
    }

    fn pending_packet() -> (tempfile::TempDir, Mutex<Node>, Packet) {
        pending_packet_with_backend(false)
    }

    fn pending_packet_with_backend(
        authenticated: bool,
    ) -> (tempfile::TempDir, Mutex<Node>, Packet) {
        let dir = tempfile::tempdir().unwrap();
        let clock = now().unwrap();
        let settings = crate::Settings::development(Some(clock - 100)).unwrap();
        let node = if authenticated {
            Node::open_with_authenticated_state(dir.path(), settings.clone(), 2).unwrap()
        } else {
            Node::open(dir.path(), settings.clone(), 2).unwrap()
        };
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        (dir, Mutex::new(node), packet)
    }

    #[test]
    fn proof_statement_precheck_rejects_before_parent_state_or_work_and_preserves_retry() {
        use trnm_crypto_primitives::pon_work;
        use trnm_mvcc_fee::pon_executor::ExecutionProgress;
        let (dir, node, packet) = pending_packet();
        let before = node.lock().unwrap().read_active().unwrap();
        let mut bad_version = packet.clone();
        bad_version.proof[0] ^= 1;
        let mut cases = vec![(bad_version, "WORK:Version")];
        for matrix in 0..3 {
            let mut bad_field = packet.clone();
            let offset = 4 + matrix * pon_work::CELLS * 4;
            bad_field.proof[offset..offset + 4]
                .copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
            cases.push((bad_field, "WORK:Field"));
        }
        let mut bad_task = packet.clone();
        let value = u32::from_le_bytes(bad_task.proof[4..8].try_into().unwrap());
        let value = ((u128::from(value) + 1) % pon_work::Q) as u32;
        bad_task.proof[4..8].copy_from_slice(&value.to_le_bytes());
        cases.push((bad_task, "WORK:Task"));
        let mut bad_ticket = packet.clone();
        let trace_offset = 4 + 3 * pon_work::CELLS * 4;
        let trace = (0u64..4096)
            .map(|nonce| pon_work::hash(b"test-bad-ticket", &[&nonce.to_le_bytes()]))
            .find(|trace| {
                pon_work::hash(b"ticket", &[&packet.header.challenge(), trace])
                    > packet.header.target
            })
            .expect("development target has rejecting tickets");
        bad_ticket.proof[trace_offset..].copy_from_slice(&trace);
        cases.push((bad_ticket, "WORK:Target"));
        let sql = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
        for (malformed, expected) in cases {
            let state_reads = std::sync::atomic::AtomicUsize::new(0);
            let work_calls = std::sync::atomic::AtomicUsize::new(0);
            let error = dispatch_shared_with_execution_progress(
                &node,
                Request::Submit {
                    packet: hex::encode(malformed.encode().unwrap()),
                },
                &mut |_| Ok(()),
                |packet| {
                    work_calls.fetch_add(1, Ordering::SeqCst);
                    WorkCheckedPacket::verify(packet)
                },
                &|point| {
                    if point == ExecutionProgress::BeforeParentBinding {
                        state_reads.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(!error.requires_owner_stop());
            assert_eq!(state_reads.load(Ordering::SeqCst), 0);
            assert_eq!(work_calls.load(Ordering::SeqCst), 0);
            assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
            let count: u64 = sql
                .query_row(
                    "SELECT COUNT(*) FROM blocks WHERE id=?",
                    [malformed.id().unwrap().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
            assert_eq!(
                node.lock()
                    .unwrap()
                    .admit(&malformed, now().unwrap())
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        let request = || Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let reply =
            dispatch_shared_with(&node, request(), &mut |_| Ok(()), WorkCheckedPacket::verify)
                .unwrap();
        assert_eq!(reply["block"], hex::encode(packet.id().unwrap()));
        let duplicate = dispatch_shared_with(&node, request(), &mut |_| Ok(()), |_| {
            panic!("an exact durable duplicate must not replay work")
        })
        .unwrap();
        assert_eq!(duplicate["block"], reply["block"]);
    }

    #[test]
    fn public_v3_false_work_precedes_unowned_state_and_keeps_valid_retry() {
        use trnm_crypto_primitives::pon_work;
        use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionProgress};
        let (_dir, node, packet) = pending_packet_with_backend(true);
        let before = node.lock().unwrap().read_active().unwrap();
        let mut malformed = packet.clone();
        let trace_offset = 4 + 3 * pon_work::CELLS * 4;
        let trace = (0u64..4096)
            .map(|nonce| pon_work::hash(b"public-false-trace-preflight", &[&nonce.to_le_bytes()]))
            .find(|trace| {
                trace.as_slice() != &packet.proof[trace_offset..]
                    && pon_work::hash(b"ticket", &[&packet.header.challenge(), trace])
                        <= packet.header.target
            })
            .unwrap();
        malformed.proof[trace_offset..].copy_from_slice(&trace);
        pon_work::precheck_proof_statement(
            malformed.header.challenge(),
            malformed.header.work_task,
            malformed.header.target,
            &malformed.proof,
        )
        .unwrap();
        for public_order in [false, true] {
            let reads = std::sync::atomic::AtomicUsize::new(0);
            let error = dispatch_shared_with_execution_observation(
                &node,
                Request::Submit {
                    packet: hex::encode(malformed.encode().unwrap()),
                },
                &mut |_| Ok(()),
                |packet| {
                    assert!(node.try_lock().is_ok());
                    WorkCheckedPacket::verify(packet)
                },
                &ExecutionControl::new(
                    &|point| {
                        if point == ExecutionProgress::BeforeParentBinding {
                            reads.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(())
                    },
                    &(),
                ),
                SubmitDispatchContext {
                    public_proof_before_unowned_task: public_order,
                    ..SubmitDispatchContext::default()
                },
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "WORK:Transcript");
            assert_eq!(reads.load(Ordering::SeqCst) == 0, public_order);
            assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        }
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let reply = dispatch_shared_with_execution_observation(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
            &ExecutionControl::new(
                &|point| {
                    if point == ExecutionProgress::BeforeParentBinding {
                        reads.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
                &(),
            ),
            SubmitDispatchContext {
                public_proof_before_unowned_task: true,
                ..SubmitDispatchContext::default()
            },
        )
        .unwrap();
        assert!(reads.load(Ordering::SeqCst) > 0);
        assert_eq!(reply["block"], hex::encode(packet.id().unwrap()));
    }

    #[test]
    fn public_v3_valid_work_cannot_reuse_parent_state_across_actual_sql_tampering() {
        use trnm_mvcc_fee::pon_executor::ExecutionControl;
        let (dir, node, packet) = pending_packet_with_backend(true);
        let before = node.lock().unwrap().read_active().unwrap();
        let sql = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
        let slot: u64 = sql
            .query_row(
                "SELECT state_slot FROM active WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let error = dispatch_shared_with_execution_observation(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| Ok(()),
            |packet| {
                let checked = WorkCheckedPacket::verify(packet)?;
                sql.execute(
                    "INSERT INTO kv VALUES(?,?,?)",
                    rusqlite::params![slot, "public-work-gap-test", b"1".as_slice()],
                )
                .unwrap();
                Ok(checked)
            },
            &ExecutionControl::new(&|_| Ok(()), &()),
            SubmitDispatchContext {
                public_proof_before_unowned_task: true,
                ..SubmitDispatchContext::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "ROOT");
        assert!(error.requires_owner_stop());
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [packet.id().unwrap().as_slice()],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        sql.execute("DELETE FROM kv WHERE key=?", ["public-work-gap-test"])
            .unwrap();
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    }

    #[test]
    fn context_cancellation_precedes_work_verifier_and_preserves_public_retry() {
        use trnm_mvcc_fee::pon_executor::ExecutionProgress;
        let (dir, node, packet) = pending_packet();
        let before = node.lock().unwrap().read_active().unwrap();
        let checked = AtomicBool::new(false);
        let observed = std::sync::atomic::AtomicUsize::new(0);
        let error = dispatch_shared_with_execution_progress(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| Ok(()),
            |packet| {
                checked.store(true, Ordering::SeqCst);
                WorkCheckedPacket::verify(packet)
            },
            &|point| {
                if point == ExecutionProgress::BeforeParentBinding {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Err(Error::new(crate::ErrorCode::FrameDeadline))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.is(crate::ErrorCode::FrameDeadline));
        assert!(!error.requires_owner_stop());
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        assert!(!checked.load(Ordering::SeqCst));
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        let sql = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
        let count: u64 = sql
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [packet.id().unwrap().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let reply = dispatch_shared_with(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
        )
        .unwrap();
        assert_eq!(reply["block"], hex::encode(packet.id().unwrap()));
    }

    #[test]
    fn work_replay_does_not_hold_the_durable_owner_lock() {
        let (_dir, node, packet) = pending_packet();
        let expected = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let reply = dispatch_shared_with(&node, request, &mut |_| Ok(()), |packet| {
            // Schedule a genuine status read while the verifier is in flight.
            assert!(node.try_lock().is_ok());
            let head = dispatch_shared_with(&node, Request::Head, &mut |_| Ok(()), |_| {
                panic!("read requests cannot ask for work verification")
            })
            .unwrap();
            assert_eq!(head["height"], 0);
            WorkCheckedPacket::verify(packet)
        })
        .unwrap();
        assert_eq!(reply["block"], hex::encode(expected));
        assert_eq!(node.lock().unwrap().stats().unwrap()["height"], 1);
    }

    #[test]
    fn cancellation_after_actual_work_verification_has_no_commit() {
        let (_dir, node, packet) = pending_packet();
        let before = node.lock().unwrap().stats().unwrap();
        let cancelled = AtomicBool::new(false);
        let mut progress = |_| ensure(!cancelled.load(Ordering::Acquire), "CANCELLED");
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let error = dispatch_shared_with(&node, request, &mut progress, |packet| {
            let checked = WorkCheckedPacket::verify(packet)?;
            cancelled.store(true, Ordering::Release);
            Ok(checked)
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "CANCELLED");
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
    }

    #[test]
    fn cancellation_inside_last_work_tile_or_final_boundary_has_no_durable_packet() {
        use trnm_crypto_primitives::pon_work::{VerificationProgress, N, R};
        for at_final_boundary in [false, true] {
            let (dir, node, packet) = pending_packet();
            let id = packet.id().unwrap();
            let before = node.lock().unwrap().stats().unwrap();
            let active_before = node.lock().unwrap().read_active().unwrap();
            let settings = node.lock().unwrap().settings().clone();
            let cancelled = AtomicBool::new(false);
            let mut dispatch_progress = |_| {
                ensure(
                    !cancelled.load(Ordering::Acquire),
                    "PUBLIC_REQUEST_CANCELLED",
                )
            };
            let request = Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            };
            let error = dispatch_shared_with(&node, request, &mut dispatch_progress, |packet| {
                WorkCheckedPacket::verify_with_progress(packet, &mut |point| {
                    let last_tile = VerificationProgress::TranscriptTile {
                        row: N / R - 1,
                        column: N / R - 1,
                        inner: N / R - 1,
                    };
                    if point
                        == if at_final_boundary {
                            VerificationProgress::BeforeVerifiedWork
                        } else {
                            last_tile
                        }
                    {
                        cancelled.store(true, Ordering::Release);
                    }
                    ensure(
                        !cancelled.load(Ordering::Acquire),
                        "PUBLIC_REQUEST_CANCELLED",
                    )
                })
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
            assert_eq!(node.lock().unwrap().stats().unwrap(), before);
            assert_eq!(node.lock().unwrap().read_active().unwrap(), active_before);
            let sql = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
            let rows: u64 = sql
                .query_row(
                    "SELECT COUNT(*) FROM blocks WHERE id=?",
                    [id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0);
            drop(sql);
            drop(node);
            let reopened = Node::open(dir.path(), settings, 2).unwrap();
            assert_eq!(reopened.stats().unwrap(), before);
            assert_eq!(reopened.read_active().unwrap(), active_before);
        }
    }

    #[test]
    fn cancellation_after_admission_preserves_fact_and_exact_retry_controls_activation() {
        use trnm_mvcc_fee::pon_executor::ExecutionProgress;
        let (dir, node, packet) = pending_packet();
        let expected = packet.id().unwrap();
        let settings = node.lock().unwrap().settings().clone();
        let cancelled = AtomicBool::new(false);
        let result = dispatch_shared_with_execution_progress(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| {
                ensure(
                    !cancelled.load(Ordering::Acquire),
                    "PUBLIC_REQUEST_CANCELLED",
                )
            },
            WorkCheckedPacket::verify,
            &|point| {
                if point == ExecutionProgress::BeforeDurableCommit {
                    // This final admitted observation succeeds. Cancellation becomes
                    // visible before commit completes, without undoing its native fact.
                    cancelled.store(true, Ordering::Release);
                    Ok(())
                } else {
                    ensure(
                        !cancelled.load(Ordering::Acquire),
                        "PUBLIC_REQUEST_CANCELLED",
                    )
                }
            },
        )
        .unwrap_err();
        assert!(cancelled.load(Ordering::Acquire));
        assert!(result.is(ErrorCode::PublicRequestCancelled));
        assert_eq!(
            node.lock().unwrap().packet(expected).unwrap().id().unwrap(),
            expected
        );
        assert_eq!(
            node.lock().unwrap().read_active().unwrap().0,
            settings.genesis()
        );
        // This is a new explicit retry, not an extension of the cancelled call.
        let reply = dispatch_shared_with(
            &node,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &mut |_| Ok(()),
            |_| panic!("exact committed retry repeated W1"),
        )
        .unwrap();
        assert_eq!(reply["block"], hex::encode(expected));
        let after = node.lock().unwrap().read_active().unwrap();
        assert_eq!(after.0, expected);
        assert_eq!(node.lock().unwrap().stats().unwrap()["height"], 1);
        drop(node);
        let reopened = Node::open(dir.path(), settings, 2).unwrap();
        assert_eq!(reopened.read_active().unwrap(), after);
        assert_eq!(reopened.packet(expected).unwrap().id().unwrap(), expected);
    }

    #[test]
    fn context_reject_and_exact_duplicate_do_not_replay_work() {
        let (_dir, node, packet) = pending_packet();
        let mut wrong = packet.clone();
        wrong.header.network[0] ^= 1;
        let request = Request::Submit {
            packet: hex::encode(wrong.encode().unwrap()),
        };
        assert_eq!(
            dispatch_shared_with(&node, request, &mut |_| Ok(()), |_| panic!(
                "bad context reached work verifier"
            ))
            .unwrap_err()
            .to_string(),
            "NETWORK"
        );
        let encoded = hex::encode(packet.encode().unwrap());
        dispatch_shared_with(
            &node,
            Request::Submit {
                packet: encoded.clone(),
            },
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
        )
        .unwrap();
        let before = node.lock().unwrap().stats().unwrap();
        dispatch_shared_with(
            &node,
            Request::Submit { packet: encoded },
            &mut |_| Ok(()),
            |_| panic!("exact stored duplicate repeated work"),
        )
        .unwrap();
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
    }

    #[test]
    fn verified_work_cannot_bypass_destination_context_or_clock() {
        let (_dir, node, packet) = pending_packet();
        let checked = WorkCheckedPacket::verify(packet.clone()).unwrap();
        let before = node.lock().unwrap().stats().unwrap();
        assert_eq!(
            node.lock()
                .unwrap()
                .admit_work_checked(checked, 1)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = Node::open(
            other_dir.path(),
            crate::Settings::development(None).unwrap(),
            1,
        )
        .unwrap();
        let before = other.stats().unwrap();
        assert_eq!(
            other
                .admit_work_checked(WorkCheckedPacket::verify(packet).unwrap(), now().unwrap())
                .unwrap_err()
                .to_string(),
            "NETWORK"
        );
        assert_eq!(other.stats().unwrap(), before);
    }

    fn existing_replay_cancelled_after_owner_acquisition(already_active: bool) {
        for authenticated in [false, true] {
            let (_directory, node, packet) = pending_packet_with_backend(authenticated);
            let id = packet.id().unwrap();
            {
                let mut owner = node.lock().unwrap();
                owner.admit(&packet, now().unwrap()).unwrap();
                if already_active {
                    owner.activate_observed(id, now().unwrap()).unwrap();
                }
            }
            let before = node.lock().unwrap().read_active().unwrap();
            let cancelled = AtomicBool::new(false);
            let visits = std::cell::Cell::new(0usize);
            let outcome = dispatch_shared_with(
                &node,
                Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &mut |_| {
                    visits.set(visits.get() + 1);
                    if visits.get() == 1 {
                        // The original owner-acquisition observation succeeds;
                        // the caller then cancels before existing-packet history
                        // and activation. This is real stored packet/reorg work.
                        cancelled.store(true, Ordering::Release);
                        Ok(())
                    } else {
                        ensure(
                            !cancelled.load(Ordering::Acquire),
                            "PUBLIC_REQUEST_CANCELLED",
                        )
                    }
                },
                |_| panic!("an exact stored replay must not repeat full W1"),
            );
            assert!(
                matches!(&outcome, Err(error) if error.is(ErrorCode::PublicRequestCancelled)
                    && !error.requires_owner_stop()),
                "existing replay ignored cancellation: active={already_active} authenticated={authenticated} visits={} outcome={outcome:?}",
                visits.get(),
            );
            assert!(visits.get() >= 2);
            assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
            assert_eq!(
                node.lock().unwrap().packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            // Cancellation creates no invalid-work verdict and cannot erase the
            // previous admission. Ordinary exact retry still recovers activation.
            let reply = dispatch_shared_with(
                &node,
                Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &mut |_| Ok(()),
                |_| panic!("stored recovery repeated W1"),
            )
            .unwrap();
            assert_eq!(reply["block"], hex::encode(id));
            assert_eq!(node.lock().unwrap().read_active().unwrap().0, id);
        }
    }

    #[test]
    fn existing_replay_cancel_stops_active_history_spam() {
        existing_replay_cancelled_after_owner_acquisition(true);
    }

    #[test]
    fn existing_replay_cancel_preserves_inactive_admission_for_recovery() {
        existing_replay_cancelled_after_owner_acquisition(false);
    }

    #[test]
    fn existing_replay_cancelled_reorg_recovers_signed_payments_once() {
        use rusqlite::OptionalExtension;
        use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
        use trnm_protocol::pon_wire::Envelope;
        fn transfer(settings: &Settings, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
            let mut payload = crate::development_public(recipient).unwrap().to_vec();
            payload.extend(amount.to_le_bytes());
            let mut tx = Envelope {
                network: settings.network(),
                sender: crate::development_public(0).unwrap(),
                nonce,
                expiry: 1000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            let key =
                signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
                    .unwrap();
            tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            tx.encode().unwrap()
        }
        for authenticated in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let clock = now().unwrap();
            let settings = Settings::development(Some(clock - 1000)).unwrap();
            let mut owner = if authenticated {
                Node::open_with_authenticated_state(directory.path(), settings.clone(), 2).unwrap()
            } else {
                Node::open(directory.path(), settings.clone(), 2).unwrap()
            };
            let left = owner
                .make(
                    settings.genesis(),
                    vec![transfer(&settings, 1, 1, 11)],
                    crate::development_public(7).unwrap(),
                    clock - 990,
                    4096,
                )
                .unwrap();
            let left_id = owner.admit(&left, clock).unwrap();
            owner.activate_observed(left_id, clock).unwrap();
            let before = owner.read_active().unwrap();
            let right = owner
                .make(
                    settings.genesis(),
                    vec![transfer(&settings, 1, 2, 7)],
                    crate::development_public(8).unwrap(),
                    clock - 989,
                    4096,
                )
                .unwrap();
            let right_id = owner.admit(&right, clock).unwrap();
            let target = owner
                .make(
                    right_id,
                    vec![transfer(&settings, 2, 3, 9)],
                    crate::development_public(8).unwrap(),
                    clock - 979,
                    4096,
                )
                .unwrap();
            let target_id = owner.admit(&target, clock).unwrap();
            let expected = owner.state_at(target_id).unwrap();
            let wire = hex::encode(target.encode().unwrap());
            let node = Mutex::new(owner);
            let observer =
                rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
            let mut stopped_at = None;
            let error = dispatch_shared_with(
                &node,
                Request::Submit {
                    packet: wire.clone(),
                },
                &mut |_| {
                    // Observe only actually COMMITTED intent progress through a
                    // separate SQLite connection. Cancel after detach and first
                    // attach, before the remaining signed transfer is applied.
                    let row: Option<(u64, u64)> = observer
                        .query_row(
                            "SELECT cursor,done FROM reorg WHERE singleton=1",
                            [],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if row == Some((2, 0)) {
                        stopped_at = row;
                        Err(Error::new(ErrorCode::PublicRequestCancelled))
                    } else {
                        Ok(())
                    }
                },
                |_| panic!("stored reorg recovery repeated W1"),
            )
            .unwrap_err();
            assert!(error.is(ErrorCode::PublicRequestCancelled) && !error.requires_owner_stop());
            assert_eq!(stopped_at, Some((2, 0)));
            assert_eq!(node.lock().unwrap().active().unwrap(), (before.0, before.1));
            assert_eq!(
                node.lock()
                    .unwrap()
                    .packet(target_id)
                    .unwrap()
                    .encode()
                    .unwrap(),
                target.encode().unwrap()
            );
            let request = Request::Submit {
                packet: wire.clone(),
            };
            let reply = dispatch_shared_with(&node, request, &mut |_| Ok(()), |_| {
                panic!("exact pending target retry repeated W1")
            })
            .unwrap();
            assert_eq!(reply["block"], hex::encode(target_id));
            let final_state = node.lock().unwrap().read_active().unwrap();
            assert_eq!(final_state.0, target_id);
            assert_eq!(final_state.2, expected);
            assert_eq!(
                final_state.2[&format!(
                    "account:{}",
                    hex::encode(crate::development_public(0).unwrap())
                )]["nonce"],
                2
            );
            let event_count: u64 = observer
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            dispatch_shared_with(
                &node,
                Request::Submit { packet: wire },
                &mut |_| Ok(()),
                |_| panic!("completed exact retry repeated W1"),
            )
            .unwrap();
            assert_eq!(node.lock().unwrap().read_active().unwrap(), final_state);
            assert_eq!(
                observer
                    .query_row("SELECT COUNT(*) FROM events", [], |row| row
                        .get::<_, u64>(0))
                    .unwrap(),
                event_count
            );
            drop(observer);
            drop(node);
            let reopened = if authenticated {
                Node::open_with_authenticated_state(directory.path(), settings, 2).unwrap()
            } else {
                Node::open(directory.path(), settings, 2).unwrap()
            };
            assert_eq!(reopened.read_active().unwrap(), final_state);
        }
    }

    #[test]
    fn owner_lock_wait_remains_cooperatively_cancellable() {
        let (_dir, node, _packet) = pending_packet();
        let held = node.lock().unwrap();
        let mut calls = 0;
        let mut progress = |_| {
            calls += 1;
            ensure(calls < 3, "CANCELLED")
        };
        assert!(matches!(lock_owner(&node, &mut progress), Err(e) if e.to_string() == "CANCELLED"));
        assert_eq!(calls, 3);
        drop(held);
        assert!(lock_owner(&node, &mut |_| Ok(())).is_ok());
    }

    #[test]
    fn intervening_heavier_branch_does_not_promote_the_verified_stale_candidate() {
        let (_dir, node, packet) = pending_packet();
        let original = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let reply = dispatch_shared_with(&node, request, &mut |_| Ok(()), |packet| {
            {
                let mut owner = node.lock().unwrap();
                let base = owner.settings().genesis_time();
                for height in 1..=2 {
                    let other = owner.make(
                        owner.active()?.0,
                        vec![],
                        crate::development_public(1)?,
                        base + height * 10,
                        4096,
                    )?;
                    let id = owner.admit(&other, now()?)?;
                    owner.activate_observed(id, now()?)?;
                }
            }
            WorkCheckedPacket::verify(packet)
        })
        .unwrap();
        assert_eq!(reply["block"], hex::encode(original));
        assert_ne!(reply["active"], reply["block"]);
        let owner = node.lock().unwrap();
        assert_eq!(owner.stats().unwrap()["height"], 2);
        assert_eq!(owner.stats().unwrap()["stored_blocks"], 4);
    }
    fn test_identity(label: u8) -> DevelopmentIdentity {
        DevelopmentIdentity::from_secret_hex(&hex::encode(hash(
            b"native-auth-test-key",
            &[&[label]],
        )))
        .unwrap()
    }

    fn authentication_fixture(settings: &Settings) -> (AuthenticatedServer, AuthenticatedClient) {
        let server_identity = test_identity(1);
        let client_identity = test_identity(2);
        let server = AuthenticatedServer::new(
            server_identity.clone(),
            vec![client_identity.public_key().to_owned()],
            1,
        )
        .unwrap();
        let client =
            AuthenticatedClient::new(client_identity, server_identity.public_key().to_owned(), 1)
                .unwrap();
        assert_eq!(
            authenticated_session(settings, client.public_key(), server.public_key(), 1,)
                .unwrap()
                .server,
            server.public_key()
        );
        (server, client)
    }

    #[test]
    fn authenticated_legacy_nonloopback_has_no_unmetered_host_bypass() {
        // V3 and legacy authenticated ingress now check the SAME fixed parent.
        // This regression works with either an unprivileged CI host (denied)
        // or an actual admin-provisioned parent (must be verified, never None).
        let remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(crate::host_kernel_parent::require_host_kernel_budget(remote, None).is_err());
        let probe = crate::host_kernel_parent::require_for_listener(remote);
        match &probe {
            Ok(Some(kernel)) => kernel.verify().unwrap(),
            Err(_) => {}
            Ok(None) => panic!("nonloopback must not run without host budget"),
        }
        // Even when an administrator provisioned a valid cgroup, the
        // unaffordable no-cookie authenticated-only WAN transport is denied.
        {
            let dir = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
            let (authentication, _) = authentication_fixture(&settings);
            let node = Node::open(dir.path(), settings, 2).unwrap();
            let listener = TcpListener::bind(remote).unwrap();
            let error = serve_authenticated(
                listener,
                node,
                Duration::from_secs(1),
                Arc::new(AtomicBool::new(true)),
                authentication,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "DEVELOPMENT_REMOTE_ADMISSION_REQUIRED");
        }
        // The priced, authenticated legacy WAN route requires the original
        // host parent too; no second identity-scoped host budget is allowed.
        if let Err(expected) = probe {
            let dir = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
            let (authentication, _) = authentication_fixture(&settings);
            let node = Node::open(dir.path(), settings, 2).unwrap();
            let listener = TcpListener::bind(remote).unwrap();
            let error = serve_authenticated_protected(
                listener,
                node,
                Duration::from_secs(1),
                Arc::new(AtomicBool::new(true)),
                authentication,
                AdmissionPolicy::development(),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected.to_string());
        }
    }

    #[test]
    fn measured_native_w1_rejection_reports_real_or_explicitly_unknown_thread_cpu() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let original = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 10,
                4096,
            )
            .unwrap();
        let mut bad = original;
        let last = bad.proof.len() - 1;
        bad.proof[last] ^= 1;
        let metrics = Mutex::new(Metrics::default());
        // The adjusted trace may happen to miss target; accept either a
        // cheap TARGET refusal or expensive TRANSCRIPT refusal as invalid.
        assert!(measured_work_verify(bad, &metrics).is_err());
        let snapshot = metrics.lock().unwrap();
        assert_eq!(snapshot.work_verifications, 1);
        assert_eq!(
            snapshot.work_verification_thread_cpu_unknown_calls
                + snapshot.work_verification_thread_cpu_known_calls,
            1
        );
        assert!(snapshot.work_verification_ns > 0);
    }

    #[test]
    fn test_authenticated_bytes_bind_session_signature_and_canonical_request() {
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (server, client) = authentication_fixture(&settings);
        let bytes = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        let verified = authenticate_request(&bytes, &settings, &server).unwrap();
        assert_eq!(verified.frame.replay_nonce(), 1);
        assert!(matches!(verified.request, Request::Head));

        let mut context: AuthenticatedRequest = serde_json::from_slice(&bytes).unwrap();
        context.session.parameters = hex::encode([7; 32]);
        assert_eq!(
            authenticate_request(&serde_json::to_vec(&context).unwrap(), &settings, &server)
                .unwrap_err()
                .to_string(),
            "AUTH_SESSION_CONTEXT"
        );

        let mut changed: AuthenticatedRequest = serde_json::from_slice(&bytes).unwrap();
        changed.request = Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        };
        assert!(
            authenticate_request(&serde_json::to_vec(&changed).unwrap(), &settings, &server,)
                .unwrap_err()
                .to_string()
                .starts_with("AUTH_SIGNATURE:")
        );

        let mut noncanonical = bytes;
        noncanonical.push(b' ');
        assert_eq!(
            authenticate_request(&noncanonical, &settings, &server)
                .unwrap_err()
                .to_string(),
            "AUTH_NONCANONICAL"
        );
    }

    #[test]
    fn test_durable_pending_request_recovers_and_completed_response_replays() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (server, client) = authentication_fixture(&settings);
        let bytes = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        let mut node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        assert!(matches!(
            node.begin_authenticated_request(request.frame, &request.payload)
                .unwrap(),
            AuthenticatedReplayDecision::Execute
        ));
        assert_eq!(node.stats().unwrap()["authenticated_pending"], 1);
        drop(node);

        let mut node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        assert!(matches!(
            node.begin_authenticated_request(request.frame, &request.payload)
                .unwrap(),
            AuthenticatedReplayDecision::Execute
        ));
        let response = signed_response(
            &server,
            &request,
            true,
            Ok(json!({"height":0,"recovered":true})),
        )
        .unwrap();
        node.finish_authenticated_request(request.frame, &response)
            .unwrap();
        assert_eq!(node.stats().unwrap()["authenticated_pending"], 0);
        drop(node);

        let mut node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        match node
            .begin_authenticated_request(request.frame, &request.payload)
            .unwrap()
        {
            AuthenticatedReplayDecision::Cached(bytes) => assert_eq!(bytes, response),
            AuthenticatedReplayDecision::Execute => panic!("completed request executed again"),
        }
        let conflicting = authenticated_request_bytes(
            &settings,
            &client,
            1,
            Request::History {
                tip: hex::encode(settings.genesis()),
                after: hex::encode(settings.genesis()),
            },
        )
        .unwrap();
        let conflicting = authenticate_request(&conflicting, &settings, &server).unwrap();
        assert_eq!(
            node.begin_authenticated_request(conflicting.frame, &conflicting.payload)
                .unwrap_err()
                .to_string(),
            "AUTH_CONFLICTING_REPLAY"
        );
    }

    #[test]
    fn test_committed_submit_with_missing_auth_ack_recovers_without_work_replay() {
        let (dir, node, packet) = pending_packet();
        let settings = node.lock().unwrap().settings().clone();
        let (server, client) = authentication_fixture(&settings);
        let bytes = authenticated_request_bytes(
            &settings,
            &client,
            1,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        node.lock()
            .unwrap()
            .begin_authenticated_request(request.frame, &request.payload)
            .unwrap();
        let first = dispatch_shared_with(
            &node,
            request.request.clone(),
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
        )
        .unwrap();
        assert_eq!(first["block"], hex::encode(packet.id().unwrap()));
        assert_eq!(node.lock().unwrap().stats().unwrap()["height"], 1);
        drop(node);

        let reopened = Mutex::new(Node::open(dir.path(), settings.clone(), 2).unwrap());
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        assert!(matches!(
            reopened
                .lock()
                .unwrap()
                .begin_authenticated_request(request.frame, &request.payload)
                .unwrap(),
            AuthenticatedReplayDecision::Execute
        ));
        let replay =
            dispatch_shared_with(&reopened, request.request.clone(), &mut |_| Ok(()), |_| {
                panic!("stored block replayed expensive work")
            })
            .unwrap();
        let response = signed_response(&server, &request, true, Ok(replay)).unwrap();
        reopened
            .lock()
            .unwrap()
            .finish_authenticated_request(request.frame, &response)
            .unwrap();
        let request = authenticate_request(&bytes, &settings, &server).unwrap();
        match reopened
            .lock()
            .unwrap()
            .begin_authenticated_request(request.frame, &request.payload)
            .unwrap()
        {
            AuthenticatedReplayDecision::Cached(bytes) => assert_eq!(bytes, response),
            AuthenticatedReplayDecision::Execute => panic!("acknowledged request executed"),
        };
    }

    #[test]
    fn test_authenticated_socket_replays_response_after_client_loses_first_ack() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (server_auth, client) = authentication_fixture(&settings);
        let node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let server = thread::spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(10),
                child_stop,
                server_auth,
            )
        });
        let bytes = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        {
            let mut stream = TcpStream::connect(address).unwrap();
            write_frame(&mut stream, &bytes).unwrap();
        }
        thread::sleep(Duration::from_millis(100));
        let response = loop {
            let mut stream = TcpStream::connect(address).unwrap();
            write_frame(&mut stream, &bytes).unwrap();
            let response = read_frame(&mut stream).unwrap();
            let envelope: AuthenticatedRequest = serde_json::from_slice(&bytes).unwrap();
            let digest = request_authority_digest(
                &envelope.session,
                envelope.replay_nonce,
                &envelope.request,
            )
            .unwrap();
            let (terminal, ok, value) =
                verify_authenticated_response(&response, &envelope.session, 1, digest).unwrap();
            if terminal {
                assert!(ok);
                assert_eq!(value["height"], 0);
                break response;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(!response.is_empty());
        stop.store(true, Ordering::Release);
        let metrics = server.join().unwrap().unwrap();
        assert_eq!(metrics.authenticated_requests, 2);
        assert_eq!(metrics.replayed_responses, 1);
        let reopened = Node::open(temp.path(), settings, 1).unwrap();
        assert_eq!(reopened.stats().unwrap()["authenticated_pending"], 0);
        assert_eq!(reopened.stats().unwrap()["authenticated_audit_rows"], 1);
    }
    #[test]
    fn test_cached_terminal_error_is_reverified_and_counted_as_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (server_auth, client) = authentication_fixture(&settings);
        let node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let server = thread::spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(10),
                child_stop,
                server_auth,
            )
        });
        let bytes = authenticated_request_bytes(
            &settings,
            &client,
            1,
            Request::Confirm {
                transaction: hex::encode([0; 32]),
                block: hex::encode([0; 32]),
            },
        )
        .unwrap();
        let envelope: AuthenticatedRequest = serde_json::from_slice(&bytes).unwrap();
        let request_digest =
            request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)
                .unwrap();
        let mut first = None;
        for _ in 0..2 {
            let mut stream = TcpStream::connect(address).unwrap();
            write_frame(&mut stream, &bytes).unwrap();
            let reply = read_frame(&mut stream).unwrap();
            let (terminal, ok, value) =
                verify_authenticated_response(&reply, &envelope.session, 1, request_digest)
                    .unwrap();
            assert!(terminal);
            assert!(!ok);
            assert!(value.get("error").and_then(Value::as_str).is_some());
            if let Some(original) = &first {
                assert_eq!(original, &reply);
            } else {
                first = Some(reply);
            }
        }
        stop.store(true, Ordering::Release);
        let metrics = server.join().unwrap().unwrap();
        assert_eq!(metrics.authenticated_requests, 2);
        assert_eq!(metrics.replayed_responses, 1);
        assert_eq!(metrics.completed_requests, 0);
        assert_eq!(metrics.rejected_requests, 2);
    }

    #[test]
    fn test_durable_client_outbox_survives_network_loss_and_rejects_changed_request() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (_server, client) = authentication_fixture(&settings);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        assert!(call_authenticated_durable(&mut node, address, &Request::Head, &client,).is_err());
        assert_eq!(node.stats().unwrap()["authenticated_outbox_pending"], 1);
        drop(node);

        let mut node = Node::open(temp.path(), settings.clone(), 1).unwrap();
        let changed = Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        };
        assert_eq!(
            call_authenticated_durable(&mut node, address, &changed, &client)
                .unwrap_err()
                .to_string(),
            "AUTH_OUTBOX_PENDING"
        );
        assert_eq!(node.stats().unwrap()["authenticated_outbox_pending"], 1);
        assert!(call_authenticated_durable(&mut node, address, &Request::Head, &client,).is_err());
        assert_eq!(node.stats().unwrap()["authenticated_outbox_pending"], 1);
    }

    #[test]
    fn test_durable_client_retries_exact_wire_after_lost_server_response() {
        let server_dir = tempfile::tempdir().unwrap();
        let client_dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (server_auth, client) = authentication_fixture(&settings);
        let server_node = Node::open(server_dir.path(), settings.clone(), 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let server = thread::spawn(move || {
            serve_authenticated(
                listener,
                server_node,
                Duration::from_secs(10),
                child_stop,
                server_auth,
            )
        });

        let mut client_node = Node::open(client_dir.path(), settings.clone(), 1).unwrap();
        assert!(pending_authenticated_request(&client_node, &client)
            .unwrap()
            .is_none());
        let wire = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        let request = outbound_authenticated_request(&wire, &settings, &client).unwrap();
        client_node
            .reserve_authenticated_outbound(request.frame, &request.payload, &wire)
            .unwrap();
        assert_eq!(
            pending_authenticated_request(&client_node, &client).unwrap(),
            Some(Request::Head)
        );
        {
            let mut stream = TcpStream::connect(address).unwrap();
            write_frame(&mut stream, &wire).unwrap();
        }
        drop(client_node);
        thread::sleep(Duration::from_millis(50));

        let mut client_node = Node::open(client_dir.path(), settings, 1).unwrap();
        assert_eq!(
            pending_authenticated_request(&client_node, &client).unwrap(),
            Some(Request::Head)
        );
        let value = loop {
            match call_authenticated_durable(&mut client_node, address, &Request::Head, &client) {
                Ok(value) => break value,
                Err(error) if error.is(ErrorCode::RemoteRetryable) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("unexpected retry error: {error}"),
            }
        };
        assert_eq!(value["height"], 0);
        assert_eq!(
            client_node.stats().unwrap()["authenticated_outbox_pending"],
            0
        );
        stop.store(true, Ordering::Release);
        let metrics = server.join().unwrap().unwrap();
        assert_eq!(metrics.replayed_responses, 1);
        assert_eq!(metrics.authenticated_requests, 2);
    }
}

/// Explicit unintegrated public development successor; old listeners unchanged.
pub mod public_v2;

pub mod public_v3;
