//! Bounded native socket ingress. Development loopback only; not Sybil-safe public P2P.
use crate::{
    authenticated_payload_digest, authenticated_profile_digest, digest, ensure,
    store::{AuthenticatedReplayDecision, WorkCheckedPacket},
    Error, Node, Packet, Result, Settings,
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
    public_key_hex, sign_hex, signing_key_from_hex, verify_hex_strict, verifying_key_from_hex,
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
    secret_hex: String,
    public_hex: String,
}
impl DevelopmentIdentity {
    pub fn from_secret_hex(secret: &str) -> Result<Self> {
        let key = signing_key_from_hex(secret).map_err(|e| Error::from(format!("AUTH_KEY:{e}")))?;
        ensure(hex::encode(key.to_bytes()) == secret, "AUTH_KEY_CANONICAL")?;
        Ok(Self {
            secret_hex: secret.to_owned(),
            public_hex: public_key_hex(&key),
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_hex
    }

    fn sign(&self, message: &[u8]) -> Result<String> {
        let key = signing_key_from_hex(&self.secret_hex)
            .map_err(|e| Error::from(format!("AUTH_KEY:{e}")))?;
        Ok(sign_hex(&key, message))
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
}
fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
fn measured_work_verify(packet: Packet, metrics: &Mutex<Metrics>) -> Result<WorkCheckedPacket> {
    let start = Instant::now();
    metrics
        .lock()
        .map_err(|_| "METRICS_POISONED")?
        .work_verifications += 1;
    let result = WorkCheckedPacket::verify(packet);
    let mut counts = metrics.lock().map_err(|_| "METRICS_POISONED")?;
    counts.work_verification_ns = counts
        .work_verification_ns
        .saturating_add(elapsed_ns(start));
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

fn submit_result(node: &mut Node, id: Hash, clock: u64) -> Result<Value> {
    let active = node.activate_observed(id, clock)?;
    Ok(json!({"block":hex::encode(id),"active":hex::encode(active),
        "generation":node.active()?.1,"physical_execution":false}))
}

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
    match request {
        Request::Submit { packet } => {
            let packet = hex_packet(&packet)?;
            {
                let mut owner = lock_owner(node, progress)?;
                let clock = now()?;
                if let Some(id) = owner.check_admission_context(&packet, clock)? {
                    return submit_result(&mut owner, id, clock);
                }
            }
            progress(0)?;
            let checked = verify(packet)?;
            // Cancellation after work must not turn into a durable admission.
            progress(0)?;
            let mut owner = lock_owner(node, progress)?;
            let clock = now()?;
            let id = owner.admit_work_checked_with_progress(checked, clock, execution_progress)?;
            submit_result(&mut owner, id, clock)
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
    if authentication.is_none() {
        ensure(
            listener.local_addr()?.ip().is_loopback(),
            "DEVELOPMENT_LOOPBACK_ONLY",
        )?;
    }
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
            workers.push(scope.spawn(move || -> Result<()> {
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
                            let reserved_refusal = error.to_string() == RESERVED_READ_ONLY_BUSY;
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
                        ensure(!stop.load(Ordering::Acquire), "CANCELLED")?;
                        ensure(Instant::now() < request_deadline, "REQUEST_DEADLINE")
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
                            owner.begin_authenticated_request(request.frame, &request.payload)
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
                            |packet| measured_work_verify(packet, &metrics),
                        );
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
                        measured_work_verify(packet, &metrics)
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

/// A valid terminal response advances the caller-owned nonce. Network failures and
/// nonterminal Busy responses preserve it for exact retry.
pub fn call_authenticated(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Value> {
    call_authenticated_inner(address, request, settings, client, replay_nonce, false)
}
pub fn call_authenticated_protected(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Value> {
    call_authenticated_inner(address, request, settings, client, replay_nonce, true)
}
fn call_authenticated_inner(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
    protected: bool,
) -> Result<Value> {
    let nonce = *replay_nonce;
    let bytes = authenticated_request_bytes(settings, client, nonce, request.clone())?;
    let envelope: AuthenticatedRequest = serde_json::from_slice(&bytes)?;
    let request_digest =
        request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let profile = if protected {
        write_protected_request_bound(&mut stream, request, &bytes)?
    } else {
        write_frame(&mut stream, &bytes)?;
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
        read_frame(&mut stream)?
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
    Err(format!(
        "{}:{error}",
        if terminal {
            "REMOTE_TERMINAL"
        } else {
            "REMOTE_RETRYABLE"
        }
    )
    .into())
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
    call_authenticated_durable_inner(node, address, request, client, false)
}
pub fn call_authenticated_durable_protected(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
) -> Result<Value> {
    call_authenticated_durable_inner(node, address, request, client, true)
}
fn call_authenticated_durable_inner(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
    protected: bool,
) -> Result<Value> {
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
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let profile = if protected {
        write_protected_request_bound(&mut stream, request, &verified.wire)?
    } else {
        write_frame(&mut stream, &verified.wire)?;
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
        read_frame(&mut stream)?
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
    Err(format!(
        "{}:{error}",
        if terminal {
            "REMOTE_TERMINAL"
        } else {
            "REMOTE_RETRYABLE"
        }
    )
    .into())
}

pub fn receive_page(
    node: &mut Node,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
) -> Result<Hash> {
    ensure(
        page.schema == "pon-native-history-v1"
            && page.network == hex::encode(node.settings().network())
            && page.parameters == hex::encode(node.settings().parameters())
            && page.genesis == hex::encode(node.settings().genesis()),
        "PAGE_CONTEXT",
    )?;
    ensure(
        page.tip == hex::encode(tip)
            && page.after == hex::encode(after)
            && page.packets.len() <= 16,
        "PAGE_CURSOR",
    )?;
    ensure(
        !page.packets.is_empty() || (after == tip && page.complete),
        "EMPTY_PAGE",
    )?;
    ensure(
        page.packets.iter().map(String::len).sum::<usize>() <= MAX_FRAME - 1024,
        "PAGE_LIMIT",
    )?;
    let packets = page
        .packets
        .iter()
        .map(|s| hex_packet(s))
        .collect::<Result<Vec<_>>>()?;
    let mut next = after;
    for packet in &packets {
        ensure(packet.header.parent == next, "PAGE_PARENT")?;
        next = packet.id()?;
    }
    ensure(
        page.next == hex::encode(next) && page.complete == (next == tip),
        "PAGE_COMPLETE",
    )?;
    for packet in &packets {
        node.admit(packet, clock)?;
    }
    if page.complete {
        node.activate_observed(tip, clock)?;
    }
    Ok(next)
}
pub fn sync_from(
    node: &mut Node,
    address: SocketAddr,
    tip: Hash,
    mut after: Hash,
    page_budget: usize,
) -> Result<Hash> {
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    for _ in 0..page_budget {
        let request = Request::History {
            tip: hex::encode(tip),
            after: hex::encode(after),
        };
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        write_frame(&mut stream, &serde_json::to_vec(&request)?)?;
        let page: Page = serde_json::from_slice(&read_frame(&mut stream)?)?;
        let complete = page.complete;
        after = receive_page(node, page, tip, after, now()?)?;
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
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    let settings = node.settings().clone();
    for _ in 0..page_budget {
        let value = call_authenticated(
            address,
            &Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            &settings,
            client,
            replay_nonce,
        )?;
        let page: Page = serde_json::from_value(value)?;
        let complete = page.complete;
        after = receive_page(node, page, tip, after, now()?)?;
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
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    for _ in 0..page_budget {
        let value = call_authenticated_durable(
            node,
            address,
            &Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            client,
        )?;
        let page: Page = serde_json::from_value(value)?;
        let complete = page.complete;
        after = receive_page(node, page, tip, after, now()?)?;
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
        let dir = tempfile::tempdir().unwrap();
        let clock = now().unwrap();
        let settings = crate::Settings::development(Some(clock - 100)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
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
    fn cancellation_set_at_durable_commit_boundary_preserves_submit_activation_and_reply() {
        use trnm_mvcc_fee::pon_executor::ExecutionProgress;
        let (dir, node, packet) = pending_packet();
        let expected = packet.id().unwrap();
        let settings = node.lock().unwrap().settings().clone();
        let cancelled = AtomicBool::new(false);
        let reply = dispatch_shared_with_execution_progress(
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
        .unwrap();
        assert!(cancelled.load(Ordering::Acquire));
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
                Err(error) if error.to_string().starts_with("REMOTE_RETRYABLE:") => {
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
