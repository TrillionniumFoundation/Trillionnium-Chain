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
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub busy_requests: u64,
    pub malformed_requests: u64,
    pub authenticated_requests: u64,
    pub replayed_responses: u64,
    pub pending_busy_requests: u64,
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
    Ok(())
}
fn read_frame_budget(stream: &mut TcpStream, budget: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + budget;
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
    ensure((1..=MAX_FRAME).contains(&bytes.len()), "FRAME_LIMIT")?;
    let deadline = Instant::now() + Duration::from_secs(5);
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
    Ok(())
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
            let id = owner.admit_work_checked(checked, clock)?;
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
    serve_inner(listener, node, lifetime, stop, None)
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
    )
}

fn serve_inner(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    authentication: Option<Arc<AuthenticatedServer>>,
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
    let deadline = Instant::now() + lifetime;
    thread::scope(|scope| -> Result<()> {
        let mut workers = Vec::new();
        for listener in listeners {
            let node = node.clone();
            let metrics = metrics.clone();
            let active_requests = active_requests.clone();
            let public = public.clone();
            let stop = stop.clone();
            let authentication = authentication.clone();
            let settings = settings.clone();
            workers.push(scope.spawn(move || -> Result<()> {
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    let (mut socket, address) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    };
                    let request_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
                    socket.set_nonblocking(false)?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                    let bytes = match read_frame(&mut socket) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .malformed_requests += 1;
                            let _ = write_frame(
                                &mut socket,
                                &serde_json::to_vec(&json!({"error":e.to_string()}))?,
                            );
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
                                let _ = write_frame(
                                    &mut socket,
                                    &serde_json::to_vec(&json!({"error":error.to_string()}))?,
                                );
                                continue;
                            }
                        };
                        let _permit = match public.try_acquire(
                            request.frame.session().peer_id().bytes(),
                            request.frame.payload_digest().bytes(),
                        ) {
                            Ok(permit) => permit,
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
                            WorkCheckedPacket::verify,
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
                    let peer = hash(b"native-peer-ip", &[address.ip().to_string().as_bytes()]);
                    let _permit = match public.try_acquire(peer, hash(b"native-request", &[&bytes]))
                    {
                        Ok(permit) => permit,
                        Err(error) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .busy_requests += 1;
                            let _ = write_frame(
                                &mut socket,
                                &serde_json::to_vec(&json!({"error":format!("BUSY:{error:?}")}))?,
                            );
                            continue;
                        }
                    };
                    let result = (|| -> Result<Value> {
                        let request: Request = serde_json::from_slice(&bytes)?;
                        dispatch_shared_with(
                            &node,
                            request,
                            &mut progress,
                            WorkCheckedPacket::verify,
                        )
                    })();
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

/// A valid terminal response advances the caller-owned nonce. Network failures and
/// nonterminal Busy responses preserve it for exact retry.
pub fn call_authenticated(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    client: &AuthenticatedClient,
    replay_nonce: &mut u64,
) -> Result<Value> {
    let nonce = *replay_nonce;
    let bytes = authenticated_request_bytes(settings, client, nonce, request.clone())?;
    let envelope: AuthenticatedRequest = serde_json::from_slice(&bytes)?;
    let request_digest =
        request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut stream, &bytes)?;
    let response = read_frame(&mut stream)?;
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

/// Persist one exact signed request before network I/O. A missing or nonterminal response
/// leaves the same bytes pending; a verified terminal response advances the durable nonce.
pub fn call_authenticated_durable(
    node: &mut Node,
    address: SocketAddr,
    request: &Request,
    client: &AuthenticatedClient,
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
    write_frame(&mut stream, &verified.wire)?;
    let response = read_frame(&mut stream)?;
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
        let wire = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        let request = outbound_authenticated_request(&wire, &settings, &client).unwrap();
        client_node
            .reserve_authenticated_outbound(request.frame, &request.payload, &wire)
            .unwrap();
        {
            let mut stream = TcpStream::connect(address).unwrap();
            write_frame(&mut stream, &wire).unwrap();
        }
        drop(client_node);
        thread::sleep(Duration::from_millis(50));

        let mut client_node = Node::open(client_dir.path(), settings, 1).unwrap();
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
