//! Public development intake: resource tickets confer no ledger/source authority.
//! Explicit development profile. No peer/nonce/replay row is persisted for unknown callers.
use super::{
    digest, elapsed_ns, ensure, hash, lock_owner, DevelopmentIdentity, Node, Request, Result,
    Settings, WorkCheckedPacket,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_protocol::pon_wire::Hash;

pub const PROFILE: &str = "public-protected-development-v2";
const HELLO_BYTES: usize = 108;
const SOLUTION_BYTES: usize = 108;
const MAX_PACKET: usize = 1_048_576;
const MAX_BODY: usize = 2 * MAX_PACKET + 64;
const MAX_READ_BODY: usize = 512;
const MAX_RESPONSE: usize = 2 * MAX_PACKET + 4096;
const MAX_CONNECTIONS: usize = 64;
const MAX_PAID_BODY_BYTES: usize = 8 * 1024 * 1024;
// Reservations partition the existing totals; no added socket/worker/queue.
const READ_BODY_RESERVE: usize = 128 * 1024;
const CONTROL_OUTPUT_RESERVE: usize = 512 * 1024;
const MAX_MUTATING_GRANTS: usize = 8;
const MAX_READ_GRANTS: usize = 8;
const MAX_SPENT: usize = 1024;
const MAX_HISTORY_STEPS: u64 = crate::ancestry_index::READ_SQL_BUDGET;
const PREFIX_MS: u64 = 2000;
const CHALLENGE_MS: u64 = 2000;
const BODY_MS: u64 = 5000;
const OVERALL_MS: u64 = 30000;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const OUTPUT_MS: u64 = 5000;
const WORK_MS: u64 = 10_000;
const CHALLENGES_PER_SECOND: u64 = 128;
const CHALLENGE_BURST: u64 = 32;
const READ_CHALLENGE_RESERVE: u64 = 8;
const IO_QUANTUM: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPolicy {
    pub bits: u8,
    pub lifetime_ms: u64,
}
impl PublicPolicy {
    pub fn new(bits: u8, lifetime: Duration) -> Result<Self> {
        let lifetime_ms = u64::try_from(lifetime.as_millis()).map_err(|_| "PUBLIC_POLICY")?;
        ensure(
            (8..=20).contains(&bits) && (100..=2000).contains(&lifetime_ms),
            "PUBLIC_POLICY",
        )?;
        Ok(Self { bits, lifetime_ms })
    }
    pub fn development() -> Self {
        Self {
            bits: 16,
            lifetime_ms: 2000,
        }
    }
    pub fn id(self) -> Hash {
        hash(b"public-protected-profile-v2",&[PROFILE.as_bytes(),b"resource-revision-r2/hello108/solution108/conn64/paid-raw-json-canonical8MiB-factor3/read-body-reserve131072/output-conservative32MiB/head-output-reserve524288/grants-mutation8-read8-held-until-connection-and-task-release/queueproof2-read2/workers2-read1/spent1024-no-live-eviction/packet1048576/body2097216/read512/response2101248/history1/error2KiB/hello2s/challenge2s/solution-policy/body5s/work10s/output5s/overall30s/quantum64KiB/derived-jump-v1-levels63-sql1024-local-integrity-only/challenge128-burst32-read-reserve8/await-write-half-close-cancels-request-operation-stage-fences/ops1-block-2-head-3-history/service1h-no-pool-no-mine/no-durable-guest-rows",&[self.bits],&self.lifetime_ms.to_le_bytes()])
    }
}
#[derive(Default, Clone, Debug, Serialize)]
pub struct PublicMetrics {
    pub accepted_connections: u64,
    pub capacity_refusals: u64,
    pub preface_refusals: u64,
    pub challenge_budget_refusals: u64,
    pub issued_challenges: u64,
    pub ticket_refusals: u64,
    pub signature_refusals: u64,
    pub spent_capacity_refusals: u64,
    pub paid_body_capacity_refusals: u64,
    pub lane_capacity_refusals: u64,
    pub disconnected_await_requests: u64,
    pub tasks_skipped_before_dispatch: u64,
    pub abandoned_tasks: u64,
    pub tasks_enqueued: u64,
    pub tasks_dequeued: u64,
    pub replay_refusals: u64,
    pub queue_refusals: u64,
    pub parse_refusals: u64,
    pub work_started: u64,
    pub work_finished: u64,
    pub work_failed: u64,
    pub work_ns: u64,
    pub executor_refusals: u64,
    pub completed_submit: u64,
    pub completed_read: u64,
    pub expired_connections: u64,
    pub expired_phase_counts: BTreeMap<String, u64>,
    pub connections_closed_on_shutdown: usize,
    pub response_write_failures: u64,
    pub output_serialization_failures: u64,
    pub peak_connections: usize,
    pub peak_paid_body_bytes: usize,
    pub peak_mutating_grants: usize,
    pub peak_read_grants: usize,
    pub peak_spent: usize,
    pub peak_output_reserved_bytes: usize,
    pub delivered_response_frames: u64,
    pub retained_phase_errors: BTreeMap<String, u64>,
    pub body_bytes_received: u64,
    pub response_bytes_written: u64,
    pub cleanup_scans: u64,
    pub unknown_caller_durable_rows: u64,
    pub paid_body_reserved_bytes_after_shutdown: usize,
    pub output_reserved_bytes_after_shutdown: usize,
    pub mutating_grants_after_shutdown: usize,
    pub read_grants_after_shutdown: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cookie {
    schema: String,
    profile: String,
    network: String,
    parameters: String,
    genesis: String,
    server: String,
    epoch: String,
    connection_nonce: String,
    peer_binding: String,
    caller: String,
    client_nonce: String,
    op: u8,
    body_len: u32,
    body_digest: String,
    bits: u8,
    lifetime_ms: u64,
    issued_tick_ms: u64,
    expires_tick_ms: u64,
    mac: String,
    signature: String,
}
impl Cookie {
    fn unsigned(&self) -> Result<Vec<u8>> {
        let mut c = self.clone();
        c.mac.clear();
        c.signature.clear();
        Ok(serde_json::to_vec(&c)?)
    }
    fn server_message(&self) -> Result<Hash> {
        let mut c = self.clone();
        c.signature.clear();
        Ok(hash(
            b"public-cookie-server-sign-v2",
            &[&serde_json::to_vec(&c)?],
        ))
    }
    fn id(&self) -> Result<Hash> {
        Ok(hash(b"public-cookie-id-v2", &[&serde_json::to_vec(self)?]))
    }
}
fn hmac(secret: &[u8; 32], message: &[u8]) -> Hash {
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for i in 0..32 {
        inner[i] ^= secret[i];
        outer[i] ^= secret[i];
    }
    let mut h = Sha256::new();
    h.update(inner);
    h.update(message);
    let first = h.finalize();
    let mut h = Sha256::new();
    h.update(outer);
    h.update(first);
    h.finalize().into()
}
fn equal_mac(a: Hash, b: Hash) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
fn winner(cookie: Hash, nonce: u64, bits: u8) -> bool {
    let h = hash(b"public-ticket-v2", &[&cookie, &nonce.to_le_bytes()]);
    u32::from_be_bytes(h[..4].try_into().expect("fixed hash")).leading_zeros() >= u32::from(bits)
}
fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut xs = [0; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut xs)?;
    Ok(xs)
}
fn request_op(request: &Request) -> Result<u8> {
    match request {
        Request::Submit { .. } => Ok(1),
        Request::Head => Ok(2),
        Request::History { .. } => Ok(3),
        _ => Err("PUBLIC_OPERATION".into()),
    }
}
#[derive(Clone, Copy)]
struct Hello {
    op: u8,
    len: usize,
    caller: Hash,
    digest: Hash,
    client_nonce: Hash,
}
impl Hello {
    fn parse(raw: &[u8]) -> Result<Self> {
        ensure(
            raw.len() == HELLO_BYTES && raw[..4] == *b"PPH2" && raw[5..8] == [0; 3],
            "PUBLIC_HELLO",
        )?;
        let op = raw[4];
        let len = u32::from_le_bytes(raw[8..12].try_into().map_err(|_| "PUBLIC_HELLO")?) as usize;
        ensure(
            matches!(op, 1..=3) && len > 0 && len <= if op == 1 { MAX_BODY } else { MAX_READ_BODY },
            "PUBLIC_BODY_LIMIT",
        )?;
        Ok(Self {
            op,
            len,
            caller: raw[12..44].try_into().map_err(|_| "PUBLIC_HELLO")?,
            digest: raw[44..76].try_into().map_err(|_| "PUBLIC_HELLO")?,
            client_nonce: raw[76..108].try_into().map_err(|_| "PUBLIC_HELLO")?,
        })
    }
    fn encode(self) -> Vec<u8> {
        let mut xs = b"PPH2".to_vec();
        xs.push(self.op);
        xs.extend([0; 3]);
        xs.extend((self.len as u32).to_le_bytes());
        xs.extend(self.caller);
        xs.extend(self.digest);
        xs.extend(self.client_nonce);
        xs
    }
}
pub struct PublicServer {
    identity: DevelopmentIdentity,
    policy: PublicPolicy,
    secret: Hash,
    epoch: Hash,
    started: Instant,
    #[cfg(test)]
    fail_next_output: AtomicBool,
}
impl PublicServer {
    pub fn new(identity: DevelopmentIdentity, policy: PublicPolicy) -> Result<Self> {
        PublicPolicy::new(policy.bits, Duration::from_millis(policy.lifetime_ms))?;
        Ok(Self {
            identity,
            policy,
            secret: entropy()?,
            epoch: entropy()?,
            started: Instant::now(),
            #[cfg(test)]
            fail_next_output: AtomicBool::new(false),
        })
    }
    fn tick(&self) -> Result<u64> {
        u64::try_from(self.started.elapsed().as_millis()).map_err(|_| "PUBLIC_CLOCK".into())
    }
    fn cookie(&self, s: &Settings, h: Hello, peer: SocketAddr) -> Result<Cookie> {
        let tick = self.tick()?;
        let mut c = Cookie {
            schema: "public-resource-cookie-v2".into(),
            profile: hex::encode(self.policy.id()),
            network: hex::encode(s.network()),
            parameters: hex::encode(s.parameters()),
            genesis: hex::encode(s.genesis()),
            server: self.identity.public_key().into(),
            epoch: hex::encode(self.epoch),
            connection_nonce: hex::encode(entropy::<32>()?),
            peer_binding: hex::encode(hash(
                b"public-peer-binding-v2",
                &[peer.to_string().as_bytes()],
            )),
            caller: hex::encode(h.caller),
            client_nonce: hex::encode(h.client_nonce),
            op: h.op,
            body_len: h.len as u32,
            body_digest: hex::encode(h.digest),
            bits: self.policy.bits,
            lifetime_ms: self.policy.lifetime_ms,
            issued_tick_ms: tick,
            expires_tick_ms: tick
                .checked_add(self.policy.lifetime_ms)
                .ok_or("PUBLIC_CLOCK")?,
            mac: String::new(),
            signature: String::new(),
        };
        c.mac = hex::encode(hmac(&self.secret, &c.unsigned()?));
        c.signature = self.identity.sign(&c.server_message()?)?;
        Ok(c)
    }
    fn validate(&self, c: &Cookie, s: &Settings, check_expiry: bool) -> Result<()> {
        ensure(
            c.schema == "public-resource-cookie-v2"
                && c.profile == hex::encode(self.policy.id())
                && c.network == hex::encode(s.network())
                && c.parameters == hex::encode(s.parameters())
                && c.genesis == hex::encode(s.genesis())
                && c.server == self.identity.public_key()
                && c.epoch == hex::encode(self.epoch)
                && c.bits == self.policy.bits
                && c.lifetime_ms == self.policy.lifetime_ms,
            "PUBLIC_COOKIE_CONTEXT",
        )?;
        ensure(
            c.issued_tick_ms <= self.tick()?
                && (!check_expiry || self.tick()? < c.expires_tick_ms)
                && c.expires_tick_ms.checked_sub(c.issued_tick_ms) == Some(self.policy.lifetime_ms),
            "PUBLIC_COOKIE_EXPIRED",
        )?;
        ensure(
            equal_mac(digest(&c.mac)?, hmac(&self.secret, &c.unsigned()?)),
            "PUBLIC_COOKIE_MAC",
        )
    }
}
struct Spent {
    rows: BTreeMap<Hash, u64>,
}
impl Spent {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }
    fn cleanup(&mut self, tick: u64) {
        self.rows.retain(|_, expiry| *expiry > tick);
    }
    fn reserve(&mut self, id: Hash, expiry: u64, tick: u64) -> Result<()> {
        ensure(expiry > tick, "PUBLIC_COOKIE_EXPIRED")?;
        ensure(!self.rows.contains_key(&id), "PUBLIC_TICKET_REPLAY")?;
        ensure(self.rows.len() < MAX_SPENT, "PUBLIC_SPENT_CAPACITY")?;
        self.rows.insert(id, expiry);
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: String,
    profile: String,
    network: String,
    parameters: String,
    genesis: String,
    server: String,
    cookie_digest: String,
    request_digest: String,
    ok: bool,
    value: Value,
    signature: String,
}
impl Response {
    fn message(&self) -> Result<Hash> {
        let mut r = Self {
            schema: self.schema.clone(),
            profile: self.profile.clone(),
            network: self.network.clone(),
            parameters: self.parameters.clone(),
            genesis: self.genesis.clone(),
            server: self.server.clone(),
            cookie_digest: self.cookie_digest.clone(),
            request_digest: self.request_digest.clone(),
            ok: self.ok,
            value: self.value.clone(),
            signature: String::new(),
        };
        r.signature.clear();
        Ok(hash(
            b"public-response-sign-v2",
            &[&serde_json::to_vec(&r)?],
        ))
    }
}
fn framed(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>> {
    ensure(
        !bytes.is_empty() && bytes.len() <= maximum,
        "PUBLIC_OUTPUT_LIMIT",
    )?;
    let mut xs = (bytes.len() as u32).to_be_bytes().to_vec();
    xs.extend(bytes);
    Ok(xs)
}
fn response(
    server: &PublicServer,
    s: &Settings,
    c: &Cookie,
    outcome: Result<Value>,
) -> Result<Vec<u8>> {
    let (ok, value) = match outcome {
        Ok(v) => (true, v),
        Err(e) => (
            false,
            json!({"error":e.to_string().chars().take(128).collect::<String>()}),
        ),
    };
    let mut r = Response {
        schema: "public-protected-response-v2".into(),
        profile: hex::encode(server.policy.id()),
        network: hex::encode(s.network()),
        parameters: hex::encode(s.parameters()),
        genesis: hex::encode(s.genesis()),
        server: server.identity.public_key().into(),
        cookie_digest: hex::encode(c.id()?),
        request_digest: c.body_digest.clone(),
        ok,
        value,
        signature: String::new(),
    };
    r.signature = server.identity.sign(&r.message()?)?;
    framed(serde_json::to_vec(&r)?, MAX_RESPONSE)
}
/// Streaming canonical equality avoids another body-sized serialization Vec.
struct ExactCanonical<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl Write for ExactCanonical<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical overflow"))?;
        if self.bytes.get(self.cursor..end) != Some(bytes) {
            return Err(std::io::Error::other("noncanonical request"));
        }
        self.cursor = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_request(bytes: &[u8], op: u8) -> Result<Request> {
    if op == 1 {
        // Reject escaping/non-hex packet text before serde's scratch allocation.
        let prefix = br#"{"op":"submit","packet":""#;
        let text = bytes
            .strip_prefix(prefix)
            .and_then(|b| b.strip_suffix(br#""}"#))
            .ok_or("PUBLIC_REQUEST_CANONICAL")?;
        ensure(
            text.len() <= 2 * MAX_PACKET
                && text.len().is_multiple_of(2)
                && text
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "PUBLIC_PACKET_TEXT",
        )?;
    }
    let request: Request = serde_json::from_slice(bytes)?;
    let mut writer = ExactCanonical { bytes, cursor: 0 };
    serde_json::to_writer(&mut writer, &request).map_err(|_| "PUBLIC_REQUEST_CANONICAL")?;
    ensure(
        writer.cursor == bytes.len() && request_op(&request)? == op,
        "PUBLIC_REQUEST_CANONICAL",
    )?;
    Ok(request)
}
struct BufferPermit {
    pool: Arc<Mutex<usize>>,
    bytes: usize,
}
impl BufferPermit {
    fn acquire(pool: Arc<Mutex<usize>>, bytes: usize, maximum: usize) -> Result<Self> {
        let mut used = pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
        ensure(
            bytes <= maximum.saturating_sub(*used),
            "PUBLIC_BUFFER_CAPACITY",
        )?;
        *used += bytes;
        drop(used);
        Ok(Self { pool, bytes })
    }
}
impl Drop for BufferPermit {
    fn drop(&mut self) {
        if let Ok(mut used) = self.pool.lock() {
            *used = used.saturating_sub(self.bytes);
        }
    }
}
struct Task {
    _permit: BufferPermit,
    _lane_permit: Arc<BufferPermit>,
    id: u64,
    cookie: Cookie,
    request: Request,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
struct Finished {
    permit: Option<BufferPermit>,
    id: u64,
    bytes: Result<Vec<u8>>,
}
enum Stage {
    Hello(Vec<u8>),
    Challenge {
        cookie: Cookie,
        bytes: Vec<u8>,
        cursor: usize,
    },
    Solution {
        cookie: Cookie,
        bytes: Vec<u8>,
    },
    Ready {
        cookie: Cookie,
        bytes: Vec<u8>,
        cursor: usize,
    },
    Body {
        cookie: Cookie,
        bytes: Vec<u8>,
    },
    Await,
    Output {
        bytes: Vec<u8>,
        cursor: usize,
        _permit: Option<BufferPermit>,
    },
}
impl Stage {
    fn phase(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Challenge { .. } => "challenge",
            Self::Solution { .. } => "solution",
            Self::Ready { .. } => "ready",
            Self::Body { .. } => "body",
            Self::Await => "work",
            Self::Output { .. } => "output",
        }
    }
}
struct Connection {
    id: u64,
    socket: TcpStream,
    peer: SocketAddr,
    deadline: Instant,
    stage: Stage,
    total_deadline: Instant,
    permit: Option<BufferPermit>,
    lane_permit: Option<Arc<BufferPermit>>,
    cancelled: Arc<AtomicBool>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
fn task_alive(deadline: Instant, stop: &AtomicBool, cancelled: &AtomicBool) -> Result<()> {
    ensure(
        !cancelled.load(Ordering::Acquire),
        "PUBLIC_REQUEST_CANCELLED",
    )?;
    ensure(
        !stop.load(Ordering::Acquire) && Instant::now() < deadline,
        "PUBLIC_REQUEST_DEADLINE",
    )
}
fn read_available(socket: &mut TcpStream, bytes: &mut Vec<u8>, expected: usize) -> Result<bool> {
    ensure(bytes.len() <= expected, "PUBLIC_READ_OVERFLOW")?;
    let remaining = expected - bytes.len();
    if remaining == 0 {
        return Ok(true);
    }
    let mut buffer = [0; IO_QUANTUM];
    match socket.read(&mut buffer[..remaining.min(IO_QUANTUM)]) {
        Ok(0) => Err("PUBLIC_EOF".into()),
        Ok(n) => {
            bytes.extend(&buffer[..n]);
            Ok(bytes.len() == expected)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}
fn write_available(socket: &mut TcpStream, bytes: &[u8], cursor: &mut usize) -> Result<bool> {
    match socket.write(&bytes[*cursor..bytes.len().min(*cursor + IO_QUANTUM)]) {
        Ok(0) => Err("PUBLIC_EOF".into()),
        Ok(n) => {
            *cursor += n;
            Ok(*cursor == bytes.len())
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}
fn public_dispatch(
    node: &Mutex<Node>,
    request: Request,
    deadline: Instant,
    stop: &AtomicBool,
    cancelled: &AtomicBool,
    metrics: &Mutex<PublicMetrics>,
) -> Result<Value> {
    let mut progress = |steps: u64| {
        task_alive(deadline, stop, cancelled)?;
        ensure(steps <= MAX_HISTORY_STEPS, "PUBLIC_HISTORY_STEPS")
    };
    match request {
        Request::Submit { packet } => {
            super::dispatch_shared_with(node, Request::Submit { packet }, &mut progress, |packet| {
                task_alive(deadline, stop, cancelled)?;
                let start = Instant::now();
                metrics.lock().map_err(|_| "PUBLIC_METRICS")?.work_started += 1;
                let result = WorkCheckedPacket::verify(packet);
                let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                m.work_ns = m.work_ns.saturating_add(elapsed_ns(start));
                m.work_finished += 1;
                if result.is_err() {
                    m.work_failed += 1;
                }
                result
            })
        }
        Request::Head => {
            let owner = lock_owner(node, &mut progress)?;
            owner.public_head_metadata()
        }
        Request::History { tip, after } => {
            let owner = lock_owner(node, &mut progress)?;
            let tip_id = digest(&tip)?;
            let after_id = digest(&after)?;
            let packets =
                owner.public_history_packet(tip_id, after_id, MAX_HISTORY_STEPS, &mut progress)?;
            let next = packets
                .last()
                .map(|p| p.id().map(hex::encode))
                .transpose()?
                .unwrap_or_else(|| after.clone());
            let mut encoded = Vec::new();
            for packet in packets {
                let raw = packet.encode()?;
                ensure(
                    raw.len()
                        .checked_mul(2)
                        .is_some_and(|n| n <= 2 * MAX_PACKET),
                    "PUBLIC_HISTORY_BYTES",
                )?;
                encoded.push(hex::encode(raw));
            }
            Ok(serde_json::to_value(super::Page {
                schema: "pon-native-history-v1".into(),
                network: hex::encode(owner.settings().network()),
                parameters: hex::encode(owner.settings().parameters()),
                genesis: hex::encode(owner.settings().genesis()),
                tip,
                after,
                complete: next == hex::encode(tip_id),
                next,
                packets: encoded,
            })?)
        }
        _ => Err("PUBLIC_OPERATION".into()),
    }
}

/// Dedicated successor. No authentication roster or durable guest operation table.
/// A finite engineering service; global saturation can still deny honest callers.
pub fn serve_public_protected_v2(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
) -> Result<PublicMetrics> {
    ensure(
        lifetime > Duration::ZERO && lifetime <= Duration::from_secs(3600),
        "PUBLIC_LIFETIME",
    )?;
    let settings = node.settings().clone();
    let node = Arc::new(Mutex::new(node));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    serve_public_protected_v2_with_owner(listener, node, settings, lifetime, stop, server, metrics)
}
// Private composition of the same single durable owner. No guest pool enable,
// public shared-owner API, new scheduler or source authority is introduced.
fn serve_public_protected_v2_with_owner(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    settings: Settings,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
    metrics: Arc<Mutex<PublicMetrics>>,
) -> Result<PublicMetrics> {
    ensure(
        lifetime > Duration::ZERO && lifetime <= Duration::from_secs(3600),
        "PUBLIC_LIFETIME",
    )?;
    listener.set_nonblocking(true)?;
    let end = Instant::now() + lifetime;
    let (proof_tx, proof_rx) = mpsc::sync_channel::<Task>(2);
    let (read_tx, read_rx) = mpsc::sync_channel::<Task>(2);
    let proof_rx = Arc::new(Mutex::new(proof_rx));
    let read_rx = Arc::new(Mutex::new(read_rx));
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Finished>(8);
    let mut connections = BTreeMap::<u64, Connection>::new();
    let mut next_id = 0u64;
    let mut spent = Spent::new();
    let body_pool = Arc::new(Mutex::new(0usize));
    let output_pool = Arc::new(Mutex::new(0usize));
    let mutating_grants = Arc::new(Mutex::new(0usize));
    let read_grants = Arc::new(Mutex::new(0usize));
    let mut challenge_tokens = CHALLENGE_BURST;
    let mut refill = Instant::now();
    let mut last_cleanup = Instant::now();
    thread::scope(|scope| -> Result<()> {
        let mut workers = Vec::new();
        for index in 0..3 {
            let queue = if index < 2 {
                proof_rx.clone()
            } else {
                read_rx.clone()
            };
            let finished = finished_tx.clone();
            let node = node.clone();
            let metrics = metrics.clone();
            let stop = stop.clone();
            let output_pool = output_pool.clone();
            let server = &server;
            let settings = &settings;
            workers.push(scope.spawn(move || -> Result<()> {
                loop {
                    let task = queue.lock().map_err(|_| "PUBLIC_QUEUE")?.try_recv();
                    match task {
                        Ok(task) => {
                            metrics.lock().map_err(|_| "PUBLIC_METRICS")?.tasks_dequeued += 1;
                            if task_alive(task.deadline, &stop, &task.cancelled).is_err() {
                                let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                m.tasks_skipped_before_dispatch += 1;
                                if task.cancelled.load(Ordering::Acquire) {
                                    m.abandoned_tasks += 1;
                                }
                                continue;
                            }
                            let response_max = if task.cookie.op == 3 {
                                MAX_RESPONSE
                            } else {
                                16384
                            };
                            let permit = BufferPermit::acquire(
                                output_pool.clone(),
                                response_max * 4,
                                if task.cookie.op == 2 {
                                    MAX_OUTPUT_BYTES
                                } else {
                                    MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE
                                },
                            );
                            let (permit, outcome) = match permit {
                                Ok(permit) => (
                                    Some(permit),
                                    public_dispatch(
                                        &node,
                                        task.request,
                                        task.deadline,
                                        &stop,
                                        &task.cancelled,
                                        &metrics,
                                    ),
                                ),
                                Err(e) => (None, Err(e)),
                            };
                            let reserved = *output_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            m.peak_output_reserved_bytes =
                                m.peak_output_reserved_bytes.max(reserved);
                            if outcome.is_ok() {
                                if task.cookie.op == 1 {
                                    m.completed_submit += 1;
                                } else {
                                    m.completed_read += 1;
                                }
                            } else if task.cookie.op == 1 {
                                m.executor_refusals += 1;
                            }
                            drop(m);
                            if task.cancelled.load(Ordering::Acquire) {
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .abandoned_tasks += 1;
                                continue;
                            }
                            // Sign and serialize in the worker, after reserving output
                            // capacity. The socket reactor only copies bounded chunks.
                            let bytes = response(server, settings, &task.cookie, outcome);
                            // Negative fault injection is compiled only for unit tests;
                            // native dispatch and signing still execute first.
                            #[cfg(test)]
                            let bytes = if server.fail_next_output.swap(false, Ordering::AcqRel) {
                                Err("TEST_OUTPUT_SERIALIZATION_FAILURE".into())
                            } else {
                                bytes
                            };
                            if finished
                                .send(Finished {
                                    permit,
                                    id: task.id,
                                    bytes,
                                })
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(TryRecvError::Empty) => {
                            if stop.load(Ordering::Acquire) || Instant::now() >= end {
                                return Ok(());
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(TryRecvError::Disconnected) => return Ok(()),
                    }
                }
            }));
        }
        let outcome = (|| -> Result<()> {
            while !stop.load(Ordering::Acquire) && Instant::now() < end {
                let elapsed = refill.elapsed().as_millis() as u64;
                let credit = elapsed.saturating_mul(CHALLENGES_PER_SECOND) / 1000;
                if credit > 0 {
                    challenge_tokens = (challenge_tokens + credit).min(CHALLENGE_BURST);
                    refill = Instant::now();
                }
                if last_cleanup.elapsed() >= Duration::from_millis(20) {
                    spent.cleanup(server.tick()?);
                    metrics.lock().map_err(|_| "PUBLIC_METRICS")?.cleanup_scans += 1;
                    last_cleanup = Instant::now();
                }
                for _ in 0..8 {
                    match listener.accept() {
                        Ok((socket, peer)) => {
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            m.accepted_connections += 1;
                            if connections.len() >= MAX_CONNECTIONS {
                                m.capacity_refusals += 1;
                                continue;
                            }
                            socket.set_nonblocking(true)?;
                            socket.set_nodelay(true)?;
                            next_id = next_id.checked_add(1).ok_or("PUBLIC_CONNECTION_ID")?;
                            connections.insert(
                                next_id,
                                Connection {
                                    id: next_id,
                                    socket,
                                    peer,
                                    deadline: Instant::now() + Duration::from_millis(PREFIX_MS),
                                    stage: Stage::Hello(Vec::with_capacity(HELLO_BYTES)),
                                    total_deadline: Instant::now()
                                        + Duration::from_millis(OVERALL_MS),
                                    permit: None,
                                    lane_permit: None,
                                    cancelled: Arc::new(AtomicBool::new(false)),
                                },
                            );
                            m.peak_connections = m.peak_connections.max(connections.len());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                for _ in 0..8 {
                    match finished_rx.try_recv() {
                        Ok(done) => {
                            if let Some(conn) = connections.get_mut(&done.id) {
                                ensure(
                                    matches!(conn.stage, Stage::Await),
                                    "PUBLIC_COMPLETION_STATE",
                                )?;
                                let bytes = match done.bytes {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                        m.output_serialization_failures += 1;
                                        *m.retained_phase_errors
                                            .entry("output".into())
                                            .or_default() += 1;
                                        drop(m);
                                        connections.remove(&done.id);
                                        continue;
                                    }
                                };
                                conn.stage = Stage::Output {
                                    bytes,
                                    cursor: 0,
                                    _permit: done.permit,
                                };
                                conn.deadline = conn
                                    .total_deadline
                                    .min(Instant::now() + Duration::from_millis(OUTPUT_MS));
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => return Err("PUBLIC_WORKERS_GONE".into()),
                    }
                }
                let mut remove = Vec::new();
                for (id, conn) in &mut connections {
                    if Instant::now() >= conn.deadline {
                        let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                        m.expired_connections += 1;
                        *m.expired_phase_counts
                            .entry(conn.stage.phase().into())
                            .or_default() += 1;
                        remove.push(*id);
                        continue;
                    }
                    let current = std::mem::replace(&mut conn.stage, Stage::Await);
                    let phase = current.phase();
                    let advanced = (|| -> Result<Stage> {
                        match current {
                            Stage::Hello(mut bytes) => {
                                if !read_available(&mut conn.socket, &mut bytes, HELLO_BYTES)? {
                                    return Ok(Stage::Hello(bytes));
                                }
                                let hello = Hello::parse(&bytes)?;
                                if challenge_tokens == 0
                                    || (hello.op == 1 && challenge_tokens <= READ_CHALLENGE_RESERVE)
                                {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .challenge_budget_refusals += 1;
                                    return Err("PUBLIC_CHALLENGE_BUDGET".into());
                                }
                                challenge_tokens -= 1;
                                let cookie = server.cookie(&settings, hello, conn.peer)?;
                                let frame = framed(serde_json::to_vec(&cookie)?, 2048)?;
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .issued_challenges += 1;
                                conn.deadline = conn
                                    .total_deadline
                                    .min(Instant::now() + Duration::from_millis(CHALLENGE_MS));
                                Ok(Stage::Challenge {
                                    cookie,
                                    bytes: frame,
                                    cursor: 0,
                                })
                            }
                            Stage::Challenge {
                                cookie,
                                bytes,
                                mut cursor,
                            } => {
                                if write_available(&mut conn.socket, &bytes, &mut cursor)? {
                                    conn.deadline = conn.total_deadline.min(
                                        server.started
                                            + Duration::from_millis(cookie.expires_tick_ms),
                                    );
                                    Ok(Stage::Solution {
                                        cookie,
                                        bytes: Vec::with_capacity(SOLUTION_BYTES),
                                    })
                                } else {
                                    Ok(Stage::Challenge {
                                        cookie,
                                        bytes,
                                        cursor,
                                    })
                                }
                            }
                            Stage::Solution { cookie, mut bytes } => {
                                if !read_available(&mut conn.socket, &mut bytes, SOLUTION_BYTES)? {
                                    return Ok(Stage::Solution { cookie, bytes });
                                }
                                server.validate(&cookie, &settings, true)?;
                                ensure(
                                    bytes[..4] == *b"PPS2" && bytes[4..36] == cookie.id()?,
                                    "PUBLIC_SOLUTION",
                                )?;
                                let nonce = u64::from_le_bytes(
                                    bytes[36..44].try_into().map_err(|_| "PUBLIC_SOLUTION")?,
                                );
                                if !winner(cookie.id()?, nonce, server.policy.bits) {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .ticket_refusals += 1;
                                    return Err("PUBLIC_TICKET_TARGET".into());
                                }
                                let auth = hash(
                                    b"public-caller-sign-v2",
                                    &[&cookie.id()?, &nonce.to_le_bytes()],
                                );
                                if verify_hex_strict(
                                    &cookie.caller,
                                    &auth,
                                    &hex::encode(&bytes[44..108]),
                                )
                                .is_err()
                                {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .signature_refusals += 1;
                                    return Err("PUBLIC_CALLER_SIGNATURE".into());
                                }
                                if let Err(e) = spent.reserve(
                                    cookie.id()?,
                                    cookie.expires_tick_ms,
                                    server.tick()?,
                                ) {
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    if e.is(crate::ErrorCode::PublicTicketReplay) {
                                        m.replay_refusals += 1;
                                    } else {
                                        m.spent_capacity_refusals += 1;
                                    }
                                    return Err(e);
                                }
                                {
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    m.peak_spent = m.peak_spent.max(spent.rows.len());
                                }
                                let n = cookie.body_len as usize;
                                let mutation = cookie.op == 1;
                                let grant_pool = if mutation {
                                    mutating_grants.clone()
                                } else {
                                    read_grants.clone()
                                };
                                let lane = match BufferPermit::acquire(
                                    grant_pool.clone(),
                                    1,
                                    if mutation {
                                        MAX_MUTATING_GRANTS
                                    } else {
                                        MAX_READ_GRANTS
                                    },
                                ) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        metrics
                                            .lock()
                                            .map_err(|_| "PUBLIC_METRICS")?
                                            .lane_capacity_refusals += 1;
                                        return Err(e);
                                    }
                                };
                                let permit = match BufferPermit::acquire(
                                    body_pool.clone(),
                                    n * 3,
                                    if mutation {
                                        MAX_PAID_BODY_BYTES - READ_BODY_RESERVE
                                    } else {
                                        MAX_PAID_BODY_BYTES
                                    },
                                ) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        metrics
                                            .lock()
                                            .map_err(|_| "PUBLIC_METRICS")?
                                            .paid_body_capacity_refusals += 1;
                                        return Err(e);
                                    }
                                };
                                conn.permit = Some(permit);
                                conn.lane_permit = Some(Arc::new(lane));
                                {
                                    let used =
                                        *body_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    m.peak_paid_body_bytes = m.peak_paid_body_bytes.max(used);
                                    let grants =
                                        *grant_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                                    if mutation {
                                        m.peak_mutating_grants = m.peak_mutating_grants.max(grants);
                                    } else {
                                        m.peak_read_grants = m.peak_read_grants.max(grants);
                                    }
                                }
                                let frame = framed(
                                    serde_json::to_vec(
                                        &json!({"schema":"public-body-ready-v2","cookie_digest":hex::encode(cookie.id()?)}),
                                    )?,
                                    256,
                                )?;
                                conn.deadline = conn
                                    .total_deadline
                                    .min(Instant::now() + Duration::from_millis(CHALLENGE_MS));
                                Ok(Stage::Ready {
                                    cookie,
                                    bytes: frame,
                                    cursor: 0,
                                })
                            }
                            Stage::Ready {
                                cookie,
                                bytes,
                                mut cursor,
                            } => {
                                if write_available(&mut conn.socket, &bytes, &mut cursor)? {
                                    let len = cookie.body_len as usize;
                                    conn.deadline = conn
                                        .total_deadline
                                        .min(Instant::now() + Duration::from_millis(BODY_MS));
                                    Ok(Stage::Body {
                                        cookie,
                                        bytes: Vec::with_capacity(len),
                                    })
                                } else {
                                    Ok(Stage::Ready {
                                        cookie,
                                        bytes,
                                        cursor,
                                    })
                                }
                            }
                            Stage::Body { cookie, mut bytes } => {
                                let before = bytes.len();
                                let complete = read_available(
                                    &mut conn.socket,
                                    &mut bytes,
                                    cookie.body_len as usize,
                                )?;
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .body_bytes_received += (bytes.len() - before) as u64;
                                if !complete {
                                    return Ok(Stage::Body { cookie, bytes });
                                }
                                ensure(
                                    cookie.body_digest
                                        == hex::encode(hash(b"public-request-body-v2", &[&bytes])),
                                    "PUBLIC_BODY_DIGEST",
                                )?;
                                let request = canonical_request(&bytes, cookie.op)?;
                                server.validate(&cookie, &settings, false)?;
                                let sender = if cookie.op == 1 { &proof_tx } else { &read_tx };
                                let task = Task {
                                    _permit: conn.permit.take().ok_or("PUBLIC_BODY_PERMIT")?,
                                    _lane_permit: conn
                                        .lane_permit
                                        .as_ref()
                                        .ok_or("PUBLIC_LANE_PERMIT")?
                                        .clone(),
                                    id: conn.id,
                                    cookie,
                                    request,
                                    deadline: conn
                                        .total_deadline
                                        .min(Instant::now() + Duration::from_millis(WORK_MS)),
                                    cancelled: conn.cancelled.clone(),
                                };
                                match sender.try_send(task) {
                                    Ok(()) => {
                                        metrics
                                            .lock()
                                            .map_err(|_| "PUBLIC_METRICS")?
                                            .tasks_enqueued += 1;
                                        conn.deadline = conn
                                            .total_deadline
                                            .min(Instant::now() + Duration::from_millis(WORK_MS));
                                        Ok(Stage::Await)
                                    }
                                    Err(TrySendError::Full(_)) => {
                                        metrics
                                            .lock()
                                            .map_err(|_| "PUBLIC_METRICS")?
                                            .queue_refusals += 1;
                                        Err("PUBLIC_QUEUE_BUSY".into())
                                    }
                                    Err(TrySendError::Disconnected(_)) => {
                                        Err("PUBLIC_QUEUE_CLOSED".into())
                                    }
                                }
                            }
                            Stage::Await => {
                                // R2 requires the caller's write half to remain open
                                // until the response. TCP cannot distinguish a full
                                // close from shutdown(Write): either EOF cancels
                                // queued/owner-waiting work. The ordinary client keeps
                                // both halves open. This is no ledger verdict.
                                match conn.socket.peek(&mut [0; 1]) {
                                    Ok(0) => {
                                        metrics
                                            .lock()
                                            .map_err(|_| "PUBLIC_METRICS")?
                                            .disconnected_await_requests += 1;
                                        conn.cancelled.store(true, Ordering::Release);
                                        Err("PUBLIC_EOF".into())
                                    }
                                    Err(e)
                                        if !matches!(
                                            e.kind(),
                                            std::io::ErrorKind::WouldBlock
                                                | std::io::ErrorKind::Interrupted
                                        ) =>
                                    {
                                        Err(e.into())
                                    }
                                    _ => Ok(Stage::Await),
                                }
                            }
                            Stage::Output {
                                bytes,
                                mut cursor,
                                _permit,
                            } => {
                                let before = cursor;
                                if write_available(&mut conn.socket, &bytes, &mut cursor)? {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .response_bytes_written += (cursor - before) as u64;
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .delivered_response_frames += 1;
                                    remove.push(*id);
                                    Ok(Stage::Await)
                                } else {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .response_bytes_written += (cursor - before) as u64;
                                    Ok(Stage::Output {
                                        bytes,
                                        cursor,
                                        _permit,
                                    })
                                }
                            }
                        }
                    })();
                    match advanced {
                        Ok(next) => conn.stage = next,
                        Err(_) => {
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            *m.retained_phase_errors.entry(phase.into()).or_default() += 1;
                            match phase {
                                "hello" => m.preface_refusals += 1,
                                "output" => m.response_write_failures += 1,
                                "body" => m.parse_refusals += 1,
                                _ => {}
                            }
                            remove.push(*id);
                        }
                    }
                }
                remove.sort_unstable();
                remove.dedup();
                for id in remove {
                    connections.remove(&id);
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        drop(proof_tx);
        drop(read_tx);
        drop(finished_rx);
        metrics
            .lock()
            .map_err(|_| "PUBLIC_METRICS")?
            .connections_closed_on_shutdown = connections.len();
        connections.clear();
        for worker in workers {
            worker.join().map_err(|_| "PUBLIC_WORKER_PANIC")??;
        }
        {
            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
            m.paid_body_reserved_bytes_after_shutdown =
                *body_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
            m.output_reserved_bytes_after_shutdown =
                *output_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
            m.mutating_grants_after_shutdown =
                *mutating_grants.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
            m.read_grants_after_shutdown = *read_grants.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
        }
        outcome
    })?;
    let final_metrics = metrics.lock().map_err(|_| "PUBLIC_METRICS")?.clone();
    Ok(final_metrics)
}

#[derive(Debug, Serialize)]
pub struct PublicReply {
    pub ok: bool,
    pub value: Value,
    pub solve_trials: u64,
    pub solve_elapsed_ns: u64,
    pub body_bytes_sent: usize,
    pub public_network_ready: bool,
    pub identity_authority: bool,
}
/// Every read is charged too. The caller must pin server/context/policy; no fallback.
pub fn call_public_protected_v2(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
) -> Result<PublicReply> {
    PublicPolicy::new(policy.bits, Duration::from_millis(policy.lifetime_ms))?;
    let raw = serde_json::to_vec(request)?;
    let op = request_op(request)?;
    let hello = Hello {
        op,
        len: raw.len(),
        caller: digest(caller.public_key())?,
        digest: hash(b"public-request-body-v2", &[&raw]),
        client_nonce: entropy()?,
    };
    Hello::parse(&hello.encode())?;
    let total_deadline = Instant::now() + Duration::from_millis(OVERALL_MS);
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    client_write(
        &mut stream,
        &hello.encode(),
        total_deadline.min(Instant::now() + Duration::from_millis(PREFIX_MS)),
    )?;
    let bytes = client_frame(
        &mut stream,
        2048,
        total_deadline.min(Instant::now() + Duration::from_millis(CHALLENGE_MS)),
    )?;
    let cookie: Cookie = serde_json::from_slice(&bytes)?;
    ensure(
        serde_json::to_vec(&cookie)? == bytes
            && cookie.schema == "public-resource-cookie-v2"
            && cookie.profile == hex::encode(policy.id())
            && cookie.network == hex::encode(settings.network())
            && cookie.parameters == hex::encode(settings.parameters())
            && cookie.genesis == hex::encode(settings.genesis())
            && cookie.server == pinned_server
            && cookie.caller == caller.public_key()
            && cookie.op == op
            && cookie.body_len as usize == raw.len()
            && cookie.body_digest == hex::encode(hello.digest)
            && cookie.client_nonce == hex::encode(hello.client_nonce)
            && cookie.bits == policy.bits
            && cookie.lifetime_ms == policy.lifetime_ms
            && cookie.expires_tick_ms.checked_sub(cookie.issued_tick_ms)
                == Some(policy.lifetime_ms),
        "PUBLIC_CHALLENGE_CONTEXT",
    )?;
    verify_hex_strict(pinned_server, &cookie.server_message()?, &cookie.signature)
        .map_err(|_| "PUBLIC_CHALLENGE_SIGNATURE")?;
    let started = Instant::now();
    let id = cookie.id()?;
    let mut solved = None;
    for nonce in 0..1_048_576u64 {
        if nonce % 256 == 0 {
            ensure(
                started.elapsed() < Duration::from_millis(policy.lifetime_ms),
                "PUBLIC_SOLVE_EXPIRED",
            )?;
        }
        if winner(id, nonce, policy.bits) {
            solved = Some(nonce);
            break;
        }
    }
    let nonce = solved.ok_or("PUBLIC_SOLVE_BUDGET")?;
    let solve_elapsed_ns = elapsed_ns(started);
    let mut solution = b"PPS2".to_vec();
    solution.extend(id);
    solution.extend(nonce.to_le_bytes());
    solution.extend(
        hex::decode(caller.sign(&hash(
            b"public-caller-sign-v2",
            &[&id, &nonce.to_le_bytes()],
        ))?)
        .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?,
    );
    client_write(
        &mut stream,
        &solution,
        total_deadline.min(started + Duration::from_millis(policy.lifetime_ms)),
    )?;
    let ready: Value = serde_json::from_slice(&client_frame(
        &mut stream,
        256,
        total_deadline.min(Instant::now() + Duration::from_millis(CHALLENGE_MS)),
    )?)?;
    ensure(
        ready["schema"] == "public-body-ready-v2" && ready["cookie_digest"] == hex::encode(id),
        "PUBLIC_READY",
    )?;
    client_write(
        &mut stream,
        &raw,
        total_deadline.min(Instant::now() + Duration::from_millis(BODY_MS)),
    )?;
    let bytes = client_frame(
        &mut stream,
        MAX_RESPONSE,
        total_deadline.min(Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS)),
    )?;
    let r: Response = serde_json::from_slice(&bytes)?;
    ensure(
        serde_json::to_vec(&r)? == bytes
            && r.schema == "public-protected-response-v2"
            && r.profile == hex::encode(policy.id())
            && r.network == hex::encode(settings.network())
            && r.parameters == hex::encode(settings.parameters())
            && r.genesis == hex::encode(settings.genesis())
            && r.server == pinned_server
            && r.cookie_digest == hex::encode(id)
            && r.request_digest == hex::encode(hello.digest),
        "PUBLIC_RESPONSE_CONTEXT",
    )?;
    verify_hex_strict(pinned_server, &r.message()?, &r.signature)
        .map_err(|_| "PUBLIC_RESPONSE_SIGNATURE")?;
    Ok(PublicReply {
        ok: r.ok,
        value: r.value,
        solve_trials: nonce + 1,
        solve_elapsed_ns,
        body_bytes_sent: raw.len(),
        public_network_ready: false,
        identity_authority: false,
    })
}
fn client_frame(stream: &mut TcpStream, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    super::read_exact_deadline(stream, &mut prefix, deadline)?;
    let n = u32::from_be_bytes(prefix) as usize;
    ensure(n > 0 && n <= maximum, "PUBLIC_CLIENT_FRAME_LIMIT")?;
    let mut bytes = vec![0; n];
    super::read_exact_deadline(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn client_write(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("PUBLIC_CLIENT_DEADLINE")?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err("PUBLIC_EOF".into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    ensure(Instant::now() < deadline, "PUBLIC_CLIENT_DEADLINE")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(n: u8) -> DevelopmentIdentity {
        DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
    }
    fn server() -> PublicServer {
        PublicServer::new(
            identity(71),
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap()
    }
    fn hello(op: u8, len: usize) -> Hello {
        Hello {
            op,
            len,
            caller: digest(identity(72).public_key()).unwrap(),
            digest: [3; 32],
            client_nonce: [4; 32],
        }
    }
    fn shared(node: Node) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(node))
    }
    fn serve_test(
        listener: TcpListener,
        node: Arc<Mutex<Node>>,
        lifetime: Duration,
        stop: Arc<AtomicBool>,
        server: PublicServer,
        metrics: Arc<Mutex<PublicMetrics>>,
    ) -> Result<PublicMetrics> {
        let settings = node.lock().map_err(|_| "TEST_OWNER")?.settings().clone();
        serve_public_protected_v2_with_owner(
            listener, node, settings, lifetime, stop, server, metrics,
        )
    }
    // Real authenticated ticket exchange. Returning before the body lets these
    // socket tests hold a bounded grant without invoking any fake work verifier.
    fn paid_grant(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<TcpStream> {
        let mut socket = TcpStream::connect(address)?;
        socket.set_nodelay(true)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        client_write(&mut socket, &hello.encode(), deadline)?;
        let raw = client_frame(&mut socket, 2048, deadline)?;
        let cookie: Cookie = serde_json::from_slice(&raw)?;
        ensure(cookie.profile == hex::encode(policy.id()), "TEST_PROFILE")?;
        verify_hex_strict(
            identity(71).public_key(),
            &cookie.server_message()?,
            &cookie.signature,
        )
        .map_err(|_| "TEST_SERVER_SIGNATURE")?;
        let id = cookie.id()?;
        let nonce = (0..1_048_576u64)
            .find(|n| winner(id, *n, policy.bits))
            .ok_or("TEST_SOLUTION")?;
        let mut solution = b"PPS2".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(caller.sign(&hash(
                b"public-caller-sign-v2",
                &[&id, &nonce.to_le_bytes()],
            ))?)
            .map_err(|_| "TEST_CALLER_SIGNATURE")?,
        );
        client_write(&mut socket, &solution, deadline)?;
        let ready: Value = serde_json::from_slice(&client_frame(&mut socket, 256, deadline)?)?;
        ensure(
            ready["schema"] == "public-body-ready-v2" && ready["cookie_digest"] == hex::encode(id),
            "TEST_READY",
        )?;
        Ok(socket)
    }
    fn wait_metric(metrics: &Mutex<PublicMetrics>, predicate: impl Fn(&PublicMetrics) -> bool) {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            if predicate(&metrics.lock().unwrap()) {
                return;
            }
            assert!(Instant::now() < end, "actual reactor observation timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn paid_mutation_body_budget_preserves_signed_read_service_with_rotating_callers() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner = shared(Node::open(directory.path(), settings.clone(), 2).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let signal = stop.clone();
        let counters = metrics.clone();
        let worker = thread::spawn(move || {
            serve_test(
                listener,
                owner,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let sizes = [
            MAX_BODY,
            (MAX_PAID_BODY_BYTES - READ_BODY_RESERVE) / 3 - MAX_BODY,
        ];
        let mut held = Vec::new();
        for (index, size) in sizes.into_iter().enumerate() {
            let caller = identity(80 + index as u8);
            let mut h = hello(1, size);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        assert_eq!(
            metrics.lock().unwrap().peak_paid_body_bytes,
            MAX_PAID_BODY_BYTES - READ_BODY_RESERVE
        );
        let caller = identity(83);
        let mut h = hello(1, 1);
        h.caller = digest(caller.public_key()).unwrap();
        assert!(paid_grant(address, h, &caller, policy).is_err());
        let reply = call_public_protected_v2(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(84),
            policy,
        )
        .unwrap();
        assert!(reply.ok);
        assert_eq!(reply.value["height"], 0);
        drop(held);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.paid_body_capacity_refusals, 1);
        assert_eq!(m.completed_read, 1);
        assert_eq!(m.work_started, 0);
        assert!(m.peak_paid_body_bytes <= MAX_PAID_BODY_BYTES);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn paid_mutation_grants_are_global_across_identity_rotation_and_release_on_eof() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let signal = stop.clone();
        let counters = metrics.clone();
        let worker = thread::spawn(move || {
            serve_test(
                listener,
                shared(source),
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let mut held = Vec::new();
        for index in 0..MAX_MUTATING_GRANTS {
            let caller = identity(80 + index as u8);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        let caller = identity(90);
        let mut h = hello(1, 1);
        h.caller = digest(caller.public_key()).unwrap();
        assert!(paid_grant(address, h, &caller, policy).is_err());
        let reply = call_public_protected_v2(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(91),
            policy,
        )
        .unwrap();
        assert!(reply.ok);
        drop(held);
        wait_metric(&metrics, |m| {
            m.retained_phase_errors.get("body").copied().unwrap_or(0) >= MAX_MUTATING_GRANTS as u64
        });
        let reply = call_public_protected_v2(
            address,
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &settings,
            identity(71).public_key(),
            &identity(92),
            policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.lane_capacity_refusals, 1);
        assert_eq!(m.peak_mutating_grants, MAX_MUTATING_GRANTS);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.work_finished, 1);
        assert_eq!(m.work_failed, 0);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let raw = serde_json::to_vec(&request).unwrap();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_test(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v2(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy
            )
            .unwrap()
            .ok
        );
        let locked = owner.lock().unwrap();
        let before = locked.active().unwrap();
        let caller = identity(80);
        let mut h = hello(1, raw.len());
        h.caller = digest(caller.public_key()).unwrap();
        h.digest = hash(b"public-request-body-v2", &[&raw]);
        let mut sockets = Vec::new();
        for _ in 0..3 {
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        // Initial Head was one task. Two Submit workers are waiting for this
        // actual owner lock, leaving the third preserved request in the queue.
        wait_metric(&metrics, |m| m.tasks_enqueued == 4 && m.tasks_dequeued == 3);
        sockets[0].shutdown(std::net::Shutdown::Write).unwrap();
        for socket in &sockets[1..] {
            socket.shutdown(std::net::Shutdown::Both).unwrap();
        }
        wait_metric(&metrics, |m| m.disconnected_await_requests == 3);
        // Keep the first caller's read half open: it receives EOF because the
        // server explicitly cancels R2 write-half-closed requests.
        assert!(client_frame(
            &mut sockets[0],
            MAX_RESPONSE,
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
        drop(sockets);
        drop(locked);
        wait_metric(&metrics, |m| m.abandoned_tasks == 3);
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        assert_eq!(owner.lock().unwrap().active().unwrap(), before);
        let reply = call_public_protected_v2(
            address,
            &request,
            &settings,
            identity(71).public_key(),
            &identity(81),
            policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.disconnected_await_requests, 3);
        assert_eq!(m.abandoned_tasks, 3);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn paid_wrong_product_is_fully_rejected_and_the_preserved_valid_packet_is_activated() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let mut bad = packet.clone();
        let offset = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
        let original = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
        let replacement = if original == 0 { 1u32 } else { 0u32 };
        bad.proof[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        // Only a canonical product field changes. Challenge/trace/ticket remain
        // the actual producer's valid bytes; no forged-ticket search is used.
        assert_eq!(bad.header, packet.header);
        let owner = shared(source);
        let before = owner.lock().unwrap().read_active().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_test(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let call = |packet: &crate::Packet| {
            call_public_protected_v2(
                address,
                &Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &settings,
                identity(71).public_key(),
                &identity(80),
                policy,
            )
            .unwrap()
        };
        let rejected = call(&bad);
        assert!(!rejected.ok);
        assert_eq!(rejected.value["error"], "WORK:Product");
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        assert!(call(&packet).ok);
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.work_started, 2);
        assert_eq!(m.work_finished, 2);
        assert_eq!(m.work_failed, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.executor_refusals, 1);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn resource_revision_r2_rejects_a_signed_r1_cookie_and_preserves_control_output_reserve() {
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        assert_eq!(
            hex::encode(server.policy.id()),
            "5f139f93d28bf5d9db859550f767d2005f8b5d02e612fedfa3c95351b1b1f701"
        );
        let mut c = server
            .cookie(&s, hello(2, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        c.profile = "978399f8f45c0795807cdbeb9df14bbdae7664a4b1c3c0a9214e05635c3de9f8".into();
        c.mac = hex::encode(hmac(&server.secret, &c.unsigned().unwrap()));
        c.signature = server.identity.sign(&c.server_message().unwrap()).unwrap();
        verify_hex_strict(
            server.identity.public_key(),
            &c.server_message().unwrap(),
            &c.signature,
        )
        .unwrap();
        assert_eq!(
            server.validate(&c, &s, true).unwrap_err().to_string(),
            "PUBLIC_COOKIE_CONTEXT"
        );
        let pool = Arc::new(Mutex::new(0));
        let bulk = BufferPermit::acquire(
            pool.clone(),
            MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE,
            MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE,
        )
        .unwrap();
        assert!(
            BufferPermit::acquire(pool.clone(), 1, MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE)
                .is_err()
        );
        let control = BufferPermit::acquire(pool.clone(), 16384 * 4, MAX_OUTPUT_BYTES).unwrap();
        assert!(*pool.lock().unwrap() <= MAX_OUTPUT_BYTES);
        drop((bulk, control));
        assert_eq!(*pool.lock().unwrap(), 0);
    }
    #[test]
    fn v3_magic_profile_pool_operation_and_signature_domains_are_rejected_exactly() {
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let v3 = super::super::public_v3::PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        assert_ne!(policy.id(), v3.id());
        let mut raw = hello(2, 10).encode();
        raw[..4].copy_from_slice(b"PPH3");
        assert!(Hello::parse(&raw).is_err());
        assert!(Hello::parse(&hello(4, 10).encode()).is_err());
        assert!(canonical_request(br#"{"op":"pool_status"}"#, 2).is_err());
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        let c = server
            .cookie(&s, hello(2, 10), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let mut wrong = c.clone();
        wrong.schema = "public-resource-cookie-v3".into();
        assert!(server.validate(&wrong, &s, true).is_err());
        let id = c.id().unwrap();
        let nonce = 77u64;
        let signer = identity(72);
        let wrong_message = hash(b"public-caller-sign-v3", &[&id, &nonce.to_le_bytes()]);
        let actual_message = hash(b"public-caller-sign-v2", &[&id, &nonce.to_le_bytes()]);
        let signature = signer.sign(&wrong_message).unwrap();
        assert!(verify_hex_strict(signer.public_key(), &actual_message, &signature).is_err());
    }
    #[test]
    fn canonical_streaming_rejects_escaped_packets_and_extra_fields() {
        let request = Request::Submit {
            packet: "aa".repeat(1024),
        };
        let raw = serde_json::to_vec(&request).unwrap();
        assert_eq!(canonical_request(&raw, 1).unwrap(), request);
        assert!(canonical_request(br#"{"op":"submit","packet":"\u0061a"}"#, 1).is_err());
        assert!(canonical_request(br#"{"op":"submit","packet":"Aa"}"#, 1).is_err());
        assert!(canonical_request(br#"{"op":"head","authority":true}"#, 2).is_err());
        assert!(canonical_request(br#" {"op":"head"}"#, 2).is_err());
        assert!(canonical_request(br#"{"op":"head"}"#, 3).is_err());
    }
    #[test]
    fn hmac_sha256_matches_rfc4231_and_fixed_32_byte_oracle_vectors() {
        // RFC 4231 section 4.2. Zero-extending its 20-byte key to 32
        // bytes produces the same 64-byte HMAC key block.
        let mut key = [0; 32];
        key[..20].fill(0x0b);
        assert_eq!(
            hex::encode(hmac(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Cross-checked with Python stdlib hmac.new(key,message,sha256).
        let key = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(hmac(&key, b"public-v2 fixed 32-byte key vector")),
            "fe60fb506037734bc465fbae6d80d241404b7ed60d34a1cde0c74334053a8e28"
        );
    }
    #[test]
    fn failed_output_closes_only_that_connection_and_later_honest_request_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let s = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let node = Node::open(directory.path(), s.clone(), 2).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let server = server();
        let policy = server.policy;
        let key = server.identity.public_key().to_owned();
        server.fail_next_output.store(true, Ordering::Release);
        let worker = thread::spawn(move || {
            serve_public_protected_v2(listener, node, Duration::from_secs(5), signal, server)
                .unwrap()
        });
        assert!(
            call_public_protected_v2(address, &Request::Head, &s, &key, &identity(72), policy)
                .is_err()
        );
        let reply =
            call_public_protected_v2(address, &Request::Head, &s, &key, &identity(72), policy)
                .unwrap();
        assert!(reply.ok);
        assert_eq!(reply.value["height"], 0);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.output_serialization_failures, 1);
        assert_eq!(m.completed_read, 2);
        assert_eq!(m.delivered_response_frames, 1);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn fixed_preface_checks_all_bounds_before_paid_body_allocation() {
        assert!(Hello::parse(&hello(1, MAX_BODY).encode()).is_ok());
        assert!(Hello::parse(&hello(1, MAX_BODY + 1).encode()).is_err());
        assert!(Hello::parse(&hello(2, MAX_READ_BODY).encode()).is_ok());
        assert!(Hello::parse(&hello(2, MAX_READ_BODY + 1).encode()).is_err());
        assert!(Hello::parse(&hello(4, 1).encode()).is_err());
        assert!(Hello::parse(&hello(1, 0).encode()).is_err());
        let mut bytes = hello(1, 1).encode();
        bytes[5] = 1;
        assert!(Hello::parse(&bytes).is_err());
        let body = serde_json::to_vec(&Request::Submit {
            packet: "00".repeat(MAX_PACKET),
        })
        .unwrap();
        assert!(body.len() <= MAX_BODY);
        let page = super::super::Page {
            schema: "pon-native-history-v1".into(),
            network: "00".repeat(32),
            parameters: "00".repeat(32),
            genesis: "00".repeat(32),
            tip: "00".repeat(32),
            after: "00".repeat(32),
            packets: vec!["00".repeat(MAX_PACKET)],
            next: "00".repeat(32),
            complete: true,
        };
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        let cookie = server
            .cookie(&s, hello(3, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        // Codec/wire boundary only. These synthetic zero bytes are not valid work.
        let response = response(
            &server,
            &s,
            &cookie,
            Ok(serde_json::to_value(page).unwrap()),
        )
        .unwrap();
        assert!(response.len() <= MAX_RESPONSE + 4);
    }
    #[test]
    fn cookie_binds_every_authority_and_resource_field_and_restart_epoch() {
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        let cookie = server
            .cookie(&s, hello(2, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        server.validate(&cookie, &s, true).unwrap();
        for field in [
            "network",
            "parameters",
            "genesis",
            "server",
            "epoch",
            "connection_nonce",
            "peer_binding",
            "caller",
            "client_nonce",
            "body_digest",
            "profile",
        ] {
            let mut value = serde_json::to_value(&cookie).unwrap();
            value[field] = json!("ff".repeat(32));
            let tampered: Cookie = serde_json::from_value(value).unwrap();
            assert!(server.validate(&tampered, &s, true).is_err(), "{field}");
        }
        for field in [
            "op",
            "body_len",
            "bits",
            "lifetime_ms",
            "issued_tick_ms",
            "expires_tick_ms",
        ] {
            let mut value = serde_json::to_value(&cookie).unwrap();
            value[field] = json!(value[field].as_u64().unwrap() + 1);
            let tampered: Cookie = serde_json::from_value(value).unwrap();
            assert!(server.validate(&tampered, &s, true).is_err(), "{field}");
        }
        let restarted = PublicServer::new(identity(71), server.policy).unwrap();
        assert!(restarted.validate(&cookie, &s, true).is_err());
        assert_ne!(
            cookie.id().unwrap(),
            server
                .cookie(&s, hello(2, 1), "127.0.0.1:1".parse().unwrap())
                .unwrap()
                .id()
                .unwrap()
        );
    }
    #[test]
    fn spent_cache_never_evicts_live_tokens_when_full() {
        let mut cache = Spent::new();
        for i in 0..MAX_SPENT {
            cache
                .reserve(hash(b"test-spent", &[&(i as u64).to_le_bytes()]), 100, 0)
                .unwrap();
        }
        assert_eq!(
            cache
                .reserve(hash(b"extra", &[]), 100, 0)
                .unwrap_err()
                .to_string(),
            "PUBLIC_SPENT_CAPACITY"
        );
        let first = hash(b"test-spent", &[&0_u64.to_le_bytes()]);
        assert_eq!(
            cache.reserve(first, 100, 0).unwrap_err().to_string(),
            "PUBLIC_TICKET_REPLAY"
        );
        cache.cleanup(99);
        assert_eq!(cache.rows.len(), MAX_SPENT);
        cache.cleanup(100);
        assert!(cache.rows.is_empty());
        assert_eq!(
            cache.reserve(first, 100, 100).unwrap_err().to_string(),
            "PUBLIC_COOKIE_EXPIRED"
        );
    }
    #[test]
    fn reservations_survive_queues_and_release_on_disconnect_and_dropped_output() {
        let lanes = Arc::new(Mutex::new(0));
        let connection_lane =
            Arc::new(BufferPermit::acquire(lanes.clone(), 1, MAX_READ_GRANTS).unwrap());
        let task_lane = connection_lane.clone();
        drop(task_lane);
        assert_eq!(*lanes.lock().unwrap(), 1);
        let running_task_lane = connection_lane.clone();
        drop(connection_lane);
        assert_eq!(*lanes.lock().unwrap(), 1);
        drop(running_task_lane);
        assert_eq!(*lanes.lock().unwrap(), 0);
        let pool = Arc::new(Mutex::new(0));
        let permit =
            BufferPermit::acquire(pool.clone(), MAX_BODY * 3, MAX_PAID_BODY_BYTES).unwrap();
        assert!(BufferPermit::acquire(pool.clone(), MAX_BODY * 3, MAX_PAID_BODY_BYTES).is_err());
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(permit).ok().unwrap();
        assert_eq!(*pool.lock().unwrap(), MAX_BODY * 3);
        // Receiver disposal releases queued bodies; no guest state is written.
        drop(rx);
        assert_eq!(*pool.lock().unwrap(), 0);
        let output = Arc::new(Mutex::new(0));
        let mut held = Vec::new();
        while let Ok(p) = BufferPermit::acquire(output.clone(), MAX_RESPONSE * 4, MAX_OUTPUT_BYTES)
        {
            held.push(p);
        }
        assert_eq!(held.len(), MAX_OUTPUT_BYTES / (MAX_RESPONSE * 4));
        assert!(BufferPermit::acquire(output.clone(), MAX_RESPONSE * 4, MAX_OUTPUT_BYTES).is_err());
        let (tx, rx) = mpsc::sync_channel(8);
        for permit in held {
            tx.send(permit).ok().unwrap();
        }
        assert!(*output.lock().unwrap() <= MAX_OUTPUT_BYTES);
        drop(rx);
        assert_eq!(*output.lock().unwrap(), 0);
    }
    fn fragmented_call(
        address: SocketAddr,
        request: &Request,
        s: &Settings,
        server_key: &str,
        delay_ms: u64,
        policy: PublicPolicy,
    ) -> Response {
        let caller = identity(72);
        let raw = serde_json::to_vec(request).unwrap();
        let hello = Hello {
            op: request_op(request).unwrap(),
            len: raw.len(),
            caller: digest(caller.public_key()).unwrap(),
            digest: hash(b"public-request-body-v2", &[&raw]),
            client_nonce: entropy().unwrap(),
        };
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let encoded = hello.encode();
        stream.write_all(&encoded[..54]).unwrap();
        thread::sleep(Duration::from_millis(delay_ms));
        stream.write_all(&encoded[54..]).unwrap();
        let cookie: Cookie = serde_json::from_slice(
            &client_frame(&mut stream, 2048, Instant::now() + Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        assert_eq!(cookie.profile, hex::encode(policy.id()));
        assert_eq!(cookie.server, server_key);
        assert_eq!(cookie.network, hex::encode(s.network()));
        assert_eq!(cookie.body_digest, hex::encode(hello.digest));
        verify_hex_strict(
            server_key,
            &cookie.server_message().unwrap(),
            &cookie.signature,
        )
        .unwrap();
        let id = cookie.id().unwrap();
        let nonce = (0..1_048_576)
            .find(|n| winner(id, *n, policy.bits))
            .unwrap();
        let mut solution = b"PPS2".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(
                caller
                    .sign(&hash(
                        b"public-caller-sign-v2",
                        &[&id, &nonce.to_le_bytes()],
                    ))
                    .unwrap(),
            )
            .unwrap(),
        );
        stream.write_all(&solution[..54]).unwrap();
        thread::sleep(Duration::from_millis(100));
        stream.write_all(&solution[54..]).unwrap();
        let ready: Value = serde_json::from_slice(
            &client_frame(&mut stream, 256, Instant::now() + Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(id));
        let chunks: Vec<_> = raw.chunks(raw.len().div_ceil(4)).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            if index > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
            stream.write_all(chunk).unwrap();
        }
        let bytes = client_frame(
            &mut stream,
            MAX_RESPONSE,
            Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS),
        )
        .unwrap();
        let reply: Response = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply.cookie_digest, hex::encode(id));
        assert_eq!(reply.request_digest, hex::encode(hello.digest));
        verify_hex_strict(server_key, &reply.message().unwrap(), &reply.signature).unwrap();
        reply
    }
    #[test]
    fn honest_fragmented_small_frames_and_body_100_to_300_ms_need_no_retry() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let s = Settings::development(Some(clock - 100)).unwrap();
        let node = Node::open(directory.path(), s.clone(), 2).unwrap();
        let packet = node
            .make(
                s.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_key = identity(71).public_key().to_owned();
        let policy = PublicPolicy::new(8, Duration::from_millis(500)).unwrap();
        let signal = stop.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v2(
                listener,
                node,
                Duration::from_secs(15),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
            )
            .unwrap()
        });
        for delay in [100, 200, 300] {
            assert!(fragmented_call(address, &Request::Head, &s, &server_key, delay, policy).ok);
        }
        // Body completion is >500 ms after issue. Valid paid grant uses its own
        // 5 s body deadline rather than the already elapsed solve-cookie deadline.
        let reply = fragmented_call(
            address,
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &s,
            &server_key,
            300,
            policy,
        );
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(reply.value["block"], hex::encode(packet.id().unwrap()));
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.completed_read, 3);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.expired_connections, 0);
        assert_eq!(m.delivered_response_frames, 4);
        assert_eq!(m.unknown_caller_durable_rows, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        assert!(m.peak_paid_body_bytes <= MAX_PAID_BODY_BYTES);
        assert!(m.peak_output_reserved_bytes <= MAX_OUTPUT_BYTES);
    }
    #[test]
    fn slow_initial_frames_cannot_occupy_read_worker_or_renew_absolute_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let s = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let node = Node::open(directory.path(), s.clone(), 2).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_key = identity(71).public_key().to_owned();
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let signal = stop.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v2(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
            )
            .unwrap()
        });
        let mut slow: Vec<_> = (0..3)
            .map(|_| {
                let mut stream = TcpStream::connect(address).unwrap();
                stream.write_all(b"P").unwrap();
                stream
            })
            .collect();
        let hello = hello(2, 1).encode();
        let started = Instant::now();
        let mut honest_attempts = 0;
        for i in 1..=25 {
            thread::sleep(Duration::from_millis(100));
            for stream in &mut slow {
                let _ = stream.write_all(&hello[i..i + 1]);
            }
            if [3, 8, 15].contains(&i) {
                honest_attempts += 1;
                let reply = call_public_protected_v2(
                    address,
                    &Request::Head,
                    &s,
                    &server_key,
                    &identity(72),
                    policy,
                )
                .unwrap();
                assert!(reply.ok);
            }
        }
        assert!(started.elapsed() > Duration::from_secs(2));
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(honest_attempts, 3);
        assert_eq!(m.completed_read, 3);
        assert!(m.expired_connections >= 3);
        assert_eq!(m.work_started, 0);
        assert!(m.peak_connections <= MAX_CONNECTIONS);
        assert_eq!(
            m.peak_paid_body_bytes,
            serde_json::to_vec(&Request::Head).unwrap().len() * 3
        );
    }
}
