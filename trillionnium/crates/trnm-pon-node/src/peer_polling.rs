//! M15 operator-pinned paid peer polling, sharing the existing exclusive Node.
//! Transport signatures authenticate replies, never remote chainwork or ledger rights.
use crate::{
    digest, ensure,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicReply, Request},
        DevelopmentIdentity, Page,
    },
    store::WorkCheckedPacket,
    Error, ErrorCode, Node, Packet, Result, Settings,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, TryLockError,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::verifying_key_from_hex;
use trnm_protocol::pon_wire::{hash, Hash};
const MAX_CONFIG_BYTES: u64 = 16384;
const MAX_PACKET_BYTES: usize = 1_048_576;
const MAX_ERROR_BYTES: usize = 2048;
pub const PEER_POLLING_SCHEMA: &str = "pon-native-pinned-peer-poll-config-v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedPeer {
    pub address: SocketAddr,
    pub server_public: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPollingConfig {
    pub schema: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub transport_profile: String,
    pub bits: u8,
    pub lifetime_ms: u64,
    pub peers: Vec<PinnedPeer>,
    pub poll_interval_ms: u64,
    pub runtime_ms: u64,
    pub max_calls: u64,
    pub max_pages_per_cycle: usize,
}
impl PeerPollingConfig {
    pub fn from_file(path: &Path, settings: &Settings) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure(
            metadata.is_file() && metadata.len() <= MAX_CONFIG_BYTES,
            "PEER_CONFIG_LIMIT",
        )?;
        ensure(
            metadata.nlink() == 1 && metadata.mode() & 0o022 == 0,
            "PEER_CONFIG_OWNED_MODE",
        )?;
        let mut raw = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut raw)?;
        ensure(raw.len() as u64 <= MAX_CONFIG_BYTES, "PEER_CONFIG_LIMIT")?;
        let cfg: Self = serde_json::from_slice(&raw)?;
        cfg.validate(settings)?;
        Ok(cfg)
    }
    pub fn policy(&self) -> Result<PublicPolicy> {
        PublicPolicy::new(self.bits, Duration::from_millis(self.lifetime_ms))
    }
    pub fn validate(&self, settings: &Settings) -> Result<()> {
        ensure(self.schema == PEER_POLLING_SCHEMA, "PEER_CONFIG_SCHEMA")?;
        let policy = self.policy()?;
        ensure(
            self.network == hex::encode(settings.network())
                && self.parameters == hex::encode(settings.parameters())
                && self.genesis == hex::encode(settings.genesis())
                && self.transport_profile == hex::encode(policy.id()),
            "PEER_CONFIG_CONTEXT",
        )?;
        ensure(
            (1..=8).contains(&self.peers.len())
                && (10..=60_000).contains(&self.poll_interval_ms)
                && (1..=259_200_000).contains(&self.runtime_ms)
                && (1..=1_000_000).contains(&self.max_calls)
                && (1..=64).contains(&self.max_pages_per_cycle),
            "PEER_CONFIG_LIMIT",
        )?;
        let mut addresses = BTreeSet::new();
        for peer in &self.peers {
            ensure(
                peer.address.port() != 0
                    && !peer.address.ip().is_unspecified()
                    && !peer.address.ip().is_multicast()
                    && addresses.insert(peer.address),
                "PEER_CONFIG_ADDRESS",
            )?;
            ensure(digest(&peer.server_public)? != [0; 32], "PEER_CONFIG_PIN")?;
            verifying_key_from_hex(&peer.server_public).map_err(|_| "PEER_CONFIG_PIN")?;
        }
        Ok(())
    }
    pub fn context(&self) -> Result<Hash> {
        Ok(hash(
            b"native-pinned-peer-poll-context-v1",
            &[&serde_json::to_vec(self)?],
        ))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct PeerFailure {
    pub message: String,
    pub complete: bool,
    pub original_bytes: usize,
    pub digest: String,
}
fn failure(error: &str) -> PeerFailure {
    let mut end = error.len().min(MAX_ERROR_BYTES);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    PeerFailure {
        message: error[..end].to_owned(),
        complete: end == error.len(),
        original_bytes: error.len(),
        digest: hex::encode(hash(b"native-peer-poll-error-v1", &[error.as_bytes()])),
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct PeerRpcCost {
    pub solve_trials: u64,
    pub solve_elapsed_ns: u64,
    pub body_bytes_sent: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct PeerPollingEvent {
    pub schema: &'static str,
    pub sequence: u64,
    pub peer: usize,
    pub stage: &'static str,
    pub target: Option<String>,
    pub cursor: String,
    pub kind: &'static str,
    pub elapsed_ns: u64,
    pub rpc_cost: Option<PeerRpcCost>,
    pub rpc_cost_scope: &'static str,
    pub error: Option<PeerFailure>,
    pub active_tip: Option<String>,
    pub public_network_ready: bool,
    pub identity_authority: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct PeerPollingSnapshot {
    pub peer: usize,
    pub fixed_target: Option<String>,
    pub cursor: String,
    pub last_completed: Option<String>,
    pub pages_this_target: u64,
    pub native_verified_new_packets: u64,
    pub admitted_pages: u64,
    pub completed_targets: u64,
    pub failures: u64,
    pub initial_anchor_fallbacks: u64,
    pub last_error: Option<PeerFailure>,
}
#[derive(Debug, Serialize)]
pub struct PeerPollingReport {
    pub schema: &'static str,
    pub context: String,
    pub cycles: u64,
    pub rpc_attempts: u64,
    pub ok_replies: u64,
    pub rejected_replies: u64,
    pub transport_errors: u64,
    pub history_pages: u64,
    pub verified_new_packets: u64,
    pub stop_reason: &'static str,
    pub elapsed_ns: u64,
    pub peers: Vec<PeerPollingSnapshot>,
    pub cursor_persistence: &'static str,
    pub native_stage_preemption: bool,
    pub public_network_ready: bool,
    pub independent_accepted: bool,
}
struct PeerState {
    target: Option<Hash>,
    cursor: Hash,
    last_completed: Option<Hash>,
    pages: u64,
    verified: u64,
    admitted: u64,
    completed: u64,
    failures: u64,
    fallbacks: u64,
    initial_fallback_used: bool,
    last_error: Option<PeerFailure>,
}
impl PeerState {
    fn new(genesis: Hash) -> Self {
        Self {
            target: None,
            cursor: genesis,
            last_completed: None,
            pages: 0,
            verified: 0,
            admitted: 0,
            completed: 0,
            failures: 0,
            fallbacks: 0,
            initial_fallback_used: false,
            last_error: None,
        }
    }
    fn snapshot(&self, peer: usize) -> PeerPollingSnapshot {
        PeerPollingSnapshot {
            peer,
            fixed_target: self.target.map(hex::encode),
            cursor: hex::encode(self.cursor),
            last_completed: self.last_completed.map(hex::encode),
            pages_this_target: self.pages,
            native_verified_new_packets: self.verified,
            admitted_pages: self.admitted,
            completed_targets: self.completed,
            failures: self.failures,
            initial_anchor_fallbacks: self.fallbacks,
            last_error: self.last_error.clone(),
        }
    }
}
fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
fn progress(end: Instant, stop: &AtomicBool) -> Result<()> {
    ensure(
        !stop.load(Ordering::Acquire) && Instant::now() < end,
        "PEER_POLL_CANCELLED",
    )
}
fn lock<'a>(
    node: &'a Mutex<Node>,
    end: Instant,
    stop: &AtomicBool,
) -> Result<MutexGuard<'a, Node>> {
    loop {
        progress(end, stop)?;
        match node.try_lock() {
            Ok(owner) => return Ok(owner),
            Err(TryLockError::Poisoned(_)) => return Err("OWNER_POISONED".into()),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
        }
    }
}
fn page(
    settings: &Settings,
    value: Value,
    target: Hash,
    after: Hash,
) -> Result<(Option<Packet>, Hash, bool)> {
    // The transport caps the complete response; reject collection/hex expansion
    // before serde can clone strings or Packet::decode can allocate raw bytes.
    let object = value.as_object().ok_or("PEER_PAGE_CANONICAL")?;
    let keys = [
        "schema",
        "network",
        "parameters",
        "genesis",
        "tip",
        "after",
        "packets",
        "next",
        "complete",
    ];
    ensure(
        object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)),
        "PEER_PAGE_CANONICAL",
    )?;
    let packets = object
        .get("packets")
        .and_then(Value::as_array)
        .ok_or("PEER_PAGE_CANONICAL")?;
    ensure(packets.len() <= 1, "PEER_PAGE_PACKET_LIMIT")?;
    if let Some(raw) = packets.first() {
        let raw = raw.as_str().ok_or("PEER_PAGE_HEX")?;
        ensure(raw.len() <= 2 * MAX_PACKET_BYTES, "PEER_PAGE_PACKET_LIMIT")?;
    }
    let parsed: Page = serde_json::from_value(value)?;
    ensure(
        parsed.schema == "pon-native-history-v1"
            && parsed.network == hex::encode(settings.network())
            && parsed.parameters == hex::encode(settings.parameters())
            && parsed.genesis == hex::encode(settings.genesis()),
        "PEER_PAGE_CONTEXT",
    )?;
    ensure(
        parsed.tip == hex::encode(target)
            && parsed.after == hex::encode(after)
            && parsed.packets.len() <= 1,
        "PEER_PAGE_CURSOR",
    )?;
    if parsed.packets.is_empty() {
        ensure(
            after == target && parsed.complete && parsed.next == hex::encode(after),
            "PEER_PAGE_EMPTY",
        )?;
        return Ok((None, after, true));
    }
    let raw = &parsed.packets[0];
    ensure(
        raw.len() <= 2 * MAX_PACKET_BYTES
            && raw.len().is_multiple_of(2)
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PEER_PAGE_PACKET_LIMIT",
    )?;
    let packet = Packet::decode(&hex::decode(raw).map_err(|_| "PEER_PAGE_HEX")?)?;
    ensure(packet.header.parent == after, "PEER_PAGE_PARENT")?;
    let next = packet.id()?;
    ensure(
        parsed.next == hex::encode(next) && parsed.complete == (next == target),
        "PEER_PAGE_COMPLETE",
    )?;
    Ok((Some(packet), next, parsed.complete))
}
/// Native task/parent/clock checks bracket the immutable owned full proof replay.
/// A repeated already-admitted exact packet uses the existing durable admission fact.
fn admit_page(node: &Mutex<Node>, packet: Packet, end: Instant, stop: &AtomicBool) -> Result<bool> {
    {
        let owner = lock(node, end, stop)?;
        if owner
            .check_admission_context(&packet, ingress::now()?)?
            .is_some()
        {
            return Ok(false);
        }
    }
    progress(end, stop)?;
    let checked = WorkCheckedPacket::verify(packet)?; // outside the only owner lock
    progress(end, stop)?;
    let mut owner = lock(node, end, stop)?;
    owner.admit_work_checked(checked, ingress::now()?)?;
    Ok(true)
}
struct PollContext<'a> {
    node: &'a Mutex<Node>,
    cfg: &'a PeerPollingConfig,
    settings: &'a Settings,
    end: Instant,
    stop: &'a AtomicBool,
}
struct EventDetail {
    stage: &'static str,
    kind: &'static str,
    elapsed_ns: u64,
    cost: Option<PeerRpcCost>,
    error: Option<PeerFailure>,
    active: Option<Hash>,
}
struct Engine {
    states: Vec<PeerState>,
    sequence: u64,
    calls: u64,
    replies: u64,
    rejections: u64,
    transport_errors: u64,
    pages: u64,
    verified: u64,
    rotation: usize,
}
impl Engine {
    fn new(cfg: &PeerPollingConfig, settings: &Settings) -> Self {
        Self {
            states: (0..cfg.peers.len())
                .map(|_| PeerState::new(settings.genesis()))
                .collect(),
            sequence: 0,
            calls: 0,
            replies: 0,
            rejections: 0,
            transport_errors: 0,
            pages: 0,
            verified: 0,
            rotation: 0,
        }
    }
    fn event<F>(&mut self, index: usize, detail: EventDetail, observe: &mut F) -> Result<()>
    where
        F: FnMut(&PeerPollingEvent) -> Result<()>,
    {
        let EventDetail {
            stage,
            kind,
            elapsed_ns,
            cost,
            error,
            active,
        } = detail;
        self.sequence += 1;
        let state = &self.states[index];
        observe(&PeerPollingEvent {schema:"native-pinned-peer-poll-event-v1",sequence:self.sequence,peer:index,stage,target:state.target.map(hex::encode),cursor:hex::encode(state.cursor),kind,elapsed_ns,rpc_cost:cost,rpc_cost_scope:"Some=successful signed reply exposes completed solve/body write; None=partial transport cost unknown, elapsed still observed",error,active_tip:active.map(hex::encode),public_network_ready:false,identity_authority:false})
    }
    fn reject<F>(
        &mut self,
        index: usize,
        stage: &'static str,
        error: Error,
        elapsed: u64,
        cost: Option<PeerRpcCost>,
        observe: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&PeerPollingEvent) -> Result<()>,
    {
        let fatal = error.requires_owner_stop();
        let retained = failure(&error.to_string());
        self.states[index].failures += 1;
        self.states[index].last_error = Some(retained.clone());
        self.event(
            index,
            EventDetail {
                stage,
                kind: "failure_cursor_retained",
                elapsed_ns: elapsed,
                cost,
                error: Some(retained),
                active: None,
            },
            observe,
        )?;
        if fatal {
            return Err(error);
        }
        Ok(())
    }
    fn step<F, R>(
        &mut self,
        index: usize,
        context: &PollContext<'_>,
        rpc: &mut R,
        observe: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(&PeerPollingEvent) -> Result<()>,
        R: FnMut(usize, &Request) -> Result<PublicReply>,
    {
        let PollContext {
            node,
            cfg,
            settings,
            end,
            stop,
        } = *context;
        progress(end, stop)?;
        if self.calls >= cfg.max_calls {
            return Ok(false);
        }
        let target = self.states[index].target;
        let request = match target {
            Some(tip) => Request::History {
                tip: hex::encode(tip),
                after: hex::encode(self.states[index].cursor),
            },
            None => Request::Head,
        };
        let stage = if target.is_some() { "history" } else { "head" };
        self.calls += 1;
        let started = Instant::now();
        let reply = match rpc(index, &request) {
            Ok(reply) => reply,
            Err(error) => {
                self.transport_errors += 1;
                self.reject(index, stage, error, nanos(started), None, observe)?;
                return Ok(false);
            }
        };
        let cost = Some(PeerRpcCost {
            solve_trials: reply.solve_trials,
            solve_elapsed_ns: reply.solve_elapsed_ns,
            body_bytes_sent: reply.body_bytes_sent,
        });
        if !reply.ok {
            self.rejections += 1;
            let error = reply
                .value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("PEER_BUSINESS_REFUSAL");
            let fallback = stage == "history"
                && ErrorCode::parse(error) == Some(ErrorCode::Cursor)
                && self.states[index].pages == 0
                && !self.states[index].initial_fallback_used
                && self.states[index].cursor != settings.genesis();
            self.reject(
                index,
                stage,
                Error::remote(format!("PEER_REFUSAL:{error}")),
                nanos(started),
                cost,
                observe,
            )?;
            if fallback {
                self.states[index].cursor = settings.genesis();
                self.states[index].initial_fallback_used = true;
                self.states[index].fallbacks += 1;
                self.event(
                    index,
                    EventDetail {
                        stage: "history",
                        kind: "initial_anchor_refused_restart_same_target_at_genesis",
                        elapsed_ns: 0,
                        cost: None,
                        error: None,
                        active: None,
                    },
                    observe,
                )?;
            }
            return Ok(false);
        }
        self.replies += 1;
        progress(end, stop)?;
        if target.is_none() {
            let parsed = reply
                .value
                .get("tip")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::from("PEER_HEAD_LOCATOR"))
                .and_then(digest);
            let locator = match parsed {
                Ok(tip) => tip,
                Err(error) => {
                    self.reject(index, stage, error, nanos(started), cost, observe)?;
                    return Ok(false);
                }
            };
            // Height, root, score and chainwork advertised by the peer are never used.
            if self.states[index].last_completed == Some(locator) {
                self.event(
                    index,
                    EventDetail {
                        stage,
                        kind: "locator_unchanged",
                        elapsed_ns: nanos(started),
                        cost,
                        error: None,
                        active: None,
                    },
                    observe,
                )?;
                return Ok(false);
            }
            self.states[index].target = Some(locator);
            self.states[index].cursor = self.states[index]
                .last_completed
                .unwrap_or(settings.genesis());
            self.states[index].pages = 0;
            self.states[index].initial_fallback_used = false;
            self.event(
                index,
                EventDetail {
                    stage,
                    kind: "fixed_target_located",
                    elapsed_ns: nanos(started),
                    cost,
                    error: None,
                    active: None,
                },
                observe,
            )?;
            let known = {
                let owner = lock(node, end, stop)?;
                match owner.parent_height(locator) {
                    Ok(_) => true,
                    Err(error)
                        if error.is(ErrorCode::UnknownParent)
                            && error.kind() == crate::ErrorKind::StaleContext =>
                    {
                        false
                    }
                    Err(error) => return Err(error),
                }
            };
            if known {
                self.complete(index, node, end, stop, observe)?;
            }
            return Ok(false);
        }
        let target = target.ok_or("PEER_TARGET")?;
        let after = self.states[index].cursor;
        let (packet, next, complete) = match page(settings, reply.value, target, after) {
            Ok(value) => value,
            Err(error) => {
                self.reject(index, stage, error, nanos(started), cost, observe)?;
                return Ok(false);
            }
        };
        let mut verified = false;
        if let Some(packet) = packet {
            match admit_page(node, packet, end, stop) {
                Ok(value) => verified = value,
                Err(error) => {
                    self.reject(
                        index,
                        "native_admission",
                        error,
                        nanos(started),
                        cost,
                        observe,
                    )?;
                    return Ok(false);
                }
            }
            self.states[index].pages += 1;
            self.states[index].admitted += 1;
            self.pages += 1;
            if verified {
                self.states[index].verified += 1;
                self.verified += 1;
            }
        }
        self.states[index].cursor = next;
        self.event(
            index,
            EventDetail {
                stage,
                kind: if verified {
                    "native_verified_page"
                } else {
                    "already_admitted_exact_page"
                },
                elapsed_ns: nanos(started),
                cost,
                error: None,
                active: None,
            },
            observe,
        )?;
        if complete {
            self.complete(index, node, end, stop, observe)?;
        }
        Ok(true)
    }
    fn complete<F>(
        &mut self,
        index: usize,
        node: &Mutex<Node>,
        end: Instant,
        stop: &AtomicBool,
        observe: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&PeerPollingEvent) -> Result<()>,
    {
        let target = self.states[index].target.ok_or("PEER_TARGET")?;
        let activated = (|| -> Result<Hash> {
            let mut owner = lock(node, end, stop)?;
            // Native accumulated work chooses; lower/equal work never takes over.
            owner.activate_observed(target, ingress::now()?)
        })();
        let active = match activated {
            Ok(active) => active,
            Err(error) => {
                self.reject(index, "activation", error, 0, None, observe)?;
                return Ok(());
            }
        };
        self.states[index].cursor = target;
        self.states[index].target = None;
        self.states[index].last_completed = Some(target);
        self.states[index].completed += 1;
        self.event(
            index,
            EventDetail {
                stage: "activation",
                kind: "fixed_target_native_complete",
                elapsed_ns: 0,
                cost: None,
                error: None,
                active: Some(active),
            },
            observe,
        )
    }
    fn cycle<F, R>(&mut self, context: &PollContext<'_>, rpc: &mut R, observe: &mut F) -> Result<()>
    where
        F: FnMut(&PeerPollingEvent) -> Result<()>,
        R: FnMut(usize, &Request) -> Result<PublicReply>,
    {
        let PollContext {
            node: _,
            cfg,
            settings: _,
            end,
            stop,
        } = *context;
        let count = self.states.len();
        let mut attempted_pages = 0;
        let mut failed = BTreeSet::new();
        // One visit per peer per round; failures retry only in the next cycle.
        loop {
            let mut any = false;
            for offset in 0..count {
                if stop.load(Ordering::Acquire)
                    || Instant::now() >= end
                    || self.calls >= cfg.max_calls
                {
                    return Ok(());
                }
                let index = (self.rotation + offset) % count;
                if failed.contains(&index) {
                    continue;
                }
                if self.states[index].target.is_some() {
                    if attempted_pages >= cfg.max_pages_per_cycle {
                        continue;
                    }
                    attempted_pages += 1;
                }
                let prior_target = self.states[index].target;
                let prior_failures = self.states[index].failures;
                let advanced = self.step(index, context, rpc, observe)?;
                if self.states[index].failures != prior_failures {
                    failed.insert(index);
                }
                // An idle/finished peer makes at most one Head observation per cycle.
                if prior_target.is_none() || self.states[index].target.is_none() {
                    failed.insert(index);
                }
                any |= advanced;
            }
            if !any || attempted_pages >= cfg.max_pages_per_cycle {
                break;
            }
        }
        self.rotation = (self.rotation + 1) % count;
        Ok(())
    }
}
/// Ordinary network/peer refusals retain a bounded cursor and retry next cycle.
/// A structural owner or observer failure is fatal and sets the shared stop flag;
/// a normal runtime/call-budget exit leaves the service running for other siblings.
pub fn run_pinned_peer_polling<F>(
    node: Arc<Mutex<Node>>,
    cfg: PeerPollingConfig,
    caller: DevelopmentIdentity,
    stop: Arc<AtomicBool>,
    mut observe: F,
) -> Result<PeerPollingReport>
where
    F: FnMut(&PeerPollingEvent) -> Result<()>,
{
    let started = Instant::now();
    let result = (|| -> Result<PeerPollingReport> {
        let startup_end = started + Duration::from_secs(10);
        let settings = lock(&node, startup_end, &stop)?.settings().clone();
        cfg.validate(&settings)?;
        let context = hex::encode(cfg.context()?);
        let policy = cfg.policy()?;
        let end = started + Duration::from_millis(cfg.runtime_ms);
        let mut engine = Engine::new(&cfg, &settings);
        let mut cycles = 0;
        let mut next = started;
        let mut rpc = |index: usize, request: &Request| {
            public_v3::call_public_protected_v3(
                cfg.peers[index].address,
                request,
                &settings,
                &cfg.peers[index].server_public,
                &caller,
                policy,
            )
        };
        let poll_context = PollContext {
            node: &node,
            cfg: &cfg,
            settings: &settings,
            end,
            stop: &stop,
        };
        while Instant::now() < end && !stop.load(Ordering::Acquire) && engine.calls < cfg.max_calls
        {
            while Instant::now() < next && Instant::now() < end && !stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(2));
            }
            if Instant::now() >= end || stop.load(Ordering::Acquire) {
                break;
            }
            cycles += 1;
            match engine.cycle(&poll_context, &mut rpc, &mut observe) {
                Err(error) if error.is(ErrorCode::PeerPollCancelled) => break,
                other => other?,
            }
            next = Instant::now() + Duration::from_millis(cfg.poll_interval_ms);
        }
        Ok(PeerPollingReport {schema:"native-pinned-peer-poll-report-v1",context,cycles,rpc_attempts:engine.calls,ok_replies:engine.replies,rejected_replies:engine.rejections,transport_errors:engine.transport_errors,history_pages:engine.pages,verified_new_packets:engine.verified,stop_reason:if stop.load(Ordering::Acquire){"shared_stop"}else if engine.calls>=cfg.max_calls{"call_budget"}else{"runtime"},elapsed_ns:nanos(started),peers:engine.states.iter().enumerate().map(|(i,s)|s.snapshot(i)).collect(),cursor_persistence:"bounded runtime memory only; a fresh runtime starts at genesis and can reuse only locally admitted exact packets; Node recovery may select a valid prefix but is not pinned-target completion",native_stage_preemption:false,public_network_ready:false,independent_accepted:false})
    })();
    if result.is_err() {
        stop.store(true, Ordering::Release);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{development_public, maintenance};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use trnm_crypto_primitives::pon_work;

    fn identity(n: u8) -> DevelopmentIdentity {
        DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
    }
    fn config(settings: &Settings) -> PeerPollingConfig {
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        PeerPollingConfig {
            schema: PEER_POLLING_SCHEMA.into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            transport_profile: hex::encode(policy.id()),
            bits: 8,
            lifetime_ms: 2000,
            peers: vec![PinnedPeer {
                address: "127.0.0.1:12345".parse().unwrap(),
                server_public: identity(71).public_key().into(),
            }],
            poll_interval_ms: 10,
            runtime_ms: 10_000,
            max_calls: 64,
            max_pages_per_cycle: 1,
        }
    }
    fn reply(ok: bool, value: Value) -> PublicReply {
        PublicReply {
            ok,
            value,
            solve_trials: 1,
            solve_elapsed_ns: 2,
            body_bytes_sent: 3,
            public_network_ready: false,
            identity_authority: false,
        }
    }
    fn page_value(
        settings: &Settings,
        target: Hash,
        after: Hash,
        packet: Option<&Packet>,
    ) -> Value {
        let next = packet.map(|p| p.id().unwrap()).unwrap_or(after);
        serde_json::to_value(Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(target),
            after: hex::encode(after),
            packets: packet
                .into_iter()
                .map(|p| hex::encode(p.encode().unwrap()))
                .collect(),
            next: hex::encode(next),
            complete: next == target,
        })
        .unwrap()
    }
    fn append(node: &mut Node, parent: Hash, timestamp: u64, miner: u64) -> Packet {
        let p = node
            .make(
                parent,
                vec![],
                development_public(miner).unwrap(),
                timestamp,
                4096,
            )
            .unwrap();
        let id = node.admit(&p, ingress::now().unwrap()).unwrap();
        node.activate_observed(id, ingress::now().unwrap()).unwrap();
        p
    }
    fn context<'a>(
        node: &'a Mutex<Node>,
        cfg: &'a PeerPollingConfig,
        s: &'a Settings,
        stop: &'a AtomicBool,
    ) -> PollContext<'a> {
        PollContext {
            node,
            cfg,
            settings: s,
            end: Instant::now() + Duration::from_secs(120),
            stop,
        }
    }
    #[test]
    fn config_has_exact_context_finite_limits_and_no_discovery() {
        let settings = Settings::development(Some(1)).unwrap();
        let cfg = config(&settings);
        cfg.validate(&settings).unwrap();
        let original = cfg.context().unwrap();
        let mut bad = cfg.clone();
        bad.network = "ff".repeat(32);
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.bits = 9;
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.peers.clear();
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.peers = vec![cfg.peers[0].clone(); 9];
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.peers.push(cfg.peers[0].clone());
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.peers[0].server_public = "00".repeat(32);
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.peers[0].address = "0.0.0.0:1".parse().unwrap();
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.max_pages_per_cycle = 65;
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.max_calls = 0;
        assert!(bad.validate(&settings).is_err());
        let mut bad = cfg.clone();
        bad.poll_interval_ms = 9;
        assert!(bad.validate(&settings).is_err());
        let mut changed = cfg.clone();
        changed.max_pages_per_cycle = 2;
        assert_ne!(original, changed.context().unwrap());
        let mut object = serde_json::to_value(&cfg).unwrap();
        object["discovery"] = true.into();
        assert!(serde_json::from_value::<PeerPollingConfig>(object).is_err());
        let mut object = serde_json::to_value(&cfg).unwrap();
        object["peers"][0]["address"] = "peer.example:12345".into();
        assert!(serde_json::from_value::<PeerPollingConfig>(object).is_err());
    }
    #[test]
    fn config_file_refuses_symlink_fifo_hardlink_writable_and_oversized() {
        let settings = Settings::development(Some(1)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("peers.json");
        std::fs::write(&good, serde_json::to_vec(&config(&settings)).unwrap()).unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        PeerPollingConfig::from_file(&good, &settings).unwrap();
        let link = dir.path().join("link");
        symlink(&good, &link).unwrap();
        assert!(PeerPollingConfig::from_file(&link, &settings).is_err());
        let hard = dir.path().join("hard");
        std::fs::hard_link(&good, &hard).unwrap();
        assert!(PeerPollingConfig::from_file(&good, &settings).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(PeerPollingConfig::from_file(&good, &settings).is_err());
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&good, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(PeerPollingConfig::from_file(&good, &settings).is_err());
        let fifo = dir.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let started = Instant::now();
        assert!(PeerPollingConfig::from_file(&fifo, &settings).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn oversized_failure_is_explicitly_retained_with_digest_and_utf8_boundary() {
        let error = "界".repeat(1000);
        let retained = failure(&error);
        assert!(!retained.complete);
        assert!(retained.message.len() <= MAX_ERROR_BYTES);
        assert_eq!(retained.original_bytes, error.len());
        assert_eq!(
            retained.digest,
            hex::encode(hash(b"native-peer-poll-error-v1", &[error.as_bytes()]))
        );
    }
    #[test]
    fn malformed_pages_fail_before_packet_allocation_and_do_not_claim_progress() {
        let settings = Settings::development(Some(1)).unwrap();
        let genesis = settings.genesis();
        let good = page_value(&settings, genesis, genesis, None);
        assert!(page(&settings, good.clone(), genesis, genesis).unwrap().2);
        for field in [
            "schema",
            "network",
            "parameters",
            "genesis",
            "tip",
            "after",
            "next",
        ] {
            let mut bad = good.clone();
            bad[field] = "ff".repeat(32).into();
            assert!(page(&settings, bad, genesis, genesis).is_err(), "{field}");
        }
        let mut bad = good.clone();
        bad["complete"] = false.into();
        assert!(page(&settings, bad, genesis, genesis).is_err());
        let mut bad = good.clone();
        bad["extra"] = true.into();
        assert!(page(&settings, bad, genesis, genesis).is_err());
        let mut bad = good.clone();
        bad["packets"] = serde_json::json!(["", ""]);
        assert!(page(&settings, bad, genesis, genesis).is_err());
        let mut bad = good.clone();
        bad["packets"] = serde_json::json!(["a".repeat(2 * MAX_PACKET_BYTES + 1)]);
        assert!(page(&settings, bad, genesis, genesis).is_err());
        let mut bad = good;
        bad["packets"] = serde_json::json!(["AB"]);
        assert!(page(&settings, bad, genesis, genesis).is_err());
    }
    #[test]
    fn real_native_fixed_tip_disconnect_one_initial_cursor_fallback_and_heavier_fork() {
        // Scripted RPC selects deterministic replies; native blocks/proofs/state/reorg are real.
        // The independent socket test below covers actual pinned signed paid transport.
        let clock = ingress::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        let local_dir = tempfile::tempdir().unwrap();
        let mut remote = Node::open(remote_dir.path(), settings.clone(), 2).unwrap();
        let genesis = settings.genesis();
        let a1 = append(&mut remote, genesis, clock - 90, 0);
        let a2 = append(&mut remote, a1.id().unwrap(), clock - 80, 0);
        let a3 = append(&mut remote, a2.id().unwrap(), clock - 70, 0);
        let b2 = append(&mut remote, a1.id().unwrap(), clock - 79, 1);
        let b3 = append(&mut remote, b2.id().unwrap(), clock - 69, 1);
        let b4 = append(&mut remote, b3.id().unwrap(), clock - 59, 1);
        let local = Mutex::new(Node::open(local_dir.path(), settings.clone(), 2).unwrap());
        let cfg = config(&settings);
        let stop = AtomicBool::new(false);
        let ctx = context(&local, &cfg, &settings, &stop);
        let mut engine = Engine::new(&cfg, &settings);
        let mut events = vec![];
        let mut observe = |e: &PeerPollingEvent| {
            events.push(serde_json::to_value(e).unwrap());
            Ok(())
        };
        let mut head = |_: usize, r: &Request| {
            assert!(matches!(r, Request::Head));
            Ok(reply(
                true,
                serde_json::json!({"tip":hex::encode(a3.id().unwrap()),"height":u64::MAX,"chainwork":"ff".repeat(32)}),
            ))
        };
        engine.cycle(&ctx, &mut head, &mut observe).unwrap();
        assert_eq!(engine.states[0].target, Some(a3.id().unwrap()));
        let mut calls = 0;
        let mut disconnected = false;
        let mut rpc = |_: usize, r: &Request| {
            let Request::History { tip, after } = r else {
                panic!("must finish fixed target before new Head")
            };
            assert_eq!(tip, &hex::encode(a3.id().unwrap()));
            calls += 1;
            if calls == 2 && !disconnected {
                disconnected = true;
                return Err("IO: injected disconnect".into());
            }
            let after = digest(after).unwrap();
            let p = if after == genesis {
                &a1
            } else if after == a1.id().unwrap() {
                &a2
            } else {
                &a3
            };
            Ok(reply(
                true,
                page_value(&settings, a3.id().unwrap(), after, Some(p)),
            ))
        };
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap(); // exactly one page
        assert_eq!(engine.pages, 1);
        assert_eq!(engine.states[0].cursor, a1.id().unwrap());
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap(); // disconnect retains cursor
        assert_eq!(engine.pages, 1);
        assert_eq!(engine.states[0].cursor, a1.id().unwrap());
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        assert_eq!(local.lock().unwrap().active().unwrap().0, a3.id().unwrap());
        assert_eq!(engine.states[0].last_completed, Some(a3.id().unwrap()));
        assert_eq!(engine.transport_errors, 1);
        let mut head = |_: usize, _: &Request| {
            Ok(reply(
                true,
                serde_json::json!({"tip":hex::encode(b4.id().unwrap())}),
            ))
        };
        engine.cycle(&ctx, &mut head, &mut observe).unwrap();
        assert_eq!(engine.states[0].cursor, a3.id().unwrap());
        let mut refusal =
            |_: usize, _: &Request| Ok(reply(false, serde_json::json!({"error":"CURSOR"})));
        engine.cycle(&ctx, &mut refusal, &mut observe).unwrap();
        assert_eq!(engine.states[0].cursor, genesis);
        assert_eq!(engine.states[0].fallbacks, 1);
        assert_eq!(engine.states[0].target, Some(b4.id().unwrap()));
        engine.cycle(&ctx, &mut refusal, &mut observe).unwrap(); // no second fallback
        assert_eq!(engine.states[0].fallbacks, 1);
        let mut rpc = |_: usize, r: &Request| {
            let Request::History { tip, after } = r else {
                panic!("fixed fork")
            };
            assert_eq!(tip, &hex::encode(b4.id().unwrap()));
            let after = digest(after).unwrap();
            let p = if after == genesis {
                &a1
            } else if after == a1.id().unwrap() {
                &b2
            } else if after == b2.id().unwrap() {
                &b3
            } else {
                &b4
            };
            Ok(reply(
                true,
                page_value(&settings, b4.id().unwrap(), after, Some(p)),
            ))
        };
        for _ in 0..4 {
            engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        }
        assert_eq!(local.lock().unwrap().active().unwrap().0, b4.id().unwrap());
        assert_eq!(engine.states[0].verified, 6); // a1 exact reuse is not new proof admission
        assert_eq!(engine.states[0].completed, 2);
        assert_eq!(engine.states[0].failures, 3);
        let mut lower_head = |_: usize, _: &Request| {
            Ok(reply(
                true,
                serde_json::json!({"tip":hex::encode(a2.id().unwrap()),"chainwork":"ff".repeat(32)}),
            ))
        };
        engine.cycle(&ctx, &mut lower_head, &mut observe).unwrap();
        assert_eq!(local.lock().unwrap().active().unwrap().0, b4.id().unwrap());
        assert_eq!(engine.states[0].last_completed, Some(a2.id().unwrap()));
        assert_eq!(engine.states[0].completed, 3);
        let retained = events
            .iter()
            .position(|e| e["error"]["message"] == "PEER_REFUSAL:CURSOR")
            .unwrap();
        assert_eq!(
            events[retained + 1]["kind"],
            "initial_anchor_refused_restart_same_target_at_genesis"
        );
        assert_eq!(
            events[retained + 1]["target"],
            hex::encode(b4.id().unwrap())
        );
        assert!(!stop.load(Ordering::Acquire));
    }
    #[test]
    fn transport_unknown_block_malformed_and_post_progress_cursor_never_fallback() {
        let settings = Settings::development(Some(1)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let node = Mutex::new(Node::open(dir.path(), settings.clone(), 1).unwrap());
        let cfg = config(&settings);
        let stop = AtomicBool::new(false);
        let ctx = context(&node, &cfg, &settings, &stop);
        let mut engine = Engine::new(&cfg, &settings);
        let original = [11; 32];
        engine.states[0].cursor = original;
        engine.states[0].target = Some([12; 32]);
        let mut observe = |_: &PeerPollingEvent| Ok(());
        let mut rpc = |_: usize, _: &Request| Err("IO: no route".into());
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        let mut rpc =
            |_: usize, _: &Request| Ok(reply(false, serde_json::json!({"error":"UNKNOWN_PARENT"})));
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        let mut rpc =
            |_: usize, _: &Request| Ok(reply(true, serde_json::json!({"error":"CURSOR"})));
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        engine.states[0].pages = 1;
        let mut rpc =
            |_: usize, _: &Request| Ok(reply(false, serde_json::json!({"error":"CURSOR"})));
        engine.cycle(&ctx, &mut rpc, &mut observe).unwrap();
        assert_eq!(engine.states[0].cursor, original);
        assert_eq!(engine.states[0].fallbacks, 0);
        assert_eq!(engine.states[0].failures, 4);
        assert_eq!(engine.calls, 4);
    }
    #[test]
    fn actual_valid_work_with_false_ledger_state_cannot_advance_cursor_or_owner() {
        let clock = ingress::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let producer_dir = tempfile::tempdir().unwrap();
        let local_dir = tempfile::tempdir().unwrap();
        let producer = Node::open(producer_dir.path(), settings.clone(), 1).unwrap();
        let mut p = producer
            .make(
                settings.genesis(),
                vec![],
                development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        p.header.state = [249; 32];
        let (a, b) = maintenance();
        let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
        let mut found = false;
        for nonce in 0..4096 {
            p.header.nonce = nonce;
            p.proof = prepared.prove(p.header.challenge()).unwrap();
            if pon_work::verify(
                p.header.challenge(),
                p.header.work_task,
                p.header.target,
                &p.proof,
            )
            .is_ok()
            {
                found = true;
                break;
            }
        }
        assert!(found);
        WorkCheckedPacket::verify(p.clone()).unwrap();
        let node = Mutex::new(Node::open(local_dir.path(), settings.clone(), 1).unwrap());
        let before = node.lock().unwrap().read_active().unwrap();
        let cfg = config(&settings);
        let stop = AtomicBool::new(false);
        let ctx = context(&node, &cfg, &settings, &stop);
        let mut engine = Engine::new(&cfg, &settings);
        engine.states[0].target = Some(p.id().unwrap());
        let mut rpc = |_: usize, _: &Request| {
            Ok(reply(
                true,
                page_value(&settings, p.id().unwrap(), settings.genesis(), Some(&p)),
            ))
        };
        engine
            .cycle(&ctx, &mut rpc, &mut |_: &PeerPollingEvent| Ok(()))
            .unwrap();
        assert_eq!(engine.states[0].cursor, settings.genesis());
        assert_eq!(engine.states[0].pages, 0);
        assert_eq!(
            engine.states[0].last_error.as_ref().unwrap().message,
            "ROOT"
        );
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
    }
    #[test]
    fn call_and_global_page_budgets_round_robin_are_hard_finite() {
        let settings = Settings::development(Some(1)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let node = Mutex::new(Node::open(dir.path(), settings.clone(), 1).unwrap());
        let mut cfg = config(&settings);
        cfg.peers.push(PinnedPeer {
            address: "127.0.0.1:12346".parse().unwrap(),
            server_public: identity(73).public_key().into(),
        });
        cfg.max_calls = 3;
        let stop = AtomicBool::new(false);
        let ctx = context(&node, &cfg, &settings, &stop);
        let mut engine = Engine::new(&cfg, &settings);
        engine.states[0].target = Some([11; 32]);
        engine.states[1].target = Some([12; 32]);
        let mut indices = vec![];
        let mut rpc = |i: usize, _: &Request| {
            indices.push(i);
            Ok(reply(false, serde_json::json!({"error":"BUSY"})))
        };
        for _ in 0..10 {
            engine
                .cycle(&ctx, &mut rpc, &mut |_: &PeerPollingEvent| Ok(()))
                .unwrap();
        }
        assert_eq!(engine.calls, 3);
        assert_eq!(indices, vec![0, 1, 0]);
        assert_eq!(engine.states[0].failures, 2);
        assert_eq!(engine.states[1].failures, 1);
    }
    #[test]
    fn actual_retained_header_fault_stops_poll_cycle_while_same_peer_diagnostic_retries() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut owner = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let block = append(&mut owner, settings.genesis(), 11, 0);
        let id = block.id().unwrap();
        let raw = block.encode().unwrap();
        let mut damaged = raw.clone();
        damaged[0] ^= 0xff;
        let node = Mutex::new(owner);
        let cfg = config(&settings);
        let stop = AtomicBool::new(false);
        let ctx = context(&node, &cfg, &settings, &stop);

        let mut peer_page = page_value(&settings, id, settings.genesis(), Some(&block));
        peer_page["packets"][0] = hex::encode(&damaged).into();
        let mut incoming = Engine::new(&cfg, &settings);
        incoming.states[0].target = Some(id);
        for _ in 0..2 {
            incoming
                .cycle(
                    &ctx,
                    &mut |_, _| Ok(reply(true, peer_page.clone())),
                    &mut |_| Ok(()),
                )
                .unwrap();
        }
        assert_eq!(incoming.calls, 2);
        assert_eq!(incoming.states[0].failures, 2);
        assert_eq!(incoming.states[0].cursor, settings.genesis());
        assert_eq!(
            incoming.states[0].last_error.as_ref().unwrap().message,
            "HEADER_CODEC"
        );
        assert_eq!(incoming.verified, 0);
        for message in [
            "HEADER_CODEC",
            "UNKNOWN_PARENT",
            "AUTH_RECOVERY:peer recovery source rejected: AUTH_PENDING_AUDIT",
        ] {
            incoming
                .cycle(
                    &ctx,
                    &mut |_, _| Ok(reply(false, serde_json::json!({"error":message}))),
                    &mut |_| Ok(()),
                )
                .unwrap();
        }
        assert_eq!(incoming.calls, 5);
        assert_eq!(incoming.states[0].cursor, settings.genesis());

        // Mutate only this test's already-admitted local row; no network listener
        // or public-service stress campaign is used for this provenance regression.
        let db = rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
        db.execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            rusqlite::params![damaged, id.as_slice()],
        )
        .unwrap();
        let mut retained = Engine::new(&cfg, &settings);
        let error = retained
            .cycle(
                &ctx,
                &mut |_, _| Ok(reply(true, serde_json::json!({"tip":hex::encode(id)}))),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert!(error.is(ErrorCode::HeaderCodec));
        assert_eq!(error.kind(), crate::ErrorKind::LocalStructure);
        assert!(error.requires_owner_stop());
        assert_eq!(error.to_string(), "HEADER_CODEC");
        assert_eq!(retained.calls, 1);
        assert_eq!(retained.states[0].failures, 1);
        assert_eq!(retained.states[0].completed, 0);
        assert_eq!(retained.states[0].cursor, settings.genesis());
        db.execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            rusqlite::params![raw, id.as_slice()],
        )
        .unwrap();
        node.lock()
            .unwrap()
            .check_observed_history(id, 1000)
            .unwrap();
    }

    #[test]
    fn typed_local_structure_stops_but_remote_and_transport_failures_retain_cursor() {
        let settings = Settings::development(Some(1)).unwrap();
        let cfg = config(&settings);
        let mut engine = Engine::new(&cfg, &settings);
        let cursor = [19; 32];
        engine.states[0].cursor = cursor;
        for (error, fatal) in [
            (Error::from("STORAGE_PACKET"), true),
            (Error::from(rusqlite::Error::InvalidQuery), true),
            (Error::remote("STORAGE_PACKET"), false),
            (Error::from("ANCESTRY_INDEX_REMOTE_FAILURE"), false),
            (Error::from(std::io::Error::other("STORAGE_PACKET")), false),
            (Error::from("ANCESTRY_INDEX_UNKNOWN_BLOCK"), false),
            (Error::from("ANCESTRY_INDEX_BUDGET"), true),
        ] {
            let display = error.to_string();
            let mut events = 0;
            let result = engine.reject(0, "history", error, 10, None, &mut |event| {
                events += 1;
                assert_eq!(event.kind, "failure_cursor_retained");
                assert_eq!(event.cursor, hex::encode(cursor));
                Ok(())
            });
            assert_eq!(result.is_err(), fatal, "{display}");
            if let Err(error) = result {
                assert_eq!(error.to_string(), display);
            }
            assert_eq!(events, 1);
            assert_eq!(engine.states[0].cursor, cursor);
        }
        assert_eq!(engine.states[0].failures, 7);
    }
    #[test]
    fn normal_zero_progress_runtime_does_not_stop_service_and_observer_error_does() {
        let settings = Settings::development(Some(1)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let node = Arc::new(Mutex::new(
            Node::open(dir.path(), settings.clone(), 1).unwrap(),
        ));
        let mut cfg = config(&settings);
        cfg.runtime_ms = 1;
        let stop = Arc::new(AtomicBool::new(false));
        // Startup/config cost may exhaust a one-ms runtime before any RPC. Whether the
        // sole refused connection happens or not, normal budget exit keeps stop false.
        let report = run_pinned_peer_polling(
            node.clone(),
            cfg.clone(),
            identity(72),
            stop.clone(),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(report.stop_reason, "runtime");
        assert!(!stop.load(Ordering::Acquire));
        cfg.runtime_ms = 2000;
        cfg.max_calls = 1;
        let failed = run_pinned_peer_polling(node, cfg, identity(72), stop.clone(), |_| {
            Err("OBSERVER_FULL".into())
        });
        assert_eq!(failed.unwrap_err().to_string(), "OBSERVER_FULL");
        assert!(stop.load(Ordering::Acquire));
    }
}
