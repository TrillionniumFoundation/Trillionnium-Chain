//! Public development intake: resource tickets confer no ledger/source authority.
//! Explicit development profile. No guest identity/replay row is persisted.
//! Pool writes are exact signed transaction facts, under the existing shared Node owner.
//! V2 retains separate signed domains; both select the current derived-index resource bound.
//! M05 transcript replay checks local cancellation; M06/SQLite retain stage fences without hard preemption.
use super::{
    digest, elapsed_ns, ensure, hash, lock_owner, DevelopmentIdentity, Node,
    Request as NativeRequest, Result, Settings, WorkCheckedPacket,
};
mod request_observation;
pub use request_observation::{
    ApplicationFrameBytes, ApplicationFramePhase, PublicRequestObservation,
    PublicRequestObservationSnapshot, PublicRequestObserver, MAX_REQUEST_OBSERVATION_RECORDS,
};
use request_observation::{ConnectionObservation, TaskObservation, ThreadCpuStamp};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
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

/// Fresh signed/wire successor. V2 remains a separate unchanged byte contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Submit {
        packet: String,
    },
    Head,
    History {
        tip: String,
        after: String,
    },
    PoolSubmitBundle {
        pool_context: String,
        transactions: Vec<String>,
    },
    PoolStatus,
}
pub const PROFILE: &str = "public-protected-development-v3";
const HELLO_BYTES: usize = 108;
const SOLUTION_BYTES: usize = 108;
const MAX_PACKET: usize = 1_048_576;
const MAX_BODY: usize = 2 * MAX_PACKET + 64;
const MAX_READ_BODY: usize = 512;
const MIN_POOL_RAW: usize = 159;
const MAX_POOL_RAW: usize = 2048;
const MAX_POOL_MEMBERS: usize = 16;
const MAX_POOL_BUNDLE_BYTES: usize = MAX_POOL_RAW * MAX_POOL_MEMBERS;
const MAX_POOL_BODY: usize = MAX_POOL_BUNDLE_BYTES * 2 + 512;
const MAX_SERVICE_SECONDS: u64 = 72 * 3600;
const MAX_RESPONSE: usize = 2 * MAX_PACKET + 4096;
const MAX_CONNECTIONS: usize = 64;
const MAX_PAID_BODY_BYTES: usize = 8 * 1024 * 1024;
// Reservations partition the existing totals; they add no socket/worker/queue.
const READ_BODY_RESERVE: usize = 128 * 1024;
const CONTROL_OUTPUT_RESERVE: usize = 512 * 1024;
const MAX_MUTATING_GRANTS: usize = 8;
const MAX_READ_GRANTS: usize = 8;
const MAX_SPENT: usize = 1024;
const MAX_HISTORY_STEPS: u64 = 1024;
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
// Local receiver policy, independent of the caller's ticket-search algorithm.
const MUTATION_CPU_BURST_NS: u64 = 2_000_000_000;
const MUTATION_CPU_REFILL_NS_PER_SECOND: u64 = 250_000_000;
const MUTATION_CPU_START_RESERVE_NS: u64 = 100_000_000;
const MUTATION_CPU_WORKERS: usize = 2;

/// Volatile service-epoch accounting, never ledger or caller identity authority.
struct PaidMutationCpuBudget {
    credit_ns: i128,
    updated: Instant,
    in_flight: usize,
    unavailable: bool,
}
impl PaidMutationCpuBudget {
    fn new() -> Self {
        Self {
            credit_ns: i128::from(MUTATION_CPU_BURST_NS),
            updated: Instant::now(),
            in_flight: 0,
            unavailable: false,
        }
    }
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.updated = now;
        let Some(credit) = elapsed
            .checked_mul(u128::from(MUTATION_CPU_REFILL_NS_PER_SECOND))
            .map(|n| n / 1_000_000_000)
            .and_then(|n| i128::try_from(n).ok())
            .and_then(|n| self.credit_ns.checked_add(n))
        else {
            self.unavailable = true;
            return;
        };
        // Refill cannot mint a second burst on top of outstanding start reserves.
        self.credit_ns = credit.min(self.credit_ceiling());
    }
    fn credit_ceiling(&self) -> i128 {
        i128::from(MUTATION_CPU_BURST_NS)
            - (self.in_flight as i128) * i128::from(MUTATION_CPU_START_RESERVE_NS)
    }
    fn reserve(&mut self, now: Instant) -> Result<()> {
        self.refill(now);
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        ensure(
            self.in_flight < MUTATION_CPU_WORKERS
                && self.credit_ns >= i128::from(MUTATION_CPU_START_RESERVE_NS),
            "PUBLIC_MUTATION_CPU_BUDGET",
        )?;
        self.credit_ns -= i128::from(MUTATION_CPU_START_RESERVE_NS);
        self.in_flight += 1;
        Ok(())
    }
    fn settle(&mut self, now: Instant, measured: Option<u64>) {
        self.refill(now);
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(measured) = measured {
            match self
                .credit_ns
                .checked_add(i128::from(MUTATION_CPU_START_RESERVE_NS) - i128::from(measured))
            {
                Some(credit) => self.credit_ns = credit.min(self.credit_ceiling()),
                None => self.unavailable = true,
            }
        } else {
            // No fabricated zero or refund when actual accounting is unavailable.
            self.unavailable = true;
        }
    }
}
#[derive(Default)]
struct MutationCpuMeasurement {
    full_work_ns: Cell<Option<u64>>,
    unavailable: Cell<bool>,
}
struct PaidMutationCpuPermit {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    stamp: Option<ThreadCpuStamp>,
    settled: bool,
}
impl PaidMutationCpuPermit {
    fn acquire(server: &PublicServer, metrics: &Mutex<PublicMetrics>) -> Result<Self> {
        let stamp = ThreadCpuStamp::start();
        #[cfg(test)]
        let stamp = if server.fail_next_cpu_start.swap(false, Ordering::AcqRel) {
            None
        } else {
            stamp
        };
        let mut budget = server
            .mutation_cpu
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        if stamp.is_none() {
            budget.unavailable = true;
        }
        let result = budget.reserve(Instant::now());
        drop(budget);
        if let Ok(mut m) = metrics.lock() {
            if result.is_err() {
                m.mutation_cpu_refusals += 1;
                m.mutation_cpu_clock_failures += u64::from(stamp.is_none());
            } else {
                m.mutation_cpu_reservations += 1;
            }
        }
        result?;
        Ok(Self {
            budget: server.mutation_cpu.clone(),
            stamp,
            settled: false,
        })
    }
    // Settlement cannot replace an already completed native outcome or ACK.
    fn finish(
        mut self,
        measurement: &MutationCpuMeasurement,
        server: &PublicServer,
        metrics: &Mutex<PublicMetrics>,
    ) -> Option<u64> {
        let total = self.stamp.take().and_then(ThreadCpuStamp::finish);
        #[cfg(test)]
        let total = if server.fail_next_cpu_finish.swap(false, Ordering::AcqRel) {
            None
        } else {
            total
        };
        #[cfg(not(test))]
        let _ = server;
        let work = measurement.full_work_ns.get().unwrap_or(0);
        let remainder = total.and_then(|n| n.checked_sub(work));
        let charged = if measurement.unavailable.get() || remainder.is_none() {
            None
        } else {
            total
        };
        if let Ok(mut budget) = self.budget.lock() {
            budget.settle(Instant::now(), charged);
        }
        self.settled = true;
        if let Ok(mut m) = metrics.lock() {
            m.mutation_cpu_clock_failures += u64::from(charged.is_none());
            if let (Some(total), Some(dispatch)) = (charged, remainder) {
                m.mutation_cpu_charged_ns = m.mutation_cpu_charged_ns.saturating_add(total);
                m.mutation_full_work_cpu_ns = m.mutation_full_work_cpu_ns.saturating_add(work);
                m.mutation_dispatch_excluding_work_cpu_ns = m
                    .mutation_dispatch_excluding_work_cpu_ns
                    .saturating_add(dispatch);
            }
        }
        total
    }
}
impl Drop for PaidMutationCpuPermit {
    fn drop(&mut self) {
        if !self.settled {
            if let Ok(mut budget) = self.budget.lock() {
                budget.settle(Instant::now(), None);
            }
        }
    }
}

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
        hash(b"public-protected-profile-v3",&[PROFILE.as_bytes(),b"resource-revision-r6/connection-local-ready-fifo-challenge-and-grant-split-read-mutation/pending64-no-extra-queue-or-worker/hello-wait-original-accept2s/paid-grant-wait-original-cookie-expiry-no-renewal/spent-reserve-once/lane-and-body-together-rollback-on-full/bounded-paid-enqueue-fifo-by-connection-with-unchanged-absolute-work-and-total-deadlines/hello108/solution108/conn64/paid-raw-json-canonical8MiB-factor3/read-body-reserve131072/output-conservative32MiB/control-output-reserve524288/grants-mutation8-read8-held-until-connection-and-task-release/queueproof2-read2/workers2-read1/spent1024-no-live-eviction/packet1048576/body2097216/read512/response2101248/history1/error2KiB/hello2s/challenge2s/solution-policy/body5s/work10s/output5s/overall30s/quantum64KiB/derived-jump-v1-levels63-sql1024-local-integrity-only/challenge128-burst32-read-reserve8/await-write-half-close-cancels-request-operation-stage-fences/ops1-block-2-head-3-history-4-poolbundle-5-poolsnapshot/poolraw159..2048-members1..16-sum32768-body66048-contextpin64hex/scalarstatus16KiB-no-reconcile-cachegc4scalars-localdiagnostic/no-guest-policy-prune-reset/shared-node-miner-operatorenabled/service72h-m05-cooperative-noise-row-tile-final-deadline-cancel-m06-sqlite-nonpreemptive/no-durable-guest-rows/global-paid-mutation-thread-cpu-bucket-reserve-before-dispatch-charge-outer-once-work-plus-nonwork-no-double-debit/read-not-charged/clock-unavailable-disables-future-mutations/native-success-preserved/two-inflight-m05-cooperative-m06-nonpreemptive-debt-no-caller-reset/available-plus-outstanding-start-reserves-ceiling",&[self.bits],&self.lifetime_ms.to_le_bytes(),&MUTATION_CPU_BURST_NS.to_le_bytes(),&MUTATION_CPU_REFILL_NS_PER_SECOND.to_le_bytes(),&MUTATION_CPU_START_RESERVE_NS.to_le_bytes(),&(MUTATION_CPU_WORKERS as u32).to_le_bytes()])
    }
}
#[derive(Default, Clone, Debug, Serialize)]
pub struct PublicMetrics {
    pub mutation_cpu_reservations: u64,
    pub mutation_cpu_refusals: u64,
    pub mutation_cpu_clock_failures: u64,
    pub mutation_cpu_charged_ns: u64,
    pub mutation_full_work_cpu_ns: u64,
    pub mutation_dispatch_excluding_work_cpu_ns: u64,
    pub mutation_cpu_in_flight_after_shutdown: usize,
    pub mutation_cpu_credit_ns_after_shutdown: u64,
    pub mutation_cpu_debt_ns_after_shutdown: u64,
    pub mutation_cpu_unavailable_after_shutdown: bool,
    pub accepted_connections: u64,
    pub capacity_refusals: u64,
    pub preface_refusals: u64,
    pub challenge_budget_refusals: u64,
    pub pending_challenge_entered: u64,
    pub pending_challenge_granted: u64,
    pub pending_challenge_closed: u64,
    pub pending_challenge_wait_ns: u64,
    pub peak_pending_challenge: usize,
    pub issued_challenges: u64,
    pub ticket_refusals: u64,
    pub signature_refusals: u64,
    pub spent_capacity_refusals: u64,
    pub paid_body_capacity_refusals: u64,
    pub lane_capacity_refusals: u64,
    pub pending_grant_entered: u64,
    pub pending_grant_granted: u64,
    pub pending_grant_closed: u64,
    pub pending_grant_wait_ns: u64,
    pub peak_pending_grant: usize,
    pub disconnected_await_requests: u64,
    pub tasks_skipped_before_dispatch: u64,
    pub abandoned_tasks: u64,
    pub tasks_enqueued: u64,
    pub tasks_dequeued: u64,
    pub replay_refusals: u64,
    pub queue_refusals: u64,
    pub queue_backpressure_events: u64,
    pub enqueued_after_backpressure: u64,
    pub queue_wait_ns: u64,
    pub peak_pending_enqueue: usize,
    pub disconnected_before_enqueue: u64,
    pub parse_refusals: u64,
    pub work_started: u64,
    pub work_finished: u64,
    pub work_failed: u64,
    pub work_ns: u64,
    pub executor_refusals: u64,
    pub completed_submit: u64,
    pub completed_pool_submit: u64,
    pub completed_pool_status: u64,
    pub pool_submit_started: u64,
    pub pool_submit_finished: u64,
    pub pool_submit_failed: u64,
    pub pool_submit_ns: u64,
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
    pub spent_reservations: u64,
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
            b"public-cookie-server-sign-v3",
            &[&serde_json::to_vec(&c)?],
        ))
    }
    fn id(&self) -> Result<Hash> {
        Ok(hash(b"public-cookie-id-v3", &[&serde_json::to_vec(self)?]))
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
    let h = hash(b"public-ticket-v3", &[&cookie, &nonce.to_le_bytes()]);
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
        Request::PoolSubmitBundle { .. } => Ok(4),
        Request::PoolStatus => Ok(5),
    }
}
fn response_maximum(op: u8) -> usize {
    if op == 3 {
        MAX_RESPONSE
    } else {
        16384
    }
}
fn mutating_operation(op: u8) -> bool {
    matches!(op, 1 | 4)
}
fn body_maximum(op: u8) -> Result<usize> {
    match op {
        1 => Ok(MAX_BODY),
        4 => Ok(MAX_POOL_BODY),
        2 | 3 | 5 => Ok(MAX_READ_BODY),
        _ => Err("PUBLIC_OPERATION".into()),
    }
}
fn lower_hex(text: &[u8]) -> bool {
    text.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
/// Check cardinality and every hex row before serde can allocate a Vec<String>.
fn pool_bundle_body_guard(bytes: &[u8]) -> Result<()> {
    ensure(bytes.len() <= MAX_POOL_BODY, "PUBLIC_POOL_BODY")?;
    let prefix = br#"{"op":"pool_submit_bundle","pool_context":""#;
    let payload = bytes
        .strip_prefix(prefix)
        .and_then(|b| b.strip_suffix(b"]}"))
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let (context, rest) = payload.split_at_checked(64).ok_or("PUBLIC_POOL_CONTEXT")?;
    ensure(lower_hex(context), "PUBLIC_POOL_CONTEXT")?;
    let mut rest = rest
        .strip_prefix(b"\",\"transactions\":[")
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let mut count = 0;
    let mut total = 0usize;
    while !rest.is_empty() {
        ensure(count < MAX_POOL_MEMBERS, "PUBLIC_POOL_MEMBERS")?;
        rest = rest.strip_prefix(b"\"").ok_or("PUBLIC_POOL_CANONICAL")?;
        let end = rest
            .iter()
            .position(|b| *b == b'"')
            .ok_or("PUBLIC_POOL_CANONICAL")?;
        let text = &rest[..end];
        ensure(
            text.len().is_multiple_of(2)
                && (2 * MIN_POOL_RAW..=2 * MAX_POOL_RAW).contains(&text.len())
                && lower_hex(text),
            "PUBLIC_POOL_RAW",
        )?;
        total = total
            .checked_add(text.len() / 2)
            .ok_or("PUBLIC_POOL_BYTES")?;
        ensure(total <= MAX_POOL_BUNDLE_BYTES, "PUBLIC_POOL_BYTES")?;
        count += 1;
        rest = &rest[end + 1..];
        if !rest.is_empty() {
            rest = rest.strip_prefix(b",").ok_or("PUBLIC_POOL_CANONICAL")?;
            ensure(!rest.is_empty(), "PUBLIC_POOL_CANONICAL")?;
        }
    }
    ensure(
        (1..=MAX_POOL_MEMBERS).contains(&count),
        "PUBLIC_POOL_MEMBERS",
    )
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
            raw.len() == HELLO_BYTES && raw[..4] == *b"PPH3" && raw[5..8] == [0; 3],
            "PUBLIC_HELLO",
        )?;
        let op = raw[4];
        let len = u32::from_le_bytes(raw[8..12].try_into().map_err(|_| "PUBLIC_HELLO")?) as usize;
        ensure(
            matches!(op, 1..=5) && len > 0 && len <= body_maximum(op)?,
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
        let mut xs = b"PPH3".to_vec();
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
    mutation_cpu: Arc<Mutex<PaidMutationCpuBudget>>,
    #[cfg(test)]
    fail_next_output: AtomicBool,
    #[cfg(test)]
    fail_next_cpu_start: AtomicBool,
    #[cfg(test)]
    fail_next_cpu_finish: AtomicBool,
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
            mutation_cpu: Arc::new(Mutex::new(PaidMutationCpuBudget::new())),
            #[cfg(test)]
            fail_next_output: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_cpu_start: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_cpu_finish: AtomicBool::new(false),
        })
    }
    fn tick(&self) -> Result<u64> {
        u64::try_from(self.started.elapsed().as_millis()).map_err(|_| "PUBLIC_CLOCK".into())
    }
    fn cookie(&self, s: &Settings, h: Hello, peer: SocketAddr) -> Result<Cookie> {
        let tick = self.tick()?;
        let mut c = Cookie {
            schema: "public-resource-cookie-v3".into(),
            profile: hex::encode(self.policy.id()),
            network: hex::encode(s.network()),
            parameters: hex::encode(s.parameters()),
            genesis: hex::encode(s.genesis()),
            server: self.identity.public_key().into(),
            epoch: hex::encode(self.epoch),
            connection_nonce: hex::encode(entropy::<32>()?),
            peer_binding: hex::encode(hash(
                b"public-peer-binding-v3",
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
            c.schema == "public-resource-cookie-v3"
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
            b"public-response-sign-v3",
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
        schema: "public-protected-response-v3".into(),
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
    framed(serde_json::to_vec(&r)?, response_maximum(c.op))
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
    ensure(
        !bytes.is_empty() && bytes.len() <= body_maximum(op)?,
        "PUBLIC_BODY_LIMIT",
    )?;
    if op == 4 {
        pool_bundle_body_guard(bytes)?;
    }
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
        Self::try_acquire(pool, bytes, maximum)?.ok_or_else(|| "PUBLIC_BUFFER_CAPACITY".into())
    }
    fn try_acquire(pool: Arc<Mutex<usize>>, bytes: usize, maximum: usize) -> Result<Option<Self>> {
        let mut used = pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
        if bytes > maximum.saturating_sub(*used) {
            return Ok(None);
        }
        *used += bytes;
        drop(used);
        Ok(Some(Self { pool, bytes }))
    }
}
impl Drop for BufferPermit {
    fn drop(&mut self) {
        if let Ok(mut used) = self.pool.lock() {
            *used = used.saturating_sub(self.bytes);
        }
    }
}
fn try_paid_permits(
    cookie: &Cookie,
    mutating_grants: &Arc<Mutex<usize>>,
    read_grants: &Arc<Mutex<usize>>,
    body_pool: &Arc<Mutex<usize>>,
) -> Result<Option<(BufferPermit, BufferPermit)>> {
    let mutation = mutating_operation(cookie.op);
    let grant_pool = if mutation {
        mutating_grants
    } else {
        read_grants
    };
    let Some(lane) = BufferPermit::try_acquire(
        grant_pool.clone(),
        1,
        if mutation {
            MAX_MUTATING_GRANTS
        } else {
            MAX_READ_GRANTS
        },
    )?
    else {
        return Ok(None);
    };
    let bytes = (cookie.body_len as usize)
        .checked_mul(3)
        .ok_or("PUBLIC_BODY_LIMIT")?;
    let Some(body) = BufferPermit::try_acquire(
        body_pool.clone(),
        bytes,
        if mutation {
            MAX_PAID_BODY_BYTES - READ_BODY_RESERVE
        } else {
            MAX_PAID_BODY_BYTES
        },
    )?
    else {
        // Dropping this temporary lane is mandatory: a waiting connection
        // cannot hold a grant while the shared body budget is unavailable.
        return Ok(None);
    };
    Ok(Some((lane, body)))
}
struct Task {
    observation: Option<TaskObservation>,
    _permit: BufferPermit,
    _lane_permit: Arc<BufferPermit>,
    id: u64,
    cookie: Cookie,
    request: Request,
    ready_at: Instant,
    backpressure_seen: bool,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
struct Finished {
    permit: Option<BufferPermit>,
    id: u64,
    bytes: Result<Vec<u8>>,
}
#[derive(Clone, Copy)]
struct PendingOrder {
    sequence: u64,
    entered_at: Instant,
}
impl PendingOrder {
    fn next(sequence: &mut u64) -> Result<Self> {
        *sequence = sequence.checked_add(1).ok_or("PUBLIC_PENDING_ORDER")?;
        Ok(Self {
            sequence: *sequence,
            entered_at: Instant::now(),
        })
    }
}
#[derive(Clone, Copy)]
enum PendingKind {
    Challenge,
    Grant,
}
enum Stage {
    Hello(Vec<u8>),
    WaitChallenge {
        hello: Hello,
        pending: PendingOrder,
    },
    Challenge {
        cookie: Cookie,
        bytes: Vec<u8>,
        cursor: usize,
    },
    Solution {
        cookie: Cookie,
        bytes: Vec<u8>,
    },
    // A private state entered only after the original full Solution checks and
    // one spent reservation. It owns no body, lane grant or canonical Task.
    WaitGrant {
        cookie: Cookie,
        pending: PendingOrder,
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
    Enqueue(Box<Task>),
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
            Self::Hello(_) | Self::WaitChallenge { .. } => "hello",
            Self::Challenge { .. } => "challenge",
            Self::Solution { .. } | Self::WaitGrant { .. } => "solution",
            Self::Ready { .. } => "ready",
            Self::Body { .. } => "body",
            Self::Enqueue(_) => "queue",
            Self::Await => "work",
            Self::Output { .. } => "output",
        }
    }
    fn pending(&self) -> Option<(PendingKind, PendingOrder)> {
        match self {
            Self::WaitChallenge { pending, .. } => Some((PendingKind::Challenge, *pending)),
            Self::WaitGrant { pending, .. } => Some((PendingKind::Grant, *pending)),
            _ => None,
        }
    }
}
// Four logical FIFO heads refer only to the existing bounded Connection map.
// A partial prefix or unsolved cookie has no order and cannot block a ready item.
#[derive(Default)]
struct PendingHeads {
    challenge: [Option<(u64, u64)>; 2],
    grant: [Option<(u64, u64)>; 2],
}
impl PendingHeads {
    fn collect(connections: &BTreeMap<u64, Connection>, now: Instant) -> Self {
        let mut heads = Self::default();
        for (id, conn) in connections {
            if now >= conn.deadline {
                continue;
            }
            let (slots, op, order) = match &conn.stage {
                Stage::WaitChallenge { hello, pending } => {
                    (&mut heads.challenge, hello.op, pending.sequence)
                }
                Stage::WaitGrant { cookie, pending } => {
                    (&mut heads.grant, cookie.op, pending.sequence)
                }
                _ => continue,
            };
            let slot = &mut slots[usize::from(mutating_operation(op))];
            let candidate = (order, *id);
            if slot.is_none_or(|head| candidate < head) {
                *slot = Some(candidate);
            }
        }
        heads
    }
    fn is_head(&self, kind: PendingKind, op: u8, id: u64) -> bool {
        let slots = match kind {
            PendingKind::Challenge => &self.challenge,
            PendingKind::Grant => &self.grant,
        };
        slots[usize::from(mutating_operation(op))].is_some_and(|(_, head)| head == id)
    }
}
fn close_pending(metrics: &mut PublicMetrics, pending: Option<(PendingKind, PendingOrder)>) {
    if let Some((kind, order)) = pending {
        let waited = elapsed_ns(order.entered_at);
        match kind {
            PendingKind::Challenge => {
                metrics.pending_challenge_closed += 1;
                metrics.pending_challenge_wait_ns =
                    metrics.pending_challenge_wait_ns.saturating_add(waited);
            }
            PendingKind::Grant => {
                metrics.pending_grant_closed += 1;
                metrics.pending_grant_wait_ns =
                    metrics.pending_grant_wait_ns.saturating_add(waited);
            }
        }
    }
}
struct Connection {
    observation: Option<ConnectionObservation>,
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
fn read_available_observed(
    socket: &mut TcpStream,
    bytes: &mut Vec<u8>,
    expected: usize,
    observation: Option<&ConnectionObservation>,
    phase: usize,
) -> Result<bool> {
    let before = bytes.len();
    let result = read_available(socket, bytes, expected);
    if let Some(record) = observation {
        record.frame(phase, bytes.len() - before, 0, matches!(&result, Ok(true)));
    }
    result
}
fn write_available_observed(
    socket: &mut TcpStream,
    bytes: &[u8],
    cursor: &mut usize,
    observation: Option<&ConnectionObservation>,
    phase: usize,
) -> Result<bool> {
    let before = *cursor;
    let result = write_available(socket, bytes, cursor);
    if let Some(record) = observation {
        record.frame(phase, 0, *cursor - before, matches!(&result, Ok(true)));
    }
    result
}
// A full channel retains this already paid request in its bounded connection.
// Existing body/lane permits own every pending task. Reactor iteration order is
// connection ID order. Retries preserve the original work and overall deadlines.
fn enqueue_paid_task(
    task: Task,
    sender: &mpsc::SyncSender<Task>,
    metrics: &Mutex<PublicMetrics>,
) -> Result<Stage> {
    let waited = elapsed_ns(task.ready_at);
    let backpressure_seen = task.backpressure_seen;
    match sender.try_send(task) {
        Ok(()) => {
            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
            m.tasks_enqueued += 1;
            m.queue_wait_ns = m.queue_wait_ns.saturating_add(waited);
            m.enqueued_after_backpressure += u64::from(backpressure_seen);
            Ok(Stage::Await)
        }
        Err(TrySendError::Full(mut task)) => {
            task.backpressure_seen = true;
            metrics
                .lock()
                .map_err(|_| "PUBLIC_METRICS")?
                .queue_backpressure_events += 1;
            Ok(Stage::Enqueue(Box::new(task)))
        }
        Err(TrySendError::Disconnected(_)) => Err("PUBLIC_QUEUE_CLOSED".into()),
    }
}
fn caller_write_half_alive(
    socket: &TcpStream,
    cancelled: &AtomicBool,
    metrics: &Mutex<PublicMetrics>,
) -> Result<()> {
    if !caller_write_half_open(socket)? {
        metrics
            .lock()
            .map_err(|_| "PUBLIC_METRICS")?
            .disconnected_await_requests += 1;
        cancelled.store(true, Ordering::Release);
        return Err("PUBLIC_EOF".into());
    }
    Ok(())
}
fn caller_write_half_open(socket: &TcpStream) -> Result<bool> {
    match socket.peek(&mut [0; 1]) {
        Ok(0) => Ok(false),
        Err(e)
            if !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Err(e.into())
        }
        _ => Ok(true),
    }
}
fn pending_alive(conn: &Connection, stop: &AtomicBool) -> Result<()> {
    task_alive(conn.deadline, stop, &conn.cancelled)?;
    if !caller_write_half_open(&conn.socket)? {
        conn.cancelled.store(true, Ordering::Release);
        return Err("PUBLIC_EOF".into());
    }
    Ok(())
}
fn public_dispatch(
    node: &Mutex<Node>,
    request: Request,
    deadline: Instant,
    stop: &AtomicBool,
    cancelled: &AtomicBool,
    metrics: &Mutex<PublicMetrics>,
    observation: (Option<&TaskObservation>, Option<&MutationCpuMeasurement>),
) -> Result<Value> {
    let (observation, mutation_cpu) = observation;
    let mut progress = |steps: u64| {
        task_alive(deadline, stop, cancelled)?;
        ensure(steps <= MAX_HISTORY_STEPS, "PUBLIC_HISTORY_STEPS")
    };
    match request {
        Request::Submit { packet } => super::dispatch_shared_with(
            node,
            NativeRequest::Submit { packet },
            &mut progress,
            |packet| {
                // The context check may have waited for the only Node owner.
                // An abandoned caller must not start a fresh full work replay.
                task_alive(deadline, stop, cancelled)?;
                let cpu = (observation.is_some() || mutation_cpu.is_some())
                    .then(ThreadCpuStamp::start)
                    .flatten();
                if let Some(charge) = mutation_cpu {
                    if cpu.is_none() {
                        charge.unavailable.set(true);
                        return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
                    }
                }
                let start = Instant::now();
                metrics.lock().map_err(|_| "PUBLIC_METRICS")?.work_started += 1;
                if let Some(record) = observation {
                    record.work_started();
                }
                let result = WorkCheckedPacket::verify_with_progress(packet, &mut |_| {
                    task_alive(deadline, stop, cancelled)
                });
                let cpu = cpu.and_then(ThreadCpuStamp::finish);
                if let Some(charge) = mutation_cpu {
                    charge.full_work_ns.set(cpu);
                    charge.unavailable.set(cpu.is_none());
                }
                if let Some(record) = observation {
                    record.work_finished(cpu, result.is_ok());
                }
                let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                m.work_ns = m.work_ns.saturating_add(elapsed_ns(start));
                m.work_finished += 1;
                if result.is_err() {
                    m.work_failed += 1;
                }
                result
            },
        ),
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
        Request::PoolSubmitBundle {
            pool_context,
            transactions,
        } => {
            progress(0)?;
            let mut owner = lock_owner(node, &mut progress)?;
            let snapshot = owner.pool_status_snapshot()?;
            ensure(pool_context == snapshot.context, "PUBLIC_POOL_CONTEXT")?;
            // The canonical body guard already capped the vector before serde allocation.
            let raws = transactions
                .iter()
                .map(|text| hex::decode(text).map_err(|_| "PUBLIC_POOL_RAW".into()))
                .collect::<Result<Vec<_>>>()?;
            // Check again before starting the nonpreemptive mutable native stage.
            progress(0)?;
            let start = Instant::now();
            metrics
                .lock()
                .map_err(|_| "PUBLIC_METRICS")?
                .pool_submit_started += 1;
            let outcome = owner.pool_submit_bundle(raws);
            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
            m.pool_submit_finished += 1;
            m.pool_submit_ns = m.pool_submit_ns.saturating_add(elapsed_ns(start));
            if outcome.is_err() {
                m.pool_submit_failed += 1;
            }
            drop(m);
            let receipt = outcome?;
            Ok(
                json!({"pool_context":pool_context,"receipt":receipt,"adoption_authority":false,
                "reward_authority":false,"exact_inclusion_proof":false,"public_network_ready":false}),
            )
        }
        Request::PoolStatus => {
            let owner = lock_owner(node, &mut progress)?;
            let snapshot = owner.pool_status_snapshot()?;
            ensure(
                snapshot.groups.len() <= 256
                    && snapshot.retained_records <= 256
                    && snapshot.retained_bytes <= 524288,
                "PUBLIC_POOL_SNAPSHOT_BOUND",
            )?;
            let mut counts = [0usize; 4];
            for group in &snapshot.groups {
                ensure(
                    group.reason.len() <= 128 && group.digests.len() <= 16,
                    "PUBLIC_POOL_SNAPSHOT_BOUND",
                )?;
                let index = match group.state {
                    crate::PoolState::Queued => 0,
                    crate::PoolState::SequenceConsumed => 1,
                    crate::PoolState::Expired => 2,
                    crate::PoolState::Blocked => 3,
                };
                counts[index] += 1;
            }
            progress(0)?;
            Ok(
                json!({"schema":"public-pool-scalar-snapshot-v3","profile":snapshot.profile,"context":snapshot.context,
                "parent":snapshot.parent,"generation":snapshot.generation,"checked_parent":snapshot.checked_parent,
                "checked_generation":snapshot.checked_generation,"classification_current":snapshot.classification_current,
                "retained_records":snapshot.retained_records,"retained_bytes":snapshot.retained_bytes,
                "local_removals":snapshot.local_removals,"gc":snapshot.gc,"queued_groups":counts[0],"sequence_consumed_groups":counts[1],
                "expired_groups":counts[2],"blocked_groups":counts[3],
                "classification_scope":"last local branch-relative classification; sequence consumed is not exact inclusion",
                "snapshot_does_not_reconcile":true,"adoption_authority":false,"reward_authority":false,
                "exact_inclusion_proof":false,"public_network_ready":false}),
            )
        }
    }
}

/// Dedicated successor. No authentication roster or durable guest operation table.
/// A finite engineering service; global saturation can still deny honest callers.
pub fn serve_public_protected_v3(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
) -> Result<PublicMetrics> {
    serve_public_protected_v3_with_metrics(
        listener,
        node,
        lifetime,
        stop,
        server,
        Arc::new(Mutex::new(PublicMetrics::default())),
    )
}

/// Trusted local observer only. Holding or modifying its mutex can affect this
/// process; these counters never authorize a guest or prove an economic bound.
pub fn serve_public_protected_v3_with_metrics(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
    metrics: Arc<Mutex<PublicMetrics>>,
) -> Result<PublicMetrics> {
    serve_public_protected_v3_inner(listener, node, lifetime, stop, server, (metrics, None))
}

/// Optional trusted local measurements, bounded by observer capacity. Never guest
/// authority. Default service paths do not allocate optional records. R5 mutation
/// admission uses mandatory checked thread clocks independently of capture.
pub fn serve_public_protected_v3_with_request_observer(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
    metrics: Arc<Mutex<PublicMetrics>>,
    observer: PublicRequestObserver,
) -> Result<PublicMetrics> {
    serve_public_protected_v3_inner(
        listener,
        node,
        lifetime,
        stop,
        server,
        (metrics, Some(observer)),
    )
}

fn serve_public_protected_v3_inner(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PublicServer,
    observations: (Arc<Mutex<PublicMetrics>>, Option<PublicRequestObserver>),
) -> Result<PublicMetrics> {
    let (metrics, observer) = observations;
    ensure(
        lifetime > Duration::ZERO && lifetime <= Duration::from_secs(MAX_SERVICE_SECONDS),
        "PUBLIC_LIFETIME",
    )?;
    listener.set_nonblocking(true)?;
    let startup_deadline = Instant::now() + Duration::from_millis(WORK_MS);
    let settings = {
        let mut progress = |_: u64| {
            ensure(
                !stop.load(Ordering::Acquire) && Instant::now() < startup_deadline,
                "PUBLIC_STARTUP_DEADLINE",
            )
        };
        let owner = lock_owner(&node, &mut progress)?;
        owner.pool_status_snapshot()?; // Explicit operator enable is required; never enable from the guest listener.
        progress(0)?;
        owner.settings().clone()
    };
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
    let mut next_pending_order = 0u64;
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
                            let response_max = response_maximum(task.cookie.op);
                            let permit = BufferPermit::acquire(
                                output_pool.clone(),
                                response_max * 4,
                                if matches!(task.cookie.op, 2 | 5) {
                                    MAX_OUTPUT_BYTES
                                } else {
                                    MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE
                                },
                            );
                            let (permit, outcome) = match permit {
                                Ok(permit) => {
                                    let cpu_permit = if mutating_operation(task.cookie.op) {
                                        PaidMutationCpuPermit::acquire(server, &metrics).map(Some)
                                    } else {
                                        Ok(None)
                                    };
                                    let outcome = match cpu_permit {
                                        Err(e) => Err(e),
                                        Ok(cpu_permit) => {
                                            if let Some(record) = &task.observation {
                                                record.dispatch_started();
                                            }
                                            let cpu = if cpu_permit.is_none() {
                                                task.observation
                                                    .as_ref()
                                                    .and_then(|_| ThreadCpuStamp::start())
                                            } else {
                                                None
                                            };
                                            let measurement = MutationCpuMeasurement::default();
                                            let outcome = public_dispatch(
                                                &node,
                                                task.request,
                                                task.deadline,
                                                &stop,
                                                &task.cancelled,
                                                &metrics,
                                                (
                                                    task.observation.as_ref(),
                                                    cpu_permit.as_ref().map(|_| &measurement),
                                                ),
                                            );
                                            let cpu = match cpu_permit {
                                                Some(permit) => {
                                                    permit.finish(&measurement, server, &metrics)
                                                }
                                                None => cpu.and_then(ThreadCpuStamp::finish),
                                            };
                                            if let Some(record) = &task.observation {
                                                record.dispatch_finished(cpu, outcome.is_ok());
                                            }
                                            outcome
                                        }
                                    };
                                    // Accounting failure after native dispatch never rewrites outcome.
                                    (Some(permit), outcome)
                                }
                                Err(e) => (None, Err(e)),
                            };
                            let reserved = *output_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            m.peak_output_reserved_bytes =
                                m.peak_output_reserved_bytes.max(reserved);
                            if outcome.is_ok() {
                                if mutating_operation(task.cookie.op) {
                                    if task.cookie.op == 4 {
                                        m.completed_pool_submit += 1;
                                    } else {
                                        m.completed_submit += 1;
                                    }
                                } else {
                                    if task.cookie.op == 5 {
                                        m.completed_pool_status += 1;
                                    } else {
                                        m.completed_read += 1;
                                    }
                                }
                            } else if mutating_operation(task.cookie.op) {
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
                            let observation = observer
                                .as_ref()
                                .and_then(PublicRequestObserver::connection);
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            m.accepted_connections += 1;
                            if connections.len() >= MAX_CONNECTIONS {
                                m.capacity_refusals += 1;
                                if let Some(record) = &observation {
                                    record.terminal("capacity");
                                }
                                continue;
                            }
                            socket.set_nonblocking(true)?;
                            socket.set_nodelay(true)?;
                            next_id = next_id.checked_add(1).ok_or("PUBLIC_CONNECTION_ID")?;
                            if let Some(record) = &observation {
                                record.identity(next_id);
                            }
                            connections.insert(
                                next_id,
                                Connection {
                                    observation,
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
                                        if let Some(record) = &conn.observation {
                                            record.terminal("serialization");
                                        }
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
                let heads = PendingHeads::collect(&connections, Instant::now());
                let mut remove = Vec::new();
                for (id, conn) in &mut connections {
                    if Instant::now() >= conn.deadline {
                        let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                        m.expired_connections += 1;
                        close_pending(&mut m, conn.stage.pending());
                        *m.expired_phase_counts
                            .entry(conn.stage.phase().into())
                            .or_default() += 1;
                        if let Some(record) = &conn.observation {
                            record.terminal(conn.stage.phase());
                        }
                        remove.push(*id);
                        continue;
                    }
                    let current = std::mem::replace(&mut conn.stage, Stage::Await);
                    let phase = current.phase();
                    let pending_before = current.pending();
                    let advanced = (|| -> Result<Stage> {
                        match current {
                            Stage::Hello(mut bytes) => {
                                if !read_available_observed(
                                    &mut conn.socket,
                                    &mut bytes,
                                    HELLO_BYTES,
                                    conn.observation.as_ref(),
                                    0,
                                )? {
                                    return Ok(Stage::Hello(bytes));
                                }
                                let hello = Hello::parse(&bytes)?;
                                if let Some(record) = &conn.observation {
                                    record.request(hello.op, hello.digest);
                                }
                                let pending = PendingOrder::next(&mut next_pending_order)?;
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .pending_challenge_entered += 1;
                                Ok(Stage::WaitChallenge { hello, pending })
                            }
                            Stage::WaitChallenge { hello, pending } => {
                                pending_alive(conn, &stop)?;
                                if !heads.is_head(PendingKind::Challenge, hello.op, *id)
                                    || challenge_tokens == 0
                                    || (mutating_operation(hello.op)
                                        && challenge_tokens <= READ_CHALLENGE_RESERVE)
                                {
                                    return Ok(Stage::WaitChallenge { hello, pending });
                                }
                                challenge_tokens -= 1;
                                let cookie = server.cookie(&settings, hello, conn.peer)?;
                                let frame = framed(serde_json::to_vec(&cookie)?, 2048)?;
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .issued_challenges += 1;
                                {
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    m.pending_challenge_granted += 1;
                                    m.pending_challenge_wait_ns = m
                                        .pending_challenge_wait_ns
                                        .saturating_add(elapsed_ns(pending.entered_at));
                                }
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
                                if write_available_observed(
                                    &mut conn.socket,
                                    &bytes,
                                    &mut cursor,
                                    conn.observation.as_ref(),
                                    1,
                                )? {
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
                                if !read_available_observed(
                                    &mut conn.socket,
                                    &mut bytes,
                                    SOLUTION_BYTES,
                                    conn.observation.as_ref(),
                                    2,
                                )? {
                                    return Ok(Stage::Solution { cookie, bytes });
                                }
                                server.validate(&cookie, &settings, true)?;
                                ensure(
                                    bytes[..4] == *b"PPS3" && bytes[4..36] == cookie.id()?,
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
                                    b"public-caller-sign-v3",
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
                                    if e.to_string() == "PUBLIC_TICKET_REPLAY" {
                                        m.replay_refusals += 1;
                                    } else {
                                        m.spent_capacity_refusals += 1;
                                    }
                                    return Err(e);
                                }
                                {
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    m.peak_spent = m.peak_spent.max(spent.rows.len());
                                    m.spent_reservations += 1;
                                }
                                let pending = PendingOrder::next(&mut next_pending_order)?;
                                metrics
                                    .lock()
                                    .map_err(|_| "PUBLIC_METRICS")?
                                    .pending_grant_entered += 1;
                                Ok(Stage::WaitGrant { cookie, pending })
                            }
                            Stage::WaitGrant { cookie, pending } => {
                                pending_alive(conn, &stop)?;
                                if !heads.is_head(PendingKind::Grant, cookie.op, *id) {
                                    return Ok(Stage::WaitGrant { cookie, pending });
                                }
                                // This private stage already validated the immutable cookie,
                                // target, signature and spent id once. Only the original
                                // absolute expiry is checked again; polling does no crypto.
                                ensure(
                                    server.tick()? < cookie.expires_tick_ms,
                                    "PUBLIC_COOKIE_EXPIRED",
                                )?;
                                let Some((lane, permit)) = try_paid_permits(
                                    &cookie,
                                    &mutating_grants,
                                    &read_grants,
                                    &body_pool,
                                )?
                                else {
                                    return Ok(Stage::WaitGrant { cookie, pending });
                                };
                                let frame = framed(
                                    serde_json::to_vec(
                                        &json!({"schema":"public-body-ready-v3","cookie_digest":hex::encode(cookie.id()?)}),
                                    )?,
                                    256,
                                )?;
                                pending_alive(conn, &stop)?;
                                conn.permit = Some(permit);
                                conn.lane_permit = Some(Arc::new(lane));
                                {
                                    let used =
                                        *body_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                                    let grant_pool = if mutating_operation(cookie.op) {
                                        &mutating_grants
                                    } else {
                                        &read_grants
                                    };
                                    let grants =
                                        *grant_pool.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
                                    let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                                    m.peak_paid_body_bytes = m.peak_paid_body_bytes.max(used);
                                    if mutating_operation(cookie.op) {
                                        m.peak_mutating_grants = m.peak_mutating_grants.max(grants);
                                    } else {
                                        m.peak_read_grants = m.peak_read_grants.max(grants);
                                    }
                                    m.pending_grant_granted += 1;
                                    m.pending_grant_wait_ns = m
                                        .pending_grant_wait_ns
                                        .saturating_add(elapsed_ns(pending.entered_at));
                                }
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
                                if write_available_observed(
                                    &mut conn.socket,
                                    &bytes,
                                    &mut cursor,
                                    conn.observation.as_ref(),
                                    3,
                                )? {
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
                                let complete = read_available_observed(
                                    &mut conn.socket,
                                    &mut bytes,
                                    cookie.body_len as usize,
                                    conn.observation.as_ref(),
                                    4,
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
                                        == hex::encode(hash(b"public-request-body-v3", &[&bytes])),
                                    "PUBLIC_BODY_DIGEST",
                                )?;
                                let request = canonical_request(&bytes, cookie.op)?;
                                server.validate(&cookie, &settings, false)?;
                                let ready_at = Instant::now();
                                let task = Task {
                                    observation: conn
                                        .observation
                                        .as_ref()
                                        .map(ConnectionObservation::task),
                                    _permit: conn.permit.take().ok_or("PUBLIC_BODY_PERMIT")?,
                                    _lane_permit: conn
                                        .lane_permit
                                        .as_ref()
                                        .ok_or("PUBLIC_LANE_PERMIT")?
                                        .clone(),
                                    id: conn.id,
                                    cookie,
                                    request,
                                    ready_at,
                                    backpressure_seen: false,
                                    deadline: conn
                                        .total_deadline
                                        .min(ready_at + Duration::from_millis(WORK_MS)),
                                    cancelled: conn.cancelled.clone(),
                                };
                                conn.deadline = task.deadline;
                                Ok(Stage::Enqueue(Box::new(task)))
                            }
                            Stage::Enqueue(task) => {
                                task_alive(task.deadline, &stop, &task.cancelled)?;
                                if let Err(error) =
                                    caller_write_half_alive(&conn.socket, &conn.cancelled, &metrics)
                                {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .disconnected_before_enqueue += 1;
                                    return Err(error);
                                }
                                let sender = if mutating_operation(task.cookie.op) {
                                    &proof_tx
                                } else {
                                    &read_tx
                                };
                                enqueue_paid_task(*task, sender, &metrics)
                            }
                            Stage::Await => {
                                // R2 requires the caller's write half to remain open
                                // until the response. TCP cannot distinguish a full
                                // close from shutdown(Write): either EOF cancels
                                // queued/owner-waiting work. The ordinary client keeps
                                // both halves open. This is no ledger verdict.
                                caller_write_half_alive(&conn.socket, &conn.cancelled, &metrics)?;
                                Ok(Stage::Await)
                            }
                            Stage::Output {
                                bytes,
                                mut cursor,
                                _permit,
                            } => {
                                let before = cursor;
                                if write_available_observed(
                                    &mut conn.socket,
                                    &bytes,
                                    &mut cursor,
                                    conn.observation.as_ref(),
                                    5,
                                )? {
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .response_bytes_written += (cursor - before) as u64;
                                    metrics
                                        .lock()
                                        .map_err(|_| "PUBLIC_METRICS")?
                                        .delivered_response_frames += 1;
                                    if let Some(record) = &conn.observation {
                                        record.terminal("response");
                                    }
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
                            if let Some(record) = &conn.observation {
                                record.terminal(phase);
                            }
                            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                            close_pending(&mut m, pending_before);
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
                let pending = connections
                    .values()
                    .filter(|conn| matches!(conn.stage, Stage::Enqueue(_)))
                    .count();
                let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                m.peak_pending_enqueue = m.peak_pending_enqueue.max(pending);
                m.peak_pending_challenge = m.peak_pending_challenge.max(
                    connections
                        .values()
                        .filter(|c| matches!(c.stage, Stage::WaitChallenge { .. }))
                        .count(),
                );
                m.peak_pending_grant = m.peak_pending_grant.max(
                    connections
                        .values()
                        .filter(|c| matches!(c.stage, Stage::WaitGrant { .. }))
                        .count(),
                );
                drop(m);
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
        for conn in connections.values() {
            let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
            close_pending(&mut m, conn.stage.pending());
            drop(m);
            if let Some(record) = &conn.observation {
                record.terminal("shutdown");
            }
        }
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
            let cpu = server
                .mutation_cpu
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
            m.mutation_cpu_in_flight_after_shutdown = cpu.in_flight;
            m.mutation_cpu_credit_ns_after_shutdown =
                u64::try_from(cpu.credit_ns.max(0)).unwrap_or(u64::MAX);
            m.mutation_cpu_debt_ns_after_shutdown =
                u64::try_from((-cpu.credit_ns).max(0)).unwrap_or(u64::MAX);
            m.mutation_cpu_unavailable_after_shutdown = cpu.unavailable;
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
/// Client-local observations, including failed calls; not admission or cost authority.
#[derive(Default, Debug, Serialize)]
pub struct PublicClientMetrics {
    pub construction_ns: u64,
    pub challenge_ns: u64,
    pub solution_search_ns: u64,
    pub solution_trials: u64,
    pub solution_found: bool,
    pub solution_body_response_ns: u64,
    pub total_elapsed_ns: u64,
    pub failed_stage: Option<&'static str>,
}
/// Wire and signed profile are identical to the ordinary client. The observation
/// reports elapsed stage time, never an adversarial cost bound or server CPU time.
pub fn call_public_protected_v3(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
) -> Result<PublicReply> {
    call_public_protected_v3_with_metrics(address, request, settings, pinned_server, caller, policy)
        .0
}
pub fn call_public_protected_v3_with_metrics(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
) -> (Result<PublicReply>, PublicClientMetrics) {
    call_public_protected_v3_with_deadline(
        address,
        request,
        settings,
        pinned_server,
        caller,
        policy,
        None,
    )
}

/// Optional caller-local absolute deadline. It only shortens the existing call
/// and phase limits; it changes no signed bytes, cookie policy or server budget.
/// The ordinary client passes None and retains its original behavior.
pub fn call_public_protected_v3_with_deadline(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    outer_deadline: Option<Instant>,
) -> (Result<PublicReply>, PublicClientMetrics) {
    let call_start = Instant::now();
    let mut phase_start = call_start;
    let mut phase = "construction";
    let mut metrics = PublicClientMetrics::default();
    let result = (|| -> Result<PublicReply> {
        if let Some(deadline) = outer_deadline {
            ensure(Instant::now() < deadline, "PUBLIC_CLIENT_DEADLINE")?;
        }
        PublicPolicy::new(policy.bits, Duration::from_millis(policy.lifetime_ms))?;
        let raw = serde_json::to_vec(request)?;
        let op = request_op(request)?;
        canonical_request(&raw, op)?;
        let hello = Hello {
            op,
            len: raw.len(),
            caller: digest(caller.public_key())?,
            digest: hash(b"public-request-body-v3", &[&raw]),
            client_nonce: entropy()?,
        };
        Hello::parse(&hello.encode())?;
        metrics.construction_ns = elapsed_ns(phase_start);
        phase = "challenge";
        phase_start = Instant::now();
        let original_deadline = Instant::now() + Duration::from_millis(OVERALL_MS);
        let total_deadline = outer_deadline
            .map(|deadline| deadline.min(original_deadline))
            .unwrap_or(original_deadline);
        let connect_budget = if outer_deadline.is_some() {
            total_deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or("PUBLIC_CLIENT_DEADLINE")?
                .min(Duration::from_secs(2))
        } else {
            Duration::from_secs(2)
        };
        let mut stream = TcpStream::connect_timeout(&address, connect_budget)?;
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
        validate_challenge_context(
            &bytes,
            &cookie,
            &hello,
            settings,
            pinned_server,
            policy,
            policy.id(),
        )?;
        metrics.challenge_ns = elapsed_ns(phase_start);
        phase = "solution-search";
        phase_start = Instant::now();
        let started = Instant::now();
        let id = cookie.id()?;
        let mut solved = None;
        for nonce in 0..1_048_576u64 {
            if nonce % 256 == 0 {
                if outer_deadline.is_some() {
                    ensure(Instant::now() < total_deadline, "PUBLIC_CLIENT_DEADLINE")?;
                }
                ensure(
                    started.elapsed() < Duration::from_millis(policy.lifetime_ms),
                    "PUBLIC_SOLVE_EXPIRED",
                )?;
            }
            metrics.solution_trials = nonce + 1;
            if winner(id, nonce, policy.bits) {
                solved = Some(nonce);
                break;
            }
        }
        let nonce = solved.ok_or("PUBLIC_SOLVE_BUDGET")?;
        let solve_elapsed_ns = elapsed_ns(started);
        metrics.solution_search_ns = elapsed_ns(phase_start);
        metrics.solution_found = true;
        phase = "solution-body-response";
        phase_start = Instant::now();
        let mut solution = b"PPS3".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(caller.sign(&hash(
                b"public-caller-sign-v3",
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
            ready["schema"] == "public-body-ready-v3" && ready["cookie_digest"] == hex::encode(id),
            "PUBLIC_READY",
        )?;
        client_write(
            &mut stream,
            &raw,
            total_deadline.min(Instant::now() + Duration::from_millis(BODY_MS)),
        )?;
        let bytes = client_frame(
            &mut stream,
            response_maximum(op),
            total_deadline.min(Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS)),
        )?;
        let r: Response = serde_json::from_slice(&bytes)?;
        ensure(
            serde_json::to_vec(&r)? == bytes
                && r.schema == "public-protected-response-v3"
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
        if outer_deadline.is_some() {
            ensure(Instant::now() < total_deadline, "PUBLIC_CLIENT_DEADLINE")?;
        }
        metrics.solution_body_response_ns = elapsed_ns(phase_start);
        phase = "complete";
        Ok(PublicReply {
            ok: r.ok,
            value: r.value,
            solve_trials: nonce + 1,
            solve_elapsed_ns,
            body_bytes_sent: raw.len(),
            public_network_ready: false,
            identity_authority: false,
        })
    })();
    if result.is_err() {
        metrics.failed_stage = Some(phase);
        let ns = elapsed_ns(phase_start);
        match phase {
            "construction" => metrics.construction_ns = ns,
            "challenge" => metrics.challenge_ns = ns,
            "solution-search" => metrics.solution_search_ns = ns,
            "solution-body-response" => metrics.solution_body_response_ns = ns,
            _ => {}
        }
    }
    metrics.total_elapsed_ns = elapsed_ns(call_start);
    (result, metrics)
}

fn validate_challenge_context(
    raw: &[u8],
    cookie: &Cookie,
    hello: &Hello,
    settings: &Settings,
    pinned_server: &str,
    policy: PublicPolicy,
    expected_profile: Hash,
) -> Result<()> {
    ensure(
        serde_json::to_vec(cookie)? == raw
            && cookie.schema == "public-resource-cookie-v3"
            && cookie.profile == hex::encode(expected_profile)
            && cookie.network == hex::encode(settings.network())
            && cookie.parameters == hex::encode(settings.parameters())
            && cookie.genesis == hex::encode(settings.genesis())
            && cookie.server == pinned_server
            && cookie.caller == hex::encode(hello.caller)
            && cookie.op == hello.op
            && cookie.body_len as usize == hello.len
            && cookie.body_digest == hex::encode(hello.digest)
            && cookie.client_nonce == hex::encode(hello.client_nonce)
            && cookie.bits == policy.bits
            && cookie.lifetime_ms == policy.lifetime_ms
            && cookie.expires_tick_ms.checked_sub(cookie.issued_tick_ms)
                == Some(policy.lifetime_ms),
        "PUBLIC_CHALLENGE_CONTEXT",
    )?;
    verify_hex_strict(pinned_server, &cookie.server_message()?, &cookie.signature)
        .map_err(|_| "PUBLIC_CHALLENGE_SIGNATURE".into())
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
    fn shared(mut node: Node) -> Arc<Mutex<Node>> {
        node.enable_local_mempool(crate::PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: crate::development_public(0).unwrap(),
        })
        .unwrap();
        Arc::new(Mutex::new(node))
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
    // Real authenticated ticket exchange. Returning before the body lets these
    // socket tests hold a bounded grant without invoking any fake work verifier.
    fn paid_grant(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<TcpStream> {
        paid_grant_counted(address, hello, caller, policy).map(|(socket, _)| socket)
    }
    fn paid_grant_counted(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<(TcpStream, [usize; 2])> {
        let (mut socket, cookie, challenge_bytes, deadline) =
            paid_solution_only(address, hello, caller, policy)?;
        let id = cookie.id()?;
        let ready_raw = client_frame(&mut socket, 256, deadline)?;
        let ready: Value = serde_json::from_slice(&ready_raw)?;
        ensure(
            ready["schema"] == "public-body-ready-v3" && ready["cookie_digest"] == hex::encode(id),
            "TEST_READY",
        )?;
        Ok((socket, [challenge_bytes, 4 + ready_raw.len()]))
    }
    fn paid_solution_only(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<(TcpStream, Cookie, usize, Instant)> {
        let mut socket = TcpStream::connect(address)?;
        socket.set_nodelay(true)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        client_write(&mut socket, &hello.encode(), deadline)?;
        let raw = client_frame(&mut socket, 2048, deadline)?;
        let challenge_bytes = 4 + raw.len();
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
        let mut solution = b"PPS3".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(caller.sign(&hash(
                b"public-caller-sign-v3",
                &[&id, &nonce.to_le_bytes()],
            ))?)
            .map_err(|_| "TEST_CALLER_SIGNATURE")?,
        );
        client_write(&mut socket, &solution, deadline)?;
        Ok((socket, cookie, challenge_bytes, deadline))
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
    fn request_observer_matches_independent_client_received_signed_frame_lengths() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner = shared(Node::open(directory.path(), settings, 1).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let observer = PublicRequestObserver::new(1).unwrap();
        let records = observer.clone();
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                Arc::new(Mutex::new(PublicMetrics::default())),
                records,
            )
            .unwrap()
        });
        let raw = serde_json::to_vec(&Request::Head).unwrap();
        let mut h = hello(2, raw.len());
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let (mut socket, sizes) = paid_grant_counted(address, h, &identity(72), policy).unwrap();
        client_write(&mut socket, &raw, Instant::now() + Duration::from_secs(2)).unwrap();
        let response_raw =
            client_frame(&mut socket, 16384, Instant::now() + Duration::from_secs(2)).unwrap();
        let response: Response = serde_json::from_slice(&response_raw).unwrap();
        assert!(response.ok);
        verify_hex_strict(
            identity(71).public_key(),
            &response.message().unwrap(),
            &response.signature,
        )
        .unwrap();
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert!(row.complete && row.frames.iter().all(|frame| frame.complete));
        assert_eq!(row.frames[1].bytes_written, sizes[0] as u64);
        assert_eq!(row.frames[3].bytes_written, sizes[1] as u64);
        assert_eq!(row.frames[5].bytes_written, (4 + response_raw.len()) as u64);
        assert_eq!(
            row.application_bytes_read,
            Some((HELLO_BYTES + SOLUTION_BYTES + raw.len()) as u64)
        );
        assert_eq!(
            row.application_bytes_written,
            Some((sizes[0] + sizes[1] + 4 + response_raw.len()) as u64)
        );
    }
    #[test]
    fn request_observer_records_actual_partial_read_eof_and_quantum_writes() {
        use std::net::Shutdown;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let observer = PublicRequestObserver::new(1).unwrap();
        let record = observer.connection().unwrap();
        client.write_all(&[1, 2, 3, 4, 5]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        assert!(
            !read_available_observed(&mut socket, &mut bytes, HELLO_BYTES, Some(&record), 0)
                .unwrap()
        );
        assert!(
            read_available_observed(&mut socket, &mut bytes, HELLO_BYTES, Some(&record), 0)
                .is_err()
        );
        assert_eq!(bytes, [1, 2, 3, 4, 5]);
        let output = vec![9; IO_QUANTUM + 17];
        let mut cursor = 0;
        assert!(
            !write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        assert_eq!(cursor, IO_QUANTUM);
        let mut received = vec![0; IO_QUANTUM];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, output[..IO_QUANTUM]);
        assert!(
            write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        let mut tail = [0; 17];
        client.read_exact(&mut tail).unwrap();
        assert_eq!(tail, [9; 17]);
        record.terminal("hello");
        drop(record);
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert_eq!(row.frames[0].bytes_read, 5);
        assert!(!row.frames[0].complete);
        assert_eq!(row.frames[5].bytes_written, output.len() as u64);
        assert!(row.frames[5].complete && row.response_frame_complete && row.complete);
        assert_eq!(row.application_bytes_read, Some(5));
        assert_eq!(row.application_bytes_written, Some(output.len() as u64));
        assert_eq!(row.dispatch_thread_cpu_ns, None);
        assert_eq!(row.full_work_thread_cpu_ns, None);
    }
    #[test]
    fn request_observer_retains_partial_output_bytes_after_actual_write_error() {
        use std::net::Shutdown;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let observer = PublicRequestObserver::new(1).unwrap();
        let record = observer.connection().unwrap();
        let output = vec![7; IO_QUANTUM + 17];
        let mut cursor = 0;
        assert!(
            !write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        let mut received = vec![0; IO_QUANTUM];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, output[..IO_QUANTUM]);
        socket.shutdown(Shutdown::Write).unwrap();
        assert!(
            write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).is_err()
        );
        assert_eq!(cursor, IO_QUANTUM);
        record.terminal("output");
        drop(record);
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert!(row.complete && !row.response_frame_complete);
        assert_eq!(row.frames[5].bytes_written, IO_QUANTUM as u64);
        assert_eq!(row.application_bytes_written, Some(IO_QUANTUM as u64));
        assert!(!row.frames[5].complete);
        assert_eq!(row.physical_network_bytes, None);
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
            serve_public_protected_v3_with_metrics(
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
        let reply = call_public_protected_v3(
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
        assert_eq!(m.paid_body_capacity_refusals, 0);
        assert_eq!(m.pending_grant_closed, 1);
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
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
            serve_public_protected_v3_with_metrics(
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
        let reply = call_public_protected_v3(
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
        let reply = call_public_protected_v3(
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
        assert_eq!(m.lane_capacity_refusals, 0);
        assert_eq!(m.pending_grant_closed, 1);
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
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
            serve_public_protected_v3_with_metrics(
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
            call_public_protected_v3(
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
        h.digest = hash(b"public-request-body-v3", &[&raw]);
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
        let reply = call_public_protected_v3(
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
    fn disconnecting_paid_requests_waiting_for_queue_cancels_without_starting_work() {
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
            serve_public_protected_v3_with_metrics(
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
            call_public_protected_v3(
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
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let mut sockets = Vec::new();
        for _ in 0..8 {
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        // Initial Head was one task. Two Submit workers are waiting for this
        // actual owner lock, leaving two in the channel and four inside bounded pending connections.
        wait_metric(&metrics, |m| {
            m.tasks_enqueued == 5 && m.tasks_dequeued == 3 && m.peak_pending_enqueue == 4
        });
        sockets[0].shutdown(std::net::Shutdown::Write).unwrap();
        for socket in &sockets[1..] {
            socket.shutdown(std::net::Shutdown::Both).unwrap();
        }
        wait_metric(&metrics, |m| m.disconnected_await_requests == 8);
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
        wait_metric(&metrics, |m| m.abandoned_tasks == 4);
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        assert_eq!(owner.lock().unwrap().active().unwrap(), before);
        let reply = call_public_protected_v3(
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
        assert_eq!(m.disconnected_await_requests, 8);
        assert_eq!(m.disconnected_before_enqueue, 4);
        assert_eq!(m.abandoned_tasks, 4);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn eight_paid_submits_wait_for_full_queue_without_losing_body_or_absolute_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let parent = source.active().unwrap().0;
        let packets: Vec<_> = (0..MAX_MUTATING_GRANTS)
            .map(|index| {
                source
                    .make(
                        parent,
                        vec![],
                        crate::development_public(index as u64).unwrap(),
                        clock - 50,
                        4096,
                    )
                    .unwrap()
            })
            .collect();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(12),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v3(
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
        let mut sockets = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            let raw = serde_json::to_vec(&Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            })
            .unwrap();
            let caller = identity(80 + index as u8);
            let mut h = hello(1, raw.len());
            h.caller = digest(caller.public_key()).unwrap();
            h.digest = hash(b"public-request-body-v3", &[&raw]);
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        wait_metric(&metrics, |m| {
            m.tasks_enqueued == 5
                && m.tasks_dequeued == 3
                && m.peak_pending_enqueue == 4
                && m.queue_backpressure_events >= 4
        });
        // The two workers and two channel slots are occupied. Four complete paid
        // requests retain their permits inside bounded connections, not a new queue.
        assert_eq!(metrics.lock().unwrap().queue_refusals, 0);
        drop(locked);
        for (socket, packet) in sockets.iter_mut().zip(&packets) {
            let bytes = client_frame(
                socket,
                MAX_RESPONSE,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            let response: Response = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response.profile, hex::encode(policy.id()));
            verify_hex_strict(
                identity(71).public_key(),
                &response.message().unwrap(),
                &response.signature,
            )
            .unwrap();
            assert!(response.ok, "{}", response.value);
            assert_eq!(response.value["block"], hex::encode(packet.id().unwrap()));
        }
        drop(sockets);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.work_started, 8);
        assert_eq!(m.work_finished, 8);
        assert_eq!(m.work_failed, 0);
        assert_eq!(m.completed_submit, 8);
        assert_eq!(m.queue_refusals, 0);
        assert_eq!(m.enqueued_after_backpressure, 4);
        assert!(m.queue_wait_ns > 0);
        assert_eq!(m.peak_mutating_grants, MAX_MUTATING_GRANTS);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn queue_backpressure_preserves_deadline_and_releases_permits_on_drop() {
        let settings = Settings::development(Some(1)).unwrap();
        let server = server();
        let cookie = server
            .cookie(&settings, hello(2, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let body_pool = Arc::new(Mutex::new(0));
        let lane_pool = Arc::new(Mutex::new(0));
        let metrics = Mutex::new(PublicMetrics::default());
        let (sender, receiver) = mpsc::sync_channel(2);
        let ready_at = Instant::now();
        let deadline = ready_at + Duration::from_millis(WORK_MS);
        let make_task = |id| Task {
            observation: None,
            _permit: BufferPermit::acquire(body_pool.clone(), 3, MAX_PAID_BODY_BYTES).unwrap(),
            _lane_permit: Arc::new(
                BufferPermit::acquire(lane_pool.clone(), 1, MAX_READ_GRANTS).unwrap(),
            ),
            id,
            cookie: cookie.clone(),
            request: Request::Head,
            ready_at,
            backpressure_seen: false,
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        assert!(matches!(
            enqueue_paid_task(make_task(1), &sender, &metrics).unwrap(),
            Stage::Await
        ));
        assert!(matches!(
            enqueue_paid_task(make_task(2), &sender, &metrics).unwrap(),
            Stage::Await
        ));
        let mut task = make_task(3);
        for _ in 0..4 {
            let Stage::Enqueue(pending) = enqueue_paid_task(task, &sender, &metrics).unwrap()
            else {
                panic!("full channel must retain paid task");
            };
            assert_eq!(pending.deadline, deadline);
            assert_eq!(pending.ready_at, ready_at);
            assert!(pending.backpressure_seen);
            assert_eq!(*body_pool.lock().unwrap(), 9);
            assert_eq!(*lane_pool.lock().unwrap(), 3);
            task = *pending;
        }
        drop(task);
        assert_eq!(*body_pool.lock().unwrap(), 6);
        assert_eq!(*lane_pool.lock().unwrap(), 2);
        drop(receiver.try_recv().unwrap());
        drop(receiver.try_recv().unwrap());
        assert_eq!(*body_pool.lock().unwrap(), 0);
        assert_eq!(*lane_pool.lock().unwrap(), 0);
        assert_eq!(metrics.lock().unwrap().queue_backpressure_events, 4);
        assert_eq!(metrics.lock().unwrap().queue_refusals, 0);
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
            serve_public_protected_v3_with_metrics(
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
            call_public_protected_v3(
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
        assert_eq!(m.mutation_cpu_reservations, 2);
        assert!(m.mutation_full_work_cpu_ns > 0);
        assert_eq!(
            m.mutation_full_work_cpu_ns + m.mutation_dispatch_excluding_work_cpu_ns,
            m.mutation_cpu_charged_ns
        );
        assert!(m.mutation_cpu_charged_ns > 0);
    }

    #[test]
    fn abandoned_public_work_preserves_cancel_then_deadline_order_without_admission() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let node = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        let owner = Mutex::new(node);
        let before = owner.lock().unwrap().stats().unwrap();
        for (cancelled_value, stop_value, expired, expected) in [
            (true, true, true, "PUBLIC_REQUEST_CANCELLED"),
            (false, true, false, "PUBLIC_REQUEST_DEADLINE"),
            (false, false, true, "PUBLIC_REQUEST_DEADLINE"),
        ] {
            let metrics = Mutex::new(PublicMetrics::default());
            let deadline = if expired {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(10)
            };
            let error = public_dispatch(
                &owner,
                Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                deadline,
                &AtomicBool::new(stop_value),
                &AtomicBool::new(cancelled_value),
                &metrics,
                (None, None),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(metrics.lock().unwrap().work_started, 0);
            assert_eq!(owner.lock().unwrap().stats().unwrap(), before);
        }
    }
    #[test]
    fn cpu_budget_reserves_two_starts_and_carries_actual_debt_before_refill() {
        let mut b = PaidMutationCpuBudget::new();
        let now = b.updated;
        b.reserve(now).unwrap();
        b.reserve(now).unwrap();
        assert_eq!(
            b.reserve(now).unwrap_err().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        // Nonpreemptive execution can exceed its start reservation; debit actual CPU.
        b.settle(now, Some(MUTATION_CPU_BURST_NS + 1_000_000_000));
        b.settle(now, Some(1_000_000_000));
        assert_eq!(b.in_flight, 0);
        assert_eq!(b.credit_ns, -2_000_000_000);
        assert!(b.reserve(now + Duration::from_secs(8)).is_err());
        b.reserve(now + Duration::from_secs(9)).unwrap();
        b.settle(now + Duration::from_secs(9), Some(0));
        assert_eq!(b.credit_ns, 250_000_000);
        b.refill(now + Duration::from_secs(100));
        assert_eq!(b.credit_ns, i128::from(MUTATION_CPU_BURST_NS));
        b.reserve(now + Duration::from_secs(100)).unwrap();
        b.refill(now + Duration::from_secs(200));
        assert_eq!(
            b.credit_ns + i128::from(MUTATION_CPU_START_RESERVE_NS),
            i128::from(MUTATION_CPU_BURST_NS)
        );
    }
    #[test]
    fn cpu_budget_missing_measurement_or_dropped_permit_disables_future_starts() {
        let mut budget = PaidMutationCpuBudget::new();
        let now = budget.updated;
        budget.reserve(now).unwrap();
        budget.settle(now, None);
        assert_eq!(budget.in_flight, 0);
        assert_eq!(
            budget
                .reserve(now + Duration::from_secs(100))
                .unwrap_err()
                .to_string(),
            "PUBLIC_MUTATION_CPU_UNAVAILABLE"
        );
        let server = server();
        let metrics = Mutex::new(PublicMetrics::default());
        let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
        drop(permit);
        let b = server.mutation_cpu.lock().unwrap();
        assert!(b.unavailable);
        assert_eq!(b.in_flight, 0);
    }
    #[test]
    fn cpu_budget_signed_native_success_survives_clock_failure_and_reads_survive_debt() {
        // Both cases use actual producer proof and native state admission; fault only the clock.
        for fail_at_finish in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let clock = super::super::now().unwrap();
            let settings = Settings::development(Some(clock - 100)).unwrap();
            let native = Node::open(directory.path(), settings.clone(), 2).unwrap();
            let packet = native
                .make(
                    native.active().unwrap().0,
                    vec![],
                    crate::development_public(0).unwrap(),
                    clock - 50,
                    4096,
                )
                .unwrap();
            let owner = shared(native);
            let before = owner.lock().unwrap().read_active().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
            let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
            let server = PublicServer::new(identity(71), policy).unwrap();
            let budget = server.mutation_cpu.clone();
            if fail_at_finish {
                server.fail_next_cpu_finish.store(true, Ordering::Release);
            }
            let (node, signal, counters) = (owner.clone(), stop.clone(), metrics.clone());
            let worker = thread::spawn(move || {
                serve_public_protected_v3_with_metrics(
                    listener,
                    node,
                    Duration::from_secs(8),
                    signal,
                    server,
                    counters,
                )
                .unwrap()
            });
            let submit = Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            };
            let call = |r: &Request, caller: u8| {
                call_public_protected_v3(
                    address,
                    r,
                    &settings,
                    identity(71).public_key(),
                    &identity(caller),
                    policy,
                )
                .unwrap()
            };
            let success = call(&submit, 80);
            assert!(success.ok, "{}", success.value);
            assert_eq!(success.value["block"], hex::encode(packet.id().unwrap()));
            let installed = owner.lock().unwrap().read_active().unwrap();
            assert_ne!(installed, before);
            if !fail_at_finish {
                // Controlled exhausted local account; clock readings and native calls stay real.
                let mut b = budget.lock().unwrap();
                b.credit_ns = -10_000_000_000;
                b.updated = Instant::now();
            }
            for caller in [81, 82, 83] {
                let denied = call(&submit, caller);
                assert!(!denied.ok);
                assert_eq!(
                    denied.value["error"],
                    if fail_at_finish {
                        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
                    } else {
                        "PUBLIC_MUTATION_CPU_BUDGET"
                    }
                );
            }
            assert!(call(&Request::Head, 84).ok);
            assert!(
                call(
                    &Request::History {
                        tip: hex::encode(packet.id().unwrap()),
                        after: hex::encode(settings.genesis())
                    },
                    85
                )
                .ok
            );
            assert_eq!(owner.lock().unwrap().read_active().unwrap(), installed);
            stop.store(true, Ordering::Release);
            let m = worker.join().unwrap();
            assert_eq!(
                (m.work_started, m.work_finished, m.completed_submit),
                (1, 1, 1)
            );
            assert_eq!(m.mutation_cpu_reservations, 1);
            assert_eq!(m.mutation_cpu_refusals, 3);
            assert_eq!(m.completed_read, 2);
            assert_eq!(m.mutation_cpu_in_flight_after_shutdown, 0);
            assert_eq!(m.mutation_cpu_unavailable_after_shutdown, fail_at_finish);
            assert_eq!(
                m.mutation_full_work_cpu_ns + m.mutation_dispatch_excluding_work_cpu_ns,
                m.mutation_cpu_charged_ns
            );
            if fail_at_finish {
                assert_eq!(m.mutation_cpu_clock_failures, 1);
            } else {
                assert!(m.mutation_cpu_charged_ns > 0);
            }
            println!(
                "r5 postclockfailure={fail_at_finish} metrics={}",
                serde_json::to_string(&m).unwrap()
            );
        }
    }
    #[test]
    fn cpu_budget_missing_start_clock_refuses_before_full_verification() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner = shared(Node::open(directory.path(), settings.clone(), 2).unwrap());
        let before = owner.lock().unwrap().read_active().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let server = PublicServer::new(identity(71), policy).unwrap();
        server.fail_next_cpu_start.store(true, Ordering::Release);
        let (node, signal) = (owner.clone(), stop.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3(listener, node, Duration::from_secs(5), signal, server)
                .unwrap()
        });
        let result = call_public_protected_v3(
            address,
            &Request::Submit {
                packet: "00".into(),
            },
            &settings,
            identity(71).public_key(),
            &identity(80),
            policy,
        )
        .unwrap();
        assert!(!result.ok);
        assert_eq!(result.value["error"], "PUBLIC_MUTATION_CPU_UNAVAILABLE");
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.work_started, 0);
        assert_eq!(m.mutation_cpu_reservations, 0);
        assert_eq!(m.mutation_cpu_refusals, 1);
        assert!(m.mutation_cpu_unavailable_after_shutdown);
    }
    #[test]
    fn resource_revision_r6_rejects_signed_old_cookies_and_preserves_control_output_reserve() {
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        assert_eq!(
            hex::encode(server.policy.id()),
            "788393e580ec629f29bda7976c93b25f5df09cf327cfca139b8f239e6aee53e6"
        );
        assert_eq!(
            hex::encode(PublicPolicy::development().id()),
            "896ca15c2035acfd2f2c7e229b847e531e3c21a03eab8f466ca910f6c3213386"
        );
        let mut c = server
            .cookie(&s, hello(2, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        for old_profile in [
            "6f7b5a6018a8f78044c932b9559af21a3a02808c2773447ba96de0935816a41e",
            "5eb1d63ec9effefbc7acaeeb8ec059e5acdbc63f31e6f1c9d005a8d2dd842efd",
            "cf406b884745823ae050d3d51087d43da10c1abcbd655af9c29e84dd1492e0ec",
            "fdc9af27f01e2ffdb8e6a24b2303ed90d5d1d3ad88f2f08d686d780e29f0bd41",
            "b32629eb243707bb1baad647ece89f22845593b91dd58490dbd6ccc695528c1d",
            "ff9e0505125c8589cc29cdf359566986eb671409377fc01aac2abb41739f1dfe",
        ] {
            c.profile = old_profile.into();
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
        }
        let default_server = PublicServer::new(identity(71), PublicPolicy::development()).unwrap();
        let h = hello(2, 1);
        let current = default_server
            .cookie(&s, h, "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let old =
            digest("bcc5e234fe15a83f3e1921d810acf1e64f8c53350d5c211c9f879c9544854a48").unwrap();
        let mut legacy = current.clone();
        legacy.profile = hex::encode(old);
        legacy.mac = hex::encode(hmac(&default_server.secret, &legacy.unsigned().unwrap()));
        legacy.signature = default_server
            .identity
            .sign(&legacy.server_message().unwrap())
            .unwrap();
        validate_challenge_context(
            &serde_json::to_vec(&legacy).unwrap(),
            &legacy,
            &h,
            &s,
            default_server.identity.public_key(),
            default_server.policy,
            old,
        )
        .unwrap();
        assert_eq!(
            default_server
                .validate(&legacy, &s, true)
                .unwrap_err()
                .to_string(),
            "PUBLIC_COOKIE_CONTEXT"
        );
        assert_eq!(
            validate_challenge_context(
                &serde_json::to_vec(&current).unwrap(),
                &current,
                &h,
                &s,
                default_server.identity.public_key(),
                default_server.policy,
                old
            )
            .unwrap_err()
            .to_string(),
            "PUBLIC_CHALLENGE_CONTEXT"
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
        let control =
            BufferPermit::acquire(pool.clone(), response_maximum(2) * 4, MAX_OUTPUT_BYTES).unwrap();
        assert!(*pool.lock().unwrap() <= MAX_OUTPUT_BYTES);
        drop((bulk, control));
        assert_eq!(*pool.lock().unwrap(), 0);
    }
    #[test]
    fn r4_typed_full_and_poison_keep_lane_body_reservations_atomic() {
        let settings = Settings::development(Some(1)).unwrap();
        let server = server();
        let mut cookie = server
            .cookie(&settings, hello(1, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let mutation = Arc::new(Mutex::new(0));
        let reads = Arc::new(Mutex::new(0));
        let body = Arc::new(Mutex::new(0));
        let full = BufferPermit::acquire(
            body.clone(),
            MAX_PAID_BODY_BYTES - READ_BODY_RESERVE,
            MAX_PAID_BODY_BYTES,
        )
        .unwrap();
        for _ in 0..64 {
            assert!(try_paid_permits(&cookie, &mutation, &reads, &body)
                .unwrap()
                .is_none());
            assert_eq!(
                *mutation.lock().unwrap(),
                0,
                "temporary lane must roll back"
            );
            assert_eq!(*reads.lock().unwrap(), 0);
            assert_eq!(
                *body.lock().unwrap(),
                MAX_PAID_BODY_BYTES - READ_BODY_RESERVE
            );
        }
        cookie.op = 2;
        let read = try_paid_permits(&cookie, &mutation, &reads, &body)
            .unwrap()
            .unwrap();
        assert_eq!(*reads.lock().unwrap(), 1);
        drop(read);
        assert_eq!(*reads.lock().unwrap(), 0);
        drop(full);
        cookie.op = 1;
        let held: Vec<_> = (0..MAX_MUTATING_GRANTS)
            .map(|_| BufferPermit::acquire(mutation.clone(), 1, MAX_MUTATING_GRANTS).unwrap())
            .collect();
        assert!(try_paid_permits(&cookie, &mutation, &reads, &body)
            .unwrap()
            .is_none());
        assert_eq!(*body.lock().unwrap(), 0);
        drop(held);
        let accepted = try_paid_permits(&cookie, &mutation, &reads, &body)
            .unwrap()
            .unwrap();
        assert_eq!(*mutation.lock().unwrap(), 1);
        assert_eq!(*body.lock().unwrap(), 3);
        drop(accepted);
        assert_eq!(*mutation.lock().unwrap(), 0);
        assert_eq!(*body.lock().unwrap(), 0);
        let poison = body.clone();
        assert!(thread::spawn(move || {
            let _held = poison.lock().unwrap();
            panic!("controlled poison");
        })
        .join()
        .is_err());
        assert_eq!(
            try_paid_permits(&cookie, &mutation, &reads, &body)
                .err()
                .unwrap()
                .to_string(),
            "PUBLIC_BUFFER_POOL"
        );
        assert_eq!(
            *mutation.lock().unwrap(),
            0,
            "poison must release its temporary lane"
        );
        assert_eq!(*reads.lock().unwrap(), 0);
    }
    #[test]
    fn r4_pending_heads_use_validated_readiness_and_original_expiry_boundaries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let server = server();
        let epoch = Instant::now();
        let expiry = epoch + Duration::from_millis(2000);
        let mut connections = BTreeMap::new();
        let mut peers = Vec::new();
        for id in 0..8u64 {
            peers.push(TcpStream::connect(address).unwrap());
            let (socket, peer) = listener.accept().unwrap();
            socket.set_nonblocking(true).unwrap();
            let op = if id % 2 == 0 { 1 } else { 2 };
            let order = PendingOrder {
                sequence: 8 - id,
                entered_at: epoch,
            };
            let stage = match id {
                0 => Stage::Solution {
                    cookie: server.cookie(&settings, hello(op, 1), peer).unwrap(),
                    bytes: vec![],
                },
                1 => Stage::Hello(vec![]),
                2..=5 => Stage::WaitChallenge {
                    hello: hello(op, 1),
                    pending: order,
                },
                _ => Stage::WaitGrant {
                    cookie: server.cookie(&settings, hello(op, 1), peer).unwrap(),
                    pending: order,
                },
            };
            connections.insert(
                id,
                Connection {
                    observation: None,
                    id,
                    socket,
                    peer,
                    deadline: expiry,
                    stage,
                    total_deadline: epoch + Duration::from_secs(30),
                    permit: None,
                    lane_permit: None,
                    cancelled: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        let heads = PendingHeads::collect(&connections, expiry - Duration::from_nanos(1));
        assert!(heads.is_head(PendingKind::Challenge, 1, 4));
        assert!(heads.is_head(PendingKind::Challenge, 2, 5));
        assert!(heads.is_head(PendingKind::Grant, 1, 6));
        assert!(heads.is_head(PendingKind::Grant, 2, 7));
        assert!(
            !heads.is_head(PendingKind::Challenge, 1, 0),
            "older unsolved accept is not a ready head"
        );
        for now in [expiry, expiry + Duration::from_nanos(1)] {
            let expired = PendingHeads::collect(&connections, now);
            assert!(expired
                .challenge
                .iter()
                .chain(&expired.grant)
                .all(Option::is_none));
        }
        for _ in 0..64 {
            let _ = PendingHeads::collect(&connections, epoch);
        }
        assert!(connections.values().all(|c| c.deadline == expiry
            && c.total_deadline == epoch + Duration::from_secs(30)
            && c.permit.is_none()
            && c.lane_permit.is_none()));
        let mut order = u64::MAX;
        assert_eq!(
            PendingOrder::next(&mut order).err().unwrap().to_string(),
            "PUBLIC_PENDING_ORDER"
        );
        assert_eq!(order, u64::MAX);
        drop((connections, peers));
    }
    #[test]
    fn r4_correctly_signed_old_and_new_challenges_are_incompatible_both_directions() {
        let settings = Settings::development(Some(1)).unwrap();
        let server = server();
        let hello = hello(2, 1);
        let current = server
            .cookie(&settings, hello, "127.0.0.1:1".parse().unwrap())
            .unwrap();
        validate_challenge_context(
            &serde_json::to_vec(&current).unwrap(),
            &current,
            &hello,
            &settings,
            server.identity.public_key(),
            server.policy,
            server.policy.id(),
        )
        .unwrap();
        for old in [
            "fdc9af27f01e2ffdb8e6a24b2303ed90d5d1d3ad88f2f08d686d780e29f0bd41",
            "b32629eb243707bb1baad647ece89f22845593b91dd58490dbd6ccc695528c1d",
            "ff9e0505125c8589cc29cdf359566986eb671409377fc01aac2abb41739f1dfe",
        ] {
            let expected = digest(old).unwrap();
            let mut legacy = current.clone();
            legacy.profile = old.into();
            legacy.mac = hex::encode(hmac(&server.secret, &legacy.unsigned().unwrap()));
            legacy.signature = server
                .identity
                .sign(&legacy.server_message().unwrap())
                .unwrap();
            verify_hex_strict(
                server.identity.public_key(),
                &legacy.server_message().unwrap(),
                &legacy.signature,
            )
            .unwrap();
            validate_challenge_context(
                &serde_json::to_vec(&legacy).unwrap(),
                &legacy,
                &hello,
                &settings,
                server.identity.public_key(),
                server.policy,
                expected,
            )
            .unwrap();
            assert_eq!(
                server
                    .validate(&legacy, &settings, true)
                    .unwrap_err()
                    .to_string(),
                "PUBLIC_COOKIE_CONTEXT"
            );
            assert_eq!(
                validate_challenge_context(
                    &serde_json::to_vec(&legacy).unwrap(),
                    &legacy,
                    &hello,
                    &settings,
                    server.identity.public_key(),
                    server.policy,
                    server.policy.id()
                )
                .unwrap_err()
                .to_string(),
                "PUBLIC_CHALLENGE_CONTEXT"
            );
            assert_eq!(
                validate_challenge_context(
                    &serde_json::to_vec(&current).unwrap(),
                    &current,
                    &hello,
                    &settings,
                    server.identity.public_key(),
                    server.policy,
                    expected
                )
                .unwrap_err()
                .to_string(),
                "PUBLIC_CHALLENGE_CONTEXT"
            );
        }
    }
    #[test]
    fn r4_real_paid_fifo_read_service_and_native_admission_after_holder_release() {
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
        let raw = serde_json::to_vec(&Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        })
        .unwrap();
        let owner = shared(source);
        let observer = PublicRequestObserver::new(32).unwrap();
        let records = observer.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
                records,
            )
            .unwrap()
        });
        let mut held = Vec::new();
        for i in 0..8 {
            let caller = identity(80 + i);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        let mut pending = Vec::new();
        for i in 0..3 {
            let caller = identity(90 + i);
            let mut h = hello(1, if i == 0 { raw.len() } else { 1 });
            h.caller = digest(caller.public_key()).unwrap();
            if i == 0 {
                h.digest = hash(b"public-request-body-v3", &[&raw]);
            }
            pending.push(paid_solution_only(address, h, &caller, policy).unwrap());
            wait_metric(&metrics, |m| m.pending_grant_entered == 9 + u64::from(i));
        }
        let read = call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(99),
            policy,
        )
        .unwrap();
        assert!(read.ok);
        assert_eq!(read.value["height"], 0);
        drop(held.pop());
        let (mut first, cookie, _, deadline) = pending.remove(0);
        let ready: Value =
            serde_json::from_slice(&client_frame(&mut first, 256, deadline).unwrap()).unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(cookie.id().unwrap()));
        for (socket, _, _, _) in &pending {
            socket.set_nonblocking(true).unwrap();
            assert_eq!(
                socket.peek(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            socket.set_nonblocking(false).unwrap();
        }
        client_write(&mut first, &raw, deadline).unwrap();
        let response: Response = serde_json::from_slice(
            &client_frame(
                &mut first,
                response_maximum(1),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap(),
        )
        .unwrap();
        verify_hex_strict(
            identity(71).public_key(),
            &response.message().unwrap(),
            &response.signature,
        )
        .unwrap();
        assert!(response.ok, "{}", response.value);
        drop(first);
        let (mut second, cookie, _, deadline) = pending.remove(0);
        let ready: Value =
            serde_json::from_slice(&client_frame(&mut second, 256, deadline).unwrap()).unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(cookie.id().unwrap()));
        pending[0].0.set_nonblocking(true).unwrap();
        assert_eq!(
            pending[0].0.peek(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        pending[0].0.set_nonblocking(false).unwrap();
        drop(second);
        let (mut third, cookie, _, deadline) = pending.remove(0);
        let ready: Value =
            serde_json::from_slice(&client_frame(&mut third, 256, deadline).unwrap()).unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(cookie.id().unwrap()));
        drop((third, held));
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.work_finished, 1);
        assert_eq!(m.work_failed, 0);
        assert_eq!(m.peak_mutating_grants, 8);
        assert_eq!(m.lane_capacity_refusals, 0);
        assert_eq!(
            m.pending_challenge_entered,
            m.pending_challenge_granted + m.pending_challenge_closed
        );
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.measurement_failures, 0);
        assert_eq!(snapshot.records_not_retained, 0);
        assert!(snapshot
            .records
            .iter()
            .all(|r| r.complete && r.physical_network_bytes.is_none()));
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter(|r| r.full_work_started)
                .count(),
            1
        );
        assert!(snapshot
            .records
            .iter()
            .filter(|r| !r.task_created)
            .all(|r| !r.full_work_started && r.full_work_thread_cpu_ns.is_none()));
    }
    #[test]
    fn r4_paid_pending_eof_original_expiry_and_shutdown_never_create_body_or_work() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let node = shared(Node::open(directory.path(), settings, 2).unwrap());
        let before = node.lock().unwrap().read_active().unwrap();
        let observer = PublicRequestObserver::new(16).unwrap();
        let records = observer.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, owner) = (stop.clone(), metrics.clone(), node.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
                records,
            )
            .unwrap()
        });
        let mut holders = Vec::new();
        for i in 0..8 {
            let caller = identity(80 + i);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            holders.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        let create = |n| {
            let caller = identity(n);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            paid_solution_only(address, h, &caller, policy).unwrap()
        };
        let cancelled = create(90);
        wait_metric(&metrics, |m| m.pending_grant_entered == 9);
        drop(cancelled);
        wait_metric(&metrics, |m| m.pending_grant_closed == 1);
        let (mut expired, cookie, _, _) = create(91);
        wait_metric(&metrics, |m| m.pending_grant_entered == 10);
        let original_interval = (cookie.issued_tick_ms, cookie.expires_tick_ms);
        // The inspection read deliberately waits longer than the server's2s
        // cookie to distinguish server expiry from a client's earlier timeout.
        // It is not a change to the public client's original read budget.
        assert_eq!(
            client_frame(&mut expired, 256, Instant::now() + Duration::from_secs(3))
                .unwrap_err()
                .to_string(),
            "FRAME_EOF"
        );
        assert_eq!(
            (cookie.issued_tick_ms, cookie.expires_tick_ms),
            original_interval
        );
        wait_metric(&metrics, |m| m.pending_grant_closed == 2);
        assert!(
            metrics
                .lock()
                .unwrap()
                .expired_phase_counts
                .get("solution")
                .copied()
                .unwrap_or(0)
                >= 1
        );
        let stopping = create(92);
        wait_metric(&metrics, |m| m.pending_grant_entered == 11);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(
            m.spent_reservations, 11,
            "one reservation per complete valid Solution"
        );
        assert_eq!(m.pending_grant_granted, 8);
        assert_eq!(m.pending_grant_closed, 3);
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
        assert_eq!(m.work_started, 0);
        assert_eq!(m.tasks_enqueued, 0);
        assert_eq!(m.body_bytes_received, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        drop((expired, stopping, holders));
        let snap = observer.snapshot();
        assert_eq!(snap.accepted_connections_seen, 11);
        assert_eq!(snap.records_not_retained, 0);
        assert_eq!(snap.measurement_failures, 0);
        let pending: Vec<_> = snap
            .records
            .iter()
            .filter(|r| r.frames[2].complete && !r.frames[3].complete)
            .collect();
        assert_eq!(pending.len(), 3);
        assert!(pending.iter().all(|r| r.complete
            && !r.task_created
            && !r.dispatch_started
            && !r.full_work_started
            && r.full_work_thread_cpu_ns.is_none()
            && r.dispatch_thread_cpu_ns.is_none()
            && r.frames[4].bytes_read == 0));
    }
    #[test]
    fn r4_challenge_burst_waits_with_existing_read_reserve_and_actual_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let node = shared(Node::open(directory.path(), settings.clone(), 2).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters) = (stop.clone(), metrics.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(4),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let mut held = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        for i in 0..48u8 {
            let mut socket = TcpStream::connect(address).unwrap();
            let mut h = hello(1, 1);
            h.caller = digest(identity(80 + i).public_key()).unwrap();
            client_write(&mut socket, &h.encode(), deadline).unwrap();
            held.push(socket);
        }
        let read = call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(129),
            policy,
        )
        .unwrap();
        assert!(read.ok);
        for socket in &mut held {
            let c: Cookie =
                serde_json::from_slice(&client_frame(socket, 2048, deadline).unwrap()).unwrap();
            verify_hex_strict(
                identity(71).public_key(),
                &c.server_message().unwrap(),
                &c.signature,
            )
            .unwrap();
        }
        drop(held);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.issued_challenges, 49);
        assert_eq!(m.challenge_budget_refusals, 0);
        assert!(m.peak_pending_challenge > 1);
        assert!(m.peak_connections <= MAX_CONNECTIONS);
        assert_eq!(
            m.pending_challenge_entered,
            m.pending_challenge_granted + m.pending_challenge_closed
        );
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
        assert_eq!(m.completed_read, 1);
        assert_eq!(m.work_started, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn pool_body_guard_checks_shape_before_vector_allocation_and_closed_metadata() {
        let request = Request::PoolSubmitBundle {
            pool_context: "ab".repeat(32),
            transactions: vec!["cd".repeat(MIN_POOL_RAW)],
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(canonical_request(&bytes, 4).unwrap(), request);
        for rows in [
            vec![],
            vec!["cd".repeat(MIN_POOL_RAW - 1)],
            vec!["cd".repeat(MAX_POOL_RAW + 1)],
            vec!["cd".repeat(MIN_POOL_RAW); MAX_POOL_MEMBERS + 1],
            vec!["CD".repeat(MIN_POOL_RAW)],
        ] {
            let raw = serde_json::to_vec(&Request::PoolSubmitBundle {
                pool_context: "ab".repeat(32),
                transactions: rows,
            })
            .unwrap();
            assert!(canonical_request(&raw, 4).is_err());
        }
        for change in [
            bytes
                .iter()
                .map(|b| if *b == b'c' { b'G' } else { *b })
                .collect::<Vec<_>>(),
            bytes[..bytes.len() - 1].to_vec(),
        ] {
            assert!(canonical_request(&change, 4).is_err());
        }
        let maximum = Request::PoolSubmitBundle {
            pool_context: "ab".repeat(32),
            transactions: vec!["cd".repeat(MAX_POOL_RAW); MAX_POOL_MEMBERS],
        };
        let raw = serde_json::to_vec(&maximum).unwrap();
        assert!(raw.len() <= MAX_POOL_BODY);
        canonical_request(&raw, 4).unwrap();
        assert!(Hello::parse(&hello(4, MAX_POOL_BODY + 1).encode()).is_err());
        assert!(Hello::parse(&hello(5, MAX_READ_BODY + 1).encode()).is_err());
        for raw in [
            br#"{"op":"pool_status","enable":true}"#.as_slice(),
            br#"{"op":"pool_prune"}"#,
            br#"{"op":"pool_reset"}"#,
        ] {
            assert!(canonical_request(raw, 5).is_err());
        }
        assert!(canonical_request(&bytes, 1).is_err());
    }
    #[test]
    fn v2_magic_profile_and_signature_domains_are_rejected_exactly() {
        let new_policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let old_policy =
            super::super::public_v2::PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        assert_ne!(new_policy.id(), old_policy.id());
        let mut old = hello(2, 10).encode();
        old[..4].copy_from_slice(b"PPH2");
        assert!(Hello::parse(&old).is_err());
        let s = Settings::development(Some(1)).unwrap();
        let server = server();
        let c = server
            .cookie(&s, hello(2, 10), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let mut old_cookie = c.clone();
        old_cookie.schema = "public-resource-cookie-v2".into();
        assert!(server.validate(&old_cookie, &s, true).is_err());
        let id = c.id().unwrap();
        let nonce = 77u64;
        let signer = identity(72);
        let old_message = hash(b"public-caller-sign-v2", &[&id, &nonce.to_le_bytes()]);
        let new_message = hash(b"public-caller-sign-v3", &[&id, &nonce.to_le_bytes()]);
        let signature = signer.sign(&old_message).unwrap();
        assert!(verify_hex_strict(signer.public_key(), &new_message, &signature).is_err());
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
            serve_public_protected_v3(
                listener,
                shared(node),
                Duration::from_secs(5),
                signal,
                server,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v3(address, &Request::Head, &s, &key, &identity(72), policy)
                .is_err()
        );
        let reply =
            call_public_protected_v3(address, &Request::Head, &s, &key, &identity(72), policy)
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
        assert!(Hello::parse(&hello(6, 1).encode()).is_err());
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
        // Task completion leaves the connection's Output-stage reservation.
        drop(task_lane);
        assert_eq!(*lanes.lock().unwrap(), 1);
        let running_task_lane = connection_lane.clone();
        // Disconnect cannot release a grant still held by native execution.
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
            digest: hash(b"public-request-body-v3", &[&raw]),
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
        let mut solution = b"PPS3".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(
                caller
                    .sign(&hash(
                        b"public-caller-sign-v3",
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
            serve_public_protected_v3(
                listener,
                shared(node),
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
            serve_public_protected_v3(
                listener,
                shared(node),
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
                let reply = call_public_protected_v3(
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
