//! Explicit pure-PoN development successor: same resource account, cross-listener
//! CPU-start ordering, and bounded exact arithmetic facts in that account's epoch.
//!
//! A waiting ticket is only a scalar position for an already dequeued request.
//! It buys no credit, authority, extra worker or longer deadline. FIFO covers
//! participating v2 listeners after bounded intake; it cannot guarantee entry or
//! progress against unlimited identities, traffic, or other local CPU consumers.
//! Facts bind exact challenge and whole A/B. Every invocation still checks its
//! current grammar, fields, task, target and trace/product claims, then the native
//! owner rechecks current state. No transcript claim or native verdict is cached.
use super::*;
use trnm_crypto_primitives::pon_work::arithmetic_facts::{
    ArithmeticFactCache, MAX_ARITHMETIC_FACT_SLOTS, MAX_ARITHMETIC_FACT_SOFTWARE_BYTES,
};

pub const PURE_PON_V2_PROFILE: &str = "public-pure-pon-development-v2";
// Each listener holds its existing dequeue-order lock while waiting, so at most
// one request per listener can reach this registry. No request body is retained.
const FIFO_CAPACITY: usize = MAX_LISTENERS_PER_CPU_DOMAIN;

impl PublicPolicy {
    /// Fresh signed identity, accepted only through explicit pure-v2 setup and
    /// client calls. No negotiation or fallback changes the pure-v1/r13 contract.
    pub fn pure_admission_v2_id(self) -> Hash {
        hash(b"public-pure-pon-resource-v2", &[
            PURE_PON_V2_PROFILE.as_bytes(), &self.id(),
            b"pure-zero-nonce-no-search/original-shared-CPU-intake-grants-bytes-workers-and-absolute-deadlines/same-epoch-cross-listener-FIFO-after-original-dequeue/at-most-one-scalar-waiter-per-listener/cancel-or-timeout-removes-position/no-identity-preference-no-guarantee-before-bounded-intake/original-verified-completion-priority/no-new-balance-or-startup-credit/exact-challenge-whole-A-B-facts-shared-only-in-same-CPU-epoch/current-task-target-trace-product-rechecked-every-call/no-verdict-authority-cache/try-lock-contention-uses-original-accounted-raw-math/fixed64-round-robin-software-objects-not-RSS/all-request-cache-work-original-actual-thread-CPU/full-native-owner-rebind/development-only-no-production-qualification",
            &(FIFO_CAPACITY as u64).to_le_bytes(),
            &(MAX_ARITHMETIC_FACT_SLOTS as u64).to_le_bytes(),
            &(MAX_ARITHMETIC_FACT_SOFTWARE_BYTES as u64).to_le_bytes(),
        ])
    }
}

pub(super) struct PureAdmissionState {
    facts: Arc<ArithmeticFactCache>,
    tickets: [u64; FIFO_CAPACITY],
    waiting: usize,
    next_ticket: u64,
    registered: u64,
    started: u64,
    cancelled: u64,
}
impl PureAdmissionState {
    fn new() -> Result<Self> {
        Ok(Self {
            facts: Arc::new(ArithmeticFactCache::new(MAX_ARITHMETIC_FACT_SLOTS)?),
            tickets: [0; FIFO_CAPACITY],
            waiting: 0,
            next_ticket: 0,
            registered: 0,
            started: 0,
            cancelled: 0,
        })
    }
    fn register(&mut self) -> Result<u64> {
        ensure(self.waiting < FIFO_CAPACITY, "PUBLIC_PURE_V2_FIFO_CAPACITY")?;
        let ticket = self.next_ticket;
        self.next_ticket = ticket
            .checked_add(1)
            .ok_or("PUBLIC_PURE_V2_FIFO_EXHAUSTED")?;
        self.tickets[self.waiting] = ticket;
        self.waiting += 1;
        self.registered = self.registered.saturating_add(1);
        Ok(ticket)
    }
    fn waiting_for_turn(&self, ticket: u64) -> Result<bool> {
        ensure(
            self.tickets[..self.waiting].contains(&ticket),
            "PUBLIC_PURE_V2_FIFO_POSITION",
        )?;
        Ok(self.tickets[0] != ticket)
    }
    fn remove(&mut self, ticket: u64, started: bool) {
        if let Some(index) = self.tickets[..self.waiting]
            .iter()
            .position(|id| *id == ticket)
        {
            self.tickets.copy_within(index + 1..self.waiting, index);
            self.waiting -= 1;
            self.tickets[self.waiting] = 0;
            if started {
                self.started = self.started.saturating_add(1);
            } else {
                self.cancelled = self.cancelled.saturating_add(1);
            }
        }
    }
    fn observation(&self) -> PureAdmissionObservation {
        PureAdmissionObservation {
            schema: "public-pure-pon-admission-observation-v2",
            waiting: self.waiting,
            registered: self.registered,
            started: self.started,
            cancelled: self.cancelled,
            fifo_capacity: FIFO_CAPACITY,
            arithmetic_slots: self.facts.capacity(),
            retained_software_bytes: self.facts.software_bytes(),
        }
    }
}

/// Same-lock diagnostic counts, with no caller identities or packet payloads.
/// `retained_software_bytes` describes cache objects, not process or kernel RSS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PureAdmissionObservation {
    pub schema: &'static str,
    pub waiting: usize,
    pub registered: u64,
    pub started: u64,
    pub cancelled: u64,
    pub fifo_capacity: usize,
    pub arithmetic_slots: usize,
    pub retained_software_bytes: usize,
}

impl PublicServer {
    /// Trusted local setup. The first participant allocates a fresh bounded fact
    /// owner; subsequent listeners clone it from the exact original CPU epoch.
    /// This does not refill, reset, reserve, or replace any intake/CPU resource.
    pub fn with_pure_admission_v2(mut self) -> Result<Self> {
        ensure(
            self.policy.is_pure_pon()
                && !self.native_growth
                && self.arithmetic_facts.is_none()
                && self.pure_admission_v2.is_none(),
            "PUBLIC_PURE_V2_PROFILE",
        )?;
        let mut budget = self
            .mutation_cpu
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        if budget.pure_admission_v2.is_none() {
            budget.pure_admission_v2 = Some(PureAdmissionState::new()?);
        }
        self.pure_admission_v2 = Some(
            budget
                .pure_admission_v2
                .as_ref()
                .ok_or("PUBLIC_PURE_V2_PROFILE")?
                .facts
                .clone(),
        );
        drop(budget);
        Ok(self)
    }
}

impl ServiceMutationCpuDomain {
    /// Observation cannot create the v2 owner, mint credit, or advance refill.
    pub fn observe_pure_admission(&self) -> Result<Option<PureAdmissionObservation>> {
        Ok(self
            .shared_budget()
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .pure_admission_v2
            .as_ref()
            .map(PureAdmissionState::observation))
    }
}

/// Lives only while the original worker waits for its original CPU start.
/// Cancellation and errors remove its position before that worker dequeues again.
pub(super) struct PureAdmissionWaiter {
    budget: Arc<Mutex<PaidMutationCpuBudget>>,
    ticket: u64,
    started: bool,
}
impl PureAdmissionWaiter {
    pub(super) fn for_server(server: &PublicServer) -> Result<Option<Self>> {
        if server.pure_admission_v2.is_none() {
            return Ok(None);
        }
        let ticket = server
            .mutation_cpu
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .pure_admission_v2
            .as_mut()
            .ok_or("PUBLIC_PURE_V2_PROFILE")?
            .register()?;
        Ok(Some(Self {
            budget: server.mutation_cpu.clone(),
            ticket,
            started: false,
        }))
    }
    pub(super) fn waiting_for_turn(&self, budget: &PaidMutationCpuBudget) -> Result<bool> {
        budget
            .pure_admission_v2
            .as_ref()
            .ok_or("PUBLIC_PURE_V2_PROFILE")?
            .waiting_for_turn(self.ticket)
    }
    pub(super) fn reserve_turn(
        &mut self,
        budget: &mut PaidMutationCpuBudget,
        now: Instant,
    ) -> Result<()> {
        // Temporarily own only the scalar registry under the already-held CPU
        // mutex. Restore it on either result. No lock or native work is nested.
        let mut fifo = budget
            .pure_admission_v2
            .take()
            .ok_or("PUBLIC_PURE_V2_PROFILE")?;
        let result = (|| {
            ensure(
                !fifo.waiting_for_turn(self.ticket)?,
                "PUBLIC_PURE_V2_FIFO_TURN",
            )?;
            budget.reserve(now)
        })();
        if result.is_ok() {
            fifo.remove(self.ticket, true);
            self.started = true;
        }
        budget.pure_admission_v2 = Some(fifo);
        result
    }
}
impl Drop for PureAdmissionWaiter {
    fn drop(&mut self) {
        if !self.started {
            if let Ok(mut budget) = self.budget.lock() {
                if let Some(fifo) = budget.pure_admission_v2.as_mut() {
                    fifo.remove(self.ticket, false);
                }
            }
        }
    }
}

/// Explicit zero-search client; rejects other policies before opening a socket.
pub fn call_public_pure_pon_v2(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    outer_deadline: Option<Instant>,
) -> (Result<PublicReply>, PublicClientMetrics) {
    if !policy.is_pure_pon() {
        return (
            Err("PUBLIC_PURE_V2_PROFILE".into()),
            PublicClientMetrics::default(),
        );
    }
    call_public_protected_v3_with_profile(
        address,
        request,
        settings,
        pinned_server,
        caller,
        (policy, ClientProfile::PurePoNV2),
        outer_deadline,
    )
}

/// Same pinned-genesis public task material, over only the signed v2 profile.
pub fn fetch_public_task_bootstrap_v2(
    address: SocketAddr,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    deadline: Option<Instant>,
) -> (
    Result<crate::public_task_bootstrap::PublicTaskBootstrap>,
    PublicClientMetrics,
) {
    let (reply, metrics) = call_public_pure_pon_v2(
        address,
        &Request::PublicTaskBootstrap,
        settings,
        pinned_server,
        caller,
        policy,
        deadline,
    );
    let result = reply.and_then(|reply| {
        ensure(reply.ok, "PUBLIC_TASK_REMOTE_REFUSED")?;
        let bundle: crate::public_task_bootstrap::PublicTaskBootstrap =
            serde_json::from_value(reply.value)?;
        bundle.validate(settings)?;
        Ok(bundle)
    });
    (result, metrics)
}

#[cfg(test)]
mod tests;
