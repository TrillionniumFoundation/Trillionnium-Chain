//! Volatile admission resources owned by the existing shared CPU domain.
//!
//! These are the existing V3 limits, now aggregate across its listeners. No key,
//! connection, new listener or cloned domain gets another quota. This is local
//! overload protection, not peer entitlement, a host kernel cap or a new ledger.
use super::{
    ensure, mutating_operation, try_paid_permits, BufferPermit, Cookie, PendingKind, PendingOrder,
    Result, CHALLENGES_PER_SECOND, CHALLENGE_BURST, MAX_CONNECTIONS, READ_CHALLENGE_RESERVE,
};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

// A local overload rule, not a renewable timeout or an identity entitlement.
pub(super) const UNPAID_PRESSURE_IDLE_MS: u64 = 250;

pub(super) struct ListenerIntake {
    pub(super) pq_authentication: super::pq_identity::AuthenticationBudget,
    // Controls aggregate spawned 3-worker listener services, their queue and
    // live spent-cookie tables under this CPU domain. Separate listener
    // rebuilds cannot exceed a finite worker/queue envelope.
    pub(super) listeners: Arc<Mutex<usize>>,
    pub(super) connections: Arc<Mutex<usize>>,
    pub(super) body_pool: Arc<Mutex<usize>>,
    pub(super) output_pool: Arc<Mutex<usize>>,
    pub(super) mutating_grants: Arc<Mutex<usize>>,
    pub(super) read_grants: Arc<Mutex<usize>>,
    challenges: Mutex<ChallengeBudget>,
    leases: Arc<Mutex<ConnectionLeases>>,
}

#[derive(Default)]
struct ConnectionLeases {
    next_id: u64,
    next_pending: u64,
    entries: BTreeMap<u64, LeaseEntry>,
    // Four indices into the same at-most-64 leases, not additional task queues.
    // A non-head poll does not scan all connections. Rebuild only after a head
    // changes or expires; the complete rebuild visits at most MAX_CONNECTIONS.
    ready_heads: [Option<u64>; 4],
    heads_dirty: bool,
    #[cfg(test)]
    head_scans: usize,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadinessStage {
    Hello,
    Challenge,
    Solution,
    Grant,
    Paid,
    Retired,
}
struct ReadyEntry {
    kind: PendingKind,
    op: u8,
    order: PendingOrder,
}
impl ReadyEntry {
    fn lane(&self) -> usize {
        ready_lane(self.kind, self.op)
    }
}
fn ready_lane(kind: PendingKind, op: u8) -> usize {
    2 * usize::from(matches!(kind, PendingKind::Grant)) + usize::from(mutating_operation(op))
}
struct LeaseEntry {
    // None protects server-owed output and every paid stage. Only Hello and
    // incomplete Solution may carry a client-input progress watermark.
    waiting_since: Option<Instant>,
    cancelled: Arc<AtomicBool>,
    pressure_cancelled: Arc<AtomicBool>,
    readiness_stage: ReadinessStage,
    ready: Option<ReadyEntry>,
    ready_op: Option<u8>,
    service_stop: Option<Arc<AtomicBool>>,
}
impl LeaseEntry {
    fn ready_alive(&self, now: Instant) -> bool {
        self.ready
            .as_ref()
            .is_some_and(|ready| now < ready.order.deadline)
            && !self.cancelled.load(Ordering::Acquire)
            && self
                .service_stop
                .as_ref()
                .is_some_and(|stop| !stop.load(Ordering::Acquire))
    }
}
impl ConnectionLeases {
    fn invalidate_head(&mut self, id: u64) {
        for head in &mut self.ready_heads {
            if *head == Some(id) {
                *head = None;
                self.heads_dirty = true;
            }
        }
    }
    fn refresh_heads(&mut self, now: Instant) {
        if !self.heads_dirty
            && self.ready_heads.iter().flatten().all(|id| {
                self.entries
                    .get(id)
                    .is_some_and(|entry| entry.ready_alive(now))
            })
        {
            return;
        }
        #[cfg(test)]
        {
            self.head_scans += 1;
        }
        let mut heads: [Option<(u64, u64)>; 4] = [None; 4];
        for (id, entry) in &mut self.entries {
            if entry.ready.is_none() {
                continue;
            }
            if !entry.ready_alive(now) {
                // Retire only scheduling metadata. Keep the actual Connection,
                // original permit and cancellation observation with its owner.
                // Once expired/stopped/cancelled, a stale clock cannot revive it.
                entry.ready = None;
                entry.readiness_stage = ReadinessStage::Retired;
                continue;
            }
            let ready = entry.ready.as_ref().unwrap();
            let candidate = (ready.order.sequence, *id);
            let head = &mut heads[ready.lane()];
            if head.is_none_or(|prior| candidate < prior) {
                *head = Some(candidate);
            }
        }
        self.ready_heads = heads.map(|head| head.map(|(_, id)| id));
        self.heads_dirty = false;
    }
}
pub(super) struct ConnectionLease {
    registry: Arc<Mutex<ConnectionLeases>>,
    id: u64,
    pressure_cancelled: Arc<AtomicBool>,
}
impl ConnectionLease {
    pub(super) fn pressure_cancelled(&self) -> bool {
        self.pressure_cancelled.load(Ordering::Acquire)
    }
    pub(super) fn protect(&self) -> Result<()> {
        self.update(None)
    }
    pub(super) fn waiting_for_input(&self, now: Instant) -> Result<()> {
        self.update(Some(now))
    }
    // A complete valid Hello may join Challenge before caller authentication;
    // Grant requires the original verified and spent-reserved Solution.
    // The same service epoch orders every listener. Socket acceptance and
    // incomplete or malformed input do not register either readiness order.
    pub(super) fn register_ready(
        &self,
        kind: PendingKind,
        op: u8,
        deadline: Instant,
        stop: &Arc<AtomicBool>,
        now: Instant,
    ) -> Result<PendingOrder> {
        let mut leases = self
            .registry
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        let entry = leases
            .entries
            .get(&self.id)
            .ok_or("PUBLIC_INTAKE_UNAVAILABLE")?;
        ensure(
            !entry.cancelled.load(Ordering::Acquire) && !stop.load(Ordering::Acquire),
            "PUBLIC_REQUEST_CANCELLED",
        )?;
        ensure(now < deadline, "PUBLIC_REQUEST_DEADLINE")?;
        ensure(entry.waiting_since.is_none(), "PUBLIC_PENDING_ORDER")?;
        if let Some(ready) = &entry.ready {
            ensure(
                ready.kind == kind
                    && ready.op == op
                    && ready.order.deadline == deadline
                    && entry
                        .service_stop
                        .as_ref()
                        .is_some_and(|bound| Arc::ptr_eq(bound, stop)),
                "PUBLIC_PENDING_ORDER",
            )?;
            // Duplicate polling/registration cannot allocate a new order or
            // refresh either the wait timestamp or the absolute deadline.
            return Ok(ready.order);
        }
        let expected = match kind {
            PendingKind::Challenge => ReadinessStage::Hello,
            PendingKind::Grant => ReadinessStage::Solution,
        };
        ensure(entry.readiness_stage == expected, "PUBLIC_PENDING_ORDER")?;
        if let Some(bound_op) = entry.ready_op {
            ensure(
                bound_op == op
                    && entry
                        .service_stop
                        .as_ref()
                        .is_some_and(|bound| Arc::ptr_eq(bound, stop)),
                "PUBLIC_PENDING_ORDER",
            )?;
        }
        let sequence = leases
            .next_pending
            .checked_add(1)
            .ok_or("PUBLIC_PENDING_ORDER")?;
        let order = PendingOrder {
            sequence,
            entered_at: now,
            deadline,
        };
        leases.next_pending = sequence;
        let entry = leases
            .entries
            .get_mut(&self.id)
            .ok_or("PUBLIC_INTAKE_UNAVAILABLE")?;
        entry.readiness_stage = match kind {
            PendingKind::Challenge => ReadinessStage::Challenge,
            PendingKind::Grant => ReadinessStage::Grant,
        };
        entry.ready = Some(ReadyEntry { kind, op, order });
        entry.ready_op = Some(op);
        entry.service_stop = Some(stop.clone());
        // A newly allocated order is later than every existing order. A dirty
        // index must be rebuilt before use, never replaced by this new arrival.
        if !leases.heads_dirty {
            leases.ready_heads[ready_lane(kind, op)].get_or_insert(self.id);
        }
        Ok(order)
    }
    fn update(&self, waiting_since: Option<Instant>) -> Result<()> {
        let mut leases = self
            .registry
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        let entry = leases
            .entries
            .get_mut(&self.id)
            .ok_or("PUBLIC_INTAKE_UNAVAILABLE")?;
        // Linearizes input progress / paid transition with cross-listener
        // cancellation. Once selected, a connection cannot become paid later.
        ensure(
            !entry.cancelled.load(Ordering::Acquire)
                && entry.readiness_stage != ReadinessStage::Retired,
            "PUBLIC_REQUEST_CANCELLED",
        )?;
        entry.waiting_since = waiting_since;
        Ok(())
    }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Ok(mut leases) = self.registry.lock() {
            leases.entries.remove(&self.id);
            leases.invalidate_head(self.id);
        }
    }
}
struct ChallengeBudget {
    tokens: u64,
    // Fractional token numerator with denominator 1e9. Poll frequency must not
    // change the declared rate; a full bucket discards all surplus credit.
    fractional: u64,
    updated: Instant,
}
impl ListenerIntake {
    pub(super) fn new() -> Self {
        Self::with_challenge_credit(CHALLENGE_BURST)
    }
    pub(super) fn after_process_restart() -> Self {
        Self::with_challenge_credit(0)
    }
    fn with_challenge_credit(tokens: u64) -> Self {
        Self {
            pq_authentication: super::pq_identity::AuthenticationBudget::default(),
            listeners: Arc::new(Mutex::new(0)),
            connections: Arc::new(Mutex::new(0)),
            body_pool: Arc::new(Mutex::new(0)),
            output_pool: Arc::new(Mutex::new(0)),
            mutating_grants: Arc::new(Mutex::new(0)),
            read_grants: Arc::new(Mutex::new(0)),
            challenges: Mutex::new(ChallengeBudget {
                tokens,
                fractional: 0,
                updated: Instant::now(),
            }),
            leases: Arc::new(Mutex::new(ConnectionLeases::default())),
        }
    }
    // Metadata follows one already acquired original slot. This creates no
    // socket, queue, worker, CPU balance or independently refundable permit.
    pub(super) fn connection_lease(
        &self,
        permit: &BufferPermit,
        cancelled: Arc<AtomicBool>,
        now: Instant,
    ) -> Result<ConnectionLease> {
        ensure(
            permit.bytes == 1 && Arc::ptr_eq(&permit.pool, &self.connections),
            "PUBLIC_INTAKE_UNAVAILABLE",
        )?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        ensure(
            leases.entries.len() < MAX_CONNECTIONS,
            "PUBLIC_INTAKE_UNAVAILABLE",
        )?;
        let id = leases
            .next_id
            .checked_add(1)
            .ok_or("PUBLIC_CONNECTION_ID")?;
        leases.next_id = id;
        let pressure_cancelled = Arc::new(AtomicBool::new(false));
        leases.entries.insert(
            id,
            LeaseEntry {
                waiting_since: Some(now),
                cancelled,
                pressure_cancelled: pressure_cancelled.clone(),
                readiness_stage: ReadinessStage::Hello,
                ready: None,
                ready_op: None,
                service_stop: None,
            },
        );
        Ok(ConnectionLease {
            registry: self.leases.clone(),
            id,
            pressure_cancelled,
        })
    }
    pub(super) fn cancel_idle_unpaid_under_pressure(&self, now: Instant) -> Result<bool> {
        // Recheck the same original pool under lock: a stale full observation
        // must not cancel another connection after an owner released capacity.
        let used = self.connections.lock().map_err(|_| "PUBLIC_BUFFER_POOL")?;
        if *used < MAX_CONNECTIONS {
            return Ok(false);
        }
        let leases = self
            .leases
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        let candidate = leases
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if entry.cancelled.load(Ordering::Acquire) {
                    return None;
                }
                let since = entry.waiting_since?;
                (now.checked_duration_since(since)?
                    >= Duration::from_millis(UNPAID_PRESSURE_IDLE_MS))
                .then_some((since, *id))
            })
            .min();
        if let Some((_, id)) = candidate {
            leases.entries[&id]
                .pressure_cancelled
                .store(true, Ordering::Release);
            leases.entries[&id].cancelled.store(true, Ordering::Release);
            // Keep both metadata and the original slot until its reactor drops
            // the actual Connection. The pressure caller itself stays refused.
            return Ok(true);
        }
        Ok(false)
    }
    // Head selection and reservation share the registry lock. A concurrent
    // listener cannot pass a stale head check and overtake an older ready item.
    // Only original in-memory budget reservations run under this lock: cookie
    // signing, socket IO, body allocation and native execution remain outside.
    fn try_ready<T>(
        &self,
        lease: &ConnectionLease,
        order: PendingOrder,
        kind: PendingKind,
        op: u8,
        now: Instant,
        reserve: impl FnOnce() -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        ensure(
            Arc::ptr_eq(&self.leases, &lease.registry),
            "PUBLIC_INTAKE_UNAVAILABLE",
        )?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        let entry = leases
            .entries
            .get(&lease.id)
            .ok_or("PUBLIC_INTAKE_UNAVAILABLE")?;
        ensure(
            !entry.cancelled.load(Ordering::Acquire)
                && entry
                    .service_stop
                    .as_ref()
                    .is_some_and(|stop| !stop.load(Ordering::Acquire)),
            "PUBLIC_REQUEST_CANCELLED",
        )?;
        ensure(now < order.deadline, "PUBLIC_REQUEST_DEADLINE")?;
        ensure(
            entry
                .ready
                .as_ref()
                .is_some_and(|ready| ready.kind == kind && ready.op == op && ready.order == order),
            "PUBLIC_PENDING_ORDER",
        )?;
        leases.refresh_heads(now);
        if leases.ready_heads[ready_lane(kind, op)] != Some(lease.id) {
            return Ok(None);
        }
        let Some(value) = reserve()? else {
            return Ok(None);
        };
        let entry = leases
            .entries
            .get_mut(&lease.id)
            .ok_or("PUBLIC_INTAKE_UNAVAILABLE")?;
        entry.ready = None;
        entry.readiness_stage = match kind {
            PendingKind::Challenge => ReadinessStage::Solution,
            PendingKind::Grant => ReadinessStage::Paid,
        };
        leases.invalidate_head(lease.id);
        Ok(Some(value))
    }
    pub(super) fn try_ready_challenge(
        &self,
        lease: &ConnectionLease,
        order: PendingOrder,
        op: u8,
        now: Instant,
    ) -> Result<bool> {
        Ok(self
            .try_ready(lease, order, PendingKind::Challenge, op, now, || {
                Ok(self.try_challenge(op, now)?.then_some(()))
            })?
            .is_some())
    }
    pub(super) fn try_ready_paid_permits(
        &self,
        lease: &ConnectionLease,
        order: PendingOrder,
        cookie: &Cookie,
        now: Instant,
    ) -> Result<Option<(BufferPermit, BufferPermit)>> {
        self.try_ready(lease, order, PendingKind::Grant, cookie.op, now, || {
            try_paid_permits(
                cookie,
                &self.mutating_grants,
                &self.read_grants,
                &self.body_pool,
            )
        })
    }
    // Caller holds the shared ready-head reservation and absolute deadline
    // first. Count once BEFORE entropy/signing. Later cancellation never refunds
    // the already incurred challenge; an exhausted request remains in its old slot.
    pub(super) fn try_challenge(&self, op: u8, now: Instant) -> Result<bool> {
        let mut budget = self
            .challenges
            .lock()
            .map_err(|_| "PUBLIC_INTAKE_UNAVAILABLE")?;
        // A second listener can sample its clock before the first gets this lock.
        // Keep one monotonic refill watermark; never credit an interval twice.
        if let Some(elapsed) = now.checked_duration_since(budget.updated) {
            const SCALE: u128 = 1_000_000_000;
            let credit = (u128::from(budget.tokens) * SCALE + u128::from(budget.fractional))
                .saturating_add(
                    elapsed
                        .as_nanos()
                        .saturating_mul(u128::from(CHALLENGES_PER_SECOND)),
                )
                .min(u128::from(CHALLENGE_BURST) * SCALE);
            budget.tokens = (credit / SCALE) as u64;
            budget.fractional = (credit % SCALE) as u64;
            budget.updated = now;
        }
        if budget.tokens == 0 || (mutating_operation(op) && budget.tokens <= READ_CHALLENGE_RESERVE)
        {
            return Ok(false);
        }
        budget.tokens -= 1;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "intake/shared_readiness_tests.rs"]
mod shared_readiness_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn pressure_lease_cannot_refund_a_slot_or_revive_after_selection() {
        let intake = ListenerIntake::new();
        let now = Instant::now();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let permit =
                BufferPermit::acquire(intake.connections.clone(), 1, MAX_CONNECTIONS).unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let lease = intake
                .connection_lease(&permit, cancelled.clone(), now)
                .unwrap();
            held.push((lease, permit, cancelled));
        }
        assert_eq!(intake.leases.lock().unwrap().entries.len(), MAX_CONNECTIONS);
        assert!(!intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_millis(249))
            .unwrap());
        assert!(intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_millis(250))
            .unwrap());
        assert!(held[0].0.pressure_cancelled());
        assert!(held[0].2.load(Ordering::Acquire));
        assert_eq!(
            held[0].0.protect().unwrap_err().to_string(),
            "PUBLIC_REQUEST_CANCELLED"
        );
        assert_eq!(*intake.connections.lock().unwrap(), MAX_CONNECTIONS);
        assert!(
            BufferPermit::try_acquire(intake.connections.clone(), 1, MAX_CONNECTIONS)
                .unwrap()
                .is_none()
        );
        // Metadata drop alone cannot return its owner's original permit.
        let (lease, permit, _) = held.remove(0);
        drop(lease);
        assert_eq!(*intake.connections.lock().unwrap(), MAX_CONNECTIONS);
        drop(permit);
        assert_eq!(*intake.connections.lock().unwrap(), MAX_CONNECTIONS - 1);
        assert!(!intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_secs(1))
            .unwrap());
        drop(held);
        assert_eq!(*intake.connections.lock().unwrap(), 0);
        assert!(intake.leases.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn pressure_protects_server_owed_and_paid_stages_and_observed_input_progress() {
        let intake = ListenerIntake::new();
        let now = Instant::now();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let permit =
                BufferPermit::acquire(intake.connections.clone(), 1, MAX_CONNECTIONS).unwrap();
            let lease = intake
                .connection_lease(&permit, Arc::new(AtomicBool::new(false)), now)
                .unwrap();
            lease.protect().unwrap();
            held.push((lease, permit));
        }
        assert!(!intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_secs(1))
            .unwrap());
        // Completing Challenge re-enters input wait. Actual new input moves the
        // idle watermark; polling without bytes makes no call and no renewal.
        held[17]
            .0
            .waiting_for_input(now + Duration::from_secs(1))
            .unwrap();
        held[17]
            .0
            .waiting_for_input(now + Duration::from_millis(1200))
            .unwrap();
        assert!(!intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_millis(1449))
            .unwrap());
        assert!(intake
            .cancel_idle_unpaid_under_pressure(now + Duration::from_millis(1450))
            .unwrap());
        assert_eq!(
            held.iter().filter(|(l, _)| l.pressure_cancelled()).count(),
            1
        );
        assert!(held[17].0.pressure_cancelled());
        assert!(held[17]
            .0
            .waiting_for_input(now + Duration::from_secs(2))
            .is_err());
    }
    #[test]
    fn pressure_registry_poison_and_wrong_original_pool_fail_closed() {
        let intake = ListenerIntake::new();
        let wrong = BufferPermit::acquire(Arc::new(Mutex::new(0)), 1, MAX_CONNECTIONS).unwrap();
        assert!(intake
            .connection_lease(&wrong, Arc::new(AtomicBool::new(false)), Instant::now())
            .is_err());
        let held =
            BufferPermit::acquire(intake.connections.clone(), MAX_CONNECTIONS, MAX_CONNECTIONS)
                .unwrap();
        let registry = intake.leases.clone();
        assert!(std::thread::spawn(move || {
            let _guard = registry.lock().unwrap();
            panic!("test-only lease poison");
        })
        .join()
        .is_err());
        assert_eq!(
            intake
                .cancel_idle_unpaid_under_pressure(Instant::now())
                .unwrap_err()
                .to_string(),
            "PUBLIC_INTAKE_UNAVAILABLE"
        );
        assert_eq!(*intake.connections.lock().unwrap(), MAX_CONNECTIONS);
        drop(held);
    }
    #[test]
    fn shared_challenge_reserve_and_no_second_refill_at_stale_time() {
        let intake = ListenerIntake::new();
        let start = intake.challenges.lock().unwrap().updated;
        for _ in 0..CHALLENGE_BURST - READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(1, start).unwrap());
        }
        assert!(!intake.try_challenge(1, start).unwrap());
        for _ in 0..READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(2, start).unwrap());
        }
        assert!(!intake.try_challenge(2, start).unwrap());
        let later = start + Duration::from_millis(16);
        assert!(intake.try_challenge(2, later).unwrap());
        assert!(intake.try_challenge(2, start).unwrap());
        assert!(!intake.try_challenge(2, later).unwrap());
        assert_eq!(intake.challenges.lock().unwrap().updated, later);
    }
    #[test]
    fn cold_restart_has_no_challenge_burst_and_refills_from_its_own_clock() {
        let intake = ListenerIntake::after_process_restart();
        let start = intake.challenges.lock().unwrap().updated;
        assert!(!intake.try_challenge(2, start).unwrap());
        assert!(intake
            .try_challenge(2, start + Duration::from_millis(8))
            .unwrap());
        assert!(!intake
            .try_challenge(1, start + Duration::from_millis(8))
            .unwrap());
        assert_eq!(intake.challenges.lock().unwrap().tokens, 0);
    }
    #[test]
    fn concurrent_challenge_requests_share_one_burst_without_keys() {
        let intake = Arc::new(ListenerIntake::new());
        let start = intake.challenges.lock().unwrap().updated;
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let x = intake.clone();
                std::thread::spawn(move || {
                    (0..8)
                        .filter(|_| x.try_challenge(2, start).unwrap())
                        .count()
                })
            })
            .collect();
        let issued: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(issued, CHALLENGE_BURST as usize);
    }
    #[test]
    fn challenge_fractional_refill_preserves_the_declared_rate_under_dense_polling() {
        let intake = ListenerIntake::after_process_restart();
        let start = intake.challenges.lock().unwrap().updated;
        let mut issued = 0_u64;
        for millis in 1..=1000_u64 {
            let now = start + Duration::from_millis(millis);
            issued += u64::from(intake.try_challenge(2, now).unwrap());
            assert!(issued <= millis * CHALLENGES_PER_SECOND / 1000);
            // A second listener carrying an older clock must neither credit the
            // interval again nor move the refill watermark backwards.
            assert!(!intake
                .try_challenge(2, now - Duration::from_millis(1))
                .unwrap());
        }
        assert_eq!(issued, CHALLENGES_PER_SECOND);
    }

    #[test]
    fn challenge_fractional_refill_keeps_the_original_mutation_read_reserve() {
        let intake = ListenerIntake::new();
        let start = intake.challenges.lock().unwrap().updated;
        for _ in 0..CHALLENGE_BURST - READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(1, start).unwrap());
        }
        let mut issued = 0_u64;
        for millis in 1..=1000_u64 {
            issued += u64::from(
                intake
                    .try_challenge(1, start + Duration::from_millis(millis))
                    .unwrap(),
            );
        }
        assert_eq!(issued, CHALLENGES_PER_SECOND);
        let end = start + Duration::from_secs(1);
        assert!(!intake.try_challenge(1, end).unwrap());
        for _ in 0..READ_CHALLENGE_RESERVE {
            assert!(intake.try_challenge(2, end).unwrap());
        }
        assert!(!intake.try_challenge(2, end).unwrap());
    }

    #[test]
    fn challenge_fractional_refill_discards_surplus_at_the_original_burst() {
        let intake = ListenerIntake::new();
        let start = intake.challenges.lock().unwrap().updated;
        let full = start + Duration::from_nanos(500);
        for _ in 0..CHALLENGE_BURST {
            assert!(intake.try_challenge(2, full).unwrap());
        }
        let one_token_ns = 1_000_000_000 / CHALLENGES_PER_SECOND;
        assert!(!intake
            .try_challenge(2, full + Duration::from_nanos(one_token_ns - 1))
            .unwrap());
        assert!(intake
            .try_challenge(2, full + Duration::from_nanos(one_token_ns))
            .unwrap());
        assert!(!intake
            .try_challenge(2, full + Duration::from_nanos(one_token_ns))
            .unwrap());
    }

    #[test]
    fn unavailable_challenge_lock_does_not_create_another_budget() {
        let intake = Arc::new(ListenerIntake::new());
        let x = intake.clone();
        assert!(std::thread::spawn(move || {
            let _guard = x.challenges.lock().unwrap();
            panic!("test-only lock poison");
        })
        .join()
        .is_err());
        assert_eq!(
            intake
                .try_challenge(2, Instant::now())
                .unwrap_err()
                .to_string(),
            "PUBLIC_INTAKE_UNAVAILABLE"
        );
    }
}
