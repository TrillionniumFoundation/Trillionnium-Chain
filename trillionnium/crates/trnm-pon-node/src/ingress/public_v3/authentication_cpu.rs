//! Classical authentication sublimit, owned by the existing listener/CPU epoch.
//!
//! It reserves before synchronous crypto, including invalid signatures, and
//! holds that reservation until the actual call returns. The original Host
//! kernel parent remains the aggregate resource limit. Mutation-response signing
//! also belongs to the mutation owner's outer interval: these observations overlap
//! and MUST NOT be added to mutation CPU or treated as another host allowance.
//! No caller identity, operation ID, account balance or authorization is used.
use super::{
    ensure, Result, ThreadCpuStamp, MUTATION_CPU_BURST_NS, MUTATION_CPU_REFILL_NS_PER_SECOND,
    MUTATION_CPU_START_RESERVE_NS, MUTATION_CPU_WORKERS,
};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::Mutex, time::Instant};

/// A read-only view of this nested sublimit, not a complete receiver CPU bill.
/// Unknown intervals retain their missing cost; the known sum is not a total.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ClassicalAuthenticationCpuObservation {
    pub schema: &'static str,
    pub attempts: u64,
    pub authenticated_input_bytes: u64,
    pub known_thread_cpu_ns: u64,
    pub known_intervals: u64,
    pub unknown_intervals: u64,
    /// Includes both active crypto and a worker's promised response signature.
    pub in_flight: usize,
    pub pending_response_signatures: usize,
    pub response_reservations: u64,
    pub unused_response_reservations: u64,
    pub stored_credit_ns: i128,
    pub unavailable: bool,
    pub interval_is_additive_to_mutation_cpu: bool,
    pub grants_host_cpu_allowance: bool,
}

struct AuthenticationCpuState {
    updated: Instant,
    credit_ns: i128,
    in_flight: usize,
    pending_response_signatures: usize,
    response_reservations: u64,
    unused_response_reservations: u64,
    unavailable: bool,
    attempts: u64,
    input_bytes: u64,
    known_cpu_ns: u64,
    known_intervals: u64,
    unknown_intervals: u64,
}
impl AuthenticationCpuState {
    fn new(credit_ns: u64, now: Instant) -> Self {
        Self {
            updated: now,
            credit_ns: i128::from(credit_ns),
            in_flight: 0,
            pending_response_signatures: 0,
            response_reservations: 0,
            unused_response_reservations: 0,
            unavailable: false,
            attempts: 0,
            input_bytes: 0,
            known_cpu_ns: 0,
            known_intervals: 0,
            unknown_intervals: 0,
        }
    }
    fn ceiling(&self) -> i128 {
        i128::from(MUTATION_CPU_BURST_NS)
            - (self.in_flight as i128) * i128::from(MUTATION_CPU_START_RESERVE_NS)
    }
    fn refill(&mut self, now: Instant) -> Result<()> {
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        // A second listener can sample time before the first obtains this
        // mutex. Never rewind the shared watermark or credit an interval twice.
        let Some(elapsed) = now.checked_duration_since(self.updated) else {
            return Ok(());
        };
        let next = elapsed
            .as_nanos()
            .checked_mul(u128::from(MUTATION_CPU_REFILL_NS_PER_SECOND))
            .map(|n| n / 1_000_000_000)
            .and_then(|n| i128::try_from(n).ok())
            .and_then(|n| self.credit_ns.checked_add(n));
        let Some(next) = next else {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        self.updated = now;
        // Outstanding start reserves are part of the original burst, not an
        // additional grant on top of a refilled full bucket.
        self.credit_ns = next.min(self.ceiling());
        Ok(())
    }
    fn reserve(&mut self, bytes: usize, now: Instant) -> Result<()> {
        if self.in_flight > MUTATION_CPU_WORKERS {
            self.unavailable = true;
        }
        self.refill(now)?;
        ensure(
            self.in_flight < MUTATION_CPU_WORKERS
                && self.credit_ns >= i128::from(MUTATION_CPU_START_RESERVE_NS),
            "PUBLIC_MUTATION_CPU_BUDGET",
        )?;
        // Counters have no lifetime request/byte cap. Checked representation
        // failure is unknown accounting, never a wrapped or reset balance.
        let next = self.attempts.checked_add(1).zip(
            u64::try_from(bytes)
                .ok()
                .and_then(|n| self.input_bytes.checked_add(n)),
        );
        let Some((attempts, input_bytes)) = next else {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        self.credit_ns -= i128::from(MUTATION_CPU_START_RESERVE_NS);
        self.in_flight += 1;
        self.attempts = attempts;
        self.input_bytes = input_bytes;
        Ok(())
    }
    fn close(&mut self, now: Instant, measured: Option<u64>, returned: bool) -> Result<()> {
        if self.in_flight == 0 || self.in_flight > MUTATION_CPU_WORKERS {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        // Only a completed, known interval in a healthy account can return its
        // unused reserve. An unwind or unreadable clock keeps the whole reserve
        // and fences all subsequent starts. Known excess CPU still becomes debt.
        if returned && measured.is_some() && !self.unavailable {
            let _ = self.refill(now);
        }
        self.in_flight -= 1;
        let known = returned && measured.is_some();
        let count = if known {
            &mut self.known_intervals
        } else {
            &mut self.unknown_intervals
        };
        if let Some(next) = count.checked_add(1) {
            *count = next;
        } else {
            self.unavailable = true;
        }
        if !known {
            self.unavailable = true;
        }
        if let Some(measured) = measured {
            if let Some(total) = self.known_cpu_ns.checked_add(measured) {
                self.known_cpu_ns = total;
            } else {
                self.unavailable = true;
            }
            let reserve = i128::from(MUTATION_CPU_START_RESERVE_NS);
            let adjustment = if self.unavailable {
                (reserve - i128::from(measured)).min(0)
            } else {
                reserve - i128::from(measured)
            };
            if let Some(credit) = self.credit_ns.checked_add(adjustment) {
                self.credit_ns = credit.min(self.ceiling());
            } else {
                self.unavailable = true;
            }
        }
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")
    }
    fn reserve_response(&mut self, now: Instant) -> Result<()> {
        let Some(count) = self.response_reservations.checked_add(1) else {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        // The classical response message is one fixed digest. Reserve its
        // representation counters as well as the original principal and slot
        // before native execution; later callers cannot consume them.
        self.reserve(32, now)?;
        self.pending_response_signatures += 1;
        self.response_reservations = count;
        Ok(())
    }
    fn start_response(&mut self) -> Result<()> {
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        if self.pending_response_signatures == 0
            || self.pending_response_signatures > self.in_flight
            || self.in_flight > MUTATION_CPU_WORKERS
        {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        // Already owned: no second credit/slot/attempt/byte admission here.
        self.pending_response_signatures -= 1;
        Ok(())
    }
    fn release_response(&mut self, now: Instant, normal: bool) -> Result<()> {
        if self.pending_response_signatures == 0
            || self.pending_response_signatures > self.in_flight
            || self.in_flight > MUTATION_CPU_WORKERS
        {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        if normal && !self.unavailable {
            let _ = self.refill(now);
        }
        self.pending_response_signatures -= 1;
        self.in_flight -= 1;
        if !normal {
            self.unavailable = true;
        }
        let Some(unused) = self.unused_response_reservations.checked_add(1) else {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        };
        self.unused_response_reservations = unused;
        // No crypto was entered, so its principal is provably unused. This is
        // not a manufactured zero-duration crypto interval; attempts/bytes
        // remain reserved and neither known nor unknown interval is invented.
        if !self.unavailable {
            let Some(credit) = self
                .credit_ns
                .checked_add(i128::from(MUTATION_CPU_START_RESERVE_NS))
            else {
                self.unavailable = true;
                return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
            };
            self.credit_ns = credit.min(self.ceiling());
        }
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")
    }
    fn observation(&self) -> ClassicalAuthenticationCpuObservation {
        ClassicalAuthenticationCpuObservation {
            schema: "public-v3-classical-authentication-cpu-v2",
            attempts: self.attempts,
            authenticated_input_bytes: self.input_bytes,
            known_thread_cpu_ns: self.known_cpu_ns,
            known_intervals: self.known_intervals,
            unknown_intervals: self.unknown_intervals,
            in_flight: self.in_flight,
            pending_response_signatures: self.pending_response_signatures,
            response_reservations: self.response_reservations,
            unused_response_reservations: self.unused_response_reservations,
            stored_credit_ns: self.credit_ns,
            unavailable: self.unavailable,
            interval_is_additive_to_mutation_cpu: false,
            grants_host_cpu_allowance: false,
        }
    }
}

/// Independent *sublimit* on authentication in the same original intake epoch.
/// Uses the existing scalar constants without recursively constructing another
/// ListenerIntake, reminting host allowance or debiting the mutation owner twice.
pub(super) struct AuthenticationCpuBudget {
    state: Mutex<AuthenticationCpuState>,
    #[cfg(test)]
    fail_next_start: AtomicBool,
    #[cfg(test)]
    fail_next_finish: AtomicBool,
    #[cfg(test)]
    response_finish_gate:
        Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
impl AuthenticationCpuBudget {
    pub(super) fn new() -> Self {
        Self::with_initial_credit(MUTATION_CPU_BURST_NS)
    }
    pub(super) fn after_process_restart() -> Self {
        Self::with_initial_credit(0)
    }
    fn with_initial_credit(credit: u64) -> Self {
        Self {
            state: Mutex::new(AuthenticationCpuState::new(credit, Instant::now())),
            #[cfg(test)]
            fail_next_start: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_finish: AtomicBool::new(false),
            #[cfg(test)]
            response_finish_gate: Mutex::new(None),
        }
    }
    fn begin(&self, bytes: usize) -> Result<AuthenticationCpuInterval<'_>> {
        self.state
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .reserve(bytes, Instant::now())?;
        self.start_interval()
    }
    fn start_interval(&self) -> Result<AuthenticationCpuInterval<'_>> {
        // Establish RAII before sampling: an unavailable start clock consumes
        // this reserved attempt without running even one cryptographic call.
        let mut interval = AuthenticationCpuInterval {
            budget: self,
            stamp: None,
            closed: false,
        };
        let stamp = ThreadCpuStamp::start();
        #[cfg(test)]
        let stamp = if self.fail_next_start.swap(false, Ordering::AcqRel) {
            None
        } else {
            stamp
        };
        interval.stamp = stamp;
        ensure(interval.stamp.is_some(), "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        Ok(interval)
    }
    pub(super) fn reserve_response(&self) -> Result<ResponseSigningReservation<'_>> {
        self.state
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .reserve_response(Instant::now())?;
        Ok(ResponseSigningReservation {
            budget: self,
            retired: false,
        })
    }
    #[cfg(test)]
    pub(super) fn fail_next_finish_for_test(&self) {
        self.fail_next_finish.store(true, Ordering::Release);
    }
    #[cfg(test)]
    pub(super) fn pause_next_response_after_signing_for_test(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, until_release) = std::sync::mpsc::channel();
        *self.response_finish_gate.lock().unwrap() = Some((entered, until_release));
        (observed, release)
    }
    #[cfg(test)]
    fn response_finish_checkpoint_for_test(&self) -> Result<()> {
        let gate = self.response_finish_gate.lock().unwrap().take();
        if let Some((entered, until_release)) = gate {
            entered.send(()).map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
            until_release
                .recv_timeout(std::time::Duration::from_millis(super::WORK_MS))
                .map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
        }
        Ok(())
    }
    pub(super) fn perform<T>(
        &self,
        bytes: usize,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let interval = self.begin(bytes)?;
        // Synchronous, bounded-input crypto has no cancellable detached task.
        // At most two such nonpreemptible intervals hold a shared reservation.
        let result = operation();
        interval.finish()?;
        result
    }
    pub(super) fn observation(&self) -> Result<ClassicalAuthenticationCpuObservation> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .observation())
    }
}
/// A worker's unique, deferred signature. It owns the original principal and
/// concurrency slot but starts no thread-CPU clock during native work/queues.
pub(super) struct ResponseSigningReservation<'a> {
    budget: &'a AuthenticationCpuBudget,
    retired: bool,
}
impl ResponseSigningReservation<'_> {
    pub(super) fn belongs_to(&self, budget: &AuthenticationCpuBudget) -> bool {
        std::ptr::eq(self.budget, budget)
    }
    pub(super) fn perform<T>(mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.budget
            .state
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .start_response()?;
        // Transfer ownership before sampling: a failed start sample must go
        // through interval Drop, never through the unused-response refund.
        self.retired = true;
        let interval = self.budget.start_interval()?;
        let result = operation();
        #[cfg(test)]
        self.budget.response_finish_checkpoint_for_test()?;
        interval.finish()?;
        result
    }
}
impl Drop for ResponseSigningReservation<'_> {
    fn drop(&mut self) {
        if !self.retired {
            let mut state = match self.budget.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    let mut state = error.into_inner();
                    state.unavailable = true;
                    state
                }
            };
            let _ = state.release_response(Instant::now(), !std::thread::panicking());
        }
    }
}
struct AuthenticationCpuInterval<'a> {
    budget: &'a AuthenticationCpuBudget,
    stamp: Option<ThreadCpuStamp>,
    closed: bool,
}
impl AuthenticationCpuInterval<'_> {
    fn measured(&mut self) -> Option<u64> {
        let measured = self.stamp.take().and_then(ThreadCpuStamp::finish);
        #[cfg(test)]
        let measured = if self.budget.fail_next_finish.swap(false, Ordering::AcqRel) {
            None
        } else {
            measured
        };
        measured
    }
    fn finish(mut self) -> Result<()> {
        let measured = self.measured();
        let mut state = match self.budget.state.lock() {
            Ok(state) => state,
            Err(error) => {
                // Retain this already sampled CPU even if another scope
                // poisoned accounting. Poison still fences every future call.
                let mut state = error.into_inner();
                state.unavailable = true;
                state
            }
        };
        self.closed = true;
        state.close(Instant::now(), measured, true)
    }
}
impl Drop for AuthenticationCpuInterval<'_> {
    fn drop(&mut self) {
        if !self.closed {
            let measured = self.measured();
            let mut state = match self.budget.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    let mut state = error.into_inner();
                    state.unavailable = true;
                    state
                }
            };
            let _ = state.close(Instant::now(), measured, false);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    fn actual_cpu() {
        let mut value = 1u64;
        for _ in 0..100_000 {
            value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
        std::hint::black_box(value);
    }

    #[test]
    fn response_reservation_starts_clock_on_actual_signer_thread() {
        let budget = AuthenticationCpuBudget::new();
        let response = budget.reserve_response().unwrap();
        let other = budget.reserve_response().unwrap();
        let pending = budget.observation().unwrap();
        assert_eq!(pending.in_flight, MUTATION_CPU_WORKERS);
        assert_eq!(pending.pending_response_signatures, 2);
        assert_eq!(pending.attempts, 2);
        assert_eq!(pending.authenticated_input_bytes, 64);
        assert_eq!(pending.known_intervals, 0);
        assert_eq!(pending.known_thread_cpu_ns, 0);
        assert_eq!(
            pending.stored_credit_ns,
            i128::from(MUTATION_CPU_BURST_NS - 2 * MUTATION_CPU_START_RESERVE_NS)
        );
        let called = AtomicBool::new(false);
        assert!(budget
            .perform(32, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        assert!(!called.load(Ordering::Acquire));
        let identity =
            super::super::DevelopmentIdentity::from_secret_hex(&hex::encode([91; 32])).unwrap();
        let message = [19; 32];
        // Real work before signing is outside the authentication interval.
        // Moving the promise is safe because it has not sampled this thread.
        actual_cpu();
        let signature = thread::scope(|scope| {
            scope
                .spawn(|| response.perform(|| identity.sign(&message)))
                .join()
                .unwrap()
                .unwrap()
        });
        trnm_crypto_primitives::verify_hex_strict(identity.public_key(), &message, &signature)
            .unwrap();
        let signed = budget.observation().unwrap();
        assert_eq!(signed.known_intervals, 1);
        assert!(signed.known_thread_cpu_ns > 0);
        assert_eq!(signed.unknown_intervals, 0);
        assert_eq!(signed.in_flight, 1);
        assert_eq!(signed.pending_response_signatures, 1);
        assert_eq!(signed.attempts, 2); // No second admission at signing.
        drop(other);
        let complete = budget.observation().unwrap();
        assert_eq!(complete.in_flight, 0);
        assert_eq!(complete.pending_response_signatures, 0);
        assert_eq!(complete.unused_response_reservations, 1);
        assert_eq!(complete.attempts, 2);
        assert!(!complete.unavailable);
        assert!(complete.stored_credit_ns <= i128::from(MUTATION_CPU_BURST_NS));
    }

    #[test]
    fn response_reservation_unknown_start_or_finish_keeps_original_principal() {
        for start_unknown in [false, true] {
            let budget = AuthenticationCpuBudget::new();
            let response = budget.reserve_response().unwrap();
            let before = budget.observation().unwrap();
            if start_unknown {
                budget.fail_next_start.store(true, Ordering::Release);
            } else {
                budget.fail_next_finish_for_test();
            }
            let called = AtomicBool::new(false);
            let identity =
                super::super::DevelopmentIdentity::from_secret_hex(&hex::encode([92; 32])).unwrap();
            let result = response.perform(|| {
                called.store(true, Ordering::Release);
                identity.sign(&[22; 32])
            });
            assert!(result
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
            assert_eq!(called.load(Ordering::Acquire), !start_unknown);
            let after = budget.observation().unwrap();
            assert!(after.unavailable);
            assert_eq!(after.in_flight, 0);
            assert_eq!(after.pending_response_signatures, 0);
            assert_eq!(after.unknown_intervals, 1);
            assert_eq!(after.unused_response_reservations, 0);
            assert!(after.stored_credit_ns <= before.stored_credit_ns);
        }
    }

    #[test]
    fn response_reservation_never_bypasses_existing_unknown_or_unwind() {
        for unwind in [false, true] {
            let budget = AuthenticationCpuBudget::new();
            let response = budget.reserve_response().unwrap();
            let before = budget.observation().unwrap();
            let called = AtomicBool::new(false);
            if unwind {
                assert!(catch_unwind(AssertUnwindSafe(|| {
                    let _held = response;
                    panic!("controlled native unwind before response crypto");
                }))
                .is_err());
            } else {
                // Explicit shared-account fault injection, not measured cost.
                budget.state.lock().unwrap().unavailable = true;
                assert!(response
                    .perform(|| {
                        called.store(true, Ordering::Release);
                        Ok(())
                    })
                    .unwrap_err()
                    .is(crate::ErrorCode::PublicMutationCpuUnavailable));
            }
            let after = budget.observation().unwrap();
            assert!(!called.load(Ordering::Acquire));
            assert!(after.unavailable);
            assert_eq!(after.in_flight, 0);
            assert_eq!(after.pending_response_signatures, 0);
            assert_eq!(after.stored_credit_ns, before.stored_credit_ns);
            assert_eq!(after.known_intervals, 0);
            assert_eq!(after.known_thread_cpu_ns, 0);
        }
    }

    #[test]
    fn response_reservation_survives_another_measured_known_cpu_overrun() {
        let budget = AuthenticationCpuBudget::new();
        let response = budget.reserve_response().unwrap();
        // A deliberately CPU-heavy real interval establishes known debt. It
        // is not a claim that an ordinary signature naturally takes this long.
        budget
            .perform(32, || {
                let stamp = ThreadCpuStamp::start().unwrap();
                let deadline = Instant::now() + Duration::from_millis(super::super::WORK_MS);
                loop {
                    actual_cpu();
                    if stamp.clone().finish().unwrap()
                        > MUTATION_CPU_BURST_NS + MUTATION_CPU_START_RESERVE_NS
                    {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "original finite test CPU window exhausted"
                    );
                }
                Ok(())
            })
            .unwrap();
        let debt = budget.observation().unwrap();
        assert!(debt.stored_credit_ns < 0);
        assert!(!debt.unavailable);
        assert_eq!(debt.unknown_intervals, 0);
        assert_eq!(debt.pending_response_signatures, 1);
        let identity =
            super::super::DevelopmentIdentity::from_secret_hex(&hex::encode([93; 32])).unwrap();
        let message = [33; 32];
        let signature = response.perform(|| identity.sign(&message)).unwrap();
        trnm_crypto_primitives::verify_hex_strict(identity.public_key(), &message, &signature)
            .unwrap();
        let after = budget.observation().unwrap();
        assert_eq!(after.known_intervals, 2);
        assert_eq!(after.in_flight, 0);
        assert_eq!(after.pending_response_signatures, 0);
        assert!(!after.unavailable);
    }

    #[test]
    fn actual_failed_authentication_is_paid_and_preserves_its_error() {
        let budget = AuthenticationCpuBudget::new();
        let error = budget
            .perform::<()>(140, || {
                actual_cpu();
                Err("PUBLIC_CALLER_SIGNATURE".into())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "PUBLIC_CALLER_SIGNATURE");
        let observed = budget.observation().unwrap();
        assert_eq!(observed.attempts, 1);
        assert_eq!(observed.authenticated_input_bytes, 140);
        assert_eq!(observed.known_intervals, 1);
        assert_eq!(observed.unknown_intervals, 0);
        assert_eq!(observed.in_flight, 0);
        assert!(observed.known_thread_cpu_ns > 0);
        assert!(!observed.unavailable);
        assert!(!observed.interval_is_additive_to_mutation_cpu);
        assert!(!observed.grants_host_cpu_allowance);
    }

    #[test]
    fn depleted_credit_refuses_before_crypto_without_touching_attempt_counters() {
        let budget = AuthenticationCpuBudget::new();
        {
            let mut state = budget.state.lock().unwrap();
            state.credit_ns = -i128::from(MUTATION_CPU_BURST_NS);
            state.updated = Instant::now();
        }
        let called = AtomicBool::new(false);
        let error = budget
            .perform(32, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
        assert!(!called.load(Ordering::Acquire));
        let observed = budget.observation().unwrap();
        assert_eq!(observed.attempts, 0);
        assert_eq!(observed.in_flight, 0);
        assert!(!observed.unavailable);
    }

    #[test]
    fn listener_key_rotation_and_reconstruction_keep_the_original_authentication_account() {
        use super::super::{
            DevelopmentIdentity, PublicPolicy, PublicServer, ServiceMutationCpuDomain,
        };
        let domain = ServiceMutationCpuDomain::standalone();
        let server = |key| {
            PublicServer::with_continuous_domain(
                DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap(),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
                &domain,
            )
            .unwrap()
        };
        let first = server(71);
        first.sign_authentication(&[7; 32]).unwrap();
        let intake = first.listener_intake().unwrap();
        // Controlled known debt isolates the ownership assertion from CPU
        // speed. It is not an observation of attack cost or public fairness.
        {
            let mut state = intake.classical_authentication.state.lock().unwrap();
            state.credit_ns = -i128::from(MUTATION_CPU_BURST_NS);
            state.updated = Instant::now();
        }
        let second = server(72);
        assert!(Arc::ptr_eq(&intake, &second.listener_intake().unwrap()));
        assert!(second
            .sign_authentication(&[8; 32])
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        drop(first);
        drop(second);
        let reconstructed = server(73);
        assert!(Arc::ptr_eq(
            &intake,
            &reconstructed.listener_intake().unwrap()
        ));
        assert!(reconstructed
            .sign_authentication(&[9; 32])
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        let after = intake.classical_authentication.observation().unwrap();
        assert_eq!(after.attempts, 1);
        assert_eq!(after.known_intervals, 1);
        assert_eq!(after.authenticated_input_bytes, 32);

        intake
            .classical_authentication
            .state
            .lock()
            .unwrap()
            .unavailable = true;
        assert!(server(74)
            .sign_authentication(&[10; 32])
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    }

    #[test]
    fn reservation_is_held_until_actual_nonpreemptible_crypto_returns() {
        let budget = Arc::new(AuthenticationCpuBudget::new());
        let (started, entered) = mpsc::channel();
        let mut workers = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..MUTATION_CPU_WORKERS {
            let budget = budget.clone();
            let started = started.clone();
            let (release, until_return) = mpsc::channel::<()>();
            releases.push(release);
            workers.push(thread::spawn(move || {
                budget.perform(32, || {
                    started.send(()).unwrap();
                    let _ = until_return.recv();
                    actual_cpu();
                    Ok(())
                })
            }));
        }
        let both_entered =
            (0..MUTATION_CPU_WORKERS).all(|_| entered.recv_timeout(Duration::from_secs(5)).is_ok());
        let while_running = budget.observation().unwrap();
        let called = AtomicBool::new(false);
        let refused = budget.perform(32, || {
            called.store(true, Ordering::Release);
            Ok(())
        });
        // Release before assertions, including the regression path, so a
        // failed test cannot strand the actual workers it was observing.
        drop(releases);
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert!(both_entered);
        assert_eq!(while_running.in_flight, MUTATION_CPU_WORKERS);
        assert_eq!(while_running.known_intervals, 0);
        assert_eq!(while_running.unknown_intervals, 0);
        assert!(refused
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        assert!(!called.load(Ordering::Acquire));
        assert!(results.iter().all(Result::is_ok));
        let completed = budget.observation().unwrap();
        assert_eq!(completed.in_flight, 0);
        assert_eq!(completed.known_intervals, MUTATION_CPU_WORKERS as u64);
        assert!(budget.perform(32, || Ok(())).is_ok());
    }

    #[test]
    fn panic_keeps_original_reserve_and_fences_later_authentication() {
        let budget = AuthenticationCpuBudget::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<()> = budget.perform(32, || {
                actual_cpu();
                panic!("controlled authentication unwind");
            });
        }));
        assert!(result.is_err());
        let observed = budget.observation().unwrap();
        assert!(observed.unavailable);
        assert_eq!(observed.in_flight, 0);
        assert_eq!(observed.unknown_intervals, 1);
        assert!(observed.known_thread_cpu_ns > 0);
        assert!(
            observed.stored_credit_ns
                <= i128::from(MUTATION_CPU_BURST_NS - MUTATION_CPU_START_RESERVE_NS)
        );
        assert!(budget
            .perform::<()>(32, || panic!("unavailable account ran crypto"))
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    }

    #[test]
    fn unknown_start_or_finish_retains_cost_and_never_fabricates_zero_cpu() {
        for at_start in [true, false] {
            let budget = AuthenticationCpuBudget::new();
            if at_start {
                budget.fail_next_start.store(true, Ordering::Release);
            } else {
                budget.fail_next_finish.store(true, Ordering::Release);
            }
            let called = AtomicBool::new(false);
            let error = budget
                .perform(32, || {
                    called.store(true, Ordering::Release);
                    actual_cpu();
                    Ok(())
                })
                .unwrap_err();
            assert!(error.is(crate::ErrorCode::PublicMutationCpuUnavailable));
            assert_eq!(called.load(Ordering::Acquire), !at_start);
            let observed = budget.observation().unwrap();
            assert_eq!(observed.attempts, 1);
            assert_eq!(observed.unknown_intervals, 1);
            assert_eq!(observed.known_intervals, 0);
            assert_eq!(observed.in_flight, 0);
            assert!(observed.unavailable);
            assert_eq!(
                observed.stored_credit_ns,
                i128::from(MUTATION_CPU_BURST_NS - MUTATION_CPU_START_RESERVE_NS)
            );
        }
    }

    #[test]
    fn ending_on_another_actual_thread_is_unknown_without_refund() {
        let budget = AuthenticationCpuBudget::new();
        thread::scope(|scope| {
            let interval = budget.begin(32).unwrap();
            let result = scope.spawn(move || interval.finish()).join().unwrap();
            assert!(result
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        });
        let observed = budget.observation().unwrap();
        assert_eq!(observed.unknown_intervals, 1);
        assert_eq!(observed.in_flight, 0);
        assert!(observed.unavailable);
        assert_eq!(
            observed.stored_credit_ns,
            i128::from(MUTATION_CPU_BURST_NS - MUTATION_CPU_START_RESERVE_NS)
        );
    }

    #[test]
    fn stale_refill_never_rewinds_or_recredits_a_shared_interval() {
        let now = Instant::now();
        let mut state = AuthenticationCpuState::new(0, now);
        state.refill(now + Duration::from_secs(1)).unwrap();
        let first = state.credit_ns;
        state.refill(now + Duration::from_millis(500)).unwrap();
        assert_eq!(state.credit_ns, first);
        assert_eq!(state.updated, now + Duration::from_secs(1));
        state.refill(now + Duration::from_secs(2)).unwrap();
        assert_eq!(
            state.credit_ns,
            i128::from(MUTATION_CPU_REFILL_NS_PER_SECOND) * 2
        );
    }

    #[test]
    fn refill_ceiling_includes_outstanding_reserves_and_overrun_keeps_debt() {
        let now = Instant::now();
        let mut state = AuthenticationCpuState::new(MUTATION_CPU_BURST_NS, now);
        for _ in 0..MUTATION_CPU_WORKERS {
            state.reserve(32, now).unwrap();
        }
        let later = now + Duration::from_secs(30);
        state.refill(later).unwrap();
        assert_eq!(
            state.credit_ns,
            i128::from(MUTATION_CPU_BURST_NS)
                - (MUTATION_CPU_WORKERS as i128) * i128::from(MUTATION_CPU_START_RESERVE_NS)
        );
        for _ in 0..MUTATION_CPU_WORKERS {
            state.close(later, Some(0), true).unwrap();
        }
        assert_eq!(state.credit_ns, i128::from(MUTATION_CPU_BURST_NS));

        let mut debt = AuthenticationCpuState::new(MUTATION_CPU_START_RESERVE_NS, now);
        debt.reserve(32, now).unwrap();
        debt.close(now, Some(MUTATION_CPU_START_RESERVE_NS * 3), true)
            .unwrap();
        assert_eq!(
            debt.credit_ns,
            -i128::from(MUTATION_CPU_START_RESERVE_NS) * 2
        );
        assert!(debt
            .reserve(32, now)
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        debt.reserve(32, now + Duration::from_secs(2)).unwrap();
        assert!(!debt.unavailable);
    }

    #[test]
    fn cold_restart_has_no_new_burst_and_observation_never_refills() {
        let budget = AuthenticationCpuBudget::after_process_restart();
        let first = budget.observation().unwrap();
        let next = budget.observation().unwrap();
        assert_eq!(first.stored_credit_ns, 0);
        assert_eq!(next.stored_credit_ns, 0);
        let now = Instant::now();
        let mut state = AuthenticationCpuState::new(0, now);
        assert!(state
            .reserve(32, now)
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        state.reserve(32, now + Duration::from_millis(400)).unwrap();
        assert_eq!(state.credit_ns, 0);
    }

    #[test]
    fn rolling_account_has_no_pq_lifetime_attempt_or_byte_cap() {
        let budget = AuthenticationCpuBudget::new();
        // These are real tiny synchronous intervals, not a network throughput
        // claim. The cumulative byte counter supplies no allocation authority.
        for _ in 0..8193 {
            budget.perform(8193, || Ok(())).unwrap();
        }
        let observed = budget.observation().unwrap();
        assert_eq!(observed.attempts, 8193);
        assert!(observed.authenticated_input_bytes > 64 * 1024 * 1024);
        assert_eq!(observed.known_intervals, 8193);
        assert_eq!(observed.in_flight, 0);
        assert!(!observed.unavailable);
    }

    fn authentication_fault(domain: &super::super::ServiceMutationCpuDomain, unknown_finish: bool) {
        let intake = domain.shared_budget().lock().unwrap().intake.clone();
        let authentication = &intake.classical_authentication;
        if unknown_finish {
            authentication
                .fail_next_finish
                .store(true, Ordering::Release);
            assert!(authentication
                .perform(32, || {
                    actual_cpu();
                    Ok(())
                })
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        } else {
            // Deterministic state-machine input, not a measured CPU result:
            // one known overrun leaves debt with no unknown or live interval.
            let now = Instant::now();
            let mut state = authentication.state.lock().unwrap();
            state.reserve(32, now).unwrap();
            state
                .close(
                    now,
                    Some(MUTATION_CPU_BURST_NS + MUTATION_CPU_START_RESERVE_NS),
                    true,
                )
                .unwrap();
            assert!(state.credit_ns < 0);
        }
        let authentication = authentication.observation().unwrap();
        assert_eq!(authentication.unavailable, unknown_finish);
        assert_eq!(authentication.in_flight, 0);
        assert_eq!(authentication.unknown_intervals, u64::from(unknown_finish));
        // The original defect was invisible to the mutation-only finisher.
        let mutation = domain.observe().unwrap();
        assert!(!mutation.accounting_unavailable);
        assert_eq!(mutation.in_flight, 0);
        assert!(mutation.stored_credit_ns >= 0);
        assert!(domain.observe_actual_flow().unwrap().is_some());
    }

    fn assert_service_fence_survives_reopen(
        mut node: crate::Node,
        path: &std::path::Path,
        settings: crate::Settings,
        domain: &super::super::ServiceMutationCpuDomain,
    ) {
        assert!(node
            .bind_public_service_cpu_domain(domain)
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert!(node
            .begin_remote_history_cpu_epoch()
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        drop(node);
        let mut reopened = crate::Node::open(path, settings, 1).unwrap();
        let fresh = super::super::ServiceMutationCpuDomain::standalone();
        assert!(reopened
            .bind_public_service_cpu_domain(&fresh)
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert!(reopened
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    }

    #[test]
    fn last_history_finisher_cannot_clear_another_listeners_authentication_fault() {
        for unknown_finish in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let settings = crate::Settings::development(None).unwrap();
            let mut node = crate::Node::open(directory.path(), settings.clone(), 1).unwrap();
            let state = node.read_active().unwrap();
            let domain = super::super::ServiceMutationCpuDomain::standalone();
            node.bind_public_service_cpu_domain(&domain).unwrap();
            assert!(node.begin_ordinary_public_service_epoch().unwrap());
            assert!(node.begin_remote_history_cpu_epoch().unwrap());
            authentication_fault(&domain, unknown_finish);
            // The non-last listener only releases its original reference. The
            // final History cleanup must inspect authentication as well as its
            // own healthy mutation account before removing the durable marker.
            node.finish_ordinary_public_service_epoch(false).unwrap();
            node.finish_remote_history_cpu_epoch(&domain).unwrap();
            // Preserve the already completed native outcome and ledger State;
            // the retained cost fence denies only subsequent service starts.
            assert_eq!(node.read_active().unwrap(), state);
            assert_service_fence_survives_reopen(node, directory.path(), settings, &domain);
        }
    }

    #[test]
    fn last_listener_rechecks_authentication_after_an_earlier_clean_snapshot() {
        for unknown_finish in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let settings = crate::Settings::development(None).unwrap();
            let mut node = crate::Node::open(directory.path(), settings.clone(), 1).unwrap();
            let state = node.read_active().unwrap();
            let domain = super::super::ServiceMutationCpuDomain::standalone();
            node.bind_public_service_cpu_domain(&domain).unwrap();
            assert!(node.begin_ordinary_public_service_epoch().unwrap());
            assert!(node.begin_ordinary_public_service_epoch().unwrap());
            let early = domain.observe_classical_authentication_cpu().unwrap();
            let early_clean = early.in_flight == 0
                && !early.unavailable
                && early.unknown_intervals == 0
                && early.stored_credit_ns >= 0;
            assert!(early_clean);
            // Linearized adversarial ordering: the other listener's crypto
            // ends after this snapshot and before the final owner lock.
            authentication_fault(&domain, unknown_finish);
            node.finish_ordinary_public_service_epoch(false).unwrap();
            node.finish_ordinary_public_service_epoch(early_clean)
                .unwrap();
            assert_eq!(node.read_active().unwrap(), state);
            assert_service_fence_survives_reopen(node, directory.path(), settings, &domain);
        }
    }

    #[test]
    fn last_listener_rechecks_original_mutation_after_an_earlier_clean_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let settings = crate::Settings::development(None).unwrap();
        let mut node = crate::Node::open(directory.path(), settings.clone(), 1).unwrap();
        let state = node.read_active().unwrap();
        let domain = super::super::ServiceMutationCpuDomain::standalone();
        node.bind_public_service_cpu_domain(&domain).unwrap();
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        let early_clean = domain.public_epoch_is_settled().unwrap();
        assert!(early_clean);

        // Use the original public operation API and two actual owner threads.
        // Moving finish off its start thread makes its measured cost UNKNOWN;
        // neither synthetic CPU numbers nor a manufactured failure flag is used.
        let operation = domain.begin().unwrap();
        actual_cpu();
        let settlement = thread::spawn(move || operation.finish()).join().unwrap();
        assert!(settlement.accounting_unavailable);
        assert_eq!(settlement.owner_cpu_ns, None);
        assert_eq!(settlement.total_cpu_ns, None);
        assert!(domain.observe().unwrap().accounting_unavailable);
        assert!(!domain.public_epoch_is_settled().unwrap());
        let authentication = domain.observe_classical_authentication_cpu().unwrap();
        assert!(!authentication.unavailable);
        assert_eq!(authentication.in_flight, 0);
        assert_eq!(authentication.unknown_intervals, 0);

        node.finish_ordinary_public_service_epoch(false).unwrap();
        node.finish_ordinary_public_service_epoch(early_clean)
            .unwrap();
        assert_eq!(node.read_active().unwrap(), state);
        assert_service_fence_survives_reopen(node, directory.path(), settings, &domain);
    }

    #[test]
    fn last_listener_busy_snapshot_does_not_poison_a_later_fully_settled_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let settings = crate::Settings::development(None).unwrap();
        let mut node = crate::Node::open(directory.path(), settings.clone(), 1).unwrap();
        let state = node.read_active().unwrap();
        let domain = super::super::ServiceMutationCpuDomain::standalone();
        node.bind_public_service_cpu_domain(&domain).unwrap();
        let owner = Arc::new(Mutex::new(node));
        let stop = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_millis(super::super::WORK_MS);
        let mut last =
            super::super::OrdinaryPublicServiceCrashFence::begin(owner.clone(), deadline, &stop)
                .unwrap();
        let mut other =
            super::super::OrdinaryPublicServiceCrashFence::begin(owner.clone(), deadline, &stop)
                .unwrap();

        // Deterministic ordering of the former race: this listener has finished
        // its own work while the other listener still owns a real operation.
        // Its earlier global snapshot is Busy, with neither debt nor Unknown.
        let operation = domain.begin().unwrap();
        let early = domain.observe().unwrap();
        assert_eq!(early.in_flight, 1);
        assert!(!early.accounting_unavailable);
        assert!(early.stored_credit_ns >= 0);
        assert!(!domain.public_epoch_is_settled().unwrap());

        // The other operation actually finishes on its original owner thread
        // before either listener obtains the final owner lock. No sleeps or
        // synthetic CPU settlement are needed to reproduce this ordering.
        actual_cpu();
        let settlement = operation.finish();
        assert!(!settlement.accounting_unavailable);
        assert!(settlement.total_cpu_ns.is_some_and(|ns| ns > 0));
        assert!(domain.public_epoch_is_settled().unwrap());
        other.complete().unwrap();
        last.complete().unwrap();
        drop(other);
        drop(last);

        let mut node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
        assert_eq!(node.read_active().unwrap(), state);
        node.bind_public_service_cpu_domain(&domain).unwrap();
        drop(node);
        let mut reopened = crate::Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), state);
        reopened
            .bind_public_service_cpu_domain(&super::super::ServiceMutationCpuDomain::standalone())
            .unwrap();
    }

    #[test]
    fn continuous_authentication_fault_prevents_clean_close_and_cold_journal_reopen() {
        use crate::operator_continuous_history::{Anchor, Journal};
        use crate::operator_task_policy::PolicyError;

        for unknown_finish in [false, true] {
            // Existing native/journal guard fixture only. It supplies neither
            // qualified Work nor a production continuous-owner attestation.
            let (_native, directory, node) = crate::Node::continuous_authentication_guard_fixture();
            let state = node.read_active().unwrap();
            let head = node.continuous_journal_head().unwrap();
            let anchor: Anchor = serde_json::from_value(head.clone()).unwrap();
            let domain = node.continuous_cpu_domain().unwrap();
            assert!(domain.public_epoch_is_settled().unwrap());
            authentication_fault(&domain, unknown_finish);
            assert!(node
                .close_continuous_checkpoint()
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
            // Failure persists the original external fault marker without a
            // CleanClose event or any change to the prior ledger outcome.
            assert_eq!(node.continuous_journal_head().unwrap(), head);
            assert_eq!(node.read_active().unwrap(), state);
            let fault: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("unavailable.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(fault["schema"], "restricted-continuous-accounting-fault-v2");
            assert_eq!(fault["label"], "CPU_OR_JOURNAL_UNKNOWN");
            drop(node);
            let reopened = Journal::open(
                directory.path(),
                rustix::process::geteuid().as_raw(),
                &crate::operator_continuous_test_support::identity(),
                &anchor,
            );
            assert_eq!(reopened.err().unwrap(), PolicyError::CpuUnknown);
        }
    }

    #[test]
    fn continuous_checkpoint_requires_actual_listener_permit_release() {
        let (_native, directory, node) = crate::Node::continuous_authentication_guard_fixture();
        let state = node.read_active().unwrap();
        let head = node.continuous_journal_head().unwrap();
        let domain = node.continuous_cpu_domain().unwrap();
        let intake = domain.shared_budget().lock().unwrap().intake.clone();
        let listener = super::super::BufferPermit::acquire(
            intake.listeners.clone(),
            1,
            super::super::MAX_LISTENERS_PER_CPU_DOMAIN,
        )
        .unwrap();
        assert_eq!(*intake.listeners.lock().unwrap(), 1);
        assert_eq!(
            node.close_continuous_checkpoint().unwrap_err().to_string(),
            "OWNER_CONTINUOUS_SCOPE_BUSY"
        );
        assert_eq!(node.continuous_journal_head().unwrap(), head);
        assert!(!directory.path().join("unavailable.json").exists());
        assert_eq!(node.read_active().unwrap(), state);

        // Live work is a temporary refusal, not unknown accounting. Only the
        // actual original permit's drop releases this shared listener count.
        drop(listener);
        assert_eq!(*intake.listeners.lock().unwrap(), 0);
        assert!(domain.public_epoch_is_settled().unwrap());
        let closed = node.close_continuous_checkpoint().unwrap();
        assert_eq!(
            closed["schema"],
            "restricted-continuous-clean-checkpoint-v2"
        );
        assert_ne!(node.continuous_journal_head().unwrap(), head);
        assert!(!directory.path().join("unavailable.json").exists());
        assert_eq!(node.read_active().unwrap(), state);
    }
}
