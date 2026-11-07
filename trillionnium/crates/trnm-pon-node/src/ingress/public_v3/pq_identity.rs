//! Explicit PQ History authentication on the original paid service and CPU owner.
//! Authentication supplies neither encryption nor chain/task/release authority.
use super::*;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES};
use zeroize::Zeroizing;

mod verifier_cache;
use verifier_cache::VerifierCache;

pub const PQ_HISTORY_PROFILE: &str = "public-protected-pq-history-development-v4";
pub(super) const PQ_SOLUTION_BYTES: usize = 44 + ML_DSA_65_SPKI_BYTES + ML_DSA_65_SIGNATURE_BYTES;
const MAX_AUTHENTICATIONS: u64 = 8192;
const MAX_AUTHENTICATED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUTHENTICATION_CPU_NS: u64 = 2_000_000_000;

/// A signer whose expected identity must come from protected configuration.
pub struct PqPublicIdentity {
    key: PqNativeSigningKey,
    key_id: String,
}
impl PqPublicIdentity {
    pub fn from_owned_seed(seed: Zeroizing<[u8; 32]>, expected_key_id: Hash) -> Result<Self> {
        let key = PqNativeSigningKey::from_owned_seed(seed, expected_key_id)
            .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
        Ok(Self {
            key,
            key_id: hex::encode(expected_key_id),
        })
    }
    pub fn public_key(&self) -> &str {
        &self.key_id
    }
    pub fn public_spki(&self) -> &[u8; ML_DSA_65_SPKI_BYTES] {
        self.key.public_spki()
    }
    fn sign(&self, message: &[u8]) -> Result<String> {
        self.key
            .sign_exact_message(message)
            .map(hex::encode)
            .map_err(|_| "PUBLIC_CALLER_SIGNATURE".into())
    }
}
pub(super) enum SigningIdentity {
    Classical(Box<DevelopmentIdentity>),
    Pq(Box<PqPublicIdentity>),
}
impl SigningIdentity {
    pub(super) fn is_pq(&self) -> bool {
        matches!(self, Self::Pq(_))
    }
    pub(super) fn public_key(&self) -> &str {
        match self {
            Self::Classical(k) => k.public_key(),
            Self::Pq(k) => k.public_key(),
        }
    }
    pub(super) fn sign(&self, message: &[u8]) -> Result<String> {
        match self {
            Self::Classical(k) => k.sign(message),
            Self::Pq(k) => k.sign(message),
        }
    }
}
pub(super) enum Caller<'a> {
    Classical(&'a DevelopmentIdentity),
    Pq(&'a PqPublicIdentity),
}
impl Caller<'_> {
    pub(super) fn is_pq(&self) -> bool {
        matches!(self, Self::Pq(_))
    }
    pub(super) fn public_key(&self) -> &str {
        match self {
            Self::Classical(k) => k.public_key(),
            Self::Pq(k) => k.public_key(),
        }
    }
    pub(super) fn sign(&self, message: &[u8]) -> Result<String> {
        match self {
            Self::Classical(k) => k.sign(message),
            Self::Pq(k) => k.sign(message),
        }
    }
    pub(super) fn append_spki(&self, out: &mut Vec<u8>) {
        if let Self::Pq(k) = self {
            out.extend_from_slice(k.public_spki());
        }
    }
}
pub(super) enum ServerPin<'a> {
    Classical(&'a str),
    Pq {
        key_id: String,
        verifier: Box<PqNativeVerifier>,
    },
}
impl ServerPin<'_> {
    pub(super) fn public_key(&self) -> &str {
        match self {
            Self::Classical(s) => s,
            Self::Pq { key_id, .. } => key_id,
        }
    }
    pub(super) fn is_pq(&self) -> bool {
        matches!(self, Self::Pq { .. })
    }
    pub(super) fn verify(&self, message: &[u8], signature: &str) -> Result<()> {
        match self {
            Self::Classical(key) => verify_hex_strict(key, message, signature)
                .map_err(|_| "PUBLIC_RESPONSE_SIGNATURE".into()),
            Self::Pq { verifier, .. } => {
                ensure(
                    signature.len() == 2 * ML_DSA_65_SIGNATURE_BYTES
                        && lower_hex(signature.as_bytes()),
                    "PUBLIC_RESPONSE_SIGNATURE",
                )?;
                verifier
                    .verify_exact_message(
                        message,
                        &hex::decode(signature).map_err(|_| "PUBLIC_RESPONSE_SIGNATURE")?,
                    )
                    .map_err(|_| "PUBLIC_RESPONSE_SIGNATURE")?;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PqAuthenticationCpuObservation {
    pub schema: &'static str,
    pub attempts: u64,
    pub bytes: u64,
    pub actual_thread_cpu_ns: u64,
    pub known_intervals: u64,
    pub unknown_intervals: u64,
    /// Active crypto plus a worker's deferred response signature.
    pub in_flight: usize,
    pub pending_response_signatures: usize,
    pub reserved_cpu_ns: u64,
    /// Original lifetime ceiling minus measured CPU and held principals.
    pub stored_credit_ns: i128,
    pub response_reservations: u64,
    pub unused_response_reservations: u64,
    pub unavailable: bool,
    pub grants_host_cpu_allowance: bool,
}
impl Default for PqAuthenticationCpuObservation {
    fn default() -> Self {
        Self {
            schema: "public-v3-pq-authentication-cpu-v1",
            attempts: 0,
            bytes: 0,
            actual_thread_cpu_ns: 0,
            known_intervals: 0,
            unknown_intervals: 0,
            in_flight: 0,
            pending_response_signatures: 0,
            reserved_cpu_ns: 0,
            stored_credit_ns: i128::from(MAX_AUTHENTICATION_CPU_NS),
            response_reservations: 0,
            unused_response_reservations: 0,
            unavailable: false,
            grants_host_cpu_allowance: false,
        }
    }
}
impl PqAuthenticationCpuObservation {
    fn reserve(&mut self, bytes: usize, response: bool) -> Result<()> {
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        let held = self
            .reserved_cpu_ns
            .checked_add(MUTATION_CPU_START_RESERVE_NS)
            .ok_or("PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        ensure(
            self.in_flight < MUTATION_CPU_WORKERS
                && self.attempts < MAX_AUTHENTICATIONS
                && self
                    .actual_thread_cpu_ns
                    .checked_add(held)
                    .is_some_and(|total| total <= MAX_AUTHENTICATION_CPU_NS),
            "PUBLIC_MUTATION_CPU_BUDGET",
        )?;
        let total = u64::try_from(bytes)
            .ok()
            .and_then(|n| self.bytes.checked_add(n))
            .ok_or("PUBLIC_BUFFER_CAPACITY")?;
        ensure(total <= MAX_AUTHENTICATED_BYTES, "PUBLIC_BUFFER_CAPACITY")?;
        self.attempts += 1; // The original closed maximum is 8192.
        self.bytes = total;
        self.reserved_cpu_ns = held;
        self.in_flight += 1;
        if response {
            self.pending_response_signatures += 1;
            self.response_reservations += 1;
        }
        Ok(())
    }
    fn start_response(&mut self) -> Result<()> {
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        // A nonpreemptible overrun must not bypass the original absolute
        // lifetime stop just because an earlier response was promised.
        ensure(
            self.actual_thread_cpu_ns < MAX_AUTHENTICATION_CPU_NS,
            "PUBLIC_MUTATION_CPU_BUDGET",
        )?;
        if self.pending_response_signatures == 0
            || self.pending_response_signatures > self.in_flight
            || self.in_flight > MUTATION_CPU_WORKERS
        {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        self.pending_response_signatures -= 1;
        Ok(())
    }
    fn release_response(&mut self, normal: bool) -> Result<()> {
        if self.pending_response_signatures == 0
            || self.pending_response_signatures > self.in_flight
            || self.in_flight > MUTATION_CPU_WORKERS
            || self.reserved_cpu_ns < MUTATION_CPU_START_RESERVE_NS
        {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        self.pending_response_signatures -= 1;
        self.in_flight -= 1;
        self.unused_response_reservations += 1;
        if !normal {
            self.unavailable = true;
        }
        if !self.unavailable {
            self.reserved_cpu_ns -= MUTATION_CPU_START_RESERVE_NS;
        }
        // Original attempts and bytes are never refunded, including a response
        // abandoned before crypto. Only its known-unused CPU principal returns.
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")
    }
    fn close(&mut self, measured: Option<u64>, returned: bool) -> Result<()> {
        if self.in_flight == 0
            || self.in_flight > MUTATION_CPU_WORKERS
            || self.reserved_cpu_ns < MUTATION_CPU_START_RESERVE_NS
        {
            self.unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        self.in_flight -= 1;
        let known = returned && measured.is_some();
        if known {
            self.known_intervals += 1;
        } else {
            self.unknown_intervals += 1;
            self.unavailable = true;
        }
        if let Some(measured) = measured {
            if let Some(total) = self.actual_thread_cpu_ns.checked_add(measured) {
                self.actual_thread_cpu_ns = total;
            } else {
                self.unavailable = true;
            }
        }
        if !self.unavailable {
            self.reserved_cpu_ns -= MUTATION_CPU_START_RESERVE_NS;
        }
        ensure(!self.unavailable, "PUBLIC_MUTATION_CPU_UNAVAILABLE")
    }
}
/// Held by ListenerIntake, hence shared by all listeners on the actual CPU epoch.
/// Original attempt/byte/CPU lifetime limits remain. A stricter two-slot and
/// 100ms principal sublimit protects promised responses within those limits;
/// it adds no refill, host allowance or classical fallback.
#[derive(Default)]
pub(super) struct AuthenticationBudget {
    usage: Mutex<PqAuthenticationCpuObservation>,
    verifiers: VerifierCache,
    #[cfg(test)]
    fail_next_finish: AtomicBool,
    #[cfg(test)]
    response_finish_gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}
struct AuthenticationInterval<'a> {
    budget: &'a AuthenticationBudget,
    stamp: Option<ThreadCpuStamp>,
    settled: bool,
}
impl AuthenticationInterval<'_> {
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
        let mut state = match self.budget.usage.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                state.unavailable = true;
                state
            }
        };
        self.settled = true;
        state.close(measured, true)
    }
}
impl Drop for AuthenticationInterval<'_> {
    fn drop(&mut self) {
        if !self.settled {
            let measured = self.measured();
            let mut state = match self.budget.usage.lock() {
                Ok(state) => state,
                Err(error) => {
                    let mut state = error.into_inner();
                    state.unavailable = true;
                    state
                }
            };
            let _ = state.close(measured, false);
        }
    }
}
impl AuthenticationBudget {
    fn start_interval(&self) -> Result<AuthenticationInterval<'_>> {
        let mut interval = AuthenticationInterval {
            budget: self,
            stamp: None,
            settled: false,
        };
        interval.stamp = ThreadCpuStamp::start();
        ensure(interval.stamp.is_some(), "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        Ok(interval)
    }
    pub(super) fn perform<T>(
        &self,
        bytes: usize,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.usage
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .reserve(bytes, false)?;
        let interval = self.start_interval()?;
        let result = operation();
        interval.finish()?;
        result
    }
    pub(super) fn reserve_response(&self) -> Result<PqResponseSigningReservation<'_>> {
        let bytes = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".len() + 48;
        self.usage
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .reserve(bytes, true)?;
        Ok(PqResponseSigningReservation {
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
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, observed) = mpsc::channel();
        let (release, until_release) = mpsc::channel();
        *self.response_finish_gate.lock().unwrap() = Some((entered, until_release));
        (observed, release)
    }
    #[cfg(test)]
    fn response_finish_checkpoint_for_test(&self) -> Result<()> {
        let gate = self.response_finish_gate.lock().unwrap().take();
        if let Some((entered, until_release)) = gate {
            entered.send(()).map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
            until_release
                .recv_timeout(Duration::from_millis(WORK_MS))
                .map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
        }
        Ok(())
    }
    pub(super) fn usage(&self) -> Result<PqAuthenticationCpuObservation> {
        let mut observation = self
            .usage
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .clone();
        observation.stored_credit_ns = i128::from(MAX_AUTHENTICATION_CPU_NS)
            - i128::from(observation.actual_thread_cpu_ns)
            - i128::from(observation.reserved_cpu_ns);
        Ok(observation)
    }
}
pub(super) struct PqResponseSigningReservation<'a> {
    budget: &'a AuthenticationBudget,
    retired: bool,
}
impl PqResponseSigningReservation<'_> {
    pub(super) fn perform<T>(mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.budget
            .usage
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .start_response()?;
        self.retired = true;
        let interval = self.budget.start_interval()?;
        let result = operation();
        #[cfg(test)]
        self.budget.response_finish_checkpoint_for_test()?;
        interval.finish()?;
        result
    }
}
impl Drop for PqResponseSigningReservation<'_> {
    fn drop(&mut self) {
        if !self.retired {
            let mut state = match self.budget.usage.lock() {
                Ok(state) => state,
                Err(error) => {
                    let mut state = error.into_inner();
                    state.unavailable = true;
                    state
                }
            };
            let _ = state.release_response(!std::thread::panicking());
        }
    }
}

pub(super) enum ResponseSigningReservation<'a> {
    Classical(super::authentication_cpu::ResponseSigningReservation<'a>),
    Pq(PqResponseSigningReservation<'a>),
}
impl ResponseSigningReservation<'_> {
    pub(super) fn sign(self, server: &PublicServer, message: &[u8]) -> Result<String> {
        let intake = server.listener_intake()?;
        match self {
            Self::Classical(reservation) => {
                ensure(
                    !server.identity.is_pq()
                        && message.len() == 32
                        && reservation.belongs_to(&intake.classical_authentication),
                    "PUBLIC_RESPONSE_SIGNATURE",
                )?;
                reservation.perform(|| server.identity.sign(message))
            }
            Self::Pq(reservation) => {
                ensure(
                    server.identity.is_pq()
                        && message.len() == b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".len() + 48
                        && std::ptr::eq(reservation.budget, &intake.pq_authentication),
                    "PUBLIC_RESPONSE_SIGNATURE",
                )?;
                reservation.perform(|| server.identity.sign(message))
            }
        }
    }
}

impl PublicPolicy {
    pub fn pq_history_id(self) -> Hash {
        hash(b"TRNM/PoN/PaidHistory/PQProfile/v4\0", &[
            PQ_HISTORY_PROFILE.as_bytes(), &self.id(),
            b"pure-ML-DSA-65/caller-cookie-response/PPH4-108/PPS4-5327/canonical-SPKI1974/signature3309/challenge16384/response2113536/read-head-and-history-only/no-classical-fallback/no-confidentiality/shared-original-CPU-intake-epoch/auth-attempts8192-bytes67108864-threadCPU2000000000-no-refund-panic-unavailable-no-inflight-preemption/response-reservation-v1/original-lifetime-caps/shared100ms-principal-and2-slot-sublimit/no-refill/attempt-byte-reserved-before-work-no-refund/unused-healthy-principal-only-refund/actual-sign-clock-single-use/unknown-panic-poison-no-refund/known-overrun-denies-reserved-start/settings-selected-public-pq-history-complete-work-identity-v1/no-production-qualification",
        ])
    }
}
impl PublicServer {
    pub(super) fn reserve_response_signing<'a>(
        &self,
        intake: &'a ListenerIntake,
    ) -> Result<ResponseSigningReservation<'a>> {
        let original = self.listener_intake()?;
        ensure(std::ptr::eq(original.as_ref(), intake), "PUBLIC_OWNER")?;
        if self.identity.is_pq() {
            intake
                .pq_authentication
                .reserve_response()
                .map(ResponseSigningReservation::Pq)
        } else {
            intake
                .classical_authentication
                .reserve_response()
                .map(ResponseSigningReservation::Classical)
        }
    }
    pub(super) fn reserve_response_signing_before<'a>(
        &self,
        intake: &'a ListenerIntake,
        deadline: Instant,
        stop: &AtomicBool,
        cancelled: &AtomicBool,
    ) -> Result<ResponseSigningReservation<'a>> {
        loop {
            task_alive(deadline, stop, cancelled)?;
            match self.reserve_response_signing(intake) {
                Ok(reservation) => return Ok(reservation),
                Err(error) if error.is(crate::ErrorCode::PublicMutationCpuBudget) => {
                    if self.identity.is_pq() {
                        let usage = intake.pq_authentication.usage()?;
                        // No PQ refill: only a still-owned original principal
                        // can make a capacity refusal transient.
                        if usage.in_flight == 0
                            || usage.attempts >= MAX_AUTHENTICATIONS
                            || usage.actual_thread_cpu_ns >= MAX_AUTHENTICATION_CPU_NS
                        {
                            return Err(error);
                        }
                    }
                    thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    pub fn new_pq_history(identity: PqPublicIdentity, policy: PublicPolicy) -> Result<Self> {
        Self::new_identity(SigningIdentity::Pq(Box::new(identity)), policy)
    }
    pub fn with_continuous_pq_history(
        identity: PqPublicIdentity,
        policy: PublicPolicy,
        domain: &ServiceMutationCpuDomain,
    ) -> Result<Self> {
        let mut server = Self::new_pq_history(identity, policy)?;
        server.mutation_cpu = domain.shared_budget();
        Ok(server)
    }
    pub(super) fn sign_authentication(&self, message: &[u8]) -> Result<String> {
        if self.identity.is_pq() {
            self.listener_intake()?
                .pq_authentication
                .perform(message.len(), || self.identity.sign(message))
        } else {
            self.listener_intake()?
                .classical_authentication
                .perform(message.len(), || self.identity.sign(message))
        }
    }
    pub(super) fn verify_caller(&self, cookie: &Cookie, nonce: u64, bytes: &[u8]) -> Result<()> {
        if self.identity.is_pq() {
            let message = caller_message(cookie, nonce, true)?;
            let intake = self.listener_intake()?;
            intake
                .pq_authentication
                .perform(bytes.len() + message.len(), || {
                    ensure(bytes.len() == PQ_SOLUTION_BYTES, "PUBLIC_SOLUTION")?;
                    let spki = &bytes[44..44 + ML_DSA_65_SPKI_BYTES];
                    intake.pq_authentication.verifiers.verify(
                        spki,
                        digest(&cookie.caller)?,
                        &message,
                        &bytes[44 + ML_DSA_65_SPKI_BYTES..],
                    )
                })
        } else {
            // The reactor already enforces this exact frame. Keep the private
            // entry equally bounded before slicing or reserving crypto work.
            ensure(bytes.len() == SOLUTION_BYTES, "PUBLIC_SOLUTION")?;
            self.listener_intake()?
                .classical_authentication
                .perform(SOLUTION_BYTES + 32, || {
                    let message = caller_message(cookie, nonce, false)?;
                    verify_hex_strict(&cookie.caller, &message, &hex::encode(&bytes[44..108]))
                        .map_err(|_| "PUBLIC_CALLER_SIGNATURE".into())
                })
        }
    }
}
pub(super) fn caller_message(cookie: &Cookie, nonce: u64, pq: bool) -> Result<Vec<u8>> {
    if pq {
        let mut message = b"TRNM/PoN/PaidHistory/Caller/PQ/v4\0".to_vec();
        message.extend_from_slice(&sha2::Sha384::digest(serde_json::to_vec(cookie)?));
        message.extend_from_slice(&nonce.to_le_bytes());
        Ok(message)
    } else {
        Ok(hash(
            b"public-caller-sign-v3",
            &[&cookie.id()?, &nonce.to_le_bytes()],
        )
        .to_vec())
    }
}
pub(super) fn schema(pq: bool, classic: &'static str, pq_schema: &'static str) -> &'static str {
    if pq {
        pq_schema
    } else {
        classic
    }
}
pub(super) fn challenge_maximum(pq: bool) -> usize {
    if pq {
        16_384
    } else {
        2048
    }
}
pub(super) fn solution_bytes(pq: bool) -> usize {
    if pq {
        PQ_SOLUTION_BYTES
    } else {
        SOLUTION_BYTES
    }
}
pub(super) fn solution_magic(pq: bool) -> &'static [u8; 4] {
    if pq {
        b"PPS4"
    } else {
        b"PPS3"
    }
}
pub(super) fn response_maximum_for(op: u8, pq: bool) -> usize {
    response_maximum(op) + if pq && op == 3 { 12_288 } else { 0 }
}

/// The pin is supplied by the caller's protected configuration. No discovery,
/// TLS certificate or classical identity is accepted as an alternative.
#[allow(clippy::too_many_arguments)]
pub fn call_public_history_pq_v4(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server_spki: &[u8],
    pinned_server_id: Hash,
    caller: &PqPublicIdentity,
    policy: PublicPolicy,
    outer_deadline: Option<Instant>,
) -> (Result<PublicReply>, PublicClientMetrics) {
    let verifier = match PqNativeVerifier::from_pinned_spki(pinned_server_spki, pinned_server_id) {
        Ok(v) => v,
        Err(_) => {
            return (
                Err("PUBLIC_CHALLENGE_SIGNATURE".into()),
                PublicClientMetrics::default(),
            )
        }
    };
    call_public_authenticated(
        address,
        request,
        settings,
        ServerPin::Pq {
            key_id: hex::encode(pinned_server_id),
            verifier: Box::new(verifier),
        },
        Caller::Pq(caller),
        (policy, ClientProfile::PqHistoryV4),
        outer_deadline,
    )
}

#[cfg(test)]
#[path = "pq_identity_tests.rs"]
mod tests;
