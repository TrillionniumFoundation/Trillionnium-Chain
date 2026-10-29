//! Explicit PQ History authentication on the original paid service and CPU owner.
//! Authentication supplies neither encryption nor chain/task/release authority.
use super::*;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES};
use zeroize::Zeroizing;

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
    Classical(DevelopmentIdentity),
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

#[derive(Default, Clone)]
pub(super) struct AuthenticationUsage {
    pub(super) attempts: u64,
    pub(super) bytes: u64,
    pub(super) actual_thread_cpu_ns: u64,
    pub(super) unavailable: bool,
}
/// Held by ListenerIntake, hence shared by all listeners on the actual CPU epoch.
/// Failure, replay and cache hits never refund reservations. A CPU overrun is
/// charged and disables subsequent work; one nonpreemptible crypto call may tail.
#[derive(Default)]
pub(super) struct AuthenticationBudget(Mutex<AuthenticationUsage>);
struct AuthenticationInterval<'a> {
    budget: &'a AuthenticationBudget,
    settled: bool,
}
impl Drop for AuthenticationInterval<'_> {
    fn drop(&mut self) {
        if !self.settled {
            if let Ok(mut state) = self.budget.0.lock() {
                state.unavailable = true;
            }
        }
    }
}
impl AuthenticationBudget {
    pub(super) fn perform<T>(
        &self,
        bytes: usize,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        {
            let mut state = self
                .0
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
            ensure(
                !state.unavailable
                    && state.attempts < MAX_AUTHENTICATIONS
                    && state.actual_thread_cpu_ns < MAX_AUTHENTICATION_CPU_NS,
                "PUBLIC_MUTATION_CPU_BUDGET",
            )?;
            let total = state
                .bytes
                .checked_add(bytes as u64)
                .ok_or("PUBLIC_BUFFER_CAPACITY")?;
            ensure(total <= MAX_AUTHENTICATED_BYTES, "PUBLIC_BUFFER_CAPACITY")?;
            state.attempts += 1;
            state.bytes = total;
        }
        let stamp = ThreadCpuStamp::start();
        if stamp.is_none() {
            self.0
                .lock()
                .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
                .unavailable = true;
            return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
        }
        let mut interval = AuthenticationInterval {
            budget: self,
            settled: false,
        };
        let result = operation();
        let elapsed = stamp.and_then(ThreadCpuStamp::finish);
        let mut state = self
            .0
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?;
        match elapsed.and_then(|n| state.actual_thread_cpu_ns.checked_add(n)) {
            Some(total) => {
                state.actual_thread_cpu_ns = total;
            }
            None => {
                state.unavailable = true;
                return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
            }
        }
        interval.settled = true;
        result
    }
    pub(super) fn usage(&self) -> Result<AuthenticationUsage> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "PUBLIC_MUTATION_CPU_UNAVAILABLE")?
            .clone())
    }
}

impl PublicPolicy {
    pub fn pq_history_id(self) -> Hash {
        hash(b"TRNM/PoN/PaidHistory/PQProfile/v4\0", &[
            PQ_HISTORY_PROFILE.as_bytes(), &self.id(),
            b"pure-ML-DSA-65/caller-cookie-response/PPH4-108/PPS4-5327/canonical-SPKI1974/signature3309/challenge16384/response2113536/read-head-and-history-only/no-classical-fallback/no-confidentiality/shared-original-CPU-intake-epoch/auth-attempts8192-bytes67108864-threadCPU2000000000-no-refund-panic-unavailable-no-inflight-preemption/settings-selected-public-pq-history-complete-work-identity-v1/no-production-qualification",
        ])
    }
}
impl PublicServer {
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
            self.identity.sign(message)
        }
    }
    pub(super) fn verify_caller(&self, cookie: &Cookie, nonce: u64, bytes: &[u8]) -> Result<()> {
        let message = caller_message(cookie, nonce, self.identity.is_pq())?;
        if self.identity.is_pq() {
            self.listener_intake()?
                .pq_authentication
                .perform(bytes.len() + message.len(), || {
                    ensure(bytes.len() == PQ_SOLUTION_BYTES, "PUBLIC_SOLUTION")?;
                    let spki = &bytes[44..44 + ML_DSA_65_SPKI_BYTES];
                    PqNativeVerifier::from_pinned_spki(spki, digest(&cookie.caller)?)
                        .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?
                        .verify_exact_message(&message, &bytes[44 + ML_DSA_65_SPKI_BYTES..])
                        .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
                    Ok(())
                })
        } else {
            verify_hex_strict(&cookie.caller, &message, &hex::encode(&bytes[44..108]))
                .map_err(|_| "PUBLIC_CALLER_SIGNATURE".into())
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
