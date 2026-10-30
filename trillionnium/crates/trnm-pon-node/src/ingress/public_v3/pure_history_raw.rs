//! Explicit research integration of zero-search admission and the unchanged
//! r13 full-W1/native execution path. This is not the pure-v1 product prefilter
//! or pure-v2 arithmetic-facts profile. Neither is silently selected here.
use super::*;

pub const PURE_HISTORY_RAW_PROFILE: &str = "public-pure-pon-history-raw-development-v1";
const CONTRACT: &[u8] = b"canonical-zero-solution-nonce/search-budget0/solution-trials0/no-admission-hashcash/full-original-W1-every-paid-submit/no-public-product-prefilter/no-rejection-cache/no-arithmetic-facts/original-shared-CPU-intake-workers-deadlines-and-verified-completion-priority/original-header-challenge-task-target-ticket-and-matrices/ordinary-native-journal-activation-cancellation-recovery-and-settlement/no-profile-negotiation-or-fallback/research-only-no-qualification";

impl PublicPolicy {
    /// Explicit constructor. Historical bits=0 retains pure-v1/pure-v2; it cannot
    /// silently acquire the distinct raw History verifier or signed identity.
    pub fn pure_history_raw(lifetime: Duration) -> Result<Self> {
        let lifetime_ms = u64::try_from(lifetime.as_millis()).map_err(|_| "PUBLIC_POLICY")?;
        ensure((100..=2000).contains(&lifetime_ms), "PUBLIC_POLICY")?;
        Ok(Self {
            bits: 0,
            lifetime_ms,
            admission_variant: PublicAdmissionVariant::PureHistoryRawV1,
        })
    }

    pub fn is_pure_history_raw(self) -> bool {
        self.admission_variant == PublicAdmissionVariant::PureHistoryRawV1
    }

    pub(super) fn validate(self) -> Result<()> {
        if self.is_pure_history_raw() {
            ensure(self.bits == 0, "PUBLIC_PURE_HISTORY_RAW_PROFILE")?;
            Self::pure_history_raw(Duration::from_millis(self.lifetime_ms))?;
        } else {
            Self::new(self.bits, Duration::from_millis(self.lifetime_ms))?;
        }
        Ok(())
    }

    pub(super) fn pure_history_raw_id(self) -> Hash {
        let original = self.original_resource_id();
        hash(
            b"public-pure-pon-history-raw-resource-v1",
            &[PURE_HISTORY_RAW_PROFILE.as_bytes(), &original, CONTRACT],
        )
    }
}

/// Receipt for the actual selected zero-search branch. A nonce is present only
/// after construction of the canonical acknowledgement; completion additionally
/// requires the ordinary signed cookie and response checks in the shared client.
#[derive(Debug, Serialize)]
pub struct PureHistoryRawAcknowledgement {
    pub schema: &'static str,
    pub profile: &'static str,
    pub policy_id: String,
    pub ticket_bits: u8,
    pub search_budget: u64,
    pub solution_trials: u64,
    pub solution_nonce: Option<u64>,
}

pub fn call_public_pure_history_raw(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    deadline: Option<Instant>,
) -> (
    Result<PublicReply>,
    PublicClientMetrics,
    PureHistoryRawAcknowledgement,
) {
    let (reply, metrics) = if policy.is_pure_history_raw() {
        call_public_protected_v3_with_deadline(
            address,
            request,
            settings,
            pinned_server,
            caller,
            policy,
            deadline,
        )
    } else {
        (
            Err("PUBLIC_PURE_HISTORY_RAW_PROFILE".into()),
            PublicClientMetrics::default(),
        )
    };
    let acknowledgement = PureHistoryRawAcknowledgement {
        schema: "public-pure-history-raw-acknowledgement-v1",
        profile: PURE_HISTORY_RAW_PROFILE,
        policy_id: hex::encode(policy.id()),
        ticket_bits: policy.bits,
        search_budget: 0,
        solution_trials: metrics.solution_trials,
        solution_nonce: metrics.solution_found.then_some(0),
    };
    (reply, metrics, acknowledgement)
}

#[cfg(test)]
mod tests;
