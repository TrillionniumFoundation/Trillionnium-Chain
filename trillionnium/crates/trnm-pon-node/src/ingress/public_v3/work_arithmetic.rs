//! Separate opt-in resource profile for exact mathematical-fact reuse.
//!
//! Default clients and servers retain the original r13 raw verifier/profile.
//! This owner is fresh and empty, volatile and local to one explicitly configured
//! server. Its setup allocation is not a guest CPU charge. All actual request
//! lookup/comparison/reconstruction/publication work runs inside the original
//! paid worker interval, including contention fallback and cancellation tails.
//! No cache outcome grants native execution or additional completion priority.
use super::*;
use trnm_crypto_primitives::pon_work::arithmetic_facts::{
    ArithmeticFactCache, ArithmeticObservation, ArithmeticPublication, MAX_ARITHMETIC_FACT_SLOTS,
    MAX_ARITHMETIC_FACT_SOFTWARE_BYTES,
};

impl PublicPolicy {
    /// This is a separate signed profile, never a replacement identity for r13.
    /// The original budgets, absolute deadlines and completion guard are bound
    /// through the original profile; only the explicitly named arithmetic path
    /// differs. It confers no production/WAN qualification.
    pub fn arithmetic_facts_id(self) -> Hash {
        hash(
            b"public-protected-profile-v3-arithmetic-facts-v1",
            &[
                &self.id(),
                b"fresh-empty-server-local-owner/exact-challenge-and-canonical-whole-A-B-bytes/completed-trace-and-optional-completed-product-only/no-verdict-task-target-state-or-authorization-cache/current-grammar-field-task-target-and-trace-product-claims-every-call/original-cooperative-cancellation/no-publish-on-returned-cancel/bounded-final-compare-publish-tail/try-lock-no-wait-contention-does-actual-raw-math/fixed64-slots-round-robin-no-growth/software-objects-not-RSS/original-actual-thread-CPU-owner-includes-all-math-cache-work/no-added-credit-deadline-or-completion-identity/independent-per-request-arithmetic-observation",
                &(MAX_ARITHMETIC_FACT_SLOTS as u64).to_le_bytes(),
                &(MAX_ARITHMETIC_FACT_SOFTWARE_BYTES as u64).to_le_bytes(),
            ],
        )
    }
}

impl PublicServer {
    /// Explicit trusted-local setup, before serving. Each enabled server starts
    /// with 64 empty slots; callers cannot insert facts or reset this owner.
    /// Enabling does not replace the shared CPU account or mint startup credit.
    /// Original constructors remain raw unless this method is explicitly called.
    pub fn with_arithmetic_facts(mut self) -> Result<Self> {
        ensure(
            self.arithmetic_facts.is_none() && !self.native_growth,
            "PUBLIC_ARITHMETIC_FACTS_ALREADY_ENABLED",
        )?;
        self.arithmetic_facts = Some(ArithmeticFactCache::new(MAX_ARITHMETIC_FACT_SLOTS)?);
        Ok(self)
    }

    pub fn resource_profile(&self) -> Hash {
        if self.native_growth {
            self.policy.growth_id()
        } else if self.arithmetic_facts.is_some() {
            self.policy.arithmetic_facts_id()
        } else {
            self.policy.id()
        }
    }

    /// Retained Rust object-storage charge for this volatile arithmetic owner.
    /// Does not include allocator metadata, ordinary per-call verifier workspace,
    /// returned values or optional request-observer rows; never an RSS claim.
    pub fn arithmetic_facts_software_bytes(&self) -> Option<usize> {
        self.arithmetic_facts
            .as_ref()
            .map(ArithmeticFactCache::software_bytes)
    }
}

/// Explicit client for the separately signed arithmetic profile. There is no
/// fallback to raw or another profile. The original client and its optional
/// absolute-deadline entry keep their exact expected r13 profile and behavior.
pub fn call_public_protected_v3_with_arithmetic_facts(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    outer_deadline: Option<Instant>,
) -> (Result<PublicReply>, PublicClientMetrics) {
    call_public_protected_v3_with_profile(
        address,
        request,
        settings,
        pinned_server,
        caller,
        (policy, ClientProfile::ArithmeticFacts),
        outer_deadline,
    )
}

/// Fixed per-request observation. These are actual path facts, not CPU estimates
/// and not additional work/payment/admission credit. None means unfinished or
/// unobserved, never a successful no-work shortcut.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublicArithmeticWorkObservation {
    pub schema: &'static str,
    pub slots: usize,
    pub retained_software_bytes: usize,
    pub completed: bool,
    pub arithmetic: Option<PublicArithmeticFactObservation>,
}
impl PublicArithmeticWorkObservation {
    pub(super) fn started(facts: &ArithmeticFactCache) -> Self {
        Self {
            schema: "public-v3-work-arithmetic-observation-v1",
            slots: facts.capacity(),
            retained_software_bytes: facts.software_bytes(),
            completed: false,
            arithmetic: None,
        }
    }
    pub(super) fn finished(facts: &ArithmeticFactCache, actual: ArithmeticObservation) -> Self {
        Self {
            completed: true,
            arithmetic: Some(actual.into()),
            ..Self::started(facts)
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublicArithmeticFactObservation {
    pub lookup_probes: usize,
    pub lookup_contended: bool,
    pub exact_fact_found: bool,
    pub trace_reused: bool,
    pub product_reused: bool,
    pub transcript_entered: bool,
    pub transcript_completed: bool,
    pub product_entered: bool,
    pub product_completed: bool,
    pub publication_probes: usize,
    pub publication: &'static str,
}
impl From<ArithmeticObservation> for PublicArithmeticFactObservation {
    fn from(actual: ArithmeticObservation) -> Self {
        Self {
            lookup_probes: actual.lookup_probes,
            lookup_contended: actual.lookup_contended,
            exact_fact_found: actual.exact_fact_found,
            trace_reused: actual.trace_reused,
            product_reused: actual.product_reused,
            transcript_entered: actual.transcript_entered,
            transcript_completed: actual.transcript_completed,
            product_entered: actual.product_entered,
            product_completed: actual.product_completed,
            publication_probes: actual.publication_probes,
            publication: match actual.publication {
                ArithmeticPublication::None => "none",
                ArithmeticPublication::Trace => "trace",
                ArithmeticPublication::Product => "product",
                ArithmeticPublication::ExistingStrongerOrEqual => "existing-stronger-or-equal",
                ArithmeticPublication::Contended => "contended",
            },
        }
    }
}

#[cfg(test)]
mod tests;
