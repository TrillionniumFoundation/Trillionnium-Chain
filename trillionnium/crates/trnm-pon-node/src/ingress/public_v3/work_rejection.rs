//! Bounded mathematical refusals for the ordinary classical V3 service.
//!
//! Only a previously completed native Transcript/Product failure can return
//! early. Current Node context, caller authentication, paid body decoding and
//! the original deadline/cancellation/actual-CPU owner remain outside this hint.
//! Valid work and every unseen complete proof identity use the full verifier.
use super::*;
use trnm_crypto_primitives::pon_work::{
    rejection_cache::{
        RejectionCache, RejectionObservation, RejectionPublication, MAX_REJECTION_CACHE_LIFETIME,
        MAX_REJECTION_CACHE_SLOTS,
    },
    VerificationProgress,
};

impl PublicServer {
    /// Install one fresh bounded owner only at ordinary service startup, after
    /// original profile/Node/Host/intake admission and before workers start.
    /// Explicit trusted configuration wins. Setup creates no new CPU credit,
    /// lane, deadline, thread, durable row or successful verification fact.
    pub(super) fn install_default_w1_rejection_cache(&mut self) -> Result<()> {
        if !self.identity.is_pq()
            && !self.native_growth
            && self.arithmetic_facts.is_none()
            && self.w1_rejection_cache.is_none()
        {
            self.w1_rejection_cache = Some(
                RejectionCache::new(MAX_REJECTION_CACHE_SLOTS, MAX_REJECTION_CACHE_LIFETIME)
                    .ok_or("PUBLIC_W1_CACHE_LIMIT")?,
            );
        }
        Ok(())
    }
}

/// The legacy full_work CPU interval still includes the complete verification
/// attempt. These additional facts distinguish reused refusal from actual native
/// replay; CPU intervals remain nested and must never be added twice.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublicRejectionWorkObservation {
    pub schema: &'static str,
    pub slots: usize,
    pub retained_software_bytes: usize,
    /// Truncated display value only, not the complete configuration identity.
    /// A positive submillisecond explicit lifetime is legitimately displayed as 0.
    pub lifetime_ms: u64,
    /// Exact original Duration without a potentially overflowing total-ns cast.
    pub lifetime_seconds: u64,
    pub lifetime_subsec_nanos: u32,
    pub completed: bool,
    pub cache: Option<PublicRejectionFactObservation>,
}
impl PublicRejectionWorkObservation {
    fn started(cache: &RejectionCache) -> Self {
        Self {
            schema: "public-v3-work-rejection-observation-v1",
            slots: cache.capacity(),
            retained_software_bytes: cache.software_bytes(),
            // Constructor bounds lifetime to the original maximum 30 seconds.
            lifetime_ms: cache.lifetime().as_millis() as u64,
            lifetime_seconds: cache.lifetime().as_secs(),
            lifetime_subsec_nanos: cache.lifetime().subsec_nanos(),
            completed: false,
            cache: None,
        }
    }
    fn finished(cache: &RejectionCache, actual: RejectionObservation) -> Self {
        Self {
            completed: true,
            cache: Some(actual.into()),
            ..Self::started(cache)
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PublicRejectionFactObservation {
    pub key_hashed: bool,
    pub lookup_contended: bool,
    pub lookup_poisoned: bool,
    pub exact_fact_found: bool,
    pub cached_rejection_returned: bool,
    pub native_verifier_started: bool,
    pub native_verifier_returned: bool,
    /// The original verifier passed BeforeReplay; a cancelled/failed replay
    /// is still an actual started attempt, never a completed-work claim.
    pub full_replay_started: bool,
    pub publication: &'static str,
}
impl From<RejectionObservation> for PublicRejectionFactObservation {
    fn from(actual: RejectionObservation) -> Self {
        Self {
            key_hashed: actual.key_hashed,
            lookup_contended: actual.lookup_contended,
            lookup_poisoned: actual.lookup_poisoned,
            exact_fact_found: actual.exact_fact_found,
            cached_rejection_returned: actual.cached_rejection_returned,
            native_verifier_started: actual.native_verifier_started,
            native_verifier_returned: actual.native_verifier_returned,
            full_replay_started: actual.full_replay_started,
            publication: match actual.publication {
                RejectionPublication::None => "none",
                RejectionPublication::Retained => "retained",
                RejectionPublication::Contended => "contended",
                RejectionPublication::Poisoned => "poisoned",
            },
        }
    }
}

pub(super) fn verify(
    packet: crate::Packet,
    cache: &RejectionCache,
    progress: &mut impl FnMut(VerificationProgress) -> Result<()>,
    observation: Option<&TaskObservation>,
) -> Result<WorkCheckedPacket> {
    let Some(record) = observation else {
        return WorkCheckedPacket::verify_with_rejection_cache(packet, cache, progress);
    };
    record.work_rejection(PublicRejectionWorkObservation::started(cache));
    let mut actual = RejectionObservation::default();
    let result = WorkCheckedPacket::verify_with_rejection_cache_observed(
        packet,
        cache,
        progress,
        &mut actual,
    );
    record.work_rejection(PublicRejectionWorkObservation::finished(cache, actual));
    result
}

#[cfg(test)]
mod tests;
