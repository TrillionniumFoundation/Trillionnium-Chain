//! Typed transaction admission at the mempool boundary.
//!
//! The legacy [`crate::AdmissionGate`] intentionally accepts `u64` ids because it
//! is used by lane/fairness tests and by a small development binary.  That id is
//! not a transaction identity and must not become a consensus or replay key.
//!
//! This module adds a narrow adapter boundary for a real signed envelope without
//! inventing a wire format in the mempool crate.  A canonical transaction crate
//! implements [`SignedEnvelopeView`], and an owner of the canonical signature
//! authority implements [`SignedAdmissionHooks`].  The mempool receives only the
//! exact digest/body, signer identity, and bounded fee/resource metadata.  It
//! never receives a raw private key and it does not persist a durable consensus
//! decision.

use std::collections::HashMap;

use crate::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

/// The maximum body size used when a caller wants the canonical command-envelope
/// default.  This is an admission bound, not a consensus block-size parameter.
pub const DEFAULT_MAX_ADMISSION_BODY_BYTES: u64 = 1024 * 1024;

/// Opaque canonical transaction digest supplied by the canonical transaction
/// implementation.  The mempool deliberately does not hash or re-encode a body:
/// digest/body binding belongs to the signed-envelope verifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalTxDigest([u8; 32]);

impl CanonicalTxDigest {
    /// Construct a digest, rejecting the all-zero value used for absent evidence.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AdmissionReject> {
        if bytes == [0; 32] {
            return Err(AdmissionReject::ZeroDigest);
        }
        Ok(Self(bytes))
    }

    /// Return the exact digest bytes supplied by the canonical adapter.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque canonical signer/account identity used to scope replay and sequence
/// checks.  The mempool does not derive this value from a body, public key, or
/// private key: the canonical transaction adapter must supply the exact identity
/// that its signature/replay authority uses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalSignerId([u8; 32]);

impl CanonicalSignerId {
    /// Construct an identity, rejecting the all-zero value used for absent or
    /// unbound sequence evidence.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AdmissionReject> {
        if bytes == [0; 32] {
            return Err(AdmissionReject::ZeroSignerId);
        }
        Ok(Self(bytes))
    }

    /// Return the exact identity bytes supplied by the canonical adapter.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Resource claims carried by a canonical transaction.
///
/// `max_bytes` is the envelope body bound and `max_gas` is the execution bound.
/// Their meaning is intentionally limited to admission checks here; execution
/// policy and fee-market policy remain with the canonical runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_gas: u64,
    pub max_bytes: u64,
}

impl ResourceLimits {
    const fn validate(
        self,
        body_len: u64,
        configured_max_body_bytes: u64,
    ) -> Result<(), AdmissionReject> {
        if self.max_gas == 0 || self.max_bytes == 0 {
            return Err(AdmissionReject::InvalidResourceLimits);
        }
        if body_len > self.max_bytes || body_len > configured_max_body_bytes {
            return Err(AdmissionReject::ResourceLimitExceeded);
        }
        Ok(())
    }
}

/// Fail-closed reasons emitted before a transaction reaches a lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionReject {
    /// The source could not prove that its body is the canonical encoding.
    CanonicalValidationUnavailable,
    /// The source's canonical validation rejected its body/field binding.
    CanonicalValidationFailed,
    ZeroDigest,
    ZeroSignerId,
    SignerIdentityUnavailable,
    EmptyBody,
    BodyTooLarge,
    InvalidNonce,
    InvalidResourceLimits,
    ResourceLimitExceeded,
    SignatureUnavailable,
    SignatureRejected,
    ReplayCheckUnavailable,
    Replay,
    RecheckUnavailable,
    RecheckFailed,
    SlotIdExhausted,
}

/// A read-only view implemented by the canonical signed-envelope type.
///
/// The implementation must return the exact body bytes and digest that the
/// external verifier authenticated.  The default canonical check rejects, so a
/// missing adapter cannot silently downgrade to an opaque/raw transaction path.
pub trait SignedEnvelopeView {
    /// Exact digest of the complete signed transaction/envelope.
    fn canonical_digest(&self) -> CanonicalTxDigest;

    /// Exact canonical signer/account identity used to scope nonce/replay
    /// protection.  A missing adapter must remain fail-closed rather than
    /// silently collapsing all signers into one global nonce domain.
    fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
        Err(AdmissionReject::SignerIdentityUnavailable)
    }

    /// Exact canonical transaction body bytes, without normalization.
    fn canonical_body(&self) -> &[u8];

    /// Account/signer nonce from the canonical transaction.
    fn nonce(&self) -> u64;

    /// Fee limit from the canonical transaction.
    fn fee_limit(&self) -> u128;

    /// Declared execution and body resource bounds.
    fn resource_limits(&self) -> ResourceLimits;

    /// Prove canonical body/digest/field binding in the owning protocol crate.
    ///
    /// A mempool-only or fixture adapter must leave this default unchanged; it
    /// will be rejected rather than being mistaken for a canonical transaction.
    fn validate_canonical(&self) -> Result<(), AdmissionReject> {
        Err(AdmissionReject::CanonicalValidationUnavailable)
    }
}

/// Signature, replay, and state-recheck hooks owned by the caller's authority
/// layer.  No key material crosses this trait boundary.  Hooks are expected to
/// be read-only checks: a `Backpressured` result can occur after they run, and
/// this crate has no durable reservation/rollback protocol for hook side effects.
pub trait SignedAdmissionHooks<E: ?Sized> {
    /// Strictly authenticate the complete envelope, including digest/body
    /// binding.  `metadata` is the immutable snapshot that will be queued, so an
    /// adapter cannot accidentally verify one mutable view and enqueue another.
    /// Returning `SignatureUnavailable` is the required fail-closed behavior when
    /// no canonical signer adapter is installed.
    fn verify_signature(
        &mut self,
        envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<(), AdmissionReject>;

    /// Check durable or epoch-scoped nonce/replay state.  The metadata exposes a
    /// signer-scoped [`SignedEnvelopeMetadata::sequence_key`]; the caller still
    /// owns its chain/epoch domain and persistence.  The default rejects, so a
    /// caller must explicitly install a replay authority rather than silently
    /// treating an in-memory queue as durable nonce protection.
    fn check_replay(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        Err(AdmissionReject::ReplayCheckUnavailable)
    }

    /// Recheck current account/runtime admission state immediately before queue
    /// insertion.  The default rejects because no runtime state owner is wired
    /// into this crate.  This is deliberately separate from signature validation.
    fn recheck(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        Err(AdmissionReject::RecheckUnavailable)
    }
}

/// The validated, key-free metadata retained by the typed gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEnvelopeMetadata {
    digest: CanonicalTxDigest,
    signer_id: CanonicalSignerId,
    body: Vec<u8>,
    nonce: u64,
    fee_limit: u128,
    resource_limits: ResourceLimits,
}

impl SignedEnvelopeMetadata {
    pub const fn digest(&self) -> CanonicalTxDigest {
        self.digest
    }

    /// Canonical signer/account identity for replay and sequence scoping.
    pub const fn signer_id(&self) -> CanonicalSignerId {
        self.signer_id
    }

    /// Canonical sequence key that a durable replay authority must fence.
    /// Keeping the signer and nonce together prevents adapters from accidentally
    /// treating a nonce as a chain-wide/global counter.
    pub const fn sequence_key(&self) -> (CanonicalSignerId, u64) {
        (self.signer_id, self.nonce)
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub const fn fee_limit(&self) -> u128 {
        self.fee_limit
    }

    pub const fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }
}

/// Result of typed admission.  The legacy [`AdmitOutcome`] remains unchanged for
/// callers that have not migrated from integer ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedAdmitOutcome {
    Accepted,
    Duplicate,
    Backpressured,
    Rejected(AdmissionReject),
}

/// Lane-aware typed admission gate.
///
/// This owns only an in-memory queue of validated metadata.  It is intentionally
/// not a WAL, mempool database, consensus executor, or durable replay authority.
/// A future node owner may use `pop_ready()` as an input to those components after
/// independently implementing the corresponding persistence protocol.
#[derive(Debug)]
pub struct TypedAdmissionGate {
    lanes: LaneAdmissionGate,
    max_body_bytes: u64,
    next_slot: u64,
    by_slot: HashMap<u64, SignedEnvelopeMetadata>,
    slot_by_digest: HashMap<CanonicalTxDigest, u64>,
}

impl TypedAdmissionGate {
    pub fn new(total_capacity: usize, critical_reserve: usize, max_body_bytes: u64) -> Self {
        Self {
            lanes: LaneAdmissionGate::new(total_capacity, critical_reserve),
            max_body_bytes,
            next_slot: 1,
            by_slot: HashMap::with_capacity(total_capacity),
            slot_by_digest: HashMap::with_capacity(total_capacity),
        }
    }

    pub fn with_default_body_limit(total_capacity: usize, critical_reserve: usize) -> Self {
        Self::new(
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
        )
    }

    pub fn queued_counts(&self) -> (usize, usize, usize) {
        self.lanes.queued_counts()
    }

    pub fn qos_snapshot(&self) -> LaneQosSnapshot {
        self.lanes.qos_snapshot()
    }

    pub fn contains_digest(&self, digest: CanonicalTxDigest) -> bool {
        self.slot_by_digest.contains_key(&digest)
    }

    /// Admit a canonical signed envelope after strict signature/replay/recheck
    /// hooks have run.  The envelope itself is not retained, only exact body
    /// bytes plus typed metadata needed by downstream execution.
    pub fn admit_signed<E, H>(
        &mut self,
        envelope: &E,
        class: IngressClass,
        hooks: &mut H,
    ) -> TypedAdmitOutcome
    where
        E: SignedEnvelopeView + ?Sized,
        H: SignedAdmissionHooks<E>,
    {
        let digest = envelope.canonical_digest();
        if self.slot_by_digest.contains_key(&digest) {
            return TypedAdmitOutcome::Duplicate;
        }

        let metadata = match self.metadata_from(envelope) {
            Ok(metadata) => metadata,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };

        if let Err(reason) = hooks.verify_signature(envelope, &metadata) {
            return TypedAdmitOutcome::Rejected(reason);
        }
        if let Err(reason) = hooks.check_replay(&metadata) {
            return TypedAdmitOutcome::Rejected(reason);
        }
        if let Err(reason) = hooks.recheck(&metadata) {
            return TypedAdmitOutcome::Rejected(reason);
        }

        // Do not allocate a synthetic slot or mutate retry bookkeeping when the
        // lane is already closed.  Duplicate classification above remains stable.
        let snapshot = self.lanes.qos_snapshot();
        let fresh_admissible = match class {
            IngressClass::Normal => snapshot.fresh_normal_admissible,
            IngressClass::Critical => snapshot.fresh_critical_admissible,
        };
        if !fresh_admissible {
            return TypedAdmitOutcome::Backpressured;
        }

        let slot = match self.allocate_slot() {
            Ok(slot) => slot,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        match self.lanes.admit(slot, class) {
            AdmitOutcome::Accepted => {
                self.slot_by_digest.insert(metadata.digest, slot);
                self.by_slot.insert(slot, metadata);
                TypedAdmitOutcome::Accepted
            }
            AdmitOutcome::Duplicate => TypedAdmitOutcome::Duplicate,
            AdmitOutcome::Backpressured => TypedAdmitOutcome::Backpressured,
        }
    }

    /// Pop the next ready metadata record.  This is an in-memory handoff only;
    /// callers must persist/commit it in their own canonical owner.
    pub fn pop_ready(&mut self) -> Option<SignedEnvelopeMetadata> {
        let slot = self.lanes.pop_ready()?;
        let metadata = self.by_slot.remove(&slot)?;
        self.slot_by_digest.remove(&metadata.digest);
        Some(metadata)
    }

    fn metadata_from<E: SignedEnvelopeView + ?Sized>(
        &self,
        envelope: &E,
    ) -> Result<SignedEnvelopeMetadata, AdmissionReject> {
        envelope.validate_canonical()?;
        let digest = envelope.canonical_digest();
        // Re-check here because a caller-provided view can be backed by mutable
        // state; all-zero is reserved for absent/unbound digest evidence.
        CanonicalTxDigest::from_bytes(digest.as_bytes())?;
        let signer_id = envelope.canonical_signer_id()?;

        let body = envelope.canonical_body();
        if body.is_empty() {
            return Err(AdmissionReject::EmptyBody);
        }
        let body_len = u64::try_from(body.len()).map_err(|_| AdmissionReject::BodyTooLarge)?;
        if body_len > self.max_body_bytes {
            return Err(AdmissionReject::BodyTooLarge);
        }
        let nonce = envelope.nonce();
        if nonce == 0 {
            return Err(AdmissionReject::InvalidNonce);
        }
        let resource_limits = envelope.resource_limits();
        resource_limits.validate(body_len, self.max_body_bytes)?;

        Ok(SignedEnvelopeMetadata {
            digest,
            signer_id,
            body: body.to_vec(),
            nonce,
            fee_limit: envelope.fee_limit(),
            resource_limits,
        })
    }

    fn allocate_slot(&mut self) -> Result<u64, AdmissionReject> {
        // Active slots are bounded by the configured queue capacity.  This loop
        // also makes wraparound fail closed instead of reusing an active id.
        for _ in 0..=self.by_slot.len().saturating_add(1) {
            let candidate = self.next_slot;
            self.next_slot = self.next_slot.checked_add(1).unwrap_or(1);
            if candidate != 0 && !self.by_slot.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(AdmissionReject::SlotIdExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureEnvelope {
        digest: CanonicalTxDigest,
        signer_id: Option<CanonicalSignerId>,
        body: Vec<u8>,
        nonce: u64,
        fee_limit: u128,
        resources: ResourceLimits,
        canonical: bool,
    }

    impl SignedEnvelopeView for FixtureEnvelope {
        fn canonical_digest(&self) -> CanonicalTxDigest {
            self.digest
        }

        fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
            self.signer_id
                .ok_or(AdmissionReject::SignerIdentityUnavailable)
        }

        fn canonical_body(&self) -> &[u8] {
            &self.body
        }

        fn nonce(&self) -> u64 {
            self.nonce
        }

        fn fee_limit(&self) -> u128 {
            self.fee_limit
        }

        fn resource_limits(&self) -> ResourceLimits {
            self.resources
        }

        fn validate_canonical(&self) -> Result<(), AdmissionReject> {
            self.canonical
                .then_some(())
                .ok_or(AdmissionReject::CanonicalValidationFailed)
        }
    }

    #[derive(Default)]
    struct Hooks {
        signature_ok: bool,
        replay: bool,
        recheck: bool,
        verify_calls: usize,
        replay_calls: usize,
        recheck_calls: usize,
    }

    impl SignedAdmissionHooks<FixtureEnvelope> for Hooks {
        fn verify_signature(
            &mut self,
            _envelope: &FixtureEnvelope,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            self.verify_calls += 1;
            self.signature_ok
                .then_some(())
                .ok_or(AdmissionReject::SignatureRejected)
        }

        fn check_replay(
            &mut self,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            self.replay_calls += 1;
            (!self.replay).then_some(()).ok_or(AdmissionReject::Replay)
        }

        fn recheck(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
            self.recheck_calls += 1;
            self.recheck
                .then_some(())
                .ok_or(AdmissionReject::RecheckFailed)
        }
    }

    fn digest(byte: u8) -> CanonicalTxDigest {
        CanonicalTxDigest::from_bytes([byte; 32]).unwrap()
    }

    fn signer(byte: u8) -> CanonicalSignerId {
        CanonicalSignerId::from_bytes([byte; 32]).unwrap()
    }

    fn envelope(byte: u8) -> FixtureEnvelope {
        FixtureEnvelope {
            digest: digest(byte),
            signer_id: Some(signer(1)),
            body: b"exact-canonical-body".to_vec(),
            nonce: 1,
            fee_limit: 17,
            resources: ResourceLimits {
                max_gas: 10_000,
                max_bytes: 128,
            },
            canonical: true,
        }
    }

    fn accepting_hooks() -> Hooks {
        Hooks {
            signature_ok: true,
            recheck: true,
            ..Hooks::default()
        }
    }

    #[test]
    fn typed_gate_retains_exact_metadata_and_dedupes_digest_across_lanes() {
        let mut gate = TypedAdmissionGate::new(2, 1, 128);
        let first = envelope(1);
        let mut hooks = accepting_hooks();

        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert!(gate.contains_digest(first.digest));
        assert_eq!(
            gate.admit_signed(&first, IngressClass::Critical, &mut hooks),
            TypedAdmitOutcome::Duplicate
        );
        assert_eq!(
            (hooks.verify_calls, hooks.replay_calls, hooks.recheck_calls),
            (1, 1, 1)
        );

        let ready = gate.pop_ready().expect("accepted metadata");
        assert_eq!(ready.digest(), first.digest);
        assert_eq!(ready.signer_id(), first.signer_id.unwrap());
        assert_eq!(ready.body(), first.body.as_slice());
        assert_eq!(ready.nonce(), first.nonce);
        assert_eq!(ready.fee_limit(), first.fee_limit);
        assert_eq!(ready.resource_limits(), first.resources);
        assert!(!gate.contains_digest(first.digest));
    }

    #[test]
    fn missing_canonical_validation_fails_closed_before_signature_hook() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut candidate = envelope(2);
        candidate.canonical = false;
        let mut hooks = accepting_hooks();

        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed)
        );
        assert_eq!(hooks.verify_calls, 0);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn missing_signer_identity_fails_closed_before_signature_hook() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut candidate = envelope(21);
        candidate.signer_id = None;
        let mut hooks = accepting_hooks();

        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );
        assert_eq!(hooks.verify_calls, 0);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn replay_hook_can_scope_nonce_to_canonical_signer_identity() {
        use std::collections::HashSet;

        #[derive(Default)]
        struct SequenceHooks {
            seen: HashSet<(CanonicalSignerId, u64)>,
        }

        impl SignedAdmissionHooks<FixtureEnvelope> for SequenceHooks {
            fn verify_signature(
                &mut self,
                _envelope: &FixtureEnvelope,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                Ok(())
            }

            fn check_replay(
                &mut self,
                metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                self.seen
                    .insert(metadata.sequence_key())
                    .then_some(())
                    .ok_or(AdmissionReject::Replay)
            }

            fn recheck(
                &mut self,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                Ok(())
            }
        }

        let mut gate = TypedAdmissionGate::with_default_body_limit(3, 0);
        let mut first = envelope(22);
        first.signer_id = Some(signer(1));
        let mut other_signer = envelope(23);
        other_signer.signer_id = Some(signer(2));
        let mut same_signer_replay = envelope(24);
        same_signer_replay.signer_id = Some(signer(1));
        let mut hooks = SequenceHooks::default();

        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(
            gate.admit_signed(&other_signer, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(
            gate.admit_signed(&same_signer_replay, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        assert_eq!(gate.queued_counts(), (2, 0, 2));
    }

    #[test]
    fn signature_replay_and_recheck_hooks_each_fail_closed() {
        let candidate = envelope(3);

        let mut signature_hooks = accepting_hooks();
        signature_hooks.signature_ok = false;
        let mut gate = TypedAdmissionGate::with_default_body_limit(3, 0);
        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut signature_hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignatureRejected)
        );

        let mut replay_hooks = accepting_hooks();
        replay_hooks.replay = true;
        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut replay_hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );

        let mut recheck_hooks = accepting_hooks();
        recheck_hooks.recheck = false;
        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut recheck_hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::RecheckFailed)
        );
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn malformed_body_nonce_and_resource_claims_are_rejected() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = accepting_hooks();

        let mut empty = envelope(4);
        empty.body.clear();
        assert_eq!(
            gate.admit_signed(&empty, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::EmptyBody)
        );

        let mut zero_nonce = envelope(5);
        zero_nonce.nonce = 0;
        assert_eq!(
            gate.admit_signed(&zero_nonce, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::InvalidNonce)
        );

        let mut zero_resources = envelope(6);
        zero_resources.resources.max_gas = 0;
        assert_eq!(
            gate.admit_signed(&zero_resources, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::InvalidResourceLimits)
        );

        let mut too_small = envelope(7);
        too_small.resources.max_bytes = 1;
        assert_eq!(
            gate.admit_signed(&too_small, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::ResourceLimitExceeded)
        );
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn valid_fresh_envelope_backpressures_without_mutating_digest_index() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(1, 0);
        let first = envelope(8);
        let second = envelope(9);
        let mut hooks = accepting_hooks();
        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(
            gate.admit_signed(&second, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Backpressured
        );
        assert!(!gate.contains_digest(second.digest));
        assert_eq!(gate.queued_counts(), (1, 0, 1));
    }

    struct SignatureOnlyHooks;

    impl SignedAdmissionHooks<FixtureEnvelope> for SignatureOnlyHooks {
        fn verify_signature(
            &mut self,
            _envelope: &FixtureEnvelope,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    #[test]
    fn omitted_replay_or_recheck_authority_is_not_an_acceptance_path() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(1, 0);
        let candidate = envelope(10);
        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut SignatureOnlyHooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::ReplayCheckUnavailable)
        );
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }
}
