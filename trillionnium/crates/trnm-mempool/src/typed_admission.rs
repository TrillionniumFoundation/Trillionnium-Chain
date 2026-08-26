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
use std::fmt;

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
    /// A mutable adapter view returned a different digest between the
    /// duplicate probe and metadata snapshot.
    CanonicalDigestChanged,
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
    /// A lifecycle operation was requested for an admission without a
    /// reservation token (for example, an item admitted through the legacy
    /// read-only API).
    ReservationUnavailable,
    /// A reservation lifecycle operation was requested in the wrong state.
    ReservationStateConflict,
    SlotIdExhausted,
    InconsistentState,
}

/// The externally-owned lifecycle state for one pending account nonce.
///
/// The mempool only moves a reservation between these states; the authority
/// behind [`PendingNonceReservation`] owns the durable meaning of each
/// transition.  In particular, this type is not a persisted replay index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingNonceReservationState {
    Reserved,
    HandedOff,
    Committed,
    Released,
}

/// A key-free lifecycle token returned by a pending-nonce authority.
///
/// Implementations must make each operation idempotent at their own durable
/// boundary.  The typed gate invokes at most one successful transition of each
/// kind for a token and drops an unresolved token through `release` so a caller
/// cannot accidentally leave a reservation owned only by the in-memory queue.
pub trait PendingNonceReservation: fmt::Debug {
    /// Return a process-local owner binding for the durable authority that
    /// created this token.  The value is deliberately opaque and is not a
    /// consensus identity; it only prevents a node boundary from applying a
    /// token created by a different local WAL owner.  Implementations which
    /// cannot provide an owner binding return `None`, and callers that need a
    /// split-brain-safe commit must reject such tokens.
    fn owner_binding(&self) -> Option<u64> {
        None
    }

    /// Transfer the queued transaction to the execution owner.
    fn handoff(&mut self) -> Result<(), AdmissionReject>;

    /// Mark execution as durably committed.
    fn commit(&mut self) -> Result<(), AdmissionReject>;

    /// Release/cancel the pending nonce reservation.
    fn release(&mut self) -> Result<(), AdmissionReject>;
}

/// Authority hook for the opt-in pending-nonce admission path.
///
/// The authority receives the exact authenticated metadata and may keep its
/// reservation in a durable store.  The mempool stores only the opaque token;
/// it has no signing key, WAL, or consensus-executor role.  The legacy
/// [`SignedAdmissionHooks::check_replay`] path remains available for callers
/// that have not migrated to lifecycle tokens, but it is intentionally
/// read-only and cannot provide this rollback/handoff contract.
pub trait PendingNonceAuthority<E: ?Sized> {
    /// Reserve `(signer_id, nonce)` for this exact digest.
    fn reserve_pending_nonce(
        &mut self,
        envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject>;
}

#[derive(Debug)]
struct PendingNonceLease {
    reservation: Option<Box<dyn PendingNonceReservation>>,
    state: PendingNonceReservationState,
}

impl PendingNonceLease {
    fn new(reservation: Box<dyn PendingNonceReservation>) -> Self {
        Self {
            reservation: Some(reservation),
            state: PendingNonceReservationState::Reserved,
        }
    }

    fn state(&self) -> PendingNonceReservationState {
        self.state
    }

    fn owner_binding(&self) -> Option<u64> {
        self.reservation
            .as_ref()
            .and_then(|reservation| reservation.owner_binding())
    }

    fn handoff(&mut self) -> Result<(), AdmissionReject> {
        if self.state != PendingNonceReservationState::Reserved {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        let reservation = self
            .reservation
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?;
        reservation.handoff()?;
        self.state = PendingNonceReservationState::HandedOff;
        Ok(())
    }

    fn commit(&mut self) -> Result<(), AdmissionReject> {
        if self.state != PendingNonceReservationState::HandedOff {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        let reservation = self
            .reservation
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?;
        reservation.commit()?;
        self.state = PendingNonceReservationState::Committed;
        self.reservation.take();
        Ok(())
    }

    fn release(&mut self) -> Result<(), AdmissionReject> {
        match self.state {
            PendingNonceReservationState::Reserved | PendingNonceReservationState::HandedOff => {}
            PendingNonceReservationState::Committed | PendingNonceReservationState::Released => {
                return Err(AdmissionReject::ReservationStateConflict)
            }
        }

        // Mark the local state before calling out.  A failing authority call is
        // terminal for this in-memory token; retry/recovery belongs to the
        // authority's durable idempotency protocol, and Drop must not invoke a
        // second release callback.
        self.state = PendingNonceReservationState::Released;
        let Some(mut reservation) = self.reservation.take() else {
            return Err(AdmissionReject::ReservationUnavailable);
        };
        reservation.release()
    }

    fn cancel(&mut self) -> Result<(), AdmissionReject> {
        if self.state != PendingNonceReservationState::Reserved {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.release()
    }
}

impl Drop for PendingNonceLease {
    fn drop(&mut self) {
        if matches!(
            self.state,
            PendingNonceReservationState::Reserved | PendingNonceReservationState::HandedOff
        ) {
            let _ = self.release();
        }
    }
}

/// A ready queue item carrying its pending-nonce lifecycle token.
///
/// Use [`Self::handoff`] before execution and [`Self::commit`] after the
/// execution owner durably commits.  Dropping an unresolved item releases its
/// reservation; explicit [`Self::cancel`] is the preferred abort path.
#[must_use = "drop or resolve the ready admission explicitly"]
#[derive(Debug)]
pub struct PendingNonceAdmission {
    metadata: SignedEnvelopeMetadata,
    lease: Option<PendingNonceLease>,
}

impl PendingNonceAdmission {
    fn new(metadata: SignedEnvelopeMetadata, lease: Option<PendingNonceLease>) -> Self {
        Self { metadata, lease }
    }

    /// Return the exact queued metadata without re-encoding its body.
    pub const fn metadata(&self) -> &SignedEnvelopeMetadata {
        &self.metadata
    }

    /// Consume the item and return metadata.  Any unresolved lifecycle token is
    /// released as the item is dropped.
    pub fn into_metadata(self) -> SignedEnvelopeMetadata {
        let Self { metadata, lease } = self;
        drop(lease);
        metadata
    }

    pub fn reservation_state(&self) -> Result<PendingNonceReservationState, AdmissionReject> {
        self.lease
            .as_ref()
            .map(PendingNonceLease::state)
            .ok_or(AdmissionReject::ReservationUnavailable)
    }

    /// Return the opaque process-local owner binding of the durable
    /// reservation.  A node owner should compare this with its own authority
    /// before performing a durable commit; `None` is intentionally not a
    /// wildcard because an unbound token cannot prove same-owner lifecycle.
    pub fn owner_binding(&self) -> Option<u64> {
        self.lease
            .as_ref()
            .and_then(PendingNonceLease::owner_binding)
    }

    pub fn handoff(&mut self) -> Result<(), AdmissionReject> {
        self.lease
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?
            .handoff()
    }

    pub fn commit(&mut self) -> Result<(), AdmissionReject> {
        self.lease
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?
            .commit()
    }

    pub fn release(&mut self) -> Result<(), AdmissionReject> {
        self.lease
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?
            .release()
    }

    /// Cancel a reservation that has not yet been handed to execution.
    pub fn cancel(&mut self) -> Result<(), AdmissionReject> {
        self.lease
            .as_mut()
            .ok_or(AdmissionReject::ReservationUnavailable)?
            .cancel()
    }
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
    pending_reservations: HashMap<u64, PendingNonceLease>,
}

impl TypedAdmissionGate {
    pub fn new(total_capacity: usize, critical_reserve: usize, max_body_bytes: u64) -> Self {
        Self {
            lanes: LaneAdmissionGate::new(total_capacity, critical_reserve),
            max_body_bytes,
            next_slot: 1,
            by_slot: HashMap::with_capacity(total_capacity),
            slot_by_digest: HashMap::with_capacity(total_capacity),
            pending_reservations: HashMap::with_capacity(total_capacity),
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

    /// Snapshot the exact key-free metadata for a canonical view without
    /// reserving capacity, invoking signature hooks, or touching a replay
    /// authority.  This is used by an authenticated restart owner when it
    /// reconstructs a durable handoff from an application readback; callers
    /// must still perform their node-owned signature/context checks before
    /// treating the result as recovery evidence.
    pub fn canonical_metadata_v0<E>(
        &self,
        envelope: &E,
    ) -> Result<SignedEnvelopeMetadata, AdmissionReject>
    where
        E: SignedEnvelopeView + ?Sized,
    {
        let digest = envelope.canonical_digest();
        self.metadata_from(envelope, digest)
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
        if let Some(&slot) = self.slot_by_digest.get(&digest) {
            return match self.validate_duplicate(envelope, digest, slot) {
                Ok(()) => TypedAdmitOutcome::Duplicate,
                Err(reason) => TypedAdmitOutcome::Rejected(reason),
            };
        }

        // Capacity is a pure queue-state decision.  Resolve it before copying
        // the body or invoking any caller hook: a saturated fresh retry must
        // be a cheap, side-effect-free Backpressured result.  In particular,
        // replay authorities must not reserve a nonce that this in-memory gate
        // cannot enqueue and therefore cannot commit or roll back.
        let snapshot = self.lanes.qos_snapshot();
        let fresh_admissible = match class {
            IngressClass::Normal => snapshot.fresh_normal_admissible,
            IngressClass::Critical => snapshot.fresh_critical_admissible,
        };
        if !fresh_admissible {
            return TypedAdmitOutcome::Backpressured;
        }

        let metadata = match self.metadata_from(envelope, digest) {
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

    /// Opt-in admission path with an explicit pending-nonce lifecycle.
    ///
    /// Capacity is checked before any authority callback.  After strict
    /// signature verification, the authority reserves the signer/nonce pair;
    /// every later rejection releases that reservation exactly once.  Accepted
    /// entries are returned by [`Self::pop_ready_with_lifecycle`], where the
    /// caller must hand off and commit (or cancel) the opaque reservation.
    ///
    /// This method deliberately does not call [`SignedAdmissionHooks::check_replay`]:
    /// `PendingNonceAuthority::reserve_pending_nonce` is the two-phase replay
    /// boundary for this opt-in API.  The old `admit_signed` method remains
    /// source-compatible for read-only hook users.
    pub fn admit_signed_with_pending_nonce<E, H, A>(
        &mut self,
        envelope: &E,
        class: IngressClass,
        hooks: &mut H,
        authority: &mut A,
    ) -> TypedAdmitOutcome
    where
        E: SignedEnvelopeView + ?Sized,
        H: SignedAdmissionHooks<E>,
        A: PendingNonceAuthority<E>,
    {
        let digest = envelope.canonical_digest();
        if let Some(&slot) = self.slot_by_digest.get(&digest) {
            return match self.validate_duplicate(envelope, digest, slot) {
                Ok(()) => TypedAdmitOutcome::Duplicate,
                Err(reason) => TypedAdmitOutcome::Rejected(reason),
            };
        }

        // Keep the side-effect-free saturation rule identical to the legacy
        // typed path: a fresh retry must not reserve a nonce for work that
        // cannot enter this in-memory queue.
        let snapshot = self.lanes.qos_snapshot();
        let fresh_admissible = match class {
            IngressClass::Normal => snapshot.fresh_normal_admissible,
            IngressClass::Critical => snapshot.fresh_critical_admissible,
        };
        if !fresh_admissible {
            return TypedAdmitOutcome::Backpressured;
        }

        let metadata = match self.metadata_from(envelope, digest) {
            Ok(metadata) => metadata,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };

        if let Err(reason) = hooks.verify_signature(envelope, &metadata) {
            return TypedAdmitOutcome::Rejected(reason);
        }

        let mut lease = match authority.reserve_pending_nonce(envelope, &metadata) {
            Ok(reservation) => PendingNonceLease::new(reservation),
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };

        if let Err(reason) = hooks.recheck(&metadata) {
            let _ = lease.release();
            return TypedAdmitOutcome::Rejected(reason);
        }

        let slot = match self.allocate_slot() {
            Ok(slot) => slot,
            Err(reason) => {
                let _ = lease.release();
                return TypedAdmitOutcome::Rejected(reason);
            }
        };
        match self.lanes.admit(slot, class) {
            AdmitOutcome::Accepted => {
                self.slot_by_digest.insert(metadata.digest, slot);
                self.by_slot.insert(slot, metadata);
                self.pending_reservations.insert(slot, lease);
                TypedAdmitOutcome::Accepted
            }
            AdmitOutcome::Duplicate => {
                let _ = lease.release();
                TypedAdmitOutcome::Duplicate
            }
            AdmitOutcome::Backpressured => {
                let _ = lease.release();
                TypedAdmitOutcome::Backpressured
            }
        }
    }

    /// Pop the next ready metadata record.  This is an in-memory handoff only;
    /// callers must persist/commit it in their own canonical owner.  If the
    /// item came through the lifecycle API, dropping the associated token here
    /// cancels/releases it; use [`Self::pop_ready_with_lifecycle`] when the
    /// execution owner needs to hand it off and commit it explicitly.
    pub fn pop_ready(&mut self) -> Option<SignedEnvelopeMetadata> {
        let (metadata, _lease) = self.pop_ready_parts()?;
        Some(metadata)
    }

    /// Pop a queue item together with its pending-nonce lifecycle token.
    ///
    /// Legacy `admit_signed` entries have no token; lifecycle methods on the
    /// returned value then fail with [`AdmissionReject::ReservationUnavailable`].
    pub fn pop_ready_with_lifecycle(&mut self) -> Option<PendingNonceAdmission> {
        let (metadata, lease) = self.pop_ready_parts()?;
        Some(PendingNonceAdmission::new(metadata, lease))
    }

    fn pop_ready_parts(&mut self) -> Option<(SignedEnvelopeMetadata, Option<PendingNonceLease>)> {
        let slot = self.lanes.pop_ready()?;
        let metadata = self.by_slot.remove(&slot);
        // Always remove/drop a reservation even if a restored queue/index
        // mismatch means the metadata record is absent.
        let lease = self.pending_reservations.remove(&slot);
        let metadata = metadata?;
        self.slot_by_digest.remove(&metadata.digest);
        Some((metadata, lease))
    }

    fn metadata_from<E: SignedEnvelopeView + ?Sized>(
        &self,
        envelope: &E,
        probed_digest: CanonicalTxDigest,
    ) -> Result<SignedEnvelopeMetadata, AdmissionReject> {
        envelope.validate_canonical()?;
        let digest = envelope.canonical_digest();
        if digest != probed_digest {
            return Err(AdmissionReject::CanonicalDigestChanged);
        }
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

    /// Revalidate an exact duplicate without invoking signature/replay hooks or
    /// cloning a second body.  A digest hit is not permission to skip the
    /// canonical adapter boundary: mutable or forged views must not turn a
    /// queued digest into a blanket acceptance path.
    fn validate_duplicate<E: SignedEnvelopeView + ?Sized>(
        &self,
        envelope: &E,
        probed_digest: CanonicalTxDigest,
        slot: u64,
    ) -> Result<(), AdmissionReject> {
        envelope.validate_canonical()?;
        let digest = envelope.canonical_digest();
        if digest != probed_digest {
            return Err(AdmissionReject::CanonicalDigestChanged);
        }
        CanonicalTxDigest::from_bytes(digest.as_bytes())?;
        let signer_id = envelope.canonical_signer_id()?;
        let queued = self
            .by_slot
            .get(&slot)
            .ok_or(AdmissionReject::InconsistentState)?;
        if queued.digest != digest || queued.signer_id != signer_id {
            return Err(AdmissionReject::CanonicalValidationFailed);
        }

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
        if queued.body != body
            || queued.nonce != nonce
            || queued.fee_limit != envelope.fee_limit()
            || queued.resource_limits != resource_limits
        {
            return Err(AdmissionReject::CanonicalValidationFailed);
        }
        Ok(())
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

    #[derive(Debug, Default)]
    struct ReservationLog {
        reserve_calls: usize,
        handoff_calls: usize,
        commit_calls: usize,
        release_calls: usize,
        active: std::collections::HashSet<(CanonicalSignerId, u64)>,
        handed_off: std::collections::HashSet<(CanonicalSignerId, u64)>,
        committed: std::collections::HashSet<(CanonicalSignerId, u64)>,
    }

    #[derive(Clone, Debug, Default)]
    struct FixturePendingNonceAuthority {
        log: std::rc::Rc<std::cell::RefCell<ReservationLog>>,
        reject_reservation: bool,
    }

    #[derive(Debug)]
    struct FixturePendingNonceReservation {
        log: std::rc::Rc<std::cell::RefCell<ReservationLog>>,
        key: (CanonicalSignerId, u64),
    }

    impl PendingNonceReservation for FixturePendingNonceReservation {
        fn handoff(&mut self) -> Result<(), AdmissionReject> {
            let mut log = self.log.borrow_mut();
            log.handoff_calls += 1;
            if !log.active.remove(&self.key) {
                return Err(AdmissionReject::InconsistentState);
            }
            log.handed_off.insert(self.key);
            Ok(())
        }

        fn commit(&mut self) -> Result<(), AdmissionReject> {
            let mut log = self.log.borrow_mut();
            log.commit_calls += 1;
            if !log.handed_off.remove(&self.key) {
                return Err(AdmissionReject::InconsistentState);
            }
            log.committed.insert(self.key);
            Ok(())
        }

        fn release(&mut self) -> Result<(), AdmissionReject> {
            let mut log = self.log.borrow_mut();
            log.release_calls += 1;
            let removed = log.active.remove(&self.key) || log.handed_off.remove(&self.key);
            removed
                .then_some(())
                .ok_or(AdmissionReject::InconsistentState)
        }
    }

    impl PendingNonceAuthority<FixtureEnvelope> for FixturePendingNonceAuthority {
        fn reserve_pending_nonce(
            &mut self,
            _envelope: &FixtureEnvelope,
            metadata: &SignedEnvelopeMetadata,
        ) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject> {
            let mut log = self.log.borrow_mut();
            log.reserve_calls += 1;
            if self.reject_reservation {
                return Err(AdmissionReject::ReplayCheckUnavailable);
            }
            let key = metadata.sequence_key();
            if log.active.contains(&key)
                || log.handed_off.contains(&key)
                || log.committed.contains(&key)
            {
                return Err(AdmissionReject::Replay);
            }
            log.active.insert(key);
            Ok(Box::new(FixturePendingNonceReservation {
                log: std::rc::Rc::clone(&self.log),
                key,
            }))
        }
    }

    fn lifecycle_authority() -> FixturePendingNonceAuthority {
        FixturePendingNonceAuthority {
            log: std::rc::Rc::new(std::cell::RefCell::new(ReservationLog::default())),
            reject_reservation: false,
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
    fn mutable_envelope_digest_cannot_change_between_probe_and_snapshot() {
        use std::cell::Cell;

        struct RotatingDigestEnvelope {
            inner: FixtureEnvelope,
            digest_calls: Cell<usize>,
        }

        impl SignedEnvelopeView for RotatingDigestEnvelope {
            fn canonical_digest(&self) -> CanonicalTxDigest {
                let call = self.digest_calls.get();
                self.digest_calls.set(call.saturating_add(1));
                if call == 0 {
                    digest(31)
                } else {
                    digest(32)
                }
            }

            fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
                self.inner.canonical_signer_id()
            }

            fn canonical_body(&self) -> &[u8] {
                self.inner.canonical_body()
            }

            fn nonce(&self) -> u64 {
                self.inner.nonce()
            }

            fn fee_limit(&self) -> u128 {
                self.inner.fee_limit()
            }

            fn resource_limits(&self) -> ResourceLimits {
                self.inner.resource_limits()
            }

            fn validate_canonical(&self) -> Result<(), AdmissionReject> {
                self.inner.validate_canonical()
            }
        }

        #[derive(Default)]
        struct RotatingHooks {
            verify_calls: usize,
        }

        impl SignedAdmissionHooks<RotatingDigestEnvelope> for RotatingHooks {
            fn verify_signature(
                &mut self,
                _envelope: &RotatingDigestEnvelope,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                self.verify_calls += 1;
                Ok(())
            }
        }

        let candidate = RotatingDigestEnvelope {
            inner: envelope(31),
            digest_calls: Cell::new(0),
        };
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = RotatingHooks::default();
        assert_eq!(
            gate.admit_signed(&candidate, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalDigestChanged)
        );
        assert_eq!(hooks.verify_calls, 0);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert!(!gate.contains_digest(digest(31)));
        assert!(!gate.contains_digest(digest(32)));
    }

    #[test]
    fn duplicate_probe_revalidates_canonical_identity_and_queued_metadata() {
        use std::cell::Cell;

        struct DuplicateRotatingDigestEnvelope {
            inner: FixtureEnvelope,
            digest_calls: Cell<usize>,
        }

        impl SignedEnvelopeView for DuplicateRotatingDigestEnvelope {
            fn canonical_digest(&self) -> CanonicalTxDigest {
                let call = self.digest_calls.get();
                self.digest_calls.set(call.saturating_add(1));
                if call == 0 {
                    self.inner.digest
                } else {
                    digest(33)
                }
            }

            fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
                self.inner.canonical_signer_id()
            }

            fn canonical_body(&self) -> &[u8] {
                self.inner.canonical_body()
            }

            fn nonce(&self) -> u64 {
                self.inner.nonce()
            }

            fn fee_limit(&self) -> u128 {
                self.inner.fee_limit()
            }

            fn resource_limits(&self) -> ResourceLimits {
                self.inner.resource_limits()
            }

            fn validate_canonical(&self) -> Result<(), AdmissionReject> {
                self.inner.validate_canonical()
            }
        }

        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let first = envelope(32);
        let mut hooks = accepting_hooks();
        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );

        let rotating = DuplicateRotatingDigestEnvelope {
            inner: first,
            digest_calls: Cell::new(0),
        };
        struct DuplicateHooks;
        impl SignedAdmissionHooks<DuplicateRotatingDigestEnvelope> for DuplicateHooks {
            fn verify_signature(
                &mut self,
                _envelope: &DuplicateRotatingDigestEnvelope,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                Ok(())
            }
        }
        let mut duplicate_hooks = DuplicateHooks;
        assert_eq!(
            gate.admit_signed(&rotating, IngressClass::Normal, &mut duplicate_hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalDigestChanged)
        );
        assert_eq!(gate.queued_counts(), (1, 0, 1));

        let mut missing_signer = envelope(32);
        missing_signer.signer_id = None;
        assert_eq!(
            gate.admit_signed(&missing_signer, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );

        let mut changed_body = envelope(32);
        changed_body.body = b"different-body".to_vec();
        assert_eq!(
            gate.admit_signed(&changed_body, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed)
        );
        assert_eq!(gate.queued_counts(), (1, 0, 1));
    }

    #[test]
    fn duplicate_index_ghost_fails_closed_instead_of_returning_duplicate() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let first = envelope(34);
        let mut hooks = accepting_hooks();
        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let slot = *gate
            .slot_by_digest
            .get(&first.digest)
            .expect("digest index entry");
        gate.by_slot.remove(&slot);
        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState)
        );
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

    #[test]
    fn saturated_retry_does_not_reserve_replay_state_before_capacity_reopens() {
        use std::collections::HashSet;

        #[derive(Default)]
        struct ReservingHooks {
            seen: HashSet<(CanonicalSignerId, u64)>,
            verify_calls: usize,
            replay_calls: usize,
            recheck_calls: usize,
        }

        impl SignedAdmissionHooks<FixtureEnvelope> for ReservingHooks {
            fn verify_signature(
                &mut self,
                _envelope: &FixtureEnvelope,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                self.verify_calls += 1;
                Ok(())
            }

            fn check_replay(
                &mut self,
                metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                self.replay_calls += 1;
                self.seen
                    .insert(metadata.sequence_key())
                    .then_some(())
                    .ok_or(AdmissionReject::Replay)
            }

            fn recheck(
                &mut self,
                _metadata: &SignedEnvelopeMetadata,
            ) -> Result<(), AdmissionReject> {
                self.recheck_calls += 1;
                Ok(())
            }
        }

        let mut gate = TypedAdmissionGate::with_default_body_limit(1, 0);
        let first = envelope(80);
        let mut second = envelope(81);
        second.nonce = 2;
        let mut hooks = ReservingHooks::default();

        assert_eq!(
            gate.admit_signed(&first, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let calls_before_retry = (hooks.verify_calls, hooks.replay_calls, hooks.recheck_calls);
        assert_eq!(
            gate.admit_signed(&second, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Backpressured
        );
        assert_eq!(
            (hooks.verify_calls, hooks.replay_calls, hooks.recheck_calls),
            calls_before_retry
        );
        assert_eq!(hooks.seen.len(), 1);

        assert!(gate.pop_ready().is_some());
        assert_eq!(
            gate.admit_signed(&second, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert!(hooks
            .seen
            .contains(&(second.signer_id.expect("fixture signer"), second.nonce)));
    }

    #[test]
    fn pending_nonce_capacity_preflight_does_not_reserve() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(1, 0);
        let first = envelope(90);
        let mut second = envelope(91);
        second.nonce = 2;
        let mut hooks = accepting_hooks();
        let mut authority = lifecycle_authority();

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &first,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &second,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Backpressured
        );
        let log = authority.log.borrow();
        assert_eq!(log.reserve_calls, 1);
        assert_eq!(gate.queued_counts(), (1, 0, 1));
    }

    #[test]
    fn pending_nonce_recheck_failure_releases_once_and_can_retry() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let candidate = envelope(92);
        let mut hooks = accepting_hooks();
        hooks.recheck = false;
        let mut authority = lifecycle_authority();

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &candidate,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::RecheckFailed)
        );
        {
            let log = authority.log.borrow();
            assert_eq!(log.reserve_calls, 1);
            assert_eq!(log.release_calls, 1);
            assert!(log.active.is_empty());
        }
        assert_eq!(gate.queued_counts(), (0, 0, 0));

        hooks.recheck = true;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &candidate,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(authority.log.borrow().reserve_calls, 2);
    }

    #[test]
    fn pending_nonce_duplicate_does_not_reserve_twice_and_scopes_nonce_by_signer() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(4, 0);
        let first = envelope(93);
        let mut same_nonce_other_digest = envelope(94);
        same_nonce_other_digest.signer_id = first.signer_id;
        let mut other_signer_same_nonce = envelope(95);
        other_signer_same_nonce.signer_id = Some(signer(2));
        let mut hooks = accepting_hooks();
        let mut authority = lifecycle_authority();

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &first,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &first,
                IngressClass::Critical,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Duplicate
        );
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &same_nonce_other_digest,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &other_signer_same_nonce,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(authority.log.borrow().reserve_calls, 3);
    }

    #[test]
    fn pending_nonce_handoff_and_commit_are_exactly_once() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let candidate = envelope(96);
        let mut hooks = accepting_hooks();
        let mut authority = lifecycle_authority();
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &candidate,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );

        let mut ready = gate
            .pop_ready_with_lifecycle()
            .expect("lifecycle queue item");
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Reserved)
        );
        ready.handoff().expect("handoff reservation");
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        assert_eq!(
            ready.handoff(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        ready.commit().expect("commit reservation");
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Committed)
        );
        assert_eq!(
            ready.commit(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        drop(ready);

        let log = authority.log.borrow();
        assert_eq!(log.handoff_calls, 1);
        assert_eq!(log.commit_calls, 1);
        assert_eq!(log.release_calls, 0);
        assert!(log
            .committed
            .contains(&(candidate.signer_id.unwrap(), candidate.nonce)));
    }

    #[test]
    fn pending_nonce_cancel_and_legacy_pop_release_once() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let first = envelope(97);
        let second = envelope(98);
        let mut hooks = accepting_hooks();
        let mut authority = lifecycle_authority();

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &first,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate
            .pop_ready_with_lifecycle()
            .expect("first lifecycle item");
        ready.cancel().expect("cancel reservation");
        assert_eq!(
            ready.cancel(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        drop(ready);
        assert_eq!(authority.log.borrow().release_calls, 1);

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &second,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        // The compatibility pop path intentionally cancels the opaque token
        // rather than silently abandoning an external nonce reservation.
        assert!(gate.pop_ready().is_some());
        assert_eq!(authority.log.borrow().release_calls, 2);

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope(99),
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let ready = gate
            .pop_ready_with_lifecycle()
            .expect("drop-release lifecycle item");
        drop(ready);
        assert_eq!(authority.log.borrow().release_calls, 3);
    }

    #[test]
    fn pending_nonce_authority_rejection_is_fail_closed() {
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let candidate = envelope(100);
        let mut hooks = accepting_hooks();
        let mut authority = lifecycle_authority();
        authority.reject_reservation = true;

        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &candidate,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::ReplayCheckUnavailable)
        );
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(authority.log.borrow().reserve_calls, 1);
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
