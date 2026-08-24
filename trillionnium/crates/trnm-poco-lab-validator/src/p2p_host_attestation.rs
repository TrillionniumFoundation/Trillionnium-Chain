//! Typed host-attestation gate for the bounded authenticated P2P mesh.
//!
//! This module is deliberately an authority boundary, not a TEE claim.  The
//! node receives opaque evidence bytes from an independently owned authority;
//! that authority is responsible for deciding whether the bytes represent a
//! real platform quote/report.  The mesh only admits a receipt after the
//! authority has bound those bytes to the complete transport/session tuple.
//! There is no positive default implementation: [`RejectingHostAttestationAuthorityV1`]
//! keeps the deployed path fail-closed until a real external verifier is
//! supplied.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};
use trnm_consensus_types::ValidatorId;

use crate::p2p_admission::ExternalPeerDirectionV1;

pub const HOST_ATTESTATION_PROFILE_V1: &str = "trnm-poco-g3-host-attestation-gate-v1";
pub const HOST_ATTESTATION_MAX_BYTES_V1: usize = 64 * 1024;

const BINDING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.host-attestation-binding.v1";
const EVIDENCE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.host-attestation-evidence.v1";

/// Opaque evidence supplied by an external attestation authority.  The bytes
/// are retained so the authority can verify the exact report/quote rather
/// than a caller-provided digest alone.  The local mesh never interprets the
/// platform-specific format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAttestationMaterialV1 {
    bytes: Arc<[u8]>,
    digest: [u8; 32],
}

impl HostAttestationMaterialV1 {
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Result<Self, HostAttestationErrorV1> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > HOST_ATTESTATION_MAX_BYTES_V1 {
            return Err(HostAttestationErrorV1::InvalidEvidence);
        }
        let digest = evidence_digest_v1(&bytes);
        Ok(Self { bytes, digest })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, HostAttestationErrorV1> {
        Self::new(Arc::<[u8]>::from(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Complete identity/context tuple for one exact directed session
/// generation.  Every field is included in [`Self::digest`]; a receipt for a
/// different node, genesis, epoch, validator set, session, generation, or
/// transport campaign cannot be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostAttestationBindingV1 {
    local: ValidatorId,
    remote: ValidatorId,
    direction: ExternalPeerDirectionV1,
    p2p_identity_public_key: [u8; 32],
    genesis_hash: [u8; 32],
    epoch: u64,
    validator_set_id: [u8; 32],
    session_id: [u8; 32],
    generation: u64,
    run_id_sha256: [u8; 32],
    network_context_digest: [u8; 32],
}

impl HostAttestationBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local: ValidatorId,
        remote: ValidatorId,
        direction: ExternalPeerDirectionV1,
        p2p_identity_public_key: [u8; 32],
        genesis_hash: [u8; 32],
        epoch: u64,
        validator_set_id: [u8; 32],
        session_id: [u8; 32],
        generation: u64,
        run_id_sha256: [u8; 32],
        network_context_digest: [u8; 32],
    ) -> Result<Self, HostAttestationErrorV1> {
        if local.is_zero()
            || remote.is_zero()
            || local == remote
            || p2p_identity_public_key == [0; 32]
            || genesis_hash == [0; 32]
            || validator_set_id == [0; 32]
            || session_id == [0; 32]
            || generation == 0
            || run_id_sha256 == [0; 32]
            || network_context_digest == [0; 32]
        {
            return Err(HostAttestationErrorV1::InvalidBinding);
        }
        Ok(Self {
            local,
            remote,
            direction,
            p2p_identity_public_key,
            genesis_hash,
            epoch,
            validator_set_id,
            session_id,
            generation,
            run_id_sha256,
            network_context_digest,
        })
    }

    pub const fn local(self) -> ValidatorId {
        self.local
    }

    pub const fn remote(self) -> ValidatorId {
        self.remote
    }

    pub const fn direction(self) -> ExternalPeerDirectionV1 {
        self.direction
    }

    pub const fn p2p_identity_public_key(self) -> [u8; 32] {
        self.p2p_identity_public_key
    }

    pub const fn genesis_hash(self) -> [u8; 32] {
        self.genesis_hash
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn run_id_sha256(self) -> [u8; 32] {
        self.run_id_sha256
    }

    pub const fn network_context_digest(self) -> [u8; 32] {
        self.network_context_digest
    }

    pub fn digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BINDING_DOMAIN_V1);
        hasher.update(self.local.as_bytes());
        hasher.update(self.remote.as_bytes());
        hasher.update([self.direction as u8]);
        hasher.update(self.p2p_identity_public_key);
        hasher.update(self.genesis_hash);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.validator_set_id);
        hasher.update(self.session_id);
        hasher.update(self.generation.to_be_bytes());
        hasher.update(self.run_id_sha256);
        hasher.update(self.network_context_digest);
        hasher.finalize().into()
    }
}

/// Request passed to the external verifier.  The verifier must authenticate
/// the exact bytes and return a token with the same binding/evidence digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAttestationRequestV1 {
    binding: HostAttestationBindingV1,
    material: HostAttestationMaterialV1,
}

impl HostAttestationRequestV1 {
    pub fn new(binding: HostAttestationBindingV1, material: HostAttestationMaterialV1) -> Self {
        Self { binding, material }
    }

    pub const fn binding(&self) -> HostAttestationBindingV1 {
        self.binding
    }

    pub fn material(&self) -> &HostAttestationMaterialV1 {
        &self.material
    }
}

/// Authority receipt retained by the mesh for one session generation.  The
/// authority chooses the monotonic sequence; the mesh rejects zero, stale,
/// duplicate, or scope-mismatched receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAttestationTokenV1 {
    binding_digest: [u8; 32],
    evidence_digest: [u8; 32],
    sequence: u64,
}

impl HostAttestationTokenV1 {
    pub fn new(
        binding: HostAttestationBindingV1,
        material: &HostAttestationMaterialV1,
        sequence: u64,
    ) -> Result<Self, HostAttestationErrorV1> {
        if sequence == 0 {
            return Err(HostAttestationErrorV1::InvalidReceipt);
        }
        Ok(Self {
            binding_digest: binding.digest(),
            evidence_digest: material.digest(),
            sequence,
        })
    }

    pub const fn binding_digest(self) -> [u8; 32] {
        self.binding_digest
    }

    pub const fn evidence_digest(self) -> [u8; 32] {
        self.evidence_digest
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// A locally verified receipt that is safe to hand to the transport
/// connection.  The registry creates this only after checking the authority
/// token against the exact binding and evidence bytes; transport code never
/// accepts a bare boolean admission marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAttestationAdmissionV1 {
    binding: HostAttestationBindingV1,
    token: HostAttestationTokenV1,
}

impl HostAttestationAdmissionV1 {
    pub(crate) fn from_verified(
        binding: HostAttestationBindingV1,
        material: &HostAttestationMaterialV1,
        token: HostAttestationTokenV1,
    ) -> Result<Self, HostAttestationErrorV1> {
        if token.binding_digest() != binding.digest() {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        if token.evidence_digest() != material.digest() {
            return Err(HostAttestationErrorV1::EvidenceMismatch);
        }
        Ok(Self { binding, token })
    }

    pub const fn binding(self) -> HostAttestationBindingV1 {
        self.binding
    }

    pub const fn token(self) -> HostAttestationTokenV1 {
        self.token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAttestationErrorV1 {
    Missing,
    InvalidBinding,
    InvalidEvidence,
    InvalidReceipt,
    BindingMismatch,
    EvidenceMismatch,
    Replay,
    AuthorityUnavailable,
    AuthorityRejected,
    LeaseAlreadyPresent,
    LeaseNotFound,
    /// A prior authority receipt was admitted locally but its compensating
    /// release is still uncertain.  No session may be revalidated or used
    /// for admission while that exact cleanup remains unresolved.
    ReleasePending,
}

impl fmt::Display for HostAttestationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "host attestation is required but missing",
            Self::InvalidBinding => "host attestation binding is invalid",
            Self::InvalidEvidence => "host attestation evidence is empty or oversized",
            Self::InvalidReceipt => "host attestation receipt is invalid",
            Self::BindingMismatch => "host attestation binding differs from the session",
            Self::EvidenceMismatch => "host attestation evidence digest differs from the request",
            Self::Replay => "host attestation receipt was replayed or regressed",
            Self::AuthorityUnavailable => "host attestation authority is unavailable",
            Self::AuthorityRejected => "host attestation authority rejected the evidence",
            Self::LeaseAlreadyPresent => "host attestation session already has a live receipt",
            Self::LeaseNotFound => "host attestation session has no live receipt",
            Self::ReleasePending => "host attestation session has an unresolved receipt release",
        })
    }
}

impl std::error::Error for HostAttestationErrorV1 {}

/// External authority boundary.  An implementation may call a platform
/// verifier, KMS, or attestation daemon; this crate intentionally provides no
/// positive/fake implementation.  `admit_v1` must cryptographically verify
/// the opaque bytes and enforce its own anti-rollback sequence before
/// returning a token.
pub trait HostAttestationAuthorityV1: Send + Sync {
    fn preflight_v1(&self) -> Result<(), HostAttestationErrorV1>;

    fn admit_v1(
        &self,
        request: HostAttestationRequestV1,
    ) -> Result<HostAttestationTokenV1, HostAttestationErrorV1>;

    fn revalidate_v1(&self, token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1>;

    fn release_v1(&self, token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1>;
}

/// Default authority used by all legacy/fixture mesh constructors.  It is
/// intentionally rejecting, so adding a host-attestation field cannot silently
/// turn a fixture into a commissioning authority.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectingHostAttestationAuthorityV1;

impl HostAttestationAuthorityV1 for RejectingHostAttestationAuthorityV1 {
    fn preflight_v1(&self) -> Result<(), HostAttestationErrorV1> {
        Err(HostAttestationErrorV1::Missing)
    }

    fn admit_v1(
        &self,
        _request: HostAttestationRequestV1,
    ) -> Result<HostAttestationTokenV1, HostAttestationErrorV1> {
        Err(HostAttestationErrorV1::Missing)
    }

    fn revalidate_v1(&self, _token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1> {
        Err(HostAttestationErrorV1::Missing)
    }

    fn release_v1(&self, _token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1> {
        Ok(())
    }
}

pub fn evidence_digest_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN_V1);
    hasher.update(bytes);
    hasher.finalize().into()
}

type HostSessionKeyV1 = (ExternalPeerDirectionV1, ValidatorId);

#[derive(Clone, Copy)]
struct ActiveHostAttestationV1 {
    admission: HostAttestationAdmissionV1,
}

/// Mesh-owned session/generation registry.  It is intentionally separate
/// from the peer-lease registry so an operator cannot accidentally treat a
/// lease as a host credential.  The registry performs the local tuple checks;
/// the injected authority owns platform verification and cross-process
/// anti-rollback.
#[derive(Clone)]
pub struct HostAttestationSessionRegistryV1 {
    authority: Arc<dyn HostAttestationAuthorityV1>,
    local: ValidatorId,
    p2p_identity_public_key: [u8; 32],
    genesis_hash: [u8; 32],
    epoch: u64,
    validator_set_id: [u8; 32],
    run_id_sha256: [u8; 32],
    network_context_digest: [u8; 32],
    material: HostAttestationMaterialV1,
    active: Arc<Mutex<BTreeMap<HostSessionKeyV1, ActiveHostAttestationV1>>>,
    last_sequence: Arc<Mutex<BTreeMap<HostSessionKeyV1, u64>>>,
    /// Tokens which the authority handed out but whose compensating release
    /// has not yet been confirmed.  Admission must remain closed for the key
    /// while one of these is present: otherwise a retry could overlap an
    /// externally live receipt which the local map no longer names.
    pending_releases: Arc<Mutex<BTreeMap<HostSessionKeyV1, Vec<HostAttestationTokenV1>>>>,
    /// Serialize the authority admission/release transaction for every clone
    /// of this registry.  The local maps alone cannot close the window between
    /// an external `admit_v1` and installing the receipt in `active`.
    admission_lock: Arc<Mutex<()>>,
}

impl HostAttestationSessionRegistryV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Arc<dyn HostAttestationAuthorityV1>,
        local: ValidatorId,
        p2p_identity_public_key: [u8; 32],
        genesis_hash: [u8; 32],
        epoch: u64,
        validator_set_id: [u8; 32],
        run_id_sha256: [u8; 32],
        network_context_digest: [u8; 32],
        material: HostAttestationMaterialV1,
    ) -> Result<Self, HostAttestationErrorV1> {
        if local.is_zero()
            || p2p_identity_public_key == [0; 32]
            || genesis_hash == [0; 32]
            || validator_set_id == [0; 32]
            || run_id_sha256 == [0; 32]
            || network_context_digest == [0; 32]
        {
            return Err(HostAttestationErrorV1::InvalidBinding);
        }
        authority.preflight_v1()?;
        Ok(Self {
            authority,
            local,
            p2p_identity_public_key,
            genesis_hash,
            epoch,
            validator_set_id,
            run_id_sha256,
            network_context_digest,
            material,
            active: Arc::new(Mutex::new(BTreeMap::new())),
            last_sequence: Arc::new(Mutex::new(BTreeMap::new())),
            pending_releases: Arc::new(Mutex::new(BTreeMap::new())),
            admission_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn preflight(&self) -> Result<(), HostAttestationErrorV1> {
        self.authority.preflight_v1()
    }

    fn binding(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<HostAttestationBindingV1, HostAttestationErrorV1> {
        HostAttestationBindingV1::new(
            self.local,
            remote,
            direction,
            self.p2p_identity_public_key,
            self.genesis_hash,
            self.epoch,
            self.validator_set_id,
            session_id,
            generation,
            self.run_id_sha256,
            self.network_context_digest,
        )
    }

    pub fn acquire(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<HostAttestationAdmissionV1, HostAttestationErrorV1> {
        let key = (direction, remote);
        // Keep the complete external admit/check/install sequence serialized
        // across clones.  In particular, do not issue a new authority token
        // while a prior failed cleanup is still unresolved.
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        self.retry_pending_releases_for_key_v1(key)?;
        if self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .contains_key(&key)
        {
            return Err(HostAttestationErrorV1::LeaseAlreadyPresent);
        }
        let binding = self.binding(direction, remote, session_id, generation)?;
        let request = HostAttestationRequestV1::new(binding, self.material.clone());
        let token = self.authority.admit_v1(request)?;
        let admission =
            match HostAttestationAdmissionV1::from_verified(binding, &self.material, token) {
                Ok(admission) => admission,
                Err(error) => {
                    self.release_or_retain_v1(key, token)?;
                    return Err(error);
                }
            };
        let mut active = match self.active.lock() {
            Ok(active) => active,
            Err(_) => {
                // The token is already externally live.  Preserve it for a
                // later exact release instead of dropping it on a poisoned
                // local mutex.
                return match self.release_or_retain_v1(key, token) {
                    Ok(()) => Err(HostAttestationErrorV1::AuthorityUnavailable),
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
        };
        if active.contains_key(&key) {
            drop(active);
            self.release_or_retain_v1(key, token)?;
            return Err(HostAttestationErrorV1::LeaseAlreadyPresent);
        }
        let mut sequences = match self.last_sequence.lock() {
            Ok(sequences) => sequences,
            Err(_) => {
                drop(active);
                return match self.release_or_retain_v1(key, token) {
                    Ok(()) => Err(HostAttestationErrorV1::AuthorityUnavailable),
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
        };
        if sequences
            .get(&key)
            .is_some_and(|previous| admission.token().sequence() <= *previous)
        {
            drop(sequences);
            drop(active);
            self.release_or_retain_v1(key, token)?;
            return Err(HostAttestationErrorV1::Replay);
        }
        sequences.insert(key, admission.token().sequence());
        active.insert(key, ActiveHostAttestationV1 { admission });
        Ok(admission)
    }

    /// Returns the exact receipt admitted for a live directed session.  The
    /// session/generation tuple is checked again so a caller cannot attach a
    /// receipt from an older reconnect attempt to a fresh socket.
    pub fn admission(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
        session_id: [u8; 32],
        generation: u64,
    ) -> Result<HostAttestationAdmissionV1, HostAttestationErrorV1> {
        // Serialize the lookup with acquire/release.  A receipt copied while
        // an exact cleanup is unresolved could otherwise be handed to a
        // transport worker even though the authority may still have both the
        // old and replacement token live.
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let expected = self.binding(direction, remote, session_id, generation)?;
        let key = (direction, remote);
        if self
            .pending_releases
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .contains_key(&key)
        {
            return Err(HostAttestationErrorV1::ReleasePending);
        }
        let active = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let admission = active
            .get(&key)
            .copied()
            .map(|entry| entry.admission)
            .ok_or(HostAttestationErrorV1::LeaseNotFound)?;
        if admission.binding() != expected
            || admission.token().binding_digest() != expected.digest()
            || admission.token().evidence_digest() != self.material.digest()
        {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        Ok(admission)
    }

    pub fn revalidate(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
    ) -> Result<(), HostAttestationErrorV1> {
        let key = (direction, remote);
        // Revalidation is an authority call, not a read-only map lookup.  It
        // must share the same transaction lock as admission/release so a
        // failed compensating release cannot race with a supposedly live
        // receipt and keep a transport session running on ambiguous state.
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if self
            .pending_releases
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .contains_key(&key)
        {
            return Err(HostAttestationErrorV1::ReleasePending);
        }
        let active = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let entry = active
            .get(&key)
            .copied()
            .ok_or(HostAttestationErrorV1::LeaseNotFound)?;
        if entry.admission.binding().digest() != entry.admission.token().binding_digest()
            || entry.admission.token().evidence_digest() != self.material.digest()
        {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        self.authority.revalidate_v1(entry.admission.token())
    }

    /// Revalidates the exact receipt retained by a mesh edge.  The directed
    /// key alone is insufficient because a reconnect may install a newer
    /// session while an older worker is still unwinding.
    pub(crate) fn revalidate_exact_v1(
        &self,
        admission: HostAttestationAdmissionV1,
    ) -> Result<(), HostAttestationErrorV1> {
        let binding = admission.binding();
        let key = (binding.direction(), binding.remote());
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if self
            .pending_releases
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .contains_key(&key)
        {
            return Err(HostAttestationErrorV1::ReleasePending);
        }
        let entry = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .get(&key)
            .copied()
            .ok_or(HostAttestationErrorV1::LeaseNotFound)?;
        if entry.admission != admission {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        if admission.binding().digest() != admission.token().binding_digest()
            || admission.token().evidence_digest() != self.material.digest()
        {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        self.authority.revalidate_v1(admission.token())
    }

    pub fn release(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
    ) -> Result<(), HostAttestationErrorV1> {
        let key = (direction, remote);
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let active_admission = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .get(&key)
            .copied()
            .map(|entry| entry.admission);
        // A previous release attempt may have retained this exact active
        // token in the pending queue.  Remember that fact before draining the
        // queue: a successful retry already consumed the authority lease, so
        // issuing a second release below would turn a recoverable cleanup into
        // a false failure on non-idempotent authorities.
        let active_was_pending = active_admission
            .map(|admission| self.pending_contains_token_v1(key, admission.token()))
            .transpose()?
            .unwrap_or(false);
        // A loser token from an earlier admission race is independent of the
        // currently active winner.  Clear it by its exact token first; a
        // key-only release would be allowed to tear down the winner.
        self.retry_pending_releases_for_key_v1(key)?;
        if let Some(admission) = active_admission {
            if active_was_pending {
                let mut active = self
                    .active
                    .lock()
                    .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
                if active
                    .get(&key)
                    .copied()
                    .map(|entry| entry.admission == admission)
                    .unwrap_or(false)
                {
                    active.remove(&key);
                }
                return Ok(());
            }
            // Keep the active receipt installed until the external authority
            // confirms release.  A release failure must not create a window
            // in which a second generation can overlap the first one.
            self.authority.release_v1(admission.token())?;
            let mut active = self
                .active
                .lock()
                .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
            if active
                .get(&key)
                .copied()
                .map(|entry| entry.admission.token() == admission.token())
                .unwrap_or(false)
            {
                active.remove(&key);
            }
        }
        Ok(())
    }

    /// Releases one exact receipt without resolving the session by its bare
    /// `(direction, remote)` key.  Mesh compensation paths use this boundary
    /// after an external peer-lease admission fails: a separately installed
    /// winner must never be torn down by a late loser cleanup callback.
    pub(crate) fn release_exact_v1(
        &self,
        admission: HostAttestationAdmissionV1,
    ) -> Result<(), HostAttestationErrorV1> {
        let binding = admission.binding();
        let key = (binding.direction(), binding.remote());
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let expected = self.binding(
            binding.direction(),
            binding.remote(),
            binding.session_id(),
            binding.generation(),
        )?;
        if binding != expected || admission.token().binding_digest() != expected.digest() {
            return Err(HostAttestationErrorV1::BindingMismatch);
        }
        if admission.token().evidence_digest() != self.material.digest() {
            return Err(HostAttestationErrorV1::EvidenceMismatch);
        }
        // If this exact receipt is already retained for a prior uncertain
        // release, the retry below is the authority operation for this call.
        // Do not issue a second release after it succeeds: many authorities
        // consume a token on the first successful call and report
        // `LeaseNotFound` for a duplicate rather than treating release as
        // idempotent.
        let was_pending = self.pending_contains_token_v1(key, admission.token())?;
        self.retry_pending_releases_for_key_v1(key)?;
        if was_pending {
            let mut active = self
                .active
                .lock()
                .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
            if active
                .get(&key)
                .copied()
                .map(|entry| entry.admission == admission)
                .unwrap_or(false)
            {
                active.remove(&key);
            }
            return Ok(());
        }
        // The exact token, not the bare key, authorizes cleanup.  A newer
        // winner may already occupy the local key while this loser callback
        // unwinds; the authority must still release the loser, and the winner
        // must remain installed.
        self.authority.release_v1(admission.token())?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if active
            .get(&key)
            .copied()
            .map(|entry| entry.admission == admission)
            .unwrap_or(false)
        {
            active.remove(&key);
        }
        Ok(())
    }

    fn pending_contains_token_v1(
        &self,
        key: HostSessionKeyV1,
        token: HostAttestationTokenV1,
    ) -> Result<bool, HostAttestationErrorV1> {
        Ok(self
            .pending_releases
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .get(&key)
            .is_some_and(|tokens| tokens.contains(&token)))
    }

    pub fn release_all(&self) -> Result<(), HostAttestationErrorV1> {
        let mut keys = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        keys.extend(
            self.pending_releases
                .lock()
                .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
                .keys()
                .copied(),
        );
        let keys = keys.into_iter().collect::<BTreeSet<_>>();
        let mut first_error = None;
        for (direction, remote) in keys {
            if let Err(error) = self.release(direction, remote) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Retries every exact authority token retained after an uncertain
    /// compensating release.  This is intentionally explicit in addition to
    /// the automatic retry at the next `acquire`/`release` boundary so a host
    /// shutdown path can drain cleanup without opening a new session.
    pub fn retry_pending_releases_v1(&self) -> Result<(), HostAttestationErrorV1> {
        let _admission_guard = self
            .admission_lock
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        let keys = self
            .pending_releases
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for key in keys {
            if let Err(error) = self.retry_pending_releases_for_key_v1(key) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn release_or_retain_v1(
        &self,
        key: HostSessionKeyV1,
        token: HostAttestationTokenV1,
    ) -> Result<(), HostAttestationErrorV1> {
        match self.authority.release_v1(token) {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut pending = self
                    .pending_releases
                    .lock()
                    .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
                let entries = pending.entry(key).or_default();
                if !entries.contains(&token) {
                    entries.push(token);
                }
                Err(error)
            }
        }
    }

    fn retry_pending_releases_for_key_v1(
        &self,
        key: HostSessionKeyV1,
    ) -> Result<(), HostAttestationErrorV1> {
        loop {
            let token = self
                .pending_releases
                .lock()
                .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
                .get(&key)
                .and_then(|entries| entries.first().copied());
            let Some(token) = token else {
                return Ok(());
            };
            // An error is deliberately sticky.  Even if the authority may
            // have applied the release, uncertainty must not permit a new
            // admission that could overlap the old token.
            self.authority.release_v1(token)?;
            let mut pending = self
                .pending_releases
                .lock()
                .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
            let Some(entries) = pending.get_mut(&key) else {
                continue;
            };
            if let Some(index) = entries.iter().position(|candidate| *candidate == token) {
                entries.remove(index);
            }
            if entries.is_empty() {
                pending.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Barrier, Mutex,
    };

    use super::*;
    use trnm_consensus_types::ValidatorId;

    fn binding() -> HostAttestationBindingV1 {
        HostAttestationBindingV1::new(
            ValidatorId::new([1; 32]),
            ValidatorId::new([2; 32]),
            ExternalPeerDirectionV1::Outbound,
            [3; 32],
            [4; 32],
            7,
            [5; 32],
            [6; 32],
            2,
            [7; 32],
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    fn binding_covers_all_session_and_campaign_coordinates() {
        let original = binding().digest();
        let mut changed = binding();
        changed.generation = 3;
        assert_ne!(original, changed.digest());
        changed.generation = 2;
        changed.session_id = [9; 32];
        assert_ne!(original, changed.digest());
        changed.session_id = [6; 32];
        changed.genesis_hash = [10; 32];
        assert_ne!(original, changed.digest());
    }

    #[test]
    fn material_digest_is_derived_from_exact_bytes() {
        let material = HostAttestationMaterialV1::from_bytes(vec![1, 2, 3]).unwrap();
        assert_eq!(material.digest(), evidence_digest_v1(&[1, 2, 3]));
        assert_ne!(material.digest(), evidence_digest_v1(&[1, 2, 4]));
        assert!(matches!(
            HostAttestationMaterialV1::from_bytes(Vec::new()),
            Err(HostAttestationErrorV1::InvalidEvidence)
        ));
    }

    #[test]
    fn typed_admission_rejects_binding_and_evidence_mismatch() {
        let original = binding();
        let material = HostAttestationMaterialV1::from_bytes(vec![1, 2, 3]).unwrap();
        let token = HostAttestationTokenV1::new(original, &material, 1).unwrap();
        let mut wrong_binding = original;
        wrong_binding.generation = original.generation() + 1;
        assert!(matches!(
            HostAttestationAdmissionV1::from_verified(wrong_binding, &material, token),
            Err(HostAttestationErrorV1::BindingMismatch)
        ));
        let other_material = HostAttestationMaterialV1::from_bytes(vec![4, 5, 6]).unwrap();
        assert!(matches!(
            HostAttestationAdmissionV1::from_verified(original, &other_material, token),
            Err(HostAttestationErrorV1::EvidenceMismatch)
        ));
    }

    #[test]
    fn rejecting_authority_never_grants_a_token() {
        let authority = RejectingHostAttestationAuthorityV1;
        let material = HostAttestationMaterialV1::from_bytes(vec![9]).unwrap();
        let request = HostAttestationRequestV1::new(binding(), material);
        assert!(matches!(
            authority.admit_v1(request),
            Err(HostAttestationErrorV1::Missing)
        ));
    }

    #[derive(Default)]
    struct TestAuthority {
        next_sequence: Mutex<u64>,
        fixed_sequence: Option<u64>,
        fail_release: AtomicBool,
        release_failures: AtomicUsize,
        revalidate_calls: AtomicUsize,
        released_tokens: Mutex<Vec<HostAttestationTokenV1>>,
        reject_duplicate_release: AtomicBool,
        wrong_binding: AtomicBool,
        admit_started: Option<Arc<Barrier>>,
        admit_continue: Option<Arc<Barrier>>,
    }

    impl HostAttestationAuthorityV1 for TestAuthority {
        fn preflight_v1(&self) -> Result<(), HostAttestationErrorV1> {
            Ok(())
        }

        fn admit_v1(
            &self,
            request: HostAttestationRequestV1,
        ) -> Result<HostAttestationTokenV1, HostAttestationErrorV1> {
            if let Some(started) = &self.admit_started {
                started.wait();
            }
            if let Some(continue_gate) = &self.admit_continue {
                continue_gate.wait();
            }
            let sequence = if let Some(fixed) = self.fixed_sequence {
                fixed
            } else {
                let mut sequence = self
                    .next_sequence
                    .lock()
                    .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
                *sequence = sequence.saturating_add(1);
                *sequence
            };
            let mut token =
                HostAttestationTokenV1::new(request.binding(), request.material(), sequence)?;
            if self.wrong_binding.load(Ordering::Acquire) {
                token.binding_digest = [0x9a; 32];
            }
            Ok(token)
        }

        fn revalidate_v1(
            &self,
            _token: HostAttestationTokenV1,
        ) -> Result<(), HostAttestationErrorV1> {
            self.revalidate_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn release_v1(&self, token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1> {
            let fail_once = self
                .release_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    if remaining > 0 {
                        Some(remaining - 1)
                    } else {
                        None
                    }
                })
                .is_ok();
            if self.fail_release.load(Ordering::Acquire) || fail_once {
                Err(HostAttestationErrorV1::AuthorityRejected)
            } else {
                let mut released = self
                    .released_tokens
                    .lock()
                    .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
                if self.reject_duplicate_release.load(Ordering::Acquire)
                    && released.contains(&token)
                {
                    return Err(HostAttestationErrorV1::LeaseNotFound);
                }
                released.push(token);
                Ok(())
            }
        }
    }

    #[test]
    fn session_registry_binds_generation_and_rejects_replay() {
        let material = HostAttestationMaterialV1::from_bytes(vec![0xaa, 0xbb]).unwrap();
        let authority = Arc::new(TestAuthority::default());
        let b = binding();
        let registry = HostAttestationSessionRegistryV1::new(
            authority,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            material,
        )
        .unwrap();
        let token = registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        assert_eq!(token.token().binding_digest(), b.digest());
        registry
            .revalidate(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();

        // The authority's sequence is intentionally held at one for this
        // second registry, proving the local generation key cannot silently
        // accept an exact receipt replay after release.
        let replay_authority = Arc::new(TestAuthority {
            next_sequence: Mutex::new(0),
            fixed_sequence: Some(1),
            ..Default::default()
        });
        let replay_registry = HostAttestationSessionRegistryV1::new(
            replay_authority,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0xaa, 0xbb]).unwrap(),
        )
        .unwrap();
        replay_registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        replay_registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
        assert!(matches!(
            replay_registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            ),
            Err(HostAttestationErrorV1::Replay)
        ));
    }

    #[test]
    fn release_failure_retains_live_receipt_and_blocks_overlap() {
        let b = binding();
        let authority = Arc::new(TestAuthority {
            next_sequence: Mutex::new(0),
            fixed_sequence: None,
            fail_release: AtomicBool::new(true),
            ..Default::default()
        });
        let registry = HostAttestationSessionRegistryV1::new(
            authority,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0x44]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            registry.release(ExternalPeerDirectionV1::Outbound, b.remote()),
            Ok(())
        ));
        registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        assert!(matches!(
            registry.release(ExternalPeerDirectionV1::Outbound, b.remote()),
            Err(HostAttestationErrorV1::AuthorityRejected)
        ));
        assert!(matches!(
            registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation() + 1,
            ),
            Err(HostAttestationErrorV1::LeaseAlreadyPresent)
        ));
    }

    #[test]
    fn concurrent_acquire_serializes_before_external_admission() {
        let b = binding();
        let authority = Arc::new(TestAuthority::default());
        let registry = HostAttestationSessionRegistryV1::new(
            authority,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0x51]).unwrap(),
        )
        .unwrap();
        let start = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let registry = registry.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    registry.acquire(
                        ExternalPeerDirectionV1::Outbound,
                        b.remote(),
                        b.session_id(),
                        b.generation(),
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("acquire worker did not panic"))
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one generation may win the serialized admission"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(HostAttestationErrorV1::LeaseAlreadyPresent)))
                .count(),
            7
        );
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
    }

    #[test]
    fn late_collision_cleanup_failure_retains_loser_token_exactly() {
        let b = binding();
        let admit_started = Arc::new(Barrier::new(2));
        let admit_continue = Arc::new(Barrier::new(2));
        let authority = Arc::new(TestAuthority {
            admit_started: Some(Arc::clone(&admit_started)),
            admit_continue: Some(Arc::clone(&admit_continue)),
            release_failures: AtomicUsize::new(1),
            ..Default::default()
        });
        let material = HostAttestationMaterialV1::from_bytes(vec![0x52]).unwrap();
        let registry = HostAttestationSessionRegistryV1::new(
            Arc::clone(&authority) as Arc<dyn HostAttestationAuthorityV1>,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            material.clone(),
        )
        .unwrap();
        let worker_registry = registry.clone();
        let worker = std::thread::spawn(move || {
            worker_registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
        });
        admit_started.wait();

        // Simulate a separately administered winner racing the local install
        // boundary.  The loser token must not be discarded when its cleanup
        // call fails once.
        let winner_binding = HostAttestationBindingV1::new(
            b.local(),
            b.remote(),
            ExternalPeerDirectionV1::Outbound,
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.session_id(),
            b.generation(),
            b.run_id_sha256(),
            b.network_context_digest(),
        )
        .unwrap();
        let winner_token = HostAttestationTokenV1::new(winner_binding, &material, 99).unwrap();
        let winner =
            HostAttestationAdmissionV1::from_verified(winner_binding, &material, winner_token)
                .unwrap();
        registry.active.lock().unwrap().insert(
            (ExternalPeerDirectionV1::Outbound, b.remote()),
            ActiveHostAttestationV1 { admission: winner },
        );
        admit_continue.wait();
        assert!(matches!(
            worker.join().expect("late-collision worker did not panic"),
            Err(HostAttestationErrorV1::AuthorityRejected)
        ));
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        assert_eq!(registry.pending_releases.lock().unwrap()[&key].len(), 1);

        // A fresh cleanup retry drains the exact loser token while retaining
        // the independently installed winner; releasing by bare key would
        // incorrectly tear that winner down.
        registry.retry_pending_releases_v1().unwrap();
        assert!(!registry.pending_releases.lock().unwrap().contains_key(&key));
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
    }

    #[test]
    fn replay_cleanup_failure_is_retained_and_retried_before_next_admit() {
        let b = binding();
        let authority = Arc::new(TestAuthority {
            fixed_sequence: Some(1),
            ..Default::default()
        });
        let registry = HostAttestationSessionRegistryV1::new(
            authority.clone(),
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0x53]).unwrap(),
        )
        .unwrap();
        registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
        authority.release_failures.store(1, Ordering::Release);
        assert!(matches!(
            registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation() + 1,
            ),
            Err(HostAttestationErrorV1::AuthorityRejected)
        ));
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        assert_eq!(registry.pending_releases.lock().unwrap()[&key].len(), 1);
        assert!(matches!(
            registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation() + 1,
            ),
            Err(HostAttestationErrorV1::Replay)
        ));
        assert!(!registry.pending_releases.lock().unwrap().contains_key(&key));
    }

    #[test]
    fn binding_mismatch_cleanup_failure_is_retained_until_exact_retry() {
        let b = binding();
        let authority = Arc::new(TestAuthority {
            release_failures: AtomicUsize::new(1),
            ..Default::default()
        });
        authority.wrong_binding.store(true, Ordering::Release);
        let registry = HostAttestationSessionRegistryV1::new(
            authority.clone(),
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0x54]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            ),
            Err(HostAttestationErrorV1::AuthorityRejected)
        ));
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        assert_eq!(registry.pending_releases.lock().unwrap()[&key].len(), 1);

        authority.wrong_binding.store(false, Ordering::Release);
        assert!(registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .is_ok());
        assert!(!registry.pending_releases.lock().unwrap().contains_key(&key));
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
    }

    #[test]
    fn unresolved_release_blocks_admission_and_revalidation_without_authority_call() {
        let b = binding();
        let authority = Arc::new(TestAuthority {
            release_failures: AtomicUsize::new(1),
            ..Default::default()
        });
        authority.wrong_binding.store(true, Ordering::Release);
        let material = HostAttestationMaterialV1::from_bytes(vec![0x55]).unwrap();
        let registry = HostAttestationSessionRegistryV1::new(
            Arc::clone(&authority) as Arc<dyn HostAttestationAuthorityV1>,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            material.clone(),
        )
        .unwrap();

        // The authority returned a token, but the compensating release was
        // uncertain.  Keep a separately installed winner to model the only
        // safe late-collision state: both exact receipts are still named.
        assert!(matches!(
            registry.acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            ),
            Err(HostAttestationErrorV1::AuthorityRejected)
        ));
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        assert!(registry.pending_releases.lock().unwrap().contains_key(&key));

        authority.wrong_binding.store(false, Ordering::Release);
        let winner_token = HostAttestationTokenV1::new(b, &material, 99).unwrap();
        let winner = HostAttestationAdmissionV1::from_verified(b, &material, winner_token).unwrap();
        registry
            .active
            .lock()
            .unwrap()
            .insert(key, ActiveHostAttestationV1 { admission: winner });

        assert!(matches!(
            registry.admission(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            ),
            Err(HostAttestationErrorV1::ReleasePending)
        ));
        assert!(matches!(
            registry.revalidate(ExternalPeerDirectionV1::Outbound, b.remote()),
            Err(HostAttestationErrorV1::ReleasePending)
        ));
        assert_eq!(authority.revalidate_calls.load(Ordering::Acquire), 0);

        registry.retry_pending_releases_v1().unwrap();
        registry
            .revalidate(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
        assert_eq!(authority.revalidate_calls.load(Ordering::Acquire), 1);
        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
    }

    #[test]
    fn exact_loser_release_does_not_remove_a_replacement_generation() {
        let b = binding();
        let authority = Arc::new(TestAuthority::default());
        let material = HostAttestationMaterialV1::from_bytes(vec![0x56]).unwrap();
        let registry = HostAttestationSessionRegistryV1::new(
            authority,
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            material.clone(),
        )
        .unwrap();
        let loser = registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        let winner_binding = HostAttestationBindingV1::new(
            b.local(),
            b.remote(),
            ExternalPeerDirectionV1::Outbound,
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            [0x57; 32],
            b.generation() + 1,
            b.run_id_sha256(),
            b.network_context_digest(),
        )
        .unwrap();
        let winner_token = HostAttestationTokenV1::new(winner_binding, &material, 99).unwrap();
        let winner =
            HostAttestationAdmissionV1::from_verified(winner_binding, &material, winner_token)
                .unwrap();
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        registry
            .active
            .lock()
            .unwrap()
            .insert(key, ActiveHostAttestationV1 { admission: winner });

        registry.release_exact_v1(loser).unwrap();
        assert_eq!(
            registry.active.lock().unwrap()[&key].admission,
            winner,
            "an exact loser cleanup must leave the replacement receipt live"
        );
        registry.release_exact_v1(winner).unwrap();
        assert!(!registry.active.lock().unwrap().contains_key(&key));
    }

    #[test]
    fn pending_active_token_is_released_once_for_non_idempotent_authority() {
        let b = binding();
        let authority = Arc::new(TestAuthority::default());
        authority
            .reject_duplicate_release
            .store(true, Ordering::Release);
        let registry = HostAttestationSessionRegistryV1::new(
            authority.clone(),
            b.local(),
            b.p2p_identity_public_key(),
            b.genesis_hash(),
            b.epoch(),
            b.validator_set_id(),
            b.run_id_sha256(),
            b.network_context_digest(),
            HostAttestationMaterialV1::from_bytes(vec![0x58]).unwrap(),
        )
        .unwrap();
        let admission = registry
            .acquire(
                ExternalPeerDirectionV1::Outbound,
                b.remote(),
                b.session_id(),
                b.generation(),
            )
            .unwrap();
        let key = (ExternalPeerDirectionV1::Outbound, b.remote());
        registry
            .pending_releases
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .push(admission.token());

        registry
            .release(ExternalPeerDirectionV1::Outbound, b.remote())
            .unwrap();
        assert_eq!(authority.released_tokens.lock().unwrap().len(), 1);
        assert!(!registry.active.lock().unwrap().contains_key(&key));
        assert!(!registry.pending_releases.lock().unwrap().contains_key(&key));
    }

    // Ensure the authority trait remains object-safe for mesh composition.
    #[test]
    fn authority_is_object_safe() {
        let _authority: Arc<Mutex<Box<dyn HostAttestationAuthorityV1>>> =
            Arc::new(Mutex::new(Box::new(RejectingHostAttestationAuthorityV1)));
    }
}
