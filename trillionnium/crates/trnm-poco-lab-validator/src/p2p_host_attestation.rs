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
    collections::BTreeMap,
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
        let binding = self.binding(direction, remote, session_id, generation)?;
        let request = HostAttestationRequestV1::new(binding, self.material.clone());
        let token = self.authority.admit_v1(request)?;
        let admission =
            match HostAttestationAdmissionV1::from_verified(binding, &self.material, token) {
                Ok(admission) => admission,
                Err(error) => {
                    let _ = self.authority.release_v1(token);
                    return Err(error);
                }
            };
        let mut active = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if active.contains_key(&key) {
            let _ = self.authority.release_v1(token);
            return Err(HostAttestationErrorV1::LeaseAlreadyPresent);
        }
        let mut sequences = self
            .last_sequence
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if sequences
            .get(&key)
            .is_some_and(|previous| admission.token().sequence() <= *previous)
        {
            let _ = self.authority.release_v1(token);
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
        let expected = self.binding(direction, remote, session_id, generation)?;
        let key = (direction, remote);
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

    pub fn release(
        &self,
        direction: ExternalPeerDirectionV1,
        remote: ValidatorId,
    ) -> Result<(), HostAttestationErrorV1> {
        let key = (direction, remote);
        let mut active = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?;
        if let Some(admission) = active.get(&key).copied().map(|entry| entry.admission) {
            // Keep the active receipt installed until the external authority
            // confirms release.  A release failure must not create a window
            // in which a second generation can overlap the first one.
            self.authority.release_v1(admission.token())?;
            active.remove(&key);
        }
        Ok(())
    }

    pub fn release_all(&self) -> Result<(), HostAttestationErrorV1> {
        let keys = self
            .active
            .lock()
            .map_err(|_| HostAttestationErrorV1::AuthorityUnavailable)?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for (direction, remote) in keys {
            if let Err(error) = self.release(direction, remote) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

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
        fail_release: bool,
    }

    impl HostAttestationAuthorityV1 for TestAuthority {
        fn preflight_v1(&self) -> Result<(), HostAttestationErrorV1> {
            Ok(())
        }

        fn admit_v1(
            &self,
            request: HostAttestationRequestV1,
        ) -> Result<HostAttestationTokenV1, HostAttestationErrorV1> {
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
            HostAttestationTokenV1::new(request.binding(), request.material(), sequence)
        }

        fn revalidate_v1(
            &self,
            _token: HostAttestationTokenV1,
        ) -> Result<(), HostAttestationErrorV1> {
            Ok(())
        }

        fn release_v1(&self, _token: HostAttestationTokenV1) -> Result<(), HostAttestationErrorV1> {
            if self.fail_release {
                Err(HostAttestationErrorV1::AuthorityRejected)
            } else {
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
            fail_release: false,
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
            fail_release: true,
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

    // Ensure the authority trait remains object-safe for mesh composition.
    #[test]
    fn authority_is_object_safe() {
        let _authority: Arc<Mutex<Box<dyn HostAttestationAuthorityV1>>> =
            Arc::new(Mutex::new(Box::new(RejectingHostAttestationAuthorityV1)));
    }
}
