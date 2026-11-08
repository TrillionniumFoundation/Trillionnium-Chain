//! Versioned, bounded PQ release authorization kernel.
//!
//! This is a project-specific binary metadata profile, not a TUF JSON client.
//! TUF role delegation, timestamp/snapshot download, JSON canonicalization
//! and TAP 21 adapters remain outside this module and keep their existing owner.
//!
//! The sole owner must atomically persist each accepted signed event and returned
//! checkpoint before publishing an effect. Recovery replays these events against
//! an independently fresh expected checkpoint. A checkpoint alone is not a log
//! consistency proof, and this kernel does not implement storage or a witness.
//! This in-memory component cannot detect total rollback of all owner state.
//! Each action's `now` must be trusted owner time in Unix seconds, never a time
//! selected by the candidate or downloaded metadata. No returned observation
//! grants FinalUse, model quality or chain authority.

use crate::{
    verify_release_bundle_v0, Digest32V0, ReleaseBundleV0, ReleaseSignatureVerifierV0,
    VerifiedReleaseBundleV0,
};
use sha2::{Digest, Sha256, Sha512};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};
use trnm_crypto_primitives::pq_auth::PqNativeVerifier;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

mod bundle_quorum;
use bundle_quorum::VerifiedBundleQuorumV1;

mod initial_root_material;
pub use initial_root_material::PqInitialRootKeyMaterialV1;

pub const RELEASE_PQ_PROFILE_V1: &[u8] = b"TRNM/Release/PQ/ML-DSA-65/v1\0";
pub const MAX_RELEASE_KEYS_V1: usize = 16;
pub const MAX_RETAINED_RELEASES_V1: usize = 4096;
pub const MAX_RECOVERY_EVENTS_V1: usize = 8192;
pub type ReleaseDigestV1 = [u8; 32];
pub type ReleaseKeyIdV1 = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PqReleaseRoleV1 {
    NodeSoftware = 1,
    ProtocolConfiguration = 2,
    CellManifest = 3,
    CellActivation = 4,
}
const ROLES: [PqReleaseRoleV1; 4] = [
    PqReleaseRoleV1::NodeSoftware,
    PqReleaseRoleV1::ProtocolConfiguration,
    PqReleaseRoleV1::CellManifest,
    PqReleaseRoleV1::CellActivation,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqReleaseRoleKeysV1 {
    pub threshold: u16,
    /// Each key ID must match its strict DER SPKI. Keys are owner-pinned here;
    /// metadata and signatures never provide replacement verification keys.
    pub keys: BTreeMap<ReleaseKeyIdV1, Vec<u8>>,
}
impl PqReleaseRoleKeysV1 {
    fn validate(&self) -> Result<ReleaseVerifiersV1, PqReleaseErrorV1> {
        if self.keys.is_empty()
            || self.keys.len() > MAX_RELEASE_KEYS_V1
            || self.threshold == 0
            || usize::from(self.threshold) > self.keys.len()
        {
            return Err(PqReleaseErrorV1::InvalidThreshold);
        }
        let mut verifiers = BTreeMap::new();
        for (id, spki) in &self.keys {
            let verifier = PqNativeVerifier::from_pinned_spki(spki, *id)
                .map_err(|_| PqReleaseErrorV1::InvalidKey)?;
            verifiers.insert(*id, verifier);
        }
        Ok(verifiers)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.threshold.to_be_bytes());
        out.extend((self.keys.len() as u64).to_be_bytes());
        for (key_id, spki) in &self.keys {
            out.extend(key_id);
            out.extend((spki.len() as u64).to_be_bytes());
            out.extend(spki);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqReleaseRootV1 {
    pub network_id: ReleaseDigestV1,
    pub generation: u64,
    pub expires_at: u64,
    pub previous_root_digest: ReleaseDigestV1,
    pub offline_root: PqReleaseRoleKeysV1,
    pub roles: BTreeMap<PqReleaseRoleV1, PqReleaseRoleKeysV1>,
}

// Prepared public keys only, never signature or current-authorization results.
// Complete root validation bounds this map to five roles of at most sixteen keys.
type ReleaseVerifiersV1 = BTreeMap<ReleaseKeyIdV1, PqNativeVerifier>;

/// A complete validation of this immutable root, retained only for this borrow.
/// With unsigned owner time, validity at `now` also implies validity at zero.
struct ValidatedPqReleaseRootV1<'a> {
    root: &'a PqReleaseRootV1,
    verifiers: ReleaseVerifiersV1,
}

impl PqReleaseRootV1 {
    fn validate_header(&self, now: u64) -> Result<(), PqReleaseErrorV1> {
        if self.network_id == [0; 32] || self.generation == 0 || self.expires_at <= now {
            return Err(PqReleaseErrorV1::InvalidRoot);
        }
        Ok(())
    }
    fn validate(&self, now: u64) -> Result<ValidatedPqReleaseRootV1<'_>, PqReleaseErrorV1> {
        self.validate_header(now)?;
        let mut verifiers = self.offline_root.validate()?;
        if self.roles.len() != ROLES.len() || ROLES.iter().any(|r| !self.roles.contains_key(r)) {
            return Err(PqReleaseErrorV1::MissingRole);
        }
        // A compromised online role cannot count as an offline-root key, or
        // impersonate another role merely because its key was reused there.
        let mut seen: BTreeSet<_> = self.offline_root.keys.keys().copied().collect();
        for role in self.roles.values() {
            let role_verifiers = role.validate()?;
            for key in role.keys.keys() {
                if !seen.insert(*key) {
                    return Err(PqReleaseErrorV1::CrossRoleKey);
                }
            }
            verifiers.extend(role_verifiers);
        }
        Ok(ValidatedPqReleaseRootV1 {
            root: self,
            verifiers,
        })
    }
    /// Domain-separated digest of the bounded, uniquely encoded complete root.
    /// Metadata signing is pure ML-DSA over this project-specific message.
    pub fn signing_message(&self) -> Result<Vec<u8>, PqReleaseErrorV1> {
        Ok(self.validate(0)?.signing_message())
    }
    pub fn digest(&self) -> Result<ReleaseDigestV1, PqReleaseErrorV1> {
        Ok(Sha256::digest(self.signing_message()?).into())
    }
    fn all_keys(&self) -> BTreeSet<ReleaseKeyIdV1> {
        self.offline_root
            .keys
            .keys()
            .chain(self.roles.values().flat_map(|r| r.keys.keys()))
            .copied()
            .collect()
    }
}

impl ValidatedPqReleaseRootV1<'_> {
    fn signing_message(&self) -> Vec<u8> {
        encode_root_message(self.root)
    }

    fn into_verifiers(self) -> ReleaseVerifiersV1 {
        self.verifiers
    }
}

fn encode_root_message(root: &PqReleaseRootV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(RELEASE_PQ_PROFILE_V1);
    bytes.push(0); // offline root domain, distinct from all content roles
    bytes.extend(root.network_id);
    bytes.extend(root.generation.to_be_bytes());
    bytes.extend(root.expires_at.to_be_bytes());
    bytes.extend(root.previous_root_digest);
    root.offline_root.encode(&mut bytes);
    for (role, keys) in &root.roles {
        bytes.push(*role as u8);
        keys.encode(&mut bytes);
    }
    let digest: [u8; 64] = Sha512::digest(&bytes).into();
    let mut message = RELEASE_PQ_PROFILE_V1.to_vec();
    message.push(0);
    message.extend(digest);
    message
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqReleaseSignatureV1 {
    pub key_id: ReleaseKeyIdV1,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqReleaseMetadataV1 {
    pub network_id: ReleaseDigestV1,
    pub role: PqReleaseRoleV1,
    pub root_generation: u64,
    pub role_version: u64,
    pub expires_at: u64,
    /// Complete prior owner checkpoint, checked at the update linearization.
    pub expected_checkpoint: ReleaseDigestV1,
    pub previous_content: Option<ReleaseDigestV1>,
    pub content: ReleaseDigestV1,
    /// Must be explicitly signed when selecting any previously published content
    /// different from the current content. Versions still advance by exactly one.
    pub approved_content_rollback: bool,
}
impl PqReleaseMetadataV1 {
    pub fn signing_message(&self) -> Vec<u8> {
        let mut message = RELEASE_PQ_PROFILE_V1.to_vec();
        message.push(self.role as u8);
        message.extend(self.network_id);
        message.extend(self.root_generation.to_be_bytes());
        message.extend(self.role_version.to_be_bytes());
        message.extend(self.expires_at.to_be_bytes());
        message.extend(self.expected_checkpoint);
        match self.previous_content {
            Some(digest) => {
                message.push(1);
                message.extend(digest);
            }
            None => {
                message.push(0);
                message.extend([0; 32]);
            }
        }
        message.extend(self.content);
        message.push(u8::from(self.approved_content_rollback));
        message
    }
}

/// An accepted signed event plus its owner-observed time. Persist events in
/// accepted order together with their resulting checkpoints. This is a typed
/// storage boundary, not a network decoder or proof that persistence occurred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqReleaseEventV1 {
    RootRotation {
        root: PqReleaseRootV1,
        old_signatures: Vec<PqReleaseSignatureV1>,
        new_signatures: Vec<PqReleaseSignatureV1>,
        observed_at: u64,
    },
    Release {
        metadata: PqReleaseMetadataV1,
        signatures: Vec<PqReleaseSignatureV1>,
        observed_at: u64,
    },
}

/// An authenticated release observation, never an execution capability.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPqReleaseV1 {
    role: PqReleaseRoleV1,
    version: u64,
    content: ReleaseDigestV1,
    checkpoint: ReleaseDigestV1,
}
impl VerifiedPqReleaseV1 {
    pub fn role(&self) -> PqReleaseRoleV1 {
        self.role
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn content(&self) -> ReleaseDigestV1 {
        self.content
    }
    pub fn checkpoint(&self) -> ReleaseDigestV1 {
        self.checkpoint
    }
}

/// Facts from a role's latest accepted signed metadata. These are rebuilt from
/// the event journal, not inferred from the content digest or activation role.
#[derive(Clone, Copy)]
struct CurrentPqReleaseV1 {
    content: ReleaseDigestV1,
    root_generation: u64,
    expires_at: u64,
}

/// Single owner authorization state. Persist accepted signed events and their
/// checkpoints atomically outside this kernel; bootstrapping is not recovery.
/// At the retained-history/event limits it fails closed; it never evicts security
/// history. A future migration must preserve the trusted checkpoint and records.
pub struct PqReleaseAuthorityV1 {
    root: PqReleaseRootV1,
    // Immutable public-key material only. The explicit prepared-initial-root API
    // may share this map across fresh reconstructions of the exact pinned root.
    // No signature/current result is shared; rotation fully validates a new map.
    verifiers: Arc<ReleaseVerifiersV1>,
    root_digest: ReleaseDigestV1,
    checkpoint: ReleaseDigestV1,
    versions: BTreeMap<PqReleaseRoleV1, u64>,
    current: BTreeMap<PqReleaseRoleV1, CurrentPqReleaseV1>,
    history: BTreeSet<(PqReleaseRoleV1, ReleaseDigestV1)>,
    retired: BTreeSet<ReleaseKeyIdV1>,
    time_floor: u64,
    event_count: usize,
}
impl PqReleaseAuthorityV1 {
    /// The caller supplies an independently provisioned digest, not one received
    /// from a candidate Cell or the download being verified.
    pub fn bootstrap_pinned(
        root: PqReleaseRootV1,
        expected_root: ReleaseDigestV1,
        now: u64,
    ) -> Result<Self, PqReleaseErrorV1> {
        let (validated, message, digest) =
            initial_root_material::validate_initial(&root, expected_root, now)?;
        let verifiers = Arc::new(validated.into_verifiers());
        Ok(Self::fresh_initial(root, verifiers, digest, &message, now))
    }
    /// Rebuild all role versions, publication lifetimes/generations, content
    /// history, retired keys and time floor
    /// from the accepted event journal. Both pins must come from the trusted
    /// owner/recovery channel; never obtain `expected_checkpoint` from this same
    /// potentially rolled-back journal. Historical expiry is checked at each
    /// recorded time; current expiry is checked when the next action is taken.
    ///
    /// Replaying a software-release event restores authorization only. The
    /// installer still verifies the actual bundle, artifacts and provenance.
    pub fn recover_pinned(
        initial_root: PqReleaseRootV1,
        expected_initial_root: ReleaseDigestV1,
        initialized_at: u64,
        events: &[PqReleaseEventV1],
        expected_checkpoint: ReleaseDigestV1,
    ) -> Result<Self, PqReleaseErrorV1> {
        if events.len() > MAX_RECOVERY_EVENTS_V1 {
            return Err(PqReleaseErrorV1::HistoryFull);
        }
        let mut authority =
            Self::bootstrap_pinned(initial_root, expected_initial_root, initialized_at)?;
        for event in events {
            match event {
                PqReleaseEventV1::RootRotation {
                    root,
                    old_signatures,
                    new_signatures,
                    observed_at,
                } => {
                    authority.rotate_root(
                        root.clone(),
                        old_signatures,
                        new_signatures,
                        *observed_at,
                    )?;
                }
                PqReleaseEventV1::Release {
                    metadata,
                    signatures,
                    observed_at,
                } => {
                    authority.accept(metadata, signatures, *observed_at)?;
                }
            }
        }
        if authority.checkpoint != expected_checkpoint {
            return Err(PqReleaseErrorV1::CheckpointConflict);
        }
        Ok(authority)
    }
    pub fn checkpoint(&self) -> ReleaseDigestV1 {
        self.checkpoint
    }
    pub fn root_digest(&self) -> ReleaseDigestV1 {
        self.root_digest
    }
    pub fn root_generation(&self) -> u64 {
        self.root.generation
    }
    pub fn role_version(&self, role: PqReleaseRoleV1) -> u64 {
        self.versions.get(&role).copied().unwrap_or(0)
    }
    /// Historical state observation. This does not check publication lifetime,
    /// the current root generation, or an independent recovery frontier.
    pub fn current_content(&self, role: PqReleaseRoleV1) -> Option<ReleaseDigestV1> {
        self.current.get(&role).map(|release| release.content)
    }

    /// Recheck one publication against the owner's current authorization state.
    ///
    /// `expected_checkpoint` must come from the independently fresh owner channel,
    /// not this journal, a cached observation, or the release being checked. `now`
    /// must come from the owner's trusted clock. Reads do not advance or persist
    /// the clock floor; a later clock rollback is the clock owner's responsibility.
    ///
    /// Success is only a current check at this call. It neither verifies installed
    /// artifact bytes nor proves that owner state was durably committed, and it
    /// does not return an execution capability. The installer must retain those
    /// boundaries and repeat this check at the actual use boundary.
    pub fn check_current(
        &self,
        role: PqReleaseRoleV1,
        content: ReleaseDigestV1,
        expected_checkpoint: ReleaseDigestV1,
        now: u64,
    ) -> Result<(), PqReleaseErrorV1> {
        if self.checkpoint != expected_checkpoint {
            return Err(PqReleaseErrorV1::CheckpointConflict);
        }
        if now < self.time_floor {
            return Err(PqReleaseErrorV1::ClockRollback);
        }
        if self.root.expires_at <= now {
            return Err(PqReleaseErrorV1::Expired);
        }
        let current = self
            .current
            .get(&role)
            .ok_or(PqReleaseErrorV1::NotCurrent)?;
        if current.content != content {
            return Err(PqReleaseErrorV1::NotCurrent);
        }
        if current.root_generation != self.root.generation {
            return Err(PqReleaseErrorV1::WrongAuthority);
        }
        if current.expires_at <= now {
            return Err(PqReleaseErrorV1::Expired);
        }
        if role == PqReleaseRoleV1::CellActivation {
            let manifest = self
                .current
                .get(&PqReleaseRoleV1::CellManifest)
                .ok_or(PqReleaseErrorV1::UnpublishedActivation)?;
            if manifest.content != content
                || manifest.root_generation != self.root.generation
                || manifest.expires_at <= now
            {
                return Err(PqReleaseErrorV1::UnpublishedActivation);
            }
        }
        Ok(())
    }

    /// Both the previously trusted root quorum and the proposed root quorum sign
    /// exactly the same new root. A candidate or old online role cannot rotate it.
    pub fn rotate_root(
        &mut self,
        next: PqReleaseRootV1,
        old_signatures: &[PqReleaseSignatureV1],
        new_signatures: &[PqReleaseSignatureV1],
        now: u64,
    ) -> Result<ReleaseDigestV1, PqReleaseErrorV1> {
        if self.event_count >= MAX_RECOVERY_EVENTS_V1 {
            return Err(PqReleaseErrorV1::HistoryFull);
        }
        if now < self.time_floor {
            return Err(PqReleaseErrorV1::ClockRollback);
        }
        // Like TUF sequential root rotation, an expired old root may authorize a
        // fresh successor; expired roots cannot authorize release effects below.
        let validated = next.validate(now)?;
        if next.network_id != self.root.network_id
            || next.previous_root_digest != self.root_digest
            || Some(next.generation) != self.root.generation.checked_add(1)
        {
            return Err(PqReleaseErrorV1::RootSequence);
        }
        let next_keys = next.all_keys();
        if !self.retired.is_disjoint(&next_keys) {
            return Err(PqReleaseErrorV1::RetiredKey);
        }
        let old_keys = self.root.all_keys();
        let removed: BTreeSet<_> = old_keys.difference(&next_keys).copied().collect();
        if self.retired.len().saturating_add(removed.len()) > MAX_RETAINED_RELEASES_V1 {
            return Err(PqReleaseErrorV1::HistoryFull);
        }
        let message = validated.signing_message();
        // Reject both complete signer sets before spending signature-verification
        // work on either quorum. These borrows retain no authorization result.
        let old_quorum =
            preflight_quorum(&self.root.offline_root, &self.verifiers, old_signatures)?;
        let new_quorum =
            preflight_quorum(&next.offline_root, &validated.verifiers, new_signatures)?;
        verify_preflighted_quorum(&message, old_quorum)?;
        verify_preflighted_quorum(&message, new_quorum)?;
        let verifiers = Arc::new(validated.into_verifiers());
        let digest: ReleaseDigestV1 = Sha256::digest(&message).into();
        let checkpoint = next_checkpoint(self.checkpoint, &message, now);
        self.retired.extend(removed);
        self.root = next;
        self.verifiers = verifiers;
        self.root_digest = digest;
        self.checkpoint = checkpoint;
        self.time_floor = now;
        self.event_count += 1;
        Ok(checkpoint)
    }

    /// Stable network/role identity bound into the existing V0 bundle. Key/root
    /// rotation does not change the content digest of an old bundle. A fresh
    /// authorization still binds the current root generation and full checkpoint,
    /// and is verified against that root's current role keys.
    pub fn bundle_signer_identity(&self, role: PqReleaseRoleV1) -> ReleaseDigestV1 {
        let mut bytes = RELEASE_PQ_PROFILE_V1.to_vec();
        bytes.extend(b"bundle-role\0");
        bytes.extend(self.root.network_id);
        bytes.push(role as u8);
        Sha256::digest(bytes).into()
    }

    /// Compose V0 source/SBOM/provenance checks with actual current PQ role
    /// verification. Success advances this authorization owner's version only;
    /// callers still must durably commit before installing or activating.
    pub fn accept_bundle(
        &mut self,
        bundle: &ReleaseBundleV0,
        required_packages: &[(Vec<u8>, Vec<u8>)],
        metadata: &PqReleaseMetadataV1,
        signatures: &[PqReleaseSignatureV1],
        now: u64,
    ) -> Result<(VerifiedReleaseBundleV0, VerifiedPqReleaseV1), PqReleaseErrorV1> {
        if metadata.role != PqReleaseRoleV1::NodeSoftware
            || metadata.content != bundle.bundle_digest.0
        {
            return Err(PqReleaseErrorV1::BundleBinding);
        }
        let verifier = BoundPqBundleVerifierV1::new(self, metadata, signatures)?;
        let verified_bundle = verify_release_bundle_v0(&verifier, bundle, required_packages)
            .map_err(|_| PqReleaseErrorV1::InvalidBundle)?;
        // Consume only the actual V0 callback's same-call quorum observation.
        // Owner time, current role and all state checks still run below.
        let quorum = verifier.into_verified_quorum()?;
        let verified_release = self.accept_with_quorum(metadata, signatures, now, Some(quorum))?;
        Ok((verified_bundle, verified_release))
    }

    /// On success only, advance metadata/activation version and append history.
    /// The actual installer must commit this owner state before using the content.
    pub fn accept(
        &mut self,
        metadata: &PqReleaseMetadataV1,
        signatures: &[PqReleaseSignatureV1],
        now: u64,
    ) -> Result<VerifiedPqReleaseV1, PqReleaseErrorV1> {
        self.accept_with_quorum(metadata, signatures, now, None)
    }

    fn accept_with_quorum(
        &mut self,
        metadata: &PqReleaseMetadataV1,
        signatures: &[PqReleaseSignatureV1],
        now: u64,
        quorum: Option<VerifiedBundleQuorumV1<'_>>,
    ) -> Result<VerifiedPqReleaseV1, PqReleaseErrorV1> {
        if self.event_count >= MAX_RECOVERY_EVENTS_V1 {
            return Err(PqReleaseErrorV1::HistoryFull);
        }
        if now < self.time_floor {
            return Err(PqReleaseErrorV1::ClockRollback);
        }
        if self.root.expires_at <= now
            || metadata.expires_at <= now
            || metadata.expires_at > self.root.expires_at
        {
            return Err(PqReleaseErrorV1::Expired);
        }
        if metadata.network_id != self.root.network_id
            || metadata.root_generation != self.root.generation
        {
            return Err(PqReleaseErrorV1::WrongAuthority);
        }
        if metadata.expected_checkpoint != self.checkpoint
            || metadata.previous_content != self.current_content(metadata.role)
        {
            return Err(PqReleaseErrorV1::CheckpointConflict);
        }
        if Some(metadata.role_version) != self.role_version(metadata.role).checked_add(1) {
            return Err(PqReleaseErrorV1::VersionRollback);
        }
        if metadata.content == [0; 32] {
            return Err(PqReleaseErrorV1::InvalidContent);
        }
        let revisited = self.history.contains(&(metadata.role, metadata.content))
            && self.current_content(metadata.role) != Some(metadata.content);
        if metadata.approved_content_rollback != revisited {
            return Err(PqReleaseErrorV1::RollbackApproval);
        }
        if metadata.role == PqReleaseRoleV1::CellActivation {
            // Activation keys cannot renew an expired publication or carry its
            // authorization across a root rotation. The current publisher must
            // approve even identical bytes again at a higher manifest version.
            let manifest = self
                .current
                .get(&PqReleaseRoleV1::CellManifest)
                .ok_or(PqReleaseErrorV1::UnpublishedActivation)?;
            if manifest.content != metadata.content
                || manifest.root_generation != self.root.generation
                || manifest.expires_at <= now
            {
                return Err(PqReleaseErrorV1::UnpublishedActivation);
            }
        }
        if !self.history.contains(&(metadata.role, metadata.content))
            && self.history.len() >= MAX_RETAINED_RELEASES_V1
        {
            return Err(PqReleaseErrorV1::HistoryFull);
        }
        let message = metadata.signing_message();
        let role = self
            .root
            .roles
            .get(&metadata.role)
            .ok_or(PqReleaseErrorV1::MissingRole)?;
        match quorum {
            Some(quorum) => {
                quorum.consume(self.root_digest, metadata.role, &message, signatures)?
            }
            None => verify_quorum(role, &self.verifiers, &message, signatures)?,
        }
        let checkpoint = next_checkpoint(self.checkpoint, &message, now);
        self.versions.insert(metadata.role, metadata.role_version);
        self.current.insert(
            metadata.role,
            CurrentPqReleaseV1 {
                content: metadata.content,
                root_generation: metadata.root_generation,
                expires_at: metadata.expires_at,
            },
        );
        self.history.insert((metadata.role, metadata.content));
        self.checkpoint = checkpoint;
        self.time_floor = now;
        self.event_count += 1;
        Ok(VerifiedPqReleaseV1 {
            role: metadata.role,
            version: metadata.role_version,
            content: metadata.content,
            checkpoint,
        })
    }
}

/// Unique signature-set binding for V0's existing signature digest field.
/// Signature bytes remain outside the bundle digest to avoid circular signing.
pub fn pq_release_signature_digest_v1(
    signatures: &[PqReleaseSignatureV1],
) -> Result<ReleaseDigestV1, PqReleaseErrorV1> {
    if signatures.is_empty() || signatures.len() > MAX_RELEASE_KEYS_V1 {
        return Err(PqReleaseErrorV1::InsufficientSignatures);
    }
    let mut ordered: Vec<_> = signatures.iter().collect();
    ordered.sort_by_key(|signature| signature.key_id);
    let mut hash = Sha256::new();
    hash.update(b"TRNM/Release/PQ/SignatureSet/v1\0");
    let mut previous = None;
    for signature in ordered {
        if previous == Some(signature.key_id) {
            return Err(PqReleaseErrorV1::DuplicateSigner);
        }
        if signature.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqReleaseErrorV1::SignatureRejected);
        }
        hash.update(signature.key_id);
        hash.update(&signature.signature);
        previous = Some(signature.key_id);
    }
    Ok(hash.finalize().into())
}
struct BoundPqBundleVerifierV1<'root, 'input> {
    authority: &'root PqReleaseAuthorityV1,
    metadata: &'input PqReleaseMetadataV1,
    signatures: &'input [PqReleaseSignatureV1],
    identity: ReleaseDigestV1,
    verified_quorum: Cell<Option<VerifiedBundleQuorumV1<'input>>>,
}
impl<'root, 'input> BoundPqBundleVerifierV1<'root, 'input> {
    fn new(
        authority: &'root PqReleaseAuthorityV1,
        metadata: &'input PqReleaseMetadataV1,
        signatures: &'input [PqReleaseSignatureV1],
    ) -> Result<Self, PqReleaseErrorV1> {
        // Preserve the original missing-role check before V0 bundle validation.
        authority
            .root
            .roles
            .get(&metadata.role)
            .ok_or(PqReleaseErrorV1::MissingRole)?;
        Ok(Self {
            authority,
            metadata,
            signatures,
            identity: authority.bundle_signer_identity(metadata.role),
            verified_quorum: Cell::new(None),
        })
    }
    fn into_verified_quorum(self) -> Result<VerifiedBundleQuorumV1<'input>, PqReleaseErrorV1> {
        self.verified_quorum
            .into_inner()
            .ok_or(PqReleaseErrorV1::InvalidBundle)
    }
}
impl ReleaseSignatureVerifierV0 for BoundPqBundleVerifierV1<'_, '_> {
    type Error = PqReleaseErrorV1;
    fn verify_release_signature(&self, bundle: &ReleaseBundleV0) -> Result<(), Self::Error> {
        self.verified_quorum.set(None);
        if bundle.bundle_digest.0 != self.metadata.content
            || bundle.signer_identity_digest != Digest32V0(self.identity)
            || bundle.signature_digest
                != Digest32V0(pq_release_signature_digest_v1(self.signatures)?)
        {
            return Err(PqReleaseErrorV1::BundleBinding);
        }
        let quorum =
            VerifiedBundleQuorumV1::verify(self.authority, self.metadata, self.signatures)?;
        self.verified_quorum.set(Some(quorum));
        Ok(())
    }
}

fn next_checkpoint(previous: ReleaseDigestV1, message: &[u8], observed_at: u64) -> ReleaseDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"TRNM/Release/PQ/Checkpoint/v1\0");
    hash.update(previous);
    hash.update(observed_at.to_be_bytes());
    hash.update((message.len() as u64).to_be_bytes());
    hash.update(message);
    hash.finalize().into()
}
fn verify_quorum(
    role: &PqReleaseRoleKeysV1,
    verifiers: &ReleaseVerifiersV1,
    message: &[u8],
    signatures: &[PqReleaseSignatureV1],
) -> Result<(), PqReleaseErrorV1> {
    verify_preflighted_quorum(message, preflight_quorum(role, verifiers, signatures)?)
}

type PreflightQuorumV1<'keys, 'signatures> = Vec<(&'keys PqNativeVerifier, &'signatures [u8])>;

/// Complete bounded, cheap checks before any mathematical signature verification.
/// The returned pairs borrow these exact immutable pins and signature bytes;
/// neither a successful preflight nor a retained verifier is authorization.
fn preflight_quorum<'keys, 'signatures>(
    role: &PqReleaseRoleKeysV1,
    verifiers: &'keys ReleaseVerifiersV1,
    signatures: &'signatures [PqReleaseSignatureV1],
) -> Result<PreflightQuorumV1<'keys, 'signatures>, PqReleaseErrorV1> {
    if signatures.len() < usize::from(role.threshold) || signatures.len() > MAX_RELEASE_KEYS_V1 {
        return Err(PqReleaseErrorV1::InsufficientSignatures);
    }
    let mut seen = BTreeSet::new();
    let mut quorum = Vec::with_capacity(signatures.len());
    for signature in signatures {
        if !seen.insert(signature.key_id) {
            return Err(PqReleaseErrorV1::DuplicateSigner);
        }
        let key = role
            .keys
            .get(&signature.key_id)
            .ok_or(PqReleaseErrorV1::UnknownSigner)?;
        let verifier = verifiers
            .get(&signature.key_id)
            .ok_or(PqReleaseErrorV1::InvalidKey)?;
        if verifier.public_key_id() != signature.key_id
            || verifier.public_spki().as_slice() != key.as_slice()
        {
            return Err(PqReleaseErrorV1::InvalidKey);
        }
        if signature.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqReleaseErrorV1::SignatureRejected);
        }
        quorum.push((verifier, signature.signature.as_slice()));
    }
    Ok(quorum)
}

fn verify_preflighted_quorum(
    message: &[u8],
    quorum: PreflightQuorumV1<'_, '_>,
) -> Result<(), PqReleaseErrorV1> {
    // Every supplied signature must verify, including all entries beyond the
    // threshold. No successful mathematical observation is cached or reused.
    for (verifier, signature) in quorum {
        verifier
            .verify_exact_message(message, signature)
            .map_err(|_| PqReleaseErrorV1::SignatureRejected)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PqReleaseErrorV1 {
    InvalidThreshold,
    InvalidKey,
    InvalidRoot,
    MissingRole,
    CrossRoleKey,
    RootPin,
    RootSequence,
    RetiredKey,
    ClockRollback,
    Expired,
    WrongAuthority,
    CheckpointConflict,
    NotCurrent,
    VersionRollback,
    InvalidContent,
    RollbackApproval,
    UnpublishedActivation,
    HistoryFull,
    InsufficientSignatures,
    DuplicateSigner,
    UnknownSigner,
    SignatureRejected,
    BundleBinding,
    InvalidBundle,
}
impl fmt::Display for PqReleaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PQ release rejected: {self:?}")
    }
}
impl Error for PqReleaseErrorV1 {}

#[cfg(test)]
mod tests;
