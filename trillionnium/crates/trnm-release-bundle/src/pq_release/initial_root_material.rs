use super::{
    encode_root_message, next_checkpoint, PqReleaseAuthorityV1, PqReleaseErrorV1, PqReleaseRootV1,
    ReleaseDigestV1, ReleaseVerifiersV1, ValidatedPqReleaseRootV1,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Immutable mathematical preparation of one complete independently pinned
/// initial root. No timestamp, checkpoint, authorization or signature result is
/// retained. This is not a current-root or dispatch capability.
pub struct PqInitialRootKeyMaterialV1 {
    root: PqReleaseRootV1,
    root_digest: ReleaseDigestV1,
    verifiers: Arc<ReleaseVerifiersV1>,
}

pub(super) fn validate_initial(
    root: &PqReleaseRootV1,
    expected_root: ReleaseDigestV1,
    now: u64,
) -> Result<(ValidatedPqReleaseRootV1<'_>, Vec<u8>, ReleaseDigestV1), PqReleaseErrorV1> {
    let validated = root.validate(now)?;
    let message = validated.signing_message();
    let digest: ReleaseDigestV1 = Sha256::digest(&message).into();
    if expected_root != digest || root.generation != 1 || root.previous_root_digest != [0; 32] {
        return Err(PqReleaseErrorV1::RootPin);
    }
    Ok((validated, message, digest))
}

impl PqInitialRootKeyMaterialV1 {
    /// The pin is an owner's independent input. `initialized_at` is the original
    /// trusted initialization time when replaying history, not today's clock.
    /// Every later bootstrap supplies and checks its own initialization time.
    pub fn prepare_pinned(
        root: PqReleaseRootV1,
        expected_root: ReleaseDigestV1,
        initialized_at: u64,
    ) -> Result<Self, PqReleaseErrorV1> {
        let (validated, _, root_digest) = validate_initial(&root, expected_root, initialized_at)?;
        let verifiers = Arc::new(validated.into_verifiers());
        Ok(Self {
            root,
            root_digest,
            verifiers,
        })
    }

    /// Full canonical root equality, not just key IDs or a caller-supplied hash.
    /// This observation says nothing about expiry, history, or current authority.
    pub fn matches_root(&self, root: &PqReleaseRootV1, expected_root: ReleaseDigestV1) -> bool {
        &self.root == root && self.root_digest == expected_root
    }
}

impl PqReleaseAuthorityV1 {
    /// Start a fresh empty authority while sharing only a matching initial root's
    /// immutable public-key preparation. History must still be fully replayed.
    /// The material's preparation time is never used as this call's time floor.
    pub fn bootstrap_pinned_with_material(
        root: PqReleaseRootV1,
        expected_root: ReleaseDigestV1,
        initialized_at: u64,
        material: &PqInitialRootKeyMaterialV1,
    ) -> Result<Self, PqReleaseErrorV1> {
        root.validate_header(initialized_at)?;
        if !material.matches_root(&root, expected_root) {
            // Preserve original malformed-root error precedence, but a second
            // otherwise valid root/pin cannot replace the material's identity.
            return match Self::bootstrap_pinned(root, expected_root, initialized_at) {
                Err(error) => Err(error),
                Ok(_) => Err(PqReleaseErrorV1::RootPin),
            };
        }
        let message = encode_root_message(&root);
        let digest: ReleaseDigestV1 = Sha256::digest(&message).into();
        if expected_root != digest || root.generation != 1 || root.previous_root_digest != [0; 32] {
            return Err(PqReleaseErrorV1::RootPin);
        }
        Ok(Self::fresh_initial(
            root,
            Arc::clone(&material.verifiers),
            digest,
            &message,
            initialized_at,
        ))
    }

    pub(super) fn fresh_initial(
        root: PqReleaseRootV1,
        verifiers: Arc<ReleaseVerifiersV1>,
        digest: ReleaseDigestV1,
        message: &[u8],
        now: u64,
    ) -> Self {
        let checkpoint = next_checkpoint([0; 32], message, now);
        Self {
            root,
            verifiers,
            root_digest: digest,
            checkpoint,
            versions: BTreeMap::new(),
            current: BTreeMap::new(),
            history: BTreeSet::new(),
            retired: BTreeSet::new(),
            time_floor: now,
            event_count: 0,
        }
    }
}
