use super::{
    verify_quorum, PqReleaseAuthorityV1, PqReleaseErrorV1, PqReleaseMetadataV1, PqReleaseRoleV1,
    PqReleaseSignatureV1, ReleaseDigestV1,
};

/// Private, non-cloneable observation of the actual V0 callback's full quorum.
/// This owns the exact message and borrows the immutable signature bytes only
/// until the same accept_bundle call consumes it. It grants no current authority.
pub(super) struct VerifiedBundleQuorumV1<'a> {
    root_digest: ReleaseDigestV1,
    role: PqReleaseRoleV1,
    message: Vec<u8>,
    signatures: &'a [PqReleaseSignatureV1],
}

impl<'a> VerifiedBundleQuorumV1<'a> {
    pub(super) fn verify(
        authority: &PqReleaseAuthorityV1,
        metadata: &PqReleaseMetadataV1,
        signatures: &'a [PqReleaseSignatureV1],
    ) -> Result<Self, PqReleaseErrorV1> {
        let keys = authority
            .root
            .roles
            .get(&metadata.role)
            .ok_or(PqReleaseErrorV1::MissingRole)?;
        let message = metadata.signing_message();
        verify_quorum(keys, &authority.verifiers, &message, signatures)?;
        Ok(Self {
            root_digest: authority.root_digest,
            role: metadata.role,
            message,
            signatures,
        })
    }

    pub(super) fn consume(
        self,
        root_digest: ReleaseDigestV1,
        role: PqReleaseRoleV1,
        message: &[u8],
        signatures: &[PqReleaseSignatureV1],
    ) -> Result<(), PqReleaseErrorV1> {
        if self.root_digest != root_digest
            || self.role != role
            || self.message != message
            || self.signatures != signatures
        {
            return Err(PqReleaseErrorV1::SignatureRejected);
        }
        Ok(())
    }
}
