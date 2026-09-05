//! Canonical, data-only old/new handoff signer requests.
//!
//! These values authenticate what a caller is asking an independent signer to
//! sign. Construction, decoding, or validation does **not** admit the request
//! to a journal, advance a watermark, invoke a producer, prove checkpoint
//! finality, or authorize an epoch transition. A signer integration must
//! require a separate unforgeable admission derived from the role's strict
//! transition prerequisites before any of those side effects.

use alloc::{boxed::Box, vec::Vec};

use subtle::ConstantTimeEq;

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_HANDOFF_SIGN_INTENT_V1},
    CertificateId, ChainId, ConsensusParametersHash, ConsensusParametersV0, Epoch, GenesisHash,
    HandoffDescriptorV0, ProtocolVersion, Result, SigningRoot, ValidationError, ValidatorId,
    ValidatorSet, ValidatorSetId,
};

/// Frozen schema for the typed old/new epoch-handoff signer request.
pub const CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1: u16 = 1;

/// Exact signer profile encoded into every handoff intent preimage.
///
/// This is distinct from the protocol handoff-vote signature domain. The
/// intent fingerprint authenticates the complete Core-to-signer request while
/// [`SigningRoot`] remains the existing role-specific protocol message root.
pub const HANDOFF_SIGNER_PROFILE_V1: &[u8] = b"trnm.poco-bft.handoff-signer.v1";

/// Closed role set. Old and new roles are never interchangeable journal keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum HandoffSignerRoleV1 {
    OldSet = 0,
    NewSet = 1,
}

impl TryFrom<u8> for HandoffSignerRoleV1 {
    type Error = ValidationError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::OldSet),
            1 => Ok(Self::NewSet),
            _ => Err(ValidationError::InvalidSignIntent(
                "unknown handoff signer role",
            )),
        }
    }
}

/// Hash of the complete immutable handoff signer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandoffSignIntentFingerprintV1([u8; 32]);

impl HandoffSignIntentFingerprintV1 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Exact, typed preimage requested for one old/new handoff signature.
///
/// The descriptor is retained both as its dedicated-domain digest and as its
/// exact canonical bytes. Old/new set and parameter references are repeated
/// explicitly, so neither role can be replayed under a different transition
/// profile even if a caller supplies the same protocol signing root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHandoffSignPreimageV1 {
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    old_epoch: Epoch,
    new_epoch: Epoch,
    signer_role: HandoffSignerRoleV1,
    validator_id: ValidatorId,
    old_protocol_version: ProtocolVersion,
    new_protocol_version: ProtocolVersion,
    old_validator_set_id: ValidatorSetId,
    new_validator_set_id: ValidatorSetId,
    old_consensus_parameters_hash: ConsensusParametersHash,
    new_consensus_parameters_hash: ConsensusParametersHash,
    descriptor_digest: CertificateId,
    descriptor_bytes: Vec<u8>,
    descriptor: HandoffDescriptorV0,
    signing_root: SigningRoot,
}

impl CanonicalHandoffSignPreimageV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        descriptor: &HandoffDescriptorV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
        signer_role: HandoffSignerRoleV1,
        validator_id: ValidatorId,
    ) -> Result<Self> {
        validate_transition_profile(
            descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
        )?;
        let authorizing_set = match signer_role {
            HandoffSignerRoleV1::OldSet => old_validator_set,
            HandoffSignerRoleV1::NewSet => new_validator_set,
        };
        if authorizing_set.validator(validator_id).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(validator_id)));
        }
        let fields = descriptor.fields();
        let descriptor_bytes = descriptor.try_cev0_bytes()?;
        let signing_root = match signer_role {
            HandoffSignerRoleV1::OldSet => descriptor.old_set_signing_root(),
            HandoffSignerRoleV1::NewSet => descriptor.new_set_signing_root(),
        };
        Ok(Self {
            schema_version: CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1,
            genesis_hash: fields.genesis_hash,
            chain_id: fields.chain_id,
            old_epoch: fields.old_epoch,
            new_epoch: fields.new_epoch,
            signer_role,
            validator_id,
            old_protocol_version: fields.old_protocol_version,
            new_protocol_version: fields.new_protocol_version,
            old_validator_set_id: old_validator_set.id(),
            new_validator_set_id: new_validator_set.id(),
            old_consensus_parameters_hash: old_consensus_parameters.hash(),
            new_consensus_parameters_hash: new_consensus_parameters.hash(),
            descriptor_digest: descriptor.id(),
            descriptor_bytes,
            descriptor: descriptor.clone(),
            signing_root,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn old_epoch(&self) -> Epoch {
        self.old_epoch
    }

    pub const fn new_epoch(&self) -> Epoch {
        self.new_epoch
    }

    pub const fn signer_role(&self) -> HandoffSignerRoleV1 {
        self.signer_role
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn old_protocol_version(&self) -> ProtocolVersion {
        self.old_protocol_version
    }

    pub const fn new_protocol_version(&self) -> ProtocolVersion {
        self.new_protocol_version
    }

    pub const fn old_validator_set_id(&self) -> ValidatorSetId {
        self.old_validator_set_id
    }

    pub const fn new_validator_set_id(&self) -> ValidatorSetId {
        self.new_validator_set_id
    }

    pub const fn old_consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.old_consensus_parameters_hash
    }

    pub const fn new_consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.new_consensus_parameters_hash
    }

    pub const fn descriptor_digest(&self) -> CertificateId {
        self.descriptor_digest
    }

    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    pub const fn descriptor(&self) -> &HandoffDescriptorV0 {
        &self.descriptor
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.signing_root
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode(encoder))
    }

    pub fn validate(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        if self.schema_version != CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: self.schema_version,
                expected: CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1,
            });
        }
        validate_transition_profile(
            &self.descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
        )?;
        let fields = self.descriptor.fields();
        if self.genesis_hash != fields.genesis_hash
            || self.chain_id != fields.chain_id
            || self.old_epoch != fields.old_epoch
            || self.new_epoch != fields.new_epoch
            || self.old_protocol_version != fields.old_protocol_version
            || self.new_protocol_version != fields.new_protocol_version
            || self.old_validator_set_id != old_validator_set.id()
            || self.new_validator_set_id != new_validator_set.id()
            || self.old_consensus_parameters_hash != old_consensus_parameters.hash()
            || self.new_consensus_parameters_hash != new_consensus_parameters.hash()
            || self.descriptor_digest != self.descriptor.id()
            || self.descriptor_bytes != self.descriptor.try_cev0_bytes()?
        {
            return Err(ValidationError::InvalidSignIntent(
                "handoff signer preimage differs from its exact transition profile",
            ));
        }
        let authorizing_set = match self.signer_role {
            HandoffSignerRoleV1::OldSet => old_validator_set,
            HandoffSignerRoleV1::NewSet => new_validator_set,
        };
        if authorizing_set.validator(self.validator_id).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(
                self.validator_id,
            )));
        }
        let expected_root = match self.signer_role {
            HandoffSignerRoleV1::OldSet => self.descriptor.old_set_signing_root(),
            HandoffSignerRoleV1::NewSet => self.descriptor.new_set_signing_root(),
        };
        if self
            .signing_root
            .as_bytes()
            .ct_eq(expected_root.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(ValidationError::InvalidSignIntent(
                "handoff signing root differs from descriptor role",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.schema_version);
        encoder.bytes(HANDOFF_SIGNER_PROFILE_V1);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u64(self.old_epoch.get());
        encoder.u64(self.new_epoch.get());
        encoder.u8(self.signer_role as u8);
        encoder.bytes(self.validator_id.as_bytes());
        encoder.u32(self.old_protocol_version.get());
        encoder.u32(self.new_protocol_version.get());
        encoder.fixed(self.old_validator_set_id.as_bytes());
        encoder.fixed(self.new_validator_set_id.as_bytes());
        encoder.fixed(self.old_consensus_parameters_hash.as_bytes());
        encoder.fixed(self.new_consensus_parameters_hash.as_bytes());
        encoder.fixed(self.descriptor_digest.as_bytes());
        encoder.bytes(&self.descriptor_bytes);
        encoder.fixed(self.signing_root.as_bytes());
    }
}

/// Complete typed, data-only handoff signer request.
///
/// There is intentionally no constructor accepting arbitrary bytes or a
/// caller-provided signing root. This type is nevertheless not signing
/// admission: even a valid instance must not by itself trigger persistence,
/// an external watermark, or a private-key producer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHandoffSignIntentV1 {
    preimage: CanonicalHandoffSignPreimageV1,
    fingerprint: HandoffSignIntentFingerprintV1,
}

impl CanonicalHandoffSignIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn old_set(
        descriptor: &HandoffDescriptorV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
        validator_id: ValidatorId,
    ) -> Result<Self> {
        Self::new(
            descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            HandoffSignerRoleV1::OldSet,
            validator_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_set(
        descriptor: &HandoffDescriptorV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
        validator_id: ValidatorId,
    ) -> Result<Self> {
        Self::new(
            descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            HandoffSignerRoleV1::NewSet,
            validator_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        descriptor: &HandoffDescriptorV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
        signer_role: HandoffSignerRoleV1,
        validator_id: ValidatorId,
    ) -> Result<Self> {
        let preimage = CanonicalHandoffSignPreimageV1::new(
            descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            signer_role,
            validator_id,
        )?;
        let fingerprint = HandoffSignIntentFingerprintV1::new(canonical_hash(
            DOMAIN_HANDOFF_SIGN_INTENT_V1,
            |encoder| preimage.encode(encoder),
        ));
        Ok(Self {
            preimage,
            fingerprint,
        })
    }

    pub const fn preimage(&self) -> &CanonicalHandoffSignPreimageV1 {
        &self.preimage
    }

    pub const fn signer_role(&self) -> HandoffSignerRoleV1 {
        self.preimage.signer_role()
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.preimage.validator_id()
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.preimage.signing_root()
    }

    pub const fn fingerprint(&self) -> HandoffSignIntentFingerprintV1 {
        self.fingerprint
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            self.preimage.encode(encoder);
            encoder.fixed(self.fingerprint.as_bytes());
        })
    }

    pub fn validate(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_consensus_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        self.preimage.validate(
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
        )?;
        let expected = canonical_hash(DOMAIN_HANDOFF_SIGN_INTENT_V1, |encoder| {
            self.preimage.encode(encoder);
        });
        if self.fingerprint.as_bytes().ct_eq(&expected).unwrap_u8() != 1 {
            return Err(ValidationError::InvalidSignIntent(
                "handoff sign intent fingerprint differs from immutable fields",
            ));
        }
        Ok(())
    }
}

fn validate_transition_profile(
    descriptor: &HandoffDescriptorV0,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_consensus_parameters: &ConsensusParametersV0,
) -> Result<()> {
    descriptor.validate_shape()?;
    old_validator_set.validate_against_parameters(old_consensus_parameters)?;
    new_validator_set.validate_against_parameters(new_consensus_parameters)?;
    let fields = descriptor.fields();
    if old_validator_set.genesis_hash() != fields.genesis_hash
        || new_validator_set.genesis_hash() != fields.genesis_hash
        || old_validator_set.chain_id() != fields.chain_id
        || new_validator_set.chain_id() != fields.chain_id
        || old_validator_set.protocol_version() != fields.old_protocol_version
        || new_validator_set.protocol_version() != fields.new_protocol_version
        || old_validator_set.epoch() != fields.old_epoch
        || new_validator_set.epoch() != fields.new_epoch
        || old_validator_set.id() != fields.old_validator_set_hash
        || new_validator_set.id() != fields.new_validator_set_hash
        || old_validator_set.consensus_parameters_hash() != fields.old_consensus_parameters_hash
        || new_validator_set.consensus_parameters_hash() != fields.new_consensus_parameters_hash
        || old_consensus_parameters.hash() != fields.old_consensus_parameters_hash
        || new_consensus_parameters.hash() != fields.new_consensus_parameters_hash
    {
        return Err(ValidationError::InvalidSignIntent(
            "handoff descriptor differs from trusted old/new set and parameter references",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        decode_canonical_handoff_sign_intent_v1_exact, BlockId, ConsensusPublicKey,
        HandoffDescriptorV0Fields, Height, NextEpochCommitmentHash, StateRoot, Validator, View,
        VotingPower, MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1,
    };

    const GENESIS: GenesisHash = GenesisHash::new([7; 32]);
    const CHAIN: ChainId = ChainId::from_static("handoff-intent-tests");

    fn validator(id: &'static [u8], key: u8) -> Validator {
        Validator::new(
            ValidatorId::from_bytes(id).unwrap(),
            ConsensusPublicKey::new([key; 32]),
            VotingPower::new(1).unwrap(),
        )
        .unwrap()
    }

    fn set(
        epoch: u64,
        parameters: &ConsensusParametersV0,
        members: [(&'static [u8], u8); 4],
    ) -> ValidatorSet {
        ValidatorSet::new(
            GENESIS,
            CHAIN,
            ProtocolVersion::V0,
            Epoch::new(epoch),
            parameters.hash(),
            members
                .into_iter()
                .map(|(id, key)| validator(id, key))
                .collect(),
        )
        .unwrap()
    }

    fn fixture() -> (
        ConsensusParametersV0,
        ConsensusParametersV0,
        ValidatorSet,
        ValidatorSet,
        HandoffDescriptorV0,
    ) {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let new_parameters = ConsensusParametersV0::reference_shadow_v0();
        let old_set = set(
            41,
            &old_parameters,
            [(b"a", 1), (b"b", 2), (b"c", 3), (b"d", 4)],
        );
        let new_set = set(
            42,
            &new_parameters,
            [(b"a", 1), (b"b", 2), (b"e", 5), (b"f", 6)],
        );
        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash: GENESIS,
            chain_id: CHAIN,
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: old_set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: old_parameters.hash(),
            new_consensus_parameters_hash: new_parameters.hash(),
            checkpoint_height: Height::new(100),
            checkpoint_block_id: BlockId::new([11; 32]),
            checkpoint_state_root: StateRoot::new([12; 32]),
            next_epoch_commitment_digest: NextEpochCommitmentHash::new([13; 32]),
            terminal_old_height: Height::new(102),
            terminal_old_block_id: BlockId::new([14; 32]),
            terminal_old_qc_digest: CertificateId::new([15; 32]),
            terminal_old_view: View::new(17),
            activation_height: Height::new(103),
            initial_new_view: View::new(1),
        })
        .unwrap();
        (old_parameters, new_parameters, old_set, new_set, descriptor)
    }

    fn decode(
        bytes: &[u8],
        old_set: &ValidatorSet,
        new_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
        new_parameters: &ConsensusParametersV0,
    ) -> crate::DecodeResult<CanonicalHandoffSignIntentV1> {
        decode_canonical_handoff_sign_intent_v1_exact(
            bytes,
            old_set,
            new_set,
            old_parameters,
            new_parameters,
        )
    }

    #[test]
    fn typed_roles_round_trip_and_bind_every_transition_reference() {
        let (old_parameters, new_parameters, old_set, new_set, descriptor) = fixture();
        let author = ValidatorId::from_bytes(b"a").unwrap();
        let old = CanonicalHandoffSignIntentV1::old_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            author,
        )
        .unwrap();
        let new = CanonicalHandoffSignIntentV1::new_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            author,
        )
        .unwrap();

        assert_eq!(old.signer_role(), HandoffSignerRoleV1::OldSet);
        assert_eq!(new.signer_role(), HandoffSignerRoleV1::NewSet);
        assert_eq!(old.signing_root(), descriptor.old_set_signing_root());
        assert_eq!(new.signing_root(), descriptor.new_set_signing_root());
        assert_ne!(old.signing_root(), new.signing_root());
        assert_ne!(old.fingerprint(), new.fingerprint());
        assert_eq!(old.preimage().descriptor_digest(), descriptor.id());
        assert_eq!(
            old.preimage().descriptor_bytes(),
            descriptor.try_cev0_bytes().unwrap()
        );
        assert_eq!(old.preimage().old_validator_set_id(), old_set.id());
        assert_eq!(old.preimage().new_validator_set_id(), new_set.id());
        assert_eq!(
            old.preimage().old_consensus_parameters_hash(),
            old_parameters.hash()
        );
        assert_eq!(
            old.preimage().new_consensus_parameters_hash(),
            new_parameters.hash()
        );

        for intent in [&old, &new] {
            let bytes = intent.canonical_bytes().unwrap();
            assert!(bytes.len() <= MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1);
            assert_eq!(
                decode(&bytes, &old_set, &new_set, &old_parameters, &new_parameters,).unwrap(),
                *intent
            );
            assert_eq!(intent.clone().canonical_bytes().unwrap(), bytes);
        }
    }

    #[test]
    fn every_single_byte_mutation_and_boundary_splice_is_rejected() {
        let (old_parameters, new_parameters, old_set, new_set, descriptor) = fixture();
        let intent = CanonicalHandoffSignIntentV1::old_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            ValidatorId::from_bytes(b"a").unwrap(),
        )
        .unwrap();
        let bytes = intent.canonical_bytes().unwrap();

        for offset in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 1;
            assert!(
                decode(
                    &mutated,
                    &old_set,
                    &new_set,
                    &old_parameters,
                    &new_parameters,
                )
                .is_err(),
                "single-byte mutation at {offset} was admitted"
            );
        }
        for prefix in 0..bytes.len() {
            assert!(
                decode(
                    &bytes[..prefix],
                    &old_set,
                    &new_set,
                    &old_parameters,
                    &new_parameters,
                )
                .is_err(),
                "truncated prefix {prefix} was admitted"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(
            &trailing,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
        )
        .is_err());
        let oversized = vec![0; MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1 + 1];
        assert_eq!(
            decode(
                &oversized,
                &old_set,
                &new_set,
                &old_parameters,
                &new_parameters,
            )
            .unwrap_err()
            .code(),
            crate::DecodeErrorCode::LengthLimitExceeded
        );
    }

    #[test]
    fn replay_under_alternate_set_parameter_or_role_context_is_rejected() {
        let (old_parameters, new_parameters, old_set, new_set, descriptor) = fixture();
        let author = ValidatorId::from_bytes(b"a").unwrap();
        let old = CanonicalHandoffSignIntentV1::old_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            author,
        )
        .unwrap();
        let bytes = old.canonical_bytes().unwrap();

        let alternate_old_set = set(
            41,
            &old_parameters,
            [(b"a", 21), (b"b", 2), (b"c", 3), (b"d", 4)],
        );
        assert!(decode(
            &bytes,
            &alternate_old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
        )
        .is_err());

        let mut alternate_fields = new_parameters.fields();
        alternate_fields.max_block_time_step_ms += 1;
        let alternate_parameters = ConsensusParametersV0::new(alternate_fields).unwrap();
        let alternate_new_set = set(
            42,
            &alternate_parameters,
            [(b"a", 1), (b"b", 2), (b"e", 5), (b"f", 6)],
        );
        assert!(decode(
            &bytes,
            &old_set,
            &alternate_new_set,
            &old_parameters,
            &alternate_parameters,
        )
        .is_err());

        let role_offset =
            2 + 4 + HANDOFF_SIGNER_PROFILE_V1.len() + 32 + 2 + CHAIN.as_bytes().len() + 8 + 8;
        let mut unknown_role = bytes.clone();
        unknown_role[role_offset] = 2;
        assert_eq!(
            decode(
                &unknown_role,
                &old_set,
                &new_set,
                &old_parameters,
                &new_parameters,
            )
            .unwrap_err()
            .code(),
            crate::DecodeErrorCode::InvalidHandoffSignIntentRole
        );
    }

    #[test]
    fn role_membership_is_exact_and_never_inferred_from_the_other_set() {
        let (old_parameters, new_parameters, old_set, new_set, descriptor) = fixture();
        let old_only = ValidatorId::from_bytes(b"c").unwrap();
        let new_only = ValidatorId::from_bytes(b"e").unwrap();
        assert!(CanonicalHandoffSignIntentV1::new_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            old_only,
        )
        .is_err());
        assert!(CanonicalHandoffSignIntentV1::old_set(
            &descriptor,
            &old_set,
            &new_set,
            &old_parameters,
            &new_parameters,
            new_only,
        )
        .is_err());
    }
}
