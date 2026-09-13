use alloc::vec::Vec;

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_EPOCH_COMMITMENT},
    BlockKind, ChainId, ConsensusParametersHash, ConsensusParametersV0, Epoch, GenesisHash, Height,
    NextEpochCommitmentHash, ProtocolVersion, Result, RolloutPhase, StateRoot, UpgradePlanHash,
    ValidationError, ValidatorSet, ValidatorSetId, SCHEMA_VERSION_V0,
};

/// Checked height geometry for one epoch under an authenticated v0 parameter
/// preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EpochGeometryV0 {
    epoch: Epoch,
    epoch_start: Height,
    epoch_end: Height,
    checkpoint_height: Height,
    seal_1_height: Height,
    seal_2_height: Height,
}

impl EpochGeometryV0 {
    pub fn new(epoch: Epoch, parameters: &ConsensusParametersV0) -> Result<Self> {
        parameters.validate_safety_invariants()?;
        let length = parameters.epoch_length_blocks();
        let epoch_index = epoch.get();
        let epoch_start = epoch_index
            .checked_mul(length)
            .and_then(|height| height.checked_add(1))
            .ok_or(ValidationError::ArithmeticOverflow("epoch start"))?;
        let epoch_end = epoch_index
            .checked_add(1)
            .and_then(|count| count.checked_mul(length))
            .ok_or(ValidationError::ArithmeticOverflow("epoch end"))?;
        let seal_count = u64::from(parameters.epoch_seal_blocks());
        let checkpoint = epoch_end
            .checked_sub(seal_count)
            .ok_or(ValidationError::ArithmeticOverflow("checkpoint height"))?;
        let seal_1 = checkpoint
            .checked_add(1)
            .ok_or(ValidationError::ArithmeticOverflow("seal-1 height"))?;
        let value = Self {
            epoch,
            epoch_start: Height::new(epoch_start),
            epoch_end: Height::new(epoch_end),
            checkpoint_height: Height::new(checkpoint),
            seal_1_height: Height::new(seal_1),
            seal_2_height: Height::new(epoch_end),
        };
        let expected_seal_2 = value
            .seal_1_height
            .get()
            .checked_add(1)
            .ok_or(ValidationError::ArithmeticOverflow("seal-2 height"))?;
        if value.seal_2_height.get() != expected_seal_2 {
            return Err(ValidationError::InvalidEpochTransition(
                "v0 geometry does not contain exactly two seals",
            ));
        }
        Ok(value)
    }

    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    pub const fn epoch_start(self) -> Height {
        self.epoch_start
    }

    pub const fn epoch_end(self) -> Height {
        self.epoch_end
    }

    pub const fn checkpoint_height(self) -> Height {
        self.checkpoint_height
    }

    pub const fn seal_1_height(self) -> Height {
        self.seal_1_height
    }

    pub const fn seal_2_height(self) -> Height {
        self.seal_2_height
    }

    pub fn last_pre_checkpoint_height(self) -> Result<Height> {
        self.checkpoint_height
            .get()
            .checked_sub(1)
            .map(Height::new)
            .ok_or(ValidationError::ArithmeticOverflow(
                "last pre-checkpoint height",
            ))
    }

    pub fn expected_block_kind(self, height: Height) -> Result<BlockKind> {
        if height < self.epoch_start || height > self.epoch_end {
            return Err(ValidationError::InvalidEpochTransition(
                "height is outside the epoch geometry",
            ));
        }
        if self.epoch.get() > 0 && height == self.epoch_start {
            return Ok(BlockKind::EpochHandoff);
        }
        if height == self.checkpoint_height {
            return Ok(BlockKind::EpochCheckpoint);
        }
        if height == self.seal_1_height {
            return Ok(BlockKind::EpochSeal1);
        }
        if height == self.seal_2_height {
            return Ok(BlockKind::EpochSeal2);
        }
        Ok(BlockKind::Regular)
    }
}

/// Frozen v0 fallback-reason codes committed by `NextEpochCommitmentV0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum EpochFallbackReasonV0 {
    None = 0,
    MalformedSnapshotInput = 1,
    ArithmeticFailure = 2,
    TooFewEligibleValidators = 3,
    InvalidValidatorIdentityOrKey = 4,
    ValidatorWeightOutOfBounds = 5,
    InvalidTotalVotingPower = 6,
    ConcentrationConstraintViolated = 7,
    InvalidCommittedParameters = 8,
    InvalidUpgradeOrActivation = 9,
}

impl TryFrom<u16> for EpochFallbackReasonV0 {
    type Error = ValidationError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::MalformedSnapshotInput),
            2 => Ok(Self::ArithmeticFailure),
            3 => Ok(Self::TooFewEligibleValidators),
            4 => Ok(Self::InvalidValidatorIdentityOrKey),
            5 => Ok(Self::ValidatorWeightOutOfBounds),
            6 => Ok(Self::InvalidTotalVotingPower),
            7 => Ok(Self::ConcentrationConstraintViolated),
            8 => Ok(Self::InvalidCommittedParameters),
            9 => Ok(Self::InvalidUpgradeOrActivation),
            _ => Err(ValidationError::InvalidEpochTransition(
                "unknown fallback-reason code",
            )),
        }
    }
}

impl From<EpochFallbackReasonV0> for u16 {
    fn from(value: EpochFallbackReasonV0) -> Self {
        value as Self
    }
}

/// Exhaustive input for the exact frozen `NextEpochCommitmentV0` preimage.
///
/// Construction checks intrinsic object shape. Authorization against old/new
/// set and parameter preimages is a separate, explicitly same-version v0
/// operation; decoding this object never authorizes an epoch anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextEpochCommitmentV0Fields {
    pub schema_version: u16,
    pub genesis_hash: GenesisHash,
    pub chain_id: ChainId,
    pub old_epoch: Epoch,
    pub new_epoch: Epoch,
    pub snapshot_cutoff_height: Height,
    pub snapshot_state_root: StateRoot,
    pub new_protocol_version: ProtocolVersion,
    pub new_validator_set_hash: ValidatorSetId,
    pub new_consensus_parameters_hash: ConsensusParametersHash,
    pub rollout_phase: RolloutPhase,
    pub upgrade_plan_hash: Option<UpgradePlanHash>,
    pub fallback_used: bool,
    pub fallback_reason: EpochFallbackReasonV0,
    pub activation_height: Height,
}

/// Exact frozen next-epoch commitment logical object.
///
/// This value is an inert commitment preimage. It does not prove that the
/// snapshot existed, that the candidate-selection algorithm was executed, or
/// that checkpoint/two-seal ancestry and a joint handoff were authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextEpochCommitmentV0 {
    fields: NextEpochCommitmentV0Fields,
}

impl NextEpochCommitmentV0 {
    pub fn new(fields: NextEpochCommitmentV0Fields) -> Result<Self> {
        let value = Self { fields };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn fields(&self) -> NextEpochCommitmentV0Fields {
        self.fields
    }

    pub fn id(&self) -> NextEpochCommitmentHash {
        NextEpochCommitmentHash::new(canonical_hash(DOMAIN_EPOCH_COMMITMENT, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub fn validate_shape(&self) -> Result<()> {
        let fields = self.fields;
        if fields.schema_version != SCHEMA_VERSION_V0 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: fields.schema_version,
                expected: SCHEMA_VERSION_V0,
            });
        }
        if fields.genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if fields.new_epoch != fields.old_epoch.checked_next()? {
            return invalid("next-epoch commitment epochs are not adjacent");
        }
        if fields.snapshot_state_root.is_zero()
            || fields.new_validator_set_hash.is_zero()
            || fields.new_consensus_parameters_hash.is_zero()
        {
            return invalid("next-epoch commitment contains a zero required hash");
        }
        if fields
            .upgrade_plan_hash
            .is_some_and(|upgrade_plan_hash| upgrade_plan_hash.is_zero())
        {
            return invalid("present upgrade-plan hash is zero");
        }
        match (fields.fallback_used, fields.fallback_reason) {
            (false, EpochFallbackReasonV0::None) => {}
            (true, EpochFallbackReasonV0::None) => {
                return invalid("fallback=true requires a nonzero reason")
            }
            (false, _) => return invalid("fallback=false requires reason zero"),
            (true, _) => {}
        }
        if fields.activation_height.get() == 0 {
            return invalid("activation height must be positive");
        }
        Ok(())
    }

    /// Validates the committed preimage against exact old/new v0 contexts.
    ///
    /// `ConsensusParametersV0` deliberately supports protocol version zero
    /// only. Consequently this method closes same-version v0-to-v0 context
    /// binding, including deterministic schedule geometry and fallback
    /// identity. A later protocol-version upgrade requires that version's
    /// separately frozen parameter type and is rejected here.
    pub fn validate_same_version_context(
        &self,
        old_validator_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
        new_validator_set: &ValidatorSet,
        new_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        self.validate_shape()?;
        old_validator_set.validate_against_parameters(old_parameters)?;
        new_validator_set.validate_against_parameters(new_parameters)?;

        let fields = self.fields;
        let old_context = (
            old_validator_set.genesis_hash(),
            old_validator_set.chain_id(),
            old_validator_set.protocol_version(),
            old_validator_set.epoch(),
            old_validator_set.consensus_parameters_hash(),
        );
        let expected_old_context = (
            fields.genesis_hash,
            fields.chain_id,
            ProtocolVersion::V0,
            fields.old_epoch,
            old_parameters.hash(),
        );
        if old_context != expected_old_context {
            return invalid("old v0 context does not match next-epoch commitment");
        }

        let new_context = (
            new_validator_set.genesis_hash(),
            new_validator_set.chain_id(),
            new_validator_set.protocol_version(),
            new_validator_set.epoch(),
            new_validator_set.id(),
            new_validator_set.consensus_parameters_hash(),
            new_parameters.rollout_phase(),
        );
        let expected_new_context = (
            fields.genesis_hash,
            fields.chain_id,
            fields.new_protocol_version,
            fields.new_epoch,
            fields.new_validator_set_hash,
            fields.new_consensus_parameters_hash,
            fields.rollout_phase,
        );
        if new_context != expected_new_context {
            return invalid("new v0 context does not match next-epoch commitment");
        }
        if fields.new_protocol_version != ProtocolVersion::V0
            || old_parameters.protocol_version() != ProtocolVersion::V0.get()
            || new_parameters.protocol_version() != ProtocolVersion::V0.get()
        {
            return invalid("same-version v0 context cannot authorize a protocol upgrade");
        }
        if fields.upgrade_plan_hash.is_some() {
            return invalid("same-version v0 context lacks an authenticated upgrade-plan preimage");
        }
        if old_parameters.epoch_length_blocks() != new_parameters.epoch_length_blocks() {
            return invalid("v0 epoch length changed across the transition");
        }

        let geometry = EpochGeometryV0::new(fields.old_epoch, old_parameters)?;
        let expected_activation = geometry
            .epoch_end()
            .get()
            .checked_add(1)
            .ok_or(ValidationError::ArithmeticOverflow("activation height"))?;
        if fields.activation_height != Height::new(expected_activation) {
            return invalid("activation height differs from the outgoing v0 schedule");
        }
        let expected_snapshot_cutoff = geometry
            .checkpoint_height()
            .get()
            .checked_sub(old_parameters.snapshot_lead_blocks())
            .ok_or(ValidationError::ArithmeticOverflow(
                "snapshot cutoff height",
            ))?;
        if fields.snapshot_cutoff_height != Height::new(expected_snapshot_cutoff) {
            return invalid("snapshot cutoff differs from the outgoing v0 schedule");
        }

        if fields.fallback_used
            && (old_parameters != new_parameters
                || old_validator_set.validators() != new_validator_set.validators())
        {
            return invalid("fallback does not carry the exact old v0 configuration");
        }

        Ok(())
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        let fields = self.fields;
        encoder.u16(fields.schema_version);
        encoder.fixed(fields.genesis_hash.as_bytes());
        encoder.consensus_string(fields.chain_id.as_bytes());
        encoder.u64(fields.old_epoch.get());
        encoder.u64(fields.new_epoch.get());
        encoder.u64(fields.snapshot_cutoff_height.get());
        encoder.fixed(fields.snapshot_state_root.as_bytes());
        encoder.u32(fields.new_protocol_version.get());
        encoder.fixed(fields.new_validator_set_hash.as_bytes());
        encoder.fixed(fields.new_consensus_parameters_hash.as_bytes());
        encoder.u8(fields.rollout_phase.into());
        encoder.optional(fields.upgrade_plan_hash.is_some(), |encoder| {
            encoder.fixed(
                fields
                    .upgrade_plan_hash
                    .as_ref()
                    .expect("optional tag is present")
                    .as_bytes(),
            );
        });
        encoder.bool(fields.fallback_used);
        encoder.u16(fields.fallback_reason.into());
        encoder.u64(fields.activation_height.get());
    }
}

fn invalid(reason: &'static str) -> Result<()> {
    Err(ValidationError::InvalidEpochTransition(reason))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{ConsensusPublicKey, Validator, ValidatorId, VotingPower};

    #[test]
    fn epoch_geometry_freezes_checkpoint_seals_and_handoff_height() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let epoch_zero = EpochGeometryV0::new(Epoch::new(0), &parameters).unwrap();
        assert_eq!(epoch_zero.epoch_start(), Height::new(1));
        assert_eq!(epoch_zero.epoch_end(), Height::new(10_000));
        assert_eq!(epoch_zero.checkpoint_height(), Height::new(9_998));
        assert_eq!(epoch_zero.seal_1_height(), Height::new(9_999));
        assert_eq!(epoch_zero.seal_2_height(), Height::new(10_000));
        assert_eq!(
            epoch_zero.last_pre_checkpoint_height().unwrap(),
            Height::new(9_997)
        );
        assert_eq!(
            epoch_zero.expected_block_kind(Height::new(1)).unwrap(),
            BlockKind::Regular
        );
        assert_eq!(
            epoch_zero.expected_block_kind(Height::new(9_998)).unwrap(),
            BlockKind::EpochCheckpoint
        );
        assert_eq!(
            epoch_zero.expected_block_kind(Height::new(9_999)).unwrap(),
            BlockKind::EpochSeal1
        );
        assert_eq!(
            epoch_zero.expected_block_kind(Height::new(10_000)).unwrap(),
            BlockKind::EpochSeal2
        );
        assert!(epoch_zero.expected_block_kind(Height::new(10_001)).is_err());

        let epoch_one = EpochGeometryV0::new(Epoch::new(1), &parameters).unwrap();
        assert_eq!(epoch_one.epoch_start(), Height::new(10_001));
        assert_eq!(
            epoch_one
                .expected_block_kind(epoch_one.epoch_start())
                .unwrap(),
            BlockKind::EpochHandoff
        );
    }

    #[test]
    fn same_version_context_binds_schedule_sets_parameters_and_fallback() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let genesis = GenesisHash::new([1; 32]);
        let chain = ChainId::new("trnm-epoch-kernel").unwrap();
        let validators = validators();
        let old_set = ValidatorSet::new(
            genesis,
            chain,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators.clone(),
        )
        .unwrap();
        let new_set = ValidatorSet::new(
            genesis,
            chain,
            ProtocolVersion::V0,
            Epoch::new(1),
            parameters.hash(),
            validators,
        )
        .unwrap();
        let fields = NextEpochCommitmentV0Fields {
            schema_version: SCHEMA_VERSION_V0,
            genesis_hash: genesis,
            chain_id: chain,
            old_epoch: Epoch::new(0),
            new_epoch: Epoch::new(1),
            snapshot_cutoff_height: Height::new(9_898),
            snapshot_state_root: StateRoot::new([2; 32]),
            new_protocol_version: ProtocolVersion::V0,
            new_validator_set_hash: new_set.id(),
            new_consensus_parameters_hash: parameters.hash(),
            rollout_phase: parameters.rollout_phase(),
            upgrade_plan_hash: None,
            fallback_used: false,
            fallback_reason: EpochFallbackReasonV0::None,
            activation_height: Height::new(10_001),
        };
        let commitment = NextEpochCommitmentV0::new(fields).unwrap();
        commitment
            .validate_same_version_context(&old_set, &parameters, &new_set, &parameters)
            .unwrap();
        assert!(!commitment.try_cev0_bytes().unwrap().is_empty());
        assert!(!commitment.id().is_zero());

        let fallback = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            fallback_used: true,
            fallback_reason: EpochFallbackReasonV0::ArithmeticFailure,
            ..fields
        })
        .unwrap();
        fallback
            .validate_same_version_context(&old_set, &parameters, &new_set, &parameters)
            .unwrap();

        let wrong_cutoff = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            snapshot_cutoff_height: Height::new(9_899),
            ..fields
        })
        .unwrap();
        assert!(wrong_cutoff
            .validate_same_version_context(&old_set, &parameters, &new_set, &parameters)
            .is_err());

        let upgrade = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            upgrade_plan_hash: Some(UpgradePlanHash::new([3; 32])),
            ..fields
        })
        .unwrap();
        assert!(upgrade
            .validate_same_version_context(&old_set, &parameters, &new_set, &parameters)
            .is_err());
    }

    #[test]
    fn fallback_redundancy_and_required_hashes_fail_closed() {
        let mut fields = standalone_fields();
        fields.fallback_used = true;
        assert!(NextEpochCommitmentV0::new(fields).is_err());

        let mut fields = standalone_fields();
        fields.fallback_reason = EpochFallbackReasonV0::InvalidCommittedParameters;
        assert!(NextEpochCommitmentV0::new(fields).is_err());

        let mut fields = standalone_fields();
        fields.upgrade_plan_hash = Some(UpgradePlanHash::ZERO);
        assert!(NextEpochCommitmentV0::new(fields).is_err());

        assert!(EpochFallbackReasonV0::try_from(10).is_err());
        assert!(EpochFallbackReasonV0::try_from(u16::MAX).is_err());
    }

    fn standalone_fields() -> NextEpochCommitmentV0Fields {
        NextEpochCommitmentV0Fields {
            schema_version: SCHEMA_VERSION_V0,
            genesis_hash: GenesisHash::new([1; 32]),
            chain_id: ChainId::new("trnm-epoch-kernel").unwrap(),
            old_epoch: Epoch::new(0),
            new_epoch: Epoch::new(1),
            snapshot_cutoff_height: Height::new(9_898),
            snapshot_state_root: StateRoot::new([2; 32]),
            new_protocol_version: ProtocolVersion::V0,
            new_validator_set_hash: ValidatorSetId::new([3; 32]),
            new_consensus_parameters_hash: ConsensusParametersHash::new([4; 32]),
            rollout_phase: RolloutPhase::Shadow,
            upgrade_plan_hash: None,
            fallback_used: false,
            fallback_reason: EpochFallbackReasonV0::None,
            activation_height: Height::new(10_001),
        }
    }

    fn validators() -> Vec<Validator> {
        (1u8..=4)
            .map(|index| {
                Validator::new(
                    ValidatorId::from_bytes(&[index]).unwrap(),
                    ConsensusPublicKey::new([index; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect()
    }
}
