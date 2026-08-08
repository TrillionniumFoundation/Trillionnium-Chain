use alloc::vec::Vec;

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_PARAMETERS},
    ConsensusParametersHash, Result, ValidationError, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATORS,
    MAX_VALIDATOR_ID_BYTES, SCHEMA_VERSION_V0,
};

/// Frozen PoCO-BFT v0 leader-schedule discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LeaderSchedule {
    CanonicalValidatorRoundRobin = 0,
}

impl TryFrom<u8> for LeaderSchedule {
    type Error = ValidationError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::CanonicalValidatorRoundRobin),
            _ => Err(ValidationError::InvalidConsensusParameters(
                "unknown leader-schedule discriminant",
            )),
        }
    }
}

impl From<LeaderSchedule> for u8 {
    fn from(value: LeaderSchedule) -> Self {
        value as Self
    }
}

/// Frozen PoCO-BFT v0 rollout-phase discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RolloutPhase {
    Shadow = 0,
    EligibilityOnly = 1,
    CappedWeight = 2,
    Full = 3,
}

impl TryFrom<u8> for RolloutPhase {
    type Error = ValidationError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Shadow),
            1 => Ok(Self::EligibilityOnly),
            2 => Ok(Self::CappedWeight),
            3 => Ok(Self::Full),
            _ => Err(ValidationError::InvalidConsensusParameters(
                "unknown rollout-phase discriminant",
            )),
        }
    }
}

impl From<RolloutPhase> for u8 {
    fn from(value: RolloutPhase) -> Self {
        value as Self
    }
}

/// Exhaustive construction input for the exact frozen 54-field
/// `ConsensusParametersV0` logical value.
///
/// Public fields make omissions a compile-time error. They are not themselves
/// validated consensus parameters; pass the complete value to
/// [`ConsensusParametersV0::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConsensusParametersV0Fields {
    pub schema_version: u16,
    pub protocol_version: u32,
    pub production_activation: bool,
    pub max_chain_id_bytes: u16,
    pub max_validator_id_bytes: u16,
    pub max_block_bytes: u32,
    pub max_consensus_message_bytes: u32,
    pub min_validators: u32,
    pub max_validators: u32,
    pub quorum_numerator: u32,
    pub quorum_denominator: u32,
    pub quorum_addend: u32,
    pub finality_certified_chain_length: u8,
    pub max_total_voting_power: u64,
    pub max_block_time_step_ms: u64,
    pub leader_schedule: LeaderSchedule,
    pub require_full_payload_before_vote: bool,
    pub base_timeout_ms: u64,
    pub timeout_multiplier_numerator: u32,
    pub timeout_multiplier_denominator: u32,
    pub timeout_max_ms: u64,
    pub epoch_length_blocks: u64,
    pub epoch_seal_blocks: u8,
    pub snapshot_lead_blocks: u64,
    pub joint_handoff_old_quorum: bool,
    pub joint_handoff_new_quorum: bool,
    pub upgrade_notice_epochs: u64,
    pub max_protocol_version_jump: u32,
    pub scale_ppm: u64,
    pub maturity_epochs: u64,
    pub max_certificate_age_epochs: u64,
    pub decay_step_ppm_per_epoch: u64,
    pub per_certificate_unit_cap: u128,
    pub per_consumer_provider_epoch_unit_cap: u128,
    pub per_task_provider_epoch_unit_cap: u128,
    pub per_provider_epoch_unit_cap: u128,
    pub units_per_power: u128,
    pub bond_atomic_units_per_power: u128,
    pub min_validator_power: u64,
    pub max_validator_power: u64,
    pub max_validator_share_ppm: u64,
    pub capped_weight_alpha_ppm: u64,
    pub full_weight_alpha_ppm: u64,
    pub rollout_phase: RolloutPhase,
    pub minimum_shadow_epochs: u64,
    pub minimum_eligibility_only_epochs: u64,
    pub minimum_capped_weight_epochs: u64,
    pub automatic_promotion: bool,
    pub evidence_window_epochs: u64,
    pub unbonding_delay_epochs: u64,
    pub jail_duration_epochs: u64,
    pub trusting_period_epochs: u64,
    pub require_trusting_period_less_than_evidence: bool,
    pub require_evidence_window_le_unbonding_delay: bool,
}

/// Exact frozen `ConsensusParametersV0` logical value.
///
/// Construction validates version-wide shape, range, arithmetic, and
/// cross-parameter safety invariants. The current P0 reference profile's
/// shadow-only policy is checked separately so this type does not permanently
/// forbid a future, epoch-governed production activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConsensusParametersV0 {
    fields: ConsensusParametersV0Fields,
}

macro_rules! parameter_getters {
    ($(($name:ident, $type:ty)),+ $(,)?) => {
        $(
            pub const fn $name(&self) -> $type {
                self.fields.$name
            }
        )+
    };
}

impl ConsensusParametersV0 {
    pub fn new(fields: ConsensusParametersV0Fields) -> Result<Self> {
        let value = Self { fields };
        value.validate_safety_invariants()?;
        Ok(value)
    }

    /// The exact values committed by `parameters.toml` for the P0 reference
    /// shadow-only profile. This does not parse TOML and contains no runtime
    /// activation decision.
    pub fn reference_shadow_v0() -> Self {
        let value = Self::new(ConsensusParametersV0Fields {
            schema_version: 0,
            protocol_version: 0,
            production_activation: false,
            max_chain_id_bytes: 128,
            max_validator_id_bytes: 128,
            max_block_bytes: 4_194_304,
            max_consensus_message_bytes: 8_388_608,
            min_validators: 4,
            max_validators: 100,
            quorum_numerator: 2,
            quorum_denominator: 3,
            quorum_addend: 1,
            finality_certified_chain_length: 3,
            max_total_voting_power: 1_152_921_504_606_846_975,
            max_block_time_step_ms: 60_000,
            leader_schedule: LeaderSchedule::CanonicalValidatorRoundRobin,
            require_full_payload_before_vote: true,
            base_timeout_ms: 1_000,
            timeout_multiplier_numerator: 3,
            timeout_multiplier_denominator: 2,
            timeout_max_ms: 30_000,
            epoch_length_blocks: 10_000,
            epoch_seal_blocks: 2,
            snapshot_lead_blocks: 100,
            joint_handoff_old_quorum: true,
            joint_handoff_new_quorum: true,
            upgrade_notice_epochs: 2,
            max_protocol_version_jump: 1,
            scale_ppm: 1_000_000,
            maturity_epochs: 2,
            max_certificate_age_epochs: 20,
            decay_step_ppm_per_epoch: 50_000,
            per_certificate_unit_cap: 1_000_000,
            per_consumer_provider_epoch_unit_cap: 10_000_000,
            per_task_provider_epoch_unit_cap: 50_000_000,
            per_provider_epoch_unit_cap: 500_000_000,
            units_per_power: 1_000_000,
            bond_atomic_units_per_power: 1_000_000_000,
            min_validator_power: 1,
            max_validator_power: 1_000_000,
            max_validator_share_ppm: 250_000,
            capped_weight_alpha_ppm: 250_000,
            full_weight_alpha_ppm: 1_000_000,
            rollout_phase: RolloutPhase::Shadow,
            minimum_shadow_epochs: 10,
            minimum_eligibility_only_epochs: 10,
            minimum_capped_weight_epochs: 20,
            automatic_promotion: false,
            evidence_window_epochs: 28,
            unbonding_delay_epochs: 30,
            jail_duration_epochs: 2,
            trusting_period_epochs: 21,
            require_trusting_period_less_than_evidence: true,
            require_evidence_window_le_unbonding_delay: true,
        })
        .expect("the frozen P0 reference parameters satisfy v0 safety invariants");
        value
            .validate_reference_shadow_profile()
            .expect("the frozen P0 reference parameters remain shadow-only");
        value
    }

    pub const fn fields(&self) -> ConsensusParametersV0Fields {
        self.fields
    }

    parameter_getters!(
        (schema_version, u16),
        (protocol_version, u32),
        (production_activation, bool),
        (max_chain_id_bytes, u16),
        (max_validator_id_bytes, u16),
        (max_block_bytes, u32),
        (max_consensus_message_bytes, u32),
        (min_validators, u32),
        (max_validators, u32),
        (quorum_numerator, u32),
        (quorum_denominator, u32),
        (quorum_addend, u32),
        (finality_certified_chain_length, u8),
        (max_total_voting_power, u64),
        (max_block_time_step_ms, u64),
        (leader_schedule, LeaderSchedule),
        (require_full_payload_before_vote, bool),
        (base_timeout_ms, u64),
        (timeout_multiplier_numerator, u32),
        (timeout_multiplier_denominator, u32),
        (timeout_max_ms, u64),
        (epoch_length_blocks, u64),
        (epoch_seal_blocks, u8),
        (snapshot_lead_blocks, u64),
        (joint_handoff_old_quorum, bool),
        (joint_handoff_new_quorum, bool),
        (upgrade_notice_epochs, u64),
        (max_protocol_version_jump, u32),
        (scale_ppm, u64),
        (maturity_epochs, u64),
        (max_certificate_age_epochs, u64),
        (decay_step_ppm_per_epoch, u64),
        (per_certificate_unit_cap, u128),
        (per_consumer_provider_epoch_unit_cap, u128),
        (per_task_provider_epoch_unit_cap, u128),
        (per_provider_epoch_unit_cap, u128),
        (units_per_power, u128),
        (bond_atomic_units_per_power, u128),
        (min_validator_power, u64),
        (max_validator_power, u64),
        (max_validator_share_ppm, u64),
        (capped_weight_alpha_ppm, u64),
        (full_weight_alpha_ppm, u64),
        (rollout_phase, RolloutPhase),
        (minimum_shadow_epochs, u64),
        (minimum_eligibility_only_epochs, u64),
        (minimum_capped_weight_epochs, u64),
        (automatic_promotion, bool),
        (evidence_window_epochs, u64),
        (unbonding_delay_epochs, u64),
        (jail_duration_epochs, u64),
        (trusting_period_epochs, u64),
        (require_trusting_period_less_than_evidence, bool),
        (require_evidence_window_le_unbonding_delay, bool),
    );

    /// Validates invariants that apply to every v0 parameter value, regardless
    /// of a later governed rollout phase or production-activation decision.
    pub fn validate_safety_invariants(&self) -> Result<()> {
        let fields = &self.fields;

        if fields.schema_version != SCHEMA_VERSION_V0 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: fields.schema_version,
                expected: SCHEMA_VERSION_V0,
            });
        }
        if fields.protocol_version != 0 {
            return Err(ValidationError::InvalidProtocolVersion);
        }
        if fields.max_chain_id_bytes == 0
            || usize::from(fields.max_chain_id_bytes) > MAX_CONSENSUS_STRING_BYTES
        {
            return invalid("chain-ID byte limit is outside the v0 hard bound");
        }
        if fields.max_validator_id_bytes == 0
            || usize::from(fields.max_validator_id_bytes) > MAX_VALIDATOR_ID_BYTES
        {
            return invalid("validator-ID byte limit is outside the v0 hard bound");
        }
        if fields.min_validators < 4
            || fields.min_validators > fields.max_validators
            || u32::try_from(MAX_VALIDATORS).map_or(true, |maximum| fields.max_validators > maximum)
        {
            return invalid("validator bounds are inconsistent");
        }
        if fields.max_block_bytes == 0
            || fields.max_consensus_message_bytes == 0
            || fields.max_block_bytes > fields.max_consensus_message_bytes
        {
            return invalid("block and consensus-message byte limits must be positive and ordered");
        }
        if !fields.require_full_payload_before_vote {
            return invalid("v0 always requires the complete payload before a vote");
        }
        if (
            fields.quorum_numerator,
            fields.quorum_denominator,
            fields.quorum_addend,
        ) != (2, 3, 1)
        {
            return invalid("v0 quorum must be floor(2W/3)+1");
        }
        if fields.finality_certified_chain_length != 3 {
            return invalid("v0 finality requires a direct three-certified-block chain");
        }
        if fields.timeout_multiplier_denominator == 0 {
            return invalid("timeout multiplier denominator must be positive");
        }
        if fields.timeout_multiplier_numerator <= fields.timeout_multiplier_denominator {
            return invalid("timeout multiplier must grow");
        }
        if fields.base_timeout_ms > fields.timeout_max_ms {
            return invalid("base timeout exceeds timeout maximum");
        }
        if fields.epoch_seal_blocks != 2 {
            return invalid("v0 requires exactly two epoch seal blocks");
        }
        if fields.snapshot_lead_blocks < u64::from(fields.finality_certified_chain_length) {
            return invalid("snapshot lead must cover the finality-certified chain");
        }
        let snapshot_and_seals = fields
            .snapshot_lead_blocks
            .checked_add(u64::from(fields.epoch_seal_blocks))
            .ok_or(ValidationError::ArithmeticOverflow(
                "snapshot lead plus epoch seals",
            ))?;
        if fields.epoch_length_blocks <= snapshot_and_seals {
            return invalid("epoch is too short for snapshot/checkpoint/seal layout");
        }
        if !fields.joint_handoff_old_quorum || !fields.joint_handoff_new_quorum {
            return invalid("v0 handoff requires both old and new quorums");
        }
        if fields.upgrade_notice_epochs < 1 {
            return invalid("upgrade notice must span at least one epoch");
        }
        if fields.max_protocol_version_jump != 1 {
            return invalid("v0 permits only a one-version jump");
        }
        if fields.scale_ppm == 0 {
            return invalid("scale_ppm must be positive");
        }
        let caps = [
            fields.per_certificate_unit_cap,
            fields.per_consumer_provider_epoch_unit_cap,
            fields.per_task_provider_epoch_unit_cap,
            fields.per_provider_epoch_unit_cap,
        ];
        if caps[0] == 0 || caps.windows(2).any(|pair| pair[0] > pair[1]) {
            return invalid("hierarchical unit caps must be positive and nondecreasing");
        }
        if fields.units_per_power == 0 || fields.bond_atomic_units_per_power == 0 {
            return invalid("capacity divisors must be positive");
        }
        if fields.min_validator_power == 0
            || fields.min_validator_power > fields.max_validator_power
        {
            return invalid("validator power bounds are inconsistent");
        }
        if fields.max_validator_share_ppm == 0
            || u128::from(fields.max_validator_share_ppm) * 3 >= u128::from(fields.scale_ppm)
        {
            return invalid("validator share cap must be positive and below one third");
        }
        if fields.capped_weight_alpha_ppm > fields.scale_ppm {
            return invalid("capped alpha is outside the ppm scale");
        }
        if fields.full_weight_alpha_ppm != fields.scale_ppm {
            return invalid("full rollout alpha must equal scale_ppm");
        }
        let minimum_candidate_power = u128::from(fields.min_validators)
            .checked_mul(u128::from(fields.min_validator_power))
            .ok_or(ValidationError::ArithmeticOverflow(
                "minimum candidate voting power",
            ))?;
        if minimum_candidate_power > u128::from(fields.max_total_voting_power) {
            return invalid("no minimum-size candidate can fit max_total_voting_power");
        }
        if fields.automatic_promotion {
            return invalid("phase promotion must never be automatic");
        }
        if !(fields.trusting_period_epochs < fields.evidence_window_epochs
            && fields.evidence_window_epochs <= fields.unbonding_delay_epochs)
        {
            return invalid(
                "required relationship is trusting_period < evidence_window <= unbonding_delay",
            );
        }
        if !fields.require_trusting_period_less_than_evidence {
            return invalid("trusting/evidence relationship must be enforced");
        }
        if !fields.require_evidence_window_le_unbonding_delay {
            return invalid("evidence/unbonding relationship must be enforced");
        }

        Ok(())
    }

    /// Applies only the policy gates that distinguish the P0 reference profile
    /// from a future epoch-governed v0 activation.
    pub fn validate_reference_shadow_profile(&self) -> Result<()> {
        if self.production_activation() {
            return invalid("the P0 reference profile must remain non-production");
        }
        if self.rollout_phase() != RolloutPhase::Shadow {
            return invalid("the P0 reference profile must remain in shadow");
        }
        Ok(())
    }

    /// Returns the exact 341-byte CEV0 value in the field order frozen by
    /// protocol section 03§11.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        try_canonical_bytes(|encoder| self.encode(encoder))
            .expect("fixed-width ConsensusParametersV0 encoding cannot overflow")
    }

    pub fn hash(&self) -> ConsensusParametersHash {
        ConsensusParametersHash::new(canonical_hash(DOMAIN_PARAMETERS, |encoder| {
            self.encode(encoder);
        }))
    }

    fn encode(&self, encoder: &mut Encoder) {
        let fields = &self.fields;
        encoder.u16(fields.schema_version);
        encoder.u32(fields.protocol_version);
        encoder.bool(fields.production_activation);
        encoder.u16(fields.max_chain_id_bytes);
        encoder.u16(fields.max_validator_id_bytes);
        encoder.u32(fields.max_block_bytes);
        encoder.u32(fields.max_consensus_message_bytes);
        encoder.u32(fields.min_validators);
        encoder.u32(fields.max_validators);
        encoder.u32(fields.quorum_numerator);
        encoder.u32(fields.quorum_denominator);
        encoder.u32(fields.quorum_addend);
        encoder.u8(fields.finality_certified_chain_length);
        encoder.u64(fields.max_total_voting_power);
        encoder.u64(fields.max_block_time_step_ms);
        encoder.u8(fields.leader_schedule.into());
        encoder.bool(fields.require_full_payload_before_vote);
        encoder.u64(fields.base_timeout_ms);
        encoder.u32(fields.timeout_multiplier_numerator);
        encoder.u32(fields.timeout_multiplier_denominator);
        encoder.u64(fields.timeout_max_ms);
        encoder.u64(fields.epoch_length_blocks);
        encoder.u8(fields.epoch_seal_blocks);
        encoder.u64(fields.snapshot_lead_blocks);
        encoder.bool(fields.joint_handoff_old_quorum);
        encoder.bool(fields.joint_handoff_new_quorum);
        encoder.u64(fields.upgrade_notice_epochs);
        encoder.u32(fields.max_protocol_version_jump);
        encoder.u64(fields.scale_ppm);
        encoder.u64(fields.maturity_epochs);
        encoder.u64(fields.max_certificate_age_epochs);
        encoder.u64(fields.decay_step_ppm_per_epoch);
        encoder.u128(fields.per_certificate_unit_cap);
        encoder.u128(fields.per_consumer_provider_epoch_unit_cap);
        encoder.u128(fields.per_task_provider_epoch_unit_cap);
        encoder.u128(fields.per_provider_epoch_unit_cap);
        encoder.u128(fields.units_per_power);
        encoder.u128(fields.bond_atomic_units_per_power);
        encoder.u64(fields.min_validator_power);
        encoder.u64(fields.max_validator_power);
        encoder.u64(fields.max_validator_share_ppm);
        encoder.u64(fields.capped_weight_alpha_ppm);
        encoder.u64(fields.full_weight_alpha_ppm);
        encoder.u8(fields.rollout_phase.into());
        encoder.u64(fields.minimum_shadow_epochs);
        encoder.u64(fields.minimum_eligibility_only_epochs);
        encoder.u64(fields.minimum_capped_weight_epochs);
        encoder.bool(fields.automatic_promotion);
        encoder.u64(fields.evidence_window_epochs);
        encoder.u64(fields.unbonding_delay_epochs);
        encoder.u64(fields.jail_duration_epochs);
        encoder.u64(fields.trusting_period_epochs);
        encoder.bool(fields.require_trusting_period_less_than_evidence);
        encoder.bool(fields.require_evidence_window_le_unbonding_delay);
    }
}

fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(ValidationError::InvalidConsensusParameters(reason))
}
