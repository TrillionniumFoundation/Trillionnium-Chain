use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

use crate::{
    canonical::{canonical_hash, DOMAIN_VALIDATOR_SET},
    ChainId, CommonConsensusContextV0, ConsensusParametersHash, ConsensusPublicKey, Epoch,
    GenesisHash, MessageKind, ProtocolVersion, Result, ValidationError, ValidatorId,
    ValidatorSetId, View, VotingPower, SCHEMA_VERSION_V0,
};

pub const MAX_VALIDATORS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    id: ValidatorId,
    consensus_key: ConsensusPublicKey,
    voting_power: VotingPower,
}

impl Validator {
    pub fn new(
        id: ValidatorId,
        consensus_key: ConsensusPublicKey,
        voting_power: VotingPower,
    ) -> Result<Self> {
        let value = Self {
            id,
            consensus_key,
            voting_power,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn id(&self) -> ValidatorId {
        self.id
    }

    pub const fn consensus_key(&self) -> ConsensusPublicKey {
        self.consensus_key
    }

    pub const fn voting_power(&self) -> VotingPower {
        self.voting_power
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.consensus_key.is_zero() {
            return Err(ValidationError::ZeroConsensusPublicKey);
        }
        if self.voting_power.get() == 0 {
            return Err(ValidationError::ZeroVotingPower);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    consensus_parameters_hash: ConsensusParametersHash,
    id: ValidatorSetId,
    validators: Vec<Validator>,
    total_power: u128,
    quorum_power: u128,
}

impl ValidatorSet {
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        consensus_parameters_hash: ConsensusParametersHash,
        validators: Vec<Validator>,
    ) -> Result<Self> {
        let (total_power, quorum_power) = validate_validators(&validators)?;
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        let id = validator_set_id(
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            consensus_parameters_hash,
            &validators,
        );
        let value = Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            consensus_parameters_hash,
            id,
            validators,
            total_power,
            quorum_power,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.consensus_parameters_hash
    }

    pub const fn id(&self) -> ValidatorSetId {
        self.id
    }

    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    pub const fn total_power(&self) -> u128 {
        self.total_power
    }

    pub const fn quorum_power(&self) -> u128 {
        self.quorum_power
    }

    pub fn validator(&self, id: ValidatorId) -> Option<&Validator> {
        self.validators
            .binary_search_by_key(&id, Validator::id)
            .ok()
            .map(|index| &self.validators[index])
    }

    pub fn power_of(&self, id: ValidatorId) -> Option<u128> {
        self.validator(id)
            .map(|validator| validator.voting_power.get() as u128)
    }

    pub fn consensus_context(
        &self,
        view: View,
        message_kind: MessageKind,
    ) -> Result<CommonConsensusContextV0> {
        CommonConsensusContextV0::new(
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.id,
            view,
            message_kind,
        )
    }

    pub fn validate_shape(&self) -> Result<()> {
        let (total_power, quorum_power) = validate_validators(&self.validators)?;
        if total_power != self.total_power || quorum_power != self.quorum_power {
            return Err(ValidationError::ValidatorSetIdMismatch);
        }
        if validator_set_id(
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.consensus_parameters_hash,
            &self.validators,
        ) != self.id
        {
            return Err(ValidationError::ValidatorSetIdMismatch);
        }
        Ok(())
    }
}

fn validate_validators(validators: &[Validator]) -> Result<(u128, u128)> {
    if validators.is_empty() {
        return Err(ValidationError::EmptyValidatorSet);
    }
    if validators.len() > MAX_VALIDATORS {
        return Err(ValidationError::TooManyValidators {
            actual: validators.len(),
            maximum: MAX_VALIDATORS,
        });
    }
    let mut previous = None;
    let mut keys = BTreeSet::new();
    let mut total_power = 0u128;
    for validator in validators {
        validator.validate_shape()?;
        if let Some(previous) = previous {
            if previous == validator.id {
                return Err(ValidationError::DuplicateValidatorId(Box::new(
                    validator.id,
                )));
            }
            if previous > validator.id {
                return Err(ValidationError::NonCanonicalValidatorOrder);
            }
        }
        previous = Some(validator.id);
        if !keys.insert(validator.consensus_key) {
            return Err(ValidationError::DuplicateConsensusPublicKey);
        }
        total_power = total_power
            .checked_add(validator.voting_power.get() as u128)
            .ok_or(ValidationError::ArithmeticOverflow("validator total power"))?;
    }
    let doubled = total_power
        .checked_mul(2)
        .ok_or(ValidationError::ArithmeticOverflow(
            "validator quorum power",
        ))?;
    let quorum_power = doubled / 3 + 1;
    Ok((total_power, quorum_power))
}

fn validator_set_id(
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    consensus_parameters_hash: ConsensusParametersHash,
    validators: &[Validator],
) -> ValidatorSetId {
    ValidatorSetId::new(canonical_hash(DOMAIN_VALIDATOR_SET, |encoder| {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(genesis_hash.as_bytes());
        encoder.consensus_string(chain_id.as_bytes());
        encoder.u32(protocol_version.get());
        encoder.u64(epoch.get());
        encoder.fixed(consensus_parameters_hash.as_bytes());
        encoder.list_len(validators.len());
        for validator in validators {
            encoder.bytes(validator.id.as_bytes());
            encoder.fixed(validator.consensus_key.as_bytes());
            encoder.u64(validator.voting_power.get());
        }
    }))
}
