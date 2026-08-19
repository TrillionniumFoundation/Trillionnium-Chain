//! Frozen-v0 native validator lifecycle without any ABCI transport surface.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_finality_types::{crypto::verify_hex, decode_hash32, hash_domain};

pub const VALIDATOR_GOVERNANCE_SCHEMA_V1: &str = "trnm_validator_governance_v1";
pub const VALIDATOR_TRANSITION_SCHEMA_V1: &str = "trnm_validator_set_transition_v1";
pub const VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1: &str = VALIDATOR_TRANSITION_SCHEMA_V1;
pub const VALIDATOR_LIFECYCLE_SCHEMA_V1: &str = "trnm_validator_lifecycle_v1";

// Mirrors CometBFT v0.38's types.MaxTotalVotingPower.
const MAX_TOTAL_VOTING_POWER: u64 = (i64::MAX as u64) / 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorGovernanceV1 {
    pub schema: String,
    pub signer_id: String,
    pub min_activation_delay_blocks: u64,
    pub unsafe_allow_single_validator_genesis: bool,
}

impl ValidatorGovernanceV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == VALIDATOR_GOVERNANCE_SCHEMA_V1,
            "unsupported validator governance schema"
        );
        ensure!(
            !self.signer_id.is_empty()
                && self.signer_id == self.signer_id.trim()
                && self.signer_id.len() <= 256,
            "validator governance signer_id is not canonical"
        );
        ensure!(
            self.min_activation_delay_blocks >= 2,
            "validator activation delay must be at least two blocks"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusValidatorV1 {
    pub public_key_hex: String,
    pub voting_power: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSetTransitionV1 {
    pub schema: String,
    pub chain_id: String,
    pub transition_id: String,
    pub base_validator_set_hash_hex: String,
    pub activation_height: u64,
    pub target_validators: Vec<ConsensusValidatorV1>,
    pub new_validator_proofs: Vec<ValidatorKeyProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorKeyProofV1 {
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledValidatorTransitionV1 {
    pub transition_id: String,
    pub base_validator_set_hash_hex: String,
    pub accepted_height: u64,
    pub activation_height: u64,
    pub target_validators: Vec<ConsensusValidatorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorLifecycleStateV1 {
    pub schema: String,
    pub chain_id: String,
    pub app_version: u64,
    pub authorized_signers_hash_hex: String,
    pub governance: ValidatorGovernanceV1,
    #[serde(default)]
    pub governance_sequence: u64,
    pub active_validators: Vec<ConsensusValidatorV1>,
    pub pending_transition: Option<ScheduledValidatorTransitionV1>,
    pub last_applied_transition_id: Option<String>,
}

pub(crate) struct ValidatorTransitionAuthorization<'a> {
    pub command_id: &'a str,
    pub signer_id: &'a str,
    pub signer_role: &'a str,
    pub nonce: u64,
    pub chain_id: &'a str,
    pub accepted_height: u64,
}

/// A protocol-invalid validator transition. Every variant is derived only
/// from the signed transition and its authorization joined to an already
/// authenticated lifecycle; no diagnostic text participates in the
/// classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidatorTransitionDeterministicInvalidV1 {
    Schema,
    TransitionChainId,
    TransitionId,
    GovernanceAuthorization,
    GovernanceSequenceMismatch,
    PendingTransitionExists,
    BaseValidatorSetHash,
    ActivationHeight,
    TargetValidatorSet,
    ValidatorSetOverlap,
    NewValidatorProof,
    NoActiveSetChange,
}

/// A fail-stop condition while scheduling against authenticated lifecycle
/// state. These variants deliberately carry no source error or free-form
/// string, keeping the protocol disposition closed and data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidatorTransitionInvariantV1 {
    AuthenticatedLifecycle,
    LifecycleContextBinding,
    GovernanceSequenceExhausted,
    ActivationDelayOverflow,
    ActiveSetHash,
    ScheduledLifecyclePostcondition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidatorTransitionScheduleFailureV1 {
    DeterministicallyInvalid(ValidatorTransitionDeterministicInvalidV1),
    Invariant(ValidatorTransitionInvariantV1),
}

impl std::fmt::Display for ValidatorTransitionScheduleFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeterministicallyInvalid(reason) => {
                write!(
                    formatter,
                    "deterministically invalid validator transition: {reason:?}"
                )
            }
            Self::Invariant(reason) => {
                write!(
                    formatter,
                    "validator transition scheduling invariant: {reason:?}"
                )
            }
        }
    }
}

impl std::error::Error for ValidatorTransitionScheduleFailureV1 {}

impl ValidatorLifecycleStateV1 {
    pub fn from_genesis(
        chain_id: String,
        app_version: u64,
        authorized_signers_hash_hex: String,
        governance: ValidatorGovernanceV1,
        validators: Vec<ConsensusValidatorV1>,
    ) -> Result<Self> {
        governance.validate()?;
        let active_validators = canonicalize_validators(validators)?;
        validate_active_set_for_governance(&governance, &active_validators)?;
        Ok(Self {
            schema: VALIDATOR_LIFECYCLE_SCHEMA_V1.to_string(),
            chain_id,
            app_version,
            authorized_signers_hash_hex,
            governance,
            governance_sequence: 0,
            active_validators,
            pending_transition: None,
            last_applied_transition_id: None,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == VALIDATOR_LIFECYCLE_SCHEMA_V1,
            "unsupported validator lifecycle schema"
        );
        ensure!(
            !self.chain_id.is_empty()
                && self.chain_id == self.chain_id.trim()
                && self.chain_id.len() <= 128,
            "validator lifecycle chain_id is not canonical"
        );
        ensure!(
            self.app_version > 0,
            "validator lifecycle app version must be positive"
        );
        let _ = decode_hash32(
            "validator lifecycle authorized signer policy",
            &self.authorized_signers_hash_hex,
        )?;
        self.governance.validate()?;
        ensure!(
            canonicalize_validators(self.active_validators.clone())? == self.active_validators,
            "active validator set is not canonical"
        );
        validate_active_set_for_governance(&self.governance, &self.active_validators)?;
        if let Some(pending) = &self.pending_transition {
            ensure!(
                !pending.transition_id.is_empty(),
                "pending validator transition_id must not be empty"
            );
            let _ = decode_hash32(
                "pending base validator set hash",
                &pending.base_validator_set_hash_hex,
            )?;
            let minimum_activation_height = pending
                .accepted_height
                .checked_add(self.governance.min_activation_delay_blocks)
                .context("pending validator activation delay overflow")?;
            ensure!(
                pending.accepted_height > 0
                    && pending.activation_height >= minimum_activation_height,
                "pending validator activation height violates governance delay"
            );
            ensure!(
                canonicalize_validators(pending.target_validators.clone())?
                    == pending.target_validators,
                "pending target validator set is not canonical"
            );
            validate_transition_target(&pending.target_validators)?;
            ensure!(
                pending.base_validator_set_hash_hex == self.active_set_hash_hex()?,
                "pending transition base validator set hash is stale"
            );
            validate_overlap(&self.active_validators, &pending.target_validators)?;
        }
        Ok(())
    }

    pub fn active_set_hash_hex(&self) -> Result<String> {
        validator_set_hash_hex(&self.active_validators)
    }

    #[cfg(any())]
    pub fn commitment(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(hash_domain(
            "trnm.cometbft.validator-lifecycle.v1",
            &[&serde_json::to_vec(self)?],
        ))
    }

    pub fn prepare_height(&mut self, height: u64) -> Result<()> {
        ensure!(height > 0, "block height must be positive");
        if let Some(pending) = &self.pending_transition {
            ensure!(
                pending.activation_height >= height,
                "validator transition activation height was skipped"
            );
        }
        if self
            .pending_transition
            .as_ref()
            .is_some_and(|pending| pending.activation_height == height)
        {
            let pending = self
                .pending_transition
                .take()
                .expect("pending transition checked");
            self.active_validators = pending.target_validators;
            self.last_applied_transition_id = Some(pending.transition_id);
        }
        self.validate()
    }

    pub(crate) fn schedule(
        &mut self,
        transition: ValidatorSetTransitionV1,
        authorization: ValidatorTransitionAuthorization<'_>,
    ) -> std::result::Result<(), ValidatorTransitionScheduleFailureV1> {
        use ValidatorTransitionDeterministicInvalidV1 as Invalid;
        use ValidatorTransitionInvariantV1 as Invariant;
        use ValidatorTransitionScheduleFailureV1::{
            DeterministicallyInvalid, Invariant as FailStop,
        };

        self.validate()
            .map_err(|_| FailStop(Invariant::AuthenticatedLifecycle))?;
        if transition.schema != VALIDATOR_TRANSITION_SCHEMA_V1 {
            return Err(DeterministicallyInvalid(Invalid::Schema));
        }
        if transition.chain_id != authorization.chain_id {
            return Err(DeterministicallyInvalid(Invalid::TransitionChainId));
        }
        if self.chain_id != authorization.chain_id {
            return Err(FailStop(Invariant::LifecycleContextBinding));
        }
        if transition.transition_id != authorization.command_id {
            return Err(DeterministicallyInvalid(Invalid::TransitionId));
        }
        if authorization.signer_role != "operator"
            || authorization.signer_id != self.governance.signer_id
        {
            return Err(DeterministicallyInvalid(Invalid::GovernanceAuthorization));
        }
        let expected_nonce = self
            .governance_sequence
            .checked_add(1)
            .ok_or(FailStop(Invariant::GovernanceSequenceExhausted))?;
        if authorization.nonce != expected_nonce {
            return Err(DeterministicallyInvalid(
                Invalid::GovernanceSequenceMismatch,
            ));
        }
        if self.pending_transition.is_some() {
            return Err(DeterministicallyInvalid(Invalid::PendingTransitionExists));
        }
        let active_set_hash_hex = self
            .active_set_hash_hex()
            .map_err(|_| FailStop(Invariant::ActiveSetHash))?;
        if transition.base_validator_set_hash_hex != active_set_hash_hex {
            return Err(DeterministicallyInvalid(Invalid::BaseValidatorSetHash));
        }
        let minimum_activation_height = authorization
            .accepted_height
            .checked_add(self.governance.min_activation_delay_blocks)
            .ok_or(FailStop(Invariant::ActivationDelayOverflow))?;
        if transition.activation_height < minimum_activation_height {
            return Err(DeterministicallyInvalid(Invalid::ActivationHeight));
        }
        let target_validators = canonicalize_validators(transition.target_validators.clone())
            .map_err(|_| DeterministicallyInvalid(Invalid::TargetValidatorSet))?;
        validate_transition_target(&target_validators)
            .map_err(|_| DeterministicallyInvalid(Invalid::TargetValidatorSet))?;
        validate_overlap(&self.active_validators, &target_validators)
            .map_err(|_| DeterministicallyInvalid(Invalid::ValidatorSetOverlap))?;
        validate_new_validator_proofs(&transition, &self.active_validators, &target_validators)
            .map_err(|_| DeterministicallyInvalid(Invalid::NewValidatorProof))?;
        if target_validators == self.active_validators {
            return Err(DeterministicallyInvalid(Invalid::NoActiveSetChange));
        }

        // Build and validate a complete candidate first. The authenticated
        // lifecycle is swapped only after every fallible check has passed, so
        // every `Err` leaves `self` byte-for-byte unchanged.
        let mut candidate = self.clone();
        candidate.pending_transition = Some(ScheduledValidatorTransitionV1 {
            transition_id: transition.transition_id,
            base_validator_set_hash_hex: transition.base_validator_set_hash_hex,
            accepted_height: authorization.accepted_height,
            activation_height: transition.activation_height,
            target_validators,
        });
        candidate.governance_sequence = authorization.nonce;
        candidate
            .validate()
            .map_err(|_| FailStop(Invariant::ScheduledLifecyclePostcondition))?;
        *self = candidate;
        Ok(())
    }
}
pub fn validator_set_hash_hex(validators: &[ConsensusValidatorV1]) -> Result<String> {
    let validators = canonicalize_validators(validators.to_vec())?;
    Ok(hex::encode(hash_domain(
        "trnm.cometbft.validator-set.v1",
        &[&serde_json::to_vec(&validators)?],
    )))
}

pub fn validator_key_proof_message(
    chain_id: &str,
    transition_id: &str,
    base_validator_set_hash_hex: &str,
    activation_height: u64,
    target_validators: &[ConsensusValidatorV1],
) -> Result<[u8; 32]> {
    let base_hash = decode_hash32("base validator set hash", base_validator_set_hash_hex)?;
    let target_hash = decode_hash32(
        "target validator set hash",
        &validator_set_hash_hex(target_validators)?,
    )?;
    Ok(hash_domain(
        "trnm.validator-key-possession.v1",
        &[
            chain_id.as_bytes(),
            transition_id.as_bytes(),
            &base_hash,
            &activation_height.to_be_bytes(),
            &target_hash,
        ],
    ))
}

fn validate_new_validator_proofs(
    transition: &ValidatorSetTransitionV1,
    current: &[ConsensusValidatorV1],
    target: &[ConsensusValidatorV1],
) -> Result<()> {
    let current_keys = current
        .iter()
        .map(|validator| validator.public_key_hex.as_str())
        .collect::<BTreeSet<_>>();
    let target_keys = target
        .iter()
        .map(|validator| validator.public_key_hex.as_str())
        .collect::<BTreeSet<_>>();
    let required = target_keys
        .difference(&current_keys)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut provided = BTreeMap::new();
    for proof in &transition.new_validator_proofs {
        let _ = decode_hash32("validator proof public key", &proof.public_key_hex)?;
        ensure!(
            target_keys.contains(proof.public_key_hex.as_str())
                && !current_keys.contains(proof.public_key_hex.as_str()),
            "validator key proof is not for a newly added target key"
        );
        ensure!(
            provided
                .insert(proof.public_key_hex.as_str(), proof)
                .is_none(),
            "duplicate validator key proof"
        );
    }
    ensure!(
        provided.keys().copied().collect::<BTreeSet<_>>() == required,
        "missing validator key possession proof"
    );
    let message = validator_key_proof_message(
        &transition.chain_id,
        &transition.transition_id,
        &transition.base_validator_set_hash_hex,
        transition.activation_height,
        target,
    )?;
    for proof in provided.values() {
        verify_hex(&proof.public_key_hex, &message, &proof.signature_hex)
            .context("verify new validator key possession proof")?;
    }
    Ok(())
}

fn canonicalize_validators(
    mut validators: Vec<ConsensusValidatorV1>,
) -> Result<Vec<ConsensusValidatorV1>> {
    validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut total = 0u64;
    for validator in &validators {
        let key = decode_hash32("validator public key", &validator.public_key_hex)?;
        ensure!(
            validator.public_key_hex == hex::encode(key),
            "validator public key must use canonical lowercase hex"
        );
        ensure!(
            keys.insert(validator.public_key_hex.clone()),
            "duplicate validator public key"
        );
        ensure!(
            addresses.insert(comet_address(&key)),
            "duplicate CometBFT validator address"
        );
        ensure!(
            validator.voting_power > 0,
            "validator voting power must be positive"
        );
        ensure!(
            validator.voting_power <= MAX_TOTAL_VOTING_POWER,
            "validator voting power exceeds CometBFT maximum"
        );
        total = total
            .checked_add(validator.voting_power)
            .context("validator total voting power overflow")?;
        ensure!(
            total <= MAX_TOTAL_VOTING_POWER,
            "validator total voting power exceeds CometBFT maximum"
        );
    }
    Ok(validators)
}

fn validate_nonempty_set(validators: &[ConsensusValidatorV1]) -> Result<()> {
    ensure!(!validators.is_empty(), "validator set must not be empty");
    Ok(())
}

fn validate_active_set_for_governance(
    governance: &ValidatorGovernanceV1,
    validators: &[ConsensusValidatorV1],
) -> Result<()> {
    if governance.unsafe_allow_single_validator_genesis {
        ensure!(
            validators.len() == 1,
            "unsafe genesis mode is restricted to an explicit single-validator devnet"
        );
        return validate_nonempty_set(validators);
    }
    validate_transition_target(validators)
}

fn validate_transition_target(validators: &[ConsensusValidatorV1]) -> Result<()> {
    ensure!(
        validators.len() >= 4,
        "validator transition target must contain at least four validators"
    );
    let total = validators
        .iter()
        .map(|validator| validator.voting_power as u128)
        .sum::<u128>();
    let max = validators
        .iter()
        .map(|validator| validator.voting_power as u128)
        .max()
        .unwrap_or(0);
    ensure!(
        max.saturating_mul(3) < total,
        "validator transition gives one validator quorum-blocking power"
    );
    Ok(())
}

fn validate_overlap(
    current: &[ConsensusValidatorV1],
    target: &[ConsensusValidatorV1],
) -> Result<()> {
    let current_by_key = current
        .iter()
        .map(|validator| (&validator.public_key_hex, validator.voting_power as u128))
        .collect::<BTreeMap<_, _>>();
    let target_by_key = target
        .iter()
        .map(|validator| (&validator.public_key_hex, validator.voting_power as u128))
        .collect::<BTreeMap<_, _>>();
    let current_total = current_by_key.values().copied().sum::<u128>();
    let target_total = target_by_key.values().copied().sum::<u128>();
    let retained_current = current_by_key
        .iter()
        .filter(|(key, _)| target_by_key.contains_key(*key))
        .map(|(_, power)| *power)
        .sum::<u128>();
    let retained_target = target_by_key
        .iter()
        .filter(|(key, _)| current_by_key.contains_key(*key))
        .map(|(_, power)| *power)
        .sum::<u128>();
    ensure!(
        retained_current.saturating_mul(3) > current_total.saturating_mul(2),
        "validator transition retains at most two-thirds of current voting power"
    );
    ensure!(
        retained_target.saturating_mul(3) > target_total.saturating_mul(2),
        "validator transition gives at least one-third of target power to new keys"
    );
    Ok(())
}

fn comet_address(public_key: &[u8; 32]) -> [u8; 20] {
    let digest = Sha256::digest(public_key);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[..20]);
    address
}
