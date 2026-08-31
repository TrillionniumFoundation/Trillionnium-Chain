use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint_proto::v0_38::{
    abci::ValidatorUpdate,
    crypto::{public_key, PublicKey},
};
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

    #[cfg(test)]
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

    pub fn updates_due_at_finalize_height(&self, height: u64) -> Result<Vec<ValidatorUpdate>> {
        self.validate()?;
        let Some(pending) = &self.pending_transition else {
            return Ok(Vec::new());
        };
        if pending.activation_height != height.saturating_add(2) {
            return Ok(Vec::new());
        }
        validator_updates(&self.active_validators, &pending.target_validators)
    }
}

pub fn validators_from_abci(updates: &[ValidatorUpdate]) -> Result<Vec<ConsensusValidatorV1>> {
    let mut validators = Vec::with_capacity(updates.len());
    for update in updates {
        ensure!(update.power > 0, "genesis validator power must be positive");
        let key = ed25519_key_bytes(update)?;
        validators.push(ConsensusValidatorV1 {
            public_key_hex: hex::encode(key),
            voting_power: u64::try_from(update.power).context("convert genesis voting power")?,
        });
    }
    let validators = canonicalize_validators(validators)?;
    validate_nonempty_set(&validators)?;
    Ok(validators)
}

pub fn validators_to_abci(validators: &[ConsensusValidatorV1]) -> Result<Vec<ValidatorUpdate>> {
    let validators = canonicalize_validators(validators.to_vec())?;
    validate_nonempty_set(&validators)?;
    validators
        .iter()
        .map(|validator| validator_update(validator, validator.voting_power))
        .collect()
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

fn validator_updates(
    current: &[ConsensusValidatorV1],
    target: &[ConsensusValidatorV1],
) -> Result<Vec<ValidatorUpdate>> {
    let current = current
        .iter()
        .map(|validator| (validator.public_key_hex.clone(), validator.voting_power))
        .collect::<BTreeMap<_, _>>();
    let target = target
        .iter()
        .map(|validator| (validator.public_key_hex.clone(), validator.voting_power))
        .collect::<BTreeMap<_, _>>();
    let mut updates = Vec::new();
    for (key, old_power) in &current {
        match target.get(key) {
            None => updates.push(validator_update(
                &ConsensusValidatorV1 {
                    public_key_hex: key.clone(),
                    voting_power: *old_power,
                },
                0,
            )?),
            Some(new_power) if new_power != old_power => {
                updates.push(validator_update(
                    &ConsensusValidatorV1 {
                        public_key_hex: key.clone(),
                        voting_power: *new_power,
                    },
                    *new_power,
                )?);
            }
            Some(_) => {}
        }
    }
    for (key, power) in &target {
        if !current.contains_key(key) {
            updates.push(validator_update(
                &ConsensusValidatorV1 {
                    public_key_hex: key.clone(),
                    voting_power: *power,
                },
                *power,
            )?);
        }
    }
    updates.sort_by_key(|update| {
        ed25519_key_bytes(update)
            .map(|key| comet_address(&key))
            .unwrap_or_default()
    });
    Ok(updates)
}

fn validator_update(validator: &ConsensusValidatorV1, power: u64) -> Result<ValidatorUpdate> {
    let key = decode_hash32("validator public key", &validator.public_key_hex)?;
    Ok(ValidatorUpdate {
        pub_key: Some(PublicKey {
            sum: Some(public_key::Sum::Ed25519(key.to_vec())),
        }),
        power: i64::try_from(power).context("convert validator voting power")?,
    })
}

fn ed25519_key_bytes(update: &ValidatorUpdate) -> Result<[u8; 32]> {
    let public_key = update
        .pub_key
        .as_ref()
        .context("validator update is missing public key")?;
    let public_key = match public_key.sum.as_ref() {
        Some(public_key::Sum::Ed25519(bytes)) => bytes,
        _ => anyhow::bail!("validator key type must be Ed25519"),
    };
    ensure!(
        public_key.len() == 32,
        "Ed25519 validator public key must be 32 bytes"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(public_key);
    Ok(key)
}

fn comet_address(public_key: &[u8; 32]) -> [u8; 20] {
    let digest = Sha256::digest(public_key);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[..20]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use trnm_finality_types::crypto::{public_key_hex, sign_hex};

    const CHAIN_ID: &str = "trnm-validator-lifecycle-typed-test";
    const GOVERNANCE_SIGNER: &str = "did:operator:validator-lifecycle-test";

    fn validator(seed: u8) -> ConsensusValidatorV1 {
        ConsensusValidatorV1 {
            public_key_hex: public_key_hex(&SigningKey::from_bytes(&[seed; 32])),
            voting_power: 10,
        }
    }

    fn lifecycle() -> ValidatorLifecycleStateV1 {
        ValidatorLifecycleStateV1::from_genesis(
            CHAIN_ID.to_string(),
            1,
            "11".repeat(32),
            ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: GOVERNANCE_SIGNER.to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            vec![validator(1), validator(2), validator(3), validator(4)],
        )
        .expect("construct valid lifecycle fixture")
    }

    fn transition_for_target(
        lifecycle: &ValidatorLifecycleStateV1,
        transition_id: &str,
        activation_height: u64,
        mut target_validators: Vec<ConsensusValidatorV1>,
        proof_seeds: &[u8],
    ) -> ValidatorSetTransitionV1 {
        target_validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        let base_validator_set_hash_hex = lifecycle
            .active_set_hash_hex()
            .expect("hash valid lifecycle fixture");
        let message = validator_key_proof_message(
            CHAIN_ID,
            transition_id,
            &base_validator_set_hash_hex,
            activation_height,
            &target_validators,
        )
        .expect("derive validator key proof message");
        ValidatorSetTransitionV1 {
            schema: VALIDATOR_TRANSITION_SCHEMA_V1.to_string(),
            chain_id: CHAIN_ID.to_string(),
            transition_id: transition_id.to_string(),
            base_validator_set_hash_hex,
            activation_height,
            target_validators,
            new_validator_proofs: proof_seeds
                .iter()
                .map(|seed| {
                    let key = SigningKey::from_bytes(&[*seed; 32]);
                    ValidatorKeyProofV1 {
                        public_key_hex: public_key_hex(&key),
                        signature_hex: sign_hex(&key, &message),
                    }
                })
                .collect(),
        }
    }

    fn valid_transition(
        lifecycle: &ValidatorLifecycleStateV1,
        transition_id: &str,
    ) -> ValidatorSetTransitionV1 {
        let mut target = lifecycle.active_validators.clone();
        target.remove(0);
        target.push(validator(9));
        transition_for_target(lifecycle, transition_id, 3, target, &[9])
    }

    fn authorization<'a>(
        command_id: &'a str,
        signer_id: &'a str,
        signer_role: &'a str,
        nonce: u64,
        chain_id: &'a str,
        accepted_height: u64,
    ) -> ValidatorTransitionAuthorization<'a> {
        ValidatorTransitionAuthorization {
            command_id,
            signer_id,
            signer_role,
            nonce,
            chain_id,
            accepted_height,
        }
    }

    fn valid_authorization(command_id: &str) -> ValidatorTransitionAuthorization<'_> {
        authorization(command_id, GOVERNANCE_SIGNER, "operator", 1, CHAIN_ID, 1)
    }

    fn assert_failure_without_mutation(
        lifecycle: &mut ValidatorLifecycleStateV1,
        transition: ValidatorSetTransitionV1,
        authorization: ValidatorTransitionAuthorization<'_>,
        expected: ValidatorTransitionScheduleFailureV1,
    ) {
        let before = lifecycle.clone();
        assert_eq!(lifecycle.schedule(transition, authorization), Err(expected));
        assert_eq!(*lifecycle, before, "schedule failure mutated lifecycle");
    }

    fn invalid(
        reason: ValidatorTransitionDeterministicInvalidV1,
    ) -> ValidatorTransitionScheduleFailureV1 {
        ValidatorTransitionScheduleFailureV1::DeterministicallyInvalid(reason)
    }

    fn invariant(reason: ValidatorTransitionInvariantV1) -> ValidatorTransitionScheduleFailureV1 {
        ValidatorTransitionScheduleFailureV1::Invariant(reason)
    }

    #[test]
    fn schedule_classifies_intrinsic_and_governance_rejections_without_mutation() {
        let command_id = "typed-validator-intrinsic";

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.schema = "trnm_validator_set_transition_v2".to_string();
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::Schema),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.chain_id = "trnm-other-chain".to_string();
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::TransitionChainId),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.transition_id = "different-command".to_string();
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::TransitionId),
        );

        let mut state = lifecycle();
        let transition = valid_transition(&state, command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(command_id, "did:operator:wrong", "operator", 1, CHAIN_ID, 1),
            invalid(ValidatorTransitionDeterministicInvalidV1::GovernanceAuthorization),
        );

        let mut state = lifecycle();
        let transition = valid_transition(&state, command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(command_id, GOVERNANCE_SIGNER, "client", 1, CHAIN_ID, 1),
            invalid(ValidatorTransitionDeterministicInvalidV1::GovernanceAuthorization),
        );

        let mut state = lifecycle();
        let transition = valid_transition(&state, command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(command_id, GOVERNANCE_SIGNER, "operator", 2, CHAIN_ID, 1),
            invalid(ValidatorTransitionDeterministicInvalidV1::GovernanceSequenceMismatch),
        );
    }

    #[test]
    fn schedule_classifies_state_and_transition_rejections_without_mutation() {
        let command_id = "typed-validator-state";

        let mut state = lifecycle();
        let first = valid_transition(&state, "typed-validator-first");
        state
            .schedule(first, valid_authorization("typed-validator-first"))
            .expect("schedule first pending transition");
        let transition = valid_transition(&state, command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(command_id, GOVERNANCE_SIGNER, "operator", 2, CHAIN_ID, 1),
            invalid(ValidatorTransitionDeterministicInvalidV1::PendingTransitionExists),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.base_validator_set_hash_hex = "22".repeat(32);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::BaseValidatorSetHash),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.activation_height = 2;
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::ActivationHeight),
        );

        let mut state = lifecycle();
        let target = state.active_validators.iter().take(3).cloned().collect();
        let transition = transition_for_target(&state, command_id, 3, target, &[]);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::TargetValidatorSet),
        );

        let mut state = lifecycle();
        let mut target = state.active_validators.clone();
        target.drain(0..2);
        target.extend([validator(8), validator(9)]);
        let transition = transition_for_target(&state, command_id, 3, target, &[]);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::ValidatorSetOverlap),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.new_validator_proofs[0].signature_hex = "00".to_string();
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::NewValidatorProof),
        );

        let mut state = lifecycle();
        let target = state.active_validators.clone();
        let transition = transition_for_target(&state, command_id, 3, target, &[]);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invalid(ValidatorTransitionDeterministicInvalidV1::NoActiveSetChange),
        );
    }

    #[test]
    fn schedule_classifies_authenticated_invariants_and_overflows_without_mutation() {
        let command_id = "typed-validator-invariant";

        let mut state = lifecycle();
        state.schema = "trnm_validator_lifecycle_v2".to_string();
        let transition = valid_transition(&lifecycle(), command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invariant(ValidatorTransitionInvariantV1::AuthenticatedLifecycle),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.chain_id = "trnm-joined-other-chain".to_string();
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(
                command_id,
                GOVERNANCE_SIGNER,
                "operator",
                1,
                "trnm-joined-other-chain",
                1,
            ),
            invariant(ValidatorTransitionInvariantV1::LifecycleContextBinding),
        );

        let mut state = lifecycle();
        state.governance_sequence = u64::MAX;
        let transition = valid_transition(&state, command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(
                command_id,
                GOVERNANCE_SIGNER,
                "operator",
                u64::MAX,
                CHAIN_ID,
                1,
            ),
            invariant(ValidatorTransitionInvariantV1::GovernanceSequenceExhausted),
        );

        let mut state = lifecycle();
        let mut transition = valid_transition(&state, command_id);
        transition.activation_height = u64::MAX;
        assert_failure_without_mutation(
            &mut state,
            transition,
            authorization(
                command_id,
                GOVERNANCE_SIGNER,
                "operator",
                1,
                CHAIN_ID,
                u64::MAX,
            ),
            invariant(ValidatorTransitionInvariantV1::ActivationDelayOverflow),
        );

        let mut state = lifecycle();
        let target = valid_transition(&state, command_id).target_validators;
        state.pending_transition = Some(ScheduledValidatorTransitionV1 {
            transition_id: "overflowing-authenticated-pending".to_string(),
            base_validator_set_hash_hex: state
                .active_set_hash_hex()
                .expect("hash lifecycle for pending overflow"),
            accepted_height: u64::MAX,
            activation_height: u64::MAX,
            target_validators: target,
        });
        assert!(state.validate().is_err());
        let transition = valid_transition(&lifecycle(), command_id);
        assert_failure_without_mutation(
            &mut state,
            transition,
            valid_authorization(command_id),
            invariant(ValidatorTransitionInvariantV1::AuthenticatedLifecycle),
        );
    }

    #[test]
    fn schedule_swaps_only_a_fully_validated_candidate() {
        let command_id = "typed-validator-success";
        let mut state = lifecycle();
        let before = state.clone();
        let transition = valid_transition(&state, command_id);
        let expected_target = transition.target_validators.clone();

        state
            .schedule(transition, valid_authorization(command_id))
            .expect("schedule valid typed validator transition");

        assert_eq!(state.governance_sequence, 1);
        assert_eq!(state.active_validators, before.active_validators);
        assert_eq!(
            state.last_applied_transition_id,
            before.last_applied_transition_id
        );
        assert_eq!(
            state.pending_transition,
            Some(ScheduledValidatorTransitionV1 {
                transition_id: command_id.to_string(),
                base_validator_set_hash_hex: before
                    .active_set_hash_hex()
                    .expect("hash pre-schedule active set"),
                accepted_height: 1,
                activation_height: 3,
                target_validators: expected_target,
            })
        );
        state.validate().expect("validate scheduled candidate");
    }
}
