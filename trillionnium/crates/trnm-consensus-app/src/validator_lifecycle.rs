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
    pub active_validators: Vec<ConsensusValidatorV1>,
    pub pending_transition: Option<ScheduledValidatorTransitionV1>,
    pub last_applied_transition_id: Option<String>,
}

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
            ensure!(
                pending.accepted_height > 0
                    && pending.activation_height
                        >= pending
                            .accepted_height
                            .saturating_add(self.governance.min_activation_delay_blocks),
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

    pub fn schedule(
        &mut self,
        transition: ValidatorSetTransitionV1,
        envelope_command_id: &str,
        envelope_signer_id: &str,
        envelope_signer_role: &str,
        expected_chain_id: &str,
        accepted_height: u64,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            transition.schema == VALIDATOR_TRANSITION_SCHEMA_V1,
            "unsupported validator transition schema"
        );
        ensure!(
            transition.chain_id == expected_chain_id,
            "validator transition chain_id mismatch"
        );
        ensure!(
            self.chain_id == expected_chain_id,
            "committed validator lifecycle chain_id mismatch"
        );
        ensure!(
            transition.transition_id == envelope_command_id,
            "validator transition_id must equal envelope command_id"
        );
        ensure!(
            envelope_signer_role == "operator" && envelope_signer_id == self.governance.signer_id,
            "validator transition is not signed by the configured governance operator"
        );
        ensure!(
            self.pending_transition.is_none(),
            "a validator transition is already pending"
        );
        ensure!(
            transition.base_validator_set_hash_hex == self.active_set_hash_hex()?,
            "validator transition base set hash mismatch"
        );
        ensure!(
            transition.activation_height
                >= accepted_height.saturating_add(self.governance.min_activation_delay_blocks),
            "validator transition activation height is too early"
        );
        let target_validators = canonicalize_validators(transition.target_validators.clone())?;
        validate_transition_target(&target_validators)?;
        validate_overlap(&self.active_validators, &target_validators)?;
        validate_new_validator_proofs(&transition, &self.active_validators, &target_validators)?;
        ensure!(
            target_validators != self.active_validators,
            "validator transition does not change the active set"
        );
        self.pending_transition = Some(ScheduledValidatorTransitionV1 {
            transition_id: transition.transition_id,
            base_validator_set_hash_hex: transition.base_validator_set_hash_hex,
            accepted_height,
            activation_height: transition.activation_height,
            target_validators,
        });
        self.validate()
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
