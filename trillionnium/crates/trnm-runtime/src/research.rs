use std::collections::{BTreeMap, BTreeSet};

use trnm_protocol::{
    research_applied_command_key, research_authority_set_key, research_domain_object_key,
    research_snapshot_key, CanonicalResearchTxV1, FeePolicyV1, FEE_COLLECTOR_ACCOUNT_V1,
    RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1, RESEARCH_AUTHORITY_SET_OBJECT_TYPE_V1,
    RESEARCH_DOMAIN_OBJECT_TYPE_V1,
};
use trnm_research_protocol::{
    AppliedCommandRecordV1, ApplyOutcome, AuthorityRole, AuthoritySetV1, CanonicalCbor,
    ClaimResolutionDecision, ExternalKey, ObjectRefV1, ProtocolStateError, ResearchCommandV1,
    ResearchDomainObjectV1, ResearchObjectKind, ResearchProtocolState, SignedResearchCommandV1,
};

use super::{
    ensure_type, event, ExecutionContext, ResourceEstimate, RuntimeError, RuntimeMutation,
    RuntimeReceipt, RuntimeState, StateView,
};

const MAX_RESEARCH_AUTHORITY_SET_BYTES: usize = 128 * 1024;
const MAX_RESEARCH_DOMAIN_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_RESEARCH_APPLIED_RECORD_BYTES: usize = 4 * 1024;
const RESEARCH_OBJECT_TOUCH_GAS: u64 = 750;

/// Build the fresh-genesis Research authority policy. Runtime execution never
/// derives authority trust from an incoming self-signed command, and this
/// singleton is never rewritten by ordinary Research transactions.
pub fn research_genesis_mutation(
    authorities: AuthoritySetV1,
) -> Result<RuntimeMutation, RuntimeError> {
    authorities
        .validate()
        .map_err(|error| RuntimeError::ResearchState(error.to_string()))?;
    let value_bytes = encode_authority_set(&authorities)?;
    Ok(RuntimeMutation {
        object_key_hex: research_authority_set_key(),
        object_type: RESEARCH_AUTHORITY_SET_OBJECT_TYPE_V1.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes,
    })
}

/// Execute one canonical Research transaction against the ordinary runtime
/// object view.
///
/// Exact signed-command replays and command-ID fingerprint conflicts both fail
/// closed before account or Research mutations are emitted. API clients recover
/// an already-applied result by querying its authenticated record, not by adding
/// another free consensus transaction to a block.
pub fn execute_research(
    tx: &CanonicalResearchTxV1,
    context: ExecutionContext<'_>,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    let signed = validate_research_transaction_context(tx, context)?;
    let mut meter = ResearchIoMeter::default();
    meter.add_validation_bytes(signed.canonical_bytes().len())?;
    let authorities = load_research_authorities(view, &mut meter)?;
    ResearchProtocolState::authorize(&authorities, &signed).map_err(map_research_state_error)?;
    if matches!(
        &signed.command,
        ResearchCommandV1::IssueWorkloadReceipt(_) | ResearchCommandV1::CreateResearchClaim(_)
    ) {
        // App v6 has no settlement activation tied to a verified Paper Raid V2
        // finality commitment. Keep the frozen V1 wire/state decodable, but do
        // not let its accepted-work or claim objects become an alternate
        // ranking/reward input lane.
        return Err(RuntimeError::LegacyResearchSettlementLocked);
    }
    reject_applied_replay(view, &signed, &mut meter)?;

    // This economic lower bound and nonce check intentionally precede all
    // command-domain reads and state-machine execution. Invalid spam cannot
    // force a bounded-but-expensive Research graph validation first.
    let mut economic_state = RuntimeState::new(view);
    let policy = economic_state.policy()?.value.clone();
    let lower_bound = estimate_research_resources(context, &signed.command, &policy, &meter)?;
    enforce_research_limits(tx, lower_bound)?;
    let (expected_nonce, available_balance) = {
        let sender = economic_state.account(&tx.sender)?;
        (
            sender
                .value
                .nonce
                .checked_add(1)
                .ok_or(RuntimeError::NonceExhausted)?,
            sender.value.balance,
        )
    };
    if tx.nonce != expected_nonce {
        return Err(RuntimeError::NonceMismatch {
            expected: expected_nonce,
            received: tx.nonce,
        });
    }
    if available_balance < lower_bound.fee_estimate {
        return Err(RuntimeError::InsufficientBalance {
            account: tx.sender.clone(),
            required: lower_bound.fee_estimate,
            available: available_balance,
        });
    }

    let primary_object_ref = signed.command.primary_object_ref();
    ensure_new_primary_absent(view, primary_object_ref, &mut meter)?;
    let (primary_object_ref, research_mutations) = {
        let mut fragment = ResearchFragment::new(view, &mut meter);
        fragment.load_command_read_set(&signed.command)?;
        let mut research_state =
            ResearchProtocolState::from_fragment(authorities, fragment.domain_objects())
                .map_err(map_research_state_error)?;
        let (primary_object_ref, changed_object_refs) = match research_state
            .apply(&signed)
            .map_err(map_research_state_error)?
        {
            ApplyOutcome::Applied {
                primary_object_ref,
                changed_object_refs,
            } => (primary_object_ref, changed_object_refs),
            ApplyOutcome::Idempotent { .. } => {
                return Err(RuntimeError::ResearchCommandReplay);
            }
        };
        let mutations =
            fragment.build_mutations(&research_state, signed.command_id, &changed_object_refs)?;
        (primary_object_ref, mutations)
    };
    for mutation in &research_mutations {
        meter.note_write(mutation)?;
    }
    let estimate = estimate_research_resources(context, &signed.command, &policy, &meter)?;
    enforce_research_limits(tx, estimate)?;

    economic_state.debit(&tx.sender, estimate.fee_estimate)?;
    economic_state.credit(FEE_COLLECTOR_ACCOUNT_V1, estimate.fee_estimate)?;
    let sender = economic_state.account(&tx.sender)?;
    sender.value.nonce = tx.nonce;
    sender.dirty = true;

    let mut mutations = economic_state.into_mutations()?;
    mutations.extend(research_mutations);
    mutations.sort_by(|left, right| left.object_key_hex.cmp(&right.object_key_hex));
    for mutation in &mutations {
        let expected_next = mutation
            .expected_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RuntimeError::ObjectVersionExhausted)?;
        if mutation.next_version != expected_next {
            return Err(RuntimeError::ResearchState(format!(
                "Research mutation {} does not advance exactly one version",
                mutation.object_key_hex
            )));
        }
    }
    if mutations
        .windows(2)
        .any(|pair| pair[0].object_key_hex == pair[1].object_key_hex)
    {
        return Err(RuntimeError::ResearchState(
            "Research mutation keys are not unique".to_string(),
        ));
    }

    let primary_key = research_key(primary_object_ref)?;
    Ok(RuntimeReceipt {
        gas_used: estimate.gas_used,
        fee_charged: estimate.fee_estimate,
        events: vec![event(
            "research_command_applied",
            [
                ("command_id", tx.command_id.as_str()),
                ("object_key", primary_key.as_str()),
            ],
        )],
        mutations,
    })
}

fn validate_research_transaction_context(
    tx: &CanonicalResearchTxV1,
    context: ExecutionContext<'_>,
) -> Result<SignedResearchCommandV1, RuntimeError> {
    tx.validate()
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    if tx.sender != context.signer_id {
        return Err(RuntimeError::SenderMismatch);
    }
    if tx.sender == FEE_COLLECTOR_ACCOUNT_V1 {
        return Err(RuntimeError::ReservedSystemAccount);
    }
    let signed = tx
        .signed_research_command()
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    if signed.chain_id != context.chain_id {
        return Err(RuntimeError::ResearchChainMismatch);
    }
    let expected_role = match signed.signer_role {
        AuthorityRole::NakamaAuthority => "nakama",
        AuthorityRole::HeptaAuthority => "hepta",
    };
    if context.signer_role != expected_role {
        return Err(RuntimeError::ResearchRoleMismatch);
    }
    Ok(signed)
}

fn estimate_research_resources(
    context: ExecutionContext<'_>,
    command: &ResearchCommandV1,
    policy: &FeePolicyV1,
    meter: &ResearchIoMeter,
) -> Result<ResourceEstimate, RuntimeError> {
    let payload_gas = u64::try_from(context.payload_len)
        .unwrap_or(u64::MAX)
        .checked_mul(policy.byte_gas)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let operation_gas = match command {
        ResearchCommandV1::MatchEvidenceCommitment(_) => 3_000,
        ResearchCommandV1::EvaluationCommitment(_) => 4_000,
        ResearchCommandV1::IssueWorkloadReceipt(_) => 5_000,
        ResearchCommandV1::CreateResearchClaim(_) => 6_000,
        ResearchCommandV1::DeclareLicense(_) => 3_500,
        ResearchCommandV1::ChallengeResearchClaim(_) => 4_500,
        ResearchCommandV1::ResolveResearchClaim(_) => 6_000,
    };
    let state_bytes = meter
        .read_bytes
        .checked_add(meter.validation_bytes)
        .and_then(|bytes| bytes.checked_add(meter.write_bytes))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let state_byte_gas = state_bytes
        .checked_mul(policy.byte_gas)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let touched_objects =
        u64::try_from(meter.touched_keys.len()).map_err(|_| RuntimeError::ArithmeticOverflow)?;
    let touch_gas = touched_objects
        .checked_mul(RESEARCH_OBJECT_TOUCH_GAS)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let gas_used = policy
        .base_gas
        .checked_add(payload_gas)
        .and_then(|gas| gas.checked_add(operation_gas))
        .and_then(|gas| gas.checked_add(state_byte_gas))
        .and_then(|gas| gas.checked_add(touch_gas))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let fee_estimate = u128::from(gas_used)
        .checked_mul(policy.gas_price)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    Ok(ResourceEstimate {
        gas_used,
        fee_estimate,
    })
}

#[derive(Debug, Default)]
struct ResearchIoMeter {
    read_bytes: u64,
    validation_bytes: u64,
    write_bytes: u64,
    touched_keys: BTreeSet<String>,
}

impl ResearchIoMeter {
    fn touch(&mut self, key: &str) {
        self.touched_keys.insert(key.to_string());
    }

    fn add_validation_bytes(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.validation_bytes = self
            .validation_bytes
            .checked_add(u64::try_from(bytes).map_err(|_| RuntimeError::ArithmeticOverflow)?)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        Ok(())
    }

    fn note_read(
        &mut self,
        key: &str,
        object_type: &str,
        value_bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        self.touch(key);
        let bytes = metered_object_bytes(key, object_type, value_bytes)?;
        self.read_bytes = self
            .read_bytes
            .checked_add(bytes)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        self.validation_bytes = self
            .validation_bytes
            .checked_add(
                u64::try_from(value_bytes.len()).map_err(|_| RuntimeError::ArithmeticOverflow)?,
            )
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        Ok(())
    }

    fn note_write(&mut self, mutation: &RuntimeMutation) -> Result<(), RuntimeError> {
        self.touch(&mutation.object_key_hex);
        let bytes = metered_object_bytes(
            &mutation.object_key_hex,
            &mutation.object_type,
            &mutation.value_bytes,
        )?;
        self.write_bytes = self
            .write_bytes
            .checked_add(bytes)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        Ok(())
    }
}

fn metered_object_bytes(
    key: &str,
    object_type: &str,
    value_bytes: &[u8],
) -> Result<u64, RuntimeError> {
    key.len()
        .checked_add(object_type.len())
        .and_then(|size| size.checked_add(std::mem::size_of::<u64>()))
        .and_then(|size| size.checked_add(value_bytes.len()))
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(RuntimeError::ArithmeticOverflow)
}

fn load_research_authorities(
    view: &dyn StateView,
    meter: &mut ResearchIoMeter,
) -> Result<AuthoritySetV1, RuntimeError> {
    let legacy_key = research_snapshot_key();
    meter.touch(&legacy_key);
    if view.get(&legacy_key).is_some() {
        return Err(RuntimeError::ResearchState(
            "legacy aggregate Research snapshot requires explicit app-version migration"
                .to_string(),
        ));
    }
    let key = research_authority_set_key();
    meter.touch(&key);
    let stored = view
        .get(&key)
        .ok_or(RuntimeError::ResearchAuthoritySetMissing)?;
    ensure_type(&key, &stored, RESEARCH_AUTHORITY_SET_OBJECT_TYPE_V1)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_RESEARCH_AUTHORITY_SET_BYTES {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    meter.note_read(&key, &stored.object_type, &stored.value_bytes)?;
    let authorities: AuthoritySetV1 = serde_json::from_slice(&stored.value_bytes)
        .map_err(|error| RuntimeError::DecodeObject(key.clone(), error.to_string()))?;
    authorities
        .validate()
        .map_err(|error| RuntimeError::ResearchState(error.to_string()))?;
    if encode_authority_set(&authorities)? != stored.value_bytes {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    Ok(authorities)
}

/// Load the same immutable genesis trust set for additive Research protocol
/// extensions without exposing or rewriting the frozen V1 aggregate state.
pub(super) fn load_research_authorities_for_extension(
    view: &dyn StateView,
) -> Result<(AuthoritySetV1, u64, u64), RuntimeError> {
    let mut meter = ResearchIoMeter::default();
    let authorities = load_research_authorities(view, &mut meter)?;
    let touched_keys =
        u64::try_from(meter.touched_keys.len()).map_err(|_| RuntimeError::ArithmeticOverflow)?;
    Ok((authorities, meter.read_bytes, touched_keys))
}

fn encode_authority_set(authorities: &AuthoritySetV1) -> Result<Vec<u8>, RuntimeError> {
    let bytes = serde_json::to_vec(authorities)
        .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
    if bytes.len() > MAX_RESEARCH_AUTHORITY_SET_BYTES {
        return Err(RuntimeError::ResearchState(
            "Research authority set exceeds the runtime byte limit".to_string(),
        ));
    }
    Ok(bytes)
}

fn enforce_research_limits(
    tx: &CanonicalResearchTxV1,
    estimate: ResourceEstimate,
) -> Result<(), RuntimeError> {
    if estimate.gas_used > tx.max_gas {
        return Err(RuntimeError::GasLimitExceeded {
            required: estimate.gas_used,
            limit: tx.max_gas,
        });
    }
    if estimate.fee_estimate > tx.fee_limit {
        return Err(RuntimeError::FeeLimitExceeded {
            required: estimate.fee_estimate,
            limit: tx.fee_limit,
        });
    }
    Ok(())
}

fn reject_applied_replay(
    view: &dyn StateView,
    signed: &SignedResearchCommandV1,
    meter: &mut ResearchIoMeter,
) -> Result<(), RuntimeError> {
    let key = applied_command_key(signed.command_id)?;
    meter.touch(&key);
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(&key, &stored, RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_RESEARCH_APPLIED_RECORD_BYTES {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    meter.note_read(&key, &stored.object_type, &stored.value_bytes)?;
    let record = AppliedCommandRecordV1::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::ResearchMirrorMismatch(key.clone()))?;
    if record.command_id != signed.command_id {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    if record.fingerprint != signed.command_fingerprint() {
        return Err(RuntimeError::ResearchAlteredReplay);
    }

    let primary = load_domain_object(
        view,
        record.primary_object_ref.kind,
        record.primary_object_ref.key,
        meter,
    )?;
    if primary.value.object_ref().object_version < record.primary_object_ref.object_version {
        return Err(RuntimeError::ResearchMirrorMismatch(primary.key));
    }
    Err(RuntimeError::ResearchCommandReplay)
}

fn ensure_new_primary_absent(
    view: &dyn StateView,
    object_ref: ObjectRefV1,
    meter: &mut ResearchIoMeter,
) -> Result<(), RuntimeError> {
    let key = research_key(object_ref)?;
    meter.touch(&key);
    if view.get(&key).is_some() {
        Err(RuntimeError::ResearchMirrorMismatch(key))
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct LoadedDomainObject {
    key: String,
    version: u64,
    value: ResearchDomainObjectV1,
}

fn load_domain_object(
    view: &dyn StateView,
    kind: ResearchObjectKind,
    external_key: ExternalKey,
    meter: &mut ResearchIoMeter,
) -> Result<LoadedDomainObject, RuntimeError> {
    let expected_ref = ObjectRefV1::new(kind, external_key, 1);
    let key = research_key(expected_ref)?;
    meter.touch(&key);
    let stored = view
        .get(&key)
        .ok_or_else(|| RuntimeError::ResearchMirrorMismatch(key.clone()))?;
    ensure_type(&key, &stored, RESEARCH_DOMAIN_OBJECT_TYPE_V1)?;
    if stored.version == 0 || stored.value_bytes.len() > MAX_RESEARCH_DOMAIN_OBJECT_BYTES {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    meter.note_read(&key, &stored.object_type, &stored.value_bytes)?;
    let value = ResearchDomainObjectV1::from_canonical_bytes(kind, &stored.value_bytes)
        .map_err(|_| RuntimeError::ResearchMirrorMismatch(key.clone()))?;
    let object_ref = value.object_ref();
    if object_ref.kind != kind
        || object_ref.key != external_key
        || object_ref.object_version != stored.version
    {
        return Err(RuntimeError::ResearchMirrorMismatch(key));
    }
    Ok(LoadedDomainObject {
        key,
        version: stored.version,
        value,
    })
}

struct ResearchFragment<'view, 'meter> {
    view: &'view dyn StateView,
    meter: &'meter mut ResearchIoMeter,
    objects: BTreeMap<(ResearchObjectKind, ExternalKey), LoadedDomainObject>,
}

impl<'view, 'meter> ResearchFragment<'view, 'meter> {
    fn new(view: &'view dyn StateView, meter: &'meter mut ResearchIoMeter) -> Self {
        Self {
            view,
            meter,
            objects: BTreeMap::new(),
        }
    }

    fn load_exact(&mut self, object_ref: ObjectRefV1) -> Result<(), RuntimeError> {
        self.load_current(object_ref.kind, object_ref.key)?;
        let object_key = research_key(object_ref)?;
        let loaded = self
            .objects
            .get(&(object_ref.kind, object_ref.key))
            .ok_or(RuntimeError::ResearchMirrorMismatch(object_key))?;
        if loaded.version != object_ref.object_version {
            return Err(RuntimeError::ResearchMirrorMismatch(loaded.key.clone()));
        }
        Ok(())
    }

    fn load_current(
        &mut self,
        kind: ResearchObjectKind,
        key: ExternalKey,
    ) -> Result<(), RuntimeError> {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.objects.entry((kind, key)) {
            entry.insert(load_domain_object(self.view, kind, key, self.meter)?);
        }
        Ok(())
    }

    fn load_command_read_set(&mut self, command: &ResearchCommandV1) -> Result<(), RuntimeError> {
        match command {
            ResearchCommandV1::MatchEvidenceCommitment(_) => {}
            ResearchCommandV1::EvaluationCommitment(payload) => {
                self.load_exact(payload.match_evidence_ref)?;
            }
            ResearchCommandV1::IssueWorkloadReceipt(payload) => {
                self.load_exact(payload.evaluation_ref)?;
            }
            ResearchCommandV1::CreateResearchClaim(payload) => {
                self.load_exact(payload.workload_receipt_ref)?;
                for object_ref in &payload.evidence_refs {
                    self.load_exact(*object_ref)?;
                }
            }
            ResearchCommandV1::DeclareLicense(payload) => {
                self.load_exact(payload.claim_ref)?;
            }
            ResearchCommandV1::ChallengeResearchClaim(payload) => {
                self.load_exact(payload.claim_ref)?;
            }
            ResearchCommandV1::ResolveResearchClaim(payload) => {
                self.load_exact(payload.challenge_ref)?;
                let challenge_key = research_key(payload.challenge_ref)?;
                let challenge = self
                    .objects
                    .get(&(
                        ResearchObjectKind::ClaimChallenge,
                        payload.challenge_ref.key,
                    ))
                    .and_then(|loaded| match &loaded.value {
                        ResearchDomainObjectV1::ClaimChallenge(object) => Some(object),
                        _ => None,
                    })
                    .ok_or(RuntimeError::ResearchMirrorMismatch(challenge_key))?;
                let claim_key = challenge.challenge.claim_ref.key;
                self.load_current(ResearchObjectKind::ResearchClaim, claim_key)?;
                if payload.decision == ClaimResolutionDecision::AmendContributorShares {
                    let claim_object_key =
                        research_domain_object_key(ResearchObjectKind::ResearchClaim, claim_key)
                            .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
                    let workload_ref = self
                        .objects
                        .get(&(ResearchObjectKind::ResearchClaim, claim_key))
                        .and_then(|loaded| match &loaded.value {
                            ResearchDomainObjectV1::ResearchClaim(object) => {
                                Some(object.claim.workload_receipt_ref)
                            }
                            _ => None,
                        })
                        .ok_or(RuntimeError::ResearchMirrorMismatch(claim_object_key))?;
                    self.load_exact(workload_ref)?;
                }
            }
        }
        Ok(())
    }

    fn domain_objects(&self) -> Vec<ResearchDomainObjectV1> {
        self.objects
            .values()
            .map(|loaded| loaded.value.clone())
            .collect()
    }

    fn build_mutations(
        &mut self,
        state: &ResearchProtocolState,
        command_id: ExternalKey,
        changed_object_refs: &[ObjectRefV1],
    ) -> Result<Vec<RuntimeMutation>, RuntimeError> {
        let record = state.get_applied_command(command_id).ok_or_else(|| {
            RuntimeError::ResearchState(
                "applied command record is absent after successful apply".to_string(),
            )
        })?;
        let record_key = applied_command_key(command_id)?;
        let record_bytes = record.canonical_bytes();
        if record_bytes.len() > MAX_RESEARCH_APPLIED_RECORD_BYTES {
            return Err(RuntimeError::ResearchState(
                "Research applied record exceeds the runtime byte limit".to_string(),
            ));
        }
        let mut mutations = Vec::with_capacity(changed_object_refs.len() + 1);
        mutations.push(RuntimeMutation {
            object_key_hex: record_key,
            object_type: RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1.to_string(),
            expected_version: None,
            next_version: 1,
            value_bytes: record_bytes,
        });

        for object_ref in changed_object_refs {
            let key = research_key(*object_ref)?;
            let expected_version = object_ref
                .object_version
                .checked_sub(1)
                .ok_or_else(|| RuntimeError::ResearchMirrorMismatch(key.clone()))?;
            let expected_version = if expected_version == 0 {
                self.meter.touch(&key);
                if self.view.get(&key).is_some() {
                    return Err(RuntimeError::ResearchMirrorMismatch(key));
                }
                None
            } else {
                let loaded = self
                    .objects
                    .get(&(object_ref.kind, object_ref.key))
                    .ok_or_else(|| RuntimeError::ResearchMirrorMismatch(key.clone()))?;
                if loaded.version != expected_version {
                    return Err(RuntimeError::ResearchMirrorMismatch(key));
                }
                Some(expected_version)
            };
            let value_bytes = state
                .object_canonical_bytes(*object_ref)
                .map_err(map_research_state_error)?;
            if value_bytes.len() > MAX_RESEARCH_DOMAIN_OBJECT_BYTES {
                return Err(RuntimeError::ResearchState(
                    "Research domain object exceeds the runtime byte limit".to_string(),
                ));
            }
            mutations.push(RuntimeMutation {
                object_key_hex: key,
                object_type: RESEARCH_DOMAIN_OBJECT_TYPE_V1.to_string(),
                expected_version,
                next_version: object_ref.object_version,
                value_bytes,
            });
        }
        Ok(mutations)
    }
}

fn research_key(object_ref: ObjectRefV1) -> Result<String, RuntimeError> {
    research_domain_object_key(object_ref.kind, object_ref.key)
        .map_err(|error| RuntimeError::Protocol(error.to_string()))
}

fn applied_command_key(command_id: ExternalKey) -> Result<String, RuntimeError> {
    research_applied_command_key(command_id)
        .map_err(|error| RuntimeError::Protocol(error.to_string()))
}

fn map_research_state_error(error: ProtocolStateError) -> RuntimeError {
    match error {
        ProtocolStateError::AlteredReplay { .. } => RuntimeError::ResearchAlteredReplay,
        other => RuntimeError::ResearchState(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use trnm_protocol::{
        account_key, AccountV1, ACCOUNT_OBJECT_TYPE_V1, CANONICAL_RESEARCH_TX_PAYLOAD_TYPE_V1,
        RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1, RESEARCH_AUTHORITY_SET_OBJECT_TYPE_V1,
        RESEARCH_DOMAIN_OBJECT_TYPE_V1, RESEARCH_SNAPSHOT_OBJECT_TYPE_V1,
    };
    use trnm_research_protocol::{
        AuthorityIdentityV1, ClaimShareV1, ContributionRole, ContributorWorkV1,
        CreateResearchClaimV1, EvaluationCommitmentV1, IssueWorkloadReceiptV1,
        MatchEvidenceCommitmentV1, ResearchCommandV1,
    };

    use super::*;
    use crate::StateObject;

    const AUTHORITY_DID: &str = "did:trnm:nakama-authority";
    const AUTHORITY_SEED: [u8; 32] = [0x11; 32];
    const HEPTA_DID: &str = "did:trnm:hepta-authority";
    const HEPTA_SEED: [u8; 32] = [0x22; 32];

    #[derive(Default)]
    struct MemoryView(BTreeMap<String, StateObject>, RefCell<Vec<String>>);

    impl StateView for MemoryView {
        fn get(&self, object_key_hex: &str) -> Option<StateObject> {
            self.1.borrow_mut().push(object_key_hex.to_string());
            self.0.get(object_key_hex).cloned()
        }
    }

    impl MemoryView {
        fn apply_mutations(&mut self, mutations: Vec<RuntimeMutation>) {
            for mutation in mutations {
                assert_eq!(
                    self.0
                        .get(&mutation.object_key_hex)
                        .map(|object| object.version),
                    mutation.expected_version
                );
                self.0.insert(
                    mutation.object_key_hex,
                    StateObject {
                        object_type: mutation.object_type,
                        version: mutation.next_version,
                        value_bytes: mutation.value_bytes,
                    },
                );
            }
        }

        fn account(&self, account: &str) -> AccountV1 {
            serde_json::from_slice(&self.0[&account_key(account)].value_bytes).unwrap()
        }

        fn clear_reads(&self) {
            self.1.borrow_mut().clear();
        }

        fn read_keys(&self) -> Vec<String> {
            self.1.borrow().clone()
        }
    }

    fn external_key(namespace: &str, id: &str) -> ExternalKey {
        ExternalKey::from_external_id(namespace, id).unwrap()
    }

    fn authority_set() -> AuthoritySetV1 {
        AuthoritySetV1::new(
            vec![AuthorityIdentityV1::new(
                AUTHORITY_DID.to_string(),
                SigningKey::from_bytes(&AUTHORITY_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap()],
            vec![AuthorityIdentityV1::new(
                HEPTA_DID.to_string(),
                SigningKey::from_bytes(&HEPTA_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn seeded_view() -> MemoryView {
        let mut view = MemoryView::default();
        view.apply_mutations(vec![research_genesis_mutation(authority_set()).unwrap()]);
        view.0.insert(
            account_key(AUTHORITY_DID),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: AUTHORITY_DID.to_string(),
                    balance: 100_000_000_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        view.0.insert(
            account_key(HEPTA_DID),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: HEPTA_DID.to_string(),
                    balance: 100_000_000_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        view
    }

    fn research_tx(suffix: &str, nonce: u64, event_byte: u8) -> CanonicalResearchTxV1 {
        let command = ResearchCommandV1::MatchEvidenceCommitment(MatchEvidenceCommitmentV1 {
            commitment_id: external_key("nakama.commitment", &format!("commitment-{suffix}")),
            match_id: external_key("nakama.match", &format!("match-{suffix}")),
            challenge_id: external_key("hepta.challenge", &format!("challenge-{suffix}")),
            event_root: [event_byte; 32],
            roster_root: [0x11; 32],
            ruleset_hash: [0x12; 32],
            dataset_hash: [0x13; 32],
            archive_hash: [0x14; 32],
            event_count: 42,
            completed_at_unix_s: 1_753_449_600 + nonce,
        });
        let signed = SignedResearchCommandV1::sign(
            "trnm-devnet-v1".to_string(),
            external_key("trnm.command", &format!("command-{suffix}")),
            AUTHORITY_DID.to_string(),
            AuthorityRole::NakamaAuthority,
            nonce,
            command,
            &SigningKey::from_bytes(&AUTHORITY_SEED),
        )
        .unwrap();
        CanonicalResearchTxV1::from_signed_command(&signed, 100_000, 100_000).unwrap()
    }

    fn hepta_tx(suffix: &str, nonce: u64, command: ResearchCommandV1) -> CanonicalResearchTxV1 {
        let signed = SignedResearchCommandV1::sign(
            "trnm-devnet-v1".to_string(),
            external_key("trnm.command", &format!("hepta-{suffix}")),
            HEPTA_DID.to_string(),
            AuthorityRole::HeptaAuthority,
            nonce,
            command,
            &SigningKey::from_bytes(&HEPTA_SEED),
        )
        .unwrap();
        CanonicalResearchTxV1::from_signed_command(&signed, 1_000_000, 1_000_000).unwrap()
    }

    fn evaluation_command(match_ref: ObjectRefV1, suffix: &str) -> ResearchCommandV1 {
        ResearchCommandV1::EvaluationCommitment(EvaluationCommitmentV1 {
            evaluation_id: external_key("hepta.evaluation", &format!("evaluation-{suffix}")),
            match_evidence_ref: match_ref,
            submission_hash: [0x20; 32],
            rubric_hash: [0x21; 32],
            evaluation_hash: [0x22; 32],
            reproduction_hash: Some([0x23; 32]),
            score_bps: 9_250,
            accepted: true,
            completed_at_unix_s: 1_753_449_700,
        })
    }

    fn context<'a>(tx: &'a CanonicalResearchTxV1, role: &'a str) -> ExecutionContext<'a> {
        ExecutionContext {
            height: 1,
            chain_id: "trnm-devnet-v1",
            signer_id: &tx.sender,
            signer_role: role,
            payload_len: tx.canonical_bytes().unwrap().len(),
        }
    }

    fn execute_and_apply(view: &mut MemoryView, tx: &CanonicalResearchTxV1) -> RuntimeReceipt {
        let receipt = execute_research(tx, context(tx, "nakama"), view).unwrap();
        view.apply_mutations(receipt.mutations.clone());
        receipt
    }

    #[test]
    fn research_command_persists_incremental_record_and_domain_object() {
        let mut view = seeded_view();
        let tx = research_tx("001", 1, 0x10);
        let signed = tx.signed_research_command().unwrap();
        let object_ref = signed.command.primary_object_ref();
        let authority_before = view.0[&research_authority_set_key()].clone();
        let sender_balance_before = view.account(AUTHORITY_DID).balance;
        let receipt = execute_and_apply(&mut view, &tx);

        assert!(receipt.gas_used > 0);
        assert_eq!(receipt.fee_charged, u128::from(receipt.gas_used));
        assert_eq!(receipt.events[0].kind, "research_command_applied");
        assert_eq!(receipt.mutations.len(), 4);
        assert!(receipt
            .mutations
            .windows(2)
            .all(|pair| pair[0].object_key_hex < pair[1].object_key_hex));
        assert!(receipt.mutations.iter().all(|mutation| {
            mutation.next_version
                == mutation
                    .expected_version
                    .unwrap_or(0)
                    .checked_add(1)
                    .unwrap()
        }));
        assert_eq!(view.account(AUTHORITY_DID).nonce, 1);
        assert_eq!(
            view.account(AUTHORITY_DID).balance,
            sender_balance_before - receipt.fee_charged
        );

        let authority_object = &view.0[&research_authority_set_key()];
        assert_eq!(
            authority_object.object_type,
            RESEARCH_AUTHORITY_SET_OBJECT_TYPE_V1
        );
        assert_eq!(authority_object, &authority_before);
        assert!(!view.0.contains_key(&research_snapshot_key()));

        let domain_key = research_key(object_ref).unwrap();
        let domain_object = &view.0[&domain_key];
        assert_eq!(domain_object.object_type, RESEARCH_DOMAIN_OBJECT_TYPE_V1);
        assert_eq!(domain_object.version, object_ref.object_version);
        let decoded = ResearchDomainObjectV1::from_canonical_bytes(
            object_ref.kind,
            &domain_object.value_bytes,
        )
        .unwrap();
        assert_eq!(decoded.object_ref(), object_ref);

        let record_key = applied_command_key(signed.command_id).unwrap();
        let record_object = &view.0[&record_key];
        assert_eq!(
            record_object.object_type,
            RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1
        );
        assert_eq!(record_object.version, 1);
        let record =
            AppliedCommandRecordV1::from_canonical_bytes(&record_object.value_bytes).unwrap();
        assert_eq!(record.command_id, signed.command_id);
        assert_eq!(record.primary_object_ref, object_ref);
    }

    #[test]
    fn exact_replay_and_altered_fingerprint_fail_closed() {
        let mut view = seeded_view();
        let tx = research_tx("001", 1, 0x10);
        execute_and_apply(&mut view, &tx);
        let state_before = view.0.clone();

        let replay = execute_research(&tx, context(&tx, "nakama"), &view).unwrap_err();
        assert_eq!(replay.code(), "research_command_replay");
        assert!(matches!(replay, RuntimeError::ResearchCommandReplay));
        assert_eq!(view.0, state_before);

        let altered = research_tx("001", 1, 0x99);
        let altered_error =
            execute_research(&altered, context(&altered, "nakama"), &view).unwrap_err();
        assert_eq!(altered_error.code(), "research_altered_replay");
        assert!(matches!(altered_error, RuntimeError::ResearchAlteredReplay));
        assert_eq!(view.0, state_before);
    }

    #[test]
    fn exact_replay_rejects_tampered_applied_record_mirror() {
        let mut view = seeded_view();
        let tx = research_tx("001", 1, 0x10);
        execute_and_apply(&mut view, &tx);
        let command_id = tx.signed_research_command().unwrap().command_id;
        let record_key = applied_command_key(command_id).unwrap();
        view.0.get_mut(&record_key).unwrap().value_bytes.push(0);

        assert!(matches!(
            execute_research(&tx, context(&tx, "nakama"), &view),
            Err(RuntimeError::ResearchMirrorMismatch(key)) if key == record_key
        ));
    }

    #[test]
    fn research_execution_rejects_missing_genesis_wrong_role_and_low_gas() {
        let tx = research_tx("001", 1, 0x10);
        assert!(matches!(
            execute_research(&tx, context(&tx, "nakama"), &MemoryView::default()),
            Err(RuntimeError::ResearchAuthoritySetMissing)
        ));

        let mut legacy = MemoryView::default();
        legacy.0.insert(
            research_snapshot_key(),
            StateObject {
                object_type: RESEARCH_SNAPSHOT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: b"{}".to_vec(),
            },
        );
        assert!(matches!(
            execute_research(&tx, context(&tx, "nakama"), &legacy),
            Err(RuntimeError::ResearchState(message))
                if message.contains("explicit app-version migration")
        ));

        let mut ambiguous = seeded_view();
        ambiguous.0.insert(
            research_snapshot_key(),
            StateObject {
                object_type: RESEARCH_SNAPSHOT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: b"{}".to_vec(),
            },
        );
        assert!(matches!(
            execute_research(&tx, context(&tx, "nakama"), &ambiguous),
            Err(RuntimeError::ResearchState(message))
                if message.contains("explicit app-version migration")
        ));

        let view = seeded_view();
        assert!(matches!(
            execute_research(&tx, context(&tx, "hepta"), &view),
            Err(RuntimeError::ResearchRoleMismatch)
        ));

        let mut wrong_chain = context(&tx, "nakama");
        wrong_chain.chain_id = "trnm-other-chain";
        assert!(matches!(
            execute_research(&tx, wrong_chain, &view),
            Err(RuntimeError::ResearchChainMismatch)
        ));

        let mut low_gas = tx;
        low_gas.max_gas = 1;
        let primary_key = research_key(
            low_gas
                .signed_research_command()
                .unwrap()
                .command
                .primary_object_ref(),
        )
        .unwrap();
        let before = view.0.clone();
        view.clear_reads();
        assert!(matches!(
            execute_research(&low_gas, context(&low_gas, "nakama"), &view),
            Err(RuntimeError::GasLimitExceeded { .. })
        ));
        assert!(!view.read_keys().contains(&primary_key));
        assert_eq!(view.0, before);
    }

    #[test]
    fn research_execution_detects_tampered_apphash_mirror() {
        let mut view = seeded_view();
        let tx = research_tx("001", 1, 0x10);
        execute_and_apply(&mut view, &tx);

        let match_ref = tx
            .signed_research_command()
            .unwrap()
            .command
            .primary_object_ref();
        let domain_key = research_key(match_ref).unwrap();
        view.0.get_mut(&domain_key).unwrap().value_bytes.push(0);
        let evaluation = ResearchCommandV1::EvaluationCommitment(EvaluationCommitmentV1 {
            evaluation_id: external_key("hepta.evaluation", "evaluation-001"),
            match_evidence_ref: match_ref,
            submission_hash: [0x20; 32],
            rubric_hash: [0x21; 32],
            evaluation_hash: [0x22; 32],
            reproduction_hash: Some([0x23; 32]),
            score_bps: 9_250,
            accepted: true,
            completed_at_unix_s: 1_753_449_700,
        });
        let signed = SignedResearchCommandV1::sign(
            "trnm-devnet-v1".to_string(),
            external_key("trnm.command", "evaluation-001"),
            HEPTA_DID.to_string(),
            AuthorityRole::HeptaAuthority,
            1,
            evaluation,
            &SigningKey::from_bytes(&HEPTA_SEED),
        )
        .unwrap();
        let evaluation_tx =
            CanonicalResearchTxV1::from_signed_command(&signed, 100_000, 100_000).unwrap();
        assert!(matches!(
            execute_research(
                &evaluation_tx,
                context(&evaluation_tx, "hepta"),
                &view
            ),
            Err(RuntimeError::ResearchMirrorMismatch(key)) if key == domain_key
        ));
    }

    #[test]
    fn research_execution_rejects_new_domain_object_collision() {
        let mut view = seeded_view();
        let tx = research_tx("001", 1, 0x10);
        let signed = tx.signed_research_command().unwrap();
        let domain_key = research_key(signed.command.primary_object_ref()).unwrap();
        view.0.insert(
            domain_key.clone(),
            StateObject {
                object_type: RESEARCH_DOMAIN_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: vec![0],
            },
        );
        assert!(matches!(
            execute_research(&tx, context(&tx, "nakama"), &view),
            Err(RuntimeError::ResearchMirrorMismatch(key)) if key == domain_key
        ));
    }

    #[test]
    fn unrelated_tampered_mirror_is_not_globally_scanned() {
        let mut view = seeded_view();
        let first = research_tx("001", 1, 0x10);
        execute_and_apply(&mut view, &first);
        let unrelated_ref = first
            .signed_research_command()
            .unwrap()
            .command
            .primary_object_ref();
        let unrelated_key = research_key(unrelated_ref).unwrap();
        view.0.get_mut(&unrelated_key).unwrap().value_bytes.push(0);

        let second = research_tx("002", 2, 0x20);
        let receipt = execute_research(&second, context(&second, "nakama"), &view).unwrap();
        assert_eq!(receipt.events[0].kind, "research_command_applied");
        assert!(!receipt
            .mutations
            .iter()
            .any(|mutation| mutation.object_key_hex == unrelated_key));
    }

    #[test]
    fn nonce_fee_and_balance_prechecks_skip_command_domain_reads() {
        let mut view = seeded_view();
        let match_tx = research_tx("precheck", 1, 0x31);
        execute_and_apply(&mut view, &match_tx);
        let match_ref = match_tx
            .signed_research_command()
            .unwrap()
            .command
            .primary_object_ref();
        let match_key = research_key(match_ref).unwrap();

        let bad_nonce = hepta_tx("bad-nonce", 7, evaluation_command(match_ref, "bad-nonce"));
        view.clear_reads();
        assert!(matches!(
            execute_research(&bad_nonce, context(&bad_nonce, "hepta"), &view),
            Err(RuntimeError::NonceMismatch { .. })
        ));
        assert!(!view.read_keys().contains(&match_key));

        let mut low_fee = hepta_tx("low-fee", 1, evaluation_command(match_ref, "low-fee"));
        low_fee.fee_limit = 1;
        view.clear_reads();
        assert!(matches!(
            execute_research(&low_fee, context(&low_fee, "hepta"), &view),
            Err(RuntimeError::FeeLimitExceeded { .. })
        ));
        assert!(!view.read_keys().contains(&match_key));

        let mut account = view.account(HEPTA_DID);
        account.balance = 0;
        view.0.get_mut(&account_key(HEPTA_DID)).unwrap().value_bytes =
            serde_json::to_vec(&account).unwrap();
        let no_balance = hepta_tx("no-balance", 1, evaluation_command(match_ref, "no-balance"));
        view.clear_reads();
        assert!(matches!(
            execute_research(&no_balance, context(&no_balance, "hepta"), &view),
            Err(RuntimeError::InsufficientBalance { .. })
        ));
        assert!(!view.read_keys().contains(&match_key));
    }

    #[test]
    fn legacy_workload_and_claim_settlement_lanes_are_locked_without_mutations() {
        let view = seeded_view();
        let contributor = external_key("hepta.contributor", "contributor-001");
        let evaluation_ref = ObjectRefV1::new(
            ResearchObjectKind::EvaluationCommitment,
            external_key("hepta.evaluation", "legacy-settlement-lock"),
            1,
        );

        let workload = ResearchCommandV1::IssueWorkloadReceipt(IssueWorkloadReceiptV1 {
            receipt_id: external_key("hepta.workload", "legacy-settlement-lock"),
            evaluation_ref,
            contributors: vec![ContributorWorkV1 {
                contributor,
                role: ContributionRole::Researcher,
                accepted_work_units: 10,
                contribution_hash: [0x51; 32],
            }],
            total_accepted_work_units: 10,
            policy_hash: [0x52; 32],
            issued_at_unix_s: 1_753_449_800,
        });
        let workload_tx = hepta_tx("legacy-settlement-workload", 1, workload);
        let workload_signed = workload_tx.signed_research_command().unwrap();
        let workload_ref = workload_signed.command.primary_object_ref();
        let before = view.0.clone();
        let error = execute_research(&workload_tx, context(&workload_tx, "hepta"), &view)
            .expect_err("legacy workload issuance must remain locked");
        assert!(matches!(
            &error,
            RuntimeError::LegacyResearchSettlementLocked
        ));
        assert_eq!(error.code(), "legacy_research_settlement_locked");
        assert_eq!(view.0, before);
        assert!(!view
            .0
            .contains_key(&applied_command_key(workload_signed.command_id).unwrap()));
        assert!(!view.0.contains_key(&research_key(workload_ref).unwrap()));

        let claim = ResearchCommandV1::CreateResearchClaim(CreateResearchClaimV1 {
            claim_id: external_key("hepta.claim", "legacy-settlement-lock"),
            workload_receipt_ref: workload_ref,
            evidence_refs: vec![evaluation_ref],
            artifact_hash: [0x53; 32],
            claim_scope_hash: [0x54; 32],
            claimants: vec![ClaimShareV1 {
                contributor,
                share_bps: 10_000,
            }],
            created_at_unix_s: 1_753_449_900,
        });
        let claim_tx = hepta_tx("legacy-settlement-claim", 1, claim);
        let claim_signed = claim_tx.signed_research_command().unwrap();
        let claim_ref = claim_signed.command.primary_object_ref();
        let error = execute_research(&claim_tx, context(&claim_tx, "hepta"), &view)
            .expect_err("legacy claim creation must remain locked");
        assert!(matches!(
            &error,
            RuntimeError::LegacyResearchSettlementLocked
        ));
        assert_eq!(error.code(), "legacy_research_settlement_locked");
        assert_eq!(view.0, before);
        assert!(!view
            .0
            .contains_key(&applied_command_key(claim_signed.command_id).unwrap()));
        assert!(!view.0.contains_key(&research_key(claim_ref).unwrap()));
    }

    #[test]
    fn more_than_ten_thousand_commands_have_constant_incremental_work() {
        let mut view = seeded_view();
        let authority_before = view.0[&research_authority_set_key()].clone();
        const COMMANDS: u64 = 10_002;
        for nonce in 1..=COMMANDS {
            let tx = research_tx(&format!("scale-{nonce:05}"), nonce, (nonce % 251) as u8 + 1);
            view.clear_reads();
            let receipt = execute_research(&tx, context(&tx, "nakama"), &view).unwrap();
            assert_eq!(receipt.mutations.len(), 4);
            assert!(view.read_keys().len() <= 8);
            view.apply_mutations(receipt.mutations);
        }

        assert_eq!(view.0[&research_authority_set_key()], authority_before);
        assert!(!view.0.contains_key(&research_snapshot_key()));
        assert_eq!(
            view.0
                .values()
                .filter(|object| { object.object_type == RESEARCH_APPLIED_COMMAND_OBJECT_TYPE_V1 })
                .count(),
            COMMANDS as usize
        );
        assert_eq!(
            view.0
                .values()
                .filter(|object| object.object_type == RESEARCH_DOMAIN_OBJECT_TYPE_V1)
                .count(),
            COMMANDS as usize
        );
    }

    #[test]
    fn authority_set_rejects_nonzero_invalid_ed25519_points() {
        // ed25519-dalek intentionally follows ZIP-215 and accepts some
        // non-canonical encodings such as [0xff; 32].  This encoding instead
        // has no Edwards decompression under those same semantics.
        let mut invalid = [0_u8; 32];
        invalid[0] = 1;
        invalid[31] = 8;
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&invalid).is_err());
        assert!(AuthorityIdentityV1::new("did:trnm:invalid".to_string(), invalid).is_err());
    }

    #[test]
    fn research_payload_type_remains_distinct_from_legacy_payload() {
        assert_eq!(
            CANONICAL_RESEARCH_TX_PAYLOAD_TYPE_V1,
            "trnm.canonical.research.tx.v1"
        );
    }
}
