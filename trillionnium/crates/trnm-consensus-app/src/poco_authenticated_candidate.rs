//! Application-authenticated B2-G reconstruction.
//!
//! Constructors consume either the cutoff-only pre-header authority or the
//! later checkpoint execution authority joined to the same private historical
//! projection. Both paths rebuild the complete B2-G transcript from exact
//! cutoff facts and immediately run the calculation with the hard-coded strict
//! Ed25519 verifier. Caller-normalized transcripts, generic verifiers, old
//! inert kernels, status values, and events are not inputs to this module.

use super::*;
use crate::{
    poco_checkpoint::{
        AuthenticatedPocoProjectionAtV0, AuthorizedPocoCheckpointExecutionV0,
        AuthorizedPocoScheduledCutoffV0,
    },
    poco_semantics::{BondStateV0, RelationshipClassV0},
};
use trnm_consensus_types::{
    compute_candidate_selection_kernel_v0, CandidateSelectionKernelV0, CertificateId,
    ConsensusParametersHash, EpochFallbackReasonV0, StateRoot,
    UnauthenticatedCandidateSelectionTranscriptV0, UnauthenticatedSnapshotCandidateV0,
    UnauthenticatedSnapshotContributionV0, ValidatorSetId,
};
use trnm_finality_types::hash_domain;

const TRANSCRIPT_DOMAIN_V0: &str = "trnm.poco-bft.authenticated-candidate-transcript.v0";
const RESULT_DOMAIN_V0: &str = "trnm.poco-bft.authenticated-candidate-result.v0";
const AUTHORIZATION_DOMAIN_V0: &str = "trnm.poco-bft.authenticated-candidate-authorization.v0";
const CUTOFF_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.authenticated-cutoff-candidate-authorization.v0";

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedPocoCandidateComputationV0 {
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    kernel: CandidateSelectionKernelV0,
    candidate_parameters_hash: ConsensusParametersHash,
    transcript_digest: [u8; 32],
    result_digest: [u8; 32],
    #[cfg(test)]
    transcript_canonical_bytes: Vec<u8>,
    #[cfg(test)]
    result_canonical_bytes: Vec<u8>,
}

/// Private-field authority for one application-authenticated candidate or
/// fallback result. The wrapped inert B2-G kernel is deliberately not exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedPocoCandidateSelectionV0 {
    checkpoint: AuthorizedPocoCheckpointExecutionV0,
    computation: AuthenticatedPocoCandidateComputationV0,
    authorization_id: [u8; 32],
}

impl AuthenticatedPocoCandidateSelectionV0 {
    pub(crate) const fn checkpoint_execution(&self) -> AuthorizedPocoCheckpointExecutionV0 {
        self.checkpoint
    }

    pub(crate) const fn old_validator_set(&self) -> &ValidatorSet {
        &self.computation.old_validator_set
    }

    pub(crate) const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.computation.old_parameters
    }

    pub(crate) const fn fallback_used(&self) -> bool {
        self.computation.kernel.fallback_used()
    }

    pub(crate) const fn fallback_reason(&self) -> EpochFallbackReasonV0 {
        self.computation.kernel.fallback_reason()
    }

    pub(crate) const fn effective_validator_set(&self) -> &ValidatorSet {
        self.computation.kernel.effective_validator_set()
    }

    pub(crate) const fn effective_parameters(&self) -> &ConsensusParametersV0 {
        self.computation.kernel.effective_parameters()
    }

    pub(crate) const fn candidate_parameters_hash(&self) -> ConsensusParametersHash {
        self.computation.candidate_parameters_hash
    }

    pub(crate) const fn transcript_digest(&self) -> [u8; 32] {
        self.computation.transcript_digest
    }

    pub(crate) const fn result_digest(&self) -> [u8; 32] {
        self.computation.result_digest
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }

    #[cfg(test)]
    pub(crate) fn transcript_canonical_bytes(&self) -> &[u8] {
        &self.computation.transcript_canonical_bytes
    }

    #[cfg(test)]
    pub(crate) fn result_canonical_bytes(&self) -> &[u8] {
        &self.computation.result_canonical_bytes
    }

    #[cfg(test)]
    pub(crate) fn computed_candidate_ids(&self) -> Vec<ValidatorId> {
        self.computation
            .kernel
            .computed_candidates()
            .iter()
            .map(|candidate| candidate.validator_id())
            .collect()
    }
}

/// Cutoff-only candidate/fallback authority for the pre-header path. It has
/// no checkpoint execution field and therefore cannot smuggle a block hash,
/// timestamp, body root, receipt root, or post-execution state into the
/// candidate transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedPocoCutoffCandidateSelectionV0 {
    cutoff: AuthorizedPocoScheduledCutoffV0,
    computation: AuthenticatedPocoCandidateComputationV0,
    authorization_id: [u8; 32],
}

impl AuthenticatedPocoCutoffCandidateSelectionV0 {
    pub(crate) const fn scheduled_cutoff(&self) -> &AuthorizedPocoScheduledCutoffV0 {
        &self.cutoff
    }

    pub(crate) const fn old_validator_set(&self) -> &ValidatorSet {
        &self.computation.old_validator_set
    }

    pub(crate) const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.computation.old_parameters
    }

    pub(crate) const fn fallback_used(&self) -> bool {
        self.computation.kernel.fallback_used()
    }

    pub(crate) const fn fallback_reason(&self) -> EpochFallbackReasonV0 {
        self.computation.kernel.fallback_reason()
    }

    pub(crate) const fn effective_validator_set(&self) -> &ValidatorSet {
        self.computation.kernel.effective_validator_set()
    }

    pub(crate) const fn effective_parameters(&self) -> &ConsensusParametersV0 {
        self.computation.kernel.effective_parameters()
    }

    pub(crate) const fn candidate_parameters_hash(&self) -> ConsensusParametersHash {
        self.computation.candidate_parameters_hash
    }

    pub(crate) const fn transcript_digest(&self) -> [u8; 32] {
        self.computation.transcript_digest
    }

    pub(crate) const fn result_digest(&self) -> [u8; 32] {
        self.computation.result_digest
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }

    #[cfg(test)]
    pub(crate) fn transcript_canonical_bytes(&self) -> &[u8] {
        &self.computation.transcript_canonical_bytes
    }

    #[cfg(test)]
    pub(crate) fn result_canonical_bytes(&self) -> &[u8] {
        &self.computation.result_canonical_bytes
    }

    #[cfg(test)]
    pub(crate) fn computed_candidate_ids(&self) -> Vec<ValidatorId> {
        self.computation
            .kernel
            .computed_candidates()
            .iter()
            .map(|candidate| candidate.validator_id())
            .collect()
    }
}

trait CandidateCutoffAuthorityV0 {
    fn epoch(&self) -> Epoch;
    fn cutoff_height(&self) -> Height;
    fn cutoff_state_root(&self) -> StateRoot;
    fn cutoff_entries_root(&self) -> [u8; 32];
    fn cutoff_entry_count(&self) -> u32;
    fn validator_set_id(&self) -> ValidatorSetId;
    fn consensus_parameters_hash(&self) -> ConsensusParametersHash;
}

impl CandidateCutoffAuthorityV0 for AuthorizedPocoCheckpointExecutionV0 {
    fn epoch(&self) -> Epoch {
        (*self).epoch()
    }

    fn cutoff_height(&self) -> Height {
        (*self).cutoff_height()
    }

    fn cutoff_state_root(&self) -> StateRoot {
        (*self).cutoff_state_root()
    }

    fn cutoff_entries_root(&self) -> [u8; 32] {
        (*self).cutoff_entries_root()
    }

    fn cutoff_entry_count(&self) -> u32 {
        (*self).cutoff_entry_count()
    }

    fn validator_set_id(&self) -> ValidatorSetId {
        (*self).validator_set_id()
    }

    fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        (*self).consensus_parameters_hash()
    }
}

impl CandidateCutoffAuthorityV0 for AuthorizedPocoScheduledCutoffV0 {
    fn epoch(&self) -> Epoch {
        AuthorizedPocoScheduledCutoffV0::epoch(self)
    }

    fn cutoff_height(&self) -> Height {
        AuthorizedPocoScheduledCutoffV0::cutoff_height(self)
    }

    fn cutoff_state_root(&self) -> StateRoot {
        AuthorizedPocoScheduledCutoffV0::cutoff_state_root(self)
    }

    fn cutoff_entries_root(&self) -> [u8; 32] {
        AuthorizedPocoScheduledCutoffV0::cutoff_entries_root(self)
    }

    fn cutoff_entry_count(&self) -> u32 {
        AuthorizedPocoScheduledCutoffV0::cutoff_entry_count(self)
    }

    fn validator_set_id(&self) -> ValidatorSetId {
        self.old_validator_set().id()
    }

    fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.old_parameters().hash()
    }
}

/// Reconstructs and authorizes B2-G from the exact historical cutoff already
/// bound into `checkpoint`. This remains crate-private so the only production
/// call site can be the checkpoint one-call join.
pub(crate) fn authorize_authenticated_poco_candidate_selection_v0(
    checkpoint: AuthorizedPocoCheckpointExecutionV0,
    cutoff: &AuthenticatedPocoProjectionAtV0,
) -> Result<AuthenticatedPocoCandidateSelectionV0> {
    let computation = compute_authenticated_poco_candidate_selection_v0(&checkpoint, cutoff)?;
    let checkpoint_bytes = checkpoint.canonical_bytes();
    let authorization_id = hash_domain(
        AUTHORIZATION_DOMAIN_V0,
        &[
            &checkpoint_bytes,
            &computation.transcript_digest,
            computation.candidate_parameters_hash.as_bytes(),
            &computation.result_digest,
        ],
    );
    Ok(AuthenticatedPocoCandidateSelectionV0 {
        checkpoint,
        computation,
        authorization_id,
    })
}

/// Reconstructs and authorizes the same B2-G candidate/fallback result from a
/// scheduled cutoff authority before any checkpoint block exists.
pub(crate) fn authorize_authenticated_poco_cutoff_candidate_selection_v0(
    cutoff_authority: AuthorizedPocoScheduledCutoffV0,
    cutoff: &AuthenticatedPocoProjectionAtV0,
) -> Result<AuthenticatedPocoCutoffCandidateSelectionV0> {
    let computation = compute_authenticated_poco_candidate_selection_v0(&cutoff_authority, cutoff)?;
    let cutoff_authorization_id = cutoff_authority.authorization_id();
    let authorization_id = hash_domain(
        CUTOFF_AUTHORIZATION_DOMAIN_V0,
        &[
            &cutoff_authorization_id,
            &computation.transcript_digest,
            computation.candidate_parameters_hash.as_bytes(),
            &computation.result_digest,
        ],
    );
    Ok(AuthenticatedPocoCutoffCandidateSelectionV0 {
        cutoff: cutoff_authority,
        computation,
        authorization_id,
    })
}

fn compute_authenticated_poco_candidate_selection_v0(
    cutoff_authority: &impl CandidateCutoffAuthorityV0,
    cutoff: &AuthenticatedPocoProjectionAtV0,
) -> Result<AuthenticatedPocoCandidateComputationV0> {
    let projection = cutoff.projection();
    let manifest = projection.manifest();
    ensure!(
        cutoff_authority.cutoff_height().get() == cutoff.version()
            && cutoff_authority.cutoff_height() == manifest.cutoff_height()
            && cutoff_authority.cutoff_state_root().as_bytes() == &cutoff.state_root()
            && cutoff_authority.cutoff_entries_root() == manifest.entries_root()
            && cutoff_authority.cutoff_entry_count() == manifest.entry_count(),
        "candidate and projection cutoff authority differ"
    );

    // This performs the complete physical/bidirectional application audit.
    // Legacy projections without kind 16 are accepted by the restore audit,
    // so the candidate join additionally requires the exact authority below.
    validate_application_authority_projection_v0(projection)?;
    let entries = projection
        .entries()
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry.value.clone()))
        .collect::<BTreeMap<_, _>>();
    let authority_key = poco_application_authority_logical_key_v0().to_vec();
    let authority_value = entries
        .get(&(
            PocoSnapshotEntryKindV0::ApplicationAuthorityState,
            authority_key.clone(),
        ))
        .context("authenticated candidate cutoff lacks kind-16 authority")?;
    let authority_parts = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        &authority_key,
        authority_value,
    )?;
    let authority = PocoApplicationAuthorityStateV0::decode_exact(&authority_parts.payload)?;
    ensure!(
        authority_parts.revision == authority.revision(),
        "candidate authority envelope/state revision mismatch"
    );

    let active = active_projection_context_v0(&entries)?;
    ensure!(
        cutoff_authority.epoch() == active.validator_set.epoch()
            && cutoff_authority.validator_set_id() == active.validator_set.id()
            && cutoff_authority.consensus_parameters_hash() == active.parameters.hash(),
        "candidate cutoff consensus configuration differs from authenticated projection"
    );
    let target_epoch = active
        .validator_set
        .epoch()
        .checked_next()
        .map_err(|error| anyhow::anyhow!("candidate target epoch: {error:?}"))?;
    let candidate_parameters =
        candidate_parameters_v0(&authority, &entries, target_epoch, active.parameters)?;

    let (bonds, jails) = bond_and_jail_facts_v0(projection)?;
    let coverage_end = target_epoch
        .get()
        .checked_add(candidate_parameters.evidence_window_epochs())
        .context("candidate bond evidence-window epoch overflow")?;
    let mut candidates = BTreeMap::new();

    // Old-set membership alone is not registration authority. Only an exact,
    // active, non-revoked kind-9/kind-16 pair matching the old key may use the
    // canonical proof-free carry path.
    for history in &authority.validator_registration_history {
        if history.revoked_at_height.is_some() {
            continue;
        }
        let validator_id =
            ValidatorId::from_bytes(&exact_opaque_hex(&history.validator_id_hex)?)
                .map_err(|error| anyhow::anyhow!("invalid candidate validator ID: {error:?}"))?;
        let Some(old) = active.validator_set.validator(validator_id) else {
            continue;
        };
        let registered_key = ConsensusPublicKey::new(exact_hash32_hex(&history.consensus_key_hex)?);
        if old.consensus_key() != registered_key {
            continue;
        }
        candidates.insert(
            validator_id,
            candidate_fact_v0(
                validator_id,
                registered_key,
                None,
                None,
                coverage_end,
                target_epoch,
                &bonds,
                &jails,
            ),
        );
    }

    // A future record either replaces one old ID with a strictly proven key
    // or introduces one new ID. Full projection validation already proved the
    // target scope, predecessor facts, uniqueness, and StrictEd25519 PoP.
    for record in &authority.future_candidate_registrations {
        let validator_id = ValidatorId::from_bytes(&exact_opaque_hex(&record.validator_id_hex)?)
            .map_err(|error| anyhow::anyhow!("invalid future candidate ID: {error:?}"))?;
        let proof_bytes = exact_hex(
            &record.proof_cev0_hex,
            1,
            MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
            "future candidate proof",
        )?;
        let proof = decode_validator_key_proof_of_possession_v0_exact(&proof_bytes)
            .map_err(|error| anyhow::anyhow!("decode future candidate PoP: {error:?}"))?;
        let consensus_key = proof.fields().public_key;
        candidates.insert(
            validator_id,
            candidate_fact_v0(
                validator_id,
                consensus_key,
                record.previous_registration_nonce,
                Some(proof),
                coverage_end,
                target_epoch,
                &bonds,
                &jails,
            ),
        );
    }

    let candidate_ids = candidates.keys().copied().collect::<BTreeSet<_>>();
    let contributions = authority
        .active_certificates
        .iter()
        .map(|certificate| contribution_fact_v0(&authority, &candidate_ids, certificate))
        .collect::<Result<Vec<_>>>()?;
    let transcript = UnauthenticatedCandidateSelectionTranscriptV0 {
        snapshot_epoch: active.validator_set.epoch(),
        snapshot_height: cutoff_authority.cutoff_height(),
        committed_snapshot_cutoff: cutoff_authority.cutoff_height(),
        candidates: candidates.into_values().collect(),
        contributions,
    };
    let transcript_bytes = canonical_transcript_bytes_v0(&transcript)?;
    let transcript_digest = hash_domain(TRANSCRIPT_DOMAIN_V0, &[&transcript_bytes]);
    let kernel = compute_candidate_selection_kernel_v0(
        &transcript,
        &active.validator_set,
        &active.parameters,
        &candidate_parameters,
        &StrictEd25519Verifier,
    )
    .map_err(|error| anyhow::anyhow!("authenticated candidate selection failed: {error:?}"))?;
    let result_bytes = canonical_result_bytes_v0(&kernel)?;
    let result_digest = hash_domain(RESULT_DOMAIN_V0, &[&result_bytes]);
    let candidate_parameters_hash = candidate_parameters.hash();

    Ok(AuthenticatedPocoCandidateComputationV0 {
        old_validator_set: active.validator_set,
        old_parameters: active.parameters,
        kernel,
        candidate_parameters_hash,
        transcript_digest,
        result_digest,
        #[cfg(test)]
        transcript_canonical_bytes: transcript_bytes,
        #[cfg(test)]
        result_canonical_bytes: result_bytes,
    })
}

fn candidate_parameters_v0(
    authority: &PocoApplicationAuthorityStateV0,
    entries: &BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
    target_epoch: Epoch,
    active_parameters: ConsensusParametersV0,
) -> Result<ConsensusParametersV0> {
    match authority
        .finalized_governance_approvals
        .binary_search_by_key(&target_epoch.get(), |approval| approval.target_epoch)
    {
        Ok(index) => {
            let approval = &authority.finalized_governance_approvals[index];
            let parameters = validate_governance_parameters_companion_v0(
                entries,
                approval.target_epoch,
                &approval.parameters_hash_hex,
            )?;
            ensure!(
                u8::from(parameters.rollout_phase()) == approval.phase,
                "approved candidate phase differs from exact parameters"
            );
            Ok(parameters)
        }
        Err(_) => Ok(active_parameters),
    }
}

type BondFactsV0 = BTreeMap<ValidatorId, (u128, u64, BondStateV0)>;
type JailFactsV0 = BTreeMap<ValidatorId, u64>;

fn bond_and_jail_facts_v0(
    projection: &ProductionPocoProjectionV0,
) -> Result<(BondFactsV0, JailFactsV0)> {
    let mut bonds = BTreeMap::new();
    let mut jails = BTreeMap::new();
    for entry in projection.entries() {
        if !matches!(
            entry.kind,
            PocoSnapshotEntryKindV0::ActiveBond | PocoSnapshotEntryKindV0::JailStatus
        ) {
            continue;
        }
        let parts = owned_semantic_parts(entry.kind, &entry.logical_key, &entry.value)?;
        let validator_id = ValidatorId::from_bytes(&parts.identity)
            .map_err(|error| anyhow::anyhow!("invalid bond/jail validator ID: {error:?}"))?;
        match parts.fact {
            SemanticFactV0::ActiveBond {
                amount,
                locked_until,
                state,
            } => ensure!(
                bonds
                    .insert(validator_id, (amount, locked_until, state))
                    .is_none(),
                "duplicate bond authority for validator"
            ),
            SemanticFactV0::JailStatus { jailed_until, .. } => ensure!(
                jails.insert(validator_id, jailed_until).is_none(),
                "duplicate jail authority for validator"
            ),
            _ => bail!("bond/jail entry decoded to wrong semantic fact"),
        }
    }
    Ok((bonds, jails))
}

#[allow(clippy::too_many_arguments)]
fn candidate_fact_v0(
    validator_id: ValidatorId,
    consensus_key: ConsensusPublicKey,
    previous_registration_nonce: Option<u64>,
    proof_of_possession: Option<trnm_consensus_types::ValidatorKeyProofOfPossessionV0>,
    coverage_end: u64,
    target_epoch: Epoch,
    bonds: &BondFactsV0,
    jails: &JailFactsV0,
) -> UnauthenticatedSnapshotCandidateV0 {
    let active_slashable_bond = bonds
        .get(&validator_id)
        .filter(|(_, locked_until, state)| {
            *state == BondStateV0::ActiveSlashable && coverage_end < *locked_until
        })
        .map_or(0, |(amount, _, _)| *amount);
    let jailed = jails
        .get(&validator_id)
        .is_some_and(|jailed_until| target_epoch.get() < *jailed_until);
    UnauthenticatedSnapshotCandidateV0 {
        validator_id,
        consensus_key,
        active_slashable_bond,
        jailed,
        registration_valid: true,
        previous_registration_nonce,
        proof_of_possession,
    }
}

fn contribution_fact_v0(
    authority: &PocoApplicationAuthorityStateV0,
    candidate_ids: &BTreeSet<ValidatorId>,
    certificate: &ActiveCertificateAuthorityV0,
) -> Result<UnauthenticatedSnapshotContributionV0> {
    let pending = authority
        .pending_challenges
        .iter()
        .any(|challenge| challenge.certificate_id_hex == certificate.certificate_id_hex);
    let relationship = RelationshipClassV0::try_from(certificate.relationship_class)?;
    let provider_validator_id =
        ValidatorId::from_bytes(&exact_opaque_hex(&certificate.provider_id_hex)?)
            .map_err(|error| anyhow::anyhow!("invalid contribution provider ID: {error:?}"))?;
    // A retained certificate from a valid compute provider remains valid
    // authenticated history even when that provider has no candidate
    // registration at this cutoff. Such history contributes zero; it must not
    // be projected as an eligible B2-G fact, because B2-G deliberately treats
    // an eligible contribution for an absent candidate as malformed input.
    let eligible = candidate_ids.contains(&provider_validator_id)
        && relationship == RelationshipClassV0::Independent
        && match certificate.lifecycle {
            CertificateAuthorityLifecycleV0::Accepted => !pending,
            CertificateAuthorityLifecycleV0::ChallengeRejected => true,
            CertificateAuthorityLifecycleV0::ChallengeSustained => false,
        };
    Ok(UnauthenticatedSnapshotContributionV0 {
        certificate_id: CertificateId::new(exact_hash32_hex(&certificate.certificate_id_hex)?),
        provider_validator_id,
        task_id: exact_opaque_hex(&certificate.task_id_hex)?,
        consumer_id: exact_opaque_hex(&certificate.consumer_id_hex)?,
        finalized_epoch: Epoch::new(certificate.finalized_epoch),
        consumed_units: certificate.consumed_units.get()?,
        eligible,
    })
}

fn canonical_transcript_bytes_v0(
    transcript: &UnauthenticatedCandidateSelectionTranscriptV0,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    output.extend_from_slice(&transcript.snapshot_epoch.get().to_be_bytes());
    output.extend_from_slice(&transcript.snapshot_height.get().to_be_bytes());
    output.extend_from_slice(&transcript.committed_snapshot_cutoff.get().to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(transcript.candidates.len())
            .context("candidate transcript count exceeds u32")?
            .to_be_bytes(),
    );
    for candidate in &transcript.candidates {
        encode_bytes(&mut output, candidate.validator_id.as_bytes());
        output.extend_from_slice(candidate.consensus_key.as_bytes());
        output.extend_from_slice(&candidate.active_slashable_bond.to_be_bytes());
        output.push(u8::from(candidate.jailed));
        output.push(u8::from(candidate.registration_valid));
        match candidate.previous_registration_nonce {
            Some(nonce) => {
                output.push(1);
                output.extend_from_slice(&nonce.to_be_bytes());
            }
            None => output.push(0),
        }
        match candidate.proof_of_possession {
            Some(proof) => {
                output.push(1);
                let proof_bytes = proof
                    .try_cev0_bytes()
                    .map_err(|error| anyhow::anyhow!("encode candidate PoP: {error:?}"))?;
                encode_bytes(&mut output, &proof_bytes);
            }
            None => output.push(0),
        }
    }
    output.extend_from_slice(
        &u32::try_from(transcript.contributions.len())
            .context("contribution transcript count exceeds u32")?
            .to_be_bytes(),
    );
    for contribution in &transcript.contributions {
        output.extend_from_slice(contribution.certificate_id.as_bytes());
        encode_bytes(&mut output, contribution.provider_validator_id.as_bytes());
        encode_bytes(&mut output, &contribution.task_id);
        encode_bytes(&mut output, &contribution.consumer_id);
        output.extend_from_slice(&contribution.finalized_epoch.get().to_be_bytes());
        output.extend_from_slice(&contribution.consumed_units.to_be_bytes());
        output.push(u8::from(contribution.eligible));
    }
    Ok(output)
}

fn canonical_result_bytes_v0(kernel: &CandidateSelectionKernelV0) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    output.extend_from_slice(&kernel.snapshot_epoch().get().to_be_bytes());
    output.extend_from_slice(&kernel.target_epoch().get().to_be_bytes());
    output.push(u8::from(kernel.fallback_used()));
    output.extend_from_slice(&u16::from(kernel.fallback_reason()).to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(kernel.computed_candidates().len())
            .context("computed candidate count exceeds u32")?
            .to_be_bytes(),
    );
    for candidate in kernel.computed_candidates() {
        encode_bytes(&mut output, candidate.validator_id().as_bytes());
        output.extend_from_slice(candidate.consensus_key().as_bytes());
        output.extend_from_slice(&candidate.decayed_units().to_be_bytes());
        output.extend_from_slice(&candidate.poco_capacity().to_be_bytes());
        output.extend_from_slice(&candidate.bond_capacity().to_be_bytes());
        output.extend_from_slice(&candidate.raw_power().to_be_bytes());
        output.push(u8::from(candidate.selected()));
        match candidate.rollout_weight() {
            Some(weight) => {
                output.push(1);
                output.extend_from_slice(&weight.to_be_bytes());
            }
            None => output.push(0),
        }
        output.extend_from_slice(&candidate.consumer_cap_hits().to_be_bytes());
        output.extend_from_slice(&candidate.task_cap_hits().to_be_bytes());
        output.push(u8::from(candidate.provider_cap_hit()));
    }
    match kernel.computed_candidate_validator_set() {
        Some(set) => {
            output.push(1);
            let set_bytes = set
                .try_cev0_bytes()
                .map_err(|error| anyhow::anyhow!("encode computed candidate set: {error:?}"))?;
            encode_bytes(&mut output, &set_bytes);
        }
        None => output.push(0),
    }
    let effective_set = kernel
        .effective_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode effective candidate set: {error:?}"))?;
    encode_bytes(&mut output, &effective_set);
    encode_bytes(
        &mut output,
        &kernel.effective_parameters().canonical_bytes(),
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_id() -> ValidatorId {
        ValidatorId::from_bytes(b"validator-a").unwrap()
    }

    fn certificate(
        relationship: RelationshipClassV0,
        lifecycle: CertificateAuthorityLifecycleV0,
    ) -> ActiveCertificateAuthorityV0 {
        ActiveCertificateAuthorityV0 {
            certificate_id_hex: "01".repeat(32),
            consumer_id_hex: hex::encode(b"consumer-a"),
            consumer_key_id_hex: hex::encode(b"consumer-key-a"),
            provider_id_hex: hex::encode(b"validator-a"),
            task_id_hex: hex::encode(b"task-a"),
            meter_id_hex: hex::encode(b"meter-a"),
            meter_version: 1,
            settlement_commitment_hex: "02".repeat(32),
            settlement_finalized_height: 1,
            consumed_units: CanonicalU128V0::new(7),
            evidence_root_hex: None,
            relationship_class: relationship as u8,
            relationship_key_hex: "03".repeat(32),
            provider_consensus_key_hex: "04".repeat(32),
            provider_registration_nonce: 1,
            provider_proof_digest_hex: "05".repeat(32),
            provider_registration_decision_id_hex: "06".repeat(32),
            provider_registration_height: 1,
            provider_registration_history_head_hex: "07".repeat(32),
            acceptance_decision_id_hex: "08".repeat(32),
            funding_decision_id_hex: "09".repeat(32),
            meter_decision_id_hex: "0a".repeat(32),
            evidence_decision_id_hex: "0b".repeat(32),
            accepted_height: 1,
            finalized_epoch: 0,
            tuple_key_hex: "0c".repeat(32),
            prunable_after_height: 2,
            lifecycle,
            lifecycle_effective_height: 1,
            lifecycle_decision_id_hex: "08".repeat(32),
            semantic_keys: Vec::new(),
        }
    }

    #[test]
    fn bond_and_jail_projection_boundaries_are_conservative_and_exact() {
        let id = validator_id();
        let key = ConsensusPublicKey::new([7; 32]);
        let mut bonds = BTreeMap::new();
        let mut jails = BTreeMap::new();
        bonds.insert(id, (99, 40, BondStateV0::ActiveSlashable));
        jails.insert(id, 11);
        let eligible = candidate_fact_v0(id, key, None, None, 39, Epoch::new(10), &bonds, &jails);
        assert_eq!(eligible.active_slashable_bond, 99);
        assert!(eligible.jailed);

        // `locked_until` and `jailed_until` are exclusive: equality is
        // already unlocked/unjailed.
        bonds.insert(id, (99, 39, BondStateV0::ActiveSlashable));
        jails.insert(id, 10);
        let boundary = candidate_fact_v0(id, key, None, None, 39, Epoch::new(10), &bonds, &jails);
        assert_eq!(boundary.active_slashable_bond, 0);
        assert!(!boundary.jailed);

        bonds.insert(id, (99, 100, BondStateV0::Unbonding));
        let unbonding = candidate_fact_v0(id, key, None, None, 39, Epoch::new(10), &bonds, &jails);
        assert_eq!(unbonding.active_slashable_bond, 0);
    }

    #[test]
    fn contribution_eligibility_admits_only_independent_resolved_authority() {
        let mut authority = PocoApplicationAuthorityStateV0::empty();
        let candidate_ids = BTreeSet::from([validator_id()]);
        let accepted = certificate(
            RelationshipClassV0::Independent,
            CertificateAuthorityLifecycleV0::Accepted,
        );
        assert!(
            contribution_fact_v0(&authority, &candidate_ids, &accepted)
                .unwrap()
                .eligible
        );

        authority
            .pending_challenges
            .push(PendingChallengeAuthorityV0 {
                challenge_id_hex: "0d".repeat(32),
                certificate_id_hex: accepted.certificate_id_hex.clone(),
                opening_decision_id_hex: "0e".repeat(32),
                opened_height: 2,
            });
        assert!(
            !contribution_fact_v0(&authority, &candidate_ids, &accepted)
                .unwrap()
                .eligible
        );
        authority.pending_challenges.clear();

        let rejected = certificate(
            RelationshipClassV0::Independent,
            CertificateAuthorityLifecycleV0::ChallengeRejected,
        );
        assert!(
            contribution_fact_v0(&authority, &candidate_ids, &rejected)
                .unwrap()
                .eligible
        );
        for relationship in [
            RelationshipClassV0::Related,
            RelationshipClassV0::Reciprocal,
            RelationshipClassV0::Unresolved,
        ] {
            assert!(
                !contribution_fact_v0(
                    &authority,
                    &candidate_ids,
                    &certificate(relationship, CertificateAuthorityLifecycleV0::Accepted),
                )
                .unwrap()
                .eligible
            );
        }
        let sustained = certificate(
            RelationshipClassV0::Independent,
            CertificateAuthorityLifecycleV0::ChallengeSustained,
        );
        assert!(
            !contribution_fact_v0(&authority, &candidate_ids, &sustained)
                .unwrap()
                .eligible
        );

        // A valid retained certificate for a compute provider that is not in
        // the cutoff candidate universe contributes zero instead of poisoning
        // the entire authenticated selection as malformed B2-G input.
        assert!(
            !contribution_fact_v0(&authority, &BTreeSet::new(), &accepted)
                .unwrap()
                .eligible
        );
    }

    #[test]
    fn no_governance_approval_carries_exact_active_parameters() {
        let authority = PocoApplicationAuthorityStateV0::empty();
        let active = ConsensusParametersV0::reference_shadow_v0();
        assert_eq!(
            candidate_parameters_v0(&authority, &BTreeMap::new(), Epoch::new(1), active).unwrap(),
            active
        );
    }

    #[test]
    fn transcript_seal_binds_candidate_bond_and_predecessor_presence() {
        let id = validator_id();
        let mut transcript = UnauthenticatedCandidateSelectionTranscriptV0 {
            snapshot_epoch: Epoch::new(0),
            snapshot_height: Height::new(9_900),
            committed_snapshot_cutoff: Height::new(9_900),
            candidates: vec![UnauthenticatedSnapshotCandidateV0 {
                validator_id: id,
                consensus_key: ConsensusPublicKey::new([7; 32]),
                active_slashable_bond: 10,
                jailed: false,
                registration_valid: true,
                previous_registration_nonce: None,
                proof_of_possession: None,
            }],
            contributions: Vec::new(),
        };
        let base = canonical_transcript_bytes_v0(&transcript).unwrap();
        transcript.candidates[0].active_slashable_bond = 11;
        assert_ne!(base, canonical_transcript_bytes_v0(&transcript).unwrap());
        transcript.candidates[0].active_slashable_bond = 10;
        transcript.candidates[0].previous_registration_nonce = Some(0);
        assert_ne!(base, canonical_transcript_bytes_v0(&transcript).unwrap());
    }
}
