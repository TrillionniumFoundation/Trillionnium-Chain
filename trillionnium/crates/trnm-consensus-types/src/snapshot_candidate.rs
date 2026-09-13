use crate::{
    canonical::{signing_root, try_canonical_bytes, Encoder, DOMAIN_VALIDATOR_KEY_POP},
    CanonicalSignable, CertificateId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    EpochFallbackReasonV0, GenesisHash, Height, ProtocolVersion, Result, RolloutPhase, Signature64,
    SignatureVerifier, SigningRoot, ValidationError, Validator, ValidatorId, ValidatorSet,
    VotingPower, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATORS, MAX_VALIDATOR_ID_BYTES,
    SCHEMA_VERSION_V0,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

/// Fixed bound for the caller-supplied task and consumer relationship IDs
/// accepted by the B2-G calculation kernel.
///
/// These IDs are not wire-authoritative protocol strings, but bounding them
/// keeps the local normalized-input surface fail-closed and prevents the
/// calculation from cloning or indexing arbitrarily large relationship keys.
pub const MAX_SNAPSHOT_RELATION_ID_BYTES: usize = 128;

/// Maximum number of caller-supplied candidate facts accepted before the
/// B2-G kernel allocates or sorts. This is the global v0 validator hard cap,
/// not an assertion that every supplied candidate becomes active.
pub const MAX_SNAPSHOT_CANDIDATES: usize = MAX_VALIDATORS;

/// Inert-kernel admission bound for normalized contribution facts.
///
/// This is deliberately not a production Consumption Certificate throughput
/// limit. A later authenticated snapshot/provenance layer may batch or stream
/// a larger state surface before projecting at most this many facts into one
/// B2-G calculation.
pub const MAX_SNAPSHOT_CONTRIBUTIONS: usize = 10_000;

/// Exhaustive fields for the exact PoCO-BFT v0 validator-key proof of
/// possession. The first seven fields form the signing preimage; `signature`
/// is the fixed-width eighth field of the exact object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorKeyProofOfPossessionV0Fields {
    pub schema_version: u16,
    pub genesis_hash: GenesisHash,
    pub chain_id: ChainId,
    pub target_epoch: Epoch,
    pub validator_id: ValidatorId,
    pub public_key: ConsensusPublicKey,
    pub registration_nonce: u64,
    pub signature: Signature64,
}

/// Exact key-control proof for one validator registration.
///
/// This proves only possession of the supplied key for the supplied scope. It
/// does not prove that the registration, nonce, or validator identity came
/// from finalized application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorKeyProofOfPossessionV0 {
    fields: ValidatorKeyProofOfPossessionV0Fields,
}

impl ValidatorKeyProofOfPossessionV0 {
    pub fn new(fields: ValidatorKeyProofOfPossessionV0Fields) -> Result<Self> {
        if fields.schema_version != SCHEMA_VERSION_V0 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: fields.schema_version,
                expected: SCHEMA_VERSION_V0,
            });
        }
        if fields.genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if fields.public_key.is_zero() {
            return Err(ValidationError::ZeroConsensusPublicKey);
        }
        fields.signature.validate_shape()?;
        Ok(Self { fields })
    }

    pub const fn fields(&self) -> ValidatorKeyProofOfPossessionV0Fields {
        self.fields
    }

    pub fn try_signing_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_signing_preimage(encoder))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            self.encode_signing_preimage(encoder);
            encoder.fixed(self.fields.signature.as_bytes());
        })
    }

    pub fn signing_root(&self) -> SigningRoot {
        signing_root(DOMAIN_VALIDATOR_KEY_POP, |encoder| {
            self.encode_signing_preimage(encoder);
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_registration<V: SignatureVerifier>(
        &self,
        expected_genesis_hash: GenesisHash,
        expected_chain_id: ChainId,
        expected_target_epoch: Epoch,
        expected_validator_id: ValidatorId,
        expected_public_key: ConsensusPublicKey,
        verifier: &V,
    ) -> Result<()> {
        let fields = self.fields;
        if fields.genesis_hash != expected_genesis_hash {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if fields.chain_id != expected_chain_id {
            return Err(ValidationError::ChainIdMismatch);
        }
        if fields.target_epoch != expected_target_epoch {
            return Err(ValidationError::EpochMismatch);
        }
        if fields.validator_id != expected_validator_id {
            return Err(ValidationError::UnknownValidator(Box::new(
                fields.validator_id,
            )));
        }
        if fields.public_key != expected_public_key {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        let validator =
            Validator::new(fields.validator_id, fields.public_key, VotingPower::new(1)?)?;
        if !verifier.verify(&validator, &self.signing_root(), &fields.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(
                fields.validator_id,
            )));
        }
        Ok(())
    }

    fn encode_signing_preimage(&self, encoder: &mut Encoder) {
        let fields = self.fields;
        encoder.u16(fields.schema_version);
        encoder.fixed(fields.genesis_hash.as_bytes());
        encoder.consensus_string(fields.chain_id.as_bytes());
        encoder.u64(fields.target_epoch.get());
        encoder.bytes(fields.validator_id.as_bytes());
        encoder.fixed(fields.public_key.as_bytes());
        encoder.u64(fields.registration_nonce);
    }
}

impl CanonicalSignable for ValidatorKeyProofOfPossessionV0 {
    fn signing_root(&self) -> SigningRoot {
        ValidatorKeyProofOfPossessionV0::signing_root(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidatorKeyProofDecodeErrorCode {
    UnexpectedEnd,
    TrailingBytes,
    InvalidSchemaVersion,
    ZeroGenesisHash,
    InvalidChainId,
    EmptyValidatorId,
    ValidatorIdTooLong,
    ZeroPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorKeyProofDecodeError {
    code: ValidatorKeyProofDecodeErrorCode,
    byte_offset: usize,
}

impl ValidatorKeyProofDecodeError {
    pub const fn code(self) -> ValidatorKeyProofDecodeErrorCode {
        self.code
    }

    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }
}

/// Bounded exact decoder for the complete eight-field PoP object.
pub fn decode_validator_key_proof_of_possession_v0_exact(
    bytes: &[u8],
) -> core::result::Result<ValidatorKeyProofOfPossessionV0, ValidatorKeyProofDecodeError> {
    let mut cursor = ProofCursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    if schema_version != SCHEMA_VERSION_V0 {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed::<32>()?);
    if genesis_hash.is_zero() {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::ZeroGenesisHash,
            genesis_offset,
        ));
    }
    let chain_offset = cursor.offset();
    let chain_length = usize::from(cursor.u16()?);
    if chain_length == 0 || chain_length > MAX_CONSENSUS_STRING_BYTES {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::InvalidChainId,
            chain_offset,
        ));
    }
    let chain_bytes = cursor.take(chain_length)?;
    let chain_id = ChainId::from_bytes(chain_bytes).map_err(|_| {
        decode_error(
            ValidatorKeyProofDecodeErrorCode::InvalidChainId,
            chain_offset,
        )
    })?;
    let target_epoch = Epoch::new(cursor.u64()?);
    let validator_offset = cursor.offset();
    let validator_length = usize::try_from(cursor.u32()?).map_err(|_| {
        decode_error(
            ValidatorKeyProofDecodeErrorCode::ValidatorIdTooLong,
            validator_offset,
        )
    })?;
    if validator_length == 0 {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::EmptyValidatorId,
            validator_offset,
        ));
    }
    if validator_length > MAX_VALIDATOR_ID_BYTES {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::ValidatorIdTooLong,
            validator_offset,
        ));
    }
    let validator_id = ValidatorId::from_bytes(cursor.take(validator_length)?).map_err(|_| {
        decode_error(
            ValidatorKeyProofDecodeErrorCode::ValidatorIdTooLong,
            validator_offset,
        )
    })?;
    let public_key_offset = cursor.offset();
    let public_key = ConsensusPublicKey::new(cursor.fixed::<32>()?);
    if public_key.is_zero() {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::ZeroPublicKey,
            public_key_offset,
        ));
    }
    let registration_nonce = cursor.u64()?;
    let signature = Signature64::from_array(cursor.fixed::<64>()?);
    if !cursor.is_finished() {
        return Err(decode_error(
            ValidatorKeyProofDecodeErrorCode::TrailingBytes,
            cursor.offset(),
        ));
    }
    Ok(ValidatorKeyProofOfPossessionV0 {
        fields: ValidatorKeyProofOfPossessionV0Fields {
            schema_version,
            genesis_hash,
            chain_id,
            target_epoch,
            validator_id,
            public_key,
            registration_nonce,
            signature,
        },
    })
}

fn decode_error(
    code: ValidatorKeyProofDecodeErrorCode,
    byte_offset: usize,
) -> ValidatorKeyProofDecodeError {
    ValidatorKeyProofDecodeError { code, byte_offset }
}

struct ProofCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProofCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(
        &mut self,
        length: usize,
    ) -> core::result::Result<&'a [u8], ValidatorKeyProofDecodeError> {
        let start = self.offset;
        let end = start
            .checked_add(length)
            .ok_or_else(|| decode_error(ValidatorKeyProofDecodeErrorCode::UnexpectedEnd, start))?;
        let value = self
            .bytes
            .get(start..end)
            .ok_or_else(|| decode_error(ValidatorKeyProofDecodeErrorCode::UnexpectedEnd, start))?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(
        &mut self,
    ) -> core::result::Result<[u8; N], ValidatorKeyProofDecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| decode_error(ValidatorKeyProofDecodeErrorCode::UnexpectedEnd, self.offset))
    }

    fn u16(&mut self) -> core::result::Result<u16, ValidatorKeyProofDecodeError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> core::result::Result<u32, ValidatorKeyProofDecodeError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> core::result::Result<u64, ValidatorKeyProofDecodeError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
}

/// One normalized contribution fact supplied by an unauthenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedSnapshotContributionV0 {
    pub certificate_id: CertificateId,
    pub provider_validator_id: ValidatorId,
    pub task_id: Vec<u8>,
    pub consumer_id: Vec<u8>,
    pub finalized_epoch: Epoch,
    pub consumed_units: u128,
    pub eligible: bool,
}

/// One normalized candidate-registration fact supplied by an unauthenticated
/// caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedSnapshotCandidateV0 {
    pub validator_id: ValidatorId,
    pub consensus_key: ConsensusPublicKey,
    pub active_slashable_bond: u128,
    pub jailed: bool,
    pub registration_valid: bool,
    pub previous_registration_nonce: Option<u64>,
    pub proof_of_possession: Option<ValidatorKeyProofOfPossessionV0>,
}

/// Caller-owned normalized input to the pure B2-G calculation kernel.
///
/// None of these facts are authenticated by this type. In particular, it is
/// not a snapshot proof, a complete Consumption Certificate encoding, or a
/// runtime/checkpoint execution witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedCandidateSelectionTranscriptV0 {
    pub snapshot_epoch: Epoch,
    pub snapshot_height: Height,
    pub committed_snapshot_cutoff: Height,
    pub candidates: Vec<UnauthenticatedSnapshotCandidateV0>,
    pub contributions: Vec<UnauthenticatedSnapshotContributionV0>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateComputationV0 {
    validator_id: ValidatorId,
    consensus_key: ConsensusPublicKey,
    decayed_units: u128,
    poco_capacity: u128,
    bond_capacity: u128,
    raw_power: u64,
    selected: bool,
    rollout_weight: Option<u64>,
    consumer_cap_hits: u32,
    task_cap_hits: u32,
    provider_cap_hit: bool,
}

impl CandidateComputationV0 {
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn consensus_key(&self) -> ConsensusPublicKey {
        self.consensus_key
    }

    pub const fn decayed_units(&self) -> u128 {
        self.decayed_units
    }

    pub const fn poco_capacity(&self) -> u128 {
        self.poco_capacity
    }

    pub const fn bond_capacity(&self) -> u128 {
        self.bond_capacity
    }

    pub const fn raw_power(&self) -> u64 {
        self.raw_power
    }

    pub const fn selected(&self) -> bool {
        self.selected
    }

    pub const fn rollout_weight(&self) -> Option<u64> {
        self.rollout_weight
    }

    pub const fn consumer_cap_hits(&self) -> u32 {
        self.consumer_cap_hits
    }

    pub const fn task_cap_hits(&self) -> u32 {
        self.task_cap_hits
    }

    pub const fn provider_cap_hit(&self) -> bool {
        self.provider_cap_hit
    }
}

/// Private-field, inert evidence of one deterministic B2-G calculation.
///
/// This value cannot authorize a validator set, epoch commitment, anchor,
/// handoff, activation, or core transition. Every state/runtime fact consumed
/// by the calculation remains unauthenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSelectionKernelV0 {
    snapshot_epoch: Epoch,
    target_epoch: Epoch,
    fallback_used: bool,
    fallback_reason: EpochFallbackReasonV0,
    computed_candidates: Vec<CandidateComputationV0>,
    computed_candidate_validator_set: Option<ValidatorSet>,
    effective_validator_set: ValidatorSet,
    effective_parameters: ConsensusParametersV0,
}

impl CandidateSelectionKernelV0 {
    pub const fn snapshot_epoch(&self) -> Epoch {
        self.snapshot_epoch
    }

    pub const fn target_epoch(&self) -> Epoch {
        self.target_epoch
    }

    pub const fn fallback_used(&self) -> bool {
        self.fallback_used
    }

    pub const fn fallback_reason(&self) -> EpochFallbackReasonV0 {
        self.fallback_reason
    }

    pub fn computed_candidates(&self) -> &[CandidateComputationV0] {
        &self.computed_candidates
    }

    pub const fn computed_candidate_validator_set(&self) -> Option<&ValidatorSet> {
        self.computed_candidate_validator_set.as_ref()
    }

    pub const fn effective_validator_set(&self) -> &ValidatorSet {
        &self.effective_validator_set
    }

    pub const fn effective_parameters(&self) -> &ConsensusParametersV0 {
        &self.effective_parameters
    }
}

#[derive(Default)]
struct FailureAccumulator {
    reason: Option<EpochFallbackReasonV0>,
}

impl FailureAccumulator {
    fn record(&mut self, reason: EpochFallbackReasonV0) {
        if reason == EpochFallbackReasonV0::None {
            return;
        }
        self.reason = Some(match self.reason {
            Some(current) => core::cmp::min(current, reason),
            None => reason,
        });
    }

    const fn reason(&self) -> Option<EpochFallbackReasonV0> {
        self.reason
    }
}

#[derive(Clone)]
struct WorkingCandidate {
    validator_id: ValidatorId,
    consensus_key: ConsensusPublicKey,
    jailed: bool,
    decayed_units: u128,
    poco_capacity: u128,
    bond_capacity: u128,
    raw_power: u64,
    selected: bool,
    rollout_weight: Option<u64>,
    consumer_cap_hits: u32,
    task_cap_hits: u32,
    provider_cap_hit: bool,
}

/// Computes the same-version v0 candidate/fallback relation over explicitly
/// unauthenticated caller facts.
///
/// `Err` is reserved for an invalid old active configuration or an impossible
/// target-epoch fallback. Candidate failures instead return a successful inert
/// kernel carrying the exact old configuration and the lowest reason code.
/// The generic verifier is caller supplied and its identity is not attested by
/// the returned token; production admission must supply a strict Ed25519
/// verifier and later authority must re-run this relation over authenticated
/// inputs or bind those inputs in a separate authenticated wrapper.
pub fn compute_candidate_selection_kernel_v0<V: SignatureVerifier>(
    transcript: &UnauthenticatedCandidateSelectionTranscriptV0,
    old_validator_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
    candidate_parameters: &ConsensusParametersV0,
    verifier: &V,
) -> Result<CandidateSelectionKernelV0> {
    old_validator_set.validate_against_parameters(old_parameters)?;
    if old_validator_set.protocol_version() != ProtocolVersion::V0
        || old_parameters.protocol_version() != ProtocolVersion::V0.get()
    {
        return Err(ValidationError::InvalidEpochTransition(
            "old active configuration is not protocol v0",
        ));
    }
    candidate_parameters.validate_safety_invariants()?;
    let target_epoch = old_validator_set.epoch().checked_next()?;
    if transcript.candidates.len() > MAX_SNAPSHOT_CANDIDATES
        || transcript.contributions.len() > MAX_SNAPSHOT_CONTRIBUTIONS
        || transcript.contributions.iter().any(|contribution| {
            contribution.task_id.is_empty()
                || contribution.task_id.len() > MAX_SNAPSHOT_RELATION_ID_BYTES
                || contribution.consumer_id.is_empty()
                || contribution.consumer_id.len() > MAX_SNAPSHOT_RELATION_ID_BYTES
        })
    {
        return fallback_without_diagnostics(
            transcript.snapshot_epoch,
            target_epoch,
            EpochFallbackReasonV0::MalformedSnapshotInput,
            old_validator_set,
            old_parameters,
        );
    }
    let mut failures = FailureAccumulator::default();

    if transcript.snapshot_epoch != old_validator_set.epoch()
        || transcript.snapshot_height != transcript.committed_snapshot_cutoff
    {
        failures.record(EpochFallbackReasonV0::MalformedSnapshotInput);
    }
    if old_parameters.epoch_length_blocks() != candidate_parameters.epoch_length_blocks() {
        failures.record(EpochFallbackReasonV0::InvalidCommittedParameters);
    }
    if !candidate_parameters.production_activation()
        && candidate_parameters.rollout_phase() != RolloutPhase::Shadow
    {
        failures.record(EpochFallbackReasonV0::InvalidUpgradeOrActivation);
    }
    if old_validator_set.chain_id().as_bytes().len()
        > usize::from(candidate_parameters.max_chain_id_bytes())
    {
        failures.record(EpochFallbackReasonV0::InvalidCommittedParameters);
    }

    let mut candidates = transcript.candidates.clone();
    candidates.sort_by_key(|candidate| candidate.validator_id);
    validate_candidate_registrations(
        &candidates,
        old_validator_set,
        target_epoch,
        candidate_parameters,
        verifier,
        &mut failures,
    );

    let candidate_ids: BTreeSet<_> = candidates
        .iter()
        .map(|candidate| candidate.validator_id)
        .collect();
    let aggregates = aggregate_contributions(
        transcript,
        &candidate_ids,
        candidate_parameters,
        &mut failures,
    );
    let mut working = compute_candidate_capacities(
        &candidates,
        &aggregates,
        candidate_parameters,
        &mut failures,
    );
    select_candidates(&mut working, candidate_parameters, &mut failures);
    assign_rollout_weights(&mut working, candidate_parameters, &mut failures);

    let mut computed_candidate_validator_set =
        if candidate_parameters.rollout_phase() == RolloutPhase::Shadow {
            None
        } else {
            build_computed_candidate_set(
                &working,
                old_validator_set,
                target_epoch,
                candidate_parameters,
                &mut failures,
            )
        };

    if candidate_parameters.rollout_phase() == RolloutPhase::Shadow {
        validate_effective_validators(
            old_validator_set.validators(),
            candidate_parameters,
            &mut failures,
        );
    } else if let Some(candidate_set) = &computed_candidate_validator_set {
        validate_effective_validators(
            candidate_set.validators(),
            candidate_parameters,
            &mut failures,
        );
    }

    let fallback_reason = failures.reason().unwrap_or(EpochFallbackReasonV0::None);
    let fallback_used = fallback_reason != EpochFallbackReasonV0::None;
    let (effective_validator_set, effective_parameters) = if fallback_used {
        (
            carry_validator_set(old_validator_set, target_epoch, old_parameters)?,
            *old_parameters,
        )
    } else if candidate_parameters.rollout_phase() == RolloutPhase::Shadow {
        (
            carry_validator_set(old_validator_set, target_epoch, candidate_parameters)?,
            *candidate_parameters,
        )
    } else {
        (
            computed_candidate_validator_set.clone().ok_or(
                ValidationError::InvalidEpochTransition(
                    "valid non-shadow candidate lacks a validator set",
                ),
            )?,
            *candidate_parameters,
        )
    };

    let mut computed_candidates: Vec<_> = working
        .into_iter()
        .map(|candidate| CandidateComputationV0 {
            validator_id: candidate.validator_id,
            consensus_key: candidate.consensus_key,
            decayed_units: candidate.decayed_units,
            poco_capacity: candidate.poco_capacity,
            bond_capacity: candidate.bond_capacity,
            raw_power: candidate.raw_power,
            selected: candidate.selected,
            rollout_weight: candidate.rollout_weight,
            consumer_cap_hits: candidate.consumer_cap_hits,
            task_cap_hits: candidate.task_cap_hits,
            provider_cap_hit: candidate.provider_cap_hit,
        })
        .collect();

    // A fallback token carries only the atomic old configuration. Candidate
    // diagnostics are intentionally suppressed because they may be derived
    // from malformed, unauthenticated, or verifier-rejected inputs and are not
    // stable authority-bearing facts.
    if fallback_used {
        computed_candidates.clear();
        computed_candidate_validator_set = None;
    }

    Ok(CandidateSelectionKernelV0 {
        snapshot_epoch: transcript.snapshot_epoch,
        target_epoch,
        fallback_used,
        fallback_reason,
        computed_candidates,
        computed_candidate_validator_set,
        effective_validator_set,
        effective_parameters,
    })
}

fn fallback_without_diagnostics(
    snapshot_epoch: Epoch,
    target_epoch: Epoch,
    fallback_reason: EpochFallbackReasonV0,
    old_validator_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
) -> Result<CandidateSelectionKernelV0> {
    Ok(CandidateSelectionKernelV0 {
        snapshot_epoch,
        target_epoch,
        fallback_used: true,
        fallback_reason,
        computed_candidates: Vec::new(),
        computed_candidate_validator_set: None,
        effective_validator_set: carry_validator_set(
            old_validator_set,
            target_epoch,
            old_parameters,
        )?,
        effective_parameters: *old_parameters,
    })
}

fn validate_candidate_registrations<V: SignatureVerifier>(
    candidates: &[UnauthenticatedSnapshotCandidateV0],
    old_validator_set: &ValidatorSet,
    target_epoch: Epoch,
    parameters: &ConsensusParametersV0,
    verifier: &V,
    failures: &mut FailureAccumulator,
) {
    let mut previous_id = None;
    let mut keys = BTreeSet::new();
    for candidate in candidates {
        if candidate.consensus_key.is_zero()
            || candidate.validator_id.as_bytes().len()
                > usize::from(parameters.max_validator_id_bytes())
            || !candidate.registration_valid
        {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }
        if previous_id == Some(candidate.validator_id) {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }
        previous_id = Some(candidate.validator_id);
        if !keys.insert(candidate.consensus_key) {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }

        let old = old_validator_set.validator(candidate.validator_id);
        let unchanged =
            old.is_some_and(|validator| validator.consensus_key() == candidate.consensus_key);
        let requires_proof = !unchanged;
        if old.is_none() && candidate.previous_registration_nonce.is_some() {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }
        if old.is_some() && !unchanged && candidate.previous_registration_nonce.is_none() {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }
        if requires_proof && candidate.proof_of_possession.is_none() {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
        }
        if let Some(proof) = candidate.proof_of_possession {
            let fields = proof.fields();
            if proof
                .verify_for_registration(
                    old_validator_set.genesis_hash(),
                    old_validator_set.chain_id(),
                    target_epoch,
                    candidate.validator_id,
                    candidate.consensus_key,
                    verifier,
                )
                .is_err()
            {
                failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
            }
            if let Some(previous_nonce) = candidate.previous_registration_nonce {
                if fields.registration_nonce <= previous_nonce {
                    failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
                }
            }
        }
    }
}

type ContributionKey = (ValidatorId, Vec<u8>, Vec<u8>);

fn aggregate_contributions(
    transcript: &UnauthenticatedCandidateSelectionTranscriptV0,
    candidate_ids: &BTreeSet<ValidatorId>,
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) -> BTreeMap<ContributionKey, u128> {
    let mut contributions = transcript.contributions.clone();
    contributions.sort_by_key(|contribution| contribution.certificate_id);
    let mut previous_id = None;
    let mut aggregates = BTreeMap::new();
    for contribution in contributions {
        if contribution.certificate_id.is_zero() || previous_id == Some(contribution.certificate_id)
        {
            failures.record(EpochFallbackReasonV0::MalformedSnapshotInput);
        }
        previous_id = Some(contribution.certificate_id);
        if contribution.task_id.is_empty()
            || contribution.task_id.len() > MAX_SNAPSHOT_RELATION_ID_BYTES
            || contribution.consumer_id.is_empty()
            || contribution.consumer_id.len() > MAX_SNAPSHOT_RELATION_ID_BYTES
        {
            failures.record(EpochFallbackReasonV0::MalformedSnapshotInput);
            continue;
        }
        if !contribution.eligible {
            continue;
        }
        if contribution.consumed_units == 0
            || !candidate_ids.contains(&contribution.provider_validator_id)
            || contribution.finalized_epoch > transcript.snapshot_epoch
        {
            failures.record(EpochFallbackReasonV0::MalformedSnapshotInput);
            continue;
        }

        let snapshot_epoch = u128::from(transcript.snapshot_epoch.get());
        let maturity_epoch = u128::from(contribution.finalized_epoch.get())
            .checked_add(u128::from(parameters.maturity_epochs()));
        let Some(maturity_epoch) = maturity_epoch else {
            failures.record(EpochFallbackReasonV0::ArithmeticFailure);
            continue;
        };
        if snapshot_epoch < maturity_epoch {
            continue;
        }
        let age = snapshot_epoch - maturity_epoch;
        if age >= u128::from(parameters.max_certificate_age_epochs()) {
            continue;
        }
        let decay_product = age.checked_mul(u128::from(parameters.decay_step_ppm_per_epoch()));
        let Some(decay_product) = decay_product else {
            failures.record(EpochFallbackReasonV0::ArithmeticFailure);
            continue;
        };
        let scale = u128::from(parameters.scale_ppm());
        // This is the normative max(0, scale - product), expressed through a
        // checked operation rather than saturating arithmetic.
        #[allow(clippy::manual_saturating_arithmetic)]
        let decay = scale.checked_sub(decay_product).unwrap_or(0);
        let capped = core::cmp::min(
            contribution.consumed_units,
            parameters.per_certificate_unit_cap(),
        );
        let Some(scaled) = capped.checked_mul(decay) else {
            failures.record(EpochFallbackReasonV0::ArithmeticFailure);
            continue;
        };
        let decayed = scaled / scale;
        let key = (
            contribution.provider_validator_id,
            contribution.task_id,
            contribution.consumer_id,
        );
        let current = aggregates.get(&key).copied().unwrap_or(0u128);
        let Some(total) = current.checked_add(decayed) else {
            failures.record(EpochFallbackReasonV0::ArithmeticFailure);
            continue;
        };
        aggregates.insert(key, total);
    }
    aggregates
}

fn compute_candidate_capacities(
    candidates: &[UnauthenticatedSnapshotCandidateV0],
    aggregates: &BTreeMap<ContributionKey, u128>,
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) -> Vec<WorkingCandidate> {
    candidates
        .iter()
        .map(|candidate| {
            let (units, consumer_cap_hits, task_cap_hits, provider_cap_hit) =
                provider_units(candidate.validator_id, aggregates, parameters, failures);
            let poco_capacity = units / parameters.units_per_power();
            let bond_capacity =
                candidate.active_slashable_bond / parameters.bond_atomic_units_per_power();
            let raw = core::cmp::min(
                core::cmp::min(poco_capacity, bond_capacity),
                u128::from(parameters.max_validator_power()),
            );
            let raw_power = u64::try_from(raw).unwrap_or(parameters.max_validator_power());
            WorkingCandidate {
                validator_id: candidate.validator_id,
                consensus_key: candidate.consensus_key,
                jailed: candidate.jailed,
                decayed_units: units,
                poco_capacity,
                bond_capacity,
                raw_power,
                selected: false,
                rollout_weight: None,
                consumer_cap_hits,
                task_cap_hits,
                provider_cap_hit,
            }
        })
        .collect()
}

fn provider_units(
    provider: ValidatorId,
    aggregates: &BTreeMap<ContributionKey, u128>,
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) -> (u128, u32, u32, bool) {
    let mut task_totals: BTreeMap<Vec<u8>, u128> = BTreeMap::new();
    let mut consumer_hits = 0u32;
    for ((entry_provider, task, _consumer), value) in aggregates {
        if *entry_provider != provider {
            continue;
        }
        let capped = core::cmp::min(*value, parameters.per_consumer_provider_epoch_unit_cap());
        if *value > capped {
            consumer_hits = consumer_hits.checked_add(1).unwrap_or_else(|| {
                failures.record(EpochFallbackReasonV0::ArithmeticFailure);
                u32::MAX
            });
        }
        let current = task_totals.get(task).copied().unwrap_or(0);
        match current.checked_add(capped) {
            Some(total) => {
                task_totals.insert(task.clone(), total);
            }
            None => failures.record(EpochFallbackReasonV0::ArithmeticFailure),
        }
    }

    let mut task_hits = 0u32;
    let mut provider_total = 0u128;
    for total in task_totals.into_values() {
        let capped = core::cmp::min(total, parameters.per_task_provider_epoch_unit_cap());
        if total > capped {
            task_hits = task_hits.checked_add(1).unwrap_or_else(|| {
                failures.record(EpochFallbackReasonV0::ArithmeticFailure);
                u32::MAX
            });
        }
        match provider_total.checked_add(capped) {
            Some(total) => provider_total = total,
            None => failures.record(EpochFallbackReasonV0::ArithmeticFailure),
        }
    }
    let units = core::cmp::min(provider_total, parameters.per_provider_epoch_unit_cap());
    (units, consumer_hits, task_hits, provider_total > units)
}

fn select_candidates(
    working: &mut [WorkingCandidate],
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) {
    let mut eligible: Vec<_> = working
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            !candidate.jailed && candidate.raw_power >= parameters.min_validator_power()
        })
        .map(|(index, _)| index)
        .collect();
    eligible.sort_by(|left, right| {
        working[*right]
            .raw_power
            .cmp(&working[*left].raw_power)
            .then_with(|| {
                working[*left]
                    .validator_id
                    .cmp(&working[*right].validator_id)
            })
    });
    let maximum = usize::try_from(parameters.max_validators()).unwrap_or(usize::MAX);
    eligible.truncate(maximum);
    if eligible.len() < usize::try_from(parameters.min_validators()).unwrap_or(usize::MAX) {
        failures.record(EpochFallbackReasonV0::TooFewEligibleValidators);
    }
    for index in eligible {
        working[index].selected = true;
    }
}

fn assign_rollout_weights(
    working: &mut [WorkingCandidate],
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) {
    for candidate in working.iter_mut().filter(|candidate| candidate.selected) {
        candidate.rollout_weight = match parameters.rollout_phase() {
            RolloutPhase::Shadow => None,
            RolloutPhase::EligibilityOnly => Some(1),
            RolloutPhase::Full => Some(candidate.raw_power),
            RolloutPhase::CappedWeight => {
                let Some(adjusted) = candidate.raw_power.checked_sub(1).map(u128::from) else {
                    failures.record(EpochFallbackReasonV0::ArithmeticFailure);
                    candidate.rollout_weight = None;
                    continue;
                };
                let weighted = u128::from(parameters.capped_weight_alpha_ppm())
                    .checked_mul(adjusted)
                    .and_then(|value| value.checked_div(u128::from(parameters.scale_ppm())))
                    .and_then(|value| value.checked_add(1));
                match weighted.and_then(|value| u64::try_from(value).ok()) {
                    Some(weight) => Some(weight),
                    None => {
                        failures.record(EpochFallbackReasonV0::ArithmeticFailure);
                        None
                    }
                }
            }
        };
    }
}

fn build_computed_candidate_set(
    working: &[WorkingCandidate],
    old_validator_set: &ValidatorSet,
    target_epoch: Epoch,
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) -> Option<ValidatorSet> {
    let mut validators = Vec::new();
    for candidate in working.iter().filter(|candidate| candidate.selected) {
        let Some(weight) = candidate.rollout_weight else {
            failures.record(EpochFallbackReasonV0::ArithmeticFailure);
            return None;
        };
        let Ok(power) = VotingPower::new(weight) else {
            failures.record(EpochFallbackReasonV0::ValidatorWeightOutOfBounds);
            return None;
        };
        let Ok(validator) = Validator::new(candidate.validator_id, candidate.consensus_key, power)
        else {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
            return None;
        };
        validators.push(validator);
    }
    if validators.is_empty() {
        return None;
    }
    validators.sort_by_key(Validator::id);
    match ValidatorSet::new(
        old_validator_set.genesis_hash(),
        old_validator_set.chain_id(),
        ProtocolVersion::V0,
        target_epoch,
        parameters.hash(),
        validators,
    ) {
        Ok(set) => Some(set),
        Err(_) => {
            failures.record(EpochFallbackReasonV0::InvalidValidatorIdentityOrKey);
            None
        }
    }
}

fn validate_effective_validators(
    validators: &[Validator],
    parameters: &ConsensusParametersV0,
    failures: &mut FailureAccumulator,
) {
    let count = validators.len();
    if count < usize::try_from(parameters.min_validators()).unwrap_or(usize::MAX) {
        failures.record(EpochFallbackReasonV0::TooFewEligibleValidators);
    }
    if count > usize::try_from(parameters.max_validators()).unwrap_or(0) {
        failures.record(EpochFallbackReasonV0::InvalidCommittedParameters);
    }
    let mut total = 0u128;
    let mut maximum = 0u128;
    for validator in validators {
        if validator.id().as_bytes().len() > usize::from(parameters.max_validator_id_bytes()) {
            failures.record(EpochFallbackReasonV0::InvalidCommittedParameters);
        }
        let power = validator.voting_power().get();
        if power < parameters.min_validator_power() || power > parameters.max_validator_power() {
            failures.record(EpochFallbackReasonV0::ValidatorWeightOutOfBounds);
        }
        maximum = core::cmp::max(maximum, u128::from(power));
        match total.checked_add(u128::from(power)) {
            Some(value) => total = value,
            None => failures.record(EpochFallbackReasonV0::ArithmeticFailure),
        }
    }
    if total == 0 || total > u128::from(parameters.max_total_voting_power()) {
        failures.record(EpochFallbackReasonV0::InvalidTotalVotingPower);
    }
    let triple = maximum.checked_mul(3);
    let scaled = maximum.checked_mul(u128::from(parameters.scale_ppm()));
    let allowed = total.checked_mul(u128::from(parameters.max_validator_share_ppm()));
    match (triple, scaled, allowed) {
        (Some(triple), Some(scaled), Some(allowed)) => {
            if triple >= total || scaled > allowed {
                failures.record(EpochFallbackReasonV0::ConcentrationConstraintViolated);
            }
        }
        _ => failures.record(EpochFallbackReasonV0::ArithmeticFailure),
    }
}

fn carry_validator_set(
    old_validator_set: &ValidatorSet,
    target_epoch: Epoch,
    parameters: &ConsensusParametersV0,
) -> Result<ValidatorSet> {
    ValidatorSet::new(
        old_validator_set.genesis_hash(),
        old_validator_set.chain_id(),
        old_validator_set.protocol_version(),
        target_epoch,
        parameters.hash(),
        old_validator_set.validators().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    #[derive(Clone, Copy)]
    struct AcceptVerifier;

    impl SignatureVerifier for AcceptVerifier {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            true
        }
    }

    #[derive(Clone, Copy)]
    struct RejectVerifier;

    impl SignatureVerifier for RejectVerifier {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            false
        }
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::from_bytes(&[b'v', index]).expect("bounded fixture validator ID")
    }

    fn validator(index: u8, power: u64) -> Validator {
        Validator::new(
            validator_id(index),
            ConsensusPublicKey::new([index; 32]),
            VotingPower::new(power).expect("positive fixture power"),
        )
        .expect("shape-valid fixture validator")
    }

    fn old_set(parameters: &ConsensusParametersV0, power: u64) -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([9; 32]),
            ChainId::from_static("trnm-b2g-test"),
            ProtocolVersion::V0,
            Epoch::new(5),
            parameters.hash(),
            (1..=4).map(|index| validator(index, power)).collect(),
        )
        .expect("valid old fixture set")
    }

    fn parameters(
        phase: RolloutPhase,
        production_activation: bool,
        mutate: impl FnOnce(&mut crate::ConsensusParametersV0Fields),
    ) -> ConsensusParametersV0 {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.rollout_phase = phase;
        fields.production_activation = production_activation;
        mutate(&mut fields);
        ConsensusParametersV0::new(fields).expect("valid fixture parameters")
    }

    fn basic_transcript(set: &ValidatorSet) -> UnauthenticatedCandidateSelectionTranscriptV0 {
        let candidates = set
            .validators()
            .iter()
            .map(|validator| UnauthenticatedSnapshotCandidateV0 {
                validator_id: validator.id(),
                consensus_key: validator.consensus_key(),
                active_slashable_bond: 1_000_000_000,
                jailed: false,
                registration_valid: true,
                previous_registration_nonce: None,
                proof_of_possession: None,
            })
            .collect();
        let contributions = (1..=4)
            .map(|index| UnauthenticatedSnapshotContributionV0 {
                certificate_id: CertificateId::new([index; 32]),
                provider_validator_id: validator_id(index),
                finalized_epoch: Epoch::new(3),
                task_id: vec![b't', index],
                consumer_id: vec![b'c', index],
                consumed_units: 1_000_000,
                eligible: true,
            })
            .collect();
        UnauthenticatedCandidateSelectionTranscriptV0 {
            snapshot_epoch: Epoch::new(5),
            snapshot_height: Height::new(9_898),
            committed_snapshot_cutoff: Height::new(9_898),
            candidates,
            contributions,
        }
    }

    fn compute(
        transcript: &UnauthenticatedCandidateSelectionTranscriptV0,
        old_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
        candidate_parameters: &ConsensusParametersV0,
    ) -> CandidateSelectionKernelV0 {
        compute_candidate_selection_kernel_v0(
            transcript,
            old_set,
            old_parameters,
            candidate_parameters,
            &AcceptVerifier,
        )
        .expect("old configuration is valid")
    }

    fn assert_fallback(
        kernel: &CandidateSelectionKernelV0,
        reason: EpochFallbackReasonV0,
        old_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
    ) {
        assert!(kernel.fallback_used());
        assert_eq!(kernel.fallback_reason(), reason);
        assert_eq!(kernel.effective_parameters(), old_parameters);
        assert!(kernel.computed_candidates().is_empty());
        assert!(kernel.computed_candidate_validator_set().is_none());
        assert_eq!(
            kernel.effective_validator_set().validators(),
            old_set.validators()
        );
        assert_eq!(
            kernel.effective_validator_set().consensus_parameters_hash(),
            old_parameters.hash()
        );
        assert_eq!(kernel.effective_validator_set().epoch(), Epoch::new(6));
    }

    #[test]
    fn pop_exact_decoder_round_trips_and_rejects_prefixes_and_trailing_bytes() {
        let proof = ValidatorKeyProofOfPossessionV0::new(ValidatorKeyProofOfPossessionV0Fields {
            schema_version: 0,
            genesis_hash: GenesisHash::new([9; 32]),
            chain_id: ChainId::from_static("trnm-b2g-test"),
            target_epoch: Epoch::new(6),
            validator_id: validator_id(5),
            public_key: ConsensusPublicKey::new([5; 32]),
            registration_nonce: 7,
            signature: Signature64::from_array([8; 64]),
        })
        .expect("shape-valid proof");
        let signing = proof
            .try_signing_cev0_bytes()
            .expect("bounded signing preimage");
        let raw = proof.try_cev0_bytes().expect("bounded proof object");
        assert_eq!(raw.len(), signing.len() + 64);
        assert_eq!(&raw[..signing.len()], signing.as_slice());
        assert_eq!(
            decode_validator_key_proof_of_possession_v0_exact(&raw).expect("exact proof decodes"),
            proof
        );
        for prefix in 0..raw.len() {
            assert_eq!(
                decode_validator_key_proof_of_possession_v0_exact(&raw[..prefix])
                    .expect_err("non-complete prefix must fail")
                    .code(),
                ValidatorKeyProofDecodeErrorCode::UnexpectedEnd
            );
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(
            decode_validator_key_proof_of_possession_v0_exact(&trailing)
                .expect_err("trailing byte must fail")
                .code(),
            ValidatorKeyProofDecodeErrorCode::TrailingBytes
        );
        let validator_length_offset = 2 + 32 + 2 + proof.fields().chain_id.as_bytes().len() + 8;
        let validator_payload_offset = validator_length_offset + 4;
        let mut zero_validator = raw.clone();
        zero_validator[validator_payload_offset..validator_payload_offset + 2].fill(0);
        assert!(decode_validator_key_proof_of_possession_v0_exact(&zero_validator).is_ok());
        assert!(proof
            .verify_for_registration(
                GenesisHash::new([9; 32]),
                ChainId::from_static("trnm-b2g-test"),
                Epoch::new(6),
                validator_id(5),
                ConsensusPublicKey::new([5; 32]),
                &AcceptVerifier,
            )
            .is_ok());
        assert!(proof
            .verify_for_registration(
                GenesisHash::new([9; 32]),
                ChainId::from_static("trnm-b2g-test"),
                Epoch::new(6),
                validator_id(5),
                ConsensusPublicKey::new([5; 32]),
                &RejectVerifier,
            )
            .is_err());
    }

    #[test]
    fn shadow_is_reason_zero_and_input_permutations_are_order_independent() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let transcript = basic_transcript(&set);
        let first = compute(&transcript, &set, &old_parameters, &old_parameters);
        assert!(!first.fallback_used());
        assert_eq!(first.fallback_reason(), EpochFallbackReasonV0::None);
        assert!(first.computed_candidate_validator_set().is_none());
        assert_eq!(first.computed_candidates().len(), 4);
        assert!(first
            .computed_candidates()
            .iter()
            .all(|candidate| candidate.selected() && candidate.raw_power() == 1));
        assert_eq!(
            first.effective_validator_set().validators(),
            set.validators()
        );
        first
            .effective_validator_set()
            .validate_against_parameters(first.effective_parameters())
            .expect("reason-zero shadow carry must satisfy candidate parameters");

        let mut permuted = transcript.clone();
        permuted.candidates.reverse();
        permuted.contributions.rotate_left(1);
        let second = compute(&permuted, &set, &old_parameters, &old_parameters);
        assert_eq!(first.computed_candidates(), second.computed_candidates());
        assert_eq!(
            first.effective_validator_set(),
            second.effective_validator_set()
        );
    }

    #[test]
    fn all_non_shadow_rollouts_produce_the_frozen_weights() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let transcript = basic_transcript(&set);
        for phase in [
            RolloutPhase::EligibilityOnly,
            RolloutPhase::CappedWeight,
            RolloutPhase::Full,
        ] {
            let candidate_parameters = parameters(phase, true, |_| {});
            let kernel = compute(&transcript, &set, &old_parameters, &candidate_parameters);
            assert!(!kernel.fallback_used(), "phase {phase:?}");
            assert_eq!(
                kernel
                    .computed_candidate_validator_set()
                    .expect("non-shadow set")
                    .validators(),
                kernel.effective_validator_set().validators()
            );
            assert!(kernel
                .effective_validator_set()
                .validators()
                .iter()
                .all(|validator| validator.voting_power().get() == 1));
            kernel
                .effective_validator_set()
                .validate_against_parameters(kernel.effective_parameters())
                .expect("reason-zero non-shadow set must satisfy candidate parameters");
        }
    }

    #[test]
    fn transcript_cardinality_is_rejected_before_clone_or_diagnostics() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);

        let mut candidates = basic_transcript(&set);
        let repeated_candidate = candidates.candidates[0].clone();
        candidates
            .candidates
            .resize(MAX_SNAPSHOT_CANDIDATES + 1, repeated_candidate);
        assert_fallback(
            &compute(&candidates, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::MalformedSnapshotInput,
            &set,
            &old_parameters,
        );

        let mut contributions = basic_transcript(&set);
        let repeated_contribution = contributions.contributions[0].clone();
        contributions
            .contributions
            .resize(MAX_SNAPSHOT_CONTRIBUTIONS + 1, repeated_contribution);
        assert_fallback(
            &compute(&contributions, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::MalformedSnapshotInput,
            &set,
            &old_parameters,
        );

        let mut oversized_relation = basic_transcript(&set);
        oversized_relation.contributions[0].task_id =
            vec![b't'; MAX_SNAPSHOT_RELATION_ID_BYTES + 1];
        assert_fallback(
            &compute(&oversized_relation, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::MalformedSnapshotInput,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn reasons_one_through_four_are_fail_closed_and_numeric_minimum_wins() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);

        let mut reason_one = basic_transcript(&set);
        reason_one.contributions[1].certificate_id = reason_one.contributions[0].certificate_id;
        reason_one.candidates[0].registration_valid = false;
        assert_fallback(
            &compute(&reason_one, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::MalformedSnapshotInput,
            &set,
            &old_parameters,
        );

        let overflow_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.per_certificate_unit_cap = u128::MAX;
            fields.per_consumer_provider_epoch_unit_cap = u128::MAX;
            fields.per_task_provider_epoch_unit_cap = u128::MAX;
            fields.per_provider_epoch_unit_cap = u128::MAX;
        });
        let mut reason_two = basic_transcript(&set);
        reason_two.contributions[0].consumed_units = u128::MAX;
        assert_fallback(
            &compute(&reason_two, &set, &old_parameters, &overflow_parameters),
            EpochFallbackReasonV0::ArithmeticFailure,
            &set,
            &old_parameters,
        );

        let mut reason_three = basic_transcript(&set);
        for candidate in &mut reason_three.candidates {
            candidate.jailed = true;
        }
        assert_fallback(
            &compute(&reason_three, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::TooFewEligibleValidators,
            &set,
            &old_parameters,
        );

        let mut reason_four = basic_transcript(&set);
        reason_four.candidates[0].registration_valid = false;
        assert_fallback(
            &compute(&reason_four, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::InvalidValidatorIdentityOrKey,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn relationship_ids_are_nonempty_and_bounded_before_eligibility_filtering() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);

        for invalid in [Vec::new(), vec![b'x'; MAX_SNAPSHOT_RELATION_ID_BYTES + 1]] {
            let mut task = basic_transcript(&set);
            task.contributions[0].eligible = false;
            task.contributions[0].task_id = invalid.clone();
            assert_fallback(
                &compute(&task, &set, &old_parameters, &old_parameters),
                EpochFallbackReasonV0::MalformedSnapshotInput,
                &set,
                &old_parameters,
            );

            let mut consumer = basic_transcript(&set);
            consumer.contributions[0].eligible = false;
            consumer.contributions[0].consumer_id = invalid;
            assert_fallback(
                &compute(&consumer, &set, &old_parameters, &old_parameters),
                EpochFallbackReasonV0::MalformedSnapshotInput,
                &set,
                &old_parameters,
            );
        }

        let mut maximum = basic_transcript(&set);
        maximum.contributions[0].task_id = vec![b't'; MAX_SNAPSHOT_RELATION_ID_BYTES];
        maximum.contributions[0].consumer_id = vec![b'c'; MAX_SNAPSHOT_RELATION_ID_BYTES];
        assert!(!compute(&maximum, &set, &old_parameters, &old_parameters).fallback_used());

        let mut future_finalization = basic_transcript(&set);
        future_finalization.contributions[0].finalized_epoch = Epoch::new(6);
        assert_fallback(
            &compute(&future_finalization, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::MalformedSnapshotInput,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn shadow_carry_must_fit_candidate_validator_id_bounds() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let candidate_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.max_validator_id_bytes = 1;
        });
        let mut transcript = basic_transcript(&set);
        for (index, candidate) in transcript.candidates.iter_mut().enumerate() {
            let byte = u8::try_from(index + 1).expect("small fixture index");
            let id = ValidatorId::from_bytes(&[byte]).expect("one-byte validator ID");
            let key = ConsensusPublicKey::new([byte + 40; 32]);
            candidate.validator_id = id;
            candidate.consensus_key = key;
            candidate.previous_registration_nonce = None;
            candidate.proof_of_possession = Some(
                ValidatorKeyProofOfPossessionV0::new(ValidatorKeyProofOfPossessionV0Fields {
                    schema_version: 0,
                    genesis_hash: set.genesis_hash(),
                    chain_id: set.chain_id(),
                    target_epoch: Epoch::new(6),
                    validator_id: id,
                    public_key: key,
                    registration_nonce: 1,
                    signature: Signature64::from_array([byte; 64]),
                })
                .expect("shape-valid PoP"),
            );
            transcript.contributions[index].provider_validator_id = id;
        }
        assert_fallback(
            &compute(&transcript, &set, &old_parameters, &candidate_parameters),
            EpochFallbackReasonV0::InvalidCommittedParameters,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn reasons_five_through_nine_are_reachable_with_valid_parameter_preimages() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);

        let reason_five_parameters = parameters(RolloutPhase::EligibilityOnly, true, |fields| {
            fields.min_validator_power = 2;
            fields.units_per_power = 500_000;
        });
        let mut reason_five = basic_transcript(&set);
        for candidate in &mut reason_five.candidates {
            candidate.active_slashable_bond = 2_000_000_000;
        }
        assert_fallback(
            &compute(&reason_five, &set, &old_parameters, &reason_five_parameters),
            EpochFallbackReasonV0::ValidatorWeightOutOfBounds,
            &set,
            &old_parameters,
        );

        let high_power_set = old_set(&old_parameters, 2);
        let reason_six = basic_transcript(&high_power_set);
        let reason_six_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.max_total_voting_power = 4;
        });
        assert_fallback(
            &compute(
                &reason_six,
                &high_power_set,
                &old_parameters,
                &reason_six_parameters,
            ),
            EpochFallbackReasonV0::InvalidTotalVotingPower,
            &high_power_set,
            &old_parameters,
        );

        let full_parameters = parameters(RolloutPhase::Full, true, |_| {});
        let mut reason_seven = basic_transcript(&set);
        reason_seven.candidates[0].active_slashable_bond = 4_000_000_000;
        for index in 10..13 {
            reason_seven
                .contributions
                .push(UnauthenticatedSnapshotContributionV0 {
                    certificate_id: CertificateId::new([index; 32]),
                    provider_validator_id: validator_id(1),
                    finalized_epoch: Epoch::new(3),
                    task_id: vec![b't', index],
                    consumer_id: vec![b'c', index],
                    consumed_units: 1_000_000,
                    eligible: true,
                });
        }
        assert_fallback(
            &compute(&reason_seven, &set, &old_parameters, &full_parameters),
            EpochFallbackReasonV0::ConcentrationConstraintViolated,
            &set,
            &old_parameters,
        );

        let reason_eight_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.epoch_length_blocks += 1;
        });
        assert_fallback(
            &compute(
                &basic_transcript(&set),
                &set,
                &old_parameters,
                &reason_eight_parameters,
            ),
            EpochFallbackReasonV0::InvalidCommittedParameters,
            &set,
            &old_parameters,
        );

        let five_validator_set = ValidatorSet::new(
            set.genesis_hash(),
            set.chain_id(),
            ProtocolVersion::V0,
            set.epoch(),
            old_parameters.hash(),
            (1..=5).map(|index| validator(index, 1)).collect(),
        )
        .expect("valid five-validator old set");
        let reason_eight_count_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.max_validators = 4
        });
        assert_fallback(
            &compute(
                &basic_transcript(&five_validator_set),
                &five_validator_set,
                &old_parameters,
                &reason_eight_count_parameters,
            ),
            EpochFallbackReasonV0::InvalidCommittedParameters,
            &five_validator_set,
            &old_parameters,
        );

        let reason_nine_parameters = parameters(RolloutPhase::EligibilityOnly, false, |_| {});
        assert_fallback(
            &compute(
                &basic_transcript(&set),
                &set,
                &old_parameters,
                &reason_nine_parameters,
            ),
            EpochFallbackReasonV0::InvalidUpgradeOrActivation,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn new_and_changed_keys_require_exact_pop_and_monotonic_nonce() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let mut transcript = basic_transcript(&set);
        transcript.candidates[0].consensus_key = ConsensusPublicKey::new([41; 32]);
        transcript.candidates[0].previous_registration_nonce = Some(7);
        transcript.candidates[0].proof_of_possession = Some(
            ValidatorKeyProofOfPossessionV0::new(ValidatorKeyProofOfPossessionV0Fields {
                schema_version: 0,
                genesis_hash: set.genesis_hash(),
                chain_id: set.chain_id(),
                target_epoch: Epoch::new(6),
                validator_id: validator_id(1),
                public_key: ConsensusPublicKey::new([41; 32]),
                registration_nonce: 8,
                signature: Signature64::from_array([3; 64]),
            })
            .expect("shape-valid changed-key PoP"),
        );
        let valid = compute(&transcript, &set, &old_parameters, &old_parameters);
        assert!(!valid.fallback_used());

        transcript.candidates[0]
            .proof_of_possession
            .as_mut()
            .expect("present PoP")
            .fields
            .registration_nonce = 7;
        assert_fallback(
            &compute(&transcript, &set, &old_parameters, &old_parameters),
            EpochFallbackReasonV0::InvalidValidatorIdentityOrKey,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn maturity_expiry_caps_and_bond_ceiling_fail_atomically() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let mut transcript = basic_transcript(&set);
        transcript.contributions[0].finalized_epoch = Epoch::new(4);
        transcript.contributions[1].finalized_epoch = Epoch::new(0);
        transcript.contributions[2].consumed_units = 9_000_000;
        transcript.candidates[2].active_slashable_bond = 1_000_000_000;
        let kernel = compute(&transcript, &set, &old_parameters, &old_parameters);
        assert_fallback(
            &kernel,
            EpochFallbackReasonV0::TooFewEligibleValidators,
            &set,
            &old_parameters,
        );
    }

    #[test]
    fn old_configuration_failure_is_an_error_not_fallback_evidence() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let wrong_old_parameters = parameters(RolloutPhase::Shadow, false, |fields| {
            fields.per_certificate_unit_cap += 1;
            fields.per_consumer_provider_epoch_unit_cap += 1;
            fields.per_task_provider_epoch_unit_cap += 1;
            fields.per_provider_epoch_unit_cap += 1;
        });
        assert!(compute_candidate_selection_kernel_v0(
            &basic_transcript(&set),
            &set,
            &wrong_old_parameters,
            &old_parameters,
            &AcceptVerifier,
        )
        .is_err());
    }

    #[test]
    fn diagnostics_are_canonical_and_selection_tie_breaks_by_validator_id() {
        let old_parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = old_set(&old_parameters, 1);
        let candidate_parameters = parameters(RolloutPhase::Full, true, |fields| {
            fields.max_validators = 4;
        });
        let mut transcript = basic_transcript(&set);
        transcript.candidates.reverse();
        let kernel = compute(&transcript, &set, &old_parameters, &candidate_parameters);
        let ids: Vec<_> = kernel
            .computed_candidates()
            .iter()
            .map(CandidateComputationV0::validator_id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
