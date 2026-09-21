// Full epoch records use a distinct local magic and context. No v0 decoder is
// relaxed: the private epoch switches below exist only inside this codec.
pub const EPOCH_SAFETY_CODEC_V1: u16 = 1;
const EPOCH_SAFETY_MAGIC_V1: &[u8; 8] = b"TRNMS14E";
const EPOCH_SAFETY_DOMAIN_V1: &str = "trnm.consensus-core.epoch-safety-record.v1";

/// Strict cryptographic decoding context, still inert with respect to native
/// application, journal, and signer ownership. Its scalar artifact/generation
/// inputs cannot create a live Core or acknowledge a persistence barrier.
#[derive(Debug)]
pub struct EpochSafetyStateRecordContextV1<'a> {
    core_config: &'a CoreConfig,
    runtime: trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    epoch: crate::EpochCoreStateV1,
    limits: SafetyStateRecordLimitsV0,
}
impl<'a> EpochSafetyStateRecordContextV1<'a> {
    pub fn new(
        core_config: &'a CoreConfig,
        runtime: trnm_consensus_crypto::StrictEpochRuntimeContextV1,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
        limits: SafetyStateRecordLimitsV0,
    ) -> Result<Self, SafetyStateRecordErrorV0> {
        if core_config.validator_set() != runtime.structural_context().new_validator_set()
            || core_config.consensus_parameters() != runtime.structural_context().new_parameters()
        {
            return Err(SafetyStateRecordErrorV0::ConfigMismatch);
        }
        let minimum = minimum_epoch_safety_record_limits_v1(core_config, &runtime)?;
        if limits.maximum_record_bytes < minimum.maximum_record_bytes
            || limits.maximum_blob_bytes < minimum.maximum_blob_bytes
        {
            return Err(SafetyStateRecordErrorV0::InsufficientLimits {
                required_record_bytes: minimum.maximum_record_bytes,
                required_blob_bytes: minimum.maximum_blob_bytes,
            });
        }
        let epoch = crate::EpochCoreStateV1::from_strict(&runtime, checkpoint_artifact, owner_generation)
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("epoch checkpoint artifact"))?;
        Ok(Self { core_config, runtime, epoch, limits })
    }
    pub const fn core_config(&self) -> &CoreConfig { self.core_config }
    pub const fn runtime(&self) -> &trnm_consensus_crypto::StrictEpochRuntimeContextV1 { &self.runtime }
    pub const fn epoch(&self) -> &crate::EpochCoreStateV1 { &self.epoch }
    pub const fn limits(&self) -> SafetyStateRecordLimitsV0 { self.limits }
    fn inner(&self) -> SafetyStateRecordContextV0<'_> {
        SafetyStateRecordContextV0 {
            core_config: self.core_config,
            verifier_profile_ref: hash_domain("trnm.consensus-core.epoch.strict-ed25519.v1", &[]),
            limits: self.limits,
            epoch_context_v1: Some(&self.runtime),
            epoch_state_v1: Some(&self.epoch),
        }
    }
}

fn epoch_evidence_components_v1(e: &trnm_consensus_types::EpochActivationEvidenceBytesV0) -> [&[u8]; 8] {
    [&e.old_checkpoint_finality, &e.next_epoch_commitment, &e.authorization_kernel,
     &e.old_validator_set, &e.old_consensus_parameters, &e.new_validator_set,
     &e.new_consensus_parameters, &e.authenticated_checkpoint_parent_header]
}

pub fn minimum_epoch_safety_record_limits_v1(
    config: &CoreConfig,
    runtime: &trnm_consensus_crypto::StrictEpochRuntimeContextV1,
) -> Result<SafetyStateRecordLimitsV0, SafetyStateRecordErrorV0> {
    if config.validator_set() != runtime.structural_context().new_validator_set()
        || config.consensus_parameters() != runtime.structural_context().new_parameters() {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let authorization = runtime.structural_context().authorization().try_cev0_bytes()
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("epoch authorization"))?.len();
    let mut evidence_size = 0;
    let mut maximum_blob = authorization;
    for component in epoch_evidence_components_v1(runtime.evidence_bytes()) {
        maximum_blob = maximum_blob.max(component.len());
        evidence_size = checked_capacity_add(evidence_size, checked_capacity_add(component.len(), 4)?)?;
    }
    minimum_epoch_record_limits(config, authorization, evidence_size, maximum_blob)
}

// The two codecs share the same reachable Safety payload and boundary slots;
// only the exact retained provenance frame differs. This changes no v1 bound.
fn minimum_epoch_record_limits(
    config: &CoreConfig,
    authorization: usize,
    evidence_size: usize,
    maximum_provenance_blob: usize,
) -> Result<SafetyStateRecordLimitsV0, SafetyStateRecordErrorV0> {
    let base = minimum_safety_state_record_limits_any_epoch_v1(config)?;
    let maximum_blob = base.maximum_blob_bytes.max(authorization).max(maximum_provenance_blob);
    // The base already covers all old field layouts. Account for every possible
    // full authorization in a proposal/finality slot plus dual-parent tags,
    // retained checkpoint/seal proposals, and exact eight-root metadata. All
    // arithmetic and the outer u32 frame are checked before opening a journal.
    let slots = checked_capacity_add(checked_capacity_mul(config.max_observed_messages(), 4)?,
        checked_capacity_mul(config.max_blocks(), 6)?)?;
    let extension = checked_capacity_add(
        crate::CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1,
        checked_capacity_add(evidence_size,
            checked_capacity_mul(slots, checked_capacity_add(authorization, 512)?)?)?)?;
    SafetyStateRecordLimitsV0::new(
        checked_capacity_add(base.maximum_record_bytes, checked_capacity_add(extension, 4096)?)?,
        maximum_blob,
    )
}

pub fn epoch_safety_record_context_ref_v1(
    context: &EpochSafetyStateRecordContextV1<'_>,
) -> Result<[u8; 32], SafetyStateRecordErrorV0> {
    let mut artifact = Encoder::new(256);
    encode_artifact_ref(context.epoch.checkpoint_artifact(), &mut artifact)?;
    Ok(hash_domain("trnm.consensus-core.epoch-safety-context.v1", &[
        &safety_state_record_config_ref_v0(&context.inner())?,
        &context.epoch.activation_binding(),
        &context.epoch.owner_generation().to_be_bytes(),
        artifact.as_slice(),
        b"TRNMS14E;codec1;schema14;phase7;qualified-real-tips;distinct-terminal-anchor;dual-app-parent;complete-eight-roots;closed-tags",
    ]))
}

fn encode_qualified_tip_v1(tip: crate::QualifiedFinalizedTipV1, e: &mut Encoder) -> Result<(), SafetyStateRecordErrorV0> {
    e.u64(tip.epoch().get())?;
    e.fixed(tip.validator_set_id().as_bytes())?;
    e.fixed(tip.parameters_hash().as_bytes())?;
    encode_finalized_tip(tip.tip(), e)
}
fn decode_qualified_tip_parts_v1(d: &mut Decoder<'_>) -> Result<(u64, [u8; 32], [u8; 32], FinalizedTip), SafetyStateRecordErrorV0> {
    Ok((d.u64("qualified epoch")?, d.fixed("qualified validator set")?,
        d.fixed("qualified parameters")?, decode_finalized_tip(d)?))
}
fn qualified_tip_matches_v1(parts: (u64, [u8; 32], [u8; 32], FinalizedTip), tip: crate::QualifiedFinalizedTipV1) -> bool {
    parts == (tip.epoch().get(), *tip.validator_set_id().as_bytes(), *tip.parameters_hash().as_bytes(), tip.tip())
}

pub fn encode_epoch_safety_record_v1(
    state: &SafetyState,
    context: &EpochSafetyStateRecordContextV1<'_>,
) -> Result<Vec<u8>, SafetyStateRecordErrorV0> {
    if context.epoch.preparation_record_v2().is_some() {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let inner = context.inner();
    validate_epoch_record_state(state, &inner, context.epoch.owner_generation())?;
    let mut e = Encoder::new_with_blob_limit(context.limits.maximum_record_bytes, context.limits.maximum_blob_bytes);
    e.epoch_v1 = true;
    e.fixed(EPOCH_SAFETY_MAGIC_V1)?;
    e.u16(EPOCH_SAFETY_CODEC_V1)?;
    e.u16(14)?;
    e.fixed(&epoch_safety_record_context_ref_v1(context)?)?;
    e.u8(7)?;
    e.u64(state.revision())?;
    e.u64(context.epoch.owner_generation())?;
    e.fixed(&context.epoch.activation_binding())?;
    encode_artifact_ref(context.epoch.checkpoint_artifact(), &mut e)?;
    for component in epoch_evidence_components_v1(context.runtime.evidence_bytes()) {
        e.blob("epoch evidence component", component, context.limits.maximum_blob_bytes)?;
    }
    encode_epoch_state_body(state, &inner, &mut e)?;
    let checksum = hash_domain(EPOCH_SAFETY_DOMAIN_V1, &[e.as_slice()]);
    e.fixed(&checksum)?;
    Ok(e.finish())
}

fn validate_epoch_record_state(
    state: &SafetyState,
    inner: &SafetyStateRecordContextV0<'_>,
    generation: u64,
) -> Result<(), SafetyStateRecordErrorV0> {
    validate_state_scope(state, inner)?;
    let boundary = state.old_epoch_boundary_v1().ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue("active epoch boundary"))?;
    if boundary.owner_generation() != generation || state.state_sync_anchor().is_some() {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    Ok(())
}

fn encode_epoch_state_body(
    state: &SafetyState,
    inner: &SafetyStateRecordContextV0<'_>,
    e: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    let boundary = state.old_epoch_boundary_v1().ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue("active epoch boundary"))?;
    encode_qualified_tip_v1(state.qualified_finalized_v1(inner.core_config.validator_set()), e)?;
    encode_qualified_tip_v1(state.qualified_application_applied_v1(inner.core_config.validator_set()), e)?;
    encode_state_payload(state, inner, e)?;
    e.u8(old_epoch_phase_tag_v1(boundary, state))?;
    encode_count(boundary.checkpoints().len(), inner.core_config.max_observed_messages(), "checkpoint candidates", e)?;
    for checkpoint in boundary.checkpoints() {
        encode_parent(checkpoint.parent(), inner, e)?;
        encode_signed_proposal(checkpoint.proposal(), checkpoint.parent(), inner, e)?;
    }
    encode_count(boundary.seals().len(), inner.core_config.max_observed_messages(), "consensus seals", e)?;
    for seal in boundary.seals() {
        let parent = boundary.checkpoints().iter().map(|c| c.proposal()).chain(boundary.seals().iter())
            .find(|p| p.block().id() == seal.block().header().parent_id())
            .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue("seal parent"))?;
        e.u64(parent.block().header().timestamp_ms())?;
        let carrier = boundary.checkpoints().first().ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue("seal checkpoint"))?.parent();
        encode_signed_proposal(seal, carrier, inner, e)?;
    }
    Ok(())
}

/// Exact decoding is deliberately not recovery or activation. Every retained
/// live-state signature and ownership cut still requires the Core/host join.
pub fn decode_epoch_safety_record_v1_exact(
    bytes: &[u8],
    context: &EpochSafetyStateRecordContextV1<'_>,
) -> Result<UnverifiedSafetyStateRecordV0, SafetyStateRecordErrorV0> {
    if context.epoch.preparation_record_v2().is_some() {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    if bytes.len() > context.limits.maximum_record_bytes { return Err(SafetyStateRecordErrorV0::RecordTooLarge); }
    let inner = context.inner();
    let mut d = Decoder::new(bytes, context.limits);
    d.epoch_v1 = true;
    if d.fixed::<8>("record magic")? != *EPOCH_SAFETY_MAGIC_V1 { return Err(SafetyStateRecordErrorV0::InvalidMagic); }
    let codec = d.u16("record codec")?;
    if codec != EPOCH_SAFETY_CODEC_V1 { return Err(SafetyStateRecordErrorV0::UnsupportedCodec(codec)); }
    let schema = d.u16("safety schema")?;
    if schema != 14 { return Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(schema)); }
    if d.fixed::<32>("context")? != epoch_safety_record_context_ref_v1(context)? { return Err(SafetyStateRecordErrorV0::ConfigMismatch); }
    let phase = d.u8("epoch phase")?;
    if phase != 7 { return Err(SafetyStateRecordErrorV0::UnknownTag("epoch phase", phase)); }
    let revision = d.u64("revision")?;
    if d.u64("owner generation")? != context.epoch.owner_generation()
        || d.fixed::<32>("activation binding")? != context.epoch.activation_binding()
        || decode_artifact_ref(&mut d)? != context.epoch.checkpoint_artifact() { return Err(SafetyStateRecordErrorV0::ConfigMismatch); }
    for expected in epoch_evidence_components_v1(context.runtime.evidence_bytes()) {
        if d.blob("epoch evidence component", context.limits.maximum_blob_bytes)? != expected { return Err(SafetyStateRecordErrorV0::ConfigMismatch); }
    }
    let state = decode_epoch_state_body(&mut d, &inner, revision, context.epoch.owner_generation())?;
    let checksum_offset = d.position();
    let checksum = d.fixed::<32>("record checksum")?;
    d.finish()?;
    if checksum != hash_domain(EPOCH_SAFETY_DOMAIN_V1, &[&bytes[..checksum_offset]]) { return Err(SafetyStateRecordErrorV0::ChecksumMismatch); }
    if encode_epoch_safety_record_v1(&state, context)? != bytes { return Err(SafetyStateRecordErrorV0::NonCanonical); }
    Ok(UnverifiedSafetyStateRecordV0 { state, record_checksum: checksum })
}

fn decode_epoch_state_body(
    d: &mut Decoder<'_>,
    inner: &SafetyStateRecordContextV0<'_>,
    revision: u64,
    generation: u64,
) -> Result<SafetyState, SafetyStateRecordErrorV0> {
    let finalized = decode_qualified_tip_parts_v1(d)?;
    let applied = decode_qualified_tip_parts_v1(d)?;
    let mut state = decode_state_payload(d, inner)?;
    if state.revision() != revision
        || !qualified_tip_matches_v1(finalized, state.qualified_finalized_v1(inner.core_config.validator_set()))
        || !qualified_tip_matches_v1(applied, state.qualified_application_applied_v1(inner.core_config.validator_set())) {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let boundary_phase = d.u8("boundary phase")?;
    let mut boundary = crate::OldEpochBoundaryStateV1::new(generation)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("owner generation"))?;
    let count = d.count("checkpoint candidates", inner.core_config.max_observed_messages(), MIN_BLOB_ITEM_BYTES)?;
    for _ in 0..count {
        let parent = decode_parent(d, inner)?;
        let proposal = decode_signed_proposal(d, &parent, inner)?;
        boundary.record_checkpoint(&proposal, parent, inner.core_config.max_observed_messages())
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("checkpoint candidate"))?;
    }
    let count = d.count("consensus seals", inner.core_config.max_observed_messages(), MIN_BLOB_ITEM_BYTES)?;
    for _ in 0..count {
        let timestamp = d.u64("seal parent timestamp")?;
        let proposal = decode_signed_proposal_at_timestamp_v1(d, timestamp, inner)?;
        let parent = boundary.checkpoints().iter().map(|c| c.proposal()).chain(boundary.seals().iter())
            .find(|p| p.block().id() == proposal.block().header().parent_id())
            .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue("seal parent"))?;
        if timestamp != parent.block().header().timestamp_ms() { return Err(SafetyStateRecordErrorV0::ConfigMismatch); }
        boundary.record_seal(&proposal, inner.core_config.consensus_parameters(), inner.core_config.max_observed_messages())
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("seal proposal"))?;
    }
    state.install_old_epoch_boundary_v1(boundary);
    if boundary_phase != old_epoch_phase_tag_v1(state.old_epoch_boundary_v1().ok_or(SafetyStateRecordErrorV0::NonCanonical)?, &state) { return Err(SafetyStateRecordErrorV0::NonCanonical); }
    Ok(state)
}
