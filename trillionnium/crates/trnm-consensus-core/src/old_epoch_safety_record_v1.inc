// Deliberately distinct from both TRNMSF13 and the future complete TRNMS14E
// activation codec. Only the outgoing epoch-zero phases 0..4 are expressible.
pub const OLD_EPOCH_BOUNDARY_SAFETY_CODEC_V1: u16 = 1;
const OLD_EPOCH_MAGIC_V1: &[u8; 8] = b"TRNMS14O";
const OLD_EPOCH_RECORD_DOMAIN_V1: &str = "trnm.consensus-core.old-epoch-safety-record.v1";

pub fn minimum_old_epoch_boundary_record_limits_v1(
    config: &CoreConfig,
) -> Result<SafetyStateRecordLimitsV0, SafetyStateRecordErrorV0> {
    let base = minimum_safety_state_record_limits_v0(config)?;
    let additional = checked_capacity_add(
        crate::CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1,
        checked_capacity_mul(config.max_observed_messages(), 2048)?,
    )?;
    SafetyStateRecordLimitsV0::new(
        checked_capacity_add(
            base.maximum_record_bytes(),
            checked_capacity_add(additional, 1024)?,
        )?,
        base.maximum_blob_bytes(),
    )
}

pub fn old_epoch_boundary_record_context_ref_v1(
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<[u8; 32], SafetyStateRecordErrorV0> {
    let minimum = minimum_old_epoch_boundary_record_limits_v1(context.core_config)?;
    if context.limits.maximum_record_bytes < minimum.maximum_record_bytes
        || context.limits.maximum_blob_bytes < minimum.maximum_blob_bytes
    {
        return Err(SafetyStateRecordErrorV0::InsufficientLimits {
            required_record_bytes: minimum.maximum_record_bytes,
            required_blob_bytes: minimum.maximum_blob_bytes,
        });
    }
    Ok(hash_domain("trnm.consensus-core.old-epoch-context.v1", &[&safety_state_record_config_ref_v0(context)?, b"schema14;outgoing-epoch0-only;qualified-finalized-and-applied;canonical-candidates;no-anchor;no-view-reset"]))
}

fn old_epoch_phase_tag_v1(boundary: &crate::OldEpochBoundaryStateV1, state: &SafetyState) -> u8 {
    use crate::OldEpochBoundaryPhaseV1::*;
    match boundary.phase(state) {
        Running => 0,
        CheckpointPrepared => 1,
        CheckpointCertified => 2,
        Seal1Certified => 3,
        CheckpointApplied => 4,
    }
}

fn encode_old_epoch_qualified_tip_v1(
    tip: FinalizedTip,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    let set = context.core_config.validator_set();
    encoder.u64(set.epoch().get())?;
    encoder.fixed(set.id().as_bytes())?;
    encoder.fixed(set.consensus_parameters_hash().as_bytes())?;
    encode_finalized_tip(tip, encoder)
}
fn decode_old_epoch_qualified_tip_v1(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<FinalizedTip, SafetyStateRecordErrorV0> {
    let set = context.core_config.validator_set();
    if decoder.u64("tip epoch")? != set.epoch().get()
        || decoder.fixed::<32>("tip validator set")? != *set.id().as_bytes()
        || decoder.fixed::<32>("tip parameters")? != *set.consensus_parameters_hash().as_bytes()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    decode_finalized_tip(decoder)
}

/// Bounded local representation of the outgoing epoch owner. This codec never
/// grants Core recovery or signer authority and cannot encode anchor-installed
/// state. All signed protocol objects retain their frozen encodings.
pub fn encode_old_epoch_boundary_safety_record_v1(
    state: &SafetyState,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<Vec<u8>, SafetyStateRecordErrorV0> {
    let boundary =
        state
            .old_epoch_boundary_v1()
            .ok_or(SafetyStateRecordErrorV0::UnsupportedSafetySchema(
                state.schema_version(),
            ))?;
    if state.epoch_state_v1().is_some()
        || state.schema_version() != 14
        || state.epoch() != Epoch::new(0)
        || state.epoch() != context.core_config.validator_set().epoch()
        || state.validator_set_id() != context.core_config.validator_set().id()
        || state.chain_id() != context.core_config.validator_set().chain_id()
        || state.protocol_version() != context.core_config.validator_set().protocol_version()
        || state.genesis_block_id() != context.core_config.genesis_block_id()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let mut payload = Encoder::new_with_blob_limit(
        context.limits.maximum_record_bytes,
        context.limits.maximum_blob_bytes,
    );
    encode_state_payload(state, context, &mut payload)?;
    let mut record = Encoder::new_with_blob_limit(
        context.limits.maximum_record_bytes,
        context.limits.maximum_blob_bytes,
    );
    record.fixed(OLD_EPOCH_MAGIC_V1)?;
    record.u16(OLD_EPOCH_BOUNDARY_SAFETY_CODEC_V1)?;
    record.u16(14)?;
    record.fixed(&old_epoch_boundary_record_context_ref_v1(context)?)?;
    record.u64(state.revision())?;
    record.u64(boundary.owner_generation())?;
    record.u8(old_epoch_phase_tag_v1(boundary, state))?;
    encode_old_epoch_qualified_tip_v1(state.finalized(), context, &mut record)?;
    encode_old_epoch_qualified_tip_v1(state.application_applied(), context, &mut record)?;
    record.blob(
        "outgoing safety payload",
        &payload.finish(),
        context.limits.maximum_record_bytes,
    )?;
    encode_count(
        boundary.checkpoints().len(),
        context.core_config.max_observed_messages(),
        "checkpoint candidates",
        &mut record,
    )?;
    for checkpoint in boundary.checkpoints() {
        encode_parent(checkpoint.parent(), context, &mut record)?;
        encode_signed_proposal(
            checkpoint.proposal(),
            checkpoint.parent(),
            context,
            &mut record,
        )?;
    }
    encode_count(
        boundary.seals().len(),
        context.core_config.max_observed_messages(),
        "consensus seals",
        &mut record,
    )?;
    for seal in boundary.seals() {
        let parent = boundary
            .checkpoints()
            .iter()
            .map(|c| c.proposal())
            .chain(boundary.seals().iter())
            .find(|p| p.block().id() == seal.block().header().parent_id())
            .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "seal parent",
            ))?;
        record.u64(parent.block().header().timestamp_ms())?;
        // This parameter is ignored by encode_signed_proposal; do not encode
        // a false application/finality parent carrier for a consensus seal.
        let carrier = boundary
            .checkpoints()
            .first()
            .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "seal checkpoint",
            ))?
            .parent();
        encode_signed_proposal(seal, carrier, context, &mut record)?;
    }
    let checksum = hash_domain(OLD_EPOCH_RECORD_DOMAIN_V1, &[record.as_slice()]);
    record.fixed(&checksum)?;
    Ok(record.finish())
}

pub fn decode_old_epoch_boundary_safety_record_v1_exact(
    bytes: &[u8],
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<UnverifiedSafetyStateRecordV0, SafetyStateRecordErrorV0> {
    if bytes.len() > context.limits.maximum_record_bytes {
        return Err(SafetyStateRecordErrorV0::RecordTooLarge);
    }
    let mut d = Decoder::new(bytes, context.limits);
    if d.fixed::<8>("record magic")? != *OLD_EPOCH_MAGIC_V1 {
        return Err(SafetyStateRecordErrorV0::InvalidMagic);
    }
    let codec = d.u16("record codec")?;
    if codec != OLD_EPOCH_BOUNDARY_SAFETY_CODEC_V1 {
        return Err(SafetyStateRecordErrorV0::UnsupportedCodec(codec));
    }
    let schema = d.u16("safety schema")?;
    if schema != 14 {
        return Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(schema));
    }
    if d.fixed::<32>("context")? != old_epoch_boundary_record_context_ref_v1(context)? {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let revision = d.u64("revision")?;
    let generation = d.u64("owner generation")?;
    let phase = d.u8("outgoing phase")?;
    if phase > 4 {
        return Err(SafetyStateRecordErrorV0::UnknownTag(
            "outgoing phase",
            phase,
        ));
    }
    let finalized = decode_old_epoch_qualified_tip_v1(&mut d, context)?;
    let applied = decode_old_epoch_qualified_tip_v1(&mut d, context)?;
    let payload = d.record_blob(
        "outgoing safety payload",
        context.limits.maximum_record_bytes,
    )?;
    let mut payload_decoder = Decoder::new(payload, context.limits);
    let mut state = decode_state_payload(&mut payload_decoder, context)?;
    payload_decoder.finish()?;
    if state.revision() != revision
        || state.finalized() != finalized
        || state.application_applied() != applied
    {
        return Err(SafetyStateRecordErrorV0::NonCanonical);
    }
    let mut boundary = crate::OldEpochBoundaryStateV1::new(generation)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("owner generation"))?;
    let n = d.count(
        "checkpoint candidates",
        context.core_config.max_observed_messages(),
        64,
    )?;
    for _ in 0..n {
        let parent = decode_parent(&mut d, context)?;
        let proposal = decode_signed_proposal(&mut d, &parent, context)?;
        boundary
            .record_checkpoint(
                &proposal,
                parent,
                context.core_config.max_observed_messages(),
            )
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("checkpoint candidate"))?;
    }
    let n = d.count(
        "consensus seals",
        context.core_config.max_observed_messages(),
        64,
    )?;
    for _ in 0..n {
        let timestamp = d.u64("seal parent timestamp")?;
        let proposal = decode_signed_proposal_at_timestamp_v1(&mut d, timestamp, context)?;
        boundary
            .record_seal(
                &proposal,
                context.core_config.consensus_parameters(),
                context.core_config.max_observed_messages(),
            )
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("consensus seal"))?;
    }
    if old_epoch_phase_tag_v1(&boundary, &state) != phase {
        return Err(SafetyStateRecordErrorV0::NonCanonical);
    }
    state.install_old_epoch_boundary_v1(boundary);
    let offset = d.position();
    let checksum = d.fixed::<32>("record checksum")?;
    d.finish()?;
    if checksum != hash_domain(OLD_EPOCH_RECORD_DOMAIN_V1, &[&bytes[..offset]]) {
        return Err(SafetyStateRecordErrorV0::ChecksumMismatch);
    }
    if encode_old_epoch_boundary_safety_record_v1(&state, context)?.as_slice() != bytes {
        return Err(SafetyStateRecordErrorV0::NonCanonical);
    }
    Ok(UnverifiedSafetyStateRecordV0 {
        state,
        record_checksum: checksum,
    })
}
