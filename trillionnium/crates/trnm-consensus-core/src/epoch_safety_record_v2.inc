// Codec2 retains the complete flat preparation provenance. It shares the
// existing Safety payload grammar, never the codec1 provenance representation.
pub const EPOCH_SAFETY_CODEC_V2: u16 = 2;
const EPOCH_SAFETY_DOMAIN_V2: &str = "trnm.consensus-core.epoch-safety-record.v2";

/// Cryptographically verified full-prefix context. Construction consumes a
/// preparation with its independently supplied root trust; a terminal runtime
/// alone cannot construct this value. This is not a journal ACK or signer lease.
#[derive(Debug)]
pub struct EpochSafetyStateRecordContextV2<'a> {
    core_config: &'a CoreConfig,
    runtime: Box<trnm_consensus_crypto::StrictEpochRuntimeContextV1>,
    epoch: crate::EpochCoreStateV1,
    limits: SafetyStateRecordLimitsV0,
}

impl<'a> EpochSafetyStateRecordContextV2<'a> {
    pub fn new(
        core_config: &'a CoreConfig,
        preparation: crate::EpochPreparationV2,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
        limits: SafetyStateRecordLimitsV0,
    ) -> Result<Self, SafetyStateRecordErrorV0> {
        let minimum = minimum_epoch_safety_record_limits_v2(core_config, &preparation)?;
        if limits.maximum_record_bytes < minimum.maximum_record_bytes
            || limits.maximum_blob_bytes < minimum.maximum_blob_bytes
        {
            return Err(SafetyStateRecordErrorV0::InsufficientLimits {
                required_record_bytes: minimum.maximum_record_bytes,
                required_blob_bytes: minimum.maximum_blob_bytes,
            });
        }
        let (epoch, runtime) = crate::EpochCoreStateV1::from_preparation_v2(
            preparation,
            checkpoint_artifact,
            owner_generation,
        )
        .map_err(|_| {
            SafetyStateRecordErrorV0::InvalidConsensusValue(
                "epoch preparation or checkpoint artifact",
            )
        })?;
        if epoch.preparation_record_v2().is_none() {
            return Err(SafetyStateRecordErrorV0::ConfigMismatch);
        }
        Ok(Self {
            core_config,
            runtime: Box::new(runtime),
            epoch,
            limits,
        })
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core_config
    }
    pub fn runtime(&self) -> &trnm_consensus_crypto::StrictEpochRuntimeContextV1 {
        &self.runtime
    }
    pub const fn epoch(&self) -> &crate::EpochCoreStateV1 {
        &self.epoch
    }
    pub const fn limits(&self) -> SafetyStateRecordLimitsV0 {
        self.limits
    }
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

/// Computes the complete reachable-record envelope before consuming the
/// preparation or opening a journal. The retained local prefix may be 64 MiB;
/// this value is never used as a CEV0 root or signature admission budget.
pub fn minimum_epoch_safety_record_limits_v2(
    config: &CoreConfig,
    preparation: &crate::EpochPreparationV2,
) -> Result<SafetyStateRecordLimitsV0, SafetyStateRecordErrorV0> {
    let activation = preparation.authority_v2();
    if config.validator_set() != activation.new_validator_set()
        || config.consensus_parameters() != activation.new_consensus_parameters()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let record_size = preparation.record_v2().as_bytes_v2().len();
    if record_size > crate::MAX_EPOCH_PREPARATION_RECORD_BYTES_V2 {
        return Err(SafetyStateRecordErrorV0::RecordTooLarge);
    }
    // The strict kernel retains the same terminal header/QC/handoff byte layout
    // as the runtime authorization used in all proposal and finality slots.
    let authorization = activation
        .authorization_cev0_bytes()
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("epoch authorization"))?
        .len();
    minimum_epoch_record_limits(
        config,
        authorization,
        checked_capacity_add(4, record_size)?,
        record_size,
    )
}

pub fn epoch_safety_record_context_ref_v2(
    context: &EpochSafetyStateRecordContextV2<'_>,
) -> Result<[u8; 32], SafetyStateRecordErrorV0> {
    let record = context
        .epoch
        .preparation_record_v2()
        .ok_or(SafetyStateRecordErrorV0::ConfigMismatch)?;
    let mut artifact = Encoder::new(256);
    encode_artifact_ref(context.epoch.checkpoint_artifact(), &mut artifact)?;
    Ok(hash_domain(
        "trnm.consensus-core.epoch-safety-context.v2",
        &[
            &safety_state_record_config_ref_v0(&context.inner())?,
            &context.epoch.activation_binding(),
            &context.epoch.owner_generation().to_be_bytes(),
            artifact.as_slice(),
            &record.root_binding_v2(),
            &record.terminal_binding_v2(),
            &record.digest_v2(),
            b"TRNMS14E;codec2;schema14;phase7;qualified-real-tips;distinct-terminal-anchor;dual-app-parent;complete-flat-TRNMEP02;closed-tags",
        ],
    ))
}

pub fn encode_epoch_safety_record_v2(
    state: &SafetyState,
    context: &EpochSafetyStateRecordContextV2<'_>,
) -> Result<Vec<u8>, SafetyStateRecordErrorV0> {
    let record = context
        .epoch
        .preparation_record_v2()
        .ok_or(SafetyStateRecordErrorV0::ConfigMismatch)?;
    let inner = context.inner();
    validate_epoch_record_state(state, &inner, context.epoch.owner_generation())?;
    let mut e = Encoder::new_with_blob_limit(
        context.limits.maximum_record_bytes,
        context.limits.maximum_blob_bytes,
    );
    e.epoch_v1 = true;
    e.fixed(EPOCH_SAFETY_MAGIC_V1)?;
    e.u16(EPOCH_SAFETY_CODEC_V2)?;
    e.u16(14)?;
    e.fixed(&epoch_safety_record_context_ref_v2(context)?)?;
    e.u8(7)?;
    e.u64(state.revision())?;
    e.u64(context.epoch.owner_generation())?;
    e.fixed(&context.epoch.activation_binding())?;
    encode_artifact_ref(context.epoch.checkpoint_artifact(), &mut e)?;
    e.blob(
        "epoch preparation provenance",
        record.as_bytes_v2(),
        crate::MAX_EPOCH_PREPARATION_RECORD_BYTES_V2,
    )?;
    encode_epoch_state_body(state, &inner, &mut e)?;
    let checksum = hash_domain(EPOCH_SAFETY_DOMAIN_V2, &[e.as_slice()]);
    e.fixed(&checksum)?;
    Ok(e.finish())
}

/// Exact codec2 decoding only. The complete prefix must byte-match the context
/// consumed from strict preparation, before decoding any Safety collections.
/// Returned state is inert until the Core semantic and physical-owner joins.
pub fn decode_epoch_safety_record_v2_exact(
    bytes: &[u8],
    context: &EpochSafetyStateRecordContextV2<'_>,
) -> Result<UnverifiedSafetyStateRecordV0, SafetyStateRecordErrorV0> {
    if bytes.len() > context.limits.maximum_record_bytes {
        return Err(SafetyStateRecordErrorV0::RecordTooLarge);
    }
    let record = context
        .epoch
        .preparation_record_v2()
        .ok_or(SafetyStateRecordErrorV0::ConfigMismatch)?;
    let inner = context.inner();
    let mut d = Decoder::new(bytes, context.limits);
    d.epoch_v1 = true;
    if d.fixed::<8>("record magic")? != *EPOCH_SAFETY_MAGIC_V1 {
        return Err(SafetyStateRecordErrorV0::InvalidMagic);
    }
    let codec = d.u16("record codec")?;
    if codec != EPOCH_SAFETY_CODEC_V2 {
        return Err(SafetyStateRecordErrorV0::UnsupportedCodec(codec));
    }
    let schema = d.u16("safety schema")?;
    if schema != 14 {
        return Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(schema));
    }
    if d.fixed::<32>("context")? != epoch_safety_record_context_ref_v2(context)? {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let phase = d.u8("epoch phase")?;
    if phase != 7 {
        return Err(SafetyStateRecordErrorV0::UnknownTag("epoch phase", phase));
    }
    let revision = d.u64("revision")?;
    if d.u64("owner generation")? != context.epoch.owner_generation()
        || d.fixed::<32>("activation binding")? != context.epoch.activation_binding()
        || decode_artifact_ref(&mut d)? != context.epoch.checkpoint_artifact()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    if d.blob(
        "epoch preparation provenance",
        crate::MAX_EPOCH_PREPARATION_RECORD_BYTES_V2,
    )? != record.as_bytes_v2()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let state =
        decode_epoch_state_body(&mut d, &inner, revision, context.epoch.owner_generation())?;
    let checksum_offset = d.position();
    let checksum = d.fixed::<32>("record checksum")?;
    d.finish()?;
    if checksum != hash_domain(EPOCH_SAFETY_DOMAIN_V2, &[&bytes[..checksum_offset]]) {
        return Err(SafetyStateRecordErrorV0::ChecksumMismatch);
    }
    if encode_epoch_safety_record_v2(&state, context)? != bytes {
        return Err(SafetyStateRecordErrorV0::NonCanonical);
    }
    Ok(UnverifiedSafetyStateRecordV0 {
        state,
        record_checksum: checksum,
    })
}
