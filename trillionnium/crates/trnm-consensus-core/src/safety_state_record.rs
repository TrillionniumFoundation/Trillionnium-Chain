//! Exact, bounded persistence codec for epoch-zero safety state.
//!
//! The record is an inert persistence representation. Decoding never creates
//! a live payload-validation capability; valid completions reconstruct only
//! [`DurableValidatedBlockCommitmentsV1`] comparison facts. Callers must pass
//! the decoded state through the Core persisted-state validator before using
//! it for recovery.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_finality_proof_v0_exact_with_trusted_genesis,
    decode_ordinary_qc_v0_exact, decode_qc_reference_v0_exact_with_trusted_genesis,
    decode_timeout_certificate_v0_exact_with_trusted_genesis, Block, BlockId, CertificateId,
    ChainId, ContextAuthorizedQcV0, Epoch, Height, ProposalWitnessV0, ProtocolVersion, QcRef,
    QcReferenceV0, QuorumCertificate, Signature64, SignedProposalV0, SigningRoot, StateRoot,
    TimeoutCertificateV0, ValidatorSetId, View,
};

use crate::model::{
    AuthenticatedGenesisApplicationParentV0, BlockIdOverlayRefV0, CoreConfig,
    DurableFinalizationV0, DurablePayloadValidationCompletionV0,
    DurablePayloadValidationObligationV0, DurablePayloadValidationResultV1,
    DurableStateSyncAnchorV0, DurableValidatedBlockCommitmentsV1, FinalizedTip,
    InvalidPayloadReference, PayloadTerminalFact, PayloadTerminalResult,
    PayloadValidationParentProvenanceV0, PayloadValidationParentV0, PayloadValidationRouteV0,
    PendingStandaloneQcSync, PendingTcHighQcSync, SafetyHalt, SafetyState, SignIntent,
    ValidatedPayloadArtifactRefV0, ValidationId,
};

pub const SAFETY_STATE_RECORD_CODEC_VERSION_V0: u16 = 0;
pub const SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0: u16 = 12;

const MAGIC: &[u8; 8] = b"TRNMSF12";
const CONFIG_DOMAIN: &str = "trnm.consensus-core.safety-state-config.v0";
const RECORD_DOMAIN: &str = "trnm.consensus-core.safety-state-record.v0";
const LAYOUT_DOMAIN: &str = "trnm.consensus-core.safety-state-layout.v0";
const LAYOUT_DESCRIPTION: &[u8] =
    b"schema12;epoch0;be;closed-tags;u16-ids;u32-blobs;nested-cev0;valid-artifact-overlay-ref;three-state-parent-carrier;authenticated-genesis-application-parent;exact-parent-provenance;ordered-finalization-queue;finalization-target-overlay-ref;durable-state-sync-anchor;application-applied-watermark;sha256-domain-framed";

const TAG_NONE: u8 = 0;
const TAG_SOME: u8 = 1;
const TAG_ROUTE_PROPOSAL: u8 = 0;
const TAG_ROUTE_SYNCED: u8 = 1;
const TAG_TERMINAL_VALID: u8 = 0;
const TAG_TERMINAL_INVALID: u8 = 1;
const TAG_RESULT_VALID: u8 = 0;
const TAG_RESULT_UNAVAILABLE: u8 = 1;
const TAG_RESULT_INVALID: u8 = 2;
const TAG_PARENT_FINALIZED: u8 = 0;
const TAG_PARENT_SPECULATIVE: u8 = 1;
const TAG_PARENT_CARRIER_LEGACY_GENESIS: u8 = 0;
const TAG_PARENT_CARRIER_AUTHENTICATED_GENESIS_APPLICATION: u8 = 1;
const TAG_PARENT_CARRIER_EXACT_HEADER: u8 = 2;
const TAG_SIGN_VOTE: u8 = 0;
const TAG_SIGN_TIMEOUT: u8 = 1;
const TAG_HALT_CONFLICTING_QCS: u8 = 0;
const TAG_HALT_PAYLOAD_CONFLICT: u8 = 1;
const TAG_HALT_INVALID_PAYLOAD: u8 = 2;
const TAG_INVALID_REFERENCE_QC: u8 = 0;
const TAG_INVALID_REFERENCE_TC: u8 = 1;
const TAG_INVALID_REFERENCE_VOTE: u8 = 2;

// Conservative lower bounds for one list item after its enclosing count.
// These prevent an attacker-controlled count from amplifying a bounded record
// into a much larger eager allocation before the item bytes are parsed.
const MIN_TERMINAL_FACT_BYTES: usize = 41;
const MAX_TERMINAL_FACT_BYTES: usize = 137;
const MIN_VALIDATION_OBLIGATION_BYTES: usize = 197;
const MIN_VALIDATION_COMPLETION_BYTES: usize = 58;
const MIN_BLOB_ITEM_BYTES: usize = 4;
const MIN_NONEMPTY_BLOB_ITEM_BYTES: usize = 5;
const MIN_DURABLE_FINALIZATION_BYTES: usize = 157;

/// Host-selected resource bounds for one exact record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyStateRecordLimitsV0 {
    maximum_record_bytes: usize,
    maximum_blob_bytes: usize,
}

impl SafetyStateRecordLimitsV0 {
    pub fn new(
        maximum_record_bytes: usize,
        maximum_blob_bytes: usize,
    ) -> Result<Self, SafetyStateRecordErrorV0> {
        if maximum_record_bytes < 128
            || maximum_blob_bytes == 0
            || maximum_blob_bytes > maximum_record_bytes
        {
            return Err(SafetyStateRecordErrorV0::InvalidLimits);
        }
        if maximum_record_bytes > u32::MAX as usize || maximum_blob_bytes > u32::MAX as usize {
            return Err(SafetyStateRecordErrorV0::InvalidLimits);
        }
        Ok(Self {
            maximum_record_bytes,
            maximum_blob_bytes,
        })
    }

    pub const fn maximum_record_bytes(self) -> usize {
        self.maximum_record_bytes
    }

    pub const fn maximum_blob_bytes(self) -> usize {
        self.maximum_blob_bytes
    }
}

/// Trusted context which binds record bytes to one Core configuration and
/// one explicitly identified signature-verifier profile.
#[derive(Debug, Clone, Copy)]
pub struct SafetyStateRecordContextV0<'a> {
    core_config: &'a CoreConfig,
    verifier_profile_ref: [u8; 32],
    limits: SafetyStateRecordLimitsV0,
}

impl<'a> SafetyStateRecordContextV0<'a> {
    pub fn new(
        core_config: &'a CoreConfig,
        verifier_profile_ref: [u8; 32],
        limits: SafetyStateRecordLimitsV0,
    ) -> Result<Self, SafetyStateRecordErrorV0> {
        let minimum = minimum_safety_state_record_limits_v0(core_config)?;
        if limits.maximum_record_bytes < minimum.maximum_record_bytes
            || limits.maximum_blob_bytes < minimum.maximum_blob_bytes
        {
            return Err(SafetyStateRecordErrorV0::InsufficientLimits {
                required_record_bytes: minimum.maximum_record_bytes,
                required_blob_bytes: minimum.maximum_blob_bytes,
            });
        }
        Ok(Self {
            core_config,
            verifier_profile_ref,
            limits,
        })
    }

    pub const fn core_config(&self) -> &'a CoreConfig {
        self.core_config
    }

    pub const fn verifier_profile_ref(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn limits(&self) -> SafetyStateRecordLimitsV0 {
        self.limits
    }
}

/// An exactly decoded, checksum- and configuration-bound record which has not
/// yet been accepted by Core's persisted-state semantic validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedSafetyStateRecordV0 {
    state: SafetyState,
    record_checksum: [u8; 32],
}

impl UnverifiedSafetyStateRecordV0 {
    pub const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub const fn record_checksum(&self) -> [u8; 32] {
        self.record_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyStateRecordErrorV0 {
    InvalidLimits,
    InsufficientLimits {
        required_record_bytes: usize,
        required_blob_bytes: usize,
    },
    RecordTooLarge,
    BlobTooLarge(&'static str),
    LengthOverflow(&'static str),
    AllocationFailed(&'static str),
    Truncated(&'static str),
    TrailingBytes,
    InvalidMagic,
    UnsupportedCodec(u16),
    UnsupportedSafetySchema(u16),
    UnsupportedEpoch,
    UnsupportedEpochAnchor,
    UnknownTag(&'static str, u8),
    ConfigMismatch,
    ChecksumMismatch,
    NonCanonical,
    InvalidConsensusValue(&'static str),
}

impl fmt::Display for SafetyStateRecordErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid safety-state record limits"),
            Self::InsufficientLimits {
                required_record_bytes,
                required_blob_bytes,
            } => write!(
                formatter,
                "safety-state limits must allow at least {required_record_bytes} record bytes and {required_blob_bytes} blob bytes"
            ),
            Self::RecordTooLarge => {
                formatter.write_str("safety-state record exceeds its byte limit")
            }
            Self::BlobTooLarge(field) => write!(formatter, "{field} exceeds its byte limit"),
            Self::LengthOverflow(field) => {
                write!(formatter, "{field} length does not fit the codec")
            }
            Self::AllocationFailed(field) => {
                write!(formatter, "could not allocate bounded {field}")
            }
            Self::Truncated(field) => write!(formatter, "truncated {field}"),
            Self::TrailingBytes => formatter.write_str("safety-state record has trailing bytes"),
            Self::InvalidMagic => formatter.write_str("invalid safety-state record magic"),
            Self::UnsupportedCodec(version) => {
                write!(formatter, "unsupported safety-state record codec {version}")
            }
            Self::UnsupportedSafetySchema(version) => {
                write!(formatter, "unsupported SafetyState schema {version}")
            }
            Self::UnsupportedEpoch => {
                formatter.write_str("record codec v0 supports epoch zero only")
            }
            Self::UnsupportedEpochAnchor => {
                formatter.write_str("record codec v0 rejects epoch anchors")
            }
            Self::UnknownTag(field, tag) => write!(formatter, "unknown {field} tag {tag}"),
            Self::ConfigMismatch => {
                formatter.write_str("safety-state record configuration mismatch")
            }
            Self::ChecksumMismatch => formatter.write_str("safety-state record checksum mismatch"),
            Self::NonCanonical => formatter.write_str("non-canonical safety-state record"),
            Self::InvalidConsensusValue(field) => {
                write!(formatter, "invalid persisted consensus value: {field}")
            }
        }
    }
}

/// Returns a conservative codec-v0 capacity envelope for every SafetyState
/// that the supplied Core configuration can durably reach.
///
/// The bound derives the largest epoch-zero QC, TC, certified header, and
/// finality proof from the active validator identifiers and the frozen CEV0
/// layouts. It also includes Core's aggregate proposal-obligation budget and
/// every bounded SafetyState collection. This makes capacity failure a
/// startup/configuration decision instead of a new failure mode after Core has
/// entered a persistence barrier.
pub fn minimum_safety_state_record_limits_v0(
    config: &CoreConfig,
) -> Result<SafetyStateRecordLimitsV0, SafetyStateRecordErrorV0> {
    config
        .validate()
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("Core configuration"))?;
    require_epoch_zero(config.validator_set().epoch())?;

    let chain_id_bytes = config.validator_set().chain_id().as_bytes().len();
    let validators = config.validator_set().validators();
    let validator_count = validators.len();
    let maximum_validator_id_bytes = validators
        .iter()
        .map(|validator| validator.id().as_bytes().len())
        .max()
        .unwrap_or(0);
    let aggregate_validator_id_bytes = validators.iter().try_fold(0usize, |total, validator| {
        checked_capacity_add(total, validator.id().as_bytes().len())
    })?;

    // Ordinary QC: fixed certificate scope plus every validator ID, its u32
    // frame, and one 64-byte signature.
    let maximum_qc_bytes = checked_capacity_add(
        checked_capacity_add(132, chain_id_bytes)?,
        checked_capacity_add(
            aggregate_validator_id_bytes,
            checked_capacity_mul(validator_count, 68)?,
        )?,
    )?;
    // TC: fixed scope, one entry per validator (ID + QcRef + signature), one
    // maximum ordinary QC per reference, and selected-QC digest.
    let maximum_tc_bytes = checked_capacity_add(
        checked_capacity_add(
            checked_capacity_add(92, chain_id_bytes)?,
            checked_capacity_add(
                aggregate_validator_id_bytes,
                checked_capacity_mul(validator_count, 156)?,
            )?,
        )?,
        checked_capacity_add(36, checked_capacity_mul(validator_count, maximum_qc_bytes)?)?,
    )?;
    // BlockHeader CEV0 with the longest active proposer ID and a present
    // next-epoch commitment (the latter is conservative for epoch-zero Core).
    let maximum_header_bytes = checked_capacity_add(
        checked_capacity_add(334, chain_id_bytes)?,
        maximum_validator_id_bytes,
    )?;
    let maximum_certified_header_bytes = checked_capacity_add(
        checked_capacity_add(
            maximum_header_bytes,
            checked_capacity_mul(2, maximum_qc_bytes)?,
        )?,
        checked_capacity_add(maximum_tc_bytes, 66)?,
    )?;
    let maximum_finality_bytes = checked_capacity_add(
        checked_capacity_add(112, chain_id_bytes)?,
        checked_capacity_mul(3, maximum_certified_header_bytes)?,
    )?;

    let maximum_message_bytes =
        config.consensus_parameters().max_consensus_message_bytes() as usize;
    let observed_slots = config.max_observed_messages();
    let validator_set_bytes = config
        .validator_set()
        .try_cev0_bytes()
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("validator set"))?
        .len();
    let required_blob_bytes = maximum_message_bytes
        .max(config.max_block_bytes())
        .max(validator_set_bytes)
        .max(config.consensus_parameters().canonical_bytes().len())
        .max(maximum_qc_bytes)
        .max(maximum_tc_bytes)
        .max(maximum_header_bytes)
        .max(maximum_finality_bytes);

    let high_and_lock = checked_capacity_mul(2, checked_capacity_add(4, maximum_qc_bytes)?)?;
    let terminal_facts = checked_capacity_mul(observed_slots, MAX_TERMINAL_FACT_BYTES)?;
    let obligations = checked_capacity_add(
        maximum_message_bytes,
        checked_capacity_mul(observed_slots, 8)?,
    )?;
    // The largest completion is the 234-byte inert Valid form: the prior
    // 106-byte snapshot plus the complete 128-byte artifact/overlay ref.
    let completions = checked_capacity_mul(observed_slots, 234)?;
    let pending_tc = checked_capacity_add(5, maximum_tc_bytes)?;
    let standalone_qcs = checked_capacity_add(
        5,
        checked_capacity_mul(
            observed_slots
                .checked_add(1)
                .ok_or(SafetyStateRecordErrorV0::LengthOverflow(
                    "minimum safety-state record bytes",
                ))?,
            checked_capacity_add(4, maximum_qc_bytes)?,
        )?,
    )?;
    let finalization = checked_capacity_add(157, maximum_finality_bytes)?;
    // Optional tag + exact genesis parent tip + the bounded proof blob.
    let state_sync_anchor = checked_capacity_add(61, maximum_finality_bytes)?;
    let finalization_queue = checked_capacity_add(
        4,
        checked_capacity_mul(
            config.max_blocks(),
            checked_capacity_add(156, maximum_finality_bytes)?,
        )?,
    )?;
    let conflicting_qc_halt = checked_capacity_add(
        2,
        checked_capacity_mul(2, checked_capacity_add(4, maximum_qc_bytes)?)?,
    )?;
    let timeout_halt = checked_capacity_add(39, maximum_tc_bytes)?;
    let maximum_halt = conflicting_qc_halt.max(timeout_halt);

    let state_record_bytes = [
        4096usize,
        chain_id_bytes,
        145, // optional authenticated genesis application parent
        high_and_lock,
        terminal_facts,
        obligations,
        completions,
        pending_tc,
        standalone_qcs,
        170, // largest pending SignIntent including its option tag
        finalization,
        state_sync_anchor,
        56, // application-applied FinalizedTip
        finalization_queue,
        33, // pending-finalize option plus CertificateId
        maximum_halt,
    ]
    .into_iter()
    .try_fold(0usize, checked_capacity_add)?;
    let required_record_bytes = state_record_bytes.max(checked_capacity_add(
        required_blob_bytes,
        1024, // metadata/config-ref framing and the outer record checksum
    )?);

    SafetyStateRecordLimitsV0::new(required_record_bytes, required_blob_bytes)
}

fn checked_capacity_add(left: usize, right: usize) -> Result<usize, SafetyStateRecordErrorV0> {
    left.checked_add(right)
        .ok_or(SafetyStateRecordErrorV0::LengthOverflow(
            "minimum safety-state record bytes",
        ))
}

fn checked_capacity_mul(left: usize, right: usize) -> Result<usize, SafetyStateRecordErrorV0> {
    left.checked_mul(right)
        .ok_or(SafetyStateRecordErrorV0::LengthOverflow(
            "minimum safety-state record bytes",
        ))
}

pub fn safety_state_record_config_ref_v0(
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<[u8; 32], SafetyStateRecordErrorV0> {
    let config = context.core_config;
    require_epoch_zero(config.validator_set().epoch())?;
    let mut encoder = Encoder::new_with_blob_limit(
        context.limits.maximum_record_bytes,
        context.limits.maximum_blob_bytes,
    );
    encoder.bytes_u16("local validator", config.local_validator().as_bytes())?;
    encoder.blob(
        "validator set",
        &config
            .validator_set()
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("validator set"))?,
        context.limits.maximum_blob_bytes,
    )?;
    encoder.blob(
        "consensus parameters",
        &config.consensus_parameters().canonical_bytes(),
        context.limits.maximum_blob_bytes,
    )?;
    encoder.u64(config.trusted_genesis_timestamp_ms())?;
    encode_optional(
        config.authenticated_genesis_application_parent_v0(),
        &mut encoder,
        encode_authenticated_genesis_application_parent,
    )?;
    encoder.u64(usize_to_u64(config.max_blocks(), "max_blocks")?)?;
    encoder.u64(usize_to_u64(
        config.max_observed_messages(),
        "max_observed_messages",
    )?)?;
    encoder.fixed(&context.verifier_profile_ref)?;
    encoder.fixed(&hash_domain(LAYOUT_DOMAIN, &[LAYOUT_DESCRIPTION]))?;
    encoder.u64(usize_to_u64(
        context.limits.maximum_record_bytes,
        "maximum record bytes",
    )?)?;
    encoder.u64(usize_to_u64(
        context.limits.maximum_blob_bytes,
        "maximum blob bytes",
    )?)?;
    Ok(hash_domain(CONFIG_DOMAIN, &[encoder.as_slice()]))
}

pub fn encode_safety_state_record_v0(
    state: &SafetyState,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<Vec<u8>, SafetyStateRecordErrorV0> {
    validate_state_scope(state, context)?;
    let config_ref = safety_state_record_config_ref_v0(context)?;
    let mut payload = Encoder::new_with_blob_limit(
        context.limits.maximum_record_bytes,
        context.limits.maximum_blob_bytes,
    );
    encode_state_payload(state, context, &mut payload)?;
    let payload = payload.finish();

    let mut record = Encoder::new(context.limits.maximum_record_bytes);
    record.fixed(MAGIC)?;
    record.u16(SAFETY_STATE_RECORD_CODEC_VERSION_V0)?;
    record.u16(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0)?;
    record.fixed(&config_ref)?;
    record.blob(
        "SafetyState payload",
        &payload,
        context.limits.maximum_record_bytes,
    )?;
    let checksum = hash_domain(RECORD_DOMAIN, &[record.as_slice()]);
    record.fixed(&checksum)?;
    Ok(record.finish())
}

pub fn decode_safety_state_record_v0_exact(
    bytes: &[u8],
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<UnverifiedSafetyStateRecordV0, SafetyStateRecordErrorV0> {
    if bytes.len() > context.limits.maximum_record_bytes {
        return Err(SafetyStateRecordErrorV0::RecordTooLarge);
    }
    let mut cursor = Decoder::new(bytes, context.limits);
    if cursor.fixed::<8>("record magic")? != *MAGIC {
        return Err(SafetyStateRecordErrorV0::InvalidMagic);
    }
    let codec = cursor.u16("record codec")?;
    if codec != SAFETY_STATE_RECORD_CODEC_VERSION_V0 {
        return Err(SafetyStateRecordErrorV0::UnsupportedCodec(codec));
    }
    let schema = cursor.u16("SafetyState schema")?;
    if schema != SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0 {
        return Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(schema));
    }
    let stored_config_ref = cursor.fixed::<32>("configuration reference")?;
    if stored_config_ref != safety_state_record_config_ref_v0(context)? {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    let payload = cursor.record_blob("SafetyState payload", context.limits.maximum_record_bytes)?;
    let checksum_offset = cursor.position();
    let stored_checksum = cursor.fixed::<32>("record checksum")?;
    cursor.finish()?;
    let expected_checksum = hash_domain(RECORD_DOMAIN, &[&bytes[..checksum_offset]]);
    if stored_checksum != expected_checksum {
        return Err(SafetyStateRecordErrorV0::ChecksumMismatch);
    }

    let mut payload_cursor = Decoder::new(payload, context.limits);
    let state = decode_state_payload(&mut payload_cursor, context)?;
    payload_cursor.finish()?;
    let canonical = encode_safety_state_record_v0(&state, context)?;
    if canonical.as_slice() != bytes {
        return Err(SafetyStateRecordErrorV0::NonCanonical);
    }
    Ok(UnverifiedSafetyStateRecordV0 {
        state,
        record_checksum: stored_checksum,
    })
}

fn validate_state_scope(
    state: &SafetyState,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<(), SafetyStateRecordErrorV0> {
    if state.schema_version() != SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0 {
        return Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(
            state.schema_version(),
        ));
    }
    require_epoch_zero(state.epoch())?;
    let config = context.core_config;
    require_epoch_zero(config.validator_set().epoch())?;
    if state.chain_id() != config.validator_set().chain_id()
        || state.protocol_version() != config.validator_set().protocol_version()
        || state.epoch() != config.validator_set().epoch()
        || state.validator_set_id() != config.validator_set().id()
        || state.genesis_block_id() != config.genesis_block_id()
        || state.authenticated_genesis_application_parent_v0().copied()
            != config
                .authenticated_genesis_application_parent_v0()
                .copied()
    {
        return Err(SafetyStateRecordErrorV0::ConfigMismatch);
    }
    Ok(())
}

fn require_epoch_zero(epoch: Epoch) -> Result<(), SafetyStateRecordErrorV0> {
    if epoch != Epoch::new(0) {
        return Err(SafetyStateRecordErrorV0::UnsupportedEpoch);
    }
    Ok(())
}

fn encode_state_payload(
    state: &SafetyState,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.bytes_u16("chain ID", state.chain_id().as_bytes())?;
    encoder.u32(state.protocol_version().get())?;
    encoder.u64(state.epoch().get())?;
    encoder.fixed(state.validator_set_id().as_bytes())?;
    encoder.fixed(state.genesis_block_id().as_bytes())?;
    encode_optional(
        state.authenticated_genesis_application_parent_v0(),
        encoder,
        encode_authenticated_genesis_application_parent,
    )?;
    encoder.u64(state.current_view().get())?;
    encode_optional_view(state.last_voted_view(), encoder)?;
    encode_optional_view(state.last_timeout_view(), encoder)?;
    encode_qc_reference(state.high_qc(), context, encoder)?;
    encode_qc_reference(state.locked_qc(), context, encoder)?;
    encode_finalized_tip(state.finalized(), encoder)?;
    encoder.u64(state.revision())?;

    encode_count(
        state.payload_terminal_facts().len(),
        context.core_config.max_observed_messages(),
        "payload terminal facts",
        encoder,
    )?;
    for fact in state.payload_terminal_facts() {
        encoder.fixed(fact.block_id().as_bytes())?;
        match fact.result() {
            PayloadTerminalResult::Valid => {
                encoder.u8(TAG_TERMINAL_VALID)?;
                let overlay =
                    fact.valid_overlay()
                        .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue(
                            "Valid terminal overlay",
                        ))?;
                encode_overlay_ref(overlay, encoder)?;
            }
            PayloadTerminalResult::DeterministicallyInvalid => {
                if fact.valid_overlay().is_some() {
                    return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                        "invalid terminal overlay",
                    ));
                }
                encoder.u8(TAG_TERMINAL_INVALID)?;
            }
        }
        encoder.u64(fact.first_recorded_revision())?;
    }

    encode_count(
        state.payload_validation_obligations().len(),
        context.core_config.max_observed_messages(),
        "validation obligations",
        encoder,
    )?;
    for obligation in state.payload_validation_obligations() {
        encode_obligation(obligation, context, encoder)?;
    }

    encode_count(
        state.payload_validation_completions().len(),
        context.core_config.max_observed_messages(),
        "validation completions",
        encoder,
    )?;
    for completion in state.payload_validation_completions() {
        encode_completion(completion, encoder)?;
    }

    encode_optional(
        state.pending_tc_high_qc_sync(),
        encoder,
        |pending, encoder| {
            encode_timeout_certificate(pending.timeout_certificate(), context, encoder)
        },
    )?;
    encode_optional(
        state.pending_standalone_qc_sync(),
        encoder,
        |pending, encoder| {
            encode_ordinary_qc(pending.active(), context, encoder)?;
            encode_count(
                pending.backlog().len(),
                context.core_config.max_observed_messages(),
                "standalone QC backlog",
                encoder,
            )?;
            for certificate in pending.backlog() {
                encode_ordinary_qc(certificate, context, encoder)?;
            }
            Ok(())
        },
    )?;
    encode_optional(state.pending_sign(), encoder, encode_sign_intent)?;
    encode_optional(
        state.last_finalization(),
        encoder,
        |finalization, encoder| encode_durable_finalization(finalization, context, encoder),
    )?;
    encode_optional(state.state_sync_anchor(), encoder, |anchor, encoder| {
        encode_durable_state_sync_anchor(anchor, context, encoder)
    })?;
    encode_finalized_tip(state.application_applied(), encoder)?;
    encode_count(
        state.finalization_queue().len(),
        context.core_config.max_blocks(),
        "application finalization queue",
        encoder,
    )?;
    for finalization in state.finalization_queue() {
        encode_durable_finalization(finalization, context, encoder)?;
    }
    encode_optional_certificate(state.pending_finalize(), encoder)?;
    encode_optional(state.safety_halt(), encoder, |halt, encoder| {
        encode_safety_halt(halt, context, encoder)
    })?;
    Ok(())
}

fn decode_state_payload(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<SafetyState, SafetyStateRecordErrorV0> {
    let chain_id = ChainId::from_bytes(decoder.bytes_u16("chain ID")?)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("chain ID"))?;
    let protocol_version = ProtocolVersion::new(decoder.u32("protocol version")?)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("protocol version"))?;
    let epoch = Epoch::new(decoder.u64("epoch")?);
    require_epoch_zero(epoch)?;
    let validator_set_id = ValidatorSetId::new(decoder.fixed::<32>("validator-set ID")?);
    let genesis_block_id = BlockId::new(decoder.fixed::<32>("genesis block ID")?);
    let authenticated_genesis_application_parent = decode_optional(
        decoder,
        "authenticated genesis application parent",
        decode_authenticated_genesis_application_parent,
    )?;
    let current_view = View::new(decoder.u64("current view")?);
    let last_voted_view = decode_optional_view(decoder, "last voted view")?;
    let last_timeout_view = decode_optional_view(decoder, "last timeout view")?;
    let high_qc = decode_qc_reference(decoder, context)?;
    let locked_qc = decode_qc_reference(decoder, context)?;
    let finalized = decode_finalized_tip(decoder)?;
    let revision = decoder.u64("revision")?;

    let terminal_count = decoder.count(
        "payload terminal facts",
        context.core_config.max_observed_messages(),
        MIN_TERMINAL_FACT_BYTES,
    )?;
    let mut payload_terminal_facts = Vec::new();
    for _ in 0..terminal_count {
        payload_terminal_facts
            .try_reserve(1)
            .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed("terminal facts"))?;
        let block_id = BlockId::new(decoder.fixed::<32>("terminal block ID")?);
        let (result, valid_overlay) = match decoder.u8("terminal result")? {
            TAG_TERMINAL_VALID => (
                PayloadTerminalResult::Valid,
                Some(decode_overlay_ref(decoder)?),
            ),
            TAG_TERMINAL_INVALID => (PayloadTerminalResult::DeterministicallyInvalid, None),
            tag => return Err(SafetyStateRecordErrorV0::UnknownTag("terminal result", tag)),
        };
        payload_terminal_facts.push(PayloadTerminalFact::from_persisted_parts(
            block_id,
            result,
            valid_overlay,
            decoder.u64("terminal first revision")?,
        ));
    }

    let obligation_count = decoder.count(
        "validation obligations",
        context.core_config.max_observed_messages(),
        MIN_VALIDATION_OBLIGATION_BYTES,
    )?;
    let mut payload_validation_obligations = Vec::new();
    for _ in 0..obligation_count {
        payload_validation_obligations
            .try_reserve(1)
            .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed("validation obligations"))?;
        payload_validation_obligations.push(decode_obligation(decoder, context)?);
    }

    let completion_count = decoder.count(
        "validation completions",
        context.core_config.max_observed_messages(),
        MIN_VALIDATION_COMPLETION_BYTES,
    )?;
    let mut payload_validation_completions = Vec::new();
    for _ in 0..completion_count {
        payload_validation_completions
            .try_reserve(1)
            .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed("validation completions"))?;
        payload_validation_completions.push(decode_completion(decoder)?);
    }

    let pending_tc_high_qc_sync = decode_optional(decoder, "pending TC sync", |decoder| {
        PendingTcHighQcSync::from_timeout_certificate(decode_timeout_certificate(decoder, context)?)
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("pending TC sync"))
    })?;
    let pending_standalone_qc_sync =
        decode_optional(decoder, "pending standalone QC sync", |decoder| {
            let active = decode_ordinary_qc(decoder, context)?;
            let count = decoder.count(
                "standalone QC backlog",
                context.core_config.max_observed_messages(),
                MIN_BLOB_ITEM_BYTES,
            )?;
            let mut backlog = Vec::new();
            for _ in 0..count {
                backlog.try_reserve(1).map_err(|_| {
                    SafetyStateRecordErrorV0::AllocationFailed("standalone QC backlog")
                })?;
                backlog.push(decode_ordinary_qc(decoder, context)?);
            }
            Ok(PendingStandaloneQcSync::from_persisted_parts(
                active, backlog,
            ))
        })?;
    let pending_sign = decode_optional(decoder, "pending sign", decode_sign_intent)?;
    let last_finalization = decode_optional(decoder, "last finalization", |decoder| {
        decode_durable_finalization(decoder, context)
    })?;
    let state_sync_anchor = decode_optional(decoder, "state-sync anchor", |decoder| {
        decode_durable_state_sync_anchor(decoder, context)
    })?;
    let application_applied = decode_finalized_tip(decoder)?;
    let finalization_count = decoder.count(
        "application finalization queue",
        context.core_config.max_blocks(),
        MIN_DURABLE_FINALIZATION_BYTES,
    )?;
    let mut finalization_queue = Vec::new();
    finalization_queue
        .try_reserve(finalization_count)
        .map_err(|_| {
            SafetyStateRecordErrorV0::AllocationFailed("application finalization queue")
        })?;
    for _ in 0..finalization_count {
        finalization_queue.push(decode_durable_finalization(decoder, context)?);
    }
    let pending_finalize = decode_optional_certificate(decoder)?;
    let safety_halt = decode_optional(decoder, "safety halt", |decoder| {
        decode_safety_halt(decoder, context)
    })?;

    let state = SafetyState::from_persisted_parts_v12(
        SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0,
        chain_id,
        protocol_version,
        epoch,
        validator_set_id,
        genesis_block_id,
        authenticated_genesis_application_parent,
        current_view,
        last_voted_view,
        last_timeout_view,
        high_qc,
        locked_qc,
        finalized,
        revision,
        payload_terminal_facts,
        payload_validation_obligations,
        payload_validation_completions,
        pending_tc_high_qc_sync,
        pending_standalone_qc_sync,
        pending_sign,
        last_finalization,
        state_sync_anchor,
        application_applied,
        finalization_queue,
        pending_finalize,
        safety_halt,
    );
    validate_state_scope(&state, context)?;
    Ok(state)
}

fn encode_obligation(
    value: &DurablePayloadValidationObligationV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_route(value.route(), encoder)?;
    encode_validation_id(value.id(), encoder)?;
    encoder.u64(value.first_recorded_revision())?;
    encode_parent(value.parent(), context, encoder)?;
    encode_signed_proposal(value.proposal(), value.parent(), context, encoder)
}

fn decode_obligation(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<DurablePayloadValidationObligationV0, SafetyStateRecordErrorV0> {
    let route = decode_route(decoder)?;
    let id = decode_validation_id(decoder)?;
    let first_recorded_revision = decoder.u64("obligation first revision")?;
    let parent = decode_parent(decoder, context)?;
    let proposal = decode_signed_proposal(decoder, &parent, context)?;
    Ok(DurablePayloadValidationObligationV0::new(
        route,
        id,
        proposal,
        parent,
        first_recorded_revision,
    ))
}

fn encode_completion(
    value: &DurablePayloadValidationCompletionV0,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_route(value.route(), encoder)?;
    encode_validation_id(value.id(), encoder)?;
    encoder.u64(value.first_recorded_revision())?;
    match value.result() {
        DurablePayloadValidationResultV1::Valid {
            commitments,
            artifact_ref,
        } => {
            encoder.u8(TAG_RESULT_VALID)?;
            encoder.fixed(commitments.block_id().as_bytes())?;
            encoder.u64(commitments.logical_block_size())?;
            encoder.u32(commitments.transaction_count())?;
            encoder.u32(commitments.evidence_count())?;
            encode_artifact_ref(artifact_ref, encoder)?;
        }
        DurablePayloadValidationResultV1::Unavailable => encoder.u8(TAG_RESULT_UNAVAILABLE)?,
        DurablePayloadValidationResultV1::DeterministicallyInvalid => {
            encoder.u8(TAG_RESULT_INVALID)?
        }
    }
    Ok(())
}

fn decode_completion(
    decoder: &mut Decoder<'_>,
) -> Result<DurablePayloadValidationCompletionV0, SafetyStateRecordErrorV0> {
    let route = decode_route(decoder)?;
    let id = decode_validation_id(decoder)?;
    let first_recorded_revision = decoder.u64("completion first revision")?;
    let result = match decoder.u8("completion result")? {
        TAG_RESULT_VALID => {
            let commitments = DurableValidatedBlockCommitmentsV1::from_persisted_parts(
                BlockId::new(decoder.fixed::<32>("valid block ID")?),
                decoder.u64("logical block size")?,
                decoder.u32("transaction count")?,
                decoder.u32("evidence count")?,
            );
            DurablePayloadValidationResultV1::Valid {
                commitments,
                artifact_ref: decode_artifact_ref(decoder)?,
            }
        }
        TAG_RESULT_UNAVAILABLE => DurablePayloadValidationResultV1::Unavailable,
        TAG_RESULT_INVALID => DurablePayloadValidationResultV1::DeterministicallyInvalid,
        tag => {
            return Err(SafetyStateRecordErrorV0::UnknownTag(
                "completion result",
                tag,
            ))
        }
    };
    Ok(DurablePayloadValidationCompletionV0::new(
        route,
        id,
        result,
        first_recorded_revision,
    ))
}

fn encode_authenticated_genesis_application_parent(
    value: &AuthenticatedGenesisApplicationParentV0,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    value.validate_shape_v0().map_err(|_| {
        SafetyStateRecordErrorV0::InvalidConsensusValue("authenticated genesis application parent")
    })?;
    encoder.fixed(value.genesis_block_id().as_bytes())?;
    encoder.u64(value.timestamp_ms())?;
    encoder.u64(value.state_version())?;
    encoder.fixed(value.state_root().as_bytes())?;
    encoder.fixed(&value.descriptor_ref())?;
    encoder.fixed(&value.projection_profile_ref())?;
    Ok(())
}

fn decode_authenticated_genesis_application_parent(
    decoder: &mut Decoder<'_>,
) -> Result<AuthenticatedGenesisApplicationParentV0, SafetyStateRecordErrorV0> {
    AuthenticatedGenesisApplicationParentV0::new(
        BlockId::new(decoder.fixed::<32>("authenticated genesis application block ID")?),
        decoder.u64("authenticated genesis application timestamp")?,
        decoder.u64("authenticated genesis application state version")?,
        StateRoot::new(decoder.fixed::<32>("authenticated genesis application state root")?),
        decoder.fixed::<32>("authenticated genesis application descriptor reference")?,
        decoder.fixed::<32>("authenticated genesis application projection profile")?,
    )
    .map_err(|_| {
        SafetyStateRecordErrorV0::InvalidConsensusValue("authenticated genesis application parent")
    })
}

fn encode_parent(
    value: &PayloadValidationParentV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_finalized_tip(value.tip(), encoder)?;
    match value.provenance() {
        PayloadValidationParentProvenanceV0::Finalized => {
            encoder.u8(TAG_PARENT_FINALIZED)?;
        }
        PayloadValidationParentProvenanceV0::Speculative(overlay) => {
            encoder.u8(TAG_PARENT_SPECULATIVE)?;
            encode_overlay_ref(overlay, encoder)?;
        }
    }
    match (
        value.exact_header(),
        value.authenticated_genesis_application_parent_v0(),
        value.is_legacy_trusted_genesis_v0(),
    ) {
        (Some(header), None, false) => {
            encoder.u8(TAG_PARENT_CARRIER_EXACT_HEADER)?;
            encoder.blob(
                "parent header",
                &header.try_cev0_bytes().map_err(|_| {
                    SafetyStateRecordErrorV0::InvalidConsensusValue("parent header")
                })?,
                context.limits.maximum_blob_bytes,
            )?;
        }
        (None, Some(parent), false) => {
            if !matches!(
                value.provenance(),
                PayloadValidationParentProvenanceV0::Finalized
            ) {
                return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                    "authenticated genesis application parent provenance",
                ));
            }
            encoder.u8(TAG_PARENT_CARRIER_AUTHENTICATED_GENESIS_APPLICATION)?;
            encode_authenticated_genesis_application_parent(&parent, encoder)?;
        }
        (None, None, true) => {
            if !matches!(
                value.provenance(),
                PayloadValidationParentProvenanceV0::Finalized
            ) {
                return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                    "legacy genesis parent provenance",
                ));
            }
            encoder.u8(TAG_PARENT_CARRIER_LEGACY_GENESIS)?;
        }
        _ => {
            return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "payload parent carrier",
            ))
        }
    }
    Ok(())
}

fn decode_parent(
    decoder: &mut Decoder<'_>,
    _context: &SafetyStateRecordContextV0<'_>,
) -> Result<PayloadValidationParentV0, SafetyStateRecordErrorV0> {
    let tip = decode_finalized_tip(decoder)?;
    let provenance = match decoder.u8("parent provenance")? {
        TAG_PARENT_FINALIZED => PayloadValidationParentProvenanceV0::Finalized,
        TAG_PARENT_SPECULATIVE => {
            PayloadValidationParentProvenanceV0::Speculative(decode_overlay_ref(decoder)?)
        }
        tag => {
            return Err(SafetyStateRecordErrorV0::UnknownTag(
                "parent provenance",
                tag,
            ))
        }
    };
    let parent = match decoder.u8("parent carrier")? {
        TAG_PARENT_CARRIER_LEGACY_GENESIS => {
            if !matches!(provenance, PayloadValidationParentProvenanceV0::Finalized) {
                return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                    "legacy genesis parent provenance",
                ));
            }
            PayloadValidationParentV0::trusted_genesis(tip)
        }
        TAG_PARENT_CARRIER_AUTHENTICATED_GENESIS_APPLICATION => {
            if !matches!(provenance, PayloadValidationParentProvenanceV0::Finalized) {
                return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                    "authenticated genesis application parent provenance",
                ));
            }
            let authenticated = decode_authenticated_genesis_application_parent(decoder)?;
            PayloadValidationParentV0::authenticated_genesis_application(tip, authenticated)
                .map_err(|_| {
                    SafetyStateRecordErrorV0::InvalidConsensusValue(
                        "authenticated genesis application parent",
                    )
                })?
        }
        TAG_PARENT_CARRIER_EXACT_HEADER => {
            let header = decode_block_header_v0_exact(
                decoder.blob("parent header", decoder.limits.maximum_blob_bytes)?,
            )
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("parent header"))?;
            match provenance {
                PayloadValidationParentProvenanceV0::Finalized => {
                    PayloadValidationParentV0::from_finalized_exact_header(header)
                }
                PayloadValidationParentProvenanceV0::Speculative(overlay) => {
                    if overlay.block_id() != header.id()
                        || overlay.parent_block_id() != header.parent_id()
                    {
                        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                            "speculative parent overlay",
                        ));
                    }
                    PayloadValidationParentV0::from_speculative_exact_header(header, overlay)
                }
            }
        }
        tag => return Err(SafetyStateRecordErrorV0::UnknownTag("parent carrier", tag)),
    };
    if parent.tip() != tip {
        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "parent tip",
        ));
    }
    Ok(parent)
}

fn encode_signed_proposal(
    proposal: &SignedProposalV0,
    _parent: &PayloadValidationParentV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    let block = proposal.block();
    if block.logical_block_size() > context.core_config.max_block_bytes() {
        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "proposal block size",
        ));
    }
    encoder.blob(
        "proposal header",
        &block
            .header()
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("proposal header"))?,
        context.limits.maximum_blob_bytes,
    )?;
    encoder.blob(
        "application payload",
        block.application_payload(),
        context.core_config.max_block_bytes(),
    )?;
    encode_count(
        block.evidence_objects().len(),
        usize::MAX,
        "proposal evidence",
        encoder,
    )?;
    for evidence in block.evidence_objects() {
        encoder.blob(
            "evidence object",
            evidence,
            context.core_config.max_block_bytes(),
        )?;
    }
    let witness = proposal.witness();
    encode_qc_reference(witness.justify_qc(), context, encoder)?;
    encode_optional(
        witness.timeout_certificate(),
        encoder,
        |certificate, encoder| encode_timeout_certificate(certificate, context, encoder),
    )?;
    if witness.epoch_anchor_authorization().is_some() {
        return Err(SafetyStateRecordErrorV0::UnsupportedEpochAnchor);
    }
    encoder.u8(TAG_NONE)?;
    encoder.fixed(witness.proposer_signature().as_bytes())
}

fn decode_signed_proposal(
    decoder: &mut Decoder<'_>,
    parent: &PayloadValidationParentV0,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<SignedProposalV0, SafetyStateRecordErrorV0> {
    let header_bytes = decoder.blob("proposal header", decoder.limits.maximum_blob_bytes)?;
    let header = decode_block_header_v0_exact(header_bytes)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("proposal header"))?;
    let application_payload_bytes =
        decoder.blob("application payload", context.core_config.max_block_bytes())?;
    if application_payload_bytes.is_empty() {
        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "application payload",
        ));
    }
    let application_payload = copy_bytes(application_payload_bytes, "application payload")?;
    let mut logical_block_size = header_bytes
        .len()
        .checked_add(4)
        .and_then(|size| size.checked_add(application_payload_bytes.len()))
        .and_then(|size| size.checked_add(4))
        .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "proposal block size",
        ))?;
    if logical_block_size > context.core_config.max_block_bytes() {
        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
            "proposal block size",
        ));
    }
    let remaining_block_bytes = context
        .core_config
        .max_block_bytes()
        .saturating_sub(logical_block_size);
    let evidence_count = decoder.count(
        "proposal evidence",
        remaining_block_bytes / MIN_NONEMPTY_BLOB_ITEM_BYTES,
        MIN_NONEMPTY_BLOB_ITEM_BYTES,
    )?;
    let mut evidence = Vec::new();
    for _ in 0..evidence_count {
        evidence
            .try_reserve(1)
            .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed("proposal evidence"))?;
        let evidence_bytes =
            decoder.blob("evidence object", context.core_config.max_block_bytes())?;
        if evidence_bytes.is_empty() {
            return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "evidence object",
            ));
        }
        logical_block_size = logical_block_size
            .checked_add(4)
            .and_then(|size| size.checked_add(evidence_bytes.len()))
            .ok_or(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "proposal block size",
            ))?;
        if logical_block_size > context.core_config.max_block_bytes() {
            return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "proposal block size",
            ));
        }
        evidence.push(copy_bytes(evidence_bytes, "evidence object")?);
    }
    let justify_qc = decode_qc_reference(decoder, context)?;
    let timeout_certificate = decode_optional(decoder, "proposal TC", |decoder| {
        decode_timeout_certificate(decoder, context)
    })?;
    match decoder.u8("epoch authorization presence")? {
        TAG_NONE => {}
        TAG_SOME => return Err(SafetyStateRecordErrorV0::UnsupportedEpochAnchor),
        tag => {
            return Err(SafetyStateRecordErrorV0::UnknownTag(
                "epoch authorization presence",
                tag,
            ))
        }
    }
    let proposer_signature = Signature64::from_array(decoder.fixed::<64>("proposer signature")?);
    let block = Block::new(header.clone(), application_payload, evidence)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("proposal block"))?;
    let witness = ProposalWitnessV0::new(
        &header,
        justify_qc,
        timeout_certificate,
        None,
        proposer_signature,
        context.core_config.validator_set(),
        None,
        context.core_config.consensus_parameters(),
        parent.tip().timestamp_ms(),
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("proposal witness"))?;
    SignedProposalV0::new(
        block,
        witness,
        context.core_config.validator_set(),
        None,
        context.core_config.consensus_parameters(),
        parent.tip().timestamp_ms(),
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("signed proposal"))
}

fn encode_qc_reference(
    value: &QcReferenceV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    let bytes = if let Some(certificate) = value.as_ordinary() {
        certificate
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("QC reference"))?
    } else {
        match value.as_synthetic() {
            Some(ContextAuthorizedQcV0::Genesis(anchor)) => anchor
                .try_cev0_bytes()
                .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("QC reference"))?,
            Some(ContextAuthorizedQcV0::Epoch(_)) => {
                return Err(SafetyStateRecordErrorV0::UnsupportedEpochAnchor);
            }
            None => {
                return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                    "QC reference",
                ));
            }
        }
    };
    encoder.blob("QC reference", &bytes, context.limits.maximum_blob_bytes)
}

fn decode_qc_reference(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<QcReferenceV0, SafetyStateRecordErrorV0> {
    decode_qc_reference_v0_exact_with_trusted_genesis(
        decoder.blob("QC reference", decoder.limits.maximum_blob_bytes)?,
        context.core_config.validator_set(),
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("QC reference"))
}

fn encode_ordinary_qc(
    value: &QuorumCertificate,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.blob(
        "ordinary QC",
        &value
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("ordinary QC"))?,
        context.limits.maximum_blob_bytes,
    )
}

fn decode_ordinary_qc(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<QuorumCertificate, SafetyStateRecordErrorV0> {
    decode_ordinary_qc_v0_exact(
        decoder.blob("ordinary QC", decoder.limits.maximum_blob_bytes)?,
        context.core_config.validator_set(),
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("ordinary QC"))
}

fn encode_timeout_certificate(
    value: &TimeoutCertificateV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    require_epoch_zero(value.epoch())?;
    encoder.blob(
        "timeout certificate",
        &value
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("timeout certificate"))?,
        context.limits.maximum_blob_bytes,
    )
}

fn decode_timeout_certificate(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<TimeoutCertificateV0, SafetyStateRecordErrorV0> {
    decode_timeout_certificate_v0_exact_with_trusted_genesis(
        decoder.blob("timeout certificate", decoder.limits.maximum_blob_bytes)?,
        context.core_config.validator_set(),
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("timeout certificate"))
}

fn encode_durable_finalization(
    value: &DurableFinalizationV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_finalized_tip(value.authenticated_parent(), encoder)?;
    encode_overlay_ref(value.target_overlay_ref(), encoder)?;
    encode_finality_proof_blob(value.proof(), context, encoder)
}

fn decode_durable_finalization(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<DurableFinalizationV0, SafetyStateRecordErrorV0> {
    let parent = decode_finalized_tip(decoder)?;
    let target_overlay_ref = decode_overlay_ref(decoder)?;
    let proof = decode_finality_proof_blob(decoder, context, parent.timestamp_ms())?;
    DurableFinalizationV0::new(parent, proof, target_overlay_ref)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("durable finalization"))
}

fn encode_durable_state_sync_anchor(
    value: &DurableStateSyncAnchorV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_finalized_tip(value.authenticated_parent(), encoder)?;
    encode_finality_proof_blob(value.proof(), context, encoder)
}

fn decode_durable_state_sync_anchor(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<DurableStateSyncAnchorV0, SafetyStateRecordErrorV0> {
    let parent = decode_finalized_tip(decoder)?;
    let proof = decode_finality_proof_blob(decoder, context, parent.timestamp_ms())?;
    DurableStateSyncAnchorV0::new(parent, proof)
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("durable state-sync anchor"))
}

fn encode_finality_proof_blob(
    proof: &trnm_consensus_types::FinalityProofV0,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.blob(
        "finality proof",
        &proof
            .try_cev0_bytes()
            .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("finality proof"))?,
        context.limits.maximum_blob_bytes,
    )
}

fn decode_finality_proof_blob(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
    authenticated_parent_timestamp_ms: u64,
) -> Result<trnm_consensus_types::FinalityProofV0, SafetyStateRecordErrorV0> {
    decode_finality_proof_v0_exact_with_trusted_genesis(
        decoder.blob("finality proof", decoder.limits.maximum_blob_bytes)?,
        context.core_config.validator_set(),
        context.core_config.consensus_parameters(),
        authenticated_parent_timestamp_ms,
    )
    .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("finality proof"))
}

fn encode_safety_halt(
    value: &SafetyHalt,
    context: &SafetyStateRecordContextV0<'_>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    match value {
        SafetyHalt::ConflictingQuorumCertificates { first, second } => {
            encoder.u8(TAG_HALT_CONFLICTING_QCS)?;
            encode_ordinary_qc(first, context, encoder)?;
            encode_ordinary_qc(second, context, encoder)
        }
        SafetyHalt::ConflictingPayloadValidation {
            block_id,
            first: PayloadTerminalResult::Valid,
            second: PayloadTerminalResult::DeterministicallyInvalid,
        } => {
            encoder.u8(TAG_HALT_PAYLOAD_CONFLICT)?;
            encoder.fixed(block_id.as_bytes())
        }
        SafetyHalt::ConflictingPayloadValidation { .. } => Err(
            SafetyStateRecordErrorV0::InvalidConsensusValue("payload-conflict halt ordering"),
        ),
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference,
        } => {
            encoder.u8(TAG_HALT_INVALID_PAYLOAD)?;
            encoder.fixed(block_id.as_bytes())?;
            match reference {
                InvalidPayloadReference::QuorumCertificate(certificate) => {
                    encoder.u8(TAG_INVALID_REFERENCE_QC)?;
                    encode_ordinary_qc(certificate, context, encoder)
                }
                InvalidPayloadReference::TimeoutCertificate(certificate) => {
                    encoder.u8(TAG_INVALID_REFERENCE_TC)?;
                    encode_timeout_certificate(certificate, context, encoder)
                }
                InvalidPayloadReference::PendingVote(intent) => {
                    encoder.u8(TAG_INVALID_REFERENCE_VOTE)?;
                    encode_sign_intent(intent, encoder)
                }
            }
        }
    }
}

fn decode_safety_halt(
    decoder: &mut Decoder<'_>,
    context: &SafetyStateRecordContextV0<'_>,
) -> Result<SafetyHalt, SafetyStateRecordErrorV0> {
    match decoder.u8("safety halt")? {
        TAG_HALT_CONFLICTING_QCS => SafetyHalt::from_conflicting_qcs(
            decode_ordinary_qc(decoder, context)?,
            decode_ordinary_qc(decoder, context)?,
        )
        .map_err(|_| SafetyStateRecordErrorV0::InvalidConsensusValue("conflicting QCs")),
        TAG_HALT_PAYLOAD_CONFLICT => Ok(SafetyHalt::conflicting_payload_validation(BlockId::new(
            decoder.fixed::<32>("conflicting payload block")?,
        ))),
        TAG_HALT_INVALID_PAYLOAD => {
            let block_id = BlockId::new(decoder.fixed::<32>("invalid payload block")?);
            let reference = match decoder.u8("invalid payload reference")? {
                TAG_INVALID_REFERENCE_QC => InvalidPayloadReference::QuorumCertificate(Box::new(
                    decode_ordinary_qc(decoder, context)?,
                )),
                TAG_INVALID_REFERENCE_TC => InvalidPayloadReference::TimeoutCertificate(Box::new(
                    decode_timeout_certificate(decoder, context)?,
                )),
                TAG_INVALID_REFERENCE_VOTE => {
                    InvalidPayloadReference::PendingVote(Box::new(decode_sign_intent(decoder)?))
                }
                tag => {
                    return Err(SafetyStateRecordErrorV0::UnknownTag(
                        "invalid payload reference",
                        tag,
                    ))
                }
            };
            SafetyHalt::deterministically_invalid_payload(block_id, reference).map_err(|_| {
                SafetyStateRecordErrorV0::InvalidConsensusValue("invalid payload halt")
            })
        }
        tag => Err(SafetyStateRecordErrorV0::UnknownTag("safety halt", tag)),
    }
}

fn encode_sign_intent(
    value: &SignIntent,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    match value {
        SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            signing_root,
        } => {
            encoder.u8(TAG_SIGN_VOTE)?;
            encoder.u64(*authorizing_safety_revision)?;
            encoder.u64(view.get())?;
            encoder.u64(height.get())?;
            encoder.fixed(block_id.as_bytes())?;
            encoder.fixed(signing_root.as_bytes())
        }
        SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            signing_root,
        } => {
            encoder.u8(TAG_SIGN_TIMEOUT)?;
            encoder.u64(*authorizing_safety_revision)?;
            encoder.u64(view.get())?;
            encode_qc_ref(*high_qc, encoder)?;
            encoder.fixed(signing_root.as_bytes())
        }
    }
}

fn decode_sign_intent(decoder: &mut Decoder<'_>) -> Result<SignIntent, SafetyStateRecordErrorV0> {
    match decoder.u8("sign intent")? {
        TAG_SIGN_VOTE => Ok(SignIntent::Vote {
            authorizing_safety_revision: decoder.u64("vote authorizing revision")?,
            view: View::new(decoder.u64("vote view")?),
            height: Height::new(decoder.u64("vote height")?),
            block_id: BlockId::new(decoder.fixed::<32>("vote block ID")?),
            signing_root: SigningRoot::new(decoder.fixed::<32>("vote signing root")?),
        }),
        TAG_SIGN_TIMEOUT => Ok(SignIntent::TimeoutVote {
            authorizing_safety_revision: decoder.u64("timeout authorizing revision")?,
            view: View::new(decoder.u64("timeout-vote view")?),
            high_qc: decode_qc_ref(decoder)?,
            signing_root: SigningRoot::new(decoder.fixed::<32>("timeout signing root")?),
        }),
        tag => Err(SafetyStateRecordErrorV0::UnknownTag("sign intent", tag)),
    }
}

fn encode_qc_ref(value: QcRef, encoder: &mut Encoder) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.fixed(value.qc_digest().as_bytes())?;
    encoder.u64(value.epoch().get())?;
    encoder.u64(value.view().get())?;
    encoder.u64(value.height().get())?;
    encoder.fixed(value.block_id().as_bytes())?;
    encoder.fixed(value.validator_set_id().as_bytes())
}

fn decode_qc_ref(decoder: &mut Decoder<'_>) -> Result<QcRef, SafetyStateRecordErrorV0> {
    Ok(QcRef::new(
        CertificateId::new(decoder.fixed::<32>("QC digest")?),
        Epoch::new(decoder.u64("QC epoch")?),
        View::new(decoder.u64("QC view")?),
        Height::new(decoder.u64("QC height")?),
        BlockId::new(decoder.fixed::<32>("QC block ID")?),
        ValidatorSetId::new(decoder.fixed::<32>("QC validator-set ID")?),
    ))
}

fn encode_finalized_tip(
    value: FinalizedTip,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.u64(value.height().get())?;
    encoder.u64(value.view().get())?;
    encoder.fixed(value.block_id().as_bytes())?;
    encoder.u64(value.timestamp_ms())
}

fn decode_finalized_tip(
    decoder: &mut Decoder<'_>,
) -> Result<FinalizedTip, SafetyStateRecordErrorV0> {
    Ok(FinalizedTip::new(
        Height::new(decoder.u64("finalized height")?),
        View::new(decoder.u64("finalized view")?),
        BlockId::new(decoder.fixed::<32>("finalized block ID")?),
        decoder.u64("finalized timestamp")?,
    ))
}

fn encode_validation_id(
    value: ValidationId,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.fixed(value.block_id().as_bytes())?;
    encoder.u64(value.view().get())?;
    encoder.u64(value.generation())
}

fn decode_validation_id(
    decoder: &mut Decoder<'_>,
) -> Result<ValidationId, SafetyStateRecordErrorV0> {
    Ok(ValidationId::new(
        BlockId::new(decoder.fixed::<32>("validation block ID")?),
        View::new(decoder.u64("validation view")?),
        decoder.u64("validation generation")?,
    ))
}

fn encode_overlay_ref(
    value: BlockIdOverlayRefV0,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.fixed(value.block_id().as_bytes())?;
    encoder.fixed(value.parent_block_id().as_bytes())?;
    encoder.fixed(&value.overlay_checksum())
}

fn decode_overlay_ref(
    decoder: &mut Decoder<'_>,
) -> Result<BlockIdOverlayRefV0, SafetyStateRecordErrorV0> {
    Ok(BlockIdOverlayRefV0::new(
        BlockId::new(decoder.fixed::<32>("overlay block ID")?),
        BlockId::new(decoder.fixed::<32>("overlay parent block ID")?),
        decoder.fixed::<32>("overlay checksum")?,
    ))
}

fn encode_artifact_ref(
    value: ValidatedPayloadArtifactRefV0,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encode_overlay_ref(value.overlay(), encoder)?;
    encoder.fixed(&value.source_artifact_checksum())
}

fn decode_artifact_ref(
    decoder: &mut Decoder<'_>,
) -> Result<ValidatedPayloadArtifactRefV0, SafetyStateRecordErrorV0> {
    Ok(ValidatedPayloadArtifactRefV0::new(
        decode_overlay_ref(decoder)?,
        decoder.fixed::<32>("source artifact checksum")?,
    ))
}

fn encode_route(
    value: PayloadValidationRouteV0,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    encoder.u8(match value {
        PayloadValidationRouteV0::Proposal => TAG_ROUTE_PROPOSAL,
        PayloadValidationRouteV0::Synced => TAG_ROUTE_SYNCED,
    })
}

fn decode_route(
    decoder: &mut Decoder<'_>,
) -> Result<PayloadValidationRouteV0, SafetyStateRecordErrorV0> {
    match decoder.u8("validation route")? {
        TAG_ROUTE_PROPOSAL => Ok(PayloadValidationRouteV0::Proposal),
        TAG_ROUTE_SYNCED => Ok(PayloadValidationRouteV0::Synced),
        tag => Err(SafetyStateRecordErrorV0::UnknownTag(
            "validation route",
            tag,
        )),
    }
}

fn encode_optional_view(
    value: Option<View>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    match value {
        Some(view) => {
            encoder.u8(TAG_SOME)?;
            encoder.u64(view.get())
        }
        None => encoder.u8(TAG_NONE),
    }
}

fn decode_optional_view(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<View>, SafetyStateRecordErrorV0> {
    match decoder.u8(field)? {
        TAG_NONE => Ok(None),
        TAG_SOME => Ok(Some(View::new(decoder.u64(field)?))),
        tag => Err(SafetyStateRecordErrorV0::UnknownTag(field, tag)),
    }
}

fn encode_optional_certificate(
    value: Option<CertificateId>,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    match value {
        Some(id) => {
            encoder.u8(TAG_SOME)?;
            encoder.fixed(id.as_bytes())
        }
        None => encoder.u8(TAG_NONE),
    }
}

fn decode_optional_certificate(
    decoder: &mut Decoder<'_>,
) -> Result<Option<CertificateId>, SafetyStateRecordErrorV0> {
    match decoder.u8("pending finalize")? {
        TAG_NONE => Ok(None),
        TAG_SOME => Ok(Some(CertificateId::new(
            decoder.fixed::<32>("pending finalize certificate")?,
        ))),
        tag => Err(SafetyStateRecordErrorV0::UnknownTag(
            "pending finalize",
            tag,
        )),
    }
}

fn encode_optional<T>(
    value: Option<&T>,
    encoder: &mut Encoder,
    encode: impl FnOnce(&T, &mut Encoder) -> Result<(), SafetyStateRecordErrorV0>,
) -> Result<(), SafetyStateRecordErrorV0> {
    match value {
        Some(value) => {
            encoder.u8(TAG_SOME)?;
            encode(value, encoder)
        }
        None => encoder.u8(TAG_NONE),
    }
}

fn decode_optional<T>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    decode: impl FnOnce(&mut Decoder<'_>) -> Result<T, SafetyStateRecordErrorV0>,
) -> Result<Option<T>, SafetyStateRecordErrorV0> {
    match decoder.u8(field)? {
        TAG_NONE => Ok(None),
        TAG_SOME => decode(decoder).map(Some),
        tag => Err(SafetyStateRecordErrorV0::UnknownTag(field, tag)),
    }
}

fn encode_count(
    count: usize,
    maximum: usize,
    field: &'static str,
    encoder: &mut Encoder,
) -> Result<(), SafetyStateRecordErrorV0> {
    if count > maximum {
        return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(field));
    }
    encoder.u32(u32::try_from(count).map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?)
}

fn hash_domain(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hash_len_prefixed(&mut hasher, domain.as_bytes());
    for part in parts {
        hash_len_prefixed(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, SafetyStateRecordErrorV0> {
    u64::try_from(value).map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))
}

fn copy_bytes(value: &[u8], field: &'static str) -> Result<Vec<u8>, SafetyStateRecordErrorV0> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(value.len())
        .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed(field))?;
    bytes.extend_from_slice(value);
    Ok(bytes)
}

struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
    maximum_blob: usize,
}

impl Encoder {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            maximum_blob: maximum,
        }
    }

    fn new_with_blob_limit(maximum: usize, maximum_blob: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            maximum_blob,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn append(&mut self, value: &[u8]) -> Result<(), SafetyStateRecordErrorV0> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(SafetyStateRecordErrorV0::RecordTooLarge)?;
        if next > self.maximum {
            return Err(SafetyStateRecordErrorV0::RecordTooLarge);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| SafetyStateRecordErrorV0::AllocationFailed("record buffer"))?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn fixed(&mut self, value: &[u8]) -> Result<(), SafetyStateRecordErrorV0> {
        self.append(value)
    }

    fn u8(&mut self, value: u8) -> Result<(), SafetyStateRecordErrorV0> {
        self.append(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), SafetyStateRecordErrorV0> {
        self.append(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), SafetyStateRecordErrorV0> {
        self.append(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), SafetyStateRecordErrorV0> {
        self.append(&value.to_be_bytes())
    }

    fn bytes_u16(
        &mut self,
        field: &'static str,
        value: &[u8],
    ) -> Result<(), SafetyStateRecordErrorV0> {
        let length = u16::try_from(value.len())
            .map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?;
        self.u16(length)?;
        self.append(value)
    }

    fn blob(
        &mut self,
        field: &'static str,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), SafetyStateRecordErrorV0> {
        if value.len() > maximum.min(self.maximum_blob) {
            return Err(SafetyStateRecordErrorV0::BlobTooLarge(field));
        }
        let length = u32::try_from(value.len())
            .map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?;
        self.u32(length)?;
        self.append(value)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: SafetyStateRecordLimitsV0,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], limits: SafetyStateRecordLimitsV0) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
        }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], SafetyStateRecordErrorV0> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SafetyStateRecordErrorV0::Truncated(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SafetyStateRecordErrorV0::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SafetyStateRecordErrorV0> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| SafetyStateRecordErrorV0::Truncated(field))
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, SafetyStateRecordErrorV0> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, SafetyStateRecordErrorV0> {
        Ok(u16::from_be_bytes(self.fixed(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SafetyStateRecordErrorV0> {
        Ok(u32::from_be_bytes(self.fixed(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SafetyStateRecordErrorV0> {
        Ok(u64::from_be_bytes(self.fixed(field)?))
    }

    fn bytes_u16(&mut self, field: &'static str) -> Result<&'a [u8], SafetyStateRecordErrorV0> {
        let length = usize::from(self.u16(field)?);
        self.take(length, field)
    }

    fn blob(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<&'a [u8], SafetyStateRecordErrorV0> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?;
        if length > maximum.min(self.limits.maximum_blob_bytes) {
            return Err(SafetyStateRecordErrorV0::BlobTooLarge(field));
        }
        self.take(length, field)
    }

    fn record_blob(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<&'a [u8], SafetyStateRecordErrorV0> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?;
        if length > maximum {
            return Err(SafetyStateRecordErrorV0::BlobTooLarge(field));
        }
        self.take(length, field)
    }

    fn count(
        &mut self,
        field: &'static str,
        maximum: usize,
        minimum_item_bytes: usize,
    ) -> Result<usize, SafetyStateRecordErrorV0> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| SafetyStateRecordErrorV0::LengthOverflow(field))?;
        if minimum_item_bytes == 0
            || count > maximum
            || count
                > self
                    .bytes
                    .len()
                    .saturating_sub(self.offset)
                    .checked_div(minimum_item_bytes)
                    .unwrap_or(0)
        {
            return Err(SafetyStateRecordErrorV0::InvalidConsensusValue(field));
        }
        Ok(count)
    }

    fn finish(&self) -> Result<(), SafetyStateRecordErrorV0> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SafetyStateRecordErrorV0::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use trnm_consensus_types::{
        ConsensusParametersV0, ConsensusPublicKey, GenesisHash, GenesisQcV0, SignatureBytes,
        SignatureVerifier, Validator, ValidatorId, VotingPower,
    };

    use super::*;
    use crate::Core;

    #[derive(Debug, Clone, Copy)]
    struct AcceptSignatures;

    impl SignatureVerifier for AcceptSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            true
        }
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::new([index; 32])
    }

    fn test_config_with_parameters(parameters: ConsensusParametersV0) -> CoreConfig {
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let set = trnm_consensus_types::ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            ChainId::from_static("trnm-safety-record-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        CoreConfig::new(validator_id(1), set, parameters, 17, 64, 64).expect("valid Core config")
    }

    fn test_config() -> CoreConfig {
        test_config_with_parameters(ConsensusParametersV0::reference_shadow_v0())
    }

    fn authenticated_genesis_application_config() -> CoreConfig {
        let base = test_config();
        let parent = AuthenticatedGenesisApplicationParentV0::new(
            base.genesis_block_id(),
            base.trusted_genesis_timestamp_ms(),
            0,
            StateRoot::new([0x31; 32]),
            [0x41; 32],
            [0x51; 32],
        )
        .expect("shape-valid authenticated genesis application parent");
        CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            base.local_validator(),
            base.validator_set().clone(),
            *base.consensus_parameters(),
            base.trusted_genesis_timestamp_ms(),
            parent,
            base.max_blocks(),
            base.max_observed_messages(),
        )
        .expect("valid authenticated genesis application config")
    }

    fn limits() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(1 << 26, 1 << 24).expect("valid test limits")
    }

    fn genesis_state(config: &CoreConfig) -> SafetyState {
        let genesis = GenesisQcV0::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set(),
        )
        .expect("valid trusted genesis QC");
        match config
            .authenticated_genesis_application_parent_v0()
            .copied()
        {
            Some(parent) => SafetyState::from_authenticated_genesis_application_for_test_v0(
                config.validator_set(),
                genesis,
                config.trusted_genesis_timestamp_ms(),
                parent,
            )
            .expect("inert authenticated-genesis SafetyState"),
            None => Core::new(config.clone(), genesis, &AcceptSignatures)
                .expect("valid legacy genesis Core")
                .safety_state()
                .clone(),
        }
    }

    #[test]
    fn genesis_record_roundtrips_canonically() {
        let config = test_config();
        let context = SafetyStateRecordContextV0::new(&config, [0x51; 32], limits())
            .expect("capacity-compatible context");
        let state = genesis_state(&config);

        let encoded = encode_safety_state_record_v0(&state, &context).expect("encode genesis");
        let decoded =
            decode_safety_state_record_v0_exact(&encoded, &context).expect("decode genesis");

        assert_eq!(
            safety_state_record_config_ref_v0(&context).expect("config reference"),
            [
                0x74, 0xf2, 0x01, 0x6d, 0xaf, 0xf3, 0x9e, 0xe2, 0x7a, 0x0e, 0x01, 0x68, 0x17, 0xb9,
                0x44, 0x35, 0xee, 0x36, 0x73, 0x0f, 0x71, 0x7d, 0xc4, 0xb6, 0xaf, 0x0d, 0x78, 0x5d,
                0xb2, 0xa4, 0x84, 0x6c,
            ],
            "the schema-v12 configuration reference is frozen"
        );
        assert_eq!(encoded.len(), 653, "the Genesis record layout is frozen");
        assert_eq!(
            decoded.record_checksum(),
            [
                0xbc, 0x8b, 0x99, 0x80, 0xed, 0x04, 0x01, 0x76, 0xb0, 0xb4, 0x71, 0x79, 0xcc, 0x53,
                0xfd, 0xeb, 0x5a, 0x87, 0xec, 0x1c, 0x1d, 0xbd, 0xc9, 0x75, 0x82, 0xf6, 0x77, 0x34,
                0x38, 0x7f, 0x42, 0x0c,
            ],
            "the Genesis record checksum is frozen"
        );

        assert_eq!(decoded.state(), &state);
        assert_eq!(
            encode_safety_state_record_v0(decoded.state(), &context).expect("re-encode genesis"),
            encoded
        );
        assert_eq!(
            decoded.record_checksum(),
            hash_domain(RECORD_DOMAIN, &[&encoded[..encoded.len() - 32]])
        );
    }

    #[test]
    fn authenticated_genesis_application_record_is_frozen_and_v11_fails_closed() {
        let config = authenticated_genesis_application_config();
        let context = SafetyStateRecordContextV0::new(&config, [0x61; 32], limits())
            .expect("capacity-compatible authenticated-genesis context");
        let state = genesis_state(&config);
        let encoded = encode_safety_state_record_v0(&state, &context)
            .expect("encode authenticated-genesis record");
        let decoded = decode_safety_state_record_v0_exact(&encoded, &context)
            .expect("decode authenticated-genesis record");
        assert_eq!(decoded.state(), &state);
        assert_eq!(
            decoded
                .state()
                .authenticated_genesis_application_parent_v0(),
            config.authenticated_genesis_application_parent_v0()
        );
        assert_eq!(
            encoded.len(),
            797,
            "schema-v12 genesis-parent record length"
        );
        assert_eq!(
            safety_state_record_config_ref_v0(&context).expect("config ref"),
            [
                0x3b, 0xfe, 0x9f, 0xbe, 0xe0, 0x2f, 0x5a, 0xd2, 0x43, 0x9b, 0xb1, 0xbf, 0x25, 0xa7,
                0x47, 0x32, 0xaf, 0x14, 0x9b, 0x05, 0x86, 0x17, 0x4e, 0x72, 0xf7, 0x6b, 0x40, 0x56,
                0x56, 0x78, 0x4d, 0x07,
            ],
            "schema-v12 genesis-parent configuration vector is frozen",
        );
        assert_eq!(
            decoded.record_checksum(),
            [
                0x06, 0xd4, 0x76, 0x28, 0x65, 0xf1, 0x13, 0xb7, 0x18, 0xb0, 0xbe, 0x57, 0x12, 0xc9,
                0xfd, 0x5e, 0x9c, 0x51, 0xd7, 0x53, 0x55, 0x56, 0x47, 0xcc, 0x09, 0x20, 0x6a, 0xd6,
                0x0c, 0xd0, 0x50, 0x1f,
            ],
            "schema-v12 genesis-parent record checksum is frozen",
        );

        let mut legacy_schema = encoded.clone();
        legacy_schema[10..12].copy_from_slice(&11u16.to_be_bytes());
        assert_eq!(
            decode_safety_state_record_v0_exact(&legacy_schema, &context),
            Err(SafetyStateRecordErrorV0::UnsupportedSafetySchema(11)),
        );

        let base = test_config();
        let foreign_parent = AuthenticatedGenesisApplicationParentV0::new(
            base.genesis_block_id(),
            base.trusted_genesis_timestamp_ms(),
            0,
            StateRoot::new([0x32; 32]),
            [0x41; 32],
            [0x51; 32],
        )
        .expect("shape-valid foreign root");
        let foreign_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            base.local_validator(),
            base.validator_set().clone(),
            *base.consensus_parameters(),
            base.trusted_genesis_timestamp_ms(),
            foreign_parent,
            base.max_blocks(),
            base.max_observed_messages(),
        )
        .expect("shape-valid foreign config");
        let foreign_context =
            SafetyStateRecordContextV0::new(&foreign_config, [0x61; 32], limits())
                .expect("capacity-compatible foreign context");
        assert_eq!(
            decode_safety_state_record_v0_exact(&encoded, &foreign_context),
            Err(SafetyStateRecordErrorV0::ConfigMismatch),
        );
    }

    #[test]
    fn exact_decoder_rejects_context_corruption_and_non_exact_framing() {
        let config = test_config();
        let context = SafetyStateRecordContextV0::new(&config, [0x51; 32], limits())
            .expect("capacity-compatible context");
        let state = genesis_state(&config);
        let encoded = encode_safety_state_record_v0(&state, &context).expect("encode genesis");

        let foreign_context = SafetyStateRecordContextV0::new(&config, [0x52; 32], limits())
            .expect("capacity-compatible foreign context");
        assert_eq!(
            decode_safety_state_record_v0_exact(&encoded, &foreign_context).unwrap_err(),
            SafetyStateRecordErrorV0::ConfigMismatch
        );

        let mut checksum_drift = encoded.clone();
        *checksum_drift.last_mut().expect("checksum byte") ^= 1;
        assert_eq!(
            decode_safety_state_record_v0_exact(&checksum_drift, &context).unwrap_err(),
            SafetyStateRecordErrorV0::ChecksumMismatch
        );

        assert!(matches!(
            decode_safety_state_record_v0_exact(&encoded[..encoded.len() - 1], &context),
            Err(SafetyStateRecordErrorV0::Truncated("record checksum"))
        ));

        let mut invalid_magic = encoded.clone();
        invalid_magic[0] ^= 1;
        assert_eq!(
            decode_safety_state_record_v0_exact(&invalid_magic, &context).unwrap_err(),
            SafetyStateRecordErrorV0::InvalidMagic
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_safety_state_record_v0_exact(&trailing, &context).unwrap_err(),
            SafetyStateRecordErrorV0::TrailingBytes
        );

        let mut unknown_codec = encoded.clone();
        unknown_codec[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            decode_safety_state_record_v0_exact(&unknown_codec, &context).unwrap_err(),
            SafetyStateRecordErrorV0::UnsupportedCodec(1)
        );

        let mut unknown_schema = encoded;
        unknown_schema[10..12].copy_from_slice(&6u16.to_be_bytes());
        assert_eq!(
            decode_safety_state_record_v0_exact(&unknown_schema, &context).unwrap_err(),
            SafetyStateRecordErrorV0::UnsupportedSafetySchema(6)
        );
        assert_eq!(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0, 12);
    }

    #[test]
    fn configured_record_limit_is_enforced_before_decode_allocation() {
        let config = test_config();
        let context = SafetyStateRecordContextV0::new(&config, [0x51; 32], limits())
            .expect("capacity-compatible context");
        let encoded = encode_safety_state_record_v0(&genesis_state(&config), &context)
            .expect("encode genesis");
        let maximum = encoded.len() - 1;
        let bounded = SafetyStateRecordLimitsV0::new(maximum, maximum)
            .expect("one-byte-short record limit remains structurally valid");
        assert!(matches!(
            SafetyStateRecordContextV0::new(&config, [0x51; 32], bounded),
            Err(SafetyStateRecordErrorV0::InsufficientLimits { .. })
        ));
        let bounded_context = SafetyStateRecordContextV0 {
            core_config: &config,
            verifier_profile_ref: [0x51; 32],
            limits: bounded,
        };

        assert_eq!(
            decode_safety_state_record_v0_exact(&encoded, &bounded_context).unwrap_err(),
            SafetyStateRecordErrorV0::RecordTooLarge
        );

        assert_eq!(
            SafetyStateRecordLimitsV0::new(127, 1),
            Err(SafetyStateRecordErrorV0::InvalidLimits)
        );
        assert_eq!(
            SafetyStateRecordLimitsV0::new(128, 0),
            Err(SafetyStateRecordErrorV0::InvalidLimits)
        );
        assert_eq!(
            SafetyStateRecordLimitsV0::new(128, 129),
            Err(SafetyStateRecordErrorV0::InvalidLimits)
        );
    }

    #[test]
    fn inner_framing_rejects_counts_blobs_and_unknown_tags_before_allocation() {
        let small_limits = SafetyStateRecordLimitsV0::new(128, 16).expect("small valid limits");

        let mut count_over_maximum = Decoder::new(&[0, 0, 0, 2, 0, 0], small_limits);
        assert_eq!(
            count_over_maximum.count("items", 1, 1),
            Err(SafetyStateRecordErrorV0::InvalidConsensusValue("items"))
        );
        let mut count_over_remaining = Decoder::new(&[0, 0, 0, 2, 0], small_limits);
        assert_eq!(
            count_over_remaining.count("items", 2, 1),
            Err(SafetyStateRecordErrorV0::InvalidConsensusValue("items"))
        );

        let mut oversized_blob = Vec::from(17u32.to_be_bytes());
        oversized_blob.extend_from_slice(&[0; 17]);
        assert_eq!(
            Decoder::new(&oversized_blob, small_limits).blob("blob", 16),
            Err(SafetyStateRecordErrorV0::BlobTooLarge("blob"))
        );
        assert_eq!(
            Decoder::new(&[0, 0, 0, 5, 1, 2], small_limits).blob("blob", 16),
            Err(SafetyStateRecordErrorV0::Truncated("blob"))
        );

        assert_eq!(
            decode_route(&mut Decoder::new(&[0xff], small_limits)),
            Err(SafetyStateRecordErrorV0::UnknownTag(
                "validation route",
                0xff
            ))
        );
        assert_eq!(
            decode_optional_view(&mut Decoder::new(&[0xff], small_limits), "optional view",),
            Err(SafetyStateRecordErrorV0::UnknownTag("optional view", 0xff))
        );
        assert_eq!(
            decode_sign_intent(&mut Decoder::new(&[0xff], small_limits)),
            Err(SafetyStateRecordErrorV0::UnknownTag("sign intent", 0xff))
        );

        let config = test_config();
        let parent_limits = limits();
        let context = SafetyStateRecordContextV0::new(&config, [0x51; 32], parent_limits)
            .expect("capacity-compatible parent context");
        let tip = genesis_state(&config).finalized();
        let mut unknown_parent = Encoder::new(parent_limits.maximum_record_bytes());
        encode_finalized_tip(tip, &mut unknown_parent).expect("encode parent tip");
        unknown_parent.u8(0xff).expect("encode unknown tag");
        assert_eq!(
            decode_parent(
                &mut Decoder::new(&unknown_parent.finish(), parent_limits),
                &context,
            ),
            Err(SafetyStateRecordErrorV0::UnknownTag(
                "parent provenance",
                0xff,
            ))
        );

        let mut headerless_speculative = Encoder::new(parent_limits.maximum_record_bytes());
        encode_finalized_tip(tip, &mut headerless_speculative).expect("encode parent tip");
        headerless_speculative
            .u8(TAG_PARENT_SPECULATIVE)
            .expect("encode speculative tag");
        encode_overlay_ref(
            BlockIdOverlayRefV0::new(BlockId::new([1; 32]), BlockId::new([2; 32]), [3; 32]),
            &mut headerless_speculative,
        )
        .expect("encode overlay ref");
        headerless_speculative
            .u8(TAG_NONE)
            .expect("encode absent header");
        assert_eq!(
            decode_parent(
                &mut Decoder::new(&headerless_speculative.finish(), parent_limits),
                &context,
            ),
            Err(SafetyStateRecordErrorV0::InvalidConsensusValue(
                "legacy genesis parent provenance",
            ))
        );

        let authenticated = *authenticated_genesis_application_config()
            .authenticated_genesis_application_parent_v0()
            .expect("configured authenticated genesis parent");
        let authenticated_parent =
            PayloadValidationParentV0::authenticated_genesis_application(tip, authenticated)
                .expect("tip-bound authenticated genesis parent");
        let mut encoded_authenticated = Encoder::new(parent_limits.maximum_record_bytes());
        encode_parent(&authenticated_parent, &context, &mut encoded_authenticated)
            .expect("encode authenticated genesis parent carrier");
        let encoded_authenticated = encoded_authenticated.finish();
        assert_eq!(
            encoded_authenticated[57], TAG_PARENT_CARRIER_AUTHENTICATED_GENESIS_APPLICATION,
            "the authenticated genesis carrier has a distinct closed tag",
        );
        assert_eq!(
            decode_parent(
                &mut Decoder::new(&encoded_authenticated, parent_limits),
                &context,
            )
            .expect("decode authenticated genesis parent carrier"),
            authenticated_parent,
        );
        let mut unknown_carrier = encoded_authenticated;
        unknown_carrier[57] = 0xff;
        assert_eq!(
            decode_parent(&mut Decoder::new(&unknown_carrier, parent_limits), &context,),
            Err(SafetyStateRecordErrorV0::UnknownTag("parent carrier", 0xff,)),
        );

        let mut encoder = Encoder::new_with_blob_limit(128, 4);
        assert_eq!(
            encoder.blob("blob", &[0; 5], 5),
            Err(SafetyStateRecordErrorV0::BlobTooLarge("blob"))
        );
    }

    #[test]
    fn preflight_derives_certificate_bounds_independently_of_message_bytes() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_block_bytes = 4096;
        fields.max_consensus_message_bytes = 4096;
        let parameters =
            ConsensusParametersV0::new(fields).expect("small message profile is valid");
        let config = test_config_with_parameters(parameters);
        let minimum = minimum_safety_state_record_limits_v0(&config)
            .expect("derive exact structural capacity envelope");

        assert!(minimum.maximum_blob_bytes() > 4096);
        let message_only_limits = SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 4096)
            .expect("numerically valid but structurally insufficient limits");
        assert!(matches!(
            SafetyStateRecordContextV0::new(&config, [0x51; 32], message_only_limits),
            Err(SafetyStateRecordErrorV0::InsufficientLimits {
                required_blob_bytes,
                ..
            }) if required_blob_bytes == minimum.maximum_blob_bytes()
        ));
    }
}
