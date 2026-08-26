//! Exact, bounded decoders for the frozen CEV0 certificate, handoff,
//! epoch-commitment, and ordinary block-body kernels.
//!
//! These functions decode canonical logical values, not protobuf or another
//! transport container. Certificate decoders require the trusted active
//! validator set because set membership, voting power, and the validator-set
//! identifier are authorization context rather than self-authenticating wire
//! claims. Body decoders require authenticated active bounds and return inert
//! values rather than runtime, voting, checkpoint, or epoch authority.
//! Cryptographic signature verification remains a separate step.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::fmt;

use crate::canonical::try_canonical_bytes;
use crate::proposal_v0::{validate_scheduled_leader, validate_timestamp_step};
use crate::{
    ApplicationPayloadV0, BlockHeader, BlockId, BlockKind, CanonicalHandoffSignIntentV1,
    CanonicalSignIntentV0, CertificateId, CertifiedHeaderV0, ChainId,
    CometFinalizedBlockIdentityV1, CometStateExportV1, CommonConsensusContextV0,
    ConsensusParametersHash, ConsensusParametersV0, ConsensusParametersV0Fields,
    ConsensusPublicKey, DoubleVoteEvidenceV0, Epoch, EpochAnchorAuthorizationV0,
    EpochFallbackReasonV0, EvidenceRoot, ExecutionEventAttributeV0, ExecutionEventV0,
    ExecutionReceiptCommitmentV0, FinalityProofV0, GenesisHash, GenesisQcCeremonyEvidenceV1,
    GenesisQcSignatureShareV1, GenesisQcV0, HandoffCertificateV0, HandoffDescriptorV0,
    HandoffDescriptorV0Fields, HandoffSignIntentFingerprintV1, HandoffSignerRoleV1, Height,
    LeaderSchedule, LegacyCometAppHashV1, LegacyCometGenesisHashV1, MessageKind,
    NextEpochCommitmentHash, NextEpochCommitmentV0, NextEpochCommitmentV0Fields, PayloadDigest,
    PocoGenesisQcBindingV1, PocoGenesisV1, PocoTargetGenesisManifestV1, PocoTargetProjectionV1,
    ProtocolVersion, QcRef, QcReferenceV0, QuorumCertificate, ReceiptsRoot, RolloutPhase,
    SignIntentFingerprintV0, Signature64, SignatureShareV0, SignatureVerifier, SigningRoot,
    StateRoot, TimeoutCertificateV0, TimeoutEntryV0, UpgradePlanHash, ValidationError, Validator,
    ValidatorId, ValidatorSet, ValidatorSetId, VerifiedCometStateExportV1, View, Vote,
    VoteEvidenceRecordV0, VotingPower, CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1,
    CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0, COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1,
    COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1, COMET_STATE_EXPORT_PROFILE_V1,
    COMET_STATE_EXPORT_SCHEMA_VERSION_V1, GENESIS_QC_CEREMONY_PROFILE_V1,
    GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1, HANDOFF_SIGNER_PROFILE_V1,
    MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1, MAX_CONSENSUS_STRING_BYTES,
    MAX_GENESIS_QC_CEREMONY_CANONICAL_BYTES_V1, MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1,
    MAX_POCO_GENESIS_CANONICAL_BYTES_V1, MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1,
    MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1,
    MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1, MAX_VALIDATORS, MAX_VALIDATOR_ID_BYTES,
    POCO_GENESIS_PROFILE_V1, POCO_GENESIS_QC_BINDING_PROFILE_V1, POCO_GENESIS_SCHEMA_VERSION_V1,
    POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1, POCO_TARGET_GENESIS_MANIFEST_SCHEMA_VERSION_V1,
    POCO_TARGET_PROJECTION_PROFILE_V1, POCO_TARGET_PROJECTION_SCHEMA_VERSION_V1, SCHEMA_VERSION_V0,
};

/// The v0 hard cap for signer, timeout-entry, and referenced-QC lists.
pub const MAX_CEV0_CERTIFICATE_ITEMS: usize = 100;

/// The maximum total number of ordinary-QC signature shares nested in one TC.
pub const MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES: usize =
    MAX_CEV0_CERTIFICATE_ITEMS * MAX_CEV0_CERTIFICATE_ITEMS;

/// The maximum old-plus-new signature shares in one handoff certificate.
pub const MAX_CEV0_HANDOFF_AGGREGATE_SIGNATURE_SHARES: usize = MAX_CEV0_CERTIFICATE_ITEMS * 2;

/// Maximum bytes accepted for one complete CEV0 logical root at an ingress
/// boundary.  The bound is deliberately aligned with the reference
/// `max_consensus_message_bytes` profile.  Individual transport profiles may
/// choose a lower ceiling, but no CEV0 admission path should accept a larger
/// root merely because its outer length field is u32-wide.
pub const MAX_CEV0_ROOT_BYTES_V0: usize = 8 * 1024 * 1024;

/// Intrinsic upper envelope of signature-verification work for one currently
/// composed v0 consensus statement. This is a structural reference only; an
/// authenticated transport profile may choose a narrower budget.
pub const MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0: usize =
    3 * (MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES + (MAX_CEV0_CERTIFICATE_ITEMS * 3) + 1);

/// Default authenticated TC share ceiling. It matches the frozen 100x100
/// nested-QC product; callers with a narrower authenticated transport profile
/// can opt into a lower allowance via [`Cev0AdmissionBudgetV0::with_limits`].
pub const MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0: usize =
    MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES;

/// Default authenticated work envelope derived from the default TC ceiling.
pub const MAX_CEV0_SIGNATURE_WORK_UNITS_V0: usize =
    3 * (MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0 + (MAX_CEV0_CERTIFICATE_ITEMS * 3) + 1);

/// Centralized per-message resource accounting used by bounded transport
/// admission.  Exact CEV0 decoders remain cryptographically inert; callers
/// charge the decoded certificate before invoking a strict verifier.  Keeping
/// the meter in this crate makes every transport profile use the same QC/TC
/// share accounting instead of inventing independent limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cev0AdmissionBudgetV0 {
    maximum_root_bytes: usize,
    maximum_signature_work: usize,
    maximum_tc_aggregate_signature_shares: usize,
    signature_work: usize,
}

impl Cev0AdmissionBudgetV0 {
    /// Builds an explicit budget.  A zero limit is valid and intentionally
    /// rejects every non-empty root/work charge; this is useful for fail-closed
    /// caller configuration and boundary tests. Explicit maxima are still
    /// clamped to the intrinsic CEV0 hard caps.
    pub const fn new(maximum_root_bytes: usize, maximum_signature_work: usize) -> Self {
        Self::with_limits(
            maximum_root_bytes,
            maximum_signature_work,
            MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0,
        )
    }

    /// Builds a budget with an explicit nested-TC share ceiling. The caller
    /// may set it to the intrinsic 10,000-share decoder cap, but that choice
    /// must be deliberate and authenticated by its transport profile. All
    /// three maxima are clamped to their intrinsic protocol hard caps, so a
    /// caller cannot widen this admission boundary accidentally.
    pub const fn with_limits(
        maximum_root_bytes: usize,
        maximum_signature_work: usize,
        maximum_tc_aggregate_signature_shares: usize,
    ) -> Self {
        let maximum_root_bytes = if maximum_root_bytes > MAX_CEV0_ROOT_BYTES_V0 {
            MAX_CEV0_ROOT_BYTES_V0
        } else {
            maximum_root_bytes
        };
        let maximum_signature_work =
            if maximum_signature_work > MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0 {
                MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0
            } else {
                maximum_signature_work
            };
        let maximum_tc_aggregate_signature_shares =
            if maximum_tc_aggregate_signature_shares > MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES {
                MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
            } else {
                maximum_tc_aggregate_signature_shares
            };
        Self {
            maximum_root_bytes,
            maximum_signature_work,
            maximum_tc_aggregate_signature_shares,
            signature_work: 0,
        }
    }

    /// Reference v0 budget for callers that do not have a narrower
    /// authenticated parameter profile available.
    pub const fn protocol_v0() -> Self {
        Self::with_limits(
            MAX_CEV0_ROOT_BYTES_V0,
            MAX_CEV0_SIGNATURE_WORK_UNITS_V0,
            MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0,
        )
    }

    /// Derives the root ceiling from authenticated parameters while retaining
    /// the intrinsic CEV0 hard maximum.  A future profile may lower the
    /// parameter value; it cannot turn a u32 length field into an unbounded
    /// allocation.
    pub fn for_parameters(parameters: &ConsensusParametersV0) -> Self {
        Self::for_validator_count(parameters, MAX_VALIDATORS)
    }

    /// Derives an authenticated budget from the active parameter profile and
    /// validator-set cardinality. The nested TC allowance is `N*N`, matching
    /// the frozen CEV0 reference table's 100-reference/10,000-share ceiling.
    /// The exact decoder still enforces the intrinsic 100-item list caps, so
    /// this context-derived budget cannot widen the protocol envelope.
    pub fn for_validator_set(
        parameters: &ConsensusParametersV0,
        validator_set: &ValidatorSet,
    ) -> Self {
        Self::for_validator_count(parameters, validator_set.validators().len())
    }

    fn for_validator_count(parameters: &ConsensusParametersV0, validator_count: usize) -> Self {
        let configured = usize::try_from(parameters.max_consensus_message_bytes())
            .unwrap_or(MAX_CEV0_ROOT_BYTES_V0);
        let validator_count = validator_count.min(MAX_CEV0_CERTIFICATE_ITEMS);
        let maximum_tc_references = validator_count.max(1);
        let maximum_tc_aggregate_signature_shares = validator_count
            .saturating_mul(maximum_tc_references)
            .min(MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES);
        let maximum_signature_work = 3usize
            .saturating_mul(
                maximum_tc_aggregate_signature_shares
                    .saturating_add(validator_count.saturating_mul(3))
                    .saturating_add(1),
            )
            .min(MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0);
        Self::with_limits(
            configured.min(MAX_CEV0_ROOT_BYTES_V0),
            maximum_signature_work,
            maximum_tc_aggregate_signature_shares,
        )
    }

    pub const fn maximum_root_bytes(&self) -> usize {
        self.maximum_root_bytes
    }

    pub const fn maximum_signature_work(&self) -> usize {
        self.maximum_signature_work
    }

    pub const fn maximum_tc_aggregate_signature_shares(&self) -> usize {
        self.maximum_tc_aggregate_signature_shares
    }

    pub const fn signature_work(&self) -> usize {
        self.signature_work
    }

    /// Checks one complete logical root before its decoder is allowed to
    /// allocate/copy nested fields.
    pub fn admit_root_bytes(&self, actual: usize) -> DecodeResult<()> {
        if actual > self.maximum_root_bytes {
            return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
        }
        Ok(())
    }

    /// Charges signature checks atomically.  The counter is advanced only when
    /// the complete charge fits, so a failed admission cannot leave a caller
    /// with a partially consumed token.
    pub fn charge_signature_work(&mut self, additional: usize) -> DecodeResult<()> {
        let total = self
            .signature_work
            .checked_add(additional)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0))?;
        if total > self.maximum_signature_work {
            return Err(DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0));
        }
        self.signature_work = total;
        Ok(())
    }

    /// Charges all ordinary QC shares in one QC reference.  Contextual
    /// synthetic anchors carry no signatures and therefore cost zero units.
    pub fn charge_qc_reference(&mut self, reference: &QcReferenceV0) -> DecodeResult<()> {
        let shares = reference
            .as_ordinary()
            .map_or(0, |certificate| certificate.votes().len());
        self.charge_signature_work(shares)
    }

    pub fn charge_qc(&mut self, certificate: &QuorumCertificate) -> DecodeResult<()> {
        self.charge_signature_work(certificate.votes().len())
    }

    /// Charges every nested ordinary QC share and every timeout-entry
    /// signature in one corrected v0 TC.  The total is computed first so a
    /// rejected aggregate cannot partially consume the budget.
    pub fn charge_timeout_certificate(
        &mut self,
        certificate: &TimeoutCertificateV0,
    ) -> DecodeResult<()> {
        self.charge_signature_work(self.timeout_certificate_signature_work(certificate)?)
    }

    /// Charges every signature-bearing nested object in one certified header.
    /// This is intentionally atomic: a rejected certifying QC must not leave
    /// the caller's budget partially consumed by the justify QC or timeout
    /// certificate that preceded it.
    pub fn charge_certified_header(&mut self, header: &CertifiedHeaderV0) -> DecodeResult<()> {
        self.charge_signature_work(self.certified_header_signature_work(header)?)
    }

    /// Charges all three certified headers in a finality proof as one unit.
    /// A finality proof is a common wire ingress boundary, so charging only
    /// its individual QC/TC decoders would leave the aggregate three-chain
    /// signature workload unbounded by the caller's authenticated budget.
    pub fn charge_finality_proof(&mut self, proof: &FinalityProofV0) -> DecodeResult<()> {
        let first = self.certified_header_signature_work(proof.finalized_block())?;
        let second = self.certified_header_signature_work(proof.child())?;
        let third = self.certified_header_signature_work(proof.grandchild())?;
        let total = first
            .checked_add(second)
            .and_then(|value| value.checked_add(third))
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0))?;
        self.charge_signature_work(total)
    }

    fn timeout_certificate_signature_work(
        &self,
        certificate: &TimeoutCertificateV0,
    ) -> DecodeResult<usize> {
        let nested_shares =
            certificate
                .referenced_qcs()
                .iter()
                .try_fold(0usize, |total, reference| {
                    let shares = reference
                        .as_ordinary()
                        .map_or(0, |ordinary| ordinary.votes().len());
                    total
                        .checked_add(shares)
                        .ok_or_else(|| DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0))
                })?;
        if nested_shares > self.maximum_tc_aggregate_signature_shares {
            return Err(DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0));
        }
        nested_shares
            .checked_add(certificate.entries().len())
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0))
    }

    fn certified_header_signature_work(&self, header: &CertifiedHeaderV0) -> DecodeResult<usize> {
        let justify = header
            .justify_qc()
            .as_ordinary()
            .map_or(0, |certificate| certificate.votes().len());
        let timeout = header
            .timeout_certificate()
            .map(|certificate| self.timeout_certificate_signature_work(certificate))
            .transpose()?
            .unwrap_or(0);
        justify
            .checked_add(timeout)
            .and_then(|value| value.checked_add(header.certifying_qc().votes().len()))
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, 0))
    }
}

/// Maximum exact CEV0 bytes in one canonical Core-to-signer intent.
///
/// The bound covers two maximum-width chain IDs, one maximum-width validator
/// ID, the larger timeout-vote preimage, and both fixed 32-byte digests. It is
/// independent of transport framing and is checked before any field parsing.
pub const MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES: usize =
    // Outer schema/profile, author, revision, and preimage tag.
    2 + (2 + MAX_CONSENSUS_STRING_BYTES) + 4 + 8 + 32 + (4 + MAX_VALIDATOR_ID_BYTES) + 8 + 1
    // Nested common consensus context.
    + 2 + 32 + (2 + MAX_CONSENSUS_STRING_BYTES) + 4 + 8 + 32 + 8 + 1
    // Timeout high-QC summary: digest, epoch, view, height, and block ID.
    + 32 + 8 + 8 + 8 + 32
    // Signing root and intent fingerprint.
    + 32 + 32;

const MAX_CEV0_HANDOFF_DESCRIPTOR_BYTES_V0: usize =
    // Schema, genesis, chain, epochs, and protocol versions.
    2 + 32 + (2 + MAX_CONSENSUS_STRING_BYTES) + 8 + 8 + 4 + 4
    // Old/new set and parameter references.
    + 32 + 32 + 32 + 32
    // Checkpoint, terminal-old, and activation coordinates/commitments.
    + 8 + 32 + 32 + 32 + 8 + 32 + 32 + 8 + 8 + 8;

/// Maximum exact CEV0 bytes in one typed old/new handoff signer intent.
///
/// The bound includes the complete descriptor twice-bound as its digest and
/// exact bytes, both trusted set/parameter references, the closed signer role,
/// and the intent fingerprint. It is checked before parsing or allocation.
pub const MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1: usize = 2
    + (4 + HANDOFF_SIGNER_PROFILE_V1.len())
    + 32
    + (2 + MAX_CONSENSUS_STRING_BYTES)
    + 8
    + 8
    + 1
    + (4 + MAX_VALIDATOR_ID_BYTES)
    + 4
    + 4
    + 32
    + 32
    + 32
    + 32
    + 32
    + (4 + MAX_CEV0_HANDOFF_DESCRIPTOR_BYTES_V0)
    + 32
    + 32;

/// Decode the exact bounded canonical bytes of a read-only
/// `CometStateExportV1` manifest. This parser validates only the manifest's
/// structural/type boundaries; it does not read a Comet database or treat an
/// opaque digest as proof until a source/export verifier supplies the
/// documented preimage.
pub fn decode_comet_state_export_v1_exact(bytes: &[u8]) -> DecodeResult<CometStateExportV1> {
    if bytes.len() > MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != COMET_STATE_EXPORT_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(COMET_STATE_EXPORT_PROFILE_V1.len())?;
    if profile.bytes != COMET_STATE_EXPORT_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let source_chain_offset = cursor.offset();
    let source_chain =
        ChainId::from_bytes(cursor.bounded_consensus_bytes()?.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, source_chain_offset)
        })?;
    let source_genesis_document_digest = LegacyCometGenesisHashV1::new(cursor.fixed()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let source_application_id = cursor.fixed()?;
    let source_store_id = cursor.fixed()?;
    let finalized_height = Height::new(cursor.u64()?);
    let block_schema_offset = cursor.offset();
    let block_schema = cursor.u16()?;
    if block_schema != COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            block_schema_offset,
        ));
    }
    let block_profile_offset = cursor.offset();
    let block_profile =
        cursor.bounded_body_bytes(COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1.len())?;
    if block_profile.bytes != COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            block_profile_offset,
        ));
    }
    let finalized_block_identity =
        CometFinalizedBlockIdentityV1::new(cursor.fixed()?, cursor.u32()?, cursor.fixed()?)
            .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let source_finality_proof_digest = cursor.fixed()?;
    let legacy_app_hash = LegacyCometAppHashV1::new(cursor.fixed()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let exported_object_root = cursor.fixed()?;
    let exported_index_root = cursor.fixed()?;
    let exported_receipts_root = cursor.fixed()?;
    let rejected_objects_root = cursor.fixed()?;
    let source_validator_set_digest = cursor.fixed()?;
    let source_application_schema_digest = cursor.fixed()?;
    let source_runtime_profile_digest = cursor.fixed()?;
    let mapping_profile_digest = cursor.fixed()?;
    cursor.finish()?;

    let export = CometStateExportV1::new(
        source_chain,
        source_genesis_document_digest,
        source_application_id,
        source_store_id,
        finalized_height,
        finalized_block_identity,
        source_finality_proof_digest,
        legacy_app_hash,
        exported_object_root,
        exported_index_root,
        exported_receipts_root,
        rejected_objects_root,
        source_validator_set_digest,
        source_application_schema_digest,
        source_runtime_profile_digest,
        mapping_profile_digest,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    let canonical = export
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(export)
}

/// Decode an exact target projection statement against an importer-owned
/// verified source token. A raw `CometStateExportV1` is deliberately not
/// accepted here: source identity/finality/mapping verification must already
/// have produced `VerifiedCometStateExportV1`. The result is still inert; a
/// target replay verifier must separately call `PocoTargetProjectionV1::verify_with`.
pub fn decode_poco_target_projection_v1_exact(
    bytes: &[u8],
    verified_source: &VerifiedCometStateExportV1,
) -> DecodeResult<PocoTargetProjectionV1> {
    if bytes.len() > MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != POCO_TARGET_PROJECTION_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(POCO_TARGET_PROJECTION_PROFILE_V1.len())?;
    if profile.bytes != POCO_TARGET_PROJECTION_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let source_commitment = cursor.fixed()?;
    let mapping_profile_digest = cursor.fixed()?;
    let target_chain_offset = cursor.offset();
    let target_chain_id =
        ChainId::from_bytes(cursor.bounded_consensus_bytes()?.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, target_chain_offset)
        })?;
    let target_genesis_hash = GenesisHash::new(cursor.fixed()?);
    let target_genesis_manifest_digest = cursor.fixed()?;
    let claimed_state_root = StateRoot::new(cursor.fixed()?);
    cursor.finish()?;

    if source_commitment != verified_source.export_commitment()
        || mapping_profile_digest != verified_source.export().mapping_profile_digest()
    {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    let projection = verified_source
        .bind_target_projection_v1(
            target_chain_id,
            target_genesis_hash,
            target_genesis_manifest_digest,
            claimed_state_root,
        )
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    let canonical = projection
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(projection)
}

/// Decode the exact bounded canonical bytes of a typed target-genesis
/// manifest. The manifest is an inert migration preimage: this endpoint
/// checks its schema/profile, target context and canonical re-encoding, but
/// does not replay application state or authorize startup/activation.
pub fn decode_poco_target_genesis_manifest_v1_exact(
    bytes: &[u8],
) -> DecodeResult<PocoTargetGenesisManifestV1> {
    if bytes.len() > MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != POCO_TARGET_GENESIS_MANIFEST_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1.len())?;
    if profile.bytes != POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let target_chain_offset = cursor.offset();
    let target_chain_id =
        ChainId::from_bytes(cursor.bounded_consensus_bytes()?.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, target_chain_offset)
        })?;
    let target_genesis_hash = GenesisHash::new(cursor.fixed()?);
    let target_validator_set_digest = ValidatorSetId::new(cursor.fixed()?);
    let target_protocol_version = ProtocolVersion::new(cursor.u32()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidProtocolVersion, cursor.offset()))?;
    let application_schema_digest = cursor.fixed()?;
    let runtime_profile_digest = cursor.fixed()?;
    let initial_state_root = StateRoot::new(cursor.fixed()?);
    cursor.finish()?;

    let manifest = PocoTargetGenesisManifestV1::new(
        target_chain_id,
        target_genesis_hash,
        target_validator_set_digest,
        target_protocol_version,
        application_schema_digest,
        runtime_profile_digest,
        initial_state_root,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    let canonical = manifest
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(manifest)
}

/// Decode exact, bounded target-validator genesis quorum evidence against an
/// importer-owned trusted set. The result is inert evidence only: it cannot
/// become a `GenesisQcV0`, an ordinary QC, or an activation authorization.
/// Signature verification remains an explicit caller operation through
/// `GenesisQcCeremonyEvidenceV1::verify`.
pub fn decode_genesis_qc_ceremony_evidence_v1_exact(
    bytes: &[u8],
    trusted_set: &ValidatorSet,
) -> DecodeResult<GenesisQcCeremonyEvidenceV1> {
    if bytes.len() > MAX_GENESIS_QC_CEREMONY_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(GENESIS_QC_CEREMONY_PROFILE_V1.len())?;
    if profile.bytes != GENESIS_QC_CEREMONY_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let binding_offset = cursor.offset();
    let binding_bytes = cursor
        .bounded_body_bytes(MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1)?
        .bytes;
    let binding = decode_poco_genesis_qc_binding_v1_exact(binding_bytes, trusted_set)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, binding_offset))?;

    let signature_count_offset = cursor.offset();
    let signature_count = cursor.list_len(MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1)?;
    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        let share_offset = cursor.offset();
        let validator_id = ValidatorId::from_bytes(cursor.bounded_validator_id_bytes()?.bytes)
            .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, share_offset))?;
        let signature = Signature64::from_array(cursor.fixed()?);
        let share = GenesisQcSignatureShareV1::new(validator_id, signature)
            .map_err(|error| map_genesis_qc_ceremony_validation_error(error, share_offset))?;
        signatures.push(share);
    }
    cursor.finish()?;

    let evidence = GenesisQcCeremonyEvidenceV1::new(binding, signatures)
        .map_err(|error| map_genesis_qc_ceremony_validation_error(error, signature_count_offset))?;
    evidence
        .validate_against_trusted_set(trusted_set)
        .map_err(|error| map_genesis_qc_ceremony_validation_error(error, signature_count_offset))?;
    let canonical = evidence
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(evidence)
}

fn map_genesis_qc_ceremony_validation_error(error: ValidationError, offset: usize) -> DecodeError {
    let code = match error {
        ValidationError::UnknownValidator(_) => DecodeErrorCode::UnknownSigner,
        ValidationError::DuplicateSigner(_) => DecodeErrorCode::DuplicateSigner,
        ValidationError::NonCanonicalSignerOrder => DecodeErrorCode::NonCanonicalSignerOrder,
        ValidationError::InsufficientQuorum { .. } => DecodeErrorCode::InsufficientQuorum,
        ValidationError::TooManyValidators { .. } => DecodeErrorCode::CountLimitExceeded,
        ValidationError::InvalidSignature(_) => DecodeErrorCode::ContextMismatch,
        _ => DecodeErrorCode::ContextMismatch,
    };
    DecodeError::new(code, offset)
}

/// Decode the exact canonical bytes of the migration-aware `PocoGenesisV1`
/// descriptor.  This object is a ceremony input, not a live consensus
/// message; it nevertheless uses the same bounded, trailing-byte rejecting
/// discipline as the CEV0 decoders so independent importers can replay it.
pub fn decode_poco_genesis_v1_exact(bytes: &[u8]) -> DecodeResult<PocoGenesisV1> {
    if bytes.len() > MAX_POCO_GENESIS_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != crate::POCO_GENESIS_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(POCO_GENESIS_PROFILE_V1.len())?;
    if profile.bytes != POCO_GENESIS_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let source_chain_offset = cursor.offset();
    let source_chain =
        ChainId::from_bytes(cursor.bounded_consensus_bytes()?.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, source_chain_offset)
        })?;
    let source_genesis_hash = LegacyCometGenesisHashV1::new(cursor.fixed()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let source_application_id = cursor.fixed()?;
    let source_store_id = cursor.fixed()?;
    let source_height = Height::new(cursor.u64()?);
    let source_block_schema_offset = cursor.offset();
    let source_block_schema = cursor.u16()?;
    if source_block_schema != COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            source_block_schema_offset,
        ));
    }
    let source_block_profile_offset = cursor.offset();
    let source_block_profile =
        cursor.bounded_body_bytes(COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1.len())?;
    if source_block_profile.bytes != COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            source_block_profile_offset,
        ));
    }
    let source_block_identity =
        CometFinalizedBlockIdentityV1::new(cursor.fixed()?, cursor.u32()?, cursor.fixed()?)
            .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let source_finality_proof_digest = cursor.fixed()?;
    let legacy_app_hash_attestation = LegacyCometAppHashV1::new(cursor.fixed()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, cursor.offset()))?;
    let export_manifest_digest = cursor.fixed()?;
    let mapping_profile_digest = cursor.fixed()?;
    let target_chain_offset = cursor.offset();
    let target_chain =
        ChainId::from_bytes(cursor.bounded_consensus_bytes()?.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, target_chain_offset)
        })?;
    let target_genesis_hash = GenesisHash::new(cursor.fixed()?);
    let target_genesis_manifest_digest = cursor.fixed()?;
    let new_state_root = StateRoot::new(cursor.fixed()?);
    let target_validator_set_digest = ValidatorSetId::new(cursor.fixed()?);
    let target_protocol_version = ProtocolVersion::new(cursor.u32()?)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidProtocolVersion, cursor.offset()))?;
    let source_namespace = cursor.fixed()?;
    let migration_instance = cursor.fixed()?;
    cursor.finish()?;

    let descriptor = PocoGenesisV1::new(
        source_chain,
        source_genesis_hash,
        source_application_id,
        source_store_id,
        source_height,
        source_block_identity,
        source_finality_proof_digest,
        legacy_app_hash_attestation,
        export_manifest_digest,
        mapping_profile_digest,
        target_chain,
        target_genesis_hash,
        target_genesis_manifest_digest,
        new_state_root,
        target_validator_set_digest,
        target_protocol_version,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if descriptor.source_namespace_id_v1() != source_namespace {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    if descriptor
        .migration_instance_digest_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?
        != migration_instance
    {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    let canonical = descriptor
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(descriptor)
}

/// Decode an exact migration descriptor/QC ceremony envelope against the
/// importer-owned epoch-zero validator set. The embedded GenesisQC remains
/// the frozen v0 object; this decoder only verifies that its bytes, descriptor
/// target, and ceremony digest are mutually consistent with the trusted set.
pub fn decode_poco_genesis_qc_binding_v1_exact(
    bytes: &[u8],
    trusted_set: &ValidatorSet,
) -> DecodeResult<PocoGenesisQcBindingV1> {
    if bytes.len() > MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let schema_offset = cursor.offset();
    let schema = cursor.u16()?;
    if schema != POCO_GENESIS_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            schema_offset,
        ));
    }
    let profile_offset = cursor.offset();
    let profile = cursor.bounded_body_bytes(POCO_GENESIS_QC_BINDING_PROFILE_V1.len())?;
    if profile.bytes != POCO_GENESIS_QC_BINDING_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            profile_offset,
        ));
    }
    let qc_bytes = cursor
        .bounded_body_bytes(MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1)?
        .bytes;
    let descriptor_bytes = cursor
        .bounded_body_bytes(MAX_POCO_GENESIS_CANONICAL_BYTES_V1)?
        .bytes;
    let ceremony = cursor.fixed()?;
    cursor.finish()?;

    let genesis_qc = GenesisQcV0::new(
        trusted_set.genesis_hash(),
        trusted_set.chain_id(),
        trusted_set,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    let expected_qc = genesis_qc
        .try_cev0_bytes()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if expected_qc.as_slice() != qc_bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    let descriptor = decode_poco_genesis_v1_exact(descriptor_bytes)?;
    let binding = descriptor
        .bind_genesis_qc_v1_with_trusted_set(genesis_qc, trusted_set)
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if binding
        .ceremony_digest_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?
        != ceremony
    {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    let canonical = binding
        .try_canonical_bytes_v1()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, 0))?;
    if canonical != bytes {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, 0));
    }
    Ok(binding)
}

pub type DecodeResult<T> = core::result::Result<T, DecodeError>;

/// Stable, machine-readable failure classes for exact CEV0 parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorCode {
    UnexpectedEof,
    TrailingBytes,
    LengthLimitExceeded,
    CountLimitExceeded,
    AggregateLimitExceeded,
    InvalidSchemaVersion,
    InvalidProtocolVersion,
    InvalidConsensusString,
    InvalidBlockKind,
    InvalidOptionalTag,
    InvalidBlockHeader,
    InvalidHandoffDescriptor,
    InvalidHandoffCertificate,
    InvalidEpochAnchorRelations,
    UnauthorizedSyntheticQc,
    ZeroGenesisHash,
    ZeroConsensusPublicKey,
    ZeroVotingPower,
    EmptyValidatorSet,
    DuplicateValidatorId,
    DuplicatePublicKey,
    NonCanonicalValidatorOrder,
    ContextMismatch,
    UnknownSigner,
    DuplicateSigner,
    NonCanonicalSignerOrder,
    NonCanonicalReferenceOrder,
    ConflictingSameViewQc,
    InsufficientQuorum,
    EmptyTc,
    InvalidReferencedQc,
    DuplicateReference,
    FutureReferenceView,
    SameBlockDifferentCoordinates,
    ReferenceSummaryMismatch,
    UnreferencedQc,
    SelectedNotMaximum,
    InvalidBoolean,
    InvalidRolloutPhase,
    InvalidFallbackReason,
    InvalidNextEpochCommitment,
    InvalidUtf8,
    NonCanonicalEventAttributeOrder,
    InvalidDoubleVoteEvidence,
    InvalidLeaderSchedule,
    InvalidConsensusParameters,
    InvalidFinalityProof,
    InvalidCheckpointTwoSeal,
    InvalidSignIntentTag,
    InvalidSignIntent,
    InvalidHandoffSignIntentRole,
    InvalidHandoffSignIntent,
}

impl DecodeErrorCode {
    /// Canonical, machine-readable decoder taxonomy order.
    ///
    /// Boundary/schema tooling consumes this single Rust-owned list rather
    /// than maintaining a second hand-written ordering.  The list is kept in
    /// the same order as [`Self::as_str`]; adding a decoder class requires
    /// updating this list and the generated protocol registry together.
    pub const ALL: &'static [Self] = &[
        Self::UnexpectedEof,
        Self::TrailingBytes,
        Self::LengthLimitExceeded,
        Self::CountLimitExceeded,
        Self::AggregateLimitExceeded,
        Self::InvalidSchemaVersion,
        Self::InvalidProtocolVersion,
        Self::InvalidConsensusString,
        Self::InvalidBlockKind,
        Self::InvalidOptionalTag,
        Self::InvalidBlockHeader,
        Self::InvalidHandoffDescriptor,
        Self::InvalidHandoffCertificate,
        Self::InvalidEpochAnchorRelations,
        Self::UnauthorizedSyntheticQc,
        Self::ZeroGenesisHash,
        Self::ZeroConsensusPublicKey,
        Self::ZeroVotingPower,
        Self::EmptyValidatorSet,
        Self::DuplicateValidatorId,
        Self::DuplicatePublicKey,
        Self::NonCanonicalValidatorOrder,
        Self::ContextMismatch,
        Self::UnknownSigner,
        Self::DuplicateSigner,
        Self::NonCanonicalSignerOrder,
        Self::NonCanonicalReferenceOrder,
        Self::ConflictingSameViewQc,
        Self::InsufficientQuorum,
        Self::InvalidReferencedQc,
        Self::EmptyTc,
        Self::DuplicateReference,
        Self::FutureReferenceView,
        Self::SameBlockDifferentCoordinates,
        Self::ReferenceSummaryMismatch,
        Self::UnreferencedQc,
        Self::SelectedNotMaximum,
        Self::InvalidBoolean,
        Self::InvalidRolloutPhase,
        Self::InvalidFallbackReason,
        Self::InvalidNextEpochCommitment,
        Self::InvalidUtf8,
        Self::NonCanonicalEventAttributeOrder,
        Self::InvalidDoubleVoteEvidence,
        Self::InvalidLeaderSchedule,
        Self::InvalidConsensusParameters,
        Self::InvalidFinalityProof,
        Self::InvalidCheckpointTwoSeal,
        Self::InvalidSignIntentTag,
        Self::InvalidSignIntent,
        Self::InvalidHandoffSignIntentRole,
        Self::InvalidHandoffSignIntent,
    ];

    /// Returns the stable snake-case code shared by the manifest and corpus.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedEof => "unexpected_eof",
            Self::TrailingBytes => "trailing_bytes",
            Self::LengthLimitExceeded => "length_limit_exceeded",
            Self::CountLimitExceeded => "count_limit_exceeded",
            Self::AggregateLimitExceeded => "aggregate_limit_exceeded",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidProtocolVersion => "invalid_protocol_version",
            Self::InvalidConsensusString => "invalid_consensus_string",
            Self::InvalidBlockKind => "invalid_block_kind",
            Self::InvalidOptionalTag => "invalid_optional_tag",
            Self::InvalidBlockHeader => "invalid_block_header",
            Self::InvalidHandoffDescriptor => "invalid_handoff_descriptor",
            Self::InvalidHandoffCertificate => "invalid_handoff_certificate",
            Self::InvalidEpochAnchorRelations => "invalid_epoch_anchor_relations",
            Self::UnauthorizedSyntheticQc => "unauthorized_synthetic_qc",
            Self::ZeroGenesisHash => "zero_genesis_hash",
            Self::ZeroConsensusPublicKey => "zero_public_key",
            Self::ZeroVotingPower => "zero_voting_power",
            Self::EmptyValidatorSet => "empty_validator_set",
            Self::DuplicateValidatorId => "duplicate_validator_id",
            Self::DuplicatePublicKey => "duplicate_public_key",
            Self::NonCanonicalValidatorOrder => "noncanonical_validator_order",
            Self::ContextMismatch => "context_mismatch",
            Self::UnknownSigner => "unknown_signer",
            Self::DuplicateSigner => "duplicate_signer",
            Self::NonCanonicalSignerOrder => "noncanonical_signer_order",
            Self::NonCanonicalReferenceOrder => "noncanonical_reference_order",
            Self::ConflictingSameViewQc => "conflicting_same_view_qc",
            Self::InsufficientQuorum => "insufficient_quorum",
            Self::InvalidReferencedQc => "invalid_referenced_qc",
            Self::EmptyTc => "empty_tc",
            Self::DuplicateReference => "duplicate_reference",
            Self::FutureReferenceView => "future_reference_view",
            Self::SameBlockDifferentCoordinates => "same_block_different_coordinates",
            Self::ReferenceSummaryMismatch => "reference_summary_mismatch",
            Self::UnreferencedQc => "unreferenced_qc",
            Self::SelectedNotMaximum => "selected_not_maximum",
            Self::InvalidBoolean => "invalid_boolean",
            Self::InvalidRolloutPhase => "invalid_rollout_phase",
            Self::InvalidFallbackReason => "invalid_fallback_reason",
            Self::InvalidNextEpochCommitment => "invalid_next_epoch_commitment",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::NonCanonicalEventAttributeOrder => "noncanonical_event_attribute_order",
            Self::InvalidDoubleVoteEvidence => "invalid_double_vote_evidence",
            Self::InvalidLeaderSchedule => "invalid_leader_schedule",
            Self::InvalidConsensusParameters => "invalid_consensus_parameters",
            Self::InvalidFinalityProof => "invalid_finality_proof",
            Self::InvalidCheckpointTwoSeal => "invalid_checkpoint_two_seal",
            Self::InvalidSignIntentTag => "invalid_sign_intent_tag",
            Self::InvalidSignIntent => "invalid_sign_intent",
            Self::InvalidHandoffSignIntentRole => "invalid_handoff_sign_intent_role",
            Self::InvalidHandoffSignIntent => "invalid_handoff_sign_intent",
        }
    }
}

/// A decoder failure at an exact byte offset in the supplied root slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    code: DecodeErrorCode,
    byte_offset: usize,
}

impl DecodeError {
    const fn new(code: DecodeErrorCode, byte_offset: usize) -> Self {
        Self { code, byte_offset }
    }

    pub const fn code(self) -> DecodeErrorCode {
        self.code
    }

    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CEV0 decode error {} at byte {}",
            self.code.as_str(),
            self.byte_offset
        )
    }
}

impl core::error::Error for DecodeError {}

/// Inert, exactly decoded epoch-anchor authorization certificate kernel.
///
/// This value deliberately cannot derive an `EpochAnchorQcV0` or upgrade
/// itself into `EpochAnchorAuthorizationV0`. It retains peer bytes only for
/// inspection, exact re-encoding, and explicit certificate-signature checks.
/// Checkpoint ancestry, the two-seal construction, and
/// `NextEpochCommitment` authenticity remain outside this API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAnchorAuthorizationKernelV0 {
    terminal_old_header: BlockHeader,
    terminal_old_qc: QuorumCertificate,
    handoff_certificate: HandoffCertificateV0,
}

impl EpochAnchorAuthorizationKernelV0 {
    pub const fn terminal_old_header(&self) -> &BlockHeader {
        &self.terminal_old_header
    }

    pub const fn terminal_old_qc(&self) -> &QuorumCertificate {
        &self.terminal_old_qc
    }

    pub const fn handoff_certificate(&self) -> &HandoffCertificateV0 {
        &self.handoff_certificate
    }

    pub fn try_cev0_bytes(&self) -> crate::Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            self.terminal_old_header.encode_cev0(encoder);
            self.terminal_old_qc.encode_cev0(encoder);
            self.handoff_certificate.encode_cev0(encoder);
        })
    }

    /// Verifies only the certificate kernel and returns no authorization.
    ///
    /// This checks the terminal ordinary QC plus both old/new handoff
    /// signature roles after revalidating their shapes and relations. Success
    /// is not proof of checkpoint ancestry, the two-seal construction, or the
    /// committed next validator/runtime context.
    pub fn verify_certificate_kernel<V: SignatureVerifier>(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        verifier: &V,
    ) -> crate::Result<()> {
        EpochAnchorAuthorizationV0::new(
            self.terminal_old_header.clone(),
            self.terminal_old_qc.clone(),
            self.handoff_certificate.clone(),
            old_validator_set,
            new_validator_set,
        )?
        .verify_certificate_kernel(old_validator_set, new_validator_set, verifier)
    }
}

const CONSENSUS_PARAMETERS_V0_BYTES: usize = 341;
const PARAMETER_SCHEMA_OFFSET: usize = 0;
const PARAMETER_PROTOCOL_OFFSET: usize = 2;
const PARAMETER_PRODUCTION_ACTIVATION_OFFSET: usize = 6;
const PARAMETER_MAX_CHAIN_ID_BYTES_OFFSET: usize = 7;
const PARAMETER_MAX_VALIDATOR_ID_BYTES_OFFSET: usize = 9;
const PARAMETER_MAX_BLOCK_BYTES_OFFSET: usize = 11;
const PARAMETER_MIN_VALIDATORS_OFFSET: usize = 19;
const PARAMETER_MAX_VALIDATORS_OFFSET: usize = 23;
const PARAMETER_QUORUM_NUMERATOR_OFFSET: usize = 27;
#[cfg(test)]
const PARAMETER_QUORUM_DENOMINATOR_OFFSET: usize = 31;
const PARAMETER_FINALITY_CHAIN_LENGTH_OFFSET: usize = 39;
const PARAMETER_MAX_TOTAL_VOTING_POWER_OFFSET: usize = 40;
const PARAMETER_LEADER_SCHEDULE_OFFSET: usize = 56;
const PARAMETER_REQUIRE_FULL_PAYLOAD_OFFSET: usize = 57;
const PARAMETER_BASE_TIMEOUT_OFFSET: usize = 58;
const PARAMETER_TIMEOUT_NUMERATOR_OFFSET: usize = 66;
const PARAMETER_EPOCH_LENGTH_OFFSET: usize = 82;
const PARAMETER_EPOCH_SEAL_BLOCKS_OFFSET: usize = 90;
const PARAMETER_SNAPSHOT_LEAD_OFFSET: usize = 91;
const PARAMETER_JOINT_OLD_QUORUM_OFFSET: usize = 99;
const PARAMETER_JOINT_NEW_QUORUM_OFFSET: usize = 100;
const PARAMETER_UPGRADE_NOTICE_OFFSET: usize = 101;
const PARAMETER_SCALE_PPM_OFFSET: usize = 113;
const PARAMETER_PER_CERTIFICATE_CAP_OFFSET: usize = 145;
const PARAMETER_PER_CONSUMER_CAP_OFFSET: usize = 161;
const PARAMETER_PER_TASK_CAP_OFFSET: usize = 177;
const PARAMETER_PER_PROVIDER_CAP_OFFSET: usize = 193;
const PARAMETER_UNITS_PER_POWER_OFFSET: usize = 209;
const PARAMETER_MIN_VALIDATOR_POWER_OFFSET: usize = 241;
const PARAMETER_MAX_VALIDATOR_SHARE_OFFSET: usize = 257;
const PARAMETER_CAPPED_ALPHA_OFFSET: usize = 265;
const PARAMETER_ROLLOUT_PHASE_OFFSET: usize = 281;
const PARAMETER_AUTOMATIC_PROMOTION_OFFSET: usize = 306;
const PARAMETER_UNBONDING_DELAY_OFFSET: usize = 315;
const PARAMETER_TRUSTING_PERIOD_OFFSET: usize = 331;
const PARAMETER_REQUIRE_TRUSTING_RELATION_OFFSET: usize = 339;
const PARAMETER_REQUIRE_UNBONDING_RELATION_OFFSET: usize = 340;

/// Decodes the exact frozen 54-field `ConsensusParametersV0` CEV0 preimage.
///
/// The parser consumes all 341 fixed bytes before applying semantic rules, so
/// a valid root plus any suffix is always classified as `trailing_bytes`.
pub fn decode_consensus_parameters_v0_exact(bytes: &[u8]) -> DecodeResult<ConsensusParametersV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_consensus_parameters_v0(&mut cursor)?;
    cursor.finish()?;
    admit_raw_consensus_parameters_v0(raw)
}

fn parse_raw_consensus_parameters_v0(
    cursor: &mut Cursor<'_>,
) -> DecodeResult<RawConsensusParametersV0> {
    let raw = RawConsensusParametersV0 {
        schema_version: cursor.u16()?,
        protocol_version: cursor.u32()?,
        production_activation: cursor.u8()?,
        max_chain_id_bytes: cursor.u16()?,
        max_validator_id_bytes: cursor.u16()?,
        max_block_bytes: cursor.u32()?,
        max_consensus_message_bytes: cursor.u32()?,
        min_validators: cursor.u32()?,
        max_validators: cursor.u32()?,
        quorum_numerator: cursor.u32()?,
        quorum_denominator: cursor.u32()?,
        quorum_addend: cursor.u32()?,
        finality_certified_chain_length: cursor.u8()?,
        max_total_voting_power: cursor.u64()?,
        max_block_time_step_ms: cursor.u64()?,
        leader_schedule: cursor.u8()?,
        require_full_payload_before_vote: cursor.u8()?,
        base_timeout_ms: cursor.u64()?,
        timeout_multiplier_numerator: cursor.u32()?,
        timeout_multiplier_denominator: cursor.u32()?,
        timeout_max_ms: cursor.u64()?,
        epoch_length_blocks: cursor.u64()?,
        epoch_seal_blocks: cursor.u8()?,
        snapshot_lead_blocks: cursor.u64()?,
        joint_handoff_old_quorum: cursor.u8()?,
        joint_handoff_new_quorum: cursor.u8()?,
        upgrade_notice_epochs: cursor.u64()?,
        max_protocol_version_jump: cursor.u32()?,
        scale_ppm: cursor.u64()?,
        maturity_epochs: cursor.u64()?,
        max_certificate_age_epochs: cursor.u64()?,
        decay_step_ppm_per_epoch: cursor.u64()?,
        per_certificate_unit_cap: cursor.u128()?,
        per_consumer_provider_epoch_unit_cap: cursor.u128()?,
        per_task_provider_epoch_unit_cap: cursor.u128()?,
        per_provider_epoch_unit_cap: cursor.u128()?,
        units_per_power: cursor.u128()?,
        bond_atomic_units_per_power: cursor.u128()?,
        min_validator_power: cursor.u64()?,
        max_validator_power: cursor.u64()?,
        max_validator_share_ppm: cursor.u64()?,
        capped_weight_alpha_ppm: cursor.u64()?,
        full_weight_alpha_ppm: cursor.u64()?,
        rollout_phase: cursor.u8()?,
        minimum_shadow_epochs: cursor.u64()?,
        minimum_eligibility_only_epochs: cursor.u64()?,
        minimum_capped_weight_epochs: cursor.u64()?,
        automatic_promotion: cursor.u8()?,
        evidence_window_epochs: cursor.u64()?,
        unbonding_delay_epochs: cursor.u64()?,
        jail_duration_epochs: cursor.u64()?,
        trusting_period_epochs: cursor.u64()?,
        require_trusting_period_less_than_evidence: cursor.u8()?,
        require_evidence_window_le_unbonding_delay: cursor.u8()?,
    };
    debug_assert_eq!(cursor.offset(), CONSENSUS_PARAMETERS_V0_BYTES);
    Ok(raw)
}

fn admit_raw_consensus_parameters_v0(
    raw: RawConsensusParametersV0,
) -> DecodeResult<ConsensusParametersV0> {
    require_schema_v0(raw.schema_version, PARAMETER_SCHEMA_OFFSET)?;
    if raw.protocol_version != ProtocolVersion::V0.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidProtocolVersion,
            PARAMETER_PROTOCOL_OFFSET,
        ));
    }
    let production_activation = admit_parameter_bool(
        raw.production_activation,
        PARAMETER_PRODUCTION_ACTIVATION_OFFSET,
    )?;
    let leader_schedule = LeaderSchedule::try_from(raw.leader_schedule).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidLeaderSchedule,
            PARAMETER_LEADER_SCHEDULE_OFFSET,
        )
    })?;
    let require_full_payload_before_vote = admit_parameter_bool(
        raw.require_full_payload_before_vote,
        PARAMETER_REQUIRE_FULL_PAYLOAD_OFFSET,
    )?;
    let joint_handoff_old_quorum = admit_parameter_bool(
        raw.joint_handoff_old_quorum,
        PARAMETER_JOINT_OLD_QUORUM_OFFSET,
    )?;
    let joint_handoff_new_quorum = admit_parameter_bool(
        raw.joint_handoff_new_quorum,
        PARAMETER_JOINT_NEW_QUORUM_OFFSET,
    )?;
    let rollout_phase = RolloutPhase::try_from(raw.rollout_phase).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidRolloutPhase,
            PARAMETER_ROLLOUT_PHASE_OFFSET,
        )
    })?;
    let automatic_promotion = admit_parameter_bool(
        raw.automatic_promotion,
        PARAMETER_AUTOMATIC_PROMOTION_OFFSET,
    )?;
    let require_trusting_period_less_than_evidence = admit_parameter_bool(
        raw.require_trusting_period_less_than_evidence,
        PARAMETER_REQUIRE_TRUSTING_RELATION_OFFSET,
    )?;
    let require_evidence_window_le_unbonding_delay = admit_parameter_bool(
        raw.require_evidence_window_le_unbonding_delay,
        PARAMETER_REQUIRE_UNBONDING_RELATION_OFFSET,
    )?;
    let fields = ConsensusParametersV0Fields {
        schema_version: raw.schema_version,
        protocol_version: raw.protocol_version,
        production_activation,
        max_chain_id_bytes: raw.max_chain_id_bytes,
        max_validator_id_bytes: raw.max_validator_id_bytes,
        max_block_bytes: raw.max_block_bytes,
        max_consensus_message_bytes: raw.max_consensus_message_bytes,
        min_validators: raw.min_validators,
        max_validators: raw.max_validators,
        quorum_numerator: raw.quorum_numerator,
        quorum_denominator: raw.quorum_denominator,
        quorum_addend: raw.quorum_addend,
        finality_certified_chain_length: raw.finality_certified_chain_length,
        max_total_voting_power: raw.max_total_voting_power,
        max_block_time_step_ms: raw.max_block_time_step_ms,
        leader_schedule,
        require_full_payload_before_vote,
        base_timeout_ms: raw.base_timeout_ms,
        timeout_multiplier_numerator: raw.timeout_multiplier_numerator,
        timeout_multiplier_denominator: raw.timeout_multiplier_denominator,
        timeout_max_ms: raw.timeout_max_ms,
        epoch_length_blocks: raw.epoch_length_blocks,
        epoch_seal_blocks: raw.epoch_seal_blocks,
        snapshot_lead_blocks: raw.snapshot_lead_blocks,
        joint_handoff_old_quorum,
        joint_handoff_new_quorum,
        upgrade_notice_epochs: raw.upgrade_notice_epochs,
        max_protocol_version_jump: raw.max_protocol_version_jump,
        scale_ppm: raw.scale_ppm,
        maturity_epochs: raw.maturity_epochs,
        max_certificate_age_epochs: raw.max_certificate_age_epochs,
        decay_step_ppm_per_epoch: raw.decay_step_ppm_per_epoch,
        per_certificate_unit_cap: raw.per_certificate_unit_cap,
        per_consumer_provider_epoch_unit_cap: raw.per_consumer_provider_epoch_unit_cap,
        per_task_provider_epoch_unit_cap: raw.per_task_provider_epoch_unit_cap,
        per_provider_epoch_unit_cap: raw.per_provider_epoch_unit_cap,
        units_per_power: raw.units_per_power,
        bond_atomic_units_per_power: raw.bond_atomic_units_per_power,
        min_validator_power: raw.min_validator_power,
        max_validator_power: raw.max_validator_power,
        max_validator_share_ppm: raw.max_validator_share_ppm,
        capped_weight_alpha_ppm: raw.capped_weight_alpha_ppm,
        full_weight_alpha_ppm: raw.full_weight_alpha_ppm,
        rollout_phase,
        minimum_shadow_epochs: raw.minimum_shadow_epochs,
        minimum_eligibility_only_epochs: raw.minimum_eligibility_only_epochs,
        minimum_capped_weight_epochs: raw.minimum_capped_weight_epochs,
        automatic_promotion,
        evidence_window_epochs: raw.evidence_window_epochs,
        unbonding_delay_epochs: raw.unbonding_delay_epochs,
        jail_duration_epochs: raw.jail_duration_epochs,
        trusting_period_epochs: raw.trusting_period_epochs,
        require_trusting_period_less_than_evidence,
        require_evidence_window_le_unbonding_delay,
    };
    validate_consensus_parameter_offsets(&fields)?;
    ConsensusParametersV0::new(fields).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_SCHEMA_OFFSET,
        )
    })
}

fn admit_parameter_bool(raw: u8, byte_offset: usize) -> DecodeResult<bool> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::new(
            DecodeErrorCode::InvalidBoolean,
            byte_offset,
        )),
    }
}

fn invalid_consensus_parameters<T>(byte_offset: usize) -> DecodeResult<T> {
    Err(DecodeError::new(
        DecodeErrorCode::InvalidConsensusParameters,
        byte_offset,
    ))
}

fn validate_consensus_parameter_offsets(fields: &ConsensusParametersV0Fields) -> DecodeResult<()> {
    if fields.max_chain_id_bytes == 0
        || usize::from(fields.max_chain_id_bytes) > MAX_CONSENSUS_STRING_BYTES
    {
        return invalid_consensus_parameters(PARAMETER_MAX_CHAIN_ID_BYTES_OFFSET);
    }
    if fields.max_validator_id_bytes == 0
        || usize::from(fields.max_validator_id_bytes) > MAX_VALIDATOR_ID_BYTES
    {
        return invalid_consensus_parameters(PARAMETER_MAX_VALIDATOR_ID_BYTES_OFFSET);
    }
    let hard_max_validators =
        u32::try_from(MAX_VALIDATORS).expect("the v0 validator hard cap fits in u32");
    if fields.min_validators < 4 || fields.min_validators > fields.max_validators {
        return invalid_consensus_parameters(PARAMETER_MIN_VALIDATORS_OFFSET);
    }
    if fields.max_validators > hard_max_validators {
        return invalid_consensus_parameters(PARAMETER_MAX_VALIDATORS_OFFSET);
    }
    if fields.max_block_bytes == 0
        || fields.max_consensus_message_bytes == 0
        || fields.max_block_bytes > fields.max_consensus_message_bytes
    {
        return invalid_consensus_parameters(PARAMETER_MAX_BLOCK_BYTES_OFFSET);
    }
    if !fields.require_full_payload_before_vote {
        return invalid_consensus_parameters(PARAMETER_REQUIRE_FULL_PAYLOAD_OFFSET);
    }
    if (
        fields.quorum_numerator,
        fields.quorum_denominator,
        fields.quorum_addend,
    ) != (2, 3, 1)
    {
        return invalid_consensus_parameters(PARAMETER_QUORUM_NUMERATOR_OFFSET);
    }
    if fields.finality_certified_chain_length != 3 {
        return invalid_consensus_parameters(PARAMETER_FINALITY_CHAIN_LENGTH_OFFSET);
    }
    if fields.timeout_multiplier_denominator == 0
        || fields.timeout_multiplier_numerator <= fields.timeout_multiplier_denominator
    {
        return invalid_consensus_parameters(PARAMETER_TIMEOUT_NUMERATOR_OFFSET);
    }
    if fields.base_timeout_ms > fields.timeout_max_ms {
        return invalid_consensus_parameters(PARAMETER_BASE_TIMEOUT_OFFSET);
    }
    if fields.epoch_seal_blocks != 2 {
        return invalid_consensus_parameters(PARAMETER_EPOCH_SEAL_BLOCKS_OFFSET);
    }
    if fields.snapshot_lead_blocks < u64::from(fields.finality_certified_chain_length) {
        return invalid_consensus_parameters(PARAMETER_SNAPSHOT_LEAD_OFFSET);
    }
    let snapshot_and_seals = fields
        .snapshot_lead_blocks
        .checked_add(u64::from(fields.epoch_seal_blocks))
        .ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidConsensusParameters,
                PARAMETER_SNAPSHOT_LEAD_OFFSET,
            )
        })?;
    if fields.epoch_length_blocks <= snapshot_and_seals {
        return invalid_consensus_parameters(PARAMETER_EPOCH_LENGTH_OFFSET);
    }
    if !fields.joint_handoff_old_quorum || !fields.joint_handoff_new_quorum {
        return invalid_consensus_parameters(PARAMETER_JOINT_OLD_QUORUM_OFFSET);
    }
    if fields.upgrade_notice_epochs < 1 || fields.max_protocol_version_jump != 1 {
        return invalid_consensus_parameters(PARAMETER_UPGRADE_NOTICE_OFFSET);
    }
    if fields.scale_ppm == 0 {
        return invalid_consensus_parameters(PARAMETER_SCALE_PPM_OFFSET);
    }
    let caps = [
        (
            fields.per_certificate_unit_cap,
            PARAMETER_PER_CERTIFICATE_CAP_OFFSET,
        ),
        (
            fields.per_consumer_provider_epoch_unit_cap,
            PARAMETER_PER_CONSUMER_CAP_OFFSET,
        ),
        (
            fields.per_task_provider_epoch_unit_cap,
            PARAMETER_PER_TASK_CAP_OFFSET,
        ),
        (
            fields.per_provider_epoch_unit_cap,
            PARAMETER_PER_PROVIDER_CAP_OFFSET,
        ),
    ];
    if caps[0].0 == 0 {
        return invalid_consensus_parameters(PARAMETER_PER_CERTIFICATE_CAP_OFFSET);
    }
    for pair in caps.windows(2) {
        if pair[0].0 > pair[1].0 {
            return invalid_consensus_parameters(PARAMETER_PER_CERTIFICATE_CAP_OFFSET);
        }
    }
    if fields.units_per_power == 0 || fields.bond_atomic_units_per_power == 0 {
        return invalid_consensus_parameters(PARAMETER_UNITS_PER_POWER_OFFSET);
    }
    if fields.min_validator_power == 0 || fields.min_validator_power > fields.max_validator_power {
        return invalid_consensus_parameters(PARAMETER_MIN_VALIDATOR_POWER_OFFSET);
    }
    if fields.max_validator_share_ppm == 0
        || u128::from(fields.max_validator_share_ppm) * 3 >= u128::from(fields.scale_ppm)
    {
        return invalid_consensus_parameters(PARAMETER_MAX_VALIDATOR_SHARE_OFFSET);
    }
    if fields.capped_weight_alpha_ppm > fields.scale_ppm
        || fields.full_weight_alpha_ppm != fields.scale_ppm
    {
        return invalid_consensus_parameters(PARAMETER_CAPPED_ALPHA_OFFSET);
    }
    let minimum_candidate_power = u128::from(fields.min_validators)
        .checked_mul(u128::from(fields.min_validator_power))
        .ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidConsensusParameters,
                PARAMETER_MAX_TOTAL_VOTING_POWER_OFFSET,
            )
        })?;
    if minimum_candidate_power > u128::from(fields.max_total_voting_power) {
        return invalid_consensus_parameters(PARAMETER_MAX_TOTAL_VOTING_POWER_OFFSET);
    }
    if fields.automatic_promotion {
        return invalid_consensus_parameters(PARAMETER_AUTOMATIC_PROMOTION_OFFSET);
    }
    if fields.trusting_period_epochs >= fields.evidence_window_epochs {
        return invalid_consensus_parameters(PARAMETER_TRUSTING_PERIOD_OFFSET);
    }
    if fields.evidence_window_epochs > fields.unbonding_delay_epochs {
        return invalid_consensus_parameters(PARAMETER_UNBONDING_DELAY_OFFSET);
    }
    if !fields.require_trusting_period_less_than_evidence {
        return invalid_consensus_parameters(PARAMETER_REQUIRE_TRUSTING_RELATION_OFFSET);
    }
    if !fields.require_evidence_window_le_unbonding_delay {
        return invalid_consensus_parameters(PARAMETER_REQUIRE_UNBONDING_RELATION_OFFSET);
    }
    Ok(())
}

/// Decodes one complete `ValidatorSetV0` CEV0 value.
pub fn decode_validator_set_v0_exact(bytes: &[u8]) -> DecodeResult<ValidatorSet> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_validator_set(&mut cursor)?;
    cursor.finish()?;
    admit_raw_validator_set(raw)
}

fn parse_raw_validator_set<'a>(cursor: &mut Cursor<'a>) -> DecodeResult<RawValidatorSet<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let validator_count_offset = cursor.offset();
    let validator_count = cursor.list_len(MAX_VALIDATORS)?;
    let mut validators = Vec::with_capacity(validator_count);
    for _ in 0..validator_count {
        let offset = cursor.offset();
        validators.push(RawValidator {
            offset,
            id: cursor.bounded_validator_id_bytes()?,
            consensus_key: ConsensusPublicKey::new(cursor.fixed()?),
            voting_power: cursor.u64()?,
        });
    }
    Ok(RawValidatorSet {
        object_offset,
        schema_version,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        consensus_parameters_hash,
        validator_count_offset,
        validators,
    })
}

fn admit_raw_validator_set(raw: RawValidatorSet<'_>) -> DecodeResult<ValidatorSet> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    let mut validators = Vec::with_capacity(raw.validators.len());
    for validator in raw.validators {
        let id = admit_validator_id(validator.id)?;
        let voting_power = VotingPower::new(validator.voting_power).map_err(|error| {
            map_validation_error(error, validator.offset, SemanticObject::ValidatorSet)
        })?;
        validators.push(
            Validator::new(id, validator.consensus_key, voting_power).map_err(|error| {
                map_validation_error(error, validator.offset, SemanticObject::ValidatorSet)
            })?,
        );
    }
    ValidatorSet::new(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.consensus_parameters_hash,
        validators,
    )
    .map_err(|error| {
        map_validation_error(
            error,
            raw.validator_count_offset,
            SemanticObject::ValidatorSet,
        )
    })
}

/// Decodes one complete canonical Core-to-signer authorization envelope.
///
/// The active validator set is trusted authorization context: both the outer
/// profile and the nested signed-message context must bind to it exactly, and
/// the author must be one of its members. The decoder admits only the frozen
/// vote and timeout-vote variants, exhausts the supplied root, validates the
/// embedded signing root and intent fingerprint, and requires byte-for-byte
/// canonical re-encoding before returning the typed intent.
///
/// This function validates encoding and validator-set binding. A signer must
/// separately enforce its monotonic SafetyState revision/watermark policy.
pub fn decode_canonical_sign_intent_v0_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> DecodeResult<CanonicalSignIntentV0> {
    if bytes.len() > MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_canonical_sign_intent(&mut cursor)?;
    cursor.finish()?;
    let intent = admit_raw_canonical_sign_intent(raw, validator_set)?;
    require_exact_canonical_reencoding(bytes, intent.canonical_bytes(), 0)?;
    Ok(intent)
}

/// Decodes one complete typed old/new epoch-handoff signer request.
///
/// All four trusted transition objects are required. The decoder rejects a
/// syntactically valid intent when any descriptor byte, role, validator,
/// signing root, set ID, parameter hash, or outer transition coordinate does
/// not reconstruct exactly from that trusted profile. No arbitrary signing
/// bytes or caller-provided root are admitted. Successful decoding is
/// data-only and grants no journal, watermark, producer, finality, or
/// transition authority.
pub fn decode_canonical_handoff_sign_intent_v1_exact(
    bytes: &[u8],
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_consensus_parameters: &ConsensusParametersV0,
) -> DecodeResult<CanonicalHandoffSignIntentV1> {
    if bytes.len() > MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1 {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }

    let mut cursor = Cursor::new(bytes);
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    if schema_version != CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            object_offset,
        ));
    }
    let profile = cursor.bounded_body_bytes(HANDOFF_SIGNER_PROFILE_V1.len())?;
    if profile.bytes != HANDOFF_SIGNER_PROFILE_V1 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            profile.length_offset,
        ));
    }
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = admit_consensus_string(cursor.bounded_consensus_bytes()?)?;
    let old_epoch = Epoch::new(cursor.u64()?);
    let new_epoch = Epoch::new(cursor.u64()?);
    let role_offset = cursor.offset();
    let signer_role = match cursor.u8()? {
        0 => HandoffSignerRoleV1::OldSet,
        1 => HandoffSignerRoleV1::NewSet,
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidHandoffSignIntentRole,
                role_offset,
            ));
        }
    };
    let validator_offset = cursor.offset();
    let validator_id = admit_validator_id(cursor.bounded_validator_id_bytes()?)?;
    let old_protocol_offset = cursor.offset();
    let old_protocol_version = ProtocolVersion::new(cursor.u32()?).map_err(|_| {
        DecodeError::new(DecodeErrorCode::InvalidProtocolVersion, old_protocol_offset)
    })?;
    let new_protocol_offset = cursor.offset();
    let new_protocol_version = ProtocolVersion::new(cursor.u32()?).map_err(|_| {
        DecodeError::new(DecodeErrorCode::InvalidProtocolVersion, new_protocol_offset)
    })?;
    let old_validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let new_validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let old_consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let new_consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let descriptor_digest_offset = cursor.offset();
    let descriptor_digest = CertificateId::new(cursor.fixed()?);
    let descriptor_bytes = cursor.bounded_body_bytes(MAX_CEV0_HANDOFF_DESCRIPTOR_BYTES_V0)?;
    let descriptor = decode_handoff_descriptor_v0_exact(descriptor_bytes.bytes).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            descriptor_bytes.length_offset,
        )
    })?;
    let signing_root_offset = cursor.offset();
    let signing_root = SigningRoot::new(cursor.fixed()?);
    let fingerprint_offset = cursor.offset();
    let fingerprint = HandoffSignIntentFingerprintV1::new(cursor.fixed()?);
    cursor.finish()?;

    let intent = match signer_role {
        HandoffSignerRoleV1::OldSet => CanonicalHandoffSignIntentV1::old_set(
            &descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            validator_id,
        ),
        HandoffSignerRoleV1::NewSet => CanonicalHandoffSignIntentV1::new_set(
            &descriptor,
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            validator_id,
        ),
    }
    .map_err(|error| {
        map_validation_error(error, object_offset, SemanticObject::HandoffSignIntent)
    })?;
    let preimage = intent.preimage();
    if genesis_hash != preimage.genesis_hash()
        || chain_id != preimage.chain_id()
        || old_epoch != preimage.old_epoch()
        || new_epoch != preimage.new_epoch()
        || old_protocol_version != preimage.old_protocol_version()
        || new_protocol_version != preimage.new_protocol_version()
        || old_validator_set_id != preimage.old_validator_set_id()
        || new_validator_set_id != preimage.new_validator_set_id()
        || old_consensus_parameters_hash != preimage.old_consensus_parameters_hash()
        || new_consensus_parameters_hash != preimage.new_consensus_parameters_hash()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            genesis_offset,
        ));
    }
    if descriptor_digest != preimage.descriptor_digest()
        || descriptor_bytes.bytes != preimage.descriptor_bytes()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            descriptor_digest_offset,
        ));
    }
    if signing_root != intent.signing_root() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            signing_root_offset,
        ));
    }
    if fingerprint != intent.fingerprint() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            fingerprint_offset,
        ));
    }
    if validator_id != intent.validator_id() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffSignIntent,
            validator_offset,
        ));
    }
    require_exact_canonical_reencoding(bytes, intent.canonical_bytes(), object_offset)?;
    Ok(intent)
}

fn parse_raw_canonical_sign_intent<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawCanonicalSignIntent<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let chain_id = cursor.bounded_consensus_bytes_raw()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_id_offset = cursor.offset();
    let validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let author = cursor.bounded_validator_id_bytes_raw()?;
    let authorizing_safety_revision_offset = cursor.offset();
    let authorizing_safety_revision = cursor.u64()?;
    let preimage_tag_offset = cursor.offset();
    let preimage_tag = cursor.u8()?;
    let preimage = match preimage_tag {
        0 => RawCanonicalSignPreimage::Vote {
            context: parse_raw_common_consensus_context(cursor)?,
            height: Height::new(cursor.u64()?),
            block_id: BlockId::new(cursor.fixed()?),
        },
        1 => RawCanonicalSignPreimage::TimeoutVote {
            context: parse_raw_common_consensus_context(cursor)?,
            high_qc_digest: CertificateId::new(cursor.fixed()?),
            high_qc_epoch: Epoch::new(cursor.u64()?),
            high_qc_view: View::new(cursor.u64()?),
            high_qc_height: Height::new(cursor.u64()?),
            high_qc_block_id: BlockId::new(cursor.fixed()?),
        },
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidSignIntentTag,
                preimage_tag_offset,
            ));
        }
    };
    let signing_root_offset = cursor.offset();
    let signing_root = SigningRoot::new(cursor.fixed()?);
    let fingerprint_offset = cursor.offset();
    let fingerprint = SignIntentFingerprintV0::new(cursor.fixed()?);
    Ok(RawCanonicalSignIntent {
        object_offset,
        schema_version,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        validator_set_id_offset,
        validator_set_id,
        author,
        authorizing_safety_revision_offset,
        authorizing_safety_revision,
        preimage,
        signing_root_offset,
        signing_root,
        fingerprint_offset,
        fingerprint,
    })
}

fn admit_raw_canonical_sign_intent(
    raw: RawCanonicalSignIntent<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<CanonicalSignIntentV0> {
    if raw.schema_version != CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            raw.object_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    validator_set.validate_shape().map_err(|error| {
        map_validation_error(error, raw.object_offset, SemanticObject::ValidatorSet)
    })?;
    if chain_id != validator_set.chain_id()
        || protocol_version != validator_set.protocol_version()
        || raw.epoch != validator_set.epoch()
        || raw.validator_set_id != validator_set.id()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            raw.validator_set_id_offset,
        ));
    }
    let author = admit_validator_id(raw.author)?;
    if validator_set.validator(author).is_none() {
        return Err(DecodeError::new(
            DecodeErrorCode::UnknownSigner,
            raw.author.length_offset,
        ));
    }
    if raw.authorizing_safety_revision == 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSignIntent,
            raw.authorizing_safety_revision_offset,
        ));
    }

    let intent = match raw.preimage {
        RawCanonicalSignPreimage::Vote {
            context,
            height,
            block_id,
        } => {
            let context = admit_raw_sign_context(context, MessageKind::Vote, validator_set)?;
            CanonicalSignIntentV0::vote(
                validator_set,
                author,
                raw.authorizing_safety_revision,
                context.view(),
                height,
                block_id,
            )
        }
        RawCanonicalSignPreimage::TimeoutVote {
            context,
            high_qc_digest,
            high_qc_epoch,
            high_qc_view,
            high_qc_height,
            high_qc_block_id,
        } => {
            let context = admit_raw_sign_context(context, MessageKind::Timeout, validator_set)?;
            CanonicalSignIntentV0::timeout_vote(
                validator_set,
                author,
                raw.authorizing_safety_revision,
                context.view(),
                QcRef::new(
                    high_qc_digest,
                    high_qc_epoch,
                    high_qc_view,
                    high_qc_height,
                    high_qc_block_id,
                    validator_set.id(),
                ),
            )
        }
    }
    .map_err(|error| map_validation_error(error, raw.object_offset, SemanticObject::SignIntent))?;

    if raw.signing_root != intent.signing_root() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSignIntent,
            raw.signing_root_offset,
        ));
    }
    if raw.fingerprint != intent.fingerprint() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSignIntent,
            raw.fingerprint_offset,
        ));
    }
    Ok(intent)
}

fn admit_raw_sign_context(
    raw: RawCommonConsensusContext<'_>,
    expected_kind: MessageKind,
    validator_set: &ValidatorSet,
) -> DecodeResult<CommonConsensusContextV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    if raw.validator_set_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            raw.validator_set_hash_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    if raw.message_kind != expected_kind as u8 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            raw.message_kind_offset,
        ));
    }
    require_trusted_set_context(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_hash,
        validator_set,
        raw.object_offset,
    )?;
    CommonConsensusContextV0::new(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_hash,
        raw.view,
        expected_kind,
    )
    .map_err(|error| map_validation_error(error, raw.object_offset, SemanticObject::SignIntent))
}

/// Decodes one complete ordinary QC and validates it against a trusted set.
///
/// Empty-signature QCs are rejected with `UnauthorizedSyntheticQc`; this API
/// never guesses genesis or epoch-anchor authority from peer-controlled bytes.
pub fn decode_ordinary_qc_v0_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> DecodeResult<QuorumCertificate> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS)?;
    cursor.finish()?;
    admit_raw_ordinary_qc(raw, validator_set)
}

/// Bounded-admission variant of [`decode_ordinary_qc_v0_exact`].  The exact
/// shape decoder remains unchanged; this wrapper performs the root-size check
/// and charges the decoded signature shares before a caller invokes strict
/// cryptographic verification.
pub fn decode_ordinary_qc_v0_exact_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<QuorumCertificate> {
    budget.admit_root_bytes(bytes.len())?;
    let certificate = decode_ordinary_qc_v0_exact(bytes, validator_set)?;
    budget.charge_qc(&certificate)?;
    Ok(certificate)
}

/// Decodes one complete QC reference in an authenticated epoch-zero context.
///
/// Ordinary, positive-view QCs retain the exact admission rules of
/// [`decode_ordinary_qc_v0_exact`]. The only synthetic value admitted by this
/// entry point is the one empty-signature `GenesisQcV0` reconstructed from
/// `epoch_zero_validator_set`. Peer bytes must match that trusted value field
/// for field and must canonically re-encode byte-for-byte. Empty-signature
/// splices and epoch-anchor QCs remain unauthorized.
pub fn decode_qc_reference_v0_exact_with_trusted_genesis(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
) -> DecodeResult<QcReferenceV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS)?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let reference = admit_raw_qc_reference_with_trusted_genesis(
        raw,
        epoch_zero_validator_set,
        &trusted_genesis,
    )?;
    require_exact_canonical_reencoding(
        bytes,
        try_canonical_bytes(|encoder| reference.encode_cev0(encoder)),
        0,
    )?;
    Ok(reference)
}

/// Bounded-admission variant of
/// [`decode_qc_reference_v0_exact_with_trusted_genesis`].
pub fn decode_qc_reference_v0_exact_with_trusted_genesis_and_budget(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<QcReferenceV0> {
    budget.admit_root_bytes(bytes.len())?;
    let reference =
        decode_qc_reference_v0_exact_with_trusted_genesis(bytes, epoch_zero_validator_set)?;
    budget.charge_qc_reference(&reference)?;
    Ok(reference)
}

/// Decodes one complete TC whose referenced QCs are all ordinary QCs.
///
/// The synthetic-anchor form requires separate trusted authorization and is
/// deliberately outside this ordinary certificate-kernel entry point.
pub fn decode_ordinary_timeout_certificate_v0_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> DecodeResult<TimeoutCertificateV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_timeout_certificate(&mut cursor)?;
    cursor.finish()?;
    admit_raw_timeout_certificate(raw, validator_set)
}

/// Bounded-admission variant of [`decode_ordinary_timeout_certificate_v0_exact`].
pub fn decode_ordinary_timeout_certificate_v0_exact_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<TimeoutCertificateV0> {
    budget.admit_root_bytes(bytes.len())?;
    // Thread the authenticated nested-share ceiling into the parser itself.
    // Charging only after an intrinsic-cap parse would still bound the final
    // result, but would allow a peer to allocate/scan the full 10,000-share
    // product before the active validator-set budget rejects it.
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_timeout_certificate_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let certificate = admit_raw_timeout_certificate(raw, validator_set)?;
    budget.charge_timeout_certificate(&certificate)?;
    Ok(certificate)
}

/// Decodes one complete epoch-zero TC with trusted GenesisQC references.
///
/// Every referenced QC is admitted either as an ordinary QC or as the exact
/// `GenesisQcV0` derived from `epoch_zero_validator_set`. Epoch-anchor and
/// other empty-signature forms are rejected. The returned value must
/// canonically re-encode to the supplied exact root.
pub fn decode_timeout_certificate_v0_exact_with_trusted_genesis(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
) -> DecodeResult<TimeoutCertificateV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_timeout_certificate(&mut cursor)?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let certificate = admit_raw_timeout_certificate_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, certificate.try_cev0_bytes(), 0)?;
    Ok(certificate)
}

/// Bounded-admission variant of
/// [`decode_timeout_certificate_v0_exact_with_trusted_genesis`].
pub fn decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<TimeoutCertificateV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_timeout_certificate_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let certificate = admit_raw_timeout_certificate_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, certificate.try_cev0_bytes(), 0)?;
    budget.charge_timeout_certificate(&certificate)?;
    Ok(certificate)
}

/// Decodes one complete canonical application-payload value.
///
/// Transaction bytes remain opaque and are copied byte-for-byte only after
/// all structural bounds and exact root exhaustion have been established.
pub fn decode_application_payload_v0_exact(
    bytes: &[u8],
    consensus_parameters: &ConsensusParametersV0,
) -> DecodeResult<ApplicationPayloadV0> {
    let maximum_bytes = usize::try_from(consensus_parameters.max_block_bytes())
        .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0))?;
    require_body_kernel_size(bytes, maximum_bytes)?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_application_payload(&mut cursor, maximum_bytes)?;
    cursor.finish()?;
    admit_raw_application_payload(raw)
}

/// Decodes one complete canonical application payload for staged root binding.
///
/// Unlike [`decode_application_payload_v0_exact`], this entry point does not
/// reject an otherwise canonical payload merely because the payload value by
/// itself exceeds the active `max_block_bytes`. That lets a source-validation
/// boundary compute and compare the canonical payload root before deciding
/// whether a root-bound logical block is deterministically oversized.
///
/// This is not an unbounded decoder. The authenticated active
/// `max_consensus_message_bytes` remains an outer hard bound checked before
/// parsing, and the supplied exact-root length is used as the structural list
/// and item bound so malformed short inputs cannot reserve capacity from the
/// larger active message allowance. Callers must still enforce the complete
/// logical block's active `max_block_bytes` after binding the returned inert
/// payload to its expected header root.
pub fn decode_application_payload_v0_exact_for_root_binding(
    bytes: &[u8],
    consensus_parameters: &ConsensusParametersV0,
) -> DecodeResult<ApplicationPayloadV0> {
    let maximum_message_bytes = usize::try_from(consensus_parameters.max_consensus_message_bytes())
        .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0))?;
    require_body_kernel_size(bytes, maximum_message_bytes)?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_application_payload(&mut cursor, bytes.len())?;
    cursor.finish()?;
    admit_raw_application_payload(raw)
}

/// Decodes one complete canonical receipt-commitment preimage.
///
/// Protocol integration must source accepted receipts from the locally
/// authorized deterministic runtime. The returned value is inert: exact
/// decoding alone neither proves that provenance nor creates runtime, voting,
/// epoch, anchor, or transition authority.
pub fn decode_execution_receipt_commitment_v0_exact(
    bytes: &[u8],
    consensus_parameters: &ConsensusParametersV0,
) -> DecodeResult<ExecutionReceiptCommitmentV0> {
    let maximum_bytes = usize::try_from(consensus_parameters.max_block_bytes())
        .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0))?;
    require_body_kernel_size(bytes, maximum_bytes)?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_execution_receipt_commitment(&mut cursor, maximum_bytes)?;
    cursor.finish()?;
    admit_raw_execution_receipt_commitment(raw)
}

/// Decodes one complete ordinary double-vote evidence value.
///
/// Its only variable-width fields are the two 128-byte-bounded chain IDs and
/// validator IDs, and it contains no list, so this endpoint has an intrinsic
/// sub-kilobyte structural bound. The enclosing block evidence list and total
/// logical block size remain subject to the authenticated active parameters.
///
/// The trusted active validator set is required for exact context and author
/// admission. The two fixed-size signatures are retained exactly; callers
/// must additionally call [`DoubleVoteEvidenceV0::verify`] with a strict
/// cryptographic verifier before treating the evidence as valid.
pub fn decode_double_vote_evidence_v0_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> DecodeResult<DoubleVoteEvidenceV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_double_vote_evidence(&mut cursor)?;
    cursor.finish()?;
    admit_raw_double_vote_evidence(raw, validator_set)
}

fn require_body_kernel_size(bytes: &[u8], maximum_bytes: usize) -> DecodeResult<()> {
    if bytes.len() > maximum_bytes {
        return Err(DecodeError::new(DecodeErrorCode::LengthLimitExceeded, 0));
    }
    Ok(())
}

fn parse_raw_application_payload<'a>(
    cursor: &mut Cursor<'a>,
    maximum_bytes: usize,
) -> DecodeResult<RawApplicationPayload<'a>> {
    let transaction_count_offset = cursor.offset();
    let minimum_frame = core::mem::size_of::<u32>();
    let maximum_transactions = bounded_list_maximum(maximum_bytes, minimum_frame);
    let transaction_count = cursor.list_len_with_minimum(maximum_transactions, minimum_frame)?;
    let mut transactions = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        transactions.push(cursor.bounded_body_bytes(maximum_bytes)?);
    }
    Ok(RawApplicationPayload {
        transaction_count_offset,
        transactions,
    })
}

fn admit_raw_application_payload(
    raw: RawApplicationPayload<'_>,
) -> DecodeResult<ApplicationPayloadV0> {
    let transactions = raw
        .transactions
        .into_iter()
        .map(|transaction| transaction.bytes.to_vec())
        .collect();
    ApplicationPayloadV0::new(transactions).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::LengthLimitExceeded,
            raw.transaction_count_offset,
        )
    })
}

fn parse_raw_execution_receipt_commitment<'a>(
    cursor: &mut Cursor<'a>,
    maximum_bytes: usize,
) -> DecodeResult<RawExecutionReceiptCommitment<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let transaction_index = cursor.u32()?;
    let payload_leaf_hash = cursor.fixed()?;
    let gas_used = cursor.u64()?;
    let fee_charged = cursor.u128()?;
    let event_count_offset = cursor.offset();
    let minimum_event = core::mem::size_of::<u64>();
    let maximum_events = bounded_list_maximum(maximum_bytes, minimum_event);
    let event_count = cursor.list_len_with_minimum(maximum_events, minimum_event)?;
    let mut events = Vec::with_capacity(event_count);
    for _ in 0..event_count {
        events.push(parse_raw_execution_event(cursor, maximum_bytes)?);
    }
    Ok(RawExecutionReceiptCommitment {
        object_offset,
        schema_version,
        transaction_index,
        payload_leaf_hash,
        gas_used,
        fee_charged,
        event_count_offset,
        events,
    })
}

fn parse_raw_execution_event<'a>(
    cursor: &mut Cursor<'a>,
    maximum_bytes: usize,
) -> DecodeResult<RawExecutionEvent<'a>> {
    let kind = cursor.bounded_body_bytes(maximum_bytes)?;
    let attribute_count_offset = cursor.offset();
    let minimum_attribute = core::mem::size_of::<u64>();
    let maximum_attributes = bounded_list_maximum(maximum_bytes, minimum_attribute);
    let attribute_count = cursor.list_len_with_minimum(maximum_attributes, minimum_attribute)?;
    let mut attributes = Vec::with_capacity(attribute_count);
    for _ in 0..attribute_count {
        let object_offset = cursor.offset();
        let key = cursor.bounded_body_bytes(maximum_bytes)?;
        let value = cursor.bounded_body_bytes(maximum_bytes)?;
        attributes.push(RawExecutionEventAttribute {
            object_offset,
            key,
            value,
        });
    }
    Ok(RawExecutionEvent {
        kind,
        attribute_count_offset,
        attributes,
    })
}

fn admit_raw_execution_receipt_commitment(
    raw: RawExecutionReceiptCommitment<'_>,
) -> DecodeResult<ExecutionReceiptCommitmentV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let mut events = Vec::with_capacity(raw.events.len());
    for event in raw.events {
        let kind = admit_runtime_string(event.kind)?;
        for pair in event.attributes.windows(2) {
            if pair[0].key.bytes >= pair[1].key.bytes {
                return Err(DecodeError::new(
                    DecodeErrorCode::NonCanonicalEventAttributeOrder,
                    pair[1].key.length_offset,
                ));
            }
        }
        let mut attributes = Vec::with_capacity(event.attributes.len());
        for attribute in event.attributes {
            let key = admit_runtime_string(attribute.key)?;
            let value = admit_runtime_string(attribute.value)?;
            attributes.push(ExecutionEventAttributeV0::new(key, value).map_err(|_| {
                DecodeError::new(DecodeErrorCode::InvalidUtf8, attribute.object_offset)
            })?);
        }
        events.push(ExecutionEventV0::new(kind, attributes).map_err(|_| {
            DecodeError::new(
                DecodeErrorCode::NonCanonicalEventAttributeOrder,
                event.attribute_count_offset,
            )
        })?);
    }
    ExecutionReceiptCommitmentV0::new(
        raw.transaction_index,
        raw.payload_leaf_hash,
        raw.gas_used,
        raw.fee_charged,
        events,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, raw.event_count_offset))
}

fn admit_runtime_string(raw: RawBytes<'_>) -> DecodeResult<Vec<u8>> {
    core::str::from_utf8(raw.bytes)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidUtf8, raw.length_offset))?;
    Ok(raw.bytes.to_vec())
}

fn bounded_list_maximum(root_maximum_bytes: usize, minimum_item_bytes: usize) -> usize {
    root_maximum_bytes.saturating_sub(core::mem::size_of::<u32>()) / minimum_item_bytes
}

fn parse_raw_double_vote_evidence<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawDoubleVoteEvidence<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let first = parse_raw_vote_evidence_record(cursor)?;
    let second = parse_raw_vote_evidence_record(cursor)?;
    Ok(RawDoubleVoteEvidence {
        object_offset,
        schema_version,
        first,
        second,
    })
}

fn parse_raw_vote_evidence_record<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawVoteEvidenceRecord<'a>> {
    let object_offset = cursor.offset();
    let context = parse_raw_common_consensus_context(cursor)?;
    let height_offset = cursor.offset();
    let height = Height::new(cursor.u64()?);
    let block_id = BlockId::new(cursor.fixed()?);
    let author = cursor.bounded_validator_id_bytes_raw()?;
    let signature_offset = cursor.offset();
    let signature = Signature64::from_array(cursor.fixed()?);
    Ok(RawVoteEvidenceRecord {
        object_offset,
        context,
        height_offset,
        height,
        block_id,
        author,
        signature_offset,
        signature,
    })
}

fn parse_raw_common_consensus_context<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawCommonConsensusContext<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes_raw()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_hash_offset = cursor.offset();
    let validator_set_hash = ValidatorSetId::new(cursor.fixed()?);
    let view = View::new(cursor.u64()?);
    let message_kind_offset = cursor.offset();
    let message_kind = cursor.u8()?;
    Ok(RawCommonConsensusContext {
        object_offset,
        schema_version,
        genesis_offset,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        validator_set_hash_offset,
        validator_set_hash,
        view,
        message_kind_offset,
        message_kind,
    })
}

fn admit_raw_double_vote_evidence(
    raw: RawDoubleVoteEvidence<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<DoubleVoteEvidenceV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let first = admit_raw_vote_evidence_record(raw.first, validator_set)?;
    let second_offset = raw.second.object_offset;
    let second_height_offset = raw.second.height_offset;
    let second_author_offset = raw.second.author.length_offset;
    let second = admit_raw_vote_evidence_record(raw.second, validator_set)?;

    if first.context() != second.context() {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            second_offset,
        ));
    }
    if first.author() != second.author() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidDoubleVoteEvidence,
            second_author_offset,
        ));
    }
    if first.height() == second.height() && first.block_id() == second.block_id() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidDoubleVoteEvidence,
            second_height_offset,
        ));
    }
    if first.signing_root() >= second.signing_root() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidDoubleVoteEvidence,
            second_offset,
        ));
    }

    DoubleVoteEvidenceV0::from_ordered_records(first, second).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidDoubleVoteEvidence,
            raw.object_offset,
        )
    })
}

fn admit_raw_vote_evidence_record(
    raw: RawVoteEvidenceRecord<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<VoteEvidenceRecordV0> {
    let context = admit_raw_vote_context(raw.context, validator_set)?;
    if raw.author.bytes.is_empty() {
        return Err(DecodeError::new(
            DecodeErrorCode::LengthLimitExceeded,
            raw.author.length_offset,
        ));
    }
    let author = admit_validator_id(raw.author)?;
    if validator_set.validator(author).is_none() {
        return Err(DecodeError::new(
            DecodeErrorCode::UnknownSigner,
            raw.author.length_offset,
        ));
    }
    VoteEvidenceRecordV0::new(context, raw.height, raw.block_id, author, raw.signature).map_err(
        |_| {
            DecodeError::new(
                DecodeErrorCode::InvalidDoubleVoteEvidence,
                raw.signature_offset,
            )
        },
    )
}

fn admit_raw_vote_context(
    raw: RawCommonConsensusContext<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<CommonConsensusContextV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    if raw.validator_set_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            raw.validator_set_hash_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    if raw.message_kind != MessageKind::Vote as u8 {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            raw.message_kind_offset,
        ));
    }
    require_trusted_set_context(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_hash,
        validator_set,
        raw.object_offset,
    )?;
    CommonConsensusContextV0::new(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_hash,
        raw.view,
        MessageKind::Vote,
    )
    .map_err(|error| {
        let offset = match error {
            ValidationError::ZeroGenesisHash => raw.genesis_offset,
            ValidationError::ValidatorSetMismatch => raw.validator_set_hash_offset,
            _ => raw.object_offset,
        };
        DecodeError::new(DecodeErrorCode::ContextMismatch, offset)
    })
}

/// Decodes one complete canonical `BlockHeaderV0` logical value.
///
/// This admits only the frozen header shape. It does not authenticate a block
/// body, execute the payload, or establish checkpoint/seal ancestry.
pub fn decode_block_header_v0_exact(bytes: &[u8]) -> DecodeResult<BlockHeader> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_block_header(&mut cursor)?;
    cursor.finish()?;
    admit_raw_block_header(raw)
}

/// Decodes one complete ordinary `CertifiedHeaderV0` against authenticated
/// old-epoch context.
///
/// The proposal justify and certifying certificates are admitted only as
/// ordinary, non-empty, positive-view QCs. An optional ordinary TC is allowed;
/// synthetic anchors and epoch-anchor authorization are intentionally outside
/// this old-epoch entry point. Signature cryptography remains a separate step.
pub fn decode_ordinary_certified_header_v0_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
) -> DecodeResult<CertifiedHeaderV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_ordinary_certified_header(&mut cursor)?;
    cursor.finish()?;
    admit_raw_ordinary_certified_header(
        raw,
        validator_set,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
    )
}

/// Bounded-admission variant of [`decode_ordinary_certified_header_v0_exact`].
/// The complete header is charged after semantic admission so nested justify,
/// timeout, and certifying QC shares all consume one authenticated budget.
pub fn decode_ordinary_certified_header_v0_exact_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<CertifiedHeaderV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_ordinary_certified_header_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let header = admit_raw_ordinary_certified_header(
        raw,
        validator_set,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
    )?;
    budget.charge_certified_header(&header)?;
    Ok(header)
}

/// Decodes one complete epoch-zero certified header with trusted GenesisQC.
///
/// The proposal justify and optional TC references may contain the exact
/// empty-signature GenesisQC derived from `epoch_zero_validator_set`.
/// Certifying QCs remain ordinary, and epoch-anchor authorization remains
/// outside this entry point. The complete semantic value must canonically
/// re-encode byte-for-byte to the supplied exact root.
pub fn decode_certified_header_v0_exact_with_trusted_genesis(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
) -> DecodeResult<CertifiedHeaderV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_ordinary_certified_header(&mut cursor)?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let certified = admit_raw_certified_header_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, certified.try_cev0_bytes(), 0)?;
    Ok(certified)
}

/// Bounded-admission variant of
/// [`decode_certified_header_v0_exact_with_trusted_genesis`].
pub fn decode_certified_header_v0_exact_with_trusted_genesis_and_budget(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<CertifiedHeaderV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_ordinary_certified_header_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let header = admit_raw_certified_header_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, header.try_cev0_bytes(), 0)?;
    budget.charge_certified_header(&header)?;
    Ok(header)
}

/// Decodes one complete same-epoch `FinalityProofV0` against authenticated
/// validator/parameter context.
///
/// This is the general three-chain decoder: it performs bounded,
/// root-exhausting CEV0 parsing and complete ordinary proposal/QC/optional-TC
/// semantic admission, but does not impose checkpoint/two-seal geometry. The
/// returned proof remains cryptographically inert until a caller verifies it
/// with a production signature verifier.
pub fn decode_finality_proof_v0_exact(
    bytes: &[u8],
    active_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
) -> DecodeResult<FinalityProofV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof(&mut cursor)?;
    cursor.finish()?;
    admit_raw_finality_proof(
        raw,
        active_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
    )
}

/// Bounded-admission variant of [`decode_finality_proof_v0_exact`].
/// Finality proofs contain three certified headers; this wrapper charges the
/// complete aggregate rather than relying on callers to budget each nested
/// certificate manually.
pub fn decode_finality_proof_v0_exact_with_budget(
    bytes: &[u8],
    active_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<FinalityProofV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let proof = admit_raw_finality_proof(
        raw,
        active_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
    )?;
    budget.charge_finality_proof(&proof)?;
    Ok(proof)
}

/// Decodes one complete epoch-zero finality proof with trusted GenesisQC.
///
/// This extends [`decode_finality_proof_v0_exact`] only enough to admit the
/// trusted genesis justification (and a TC that references it) in the exact
/// protocol positions allowed by `CertifiedHeaderV0`. It cannot reconstruct
/// epoch-anchor authorization. The complete proof must canonically re-encode
/// byte-for-byte to the supplied exact root.
pub fn decode_finality_proof_v0_exact_with_trusted_genesis(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
) -> DecodeResult<FinalityProofV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof(&mut cursor)?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let proof = admit_raw_finality_proof_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, proof.try_cev0_bytes(), 0)?;
    Ok(proof)
}

/// Bounded-admission variant of
/// [`decode_finality_proof_v0_exact_with_trusted_genesis`].
pub fn decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(
    bytes: &[u8],
    epoch_zero_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<FinalityProofV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let trusted_genesis = trusted_genesis_qc_v0(epoch_zero_validator_set, raw.object_offset)?;
    let proof = admit_raw_finality_proof_with_reference_admission(
        raw,
        epoch_zero_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
        QcReferenceAdmissionV0::TrustedGenesis(&trusted_genesis),
    )?;
    require_exact_canonical_reencoding(bytes, proof.try_cev0_bytes(), 0)?;
    budget.charge_finality_proof(&proof)?;
    Ok(proof)
}

/// Decodes the exact old-set checkpoint/two-seal finality kernel.
///
/// This performs bounded root-exhausting CEV0 decoding, complete ordinary
/// proposal/QC/optional-TC semantic admission, authenticated parent-relative
/// timestamp checks, and the checkpoint/two-seal geometry and commitment
/// relations. The returned proof remains inert until the caller separately
/// invokes `verify_checkpoint_two_seal_kernel` with a production strict
/// signature verifier.
pub fn decode_checkpoint_finality_proof_v0_exact(
    bytes: &[u8],
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    authenticated_checkpoint_parent_timestamp_ms: u64,
) -> DecodeResult<FinalityProofV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof(&mut cursor)?;
    cursor.finish()?;
    let object_offset = raw.object_offset;
    let proof = admit_raw_finality_proof(
        raw,
        old_validator_set,
        old_consensus_parameters,
        authenticated_checkpoint_parent_timestamp_ms,
    )?;
    proof
        .validate_checkpoint_two_seal_kernel(
            old_validator_set,
            old_consensus_parameters,
            next_epoch_commitment,
            authenticated_checkpoint_parent_timestamp_ms,
        )
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidCheckpointTwoSeal, object_offset))?;
    Ok(proof)
}

/// Bounded-admission variant of
/// [`decode_checkpoint_finality_proof_v0_exact`].
pub fn decode_checkpoint_finality_proof_v0_exact_with_budget(
    bytes: &[u8],
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    authenticated_checkpoint_parent_timestamp_ms: u64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> DecodeResult<FinalityProofV0> {
    budget.admit_root_bytes(bytes.len())?;
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_checkpoint_finality_proof_with_aggregate_limit(
        &mut cursor,
        budget.maximum_tc_aggregate_signature_shares(),
    )?;
    cursor.finish()?;
    let object_offset = raw.object_offset;
    let proof = admit_raw_finality_proof(
        raw,
        old_validator_set,
        old_consensus_parameters,
        authenticated_checkpoint_parent_timestamp_ms,
    )?;
    proof
        .validate_checkpoint_two_seal_kernel(
            old_validator_set,
            old_consensus_parameters,
            next_epoch_commitment,
            authenticated_checkpoint_parent_timestamp_ms,
        )
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidCheckpointTwoSeal, object_offset))?;
    budget.charge_finality_proof(&proof)?;
    Ok(proof)
}

fn parse_raw_ordinary_certified_header<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawOrdinaryCertifiedHeader<'a>> {
    parse_raw_ordinary_certified_header_with_aggregate_limit(
        cursor,
        MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
    )
}

fn parse_raw_ordinary_certified_header_with_aggregate_limit<'a>(
    cursor: &mut Cursor<'a>,
    maximum_aggregate_shares: usize,
) -> DecodeResult<RawOrdinaryCertifiedHeader<'a>> {
    let object_offset = cursor.offset();
    let header = parse_raw_block_header(cursor)?;
    let maximum_qc_shares = maximum_aggregate_shares.min(MAX_CEV0_CERTIFICATE_ITEMS);
    let justify_qc = parse_raw_qc(cursor, maximum_qc_shares)?;
    let timeout_tag_offset = cursor.offset();
    let timeout_certificate = match cursor.u8()? {
        0 => None,
        1 => Some(parse_raw_timeout_certificate_with_aggregate_limit(
            cursor,
            maximum_aggregate_shares,
        )?),
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidOptionalTag,
                timeout_tag_offset,
            ));
        }
    };
    let anchor_tag_offset = cursor.offset();
    match cursor.u8()? {
        0 => {}
        1 => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidCheckpointTwoSeal,
                anchor_tag_offset,
            ));
        }
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidOptionalTag,
                anchor_tag_offset,
            ));
        }
    }
    let proposer_signature = Signature64::from_array(cursor.fixed()?);
    let certifying_qc = parse_raw_qc(cursor, maximum_qc_shares)?;
    Ok(RawOrdinaryCertifiedHeader {
        object_offset,
        header,
        justify_qc,
        timeout_certificate,
        proposer_signature,
        certifying_qc,
    })
}

fn admit_raw_ordinary_certified_header(
    raw: RawOrdinaryCertifiedHeader<'_>,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
) -> DecodeResult<CertifiedHeaderV0> {
    admit_raw_certified_header_with_reference_admission(
        raw,
        validator_set,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
        QcReferenceAdmissionV0::OrdinaryOnly,
    )
}

fn admit_raw_certified_header_with_reference_admission(
    raw: RawOrdinaryCertifiedHeader<'_>,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
    reference_admission: QcReferenceAdmissionV0<'_>,
) -> DecodeResult<CertifiedHeaderV0> {
    let object_offset = raw.object_offset;
    let proposer_offset = raw.header.proposer_id.length_offset;
    let header = admit_raw_block_header(raw.header)?;
    validator_set
        .validate_against_parameters(consensus_parameters)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidConsensusParameters, 0))?;
    if header.genesis_hash() != validator_set.genesis_hash()
        || header.chain_id() != validator_set.chain_id()
        || header.protocol_version() != validator_set.protocol_version()
        || header.epoch() != validator_set.epoch()
        || header.validator_set_id() != validator_set.id()
        || header.consensus_parameters_hash() != consensus_parameters.hash()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidFinalityProof,
            object_offset,
        ));
    }
    validate_scheduled_leader(&header, validator_set, consensus_parameters)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidLeaderSchedule, proposer_offset))?;
    validate_timestamp_step(
        authenticated_parent_timestamp_ms,
        header.timestamp_ms(),
        consensus_parameters,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidFinalityProof, object_offset))?;

    let justify_qc = admit_raw_qc_reference(raw.justify_qc, validator_set, reference_admission)?;
    let timeout_certificate = raw
        .timeout_certificate
        .map(|certificate| {
            admit_raw_timeout_certificate_with_reference_admission(
                certificate,
                validator_set,
                reference_admission,
            )
        })
        .transpose()?;
    let certifying_qc = admit_raw_ordinary_qc(raw.certifying_qc, validator_set)?;
    CertifiedHeaderV0::new(
        header,
        justify_qc,
        timeout_certificate,
        None,
        raw.proposer_signature,
        certifying_qc,
        validator_set,
        None,
        consensus_parameters,
        authenticated_parent_timestamp_ms,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidFinalityProof, object_offset))
}

fn parse_raw_checkpoint_finality_proof<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawCheckpointFinalityProof<'a>> {
    parse_raw_checkpoint_finality_proof_with_aggregate_limit(
        cursor,
        MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
    )
}

fn parse_raw_checkpoint_finality_proof_with_aggregate_limit<'a>(
    cursor: &mut Cursor<'a>,
    maximum_aggregate_shares: usize,
) -> DecodeResult<RawCheckpointFinalityProof<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let parameters_hash_offset = cursor.offset();
    let consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let finalized_block =
        parse_raw_ordinary_certified_header_with_aggregate_limit(cursor, maximum_aggregate_shares)?;
    let child =
        parse_raw_ordinary_certified_header_with_aggregate_limit(cursor, maximum_aggregate_shares)?;
    let grandchild =
        parse_raw_ordinary_certified_header_with_aggregate_limit(cursor, maximum_aggregate_shares)?;
    Ok(RawCheckpointFinalityProof {
        object_offset,
        schema_version,
        genesis_offset,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        validator_set_id,
        parameters_hash_offset,
        consensus_parameters_hash,
        finalized_block,
        child,
        grandchild,
    })
}

fn admit_raw_finality_proof(
    raw: RawCheckpointFinalityProof<'_>,
    active_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
) -> DecodeResult<FinalityProofV0> {
    admit_raw_finality_proof_with_reference_admission(
        raw,
        active_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
        QcReferenceAdmissionV0::OrdinaryOnly,
    )
}

fn admit_raw_finality_proof_with_reference_admission(
    raw: RawCheckpointFinalityProof<'_>,
    active_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_finalized_parent_timestamp_ms: u64,
    reference_admission: QcReferenceAdmissionV0<'_>,
) -> DecodeResult<FinalityProofV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    require_trusted_set_context(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_id,
        active_validator_set,
        raw.object_offset,
    )?;
    active_validator_set
        .validate_against_parameters(consensus_parameters)
        .map_err(|_| {
            DecodeError::new(
                DecodeErrorCode::InvalidConsensusParameters,
                raw.parameters_hash_offset,
            )
        })?;
    if raw.consensus_parameters_hash != consensus_parameters.hash()
        || raw.consensus_parameters_hash != active_validator_set.consensus_parameters_hash()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidFinalityProof,
            raw.parameters_hash_offset,
        ));
    }

    let finalized_block = admit_raw_certified_header_with_reference_admission(
        raw.finalized_block,
        active_validator_set,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
        reference_admission,
    )?;
    let child_parent_timestamp_ms = finalized_block.header().timestamp_ms();
    let child = admit_raw_certified_header_with_reference_admission(
        raw.child,
        active_validator_set,
        consensus_parameters,
        child_parent_timestamp_ms,
        reference_admission,
    )?;
    let grandchild_parent_timestamp_ms = child.header().timestamp_ms();
    let grandchild = admit_raw_certified_header_with_reference_admission(
        raw.grandchild,
        active_validator_set,
        consensus_parameters,
        grandchild_parent_timestamp_ms,
        reference_admission,
    )?;
    let proof = FinalityProofV0::new(
        finalized_block,
        child,
        grandchild,
        active_validator_set,
        None,
        consensus_parameters,
        authenticated_finalized_parent_timestamp_ms,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidFinalityProof, raw.object_offset))?;
    Ok(proof)
}

/// Decodes one complete canonical `NextEpochCommitmentV0` logical value.
///
/// The returned value is an inert commitment preimage. Exact decoding and
/// intrinsic shape admission do not authenticate the snapshot, validator set,
/// parameter preimage, upgrade plan, checkpoint ancestry, or epoch handoff.
pub fn decode_next_epoch_commitment_v0_exact(bytes: &[u8]) -> DecodeResult<NextEpochCommitmentV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_next_epoch_commitment(&mut cursor)?;
    cursor.finish()?;
    admit_raw_next_epoch_commitment(raw)
}

fn parse_raw_next_epoch_commitment<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawNextEpochCommitment<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes_raw()?;
    let old_epoch = Epoch::new(cursor.u64()?);
    let new_epoch_offset = cursor.offset();
    let new_epoch = Epoch::new(cursor.u64()?);
    let snapshot_cutoff_height = Height::new(cursor.u64()?);
    let snapshot_state_root_offset = cursor.offset();
    let snapshot_state_root = StateRoot::new(cursor.fixed()?);
    let protocol_offset = cursor.offset();
    let new_protocol_version = cursor.u32()?;
    let new_validator_set_hash_offset = cursor.offset();
    let new_validator_set_hash = ValidatorSetId::new(cursor.fixed()?);
    let new_consensus_parameters_hash_offset = cursor.offset();
    let new_consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let rollout_phase_offset = cursor.offset();
    let rollout_phase = cursor.u8()?;
    let optional_tag_offset = cursor.offset();
    let upgrade_plan_hash = match cursor.u8()? {
        0 => None,
        1 => Some(UpgradePlanHash::new(cursor.fixed()?)),
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidOptionalTag,
                optional_tag_offset,
            ));
        }
    };
    let fallback_used_offset = cursor.offset();
    let fallback_used = cursor.u8()?;
    let fallback_reason_offset = cursor.offset();
    let fallback_reason = cursor.u16()?;
    let activation_height_offset = cursor.offset();
    let activation_height = Height::new(cursor.u64()?);
    Ok(RawNextEpochCommitment {
        object_offset,
        schema_version,
        genesis_offset,
        genesis_hash,
        chain_id,
        old_epoch,
        new_epoch_offset,
        new_epoch,
        snapshot_cutoff_height,
        snapshot_state_root_offset,
        snapshot_state_root,
        protocol_offset,
        new_protocol_version,
        new_validator_set_hash_offset,
        new_validator_set_hash,
        new_consensus_parameters_hash_offset,
        new_consensus_parameters_hash,
        rollout_phase_offset,
        rollout_phase,
        upgrade_plan_hash_offset: optional_tag_offset,
        upgrade_plan_hash,
        fallback_used_offset,
        fallback_used,
        fallback_reason_offset,
        fallback_reason,
        activation_height_offset,
        activation_height,
    })
}

fn admit_raw_next_epoch_commitment(
    raw: RawNextEpochCommitment<'_>,
) -> DecodeResult<NextEpochCommitmentV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let new_protocol_version = ProtocolVersion::new(raw.new_protocol_version).map_err(|error| {
        map_validation_error(
            error,
            raw.protocol_offset,
            SemanticObject::NextEpochCommitment,
        )
    })?;
    let rollout_phase = RolloutPhase::try_from(raw.rollout_phase).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidRolloutPhase,
            raw.rollout_phase_offset,
        )
    })?;
    let fallback_used = match raw.fallback_used {
        0 => false,
        1 => true,
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidBoolean,
                raw.fallback_used_offset,
            ));
        }
    };
    let fallback_reason = EpochFallbackReasonV0::try_from(raw.fallback_reason).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidFallbackReason,
            raw.fallback_reason_offset,
        )
    })?;
    for (is_zero, offset) in [
        (
            raw.snapshot_state_root.is_zero(),
            raw.snapshot_state_root_offset,
        ),
        (
            raw.new_validator_set_hash.is_zero(),
            raw.new_validator_set_hash_offset,
        ),
        (
            raw.new_consensus_parameters_hash.is_zero(),
            raw.new_consensus_parameters_hash_offset,
        ),
    ] {
        if is_zero {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidNextEpochCommitment,
                offset,
            ));
        }
    }
    if raw
        .upgrade_plan_hash
        .is_some_and(|upgrade_plan_hash| upgrade_plan_hash.is_zero())
    {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidNextEpochCommitment,
            raw.upgrade_plan_hash_offset,
        ));
    }
    if raw.old_epoch.get().checked_add(1) != Some(raw.new_epoch.get()) {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidNextEpochCommitment,
            raw.new_epoch_offset,
        ));
    }
    if fallback_used == (fallback_reason == EpochFallbackReasonV0::None) {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidFallbackReason,
            raw.fallback_reason_offset,
        ));
    }
    if raw.activation_height.get() == 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidNextEpochCommitment,
            raw.activation_height_offset,
        ));
    }
    NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
        schema_version: raw.schema_version,
        genesis_hash: raw.genesis_hash,
        chain_id,
        old_epoch: raw.old_epoch,
        new_epoch: raw.new_epoch,
        snapshot_cutoff_height: raw.snapshot_cutoff_height,
        snapshot_state_root: raw.snapshot_state_root,
        new_protocol_version,
        new_validator_set_hash: raw.new_validator_set_hash,
        new_consensus_parameters_hash: raw.new_consensus_parameters_hash,
        rollout_phase,
        upgrade_plan_hash: raw.upgrade_plan_hash,
        fallback_used,
        fallback_reason,
        activation_height: raw.activation_height,
    })
    .map_err(|error| {
        map_validation_error(
            error,
            raw.object_offset,
            SemanticObject::NextEpochCommitment,
        )
    })
}

/// Decodes one complete handoff descriptor without claiming transition
/// authorization. Old/new set binding is enforced by the certificate APIs.
pub fn decode_handoff_descriptor_v0_exact(bytes: &[u8]) -> DecodeResult<HandoffDescriptorV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_handoff_descriptor(&mut cursor)?;
    cursor.finish()?;
    admit_raw_handoff_descriptor(raw)
}

/// Decodes and semantically admits the shape and both weighted signer roles
/// of one handoff certificate against trusted old/new validator sets.
pub fn decode_handoff_certificate_v0_exact(
    bytes: &[u8],
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
) -> DecodeResult<HandoffCertificateV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_handoff_certificate(&mut cursor)?;
    cursor.finish()?;
    admit_raw_handoff_certificate(raw, old_validator_set, new_validator_set)
}

/// Decodes the bounded epoch-anchor authorization *certificate kernel*.
///
/// The terminal QC is admitted strictly as an ordinary, non-empty old-set QC;
/// peer bytes are never reinterpreted as a synthetic anchor. This validates
/// the terminal header/QC/descriptor relations and both handoff signer roles,
/// but it does not prove checkpoint ancestry, the two-seal construction,
/// `NextEpochCommitment` reconstruction, signature cryptography, or complete
/// epoch-transition authorization.
pub fn decode_epoch_anchor_authorization_kernel_v0_exact(
    bytes: &[u8],
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
) -> DecodeResult<EpochAnchorAuthorizationKernelV0> {
    let mut cursor = Cursor::new(bytes);
    let raw = parse_raw_epoch_anchor_authorization_kernel(&mut cursor)?;
    cursor.finish()?;

    let terminal_old_header = admit_raw_block_header(raw.terminal_old_header)?;
    let terminal_old_qc = admit_raw_ordinary_qc(raw.terminal_old_qc, old_validator_set)?;
    let handoff_certificate = admit_raw_handoff_certificate(
        raw.handoff_certificate,
        old_validator_set,
        new_validator_set,
    )?;
    EpochAnchorAuthorizationV0::new(
        terminal_old_header.clone(),
        terminal_old_qc.clone(),
        handoff_certificate.clone(),
        old_validator_set,
        new_validator_set,
    )
    .map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidEpochAnchorRelations,
            raw.object_offset,
        )
    })?;
    Ok(EpochAnchorAuthorizationKernelV0 {
        terminal_old_header,
        terminal_old_qc,
        handoff_certificate,
    })
}

fn parse_raw_block_header<'a>(cursor: &mut Cursor<'a>) -> DecodeResult<RawBlockHeader<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let view = View::new(cursor.u64()?);
    let height = Height::new(cursor.u64()?);
    let block_kind_offset = cursor.offset();
    let block_kind = match cursor.u8()? {
        0 => BlockKind::Regular,
        1 => BlockKind::EpochCheckpoint,
        2 => BlockKind::EpochSeal1,
        3 => BlockKind::EpochSeal2,
        4 => BlockKind::EpochHandoff,
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidBlockKind,
                block_kind_offset,
            ));
        }
    };
    let parent_id = BlockId::new(cursor.fixed()?);
    let proposer_id = cursor.bounded_validator_id_bytes()?;
    let validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let payload_digest = PayloadDigest::new(cursor.fixed()?);
    let state_root = StateRoot::new(cursor.fixed()?);
    let receipts_root = ReceiptsRoot::new(cursor.fixed()?);
    let evidence_root = EvidenceRoot::new(cursor.fixed()?);
    let timestamp_ms = cursor.u64()?;
    let optional_tag_offset = cursor.offset();
    let next_epoch_commitment_hash = match cursor.u8()? {
        0 => None,
        1 => Some(NextEpochCommitmentHash::new(cursor.fixed()?)),
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidOptionalTag,
                optional_tag_offset,
            ));
        }
    };
    Ok(RawBlockHeader {
        object_offset,
        schema_version,
        genesis_offset,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        view,
        height,
        block_kind,
        parent_id,
        proposer_id,
        validator_set_id,
        consensus_parameters_hash,
        payload_digest,
        state_root,
        receipts_root,
        evidence_root,
        timestamp_ms,
        next_epoch_commitment_hash,
    })
}

fn admit_raw_block_header(raw: RawBlockHeader<'_>) -> DecodeResult<BlockHeader> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    if raw.protocol_version != ProtocolVersion::V0.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidBlockHeader,
            raw.protocol_offset,
        ));
    }
    let protocol_version = ProtocolVersion::V0;
    let proposer_id = admit_validator_id(raw.proposer_id)?;
    BlockHeader::new(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.view,
        raw.height,
        raw.block_kind,
        raw.parent_id,
        proposer_id,
        raw.validator_set_id,
        raw.consensus_parameters_hash,
        raw.payload_digest,
        raw.state_root,
        raw.receipts_root,
        raw.evidence_root,
        raw.timestamp_ms,
        raw.next_epoch_commitment_hash,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidBlockHeader, raw.object_offset))
}

fn parse_raw_handoff_descriptor<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawHandoffDescriptor<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_offset = cursor.offset();
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let old_epoch = Epoch::new(cursor.u64()?);
    let new_epoch = Epoch::new(cursor.u64()?);
    let old_protocol_version = cursor.u32()?;
    let new_protocol_version = cursor.u32()?;
    let old_validator_set_hash = ValidatorSetId::new(cursor.fixed()?);
    let new_validator_set_hash = ValidatorSetId::new(cursor.fixed()?);
    let old_consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let new_consensus_parameters_hash = ConsensusParametersHash::new(cursor.fixed()?);
    let checkpoint_height = Height::new(cursor.u64()?);
    let checkpoint_block_id = BlockId::new(cursor.fixed()?);
    let checkpoint_state_root = StateRoot::new(cursor.fixed()?);
    let next_epoch_commitment_digest = NextEpochCommitmentHash::new(cursor.fixed()?);
    let terminal_old_height = Height::new(cursor.u64()?);
    let terminal_old_block_id = BlockId::new(cursor.fixed()?);
    let terminal_old_qc_digest = CertificateId::new(cursor.fixed()?);
    let terminal_old_view = View::new(cursor.u64()?);
    let activation_height = Height::new(cursor.u64()?);
    let initial_new_view = View::new(cursor.u64()?);
    Ok(RawHandoffDescriptor {
        object_offset,
        schema_version,
        genesis_offset,
        genesis_hash,
        chain_id,
        old_epoch,
        new_epoch,
        old_protocol_version,
        new_protocol_version,
        old_validator_set_hash,
        new_validator_set_hash,
        old_consensus_parameters_hash,
        new_consensus_parameters_hash,
        checkpoint_height,
        checkpoint_block_id,
        checkpoint_state_root,
        next_epoch_commitment_digest,
        terminal_old_height,
        terminal_old_block_id,
        terminal_old_qc_digest,
        terminal_old_view,
        activation_height,
        initial_new_view,
    })
}

fn admit_raw_handoff_descriptor(
    raw: RawHandoffDescriptor<'_>,
) -> DecodeResult<HandoffDescriptorV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    if raw.genesis_hash.is_zero() {
        return Err(DecodeError::new(
            DecodeErrorCode::ZeroGenesisHash,
            raw.genesis_offset,
        ));
    }
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let old_protocol_version = ProtocolVersion::new(raw.old_protocol_version).map_err(|_| {
        DecodeError::new(DecodeErrorCode::InvalidHandoffDescriptor, raw.object_offset)
    })?;
    let new_protocol_version = ProtocolVersion::new(raw.new_protocol_version).map_err(|_| {
        DecodeError::new(DecodeErrorCode::InvalidHandoffDescriptor, raw.object_offset)
    })?;
    HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: raw.genesis_hash,
        chain_id,
        old_epoch: raw.old_epoch,
        new_epoch: raw.new_epoch,
        old_protocol_version,
        new_protocol_version,
        old_validator_set_hash: raw.old_validator_set_hash,
        new_validator_set_hash: raw.new_validator_set_hash,
        old_consensus_parameters_hash: raw.old_consensus_parameters_hash,
        new_consensus_parameters_hash: raw.new_consensus_parameters_hash,
        checkpoint_height: raw.checkpoint_height,
        checkpoint_block_id: raw.checkpoint_block_id,
        checkpoint_state_root: raw.checkpoint_state_root,
        next_epoch_commitment_digest: raw.next_epoch_commitment_digest,
        terminal_old_height: raw.terminal_old_height,
        terminal_old_block_id: raw.terminal_old_block_id,
        terminal_old_qc_digest: raw.terminal_old_qc_digest,
        terminal_old_view: raw.terminal_old_view,
        activation_height: raw.activation_height,
        initial_new_view: raw.initial_new_view,
    })
    .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidHandoffDescriptor, raw.object_offset))
}

fn parse_raw_handoff_certificate<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawHandoffCertificate<'a>> {
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let descriptor = parse_raw_handoff_descriptor(cursor)?;
    let old_count_offset = cursor.offset();
    let old_count = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS)?;
    let mut old_signatures = Vec::with_capacity(old_count);
    for _ in 0..old_count {
        old_signatures.push(parse_raw_signature_share(cursor)?);
    }
    let new_count_offset = cursor.offset();
    let new_count = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS)?;
    let aggregate = old_count.checked_add(new_count).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, new_count_offset)
    })?;
    if aggregate > MAX_CEV0_HANDOFF_AGGREGATE_SIGNATURE_SHARES {
        return Err(DecodeError::new(
            DecodeErrorCode::AggregateLimitExceeded,
            new_count_offset,
        ));
    }
    let mut new_signatures = Vec::with_capacity(new_count);
    for _ in 0..new_count {
        new_signatures.push(parse_raw_signature_share(cursor)?);
    }
    Ok(RawHandoffCertificate {
        object_offset,
        schema_version,
        descriptor,
        old_count_offset,
        old_signatures,
        new_count_offset,
        new_signatures,
    })
}

fn parse_raw_signature_share<'a>(cursor: &mut Cursor<'a>) -> DecodeResult<RawSignatureShare<'a>> {
    Ok(RawSignatureShare {
        offset: cursor.offset(),
        author: cursor.bounded_validator_id_bytes()?,
        signature: Signature64::from_array(cursor.fixed()?),
    })
}

fn admit_raw_handoff_certificate(
    raw: RawHandoffCertificate<'_>,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
) -> DecodeResult<HandoffCertificateV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let descriptor = admit_raw_handoff_descriptor(raw.descriptor)?;
    require_handoff_descriptor_context(
        &descriptor,
        old_validator_set,
        new_validator_set,
        raw.object_offset,
    )?;
    let old_signatures =
        admit_handoff_signature_role(raw.old_signatures, raw.old_count_offset, old_validator_set)?;
    let new_signatures =
        admit_handoff_signature_role(raw.new_signatures, raw.new_count_offset, new_validator_set)?;
    HandoffCertificateV0::new(
        descriptor,
        old_signatures,
        new_signatures,
        old_validator_set,
        new_validator_set,
    )
    .map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidHandoffCertificate,
            raw.object_offset,
        )
    })
}

fn admit_handoff_signature_role(
    raw: Vec<RawSignatureShare<'_>>,
    count_offset: usize,
    validator_set: &ValidatorSet,
) -> DecodeResult<Vec<SignatureShareV0>> {
    if raw.is_empty() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffCertificate,
            count_offset,
        ));
    }
    let mut previous = None;
    let mut signed_power = 0u128;
    let mut shares = Vec::with_capacity(raw.len());
    for share in raw {
        let validator_id = admit_validator_id(share.author)?;
        if let Some(prior) = previous {
            if prior == validator_id {
                return Err(DecodeError::new(
                    DecodeErrorCode::DuplicateSigner,
                    share.offset,
                ));
            }
            if prior > validator_id {
                return Err(DecodeError::new(
                    DecodeErrorCode::NonCanonicalSignerOrder,
                    share.offset,
                ));
            }
        }
        previous = Some(validator_id);
        let power = validator_set
            .power_of(validator_id)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::UnknownSigner, share.offset))?;
        signed_power = signed_power.checked_add(power).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, share.offset)
        })?;
        shares.push(
            SignatureShareV0::new(validator_id, share.signature).map_err(|_| {
                DecodeError::new(DecodeErrorCode::InvalidHandoffCertificate, share.offset)
            })?,
        );
    }
    if signed_power < validator_set.quorum_power() {
        return Err(DecodeError::new(
            DecodeErrorCode::InsufficientQuorum,
            count_offset,
        ));
    }
    Ok(shares)
}

fn require_handoff_descriptor_context(
    descriptor: &HandoffDescriptorV0,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
    offset: usize,
) -> DecodeResult<()> {
    old_validator_set
        .validate_shape()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, offset))?;
    new_validator_set
        .validate_shape()
        .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, offset))?;
    let fields = descriptor.fields();
    let old_matches = fields.genesis_hash == old_validator_set.genesis_hash()
        && fields.chain_id == old_validator_set.chain_id()
        && fields.old_protocol_version == old_validator_set.protocol_version()
        && fields.old_epoch == old_validator_set.epoch()
        && fields.old_validator_set_hash == old_validator_set.id()
        && fields.old_consensus_parameters_hash == old_validator_set.consensus_parameters_hash();
    let new_matches = fields.genesis_hash == new_validator_set.genesis_hash()
        && fields.chain_id == new_validator_set.chain_id()
        && fields.new_protocol_version == new_validator_set.protocol_version()
        && fields.new_epoch == new_validator_set.epoch()
        && fields.new_validator_set_hash == new_validator_set.id()
        && fields.new_consensus_parameters_hash == new_validator_set.consensus_parameters_hash();
    if !old_matches || !new_matches {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidHandoffCertificate,
            offset,
        ));
    }
    Ok(())
}

fn parse_raw_epoch_anchor_authorization_kernel<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawEpochAnchorAuthorization<'a>> {
    let object_offset = cursor.offset();
    let terminal_old_header = parse_raw_block_header(cursor)?;
    let terminal_old_qc = parse_raw_qc(cursor, MAX_CEV0_CERTIFICATE_ITEMS)?;
    let handoff_certificate = parse_raw_handoff_certificate(cursor)?;
    Ok(RawEpochAnchorAuthorization {
        object_offset,
        terminal_old_header,
        terminal_old_qc,
        handoff_certificate,
    })
}

fn parse_raw_timeout_certificate<'a>(
    cursor: &mut Cursor<'a>,
) -> DecodeResult<RawTimeoutCertificate<'a>> {
    parse_raw_timeout_certificate_with_aggregate_limit(
        cursor,
        MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
    )
}

/// Parses a TC while applying the caller's authenticated nested-QC share
/// ceiling before reading or allocating any nested signature list.  The
/// unbudgeted exact decoder deliberately uses the intrinsic protocol cap;
/// budgeted ingress must pass its narrower validator-set/profile cap here.
fn parse_raw_timeout_certificate_with_aggregate_limit<'a>(
    cursor: &mut Cursor<'a>,
    maximum_aggregate_shares: usize,
) -> DecodeResult<RawTimeoutCertificate<'a>> {
    let maximum_aggregate_shares =
        maximum_aggregate_shares.min(MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES);
    let object_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_hash = ValidatorSetId::new(cursor.fixed()?);
    let timed_out_view = View::new(cursor.u64()?);

    let entry_count = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS)?;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let offset = cursor.offset();
        entries.push(RawTimeoutEntry {
            offset,
            signer_id: cursor.bounded_validator_id_bytes()?,
            qc_digest: CertificateId::new(cursor.fixed()?),
            qc_epoch: Epoch::new(cursor.u64()?),
            qc_view: View::new(cursor.u64()?),
            qc_height: Height::new(cursor.u64()?),
            qc_block_id: BlockId::new(cursor.fixed()?),
            signature: Signature64::from_array(cursor.fixed()?),
        });
    }

    let reference_count = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS)?;
    let mut referenced_qcs = Vec::with_capacity(reference_count);
    let mut aggregate_shares = 0usize;
    for _ in 0..reference_count {
        let remaining = maximum_aggregate_shares
            .checked_sub(aggregate_shares)
            .ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, cursor.offset())
            })?;
        let certificate = parse_raw_qc(cursor, remaining)?;
        aggregate_shares = aggregate_shares
            .checked_add(certificate.signatures.len())
            .ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::AggregateLimitExceeded, cursor.offset())
            })?;
        referenced_qcs.push(certificate);
    }
    let selected_high_qc_digest = CertificateId::new(cursor.fixed()?);
    Ok(RawTimeoutCertificate {
        object_offset,
        schema_version,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        validator_set_hash,
        timed_out_view,
        entries,
        referenced_qcs,
        selected_high_qc_digest,
    })
}

#[derive(Clone, Copy)]
enum QcReferenceAdmissionV0<'a> {
    OrdinaryOnly,
    TrustedGenesis(&'a GenesisQcV0),
}

fn admit_raw_qc_reference(
    raw: RawQc<'_>,
    validator_set: &ValidatorSet,
    admission: QcReferenceAdmissionV0<'_>,
) -> DecodeResult<QcReferenceV0> {
    match admission {
        QcReferenceAdmissionV0::OrdinaryOnly => {
            admit_raw_ordinary_qc(raw, validator_set).map(QcReferenceV0::ordinary)
        }
        QcReferenceAdmissionV0::TrustedGenesis(trusted_genesis) => {
            admit_raw_qc_reference_with_trusted_genesis(raw, validator_set, trusted_genesis)
        }
    }
}

fn admit_raw_timeout_certificate(
    raw: RawTimeoutCertificate<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<TimeoutCertificateV0> {
    admit_raw_timeout_certificate_with_reference_admission(
        raw,
        validator_set,
        QcReferenceAdmissionV0::OrdinaryOnly,
    )
}

fn admit_raw_timeout_certificate_with_reference_admission(
    raw: RawTimeoutCertificate<'_>,
    validator_set: &ValidatorSet,
    reference_admission: QcReferenceAdmissionV0<'_>,
) -> DecodeResult<TimeoutCertificateV0> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    require_trusted_set_context(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_hash,
        validator_set,
        raw.object_offset,
    )?;
    let mut entries = Vec::with_capacity(raw.entries.len());
    for entry in raw.entries {
        let signer_id = admit_validator_id(entry.signer_id)?;
        let high_qc = QcRef::new(
            entry.qc_digest,
            entry.qc_epoch,
            entry.qc_view,
            entry.qc_height,
            entry.qc_block_id,
            validator_set.id(),
        );
        entries.push(
            TimeoutEntryV0::new(signer_id, high_qc, entry.signature).map_err(|error| {
                map_validation_error(error, entry.offset, SemanticObject::Certificate)
            })?,
        );
    }
    let mut referenced_qcs = Vec::with_capacity(raw.referenced_qcs.len());
    for referenced in raw.referenced_qcs {
        let reference = admit_raw_qc_reference(referenced, validator_set, reference_admission)
            .map_err(|error| {
                DecodeError::new(DecodeErrorCode::InvalidReferencedQc, error.byte_offset())
            })?;
        referenced_qcs.push(reference);
    }
    validate_timeout_relations(
        raw.timed_out_view,
        &entries,
        &referenced_qcs,
        raw.selected_high_qc_digest,
        raw.object_offset,
    )?;
    TimeoutCertificateV0::new(
        raw.timed_out_view,
        entries,
        referenced_qcs,
        raw.selected_high_qc_digest,
        validator_set,
    )
    .map_err(|error| map_validation_error(error, raw.object_offset, SemanticObject::Certificate))
}

fn parse_raw_qc<'a>(
    cursor: &mut Cursor<'a>,
    remaining_aggregate_shares: usize,
) -> DecodeResult<RawQc<'a>> {
    let certificate_offset = cursor.offset();
    let schema_version = cursor.u16()?;
    let genesis_hash = GenesisHash::new(cursor.fixed()?);
    let chain_id = cursor.bounded_consensus_bytes()?;
    let protocol_offset = cursor.offset();
    let protocol_version = cursor.u32()?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_id = ValidatorSetId::new(cursor.fixed()?);
    let view_offset = cursor.offset();
    let view = View::new(cursor.u64()?);
    let height = Height::new(cursor.u64()?);
    let block_id = BlockId::new(cursor.fixed()?);
    let signature_count_offset = cursor.offset();
    let signature_count = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS)?;
    if signature_count > remaining_aggregate_shares {
        return Err(DecodeError::new(
            DecodeErrorCode::AggregateLimitExceeded,
            signature_count_offset,
        ));
    }

    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        signatures.push(RawSignatureShare {
            offset: cursor.offset(),
            author: cursor.bounded_validator_id_bytes()?,
            signature: Signature64::from_array(cursor.fixed()?),
        });
    }
    Ok(RawQc {
        object_offset: certificate_offset,
        schema_version,
        genesis_hash,
        chain_id,
        protocol_offset,
        protocol_version,
        epoch,
        validator_set_id,
        view_offset,
        view,
        height,
        block_id,
        signature_count_offset,
        signatures,
    })
}

fn admit_raw_ordinary_qc(
    raw: RawQc<'_>,
    validator_set: &ValidatorSet,
) -> DecodeResult<QuorumCertificate> {
    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    require_trusted_set_context(
        raw.genesis_hash,
        chain_id,
        protocol_version,
        raw.epoch,
        raw.validator_set_id,
        validator_set,
        raw.object_offset,
    )?;
    if raw.view == View::new(0) {
        return Err(DecodeError::new(
            DecodeErrorCode::UnauthorizedSyntheticQc,
            raw.view_offset,
        ));
    }
    if raw.signatures.is_empty() {
        return Err(DecodeError::new(
            DecodeErrorCode::UnauthorizedSyntheticQc,
            raw.signature_count_offset,
        ));
    }
    let mut votes = Vec::with_capacity(raw.signatures.len());
    for share in raw.signatures {
        let author = admit_validator_id(share.author)?;
        votes.push(
            Vote::new(
                chain_id,
                protocol_version,
                raw.epoch,
                raw.view,
                raw.height,
                raw.block_id,
                raw.validator_set_id,
                author,
                share.signature,
                validator_set,
            )
            .map_err(|error| {
                map_validation_error(error, share.offset, SemanticObject::Certificate)
            })?,
        );
    }
    QuorumCertificate::new(
        chain_id,
        protocol_version,
        raw.epoch,
        raw.view,
        raw.height,
        raw.block_id,
        raw.validator_set_id,
        votes,
        validator_set,
    )
    .map_err(|error| map_validation_error(error, raw.object_offset, SemanticObject::Certificate))
}

fn trusted_genesis_qc_v0(
    epoch_zero_validator_set: &ValidatorSet,
    byte_offset: usize,
) -> DecodeResult<GenesisQcV0> {
    GenesisQcV0::new(
        epoch_zero_validator_set.genesis_hash(),
        epoch_zero_validator_set.chain_id(),
        epoch_zero_validator_set,
    )
    .map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, byte_offset))
}

fn admit_raw_qc_reference_with_trusted_genesis(
    raw: RawQc<'_>,
    epoch_zero_validator_set: &ValidatorSet,
    trusted_genesis: &GenesisQcV0,
) -> DecodeResult<QcReferenceV0> {
    if !raw.signatures.is_empty() {
        return admit_raw_ordinary_qc(raw, epoch_zero_validator_set).map(QcReferenceV0::ordinary);
    }

    require_schema_v0(raw.schema_version, raw.object_offset)?;
    let chain_id = admit_consensus_string(raw.chain_id)?;
    let protocol_version = admit_protocol_v0(raw.protocol_version, raw.protocol_offset)?;
    if raw.genesis_hash != trusted_genesis.genesis_hash()
        || chain_id != trusted_genesis.chain_id()
        || protocol_version != trusted_genesis.protocol_version()
        || raw.epoch != trusted_genesis.epoch()
        || raw.validator_set_id != trusted_genesis.validator_set_hash()
        || raw.view != trusted_genesis.view()
        || raw.height != trusted_genesis.height()
        || raw.block_id != trusted_genesis.block_id()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::UnauthorizedSyntheticQc,
            raw.object_offset,
        ));
    }
    trusted_genesis
        .matches_trusted_set(epoch_zero_validator_set)
        .map_err(|_| {
            DecodeError::new(DecodeErrorCode::UnauthorizedSyntheticQc, raw.object_offset)
        })?;
    Ok(QcReferenceV0::genesis_anchor(trusted_genesis.clone()))
}

fn require_exact_canonical_reencoding(
    supplied: &[u8],
    canonical: crate::Result<Vec<u8>>,
    byte_offset: usize,
) -> DecodeResult<()> {
    let canonical =
        canonical.map_err(|_| DecodeError::new(DecodeErrorCode::ContextMismatch, byte_offset))?;
    if canonical.as_slice() != supplied {
        return Err(DecodeError::new(
            DecodeErrorCode::ContextMismatch,
            byte_offset,
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RawBytes<'a> {
    length_offset: usize,
    bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct RawConsensusParametersV0 {
    schema_version: u16,
    protocol_version: u32,
    production_activation: u8,
    max_chain_id_bytes: u16,
    max_validator_id_bytes: u16,
    max_block_bytes: u32,
    max_consensus_message_bytes: u32,
    min_validators: u32,
    max_validators: u32,
    quorum_numerator: u32,
    quorum_denominator: u32,
    quorum_addend: u32,
    finality_certified_chain_length: u8,
    max_total_voting_power: u64,
    max_block_time_step_ms: u64,
    leader_schedule: u8,
    require_full_payload_before_vote: u8,
    base_timeout_ms: u64,
    timeout_multiplier_numerator: u32,
    timeout_multiplier_denominator: u32,
    timeout_max_ms: u64,
    epoch_length_blocks: u64,
    epoch_seal_blocks: u8,
    snapshot_lead_blocks: u64,
    joint_handoff_old_quorum: u8,
    joint_handoff_new_quorum: u8,
    upgrade_notice_epochs: u64,
    max_protocol_version_jump: u32,
    scale_ppm: u64,
    maturity_epochs: u64,
    max_certificate_age_epochs: u64,
    decay_step_ppm_per_epoch: u64,
    per_certificate_unit_cap: u128,
    per_consumer_provider_epoch_unit_cap: u128,
    per_task_provider_epoch_unit_cap: u128,
    per_provider_epoch_unit_cap: u128,
    units_per_power: u128,
    bond_atomic_units_per_power: u128,
    min_validator_power: u64,
    max_validator_power: u64,
    max_validator_share_ppm: u64,
    capped_weight_alpha_ppm: u64,
    full_weight_alpha_ppm: u64,
    rollout_phase: u8,
    minimum_shadow_epochs: u64,
    minimum_eligibility_only_epochs: u64,
    minimum_capped_weight_epochs: u64,
    automatic_promotion: u8,
    evidence_window_epochs: u64,
    unbonding_delay_epochs: u64,
    jail_duration_epochs: u64,
    trusting_period_epochs: u64,
    require_trusting_period_less_than_evidence: u8,
    require_evidence_window_le_unbonding_delay: u8,
}

#[derive(Debug)]
struct RawApplicationPayload<'a> {
    transaction_count_offset: usize,
    transactions: Vec<RawBytes<'a>>,
}

#[derive(Debug)]
struct RawExecutionEventAttribute<'a> {
    object_offset: usize,
    key: RawBytes<'a>,
    value: RawBytes<'a>,
}

#[derive(Debug)]
struct RawExecutionEvent<'a> {
    kind: RawBytes<'a>,
    attribute_count_offset: usize,
    attributes: Vec<RawExecutionEventAttribute<'a>>,
}

#[derive(Debug)]
struct RawExecutionReceiptCommitment<'a> {
    object_offset: usize,
    schema_version: u16,
    transaction_index: u32,
    payload_leaf_hash: [u8; 32],
    gas_used: u64,
    fee_charged: u128,
    event_count_offset: usize,
    events: Vec<RawExecutionEvent<'a>>,
}

#[derive(Debug)]
struct RawCommonConsensusContext<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_offset: usize,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    validator_set_hash_offset: usize,
    validator_set_hash: ValidatorSetId,
    view: View,
    message_kind_offset: usize,
    message_kind: u8,
}

#[derive(Debug)]
enum RawCanonicalSignPreimage<'a> {
    Vote {
        context: RawCommonConsensusContext<'a>,
        height: Height,
        block_id: BlockId,
    },
    TimeoutVote {
        context: RawCommonConsensusContext<'a>,
        high_qc_digest: CertificateId,
        high_qc_epoch: Epoch,
        high_qc_view: View,
        high_qc_height: Height,
        high_qc_block_id: BlockId,
    },
}

#[derive(Debug)]
struct RawCanonicalSignIntent<'a> {
    object_offset: usize,
    schema_version: u16,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    validator_set_id_offset: usize,
    validator_set_id: ValidatorSetId,
    author: RawBytes<'a>,
    authorizing_safety_revision_offset: usize,
    authorizing_safety_revision: u64,
    preimage: RawCanonicalSignPreimage<'a>,
    signing_root_offset: usize,
    signing_root: SigningRoot,
    fingerprint_offset: usize,
    fingerprint: SignIntentFingerprintV0,
}

#[derive(Debug)]
struct RawVoteEvidenceRecord<'a> {
    object_offset: usize,
    context: RawCommonConsensusContext<'a>,
    height_offset: usize,
    height: Height,
    block_id: BlockId,
    author: RawBytes<'a>,
    signature_offset: usize,
    signature: Signature64,
}

#[derive(Debug)]
struct RawDoubleVoteEvidence<'a> {
    object_offset: usize,
    schema_version: u16,
    first: RawVoteEvidenceRecord<'a>,
    second: RawVoteEvidenceRecord<'a>,
}

#[derive(Debug)]
struct RawValidator<'a> {
    offset: usize,
    id: RawBytes<'a>,
    consensus_key: ConsensusPublicKey,
    voting_power: u64,
}

#[derive(Debug)]
struct RawValidatorSet<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    consensus_parameters_hash: ConsensusParametersHash,
    validator_count_offset: usize,
    validators: Vec<RawValidator<'a>>,
}

#[derive(Debug)]
struct RawBlockHeader<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_offset: usize,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    view: View,
    height: Height,
    block_kind: BlockKind,
    parent_id: BlockId,
    proposer_id: RawBytes<'a>,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    payload_digest: PayloadDigest,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    timestamp_ms: u64,
    next_epoch_commitment_hash: Option<NextEpochCommitmentHash>,
}

#[derive(Debug)]
struct RawOrdinaryCertifiedHeader<'a> {
    object_offset: usize,
    header: RawBlockHeader<'a>,
    justify_qc: RawQc<'a>,
    timeout_certificate: Option<RawTimeoutCertificate<'a>>,
    proposer_signature: Signature64,
    certifying_qc: RawQc<'a>,
}

#[derive(Debug)]
struct RawCheckpointFinalityProof<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_offset: usize,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    parameters_hash_offset: usize,
    consensus_parameters_hash: ConsensusParametersHash,
    finalized_block: RawOrdinaryCertifiedHeader<'a>,
    child: RawOrdinaryCertifiedHeader<'a>,
    grandchild: RawOrdinaryCertifiedHeader<'a>,
}

#[derive(Debug)]
struct RawNextEpochCommitment<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_offset: usize,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    old_epoch: Epoch,
    new_epoch_offset: usize,
    new_epoch: Epoch,
    snapshot_cutoff_height: Height,
    snapshot_state_root_offset: usize,
    snapshot_state_root: StateRoot,
    protocol_offset: usize,
    new_protocol_version: u32,
    new_validator_set_hash_offset: usize,
    new_validator_set_hash: ValidatorSetId,
    new_consensus_parameters_hash_offset: usize,
    new_consensus_parameters_hash: ConsensusParametersHash,
    rollout_phase_offset: usize,
    rollout_phase: u8,
    upgrade_plan_hash_offset: usize,
    upgrade_plan_hash: Option<UpgradePlanHash>,
    fallback_used_offset: usize,
    fallback_used: u8,
    fallback_reason_offset: usize,
    fallback_reason: u16,
    activation_height_offset: usize,
    activation_height: Height,
}

#[derive(Debug)]
struct RawHandoffDescriptor<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_offset: usize,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    old_epoch: Epoch,
    new_epoch: Epoch,
    old_protocol_version: u32,
    new_protocol_version: u32,
    old_validator_set_hash: ValidatorSetId,
    new_validator_set_hash: ValidatorSetId,
    old_consensus_parameters_hash: ConsensusParametersHash,
    new_consensus_parameters_hash: ConsensusParametersHash,
    checkpoint_height: Height,
    checkpoint_block_id: BlockId,
    checkpoint_state_root: StateRoot,
    next_epoch_commitment_digest: NextEpochCommitmentHash,
    terminal_old_height: Height,
    terminal_old_block_id: BlockId,
    terminal_old_qc_digest: CertificateId,
    terminal_old_view: View,
    activation_height: Height,
    initial_new_view: View,
}

#[derive(Debug)]
struct RawSignatureShare<'a> {
    offset: usize,
    author: RawBytes<'a>,
    signature: Signature64,
}

#[derive(Debug)]
struct RawHandoffCertificate<'a> {
    object_offset: usize,
    schema_version: u16,
    descriptor: RawHandoffDescriptor<'a>,
    old_count_offset: usize,
    old_signatures: Vec<RawSignatureShare<'a>>,
    new_count_offset: usize,
    new_signatures: Vec<RawSignatureShare<'a>>,
}

#[derive(Debug)]
struct RawQc<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    view_offset: usize,
    view: View,
    height: Height,
    block_id: BlockId,
    signature_count_offset: usize,
    signatures: Vec<RawSignatureShare<'a>>,
}

#[derive(Debug)]
struct RawTimeoutEntry<'a> {
    offset: usize,
    signer_id: RawBytes<'a>,
    qc_digest: CertificateId,
    qc_epoch: Epoch,
    qc_view: View,
    qc_height: Height,
    qc_block_id: BlockId,
    signature: Signature64,
}

#[derive(Debug)]
struct RawTimeoutCertificate<'a> {
    object_offset: usize,
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: RawBytes<'a>,
    protocol_offset: usize,
    protocol_version: u32,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    timed_out_view: View,
    entries: Vec<RawTimeoutEntry<'a>>,
    referenced_qcs: Vec<RawQc<'a>>,
    selected_high_qc_digest: CertificateId,
}

#[derive(Debug)]
struct RawEpochAnchorAuthorization<'a> {
    object_offset: usize,
    terminal_old_header: RawBlockHeader<'a>,
    terminal_old_qc: RawQc<'a>,
    handoff_certificate: RawHandoffCertificate<'a>,
}

fn require_schema_v0(actual: u16, byte_offset: usize) -> DecodeResult<()> {
    if actual != SCHEMA_VERSION_V0 {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidSchemaVersion,
            byte_offset,
        ));
    }
    Ok(())
}

fn admit_protocol_v0(actual: u32, byte_offset: usize) -> DecodeResult<ProtocolVersion> {
    if actual != ProtocolVersion::V0.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidProtocolVersion,
            byte_offset,
        ));
    }
    Ok(ProtocolVersion::V0)
}

fn admit_consensus_string(raw: RawBytes<'_>) -> DecodeResult<ChainId> {
    ChainId::from_bytes(raw.bytes)
        .map_err(|_| DecodeError::new(DecodeErrorCode::InvalidConsensusString, raw.length_offset))
}

fn admit_validator_id(raw: RawBytes<'_>) -> DecodeResult<ValidatorId> {
    ValidatorId::from_bytes(raw.bytes)
        .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, raw.length_offset))
}

fn validate_timeout_relations(
    timed_out_view: View,
    entries: &[TimeoutEntryV0],
    referenced_qcs: &[QcReferenceV0],
    selected_high_qc_digest: CertificateId,
    byte_offset: usize,
) -> DecodeResult<()> {
    if entries.is_empty() || referenced_qcs.is_empty() {
        return Err(DecodeError::new(DecodeErrorCode::EmptyTc, byte_offset));
    }

    let mut previous_reference = None;
    let mut reference_ids = BTreeSet::new();
    let mut view_coordinates = BTreeMap::new();
    let mut block_coordinates = BTreeMap::new();
    for referenced in referenced_qcs {
        let summary = referenced.qc_ref();
        if summary.view() > timed_out_view {
            return Err(DecodeError::new(
                DecodeErrorCode::FutureReferenceView,
                byte_offset,
            ));
        }
        let id = referenced.id();
        if let Some(previous) = previous_reference {
            if previous == id {
                return Err(DecodeError::new(
                    DecodeErrorCode::DuplicateReference,
                    byte_offset,
                ));
            }
            if previous > id {
                return Err(DecodeError::new(
                    DecodeErrorCode::NonCanonicalReferenceOrder,
                    byte_offset,
                ));
            }
        }
        previous_reference = Some(id);
        reference_ids.insert(id);

        let coordinate = (summary.epoch(), summary.view());
        let certified = (summary.height(), summary.block_id());
        if view_coordinates
            .insert(coordinate, certified)
            .is_some_and(|prior| prior != certified)
        {
            return Err(DecodeError::new(
                DecodeErrorCode::ConflictingSameViewQc,
                byte_offset,
            ));
        }
        let block_coordinate = (summary.epoch(), summary.view(), summary.height());
        if block_coordinates
            .insert(summary.block_id(), block_coordinate)
            .is_some_and(|prior| prior != block_coordinate)
        {
            return Err(DecodeError::new(
                DecodeErrorCode::SameBlockDifferentCoordinates,
                byte_offset,
            ));
        }
    }

    let mut previous_signer = None;
    let mut maximum: Option<QcRef> = None;
    let mut used_references = BTreeSet::new();
    for entry in entries {
        let signer = entry.signer_id();
        if let Some(previous) = previous_signer {
            if previous == signer {
                return Err(DecodeError::new(
                    DecodeErrorCode::DuplicateSigner,
                    byte_offset,
                ));
            }
            if previous > signer {
                return Err(DecodeError::new(
                    DecodeErrorCode::NonCanonicalSignerOrder,
                    byte_offset,
                ));
            }
        }
        previous_signer = Some(signer);

        if !referenced_qcs
            .iter()
            .any(|candidate| candidate.qc_ref() == entry.high_qc())
        {
            return Err(DecodeError::new(
                DecodeErrorCode::ReferenceSummaryMismatch,
                byte_offset,
            ));
        }
        used_references.insert(entry.high_qc().qc_digest());
        maximum = match maximum {
            Some(current)
                if (current.view(), current.block_id(), current.qc_digest())
                    >= (
                        entry.high_qc().view(),
                        entry.high_qc().block_id(),
                        entry.high_qc().qc_digest(),
                    ) =>
            {
                Some(current)
            }
            _ => Some(entry.high_qc()),
        };
    }

    if used_references != reference_ids {
        return Err(DecodeError::new(
            DecodeErrorCode::UnreferencedQc,
            byte_offset,
        ));
    }
    if maximum.is_none_or(|summary: QcRef| summary.qc_digest() != selected_high_qc_digest) {
        return Err(DecodeError::new(
            DecodeErrorCode::SelectedNotMaximum,
            byte_offset,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn require_trusted_set_context(
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    validator_set: &ValidatorSet,
    offset: usize,
) -> DecodeResult<()> {
    validator_set
        .validate_shape()
        .map_err(|error| map_validation_error(error, offset, SemanticObject::ValidatorSet))?;
    if genesis_hash != validator_set.genesis_hash()
        || chain_id != validator_set.chain_id()
        || protocol_version != validator_set.protocol_version()
        || epoch != validator_set.epoch()
        || validator_set_id != validator_set.id()
    {
        return Err(DecodeError::new(DecodeErrorCode::ContextMismatch, offset));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SemanticObject {
    ValidatorSet,
    Certificate,
    NextEpochCommitment,
    SignIntent,
    HandoffSignIntent,
}

fn map_validation_error(
    error: ValidationError,
    byte_offset: usize,
    object: SemanticObject,
) -> DecodeError {
    let code = match error {
        ValidationError::InvalidSchemaVersion { .. } => DecodeErrorCode::InvalidSchemaVersion,
        ValidationError::InvalidProtocolVersion => DecodeErrorCode::InvalidProtocolVersion,
        ValidationError::InvalidConsensusString => DecodeErrorCode::InvalidConsensusString,
        ValidationError::EmptyValidatorId | ValidationError::ValidatorIdTooLong { .. } => {
            DecodeErrorCode::LengthLimitExceeded
        }
        ValidationError::ZeroGenesisHash => DecodeErrorCode::ZeroGenesisHash,
        ValidationError::ZeroConsensusPublicKey => DecodeErrorCode::ZeroConsensusPublicKey,
        ValidationError::ZeroVotingPower => DecodeErrorCode::ZeroVotingPower,
        ValidationError::EmptyValidatorSet => DecodeErrorCode::EmptyValidatorSet,
        ValidationError::TooManyValidators { .. } => DecodeErrorCode::CountLimitExceeded,
        ValidationError::DuplicateValidatorId(_) => DecodeErrorCode::DuplicateValidatorId,
        ValidationError::DuplicateConsensusPublicKey => DecodeErrorCode::DuplicatePublicKey,
        ValidationError::NonCanonicalValidatorOrder => DecodeErrorCode::NonCanonicalValidatorOrder,
        ValidationError::ValidatorSetIdMismatch => DecodeErrorCode::ContextMismatch,
        ValidationError::GenesisHashMismatch
        | ValidationError::ChainIdMismatch
        | ValidationError::ProtocolVersionMismatch
        | ValidationError::EpochMismatch
        | ValidationError::ValidatorSetMismatch
        | ValidationError::CertificateMismatch => DecodeErrorCode::ContextMismatch,
        ValidationError::UnknownValidator(_) => DecodeErrorCode::UnknownSigner,
        ValidationError::DuplicateSigner(_) => DecodeErrorCode::DuplicateSigner,
        ValidationError::NonCanonicalSignerOrder => DecodeErrorCode::NonCanonicalSignerOrder,
        ValidationError::NonCanonicalQcOrder => DecodeErrorCode::NonCanonicalReferenceOrder,
        ValidationError::ConflictingSameViewQc => DecodeErrorCode::ConflictingSameViewQc,
        ValidationError::InsufficientQuorum { .. } => DecodeErrorCode::InsufficientQuorum,
        ValidationError::InvalidCertificate(_) => DecodeErrorCode::InvalidReferencedQc,
        ValidationError::InvalidSignIntent(_)
            if matches!(object, SemanticObject::HandoffSignIntent) =>
        {
            DecodeErrorCode::InvalidHandoffSignIntent
        }
        ValidationError::InvalidSignIntent(_) => DecodeErrorCode::InvalidSignIntent,
        _ => match object {
            SemanticObject::ValidatorSet => DecodeErrorCode::ContextMismatch,
            SemanticObject::Certificate => DecodeErrorCode::InvalidReferencedQc,
            SemanticObject::NextEpochCommitment => DecodeErrorCode::InvalidNextEpochCommitment,
            SemanticObject::SignIntent => DecodeErrorCode::InvalidSignIntent,
            SemanticObject::HandoffSignIntent => DecodeErrorCode::InvalidHandoffSignIntent,
        },
    };
    DecodeError::new(code, byte_offset)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn finish(&self) -> DecodeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DecodeError::new(
                DecodeErrorCode::TrailingBytes,
                self.offset,
            ))
        }
    }

    fn take(&mut self, length: usize) -> DecodeResult<&'a [u8]> {
        let start = self.offset;
        let end = start
            .checked_add(length)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, self.offset))?;
        let value = self
            .bytes
            .get(start..end)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::UnexpectedEof, self.bytes.len()))?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> DecodeResult<[u8; N]> {
        let mut value = [0u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn u8(&mut self) -> DecodeResult<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> DecodeResult<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn u128(&mut self) -> DecodeResult<u128> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn bounded_body_bytes(&mut self, maximum: usize) -> DecodeResult<RawBytes<'a>> {
        let length_offset = self.offset;
        let length = usize::try_from(self.u32()?)
            .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, length_offset))?;
        if length > maximum {
            return Err(DecodeError::new(
                DecodeErrorCode::LengthLimitExceeded,
                length_offset,
            ));
        }
        let bytes = self.take(length)?;
        Ok(RawBytes {
            length_offset,
            bytes,
        })
    }

    fn bounded_consensus_bytes(&mut self) -> DecodeResult<RawBytes<'a>> {
        let raw = self.bounded_consensus_bytes_raw()?;
        ChainId::from_bytes(raw.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::InvalidConsensusString, raw.length_offset)
        })?;
        Ok(raw)
    }

    fn bounded_consensus_bytes_raw(&mut self) -> DecodeResult<RawBytes<'a>> {
        let length_offset = self.offset;
        let length = usize::from(self.u16()?);
        if length > MAX_CONSENSUS_STRING_BYTES {
            return Err(DecodeError::new(
                DecodeErrorCode::LengthLimitExceeded,
                length_offset,
            ));
        }
        let bytes = self.take(length)?;
        Ok(RawBytes {
            length_offset,
            bytes,
        })
    }

    fn bounded_validator_id_bytes(&mut self) -> DecodeResult<RawBytes<'a>> {
        let raw = self.bounded_validator_id_bytes_raw()?;
        ValidatorId::from_bytes(raw.bytes).map_err(|_| {
            DecodeError::new(DecodeErrorCode::LengthLimitExceeded, raw.length_offset)
        })?;
        Ok(raw)
    }

    fn bounded_validator_id_bytes_raw(&mut self) -> DecodeResult<RawBytes<'a>> {
        let length_offset = self.offset;
        let length = usize::try_from(self.u32()?)
            .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, length_offset))?;
        if length > MAX_VALIDATOR_ID_BYTES {
            return Err(DecodeError::new(
                DecodeErrorCode::LengthLimitExceeded,
                length_offset,
            ));
        }
        let bytes = self.take(length)?;
        Ok(RawBytes {
            length_offset,
            bytes,
        })
    }

    fn list_len(&mut self, maximum: usize) -> DecodeResult<usize> {
        let length_offset = self.offset;
        let length = usize::try_from(self.u32()?)
            .map_err(|_| DecodeError::new(DecodeErrorCode::LengthLimitExceeded, length_offset))?;
        if length > maximum {
            return Err(DecodeError::new(
                DecodeErrorCode::CountLimitExceeded,
                length_offset,
            ));
        }
        Ok(length)
    }

    fn list_len_with_minimum(
        &mut self,
        maximum: usize,
        minimum_item_bytes: usize,
    ) -> DecodeResult<usize> {
        let length = self.list_len(maximum)?;
        let minimum_encoded_bytes = length.checked_mul(minimum_item_bytes).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::CountLimitExceeded, self.offset - 4)
        })?;
        if minimum_encoded_bytes > self.remaining() {
            return Err(DecodeError::new(
                DecodeErrorCode::UnexpectedEof,
                self.bytes.len(),
            ));
        }
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::SIGNATURE_BYTES;

    #[test]
    fn decoder_error_code_registry_is_unique_and_stable() {
        assert_eq!(DecodeErrorCode::ALL.len(), 52);
        assert_eq!(DecodeErrorCode::ALL[0].as_str(), "unexpected_eof");
        assert_eq!(
            DecodeErrorCode::ALL[DecodeErrorCode::ALL.len() - 1].as_str(),
            "invalid_handoff_sign_intent"
        );
        assert_eq!(DecodeErrorCode::ALL[8].as_str(), "invalid_block_kind");
        assert_eq!(DecodeErrorCode::ALL[29].as_str(), "invalid_referenced_qc");
        assert_eq!(DecodeErrorCode::ALL[30].as_str(), "empty_tc");
        assert_eq!(
            DecodeErrorCode::ALL[47].as_str(),
            "invalid_checkpoint_two_seal"
        );
        for (index, code) in DecodeErrorCode::ALL.iter().enumerate() {
            assert!(
                DecodeErrorCode::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != code.as_str()),
                "duplicate decoder error code {}",
                code.as_str()
            );
        }
    }

    struct AcceptSignatures;

    impl SignatureVerifier for AcceptSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &crate::SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            true
        }
    }

    struct RejectSignatures;

    impl SignatureVerifier for RejectSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &crate::SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            false
        }
    }

    fn validator(id: u8, power: u64) -> Validator {
        Validator::new(
            ValidatorId::from_bytes(&[id]).unwrap(),
            ConsensusPublicKey::new([id; 32]),
            VotingPower::new(power).unwrap(),
        )
        .unwrap()
    }

    fn sample_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([9; 32]),
            ChainId::new("trnm-decoder").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(7),
            ConsensusParametersHash::new([8; 32]),
            vec![
                validator(1, 4),
                validator(2, 3),
                validator(3, 2),
                validator(4, 1),
            ],
        )
        .unwrap()
    }

    fn assert_parameter_error(
        bytes: &[u8],
        expected_code: DecodeErrorCode,
        expected_offset: usize,
    ) {
        let error = decode_consensus_parameters_v0_exact(bytes).unwrap_err();
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.byte_offset(), expected_offset);
    }

    #[test]
    fn consensus_parameters_decoder_round_trips_and_exhausts_the_exact_root() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let bytes = parameters.canonical_bytes();
        assert_eq!(bytes.len(), CONSENSUS_PARAMETERS_V0_BYTES);
        assert_eq!(
            decode_consensus_parameters_v0_exact(&bytes).unwrap(),
            parameters
        );

        for prefix_length in 0..bytes.len() {
            assert_parameter_error(
                &bytes[..prefix_length],
                DecodeErrorCode::UnexpectedEof,
                prefix_length,
            );
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_parameter_error(
            &trailing,
            DecodeErrorCode::TrailingBytes,
            CONSENSUS_PARAMETERS_V0_BYTES,
        );

        let mut semantic_and_trailing = bytes;
        semantic_and_trailing[PARAMETER_REQUIRE_FULL_PAYLOAD_OFFSET] = 0;
        semantic_and_trailing.push(0);
        assert_parameter_error(
            &semantic_and_trailing,
            DecodeErrorCode::TrailingBytes,
            CONSENSUS_PARAMETERS_V0_BYTES,
        );
    }

    #[test]
    fn consensus_parameters_decoder_freezes_discriminants_and_boolean_offsets() {
        let bytes = ConsensusParametersV0::reference_shadow_v0().canonical_bytes();

        let mut schema = bytes.clone();
        schema[PARAMETER_SCHEMA_OFFSET..PARAMETER_SCHEMA_OFFSET + 2]
            .copy_from_slice(&1u16.to_be_bytes());
        assert_parameter_error(
            &schema,
            DecodeErrorCode::InvalidSchemaVersion,
            PARAMETER_SCHEMA_OFFSET,
        );

        let mut protocol = bytes.clone();
        protocol[PARAMETER_PROTOCOL_OFFSET..PARAMETER_PROTOCOL_OFFSET + 4]
            .copy_from_slice(&1u32.to_be_bytes());
        assert_parameter_error(
            &protocol,
            DecodeErrorCode::InvalidProtocolVersion,
            PARAMETER_PROTOCOL_OFFSET,
        );

        for offset in [
            PARAMETER_PRODUCTION_ACTIVATION_OFFSET,
            PARAMETER_REQUIRE_FULL_PAYLOAD_OFFSET,
            PARAMETER_JOINT_OLD_QUORUM_OFFSET,
            PARAMETER_JOINT_NEW_QUORUM_OFFSET,
            PARAMETER_AUTOMATIC_PROMOTION_OFFSET,
            PARAMETER_REQUIRE_TRUSTING_RELATION_OFFSET,
            PARAMETER_REQUIRE_UNBONDING_RELATION_OFFSET,
        ] {
            let mut invalid = bytes.clone();
            invalid[offset] = 2;
            assert_parameter_error(&invalid, DecodeErrorCode::InvalidBoolean, offset);
        }

        let mut leader = bytes.clone();
        leader[PARAMETER_LEADER_SCHEDULE_OFFSET] = 1;
        assert_parameter_error(
            &leader,
            DecodeErrorCode::InvalidLeaderSchedule,
            PARAMETER_LEADER_SCHEDULE_OFFSET,
        );

        let mut rollout = bytes;
        rollout[PARAMETER_ROLLOUT_PHASE_OFFSET] = 4;
        assert_parameter_error(
            &rollout,
            DecodeErrorCode::InvalidRolloutPhase,
            PARAMETER_ROLLOUT_PHASE_OFFSET,
        );
    }

    #[test]
    fn consensus_parameters_decoder_rejects_hard_caps_and_safety_invariants() {
        let bytes = ConsensusParametersV0::reference_shadow_v0().canonical_bytes();

        let mut max_validators = bytes.clone();
        max_validators[PARAMETER_MAX_VALIDATORS_OFFSET..PARAMETER_MAX_VALIDATORS_OFFSET + 4]
            .copy_from_slice(&101u32.to_be_bytes());
        assert_parameter_error(
            &max_validators,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_MAX_VALIDATORS_OFFSET,
        );

        let mut snapshot_lead = bytes.clone();
        snapshot_lead[PARAMETER_SNAPSHOT_LEAD_OFFSET..PARAMETER_SNAPSHOT_LEAD_OFFSET + 8]
            .copy_from_slice(&0u64.to_be_bytes());
        assert_parameter_error(
            &snapshot_lead,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_SNAPSHOT_LEAD_OFFSET,
        );

        let mut short_snapshot_lead = bytes.clone();
        short_snapshot_lead[PARAMETER_SNAPSHOT_LEAD_OFFSET..PARAMETER_SNAPSHOT_LEAD_OFFSET + 8]
            .copy_from_slice(&2u64.to_be_bytes());
        assert_parameter_error(
            &short_snapshot_lead,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_SNAPSHOT_LEAD_OFFSET,
        );

        let mut boundary_snapshot_lead = bytes.clone();
        boundary_snapshot_lead[PARAMETER_SNAPSHOT_LEAD_OFFSET..PARAMETER_SNAPSHOT_LEAD_OFFSET + 8]
            .copy_from_slice(&3u64.to_be_bytes());
        assert_eq!(
            decode_consensus_parameters_v0_exact(&boundary_snapshot_lead)
                .expect("snapshot lead equal to the finality chain is valid")
                .snapshot_lead_blocks(),
            3,
        );

        let mut seal_count = bytes.clone();
        seal_count[PARAMETER_EPOCH_SEAL_BLOCKS_OFFSET] = 1;
        assert_parameter_error(
            &seal_count,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_EPOCH_SEAL_BLOCKS_OFFSET,
        );

        let mut finality_length = bytes.clone();
        finality_length[PARAMETER_FINALITY_CHAIN_LENGTH_OFFSET] = 2;
        assert_parameter_error(
            &finality_length,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_FINALITY_CHAIN_LENGTH_OFFSET,
        );

        let mut quorum = bytes.clone();
        quorum[PARAMETER_QUORUM_DENOMINATOR_OFFSET..PARAMETER_QUORUM_DENOMINATOR_OFFSET + 4]
            .copy_from_slice(&4u32.to_be_bytes());
        assert_parameter_error(
            &quorum,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_QUORUM_NUMERATOR_OFFSET,
        );

        let mut share_cap = bytes.clone();
        share_cap[PARAMETER_MAX_VALIDATOR_SHARE_OFFSET..PARAMETER_MAX_VALIDATOR_SHARE_OFFSET + 8]
            .copy_from_slice(&333_334u64.to_be_bytes());
        assert_parameter_error(
            &share_cap,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_MAX_VALIDATOR_SHARE_OFFSET,
        );

        let mut automatic = bytes;
        automatic[PARAMETER_AUTOMATIC_PROMOTION_OFFSET] = 1;
        assert_parameter_error(
            &automatic,
            DecodeErrorCode::InvalidConsensusParameters,
            PARAMETER_AUTOMATIC_PROMOTION_OFFSET,
        );
    }

    fn sample_next_epoch_commitment(
        rollout_phase: RolloutPhase,
        upgrade_plan_hash: Option<UpgradePlanHash>,
        fallback_reason: EpochFallbackReasonV0,
    ) -> NextEpochCommitmentV0 {
        NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            schema_version: SCHEMA_VERSION_V0,
            genesis_hash: GenesisHash::new([31; 32]),
            chain_id: ChainId::new("trnm-next-epoch-decoder").unwrap(),
            old_epoch: Epoch::new(7),
            new_epoch: Epoch::new(8),
            snapshot_cutoff_height: Height::new(79_997),
            snapshot_state_root: StateRoot::new([32; 32]),
            new_protocol_version: ProtocolVersion::V0,
            new_validator_set_hash: ValidatorSetId::new([33; 32]),
            new_consensus_parameters_hash: ConsensusParametersHash::new([34; 32]),
            rollout_phase,
            upgrade_plan_hash,
            fallback_used: fallback_reason != EpochFallbackReasonV0::None,
            fallback_reason,
            activation_height: Height::new(80_001),
        })
        .unwrap()
    }

    fn qc(
        set: &ValidatorSet,
        view: u64,
        height: u64,
        block: u8,
        signer_indexes: &[usize],
    ) -> QuorumCertificate {
        qc_for_block(set, view, height, BlockId::new([block; 32]), signer_indexes)
    }

    fn qc_for_block(
        set: &ValidatorSet,
        view: u64,
        height: u64,
        block_id: BlockId,
        signer_indexes: &[usize],
    ) -> QuorumCertificate {
        let votes = signer_indexes
            .iter()
            .map(|index| {
                let signer = &set.validators()[*index];
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    View::new(view),
                    Height::new(height),
                    block_id,
                    set.id(),
                    signer.id(),
                    Signature64::from_array([signer.id().as_bytes()[0]; SIGNATURE_BYTES]),
                    set,
                )
                .unwrap()
            })
            .collect();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block_id,
            set.id(),
            votes,
            set,
        )
        .unwrap()
    }

    fn sample_tc(set: &ValidatorSet) -> TimeoutCertificateV0 {
        let low = qc(set, 3, 11, 3, &[0, 1]);
        let high = qc(set, 5, 13, 5, &[0, 1]);
        let entries = vec![
            TimeoutEntryV0::new(
                set.validators()[0].id(),
                QcRef::from(&low),
                Signature64::from_array([11; SIGNATURE_BYTES]),
            )
            .unwrap(),
            TimeoutEntryV0::new(
                set.validators()[1].id(),
                QcRef::from(&high),
                Signature64::from_array([12; SIGNATURE_BYTES]),
            )
            .unwrap(),
        ];
        let selected = high.id();
        let mut references = vec![QcReferenceV0::ordinary(low), QcReferenceV0::ordinary(high)];
        references.sort_by_key(QcReferenceV0::id);
        TimeoutCertificateV0::new(View::new(9), entries, references, selected, set).unwrap()
    }

    fn trusted_genesis_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([71; 32]),
            ChainId::new("trnm-trusted-genesis-decoder").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![
                validator(1, 1),
                validator(2, 1),
                validator(3, 1),
                validator(4, 1),
            ],
        )
        .unwrap()
    }

    fn trusted_genesis_reference(set: &ValidatorSet) -> QcReferenceV0 {
        QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
        )
    }

    fn qc_reference_bytes(reference: &QcReferenceV0) -> Vec<u8> {
        try_canonical_bytes(|encoder| reference.encode_cev0(encoder)).unwrap()
    }

    fn trusted_genesis_timeout(set: &ValidatorSet) -> TimeoutCertificateV0 {
        let reference = trusted_genesis_reference(set);
        let high_qc = reference.qc_ref();
        let entries = set.validators()[..3]
            .iter()
            .map(|validator| {
                TimeoutEntryV0::new(
                    validator.id(),
                    high_qc,
                    Signature64::from_array([validator.id().as_bytes()[0]; SIGNATURE_BYTES]),
                )
                .unwrap()
            })
            .collect();
        TimeoutCertificateV0::new(
            View::new(2),
            entries,
            vec![reference.clone()],
            reference.id(),
            set,
        )
        .unwrap()
    }

    fn trusted_genesis_header(
        set: &ValidatorSet,
        view: u64,
        height: u64,
        parent_id: BlockId,
        timestamp_ms: u64,
    ) -> BlockHeader {
        let proposer_index = usize::try_from((view - 1) % set.validators().len() as u64).unwrap();
        let root_seed = u8::try_from(height).unwrap();
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            BlockKind::Regular,
            parent_id,
            set.validators()[proposer_index].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([root_seed; 32]),
            StateRoot::new([root_seed.wrapping_add(1); 32]),
            ReceiptsRoot::new([root_seed.wrapping_add(2); 32]),
            EvidenceRoot::new([root_seed.wrapping_add(3); 32]),
            timestamp_ms,
            None,
        )
        .unwrap()
    }

    fn trusted_genesis_certified(
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        header: BlockHeader,
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        authenticated_parent_timestamp_ms: u64,
    ) -> CertifiedHeaderV0 {
        let certifying_qc = qc_for_block(
            set,
            header.view().get(),
            header.height().get(),
            header.id(),
            &[0, 1, 2],
        );
        CertifiedHeaderV0::new(
            header,
            justify_qc,
            timeout_certificate,
            None,
            Signature64::from_array([91; SIGNATURE_BYTES]),
            certifying_qc,
            set,
            None,
            parameters,
            authenticated_parent_timestamp_ms,
        )
        .unwrap()
    }

    fn trusted_genesis_finality_fixture(
    ) -> (ValidatorSet, ConsensusParametersV0, u64, FinalityProofV0) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = trusted_genesis_set(&parameters);
        let authenticated_genesis_timestamp_ms = 100;
        let first_header = trusted_genesis_header(
            &set,
            1,
            1,
            BlockId::new(*set.genesis_hash().as_bytes()),
            101,
        );
        let first = trusted_genesis_certified(
            &set,
            &parameters,
            first_header,
            trusted_genesis_reference(&set),
            None,
            authenticated_genesis_timestamp_ms,
        );
        let second_header = trusted_genesis_header(&set, 2, 2, first.header().id(), 102);
        let second = trusted_genesis_certified(
            &set,
            &parameters,
            second_header,
            QcReferenceV0::ordinary(first.certifying_qc().clone()),
            None,
            first.header().timestamp_ms(),
        );
        let third_header = trusted_genesis_header(&set, 3, 3, second.header().id(), 103);
        let third = trusted_genesis_certified(
            &set,
            &parameters,
            third_header,
            QcReferenceV0::ordinary(second.certifying_qc().clone()),
            None,
            second.header().timestamp_ms(),
        );
        let proof = FinalityProofV0::new(
            first,
            second,
            third,
            &set,
            None,
            &parameters,
            authenticated_genesis_timestamp_ms,
        )
        .unwrap();
        (set, parameters, authenticated_genesis_timestamp_ms, proof)
    }

    struct SampleHandoffKernel {
        old_set: ValidatorSet,
        new_set: ValidatorSet,
        terminal_header: BlockHeader,
        descriptor: HandoffDescriptorV0,
        certificate: HandoffCertificateV0,
        authorization: EpochAnchorAuthorizationV0,
    }

    fn handoff_shares(set: &ValidatorSet, signer_indexes: &[usize]) -> Vec<SignatureShareV0> {
        signer_indexes
            .iter()
            .map(|index| {
                let validator_id = set.validators()[*index].id();
                SignatureShareV0::new(
                    validator_id,
                    Signature64::from_array([validator_id.as_bytes()[0]; crate::SIGNATURE_BYTES]),
                )
                .unwrap()
            })
            .collect()
    }

    fn sample_handoff_kernel() -> SampleHandoffKernel {
        let old_set = sample_set();
        let new_parameters = crate::ConsensusParametersV0::reference_shadow_v0();
        let new_set = ValidatorSet::new(
            old_set.genesis_hash(),
            old_set.chain_id(),
            ProtocolVersion::V0,
            old_set.epoch().checked_next().unwrap(),
            new_parameters.hash(),
            vec![
                validator(11, 4),
                validator(12, 3),
                validator(13, 2),
                validator(14, 1),
            ],
        )
        .unwrap();
        let next_epoch_commitment = NextEpochCommitmentHash::new([16; 32]);
        let checkpoint_state_root = StateRoot::new([17; 32]);
        let terminal_header = BlockHeader::new(
            old_set.genesis_hash(),
            old_set.chain_id(),
            old_set.protocol_version(),
            old_set.epoch(),
            View::new(12),
            Height::new(10),
            BlockKind::EpochSeal2,
            BlockId::new([18; 32]),
            old_set.validators()[0].id(),
            old_set.id(),
            old_set.consensus_parameters_hash(),
            PayloadDigest::new([19; 32]),
            checkpoint_state_root,
            ReceiptsRoot::new([20; 32]),
            EvidenceRoot::new([21; 32]),
            10_000,
            Some(next_epoch_commitment),
        )
        .unwrap();
        let terminal_qc = qc_for_block(&old_set, 12, 10, terminal_header.id(), &[0, 1]);
        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash: old_set.genesis_hash(),
            chain_id: old_set.chain_id(),
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: old_set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: old_set.consensus_parameters_hash(),
            new_consensus_parameters_hash: new_set.consensus_parameters_hash(),
            checkpoint_height: Height::new(8),
            checkpoint_block_id: BlockId::new([22; 32]),
            checkpoint_state_root,
            next_epoch_commitment_digest: next_epoch_commitment,
            terminal_old_height: terminal_header.height(),
            terminal_old_block_id: terminal_header.id(),
            terminal_old_qc_digest: terminal_qc.id(),
            terminal_old_view: terminal_header.view(),
            activation_height: Height::new(11),
            initial_new_view: View::new(1),
        })
        .unwrap();
        let certificate = HandoffCertificateV0::new(
            descriptor.clone(),
            handoff_shares(&old_set, &[0, 1]),
            handoff_shares(&new_set, &[0, 1]),
            &old_set,
            &new_set,
        )
        .unwrap();
        let authorization = EpochAnchorAuthorizationV0::new(
            terminal_header.clone(),
            terminal_qc.clone(),
            certificate.clone(),
            &old_set,
            &new_set,
        )
        .unwrap();
        SampleHandoffKernel {
            old_set,
            new_set,
            terminal_header,
            descriptor,
            certificate,
            authorization,
        }
    }

    fn validator_count_offset(bytes: &[u8]) -> usize {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        cursor.u32().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.offset()
    }

    fn qc_signature_count_offset(bytes: &[u8]) -> usize {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        cursor.u32().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u64().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.offset()
    }

    fn qc_view_offset(bytes: &[u8]) -> usize {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        cursor.u32().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.offset()
    }

    fn tc_offsets(bytes: &[u8]) -> (usize, usize, usize) {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        cursor.u32().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u64().unwrap();
        let entries_offset = cursor.offset();
        let entries = cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS).unwrap();
        for _ in 0..entries {
            cursor.bounded_validator_id_bytes().unwrap();
            let _: [u8; 32] = cursor.fixed().unwrap();
            cursor.u64().unwrap();
            cursor.u64().unwrap();
            cursor.u64().unwrap();
            let _: [u8; 32] = cursor.fixed().unwrap();
            let _: [u8; SIGNATURE_BYTES] = cursor.fixed().unwrap();
        }
        let references_offset = cursor.offset();
        cursor.list_len(MAX_CEV0_CERTIFICATE_ITEMS).unwrap();
        (entries_offset, references_offset, cursor.offset())
    }

    fn block_header_offsets(bytes: &[u8]) -> (usize, usize, usize, usize, usize) {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        cursor.u32().unwrap();
        cursor.u64().unwrap();
        let view_offset = cursor.offset();
        cursor.u64().unwrap();
        cursor.u64().unwrap();
        let kind_offset = cursor.offset();
        cursor.u8().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let proposer_length_offset = cursor.offset();
        cursor.bounded_validator_id_bytes().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let state_root_offset = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u64().unwrap();
        let optional_tag_offset = cursor.offset();
        (
            view_offset,
            kind_offset,
            proposer_length_offset,
            state_root_offset,
            optional_tag_offset,
        )
    }

    fn descriptor_offsets(bytes: &[u8]) -> (usize, usize, usize, usize, usize) {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        let old_epoch_offset = cursor.offset();
        cursor.u64().unwrap();
        let new_epoch_offset = cursor.offset();
        cursor.u64().unwrap();
        cursor.u32().unwrap();
        cursor.u32().unwrap();
        let old_set_offset = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u64().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u64().unwrap();
        let terminal_block_offset = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let terminal_qc_digest_offset = cursor.offset();
        (
            old_epoch_offset,
            new_epoch_offset,
            old_set_offset,
            terminal_block_offset,
            terminal_qc_digest_offset,
        )
    }

    fn parsed_handoff_offsets(bytes: &[u8]) -> (usize, usize, usize, usize, usize) {
        let mut cursor = Cursor::new(bytes);
        let raw = parse_raw_handoff_certificate(&mut cursor).unwrap();
        cursor.finish().unwrap();
        (
            raw.old_count_offset,
            raw.old_signatures[0].offset,
            raw.old_signatures[1].offset,
            raw.new_signatures[0].offset,
            raw.new_signatures[1].offset,
        )
    }

    #[derive(Debug, Clone, Copy)]
    struct NextCommitmentOffsets {
        old_epoch: usize,
        new_epoch: usize,
        snapshot_state_root: usize,
        new_validator_set_hash: usize,
        new_consensus_parameters_hash: usize,
        rollout_phase: usize,
        optional_tag: usize,
        fallback_used: usize,
        fallback_reason: usize,
        activation_height: usize,
    }

    fn next_commitment_offsets(bytes: &[u8]) -> NextCommitmentOffsets {
        let mut cursor = Cursor::new(bytes);
        cursor.u16().unwrap();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.bounded_consensus_bytes().unwrap();
        let old_epoch = cursor.offset();
        cursor.u64().unwrap();
        let new_epoch = cursor.offset();
        cursor.u64().unwrap();
        cursor.u64().unwrap();
        let snapshot_state_root = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        cursor.u32().unwrap();
        let new_validator_set_hash = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let new_consensus_parameters_hash = cursor.offset();
        let _: [u8; 32] = cursor.fixed().unwrap();
        let rollout_phase = cursor.offset();
        cursor.u8().unwrap();
        let optional_tag = cursor.offset();
        match cursor.u8().unwrap() {
            0 => {}
            1 => {
                let _: [u8; 32] = cursor.fixed().unwrap();
            }
            _ => unreachable!("sample commitment uses a canonical optional tag"),
        }
        let fallback_used = cursor.offset();
        cursor.u8().unwrap();
        let fallback_reason = cursor.offset();
        cursor.u16().unwrap();
        let activation_height = cursor.offset();
        cursor.u64().unwrap();
        cursor.finish().unwrap();
        NextCommitmentOffsets {
            old_epoch,
            new_epoch,
            snapshot_state_root,
            new_validator_set_hash,
            new_consensus_parameters_hash,
            rollout_phase,
            optional_tag,
            fallback_used,
            fallback_reason,
            activation_height,
        }
    }

    #[test]
    fn next_epoch_commitment_decoder_round_trips_and_is_exact() {
        for upgrade_plan_hash in [None, Some(UpgradePlanHash::new([35; 32]))] {
            let commitment = sample_next_epoch_commitment(
                RolloutPhase::Shadow,
                upgrade_plan_hash,
                EpochFallbackReasonV0::None,
            );
            let bytes = commitment.try_cev0_bytes().unwrap();
            assert_eq!(
                decode_next_epoch_commitment_v0_exact(&bytes).unwrap(),
                commitment
            );
            for prefix_length in 0..bytes.len() {
                let error =
                    decode_next_epoch_commitment_v0_exact(&bytes[..prefix_length]).unwrap_err();
                assert_eq!(error.code(), DecodeErrorCode::UnexpectedEof);
                assert_eq!(error.byte_offset(), prefix_length);
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            let error = decode_next_epoch_commitment_v0_exact(&trailing).unwrap_err();
            assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
            assert_eq!(error.byte_offset(), bytes.len());
        }
    }

    #[test]
    fn next_epoch_commitment_decoder_freezes_discriminants_and_fallback_pairs() {
        for rollout_phase in [
            RolloutPhase::Shadow,
            RolloutPhase::EligibilityOnly,
            RolloutPhase::CappedWeight,
            RolloutPhase::Full,
        ] {
            let commitment =
                sample_next_epoch_commitment(rollout_phase, None, EpochFallbackReasonV0::None);
            let bytes = commitment.try_cev0_bytes().unwrap();
            assert_eq!(
                decode_next_epoch_commitment_v0_exact(&bytes).unwrap(),
                commitment
            );
        }

        for fallback_reason in [
            EpochFallbackReasonV0::MalformedSnapshotInput,
            EpochFallbackReasonV0::ArithmeticFailure,
            EpochFallbackReasonV0::TooFewEligibleValidators,
            EpochFallbackReasonV0::InvalidValidatorIdentityOrKey,
            EpochFallbackReasonV0::ValidatorWeightOutOfBounds,
            EpochFallbackReasonV0::InvalidTotalVotingPower,
            EpochFallbackReasonV0::ConcentrationConstraintViolated,
            EpochFallbackReasonV0::InvalidCommittedParameters,
            EpochFallbackReasonV0::InvalidUpgradeOrActivation,
        ] {
            let commitment =
                sample_next_epoch_commitment(RolloutPhase::Full, None, fallback_reason);
            let bytes = commitment.try_cev0_bytes().unwrap();
            assert_eq!(
                decode_next_epoch_commitment_v0_exact(&bytes).unwrap(),
                commitment
            );
        }

        let commitment =
            sample_next_epoch_commitment(RolloutPhase::Shadow, None, EpochFallbackReasonV0::None);
        let bytes = commitment.try_cev0_bytes().unwrap();
        let offsets = next_commitment_offsets(&bytes);

        let mut invalid_rollout = bytes.clone();
        invalid_rollout[offsets.rollout_phase] = 4;
        let error = decode_next_epoch_commitment_v0_exact(&invalid_rollout).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidRolloutPhase);
        assert_eq!(error.byte_offset(), offsets.rollout_phase);

        let mut invalid_optional = bytes.clone();
        invalid_optional[offsets.optional_tag] = 2;
        let error = decode_next_epoch_commitment_v0_exact(&invalid_optional).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidOptionalTag);
        assert_eq!(error.byte_offset(), offsets.optional_tag);

        let mut invalid_boolean = bytes.clone();
        invalid_boolean[offsets.fallback_used] = 2;
        let error = decode_next_epoch_commitment_v0_exact(&invalid_boolean).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidBoolean);
        assert_eq!(error.byte_offset(), offsets.fallback_used);

        let mut invalid_reason = bytes.clone();
        invalid_reason[offsets.fallback_reason..offsets.fallback_reason + 2]
            .copy_from_slice(&10u16.to_be_bytes());
        let error = decode_next_epoch_commitment_v0_exact(&invalid_reason).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidFallbackReason);
        assert_eq!(error.byte_offset(), offsets.fallback_reason);

        let mut false_with_reason = bytes.clone();
        false_with_reason[offsets.fallback_reason..offsets.fallback_reason + 2]
            .copy_from_slice(&1u16.to_be_bytes());
        let error = decode_next_epoch_commitment_v0_exact(&false_with_reason).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidFallbackReason);
        assert_eq!(error.byte_offset(), offsets.fallback_reason);

        let mut true_without_reason = bytes.clone();
        true_without_reason[offsets.fallback_used] = 1;
        let error = decode_next_epoch_commitment_v0_exact(&true_without_reason).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidFallbackReason);
        assert_eq!(error.byte_offset(), offsets.fallback_reason);

        let mut semantic_error_with_trailing = invalid_rollout;
        semantic_error_with_trailing.push(0);
        assert_eq!(
            decode_next_epoch_commitment_v0_exact(&semantic_error_with_trailing)
                .unwrap_err()
                .code(),
            DecodeErrorCode::TrailingBytes
        );
    }

    #[test]
    fn next_epoch_commitment_decoder_maps_intrinsic_shape_failures() {
        let commitment =
            sample_next_epoch_commitment(RolloutPhase::Shadow, None, EpochFallbackReasonV0::None);
        let bytes = commitment.try_cev0_bytes().unwrap();
        let offsets = next_commitment_offsets(&bytes);

        let mut wrong_schema = bytes.clone();
        wrong_schema[..2].copy_from_slice(&1u16.to_be_bytes());
        let error = decode_next_epoch_commitment_v0_exact(&wrong_schema).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidSchemaVersion);
        assert_eq!(error.byte_offset(), 0);

        let mut zero_genesis = bytes.clone();
        zero_genesis[2..34].fill(0);
        let error = decode_next_epoch_commitment_v0_exact(&zero_genesis).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::ZeroGenesisHash);
        assert_eq!(error.byte_offset(), 2);

        let old_epoch = bytes[offsets.old_epoch..offsets.old_epoch + 8].to_vec();
        let mut nonadjacent_epoch = bytes.clone();
        nonadjacent_epoch[offsets.new_epoch..offsets.new_epoch + 8].copy_from_slice(&old_epoch);

        let mut zero_snapshot_root = bytes.clone();
        zero_snapshot_root[offsets.snapshot_state_root..offsets.snapshot_state_root + 32].fill(0);
        let mut zero_validator_set = bytes.clone();
        zero_validator_set[offsets.new_validator_set_hash..offsets.new_validator_set_hash + 32]
            .fill(0);
        let mut zero_parameters = bytes.clone();
        zero_parameters
            [offsets.new_consensus_parameters_hash..offsets.new_consensus_parameters_hash + 32]
            .fill(0);
        let mut zero_activation = bytes.clone();
        zero_activation[offsets.activation_height..offsets.activation_height + 8].fill(0);

        for (invalid, expected_offset) in [
            (nonadjacent_epoch, offsets.new_epoch),
            (zero_snapshot_root, offsets.snapshot_state_root),
            (zero_validator_set, offsets.new_validator_set_hash),
            (zero_parameters, offsets.new_consensus_parameters_hash),
            (zero_activation, offsets.activation_height),
        ] {
            let error = decode_next_epoch_commitment_v0_exact(&invalid).unwrap_err();
            assert_eq!(error.code(), DecodeErrorCode::InvalidNextEpochCommitment);
            assert_eq!(error.byte_offset(), expected_offset);
        }

        let present = sample_next_epoch_commitment(
            RolloutPhase::Shadow,
            Some(UpgradePlanHash::new([35; 32])),
            EpochFallbackReasonV0::None,
        );
        let mut zero_upgrade = present.try_cev0_bytes().unwrap();
        let present_offsets = next_commitment_offsets(&zero_upgrade);
        zero_upgrade[present_offsets.optional_tag + 1..present_offsets.optional_tag + 33].fill(0);
        let error = decode_next_epoch_commitment_v0_exact(&zero_upgrade).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidNextEpochCommitment);
        assert_eq!(error.byte_offset(), present_offsets.optional_tag);
    }

    #[test]
    fn next_epoch_commitment_decoder_enforces_chain_id_bounds() {
        let commitment =
            sample_next_epoch_commitment(RolloutPhase::Shadow, None, EpochFallbackReasonV0::None);
        let fields = commitment.fields();
        let maximum_chain_id = ChainId::from_bytes(&[b'x'; MAX_CONSENSUS_STRING_BYTES]).unwrap();
        let maximum = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            chain_id: maximum_chain_id,
            ..fields
        })
        .unwrap();
        let maximum_bytes = maximum.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_next_epoch_commitment_v0_exact(&maximum_bytes).unwrap(),
            maximum
        );

        let bytes = commitment.try_cev0_bytes().unwrap();
        let chain_length_offset = 2 + 32;
        let chain_start = chain_length_offset + 2;
        let chain_length = usize::from(u16::from_be_bytes(
            bytes[chain_length_offset..chain_start].try_into().unwrap(),
        ));
        let suffix = &bytes[chain_start + chain_length..];

        let mut empty = bytes[..chain_length_offset].to_vec();
        empty.extend_from_slice(&0u16.to_be_bytes());
        empty.extend_from_slice(suffix);
        let error = decode_next_epoch_commitment_v0_exact(&empty).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidConsensusString);
        assert_eq!(error.byte_offset(), chain_length_offset);
        empty.push(0);
        let error = decode_next_epoch_commitment_v0_exact(&empty).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
        assert_eq!(error.byte_offset(), empty.len() - 1);

        let excessive_length = MAX_CONSENSUS_STRING_BYTES + 1;
        let mut excessive = bytes[..chain_length_offset].to_vec();
        excessive.extend_from_slice(&(excessive_length as u16).to_be_bytes());
        excessive.extend_from_slice(&vec![b'x'; excessive_length]);
        excessive.extend_from_slice(suffix);
        let error = decode_next_epoch_commitment_v0_exact(&excessive).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(error.byte_offset(), chain_length_offset);
    }

    #[test]
    fn certificate_only_handoff_checks_cannot_authorize_proposal_or_tc_epoch_anchors() {
        let sample = sample_handoff_kernel();
        assert!(sample
            .authorization
            .verify_certificate_kernel(&sample.old_set, &sample.new_set, &AcceptSignatures,)
            .is_ok());

        let anchor = QcReferenceV0::epoch_anchor(sample.authorization.epoch_anchor_qc());
        let entries = sample.new_set.validators()[..2]
            .iter()
            .map(|validator| {
                TimeoutEntryV0::new(
                    validator.id(),
                    anchor.qc_ref(),
                    Signature64::from_array([41; SIGNATURE_BYTES]),
                )
                .unwrap()
            })
            .collect();
        let timeout_certificate = TimeoutCertificateV0::new(
            View::new(1),
            entries,
            vec![anchor.clone()],
            anchor.id(),
            &sample.new_set,
        )
        .unwrap();
        assert_eq!(
            timeout_certificate.verify(
                &sample.new_set,
                Some((&sample.authorization, &sample.old_set)),
                &AcceptSignatures,
            ),
            Err(ValidationError::InvalidCertificate(
                "complete trusted epoch-anchor authorization is not implemented"
            ))
        );

        let parameters = crate::ConsensusParametersV0::reference_shadow_v0();
        let header = BlockHeader::new(
            sample.new_set.genesis_hash(),
            sample.new_set.chain_id(),
            sample.new_set.protocol_version(),
            sample.new_set.epoch(),
            View::new(1),
            Height::new(11),
            BlockKind::EpochHandoff,
            sample.terminal_header.id(),
            sample.new_set.validators()[0].id(),
            sample.new_set.id(),
            sample.new_set.consensus_parameters_hash(),
            PayloadDigest::new([42; 32]),
            StateRoot::new([43; 32]),
            ReceiptsRoot::new([44; 32]),
            EvidenceRoot::new([45; 32]),
            sample.terminal_header.timestamp_ms() + 1,
            None,
        )
        .unwrap();
        let witness = crate::ProposalWitnessV0::new(
            &header,
            anchor,
            None,
            Some(sample.authorization.clone()),
            Signature64::from_array([46; SIGNATURE_BYTES]),
            &sample.new_set,
            Some(&sample.old_set),
            &parameters,
            sample.terminal_header.timestamp_ms(),
        )
        .unwrap();
        assert_eq!(
            witness.verify_for_header(
                &header,
                &sample.new_set,
                Some(&sample.old_set),
                &parameters,
                sample.terminal_header.timestamp_ms(),
                &AcceptSignatures,
            ),
            Err(ValidationError::InvalidProposal(
                "complete trusted epoch-anchor authorization is not implemented"
            ))
        );
    }

    #[test]
    fn exact_decoders_round_trip_certificate_kernel() {
        let set = sample_set();
        let set_bytes = set.try_cev0_bytes().unwrap();
        assert_eq!(decode_validator_set_v0_exact(&set_bytes).unwrap(), set);

        let certificate = qc(&set, 3, 11, 3, &[0, 1]);
        let certificate_bytes = certificate.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_ordinary_qc_v0_exact(&certificate_bytes, &set).unwrap(),
            certificate
        );

        let timeout = sample_tc(&set);
        let timeout_bytes = timeout.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&timeout_bytes, &set).unwrap(),
            timeout
        );
    }

    #[test]
    fn exact_handoff_kernel_decoders_round_trip_and_enforce_root_boundaries() {
        fn assert_exact_boundaries<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> DecodeResult<T>) {
            for prefix_length in 0..bytes.len() {
                let error = match decode(&bytes[..prefix_length]) {
                    Ok(_) => panic!("incomplete B2-B CEV0 prefix was accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.code(), DecodeErrorCode::UnexpectedEof);
                assert_eq!(error.byte_offset(), prefix_length);
            }
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            let error = match decode(&trailing) {
                Ok(_) => panic!("B2-B CEV0 root with a trailing byte was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
            assert_eq!(error.byte_offset(), bytes.len());
        }

        let sample = sample_handoff_kernel();
        let header_bytes = sample.terminal_header.try_cev0_bytes().unwrap();
        let descriptor_bytes = sample.descriptor.try_cev0_bytes().unwrap();
        let certificate_bytes = sample.certificate.try_cev0_bytes().unwrap();
        let authorization_bytes = sample.authorization.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_block_header_v0_exact(&header_bytes).unwrap(),
            sample.terminal_header
        );
        assert_eq!(
            decode_handoff_descriptor_v0_exact(&descriptor_bytes).unwrap(),
            sample.descriptor
        );
        assert_eq!(
            decode_handoff_certificate_v0_exact(
                &certificate_bytes,
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap(),
            sample.certificate
        );
        let kernel = decode_epoch_anchor_authorization_kernel_v0_exact(
            &authorization_bytes,
            &sample.old_set,
            &sample.new_set,
        )
        .unwrap();
        assert_eq!(
            kernel.terminal_old_header(),
            sample.authorization.terminal_old_header()
        );
        assert_eq!(
            kernel.terminal_old_qc(),
            sample.authorization.terminal_old_qc()
        );
        assert_eq!(
            kernel.handoff_certificate(),
            sample.authorization.handoff_certificate()
        );
        assert_eq!(kernel.try_cev0_bytes().unwrap(), authorization_bytes);
        assert!(kernel
            .verify_certificate_kernel(&sample.old_set, &sample.new_set, &RejectSignatures,)
            .is_err());
        assert!(kernel
            .verify_certificate_kernel(&sample.old_set, &sample.new_set, &AcceptSignatures,)
            .is_ok());

        assert_exact_boundaries(&header_bytes, decode_block_header_v0_exact);
        assert_exact_boundaries(&descriptor_bytes, decode_handoff_descriptor_v0_exact);
        assert_exact_boundaries(&certificate_bytes, |bytes| {
            decode_handoff_certificate_v0_exact(bytes, &sample.old_set, &sample.new_set)
        });
        assert_exact_boundaries(&authorization_bytes, |bytes| {
            decode_epoch_anchor_authorization_kernel_v0_exact(
                bytes,
                &sample.old_set,
                &sample.new_set,
            )
        });
    }

    #[test]
    fn block_header_decoder_enforces_discriminants_bounds_and_shape() {
        let sample = sample_handoff_kernel();
        let bytes = sample.terminal_header.try_cev0_bytes().unwrap();
        let (view_offset, kind_offset, proposer_length_offset, _, optional_tag_offset) =
            block_header_offsets(&bytes);

        let mut unknown_kind = bytes.clone();
        unknown_kind[kind_offset] = 5;
        let error = decode_block_header_v0_exact(&unknown_kind).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidBlockKind);
        assert_eq!(error.byte_offset(), kind_offset);

        let mut invalid_optional = bytes.clone();
        invalid_optional[optional_tag_offset] = 2;
        let error = decode_block_header_v0_exact(&invalid_optional).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::InvalidOptionalTag);
        assert_eq!(error.byte_offset(), optional_tag_offset);

        let mut zero_view = bytes.clone();
        zero_view[view_offset..view_offset + 8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_block_header_v0_exact(&zero_view).unwrap_err().code(),
            DecodeErrorCode::InvalidBlockHeader
        );

        for invalid_length in [0u32, 129, u32::MAX] {
            let mut invalid_id = bytes.clone();
            invalid_id[proposer_length_offset..proposer_length_offset + 4]
                .copy_from_slice(&invalid_length.to_be_bytes());
            assert_eq!(
                decode_block_header_v0_exact(&invalid_id)
                    .unwrap_err()
                    .code(),
                DecodeErrorCode::LengthLimitExceeded
            );
        }

        let proposer = ValidatorId::from_bytes(&[31; MAX_VALIDATOR_ID_BYTES]).unwrap();
        let header_with_max_id = BlockHeader::new(
            sample.terminal_header.genesis_hash(),
            sample.terminal_header.chain_id(),
            sample.terminal_header.protocol_version(),
            sample.terminal_header.epoch(),
            sample.terminal_header.view(),
            sample.terminal_header.height(),
            sample.terminal_header.block_kind(),
            sample.terminal_header.parent_id(),
            proposer,
            sample.terminal_header.validator_set_id(),
            sample.terminal_header.consensus_parameters_hash(),
            sample.terminal_header.payload_digest(),
            sample.terminal_header.state_root(),
            sample.terminal_header.receipts_root(),
            sample.terminal_header.evidence_root(),
            sample.terminal_header.timestamp_ms(),
            sample.terminal_header.next_epoch_commitment_hash(),
        )
        .unwrap();
        assert_eq!(
            decode_block_header_v0_exact(&header_with_max_id.try_cev0_bytes().unwrap()).unwrap(),
            header_with_max_id
        );
    }

    #[test]
    fn handoff_decoder_enforces_descriptor_context_roles_and_caps() {
        let sample = sample_handoff_kernel();
        let mut max_chain_fields = sample.descriptor.fields().clone();
        max_chain_fields.chain_id = ChainId::new(&"a".repeat(MAX_CONSENSUS_STRING_BYTES)).unwrap();
        let max_chain_descriptor = HandoffDescriptorV0::new(max_chain_fields).unwrap();
        let max_chain_bytes = max_chain_descriptor.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_handoff_descriptor_v0_exact(&max_chain_bytes).unwrap(),
            max_chain_descriptor
        );
        let chain_length_offset = 2 + 32;
        let mut empty_chain = max_chain_bytes.clone();
        empty_chain[chain_length_offset..chain_length_offset + 2]
            .copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            decode_handoff_descriptor_v0_exact(&empty_chain)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidConsensusString
        );
        let mut excessive_chain = max_chain_bytes;
        excessive_chain[chain_length_offset..chain_length_offset + 2]
            .copy_from_slice(&129u16.to_be_bytes());
        assert_eq!(
            decode_handoff_descriptor_v0_exact(&excessive_chain)
                .unwrap_err()
                .code(),
            DecodeErrorCode::LengthLimitExceeded
        );

        let descriptor_bytes = sample.descriptor.try_cev0_bytes().unwrap();
        let (_, new_epoch_offset, _, _, _) = descriptor_offsets(&descriptor_bytes);
        let mut nonadjacent = descriptor_bytes;
        nonadjacent[new_epoch_offset..new_epoch_offset + 8]
            .copy_from_slice(&(sample.old_set.epoch().get() + 2).to_be_bytes());
        assert_eq!(
            decode_handoff_descriptor_v0_exact(&nonadjacent)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidHandoffDescriptor
        );

        let bytes = sample.certificate.try_cev0_bytes().unwrap();
        let (old_count_offset, first_old, second_old, first_new, second_new) =
            parsed_handoff_offsets(&bytes);
        for excessive in [101u32, u32::MAX] {
            let mut invalid_count = bytes.clone();
            invalid_count[old_count_offset..old_count_offset + 4]
                .copy_from_slice(&excessive.to_be_bytes());
            let error = decode_handoff_certificate_v0_exact(
                &invalid_count,
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap_err();
            assert_eq!(error.code(), DecodeErrorCode::CountLimitExceeded);
            assert_eq!(error.byte_offset(), old_count_offset);
        }

        let mut duplicate = bytes.clone();
        duplicate[second_old + 4] = duplicate[first_old + 4];
        let error =
            decode_handoff_certificate_v0_exact(&duplicate, &sample.old_set, &sample.new_set)
                .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::DuplicateSigner);
        assert_eq!(error.byte_offset(), second_old);

        let mut noncanonical = bytes.clone();
        noncanonical.swap(first_new + 4, second_new + 4);
        let error =
            decode_handoff_certificate_v0_exact(&noncanonical, &sample.old_set, &sample.new_set)
                .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::NonCanonicalSignerOrder);
        assert_eq!(error.byte_offset(), second_new);

        let mut unknown = bytes.clone();
        unknown[first_old + 4] = 99;
        let error = decode_handoff_certificate_v0_exact(&unknown, &sample.old_set, &sample.new_set)
            .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::UnknownSigner);
        assert_eq!(error.byte_offset(), first_old);

        let descriptor_start = 2usize;
        let (_, _, old_set_offset, _, _) = descriptor_offsets(&bytes[descriptor_start..]);
        let mut wrong_context = bytes.clone();
        wrong_context[descriptor_start + old_set_offset] ^= 1;
        assert_eq!(
            decode_handoff_certificate_v0_exact(&wrong_context, &sample.old_set, &sample.new_set,)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidHandoffCertificate
        );

        let insufficient = HandoffCertificateV0::from_parts_for_test(
            sample.descriptor.clone(),
            handoff_shares(&sample.old_set, &[3]),
            handoff_shares(&sample.new_set, &[0, 1]),
        )
        .unwrap();
        assert_eq!(
            decode_handoff_certificate_v0_exact(
                &insufficient.try_cev0_bytes().unwrap(),
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::InsufficientQuorum
        );

        let mut cursor = Cursor::new(&bytes);
        let raw = parse_raw_handoff_certificate(&mut cursor).unwrap();
        let mut empty_old = Vec::new();
        empty_old.extend_from_slice(&bytes[..raw.old_count_offset]);
        empty_old.extend_from_slice(&0u32.to_be_bytes());
        empty_old.extend_from_slice(&bytes[raw.new_count_offset..]);
        assert_eq!(
            decode_handoff_certificate_v0_exact(&empty_old, &sample.old_set, &sample.new_set,)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidHandoffCertificate
        );
    }

    #[test]
    fn handoff_decoder_accepts_exact_two_hundred_share_aggregate() {
        fn hundred_set(epoch: u64, parameters: u8, key_bias: u8) -> ValidatorSet {
            let validators = (1u8..=100)
                .map(|id| {
                    Validator::new(
                        ValidatorId::from_bytes(&[id]).unwrap(),
                        ConsensusPublicKey::new([id.wrapping_add(key_bias); 32]),
                        VotingPower::new(1).unwrap(),
                    )
                    .unwrap()
                })
                .collect();
            ValidatorSet::new(
                GenesisHash::new([41; 32]),
                ChainId::new("handoff-caps").unwrap(),
                ProtocolVersion::V0,
                Epoch::new(epoch),
                ConsensusParametersHash::new([parameters; 32]),
                validators,
            )
            .unwrap()
        }

        let old_set = hundred_set(3, 42, 100);
        let new_set = hundred_set(4, 43, 150);
        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash: old_set.genesis_hash(),
            chain_id: old_set.chain_id(),
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: old_set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: old_set.consensus_parameters_hash(),
            new_consensus_parameters_hash: new_set.consensus_parameters_hash(),
            checkpoint_height: Height::new(8),
            checkpoint_block_id: BlockId::new([44; 32]),
            checkpoint_state_root: StateRoot::new([45; 32]),
            next_epoch_commitment_digest: NextEpochCommitmentHash::new([46; 32]),
            terminal_old_height: Height::new(10),
            terminal_old_block_id: BlockId::new([47; 32]),
            terminal_old_qc_digest: CertificateId::new([48; 32]),
            terminal_old_view: View::new(12),
            activation_height: Height::new(11),
            initial_new_view: View::new(1),
        })
        .unwrap();
        let all: Vec<_> = (0..100).collect();
        let certificate = HandoffCertificateV0::new(
            descriptor,
            handoff_shares(&old_set, &all),
            handoff_shares(&new_set, &all),
            &old_set,
            &new_set,
        )
        .unwrap();
        assert_eq!(
            certificate.old_signatures().len() + certificate.new_signatures().len(),
            MAX_CEV0_HANDOFF_AGGREGATE_SIGNATURE_SHARES
        );
        assert_eq!(
            decode_handoff_certificate_v0_exact(
                &certificate.try_cev0_bytes().unwrap(),
                &old_set,
                &new_set,
            )
            .unwrap(),
            certificate
        );
    }

    #[test]
    fn epoch_anchor_kernel_requires_ordinary_qc_and_exact_terminal_relations() {
        let sample = sample_handoff_kernel();
        let bytes = sample.authorization.try_cev0_bytes().unwrap();
        let mut cursor = Cursor::new(&bytes);
        parse_raw_block_header(&mut cursor).unwrap();
        let header_end = cursor.offset();
        let terminal_qc = parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS).unwrap();
        let terminal_qc_end = cursor.offset();
        let handoff_start = cursor.offset();
        parse_raw_handoff_certificate(&mut cursor).unwrap();
        cursor.finish().unwrap();

        let (_, kind_offset, _, state_root_offset, optional_tag_offset) =
            block_header_offsets(&bytes[..header_end]);
        let mut wrong_kind = bytes.clone();
        wrong_kind[kind_offset] = BlockKind::EpochSeal1 as u8;
        assert_eq!(
            decode_epoch_anchor_authorization_kernel_v0_exact(
                &wrong_kind,
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::InvalidEpochAnchorRelations
        );

        let mut empty_qc = Vec::new();
        empty_qc.extend_from_slice(&bytes[..terminal_qc.signature_count_offset]);
        empty_qc.extend_from_slice(&0u32.to_be_bytes());
        empty_qc.extend_from_slice(&bytes[terminal_qc_end..]);
        assert_eq!(
            decode_epoch_anchor_authorization_kernel_v0_exact(
                &empty_qc,
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let mut wrong_qc_block = bytes.clone();
        let terminal_qc_block_offset = terminal_qc.signature_count_offset - 32;
        wrong_qc_block[terminal_qc_block_offset] ^= 1;
        assert_eq!(
            decode_epoch_anchor_authorization_kernel_v0_exact(
                &wrong_qc_block,
                &sample.old_set,
                &sample.new_set,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::InvalidEpochAnchorRelations
        );

        let descriptor_start = handoff_start + 2;
        let (_, _, _, terminal_block_offset, terminal_qc_digest_offset) =
            descriptor_offsets(&bytes[descriptor_start..]);
        for offset in [
            state_root_offset,
            optional_tag_offset + 1,
            descriptor_start + terminal_block_offset,
            descriptor_start + terminal_qc_digest_offset,
        ] {
            let mut mismatch = bytes.clone();
            mismatch[offset] ^= 1;
            assert_eq!(
                decode_epoch_anchor_authorization_kernel_v0_exact(
                    &mismatch,
                    &sample.old_set,
                    &sample.new_set,
                )
                .unwrap_err()
                .code(),
                DecodeErrorCode::InvalidEpochAnchorRelations
            );
        }
    }

    #[test]
    fn exact_decoders_reject_every_root_prefix_and_trailing_bytes() {
        fn assert_exact_boundaries<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> DecodeResult<T>) {
            for prefix_length in 0..bytes.len() {
                let error = match decode(&bytes[..prefix_length]) {
                    Ok(_) => panic!("incomplete CEV0 prefix was accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.code(), DecodeErrorCode::UnexpectedEof);
                assert!(error.byte_offset() <= prefix_length);
            }
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            let error = match decode(&trailing) {
                Ok(_) => panic!("CEV0 root with a trailing byte was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
            assert_eq!(error.byte_offset(), trailing.len() - 1);
        }

        let set = sample_set();
        assert_exact_boundaries(
            &set.try_cev0_bytes().unwrap(),
            decode_validator_set_v0_exact,
        );
        assert_exact_boundaries(
            &qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap(),
            |bytes| decode_ordinary_qc_v0_exact(bytes, &set),
        );
        assert_exact_boundaries(&sample_tc(&set).try_cev0_bytes().unwrap(), |bytes| {
            decode_ordinary_timeout_certificate_v0_exact(bytes, &set)
        });
    }

    #[test]
    fn decoder_rejects_schema_strings_and_lengths_before_payload_reads() {
        let set = sample_set();
        let mut qc_bytes = qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap();
        qc_bytes[..2].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            decode_ordinary_qc_v0_exact(&qc_bytes, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidSchemaVersion
        );

        let chain = "a".repeat(MAX_CONSENSUS_STRING_BYTES);
        let max_string_set = ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::new(&chain).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            ConsensusParametersHash::new([6; 32]),
            vec![validator(1, 1)],
        )
        .unwrap();
        let max_string_bytes = max_string_set.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_validator_set_v0_exact(&max_string_bytes).unwrap(),
            max_string_set
        );

        let mut too_long = max_string_bytes.clone();
        too_long[34..36].copy_from_slice(
            &u16::try_from(MAX_CONSENSUS_STRING_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            decode_validator_set_v0_exact(&too_long).unwrap_err().code(),
            DecodeErrorCode::LengthLimitExceeded
        );

        let mut empty = Vec::with_capacity(max_string_bytes.len() - MAX_CONSENSUS_STRING_BYTES);
        empty.extend_from_slice(&max_string_bytes[..34]);
        empty.extend_from_slice(&0u16.to_be_bytes());
        empty.extend_from_slice(&max_string_bytes[36 + MAX_CONSENSUS_STRING_BYTES..]);
        assert_eq!(
            decode_validator_set_v0_exact(&empty).unwrap_err().code(),
            DecodeErrorCode::InvalidConsensusString
        );

        let mut invalid_ascii = max_string_bytes;
        invalid_ascii[36] = b'A';
        assert_eq!(
            decode_validator_set_v0_exact(&invalid_ascii)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidConsensusString
        );
    }

    #[test]
    fn decoder_enforces_validator_id_and_list_hard_caps_before_allocation() {
        let id = vec![1; MAX_VALIDATOR_ID_BYTES];
        let set = ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::new("caps").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            ConsensusParametersHash::new([6; 32]),
            vec![Validator::new(
                ValidatorId::from_bytes(&id).unwrap(),
                ConsensusPublicKey::new([1; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .unwrap();
        let bytes = set.try_cev0_bytes().unwrap();
        assert_eq!(decode_validator_set_v0_exact(&bytes).unwrap(), set);

        let count_offset = validator_count_offset(&bytes);
        let first_id_length_offset = count_offset + 4;
        let mut too_long = bytes.clone();
        too_long[first_id_length_offset..first_id_length_offset + 4].copy_from_slice(
            &u32::try_from(MAX_VALIDATOR_ID_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            decode_validator_set_v0_exact(&too_long).unwrap_err().code(),
            DecodeErrorCode::LengthLimitExceeded
        );

        let mut empty = Vec::with_capacity(bytes.len() - MAX_VALIDATOR_ID_BYTES);
        empty.extend_from_slice(&bytes[..first_id_length_offset]);
        empty.extend_from_slice(&0u32.to_be_bytes());
        empty.extend_from_slice(&bytes[first_id_length_offset + 4 + MAX_VALIDATOR_ID_BYTES..]);
        assert_eq!(
            decode_validator_set_v0_exact(&empty).unwrap_err().code(),
            DecodeErrorCode::LengthLimitExceeded
        );

        for excessive in [101u32, u32::MAX] {
            let mut mutated = bytes.clone();
            mutated[count_offset..count_offset + 4].copy_from_slice(&excessive.to_be_bytes());
            assert_eq!(
                decode_validator_set_v0_exact(&mutated).unwrap_err().code(),
                DecodeErrorCode::CountLimitExceeded
            );
        }
    }

    #[test]
    fn trusted_genesis_qc_reference_decoder_accepts_only_the_exact_anchor() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = trusted_genesis_set(&parameters);
        let reference = trusted_genesis_reference(&set);
        let bytes = qc_reference_bytes(&reference);

        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&bytes, &set).unwrap(),
            reference
        );
        assert_eq!(
            decode_ordinary_qc_v0_exact(&bytes, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let ordinary = qc(&set, 1, 1, 81, &[0, 1, 2]);
        let ordinary_bytes = ordinary.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&ordinary_bytes, &set)
                .unwrap()
                .as_ordinary(),
            Some(&ordinary)
        );

        let view_offset = qc_view_offset(&bytes);
        let mut wrong_view = bytes.clone();
        wrong_view[view_offset..view_offset + 8].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&wrong_view, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let block_offset = view_offset + 16;
        let mut wrong_block = bytes.clone();
        wrong_block[block_offset] ^= 1;
        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&wrong_block, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let epoch_anchor = sample_handoff_kernel()
            .authorization
            .epoch_anchor_qc()
            .try_cev0_bytes()
            .unwrap();
        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&epoch_anchor, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&bytes[..bytes.len() - 1], &set,)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnexpectedEof
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_qc_reference_v0_exact_with_trusted_genesis(&trailing, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::TrailingBytes
        );
    }

    #[test]
    fn trusted_genesis_timeout_decoder_reconstructs_only_exact_references() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = trusted_genesis_set(&parameters);
        let timeout = trusted_genesis_timeout(&set);
        let bytes = timeout.try_cev0_bytes().unwrap();

        assert_eq!(
            decode_timeout_certificate_v0_exact_with_trusted_genesis(&bytes, &set).unwrap(),
            timeout
        );
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&bytes, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidReferencedQc
        );

        let (_, _, first_reference) = tc_offsets(&bytes);
        let nested_view = first_reference + qc_view_offset(&bytes[first_reference..]);
        let mut spliced = bytes.clone();
        spliced[nested_view..nested_view + 8].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(
            decode_timeout_certificate_v0_exact_with_trusted_genesis(&spliced, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidReferencedQc
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_timeout_certificate_v0_exact_with_trusted_genesis(&trailing, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::TrailingBytes
        );
    }

    #[test]
    fn trusted_genesis_certified_header_and_finality_proof_round_trip_exactly() {
        fn certified_anchor_tag_offset(bytes: &[u8]) -> usize {
            let mut cursor = Cursor::new(bytes);
            parse_raw_block_header(&mut cursor).unwrap();
            parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS).unwrap();
            match cursor.u8().unwrap() {
                0 => {}
                1 => {
                    parse_raw_timeout_certificate(&mut cursor).unwrap();
                }
                _ => unreachable!("fixture uses a canonical timeout tag"),
            }
            cursor.offset()
        }

        let (set, parameters, genesis_timestamp_ms, proof) = trusted_genesis_finality_fixture();
        let first = proof.finalized_block().clone();
        let first_bytes = first.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_certified_header_v0_exact_with_trusted_genesis(
                &first_bytes,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap(),
            first
        );
        assert_eq!(
            decode_ordinary_certified_header_v0_exact(
                &first_bytes,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let skipped_header = trusted_genesis_header(
            &set,
            3,
            1,
            BlockId::new(*set.genesis_hash().as_bytes()),
            genesis_timestamp_ms + 1,
        );
        let skipped = trusted_genesis_certified(
            &set,
            &parameters,
            skipped_header,
            trusted_genesis_reference(&set),
            Some(trusted_genesis_timeout(&set)),
            genesis_timestamp_ms,
        );
        let skipped_bytes = skipped.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_certified_header_v0_exact_with_trusted_genesis(
                &skipped_bytes,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap(),
            skipped
        );

        let anchor_tag = certified_anchor_tag_offset(&skipped_bytes);
        let mut epoch_authorization_tag = skipped_bytes.clone();
        epoch_authorization_tag[anchor_tag] = 1;
        assert_eq!(
            decode_certified_header_v0_exact_with_trusted_genesis(
                &epoch_authorization_tag,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::InvalidCheckpointTwoSeal
        );
        let mut unknown_authorization_tag = skipped_bytes;
        unknown_authorization_tag[anchor_tag] = 2;
        assert_eq!(
            decode_certified_header_v0_exact_with_trusted_genesis(
                &unknown_authorization_tag,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::InvalidOptionalTag
        );

        let proof_bytes = proof.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_finality_proof_v0_exact_with_trusted_genesis(
                &proof_bytes,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap(),
            proof
        );
        assert_eq!(
            decode_finality_proof_v0_exact(&proof_bytes, &set, &parameters, genesis_timestamp_ms,)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        let mut trailing = proof_bytes;
        trailing.push(0);
        assert_eq!(
            decode_finality_proof_v0_exact_with_trusted_genesis(
                &trailing,
                &set,
                &parameters,
                genesis_timestamp_ms,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::TrailingBytes
        );
    }

    #[test]
    fn ordinary_qc_decoder_rejects_synthetic_and_noncanonical_signers() {
        let set = sample_set();
        let bytes = qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap();
        let count_offset = qc_signature_count_offset(&bytes);

        let mut empty = bytes[..count_offset + 4].to_vec();
        empty[count_offset..count_offset + 4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_ordinary_qc_v0_exact(&empty, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnauthorizedSyntheticQc
        );

        for excessive in [101u32, u32::MAX] {
            let mut mutated = bytes.clone();
            mutated[count_offset..count_offset + 4].copy_from_slice(&excessive.to_be_bytes());
            assert_eq!(
                decode_ordinary_qc_v0_exact(&mutated, &set)
                    .unwrap_err()
                    .code(),
                DecodeErrorCode::CountLimitExceeded
            );
        }

        let first_share = count_offset + 4;
        let first_id_length = 4usize;
        let first_id_length_value = 1usize;
        let second_share = first_share + first_id_length + first_id_length_value + SIGNATURE_BYTES;
        let mut duplicate = bytes;
        duplicate[second_share + first_id_length] = duplicate[first_share + first_id_length];
        assert_eq!(
            decode_ordinary_qc_v0_exact(&duplicate, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::DuplicateSigner
        );

        let mut signed_view_zero = qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap();
        let view_offset = qc_view_offset(&signed_view_zero);
        signed_view_zero[view_offset..view_offset + 8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_ordinary_qc_v0_exact(&signed_view_zero, &set)
                .unwrap_err()
                .code()
                .as_str(),
            "unauthorized_synthetic_qc"
        );

        let view_end = qc_view_offset(&signed_view_zero) + 8;
        assert_eq!(
            decode_ordinary_qc_v0_exact(&signed_view_zero[..view_end], &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::UnexpectedEof
        );

        let mut empty_with_trailing = empty;
        empty_with_trailing.push(0);
        assert_eq!(
            decode_ordinary_qc_v0_exact(&empty_with_trailing, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::TrailingBytes
        );
    }

    #[test]
    fn timeout_decoder_enforces_outer_caps_and_rejects_synthetic_references() {
        let set = sample_set();
        let bytes = sample_tc(&set).try_cev0_bytes().unwrap();
        let (entries_offset, references_offset, first_reference) = tc_offsets(&bytes);

        for offset in [entries_offset, references_offset] {
            for excessive in [101u32, u32::MAX] {
                let mut mutated = bytes.clone();
                mutated[offset..offset + 4].copy_from_slice(&excessive.to_be_bytes());
                assert_eq!(
                    decode_ordinary_timeout_certificate_v0_exact(&mutated, &set)
                        .unwrap_err()
                        .code(),
                    DecodeErrorCode::CountLimitExceeded
                );
            }
        }

        let first_qc_count = qc_signature_count_offset(&bytes[first_reference..]) + first_reference;
        let first_qc_end = {
            let mut cursor = Cursor::new(&bytes[first_reference..]);
            parse_raw_qc(&mut cursor, MAX_CEV0_CERTIFICATE_ITEMS).unwrap();
            first_reference + cursor.offset()
        };
        let mut synthetic = Vec::with_capacity(bytes.len());
        synthetic.extend_from_slice(&bytes[..first_qc_count]);
        synthetic.extend_from_slice(&0u32.to_be_bytes());
        synthetic.extend_from_slice(&bytes[first_qc_end..]);
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&synthetic, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidReferencedQc
        );

        let nested_view_offset = first_reference + qc_view_offset(&bytes[first_reference..]);
        let mut view_zero_reference = bytes.clone();
        view_zero_reference[nested_view_offset..nested_view_offset + 8]
            .copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&view_zero_reference, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::InvalidReferencedQc
        );

        let signer_length_offset = first_qc_count + 4;
        let mut empty_nested_signer = Vec::with_capacity(bytes.len() - 1);
        empty_nested_signer.extend_from_slice(&bytes[..signer_length_offset]);
        empty_nested_signer.extend_from_slice(&0u32.to_be_bytes());
        empty_nested_signer.extend_from_slice(&bytes[signer_length_offset + 5..]);
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&empty_nested_signer, &set)
                .unwrap_err()
                .code(),
            DecodeErrorCode::LengthLimitExceeded
        );
    }

    #[test]
    fn exact_hard_caps_include_one_hundred_by_one_hundred_tc_shares() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators: Vec<_> = (1u8..=100).map(|id| validator(id, 1)).collect();
        let set = ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::new("hard-caps").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(3),
            parameters.hash(),
            validators,
        )
        .unwrap();
        assert_eq!(
            decode_validator_set_v0_exact(&set.try_cev0_bytes().unwrap()).unwrap(),
            set
        );

        let all_signers: Vec<_> = (0..MAX_CEV0_CERTIFICATE_ITEMS).collect();
        let qcs: Vec<_> = (1u8..=100)
            .map(|coordinate| {
                qc(
                    &set,
                    u64::from(coordinate),
                    u64::from(coordinate),
                    coordinate,
                    &all_signers,
                )
            })
            .collect();
        assert_eq!(qcs.len() * qcs[0].votes().len(), 10_000);

        let entries: Vec<_> = set
            .validators()
            .iter()
            .zip(qcs.iter())
            .map(|(signer, certificate)| {
                TimeoutEntryV0::new(
                    signer.id(),
                    QcRef::from(certificate),
                    Signature64::from_array([signer.id().as_bytes()[0]; SIGNATURE_BYTES]),
                )
                .unwrap()
            })
            .collect();
        let selected = qcs.last().unwrap().id();
        let mut references: Vec<_> = qcs.into_iter().map(QcReferenceV0::ordinary).collect();
        references.sort_by_key(QcReferenceV0::id);
        let timeout =
            TimeoutCertificateV0::new(View::new(100), entries, references, selected, &set).unwrap();
        let bytes = timeout.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&bytes, &set).unwrap(),
            timeout
        );

        // Both the context-derived and default budgets must preserve the
        // frozen 10,000-share boundary. A previous N*(N-1) derivation rejected
        // this valid certificate at 9,900 shares before signature work.
        let mut bound_budget = Cev0AdmissionBudgetV0::for_validator_set(&parameters, &set);
        assert_eq!(
            bound_budget.maximum_tc_aggregate_signature_shares(),
            MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
        );
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact_with_budget(
                &bytes,
                &set,
                &mut bound_budget,
            )
            .unwrap(),
            timeout
        );
        let mut default_budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert_eq!(
            default_budget.maximum_tc_aggregate_signature_shares(),
            MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
        );
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact_with_budget(
                &bytes,
                &set,
                &mut default_budget,
            )
            .unwrap(),
            timeout
        );

        // One more referenced QC would exceed the frozen 100-reference /
        // 10,000-share envelope. Reject the count before nested allocation.
        let (_, references_offset, _) = tc_offsets(&bytes);
        let mut over_reference_cap = bytes.clone();
        over_reference_cap[references_offset..references_offset + 4]
            .copy_from_slice(&101u32.to_be_bytes());
        let mut over_budget = Cev0AdmissionBudgetV0::for_validator_set(&parameters, &set);
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact_with_budget(
                &over_reference_cap,
                &set,
                &mut over_budget,
            )
            .unwrap_err()
            .code(),
            DecodeErrorCode::CountLimitExceeded
        );
    }

    #[test]
    fn aggregate_limit_is_checked_before_nested_vote_allocation() {
        let set = sample_set();
        let bytes = qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap();
        let mut cursor = Cursor::new(&bytes);
        let error = parse_raw_qc(&mut cursor, 1).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::AggregateLimitExceeded);
        assert_eq!(error.byte_offset(), qc_signature_count_offset(&bytes));
    }

    #[test]
    fn budgeted_tc_rejects_nested_share_count_before_payload_reads() {
        let set = sample_set();
        let bytes = sample_tc(&set).try_cev0_bytes().unwrap();
        let (_, references_offset, _) = tc_offsets(&bytes);
        let first_reference = references_offset + 4;
        let nested_signature_count =
            first_reference + qc_signature_count_offset(&bytes[first_reference..]);

        // Leave only the nested QC header and its declared two-share count.
        // A contextual one-share budget must reject that declaration before
        // attempting to read either signature. Without the threaded parser
        // ceiling this same prefix would be reported as UnexpectedEof.
        let truncated = bytes[..nested_signature_count + 4].to_vec();
        let mut budget = Cev0AdmissionBudgetV0::with_limits(bytes.len(), usize::MAX, 1);
        let error =
            decode_ordinary_timeout_certificate_v0_exact_with_budget(&truncated, &set, &mut budget)
                .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::AggregateLimitExceeded);
        assert_eq!(error.byte_offset(), nested_signature_count);
        assert_eq!(budget.signature_work(), 0);
    }

    #[test]
    fn protocol_version_is_rejected_by_all_three_root_decoders() {
        fn protocol_offset(bytes: &[u8]) -> usize {
            let mut cursor = Cursor::new(bytes);
            cursor.u16().unwrap();
            let _: [u8; 32] = cursor.fixed().unwrap();
            cursor.bounded_consensus_bytes().unwrap();
            cursor.offset()
        }

        let set = sample_set();
        let mut set_bytes = set.try_cev0_bytes().unwrap();
        let offset = protocol_offset(&set_bytes);
        set_bytes[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            decode_validator_set_v0_exact(&set_bytes)
                .unwrap_err()
                .code()
                .as_str(),
            "invalid_protocol_version"
        );

        let mut qc_bytes = qc(&set, 3, 11, 3, &[0, 1]).try_cev0_bytes().unwrap();
        let offset = protocol_offset(&qc_bytes);
        qc_bytes[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            decode_ordinary_qc_v0_exact(&qc_bytes, &set)
                .unwrap_err()
                .code()
                .as_str(),
            "invalid_protocol_version"
        );

        let mut tc_bytes = sample_tc(&set).try_cev0_bytes().unwrap();
        let offset = protocol_offset(&tc_bytes);
        tc_bytes[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            decode_ordinary_timeout_certificate_v0_exact(&tc_bytes, &set)
                .unwrap_err()
                .code()
                .as_str(),
            "invalid_protocol_version"
        );
    }

    #[test]
    fn timeout_relation_failures_have_manifest_stable_codes() {
        fn entry(signer: ValidatorId, certificate: &QuorumCertificate) -> TimeoutEntryV0 {
            TimeoutEntryV0::new(
                signer,
                QcRef::from(certificate),
                Signature64::from_array([42; SIGNATURE_BYTES]),
            )
            .unwrap()
        }

        let set = sample_set();
        let low = qc(&set, 3, 11, 3, &[0, 1]);
        let high = qc(&set, 5, 13, 5, &[0, 1]);
        let future = qc(&set, 10, 15, 10, &[0, 1]);
        let same_block_other_coordinate = qc(&set, 5, 13, 3, &[0, 1]);
        let same_view_other_block = qc(&set, 3, 11, 4, &[0, 1]);

        let assert_code = |result: DecodeResult<()>, expected: &'static str| {
            assert_eq!(result.unwrap_err().code().as_str(), expected);
        };

        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[entry(set.validators()[0].id(), &future)],
                &[QcReferenceV0::ordinary(future.clone())],
                future.id(),
                0,
            ),
            "future_reference_view",
        );

        let mut same_block_references = vec![
            QcReferenceV0::ordinary(low.clone()),
            QcReferenceV0::ordinary(same_block_other_coordinate.clone()),
        ];
        same_block_references.sort_by_key(QcReferenceV0::id);
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[
                    entry(set.validators()[0].id(), &low),
                    entry(set.validators()[1].id(), &same_block_other_coordinate),
                ],
                &same_block_references,
                same_block_other_coordinate.id(),
                0,
            ),
            "same_block_different_coordinates",
        );

        let mut same_view_references = vec![
            QcReferenceV0::ordinary(low.clone()),
            QcReferenceV0::ordinary(same_view_other_block.clone()),
        ];
        same_view_references.sort_by_key(QcReferenceV0::id);
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[
                    entry(set.validators()[0].id(), &low),
                    entry(set.validators()[1].id(), &same_view_other_block),
                ],
                &same_view_references,
                low.id(),
                0,
            ),
            "conflicting_same_view_qc",
        );

        let mut references = vec![
            QcReferenceV0::ordinary(low.clone()),
            QcReferenceV0::ordinary(high.clone()),
        ];
        references.sort_by_key(QcReferenceV0::id);
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[
                    entry(set.validators()[0].id(), &low),
                    entry(set.validators()[1].id(), &high),
                ],
                &references,
                low.id(),
                0,
            ),
            "selected_not_maximum",
        );
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[entry(set.validators()[0].id(), &future)],
                &references,
                high.id(),
                0,
            ),
            "reference_summary_mismatch",
        );
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[entry(set.validators()[0].id(), &low)],
                &references,
                high.id(),
                0,
            ),
            "unreferenced_qc",
        );

        let duplicate_reference = QcReferenceV0::ordinary(low.clone());
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[entry(set.validators()[0].id(), &low)],
                &[duplicate_reference.clone(), duplicate_reference],
                low.id(),
                0,
            ),
            "duplicate_reference",
        );

        references.reverse();
        assert_code(
            validate_timeout_relations(
                View::new(9),
                &[
                    entry(set.validators()[0].id(), &low),
                    entry(set.validators()[1].id(), &high),
                ],
                &references,
                high.id(),
                0,
            ),
            "noncanonical_reference_order",
        );
    }

    #[test]
    fn body_kernel_exact_decoders_round_trip_and_reject_inexact_roots() {
        fn assert_boundaries<T, F>(raw: &[u8], mut decode: F)
        where
            F: FnMut(&[u8]) -> DecodeResult<T>,
        {
            for prefix_length in 0..raw.len() {
                let error = decode(&raw[..prefix_length])
                    .err()
                    .expect("every incomplete canonical prefix must fail");
                assert_eq!(error.code(), DecodeErrorCode::UnexpectedEof);
                assert_eq!(error.byte_offset(), prefix_length);
            }
            let mut trailing = raw.to_vec();
            trailing.push(0);
            let error = decode(&trailing)
                .err()
                .expect("an exact decoder must reject trailing bytes");
            assert_eq!(error.code(), DecodeErrorCode::TrailingBytes);
            assert_eq!(error.byte_offset(), raw.len());
        }

        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let payload = ApplicationPayloadV0::new(vec![vec![], vec![0, 1, 2, 255]]).unwrap();
        let payload_raw = payload.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_application_payload_v0_exact(&payload_raw, &parameters).unwrap(),
            payload
        );
        assert_boundaries(&payload_raw, |bytes| {
            decode_application_payload_v0_exact(bytes, &parameters)
        });

        let receipt = ExecutionReceiptCommitmentV0::for_transaction(
            &payload,
            1,
            21_000,
            777,
            vec![ExecutionEventV0::new(
                b"transfer".to_vec(),
                vec![
                    ExecutionEventAttributeV0::new(b"from".to_vec(), b"alice".to_vec()).unwrap(),
                    ExecutionEventAttributeV0::new(b"to".to_vec(), b"bob".to_vec()).unwrap(),
                ],
            )
            .unwrap()],
        )
        .unwrap();
        let receipt_raw = receipt.try_cev0_bytes().unwrap();
        assert_eq!(
            decode_execution_receipt_commitment_v0_exact(&receipt_raw, &parameters).unwrap(),
            receipt
        );
        assert_boundaries(&receipt_raw, |bytes| {
            decode_execution_receipt_commitment_v0_exact(bytes, &parameters)
        });

        let set = sample_set();
        let context = CommonConsensusContextV0::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            set.id(),
            View::new(2),
            MessageKind::Vote,
        )
        .unwrap();
        let evidence = DoubleVoteEvidenceV0::new(
            VoteEvidenceRecordV0::new(
                context,
                Height::new(9),
                BlockId::new([31; 32]),
                set.validators()[2].id(),
                Signature64::from_array([41; 64]),
            )
            .unwrap(),
            VoteEvidenceRecordV0::new(
                context,
                Height::new(9),
                BlockId::new([32; 32]),
                set.validators()[2].id(),
                Signature64::from_array([42; 64]),
            )
            .unwrap(),
        )
        .unwrap();
        let evidence_raw = evidence.try_cev0_bytes().unwrap();
        let decoded = decode_double_vote_evidence_v0_exact(&evidence_raw, &set).unwrap();
        assert_eq!(decoded, evidence);
        decoded.verify(&set, &AcceptSignatures).unwrap();
        assert_boundaries(&evidence_raw, |bytes| {
            decode_double_vote_evidence_v0_exact(bytes, &set)
        });
    }

    #[test]
    fn staged_application_payload_decode_preserves_root_material_past_block_limit() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_block_bytes = 12;
        fields.max_consensus_message_bytes = 64;
        let parameters = ConsensusParametersV0::new(fields).unwrap();
        let payload = ApplicationPayloadV0::new(vec![vec![0xa5; 9]]).unwrap();
        let bytes = payload.try_cev0_bytes().unwrap();
        assert_eq!(bytes.len(), 17);

        let legacy_error = decode_application_payload_v0_exact(&bytes, &parameters).unwrap_err();
        assert_eq!(legacy_error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(legacy_error.byte_offset(), 0);

        let staged =
            decode_application_payload_v0_exact_for_root_binding(&bytes, &parameters).unwrap();
        assert_eq!(staged, payload);
        assert_eq!(
            staged.payload_root().unwrap(),
            payload.payload_root().unwrap()
        );

        let mut trailing = bytes;
        trailing.push(0);
        let trailing_error =
            decode_application_payload_v0_exact_for_root_binding(&trailing, &parameters)
                .unwrap_err();
        assert_eq!(trailing_error.code(), DecodeErrorCode::TrailingBytes);
        assert_eq!(trailing_error.byte_offset(), 17);
    }

    #[test]
    fn staged_application_payload_decode_retains_authenticated_message_bound() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_block_bytes = 12;
        fields.max_consensus_message_bytes = 20;
        let parameters = ConsensusParametersV0::new(fields).unwrap();

        let error = decode_application_payload_v0_exact_for_root_binding(&[0; 21], &parameters)
            .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(error.byte_offset(), 0);

        let declared_count_without_items = 2u32.to_be_bytes();
        let short_error = decode_application_payload_v0_exact_for_root_binding(
            &declared_count_without_items,
            &parameters,
        )
        .unwrap_err();
        assert_eq!(short_error.code(), DecodeErrorCode::CountLimitExceeded);
        assert_eq!(short_error.byte_offset(), 0);
    }

    #[test]
    fn admission_budget_rejects_root_before_any_decode_work() {
        let budget = Cev0AdmissionBudgetV0::new(8, 16);
        let error = budget.admit_root_bytes(9).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(error.byte_offset(), 0);
    }

    #[test]
    fn admission_budget_explicit_limits_cannot_widen_intrinsic_caps() {
        let budget = Cev0AdmissionBudgetV0::with_limits(usize::MAX, usize::MAX, usize::MAX);
        assert_eq!(budget.maximum_root_bytes(), MAX_CEV0_ROOT_BYTES_V0);
        assert_eq!(
            budget.maximum_signature_work(),
            MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0
        );
        assert_eq!(
            budget.maximum_tc_aggregate_signature_shares(),
            MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
        );

        let default_tc = Cev0AdmissionBudgetV0::new(usize::MAX, usize::MAX);
        assert_eq!(default_tc.maximum_root_bytes(), MAX_CEV0_ROOT_BYTES_V0);
        assert_eq!(
            default_tc.maximum_signature_work(),
            MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0
        );
        assert_eq!(
            default_tc.maximum_tc_aggregate_signature_shares(),
            MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0
        );
    }

    #[test]
    fn admission_budget_default_tc_ceiling_matches_intrinsic_cap() {
        let budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert_eq!(
            budget.maximum_tc_aggregate_signature_shares(),
            MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
        );
        assert_eq!(
            budget.maximum_signature_work(),
            MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0
        );

        let set = sample_set();
        let tc = sample_tc(&set);
        let mut constrained = Cev0AdmissionBudgetV0::with_limits(4096, 128, 1);
        let error = constrained.charge_timeout_certificate(&tc).unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::AggregateLimitExceeded);
        assert_eq!(constrained.signature_work(), 0);
    }

    #[test]
    fn finality_budget_charges_all_three_headers_atomically() {
        let (set, parameters, genesis_timestamp_ms, proof) = trusted_genesis_finality_fixture();
        let bytes = proof.try_cev0_bytes().unwrap();

        let mut accepted = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(
            &bytes,
            &set,
            &parameters,
            genesis_timestamp_ms,
            &mut accepted,
        )
        .unwrap();
        assert_eq!(decoded, proof);
        assert!(accepted.signature_work() > 0);

        // The proof is fully shape/semantic-checked before this aggregate
        // charge. A too-small budget must reject without charging the first
        // header's shares and thereby making retries order-dependent.
        let mut constrained = Cev0AdmissionBudgetV0::with_limits(bytes.len(), 1, 1);
        let error = decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(
            &bytes,
            &set,
            &parameters,
            genesis_timestamp_ms,
            &mut constrained,
        )
        .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::AggregateLimitExceeded);
        assert_eq!(constrained.signature_work(), 0);

        let mut too_large = Cev0AdmissionBudgetV0::with_limits(bytes.len() - 1, usize::MAX, 1);
        let error = decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(
            &bytes,
            &set,
            &parameters,
            genesis_timestamp_ms,
            &mut too_large,
        )
        .unwrap_err();
        assert_eq!(error.code(), DecodeErrorCode::LengthLimitExceeded);
        assert_eq!(too_large.signature_work(), 0);
    }
}
