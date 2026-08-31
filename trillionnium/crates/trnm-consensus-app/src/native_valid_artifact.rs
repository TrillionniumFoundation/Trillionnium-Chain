//! Canonical durable `Valid` artifact and callback records.
//!
//! The records in this module are inert application facts.  Decoding and
//! rebinding them never recreate `ValidatedBlockCommitmentsV0`, a Core input,
//! a JMT apply capability, or permission to advance an application head.

use std::{collections::BTreeMap, error::Error, fmt};

use jmt::{storage::TreeReader, RootHash};
use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
use trnm_consensus_types::{
    decode_execution_receipt_commitment_v0_exact, ApplicationPayloadV0, BlockId,
    ConsensusParametersV0, ExecutionReceiptsV0, View,
};
use trnm_finality_types::hash_domain;

use crate::{
    auth_tree::{
        durable_plan::{
            revalidate_durable_jmt_plan_commitment_v0, DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0,
        },
        stored_object_key, stored_object_key_preimage, validator_state_key, AuthWrite,
        AuthenticatedObjectRecord, MAX_AUTH_KEY_PREIMAGE_BYTES,
    },
    native_validation_artifact::NativeValidationArtifactIdentityV0,
    poco_snapshot::{
        decode_poco_snapshot_physical_key_v0_exact, PocoSnapshotEntryKindV0,
        PocoSnapshotManifestV0, PocoSnapshotPhysicalKeyV0, MAX_POCO_SNAPSHOT_ENTRIES,
    },
    poco_transition::{decode_poco_snapshot_value_v0_exact, VerifiedPocoSnapshotValueV0},
    validator_lifecycle::{ValidatorLifecycleStateV1, VALIDATOR_LIFECYCLE_SCHEMA_V1},
    StoredObject,
};

pub(crate) const DURABLE_VALID_ARTIFACT_CODEC_V0: &str = "trnm.native-validation.valid-artifact.v0";
pub(crate) const DURABLE_VALID_CALLBACK_CODEC_V0: &str = "trnm.native-validation.valid-callback.v0";

const DURABLE_VALID_ARTIFACT_CODEC_VERSION_V0: u16 = 0;
const DURABLE_VALID_CALLBACK_CODEC_VERSION_V0: u16 = 0;
const DURABLE_VALID_OUTBOX_ROW_CODEC_VERSION_V0: u16 = 0;
const DURABLE_VALID_RESULT_KIND_V0: u8 = 0;
const DURABLE_VALID_DELIVERY_ATTEMPT_V0: u64 = 0;

pub(crate) const DURABLE_VALID_CALLBACK_BYTES_V0: usize = 84;
pub(crate) const MAX_DURABLE_VALID_RECEIPTS_BYTES_V0: usize = 4 * 1024 * 1024;
pub(crate) const MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0: usize = 4 * 1024 * 1024;
pub(crate) const MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0: usize = 56 * 1024 * 1024;
const MAX_DURABLE_VALID_WRITE_VALUE_BYTES_V0: usize = 16 * 1024 * 1024;
const MAX_DURABLE_VALID_COMMAND_ID_BYTES_V0: usize = 160;
const MAX_DURABLE_VALID_SIGNER_ID_BYTES_V0: usize = 256;
const MAX_DURABLE_VALID_TRANSACTION_COUNT_V0: usize = 65_536;
const MAX_DURABLE_VALID_WRITE_COUNT_V0: usize = 65_536;
const DURABLE_VALID_ARTIFACT_FIXED_AND_FRAME_BUDGET_V0: usize = 64 * 1024;
const DURABLE_VALID_ARTIFACT_FIXED_BYTES_V0: usize = 396;

/// The replay index and canonical write recipe share one 56 MiB inert domain
/// delta budget.  The physical JMT plan is represented by one fixed streaming
/// commitment, so artifact capacity no longer depends on an unproved bound on
/// physical JMT node amplification.
pub(crate) const MAX_DURABLE_VALID_ARTIFACT_BYTES_V0: usize = MAX_DURABLE_VALID_RECEIPTS_BYTES_V0
    + MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0
    + DURABLE_VALID_ARTIFACT_FIXED_AND_FRAME_BUDGET_V0;

const DURABLE_VALID_ARTIFACT_DOMAIN_V0: &str = "trnm.consensus-app.valid-validation-artifact.v0";
const DURABLE_VALID_CALLBACK_PAYLOAD_DOMAIN_V0: &str =
    "trnm.consensus-app.valid-validation-callback-payload.v0";
const DURABLE_VALID_CALLBACK_IDEMPOTENCY_DOMAIN_V0: &str =
    "trnm.consensus-app.valid-validation-callback-idempotency.v0";
const DURABLE_VALID_CALLBACK_OUTBOX_ROW_DOMAIN_V0: &str =
    "trnm.consensus-app.valid-validation-callback-outbox-row.v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableValidArtifactFactsV0 {
    target_height: u64,
    parent_height: u64,
    parent_block_id: BlockId,
    parent_state_version: u64,
    parent_state_root: [u8; 32],
    payload_root: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    evidence_root: [u8; 32],
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
}

impl DurableValidArtifactFactsV0 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new_v0(
        target_height: u64,
        parent_height: u64,
        parent_block_id: BlockId,
        parent_state_version: u64,
        parent_state_root: [u8; 32],
        payload_root: [u8; 32],
        state_root: [u8; 32],
        receipts_root: [u8; 32],
        evidence_root: [u8; 32],
        logical_block_size: u64,
        transaction_count: u32,
        evidence_count: u32,
    ) -> Self {
        Self {
            target_height,
            parent_height,
            parent_block_id,
            parent_state_version,
            parent_state_root,
            payload_root,
            state_root,
            receipts_root,
            evidence_root,
            logical_block_size,
            transaction_count,
            evidence_count,
        }
    }

    pub(crate) const fn target_height(self) -> u64 {
        self.target_height
    }

    pub(crate) const fn parent_height(self) -> u64 {
        self.parent_height
    }

    pub(crate) const fn parent_block_id(self) -> BlockId {
        self.parent_block_id
    }

    pub(crate) const fn parent_state_version(self) -> u64 {
        self.parent_state_version
    }

    pub(crate) const fn parent_state_root(self) -> [u8; 32] {
        self.parent_state_root
    }

    pub(crate) const fn payload_root(self) -> [u8; 32] {
        self.payload_root
    }

    pub(crate) const fn state_root(self) -> [u8; 32] {
        self.state_root
    }

    pub(crate) const fn receipts_root(self) -> [u8; 32] {
        self.receipts_root
    }

    pub(crate) const fn evidence_root(self) -> [u8; 32] {
        self.evidence_root
    }

    pub(crate) const fn logical_block_size(self) -> u64 {
        self.logical_block_size
    }

    pub(crate) const fn transaction_count(self) -> u32 {
        self.transaction_count
    }

    pub(crate) const fn evidence_count(self) -> u32 {
        self.evidence_count
    }
}

pub(crate) struct DurableValidArtifactInputV0<'a> {
    pub(crate) identity: NativeValidationArtifactIdentityV0,
    pub(crate) facts: DurableValidArtifactFactsV0,
    pub(crate) command_ids: &'a [String],
    pub(crate) signer_nonces: &'a [(String, u64)],
    pub(crate) receipts_cev0: &'a [u8],
    pub(crate) writes: &'a [AuthWrite],
    pub(crate) durable_plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableValidSignerNonceV0<'a> {
    signer_id: &'a str,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableValidObjectChangeV0 {
    object: StoredObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DurableValidPocoChangeV0 {
    Manifest(PocoSnapshotManifestV0),
    Entry {
        kind: PocoSnapshotEntryKindV0,
        logical_key: Box<[u8]>,
        value: Option<VerifiedPocoSnapshotValueV0>,
    },
}

impl DurableValidObjectChangeV0 {
    pub(crate) const fn object(&self) -> &StoredObject {
        &self.object
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableValidDomainDeltaV0 {
    objects: Box<[DurableValidObjectChangeV0]>,
    validator_lifecycle: Option<ValidatorLifecycleStateV1>,
    poco_changes: Box<[DurableValidPocoChangeV0]>,
    replay_count: usize,
}

impl DurableValidDomainDeltaV0 {
    pub(crate) fn objects(&self) -> &[DurableValidObjectChangeV0] {
        &self.objects
    }

    pub(crate) const fn validator_lifecycle(&self) -> Option<&ValidatorLifecycleStateV1> {
        self.validator_lifecycle.as_ref()
    }

    pub(crate) fn poco_changes(&self) -> &[DurableValidPocoChangeV0] {
        &self.poco_changes
    }

    pub(crate) const fn replay_count(&self) -> usize {
        self.replay_count
    }
}

impl DurableValidSignerNonceV0<'_> {
    pub(crate) fn signer_id(&self) -> &str {
        self.signer_id
    }

    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableValidAuthWriteV0<'a> {
    key: &'a [u8],
    value: Option<&'a [u8]>,
}

impl DurableValidAuthWriteV0<'_> {
    pub(crate) fn key(&self) -> &[u8] {
        self.key
    }

    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableValidRecordKindV0 {
    Artifact,
    Callback,
}

impl fmt::Display for DurableValidRecordKindV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Artifact => "valid artifact",
            Self::Callback => "valid callback",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DurableValidCodecErrorV0 {
    UnsupportedCodec(DurableValidRecordKindV0),
    TooLarge {
        record: DurableValidRecordKindV0,
        maximum: usize,
        actual: usize,
    },
    AllocationFailed(DurableValidRecordKindV0),
    WrongLength {
        record: DurableValidRecordKindV0,
        expected: usize,
        actual: usize,
    },
    UnsupportedVersion {
        record: DurableValidRecordKindV0,
        version: u16,
    },
    UnknownRoute {
        record: DurableValidRecordKindV0,
        route: u8,
    },
    UnknownResultKind {
        record: DurableValidRecordKindV0,
        result_kind: u8,
    },
    Truncated(DurableValidRecordKindV0),
    TrailingBytes(DurableValidRecordKindV0),
    NonCanonical(DurableValidRecordKindV0),
    InvalidFacts,
    InvalidReplayIndex,
    InvalidDomainDelta,
    InvalidWriteRecipe,
    InvalidDurablePlan,
}

impl fmt::Display for DurableValidCodecErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCodec(record) => write!(formatter, "unsupported {record} codec"),
            Self::TooLarge {
                record,
                maximum,
                actual,
            } => write!(
                formatter,
                "{record} has {actual} bytes; maximum is {maximum}"
            ),
            Self::AllocationFailed(record) => {
                write!(formatter, "cannot reserve memory for {record}")
            }
            Self::WrongLength {
                record,
                expected,
                actual,
            } => write!(
                formatter,
                "{record} has {actual} bytes; expected {expected}"
            ),
            Self::UnsupportedVersion { record, version } => {
                write!(formatter, "unsupported {record} version {version}")
            }
            Self::UnknownRoute { record, route } => {
                write!(formatter, "unknown {record} route {route}")
            }
            Self::UnknownResultKind {
                record,
                result_kind,
            } => write!(formatter, "unknown {record} result kind {result_kind}"),
            Self::Truncated(record) => write!(formatter, "truncated {record}"),
            Self::TrailingBytes(record) => write!(formatter, "trailing bytes in {record}"),
            Self::NonCanonical(record) => write!(formatter, "non-canonical {record}"),
            Self::InvalidFacts => formatter.write_str("invalid valid-artifact facts"),
            Self::InvalidReplayIndex => {
                formatter.write_str("invalid valid-artifact command/nonce replay index")
            }
            Self::InvalidDomainDelta => {
                formatter.write_str("invalid valid-artifact typed domain delta")
            }
            Self::InvalidWriteRecipe => formatter.write_str("invalid valid-artifact write recipe"),
            Self::InvalidDurablePlan => formatter.write_str("invalid durable JMT plan"),
        }
    }
}

impl Error for DurableValidCodecErrorV0 {}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableValidBindingErrorV0 {
    ResultKindMismatch,
    IdentityMismatch,
    FactsMismatch,
    ArtifactChecksumMismatch,
    CallbackArtifactChecksumMismatch,
    CallbackPayloadChecksumMismatch,
    CallbackIdempotencyKeyMismatch,
    CallbackOutboxChecksumMismatch,
    DeliveryAttemptMismatch,
}

impl fmt::Display for DurableValidBindingErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResultKindMismatch => "valid result kind mismatch",
            Self::IdentityMismatch => "valid artifact identity mismatch",
            Self::FactsMismatch => "valid artifact facts mismatch",
            Self::ArtifactChecksumMismatch => "valid artifact checksum mismatch",
            Self::CallbackArtifactChecksumMismatch => "valid callback artifact checksum mismatch",
            Self::CallbackPayloadChecksumMismatch => "valid callback payload checksum mismatch",
            Self::CallbackIdempotencyKeyMismatch => "valid callback idempotency mismatch",
            Self::CallbackOutboxChecksumMismatch => "valid callback outbox mismatch",
            Self::DeliveryAttemptMismatch => "valid callback delivery attempt mismatch",
        })
    }
}

impl Error for DurableValidBindingErrorV0 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DurableValidRecordErrorV0 {
    Codec(DurableValidCodecErrorV0),
    Binding(DurableValidBindingErrorV0),
}

impl fmt::Display for DurableValidRecordErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => fmt::Display::fmt(error, formatter),
            Self::Binding(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for DurableValidRecordErrorV0 {}

impl From<DurableValidCodecErrorV0> for DurableValidRecordErrorV0 {
    fn from(error: DurableValidCodecErrorV0) -> Self {
        Self::Codec(error)
    }
}

impl From<DurableValidBindingErrorV0> for DurableValidRecordErrorV0 {
    fn from(error: DurableValidBindingErrorV0) -> Self {
        Self::Binding(error)
    }
}

#[derive(Debug)]
pub(crate) struct PreparedDurableValidArtifactRecordV0 {
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
    encoded: Vec<u8>,
    checksum: [u8; 32],
}

impl PreparedDurableValidArtifactRecordV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn facts(&self) -> DurableValidArtifactFactsV0 {
        self.facts
    }

    pub(crate) const fn artifact_codec(&self) -> &'static str {
        DURABLE_VALID_ARTIFACT_CODEC_V0
    }

    pub(crate) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub(crate) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}

#[derive(Debug)]
pub(crate) struct UnverifiedDurableValidArtifactV0<'a> {
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
    command_ids: Vec<&'a str>,
    signer_nonces: Vec<DurableValidSignerNonceV0<'a>>,
    receipts_cev0: &'a [u8],
    writes: Vec<DurableValidAuthWriteV0<'a>>,
    durable_plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    checksum: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct RevalidatedDurableValidArtifactV0<'a> {
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
    command_ids: Vec<&'a str>,
    signer_nonces: Vec<DurableValidSignerNonceV0<'a>>,
    receipts_cev0: &'a [u8],
    writes: Vec<DurableValidAuthWriteV0<'a>>,
    durable_plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
    checksum: [u8; 32],
}

impl<'a> UnverifiedDurableValidArtifactV0<'a> {
    pub(crate) fn revalidate_v0(
        self,
        expected_identity: NativeValidationArtifactIdentityV0,
        expected_facts: DurableValidArtifactFactsV0,
        stored_result_kind: u8,
        stored_checksum: [u8; 32],
    ) -> Result<RevalidatedDurableValidArtifactV0<'a>, DurableValidBindingErrorV0> {
        if stored_result_kind != DURABLE_VALID_RESULT_KIND_V0 {
            return Err(DurableValidBindingErrorV0::ResultKindMismatch);
        }
        if self.identity != expected_identity {
            return Err(DurableValidBindingErrorV0::IdentityMismatch);
        }
        if self.facts != expected_facts {
            return Err(DurableValidBindingErrorV0::FactsMismatch);
        }
        if self.checksum != stored_checksum {
            return Err(DurableValidBindingErrorV0::ArtifactChecksumMismatch);
        }
        Ok(RevalidatedDurableValidArtifactV0 {
            identity: self.identity,
            facts: self.facts,
            command_ids: self.command_ids,
            signer_nonces: self.signer_nonces,
            receipts_cev0: self.receipts_cev0,
            writes: self.writes,
            durable_plan_commitment: self.durable_plan_commitment,
            checksum: self.checksum,
        })
    }
}

impl RevalidatedDurableValidArtifactV0<'_> {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn facts(&self) -> DurableValidArtifactFactsV0 {
        self.facts
    }

    pub(crate) fn command_ids(&self) -> &[&str] {
        &self.command_ids
    }

    pub(crate) fn signer_nonces(&self) -> &[DurableValidSignerNonceV0<'_>] {
        &self.signer_nonces
    }

    pub(crate) fn receipts_cev0(&self) -> &[u8] {
        self.receipts_cev0
    }

    pub(crate) fn writes(&self) -> &[DurableValidAuthWriteV0<'_>] {
        &self.writes
    }

    pub(crate) const fn durable_plan_commitment(
        &self,
    ) -> [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0] {
        self.durable_plan_commitment
    }

    pub(crate) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }

    /// Reconstructs closed, read-only domain facts from the canonical raw
    /// recipe.  This deliberately returns neither `AuthWrite` nor an
    /// apply-capable application delta: it is a semantic corruption check for
    /// the sealed artifact, not promotion authority.
    pub(crate) fn revalidate_domain_delta_v0(
        &self,
    ) -> Result<DurableValidDomainDeltaV0, DurableValidCodecErrorV0> {
        revalidate_domain_write_views_v0(
            self.facts,
            self.command_ids.len(),
            self.writes.iter().map(|write| (write.key(), write.value())),
        )
    }

    /// Rebuilds the canonical receipt list against the exact retained payload
    /// and active parameters.  This returns inert receipt commitments only;
    /// it does not recreate runtime provenance or validation authority.
    pub(crate) fn revalidate_receipts_v0(
        &self,
        payload: &ApplicationPayloadV0,
        parameters: &ConsensusParametersV0,
    ) -> Result<ExecutionReceiptsV0, DurableValidCodecErrorV0> {
        if payload.transaction_count() != self.facts.transaction_count()
            || payload
                .payload_root()
                .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?
                .as_bytes()
                != &self.facts.payload_root()
        {
            return Err(DurableValidCodecErrorV0::InvalidFacts);
        }
        let maximum_receipt_bytes = usize::try_from(parameters.max_block_bytes())
            .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?;
        let mut decoder =
            ExactValidRecordDecoderV0::new(self.receipts_cev0, DurableValidRecordKindV0::Artifact);
        let receipt_count = usize::try_from(decoder.read_u32_v0()?)
            .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?;
        if receipt_count != usize::try_from(self.facts.transaction_count()).unwrap_or(usize::MAX)
            || receipt_count > decoder.remaining_len_v0() / 4
        {
            return Err(DurableValidCodecErrorV0::InvalidFacts);
        }
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(receipt_count).map_err(|_| {
            DurableValidCodecErrorV0::AllocationFailed(DurableValidRecordKindV0::Artifact)
        })?;
        for _ in 0..receipt_count {
            let encoded = decoder.read_u32_framed_v0(maximum_receipt_bytes)?;
            receipts.push(
                decode_execution_receipt_commitment_v0_exact(encoded, parameters)
                    .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?,
            );
        }
        decoder.finish_v0()?;
        let receipts = ExecutionReceiptsV0::new(payload, receipts)
            .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?;
        if receipts
            .try_cev0_bytes()
            .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?
            .as_slice()
            != self.receipts_cev0
            || receipts
                .receipts_root()
                .map_err(|_| DurableValidCodecErrorV0::InvalidFacts)?
                .as_bytes()
                != &self.facts.receipts_root()
        {
            return Err(DurableValidCodecErrorV0::InvalidFacts);
        }
        Ok(receipts)
    }

    /// Replans against the authenticated parent and canonical recipe retained
    /// by this artifact. Success requires both the exact resulting root and the
    /// streaming commitment of every physical JMT field to match. The fresh
    /// plan is dropped and no apply authority is released.
    pub(crate) fn revalidate_durable_plan_v0<R: TreeReader>(
        &self,
        reader: &R,
    ) -> Result<(), DurableValidCodecErrorV0> {
        revalidate_durable_jmt_plan_commitment_v0(
            reader,
            self.facts.target_height(),
            Some(RootHash(self.facts.parent_state_root())),
            RootHash(self.facts.state_root()),
            self.durable_plan_commitment,
            self.writes.iter().map(|write| (write.key(), write.value())),
        )
        .map_err(|_| DurableValidCodecErrorV0::InvalidDurablePlan)?;
        Ok(())
    }
}

pub(crate) fn durable_valid_result_kind_v0() -> u8 {
    DURABLE_VALID_RESULT_KIND_V0
}

pub(crate) fn prepare_durable_valid_artifact_v0(
    input: DurableValidArtifactInputV0<'_>,
) -> Result<PreparedDurableValidArtifactRecordV0, DurableValidCodecErrorV0> {
    validate_facts_v0(input.identity, input.facts)?;
    validate_replay_index_v0(input.facts, input.command_ids, input.signer_nonces)?;
    validate_write_recipe_v0(input.writes)?;
    revalidate_domain_write_views_v0(
        input.facts,
        input.command_ids.len(),
        input
            .writes
            .iter()
            .map(|write| (write.key(), write.value())),
    )?;
    validate_component_bounds_v0(
        input.command_ids,
        input.signer_nonces,
        input.receipts_cev0,
        input.writes,
    )?;
    let encoded = encode_artifact_v0(
        input.identity,
        input.facts,
        input.command_ids,
        input.signer_nonces,
        input.receipts_cev0,
        input.writes,
        input.durable_plan_commitment,
    )?;
    let checksum = hash_domain(DURABLE_VALID_ARTIFACT_DOMAIN_V0, &[&encoded]);
    Ok(PreparedDurableValidArtifactRecordV0 {
        identity: input.identity,
        facts: input.facts,
        encoded,
        checksum,
    })
}

pub(crate) fn decode_durable_valid_artifact_v0(
    encoded: &[u8],
) -> Result<UnverifiedDurableValidArtifactV0<'_>, DurableValidCodecErrorV0> {
    let record = DurableValidRecordKindV0::Artifact;
    if encoded.len() > MAX_DURABLE_VALID_ARTIFACT_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record,
            maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactValidRecordDecoderV0::new(encoded, record);
    let version = decoder.read_u16_v0()?;
    if version != DURABLE_VALID_ARTIFACT_CODEC_VERSION_V0 {
        return Err(DurableValidCodecErrorV0::UnsupportedVersion { record, version });
    }
    let route = decode_route_v0(decoder.read_u8_v0()?, record)?;
    let validation_id = ValidationId::new(
        BlockId::new(decoder.read_array_v0()?),
        View::new(decoder.read_u64_v0()?),
        decoder.read_u64_v0()?,
    );
    let identity = NativeValidationArtifactIdentityV0::new_v0(
        route,
        validation_id,
        decoder.read_array_v0()?,
        decoder.read_array_v0()?,
    );
    let result_kind = decoder.read_u8_v0()?;
    if result_kind != DURABLE_VALID_RESULT_KIND_V0 {
        return Err(DurableValidCodecErrorV0::UnknownResultKind {
            record,
            result_kind,
        });
    }
    let facts = DurableValidArtifactFactsV0::new_v0(
        decoder.read_u64_v0()?,
        decoder.read_u64_v0()?,
        BlockId::new(decoder.read_array_v0()?),
        decoder.read_u64_v0()?,
        decoder.read_array_v0()?,
        decoder.read_array_v0()?,
        decoder.read_array_v0()?,
        decoder.read_array_v0()?,
        decoder.read_array_v0()?,
        decoder.read_u64_v0()?,
        decoder.read_u32_v0()?,
        decoder.read_u32_v0()?,
    );
    validate_facts_v0(identity, facts)?;
    let replay_start = decoder.remaining_len_v0();
    let command_count = usize::try_from(decoder.read_u32_v0()?)
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    let expected_transaction_count = usize::try_from(facts.transaction_count())
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    if command_count != expected_transaction_count
        || command_count > MAX_DURABLE_VALID_TRANSACTION_COUNT_V0
        || command_count > decoder.remaining_len_v0() / 4
    {
        return Err(DurableValidCodecErrorV0::InvalidReplayIndex);
    }
    let mut command_ids = Vec::new();
    command_ids
        .try_reserve_exact(command_count)
        .map_err(|_| DurableValidCodecErrorV0::AllocationFailed(record))?;
    for _ in 0..command_count {
        let command_id = decoder.read_u32_framed_v0(MAX_DURABLE_VALID_COMMAND_ID_BYTES_V0)?;
        command_ids.push(
            std::str::from_utf8(command_id)
                .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?,
        );
    }
    let signer_nonce_count = usize::try_from(decoder.read_u32_v0()?)
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    if signer_nonce_count != expected_transaction_count
        || signer_nonce_count > MAX_DURABLE_VALID_TRANSACTION_COUNT_V0
        || signer_nonce_count > decoder.remaining_len_v0() / 12
    {
        return Err(DurableValidCodecErrorV0::InvalidReplayIndex);
    }
    let mut signer_nonces = Vec::new();
    signer_nonces
        .try_reserve_exact(signer_nonce_count)
        .map_err(|_| DurableValidCodecErrorV0::AllocationFailed(record))?;
    for _ in 0..signer_nonce_count {
        let signer_id = decoder.read_u32_framed_v0(MAX_DURABLE_VALID_SIGNER_ID_BYTES_V0)?;
        signer_nonces.push(DurableValidSignerNonceV0 {
            signer_id: std::str::from_utf8(signer_id)
                .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?,
            nonce: decoder.read_u64_v0()?,
        });
    }
    let replay_bytes = replay_start
        .checked_sub(decoder.remaining_len_v0())
        .ok_or(DurableValidCodecErrorV0::InvalidReplayIndex)?;
    if replay_bytes > MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record,
            maximum: MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0,
            actual: replay_bytes,
        });
    }
    validate_decoded_replay_index_v0(facts, &command_ids, &signer_nonces)?;
    let receipts_cev0 = decoder.read_u32_framed_v0(MAX_DURABLE_VALID_RECEIPTS_BYTES_V0)?;
    let write_count = usize::try_from(decoder.read_u32_v0()?)
        .map_err(|_| DurableValidCodecErrorV0::InvalidWriteRecipe)?;
    if write_count > MAX_DURABLE_VALID_WRITE_COUNT_V0
        || write_count > decoder.remaining_len_v0() / 6
    {
        return Err(DurableValidCodecErrorV0::InvalidWriteRecipe);
    }
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(write_count)
        .map_err(|_| DurableValidCodecErrorV0::AllocationFailed(record))?;
    for _ in 0..write_count {
        let key = decoder.read_u32_framed_v0(MAX_AUTH_KEY_PREIMAGE_BYTES)?;
        let value = match decoder.read_u8_v0()? {
            0 => None,
            1 => Some(decoder.read_u32_framed_v0(MAX_DURABLE_VALID_WRITE_VALUE_BYTES_V0)?),
            _ => return Err(DurableValidCodecErrorV0::InvalidWriteRecipe),
        };
        writes.push(DurableValidAuthWriteV0 { key, value });
    }
    validate_decoded_write_recipe_v0(&writes)?;
    revalidate_domain_write_views_v0(
        facts,
        command_ids.len(),
        writes.iter().map(|write| (write.key(), write.value())),
    )?;
    let durable_plan_commitment = decoder.read_array_v0()?;
    decoder.finish_v0()?;
    validate_decoded_component_bounds_v0(&command_ids, &signer_nonces, receipts_cev0, &writes)?;

    let checksum = hash_domain(DURABLE_VALID_ARTIFACT_DOMAIN_V0, &[encoded]);
    Ok(UnverifiedDurableValidArtifactV0 {
        identity,
        facts,
        command_ids,
        signer_nonces,
        receipts_cev0,
        writes,
        durable_plan_commitment,
        checksum,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_durable_valid_artifact_v0<'a>(
    artifact_codec: &str,
    artifact_bytes: &'a [u8],
    artifact_checksum: [u8; 32],
    stored_result_kind: u8,
    expected_identity: NativeValidationArtifactIdentityV0,
    expected_facts: DurableValidArtifactFactsV0,
) -> Result<RevalidatedDurableValidArtifactV0<'a>, DurableValidRecordErrorV0> {
    if artifact_codec != DURABLE_VALID_ARTIFACT_CODEC_V0 {
        return Err(
            DurableValidCodecErrorV0::UnsupportedCodec(DurableValidRecordKindV0::Artifact).into(),
        );
    }
    Ok(
        decode_durable_valid_artifact_v0(artifact_bytes)?.revalidate_v0(
            expected_identity,
            expected_facts,
            stored_result_kind,
            artifact_checksum,
        )?,
    )
}

#[derive(Debug)]
pub(crate) struct PreparedDurableValidCallbackRecordV0 {
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_VALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl PreparedDurableValidCallbackRecordV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn result_kind(&self) -> u8 {
        DURABLE_VALID_RESULT_KIND_V0
    }

    pub(crate) const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub(crate) const fn payload_codec(&self) -> &'static str {
        DURABLE_VALID_CALLBACK_CODEC_V0
    }

    pub(crate) const fn payload(&self) -> &[u8; DURABLE_VALID_CALLBACK_BYTES_V0] {
        &self.payload
    }

    pub(crate) const fn payload_checksum(&self) -> [u8; 32] {
        self.payload_checksum
    }

    pub(crate) const fn idempotency_key(&self) -> [u8; 32] {
        self.idempotency_key
    }

    pub(crate) const fn delivery_attempt(&self) -> u64 {
        DURABLE_VALID_DELIVERY_ATTEMPT_V0
    }

    pub(crate) const fn outbox_checksum(&self) -> [u8; 32] {
        self.outbox_checksum
    }
}

#[derive(Debug)]
pub(crate) struct UnverifiedDurableValidCallbackV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_VALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct RevalidatedDurableValidCallbackV0 {
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_VALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl RevalidatedDurableValidCallbackV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub(crate) const fn payload(&self) -> &[u8; DURABLE_VALID_CALLBACK_BYTES_V0] {
        &self.payload
    }

    pub(crate) const fn payload_checksum(&self) -> [u8; 32] {
        self.payload_checksum
    }

    pub(crate) const fn idempotency_key(&self) -> [u8; 32] {
        self.idempotency_key
    }

    pub(crate) const fn outbox_checksum(&self) -> [u8; 32] {
        self.outbox_checksum
    }
}

impl From<PreparedDurableValidCallbackRecordV0> for RevalidatedDurableValidCallbackV0 {
    fn from(prepared: PreparedDurableValidCallbackRecordV0) -> Self {
        Self {
            identity: prepared.identity,
            artifact_checksum: prepared.artifact_checksum,
            payload: prepared.payload,
            payload_checksum: prepared.payload_checksum,
            idempotency_key: prepared.idempotency_key,
            outbox_checksum: prepared.outbox_checksum,
        }
    }
}

pub(crate) fn prepare_durable_valid_callback_v0(
    artifact: &PreparedDurableValidArtifactRecordV0,
) -> PreparedDurableValidCallbackRecordV0 {
    let identity = artifact.identity();
    let artifact_checksum = artifact.checksum();
    let payload = encode_durable_valid_callback_v0(identity, artifact_checksum);
    let payload_checksum = durable_valid_callback_payload_checksum_v0(&payload);
    let idempotency_key = durable_valid_callback_idempotency_key_v0(identity, artifact_checksum);
    let outbox_checksum = durable_valid_callback_outbox_checksum_v0(
        identity,
        artifact_checksum,
        DURABLE_VALID_CALLBACK_CODEC_V0,
        payload_checksum,
        idempotency_key,
        DURABLE_VALID_DELIVERY_ATTEMPT_V0,
    );
    PreparedDurableValidCallbackRecordV0 {
        identity,
        artifact_checksum,
        payload,
        payload_checksum,
        idempotency_key,
        outbox_checksum,
    }
}

pub(crate) fn decode_durable_valid_callback_v0(
    encoded: &[u8],
) -> Result<UnverifiedDurableValidCallbackV0, DurableValidCodecErrorV0> {
    let record = DurableValidRecordKindV0::Callback;
    if encoded.len() != DURABLE_VALID_CALLBACK_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::WrongLength {
            record,
            expected: DURABLE_VALID_CALLBACK_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactValidRecordDecoderV0::new(encoded, record);
    let version = decoder.read_u16_v0()?;
    if version != DURABLE_VALID_CALLBACK_CODEC_VERSION_V0 {
        return Err(DurableValidCodecErrorV0::UnsupportedVersion { record, version });
    }
    let route = decode_route_v0(decoder.read_u8_v0()?, record)?;
    let validation_id = ValidationId::new(
        BlockId::new(decoder.read_array_v0()?),
        View::new(decoder.read_u64_v0()?),
        decoder.read_u64_v0()?,
    );
    let result_kind = decoder.read_u8_v0()?;
    if result_kind != DURABLE_VALID_RESULT_KIND_V0 {
        return Err(DurableValidCodecErrorV0::UnknownResultKind {
            record,
            result_kind,
        });
    }
    let artifact_checksum = decoder.read_array_v0()?;
    decoder.finish_v0()?;
    let identity =
        NativeValidationArtifactIdentityV0::new_v0(route, validation_id, [0; 32], [0; 32]);
    let canonical = encode_durable_valid_callback_v0(identity, artifact_checksum);
    if canonical.as_slice() != encoded {
        return Err(DurableValidCodecErrorV0::NonCanonical(record));
    }
    Ok(UnverifiedDurableValidCallbackV0 {
        route,
        validation_id,
        artifact_checksum,
        payload: canonical,
        payload_checksum: durable_valid_callback_payload_checksum_v0(encoded),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_durable_valid_callback_v0(
    payload_codec: &str,
    payload_bytes: &[u8],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    expected_delivery_attempt: u64,
    outbox_checksum: [u8; 32],
    stored_result_kind: u8,
    stored_artifact_checksum: [u8; 32],
    expected_identity: NativeValidationArtifactIdentityV0,
) -> Result<RevalidatedDurableValidCallbackV0, DurableValidRecordErrorV0> {
    if payload_codec != DURABLE_VALID_CALLBACK_CODEC_V0 {
        return Err(
            DurableValidCodecErrorV0::UnsupportedCodec(DurableValidRecordKindV0::Callback).into(),
        );
    }
    if stored_result_kind != DURABLE_VALID_RESULT_KIND_V0 {
        return Err(DurableValidBindingErrorV0::ResultKindMismatch.into());
    }
    if delivery_attempt != expected_delivery_attempt {
        return Err(DurableValidBindingErrorV0::DeliveryAttemptMismatch.into());
    }
    let unverified = decode_durable_valid_callback_v0(payload_bytes)?;
    if unverified.route != expected_identity.route()
        || unverified.validation_id != expected_identity.validation_id()
    {
        return Err(DurableValidBindingErrorV0::IdentityMismatch.into());
    }
    if unverified.artifact_checksum != stored_artifact_checksum {
        return Err(DurableValidBindingErrorV0::CallbackArtifactChecksumMismatch.into());
    }
    if unverified.payload_checksum != payload_checksum {
        return Err(DurableValidBindingErrorV0::CallbackPayloadChecksumMismatch.into());
    }
    let expected_idempotency =
        durable_valid_callback_idempotency_key_v0(expected_identity, stored_artifact_checksum);
    if idempotency_key != expected_idempotency {
        return Err(DurableValidBindingErrorV0::CallbackIdempotencyKeyMismatch.into());
    }
    let expected_outbox = durable_valid_callback_outbox_checksum_v0(
        expected_identity,
        stored_artifact_checksum,
        payload_codec,
        payload_checksum,
        idempotency_key,
        delivery_attempt,
    );
    if outbox_checksum != expected_outbox {
        return Err(DurableValidBindingErrorV0::CallbackOutboxChecksumMismatch.into());
    }
    Ok(RevalidatedDurableValidCallbackV0 {
        identity: expected_identity,
        artifact_checksum: stored_artifact_checksum,
        payload: unverified.payload,
        payload_checksum,
        idempotency_key,
        outbox_checksum,
    })
}

pub(crate) fn durable_valid_callback_payload_checksum_for_identity_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
) -> [u8; 32] {
    durable_valid_callback_payload_checksum_v0(&encode_durable_valid_callback_v0(
        identity,
        artifact_checksum,
    ))
}

pub(crate) fn durable_valid_callback_idempotency_key_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
) -> [u8; 32] {
    let validation_id = identity.validation_id();
    let route = [route_code_v0(identity.route())];
    let view = validation_id.view().get().to_be_bytes();
    let generation = validation_id.generation().to_be_bytes();
    let result = [DURABLE_VALID_RESULT_KIND_V0];
    hash_domain(
        DURABLE_VALID_CALLBACK_IDEMPOTENCY_DOMAIN_V0,
        &[
            &route,
            validation_id.block_id().as_bytes(),
            &view,
            &generation,
            &result,
            &artifact_checksum,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn durable_valid_callback_outbox_checksum_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload_codec: &str,
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
) -> [u8; 32] {
    let validation_id = identity.validation_id();
    let codec_version = DURABLE_VALID_OUTBOX_ROW_CODEC_VERSION_V0.to_be_bytes();
    let route = [route_code_v0(identity.route())];
    let view = validation_id.view().get().to_be_bytes();
    let generation = validation_id.generation().to_be_bytes();
    let result = [DURABLE_VALID_RESULT_KIND_V0];
    let delivery_attempt = delivery_attempt.to_be_bytes();
    hash_domain(
        DURABLE_VALID_CALLBACK_OUTBOX_ROW_DOMAIN_V0,
        &[
            &codec_version,
            &route,
            validation_id.block_id().as_bytes(),
            &view,
            &generation,
            &result,
            &artifact_checksum,
            payload_codec.as_bytes(),
            &payload_checksum,
            &idempotency_key,
            &delivery_attempt,
        ],
    )
}

fn validate_facts_v0(
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
) -> Result<(), DurableValidCodecErrorV0> {
    let expected_target_height = facts
        .parent_height()
        .checked_add(1)
        .ok_or(DurableValidCodecErrorV0::InvalidFacts)?;
    if facts.target_height() == 0
        || facts.target_height() != expected_target_height
        || facts.parent_state_version() != facts.parent_height()
        || identity.validation_id().block_id().is_zero()
        || !usize::try_from(facts.transaction_count())
            .is_ok_and(|count| count <= MAX_DURABLE_VALID_TRANSACTION_COUNT_V0)
    {
        return Err(DurableValidCodecErrorV0::InvalidFacts);
    }
    Ok(())
}

fn validate_write_recipe_v0(writes: &[AuthWrite]) -> Result<(), DurableValidCodecErrorV0> {
    validate_write_views_v0(writes.iter().map(|write| (write.key(), write.value())))
}

fn validate_replay_index_v0(
    facts: DurableValidArtifactFactsV0,
    command_ids: &[String],
    signer_nonces: &[(String, u64)],
) -> Result<(), DurableValidCodecErrorV0> {
    validate_replay_views_v0(
        facts,
        command_ids.iter().map(String::as_str),
        signer_nonces
            .iter()
            .map(|(signer_id, nonce)| (signer_id.as_str(), *nonce)),
    )
}

fn validate_decoded_replay_index_v0(
    facts: DurableValidArtifactFactsV0,
    command_ids: &[&str],
    signer_nonces: &[DurableValidSignerNonceV0<'_>],
) -> Result<(), DurableValidCodecErrorV0> {
    validate_replay_views_v0(
        facts,
        command_ids.iter().copied(),
        signer_nonces
            .iter()
            .map(|entry| (entry.signer_id(), entry.nonce())),
    )
}

fn validate_replay_views_v0<'a>(
    facts: DurableValidArtifactFactsV0,
    command_ids: impl ExactSizeIterator<Item = &'a str>,
    signer_nonces: impl ExactSizeIterator<Item = (&'a str, u64)>,
) -> Result<(), DurableValidCodecErrorV0> {
    let expected = usize::try_from(facts.transaction_count())
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    if command_ids.len() != expected || signer_nonces.len() != expected {
        return Err(DurableValidCodecErrorV0::InvalidReplayIndex);
    }
    let mut previous_command: Option<&str> = None;
    for command_id in command_ids {
        if !valid_replay_token_v0(command_id, MAX_DURABLE_VALID_COMMAND_ID_BYTES_V0)
            || previous_command.is_some_and(|previous| previous >= command_id)
        {
            return Err(DurableValidCodecErrorV0::InvalidReplayIndex);
        }
        previous_command = Some(command_id);
    }
    let mut previous_nonce: Option<(&str, u64)> = None;
    for (signer_id, nonce) in signer_nonces {
        if nonce == 0
            || !valid_replay_token_v0(signer_id, MAX_DURABLE_VALID_SIGNER_ID_BYTES_V0)
            || previous_nonce.is_some_and(|previous| previous >= (signer_id, nonce))
        {
            return Err(DurableValidCodecErrorV0::InvalidReplayIndex);
        }
        previous_nonce = Some((signer_id, nonce));
    }
    Ok(())
}

fn valid_replay_token_v0(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        && !value.chars().any(char::is_control)
}

fn validate_decoded_write_recipe_v0(
    writes: &[DurableValidAuthWriteV0<'_>],
) -> Result<(), DurableValidCodecErrorV0> {
    validate_write_views_v0(writes.iter().map(|write| (write.key(), write.value())))
}

fn validate_write_views_v0<'a>(
    writes: impl IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
) -> Result<(), DurableValidCodecErrorV0> {
    let mut previous_key: Option<&[u8]> = None;
    for (key, value) in writes {
        if key.is_empty()
            || key.len() > MAX_AUTH_KEY_PREIMAGE_BYTES
            || value.is_some_and(|value| value.len() > MAX_DURABLE_VALID_WRITE_VALUE_BYTES_V0)
            || previous_key.is_some_and(|previous| previous >= key)
        {
            return Err(DurableValidCodecErrorV0::InvalidWriteRecipe);
        }
        previous_key = Some(key);
    }
    Ok(())
}

fn revalidate_domain_write_views_v0<'a>(
    facts: DurableValidArtifactFactsV0,
    replay_count: usize,
    writes: impl IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
) -> Result<DurableValidDomainDeltaV0, DurableValidCodecErrorV0> {
    let validator_key =
        validator_state_key().map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
    let mut objects = Vec::new();
    let mut validator_lifecycle = None;
    let mut poco_changes = Vec::new();
    let mut poco_manifest_count = 0usize;
    let mut hashed_keys = BTreeMap::new();

    for (key, value) in writes {
        let key_hash = crate::auth_tree::authenticated_key_hash(key)
            .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
        if hashed_keys.insert(key_hash, key.to_vec()).is_some() {
            return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
        }

        if key == validator_key.as_slice() {
            if validator_lifecycle.is_some() {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            let value = value.ok_or(DurableValidCodecErrorV0::InvalidDomainDelta)?;
            let record = AuthenticatedObjectRecord::decode(value)
                .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
            if record.object_type != VALIDATOR_LIFECYCLE_SCHEMA_V1
                || record.object_version != facts.target_height()
                || AuthenticatedObjectRecord::new(
                    record.object_type.clone(),
                    record.object_version,
                    record.value.clone(),
                )
                .and_then(|record| record.encode())
                .ok()
                .as_deref()
                    != Some(value)
            {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            let lifecycle: ValidatorLifecycleStateV1 = serde_json::from_slice(&record.value)
                .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
            lifecycle
                .validate()
                .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
            if serde_json::to_vec(&lifecycle)
                .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?
                != record.value
            {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            validator_lifecycle = Some(lifecycle);
            continue;
        }

        if let Ok(object_key_hex) = stored_object_key_preimage(key) {
            let value = value.ok_or(DurableValidCodecErrorV0::InvalidDomainDelta)?;
            if stored_object_key(&object_key_hex).ok().as_deref() != Some(key) {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            let record = AuthenticatedObjectRecord::decode(value)
                .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
            if record.object_version == 0
                || AuthenticatedObjectRecord::new(
                    record.object_type.clone(),
                    record.object_version,
                    record.value.clone(),
                )
                .and_then(|record| record.encode())
                .ok()
                .as_deref()
                    != Some(value)
            {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            let object = StoredObject {
                object_key_hex,
                object_type: record.object_type,
                version: record.object_version,
                value_hash_hex: hex::encode(hash_domain(
                    "trnm.state.object.value.v1",
                    &[&record.value],
                )),
                value_bytes: record.value,
            };
            if !crate::native_payload_validation::validate_durable_valid_runtime_object_v0(
                facts.target_height(),
                &object,
            ) {
                return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
            }
            objects.push(DurableValidObjectChangeV0 { object });
            continue;
        }

        let decoded = decode_poco_snapshot_physical_key_v0_exact(key)
            .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?
            .ok_or(DurableValidCodecErrorV0::InvalidDomainDelta)?;
        match decoded {
            PocoSnapshotPhysicalKeyV0::Manifest => {
                let value = value.ok_or(DurableValidCodecErrorV0::InvalidDomainDelta)?;
                let manifest = PocoSnapshotManifestV0::decode_exact(value)
                    .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)?;
                if manifest.cutoff_height().get() > facts.target_height() {
                    return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
                }
                poco_manifest_count = poco_manifest_count
                    .checked_add(1)
                    .ok_or(DurableValidCodecErrorV0::InvalidDomainDelta)?;
                poco_changes.push(DurableValidPocoChangeV0::Manifest(manifest));
            }
            PocoSnapshotPhysicalKeyV0::Entry { kind, logical_key } => {
                if value.is_none() && kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState {
                    return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
                }
                let verified = value
                    .map(|value| {
                        decode_poco_snapshot_value_v0_exact(kind, &logical_key, value)
                            .map_err(|_| DurableValidCodecErrorV0::InvalidDomainDelta)
                    })
                    .transpose()?;
                poco_changes.push(DurableValidPocoChangeV0::Entry {
                    kind,
                    logical_key: logical_key.into_boxed_slice(),
                    value: verified,
                });
            }
        }
    }

    if poco_changes.len() > MAX_POCO_SNAPSHOT_ENTRIES.saturating_add(1)
        || (!poco_changes.is_empty() && poco_manifest_count != 1)
    {
        return Err(DurableValidCodecErrorV0::InvalidDomainDelta);
    }
    Ok(DurableValidDomainDeltaV0 {
        objects: objects.into_boxed_slice(),
        validator_lifecycle,
        poco_changes: poco_changes.into_boxed_slice(),
        replay_count,
    })
}

fn validate_component_bounds_v0(
    command_ids: &[String],
    signer_nonces: &[(String, u64)],
    receipts_cev0: &[u8],
    writes: &[AuthWrite],
) -> Result<(), DurableValidCodecErrorV0> {
    validate_component_lengths_v0(
        command_ids.iter().map(String::as_str),
        signer_nonces
            .iter()
            .map(|(signer_id, nonce)| (signer_id.as_str(), *nonce)),
        receipts_cev0,
        writes.iter().map(|write| (write.key(), write.value())),
    )
}

fn validate_decoded_component_bounds_v0(
    command_ids: &[&str],
    signer_nonces: &[DurableValidSignerNonceV0<'_>],
    receipts_cev0: &[u8],
    writes: &[DurableValidAuthWriteV0<'_>],
) -> Result<(), DurableValidCodecErrorV0> {
    validate_component_lengths_v0(
        command_ids.iter().copied(),
        signer_nonces
            .iter()
            .map(|entry| (entry.signer_id(), entry.nonce())),
        receipts_cev0,
        writes.iter().map(|write| (write.key(), write.value())),
    )
}

fn validate_component_lengths_v0<'a, 'b, 'c>(
    command_ids: impl ExactSizeIterator<Item = &'a str>,
    signer_nonces: impl ExactSizeIterator<Item = (&'b str, u64)>,
    receipts_cev0: &[u8],
    writes: impl IntoIterator<Item = (&'c [u8], Option<&'c [u8]>)>,
) -> Result<(), DurableValidCodecErrorV0> {
    if receipts_cev0.len() > MAX_DURABLE_VALID_RECEIPTS_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record: DurableValidRecordKindV0::Artifact,
            maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            actual: receipts_cev0.len(),
        });
    }
    let replay_bytes = command_ids
        .map(|command_id| 4usize.saturating_add(command_id.len()))
        .chain(signer_nonces.map(|(signer_id, _)| 4usize.saturating_add(signer_id.len() + 8)))
        .try_fold(8usize, usize::checked_add)
        .ok_or(DurableValidCodecErrorV0::InvalidReplayIndex)?;
    if replay_bytes > MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record: DurableValidRecordKindV0::Artifact,
            maximum: MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0,
            actual: replay_bytes,
        });
    }
    let mut recipe_bytes = 4usize;
    let mut write_count = 0usize;
    for (key, value) in writes {
        write_count = write_count
            .checked_add(1)
            .ok_or(DurableValidCodecErrorV0::InvalidWriteRecipe)?;
        recipe_bytes = recipe_bytes
            .checked_add(4 + key.len() + 1)
            .and_then(|size| value.map_or(Some(size), |value| size.checked_add(4 + value.len())))
            .ok_or(DurableValidCodecErrorV0::InvalidWriteRecipe)?;
    }
    if write_count > MAX_DURABLE_VALID_WRITE_COUNT_V0 {
        return Err(DurableValidCodecErrorV0::InvalidWriteRecipe);
    }
    u32::try_from(write_count).map_err(|_| DurableValidCodecErrorV0::InvalidWriteRecipe)?;
    if replay_bytes
        .checked_add(recipe_bytes)
        .is_none_or(|bytes| bytes > MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0)
    {
        return Err(DurableValidCodecErrorV0::InvalidWriteRecipe);
    }
    Ok(())
}

fn encode_artifact_v0(
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
    command_ids: &[String],
    signer_nonces: &[(String, u64)],
    receipts_cev0: &[u8],
    writes: &[AuthWrite],
    durable_plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
) -> Result<Vec<u8>, DurableValidCodecErrorV0> {
    encode_artifact_parts_v0(
        identity,
        facts,
        command_ids.iter().map(String::as_str),
        signer_nonces
            .iter()
            .map(|(signer_id, nonce)| (signer_id.as_str(), *nonce)),
        receipts_cev0,
        writes.iter().map(|write| (write.key(), write.value())),
        durable_plan_commitment,
    )
}

fn encode_artifact_parts_v0<'a, 'b, 'c, C, S, I>(
    identity: NativeValidationArtifactIdentityV0,
    facts: DurableValidArtifactFactsV0,
    command_ids: C,
    signer_nonces: S,
    receipts_cev0: &[u8],
    writes: I,
    durable_plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
) -> Result<Vec<u8>, DurableValidCodecErrorV0>
where
    C: Clone + ExactSizeIterator<Item = &'a str>,
    S: Clone + ExactSizeIterator<Item = (&'b str, u64)>,
    I: Clone + ExactSizeIterator<Item = (&'c [u8], Option<&'c [u8]>)>,
{
    let exact_encoded_len = durable_valid_artifact_encoded_len_v0(
        command_ids.clone(),
        signer_nonces.clone(),
        receipts_cev0,
        writes.clone(),
    )?;
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(exact_encoded_len).map_err(|_| {
        DurableValidCodecErrorV0::AllocationFailed(DurableValidRecordKindV0::Artifact)
    })?;
    push_artifact_bytes_v0(
        &mut encoded,
        &DURABLE_VALID_ARTIFACT_CODEC_VERSION_V0.to_be_bytes(),
    )?;
    push_artifact_bytes_v0(&mut encoded, &[route_code_v0(identity.route())])?;
    let validation_id = identity.validation_id();
    push_artifact_bytes_v0(&mut encoded, validation_id.block_id().as_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &validation_id.view().get().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &validation_id.generation().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &identity.request_fingerprint())?;
    push_artifact_bytes_v0(&mut encoded, &identity.job_immutable_checksum())?;
    push_artifact_bytes_v0(&mut encoded, &[DURABLE_VALID_RESULT_KIND_V0])?;
    push_artifact_bytes_v0(&mut encoded, &facts.target_height().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &facts.parent_height().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, facts.parent_block_id().as_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &facts.parent_state_version().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &facts.parent_state_root())?;
    push_artifact_bytes_v0(&mut encoded, &facts.payload_root())?;
    push_artifact_bytes_v0(&mut encoded, &facts.state_root())?;
    push_artifact_bytes_v0(&mut encoded, &facts.receipts_root())?;
    push_artifact_bytes_v0(&mut encoded, &facts.evidence_root())?;
    push_artifact_bytes_v0(&mut encoded, &facts.logical_block_size().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &facts.transaction_count().to_be_bytes())?;
    push_artifact_bytes_v0(&mut encoded, &facts.evidence_count().to_be_bytes())?;
    let command_count = u32::try_from(command_ids.len())
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    push_artifact_bytes_v0(&mut encoded, &command_count.to_be_bytes())?;
    for command_id in command_ids {
        push_artifact_framed_v0(&mut encoded, command_id.as_bytes())?;
    }
    let signer_nonce_count = u32::try_from(signer_nonces.len())
        .map_err(|_| DurableValidCodecErrorV0::InvalidReplayIndex)?;
    push_artifact_bytes_v0(&mut encoded, &signer_nonce_count.to_be_bytes())?;
    for (signer_id, nonce) in signer_nonces {
        push_artifact_framed_v0(&mut encoded, signer_id.as_bytes())?;
        push_artifact_bytes_v0(&mut encoded, &nonce.to_be_bytes())?;
    }
    push_artifact_framed_v0(&mut encoded, receipts_cev0)?;
    let write_count =
        u32::try_from(writes.len()).map_err(|_| DurableValidCodecErrorV0::InvalidWriteRecipe)?;
    push_artifact_bytes_v0(&mut encoded, &write_count.to_be_bytes())?;
    for (key, value) in writes {
        push_artifact_framed_v0(&mut encoded, key)?;
        match value {
            None => push_artifact_bytes_v0(&mut encoded, &[0])?,
            Some(value) => {
                push_artifact_bytes_v0(&mut encoded, &[1])?;
                push_artifact_framed_v0(&mut encoded, value)?;
            }
        }
    }
    push_artifact_bytes_v0(&mut encoded, &durable_plan_commitment)?;
    debug_assert_eq!(encoded.len(), exact_encoded_len);
    Ok(encoded)
}

fn durable_valid_artifact_encoded_len_v0<'a, 'b, 'c>(
    command_ids: impl Iterator<Item = &'a str>,
    signer_nonces: impl Iterator<Item = (&'b str, u64)>,
    receipts_cev0: &[u8],
    writes: impl Iterator<Item = (&'c [u8], Option<&'c [u8]>)>,
) -> Result<usize, DurableValidCodecErrorV0> {
    let mut length = DURABLE_VALID_ARTIFACT_FIXED_BYTES_V0;
    for command_id in command_ids {
        length = checked_artifact_length_add_v0(length, 4)?;
        length = checked_artifact_length_add_v0(length, command_id.len())?;
    }
    for (signer_id, _) in signer_nonces {
        length = checked_artifact_length_add_v0(length, 4)?;
        length = checked_artifact_length_add_v0(length, signer_id.len())?;
        length = checked_artifact_length_add_v0(length, 8)?;
    }
    length = checked_artifact_length_add_v0(length, receipts_cev0.len())?;
    for (key, value) in writes {
        length = checked_artifact_length_add_v0(length, 4)?;
        length = checked_artifact_length_add_v0(length, key.len())?;
        length = checked_artifact_length_add_v0(length, 1)?;
        if let Some(value) = value {
            length = checked_artifact_length_add_v0(length, 4)?;
            length = checked_artifact_length_add_v0(length, value.len())?;
        }
    }
    if length > MAX_DURABLE_VALID_ARTIFACT_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record: DurableValidRecordKindV0::Artifact,
            maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            actual: length,
        });
    }
    Ok(length)
}

fn checked_artifact_length_add_v0(
    length: usize,
    additional: usize,
) -> Result<usize, DurableValidCodecErrorV0> {
    length
        .checked_add(additional)
        .ok_or(DurableValidCodecErrorV0::TooLarge {
            record: DurableValidRecordKindV0::Artifact,
            maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            actual: usize::MAX,
        })
}

fn encode_durable_valid_callback_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
) -> [u8; DURABLE_VALID_CALLBACK_BYTES_V0] {
    let mut encoded = [0; DURABLE_VALID_CALLBACK_BYTES_V0];
    let mut offset = 0;
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &DURABLE_VALID_CALLBACK_CODEC_VERSION_V0.to_be_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &[route_code_v0(identity.route())],
    );
    let validation_id = identity.validation_id();
    put_exact_v0(
        &mut encoded,
        &mut offset,
        validation_id.block_id().as_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &validation_id.view().get().to_be_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &validation_id.generation().to_be_bytes(),
    );
    put_exact_v0(&mut encoded, &mut offset, &[DURABLE_VALID_RESULT_KIND_V0]);
    put_exact_v0(&mut encoded, &mut offset, &artifact_checksum);
    debug_assert_eq!(offset, DURABLE_VALID_CALLBACK_BYTES_V0);
    encoded
}

fn durable_valid_callback_payload_checksum_v0(encoded: &[u8]) -> [u8; 32] {
    hash_domain(DURABLE_VALID_CALLBACK_PAYLOAD_DOMAIN_V0, &[encoded])
}

const fn route_code_v0(route: PayloadValidationRouteV0) -> u8 {
    match route {
        PayloadValidationRouteV0::Proposal => 0,
        PayloadValidationRouteV0::Synced => 1,
    }
}

fn decode_route_v0(
    route: u8,
    record: DurableValidRecordKindV0,
) -> Result<PayloadValidationRouteV0, DurableValidCodecErrorV0> {
    match route {
        0 => Ok(PayloadValidationRouteV0::Proposal),
        1 => Ok(PayloadValidationRouteV0::Synced),
        _ => Err(DurableValidCodecErrorV0::UnknownRoute { record, route }),
    }
}

fn push_artifact_framed_v0(
    encoded: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), DurableValidCodecErrorV0> {
    let length = u32::try_from(value.len()).map_err(|_| DurableValidCodecErrorV0::TooLarge {
        record: DurableValidRecordKindV0::Artifact,
        maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
        actual: value.len(),
    })?;
    push_artifact_bytes_v0(encoded, &length.to_be_bytes())?;
    push_artifact_bytes_v0(encoded, value)
}

fn push_artifact_bytes_v0(
    encoded: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), DurableValidCodecErrorV0> {
    let next_len =
        encoded
            .len()
            .checked_add(value.len())
            .ok_or(DurableValidCodecErrorV0::TooLarge {
                record: DurableValidRecordKindV0::Artifact,
                maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
                actual: usize::MAX,
            })?;
    if next_len > MAX_DURABLE_VALID_ARTIFACT_BYTES_V0 {
        return Err(DurableValidCodecErrorV0::TooLarge {
            record: DurableValidRecordKindV0::Artifact,
            maximum: MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            actual: next_len,
        });
    }
    if next_len > encoded.capacity() {
        encoded
            .try_reserve_exact(next_len - encoded.len())
            .map_err(|_| {
                DurableValidCodecErrorV0::AllocationFailed(DurableValidRecordKindV0::Artifact)
            })?;
    }
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_exact_v0<const LENGTH: usize>(target: &mut [u8; LENGTH], offset: &mut usize, value: &[u8]) {
    let end = offset
        .checked_add(value.len())
        .expect("fixed valid record offset does not overflow");
    target[*offset..end].copy_from_slice(value);
    *offset = end;
}

struct ExactValidRecordDecoderV0<'a> {
    remaining: &'a [u8],
    record: DurableValidRecordKindV0,
}

impl<'a> ExactValidRecordDecoderV0<'a> {
    const fn new(encoded: &'a [u8], record: DurableValidRecordKindV0) -> Self {
        Self {
            remaining: encoded,
            record,
        }
    }

    const fn remaining_len_v0(&self) -> usize {
        self.remaining.len()
    }

    fn read_array_v0<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], DurableValidCodecErrorV0> {
        let Some((value, remaining)) = self.remaining.split_at_checked(LENGTH) else {
            return Err(DurableValidCodecErrorV0::Truncated(self.record));
        };
        self.remaining = remaining;
        Ok(value
            .try_into()
            .expect("checked exact valid record field length"))
    }

    fn read_u8_v0(&mut self) -> Result<u8, DurableValidCodecErrorV0> {
        Ok(self.read_array_v0::<1>()?[0])
    }

    fn read_u16_v0(&mut self) -> Result<u16, DurableValidCodecErrorV0> {
        Ok(u16::from_be_bytes(self.read_array_v0()?))
    }

    fn read_u32_v0(&mut self) -> Result<u32, DurableValidCodecErrorV0> {
        Ok(u32::from_be_bytes(self.read_array_v0()?))
    }

    fn read_u64_v0(&mut self) -> Result<u64, DurableValidCodecErrorV0> {
        Ok(u64::from_be_bytes(self.read_array_v0()?))
    }

    fn read_u32_framed_v0(&mut self, maximum: usize) -> Result<&'a [u8], DurableValidCodecErrorV0> {
        let length = usize::try_from(self.read_u32_v0()?)
            .map_err(|_| DurableValidCodecErrorV0::Truncated(self.record))?;
        if length > maximum {
            return Err(DurableValidCodecErrorV0::TooLarge {
                record: self.record,
                maximum,
                actual: length,
            });
        }
        let Some((value, remaining)) = self.remaining.split_at_checked(length) else {
            return Err(DurableValidCodecErrorV0::Truncated(self.record));
        };
        self.remaining = remaining;
        Ok(value)
    }

    fn finish_v0(self) -> Result<(), DurableValidCodecErrorV0> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(DurableValidCodecErrorV0::TrailingBytes(self.record))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::{
        auth_tree::InMemoryAuthTree,
        native_execution::{NativeBlockExecutionV0, NativeTransactionReceiptFactsV0},
    };

    struct FixtureV0 {
        identity: NativeValidationArtifactIdentityV0,
        facts: DurableValidArtifactFactsV0,
        command_ids: Vec<String>,
        signer_nonces: Vec<(String, u64)>,
        writes: Vec<AuthWrite>,
        payload: ApplicationPayloadV0,
        receipts: Vec<u8>,
        plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
        parent_tree: InMemoryAuthTree,
    }

    fn fixture_v0(route: PayloadValidationRouteV0) -> FixtureV0 {
        let mut tree = InMemoryAuthTree::default();
        let parent_root = tree
            .put_value_set(
                0,
                [
                    AuthWrite::put(b"valid-artifact-parent".to_vec(), b"parent".to_vec())
                        .expect("parent write"),
                ],
            )
            .expect("parent state");
        let monetary_value = serde_json::to_vec(&trnm_protocol::MonetaryStateV1::default())
            .expect("canonical monetary fixture value");
        let monetary_object = StoredObject {
            object_key_hex: trnm_protocol::monetary_state_key(),
            object_type: trnm_protocol::MONETARY_STATE_OBJECT_TYPE_V1.to_string(),
            version: 1,
            value_hash_hex: hex::encode(hash_domain(
                "trnm.state.object.value.v1",
                &[&monetary_value],
            )),
            value_bytes: monetary_value,
        };
        let mut writes = vec![
            crate::authenticated_object_write(&crate::default_fee_policy_object())
                .expect("canonical fee-policy fixture write"),
            crate::authenticated_object_write(&monetary_object)
                .expect("canonical monetary fixture write"),
        ];
        writes.sort_by(|left, right| left.key().cmp(right.key()));
        let plan = tree
            .plan_put_value_set(1, writes.clone())
            .expect("valid artifact plan");
        let state_root = plan.root_hash.0;
        let plan_commitment = plan
            .durable_jmt_plan_commitment_v0()
            .expect("commit valid artifact plan");
        let transactions = vec![
            Bytes::from_static(b"valid-artifact-transaction-a"),
            Bytes::from_static(b"valid-artifact-transaction-b"),
        ];
        let execution = NativeBlockExecutionV0::try_new(
            &transactions,
            vec![
                NativeTransactionReceiptFactsV0::internal_operation(),
                NativeTransactionReceiptFactsV0::internal_operation(),
            ],
        )
        .expect("valid artifact receipt fixture");
        let payload = execution.application_payload().clone();
        let payload_root = payload.payload_root().expect("fixture payload root");
        let receipts_root = execution
            .execution_receipts()
            .receipts_root()
            .expect("fixture receipts root");
        let receipts = execution
            .execution_receipts()
            .try_cev0_bytes()
            .expect("fixture receipts CEV0");
        let identity = NativeValidationArtifactIdentityV0::new_v0(
            route,
            ValidationId::new(BlockId::new([0x11; 32]), View::new(7), 3),
            [0x22; 32],
            [0x33; 32],
        );
        let facts = DurableValidArtifactFactsV0::new_v0(
            1,
            0,
            BlockId::new([0x44; 32]),
            0,
            parent_root.0,
            *payload_root.as_bytes(),
            state_root,
            *receipts_root.as_bytes(),
            [0x77; 32],
            4096,
            2,
            1,
        );
        FixtureV0 {
            identity,
            facts,
            command_ids: vec![
                "valid-artifact-command-a".into(),
                "valid-artifact-command-b".into(),
            ],
            signer_nonces: vec![
                ("valid-artifact-signer-a".into(), 1),
                ("valid-artifact-signer-b".into(), 1),
            ],
            writes,
            payload,
            receipts,
            plan_commitment,
            parent_tree: tree,
        }
    }

    fn prepare_fixture_v0(fixture: &FixtureV0) -> PreparedDurableValidArtifactRecordV0 {
        prepare_durable_valid_artifact_v0(DurableValidArtifactInputV0 {
            identity: fixture.identity,
            facts: fixture.facts,
            command_ids: &fixture.command_ids,
            signer_nonces: &fixture.signer_nonces,
            receipts_cev0: &fixture.receipts,
            writes: &fixture.writes,
            durable_plan_commitment: fixture.plan_commitment,
        })
        .expect("prepare valid artifact")
    }

    #[test]
    fn valid_artifact_and_callback_round_trip_for_both_routes_v0() {
        for route in [
            PayloadValidationRouteV0::Proposal,
            PayloadValidationRouteV0::Synced,
        ] {
            let fixture = fixture_v0(route);
            let artifact = prepare_fixture_v0(&fixture);
            assert!(artifact.encoded().len() < MAX_DURABLE_VALID_ARTIFACT_BYTES_V0);
            let verified = verify_durable_valid_artifact_v0(
                artifact.artifact_codec(),
                artifact.encoded(),
                artifact.checksum(),
                durable_valid_result_kind_v0(),
                fixture.identity,
                fixture.facts,
            )
            .expect("verify valid artifact");
            assert_eq!(verified.identity(), fixture.identity);
            assert_eq!(verified.facts(), fixture.facts);
            assert_eq!(
                verified.command_ids().to_vec(),
                fixture
                    .command_ids
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
            );
            assert_eq!(verified.signer_nonces().len(), fixture.signer_nonces.len());
            assert_eq!(verified.receipts_cev0(), fixture.receipts);
            assert_eq!(verified.durable_plan_commitment(), fixture.plan_commitment);
            verified
                .revalidate_receipts_v0(
                    &fixture.payload,
                    &ConsensusParametersV0::reference_shadow_v0(),
                )
                .expect("revalidate canonical valid receipts");
            verified
                .revalidate_durable_plan_v0(&fixture.parent_tree)
                .expect("replan exact valid artifact against parent");
            let delta = verified
                .revalidate_domain_delta_v0()
                .expect("revalidate inert typed domain delta");
            assert_eq!(delta.objects().len(), fixture.writes.len());
            assert_eq!(delta.replay_count(), fixture.command_ids.len());
            assert!(delta.validator_lifecycle().is_none());
            assert!(delta.poco_changes().is_empty());
            assert_eq!(verified.writes().len(), fixture.writes.len());
            for (decoded, expected) in verified.writes().iter().zip(&fixture.writes) {
                assert_eq!(decoded.key(), expected.key());
                assert_eq!(decoded.value(), expected.value());
            }

            let callback = prepare_durable_valid_callback_v0(&artifact);
            let rebound = verify_durable_valid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                callback.idempotency_key(),
                callback.delivery_attempt(),
                DURABLE_VALID_DELIVERY_ATTEMPT_V0,
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                fixture.identity,
            )
            .expect("verify valid callback");
            assert_eq!(rebound.identity(), fixture.identity);
            assert_eq!(rebound.artifact_checksum(), artifact.checksum());
            assert_eq!(rebound.payload(), callback.payload());
            assert_eq!(rebound.payload_checksum(), callback.payload_checksum());
            assert_eq!(rebound.idempotency_key(), callback.idempotency_key());
            assert_eq!(rebound.outbox_checksum(), callback.outbox_checksum());
            assert_eq!(
                durable_valid_callback_payload_checksum_for_identity_v0(
                    fixture.identity,
                    artifact.checksum(),
                ),
                callback.payload_checksum()
            );
        }
    }

    #[test]
    fn valid_artifact_decoder_rejects_version_route_result_truncation_and_trailing_v0() {
        let fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_fixture_v0(&fixture);

        let mut wrong_version = artifact.encoded().to_vec();
        wrong_version[1] = 1;
        assert!(matches!(
            decode_durable_valid_artifact_v0(&wrong_version),
            Err(DurableValidCodecErrorV0::UnsupportedVersion { .. })
        ));

        let mut wrong_route = artifact.encoded().to_vec();
        wrong_route[2] = 9;
        assert!(matches!(
            decode_durable_valid_artifact_v0(&wrong_route),
            Err(DurableValidCodecErrorV0::UnknownRoute { .. })
        ));

        let mut wrong_result = artifact.encoded().to_vec();
        wrong_result[115] = 1;
        assert!(matches!(
            decode_durable_valid_artifact_v0(&wrong_result),
            Err(DurableValidCodecErrorV0::UnknownResultKind { .. })
        ));

        let truncated = &artifact.encoded()[..artifact.encoded().len() - 1];
        assert!(matches!(
            decode_durable_valid_artifact_v0(truncated),
            Err(DurableValidCodecErrorV0::Truncated(_))
        ));

        let mut trailing = artifact.encoded().to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_durable_valid_artifact_v0(&trailing),
            Err(DurableValidCodecErrorV0::TrailingBytes(_))
        ));
    }

    #[test]
    fn valid_artifact_rejects_noncanonical_recipe_invalid_plan_and_binding_drift_v0() {
        let mut fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        fixture.writes.swap(0, 1);
        assert_eq!(
            prepare_durable_valid_artifact_v0(DurableValidArtifactInputV0 {
                identity: fixture.identity,
                facts: fixture.facts,
                command_ids: &fixture.command_ids,
                signer_nonces: &fixture.signer_nonces,
                receipts_cev0: &fixture.receipts,
                writes: &fixture.writes,
                durable_plan_commitment: fixture.plan_commitment,
            })
            .expect_err("unordered recipe is rejected"),
            DurableValidCodecErrorV0::InvalidWriteRecipe
        );

        let fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        let mut invalid_plan_commitment = fixture.plan_commitment;
        invalid_plan_commitment[0] ^= 1;
        let spliced_artifact = prepare_durable_valid_artifact_v0(DurableValidArtifactInputV0 {
            identity: fixture.identity,
            facts: fixture.facts,
            command_ids: &fixture.command_ids,
            signer_nonces: &fixture.signer_nonces,
            receipts_cev0: &fixture.receipts,
            writes: &fixture.writes,
            durable_plan_commitment: invalid_plan_commitment,
        })
        .expect("an inert commitment is structurally opaque");
        let spliced_verified = verify_durable_valid_artifact_v0(
            spliced_artifact.artifact_codec(),
            spliced_artifact.encoded(),
            spliced_artifact.checksum(),
            durable_valid_result_kind_v0(),
            fixture.identity,
            fixture.facts,
        )
        .expect("bind the structurally valid spliced commitment");
        assert_eq!(
            spliced_verified
                .revalidate_durable_plan_v0(&fixture.parent_tree)
                .expect_err("spliced plan commitment is rejected by exact replanning"),
            DurableValidCodecErrorV0::InvalidDurablePlan
        );

        let artifact = prepare_fixture_v0(&fixture);
        let wrong_identity = NativeValidationArtifactIdentityV0::new_v0(
            PayloadValidationRouteV0::Synced,
            fixture.identity.validation_id(),
            fixture.identity.request_fingerprint(),
            fixture.identity.job_immutable_checksum(),
        );
        assert!(matches!(
            verify_durable_valid_artifact_v0(
                artifact.artifact_codec(),
                artifact.encoded(),
                artifact.checksum(),
                durable_valid_result_kind_v0(),
                wrong_identity,
                fixture.facts,
            ),
            Err(DurableValidRecordErrorV0::Binding(
                DurableValidBindingErrorV0::IdentityMismatch
            ))
        ));
        let mut wrong_checksum = artifact.checksum();
        wrong_checksum[0] ^= 1;
        assert!(matches!(
            verify_durable_valid_artifact_v0(
                artifact.artifact_codec(),
                artifact.encoded(),
                wrong_checksum,
                durable_valid_result_kind_v0(),
                fixture.identity,
                fixture.facts,
            ),
            Err(DurableValidRecordErrorV0::Binding(
                DurableValidBindingErrorV0::ArtifactChecksumMismatch
            ))
        ));
    }

    #[test]
    fn historical_revalidation_rejects_root_receipt_and_parent_splices_v0() {
        let mut fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        fixture.facts.state_root[0] ^= 1;
        let artifact = prepare_fixture_v0(&fixture);
        let verified = verify_durable_valid_artifact_v0(
            artifact.artifact_codec(),
            artifact.encoded(),
            artifact.checksum(),
            durable_valid_result_kind_v0(),
            fixture.identity,
            fixture.facts,
        )
        .expect("structurally bind intentionally spliced state fact");
        assert_eq!(
            verified
                .revalidate_durable_plan_v0(&fixture.parent_tree)
                .expect_err("physical plan root must bind the artifact state root"),
            DurableValidCodecErrorV0::InvalidDurablePlan
        );

        let mut fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        fixture.facts.receipts_root[0] ^= 1;
        let artifact = prepare_fixture_v0(&fixture);
        let verified = verify_durable_valid_artifact_v0(
            artifact.artifact_codec(),
            artifact.encoded(),
            artifact.checksum(),
            durable_valid_result_kind_v0(),
            fixture.identity,
            fixture.facts,
        )
        .expect("structurally bind intentionally spliced receipt fact");
        assert_eq!(
            verified
                .revalidate_receipts_v0(
                    &fixture.payload,
                    &ConsensusParametersV0::reference_shadow_v0(),
                )
                .expect_err("canonical receipts must bind the artifact receipt root"),
            DurableValidCodecErrorV0::InvalidFacts
        );

        let fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_fixture_v0(&fixture);
        let verified = verify_durable_valid_artifact_v0(
            artifact.artifact_codec(),
            artifact.encoded(),
            artifact.checksum(),
            durable_valid_result_kind_v0(),
            fixture.identity,
            fixture.facts,
        )
        .expect("bind exact artifact before wrong-parent check");
        assert_eq!(
            verified
                .revalidate_durable_plan_v0(&InMemoryAuthTree::default())
                .expect_err("missing authenticated parent must reject historical replan"),
            DurableValidCodecErrorV0::InvalidDurablePlan
        );
    }

    #[test]
    fn valid_callback_rejects_every_persisted_binding_drift_v0() {
        let fixture = fixture_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_fixture_v0(&fixture);
        let callback = prepare_durable_valid_callback_v0(&artifact);
        let mut wrong_payload = *callback.payload();
        wrong_payload[51] = 1;
        assert!(matches!(
            decode_durable_valid_callback_v0(&wrong_payload),
            Err(DurableValidCodecErrorV0::UnknownResultKind { .. })
        ));

        let mut wrong_idempotency = callback.idempotency_key();
        wrong_idempotency[0] ^= 1;
        assert!(matches!(
            verify_durable_valid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                wrong_idempotency,
                callback.delivery_attempt(),
                callback.delivery_attempt(),
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                fixture.identity,
            ),
            Err(DurableValidRecordErrorV0::Binding(
                DurableValidBindingErrorV0::CallbackIdempotencyKeyMismatch
            ))
        ));
        assert!(matches!(
            verify_durable_valid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                callback.idempotency_key(),
                1,
                0,
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                fixture.identity,
            ),
            Err(DurableValidRecordErrorV0::Binding(
                DurableValidBindingErrorV0::DeliveryAttemptMismatch
            ))
        ));
    }

    #[test]
    fn valid_artifact_capacity_formula_is_closed_v0() {
        assert_eq!(
            MAX_DURABLE_VALID_ARTIFACT_BYTES_V0,
            MAX_DURABLE_VALID_RECEIPTS_BYTES_V0
                + MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0
                + DURABLE_VALID_ARTIFACT_FIXED_AND_FRAME_BUDGET_V0
        );
        const {
            assert!(
                MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0 <= MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0
            );
            assert!(DURABLE_VALID_ARTIFACT_FIXED_AND_FRAME_BUDGET_V0 > 512);
        }
        assert_eq!(
            MAX_DURABLE_VALID_RECEIPTS_BYTES_V0,
            usize::try_from(ConsensusParametersV0::reference_shadow_v0().max_block_bytes())
                .expect("reference max block bytes fit usize")
        );
        assert_eq!(MAX_DURABLE_VALID_ARTIFACT_BYTES_V0, 62_980_096);
        const {
            assert!(MAX_DURABLE_VALID_ARTIFACT_BYTES_V0 < 61 * 1024 * 1024);
        }

        // Every strict transaction carries at least the 518-byte compact
        // signed-envelope shape plus the four-byte CEV0 transaction frame.
        // Header/list/evidence bytes only reduce this conservative maximum.
        const MIN_STRICT_TRANSACTION_CEV0_BYTES_V0: usize = 522;
        const MAX_RUNTIME_WRITES_PER_TRANSACTION_V0: usize = 6;
        const MAX_RUNTIME_RECIPE_BYTES_PER_TRANSACTION_V0: usize = 4_540;
        const MAX_REPLAY_BYTES_PER_TRANSACTION_V0: usize = 432;
        const MAX_LIFECYCLE_RECIPE_BYTES_V0: usize = 4 * 1024 * 1024 + 128;
        let max_block_bytes = MAX_DURABLE_VALID_RECEIPTS_BYTES_V0;
        let max_transaction_count = max_block_bytes / MIN_STRICT_TRANSACTION_CEV0_BYTES_V0;
        let max_write_count = MAX_RUNTIME_WRITES_PER_TRANSACTION_V0
            .checked_mul(max_transaction_count)
            .and_then(|count| count.checked_add(MAX_POCO_SNAPSHOT_ENTRIES + 1 + 1))
            .expect("reference write-count formula is bounded");
        assert_eq!(max_transaction_count, 8_035);
        assert_eq!(max_write_count, 58_212);
        assert!(max_transaction_count < MAX_DURABLE_VALID_TRANSACTION_COUNT_V0);
        assert!(max_write_count < MAX_DURABLE_VALID_WRITE_COUNT_V0);
        assert_eq!(
            validate_component_lengths_v0(
                std::iter::empty::<&str>(),
                std::iter::empty::<(&str, u64)>(),
                &[],
                std::iter::repeat_n(
                    (b"k".as_slice(), None),
                    MAX_DURABLE_VALID_WRITE_COUNT_V0 + 1,
                ),
            ),
            Err(DurableValidCodecErrorV0::InvalidWriteRecipe),
        );

        let max_replay_bytes = 8usize
            .checked_add(
                max_transaction_count
                    .checked_mul(MAX_REPLAY_BYTES_PER_TRANSACTION_V0)
                    .expect("reference replay formula is bounded"),
            )
            .expect("reference replay framing is bounded");
        assert_eq!(max_replay_bytes, 3_471_128);
        assert!(max_replay_bytes < MAX_DURABLE_VALID_REPLAY_INDEX_BYTES_V0);

        let max_domain_delta_bytes = 4usize
            .checked_add(
                max_transaction_count
                    .checked_mul(MAX_RUNTIME_RECIPE_BYTES_PER_TRANSACTION_V0)
                    .expect("reference runtime recipe formula is bounded"),
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    crate::poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES
                        + 9 * (MAX_POCO_SNAPSHOT_ENTRIES + 1),
                )
            })
            .and_then(|bytes| bytes.checked_add(MAX_LIFECYCLE_RECIPE_BYTES_V0))
            .and_then(|bytes| bytes.checked_add(max_replay_bytes))
            .expect("reference domain-delta formula is bounded");
        assert_eq!(max_domain_delta_bytes, 52_623_081);
        assert!(max_domain_delta_bytes < MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0);

        // The current seal/readback algorithm may retain two artifact BLOBs,
        // one decoded domain delta, receipts and the input block concurrently.
        // The JMT physical plan is streamed into its fixed commitment and no
        // longer adds a second plan-sized Vec. This remains a conservative
        // explicit-Vec envelope, not a bound on the JMT planner's internal
        // nodes or allocator/SQLite overhead.
        let maximum_large_component_peak = 2usize
            .checked_mul(MAX_DURABLE_VALID_ARTIFACT_BYTES_V0)
            .and_then(|bytes| bytes.checked_add(MAX_DURABLE_VALID_DOMAIN_DELTA_BYTES_V0))
            .and_then(|bytes| bytes.checked_add(MAX_DURABLE_VALID_RECEIPTS_BYTES_V0))
            .and_then(|bytes| bytes.checked_add(max_block_bytes))
            .expect("large-component peak formula is bounded");
        assert_eq!(maximum_large_component_peak, 193_069_056);
        assert!(maximum_large_component_peak < 192 * 1024 * 1024);
    }
}
