//! Canonical deterministic-invalid validation artifact and callback records.
//!
//! These records are application-owned durable facts. Strict decoding proves
//! only that their bytes are bounded, canonical, and checksum-consistent.
//! Revalidation additionally binds them to one already-verified durable job;
//! neither stage constructs `PayloadValidationResult`, a Core input, callback
//! authority, or permission to advance the validation job state machine.

use std::{error::Error, fmt};

use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
use trnm_consensus_types::{BlockId, View};
use trnm_finality_types::hash_domain;

pub(crate) const DURABLE_INVALID_ARTIFACT_CODEC_V0: &str =
    "trnm.native-validation.invalid-artifact.v0";
pub(crate) const DURABLE_INVALID_CALLBACK_CODEC_V0: &str =
    "trnm.native-validation.invalid-callback.v0";

const DURABLE_INVALID_ARTIFACT_CODEC_VERSION_V0: u16 = 0;
const DURABLE_INVALID_CALLBACK_CODEC_VERSION_V0: u16 = 0;
const DURABLE_INVALID_OUTBOX_ROW_CODEC_VERSION_V0: u16 = 0;
const DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0: u8 = 1;
const DURABLE_INVALID_DELIVERY_ATTEMPT_V0: u64 = 0;

pub(crate) const DURABLE_INVALID_ARTIFACT_BYTES_V0: usize = 120;
pub(crate) const DURABLE_INVALID_CALLBACK_BYTES_V0: usize = 84;

const DURABLE_INVALID_ARTIFACT_DOMAIN_V0: &str = "trnm.consensus-app.validation-artifact.v0";
const DURABLE_INVALID_CALLBACK_PAYLOAD_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-callback-payload.v0";
const DURABLE_INVALID_CALLBACK_IDEMPOTENCY_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-callback-idempotency.v0";
const DURABLE_INVALID_CALLBACK_OUTBOX_ROW_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-callback-outbox-row.v0";

/// Closed, stable deterministic-invalid reasons activated by the v7 journal.
///
/// Zero remains permanently unassigned. No runtime diagnostic, availability
/// failure, invariant fault, or general execution outcome can enter this
/// representation.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableDeterministicInvalidReasonV0 {
    ComputedStateRootMismatch = 1,
    ComputedReceiptsRootMismatch = 2,
}

impl DurableDeterministicInvalidReasonV0 {
    pub(crate) const fn code_v0(self) -> u32 {
        self as u32
    }

    pub(crate) const fn from_code_v0(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::ComputedStateRootMismatch),
            2 => Some(Self::ComputedReceiptsRootMismatch),
            _ => None,
        }
    }
}

/// Job identity and immutable digests to which an invalid artifact is bound.
///
/// Constructing this value grants no persistence or callback authority. Store
/// admission must derive it from an already verified durable row, while the
/// live bridge must retain its owning comparator carrier separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeValidationArtifactIdentityV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    job_immutable_checksum: [u8; 32],
}

impl NativeValidationArtifactIdentityV0 {
    pub(crate) const fn new_v0(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        request_fingerprint: [u8; 32],
        job_immutable_checksum: [u8; 32],
    ) -> Self {
        Self {
            route,
            validation_id,
            request_fingerprint,
            job_immutable_checksum,
        }
    }

    pub(crate) const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub(crate) const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub(crate) const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub(crate) const fn job_immutable_checksum(self) -> [u8; 32] {
        self.job_immutable_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableNativeValidationRecordKindV0 {
    InvalidArtifact,
    InvalidCallback,
}

impl fmt::Display for DurableNativeValidationRecordKindV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArtifact => "deterministic-invalid artifact",
            Self::InvalidCallback => "deterministic-invalid callback",
        })
    }
}

/// Structural or version failure while decoding one canonical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableNativeValidationCodecErrorV0 {
    UnsupportedCodec(DurableNativeValidationRecordKindV0),
    WrongLength {
        record: DurableNativeValidationRecordKindV0,
        expected: usize,
        actual: usize,
    },
    UnsupportedVersion {
        record: DurableNativeValidationRecordKindV0,
        version: u16,
    },
    UnknownRoute {
        record: DurableNativeValidationRecordKindV0,
        route: u8,
    },
    UnknownResultKind {
        record: DurableNativeValidationRecordKindV0,
        result_kind: u8,
    },
    UnknownInvalidReason(u32),
    Truncated(DurableNativeValidationRecordKindV0),
    TrailingBytes(DurableNativeValidationRecordKindV0),
    NonCanonical(DurableNativeValidationRecordKindV0),
}

impl fmt::Display for DurableNativeValidationCodecErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCodec(record) => write!(formatter, "unsupported {record} codec"),
            Self::WrongLength {
                record,
                expected,
                actual,
            } => write!(
                formatter,
                "{record} has {actual} bytes; expected exactly {expected}"
            ),
            Self::UnsupportedVersion { record, version } => {
                write!(formatter, "unsupported {record} version {version}")
            }
            Self::UnknownRoute { record, route } => {
                write!(formatter, "unknown {record} route tag {route}")
            }
            Self::UnknownResultKind {
                record,
                result_kind,
            } => write!(formatter, "unknown {record} result tag {result_kind}"),
            Self::UnknownInvalidReason(reason) => {
                write!(formatter, "unknown deterministic-invalid reason {reason}")
            }
            Self::Truncated(record) => write!(formatter, "truncated {record}"),
            Self::TrailingBytes(record) => write!(formatter, "trailing bytes in {record}"),
            Self::NonCanonical(record) => write!(formatter, "non-canonical {record}"),
        }
    }
}

impl Error for DurableNativeValidationCodecErrorV0 {}

/// Congruence failure between canonical bytes and verified job/outbox facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum DurableNativeValidationBindingErrorV0 {
    ResultKindMismatch,
    RouteMismatch,
    ValidationIdMismatch,
    RequestFingerprintMismatch,
    JobImmutableChecksumMismatch,
    InvalidReasonMismatch,
    ArtifactChecksumMismatch,
    PayloadChecksumMismatch,
    IdempotencyKeyMismatch,
    OutboxChecksumMismatch,
    DeliveryAttemptMismatch,
}

impl fmt::Display for DurableNativeValidationBindingErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResultKindMismatch => "deterministic-invalid result kind mismatch",
            Self::RouteMismatch => "validation route mismatch",
            Self::ValidationIdMismatch => "full validation identity mismatch",
            Self::RequestFingerprintMismatch => "validation request fingerprint mismatch",
            Self::JobImmutableChecksumMismatch => "validation job immutable checksum mismatch",
            Self::InvalidReasonMismatch => "deterministic-invalid reason mismatch",
            Self::ArtifactChecksumMismatch => "validation artifact checksum mismatch",
            Self::PayloadChecksumMismatch => "validation callback payload checksum mismatch",
            Self::IdempotencyKeyMismatch => "validation callback idempotency key mismatch",
            Self::OutboxChecksumMismatch => "validation callback outbox checksum mismatch",
            Self::DeliveryAttemptMismatch => "validation callback delivery attempt mismatch",
        })
    }
}

impl Error for DurableNativeValidationBindingErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableNativeValidationRecordErrorV0 {
    Codec(DurableNativeValidationCodecErrorV0),
    Binding(DurableNativeValidationBindingErrorV0),
}

impl fmt::Display for DurableNativeValidationRecordErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => fmt::Display::fmt(error, formatter),
            Self::Binding(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for DurableNativeValidationRecordErrorV0 {}

impl From<DurableNativeValidationCodecErrorV0> for DurableNativeValidationRecordErrorV0 {
    fn from(error: DurableNativeValidationCodecErrorV0) -> Self {
        Self::Codec(error)
    }
}

impl From<DurableNativeValidationBindingErrorV0> for DurableNativeValidationRecordErrorV0 {
    fn from(error: DurableNativeValidationBindingErrorV0) -> Self {
        Self::Binding(error)
    }
}

/// Canonical live-evaluation artifact bytes. This remains inert data; the
/// owning validation carrier is deliberately not represented here.
#[derive(Debug)]
pub(crate) struct PreparedDurableInvalidArtifactRecordV0 {
    identity: NativeValidationArtifactIdentityV0,
    reason: DurableDeterministicInvalidReasonV0,
    encoded: [u8; DURABLE_INVALID_ARTIFACT_BYTES_V0],
    checksum: [u8; 32],
}

impl PreparedDurableInvalidArtifactRecordV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.reason
    }

    pub(crate) const fn artifact_codec(&self) -> &'static str {
        DURABLE_INVALID_ARTIFACT_CODEC_V0
    }

    pub(crate) const fn encoded(&self) -> &[u8; DURABLE_INVALID_ARTIFACT_BYTES_V0] {
        &self.encoded
    }

    pub(crate) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}

/// Structurally canonical artifact bytes not yet bound to a durable job.
#[derive(Debug)]
pub(crate) struct UnverifiedDurableInvalidArtifactV0 {
    identity: NativeValidationArtifactIdentityV0,
    reason: DurableDeterministicInvalidReasonV0,
    encoded: [u8; DURABLE_INVALID_ARTIFACT_BYTES_V0],
    checksum: [u8; 32],
}

impl UnverifiedDurableInvalidArtifactV0 {
    pub(crate) fn revalidate_v0(
        self,
        expected_identity: NativeValidationArtifactIdentityV0,
        stored_result_kind: u8,
        stored_reason: DurableDeterministicInvalidReasonV0,
        stored_checksum: [u8; 32],
    ) -> Result<RevalidatedDurableInvalidArtifactV0, DurableNativeValidationBindingErrorV0> {
        if stored_result_kind != DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0 {
            return Err(DurableNativeValidationBindingErrorV0::ResultKindMismatch);
        }
        validate_identity_binding_v0(self.identity, expected_identity)?;
        if self.reason != stored_reason {
            return Err(DurableNativeValidationBindingErrorV0::InvalidReasonMismatch);
        }
        if self.checksum != stored_checksum {
            return Err(DurableNativeValidationBindingErrorV0::ArtifactChecksumMismatch);
        }
        Ok(RevalidatedDurableInvalidArtifactV0 {
            identity: self.identity,
            reason: self.reason,
            encoded: self.encoded,
            checksum: self.checksum,
        })
    }
}

/// Canonical artifact rebound to one verified durable job. It is a recovery
/// fact only and cannot be converted into Core authority.
#[derive(Debug)]
pub(crate) struct RevalidatedDurableInvalidArtifactV0 {
    identity: NativeValidationArtifactIdentityV0,
    reason: DurableDeterministicInvalidReasonV0,
    encoded: [u8; DURABLE_INVALID_ARTIFACT_BYTES_V0],
    checksum: [u8; 32],
}

impl RevalidatedDurableInvalidArtifactV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.reason
    }

    pub(crate) const fn encoded(&self) -> &[u8; DURABLE_INVALID_ARTIFACT_BYTES_V0] {
        &self.encoded
    }

    pub(crate) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}

/// Canonical callback/outbox bytes derived from one canonical invalid
/// artifact. It remains inert until a future dispatcher re-executes and
/// rebinds the request under Core-owned durable obligation authority.
#[derive(Debug)]
pub(crate) struct PreparedDurableInvalidCallbackRecordV0 {
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_INVALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl PreparedDurableInvalidCallbackRecordV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn result_kind(&self) -> u8 {
        DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0
    }

    pub(crate) const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub(crate) const fn payload_codec(&self) -> &'static str {
        DURABLE_INVALID_CALLBACK_CODEC_V0
    }

    pub(crate) const fn payload(&self) -> &[u8; DURABLE_INVALID_CALLBACK_BYTES_V0] {
        &self.payload
    }

    pub(crate) const fn payload_checksum(&self) -> [u8; 32] {
        self.payload_checksum
    }

    pub(crate) const fn idempotency_key(&self) -> [u8; 32] {
        self.idempotency_key
    }

    pub(crate) const fn delivery_attempt(&self) -> u64 {
        DURABLE_INVALID_DELIVERY_ATTEMPT_V0
    }

    pub(crate) const fn outbox_checksum(&self) -> [u8; 32] {
        self.outbox_checksum
    }
}

/// Structurally canonical callback bytes not yet rebound to the verified job
/// and artifact columns which own the corresponding outbox row.
#[derive(Debug)]
pub(crate) struct UnverifiedDurableInvalidCallbackV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_INVALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
}

/// Exact callback/outbox facts rebound to one verified callback-pending job.
/// This remains inert and is not a Core input or delivery capability.
#[derive(Debug)]
pub(crate) struct RevalidatedDurableInvalidCallbackV0 {
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload: [u8; DURABLE_INVALID_CALLBACK_BYTES_V0],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl RevalidatedDurableInvalidCallbackV0 {
    pub(crate) const fn identity(&self) -> NativeValidationArtifactIdentityV0 {
        self.identity
    }

    pub(crate) const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub(crate) const fn payload(&self) -> &[u8; DURABLE_INVALID_CALLBACK_BYTES_V0] {
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

pub(crate) fn prepare_durable_invalid_artifact_v0(
    identity: NativeValidationArtifactIdentityV0,
    reason: DurableDeterministicInvalidReasonV0,
) -> PreparedDurableInvalidArtifactRecordV0 {
    let encoded = encode_durable_invalid_artifact_v0(identity, reason);
    let checksum = durable_invalid_artifact_checksum_v0(&encoded);
    PreparedDurableInvalidArtifactRecordV0 {
        identity,
        reason,
        encoded,
        checksum,
    }
}

pub(crate) const fn durable_deterministic_invalid_result_kind_v0() -> u8 {
    DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0
}

pub(crate) fn decode_durable_invalid_artifact_v0(
    encoded: &[u8],
) -> Result<UnverifiedDurableInvalidArtifactV0, DurableNativeValidationCodecErrorV0> {
    let record = DurableNativeValidationRecordKindV0::InvalidArtifact;
    if encoded.len() != DURABLE_INVALID_ARTIFACT_BYTES_V0 {
        return Err(DurableNativeValidationCodecErrorV0::WrongLength {
            record,
            expected: DURABLE_INVALID_ARTIFACT_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactRecordDecoderV0::new(encoded, record);
    let version = decoder.read_u16_v0()?;
    if version != DURABLE_INVALID_ARTIFACT_CODEC_VERSION_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnsupportedVersion { record, version });
    }
    let route = decode_route_v0(decoder.read_u8_v0()?, record)?;
    let block_id = BlockId::new(decoder.read_array_v0()?);
    let view = View::new(decoder.read_u64_v0()?);
    let generation = decoder.read_u64_v0()?;
    let request_fingerprint = decoder.read_array_v0()?;
    let job_immutable_checksum = decoder.read_array_v0()?;
    let result_kind = decoder.read_u8_v0()?;
    if result_kind != DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnknownResultKind {
            record,
            result_kind,
        });
    }
    let reason_code = decoder.read_u32_v0()?;
    let reason = DurableDeterministicInvalidReasonV0::from_code_v0(reason_code).ok_or(
        DurableNativeValidationCodecErrorV0::UnknownInvalidReason(reason_code),
    )?;
    decoder.finish_v0()?;

    let identity = NativeValidationArtifactIdentityV0::new_v0(
        route,
        ValidationId::new(block_id, view, generation),
        request_fingerprint,
        job_immutable_checksum,
    );
    let canonical = encode_durable_invalid_artifact_v0(identity, reason);
    if canonical.as_slice() != encoded {
        return Err(DurableNativeValidationCodecErrorV0::NonCanonical(record));
    }
    Ok(UnverifiedDurableInvalidArtifactV0 {
        identity,
        reason,
        encoded: canonical,
        checksum: durable_invalid_artifact_checksum_v0(encoded),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_durable_invalid_artifact_v0(
    artifact_codec: &str,
    artifact_bytes: &[u8],
    artifact_checksum: [u8; 32],
    stored_result_kind: u8,
    stored_reason: DurableDeterministicInvalidReasonV0,
    expected_identity: NativeValidationArtifactIdentityV0,
) -> Result<RevalidatedDurableInvalidArtifactV0, DurableNativeValidationRecordErrorV0> {
    if artifact_codec != DURABLE_INVALID_ARTIFACT_CODEC_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnsupportedCodec(
            DurableNativeValidationRecordKindV0::InvalidArtifact,
        )
        .into());
    }
    Ok(
        decode_durable_invalid_artifact_v0(artifact_bytes)?.revalidate_v0(
            expected_identity,
            stored_result_kind,
            stored_reason,
            artifact_checksum,
        )?,
    )
}

pub(crate) fn prepare_durable_invalid_callback_v0(
    artifact: &PreparedDurableInvalidArtifactRecordV0,
) -> PreparedDurableInvalidCallbackRecordV0 {
    let identity = artifact.identity;
    let artifact_checksum = artifact.checksum;
    let payload = encode_durable_invalid_callback_v0(identity, artifact_checksum);
    let payload_checksum = durable_invalid_callback_payload_checksum_v0(&payload);
    let idempotency_key = durable_invalid_callback_idempotency_key_v0(identity, artifact_checksum);
    let outbox_checksum = durable_invalid_callback_outbox_checksum_v0(
        identity,
        artifact_checksum,
        DURABLE_INVALID_CALLBACK_CODEC_V0,
        payload_checksum,
        idempotency_key,
        DURABLE_INVALID_DELIVERY_ATTEMPT_V0,
    );
    PreparedDurableInvalidCallbackRecordV0 {
        identity,
        artifact_checksum,
        payload,
        payload_checksum,
        idempotency_key,
        outbox_checksum,
    }
}

pub(crate) fn decode_durable_invalid_callback_v0(
    encoded: &[u8],
) -> Result<UnverifiedDurableInvalidCallbackV0, DurableNativeValidationCodecErrorV0> {
    let record = DurableNativeValidationRecordKindV0::InvalidCallback;
    if encoded.len() != DURABLE_INVALID_CALLBACK_BYTES_V0 {
        return Err(DurableNativeValidationCodecErrorV0::WrongLength {
            record,
            expected: DURABLE_INVALID_CALLBACK_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactRecordDecoderV0::new(encoded, record);
    let version = decoder.read_u16_v0()?;
    if version != DURABLE_INVALID_CALLBACK_CODEC_VERSION_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnsupportedVersion { record, version });
    }
    let route = decode_route_v0(decoder.read_u8_v0()?, record)?;
    let block_id = BlockId::new(decoder.read_array_v0()?);
    let view = View::new(decoder.read_u64_v0()?);
    let generation = decoder.read_u64_v0()?;
    let result_kind = decoder.read_u8_v0()?;
    if result_kind != DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnknownResultKind {
            record,
            result_kind,
        });
    }
    let artifact_checksum = decoder.read_array_v0()?;
    decoder.finish_v0()?;

    let canonical = encode_durable_invalid_callback_v0(
        NativeValidationArtifactIdentityV0::new_v0(
            route,
            ValidationId::new(block_id, view, generation),
            [0; 32],
            [0; 32],
        ),
        artifact_checksum,
    );
    if canonical.as_slice() != encoded {
        return Err(DurableNativeValidationCodecErrorV0::NonCanonical(record));
    }
    Ok(UnverifiedDurableInvalidCallbackV0 {
        route,
        validation_id: ValidationId::new(block_id, view, generation),
        artifact_checksum,
        payload: canonical,
        payload_checksum: durable_invalid_callback_payload_checksum_v0(encoded),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_durable_invalid_callback_v0(
    payload_codec: &str,
    payload_bytes: &[u8],
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    outbox_checksum: [u8; 32],
    stored_result_kind: u8,
    stored_artifact_checksum: [u8; 32],
    expected_identity: NativeValidationArtifactIdentityV0,
) -> Result<RevalidatedDurableInvalidCallbackV0, DurableNativeValidationRecordErrorV0> {
    if payload_codec != DURABLE_INVALID_CALLBACK_CODEC_V0 {
        return Err(DurableNativeValidationCodecErrorV0::UnsupportedCodec(
            DurableNativeValidationRecordKindV0::InvalidCallback,
        )
        .into());
    }
    if stored_result_kind != DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0 {
        return Err(DurableNativeValidationBindingErrorV0::ResultKindMismatch.into());
    }
    if delivery_attempt != DURABLE_INVALID_DELIVERY_ATTEMPT_V0 {
        return Err(DurableNativeValidationBindingErrorV0::DeliveryAttemptMismatch.into());
    }
    let unverified = decode_durable_invalid_callback_v0(payload_bytes)?;
    if unverified.route != expected_identity.route {
        return Err(DurableNativeValidationBindingErrorV0::RouteMismatch.into());
    }
    if unverified.validation_id != expected_identity.validation_id {
        return Err(DurableNativeValidationBindingErrorV0::ValidationIdMismatch.into());
    }
    if unverified.artifact_checksum != stored_artifact_checksum {
        return Err(DurableNativeValidationBindingErrorV0::ArtifactChecksumMismatch.into());
    }
    if unverified.payload_checksum != payload_checksum {
        return Err(DurableNativeValidationBindingErrorV0::PayloadChecksumMismatch.into());
    }
    let expected_idempotency =
        durable_invalid_callback_idempotency_key_v0(expected_identity, stored_artifact_checksum);
    if idempotency_key != expected_idempotency {
        return Err(DurableNativeValidationBindingErrorV0::IdempotencyKeyMismatch.into());
    }
    let expected_outbox = durable_invalid_callback_outbox_checksum_v0(
        expected_identity,
        stored_artifact_checksum,
        payload_codec,
        payload_checksum,
        idempotency_key,
        delivery_attempt,
    );
    if outbox_checksum != expected_outbox {
        return Err(DurableNativeValidationBindingErrorV0::OutboxChecksumMismatch.into());
    }
    Ok(RevalidatedDurableInvalidCallbackV0 {
        identity: expected_identity,
        artifact_checksum: stored_artifact_checksum,
        payload: unverified.payload,
        payload_checksum,
        idempotency_key,
        outbox_checksum,
    })
}

pub(crate) fn durable_invalid_callback_idempotency_key_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
) -> [u8; 32] {
    let route = [route_code_v0(identity.route)];
    let validation_id = identity.validation_id;
    let view = validation_id.view().get().to_be_bytes();
    let generation = validation_id.generation().to_be_bytes();
    let result = [DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0];
    hash_domain(
        DURABLE_INVALID_CALLBACK_IDEMPOTENCY_DOMAIN_V0,
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
pub(crate) fn durable_invalid_callback_outbox_checksum_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
    payload_codec: &str,
    payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
) -> [u8; 32] {
    let codec_version = DURABLE_INVALID_OUTBOX_ROW_CODEC_VERSION_V0.to_be_bytes();
    let route = [route_code_v0(identity.route)];
    let validation_id = identity.validation_id;
    let view = validation_id.view().get().to_be_bytes();
    let generation = validation_id.generation().to_be_bytes();
    let result = [DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0];
    let delivery_attempt = delivery_attempt.to_be_bytes();
    hash_domain(
        DURABLE_INVALID_CALLBACK_OUTBOX_ROW_DOMAIN_V0,
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

fn encode_durable_invalid_artifact_v0(
    identity: NativeValidationArtifactIdentityV0,
    reason: DurableDeterministicInvalidReasonV0,
) -> [u8; DURABLE_INVALID_ARTIFACT_BYTES_V0] {
    let mut encoded = [0; DURABLE_INVALID_ARTIFACT_BYTES_V0];
    let mut offset = 0;
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &DURABLE_INVALID_ARTIFACT_CODEC_VERSION_V0.to_be_bytes(),
    );
    put_exact_v0(&mut encoded, &mut offset, &[route_code_v0(identity.route)]);
    put_exact_v0(
        &mut encoded,
        &mut offset,
        identity.validation_id.block_id().as_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &identity.validation_id.view().get().to_be_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &identity.validation_id.generation().to_be_bytes(),
    );
    put_exact_v0(&mut encoded, &mut offset, &identity.request_fingerprint);
    put_exact_v0(&mut encoded, &mut offset, &identity.job_immutable_checksum);
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &[DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0],
    );
    put_exact_v0(&mut encoded, &mut offset, &reason.code_v0().to_be_bytes());
    debug_assert_eq!(offset, DURABLE_INVALID_ARTIFACT_BYTES_V0);
    encoded
}

fn encode_durable_invalid_callback_v0(
    identity: NativeValidationArtifactIdentityV0,
    artifact_checksum: [u8; 32],
) -> [u8; DURABLE_INVALID_CALLBACK_BYTES_V0] {
    let mut encoded = [0; DURABLE_INVALID_CALLBACK_BYTES_V0];
    let mut offset = 0;
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &DURABLE_INVALID_CALLBACK_CODEC_VERSION_V0.to_be_bytes(),
    );
    put_exact_v0(&mut encoded, &mut offset, &[route_code_v0(identity.route)]);
    put_exact_v0(
        &mut encoded,
        &mut offset,
        identity.validation_id.block_id().as_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &identity.validation_id.view().get().to_be_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &identity.validation_id.generation().to_be_bytes(),
    );
    put_exact_v0(
        &mut encoded,
        &mut offset,
        &[DURABLE_DETERMINISTIC_INVALID_RESULT_KIND_V0],
    );
    put_exact_v0(&mut encoded, &mut offset, &artifact_checksum);
    debug_assert_eq!(offset, DURABLE_INVALID_CALLBACK_BYTES_V0);
    encoded
}

fn durable_invalid_artifact_checksum_v0(encoded: &[u8]) -> [u8; 32] {
    hash_domain(DURABLE_INVALID_ARTIFACT_DOMAIN_V0, &[encoded])
}

fn durable_invalid_callback_payload_checksum_v0(encoded: &[u8]) -> [u8; 32] {
    hash_domain(DURABLE_INVALID_CALLBACK_PAYLOAD_DOMAIN_V0, &[encoded])
}

fn validate_identity_binding_v0(
    actual: NativeValidationArtifactIdentityV0,
    expected: NativeValidationArtifactIdentityV0,
) -> Result<(), DurableNativeValidationBindingErrorV0> {
    if actual.route != expected.route {
        return Err(DurableNativeValidationBindingErrorV0::RouteMismatch);
    }
    if actual.validation_id != expected.validation_id {
        return Err(DurableNativeValidationBindingErrorV0::ValidationIdMismatch);
    }
    if actual.request_fingerprint != expected.request_fingerprint {
        return Err(DurableNativeValidationBindingErrorV0::RequestFingerprintMismatch);
    }
    if actual.job_immutable_checksum != expected.job_immutable_checksum {
        return Err(DurableNativeValidationBindingErrorV0::JobImmutableChecksumMismatch);
    }
    Ok(())
}

const fn route_code_v0(route: PayloadValidationRouteV0) -> u8 {
    match route {
        PayloadValidationRouteV0::Proposal => 0,
        PayloadValidationRouteV0::Synced => 1,
    }
}

fn decode_route_v0(
    route: u8,
    record: DurableNativeValidationRecordKindV0,
) -> Result<PayloadValidationRouteV0, DurableNativeValidationCodecErrorV0> {
    match route {
        0 => Ok(PayloadValidationRouteV0::Proposal),
        1 => Ok(PayloadValidationRouteV0::Synced),
        _ => Err(DurableNativeValidationCodecErrorV0::UnknownRoute { record, route }),
    }
}

fn put_exact_v0<const LENGTH: usize>(target: &mut [u8; LENGTH], offset: &mut usize, value: &[u8]) {
    let end = offset
        .checked_add(value.len())
        .expect("fixed validation record offset does not overflow");
    target[*offset..end].copy_from_slice(value);
    *offset = end;
}

struct ExactRecordDecoderV0<'a> {
    remaining: &'a [u8],
    record: DurableNativeValidationRecordKindV0,
}

impl<'a> ExactRecordDecoderV0<'a> {
    const fn new(encoded: &'a [u8], record: DurableNativeValidationRecordKindV0) -> Self {
        Self {
            remaining: encoded,
            record,
        }
    }

    fn read_array_v0<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], DurableNativeValidationCodecErrorV0> {
        let Some((value, remaining)) = self.remaining.split_at_checked(LENGTH) else {
            return Err(DurableNativeValidationCodecErrorV0::Truncated(self.record));
        };
        self.remaining = remaining;
        Ok(value
            .try_into()
            .expect("checked exact validation record field length"))
    }

    fn read_u8_v0(&mut self) -> Result<u8, DurableNativeValidationCodecErrorV0> {
        Ok(self.read_array_v0::<1>()?[0])
    }

    fn read_u16_v0(&mut self) -> Result<u16, DurableNativeValidationCodecErrorV0> {
        Ok(u16::from_be_bytes(self.read_array_v0()?))
    }

    fn read_u32_v0(&mut self) -> Result<u32, DurableNativeValidationCodecErrorV0> {
        Ok(u32::from_be_bytes(self.read_array_v0()?))
    }

    fn read_u64_v0(&mut self) -> Result<u64, DurableNativeValidationCodecErrorV0> {
        Ok(u64::from_be_bytes(self.read_array_v0()?))
    }

    fn finish_v0(self) -> Result<(), DurableNativeValidationCodecErrorV0> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(DurableNativeValidationCodecErrorV0::TrailingBytes(
                self.record,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_identity_v0(route: PayloadValidationRouteV0) -> NativeValidationArtifactIdentityV0 {
        NativeValidationArtifactIdentityV0::new_v0(
            route,
            ValidationId::new(
                BlockId::new([0x11; 32]),
                View::new(0x0102_0304_0506_0708),
                0x1112_1314_1516_1718,
            ),
            [0x22; 32],
            [0x33; 32],
        )
    }

    fn hash32_v0(encoded: &str) -> [u8; 32] {
        hex::decode(encoded)
            .expect("frozen hash hex")
            .try_into()
            .expect("frozen hash is 32 bytes")
    }

    #[test]
    fn invalid_artifact_and_callback_v0_frozen_vectors() {
        let artifact = prepare_durable_invalid_artifact_v0(
            fixture_identity_v0(PayloadValidationRouteV0::Proposal),
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        assert_eq!(artifact.encoded().len(), 120);
        assert_eq!(
            hex::encode(artifact.encoded()),
            concat!(
                "000000",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0102030405060708",
                "1112131415161718",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "01",
                "00000001"
            )
        );
        assert_eq!(
            artifact.checksum(),
            hash32_v0("aedb036187f674437addd8a41139a59b9e105749ba7b9829c396952bfd1268c1")
        );

        let callback = prepare_durable_invalid_callback_v0(&artifact);
        assert_eq!(callback.payload().len(), 84);
        assert_eq!(
            hex::encode(callback.payload()),
            concat!(
                "000000",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0102030405060708",
                "1112131415161718",
                "01",
                "aedb036187f674437addd8a41139a59b9e105749ba7b9829c396952bfd1268c1"
            )
        );
        assert_eq!(
            callback.payload_checksum(),
            hash32_v0("d2be6590a9e065322423834bb307ad5ea2141accd71df8c277ff8c3ea3d2c530")
        );
        assert_eq!(
            callback.idempotency_key(),
            hash32_v0("ddf6afeb288756fb8fd4ec527679d09eb444c008b168f2c9137d6940943b08f7")
        );
        assert_eq!(
            callback.outbox_checksum(),
            hash32_v0("916c214f5021a0dd54f85e16e5e7aac3e3f16805e2021d3bf03e99403581966d")
        );
    }

    #[test]
    fn both_routes_and_closed_reasons_round_trip_only_as_inert_facts() {
        for (route, reason) in [
            (
                PayloadValidationRouteV0::Proposal,
                DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
            ),
            (
                PayloadValidationRouteV0::Synced,
                DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch,
            ),
        ] {
            let identity = fixture_identity_v0(route);
            let prepared = prepare_durable_invalid_artifact_v0(identity, reason);
            let verified = verify_durable_invalid_artifact_v0(
                prepared.artifact_codec(),
                prepared.encoded(),
                prepared.checksum(),
                durable_deterministic_invalid_result_kind_v0(),
                reason,
                identity,
            )
            .expect("verify canonical invalid artifact");
            assert_eq!(verified.identity(), identity);
            assert_eq!(verified.reason(), reason);
            assert_eq!(verified.encoded(), prepared.encoded());

            let callback = prepare_durable_invalid_callback_v0(&prepared);
            let verified_callback = verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                callback.idempotency_key(),
                callback.delivery_attempt(),
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            )
            .expect("verify canonical invalid callback");
            assert_eq!(verified_callback.identity(), identity);
            assert_eq!(verified_callback.payload(), callback.payload());
            assert_eq!(verified_callback.artifact_checksum(), prepared.checksum());
        }
    }

    #[test]
    fn invalid_artifact_decoder_rejects_unknown_and_non_exact_records() {
        let artifact = prepare_durable_invalid_artifact_v0(
            fixture_identity_v0(PayloadValidationRouteV0::Proposal),
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        let bytes = artifact.encoded();

        assert!(matches!(
            decode_durable_invalid_artifact_v0(&bytes[..119]),
            Err(DurableNativeValidationCodecErrorV0::WrongLength { .. })
        ));
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_durable_invalid_artifact_v0(&trailing),
            Err(DurableNativeValidationCodecErrorV0::WrongLength { .. })
        ));

        let mut unknown_version = *bytes;
        unknown_version[1] = 1;
        assert!(matches!(
            decode_durable_invalid_artifact_v0(&unknown_version),
            Err(DurableNativeValidationCodecErrorV0::UnsupportedVersion { .. })
        ));
        let mut unknown_route = *bytes;
        unknown_route[2] = 2;
        assert!(matches!(
            decode_durable_invalid_artifact_v0(&unknown_route),
            Err(DurableNativeValidationCodecErrorV0::UnknownRoute { .. })
        ));
        let mut unknown_result = *bytes;
        unknown_result[115] = 0;
        assert!(matches!(
            decode_durable_invalid_artifact_v0(&unknown_result),
            Err(DurableNativeValidationCodecErrorV0::UnknownResultKind { .. })
        ));
        let mut unknown_reason = *bytes;
        unknown_reason[116..120].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            decode_durable_invalid_artifact_v0(&unknown_reason),
            Err(DurableNativeValidationCodecErrorV0::UnknownInvalidReason(0))
        ));
    }

    #[test]
    fn invalid_callback_decoder_rejects_unknown_and_non_exact_records() {
        let artifact = prepare_durable_invalid_artifact_v0(
            fixture_identity_v0(PayloadValidationRouteV0::Proposal),
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        let callback = prepare_durable_invalid_callback_v0(&artifact);
        let bytes = callback.payload();

        assert!(matches!(
            decode_durable_invalid_callback_v0(&bytes[..83]),
            Err(DurableNativeValidationCodecErrorV0::WrongLength { .. })
        ));
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_durable_invalid_callback_v0(&trailing),
            Err(DurableNativeValidationCodecErrorV0::WrongLength { .. })
        ));

        let mut unknown_version = *bytes;
        unknown_version[1] = 1;
        assert!(matches!(
            decode_durable_invalid_callback_v0(&unknown_version),
            Err(DurableNativeValidationCodecErrorV0::UnsupportedVersion { .. })
        ));
        let mut unknown_route = *bytes;
        unknown_route[2] = 2;
        assert!(matches!(
            decode_durable_invalid_callback_v0(&unknown_route),
            Err(DurableNativeValidationCodecErrorV0::UnknownRoute { .. })
        ));
        let mut unknown_result = *bytes;
        unknown_result[51] = 0;
        assert!(matches!(
            decode_durable_invalid_callback_v0(&unknown_result),
            Err(DurableNativeValidationCodecErrorV0::UnknownResultKind { .. })
        ));
    }

    #[test]
    fn checksum_consistent_artifact_splices_fail_job_rebinding() {
        let identity = fixture_identity_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_durable_invalid_artifact_v0(
            identity,
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        let cases = [
            (2, DurableNativeValidationBindingErrorV0::RouteMismatch),
            (
                3,
                DurableNativeValidationBindingErrorV0::ValidationIdMismatch,
            ),
            (
                51,
                DurableNativeValidationBindingErrorV0::RequestFingerprintMismatch,
            ),
            (
                83,
                DurableNativeValidationBindingErrorV0::JobImmutableChecksumMismatch,
            ),
        ];
        for (offset, expected) in cases {
            let mut spliced = *artifact.encoded();
            spliced[offset] ^= 1;
            let checksum = durable_invalid_artifact_checksum_v0(&spliced);
            let error = decode_durable_invalid_artifact_v0(&spliced)
                .expect("splice remains structurally canonical")
                .revalidate_v0(
                    identity,
                    durable_deterministic_invalid_result_kind_v0(),
                    DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
                    checksum,
                )
                .expect_err("checksum-consistent identity splice must fail");
            assert_eq!(error, expected);
        }

        let receipts = prepare_durable_invalid_artifact_v0(
            identity,
            DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch,
        );
        assert_eq!(
            decode_durable_invalid_artifact_v0(receipts.encoded())
                .expect("canonical alternate reason")
                .revalidate_v0(
                    identity,
                    durable_deterministic_invalid_result_kind_v0(),
                    DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
                    receipts.checksum(),
                )
                .expect_err("reason splice must fail"),
            DurableNativeValidationBindingErrorV0::InvalidReasonMismatch
        );
    }

    #[test]
    fn persisted_columns_must_match_their_canonical_records() {
        let identity = fixture_identity_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_durable_invalid_artifact_v0(
            identity,
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        assert!(matches!(
            verify_durable_invalid_artifact_v0(
                "trnm.native-validation.invalid-artifact.v1",
                artifact.encoded(),
                artifact.checksum(),
                durable_deterministic_invalid_result_kind_v0(),
                artifact.reason(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Codec(
                DurableNativeValidationCodecErrorV0::UnsupportedCodec(_)
            ))
        ));
        let mut wrong_artifact_checksum = artifact.checksum();
        wrong_artifact_checksum[0] ^= 1;
        assert!(matches!(
            verify_durable_invalid_artifact_v0(
                artifact.artifact_codec(),
                artifact.encoded(),
                wrong_artifact_checksum,
                durable_deterministic_invalid_result_kind_v0(),
                artifact.reason(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::ArtifactChecksumMismatch
            ))
        ));

        let callback = prepare_durable_invalid_callback_v0(&artifact);
        let mut wrong_payload_checksum = callback.payload_checksum();
        wrong_payload_checksum[0] ^= 1;
        assert!(matches!(
            verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                wrong_payload_checksum,
                callback.idempotency_key(),
                callback.delivery_attempt(),
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::PayloadChecksumMismatch
            ))
        ));
        assert!(matches!(
            verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                callback.idempotency_key(),
                1,
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::DeliveryAttemptMismatch
            ))
        ));
    }

    #[test]
    fn callback_payload_and_outbox_splices_fail_rebinding() {
        let identity = fixture_identity_v0(PayloadValidationRouteV0::Proposal);
        let artifact = prepare_durable_invalid_artifact_v0(
            identity,
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        );
        let callback = prepare_durable_invalid_callback_v0(&artifact);

        let mut spliced_payload = *callback.payload();
        spliced_payload[3] ^= 1;
        let spliced_payload_checksum =
            durable_invalid_callback_payload_checksum_v0(&spliced_payload);
        let spliced_idempotency = callback.idempotency_key();
        let spliced_outbox = durable_invalid_callback_outbox_checksum_v0(
            identity,
            callback.artifact_checksum(),
            callback.payload_codec(),
            spliced_payload_checksum,
            spliced_idempotency,
            callback.delivery_attempt(),
        );
        assert!(matches!(
            verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                &spliced_payload,
                spliced_payload_checksum,
                spliced_idempotency,
                callback.delivery_attempt(),
                spliced_outbox,
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::ValidationIdMismatch
            ))
        ));

        let mut wrong_idempotency = callback.idempotency_key();
        wrong_idempotency[0] ^= 1;
        assert!(matches!(
            verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                wrong_idempotency,
                callback.delivery_attempt(),
                callback.outbox_checksum(),
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::IdempotencyKeyMismatch
            ))
        ));

        let mut wrong_outbox = callback.outbox_checksum();
        wrong_outbox[0] ^= 1;
        assert!(matches!(
            verify_durable_invalid_callback_v0(
                callback.payload_codec(),
                callback.payload(),
                callback.payload_checksum(),
                callback.idempotency_key(),
                callback.delivery_attempt(),
                wrong_outbox,
                callback.result_kind(),
                callback.artifact_checksum(),
                identity,
            ),
            Err(DurableNativeValidationRecordErrorV0::Binding(
                DurableNativeValidationBindingErrorV0::OutboxChecksumMismatch
            ))
        ));
    }
}
