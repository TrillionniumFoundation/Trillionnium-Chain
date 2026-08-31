//! Inert direct-7 recovery barrier vocabulary.
//!
//! These values authenticate one exact recovery context and two N/N barriers.
//! They do not contain a signing key, durable-store handle, timer, runtime, or
//! activation method.  In particular, decoding or verifying a
//! [`RecoveryStartCertificateV1`] never grants ordinary consensus authority.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use crate::{
    canonical::{
        canonical_hash, signing_root, try_canonical_bytes, CanonicalSignable, Encoder,
        DOMAIN_RECOVERY_CAUGHT_UP_CUT_V1, DOMAIN_RECOVERY_CONTEXT_V1, DOMAIN_RECOVERY_READY_SET_V1,
        DOMAIN_RECOVERY_READY_V1, DOMAIN_RECOVERY_START_CERTIFICATE_V1, DOMAIN_RECOVERY_START_V1,
        DOMAIN_RECOVERY_ZERO_DELTA_CUT_V1,
    },
    BlockId, CertificateId, Epoch, Height, Signature64, SignatureVerifier, SigningRoot, StateRoot,
    ValidatorId, ValidatorSet, ValidatorSetId, MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
};

// These recovery artifacts have not crossed an operational activation
// boundary. V1 therefore intentionally replaces the earlier inert wire in
// place so every recovery signature binds the exact RestartPark artifact and
// the exact N/N RestartParkedAck artifact plus its fifth-phase admission set.
// Exact decoding fails closed on bytes produced by the earlier shape.
pub const RECOVERY_SCHEMA_VERSION_V1: u16 = 1;
pub const DIRECT7_RECOVERY_VALIDATOR_COUNT_V1: usize = 7;
pub const RECOVERY_PROCESS_INSTANCE_V1: u64 = 2;

pub const MAX_RECOVERY_CONTEXT_BYTES_V1: usize = 768;
pub const MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1: usize = 1_024;
pub const MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1: usize = 768;
pub const MAX_SIGNED_RECOVERY_READY_BYTES_V1: usize = 1_024;
pub const MAX_RECOVERY_READY_SET_BYTES_V1: usize = 8 * 1_024;
pub const MAX_SIGNED_RECOVERY_START_BYTES_V1: usize = 1_024;
pub const MAX_RECOVERY_START_CERTIFICATE_BYTES_V1: usize = 16 * 1_024;

pub type RecoveryResultV1<T> = core::result::Result<T, RecoveryErrorV1>;

/// Fail-closed construction, authentication, and exact-decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryErrorV1 {
    TooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    UnexpectedEnd {
        byte_offset: usize,
    },
    TrailingBytes {
        byte_offset: usize,
    },
    InvalidSchemaVersion {
        actual: u16,
        expected: u16,
    },
    UnknownRecoveryMode {
        actual: u8,
    },
    InvalidValidatorSet,
    UnsupportedValidatorProfile {
        actual: usize,
        expected: usize,
    },
    WrongValidatorSet,
    InvalidValidatorId {
        byte_offset: usize,
    },
    ZeroDigest(&'static str),
    UnknownTarget,
    InvalidProcessInstance {
        actual: u64,
        expected: u64,
    },
    InvalidCutGeometry(&'static str),
    UnknownSigner(Box<ValidatorId>),
    InvalidSignatureBytes,
    InvalidSignature(Box<ValidatorId>),
    ContextMismatch,
    ReadySetMismatch,
    Incomplete {
        actual: usize,
        expected: usize,
    },
    DuplicateSigner(Box<ValidatorId>),
    Equivocation(Box<ValidatorId>),
    NonCanonicalSignerOrder,
    NonCanonicalEncoding,
    EncodingFailure,
}

impl fmt::Display for RecoveryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{field} length {actual} exceeds maximum {maximum}"
            ),
            Self::UnexpectedEnd { byte_offset } => {
                write!(formatter, "unexpected end at byte {byte_offset}")
            }
            Self::TrailingBytes { byte_offset } => {
                write!(formatter, "trailing bytes at byte {byte_offset}")
            }
            Self::InvalidSchemaVersion { actual, expected } => write!(
                formatter,
                "recovery schema version {actual} does not equal {expected}"
            ),
            Self::UnknownRecoveryMode { actual } => {
                write!(formatter, "unknown recovery mode {actual}")
            }
            Self::InvalidValidatorSet => formatter.write_str("invalid validator set"),
            Self::UnsupportedValidatorProfile { actual, expected } => write!(
                formatter,
                "validator count {actual} does not equal direct-7 count {expected}"
            ),
            Self::WrongValidatorSet => formatter.write_str("wrong validator set"),
            Self::InvalidValidatorId { byte_offset } => {
                write!(formatter, "invalid validator ID at byte {byte_offset}")
            }
            Self::ZeroDigest(field) => write!(formatter, "{field} must not be zero"),
            Self::UnknownTarget => formatter.write_str("unknown recovery target"),
            Self::InvalidProcessInstance { actual, expected } => write!(
                formatter,
                "recovery process instance {actual} does not equal {expected}"
            ),
            Self::InvalidCutGeometry(reason) => write!(formatter, "invalid recovery cut: {reason}"),
            Self::UnknownSigner(origin) => write!(formatter, "unknown recovery signer {origin:?}"),
            Self::InvalidSignatureBytes => formatter.write_str("invalid recovery signature bytes"),
            Self::InvalidSignature(origin) => {
                write!(formatter, "invalid recovery signature by {origin:?}")
            }
            Self::ContextMismatch => formatter.write_str("recovery context mismatch"),
            Self::ReadySetMismatch => formatter.write_str("recovery ReadySet mismatch"),
            Self::Incomplete { actual, expected } => write!(
                formatter,
                "recovery signer count {actual} does not equal {expected}"
            ),
            Self::DuplicateSigner(origin) => {
                write!(formatter, "duplicate recovery signer {origin:?}")
            }
            Self::Equivocation(origin) => {
                write!(formatter, "recovery equivocation by {origin:?}")
            }
            Self::NonCanonicalSignerOrder => {
                formatter.write_str("recovery signers are not in canonical order")
            }
            Self::NonCanonicalEncoding => formatter.write_str("non-canonical recovery encoding"),
            Self::EncodingFailure => formatter.write_str("recovery encoding failed"),
        }
    }
}

impl core::error::Error for RecoveryErrorV1 {}

/// Recovery delta mode committed by every Ready and Start signature.
///
/// `NonZeroDelta` reserves a distinct canonical tag for the later passive
/// state-sync tranche.  This module supplies no state-sync or activation
/// authority for either variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecoveryModeV1 {
    ZeroDelta = 0,
    NonZeroDelta = 1,
}

impl TryFrom<u8> for RecoveryModeV1 {
    type Error = RecoveryErrorV1;

    fn try_from(value: u8) -> RecoveryResultV1<Self> {
        match value {
            0 => Ok(Self::ZeroDelta),
            1 => Ok(Self::NonZeroDelta),
            actual => Err(RecoveryErrorV1::UnknownRecoveryMode { actual }),
        }
    }
}

impl From<RecoveryModeV1> for u8 {
    fn from(value: RecoveryModeV1) -> Self {
        value as Self
    }
}

/// Exhaustive direct-7 recovery context preimage.
///
/// Artifact fields are SHA-256 digests of the exact raw artifacts named by
/// the field.  `node_facts_sha256` binds the typed process-2 reconstruction
/// facts selected by the upper-layer consuming owner; this inert crate does
/// not manufacture those facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryContextV1Fields {
    pub mode: RecoveryModeV1,
    pub campaign_context_sha256: [u8; 32],
    pub fleet_start_certificate_sha256: [u8; 32],
    pub validator_set_id: ValidatorSetId,
    pub validator_set_artifact_sha256: [u8; 32],
    pub restart_cut_artifact_sha256: [u8; 32],
    pub restart_park_artifact_sha256: [u8; 32],
    pub restart_parked_ack_artifact_sha256: [u8; 32],
    pub restart_parked_ack_admission_set_sha256: [u8; 32],
    pub caught_up_cut_artifact_sha256: [u8; 32],
    pub target_validator: ValidatorId,
    pub process_instance: u64,
    pub recovery_nonce: [u8; 32],
    pub restart_cut_epoch: Epoch,
    pub restart_cut_height: Height,
    pub restart_cut_block_id: BlockId,
    pub restart_cut_state_root: StateRoot,
    pub restart_cut_chain_root: [u8; 32],
    pub terminal_epoch: Epoch,
    pub terminal_height: Height,
    pub terminal_block_id: BlockId,
    pub terminal_state_root: StateRoot,
    pub terminal_chain_root: [u8; 32],
    pub node_facts_sha256: [u8; 32],
}

/// Canonical context signed by all direct-7 recovery barrier participants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryContextV1 {
    fields: RecoveryContextV1Fields,
}

impl RecoveryContextV1 {
    pub fn new_direct7(
        fields: RecoveryContextV1Fields,
        validator_set: &ValidatorSet,
    ) -> RecoveryResultV1<Self> {
        let value = Self { fields };
        value.validate_direct7(validator_set)?;
        Ok(value)
    }

    pub const fn fields(&self) -> RecoveryContextV1Fields {
        self.fields
    }

    pub const fn mode(&self) -> RecoveryModeV1 {
        self.fields.mode
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.fields.validator_set_id
    }

    pub const fn target_validator(&self) -> ValidatorId {
        self.fields.target_validator
    }

    pub const fn process_instance(&self) -> u64 {
        self.fields.process_instance
    }

    pub const fn restart_park_artifact_sha256(&self) -> [u8; 32] {
        self.fields.restart_park_artifact_sha256
    }

    pub const fn restart_parked_ack_artifact_sha256(&self) -> [u8; 32] {
        self.fields.restart_parked_ack_artifact_sha256
    }

    pub const fn restart_parked_ack_admission_set_sha256(&self) -> [u8; 32] {
        self.fields.restart_parked_ack_admission_set_sha256
    }

    pub const fn restart_cut_height(&self) -> Height {
        self.fields.restart_cut_height
    }

    pub const fn terminal_height(&self) -> Height {
        self.fields.terminal_height
    }

    pub const fn node_facts_sha256(&self) -> [u8; 32] {
        self.fields.node_facts_sha256
    }

    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_RECOVERY_CONTEXT_V1, |encoder| {
            self.encode_cev1(encoder);
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "RecoveryContextV1",
            MAX_RECOVERY_CONTEXT_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn validate_direct7(&self, validator_set: &ValidatorSet) -> RecoveryResultV1<()> {
        validator_set
            .validate_shape()
            .map_err(|_| RecoveryErrorV1::InvalidValidatorSet)?;
        let actual = validator_set.validators().len();
        if actual != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            return Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual,
                expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
            });
        }
        let fields = self.fields;
        if fields.validator_set_id != validator_set.id() {
            return Err(RecoveryErrorV1::WrongValidatorSet);
        }
        if validator_set.validator(fields.target_validator).is_none() {
            return Err(RecoveryErrorV1::UnknownTarget);
        }
        if fields.process_instance != RECOVERY_PROCESS_INSTANCE_V1 {
            return Err(RecoveryErrorV1::InvalidProcessInstance {
                actual: fields.process_instance,
                expected: RECOVERY_PROCESS_INSTANCE_V1,
            });
        }
        for (field, digest) in [
            ("campaign context SHA-256", fields.campaign_context_sha256),
            (
                "FleetStart certificate SHA-256",
                fields.fleet_start_certificate_sha256,
            ),
            ("validator-set ID", *fields.validator_set_id.as_bytes()),
            (
                "validator-set artifact SHA-256",
                fields.validator_set_artifact_sha256,
            ),
            (
                "RestartCut artifact SHA-256",
                fields.restart_cut_artifact_sha256,
            ),
            (
                "RestartPark artifact SHA-256",
                fields.restart_park_artifact_sha256,
            ),
            (
                "RestartParkedAck artifact SHA-256",
                fields.restart_parked_ack_artifact_sha256,
            ),
            (
                "RestartParkedAck admission-set SHA-256",
                fields.restart_parked_ack_admission_set_sha256,
            ),
            (
                "caught-up cut artifact SHA-256",
                fields.caught_up_cut_artifact_sha256,
            ),
            ("recovery nonce", fields.recovery_nonce),
            (
                "RestartCut block ID",
                *fields.restart_cut_block_id.as_bytes(),
            ),
            (
                "RestartCut state root",
                *fields.restart_cut_state_root.as_bytes(),
            ),
            ("RestartCut chain root", fields.restart_cut_chain_root),
            ("terminal block ID", *fields.terminal_block_id.as_bytes()),
            (
                "terminal state root",
                *fields.terminal_state_root.as_bytes(),
            ),
            ("terminal chain root", fields.terminal_chain_root),
            ("Node facts SHA-256", fields.node_facts_sha256),
        ] {
            if digest == [0; 32] {
                return Err(RecoveryErrorV1::ZeroDigest(field));
            }
        }
        if fields.restart_cut_height.get() == 0 || fields.terminal_height.get() == 0 {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "heights must be positive",
            ));
        }
        if fields.restart_cut_epoch != validator_set.epoch()
            || fields.terminal_epoch != validator_set.epoch()
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "RestartCut and terminal epochs must equal the validator-set epoch",
            ));
        }
        match fields.mode {
            RecoveryModeV1::ZeroDelta => {
                if (
                    fields.terminal_epoch,
                    fields.terminal_height,
                    fields.terminal_block_id,
                    fields.terminal_state_root,
                    fields.terminal_chain_root,
                ) != (
                    fields.restart_cut_epoch,
                    fields.restart_cut_height,
                    fields.restart_cut_block_id,
                    fields.restart_cut_state_root,
                    fields.restart_cut_chain_root,
                ) {
                    return Err(RecoveryErrorV1::InvalidCutGeometry(
                        "zero-delta terminal cut differs from RestartCut",
                    ));
                }
            }
            RecoveryModeV1::NonZeroDelta => {
                if fields.terminal_epoch < fields.restart_cut_epoch
                    || fields.terminal_height <= fields.restart_cut_height
                    || fields.terminal_block_id == fields.restart_cut_block_id
                    || fields.terminal_chain_root == fields.restart_cut_chain_root
                {
                    return Err(RecoveryErrorV1::InvalidCutGeometry(
                        "nonzero-delta terminal cut does not advance RestartCut",
                    ));
                }
            }
        }
        Ok(())
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        let fields = self.fields;
        encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
        encoder.u8(fields.mode.into());
        encoder.fixed(&fields.campaign_context_sha256);
        encoder.fixed(&fields.fleet_start_certificate_sha256);
        encoder.fixed(fields.validator_set_id.as_bytes());
        encoder.fixed(&fields.validator_set_artifact_sha256);
        encoder.fixed(&fields.restart_cut_artifact_sha256);
        encoder.fixed(&fields.restart_park_artifact_sha256);
        encoder.fixed(&fields.restart_parked_ack_artifact_sha256);
        encoder.fixed(&fields.restart_parked_ack_admission_set_sha256);
        encoder.fixed(&fields.caught_up_cut_artifact_sha256);
        encoder.bytes(fields.target_validator.as_bytes());
        encoder.u64(fields.process_instance);
        encoder.fixed(&fields.recovery_nonce);
        encoder.u64(fields.restart_cut_epoch.get());
        encoder.u64(fields.restart_cut_height.get());
        encoder.fixed(fields.restart_cut_block_id.as_bytes());
        encoder.fixed(fields.restart_cut_state_root.as_bytes());
        encoder.fixed(&fields.restart_cut_chain_root);
        encoder.u64(fields.terminal_epoch.get());
        encoder.u64(fields.terminal_height.get());
        encoder.fixed(fields.terminal_block_id.as_bytes());
        encoder.fixed(fields.terminal_state_root.as_bytes());
        encoder.fixed(&fields.terminal_chain_root);
        encoder.fixed(&fields.node_facts_sha256);
    }
}

/// Exhaustive facts for one exact stop-the-world zero-delta cut.
///
/// The source and terminal coordinates are both encoded and must be byte-for-byte
/// equal across epoch, height, block, state, and finalized-chain-root.  The
/// opaque artifact digests are supplied by upper-layer consuming owners.  This
/// inert value contains no signer, journal, checkpoint, Core, timer, catch-up,
/// or activation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryZeroDeltaCutV1Fields {
    pub campaign_context_sha256: [u8; 32],
    pub fleet_start_certificate_sha256: [u8; 32],
    pub validator_set_id: ValidatorSetId,
    pub validator_set_artifact_sha256: [u8; 32],
    pub restart_cut_artifact_sha256: [u8; 32],
    pub restart_park_artifact_sha256: [u8; 32],
    pub restart_parked_ack_artifact_sha256: [u8; 32],
    pub restart_parked_ack_admission_set_sha256: [u8; 32],
    pub target_validator: ValidatorId,
    pub process_instance: u64,
    pub recovery_nonce: [u8; 32],
    pub node_facts_sha256: [u8; 32],
    pub signer_inventory_invariant_sha256: [u8; 32],
    pub source_epoch: Epoch,
    pub source_height: Height,
    pub source_block_id: BlockId,
    pub source_state_root: StateRoot,
    pub source_finalized_chain_root: [u8; 32],
    pub terminal_epoch: Epoch,
    pub terminal_height: Height,
    pub terminal_block_id: BlockId,
    pub terminal_state_root: StateRoot,
    pub terminal_finalized_chain_root: [u8; 32],
    pub terminal_application_commit_sha256: [u8; 32],
    pub terminal_checkpoint_canonical_sha256: [u8; 32],
}

/// Canonical, inert proof vocabulary for an exact zero-delta recovery cut.
///
/// This type is deliberately distinct from [`RecoveryCaughtUpCutV1`], whose
/// constructor requires a height-advancing nonzero passive catch-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryZeroDeltaCutV1 {
    fields: RecoveryZeroDeltaCutV1Fields,
}

impl RecoveryZeroDeltaCutV1 {
    pub fn new_direct7(
        fields: RecoveryZeroDeltaCutV1Fields,
        validator_set: &ValidatorSet,
    ) -> RecoveryResultV1<Self> {
        let value = Self { fields };
        value.validate_direct7(validator_set)?;
        Ok(value)
    }

    pub const fn fields(&self) -> RecoveryZeroDeltaCutV1Fields {
        self.fields
    }

    pub const fn restart_park_artifact_sha256(&self) -> [u8; 32] {
        self.fields.restart_park_artifact_sha256
    }

    pub const fn restart_parked_ack_artifact_sha256(&self) -> [u8; 32] {
        self.fields.restart_parked_ack_artifact_sha256
    }

    pub const fn restart_parked_ack_admission_set_sha256(&self) -> [u8; 32] {
        self.fields.restart_parked_ack_admission_set_sha256
    }

    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_RECOVERY_ZERO_DELTA_CUT_V1, |encoder| {
            self.encode_cev1(encoder);
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "RecoveryZeroDeltaCutV1",
            MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn validate_direct7(&self, validator_set: &ValidatorSet) -> RecoveryResultV1<()> {
        validator_set
            .validate_shape()
            .map_err(|_| RecoveryErrorV1::InvalidValidatorSet)?;
        let actual = validator_set.validators().len();
        if actual != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            return Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual,
                expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
            });
        }

        let fields = self.fields;
        if fields.validator_set_id != validator_set.id() {
            return Err(RecoveryErrorV1::WrongValidatorSet);
        }
        if validator_set.validator(fields.target_validator).is_none() {
            return Err(RecoveryErrorV1::UnknownTarget);
        }
        if fields.process_instance != RECOVERY_PROCESS_INSTANCE_V1 {
            return Err(RecoveryErrorV1::InvalidProcessInstance {
                actual: fields.process_instance,
                expected: RECOVERY_PROCESS_INSTANCE_V1,
            });
        }
        for (field, digest) in [
            ("campaign context SHA-256", fields.campaign_context_sha256),
            (
                "FleetStart certificate SHA-256",
                fields.fleet_start_certificate_sha256,
            ),
            ("validator-set ID", *fields.validator_set_id.as_bytes()),
            (
                "validator-set artifact SHA-256",
                fields.validator_set_artifact_sha256,
            ),
            (
                "RestartCut artifact SHA-256",
                fields.restart_cut_artifact_sha256,
            ),
            (
                "RestartPark artifact SHA-256",
                fields.restart_park_artifact_sha256,
            ),
            (
                "RestartParkedAck artifact SHA-256",
                fields.restart_parked_ack_artifact_sha256,
            ),
            (
                "RestartParkedAck admission-set SHA-256",
                fields.restart_parked_ack_admission_set_sha256,
            ),
            ("recovery nonce", fields.recovery_nonce),
            ("Node facts SHA-256", fields.node_facts_sha256),
            (
                "signer-inventory invariant SHA-256",
                fields.signer_inventory_invariant_sha256,
            ),
            ("source block ID", *fields.source_block_id.as_bytes()),
            ("source state root", *fields.source_state_root.as_bytes()),
            (
                "source finalized-chain root",
                fields.source_finalized_chain_root,
            ),
            ("terminal block ID", *fields.terminal_block_id.as_bytes()),
            (
                "terminal state root",
                *fields.terminal_state_root.as_bytes(),
            ),
            (
                "terminal finalized-chain root",
                fields.terminal_finalized_chain_root,
            ),
            (
                "terminal application-commit SHA-256",
                fields.terminal_application_commit_sha256,
            ),
            (
                "terminal checkpoint canonical SHA-256",
                fields.terminal_checkpoint_canonical_sha256,
            ),
        ] {
            if digest == [0; 32] {
                return Err(RecoveryErrorV1::ZeroDigest(field));
            }
        }

        if fields.source_height.get() == 0 || fields.terminal_height.get() == 0 {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "zero-delta heights must be positive",
            ));
        }
        if fields.source_epoch != validator_set.epoch()
            || fields.terminal_epoch != validator_set.epoch()
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "zero-delta source and terminal epochs must equal the validator-set epoch",
            ));
        }
        if (
            fields.terminal_epoch,
            fields.terminal_height,
            fields.terminal_block_id,
            fields.terminal_state_root,
            fields.terminal_finalized_chain_root,
        ) != (
            fields.source_epoch,
            fields.source_height,
            fields.source_block_id,
            fields.source_state_root,
            fields.source_finalized_chain_root,
        ) {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "zero-delta terminal cut differs from source cut",
            ));
        }
        Ok(())
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        let fields = self.fields;
        encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
        encoder.fixed(&fields.campaign_context_sha256);
        encoder.fixed(&fields.fleet_start_certificate_sha256);
        encoder.fixed(fields.validator_set_id.as_bytes());
        encoder.fixed(&fields.validator_set_artifact_sha256);
        encoder.fixed(&fields.restart_cut_artifact_sha256);
        encoder.fixed(&fields.restart_park_artifact_sha256);
        encoder.fixed(&fields.restart_parked_ack_artifact_sha256);
        encoder.fixed(&fields.restart_parked_ack_admission_set_sha256);
        encoder.bytes(fields.target_validator.as_bytes());
        encoder.u64(fields.process_instance);
        encoder.fixed(&fields.recovery_nonce);
        encoder.fixed(&fields.node_facts_sha256);
        encoder.fixed(&fields.signer_inventory_invariant_sha256);
        encoder.u64(fields.source_epoch.get());
        encoder.u64(fields.source_height.get());
        encoder.fixed(fields.source_block_id.as_bytes());
        encoder.fixed(fields.source_state_root.as_bytes());
        encoder.fixed(&fields.source_finalized_chain_root);
        encoder.u64(fields.terminal_epoch.get());
        encoder.u64(fields.terminal_height.get());
        encoder.fixed(fields.terminal_block_id.as_bytes());
        encoder.fixed(fields.terminal_state_root.as_bytes());
        encoder.fixed(&fields.terminal_finalized_chain_root);
        encoder.fixed(&fields.terminal_application_commit_sha256);
        encoder.fixed(&fields.terminal_checkpoint_canonical_sha256);
    }
}

/// Exhaustive facts for one nonzero passive catch-up cut.
///
/// The last-certified coordinate may be ahead of the locally finalized and
/// application-applied terminal coordinate, but never behind it.  The opaque
/// `signer_inventory_invariant_sha256` is the upper layer's canonical digest
/// of the exact equality facts proving that passive catch-up did not consume
/// or advance signer inventory.  This crate binds that digest but grants no
/// signer, catch-up, finalization, checkpoint, journal, or activation ability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryCaughtUpCutV1Fields {
    pub campaign_context_sha256: [u8; 32],
    pub fleet_start_certificate_sha256: [u8; 32],
    pub validator_set_id: ValidatorSetId,
    pub validator_set_artifact_sha256: [u8; 32],
    pub restart_cut_artifact_sha256: [u8; 32],
    pub restart_park_artifact_sha256: [u8; 32],
    pub target_validator: ValidatorId,
    pub process_instance: u64,
    pub recovery_nonce: [u8; 32],
    pub catchup_bundle_artifact_sha256: [u8; 32],
    pub node_facts_sha256: [u8; 32],
    pub signer_inventory_invariant_sha256: [u8; 32],
    pub restart_cut_epoch: Epoch,
    pub restart_cut_height: Height,
    pub restart_cut_block_id: BlockId,
    pub restart_cut_state_root: StateRoot,
    pub restart_cut_chain_root: [u8; 32],
    pub last_certified_epoch: Epoch,
    pub last_certified_height: Height,
    pub last_certified_block_id: BlockId,
    pub last_certified_qc_digest: CertificateId,
    pub terminal_epoch: Epoch,
    pub terminal_height: Height,
    pub terminal_block_id: BlockId,
    pub terminal_state_root: StateRoot,
    pub terminal_chain_root: [u8; 32],
    pub terminal_application_commit_sha256: [u8; 32],
    pub terminal_checkpoint_sha256: [u8; 32],
}

/// Canonical, inert proof vocabulary for one exact nonzero caught-up cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryCaughtUpCutV1 {
    fields: RecoveryCaughtUpCutV1Fields,
}

impl RecoveryCaughtUpCutV1 {
    pub fn new_direct7(
        fields: RecoveryCaughtUpCutV1Fields,
        validator_set: &ValidatorSet,
    ) -> RecoveryResultV1<Self> {
        let value = Self { fields };
        value.validate_direct7(validator_set)?;
        Ok(value)
    }

    pub const fn fields(&self) -> RecoveryCaughtUpCutV1Fields {
        self.fields
    }

    pub const fn restart_park_artifact_sha256(&self) -> [u8; 32] {
        self.fields.restart_park_artifact_sha256
    }

    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_RECOVERY_CAUGHT_UP_CUT_V1, |encoder| {
            self.encode_cev1(encoder);
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "RecoveryCaughtUpCutV1",
            MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn validate_direct7(&self, validator_set: &ValidatorSet) -> RecoveryResultV1<()> {
        validator_set
            .validate_shape()
            .map_err(|_| RecoveryErrorV1::InvalidValidatorSet)?;
        let actual = validator_set.validators().len();
        if actual != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
            return Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual,
                expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
            });
        }

        let fields = self.fields;
        if fields.validator_set_id != validator_set.id() {
            return Err(RecoveryErrorV1::WrongValidatorSet);
        }
        if validator_set.validator(fields.target_validator).is_none() {
            return Err(RecoveryErrorV1::UnknownTarget);
        }
        if fields.process_instance != RECOVERY_PROCESS_INSTANCE_V1 {
            return Err(RecoveryErrorV1::InvalidProcessInstance {
                actual: fields.process_instance,
                expected: RECOVERY_PROCESS_INSTANCE_V1,
            });
        }
        for (field, digest) in [
            ("campaign context SHA-256", fields.campaign_context_sha256),
            (
                "FleetStart certificate SHA-256",
                fields.fleet_start_certificate_sha256,
            ),
            ("validator-set ID", *fields.validator_set_id.as_bytes()),
            (
                "validator-set artifact SHA-256",
                fields.validator_set_artifact_sha256,
            ),
            (
                "RestartCut artifact SHA-256",
                fields.restart_cut_artifact_sha256,
            ),
            (
                "RestartPark artifact SHA-256",
                fields.restart_park_artifact_sha256,
            ),
            ("recovery nonce", fields.recovery_nonce),
            (
                "catch-up bundle artifact SHA-256",
                fields.catchup_bundle_artifact_sha256,
            ),
            ("Node facts SHA-256", fields.node_facts_sha256),
            (
                "signer-inventory invariant SHA-256",
                fields.signer_inventory_invariant_sha256,
            ),
            (
                "RestartCut block ID",
                *fields.restart_cut_block_id.as_bytes(),
            ),
            (
                "RestartCut state root",
                *fields.restart_cut_state_root.as_bytes(),
            ),
            ("RestartCut chain root", fields.restart_cut_chain_root),
            (
                "last-certified block ID",
                *fields.last_certified_block_id.as_bytes(),
            ),
            (
                "last-certified QC digest",
                *fields.last_certified_qc_digest.as_bytes(),
            ),
            ("terminal block ID", *fields.terminal_block_id.as_bytes()),
            (
                "terminal state root",
                *fields.terminal_state_root.as_bytes(),
            ),
            ("terminal chain root", fields.terminal_chain_root),
            (
                "terminal application-commit SHA-256",
                fields.terminal_application_commit_sha256,
            ),
            (
                "terminal checkpoint SHA-256",
                fields.terminal_checkpoint_sha256,
            ),
        ] {
            if digest == [0; 32] {
                return Err(RecoveryErrorV1::ZeroDigest(field));
            }
        }

        let set_epoch = validator_set.epoch();
        if fields.restart_cut_epoch != set_epoch
            || fields.last_certified_epoch != set_epoch
            || fields.terminal_epoch != set_epoch
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "RestartCut, last-certified, and terminal epochs must equal the validator-set epoch",
            ));
        }
        if fields.restart_cut_height.get() == 0
            || fields.terminal_height.get() == 0
            || fields.last_certified_height.get() == 0
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "caught-up heights must be positive",
            ));
        }
        if fields.terminal_height <= fields.restart_cut_height {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "terminal applied height does not advance RestartCut",
            ));
        }
        if fields.last_certified_height < fields.terminal_height {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "last-certified height is behind terminal applied height",
            ));
        }
        if fields.terminal_block_id == fields.restart_cut_block_id
            || fields.last_certified_block_id == fields.restart_cut_block_id
            || fields.terminal_chain_root == fields.restart_cut_chain_root
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "caught-up terminal does not differ from RestartCut",
            ));
        }
        if (fields.last_certified_height == fields.terminal_height)
            != (fields.last_certified_block_id == fields.terminal_block_id)
        {
            return Err(RecoveryErrorV1::InvalidCutGeometry(
                "last-certified and terminal coordinates disagree",
            ));
        }
        Ok(())
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        let fields = self.fields;
        encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
        encoder.fixed(&fields.campaign_context_sha256);
        encoder.fixed(&fields.fleet_start_certificate_sha256);
        encoder.fixed(fields.validator_set_id.as_bytes());
        encoder.fixed(&fields.validator_set_artifact_sha256);
        encoder.fixed(&fields.restart_cut_artifact_sha256);
        encoder.fixed(&fields.restart_park_artifact_sha256);
        encoder.bytes(fields.target_validator.as_bytes());
        encoder.u64(fields.process_instance);
        encoder.fixed(&fields.recovery_nonce);
        encoder.fixed(&fields.catchup_bundle_artifact_sha256);
        encoder.fixed(&fields.node_facts_sha256);
        encoder.fixed(&fields.signer_inventory_invariant_sha256);
        encoder.u64(fields.restart_cut_epoch.get());
        encoder.u64(fields.restart_cut_height.get());
        encoder.fixed(fields.restart_cut_block_id.as_bytes());
        encoder.fixed(fields.restart_cut_state_root.as_bytes());
        encoder.fixed(&fields.restart_cut_chain_root);
        encoder.u64(fields.last_certified_epoch.get());
        encoder.u64(fields.last_certified_height.get());
        encoder.fixed(fields.last_certified_block_id.as_bytes());
        encoder.fixed(fields.last_certified_qc_digest.as_bytes());
        encoder.u64(fields.terminal_epoch.get());
        encoder.u64(fields.terminal_height.get());
        encoder.fixed(fields.terminal_block_id.as_bytes());
        encoder.fixed(fields.terminal_state_root.as_bytes());
        encoder.fixed(&fields.terminal_chain_root);
        encoder.fixed(&fields.terminal_application_commit_sha256);
        encoder.fixed(&fields.terminal_checkpoint_sha256);
    }
}

/// One independently authenticated Ready statement for an exact context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecoveryReadyV1 {
    context: RecoveryContextV1,
    origin: ValidatorId,
    signature: Signature64,
}

impl SignedRecoveryReadyV1 {
    /// Constructs only after authenticating externally supplied signature
    /// bytes.  Signing itself remains outside this crate.
    pub fn from_signature<V: SignatureVerifier>(
        context: RecoveryContextV1,
        origin: ValidatorId,
        signature: Signature64,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<Self> {
        let value = Self {
            context,
            origin,
            signature,
        };
        value.verify(validator_set, verifier)?;
        Ok(value)
    }

    pub fn from_signature_bytes<V: SignatureVerifier>(
        context: RecoveryContextV1,
        origin: ValidatorId,
        signature_bytes: &[u8],
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<Self> {
        let signature = Signature64::from_slice(signature_bytes)
            .map_err(|_| RecoveryErrorV1::InvalidSignatureBytes)?;
        Self::from_signature(context, origin, signature, validator_set, verifier)
    }

    pub const fn context(&self) -> &RecoveryContextV1 {
        &self.context
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn signature(&self) -> &Signature64 {
        &self.signature
    }

    /// Root an external signer must sign.  This computes inert bytes only.
    pub fn signing_root_for(context: &RecoveryContextV1, origin: ValidatorId) -> SigningRoot {
        signing_root(DOMAIN_RECOVERY_READY_V1, |encoder| {
            encode_ready_signing_preimage(encoder, context, origin);
        })
    }

    pub fn signing_root(&self) -> SigningRoot {
        Self::signing_root_for(&self.context, self.origin)
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "SignedRecoveryReadyV1",
            MAX_SIGNED_RECOVERY_READY_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<()> {
        self.context.validate_direct7(validator_set)?;
        let validator = validator_set
            .validator(self.origin)
            .ok_or_else(|| RecoveryErrorV1::UnknownSigner(Box::new(self.origin)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(RecoveryErrorV1::InvalidSignature(Box::new(self.origin)));
        }
        Ok(())
    }

    fn verify_for_context<V: SignatureVerifier>(
        &self,
        expected_context: &RecoveryContextV1,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<()> {
        if &self.context != expected_context {
            return Err(RecoveryErrorV1::ContextMismatch);
        }
        self.verify(validator_set, verifier)
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        encode_ready_signing_preimage(encoder, &self.context, self.origin);
        encoder.fixed(self.signature.as_bytes());
    }
}

impl CanonicalSignable for SignedRecoveryReadyV1 {
    fn signing_root(&self) -> SigningRoot {
        SignedRecoveryReadyV1::signing_root(self)
    }
}

/// Full direct-7 Ready barrier in canonical ValidatorSet order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReadySetV1 {
    context: RecoveryContextV1,
    statements: Vec<SignedRecoveryReadyV1>,
}

impl RecoveryReadySetV1 {
    pub fn new(
        context: RecoveryContextV1,
        statements: Vec<SignedRecoveryReadyV1>,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> RecoveryResultV1<Self> {
        validate_ready_statements(&context, &statements, validator_set, verifier)?;
        Ok(Self {
            context,
            statements,
        })
    }

    pub const fn context(&self) -> &RecoveryContextV1 {
        &self.context
    }

    pub fn statements(&self) -> &[SignedRecoveryReadyV1] {
        &self.statements
    }

    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedRecoveryReadyV1> {
        self.statements
            .binary_search_by_key(&origin, SignedRecoveryReadyV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_RECOVERY_READY_SET_V1, |encoder| {
            self.encode_cev1(encoder);
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "RecoveryReadySetV1",
            MAX_RECOVERY_READY_SET_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn verify(
        &self,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> RecoveryResultV1<()> {
        validate_ready_statements(&self.context, &self.statements, validator_set, verifier)
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
        self.context.encode_cev1(encoder);
        encoder.list_len(self.statements.len());
        for statement in &self.statements {
            statement.encode_cev1(encoder);
        }
    }
}

/// One independently authenticated Start statement over one full ReadySet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecoveryStartV1 {
    context: RecoveryContextV1,
    origin: ValidatorId,
    ready_set_digest: [u8; 32],
    signature: Signature64,
}

impl SignedRecoveryStartV1 {
    /// Constructs only from a complete ReadySet and externally supplied
    /// signature.  There is deliberately no constructor taking a caller-
    /// asserted ReadySet digest.
    pub fn from_signature<V: SignatureVerifier>(
        ready_set: &RecoveryReadySetV1,
        origin: ValidatorId,
        signature: Signature64,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<Self> {
        ready_set.verify(validator_set, verifier)?;
        let value = Self {
            context: *ready_set.context(),
            origin,
            ready_set_digest: ready_set.digest(),
            signature,
        };
        value.verify(ready_set, validator_set, verifier)?;
        Ok(value)
    }

    pub fn from_signature_bytes<V: SignatureVerifier>(
        ready_set: &RecoveryReadySetV1,
        origin: ValidatorId,
        signature_bytes: &[u8],
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<Self> {
        let signature = Signature64::from_slice(signature_bytes)
            .map_err(|_| RecoveryErrorV1::InvalidSignatureBytes)?;
        Self::from_signature(ready_set, origin, signature, validator_set, verifier)
    }

    pub const fn context(&self) -> &RecoveryContextV1 {
        &self.context
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn ready_set_digest(&self) -> [u8; 32] {
        self.ready_set_digest
    }

    pub const fn signature(&self) -> &Signature64 {
        &self.signature
    }

    /// Root an external signer must sign.  The complete ReadySet, rather than
    /// a free caller scalar, is required to derive it.
    pub fn signing_root_for(ready_set: &RecoveryReadySetV1, origin: ValidatorId) -> SigningRoot {
        let ready_set_digest = ready_set.digest();
        signing_root(DOMAIN_RECOVERY_START_V1, |encoder| {
            encode_start_signing_preimage(encoder, ready_set.context(), origin, &ready_set_digest);
        })
    }

    pub fn signing_root(&self) -> SigningRoot {
        signing_root(DOMAIN_RECOVERY_START_V1, |encoder| {
            encode_start_signing_preimage(
                encoder,
                &self.context,
                self.origin,
                &self.ready_set_digest,
            );
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "SignedRecoveryStartV1",
            MAX_SIGNED_RECOVERY_START_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        ready_set: &RecoveryReadySetV1,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> RecoveryResultV1<()> {
        ready_set.verify(validator_set, verifier)?;
        if self.context != *ready_set.context() {
            return Err(RecoveryErrorV1::ContextMismatch);
        }
        if self.ready_set_digest != ready_set.digest() {
            return Err(RecoveryErrorV1::ReadySetMismatch);
        }
        let validator = validator_set
            .validator(self.origin)
            .ok_or_else(|| RecoveryErrorV1::UnknownSigner(Box::new(self.origin)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(RecoveryErrorV1::InvalidSignature(Box::new(self.origin)));
        }
        Ok(())
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        encode_start_signing_preimage(encoder, &self.context, self.origin, &self.ready_set_digest);
        encoder.fixed(self.signature.as_bytes());
    }
}

impl CanonicalSignable for SignedRecoveryStartV1 {
    fn signing_root(&self) -> SigningRoot {
        SignedRecoveryStartV1::signing_root(self)
    }
}

/// Full direct-7 Start certificate retaining and binding the complete ReadySet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryStartCertificateV1 {
    ready_set: RecoveryReadySetV1,
    statements: Vec<SignedRecoveryStartV1>,
}

impl RecoveryStartCertificateV1 {
    pub fn new(
        ready_set: RecoveryReadySetV1,
        statements: Vec<SignedRecoveryStartV1>,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> RecoveryResultV1<Self> {
        validate_start_statements(&ready_set, &statements, validator_set, verifier)?;
        Ok(Self {
            ready_set,
            statements,
        })
    }

    pub const fn ready_set(&self) -> &RecoveryReadySetV1 {
        &self.ready_set
    }

    pub const fn context(&self) -> &RecoveryContextV1 {
        self.ready_set.context()
    }

    pub fn statements(&self) -> &[SignedRecoveryStartV1] {
        &self.statements
    }

    pub const fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedRecoveryStartV1> {
        self.statements
            .binary_search_by_key(&origin, SignedRecoveryStartV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_RECOVERY_START_CERTIFICATE_V1, |encoder| {
            self.encode_cev1(encoder);
        })
    }

    pub fn try_cev1_bytes(&self) -> RecoveryResultV1<Vec<u8>> {
        encode_bounded(
            "RecoveryStartCertificateV1",
            MAX_RECOVERY_START_CERTIFICATE_BYTES_V1,
            |encoder| self.encode_cev1(encoder),
        )
    }

    pub fn verify(
        &self,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> RecoveryResultV1<()> {
        validate_start_statements(&self.ready_set, &self.statements, validator_set, verifier)
    }

    fn encode_cev1(&self, encoder: &mut Encoder) {
        encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
        self.ready_set.encode_cev1(encoder);
        encoder.list_len(self.statements.len());
        for statement in &self.statements {
            statement.encode_cev1(encoder);
        }
    }
}

pub fn decode_recovery_context_v1_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryContextV1> {
    require_bounded_wire("RecoveryContextV1", bytes, MAX_RECOVERY_CONTEXT_BYTES_V1)?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_context(&mut cursor, validator_set)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

pub fn decode_recovery_zero_delta_cut_v1_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryZeroDeltaCutV1> {
    require_bounded_wire(
        "RecoveryZeroDeltaCutV1",
        bytes,
        MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
    )?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_zero_delta_cut(&mut cursor, validator_set)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

pub fn decode_recovery_caught_up_cut_v1_exact(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryCaughtUpCutV1> {
    require_bounded_wire(
        "RecoveryCaughtUpCutV1",
        bytes,
        MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1,
    )?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_caught_up_cut(&mut cursor, validator_set)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

pub fn decode_signed_recovery_ready_v1_exact<V: SignatureVerifier>(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<SignedRecoveryReadyV1> {
    require_bounded_wire(
        "SignedRecoveryReadyV1",
        bytes,
        MAX_SIGNED_RECOVERY_READY_BYTES_V1,
    )?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_signed_ready(&mut cursor, validator_set, verifier)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

pub fn decode_recovery_ready_set_v1_exact<V: SignatureVerifier>(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<RecoveryReadySetV1> {
    require_bounded_wire("RecoveryReadySetV1", bytes, MAX_RECOVERY_READY_SET_BYTES_V1)?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_ready_set(&mut cursor, validator_set, verifier)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

/// Exact-decodes one Start statement only after joining the complete ReadySet
/// it claims to bind.
pub fn decode_signed_recovery_start_v1_exact<V: SignatureVerifier>(
    bytes: &[u8],
    ready_set: &RecoveryReadySetV1,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<SignedRecoveryStartV1> {
    require_bounded_wire(
        "SignedRecoveryStartV1",
        bytes,
        MAX_SIGNED_RECOVERY_START_BYTES_V1,
    )?;
    ready_set.verify(validator_set, verifier)?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    let value = parse_signed_start(&mut cursor, ready_set, validator_set, verifier)?;
    cursor.finish()?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

pub fn decode_recovery_start_certificate_v1_exact<V: SignatureVerifier>(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<RecoveryStartCertificateV1> {
    require_bounded_wire(
        "RecoveryStartCertificateV1",
        bytes,
        MAX_RECOVERY_START_CERTIFICATE_BYTES_V1,
    )?;
    let mut cursor = RecoveryCursorV1::new(bytes);
    require_schema(&mut cursor)?;
    let ready_set = parse_ready_set(&mut cursor, validator_set, verifier)?;
    let count = cursor.list_len()?;
    if count != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        return Err(RecoveryErrorV1::Incomplete {
            actual: count,
            expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        });
    }
    let mut statements = Vec::with_capacity(DIRECT7_RECOVERY_VALIDATOR_COUNT_V1);
    for _ in 0..DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        statements.push(parse_signed_start(
            &mut cursor,
            &ready_set,
            validator_set,
            verifier,
        )?);
    }
    cursor.finish()?;
    let value = RecoveryStartCertificateV1::new(ready_set, statements, validator_set, verifier)?;
    require_canonical(bytes, value.try_cev1_bytes()?)?;
    Ok(value)
}

fn validate_ready_statements<V: SignatureVerifier>(
    context: &RecoveryContextV1,
    statements: &[SignedRecoveryReadyV1],
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<()> {
    context.validate_direct7(validator_set)?;
    if statements.len() != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        return Err(RecoveryErrorV1::Incomplete {
            actual: statements.len(),
            expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        });
    }
    for (index, statement) in statements.iter().enumerate() {
        for prior in &statements[..index] {
            if statement.origin == prior.origin {
                return if statement.context == prior.context {
                    Err(RecoveryErrorV1::DuplicateSigner(Box::new(statement.origin)))
                } else {
                    Err(RecoveryErrorV1::Equivocation(Box::new(statement.origin)))
                };
            }
        }
    }
    for statement in statements {
        statement.verify_for_context(context, validator_set, verifier)?;
    }
    if statements
        .iter()
        .zip(validator_set.validators())
        .any(|(statement, validator)| statement.origin != validator.id())
    {
        return Err(RecoveryErrorV1::NonCanonicalSignerOrder);
    }
    Ok(())
}

fn validate_start_statements<V: SignatureVerifier>(
    ready_set: &RecoveryReadySetV1,
    statements: &[SignedRecoveryStartV1],
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<()> {
    ready_set.verify(validator_set, verifier)?;
    if statements.len() != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        return Err(RecoveryErrorV1::Incomplete {
            actual: statements.len(),
            expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        });
    }
    for (index, statement) in statements.iter().enumerate() {
        for prior in &statements[..index] {
            if statement.origin == prior.origin {
                return if statement.context == prior.context
                    && statement.ready_set_digest == prior.ready_set_digest
                {
                    Err(RecoveryErrorV1::DuplicateSigner(Box::new(statement.origin)))
                } else {
                    Err(RecoveryErrorV1::Equivocation(Box::new(statement.origin)))
                };
            }
        }
    }
    for statement in statements {
        statement.verify(ready_set, validator_set, verifier)?;
    }
    if statements
        .iter()
        .zip(validator_set.validators())
        .any(|(statement, validator)| statement.origin != validator.id())
    {
        return Err(RecoveryErrorV1::NonCanonicalSignerOrder);
    }
    Ok(())
}

fn encode_ready_signing_preimage(
    encoder: &mut Encoder,
    context: &RecoveryContextV1,
    origin: ValidatorId,
) {
    encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
    context.encode_cev1(encoder);
    encoder.bytes(origin.as_bytes());
}

fn encode_start_signing_preimage(
    encoder: &mut Encoder,
    context: &RecoveryContextV1,
    origin: ValidatorId,
    ready_set_digest: &[u8; 32],
) {
    encoder.u16(RECOVERY_SCHEMA_VERSION_V1);
    context.encode_cev1(encoder);
    encoder.bytes(origin.as_bytes());
    encoder.fixed(ready_set_digest);
}

fn encode_bounded(
    field: &'static str,
    maximum: usize,
    encode: impl FnOnce(&mut Encoder),
) -> RecoveryResultV1<Vec<u8>> {
    let bytes = try_canonical_bytes(encode).map_err(|_| RecoveryErrorV1::EncodingFailure)?;
    if bytes.len() > maximum {
        return Err(RecoveryErrorV1::TooLarge {
            field,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn require_bounded_wire(field: &'static str, bytes: &[u8], maximum: usize) -> RecoveryResultV1<()> {
    if bytes.len() > maximum {
        return Err(RecoveryErrorV1::TooLarge {
            field,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn require_canonical(bytes: &[u8], canonical: Vec<u8>) -> RecoveryResultV1<()> {
    if bytes != canonical {
        return Err(RecoveryErrorV1::NonCanonicalEncoding);
    }
    Ok(())
}

fn require_schema(cursor: &mut RecoveryCursorV1<'_>) -> RecoveryResultV1<()> {
    let actual = cursor.u16()?;
    if actual != RECOVERY_SCHEMA_VERSION_V1 {
        return Err(RecoveryErrorV1::InvalidSchemaVersion {
            actual,
            expected: RECOVERY_SCHEMA_VERSION_V1,
        });
    }
    Ok(())
}

fn parse_context(
    cursor: &mut RecoveryCursorV1<'_>,
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryContextV1> {
    require_schema(cursor)?;
    let fields = RecoveryContextV1Fields {
        mode: RecoveryModeV1::try_from(cursor.u8()?)?,
        campaign_context_sha256: cursor.fixed()?,
        fleet_start_certificate_sha256: cursor.fixed()?,
        validator_set_id: ValidatorSetId::new(cursor.fixed()?),
        validator_set_artifact_sha256: cursor.fixed()?,
        restart_cut_artifact_sha256: cursor.fixed()?,
        restart_park_artifact_sha256: cursor.fixed()?,
        restart_parked_ack_artifact_sha256: cursor.fixed()?,
        restart_parked_ack_admission_set_sha256: cursor.fixed()?,
        caught_up_cut_artifact_sha256: cursor.fixed()?,
        target_validator: cursor.validator_id()?,
        process_instance: cursor.u64()?,
        recovery_nonce: cursor.fixed()?,
        restart_cut_epoch: Epoch::new(cursor.u64()?),
        restart_cut_height: Height::new(cursor.u64()?),
        restart_cut_block_id: BlockId::new(cursor.fixed()?),
        restart_cut_state_root: StateRoot::new(cursor.fixed()?),
        restart_cut_chain_root: cursor.fixed()?,
        terminal_epoch: Epoch::new(cursor.u64()?),
        terminal_height: Height::new(cursor.u64()?),
        terminal_block_id: BlockId::new(cursor.fixed()?),
        terminal_state_root: StateRoot::new(cursor.fixed()?),
        terminal_chain_root: cursor.fixed()?,
        node_facts_sha256: cursor.fixed()?,
    };
    RecoveryContextV1::new_direct7(fields, validator_set)
}

fn parse_zero_delta_cut(
    cursor: &mut RecoveryCursorV1<'_>,
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryZeroDeltaCutV1> {
    require_schema(cursor)?;
    let fields = RecoveryZeroDeltaCutV1Fields {
        campaign_context_sha256: cursor.fixed()?,
        fleet_start_certificate_sha256: cursor.fixed()?,
        validator_set_id: ValidatorSetId::new(cursor.fixed()?),
        validator_set_artifact_sha256: cursor.fixed()?,
        restart_cut_artifact_sha256: cursor.fixed()?,
        restart_park_artifact_sha256: cursor.fixed()?,
        restart_parked_ack_artifact_sha256: cursor.fixed()?,
        restart_parked_ack_admission_set_sha256: cursor.fixed()?,
        target_validator: cursor.validator_id()?,
        process_instance: cursor.u64()?,
        recovery_nonce: cursor.fixed()?,
        node_facts_sha256: cursor.fixed()?,
        signer_inventory_invariant_sha256: cursor.fixed()?,
        source_epoch: Epoch::new(cursor.u64()?),
        source_height: Height::new(cursor.u64()?),
        source_block_id: BlockId::new(cursor.fixed()?),
        source_state_root: StateRoot::new(cursor.fixed()?),
        source_finalized_chain_root: cursor.fixed()?,
        terminal_epoch: Epoch::new(cursor.u64()?),
        terminal_height: Height::new(cursor.u64()?),
        terminal_block_id: BlockId::new(cursor.fixed()?),
        terminal_state_root: StateRoot::new(cursor.fixed()?),
        terminal_finalized_chain_root: cursor.fixed()?,
        terminal_application_commit_sha256: cursor.fixed()?,
        terminal_checkpoint_canonical_sha256: cursor.fixed()?,
    };
    RecoveryZeroDeltaCutV1::new_direct7(fields, validator_set)
}

fn parse_caught_up_cut(
    cursor: &mut RecoveryCursorV1<'_>,
    validator_set: &ValidatorSet,
) -> RecoveryResultV1<RecoveryCaughtUpCutV1> {
    require_schema(cursor)?;
    let fields = RecoveryCaughtUpCutV1Fields {
        campaign_context_sha256: cursor.fixed()?,
        fleet_start_certificate_sha256: cursor.fixed()?,
        validator_set_id: ValidatorSetId::new(cursor.fixed()?),
        validator_set_artifact_sha256: cursor.fixed()?,
        restart_cut_artifact_sha256: cursor.fixed()?,
        restart_park_artifact_sha256: cursor.fixed()?,
        target_validator: cursor.validator_id()?,
        process_instance: cursor.u64()?,
        recovery_nonce: cursor.fixed()?,
        catchup_bundle_artifact_sha256: cursor.fixed()?,
        node_facts_sha256: cursor.fixed()?,
        signer_inventory_invariant_sha256: cursor.fixed()?,
        restart_cut_epoch: Epoch::new(cursor.u64()?),
        restart_cut_height: Height::new(cursor.u64()?),
        restart_cut_block_id: BlockId::new(cursor.fixed()?),
        restart_cut_state_root: StateRoot::new(cursor.fixed()?),
        restart_cut_chain_root: cursor.fixed()?,
        last_certified_epoch: Epoch::new(cursor.u64()?),
        last_certified_height: Height::new(cursor.u64()?),
        last_certified_block_id: BlockId::new(cursor.fixed()?),
        last_certified_qc_digest: CertificateId::new(cursor.fixed()?),
        terminal_epoch: Epoch::new(cursor.u64()?),
        terminal_height: Height::new(cursor.u64()?),
        terminal_block_id: BlockId::new(cursor.fixed()?),
        terminal_state_root: StateRoot::new(cursor.fixed()?),
        terminal_chain_root: cursor.fixed()?,
        terminal_application_commit_sha256: cursor.fixed()?,
        terminal_checkpoint_sha256: cursor.fixed()?,
    };
    RecoveryCaughtUpCutV1::new_direct7(fields, validator_set)
}

fn parse_signed_ready<V: SignatureVerifier>(
    cursor: &mut RecoveryCursorV1<'_>,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<SignedRecoveryReadyV1> {
    require_schema(cursor)?;
    let context = parse_context(cursor, validator_set)?;
    let origin = cursor.validator_id()?;
    let signature = Signature64::from_array(cursor.fixed::<SIGNATURE_BYTES>()?);
    SignedRecoveryReadyV1::from_signature(context, origin, signature, validator_set, verifier)
}

fn parse_ready_set<V: SignatureVerifier>(
    cursor: &mut RecoveryCursorV1<'_>,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<RecoveryReadySetV1> {
    require_schema(cursor)?;
    let context = parse_context(cursor, validator_set)?;
    let count = cursor.list_len()?;
    if count != DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        return Err(RecoveryErrorV1::Incomplete {
            actual: count,
            expected: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        });
    }
    let mut statements = Vec::with_capacity(DIRECT7_RECOVERY_VALIDATOR_COUNT_V1);
    for _ in 0..DIRECT7_RECOVERY_VALIDATOR_COUNT_V1 {
        statements.push(parse_signed_ready(cursor, validator_set, verifier)?);
    }
    RecoveryReadySetV1::new(context, statements, validator_set, verifier)
}

fn parse_signed_start<V: SignatureVerifier>(
    cursor: &mut RecoveryCursorV1<'_>,
    ready_set: &RecoveryReadySetV1,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> RecoveryResultV1<SignedRecoveryStartV1> {
    require_schema(cursor)?;
    let context = parse_context(cursor, validator_set)?;
    let origin = cursor.validator_id()?;
    let ready_set_digest = cursor.fixed()?;
    let signature = Signature64::from_array(cursor.fixed::<SIGNATURE_BYTES>()?);
    if context != *ready_set.context() {
        return Err(RecoveryErrorV1::ContextMismatch);
    }
    if ready_set_digest != ready_set.digest() {
        return Err(RecoveryErrorV1::ReadySetMismatch);
    }
    SignedRecoveryStartV1::from_signature(ready_set, origin, signature, validator_set, verifier)
}

struct RecoveryCursorV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> RecoveryResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RecoveryErrorV1::UnexpectedEnd {
                byte_offset: self.offset,
            })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RecoveryErrorV1::UnexpectedEnd {
                byte_offset: self.offset,
            })?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> RecoveryResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| RecoveryErrorV1::UnexpectedEnd {
                byte_offset: self.offset,
            })
    }

    fn u8(&mut self) -> RecoveryResultV1<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> RecoveryResultV1<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> RecoveryResultV1<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> RecoveryResultV1<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn list_len(&mut self) -> RecoveryResultV1<usize> {
        usize::try_from(self.u32()?).map_err(|_| RecoveryErrorV1::TooLarge {
            field: "recovery list",
            actual: usize::MAX,
            maximum: DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        })
    }

    fn validator_id(&mut self) -> RecoveryResultV1<ValidatorId> {
        let byte_offset = self.offset;
        let length = usize::try_from(self.u32()?)
            .map_err(|_| RecoveryErrorV1::InvalidValidatorId { byte_offset })?;
        if length == 0 || length > MAX_VALIDATOR_ID_BYTES {
            return Err(RecoveryErrorV1::InvalidValidatorId { byte_offset });
        }
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| RecoveryErrorV1::InvalidValidatorId { byte_offset })
    }

    fn finish(&self) -> RecoveryResultV1<()> {
        if self.offset != self.bytes.len() {
            return Err(RecoveryErrorV1::TrailingBytes {
                byte_offset: self.offset,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChainId, ConsensusParametersHash, ConsensusPublicKey, GenesisHash, ProtocolVersion,
        SignatureBytes, Validator, VotingPower,
    };

    #[derive(Debug, Clone, Copy)]
    struct BoundVerifier;

    impl SignatureVerifier for BoundVerifier {
        fn verify(
            &self,
            validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == validator.consensus_key().as_bytes()[..]
        }
    }

    fn validator_set(count: usize, key_bias: u8) -> ValidatorSet {
        let validators = (1..=count)
            .map(|index| {
                let byte = u8::try_from(index).unwrap();
                Validator::new(
                    ValidatorId::new([byte; 32]),
                    ConsensusPublicKey::new([byte.wrapping_add(key_bias); 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::from_static("trnm-recovery-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([0x22; 32]),
            validators,
        )
        .unwrap()
    }

    fn zero_delta_fields(set: &ValidatorSet) -> RecoveryContextV1Fields {
        RecoveryContextV1Fields {
            mode: RecoveryModeV1::ZeroDelta,
            campaign_context_sha256: [0x31; 32],
            fleet_start_certificate_sha256: [0x32; 32],
            validator_set_id: set.id(),
            validator_set_artifact_sha256: [0x33; 32],
            restart_cut_artifact_sha256: [0x34; 32],
            restart_park_artifact_sha256: [0x39; 32],
            restart_parked_ack_artifact_sha256: [0x3a; 32],
            restart_parked_ack_admission_set_sha256: [0x3b; 32],
            caught_up_cut_artifact_sha256: [0x35; 32],
            target_validator: set.validators()[0].id(),
            process_instance: RECOVERY_PROCESS_INSTANCE_V1,
            recovery_nonce: [0x36; 32],
            restart_cut_epoch: Epoch::new(4),
            restart_cut_height: Height::new(50),
            restart_cut_block_id: BlockId::new([0x41; 32]),
            restart_cut_state_root: StateRoot::new([0x42; 32]),
            restart_cut_chain_root: [0x43; 32],
            terminal_epoch: Epoch::new(4),
            terminal_height: Height::new(50),
            terminal_block_id: BlockId::new([0x41; 32]),
            terminal_state_root: StateRoot::new([0x42; 32]),
            terminal_chain_root: [0x43; 32],
            node_facts_sha256: [0x44; 32],
        }
    }

    fn zero_delta_cut_fields(set: &ValidatorSet) -> RecoveryZeroDeltaCutV1Fields {
        RecoveryZeroDeltaCutV1Fields {
            campaign_context_sha256: [0x81; 32],
            fleet_start_certificate_sha256: [0x82; 32],
            validator_set_id: set.id(),
            validator_set_artifact_sha256: [0x83; 32],
            restart_cut_artifact_sha256: [0x84; 32],
            restart_park_artifact_sha256: [0x8d; 32],
            restart_parked_ack_artifact_sha256: [0x8e; 32],
            restart_parked_ack_admission_set_sha256: [0x8f; 32],
            target_validator: set.validators()[0].id(),
            process_instance: RECOVERY_PROCESS_INSTANCE_V1,
            recovery_nonce: [0x85; 32],
            node_facts_sha256: [0x86; 32],
            signer_inventory_invariant_sha256: [0x87; 32],
            source_epoch: set.epoch(),
            source_height: Height::new(50),
            source_block_id: BlockId::new([0x88; 32]),
            source_state_root: StateRoot::new([0x89; 32]),
            source_finalized_chain_root: [0x8a; 32],
            terminal_epoch: set.epoch(),
            terminal_height: Height::new(50),
            terminal_block_id: BlockId::new([0x88; 32]),
            terminal_state_root: StateRoot::new([0x89; 32]),
            terminal_finalized_chain_root: [0x8a; 32],
            terminal_application_commit_sha256: [0x8b; 32],
            terminal_checkpoint_canonical_sha256: [0x8c; 32],
        }
    }

    fn caught_up_fields(set: &ValidatorSet) -> RecoveryCaughtUpCutV1Fields {
        RecoveryCaughtUpCutV1Fields {
            campaign_context_sha256: [0x61; 32],
            fleet_start_certificate_sha256: [0x62; 32],
            validator_set_id: set.id(),
            validator_set_artifact_sha256: [0x63; 32],
            restart_cut_artifact_sha256: [0x64; 32],
            restart_park_artifact_sha256: [0x73; 32],
            target_validator: set.validators()[0].id(),
            process_instance: RECOVERY_PROCESS_INSTANCE_V1,
            recovery_nonce: [0x65; 32],
            catchup_bundle_artifact_sha256: [0x66; 32],
            node_facts_sha256: [0x67; 32],
            signer_inventory_invariant_sha256: [0x68; 32],
            restart_cut_epoch: set.epoch(),
            restart_cut_height: Height::new(50),
            restart_cut_block_id: BlockId::new([0x69; 32]),
            restart_cut_state_root: StateRoot::new([0x6a; 32]),
            restart_cut_chain_root: [0x6b; 32],
            last_certified_epoch: set.epoch(),
            last_certified_height: Height::new(54),
            last_certified_block_id: BlockId::new([0x6c; 32]),
            last_certified_qc_digest: CertificateId::new([0x6d; 32]),
            terminal_epoch: set.epoch(),
            terminal_height: Height::new(52),
            terminal_block_id: BlockId::new([0x6e; 32]),
            terminal_state_root: StateRoot::new([0x6f; 32]),
            terminal_chain_root: [0x70; 32],
            terminal_application_commit_sha256: [0x71; 32],
            terminal_checkpoint_sha256: [0x72; 32],
        }
    }

    fn context(set: &ValidatorSet) -> RecoveryContextV1 {
        RecoveryContextV1::new_direct7(zero_delta_fields(set), set).unwrap()
    }

    fn park_alternate_context(set: &ValidatorSet) -> RecoveryContextV1 {
        let mut fields = zero_delta_fields(set);
        fields.restart_park_artifact_sha256 = [0x91; 32];
        RecoveryContextV1::new_direct7(fields, set).unwrap()
    }

    fn parked_ack_alternate_contexts(set: &ValidatorSet) -> [(&'static str, RecoveryContextV1); 2] {
        let mut artifact_fields = zero_delta_fields(set);
        artifact_fields.restart_parked_ack_artifact_sha256 = [0x92; 32];
        let mut admission_fields = zero_delta_fields(set);
        admission_fields.restart_parked_ack_admission_set_sha256 = [0x93; 32];
        [
            (
                "restart ParkedAck artifact SHA-256",
                RecoveryContextV1::new_direct7(artifact_fields, set).unwrap(),
            ),
            (
                "restart ParkedAck admission-set SHA-256",
                RecoveryContextV1::new_direct7(admission_fields, set).unwrap(),
            ),
        ]
    }

    fn signature_for(set: &ValidatorSet, origin: ValidatorId, root: SigningRoot) -> Signature64 {
        let validator = set.validator(origin).unwrap();
        let mut bytes = [0u8; SIGNATURE_BYTES];
        bytes[..32].copy_from_slice(root.as_bytes());
        bytes[32..].copy_from_slice(validator.consensus_key().as_bytes());
        Signature64::from_array(bytes)
    }

    fn ready(
        context: RecoveryContextV1,
        origin: ValidatorId,
        set: &ValidatorSet,
    ) -> SignedRecoveryReadyV1 {
        let root = SignedRecoveryReadyV1::signing_root_for(&context, origin);
        SignedRecoveryReadyV1::from_signature(
            context,
            origin,
            signature_for(set, origin, root),
            set,
            &BoundVerifier,
        )
        .unwrap()
    }

    fn ready_statements(
        context: RecoveryContextV1,
        set: &ValidatorSet,
    ) -> Vec<SignedRecoveryReadyV1> {
        set.validators()
            .iter()
            .map(|validator| ready(context, validator.id(), set))
            .collect()
    }

    fn ready_set(context: RecoveryContextV1, set: &ValidatorSet) -> RecoveryReadySetV1 {
        RecoveryReadySetV1::new(context, ready_statements(context, set), set, &BoundVerifier)
            .unwrap()
    }

    fn start(
        ready_set: &RecoveryReadySetV1,
        origin: ValidatorId,
        set: &ValidatorSet,
    ) -> SignedRecoveryStartV1 {
        let root = SignedRecoveryStartV1::signing_root_for(ready_set, origin);
        SignedRecoveryStartV1::from_signature(
            ready_set,
            origin,
            signature_for(set, origin, root),
            set,
            &BoundVerifier,
        )
        .unwrap()
    }

    fn start_statements(
        ready_set: &RecoveryReadySetV1,
        set: &ValidatorSet,
    ) -> Vec<SignedRecoveryStartV1> {
        set.validators()
            .iter()
            .map(|validator| start(ready_set, validator.id(), set))
            .collect()
    }

    #[test]
    fn zero_delta_context_round_trips_and_binds_exact_cut() {
        let set = validator_set(7, 0x20);
        let context = context(&set);
        let raw = context.try_cev1_bytes().unwrap();
        let decoded = decode_recovery_context_v1_exact(&raw, &set).unwrap();

        assert_eq!(decoded, context);
        assert_eq!(decoded.mode(), RecoveryModeV1::ZeroDelta);
        assert_eq!(decoded.validator_set_id(), set.id());
        assert_eq!(decoded.process_instance(), 2);
        assert_eq!(
            decoded.restart_park_artifact_sha256(),
            context.fields().restart_park_artifact_sha256
        );
        assert_eq!(
            decoded.restart_parked_ack_artifact_sha256(),
            context.fields().restart_parked_ack_artifact_sha256
        );
        assert_eq!(
            decoded.restart_parked_ack_admission_set_sha256(),
            context.fields().restart_parked_ack_admission_set_sha256
        );
        assert_eq!(decoded.restart_cut_height(), decoded.terminal_height());
        assert_ne!(decoded.digest(), [0; 32]);

        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            decode_recovery_context_v1_exact(&trailing, &set),
            Err(RecoveryErrorV1::TrailingBytes { .. })
        ));
        assert!(matches!(
            decode_recovery_context_v1_exact(&raw[..raw.len() - 1], &set),
            Err(RecoveryErrorV1::UnexpectedEnd { .. })
        ));
    }

    #[test]
    fn context_rejects_wrong_profile_zero_digest_and_false_zero_delta() {
        let set = validator_set(7, 0x20);
        let six = validator_set(6, 0x20);
        assert!(matches!(
            RecoveryContextV1::new_direct7(zero_delta_fields(&six), &six),
            Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual: 6,
                expected: 7
            })
        ));

        let mut fields = zero_delta_fields(&set);
        fields.restart_cut_artifact_sha256 = [0; 32];
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::ZeroDigest("RestartCut artifact SHA-256"))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.restart_park_artifact_sha256 = [0; 32];
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::ZeroDigest("RestartPark artifact SHA-256"))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.restart_parked_ack_artifact_sha256 = [0; 32];
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::ZeroDigest(
                "RestartParkedAck artifact SHA-256"
            ))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.restart_parked_ack_admission_set_sha256 = [0; 32];
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::ZeroDigest(
                "RestartParkedAck admission-set SHA-256"
            ))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.caught_up_cut_artifact_sha256 = [0; 32];
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::ZeroDigest(
                "caught-up cut artifact SHA-256"
            ))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.terminal_height = Height::new(51);
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        let mut fields = zero_delta_fields(&set);
        fields.process_instance = 3;
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::InvalidProcessInstance {
                actual: 3,
                expected: 2
            })
        ));

        let mut fields = zero_delta_fields(&set);
        fields.restart_cut_epoch = Epoch::new(set.epoch().get() + 1);
        fields.terminal_epoch = fields.restart_cut_epoch;
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));
    }

    #[test]
    fn nonzero_mode_has_reserved_distinct_geometry_and_unknown_tag_fails() {
        let set = validator_set(7, 0x20);
        let mut fields = zero_delta_fields(&set);
        fields.mode = RecoveryModeV1::NonZeroDelta;
        fields.terminal_height = Height::new(51);
        fields.terminal_block_id = BlockId::new([0x51; 32]);
        fields.terminal_state_root = StateRoot::new([0x52; 32]);
        fields.terminal_chain_root = [0x53; 32];
        let nonzero = RecoveryContextV1::new_direct7(fields, &set).unwrap();
        assert_eq!(nonzero.mode(), RecoveryModeV1::NonZeroDelta);

        let mut raw = nonzero.try_cev1_bytes().unwrap();
        raw[2] = 9;
        assert_eq!(
            decode_recovery_context_v1_exact(&raw, &set).unwrap_err(),
            RecoveryErrorV1::UnknownRecoveryMode { actual: 9 }
        );

        let mut fields = zero_delta_fields(&set);
        fields.mode = RecoveryModeV1::NonZeroDelta;
        fields.terminal_height = Height::new(51);
        fields.terminal_block_id = BlockId::new([0x51; 32]);
        assert!(matches!(
            RecoveryContextV1::new_direct7(fields, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));
    }

    #[test]
    fn zero_delta_cut_round_trips_exact_equal_source_and_terminal() {
        let set = validator_set(7, 0x20);
        let fields = zero_delta_cut_fields(&set);
        let cut = RecoveryZeroDeltaCutV1::new_direct7(fields, &set).unwrap();
        let raw = cut.try_cev1_bytes().unwrap();
        let decoded = decode_recovery_zero_delta_cut_v1_exact(&raw, &set).unwrap();

        assert_eq!(decoded, cut);
        assert_eq!(decoded.fields(), fields);
        assert_eq!(
            decoded.restart_park_artifact_sha256(),
            fields.restart_park_artifact_sha256
        );
        assert_eq!(
            decoded.restart_parked_ack_artifact_sha256(),
            fields.restart_parked_ack_artifact_sha256
        );
        assert_eq!(
            decoded.restart_parked_ack_admission_set_sha256(),
            fields.restart_parked_ack_admission_set_sha256
        );
        assert_ne!(decoded.digest(), [0; 32]);
        assert_ne!(decoded.digest(), context(&set).digest());
        assert!(raw.len() <= MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1);

        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            decode_recovery_zero_delta_cut_v1_exact(&trailing, &set),
            Err(RecoveryErrorV1::TrailingBytes { .. })
        ));
        assert!(matches!(
            decode_recovery_zero_delta_cut_v1_exact(&raw[..raw.len() - 1], &set),
            Err(RecoveryErrorV1::UnexpectedEnd { .. })
        ));

        let oversized = alloc::vec![0u8; MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1 + 1];
        assert!(matches!(
            decode_recovery_zero_delta_cut_v1_exact(&oversized, &set),
            Err(RecoveryErrorV1::TooLarge {
                field: "RecoveryZeroDeltaCutV1",
                ..
            })
        ));
    }

    #[test]
    fn zero_delta_cut_rejects_every_critical_zero_digest_mutant() {
        let set = validator_set(7, 0x20);
        let fields = zero_delta_cut_fields(&set);

        macro_rules! reject_zero {
            ($field:ident, $zero:expr) => {{
                let mut mutant = fields;
                mutant.$field = $zero;
                assert!(
                    matches!(
                        RecoveryZeroDeltaCutV1::new_direct7(mutant, &set),
                        Err(RecoveryErrorV1::ZeroDigest(_))
                    ),
                    "zero {} mutant was accepted",
                    stringify!($field)
                );
            }};
        }

        reject_zero!(campaign_context_sha256, [0; 32]);
        reject_zero!(fleet_start_certificate_sha256, [0; 32]);
        reject_zero!(validator_set_artifact_sha256, [0; 32]);
        reject_zero!(restart_cut_artifact_sha256, [0; 32]);
        reject_zero!(restart_park_artifact_sha256, [0; 32]);
        reject_zero!(restart_parked_ack_artifact_sha256, [0; 32]);
        reject_zero!(restart_parked_ack_admission_set_sha256, [0; 32]);
        reject_zero!(recovery_nonce, [0; 32]);
        reject_zero!(node_facts_sha256, [0; 32]);
        reject_zero!(signer_inventory_invariant_sha256, [0; 32]);
        reject_zero!(source_block_id, BlockId::new([0; 32]));
        reject_zero!(source_state_root, StateRoot::new([0; 32]));
        reject_zero!(source_finalized_chain_root, [0; 32]);
        reject_zero!(terminal_block_id, BlockId::new([0; 32]));
        reject_zero!(terminal_state_root, StateRoot::new([0; 32]));
        reject_zero!(terminal_finalized_chain_root, [0; 32]);
        reject_zero!(terminal_application_commit_sha256, [0; 32]);
        reject_zero!(terminal_checkpoint_canonical_sha256, [0; 32]);

        let mut zero_set_id = fields;
        zero_set_id.validator_set_id = ValidatorSetId::new([0; 32]);
        assert_eq!(
            RecoveryZeroDeltaCutV1::new_direct7(zero_set_id, &set).unwrap_err(),
            RecoveryErrorV1::WrongValidatorSet
        );
    }

    #[test]
    fn zero_delta_cut_rejects_profile_identity_and_geometry_mutants() {
        let set = validator_set(7, 0x20);
        let six = validator_set(6, 0x20);
        assert!(matches!(
            RecoveryZeroDeltaCutV1::new_direct7(zero_delta_cut_fields(&six), &six),
            Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual: 6,
                expected: 7
            })
        ));

        let mut unknown_target = zero_delta_cut_fields(&set);
        unknown_target.target_validator = ValidatorId::new([0xf0; 32]);
        assert_eq!(
            RecoveryZeroDeltaCutV1::new_direct7(unknown_target, &set).unwrap_err(),
            RecoveryErrorV1::UnknownTarget
        );

        let mut wrong_process = zero_delta_cut_fields(&set);
        wrong_process.process_instance = 1;
        assert_eq!(
            RecoveryZeroDeltaCutV1::new_direct7(wrong_process, &set).unwrap_err(),
            RecoveryErrorV1::InvalidProcessInstance {
                actual: 1,
                expected: 2,
            }
        );

        for epoch_field in 0..2 {
            let mut mutant = zero_delta_cut_fields(&set);
            let wrong_epoch = Epoch::new(set.epoch().get() + 1);
            match epoch_field {
                0 => mutant.source_epoch = wrong_epoch,
                1 => mutant.terminal_epoch = wrong_epoch,
                _ => unreachable!(),
            }
            assert!(matches!(
                RecoveryZeroDeltaCutV1::new_direct7(mutant, &set),
                Err(RecoveryErrorV1::InvalidCutGeometry(_))
            ));
        }

        let mut zero_height = zero_delta_cut_fields(&set);
        zero_height.source_height = Height::new(0);
        zero_height.terminal_height = Height::new(0);
        assert!(matches!(
            RecoveryZeroDeltaCutV1::new_direct7(zero_height, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        for geometry_field in 0..4 {
            let mut mutant = zero_delta_cut_fields(&set);
            match geometry_field {
                0 => mutant.terminal_height = Height::new(mutant.source_height.get() + 1),
                1 => mutant.terminal_block_id = BlockId::new([0x91; 32]),
                2 => mutant.terminal_state_root = StateRoot::new([0x92; 32]),
                3 => mutant.terminal_finalized_chain_root = [0x93; 32],
                _ => unreachable!(),
            }
            assert!(matches!(
                RecoveryZeroDeltaCutV1::new_direct7(mutant, &set),
                Err(RecoveryErrorV1::InvalidCutGeometry(_))
            ));
        }
    }

    #[test]
    fn caught_up_cut_round_trips_exact_nonzero_tail_and_terminal_coordinates() {
        let set = validator_set(7, 0x20);
        let fields = caught_up_fields(&set);
        let cut = RecoveryCaughtUpCutV1::new_direct7(fields, &set).unwrap();
        let raw = cut.try_cev1_bytes().unwrap();
        let decoded = decode_recovery_caught_up_cut_v1_exact(&raw, &set).unwrap();

        assert_eq!(decoded, cut);
        assert_eq!(decoded.fields(), fields);
        assert_eq!(
            decoded.restart_park_artifact_sha256(),
            fields.restart_park_artifact_sha256
        );
        assert_ne!(decoded.digest(), [0; 32]);
        assert!(raw.len() <= MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1);

        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            decode_recovery_caught_up_cut_v1_exact(&trailing, &set),
            Err(RecoveryErrorV1::TrailingBytes { .. })
        ));
        assert!(matches!(
            decode_recovery_caught_up_cut_v1_exact(&raw[..raw.len() - 1], &set),
            Err(RecoveryErrorV1::UnexpectedEnd { .. })
        ));

        let mut zero_campaign_mutant = raw;
        zero_campaign_mutant[2..34].fill(0);
        assert_eq!(
            decode_recovery_caught_up_cut_v1_exact(&zero_campaign_mutant, &set).unwrap_err(),
            RecoveryErrorV1::ZeroDigest("campaign context SHA-256")
        );

        let oversized = alloc::vec![0u8; MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1 + 1];
        assert!(matches!(
            decode_recovery_caught_up_cut_v1_exact(&oversized, &set),
            Err(RecoveryErrorV1::TooLarge {
                field: "RecoveryCaughtUpCutV1",
                ..
            })
        ));
    }

    #[test]
    fn caught_up_cut_rejects_every_critical_zero_digest_mutant() {
        let set = validator_set(7, 0x20);
        let fields = caught_up_fields(&set);

        macro_rules! reject_zero {
            ($field:ident, $zero:expr) => {{
                let mut mutant = fields;
                mutant.$field = $zero;
                assert!(
                    matches!(
                        RecoveryCaughtUpCutV1::new_direct7(mutant, &set),
                        Err(RecoveryErrorV1::ZeroDigest(_))
                    ),
                    "zero {} mutant was accepted",
                    stringify!($field)
                );
            }};
        }

        reject_zero!(campaign_context_sha256, [0; 32]);
        reject_zero!(fleet_start_certificate_sha256, [0; 32]);
        reject_zero!(validator_set_artifact_sha256, [0; 32]);
        reject_zero!(restart_cut_artifact_sha256, [0; 32]);
        reject_zero!(restart_park_artifact_sha256, [0; 32]);
        reject_zero!(recovery_nonce, [0; 32]);
        reject_zero!(catchup_bundle_artifact_sha256, [0; 32]);
        reject_zero!(node_facts_sha256, [0; 32]);
        reject_zero!(signer_inventory_invariant_sha256, [0; 32]);
        reject_zero!(restart_cut_block_id, BlockId::new([0; 32]));
        reject_zero!(restart_cut_state_root, StateRoot::new([0; 32]));
        reject_zero!(restart_cut_chain_root, [0; 32]);
        reject_zero!(last_certified_block_id, BlockId::new([0; 32]));
        reject_zero!(last_certified_qc_digest, CertificateId::new([0; 32]));
        reject_zero!(terminal_block_id, BlockId::new([0; 32]));
        reject_zero!(terminal_state_root, StateRoot::new([0; 32]));
        reject_zero!(terminal_chain_root, [0; 32]);
        reject_zero!(terminal_application_commit_sha256, [0; 32]);
        reject_zero!(terminal_checkpoint_sha256, [0; 32]);

        let mut zero_set_id = fields;
        zero_set_id.validator_set_id = ValidatorSetId::new([0; 32]);
        assert_eq!(
            RecoveryCaughtUpCutV1::new_direct7(zero_set_id, &set).unwrap_err(),
            RecoveryErrorV1::WrongValidatorSet
        );
    }

    #[test]
    fn caught_up_cut_rejects_profile_epoch_and_geometry_mutants() {
        let set = validator_set(7, 0x20);
        let six = validator_set(6, 0x20);
        assert!(matches!(
            RecoveryCaughtUpCutV1::new_direct7(caught_up_fields(&six), &six),
            Err(RecoveryErrorV1::UnsupportedValidatorProfile {
                actual: 6,
                expected: 7
            })
        ));

        let mut unknown_target = caught_up_fields(&set);
        unknown_target.target_validator = ValidatorId::new([0xf0; 32]);
        assert_eq!(
            RecoveryCaughtUpCutV1::new_direct7(unknown_target, &set).unwrap_err(),
            RecoveryErrorV1::UnknownTarget
        );

        let mut wrong_process = caught_up_fields(&set);
        wrong_process.process_instance = 1;
        assert_eq!(
            RecoveryCaughtUpCutV1::new_direct7(wrong_process, &set).unwrap_err(),
            RecoveryErrorV1::InvalidProcessInstance {
                actual: 1,
                expected: 2,
            }
        );

        for epoch_field in 0..3 {
            let mut mutant = caught_up_fields(&set);
            let wrong_epoch = Epoch::new(set.epoch().get() + 1);
            match epoch_field {
                0 => mutant.restart_cut_epoch = wrong_epoch,
                1 => mutant.last_certified_epoch = wrong_epoch,
                2 => mutant.terminal_epoch = wrong_epoch,
                _ => unreachable!(),
            }
            assert!(matches!(
                RecoveryCaughtUpCutV1::new_direct7(mutant, &set),
                Err(RecoveryErrorV1::InvalidCutGeometry(_))
            ));
        }

        let mut no_advance = caught_up_fields(&set);
        no_advance.terminal_height = no_advance.restart_cut_height;
        assert!(matches!(
            RecoveryCaughtUpCutV1::new_direct7(no_advance, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        let mut certified_behind = caught_up_fields(&set);
        certified_behind.last_certified_height = Height::new(51);
        assert!(matches!(
            RecoveryCaughtUpCutV1::new_direct7(certified_behind, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        let mut unchanged_chain = caught_up_fields(&set);
        unchanged_chain.terminal_chain_root = unchanged_chain.restart_cut_chain_root;
        assert!(matches!(
            RecoveryCaughtUpCutV1::new_direct7(unchanged_chain, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        let mut equal_height_wrong_block = caught_up_fields(&set);
        equal_height_wrong_block.last_certified_height = equal_height_wrong_block.terminal_height;
        assert!(matches!(
            RecoveryCaughtUpCutV1::new_direct7(equal_height_wrong_block, &set),
            Err(RecoveryErrorV1::InvalidCutGeometry(_))
        ));

        let mut equal_coordinate = caught_up_fields(&set);
        equal_coordinate.last_certified_height = equal_coordinate.terminal_height;
        equal_coordinate.last_certified_block_id = equal_coordinate.terminal_block_id;
        RecoveryCaughtUpCutV1::new_direct7(equal_coordinate, &set).unwrap();
    }

    #[test]
    fn ready_signature_constructor_authenticates_bytes_and_membership() {
        let set = validator_set(7, 0x20);
        let context = context(&set);
        let origin = set.validators()[0].id();
        let root = SignedRecoveryReadyV1::signing_root_for(&context, origin);
        let mut signature = *signature_for(&set, origin, root).as_bytes();
        signature[0] ^= 1;
        assert!(matches!(
            SignedRecoveryReadyV1::from_signature_bytes(
                context,
                origin,
                &signature,
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::InvalidSignature(id)) if *id == origin
        ));
        assert_eq!(
            SignedRecoveryReadyV1::from_signature_bytes(
                context,
                origin,
                &[0; SIGNATURE_BYTES - 1],
                &set,
                &BoundVerifier
            )
            .unwrap_err(),
            RecoveryErrorV1::InvalidSignatureBytes
        );

        let foreign = ValidatorId::new([0xf0; 32]);
        assert!(matches!(
            SignedRecoveryReadyV1::from_signature(
                context,
                foreign,
                Signature64::from_array([0; SIGNATURE_BYTES]),
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::UnknownSigner(id)) if *id == foreign
        ));
    }

    #[test]
    fn park_only_context_change_rekeys_ready_and_start() {
        let set = validator_set(7, 0x20);
        let primary = context(&set);
        let alternate = park_alternate_context(&set);
        let origin = set.validators()[0].id();

        let mut expected_alternate_fields = primary.fields();
        expected_alternate_fields.restart_park_artifact_sha256 =
            alternate.restart_park_artifact_sha256();
        assert_eq!(alternate.fields(), expected_alternate_fields);
        assert_ne!(primary.digest(), alternate.digest());
        assert_ne!(
            SignedRecoveryReadyV1::signing_root_for(&primary, origin),
            SignedRecoveryReadyV1::signing_root_for(&alternate, origin)
        );

        let primary_ready = ready_set(primary, &set);
        let alternate_ready = ready_set(alternate, &set);
        assert_ne!(primary_ready.digest(), alternate_ready.digest());
        assert_ne!(
            SignedRecoveryStartV1::signing_root_for(&primary_ready, origin),
            SignedRecoveryStartV1::signing_root_for(&alternate_ready, origin)
        );
    }

    #[test]
    fn parked_ack_context_fields_independently_rekey_and_reject_wrong_context_barriers() {
        let set = validator_set(7, 0x20);
        let primary = context(&set);
        let origin = set.validators()[0].id();
        let primary_ready = ready_set(primary, &set);
        let primary_start = start(&primary_ready, origin, &set);
        let primary_start_raw = primary_start.try_cev1_bytes().unwrap();
        let primary_start_statements = start_statements(&primary_ready, &set);

        for (field, alternate) in parked_ack_alternate_contexts(&set) {
            assert_ne!(
                primary.digest(),
                alternate.digest(),
                "{field} must rekey context"
            );
            assert_ne!(
                SignedRecoveryReadyV1::signing_root_for(&primary, origin),
                SignedRecoveryReadyV1::signing_root_for(&alternate, origin),
                "{field} must rekey RecoveryReady"
            );
            assert_eq!(
                RecoveryReadySetV1::new(
                    primary,
                    ready_statements(alternate, &set),
                    &set,
                    &BoundVerifier,
                )
                .unwrap_err(),
                RecoveryErrorV1::ContextMismatch,
                "{field} must not validate under the prior ReadySet context"
            );

            let alternate_ready = ready_set(alternate, &set);
            assert_ne!(
                primary_ready.digest(),
                alternate_ready.digest(),
                "{field} must rekey the ReadySet"
            );
            assert_ne!(
                SignedRecoveryStartV1::signing_root_for(&primary_ready, origin),
                SignedRecoveryStartV1::signing_root_for(&alternate_ready, origin),
                "{field} must rekey RecoveryStart"
            );
            assert_eq!(
                primary_start
                    .verify(&alternate_ready, &set, &BoundVerifier)
                    .unwrap_err(),
                RecoveryErrorV1::ContextMismatch,
                "{field} must not validate against a different ReadySet context"
            );
            assert_eq!(
                decode_signed_recovery_start_v1_exact(
                    &primary_start_raw,
                    &alternate_ready,
                    &set,
                    &BoundVerifier,
                )
                .unwrap_err(),
                RecoveryErrorV1::ContextMismatch,
                "{field} must not reopen a Start statement against a different ReadySet"
            );
            assert_eq!(
                RecoveryStartCertificateV1::new(
                    alternate_ready,
                    primary_start_statements.clone(),
                    &set,
                    &BoundVerifier,
                )
                .unwrap_err(),
                RecoveryErrorV1::ContextMismatch,
                "{field} must not validate a Start certificate under a different context"
            );
        }
    }

    #[test]
    fn ready_set_is_exact_unique_context_bound_and_canonically_ordered() {
        let set = validator_set(7, 0x20);
        let context = context(&set);
        let alternate = park_alternate_context(&set);
        let statements = ready_statements(context, &set);

        let mut missing = statements.clone();
        missing.pop();
        assert!(matches!(
            RecoveryReadySetV1::new(context, missing, &set, &BoundVerifier),
            Err(RecoveryErrorV1::Incomplete {
                actual: 6,
                expected: 7
            })
        ));

        let mut duplicate = statements.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(matches!(
            RecoveryReadySetV1::new(context, duplicate, &set, &BoundVerifier),
            Err(RecoveryErrorV1::DuplicateSigner(_))
        ));

        let mut equivocation = statements.clone();
        equivocation[1] = ready(alternate, statements[0].origin(), &set);
        assert!(matches!(
            RecoveryReadySetV1::new(context, equivocation, &set, &BoundVerifier),
            Err(RecoveryErrorV1::Equivocation(_))
        ));

        let mut wrong_context = statements.clone();
        wrong_context[1] = ready(alternate, set.validators()[1].id(), &set);
        assert_eq!(
            RecoveryReadySetV1::new(context, wrong_context, &set, &BoundVerifier).unwrap_err(),
            RecoveryErrorV1::ContextMismatch
        );

        let mut noncanonical = statements;
        noncanonical.swap(0, 1);
        assert_eq!(
            RecoveryReadySetV1::new(context, noncanonical, &set, &BoundVerifier).unwrap_err(),
            RecoveryErrorV1::NonCanonicalSignerOrder
        );
    }

    #[test]
    fn ready_and_start_artifacts_round_trip_with_full_ready_set_binding() {
        let set = validator_set(7, 0x20);
        let context = context(&set);
        let ready_set = ready_set(context, &set);
        let ready_raw = ready_set.try_cev1_bytes().unwrap();
        let decoded_ready =
            decode_recovery_ready_set_v1_exact(&ready_raw, &set, &BoundVerifier).unwrap();
        assert_eq!(decoded_ready, ready_set);
        assert_eq!(decoded_ready.statement_count(), 7);
        assert!(decoded_ready.statement(set.validators()[6].id()).is_some());

        let one_start = start(&ready_set, set.validators()[0].id(), &set);
        let one_start_raw = one_start.try_cev1_bytes().unwrap();
        assert_eq!(
            decode_signed_recovery_start_v1_exact(&one_start_raw, &ready_set, &set, &BoundVerifier)
                .unwrap(),
            one_start
        );

        let certificate = RecoveryStartCertificateV1::new(
            ready_set.clone(),
            start_statements(&ready_set, &set),
            &set,
            &BoundVerifier,
        )
        .unwrap();
        let raw = certificate.try_cev1_bytes().unwrap();
        let decoded =
            decode_recovery_start_certificate_v1_exact(&raw, &set, &BoundVerifier).unwrap();
        assert_eq!(decoded, certificate);
        assert_eq!(decoded.ready_set(), &ready_set);
        assert_eq!(decoded.statement_count(), 7);
        assert_ne!(decoded.digest(), [0; 32]);

        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            decode_recovery_start_certificate_v1_exact(&trailing, &set, &BoundVerifier),
            Err(RecoveryErrorV1::TrailingBytes { .. })
        ));
        assert!(matches!(
            decode_recovery_start_certificate_v1_exact(&raw[..raw.len() - 1], &set, &BoundVerifier),
            Err(RecoveryErrorV1::UnexpectedEnd { .. })
        ));
    }

    #[test]
    fn start_certificate_rejects_missing_duplicate_equivocation_and_other_ready_set() {
        let set = validator_set(7, 0x20);
        let context = context(&set);
        let alternate = park_alternate_context(&set);
        let primary_ready_set = ready_set(context, &set);
        let alternate_ready_set = ready_set(alternate, &set);
        let statements = start_statements(&primary_ready_set, &set);

        let mut missing = statements.clone();
        missing.pop();
        assert!(matches!(
            RecoveryStartCertificateV1::new(
                primary_ready_set.clone(),
                missing,
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::Incomplete {
                actual: 6,
                expected: 7
            })
        ));

        let mut duplicate = statements.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(matches!(
            RecoveryStartCertificateV1::new(
                primary_ready_set.clone(),
                duplicate,
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::DuplicateSigner(_))
        ));

        let mut equivocation = statements.clone();
        equivocation[1] = start(&alternate_ready_set, statements[0].origin(), &set);
        assert!(matches!(
            RecoveryStartCertificateV1::new(
                primary_ready_set.clone(),
                equivocation,
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::Equivocation(_))
        ));

        let mut wrong_ready_set = statements.clone();
        wrong_ready_set[1] = start(&alternate_ready_set, set.validators()[1].id(), &set);
        assert!(matches!(
            RecoveryStartCertificateV1::new(
                primary_ready_set.clone(),
                wrong_ready_set,
                &set,
                &BoundVerifier
            ),
            Err(RecoveryErrorV1::ContextMismatch | RecoveryErrorV1::ReadySetMismatch)
        ));

        let mut noncanonical = statements;
        noncanonical.swap(0, 1);
        assert_eq!(
            RecoveryStartCertificateV1::new(primary_ready_set, noncanonical, &set, &BoundVerifier,)
                .unwrap_err(),
            RecoveryErrorV1::NonCanonicalSignerOrder
        );
    }

    #[test]
    fn exact_decoders_enforce_top_level_capacity_and_validator_set_join() {
        let set = validator_set(7, 0x20);
        let other_set = validator_set(7, 0x40);
        let context = context(&set);
        let raw = context.try_cev1_bytes().unwrap();
        assert_eq!(
            decode_recovery_context_v1_exact(&raw, &other_set).unwrap_err(),
            RecoveryErrorV1::WrongValidatorSet
        );

        let oversized = alloc::vec![0u8; MAX_RECOVERY_CONTEXT_BYTES_V1 + 1];
        assert!(matches!(
            decode_recovery_context_v1_exact(&oversized, &set),
            Err(RecoveryErrorV1::TooLarge {
                field: "RecoveryContextV1",
                ..
            })
        ));
    }
}
