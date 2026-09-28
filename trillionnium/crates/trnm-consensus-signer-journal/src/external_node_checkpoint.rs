//! Independent whole-node checkpoint data and CAS port, shared by Node and the Unix adapter.
//!
//! This module owns no database, socket, clock or verified-owner constructor.
//! Sharing the signer watermark *type* does not share its authority: whole-node
//! checkpoints remain a separate independently administered CAS domain.
//! The frozen V0 bytes and Node's public compatibility re-exports are unchanged.

use crate::SignerWatermarkV0;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use trnm_consensus_types::{BlockId, StateRoot};

const RECORD_MAGIC_V0: [u8; 8] = *b"TRNMNCP0";
const CHECKSUM_DOMAIN_V0: &[u8] = b"trnm.external-node-checkpoint.value.v0";

/// Frozen schema carried inside every canonical node-checkpoint value.
pub const EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0: u64 = 0;
/// Exact byte length of the canonical V0 value, including its checksum.
pub const EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0: usize = 672;

/// Canonical fields committed by one whole-node external checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalNodeCheckpointFieldsV0 {
    pub scope: [u8; 32],
    pub generation: u64,
    pub predecessor_checksum: [u8; 32],

    pub safety_journal_id: [u8; 32],
    pub safety_verifier_profile_ref: [u8; 32],
    pub safety_revision: u64,
    pub safety_state_record_checksum: [u8; 32],
    pub safety_record_chain_checksum: [u8; 32],

    pub application_host_config_ref: [u8; 32],
    pub application_projection_profile_ref: [u8; 32],
    pub application_safety_binding_manifest_checksum: [u8; 32],
    pub application_committed_head_row_checksum: [u8; 32],
    pub application_recovery_closure_checksum: [u8; 32],
    pub application_block_id: BlockId,
    pub application_height: u64,
    pub application_state_root: StateRoot,
    pub application_view: u64,
    pub application_timestamp_ms: u64,

    pub signer_journal_id: [u8; 32],
    pub signer_profile_checksum: [u8; 32],
    pub signer_exact_watermark: SignerWatermarkV0,
}

/// Versioned, checksummed value stored in the independent CAS domain.
///
/// Constructing this value validates its canonical shape, but does not prove
/// that any local store actually has the committed heads.  Only the non-Clone
/// Node's non-Clone `ConfirmedNodeCheckpointCandidateV0` represents that later trusted join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalNodeCheckpointV0 {
    fields: ExternalNodeCheckpointFieldsV0,
    checkpoint_checksum: [u8; 32],
}

impl ExternalNodeCheckpointV0 {
    pub fn new(
        fields: ExternalNodeCheckpointFieldsV0,
    ) -> Result<Self, ExternalNodeCheckpointDecodeErrorV0> {
        validate_fields_v0(&fields)?;
        let mut encoded = [0u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0];
        encode_prefix_v0(&fields, &mut encoded);
        let checkpoint_checksum = checkpoint_checksum_v0(&encoded[..640]);
        Ok(Self {
            fields,
            checkpoint_checksum,
        })
    }

    pub fn decode_canonical_exact(
        encoded: &[u8],
    ) -> Result<Self, ExternalNodeCheckpointDecodeErrorV0> {
        if encoded.len() != EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::WrongLength);
        }
        if encoded[..8] != RECORD_MAGIC_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::WrongMagic);
        }
        if read_u64_v0(encoded, 8) != EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::UnsupportedSchema);
        }

        let signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
            read_array_v0(encoded, 536),
            read_array_v0(encoded, 568),
            read_u64_v0(encoded, 600),
            read_array_v0(encoded, 608),
        )
        .map_err(|_| ExternalNodeCheckpointDecodeErrorV0::InvalidField("signer watermark"))?;

        let fields = ExternalNodeCheckpointFieldsV0 {
            scope: read_array_v0(encoded, 16),
            generation: read_u64_v0(encoded, 48),
            predecessor_checksum: read_array_v0(encoded, 56),
            safety_journal_id: read_array_v0(encoded, 88),
            safety_verifier_profile_ref: read_array_v0(encoded, 120),
            safety_revision: read_u64_v0(encoded, 152),
            safety_state_record_checksum: read_array_v0(encoded, 160),
            safety_record_chain_checksum: read_array_v0(encoded, 192),
            application_host_config_ref: read_array_v0(encoded, 224),
            application_projection_profile_ref: read_array_v0(encoded, 256),
            application_safety_binding_manifest_checksum: read_array_v0(encoded, 288),
            application_committed_head_row_checksum: read_array_v0(encoded, 320),
            application_recovery_closure_checksum: read_array_v0(encoded, 352),
            application_block_id: BlockId::new(read_array_v0(encoded, 384)),
            application_height: read_u64_v0(encoded, 416),
            application_state_root: StateRoot::new(read_array_v0(encoded, 424)),
            application_view: read_u64_v0(encoded, 456),
            application_timestamp_ms: read_u64_v0(encoded, 464),
            signer_journal_id: read_array_v0(encoded, 472),
            signer_profile_checksum: read_array_v0(encoded, 504),
            signer_exact_watermark,
        };
        let value = Self::new(fields)?;
        let persisted_checksum: [u8; 32] = read_array_v0(encoded, 640);
        if persisted_checksum != value.checkpoint_checksum {
            return Err(ExternalNodeCheckpointDecodeErrorV0::ChecksumMismatch);
        }
        Ok(value)
    }

    pub fn encode_canonical(&self) -> [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0] {
        let mut encoded = [0u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0];
        encode_prefix_v0(&self.fields, &mut encoded);
        encoded[640..].copy_from_slice(&self.checkpoint_checksum);
        encoded
    }

    pub const fn schema(&self) -> u64 {
        EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0
    }

    pub const fn fields(&self) -> &ExternalNodeCheckpointFieldsV0 {
        &self.fields
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.fields.scope
    }

    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }

    pub const fn predecessor_checksum(&self) -> [u8; 32] {
        self.fields.predecessor_checksum
    }

    pub const fn checkpoint_checksum(&self) -> [u8; 32] {
        self.checkpoint_checksum
    }

    pub const fn signer_exact_watermark(&self) -> SignerWatermarkV0 {
        self.fields.signer_exact_watermark
    }

    /// Validate the monotonic link required for a non-initial CAS target.
    pub fn validate_successor_of(
        &self,
        predecessor: &Self,
    ) -> Result<(), ExternalNodeCheckpointDecodeErrorV0> {
        if self.scope() != predecessor.scope() {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor scope",
            ));
        }
        let expected_generation = predecessor.generation().checked_add(1).ok_or(
            ExternalNodeCheckpointDecodeErrorV0::InvalidField("successor generation overflow"),
        )?;
        if self.generation() != expected_generation {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor generation",
            ));
        }
        if self.predecessor_checksum() != predecessor.checkpoint_checksum() {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor checkpoint checksum",
            ));
        }
        Ok(())
    }
}

/// Exact canonical decoding failures.  No decoding failure is retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointDecodeErrorV0 {
    WrongLength,
    WrongMagic,
    UnsupportedSchema,
    InvalidField(&'static str),
    ChecksumMismatch,
}

impl fmt::Display for ExternalNodeCheckpointDecodeErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => formatter.write_str("external node checkpoint length differs"),
            Self::WrongMagic => formatter.write_str("external node checkpoint magic differs"),
            Self::UnsupportedSchema => {
                formatter.write_str("external node checkpoint schema is unsupported")
            }
            Self::InvalidField(field) => {
                write!(formatter, "external node checkpoint has invalid {field}")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("external node checkpoint checksum differs")
            }
        }
    }
}

impl Error for ExternalNodeCheckpointDecodeErrorV0 {}

/// Closed errors supplied by an independently administered node-checkpoint
/// backend.  This interface is not an HSM/KMS contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointStoreErrorV0 {
    Unavailable,
    CompareFailed,
    InvalidPersistedState,
}

impl fmt::Display for ExternalNodeCheckpointStoreErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("external node checkpoint is unavailable"),
            Self::CompareFailed => {
                formatter.write_str("external node checkpoint compare-and-advance failed")
            }
            Self::InvalidPersistedState => {
                formatter.write_str("external node checkpoint persisted state is invalid")
            }
        }
    }
}

impl Error for ExternalNodeCheckpointStoreErrorV0 {}

/// Independently administered CAS storage for whole-node checkpoints.
///
/// This is a second CAS domain and must not be implemented by delegating to
/// `ExternalMonotonicWatermarkV0`.  Implementations must durably isolate one
/// value per scope from the Safety/App/signer namespaces.  For a first value,
/// `expected` must be `None`, `target.generation()` must be zero, and its
/// predecessor must be zero.  For a successor, the target must preserve scope,
/// advance generation by exactly one, and name `expected.checkpoint_checksum()`
/// as predecessor; implementations should call
/// [`ExternalNodeCheckpointV0::validate_successor_of`] or enforce the same
/// checks.  An uncertain result must be resolved by a fresh `load`.
pub trait ExternalNodeCheckpointStoreV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0>;

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointStoreErrorV0>;
}

fn validate_fields_v0(
    fields: &ExternalNodeCheckpointFieldsV0,
) -> Result<(), ExternalNodeCheckpointDecodeErrorV0> {
    let nonzero = [
        (fields.scope, "scope"),
        (fields.safety_journal_id, "safety journal id"),
        (
            fields.safety_verifier_profile_ref,
            "safety verifier profile",
        ),
        (
            fields.safety_state_record_checksum,
            "safety state record checksum",
        ),
        (
            fields.safety_record_chain_checksum,
            "safety record chain checksum",
        ),
        (
            fields.application_host_config_ref,
            "application host config",
        ),
        (
            fields.application_projection_profile_ref,
            "application projection profile",
        ),
        (
            fields.application_safety_binding_manifest_checksum,
            "application safety binding manifest checksum",
        ),
        (
            fields.application_committed_head_row_checksum,
            "application committed head row checksum",
        ),
        (
            fields.application_recovery_closure_checksum,
            "application recovery closure checksum",
        ),
        (fields.signer_journal_id, "signer journal id"),
        (fields.signer_profile_checksum, "signer profile checksum"),
    ];
    for (value, name) in nonzero {
        if value == [0; 32] {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(name));
        }
    }
    if fields.application_block_id.is_zero() {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "application block id",
        ));
    }
    if fields.application_state_root.is_zero() {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "application state root",
        ));
    }
    if fields.generation == 0 && fields.predecessor_checksum != [0; 32] {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "generation-zero predecessor",
        ));
    }
    if fields.generation != 0 && fields.predecessor_checksum == [0; 32] {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "successor predecessor",
        ));
    }
    if fields.signer_exact_watermark.scope() != fields.scope {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "signer watermark scope",
        ));
    }
    if fields.signer_exact_watermark.journal_id() != fields.signer_journal_id {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "signer watermark journal id",
        ));
    }
    Ok(())
}

fn encode_prefix_v0(
    fields: &ExternalNodeCheckpointFieldsV0,
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
) {
    encoded[..8].copy_from_slice(&RECORD_MAGIC_V0);
    write_u64_v0(encoded, 8, EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0);
    write_array_v0(encoded, 16, fields.scope);
    write_u64_v0(encoded, 48, fields.generation);
    write_array_v0(encoded, 56, fields.predecessor_checksum);
    write_array_v0(encoded, 88, fields.safety_journal_id);
    write_array_v0(encoded, 120, fields.safety_verifier_profile_ref);
    write_u64_v0(encoded, 152, fields.safety_revision);
    write_array_v0(encoded, 160, fields.safety_state_record_checksum);
    write_array_v0(encoded, 192, fields.safety_record_chain_checksum);
    write_array_v0(encoded, 224, fields.application_host_config_ref);
    write_array_v0(encoded, 256, fields.application_projection_profile_ref);
    write_array_v0(
        encoded,
        288,
        fields.application_safety_binding_manifest_checksum,
    );
    write_array_v0(encoded, 320, fields.application_committed_head_row_checksum);
    write_array_v0(encoded, 352, fields.application_recovery_closure_checksum);
    write_array_v0(encoded, 384, fields.application_block_id.into_bytes());
    write_u64_v0(encoded, 416, fields.application_height);
    write_array_v0(encoded, 424, fields.application_state_root.into_bytes());
    write_u64_v0(encoded, 456, fields.application_view);
    write_u64_v0(encoded, 464, fields.application_timestamp_ms);
    write_array_v0(encoded, 472, fields.signer_journal_id);
    write_array_v0(encoded, 504, fields.signer_profile_checksum);
    write_array_v0(encoded, 536, fields.signer_exact_watermark.scope());
    write_array_v0(encoded, 568, fields.signer_exact_watermark.journal_id());
    write_u64_v0(encoded, 600, fields.signer_exact_watermark.sequence());
    write_array_v0(encoded, 608, fields.signer_exact_watermark.chain_checksum());
}

fn checkpoint_checksum_v0(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((CHECKSUM_DOMAIN_V0.len() as u64).to_be_bytes());
    hasher.update(CHECKSUM_DOMAIN_V0);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_array_v0(encoded: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(&encoded[offset..offset + 32]);
    value
}

fn read_u64_v0(encoded: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&encoded[offset..offset + 8]);
    u64::from_be_bytes(value)
}

fn write_array_v0(
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
    offset: usize,
    value: [u8; 32],
) {
    encoded[offset..offset + 32].copy_from_slice(&value);
}

fn write_u64_v0(
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
    offset: usize,
    value: u64,
) {
    encoded[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
