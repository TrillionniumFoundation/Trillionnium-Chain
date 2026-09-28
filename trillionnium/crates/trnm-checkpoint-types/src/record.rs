//! Generic independent owner-frontier checkpoint data and CAS contract.
//! Fresh V2 format; no historical compatibility or runtime authority.
//! A consuming host must independently reconcile its local roots.

use crate::EffectWatermarkV2;
use crate::{BlockId, StateRoot};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const RECORD_MAGIC_V2: [u8; 8] = *b"TRNMCP02";
const CHECKSUM_DOMAIN_V2: &[u8] = b"trnm.external-node-checkpoint.value.v2";

/// Portable schema carried inside every canonical node-checkpoint value.
pub const EXTERNAL_CHECKPOINT_SCHEMA_V2: u64 = 2;
/// Exact byte length of the canonical V2 value, including its checksum.
pub const EXTERNAL_CHECKPOINT_RECORD_BYTES_V2: usize = 672;

/// Canonical fields committed by one whole-node external checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalCheckpointFieldsV2 {
    pub scope: [u8; 32],
    pub generation: u64,
    pub predecessor_checksum: [u8; 32],

    pub authority_journal_id: [u8; 32],
    pub authority_verifier_profile_ref: [u8; 32],
    pub authority_revision: u64,
    pub authority_state_record_checksum: [u8; 32],
    pub authority_record_chain_checksum: [u8; 32],

    pub application_host_config_ref: [u8; 32],
    pub application_projection_profile_ref: [u8; 32],
    pub application_authority_binding_manifest_checksum: [u8; 32],
    pub application_committed_head_row_checksum: [u8; 32],
    pub application_recovery_closure_checksum: [u8; 32],
    pub application_block_id: BlockId,
    pub application_height: u64,
    pub application_state_root: StateRoot,
    pub application_generation: u64,
    pub application_timestamp_ms: u64,

    pub effect_journal_id: [u8; 32],
    pub effect_profile_checksum: [u8; 32],
    pub effect_exact_watermark: EffectWatermarkV2,
}

/// Versioned data value. Canonical shape validation does not prove that local
/// stores hold these roots or that an external frontier is current. A consuming
/// host must perform that independent join; no verified runtime owner is supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalCheckpointV2 {
    fields: ExternalCheckpointFieldsV2,
    checkpoint_checksum: [u8; 32],
}

impl ExternalCheckpointV2 {
    pub fn new(
        fields: ExternalCheckpointFieldsV2,
    ) -> Result<Self, ExternalCheckpointDecodeErrorV2> {
        validate_fields_v2(&fields)?;
        let mut encoded = [0u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2];
        encode_prefix_v2(&fields, &mut encoded);
        let checkpoint_checksum = checkpoint_checksum_v2(&encoded[..640]);
        Ok(Self {
            fields,
            checkpoint_checksum,
        })
    }

    pub fn decode_canonical_exact(encoded: &[u8]) -> Result<Self, ExternalCheckpointDecodeErrorV2> {
        if encoded.len() != EXTERNAL_CHECKPOINT_RECORD_BYTES_V2 {
            return Err(ExternalCheckpointDecodeErrorV2::WrongLength);
        }
        if encoded[..8] != RECORD_MAGIC_V2 {
            return Err(ExternalCheckpointDecodeErrorV2::WrongMagic);
        }
        if read_u64_v2(encoded, 8) != EXTERNAL_CHECKPOINT_SCHEMA_V2 {
            return Err(ExternalCheckpointDecodeErrorV2::UnsupportedSchema);
        }

        let effect_exact_watermark = EffectWatermarkV2::from_persisted_parts(
            read_array_v2(encoded, 536),
            read_array_v2(encoded, 568),
            read_u64_v2(encoded, 600),
            read_array_v2(encoded, 608),
        )
        .map_err(|_| ExternalCheckpointDecodeErrorV2::InvalidField("signer watermark"))?;

        let fields = ExternalCheckpointFieldsV2 {
            scope: read_array_v2(encoded, 16),
            generation: read_u64_v2(encoded, 48),
            predecessor_checksum: read_array_v2(encoded, 56),
            authority_journal_id: read_array_v2(encoded, 88),
            authority_verifier_profile_ref: read_array_v2(encoded, 120),
            authority_revision: read_u64_v2(encoded, 152),
            authority_state_record_checksum: read_array_v2(encoded, 160),
            authority_record_chain_checksum: read_array_v2(encoded, 192),
            application_host_config_ref: read_array_v2(encoded, 224),
            application_projection_profile_ref: read_array_v2(encoded, 256),
            application_authority_binding_manifest_checksum: read_array_v2(encoded, 288),
            application_committed_head_row_checksum: read_array_v2(encoded, 320),
            application_recovery_closure_checksum: read_array_v2(encoded, 352),
            application_block_id: BlockId::new(read_array_v2(encoded, 384)),
            application_height: read_u64_v2(encoded, 416),
            application_state_root: StateRoot::new(read_array_v2(encoded, 424)),
            application_generation: read_u64_v2(encoded, 456),
            application_timestamp_ms: read_u64_v2(encoded, 464),
            effect_journal_id: read_array_v2(encoded, 472),
            effect_profile_checksum: read_array_v2(encoded, 504),
            effect_exact_watermark,
        };
        let value = Self::new(fields)?;
        let persisted_checksum: [u8; 32] = read_array_v2(encoded, 640);
        if persisted_checksum != value.checkpoint_checksum {
            return Err(ExternalCheckpointDecodeErrorV2::ChecksumMismatch);
        }
        Ok(value)
    }

    pub fn encode_canonical(&self) -> [u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2] {
        let mut encoded = [0u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2];
        encode_prefix_v2(&self.fields, &mut encoded);
        encoded[640..].copy_from_slice(&self.checkpoint_checksum);
        encoded
    }

    pub const fn schema(&self) -> u64 {
        EXTERNAL_CHECKPOINT_SCHEMA_V2
    }

    pub const fn fields(&self) -> &ExternalCheckpointFieldsV2 {
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

    pub const fn effect_exact_watermark(&self) -> EffectWatermarkV2 {
        self.fields.effect_exact_watermark
    }

    /// Validate the monotonic link required for a non-initial CAS target.
    pub fn validate_successor_of(
        &self,
        predecessor: &Self,
    ) -> Result<(), ExternalCheckpointDecodeErrorV2> {
        if self.scope() != predecessor.scope() {
            return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
                "successor scope",
            ));
        }
        let expected_generation = predecessor.generation().checked_add(1).ok_or(
            ExternalCheckpointDecodeErrorV2::InvalidField("successor generation overflow"),
        )?;
        if self.generation() != expected_generation {
            return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
                "successor generation",
            ));
        }
        if self.predecessor_checksum() != predecessor.checkpoint_checksum() {
            return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
                "successor checkpoint checksum",
            ));
        }
        Ok(())
    }
}

/// Exact canonical decoding failures.  No decoding failure is retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalCheckpointDecodeErrorV2 {
    WrongLength,
    WrongMagic,
    UnsupportedSchema,
    InvalidField(&'static str),
    ChecksumMismatch,
}

impl fmt::Display for ExternalCheckpointDecodeErrorV2 {
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

impl Error for ExternalCheckpointDecodeErrorV2 {}

/// Closed errors supplied by an independently administered node-checkpoint
/// backend.  This interface is not an HSM/KMS contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalCheckpointStoreErrorV2 {
    Unavailable,
    CompareFailed,
    InvalidPersistedState,
}

impl fmt::Display for ExternalCheckpointStoreErrorV2 {
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

impl Error for ExternalCheckpointStoreErrorV2 {}

/// Independently administered CAS storage for whole-node checkpoints.
///
/// This is a second CAS domain and must not be implemented by delegating to
/// `ExternalMonotonicWatermarkV2`.  Implementations must durably isolate one
/// value per scope from the Safety/App/signer namespaces.  For a first value,
/// `expected` must be `None`, `target.generation()` must be zero, and its
/// predecessor must be zero.  For a successor, the target must preserve scope,
/// advance generation by exactly one, and name `expected.checkpoint_checksum()`
/// as predecessor; implementations should call
/// [`ExternalCheckpointV2::validate_successor_of`] or enforce the same
/// checks.  An uncertain result must be resolved by a fresh `load`.
pub trait ExternalCheckpointStoreV2 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalCheckpointV2>, ExternalCheckpointStoreErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalCheckpointV2>,
        target: ExternalCheckpointV2,
    ) -> Result<(), ExternalCheckpointStoreErrorV2>;
}

fn validate_fields_v2(
    fields: &ExternalCheckpointFieldsV2,
) -> Result<(), ExternalCheckpointDecodeErrorV2> {
    let nonzero = [
        (fields.scope, "scope"),
        (fields.authority_journal_id, "safety journal id"),
        (
            fields.authority_verifier_profile_ref,
            "safety verifier profile",
        ),
        (
            fields.authority_state_record_checksum,
            "safety state record checksum",
        ),
        (
            fields.authority_record_chain_checksum,
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
            fields.application_authority_binding_manifest_checksum,
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
        (fields.effect_journal_id, "signer journal id"),
        (fields.effect_profile_checksum, "signer profile checksum"),
    ];
    for (value, name) in nonzero {
        if value == [0; 32] {
            return Err(ExternalCheckpointDecodeErrorV2::InvalidField(name));
        }
    }
    if fields.application_block_id.is_zero() {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "application block id",
        ));
    }
    if fields.application_state_root.is_zero() {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "application state root",
        ));
    }
    if fields.generation == 0 && fields.predecessor_checksum != [0; 32] {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "generation-zero predecessor",
        ));
    }
    if fields.generation != 0 && fields.predecessor_checksum == [0; 32] {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "successor predecessor",
        ));
    }
    if fields.effect_exact_watermark.scope() != fields.scope {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "signer watermark scope",
        ));
    }
    if fields.effect_exact_watermark.journal_id() != fields.effect_journal_id {
        return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
            "signer watermark journal id",
        ));
    }
    Ok(())
}

fn encode_prefix_v2(
    fields: &ExternalCheckpointFieldsV2,
    encoded: &mut [u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2],
) {
    encoded[..8].copy_from_slice(&RECORD_MAGIC_V2);
    write_u64_v2(encoded, 8, EXTERNAL_CHECKPOINT_SCHEMA_V2);
    write_array_v2(encoded, 16, fields.scope);
    write_u64_v2(encoded, 48, fields.generation);
    write_array_v2(encoded, 56, fields.predecessor_checksum);
    write_array_v2(encoded, 88, fields.authority_journal_id);
    write_array_v2(encoded, 120, fields.authority_verifier_profile_ref);
    write_u64_v2(encoded, 152, fields.authority_revision);
    write_array_v2(encoded, 160, fields.authority_state_record_checksum);
    write_array_v2(encoded, 192, fields.authority_record_chain_checksum);
    write_array_v2(encoded, 224, fields.application_host_config_ref);
    write_array_v2(encoded, 256, fields.application_projection_profile_ref);
    write_array_v2(
        encoded,
        288,
        fields.application_authority_binding_manifest_checksum,
    );
    write_array_v2(encoded, 320, fields.application_committed_head_row_checksum);
    write_array_v2(encoded, 352, fields.application_recovery_closure_checksum);
    write_array_v2(encoded, 384, fields.application_block_id.into_bytes());
    write_u64_v2(encoded, 416, fields.application_height);
    write_array_v2(encoded, 424, fields.application_state_root.into_bytes());
    write_u64_v2(encoded, 456, fields.application_generation);
    write_u64_v2(encoded, 464, fields.application_timestamp_ms);
    write_array_v2(encoded, 472, fields.effect_journal_id);
    write_array_v2(encoded, 504, fields.effect_profile_checksum);
    write_array_v2(encoded, 536, fields.effect_exact_watermark.scope());
    write_array_v2(encoded, 568, fields.effect_exact_watermark.journal_id());
    write_u64_v2(encoded, 600, fields.effect_exact_watermark.sequence());
    write_array_v2(encoded, 608, fields.effect_exact_watermark.chain_checksum());
}

fn checkpoint_checksum_v2(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((CHECKSUM_DOMAIN_V2.len() as u64).to_be_bytes());
    hasher.update(CHECKSUM_DOMAIN_V2);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_array_v2(encoded: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(&encoded[offset..offset + 32]);
    value
}

fn read_u64_v2(encoded: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&encoded[offset..offset + 8]);
    u64::from_be_bytes(value)
}

fn write_array_v2(
    encoded: &mut [u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2],
    offset: usize,
    value: [u8; 32],
) {
    encoded[offset..offset + 32].copy_from_slice(&value);
}

fn write_u64_v2(
    encoded: &mut [u8; EXTERNAL_CHECKPOINT_RECORD_BYTES_V2],
    offset: usize,
    value: u64,
) {
    encoded[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
