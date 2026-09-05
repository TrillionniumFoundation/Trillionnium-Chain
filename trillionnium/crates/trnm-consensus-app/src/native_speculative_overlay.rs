//! Route-stable, inert manifests for one BlockId-keyed speculative overlay.
//!
//! This module deliberately stops before persistence, parent-view construction,
//! JMT application, finalization, or garbage collection.  A manifest can only
//! be prepared by joining:
//!
//! - one request binding minted from a deeply authenticated durable job by the
//!   application store; and
//! - one already revalidated G1h `Valid` artifact.
//!
//! Route, validation view/generation, request fingerprint, immutable-job
//! checksum, and source-artifact checksum are intentionally absent.  Exact
//! Proposal and Synced evaluations of the same block therefore converge on one
//! manifest.  The source job/artifact lineage remains a separate store-row and
//! Core-reference concern.  Decoding this codec never recreates an
//! `AuthWrite`, a JMT plan, a domain delta, validation/callback authority, or
//! permission to advance either the speculative or committed application head.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_types::{decode_block_header_v0_exact, BlockHeader, BlockId};
use trnm_finality_types::hash_domain;

use crate::native_valid_artifact::{DurableValidCodecErrorV0, RevalidatedDurableValidArtifactV0};

pub(crate) const NATIVE_SPECULATIVE_OVERLAY_MANIFEST_CODEC_V0: &str =
    "trnm.native-speculative-overlay.manifest.v0";
pub(crate) const NATIVE_SPECULATIVE_OVERLAY_REF_CODEC_V0: &str =
    "trnm.native-speculative-overlay.ref.v0";

const NATIVE_SPECULATIVE_OVERLAY_MANIFEST_CODEC_VERSION_V0: u16 = 0;
const NATIVE_SPECULATIVE_OVERLAY_REF_CODEC_VERSION_V0: u16 = 0;

pub(crate) const NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0: usize = 522;
pub(crate) const NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0: usize = 66;

const NATIVE_SPECULATIVE_OVERLAY_TARGET_HEADER_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.target-header.v0";
const NATIVE_SPECULATIVE_OVERLAY_PARENT_HEADER_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.parent-header.v0";
const NATIVE_SPECULATIVE_OVERLAY_CONFIG_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.config.v0";
const NATIVE_SPECULATIVE_OVERLAY_RECEIPTS_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.receipts.v0";
const NATIVE_SPECULATIVE_OVERLAY_REPLAY_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.replay.v0";
const NATIVE_SPECULATIVE_OVERLAY_DOMAIN_RECIPE_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.domain-recipe.v0";
const NATIVE_SPECULATIVE_OVERLAY_MANIFEST_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.manifest-checksum.v0";
const NATIVE_SPECULATIVE_OVERLAY_REF_DOMAIN_V0: &str =
    "trnm.consensus-app.native-speculative-overlay.ref-checksum.v0";

const NATIVE_SPECULATIVE_OVERLAY_REPLAY_COMMITMENT_VERSION_V0: u16 = 0;
const NATIVE_SPECULATIVE_OVERLAY_DOMAIN_RECIPE_COMMITMENT_VERSION_V0: u16 = 0;
const NATIVE_SPECULATIVE_OVERLAY_CONFIG_COMMITMENT_VERSION_V0: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeSpeculativeOverlayRecordKindV0 {
    Manifest,
    Reference,
}

impl fmt::Display for NativeSpeculativeOverlayRecordKindV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Manifest => "native speculative-overlay manifest",
            Self::Reference => "native speculative-overlay reference",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NativeSpeculativeOverlayCodecErrorV0 {
    WrongLength {
        record: NativeSpeculativeOverlayRecordKindV0,
        expected: usize,
        actual: usize,
    },
    UnsupportedVersion {
        record: NativeSpeculativeOverlayRecordKindV0,
        version: u16,
    },
    NonCanonical(NativeSpeculativeOverlayRecordKindV0),
    InvalidRequestBinding,
    RequestConfigurationMismatch,
    ArtifactBindingMismatch,
    InvalidArtifact(DurableValidCodecErrorV0),
    ChecksumMismatch(NativeSpeculativeOverlayRecordKindV0),
    ReferenceBindingMismatch,
}

impl fmt::Display for NativeSpeculativeOverlayCodecErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::NonCanonical(record) => write!(formatter, "non-canonical {record}"),
            Self::InvalidRequestBinding => {
                formatter.write_str("invalid speculative-overlay request binding")
            }
            Self::RequestConfigurationMismatch => formatter
                .write_str("speculative-overlay request configuration does not match its header"),
            Self::ArtifactBindingMismatch => {
                formatter.write_str("speculative-overlay request and Valid artifact do not match")
            }
            Self::InvalidArtifact(error) => {
                write!(
                    formatter,
                    "invalid speculative-overlay Valid artifact: {error}"
                )
            }
            Self::ChecksumMismatch(record) => write!(formatter, "{record} checksum mismatch"),
            Self::ReferenceBindingMismatch => {
                formatter.write_str("speculative-overlay reference binding mismatch")
            }
        }
    }
}

impl Error for NativeSpeculativeOverlayCodecErrorV0 {}

/// Store-authenticated, route-stable request fields needed to bind an overlay.
///
/// The production constructor consumes a permit which only `ApplicationStore`
/// may mint after deep validation of the exact durable job.  In particular,
/// no sibling can assemble header/body/config digests and present them as a
/// durable-job fact without that permit.  This carrier is neither cloneable nor
/// serializable and grants no persistence or apply authority by itself.
#[must_use = "an authenticated overlay request binding must remain joined to its Valid artifact"]
#[derive(Debug)]
pub(crate) struct NativeSpeculativeOverlayRequestBindingV0 {
    target_block_id: BlockId,
    target_height: u64,
    target_payload_root: [u8; 32],
    target_state_root: [u8; 32],
    target_receipts_root: [u8; 32],
    target_evidence_root: [u8; 32],
    parent_block_id: BlockId,
    parent_height: u64,
    parent_state_root: Option<[u8; 32]>,
    target_header_commitment: [u8; 32],
    parent_header_commitment: [u8; 32],
    body_commitment: [u8; 32],
    config_commitment: [u8; 32],
}

impl NativeSpeculativeOverlayRequestBindingV0 {
    /// Joins stable fields from one exact, deeply revalidated durable job.
    ///
    /// `body_commitment` is the existing domain-separated checksum of the
    /// canonical body record. `runtime_profile_ref` and `host_config_ref` are
    /// likewise the exact references already verified against that job.  This
    /// function never accepts route, view, generation, request fingerprint, or
    /// immutable-job checksum.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_exact_job_v0(
        _permit: crate::store::NativeSpeculativeOverlayBindingPermitV0,
        target_header_cev0: &[u8],
        parent_header_cev0: Option<&[u8]>,
        body_commitment: [u8; 32],
        validator_set_id: [u8; 32],
        parameters_hash: [u8; 32],
        protocol_version: u32,
        runtime_profile_ref: [u8; 32],
        host_config_ref: [u8; 32],
    ) -> Result<Self, NativeSpeculativeOverlayCodecErrorV0> {
        Self::from_exact_job_parts_v0(
            target_header_cev0,
            parent_header_cev0,
            body_commitment,
            validator_set_id,
            parameters_hash,
            protocol_version,
            runtime_profile_ref,
            host_config_ref,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_exact_job_parts_v0(
        target_header_cev0: &[u8],
        parent_header_cev0: Option<&[u8]>,
        body_commitment: [u8; 32],
        validator_set_id: [u8; 32],
        parameters_hash: [u8; 32],
        protocol_version: u32,
        runtime_profile_ref: [u8; 32],
        host_config_ref: [u8; 32],
    ) -> Result<Self, NativeSpeculativeOverlayCodecErrorV0> {
        let target_header = decode_exact_header_v0(target_header_cev0)?;
        if target_header.validator_set_id().as_bytes() != &validator_set_id
            || target_header.consensus_parameters_hash().as_bytes() != &parameters_hash
            || target_header.protocol_version().get() != protocol_version
        {
            return Err(NativeSpeculativeOverlayCodecErrorV0::RequestConfigurationMismatch);
        }

        let (parent_header, parent_header_presence) = match parent_header_cev0 {
            Some(encoded) => (Some(decode_exact_header_v0(encoded)?), [1]),
            None => (None, [0]),
        };
        let parent_header_bytes = parent_header_cev0.unwrap_or_default();
        let (parent_block_id, parent_height, parent_state_root) = if let Some(parent_header) =
            parent_header.as_ref()
        {
            if target_header.parent_id() != parent_header.id()
                || parent_header.height().get().checked_add(1) != Some(target_header.height().get())
                || parent_header.chain_id() != target_header.chain_id()
                || parent_header.genesis_hash() != target_header.genesis_hash()
            {
                return Err(NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding);
            }
            (
                parent_header.id(),
                parent_header.height().get(),
                Some(*parent_header.state_root().as_bytes()),
            )
        } else {
            if target_header.height().get() != 1
                || target_header.parent_id().as_bytes() != target_header.genesis_hash().as_bytes()
            {
                return Err(NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding);
            }
            (target_header.parent_id(), 0, None)
        };

        let config_version = NATIVE_SPECULATIVE_OVERLAY_CONFIG_COMMITMENT_VERSION_V0.to_be_bytes();
        let protocol_version = protocol_version.to_be_bytes();
        Ok(Self {
            target_block_id: target_header.id(),
            target_height: target_header.height().get(),
            target_payload_root: *target_header.payload_root().as_bytes(),
            target_state_root: *target_header.state_root().as_bytes(),
            target_receipts_root: *target_header.receipts_root().as_bytes(),
            target_evidence_root: *target_header.evidence_root().as_bytes(),
            parent_block_id,
            parent_height,
            parent_state_root,
            target_header_commitment: hash_domain(
                NATIVE_SPECULATIVE_OVERLAY_TARGET_HEADER_DOMAIN_V0,
                &[target_header_cev0],
            ),
            parent_header_commitment: hash_domain(
                NATIVE_SPECULATIVE_OVERLAY_PARENT_HEADER_DOMAIN_V0,
                &[&parent_header_presence, parent_header_bytes],
            ),
            body_commitment,
            config_commitment: hash_domain(
                NATIVE_SPECULATIVE_OVERLAY_CONFIG_DOMAIN_V0,
                &[
                    &config_version,
                    &validator_set_id,
                    &parameters_hash,
                    &protocol_version,
                    &runtime_profile_ref,
                    &host_config_ref,
                ],
            ),
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn from_exact_job_for_test_v0(
        target_header_cev0: &[u8],
        parent_header_cev0: Option<&[u8]>,
        body_commitment: [u8; 32],
        validator_set_id: [u8; 32],
        parameters_hash: [u8; 32],
        protocol_version: u32,
        runtime_profile_ref: [u8; 32],
        host_config_ref: [u8; 32],
    ) -> Result<Self, NativeSpeculativeOverlayCodecErrorV0> {
        Self::from_exact_job_parts_v0(
            target_header_cev0,
            parent_header_cev0,
            body_commitment,
            validator_set_id,
            parameters_hash,
            protocol_version,
            runtime_profile_ref,
            host_config_ref,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeSpeculativeOverlayManifestFieldsV0 {
    target_block_id: BlockId,
    parent_block_id: BlockId,
    target_height: u64,
    parent_height: u64,
    parent_state_version: u64,
    parent_state_root: [u8; 32],
    payload_root: [u8; 32],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    evidence_root: [u8; 32],
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
    target_header_commitment: [u8; 32],
    parent_header_commitment: [u8; 32],
    body_commitment: [u8; 32],
    config_commitment: [u8; 32],
    receipts_commitment: [u8; 32],
    replay_commitment: [u8; 32],
    domain_recipe_commitment: [u8; 32],
    physical_plan_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeSpeculativeOverlayManifestRecordV0 {
    fields: NativeSpeculativeOverlayManifestFieldsV0,
    encoded: [u8; NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0],
    checksum: [u8; 32],
    overlay_ref: NativeSpeculativeOverlayRefV0,
}

/// Live preparation lineage for one route-stable overlay manifest.
///
/// The value is still inert with respect to JMT/domain application, but it is
/// intentionally distinct from the decoded type so reopening bytes can never
/// recreate the carrier a future atomic store insertion will require.
#[derive(Debug)]
#[must_use = "a prepared overlay manifest must stay joined to its exact store transaction"]
pub(crate) struct PreparedNativeSpeculativeOverlayManifestV0 {
    record: NativeSpeculativeOverlayManifestRecordV0,
}

/// Strict, route-stable manifest bytes rebound to their checksum.
///
/// This decoded record exposes only identities, counters, roots, and
/// commitments. It cannot be converted into the prepared type and cannot
/// expose receipts, replay entries, the write recipe, typed domain delta, or a
/// physical JMT plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevalidatedNativeSpeculativeOverlayManifestV0 {
    record: NativeSpeculativeOverlayManifestRecordV0,
}

macro_rules! impl_overlay_manifest_accessors_v0 {
    ($manifest:ty) => {
        impl $manifest {
            pub(crate) const fn target_block_id(&self) -> BlockId {
                self.record.fields.target_block_id
            }

            pub(crate) const fn parent_block_id(&self) -> BlockId {
                self.record.fields.parent_block_id
            }

            pub(crate) const fn target_height(&self) -> u64 {
                self.record.fields.target_height
            }

            pub(crate) const fn parent_height(&self) -> u64 {
                self.record.fields.parent_height
            }

            pub(crate) const fn parent_state_version(&self) -> u64 {
                self.record.fields.parent_state_version
            }

            pub(crate) const fn parent_state_root(&self) -> [u8; 32] {
                self.record.fields.parent_state_root
            }

            pub(crate) const fn payload_root(&self) -> [u8; 32] {
                self.record.fields.payload_root
            }

            pub(crate) const fn state_root(&self) -> [u8; 32] {
                self.record.fields.state_root
            }

            pub(crate) const fn receipts_root(&self) -> [u8; 32] {
                self.record.fields.receipts_root
            }

            pub(crate) const fn evidence_root(&self) -> [u8; 32] {
                self.record.fields.evidence_root
            }

            pub(crate) const fn logical_block_size(&self) -> u64 {
                self.record.fields.logical_block_size
            }

            pub(crate) const fn transaction_count(&self) -> u32 {
                self.record.fields.transaction_count
            }

            pub(crate) const fn evidence_count(&self) -> u32 {
                self.record.fields.evidence_count
            }

            pub(crate) const fn target_header_commitment(&self) -> [u8; 32] {
                self.record.fields.target_header_commitment
            }

            pub(crate) const fn parent_header_commitment(&self) -> [u8; 32] {
                self.record.fields.parent_header_commitment
            }

            pub(crate) const fn body_commitment(&self) -> [u8; 32] {
                self.record.fields.body_commitment
            }

            pub(crate) const fn config_commitment(&self) -> [u8; 32] {
                self.record.fields.config_commitment
            }

            pub(crate) const fn receipts_commitment(&self) -> [u8; 32] {
                self.record.fields.receipts_commitment
            }

            pub(crate) const fn replay_commitment(&self) -> [u8; 32] {
                self.record.fields.replay_commitment
            }

            pub(crate) const fn domain_recipe_commitment(&self) -> [u8; 32] {
                self.record.fields.domain_recipe_commitment
            }

            pub(crate) const fn physical_plan_commitment(&self) -> [u8; 32] {
                self.record.fields.physical_plan_commitment
            }

            pub(crate) const fn encoded(
                &self,
            ) -> &[u8; NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0] {
                &self.record.encoded
            }

            pub(crate) const fn checksum(&self) -> [u8; 32] {
                self.record.checksum
            }

            pub(crate) const fn overlay_ref(&self) -> &NativeSpeculativeOverlayRefV0 {
                &self.record.overlay_ref
            }
        }
    };
}

impl_overlay_manifest_accessors_v0!(PreparedNativeSpeculativeOverlayManifestV0);
impl_overlay_manifest_accessors_v0!(RevalidatedNativeSpeculativeOverlayManifestV0);

/// Strict, checksum-bound reference to one inert manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeSpeculativeOverlayRefV0 {
    block_id: BlockId,
    manifest_checksum: [u8; 32],
    encoded: [u8; NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0],
    checksum: [u8; 32],
}

impl NativeSpeculativeOverlayRefV0 {
    pub(crate) const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub(crate) const fn manifest_checksum(&self) -> [u8; 32] {
        self.manifest_checksum
    }

    pub(crate) const fn encoded(&self) -> &[u8; NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0] {
        &self.encoded
    }

    pub(crate) const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}

/// Consumes one store-authenticated stable request binding and joins it to the
/// route-independent surface of one revalidated G1h artifact.
pub(crate) fn prepare_native_speculative_overlay_manifest_v0(
    binding: NativeSpeculativeOverlayRequestBindingV0,
    artifact: &RevalidatedDurableValidArtifactV0<'_>,
) -> Result<PreparedNativeSpeculativeOverlayManifestV0, NativeSpeculativeOverlayCodecErrorV0> {
    let identity = artifact.identity();
    let facts = artifact.facts();
    if identity.validation_id().block_id() != binding.target_block_id
        || facts.target_height() != binding.target_height
        || facts.parent_height() != binding.parent_height
        || facts.parent_block_id() != binding.parent_block_id
        || facts.parent_state_version() != facts.parent_height()
        || binding
            .parent_state_root
            .is_some_and(|root| root != facts.parent_state_root())
        || facts.payload_root() != binding.target_payload_root
        || facts.state_root() != binding.target_state_root
        || facts.receipts_root() != binding.target_receipts_root
        || facts.evidence_root() != binding.target_evidence_root
    {
        return Err(NativeSpeculativeOverlayCodecErrorV0::ArtifactBindingMismatch);
    }

    // This performs the closed namespace/object/lifecycle/PoCO semantic pass.
    // The returned delta is intentionally dropped; no apply-capable carrier is
    // retained by this manifest.
    drop(
        artifact
            .revalidate_domain_delta_v0()
            .map_err(NativeSpeculativeOverlayCodecErrorV0::InvalidArtifact)?,
    );

    let fields = NativeSpeculativeOverlayManifestFieldsV0 {
        target_block_id: binding.target_block_id,
        parent_block_id: binding.parent_block_id,
        target_height: facts.target_height(),
        parent_height: facts.parent_height(),
        parent_state_version: facts.parent_state_version(),
        parent_state_root: facts.parent_state_root(),
        payload_root: facts.payload_root(),
        state_root: facts.state_root(),
        receipts_root: facts.receipts_root(),
        evidence_root: facts.evidence_root(),
        logical_block_size: facts.logical_block_size(),
        transaction_count: facts.transaction_count(),
        evidence_count: facts.evidence_count(),
        target_header_commitment: binding.target_header_commitment,
        parent_header_commitment: binding.parent_header_commitment,
        body_commitment: binding.body_commitment,
        config_commitment: binding.config_commitment,
        receipts_commitment: hash_domain(
            NATIVE_SPECULATIVE_OVERLAY_RECEIPTS_DOMAIN_V0,
            &[artifact.receipts_cev0()],
        ),
        replay_commitment: replay_commitment_v0(artifact)?,
        domain_recipe_commitment: domain_recipe_commitment_v0(artifact)?,
        physical_plan_commitment: artifact.durable_plan_commitment(),
    };
    finish_manifest_v0(fields)
}

pub(crate) fn verify_native_speculative_overlay_manifest_v0(
    encoded: &[u8],
    stored_checksum: [u8; 32],
) -> Result<RevalidatedNativeSpeculativeOverlayManifestV0, NativeSpeculativeOverlayCodecErrorV0> {
    let fields = decode_manifest_fields_v0(encoded)?;
    let canonical = encode_manifest_fields_v0(fields);
    if canonical.as_slice() != encoded {
        return Err(NativeSpeculativeOverlayCodecErrorV0::NonCanonical(
            NativeSpeculativeOverlayRecordKindV0::Manifest,
        ));
    }
    let checksum = manifest_checksum_v0(&canonical);
    if checksum != stored_checksum {
        return Err(NativeSpeculativeOverlayCodecErrorV0::ChecksumMismatch(
            NativeSpeculativeOverlayRecordKindV0::Manifest,
        ));
    }
    let overlay_ref = prepare_ref_v0(fields.target_block_id, checksum);
    Ok(RevalidatedNativeSpeculativeOverlayManifestV0 {
        record: NativeSpeculativeOverlayManifestRecordV0 {
            fields,
            encoded: canonical,
            checksum,
            overlay_ref,
        },
    })
}

pub(crate) fn verify_native_speculative_overlay_ref_v0(
    encoded: &[u8],
    stored_checksum: [u8; 32],
    expected_block_id: BlockId,
    expected_manifest_checksum: [u8; 32],
) -> Result<NativeSpeculativeOverlayRefV0, NativeSpeculativeOverlayCodecErrorV0> {
    let record = NativeSpeculativeOverlayRecordKindV0::Reference;
    if encoded.len() != NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0 {
        return Err(NativeSpeculativeOverlayCodecErrorV0::WrongLength {
            record,
            expected: NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactOverlayDecoderV0::new(encoded);
    let version = decoder.read_u16_v0();
    if version != NATIVE_SPECULATIVE_OVERLAY_REF_CODEC_VERSION_V0 {
        return Err(NativeSpeculativeOverlayCodecErrorV0::UnsupportedVersion { record, version });
    }
    let block_id = BlockId::new(decoder.read_array_v0());
    let manifest_checksum = decoder.read_array_v0();
    if block_id.is_zero() {
        return Err(NativeSpeculativeOverlayCodecErrorV0::NonCanonical(record));
    }
    let canonical = encode_ref_v0(block_id, manifest_checksum);
    if canonical.as_slice() != encoded {
        return Err(NativeSpeculativeOverlayCodecErrorV0::NonCanonical(record));
    }
    let checksum = ref_checksum_v0(&canonical);
    if checksum != stored_checksum {
        return Err(NativeSpeculativeOverlayCodecErrorV0::ChecksumMismatch(
            record,
        ));
    }
    if block_id != expected_block_id || manifest_checksum != expected_manifest_checksum {
        return Err(NativeSpeculativeOverlayCodecErrorV0::ReferenceBindingMismatch);
    }
    Ok(NativeSpeculativeOverlayRefV0 {
        block_id,
        manifest_checksum,
        encoded: canonical,
        checksum,
    })
}

fn finish_manifest_v0(
    fields: NativeSpeculativeOverlayManifestFieldsV0,
) -> Result<PreparedNativeSpeculativeOverlayManifestV0, NativeSpeculativeOverlayCodecErrorV0> {
    validate_manifest_fields_v0(fields)?;
    let encoded = encode_manifest_fields_v0(fields);
    let checksum = manifest_checksum_v0(&encoded);
    let overlay_ref = prepare_ref_v0(fields.target_block_id, checksum);
    Ok(PreparedNativeSpeculativeOverlayManifestV0 {
        record: NativeSpeculativeOverlayManifestRecordV0 {
            fields,
            encoded,
            checksum,
            overlay_ref,
        },
    })
}

fn prepare_ref_v0(block_id: BlockId, manifest_checksum: [u8; 32]) -> NativeSpeculativeOverlayRefV0 {
    let encoded = encode_ref_v0(block_id, manifest_checksum);
    let checksum = ref_checksum_v0(&encoded);
    NativeSpeculativeOverlayRefV0 {
        block_id,
        manifest_checksum,
        encoded,
        checksum,
    }
}

fn validate_manifest_fields_v0(
    fields: NativeSpeculativeOverlayManifestFieldsV0,
) -> Result<(), NativeSpeculativeOverlayCodecErrorV0> {
    if fields.target_block_id.is_zero()
        || fields.parent_block_id.is_zero()
        || fields.target_height == 0
        || fields.parent_height.checked_add(1) != Some(fields.target_height)
        || fields.parent_state_version != fields.parent_height
    {
        return Err(NativeSpeculativeOverlayCodecErrorV0::NonCanonical(
            NativeSpeculativeOverlayRecordKindV0::Manifest,
        ));
    }
    Ok(())
}

fn decode_exact_header_v0(
    encoded: &[u8],
) -> Result<BlockHeader, NativeSpeculativeOverlayCodecErrorV0> {
    let header = decode_block_header_v0_exact(encoded)
        .map_err(|_| NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding)?;
    if header
        .try_cev0_bytes()
        .map_err(|_| NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding)?
        .as_slice()
        != encoded
    {
        return Err(NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding);
    }
    Ok(header)
}

fn replay_commitment_v0(
    artifact: &RevalidatedDurableValidArtifactV0<'_>,
) -> Result<[u8; 32], NativeSpeculativeOverlayCodecErrorV0> {
    let mut hasher = ExactOverlayDomainHasherV0::new(NATIVE_SPECULATIVE_OVERLAY_REPLAY_DOMAIN_V0);
    hasher.frame_v0(&NATIVE_SPECULATIVE_OVERLAY_REPLAY_COMMITMENT_VERSION_V0.to_be_bytes());
    let command_count = u32::try_from(artifact.command_ids().len())
        .map_err(|_| NativeSpeculativeOverlayCodecErrorV0::ArtifactBindingMismatch)?;
    hasher.frame_v0(&command_count.to_be_bytes());
    for command_id in artifact.command_ids() {
        hasher.frame_v0(command_id.as_bytes());
    }
    let signer_nonce_count = u32::try_from(artifact.signer_nonces().len())
        .map_err(|_| NativeSpeculativeOverlayCodecErrorV0::ArtifactBindingMismatch)?;
    hasher.frame_v0(&signer_nonce_count.to_be_bytes());
    for signer_nonce in artifact.signer_nonces() {
        hasher.frame_v0(signer_nonce.signer_id().as_bytes());
        hasher.frame_v0(&signer_nonce.nonce().to_be_bytes());
    }
    Ok(hasher.finish_v0())
}

fn domain_recipe_commitment_v0(
    artifact: &RevalidatedDurableValidArtifactV0<'_>,
) -> Result<[u8; 32], NativeSpeculativeOverlayCodecErrorV0> {
    let mut hasher =
        ExactOverlayDomainHasherV0::new(NATIVE_SPECULATIVE_OVERLAY_DOMAIN_RECIPE_DOMAIN_V0);
    hasher.frame_v0(&NATIVE_SPECULATIVE_OVERLAY_DOMAIN_RECIPE_COMMITMENT_VERSION_V0.to_be_bytes());
    let write_count = u32::try_from(artifact.writes().len())
        .map_err(|_| NativeSpeculativeOverlayCodecErrorV0::ArtifactBindingMismatch)?;
    hasher.frame_v0(&write_count.to_be_bytes());
    for write in artifact.writes() {
        hasher.frame_v0(write.key());
        match write.value() {
            None => hasher.frame_v0(&[0]),
            Some(value) => {
                hasher.frame_v0(&[1]);
                hasher.frame_v0(value);
            }
        }
    }
    Ok(hasher.finish_v0())
}

fn manifest_checksum_v0(encoded: &[u8; NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0]) -> [u8; 32] {
    hash_domain(NATIVE_SPECULATIVE_OVERLAY_MANIFEST_DOMAIN_V0, &[encoded])
}

fn ref_checksum_v0(encoded: &[u8; NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0]) -> [u8; 32] {
    hash_domain(NATIVE_SPECULATIVE_OVERLAY_REF_DOMAIN_V0, &[encoded])
}

fn encode_manifest_fields_v0(
    fields: NativeSpeculativeOverlayManifestFieldsV0,
) -> [u8; NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0] {
    let mut encoded = [0u8; NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0];
    let mut offset = 0usize;
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &NATIVE_SPECULATIVE_OVERLAY_MANIFEST_CODEC_VERSION_V0.to_be_bytes(),
    );
    put_overlay_bytes_v0(&mut encoded, &mut offset, fields.target_block_id.as_bytes());
    put_overlay_bytes_v0(&mut encoded, &mut offset, fields.parent_block_id.as_bytes());
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.target_height.to_be_bytes(),
    );
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.parent_height.to_be_bytes(),
    );
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.parent_state_version.to_be_bytes(),
    );
    put_overlay_bytes_v0(&mut encoded, &mut offset, &fields.parent_state_root);
    put_overlay_bytes_v0(&mut encoded, &mut offset, &fields.payload_root);
    put_overlay_bytes_v0(&mut encoded, &mut offset, &fields.state_root);
    put_overlay_bytes_v0(&mut encoded, &mut offset, &fields.receipts_root);
    put_overlay_bytes_v0(&mut encoded, &mut offset, &fields.evidence_root);
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.logical_block_size.to_be_bytes(),
    );
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.transaction_count.to_be_bytes(),
    );
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &fields.evidence_count.to_be_bytes(),
    );
    for commitment in [
        fields.target_header_commitment,
        fields.parent_header_commitment,
        fields.body_commitment,
        fields.config_commitment,
        fields.receipts_commitment,
        fields.replay_commitment,
        fields.domain_recipe_commitment,
        fields.physical_plan_commitment,
    ] {
        put_overlay_bytes_v0(&mut encoded, &mut offset, &commitment);
    }
    debug_assert_eq!(offset, NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0);
    encoded
}

fn decode_manifest_fields_v0(
    encoded: &[u8],
) -> Result<NativeSpeculativeOverlayManifestFieldsV0, NativeSpeculativeOverlayCodecErrorV0> {
    let record = NativeSpeculativeOverlayRecordKindV0::Manifest;
    if encoded.len() != NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0 {
        return Err(NativeSpeculativeOverlayCodecErrorV0::WrongLength {
            record,
            expected: NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0,
            actual: encoded.len(),
        });
    }
    let mut decoder = ExactOverlayDecoderV0::new(encoded);
    let version = decoder.read_u16_v0();
    if version != NATIVE_SPECULATIVE_OVERLAY_MANIFEST_CODEC_VERSION_V0 {
        return Err(NativeSpeculativeOverlayCodecErrorV0::UnsupportedVersion { record, version });
    }
    let fields = NativeSpeculativeOverlayManifestFieldsV0 {
        target_block_id: BlockId::new(decoder.read_array_v0()),
        parent_block_id: BlockId::new(decoder.read_array_v0()),
        target_height: decoder.read_u64_v0(),
        parent_height: decoder.read_u64_v0(),
        parent_state_version: decoder.read_u64_v0(),
        parent_state_root: decoder.read_array_v0(),
        payload_root: decoder.read_array_v0(),
        state_root: decoder.read_array_v0(),
        receipts_root: decoder.read_array_v0(),
        evidence_root: decoder.read_array_v0(),
        logical_block_size: decoder.read_u64_v0(),
        transaction_count: decoder.read_u32_v0(),
        evidence_count: decoder.read_u32_v0(),
        target_header_commitment: decoder.read_array_v0(),
        parent_header_commitment: decoder.read_array_v0(),
        body_commitment: decoder.read_array_v0(),
        config_commitment: decoder.read_array_v0(),
        receipts_commitment: decoder.read_array_v0(),
        replay_commitment: decoder.read_array_v0(),
        domain_recipe_commitment: decoder.read_array_v0(),
        physical_plan_commitment: decoder.read_array_v0(),
    };
    validate_manifest_fields_v0(fields)?;
    Ok(fields)
}

fn encode_ref_v0(
    block_id: BlockId,
    manifest_checksum: [u8; 32],
) -> [u8; NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0] {
    let mut encoded = [0u8; NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0];
    let mut offset = 0usize;
    put_overlay_bytes_v0(
        &mut encoded,
        &mut offset,
        &NATIVE_SPECULATIVE_OVERLAY_REF_CODEC_VERSION_V0.to_be_bytes(),
    );
    put_overlay_bytes_v0(&mut encoded, &mut offset, block_id.as_bytes());
    put_overlay_bytes_v0(&mut encoded, &mut offset, &manifest_checksum);
    debug_assert_eq!(offset, NATIVE_SPECULATIVE_OVERLAY_REF_BYTES_V0);
    encoded
}

fn put_overlay_bytes_v0<const N: usize>(encoded: &mut [u8; N], offset: &mut usize, value: &[u8]) {
    let end = offset
        .checked_add(value.len())
        .expect("fixed overlay codec offset does not overflow");
    encoded[*offset..end].copy_from_slice(value);
    *offset = end;
}

struct ExactOverlayDecoderV0<'a> {
    remaining: &'a [u8],
}

impl<'a> ExactOverlayDecoderV0<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn read_array_v0<const N: usize>(&mut self) -> [u8; N] {
        let (value, remaining) = self.remaining.split_at(N);
        self.remaining = remaining;
        value
            .try_into()
            .expect("fixed overlay decoder was length-checked")
    }

    fn read_u16_v0(&mut self) -> u16 {
        u16::from_be_bytes(self.read_array_v0())
    }

    fn read_u32_v0(&mut self) -> u32 {
        u32::from_be_bytes(self.read_array_v0())
    }

    fn read_u64_v0(&mut self) -> u64 {
        u64::from_be_bytes(self.read_array_v0())
    }
}

/// Streaming form of `trnm_finality_types::hash_domain` used to avoid cloning
/// bounded-but-large replay and domain recipes into an intermediate buffer.
struct ExactOverlayDomainHasherV0(Sha256);

impl ExactOverlayDomainHasherV0 {
    fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self(hasher)
    }

    fn frame_v0(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn finish_v0(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
    use trnm_consensus_types::{
        BlockKind, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
        PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot, ValidatorId, ValidatorSetId, View,
    };

    use crate::{
        auth_tree::durable_plan::DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0,
        native_execution::NativeBlockExecutionV0,
        native_valid_artifact::{
            durable_valid_result_kind_v0, prepare_durable_valid_artifact_v0,
            verify_durable_valid_artifact_v0, DurableValidArtifactFactsV0,
            DurableValidArtifactInputV0,
        },
        native_validation_artifact::NativeValidationArtifactIdentityV0,
    };

    const BODY_COMMITMENT_V0: [u8; 32] = [0x71; 32];
    const RUNTIME_PROFILE_REF_V0: [u8; 32] = [0x72; 32];
    const HOST_CONFIG_REF_V0: [u8; 32] = [0x73; 32];

    struct FixtureV0 {
        target_header: BlockHeader,
        parent_header: BlockHeader,
        facts: DurableValidArtifactFactsV0,
        receipts_cev0: Vec<u8>,
    }

    fn fixture_v0() -> FixtureV0 {
        let execution = NativeBlockExecutionV0::empty();
        let payload_root = execution
            .application_payload()
            .payload_root()
            .expect("empty payload root");
        let receipts_root = execution
            .execution_receipts()
            .receipts_root()
            .expect("empty receipts root");
        let receipts_cev0 = execution
            .execution_receipts()
            .try_cev0_bytes()
            .expect("empty receipts CEV0");
        let genesis_hash = GenesisHash::new([0x11; 32]);
        let chain_id = ChainId::new("overlay-route-stable-test").expect("test chain ID");
        let validator_set_id = ValidatorSetId::new([0x12; 32]);
        let parameters_hash = ConsensusParametersHash::new([0x13; 32]);
        let parent_header = BlockHeader::new(
            genesis_hash,
            chain_id,
            ProtocolVersion::V0,
            Epoch::new(0),
            View::new(7),
            Height::new(1),
            BlockKind::Regular,
            BlockId::new([0x14; 32]),
            ValidatorId::new([0x15; 32]),
            validator_set_id,
            parameters_hash,
            PayloadDigest::new([0x16; 32]),
            StateRoot::new([0x17; 32]),
            ReceiptsRoot::new([0x18; 32]),
            EvidenceRoot::new([0x19; 32]),
            10,
            None,
        )
        .expect("parent header");
        let target_header = BlockHeader::new(
            genesis_hash,
            chain_id,
            ProtocolVersion::V0,
            Epoch::new(0),
            View::new(8),
            Height::new(2),
            BlockKind::Regular,
            parent_header.id(),
            ValidatorId::new([0x15; 32]),
            validator_set_id,
            parameters_hash,
            payload_root,
            StateRoot::new([0x21; 32]),
            receipts_root,
            EvidenceRoot::new([0x22; 32]),
            11,
            None,
        )
        .expect("target header");
        let facts = DurableValidArtifactFactsV0::new_v0(
            target_header.height().get(),
            parent_header.height().get(),
            parent_header.id(),
            parent_header.height().get(),
            *parent_header.state_root().as_bytes(),
            *target_header.payload_root().as_bytes(),
            *target_header.state_root().as_bytes(),
            *target_header.receipts_root().as_bytes(),
            *target_header.evidence_root().as_bytes(),
            4,
            0,
            0,
        );
        FixtureV0 {
            target_header,
            parent_header,
            facts,
            receipts_cev0,
        }
    }

    fn request_binding_v0(fixture: &FixtureV0) -> NativeSpeculativeOverlayRequestBindingV0 {
        NativeSpeculativeOverlayRequestBindingV0::from_exact_job_for_test_v0(
            &fixture
                .target_header
                .try_cev0_bytes()
                .expect("target header CEV0"),
            Some(
                &fixture
                    .parent_header
                    .try_cev0_bytes()
                    .expect("parent header CEV0"),
            ),
            BODY_COMMITMENT_V0,
            *fixture.target_header.validator_set_id().as_bytes(),
            *fixture.target_header.consensus_parameters_hash().as_bytes(),
            fixture.target_header.protocol_version().get(),
            RUNTIME_PROFILE_REF_V0,
            HOST_CONFIG_REF_V0,
        )
        .expect("route-stable request binding")
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_artifact_v0<'a>(
        fixture: &FixtureV0,
        route: PayloadValidationRouteV0,
        view: View,
        generation: u64,
        request_fingerprint: [u8; 32],
        immutable_checksum: [u8; 32],
        plan_commitment: [u8; DURABLE_AUTH_PLAN_COMMITMENT_BYTES_V0],
        artifact_bytes: &'a mut Vec<u8>,
    ) -> RevalidatedDurableValidArtifactV0<'a> {
        let identity = NativeValidationArtifactIdentityV0::new_v0(
            route,
            ValidationId::new(fixture.target_header.id(), view, generation),
            request_fingerprint,
            immutable_checksum,
        );
        let prepared = prepare_durable_valid_artifact_v0(DurableValidArtifactInputV0 {
            identity,
            facts: fixture.facts,
            command_ids: &[],
            signer_nonces: &[],
            receipts_cev0: &fixture.receipts_cev0,
            writes: &[],
            durable_plan_commitment: plan_commitment,
        })
        .expect("prepare route-specific Valid artifact");
        let checksum = prepared.checksum();
        artifact_bytes.extend_from_slice(prepared.encoded());
        verify_durable_valid_artifact_v0(
            prepared.artifact_codec(),
            artifact_bytes,
            checksum,
            durable_valid_result_kind_v0(),
            identity,
            fixture.facts,
        )
        .expect("revalidate route-specific Valid artifact")
    }

    #[test]
    fn manifest_and_reference_round_trip_are_strict_and_inert_v0() {
        let fixture = fixture_v0();
        let mut artifact_bytes = Vec::new();
        let artifact = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Proposal,
            fixture.target_header.view(),
            3,
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            &mut artifact_bytes,
        );
        let manifest =
            prepare_native_speculative_overlay_manifest_v0(request_binding_v0(&fixture), &artifact)
                .expect("prepare overlay manifest");
        assert_eq!(
            manifest.encoded().len(),
            NATIVE_SPECULATIVE_OVERLAY_MANIFEST_BYTES_V0
        );
        assert_eq!(manifest.target_block_id(), fixture.target_header.id());
        assert_eq!(manifest.parent_block_id(), fixture.parent_header.id());
        assert_eq!(manifest.target_height(), 2);
        assert_eq!(manifest.parent_height(), 1);
        assert_eq!(manifest.parent_state_version(), 1);
        assert_eq!(
            manifest.parent_state_root(),
            *fixture.parent_header.state_root().as_bytes()
        );
        assert_eq!(
            manifest.payload_root(),
            *fixture.target_header.payload_root().as_bytes()
        );
        assert_eq!(
            manifest.state_root(),
            *fixture.target_header.state_root().as_bytes()
        );
        assert_eq!(
            manifest.receipts_root(),
            *fixture.target_header.receipts_root().as_bytes()
        );
        assert_eq!(
            manifest.evidence_root(),
            *fixture.target_header.evidence_root().as_bytes()
        );
        assert_eq!(manifest.logical_block_size(), 4);
        assert_eq!(manifest.transaction_count(), 0);
        assert_eq!(manifest.evidence_count(), 0);
        assert_eq!(manifest.body_commitment(), BODY_COMMITMENT_V0);
        assert_eq!(manifest.physical_plan_commitment(), [0x33; 32]);

        let reopened =
            verify_native_speculative_overlay_manifest_v0(manifest.encoded(), manifest.checksum())
                .expect("strict manifest reopen");
        assert_eq!(reopened.encoded(), manifest.encoded());
        assert_eq!(reopened.checksum(), manifest.checksum());
        assert_eq!(reopened.target_block_id(), manifest.target_block_id());
        assert_eq!(reopened.parent_block_id(), manifest.parent_block_id());
        assert_eq!(
            reopened.physical_plan_commitment(),
            manifest.physical_plan_commitment()
        );
        let overlay_ref = manifest.overlay_ref();
        assert_eq!(overlay_ref.block_id(), fixture.target_header.id());
        assert_eq!(overlay_ref.manifest_checksum(), manifest.checksum());
        let reopened_ref = verify_native_speculative_overlay_ref_v0(
            overlay_ref.encoded(),
            overlay_ref.checksum(),
            manifest.target_block_id(),
            manifest.checksum(),
        )
        .expect("strict overlay-ref reopen");
        assert_eq!(&reopened_ref, overlay_ref);
    }

    #[test]
    fn proposal_and_synced_evaluations_converge_without_route_or_job_identity_v0() {
        let fixture = fixture_v0();
        let mut proposal_bytes = Vec::new();
        let proposal = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Proposal,
            fixture.target_header.view(),
            3,
            [0x41; 32],
            [0x42; 32],
            [0x43; 32],
            &mut proposal_bytes,
        );
        let proposal_manifest =
            prepare_native_speculative_overlay_manifest_v0(request_binding_v0(&fixture), &proposal)
                .expect("proposal manifest");

        let mut synced_bytes = Vec::new();
        let synced = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Synced,
            fixture.target_header.view(),
            99,
            [0x51; 32],
            [0x52; 32],
            [0x43; 32],
            &mut synced_bytes,
        );
        let synced_manifest =
            prepare_native_speculative_overlay_manifest_v0(request_binding_v0(&fixture), &synced)
                .expect("synced manifest");

        assert_ne!(proposal.identity(), synced.identity());
        assert_ne!(proposal.checksum(), synced.checksum());
        assert_eq!(proposal_manifest.encoded(), synced_manifest.encoded());
        assert_eq!(proposal_manifest.checksum(), synced_manifest.checksum());
        assert_eq!(
            proposal_manifest.overlay_ref(),
            synced_manifest.overlay_ref()
        );
    }

    #[test]
    fn manifest_binds_route_stable_receipts_recipe_and_physical_plan_surfaces_v0() {
        let fixture = fixture_v0();
        let mut baseline_bytes = Vec::new();
        let baseline = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Proposal,
            fixture.target_header.view(),
            1,
            [1; 32],
            [2; 32],
            [3; 32],
            &mut baseline_bytes,
        );
        let baseline_manifest =
            prepare_native_speculative_overlay_manifest_v0(request_binding_v0(&fixture), &baseline)
                .expect("baseline manifest");

        let mut plan_splice_bytes = Vec::new();
        let plan_splice = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Proposal,
            fixture.target_header.view(),
            1,
            [1; 32],
            [2; 32],
            [4; 32],
            &mut plan_splice_bytes,
        );
        let plan_splice_manifest = prepare_native_speculative_overlay_manifest_v0(
            request_binding_v0(&fixture),
            &plan_splice,
        )
        .expect("plan-splice manifest");
        assert_ne!(
            baseline_manifest.physical_plan_commitment(),
            plan_splice_manifest.physical_plan_commitment()
        );
        assert_ne!(
            baseline_manifest.checksum(),
            plan_splice_manifest.checksum()
        );

        let mut spliced_state_root = fixture.facts.state_root();
        spliced_state_root[0] ^= 1;
        let root_splice_facts = DurableValidArtifactFactsV0::new_v0(
            fixture.facts.target_height(),
            fixture.facts.parent_height(),
            fixture.facts.parent_block_id(),
            fixture.facts.parent_state_version(),
            fixture.facts.parent_state_root(),
            fixture.facts.payload_root(),
            spliced_state_root,
            fixture.facts.receipts_root(),
            fixture.facts.evidence_root(),
            fixture.facts.logical_block_size(),
            fixture.facts.transaction_count(),
            fixture.facts.evidence_count(),
        );
        let identity = NativeValidationArtifactIdentityV0::new_v0(
            PayloadValidationRouteV0::Proposal,
            ValidationId::new(fixture.target_header.id(), fixture.target_header.view(), 1),
            [1; 32],
            [2; 32],
        );
        let prepared = prepare_durable_valid_artifact_v0(DurableValidArtifactInputV0 {
            identity,
            facts: root_splice_facts,
            command_ids: &[],
            signer_nonces: &[],
            receipts_cev0: &fixture.receipts_cev0,
            writes: &[],
            durable_plan_commitment: [3; 32],
        })
        .expect("structural root-splice artifact");
        let root_splice = verify_durable_valid_artifact_v0(
            prepared.artifact_codec(),
            prepared.encoded(),
            prepared.checksum(),
            durable_valid_result_kind_v0(),
            identity,
            root_splice_facts,
        )
        .expect("bind structural root splice");
        assert_eq!(
            prepare_native_speculative_overlay_manifest_v0(
                request_binding_v0(&fixture),
                &root_splice,
            )
            .expect_err("target header and artifact root must match"),
            NativeSpeculativeOverlayCodecErrorV0::ArtifactBindingMismatch
        );
    }

    #[test]
    fn manifest_and_reference_reject_boundaries_checksums_and_ref_splices_v0() {
        let fixture = fixture_v0();
        let mut artifact_bytes = Vec::new();
        let artifact = verified_artifact_v0(
            &fixture,
            PayloadValidationRouteV0::Proposal,
            fixture.target_header.view(),
            1,
            [0x61; 32],
            [0x62; 32],
            [0x63; 32],
            &mut artifact_bytes,
        );
        let manifest =
            prepare_native_speculative_overlay_manifest_v0(request_binding_v0(&fixture), &artifact)
                .expect("manifest");

        let truncated = &manifest.encoded()[..manifest.encoded().len() - 1];
        assert!(matches!(
            verify_native_speculative_overlay_manifest_v0(truncated, manifest.checksum()),
            Err(NativeSpeculativeOverlayCodecErrorV0::WrongLength { .. })
        ));
        let mut trailing = manifest.encoded().to_vec();
        trailing.push(0);
        assert!(matches!(
            verify_native_speculative_overlay_manifest_v0(&trailing, manifest.checksum()),
            Err(NativeSpeculativeOverlayCodecErrorV0::WrongLength { .. })
        ));
        let mut wrong_version = *manifest.encoded();
        wrong_version[1] = 1;
        assert!(matches!(
            verify_native_speculative_overlay_manifest_v0(&wrong_version, manifest.checksum()),
            Err(NativeSpeculativeOverlayCodecErrorV0::UnsupportedVersion { .. })
        ));
        let mut wrong_checksum = manifest.checksum();
        wrong_checksum[0] ^= 1;
        assert!(matches!(
            verify_native_speculative_overlay_manifest_v0(manifest.encoded(), wrong_checksum),
            Err(NativeSpeculativeOverlayCodecErrorV0::ChecksumMismatch(
                NativeSpeculativeOverlayRecordKindV0::Manifest
            ))
        ));

        let overlay_ref = manifest.overlay_ref();
        let mut wrong_ref_checksum = overlay_ref.checksum();
        wrong_ref_checksum[0] ^= 1;
        assert!(matches!(
            verify_native_speculative_overlay_ref_v0(
                overlay_ref.encoded(),
                wrong_ref_checksum,
                overlay_ref.block_id(),
                overlay_ref.manifest_checksum(),
            ),
            Err(NativeSpeculativeOverlayCodecErrorV0::ChecksumMismatch(
                NativeSpeculativeOverlayRecordKindV0::Reference
            ))
        ));
        assert_eq!(
            verify_native_speculative_overlay_ref_v0(
                overlay_ref.encoded(),
                overlay_ref.checksum(),
                BlockId::new([0x99; 32]),
                overlay_ref.manifest_checksum(),
            )
            .expect_err("different block cannot claim the ref"),
            NativeSpeculativeOverlayCodecErrorV0::ReferenceBindingMismatch
        );
        assert!(matches!(
            verify_native_speculative_overlay_ref_v0(
                &overlay_ref.encoded()[..overlay_ref.encoded().len() - 1],
                overlay_ref.checksum(),
                overlay_ref.block_id(),
                overlay_ref.manifest_checksum(),
            ),
            Err(NativeSpeculativeOverlayCodecErrorV0::WrongLength { .. })
        ));
    }

    #[test]
    fn request_binding_requires_exact_headers_and_matching_configuration_v0() {
        let fixture = fixture_v0();
        let target = fixture.target_header.try_cev0_bytes().expect("target CEV0");
        let parent = fixture.parent_header.try_cev0_bytes().expect("parent CEV0");
        let mut truncated = target.clone();
        truncated.pop();
        assert_eq!(
            NativeSpeculativeOverlayRequestBindingV0::from_exact_job_for_test_v0(
                &truncated,
                Some(&parent),
                BODY_COMMITMENT_V0,
                *fixture.target_header.validator_set_id().as_bytes(),
                *fixture.target_header.consensus_parameters_hash().as_bytes(),
                fixture.target_header.protocol_version().get(),
                RUNTIME_PROFILE_REF_V0,
                HOST_CONFIG_REF_V0,
            )
            .expect_err("truncated header is rejected"),
            NativeSpeculativeOverlayCodecErrorV0::InvalidRequestBinding
        );
        assert_eq!(
            NativeSpeculativeOverlayRequestBindingV0::from_exact_job_for_test_v0(
                &target,
                Some(&parent),
                BODY_COMMITMENT_V0,
                [0xff; 32],
                *fixture.target_header.consensus_parameters_hash().as_bytes(),
                fixture.target_header.protocol_version().get(),
                RUNTIME_PROFILE_REF_V0,
                HOST_CONFIG_REF_V0,
            )
            .expect_err("detached configuration splice is rejected"),
            NativeSpeculativeOverlayCodecErrorV0::RequestConfigurationMismatch
        );
    }
}
