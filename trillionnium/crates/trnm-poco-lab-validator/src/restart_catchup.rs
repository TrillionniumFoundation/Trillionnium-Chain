//! Dedicated, inert wire and bounded admission for process-2 catch-up.
//!
//! `RestartCatchup` is deliberately separate from ordinary consensus ingress
//! and the five-phase restart protocol.  This module can authenticate and
//! canonically classify one Request, Manifest, or Chunk, then consume that
//! verified carrier into a non-evicting process-local admission action.  It
//! has no mesh handler, archive reader/writer, process journal transition,
//! RecoveryReady/RecoveryStart barrier, signer, timer, Core, or Node authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ConsensusParametersV0, ValidatorId, ValidatorSet,
};
use trnm_native_application::{
    decode_native_executed_block_artifact_v0, encode_native_executed_block_artifact_v0,
};

use crate::{
    config::validate_run_id,
    consensus_mesh::{MeshInboundFrameV0, PeerDirectionV0, PeerSessionFactsV0},
    frame::{AuthenticatedFrame, FrameKind, MAX_FRAME_PAYLOAD_BYTES},
    relay::ConsensusRelayEnvelopeV0,
    wire::{decode_quorum_certificate, UnboundProposalV0},
};

const WIRE_MAGIC_V1: &[u8; 8] = b"TRNMRCU1";
const WIRE_VERSION_V1: u16 = 1;
const REQUEST_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.request.v1";
const MANIFEST_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.manifest.v1";
const CHUNK_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.chunk.v1";
const CONTEXT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.context.v1";
const MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.manifest-id.v1";
const CHUNK_CONTENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.chunk-content.v1";
const MESSAGE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.message.v1";
const BUNDLE_ENTRY_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.bundle-entry.v1";
const APPLIED_CUT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-catchup.applied-cut.v1";
const BUNDLE_MAGIC_V1: &[u8; 8] = b"TRNMRBU1";
const BUNDLE_VERSION_V1: u16 = 1;
const BUNDLE_ENTRY_MAGIC_V1: &[u8; 8] = b"TRNMRBE1";
const BUNDLE_ENTRY_VERSION_V1: u16 = 1;
const RESTART_CATCHUP_BUNDLE_FILE_V1: &str = "restart-catchup-provider-bundle-v1.bin";
const RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1: &str = "restart-catchup-provider-bundle-v1.next";
const RESTART_CATCHUP_BUNDLE_SIDECARS_V1: [&str; 3] = [
    RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1,
    "restart-catchup-provider-bundle-v1.tmp",
    "restart-catchup-provider-bundle-v1.lock",
];
const RESTART_CATCHUP_BUNDLE_WRITING_PREFIX_V1: &str =
    "restart-catchup-provider-bundle-v1.writing.";
static RESTART_CATCHUP_BUNDLE_WRITING_ATTEMPT_V1: AtomicU64 = AtomicU64::new(0);
const SIGNATURE_BYTES_V1: usize = 64;
const MAX_CONTEXT_BYTES_V1: usize = 768;
const MAX_BODY_BYTES_V1: usize = 72 * 1024;

/// First-profile bounds.  They are intentionally limited to the seven-node
/// direct-recovery campaign; 31/100-validator recovery remains unavailable.
pub const RESTART_CATCHUP_VALIDATOR_COUNT_V1: usize = 7;
pub const RESTART_CATCHUP_PROVIDER_LIMIT_V1: usize = RESTART_CATCHUP_VALIDATOR_COUNT_V1 - 1;
pub const MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1: u32 = 4_096;
pub const MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1: u32 = 16;
pub const MAX_RESTART_CATCHUP_CHUNK_BYTES_V1: usize = 32 * 1024;
pub const MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1: u64 = 512 * 1024;
pub const MAX_RESTART_CATCHUP_WIRE_BYTES_V1: usize = 96 * 1024;
pub const MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1: usize = 512 * 1024;
pub const MAX_RESTART_CATCHUP_ENTRY_PROPOSAL_BYTES_V1: usize = 192 * 1024;
pub const MAX_RESTART_CATCHUP_ENTRY_QC_BYTES_V1: usize = 64 * 1024;
pub const MAX_RESTART_CATCHUP_ENTRY_NATIVE_ARTIFACT_BYTES_V1: usize = 240 * 1024;

const MAX_TOTAL_CHUNKS_V1: usize =
    RESTART_CATCHUP_PROVIDER_LIMIT_V1 * MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1 as usize;
const MAX_TOTAL_BYTES_V1: u64 =
    RESTART_CATCHUP_PROVIDER_LIMIT_V1 as u64 * MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1;

const _: () = assert!(MAX_RESTART_CATCHUP_WIRE_BYTES_V1 < MAX_FRAME_PAYLOAD_BYTES);
const _: () = assert!(MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1 < MAX_FRAME_PAYLOAD_BYTES as u64);
const _: () = assert!(MAX_RESTART_CATCHUP_CHUNK_BYTES_V1 < MAX_BODY_BYTES_V1);
const _: () = assert!(
    MAX_RESTART_CATCHUP_ENTRY_PROPOSAL_BYTES_V1
        + MAX_RESTART_CATCHUP_ENTRY_QC_BYTES_V1
        + MAX_RESTART_CATCHUP_ENTRY_NATIVE_ARTIFACT_BYTES_V1
        < MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RestartCatchupSubtypeV1 {
    Request = 1,
    Manifest = 2,
    Chunk = 3,
}

impl RestartCatchupSubtypeV1 {
    fn signing_domain(self) -> &'static [u8] {
        match self {
            Self::Request => REQUEST_SIGNING_DOMAIN_V1,
            Self::Manifest => MANIFEST_SIGNING_DOMAIN_V1,
            Self::Chunk => CHUNK_SIGNING_DOMAIN_V1,
        }
    }
}

impl TryFrom<u8> for RestartCatchupSubtypeV1 {
    type Error = RestartCatchupErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Manifest),
            3 => Ok(Self::Chunk),
            _ => Err(RestartCatchupErrorV1::Malformed("subtype")),
        }
    }
}

/// Complete recovery-session identity shared by one target and all providers.
/// It is inert, cloneable wire data and carries no restart transition owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartCatchupContextV1 {
    run_id: String,
    campaign_context_sha256: [u8; 32],
    fleet_start_certificate_sha256: [u8; 32],
    validator_set_id: [u8; 32],
    validator_set_sha256: [u8; 32],
    restart_cut_artifact_sha256: [u8; 32],
    target_validator: ValidatorId,
    process_instance: u64,
    recovery_nonce: [u8; 32],
    restart_cut_height: u64,
    restart_cut_block_id: [u8; 32],
}

impl RestartCatchupContextV1 {
    // B1a deliberately ships the authenticated wire boundary before B1b
    // installs the runtime scheduler that will construct this expected
    // context. Keep the constructor crate-private and warning-clean meanwhile.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn new_expected_v1(
        run_id: String,
        campaign_context_sha256: [u8; 32],
        fleet_start_certificate_sha256: [u8; 32],
        validator_set_id: [u8; 32],
        validator_set_sha256: [u8; 32],
        restart_cut_artifact_sha256: [u8; 32],
        target_validator: ValidatorId,
        process_instance: u64,
        recovery_nonce: [u8; 32],
        restart_cut_height: u64,
        restart_cut_block_id: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCatchupErrorV1> {
        let value = Self {
            run_id,
            campaign_context_sha256,
            fleet_start_certificate_sha256,
            validator_set_id,
            validator_set_sha256,
            restart_cut_artifact_sha256,
            target_validator,
            process_instance,
            recovery_nonce,
            restart_cut_height,
            restart_cut_block_id,
        };
        value.validate_for_set(validator_set)?;
        Ok(value)
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn campaign_context_sha256(&self) -> [u8; 32] {
        self.campaign_context_sha256
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.validator_set_sha256
    }

    pub const fn restart_cut_artifact_sha256(&self) -> [u8; 32] {
        self.restart_cut_artifact_sha256
    }

    pub const fn target_validator(&self) -> ValidatorId {
        self.target_validator
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn recovery_nonce(&self) -> [u8; 32] {
        self.recovery_nonce
    }

    pub const fn restart_cut_height(&self) -> u64 {
        self.restart_cut_height
    }

    pub const fn restart_cut_block_id(&self) -> [u8; 32] {
        self.restart_cut_block_id
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(CONTEXT_DIGEST_DOMAIN_V1, &self.encode())
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(512);
        put_bytes_u16(&mut output, self.run_id.as_bytes());
        output.extend_from_slice(&self.campaign_context_sha256);
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.extend_from_slice(&self.validator_set_id);
        output.extend_from_slice(&self.validator_set_sha256);
        output.extend_from_slice(&self.restart_cut_artifact_sha256);
        put_validator_id(&mut output, self.target_validator);
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.recovery_nonce);
        output.extend_from_slice(&self.restart_cut_height.to_be_bytes());
        output.extend_from_slice(&self.restart_cut_block_id);
        debug_assert!(output.len() <= MAX_CONTEXT_BYTES_V1);
        output
    }

    fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCatchupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let mut cursor = CatchupCursorV1::new(bytes);
        let run_id_length = u16::from_be_bytes(cursor.array()?) as usize;
        if run_id_length == 0 {
            return Err(RestartCatchupErrorV1::Malformed("run ID length"));
        }
        let run_id = std::str::from_utf8(cursor.take(run_id_length)?)
            .map_err(|_| RestartCatchupErrorV1::Malformed("run ID UTF-8"))?
            .to_owned();
        let value = Self {
            run_id,
            campaign_context_sha256: cursor.array()?,
            fleet_start_certificate_sha256: cursor.array()?,
            validator_set_id: cursor.array()?,
            validator_set_sha256: cursor.array()?,
            restart_cut_artifact_sha256: cursor.array()?,
            target_validator: cursor.validator_id()?,
            process_instance: u64::from_be_bytes(cursor.array()?),
            recovery_nonce: cursor.array()?,
            restart_cut_height: u64::from_be_bytes(cursor.array()?),
            restart_cut_block_id: cursor.array()?,
        };
        cursor.finish()?;
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(RestartCatchupErrorV1::NonCanonical);
        }
        Ok(value)
    }

    fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), RestartCatchupErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RestartCatchupErrorV1::InvalidValidatorSet)?;
        if validator_set.validators().len() != RESTART_CATCHUP_VALIDATOR_COUNT_V1 {
            return Err(RestartCatchupErrorV1::UnsupportedProfile);
        }
        if !self.run_id.starts_with("poco-g3-7-") || validate_run_id(&self.run_id).is_err() {
            return Err(RestartCatchupErrorV1::Malformed("run ID"));
        }
        if validator_set
            .validators()
            .iter()
            .any(|validator| validator.id().as_bytes().len() != 32)
        {
            return Err(RestartCatchupErrorV1::InvalidValidatorSet);
        }
        if self.validator_set_id != *validator_set.id().as_bytes() {
            return Err(RestartCatchupErrorV1::WrongValidatorSet);
        }
        if validator_set.validator(self.target_validator).is_none() {
            return Err(RestartCatchupErrorV1::UnknownTarget);
        }
        if self.process_instance != 2 {
            return Err(RestartCatchupErrorV1::Malformed("process instance"));
        }
        for digest in [
            self.campaign_context_sha256,
            self.fleet_start_certificate_sha256,
            self.validator_set_id,
            self.validator_set_sha256,
            self.restart_cut_artifact_sha256,
            self.recovery_nonce,
            self.restart_cut_block_id,
        ] {
            if digest == [0; 32] {
                return Err(RestartCatchupErrorV1::Malformed(
                    "zero recovery context digest",
                ));
            }
        }
        if self.restart_cut_height == 0 {
            return Err(RestartCatchupErrorV1::Malformed("RestartCut height"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupRequestFactsV1 {
    restart_cut_height: u64,
    restart_cut_block_id: [u8; 32],
    maximum_entries: u32,
    maximum_chunks: u32,
    maximum_bytes: u64,
}

impl RestartCatchupRequestFactsV1 {
    pub const fn restart_cut_height(self) -> u64 {
        self.restart_cut_height
    }

    pub const fn restart_cut_block_id(self) -> [u8; 32] {
        self.restart_cut_block_id
    }

    pub const fn maximum_entries(self) -> u32 {
        self.maximum_entries
    }

    pub const fn maximum_chunks(self) -> u32 {
        self.maximum_chunks
    }

    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupManifestFactsV1 {
    restart_cut_height: u64,
    restart_cut_block_id: [u8; 32],
    first_height: u64,
    entry_count: u32,
    chunk_count: u32,
    total_bytes: u64,
    last_certified_height: u64,
    last_certified_block_id: [u8; 32],
    last_certified_proposal_sha256: [u8; 32],
    last_certified_qc_sha256: [u8; 32],
    target_applied_height: u64,
    target_applied_block_id: [u8; 32],
    target_applied_state_root: [u8; 32],
    target_applied_application_commit_id: [u8; 32],
    target_applied_chain_root: [u8; 32],
    target_applied_timestamp_ms: u64,
    target_applied_checkpoint_sha256: [u8; 32],
    target_applied_artifact_commitment: [u8; 32],
    target_applied_entry_digest: [u8; 32],
    terminal_entry_digest: [u8; 32],
    bundle_sha256: [u8; 32],
    manifest_digest: [u8; 32],
}

impl RestartCatchupManifestFactsV1 {
    pub const fn restart_cut_height(self) -> u64 {
        self.restart_cut_height
    }

    pub const fn restart_cut_block_id(self) -> [u8; 32] {
        self.restart_cut_block_id
    }

    pub const fn first_height(self) -> u64 {
        self.first_height
    }

    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }

    pub const fn chunk_count(self) -> u32 {
        self.chunk_count
    }

    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    pub const fn last_certified_height(self) -> u64 {
        self.last_certified_height
    }

    pub const fn last_certified_block_id(self) -> [u8; 32] {
        self.last_certified_block_id
    }

    pub const fn last_certified_proposal_sha256(self) -> [u8; 32] {
        self.last_certified_proposal_sha256
    }

    pub const fn last_certified_qc_sha256(self) -> [u8; 32] {
        self.last_certified_qc_sha256
    }

    pub const fn target_applied_height(self) -> u64 {
        self.target_applied_height
    }

    pub const fn target_applied_block_id(self) -> [u8; 32] {
        self.target_applied_block_id
    }

    pub const fn target_applied_state_root(self) -> [u8; 32] {
        self.target_applied_state_root
    }

    pub const fn target_applied_application_commit_id(self) -> [u8; 32] {
        self.target_applied_application_commit_id
    }

    pub const fn target_applied_chain_root(self) -> [u8; 32] {
        self.target_applied_chain_root
    }

    pub const fn target_applied_timestamp_ms(self) -> u64 {
        self.target_applied_timestamp_ms
    }

    pub const fn target_applied_checkpoint_sha256(self) -> [u8; 32] {
        self.target_applied_checkpoint_sha256
    }

    pub const fn target_applied_artifact_commitment(self) -> [u8; 32] {
        self.target_applied_artifact_commitment
    }

    pub const fn target_applied_entry_digest(self) -> [u8; 32] {
        self.target_applied_entry_digest
    }

    pub const fn terminal_entry_digest(self) -> [u8; 32] {
        self.terminal_entry_digest
    }

    pub const fn bundle_sha256(self) -> [u8; 32] {
        self.bundle_sha256
    }

    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupChunkFactsV1 {
    manifest_digest: [u8; 32],
    chunk_index: u32,
    chunk_count: u32,
    predecessor_digest: [u8; 32],
    content_digest: [u8; 32],
    byte_count: u32,
}

impl RestartCatchupChunkFactsV1 {
    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn chunk_index(self) -> u32 {
        self.chunk_index
    }

    pub const fn chunk_count(self) -> u32 {
        self.chunk_count
    }

    pub const fn predecessor_digest(self) -> [u8; 32] {
        self.predecessor_digest
    }

    pub const fn content_digest(self) -> [u8; 32] {
        self.content_digest
    }

    pub const fn byte_count(self) -> u32 {
        self.byte_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCatchupRequestBodyV1 {
    facts: RestartCatchupRequestFactsV1,
}

impl RestartCatchupRequestBodyV1 {
    fn validate(&self, context: &RestartCatchupContextV1) -> Result<(), RestartCatchupErrorV1> {
        let facts = self.facts;
        let chunk_capacity = u64::from(facts.maximum_chunks)
            .checked_mul(MAX_RESTART_CATCHUP_CHUNK_BYTES_V1 as u64)
            .ok_or(RestartCatchupErrorV1::Capacity)?;
        if facts.restart_cut_height != context.restart_cut_height
            || facts.restart_cut_block_id != context.restart_cut_block_id
            || facts.maximum_entries == 0
            || facts.maximum_entries > MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1
            || facts.maximum_chunks == 0
            || facts.maximum_chunks > MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1
            || facts.maximum_bytes == 0
            || facts.maximum_bytes > MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1
            || facts.maximum_bytes > chunk_capacity
        {
            return Err(RestartCatchupErrorV1::Malformed("request bounds"));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.facts.restart_cut_height.to_be_bytes());
        output.extend_from_slice(&self.facts.restart_cut_block_id);
        output.extend_from_slice(&self.facts.maximum_entries.to_be_bytes());
        output.extend_from_slice(&self.facts.maximum_chunks.to_be_bytes());
        output.extend_from_slice(&self.facts.maximum_bytes.to_be_bytes());
    }

    fn decode(cursor: &mut CatchupCursorV1<'_>) -> Result<Self, RestartCatchupErrorV1> {
        Ok(Self {
            facts: RestartCatchupRequestFactsV1 {
                restart_cut_height: u64::from_be_bytes(cursor.array()?),
                restart_cut_block_id: cursor.array()?,
                maximum_entries: u32::from_be_bytes(cursor.array()?),
                maximum_chunks: u32::from_be_bytes(cursor.array()?),
                maximum_bytes: u64::from_be_bytes(cursor.array()?),
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCatchupManifestBodyV1 {
    restart_cut_height: u64,
    restart_cut_block_id: [u8; 32],
    first_height: u64,
    entry_count: u32,
    chunk_count: u32,
    total_bytes: u64,
    last_certified_height: u64,
    last_certified_block_id: [u8; 32],
    last_certified_proposal_sha256: [u8; 32],
    last_certified_qc_sha256: [u8; 32],
    target_applied_height: u64,
    target_applied_block_id: [u8; 32],
    target_applied_state_root: [u8; 32],
    target_applied_application_commit_id: [u8; 32],
    target_applied_chain_root: [u8; 32],
    target_applied_timestamp_ms: u64,
    target_applied_checkpoint_sha256: [u8; 32],
    target_applied_artifact_commitment: [u8; 32],
    target_applied_entry_digest: [u8; 32],
    terminal_entry_digest: [u8; 32],
    bundle_sha256: [u8; 32],
}

impl RestartCatchupManifestBodyV1 {
    fn validate(&self, context: &RestartCatchupContextV1) -> Result<(), RestartCatchupErrorV1> {
        let expected_first =
            context
                .restart_cut_height
                .checked_add(1)
                .ok_or(RestartCatchupErrorV1::Malformed(
                    "manifest first height overflow",
                ))?;
        let expected_entries = self
            .last_certified_height
            .checked_sub(context.restart_cut_height)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(RestartCatchupErrorV1::Malformed("manifest entry count"))?;
        let chunk_capacity = u64::from(self.chunk_count)
            .checked_mul(MAX_RESTART_CATCHUP_CHUNK_BYTES_V1 as u64)
            .ok_or(RestartCatchupErrorV1::Capacity)?;
        if self.restart_cut_height != context.restart_cut_height
            || self.restart_cut_block_id != context.restart_cut_block_id
            || self.first_height != expected_first
            || self.last_certified_height < self.first_height
            || self.entry_count == 0
            || self.entry_count != expected_entries
            || self.entry_count > MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1
            || self.chunk_count == 0
            || self.chunk_count > MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1
            || self.total_bytes == 0
            || self.total_bytes > MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1
            || self.total_bytes > chunk_capacity
            || self.total_bytes < u64::from(self.chunk_count)
            || self.target_applied_height < self.first_height
            || self.target_applied_height > self.last_certified_height
            || self.target_applied_timestamp_ms == 0
        {
            return Err(RestartCatchupErrorV1::Malformed("manifest bounds"));
        }
        for digest in [
            self.last_certified_block_id,
            self.last_certified_proposal_sha256,
            self.last_certified_qc_sha256,
            self.target_applied_block_id,
            self.target_applied_state_root,
            self.target_applied_application_commit_id,
            self.target_applied_chain_root,
            self.target_applied_checkpoint_sha256,
            self.target_applied_artifact_commitment,
            self.target_applied_entry_digest,
            self.terminal_entry_digest,
            self.bundle_sha256,
        ] {
            if digest == [0; 32] {
                return Err(RestartCatchupErrorV1::Malformed(
                    "zero manifest certified/applied coordinate",
                ));
            }
        }
        Ok(())
    }

    fn facts(self, manifest_digest: [u8; 32]) -> RestartCatchupManifestFactsV1 {
        RestartCatchupManifestFactsV1 {
            restart_cut_height: self.restart_cut_height,
            restart_cut_block_id: self.restart_cut_block_id,
            first_height: self.first_height,
            entry_count: self.entry_count,
            chunk_count: self.chunk_count,
            total_bytes: self.total_bytes,
            last_certified_height: self.last_certified_height,
            last_certified_block_id: self.last_certified_block_id,
            last_certified_proposal_sha256: self.last_certified_proposal_sha256,
            last_certified_qc_sha256: self.last_certified_qc_sha256,
            target_applied_height: self.target_applied_height,
            target_applied_block_id: self.target_applied_block_id,
            target_applied_state_root: self.target_applied_state_root,
            target_applied_application_commit_id: self.target_applied_application_commit_id,
            target_applied_chain_root: self.target_applied_chain_root,
            target_applied_timestamp_ms: self.target_applied_timestamp_ms,
            target_applied_checkpoint_sha256: self.target_applied_checkpoint_sha256,
            target_applied_artifact_commitment: self.target_applied_artifact_commitment,
            target_applied_entry_digest: self.target_applied_entry_digest,
            terminal_entry_digest: self.terminal_entry_digest,
            bundle_sha256: self.bundle_sha256,
            manifest_digest,
        }
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.restart_cut_height.to_be_bytes());
        output.extend_from_slice(&self.restart_cut_block_id);
        output.extend_from_slice(&self.first_height.to_be_bytes());
        output.extend_from_slice(&self.entry_count.to_be_bytes());
        output.extend_from_slice(&self.chunk_count.to_be_bytes());
        output.extend_from_slice(&self.total_bytes.to_be_bytes());
        output.extend_from_slice(&self.last_certified_height.to_be_bytes());
        output.extend_from_slice(&self.last_certified_block_id);
        output.extend_from_slice(&self.last_certified_proposal_sha256);
        output.extend_from_slice(&self.last_certified_qc_sha256);
        output.extend_from_slice(&self.target_applied_height.to_be_bytes());
        output.extend_from_slice(&self.target_applied_block_id);
        output.extend_from_slice(&self.target_applied_state_root);
        output.extend_from_slice(&self.target_applied_application_commit_id);
        output.extend_from_slice(&self.target_applied_chain_root);
        output.extend_from_slice(&self.target_applied_timestamp_ms.to_be_bytes());
        output.extend_from_slice(&self.target_applied_checkpoint_sha256);
        output.extend_from_slice(&self.target_applied_artifact_commitment);
        output.extend_from_slice(&self.target_applied_entry_digest);
        output.extend_from_slice(&self.terminal_entry_digest);
        output.extend_from_slice(&self.bundle_sha256);
    }

    fn decode(cursor: &mut CatchupCursorV1<'_>) -> Result<Self, RestartCatchupErrorV1> {
        Ok(Self {
            restart_cut_height: u64::from_be_bytes(cursor.array()?),
            restart_cut_block_id: cursor.array()?,
            first_height: u64::from_be_bytes(cursor.array()?),
            entry_count: u32::from_be_bytes(cursor.array()?),
            chunk_count: u32::from_be_bytes(cursor.array()?),
            total_bytes: u64::from_be_bytes(cursor.array()?),
            last_certified_height: u64::from_be_bytes(cursor.array()?),
            last_certified_block_id: cursor.array()?,
            last_certified_proposal_sha256: cursor.array()?,
            last_certified_qc_sha256: cursor.array()?,
            target_applied_height: u64::from_be_bytes(cursor.array()?),
            target_applied_block_id: cursor.array()?,
            target_applied_state_root: cursor.array()?,
            target_applied_application_commit_id: cursor.array()?,
            target_applied_chain_root: cursor.array()?,
            target_applied_timestamp_ms: u64::from_be_bytes(cursor.array()?),
            target_applied_checkpoint_sha256: cursor.array()?,
            target_applied_artifact_commitment: cursor.array()?,
            target_applied_entry_digest: cursor.array()?,
            terminal_entry_digest: cursor.array()?,
            bundle_sha256: cursor.array()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestartCatchupChunkBodyV1 {
    manifest_digest: [u8; 32],
    chunk_index: u32,
    chunk_count: u32,
    predecessor_digest: [u8; 32],
    content_digest: [u8; 32],
    bytes: Vec<u8>,
}

impl RestartCatchupChunkBodyV1 {
    fn validate(&self) -> Result<(), RestartCatchupErrorV1> {
        if self.manifest_digest == [0; 32]
            || self.predecessor_digest == [0; 32]
            || self.content_digest == [0; 32]
            || self.chunk_count == 0
            || self.chunk_count > MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1
            || self.chunk_index >= self.chunk_count
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_RESTART_CATCHUP_CHUNK_BYTES_V1
        {
            return Err(RestartCatchupErrorV1::Malformed("chunk bounds"));
        }
        if chunk_content_digest_v1(&self.bytes) != self.content_digest {
            return Err(RestartCatchupErrorV1::Malformed("chunk content digest"));
        }
        Ok(())
    }

    fn facts(&self) -> Result<RestartCatchupChunkFactsV1, RestartCatchupErrorV1> {
        Ok(RestartCatchupChunkFactsV1 {
            manifest_digest: self.manifest_digest,
            chunk_index: self.chunk_index,
            chunk_count: self.chunk_count,
            predecessor_digest: self.predecessor_digest,
            content_digest: self.content_digest,
            byte_count: u32::try_from(self.bytes.len())
                .map_err(|_| RestartCatchupErrorV1::TooLarge)?,
        })
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), RestartCatchupErrorV1> {
        output.extend_from_slice(&self.manifest_digest);
        output.extend_from_slice(&self.chunk_index.to_be_bytes());
        output.extend_from_slice(&self.chunk_count.to_be_bytes());
        output.extend_from_slice(&self.predecessor_digest);
        output.extend_from_slice(&self.content_digest);
        put_bytes_u32(output, &self.bytes)?;
        Ok(())
    }

    fn decode(cursor: &mut CatchupCursorV1<'_>) -> Result<Self, RestartCatchupErrorV1> {
        let manifest_digest = cursor.array()?;
        let chunk_index = u32::from_be_bytes(cursor.array()?);
        let chunk_count = u32::from_be_bytes(cursor.array()?);
        let predecessor_digest = cursor.array()?;
        let content_digest = cursor.array()?;
        let byte_count = u32::from_be_bytes(cursor.array()?) as usize;
        if byte_count == 0 || byte_count > MAX_RESTART_CATCHUP_CHUNK_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let bytes = cursor.take(byte_count)?.to_vec();
        Ok(Self {
            manifest_digest,
            chunk_index,
            chunk_count,
            predecessor_digest,
            content_digest,
            bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RestartCatchupBodyV1 {
    Request(RestartCatchupRequestBodyV1),
    Manifest(RestartCatchupManifestBodyV1),
    Chunk(RestartCatchupChunkBodyV1),
}

impl RestartCatchupBodyV1 {
    const fn subtype(&self) -> RestartCatchupSubtypeV1 {
        match self {
            Self::Request(_) => RestartCatchupSubtypeV1::Request,
            Self::Manifest(_) => RestartCatchupSubtypeV1::Manifest,
            Self::Chunk(_) => RestartCatchupSubtypeV1::Chunk,
        }
    }

    fn validate(&self, context: &RestartCatchupContextV1) -> Result<(), RestartCatchupErrorV1> {
        match self {
            Self::Request(body) => body.validate(context),
            Self::Manifest(body) => body.validate(context),
            Self::Chunk(body) => body.validate(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, RestartCatchupErrorV1> {
        let mut output = Vec::new();
        match self {
            Self::Request(body) => body.encode(&mut output),
            Self::Manifest(body) => body.encode(&mut output),
            Self::Chunk(body) => body.encode(&mut output)?,
        }
        if output.is_empty() || output.len() > MAX_BODY_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        Ok(output)
    }

    fn decode(
        subtype: RestartCatchupSubtypeV1,
        bytes: &[u8],
        context: &RestartCatchupContextV1,
    ) -> Result<Self, RestartCatchupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_BODY_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let mut cursor = CatchupCursorV1::new(bytes);
        let value = match subtype {
            RestartCatchupSubtypeV1::Request => {
                Self::Request(RestartCatchupRequestBodyV1::decode(&mut cursor)?)
            }
            RestartCatchupSubtypeV1::Manifest => {
                Self::Manifest(RestartCatchupManifestBodyV1::decode(&mut cursor)?)
            }
            RestartCatchupSubtypeV1::Chunk => {
                Self::Chunk(RestartCatchupChunkBodyV1::decode(&mut cursor)?)
            }
        };
        cursor.finish()?;
        value.validate(context)?;
        if value.encode()? != bytes {
            return Err(RestartCatchupErrorV1::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedRestartCatchupMessageV1 {
    context: RestartCatchupContextV1,
    provider: ValidatorId,
    origin: ValidatorId,
    body: RestartCatchupBodyV1,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedRestartCatchupMessageV1 {
    fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, RestartCatchupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_RESTART_CATCHUP_WIRE_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let mut cursor = CatchupCursorV1::new(bytes);
        if cursor.take(WIRE_MAGIC_V1.len())? != WIRE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(RestartCatchupErrorV1::Malformed("wire header"));
        }
        let subtype = RestartCatchupSubtypeV1::try_from(cursor.byte()?)?;
        let context_length = u32::from_be_bytes(cursor.array()?) as usize;
        if context_length == 0 || context_length > MAX_CONTEXT_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let context = RestartCatchupContextV1::decode(cursor.take(context_length)?, validator_set)?;
        let provider = cursor.validator_id()?;
        let origin = cursor.validator_id()?;
        let body_length = u32::from_be_bytes(cursor.array()?) as usize;
        if body_length == 0
            || body_length > MAX_BODY_BYTES_V1
            || body_length.checked_add(SIGNATURE_BYTES_V1) != Some(cursor.remaining())
        {
            return Err(RestartCatchupErrorV1::Malformed("body length"));
        }
        let body = RestartCatchupBodyV1::decode(subtype, cursor.take(body_length)?, &context)?;
        let signature = cursor.array()?;
        cursor.finish()?;
        let value = Self {
            context,
            provider,
            origin,
            body,
            signature,
        };
        value.validate_common(validator_set)?;
        value.verify_signature(validator_set)?;
        if value.encode()? != bytes {
            return Err(RestartCatchupErrorV1::NonCanonical);
        }
        Ok(value)
    }

    #[cfg(test)]
    fn sign_for_test(
        context: RestartCatchupContextV1,
        provider: ValidatorId,
        origin: ValidatorId,
        body: RestartCatchupBodyV1,
        validator_set: &ValidatorSet,
        origin_key: &SigningKey,
    ) -> Result<Self, RestartCatchupErrorV1> {
        let mut value = Self {
            context,
            provider,
            origin,
            body,
            signature: [0; SIGNATURE_BYTES_V1],
        };
        value.validate_common(validator_set)?;
        if origin_key.verifying_key().as_bytes()
            != validator_set
                .validator(origin)
                .ok_or(RestartCatchupErrorV1::UnknownOrigin)?
                .consensus_key()
                .as_bytes()
        {
            return Err(RestartCatchupErrorV1::OriginKeyMismatch);
        }
        value.signature = origin_key.sign(&value.signing_root()?).to_bytes();
        Ok(value)
    }

    fn subtype(&self) -> RestartCatchupSubtypeV1 {
        self.body.subtype()
    }

    fn validate_common(&self, validator_set: &ValidatorSet) -> Result<(), RestartCatchupErrorV1> {
        self.context.validate_for_set(validator_set)?;
        if validator_set.validator(self.provider).is_none() {
            return Err(RestartCatchupErrorV1::UnknownProvider);
        }
        if self.provider == self.context.target_validator {
            return Err(RestartCatchupErrorV1::ProviderIsTarget);
        }
        if validator_set.validator(self.origin).is_none() {
            return Err(RestartCatchupErrorV1::UnknownOrigin);
        }
        match self.subtype() {
            RestartCatchupSubtypeV1::Request if self.origin != self.context.target_validator => {
                return Err(RestartCatchupErrorV1::RequestOriginNotTarget);
            }
            RestartCatchupSubtypeV1::Manifest | RestartCatchupSubtypeV1::Chunk
                if self.provider != self.origin =>
            {
                return Err(RestartCatchupErrorV1::ProviderOriginMismatch);
            }
            _ => {}
        }
        self.body.validate(&self.context)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, RestartCatchupErrorV1> {
        let context = self.context.encode();
        let body = self.body.encode()?;
        let mut output = Vec::with_capacity(
            WIRE_MAGIC_V1.len()
                + 2
                + 1
                + 4
                + context.len()
                + self.provider.as_bytes().len()
                + self.origin.as_bytes().len()
                + 8
                + body.len(),
        );
        output.extend_from_slice(WIRE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.push(self.subtype() as u8);
        put_bytes_u32(&mut output, &context)?;
        put_validator_id(&mut output, self.provider);
        put_validator_id(&mut output, self.origin);
        put_bytes_u32(&mut output, &body)?;
        Ok(output)
    }

    fn encode(&self) -> Result<Vec<u8>, RestartCatchupErrorV1> {
        let mut output = self.encode_unsigned()?;
        output.extend_from_slice(&self.signature);
        if output.len() > MAX_RESTART_CATCHUP_WIRE_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        Ok(output)
    }

    fn signing_root(&self) -> Result<[u8; 32], RestartCatchupErrorV1> {
        Ok(hash_canonical(
            self.subtype().signing_domain(),
            &self.encode_unsigned()?,
        ))
    }

    fn verify_signature(&self, validator_set: &ValidatorSet) -> Result<(), RestartCatchupErrorV1> {
        let validator = validator_set
            .validator(self.origin)
            .ok_or(RestartCatchupErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| RestartCatchupErrorV1::InvalidSignature)?;
        key.verify_strict(
            &self.signing_root()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RestartCatchupErrorV1::InvalidSignature)
    }

    fn message_digest(&self) -> Result<[u8; 32], RestartCatchupErrorV1> {
        Ok(hash_canonical(MESSAGE_DIGEST_DOMAIN_V1, &self.encode()?))
    }

    fn manifest_digest(&self) -> Result<Option<[u8; 32]>, RestartCatchupErrorV1> {
        match &self.body {
            RestartCatchupBodyV1::Manifest(_) => Ok(Some(hash_canonical(
                MANIFEST_DIGEST_DOMAIN_V1,
                &self.encode_unsigned()?,
            ))),
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartCatchupTransportSourceV1 {
    DirectMesh,
    SparseRelayMesh,
    #[cfg(test)]
    VerifiedSignedBytes,
}

impl RestartCatchupTransportSourceV1 {
    const fn permits_direct(self) -> bool {
        match self {
            Self::DirectMesh => true,
            Self::SparseRelayMesh => false,
            #[cfg(test)]
            Self::VerifiedSignedBytes => true,
        }
    }

    const fn permits_relay(self) -> bool {
        match self {
            Self::DirectMesh => false,
            Self::SparseRelayMesh => true,
            #[cfg(test)]
            Self::VerifiedSignedBytes => true,
        }
    }

    const fn is_mesh(self) -> bool {
        match self {
            Self::DirectMesh | Self::SparseRelayMesh => true,
            #[cfg(test)]
            Self::VerifiedSignedBytes => false,
        }
    }
}

/// Exact transport facts minted by consuming the non-Clone mesh queue owner.
/// A cloneable [`AuthenticatedFrame`] cannot recreate this receipt in a
/// normal build, and every downstream catch-up carrier retains the outer
/// fingerprint alongside the session generation.
#[derive(Debug)]
struct AuthenticatedRestartCatchupTransportV1 {
    source: RestartCatchupTransportSourceV1,
    remote: ValidatorId,
    session_id: [u8; 32],
    session_generation: u64,
    outer_frame_fingerprint: [u8; 32],
}

/// Verified inner carrier.  It is intentionally non-Clone and exposes only
/// read-only facts; admission must consume it before chunk bytes are released.
pub struct VerifiedRestartCatchupCarrierV1 {
    message: SignedRestartCatchupMessageV1,
    transport: AuthenticatedRestartCatchupTransportV1,
}

impl VerifiedRestartCatchupCarrierV1 {
    pub const fn context(&self) -> &RestartCatchupContextV1 {
        &self.message.context
    }

    pub const fn provider(&self) -> ValidatorId {
        self.message.provider
    }

    pub const fn origin(&self) -> ValidatorId {
        self.message.origin
    }

    pub fn subtype(&self) -> RestartCatchupSubtypeV1 {
        self.message.subtype()
    }

    pub fn message_digest(&self) -> [u8; 32] {
        self.message
            .message_digest()
            .expect("verified bounded carrier always re-encodes")
    }

    pub fn request_facts(&self) -> Option<RestartCatchupRequestFactsV1> {
        match &self.message.body {
            RestartCatchupBodyV1::Request(body) => Some(body.facts),
            _ => None,
        }
    }

    pub fn manifest_facts(&self) -> Option<RestartCatchupManifestFactsV1> {
        match &self.message.body {
            RestartCatchupBodyV1::Manifest(body) => Some(
                (*body).facts(
                    self.message
                        .manifest_digest()
                        .expect("verified bounded manifest re-encodes")
                        .expect("manifest body has manifest digest"),
                ),
            ),
            _ => None,
        }
    }

    pub fn chunk_facts(&self) -> Option<RestartCatchupChunkFactsV1> {
        match &self.message.body {
            RestartCatchupBodyV1::Chunk(body) => Some(
                body.facts()
                    .expect("verified bounded chunk length fits the frozen wire"),
            ),
            _ => None,
        }
    }
}

fn validate_authenticated_catchup_transport_v1(
    frame: &AuthenticatedFrame,
    transport: &AuthenticatedRestartCatchupTransportV1,
    run_id: &str,
    direct: bool,
) -> Result<(), RestartCatchupErrorV1> {
    let source_allowed = if direct {
        transport.source.permits_direct()
    } else {
        transport.source.permits_relay()
    };
    if !source_allowed
        || transport.session_id == [0; 32]
        || transport.remote != frame.sender
        || transport.session_id != frame.session
        || (transport.source.is_mesh() && transport.session_generation == 0)
        || transport.outer_frame_fingerprint != frame.fingerprint(run_id)
    {
        return Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch);
    }
    Ok(())
}

fn take_authenticated_catchup_mesh_frame_v1(
    inbound: MeshInboundFrameV0,
    expected_session: PeerSessionFactsV0,
    run_id: &str,
) -> Result<(AuthenticatedFrame, AuthenticatedRestartCatchupTransportV1), RestartCatchupErrorV1> {
    let remote = inbound.remote();
    let session_id = inbound.session_id();
    let session_generation = inbound.session_generation();
    let frame = inbound.into_frame();
    if expected_session.direction() != PeerDirectionV0::Inbound
        || expected_session.remote() != remote
        || expected_session.session_id() != session_id
        || expected_session.generation() != session_generation
        || session_id == [0; 32]
        || session_generation == 0
        || remote != frame.sender
        || session_id != frame.session
    {
        return Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch);
    }
    let transport = AuthenticatedRestartCatchupTransportV1 {
        source: RestartCatchupTransportSourceV1::DirectMesh,
        remote,
        session_id,
        session_generation,
        outer_frame_fingerprint: frame.fingerprint(run_id),
    };
    Ok((frame, transport))
}

fn decode_authenticated_restart_catchup_frame_with_transport_v1(
    frame: &AuthenticatedFrame,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
    transport: AuthenticatedRestartCatchupTransportV1,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    expected_context.validate_for_set(validator_set)?;
    validate_authenticated_catchup_transport_v1(
        frame,
        &transport,
        expected_context.run_id(),
        true,
    )?;
    if frame.kind != FrameKind::RestartCatchup {
        return Err(RestartCatchupErrorV1::UnsupportedFrameKind);
    }
    if validator_set.validator(frame.sender).is_none() {
        return Err(RestartCatchupErrorV1::UnknownOuterSender);
    }
    let message = SignedRestartCatchupMessageV1::decode(&frame.payload, validator_set)?;
    if &message.context != expected_context {
        return Err(RestartCatchupErrorV1::WrongContext);
    }
    if frame.sender != message.origin {
        return Err(RestartCatchupErrorV1::OuterOriginMismatch);
    }
    Ok(VerifiedRestartCatchupCarrierV1 { message, transport })
}

fn decode_authenticated_relayed_restart_catchup_frame_with_transport_v1(
    frame: &AuthenticatedFrame,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
    transport: AuthenticatedRestartCatchupTransportV1,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    expected_context.validate_for_set(validator_set)?;
    validate_authenticated_catchup_transport_v1(
        frame,
        &transport,
        expected_context.run_id(),
        false,
    )?;
    if frame.kind != FrameKind::ConsensusRelay {
        return Err(RestartCatchupErrorV1::UnsupportedFrameKind);
    }
    if validator_set.validator(frame.sender).is_none() {
        return Err(RestartCatchupErrorV1::UnknownOuterSender);
    }
    let envelope = ConsensusRelayEnvelopeV0::decode_with_inner_payload_limit(
        &frame.payload,
        validator_set,
        MAX_RESTART_CATCHUP_WIRE_BYTES_V1,
    )
    .map_err(|_| RestartCatchupErrorV1::InvalidRelayEnvelope)?;
    if envelope.inner_kind() != FrameKind::RestartCatchup {
        return Err(RestartCatchupErrorV1::UnsupportedFrameKind);
    }
    let message = SignedRestartCatchupMessageV1::decode(envelope.payload(), validator_set)?;
    if &message.context != expected_context {
        return Err(RestartCatchupErrorV1::WrongContext);
    }
    if envelope.origin() != message.origin {
        return Err(RestartCatchupErrorV1::RelayOriginMismatch);
    }
    Ok(VerifiedRestartCatchupCarrierV1 { message, transport })
}

/// Decodes a directly delivered catch-up frame by consuming the authenticated
/// mesh queue owner and joining it to the current inbound session facts. The
/// caller must supply facts from the live mesh lifecycle owner; stale
/// `(remote, session, generation)` tuples are rejected before inner decoding.
pub(crate) fn decode_authenticated_restart_catchup_mesh_frame_v1(
    inbound: MeshInboundFrameV0,
    expected_session: PeerSessionFactsV0,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    expected_context.validate_for_set(validator_set)?;
    let (frame, transport) = take_authenticated_catchup_mesh_frame_v1(
        inbound,
        expected_session,
        expected_context.run_id(),
    )?;
    decode_authenticated_restart_catchup_frame_with_transport_v1(
        &frame,
        expected_context,
        validator_set,
        transport,
    )
}

/// Decodes a relayed catch-up frame by consuming the authenticated mesh queue
/// owner. The outer hop remains bound to the live mesh session while the
/// inner envelope is checked against its independently signed origin.
pub(crate) fn decode_authenticated_relayed_restart_catchup_mesh_frame_v1(
    inbound: MeshInboundFrameV0,
    expected_session: PeerSessionFactsV0,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    expected_context.validate_for_set(validator_set)?;
    let (frame, mut transport) = take_authenticated_catchup_mesh_frame_v1(
        inbound,
        expected_session,
        expected_context.run_id(),
    )?;
    transport.source = RestartCatchupTransportSourceV1::SparseRelayMesh;
    decode_authenticated_relayed_restart_catchup_frame_with_transport_v1(
        &frame,
        expected_context,
        validator_set,
        transport,
    )
}

/// Test-only signed-byte adapters. Release builds expose no raw
/// `AuthenticatedFrame` catch-up decoder, so callers cannot bypass the mesh
/// owner/session/generation boundary with a cloneable frame.
#[cfg(test)]
fn decode_authenticated_restart_catchup_frame_v1(
    frame: &AuthenticatedFrame,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    if frame.session == [0; 32] {
        return Err(RestartCatchupErrorV1::Malformed("session ID"));
    }
    let transport = AuthenticatedRestartCatchupTransportV1 {
        source: RestartCatchupTransportSourceV1::VerifiedSignedBytes,
        remote: frame.sender,
        session_id: frame.session,
        session_generation: 0,
        outer_frame_fingerprint: frame.fingerprint(expected_context.run_id()),
    };
    decode_authenticated_restart_catchup_frame_with_transport_v1(
        frame,
        expected_context,
        validator_set,
        transport,
    )
}

#[cfg(test)]
fn decode_authenticated_relayed_restart_catchup_frame_v1(
    frame: &AuthenticatedFrame,
    expected_context: &RestartCatchupContextV1,
    validator_set: &ValidatorSet,
) -> Result<VerifiedRestartCatchupCarrierV1, RestartCatchupErrorV1> {
    if frame.session == [0; 32] {
        return Err(RestartCatchupErrorV1::Malformed("session ID"));
    }
    let transport = AuthenticatedRestartCatchupTransportV1 {
        source: RestartCatchupTransportSourceV1::VerifiedSignedBytes,
        remote: frame.sender,
        session_id: frame.session,
        session_generation: 0,
        outer_frame_fingerprint: frame.fingerprint(expected_context.run_id()),
    };
    decode_authenticated_relayed_restart_catchup_frame_with_transport_v1(
        frame,
        expected_context,
        validator_set,
        transport,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupAdmissionCapacityV1 {
    maximum_providers: usize,
    maximum_chunks: usize,
    maximum_bytes: u64,
}

impl RestartCatchupAdmissionCapacityV1 {
    pub const fn maximum_providers(self) -> usize {
        self.maximum_providers
    }

    pub const fn maximum_chunks(self) -> usize {
        self.maximum_chunks
    }

    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }
}

pub fn required_restart_catchup_capacity_v1(
    validator_count: usize,
) -> Result<RestartCatchupAdmissionCapacityV1, RestartCatchupErrorV1> {
    if validator_count != RESTART_CATCHUP_VALIDATOR_COUNT_V1 {
        return Err(RestartCatchupErrorV1::UnsupportedProfile);
    }
    let maximum_chunks = RESTART_CATCHUP_PROVIDER_LIMIT_V1
        .checked_mul(MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1 as usize)
        .filter(|value| *value == MAX_TOTAL_CHUNKS_V1)
        .ok_or(RestartCatchupErrorV1::Capacity)?;
    let maximum_bytes = u64::try_from(RESTART_CATCHUP_PROVIDER_LIMIT_V1)
        .ok()
        .and_then(|count| count.checked_mul(MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1))
        .filter(|value| *value == MAX_TOTAL_BYTES_V1)
        .ok_or(RestartCatchupErrorV1::Capacity)?;
    Ok(RestartCatchupAdmissionCapacityV1 {
        maximum_providers: RESTART_CATCHUP_PROVIDER_LIMIT_V1,
        maximum_chunks,
        maximum_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartCatchupAdmissionV1 {
    New,
    ExactDuplicate,
}

pub struct RestartCatchupRequestActionV1 {
    context_digest: [u8; 32],
    provider: ValidatorId,
    facts: RestartCatchupRequestFactsV1,
}

impl RestartCatchupRequestActionV1 {
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub const fn provider(&self) -> ValidatorId {
        self.provider
    }

    pub const fn facts(&self) -> RestartCatchupRequestFactsV1 {
        self.facts
    }
}

pub struct RestartCatchupManifestActionV1 {
    context_digest: [u8; 32],
    provider: ValidatorId,
    facts: RestartCatchupManifestFactsV1,
}

impl RestartCatchupManifestActionV1 {
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub const fn provider(&self) -> ValidatorId {
        self.provider
    }

    pub const fn facts(&self) -> RestartCatchupManifestFactsV1 {
        self.facts
    }
}

pub struct RestartCatchupChunkActionV1 {
    context_digest: [u8; 32],
    provider: ValidatorId,
    facts: RestartCatchupChunkFactsV1,
    bytes: Vec<u8>,
}

impl RestartCatchupChunkActionV1 {
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub const fn provider(&self) -> ValidatorId {
        self.provider
    }

    pub const fn facts(&self) -> RestartCatchupChunkFactsV1 {
        self.facts
    }

    /// The only byte release is consuming and occurs after verified admission.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub enum RestartCatchupConsumingActionV1 {
    Request(RestartCatchupRequestActionV1),
    Manifest(RestartCatchupManifestActionV1),
    Chunk(RestartCatchupChunkActionV1),
}

pub struct RestartCatchupAdmissionResultV1 {
    admission: RestartCatchupAdmissionV1,
    action: Option<RestartCatchupConsumingActionV1>,
}

impl RestartCatchupAdmissionResultV1 {
    pub const fn admission(&self) -> RestartCatchupAdmissionV1 {
        self.admission
    }

    pub fn into_action(self) -> Option<RestartCatchupConsumingActionV1> {
        self.action
    }
}

#[derive(Debug, Clone, Copy)]
struct StoredRequestV1 {
    message_digest: [u8; 32],
    facts: RestartCatchupRequestFactsV1,
}

#[derive(Debug, Clone, Copy)]
struct StoredManifestV1 {
    message_digest: [u8; 32],
    facts: RestartCatchupManifestFactsV1,
}

#[derive(Debug, Clone, Copy)]
struct StoredChunkV1 {
    message_digest: [u8; 32],
}

#[derive(Debug, Default)]
struct ProviderAdmissionStateV1 {
    request: Option<StoredRequestV1>,
    manifest: Option<StoredManifestV1>,
    chunks: BTreeMap<u32, StoredChunkV1>,
    next_chunk_index: u32,
    next_predecessor_digest: [u8; 32],
    received_bytes: u64,
    completed: bool,
}

/// Six non-target providers from one seven-validator set, with non-evicting
/// admission. A semantic conflict, ordering violation, predecessor mismatch,
/// or capacity breach permanently poisons this recovery session.
pub struct RestartCatchupAdmissionWindowV1 {
    context: RestartCatchupContextV1,
    origins: BTreeSet<ValidatorId>,
    eligible_providers: BTreeSet<ValidatorId>,
    capacity: RestartCatchupAdmissionCapacityV1,
    provider_states: BTreeMap<ValidatorId, ProviderAdmissionStateV1>,
    reserved_chunks: usize,
    reserved_bytes: u64,
    received_chunks: usize,
    received_bytes: u64,
    poisoned: bool,
}

impl RestartCatchupAdmissionWindowV1 {
    pub fn new(
        context: RestartCatchupContextV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RestartCatchupErrorV1> {
        context.validate_for_set(validator_set)?;
        let capacity = required_restart_catchup_capacity_v1(validator_set.validators().len())?;
        let origins = validator_set
            .validators()
            .iter()
            .map(|validator| validator.id())
            .collect::<BTreeSet<_>>();
        let eligible_providers = origins
            .iter()
            .copied()
            .filter(|validator| *validator != context.target_validator)
            .collect::<BTreeSet<_>>();
        if origins.len() != RESTART_CATCHUP_VALIDATOR_COUNT_V1
            || eligible_providers.len() != capacity.maximum_providers
        {
            return Err(RestartCatchupErrorV1::InvalidValidatorSet);
        }
        Ok(Self {
            context,
            origins,
            eligible_providers,
            capacity,
            provider_states: BTreeMap::new(),
            reserved_chunks: 0,
            reserved_bytes: 0,
            received_chunks: 0,
            received_bytes: 0,
            poisoned: false,
        })
    }

    pub fn admit(
        &mut self,
        carrier: VerifiedRestartCatchupCarrierV1,
    ) -> Result<RestartCatchupAdmissionResultV1, RestartCatchupErrorV1> {
        self.ensure_live()?;
        let VerifiedRestartCatchupCarrierV1 { message, transport } = carrier;
        if !self.origins.contains(&transport.remote)
            || transport.session_id == [0; 32]
            || transport.outer_frame_fingerprint == [0; 32]
            || (transport.source.is_mesh() && transport.session_generation == 0)
        {
            return Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch);
        }
        if message.context != self.context {
            return Err(RestartCatchupErrorV1::WrongContext);
        }
        if !self.eligible_providers.contains(&message.provider)
            || !self.origins.contains(&message.origin)
        {
            return Err(RestartCatchupErrorV1::UnknownProvider);
        }
        let message_digest = message.message_digest()?;
        let context_digest = self.context.digest();
        let provider = message.provider;
        let manifest_digest = message.manifest_digest()?;
        match message.body {
            RestartCatchupBodyV1::Request(body) => {
                self.admit_request(provider, context_digest, message_digest, body.facts)
            }
            RestartCatchupBodyV1::Manifest(body) => self.admit_manifest(
                provider,
                context_digest,
                message_digest,
                body.facts(manifest_digest.expect("manifest digest exists")),
            ),
            RestartCatchupBodyV1::Chunk(body) => {
                self.admit_chunk(provider, context_digest, message_digest, body)
            }
        }
    }

    pub const fn capacity(&self) -> RestartCatchupAdmissionCapacityV1 {
        self.capacity
    }

    pub fn provider_count(&self) -> usize {
        self.provider_states.len()
    }

    pub const fn reserved_chunks(&self) -> usize {
        self.reserved_chunks
    }

    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    pub const fn received_chunks(&self) -> usize {
        self.received_chunks
    }

    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn admit_request(
        &mut self,
        provider: ValidatorId,
        context_digest: [u8; 32],
        message_digest: [u8; 32],
        facts: RestartCatchupRequestFactsV1,
    ) -> Result<RestartCatchupAdmissionResultV1, RestartCatchupErrorV1> {
        if let Some(state) = self.provider_states.get(&provider) {
            if let Some(existing) = state.request {
                if existing.message_digest == message_digest {
                    return Ok(exact_duplicate_result());
                }
                return self.poison(RestartCatchupErrorV1::Equivocation("request"));
            }
            return self.poison(RestartCatchupErrorV1::OutOfOrder("request"));
        }
        if self.provider_states.len() == self.capacity.maximum_providers {
            return self.poison(RestartCatchupErrorV1::Capacity);
        }
        let mut state = ProviderAdmissionStateV1::default();
        state.request = Some(StoredRequestV1 {
            message_digest,
            facts,
        });
        self.provider_states.insert(provider, state);
        Ok(RestartCatchupAdmissionResultV1 {
            admission: RestartCatchupAdmissionV1::New,
            action: Some(RestartCatchupConsumingActionV1::Request(
                RestartCatchupRequestActionV1 {
                    context_digest,
                    provider,
                    facts,
                },
            )),
        })
    }

    fn admit_manifest(
        &mut self,
        provider: ValidatorId,
        context_digest: [u8; 32],
        message_digest: [u8; 32],
        facts: RestartCatchupManifestFactsV1,
    ) -> Result<RestartCatchupAdmissionResultV1, RestartCatchupErrorV1> {
        let Some(state) = self.provider_states.get(&provider) else {
            return self.poison(RestartCatchupErrorV1::OutOfOrder("manifest before request"));
        };
        if let Some(existing) = state.manifest {
            if existing.message_digest == message_digest {
                return Ok(exact_duplicate_result());
            }
            return self.poison(RestartCatchupErrorV1::Equivocation("manifest"));
        }
        let request = state
            .request
            .ok_or(RestartCatchupErrorV1::OutOfOrder("manifest request"))?;
        if !state.chunks.is_empty()
            || facts.restart_cut_height != request.facts.restart_cut_height
            || facts.restart_cut_block_id != request.facts.restart_cut_block_id
            || facts.entry_count > request.facts.maximum_entries
            || facts.chunk_count > request.facts.maximum_chunks
            || facts.total_bytes > request.facts.maximum_bytes
        {
            return self.poison(RestartCatchupErrorV1::SemanticConflict(
                "manifest request bounds",
            ));
        }
        let Some(projected_chunks) = self.reserved_chunks.checked_add(facts.chunk_count as usize)
        else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        let Some(projected_bytes) = self.reserved_bytes.checked_add(facts.total_bytes) else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        if projected_chunks > self.capacity.maximum_chunks
            || projected_bytes > self.capacity.maximum_bytes
        {
            return self.poison(RestartCatchupErrorV1::Capacity);
        }
        let state = self
            .provider_states
            .get_mut(&provider)
            .expect("provider request was observed above");
        state.manifest = Some(StoredManifestV1 {
            message_digest,
            facts,
        });
        state.next_predecessor_digest = facts.manifest_digest;
        self.reserved_chunks = projected_chunks;
        self.reserved_bytes = projected_bytes;
        Ok(RestartCatchupAdmissionResultV1 {
            admission: RestartCatchupAdmissionV1::New,
            action: Some(RestartCatchupConsumingActionV1::Manifest(
                RestartCatchupManifestActionV1 {
                    context_digest,
                    provider,
                    facts,
                },
            )),
        })
    }

    fn admit_chunk(
        &mut self,
        provider: ValidatorId,
        context_digest: [u8; 32],
        message_digest: [u8; 32],
        body: RestartCatchupChunkBodyV1,
    ) -> Result<RestartCatchupAdmissionResultV1, RestartCatchupErrorV1> {
        let facts = body.facts()?;
        let Some(state) = self.provider_states.get(&provider) else {
            return self.poison(RestartCatchupErrorV1::OutOfOrder("chunk before request"));
        };
        if let Some(existing) = state.chunks.get(&facts.chunk_index) {
            if existing.message_digest == message_digest {
                return Ok(exact_duplicate_result());
            }
            return self.poison(RestartCatchupErrorV1::Equivocation("chunk index"));
        }
        let Some(manifest) = state.manifest else {
            return self.poison(RestartCatchupErrorV1::OutOfOrder("chunk before manifest"));
        };
        if state.completed
            || facts.manifest_digest != manifest.facts.manifest_digest
            || facts.chunk_count != manifest.facts.chunk_count
            || facts.chunk_index != state.next_chunk_index
            || facts.predecessor_digest != state.next_predecessor_digest
        {
            return self.poison(RestartCatchupErrorV1::SemanticConflict(
                "chunk order, manifest, count, or predecessor",
            ));
        }
        let Some(provider_bytes) = state
            .received_bytes
            .checked_add(u64::from(facts.byte_count))
        else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        let Some(received_chunks) = self.received_chunks.checked_add(1) else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        let Some(received_bytes) = self.received_bytes.checked_add(u64::from(facts.byte_count))
        else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        let Some(next_chunk_index) = state.next_chunk_index.checked_add(1) else {
            return self.poison(RestartCatchupErrorV1::Capacity);
        };
        let is_last = facts
            .chunk_index
            .checked_add(1)
            .is_some_and(|value| value == facts.chunk_count);
        if provider_bytes > manifest.facts.total_bytes
            || received_chunks > self.capacity.maximum_chunks
            || received_bytes > self.capacity.maximum_bytes
            || (is_last && provider_bytes != manifest.facts.total_bytes)
            || (!is_last && provider_bytes >= manifest.facts.total_bytes)
        {
            return self.poison(RestartCatchupErrorV1::SemanticConflict(
                "chunk aggregate bytes",
            ));
        }
        let state = self
            .provider_states
            .get_mut(&provider)
            .expect("provider state was observed above");
        state
            .chunks
            .insert(facts.chunk_index, StoredChunkV1 { message_digest });
        state.next_chunk_index = next_chunk_index;
        state.next_predecessor_digest = facts.content_digest;
        state.received_bytes = provider_bytes;
        state.completed = is_last;
        self.received_chunks = received_chunks;
        self.received_bytes = received_bytes;
        Ok(RestartCatchupAdmissionResultV1 {
            admission: RestartCatchupAdmissionV1::New,
            action: Some(RestartCatchupConsumingActionV1::Chunk(
                RestartCatchupChunkActionV1 {
                    context_digest,
                    provider,
                    facts,
                    bytes: body.bytes,
                },
            )),
        })
    }

    fn ensure_live(&self) -> Result<(), RestartCatchupErrorV1> {
        if self.poisoned {
            Err(RestartCatchupErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }

    fn poison<T>(&mut self, error: RestartCatchupErrorV1) -> Result<T, RestartCatchupErrorV1> {
        self.poisoned = true;
        Err(error)
    }
}

fn exact_duplicate_result() -> RestartCatchupAdmissionResultV1 {
    RestartCatchupAdmissionResultV1 {
        admission: RestartCatchupAdmissionV1::ExactDuplicate,
        action: None,
    }
}

/// One locally applied application/finality cut. `chain_root` is the real
/// Core finalized-prefix commitment claimed by the provider; it is not a
/// bundle-entry hash chain. The checkpoint and artifact commitments are
/// deliberately distinct: neither a signed provider manifest nor this inert
/// value is authority to install or accept any of them. A consuming Node
/// replay must recompute the application commit and Core chain root locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupAppliedCutV1 {
    height: u64,
    block_id: [u8; 32],
    state_root: [u8; 32],
    application_commit_id: [u8; 32],
    chain_root: [u8; 32],
    timestamp_ms: u64,
    checkpoint_sha256: [u8; 32],
    artifact_commitment: [u8; 32],
}

impl RestartCatchupAppliedCutV1 {
    /// Inert projection used only after the caller has authenticated the
    /// corresponding RestartCut/checkpoint authority.  It is not an owner and
    /// cannot be converted into a durable bundle without a signed manifest and
    /// strict canonical bundle decode.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_local_cut_v1(
        height: u64,
        block_id: [u8; 32],
        state_root: [u8; 32],
        application_commit_id: [u8; 32],
        chain_root: [u8; 32],
        timestamp_ms: u64,
        checkpoint_sha256: [u8; 32],
        artifact_commitment: [u8; 32],
    ) -> Result<Self, RestartCatchupErrorV1> {
        let value = Self {
            height,
            block_id,
            state_root,
            application_commit_id,
            chain_root,
            timestamp_ms,
            checkpoint_sha256,
            artifact_commitment,
        };
        value.validate_v1()?;
        Ok(value)
    }

    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn block_id(self) -> [u8; 32] {
        self.block_id
    }

    pub const fn state_root(self) -> [u8; 32] {
        self.state_root
    }

    pub const fn application_commit_id(self) -> [u8; 32] {
        self.application_commit_id
    }

    pub const fn chain_root(self) -> [u8; 32] {
        self.chain_root
    }

    pub const fn timestamp_ms(self) -> u64 {
        self.timestamp_ms
    }

    pub const fn checkpoint_sha256(self) -> [u8; 32] {
        self.checkpoint_sha256
    }

    pub const fn artifact_commitment(self) -> [u8; 32] {
        self.artifact_commitment
    }

    pub fn digest(self) -> [u8; 32] {
        hash_canonical(APPLIED_CUT_DIGEST_DOMAIN_V1, &self.encode_v1())
    }

    fn validate_v1(self) -> Result<(), RestartCatchupErrorV1> {
        if self.height == 0 || self.timestamp_ms == 0 {
            return Err(RestartCatchupErrorV1::BundleMalformed(
                "zero applied-cut height or timestamp",
            ));
        }
        for digest in [
            self.block_id,
            self.state_root,
            self.application_commit_id,
            self.chain_root,
            self.checkpoint_sha256,
            self.artifact_commitment,
        ] {
            if digest == [0; 32] {
                return Err(RestartCatchupErrorV1::BundleMalformed(
                    "zero applied-cut commitment",
                ));
            }
        }
        Ok(())
    }

    fn encode_v1(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(176);
        output.extend_from_slice(&self.height.to_be_bytes());
        output.extend_from_slice(&self.block_id);
        output.extend_from_slice(&self.state_root);
        output.extend_from_slice(&self.application_commit_id);
        output.extend_from_slice(&self.chain_root);
        output.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_sha256);
        output.extend_from_slice(&self.artifact_commitment);
        output
    }

    fn decode_v1(cursor: &mut CatchupCursorV1<'_>) -> Result<Self, RestartCatchupErrorV1> {
        let value = Self {
            height: u64::from_be_bytes(cursor.array()?),
            block_id: cursor.array()?,
            state_root: cursor.array()?,
            application_commit_id: cursor.array()?,
            chain_root: cursor.array()?,
            timestamp_ms: u64::from_be_bytes(cursor.array()?),
            checkpoint_sha256: cursor.array()?,
            artifact_commitment: cursor.array()?,
        };
        value.validate_v1()?;
        Ok(value)
    }
}

/// Exact signed Proposal/QC tail retained separately from the lower locally
/// applied cut.  A provider may be certified ahead of locally applied
/// finality; conflating these coordinates would authorize an unsafe shortcut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartCatchupCertifiedTailV1 {
    height: u64,
    block_id: [u8; 32],
    signed_proposal_sha256: [u8; 32],
    quorum_certificate_sha256: [u8; 32],
}

impl RestartCatchupCertifiedTailV1 {
    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn block_id(self) -> [u8; 32] {
        self.block_id
    }

    pub const fn signed_proposal_sha256(self) -> [u8; 32] {
        self.signed_proposal_sha256
    }

    pub const fn quorum_certificate_sha256(self) -> [u8; 32] {
        self.quorum_certificate_sha256
    }

    fn validate_v1(self) -> Result<(), RestartCatchupErrorV1> {
        if self.height == 0
            || [
                self.block_id,
                self.signed_proposal_sha256,
                self.quorum_certificate_sha256,
            ]
            .into_iter()
            .any(|digest| digest == [0; 32])
        {
            return Err(RestartCatchupErrorV1::BundleMalformed(
                "invalid certified Proposal/QC tail",
            ));
        }
        Ok(())
    }

    fn encode_v1(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.height.to_be_bytes());
        output.extend_from_slice(&self.block_id);
        output.extend_from_slice(&self.signed_proposal_sha256);
        output.extend_from_slice(&self.quorum_certificate_sha256);
    }

    fn decode_v1(cursor: &mut CatchupCursorV1<'_>) -> Result<Self, RestartCatchupErrorV1> {
        let value = Self {
            height: u64::from_be_bytes(cursor.array()?),
            block_id: cursor.array()?,
            signed_proposal_sha256: cursor.array()?,
            quorum_certificate_sha256: cursor.array()?,
        };
        value.validate_v1()?;
        Ok(value)
    }
}

/// Canonical, bounded catch-up entry.  It carries the exact signed Proposal,
/// strict QC, and canonical native execution artifact.  It is only candidate
/// material: no method imports it into Node, Core, Safety, or application
/// stores.
pub struct RestartCatchupBundleEntryV1 {
    height: u64,
    block_id: [u8; 32],
    application_commit_id: [u8; 32],
    predecessor_digest: [u8; 32],
    entry_digest: [u8; 32],
    signed_proposal_bytes: Vec<u8>,
    quorum_certificate_bytes: Vec<u8>,
    native_executed_artifact_bytes: Vec<u8>,
}

impl fmt::Debug for RestartCatchupBundleEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestartCatchupBundleEntryV1")
            .field("height", &self.height)
            .field("block_id", &self.block_id)
            .field("predecessor_digest", &self.predecessor_digest)
            .field("entry_digest", &self.entry_digest)
            .field("signed_proposal_bytes", &self.signed_proposal_bytes.len())
            .field(
                "quorum_certificate_bytes",
                &self.quorum_certificate_bytes.len(),
            )
            .field(
                "native_executed_artifact_bytes",
                &self.native_executed_artifact_bytes.len(),
            )
            .finish_non_exhaustive()
    }
}

impl RestartCatchupBundleEntryV1 {
    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_id(&self) -> [u8; 32] {
        self.block_id
    }

    pub const fn application_commit_id(&self) -> [u8; 32] {
        self.application_commit_id
    }

    pub const fn predecessor_digest(&self) -> [u8; 32] {
        self.predecessor_digest
    }

    pub const fn entry_digest(&self) -> [u8; 32] {
        self.entry_digest
    }

    pub fn signed_proposal_sha256(&self) -> [u8; 32] {
        sha256_v1(&self.signed_proposal_bytes)
    }

    pub fn quorum_certificate_sha256(&self) -> [u8; 32] {
        sha256_v1(&self.quorum_certificate_bytes)
    }

    pub fn native_artifact_commitment(&self) -> [u8; 32] {
        sha256_v1(&self.native_executed_artifact_bytes)
    }

    fn encode_v1(&self) -> Result<Vec<u8>, RestartCatchupErrorV1> {
        let mut output = Vec::with_capacity(
            154usize
                .saturating_add(self.signed_proposal_bytes.len())
                .saturating_add(self.quorum_certificate_bytes.len())
                .saturating_add(self.native_executed_artifact_bytes.len()),
        );
        output.extend_from_slice(BUNDLE_ENTRY_MAGIC_V1);
        output.extend_from_slice(&BUNDLE_ENTRY_VERSION_V1.to_be_bytes());
        output.extend_from_slice(&self.height.to_be_bytes());
        output.extend_from_slice(&self.block_id);
        output.extend_from_slice(&self.application_commit_id);
        output.extend_from_slice(&self.predecessor_digest);
        put_bounded_bundle_bytes_v1(
            &mut output,
            &self.signed_proposal_bytes,
            MAX_RESTART_CATCHUP_ENTRY_PROPOSAL_BYTES_V1,
            "signed Proposal",
        )?;
        put_bounded_bundle_bytes_v1(
            &mut output,
            &self.quorum_certificate_bytes,
            MAX_RESTART_CATCHUP_ENTRY_QC_BYTES_V1,
            "QC",
        )?;
        put_bounded_bundle_bytes_v1(
            &mut output,
            &self.native_executed_artifact_bytes,
            MAX_RESTART_CATCHUP_ENTRY_NATIVE_ARTIFACT_BYTES_V1,
            "native execution artifact",
        )?;
        let observed = hash_canonical(BUNDLE_ENTRY_DIGEST_DOMAIN_V1, &output);
        if observed != self.entry_digest {
            return Err(RestartCatchupErrorV1::BundleMismatch(
                "entry digest differs from canonical entry body",
            ));
        }
        output.extend_from_slice(&self.entry_digest);
        Ok(output)
    }
}

struct RestartCatchupEntryParentV1 {
    height: u64,
    block_id: [u8; 32],
    state_root: [u8; 32],
    application_commit_id: [u8; 32],
    timestamp_ms: u64,
    predecessor_digest: [u8; 32],
}

impl RestartCatchupEntryParentV1 {
    fn from_applied_cut_v1(cut: RestartCatchupAppliedCutV1) -> Self {
        Self {
            height: cut.height,
            block_id: cut.block_id,
            state_root: cut.state_root,
            application_commit_id: cut.application_commit_id,
            timestamp_ms: cut.timestamp_ms,
            predecessor_digest: cut.digest(),
        }
    }

    fn advance_v1(
        &mut self,
        entry: &RestartCatchupBundleEntryV1,
        timestamp_ms: u64,
        state: [u8; 32],
    ) {
        self.height = entry.height;
        self.block_id = entry.block_id;
        self.state_root = state;
        self.application_commit_id = entry.application_commit_id;
        self.timestamp_ms = timestamp_ms;
        self.predecessor_digest = entry.entry_digest;
    }
}

/// Fully decoded provider candidate.  It remains inert and is intentionally
/// non-Clone; only the durable pinned owner below may retain it across a
/// recovery barrier.
pub struct VerifiedRestartCatchupBundleCandidateV1 {
    expected_context: RestartCatchupContextV1,
    manifest_facts: RestartCatchupManifestFactsV1,
    context_digest: [u8; 32],
    provider: ValidatorId,
    source_applied_cut: RestartCatchupAppliedCutV1,
    last_certified_tail: RestartCatchupCertifiedTailV1,
    target_applied_cut: RestartCatchupAppliedCutV1,
    target_applied_entry_digest: [u8; 32],
    entries: Vec<RestartCatchupBundleEntryV1>,
    canonical_bytes: Vec<u8>,
    bundle_sha256: [u8; 32],
}

impl fmt::Debug for VerifiedRestartCatchupBundleCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRestartCatchupBundleCandidateV1")
            .field("context_digest", &self.context_digest)
            .field("provider", &self.provider)
            .field("source_applied_cut", &self.source_applied_cut)
            .field("last_certified_tail", &self.last_certified_tail)
            .field("target_applied_cut", &self.target_applied_cut)
            .field("entry_count", &self.entries.len())
            .field("bundle_sha256", &self.bundle_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedRestartCatchupBundleCandidateV1 {
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub const fn provider(&self) -> ValidatorId {
        self.provider
    }

    pub const fn source_applied_cut(&self) -> RestartCatchupAppliedCutV1 {
        self.source_applied_cut
    }

    pub const fn last_certified_tail(&self) -> RestartCatchupCertifiedTailV1 {
        self.last_certified_tail
    }

    pub const fn target_applied_cut(&self) -> RestartCatchupAppliedCutV1 {
        self.target_applied_cut
    }

    pub const fn target_applied_entry_digest(&self) -> [u8; 32] {
        self.target_applied_entry_digest
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub const fn bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }
}

/// Expected bundle identity can only be formed by consuming an authenticated,
/// admitted provider manifest.  It is not a scalar owner constructor and the
/// manifest facts alone never become caught-up authority.
pub struct RestartCatchupBundleExpectationV1 {
    context: RestartCatchupContextV1,
    provider: ValidatorId,
    source_applied_cut: RestartCatchupAppliedCutV1,
    manifest: RestartCatchupManifestFactsV1,
}

impl RestartCatchupBundleExpectationV1 {
    pub(crate) fn from_authenticated_manifest_v1(
        context: RestartCatchupContextV1,
        source_applied_cut: RestartCatchupAppliedCutV1,
        manifest: RestartCatchupManifestActionV1,
    ) -> Result<Self, RestartCatchupErrorV1> {
        source_applied_cut.validate_v1()?;
        if manifest.context_digest != context.digest()
            || source_applied_cut.height != context.restart_cut_height
            || source_applied_cut.block_id != context.restart_cut_block_id
        {
            return Err(RestartCatchupErrorV1::BundleMismatch(
                "manifest/source cut differs from expected recovery context",
            ));
        }
        let value = Self {
            context,
            provider: manifest.provider,
            source_applied_cut,
            manifest: manifest.facts,
        };
        value.validate_relations_v1()?;
        Ok(value)
    }

    pub const fn context(&self) -> &RestartCatchupContextV1 {
        &self.context
    }

    pub const fn provider(&self) -> ValidatorId {
        self.provider
    }

    pub const fn source_applied_cut(&self) -> RestartCatchupAppliedCutV1 {
        self.source_applied_cut
    }

    pub const fn manifest_facts(&self) -> RestartCatchupManifestFactsV1 {
        self.manifest
    }

    fn last_certified_tail_v1(&self) -> RestartCatchupCertifiedTailV1 {
        RestartCatchupCertifiedTailV1 {
            height: self.manifest.last_certified_height,
            block_id: self.manifest.last_certified_block_id,
            signed_proposal_sha256: self.manifest.last_certified_proposal_sha256,
            quorum_certificate_sha256: self.manifest.last_certified_qc_sha256,
        }
    }

    fn target_applied_cut_v1(&self) -> RestartCatchupAppliedCutV1 {
        RestartCatchupAppliedCutV1 {
            height: self.manifest.target_applied_height,
            block_id: self.manifest.target_applied_block_id,
            state_root: self.manifest.target_applied_state_root,
            application_commit_id: self.manifest.target_applied_application_commit_id,
            chain_root: self.manifest.target_applied_chain_root,
            timestamp_ms: self.manifest.target_applied_timestamp_ms,
            checkpoint_sha256: self.manifest.target_applied_checkpoint_sha256,
            artifact_commitment: self.manifest.target_applied_artifact_commitment,
        }
    }

    fn validate_relations_v1(&self) -> Result<(), RestartCatchupErrorV1> {
        let tail = self.last_certified_tail_v1();
        let target = self.target_applied_cut_v1();
        tail.validate_v1()?;
        target.validate_v1()?;
        if self.context.process_instance != 2
            || self.manifest.restart_cut_height != self.source_applied_cut.height
            || self.manifest.restart_cut_block_id != self.source_applied_cut.block_id
            || self.manifest.first_height
                != self
                    .source_applied_cut
                    .height
                    .checked_add(1)
                    .ok_or(RestartCatchupErrorV1::Capacity)?
            || self.manifest.entry_count
                != u32::try_from(
                    tail.height
                        .checked_sub(self.source_applied_cut.height)
                        .ok_or(RestartCatchupErrorV1::BundleMismatch(
                            "certified tail precedes source applied cut",
                        ))?,
                )
                .map_err(|_| RestartCatchupErrorV1::Capacity)?
            || target.height <= self.source_applied_cut.height
            || target.height > tail.height
            || target.chain_root == self.source_applied_cut.chain_root
        {
            return Err(RestartCatchupErrorV1::BundleMismatch(
                "certified tail and target applied cut relations",
            ));
        }
        Ok(())
    }
}

/// Reassembles exactly one provider's complete signed Manifest/Chunk chain.
/// Cross-provider chunks, a second manifest, reordering, or byte overrun
/// permanently poison the assembler before any durable publication.
pub struct RestartCatchupProviderBundleAssemblerV1 {
    expectation: RestartCatchupBundleExpectationV1,
    bytes: Vec<u8>,
    next_chunk_index: u32,
    next_predecessor_digest: [u8; 32],
    poisoned: bool,
}

impl RestartCatchupProviderBundleAssemblerV1 {
    pub(crate) fn new(expectation: RestartCatchupBundleExpectationV1) -> Self {
        let next_predecessor_digest = expectation.manifest.manifest_digest;
        Self {
            expectation,
            bytes: Vec::new(),
            next_chunk_index: 0,
            next_predecessor_digest,
            poisoned: false,
        }
    }

    pub(crate) fn admit_chunk_v1(
        &mut self,
        chunk: RestartCatchupChunkActionV1,
    ) -> Result<(), RestartCatchupErrorV1> {
        if self.poisoned {
            return Err(RestartCatchupErrorV1::Poisoned);
        }
        let facts = chunk.facts;
        if chunk.context_digest != self.expectation.context.digest()
            || chunk.provider != self.expectation.provider
            || facts.manifest_digest != self.expectation.manifest.manifest_digest
            || facts.chunk_count != self.expectation.manifest.chunk_count
            || facts.chunk_index != self.next_chunk_index
            || facts.predecessor_digest != self.next_predecessor_digest
        {
            self.poisoned = true;
            return Err(RestartCatchupErrorV1::BundleMismatch(
                "cross-provider or broken manifest/chunk chain",
            ));
        }
        let bytes = chunk.into_bytes();
        let Some(projected) = self.bytes.len().checked_add(bytes.len()) else {
            self.poisoned = true;
            return Err(RestartCatchupErrorV1::Capacity);
        };
        if projected > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1
            || u64::try_from(projected).unwrap_or(u64::MAX) > self.expectation.manifest.total_bytes
        {
            self.poisoned = true;
            return Err(RestartCatchupErrorV1::Capacity);
        }
        self.bytes.extend_from_slice(&bytes);
        let Some(next_chunk_index) = self.next_chunk_index.checked_add(1) else {
            self.poisoned = true;
            return Err(RestartCatchupErrorV1::Capacity);
        };
        self.next_chunk_index = next_chunk_index;
        self.next_predecessor_digest = facts.content_digest;
        Ok(())
    }

    pub(crate) fn finish_v1(
        self,
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
    ) -> Result<VerifiedRestartCatchupBundleCandidateV1, RestartCatchupErrorV1> {
        if self.poisoned
            || self.next_chunk_index != self.expectation.manifest.chunk_count
            || u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
                != self.expectation.manifest.total_bytes
            || sha256_v1(&self.bytes) != self.expectation.manifest.bundle_sha256
        {
            return Err(RestartCatchupErrorV1::BundleMismatch(
                "provider bundle is incomplete or differs from signed manifest",
            ));
        }
        decode_restart_catchup_bundle_candidate_v1(
            &self.bytes,
            &self.expectation,
            validator_set,
            consensus_parameters,
        )
    }
}

fn decode_restart_catchup_bundle_candidate_v1(
    bytes: &[u8],
    expectation: &RestartCatchupBundleExpectationV1,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<VerifiedRestartCatchupBundleCandidateV1, RestartCatchupErrorV1> {
    expectation.validate_relations_v1()?;
    expectation.context.validate_for_set(validator_set)?;
    if bytes.is_empty() || bytes.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 {
        return Err(RestartCatchupErrorV1::TooLarge);
    }
    if sha256_v1(bytes) != expectation.manifest.bundle_sha256 {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "bundle SHA-256 differs from authenticated manifest",
        ));
    }
    let mut cursor = CatchupCursorV1::new(bytes);
    if cursor.take(BUNDLE_MAGIC_V1.len())? != BUNDLE_MAGIC_V1
        || u16::from_be_bytes(cursor.array()?) != BUNDLE_VERSION_V1
    {
        return Err(RestartCatchupErrorV1::BundleMalformed(
            "bundle magic or version",
        ));
    }
    let context_digest = cursor.array()?;
    let process_instance = u64::from_be_bytes(cursor.array()?);
    let provider = cursor.validator_id()?;
    let source_applied_cut = RestartCatchupAppliedCutV1::decode_v1(&mut cursor)?;
    let last_certified_tail = RestartCatchupCertifiedTailV1::decode_v1(&mut cursor)?;
    let target_applied_cut = RestartCatchupAppliedCutV1::decode_v1(&mut cursor)?;
    let target_applied_entry_digest = cursor.array()?;
    let entry_count = u32::from_be_bytes(cursor.array()?);
    if context_digest != expectation.context.digest()
        || process_instance != 2
        || provider != expectation.provider
        || source_applied_cut != expectation.source_applied_cut
        || last_certified_tail != expectation.last_certified_tail_v1()
        || target_applied_cut != expectation.target_applied_cut_v1()
        || target_applied_entry_digest != expectation.manifest.target_applied_entry_digest
        || entry_count != expectation.manifest.entry_count
        || entry_count == 0
        || entry_count > MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1
    {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "bundle header differs from expected context/manifest",
        ));
    }

    let mut parent = RestartCatchupEntryParentV1::from_applied_cut_v1(source_applied_cut);
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut target_match = false;
    for _ in 0..entry_count {
        let length = u32::from_be_bytes(cursor.array()?) as usize;
        if length == 0 || length > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
        let entry = decode_restart_catchup_bundle_entry_v1(
            cursor.take(length)?,
            &parent,
            validator_set,
            consensus_parameters,
        )?;
        let signed = UnboundProposalV0::decode(
            &entry.signed_proposal_bytes,
            validator_set,
            consensus_parameters,
        )?
        .bind_authenticated_parent(
            validator_set,
            consensus_parameters,
            parent.timestamp_ms,
        )?;
        let state_root = *signed.block().header().state_root().as_bytes();
        let timestamp_ms = signed.block().header().timestamp_ms();
        if entry.height == target_applied_cut.height {
            if entry.block_id != target_applied_cut.block_id
                || state_root != target_applied_cut.state_root
                || entry.application_commit_id != target_applied_cut.application_commit_id
                || timestamp_ms != target_applied_cut.timestamp_ms
                || entry.entry_digest != target_applied_entry_digest
                || entry.native_artifact_commitment() != target_applied_cut.artifact_commitment
            {
                return Err(RestartCatchupErrorV1::BundleMismatch(
                    "target applied cut differs from its canonical entry",
                ));
            }
            target_match = true;
        }
        parent.advance_v1(&entry, timestamp_ms, state_root);
        entries.push(entry);
    }
    cursor.finish()?;
    let terminal = entries
        .last()
        .ok_or(RestartCatchupErrorV1::BundleMalformed(
            "empty nonzero bundle",
        ))?;
    if !target_match
        || terminal.height != last_certified_tail.height
        || terminal.block_id != last_certified_tail.block_id
        || terminal.signed_proposal_sha256() != last_certified_tail.signed_proposal_sha256
        || terminal.quorum_certificate_sha256() != last_certified_tail.quorum_certificate_sha256
        || terminal.entry_digest != expectation.manifest.terminal_entry_digest
    {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "terminal certified tail or target applied entry is absent",
        ));
    }
    let canonical = encode_restart_catchup_bundle_v1(
        context_digest,
        provider,
        source_applied_cut,
        last_certified_tail,
        target_applied_cut,
        target_applied_entry_digest,
        &entries,
    )?;
    if canonical != bytes {
        return Err(RestartCatchupErrorV1::NonCanonical);
    }
    Ok(VerifiedRestartCatchupBundleCandidateV1 {
        expected_context: expectation.context.clone(),
        manifest_facts: expectation.manifest,
        context_digest,
        provider,
        source_applied_cut,
        last_certified_tail,
        target_applied_cut,
        target_applied_entry_digest,
        entries,
        canonical_bytes: canonical,
        bundle_sha256: sha256_v1(bytes),
    })
}

fn decode_restart_catchup_bundle_entry_v1(
    bytes: &[u8],
    parent: &RestartCatchupEntryParentV1,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<RestartCatchupBundleEntryV1, RestartCatchupErrorV1> {
    let mut cursor = CatchupCursorV1::new(bytes);
    if cursor.take(BUNDLE_ENTRY_MAGIC_V1.len())? != BUNDLE_ENTRY_MAGIC_V1
        || u16::from_be_bytes(cursor.array()?) != BUNDLE_ENTRY_VERSION_V1
    {
        return Err(RestartCatchupErrorV1::BundleMalformed(
            "entry magic or version",
        ));
    }
    let height = u64::from_be_bytes(cursor.array()?);
    let block_id = cursor.array()?;
    let application_commit_id = cursor.array()?;
    let predecessor_digest = cursor.array()?;
    let signed_proposal_bytes = take_bounded_bundle_bytes_v1(
        &mut cursor,
        MAX_RESTART_CATCHUP_ENTRY_PROPOSAL_BYTES_V1,
        "signed Proposal",
    )?;
    let quorum_certificate_bytes =
        take_bounded_bundle_bytes_v1(&mut cursor, MAX_RESTART_CATCHUP_ENTRY_QC_BYTES_V1, "QC")?;
    let native_executed_artifact_bytes = take_bounded_bundle_bytes_v1(
        &mut cursor,
        MAX_RESTART_CATCHUP_ENTRY_NATIVE_ARTIFACT_BYTES_V1,
        "native execution artifact",
    )?;
    let digest_offset = cursor.offset;
    let entry_digest = cursor.array()?;
    cursor.finish()?;
    if height
        != parent
            .height
            .checked_add(1)
            .ok_or(RestartCatchupErrorV1::Capacity)?
        || predecessor_digest != parent.predecessor_digest
        || application_commit_id == [0; 32]
        || entry_digest != hash_canonical(BUNDLE_ENTRY_DIGEST_DOMAIN_V1, &bytes[..digest_offset])
    {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "entry sequence, predecessor, commit, or digest",
        ));
    }

    let unbound =
        UnboundProposalV0::decode(&signed_proposal_bytes, validator_set, consensus_parameters)?;
    let signed = unbound.bind_authenticated_parent(
        validator_set,
        consensus_parameters,
        parent.timestamp_ms,
    )?;
    let header = signed.block().header();
    let certificate = decode_quorum_certificate(&quorum_certificate_bytes, validator_set)?;
    let executed = decode_native_executed_block_artifact_v0(&native_executed_artifact_bytes)
        .map_err(|_| RestartCatchupErrorV1::BundleMalformed("native execution artifact"))?;
    if encode_native_executed_block_artifact_v0(&executed)
        .map_err(|_| RestartCatchupErrorV1::BundleMalformed("native execution artifact"))?
        != native_executed_artifact_bytes
    {
        return Err(RestartCatchupErrorV1::NonCanonical);
    }
    let request = executed.request();
    let expected = request.expected();
    let payload = decode_application_payload_v0_exact(
        signed.block().application_payload(),
        consensus_parameters,
    )
    .map_err(|_| RestartCatchupErrorV1::BundleMalformed("application payload"))?;
    if header.height().get() != height
        || *header.id().as_bytes() != block_id
        || *header.parent_id().as_bytes() != parent.block_id
        || certificate.height().get() != height
        || *certificate.block_id().as_bytes() != block_id
        || request.chain_id().as_str().as_bytes() != validator_set.chain_id().as_bytes()
        || request.genesis_hash().as_bytes() != validator_set.genesis_hash().as_bytes()
        || request.height().get() != height
        || request.block_id().as_bytes() != &block_id
        || request.parent().height().get() != parent.height
        || request.parent().block_id().as_bytes() != &parent.block_id
        || request.parent().state_root().as_bytes() != &parent.state_root
        || request.parent().commit_id().as_bytes() != &parent.application_commit_id
        || request.timestamp_ms() != header.timestamp_ms()
        || request.active_validator_set_id().as_bytes() != validator_set.id().as_bytes()
        || request.transactions() != payload.transactions()
        || expected.payload_root().as_bytes() != header.payload_root().as_bytes()
        || expected.post_state_root().as_bytes() != header.state_root().as_bytes()
        || expected.receipts_root().as_bytes() != header.receipts_root().as_bytes()
        || expected.evidence_root().as_bytes() != header.evidence_root().as_bytes()
    {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "Proposal/QC/native artifact/application-parent binding",
        ));
    }
    let entry = RestartCatchupBundleEntryV1 {
        height,
        block_id,
        application_commit_id,
        predecessor_digest,
        entry_digest,
        signed_proposal_bytes,
        quorum_certificate_bytes,
        native_executed_artifact_bytes,
    };
    if entry.encode_v1()? != bytes {
        return Err(RestartCatchupErrorV1::NonCanonical);
    }
    Ok(entry)
}

#[allow(clippy::too_many_arguments)]
fn encode_restart_catchup_bundle_v1(
    context_digest: [u8; 32],
    provider: ValidatorId,
    source_applied_cut: RestartCatchupAppliedCutV1,
    last_certified_tail: RestartCatchupCertifiedTailV1,
    target_applied_cut: RestartCatchupAppliedCutV1,
    target_applied_entry_digest: [u8; 32],
    entries: &[RestartCatchupBundleEntryV1],
) -> Result<Vec<u8>, RestartCatchupErrorV1> {
    if entries.is_empty() || entries.len() > MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1 as usize {
        return Err(RestartCatchupErrorV1::Capacity);
    }
    let mut output = Vec::new();
    output.extend_from_slice(BUNDLE_MAGIC_V1);
    output.extend_from_slice(&BUNDLE_VERSION_V1.to_be_bytes());
    output.extend_from_slice(&context_digest);
    output.extend_from_slice(&2u64.to_be_bytes());
    put_validator_id(&mut output, provider);
    output.extend_from_slice(&source_applied_cut.encode_v1());
    last_certified_tail.encode_v1(&mut output);
    output.extend_from_slice(&target_applied_cut.encode_v1());
    output.extend_from_slice(&target_applied_entry_digest);
    output.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| RestartCatchupErrorV1::Capacity)?
            .to_be_bytes(),
    );
    for entry in entries {
        let bytes = entry.encode_v1()?;
        put_bytes_u32(&mut output, &bytes)?;
        if output.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 {
            return Err(RestartCatchupErrorV1::TooLarge);
        }
    }
    Ok(output)
}

fn put_bounded_bundle_bytes_v1(
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
    label: &'static str,
) -> Result<(), RestartCatchupErrorV1> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RestartCatchupErrorV1::BundleMalformed(label));
    }
    put_bytes_u32(output, bytes)
}

fn take_bounded_bundle_bytes_v1(
    cursor: &mut CatchupCursorV1<'_>,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, RestartCatchupErrorV1> {
    let length = u32::from_be_bytes(cursor.array()?) as usize;
    if length == 0 || length > maximum {
        return Err(RestartCatchupErrorV1::BundleMalformed(label));
    }
    Ok(cursor.take(length)?.to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCatchupBundleDirectoryIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl RestartCatchupBundleDirectoryIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o777,
        }
    }

    fn matches_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o777
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCatchupBundleFileIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl RestartCatchupBundleFileIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o777,
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }

    fn matches_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.uid == metadata.uid()
            && self.mode == metadata.permissions().mode() & 0o777
            && self.links == metadata.nlink()
            && self.length == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanoseconds == metadata.mtime_nsec()
    }
}

struct PinnedRestartCatchupBundleFileV1 {
    root_path: PathBuf,
    path: PathBuf,
    root_file: File,
    bundle_file: File,
    root_identity: RestartCatchupBundleDirectoryIdentityV1,
    bundle_identity: RestartCatchupBundleFileIdentityV1,
}

impl PinnedRestartCatchupBundleFileV1 {
    fn revalidate_v1(&self) -> Result<(), RestartCatchupErrorV1> {
        ensure_no_restart_catchup_bundle_sidecars_v1(&self.root_path)?;
        if self.path != self.root_path.join(RESTART_CATCHUP_BUNDLE_FILE_V1)
            || self.path.file_name() != Some(OsStr::new(RESTART_CATCHUP_BUNDLE_FILE_V1))
        {
            return Err(RestartCatchupErrorV1::Durable(
                "bundle escaped fixed private path".to_owned(),
            ));
        }
        let held_root = self
            .root_file
            .metadata()
            .map_err(|error| durable_io_v1("inspect held bundle root", error))?;
        let held_bundle = self
            .bundle_file
            .metadata()
            .map_err(|error| durable_io_v1("inspect held bundle file", error))?;
        validate_restart_catchup_bundle_root_metadata_v1(&held_root)?;
        validate_restart_catchup_bundle_file_metadata_v1(&held_bundle, self.root_identity.uid)?;
        let path_metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| durable_io_v1("inspect bundle path", error))?;
        if path_metadata.file_type().is_symlink()
            || !self.root_identity.matches_v1(&held_root)
            || !self.bundle_identity.matches_v1(&held_bundle)
            || !self.bundle_identity.matches_v1(&path_metadata)
        {
            return Err(RestartCatchupErrorV1::Durable(
                "held bundle or private root identity changed".to_owned(),
            ));
        }
        let (fresh_root, fresh_identity) = open_restart_catchup_bundle_root_v1(&self.root_path)?;
        if fresh_identity != self.root_identity {
            return Err(RestartCatchupErrorV1::Durable(
                "bundle private-root path was replaced".to_owned(),
            ));
        }
        drop(fresh_root);
        Ok(())
    }
}

/// Process-affined, non-Clone owner of one immutable provider bundle.  It has
/// no raw-parts constructor, byte escape, Node importer, journal transition,
/// Ready/Start method, or activation method.
#[must_use = "the pinned catch-up provider bundle must remain owned through local import"]
pub struct StoredRestartCatchupProviderBundleV1 {
    pinned: PinnedRestartCatchupBundleFileV1,
    candidate: VerifiedRestartCatchupBundleCandidateV1,
    expectation: RestartCatchupBundleExpectationV1,
    owner_process_id: u32,
}

impl fmt::Debug for StoredRestartCatchupProviderBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredRestartCatchupProviderBundleV1")
            .field("path", &self.pinned.path)
            .field("provider", &self.candidate.provider)
            .field("bundle_sha256", &self.candidate.bundle_sha256)
            .field("owner_process_id", &self.owner_process_id)
            .finish_non_exhaustive()
    }
}

impl StoredRestartCatchupProviderBundleV1 {
    pub fn path_v1(&self) -> &Path {
        &self.pinned.path
    }

    pub const fn provider_v1(&self) -> ValidatorId {
        self.candidate.provider
    }

    pub const fn bundle_sha256_v1(&self) -> [u8; 32] {
        self.candidate.bundle_sha256
    }

    pub const fn last_certified_tail_v1(&self) -> RestartCatchupCertifiedTailV1 {
        self.candidate.last_certified_tail
    }

    pub const fn target_applied_cut_v1(&self) -> RestartCatchupAppliedCutV1 {
        self.candidate.target_applied_cut
    }

    pub fn revalidate_fresh_v1(
        &self,
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
    ) -> Result<(), RestartCatchupErrorV1> {
        if std::process::id() != self.owner_process_id {
            return Err(RestartCatchupErrorV1::WrongProcess);
        }
        self.pinned.revalidate_v1()?;
        let (fresh_pin, bytes, sha256) =
            open_and_read_restart_catchup_bundle_v1(&self.pinned.root_path)?;
        if fresh_pin.root_identity != self.pinned.root_identity
            || fresh_pin.bundle_identity != self.pinned.bundle_identity
            || sha256 != self.candidate.bundle_sha256
        {
            return Err(RestartCatchupErrorV1::Durable(
                "fresh bundle identity or content address changed".to_owned(),
            ));
        }
        let fresh = decode_restart_catchup_bundle_candidate_v1(
            &bytes,
            &self.expectation,
            validator_set,
            consensus_parameters,
        )?;
        if fresh.canonical_bytes != self.candidate.canonical_bytes
            || fresh.bundle_sha256 != self.candidate.bundle_sha256
        {
            return Err(RestartCatchupErrorV1::Durable(
                "fresh strict bundle differs from retained candidate".to_owned(),
            ));
        }
        fresh_pin.revalidate_v1()?;
        self.pinned.revalidate_v1()
    }
}

/// Create-new persists only a fully verified candidate and immediately joins
/// it back to the signed-manifest SHA/context through a fresh strict read.
pub(crate) fn persist_restart_catchup_provider_bundle_v1(
    private_root: &Path,
    candidate: VerifiedRestartCatchupBundleCandidateV1,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<StoredRestartCatchupProviderBundleV1, RestartCatchupErrorV1> {
    if candidate.bundle_sha256 != sha256_v1(&candidate.canonical_bytes)
        || candidate.bundle_sha256 != candidate.manifest_facts.bundle_sha256
    {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "verified candidate differs from signed manifest content address",
        ));
    }
    let expectation = RestartCatchupBundleExpectationV1 {
        context: candidate.expected_context.clone(),
        provider: candidate.provider,
        source_applied_cut: candidate.source_applied_cut,
        manifest: candidate.manifest_facts,
    };
    expectation.validate_relations_v1()?;
    publish_restart_catchup_bundle_create_new_v1(private_root, &candidate.canonical_bytes)?;
    let stored = load_restart_catchup_provider_bundle_v1(
        private_root,
        expectation,
        validator_set,
        consensus_parameters,
    )?;
    if stored.candidate.canonical_bytes != candidate.canonical_bytes {
        return Err(RestartCatchupErrorV1::Durable(
            "freshly stored bundle differs from verified input".to_owned(),
        ));
    }
    Ok(stored)
}

/// Reopens only the fixed file and requires an independently reacquired
/// authenticated manifest expectation, including exact SHA and recovery
/// context.  Adjacent files and the provider's scalar manifest facts alone
/// are not owner authority.
pub(crate) fn load_restart_catchup_provider_bundle_v1(
    private_root: &Path,
    expectation: RestartCatchupBundleExpectationV1,
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<StoredRestartCatchupProviderBundleV1, RestartCatchupErrorV1> {
    expectation.validate_relations_v1()?;
    let (pinned, bytes, sha256) = open_and_read_restart_catchup_bundle_v1(private_root)?;
    if sha256 != expectation.manifest.bundle_sha256 {
        return Err(RestartCatchupErrorV1::BundleMismatch(
            "stored bundle differs from authenticated expected SHA-256",
        ));
    }
    let candidate = decode_restart_catchup_bundle_candidate_v1(
        &bytes,
        &expectation,
        validator_set,
        consensus_parameters,
    )?;
    pinned.revalidate_v1()?;
    Ok(StoredRestartCatchupProviderBundleV1 {
        pinned,
        candidate,
        expectation,
        owner_process_id: std::process::id(),
    })
}

fn restart_catchup_bundle_writing_file_name_v1(process_id: u32, attempt: u64) -> String {
    format!("{RESTART_CATCHUP_BUNDLE_WRITING_PREFIX_V1}{process_id:08x}.{attempt:016x}")
}

fn next_restart_catchup_bundle_writing_file_name_v1() -> String {
    restart_catchup_bundle_writing_file_name_v1(
        std::process::id(),
        RESTART_CATCHUP_BUNDLE_WRITING_ATTEMPT_V1.fetch_add(1, Ordering::Relaxed),
    )
}

fn is_restart_catchup_lower_hex_digit_v1(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn restart_catchup_bundle_writing_name_v1(name: &OsStr) -> Option<bool> {
    let name = name.as_bytes();
    let prefix = RESTART_CATCHUP_BUNDLE_WRITING_PREFIX_V1.as_bytes();
    if !name.starts_with(prefix) {
        return None;
    }
    let suffix = &name[prefix.len()..];
    Some(
        suffix.len() == 25
            && suffix[8] == b'.'
            && suffix[..8]
                .iter()
                .copied()
                .all(is_restart_catchup_lower_hex_digit_v1)
            && suffix[..8].iter().any(|byte| *byte != b'0')
            && suffix[9..]
                .iter()
                .copied()
                .all(is_restart_catchup_lower_hex_digit_v1),
    )
}

fn restart_catchup_bundle_path_exists_no_follow_v1(
    path: &Path,
    label: &str,
) -> Result<bool, RestartCatchupErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(durable_io_v1(label, error)),
    }
}

fn revalidate_restart_catchup_bundle_publication_root_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: RestartCatchupBundleDirectoryIdentityV1,
) -> Result<(), RestartCatchupErrorV1> {
    let held = root_file
        .metadata()
        .map_err(|error| durable_io_v1("reinspect held bundle publication root", error))?;
    let path = fs::symlink_metadata(private_root)
        .map_err(|error| durable_io_v1("reinspect bundle publication root path", error))?;
    if path.file_type().is_symlink()
        || !root_identity.matches_v1(&held)
        || !root_identity.matches_v1(&path)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root changed during publication".to_owned(),
        ));
    }
    Ok(())
}

fn validate_restart_catchup_bundle_publication_candidate_v1(
    path: &Path,
    expected_uid: u32,
    expected_bytes: &[u8],
    expected_links: u64,
) -> Result<RestartCatchupBundleFileIdentityV1, RestartCatchupErrorV1> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| durable_io_v1("inspect bundle publication candidate", error))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.permissions().mode() & 0o777 != 0o600
        || before.uid() != expected_uid
        || before.nlink() != expected_links
        || before.len() != u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
        || before.len() == 0
        || before.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 as u64
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle publication candidate has foreign metadata".to_owned(),
        ));
    }
    let identity = RestartCatchupBundleFileIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| durable_io_v1("open bundle publication candidate", error))?;
    let opened = file
        .metadata()
        .map_err(|error| durable_io_v1("inspect opened bundle publication candidate", error))?;
    if !identity.matches_v1(&opened) {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle publication candidate changed while opening".to_owned(),
        ));
    }
    let mut observed = Vec::with_capacity(expected_bytes.len());
    Read::by_ref(&mut file)
        .take(MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 as u64 + 1)
        .read_to_end(&mut observed)
        .map_err(|error| durable_io_v1("read bundle publication candidate", error))?;
    let after = file
        .metadata()
        .map_err(|error| durable_io_v1("reinspect bundle publication candidate", error))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| durable_io_v1("reinspect bundle candidate path", error))?;
    if observed != expected_bytes
        || !identity.matches_v1(&after)
        || !identity.matches_v1(&path_after)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle publication candidate is partial, mutated, or foreign".to_owned(),
        ));
    }
    Ok(identity)
}

fn cleanup_one_interrupted_restart_catchup_bundle_writing_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: RestartCatchupBundleDirectoryIdentityV1,
    expected_bytes: &[u8],
    writing: &Path,
    next: &Path,
    target: &Path,
) -> Result<(), RestartCatchupErrorV1> {
    let before = fs::symlink_metadata(writing)
        .map_err(|error| durable_io_v1("inspect interrupted bundle writing candidate", error))?;
    let mode = before.permissions().mode() & 0o777;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != root_identity.uid
        || mode & !0o600 != 0
        || !matches!(before.nlink(), 1 | 2)
        || before.len() > u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "interrupted bundle writing candidate has foreign metadata; preserved".to_owned(),
        ));
    }
    let identity = RestartCatchupBundleFileIdentityV1::from_metadata_v1(&before);
    let observed = if before.len() == 0 {
        Vec::new()
    } else {
        if mode != 0o600 {
            return Err(RestartCatchupErrorV1::Durable(
                "nonempty interrupted bundle writing candidate has incomplete permissions; preserved"
                    .to_owned(),
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(writing)
            .map_err(|error| durable_io_v1("open interrupted bundle writing candidate", error))?;
        let opened = file.metadata().map_err(|error| {
            durable_io_v1("inspect opened interrupted bundle writing candidate", error)
        })?;
        if !identity.matches_v1(&opened) {
            return Err(RestartCatchupErrorV1::Durable(
                "interrupted bundle writing candidate changed while opening; preserved".to_owned(),
            ));
        }
        let mut observed = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
        Read::by_ref(&mut file)
            .take(u64::try_from(expected_bytes.len()).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut observed)
            .map_err(|error| durable_io_v1("read interrupted bundle writing candidate", error))?;
        let after = file.metadata().map_err(|error| {
            durable_io_v1(
                "reinspect opened interrupted bundle writing candidate",
                error,
            )
        })?;
        if !identity.matches_v1(&after) {
            return Err(RestartCatchupErrorV1::Durable(
                "interrupted bundle writing candidate changed while reading; preserved".to_owned(),
            ));
        }
        observed
    };
    if !expected_bytes.starts_with(&observed) {
        return Err(RestartCatchupErrorV1::Durable(
            "interrupted bundle writing candidate is not an exact canonical prefix; preserved"
                .to_owned(),
        ));
    }
    if restart_catchup_bundle_path_exists_no_follow_v1(
        target,
        "inspect bundle target during writing recovery",
    )? {
        return Err(RestartCatchupErrorV1::Durable(
            "interrupted bundle writing candidate coexists with final target; preserved".to_owned(),
        ));
    }
    let next_exists = restart_catchup_bundle_path_exists_no_follow_v1(
        next,
        "inspect fixed bundle candidate during writing recovery",
    )?;
    match identity.links {
        1 if next_exists => {
            return Err(RestartCatchupErrorV1::Durable(
                "unlinked bundle writing candidate coexists with foreign fixed candidate; preserved"
                    .to_owned(),
            ));
        }
        1 => {}
        2 if !next_exists || observed != expected_bytes => {
            return Err(RestartCatchupErrorV1::Durable(
                "linked bundle writing candidate lacks its exact complete fixed link; preserved"
                    .to_owned(),
            ));
        }
        2 => {
            let next_identity = validate_restart_catchup_bundle_publication_candidate_v1(
                next,
                root_identity.uid,
                expected_bytes,
                2,
            )?;
            if next_identity != identity {
                return Err(RestartCatchupErrorV1::Durable(
                    "bundle writing candidate and fixed candidate are different inodes; preserved"
                        .to_owned(),
                ));
            }
        }
        _ => unreachable!("writing link count was checked above"),
    }
    let path_after = fs::symlink_metadata(writing).map_err(|error| {
        durable_io_v1("reinspect interrupted bundle writing candidate path", error)
    })?;
    if !identity.matches_v1(&path_after) {
        return Err(RestartCatchupErrorV1::Durable(
            "interrupted bundle writing candidate path was replaced; preserved".to_owned(),
        ));
    }
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .map_err(|error| durable_io_v1("remove authenticated interrupted bundle writing", error))?;
    root_file
        .sync_all()
        .map_err(|error| durable_io_v1("fsync cleaned bundle writing candidate", error))?;
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, root_file, root_identity)?;
    if identity.links == 2 {
        validate_restart_catchup_bundle_publication_candidate_v1(
            next,
            root_identity.uid,
            expected_bytes,
            1,
        )?;
    }
    Ok(())
}

fn cleanup_interrupted_restart_catchup_bundle_writing_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: RestartCatchupBundleDirectoryIdentityV1,
    expected_bytes: &[u8],
    next: &Path,
    target: &Path,
) -> Result<(), RestartCatchupErrorV1> {
    let mut names = fs::read_dir(private_root)
        .map_err(|error| durable_io_v1("scan bundle root for interrupted writing", error))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| durable_io_v1("read bundle writing candidate names", error))?;
    names.sort();
    for name in names {
        let Some(canonical) = restart_catchup_bundle_writing_name_v1(&name) else {
            continue;
        };
        let writing = private_root.join(&name);
        if !canonical {
            return Err(RestartCatchupErrorV1::Durable(format!(
                "malformed bundle writing candidate is preserved: {}",
                writing.display()
            )));
        }
        cleanup_one_interrupted_restart_catchup_bundle_writing_v1(
            private_root,
            root_file,
            root_identity,
            expected_bytes,
            &writing,
            next,
            target,
        )?;
    }
    Ok(())
}

fn create_complete_restart_catchup_bundle_writing_v1(
    private_root: &Path,
    expected_uid: u32,
    bytes: &[u8],
) -> Result<PathBuf, RestartCatchupErrorV1> {
    let name = next_restart_catchup_bundle_writing_file_name_v1();
    let writing = private_root.join(&name);
    if writing.parent() != Some(private_root)
        || writing.file_name() != Some(OsStr::new(&name))
        || restart_catchup_bundle_writing_name_v1(OsStr::new(&name)) != Some(true)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle writing candidate escaped unique private path".to_owned(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&writing)
        .map_err(|error| durable_io_v1("create-new unique bundle writing candidate", error))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| durable_io_v1("chmod unique bundle writing candidate", error))?;
    file.write_all(bytes)
        .map_err(|error| durable_io_v1("write unique bundle writing candidate", error))?;
    file.sync_all()
        .map_err(|error| durable_io_v1("fsync unique bundle writing candidate", error))?;
    drop(file);
    validate_restart_catchup_bundle_publication_candidate_v1(&writing, expected_uid, bytes, 1)?;
    Ok(writing)
}

fn link_complete_restart_catchup_bundle_writing_to_next_v1(
    private_root: &Path,
    root_file: &File,
    root_identity: RestartCatchupBundleDirectoryIdentityV1,
    bytes: &[u8],
    writing: &Path,
    next: &Path,
) -> Result<(), RestartCatchupErrorV1> {
    validate_restart_catchup_bundle_publication_candidate_v1(writing, root_identity.uid, bytes, 1)?;
    match fs::hard_link(writing, next) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(durable_io_v1(
                "link complete bundle writing candidate no-replace",
                error,
            ));
        }
    }
    let writing_linked = validate_restart_catchup_bundle_publication_candidate_v1(
        writing,
        root_identity.uid,
        bytes,
        2,
    )?;
    let next_linked = validate_restart_catchup_bundle_publication_candidate_v1(
        next,
        root_identity.uid,
        bytes,
        2,
    )?;
    if writing_linked != next_linked {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle writing candidate did not link to exact fixed candidate inode".to_owned(),
        ));
    }
    root_file
        .sync_all()
        .map_err(|error| durable_io_v1("fsync linked bundle writing candidate", error))?;
    let writing_before_unlink = validate_restart_catchup_bundle_publication_candidate_v1(
        writing,
        root_identity.uid,
        bytes,
        2,
    )?;
    let next_before_unlink = validate_restart_catchup_bundle_publication_candidate_v1(
        next,
        root_identity.uid,
        bytes,
        2,
    )?;
    if writing_before_unlink != next_before_unlink {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle writing and fixed candidates diverged before unlink".to_owned(),
        ));
    }
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, root_file, root_identity)?;
    fs::remove_file(writing)
        .map_err(|error| durable_io_v1("remove linked unique bundle writing candidate", error))?;
    root_file
        .sync_all()
        .map_err(|error| durable_io_v1("fsync fixed bundle candidate publication", error))?;
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, root_file, root_identity)?;
    validate_restart_catchup_bundle_publication_candidate_v1(next, root_identity.uid, bytes, 1)?;
    Ok(())
}

fn publish_restart_catchup_bundle_create_new_v1(
    private_root: &Path,
    bytes: &[u8],
) -> Result<(), RestartCatchupErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 {
        return Err(RestartCatchupErrorV1::TooLarge);
    }
    let (root_file, root_identity) = open_restart_catchup_bundle_root_v1(private_root)?;
    root_file
        .try_lock()
        .map_err(|error| durable_io_v1("lock bundle publication root lifetime", error.into()))?;
    let target = private_root.join(RESTART_CATCHUP_BUNDLE_FILE_V1);
    let next = private_root.join(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1);
    if target.parent() != Some(private_root)
        || target.file_name() != Some(OsStr::new(RESTART_CATCHUP_BUNDLE_FILE_V1))
        || next.parent() != Some(private_root)
        || next.file_name() != Some(OsStr::new(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1))
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle publication path escaped private root".to_owned(),
        ));
    }
    ensure_no_restart_catchup_bundle_sidecars_except_v1(
        private_root,
        Some(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1),
        true,
    )?;
    cleanup_interrupted_restart_catchup_bundle_writing_v1(
        private_root,
        &root_file,
        root_identity,
        bytes,
        &next,
        &target,
    )?;
    ensure_no_restart_catchup_bundle_sidecars_except_v1(
        private_root,
        Some(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1),
        false,
    )?;

    let target_exists = restart_catchup_bundle_path_exists_no_follow_v1(
        &target,
        "inspect bundle publication target",
    )?;
    let next_exists = restart_catchup_bundle_path_exists_no_follow_v1(
        &next,
        "inspect fixed bundle publication candidate",
    )?;
    if target_exists && !next_exists {
        drop(root_file);
        let (pinned, existing, existing_sha256) =
            open_and_read_restart_catchup_bundle_v1(private_root)?;
        if existing != bytes || existing_sha256 != sha256_v1(bytes) {
            return Err(RestartCatchupErrorV1::Durable(
                "immutable bundle target exists with different or partial bytes".to_owned(),
            ));
        }
        pinned.revalidate_v1()?;
        return Ok(());
    }

    if !next_exists {
        let writing = create_complete_restart_catchup_bundle_writing_v1(
            private_root,
            root_identity.uid,
            bytes,
        )?;
        link_complete_restart_catchup_bundle_writing_to_next_v1(
            private_root,
            &root_file,
            root_identity,
            bytes,
            &writing,
            &next,
        )?;
    }

    let next_identity = validate_restart_catchup_bundle_publication_candidate_v1(
        &next,
        root_identity.uid,
        bytes,
        if target_exists { 2 } else { 1 },
    )?;
    if target_exists {
        let target_metadata = fs::symlink_metadata(&target)
            .map_err(|error| durable_io_v1("inspect bundle response-loss target", error))?;
        if target_metadata.file_type().is_symlink() || !next_identity.matches_v1(&target_metadata) {
            return Err(RestartCatchupErrorV1::Durable(
                "bundle target and fixed candidate are not one response-loss inode".to_owned(),
            ));
        }
    } else {
        match fs::hard_link(&next, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(durable_io_v1(
                    "publish bundle target without replacement",
                    error,
                ));
            }
        }
        let next_linked = validate_restart_catchup_bundle_publication_candidate_v1(
            &next,
            root_identity.uid,
            bytes,
            2,
        )?;
        let target_metadata = fs::symlink_metadata(&target)
            .map_err(|error| durable_io_v1("inspect published bundle target", error))?;
        if target_metadata.file_type().is_symlink() || !next_linked.matches_v1(&target_metadata) {
            return Err(RestartCatchupErrorV1::Durable(
                "bundle no-replace publication did not create one linked target".to_owned(),
            ));
        }
    }

    root_file
        .sync_all()
        .map_err(|error| durable_io_v1("fsync linked bundle target publication", error))?;
    let next_before_unlink = validate_restart_catchup_bundle_publication_candidate_v1(
        &next,
        root_identity.uid,
        bytes,
        2,
    )?;
    let target_before_unlink = validate_restart_catchup_bundle_publication_candidate_v1(
        &target,
        root_identity.uid,
        bytes,
        2,
    )?;
    if next_before_unlink != target_before_unlink {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle fixed candidate and target diverged before unlink".to_owned(),
        ));
    }
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, &root_file, root_identity)?;
    fs::remove_file(&next)
        .map_err(|error| durable_io_v1("remove committed fixed bundle candidate", error))?;
    root_file
        .sync_all()
        .map_err(|error| durable_io_v1("fsync final bundle publication", error))?;
    revalidate_restart_catchup_bundle_publication_root_v1(private_root, &root_file, root_identity)?;
    validate_restart_catchup_bundle_publication_candidate_v1(&target, root_identity.uid, bytes, 1)?;
    drop(root_file);
    ensure_no_restart_catchup_bundle_sidecars_v1(private_root)?;
    let (pinned, observed, observed_sha256) =
        open_and_read_restart_catchup_bundle_v1(private_root)?;
    if observed != bytes || observed_sha256 != sha256_v1(bytes) {
        return Err(RestartCatchupErrorV1::Durable(
            "published bundle differs from exact canonical input".to_owned(),
        ));
    }
    pinned.revalidate_v1()
}

fn open_and_read_restart_catchup_bundle_v1(
    private_root: &Path,
) -> Result<(PinnedRestartCatchupBundleFileV1, Vec<u8>, [u8; 32]), RestartCatchupErrorV1> {
    let (root_file, root_identity) = open_restart_catchup_bundle_root_v1(private_root)?;
    ensure_no_restart_catchup_bundle_sidecars_v1(private_root)?;
    let path = private_root.join(RESTART_CATCHUP_BUNDLE_FILE_V1);
    let before =
        fs::symlink_metadata(&path).map_err(|error| durable_io_v1("inspect bundle path", error))?;
    if before.file_type().is_symlink() {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle path is symlink".to_owned(),
        ));
    }
    validate_restart_catchup_bundle_file_metadata_v1(&before, root_identity.uid)?;
    let identity = RestartCatchupBundleFileIdentityV1::from_metadata_v1(&before);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| durable_io_v1("open bundle", error))?;
    let opened = file
        .metadata()
        .map_err(|error| durable_io_v1("inspect opened bundle", error))?;
    validate_restart_catchup_bundle_file_metadata_v1(&opened, root_identity.uid)?;
    if !identity.matches_v1(&opened) {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle identity changed while opening".to_owned(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| durable_io_v1("seek bundle", error))?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| durable_io_v1("read bundle", error))?;
    let after_handle = file
        .metadata()
        .map_err(|error| durable_io_v1("reinspect bundle handle", error))?;
    let after_path = fs::symlink_metadata(&path)
        .map_err(|error| durable_io_v1("reinspect bundle path", error))?;
    if bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
        || bytes.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1
        || after_path.file_type().is_symlink()
        || !identity.matches_v1(&after_handle)
        || !identity.matches_v1(&after_path)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle changed during bounded read/hash".to_owned(),
        ));
    }
    let pinned = PinnedRestartCatchupBundleFileV1 {
        root_path: private_root.to_path_buf(),
        path,
        root_file,
        bundle_file: file,
        root_identity,
        bundle_identity: identity,
    };
    Ok((pinned, bytes.clone(), sha256_v1(&bytes)))
}

fn open_restart_catchup_bundle_root_v1(
    root: &Path,
) -> Result<(File, RestartCatchupBundleDirectoryIdentityV1), RestartCatchupErrorV1> {
    if !root.is_absolute() {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root is not absolute".to_owned(),
        ));
    }
    let before = fs::symlink_metadata(root)
        .map_err(|error| durable_io_v1("inspect bundle private root", error))?;
    if before.file_type().is_symlink() {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root is symlink".to_owned(),
        ));
    }
    validate_restart_catchup_bundle_root_metadata_v1(&before)?;
    let canonical = fs::canonicalize(root)
        .map_err(|error| durable_io_v1("canonicalize bundle private root", error))?;
    if canonical != root {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root has non-canonical ancestor".to_owned(),
        ));
    }
    let identity = RestartCatchupBundleDirectoryIdentityV1::from_metadata_v1(&before);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .map_err(|error| durable_io_v1("open bundle private root", error))?;
    let opened = file
        .metadata()
        .map_err(|error| durable_io_v1("inspect opened bundle root", error))?;
    let after = fs::symlink_metadata(root)
        .map_err(|error| durable_io_v1("reinspect bundle root", error))?;
    if after.file_type().is_symlink()
        || !identity.matches_v1(&opened)
        || !identity.matches_v1(&after)
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root identity changed while opening".to_owned(),
        ));
    }
    Ok((file, identity))
}

fn validate_restart_catchup_bundle_root_metadata_v1(
    metadata: &fs::Metadata,
) -> Result<(), RestartCatchupErrorV1> {
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle private root is not exact 0700 directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_restart_catchup_bundle_file_metadata_v1(
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<(), RestartCatchupErrorV1> {
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.len() == 0
        || metadata.len() > MAX_RESTART_CATCHUP_BUNDLE_BYTES_V1 as u64
    {
        return Err(RestartCatchupErrorV1::Durable(
            "bundle is not one exact private regular file".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_no_restart_catchup_bundle_sidecars_v1(root: &Path) -> Result<(), RestartCatchupErrorV1> {
    ensure_no_restart_catchup_bundle_sidecars_except_v1(root, None, false)
}

fn ensure_no_restart_catchup_bundle_sidecars_except_v1(
    root: &Path,
    allowed_fixed: Option<&str>,
    allow_writing: bool,
) -> Result<(), RestartCatchupErrorV1> {
    for name in RESTART_CATCHUP_BUNDLE_SIDECARS_V1 {
        if allowed_fixed == Some(name) {
            continue;
        }
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(RestartCatchupErrorV1::Durable(format!(
                    "bundle publication sidecar exists: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(durable_io_v1("inspect bundle sidecar", error)),
        }
    }
    if !allow_writing {
        for entry in fs::read_dir(root)
            .map_err(|error| durable_io_v1("scan bundle writing sidecars", error))?
        {
            let entry = entry.map_err(|error| durable_io_v1("read bundle sidecar entry", error))?;
            if restart_catchup_bundle_writing_name_v1(&entry.file_name()).is_some() {
                return Err(RestartCatchupErrorV1::Durable(format!(
                    "bundle publication writing sidecar exists: {}",
                    entry.path().display()
                )));
            }
        }
    }
    Ok(())
}

fn durable_io_v1(label: &str, error: std::io::Error) -> RestartCatchupErrorV1 {
    RestartCatchupErrorV1::Durable(format!("{label}: {error}"))
}

pub fn chunk_content_digest_v1(bytes: &[u8]) -> [u8; 32] {
    hash_canonical(CHUNK_CONTENT_DIGEST_DOMAIN_V1, bytes)
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hash_canonical(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn put_bytes_u16(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("bounded catch-up field fits u16")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RestartCatchupErrorV1> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| RestartCatchupErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn put_validator_id(output: &mut Vec<u8>, value: ValidatorId) {
    put_bytes_u16(output, value.as_bytes());
}

struct CatchupCursorV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CatchupCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RestartCatchupErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RestartCatchupErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RestartCatchupErrorV1::Malformed("truncated payload"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RestartCatchupErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| RestartCatchupErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, RestartCatchupErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RestartCatchupErrorV1::Malformed("byte"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId, RestartCatchupErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| RestartCatchupErrorV1::Malformed("validator ID"))
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn finish(self) -> Result<(), RestartCatchupErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RestartCatchupErrorV1::Malformed("trailing payload"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartCatchupErrorV1 {
    Malformed(&'static str),
    TooLarge,
    NonCanonical,
    InvalidValidatorSet,
    UnsupportedProfile,
    WrongValidatorSet,
    WrongContext,
    UnknownTarget,
    UnknownProvider,
    UnknownOrigin,
    UnknownOuterSender,
    AuthenticatedTransportMismatch,
    OuterOriginMismatch,
    InvalidRelayEnvelope,
    RelayOriginMismatch,
    ProviderIsTarget,
    RequestOriginNotTarget,
    ProviderOriginMismatch,
    OriginKeyMismatch,
    InvalidSignature,
    UnsupportedFrameKind,
    Capacity,
    Equivocation(&'static str),
    SemanticConflict(&'static str),
    OutOfOrder(&'static str),
    BundleMalformed(&'static str),
    BundleMismatch(&'static str),
    Durable(String),
    WrongProcess,
    ConsensusWire(String),
    Poisoned,
}

impl fmt::Display for RestartCatchupErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed restart catch-up {field}"),
            Self::TooLarge => formatter.write_str("restart catch-up wire crosses its bound"),
            Self::NonCanonical => formatter.write_str("restart catch-up wire is non-canonical"),
            Self::InvalidValidatorSet => formatter.write_str("invalid restart catch-up set"),
            Self::UnsupportedProfile => {
                formatter.write_str("restart catch-up supports only the 7-validator profile")
            }
            Self::WrongValidatorSet => {
                formatter.write_str("restart catch-up belongs to another validator set")
            }
            Self::WrongContext => {
                formatter.write_str("restart catch-up belongs to another recovery context")
            }
            Self::UnknownTarget => formatter.write_str("restart catch-up target is unknown"),
            Self::UnknownProvider => formatter.write_str("restart catch-up provider is unknown"),
            Self::UnknownOrigin => formatter.write_str("restart catch-up origin is unknown"),
            Self::UnknownOuterSender => {
                formatter.write_str("restart catch-up outer sender is unknown")
            }
            Self::AuthenticatedTransportMismatch => formatter
                .write_str("restart catch-up frame differs from its authenticated mesh owner"),
            Self::OuterOriginMismatch => {
                formatter.write_str("restart catch-up direct sender differs from signed origin")
            }
            Self::InvalidRelayEnvelope => {
                formatter.write_str("restart catch-up relay envelope is invalid")
            }
            Self::RelayOriginMismatch => formatter
                .write_str("restart catch-up relay origin differs from signed inner origin"),
            Self::ProviderIsTarget => {
                formatter.write_str("restart catch-up target cannot provide its own suffix")
            }
            Self::RequestOriginNotTarget => {
                formatter.write_str("restart catch-up Request origin is not the target")
            }
            Self::ProviderOriginMismatch => {
                formatter.write_str("restart catch-up provider differs from signed origin")
            }
            Self::OriginKeyMismatch => {
                formatter.write_str("restart catch-up signing key differs from origin")
            }
            Self::InvalidSignature => {
                formatter.write_str("restart catch-up origin signature is invalid")
            }
            Self::UnsupportedFrameKind => {
                formatter.write_str("frame kind is outside restart catch-up ingress")
            }
            Self::Capacity => formatter.write_str("restart catch-up capacity exhausted"),
            Self::Equivocation(slot) => write!(formatter, "restart catch-up {slot} equivocation"),
            Self::SemanticConflict(field) => {
                write!(formatter, "restart catch-up semantic conflict: {field}")
            }
            Self::OutOfOrder(field) => write!(formatter, "restart catch-up out of order: {field}"),
            Self::BundleMalformed(field) => {
                write!(formatter, "malformed restart catch-up bundle: {field}")
            }
            Self::BundleMismatch(field) => {
                write!(formatter, "restart catch-up bundle mismatch: {field}")
            }
            Self::Durable(reason) => {
                write!(
                    formatter,
                    "restart catch-up durable bundle failure: {reason}"
                )
            }
            Self::WrongProcess => formatter
                .write_str("restart catch-up durable bundle owner crossed its process affinity"),
            Self::ConsensusWire(reason) => {
                write!(
                    formatter,
                    "restart catch-up canonical consensus entry: {reason}"
                )
            }
            Self::Poisoned => formatter.write_str("restart catch-up admission is poisoned"),
        }
    }
}

impl std::error::Error for RestartCatchupErrorV1 {}

impl From<crate::wire::ConsensusWireError> for RestartCatchupErrorV1 {
    fn from(error: crate::wire::ConsensusWireError) -> Self {
        Self::ConsensusWire(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;
    use crate::relay::ConsensusRelayEnvelopeV0;

    fn fixture(validator_count: usize) -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..validator_count)
            .map(|index| {
                let seed = u8::try_from(index + 1).unwrap();
                SigningKey::from_bytes(&[seed; 32])
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x31 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-restart-catchup-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn fixture_with_validator_id_length(length: usize) -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..RESTART_CATCHUP_VALIDATOR_COUNT_V1)
            .map(|index| {
                let seed = u8::try_from(index + 1).unwrap();
                SigningKey::from_bytes(&[seed; 32])
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let byte = 0x31 + u8::try_from(index).unwrap();
                Validator::new(
                    ValidatorId::from_bytes(&vec![byte; length]).unwrap(),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-restart-catchup-id-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn context(set: &ValidatorSet) -> RestartCatchupContextV1 {
        RestartCatchupContextV1::new_expected_v1(
            "poco-g3-7-20260818T060420Z-a1b2c3d4".to_owned(),
            [0x41; 32],
            [0x42; 32],
            *set.id().as_bytes(),
            [0x43; 32],
            [0x44; 32],
            set.validators()[0].id(),
            2,
            [0x45; 32],
            3,
            [0x46; 32],
            set,
        )
        .unwrap()
    }

    fn request_body(
        context: &RestartCatchupContextV1,
        maximum_entries: u32,
        maximum_chunks: u32,
        maximum_bytes: u64,
    ) -> RestartCatchupBodyV1 {
        RestartCatchupBodyV1::Request(RestartCatchupRequestBodyV1 {
            facts: RestartCatchupRequestFactsV1 {
                restart_cut_height: context.restart_cut_height,
                restart_cut_block_id: context.restart_cut_block_id,
                maximum_entries,
                maximum_chunks,
                maximum_bytes,
            },
        })
    }

    fn manifest_body(
        context: &RestartCatchupContextV1,
        entry_count: u32,
        chunk_count: u32,
        total_bytes: u64,
    ) -> RestartCatchupBodyV1 {
        RestartCatchupBodyV1::Manifest(RestartCatchupManifestBodyV1 {
            restart_cut_height: context.restart_cut_height,
            restart_cut_block_id: context.restart_cut_block_id,
            first_height: context.restart_cut_height + 1,
            entry_count,
            chunk_count,
            total_bytes,
            last_certified_height: context.restart_cut_height + u64::from(entry_count),
            last_certified_block_id: [0x51; 32],
            last_certified_proposal_sha256: [0x52; 32],
            last_certified_qc_sha256: [0x53; 32],
            target_applied_height: context.restart_cut_height + 1,
            target_applied_block_id: [0x54; 32],
            target_applied_state_root: [0x55; 32],
            target_applied_application_commit_id: [0x56; 32],
            target_applied_chain_root: [0x5c; 32],
            target_applied_timestamp_ms: 100,
            target_applied_checkpoint_sha256: [0x57; 32],
            target_applied_artifact_commitment: [0x58; 32],
            target_applied_entry_digest: [0x59; 32],
            terminal_entry_digest: [0x5a; 32],
            bundle_sha256: [0x5b; 32],
        })
    }

    fn chunk_body(
        manifest_digest: [u8; 32],
        chunk_index: u32,
        chunk_count: u32,
        predecessor_digest: [u8; 32],
        bytes: &[u8],
    ) -> RestartCatchupBodyV1 {
        RestartCatchupBodyV1::Chunk(RestartCatchupChunkBodyV1 {
            manifest_digest,
            chunk_index,
            chunk_count,
            predecessor_digest,
            content_digest: chunk_content_digest_v1(bytes),
            bytes: bytes.to_vec(),
        })
    }

    fn signed_request(
        context: &RestartCatchupContextV1,
        provider: ValidatorId,
        set: &ValidatorSet,
        target_key: &SigningKey,
        maximum_entries: u32,
        maximum_chunks: u32,
        maximum_bytes: u64,
    ) -> SignedRestartCatchupMessageV1 {
        SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            context.target_validator,
            request_body(context, maximum_entries, maximum_chunks, maximum_bytes),
            set,
            target_key,
        )
        .unwrap()
    }

    fn signed_manifest(
        context: &RestartCatchupContextV1,
        provider: ValidatorId,
        set: &ValidatorSet,
        provider_key: &SigningKey,
        entry_count: u32,
        chunk_count: u32,
        total_bytes: u64,
    ) -> SignedRestartCatchupMessageV1 {
        SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            provider,
            manifest_body(context, entry_count, chunk_count, total_bytes),
            set,
            provider_key,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_chunk(
        context: &RestartCatchupContextV1,
        provider: ValidatorId,
        set: &ValidatorSet,
        provider_key: &SigningKey,
        manifest_digest: [u8; 32],
        chunk_index: u32,
        chunk_count: u32,
        predecessor_digest: [u8; 32],
        bytes: &[u8],
    ) -> SignedRestartCatchupMessageV1 {
        SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            provider,
            chunk_body(
                manifest_digest,
                chunk_index,
                chunk_count,
                predecessor_digest,
                bytes,
            ),
            set,
            provider_key,
        )
        .unwrap()
    }

    fn frame(
        outer_sender: ValidatorId,
        message: &SignedRestartCatchupMessageV1,
    ) -> AuthenticatedFrame {
        AuthenticatedFrame {
            sender: outer_sender,
            session: [0x61; 32],
            sequence: 1,
            kind: FrameKind::RestartCatchup,
            payload: message.encode().unwrap(),
        }
    }

    fn relay_frame(
        hop_sender: ValidatorId,
        envelope: &ConsensusRelayEnvelopeV0,
    ) -> AuthenticatedFrame {
        AuthenticatedFrame {
            sender: hop_sender,
            session: [0x62; 32],
            sequence: 2,
            kind: FrameKind::ConsensusRelay,
            payload: envelope.encode(),
        }
    }

    fn carrier(
        message: &SignedRestartCatchupMessageV1,
        set: &ValidatorSet,
    ) -> VerifiedRestartCatchupCarrierV1 {
        decode_authenticated_restart_catchup_frame_v1(
            &frame(message.origin, message),
            &message.context,
            set,
        )
        .unwrap()
    }

    fn resign_unchecked(message: &mut SignedRestartCatchupMessageV1, key: &SigningKey) {
        message.signature = key.sign(&message.signing_root().unwrap()).to_bytes();
    }

    #[test]
    fn canonical_subtypes_have_independent_origin_signatures_and_read_only_facts() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let target = context.target_validator;
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 2, 2, 6);
        let request_wire = request.encode().unwrap();
        assert_eq!(
            SignedRestartCatchupMessageV1::decode(&request_wire, &set)
                .unwrap()
                .encode()
                .unwrap(),
            request_wire
        );
        let request_carrier = carrier(&request, &set);
        assert_eq!(request_carrier.origin(), target);
        assert_eq!(request_carrier.provider(), provider);
        assert_eq!(request_carrier.subtype(), RestartCatchupSubtypeV1::Request);
        assert_eq!(request_carrier.request_facts().unwrap().maximum_bytes(), 6);
        assert!(request_carrier.manifest_facts().is_none());
        assert!(request_carrier.chunk_facts().is_none());

        let manifest = signed_manifest(&context, provider, &set, &keys[1], 2, 2, 6);
        let manifest_digest = manifest.manifest_digest().unwrap().unwrap();
        let manifest_carrier = carrier(&manifest, &set);
        let manifest_facts = manifest_carrier.manifest_facts().unwrap();
        assert_eq!(manifest_facts.restart_cut_height(), 3);
        assert_eq!(manifest_facts.restart_cut_block_id(), [0x46; 32]);
        assert_eq!(manifest_facts.manifest_digest(), manifest_digest);
        assert_eq!(manifest_facts.last_certified_height(), 5);
        assert_eq!(manifest_facts.target_applied_height(), 4);
        assert_ne!(
            manifest_facts.last_certified_block_id(),
            manifest_facts.target_applied_block_id()
        );
        assert_ne!(
            manifest_facts.last_certified_qc_sha256(),
            manifest_facts.target_applied_checkpoint_sha256()
        );
        let chunk = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abc",
        );
        let chunk_carrier = carrier(&chunk, &set);
        assert_eq!(chunk_carrier.chunk_facts().unwrap().byte_count(), 3);
        assert_ne!(
            hash_canonical(
                REQUEST_SIGNING_DOMAIN_V1,
                &request.encode_unsigned().unwrap()
            ),
            hash_canonical(
                MANIFEST_SIGNING_DOMAIN_V1,
                &request.encode_unsigned().unwrap()
            )
        );
    }

    #[test]
    fn direct_and_relay_origins_must_equal_the_independently_signed_inner_origin() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        assert!(matches!(
            decode_authenticated_restart_catchup_frame_v1(
                &frame(set.validators()[3].id(), &request),
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::OuterOriginMismatch)
        ));
        assert!(carrier(&request, &set).request_facts().is_some());

        let mut invalid_inner = request.clone();
        invalid_inner.signature[0] ^= 1;
        assert!(matches!(
            decode_authenticated_restart_catchup_frame_v1(
                &frame(set.validators()[3].id(), &invalid_inner),
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::InvalidSignature)
        ));

        let relay = ConsensusRelayEnvelopeV0::new(
            context.target_validator,
            FrameKind::RestartCatchup,
            1,
            request.encode().unwrap(),
            &set,
            &keys[0],
        )
        .unwrap();
        assert!(decode_authenticated_relayed_restart_catchup_frame_v1(
            &relay_frame(set.validators()[3].id(), &relay),
            &context,
            &set,
        )
        .unwrap()
        .request_facts()
        .is_some());
        let mut wrong_expected_context = context.clone();
        wrong_expected_context.recovery_nonce = [0x7a; 32];
        assert!(matches!(
            decode_authenticated_relayed_restart_catchup_frame_v1(
                &relay_frame(set.validators()[3].id(), &relay),
                &wrong_expected_context,
                &set,
            ),
            Err(RestartCatchupErrorV1::WrongContext)
        ));

        let mismatched_origin = ConsensusRelayEnvelopeV0::new(
            set.validators()[3].id(),
            FrameKind::RestartCatchup,
            1,
            request.encode().unwrap(),
            &set,
            &keys[3],
        )
        .unwrap();
        assert!(matches!(
            decode_authenticated_relayed_restart_catchup_frame_v1(
                &relay_frame(set.validators()[2].id(), &mismatched_origin),
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::RelayOriginMismatch)
        ));

        let invalid_inner_relay = ConsensusRelayEnvelopeV0::new(
            context.target_validator,
            FrameKind::RestartCatchup,
            1,
            invalid_inner.encode().unwrap(),
            &set,
            &keys[0],
        )
        .unwrap();
        assert!(matches!(
            decode_authenticated_relayed_restart_catchup_frame_v1(
                &relay_frame(set.validators()[2].id(), &invalid_inner_relay),
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::InvalidSignature)
        ));
    }

    #[test]
    fn direct_and_relay_decoders_reject_zero_outer_session_but_keep_relay_inner_synthetic() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);

        let mut direct = frame(request.origin, &request);
        direct.session = [0; 32];
        assert!(matches!(
            decode_authenticated_restart_catchup_frame_v1(&direct, &context, &set),
            Err(RestartCatchupErrorV1::Malformed("session ID"))
        ));

        let relay = ConsensusRelayEnvelopeV0::new(
            request.origin,
            FrameKind::RestartCatchup,
            1,
            request.encode().unwrap(),
            &set,
            &keys[0],
        )
        .unwrap();
        let mut relayed = relay_frame(set.validators()[3].id(), &relay);
        relayed.session = [0; 32];
        assert!(matches!(
            decode_authenticated_relayed_restart_catchup_frame_v1(&relayed, &context, &set),
            Err(RestartCatchupErrorV1::Malformed("session ID"))
        ));

        // The relay's embedded comparison frame still has its intentional
        // zero session; a real nonzero outer hop must continue to decode it.
        assert!(decode_authenticated_relayed_restart_catchup_frame_v1(
            &relay_frame(set.validators()[3].id(), &relay),
            &context,
            &set,
        )
        .is_ok());
    }

    #[test]
    fn mesh_catchup_decoder_rejects_stale_session_generation_and_owner_substitution() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);

        let direct = frame(request.origin, &request);
        let current_direct = PeerSessionFactsV0::for_test(
            request.origin,
            PeerDirectionV0::Inbound,
            direct.session,
            2,
        );
        let carrier = decode_authenticated_restart_catchup_mesh_frame_v1(
            MeshInboundFrameV0::for_test(current_direct, direct.clone()),
            current_direct,
            &context,
            &set,
        )
        .unwrap();
        assert_eq!(carrier.origin(), request.origin);

        // A frame retained from the old connection cannot be admitted under
        // the replacement session, even when all inner bytes and signatures
        // remain valid.
        let old_session = PeerSessionFactsV0::for_test(
            request.origin,
            PeerDirectionV0::Inbound,
            direct.session,
            1,
        );
        let new_session =
            PeerSessionFactsV0::for_test(request.origin, PeerDirectionV0::Inbound, [0x63; 32], 2);
        assert!(matches!(
            decode_authenticated_restart_catchup_mesh_frame_v1(
                MeshInboundFrameV0::for_test(old_session, direct.clone()),
                new_session,
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch)
        ));

        // A same-session frame from an obsolete worker generation is equally
        // stale; the semantic catch-up digest is not a replay authority.
        let current_generation = PeerSessionFactsV0::for_test(
            request.origin,
            PeerDirectionV0::Inbound,
            direct.session,
            3,
        );
        assert!(matches!(
            decode_authenticated_restart_catchup_mesh_frame_v1(
                MeshInboundFrameV0::for_test(old_session, direct),
                current_generation,
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch)
        ));

        let relay = ConsensusRelayEnvelopeV0::new(
            request.origin,
            FrameKind::RestartCatchup,
            1,
            request.encode().unwrap(),
            &set,
            &keys[0],
        )
        .unwrap();
        let relayed = relay_frame(set.validators()[3].id(), &relay);
        let current_relay = PeerSessionFactsV0::for_test(
            set.validators()[3].id(),
            PeerDirectionV0::Inbound,
            relayed.session,
            4,
        );
        assert!(decode_authenticated_relayed_restart_catchup_mesh_frame_v1(
            MeshInboundFrameV0::for_test(current_relay, relayed.clone()),
            current_relay,
            &context,
            &set,
        )
        .is_ok());
        let stale_relay = PeerSessionFactsV0::for_test(
            set.validators()[3].id(),
            PeerDirectionV0::Inbound,
            relayed.session,
            5,
        );
        assert!(matches!(
            decode_authenticated_relayed_restart_catchup_mesh_frame_v1(
                MeshInboundFrameV0::for_test(current_relay, relayed),
                stale_relay,
                &context,
                &set,
            ),
            Err(RestartCatchupErrorV1::AuthenticatedTransportMismatch)
        ));
    }

    #[test]
    fn signature_domain_key_origin_provider_and_target_mutants_fail_closed() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let mut wrong_domain = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        wrong_domain.signature = keys[0]
            .sign(&hash_canonical(
                MANIFEST_SIGNING_DOMAIN_V1,
                &wrong_domain.encode_unsigned().unwrap(),
            ))
            .to_bytes();
        assert!(matches!(
            SignedRestartCatchupMessageV1::decode(&wrong_domain.encode().unwrap(), &set),
            Err(RestartCatchupErrorV1::InvalidSignature)
        ));

        assert!(matches!(
            SignedRestartCatchupMessageV1::sign_for_test(
                context.clone(),
                provider,
                context.target_validator,
                request_body(&context, 1, 1, 3),
                &set,
                &keys[1],
            ),
            Err(RestartCatchupErrorV1::OriginKeyMismatch)
        ));
        assert!(matches!(
            SignedRestartCatchupMessageV1::sign_for_test(
                context.clone(),
                context.target_validator,
                context.target_validator,
                request_body(&context, 1, 1, 3),
                &set,
                &keys[0],
            ),
            Err(RestartCatchupErrorV1::ProviderIsTarget)
        ));

        let mut request_from_provider = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        request_from_provider.origin = provider;
        resign_unchecked(&mut request_from_provider, &keys[1]);
        assert!(matches!(
            SignedRestartCatchupMessageV1::decode(&request_from_provider.encode().unwrap(), &set,),
            Err(RestartCatchupErrorV1::RequestOriginNotTarget)
        ));

        let mut provider_reply_from_target =
            signed_manifest(&context, provider, &set, &keys[1], 1, 1, 3);
        provider_reply_from_target.origin = context.target_validator;
        resign_unchecked(&mut provider_reply_from_target, &keys[0]);
        assert!(matches!(
            SignedRestartCatchupMessageV1::decode(
                &provider_reply_from_target.encode().unwrap(),
                &set,
            ),
            Err(RestartCatchupErrorV1::ProviderOriginMismatch)
        ));

        let mut wrong_kind = frame(context.target_validator, &request_from_provider);
        wrong_kind.kind = FrameKind::RestartPrepare;
        assert!(matches!(
            decode_authenticated_restart_catchup_frame_v1(&wrong_kind, &context, &set),
            Err(RestartCatchupErrorV1::UnsupportedFrameKind)
        ));
        let mut unknown_outer = frame(context.target_validator, &provider_reply_from_target);
        unknown_outer.sender = ValidatorId::new([0xee; 32]);
        assert!(matches!(
            decode_authenticated_restart_catchup_frame_v1(&unknown_outer, &context, &set),
            Err(RestartCatchupErrorV1::UnknownOuterSender)
        ));
    }

    #[test]
    fn every_recovery_context_field_is_bound_and_mutants_are_rejected() {
        let (set, keys) = fixture(7);
        let base = context(&set);
        let provider = set.validators()[1].id();
        let mut valid_mutants = Vec::new();
        let mut value = base.clone();
        value.run_id = "poco-g3-7-20260818T060421Z-deadbeef".to_owned();
        valid_mutants.push((value, 0usize));
        let mut value = base.clone();
        value.campaign_context_sha256 = [0x71; 32];
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.fleet_start_certificate_sha256 = [0x72; 32];
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.validator_set_sha256 = [0x73; 32];
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.restart_cut_artifact_sha256 = [0x74; 32];
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.target_validator = set.validators()[2].id();
        valid_mutants.push((value, 2));
        let mut value = base.clone();
        value.recovery_nonce = [0x75; 32];
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.restart_cut_height = 4;
        valid_mutants.push((value, 0));
        let mut value = base.clone();
        value.restart_cut_block_id = [0x76; 32];
        valid_mutants.push((value, 0));

        for (mutant, target_index) in valid_mutants {
            let message = signed_request(&mutant, provider, &set, &keys[target_index], 1, 1, 3);
            assert!(matches!(
                decode_authenticated_restart_catchup_frame_v1(
                    &frame(message.origin, &message),
                    &base,
                    &set,
                ),
                Err(RestartCatchupErrorV1::WrongContext)
            ));
        }

        for mutate in [0u8, 1] {
            let mut message = signed_request(&base, provider, &set, &keys[0], 1, 1, 3);
            if mutate == 0 {
                message.context.validator_set_id = [0x77; 32];
            } else {
                message.context.process_instance = 1;
            }
            resign_unchecked(&mut message, &keys[0]);
            assert!(
                SignedRestartCatchupMessageV1::decode(&message.encode().unwrap(), &set).is_err()
            );
        }
    }

    #[test]
    fn context_reuses_canonical_g3_run_id_grammar_and_requires_fixed_width_validator_ids() {
        let (set, _) = fixture(7);
        let base = context(&set);
        for run_id in [
            "poco-g3-7-20260818T060420Z-a1b2c3d".to_owned(),
            "poco-g3-7-20260818T060420Z-a1b2c3d4-extra".to_owned(),
            "poco-g3-7-20260818T06042Z-a1b2c3d4".to_owned(),
            "poco-g3-7-20260818X060420Z-a1b2c3d4".to_owned(),
            "poco-g3-7-20260818T060420Z-A1b2c3d4".to_owned(),
            "poco-g3-7-has_underscore".to_owned(),
            "poco-g3-7-has.dot".to_owned(),
            "poco-g3-7-has-A".to_owned(),
        ] {
            let mut mutant = base.clone();
            mutant.run_id = run_id;
            assert!(matches!(
                mutant.validate_for_set(&set),
                Err(RestartCatchupErrorV1::Malformed("run ID"))
            ));
        }

        for length in [1usize, 31, 33, 128] {
            let (non_g3_set, _) = fixture_with_validator_id_length(length);
            assert!(matches!(
                RestartCatchupContextV1::new_expected_v1(
                    "poco-g3-7-20260818T060420Z-a1b2c3d4".to_owned(),
                    [0x41; 32],
                    [0x42; 32],
                    *non_g3_set.id().as_bytes(),
                    [0x43; 32],
                    [0x44; 32],
                    non_g3_set.validators()[0].id(),
                    2,
                    [0x45; 32],
                    3,
                    [0x46; 32],
                    &non_g3_set,
                ),
                Err(RestartCatchupErrorV1::InvalidValidatorSet)
            ));
        }
    }

    #[test]
    fn byte_bearing_public_owners_have_no_debug_or_clone_escape() {
        let source = include_str!("restart_catchup.rs");
        for declaration in [
            "pub struct VerifiedRestartCatchupCarrierV1",
            "pub struct RestartCatchupChunkActionV1",
            "pub enum RestartCatchupConsumingActionV1",
            "pub struct RestartCatchupAdmissionResultV1",
        ] {
            assert!(source.contains(declaration));
            assert!(!source.contains(&format!("#[derive(Debug)]\n{declaration}")));
            assert!(!source.contains(&format!("#[derive(Debug, Clone)]\n{declaration}")));
        }
    }

    #[test]
    fn canonical_decoder_rejects_trailing_noncanonical_oversize_and_bad_body_bounds() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        let mut trailing = request.encode().unwrap();
        trailing.push(0);
        assert!(SignedRestartCatchupMessageV1::decode(&trailing, &set).is_err());
        assert!(matches!(
            SignedRestartCatchupMessageV1::decode(
                &vec![0; MAX_RESTART_CATCHUP_WIRE_BYTES_V1 + 1],
                &set,
            ),
            Err(RestartCatchupErrorV1::TooLarge)
        ));
        let mut wrong_subtype = request.encode().unwrap();
        wrong_subtype[WIRE_MAGIC_V1.len() + 2] = RestartCatchupSubtypeV1::Chunk as u8;
        assert!(SignedRestartCatchupMessageV1::decode(&wrong_subtype, &set).is_err());

        assert!(SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            context.target_validator,
            request_body(
                &context,
                MAX_RESTART_CATCHUP_ENTRIES_PER_PROVIDER_V1 + 1,
                1,
                3,
            ),
            &set,
            &keys[0],
        )
        .is_err());
        let mut wrong_cut_request = match request_body(&context, 1, 1, 3) {
            RestartCatchupBodyV1::Request(body) => body,
            _ => unreachable!(),
        };
        wrong_cut_request.facts.restart_cut_block_id = [0x84; 32];
        assert!(SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            context.target_validator,
            RestartCatchupBodyV1::Request(wrong_cut_request),
            &set,
            &keys[0],
        )
        .is_err());
        assert!(SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            provider,
            manifest_body(&context, 0, 1, 3),
            &set,
            &keys[1],
        )
        .is_err());
        for mutation in 0u8..3 {
            let mut body = match manifest_body(&context, 2, 2, 6) {
                RestartCatchupBodyV1::Manifest(body) => body,
                _ => unreachable!(),
            };
            match mutation {
                0 => body.first_height += 1,
                1 => body.entry_count += 1,
                2 => body.target_applied_checkpoint_sha256 = [0; 32],
                _ => unreachable!(),
            }
            assert!(SignedRestartCatchupMessageV1::sign_for_test(
                context.clone(),
                provider,
                provider,
                RestartCatchupBodyV1::Manifest(body),
                &set,
                &keys[1],
            )
            .is_err());
        }
        let oversized = vec![0x81; MAX_RESTART_CATCHUP_CHUNK_BYTES_V1 + 1];
        assert!(SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            provider,
            chunk_body([0x82; 32], 0, 1, [0x82; 32], &oversized),
            &set,
            &keys[1],
        )
        .is_err());
        let mut bad_digest_body = match chunk_body([0x83; 32], 0, 1, [0x83; 32], b"abc") {
            RestartCatchupBodyV1::Chunk(body) => body,
            _ => unreachable!(),
        };
        bad_digest_body.content_digest[0] ^= 1;
        assert!(SignedRestartCatchupMessageV1::sign_for_test(
            context,
            provider,
            provider,
            RestartCatchupBodyV1::Chunk(bad_digest_body),
            &set,
            &keys[1],
        )
        .is_err());
    }

    #[test]
    fn exact_duplicate_is_inert_and_ordered_chunks_release_only_consuming_actions() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 2, 2, 6);
        let manifest = signed_manifest(&context, provider, &set, &keys[1], 2, 2, 6);
        let manifest_digest = manifest.manifest_digest().unwrap().unwrap();
        let first = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abc",
        );
        let first_digest = match &first.body {
            RestartCatchupBodyV1::Chunk(body) => body.content_digest,
            _ => unreachable!(),
        };
        let second = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            1,
            2,
            first_digest,
            b"def",
        );
        let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        for message in [&request, &manifest, &first] {
            let admitted = window.admit(carrier(message, &set)).unwrap();
            assert_eq!(admitted.admission(), RestartCatchupAdmissionV1::New);
            assert!(admitted.into_action().is_some());
            let duplicate = window.admit(carrier(message, &set)).unwrap();
            assert_eq!(
                duplicate.admission(),
                RestartCatchupAdmissionV1::ExactDuplicate
            );
            assert!(duplicate.into_action().is_none());
        }
        let admitted = window.admit(carrier(&second, &set)).unwrap();
        let action = admitted.into_action().unwrap();
        let RestartCatchupConsumingActionV1::Chunk(chunk) = action else {
            panic!("expected consuming chunk action");
        };
        assert_eq!(chunk.facts().chunk_index(), 1);
        assert_eq!(chunk.into_bytes(), b"def".to_vec());
        assert_eq!(window.provider_count(), 1);
        assert_eq!(window.reserved_chunks(), 2);
        assert_eq!(window.reserved_bytes(), 6);
        assert_eq!(window.received_chunks(), 2);
        assert_eq!(window.received_bytes(), 6);
        for replay in [&request, &manifest, &first, &second] {
            let duplicate = window.admit(carrier(replay, &set)).unwrap();
            assert_eq!(
                duplicate.admission(),
                RestartCatchupAdmissionV1::ExactDuplicate
            );
            assert!(duplicate.into_action().is_none());
        }
        assert!(!window.is_poisoned());
    }

    #[test]
    fn request_manifest_and_chunk_conflicts_permanently_poison() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 2, 2, 6);
        let conflicting_request = signed_request(&context, provider, &set, &keys[0], 3, 2, 6);
        let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        window.admit(carrier(&request, &set)).unwrap();
        assert!(matches!(
            window.admit(carrier(&conflicting_request, &set)),
            Err(RestartCatchupErrorV1::Equivocation("request"))
        ));
        assert!(window.is_poisoned());
        assert!(matches!(
            window.admit(carrier(&request, &set)),
            Err(RestartCatchupErrorV1::Poisoned)
        ));

        let manifest = signed_manifest(&context, provider, &set, &keys[1], 2, 2, 6);
        let mut alternate_manifest_body = match manifest_body(&context, 2, 2, 6) {
            RestartCatchupBodyV1::Manifest(body) => body,
            _ => unreachable!(),
        };
        alternate_manifest_body.last_certified_block_id = [0xa1; 32];
        let alternate_manifest = SignedRestartCatchupMessageV1::sign_for_test(
            context.clone(),
            provider,
            provider,
            RestartCatchupBodyV1::Manifest(alternate_manifest_body),
            &set,
            &keys[1],
        )
        .unwrap();
        let mut manifest_window =
            RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        manifest_window.admit(carrier(&request, &set)).unwrap();
        manifest_window.admit(carrier(&manifest, &set)).unwrap();
        assert!(matches!(
            manifest_window.admit(carrier(&alternate_manifest, &set)),
            Err(RestartCatchupErrorV1::Equivocation("manifest"))
        ));
        assert!(manifest_window.is_poisoned());

        let manifest_digest = manifest.manifest_digest().unwrap().unwrap();
        let first = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abc",
        );
        let conflicting_first = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abd",
        );
        let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        for message in [&request, &manifest, &first] {
            window.admit(carrier(message, &set)).unwrap();
        }
        assert!(matches!(
            window.admit(carrier(&conflicting_first, &set)),
            Err(RestartCatchupErrorV1::Equivocation("chunk index"))
        ));
        assert!(window.is_poisoned());
    }

    #[test]
    fn order_manifest_predecessor_count_and_byte_mutants_poison() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 2, 2, 7);
        let manifest = signed_manifest(&context, provider, &set, &keys[1], 2, 2, 7);
        let manifest_digest = manifest.manifest_digest().unwrap().unwrap();

        let mut before_request =
            RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        assert!(matches!(
            before_request.admit(carrier(&manifest, &set)),
            Err(RestartCatchupErrorV1::OutOfOrder(_))
        ));
        assert!(before_request.is_poisoned());

        let premature_chunk = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abc",
        );
        let mut before_manifest =
            RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        before_manifest.admit(carrier(&request, &set)).unwrap();
        assert!(matches!(
            before_manifest.admit(carrier(&premature_chunk, &set)),
            Err(RestartCatchupErrorV1::OutOfOrder("chunk before manifest"))
        ));
        assert!(before_manifest.is_poisoned());

        let cases = [
            signed_chunk(
                &context,
                provider,
                &set,
                &keys[1],
                [0x91; 32],
                0,
                2,
                manifest_digest,
                b"abc",
            ),
            signed_chunk(
                &context,
                provider,
                &set,
                &keys[1],
                manifest_digest,
                1,
                2,
                manifest_digest,
                b"abc",
            ),
            signed_chunk(
                &context,
                provider,
                &set,
                &keys[1],
                manifest_digest,
                0,
                2,
                [0x92; 32],
                b"abc",
            ),
            signed_chunk(
                &context,
                provider,
                &set,
                &keys[1],
                manifest_digest,
                0,
                1,
                manifest_digest,
                b"abc",
            ),
        ];
        for mutant in cases {
            let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
            window.admit(carrier(&request, &set)).unwrap();
            window.admit(carrier(&manifest, &set)).unwrap();
            assert!(matches!(
                window.admit(carrier(&mutant, &set)),
                Err(RestartCatchupErrorV1::SemanticConflict(_))
            ));
            assert!(window.is_poisoned());
        }

        let first = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            2,
            manifest_digest,
            b"abc",
        );
        let first_digest = match &first.body {
            RestartCatchupBodyV1::Chunk(body) => body.content_digest,
            _ => unreachable!(),
        };
        let short_final = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            1,
            2,
            first_digest,
            b"def",
        );
        let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        for message in [&request, &manifest, &first] {
            window.admit(carrier(message, &set)).unwrap();
        }
        assert!(matches!(
            window.admit(carrier(&short_final, &set)),
            Err(RestartCatchupErrorV1::SemanticConflict(
                "chunk aggregate bytes"
            ))
        ));
        assert!(window.is_poisoned());

        let tight_request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        let oversized_manifest = signed_manifest(&context, provider, &set, &keys[1], 2, 2, 6);
        let mut window = RestartCatchupAdmissionWindowV1::new(context, &set).unwrap();
        window.admit(carrier(&tight_request, &set)).unwrap();
        assert!(matches!(
            window.admit(carrier(&oversized_manifest, &set)),
            Err(RestartCatchupErrorV1::SemanticConflict(
                "manifest request bounds"
            ))
        ));
        assert!(window.is_poisoned());
    }

    #[test]
    fn seven_validator_capacity_is_checked_before_state_construction() {
        let capacity = required_restart_catchup_capacity_v1(7).unwrap();
        assert_eq!(capacity.maximum_providers(), 6);
        assert_eq!(capacity.maximum_chunks(), 96);
        assert_eq!(capacity.maximum_bytes(), 3 * 1024 * 1024);
        for unsupported in [0, 1, 6, 31, 100, usize::MAX] {
            assert!(matches!(
                required_restart_catchup_capacity_v1(unsupported),
                Err(RestartCatchupErrorV1::UnsupportedProfile)
            ));
        }
        let (set, keys) = fixture(7);
        let context7 = context(&set);
        let mut window = RestartCatchupAdmissionWindowV1::new(context7.clone(), &set).unwrap();
        for (index, validator) in set.validators().iter().enumerate().skip(1) {
            let request = signed_request(
                &context7,
                validator.id(),
                &set,
                &keys[0],
                1,
                MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1,
                MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1,
            );
            let manifest = signed_manifest(
                &context7,
                validator.id(),
                &set,
                &keys[index],
                1,
                MAX_RESTART_CATCHUP_CHUNKS_PER_PROVIDER_V1,
                MAX_RESTART_CATCHUP_BYTES_PER_PROVIDER_V1,
            );
            window.admit(carrier(&request, &set)).unwrap();
            window.admit(carrier(&manifest, &set)).unwrap();
        }
        assert_eq!(window.provider_count(), 6);
        assert_eq!(window.reserved_chunks(), capacity.maximum_chunks());
        assert_eq!(window.reserved_bytes(), capacity.maximum_bytes());
        assert!(!window.is_poisoned());

        let (set31, _) = fixture(31);
        let mut context31 = context(&fixture(7).0);
        context31.validator_set_id = *set31.id().as_bytes();
        context31.target_validator = set31.validators()[0].id();
        context31.run_id = "poco-g3-7-still-not-31-enabled".to_owned();
        assert!(matches!(
            RestartCatchupAdmissionWindowV1::new(context31, &set31),
            Err(RestartCatchupErrorV1::UnsupportedProfile)
        ));
    }

    #[test]
    fn impossible_internal_capacity_overflow_still_permanently_poisons() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let provider = set.validators()[1].id();
        let request = signed_request(&context, provider, &set, &keys[0], 1, 1, 3);
        let manifest = signed_manifest(&context, provider, &set, &keys[1], 1, 1, 3);

        let mut manifest_overflow =
            RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        manifest_overflow.admit(carrier(&request, &set)).unwrap();
        manifest_overflow.reserved_chunks = usize::MAX;
        assert!(matches!(
            manifest_overflow.admit(carrier(&manifest, &set)),
            Err(RestartCatchupErrorV1::Capacity)
        ));
        assert!(manifest_overflow.is_poisoned());

        let manifest_digest = manifest.manifest_digest().unwrap().unwrap();
        let chunk = signed_chunk(
            &context,
            provider,
            &set,
            &keys[1],
            manifest_digest,
            0,
            1,
            manifest_digest,
            b"abc",
        );
        let mut chunk_overflow = RestartCatchupAdmissionWindowV1::new(context, &set).unwrap();
        chunk_overflow.admit(carrier(&request, &set)).unwrap();
        chunk_overflow.admit(carrier(&manifest, &set)).unwrap();
        chunk_overflow
            .provider_states
            .get_mut(&provider)
            .unwrap()
            .received_bytes = u64::MAX;
        assert!(matches!(
            chunk_overflow.admit(carrier(&chunk, &set)),
            Err(RestartCatchupErrorV1::Capacity)
        ));
        assert!(chunk_overflow.is_poisoned());
    }

    #[test]
    fn provider_bundle_assembler_rejects_cross_provider_chunk_before_byte_release() {
        let (set, keys) = fixture(7);
        let context = context(&set);
        let first_provider = set.validators()[1].id();
        let second_provider = set.validators()[2].id();
        let first_request = signed_request(&context, first_provider, &set, &keys[0], 2, 1, 3);
        let first_manifest = signed_manifest(&context, first_provider, &set, &keys[1], 2, 1, 3);
        let second_request = signed_request(&context, second_provider, &set, &keys[0], 1, 1, 3);
        let second_manifest = signed_manifest(&context, second_provider, &set, &keys[2], 1, 1, 3);
        let second_manifest_digest = second_manifest.manifest_digest().unwrap().unwrap();
        let second_chunk = signed_chunk(
            &context,
            second_provider,
            &set,
            &keys[2],
            second_manifest_digest,
            0,
            1,
            second_manifest_digest,
            b"bad",
        );
        let mut window = RestartCatchupAdmissionWindowV1::new(context.clone(), &set).unwrap();
        window.admit(carrier(&first_request, &set)).unwrap();
        let first_manifest_action = match window
            .admit(carrier(&first_manifest, &set))
            .unwrap()
            .into_action()
            .unwrap()
        {
            RestartCatchupConsumingActionV1::Manifest(action) => action,
            _ => panic!("expected first provider manifest"),
        };
        window.admit(carrier(&second_request, &set)).unwrap();
        window.admit(carrier(&second_manifest, &set)).unwrap();
        let second_chunk_action = match window
            .admit(carrier(&second_chunk, &set))
            .unwrap()
            .into_action()
            .unwrap()
        {
            RestartCatchupConsumingActionV1::Chunk(action) => action,
            _ => panic!("expected second provider chunk"),
        };
        let source = RestartCatchupAppliedCutV1::from_authenticated_local_cut_v1(
            context.restart_cut_height,
            context.restart_cut_block_id,
            [0xb1; 32],
            [0xb2; 32],
            [0xb3; 32],
            99,
            [0xb4; 32],
            [0xb5; 32],
        )
        .unwrap();
        let expectation = RestartCatchupBundleExpectationV1::from_authenticated_manifest_v1(
            context,
            source,
            first_manifest_action,
        )
        .unwrap();
        let mut assembler = RestartCatchupProviderBundleAssemblerV1::new(expectation);
        assert!(matches!(
            assembler.admit_chunk_v1(second_chunk_action),
            Err(RestartCatchupErrorV1::BundleMismatch(
                "cross-provider or broken manifest/chunk chain"
            ))
        ));
        assert!(assembler.poisoned);
    }

    fn private_bundle_publication_root_v1(temporary: &TempDir, name: &str) -> PathBuf {
        let root = temporary.path().join(name);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn write_private_bundle_publication_file_v1(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(root).unwrap().sync_all().unwrap();
        path
    }

    #[test]
    fn fixed_private_bundle_publish_is_exact_response_loss_idempotent_and_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let root = private_bundle_publication_root_v1(&temporary, "restart-catchup-private-v1");
        let bytes = b"strict-decoder-precedes-this-private-publication";
        publish_restart_catchup_bundle_create_new_v1(&root, bytes).unwrap();
        publish_restart_catchup_bundle_create_new_v1(&root, bytes).unwrap();
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&root, b"mutant"),
            Err(RestartCatchupErrorV1::Durable(_))
        ));

        let sidecar_root =
            private_bundle_publication_root_v1(&temporary, "restart-catchup-sidecar-v1");
        fs::write(
            sidecar_root.join(RESTART_CATCHUP_BUNDLE_SIDECARS_V1[1]),
            b"mutant",
        )
        .unwrap();
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&sidecar_root, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
    }

    #[test]
    fn fixed_bundle_next_states_reconcile_only_exact_response_loss() {
        let temporary = TempDir::new().unwrap();
        let bytes = b"strict-fixed-next-publication-candidate";

        let next_only = private_bundle_publication_root_v1(&temporary, "bundle-next-only-v1");
        let next = write_private_bundle_publication_file_v1(
            &next_only,
            RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1,
            bytes,
        );
        publish_restart_catchup_bundle_create_new_v1(&next_only, bytes).unwrap();
        assert!(!next.exists());
        assert_eq!(
            fs::read(next_only.join(RESTART_CATCHUP_BUNDLE_FILE_V1)).unwrap(),
            bytes
        );

        let linked = private_bundle_publication_root_v1(&temporary, "bundle-linked-final-v1");
        publish_restart_catchup_bundle_create_new_v1(&linked, bytes).unwrap();
        let target = linked.join(RESTART_CATCHUP_BUNDLE_FILE_V1);
        let next = linked.join(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1);
        fs::hard_link(&target, &next).unwrap();
        File::open(&linked).unwrap().sync_all().unwrap();
        publish_restart_catchup_bundle_create_new_v1(&linked, bytes).unwrap();
        assert!(!next.exists());
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);

        let partial = private_bundle_publication_root_v1(&temporary, "bundle-partial-next-v1");
        let partial_next = write_private_bundle_publication_file_v1(
            &partial,
            RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1,
            &bytes[..bytes.len() - 1],
        );
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&partial, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert_eq!(fs::read(&partial_next).unwrap(), &bytes[..bytes.len() - 1]);
        assert!(!partial.join(RESTART_CATCHUP_BUNDLE_FILE_V1).exists());
    }

    #[test]
    fn bundle_publication_recovers_authenticated_writing_kill_windows() {
        let temporary = TempDir::new().unwrap();
        let bytes = b"complete-provider-bundle-publication-bytes";
        for (attempt, prefix_length, incomplete_mode) in [
            (1u64, 0usize, Some(0o000)),
            (2, 1, None),
            (3, bytes.len() - 1, None),
            (4, bytes.len(), None),
        ] {
            let root = private_bundle_publication_root_v1(
                &temporary,
                &format!("bundle-writing-kill-{attempt}-v1"),
            );
            let writing_name = restart_catchup_bundle_writing_file_name_v1(0x72a1, attempt);
            let writing = write_private_bundle_publication_file_v1(
                &root,
                &writing_name,
                &bytes[..prefix_length],
            );
            if let Some(mode) = incomplete_mode {
                fs::set_permissions(&writing, fs::Permissions::from_mode(mode)).unwrap();
            }
            publish_restart_catchup_bundle_create_new_v1(&root, bytes).unwrap();
            assert!(!writing.exists());
            assert_eq!(
                fs::read(root.join(RESTART_CATCHUP_BUNDLE_FILE_V1)).unwrap(),
                bytes
            );
            ensure_no_restart_catchup_bundle_sidecars_v1(&root).unwrap();
        }
    }

    #[test]
    fn bundle_publication_recovers_exact_writing_to_next_response_loss() {
        let temporary = TempDir::new().unwrap();
        let root = private_bundle_publication_root_v1(&temporary, "bundle-writing-linked-v1");
        let bytes = b"complete-linked-provider-bundle-publication";
        let writing_name = restart_catchup_bundle_writing_file_name_v1(0x72a2, 9);
        let writing = write_private_bundle_publication_file_v1(&root, &writing_name, bytes);
        let next = root.join(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1);
        fs::hard_link(&writing, &next).unwrap();
        File::open(&root).unwrap().sync_all().unwrap();

        publish_restart_catchup_bundle_create_new_v1(&root, bytes).unwrap();
        let target = root.join(RESTART_CATCHUP_BUNDLE_FILE_V1);
        assert!(!writing.exists());
        assert!(!next.exists());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::metadata(target).unwrap().nlink(), 1);
    }

    #[test]
    fn bundle_publication_preserves_foreign_writing_mutants_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let bytes = b"expected-provider-bundle-publication-bytes";

        let mismatched = private_bundle_publication_root_v1(&temporary, "bundle-mutant-prefix-v1");
        let mismatched_name = restart_catchup_bundle_writing_file_name_v1(0x72a3, 10);
        let mut mismatched_bytes = bytes[..bytes.len() - 1].to_vec();
        mismatched_bytes[0] ^= 1;
        let mismatched_path = write_private_bundle_publication_file_v1(
            &mismatched,
            &mismatched_name,
            &mismatched_bytes,
        );
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&mismatched, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_bytes);
        assert!(!mismatched.join(RESTART_CATCHUP_BUNDLE_FILE_V1).exists());

        let third_link = private_bundle_publication_root_v1(&temporary, "bundle-third-link-v1");
        let third_name = restart_catchup_bundle_writing_file_name_v1(0x72a4, 11);
        let third_path = write_private_bundle_publication_file_v1(&third_link, &third_name, bytes);
        let foreign_link = third_link.join("foreign-bundle-writing-link.bin");
        fs::hard_link(&third_path, &foreign_link).unwrap();
        File::open(&third_link).unwrap().sync_all().unwrap();
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&third_link, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert!(third_path.exists());
        assert!(foreign_link.exists());
        assert_eq!(fs::metadata(&third_path).unwrap().nlink(), 2);

        let separate_next =
            private_bundle_publication_root_v1(&temporary, "bundle-separate-next-v1");
        let separate_name = restart_catchup_bundle_writing_file_name_v1(0x72a5, 12);
        let separate_path =
            write_private_bundle_publication_file_v1(&separate_next, &separate_name, bytes);
        let separate_fixed = write_private_bundle_publication_file_v1(
            &separate_next,
            RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1,
            bytes,
        );
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&separate_next, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert!(separate_path.exists());
        assert!(separate_fixed.exists());
        assert_eq!(fs::metadata(&separate_path).unwrap().nlink(), 1);
        assert_eq!(fs::metadata(&separate_fixed).unwrap().nlink(), 1);

        let mutated_linked =
            private_bundle_publication_root_v1(&temporary, "bundle-mutated-linked-v1");
        let mutated_name = restart_catchup_bundle_writing_file_name_v1(0x72a6, 13);
        let mut mutated_bytes = bytes.to_vec();
        let last = mutated_bytes.len() - 1;
        mutated_bytes[last] ^= 1;
        let mutated_path = write_private_bundle_publication_file_v1(
            &mutated_linked,
            &mutated_name,
            &mutated_bytes,
        );
        let mutated_next = mutated_linked.join(RESTART_CATCHUP_BUNDLE_NEXT_FILE_V1);
        fs::hard_link(&mutated_path, &mutated_next).unwrap();
        File::open(&mutated_linked).unwrap().sync_all().unwrap();
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&mutated_linked, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert_eq!(fs::read(&mutated_path).unwrap(), mutated_bytes);
        assert!(mutated_next.exists());
        assert_eq!(fs::metadata(&mutated_path).unwrap().nlink(), 2);

        let malformed = private_bundle_publication_root_v1(&temporary, "bundle-malformed-name-v1");
        let malformed_name = format!("{RESTART_CATCHUP_BUNDLE_WRITING_PREFIX_V1}foreign");
        let malformed_path =
            write_private_bundle_publication_file_v1(&malformed, &malformed_name, &bytes[..1]);
        assert!(matches!(
            publish_restart_catchup_bundle_create_new_v1(&malformed, bytes),
            Err(RestartCatchupErrorV1::Durable(_))
        ));
        assert_eq!(fs::read(&malformed_path).unwrap(), &bytes[..1]);
        assert!(!malformed.join(RESTART_CATCHUP_BUNDLE_FILE_V1).exists());
    }

    #[test]
    fn durable_bundle_owner_is_non_clone_process_affined_and_has_no_raw_parts_escape() {
        let source = include_str!("restart_catchup.rs");
        assert!(source.contains("pub struct StoredRestartCatchupProviderBundleV1"));
        assert!(source.contains("owner_process_id: u32"));
        assert!(source.contains("std::process::id() != self.owner_process_id"));
        let forbidden_clone_impl =
            ["impl Clone for StoredRestartCatchup", "ProviderBundleV1"].concat();
        let forbidden_from_parts =
            ["StoredRestartCatchupProviderBundleV1::from_", "parts"].concat();
        let forbidden_raw_parts = ["into_raw_", "parts_v1"].concat();
        let synthetic_chain_root = ["next_chain_", "root_v1"].concat();
        assert!(!source.contains(&forbidden_clone_impl));
        assert!(!source.contains(&forbidden_from_parts));
        assert!(!source.contains(&forbidden_raw_parts));
        assert!(!source.contains(&synthetic_chain_root));
        assert!(source.contains("real\n/// Core finalized-prefix commitment"));
        assert!(!include_str!("signed_replay_archive.rs")
            .contains("restart-catchup-provider-bundle-v1"));
    }

    #[test]
    fn static_boundary_has_no_runtime_node_archive_ready_start_or_generic_payload_seam() {
        let source = include_str!("restart_catchup.rs");
        let forbidden_public_payload = ["pub fn ", "payload("].concat();
        let forbidden_public_sign = ["pub fn ", "sign_"].concat();
        assert!(!source.contains(&forbidden_public_payload));
        assert!(!source.contains(&forbidden_public_sign));
        for raw_decoder in [
            [
                "pub ",
                "fn ",
                "decode_authenticated_restart_catchup_frame_v1",
            ]
            .concat(),
            [
                "pub ",
                "fn ",
                "decode_authenticated_relayed_restart_catchup_frame_v1",
            ]
            .concat(),
        ] {
            assert!(!source.contains(&raw_decoder));
        }
        for operational in [
            include_str!("main.rs"),
            include_str!("consensus_runtime.rs"),
            include_str!("continuous_runtime.rs"),
            include_str!("runtime.rs"),
            include_str!("runtime_control.rs"),
            include_str!("signed_replay_archive.rs"),
            include_str!("process_event.rs"),
            include_str!("../../trnm-node/src/lib.rs"),
            include_str!("../../trnm-node/src/main.rs"),
            include_str!("../../trnm-poco-node/src/lib.rs"),
            include_str!("../../trnm-poco-node/src/main.rs"),
        ] {
            assert!(!operational.contains("FrameKind::RestartCatchup"));
            assert!(!operational.contains("restart_catchup::"));
        }
        for forbidden in [
            ["Recovery", "ReadyV1"].concat(),
            ["Recovery", "StartV1"].concat(),
            ["restart_completed", " = true"].concat(),
            ["VALIDATOR_RUNTIME", "_STARTED"].concat(),
            ["std::", "net"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }
}
