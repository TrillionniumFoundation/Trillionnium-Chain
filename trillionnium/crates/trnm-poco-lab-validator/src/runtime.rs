//! Strict evidence codec for the continuation-only G3 authority profile.
//!
//! The Node-owned runtime retains every signing-capable resource. This module
//! deliberately receives only terminal comparison facts and turns them into
//! one bounded, hash-chained JSON artifact. The artifact proves neither a
//! signature nor a continuous validator loop.

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_poco_node::{
    PocoNodeLabInertRequestFactsV0, PocoNodeLabInertRequestOwnerV0,
    PocoNodeLabOrdinaryProposalRuntimeV0, PocoNodeLabProposalJournalConfigV0,
};

use crate::crypto::LabFileWatermark;

pub type LabOrdinaryProposalRuntimeV0 = PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>;
pub type LabInertRequestOwnerV0 = PocoNodeLabInertRequestOwnerV0<LabFileWatermark>;
pub type LabProposalJournalConfigV0 = PocoNodeLabProposalJournalConfigV0;

const SCHEMA: &str = "trnm-poco-g3-authority-run-v1";
const PROFILE: &str = "frozen-v0-one-shot-authority";
const CHAIN_DOMAIN: &[u8] = b"trnm.poco-g3.authority-event-chain.v1";
const ARTIFACT_DOMAIN: &[u8] = b"trnm.poco-g3.authority-artifact.v1";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024;
const EVENT_KINDS: [&str; 9] = [
    "bootstrap_confirmed",
    "proposal_admitted",
    "obligation_safety_durable",
    "durable_p_confirmed",
    "core_d_durable",
    "safety_c_durable",
    "application_k_durable",
    "whole_node_checkpoint_cas_confirmed",
    "inert_request_retained",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityArtifactContextV1 {
    run_id: [u8; 32],
    validator_id: [u8; 32],
    config_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    validator_set_id: [u8; 32],
}

impl AuthorityArtifactContextV1 {
    pub fn new(
        run_id: &str,
        validator_id: [u8; 32],
        config_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        validator_set_id: [u8; 32],
    ) -> Result<Self, AuthorityArtifactErrorV1> {
        if run_id.is_empty()
            || run_id.len() > 96
            || !run_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || validator_id == [0; 32]
            || config_sha256 == [0; 32]
            || candidate_source_sha256 == [0; 32]
            || validator_set_id == [0; 32]
        {
            return Err(AuthorityArtifactErrorV1::Invalid("context"));
        }
        Ok(Self {
            run_id: sha256_domain(b"trnm.poco-g3.run-id.v1", &[run_id.as_bytes()]),
            validator_id,
            config_sha256,
            candidate_source_sha256,
            validator_set_id,
        })
    }

    fn digest(self) -> [u8; 32] {
        sha256_domain(
            b"trnm.poco-g3.authority-context.v1",
            &[
                &self.run_id,
                &self.validator_id,
                &self.config_sha256,
                &self.candidate_source_sha256,
                &self.validator_set_id,
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEventV1 {
    pub ordinal: u8,
    pub event_kind: String,
    /// Local monotonic measurement only; never consensus time.
    pub monotonic_ns: u64,
    pub context_digest: String,
    pub block_id: String,
    pub height: u64,
    pub view: u64,
    pub safety_revision: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_checksum: String,
    pub previous_event_checksum: String,
    pub event_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTerminalV1 {
    pub application_head_state_root: String,
    pub application_k_store_sequence: u64,
    pub application_k_row_checksum: String,
    pub safety_record_checksum: String,
    pub safety_chain_checksum: String,
    pub signer_exact_watermark: SignerWatermarkJsonV1,
    pub signer_watermark_unchanged: bool,
    pub checkpoint_canonical_sha256: String,
    pub signing_root: String,
    pub signature_produced: bool,
    pub signature_ready_submitted: bool,
    pub broadcast: bool,
    pub production: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerWatermarkJsonV1 {
    pub scope: String,
    pub journal_id: String,
    pub sequence: u64,
    pub chain_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityArtifactV1 {
    pub schema: String,
    pub profile: String,
    pub context_digest: String,
    pub run_id_sha256: String,
    pub validator_id: String,
    pub config_sha256: String,
    pub candidate_source_sha256: String,
    pub validator_set_id: String,
    pub events: Vec<AuthorityEventV1>,
    pub terminal: AuthorityTerminalV1,
    pub artifact_checksum: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositiveCheckpointBootstrapAssessmentV1 {
    pub authenticated_h1_safety_and_application_closure_available: bool,
    pub generic_core_authority_released: bool,
    pub durable_application_head_released: bool,
    pub operational_signer_owner_released: bool,
    pub whole_node_checkpoint_commissioned: bool,
    pub ordinary_runtime_ready: bool,
}

/// Machine-readable status of the deployed zero-Comet fresh commissioning
/// route. The closed h1->h2->h3 material is authenticated before the Node
/// takeover releases one specialized ordinary-runtime owner; none of these
/// booleans is evidence that a multihost process has actually run.
pub const fn positive_checkpoint_bootstrap_assessment_v1() -> PositiveCheckpointBootstrapAssessmentV1
{
    PositiveCheckpointBootstrapAssessmentV1 {
        authenticated_h1_safety_and_application_closure_available: true,
        generic_core_authority_released: true,
        durable_application_head_released: true,
        operational_signer_owner_released: true,
        whole_node_checkpoint_commissioned: true,
        ordinary_runtime_ready: true,
    }
}

impl AuthorityArtifactV1 {
    pub fn from_inert_facts(
        context: AuthorityArtifactContextV1,
        signer_watermark_before: SignerWatermarkV0,
        facts: &PocoNodeLabInertRequestFactsV0,
    ) -> Result<Self, AuthorityArtifactErrorV1> {
        let checkpoint = facts.checkpoint();
        let fields = checkpoint.fields();
        if signer_watermark_before != facts.signer_exact_watermark()
            || fields.signer_exact_watermark != facts.signer_exact_watermark()
            || fields.application_committed_head_row_checksum != facts.application_row_checksum()
            || fields.safety_revision != facts.authorizing_safety_revision()
            || fields.safety_state_record_checksum != facts.safety_record_checksum()
            || fields.safety_record_chain_checksum != facts.safety_chain_checksum()
        {
            return Err(AuthorityArtifactErrorV1::Invalid("terminal authority join"));
        }
        let context_digest = context.digest();
        let checkpoint_bytes = checkpoint.encode_canonical();
        let checkpoint_digest: [u8; 32] = Sha256::digest(checkpoint_bytes).into();
        let elapsed = facts.stage_elapsed_ns();
        let safety_revisions = facts.stage_safety_revisions();
        let checkpoint_generations = facts.stage_checkpoint_generations();
        let checkpoint_checksums = facts.stage_checkpoint_checksums();
        if elapsed.windows(2).any(|window| window[0] > window[1]) {
            return Err(AuthorityArtifactErrorV1::Invalid(
                "non-monotonic local measurements",
            ));
        }
        let mut previous = [0u8; 32];
        let mut events = Vec::with_capacity(EVENT_KINDS.len());
        for (index, kind) in EVENT_KINDS.iter().enumerate() {
            let ordinal = u8::try_from(index + 1)
                .map_err(|_| AuthorityArtifactErrorV1::Invalid("event ordinal"))?;
            let mut event = AuthorityEventV1 {
                ordinal,
                event_kind: (*kind).to_owned(),
                monotonic_ns: elapsed[index],
                context_digest: hex::encode(context_digest),
                block_id: hex::encode(facts.block_id().as_bytes()),
                height: facts.height(),
                view: facts.view().get(),
                safety_revision: safety_revisions[index],
                checkpoint_generation: checkpoint_generations[index],
                checkpoint_checksum: hex::encode(checkpoint_checksums[index]),
                previous_event_checksum: hex::encode(previous),
                event_checksum: String::new(),
            };
            let event_checksum = event_checksum_fields(
                context_digest,
                &event,
                previous,
                *facts.block_id().as_bytes(),
                checkpoint_checksums[index],
            );
            event.event_checksum = hex::encode(event_checksum);
            events.push(event);
            previous = event_checksum;
        }
        let watermark = facts.signer_exact_watermark();
        let terminal = AuthorityTerminalV1 {
            application_head_state_root: hex::encode(fields.application_state_root.as_bytes()),
            application_k_store_sequence: facts.application_store_sequence(),
            application_k_row_checksum: hex::encode(facts.application_row_checksum()),
            safety_record_checksum: hex::encode(facts.safety_record_checksum()),
            safety_chain_checksum: hex::encode(facts.safety_chain_checksum()),
            signer_exact_watermark: SignerWatermarkJsonV1 {
                scope: hex::encode(watermark.scope()),
                journal_id: hex::encode(watermark.journal_id()),
                sequence: watermark.sequence(),
                chain_checksum: hex::encode(watermark.chain_checksum()),
            },
            signer_watermark_unchanged: true,
            checkpoint_canonical_sha256: hex::encode(checkpoint_digest),
            signing_root: hex::encode(facts.signing_root()),
            signature_produced: false,
            signature_ready_submitted: false,
            broadcast: false,
            production: false,
        };
        let mut artifact = Self {
            schema: SCHEMA.to_owned(),
            profile: PROFILE.to_owned(),
            context_digest: hex::encode(context_digest),
            run_id_sha256: hex::encode(context.run_id),
            validator_id: hex::encode(context.validator_id),
            config_sha256: hex::encode(context.config_sha256),
            candidate_source_sha256: hex::encode(context.candidate_source_sha256),
            validator_set_id: hex::encode(context.validator_set_id),
            events,
            terminal,
            artifact_checksum: String::new(),
        };
        artifact.artifact_checksum = hex::encode(artifact.compute_checksum()?);
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityArtifactErrorV1> {
        self.validate()?;
        serde_json::to_vec(self).map_err(AuthorityArtifactErrorV1::Json)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, AuthorityArtifactErrorV1> {
        if bytes.is_empty()
            || u64::try_from(bytes.len())
                .ok()
                .is_none_or(|size| size > MAX_ARTIFACT_BYTES)
            || bytes.last() == Some(&b'\n')
        {
            return Err(AuthorityArtifactErrorV1::Invalid("JSON envelope"));
        }
        let value: Self = serde_json::from_slice(bytes).map_err(AuthorityArtifactErrorV1::Json)?;
        value.validate()?;
        if serde_json::to_vec(&value).map_err(AuthorityArtifactErrorV1::Json)? != bytes {
            return Err(AuthorityArtifactErrorV1::Invalid("non-canonical JSON"));
        }
        Ok(value)
    }

    /// Creates one new `0600` artifact, fsyncs it and its parent directory,
    /// then reopens it through the strict reader. Existing paths are never
    /// replaced or normalized.
    pub fn write_new_exact(&self, path: &Path) -> Result<(), AuthorityArtifactErrorV1> {
        let bytes = self.to_canonical_json()?;
        let (path, parent) = canonical_artifact_target(path)?;
        let directory = File::open(&parent).map_err(AuthorityArtifactErrorV1::Io)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(AuthorityArtifactErrorV1::Io)?;
        let write_result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            directory.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&path);
            return Err(AuthorityArtifactErrorV1::Io(error));
        }
        if Self::read_exact(&path)? != *self {
            return Err(AuthorityArtifactErrorV1::Invalid("artifact readback"));
        }
        Ok(())
    }

    /// Reads one manifest-independent local artifact from a pinned regular
    /// file. This authenticates file shape and the internal hash chain, not
    /// the validator identity; a later signed run report must bind this digest.
    pub fn read_exact(path: &Path) -> Result<Self, AuthorityArtifactErrorV1> {
        let (path, parent) = canonical_artifact_target(path)?;
        let before = fs::symlink_metadata(&path).map_err(AuthorityArtifactErrorV1::Io)?;
        let parent_metadata = fs::metadata(&parent).map_err(AuthorityArtifactErrorV1::Io)?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.permissions().mode() & 0o777 != 0o600
            || before.nlink() != 1
            || before.uid() != parent_metadata.uid()
            || before.len() == 0
            || before.len() > MAX_ARTIFACT_BYTES
        {
            return Err(AuthorityArtifactErrorV1::Invalid("artifact file"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(AuthorityArtifactErrorV1::Io)?;
        let opened = file.metadata().map_err(AuthorityArtifactErrorV1::Io)?;
        if opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.len() != before.len()
            || opened.nlink() != 1
            || opened.uid() != before.uid()
        {
            return Err(AuthorityArtifactErrorV1::Invalid("artifact file identity"));
        }
        let capacity = usize::try_from(before.len())
            .map_err(|_| AuthorityArtifactErrorV1::Invalid("artifact length"))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(AuthorityArtifactErrorV1::Io)?;
        let after = fs::symlink_metadata(&path).map_err(AuthorityArtifactErrorV1::Io)?;
        if bytes.len() != capacity
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || after.len() != opened.len()
            || after.nlink() != 1
        {
            return Err(AuthorityArtifactErrorV1::Invalid(
                "artifact changed while read",
            ));
        }
        Self::from_canonical_json(&bytes)
    }

    pub fn validate(&self) -> Result<(), AuthorityArtifactErrorV1> {
        if self.schema != SCHEMA
            || self.profile != PROFILE
            || self.events.len() != EVENT_KINDS.len()
            || self.terminal.signature_produced
            || self.terminal.signature_ready_submitted
            || self.terminal.broadcast
            || self.terminal.production
            || !self.terminal.signer_watermark_unchanged
        {
            return Err(AuthorityArtifactErrorV1::Invalid("profile"));
        }
        let context_digest = decode32(&self.context_digest)?;
        let run_id_sha256 = decode32(&self.run_id_sha256)?;
        let validator_id = decode_nonzero32(&self.validator_id)?;
        let config_sha256 = decode_nonzero32(&self.config_sha256)?;
        let candidate_source_sha256 = decode_nonzero32(&self.candidate_source_sha256)?;
        let validator_set_id = decode_nonzero32(&self.validator_set_id)?;
        if context_digest
            != sha256_domain(
                b"trnm.poco-g3.authority-context.v1",
                &[
                    &run_id_sha256,
                    &validator_id,
                    &config_sha256,
                    &candidate_source_sha256,
                    &validator_set_id,
                ],
            )
        {
            return Err(AuthorityArtifactErrorV1::Invalid("context digest"));
        }
        let block_id = decode32(&self.events[0].block_id)?;
        let mut previous = [0u8; 32];
        let mut prior_ns = 0;
        for (index, event) in self.events.iter().enumerate() {
            let ordinal = u8::try_from(index + 1)
                .map_err(|_| AuthorityArtifactErrorV1::Invalid("event ordinal"))?;
            if event.ordinal != ordinal
                || event.event_kind != EVENT_KINDS[index]
                || decode32(&event.context_digest)? != context_digest
                || decode32(&event.block_id)? != block_id
                || decode32(&event.previous_event_checksum)? != previous
                || (index > 0 && event.monotonic_ns < prior_ns)
                || event.height != self.events[0].height
                || event.view != self.events[0].view
            {
                return Err(AuthorityArtifactErrorV1::Invalid("event inventory"));
            }
            let checkpoint_checksum = decode_nonzero32(&event.checkpoint_checksum)?;
            let actual = decode32(&event.event_checksum)?;
            let expected = event_checksum_fields(
                context_digest,
                event,
                previous,
                block_id,
                checkpoint_checksum,
            );
            if actual != expected {
                return Err(AuthorityArtifactErrorV1::Invalid("event checksum"));
            }
            previous = actual;
            prior_ns = event.monotonic_ns;
        }
        self.validate_stage_profile()?;
        decode_nonzero32(&self.terminal.application_head_state_root)?;
        if self.terminal.application_k_store_sequence == 0 {
            return Err(AuthorityArtifactErrorV1::Invalid(
                "application K store sequence",
            ));
        }
        decode_nonzero32(&self.terminal.application_k_row_checksum)?;
        decode_nonzero32(&self.terminal.safety_record_checksum)?;
        decode_nonzero32(&self.terminal.safety_chain_checksum)?;
        decode_nonzero32(&self.terminal.signer_exact_watermark.scope)?;
        decode_nonzero32(&self.terminal.signer_exact_watermark.journal_id)?;
        decode_nonzero32(&self.terminal.signer_exact_watermark.chain_checksum)?;
        decode_nonzero32(&self.terminal.checkpoint_canonical_sha256)?;
        decode_nonzero32(&self.terminal.signing_root)?;
        if decode32(&self.artifact_checksum)? != self.compute_checksum()? {
            return Err(AuthorityArtifactErrorV1::Invalid("artifact checksum"));
        }
        Ok(())
    }

    fn validate_stage_profile(&self) -> Result<(), AuthorityArtifactErrorV1> {
        let safety = self
            .events
            .iter()
            .map(|event| event.safety_revision)
            .collect::<Vec<_>>();
        let generations = self
            .events
            .iter()
            .map(|event| event.checkpoint_generation)
            .collect::<Vec<_>>();
        let checksums = self
            .events
            .iter()
            .map(|event| decode_nonzero32(&event.checkpoint_checksum))
            .collect::<Result<Vec<_>, _>>()?;
        if safety[0] != safety[1]
            || safety[0].checked_add(1) != Some(safety[2])
            || safety[2] != safety[3]
            || safety[2] != safety[4]
            || safety[4].checked_add(1) != Some(safety[5])
            || safety[5..].iter().any(|revision| *revision != safety[5])
            || generations[..7]
                .iter()
                .any(|generation| *generation != generations[0])
            || generations[0].checked_add(1) != Some(generations[7])
            || generations[8] != generations[7]
            || checksums[..7]
                .iter()
                .any(|checksum| *checksum != checksums[0])
            || checksums[7] == checksums[0]
            || checksums[8] != checksums[7]
        {
            return Err(AuthorityArtifactErrorV1::Invalid("stage profile"));
        }
        Ok(())
    }

    fn compute_checksum(&self) -> Result<[u8; 32], AuthorityArtifactErrorV1> {
        let mut copy = self.clone();
        copy.artifact_checksum.clear();
        let bytes = serde_json::to_vec(&copy).map_err(AuthorityArtifactErrorV1::Json)?;
        Ok(sha256_domain(ARTIFACT_DOMAIN, &[&bytes]))
    }
}

fn event_checksum_fields(
    context_digest: [u8; 32],
    event: &AuthorityEventV1,
    previous: [u8; 32],
    block_id: [u8; 32],
    checkpoint_checksum: [u8; 32],
) -> [u8; 32] {
    sha256_domain(
        CHAIN_DOMAIN,
        &[
            &context_digest,
            &[event.ordinal],
            event.event_kind.as_bytes(),
            &event.monotonic_ns.to_be_bytes(),
            &block_id,
            &event.height.to_be_bytes(),
            &event.view.to_be_bytes(),
            &event.safety_revision.to_be_bytes(),
            &event.checkpoint_generation.to_be_bytes(),
            &checkpoint_checksum,
            &previous,
        ],
    )
}

fn sha256_domain(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn decode32(value: &str) -> Result<[u8; 32], AuthorityArtifactErrorV1> {
    let bytes = hex::decode(value).map_err(|_| AuthorityArtifactErrorV1::Invalid("hex32"))?;
    bytes
        .try_into()
        .map_err(|_| AuthorityArtifactErrorV1::Invalid("hex32"))
}

fn decode_nonzero32(value: &str) -> Result<[u8; 32], AuthorityArtifactErrorV1> {
    let value = decode32(value)?;
    if value == [0; 32] {
        return Err(AuthorityArtifactErrorV1::Invalid("zero hex32"));
    }
    Ok(value)
}

fn canonical_artifact_target(
    supplied: &Path,
) -> Result<(PathBuf, PathBuf), AuthorityArtifactErrorV1> {
    if !supplied.is_absolute() || supplied.file_name().is_none() {
        return Err(AuthorityArtifactErrorV1::Invalid("artifact path"));
    }
    let parent = supplied
        .parent()
        .ok_or(AuthorityArtifactErrorV1::Invalid("artifact parent"))?;
    let canonical_parent = fs::canonicalize(parent).map_err(AuthorityArtifactErrorV1::Io)?;
    if parent != canonical_parent {
        return Err(AuthorityArtifactErrorV1::Invalid("artifact parent alias"));
    }
    let metadata = fs::symlink_metadata(&canonical_parent).map_err(AuthorityArtifactErrorV1::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(AuthorityArtifactErrorV1::Invalid(
            "artifact parent permissions",
        ));
    }
    Ok((
        canonical_parent.join(
            supplied
                .file_name()
                .ok_or(AuthorityArtifactErrorV1::Invalid("artifact path"))?,
        ),
        canonical_parent,
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{
        decode32, event_checksum_fields, sha256_domain, AuthorityArtifactV1, AuthorityEventV1,
        AuthorityTerminalV1, SignerWatermarkJsonV1, EVENT_KINDS, PROFILE, SCHEMA,
    };

    fn fixture() -> AuthorityArtifactV1 {
        let run_id = [4u8; 32];
        let validator = [5u8; 32];
        let config = [6u8; 32];
        let source = [7u8; 32];
        let set = [8u8; 32];
        let context = sha256_domain(
            b"trnm.poco-g3.authority-context.v1",
            &[&run_id, &validator, &config, &source, &set],
        );
        let block = [2u8; 32];
        let mut previous = [0u8; 32];
        let mut events = Vec::new();
        for (index, kind) in EVENT_KINDS.iter().enumerate() {
            let safety_revision = match index {
                0 | 1 => 9,
                2..=4 => 10,
                _ => 11,
            };
            let checkpoint_generation = if index < 7 { 4 } else { 5 };
            let checkpoint = if index < 7 { [3u8; 32] } else { [18u8; 32] };
            let mut event = AuthorityEventV1 {
                ordinal: u8::try_from(index + 1).unwrap(),
                event_kind: (*kind).to_owned(),
                monotonic_ns: u64::try_from(index).unwrap() * 10,
                context_digest: hex::encode(context),
                block_id: hex::encode(block),
                height: 7,
                view: 9,
                safety_revision,
                checkpoint_generation,
                checkpoint_checksum: hex::encode(checkpoint),
                previous_event_checksum: hex::encode(previous),
                event_checksum: String::new(),
            };
            let checksum = event_checksum_fields(context, &event, previous, block, checkpoint);
            event.event_checksum = hex::encode(checksum);
            previous = checksum;
            events.push(event);
        }
        let mut artifact = AuthorityArtifactV1 {
            schema: SCHEMA.to_owned(),
            profile: PROFILE.to_owned(),
            context_digest: hex::encode(context),
            run_id_sha256: hex::encode(run_id),
            validator_id: hex::encode(validator),
            config_sha256: hex::encode(config),
            candidate_source_sha256: hex::encode(source),
            validator_set_id: hex::encode(set),
            events,
            terminal: AuthorityTerminalV1 {
                application_head_state_root: hex::encode([9; 32]),
                application_k_store_sequence: 3,
                application_k_row_checksum: hex::encode([10; 32]),
                safety_record_checksum: hex::encode([11; 32]),
                safety_chain_checksum: hex::encode([12; 32]),
                signer_exact_watermark: SignerWatermarkJsonV1 {
                    scope: hex::encode([13; 32]),
                    journal_id: hex::encode([14; 32]),
                    sequence: 0,
                    chain_checksum: hex::encode([15; 32]),
                },
                signer_watermark_unchanged: true,
                checkpoint_canonical_sha256: hex::encode([16; 32]),
                signing_root: hex::encode([17; 32]),
                signature_produced: false,
                signature_ready_submitted: false,
                broadcast: false,
                production: false,
            },
            artifact_checksum: String::new(),
        };
        artifact.artifact_checksum = hex::encode(artifact.compute_checksum().unwrap());
        artifact
    }

    #[test]
    fn canonical_codec_round_trips_exactly() {
        let artifact = fixture();
        artifact.validate().unwrap();
        let bytes = artifact.to_canonical_json().unwrap();
        assert_eq!(
            AuthorityArtifactV1::from_canonical_json(&bytes).unwrap(),
            artifact
        );
    }

    #[test]
    fn every_authority_mutant_fails_closed() {
        let original = fixture();
        let mut mutants = Vec::new();
        let mut value = original.clone();
        value.schema.push('x');
        mutants.push(value);
        let mut value = original.clone();
        value.events.swap(4, 5);
        mutants.push(value);
        let mut value = original.clone();
        value.events[5].monotonic_ns = 1;
        mutants.push(value);
        let mut value = original.clone();
        value.events[6].block_id = hex::encode([99; 32]);
        mutants.push(value);
        let mut value = original.clone();
        value.events[8].event_checksum = hex::encode([98; 32]);
        mutants.push(value);
        let mut value = original.clone();
        value.terminal.signature_produced = true;
        mutants.push(value);
        let mut value = original.clone();
        value.terminal.broadcast = true;
        mutants.push(value);
        let mut value = original.clone();
        value.terminal.application_k_row_checksum = "00".to_owned();
        mutants.push(value);
        let mut value = original.clone();
        value.context_digest = hex::encode([97; 32]);
        mutants.push(value);
        let mut value = original.clone();
        value.artifact_checksum = hex::encode([96; 32]);
        mutants.push(value);
        for mutant in mutants {
            assert!(mutant.validate().is_err());
        }
    }

    #[test]
    fn decoder_rejects_unknown_trailing_and_noncanonical_input() {
        let bytes = fixture().to_canonical_json().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(b'\n');
        assert!(AuthorityArtifactV1::from_canonical_json(&trailing).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(
            AuthorityArtifactV1::from_canonical_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        assert_eq!(decode32(&hex::encode([1; 32])).unwrap(), [1; 32]);
    }

    #[test]
    fn file_writer_reader_are_create_only_pinned_and_alias_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut permissions = std::fs::metadata(directory.path()).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(directory.path(), permissions).unwrap();
        let path = directory.path().join("authority.json");
        let artifact = fixture();
        artifact.write_new_exact(&path).unwrap();
        assert_eq!(AuthorityArtifactV1::read_exact(&path).unwrap(), artifact);
        assert!(artifact.write_new_exact(&path).is_err());

        let hard_link = directory.path().join("authority-hardlink.json");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(AuthorityArtifactV1::read_exact(&path).is_err());
        assert!(AuthorityArtifactV1::read_exact(&hard_link).is_err());
        std::fs::remove_file(&hard_link).unwrap();

        let symlink = directory.path().join("authority-symlink.json");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(AuthorityArtifactV1::read_exact(&symlink).is_err());
    }
}

#[derive(Debug)]
pub enum AuthorityArtifactErrorV1 {
    Invalid(&'static str),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl fmt::Display for AuthorityArtifactErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "invalid authority artifact: {field}"),
            Self::Json(error) => write!(formatter, "authority artifact JSON: {error}"),
            Self::Io(error) => write!(formatter, "authority artifact I/O: {error}"),
        }
    }
}

impl Error for AuthorityArtifactErrorV1 {}
