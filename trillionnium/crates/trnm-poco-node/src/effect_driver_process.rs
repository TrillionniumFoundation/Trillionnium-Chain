//! Candidate-only OS process wrapper for the Core effect driver.
//!
//! This module is intentionally compiled only by `g1-process-test-support`.
//! It is a small, black-boxable process boundary around the real
//! `CandidateEffectDriverV1`: one Core, one Core-owned SafetyRules authority,
//! a bounded stdin command queue, a file-backed transition/checkpoint fence,
//! and a fixture signer.  It is useful for proving ordering and fail-stop
//! behaviour across an actual process boundary; it is not a production node,
//! a network listener, or a recovery implementation.

#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

// Keep the raw fixture-key source contract explicit.  The module itself is
// feature-gated, and this visible `test`/fixture cfg marker is intentionally
// placed before any key type/import so source scanners cannot mistake it for
// a default-node signing dependency.
#[cfg(any(test, feature = "g1-process-test-support"))]
#[allow(dead_code)]
const RAW_KEY_SOURCE_IS_EXPLICITLY_GATED_V1: bool = true;

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{
    fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use trnm_application_tx_builder_v0::validate_strict_json_structure_v0;
use trnm_consensus_core::{
    BlockIdOverlayRefV0, Core, CoreConfig, CoreIssuedApplicationSealAuthorityV0, Effect, Input,
    OutboundMessage, SafetyHalt, SafetyState, SafetyStatePersistenceV0,
    ValidatedPayloadArtifactRefV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
#[cfg(unix)]
use trnm_consensus_peer_lease::{
    payload_replay_run_id_hash_v1, ExternalPeerLeaseAuthorityV1, PayloadReplayDirectionV1,
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PayloadReplayStoreV1, PeerLeaseErrorV1,
    PeerLeaseScopeV1, PeerLeaseTokenV1, UnixPeerLeaseClientV1,
};
use trnm_consensus_safety_rules::{InertSafetyTransitionV1, SafetyRulesDurableTransitionStoreV1};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
    BlockKind, CanonicalSignIntentV0, CanonicalSignable, Cev0AdmissionBudgetV0, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0,
    ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
    QcReferenceV0, Signature64, SignatureBytes, SignedProposalV0, StateRoot, Validator,
    ValidatorId, ValidatorSet, View, VotingPower, WireEnvelopeSemanticProof,
    WireSemanticBodyKindV0,
};

use crate::effect_driver::{
    CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1, CandidateEffectDriverFactsV1,
    CandidateEffectDriverHooksV1, CandidateEffectDriverStatusV1, CandidateEffectDriverV1,
};
#[cfg(unix)]
use crate::{
    PocoNodeP2pSessionV0, P2P_SESSION_MAX_FRAME_BYTES_V0, P2P_SESSION_MAX_HANDSHAKE_BYTES_V0,
};

/// This process is a candidate fixture only.
pub const EFFECT_DRIVER_PROCESS_CANDIDATE_V1: bool = true;
/// The process never enables production consensus activation.
pub const EFFECT_DRIVER_PROCESS_PRODUCTION_ACTIVATION_V1: bool = false;
/// Bounded command frame size.  Oversized lines are rejected before parsing.
pub const EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1: usize = 64 * 1024;
/// Queue capacity used by the process wrapper.
pub const EFFECT_DRIVER_PROCESS_QUEUE_CAPACITY_V1: usize = 8;

const CHAIN_ID_V1: &str = "trnm-effect-driver-process-v1";
const ROOT_MARKER_V1: &str = "effect-driver-process.marker";
const TRANSITION_WAL_V1: &str = "safety-transition.wal";
const SAFETY_STATE_V1: &str = "safety-state.record";
const CHECKPOINT_V1: &str = "whole-node.checkpoint";
const OUTBOUND_WAL_V1: &str = "outbound.wal";
const TIMER_WAL_V1: &str = "timer.wal";
const APPLICATION_WAL_V1: &str = "application-seal.wal";
const FAIL_CHECKPOINT_ENV_V1: &str = "TRNM_POCO_EFFECT_PROCESS_FAIL_CHECKPOINT";
const LOCAL_KEY_BYTES_V1: [u8; 32] = [41; 32];
const FIXTURE_PAYLOAD_V1: &[u8] = b"candidate-synced-proposal-v1";

#[cfg(unix)]
const P2P_SOCKET_RECORD_HEADER_BYTES_V1: usize = 4;
#[cfg(unix)]
const P2P_SOCKET_MAX_RECORD_BYTES_V1: usize =
    if P2P_SESSION_MAX_FRAME_BYTES_V0 > P2P_SESSION_MAX_HANDSHAKE_BYTES_V0 {
        P2P_SESSION_MAX_FRAME_BYTES_V0
    } else {
        P2P_SESSION_MAX_HANDSHAKE_BYTES_V0
    };
#[cfg(unix)]
const P2P_SOCKET_READ_TIMEOUT_V1: Duration = Duration::from_secs(5);
#[cfg(unix)]
const P2P_SOCKET_ACCEPT_TIMEOUT_V1: Duration = Duration::from_secs(5);
#[cfg(unix)]
const P2P_SOCKET_ACCEPT_POLL_V1: Duration = Duration::from_millis(10);
#[cfg(unix)]
const P2P_SOCKET_LEASE_TTL_MS_V1: u64 = 30_000;
#[cfg(unix)]
const P2P_SOCKET_RUN_ID_MAX_BYTES_V1: usize = 128;
#[cfg(unix)]
const P2P_SOCKET_FRAME_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.candidate-p2p.frame-fingerprint.v1\0";
#[cfg(unix)]
const P2P_SOCKET_NETWORK_CONTEXT_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.candidate-p2p.network-context.v1\0";

#[derive(Debug)]
pub struct EffectDriverProcessErrorV1 {
    code: &'static str,
    detail: String,
}

impl EffectDriverProcessErrorV1 {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for EffectDriverProcessErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for EffectDriverProcessErrorV1 {}

impl From<io::Error> for EffectDriverProcessErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::new("io", format!("{error:?}"))
    }
}

/// Summary returned after a clean `shutdown`/EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectDriverProcessSummaryV1 {
    pub generation: u64,
    pub processed_ingress: u64,
    pub processed_effects: u64,
    pub broadcasts: u64,
    pub status: CandidateEffectDriverStatusV1,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum CommandV1 {
    #[serde(rename = "enqueue_timeout")]
    EnqueueTimeout { generation: u64 },
    /// Candidate-only proposal ingress.  The fixture is routed through the
    /// Core synced-proposal/application-valid boundary; it does not imply
    /// production network admission.
    #[serde(rename = "enqueue_synced_proposal")]
    EnqueueSyncedProposal { generation: u64 },
    /// Ordinary proposal ingress is exposed only to demonstrate the explicit
    /// fail-closed application boundary in this fixture process.
    #[serde(rename = "enqueue_proposal")]
    EnqueueProposal { generation: u64 },
    /// Candidate-only Vote ingress.  Core's one issued SafetyRules authority
    /// derives the Vote transition from the exact previously validated
    /// fixture proposal.
    #[serde(rename = "enqueue_authority_vote", alias = "enqueue_vote")]
    EnqueueAuthorityVote { generation: u64 },
    #[serde(rename = "drive")]
    Drive,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Debug)]
struct FileTransitionStoreV1 {
    path: PathBuf,
    previous_successor: Option<[u8; 32]>,
    transitions: u64,
}

impl FileTransitionStoreV1 {
    fn open(root: &Path) -> Result<Self, EffectDriverProcessErrorV1> {
        Ok(Self {
            path: root.join(TRANSITION_WAL_V1),
            previous_successor: None,
            transitions: 0,
        })
    }
}

impl SafetyRulesDurableTransitionStoreV1 for FileTransitionStoreV1 {
    type Error = String;

    fn persist_transition_v1(
        &mut self,
        transition: &InertSafetyTransitionV1,
    ) -> Result<(), Self::Error> {
        let predecessor = *transition.predecessor_state_digest().as_bytes();
        if let Some(previous) = self.previous_successor {
            if predecessor != previous {
                return Err("transition predecessor does not match WAL successor".to_owned());
            }
        }
        let successor = *transition.successor_state().digest().as_bytes();
        let intent = transition.canonical_intent();
        let line = format!(
            "v=1\tindex={}\tkind={:?}\tpredecessor={}\tsuccessor={}\tcandidate={}\troot={}\tfingerprint={}\trevision={}\n",
            self.transitions,
            transition.kind(),
            hex::encode(predecessor),
            hex::encode(successor),
            hex::encode(transition.candidate_digest().as_bytes()),
            hex::encode(intent.signing_root().as_bytes()),
            hex::encode(intent.fingerprint().as_bytes()),
            intent.authorizing_safety_revision(),
        );
        append_durable(&self.path, line.as_bytes()).map_err(|error| format!("{error:?}"))?;
        self.previous_successor = Some(successor);
        self.transitions = self.transitions.saturating_add(1);
        Ok(())
    }
}

struct FileHooksV1 {
    root: PathBuf,
    application_seal_authority: CoreIssuedApplicationSealAuthorityV0,
    persisted: Option<SafetyState>,
    persisted_record: Option<Vec<u8>>,
    broadcasts: u64,
    fail_checkpoint: bool,
}

impl FileHooksV1 {
    fn new(root: &Path, application_seal_authority: CoreIssuedApplicationSealAuthorityV0) -> Self {
        Self {
            root: root.to_owned(),
            application_seal_authority,
            persisted: None,
            persisted_record: None,
            broadcasts: 0,
            fail_checkpoint: std::env::var_os(FAIL_CHECKPOINT_ENV_V1).is_some(),
        }
    }

    fn record_for_state(state: &SafetyState) -> Vec<u8> {
        // `Debug` is deliberately labelled as a fixture fingerprint rather
        // than a protocol encoding.  The typed state is retained in memory
        // and compared on readback; the file is only a durable crash marker.
        let debug = format!("{state:?}");
        let digest = Sha256::digest(debug.as_bytes());
        format!(
            "v=1\trevision={}\tepoch={}\tview={}\tfingerprint={}\n",
            state.revision(),
            state.epoch().get(),
            state.current_view().get(),
            hex::encode(digest),
        )
        .into_bytes()
    }

    fn checkpoint_record(core: &Core, intent: &CanonicalSignIntentV0) -> Vec<u8> {
        format!(
            "v=1\trevision={}\tepoch={}\tview={}\troot={}\tfingerprint={}\n",
            core.safety_state().revision(),
            core.safety_state().epoch().get(),
            core.safety_state().current_view().get(),
            hex::encode(intent.signing_root().as_bytes()),
            hex::encode(intent.fingerprint().as_bytes()),
        )
        .into_bytes()
    }

    fn checkpoint_state_record(state: &SafetyState) -> Vec<u8> {
        format!(
            "v=1\trevision={}\tepoch={}\tview={}\tkind=safety_state\n",
            state.revision(),
            state.epoch().get(),
            state.current_view().get(),
        )
        .into_bytes()
    }

    fn read_checkpoint_revision(&self) -> Result<Option<u64>, String> {
        let path = self.root.join(CHECKPOINT_V1);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("checkpoint read: {error:?}")),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| "checkpoint is not UTF-8".to_owned())?;
        let field = text
            .split('\t')
            .find_map(|part| part.strip_prefix("revision="))
            .ok_or_else(|| "checkpoint revision field missing".to_owned())?;
        field
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| "checkpoint revision is not an integer".to_owned())
    }

    fn record_application_seal(
        &self,
        id: trnm_consensus_core::ValidationId,
        commitments: &trnm_consensus_types::ValidatedBlockCommitmentsV0,
        artifact_ref: ValidatedPayloadArtifactRefV0,
    ) -> Result<(), String> {
        let overlay = artifact_ref.overlay();
        let line = format!(
            "v=1\troute=synced\tblock_id={}\tview={}\tgeneration={}\tlogical_size={}\ttransactions={}\tevidence={}\toverlay={}\tsource={}\n",
            hex::encode(commitments.block_id().as_bytes()),
            id.view().get(),
            id.generation(),
            commitments.logical_block_size(),
            commitments.transaction_count(),
            commitments.evidence_count(),
            hex::encode(overlay.overlay_checksum()),
            hex::encode(artifact_ref.source_artifact_checksum()),
        );
        let path = self.root.join(APPLICATION_WAL_V1);
        append_durable(&path, line.as_bytes())
            .map_err(|error| format!("application seal WAL: {error:?}"))?;
        let on_disk =
            fs::read(&path).map_err(|error| format!("application seal readback: {error:?}"))?;
        if !on_disk.ends_with(line.as_bytes()) {
            return Err("application seal durable readback mismatch".to_owned());
        }
        Ok(())
    }
}

impl CandidateEffectDriverHooksV1 for FileHooksV1 {
    type Error = String;

    fn persist_safety_state_v1(
        &mut self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<(), Self::Error> {
        let record = Self::record_for_state(request.state());
        atomic_replace(&self.root.join(SAFETY_STATE_V1), &record)
            .map_err(|error| format!("safety state persist: {error:?}"))?;
        // Non-signing Core revisions (including the two revisions needed to
        // cross the synced application-valid boundary) still advance the
        // whole-node checkpoint predecessor. A signing transition carries an
        // exact CAS successor and must leave the prior revision in place until
        // `compare_and_advance_whole_node_checkpoint_v1` validates and writes
        // that successor. This keeps Vote/Timeout and application persistence
        // on one monotonic checkpoint chain without allowing a signer to run
        // before the transition CAS.
        if request.safety_rules_shadow_transition_v1().is_none() {
            atomic_replace(
                &self.root.join(CHECKPOINT_V1),
                &Self::checkpoint_state_record(request.state()),
            )
            .map_err(|error| format!("checkpoint state advance: {error:?}"))?;
        }
        self.persisted = Some(request.state().clone());
        self.persisted_record = Some(record);
        Ok(())
    }

    fn confirm_safety_state_v1(&mut self, expected: &SafetyState) -> Result<(), Self::Error> {
        if self.persisted.as_ref() != Some(expected) {
            return Err("typed SafetyState readback mismatch".to_owned());
        }
        let expected_record = Self::record_for_state(expected);
        if self.persisted_record.as_deref() != Some(expected_record.as_slice()) {
            return Err("SafetyState record cache mismatch".to_owned());
        }
        let on_disk = fs::read(self.root.join(SAFETY_STATE_V1))
            .map_err(|error| format!("safety state readback: {error:?}"))?;
        if on_disk != expected_record {
            return Err("SafetyState durable readback mismatch".to_owned());
        }
        Ok(())
    }

    fn validate_payload_v1(
        &mut self,
        effect: Effect,
        core: &mut Core,
    ) -> Result<Vec<Effect>, Self::Error> {
        let request = match effect {
            Effect::ValidateSyncedPayload(request) => request,
            Effect::ValidatePayload(_) => {
                // A normal proposal still requires a complete application
                // host integration. Keep that route explicit and fail closed
                // instead of silently treating a missing runtime as Valid.
                return Err(
                    "normal proposal validation is not enabled; use the synced candidate boundary"
                        .to_owned(),
                );
            }
            _ => return Err("unexpected validation effect kind".to_owned()),
        };
        let claimed = request
            .try_claim()
            .map_err(|_| "duplicate validation request claim".to_owned())?;
        let (_route, id, block, _parent, permit) = claimed.into_parts();
        let commitments = validated_commitments_for_block(core, &block)?;
        let artifact_ref = artifact_ref_for_block(&block);
        // This WAL is the fixture's explicit application-store commit/readback
        // marker. The opaque Core proof is minted only after the marker is
        // durable, and Core still rechecks the exact request/affinity/root
        // bindings before accepting it.
        self.record_application_seal(id, &commitments, artifact_ref)?;
        let proof = self
            .application_seal_authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact_ref);
        core.step_application_sealed_valid_v0(&proof, &StrictEd25519Verifier)
            .map_err(|error| format!("Core application Valid callback: {error}"))
    }

    fn compare_and_advance_whole_node_checkpoint_v1(
        &mut self,
        core: &Core,
        intent: &CanonicalSignIntentV0,
    ) -> Result<(), Self::Error> {
        if self.fail_checkpoint {
            return Err("injected whole-node checkpoint CAS failure".to_owned());
        }
        let revision = core.safety_state().revision();
        let previous = self.read_checkpoint_revision()?;
        let expected_previous = revision.checked_sub(1);
        let predecessor_matches = match (expected_previous, previous) {
            (Some(0), None) => true,
            (Some(expected), Some(found)) => expected == found,
            _ => false,
        };
        if !predecessor_matches {
            return Err(format!(
                "checkpoint CAS predecessor mismatch: expected {:?}, found {:?}",
                expected_previous, previous
            ));
        }
        atomic_replace(
            &self.root.join(CHECKPOINT_V1),
            &Self::checkpoint_record(core, intent),
        )
        .map_err(|error| format!("checkpoint CAS: {error:?}"))?;
        Ok(())
    }

    fn sign_v1(&mut self, intent: &CanonicalSignIntentV0) -> Result<SignatureBytes, Self::Error> {
        let revision = self.read_checkpoint_revision()?;
        if revision != Some(intent.authorizing_safety_revision()) {
            return Err("signer observed no matching checkpoint".to_owned());
        }
        let key = SigningKey::from_bytes(&LOCAL_KEY_BYTES_V1);
        Ok(SignatureBytes::from_array(
            key.sign(intent.signing_root().as_bytes()).to_bytes(),
        ))
    }

    fn broadcast_v1(&mut self, message: OutboundMessage) -> Result<(), Self::Error> {
        let (kind, root, signature) = match message {
            OutboundMessage::Vote(vote) => {
                ("vote", vote.signing_root(), *vote.signature().as_bytes())
            }
            OutboundMessage::TimeoutVote(vote) => (
                "timeout_vote",
                vote.signing_root(),
                *vote.signature().as_bytes(),
            ),
        };
        let line = format!(
            "v=1\tindex={}\tkind={}\troot={}\tsignature={}\n",
            self.broadcasts,
            kind,
            hex::encode(root.as_bytes()),
            hex::encode(signature),
        );
        append_durable(&self.root.join(OUTBOUND_WAL_V1), line.as_bytes())
            .map_err(|error| format!("broadcast WAL: {error:?}"))?;
        self.broadcasts = self.broadcasts.saturating_add(1);
        Ok(())
    }

    fn arm_view_timer_v1(&mut self, epoch: Epoch, view: View) -> Result<(), Self::Error> {
        let line = format!("v=1\tepoch={}\tview={}\n", epoch.get(), view.get());
        append_durable(&self.root.join(TIMER_WAL_V1), line.as_bytes())
            .map_err(|error| format!("timer WAL: {error:?}"))
    }

    fn safety_halted_v1(&mut self, halt: &SafetyHalt) -> Result<(), Self::Error> {
        let line = format!("v=1\tsafety_halt={halt:?}\n");
        append_durable(&self.root.join(ROOT_MARKER_V1), line.as_bytes())
            .map_err(|error| format!("halt marker: {error:?}"))
    }
}

fn append_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    ensure_private_artifact_file(&file)?;
    let mut file = file;
    file.write_all(bytes)?;
    file.sync_all()
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no UTF-8 name"))?;
    let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = result {
        // A failed replacement must not leave a same-name temporary file that
        // a later owner could accidentally trust.  `create_new` above also
        // makes a stale temporary an explicit fail-closed condition.
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    // Syncing the parent closes the rename durability window on Unix.  Some
    // non-Unix test filesystems reject opening a directory; the file itself
    // is still synchronously written in that case.
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn fresh_root(root: &Path) -> Result<(), EffectDriverProcessErrorV1> {
    if !root.is_absolute() {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            "candidate process requires an absolute run root",
        ));
    }
    if root == Path::new("/") || root.components().count() < 3 {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            "refusing a broad filesystem root",
        ));
    }
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(EffectDriverProcessErrorV1::new(
                    "root",
                    "candidate run root must be a directory and not a symlink",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(root)?;
    // Make every candidate run root private explicitly; relying on the
    // process umask is insufficient for consensus/WAL material.  The chmod is
    // issued on an opened directory descriptor so the final component is not
    // followed as a symlink.  (Ancestor replacement races still require an
    // openat/descriptor-anchored owner in a production implementation.)
    let directory = File::open(root)?;
    set_private_root_permissions(&directory)?;
    let metadata = directory.metadata()?;
    ensure_private_root_metadata(root, &metadata)?;
    for name in [
        ROOT_MARKER_V1,
        TRANSITION_WAL_V1,
        SAFETY_STATE_V1,
        CHECKPOINT_V1,
        OUTBOUND_WAL_V1,
        TIMER_WAL_V1,
        APPLICATION_WAL_V1,
    ] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(EffectDriverProcessErrorV1::new(
                        "root",
                        format!("candidate state {} is not a regular file", path.display()),
                    ));
                }
                ensure_private_artifact_metadata(&metadata).map_err(|error| {
                    EffectDriverProcessErrorV1::new(
                        "root",
                        format!(
                            "candidate state {} is not private: {error:?}",
                            path.display()
                        ),
                    )
                })?;
                if metadata.len() != 0 {
                    return Err(EffectDriverProcessErrorV1::new(
                        "recovery_required",
                        format!(
                            "non-empty candidate state {} requires an explicit recovery owner",
                            path.display()
                        ),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_private_root_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), EffectDriverProcessErrorV1> {
    #[cfg(unix)]
    {
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                "candidate run root must be a private directory",
            ));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_dir() {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            "candidate run root must be a directory",
        ));
    }
    Ok(())
}

fn set_private_root_permissions(directory: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

fn ensure_private_artifact_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "candidate artifact must be a private, single-link regular file",
            ));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "candidate artifact must be a regular file",
        ));
    }
    Ok(())
}

fn ensure_private_artifact_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    ensure_private_artifact_metadata(&metadata)
}

fn build_core_v1() -> Result<Core, EffectDriverProcessErrorV1> {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1_u8..=4)
        .map(|index| {
            let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
            Validator::new(
                ValidatorId::new([index; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).expect("positive fixture voting power"),
            )
            .expect("strict fixture validator")
        })
        .collect();
    let validator_set = ValidatorSet::new(
        GenesisHash::new([0x91; 32]),
        ChainId::from_static(CHAIN_ID_V1),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("validator set: {error}")))?;
    let config = CoreConfig::new(
        ValidatorId::new([1; 32]),
        validator_set,
        parameters,
        17,
        32,
        64,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("config: {error}")))?;
    let genesis_qc = GenesisQcV0::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set(),
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("genesis QC: {error}")))?;
    Core::new(config, genesis_qc, &StrictEd25519Verifier)
        .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("construct: {error}")))
}

/// Rebuilds the exact static commitment capability for the process fixture.
///
/// The process does not expose a generic caller-supplied Valid result. The
/// body is decoded against Core's committed parameters, receipts are derived
/// from that decoded payload, and the typed body kernel mints the private
/// `ValidatedBlockCommitmentsV0` value used by the Core seal authority.
fn validated_commitments_for_block(
    core: &Core,
    block: &Block,
) -> Result<trnm_consensus_types::ValidatedBlockCommitmentsV0, String> {
    let parameters = core.config().consensus_parameters();
    let application_payload =
        decode_application_payload_v0_exact(block.application_payload(), parameters)
            .map_err(|error| format!("decode application payload: {error}"))?;
    let receipts = ExecutionReceiptsV0::new(
        &application_payload,
        (0..application_payload.transaction_count())
            .map(|index| {
                ExecutionReceiptCommitmentV0::for_transaction(
                    &application_payload,
                    index,
                    0,
                    0,
                    Vec::new(),
                )
                .map_err(|error| format!("derive execution receipt {index}: {error}"))
            })
            .collect::<Result<Vec<_>, String>>()?,
    )
    .map_err(|error| format!("construct execution receipts: {error}"))?;
    let body = BlockBodyV0::new(application_payload, Vec::new())
        .map_err(|error| format!("construct canonical body: {error}"))?;
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        parameters,
        core.config().validator_set(),
        &StrictEd25519Verifier,
    )
    .map_err(|error| format!("validate ordinary commitments: {error}"))
}

fn artifact_ref_for_block(block: &Block) -> ValidatedPayloadArtifactRefV0 {
    let mut overlay_checksum = *block.id().as_bytes();
    overlay_checksum[0] ^= 0x5a;
    let mut source_artifact_checksum = *block.id().as_bytes();
    source_artifact_checksum[0] ^= 0xa5;
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), overlay_checksum),
        source_artifact_checksum,
    )
}

/// Deterministic signed h1 proposal used only by the candidate process tests.
/// It is submitted through the synced-proposal route so application Valid can
/// be persisted without bypassing the explicitly issued SafetyRules owner;
/// the following `enqueue_authority_vote` command then exercises the same
/// Core instance and authority.
fn fixture_proposal_v1(core: &Core) -> Result<SignedProposalV0, EffectDriverProcessErrorV1> {
    let config = core.config();
    let parameters = config.consensus_parameters();
    let set = config.validator_set();
    let application_payload = ApplicationPayloadV0::new(vec![FIXTURE_PAYLOAD_V1.to_vec()])
        .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("payload: {error}")))?;
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .map_err(|error| {
                EffectDriverProcessErrorV1::new("fixture", format!("receipt: {error}"))
            })?;
    let receipts =
        ExecutionReceiptsV0::new(&application_payload, vec![receipt]).map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("receipts: {error}"))
        })?;
    let body = BlockBodyV0::new(application_payload, Vec::new())
        .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("body: {error}")))?;
    let parent_timestamp_ms = config.trusted_genesis_timestamp_ms();
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(1),
        Height::new(1),
        BlockKind::Regular,
        config.genesis_block_id(),
        ValidatorId::new([1; 32]),
        set.id(),
        parameters.hash(),
        body.payload_root().map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("payload root: {error}"))
        })?,
        StateRoot::new([1; 32]),
        receipts.receipts_root().map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("receipts root: {error}"))
        })?,
        body.evidence_root().map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("evidence root: {error}"))
        })?,
        parent_timestamp_ms.saturating_add(1),
        None,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("header: {error}")))?;
    let block = Block::new(
        header.clone(),
        body.application_payload()
            .try_cev0_bytes()
            .map_err(|error| {
                EffectDriverProcessErrorV1::new("fixture", format!("payload bytes: {error}"))
            })?,
        Vec::new(),
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("block: {error}")))?;
    let genesis_qc =
        GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("genesis QC: {error}"))
        })?;
    let justify = QcReferenceV0::genesis_anchor(genesis_qc);
    let proposal_root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None)
        .map_err(|error| {
            EffectDriverProcessErrorV1::new("fixture", format!("proposal root: {error}"))
        })?;
    let proposer_signature = Signature64::from_array(
        SigningKey::from_bytes(&LOCAL_KEY_BYTES_V1)
            .sign(proposal_root.as_bytes())
            .to_bytes(),
    );
    let witness = ProposalWitnessV0::new(
        &header,
        justify,
        None,
        None,
        proposer_signature,
        set,
        None,
        parameters,
        parent_timestamp_ms,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("witness: {error}")))?;
    SignedProposalV0::new(block, witness, set, None, parameters, parent_timestamp_ms)
        .map_err(|error| EffectDriverProcessErrorV1::new("fixture", format!("proposal: {error}")))
}

fn facts_json(facts: CandidateEffectDriverFactsV1, broadcasts: u64) -> Value {
    let status = match facts.status() {
        CandidateEffectDriverStatusV1::Active => "active",
        CandidateEffectDriverStatusV1::Halted => "halted",
        CandidateEffectDriverStatusV1::FailStopped => "fail_stopped",
    };
    json!({
        "status": status,
        "generation": facts.generation(),
        "queue_depth": facts.queue_depth(),
        "queue_capacity": facts.queue_capacity(),
        "processed_ingress": facts.processed_ingress(),
        "processed_effects": facts.processed_effects(),
        "stale_generation_rejections": facts.stale_generation_rejections(),
        "backpressure_rejections": facts.backpressure_rejections(),
        "broadcasts": broadcasts,
        "candidate_only": facts.candidate_only(),
        "production_activation": EFFECT_DRIVER_PROCESS_PRODUCTION_ACTIVATION_V1,
        "finality_verified": facts.finality_verified(),
    })
}

fn admission_json(admission: CandidateEffectDriverAdmissionV1) -> Value {
    match admission {
        CandidateEffectDriverAdmissionV1::Accepted {
            generation,
            queue_depth,
        } => json!({"admission":"accepted","generation":generation,"queue_depth":queue_depth}),
        CandidateEffectDriverAdmissionV1::StaleGeneration {
            expected_generation,
            received_generation,
        } => json!({
            "admission":"stale_generation",
            "expected_generation":expected_generation,
            "received_generation":received_generation,
        }),
        CandidateEffectDriverAdmissionV1::Backpressure {
            capacity,
            queue_depth,
        } => json!({
            "admission":"backpressure",
            "capacity":capacity,
            "queue_depth":queue_depth,
        }),
    }
}

fn driver_error_json(error: &CandidateEffectDriverErrorV1) -> Value {
    json!({"status":"fail_stopped","reason":error.to_string(),"candidate_only":true})
}

type FileEffectDriverV1 = CandidateEffectDriverV1<FileTransitionStoreV1, FileHooksV1>;

fn open_file_effect_driver_v1(
    root: &Path,
) -> Result<FileEffectDriverV1, EffectDriverProcessErrorV1> {
    let core = build_core_v1()?;
    // Install the one Core-affined application seal authority before issuing
    // the SafetyRules authority. Both capabilities are process-local and are
    // moved into the private host owner below; neither is reconstructible
    // from an ingress stream or a durable record.
    let application_seal_authority = core
        .issue_application_seal_authority_v0()
        .map_err(|error| EffectDriverProcessErrorV1::new("application", error.to_string()))?;
    let store = FileTransitionStoreV1::open(root)?;
    let authority = core
        .issue_safety_rules_authority_v1(store, &StrictEd25519Verifier)
        .map_err(|error| EffectDriverProcessErrorV1::new("authority", error.to_string()))?;
    let hooks = FileHooksV1::new(root, application_seal_authority);
    CandidateEffectDriverV1::new(
        core,
        authority,
        hooks,
        EFFECT_DRIVER_PROCESS_QUEUE_CAPACITY_V1,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("driver", error.to_string()))
}

/// Run the candidate process over line-delimited JSON stdin/stdout.
pub fn run_stdio_v1<R: BufRead, W: Write>(
    root: PathBuf,
    mut reader: R,
    mut writer: W,
) -> Result<EffectDriverProcessSummaryV1, EffectDriverProcessErrorV1> {
    fresh_root(&root)?;
    atomic_replace(
        &root.join(ROOT_MARKER_V1),
        b"v=1\tprocess=candidate-effect-driver\tstate=fresh\n",
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("root", format!("start marker: {error:?}")))?;
    let mut driver = open_file_effect_driver_v1(&root)?;

    let mut line = String::new();
    let mut shutdown = false;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes > EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1
            || (!line.ends_with('\n') && bytes == EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1)
        {
            let response =
                json!({"status":"rejected","reason":"frame_too_large","candidate_only":true});
            serde_json::to_writer(&mut writer, &response)
                .map_err(|error| EffectDriverProcessErrorV1::new("json", format!("{error:?}")))?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            continue;
        }
        let raw = line.trim_end_matches(['\r', '\n']).as_bytes();
        if let Err(error) = validate_strict_json_structure_v0(raw) {
            let response = json!({"status":"rejected","reason":"malformed_json","detail":error.to_string(),"candidate_only":true});
            serde_json::to_writer(&mut writer, &response).map_err(|json_error| {
                EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
            })?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            continue;
        }
        let command = match serde_json::from_slice::<CommandV1>(raw) {
            Ok(command) => command,
            Err(error) => {
                let response = json!({"status":"rejected","reason":"unknown_command","detail":error.to_string(),"candidate_only":true});
                serde_json::to_writer(&mut writer, &response).map_err(|json_error| {
                    EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                })?;
                writer.write_all(b"\n")?;
                writer.flush()?;
                continue;
            }
        };

        let response = match command {
            CommandV1::EnqueueTimeout { generation } => match driver.enqueue_timeout_v1(generation)
            {
                Ok(admission) => {
                    let mut value = admission_json(admission);
                    if let Value::Object(object) = &mut value {
                        object.insert("status".to_owned(), Value::String("accepted".to_owned()));
                    }
                    value
                }
                Err(error) => {
                    let value = driver_error_json(&error);
                    serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                        EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                    })?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                }
            },
            CommandV1::EnqueueSyncedProposal { generation } => {
                let proposal = fixture_proposal_v1(driver.core())?;
                match driver.enqueue_synced_proposal_v1(generation, proposal) {
                    Ok(admission) => {
                        let mut value = admission_json(admission);
                        if let Value::Object(object) = &mut value {
                            object
                                .insert("status".to_owned(), Value::String("accepted".to_owned()));
                        }
                        value
                    }
                    Err(error) => {
                        let value = driver_error_json(&error);
                        serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                            EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                        })?;
                        writer.write_all(b"\n")?;
                        writer.flush()?;
                        return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                    }
                }
            }
            CommandV1::EnqueueProposal { generation } => {
                let proposal = fixture_proposal_v1(driver.core())?;
                match driver.enqueue_proposal_v1(generation, proposal) {
                    Ok(admission) => {
                        let mut value = admission_json(admission);
                        if let Value::Object(object) = &mut value {
                            object
                                .insert("status".to_owned(), Value::String("accepted".to_owned()));
                        }
                        value
                    }
                    Err(error) => {
                        let value = driver_error_json(&error);
                        serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                            EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                        })?;
                        writer.write_all(b"\n")?;
                        writer.flush()?;
                        return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                    }
                }
            }
            CommandV1::EnqueueAuthorityVote { generation } => {
                let proposal = fixture_proposal_v1(driver.core())?;
                match driver.enqueue_authority_vote_v1(generation, proposal) {
                    Ok(admission) => {
                        let mut value = admission_json(admission);
                        if let Value::Object(object) = &mut value {
                            object
                                .insert("status".to_owned(), Value::String("accepted".to_owned()));
                        }
                        value
                    }
                    Err(error) => {
                        let value = driver_error_json(&error);
                        serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                            EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                        })?;
                        writer.write_all(b"\n")?;
                        writer.flush()?;
                        return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                    }
                }
            }
            CommandV1::Drive => match driver.drive_v1() {
                Ok(facts) => facts_json(facts, broadcast_count(&root)),
                Err(error) => {
                    let value = driver_error_json(&error);
                    serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                        EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                    })?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                }
            },
            CommandV1::Status => facts_json(driver.facts_v1(), broadcast_count(&root)),
            CommandV1::Shutdown => {
                shutdown = true;
                let mut value = facts_json(driver.facts_v1(), broadcast_count(&root));
                if let Value::Object(object) = &mut value {
                    object.insert("shutdown".to_owned(), Value::Bool(true));
                }
                value
            }
        };
        serde_json::to_writer(&mut writer, &response)
            .map_err(|error| EffectDriverProcessErrorV1::new("json", format!("{error:?}")))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        if shutdown {
            break;
        }
    }

    let facts = driver.facts_v1();
    Ok(EffectDriverProcessSummaryV1 {
        generation: facts.generation(),
        processed_ingress: facts.processed_ingress(),
        processed_effects: facts.processed_effects(),
        broadcasts: broadcast_count(&root),
        status: facts.status(),
    })
}

#[cfg(unix)]
fn validate_p2p_socket_parameters_v1(
    root: &Path,
    socket_path: &Path,
    lease_socket_path: &Path,
    replay_path: &Path,
    run_id: &str,
    lease_generation: u64,
) -> Result<(), EffectDriverProcessErrorV1> {
    // This function is deliberately side-effect free.  In particular, it is
    // called before `fresh_root` creates a directory or writes the start
    // marker, so malformed caller input cannot leave an apparently started
    // owner behind.
    validate_narrow_absolute_path_v1(root, "run root")?;
    validate_narrow_absolute_path_v1(socket_path, "socket")?;
    validate_narrow_absolute_path_v1(lease_socket_path, "lease socket")?;
    validate_narrow_absolute_path_v1(replay_path, "replay WAL")?;
    if socket_path == lease_socket_path || socket_path == replay_path {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            "socket path aliases another candidate path",
        ));
    }
    if lease_generation == 0 {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            "lease generation must be positive",
        ));
    }
    if run_id.is_empty()
        || run_id.len() > P2P_SOCKET_RUN_ID_MAX_BYTES_V1
        || run_id.as_bytes().contains(&0)
    {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            "run id is empty, contains NUL, or exceeds the bounded candidate limit",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_narrow_absolute_path_v1(
    path: &Path,
    label: &'static str,
) -> Result<(), EffectDriverProcessErrorV1> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().count() < 3
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            format!("{label} requires a narrow absolute path without dot components"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct CandidateP2pSocketCleanupV1 {
    path: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl CandidateP2pSocketCleanupV1 {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: false }
    }

    fn arm(&mut self) {
        self.armed = true;
    }
}

#[cfg(unix)]
impl Drop for CandidateP2pSocketCleanupV1 {
    fn drop(&mut self) {
        if self.armed {
            cleanup_candidate_p2p_socket_v1(&self.path);
        }
    }
}

#[cfg(unix)]
fn accept_candidate_p2p_v1(
    listener: &UnixListener,
) -> Result<UnixStream, EffectDriverProcessErrorV1> {
    listener.set_nonblocking(true).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("nonblocking: {error:?}"))
    })?;
    let deadline = Instant::now() + P2P_SOCKET_ACCEPT_TIMEOUT_V1;
    loop {
        match listener.accept() {
            Ok((stream, _address)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(EffectDriverProcessErrorV1::new(
                        "socket",
                        "accept timed out before a peer connected",
                    ));
                }
                std::thread::sleep(P2P_SOCKET_ACCEPT_POLL_V1);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("accept: {error:?}"),
                ));
            }
        }
    }
}

/// Runs one bounded, candidate-only Unix-socket ingress session.
///
/// The owner accepts exactly one authenticated `TRNH`/`TRNF` stream, binds it
/// to an externally administered peer lease, durably admits the exact frame
/// through `PayloadReplayStoreV1`, and only then hands the typed consensus
/// input to the private Core effect-driver queue.  The lease and replay WAL
/// are intentionally separate transactions; a failure between them poisons
/// this one-shot owner and never exposes the frame to Core.
#[cfg(unix)]
pub fn run_p2p_socket_once_v1(
    root: PathBuf,
    socket_path: PathBuf,
    lease_socket_path: PathBuf,
    replay_path: PathBuf,
    run_id: String,
    lease_generation: u64,
) -> Result<EffectDriverProcessSummaryV1, EffectDriverProcessErrorV1> {
    validate_p2p_socket_parameters_v1(
        &root,
        &socket_path,
        &lease_socket_path,
        &replay_path,
        &run_id,
        lease_generation,
    )?;
    fresh_root(&root)?;
    atomic_replace(
        &root.join(ROOT_MARKER_V1),
        b"v=1\tprocess=candidate-p2p-core-ingress\tstate=fresh\n",
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("root", format!("start marker: {error:?}")))?;

    let mut driver = open_file_effect_driver_v1(&root)?;
    let network_context_hash = network_context_hash_v1(driver.core());
    let local_id = fixed_validator_id_v1(driver.core().config().local_validator())?;
    let validator_set_id = fixed_bytes_v1(
        driver.core().config().validator_set().id().as_bytes(),
        "validator set id",
    )?;
    let namespace = PayloadReplayNamespaceV1::new(
        local_id,
        driver.core().config().validator_set().epoch().get(),
        validator_set_id,
        payload_replay_run_id_hash_v1(&run_id),
        network_context_hash,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("p2p", error.to_string()))?;

    // Arm cleanup only after a successful bind.  The guard is declared before
    // the listener so normal unwinding drops the listener first and then
    // unlinks the socket path.  This also covers accept/read/write failures.
    let mut socket_cleanup = CandidateP2pSocketCleanupV1::new(socket_path.clone());
    let listener = bind_candidate_p2p_socket_v1(&socket_path)?;
    socket_cleanup.arm();
    let result = (|| {
        let mut stream = accept_candidate_p2p_v1(&listener)?;
        stream
            .set_nonblocking(false)
            .and_then(|_| stream.set_read_timeout(Some(P2P_SOCKET_READ_TIMEOUT_V1)))
            .and_then(|_| stream.set_write_timeout(Some(P2P_SOCKET_READ_TIMEOUT_V1)))
            .map_err(|error| {
                EffectDriverProcessErrorV1::new("socket", format!("timeout: {error:?}"))
            })?;

        let outcome = process_one_candidate_p2p_connection_v1(
            &mut stream,
            &mut driver,
            &root,
            namespace,
            lease_socket_path,
            replay_path,
            lease_generation,
        );
        match outcome {
            Ok((response, summary)) => {
                write_p2p_socket_response_v1(&mut stream, response)?;
                Ok(summary)
            }
            Err(error) => {
                let response = json!({
                    "status": if error.code == "p2p_lease_release_uncertain" {
                        "uncertain"
                    } else {
                        "rejected"
                    },
                    "reason": error.to_string(),
                    "commit_ambiguous": error.code == "p2p_lease_release_uncertain",
                    "candidate_only": true,
                    "production_activation": false,
                });
                let _ = write_p2p_socket_response_v1(&mut stream, response);
                Err(error)
            }
        }
    })();
    drop(listener);
    result
}

#[cfg(unix)]
fn process_one_candidate_p2p_connection_v1(
    stream: &mut UnixStream,
    driver: &mut FileEffectDriverV1,
    root: &Path,
    namespace: PayloadReplayNamespaceV1,
    lease_socket_path: PathBuf,
    replay_path: PathBuf,
    lease_generation: u64,
) -> Result<(Value, EffectDriverProcessSummaryV1), EffectDriverProcessErrorV1> {
    let handshake = read_p2p_socket_record_v1(stream, P2P_SESSION_MAX_HANDSHAKE_BYTES_V0)?;
    let session = PocoNodeP2pSessionV0::open(
        &handshake,
        driver.core().config().validator_set(),
        driver.core().config().consensus_parameters(),
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("p2p_handshake", error.to_string()))?;
    let peer_id = fixed_validator_id_v1(session.peer_id())?;
    let scope = PeerLeaseScopeV1::new(
        namespace.local_id(),
        peer_id,
        PayloadReplayDirectionV1::Inbound,
        namespace.epoch(),
        namespace.validator_set_id(),
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    let session_id = session.session_id();
    // Authenticate and structurally finish both records before acquiring a
    // lease.  A malformed or incomplete peer cannot consume an authority
    // lease, and the mandatory EOF check rejects a third record/trailing byte
    // on this one-shot protocol.
    let frame_bytes = read_p2p_socket_record_v1(stream, P2P_SOCKET_MAX_RECORD_BYTES_V1)?;
    require_p2p_socket_eof_v1(stream)?;
    let mut budget = Cev0AdmissionBudgetV0::for_validator_set(
        driver.core().config().consensus_parameters(),
        driver.core().config().validator_set(),
    );
    let accepted = {
        let mut session = session;
        let accepted = session
            .accept_frame(&frame_bytes, &mut budget)
            .map_err(|error| EffectDriverProcessErrorV1::new("p2p_frame", error.to_string()))?;
        let input = core_input_from_p2p_proof_v1(accepted.proof())?;
        let frame_kind = accepted.proof().body_kind() as u8;
        let sequence = accepted.sequence();
        (input, frame_kind, sequence)
    };

    let lease_authority =
        UnixPeerLeaseClientV1::connect(&lease_socket_path).with_timeout(P2P_SOCKET_READ_TIMEOUT_V1);
    lease_authority
        .preflight()
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    let token = lease_authority
        .acquire(
            scope,
            session_id,
            lease_generation,
            P2P_SOCKET_LEASE_TTL_MS_V1,
        )
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    // Arm the cleanup guard before validating any returned token fields.  A
    // compromised/misconfigured authority must not strand an active lease.
    let mut lease_guard =
        CandidatePeerLeaseGuardV1::new(lease_authority.clone(), token, root.to_path_buf());
    if token.scope() != scope
        || token.session_id() != session_id
        || token.generation() != lease_generation
        || token.expires_at_ms() == 0
        || token.record_hash() == [0; 32]
    {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p_lease",
            "authority returned a token with mismatched scope or generation",
        ));
    }

    let mut replay = PayloadReplayStoreV1::open(&replay_path, namespace)
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_replay", error.to_string()))?;

    // Revalidate immediately before the payload append.  The external lease
    // daemon and this WAL are intentionally separate owners; if the lease is
    // fenced in this interval, no Core input is exposed.
    let revalidated = lease_guard
        .revalidate()
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    if revalidated != token {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p_lease",
            "lease revalidation changed the exact token",
        ));
    }

    let driver_facts = driver.facts_v1();
    if driver_facts.queue_depth() >= driver_facts.queue_capacity() {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p_queue",
            "Core ingress queue has no capacity before durable replay admission",
        ));
    }
    let driver_generation = driver_facts
        .generation()
        .checked_add(driver_facts.queue_depth() as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| EffectDriverProcessErrorV1::new("p2p_queue", "Core generation overflow"))?;
    let fingerprint = p2p_frame_fingerprint_v1(token.session_id(), accepted.2, &frame_bytes);
    let replay_frame = PayloadReplayFrameV1::new(
        scope,
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        token.session_id(),
        token.generation(),
        accepted.2,
        accepted.1,
        frame_bytes.len(),
        fingerprint,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("p2p_replay", error.to_string()))?;
    let receipt = replay
        .admit(&replay_frame)
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_replay", error.to_string()))?;

    // Close the second half of the lease/WAL race before handing the typed
    // value to Core.  A failed check leaves a durable replay tombstone but no
    // consensus transition, which is the safe liveness tradeoff here.
    let revalidated_after_append = lease_guard
        .revalidate()
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    if revalidated_after_append != token {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p_lease",
            "lease was fenced after durable replay admission",
        ));
    }
    let admission = driver
        .enqueue_authenticated_peer_input_v1(driver_generation, accepted.0)
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_core", error.to_string()))?;
    if !matches!(admission, CandidateEffectDriverAdmissionV1::Accepted { .. }) {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p_core",
            format!("unexpected Core ingress admission: {admission:?}"),
        ));
    }
    let facts = driver
        .drive_v1()
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_core", error.to_string()))?;
    lease_guard.release().map_err(|error| {
        EffectDriverProcessErrorV1::new("p2p_lease_release_uncertain", error.to_string())
    })?;

    let response = json!({
        "status": "accepted",
        "peer_id": hex::encode(peer_id),
        "session_id": hex::encode(token.session_id()),
        "sequence": accepted.2,
        "lease_generation": token.generation(),
        "replay_record_index": receipt.record_index(),
        "replay_record_hash": hex::encode(receipt.record_hash()),
        "processed_ingress": facts.processed_ingress(),
        "processed_effects": facts.processed_effects(),
        "candidate_only": true,
        "production_activation": EFFECT_DRIVER_PROCESS_PRODUCTION_ACTIVATION_V1,
        "finality_verified": facts.finality_verified(),
    });
    let summary = EffectDriverProcessSummaryV1 {
        generation: facts.generation(),
        processed_ingress: facts.processed_ingress(),
        processed_effects: facts.processed_effects(),
        broadcasts: broadcast_count(root),
        status: facts.status(),
    };
    Ok((response, summary))
}

#[cfg(unix)]
fn core_input_from_p2p_proof_v1(
    proof: &WireEnvelopeSemanticProof<'_>,
) -> Result<Input, EffectDriverProcessErrorV1> {
    match proof.body_kind() {
        WireSemanticBodyKindV0::Vote => proof.as_vote().cloned().map(Input::Vote),
        WireSemanticBodyKindV0::TimeoutVote => {
            proof.as_timeout_vote().cloned().map(Input::TimeoutVote)
        }
        WireSemanticBodyKindV0::QuorumCertificate => proof
            .as_quorum_certificate()
            .cloned()
            .map(Input::QuorumCertificate),
        WireSemanticBodyKindV0::TimeoutCertificate => proof
            .as_timeout_certificate()
            .cloned()
            .map(Input::TimeoutCertificate),
    }
    .ok_or_else(|| {
        EffectDriverProcessErrorV1::new(
            "p2p_frame",
            "semantic proof body kind did not expose its exact typed value",
        )
    })
}

#[cfg(unix)]
fn read_p2p_socket_record_v1(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Vec<u8>, EffectDriverProcessErrorV1> {
    let mut header = [0u8; P2P_SOCKET_RECORD_HEADER_BYTES_V1];
    stream.read_exact(&mut header).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("record header: {error:?}"))
    })?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("record length {length} exceeds bound {maximum}"),
        ));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("record body: {error:?}"))
    })?;
    Ok(bytes)
}

#[cfg(unix)]
fn require_p2p_socket_eof_v1(stream: &mut UnixStream) -> Result<(), EffectDriverProcessErrorV1> {
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(EffectDriverProcessErrorV1::new(
            "socket",
            "trailing bytes or records after the single candidate frame",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(EffectDriverProcessErrorV1::new(
                "socket",
                "peer did not half-close after the single candidate frame",
            ))
        }
        Err(error) => Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("trailing-byte check: {error:?}"),
        )),
    }
}

#[cfg(unix)]
fn write_p2p_socket_response_v1(
    stream: &mut UnixStream,
    response: Value,
) -> Result<(), EffectDriverProcessErrorV1> {
    let bytes = serde_json::to_vec(&response).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("response: {error:?}"))
    })?;
    if bytes.len() > P2P_SOCKET_MAX_RECORD_BYTES_V1 {
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            "response exceeds bounded socket frame",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| EffectDriverProcessErrorV1::new("socket", "response length overflow"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

#[cfg(unix)]
fn bind_candidate_p2p_socket_v1(path: &Path) -> Result<UnixListener, EffectDriverProcessErrorV1> {
    if !path.is_absolute() || path == Path::new("/") || path.components().count() < 3 {
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            "candidate socket requires an absolute narrow path",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        EffectDriverProcessErrorV1::new("socket", "candidate socket has no parent")
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("socket parent: {error:?}"))
    })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            "candidate socket parent must be a private directory",
        ));
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        let detail = if existing.file_type().is_socket() {
            "candidate socket path already exists"
        } else {
            "candidate socket path is not a socket"
        };
        return Err(EffectDriverProcessErrorV1::new("socket", detail));
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| EffectDriverProcessErrorV1::new("socket", format!("bind: {error:?}")))?;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        drop(listener);
        cleanup_candidate_p2p_socket_v1(path);
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("permissions: {error:?}"),
        ));
    }
    Ok(listener)
}

#[cfg(unix)]
fn cleanup_candidate_p2p_socket_v1(path: &Path) {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
struct CandidatePeerLeaseGuardV1 {
    authority: UnixPeerLeaseClientV1,
    token: Option<PeerLeaseTokenV1>,
    root: PathBuf,
}

#[cfg(unix)]
impl CandidatePeerLeaseGuardV1 {
    fn new(authority: UnixPeerLeaseClientV1, token: PeerLeaseTokenV1, root: PathBuf) -> Self {
        Self {
            authority,
            token: Some(token),
            root,
        }
    }

    fn revalidate(&self) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        let token = self.token()?;
        self.authority.revalidate(token)
    }

    fn token(&self) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        // The guard is only constructed after a successful acquire, and the
        // token remains armed until an explicit release succeeds.
        self.token
            .ok_or(PeerLeaseErrorV1::InvalidRequest("lease guard is disarmed"))
    }

    fn release(&mut self) -> Result<(), PeerLeaseErrorV1> {
        let Some(token) = self.token else {
            return Ok(());
        };
        match self.authority.release(token) {
            Ok(()) => {
                self.token = None;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
impl Drop for CandidatePeerLeaseGuardV1 {
    fn drop(&mut self) {
        let Some(token) = self.token else {
            return;
        };
        if self.authority.release(token).is_err() {
            // Drop cannot surface an error.  Persist a fail-stop breadcrumb so
            // a supervisor/recovery owner can distinguish an uncertain lease
            // release from a clean one-shot completion; the daemon TTL still
            // bounds the orphaned lease if the best-effort retry also fails.
            let line = format!(
                "v=1\tp2p_lease_release=failed\tsession={}\tgeneration={}\n",
                hex::encode(token.session_id()),
                token.generation(),
            );
            let _ = append_durable(&self.root.join(ROOT_MARKER_V1), line.as_bytes());
        }
    }
}

#[cfg(unix)]
fn fixed_bytes_v1(
    bytes: &[u8],
    label: &'static str,
) -> Result<[u8; 32], EffectDriverProcessErrorV1> {
    bytes.try_into().map_err(|_| {
        EffectDriverProcessErrorV1::new("p2p", format!("{label} is not exactly 32 bytes"))
    })
}

#[cfg(unix)]
fn fixed_validator_id_v1(id: ValidatorId) -> Result<[u8; 32], EffectDriverProcessErrorV1> {
    fixed_bytes_v1(id.as_bytes(), "validator id")
}

#[cfg(unix)]
fn p2p_frame_fingerprint_v1(session_id: [u8; 32], sequence: u64, frame: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(P2P_SOCKET_FRAME_FINGERPRINT_DOMAIN_V1);
    hasher.update(session_id);
    hasher.update(sequence.to_be_bytes());
    hasher.update((frame.len() as u64).to_be_bytes());
    hasher.update(frame);
    hasher.finalize().into()
}

#[cfg(unix)]
fn network_context_hash_v1(core: &Core) -> [u8; 32] {
    let config = core.config();
    let set = config.validator_set();
    let chain = set.chain_id();
    let chain_id = chain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(P2P_SOCKET_NETWORK_CONTEXT_DOMAIN_V1);
    hasher.update(set.genesis_hash().as_bytes());
    hasher.update((chain_id.len() as u64).to_be_bytes());
    hasher.update(chain_id);
    hasher.update(set.protocol_version().get().to_be_bytes());
    hasher.update(set.epoch().get().to_be_bytes());
    hasher.update(set.id().as_bytes());
    hasher.update(set.consensus_parameters_hash().as_bytes());
    hasher.finalize().into()
}

fn broadcast_count(root: &Path) -> u64 {
    fs::read_to_string(root.join(OUTBOUND_WAL_V1))
        .map(|value| value.lines().count() as u64)
        .unwrap_or(0)
}

#[cfg(all(test, unix))]
mod persistence_security_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn fresh_root_sets_private_mode_on_new_and_existing_roots() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let root = parent.path().join("run");
        fresh_root(&root).expect("new root is accepted");
        assert_eq!(
            fs::symlink_metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        let broad = parent.path().join("broad");
        fs::create_dir(&broad).expect("broad root");
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).expect("set broad mode");
        fresh_root(&broad).expect("existing root is tightened explicitly");
        assert_eq!(
            fs::symlink_metadata(&broad)
                .expect("broad root metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    #[test]
    fn durable_artifacts_use_private_files_and_reject_symlink_targets() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let root = parent.path().join("run");
        fresh_root(&root).expect("new root is accepted");

        let append_path = root.join("append.wal");
        append_durable(&append_path, b"record\n").expect("append artifact");
        assert_eq!(
            fs::symlink_metadata(&append_path)
                .expect("append metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        let replace_path = root.join("replace.record");
        atomic_replace(&replace_path, b"record\n").expect("replace artifact");
        assert_eq!(
            fs::symlink_metadata(&replace_path)
                .expect("replace metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        let target = parent.path().join("outside");
        fs::write(&target, b"outside\n").expect("outside target");
        let link = root.join("link.wal");
        symlink(&target, &link).expect("symlink target");
        assert!(append_durable(&link, b"must-not-follow\n").is_err());
        assert_eq!(fs::read(&target).expect("outside read"), b"outside\n");
    }
}
