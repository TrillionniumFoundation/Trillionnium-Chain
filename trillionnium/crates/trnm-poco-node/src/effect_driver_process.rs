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
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};

use ed25519_dalek::{Signer, SigningKey};
#[cfg(unix)]
use fs2::FileExt;
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
    payload_replay_run_id_hash_v1, ExternalPeerLeaseAuthorityV1, PayloadReplayBodyErrorV1,
    PayloadReplayBodyStoreV1, PayloadReplayDirectionV1, PayloadReplayErrorV1, PayloadReplayFrameV1,
    PayloadReplayNamespaceV1, PayloadReplayStoreV1, PeerLeaseErrorV1, PeerLeaseScopeV1,
    PeerLeaseTokenV1, UnixPeerLeaseClientV1,
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
// A prepared-but-not-acknowledged P2P replay is retained as an explicit
// recovery breadcrumb.  It is deliberately part of the fresh-root inventory:
// a subsequent one-shot owner must stop and hand this record to a recovery
// owner rather than silently retrying the same frame.
const P2P_REPLAY_PENDING_V1: &str = "p2p-replay.pending";
// The replay WAL intentionally contains only authenticated frame identity.
// Exact frame bytes live in a separate, dedicated directory beside that WAL;
// the two stores are reconciled explicitly and are never treated as one
// atomic transaction.
const P2P_REPLAY_BODY_DIRECTORY_SUFFIX_V1: &str = ".body-v1";
// Failed atomic publications are retained as recovery evidence.  A process
// local nonce prevents a retry in the same owner from colliding forever with
// the retained temporary pathname.
static ROOT_TEMP_NONCE_V1: AtomicU64 = AtomicU64::new(0);
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
// One absolute budget covers both authenticated input records, the required
// half-close, and the bounded response write.  Per-I/O socket timeouts alone
// permit a peer to drip one byte just before each timeout indefinitely.
const P2P_SOCKET_OPERATION_TIMEOUT_V1: Duration = Duration::from_secs(30);
#[cfg(unix)]
const P2P_SOCKET_ACCEPT_TIMEOUT_V1: Duration = Duration::from_secs(5);
#[cfg(unix)]
const P2P_SOCKET_ACCEPT_POLL_V1: Duration = Duration::from_millis(10);
#[cfg(unix)]
// Keep the authority lease wider than the one-shot socket budget so a slow
// but bounded replay/Core path can be detected before it reaches expiry.
const P2P_SOCKET_LEASE_TTL_MS_V1: u64 = 120_000;
// A token which is about to expire cannot safely cover the replay/Core
// boundary. Keep the complete 30-second socket budget plus one lease-client
// round trip in reserve and fail closed before exposing an input when the
// authority returns a nearly-dead token.
#[cfg(unix)]
const P2P_SOCKET_MIN_REMAINING_LEASE_MS_V1: u64 = P2P_SOCKET_OPERATION_TIMEOUT_V1.as_millis()
    as u64
    + P2P_SOCKET_READ_TIMEOUT_V1.as_millis() as u64;
#[cfg(unix)]
const P2P_SOCKET_RUN_ID_MAX_BYTES_V1: usize = 128;
// macOS has the smallest `sockaddr_un.sun_path` supported by the candidate
// fleet (104 bytes including the trailing NUL).  Keep the shared candidate
// seam within that cross-platform bound instead of relying on bind/connect to
// fail after durable state has already been created.
#[cfg(unix)]
const P2P_UNIX_SOCKET_PATH_MAX_BYTES_V1: usize = 103;
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
    commit_ambiguous: bool,
}

impl EffectDriverProcessErrorV1 {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            commit_ambiguous: false,
        }
    }

    fn commit_ambiguous(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            commit_ambiguous: true,
        }
    }

    /// True when the failed operation may already have crossed a durable
    /// lease, replay, or Core-delivery boundary.  Callers must resolve the
    /// owned state rather than treating this as an ordinary retryable reject.
    pub const fn is_commit_ambiguous(&self) -> bool {
        self.commit_ambiguous
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
    #[cfg(unix)]
    let identity = artifact_identity_v1(path, &file)?;
    #[cfg(unix)]
    verify_artifact_path_identity_v1(path, identity)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    verify_artifact_path_identity_v1(path, identity)?;
    sync_parent_directory_v1(path)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no UTF-8 name"))?;
    let temp = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        ROOT_TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed),
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&temp)?;
        ensure_private_artifact_file(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        let replacement_identity = artifact_identity_v1(&temp, &file)?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        verify_artifact_path_identity_v1(path, replacement_identity)?;
        #[cfg(not(unix))]
        ensure_private_artifact_metadata(&fs::symlink_metadata(path)?)?;
        sync_parent_directory_v1(path)?;
        Ok::<(), io::Error>(())
    })();
    // Do not unlink the temporary by pathname here: after `create_new` or a
    // write failure, a same-UID process could have replaced that name.
    // Leaving it makes the next owner fail closed on the stale create_new
    // name and preserves the evidence for recovery.
    result?;
    Ok(())
}

fn sync_parent_directory_v1(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    #[cfg(unix)]
    {
        // WAL creation and rename publication are not durable until the
        // containing directory is synced.  Propagate both open and fsync
        // failures: returning success here would misclassify an uncertain
        // crash cut as a committed artifact.
        let directory = open_directory_no_follow_v1(parent)?;
        directory.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

#[cfg(unix)]
fn artifact_identity_v1(path: &Path, file: &File) -> io::Result<CandidateFsIdentityV1> {
    let descriptor = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    ensure_private_artifact_metadata(&path_metadata)?;
    let descriptor_identity = CandidateFsIdentityV1::from_metadata(&descriptor);
    if descriptor_identity != CandidateFsIdentityV1::from_metadata(&path_metadata) {
        return Err(io::Error::other(
            "candidate artifact descriptor/path identity changed",
        ));
    }
    Ok(descriptor_identity)
}

#[cfg(unix)]
fn verify_artifact_path_identity_v1(
    path: &Path,
    expected: CandidateFsIdentityV1,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure_private_artifact_metadata(&metadata)?;
    if CandidateFsIdentityV1::from_metadata(&metadata) != expected {
        return Err(io::Error::other("candidate artifact path identity changed"));
    }
    Ok(())
}

/// Validate every already-materialized directory component of a candidate
/// path before any state is created.  A lexical `Path` check is not enough:
/// an ancestor symlink (or a world-writable ancestor) can redirect the
/// process into a namespace which the caller did not intend to own.  Missing
/// components are returned so the caller can create and tighten only those
/// components, rather than changing permissions on an existing parent.
fn validate_directory_ancestry_v1(
    path: &Path,
    label: &'static str,
    minimum_components: usize,
    allow_missing: bool,
) -> Result<Vec<PathBuf>, EffectDriverProcessErrorV1> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().count() < minimum_components
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            format!("{label} requires a narrow absolute path without dot components"),
        ));
    }

    let mut current = PathBuf::from("/");
    let mut missing = Vec::new();
    #[cfg(unix)]
    let mut trusted_owner: Option<u32> = None;

    for component in path.components() {
        let Component::Normal(part) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                format!("{label} contains a non-normal path component"),
            ));
        };
        current.push(part);

        // Once a component is missing, all following components are also
        // missing by definition.  They are checked with O_NOFOLLOW after
        // creation below.
        if !missing.is_empty() {
            missing.push(current.clone());
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(EffectDriverProcessErrorV1::new(
                        "root",
                        format!(
                            "{label} component {} is a symlink or not a directory",
                            current.display()
                        ),
                    ));
                }
                #[cfg(unix)]
                validate_directory_ancestor_metadata_v1(&current, &metadata, &mut trusted_owner)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing => {
                missing.push(current.clone());
            }
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "root",
                    format!("{label} component {}: {error:?}", current.display()),
                ));
            }
        }
    }

    // Canonicalizing the last existing prefix catches a symlink alias even
    // when the final run-root component itself has not been created yet.
    let existing_prefix = missing
        .first()
        .and_then(|value| value.parent())
        .unwrap_or(path);
    let canonical_prefix = fs::canonicalize(existing_prefix).map_err(|error| {
        EffectDriverProcessErrorV1::new(
            "root",
            format!(
                "{label} canonical prefix {}: {error:?}",
                existing_prefix.display()
            ),
        )
    })?;
    if canonical_prefix != existing_prefix {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            format!("{label} contains a symlink alias"),
        ));
    }
    Ok(missing)
}

#[cfg(unix)]
fn validate_directory_ancestor_metadata_v1(
    path: &Path,
    metadata: &fs::Metadata,
    trusted_owner: &mut Option<u32>,
) -> Result<(), EffectDriverProcessErrorV1> {
    let mode = metadata.permissions().mode() & 0o7777;
    let owner = metadata.uid();
    // A root-owned sticky directory (for example /tmp) is the one deliberate
    // exception to the no-write rule: the sticky bit prevents an unprivileged
    // peer from replacing another owner's child.  Group-write is rejected as
    // well as world-write for every other ancestor; a same-group process can
    // otherwise replace a pathname between the lexical check and openat.
    if mode & 0o022 != 0 && !(owner == 0 && mode & 0o1000 != 0) {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            format!(
                "directory ancestor {} is group/world writable (mode {mode:o})",
                path.display()
            ),
        ));
    }
    if owner != 0 && owner != rustix::process::geteuid().as_raw() {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            format!(
                "directory ancestor {} is owned by a different user ({owner})",
                path.display()
            ),
        ));
    }
    // System-owned components are accepted only when they are not writable;
    // all non-root components in the chain must belong to one uid.  This
    // rejects a path which crosses into a different user's writable tree
    // without requiring a platform-specific getuid syscall.
    if owner != 0 {
        if let Some(expected) = *trusted_owner {
            if expected != owner {
                return Err(EffectDriverProcessErrorV1::new(
                    "root",
                    format!(
                        "directory ancestor {} changes non-root owner from {expected} to {owner}",
                        path.display()
                    ),
                ));
            }
        } else {
            *trusted_owner = Some(owner);
        }
    }
    Ok(())
}

fn open_directory_no_follow_v1(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    options.open(path)
}

fn tighten_new_directories_v1(missing: &[PathBuf]) -> Result<(), EffectDriverProcessErrorV1> {
    for path in missing {
        let directory = open_directory_no_follow_v1(path).map_err(|error| {
            EffectDriverProcessErrorV1::new(
                "root",
                format!("open newly-created directory {}: {error:?}", path.display()),
            )
        })?;
        set_private_root_permissions(&directory).map_err(|error| {
            EffectDriverProcessErrorV1::new(
                "root",
                format!("tighten directory {}: {error:?}", path.display()),
            )
        })?;
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
    let missing = validate_directory_ancestry_v1(root, "run root", 3, true)?;
    fs::create_dir_all(root)?;
    tighten_new_directories_v1(&missing)?;
    // Re-run the complete ancestry check after creation.  This closes the
    // common create_dir_all/symlink substitution cut before any artifact is
    // opened or renamed.
    validate_directory_ancestry_v1(root, "run root", 3, false)?;
    // Make every candidate run root private explicitly; relying on the
    // process umask is insufficient for consensus/WAL material.  The chmod is
    // issued on an opened, O_NOFOLLOW directory descriptor so the final
    // component is not followed as a symlink.
    let directory = open_directory_no_follow_v1(root)?;
    set_private_root_permissions(&directory)?;
    let metadata = directory.metadata()?;
    ensure_private_root_metadata(root, &metadata)?;
    let state_names = [
        ROOT_MARKER_V1,
        TRANSITION_WAL_V1,
        SAFETY_STATE_V1,
        CHECKPOINT_V1,
        OUTBOUND_WAL_V1,
        TIMER_WAL_V1,
        APPLICATION_WAL_V1,
        P2P_REPLAY_PENDING_V1,
    ];
    // A "fresh" root is an exact inventory, not just a set of known files
    // which happen to be empty.  Reject unknown files, directories and stale
    // atomic-replace temporaries so a previous/hostile owner cannot smuggle
    // unreviewed state past the recovery boundary.
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !state_names
            .iter()
            .any(|name| entry.file_name() == Path::new(name).as_os_str())
        {
            return Err(EffectDriverProcessErrorV1::new(
                "recovery_required",
                format!(
                    "unknown candidate state {} requires an explicit recovery owner",
                    entry.path().display()
                ),
            ));
        }
    }
    for name in state_names {
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
                if name == ROOT_MARKER_V1 {
                    // The marker is created only when an owner starts.  An
                    // existing empty marker is therefore not an idempotent
                    // clean state; it is indistinguishable from truncation
                    // by a same-UID process and must stop for recovery.
                    return Err(EffectDriverProcessErrorV1::new(
                        "recovery_required",
                        format!(
                            "empty candidate state {} requires an explicit recovery owner",
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
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                "candidate run root must be an owner-private 0700 directory",
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

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateFsIdentityV1 {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
impl CandidateFsIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        }
    }
}

/// One advisory lock and descriptor/path identity pin for a candidate run
/// root.  The lock is intentionally held for the whole process lifetime, so
/// two cooperating candidate owners cannot append to the same WAL namespace.
/// Every caller still has to treat an identity mismatch as a poisoned cut:
/// advisory locks cannot stop a hostile same-uid process from replacing a
/// pathname after validation.
#[cfg(unix)]
#[derive(Debug)]
struct CandidateRunRootGuardV1 {
    path: PathBuf,
    directory: File,
    identity: CandidateFsIdentityV1,
}

#[cfg(unix)]
impl CandidateRunRootGuardV1 {
    fn acquire(path: &Path) -> Result<Self, EffectDriverProcessErrorV1> {
        let directory = open_directory_no_follow_v1(path).map_err(|error| {
            EffectDriverProcessErrorV1::new("root", format!("open run-root descriptor: {error:?}"))
        })?;
        let descriptor_metadata = directory.metadata().map_err(|error| {
            EffectDriverProcessErrorV1::new("root", format!("stat run-root descriptor: {error:?}"))
        })?;
        ensure_private_root_metadata(path, &descriptor_metadata)?;
        let path_metadata = fs::symlink_metadata(path).map_err(|error| {
            EffectDriverProcessErrorV1::new("root", format!("stat run-root path: {error:?}"))
        })?;
        ensure_private_root_metadata(path, &path_metadata)?;
        let identity = CandidateFsIdentityV1::from_metadata(&descriptor_metadata);
        if CandidateFsIdentityV1::from_metadata(&path_metadata) != identity {
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                "run-root descriptor/path identity changed before locking",
            ));
        }
        if fs::canonicalize(path).map_err(|error| {
            EffectDriverProcessErrorV1::new("root", format!("canonicalize run-root: {error:?}"))
        })? != path
        {
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                "run-root path is a symlink alias",
            ));
        }
        if let Err(error) = FileExt::try_lock_exclusive(&directory) {
            let code = if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied
            ) {
                "root_busy"
            } else {
                "root_lock"
            };
            return Err(EffectDriverProcessErrorV1::new(
                code,
                format!("run-root lock: {error:?}"),
            ));
        }
        let guard = Self {
            path: path.to_path_buf(),
            directory,
            identity,
        };
        guard.validate_identity()?;
        Ok(guard)
    }

    fn validate_identity(&self) -> Result<(), EffectDriverProcessErrorV1> {
        let descriptor_metadata = self.directory.metadata().map_err(|error| {
            EffectDriverProcessErrorV1::new(
                "root",
                format!("stat held run-root descriptor: {error:?}"),
            )
        })?;
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            EffectDriverProcessErrorV1::new("root", format!("stat held run-root path: {error:?}"))
        })?;
        ensure_private_root_metadata(&self.path, &descriptor_metadata)?;
        ensure_private_root_metadata(&self.path, &path_metadata)?;
        if CandidateFsIdentityV1::from_metadata(&descriptor_metadata) != self.identity
            || CandidateFsIdentityV1::from_metadata(&path_metadata) != self.identity
            || fs::canonicalize(&self.path).map_err(|error| {
                EffectDriverProcessErrorV1::new(
                    "root",
                    format!("canonicalize held run-root: {error:?}"),
                )
            })? != self.path
        {
            return Err(EffectDriverProcessErrorV1::new(
                "root",
                "run-root descriptor/path identity changed",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for CandidateRunRootGuardV1 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.directory);
    }
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
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "candidate artifact must be an owner-private 0600 single-link regular file",
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

fn write_stdio_json_line<W: Write>(
    writer: &mut W,
    value: &Value,
) -> Result<(), EffectDriverProcessErrorV1> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        EffectDriverProcessErrorV1::new("stdio", format!("response serialization/write: {error:?}"))
    })?;
    writer.write_all(b"\n").map_err(|error| {
        EffectDriverProcessErrorV1::new("stdio", format!("response write: {error:?}"))
    })?;
    writer.flush().map_err(|error| {
        EffectDriverProcessErrorV1::new("stdio", format!("response flush: {error:?}"))
    })?;
    Ok(())
}

fn write_stdio_json_line_uncertain<W: Write>(
    writer: &mut W,
    value: &Value,
) -> Result<(), EffectDriverProcessErrorV1> {
    write_stdio_json_line(writer, value).map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous("stdio_response_uncertain", error.to_string())
    })?;
    Ok(())
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

enum BoundedStdioLineV1 {
    Complete(Vec<u8>),
    TooLarge,
}

/// Read one line without allowing `BufRead::read_line` to grow a buffer
/// without bound.  At most `maximum` bytes are retained; an oversized line is
/// drained (without allocation) through its newline so the next command keeps
/// its framing.
fn read_bounded_stdio_line_v1<R: BufRead>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<BoundedStdioLineV1>> {
    let mut line = Vec::with_capacity(maximum.min(8 * 1024));
    let mut total = 0usize;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if total == 0 {
                return Ok(None);
            }
            return Ok(Some(if total >= maximum {
                BoundedStdioLineV1::TooLarge
            } else {
                BoundedStdioLineV1::Complete(line)
            }));
        }

        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let available = newline.map_or(buffer.len(), |index| index + 1);
        let remaining = maximum.saturating_sub(total);
        if available <= remaining {
            line.extend_from_slice(&buffer[..available]);
            total += available;
            reader.consume(available);
            if newline.is_some() {
                return Ok(Some(BoundedStdioLineV1::Complete(line)));
            }
            continue;
        }

        // Keep only the bounded prefix, then discard the rest of this line.
        if remaining > 0 {
            line.extend_from_slice(&buffer[..remaining]);
            reader.consume(remaining);
        }
        drain_stdio_line_v1(reader)?;
        return Ok(Some(BoundedStdioLineV1::TooLarge));
    }
}

fn drain_stdio_line_v1<R: BufRead>(reader: &mut R) -> io::Result<()> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
            reader.consume(index + 1);
            return Ok(());
        }
        let length = buffer.len();
        reader.consume(length);
    }
}

/// Run the candidate process over line-delimited JSON stdin/stdout.
pub fn run_stdio_v1<R: BufRead, W: Write>(
    root: PathBuf,
    mut reader: R,
    mut writer: W,
) -> Result<EffectDriverProcessSummaryV1, EffectDriverProcessErrorV1> {
    fresh_root(&root)?;
    #[cfg(unix)]
    let root_guard = CandidateRunRootGuardV1::acquire(&root)?;
    atomic_replace(
        &root.join(ROOT_MARKER_V1),
        b"v=1\tprocess=candidate-effect-driver\tstate=fresh\n",
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("root", format!("start marker: {error:?}")))?;
    let mut driver = open_file_effect_driver_v1(&root)?;

    let mut shutdown = false;
    while let Some(line) =
        read_bounded_stdio_line_v1(&mut reader, EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1)?
    {
        let line = match line {
            BoundedStdioLineV1::Complete(bytes) => String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            BoundedStdioLineV1::TooLarge => {
                let response =
                    json!({"status":"rejected","reason":"frame_too_large","candidate_only":true});
                write_stdio_json_line(&mut writer, &response)?;
                continue;
            }
        };
        let raw = line.trim_end_matches(['\r', '\n']).as_bytes();
        if let Err(error) = validate_strict_json_structure_v0(raw) {
            let response = json!({"status":"rejected","reason":"malformed_json","detail":error.to_string(),"candidate_only":true});
            write_stdio_json_line(&mut writer, &response)?;
            continue;
        }
        let command = match serde_json::from_slice::<CommandV1>(raw) {
            Ok(command) => command,
            Err(error) => {
                let response = json!({"status":"rejected","reason":"unknown_command","detail":error.to_string(),"candidate_only":true});
                write_stdio_json_line(&mut writer, &response)?;
                continue;
            }
        };
        let response_may_follow_commit = matches!(
            &command,
            CommandV1::EnqueueTimeout { .. }
                | CommandV1::EnqueueSyncedProposal { .. }
                | CommandV1::EnqueueProposal { .. }
                | CommandV1::EnqueueAuthorityVote { .. }
                | CommandV1::Drive
        );

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
                    write_stdio_json_line_uncertain(&mut writer, &value)?;
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
                        write_stdio_json_line_uncertain(&mut writer, &value)?;
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
                        write_stdio_json_line_uncertain(&mut writer, &value)?;
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
                        write_stdio_json_line_uncertain(&mut writer, &value)?;
                        return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                    }
                }
            }
            CommandV1::Drive => match driver.drive_v1() {
                Ok(facts) => facts_json(facts, broadcast_count(&root)),
                Err(error) => {
                    let value = driver_error_json(&error);
                    write_stdio_json_line_uncertain(&mut writer, &value)?;
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
        if response_may_follow_commit {
            write_stdio_json_line_uncertain(&mut writer, &response)?;
        } else {
            write_stdio_json_line(&mut writer, &response)?;
        }
        if shutdown {
            break;
        }
    }

    #[cfg(unix)]
    root_guard.validate_identity()?;
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
fn payload_replay_body_root_v1(replay_path: &Path) -> Result<PathBuf, EffectDriverProcessErrorV1> {
    let name = replay_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            EffectDriverProcessErrorV1::new("p2p", "replay WAL requires a UTF-8 filename")
        })?;
    Ok(replay_path.with_file_name(format!(".{name}{P2P_REPLAY_BODY_DIRECTORY_SUFFIX_V1}")))
}

#[cfg(unix)]
fn ensure_payload_replay_body_root_v1(
    replay_path: &Path,
) -> Result<PathBuf, EffectDriverProcessErrorV1> {
    let body_root = payload_replay_body_root_v1(replay_path)?;
    match fs::symlink_metadata(&body_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.permissions().mode() & 0o7777 != 0o700
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || fs::canonicalize(&body_root).map_err(|error| {
                    EffectDriverProcessErrorV1::new(
                        "p2p_replay_body",
                        format!("canonicalize body store root: {error:?}"),
                    )
                })? != body_root
            {
                return Err(EffectDriverProcessErrorV1::new(
                    "p2p_replay_body",
                    "body store root is not an owner-private canonical directory",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&body_root).map_err(|error| {
                EffectDriverProcessErrorV1::new(
                    "p2p_replay_body",
                    format!("create body store root: {error:?}"),
                )
            })?;
            let directory = open_directory_no_follow_v1(&body_root).map_err(|error| {
                EffectDriverProcessErrorV1::new(
                    "p2p_replay_body",
                    format!("open body store root: {error:?}"),
                )
            })?;
            set_private_root_permissions(&directory).map_err(|error| {
                EffectDriverProcessErrorV1::new(
                    "p2p_replay_body",
                    format!("tighten body store root: {error:?}"),
                )
            })?;
        }
        Err(error) => {
            return Err(EffectDriverProcessErrorV1::new(
                "p2p_replay_body",
                format!("body store root metadata: {error:?}"),
            ))
        }
    }
    Ok(body_root)
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
    validate_unix_socket_path_length_v1(socket_path, "socket")?;
    validate_unix_socket_path_length_v1(lease_socket_path, "lease socket")?;

    let replay_name = replay_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            EffectDriverProcessErrorV1::new("p2p", "replay WAL requires a UTF-8 filename")
        })?;
    let replay_lock = replay_path.with_file_name(format!(".{replay_name}.lock-v1"));
    let replay_head = replay_path.with_file_name(format!(".{replay_name}.head-v1"));
    let replay_body_root = payload_replay_body_root_v1(replay_path)?;
    let candidate_paths = [
        socket_path.to_path_buf(),
        lease_socket_path.to_path_buf(),
        replay_path.to_path_buf(),
        replay_lock,
        replay_head,
        replay_body_root,
    ];
    for (index, left) in candidate_paths.iter().enumerate() {
        if candidate_paths[index + 1..]
            .iter()
            .any(|right| right == left)
        {
            return Err(EffectDriverProcessErrorV1::new(
                "p2p",
                "candidate socket/replay paths or replay sidecars collide",
            ));
        }
    }

    let root_artifacts = [
        ROOT_MARKER_V1,
        TRANSITION_WAL_V1,
        SAFETY_STATE_V1,
        CHECKPOINT_V1,
        OUTBOUND_WAL_V1,
        TIMER_WAL_V1,
        APPLICATION_WAL_V1,
        P2P_REPLAY_PENDING_V1,
    ]
    .map(|name| root.join(name));
    if candidate_paths.iter().any(|path| {
        path == root
            || path.starts_with(root)
            || root_artifacts.iter().any(|artifact| artifact == path)
    }) {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            "candidate socket/replay path must be outside the run root and its artifacts",
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
fn validate_unix_socket_path_length_v1(
    path: &Path,
    label: &'static str,
) -> Result<(), EffectDriverProcessErrorV1> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() > P2P_UNIX_SOCKET_PATH_MAX_BYTES_V1 {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            format!("{label} is empty, contains NUL, or exceeds the Unix sun_path limit"),
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
    // Reject an existing symlink alias before any caller opens or creates the
    // path.  Missing leaf components are fine (the owner may create them),
    // but the nearest existing prefix must have the exact lexical identity
    // supplied by the caller.
    let mut existing_prefix = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&existing_prefix) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !existing_prefix.pop() {
                    return Err(EffectDriverProcessErrorV1::new(
                        "p2p",
                        format!("{label} has no existing filesystem prefix"),
                    ));
                }
            }
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "p2p",
                    format!("{label} prefix metadata: {error:?}"),
                ));
            }
        }
    }
    let canonical_prefix = fs::canonicalize(&existing_prefix).map_err(|error| {
        EffectDriverProcessErrorV1::new("p2p", format!("{label} canonical prefix: {error:?}"))
    })?;
    if canonical_prefix != existing_prefix {
        return Err(EffectDriverProcessErrorV1::new(
            "p2p",
            format!("{label} contains a symlink alias"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct CandidateP2pSocketCleanupV1 {
    path: PathBuf,
    identity: Option<CandidateFsIdentityV1>,
    // Keep a descriptor clone alive until cleanup runs.  Otherwise the
    // original inode could be freed after the listener drops and a racing
    // replacement could (in principle) receive the same inode number.
    listener: Option<UnixListener>,
    armed: bool,
}

#[cfg(unix)]
impl CandidateP2pSocketCleanupV1 {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            identity: None,
            listener: None,
            armed: false,
        }
    }

    fn arm(&mut self, identity: CandidateFsIdentityV1, listener: &UnixListener) -> io::Result<()> {
        self.listener = Some(listener.try_clone()?);
        self.identity = Some(identity);
        self.armed = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for CandidateP2pSocketCleanupV1 {
    fn drop(&mut self) {
        if self.armed {
            cleanup_candidate_p2p_socket_v1(&self.path, self.identity);
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
    let root_guard = CandidateRunRootGuardV1::acquire(&root)?;
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
    // the listener and retains a descriptor clone, so its identity-pinned
    // unlink runs while the original inode is still held open.  This also
    // covers accept/read/write failures.
    let mut socket_cleanup = CandidateP2pSocketCleanupV1::new(socket_path.clone());
    let (listener, socket_identity) = bind_candidate_p2p_socket_v1(&socket_path)?;
    if let Err(error) = socket_cleanup.arm(socket_identity, &listener) {
        // The listener is still alive here, so identity-pinned cleanup cannot
        // be confused with an inode which a replacement process reclaimed.
        cleanup_candidate_p2p_socket_v1(&socket_path, Some(socket_identity));
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("pin listener: {error:?}"),
        ));
    }
    let mut stream = accept_candidate_p2p_v1(&listener)?;
    stream.set_nonblocking(true).map_err(|error| {
        EffectDriverProcessErrorV1::new("socket", format!("nonblocking: {error:?}"))
    })?;
    let operation_deadline = Instant::now()
        .checked_add(P2P_SOCKET_OPERATION_TIMEOUT_V1)
        .unwrap_or_else(Instant::now);

    let outcome = process_one_candidate_p2p_connection_v1(
        &mut stream,
        &mut driver,
        &root,
        namespace,
        lease_socket_path,
        replay_path,
        lease_generation,
        operation_deadline,
    );
    // Validate the root before emitting either response.  A namespace change
    // after durable work is always an uncertainty, so the peer must not see a
    // stale ordinary rejection that invites a duplicate retry.
    let outcome = match root_guard.validate_identity() {
        Ok(()) => outcome,
        Err(identity_error) => match outcome {
            Ok(_) => Err(EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_root_identity_uncertain",
                format!("run-root identity validation failed after operation: {identity_error}"),
            )),
            Err(error) if error.is_commit_ambiguous() => Err(error),
            Err(error) => Err(EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_root_identity_uncertain",
                format!("{error}; run-root identity validation failed: {identity_error}"),
            )),
        },
    };
    match outcome {
        Ok((response, summary)) => {
            write_p2p_socket_response_v1(&mut stream, response, operation_deadline).map_err(
                |error| {
                    EffectDriverProcessErrorV1::commit_ambiguous(
                        "p2p_response_uncertain",
                        error.to_string(),
                    )
                },
            )?;
            Ok(summary)
        }
        Err(error) => {
            let response = p2p_error_response_v1(&error);
            let _ = write_p2p_socket_response_v1(&mut stream, response, operation_deadline);
            Err(error)
        }
    }
}

#[cfg(unix)]
fn p2p_error_response_v1(error: &EffectDriverProcessErrorV1) -> Value {
    let commit_ambiguous = error.is_commit_ambiguous();
    json!({
        "status": if commit_ambiguous { "uncertain" } else { "rejected" },
        "reason": error.to_string(),
        "commit_ambiguous": commit_ambiguous,
        "replay_commit_state": if commit_ambiguous {
            "unknown_requires_recovery"
        } else {
            "not_admitted"
        },
        "candidate_only": true,
        "production_activation": false,
    })
}

#[cfg(unix)]
fn map_peer_lease_acquire_error_v1(error: PeerLeaseErrorV1) -> EffectDriverProcessErrorV1 {
    let detail = error.to_string();
    match error {
        // A decoded rejection is the daemon's explicit statement that the
        // acquire did not commit.  Any transport/protocol/local-shape error
        // may instead be a lost response after the daemon synced the lease.
        PeerLeaseErrorV1::Rejected(_) => EffectDriverProcessErrorV1::new("p2p_lease", detail),
        PeerLeaseErrorV1::InvalidRequest(_)
        | PeerLeaseErrorV1::Io(_)
        | PeerLeaseErrorV1::Protocol(_) => {
            EffectDriverProcessErrorV1::commit_ambiguous("p2p_lease_acquire_uncertain", detail)
        }
    }
}

#[cfg(unix)]
fn map_payload_replay_admit_error_v1(error: PayloadReplayErrorV1) -> EffectDriverProcessErrorV1 {
    let commit_ambiguous = error.commit_ambiguous();
    let detail = error.to_string();
    if commit_ambiguous {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_replay_admission_uncertain", detail)
    } else {
        EffectDriverProcessErrorV1::new("p2p_replay", detail)
    }
}

#[cfg(unix)]
fn map_payload_replay_body_error_v1(error: PayloadReplayBodyErrorV1) -> EffectDriverProcessErrorV1 {
    let detail = error.to_string();
    if error.commit_ambiguous() {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_replay_body_uncertain", detail)
    } else {
        EffectDriverProcessErrorV1::new("p2p_replay_body", detail)
    }
}

#[cfg(unix)]
fn finalize_p2p_post_acquire_error_v1(
    lease_guard: &mut CandidatePeerLeaseGuardV1,
    error: EffectDriverProcessErrorV1,
) -> EffectDriverProcessErrorV1 {
    // Once acquire has returned a token, every exit must make the release
    // outcome explicit.  A clean release proves that a pre-admission reject
    // did not leave a live lease; a failed release is itself an uncertain
    // commit boundary and must never be reported as an ordinary retryable
    // rejection.  For errors which already crossed replay/Core, preserve the
    // original uncertainty even when release succeeds.
    match lease_guard.release() {
        Ok(()) => error,
        Err(release_error) => EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_lease_release_uncertain",
            format!("{error}; lease release outcome is uncertain: {release_error}"),
        ),
    }
}

#[cfg(unix)]
fn validate_p2p_token_remaining_ttl_v1(
    token: PeerLeaseTokenV1,
) -> Result<(), EffectDriverProcessErrorV1> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_lease_acquire_uncertain",
                format!("system clock is before Unix epoch: {error}"),
            )
        })?
        .as_millis();
    let now_ms = u64::try_from(now_ms).map_err(|_| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_lease_acquire_uncertain",
            "system clock milliseconds overflow",
        )
    })?;
    let required_until = now_ms
        .checked_add(P2P_SOCKET_MIN_REMAINING_LEASE_MS_V1)
        .ok_or_else(|| {
            EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_lease_acquire_uncertain",
                "lease remaining-TTL bound overflow",
            )
        })?;
    if token.expires_at_ms() <= required_until {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_lease_acquire_uncertain",
            format!(
                "lease token has insufficient remaining TTL (expires_at_ms={}, now_ms={now_ms})",
                token.expires_at_ms()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_p2p_replay_pending_v1(
    root: &Path,
    frame: PayloadReplayFrameV1,
    driver_generation: u64,
) -> Result<(), EffectDriverProcessErrorV1> {
    // Publish the recovery breadcrumb before touching the replay WAL.  A
    // crash at any later cut therefore leaves an owner-visible record instead
    // of an apparently fresh root which invites an unsafe duplicate retry.
    let line = format!(
        "v=1\tstate=prepared\tremote={}\tdirection={}\tsession={}\tlease_generation={}\tsequence={}\tframe_kind={}\tpayload_len={}\tdriver_generation={}\tfingerprint={}\n",
        hex::encode(frame.scope().remote_id()),
        frame.scope().direction() as u8,
        hex::encode(frame.session_id()),
        frame.generation(),
        frame.sequence(),
        frame.frame_kind(),
        frame.payload_len(),
        driver_generation,
        hex::encode(frame.frame_fingerprint()),
    );
    atomic_replace(&root.join(P2P_REPLAY_PENDING_V1), line.as_bytes()).map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_recovery_pending_uncertain",
            format!("publish replay recovery breadcrumb: {error:?}"),
        )
    })
}

#[cfg(unix)]
fn clear_p2p_replay_pending_v1(root: &Path) -> Result<(), EffectDriverProcessErrorV1> {
    // Keep an empty, private file as the explicit acknowledged state.  The
    // next fresh-root preflight accepts it, while a non-empty record remains
    // a hard recovery stop.
    atomic_replace(&root.join(P2P_REPLAY_PENDING_V1), &[]).map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_recovery_pending_uncertain",
            format!("clear replay recovery breadcrumb: {error:?}"),
        )
    })
}

#[cfg(unix)]
// This candidate boundary keeps every authority/path/deadline input explicit;
// bundling them would obscure which values are caller-owned capabilities.
#[allow(clippy::too_many_arguments)]
fn process_one_candidate_p2p_connection_v1(
    stream: &mut UnixStream,
    driver: &mut FileEffectDriverV1,
    root: &Path,
    namespace: PayloadReplayNamespaceV1,
    lease_socket_path: PathBuf,
    replay_path: PathBuf,
    lease_generation: u64,
    operation_deadline: Instant,
) -> Result<(Value, EffectDriverProcessSummaryV1), EffectDriverProcessErrorV1> {
    let handshake = read_p2p_socket_record_v1(
        stream,
        P2P_SESSION_MAX_HANDSHAKE_BYTES_V0,
        operation_deadline,
    )?;
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
    let frame_bytes =
        read_p2p_socket_record_v1(stream, P2P_SOCKET_MAX_RECORD_BYTES_V1, operation_deadline)?;
    require_p2p_socket_eof_v1(stream, operation_deadline)?;
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

    let lease_authority = UnixPeerLeaseClientV1::connect(&lease_socket_path)
        .with_timeout(P2P_SOCKET_READ_TIMEOUT_V1)
        .with_deadline(operation_deadline);
    lease_authority
        .preflight()
        .map_err(|error| EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()))?;
    let token = match lease_authority.acquire(
        scope,
        session_id,
        lease_generation,
        P2P_SOCKET_LEASE_TTL_MS_V1,
    ) {
        Ok(token) => token,
        Err(error) => {
            let mapped = map_peer_lease_acquire_error_v1(error);
            if !mapped.is_commit_ambiguous() {
                return Err(mapped);
            }
            // Acquire is idempotent for an exact session/generation tuple.
            // A single bounded retry recovers a token when the daemon
            // durably appended the first request but its response was lost;
            // if the retry also fails, retain the original uncertainty and
            // require the recovery owner to inspect the authority journal.
            match lease_authority.acquire(
                scope,
                session_id,
                lease_generation,
                P2P_SOCKET_LEASE_TTL_MS_V1,
            ) {
                Ok(token) => token,
                Err(_) => return Err(mapped),
            }
        }
    };
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
        return Err(finalize_p2p_post_acquire_error_v1(
            &mut lease_guard,
            EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_lease_acquire_uncertain",
                "authority returned a token with mismatched scope or generation",
            ),
        ));
    }
    if let Err(error) = validate_p2p_token_remaining_ttl_v1(token) {
        return Err(finalize_p2p_post_acquire_error_v1(&mut lease_guard, error));
    }

    let mut replay = match PayloadReplayStoreV1::open(&replay_path, namespace) {
        Ok(replay) => replay,
        Err(error) => {
            return Err(finalize_p2p_post_acquire_error_v1(
                &mut lease_guard,
                EffectDriverProcessErrorV1::new("p2p_replay", error.to_string()),
            ));
        }
    };
    let body_root = match ensure_payload_replay_body_root_v1(&replay_path) {
        Ok(path) => path,
        Err(error) => return Err(finalize_p2p_post_acquire_error_v1(&mut lease_guard, error)),
    };
    let mut body_store = match PayloadReplayBodyStoreV1::open(&body_root, namespace) {
        Ok(store) => store,
        Err(error) => {
            return Err(finalize_p2p_post_acquire_error_v1(
                &mut lease_guard,
                map_payload_replay_body_error_v1(error),
            ))
        }
    };

    // Revalidate immediately before the payload append.  The external lease
    // daemon and this WAL are intentionally separate owners; if the lease is
    // fenced in this interval, no Core input is exposed.
    let revalidated = match lease_guard.revalidate() {
        Ok(token) => token,
        Err(error) => {
            return Err(finalize_p2p_post_acquire_error_v1(
                &mut lease_guard,
                EffectDriverProcessErrorV1::new("p2p_lease", error.to_string()),
            ));
        }
    };
    if revalidated != token {
        return Err(finalize_p2p_post_acquire_error_v1(
            &mut lease_guard,
            EffectDriverProcessErrorV1::new(
                "p2p_lease",
                "lease revalidation changed the exact token",
            ),
        ));
    }
    if let Err(error) = validate_p2p_token_remaining_ttl_v1(revalidated) {
        return Err(finalize_p2p_post_acquire_error_v1(&mut lease_guard, error));
    }

    let driver_facts = driver.facts_v1();
    if driver_facts.queue_depth() >= driver_facts.queue_capacity() {
        return Err(finalize_p2p_post_acquire_error_v1(
            &mut lease_guard,
            EffectDriverProcessErrorV1::new(
                "p2p_queue",
                "Core ingress queue has no capacity before durable replay admission",
            ),
        ));
    }
    let driver_generation = driver_facts
        .generation()
        .checked_add(driver_facts.queue_depth() as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            finalize_p2p_post_acquire_error_v1(
                &mut lease_guard,
                EffectDriverProcessErrorV1::new("p2p_queue", "Core generation overflow"),
            )
        })?;
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
    .map_err(|error| {
        finalize_p2p_post_acquire_error_v1(
            &mut lease_guard,
            EffectDriverProcessErrorV1::new("p2p_replay", error.to_string()),
        )
    })?;
    if let Err(error) = prepare_p2p_replay_pending_v1(root, replay_frame, driver_generation) {
        return Err(finalize_p2p_post_acquire_error_v1(&mut lease_guard, error));
    }
    let receipt = match replay.admit(&replay_frame) {
        Ok(receipt) => receipt,
        Err(error) => {
            let mapped = map_payload_replay_admit_error_v1(error);
            // A validation/replay reject is known to have happened before a
            // durable append, so remove the prepared breadcrumb before
            // returning.  If clearing it fails, retain uncertainty.
            let mapped = if mapped.is_commit_ambiguous() {
                mapped
            } else {
                match clear_p2p_replay_pending_v1(root) {
                    Ok(()) => mapped,
                    Err(clear_error) => clear_error,
                }
            };
            return Err(finalize_p2p_post_acquire_error_v1(&mut lease_guard, mapped));
        }
    };

    // The metadata WAL and the exact authenticated bytes are separate durable
    // owners.  Persist the bytes before exposing the typed input to Core; a
    // failure here is explicitly uncertain and leaves the replay breadcrumb
    // for the external recovery owner rather than dropping the only source
    // body after a successful WAL append.
    let body_receipt = body_store
        .put(replay_frame, receipt, &frame_bytes)
        .map_err(map_payload_replay_body_error_v1)
        .map_err(|error| finalize_p2p_post_acquire_error_v1(&mut lease_guard, error))?;

    // Close the second half of the lease/WAL race before handing the typed
    // value to Core.  A failed check leaves a durable replay tombstone but no
    // consensus transition, which is the safe liveness tradeoff here.
    let revalidated_after_append = lease_guard.revalidate().map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_post_replay_uncertain", error.to_string())
    })?;
    if revalidated_after_append != token {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            "lease was fenced after durable replay admission",
        ));
    }
    // Replay admission and Core delivery are separate durable boundaries.  A
    // slow WAL/fsync or a stalled local scheduler can consume the lease's
    // remaining TTL after the first check; do not hand an input to Core unless
    // the exact lease is still valid for the complete enqueue/drive window.
    validate_p2p_token_remaining_ttl_v1(revalidated_after_append).map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            format!("lease remaining TTL expired before Core delivery: {error}"),
        )
    })?;
    let admission = driver
        .enqueue_authenticated_peer_input_v1(driver_generation, accepted.0)
        .map_err(|error| {
            EffectDriverProcessErrorV1::commit_ambiguous(
                "p2p_post_replay_uncertain",
                error.to_string(),
            )
        })?;
    if !matches!(admission, CandidateEffectDriverAdmissionV1::Accepted { .. }) {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            format!("unexpected Core ingress admission: {admission:?}"),
        ));
    }
    // Enqueue itself can cross a scheduler/IPC boundary.  Re-check the
    // authority immediately before driving Core so an expiry or fence in
    // that interval is surfaced as uncertainty rather than a clean success.
    let revalidated_before_drive = lease_guard.revalidate().map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_post_replay_uncertain", error.to_string())
    })?;
    if revalidated_before_drive != token {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            "lease was fenced after Core enqueue and before drive",
        ));
    }
    validate_p2p_token_remaining_ttl_v1(revalidated_before_drive).map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            format!("lease remaining TTL expired before Core drive: {error}"),
        )
    })?;
    let facts = driver.drive_v1().map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_post_replay_uncertain", error.to_string())
    })?;
    // The drive call is synchronous but not interruptible by the socket
    // deadline.  Revalidate once more before releasing the lease so an
    // expiry/fence during Core processing is surfaced as an uncertain result
    // and cannot be mistaken for a fully fenced success.
    let revalidated_after_drive = lease_guard.revalidate().map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous("p2p_post_replay_uncertain", error.to_string())
    })?;
    if revalidated_after_drive != token {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            "lease was fenced during Core drive",
        ));
    }
    if let Err(error) = validate_p2p_token_remaining_ttl_v1(revalidated_after_drive) {
        return Err(EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_post_replay_uncertain",
            format!("lease expired during Core drive: {error}"),
        ));
    }
    lease_guard.release().map_err(|error| {
        EffectDriverProcessErrorV1::commit_ambiguous(
            "p2p_lease_release_uncertain",
            error.to_string(),
        )
    })?;
    clear_p2p_replay_pending_v1(root)?;

    let response = json!({
        "status": "accepted",
        "peer_id": hex::encode(peer_id),
        "session_id": hex::encode(token.session_id()),
        "sequence": accepted.2,
        "lease_generation": token.generation(),
        "replay_record_index": receipt.record_index(),
        "replay_record_hash": hex::encode(receipt.record_hash()),
        "replay_body_digest": hex::encode(body_receipt.body_digest()),
        "replay_body_len": body_receipt.body_len(),
        "replay_body_idempotent": body_receipt.idempotent_replay(),
        "replay_commit_state": "admitted_not_core_committed",
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
    deadline: Instant,
) -> Result<Vec<u8>, EffectDriverProcessErrorV1> {
    let mut header = [0u8; P2P_SOCKET_RECORD_HEADER_BYTES_V1];
    read_p2p_exact_until_v1(stream, &mut header, deadline, "record header")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("record length {length} exceeds bound {maximum}"),
        ));
    }
    let mut bytes = vec![0u8; length];
    read_p2p_exact_until_v1(stream, &mut bytes, deadline, "record body")?;
    Ok(bytes)
}

#[cfg(unix)]
fn require_p2p_socket_eof_v1(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(), EffectDriverProcessErrorV1> {
    let mut trailing = [0u8; 1];
    loop {
        ensure_p2p_deadline_v1(deadline, "peer did not half-close")?;
        match stream.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    "trailing bytes or records after the single candidate frame",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep_until_p2p_deadline_v1(deadline, "peer did not half-close")?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("trailing-byte check: {error:?}"),
                ));
            }
        }
    }
}

#[cfg(unix)]
fn write_p2p_socket_response_v1(
    stream: &mut UnixStream,
    response: Value,
    deadline: Instant,
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
    write_p2p_all_until_v1(stream, &length.to_be_bytes(), deadline, "response header")?;
    write_p2p_all_until_v1(stream, &bytes, deadline, "response body")?;
    loop {
        ensure_p2p_deadline_v1(deadline, "response flush")?;
        match stream.flush() {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep_until_p2p_deadline_v1(deadline, "response flush")?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("response flush: {error:?}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn p2p_timeout_error_v1(detail: &str) -> EffectDriverProcessErrorV1 {
    EffectDriverProcessErrorV1::new("socket", detail)
}

#[cfg(unix)]
fn sleep_until_p2p_deadline_v1(
    deadline: Instant,
    detail: &str,
) -> Result<(), EffectDriverProcessErrorV1> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| p2p_timeout_error_v1(detail))?;
    std::thread::sleep(remaining.min(Duration::from_millis(10)));
    Ok(())
}

#[cfg(unix)]
fn read_p2p_exact_until_v1(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<(), EffectDriverProcessErrorV1> {
    let mut offset = 0;
    while offset < buffer.len() {
        ensure_p2p_deadline_v1(deadline, label)?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("{label}: unexpected EOF"),
                ));
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep_until_p2p_deadline_v1(deadline, label)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("{label}: {error:?}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_p2p_all_until_v1(
    stream: &mut UnixStream,
    buffer: &[u8],
    deadline: Instant,
    label: &str,
) -> Result<(), EffectDriverProcessErrorV1> {
    let mut offset = 0;
    while offset < buffer.len() {
        ensure_p2p_deadline_v1(deadline, label)?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("{label}: zero-byte write"),
                ));
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep_until_p2p_deadline_v1(deadline, label)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(EffectDriverProcessErrorV1::new(
                    "socket",
                    format!("{label}: {error:?}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_p2p_deadline_v1(
    deadline: Instant,
    detail: &str,
) -> Result<(), EffectDriverProcessErrorV1> {
    if Instant::now() >= deadline {
        return Err(p2p_timeout_error_v1(detail));
    }
    Ok(())
}

#[cfg(unix)]
fn bind_candidate_p2p_socket_v1(
    path: &Path,
) -> Result<(UnixListener, CandidateFsIdentityV1), EffectDriverProcessErrorV1> {
    validate_narrow_absolute_path_v1(path, "socket")?;
    let parent = path.parent().ok_or_else(|| {
        EffectDriverProcessErrorV1::new("socket", "candidate socket has no parent")
    })?;
    validate_directory_ancestry_v1(parent, "socket parent", 2, false)?;
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
    let bound_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(listener);
            return Err(EffectDriverProcessErrorV1::new(
                "socket",
                format!("stat bound socket: {error:?}"),
            ));
        }
    };
    if !bound_metadata.file_type().is_socket() {
        drop(listener);
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            "bind did not produce a Unix socket path",
        ));
    }
    let identity = CandidateFsIdentityV1::from_metadata(&bound_metadata);
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        cleanup_candidate_p2p_socket_v1(path, Some(identity));
        drop(listener);
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            format!("permissions: {error:?}"),
        ));
    }
    let post_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            cleanup_candidate_p2p_socket_v1(path, Some(identity));
            drop(listener);
            return Err(EffectDriverProcessErrorV1::new(
                "socket",
                format!("stat socket after permissions: {error:?}"),
            ));
        }
    };
    if !post_metadata.file_type().is_socket()
        || CandidateFsIdentityV1::from_metadata(&post_metadata) != identity
        || post_metadata.permissions().mode() & 0o7777 != 0o600
    {
        // Never remove a replacement socket/path: cleanup is pinned to the
        // device/inode observed immediately after bind.
        cleanup_candidate_p2p_socket_v1(path, Some(identity));
        drop(listener);
        return Err(EffectDriverProcessErrorV1::new(
            "socket",
            "socket path identity changed during bind setup",
        ));
    }
    Ok((listener, identity))
}

#[cfg(unix)]
fn cleanup_candidate_p2p_socket_v1(path: &Path, expected: Option<CandidateFsIdentityV1>) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if !metadata.file_type().is_socket() {
        return;
    }
    if let Some(expected) = expected {
        if CandidateFsIdentityV1::from_metadata(&metadata) != expected {
            return;
        }
    }
    let _ = fs::remove_file(path);
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
        os::unix::net::UnixListener,
    };

    #[test]
    fn fresh_root_sets_private_mode_on_new_and_existing_roots() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
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
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
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

    #[test]
    fn fresh_root_rejects_symlink_and_writable_ancestors() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");

        let real = parent.path().join("real");
        fs::create_dir(&real).expect("real ancestor");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))
            .expect("private real ancestor");
        let alias = parent.path().join("alias");
        symlink(&real, &alias).expect("ancestor symlink");
        let symlink_root = alias.join("run");
        let error = fresh_root(&symlink_root).expect_err("symlink ancestor must fail closed");
        assert!(error.to_string().contains("symlink"));
        assert!(!real.join("run").exists());

        let broad = parent.path().join("broad");
        fs::create_dir(&broad).expect("broad ancestor");
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o777))
            .expect("broad ancestor mode");
        let broad_root = broad.join("run");
        let error = fresh_root(&broad_root).expect_err("writable ancestor must fail closed");
        assert!(error.to_string().contains("writable"));
        assert!(!broad_root.exists());
    }

    #[test]
    fn fresh_root_tightens_all_new_directory_components() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let root = parent.path().join("new").join("nested").join("run");
        fresh_root(&root).expect("new nested root is accepted");
        for path in [
            parent.path().join("new"),
            parent.path().join("new").join("nested"),
            root.clone(),
        ] {
            assert_eq!(
                fs::symlink_metadata(&path)
                    .expect("new directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700,
                "new directory {} must be private",
                path.display()
            );
        }
    }

    #[test]
    fn fresh_root_rejects_unknown_state_inventory() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let root = parent.path().join("run");
        fs::create_dir(&root).expect("run root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private run root");
        let unknown = root.join("stale-owner-state");
        fs::write(&unknown, b"stale").expect("unknown state");
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600))
            .expect("private unknown state");
        let error = fresh_root(&root).expect_err("unknown inventory must fail closed");
        assert!(error.to_string().contains("recovery_required"));
        assert!(
            unknown.exists(),
            "preflight must not destroy recovery evidence"
        );
    }

    #[test]
    fn run_root_lock_is_exclusive_and_identity_pinned() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let root = parent.path().join("run");
        fresh_root(&root).expect("root is accepted");
        let first = CandidateRunRootGuardV1::acquire(&root).expect("first owner lock");
        let second = CandidateRunRootGuardV1::acquire(&root)
            .expect_err("second owner must not share the run root");
        assert!(
            second.to_string().contains("root_busy"),
            "unexpected lock error: {second}"
        );
        first.validate_identity().expect("held root identity");

        // Replacing the pathname while the original descriptor is retained
        // must poison the guard rather than silently blessing the replacement.
        let moved = parent.path().join("moved");
        fs::rename(&root, &moved).expect("move original root");
        fs::create_dir(&root).expect("replacement root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("replacement root mode");
        assert!(
            first.validate_identity().is_err(),
            "root replacement must fail the descriptor/path identity check"
        );
        drop(first);
        fs::remove_dir(&root).expect("remove replacement root");
        fs::rename(&moved, &root).expect("restore original root");
        let replacement = CandidateRunRootGuardV1::acquire(&root).expect("lock after release");
        replacement
            .validate_identity()
            .expect("replacement owner identity");
    }

    #[test]
    fn socket_cleanup_does_not_unlink_a_replacement_inode() {
        let parent = tempfile::tempdir().expect("temporary socket parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private socket parent");
        let path = parent.path().join("candidate.sock");
        let (listener, identity) =
            bind_candidate_p2p_socket_v1(&path).expect("candidate socket bind");
        // A pathname must be unlinked before a second listener can claim it;
        // this models a same-uid replacement racing with the cleanup guard.
        fs::remove_file(&path).expect("remove original socket pathname");
        let replacement = UnixListener::bind(&path).expect("replacement socket bind");
        cleanup_candidate_p2p_socket_v1(&path, Some(identity));
        assert!(
            fs::symlink_metadata(&path)
                .expect("replacement metadata")
                .file_type()
                .is_socket(),
            "cleanup must leave a replacement socket inode in place"
        );
        drop(listener);
        drop(replacement);
        fs::remove_file(&path).expect("remove replacement socket");
    }

    #[test]
    fn stdio_line_reader_bounds_oversized_input_and_preserves_framing() {
        use std::io::Cursor;

        let mut input = vec![b'x'; EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1 + 1];
        input.push(b'\n');
        input.extend_from_slice(b"{\"command\":\"shutdown\"}\n");
        let mut reader = Cursor::new(input);
        assert!(matches!(
            read_bounded_stdio_line_v1(&mut reader, EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1)
                .expect("bounded read"),
            Some(BoundedStdioLineV1::TooLarge)
        ));
        let next =
            read_bounded_stdio_line_v1(&mut reader, EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1)
                .expect("framed follow-up read");
        assert!(matches!(
            next,
            Some(BoundedStdioLineV1::Complete(bytes))
                if bytes.as_slice() == b"{\"command\":\"shutdown\"}\n"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn p2p_frame_io_uses_one_absolute_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().expect("socket pair");
        reader.set_nonblocking(true).expect("nonblocking reader");
        writer.set_nonblocking(true).expect("nonblocking writer");
        let expired = Instant::now();
        let mut byte = [0u8; 1];
        let read_error = read_p2p_exact_until_v1(&mut reader, &mut byte, expired, "drip read")
            .expect_err("expired frame read must fail closed");
        assert!(read_error.to_string().contains("drip read"));
        let write_error = write_p2p_all_until_v1(&mut writer, &[1], expired, "drip write")
            .expect_err("expired frame write must fail closed");
        assert!(write_error.to_string().contains("drip write"));
    }

    #[test]
    fn p2p_parameter_validation_rejects_path_collisions_aliases_and_long_sockets() {
        let root = PathBuf::from("/tmp/trnm-poco-parameter-root");
        let socket = PathBuf::from("/tmp/trnm-poco-candidate.sock");
        let lease_socket = PathBuf::from("/tmp/trnm-poco-lease.sock");
        let replay = PathBuf::from("/tmp/trnm-poco-replay.wal");
        validate_p2p_socket_parameters_v1(&root, &socket, &lease_socket, &replay, "run-1", 1)
            .expect("distinct bounded paths are accepted");

        assert!(
            validate_p2p_socket_parameters_v1(&root, &socket, &replay, &replay, "run-1", 1,)
                .is_err()
        );

        let artifact = root.join(ROOT_MARKER_V1);
        assert!(validate_p2p_socket_parameters_v1(
            &root,
            &artifact,
            &lease_socket,
            &replay,
            "run-1",
            1,
        )
        .is_err());

        let nested_replay = root.join("untracked-replay.wal");
        assert!(validate_p2p_socket_parameters_v1(
            &root,
            &socket,
            &lease_socket,
            &nested_replay,
            "run-1",
            1,
        )
        .is_err());

        let long_socket =
            PathBuf::from("/tmp").join("s".repeat(P2P_UNIX_SOCKET_PATH_MAX_BYTES_V1 + 1));
        assert!(validate_p2p_socket_parameters_v1(
            &root,
            &long_socket,
            &lease_socket,
            &replay,
            "run-1",
            1,
        )
        .is_err());

        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let real = parent.path().join("real");
        fs::create_dir(&real).expect("real directory");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("real directory mode");
        symlink(&real, parent.path().join("alias")).expect("directory alias");
        let aliased_socket = parent.path().join("alias").join("candidate.sock");
        assert!(validate_p2p_socket_parameters_v1(
            &parent.path().join("run"),
            &aliased_socket,
            &parent.path().join("lease.sock"),
            &parent.path().join("replay.wal"),
            "run-1",
            1,
        )
        .is_err());
    }

    #[test]
    fn p2p_commit_boundary_errors_are_reported_as_uncertain() {
        let definitive = map_peer_lease_acquire_error_v1(PeerLeaseErrorV1::Rejected(
            trnm_consensus_peer_lease::LeaseRejectCodeV1::AlreadyLeased,
        ));
        assert!(!definitive.is_commit_ambiguous());
        assert_eq!(p2p_error_response_v1(&definitive)["status"], "rejected");
        assert_eq!(
            p2p_error_response_v1(&definitive)["commit_ambiguous"],
            false
        );

        // A transport/protocol failure can be the lost response after the
        // daemon synced the acquire record.  It must not be collapsed into a
        // normal rejection which invites an unsafe generation retry.
        let acquire_io = map_peer_lease_acquire_error_v1(PeerLeaseErrorV1::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "response lost",
        )));
        assert!(acquire_io.is_commit_ambiguous());
        assert_eq!(p2p_error_response_v1(&acquire_io)["status"], "uncertain");
        assert_eq!(p2p_error_response_v1(&acquire_io)["commit_ambiguous"], true);

        let replay_io = map_payload_replay_admit_error_v1(PayloadReplayErrorV1::CommitAmbiguous(
            Box::new(PayloadReplayErrorV1::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "head publication interrupted",
            ))),
        ));
        assert!(replay_io.is_commit_ambiguous());
        assert_eq!(p2p_error_response_v1(&replay_io)["status"], "uncertain");
        assert_eq!(p2p_error_response_v1(&replay_io)["commit_ambiguous"], true);

        // Validation/replay rejects happen before the WAL append and retain
        // the ordinary rejected response semantics.
        let replay_reject = map_payload_replay_admit_error_v1(PayloadReplayErrorV1::Replay);
        assert!(!replay_reject.is_commit_ambiguous());
        assert_eq!(p2p_error_response_v1(&replay_reject)["status"], "rejected");
        assert_eq!(
            p2p_error_response_v1(&replay_reject)["commit_ambiguous"],
            false
        );
    }

    #[test]
    fn pending_replay_breadcrumb_blocks_fresh_owner_until_acknowledged() {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let root = parent.path().join("run");
        fresh_root(&root).expect("fresh root");
        let scope = PeerLeaseScopeV1::new(
            [1; 32],
            [2; 32],
            PayloadReplayDirectionV1::Inbound,
            1,
            [3; 32],
        )
        .expect("scope");
        let frame =
            PayloadReplayFrameV1::new(scope, [4; 32], [5; 32], [6; 32], 1, 0, 1, 16, [7; 32])
                .expect("frame");
        prepare_p2p_replay_pending_v1(&root, frame, 1).expect("prepare breadcrumb");
        assert_eq!(
            fs::symlink_metadata(root.join(P2P_REPLAY_PENDING_V1))
                .expect("pending metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        let blocked = fresh_root(&root).expect_err("pending replay must require recovery");
        assert!(blocked.to_string().contains("recovery"));
        clear_p2p_replay_pending_v1(&root).expect("ack breadcrumb");
        fresh_root(&root).expect("empty acknowledged breadcrumb is reusable");
    }
}
