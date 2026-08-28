#![cfg(unix)]
#![forbid(unsafe_code)]

//! Candidate-only G1-R2 replay-to-Core durable-delivery coordinator.
//!
//! The first half of this compilation unit is the R2-A recoverable
//! pending/ack/completion state machine. The sealed `CandidateCoreIngressV1`
//! below is the R2-B probe: it drives a real in-process `Core` through the
//! non-voting synced-proposal path and canonical SafetyState codec, but its
//! proposal body is synthetic fixture material and it has no production or
//! restart/process authority. Keeping the probe in this trusted boundary
//! lets the receipt constructor stay private while the source/evidence tuple
//! remains explicitly candidate-only.

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use ed25519_dalek::{Signer, SigningKey};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    decode_safety_state_record_v0_exact, encode_safety_state_record_v0, BlockIdOverlayRefV0, Core,
    CoreConfig, CoreIssuedApplicationSealAuthorityV0, Effect, Input, NativeValidPostAckActionV0,
    PayloadValidationRouteV0, SafetyState, SafetyStatePersistenceV0, SafetyStateRecordContextV0,
    SafetyStateRecordLimitsV0, ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_peer_lease::{
    PayloadReplayCoreAcknowledgementV1, PayloadReplayNamespaceV1, PayloadReplayRecoveryErrorV1,
    PayloadReplayRecoveryOwnerV1, PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
    BlockKind, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height,
    ProposalWitnessV0, ProtocolVersion, QcReferenceV0, Signature64, SignedProposalV0, StateRoot,
    Validator, ValidatorId, ValidatorSet, View, VotingPower,
};

const PRIVATE_DIRECTORY_MODE_V1: u32 = 0o700;
const PRIVATE_FILE_MODE_V1: u32 = 0o600;
const LOCK_NAME_V1: &str = ".replay-to-core.lock-v1";

const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.namespace.v1";
const TARGET_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.target.v1";
const REQUEST_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.request.v1";
const IDEMPOTENCY_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.idempotency.v1";
const PENDING_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.pending-record.v1";
const COMPLETED_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.completed-record.v1";
const CORE_INPUT_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.core-input.v1";
const CORE_STATE_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.core-state.v1";
const CORE_ACK_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.core-ack.v1";

const PENDING_MAGIC_V1: [u8; 8] = *b"TRNR2PN1";
const COMPLETED_MAGIC_V1: [u8; 8] = *b"TRNR2CM1";
const RECORD_VERSION_V1: u8 = 1;
const PENDING_PREFIX_BYTES_V1: usize = 244;
const PENDING_BYTES_V1: usize = PENDING_PREFIX_BYTES_V1 + 32;
const COMPLETED_PREFIX_BYTES_V1: usize = 316;
const COMPLETED_BYTES_V1: usize = COMPLETED_PREFIX_BYTES_V1 + 32;
const CORE_INPUT_MAGIC_V1: [u8; 8] = *b"TRNR2IN1";
const CORE_STATE_MAGIC_V1: [u8; 8] = *b"TRNR2CS1";
const CORE_INPUT_NAME_V1: &str = "core-input.v1";
const CORE_STATE_NAME_V1: &str = "core-state.v1";
const CORE_PREDECESSOR_NAME_V1: &str = "core-predecessor.v1";
const CORE_LOCK_NAME_V1: &str = ".core-ingress.lock-v1";
const CORE_OBLIGATION_NAME_V1: &str = "core-safety-obligation.record";
const CORE_DELIVERY_NAME_V1: &str = "core-safety-delivery.record";
const CORE_VERIFIER_PROFILE_REF_V1: [u8; 32] = [0xC7; 32];
const CORE_INPUT_PREAUTH_DOMAIN_V1: &str = "trnm.consensus-core.preauthentication-input.v0";
const CORE_INPUT_RECORD_PREFIX_BYTES_V1: usize = 204;
const CORE_INPUT_RECORD_BYTES_V1: usize = CORE_INPUT_RECORD_PREFIX_BYTES_V1 + 32;
// The state fact includes the canonical codec checksum of the durable
// SafetyState record.  This is an unkeyed integrity checksum for accidental
// corruption only; it is not an authentication tag against a same-UID writer.
const CORE_STATE_RECORD_PREFIX_BYTES_V1: usize = 276;
const CORE_STATE_RECORD_BYTES_V1: usize = CORE_STATE_RECORD_PREFIX_BYTES_V1 + 32;

static TEMP_NONCE_V1: AtomicU64 = AtomicU64::new(0);

pub const REPLAY_TO_CORE_COORDINATOR_CANDIDATE_V1: bool = true;
pub const REPLAY_TO_CORE_PENDING_BEFORE_CORE_V1: bool = true;
pub const REPLAY_TO_CORE_SEALED_AUTHORITY_V1: bool = true;
pub const REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = false;
pub const REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = false;
pub const REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false;
pub const REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = false;
pub const REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = false;
/// Candidate process-owned durability seam; this is not a live consensus
/// Core adapter and does not alter any production truth flag.
pub const REPLAY_TO_CORE_DURABLE_INGRESS_JOURNAL_CANDIDATE_V1: bool = true;
/// The probe below calls the real Core library in a sealed, feature-gated
/// candidate owner. It is deliberately distinct from the live-adapter and
/// production flags above until authenticated body resolution and process
/// restart evidence are available.
pub const REPLAY_TO_CORE_REAL_CORE_INGRESS_CANDIDATE_V1: bool = true;
pub const REPLAY_TO_CORE_FAULT_CUT_MATRIX_CANDIDATE_V1: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreReplayRequestV1 {
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
    target_digest: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    request_digest: [u8; 32],
    idempotency_key: [u8; 32],
}

impl CoreReplayRequestV1 {
    fn new(
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
        input_digest: [u8; 32],
        predecessor_checkpoint: [u8; 32],
    ) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        if input_digest == [0; 32] || predecessor_checkpoint == [0; 32] {
            return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "Core input and predecessor checkpoint digests must be nonzero",
            ));
        }
        let namespace_digest = payload_namespace_digest(namespace);
        let target_digest = payload_target_digest(target);
        let request_digest = replay_request_digest(
            namespace_digest,
            target_digest,
            input_digest,
            predecessor_checkpoint,
        );
        let idempotency_key = replay_idempotency_key(request_digest);
        Ok(Self {
            namespace_digest,
            target,
            target_digest,
            input_digest,
            predecessor_checkpoint,
            request_digest,
            idempotency_key,
        })
    }

    pub const fn target(self) -> PayloadReplayRecoveryTargetV1 {
        self.target
    }

    pub const fn namespace_digest(self) -> [u8; 32] {
        self.namespace_digest
    }

    pub const fn target_digest(self) -> [u8; 32] {
        self.target_digest
    }

    pub const fn input_digest(self) -> [u8; 32] {
        self.input_digest
    }

    pub const fn predecessor_checkpoint(self) -> [u8; 32] {
        self.predecessor_checkpoint
    }

    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }
}

/// A receipt that can be constructed only inside this compilation unit.
/// The candidate owner below may call this constructor only after the real
/// Core D transition has been persisted, decoded and semantically checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDurableReplayReceiptV1 {
    target_digest: [u8; 32],
    idempotency_key: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
}

impl CoreDurableReplayReceiptV1 {
    // Keep this constructor private: neither an RPC caller nor a generic
    // callback can mint a durable-Core fact from inert revision/digest data.
    #[cfg_attr(not(test), allow(dead_code))]
    fn new_after_durable_core(
        request: CoreReplayRequestV1,
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
    ) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        if core_safety_revision == 0 || core_ack_digest == [0; 32] {
            return Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch);
        }
        Ok(Self {
            target_digest: request.target_digest,
            idempotency_key: request.idempotency_key,
            predecessor_checkpoint: request.predecessor_checkpoint,
            core_safety_revision,
            core_ack_digest,
        })
    }

    fn validate_for(
        self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        if self.target_digest != request.target_digest
            || self.idempotency_key != request.idempotency_key
            || self.predecessor_checkpoint != request.predecessor_checkpoint
            || self.core_safety_revision == 0
            || self.core_ack_digest == [0; 32]
        {
            return Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch);
        }
        Ok(())
    }
}

mod sealed {
    pub trait SealedReplayToCoreAuthorityV1 {}
}

/// Sealed on purpose.  A generic caller cannot implement this trait and mint
/// a durable-Core fact.  R2-B must add the concrete implementation in this
/// trusted compilation boundary.
pub trait ReplayToCoreAuthorityV1: sealed::SealedReplayToCoreAuthorityV1 {
    fn deliver_durably(
        &mut self,
        request: CoreReplayRequestV1,
    ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDeliveryErrorV1 {
    reason: &'static str,
}

impl CoreDeliveryErrorV1 {
    #[cfg_attr(not(test), allow(dead_code))]
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for CoreDeliveryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for CoreDeliveryErrorV1 {}

/// Fault cuts for the candidate Core/process adapter.  The first four cuts
/// are inside the Core input and SafetyState persistence boundary; replay-ack
/// and completion cuts remain owned by [`ReplayToCoreCoordinatorV1`].  A cut
/// is consumed once and leaves its durable evidence in place, so a caller
/// must reopen/reconcile before retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReplayFaultCutV1 {
    /// Stop before handing the internally owned proposal to Core.
    BeforeCoreInput,
    /// Core accepted the proposal, but its first SafetyState record was not
    /// persisted yet.
    CoreAcceptedBeforePersistence,
    /// The SafetyState record was fsynced, but this owner did not complete its
    /// read-back check.
    PersistenceBeforeReadback,
    /// The exact Core state was read back, but no replay receipt was minted.
    ReadbackBeforeReplayAck,
}

impl CoreReplayFaultCutV1 {
    const fn reason(self) -> &'static str {
        match self {
            Self::BeforeCoreInput => "fault cut before Core input",
            Self::CoreAcceptedBeforePersistence => {
                "fault cut after Core input acceptance before SafetyState persistence"
            }
            Self::PersistenceBeforeReadback => {
                "fault cut after SafetyState persistence before durable readback"
            }
            Self::ReadbackBeforeReplayAck => {
                "fault cut after durable Core readback before replay acknowledgement"
            }
        }
    }
}

/// Exact scalar facts retained by the candidate Core ingress journal.  The
/// canonical SafetyState itself is persisted through Core's schema-13 codec;
/// these facts bind the replay request to the internally owned proposal and
/// make an idempotent response independent of volatile Core memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreIngressFactsV1 {
    request_digest: [u8; 32],
    target_digest: [u8; 32],
    idempotency_key: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    core_input_digest: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    core_state_record_checksum: [u8; 32],
}

impl CoreIngressFactsV1 {
    fn from_request(
        request: CoreReplayRequestV1,
        core_input_digest: [u8; 32],
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
        core_state_record_checksum: [u8; 32],
    ) -> Result<Self, CoreDeliveryErrorV1> {
        if core_input_digest == [0; 32]
            || core_safety_revision == 0
            || core_ack_digest == [0; 32]
            || core_state_record_checksum == [0; 32]
        {
            return Err(CoreDeliveryErrorV1::new(
                "candidate Core ingress facts must be nonzero",
            ));
        }
        Ok(Self {
            request_digest: request.request_digest,
            target_digest: request.target_digest,
            idempotency_key: request.idempotency_key,
            input_digest: request.input_digest,
            predecessor_checkpoint: request.predecessor_checkpoint,
            core_input_digest,
            core_safety_revision,
            core_ack_digest,
            core_state_record_checksum,
        })
    }

    fn matches_request(self, request: CoreReplayRequestV1) -> bool {
        self.request_digest == request.request_digest
            && self.target_digest == request.target_digest
            && self.idempotency_key == request.idempotency_key
            && self.input_digest == request.input_digest
            && self.predecessor_checkpoint == request.predecessor_checkpoint
    }
}

/// Candidate-only Core/process owner.  It owns one real `Core` instance and
/// one Core-issued application seal capability.  The proposal body is a
/// deterministic fixture derived from the request input digest; this makes
/// the boundary executable today while keeping the live adapter flag false:
/// production replay must instead resolve an authenticated body from the
/// node's replay journal before calling `Core::step`.
pub struct CandidateCoreIngressV1 {
    root: PathBuf,
    directory: File,
    _lock: File,
    core: Core,
    application_seal_authority: CoreIssuedApplicationSealAuthorityV0,
    fault_cut: Option<CoreReplayFaultCutV1>,
    calls: u64,
}

impl fmt::Debug for CandidateCoreIngressV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateCoreIngressV1")
            .field("root", &self.root)
            .field("fault_cut", &self.fault_cut)
            .field("calls", &self.calls)
            .field("core_revision", &self.core.safety_state().revision())
            .finish_non_exhaustive()
    }
}

impl CandidateCoreIngressV1 {
    /// Opens a private process-owned Core ingress root.  The predecessor
    /// checkpoint is pinned on first open and must match on every later open.
    pub fn open(
        root: impl AsRef<Path>,
        predecessor_checkpoint: [u8; 32],
    ) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        if predecessor_checkpoint == [0; 32] {
            return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "Core ingress predecessor checkpoint must be nonzero",
            ));
        }
        let root = root.as_ref().to_path_buf();
        validate_private_root(&root)?;
        let directory = File::open(&root)?;
        let lock_path = root.join(CORE_LOCK_NAME_V1);
        let lock = open_or_create_private_file(&lock_path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(ReplayToCoreCoordinatorErrorV1::Busy)
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
        let checkpoint_path = root.join(CORE_PREDECESSOR_NAME_V1);
        reconcile_private_temp_if_final(&directory, &checkpoint_path)?;
        match fs::symlink_metadata(&checkpoint_path) {
            Ok(_) => {
                let bytes = read_private_exact(&checkpoint_path, 32)?;
                if bytes.as_slice() != predecessor_checkpoint {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                write_private_atomic_new(&directory, &checkpoint_path, &predecessor_checkpoint)?;
                directory.sync_all()?;
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }

        let core = build_candidate_core_v1().map_err(|_| {
            ReplayToCoreCoordinatorErrorV1::CoreDelivery(CoreDeliveryErrorV1::new(
                "candidate Core construction failed",
            ))
        })?;
        let application_seal_authority =
            core.issue_application_seal_authority_v0().map_err(|_| {
                ReplayToCoreCoordinatorErrorV1::CoreDelivery(CoreDeliveryErrorV1::new(
                    "candidate application seal authority unavailable",
                ))
            })?;
        Ok(Self {
            root,
            directory,
            _lock: lock,
            core,
            application_seal_authority,
            fault_cut: None,
            calls: 0,
        })
    }

    pub fn set_fault_cut(&mut self, cut: Option<CoreReplayFaultCutV1>) {
        self.fault_cut = cut;
    }

    pub const fn calls(&self) -> u64 {
        self.calls
    }

    pub const fn core_revision(&self) -> u64 {
        self.core.safety_state().revision()
    }

    fn consume_fault(&mut self, expected: CoreReplayFaultCutV1) -> bool {
        if self.fault_cut == Some(expected) {
            self.fault_cut = None;
            true
        } else {
            false
        }
    }

    /// Rebuilds the candidate Core from its deterministic genesis fixture.
    ///
    /// The candidate adapter is intentionally process-local, so a restart (or
    /// a retry after an injected crash cut) must not pretend that its in-memory
    /// Core state survived.  Durable phase records are replayed from genesis
    /// and compared byte-for-byte by `write_safety_state` before the next
    /// barrier is acknowledged.
    fn rebuild_core(&mut self) -> Result<(), CoreDeliveryErrorV1> {
        let core = build_candidate_core_v1()
            .map_err(|_| CoreDeliveryErrorV1::new("candidate Core reconstruction failed"))?;
        let application_seal_authority =
            core.issue_application_seal_authority_v0().map_err(|_| {
                CoreDeliveryErrorV1::new("candidate application seal authority unavailable")
            })?;
        self.core = core;
        self.application_seal_authority = application_seal_authority;
        Ok(())
    }

    fn predecessor_matches(&self, request: CoreReplayRequestV1) -> Result<(), CoreDeliveryErrorV1> {
        let path = self.root.join(CORE_PREDECESSOR_NAME_V1);
        reconcile_private_temp_if_final(&self.directory, &path).map_err(|_| {
            CoreDeliveryErrorV1::new("Core predecessor temporary publication is ambiguous")
        })?;
        let bytes = read_private_exact(&path, 32)
            .map_err(|_| CoreDeliveryErrorV1::new("Core predecessor checkpoint read failed"))?;
        if bytes.as_slice() != request.predecessor_checkpoint {
            return Err(CoreDeliveryErrorV1::new(
                "whole-node predecessor checkpoint changed",
            ));
        }
        Ok(())
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(CORE_STATE_NAME_V1)
    }

    fn input_path(&self) -> PathBuf {
        self.root.join(CORE_INPUT_NAME_V1)
    }

    fn persisted_facts(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<Option<CoreIngressFactsV1>, CoreDeliveryErrorV1> {
        let input_path = self.input_path();
        let state_path = self.state_path();
        let predecessor_path = self.root.join(CORE_PREDECESSOR_NAME_V1);
        let obligation_path = self.root.join(CORE_OBLIGATION_NAME_V1);
        let delivery_path = self.root.join(CORE_DELIVERY_NAME_V1);
        for path in [
            input_path.clone(),
            state_path.clone(),
            predecessor_path.clone(),
            obligation_path.clone(),
            delivery_path.clone(),
        ] {
            reconcile_private_temp_if_final(&self.directory, &path).map_err(|_| {
                CoreDeliveryErrorV1::new("Core ingress temporary publication is ambiguous")
            })?;
        }
        let input_present = private_path_present(&input_path)?;
        let state_present = private_path_present(&state_path)?;
        let obligation_present = private_path_present(&obligation_path)?;
        let delivery_present = private_path_present(&delivery_path)?;
        // Phase records form a strict prefix.  An orphaned obligation or
        // delivery is not safe to reinterpret as a fresh request after a
        // restart: require the authenticated same-request recovery owner
        // instead of silently overwriting a missing breadcrumb.
        if state_present {
            if !input_present || !obligation_present || !delivery_present {
                return Err(CoreDeliveryErrorV1::new(
                    "Core ingress state exists without its complete durable phase prefix",
                ));
            }
        } else if !matches!(
            (input_present, obligation_present, delivery_present),
            (false, false, false) | (true, false, false) | (true, true, false) | (true, true, true)
        ) {
            return Err(CoreDeliveryErrorV1::new(
                "Core ingress durable phase records are not a contiguous prefix",
            ));
        }

        let path = state_path;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = read_private_exact(&path, CORE_STATE_RECORD_BYTES_V1)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core ingress state is corrupt"))?;
                let facts = decode_core_ingress_facts(&bytes)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core ingress state is corrupt"))?;
                if !facts.matches_request(request) {
                    return Err(CoreDeliveryErrorV1::new(
                        "Core ingress state conflicts with the exact replay request",
                    ));
                }
                let input = read_private_exact(&self.input_path(), CORE_INPUT_RECORD_BYTES_V1)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core ingress input is corrupt"))?;
                let input = decode_core_ingress_input(&input)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core ingress input is corrupt"))?;
                let expected = expected_candidate_transition_v1(request)?;
                if input.request_digest != request.request_digest
                    || input.target_digest != request.target_digest
                    || input.idempotency_key != request.idempotency_key
                    || input.input_digest != request.input_digest
                    || input.predecessor_checkpoint != request.predecessor_checkpoint
                    || input.core_input_digest != facts.core_input_digest
                    || input.core_input_digest != expected.core_input_digest
                {
                    return Err(CoreDeliveryErrorV1::new(
                        "Core ingress input does not match the sealed receipt facts",
                    ));
                }
                let delivery = read_private_record(&delivery_path)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core delivery record is corrupt"))?;
                let (delivery_state, delivery_checksum) = self
                    .decode_validated_state_record(&delivery, facts.core_safety_revision)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core delivery record is invalid"))?;
                let delivery_revision = delivery_state.revision();
                if delivery_revision != facts.core_safety_revision
                    || delivery_checksum != facts.core_state_record_checksum
                {
                    return Err(CoreDeliveryErrorV1::new(
                        "Core delivery record does not match the sealed receipt facts",
                    ));
                }
                let obligation = read_private_record(&obligation_path)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core obligation record is corrupt"))?;
                let (obligation_state, _) = self
                    .decode_validated_state_record(&obligation, 1)
                    .map_err(|_| CoreDeliveryErrorV1::new("Core obligation record is invalid"))?;
                if obligation_state.revision().checked_add(1) != Some(delivery_revision) {
                    return Err(CoreDeliveryErrorV1::new(
                        "Core obligation and delivery revisions are not consecutive",
                    ));
                }
                Core::validate_persisted_successor_v0(
                    self.core.config(),
                    &obligation_state,
                    &delivery_state,
                    &StrictEd25519Verifier,
                )
                .map_err(|_| {
                    CoreDeliveryErrorV1::new(
                        "Core obligation and delivery are not a valid persisted successor",
                    )
                })?;
                if obligation_state != expected.obligation_state
                    || delivery_state != expected.delivery_state
                    || facts.core_safety_revision != expected.delivery_state.revision()
                    || facts.core_ack_digest
                        != candidate_core_ack_digest_v1(
                            request,
                            &delivery,
                            expected.delivery_digest,
                        )
                {
                    return Err(CoreDeliveryErrorV1::new(
                        "Core durable states do not bind the exact candidate request transition",
                    ));
                }
                Ok(Some(facts))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(CoreDeliveryErrorV1::new("Core ingress state lookup failed")),
        }
    }

    fn write_safety_state(
        &self,
        persistence: &SafetyStatePersistenceV0,
        slot: &'static str,
    ) -> Result<Vec<u8>, CoreDeliveryErrorV1> {
        let limits = SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .map_err(|_| CoreDeliveryErrorV1::new("invalid SafetyState record limits"))?;
        let context = SafetyStateRecordContextV0::new(
            self.core.config(),
            CORE_VERIFIER_PROFILE_REF_V1,
            limits,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("SafetyState record context rejected"))?;
        let bytes = encode_safety_state_record_v0(persistence.state(), &context)
            .map_err(|_| CoreDeliveryErrorV1::new("SafetyState encoding failed"))?;
        let path = self.root.join(slot);
        write_private_atomic_new(&self.directory, &path, &bytes).map_err(|_| {
            CoreDeliveryErrorV1::new("SafetyState persistence or reconciliation failed")
        })?;
        Ok(bytes)
    }

    fn readback_safety_state(
        &self,
        persistence: &SafetyStatePersistenceV0,
        slot: &'static str,
        expected_len: usize,
    ) -> Result<Vec<u8>, CoreDeliveryErrorV1> {
        let limits = SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .map_err(|_| CoreDeliveryErrorV1::new("invalid SafetyState record limits"))?;
        let context = SafetyStateRecordContextV0::new(
            self.core.config(),
            CORE_VERIFIER_PROFILE_REF_V1,
            limits,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("SafetyState record context rejected"))?;
        let path = self.root.join(slot);
        let reread = read_private_exact(&path, expected_len)
            .map_err(|_| CoreDeliveryErrorV1::new("SafetyState durable readback failed"))?;
        let decoded = decode_safety_state_record_v0_exact(&reread, &context)
            .map_err(|_| CoreDeliveryErrorV1::new("SafetyState decode/readback failed"))?;
        if decoded.state() != persistence.state() {
            return Err(CoreDeliveryErrorV1::new(
                "SafetyState typed readback differs from Core",
            ));
        }
        Core::validate_persisted_state_v0(
            self.core.config(),
            decoded.state(),
            &StrictEd25519Verifier,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("SafetyState semantic readback validation failed"))?;
        Ok(reread)
    }

    fn validate_persisted_state_record(
        &self,
        bytes: &[u8],
        expected_revision: u64,
    ) -> Result<(u64, [u8; 32]), CoreDeliveryErrorV1> {
        let (state, checksum) = self.decode_validated_state_record(bytes, expected_revision)?;
        Ok((state.revision(), checksum))
    }

    fn decode_validated_state_record(
        &self,
        bytes: &[u8],
        expected_revision: u64,
    ) -> Result<(SafetyState, [u8; 32]), CoreDeliveryErrorV1> {
        let limits = SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .map_err(|_| CoreDeliveryErrorV1::new("invalid SafetyState record limits"))?;
        let context = SafetyStateRecordContextV0::new(
            self.core.config(),
            CORE_VERIFIER_PROFILE_REF_V1,
            limits,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("SafetyState record context rejected"))?;
        let decoded = decode_safety_state_record_v0_exact(bytes, &context)
            .map_err(|_| CoreDeliveryErrorV1::new("SafetyState record decode failed"))?;
        if decoded.state().revision() != expected_revision {
            return Err(CoreDeliveryErrorV1::new(
                "SafetyState record revision differs from the expected Core barrier",
            ));
        }
        Core::validate_persisted_state_v0(
            self.core.config(),
            decoded.state(),
            &StrictEd25519Verifier,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("SafetyState semantic validation failed"))?;
        Ok((decoded.state().clone(), decoded.record_checksum()))
    }

    fn persist_safety_state(
        &self,
        persistence: &SafetyStatePersistenceV0,
        slot: &'static str,
    ) -> Result<Vec<u8>, CoreDeliveryErrorV1> {
        let bytes = self.write_safety_state(persistence, slot)?;
        self.readback_safety_state(persistence, slot, bytes.len())
    }

    fn deliver_real_candidate(
        &mut self,
        request: CoreReplayRequestV1,
    ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1> {
        self.predecessor_matches(request)?;
        if self.consume_fault(CoreReplayFaultCutV1::BeforeCoreInput) {
            return Err(CoreDeliveryErrorV1::new(
                CoreReplayFaultCutV1::BeforeCoreInput.reason(),
            ));
        }

        // The exact request is first made durable as an ingress breadcrumb.
        // This is the candidate's private replacement for the authenticated
        // replay journal lookup which the production node still lacks.
        let proposal = fixture_proposal_for_input_v1(&self.core, request)?;
        // Replay is deliberately admitted through Core's non-voting synced
        // route.  A replay must install/validate the exact body and advance
        // the durable delivery boundary without staging a local Vote.
        let core_input = Input::SyncedProposal(Box::new(proposal.clone()));
        let core_input_digest = candidate_core_input_digest_v1(&core_input);
        let input_bytes = encode_core_ingress_input(request, core_input_digest);
        write_private_atomic_new(&self.directory, &self.input_path(), &input_bytes).map_err(
            |_| CoreDeliveryErrorV1::new("Core ingress input persistence or reconciliation failed"),
        )?;

        let effects = self
            .core
            .step(core_input, &StrictEd25519Verifier)
            .map_err(|_| CoreDeliveryErrorV1::new("Core rejected the replay proposal"))?;
        let obligation = match effects.as_slice() {
            [Effect::PersistSafetyState(value)] => value.clone(),
            _ => {
                return Err(CoreDeliveryErrorV1::new(
                    "Core replay input emitted an unexpected effect set",
                ))
            }
        };
        if self.consume_fault(CoreReplayFaultCutV1::CoreAcceptedBeforePersistence) {
            return Err(CoreDeliveryErrorV1::new(
                CoreReplayFaultCutV1::CoreAcceptedBeforePersistence.reason(),
            ));
        }
        let obligation_bytes = self.write_safety_state(&obligation, CORE_OBLIGATION_NAME_V1)?;
        if self.consume_fault(CoreReplayFaultCutV1::PersistenceBeforeReadback) {
            return Err(CoreDeliveryErrorV1::new(
                CoreReplayFaultCutV1::PersistenceBeforeReadback.reason(),
            ));
        }
        self.readback_safety_state(&obligation, CORE_OBLIGATION_NAME_V1, obligation_bytes.len())?;
        let released = self
            .core
            .step(
                Input::StorageAck {
                    barrier: obligation.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                CoreDeliveryErrorV1::new("Core rejected the SafetyState acknowledgement")
            })?;
        let Some(Effect::ValidateSyncedPayload(validation)) = released.first() else {
            return Err(CoreDeliveryErrorV1::new(
                "Core did not expose the exact Synced replay validation request",
            ));
        };
        if released.len() != 1
            || validation.route() != PayloadValidationRouteV0::Synced
            || validation.id()
                != ValidationId::new(proposal.block().id(), proposal.block().header().view(), 1)
            || validation.block() != proposal.block()
            || !validation.parent().is_legacy_trusted_genesis_v0()
            || validation.parent().tip() != self.core.safety_state().finalized()
            || validation.parent_binding_ref_v0().is_err()
        {
            return Err(CoreDeliveryErrorV1::new(
                "Core replay validation request identity or parent binding differs",
            ));
        }
        let validation = match released.into_iter().next() {
            Some(Effect::ValidateSyncedPayload(value)) => value,
            _ => unreachable!("the exact validation effect shape was checked"),
        };
        let (route, id, block, parent, permit) = validation
            .try_claim()
            .map_err(|_| CoreDeliveryErrorV1::new("Core validation request claim failed"))?
            .into_parts();
        if route != PayloadValidationRouteV0::Synced
            || id != ValidationId::new(proposal.block().id(), proposal.block().header().view(), 1)
            || block != *proposal.block()
            || !parent.is_legacy_trusted_genesis_v0()
            || parent.tip() != self.core.safety_state().finalized()
        {
            return Err(CoreDeliveryErrorV1::new(
                "claimed Core replay validation identity or parent differs",
            ));
        }
        let commitments = validated_commitments_for_candidate_block_v1(&self.core, &block)?;
        let artifact_ref = artifact_ref_for_candidate_block_v1(&block);
        let seal = self
            .application_seal_authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact_ref);
        let accepted = self
            .core
            .step_application_sealed_valid_to_delivery_v0(&seal, &StrictEd25519Verifier)
            .map_err(|_| CoreDeliveryErrorV1::new("Core Valid delivery failed"))?;
        let delivery_persistence = accepted.persistence_request_v0().clone();
        if accepted.route_v0() != PayloadValidationRouteV0::Synced
            || accepted.validation_id_v0()
                != ValidationId::new(proposal.block().id(), proposal.block().header().view(), 1)
            || delivery_persistence.native_valid_post_ack_action_v0()
                != Some(NativeValidPostAckActionV0::None)
            || delivery_persistence
                .native_finalization_applied_v0()
                .is_some()
        {
            return Err(CoreDeliveryErrorV1::new(
                "Core delivery carrier exposed an unexpected route or side effect",
            ));
        }
        let delivery_bytes =
            self.persist_safety_state(&delivery_persistence, CORE_DELIVERY_NAME_V1)?;
        if self.consume_fault(CoreReplayFaultCutV1::ReadbackBeforeReplayAck) {
            return Err(CoreDeliveryErrorV1::new(
                CoreReplayFaultCutV1::ReadbackBeforeReplayAck.reason(),
            ));
        }
        let delivery_effects = self
            .core
            .step(
                Input::StorageAck {
                    barrier: delivery_persistence.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                CoreDeliveryErrorV1::new("Core delivery persistence acknowledgement failed")
            })?;
        if !delivery_effects.is_empty() {
            return Err(CoreDeliveryErrorV1::new(
                "Core delivery acknowledgement emitted unexpected effects",
            ));
        }
        self.predecessor_matches(request)?;
        let ack_digest =
            candidate_core_ack_digest_v1(request, &delivery_bytes, accepted.delivery_digest_v0());
        let (_, delivery_checksum) = self.validate_persisted_state_record(
            &delivery_bytes,
            delivery_persistence.state().revision(),
        )?;
        let facts = CoreIngressFactsV1::from_request(
            request,
            core_input_digest,
            delivery_persistence.state().revision(),
            ack_digest,
            delivery_checksum,
        )?;
        let bytes = encode_core_ingress_facts(facts);
        write_private_atomic_new(&self.directory, &self.state_path(), &bytes).map_err(|_| {
            CoreDeliveryErrorV1::new(
                "Core ingress receipt state persistence or reconciliation failed",
            )
        })?;
        let reread = read_private_exact(&self.state_path(), CORE_STATE_RECORD_BYTES_V1)
            .map_err(|_| CoreDeliveryErrorV1::new("Core ingress receipt state readback failed"))?;
        if decode_core_ingress_facts(&reread)
            .map_err(|_| CoreDeliveryErrorV1::new("Core ingress receipt state corrupt"))?
            != facts
        {
            return Err(CoreDeliveryErrorV1::new(
                "Core ingress receipt state readback mismatch",
            ));
        }
        CoreDurableReplayReceiptV1::new_after_durable_core(
            request,
            facts.core_safety_revision,
            facts.core_ack_digest,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("Core durable receipt construction failed"))
    }
}

impl sealed::SealedReplayToCoreAuthorityV1 for CandidateCoreIngressV1 {}

impl ReplayToCoreAuthorityV1 for CandidateCoreIngressV1 {
    fn deliver_durably(
        &mut self,
        request: CoreReplayRequestV1,
    ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1> {
        self.calls = self.calls.saturating_add(1);
        self.predecessor_matches(request)?;
        if let Some(facts) = self.persisted_facts(request)? {
            return CoreDurableReplayReceiptV1::new_after_durable_core(
                request,
                facts.core_safety_revision,
                facts.core_ack_digest,
            )
            .map_err(|_| CoreDeliveryErrorV1::new("persisted Core receipt is invalid"));
        }
        // No sealed facts exist yet.  Reconstruct the process-local Core so a
        // retry after any uncertain cut starts from the same deterministic
        // predecessor and can reconcile phase records idempotently.
        self.rebuild_core()?;
        self.deliver_real_candidate(request)
    }
}

#[derive(Debug)]
pub enum ReplayToCoreCoordinatorErrorV1 {
    InvalidRequest(&'static str),
    Io(io::Error),
    Busy,
    Corrupt,
    Conflict,
    EarlierDeliveryPending,
    AmbiguousPublication,
    ReplayRecovery(Box<PayloadReplayRecoveryErrorV1>),
    CoreDelivery(CoreDeliveryErrorV1),
    CoreReceiptMismatch,
    PayloadPublicationNotDurable,
}

impl fmt::Display for ReplayToCoreCoordinatorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => formatter.write_str(reason),
            Self::Io(error) => write!(formatter, "replay-to-Core I/O error: {error}"),
            Self::Busy => formatter.write_str("replay-to-Core coordinator is busy"),
            Self::Corrupt => formatter.write_str("replay-to-Core coordinator state is corrupt"),
            Self::Conflict => {
                formatter.write_str("replay-to-Core request conflicts with durable state")
            }
            Self::EarlierDeliveryPending => {
                formatter.write_str("an earlier replay-to-Core target remains unresolved")
            }
            Self::AmbiguousPublication => {
                formatter.write_str("replay-to-Core completion publication is ambiguous")
            }
            Self::ReplayRecovery(error) => write!(
                formatter,
                "payload replay recovery rejected the transition: {error}"
            ),
            Self::CoreDelivery(error) => write!(formatter, "Core delivery failed: {error}"),
            Self::CoreReceiptMismatch => {
                formatter.write_str("Core durable receipt does not bind the exact pending request")
            }
            Self::PayloadPublicationNotDurable => {
                formatter.write_str("payload publication is not durable after bounded recovery")
            }
        }
    }
}

impl Error for ReplayToCoreCoordinatorErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ReplayRecovery(error) => Some(error.as_ref()),
            Self::CoreDelivery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ReplayToCoreCoordinatorErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayToCoreCompletionReceiptV1 {
    request_digest: [u8; 32],
    idempotency_key: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    replay_ack_hash: [u8; 32],
    idempotent_replay: bool,
}

impl ReplayToCoreCompletionReceiptV1 {
    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn core_safety_revision(self) -> u64 {
        self.core_safety_revision
    }

    pub const fn core_ack_digest(self) -> [u8; 32] {
        self.core_ack_digest
    }

    pub const fn replay_ack_hash(self) -> [u8; 32] {
        self.replay_ack_hash
    }

    pub const fn idempotent_replay(self) -> bool {
        self.idempotent_replay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFactsV1 {
    namespace_digest: [u8; 32],
    target_digest: [u8; 32],
    record_index: u64,
    record_hash: [u8; 32],
    frame_fingerprint: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    idempotency_key: [u8; 32],
}

impl PendingFactsV1 {
    fn from_request(request: CoreReplayRequestV1) -> Self {
        let target = request.target;
        Self {
            namespace_digest: request.namespace_digest,
            target_digest: request.target_digest,
            record_index: target.record_index(),
            record_hash: target.record_hash(),
            frame_fingerprint: target.frame_fingerprint(),
            input_digest: request.input_digest,
            predecessor_checkpoint: request.predecessor_checkpoint,
            idempotency_key: request.idempotency_key,
        }
    }

    fn matches(self, request: CoreReplayRequestV1) -> bool {
        self == Self::from_request(request)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompletedFactsV1 {
    pending: PendingFactsV1,
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    replay_ack_hash: [u8; 32],
}

impl CompletedFactsV1 {
    fn receipt(
        self,
        request: CoreReplayRequestV1,
        idempotent_replay: bool,
    ) -> ReplayToCoreCompletionReceiptV1 {
        ReplayToCoreCompletionReceiptV1 {
            request_digest: request.request_digest,
            idempotency_key: request.idempotency_key,
            core_safety_revision: self.core_safety_revision,
            core_ack_digest: self.core_ack_digest,
            replay_ack_hash: self.replay_ack_hash,
            idempotent_replay,
        }
    }
}

#[derive(Debug)]
pub struct ReplayToCoreCoordinatorV1 {
    root: PathBuf,
    directory: File,
    _lock: File,
}

impl ReplayToCoreCoordinatorV1 {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        let root = root.as_ref().to_path_buf();
        validate_private_root(&root)?;
        let directory = File::open(&root)?;
        let lock_path = root.join(LOCK_NAME_V1);
        let lock = open_or_create_private_file(&lock_path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(ReplayToCoreCoordinatorErrorV1::Busy)
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
        Ok(Self {
            root,
            directory,
            _lock: lock,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn drive<A: ReplayToCoreAuthorityV1>(
        &mut self,
        authority: &mut A,
        payload_wal: impl AsRef<Path>,
        replay_ack_root: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
        core_input_digest: [u8; 32],
        predecessor_checkpoint: [u8; 32],
    ) -> Result<ReplayToCoreCompletionReceiptV1, ReplayToCoreCoordinatorErrorV1> {
        let request =
            CoreReplayRequestV1::new(namespace, target, core_input_digest, predecessor_checkpoint)?;
        self.reject_retained_completion_temporaries()?;

        if let Some(completed) = self.read_completed_if_present(request)? {
            self.reconcile_pending_residue(request)?;
            return Ok(completed.receipt(request, true));
        }

        self.reject_other_pending_targets(request)?;
        self.ensure_pending(request)?;

        let mut replay_owner =
            PayloadReplayRecoveryOwnerV1::open(payload_wal, replay_ack_root, namespace, target)
                .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;

        let mut status = replay_owner
            .status()
            .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;
        if status.payload_publication_recoverable() {
            status = replay_owner
                .recover_payload_publication()
                .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;
        }

        let completed = match status {
            PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                core_safety_revision,
                core_ack_digest,
                acknowledgement_hash,
                ..
            } => CompletedFactsV1 {
                pending: PendingFactsV1::from_request(request),
                core_safety_revision,
                core_ack_digest,
                replay_ack_hash: acknowledgement_hash,
            },
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. } => {
                let core_receipt = authority
                    .deliver_durably(request)
                    .map_err(ReplayToCoreCoordinatorErrorV1::CoreDelivery)?;
                core_receipt.validate_for(request)?;
                let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(
                    target,
                    core_receipt.core_safety_revision,
                    core_receipt.core_ack_digest,
                )
                .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;
                let replay_receipt =
                    replay_owner
                        .acknowledge_core(acknowledgement)
                        .map_err(|error| {
                            ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error))
                        })?;
                CompletedFactsV1 {
                    pending: PendingFactsV1::from_request(request),
                    core_safety_revision: core_receipt.core_safety_revision,
                    core_ack_digest: core_receipt.core_ack_digest,
                    replay_ack_hash: replay_receipt.acknowledgement_hash(),
                }
            }
            PayloadReplayRecoveryStatusV1::RecoverableHeadLag { .. }
            | PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries { .. } => {
                return Err(ReplayToCoreCoordinatorErrorV1::PayloadPublicationNotDurable)
            }
        };

        self.publish_completed(request, completed)?;
        Ok(completed.receipt(request, false))
    }

    fn pending_path(&self, request: CoreReplayRequestV1) -> PathBuf {
        self.root.join(format!(
            "pending-{:020}-{}.v1",
            request.target.record_index(),
            hex32(request.target.record_hash())
        ))
    }

    fn completed_path(&self, request: CoreReplayRequestV1) -> PathBuf {
        self.root.join(format!(
            "completed-{:020}-{}.v1",
            request.target.record_index(),
            hex32(request.target.record_hash())
        ))
    }

    fn ensure_pending(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let path = self.pending_path(request);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let facts = read_pending(&path)?;
                if !facts.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let bytes = encode_pending(PendingFactsV1::from_request(request));
                write_private_new(&path, &bytes)?;
                self.directory.sync_all()?;
                Ok(())
            }
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn reject_other_pending_targets(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let expected = self.pending_path(request);
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            };
            if name.starts_with("pending-") && name.ends_with(".v1") {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || !private_regular_file(&metadata) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
                }
                if entry.path() != expected {
                    return Err(ReplayToCoreCoordinatorErrorV1::EarlierDeliveryPending);
                }
            }
        }
        Ok(())
    }

    fn reject_retained_completion_temporaries(&self) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            };
            if name.starts_with(".completed-") && name.contains(".tmp-") {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || !matches!(metadata.nlink(), 1 | 2)
                    || metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE_V1
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
                }
                return Err(ReplayToCoreCoordinatorErrorV1::AmbiguousPublication);
            }
        }
        Ok(())
    }

    fn read_completed_if_present(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<Option<CompletedFactsV1>, ReplayToCoreCoordinatorErrorV1> {
        let path = self.completed_path(request);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let completed = read_completed(&path)?;
                if !completed.pending.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                Ok(Some(completed))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn reconcile_pending_residue(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let pending_path = self.pending_path(request);
        match fs::symlink_metadata(&pending_path) {
            Ok(_) => {
                let pending = read_pending(&pending_path)?;
                if !pending.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                fs::remove_file(pending_path)?;
                self.directory.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn publish_completed(
        &self,
        request: CoreReplayRequestV1,
        completed: CompletedFactsV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        if !completed.pending.matches(request)
            || completed.core_safety_revision == 0
            || completed.core_ack_digest == [0; 32]
            || completed.replay_ack_hash == [0; 32]
        {
            return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
        }
        if let Some(existing) = self.read_completed_if_present(request)? {
            if existing != completed {
                return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
            }
            return self.reconcile_pending_residue(request);
        }

        let final_path = self.completed_path(request);
        let final_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "completed path requires a UTF-8 filename",
            ))?;
        let temporary = final_path.with_file_name(format!(
            ".{final_name}.tmp-{}-{}",
            std::process::id(),
            TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = encode_completed(completed);
        write_private_new(&temporary, &bytes)?;
        match fs::hard_link(&temporary, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ReplayToCoreCoordinatorErrorV1::Conflict)
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
        if let Err(error) = self.directory.sync_all() {
            return Err(ReplayToCoreCoordinatorErrorV1::Io(error));
        }
        if let Err(error) = fs::remove_file(&temporary) {
            return Err(ReplayToCoreCoordinatorErrorV1::Io(error));
        }
        self.directory.sync_all()?;
        let reread = read_completed(&final_path)?;
        if reread != completed {
            return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
        }
        self.reconcile_pending_residue(request)
    }
}

const CANDIDATE_CORE_CHAIN_ID_V1: &str = "trnm-replay-core-candidate-v1";
const CANDIDATE_CORE_KEY_BYTES_V1: [u8; 32] = [41; 32];
const CANDIDATE_CORE_PAYLOAD_DOMAIN_V1: &[u8] = b"trnm.g1-r2b.candidate-replay-payload.v1";

struct CandidateExpectedTransitionV1 {
    core_input_digest: [u8; 32],
    obligation_state: SafetyState,
    delivery_state: SafetyState,
    delivery_digest: [u8; 32],
}

fn build_candidate_core_v1() -> Result<Core, ()> {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1_u8..=4)
        .map(|index| {
            let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
            Validator::new(
                ValidatorId::new([index; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).expect("positive fixture voting power"),
            )
            .map_err(|_| ())
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let validator_set = ValidatorSet::new(
        GenesisHash::new([0x91; 32]),
        ChainId::from_static(CANDIDATE_CORE_CHAIN_ID_V1),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|_| ())?;
    let config = CoreConfig::new(
        ValidatorId::new([1; 32]),
        validator_set,
        parameters,
        1_700_000_000_000,
        32,
        64,
    )
    .map_err(|_| ())?;
    let genesis_qc = GenesisQcV0::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set(),
    )
    .map_err(|_| ())?;
    Core::new(config, genesis_qc, &StrictEd25519Verifier).map_err(|_| ())
}

/// Replays the complete candidate transition on a fresh Core solely to
/// authenticate durable phase records during reopen.  The returned states are
/// comparison material; no capability from this scratch Core is exposed.
fn expected_candidate_transition_v1(
    request: CoreReplayRequestV1,
) -> Result<CandidateExpectedTransitionV1, CoreDeliveryErrorV1> {
    let mut core = build_candidate_core_v1()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate Core reconstruction failed"))?;
    let proposal = fixture_proposal_for_input_v1(&core, request)?;
    let core_input = Input::SyncedProposal(Box::new(proposal.clone()));
    let core_input_digest = candidate_core_input_digest_v1(&core_input);
    let effects = core
        .step(core_input, &StrictEd25519Verifier)
        .map_err(|_| CoreDeliveryErrorV1::new("candidate Core replay reconstruction failed"))?;
    let obligation_persistence = match effects.as_slice() {
        [Effect::PersistSafetyState(value)] => value,
        _ => {
            return Err(CoreDeliveryErrorV1::new(
                "candidate Core reconstruction emitted an unexpected obligation effect",
            ))
        }
    };
    let obligation_state = obligation_persistence.state().clone();
    let released = core
        .step(
            Input::StorageAck {
                barrier: obligation_persistence.barrier(),
            },
            &StrictEd25519Verifier,
        )
        .map_err(|_| CoreDeliveryErrorV1::new("candidate Core obligation replay failed"))?;
    let validation = match released.as_slice() {
        [Effect::ValidateSyncedPayload(value)] => value.clone(),
        _ => {
            return Err(CoreDeliveryErrorV1::new(
                "candidate Core reconstruction emitted an unexpected validation effect set",
            ))
        }
    };
    let (route, id, block, parent, permit) = validation
        .try_claim()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate Core validation claim failed"))?
        .into_parts();
    if route != PayloadValidationRouteV0::Synced
        || id != ValidationId::new(proposal.block().id(), proposal.block().header().view(), 1)
        || block != *proposal.block()
        || !parent.is_legacy_trusted_genesis_v0()
        || parent.tip() != core.safety_state().finalized()
    {
        return Err(CoreDeliveryErrorV1::new(
            "candidate Core reconstruction validation identity differs",
        ));
    }
    let commitments = validated_commitments_for_candidate_block_v1(&core, &block)?;
    let artifact_ref = artifact_ref_for_candidate_block_v1(&block);
    let seal_authority = core
        .issue_application_seal_authority_v0()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate seal authority reconstruction failed"))?;
    let seal =
        seal_authority.seal_after_application_store_commit_v0(permit, commitments, artifact_ref);
    let accepted = core
        .step_application_sealed_valid_to_delivery_v0(&seal, &StrictEd25519Verifier)
        .map_err(|_| CoreDeliveryErrorV1::new("candidate Core delivery reconstruction failed"))?;
    let delivery_persistence = accepted.persistence_request_v0();
    let delivery_state = delivery_persistence.state().clone();
    Ok(CandidateExpectedTransitionV1 {
        core_input_digest,
        obligation_state,
        delivery_state,
        delivery_digest: accepted.delivery_digest_v0(),
    })
}

fn fixture_proposal_for_input_v1(
    core: &Core,
    request: CoreReplayRequestV1,
) -> Result<SignedProposalV0, CoreDeliveryErrorV1> {
    let config = core.config();
    let parameters = config.consensus_parameters();
    let set = config.validator_set();
    let mut payload = Vec::with_capacity(CANDIDATE_CORE_PAYLOAD_DOMAIN_V1.len() + 32);
    payload.extend_from_slice(CANDIDATE_CORE_PAYLOAD_DOMAIN_V1);
    payload.extend_from_slice(&request.namespace_digest);
    payload.extend_from_slice(&request.target_digest);
    payload.extend_from_slice(&request.idempotency_key);
    payload.extend_from_slice(&request.input_digest);
    payload.extend_from_slice(&request.predecessor_checkpoint);
    let application_payload = ApplicationPayloadV0::new(vec![payload])
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay payload construction failed"))?;
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .map_err(|_| {
                CoreDeliveryErrorV1::new("candidate replay receipt construction failed")
            })?;
    let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay receipts construction failed"))?;
    let body = BlockBodyV0::new(application_payload, Vec::new())
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay body construction failed"))?;
    let payload_root = body
        .payload_root()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay payload root failed"))?;
    let receipts_root = receipts
        .receipts_root()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay receipts root failed"))?;
    let evidence_root = body
        .evidence_root()
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay evidence root failed"))?;
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
        payload_root,
        StateRoot::new([1; 32]),
        receipts_root,
        evidence_root,
        parent_timestamp_ms.saturating_add(1),
        None,
    )
    .map_err(|_| CoreDeliveryErrorV1::new("candidate replay header construction failed"))?;
    let block = Block::new(
        header.clone(),
        body.application_payload()
            .try_cev0_bytes()
            .map_err(|_| CoreDeliveryErrorV1::new("candidate replay payload bytes failed"))?,
        Vec::new(),
    )
    .map_err(|_| CoreDeliveryErrorV1::new("candidate replay block construction failed"))?;
    let genesis_qc = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set)
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay genesis QC failed"))?;
    let justify = QcReferenceV0::genesis_anchor(genesis_qc);
    let proposal_root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None)
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay signing root failed"))?;
    let proposer_signature = Signature64::from_array(
        SigningKey::from_bytes(&CANDIDATE_CORE_KEY_BYTES_V1)
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
    .map_err(|_| CoreDeliveryErrorV1::new("candidate replay witness construction failed"))?;
    SignedProposalV0::new(block, witness, set, None, parameters, parent_timestamp_ms)
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay proposal construction failed"))
}

fn validated_commitments_for_candidate_block_v1(
    core: &Core,
    block: &Block,
) -> Result<trnm_consensus_types::ValidatedBlockCommitmentsV0, CoreDeliveryErrorV1> {
    let parameters = core.config().consensus_parameters();
    let application_payload =
        decode_application_payload_v0_exact(block.application_payload(), parameters)
            .map_err(|_| CoreDeliveryErrorV1::new("candidate replay payload decode failed"))?;
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
                .map_err(|_| CoreDeliveryErrorV1::new("candidate replay receipt derivation failed"))
            })
            .collect::<Result<Vec<_>, CoreDeliveryErrorV1>>()?,
    )
    .map_err(|_| CoreDeliveryErrorV1::new("candidate replay receipts validation failed"))?;
    let body = BlockBodyV0::new(application_payload, Vec::new())
        .map_err(|_| CoreDeliveryErrorV1::new("candidate replay body decode failed"))?;
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        parameters,
        core.config().validator_set(),
        &StrictEd25519Verifier,
    )
    .map_err(|_| CoreDeliveryErrorV1::new("candidate replay commitment validation failed"))
}

fn artifact_ref_for_candidate_block_v1(block: &Block) -> ValidatedPayloadArtifactRefV0 {
    let mut overlay_checksum = *block.id().as_bytes();
    overlay_checksum[0] ^= 0x5a;
    let mut source_artifact_checksum = *block.id().as_bytes();
    source_artifact_checksum[0] ^= 0xa5;
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), overlay_checksum),
        source_artifact_checksum,
    )
}

fn candidate_core_input_digest_v1(input: &Input) -> [u8; 32] {
    let Input::SyncedProposal(proposal) = input else {
        return [0; 32];
    };
    candidate_preauth_hash_v1(
        CORE_INPUT_PREAUTH_DOMAIN_V1,
        &[
            &[1_u8],
            proposal.block().id().as_bytes(),
            proposal.proposal_signing_root().as_bytes(),
            proposal.proposer().as_bytes(),
            proposal.witness().proposer_signature().as_bytes(),
        ],
    )
}

fn candidate_preauth_hash_v1(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreIngressInputFactsV1 {
    request_digest: [u8; 32],
    target_digest: [u8; 32],
    idempotency_key: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    core_input_digest: [u8; 32],
}

fn encode_core_ingress_input(
    request: CoreReplayRequestV1,
    core_input_digest: [u8; 32],
) -> [u8; CORE_INPUT_RECORD_BYTES_V1] {
    let mut bytes = Vec::with_capacity(CORE_INPUT_RECORD_BYTES_V1);
    bytes.extend_from_slice(&CORE_INPUT_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&request.request_digest);
    bytes.extend_from_slice(&request.target_digest);
    bytes.extend_from_slice(&request.idempotency_key);
    bytes.extend_from_slice(&request.input_digest);
    bytes.extend_from_slice(&request.predecessor_checkpoint);
    bytes.extend_from_slice(&core_input_digest);
    debug_assert_eq!(bytes.len(), CORE_INPUT_RECORD_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(CORE_INPUT_DOMAIN_V1, &bytes));
    bytes.try_into().expect("fixed Core ingress input record")
}

fn decode_core_ingress_input(
    bytes: &[u8],
) -> Result<CoreIngressInputFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != CORE_INPUT_RECORD_BYTES_V1
        || bytes[..8] != CORE_INPUT_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[CORE_INPUT_RECORD_PREFIX_BYTES_V1..]
            != record_checksum(
                CORE_INPUT_DOMAIN_V1,
                &bytes[..CORE_INPUT_RECORD_PREFIX_BYTES_V1],
            )
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(CoreIngressInputFactsV1 {
        request_digest: bytes[12..44].try_into().expect("request digest"),
        target_digest: bytes[44..76].try_into().expect("target digest"),
        idempotency_key: bytes[76..108].try_into().expect("idempotency key"),
        input_digest: bytes[108..140].try_into().expect("input digest"),
        predecessor_checkpoint: bytes[140..172].try_into().expect("predecessor checkpoint"),
        core_input_digest: bytes[172..204].try_into().expect("Core input digest"),
    })
}

fn encode_core_ingress_facts(facts: CoreIngressFactsV1) -> [u8; CORE_STATE_RECORD_BYTES_V1] {
    let mut bytes = Vec::with_capacity(CORE_STATE_RECORD_BYTES_V1);
    bytes.extend_from_slice(&CORE_STATE_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&facts.request_digest);
    bytes.extend_from_slice(&facts.target_digest);
    bytes.extend_from_slice(&facts.idempotency_key);
    bytes.extend_from_slice(&facts.input_digest);
    bytes.extend_from_slice(&facts.predecessor_checkpoint);
    bytes.extend_from_slice(&facts.core_input_digest);
    bytes.extend_from_slice(&facts.core_safety_revision.to_be_bytes());
    bytes.extend_from_slice(&facts.core_ack_digest);
    bytes.extend_from_slice(&facts.core_state_record_checksum);
    debug_assert_eq!(bytes.len(), CORE_STATE_RECORD_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(CORE_STATE_DOMAIN_V1, &bytes));
    bytes.try_into().expect("fixed Core ingress state record")
}

fn decode_core_ingress_facts(
    bytes: &[u8],
) -> Result<CoreIngressFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != CORE_STATE_RECORD_BYTES_V1
        || bytes[..8] != CORE_STATE_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[CORE_STATE_RECORD_PREFIX_BYTES_V1..]
            != record_checksum(
                CORE_STATE_DOMAIN_V1,
                &bytes[..CORE_STATE_RECORD_PREFIX_BYTES_V1],
            )
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let core_safety_revision =
        u64::from_be_bytes(bytes[204..212].try_into().expect("Core safety revision"));
    let core_ack_digest = bytes[212..244].try_into().expect("Core ack digest");
    let core_state_record_checksum = bytes[244..276]
        .try_into()
        .expect("Core state record checksum");
    if core_safety_revision == 0
        || core_ack_digest == [0; 32]
        || core_state_record_checksum == [0; 32]
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(CoreIngressFactsV1 {
        request_digest: bytes[12..44].try_into().expect("request digest"),
        target_digest: bytes[44..76].try_into().expect("target digest"),
        idempotency_key: bytes[76..108].try_into().expect("idempotency key"),
        input_digest: bytes[108..140].try_into().expect("input digest"),
        predecessor_checkpoint: bytes[140..172].try_into().expect("predecessor checkpoint"),
        core_input_digest: bytes[172..204].try_into().expect("Core input digest"),
        core_safety_revision,
        core_ack_digest,
        core_state_record_checksum,
    })
}

fn candidate_core_ack_digest_v1(
    request: CoreReplayRequestV1,
    state_record: &[u8],
    delivery_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CORE_ACK_DOMAIN_V1);
    hasher.update(request.request_digest);
    hasher.update(request.idempotency_key);
    hasher.update(delivery_digest);
    hasher.update((state_record.len() as u64).to_be_bytes());
    hasher.update(state_record);
    hasher.finalize().into()
}

fn payload_namespace_digest(namespace: PayloadReplayNamespaceV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_DOMAIN_V1);
    hasher.update(namespace.local_id());
    hasher.update(namespace.epoch().to_be_bytes());
    hasher.update(namespace.validator_set_id());
    hasher.update(namespace.run_id_hash());
    hasher.update(namespace.network_context_hash());
    hasher.finalize().into()
}

fn payload_target_digest(target: PayloadReplayRecoveryTargetV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TARGET_DOMAIN_V1);
    hasher.update(target.record_index().to_be_bytes());
    hasher.update(target.record_hash());
    hasher.update(target.remote_id());
    hasher.update([target.direction() as u8]);
    hasher.update(target.session_id());
    hasher.update(target.generation().to_be_bytes());
    hasher.update(target.sequence().to_be_bytes());
    hasher.update([target.frame_kind()]);
    hasher.update(target.payload_len().to_be_bytes());
    hasher.update(target.frame_fingerprint());
    hasher.finalize().into()
}

fn replay_request_digest(
    namespace_digest: [u8; 32],
    target_digest: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN_V1);
    hasher.update(namespace_digest);
    hasher.update(target_digest);
    hasher.update(input_digest);
    hasher.update(predecessor_checkpoint);
    hasher.finalize().into()
}

fn replay_idempotency_key(request_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_DOMAIN_V1);
    hasher.update(request_digest);
    hasher.finalize().into()
}

fn encode_pending(facts: PendingFactsV1) -> [u8; PENDING_BYTES_V1] {
    let mut bytes = Vec::with_capacity(PENDING_BYTES_V1);
    bytes.extend_from_slice(&PENDING_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&facts.namespace_digest);
    bytes.extend_from_slice(&facts.target_digest);
    bytes.extend_from_slice(&facts.record_index.to_be_bytes());
    bytes.extend_from_slice(&facts.record_hash);
    bytes.extend_from_slice(&facts.frame_fingerprint);
    bytes.extend_from_slice(&facts.input_digest);
    bytes.extend_from_slice(&facts.predecessor_checkpoint);
    bytes.extend_from_slice(&facts.idempotency_key);
    debug_assert_eq!(bytes.len(), PENDING_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(PENDING_DOMAIN_V1, &bytes));
    bytes
        .try_into()
        .expect("fixed pending replay-to-Core record")
}

fn decode_pending(bytes: &[u8]) -> Result<PendingFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != PENDING_BYTES_V1
        || bytes[..8] != PENDING_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[PENDING_PREFIX_BYTES_V1..]
            != record_checksum(PENDING_DOMAIN_V1, &bytes[..PENDING_PREFIX_BYTES_V1])
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(PendingFactsV1 {
        namespace_digest: bytes[12..44].try_into().expect("namespace digest"),
        target_digest: bytes[44..76].try_into().expect("target digest"),
        record_index: u64::from_be_bytes(bytes[76..84].try_into().expect("record index")),
        record_hash: bytes[84..116].try_into().expect("record hash"),
        frame_fingerprint: bytes[116..148].try_into().expect("frame fingerprint"),
        input_digest: bytes[148..180].try_into().expect("input digest"),
        predecessor_checkpoint: bytes[180..212].try_into().expect("predecessor checkpoint"),
        idempotency_key: bytes[212..244].try_into().expect("idempotency key"),
    })
}

fn encode_completed(facts: CompletedFactsV1) -> [u8; COMPLETED_BYTES_V1] {
    let pending = facts.pending;
    let mut bytes = Vec::with_capacity(COMPLETED_BYTES_V1);
    bytes.extend_from_slice(&COMPLETED_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&pending.namespace_digest);
    bytes.extend_from_slice(&pending.target_digest);
    bytes.extend_from_slice(&pending.record_index.to_be_bytes());
    bytes.extend_from_slice(&pending.record_hash);
    bytes.extend_from_slice(&pending.frame_fingerprint);
    bytes.extend_from_slice(&pending.input_digest);
    bytes.extend_from_slice(&pending.predecessor_checkpoint);
    bytes.extend_from_slice(&pending.idempotency_key);
    bytes.extend_from_slice(&facts.core_safety_revision.to_be_bytes());
    bytes.extend_from_slice(&facts.core_ack_digest);
    bytes.extend_from_slice(&facts.replay_ack_hash);
    debug_assert_eq!(bytes.len(), COMPLETED_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(COMPLETED_DOMAIN_V1, &bytes));
    bytes
        .try_into()
        .expect("fixed completed replay-to-Core record")
}

fn decode_completed(bytes: &[u8]) -> Result<CompletedFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != COMPLETED_BYTES_V1
        || bytes[..8] != COMPLETED_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[COMPLETED_PREFIX_BYTES_V1..]
            != record_checksum(COMPLETED_DOMAIN_V1, &bytes[..COMPLETED_PREFIX_BYTES_V1])
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let core_safety_revision =
        u64::from_be_bytes(bytes[244..252].try_into().expect("Core safety revision"));
    let core_ack_digest = bytes[252..284].try_into().expect("Core ack digest");
    let replay_ack_hash = bytes[284..316].try_into().expect("replay ack hash");
    if core_safety_revision == 0 || core_ack_digest == [0; 32] || replay_ack_hash == [0; 32] {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(CompletedFactsV1 {
        pending: PendingFactsV1 {
            namespace_digest: bytes[12..44].try_into().expect("namespace digest"),
            target_digest: bytes[44..76].try_into().expect("target digest"),
            record_index: u64::from_be_bytes(bytes[76..84].try_into().expect("record index")),
            record_hash: bytes[84..116].try_into().expect("record hash"),
            frame_fingerprint: bytes[116..148].try_into().expect("frame fingerprint"),
            input_digest: bytes[148..180].try_into().expect("input digest"),
            predecessor_checkpoint: bytes[180..212].try_into().expect("predecessor checkpoint"),
            idempotency_key: bytes[212..244].try_into().expect("idempotency key"),
        },
        core_safety_revision,
        core_ack_digest,
        replay_ack_hash,
    })
}

fn record_checksum(domain: &[u8], prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_pending(path: &Path) -> Result<PendingFactsV1, ReplayToCoreCoordinatorErrorV1> {
    let bytes = read_private_exact(path, PENDING_BYTES_V1)?;
    decode_pending(&bytes)
}

fn read_completed(path: &Path) -> Result<CompletedFactsV1, ReplayToCoreCoordinatorErrorV1> {
    let bytes = read_private_exact(path, COMPLETED_BYTES_V1)?;
    decode_completed(&bytes)
}

fn read_private_exact(
    path: &Path,
    expected: usize,
) -> Result<Vec<u8>, ReplayToCoreCoordinatorErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !private_regular_file(&metadata)
        || metadata.len() != expected as u64
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    let descriptor = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !private_regular_file(&descriptor)
        || descriptor.len() != expected as u64
        || !private_regular_file(&named)
        || named.len() != expected as u64
        || descriptor.dev() != metadata.dev()
        || descriptor.ino() != metadata.ino()
        || descriptor.uid() != metadata.uid()
        || descriptor.dev() != named.dev()
        || descriptor.ino() != named.ino()
        || descriptor.uid() != named.uid()
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let mut bytes = Vec::with_capacity(expected);
    Read::by_ref(&mut file)
        .take(expected as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(bytes)
}

fn private_path_present(path: &Path) -> Result<bool, CoreDeliveryErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CoreDeliveryErrorV1::new("Core ingress phase lookup failed")),
    }
}

/// Reads one bounded private record while preserving the inode/owner/mode
/// checks performed by `read_private_exact`.  Record length is discovered
/// only after the metadata check; the canonical codec then authenticates the
/// exact byte sequence.
fn read_private_record(path: &Path) -> Result<Vec<u8>, ReplayToCoreCoordinatorErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let length =
        usize::try_from(metadata.len()).map_err(|_| ReplayToCoreCoordinatorErrorV1::Corrupt)?;
    read_private_exact(path, length)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE_V1);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V1))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn private_temp_path(path: &Path) -> Result<PathBuf, ReplayToCoreCoordinatorErrorV1> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ReplayToCoreCoordinatorErrorV1::Corrupt)?;
    Ok(path.with_file_name(format!(".{name}.tmp-v1")))
}

/// Publish a private record without exposing a partially written final path.
/// A fixed slot-local temporary makes restart reconciliation deterministic:
/// complete temporary data can be linked into place, while partial or
/// conflicting data remains an explicit fail-closed condition.
fn write_private_atomic_new(
    directory: &File,
    path: &Path,
    bytes: &[u8],
) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    let temporary = private_temp_path(path)?;
    reconcile_private_temp_if_final(directory, path)?;

    match fs::symlink_metadata(path) {
        Ok(_) => {
            let existing = read_private_exact(path, bytes.len())?;
            if existing != bytes {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    }

    match fs::symlink_metadata(&temporary) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !private_regular_file(&metadata) {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            }
            let existing = read_private_exact(&temporary, bytes.len())?;
            if existing != bytes {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_private_new(&temporary, bytes)?;
        }
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    }

    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_private_exact(path, bytes.len())?;
            if existing != bytes {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            }
        }
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    }
    directory.sync_all()?;
    // If the process dies before this unlink, the next owner observes the
    // same inode at both names and removes only the temporary link.
    fs::remove_file(&temporary)?;
    directory.sync_all()?;
    let published = read_private_exact(path, bytes.len())?;
    if published != bytes {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(())
}

/// Reconcile a slot's temporary publication when its final path is present.
/// A same-inode two-link residue is the expected crash window; a different or
/// mismatching inode is ambiguous and rejected.
fn reconcile_private_temp_if_final(
    directory: &File,
    path: &Path,
) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    let temporary = private_temp_path(path)?;
    let final_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    };
    let temporary_metadata = match fs::symlink_metadata(&temporary) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    };
    let final_private = final_metadata.is_file()
        && final_metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
        && final_metadata.uid() == rustix::process::geteuid().as_raw();
    let temporary_private = temporary_metadata.is_file()
        && temporary_metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
        && temporary_metadata.uid() == rustix::process::geteuid().as_raw();
    if final_metadata.file_type().is_symlink()
        || temporary_metadata.file_type().is_symlink()
        || !final_private
        || !temporary_private
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    if final_metadata.dev() == temporary_metadata.dev()
        && final_metadata.ino() == temporary_metadata.ino()
        && final_metadata.nlink() == 2
        && temporary_metadata.nlink() == 2
    {
        fs::remove_file(&temporary)?;
        directory.sync_all()?;
        return Ok(());
    }
    if final_metadata.nlink() != 1
        || temporary_metadata.nlink() != 1
        || temporary_metadata.len() != final_metadata.len()
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let final_bytes = read_private_exact(path, final_metadata.len() as usize)?;
    let temporary_bytes = read_private_exact(&temporary, temporary_metadata.len() as usize)?;
    if final_bytes != temporary_bytes {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    fs::remove_file(&temporary)?;
    directory.sync_all()?;
    Ok(())
}

fn open_or_create_private_file(path: &Path) -> Result<File, ReplayToCoreCoordinatorErrorV1> {
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            // Never repair an existing authority file in place.  A broad
            // mode, extra hard link, wrong owner or non-regular node is
            // evidence of tampering and must fail closed before opening it.
            if metadata.file_type().is_symlink() || !private_regular_file(&metadata) {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE_V1);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !existed {
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V1))?;
    }
    let metadata = file.metadata()?;
    if !private_regular_file(&metadata) {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
        || metadata.uid() != named.uid()
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(file)
}

fn validate_private_root(path: &Path) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    if !path.is_absolute() {
        return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
            "coordinator root must be absolute",
        ));
    }
    validate_private_root_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != PRIVATE_DIRECTORY_MODE_V1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || fs::canonicalize(path)? != path
    {
        return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
            "coordinator root must be a canonical owner-only directory",
        ));
    }
    Ok(())
}

fn validate_private_root_ancestors(path: &Path) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    let current_uid = rustix::process::geteuid().as_raw();
    let mut ancestor = path
        .parent()
        .ok_or(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
            "coordinator root has no parent",
        ))?;
    loop {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                    "coordinator root ancestor does not exist",
                ))
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        };
        let mode = metadata.permissions().mode() & 0o7777;
        // Root-owned sticky directories (notably `/tmp`) are the one
        // intentional writable-ancestor exception: the kernel prevents a
        // different owner from replacing an existing child name there.
        let allowed_root_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        let owner_ok = metadata.uid() == current_uid || metadata.uid() == 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !owner_ok
            || (mode & 0o022 != 0 && !allowed_root_sticky)
        {
            return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "coordinator root ancestor must be a non-writable owner directory",
            ));
        }
        if ancestor == Path::new("/") {
            break;
        }
        ancestor = ancestor
            .parent()
            .ok_or(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "coordinator root ancestor traversal failed",
            ))?;
    }
    Ok(())
}

fn private_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
        && metadata.uid() == rustix::process::geteuid().as_raw()
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() {
    println!(
        "status=g1-r2-r2b-candidate pending_before_core=true sealed_core_authority=true real_core_ingress_candidate=true fault_cut_matrix_candidate=true live_core_adapter=false core_ack_generated_by_core=false atomic_with_core=false node_process_integration=false production=false"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;
    use trnm_consensus_peer_lease::{
        PayloadReplayFrameV1, PayloadReplayStoreV1, PeerLeaseDirectionV1,
    };

    fn private_tempdir(prefix: &str) -> TempDir {
        let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn private_child(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn namespace() -> PayloadReplayNamespaceV1 {
        PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
    }

    fn frame(
        namespace: PayloadReplayNamespaceV1,
        sequence: u64,
        fingerprint: [u8; 32],
    ) -> PayloadReplayFrameV1 {
        PayloadReplayFrameV1::new(
            namespace
                .scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
                .unwrap(),
            namespace.run_id_hash(),
            namespace.network_context_hash(),
            [5; 32],
            1,
            sequence,
            2,
            11,
            fingerprint,
        )
        .unwrap()
    }

    fn admit(
        wal: &Path,
        namespace: PayloadReplayNamespaceV1,
        frame: PayloadReplayFrameV1,
    ) -> PayloadReplayRecoveryTargetV1 {
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(wal, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        PayloadReplayRecoveryTargetV1::from_admission(frame, receipt)
    }

    #[derive(Debug, Default)]
    struct FakeCoreV1 {
        calls: usize,
        fail: bool,
        expected_pending: Option<PathBuf>,
        receipts: BTreeMap<[u8; 32], CoreDurableReplayReceiptV1>,
    }

    impl sealed::SealedReplayToCoreAuthorityV1 for FakeCoreV1 {}

    impl ReplayToCoreAuthorityV1 for FakeCoreV1 {
        fn deliver_durably(
            &mut self,
            request: CoreReplayRequestV1,
        ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1> {
            if let Some(path) = &self.expected_pending {
                assert!(path.exists(), "Core was called before pending durability");
            }
            self.calls += 1;
            if self.fail {
                return Err(CoreDeliveryErrorV1::new("synthetic durable Core refusal"));
            }
            if let Some(receipt) = self.receipts.get(&request.idempotency_key).copied() {
                return Ok(receipt);
            }
            let receipt =
                CoreDurableReplayReceiptV1::new_after_durable_core(request, 19, [21; 32]).unwrap();
            self.receipts.insert(request.idempotency_key, receipt);
            Ok(receipt)
        }
    }

    struct FixtureV1 {
        _root: TempDir,
        wal: PathBuf,
        replay_ack_root: PathBuf,
        coordinator_root: PathBuf,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
    }

    fn fixture(prefix: &str) -> FixtureV1 {
        let root = private_tempdir(prefix);
        let wal = root.path().join("payload.wal");
        let replay_ack_root = private_child(root.path(), "replay-acks");
        let coordinator_root = private_child(root.path(), "coordinator");
        let namespace = namespace();
        let target = admit(&wal, namespace, frame(namespace, 0, [10; 32]));
        FixtureV1 {
            _root: root,
            wal,
            replay_ack_root,
            coordinator_root,
            namespace,
            target,
        }
    }

    #[test]
    fn pending_is_durable_before_core_and_completion_is_idempotent() {
        let fixture = fixture("trnm-r2-normal-");
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        let mut core = FakeCoreV1 {
            expected_pending: Some(coordinator.pending_path(request)),
            ..FakeCoreV1::default()
        };
        let first = coordinator
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 1);
        assert!(!first.idempotent_replay());
        assert!(!coordinator.pending_path(request).exists());
        drop(coordinator);

        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let second = reopened
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 1);
        assert!(second.idempotent_replay());
        assert_eq!(first.replay_ack_hash(), second.replay_ack_hash());
    }

    #[test]
    fn core_failure_retains_pending_and_blocks_a_later_target() {
        let fixture = fixture("trnm-r2-pending-block-");
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1 {
            fail: true,
            ..FakeCoreV1::default()
        };
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::CoreDelivery(_))
        ));
        drop(coordinator);

        let second_frame = frame(fixture.namespace, 1, [11; 32]);
        let second_target = admit(&fixture.wal, fixture.namespace, second_frame);
        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        assert!(matches!(
            reopened.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                second_target,
                [32; 32],
                [33; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::EarlierDeliveryPending)
        ));
    }

    #[test]
    fn exact_existing_replay_ack_completes_without_core_redelivery() {
        let fixture = fixture("trnm-r2-existing-ack-");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        {
            let mut replay_owner = PayloadReplayRecoveryOwnerV1::open(
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
            )
            .unwrap();
            replay_owner
                .acknowledge_core(
                    PayloadReplayCoreAcknowledgementV1::new(fixture.target, 19, [21; 32]).unwrap(),
                )
                .unwrap();
        }
        let mut core = FakeCoreV1 {
            fail: true,
            ..FakeCoreV1::default()
        };
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let completion = coordinator
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 0);
        assert_eq!(completion.core_safety_revision(), 19);
        assert!(!coordinator.pending_path(request).exists());
    }

    #[test]
    fn conflicting_request_for_existing_pending_fails_closed() {
        let fixture = fixture("trnm-r2-pending-conflict-");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [99; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Conflict)
        ));
        assert_eq!(core.calls, 0);
    }

    #[test]
    fn tampered_pending_record_is_rejected() {
        let fixture = fixture("trnm-r2-pending-tamper-");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
            let path = coordinator.pending_path(request);
            let mut bytes = fs::read(&path).unwrap();
            bytes[148] ^= 1;
            fs::write(path, bytes).unwrap();
        }
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Corrupt)
        ));
    }

    #[test]
    fn live_coordinator_lock_excludes_a_second_owner() {
        let fixture = fixture("trnm-r2-lock-");
        let _first = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root),
            Err(ReplayToCoreCoordinatorErrorV1::Busy)
        ));
    }

    #[test]
    fn retained_completion_temporary_is_an_ambiguous_stop() {
        let fixture = fixture("trnm-r2-completion-temp-");
        let path = fixture
            .coordinator_root
            .join(".completed-retained.v1.tmp-1-1");
        fs::write(&path, b"retained").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::AmbiguousPublication)
        ));
    }

    #[test]
    fn completed_and_exact_pending_residue_reconcile_without_core() {
        let fixture = fixture("trnm-r2-completed-residue-");
        let mut core = FakeCoreV1::default();
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        {
            let mut coordinator =
                ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator
                .drive(
                    &mut core,
                    &fixture.wal,
                    &fixture.replay_ack_root,
                    fixture.namespace,
                    fixture.target,
                    [30; 32],
                    [31; 32],
                )
                .unwrap();
            write_private_new(
                &coordinator.pending_path(request),
                &encode_pending(PendingFactsV1::from_request(request)),
            )
            .unwrap();
        }
        let prior_calls = core.calls;
        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let receipt = reopened
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert!(receipt.idempotent_replay());
        assert_eq!(core.calls, prior_calls);
        assert!(!reopened.pending_path(request).exists());
    }

    #[test]
    fn wrong_namespace_cannot_reuse_pending_target() {
        let fixture = fixture("trnm-r2-namespace-");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        let wrong_namespace =
            PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [44; 32]).unwrap();
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                wrong_namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Conflict)
        ));
    }

    #[test]
    fn broad_or_relative_coordinator_root_is_rejected() {
        let root = private_tempdir("trnm-r2-root-mode-");
        let broad = root.path().join("broad");
        fs::create_dir(&broad).unwrap();
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(&broad),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(Path::new("relative-root")),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
    }

    #[test]
    fn writable_or_symlink_ancestor_is_rejected() {
        let root = private_tempdir("trnm-r2b-ancestor-");
        let writable_parent = root.path().join("writable-parent");
        fs::create_dir(&writable_parent).unwrap();
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let writable_target = writable_parent.join("coordinator");
        fs::create_dir(&writable_target).unwrap();
        fs::set_permissions(&writable_target, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(&writable_target),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
        assert!(matches!(
            CandidateCoreIngressV1::open(&writable_target, [31; 32]),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));

        let real_parent = root.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let symlink_parent = root.path().join("symlink-parent");
        symlink(&real_parent, &symlink_parent).unwrap();
        let symlink_target = real_parent.join("coordinator");
        fs::create_dir(&symlink_target).unwrap();
        fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(symlink_parent.join("coordinator")),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
        assert!(matches!(
            CandidateCoreIngressV1::open(symlink_parent.join("coordinator"), [31; 32]),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
    }

    #[test]
    fn candidate_core_lock_symlink_is_rejected() {
        let fixture = fixture("trnm-r2b-lock-symlink-");
        let core_root = private_child(fixture._root.path(), "core-ingress");
        let target = core_root.join("lock-target");
        write_private_new(&target, &[0; 1]).unwrap();
        symlink(&target, core_root.join(CORE_LOCK_NAME_V1)).unwrap();
        assert!(matches!(
            CandidateCoreIngressV1::open(&core_root, [31; 32]),
            Err(ReplayToCoreCoordinatorErrorV1::Corrupt)
        ));
    }

    #[test]
    fn candidate_core_existing_broad_lock_mode_is_rejected_without_repair() {
        let fixture = fixture("trnm-r2b-lock-mode-");
        let core_root = private_child(fixture._root.path(), "core-ingress");
        let lock = core_root.join(CORE_LOCK_NAME_V1);
        write_private_new(&lock, &[0; 1]).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            CandidateCoreIngressV1::open(&core_root, [31; 32]),
            Err(ReplayToCoreCoordinatorErrorV1::Corrupt)
        ));
        assert_eq!(
            fs::symlink_metadata(&lock).unwrap().permissions().mode() & 0o7777,
            0o666
        );
    }

    #[test]
    fn candidate_atomic_publication_reconciles_same_inode_temporary() {
        let fixture = fixture("trnm-r2b-atomic-residue-");
        let core_root = private_child(fixture._root.path(), "core-ingress");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        let receipt = adapter.deliver_durably(request).unwrap();
        let delivery = core_root.join(CORE_DELIVERY_NAME_V1);
        let temporary = private_temp_path(&delivery).unwrap();
        fs::hard_link(&delivery, &temporary).unwrap();
        assert_eq!(fs::symlink_metadata(&delivery).unwrap().nlink(), 2);
        assert_eq!(fs::symlink_metadata(&temporary).unwrap().nlink(), 2);
        assert_eq!(adapter.deliver_durably(request).unwrap(), receipt);
        assert!(!temporary.exists());
    }

    #[test]
    fn candidate_atomic_partial_temporary_fails_closed() {
        let fixture = fixture("trnm-r2b-atomic-partial-");
        let core_root = private_child(fixture._root.path(), "core-ingress");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        let input = core_root.join(CORE_INPUT_NAME_V1);
        let temporary = private_temp_path(&input).unwrap();
        write_private_new(&temporary, &[0; 1]).unwrap();
        assert!(adapter.deliver_durably(request).is_err());
        assert!(!core_root.join(CORE_STATE_NAME_V1).exists());
    }

    #[test]
    fn core_receipt_must_bind_exact_request() {
        let fixture = fixture("trnm-r2-receipt-bind-");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        let other = CoreReplayRequestV1::new(fixture.namespace, fixture.target, [32; 32], [31; 32])
            .unwrap();
        let receipt =
            CoreDurableReplayReceiptV1::new_after_durable_core(request, 19, [21; 32]).unwrap();
        assert!(matches!(
            receipt.validate_for(other),
            Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch)
        ));
    }

    #[test]
    fn candidate_core_ingress_runs_real_core_and_persists_readback() {
        let fixture = fixture("trnm-r2b-core-positive-");
        let core_root = private_child(fixture._root.path(), "core-ingress");
        let request =
            CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        let receipt = adapter.deliver_durably(request).unwrap();
        assert_eq!(receipt.core_safety_revision, 2);
        assert_ne!(receipt.core_ack_digest, [0; 32]);
        assert_eq!(adapter.core_revision(), 2);
        assert!(core_root.join(CORE_INPUT_NAME_V1).exists());
        assert!(core_root.join(CORE_OBLIGATION_NAME_V1).exists());
        assert!(core_root.join(CORE_DELIVERY_NAME_V1).exists());
        assert!(core_root.join(CORE_STATE_NAME_V1).exists());
    }

    #[test]
    fn candidate_reopen_rejects_ack_mutation_and_orphaned_phase() {
        let base_fixture = fixture("trnm-r2b-reopen-mutants-");
        let core_root = private_child(base_fixture._root.path(), "core-ingress");
        let request = CoreReplayRequestV1::new(
            base_fixture.namespace,
            base_fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        adapter.deliver_durably(request).unwrap();

        // A same-UID writer can recompute the candidate's unkeyed checksum,
        // but the deterministic Core transition check must still reject a
        // changed acknowledgement digest.
        let state_path = core_root.join(CORE_STATE_NAME_V1);
        let mut state = fs::read(&state_path).unwrap();
        state[212] ^= 1;
        let checksum = record_checksum(
            CORE_STATE_DOMAIN_V1,
            &state[..CORE_STATE_RECORD_PREFIX_BYTES_V1],
        );
        state[CORE_STATE_RECORD_PREFIX_BYTES_V1..].copy_from_slice(&checksum);
        fs::write(&state_path, &state).unwrap();
        assert!(adapter.deliver_durably(request).is_err());

        // An obligation/delivery without the input breadcrumb is an
        // ambiguous phase prefix and must never be reinterpreted as a fresh
        // candidate request.
        let cut_fixture = fixture("trnm-r2b-reopen-orphan-");
        let cut_root = private_child(cut_fixture._root.path(), "core-ingress");
        let cut_request = CoreReplayRequestV1::new(
            cut_fixture.namespace,
            cut_fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let mut cut_adapter = CandidateCoreIngressV1::open(&cut_root, [31; 32]).unwrap();
            cut_adapter.set_fault_cut(Some(CoreReplayFaultCutV1::PersistenceBeforeReadback));
            assert!(cut_adapter.deliver_durably(cut_request).is_err());
        }
        fs::remove_file(cut_root.join(CORE_INPUT_NAME_V1)).unwrap();
        let mut reopened = CandidateCoreIngressV1::open(&cut_root, [31; 32]).unwrap();
        assert!(reopened.deliver_durably(cut_request).is_err());
    }

    #[test]
    fn candidate_core_fault_cuts_never_mint_a_receipt() {
        let cuts = [
            (
                "trnm-r2b-cut-before-input-",
                CoreReplayFaultCutV1::BeforeCoreInput,
                false,
                false,
                false,
                false,
            ),
            (
                "trnm-r2b-cut-after-input-",
                CoreReplayFaultCutV1::CoreAcceptedBeforePersistence,
                true,
                false,
                false,
                false,
            ),
            (
                "trnm-r2b-cut-before-readback-",
                CoreReplayFaultCutV1::PersistenceBeforeReadback,
                true,
                true,
                false,
                false,
            ),
            (
                "trnm-r2b-cut-before-ack-",
                CoreReplayFaultCutV1::ReadbackBeforeReplayAck,
                true,
                true,
                true,
                false,
            ),
        ];

        for (prefix, cut, has_input, has_obligation, has_delivery, has_facts) in cuts {
            let fixture = fixture(prefix);
            let core_root = private_child(fixture._root.path(), "core-ingress");
            let request =
                CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                    .unwrap();
            let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
            adapter.set_fault_cut(Some(cut));
            let error = adapter
                .deliver_durably(request)
                .expect_err("a fault cut must not return a Core receipt");
            assert!(error.to_string().contains("fault cut"));
            assert_eq!(core_root.join(CORE_INPUT_NAME_V1).exists(), has_input);
            assert_eq!(
                core_root.join(CORE_OBLIGATION_NAME_V1).exists(),
                has_obligation
            );
            assert_eq!(core_root.join(CORE_DELIVERY_NAME_V1).exists(), has_delivery);
            assert_eq!(core_root.join(CORE_STATE_NAME_V1).exists(), has_facts);
        }
    }

    #[test]
    fn candidate_core_fault_cuts_reconcile_after_reopen() {
        let cuts = [
            (
                "trnm-r2b-reopen-before-input-",
                CoreReplayFaultCutV1::BeforeCoreInput,
            ),
            (
                "trnm-r2b-reopen-after-input-",
                CoreReplayFaultCutV1::CoreAcceptedBeforePersistence,
            ),
            (
                "trnm-r2b-reopen-before-readback-",
                CoreReplayFaultCutV1::PersistenceBeforeReadback,
            ),
            (
                "trnm-r2b-reopen-before-ack-",
                CoreReplayFaultCutV1::ReadbackBeforeReplayAck,
            ),
        ];

        for (prefix, cut) in cuts {
            let fixture = fixture(prefix);
            let core_root = private_child(fixture._root.path(), "core-ingress");
            let request =
                CoreReplayRequestV1::new(fixture.namespace, fixture.target, [30; 32], [31; 32])
                    .unwrap();
            {
                let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
                adapter.set_fault_cut(Some(cut));
                assert!(adapter.deliver_durably(request).is_err());
            }

            // Reopen simulates a process restart after the uncertain cut.  A
            // fresh Core must reconcile any durable phase records and only
            // then mint the sealed receipt.
            let mut reopened = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
            let receipt = reopened
                .deliver_durably(request)
                .expect("reopened candidate must reconcile the durable phase");
            assert_eq!(receipt.core_safety_revision, 2);
            assert_ne!(receipt.core_ack_digest, [0; 32]);
            assert_eq!(reopened.core_revision(), 2);
            assert!(core_root.join(CORE_STATE_NAME_V1).exists());

            let second = reopened.deliver_durably(request).unwrap();
            assert_eq!(second, receipt);
        }
    }

    #[test]
    fn persisted_core_receipt_rechecks_canonical_delivery_and_predecessor() {
        let first_fixture = fixture("trnm-r2b-core-recheck-");
        let core_root = private_child(first_fixture._root.path(), "core-ingress");
        let request = CoreReplayRequestV1::new(
            first_fixture.namespace,
            first_fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        adapter.deliver_durably(request).unwrap();

        let delivery_path = core_root.join(CORE_DELIVERY_NAME_V1);
        let original_delivery = fs::read(&delivery_path).unwrap();
        let mut delivery = original_delivery.clone();
        delivery[16] ^= 1;
        fs::write(&delivery_path, delivery).unwrap();
        assert!(adapter.deliver_durably(request).is_err());

        fs::write(&delivery_path, original_delivery).unwrap();
        let input_path = core_root.join(CORE_INPUT_NAME_V1);
        let mut input = fs::read(&input_path).unwrap();
        input[20] ^= 1;
        fs::write(&input_path, input).unwrap();
        assert!(adapter.deliver_durably(request).is_err());

        // Restore the exact delivery record by using a fresh fixture, then
        // prove that a changed whole-node predecessor is also fail-closed.
        let second_fixture = fixture("trnm-r2b-core-predecessor-recheck-");
        let core_root = private_child(second_fixture._root.path(), "core-ingress");
        let request = CoreReplayRequestV1::new(
            second_fixture.namespace,
            second_fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        let mut adapter = CandidateCoreIngressV1::open(&core_root, [31; 32]).unwrap();
        adapter.deliver_durably(request).unwrap();
        fs::write(core_root.join(CORE_PREDECESSOR_NAME_V1), [32; 32]).unwrap();
        assert!(adapter.deliver_durably(request).is_err());
    }
}
