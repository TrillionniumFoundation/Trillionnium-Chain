//! Existing-only, candidate recovery of a previously signed native Vote.
//! No Core, signature producer, mutable accessor, or activation is retained.

use std::{error::Error, fmt, fs, path::Path};

use trnm_consensus_core::{
    native_valid_result_checksum_v0, CoreConfig, NativeValidPostAckActionV0,
    PayloadValidationRouteV0, SafetyStateRecordLimitsV0, SignIntent,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyStateStoreProfileV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, PinnedSqliteSignerJournalV0, SignerJournalConflictV0,
    SignerJournalErrorV0, SignerJournalProfileV0,
};
use trnm_consensus_types::{CanonicalSignIntentV0, Vote};
use trnm_native_application_sqlite::{
    ProposalRouteV0, ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0,
    SqliteProposalValidationStoreV0, ValidationStoreErrorCodeV0, ValidationStoreErrorV0,
};
use trnm_native_execution_v0::{
    DurableExecutionHistoryStatusV0, DurableNativeApplicationV0, NativeApplicationConfigV0,
    NativeApplicationExecutionErrorCodeV0, NativeApplicationExecutionErrorV0,
};

use crate::{
    cross_store_lock::CrossStoreLockGuardV0,
    deployed_lab_recovery::{
        existing_paths_v0, hash_v0, validate_binding_context_v0, AuthorityPathsV0,
        MAXIMUM_BLOB_BYTES_V0, MAXIMUM_RECORD_BYTES_V0, MAXIMUM_SAFETY_DATABASE_BYTES_V0,
        MAXIMUM_SIGNER_DATABASE_BYTES_V0, MAXIMUM_SIGNER_INTENTS_V0,
        MAXIMUM_SIGNER_INTENT_BYTES_V0, MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0,
        PROPOSAL_OWNER_DOMAIN_V0, PROPOSAL_SCOPE_DOMAIN_V0,
    },
    derive_signer_watermark_scope_v0,
    external_node_checkpoint::{
        native_k_application_projection_v1, NativeKAuthorizingSafetyFactsV1,
    },
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
    SIGNER_JOURNAL_PROFILE_REF_V0, STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocoNodeNativeSignedVoteReplayErrorV1 {
    Unavailable { stage: &'static str },
    Rejected { stage: &'static str, detail: String },
}
impl fmt::Display for PocoNodeNativeSignedVoteReplayErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native signed Vote replay: {self:?}")
    }
}
impl Error for PocoNodeNativeSignedVoteReplayErrorV1 {}
type ReplayResult<T> = Result<T, PocoNodeNativeSignedVoteReplayErrorV1>;
fn rejected(stage: &'static str, error: impl fmt::Debug) -> PocoNodeNativeSignedVoteReplayErrorV1 {
    PocoNodeNativeSignedVoteReplayErrorV1::Rejected {
        stage,
        detail: format!("{error:?}"),
    }
}
fn unavailable(stage: &'static str) -> PocoNodeNativeSignedVoteReplayErrorV1 {
    PocoNodeNativeSignedVoteReplayErrorV1::Unavailable { stage }
}
fn signer_error(
    stage: &'static str,
    error: SignerJournalErrorV0,
) -> PocoNodeNativeSignedVoteReplayErrorV1 {
    if matches!(
        error,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkRepairRequired)
    ) {
        unavailable(stage)
    } else {
        rejected(stage, error)
    }
}
macro_rules! readback {
    ($stage:literal, $call:expr) => {
        $call.map_err(|e| rejected($stage, e))?
    };
}

fn validation_error(
    stage: &'static str,
    error: ValidationStoreErrorV0,
) -> PocoNodeNativeSignedVoteReplayErrorV1 {
    if matches!(
        error.code(),
        ValidationStoreErrorCodeV0::NotFound
            | ValidationStoreErrorCodeV0::Storage
            | ValidationStoreErrorCodeV0::CommitUncertain
            | ValidationStoreErrorCodeV0::InvalidTransition
    ) || error.context() == "terminal_k_audit.nonterminal_job"
    {
        unavailable(stage)
    } else {
        rejected(stage, error)
    }
}

fn application_error(
    stage: &'static str,
    error: NativeApplicationExecutionErrorV0,
) -> PocoNodeNativeSignedVoteReplayErrorV1 {
    if matches!(
        error.code(),
        NativeApplicationExecutionErrorCodeV0::Storage
            | NativeApplicationExecutionErrorCodeV0::Busy
            | NativeApplicationExecutionErrorCodeV0::CommitUncertain
    ) {
        unavailable(stage)
    } else {
        rejected(stage, error)
    }
}

macro_rules! validation_readback {
    ($stage:literal, $call:expr) => {
        $call.map_err(|e| validation_error($stage, e))?
    };
}

macro_rules! application_readback {
    ($stage:literal, $call:expr) => {
        $call.map_err(|e| application_error($stage, e))?
    };
}

/// A private-constructor copy of one historical message, not fresh signing
/// authority. Cloning/retransmission can reproduce only these same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeReplayedNativeVoteV1 {
    vote: Vote,
}
impl PocoNodeReplayedNativeVoteV1 {
    pub const fn vote_v1(&self) -> &Vote {
        &self.vote
    }
}

/// Non-cloneable owner which keeps every participating store and its namespace
/// locks alive. This candidate has no consensus runtime or signing surface.
pub struct PocoNodeNativeSignedVoteReplayOwnerV1<W> {
    config: CoreConfig,
    paths: AuthorityPathsV0,
    safety: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer: PinnedSqliteSignerJournalV0<W>,
    application: DurableNativeApplicationV0,
    validation: SqliteProposalValidationStoreV0,
    checkpoint: SqliteExternalNodeCheckpointStoreV0,
    root_lock: CrossStoreLockGuardV0,
    initial_checkpoint: Option<ExternalNodeCheckpointV0>,
    failed: bool,
}

/// Reopen only a fully existing commissioned laboratory root. Missing paths
/// are rejected before Application/K open could create a new namespace.
pub fn open_existing_native_signed_vote_replay_v1<W: ExternalMonotonicWatermarkV0>(
    root: impl AsRef<Path>,
    config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    watermark: W,
) -> ReplayResult<PocoNodeNativeSignedVoteReplayOwnerV1<W>> {
    if config.validator_set().epoch().get() != 0
        || config.validator_set() != application_config.validator_set_v0()
        || config.consensus_parameters() != application_config.consensus_parameters_v0()
        || config.validator_set().chain_id().as_str() != application_config.chain_id_v0()
        || config.validator_set().genesis_hash().as_bytes() != &application_config.genesis_hash_v0()
    {
        return Err(rejected(
            "context",
            "commissioned native/consensus context mismatch",
        ));
    }
    let paths = readback!("paths", existing_paths_v0(root.as_ref()));
    for path in [
        &paths.target_safety,
        &paths.signer,
        &paths.application,
        &paths.validation,
        &paths.checkpoint,
    ] {
        let metadata = fs::symlink_metadata(path).map_err(|_| unavailable("existing_namespace"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
            return Err(rejected(
                "existing_namespace",
                "expected nonempty existing regular database",
            ));
        }
    }
    let root_lock = readback!(
        "root_lock",
        CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(
            &paths.application,
            &paths.validation
        )
    );
    let signer_profile = readback!(
        "signer_profile",
        SignerJournalProfileV0::new(
            config.validator_set().clone(),
            config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&config),
            MAXIMUM_SIGNER_INTENTS_V0,
            MAXIMUM_SIGNER_INTENT_BYTES_V0,
            MAXIMUM_SIGNER_DATABASE_BYTES_V0
        )
    );
    let mut signer =
        PinnedSqliteSignerJournalV0::open_existing_v0(&paths.signer, signer_profile, watermark)
            .map_err(|e| signer_error("signer_pin", e))?;
    let signer_facts = signer
        .confirm_node_checkpoint_head_exact_v0()
        .map_err(|e| signer_error("signer_head", e))?;
    if signer_facts.pending_intent().is_some() {
        return Err(unavailable("unsigned_signer_tail"));
    }
    let limits = readback!(
        "safety_limits",
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES_V0, MAXIMUM_BLOB_BYTES_V0)
    );
    let profile = readback!(
        "safety_profile",
        SafetyStateStoreProfileV0::new(
            config.clone(),
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0
        )
    );
    let safety = readback!(
        "safety_open",
        SqliteSafetyStateStoreV0::open_existing(
            &paths.target_safety,
            profile,
            StrictEd25519Verifier
        )
    );
    let application = application_readback!(
        "application_open",
        DurableNativeApplicationV0::open(&paths.application, application_config)
    );
    let scope = readback!(
        "validation_scope",
        ProposalValidationStoreScopeV0::new(hash_v0(
            PROPOSAL_SCOPE_DOMAIN_V0,
            &[
                config.validator_set().id().as_bytes(),
                config.local_validator().as_bytes()
            ]
        ))
    );
    let validation = validation_readback!(
        "validation_open",
        SqliteProposalValidationStoreV0::open(
            &paths.validation,
            scope,
            MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0
        )
    );
    let checkpoint = readback!(
        "checkpoint_open",
        SqliteExternalNodeCheckpointStoreV0::open_existing(&paths.checkpoint)
    );
    let mut owner = PocoNodeNativeSignedVoteReplayOwnerV1 {
        config,
        paths,
        safety,
        signer,
        application,
        validation,
        checkpoint,
        root_lock,
        initial_checkpoint: None,
        failed: false,
    };
    owner.replay_exact_vote_v1()?;
    Ok(owner)
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeNativeSignedVoteReplayOwnerV1<W> {
    /// Revalidates the complete join twice and returns only the previously
    /// journaled Vote. There is no acknowledgement or durable state change.
    pub fn replay_exact_vote_v1(&mut self) -> ReplayResult<PocoNodeReplayedNativeVoteV1> {
        if self.failed {
            return Err(unavailable("owner_fenced"));
        }
        self.failed = true;
        let first = self.read_join_v1()?;
        let second = self.read_join_v1()?;
        if first != second {
            return Err(rejected("fresh_join", "owner changed during replay"));
        }
        if self
            .initial_checkpoint
            .is_some_and(|checkpoint| checkpoint != second.1)
        {
            return Err(rejected(
                "checkpoint_changed",
                "checkpoint no longer matches opened owner",
            ));
        }
        self.initial_checkpoint = Some(second.1);
        self.failed = false;
        Ok(PocoNodeReplayedNativeVoteV1 { vote: second.0 })
    }

    fn read_join_v1(&mut self) -> ReplayResult<(Vote, ExternalNodeCheckpointV0)> {
        readback!("root_identity", self.root_lock.validate_identity_v0());
        let head = readback!("safety_head", self.safety.head());
        let authorizing = if head
            .transition_context()
            .native_valid_transition()
            .is_some()
        {
            head.clone()
        } else if matches!(
            head.transition_context(),
            SafetyTransitionContextV0::Ordinary
        ) {
            let prior = readback!(
                "safety_predecessor",
                self.safety.authenticated_predecessor_v0()
            )
            .ok_or_else(|| unavailable("authorizing_predecessor"))?;
            if !head
                .state()
                .matches_durable_signature_released_successor_of_v1(prior.state())
            {
                return Err(unavailable("not_exact_signature_release"));
            }
            prior
        } else {
            return Err(unavailable("unsupported_safety_cut"));
        };
        let transition = authorizing
            .transition_context()
            .native_valid_transition()
            .ok_or_else(|| unavailable("authorizing_native_valid"))?;
        let state = authorizing.state();
        if state.safety_halt().is_some()
            || state.pending_finalize().is_some()
            || state.pending_tc_high_qc_sync().is_some()
            || state.pending_standalone_qc_sync().is_some()
            || !state.payload_validation_obligations().is_empty()
            || transition.route() != PayloadValidationRouteV0::Proposal
            || transition.post_ack_action_code()
                != NativeValidPostAckActionV0::RequestSignature.code()
            || transition.completion_revision() != authorizing.revision()
        {
            return Err(unavailable("unsupported_authorizing_cut"));
        }
        let Some(SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            signing_root,
        }) = state.pending_sign()
        else {
            return Err(unavailable("no_authorized_vote"));
        };
        if *authorizing_safety_revision != authorizing.revision() {
            return Err(unavailable("historical_signing_authorization"));
        }
        let completions = state
            .payload_validation_completions()
            .iter()
            .filter(|c| c.first_recorded_revision() == authorizing.revision())
            .collect::<Vec<_>>();
        let [completion] = completions.as_slice() else {
            return Err(unavailable("current_valid_completion"));
        };
        if completion.route() != transition.route()
            || completion.id() != transition.validation_id()
            || native_valid_result_checksum_v0(completion.result())
                != Some(transition.valid_result_checksum())
        {
            return Err(rejected(
                "native_valid_completion",
                "transition/completion mismatch",
            ));
        }
        let artifact = completion
            .result()
            .artifact_ref()
            .ok_or_else(|| unavailable("no_valid_artifact"))?;
        let intent = readback!(
            "canonical_intent",
            CanonicalSignIntentV0::vote(
                self.config.validator_set(),
                self.config.local_validator(),
                *authorizing_safety_revision,
                *view,
                *height,
                *block_id
            )
        );
        if intent.signing_root() != *signing_root {
            return Err(rejected("intent_root", "durable Vote root mismatch"));
        }
        let signed = self
            .signer
            .read_signed_intent_exact_v1(&intent)
            .map_err(|e| signer_error("signed_readback", e))?
            .ok_or_else(|| unavailable("exact_signature_absent"))?;
        let signer = signed.checkpoint_facts_v1();
        let safety = readback!(
            "safety_confirmation",
            self.safety
                .confirm_node_checkpoint_head_exact_v0(head.state())
        );
        if !signer.belongs_to_pinned_journal_at_path_v0(&self.signer, &self.paths.signer)
            || signer.pending_intent().is_some()
            || signer
                .capacity()
                .maximum_safety_revision()
                .is_some_and(|r| r > authorizing.revision())
            || signer.capacity().maximum_vote_view()
                != head.state().last_voted_view().map(|v| v.get())
            || signer.capacity().maximum_timeout_view()
                != head.state().last_timeout_view().map(|v| v.get())
        {
            return Err(rejected("signer_safety", "signer/Safety owner mismatch"));
        }
        let audit = validation_readback!(
            "terminal_k_audit",
            self.validation.confirm_terminal_k_audit_v0()
        );
        let owner = readback!(
            "validation_owner",
            ProposalValidationOwnerIdV0::new(hash_v0(
                PROPOSAL_OWNER_DOMAIN_V0,
                &[
                    &self
                        .application
                        .config_v0()
                        .chain_genesis_facts_v0()
                        .chain_descriptor_hash_v0(),
                    self.config.local_validator().as_bytes()
                ]
            ))
        );
        if !audit.belongs_to_store_at_path_v0(&self.validation, &self.paths.validation)
            || audit.owner_id_v0() != owner
            || audit.store_sequence_v0()
                != audit
                    .terminal_row_count_v0()
                    .checked_mul(3)
                    .ok_or_else(|| rejected("k_sequence", "overflow"))?
        {
            return Err(rejected("terminal_k_owner", "K owner/inventory mismatch"));
        }
        let matches = audit
            .terminal_bindings_v0()
            .iter()
            .filter(|b| {
                b.block_id().as_bytes() == completion.id().block_id().as_bytes()
                    && b.view() == completion.id().view().get()
                    && b.generation() == completion.id().generation()
                    && b.route() == ProposalRouteV0::Proposal
            })
            .collect::<Vec<_>>();
        let [binding] = matches.as_slice() else {
            return Err(unavailable("exact_k_binding"));
        };
        let binding = *binding;
        readback!(
            "binding_context",
            validate_binding_context_v0(binding, &self.config)
        );
        if binding.route() != ProposalRouteV0::Proposal
            || binding.block_id().as_bytes() != block_id.as_bytes()
            || binding.height().get() != height.get()
            || binding.view() != view.get()
        {
            return Err(rejected("binding_vote", "K binding differs from Vote"));
        }
        let k = validation_readback!(
            "k_readback",
            self.validation
                .confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        );
        let closure = k.safety_closure_v0();
        if !k.belongs_to_store_at_path_v0(&self.validation, &self.paths.validation)
            || k.owner_id_v0() != owner
            || closure.validation_id() != binding.validation_id()
            || closure.safety_revision() != authorizing.revision()
            || closure.safety_record_digest().as_bytes() != &authorizing.state_record_checksum()
            || closure.vote_intent_digest().as_bytes() != signing_root.as_bytes()
            || closure.core_delivery_digest() != k.core_delivery_digest_v0()
        {
            return Err(rejected(
                "k_safety",
                "K does not bind the authorizing Safety record",
            ));
        }
        let executed = validation_readback!(
            "k_artifact",
            self.validation.read_artifact_exact_v0(binding)
        );
        let p = application_readback!(
            "p_history",
            self.application
                .confirm_durable_execution_history_row_v0(&executed)
        );
        if p.status_v0() != DurableExecutionHistoryStatusV0::Prepared {
            return Err(unavailable("p_not_prepared"));
        }
        let parent = application_readback!("p_parent", p.parent_head_v0());
        let target = application_readback!("p_target", p.target_head_v0());
        if !p.belongs_to_application_at_path_v0(&self.application, &self.paths.application)
            || p.store_id_v0() != self.application.config_v0().store_id()
            || p.artifact_digest_v0() != artifact.source_artifact_checksum()
            || p.overlay_digest_v0() != artifact.overlay().overlay_checksum()
            || parent.block_id().as_bytes() != artifact.overlay().parent_block_id().as_bytes()
            || target.block_id().as_bytes() != block_id.as_bytes()
            || target.height().get() != height.get()
        {
            return Err(rejected(
                "p_k_safety",
                "native artifact/overlay differs from K/Safety",
            ));
        }
        let committed = application_readback!(
            "committed_head",
            self.application.confirmed_committed_head_v0()
        );
        let applied = head.state().application_applied();
        if committed.block_id().as_bytes() != applied.block_id().as_bytes()
            || committed.height().get() != applied.height().get()
        {
            return Err(rejected(
                "committed_safety",
                "application committed head differs from Safety",
            ));
        }
        let checkpoint = readback!(
            "checkpoint_load",
            self.checkpoint.load(signer.exact_watermark().scope())
        )
        .ok_or_else(|| unavailable("checkpoint_absent"))?;
        let fields = checkpoint.fields();
        if fields.scope != signer.exact_watermark().scope()
            || fields.safety_journal_id != safety.journal_id_v0()
            || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
            || fields.safety_revision != safety.revision_v0()
            || fields.safety_state_record_checksum != safety.state_record_checksum_v0()
            || fields.safety_record_chain_checksum != safety.chain_checksum_v0()
            || fields.signer_journal_id != signer.journal_id()
            || fields.signer_profile_checksum != signer.profile_checksum()
            || fields.signer_exact_watermark != signer.exact_watermark()
        {
            return Err(unavailable("checkpoint_owner_join"));
        }
        let projection = native_k_application_projection_v1(
            &NativeKAuthorizingSafetyFactsV1 {
                journal_id: safety.journal_id_v0(),
                verifier_profile_ref: safety.verifier_profile_ref_v0(),
                core_config_ref: safety.core_config_ref_v0(),
                revision: authorizing.revision(),
                state_record_checksum: authorizing.state_record_checksum(),
                chain_checksum: authorizing.chain_checksum(),
            },
            &k,
        );
        if !projection.matches_checkpoint_application_v1(&checkpoint) {
            return Err(unavailable("checkpoint_native_k_join"));
        }
        let vote = readback!(
            "vote",
            Vote::new(
                self.config.validator_set().chain_id(),
                self.config.validator_set().protocol_version(),
                self.config.validator_set().epoch(),
                *view,
                *height,
                *block_id,
                self.config.validator_set().id(),
                self.config.local_validator(),
                signed.signature_v1(),
                self.config.validator_set()
            )
        );
        readback!(
            "vote_verify",
            vote.verify(self.config.validator_set(), &StrictEd25519Verifier)
        );
        let fresh_signer = self
            .signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(|e| signer_error("final_signer_head", e))?;
        if fresh_signer.exact_watermark() != signer.exact_watermark()
            || fresh_signer.capacity() != signer.capacity()
            || fresh_signer.lifetime_inventory() != signer.lifetime_inventory()
            || readback!(
                "final_checkpoint",
                self.checkpoint.load(signer.exact_watermark().scope())
            ) != Some(checkpoint)
        {
            return Err(rejected(
                "final_external_heads",
                "external authority changed during joined readback",
            ));
        }
        let fresh_safety = readback!("final_safety", self.safety.head());
        if fresh_safety.state_record_checksum() != head.state_record_checksum()
            || fresh_safety.chain_checksum() != head.chain_checksum()
        {
            return Err(rejected(
                "final_safety",
                "Safety changed during joined readback",
            ));
        }
        readback!("root_identity_after", self.root_lock.validate_identity_v0());
        Ok((vote, checkpoint))
    }
}
