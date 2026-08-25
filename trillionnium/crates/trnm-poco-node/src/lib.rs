#![forbid(unsafe_code)]
//! Fail-closed lifecycle scaffold for the future PoCO-BFT node.
//!
//! The default build now contains a private, non-cloneable owner scaffold for
//! one `trnm-native-application` implementation. Its raw constructor and
//! finality-permit constructor are test-only, and none of its types are
//! re-exported, so the production crate has no execute-to-committed-head
//! authority. The test seam preserves exact request/result binding and
//! fail-stops on application uncertainty or result substitution, but it is not
//! yet joined to Core, SafetyStore, finality, authenticated recovery,
//! whole-node checkpointing, or the process host.
//!
//! The owner module is intentionally not part of this crate's external API:
//!
//! ```compile_fail
//! use trnm_poco_node::native_application_owner::PocoNodeNativeApplicationOwnerV0;
//! ```
//!
//! Nor may the owner or its finality capability be re-exported at the crate
//! root:
//!
//! ```compile_fail
//! use trnm_poco_node::PocoNodeNativeApplicationOwnerV0;
//! ```
//!
//! ```compile_fail
//! use trnm_poco_node::PocoNodeNativeFinalityPermitV0;
//! ```
//!
//! The default-built durable-`P` splice is equally private; downstream crates
//! cannot name either its Node owner or its joined Core/App capability:
//!
//! ```compile_fail
//! use trnm_poco_node::native_proposal_p_host::PocoNodeNativeProposalPHostV0;
//! ```
//!
//! ```compile_fail
//! use trnm_poco_node::PocoNodeNativePersistedProposalPV0;
//! ```
//!
//! This package is deliberately separate from the frozen legacy `trnm-node`
//! harness. The feature-gated `PocoNodeProcessHostV0` is the development-only,
//! existing-state owner for one Core, SQLite SafetyStore, native application
//! facade, and independent signer journal. It reconciles those namespaces
//! before retaining exact Core effects as inert memory; none of the owners can
//! be detached through its API. Earlier bounded timeout and invalid-recovery
//! hosts remain test adapters, not the process entry point.
//!
//! This is not a general effect driver or a production node. The unified owner
//! executes only authenticated startup reconciliation, including the existing
//! deterministic-invalid and tag-3 recovery slices. A fresh epoch-zero h1
//! state-sync anchor may enter an offline replay-fenced mode whose sole
//! retained effect is `RequestSafetyReplay`. A separate existing-only owner
//! can instead authenticate the exact proof-named empty h2/h3 bodies, keep a
//! virgin signer pinned, and close their real speculative P/D/C/K lifecycle
//! without finalization authority. Stable rev0/rev2/rev4 cuts reopen; rev1/3
//! remain unrecoverable in-flight cuts. Rev4 reconstructs the pruned h2
//! transition and requires its chain checksum to equal Safety's authenticated
//! retained rev3 predecessor before activation.
//! This is not a snapshot downloader, peer authenticator, or
//! general-height/cross-epoch state sync. The host never signs, applies a
//! fresh finalization, arms a timer,
//! synchronizes a certificate, binds a network, or accepts ingress. Its
//! retained effects are observable only as sanitized kinds. Default,
//! production-shaped and unknown binary invocations always exit non-zero. Two
//! explicit manifest-bound G2 candidate-only commands may instead prepare an
//! inert process anchor or retain a freshly revalidated inert owner until
//! control-stdin EOF; neither command reaches Core, networking, signing,
//! voting or application. These
//! omissions keep the scaffold fail-closed until the
//! frozen production contracts have real adapters; they must not be bypassed
//! with the private CometBFT application fixture.
//!
//! Consensus private-key material is not part of the default host surface.
//! The direct `ed25519-dalek` dependency is available only through the
//! explicitly named `fixture-raw-key` feature (which is transitively selected
//! by process-test helper features).  The raw-key code below is confined to
//! `#[cfg(test)]` or those fixture/test-support paths; production constructors
//! accept only the typed signer-journal/remote-signer boundaries.  This is a
//! compile boundary, not a claim that the laboratory validator crate has
//! already been split into a production crate and a fixture crate.
//!
//! An operator-pinned authenticated genesis application parent is also outside
//! every ordinary or generic owner in this package. The separate
//! feature-gated `PocoNodeAuthenticatedGenesisCommissioningHostV0` can own only its inert
//! revision-zero commissioning closure; it exposes no Core, effect, runtime
//! authority, signer activation, network, timer, finalization, or production
//! path. Generic hosts never infer that role or fall through to store-level
//! rejection.
//!
//! The safety store, signer journal, and optional application recovery store
//! must live in non-overlapping, already-existing canonical parent
//! directories. Equal, ancestor, and descendant parent namespaces are all
//! refused. This limits one directory replacement from replacing several
//! local histories, but does not create an atomic transaction across any store
//! or the external signer watermark. New initialization writes the safety
//! store first and the signer journal second. A crash between those operations
//! can therefore leave a safety-only namespace; any partial namespace fails
//! closed on recovery and requires explicit operator quarantine or recovery.
//! Startup rejects a signer maximum Safety revision ahead of the authenticated
//! SafetyStore head, but this is not complete locked-QC/SafetyRules or
//! whole-SafetyStore rollback reconciliation.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
use trnm_consensus_app::NativeValidationRecoveredInvalidReasonV0;
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_app::{
    NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveredInvalidCallbackFactsV0,
    NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryOpenFailureV0,
    NativeValidationRecoveryReconcileFailureV0, NativeValidationRecoveryStoreConfigV0,
    NativeValidationRecoveryStoreV0, NativeValidationRecoveryTransitionFailureV0,
};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_core::{
    Core, Input, PayloadValidationResult, PayloadValidationRouteV0, SafetyStatePersistenceV0,
    ValidationId,
};
use trnm_consensus_core::{
    CoreConfig, DurablePayloadValidationResultV1, Effect, SafetyState, SafetyStateRecordLimitsV0,
};
use trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0;
#[cfg(any(feature = "legacy-consensus-app", test))]
use trnm_consensus_crypto::StrictEd25519Verifier;
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_safety_store::SqliteSafetyStateStoreV0;
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_safety_store::{
    ConfirmedNativeDeterministicInvalidHeadV0, NativeDeterministicInvalidTransitionV0,
    SafetyTransitionContextV0,
};
use trnm_consensus_safety_store::{
    RecoveredSafetyStateV0, SafetyStateStoreProfileV0, SafetyStoreErrorV0,
};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_signer_journal::JournalCapacityV0;
#[cfg(any(feature = "legacy-consensus-app", test))]
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, SignerJournalErrorV0, SignerJournalProfileV0,
    SqliteSignerJournalV0,
};
use trnm_consensus_types::{RolloutPhase, ValidationError};

/// Raw consensus keys are intentionally unavailable to the default host.
///
/// This constant is kept public so release/preflight tooling can assert the
/// boundary without importing any private-key type.  `true` means that the
/// caller deliberately opted into a fixture/process-test build.
pub const FIXTURE_RAW_KEY_FEATURE_ONLY_V0: bool = cfg!(feature = "fixture-raw-key");

/// The production host has no raw private-key dependency or constructor.
/// This remains false even in fixture builds; opting into a fixture never
/// changes the production activation claim.
pub const PRODUCTION_RAW_KEY_DEPENDENCY_V0: bool = false;

#[cfg(feature = "legacy-consensus-app")]
mod authenticated_genesis_commissioning;
#[cfg(feature = "legacy-consensus-app")]
mod authenticated_genesis_h1_takeover;
#[allow(dead_code)]
mod cross_plane_checkpoint_v1;
mod cross_store_lock;
#[cfg(feature = "lab-validator-runtime")]
mod deployed_lab_commissioning;
#[cfg(feature = "lab-validator-runtime")]
mod deployed_lab_process2_recovery;
#[cfg(feature = "lab-validator-runtime")]
mod deployed_lab_recovery;
mod external_node_checkpoint;
#[cfg(feature = "external-proposal-signer")]
mod external_proposal_signer_runtime;
#[cfg(feature = "external-signer-runtime")]
mod external_signer_runtime;
#[cfg(feature = "lab-validator-runtime")]
mod finalization_intent_wal;
mod g2_manifest_bound_process_v2;
#[allow(dead_code)]
mod g2_manifest_bound_v2;
#[allow(dead_code)]
mod g2_order_commit_v1;
#[cfg(feature = "lab-validator-runtime")]
mod lab_authority;
#[cfg(feature = "lab-validator-runtime")]
mod lab_epoch_handoff;
#[allow(dead_code)]
mod native_application_owner;
#[cfg(feature = "lab-validator-runtime")]
mod native_h1_ordinary_takeover;
#[cfg(feature = "lab-validator-runtime-test-support")]
mod native_h1_ordinary_test_support;
mod native_h1_state_sync_commissioning;
#[allow(dead_code)]
mod native_proposal_p_host;
#[cfg(feature = "node-event-wal")]
mod node_event_wal;
mod ordinary_timeout;
#[cfg(feature = "legacy-consensus-app")]
mod process_host;
mod recovery_ready_start;
mod remote_signer_protocol_adapter_v1;
mod remote_signer_roles_v1;
#[cfg(feature = "safety-rules-sidecar")]
mod safety_rules_sidecar;
#[cfg(feature = "tx-admission-wal")]
mod tx_admission_wal;

#[cfg(feature = "legacy-consensus-app")]
pub use authenticated_genesis_commissioning::{
    PocoNodeAuthenticatedGenesisCommissioningConfigV0,
    PocoNodeAuthenticatedGenesisCommissioningErrorV0,
    PocoNodeAuthenticatedGenesisCommissioningFactsV0,
    PocoNodeAuthenticatedGenesisCommissioningHostV0,
    PocoNodeAuthenticatedGenesisCommissioningModeV0,
    PocoNodeAuthenticatedGenesisH1CompletedFactsV0, PocoNodeAuthenticatedGenesisH1CompletedHostV0,
    PocoNodeAuthenticatedGenesisH1CompletedModeV0, PocoNodeAuthenticatedGenesisH1RunErrorV0,
    PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0,
    PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0,
    PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0,
    PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0,
    PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0,
    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0,
};
#[cfg(feature = "legacy-consensus-app")]
pub use authenticated_genesis_h1_takeover::{
    PocoNodeAuthenticatedGenesisH1TakeoverConfigV0, PocoNodeAuthenticatedGenesisH1TakeoverErrorV0,
    PocoNodeAuthenticatedGenesisH1TakeoverFactsV0, PocoNodeAuthenticatedGenesisH1TakeoverHostV0,
    PocoNodeAuthenticatedGenesisH1TakeoverModeV0, PocoNodeAuthenticatedGenesisH1TakeoverSourceV0,
};

#[cfg(feature = "lab-validator-runtime")]
pub use deployed_lab_commissioning::{
    commission_deployed_lab_ordinary_runtime_v0, validate_deployed_lab_core_record_envelope_v0,
    PocoNodeDeployedLabBootstrapV0, PocoNodeDeployedLabCommissioningErrorV0,
    DEPLOYED_LAB_MAXIMUM_BLOB_BYTES_V0, DEPLOYED_LAB_MAXIMUM_RECORD_BYTES_V0,
};
#[cfg(feature = "lab-validator-runtime")]
pub use deployed_lab_process2_recovery::{
    recover_deployed_lab_process2_v0, PocoNodeDeployedLabProcess2ActivatedFactsV1,
    PocoNodeDeployedLabProcess2ActivatedOwnerV1, PocoNodeDeployedLabProcess2CaughtUpOwnerV1,
    PocoNodeDeployedLabProcess2RecoveryErrorV0, PocoNodeDeployedLabProcess2RecoveryFactsV0,
    PocoNodeDeployedLabProcess2RecoveryOwnerV0, PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1,
    PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1, PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1,
    PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1, PocoNodeDeployedLabZeroDeltaRestartCutV1,
    DEPLOYED_LAB_PROCESS2_ACTIVATION_V0, DEPLOYED_LAB_PROCESS2_CLEAN_CUT_RECOVERY_V0,
    DEPLOYED_LAB_PROCESS2_PENDING_SIGN_REPLAY_V0,
};
#[cfg(feature = "lab-validator-runtime")]
pub use deployed_lab_recovery::{
    reopen_deployed_lab_ordinary_cut_v0, PocoNodeDeployedLabAuthenticatedReplayFactsV0,
    PocoNodeDeployedLabAuthenticatedReplayOwnerV0, PocoNodeDeployedLabOrdinaryRecoveryOwnerV0,
    PocoNodeDeployedLabRecoveryErrorV0, PocoNodeDeployedLabRecoveryFactsV0,
    PocoNodeDeployedLabReplayBlockV0, PocoNodeDeployedLabSignedAncestryReplayChallengeV0,
    PocoNodeDeployedLabSignedReplayEntryV0, DEPLOYED_LAB_COHERENT_WHOLE_ROOT_ROLLBACK_AUTHORITY_V0,
};
#[cfg(feature = "lab-validator-runtime-test-support")]
pub use deployed_lab_recovery::{
    reopen_deployed_lab_ordinary_host_v0, PocoNodeDeployedLabRecoveryHostV0,
};
pub use external_node_checkpoint::{
    reconcile_development_only_external_node_checkpoint_startup_v0,
    ConfirmedNodeCheckpointCandidateV0, ExternalNodeCheckpointDecodeErrorV0,
    ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStartupErrorV0,
    ExternalNodeCheckpointStartupModeV0, ExternalNodeCheckpointStartupOutcomeV0,
    ExternalNodeCheckpointStoreErrorV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
    SqliteExternalNodeCheckpointStoreV0, EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0,
    EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0, EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0,
    EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0,
};
#[cfg(feature = "external-proposal-signer")]
pub use external_proposal_signer_runtime::{
    initialize_unix_external_proposal_signer_v0, UnixExternalProposalSignerV0,
    UNIX_EXTERNAL_PROPOSAL_SIGNER_CLIENT_COMPOSITION_V0,
    UNIX_EXTERNAL_PROPOSAL_SIGNER_PRODUCTION_CANDIDATE_V0,
    UNIX_EXTERNAL_PROPOSAL_SIGNER_RUNTIME_ACTIVATION_V0,
};
#[cfg(feature = "external-signer-runtime")]
pub use external_signer_runtime::{
    initialize_unix_external_timeout_host_v0, open_unix_external_timeout_host_v0,
    UnixExternalTimeoutHostV0, UNIX_EXTERNAL_TIMEOUT_LOCKED_QC_AUTHORITY_V0,
    UNIX_EXTERNAL_TIMEOUT_PRODUCTION_ACTIVATION_V0, UNIX_EXTERNAL_TIMEOUT_PROPOSAL_SIGNING_V0,
    UNIX_EXTERNAL_TIMEOUT_RUNTIME_COMPOSITION_V0,
};
pub use g2_manifest_bound_process_v2::{
    prepare_g2_manifest_bound_candidate_process_v2, run_g2_manifest_bound_candidate_process_v2,
    PocoNodeG2CandidatePreparedFactsV2, PocoNodeG2CandidateProcessErrorV2,
    PocoNodeG2CandidateProcessManifestV2,
};
#[cfg(feature = "g2-process-test-support")]
#[doc(hidden)]
pub use g2_order_commit_v1::real_e2e_tests::PocoNodeG2ProcessFixtureV2;
#[cfg(feature = "lab-validator-runtime")]
pub use lab_authority::{
    PocoNodeLabAuthorityErrorV0, PocoNodeLabAuthorityPhaseV0, PocoNodeLabCertificateAdvanceV0,
    PocoNodeLabCheckpointComparisonClassV0, PocoNodeLabCheckpointComparisonErrorV0,
    PocoNodeLabFinalizedProofV0, PocoNodeLabFinalizedQueryErrorV0, PocoNodeLabFinalizedQueryV0,
    PocoNodeLabFreshOrdinaryGenesisConfigV0, PocoNodeLabInertRequestFactsV0,
    PocoNodeLabInertRequestOwnerV0, PocoNodeLabInertTimeoutFactsV0, PocoNodeLabInertTimeoutOwnerV0,
    PocoNodeLabOrdinaryProposalRuntimeV0, PocoNodeLabPendingFinalizationOwnerV0,
    PocoNodeLabPhaseFactsV0, PocoNodeLabProposalBindingV0, PocoNodeLabProposalJournalConfigV0,
    PocoNodeLabProposalParentV0, PocoNodeLabRuntimeFactsV0, PocoNodeLabSignedTimeoutFactsV0,
    PocoNodeLabSignedTimeoutOutboundV0, PocoNodeLabSignedTimeoutOwnerV0,
    PocoNodeLabSignedVoteFactsV0, PocoNodeLabSignedVoteOutboundV0, PocoNodeLabSignedVoteOwnerV0,
    PocoNodeLabTerminalCheckpointApplicationV0, PocoNodeLabTerminalCutV0,
    PocoNodeLabTerminalOwnerV0,
};
#[cfg(feature = "lab-validator-runtime")]
pub use lab_epoch_handoff::{
    verify_poco_node_lab_same_version_epoch_transition_v0,
    PocoNodeLabEpochTransitionObservationErrorV0, PocoNodeLabVerifiedEpochTransitionObservationV0,
};
#[cfg(feature = "lab-validator-runtime")]
pub use native_h1_ordinary_takeover::PocoNodeNativeH1OrdinaryRecoveryConfigV0;
#[cfg(feature = "lab-validator-runtime-test-support")]
pub use native_h1_ordinary_test_support::{
    commission_native_h1_ordinary_lab_test_bundle_v0, PocoNodeNativeH1OrdinaryLabTestBundleV0,
    PocoNodeNativeH1OrdinaryLabTestSupportErrorV0,
};
pub use native_h1_state_sync_commissioning::{
    PocoNodeNativeH1StateSyncCommissionedFactsV0, PocoNodeNativeH1StateSyncCommissionedHostV0,
    PocoNodeNativeH1StateSyncCommissioningConfigV0, PocoNodeNativeH1StateSyncCommissioningErrorV0,
    PocoNodeNativeH1StateSyncPromotionSourceV0,
};
#[cfg(feature = "node-event-wal")]
pub use node_event_wal::{
    NodeEventCommitDriverV1, NodeEventCommitReceiptV1, NodeEventIntentV1, NodeEventRecoveryV1,
    NodeEventWalErrorV1, NodeEventWalV1, PocoNodeHostEventCommitOwnerV1,
    PocoNodeHostEventCommitWalV1, PocoNodeHostEventWalErrorV1,
    NODE_EVENT_WAL_PRODUCTION_ACTIVATION_V1, NODE_EVENT_WAL_RUNTIME_COMPOSITION_V1,
};
#[cfg(feature = "node-event-wal")]
pub use ordinary_timeout::PocoNodeHostEventWalOwnerV1;
#[cfg(feature = "recovery-process-test-support")]
pub use ordinary_timeout::PocoNodeTimeoutSigningProcessCheckpointPhaseV0;
pub use ordinary_timeout::{PocoNodeHostActionV0, PocoNodeHostV0, PocoNodeSignedOutboundV0};
#[cfg(feature = "legacy-consensus-app")]
pub use process_host::{
    PocoNodeInertEffectKindV0, PocoNodeProcessBootstrapFactsV0, PocoNodeProcessBootstrapModeV0,
    PocoNodeProcessConfigV0, PocoNodeProcessHostErrorV0, PocoNodeProcessHostV0,
    PocoNodeProcessLifecyclePhaseV0,
};
pub use recovery_ready_start::{
    Process2RecoveryReadyStartCoordinatorV1, Process2RecoveryTransitionBindingV1,
    Process2RecoveryTransitionFactsV1, Process2RecoveryTransitionJournalV1,
    Process2RecoveryTransitionPhaseV1, RecoveryTransitionJournalErrorV1,
    PROCESS2_RECOVERY_READY_START_COORDINATOR_V1, PROCESS2_RECOVERY_RUNTIME_WIRING_V1,
    PROCESS2_RECOVERY_START_ACTIVATION_V1, PROCESS2_RECOVERY_TRANSITION_JOURNAL_V1,
};
pub use remote_signer_protocol_adapter_v1::{
    decode_remote_signer_protocol_adapter_v1_exact,
    prepare_remote_signer_protocol_adapter_v1_exact, PocoNodeRemoteSignerProtocolAdapterErrorV1,
    PocoNodeRemoteSignerProtocolAdapterV1, MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_BARE_REF_BINDING_SOURCE_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_DESCRIPTOR_EQUIVALENCE_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_DIRECT_CONSTRUCTOR_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_LEASE_AUTHORITY_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_PRODUCTION_ACTIVATION_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_REQUEST_AUTHORITY_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_RESOLVER_ATTESTATION_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_RUNTIME_ACTIVATION_V1,
    REMOTE_SIGNER_PROTOCOL_ADAPTER_SAFETY_RULES_V1, REMOTE_SIGNER_PROTOCOL_ADAPTER_SCHEMA_V1,
};
pub use remote_signer_roles_v1::{
    decode_remote_signer_role_bindings_v1_exact, ConsensusRemoteSignerProfileV1,
    ConsensusSignerPurposeV1, ConsensusTimeoutSignCommandV1, ConsensusVoteSignCommandV1,
    OperatorRecoveryPublicKeyV1, OperatorRecoveryRemoteSignerProfileV1,
    OperatorRecoverySigningPurposeV1, P2pIdentityPublicKeyV1, P2pIdentityRemoteSignerProfileV1,
    P2pIdentitySigningPurposeV1, PocoNodeRemoteSignerRoleBindingsV1, RemoteSignerEndpointRefV1,
    RemoteSignerProfileRefV1, RemoteSignerRoleConfigErrorV1, RemoteSignerRoleV1,
    MAX_REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_BYTES_V1, MAX_REMOTE_SIGNER_PROFILE_DESCRIPTOR_BYTES_V1,
    MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1, REMOTE_SIGNER_GENERIC_SIGN_BYTES_V1,
    REMOTE_SIGNER_ROLE_BINDINGS_SCHEMA_V1, REMOTE_SIGNER_RUNTIME_ACTIVATION_V1,
    REMOTE_SIGNER_RUNTIME_PRIVATE_KEY_CONFIG_V1, REMOTE_SIGNER_SAFETY_RULES_EVALUATION_V1,
    REMOTE_SIGNER_SAFE_VOTE_AUTHORITY_V1,
};
#[cfg(feature = "safety-rules-sidecar")]
pub use safety_rules_sidecar::{
    SafetyRulesSemanticSidecarErrorV1, SafetyRulesSemanticSidecarV1,
    SAFETY_RULES_SEMANTIC_SIDECAR_PRODUCTION_ACTIVATION_V1,
    SAFETY_RULES_SEMANTIC_SIDECAR_RUNTIME_COMPOSITION_V1,
};
#[cfg(feature = "tx-admission-wal")]
pub use tx_admission_wal::{
    NodeOwnedTxAdmissionBoundaryV0, SqlitePendingNonceAuthorityV0, TxAdmissionWalErrorV0,
    TX_ADMISSION_BOUNDARY_BROADCAST_V0, TX_ADMISSION_BOUNDARY_CHECKTX_V0,
    TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0, TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0,
    TX_ADMISSION_BOUNDARY_SIGNING_V0, TX_ADMISSION_WAL_PRODUCTION_ACTIVATION_V0,
    TX_ADMISSION_WAL_RUNTIME_COMPOSITION_V0,
};
/// This package must not be interpreted as a deployable consensus candidate.
pub const PRODUCTION_CANDIDATE_V0: bool = false;

/// This package has only a bounded timeout-signing effect path, not a complete
/// node host, pacemaker, application driver, or network runtime.
pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;

/// SHA-256 of `trnm.poco-node.strict-ed25519-verifier-profile.v0`.
///
/// The safety journal binds this exact verification implementation profile;
/// callers cannot substitute a caller-selected profile reference.
pub const STRICT_ED25519_VERIFIER_PROFILE_REF_V0: [u8; 32] = [
    0x21, 0xc6, 0x12, 0x2a, 0xbb, 0xc2, 0xae, 0x7c, 0x72, 0xf0, 0x22, 0x72, 0xc1, 0xdc, 0x24, 0x1b,
    0xb0, 0x3a, 0x52, 0x67, 0x7d, 0xc4, 0x1f, 0xd2, 0x53, 0x63, 0x3f, 0x17, 0x89, 0xcc, 0x41, 0x1a,
];

/// SHA-256 of `trnm.poco-node.signer-journal-profile.v0`.
///
/// This binds the host's frozen strict-Ed25519 signer-journal profile; it is not
/// a key identifier or a claim that a production producer/HSM is configured.
pub const SIGNER_JOURNAL_PROFILE_REF_V0: [u8; 32] = [
    0xe4, 0xff, 0xb8, 0x35, 0x52, 0x4b, 0xfd, 0x25, 0x4a, 0xb3, 0x11, 0x0c, 0xa6, 0xad, 0xcf, 0x13,
    0xc4, 0x85, 0x57, 0x4c, 0xdf, 0xdf, 0xc0, 0x0d, 0x1e, 0x84, 0x42, 0x2d, 0x42, 0xb9, 0x36, 0x69,
];

const SIGNER_WATERMARK_SCOPE_DOMAIN_V0: &[u8] = b"trnm.poco-node.signer-watermark-scope.v0";

/// A frozen production contract which this scaffold intentionally does not
/// implement or claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwiredProductionContractV0 {
    CanonicalSignIntentSignerAdapter,
    IndependentSignerWatermark,
    CompleteHotstuffSafetyRules,
    SafetyStateSignerLockReconciliation,
    ApplicationStoreAdapter,
    ApplicationValidationRecoveryBeyondDeterministicInvalid,
    BlockIdSpeculativeOverlay,
    OrderedFinalizationQueue,
    EffectDriver,
    AuthenticatedPacemakerTransport,
    StateSync,
}

impl UnwiredProductionContractV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalSignIntentSignerAdapter => "canonical_sign_intent_signer_adapter_v0",
            Self::IndependentSignerWatermark => "independent_signer_watermark",
            Self::CompleteHotstuffSafetyRules => "complete_hotstuff_safety_rules",
            Self::SafetyStateSignerLockReconciliation => "safety_state_signer_lock_reconciliation",
            Self::ApplicationStoreAdapter => "application_store_adapter",
            Self::ApplicationValidationRecoveryBeyondDeterministicInvalid => {
                "application_validation_recovery_beyond_deterministic_invalid_v0"
            }
            Self::BlockIdSpeculativeOverlay => "block_id_speculative_overlay",
            Self::OrderedFinalizationQueue => "ordered_finalization_queue",
            Self::EffectDriver => "core_effect_driver",
            Self::AuthenticatedPacemakerTransport => "authenticated_pacemaker_transport",
            Self::StateSync => "state_sync",
        }
    }
}

/// Exact activation blockers at this host boundary.
pub const UNWIRED_PRODUCTION_CONTRACTS_V0: &[UnwiredProductionContractV0] = &[
    UnwiredProductionContractV0::CanonicalSignIntentSignerAdapter,
    UnwiredProductionContractV0::IndependentSignerWatermark,
    UnwiredProductionContractV0::CompleteHotstuffSafetyRules,
    UnwiredProductionContractV0::SafetyStateSignerLockReconciliation,
    UnwiredProductionContractV0::ApplicationStoreAdapter,
    UnwiredProductionContractV0::ApplicationValidationRecoveryBeyondDeterministicInvalid,
    UnwiredProductionContractV0::BlockIdSpeculativeOverlay,
    UnwiredProductionContractV0::OrderedFinalizationQueue,
    UnwiredProductionContractV0::EffectDriver,
    UnwiredProductionContractV0::AuthenticatedPacemakerTransport,
    UnwiredProductionContractV0::StateSync,
];

/// Typed, local-only startup configuration for the bounded host scaffold.
///
/// Consensus parameters remain inside [`CoreConfig`]. Record and database
/// capacities are node-local resource bounds and never become block-validity
/// inputs.
#[derive(Debug, Clone)]
pub struct PocoNodeStartConfigV0 {
    safety_store_path: PathBuf,
    safety_store_profile: SafetyStateStoreProfileV0,
    signer_journal_path: PathBuf,
    signer_journal_profile: SignerJournalProfileV0,
}

impl PocoNodeStartConfigV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
        record_limits: SafetyStateRecordLimitsV0,
        maximum_safety_database_bytes: usize,
        maximum_signer_intents: u64,
        maximum_signer_intent_bytes: usize,
        maximum_signer_database_bytes: usize,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_authenticated_genesis_commissioning_v0(&core_config)?;
        // `ValidatorSet::new` is intentionally algorithm-neutral for CEV0
        // fixtures.  This host is an Ed25519 boundary, so perform the strict
        // all-member key admission before any path canonicalization or store
        // profile construction.  Private fields keep production callers from
        // bypassing this constructor; test-only unchecked fixtures remain
        // explicitly outside the startup surface.
        validate_validator_set_strict_ed25519_v0(core_config.validator_set())
            .map_err(PocoNodeHostErrorV0::strict_validator_set)?;
        let safety_store_path = safety_store_path.as_ref();
        if !safety_store_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSafetyStorePath);
        }
        if safety_store_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStorePath);
        }
        let signer_journal_path = signer_journal_path.as_ref();
        if !signer_journal_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSignerJournalPath);
        }
        if signer_journal_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalPath);
        }
        if core_config.consensus_parameters().production_activation() {
            return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
        }
        let rollout_phase = core_config.consensus_parameters().rollout_phase();
        if rollout_phase != RolloutPhase::Shadow {
            return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
        }
        let epoch = core_config.validator_set().epoch().get();
        if epoch != 0 {
            return Err(PocoNodeHostErrorV0::UnsupportedEpoch { epoch });
        }
        let safety_store_file_name = safety_store_path
            .file_name()
            .expect("validated safety-store file name");
        let safety_store_parent = fs::canonicalize(
            safety_store_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSafetyStorePath)?,
        )
        .map_err(PocoNodeHostErrorV0::safety_store_parent)?;
        if !safety_store_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStoreParent);
        }
        let signer_journal_file_name = signer_journal_path
            .file_name()
            .expect("validated signer-journal file name");
        let signer_journal_parent = fs::canonicalize(
            signer_journal_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSignerJournalPath)?,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal_parent)?;
        if !signer_journal_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalParent);
        }
        if canonical_parent_namespaces_overlap_v0(&safety_store_parent, &signer_journal_parent) {
            return Err(PocoNodeHostErrorV0::SharedStoreParentNamespace);
        }
        let safety_store_path = safety_store_parent.join(safety_store_file_name);
        let signer_journal_path = signer_journal_parent.join(signer_journal_file_name);
        let signer_journal_profile = SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let safety_store_profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits,
            maximum_safety_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        })
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store_path.as_path()
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.safety_store_profile.core_config()
    }

    pub const fn record_limits(&self) -> SafetyStateRecordLimitsV0 {
        self.safety_store_profile.record_limits()
    }

    #[cfg(feature = "legacy-consensus-app")]
    pub(crate) const fn safety_verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.safety_store_profile.verifier_profile_ref()
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.safety_store_profile.maximum_database_bytes()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal_path.as_path()
    }

    pub const fn maximum_signer_intents(&self) -> u64 {
        self.signer_journal_profile.maximum_intents()
    }

    pub const fn maximum_signer_intent_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_intent_bytes()
    }

    pub const fn maximum_signer_database_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_database_bytes()
    }

    /// Exact SafetyStore profile used only by the required-feature process
    /// recovery helper while it constructs an initial authentic O+P case.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn recovery_process_safety_store_profile_v0(&self) -> SafetyStateStoreProfileV0 {
        self.safety_store_profile.clone()
    }

    /// Exact signer-journal profile used only by the required-feature process
    /// recovery helper while it constructs an initial authentic O+P case.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn recovery_process_signer_journal_profile_v0(&self) -> SignerJournalProfileV0 {
        self.signer_journal_profile.clone()
    }
}

/// Existing-only startup configuration for the bounded G1c validation
/// recovery path.
///
/// The application status path is canonicalized only through its already-
/// existing parent. The application facade separately derives and verifies
/// its exact SQLite path before opening it. All three store parents must be
/// non-overlapping canonical namespaces: equal, ancestor, and descendant
/// parents are refused.
#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug)]
pub struct PocoNodeValidationRecoveryConfigV0 {
    node: PocoNodeStartConfigV0,
    application_status_path: PathBuf,
    signer_policy_hash: [u8; 32],
}

#[cfg(feature = "legacy-consensus-app")]
impl PocoNodeValidationRecoveryConfigV0 {
    pub fn new(
        node: PocoNodeStartConfigV0,
        application_status_path: impl AsRef<Path>,
        signer_policy_hash: [u8; 32],
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_authenticated_genesis_commissioning_v0(node.core_config())?;
        let application_status_path = application_status_path.as_ref();
        if !application_status_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeApplicationStatusPath);
        }
        let application_file_name = application_status_path
            .file_name()
            .ok_or(PocoNodeHostErrorV0::InvalidApplicationStatusPath)?;
        let application_parent = fs::canonicalize(
            application_status_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidApplicationStatusPath)?,
        )
        .map_err(PocoNodeHostErrorV0::application_store_parent)?;
        if !application_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidApplicationStoreParent);
        }
        let safety_parent = node
            .safety_store_path
            .parent()
            .ok_or(PocoNodeHostErrorV0::InvalidSafetyStorePath)?;
        let signer_parent = node
            .signer_journal_path
            .parent()
            .ok_or(PocoNodeHostErrorV0::InvalidSignerJournalPath)?;
        if canonical_parent_namespaces_overlap_v0(&application_parent, safety_parent)
            || canonical_parent_namespaces_overlap_v0(&application_parent, signer_parent)
        {
            return Err(PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace);
        }
        Ok(Self {
            node,
            application_status_path: application_parent.join(application_file_name),
            signer_policy_hash,
        })
    }

    pub const fn node_config(&self) -> &PocoNodeStartConfigV0 {
        &self.node
    }

    pub fn application_status_path(&self) -> &Path {
        self.application_status_path.as_path()
    }

    pub const fn signer_policy_hash(&self) -> [u8; 32] {
        self.signer_policy_hash
    }
}

fn canonical_parent_namespaces_overlap_v0(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn reject_authenticated_genesis_commissioning_v0(
    core_config: &CoreConfig,
) -> Result<(), PocoNodeHostErrorV0> {
    if core_config
        .authenticated_genesis_application_parent_v0()
        .is_some()
    {
        return Err(PocoNodeHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost);
    }
    Ok(())
}

fn derive_signer_watermark_scope_v0(core_config: &CoreConfig) -> [u8; 32] {
    let validator_set = core_config.validator_set();
    let author = core_config.local_validator();
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_WATERMARK_SCOPE_DOMAIN_V0);
    hasher.update((validator_set.chain_id().as_bytes().len() as u64).to_be_bytes());
    hasher.update(validator_set.chain_id().as_bytes());
    hasher.update(validator_set.protocol_version().get().to_be_bytes());
    hasher.update(validator_set.epoch().get().to_be_bytes());
    hasher.update(validator_set.id().as_bytes());
    hasher.update((author.as_bytes().len() as u64).to_be_bytes());
    hasher.update(author.as_bytes());
    hasher.finalize().into()
}

/// How a host owner acquired its exact safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBootstrapModeV0 {
    InitializedGenesis,
    RecoveredExisting,
}

/// Lifecycle phases currently expressible by the ordinary and recovery hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifecyclePhaseV0 {
    BootstrappedInert,
    BoundedTimeoutSigning,
}

/// Application-journal state observed before the bounded recovery transition.
#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoverySourceStateV0 {
    CallbackPending,
    Delivered,
    Acked,
}

/// Exact result of the recovery-aware inert bootstrap.
#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoveryBootstrapV0 {
    NotRequired,
    ObligationCompleted {
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        completion_revision: u64,
        source: ValidationRecoverySourceStateV0,
    },
    CompletionConfirmed {
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        completion_revision: u64,
        source: ValidationRecoverySourceStateV0,
    },
}

/// A durable boundary exposed only to the real-process recovery test helper.
///
/// These names describe the exact SafetyState/ApplicationStore pair after
/// both stores have completed their own durability and exact-readback checks.
/// The observer cannot alter either store and is absent from default builds
/// and the official `--no-default-features` development-library artifact.
#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoveryProcessCheckpointPhaseV0 {
    ObligationCallbackPending,
    ObligationDelivered,
    CompletionDelivered,
    CompletionAcked,
}

#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
impl ValidationRecoveryProcessCheckpointPhaseV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObligationCallbackPending => "obligation_callback_pending",
            Self::ObligationDelivered => "obligation_delivered",
            Self::CompletionDelivered => "completion_delivered",
            Self::CompletionAcked => "completion_acked",
        }
    }
}

/// Exact facts supplied to the feature-only real-process checkpoint observer.
#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationRecoveryProcessCheckpointV0 {
    phase: ValidationRecoveryProcessCheckpointPhaseV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    obligation_revision: u64,
    safety_revision: u64,
}

#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
impl ValidationRecoveryProcessCheckpointV0 {
    pub const fn phase(self) -> ValidationRecoveryProcessCheckpointPhaseV0 {
        self.phase
    }

    pub const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn reason(self) -> NativeValidationRecoveredInvalidReasonV0 {
        self.reason
    }

    pub const fn obligation_revision(self) -> u64 {
        self.obligation_revision
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }
}

/// Non-cloneable, recovery-aware owner of the Core and all three local
/// journals used by the bounded deterministic-invalid G1c slice.
///
/// This type has no constructor for fresh application state and no effect-
/// driving API. It can only authenticate an existing schema-v8 application
/// journal and either complete one exact durable invalid obligation, confirm
/// one exact already-persisted completion, or prove that no active recovery
/// work exists.
#[cfg(feature = "legacy-consensus-app")]
pub struct PocoNodeValidationRecoveryHostV0<W> {
    core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    signer_journal_head: SignerWatermarkV0,
    _application_recovery: NativeValidationRecoveryStoreV0,
    application_status_path: PathBuf,
    recovery: ValidationRecoveryBootstrapV0,
    pending_inert_effects: Vec<Effect>,
}

#[cfg(feature = "legacy-consensus-app")]
type ValidationRecoveryOpenPartsV0 = (Core, ValidationRecoveryBootstrapV0, Vec<Effect>, bool);

#[cfg(feature = "legacy-consensus-app")]
impl<W: ExternalMonotonicWatermarkV0> PocoNodeValidationRecoveryHostV0<W> {
    /// Opens all three existing stores and closes the bounded O/P/D/C/K crash
    /// matrix for one deterministic-invalid validation job.
    ///
    /// The order is intentionally a recoverable join, not a cross-WAL atomic
    /// transaction. For an obligation head the exact callback is first
    /// accepted by Core, the application row becomes Delivered, the opaque
    /// Core persistence request is written with its complete application
    /// context, that exact SafetyStore head is read back, the application row
    /// becomes Acked, and only then is `StorageAck` returned to Core. For an
    /// already-complete head no callback or synthetic `StorageAck` is issued.
    pub fn open_existing(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(config.node_config())?;
        #[cfg(feature = "recovery-process-test-support")]
        {
            Self::open_existing_inner_v0(config, external_watermark, None)
        }
        #[cfg(not(feature = "recovery-process-test-support"))]
        {
            Self::open_existing_inner_v0(config, external_watermark)
        }
    }

    /// Opens through the official host while observing authenticated durable
    /// boundaries for the feature-gated real-process SIGKILL matrix.
    ///
    /// The observer is invoked only after the named store pair has completed
    /// its normal durability and exact-readback checks. Returning from the
    /// observer allows the official transition to continue unchanged. This
    /// API does not exist in default builds or the official
    /// `--no-default-features` development-library artifact.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn open_existing_with_process_checkpoint_observer_v0<F>(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
        mut observer: F,
    ) -> Result<Self, PocoNodeHostErrorV0>
    where
        F: FnMut(ValidationRecoveryProcessCheckpointV0),
    {
        reject_activation_request(config.node_config())?;
        Self::open_existing_inner_v0(config, external_watermark, Some(&mut observer))
    }

    fn open_existing_inner_v0(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
        #[cfg(feature = "recovery-process-test-support")] checkpoint_observer: Option<
            &mut dyn FnMut(ValidationRecoveryProcessCheckpointV0),
        >,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(config.node_config())?;
        let core_config = config.node.core_config().clone();
        let chain_id = core_config.validator_set().chain_id();
        let PocoNodeValidationRecoveryConfigV0 {
            node,
            application_status_path,
            signer_policy_hash,
        } = config;
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = node;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        validate_signer_safety_revision_v0(&signer_journal, &head)?;
        let mut application_recovery = NativeValidationRecoveryStoreV0::open_existing_v8(
            NativeValidationRecoveryStoreConfigV0::new(
                application_status_path.clone(),
                chain_id,
                signer_policy_hash,
                safety_store.journal_id_v0(),
                safety_store.verifier_profile_ref_v0(),
            ),
        )
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryOpen)?;
        let active_application_jobs = application_recovery.active_recovery_job_count_v0();
        let obligation_count = head.state().payload_validation_obligations().len();

        let (core, recovery, pending_inert_effects, safety_already_bound) = match obligation_count {
            0 => recover_without_obligation_v0(
                core_config,
                head,
                &safety_store,
                &mut application_recovery,
                active_application_jobs,
                &verifier,
            )?,
            1 => recover_one_invalid_obligation_v0(
                core_config,
                head,
                &mut safety_store,
                &mut application_recovery,
                active_application_jobs,
                &verifier,
                #[cfg(feature = "recovery-process-test-support")]
                checkpoint_observer,
            )?,
            count => {
                return Err(PocoNodeHostErrorV0::UnsupportedValidationObligationCount { count });
            }
        };
        if !safety_already_bound {
            safety_store
                .bind_core_v0(core.safety_state_persistence_binding_v0())
                .map_err(PocoNodeHostErrorV0::safety_store)?;
        }
        let final_head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        if final_head.state() != core.safety_state() {
            return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
        }
        validate_signer_safety_revision_v0(&signer_journal, &final_head)?;
        application_recovery
            .final_exact_audit_v0()
            .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        validate_signer_safety_revision_v0(&signer_journal, &final_head)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            _application_recovery: application_recovery,
            application_status_path,
            recovery,
            pending_inert_effects,
        })
    }

    pub const fn lifecycle_phase(&self) -> HostLifecyclePhaseV0 {
        HostLifecyclePhaseV0::BootstrappedInert
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core.config()
    }

    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub const fn recovery(&self) -> ValidationRecoveryBootstrapV0 {
        self.recovery
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store.path()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal.path()
    }

    pub fn application_status_path(&self) -> &Path {
        self.application_status_path.as_path()
    }

    pub const fn signer_journal_head(&self) -> SignerWatermarkV0 {
        self.signer_journal_head
    }

    pub fn signer_journal_capacity(&self) -> Result<JournalCapacityV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .capacity()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    /// Effects made durable by the final same-process `StorageAck` but kept
    /// inert by this scaffold. V0 permits only a durable safety-halt notice;
    /// no effect is signed, broadcast, or delivered by this package.
    pub fn pending_inert_effect_count(&self) -> usize {
        self.pending_inert_effects.len()
    }

    pub fn safety_head(&self) -> Result<RecoveredSafetyStateV0, PocoNodeHostErrorV0> {
        self.safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
    }

    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

#[cfg(feature = "legacy-consensus-app")]
fn recover_without_obligation_v0(
    core_config: CoreConfig,
    head: RecoveredSafetyStateV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeValidationRecoveryStoreV0,
    active_application_jobs: usize,
    verifier: &StrictEd25519Verifier,
) -> Result<ValidationRecoveryOpenPartsV0, PocoNodeHostErrorV0> {
    match head.transition_context() {
        SafetyTransitionContextV0::Ordinary => {
            if head_has_current_invalid_completion_v0(head.state()) {
                return Err(PocoNodeHostErrorV0::OrdinaryContextForInvalidCompletion {
                    revision: head.revision(),
                });
            }
            if active_application_jobs != 0 {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: 0,
                        actual: active_application_jobs,
                    },
                );
            }
            let core = Core::recover(core_config, head.state().clone(), verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            Ok((
                core,
                ValidationRecoveryBootstrapV0::NotRequired,
                Vec::new(),
                false,
            ))
        }
        SafetyTransitionContextV0::NativeDeterministicInvalid(_) => {
            if active_application_jobs > 1 {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: 1,
                        actual: active_application_jobs,
                    },
                );
            }
            let confirmed = safety_store
                .confirmed_native_deterministic_invalid_head_v0()
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            let source = application
                .recover_confirmed_invalid_completion_v0(&confirmed)
                .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
            let expected_active = match source {
                NativeValidationRecoveredInvalidStateV0::Delivered => 1,
                NativeValidationRecoveredInvalidStateV0::Acked => 0,
                NativeValidationRecoveredInvalidStateV0::CallbackPending => {
                    return Err(PocoNodeHostErrorV0::UnexpectedCompletionApplicationState);
                }
            };
            if active_application_jobs != expected_active {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: expected_active,
                        actual: active_application_jobs,
                    },
                );
            }
            let acked = application
                .acknowledge_recovered_invalid_completion_v0(&confirmed)
                .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
            validate_acked_facts_against_confirmation_v0(&acked, &confirmed)?;
            let core = Core::recover(core_config, confirmed.state().clone(), verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            Ok((
                core,
                ValidationRecoveryBootstrapV0::CompletionConfirmed {
                    route: confirmed.transition().route(),
                    validation_id: confirmed.transition().validation_id(),
                    completion_revision: confirmed.transition().completion_revision(),
                    source: source.into(),
                },
                Vec::new(),
                false,
            ))
        }
        SafetyTransitionContextV0::NativeValid(_) => {
            Err(PocoNodeHostErrorV0::NativeValidRecoveryUnavailable {
                revision: head.revision(),
            })
        }
        SafetyTransitionContextV0::NativeFinalizationApplied(_) => Err(
            PocoNodeHostErrorV0::NativeFinalizationAppliedRecoveryUnavailable {
                revision: head.revision(),
            },
        ),
        SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_) => Err(
            PocoNodeHostErrorV0::StateSyncCheckpointBootstrapRequiresUnifiedHost {
                revision: head.revision(),
            },
        ),
        SafetyTransitionContextV0::AuthenticatedGenesisApplicationBootstrap(_) => {
            Err(PocoNodeHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost)
        }
    }
}

#[cfg(feature = "legacy-consensus-app")]
fn recover_one_invalid_obligation_v0(
    core_config: CoreConfig,
    head: RecoveredSafetyStateV0,
    safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeValidationRecoveryStoreV0,
    active_application_jobs: usize,
    verifier: &StrictEd25519Verifier,
    #[cfg(feature = "recovery-process-test-support")] mut checkpoint_observer: Option<
        &mut dyn FnMut(ValidationRecoveryProcessCheckpointV0),
    >,
) -> Result<ValidationRecoveryOpenPartsV0, PocoNodeHostErrorV0> {
    if !matches!(
        head.transition_context(),
        SafetyTransitionContextV0::Ordinary
    ) {
        return Err(PocoNodeHostErrorV0::UnexpectedObligationTransitionContext {
            revision: head.revision(),
        });
    }
    if active_application_jobs != 1 {
        return Err(
            PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                expected: 1,
                actual: active_application_jobs,
            },
        );
    }
    #[cfg(feature = "recovery-process-test-support")]
    let obligation_revision = head.revision();
    let session = Core::begin_payload_validation_obligation_recovery_v0(
        core_config,
        head.state().clone(),
        verifier,
    )
    .map_err(PocoNodeHostErrorV0::core)?;
    let route = session.challenge().route();
    let validation_id = session.challenge().id();
    let mut core = match session.reconcile_and_activate_v0(application) {
        Ok(core) => core,
        Err(error) => {
            if let Some(failure) = application.last_reconcile_failure_v0() {
                return Err(PocoNodeHostErrorV0::ApplicationRecoveryReconcile(failure));
            }
            return Err(PocoNodeHostErrorV0::core(error));
        }
    };
    let source = application
        .recovered_obligation_state_v0()
        .ok_or(PocoNodeHostErrorV0::MissingReconciledApplicationOwner)?;
    if !matches!(
        source,
        NativeValidationRecoveredInvalidStateV0::CallbackPending
            | NativeValidationRecoveredInvalidStateV0::Delivered
    ) {
        return Err(PocoNodeHostErrorV0::UnexpectedObligationApplicationState);
    }
    let reconciled_callback = application
        .recovered_obligation_callback_facts_v0()
        .ok_or(PocoNodeHostErrorV0::MissingReconciledApplicationOwner)?;
    validate_callback_identity_v0(&reconciled_callback, route, validation_id)?;
    #[cfg(feature = "recovery-process-test-support")]
    if source == NativeValidationRecoveredInvalidStateV0::CallbackPending {
        emit_recovery_process_checkpoint_v0(
            &mut checkpoint_observer,
            ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending,
            reconciled_callback,
            obligation_revision,
            obligation_revision,
        );
    }
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
    };
    let effects = core
        .step(input, verifier)
        .map_err(PocoNodeHostErrorV0::core)?;
    let request = take_exact_recovery_persistence_v0(effects)?;
    let callback_facts = application
        .record_recovered_core_acceptance_v0(&request)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    validate_callback_identity_v0(&callback_facts, route, validation_id)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered,
        callback_facts,
        obligation_revision,
        obligation_revision,
    );
    let context =
        native_invalid_transition_context_v0(&callback_facts, request.state().revision())?;
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    safety_store
        .persist_exact_v0(&request, &context)
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    let confirmed = safety_store
        .confirmed_native_deterministic_invalid_head_exact_v0(request.state(), &context)
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered,
        callback_facts,
        obligation_revision,
        confirmed.revision(),
    );
    let completion_state = application
        .recover_confirmed_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    if completion_state != NativeValidationRecoveredInvalidStateV0::Delivered {
        return Err(PocoNodeHostErrorV0::UnexpectedCompletionApplicationState);
    }
    let acked = application
        .acknowledge_recovered_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    validate_acked_facts_against_confirmation_v0(&acked, &confirmed)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked,
        callback_facts,
        obligation_revision,
        confirmed.revision(),
    );
    let barrier = request.barrier();
    let pending_inert_effects = core
        .step(Input::StorageAck { barrier }, verifier)
        .map_err(PocoNodeHostErrorV0::core)?;
    validate_inert_post_ack_effects_v0(&pending_inert_effects)?;
    if core.safety_state() != confirmed.state() {
        return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
    }
    Ok((
        core,
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: confirmed.transition().completion_revision(),
            source: source.into(),
        },
        pending_inert_effects,
        true,
    ))
}

#[cfg(all(
    feature = "legacy-consensus-app",
    feature = "recovery-process-test-support"
))]
fn emit_recovery_process_checkpoint_v0(
    observer: &mut Option<&mut dyn FnMut(ValidationRecoveryProcessCheckpointV0)>,
    phase: ValidationRecoveryProcessCheckpointPhaseV0,
    callback: NativeValidationRecoveredInvalidCallbackFactsV0,
    obligation_revision: u64,
    safety_revision: u64,
) {
    if let Some(observer) = observer.as_deref_mut() {
        observer(ValidationRecoveryProcessCheckpointV0 {
            phase,
            route: callback.route(),
            validation_id: callback.validation_id(),
            reason: callback.reason(),
            obligation_revision,
            safety_revision,
        });
    }
}

#[cfg(feature = "legacy-consensus-app")]
impl From<NativeValidationRecoveredInvalidStateV0> for ValidationRecoverySourceStateV0 {
    fn from(state: NativeValidationRecoveredInvalidStateV0) -> Self {
        match state {
            NativeValidationRecoveredInvalidStateV0::CallbackPending => Self::CallbackPending,
            NativeValidationRecoveredInvalidStateV0::Delivered => Self::Delivered,
            NativeValidationRecoveredInvalidStateV0::Acked => Self::Acked,
        }
    }
}

fn head_has_current_invalid_completion_v0(state: &SafetyState) -> bool {
    state
        .payload_validation_completions()
        .iter()
        .any(|completion| {
            completion.first_recorded_revision() == state.revision()
                && completion.result() == DurablePayloadValidationResultV1::DeterministicallyInvalid
        })
}

#[cfg(feature = "legacy-consensus-app")]
fn take_exact_recovery_persistence_v0(
    effects: Vec<Effect>,
) -> Result<SafetyStatePersistenceV0, PocoNodeHostErrorV0> {
    if effects.len() != 1 {
        return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
            expected: 1,
            actual: effects.len(),
        });
    }
    match effects
        .into_iter()
        .next()
        .expect("exact effect count checked")
    {
        Effect::PersistSafetyState(request) => Ok(request),
        effect => Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffect {
            effect: effect_name_v0(&effect),
        }),
    }
}

fn effect_name_v0(effect: &Effect) -> &'static str {
    match effect {
        Effect::PersistSafetyState(_) => "persist_safety_state",
        Effect::ValidatePayload(_) => "validate_payload",
        Effect::ValidateSyncedPayload(_) => "validate_synced_payload",
        Effect::RequestSignature { .. } => "request_signature",
        Effect::Broadcast(_) => "broadcast",
        Effect::ArmViewTimer { .. } => "arm_view_timer",
        Effect::RequestSafetyReplay { .. } => "request_safety_replay",
        Effect::RequestTcHighQcSync { .. } => "request_tc_high_qc_sync",
        Effect::RequestStandaloneQcSync { .. } => "request_standalone_qc_sync",
        Effect::SafetyHalted(_) => "safety_halted",
        Effect::Finalize(_) => "finalize",
        Effect::Evidence(_) => "evidence",
    }
}

fn validate_signer_safety_revision_v0<W: ExternalMonotonicWatermarkV0>(
    signer_journal: &SqliteSignerJournalV0<W>,
    safety_head: &RecoveredSafetyStateV0,
) -> Result<(), PocoNodeHostErrorV0> {
    let capacity = signer_journal
        .capacity()
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
    if let Some(signer_revision) = capacity.maximum_safety_revision() {
        if signer_revision > safety_head.revision() {
            return Err(PocoNodeHostErrorV0::SignerSafetyRevisionAhead {
                signer_revision,
                safety_revision: safety_head.revision(),
            });
        }
    }
    let prepared_tail = capacity.intent_count() > 0
        && capacity
            .intent_count()
            .checked_mul(2)
            .and_then(|events| events.checked_sub(1))
            == Some(capacity.event_count());
    if prepared_tail && safety_head.state().pending_sign().is_none() {
        return Err(PocoNodeHostErrorV0::PreparedSignerIntentWithoutCoreOutbox {
            safety_revision: safety_head.revision(),
        });
    }
    Ok(())
}

#[cfg(feature = "legacy-consensus-app")]
fn validate_inert_post_ack_effects_v0(effects: &[Effect]) -> Result<(), PocoNodeHostErrorV0> {
    if let Some(effect) = effects
        .iter()
        .find(|effect| !matches!(effect, Effect::SafetyHalted(_)))
    {
        return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffect {
            effect: effect_name_v0(effect),
        });
    }
    Ok(())
}

#[cfg(feature = "legacy-consensus-app")]
fn validate_callback_identity_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
) -> Result<(), PocoNodeHostErrorV0> {
    if facts.route() != route || facts.validation_id() != validation_id {
        return Err(PocoNodeHostErrorV0::ApplicationCallbackIdentityMismatch);
    }
    Ok(())
}

#[cfg(feature = "legacy-consensus-app")]
fn native_invalid_transition_context_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    completion_revision: u64,
) -> Result<SafetyTransitionContextV0, PocoNodeHostErrorV0> {
    let transition = NativeDeterministicInvalidTransitionV0::new(
        facts.route(),
        facts.validation_id(),
        facts.request_fingerprint(),
        facts.immutable_checksum(),
        facts.host_config_ref(),
        facts.reason().code_v0(),
        facts.artifact_checksum(),
        facts.callback_payload_checksum(),
        facts.idempotency_key(),
        facts.delivery_attempt(),
        facts.row_checksum(),
        facts.outbox_checksum(),
        completion_revision,
    )
    .map_err(PocoNodeHostErrorV0::safety_store)?;
    Ok(SafetyTransitionContextV0::native_deterministic_invalid(
        transition,
    ))
}

#[cfg(feature = "legacy-consensus-app")]
fn validate_acked_facts_against_confirmation_v0(
    acked: &NativeValidationRecoveredAckedFactsV0,
    confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
) -> Result<(), PocoNodeHostErrorV0> {
    let transition = confirmed.transition();
    if acked.route() != transition.route()
        || acked.validation_id() != transition.validation_id()
        || acked.request_fingerprint() != transition.request_fingerprint()
        || acked.immutable_checksum() != transition.job_immutable_checksum()
        || acked.host_config_ref() != transition.application_host_config_ref()
        || acked.reason().code_v0() != transition.reason_code()
        || acked.artifact_checksum() != transition.artifact_checksum()
        || acked.callback_payload_checksum() != transition.callback_payload_checksum()
        || acked.accepted_core_revision() != transition.completion_revision()
        || acked.predecessor_idempotency_key() != transition.idempotency_key()
        || acked.predecessor_delivery_attempt() != transition.delivery_attempt()
        || acked.predecessor_delivered_row_checksum() != transition.delivered_job_row_checksum()
        || acked.predecessor_outbox_checksum() != transition.outbox_checksum()
    {
        return Err(PocoNodeHostErrorV0::ApplicationAcknowledgementMismatch);
    }
    Ok(())
}

fn reject_activation_request(config: &PocoNodeStartConfigV0) -> Result<(), PocoNodeHostErrorV0> {
    reject_authenticated_genesis_commissioning_v0(config.core_config())?;
    let parameters = config.core_config().consensus_parameters();
    if parameters.production_activation() {
        return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
    }
    let rollout_phase = parameters.rollout_phase();
    if rollout_phase != RolloutPhase::Shadow {
        return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
    }
    Ok(())
}

/// The static production gate used by the inert binary and live owner alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionActivationBlockedV0 {
    _private: (),
}

impl ProductionActivationBlockedV0 {
    const fn new() -> Self {
        Self { _private: () }
    }

    pub const fn blockers(self) -> &'static [UnwiredProductionContractV0] {
        UNWIRED_PRODUCTION_CONTRACTS_V0
    }
}

impl fmt::Display for ProductionActivationBlockedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production activation is blocked; unwired contracts: ")?;
        for (index, contract) in UNWIRED_PRODUCTION_CONTRACTS_V0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            formatter.write_str(contract.as_str())?;
        }
        Ok(())
    }
}

impl Error for ProductionActivationBlockedV0 {}

pub const fn production_activation_gate_v0() -> Result<(), ProductionActivationBlockedV0> {
    Err(ProductionActivationBlockedV0::new())
}

/// Startup failures are fail-closed and never converted into consensus
/// invalidity.
#[derive(Debug)]
pub enum PocoNodeHostErrorV0 {
    RelativeSafetyStorePath,
    InvalidSafetyStorePath,
    SafetyStoreParentIo(Box<io::Error>),
    InvalidSafetyStoreParent,
    RelativeSignerJournalPath,
    InvalidSignerJournalPath,
    SignerJournalParentIo(Box<io::Error>),
    InvalidSignerJournalParent,
    SharedStoreParentNamespace,
    RelativeApplicationStatusPath,
    InvalidApplicationStatusPath,
    ApplicationStoreParentIo(Box<io::Error>),
    InvalidApplicationStoreParent,
    SharedApplicationStoreParentNamespace,
    AuthenticatedGenesisCommissioningRequiresDedicatedHost,
    ProductionActivationRequested,
    StrictValidatorSetAdmission {
        reason: &'static str,
    },
    NonShadowRolloutRequested {
        rollout_phase: RolloutPhase,
    },
    UnsupportedEpoch {
        epoch: u64,
    },
    AuthenticatedObligationReplayUnavailable {
        revision: u64,
        obligation_count: usize,
    },
    ValidationRecoveryAwareOpenRequired {
        revision: u64,
    },
    UnsupportedValidationObligationCount {
        count: usize,
    },
    UnexpectedActiveApplicationRecoveryJobs {
        expected: usize,
        actual: usize,
    },
    OrdinaryContextForInvalidCompletion {
        revision: u64,
    },
    NativeValidRecoveryUnavailable {
        revision: u64,
    },
    NativeFinalizationAppliedRecoveryUnavailable {
        revision: u64,
    },
    StateSyncCheckpointBootstrapRequiresUnifiedHost {
        revision: u64,
    },
    UnexpectedObligationTransitionContext {
        revision: u64,
    },
    MissingNativeInvalidTransitionContext {
        revision: u64,
    },
    MissingReconciledApplicationOwner,
    UnexpectedObligationApplicationState,
    UnexpectedCompletionApplicationState,
    ApplicationCallbackIdentityMismatch,
    ApplicationAcknowledgementMismatch,
    UnexpectedRecoveryEffectSet {
        expected: usize,
        actual: usize,
    },
    UnexpectedRecoveryEffect {
        effect: &'static str,
    },
    RecoveredHeadMismatch,
    RecoveredTransitionHeadMismatch,
    OrdinaryPersistenceReadbackMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    NonOrdinarySigningHead {
        revision: u64,
    },
    SignerSafetyRevisionAhead {
        signer_revision: u64,
        safety_revision: u64,
    },
    PreparedSignerIntentWithoutCoreOutbox {
        safety_revision: u64,
    },
    UnsupportedBoundedBootstrapState {
        revision: u64,
        state: &'static str,
    },
    UnsupportedTimeoutSigningIntentKind,
    MissingTimeoutIntentAfterPersistence {
        revision: u64,
    },
    MissingDurableTimeoutSignIntent {
        revision: u64,
    },
    DurableSignIntentMismatch {
        revision: u64,
    },
    SigningCoreSafetyHeadMismatch {
        core_revision: u64,
        safety_revision: u64,
    },
    SigningHeadChangedDuringProducer {
        before_revision: u64,
        after_revision: u64,
    },
    SignIntentSafetyRevisionMismatch {
        intent_revision: u64,
        safety_revision: u64,
    },
    MultipleBoundedPersistenceEffects,
    MultipleSignedOutboundContexts,
    MissingSignedOutboundContext,
    SignedOutboundMismatch,
    UnconsumedSignedOutboundContext,
    UnsupportedBoundedHostEffect {
        effect: &'static str,
    },
    BoundedEffectLimitExceeded,
    BoundedTimeoutHostFailStopped,
    Core(Box<trnm_consensus_core::CoreError>),
    SafetyStore(Box<SafetyStoreErrorV0>),
    SignerJournal(Box<SignerJournalErrorV0>),
    #[cfg(feature = "safety-rules-sidecar")]
    SafetyRulesSemanticSidecar(safety_rules_sidecar::SafetyRulesSemanticSidecarErrorV1),
    #[cfg(feature = "safety-rules-sidecar")]
    SafetyRulesShadowTransitionMismatch {
        revision: u64,
    },
    #[cfg(feature = "safety-rules-sidecar")]
    SafetyRulesSidecarPendingRecoveryRequired {
        revision: u64,
    },
    #[cfg(feature = "safety-rules-sidecar")]
    SafetyRulesSidecarRecoveryNotPending,
    #[cfg(feature = "legacy-consensus-app")]
    ApplicationRecoveryOpen(NativeValidationRecoveryOpenFailureV0),
    #[cfg(feature = "legacy-consensus-app")]
    ApplicationRecoveryReconcile(NativeValidationRecoveryReconcileFailureV0),
    #[cfg(feature = "legacy-consensus-app")]
    ApplicationRecoveryTransition(NativeValidationRecoveryTransitionFailureV0),
}

impl PocoNodeHostErrorV0 {
    fn core(error: trnm_consensus_core::CoreError) -> Self {
        Self::Core(Box::new(error))
    }

    fn safety_store(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(Box::new(error))
    }

    fn signer_journal(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(Box::new(error))
    }

    fn strict_validator_set(error: ValidationError) -> Self {
        let reason = match error {
            ValidationError::InvalidValidatorSet(reason) => reason,
            _ => "validator set shape is not admissible for strict Ed25519",
        };
        Self::StrictValidatorSetAdmission { reason }
    }

    #[cfg(feature = "safety-rules-sidecar")]
    fn safety_rules_sidecar(
        error: safety_rules_sidecar::SafetyRulesSemanticSidecarErrorV1,
    ) -> Self {
        Self::SafetyRulesSemanticSidecar(error)
    }

    fn safety_store_parent(error: io::Error) -> Self {
        Self::SafetyStoreParentIo(Box::new(error))
    }

    fn signer_journal_parent(error: io::Error) -> Self {
        Self::SignerJournalParentIo(Box::new(error))
    }

    #[cfg(feature = "legacy-consensus-app")]
    fn application_store_parent(error: io::Error) -> Self {
        Self::ApplicationStoreParentIo(Box::new(error))
    }
}

impl fmt::Display for PocoNodeHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeSafetyStorePath => {
                formatter.write_str("safety-store path must be absolute")
            }
            Self::InvalidSafetyStorePath => {
                formatter.write_str("safety-store path must name a database file")
            }
            Self::SafetyStoreParentIo(error) => {
                write!(formatter, "safety-store parent must already exist: {error}")
            }
            Self::InvalidSafetyStoreParent => {
                formatter.write_str("safety-store parent must be a directory")
            }
            Self::RelativeSignerJournalPath => {
                formatter.write_str("signer-journal path must be absolute")
            }
            Self::InvalidSignerJournalPath => {
                formatter.write_str("signer-journal path must name a database file")
            }
            Self::SignerJournalParentIo(error) => {
                write!(formatter, "signer-journal parent must already exist: {error}")
            }
            Self::InvalidSignerJournalParent => {
                formatter.write_str("signer-journal parent must be a directory")
            }
            Self::SharedStoreParentNamespace => {
                formatter.write_str(
                    "safety-store and signer-journal must use non-overlapping canonical parent directories",
                )
            }
            Self::RelativeApplicationStatusPath => {
                formatter.write_str("application status path must be absolute")
            }
            Self::InvalidApplicationStatusPath => {
                formatter.write_str("application status path must name a file")
            }
            Self::ApplicationStoreParentIo(error) => {
                write!(formatter, "application-store parent must already exist: {error}")
            }
            Self::InvalidApplicationStoreParent => {
                formatter.write_str("application-store parent must be a directory")
            }
            Self::SharedApplicationStoreParentNamespace => formatter.write_str(
                "application, safety, and signer stores must use non-overlapping canonical parent directories",
            ),
            Self::AuthenticatedGenesisCommissioningRequiresDedicatedHost => formatter.write_str(
                "authenticated genesis application commissioning requires the dedicated inert commissioning host",
            ),
            Self::ProductionActivationRequested => formatter.write_str(
                "incomplete PoCO host refuses production-activated consensus parameters",
            ),
            Self::StrictValidatorSetAdmission { reason } => write!(
                formatter,
                "strict Ed25519 validator-set admission failed: {reason}",
            ),
            Self::NonShadowRolloutRequested { rollout_phase } => write!(
                formatter,
                "incomplete PoCO host supports only shadow rollout, got {rollout_phase:?}",
            ),
            Self::UnsupportedEpoch { epoch } => {
                write!(formatter, "incomplete PoCO host supports only epoch zero, got {epoch}")
            }
            Self::AuthenticatedObligationReplayUnavailable {
                revision,
                obligation_count,
            } => write!(
                formatter,
                "safety revision {revision} retains {obligation_count} validation obligation(s); this legacy open cannot authenticate the application recovery join",
            ),
            Self::ValidationRecoveryAwareOpenRequired { revision } => write!(
                formatter,
                "safety revision {revision} requires the application-aware validation recovery host",
            ),
            Self::UnsupportedValidationObligationCount { count } => write!(
                formatter,
                "bounded validation recovery requires at most one obligation, got {count}",
            ),
            Self::UnexpectedActiveApplicationRecoveryJobs { expected, actual } => write!(
                formatter,
                "validation recovery expected {expected} active application job(s), got {actual}",
            ),
            Self::OrdinaryContextForInvalidCompletion { revision } => write!(
                formatter,
                "safety revision {revision} records a deterministic-invalid completion with an ordinary transition context",
            ),
            Self::NativeValidRecoveryUnavailable { revision } => write!(
                formatter,
                "safety revision {revision} records a native Valid completion, but this invalid-only recovery host cannot authenticate its application lifecycle or remint its callback authority",
            ),
            Self::NativeFinalizationAppliedRecoveryUnavailable { revision } => write!(
                formatter,
                "safety revision {revision} records a native finalization apply, but this invalid-only recovery host cannot authenticate its ApplicationStore receipt or remint the exact post-ack action",
            ),
            Self::StateSyncCheckpointBootstrapRequiresUnifiedHost { revision } => write!(
                formatter,
                "safety revision {revision} is an h1 state-sync checkpoint bootstrap which only the unified offline process host may reconcile",
            ),
            Self::UnexpectedObligationTransitionContext { revision } => write!(
                formatter,
                "obligation-bearing safety revision {revision} has a non-ordinary transition context",
            ),
            Self::MissingNativeInvalidTransitionContext { revision } => write!(
                formatter,
                "safety revision {revision} lacks its authenticated native-invalid transition context",
            ),
            Self::MissingReconciledApplicationOwner => formatter.write_str(
                "application recovery accepted the Core challenge without retaining its exact owner",
            ),
            Self::UnexpectedObligationApplicationState => formatter.write_str(
                "obligation recovery did not bind a CallbackPending or Delivered application row",
            ),
            Self::UnexpectedCompletionApplicationState => formatter.write_str(
                "completion recovery encountered an application state outside Delivered/Acked",
            ),
            Self::ApplicationCallbackIdentityMismatch => formatter.write_str(
                "application callback facts differ from the Core recovery challenge",
            ),
            Self::ApplicationAcknowledgementMismatch => formatter.write_str(
                "application acknowledgement differs from the authenticated SafetyStore context",
            ),
            Self::UnexpectedRecoveryEffectSet { expected, actual } => write!(
                formatter,
                "Core recovery expected {expected} effect(s), got {actual}",
            ),
            Self::UnexpectedRecoveryEffect { effect } => {
                write!(formatter, "Core recovery emitted unsupported effect {effect}")
            }
            Self::RecoveredHeadMismatch => {
                formatter.write_str("recovered Core state differs from the authenticated journal head")
            }
            Self::RecoveredTransitionHeadMismatch => formatter.write_str(
                "SafetyStore exact readback differs from the Core request or application transition context",
            ),
            Self::OrdinaryPersistenceReadbackMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "ordinary SafetyStore readback revision {actual_revision} differs from Core barrier {expected_revision}",
            ),
            Self::NonOrdinarySigningHead { revision } => write!(
                formatter,
                "signing requires an ordinary authenticated SafetyStore head, got revision {revision}",
            ),
            Self::SignerSafetyRevisionAhead {
                signer_revision,
                safety_revision,
            } => write!(
                formatter,
                "signer journal safety revision {signer_revision} is ahead of SafetyStore revision {safety_revision}",
            ),
            Self::PreparedSignerIntentWithoutCoreOutbox { safety_revision } => write!(
                formatter,
                "signer journal has one prepared unsigned tail, but SafetyStore revision {safety_revision} has no durable Core signing outbox",
            ),
            Self::UnsupportedBoundedBootstrapState { revision, state } => write!(
                formatter,
                "bounded timeout-signing host cannot open SafetyStore revision {revision} with {state}",
            ),
            Self::UnsupportedTimeoutSigningIntentKind => formatter.write_str(
                "bounded timeout-signing host refuses vote signing and non-timeout outbound messages",
            ),
            Self::MissingTimeoutIntentAfterPersistence { revision } => write!(
                formatter,
                "ordinary timeout persistence at SafetyStore revision {revision} did not retain a durable timeout sign intent",
            ),
            Self::MissingDurableTimeoutSignIntent { revision } => write!(
                formatter,
                "SafetyStore revision {revision} has no durable timeout sign intent for the Core signer request",
            ),
            Self::DurableSignIntentMismatch { revision } => write!(
                formatter,
                "Core signer request differs from the durable timeout intent at SafetyStore revision {revision}",
            ),
            Self::SigningCoreSafetyHeadMismatch {
                core_revision,
                safety_revision,
            } => write!(
                formatter,
                "Core signing state revision {core_revision} differs from authenticated SafetyStore revision {safety_revision}",
            ),
            Self::SigningHeadChangedDuringProducer {
                before_revision,
                after_revision,
            } => write!(
                formatter,
                "authenticated SafetyStore head changed from revision {before_revision} to {after_revision} while the signature producer was running",
            ),
            Self::SignIntentSafetyRevisionMismatch {
                intent_revision,
                safety_revision,
            } => write!(
                formatter,
                "sign intent authorizes SafetyState revision {intent_revision}, but authenticated head is {safety_revision}",
            ),
            Self::MultipleBoundedPersistenceEffects => formatter.write_str(
                "bounded timeout-signing call emitted more than one SafetyState persistence effect",
            ),
            Self::MultipleSignedOutboundContexts => formatter.write_str(
                "bounded timeout-signing call attempted to authorize multiple outbound messages",
            ),
            Self::MissingSignedOutboundContext => formatter.write_str(
                "Core emitted a broadcast without the exact signer context owned by this call",
            ),
            Self::SignedOutboundMismatch => formatter.write_str(
                "Core outbound message differs from the exact signature and signing root released by the signer journal",
            ),
            Self::UnconsumedSignedOutboundContext => formatter.write_str(
                "Core accepted a signature without emitting its exact outbound message",
            ),
            Self::UnsupportedBoundedHostEffect { effect } => write!(
                formatter,
                "bounded timeout-signing host cannot drive Core effect {effect}",
            ),
            Self::BoundedEffectLimitExceeded => formatter.write_str(
                "bounded timeout-signing host exceeded its per-call effect limit",
            ),
            Self::BoundedTimeoutHostFailStopped => formatter.write_str(
                "bounded timeout-signing host is terminally fail-stopped after a non-retryable error",
            ),
            Self::Core(error) => write!(formatter, "PoCO Core startup failed: {error}"),
            Self::SafetyStore(error) => write!(formatter, "PoCO safety-store startup failed: {error}"),
            Self::SignerJournal(error) => {
                write!(formatter, "PoCO signer-journal startup failed: {error}")
            }
            #[cfg(feature = "safety-rules-sidecar")]
            Self::SafetyRulesSemanticSidecar(error) => {
                write!(formatter, "PoCO SafetyRules semantic sidecar failed: {error}")
            }
            #[cfg(feature = "safety-rules-sidecar")]
            Self::SafetyRulesShadowTransitionMismatch { revision } => write!(
                formatter,
                "Core SafetyRules shadow transition does not bind timeout persistence revision {revision}",
            ),
            #[cfg(feature = "safety-rules-sidecar")]
            Self::SafetyRulesSidecarPendingRecoveryRequired { revision } => write!(
                formatter,
                "SafetyRules sidecar has an unresolved pending timeout transition at revision {revision}; ordinary reopen is fail-closed",
            ),
            #[cfg(feature = "safety-rules-sidecar")]
            Self::SafetyRulesSidecarRecoveryNotPending => formatter.write_str(
                "explicit SafetyRules sidecar recovery was requested without a durable pending marker",
            ),
            #[cfg(feature = "legacy-consensus-app")]
            Self::ApplicationRecoveryOpen(error) => {
                write!(formatter, "application recovery open failed: {error}")
            }
            #[cfg(feature = "legacy-consensus-app")]
            Self::ApplicationRecoveryReconcile(error) => {
                write!(formatter, "application recovery reconciliation failed: {error:?}")
            }
            #[cfg(feature = "legacy-consensus-app")]
            Self::ApplicationRecoveryTransition(error) => {
                write!(formatter, "application recovery transition failed: {error:?}")
            }
        }
    }
}

impl Error for PocoNodeHostErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SafetyStoreParentIo(error) => Some(error.as_ref()),
            Self::SignerJournalParentIo(error) => Some(error.as_ref()),
            Self::ApplicationStoreParentIo(error) => Some(error.as_ref()),
            Self::SafetyStore(error) => Some(error.as_ref()),
            Self::SignerJournal(error) => Some(error.as_ref()),
            #[cfg(feature = "safety-rules-sidecar")]
            Self::SafetyRulesSemanticSidecar(error) => Some(error),
            #[cfg(feature = "legacy-consensus-app")]
            Self::ApplicationRecoveryOpen(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
mod recovery_tests;

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    #[cfg(target_os = "linux")]
    use ed25519_dalek::{Signer, SigningKey};
    #[cfg(target_os = "linux")]
    use tempfile::TempDir;
    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    use trnm_consensus_core::AuthenticatedGenesisApplicationParentV0;
    use trnm_consensus_core::{OutboundMessage, SafetyStateRecordLimitsV0, SignIntent};
    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    use trnm_consensus_safety_rules::{SafetyRulesContextV1, SafetyRulesStateV1};
    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    use trnm_consensus_safety_store::SqliteSafetyStateStoreV0;
    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    use trnm_consensus_signer_journal::{
        ExternalWatermarkErrorV0, ExternalWatermarkSemanticFactsV0,
    };
    #[cfg(target_os = "linux")]
    use trnm_consensus_signer_journal::{
        SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0,
    };
    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    use trnm_consensus_types::StateRoot;
    use trnm_consensus_types::{
        BlockId, CanonicalSignIntentV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, GenesisQcV0, Height, ProtocolVersion, QcReferenceV0, SignatureBytes,
        Validator, ValidatorId, ValidatorSet, View, VotingPower,
    };

    use super::*;

    const _: () = {
        assert!(!PRODUCTION_CANDIDATE_V0);
        assert!(!HOST_IMPLEMENTATION_COMPLETE_V0);
    };

    const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
    const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
    const MAXIMUM_DATABASE_BYTES: usize = 192 * 1024 * 1024;
    const MAXIMUM_SIGNER_INTENTS: u64 = 64;
    const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
    const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

    // Public keys derived from deterministic test seeds 101..104.  The
    // generic Core fixtures may still use synthetic signatures, but startup
    // configuration now exercises the real strict Ed25519 key-shape gate.
    const TEST_VALID_CONSENSUS_PUBLIC_KEYS: [[u8; 32]; 4] = [
        [
            0xd6, 0x2f, 0x01, 0x6a, 0x1e, 0xfd, 0x1e, 0x4f, 0xdf, 0x79, 0x3e, 0xb4, 0x2c, 0xd8,
            0x44, 0x71, 0xe1, 0xba, 0x9f, 0x0c, 0xf0, 0x4d, 0x12, 0x87, 0xb5, 0xcc, 0x71, 0xf6,
            0x16, 0x28, 0x7c, 0xb8,
        ],
        [
            0x34, 0xb4, 0xd9, 0x04, 0x31, 0x56, 0xcb, 0x6d, 0xcf, 0x0b, 0xeb, 0x0a, 0x29, 0x49,
            0xb7, 0x55, 0x9c, 0x94, 0x0d, 0x2b, 0xcb, 0x6d, 0xbe, 0x8c, 0x53, 0xa9, 0xb3, 0x02,
            0x78, 0xe3, 0xa7, 0x46,
        ],
        [
            0x12, 0xa4, 0x15, 0x92, 0xc8, 0xb7, 0xc1, 0x7d, 0x40, 0x59, 0xe7, 0xb2, 0x9b, 0x61,
            0xe8, 0xff, 0x96, 0xc7, 0x41, 0x5f, 0x2f, 0x80, 0x33, 0x48, 0xf2, 0xf0, 0x17, 0xe0,
            0x5b, 0x9e, 0xa1, 0xda,
        ],
        [
            0x54, 0xb0, 0xd8, 0x1d, 0x0f, 0xa7, 0xd0, 0x0e, 0x4a, 0x7d, 0x60, 0x0d, 0xfa, 0xba,
            0x6f, 0x2b, 0x22, 0x03, 0x5b, 0x22, 0xfe, 0x33, 0x5e, 0x17, 0xed, 0xf5, 0xf9, 0xaa,
            0x5b, 0xb0, 0x50, 0x74,
        ],
    ];

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Default)]
    struct MemoryWatermark {
        value: Arc<Mutex<Option<SignerWatermarkV0>>>,
        load_calls: Arc<AtomicUsize>,
        compare_calls: Arc<AtomicUsize>,
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    impl MemoryWatermark {
        fn load_call_count(&self) -> usize {
            self.load_calls.load(Ordering::SeqCst)
        }

        fn compare_call_count(&self) -> usize {
            self.compare_calls.load(Ordering::SeqCst)
        }
    }

    #[cfg(target_os = "linux")]
    impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<
            Option<SignerWatermarkV0>,
            trnm_consensus_signer_journal::ExternalWatermarkErrorV0,
        > {
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            let value = *self.value.lock().expect("test watermark lock");
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(
                    trnm_consensus_signer_journal::ExternalWatermarkErrorV0::InvalidPersistedState,
                );
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), trnm_consensus_signer_journal::ExternalWatermarkErrorV0> {
            use trnm_consensus_signer_journal::ExternalWatermarkErrorV0;

            self.compare_calls.fetch_add(1, Ordering::SeqCst);
            let mut value = self.value.lock().expect("test watermark lock");
            if *value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(source)
                    if source.scope() == target.scope()
                        && source.journal_id() == target.journal_id()
                        && source.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            *value = Some(target);
            Ok(())
        }
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[derive(Debug, Default)]
    struct MemorySemanticWatermarkV0 {
        head: Option<SignerWatermarkV0>,
        facts: Option<ExternalWatermarkSemanticFactsV0>,
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    impl ExternalMonotonicWatermarkV0 for MemorySemanticWatermarkV0 {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn compare_and_advance(
            &mut self,
            _expected: Option<SignerWatermarkV0>,
            _target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn semantic_mode_v0(&self) -> bool {
            true
        }

        fn semantic_per_reservation_v0(&self) -> bool {
            true
        }

        fn load_semantic_v0(
            &mut self,
            _scope: [u8; 32],
            _journal_id: [u8; 32],
        ) -> Result<
            Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
            ExternalWatermarkErrorV0,
        > {
            Ok(self.head.zip(self.facts))
        }

        fn compare_and_advance_semantic_genesis_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            if self.head != expected || target.sequence() != 0 {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            let facts =
                ExternalWatermarkSemanticFactsV0::new(0, 0, 1, [1; 32], [2; 32], [3; 32], [9; 32])
                    .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
            self.head = Some(target);
            self.facts = Some(facts);
            Ok(())
        }

        fn compare_and_advance_semantic_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
            facts: ExternalWatermarkSemanticFactsV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let Some(previous) = self.head else {
                return Err(ExternalWatermarkErrorV0::Unavailable);
            };
            if self.head != expected
                || target.sequence() != previous.sequence().saturating_add(1)
                || facts.capability != [9; 32]
            {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            self.head = Some(target);
            self.facts = Some(facts);
            Ok(())
        }
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[derive(Debug, Clone, Default)]
    struct SharedMemorySemanticWatermarkV0 {
        inner: Arc<Mutex<MemorySemanticWatermarkV0>>,
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    impl ExternalMonotonicWatermarkV0 for SharedMemorySemanticWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            self.inner
                .lock()
                .expect("shared semantic watermark lock")
                .load(scope)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            self.inner
                .lock()
                .expect("shared semantic watermark lock")
                .compare_and_advance(expected, target)
        }

        fn semantic_mode_v0(&self) -> bool {
            true
        }

        fn semantic_per_reservation_v0(&self) -> bool {
            true
        }

        fn load_semantic_v0(
            &mut self,
            scope: [u8; 32],
            journal_id: [u8; 32],
        ) -> Result<
            Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
            ExternalWatermarkErrorV0,
        > {
            self.inner
                .lock()
                .expect("shared semantic watermark lock")
                .load_semantic_v0(scope, journal_id)
        }

        fn compare_and_advance_semantic_genesis_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            self.inner
                .lock()
                .expect("shared semantic watermark lock")
                .compare_and_advance_semantic_genesis_v0(expected, target)
        }

        fn compare_and_advance_semantic_v0(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
            facts: ExternalWatermarkSemanticFactsV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            self.inner
                .lock()
                .expect("shared semantic watermark lock")
                .compare_and_advance_semantic_v0(expected, target, facts)
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct UnavailableProducerV0;

    #[cfg(target_os = "linux")]
    impl SignatureProducerV0 for UnavailableProducerV0 {
        fn sign(
            &mut self,
            _request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            Err(SignatureProducerErrorV0::Unavailable)
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct RejectedProducerV0 {
        calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl SignatureProducerV0 for RejectedProducerV0 {
        fn sign(
            &mut self,
            _request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SignatureProducerErrorV0::Rejected)
        }
    }

    #[cfg(target_os = "linux")]
    struct StrictProducerV0 {
        key: SigningKey,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl SignatureProducerV0 for StrictProducerV0 {
        fn sign(
            &mut self,
            request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            assert_eq!(request.signer_profile_ref(), SIGNER_JOURNAL_PROFILE_REF_V0);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SignatureBytes::from_array(
                self.key.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    struct UnavailableOnceProducerV0 {
        key: SigningKey,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl SignatureProducerV0 for UnavailableOnceProducerV0 {
        fn sign(
            &mut self,
            request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Err(SignatureProducerErrorV0::Unavailable);
            }
            Ok(SignatureBytes::from_array(
                self.key.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::new([index; 32])
    }

    fn core_config(parameters: ConsensusParametersV0) -> CoreConfig {
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new(TEST_VALID_CONSENSUS_PUBLIC_KEYS[(index - 1) as usize]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-node-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        CoreConfig::new(validator_id(1), validator_set, parameters, 17, 64, 64)
            .expect("valid Core config")
    }

    fn core_config_with_first_consensus_key(
        parameters: ConsensusParametersV0,
        first_key: [u8; 32],
    ) -> CoreConfig {
        let validators = (1u8..=4)
            .map(|index| {
                let key = if index == 1 {
                    first_key
                } else {
                    TEST_VALID_CONSENSUS_PUBLIC_KEYS[(index - 1) as usize]
                };
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new(key),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("shape-valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-node-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("shape-valid validator set");
        CoreConfig::new(validator_id(1), validator_set, parameters, 17, 64, 64)
            .expect("valid Core config")
    }

    #[cfg(target_os = "linux")]
    fn strict_core_config_and_local_key() -> (CoreConfig, SigningKey) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1_u8..=4)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive strict voting power"),
                )
                .expect("valid strict validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-node-timeout-signing-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid strict validator set");
        let config = CoreConfig::new(validator_id(1), validator_set, parameters, 17, 64, 64)
            .expect("valid strict Core config");
        (config, SigningKey::from_bytes(&[41; 32]))
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    fn authenticated_genesis_core_config_v0() -> CoreConfig {
        let base = core_config(ConsensusParametersV0::reference_shadow_v0());
        let parent = AuthenticatedGenesisApplicationParentV0::new(
            base.genesis_block_id(),
            base.trusted_genesis_timestamp_ms(),
            0,
            StateRoot::new([0x31; 32]),
            [0x41; 32],
            [0x51; 32],
        )
        .expect("shape-valid authenticated genesis application parent");
        CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            base.local_validator(),
            base.validator_set().clone(),
            *base.consensus_parameters(),
            base.trusted_genesis_timestamp_ms(),
            parent,
            base.max_blocks(),
            base.max_observed_messages(),
        )
        .expect("shadow authenticated-genesis Core config")
    }

    fn record_limits() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid local record limits")
    }

    fn start_config(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
    ) -> Result<PocoNodeStartConfigV0, PocoNodeHostErrorV0> {
        PocoNodeStartConfigV0::new(
            safety_store_path,
            signer_journal_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    fn unchecked_start_config_v0(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
    ) -> PocoNodeStartConfigV0 {
        let signer_journal_profile = SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("construct test-only signer profile before the node fence");
        let safety_store_profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
        )
        .expect("construct test-only Safety profile before the node fence");
        PocoNodeStartConfigV0 {
            safety_store_path: safety_store_path.as_ref().to_path_buf(),
            safety_store_profile,
            signer_journal_path: signer_journal_path.as_ref().to_path_buf(),
            signer_journal_profile,
        }
    }

    fn genesis_qc(core_config: &CoreConfig) -> GenesisQcV0 {
        GenesisQcV0::new(
            core_config.validator_set().genesis_hash(),
            core_config.validator_set().chain_id(),
            core_config.validator_set(),
        )
        .expect("valid genesis anchor")
    }

    #[cfg(target_os = "linux")]
    fn protected_temp_dir() -> TempDir {
        let directory = TempDir::new().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("protect temporary safety-store directory");
        }
        directory
    }

    #[cfg(target_os = "linux")]
    fn protected_store_namespace(root: &TempDir, name: &str) -> PathBuf {
        let namespace = root.path().join(name);
        create_protected_directory(&namespace);
        namespace
    }

    #[cfg(target_os = "linux")]
    fn create_protected_directory(path: &Path) {
        fs::create_dir_all(path).expect("create isolated store namespace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("protect isolated store namespace");
        }
    }

    #[cfg(target_os = "linux")]
    fn dual_store_paths(root: &TempDir) -> (PathBuf, PathBuf) {
        (
            protected_store_namespace(root, "safety").join("safety.sqlite3"),
            protected_store_namespace(root, "signer").join("signer.sqlite3"),
        )
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    fn timeout_sidecar_fixture_v1(
        core_config: &CoreConfig,
        genesis_qc: &GenesisQcV0,
        semantic_watermark: SharedMemorySemanticWatermarkV0,
    ) -> (
        SafetyRulesSemanticSidecarV1<SharedMemorySemanticWatermarkV0>,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        let context = SafetyRulesContextV1::new(
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.local_validator(),
            core_config.trusted_genesis_timestamp_ms(),
            64,
        )
        .expect("construct exact shadow context");
        let shadow_state =
            SafetyRulesStateV1::from_genesis(&context, genesis_qc.clone(), &StrictEd25519Verifier)
                .expect("construct exact genesis shadow state");
        let scope = [0x11; 32];
        let journal_id = [0x22; 32];
        let capability = [0x09; 32];
        let sidecar = SafetyRulesSemanticSidecarV1::open(
            semantic_watermark,
            scope,
            journal_id,
            capability,
            shadow_state.digest(),
        )
        .expect("open semantic sidecar against genesis");
        (sidecar, scope, journal_id, capability)
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    fn read_safety_head_for_test_v1(
        safety_path: &Path,
        core_config: CoreConfig,
    ) -> RecoveredSafetyStateV0 {
        let profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
        )
        .expect("construct SafetyStore profile for inspection");
        let store =
            SqliteSafetyStateStoreV0::open_existing(safety_path, profile, StrictEd25519Verifier)
                .expect("open SafetyStore for inspection");
        store.head().expect("read SafetyStore head")
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    fn triple_store_paths(root: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let (safety, signer) = dual_store_paths(root);
        let application = protected_store_namespace(root, "application").join("state.json");
        (safety, signer, application)
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    fn assert_store_parent_empty_v0(path: &Path, context: &str) {
        let parent = path.parent().expect("store path retains its parent");
        let entries = fs::read_dir(parent)
            .expect("read protected store parent")
            .map(|entry| {
                entry
                    .expect("read protected store-parent entry")
                    .file_name()
            })
            .collect::<Vec<_>>();
        assert!(
            entries.is_empty(),
            "{context} must leave the complete store parent empty: {entries:?}"
        );
    }

    #[test]
    fn static_activation_gate_names_real_unwired_contracts() {
        let error = production_activation_gate_v0().expect_err("activation must remain blocked");
        assert_eq!(error.blockers(), UNWIRED_PRODUCTION_CONTRACTS_V0);
        assert!(error.to_string().contains("independent_signer_watermark"));
        assert!(error.to_string().contains("complete_hotstuff_safety_rules"));
        assert!(!error.to_string().contains("append_only_sign_journal"));
        assert!(error.to_string().contains("block_id_speculative_overlay"));
        assert!(error
            .to_string()
            .contains("application_validation_recovery_beyond_deterministic_invalid_v0"));
        assert!(!error
            .to_string()
            .contains(",application_validation_recovery,"));
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn ordinary_config_surfaces_fence_authenticated_genesis_before_path_validation_v0() {
        enum Surface {
            Start,
            ValidationRecovery,
        }

        let directory = protected_temp_dir();
        let (safety_path, signer_path, _) = triple_store_paths(&directory);
        for surface in [Surface::Start, Surface::ValidationRecovery] {
            let error = match surface {
                Surface::Start => start_config(
                    "relative-safety.sqlite3",
                    "relative-signer.sqlite3",
                    authenticated_genesis_core_config_v0(),
                )
                .expect_err("authenticated-genesis start config must be fenced before relative paths"),
                Surface::ValidationRecovery => PocoNodeValidationRecoveryConfigV0::new(
                    unchecked_start_config_v0(
                        &safety_path,
                        &signer_path,
                        authenticated_genesis_core_config_v0(),
                    ),
                    "relative-application.json",
                    [0x5a; 32],
                )
                .expect_err(
                    "authenticated-genesis recovery config must be fenced before its application path",
                ),
            };
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
            ));
        }
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn ordinary_host_entries_fence_authenticated_genesis_before_every_owner_v0() {
        #[derive(Clone, Copy, Debug)]
        enum Surface {
            Initialize,
            Open,
            ValidationRecoveryOpen,
        }

        let directory = protected_temp_dir();
        let (safety_path, signer_path, application_path) = triple_store_paths(&directory);
        let core_config = authenticated_genesis_core_config_v0();
        let genesis_qc = genesis_qc(&core_config);
        for surface in [
            Surface::Initialize,
            Surface::Open,
            Surface::ValidationRecoveryOpen,
        ] {
            let watermark = MemoryWatermark::default();
            let node = unchecked_start_config_v0(&safety_path, &signer_path, core_config.clone());
            let error = match surface {
                Surface::Initialize => PocoNodeHostV0::initialize_new(
                    node,
                    genesis_qc.clone(),
                    watermark.clone(),
                    UnavailableProducerV0,
                )
                .err()
                .expect("generic initialization must reject authenticated genesis"),
                Surface::Open => {
                    PocoNodeHostV0::open_existing(node, watermark.clone(), UnavailableProducerV0)
                        .err()
                        .expect("generic open must reject authenticated genesis")
                }
                Surface::ValidationRecoveryOpen => PocoNodeValidationRecoveryHostV0::open_existing(
                    PocoNodeValidationRecoveryConfigV0 {
                        node,
                        application_status_path: application_path.clone(),
                        signer_policy_hash: [0x5a; 32],
                    },
                    watermark.clone(),
                )
                .err()
                .expect("generic recovery open must reject authenticated genesis"),
            };
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::AuthenticatedGenesisCommissioningRequiresDedicatedHost
            ));
            assert_eq!(
                watermark.load_call_count(),
                0,
                "{surface:?} must reject before loading the external watermark",
            );
            assert_eq!(
                watermark.compare_call_count(),
                0,
                "{surface:?} must reject before external watermark CAS",
            );
            assert!(
                !safety_path.exists(),
                "{surface:?} must reject before SafetyStore creation/open",
            );
            assert!(
                !signer_path.exists(),
                "{surface:?} must reject before signer creation/open",
            );
            assert!(
                !application_path.exists(),
                "{surface:?} must reject before application recovery open",
            );
            assert_store_parent_empty_v0(&safety_path, "Safety fence");
            assert_store_parent_empty_v0(&signer_path, "signer fence");
            assert_store_parent_empty_v0(&application_path, "application fence");
        }
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn validation_recovery_config_requires_a_third_canonical_namespace() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let application_path = safety_path
            .parent()
            .expect("safety namespace")
            .join("state.json");
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let error = PocoNodeValidationRecoveryConfigV0::new(node, application_path, [0x5a; 32])
            .expect_err("application WAL must not share the safety namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
        ));
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn validation_recovery_config_rejects_application_ancestor_and_descendant_namespaces() {
        let directory = protected_temp_dir();
        let cases = [
            (
                "application-under-safety",
                "safety",
                "signer",
                "safety/application",
            ),
            (
                "application-over-safety",
                "application/safety",
                "signer",
                "application",
            ),
            (
                "application-under-signer",
                "safety",
                "signer",
                "signer/application",
            ),
            (
                "application-over-signer",
                "safety",
                "application/signer",
                "application",
            ),
        ];

        for (case, safety_parent, signer_parent, application_parent) in cases {
            let case_root = directory.path().join(case);
            let safety_parent = case_root.join(safety_parent);
            let signer_parent = case_root.join(signer_parent);
            let application_parent = case_root.join(application_parent);
            create_protected_directory(&safety_parent);
            create_protected_directory(&signer_parent);
            create_protected_directory(&application_parent);

            let node = start_config(
                safety_parent.join("safety.sqlite3"),
                signer_parent.join("signer.sqlite3"),
                core_config(ConsensusParametersV0::reference_shadow_v0()),
            )
            .expect("safety and signer parents remain non-overlapping");
            let error = PocoNodeValidationRecoveryConfigV0::new(
                node,
                application_parent.join("state.json"),
                [0x5a; 32],
            )
            .expect_err("application parent must not contain or be contained by another store");
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
            ));
        }
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn validation_recovery_config_rejects_nested_application_after_symlink_canonicalization() {
        use std::os::unix::fs::symlink;

        let directory = protected_temp_dir();
        let safety_parent = protected_store_namespace(&directory, "safety");
        let signer_parent = protected_store_namespace(&directory, "signer");
        let nested_application_parent = safety_parent.join("nested-application");
        create_protected_directory(&nested_application_parent);
        let application_alias = directory.path().join("application-alias");
        symlink(&nested_application_parent, &application_alias)
            .expect("create application namespace symlink");

        let node = start_config(
            safety_parent.join("safety.sqlite3"),
            signer_parent.join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("raw safety and signer paths are valid siblings");
        let error = PocoNodeValidationRecoveryConfigV0::new(
            node,
            application_alias.join("state.json"),
            [0x5a; 32],
        )
        .expect_err("canonicalized application alias must reveal the nested namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
        ));
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn validation_recovery_config_freezes_three_distinct_paths() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path, application_path) = triple_store_paths(&directory);
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let recovery = PocoNodeValidationRecoveryConfigV0::new(node, &application_path, [0x5a; 32])
            .expect("valid triple-store recovery config");
        assert_eq!(recovery.application_status_path(), application_path);
        assert_eq!(recovery.signer_policy_hash(), [0x5a; 32]);
        assert_eq!(recovery.node_config().safety_store_path(), safety_path);
        assert_eq!(recovery.node_config().signer_journal_path(), signer_path);
    }

    #[cfg(all(target_os = "linux", feature = "legacy-consensus-app"))]
    #[test]
    fn validation_recovery_config_rejects_relative_application_path() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let error =
            PocoNodeValidationRecoveryConfigV0::new(node, "relative/state.json", [0x5a; 32])
                .expect_err("relative application recovery state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeApplicationStatusPath
        ));
    }

    #[test]
    fn startup_config_rejects_relative_store_path() {
        let error = PocoNodeStartConfigV0::new(
            "relative/safety.sqlite3",
            "/tmp/trnm-poco-node-relative-safety-signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("relative startup state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSafetyStorePath
        ));
    }

    #[test]
    fn startup_config_rejects_undecodable_consensus_key_before_filesystem_work() {
        let error = PocoNodeStartConfigV0::new(
            "relative-safety.sqlite3",
            "relative-signer.sqlite3",
            core_config_with_first_consensus_key(
                ConsensusParametersV0::reference_shadow_v0(),
                [0x02; 32],
            ),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("startup must reject an undecodable consensus key");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::StrictValidatorSetAdmission { reason }
                if reason.contains("decodable Ed25519")
        ));
    }

    #[test]
    fn startup_config_rejects_small_order_consensus_key_before_filesystem_work() {
        let error = PocoNodeStartConfigV0::new(
            "relative-safety.sqlite3",
            "relative-signer.sqlite3",
            core_config_with_first_consensus_key(
                ConsensusParametersV0::reference_shadow_v0(),
                [
                    0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("startup must reject a weak consensus key");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::StrictValidatorSetAdmission { reason }
                if reason.contains("weak/small-order")
        ));
    }

    #[test]
    fn startup_source_contract_keeps_strict_validator_admission_before_store_setup() {
        let source = include_str!("lib.rs");
        let admission = source
            .find("validate_validator_set_strict_ed25519_v0(core_config.validator_set())")
            .expect("startup must retain strict validator-set admission");
        let path_validation = source
            .find("let safety_store_path = safety_store_path.as_ref();")
            .expect("startup path validation marker");
        assert!(
            admission < path_validation,
            "strict key admission must run before path/store setup"
        );
        assert!(
            source.contains("StrictValidatorSetAdmission { reason }")
                || source.contains("StrictValidatorSetAdmission {")
        );
    }

    #[test]
    fn startup_config_rejects_relative_signer_journal_path() {
        let error = start_config(
            "/tmp/trnm-poco-node-relative-signer-safety.sqlite3",
            "relative/signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("relative signer state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSignerJournalPath
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_shared_canonical_parent_namespace() {
        let directory = protected_temp_dir();
        let error = start_config(
            directory.path().join("safety.sqlite3"),
            directory.path().join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("two histories in one canonical parent must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedStoreParentNamespace
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_safety_signer_ancestor_and_descendant_namespaces() {
        let directory = protected_temp_dir();
        let outer = protected_store_namespace(&directory, "outer");
        let nested = outer.join("nested");
        create_protected_directory(&nested);

        for (safety_parent, signer_parent) in [(&outer, &nested), (&nested, &outer)] {
            let error = start_config(
                safety_parent.join("safety.sqlite3"),
                signer_parent.join("signer.sqlite3"),
                core_config(ConsensusParametersV0::reference_shadow_v0()),
            )
            .expect_err("safety and signer parents must not contain one another");
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::SharedStoreParentNamespace
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_nested_store_after_symlink_canonicalization() {
        use std::os::unix::fs::symlink;

        let directory = protected_temp_dir();
        let safety_parent = protected_store_namespace(&directory, "safety");
        let nested_signer_parent = safety_parent.join("nested-signer");
        create_protected_directory(&nested_signer_parent);
        let signer_alias = directory.path().join("signer-alias");
        symlink(&nested_signer_parent, &signer_alias).expect("create signer namespace symlink");

        let error = start_config(
            safety_parent.join("safety.sqlite3"),
            signer_alias.join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("canonicalized signer alias must reveal the nested namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedStoreParentNamespace
        ));
    }

    #[test]
    fn startup_config_rejects_production_activation() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.production_activation = true;
        let activated = ConsensusParametersV0::new(fields)
            .expect("production flag is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-production-refusal.sqlite3",
            "/tmp/trnm-poco-node-production-refusal-signer.sqlite3",
            core_config(activated),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse production activation");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::ProductionActivationRequested
        ));
    }

    #[test]
    fn startup_config_rejects_non_shadow_rollout() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.rollout_phase = RolloutPhase::EligibilityOnly;
        let non_shadow = ConsensusParametersV0::new(fields)
            .expect("eligibility-only is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-rollout-refusal.sqlite3",
            "/tmp/trnm-poco-node-rollout-refusal-signer.sqlite3",
            core_config(non_shadow),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse non-shadow rollout");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::NonShadowRolloutRequested {
                rollout_phase: RolloutPhase::EligibilityOnly
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_host_initializes_and_recovers_exact_dual_store_ownership() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config =
            start_config(&safety_path, &signer_path, core_config).expect("valid inert host config");
        let watermark = MemoryWatermark::default();

        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc,
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize exact dual-store owner");
        assert_eq!(
            host.bootstrap_mode(),
            HostBootstrapModeV0::InitializedGenesis
        );
        assert_eq!(
            host.lifecycle_phase(),
            HostLifecyclePhaseV0::BoundedTimeoutSigning
        );
        assert_eq!(host.safety_state().revision(), 0);
        assert_eq!(host.safety_head().expect("journal head").revision(), 0);
        assert_eq!(host.safety_store_path(), safety_path.as_path());
        assert_eq!(host.signer_journal_path(), signer_path.as_path());
        assert_eq!(
            host.signer_journal_head()
                .expect("authenticated signer head")
                .sequence(),
            0
        );
        assert_eq!(
            host.signer_journal_capacity()
                .expect("signer capacity")
                .intent_count(),
            0
        );
        assert!(host.production_activation_check().is_err());

        let duplicate_open = match PocoNodeHostV0::open_existing(
            config.clone(),
            watermark.clone(),
            UnavailableProducerV0,
        ) {
            Ok(_) => panic!("a second live owner must not open the same journal"),
            Err(error) => error,
        };
        assert!(matches!(
            duplicate_open,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Locked)
        ));
        drop(host);

        let mut recovered = PocoNodeHostV0::open_existing(config, watermark, UnavailableProducerV0)
            .expect("recover exact dual-store owner");
        assert_eq!(
            recovered.bootstrap_mode(),
            HostBootstrapModeV0::RecoveredExisting
        );
        assert_eq!(recovered.safety_state().revision(), 0);
        assert_eq!(recovered.safety_store_path(), safety_path.as_path());
        assert_eq!(recovered.signer_journal_path(), signer_path.as_path());
        assert_eq!(
            recovered
                .signer_journal_head()
                .expect("authenticated signer head")
                .sequence(),
            0
        );
        assert!(recovered.production_activation_check().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_timeout_signing_persists_before_broadcast_and_replays_exactly() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout host config");
        let watermark = MemoryWatermark::default();
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc,
            watermark.clone(),
            StrictProducerV0 {
                key: local_key.clone(),
                calls: Arc::clone(&producer_calls),
            },
        )
        .expect("initialize bounded timeout-signing host");

        assert_eq!(
            host.resume_v0().expect("resume genesis host"),
            vec![PocoNodeHostActionV0::ArmViewTimer {
                epoch: Epoch::new(0),
                view: View::new(1),
            }]
        );

        let actions = host
            .on_local_timeout_v0()
            .expect("persist, sign, and release one local timeout");
        let [PocoNodeHostActionV0::Broadcast(first_outbound)] = actions.as_slice() else {
            panic!("timeout path must release exactly one signed outbound");
        };
        assert_eq!(first_outbound.authorizing_safety_revision(), 1);
        assert_ne!(first_outbound.intent_fingerprint().into_bytes(), [0; 32]);
        let OutboundMessage::TimeoutVote(first_timeout) = first_outbound.message() else {
            panic!("bounded host must release only timeout votes");
        };
        assert_eq!(first_timeout.epoch(), Epoch::new(0));
        assert_eq!(first_timeout.view(), View::new(1));
        first_timeout
            .verify(core_config.validator_set(), &StrictEd25519Verifier)
            .expect("released timeout vote verifies under the frozen validator set");
        assert_eq!(producer_calls.load(Ordering::SeqCst), 1);

        let durable_head = host.safety_head().expect("authenticated safety head");
        assert_eq!(durable_head.revision(), 1);
        assert!(matches!(
            durable_head.state().pending_sign(),
            Some(SignIntent::TimeoutVote {
                authorizing_safety_revision: 1,
                view,
                ..
            }) if *view == View::new(1)
        ));
        assert!(host.safety_state().pending_sign().is_none());
        let capacity = host
            .signer_journal_capacity()
            .expect("authenticated signer capacity");
        assert_eq!(capacity.intent_count(), 1);
        assert_eq!(capacity.event_count(), 2);
        assert_eq!(capacity.maximum_safety_revision(), Some(1));
        assert_eq!(capacity.maximum_timeout_view(), Some(1));
        assert_eq!(
            host.signer_journal_head()
                .expect("synchronized signer head")
                .sequence(),
            2
        );
        let first_outbound = first_outbound.clone();
        drop(host);

        let mut recovered = PocoNodeHostV0::open_existing(
            config,
            watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&producer_calls),
            },
        )
        .expect("recover exact pending timeout outbox");
        let replay = recovered
            .resume_v0()
            .expect("replay persisted signature and timeout vote");
        assert_eq!(
            replay,
            vec![PocoNodeHostActionV0::Broadcast(first_outbound)]
        );
        assert_eq!(
            producer_calls.load(Ordering::SeqCst),
            1,
            "persisted exact replay must skip the producer"
        );
        assert_eq!(
            recovered
                .signer_journal_head()
                .expect("replayed signer head")
                .sequence(),
            2
        );
        let replay_capacity = recovered
            .signer_journal_capacity()
            .expect("replayed signer capacity");
        assert_eq!(replay_capacity.intent_count(), 1);
        assert_eq!(replay_capacity.event_count(), 2);
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn bounded_host_timeout_event_wal_commits_exact_safety_readback() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path = protected_store_namespace(&directory, "events").join("node-events.wal");
        let (core_config, local_key) = strict_core_config_and_local_key();
        let config =
            start_config(&safety_path, &signer_path, core_config.clone()).expect("host config");
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc(&core_config),
            MemoryWatermark::default(),
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("initialize bounded host");
        host.resume_v0().expect("arm the first timeout view");

        let foreign_event_path =
            protected_store_namespace(&directory, "foreign-events").join("node-events.wal");
        let mut foreign_wal =
            NodeEventWalV1::open(&foreign_event_path, [0x73; 32]).expect("open foreign WAL");
        assert!(matches!(
            host.prepare_timeout_event_v1(&mut foreign_wal),
            Err(PocoNodeHostEventWalErrorV1::BindingMismatch)
        ));
        assert!(foreign_wal.pending().is_none());

        let mut wal = NodeEventWalV1::open(&event_path, host.timeout_event_wal_namespace_v1())
            .expect("open host-bound event WAL");
        let receipt = host
            .on_local_timeout_with_event_wal_v1(&mut wal)
            .expect("timeout and exact event commit");
        let head = host.safety_head().expect("read authenticated safety head");
        assert_eq!(receipt.commit_digest(), head.state_record_checksum());
        assert_ne!(receipt.event_id(), [0; 32]);
        assert!(wal.pending().is_none());
        assert_eq!(wal.last_commit(), Some(receipt));
        assert!(host.production_activation_check().is_err());
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn timeout_event_recovery_rejects_live_core_successor_mismatch() {
        let (core_config, _) = strict_core_config_and_local_key();
        let mut evaluator = trnm_consensus_core::Core::new(
            core_config.clone(),
            genesis_qc(&core_config),
            &StrictEd25519Verifier,
        )
        .expect("construct exact timeout evaluator");
        let predecessor = evaluator.safety_state().clone();
        let epoch = predecessor.epoch();
        let view = predecessor.current_view();
        evaluator
            .step(
                trnm_consensus_core::Input::LocalTimeout { epoch, view },
                &StrictEd25519Verifier,
            )
            .expect("derive exact timeout successor");
        let successor = evaluator.safety_state().clone();

        assert!(
            ordinary_timeout::validate_timeout_event_core_successor_binding_v1(
                &successor, &successor,
            )
            .is_ok(),
            "an exact live Core successor must be accepted"
        );
        assert!(matches!(
            ordinary_timeout::validate_timeout_event_core_successor_binding_v1(
                &predecessor,
                &successor,
            ),
            Err(PocoNodeHostEventWalErrorV1::BindingMismatch)
        ));
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn timeout_event_recovery_rejects_stale_live_core_and_keeps_wal_pending() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path =
            protected_store_namespace(&directory, "stale-core-events").join("node-events.wal");
        let (core_config, _) = strict_core_config_and_local_key();
        let config =
            start_config(&safety_path, &signer_path, core_config.clone()).expect("host config");
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc(&core_config),
            MemoryWatermark::default(),
            UnavailableProducerV0,
        )
        .expect("initialize bounded host");
        host.resume_v0().expect("arm the first timeout view");
        let mut wal = NodeEventWalV1::open(&event_path, host.timeout_event_wal_namespace_v1())
            .expect("open host-bound event WAL");
        let intent = host
            .prepare_timeout_event_v1(&mut wal)
            .expect("prepare authenticated timeout intent");

        assert!(matches!(
            host.on_local_timeout_v0(),
            Err(PocoNodeHostErrorV0::SignerJournal(_))
        ));
        assert_eq!(
            host.safety_head().expect("read successor head").revision(),
            1
        );

        // Leave the durable SafetyStore at the exact successor while
        // deliberately restoring a stale live Core.  Recovery must reject
        // this mixed authority and must not commit the pending event.
        let stale_core = trnm_consensus_core::Core::new(
            core_config.clone(),
            genesis_qc(&core_config),
            &StrictEd25519Verifier,
        )
        .expect("construct stale predecessor Core");
        host.replace_core_for_event_recovery_test_v1(stale_core);
        let error = host
            .recover_pending_timeout_event_with_wal_v1(&mut wal)
            .expect_err("stale Core must block event recovery");
        assert!(matches!(
            error,
            PocoNodeHostEventWalErrorV1::BindingMismatch
        ));
        assert_eq!(wal.pending(), Some(intent));
        assert_eq!(
            host.safety_head()
                .expect("read unchanged successor")
                .revision(),
            1
        );
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn single_owner_timeout_host_retains_the_authenticated_event_wal() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path =
            protected_store_namespace(&directory, "owned-events").join("node-events.wal");
        let (core_config, local_key) = strict_core_config_and_local_key();
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded host config");
        let watermark = MemoryWatermark::default();
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let mut owner = PocoNodeHostEventWalOwnerV1::initialize_new(
            config.clone(),
            genesis_qc(&core_config),
            watermark.clone(),
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&producer_calls),
            },
            &event_path,
        )
        .expect("single owner opens authenticated event WAL");
        assert_ne!(owner.wal().namespace(), [0; 32]);
        owner.resume_v0().expect("arm first timeout view");
        let receipt = owner
            .on_local_timeout_v1()
            .expect("timeout commits through owned WAL");
        assert_eq!(
            receipt.commit_digest(),
            owner.safety_head().unwrap().state_record_checksum()
        );
        assert!(owner.wal().pending().is_none());
        assert!(owner.production_activation_check().is_err());
        drop(owner);

        let mut reopened = PocoNodeHostEventWalOwnerV1::open_existing(
            config,
            watermark,
            StrictProducerV0 {
                key: SigningKey::from_bytes(&[41; 32]),
                calls: Arc::clone(&producer_calls),
            },
            &event_path,
        )
        .expect("reopen single owner and exact WAL namespace");
        assert!(matches!(
            reopened
                .restart_recovery_v1()
                .expect("revalidate owned WAL"),
            NodeEventRecoveryV1::Clean {
                last_commit: Some(_)
            }
        ));
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn single_owner_resume_requires_pending_event_recovery_before_host_actions() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path =
            protected_store_namespace(&directory, "pending-owned-events").join("node-events.wal");
        let (core_config, local_key) = strict_core_config_and_local_key();
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded host config");
        let watermark = MemoryWatermark::default();
        let producer_calls = Arc::new(AtomicUsize::new(0));

        // Leave the exact event intent durable while the host effect has
        // already advanced SafetyStore.  This is the crash window in which
        // Core's outbox is otherwise replayable but the event WAL has not
        // established the matching commit readback.
        let mut owner = PocoNodeHostEventWalOwnerV1::initialize_new(
            config.clone(),
            genesis_qc(&core_config),
            watermark.clone(),
            UnavailableProducerV0,
            &event_path,
        )
        .expect("initialize single owner");
        owner.resume_v0().expect("arm first timeout view");
        assert!(matches!(
            owner.on_local_timeout_v1(),
            Err(PocoNodeHostEventWalErrorV1::Host(_))
        ));
        let pending = owner.wal().pending().expect("timeout intent is pending");
        let advanced_head = owner
            .safety_head()
            .expect("read effect-side SafetyStore head");
        assert_eq!(advanced_head.revision(), 1);
        drop(owner);

        let mut reopened = PocoNodeHostEventWalOwnerV1::open_existing(
            config,
            watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&producer_calls),
            },
            &event_path,
        )
        .expect("reopen owner with the pending WAL");
        let before_resume = reopened
            .safety_head()
            .expect("read authenticated head before gated resume");
        let error = reopened
            .resume_v0()
            .expect_err("pending event must gate all host actions");
        assert!(matches!(
            error,
            PocoNodeHostEventWalErrorV1::RecoveryReadbackRequired
        ));
        assert_eq!(reopened.wal().pending(), Some(pending));
        assert_eq!(
            reopened
                .safety_head()
                .expect("read head after gated resume"),
            before_resume,
            "resume must not advance the host while event recovery is pending"
        );
        assert_eq!(
            producer_calls.load(Ordering::SeqCst),
            0,
            "gated resume must not invoke the signer or emit a broadcast"
        );

        let receipt = reopened
            .recover_pending_v1()
            .expect("fresh durable readback resolves the pending event")
            .expect("the WAL was pending");
        assert_eq!(receipt.event_id(), pending.event_id());
        assert!(reopened.wal().pending().is_none());
        let actions = reopened
            .resume_v0()
            .expect("resume after exact event recovery");
        assert!(matches!(
            actions.as_slice(),
            [PocoNodeHostActionV0::Broadcast(outbound)]
                if matches!(outbound.message(), OutboundMessage::TimeoutVote(_))
        ));
        assert_eq!(producer_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn startup_and_single_owner_paths_reject_non_ed25519_validator_keys_before_store_creation() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path =
            protected_store_namespace(&directory, "rejected-events").join("node-events.wal");
        let core_config = core_config_with_first_consensus_key(
            ConsensusParametersV0::reference_shadow_v0(),
            [0x02; 32],
        );
        let error = PocoNodeStartConfigV0::new(
            &safety_path,
            &signer_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("startup must require strict Ed25519 admission");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::StrictValidatorSetAdmission { .. }
        ));
        assert!(!safety_path.exists());
        assert!(!signer_path.exists());
        assert!(!event_path.exists());
    }

    #[cfg(all(target_os = "linux", feature = "node-event-wal"))]
    #[test]
    fn bounded_host_timeout_event_wal_preserves_uncertain_effect_until_reopen_readback() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let event_path = protected_store_namespace(&directory, "events").join("node-events.wal");
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config =
            start_config(&safety_path, &signer_path, core_config.clone()).expect("host config");
        let watermark = MemoryWatermark::default();
        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc,
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize bounded host");
        host.resume_v0().expect("arm the first timeout view");
        let mut wal = NodeEventWalV1::open(&event_path, host.timeout_event_wal_namespace_v1())
            .expect("open host-bound event WAL");
        let intent = host
            .prepare_timeout_event_v1(&mut wal)
            .expect("prepare authenticated timeout intent");

        assert!(matches!(
            host.recover_pending_timeout_event_with_wal_v1(&mut wal),
            Err(PocoNodeHostEventWalErrorV1::RecoveryReadbackRequired)
        ));
        assert_eq!(wal.pending(), Some(intent));

        let error = host
            .on_local_timeout_v0()
            .expect_err("unavailable signer leaves an uncertain durable effect");
        assert!(matches!(error, PocoNodeHostErrorV0::SignerJournal(_)));
        assert_eq!(
            host.safety_head().expect("read successor head").revision(),
            1
        );
        drop(host);

        let mut recovered = PocoNodeHostV0::open_existing(
            config,
            watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("reopen exact host after uncertain signer result");
        let receipt = recovered
            .recover_pending_timeout_event_with_wal_v1(&mut wal)
            .expect("fresh SafetyStore readback closes the pending event")
            .expect("WAL was pending");
        assert_eq!(receipt.event_id(), intent.event_id());
        assert_eq!(
            receipt.commit_digest(),
            recovered.safety_head().unwrap().state_record_checksum()
        );
        assert!(wal.pending().is_none());
        let actions = recovered.resume_v0().expect("replay the persisted timeout");
        assert!(matches!(
            actions.as_slice(),
            [PocoNodeHostActionV0::Broadcast(outbound)]
                if matches!(outbound.message(), OutboundMessage::TimeoutVote(_))
        ));
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn bounded_timeout_sidecar_cas_precedes_sqlite_and_releases_exact_vote() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout host config");

        let context = SafetyRulesContextV1::new(
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.local_validator(),
            core_config.trusted_genesis_timestamp_ms(),
            64,
        )
        .expect("construct exact shadow context");
        let state =
            SafetyRulesStateV1::from_genesis(&context, genesis_qc.clone(), &StrictEd25519Verifier)
                .expect("construct exact genesis shadow state");
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            MemorySemanticWatermarkV0::default(),
            [0x11; 32],
            [0x22; 32],
            [0x09; 32],
            state.digest(),
        )
        .expect("open semantic sidecar against the authenticated genesis state");
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc,
            MemoryWatermark::default(),
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("initialize bounded timeout host");

        let actions = host
            .on_local_timeout_with_safety_rules_sidecar_v1(&mut sidecar)
            .expect("sidecar CAS, SQLite persistence, and exact timeout signing succeed");
        assert!(matches!(
            actions.as_slice(),
            [PocoNodeHostActionV0::Broadcast(outbound)]
                if matches!(outbound.message(), OutboundMessage::TimeoutVote(_))
        ));
        assert_eq!(
            sidecar
                .expected_watermark()
                .map(|watermark| watermark.sequence()),
            Some(1),
            "the semantic CAS must complete before the host releases the timeout"
        );
        assert_eq!(
            host.safety_head()
                .expect("authenticated SQLite head")
                .revision(),
            1,
            "the local SafetyStore reaches the same transition after the sidecar"
        );
        assert_eq!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect completed sidecar marker"),
            None,
            "the pending marker is removed only after the local SQLite barrier succeeds"
        );
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn bounded_timeout_sidecar_failure_does_not_mutate_live_core_before_cas_v1() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout host config");

        let context = SafetyRulesContextV1::new(
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.local_validator(),
            core_config.trusted_genesis_timestamp_ms(),
            64,
        )
        .expect("construct exact shadow context");
        let state =
            SafetyRulesStateV1::from_genesis(&context, genesis_qc.clone(), &StrictEd25519Verifier)
                .expect("construct exact genesis shadow state");
        // The fixture watermark's genesis anchor is valid, but it rejects a
        // transition whose semantic capability differs from that anchor.
        // This gives us a deterministic CAS failure after the marker write.
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            MemorySemanticWatermarkV0::default(),
            [0x11; 32],
            [0x22; 32],
            [0x08; 32],
            state.digest(),
        )
        .expect("open semantic sidecar against the authenticated genesis state");
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc,
            MemoryWatermark::default(),
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("initialize bounded timeout host");
        let predecessor = host.safety_state().clone();

        let error = host
            .on_local_timeout_with_safety_rules_sidecar_v1(&mut sidecar)
            .expect_err("semantic CAS failure must stop before live Core installation");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SafetyRulesSemanticSidecar(_)
        ));
        assert!(sidecar.is_poisoned());
        assert_eq!(
            host.safety_state(),
            &predecessor,
            "the live Core must remain at its predecessor when external CAS fails"
        );
        assert_eq!(
            host.safety_head()
                .expect("read unchanged SafetyStore head")
                .revision(),
            0,
            "the local SQLite state must not install a successor before CAS"
        );
        assert!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect pending marker after CAS failure")
                .is_some(),
            "the marker remains as an explicit recovery fence"
        );
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn explicit_timeout_sidecar_recovery_repairs_external_cas_before_sqlite() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout recovery config");
        let signer_watermark = MemoryWatermark::default();
        let semantic_watermark = SharedMemorySemanticWatermarkV0::default();
        let context = SafetyRulesContextV1::new(
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.local_validator(),
            core_config.trusted_genesis_timestamp_ms(),
            64,
        )
        .expect("construct exact shadow context");
        let shadow_state =
            SafetyRulesStateV1::from_genesis(&context, genesis_qc.clone(), &StrictEd25519Verifier)
                .expect("construct exact shadow genesis state");
        let scope = [0x11; 32];
        let journal_id = [0x22; 32];
        let capability = [0x09; 32];
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            semantic_watermark.clone(),
            scope,
            journal_id,
            capability,
            shadow_state.digest(),
        )
        .expect("open semantic sidecar against genesis");
        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc,
            signer_watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize bounded timeout host");

        // This is the exact crash window: the authenticated Core has emitted
        // its timeout transition and the external semantic CAS has advanced,
        // but SQLite has not received the successor state yet.
        host.prepare_timeout_sidecar_crash_for_test_v1(&mut sidecar)
            .expect("publish marker and perform external CAS");
        assert_eq!(host.safety_head().expect("predecessor head").revision(), 0);
        assert_eq!(
            sidecar
                .expected_watermark()
                .map(|watermark| watermark.sequence()),
            Some(1)
        );
        assert!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect pending marker")
                .is_some()
        );
        drop(host);
        drop(sidecar);

        let calls = Arc::new(AtomicUsize::new(0));
        let mut recovered = PocoNodeHostV0::open_existing_with_safety_rules_external_v1(
            config,
            signer_watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&calls),
            },
            semantic_watermark,
            scope,
            journal_id,
            capability,
        )
        .expect("explicit recovery owner repairs the exact transition");
        assert_eq!(
            recovered
                .safety_head()
                .expect("recovered successor head")
                .revision(),
            1
        );
        assert_eq!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect cleared marker"),
            None
        );
        let actions = recovered
            .resume_v0()
            .expect("resume the recovered timeout without a second CAS");
        assert!(matches!(
            actions.as_slice(),
            [PocoNodeHostActionV0::Broadcast(outbound)]
                if matches!(outbound.message(), OutboundMessage::TimeoutVote(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn explicit_timeout_sidecar_recovery_reopens_after_sqlite_before_marker_clear() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout recovery config");
        let signer_watermark = MemoryWatermark::default();
        let semantic_watermark = SharedMemorySemanticWatermarkV0::default();
        let context = SafetyRulesContextV1::new(
            core_config.validator_set().clone(),
            *core_config.consensus_parameters(),
            core_config.local_validator(),
            core_config.trusted_genesis_timestamp_ms(),
            64,
        )
        .expect("construct exact shadow context");
        let shadow_state =
            SafetyRulesStateV1::from_genesis(&context, genesis_qc.clone(), &StrictEd25519Verifier)
                .expect("construct exact shadow genesis state");
        let scope = [0x11; 32];
        let journal_id = [0x22; 32];
        let capability = [0x09; 32];
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            semantic_watermark.clone(),
            scope,
            journal_id,
            capability,
            shadow_state.digest(),
        )
        .expect("open semantic sidecar against genesis");
        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc,
            signer_watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize bounded timeout host");
        host.prepare_timeout_sidecar_sqlite_before_clear_for_test_v1(&mut sidecar)
            .expect("publish marker, CAS, and SQLite successor");
        assert_eq!(host.safety_head().expect("successor head").revision(), 1);
        assert_eq!(
            sidecar
                .expected_watermark()
                .map(|watermark| watermark.sequence()),
            Some(1)
        );
        drop(host);
        drop(sidecar);

        let calls = Arc::new(AtomicUsize::new(0));
        let mut recovered = PocoNodeHostV0::open_existing_with_safety_rules_external_v1(
            config,
            signer_watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&calls),
            },
            semantic_watermark,
            scope,
            journal_id,
            capability,
        )
        .expect("explicit recovery owner must use retained predecessor");
        assert_eq!(
            recovered
                .safety_head()
                .expect("reopened successor head")
                .revision(),
            1
        );
        assert_eq!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect cleared marker"),
            None
        );
        let actions = recovered
            .resume_v0()
            .expect("resume the already persisted timeout exactly once");
        assert!(matches!(
            actions.as_slice(),
            [PocoNodeHostActionV0::Broadcast(outbound)]
                if matches!(outbound.message(), OutboundMessage::TimeoutVote(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn explicit_timeout_sidecar_recovery_authenticates_signer_profile_before_mutation() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout recovery config");
        let signer_watermark = MemoryWatermark::default();
        let semantic_watermark = SharedMemorySemanticWatermarkV0::default();
        let (mut sidecar, scope, journal_id, capability) =
            timeout_sidecar_fixture_v1(&core_config, &genesis_qc, semantic_watermark.clone());
        let mut host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc.clone(),
            signer_watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize bounded timeout host");
        host.prepare_timeout_sidecar_crash_for_test_v1(&mut sidecar)
            .expect("publish marker and external CAS");
        let marker = crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
            .expect("inspect pending marker")
            .expect("marker is present");
        assert!(marker.signer_journal_id().is_some());
        assert_eq!(host.safety_head().expect("predecessor head").revision(), 0);
        drop(host);
        drop(sidecar);

        // The signer SQLite file exists and is shape-valid, but this profile
        // differs from the authenticated journal metadata.  Recovery must
        // reject here, before opening the semantic sidecar or persisting the
        // regenerated Safety transition.
        let mismatched_config = PocoNodeStartConfigV0::new(
            &safety_path,
            &signer_path,
            core_config.clone(),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS + 1,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("construct profile-mismatch recovery config");
        let error = match PocoNodeHostV0::open_existing_with_safety_rules_external_v1(
            mismatched_config,
            signer_watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            semantic_watermark.clone(),
            scope,
            journal_id,
            capability,
        ) {
            Ok(_) => panic!("profile mismatch must fail before recovery mutation"),
            Err(error) => error,
        };
        assert!(matches!(error, PocoNodeHostErrorV0::SignerJournal(_)));
        assert_eq!(
            read_safety_head_for_test_v1(&safety_path, core_config.clone()).revision(),
            0,
            "SafetyStore must remain at its predecessor when signer auth fails"
        );
        assert_eq!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect retained marker"),
            Some(marker)
        );
        assert_eq!(
            semantic_watermark
                .inner
                .lock()
                .expect("semantic watermark lock")
                .head
                .map(|head| head.sequence()),
            Some(1),
            "sidecar head must remain exactly at the crash-time CAS"
        );
    }

    #[cfg(all(target_os = "linux", feature = "safety-rules-sidecar"))]
    #[test]
    fn explicit_timeout_sidecar_recovery_rejects_foreign_signer_identity_before_mutation() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let foreign_safety_path =
            protected_store_namespace(&directory, "foreign-safety").join("safety.sqlite3");
        let foreign_signer_path =
            protected_store_namespace(&directory, "foreign-signer").join("signer.sqlite3");
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid bounded timeout recovery config");
        let signer_watermark = MemoryWatermark::default();
        let semantic_watermark = SharedMemorySemanticWatermarkV0::default();
        let (mut sidecar, scope, journal_id, capability) =
            timeout_sidecar_fixture_v1(&core_config, &genesis_qc, semantic_watermark.clone());
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc.clone(),
            signer_watermark,
            UnavailableProducerV0,
        )
        .expect("initialize original timeout host");
        host.prepare_timeout_sidecar_crash_for_test_v1(&mut sidecar)
            .expect("publish marker and external CAS");
        let marker = crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
            .expect("inspect pending marker")
            .expect("marker is present");
        drop(host);
        drop(sidecar);

        // Initialize an independent, empty signer namespace with the exact
        // same profile.  Its independent journal identity must not be able to
        // consume the original SafetyStore's pending marker.
        let foreign_config = start_config(
            &foreign_safety_path,
            &foreign_signer_path,
            core_config.clone(),
        )
        .expect("valid foreign signer host config");
        let foreign_watermark = MemoryWatermark::default();
        let foreign_host = PocoNodeHostV0::initialize_new(
            foreign_config,
            genesis_qc,
            foreign_watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize independent signer namespace");
        drop(foreign_host);

        let mixed_config = start_config(&safety_path, &foreign_signer_path, core_config.clone())
            .expect("mixed safety/foreign-signer paths retain distinct namespaces");
        let error = match PocoNodeHostV0::open_existing_with_safety_rules_external_v1(
            mixed_config,
            foreign_watermark,
            StrictProducerV0 {
                key: local_key,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            semantic_watermark.clone(),
            scope,
            journal_id,
            capability,
        ) {
            Ok(_) => panic!("foreign signer identity must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SafetyRulesSemanticSidecar(
                SafetyRulesSemanticSidecarErrorV1::PendingMarkerSignerIdentityMismatch
            )
        ));
        assert_eq!(
            read_safety_head_for_test_v1(&safety_path, core_config).revision(),
            0,
            "foreign signer rejection must not advance SafetyStore"
        );
        assert_eq!(
            crate::safety_rules_sidecar::load_pending_timeout_marker_v1(&safety_path)
                .expect("inspect retained marker"),
            Some(marker)
        );
        assert_eq!(
            semantic_watermark
                .inner
                .lock()
                .expect("semantic watermark lock")
                .head
                .map(|head| head.sequence()),
            Some(1),
            "foreign signer rejection must not advance sidecar"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_producer_leaves_exact_prepared_tail_for_same_intent_retry() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid producer retry config");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc(&core_config),
            MemoryWatermark::default(),
            UnavailableOnceProducerV0 {
                key: local_key,
                calls: Arc::clone(&calls),
            },
        )
        .expect("initialize producer retry host");

        let first_error = host
            .on_local_timeout_v0()
            .expect_err("first producer call is deliberately unavailable");
        assert!(matches!(
            first_error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(
                    error.as_ref(),
                    SignerJournalErrorV0::SignatureProducer(
                        SignatureProducerErrorV0::Unavailable
                    )
                )
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let prepared = host
            .signer_journal_capacity()
            .expect("prepared signer tail is authenticated");
        assert_eq!(prepared.intent_count(), 1);
        assert_eq!(prepared.event_count(), 1);
        assert_eq!(prepared.maximum_safety_revision(), Some(1));
        assert_eq!(
            host.signer_journal_head()
                .expect("prepared external watermark")
                .sequence(),
            1
        );
        assert_eq!(host.safety_head().expect("safety head").revision(), 1);

        let retry = host
            .resume_v0()
            .expect("same durable Core intent completes on retry");
        let [PocoNodeHostActionV0::Broadcast(retried_outbound)] = retry.as_slice() else {
            panic!("retry must release exactly one timeout outbound");
        };
        assert_eq!(retried_outbound.authorizing_safety_revision(), 1);
        assert!(matches!(
            retried_outbound.message(),
            OutboundMessage::TimeoutVote(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let completed = host
            .signer_journal_capacity()
            .expect("completed signer tail is authenticated");
        assert_eq!(completed.intent_count(), 1);
        assert_eq!(completed.event_count(), 2);
        assert_eq!(
            host.signer_journal_head()
                .expect("completed external watermark")
                .sequence(),
            2
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_retryable_signer_failure_terminally_fail_stops_the_live_host() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, _) = strict_core_config_and_local_key();
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid fail-stop config");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc(&core_config),
            MemoryWatermark::default(),
            RejectedProducerV0 {
                calls: Arc::clone(&calls),
            },
        )
        .expect("initialize fail-stop host");

        let first = host
            .on_local_timeout_v0()
            .expect_err("producer rejection is non-retryable in the live host");
        assert!(matches!(
            first,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(
                    error.as_ref(),
                    SignerJournalErrorV0::SignatureProducer(
                        SignatureProducerErrorV0::Rejected
                    )
                )
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            host.resume_v0(),
            Err(PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_dispatcher_rejects_vote_intent_before_producer_or_journal() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid vote refusal config");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc(&core_config),
            MemoryWatermark::default(),
            StrictProducerV0 {
                key: local_key,
                calls: Arc::clone(&calls),
            },
        )
        .expect("initialize vote refusal host");
        let vote_intent = CanonicalSignIntentV0::vote(
            core_config.validator_set(),
            core_config.local_validator(),
            1,
            View::new(1),
            Height::new(1),
            BlockId::new([0x51; 32]),
        )
        .expect("shape-valid canonical vote intent");

        let error = host
            .drive_test_effects_v0(vec![Effect::RequestSignature {
                intent: vote_intent,
            }])
            .expect_err("timeout-only dispatcher must reject vote signing");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let capacity = host
            .signer_journal_capacity()
            .expect("vote refusal leaves journal unchanged");
        assert_eq!(capacity.intent_count(), 0);
        assert_eq!(capacity.event_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_profile_mismatch_fails_after_safety_store_authentication() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid initial config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config,
            genesis_qc,
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize dual stores");
        drop(host);

        let mismatched = PocoNodeStartConfigV0::new(
            &safety_path,
            &signer_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS + 1,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("shape-valid alternate local capacity profile");
        let error =
            match PocoNodeHostV0::open_existing(mismatched, watermark, UnavailableProducerV0) {
                Ok(_) => panic!("different signer profile must not open"),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::MetadataMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_revision_ahead_of_authenticated_safety_head_fails_startup() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let (core_config, local_key) = strict_core_config_and_local_key();
        let genesis = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid rollback-join config");
        let signer_profile = config.signer_journal_profile.clone();
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis.clone(),
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize exact dual stores at revision zero");
        drop(host);

        let mut signer_journal =
            SqliteSignerJournalV0::open_existing(&signer_path, signer_profile, watermark.clone())
                .expect("open independent signer journal fixture");
        let intent = CanonicalSignIntentV0::timeout_vote(
            core_config.validator_set(),
            core_config.local_validator(),
            1,
            View::new(1),
            QcReferenceV0::genesis_anchor(genesis).qc_ref(),
        )
        .expect("valid timeout intent one revision ahead of SafetyStore");
        let calls = Arc::new(AtomicUsize::new(0));
        signer_journal
            .sign_exact_v0(
                &intent,
                &mut StrictProducerV0 {
                    key: local_key,
                    calls: Arc::clone(&calls),
                },
            )
            .expect("advance signer journal fixture to safety revision one");
        drop(signer_journal);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let error = match PocoNodeHostV0::open_existing(config, watermark, UnavailableProducerV0) {
            Ok(_) => panic!("signer-ahead rollback join must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerSafetyRevisionAhead {
                signer_revision: 1,
                safety_revision: 0,
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_partial_dual_store_namespace_fails_closed() {
        let missing_signer_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_signer_directory);
        let safety_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, safety_only_core_config.clone())
            .expect("valid missing-signer config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&safety_only_core_config),
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize missing-signer fixture");
        drop(host);
        fs::remove_file(&signer_path).expect("remove signer database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark, UnavailableProducerV0) {
            Ok(_) => panic!("safety-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::Missing("database"))
        ));

        let missing_safety_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_safety_directory);
        let signer_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, signer_only_core_config.clone())
            .expect("valid missing-safety config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&signer_only_core_config),
            watermark.clone(),
            UnavailableProducerV0,
        )
        .expect("initialize missing-safety fixture");
        drop(host);
        fs::remove_file(&safety_path).expect("remove safety database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark, UnavailableProducerV0) {
            Ok(_) => panic!("signer-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Missing("database"))
        ));
    }
}
