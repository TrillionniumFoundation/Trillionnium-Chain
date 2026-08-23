//! Replay-fenced recovery of one deployed laboratory anchored-ordinary Ready cut.
//!
//! This owner reopens the exact namespaces created by
//! `deployed_lab_commissioning`, authenticates their complete current heads,
//! reconstructs the durable speculative P/K path selected by Safety's high QC,
//! and uses Core's dedicated anchored-ordinary recovery boundary to authenticate
//! the exact empty h2/h3 bodies. For revision>5 it additionally emits inert
//! coordinates for the signed Proposal/QC ancestry which local stores do not
//! retain. The resulting Core and every startup effect remain private: no
//! signer, timer driver, ingress, consensus runtime, ancestry completion, or
//! network catch-up authority is released.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    Core, CoreConfig, Effect, SafetyState, StateSyncAnchorOrdinaryRecoveryChallengeV0,
    StateSyncAnchorOrdinaryRecoveryReconcilerV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyStateStoreProfileV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, PinnedSqliteSignerJournalV0, SignerJournalProfileV0,
    SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockId, CertificateId, CertifiedHeaderV0, QcRef,
    QuorumCertificate, SignedProposalV0, StateRoot, ValidatorId, View,
};
use trnm_native_application::{
    ApplicationHeadV0, ChainIdV0, GenesisHashV0, Hash32V0, NativeApplicationRecoveryRequestV0,
    NativeApplicationV0, NativeRecoveryDispositionV0, NativeRecoveryWatermarksV0,
};
use trnm_native_application_sqlite::{
    ProposalRouteV0, ProposalValidationBindingV0, ProposalValidationOwnerIdV0,
    ProposalValidationStoreScopeV0, ReplaySessionPresenceV0, SqliteProposalValidationStoreV0,
};
use trnm_native_execution_v0::{
    ConfirmedDurableExecutionHistoryRowV0, DurableExecutionHistoryStatusV0,
    DurableNativeApplicationV0, NativeApplicationConfigV0,
};

use crate::{
    derive_signer_watermark_scope_v0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
    SqliteExternalNodeCheckpointStoreV0, SIGNER_JOURNAL_PROFILE_REF_V0,
    STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

pub(super) const MAXIMUM_RECORD_BYTES_V0: usize = 64 * 1024 * 1024;
pub(super) const MAXIMUM_BLOB_BYTES_V0: usize = 16 * 1024 * 1024;
pub(super) const MAXIMUM_SAFETY_DATABASE_BYTES_V0: usize = 256 * 1024 * 1024;
pub(super) const MAXIMUM_SIGNER_INTENTS_V0: u64 = 4_096;
pub(super) const MAXIMUM_SIGNER_INTENT_BYTES_V0: usize = 4_096;
pub(super) const MAXIMUM_SIGNER_DATABASE_BYTES_V0: usize = 64 * 1024 * 1024;
pub(super) const MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0: u64 = 6;
pub(super) const PROPOSAL_SCOPE_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.proposal-scope.v0";
pub(super) const PROPOSAL_OWNER_DOMAIN_V0: &[u8] = b"trnm.poco-node.deployed-lab.proposal-owner.v0";

/// A coherent rollback of every local authority namespace still requires an
/// independently administered whole-node monotonic anchor. The signer
/// watermark protects its own event chain, not Safety-only QC progress.
pub const DEPLOYED_LAB_COHERENT_WHOLE_ROOT_ROLLBACK_AUTHORITY_V0: bool = false;

/// Stage-addressed failure for deployed ordinary recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeDeployedLabRecoveryErrorV0 {
    stage: &'static str,
    detail: String,
}

impl PocoNodeDeployedLabRecoveryErrorV0 {
    fn from_debug(stage: &'static str, error: impl fmt::Debug) -> Self {
        Self {
            stage,
            detail: format!("{error:?}"),
        }
    }

    fn message(stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    pub const fn stage_v0(&self) -> &'static str {
        self.stage
    }
}

impl fmt::Display for PocoNodeDeployedLabRecoveryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deployed Lab recovery failed at {}: {}",
            self.stage, self.detail
        )
    }
}

impl Error for PocoNodeDeployedLabRecoveryErrorV0 {}

macro_rules! recover_try {
    ($stage:literal, $expression:expr) => {
        $expression
            .map_err(|error| PocoNodeDeployedLabRecoveryErrorV0::from_debug($stage, error))?
    };
}

/// One authenticated speculative block on the high-QC replay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabReplayBlockV0 {
    block_id: BlockId,
    parent_block_id: BlockId,
    height: u64,
    view: View,
    timestamp_ms: u64,
    post_state_root: StateRoot,
}

impl PocoNodeDeployedLabReplayBlockV0 {
    pub const fn block_id_v0(self) -> BlockId {
        self.block_id
    }

    pub const fn parent_block_id_v0(self) -> BlockId {
        self.parent_block_id
    }

    pub const fn height_v0(self) -> u64 {
        self.height
    }

    pub const fn view_v0(self) -> View {
        self.view
    }

    pub const fn timestamp_ms_v0(self) -> u64 {
        self.timestamp_ms
    }

    pub const fn post_state_root_v0(self) -> StateRoot {
        self.post_state_root
    }
}

/// Inert coordinates which must be satisfied by authenticated signed replay.
///
/// The terminal P/K inventory proves application execution only. It does not
/// contain proposal witnesses or certifying QCs. Every block listed here must
/// therefore be supplied as the exact [`SignedProposalV0`] plus its verified
/// ordinary QC before any later owner may submit `SafetyReplayComplete` or
/// release timer, signer, ingress, or runtime authority. This value has no
/// public constructor and is not itself a replay ticket.
#[derive(Debug, PartialEq, Eq)]
pub struct PocoNodeDeployedLabSignedAncestryReplayChallengeV0 {
    anchor_proof_id: CertificateId,
    anchor_h3_block_id: BlockId,
    safety_revision: u64,
    safety_chain_checksum: [u8; 32],
    finalized_block_id: BlockId,
    finalized_height: u64,
    high_qc: QcRef,
    locked_qc: QcRef,
    current_view: View,
    required_blocks: Vec<PocoNodeDeployedLabReplayBlockV0>,
}

/// Untrusted signed replay material for one exact recovered application row.
///
/// Construction grants no authority. Only consumption by the recovery owner
/// can turn a complete, strictly verified sequence into an authenticated
/// activation carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeDeployedLabSignedReplayEntryV0 {
    proposal: SignedProposalV0,
    certificate: QuorumCertificate,
}

impl PocoNodeDeployedLabSignedReplayEntryV0 {
    pub fn new(proposal: SignedProposalV0, certificate: QuorumCertificate) -> Self {
        Self {
            proposal,
            certificate,
        }
    }

    pub const fn proposal_v0(&self) -> &SignedProposalV0 {
        &self.proposal
    }

    pub const fn certificate_v0(&self) -> &QuorumCertificate {
        &self.certificate
    }
}

/// Scalar readback of the exact signed ancestry admitted by the activation
/// seam. These facts are descriptive; the non-cloneable owner below is the
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
    challenge_sha256: [u8; 32],
    safety_revision: u64,
    authenticated_block_count: u64,
    terminal_certificate_id: CertificateId,
}

impl PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
    pub const fn challenge_sha256_v0(self) -> [u8; 32] {
        self.challenge_sha256
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn authenticated_block_count_v0(self) -> u64 {
        self.authenticated_block_count
    }

    pub const fn terminal_certificate_id_v0(self) -> CertificateId {
        self.terminal_certificate_id
    }
}

impl PocoNodeDeployedLabSignedAncestryReplayChallengeV0 {
    pub const fn anchor_proof_id_v0(&self) -> CertificateId {
        self.anchor_proof_id
    }

    pub const fn anchor_h3_block_id_v0(&self) -> BlockId {
        self.anchor_h3_block_id
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_chain_checksum_v0(&self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn finalized_block_id_v0(&self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(&self) -> u64 {
        self.finalized_height
    }

    pub const fn high_qc_v0(&self) -> QcRef {
        self.high_qc
    }

    pub const fn locked_qc_v0(&self) -> QcRef {
        self.locked_qc
    }

    pub const fn current_view_v0(&self) -> View {
        self.current_view
    }

    pub fn required_blocks_v0(&self) -> &[PocoNodeDeployedLabReplayBlockV0] {
        &self.required_blocks
    }

    pub const fn requires_signed_ancestry_replay_v0(&self) -> bool {
        !self.required_blocks.is_empty()
    }
}

/// Inert facts for one fully authenticated, replay-fenced ordinary cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeDeployedLabRecoveryFactsV0 {
    checkpoint: ExternalNodeCheckpointV0,
    local_validator: ValidatorId,
    current_view: View,
    high_qc: QcRef,
    finalized_block_id: BlockId,
    finalized_height: u64,
    application_applied_block_id: BlockId,
    application_applied_height: u64,
    application_commit_sequence: u64,
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_exact_watermark: trnm_consensus_signer_journal::SignerWatermarkV0,
    proposal_validation_sequence: u64,
    proposal_validation_terminal_rows: u64,
    committed_application_records: u64,
    prepared_application_records: u64,
    application_history_records: u64,
    high_qc_replay_path: Vec<PocoNodeDeployedLabReplayBlockV0>,
}

impl PocoNodeDeployedLabRecoveryFactsV0 {
    pub const fn checkpoint_v0(&self) -> ExternalNodeCheckpointV0 {
        self.checkpoint
    }

    pub const fn local_validator_v0(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn current_view_v0(&self) -> View {
        self.current_view
    }

    pub const fn high_qc_v0(&self) -> QcRef {
        self.high_qc
    }

    pub const fn finalized_block_id_v0(&self) -> BlockId {
        self.finalized_block_id
    }

    pub const fn finalized_height_v0(&self) -> u64 {
        self.finalized_height
    }

    pub const fn application_applied_block_id_v0(&self) -> BlockId {
        self.application_applied_block_id
    }

    pub const fn application_applied_height_v0(&self) -> u64 {
        self.application_applied_height
    }

    pub const fn application_commit_sequence_v0(&self) -> u64 {
        self.application_commit_sequence
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn safety_chain_checksum_v0(&self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn signer_exact_watermark_v0(
        &self,
    ) -> trnm_consensus_signer_journal::SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn proposal_validation_sequence_v0(&self) -> u64 {
        self.proposal_validation_sequence
    }

    pub const fn proposal_validation_terminal_rows_v0(&self) -> u64 {
        self.proposal_validation_terminal_rows
    }

    pub const fn prepared_application_records_v0(&self) -> u64 {
        self.prepared_application_records
    }

    pub const fn committed_application_records_v0(&self) -> u64 {
        self.committed_application_records
    }

    pub const fn application_history_records_v0(&self) -> u64 {
        self.application_history_records
    }

    pub fn high_qc_replay_path_v0(&self) -> &[PocoNodeDeployedLabReplayBlockV0] {
        &self.high_qc_replay_path
    }
}

/// Non-cloneable owner of one exact recovered cut.
///
/// Every field remains private and no activation method exists.  Holding this
/// value pins the authenticated store identities and Core recovery state while
/// a later network-replay tranche is still absent.
#[must_use = "the recovered cut owner pins all durable authorities"]
pub struct PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W: ExternalMonotonicWatermarkV0> {
    facts: PocoNodeDeployedLabRecoveryFactsV0,
    replay_challenge: PocoNodeDeployedLabSignedAncestryReplayChallengeV0,
    _core: Core,
    _suppressed_startup_effects: Vec<Effect>,
    _safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    _application: DurableNativeApplicationV0,
    _signer: PinnedSqliteSignerJournalV0<W>,
    _checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    _validation_store: SqliteProposalValidationStoreV0,
    _application_history_rows: Vec<ConfirmedDurableExecutionHistoryRowV0>,
    _replay_bindings: Vec<ProposalValidationBindingV0>,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeDeployedLabRecoveryFactsV0 {
        &self.facts
    }

    pub const fn signed_ancestry_replay_challenge_v0(
        &self,
    ) -> &PocoNodeDeployedLabSignedAncestryReplayChallengeV0 {
        &self.replay_challenge
    }

    /// Consumes untrusted network/archive replay and returns a non-forgeable,
    /// still-inert activation carrier only after every signed Proposal, QC,
    /// application P/K coordinate, and durable owner head agrees exactly.
    ///
    /// This seam intentionally does not submit `SafetyReplayComplete`, activate
    /// the signer, release a timer, or expose a consensus runtime. Core replay
    /// still needs a crash-safe P/D/C/K driver which can acknowledge each
    /// replay persistence transition without replacing the already durable
    /// native execution rows.
    pub fn authenticate_signed_ancestry_replay_v0(
        mut self,
        entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    ) -> Result<PocoNodeDeployedLabAuthenticatedReplayOwnerV0<W>, PocoNodeDeployedLabRecoveryErrorV0>
    {
        let required = self.replay_challenge.required_blocks_v0();
        if required.is_empty() || entries.len() != required.len() {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.signed_inventory",
                "signed replay must exactly cover every post-h3 challenge block",
            ));
        }
        let set = self._core.config().validator_set();
        let parameters = self._core.config().consensus_parameters();
        let maximum_message_bytes = parameters.max_consensus_message_bytes() as usize;
        let mut prior_certificate = None;
        let mut observed_ids = BTreeSet::new();
        for (index, (coordinate, entry)) in required.iter().zip(&entries).enumerate() {
            let proposal = entry.proposal_v0();
            let certificate = entry.certificate_v0();
            let header = proposal.block().header();
            let binding = self
                ._replay_bindings
                .iter()
                .find(|binding| binding.block_id().as_bytes() == coordinate.block_id.as_bytes())
                .ok_or_else(|| {
                    PocoNodeDeployedLabRecoveryErrorV0::message(
                        "replay.binding",
                        "signed replay block lacks its exact retained terminal K binding",
                    )
                })?;
            let parent = self
                .facts
                .high_qc_replay_path
                .iter()
                .find(|candidate| candidate.block_id == coordinate.parent_block_id)
                .ok_or_else(|| {
                    PocoNodeDeployedLabRecoveryErrorV0::message(
                        "replay.parent",
                        "signed replay parent is absent from the authenticated P/K path",
                    )
                })?;
            if index > 0 && prior_certificate != Some(proposal.witness().justify_qc().qc_ref()) {
                return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                    "replay.certificate_chain",
                    "signed replay proposal does not carry the preceding exact QC",
                ));
            }
            if proposal.block().id() != coordinate.block_id
                || header.parent_id() != coordinate.parent_block_id
                || header.height().get() != coordinate.height
                || header.view() != coordinate.view
                || header.timestamp_ms() != coordinate.timestamp_ms
                || proposal.witness().justify_qc().qc_ref().block_id() != coordinate.parent_block_id
                || proposal.witness().justify_qc().qc_ref().height().get()
                    != coordinate.height.checked_sub(1).ok_or_else(|| {
                        PocoNodeDeployedLabRecoveryErrorV0::message(
                            "replay.height",
                            "signed replay height underflowed",
                        )
                    })?
                || proposal.witness().justify_qc().qc_ref().view() != parent.view
                || binding.parent().block_id().as_bytes() != coordinate.parent_block_id.as_bytes()
                || binding.block_id().as_bytes() != coordinate.block_id.as_bytes()
                || binding.height().get() != coordinate.height
                || binding.view() != coordinate.view.get()
                || binding.timestamp_ms() != coordinate.timestamp_ms
                || binding.commitments().payload_root().as_bytes()
                    != header.payload_root().as_bytes()
                || binding.commitments().post_state_root().as_bytes()
                    != header.state_root().as_bytes()
                || binding.commitments().receipts_root().as_bytes()
                    != header.receipts_root().as_bytes()
                || binding.commitments().evidence_root().as_bytes()
                    != header.evidence_root().as_bytes()
                || coordinate.post_state_root != header.state_root()
                || certificate.block_id() != coordinate.block_id
                || certificate.height().get() != coordinate.height
                || certificate.view() != coordinate.view
                || proposal.block().logical_block_size() > self._core.config().max_block_bytes()
                || proposal
                    .durable_validation_resource_size_v0()
                    .map_err(|error| {
                        PocoNodeDeployedLabRecoveryErrorV0::from_debug(
                            "replay.resource_size",
                            error,
                        )
                    })?
                    > maximum_message_bytes
            {
                return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                    "replay.coordinate_join",
                    "signed Proposal/QC differs from its exact P/K replay coordinate",
                ));
            }
            recover_try!(
                "replay.proposal_signature",
                proposal.verify(
                    set,
                    None,
                    parameters,
                    parent.timestamp_ms,
                    &StrictEd25519Verifier,
                )
            );
            recover_try!(
                "replay.certificate_signature",
                certificate.verify(set, &StrictEd25519Verifier)
            );
            let certificate_ref = QcRef::from(certificate);
            if (certificate_ref.block_id() == self.replay_challenge.high_qc.block_id()
                && certificate_ref != self.replay_challenge.high_qc)
                || (certificate_ref.block_id() == self.replay_challenge.locked_qc.block_id()
                    && certificate_ref != self.replay_challenge.locked_qc)
                || !observed_ids.insert(certificate.id())
            {
                return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                    "replay.safety_certificate",
                    "signed replay QC is duplicate or differs from a durable Safety anchor",
                ));
            }
            prior_certificate = Some(certificate_ref);
        }
        if prior_certificate != Some(self.replay_challenge.high_qc) {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.terminal_certificate",
                "signed replay does not terminate at the exact durable high QC",
            ));
        }

        let safety = recover_try!("replay.final_safety", self._safety_store.head());
        let application = recover_try!(
            "replay.final_application",
            self._application.confirmed_committed_head_v0()
        );
        let signer = recover_try!(
            "replay.final_signer",
            self._signer.confirm_node_checkpoint_head_exact_v0()
        );
        let checkpoint = recover_try!(
            "replay.final_checkpoint",
            self._checkpoint_store.load(self.facts.checkpoint.scope())
        );
        let validation_sequence = recover_try!(
            "replay.final_validation",
            self._validation_store.durable_sequence_v0()
        );
        if safety.state() != self._core.safety_state()
            || safety.revision() != self.facts.safety_revision
            || application.block_id().as_bytes()
                != self.facts.application_applied_block_id.as_bytes()
            || application.height().get() != self.facts.application_applied_height
            || signer.exact_watermark() != self.facts.signer_exact_watermark
            || checkpoint != Some(self.facts.checkpoint)
            || validation_sequence != self.facts.proposal_validation_sequence
        {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.final_owner_join",
                "a durable recovery owner changed during signed ancestry authentication",
            ));
        }
        let authenticated_block_count = u64::try_from(entries.len()).map_err(|_| {
            PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.count",
                "authenticated replay length overflows u64",
            )
        })?;
        let facts = PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
            challenge_sha256: signed_replay_challenge_sha256_v0(&self.replay_challenge),
            safety_revision: self.facts.safety_revision,
            authenticated_block_count,
            terminal_certificate_id: self.replay_challenge.high_qc.qc_digest(),
        };
        Ok(PocoNodeDeployedLabAuthenticatedReplayOwnerV0 {
            recovery: self,
            entries,
            facts,
        })
    }
}

/// Test-support host boundary for an already authenticated deployed cut.
///
/// The ordinary recovery owner above deliberately predates a real node host:
/// it owns Core and all durable namespaces but exposes no lifecycle surface.
/// This wrapper is the smallest safe integration point for host reopen tests.
/// It does not install an effect driver, activate a signer, or release a
/// timer.  Opening it performs the existing Core anchor-recovery coordinator
/// and then performs one more owner-affinity read immediately before the host
/// is returned.  The extra read closes the otherwise untested gap between the
/// recovery coordinator returning and a host retaining the owner.
#[cfg(feature = "lab-validator-runtime-test-support")]
#[must_use = "the test host pins the authenticated recovery owner"]
pub struct PocoNodeDeployedLabRecoveryHostV0<W: ExternalMonotonicWatermarkV0> {
    owner: PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W>,
}

#[cfg(feature = "lab-validator-runtime-test-support")]
impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabRecoveryHostV0<W> {
    pub const fn facts_v0(&self) -> &PocoNodeDeployedLabRecoveryFactsV0 {
        self.owner.facts_v0()
    }

    /// Read-only identity of the permanent h1 state-sync anchor retained by
    /// the recovered Core.  This is deliberately a scalar projection: it
    /// exposes no proof, store, signer, or successor authority.
    pub fn state_sync_anchor_proof_id_v0(&self) -> Option<CertificateId> {
        match self.owner._core.safety_state().state_sync_anchor() {
            Some(anchor) => Some(anchor.proof_id()),
            None => None,
        }
    }

    /// Height of the permanent h1 state-sync anchor, if the recovered Core
    /// retained one.  A deployed ordinary cut must report height one.
    pub fn state_sync_anchor_height_v0(&self) -> Option<u64> {
        match self.owner._core.safety_state().state_sync_anchor() {
            Some(anchor) => Some(anchor.proof().finalized_block().header().height().get()),
            None => None,
        }
    }

    /// Re-read the Core/Safety/signer/checkpoint join while the host is held.
    ///
    /// This is intentionally read-only.  Any disagreement fail-stops the
    /// host and prevents a caller from treating a post-open mutation as a
    /// valid recovery result.
    pub fn revalidate_durable_boundary_v0(
        &mut self,
    ) -> Result<(), PocoNodeDeployedLabRecoveryErrorV0> {
        let expected = self.owner.facts.checkpoint;
        let safety = self.owner._safety_store.head().map_err(|error| {
            PocoNodeDeployedLabRecoveryErrorV0::from_debug("host.safety_readback", error)
        })?;
        if safety.state() != self.owner._core.safety_state() {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "host.core_safety_join",
                "host reopen observed a Safety head different from the recovered Core",
            ));
        }
        let signer = self
            .owner
            ._signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(|error| {
                PocoNodeDeployedLabRecoveryErrorV0::from_debug("host.signer_readback", error)
            })?;
        if signer.exact_watermark() != expected.signer_exact_watermark() {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "host.signer_checkpoint_join",
                "host reopen observed a signer watermark different from the checkpoint",
            ));
        }
        let observed = self
            .owner
            ._checkpoint_store
            .load(expected.scope())
            .map_err(|error| {
                PocoNodeDeployedLabRecoveryErrorV0::from_debug("host.checkpoint_readback", error)
            })?;
        if observed != Some(expected) {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "host.checkpoint_join",
                "host reopen observed a changed or missing external checkpoint",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "lab-validator-runtime-test-support")]
impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeDeployedLabRecoveryHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabRecoveryHostV0")
            .field("facts", self.owner.facts_v0())
            .finish_non_exhaustive()
    }
}

/// Open the existing deployed cut through the test-only host boundary.
///
/// The underlying recovery coordinator remains the sole constructor of the
/// Core owner.  This function only adds a final, read-only host admission
/// check; it cannot commission a fresh namespace or enable production flags.
#[cfg(feature = "lab-validator-runtime-test-support")]
pub fn reopen_deployed_lab_ordinary_host_v0<W, F, E>(
    authority_root: impl AsRef<Path>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    open_watermark: F,
) -> Result<PocoNodeDeployedLabRecoveryHostV0<W>, PocoNodeDeployedLabRecoveryErrorV0>
where
    W: ExternalMonotonicWatermarkV0,
    F: FnOnce(&Path) -> Result<W, E>,
    E: fmt::Debug,
{
    let owner = reopen_deployed_lab_ordinary_cut_v0(
        authority_root,
        core_config,
        application_config,
        open_watermark,
    )?;
    let mut host = PocoNodeDeployedLabRecoveryHostV0 { owner };
    host.revalidate_durable_boundary_v0()?;
    Ok(host)
}

/// Non-cloneable output of exact signed-ancestry authentication.
///
/// It pins all underlying durable owners and retains the verified signed
/// replay bytes. No normal-build method currently releases Core, signer,
/// timer, ingress, or continuous-runtime authority from this carrier.
#[must_use = "authenticated replay remains inert until crash-safe activation exists"]
pub struct PocoNodeDeployedLabAuthenticatedReplayOwnerV0<W: ExternalMonotonicWatermarkV0> {
    recovery: PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W>,
    entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    facts: PocoNodeDeployedLabAuthenticatedReplayFactsV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabAuthenticatedReplayOwnerV0<W> {
    pub const fn facts_v0(&self) -> PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
        self.facts
    }

    pub const fn recovery_facts_v0(&self) -> &PocoNodeDeployedLabRecoveryFactsV0 {
        &self.recovery.facts
    }

    pub fn signed_replay_v0(&self) -> &[PocoNodeDeployedLabSignedReplayEntryV0] {
        &self.entries
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug
    for PocoNodeDeployedLabAuthenticatedReplayOwnerV0<W>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabAuthenticatedReplayOwnerV0")
            .field("facts", &self.facts)
            .field("recovery_facts", &self.recovery.facts)
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabOrdinaryRecoveryOwnerV0")
            .field("facts", &self.facts)
            .field("replay_challenge", &self.replay_challenge)
            .finish_non_exhaustive()
    }
}

pub(super) struct AuthorityPathsV0 {
    pub(super) target_safety: PathBuf,
    pub(super) signer: PathBuf,
    pub(super) application: PathBuf,
    pub(super) checkpoint: PathBuf,
    pub(super) validation: PathBuf,
    pub(super) watermark: PathBuf,
}

pub(super) struct RecoveredHistoryKV0 {
    pub(super) binding: ProposalValidationBindingV0,
    pub(super) application_head: ApplicationHeadV0,
    pub(super) validation_row_checksum: [u8; 32],
    pub(super) status: DurableExecutionHistoryStatusV0,
    pub(super) history_row: ConfirmedDurableExecutionHistoryRowV0,
}

struct ExactDeployedAnchorOrdinaryReconcilerV0 {
    expected_safety: SafetyState,
    expected_child: SignedProposalV0,
    expected_grandchild: SignedProposalV0,
    calls: usize,
}

impl StateSyncAnchorOrdinaryRecoveryReconcilerV0 for ExactDeployedAnchorOrdinaryReconcilerV0 {
    fn reconcile_state_sync_anchor_ordinary_v0(
        &mut self,
        challenge: &StateSyncAnchorOrdinaryRecoveryChallengeV0,
    ) -> bool {
        self.calls = self.calls.saturating_add(1);
        challenge.safety_state() == &self.expected_safety
            && challenge.child() == &self.expected_child
            && challenge.grandchild() == &self.expected_grandchild
    }
}

/// Reopens one exact deployed anchored-ordinary Ready cut without minting
/// runtime, signing, timer-driver, finalization, or network authority.
pub fn reopen_deployed_lab_ordinary_cut_v0<W, F, E>(
    authority_root: impl AsRef<Path>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    open_watermark: F,
) -> Result<PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<W>, PocoNodeDeployedLabRecoveryErrorV0>
where
    W: ExternalMonotonicWatermarkV0,
    F: FnOnce(&Path) -> Result<W, E>,
    E: fmt::Debug,
{
    validate_context_v0(&core_config, &application_config)?;
    let paths = existing_paths_v0(authority_root.as_ref())?;
    let limits = recover_try!(
        "safety.record_limits",
        trnm_consensus_core::SafetyStateRecordLimitsV0::new(
            MAXIMUM_RECORD_BYTES_V0,
            MAXIMUM_BLOB_BYTES_V0,
        )
    );
    let safety_profile = recover_try!(
        "safety.profile",
        SafetyStateStoreProfileV0::new(
            core_config.clone(),
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0,
        )
    );
    let safety_store = recover_try!(
        "safety.open_existing",
        SqliteSafetyStateStoreV0::open_existing(
            &paths.target_safety,
            safety_profile,
            StrictEd25519Verifier,
        )
    );
    let safety_head = recover_try!("safety.head", safety_store.head());
    let safety = safety_head.state();
    let finalized = safety.finalized();
    let applied = safety.application_applied();
    let high_qc = safety.high_qc().qc_ref();
    if !recoverable_clean_transition_v0(safety, safety_head.transition_context())
        || safety.state_sync_anchor().is_none()
        || safety.safety_halt().is_some()
        || finalized.height().get() == 0
        || finalized != applied
        || safety.pending_sign().is_some()
        || safety.pending_finalize().is_some()
        || safety.pending_finalization().is_some()
        || safety.pending_tc_high_qc_sync().is_some()
        || safety.pending_standalone_qc_sync().is_some()
        || !safety.finalization_queue().is_empty()
        || !safety.payload_validation_obligations().is_empty()
        || high_qc.height() < applied.height()
        || safety.current_view() <= high_qc.view()
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "safety.clean_cut",
            "only a deployed anchored-ordinary Ready cut with no pending obligation, sign, certificate sync, or finalization can be reopened",
        ));
    }
    let anchor = safety
        .state_sync_anchor()
        .expect("the exact deployed promotion cut retains its permanent h1 anchor");
    let child = reconstruct_empty_anchor_successor_v0(
        anchor.proof().child(),
        core_config.validator_set(),
        core_config.consensus_parameters(),
        anchor.proof().finalized_block().header().timestamp_ms(),
    )?;
    let grandchild = reconstruct_empty_anchor_successor_v0(
        anchor.proof().grandchild(),
        core_config.validator_set(),
        core_config.consensus_parameters(),
        anchor.proof().child().header().timestamp_ms(),
    )?;
    let safety_facts = recover_try!(
        "safety.confirm_exact",
        safety_store.confirm_node_checkpoint_head_exact_v0(safety)
    );

    let application = recover_try!(
        "application.open_existing",
        DurableNativeApplicationV0::open(&paths.application, application_config)
    );
    let committed = recover_try!(
        "application.committed_head",
        application.confirmed_committed_head_v0()
    );
    if committed.block_id().as_bytes() != applied.block_id().as_bytes()
        || committed.height().get() != applied.height().get()
        || committed.state_root().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "application.applied_join",
            "native committed head differs from Safety application_applied",
        ));
    }

    let chain_facts = application.config_v0().chain_genesis_facts_v0();
    let scope_bytes = hash_v0(
        PROPOSAL_SCOPE_DOMAIN_V0,
        &[
            core_config.validator_set().id().as_bytes(),
            core_config.local_validator().as_bytes(),
        ],
    );
    let owner_bytes = hash_v0(
        PROPOSAL_OWNER_DOMAIN_V0,
        &[
            &chain_facts.chain_descriptor_hash_v0(),
            core_config.local_validator().as_bytes(),
        ],
    );
    let validation_scope = recover_try!(
        "validation.scope",
        ProposalValidationStoreScopeV0::new(scope_bytes)
    );
    let validation_owner = recover_try!(
        "validation.owner",
        ProposalValidationOwnerIdV0::new(owner_bytes)
    );
    let mut validation_store = recover_try!(
        "validation.open_existing",
        SqliteProposalValidationStoreV0::open(
            &paths.validation,
            validation_scope,
            MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0,
        )
    );
    if !matches!(
        recover_try!(
            "validation.replay_session_presence",
            validation_store.replay_session_presence_v0()
        ),
        ReplaySessionPresenceV0::None
    ) {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "validation.replay_session_pending",
            "an existing replay session must be resumed by the dedicated process2 recovery owner",
        ));
    }
    let terminal_audit = recover_try!(
        "validation.terminal_audit",
        validation_store.confirm_terminal_k_audit_v0()
    );
    let expected_validation_sequence = terminal_audit
        .terminal_row_count_v0()
        .checked_mul(3)
        .ok_or_else(|| {
            PocoNodeDeployedLabRecoveryErrorV0::message(
                "validation.sequence_overflow",
                "terminal K inventory sequence overflowed",
            )
        })?;
    if !terminal_audit.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
        || terminal_audit.scope_v0() != validation_scope
        || terminal_audit.owner_id_v0() != validation_owner
        || terminal_audit.store_id_v0() == [0; 32]
        || terminal_audit.store_sequence_v0() < MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0
        || terminal_audit.store_sequence_v0() != expected_validation_sequence
        || terminal_audit.maximum_terminal_height_v0() < 3
        || usize::try_from(terminal_audit.terminal_row_count_v0()).ok()
            != Some(terminal_audit.terminal_bindings_v0().len())
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "validation.owner_join",
            "terminal K inventory differs from the deployed proposal owner",
        ));
    }

    let mut history = BTreeMap::new();
    let mut committed_count = 0_u64;
    let mut prepared_count = 0_u64;
    for binding in terminal_audit.terminal_bindings_v0() {
        validate_binding_context_v0(binding, &core_config)?;
        let row = recover_try!(
            "validation.k_readback",
            validation_store.confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        );
        let executed = recover_try!(
            "validation.artifact_readback",
            validation_store.read_artifact_exact_v0(binding)
        );
        let history_row = recover_try!(
            "application.history_readback",
            application.confirm_durable_execution_history_row_v0(&executed)
        );
        let application_parent =
            recover_try!("application.history_parent", history_row.parent_head_v0());
        let application_head =
            recover_try!("application.history_target", history_row.target_head_v0());
        if row.binding_v0() != binding
            || row.scope_v0() != validation_scope
            || row.store_id_v0() != validation_store.store_id_v0()
            || row.owner_id_v0() != validation_owner
            || row.store_sequence_v0() != terminal_audit.store_sequence_v0()
            || !row.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
            || executed.request().parent() != binding.parent()
            || executed.request().block_id() != binding.block_id()
            || executed.request().height() != binding.height()
            || executed.request().timestamp_ms() != binding.timestamp_ms()
            || executed.request().active_validator_set_id() != binding.active_validator_set_id()
            || executed.request().expected() != binding.commitments()
            || !history_row.belongs_to_application_at_path_v0(&application, &paths.application)
            || history_row.store_id_v0() != application.config_v0().store_id()
            || &application_parent != binding.parent()
            || application_head.block_id() != binding.block_id()
            || application_head.height() != binding.height()
            || application_head.state_root() != binding.commitments().post_state_root()
            || ((binding.height().get() <= applied.height().get())
                != (history_row.status_v0() == DurableExecutionHistoryStatusV0::Committed))
        {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "validation.pk_join",
                "terminal K differs from its exact durable application P",
            ));
        }
        match history_row.status_v0() {
            DurableExecutionHistoryStatusV0::Committed => {
                committed_count = committed_count.checked_add(1).ok_or_else(|| {
                    PocoNodeDeployedLabRecoveryErrorV0::message(
                        "application.committed_count",
                        "committed application history count overflowed",
                    )
                })?;
            }
            DurableExecutionHistoryStatusV0::Prepared => {
                prepared_count = prepared_count.checked_add(1).ok_or_else(|| {
                    PocoNodeDeployedLabRecoveryErrorV0::message(
                        "application.prepared_count",
                        "prepared application history count overflowed",
                    )
                })?;
            }
        }
        let block_id = BlockId::new(*binding.block_id().as_bytes());
        if history
            .insert(
                block_id,
                RecoveredHistoryKV0 {
                    binding: binding.clone(),
                    application_head,
                    validation_row_checksum: *row.row_checksum_v0().as_bytes(),
                    status: history_row.status_v0(),
                    history_row,
                },
            )
            .is_some()
        {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "validation.duplicate_block",
                "terminal K inventory contains a duplicate block id",
            ));
        }
    }

    let recovery_request = recover_try!(
        "application.recovery_request",
        NativeApplicationRecoveryRequestV0::new(
            recover_try!(
                "application.chain_id",
                ChainIdV0::new(application.config_v0().chain_id_v0())
            ),
            recover_try!(
                "application.genesis_hash",
                GenesisHashV0::new(application.config_v0().genesis_hash_v0())
            ),
            Hash32V0::new(application.config_v0().chain_descriptor_hash_v0()),
            Hash32V0::new(application.config_v0().signer_policy_commitment_v0()),
            committed.clone(),
            NativeRecoveryWatermarksV0::new(0, 0, 0),
        )
    );
    let application_recovery = recover_try!(
        "application.recovery_readback",
        application.recover(recovery_request)
    );
    let history_count = u64::try_from(history.len()).map_err(|_| {
        PocoNodeDeployedLabRecoveryErrorV0::message(
            "application.history_count",
            "terminal P/K history length overflows u64",
        )
    })?;
    match application_recovery.disposition() {
        NativeRecoveryDispositionV0::Exact if prepared_count == 0 => {}
        NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records }
            if pending_records == prepared_count => {}
        _ => {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "application.pending_join",
                "native prepared-P inventory differs from terminal K recovery rows",
            ));
        }
    }
    let expected_committed_count = committed.height().get().checked_sub(1).ok_or_else(|| {
        PocoNodeDeployedLabRecoveryErrorV0::message(
            "application.committed_count",
            "deployed anchored application head precedes trusted h1",
        )
    })?;
    if committed_count != expected_committed_count
        || history_count != terminal_audit.terminal_row_count_v0()
        || committed_count.checked_add(prepared_count) != Some(history_count)
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "application.complete_history_join",
            "terminal K inventory does not exactly cover committed plus prepared application P history",
        ));
    }
    validate_anchor_successor_pk_join_v0(&child, &history)?;
    validate_anchor_successor_pk_join_v0(&grandchild, &history)?;

    let high_qc_path = reconstruct_high_qc_path_v0(
        high_qc,
        safety.locked_qc().qc_ref(),
        finalized,
        anchor.proof().finalized_block().header().id(),
        anchor.proof().finalized_block().header().view(),
        anchor.proof().grandchild().header().id(),
        &committed,
        &history,
    )?;

    let watermark = recover_try!("watermark.open", open_watermark(&paths.watermark));
    let signer_profile = recover_try!(
        "signer.profile",
        SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            MAXIMUM_SIGNER_INTENTS_V0,
            MAXIMUM_SIGNER_INTENT_BYTES_V0,
            MAXIMUM_SIGNER_DATABASE_BYTES_V0,
        )
    );
    let mut signer = recover_try!(
        "signer.pin_existing",
        SqliteSignerJournalV0::pin_existing_v0(&paths.signer, signer_profile, watermark)
    );
    let signer_facts = recover_try!(
        "signer.confirm_external_exact",
        signer.confirm_node_checkpoint_head_exact_v0()
    );
    if signer_facts.pending_intent().is_some()
        || !signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer)
        || signer_facts
            .capacity()
            .maximum_safety_revision()
            .is_some_and(|revision| revision > safety_facts.revision_v0())
        || signer_facts.capacity().maximum_vote_view()
            != safety.last_voted_view().map(|view| view.get())
        || signer_facts.capacity().maximum_timeout_view()
            != safety.last_timeout_view().map(|view| view.get())
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "signer.clean_cut",
            "pinned signer is not one exact external-watermark clean cut",
        ));
    }

    let mut checkpoint_store = recover_try!(
        "checkpoint.open_existing",
        SqliteExternalNodeCheckpointStoreV0::open_existing(&paths.checkpoint)
    );
    let checkpoint = recover_try!(
        "checkpoint.load",
        checkpoint_store.load(signer_facts.exact_watermark().scope())
    )
    .ok_or_else(|| {
        PocoNodeDeployedLabRecoveryErrorV0::message(
            "checkpoint.missing",
            "whole-node checkpoint is absent",
        )
    })?;
    validate_checkpoint_join_v0(
        checkpoint,
        &safety_facts,
        &signer_facts,
        &application,
        &committed,
        &validation_store,
        &history,
    )?;
    let observed = recover_try!(
        "checkpoint.fresh_readback",
        checkpoint_store.load(checkpoint.scope())
    );
    if observed != Some(checkpoint) {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "checkpoint.changed",
            "whole-node checkpoint changed during recovery readback",
        ));
    }
    let successor_bundle = recover_try!(
        "core.anchor_successor_bundle",
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &core_config,
            safety,
            child.clone(),
            grandchild.clone(),
            &StrictEd25519Verifier,
        )
    );
    let recovery_session = recover_try!(
        "core.anchor_ordinary_recovery",
        Core::begin_state_sync_anchor_ordinary_recovery_v0(
            core_config.clone(),
            safety.clone(),
            successor_bundle,
            &StrictEd25519Verifier,
        )
    );
    let mut reconciler = ExactDeployedAnchorOrdinaryReconcilerV0 {
        expected_safety: safety.clone(),
        expected_child: child,
        expected_grandchild: grandchild,
        calls: 0,
    };
    let activation = recover_try!(
        "core.anchor_ordinary_reconcile",
        recovery_session.reconcile_and_activate_v0(&mut reconciler, &StrictEd25519Verifier)
    );
    let startup_effects_match = if safety.revision() == 5 {
        matches!(
            activation.effects(),
            [Effect::ArmViewTimer { epoch, view }]
                if *epoch == safety.epoch() && *view == safety.current_view()
        )
    } else {
        activation.effects().is_empty()
    };
    if reconciler.calls != 1 || !startup_effects_match || activation.core().safety_state() != safety
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "core.anchor_ordinary_effects",
            "anchored ordinary recovery did not reproduce the exact inert Core and revision-specific suppressed effects",
        ));
    }
    let (core, suppressed_startup_effects) = activation.into_parts_v0();
    let final_safety = recover_try!("safety.final_readback", safety_store.head());
    let final_application = recover_try!(
        "application.final_readback",
        application.confirmed_committed_head_v0()
    );
    if final_safety.state() != core.safety_state()
        || final_safety.revision() != safety_facts.revision_v0()
        || final_application != committed
        || recover_try!(
            "validation.final_sequence",
            validation_store.durable_sequence_v0()
        ) != terminal_audit.store_sequence_v0()
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "terminal.changed",
            "one durable namespace changed during the recovery join",
        ));
    }

    let replay_bindings = high_qc_path
        .iter()
        .map(|block| {
            history
                .get(&block.block_id)
                .expect("validated high-QC path retains every binding")
                .binding
                .clone()
        })
        .collect::<Vec<_>>();
    let required_blocks = high_qc_path
        .iter()
        .copied()
        .filter(|block| block.height > 3)
        .collect();
    let replay_challenge = PocoNodeDeployedLabSignedAncestryReplayChallengeV0 {
        anchor_proof_id: anchor.proof_id(),
        anchor_h3_block_id: anchor.proof().grandchild().header().id(),
        safety_revision: safety_facts.revision_v0(),
        safety_chain_checksum: safety_facts.chain_checksum_v0(),
        finalized_block_id: finalized.block_id(),
        finalized_height: finalized.height().get(),
        high_qc,
        locked_qc: safety.locked_qc().qc_ref(),
        current_view: safety.current_view(),
        required_blocks,
    };
    let application_history_rows = history
        .into_values()
        .map(|retained| retained.history_row)
        .collect();
    let facts = PocoNodeDeployedLabRecoveryFactsV0 {
        checkpoint,
        local_validator: core_config.local_validator(),
        current_view: core.safety_state().current_view(),
        high_qc,
        finalized_block_id: finalized.block_id(),
        finalized_height: finalized.height().get(),
        application_applied_block_id: applied.block_id(),
        application_applied_height: applied.height().get(),
        application_commit_sequence: application_recovery.watermarks().application_commit(),
        safety_revision: safety_facts.revision_v0(),
        safety_state_record_checksum: safety_facts.state_record_checksum_v0(),
        safety_chain_checksum: safety_facts.chain_checksum_v0(),
        signer_exact_watermark: signer_facts.exact_watermark(),
        proposal_validation_sequence: terminal_audit.store_sequence_v0(),
        proposal_validation_terminal_rows: terminal_audit.terminal_row_count_v0(),
        committed_application_records: committed_count,
        prepared_application_records: prepared_count,
        application_history_records: history_count,
        high_qc_replay_path: high_qc_path,
    };
    Ok(PocoNodeDeployedLabOrdinaryRecoveryOwnerV0 {
        facts,
        replay_challenge,
        _core: core,
        _suppressed_startup_effects: suppressed_startup_effects,
        _safety_store: safety_store,
        _application: application,
        _signer: signer,
        _checkpoint_store: checkpoint_store,
        _validation_store: validation_store,
        _application_history_rows: application_history_rows,
        _replay_bindings: replay_bindings,
    })
}

pub(super) fn reconstruct_empty_anchor_successor_v0(
    certified: &CertifiedHeaderV0,
    validator_set: &trnm_consensus_types::ValidatorSet,
    consensus_parameters: &trnm_consensus_types::ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
) -> Result<SignedProposalV0, PocoNodeDeployedLabRecoveryErrorV0> {
    let payload = recover_try!(
        "core.anchor_empty_payload",
        ApplicationPayloadV0::new(Vec::new())
    );
    let payload_bytes = recover_try!("core.anchor_empty_payload_encode", payload.try_cev0_bytes());
    let block = recover_try!(
        "core.anchor_empty_block",
        Block::new(certified.header().clone(), payload_bytes, Vec::new(),)
    );
    let proposal = recover_try!(
        "core.anchor_signed_proposal",
        SignedProposalV0::new(
            block,
            certified.witness().clone(),
            validator_set,
            None,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
    );
    Ok(proposal)
}

fn validate_anchor_successor_pk_join_v0(
    proposal: &SignedProposalV0,
    history: &BTreeMap<BlockId, RecoveredHistoryKV0>,
) -> Result<(), PocoNodeDeployedLabRecoveryErrorV0> {
    let header = proposal.block().header();
    let retained = history.get(&header.id()).ok_or_else(|| {
        PocoNodeDeployedLabRecoveryErrorV0::message(
            "validation.anchor_successor_missing",
            "one proof-named anchored successor lacks an exact P/K history row",
        )
    })?;
    let binding = &retained.binding;
    let commitments = binding.commitments();
    if binding.route() != ProposalRouteV0::Synced
        || binding.block_id().as_bytes() != header.id().as_bytes()
        || binding.parent().block_id().as_bytes() != header.parent_id().as_bytes()
        || binding.height().get() != header.height().get()
        || binding.view() != header.view().get()
        || binding.timestamp_ms() != header.timestamp_ms()
        || binding.active_validator_set_id().as_bytes() != header.validator_set_id().as_bytes()
        || commitments.payload_root().as_bytes() != header.payload_root().as_bytes()
        || commitments.post_state_root().as_bytes() != header.state_root().as_bytes()
        || commitments.receipts_root().as_bytes() != header.receipts_root().as_bytes()
        || commitments.evidence_root().as_bytes() != header.evidence_root().as_bytes()
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "validation.anchor_successor_join",
            "proof-named anchored successor body differs from its exact terminal K and durable P",
        ));
    }
    Ok(())
}

fn recoverable_clean_transition_v0(
    safety: &SafetyState,
    context: &SafetyTransitionContextV0,
) -> bool {
    matches!(
        (safety.revision(), context),
        (
            5,
            SafetyTransitionContextV0::StateSyncAnchorOrdinaryPromotion(_)
        ) | (6.., SafetyTransitionContextV0::Ordinary)
            | (6.., SafetyTransitionContextV0::NativeFinalizationApplied(_))
    )
}

fn validate_context_v0(
    core: &CoreConfig,
    application: &NativeApplicationConfigV0,
) -> Result<(), PocoNodeDeployedLabRecoveryErrorV0> {
    if core.authenticated_genesis_application_parent_v0().is_some()
        || application.validator_set_v0() != core.validator_set()
        || application.consensus_parameters_v0() != core.consensus_parameters()
        || application.chain_id_v0() != core.validator_set().chain_id().as_str()
        || application.genesis_hash_v0() != *core.validator_set().genesis_hash().as_bytes()
        || application.initial_block_id_v0() != *core.genesis_block_id().as_bytes()
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "context",
            "Core and native application configurations differ",
        ));
    }
    Ok(())
}

pub(super) fn existing_paths_v0(
    root: &Path,
) -> Result<AuthorityPathsV0, PocoNodeDeployedLabRecoveryErrorV0> {
    let metadata = recover_try!("filesystem.root_metadata", fs::symlink_metadata(root));
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "filesystem.root",
            "authority root is not one non-symlink 0700 directory",
        ));
    }
    let root = recover_try!("filesystem.root_canonicalize", root.canonicalize());
    let expected = [
        "application",
        "checkpoint",
        "signer",
        "source-safety",
        "target-safety",
        "validation",
        "watermark",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let observed = recover_try!("filesystem.root_inventory", fs::read_dir(&root))
        .map(|entry| {
            entry
                .map_err(|error| {
                    PocoNodeDeployedLabRecoveryErrorV0::from_debug("filesystem.root_entry", error)
                })
                .and_then(|entry| {
                    entry.file_name().into_string().map_err(|_| {
                        PocoNodeDeployedLabRecoveryErrorV0::message(
                            "filesystem.root_entry",
                            "authority namespace name is not UTF-8",
                        )
                    })
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "filesystem.root_inventory",
            "authority root does not contain exactly the seven deployed namespaces",
        ));
    }
    let path = |namespace: &'static str, filename: &'static str| {
        let parent = root.join(namespace);
        let metadata = fs::symlink_metadata(&parent).map_err(|error| {
            PocoNodeDeployedLabRecoveryErrorV0::from_debug(
                "filesystem.namespace_metadata",
                (namespace, error),
            )
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            || parent.canonicalize().ok().as_deref() != Some(parent.as_path())
        {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "filesystem.namespace",
                "deployed authority namespace is not one canonical non-symlink 0700 directory",
            ));
        }
        Ok(parent.join(filename))
    };
    // Source Safety is deliberately not opened: its h1 commissioning owner was
    // retired before ordinary activation.  Its namespace identity is still
    // required so a partial/fresh commissioning tree cannot masquerade as a
    // recoverable ordinary root.
    let source_safety = path("source-safety", "safety.sqlite3")?;
    let source_metadata = recover_try!(
        "filesystem.source_safety_metadata",
        fs::symlink_metadata(&source_safety)
    );
    if source_metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "filesystem.source_safety",
            "retired source Safety database is not one private regular file",
        ));
    }
    Ok(AuthorityPathsV0 {
        target_safety: path("target-safety", "safety.sqlite3")?,
        signer: path("signer", "signer.sqlite3")?,
        application: path("application", "application.sqlite3")?,
        checkpoint: path("checkpoint", "checkpoint.sqlite3")?,
        validation: path("validation", "validation.sqlite3")?,
        watermark: path("watermark", "signer-watermark.v1")?,
    })
}

pub(super) fn validate_binding_context_v0(
    binding: &ProposalValidationBindingV0,
    core: &CoreConfig,
) -> Result<(), PocoNodeDeployedLabRecoveryErrorV0> {
    if binding.chain_id().as_str() != core.validator_set().chain_id().as_str()
        || binding.genesis_hash().as_bytes() != core.validator_set().genesis_hash().as_bytes()
        || binding.active_validator_set_id().as_bytes() != core.validator_set().id().as_bytes()
        || binding.height().get() == 0
        || binding.view() == 0
        || binding.timestamp_ms() == 0
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "validation.binding_context",
            "terminal K binding differs from the recovered consensus context",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reconstruct_high_qc_path_v0(
    high_qc: QcRef,
    locked_qc: QcRef,
    finalized: trnm_consensus_core::FinalizedTip,
    anchor_h1_block_id: BlockId,
    anchor_h1_view: View,
    anchor_h3_block_id: BlockId,
    committed: &ApplicationHeadV0,
    history: &BTreeMap<BlockId, RecoveredHistoryKV0>,
) -> Result<Vec<PocoNodeDeployedLabReplayBlockV0>, PocoNodeDeployedLabRecoveryErrorV0> {
    let mut reversed = Vec::new();
    let mut cursor_id = high_qc.block_id();
    let mut cursor_height = high_qc.height().get();
    while cursor_height > 1 {
        let retained = history.get(&cursor_id).ok_or_else(|| {
            PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.missing_k",
                "Safety high-QC path is missing one terminal application P/K row",
            )
        })?;
        let binding = &retained.binding;
        let expected_status = if cursor_height <= committed.height().get() {
            DurableExecutionHistoryStatusV0::Committed
        } else {
            DurableExecutionHistoryStatusV0::Prepared
        };
        if binding.height().get() != cursor_height
            || retained.application_head.block_id().as_bytes() != cursor_id.as_bytes()
            || retained.status != expected_status
            || (cursor_height == committed.height().get()
                && cursor_id.as_bytes() != committed.block_id().as_bytes())
        {
            return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.coordinate",
                "high-QC replay coordinate differs from its terminal K binding",
            ));
        }
        reversed.push(PocoNodeDeployedLabReplayBlockV0 {
            block_id: cursor_id,
            parent_block_id: BlockId::new(*binding.parent().block_id().as_bytes()),
            height: cursor_height,
            view: View::new(binding.view()),
            timestamp_ms: binding.timestamp_ms(),
            post_state_root: StateRoot::new(*binding.commitments().post_state_root().as_bytes()),
        });
        cursor_id = BlockId::new(*binding.parent().block_id().as_bytes());
        cursor_height = cursor_height.checked_sub(1).ok_or_else(|| {
            PocoNodeDeployedLabRecoveryErrorV0::message(
                "replay.height",
                "high-QC replay height underflowed",
            )
        })?;
    }
    if cursor_id != anchor_h1_block_id
        || reversed
            .first()
            .is_none_or(|tip| tip.block_id != high_qc.block_id())
        || reversed
            .first()
            .is_some_and(|tip| tip.view != high_qc.view())
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "replay.anchor",
            "high-QC P/K path does not terminate at the authenticated h1 base",
        ));
    }
    reversed.reverse();
    let matches_coordinate = |block_id: BlockId, height: u64, view: View| {
        if height == 1 {
            block_id == anchor_h1_block_id && view == anchor_h1_view
        } else {
            reversed.iter().any(|block| {
                block.block_id == block_id && block.height == height && block.view == view
            })
        }
    };
    if reversed
        .iter()
        .find(|block| block.height == 3)
        .is_none_or(|block| block.block_id != anchor_h3_block_id)
        || !matches_coordinate(
            finalized.block_id(),
            finalized.height().get(),
            finalized.view(),
        )
        || !matches_coordinate(
            locked_qc.block_id(),
            locked_qc.height().get(),
            locked_qc.view(),
        )
    {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "replay.safety_anchors",
            "terminal P/K ancestry does not cover exact h3, finalized, and locked-QC coordinates",
        ));
    }
    Ok(reversed)
}

pub(super) fn validate_checkpoint_join_v0(
    checkpoint: ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
    committed: &ApplicationHeadV0,
    validation_store: &SqliteProposalValidationStoreV0,
    history: &BTreeMap<BlockId, RecoveredHistoryKV0>,
) -> Result<(), PocoNodeDeployedLabRecoveryErrorV0> {
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
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "checkpoint.owner_join",
            "whole-node checkpoint differs from exact Safety or signer heads",
        ));
    }

    let app_config = application.config_v0();
    let expected_committed_owner = hash_v0(
        b"trnm.poco-node.lab-finalization.application-owner.v0",
        &[
            app_config.chain_id_v0().as_bytes(),
            &app_config.genesis_hash_v0(),
            &app_config.store_id(),
            &app_config.chain_descriptor_hash_v0(),
        ],
    );
    let expected_committed_head_row = application_head_checksum_v0(
        b"trnm.poco-node.lab-finalization.checkpoint-head.v0",
        committed,
    );
    let finalization_profile = hash_v0(
        b"trnm.poco-node.lab-finalization.application-profile.v0",
        &[b"committed-finalization"],
    );
    let timeout_profile = hash_v0(
        b"trnm.poco-node.lab-timeout-rebase.application-profile.v0",
        &[
            b"committed-application-anchor",
            b"retained-selected-high-qc-path",
        ],
    );
    let committed_match = fields.application_host_config_ref == expected_committed_owner
        && matches!(
            fields.application_projection_profile_ref,
            value if value == finalization_profile || value == timeout_profile
        )
        && fields.application_committed_head_row_checksum == expected_committed_head_row
        && fields.application_block_id.as_bytes() == committed.block_id().as_bytes()
        && fields.application_height == committed.height().get()
        && fields.application_state_root.as_bytes() == committed.state_root().as_bytes()
        && fields.application_view == safety.state_v0().application_applied().view().get()
        && fields.application_timestamp_ms
            == safety.state_v0().application_applied().timestamp_ms();

    let validation_scope = validation_store.scope_v0();
    let validation_store_id = validation_store.store_id_v0();
    let prepared_matches = history
        .values()
        .filter(|retained| {
            if retained.status != DurableExecutionHistoryStatusV0::Prepared {
                return false;
            }
            let genesis_hash = retained.binding.genesis_hash();
            let parts = [
                validation_scope.as_bytes().as_slice(),
                validation_store_id.as_slice(),
                retained.binding.chain_id().as_str().as_bytes(),
                genesis_hash.as_bytes().as_slice(),
            ];
            let takeover_owner = hash_v0(
                b"trnm.poco-node.anchor-successor.checkpoint.owner.v0",
                &parts,
            );
            let takeover_profile = hash_v0(
                b"trnm.poco-node.anchor-successor.checkpoint.profile.v0",
                &[
                    b"proposal-validation-schema-3",
                    b"anchored-synced-terminal-k",
                ],
            );
            let native_owner = hash_v0(b"trnm.native-k-checkpoint.application-owner.v0", &parts);
            let native_profile = hash_v0(
                b"trnm.native-k-checkpoint.projection-profile.v0",
                &[b"proposal-validation-schema-3", b"terminal-k"],
            );
            ((fields.application_host_config_ref == takeover_owner
                && fields.application_projection_profile_ref == takeover_profile)
                ^ (fields.application_host_config_ref == native_owner
                    && fields.application_projection_profile_ref == native_profile))
                && fields.application_committed_head_row_checksum
                    == retained.validation_row_checksum
                && fields.application_block_id.as_bytes() == retained.binding.block_id().as_bytes()
                && fields.application_height == retained.binding.height().get()
                && fields.application_state_root.as_bytes()
                    == retained.binding.commitments().post_state_root().as_bytes()
                && fields.application_view == retained.binding.view()
                && fields.application_timestamp_ms == retained.binding.timestamp_ms()
        })
        .count();
    if !matches!((committed_match, prepared_matches), (true, 0) | (false, 1)) {
        return Err(PocoNodeDeployedLabRecoveryErrorV0::message(
            "checkpoint.application_join",
            "checkpoint application projection is absent, ambiguous, or forged",
        ));
    }
    Ok(())
}

fn application_head_checksum_v0(domain: &[u8], head: &ApplicationHeadV0) -> [u8; 32] {
    hash_v0(
        domain,
        &[
            &head.height().get().to_be_bytes(),
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ],
    )
}

fn signed_replay_challenge_sha256_v0(
    challenge: &PocoNodeDeployedLabSignedAncestryReplayChallengeV0,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-node.deployed-lab.signed-replay-challenge.v0");
    let high_qc_id = challenge.high_qc.qc_digest();
    let locked_qc_id = challenge.locked_qc.qc_digest();
    for part in [
        challenge.anchor_proof_id.as_bytes().as_slice(),
        challenge.anchor_h3_block_id.as_bytes().as_slice(),
        challenge.safety_chain_checksum.as_slice(),
        challenge.finalized_block_id.as_bytes().as_slice(),
        high_qc_id.as_bytes().as_slice(),
        locked_qc_id.as_bytes().as_slice(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    for scalar in [
        challenge.safety_revision,
        challenge.finalized_height,
        challenge.high_qc.view().get(),
        challenge.high_qc.height().get(),
        challenge.locked_qc.view().get(),
        challenge.locked_qc.height().get(),
        challenge.current_view.get(),
        u64::try_from(challenge.required_blocks.len()).unwrap_or(u64::MAX),
    ] {
        hasher.update(scalar.to_be_bytes());
    }
    for block in &challenge.required_blocks {
        hasher.update(block.block_id.as_bytes());
        hasher.update(block.parent_block_id.as_bytes());
        hasher.update(block.height.to_be_bytes());
        hasher.update(block.view.get().to_be_bytes());
        hasher.update(block.timestamp_ms.to_be_bytes());
        hasher.update(block.post_state_root.as_bytes());
    }
    hasher.finalize().into()
}

pub(super) fn hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

#[cfg(all(test, feature = "lab-validator-runtime-test-support"))]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;
    use trnm_consensus_core::leader_for;
    use trnm_consensus_signer_journal::{
        ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignatureProducerV0,
        SignatureRequestV0, SignerWatermarkV0,
    };
    use trnm_consensus_types::{
        BlockHeader, BlockKind, EvidenceRoot, Height, PayloadDigest, ProposalWitnessV0,
        QuorumCertificate, ReceiptsRoot, SignatureBytes, Vote,
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct SharedWatermarkV0 {
        value: Arc<Mutex<Option<SignerWatermarkV0>>>,
    }

    impl ExternalMonotonicWatermarkV0 for SharedWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = *self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut value = self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if *value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(previous)
                    if previous.scope() == target.scope()
                        && previous.journal_id() == target.journal_id()
                        && previous.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            *value = Some(target);
            Ok(())
        }
    }

    struct ExactProducerV0(SigningKey);

    impl SignatureProducerV0 for ExactProducerV0 {
        fn sign(
            &mut self,
            request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            Ok(SignatureBytes::from_array(
                self.0.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    #[test]
    fn fresh_revision_five_cut_reopens_only_as_exact_replay_fenced_owner_v0() {
        let result = std::thread::Builder::new()
            .name("deployed-lab-recovery-exact-cut".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(assert_fresh_revision_five_cut_reopens_only_as_exact_replay_fenced_owner_v0)
            .expect("spawn bounded large-stack deployed recovery test")
            .join();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn assert_fresh_revision_five_cut_reopens_only_as_exact_replay_fenced_owner_v0() {
        let directory = tempdir().expect("create recovery test root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect recovery test root");
        let watermark = SharedWatermarkV0::default();
        let bundle = crate::commission_native_h1_ordinary_lab_test_bundle_v0(
            directory.path(),
            watermark.clone(),
            4,
            0,
        )
        .expect("commission exact deployed h1-h3 test cut");
        let (core_config, application_config, runtime) = bundle.into_recovery_test_parts_v0();
        let live = runtime.phase_facts_v0();
        assert_eq!(live.safety_revision_v0(), 5);
        assert_eq!(live.finalized_height_v0(), 1);
        assert_eq!(live.high_qc_v0().height().get(), 3);
        drop(runtime);

        let recovered = reopen_deployed_lab_ordinary_cut_v0(
            directory.path(),
            core_config,
            application_config,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(watermark),
        )
        .expect("reopen exact revision-five cut");
        let facts = recovered.facts_v0();
        assert_eq!(facts.safety_revision_v0(), 5);
        assert_eq!(facts.finalized_height_v0(), 1);
        assert_eq!(facts.application_applied_height_v0(), 1);
        assert_eq!(facts.high_qc_v0().height().get(), 3);
        assert_eq!(facts.committed_application_records_v0(), 0);
        assert_eq!(facts.prepared_application_records_v0(), 2);
        assert_eq!(facts.application_history_records_v0(), 2);
        assert_eq!(facts.proposal_validation_sequence_v0(), 6);
        assert_eq!(facts.proposal_validation_terminal_rows_v0(), 2);
        assert_eq!(
            facts
                .high_qc_replay_path_v0()
                .iter()
                .map(|block| block.height_v0())
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        let challenge = recovered.signed_ancestry_replay_challenge_v0();
        assert_eq!(challenge.safety_revision_v0(), 5);
        assert_eq!(
            challenge.anchor_h3_block_id_v0(),
            facts.high_qc_v0().block_id()
        );
        assert!(!challenge.requires_signed_ancestry_replay_v0());
        assert!(challenge.required_blocks_v0().is_empty());
    }

    #[test]
    fn revision_greater_than_five_reopens_only_with_signed_ancestry_challenge_v0() {
        let result = std::thread::Builder::new()
            .name("deployed-lab-recovery-post-h4-cut".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(assert_revision_greater_than_five_reopens_only_with_signed_ancestry_challenge_v0)
            .expect("spawn bounded large-stack post-h4 recovery test")
            .join();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn assert_revision_greater_than_five_reopens_only_with_signed_ancestry_challenge_v0() {
        let directory = tempdir().expect("create post-h4 recovery test root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect post-h4 recovery test root");
        let watermark = SharedWatermarkV0::default();
        // The canonical takeover enters view four, whose round-robin leader is
        // validator index three in this four-member fixture.
        let bundle = crate::commission_native_h1_ordinary_lab_test_bundle_v0(
            directory.path(),
            watermark.clone(),
            4,
            3,
        )
        .expect("commission exact deployed h1-h3 post-h4 fixture");
        let validator_set = bundle.validator_set_v0().clone();
        let parameters = *bundle.consensus_parameters_v0();
        let height = bundle.ordinary_start_height_v0();
        let timestamp_ms = 400;
        let transactions = bundle
            .ordinary_transactions_v0(height, timestamp_ms)
            .expect("author exact h4 application transaction");
        let binding = bundle
            .runtime_v0()
            .proposal_binding_v0()
            .expect("read exact h4 proposal binding");
        let (parent, preview) = bundle
            .runtime_v0()
            .preview_next_nonempty_v0(transactions.clone(), timestamp_ms)
            .expect("preview exact h4 transition");
        let payload = ApplicationPayloadV0::new(transactions).expect("construct h4 payload");
        assert_eq!(
            payload
                .payload_root()
                .expect("derive h4 payload root")
                .as_bytes(),
            preview.payload_root().as_bytes()
        );
        let proposer = leader_for(&validator_set, binding.current_view_v0());
        assert_eq!(proposer, bundle.local_validator_v0());
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            binding.current_view_v0(),
            Height::new(height),
            BlockKind::Regular,
            BlockId::new(*parent.application_head_v0().block_id().as_bytes()),
            proposer,
            validator_set.id(),
            parameters.hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            timestamp_ms,
            None,
        )
        .expect("construct exact h4 header");
        let block = Block::new(
            header,
            payload.try_cev0_bytes().expect("encode exact h4 payload"),
            Vec::new(),
        )
        .expect("construct exact h4 block");
        let proposal_root =
            ProposalWitnessV0::signing_root_for(block.header(), binding.high_qc_v0(), None, None)
                .expect("derive exact h4 proposal root");
        let witness = ProposalWitnessV0::new(
            block.header(),
            binding.high_qc_v0().clone(),
            None,
            None,
            bundle
                .sign_consensus_root_v0(proposer, proposal_root)
                .expect("sign exact h4 proposal root"),
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("construct exact h4 proposal witness");
        let proposal = SignedProposalV0::new(
            block,
            witness,
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("construct exact signed h4 proposal");
        let replay_proposal = proposal.clone();
        let h4_id = proposal.block().id();
        let votes = validator_set
            .validators()
            .iter()
            .map(|validator| {
                let root = Vote::signing_root_for_set(
                    &validator_set,
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    h4_id,
                )
                .expect("derive exact h4 Vote root");
                Vote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    h4_id,
                    validator_set.id(),
                    validator.id(),
                    bundle
                        .sign_consensus_root_v0(validator.id(), root)
                        .expect("sign exact h4 Vote root"),
                    &validator_set,
                )
                .expect("construct exact h4 Vote")
            })
            .collect::<Vec<_>>();
        let h4_qc = QuorumCertificate::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            proposal.block().header().view(),
            proposal.block().header().height(),
            h4_id,
            validator_set.id(),
            votes,
            &validator_set,
        )
        .expect("construct exact h4 QC");
        let mut producer = ExactProducerV0(bundle.signing_key_v0().clone());
        let (core_config, application_config, reopen_application_config, runtime) =
            bundle.into_reopen_test_parts_v0();
        let signed = runtime
            .drive_one_to_inert_request_v0(proposal)
            .expect("drive exact h4 through P/D/C/K")
            .sign_exact_vote_v0(&mut producer)
            .expect("journal and release exact local h4 Vote");
        let mut advance = signed
            .advance_quorum_certificate_v0(h4_qc.clone())
            .expect("advance exact h4 QC");
        let runtime = loop {
            match advance {
                crate::PocoNodeLabCertificateAdvanceV0::Ready(runtime) => break *runtime,
                crate::PocoNodeLabCertificateAdvanceV0::PendingFinalization(owner) => {
                    advance = owner
                        .apply_and_ack_finalization_v0()
                        .expect("apply exact post-h4 finalization")
                }
            }
        };
        let live = runtime.phase_facts_v0();
        assert!(live.safety_revision_v0() > 5);
        assert_eq!(live.high_qc_v0().block_id(), h4_id);
        assert!(live.finalized_height_v0() >= 2);
        assert_eq!(
            live.application_applied_height_v0(),
            live.finalized_height_v0()
        );

        // The h4 QC drives the three-chain finalization of the older
        // finalized tip (h4 itself remains the high-QC/speculative head).
        // Exercise the real Ready-runtime query boundary against the native
        // P row committed by `apply_and_ack_finalization_v0`, rather than the
        // h1-h3 trusted-base fixture which intentionally has no committed P.
        let finalized_block_id = live.finalized_block_id_v0();
        let finalized_height = live.finalized_height_v0();
        let finalized_proof = runtime
            .finalized_proof_v0()
            .expect("expose the exact post-h4 finalized proof");
        assert_eq!(finalized_proof.finalized_block_id_v0(), finalized_block_id);
        assert_eq!(finalized_proof.finalized_height_v0(), finalized_height);
        let by_block = runtime
            .read_finalized_by_block_id_v0(finalized_block_id)
            .expect("read the committed finalized P row by proof-named BlockId");
        assert_eq!(by_block.proof_v0(), &finalized_proof);
        let by_block_head = by_block
            .read_v0()
            .finalized_head_v0()
            .expect("decode the committed finalized application head");
        assert_eq!(by_block_head.height().get(), finalized_height);
        assert_eq!(
            by_block_head.block_id().as_bytes(),
            finalized_block_id.as_bytes()
        );
        assert_eq!(
            by_block_head.state_root().as_bytes(),
            finalized_proof.state_root_v0().as_bytes()
        );
        assert_eq!(
            by_block.read_v0().receipts_root_v0().as_bytes(),
            finalized_proof.receipts_root_v0().as_bytes()
        );
        let by_height = runtime
            .read_finalized_by_height_v0(finalized_height)
            .expect("read the same committed finalized P row by height");
        assert_eq!(by_height.proof_v0(), by_block.proof_v0());
        assert_eq!(
            by_height.read_v0().durable_row_v0().p_digest_v0(),
            by_block.read_v0().durable_row_v0().p_digest_v0()
        );
        assert!(runtime
            .install_and_recover_finalization_intent_marker_for_test_v0()
            .expect("exact finalization intent readback"));
        drop(runtime);

        let first_core_config = core_config.clone();
        let recovered = reopen_deployed_lab_ordinary_cut_v0(
            directory.path(),
            core_config,
            application_config,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(watermark.clone()),
        )
        .expect("reopen exact post-h4 ordinary cut");
        let facts = recovered.facts_v0().clone();
        assert!(facts.safety_revision_v0() > 5);
        assert_eq!(facts.high_qc_v0().block_id(), h4_id);
        assert_eq!(facts.finalized_height_v0(), live.finalized_height_v0());
        assert_eq!(
            facts.application_applied_height_v0(),
            facts.finalized_height_v0()
        );
        assert_eq!(facts.committed_application_records_v0(), 1);
        assert_eq!(facts.prepared_application_records_v0(), 2);
        assert_eq!(facts.application_history_records_v0(), 3);
        assert_eq!(facts.proposal_validation_sequence_v0(), 9);
        assert_eq!(
            facts
                .high_qc_replay_path_v0()
                .iter()
                .map(|block| block.height_v0())
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        let challenge = recovered.signed_ancestry_replay_challenge_v0();
        assert!(challenge.requires_signed_ancestry_replay_v0());
        assert_eq!(challenge.required_blocks_v0().len(), 1);
        assert_eq!(challenge.required_blocks_v0()[0].block_id_v0(), h4_id);
        assert_eq!(challenge.required_blocks_v0()[0].height_v0(), 4);
        let authenticated = recovered
            .authenticate_signed_ancestry_replay_v0(vec![
                PocoNodeDeployedLabSignedReplayEntryV0::new(replay_proposal, h4_qc),
            ])
            .expect("authenticate exact signed h4 replay without releasing runtime");
        assert_eq!(authenticated.facts_v0().authenticated_block_count_v0(), 1);
        assert_eq!(
            authenticated.facts_v0().terminal_certificate_id_v0(),
            live.high_qc_v0().qc_digest()
        );
        assert_eq!(authenticated.signed_replay_v0().len(), 1);
        assert_ne!(authenticated.facts_v0().challenge_sha256_v0(), [0; 32]);

        // A second fresh host must observe the same committed application and
        // checkpoint heads after the first recovery owner is dropped.  This
        // is the bounded duplicate-apply/restart assertion for the real
        // native P/D/C/K -> finalization path: reopening is read-only and
        // cannot create a second committed application row.
        drop(authenticated);
        let reopened_again = reopen_deployed_lab_ordinary_host_v0(
            directory.path(),
            first_core_config,
            reopen_application_config,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(watermark),
        )
        .expect("second fresh reopen of the exact post-h4 ordinary cut");
        assert_eq!(reopened_again.facts_v0(), &facts);
    }

    #[test]
    fn host_reopen_detects_external_checkpoint_tamper_after_core_recovery_v0() {
        let result = std::thread::Builder::new()
            .name("deployed-lab-host-reopen-checkpoint-tamper".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(assert_host_reopen_detects_external_checkpoint_tamper_after_core_recovery_v0)
            .expect("spawn bounded large-stack host reopen test")
            .join();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn assert_host_reopen_detects_external_checkpoint_tamper_after_core_recovery_v0() {
        let directory = tempdir().expect("create host reopen test root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect host reopen test root");
        let watermark = SharedWatermarkV0::default();
        let bundle = crate::commission_native_h1_ordinary_lab_test_bundle_v0(
            directory.path(),
            watermark.clone(),
            4,
            0,
        )
        .expect("commission exact deployed h1-h3 host reopen cut");
        let (core_config, application_config, reopen_application_config, runtime) =
            bundle.into_reopen_test_parts_v0();
        drop(runtime);

        let first_watermark = watermark.clone();
        let first_host = reopen_deployed_lab_ordinary_host_v0(
            directory.path(),
            core_config.clone(),
            application_config,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(first_watermark),
        )
        .expect("open exact cut through the host recovery boundary");
        assert!(
            first_host.state_sync_anchor_proof_id_v0().is_some(),
            "reopened Core must retain the permanent h1 state-sync anchor"
        );
        assert_eq!(first_host.state_sync_anchor_height_v0(), Some(1));
        let expected_anchor_proof_id = first_host.state_sync_anchor_proof_id_v0();
        let expected_facts = first_host.facts_v0().clone();
        let checkpoint = expected_facts.checkpoint_v0();
        drop(first_host);

        let second_watermark = watermark.clone();
        let mut host = reopen_deployed_lab_ordinary_host_v0(
            directory.path(),
            core_config,
            reopen_application_config,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(second_watermark),
        )
        .expect("reopen the same durable cut through a fresh host");
        assert_eq!(
            host.state_sync_anchor_proof_id_v0(),
            expected_anchor_proof_id
        );
        assert_eq!(host.state_sync_anchor_height_v0(), Some(1));
        assert_eq!(host.facts_v0(), &expected_facts);
        host.revalidate_durable_boundary_v0()
            .expect("reopened host readback must match the recovered Core/checkpoint join");

        let path = directory.path().join("checkpoint/checkpoint.sqlite3");
        let mut corrupted = checkpoint.encode_canonical();
        corrupted[352] ^= 1;
        let connection = rusqlite::Connection::open(&path).expect("open checkpoint for tamper");
        assert_eq!(
            connection
                .execute(
                    "UPDATE trnm_external_node_checkpoint_v0 SET record = ?1 WHERE scope = ?2",
                    rusqlite::params![&corrupted[..], checkpoint.scope().as_slice()],
                )
                .expect("tamper only the canonical checkpoint record"),
            1
        );
        drop(connection);

        let error = host
            .revalidate_durable_boundary_v0()
            .expect_err("host must fail closed after external checkpoint tamper");
        assert_eq!(error.stage_v0(), "host.checkpoint_readback");
    }
}
