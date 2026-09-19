#![cfg(test)]

//! Actual native/Core/Safety/original signer and independent node-checkpoint
//! owners. Only the separately administered signer watermark service is a test
//! double; fixture joint signatures are authenticated public peer evidence.
use crate::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use trnm_consensus_core::{
    epoch_state_tests_v1 as core_fixture, minimum_epoch_safety_record_limits_v1,
    BlockIdOverlayRefV0, CoreConfig, EpochSafetyStateRecordContextV1,
    PreparedEpochCoreActivationV1, ValidatedPayloadArtifactRefV0,
};
use trnm_consensus_crypto::{
    verify_pre_handoff_context_strict_v1, verify_same_version_epoch_activation_authority_strict_v0,
    StrictEpochRuntimeContextV1,
};
use trnm_consensus_safety_store::{
    test_fixtures::{build_native_old_epoch_terminal_v1, NativeOldEpochTerminalFixtureV1},
    EpochSafetyHeadPinV1, EpochSafetyJournalProfileV1, SqliteEpochSafetyJournalV1,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalSignerRetirementV1, ExternalWatermarkErrorV0,
    HandoffSignerJournalProfileV1, RetiredSqliteSignerJournalV1, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0, SignerRetirementHostCutV1,
    SignerRetirementRecordV1, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_epoch_anchor_authorization_kernel_v0_exact, decode_finality_proof_v0_exact, Block,
    BlockHeader, BlockId, BlockKind, CanonicalHandoffSignIntentV1, EvidenceRoot, PayloadDigest,
    ProposalWitnessV0, QcReferenceV0, ReceiptsRoot, SignatureBytes, SignedProposalV0, StateRoot,
    View,
};
use trnm_native_execution_v0::{
    test_fixtures::native_checkpoint_fixture_config_v1, AuthenticatedEpochApplicationEdgeV1,
    DurableNativeApplicationV0,
};

type WatermarkState = (Option<SignerWatermarkV0>, Option<SignerRetirementRecordV1>);
#[derive(Clone, Default)]
struct Watermark(Arc<Mutex<WatermarkState>>, Arc<Mutex<Option<PathBuf>>>);
impl ExternalMonotonicWatermarkV0 for Watermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let s = self.0.lock().unwrap();
        if s.1.is_some() || s.0.is_some_and(|w| w.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let value = s.0;
        drop(s);
        if value.is_some_and(|w| w.sequence() == 1) {
            if let Some(path) = self.1.lock().unwrap().take() {
                let displaced = path.with_extension("displaced-before-key");
                std::fs::rename(&path, &displaced).unwrap();
                std::fs::copy(&displaced, &path).unwrap();
            }
        }
        Ok(value)
    }
    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut s = self.0.lock().unwrap();
        if s.1.is_some() || s.0 != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        s.0 = Some(target);
        Ok(())
    }
}
impl ExternalSignerRetirementV1 for Watermark {
    fn load_signer_retirement_v1(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerRetirementRecordV1>, ExternalWatermarkErrorV0> {
        let s = self.0.lock().unwrap();
        if s.0.is_some_and(|w| w.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(s.1)
    }
    fn retire_signer_exact_v1(
        &mut self,
        record: &SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
        let mut s = self.0.lock().unwrap();
        if s.1 == Some(*record) {
            return Ok(record.terminal_watermark_v1());
        }
        if s.1.is_some() || s.0 != Some(record.source_v1()) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        s.1 = Some(*record);
        Ok(record.terminal_watermark_v1())
    }
}
struct Key {
    key: SigningKey,
    calls: usize,
}
impl SignatureProducerV0 for Key {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls += 1;
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}
struct SignedOldCase {
    dir: tempfile::TempDir,
    fixture: Box<NativeOldEpochTerminalFixtureV1>,
    ordinary: SqliteSignerJournalV0<Watermark>,
    ordinary_profile: SignerJournalProfileV0,
    initial_watermark: SignerWatermarkV0,
    key: Key,
    old_watermark: Watermark,
}
fn signed_old_case() -> Box<SignedOldCase> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = native_checkpoint_fixture_config_v1();
    let profile = SignerJournalProfileV0::new(
        config.validator_set_v0().clone(),
        config.validator_set_v0().validators()[0].id(),
        [81; 32],
        [82; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let old_watermark = Watermark::default();
    let mut ordinary = SqliteSignerJournalV0::initialize_new(
        dir.path().join("original.db"),
        profile.clone(),
        old_watermark.clone(),
    )
    .unwrap();
    let initial_watermark = ordinary
        .confirm_node_checkpoint_head_exact_v0()
        .unwrap()
        .exact_watermark();
    let mut key = Key {
        key: SigningKey::from_bytes(&[20; 32]),
        calls: 0,
    };
    let fixture = Box::new(
        build_native_old_epoch_terminal_v1(&dir.path().join("chain"), |intent| {
            Ok(ordinary.sign_exact_v0(intent, &mut key)?)
        })
        .unwrap(),
    );
    assert_eq!(key.calls, 10);
    assert_eq!(fixture.sign_intents.len(), 10);
    Box::new(SignedOldCase {
        dir,
        fixture,
        ordinary,
        ordinary_profile: profile,
        initial_watermark,
        key,
        old_watermark,
    })
}

fn prepare_from_actual_terminal(
    f: &NativeOldEpochTerminalFixtureV1,
) -> (
    EpochSafetyJournalProfileV1,
    Box<PreparedEpochCoreActivationV1>,
    SignedProposalV0,
) {
    let receipt = f
        .application
        .confirm_prepared_checkpoint_execution_v1(&f.checkpoint, &f.checkpoint_execution)
        .unwrap();
    let proof = decode_finality_proof_v0_exact(
        &f.checkpoint_finality_bytes,
        receipt.old_validator_set(),
        receipt.old_parameters(),
        f.checkpoint_parent_header.timestamp_ms(),
    )
    .unwrap();
    let anchor = decode_epoch_anchor_authorization_kernel_v0_exact(
        &f.handoff_anchor_bytes,
        receipt.old_validator_set(),
        receipt.new_validator_set(),
    )
    .unwrap();
    let activation = verify_same_version_epoch_activation_authority_strict_v0(
        &proof,
        &receipt.next_epoch_commitment(),
        &anchor,
        receipt.old_validator_set(),
        receipt.old_parameters(),
        receipt.new_validator_set(),
        receipt.new_parameters(),
        &f.checkpoint_parent_header,
    )
    .unwrap();
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(activation).unwrap();
    let proposal = core_fixture::first_chain_native_fixture(&runtime, &[1])
        .into_iter()
        .next()
        .expect("first actual epoch proposal fixture")
        .0;
    let new_set = runtime.structural_context().new_validator_set();
    let config = CoreConfig::new(
        new_set.validators()[0].id(),
        new_set.clone(),
        *runtime.structural_context().new_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let row = f
        .application
        .confirm_durable_execution_history_row_v0(&f.checkpoint_execution)
        .unwrap();
    let h = f.checkpoint.header();
    let artifact = ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(h.id(), h.parent_id(), row.overlay_digest_v0()),
        row.artifact_digest_v0(),
    );
    let limits = minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
    let context =
        EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits).unwrap();
    let profile = EpochSafetyJournalProfileV1::new(f.profile.clone(), &context).unwrap();
    let (_, terminal) = f.journal.prepare_terminal_recovery_v1(f.pin).unwrap();
    (
        profile,
        Box::new(terminal.prepare_epoch_activation_v1(&context).unwrap()),
        proposal,
    )
}

struct EpochRuntimeCaseV1 {
    dir: tempfile::TempDir,
    external_path: PathBuf,
    prepared: Box<PreparedEpochCoreActivationV1>,
    journal: SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    application: DurableNativeApplicationV0,
    edge: AuthenticatedEpochApplicationEdgeV1,
    retired: RetiredSqliteSignerJournalV1<Watermark>,
    retired_checkpoint: ConfirmedRetiredEpochNodeCheckpointV1,
    ordinary: SqliteSignerJournalV0<Watermark>,
    key: Key,
    recovery: Box<RecoveryDataV1>,
}
struct RecoveryDataV1 {
    profile: EpochSafetyJournalProfileV1,
    old_watermark: Watermark,
    new_watermark: Watermark,
    context: trnm_consensus_crypto::StrictPreHandoffContextV1,
    intent: CanonicalHandoffSignIntentV1,
    preview: trnm_native_execution_v0::NativeBlockPreviewRequestV0,
    checkpoint: trnm_consensus_types::BlockHeader,
    cutoff: Vec<u8>,
    cutoff_parent: Vec<u8>,
    finality: Vec<u8>,
    anchor: Vec<u8>,
    proposal: SignedProposalV0,
}
fn build_epoch_runtime_case_v1() -> Box<EpochRuntimeCaseV1> {
    complete_epoch_runtime_case_v1(initialize_epoch_journal_case_v1(signed_old_case()))
}
struct JournalCaseV1 {
    original: Box<SignedOldCase>,
    prepared: Box<PreparedEpochCoreActivationV1>,
    journal: SqliteEpochSafetyJournalV1,
    pin: EpochSafetyHeadPinV1,
    profile: EpochSafetyJournalProfileV1,
    proposal: SignedProposalV0,
}
// Keep the retirement/composite-construction frame out of strict journal
// initialization, which deliberately revalidates the complete 14E evidence.
fn initialize_epoch_journal_case_v1(original: Box<SignedOldCase>) -> Box<JournalCaseV1> {
    let (profile, prepared, proposal) = prepare_from_actual_terminal(&original.fixture);
    let (journal, initial) = SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        original.dir.path().join("epoch9.db"),
        profile.clone(),
        &original.fixture.journal,
        original.fixture.pin,
        &prepared,
    )
    .unwrap();
    let pin = initial.pin_v1();
    Box::new(JournalCaseV1 {
        original,
        prepared,
        journal,
        pin,
        profile,
        proposal,
    })
}
fn complete_epoch_runtime_case_v1(case: Box<JournalCaseV1>) -> Box<EpochRuntimeCaseV1> {
    let JournalCaseV1 {
        original,
        prepared,
        journal,
        pin,
        profile,
        proposal,
    } = *case;
    let SignedOldCase {
        dir,
        fixture: f,
        ordinary,
        ordinary_profile,
        initial_watermark,
        key,
        old_watermark,
    } = *original;
    let safety_head = f.journal.fresh_read_v1(f.pin).unwrap();
    let origin = safety_head.migration_source_v1();
    // Real independently recorded virgin source7/ordinary-journal commissioning
    // cut, captured before the first signer callback. Legacy projection hashes
    // are comparison data, never native P or runtime activation authority.
    let predecessor = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: initial_watermark.scope(),
        generation: 0,
        predecessor_checksum: [0; 32],
        safety_journal_id: origin.journal_id_v1(),
        safety_verifier_profile_ref: origin.verifier_profile_ref_v1(),
        safety_revision: origin.revision_v1(),
        safety_state_record_checksum: origin.state_record_checksum_v1(),
        safety_record_chain_checksum: origin.chain_checksum_v1(),
        application_host_config_ref: [91; 32],
        application_projection_profile_ref: [92; 32],
        application_safety_binding_manifest_checksum: [93; 32],
        application_committed_head_row_checksum: [94; 32],
        application_recovery_closure_checksum: [95; 32],
        application_block_id: BlockId::new(f.config.initial_block_id_v0()),
        application_height: 0,
        application_state_root: StateRoot::new(f.config.initial_state_root()),
        application_view: 0,
        application_timestamp_ms: 0,
        signer_journal_id: initial_watermark.journal_id(),
        signer_profile_checksum: ordinary_profile.profile_checksum(),
        signer_exact_watermark: initial_watermark,
    })
    .unwrap();
    let external_path = dir.path().join("independent-node.db");
    let mut external = SqliteExternalNodeCheckpointStoreV0::initialize_new(&external_path).unwrap();
    external.compare_and_advance(None, predecessor).unwrap();
    let receipt = f
        .application
        .confirm_pre_handoff_checkpoint_v1(f.pre_handoff_preparation, &f.checkpoint_finality_bytes)
        .unwrap();
    let anchor = decode_epoch_anchor_authorization_kernel_v0_exact(
        &f.handoff_anchor_bytes,
        receipt.old_validator_set(),
        receipt.new_validator_set(),
    )
    .unwrap();
    let descriptor = anchor.handoff_certificate().descriptor();
    let author = receipt.old_validator_set().validators()[0].id();
    let handoff_profile = HandoffSignerJournalProfileV1::for_epoch_handoff(
        receipt.old_validator_set().clone(),
        receipt.new_validator_set().clone(),
        *receipt.old_parameters(),
        *receipt.new_parameters(),
        author,
        [81; 32],
        [83; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let context = verify_pre_handoff_context_strict_v1(
        receipt.checkpoint_finality(),
        &receipt.next_epoch_commitment(),
        descriptor,
        receipt.old_validator_set(),
        receipt.old_parameters(),
        receipt.new_validator_set(),
        receipt.new_parameters(),
        receipt.checkpoint_parent_header(),
    )
    .unwrap();
    let intent = CanonicalHandoffSignIntentV1::old_set(
        descriptor,
        receipt.old_validator_set(),
        receipt.new_validator_set(),
        receipt.old_parameters(),
        receipt.new_parameters(),
        author,
    )
    .unwrap();
    let host = SignerRetirementHostCutV1 {
        owner_generation: safety_head.owner_generation_v1(),
        native_committed_cut: receipt.committed_owner_cut_ref_v1(),
        safety_revision: safety_head.revision_v1(),
        safety_record_checksum: safety_head.state_record_checksum_v1(),
    };
    let mut retired = ordinary
        .retire_for_handoff_v1(&context, &intent, host)
        .unwrap();
    let retired_receipt = retired.confirm_retirement_v1().unwrap();
    let retired_checkpoint = confirm_retired_epoch_node_checkpoint_v1(
        external,
        predecessor,
        &f.application,
        &receipt,
        descriptor,
        &handoff_profile,
        &f.journal,
        &safety_head,
        &mut retired,
        &retired_receipt,
    )
    .unwrap();
    let new_profile = SignerJournalProfileV0::new(
        receipt.new_validator_set().clone(),
        author,
        [81; 32],
        [84; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let new_watermark = Watermark::default();
    let ordinary = SqliteSignerJournalV0::initialize_new(
        dir.path().join("new-ordinary.db"),
        new_profile,
        new_watermark.clone(),
    )
    .unwrap();
    let r = f.checkpoint_execution.request();
    let recovery = Box::new(RecoveryDataV1 {
        profile,
        old_watermark,
        new_watermark,
        context,
        intent,
        preview: trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
            r.chain_id().clone(),
            r.genesis_hash(),
            r.parent().clone(),
            r.height(),
            r.timestamp_ms(),
            r.active_validator_set_id(),
            r.transactions().to_vec(),
        )
        .unwrap(),
        checkpoint: f.checkpoint.header().clone(),
        cutoff: f.cutoff_finality_bytes.clone(),
        cutoff_parent: f.cutoff_parent_header_bytes.clone(),
        finality: f.checkpoint_finality_bytes.clone(),
        anchor: f.handoff_anchor_bytes.clone(),
        proposal: proposal.clone(),
    });
    let confirmed = f
        .application
        .confirm_poco_checkpoint_v0(
            f.checkpoint,
            &f.checkpoint_finality_bytes,
            &f.handoff_anchor_bytes,
        )
        .unwrap();
    let edge = confirmed.into_epoch_application_edge_v1().unwrap();
    drop(
        f.application
            .confirm_epoch_application_edge_v1(&edge)
            .unwrap(),
    );
    Box::new(EpochRuntimeCaseV1 {
        dir,
        external_path,
        prepared,
        journal,
        pin,
        application: f.application,
        edge,
        retired,
        retired_checkpoint,
        ordinary,
        key,
        recovery,
    })
}

#[test]
fn actual_epoch_runtime_fixture_joins_pending_safety_native_edge_and_retirement() {
    let mut case = build_epoch_runtime_case_v1();
    assert_eq!(case.key.calls, 10);
    assert!(case.external_path.is_file());
    assert!(case.dir.path().is_dir());
    assert!(case
        .retired_checkpoint
        .belongs_to_retired_owner_v1(&mut case.retired));
    drop(
        case.application
            .confirm_epoch_application_edge_v1(&case.edge)
            .unwrap(),
    );
    let safety = case
        .journal
        .confirm_exact_request_v1(
            case.pin,
            case.prepared.initial_persistence_v1(),
            &trnm_consensus_safety_store::SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    assert_eq!(safety.state_v1().application_applied().height().get(), 8);
    assert_eq!(safety.state_v1().epoch().get(), 1);
    assert_eq!(
        case.ordinary
            .confirm_node_checkpoint_head_exact_v0()
            .unwrap()
            .exact_watermark()
            .sequence(),
        0
    );
}

type LiveCaseV1 = (
    tempfile::TempDir,
    CandidateEpochRuntimeV1<Watermark, Watermark>,
    Key,
    Box<RecoveryDataV1>,
);

fn activate_actual_case_v1(case: Box<EpochRuntimeCaseV1>) -> Box<LiveCaseV1> {
    let EpochRuntimeCaseV1 {
        dir,
        prepared,
        journal,
        pin,
        application,
        edge,
        retired,
        retired_checkpoint,
        ordinary,
        key,
        recovery,
        ..
    } = *case;
    let runtime = CandidateEpochRuntimeV1::activate_continuing_v1(
        *prepared,
        journal,
        pin,
        application,
        edge,
        retired,
        retired_checkpoint,
        ordinary,
    )
    .unwrap();
    Box::new((dir, runtime, key, recovery))
}

fn native_first_proposal_v1(
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    justify: &QcReferenceV0,
    authorization: &trnm_consensus_types::EpochAnchorAuthorizationV0,
) -> SignedProposalV0 {
    let timestamp = edge
        .consensus_parent()
        .timestamp_ms()
        .checked_add(1)
        .unwrap();
    let request = edge.preview_request_v1(timestamp, Vec::new()).unwrap();
    let preview = application.preview_epoch_block_v1(edge, &request).unwrap();
    let set = edge.new_validator_set();
    let params = edge.new_parameters();
    let proposer = trnm_consensus_core::leader_for(set, View::new(1));
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(1),
        trnm_consensus_types::Height::new(edge.first_application_height()),
        BlockKind::EpochHandoff,
        edge.consensus_parent().id(),
        proposer,
        set.id(),
        params.hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        timestamp,
        None,
    )
    .unwrap();
    let root =
        ProposalWitnessV0::signing_root_for(&header, justify, None, Some(authorization)).unwrap();
    let index = set
        .validators()
        .iter()
        .position(|validator| validator.id() == proposer)
        .unwrap();
    let signature = SigningKey::from_bytes(&[20 + index as u8; 32]).sign(root.as_bytes());
    let witness = ProposalWitnessV0::new(
        &header,
        justify.clone(),
        None,
        Some(authorization.clone()),
        SignatureBytes::from_array(signature.to_bytes()),
        set,
        Some(edge.old_validator_set()),
        params,
        edge.consensus_parent().timestamp_ms(),
    )
    .unwrap();
    SignedProposalV0::new(
        Block::new(
            header,
            trnm_consensus_types::ApplicationPayloadV0::new(Vec::new())
                .unwrap()
                .try_cev0_bytes()
                .unwrap(),
            Vec::new(),
        )
        .unwrap(),
        witness,
        set,
        Some(edge.old_validator_set()),
        params,
        edge.consensus_parent().timestamp_ms(),
    )
    .unwrap()
}

fn native_epoch_descendants_v1(
    first: &BlockHeader,
    set: &trnm_consensus_types::ValidatorSet,
    params: &trnm_consensus_types::ConsensusParametersV0,
) -> [BlockHeader; 2] {
    let mut parent = first.clone();
    let mut descendants = Vec::with_capacity(2);
    for _ in 0..2 {
        let view = View::new(parent.view().get().checked_add(1).unwrap());
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            trnm_consensus_types::Height::new(parent.height().get().checked_add(1).unwrap()),
            BlockKind::Regular,
            parent.id(),
            trnm_consensus_core::leader_for(set, view),
            set.id(),
            params.hash(),
            parent.payload_root().clone(),
            parent.state_root().clone(),
            parent.receipts_root().clone(),
            parent.evidence_root().clone(),
            parent.timestamp_ms().checked_add(1).unwrap(),
            None,
        )
        .unwrap();
        parent = header.clone();
        descendants.push(header);
    }
    descendants.try_into().unwrap()
}

#[test]
fn actual_epoch_runtime_activation_releases_timer_then_persisted_timeout_once() {
    assert_activation_then_timeout_v1(activate_actual_case_v1(build_epoch_runtime_case_v1()));
}
fn assert_activation_then_timeout_v1(mut live: Box<LiveCaseV1>) {
    assert_eq!(
        live.2.calls, 10,
        "activation itself must never enter the key"
    );
    let checkpoint = live.1.confirm_initial_activation_v1().unwrap();
    assert_eq!(
        checkpoint.fields().phase,
        EpochCheckpointPhaseV1::ActivationCommitted
    );
    assert_eq!(checkpoint.fields().epoch, 1);
    assert_eq!(checkpoint.fields().application.height, 8);
    assert_eq!(checkpoint.fields().edge.terminal_old_height, 10);
    assert!(!live.1.driver.activation_persistence_pending_v1());
    let effects = live.1.take_initial_timer_effects_v1().unwrap();
    assert_eq!(effects.len(), 1);
    assert!(
        matches!(&effects[0], trnm_consensus_core::Effect::ArmViewTimer { epoch, view, .. }
        if epoch.get() == 1 && view.get() == 1)
    );
    assert!(live.1.take_initial_timer_effects_v1().unwrap().is_empty());
    let (dir, runtime, mut key, _) = *live;
    let (mut runtime, vote) = runtime.sign_initial_timeout_v1(&mut key).unwrap();
    assert_eq!(
        key.calls, 11,
        "exactly the one new-epoch timeout enters the key"
    );
    assert_eq!(vote.epoch().get(), 1);
    assert_eq!(
        runtime.checkpoint.fields().phase,
        EpochCheckpointPhaseV1::Ordinary
    );
    assert!(runtime.driver.state().pending_sign().is_none());
    assert_eq!(runtime.checkpoint.fields().ordinary.unwrap().sequence, 2);
    assert_eq!(
        runtime.checkpoint.fields().generation,
        checkpoint.fields().generation + 3
    );
    runtime
        .checkpoint_store
        .confirm_exact(&runtime.checkpoint)
        .unwrap();
    runtime.journal.fresh_read_v1(runtime.pin).unwrap();
    assert!(dir.path().is_dir());
}

#[test]
fn actual_epoch_runtime_admits_first_proposal_to_durable_validation_without_signing() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let (dir, runtime, key, recovery) = *live;
    // The proposal was signed from this activation's exact context before the
    // Core owner was moved into the candidate runtime.  Reusing the corpus
    // vector here would silently introduce a different epoch/validator set.
    let proposal = recovery.proposal.clone();
    let mut runtime = runtime
        .admit_epoch_proposal_v1(proposal.clone())
        .expect("proposal admission persists the Core obligation");
    let request = runtime
        .pending_epoch_proposal_validation_v1()
        .expect("Core retains one exact validation request");
    assert_eq!(request.block().id(), proposal.block().id());
    assert_eq!(request.block().header().epoch().get(), 1);
    assert_eq!(runtime.driver.state().epoch().get(), 1);
    assert_eq!(runtime.driver.state().pending_sign(), None);
    assert_eq!(
        runtime
            .driver
            .state()
            .payload_validation_obligations()
            .len(),
        1
    );
    assert_eq!(
        runtime
            .ordinary
            .confirm_node_checkpoint_head_exact_v0()
            .expect("signer checkpoint")
            .exact_watermark()
            .sequence(),
        0,
        "admission must not consume the new epoch signer"
    );
    assert_eq!(key.calls, 10, "proposal admission must not call the signer");
    runtime.confirm_current_cut_v1().unwrap();
    assert!(dir.path().is_dir());
    drop(recovery);
}

#[test]
fn actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing() {
    std::thread::Builder::new()
        .name("epoch-native-pdc-test".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
            let (dir, runtime, key, recovery) = *live;
            let proposal = native_first_proposal_v1(
                &runtime.application,
                &runtime.edge,
                recovery.proposal.witness().justify_qc(),
                recovery
                    .proposal
                    .witness()
                    .epoch_anchor_authorization()
                    .expect("epoch proposal anchor authorization"),
            );
            let block_id = *proposal.block().id().as_bytes();
            let runtime = runtime
                .admit_epoch_proposal_v1(proposal.clone())
                .expect("native proposal admission");
            let (runtime, effects) = runtime
                .execute_admitted_epoch_proposal_v1()
                .expect("native P/D/C execution");
            assert!(effects.iter().any(|effect| matches!(
                effect,
                trnm_consensus_core::Effect::RequestSignature { .. }
            )));
            assert_eq!(key.calls, 10, "P/D/C must not call the signer");
            assert_eq!(runtime.driver.state().pending_sign().is_some(), true);
            let p = runtime
                .application
                .reopen_prepared_epoch_execution_v1(block_id)
                .expect("durable native P readback");
            assert_eq!(p.header().unwrap(), *proposal.block().header());
            let descendants = native_epoch_descendants_v1(
                proposal.block().header(),
                runtime.edge.new_validator_set(),
                runtime.edge.new_parameters(),
            );
            let mut headers = vec![proposal.block().header().clone()];
            headers.extend(descendants);
            let proof = trnm_native_execution_v0::test_fixtures::epoch_first_finality(
                &runtime.edge,
                &headers,
            );
            let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
            let mut runtime = runtime
                .commit_admitted_epoch_finality_v1(&proof, &mut budget)
                .expect("strict first-new finality commits native K");
            runtime
                .confirm_current_cut_v1()
                .expect("post-K current cut revalidation");
            assert!(runtime.pending_epoch_proposal_validation_v1().is_none());
            assert_eq!(runtime.checkpoint.fields().application.height, 11);
            assert_eq!(key.calls, 10, "K must not call the signer");
            let repeated = match runtime.admit_epoch_proposal_v1(proposal) {
                Ok(_) => panic!("a committed first-new cut must reject repeated crossing"),
                Err(error) => error,
            };
            assert!(
                repeated
                    .to_string()
                    .contains("first-new epoch crossing already committed"),
                "repeated crossing must fail at the persisted application cut: {repeated:#}"
            );
            assert_eq!(key.calls, 10, "repeated crossing must not call the signer");
            assert!(dir.path().is_dir());
        })
        .expect("spawn epoch native P/D/C test")
        .join()
        .expect("epoch native P/D/C test panicked");
}

#[test]
fn actual_epoch_runtime_external_callback_replacement_fences_before_key() {
    assert_external_replacement_v1(activate_actual_case_v1(build_epoch_runtime_case_v1()));
}
fn assert_external_replacement_v1(live: Box<LiveCaseV1>) {
    let (dir, runtime, mut key, recovery) = *live;
    let native_path = runtime.application.path().to_path_buf();
    *recovery.new_watermark.1.lock().unwrap() = Some(native_path.clone());
    let result = runtime.sign_initial_timeout_v1(&mut key);
    assert!(
        result.is_err(),
        "replacement was accepted: key calls={}, hook fired={}",
        key.calls,
        recovery.new_watermark.1.lock().unwrap().is_none()
    );
    assert_eq!(
        key.calls, 10,
        "replacement after intent persistence must not enter the new key"
    );
    assert!(recovery.new_watermark.1.lock().unwrap().is_none());
    assert!(native_path.with_extension("displaced-before-key").is_file());
    assert_eq!(
        recovery
            .new_watermark
            .0
            .lock()
            .unwrap()
            .0
            .unwrap()
            .sequence(),
        1
    );
    assert!(dir.path().is_dir());
}

struct ClosedLiveCaseV1 {
    dir: tempfile::TempDir,
    key: Key,
    recovery: Box<RecoveryDataV1>,
    native_path: PathBuf,
    old_path: PathBuf,
    old_profile: SignerJournalProfileV0,
    retirement: SignerRetirementRecordV1,
    new_path: PathBuf,
    new_profile: SignerJournalProfileV0,
    safety_path: PathBuf,
    safety_pin: EpochSafetyHeadPinV1,
    external_path: PathBuf,
    checkpoint: EpochNodeCheckpointV1,
}
fn close_actual_runtime_v1(live: Box<LiveCaseV1>) -> Box<ClosedLiveCaseV1> {
    let (dir, runtime, key, recovery) = *live;
    let closed = Box::new(ClosedLiveCaseV1 {
        native_path: runtime.application.path().to_path_buf(),
        old_path: runtime.retired.path_v1().to_path_buf(),
        old_profile: runtime.retired.profile_v1().clone(),
        retirement: *runtime.retired.record_v1(),
        new_path: runtime.ordinary.path().to_path_buf(),
        new_profile: runtime.ordinary.profile().clone(),
        safety_path: runtime.journal.path_v1().to_path_buf(),
        safety_pin: runtime.pin,
        external_path: dir.path().join("independent-node.db"),
        checkpoint: runtime.checkpoint,
        dir,
        key,
        recovery,
    });
    // No old Core, native, journal9, retired/ordinary signer, node store or
    // owner-affine receipt survives into the new process-shaped recovery.
    drop(runtime);
    closed
}
fn reopen_actual_native_v1(
    c: &ClosedLiveCaseV1,
) -> (
    DurableNativeApplicationV0,
    AuthenticatedEpochApplicationEdgeV1,
) {
    let app =
        DurableNativeApplicationV0::open(&c.native_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let r = &c.recovery;
    let prepared = app
        .prepare_native_poco_checkpoint_v0(
            &r.preview,
            r.checkpoint.view(),
            r.checkpoint.proposer_id(),
            &r.cutoff,
            &r.cutoff_parent,
        )
        .unwrap();
    let edge = app
        .confirm_poco_checkpoint_v0(prepared, &r.finality, &r.anchor)
        .unwrap()
        .into_epoch_application_edge_v1()
        .unwrap();
    (app, edge)
}
fn reopen_actual_runtime_v1(closed: Box<ClosedLiveCaseV1>) -> anyhow::Result<Box<LiveCaseV1>> {
    let (application, edge) = reopen_actual_native_v1(&closed);
    let journal = SqliteEpochSafetyJournalV1::open_existing_v1(
        &closed.safety_path,
        closed.recovery.profile.clone(),
        closed.safety_pin,
    )?;
    let retired = RetiredSqliteSignerJournalV1::open_existing_v1(
        &closed.old_path,
        closed.old_profile.clone(),
        closed.recovery.old_watermark.clone(),
        closed.retirement,
        &closed.recovery.context,
        &closed.recovery.intent,
    )?;
    let ordinary = SqliteSignerJournalV0::open_existing(
        &closed.new_path,
        closed.new_profile.clone(),
        closed.recovery.new_watermark.clone(),
    )?;
    let checkpoint_store =
        SqliteEpochNodeCheckpointStoreV1::open_existing(&closed.external_path, &closed.checkpoint)?;
    let runtime = CandidateEpochRuntimeV1::recover_initial_continuing_v1(
        journal,
        application,
        edge,
        retired,
        ordinary,
        checkpoint_store,
        closed.checkpoint,
    )?;
    Ok(Box::new((closed.dir, runtime, closed.key, closed.recovery)))
}

fn readback_actual_progressed_v1(
    closed: &ClosedLiveCaseV1,
    block_id: [u8; 32],
) -> anyhow::Result<ProgressedEpochRecoveryReadbackV1> {
    let (application, edge) = reopen_actual_native_v1(closed);
    let journal = SqliteEpochSafetyJournalV1::open_existing_v1(
        &closed.safety_path,
        closed.recovery.profile.clone(),
        closed.safety_pin,
    )?;
    let retired = RetiredSqliteSignerJournalV1::open_existing_v1(
        &closed.old_path,
        closed.old_profile.clone(),
        closed.recovery.old_watermark.clone(),
        closed.retirement,
        &closed.recovery.context,
        &closed.recovery.intent,
    )?;
    let ordinary = SqliteSignerJournalV0::open_existing(
        &closed.new_path,
        closed.new_profile.clone(),
        closed.recovery.new_watermark.clone(),
    )?;
    let checkpoint_store =
        SqliteEpochNodeCheckpointStoreV1::open_existing(&closed.external_path, &closed.checkpoint)?;
    Ok(
        CandidateEpochRuntimeV1::recover_progressed_obligation_readback_v1(
            journal,
            application,
            edge,
            retired,
            ordinary,
            checkpoint_store,
            closed.checkpoint,
            block_id,
        )?,
    )
}

fn readback_actual_pending_validation_v1(
    closed: &ClosedLiveCaseV1,
    block_id: [u8; 32],
) -> anyhow::Result<PendingEpochValidationRecoveryReadbackV1> {
    let (application, edge) = reopen_actual_native_v1(closed);
    let journal = SqliteEpochSafetyJournalV1::open_existing_v1(
        &closed.safety_path,
        closed.recovery.profile.clone(),
        closed.safety_pin,
    )?;
    let retired = RetiredSqliteSignerJournalV1::open_existing_v1(
        &closed.old_path,
        closed.old_profile.clone(),
        closed.recovery.old_watermark.clone(),
        closed.retirement,
        &closed.recovery.context,
        &closed.recovery.intent,
    )?;
    let ordinary = SqliteSignerJournalV0::open_existing(
        &closed.new_path,
        closed.new_profile.clone(),
        closed.recovery.new_watermark.clone(),
    )?;
    let checkpoint_store =
        SqliteEpochNodeCheckpointStoreV1::open_existing(&closed.external_path, &closed.checkpoint)?;
    Ok(
        CandidateEpochRuntimeV1::recover_pending_epoch_validation_readback_v1(
            journal,
            application,
            edge,
            retired,
            ordinary,
            checkpoint_store,
            closed.checkpoint,
            block_id,
        )?,
    )
}

#[test]
fn actual_epoch_runtime_pending_validation_recovery_rejoins_without_execution_or_signing() {
    std::thread::Builder::new()
        .name("epoch-pending-validation-recovery-test".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
            let (dir, runtime, key, recovery) = *live;
            let proposal = native_first_proposal_v1(
                &runtime.application,
                &runtime.edge,
                recovery.proposal.witness().justify_qc(),
                recovery
                    .proposal
                    .witness()
                    .epoch_anchor_authorization()
                    .expect("epoch proposal anchor authorization"),
            );
            let block_id = *proposal.block().id().as_bytes();
            let runtime = runtime
                .admit_epoch_proposal_v1(proposal)
                .expect("native proposal admission");
            assert!(runtime.pending_epoch_proposal_validation_v1().is_some());
            assert_eq!(key.calls, 10, "admission must not call the signer");
            let closed = close_actual_runtime_v1(Box::new((dir, runtime, key, recovery)));
            let readback = readback_actual_pending_validation_v1(&closed, block_id)
                .expect("pending validation readback after process-shaped restart");
            assert_eq!(readback.block_id, block_id);
            assert_eq!(
                readback.safety_revision,
                closed.checkpoint.fields().target_safety.revision
            );
            assert_eq!(readback.validation_view, 1);
            assert_eq!(readback.validation_generation, readback.safety_revision);
            assert_ne!(readback.proposal_root, [0; 32]);
            assert_eq!(closed.key.calls, 10, "readback must never call the signer");
            assert!(closed.dir.path().is_dir());
        })
        .expect("spawn pending validation recovery test")
        .join()
        .expect("pending validation recovery test panicked");
}

#[test]
fn actual_epoch_runtime_progressed_obligation_recovery_rejoins_pdc_without_signing() {
    std::thread::Builder::new()
        .name("epoch-progressed-recovery-test".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
            let (dir, runtime, key, recovery) = *live;
            let proposal = native_first_proposal_v1(
                &runtime.application,
                &runtime.edge,
                recovery.proposal.witness().justify_qc(),
                recovery
                    .proposal
                    .witness()
                    .epoch_anchor_authorization()
                    .expect("epoch proposal anchor authorization"),
            );
            let block_id = *proposal.block().id().as_bytes();
            let runtime = runtime
                .admit_epoch_proposal_v1(proposal)
                .expect("native proposal admission");
            let (runtime, effects) = runtime
                .execute_admitted_epoch_proposal_v1()
                .expect("native P/D/C execution");
            assert!(effects.iter().any(|effect| matches!(
                effect,
                trnm_consensus_core::Effect::RequestSignature { .. }
            )));
            assert_eq!(key.calls, 10, "P/D/C must not call the signer");
            let closed = close_actual_runtime_v1(Box::new((dir, runtime, key, recovery)));
            let readback = readback_actual_progressed_v1(&closed, block_id)
                .expect("progressed P/D/C readback after process-shaped restart");
            assert_eq!(readback.block_id, block_id);
            assert_eq!(
                readback.safety_revision,
                closed.checkpoint.fields().target_safety.revision
            );
            assert_ne!(readback.p_digest, [0; 32]);
            assert_ne!(readback.artifact_digest, [0; 32]);
            assert!(closed.dir.path().is_dir());
        })
        .expect("spawn progressed recovery test")
        .join()
        .expect("progressed recovery test panicked");
}

#[test]
fn actual_epoch_runtime_all_owner_initial_recovery_rearms_without_signing() {
    assert_initial_recovery_v1(activate_actual_case_v1(build_epoch_runtime_case_v1()));
}
fn assert_initial_recovery_v1(live: Box<LiveCaseV1>) {
    let expected = live.1.checkpoint;
    let closed = close_actual_runtime_v1(live);
    let reopened = reopen_actual_runtime_v1(closed).unwrap();
    assert_recovered_then_timeout_v1(reopened, expected);
}
fn assert_recovered_then_timeout_v1(
    mut reopened: Box<LiveCaseV1>,
    expected: EpochNodeCheckpointV1,
) {
    assert_eq!(reopened.2.calls, 10);
    assert_eq!(
        reopened.1.confirm_initial_activation_v1().unwrap(),
        expected
    );
    assert_eq!(reopened.1.take_initial_timer_effects_v1().unwrap().len(), 1);
    assert!(reopened
        .1
        .take_initial_timer_effects_v1()
        .unwrap()
        .is_empty());
    let (dir, runtime, mut key, recovery) = *reopened;
    let (runtime, vote) = runtime.sign_initial_timeout_v1(&mut key).unwrap();
    assert_eq!(vote.epoch().get(), 1);
    assert_eq!(key.calls, 11);
    // A later durable decision cannot be reset through the initial-only API.
    let closed = close_actual_runtime_v1(Box::new((dir, runtime, key, recovery)));
    assert!(reopen_actual_runtime_v1(closed).is_err());
}
