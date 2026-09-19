//! Actual Core/journal8/native P and SQLite original-custody integration.
//! Only the independently administered watermark service is a test double.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_safety_store::test_fixtures::{
    build_native_old_epoch_terminal_v1, NativeOldEpochTerminalFixtureV1,
};
use trnm_consensus_signer_journal::{
    HandoffSignatureRequestV1, SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0,
};
use trnm_consensus_types::{BlockId, HandoffDescriptorV0Fields, Height, StateRoot, View};
use trnm_native_execution_v0::test_fixtures::native_checkpoint_fixture_config_v1;
use trnm_poco_node_authority::{
    confirm_retired_epoch_node_checkpoint_v1, ExternalNodeCheckpointFieldsV0,
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
};

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
impl HandoffSignatureProducerV1 for Key {
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls += 1;
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

struct Case {
    dir: tempfile::TempDir,
    fixture: NativeOldEpochTerminalFixtureV1,
    ordinary: SqliteSignerJournalV0<Watermark>,
    ordinary_profile: SignerJournalProfileV0,
    ordinary_watermark: Watermark,
    initial_watermark: SignerWatermarkV0,
    key: Key,
}
fn build_case() -> Box<Case> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = native_checkpoint_fixture_config_v1();
    let author = config.validator_set_v0().validators()[0].id();
    let ordinary_profile = SignerJournalProfileV0::new(
        config.validator_set_v0().clone(),
        author,
        [81; 32],
        [82; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let ordinary_path = dir.path().join("original.db");
    let ordinary_watermark = Watermark::default();
    let mut ordinary = SqliteSignerJournalV0::initialize_new(
        &ordinary_path,
        ordinary_profile.clone(),
        ordinary_watermark.clone(),
    )
    .unwrap();
    let initial_signer = ordinary.confirm_node_checkpoint_head_exact_v0().unwrap();
    let initial_watermark = initial_signer.exact_watermark();
    let mut key = Key {
        key: SigningKey::from_bytes(&[20; 32]),
        calls: 0,
    };
    let fixture = build_native_old_epoch_terminal_v1(&dir.path().join("chain"), |intent| {
        Ok(ordinary.sign_exact_v0(intent, &mut key)?)
    })
    .unwrap();
    assert_eq!(key.calls, 10);
    assert_eq!(fixture.sign_intents.len(), 10);
    Box::new(Case {
        dir,
        fixture,
        ordinary,
        ordinary_profile,
        ordinary_watermark,
        initial_watermark,
        key,
    })
}
#[test]
fn real_native_terminal_checkpoint_recovers_original_retired_custody_and_exact_handoff() {
    run_join(build_case());
}
fn run_join(case: Box<Case>) {
    let Case {
        dir,
        fixture,
        mut ordinary,
        ordinary_profile,
        ordinary_watermark,
        initial_watermark,
        mut key,
    } = *case;
    let config = &fixture.config;
    let author = config.validator_set_v0().validators()[0].id();
    let ordinary_path = dir.path().join("original.db");
    let receipt = fixture
        .application
        .confirm_pre_handoff_checkpoint_v1(
            fixture.pre_handoff_preparation,
            &fixture.checkpoint_finality_bytes,
        )
        .unwrap();
    let terminal = receipt.checkpoint_finality().grandchild();
    let old = receipt.old_validator_set();
    let new = receipt.new_validator_set();
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old.genesis_hash(),
        chain_id: old.chain_id(),
        old_epoch: old.epoch(),
        new_epoch: new.epoch(),
        old_protocol_version: old.protocol_version(),
        new_protocol_version: new.protocol_version(),
        old_validator_set_hash: old.id(),
        new_validator_set_hash: new.id(),
        old_consensus_parameters_hash: receipt.old_parameters().hash(),
        new_consensus_parameters_hash: receipt.new_parameters().hash(),
        checkpoint_height: receipt.header().height(),
        checkpoint_block_id: receipt.header().id(),
        checkpoint_state_root: receipt.header().state_root(),
        next_epoch_commitment_digest: receipt.next_epoch_commitment().id(),
        terminal_old_height: terminal.header().height(),
        terminal_old_block_id: terminal.header().id(),
        terminal_old_qc_digest: terminal.certifying_qc().id(),
        terminal_old_view: terminal.header().view(),
        activation_height: Height::new(11),
        initial_new_view: View::new(1),
    })
    .unwrap();
    let handoff_profile = HandoffSignerJournalProfileV1::for_epoch_handoff(
        old.clone(),
        new.clone(),
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
    let safety_head = terminal_head(&fixture.journal, fixture.pin);
    let origin = safety_head.migration_source_v1();
    // Explicitly trusted genesis commissioning input. These actual original
    // journal identities were captured before the first signature/migration.
    // Legacy projection checksums are inert here; this is no ordinary P/ACK grant.
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
        application_block_id: BlockId::new(config.initial_block_id_v0()),
        application_height: 0,
        application_state_root: StateRoot::new(config.initial_state_root()),
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
    let handoff_path = dir.path().join("handoff.db");
    let handoff_watermark = Watermark::default();
    let handoff = SqliteHandoffSignerJournalV1::create_new(
        &handoff_path,
        handoff_profile.clone(),
        handoff_watermark.clone(),
    )
    .unwrap();
    let original_facts = ordinary.confirm_node_checkpoint_head_exact_v0().unwrap();
    let mut runtime = CandidateHandoffRuntimeV1::from_owners_with_original_ordinary_v1(
        &fixture.application,
        handoff,
        &mut ordinary,
        original_facts,
    )
    .unwrap();
    let (mut retired, confirmed) = runtime
        .retire_ordinary_before_handoff_v1(
            &fixture.application,
            &receipt,
            &descriptor,
            &fixture.journal,
            &safety_head,
            ordinary,
        )
        .unwrap();
    // Each rejected predecessor is itself checksummed and durably recorded;
    // rejection must come from joining the actual owners, not its codec shape.
    for mutation in 0..8 {
        let mut fields = *predecessor.fields();
        match mutation {
            0 => fields.safety_journal_id = [101; 32],
            1 => fields.safety_verifier_profile_ref = [102; 32],
            2 => fields.safety_revision += 1,
            3 => fields.safety_state_record_checksum = [103; 32],
            4 => fields.safety_record_chain_checksum = [104; 32],
            5 => fields.application_block_id = BlockId::new([105; 32]),
            6 => fields.application_state_root = StateRoot::new([106; 32]),
            7 => {
                fields.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
                    initial_watermark.scope(),
                    initial_watermark.journal_id(),
                    0,
                    [107; 32],
                )
                .unwrap()
            }
            _ => unreachable!(),
        }
        let changed = ExternalNodeCheckpointV0::new(fields).unwrap();
        let path = dir.path().join(format!("wrong-predecessor-{mutation}.db"));
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path).unwrap();
        store.compare_and_advance(None, changed).unwrap();
        assert!(
            confirm_retired_epoch_node_checkpoint_v1(
                store,
                changed,
                &fixture.application,
                &receipt,
                &descriptor,
                &handoff_profile,
                &fixture.journal,
                &safety_head,
                &mut retired,
                &confirmed,
            )
            .is_err(),
            "mutated real predecessor {mutation}"
        );
        assert_eq!(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&path)
                .unwrap()
                .load(changed.scope())
                .unwrap(),
            Some(changed),
            "reject before CAS"
        );
    }
    let checkpoint = confirm_retired_epoch_node_checkpoint_v1(
        external,
        predecessor,
        &fixture.application,
        &receipt,
        &descriptor,
        &handoff_profile,
        &fixture.journal,
        &safety_head,
        &mut retired,
        &confirmed,
    )
    .unwrap();
    assert!(checkpoint.belongs_to_retired_owner_v1(&mut retired));
    let target = *checkpoint.checkpoint_v1();
    assert_eq!(target.generation(), 1);
    assert_eq!(target.fields().application_height, 8);
    assert_eq!(
        target.fields().signer_exact_watermark,
        retired.record_v1().terminal_watermark_v1()
    );
    let first = runtime
        .sign_retired_handoff_exact_v1(
            &fixture.application,
            &receipt,
            &descriptor,
            HandoffSignerRoleV1::OldSet,
            &fixture.journal,
            &safety_head,
            &mut retired,
            &confirmed,
            &mut key,
        )
        .unwrap();
    assert_eq!(key.calls, 11);
    let context = verify_receipt(
        &fixture.application,
        &receipt,
        &descriptor,
        &handoff_profile,
    )
    .unwrap();
    let intent = first.intent().clone();
    let record = *retired.record_v1();
    let other_path = dir.path().join("same-key-second-owner.db");
    let other = SqliteSignerJournalV0::initialize_new(
        &other_path,
        ordinary_profile.clone(),
        Watermark::default(),
    )
    .unwrap();
    let mut other = other
        .retire_for_handoff_v1(&context, &intent, record.host_cut_v1())
        .unwrap();
    let other_confirmed = other.confirm_retirement_v1().unwrap();
    assert!(
        confirm_retired_epoch_node_checkpoint_v1(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&external_path).unwrap(),
            predecessor,
            &fixture.application,
            &receipt,
            &descriptor,
            &handoff_profile,
            &fixture.journal,
            &safety_head,
            &mut other,
            &other_confirmed,
        )
        .is_err(),
        "identical key, scope and profile do not confer original journal identity"
    );
    drop(runtime);
    drop(checkpoint);
    drop(retired);
    let application_path = fixture.application.path().to_path_buf();
    let safety_path = fixture.journal.path_v1().to_path_buf();
    let checkpoint_header = receipt.header().clone();
    let old_native_cut = receipt.committed_owner_cut_ref_v1();
    let request = fixture.checkpoint_execution.request();
    let preview = trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        request.parent().clone(),
        request.height(),
        request.timestamp_ms(),
        request.active_validator_set_id(),
        request.transactions().to_vec(),
    )
    .unwrap();
    // Close every actual local owner and discard its affine receipts before
    // reopening the independently pinned source/target cuts. Public proof bytes
    // survive; none of the old live authority handles survive this boundary.
    drop(receipt);
    drop(safety_head);
    drop(fixture.checkpoint);
    drop(fixture.application);
    drop(fixture.owner);
    drop(fixture.journal);
    drop(fixture.source_journal);
    let application = DurableNativeApplicationV0::open(&application_path, fixture.config).unwrap();
    let prepared = application
        .prepare_native_poco_checkpoint_v0(
            &preview,
            checkpoint_header.view(),
            checkpoint_header.proposer_id(),
            &fixture.cutoff_finality_bytes,
            &fixture.cutoff_parent_header_bytes,
        )
        .unwrap();
    let receipt = application
        .confirm_pre_handoff_checkpoint_v1(prepared, &fixture.checkpoint_finality_bytes)
        .unwrap();
    assert_eq!(receipt.committed_owner_cut_ref_v1(), old_native_cut);
    let journal =
        SqliteOldEpochSafetyJournalV1::open_existing_v1(&safety_path, fixture.profile, fixture.pin)
            .unwrap();
    let safety_head = terminal_head(&journal, fixture.pin);
    assert!(
        SqliteSignerJournalV0::open_existing(
            &ordinary_path,
            ordinary_profile.clone(),
            ordinary_watermark.clone(),
        )
        .is_err(),
        "retired SQLite cannot become ordinary custody again"
    );
    let mut retired = RetiredSqliteSignerJournalV1::open_existing_v1(
        &ordinary_path,
        ordinary_profile,
        ordinary_watermark,
        record,
        &context,
        &intent,
    )
    .unwrap();
    let confirmed = retired.confirm_retirement_v1().unwrap();
    let checkpoint = confirm_retired_epoch_node_checkpoint_v1(
        SqliteExternalNodeCheckpointStoreV0::open_existing(&external_path).unwrap(),
        predecessor,
        &application,
        &receipt,
        &descriptor,
        &handoff_profile,
        &journal,
        &safety_head,
        &mut retired,
        &confirmed,
    )
    .unwrap();
    assert_eq!(
        *checkpoint.checkpoint_v1(),
        target,
        "exact target retry never creates another generation"
    );
    let mut recovered =
        CandidateHandoffRuntimeV1::recover_with_checkpointed_retired_ordinary_exact_v1(
            &application,
            &receipt,
            &descriptor,
            HandoffSignerRoleV1::OldSet,
            &handoff_path,
            handoff_profile,
            handoff_watermark,
            &journal,
            &safety_head,
            &mut retired,
            &confirmed,
            checkpoint,
        )
        .unwrap();
    let retry = recovered
        .sign_retired_handoff_exact_v1(
            &application,
            &receipt,
            &descriptor,
            HandoffSignerRoleV1::OldSet,
            &journal,
            &safety_head,
            &mut retired,
            &confirmed,
            &mut key,
        )
        .unwrap();
    assert_eq!(retry.signature(), first.signature());
    assert_eq!(
        key.calls, 11,
        "recovery releases the persisted exact signature without calling the key"
    );
    // An independent checkpoint change invalidates the live recovered join.
    let mut advanced = *target.fields();
    advanced.generation += 1;
    advanced.predecessor_checksum = target.checkpoint_checksum();
    let advanced = ExternalNodeCheckpointV0::new(advanced).unwrap();
    SqliteExternalNodeCheckpointStoreV0::open_existing(&external_path)
        .unwrap()
        .compare_and_advance(Some(target), advanced)
        .unwrap();
    assert!(recovered
        .sign_retired_handoff_exact_v1(
            &application,
            &receipt,
            &descriptor,
            HandoffSignerRoleV1::OldSet,
            &journal,
            &safety_head,
            &mut retired,
            &confirmed,
            &mut key,
        )
        .is_err());
    assert_eq!(
        key.calls, 11,
        "changed independent cut fences before key access"
    );
}

fn terminal_head(
    journal: &SqliteOldEpochSafetyJournalV1,
    pin: trnm_consensus_safety_store::OldEpochSafetyHeadPinV1,
) -> ConfirmedOldEpochSafetyHeadV1 {
    journal.prepare_terminal_recovery_v1(pin).unwrap().0
}
