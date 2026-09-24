// Genuine owner chain. Header reads below are original committed native P
// readbacks, not constructed consensus history or fake settled Safety rows.
#[inline(never)]
fn original_successor_preparation_v9(
    attached: &super::EpochHandoffAttachedRuntimeV8<Watermark, Watermark, Watermark>,
) -> trnm_consensus_core::EpochPreparationV2 {
    use trnm_consensus_core::{prepare_epoch_handoff_evidence_v2, EpochPreparationEntryV2};
    use trnm_consensus_types::{Cev0AdmissionBudgetV0, EpochActivationEvidenceBytesV0};
    let source = &attached.roles.retired.source;
    let epoch = source.driver.state().epoch_state_v1().unwrap();
    let proof = source.driver.state().last_finalization_proof().unwrap();
    let context = source.receipt.strict_context();
    let mut cursor = source.receipt.header().parent_id();
    let mut headers = Vec::new();
    while cursor != epoch.terminal_old_header().id() {
        let p = source
            .application
            .reopen_prepared_epoch_execution_v1(cursor.into_bytes())
            .unwrap();
        let fresh = source
            .application
            .confirm_prepared_epoch_execution_v1(&p)
            .unwrap();
        assert!(fresh.commit_sequence().is_some());
        let header = p.header().unwrap();
        cursor = header.parent_id();
        headers.push(header);
        assert!(headers.len() < 256);
    }
    let parent = headers[0].try_cev0_bytes().unwrap();
    headers.push(epoch.terminal_old_header().clone());
    headers.reverse();
    assert_eq!(headers.len(), 8);
    let encoded = headers
        .iter()
        .map(|h| h.try_cev0_bytes().unwrap())
        .collect::<Vec<_>>();
    let borrowed = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: proof.try_cev0_bytes().unwrap(),
        next_epoch_commitment: source
            .selection
            .next_epoch_commitment()
            .try_cev0_bytes()
            .unwrap(),
        authorization_kernel: attached.kernel.to_vec(),
        old_validator_set: context.old_validator_set().try_cev0_bytes().unwrap(),
        old_consensus_parameters: context.old_consensus_parameters().canonical_bytes(),
        new_validator_set: context.new_validator_set().try_cev0_bytes().unwrap(),
        new_consensus_parameters: context.new_consensus_parameters().canonical_bytes(),
        authenticated_checkpoint_parent_header: parent,
    };
    let entries = [
        EpochPreparationEntryV2 {
            binding_ref: epoch.activation_binding(),
            retained_ancestry: &[],
            evidence: epoch.evidence_bytes().as_preimages(),
        },
        EpochPreparationEntryV2 {
            binding_ref: attached.edge.successor_binding(),
            retained_ancestry: &borrowed,
            evidence: evidence.as_preimages(),
        },
    ];
    prepare_epoch_handoff_evidence_v2(
        &entries,
        epoch.old_validator_set(),
        epoch.old_parameters(),
        epoch.activation_binding(),
        attached.edge.successor_binding(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap()
}

#[inline(never)]
fn activate_actual_successor_v9(case: Box<RolesCaseV7>, incoming: Watermark) {
    let (directory, roles, key, _) = *case;
    let calls = key.calls;
    let kernel = genuine_joint_kernel_v8(&roles, false);
    let attached = roles.attach_joint_handoff_v8(&kernel).unwrap();
    let source_cut = attached.checkpoint;
    let old_safety_path = attached
        .roles
        .retired
        .source
        .journal
        .path_v1()
        .to_path_buf();
    let old_safety = sqlite_logical_image_v3(&old_safety_path);
    let preparation = original_successor_preparation_v9(&attached);
    let preparation_digest = preparation.record_v2().digest_v2();
    let profile = SignerJournalProfileV0::new(
        preparation.authority_v2().new_validator_set().clone(),
        attached.roles.retired.retired.profile_v1().author(),
        attached
            .roles
            .retired
            .retired
            .profile_v1()
            .signer_profile_ref(),
        [0xe9; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let watermark = Watermark::default();
    let ordinary_path = directory.path().join("successor-ordinary-v9.db");
    let ordinary =
        SqliteSignerJournalV0::initialize_new(&ordinary_path, profile, watermark.clone()).unwrap();
    let journal_path = directory.path().join("successor-journal12-v9.db");
    let mut owner = attached
        .activate_successor_v9(preparation, &journal_path, ordinary)
        .unwrap();
    let cut = owner.confirm_activated_cut_v9().unwrap();
    assert_eq!(
        cut.fields().phase,
        super::EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12
    );
    assert_eq!(cut.fields().predecessor_checksum, source_cut.checksum());
    assert_eq!(cut.fields().generation, source_cut.fields().generation + 1);
    assert_eq!(
        cut.fields().owner_generation,
        source_cut.fields().owner_generation + 1
    );
    assert_eq!(cut.fields().epoch, source_cut.fields().epoch + 1);
    assert_eq!(cut.fields().application, source_cut.fields().application);
    assert_eq!(cut.fields().edge, source_cut.fields().edge);
    assert_eq!(
        cut.fields().source_safety,
        Some(source_cut.fields().target_safety)
    );
    assert_eq!(
        cut.fields().target_safety.revision,
        source_cut.fields().target_safety.revision + 1
    );
    assert!(!owner.driver.activation_persistence_pending_v2());
    assert!(matches!(
        owner.source.roles.retired.source.driver,
        super::OutgoingEpochCoreV9::Historical(_)
    ));
    assert_eq!(
        owner
            .driver
            .state()
            .epoch_state_v1()
            .unwrap()
            .preparation_record_v2()
            .unwrap()
            .digest_v2(),
        preparation_digest
    );
    assert!(matches!(
        owner.take_startup_effects_v9().unwrap().as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));
    assert!(owner.take_startup_effects_v9().unwrap().is_empty());
    assert_eq!(key.calls, calls);
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), 0);
    assert!(sqlite_logical_image_v3(&old_safety_path) == old_safety);
    let sql = rusqlite::Connection::open_with_flags(
        &journal_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        sql.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        12
    );
    drop(sql);
    // A later actual retired-source callback replaces O after its external
    // exact-head check. No key is involved; the final pure-local O read rejects.
    *incoming.4.lock().unwrap() = Some(ordinary_path.clone());
    let rejected = owner.confirm_activated_cut_v9().unwrap_err().to_string();
    assert!(incoming.4.lock().unwrap().is_none());
    assert!(rejected.contains("FileIdentityChanged"), "{rejected}");
    std::fs::remove_file(&ordinary_path).unwrap();
    std::fs::rename(
        ordinary_path.with_extension("retirement-callback-displaced"),
        &ordinary_path,
    )
    .unwrap();
    assert!(owner
        .confirm_activated_cut_v9()
        .unwrap_err()
        .to_string()
        .contains("fenced"));
    assert_eq!(key.calls, calls);
    let pin = owner.pin;
    let target_profile = owner.profile.clone();
    let node_path = owner
        .source
        .roles
        .retired
        .checkpoint_store
        .database_path()
        .to_path_buf();
    drop(owner);
    confirm_successor_cold_v9(Box::new(ColdSuccessorCaseV9 {
        journal_path,
        target_profile,
        pin,
        node_path,
        cut,
        preparation_digest,
        old_safety_path,
        old_safety,
    }));
}

struct ColdSuccessorCaseV9 {
    journal_path: std::path::PathBuf,
    target_profile: Box<trnm_consensus_safety_store::EpochSafetyJournalProfileV4>,
    pin: trnm_consensus_safety_store::EpochSafetyHeadPinV4,
    node_path: std::path::PathBuf,
    cut: super::EpochNodeCheckpointV1,
    preparation_digest: [u8; 32],
    old_safety_path: std::path::PathBuf,
    old_safety: Vec<SqliteTableImageV3>,
}

#[inline(never)]
fn confirm_successor_cold_v9(case: Box<ColdSuccessorCaseV9>) {
    let ColdSuccessorCaseV9 {
        journal_path,
        target_profile,
        pin,
        node_path,
        cut,
        preparation_digest,
        old_safety_path,
        old_safety,
    } = *case;
    let journal = trnm_consensus_safety_store::SqliteEpochSafetyJournalV4::open_existing_v4(
        &journal_path,
        *target_profile,
        pin,
    )
    .unwrap();
    let (head, recovery) = journal.prepare_recovery_v4(pin).unwrap();
    assert_eq!(head.state_v4(), recovery.state());
    assert_eq!(
        head.state_v4()
            .epoch_state_v1()
            .unwrap()
            .preparation_record_v2()
            .unwrap()
            .digest_v2(),
        preparation_digest
    );
    let mut node =
        super::SqliteEpochNodeCheckpointStoreV1::open_existing(&node_path, &cut).unwrap();
    assert_eq!(node.load().unwrap(), cut);
    assert!(sqlite_logical_image_v3(&old_safety_path) == old_safety);
}

#[test]
fn actual_epoch_successor_activation_preserves_owners_and_initial_ack_v9() {
    let (roles, incoming) = build_actual_attachment_case_v8();
    activate_actual_successor_v9(roles, incoming);
}

#[inline(never)]
fn reject_actual_successor_after_initial_write_v9(case: Box<RolesCaseV7>, incoming: Watermark) {
    let (directory, roles, key, _) = *case;
    let calls = key.calls;
    let kernel = genuine_joint_kernel_v8(&roles, false);
    let attached = roles.attach_joint_handoff_v8(&kernel).unwrap();
    let original = attached.checkpoint;
    let node_path = attached
        .roles
        .retired
        .checkpoint_store
        .database_path()
        .to_path_buf();
    let preparation = original_successor_preparation_v9(&attached);
    let profile = SignerJournalProfileV0::new(
        preparation.authority_v2().new_validator_set().clone(),
        attached.roles.retired.retired.profile_v1().author(),
        attached
            .roles
            .retired
            .retired
            .profile_v1()
            .signer_profile_ref(),
        [0xea; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let watermark = Watermark::default();
    let ordinary_path = directory.path().join("successor-refused-ordinary.db");
    let ordinary =
        SqliteSignerJournalV0::initialize_new(&ordinary_path, profile, watermark.clone()).unwrap();
    let journal_path = directory.path().join("successor-refused-journal12.db");
    *incoming.6.lock().unwrap() = Some((journal_path.clone(), ordinary_path));
    let rejected = attached
        .activate_successor_v9(preparation, &journal_path, ordinary)
        .err()
        .expect("post-write source callback must reject activation");
    assert!(
        rejected.to_string().contains("FileIdentityChanged"),
        "{rejected}"
    );
    assert!(incoming.6.lock().unwrap().is_none());
    assert_eq!(key.calls, calls);
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), 0);
    // Actual physical initialization happened, but no independent activation
    // checkpoint was published and no live owner or ACK effects escaped.
    let sql = rusqlite::Connection::open_with_flags(
        &journal_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        sql.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        12
    );
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM epoch_records", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let mut node =
        super::SqliteEpochNodeCheckpointStoreV1::open_existing(&node_path, &original).unwrap();
    assert_eq!(node.load().unwrap(), original);
}

#[test]
fn actual_epoch_successor_activation_after_write_callback_blocks_ack_v9() {
    let (roles, incoming) = build_actual_attachment_case_v8();
    reject_actual_successor_after_initial_write_v9(roles, incoming);
}

type SuccessorCaseV10 = (
    tempfile::TempDir,
    super::SuccessorEpochRuntimeV9<Watermark, Watermark, Watermark, Watermark>,
    Key,
    Watermark,
);

#[inline(never)]
fn activate_live_successor_v10(case: Box<RolesCaseV7>) -> Box<SuccessorCaseV10> {
    let (directory, roles, key, _) = *case;
    let kernel = genuine_joint_kernel_v8(&roles, false);
    let attached = roles.attach_joint_handoff_v8(&kernel).unwrap();
    let preparation = original_successor_preparation_v9(&attached);
    let profile = SignerJournalProfileV0::new(
        preparation.authority_v2().new_validator_set().clone(),
        attached.roles.retired.retired.profile_v1().author(),
        attached
            .roles
            .retired
            .retired
            .profile_v1()
            .signer_profile_ref(),
        [0xeb; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap();
    let watermark = Watermark::default();
    let ordinary_path = directory.path().join("successor-ordinary-v10.db");
    let ordinary =
        SqliteSignerJournalV0::initialize_new(&ordinary_path, profile, watermark.clone()).unwrap();
    let journal_path = directory.path().join("successor-journal12-v10.db");
    let mut owner = attached
        .activate_successor_v9(preparation, &journal_path, ordinary)
        .unwrap();
    assert!(matches!(
        owner.take_startup_effects_v9().unwrap().as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));
    assert!(owner.take_startup_effects_v9().unwrap().is_empty());
    owner.confirm_activated_cut_v9().unwrap();
    Box::new((directory, owner, key, watermark))
}

fn successor_first_proposal_v10(
    owner: &super::SuccessorEpochRuntimeV9<Watermark, Watermark, Watermark, Watermark>,
) -> SignedProposalV0 {
    use ed25519_dalek::Signer;
    let epoch = owner.driver.state().epoch_state_v1().unwrap();
    let strict = epoch.strict_context().unwrap();
    let set = owner.driver.config().validator_set();
    let params = owner.driver.config().consensus_parameters();
    let edge = &owner.source.edge;
    assert_eq!(strict.activation().terminal_old_header().id().as_bytes(), &edge.terminal_block());
    let payload = trnm_consensus_types::ApplicationPayloadV0::new(Vec::new()).unwrap();
    let body = trnm_consensus_types::BlockBodyV0::new(payload.clone(), Vec::new()).unwrap();
    let app = owner.checkpoint.fields().application;
    let app_parent = trnm_native_application::ApplicationHeadV0::new(
        trnm_native_application::HeightV0::new(app.height),
        trnm_native_application::BlockIdV0::new(app.block_id).unwrap(),
        trnm_native_application::StateRootV0::new(app.state_root).unwrap(),
        trnm_native_application::ApplicationCommitIdV0::new(app.native_commit_id).unwrap(),
    );
    let timestamp = strict
        .activation()
        .terminal_old_header()
        .timestamp_ms()
        .checked_add(1)
        .unwrap();
    let preview = owner
        .source
        .roles
        .retired
        .source
        .application
        .preview_later_epoch_block_v1(
            edge,
            &trnm_native_application::NativeEpochBlockPreviewRequestV1::new(
                trnm_native_application::ChainIdV0::new(set.chain_id().as_str()).unwrap(),
                trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes())
                    .unwrap(),
                app_parent,
                trnm_native_application::BlockIdV0::new(edge.terminal_block()).unwrap(),
                trnm_native_application::HeightV0::new(edge.terminal_height()),
                trnm_native_application::Hash32V0::new(edge.successor_binding()),
                trnm_native_application::HeightV0::new(edge.first_application_height()),
                timestamp,
                trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    let view = owner.driver.state().current_view();
    let proposer = trnm_consensus_core::leader_for(set, view);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        trnm_consensus_types::Height::new(edge.first_application_height()),
        BlockKind::EpochHandoff,
        BlockId::new(edge.terminal_block()),
        proposer,
        set.id(),
        params.hash(),
        body.payload_root().unwrap(),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        body.evidence_root().unwrap(),
        timestamp,
        None,
    )
    .unwrap();
    let justify = strict.anchor_reference().clone();
    let authorization = strict.structural_context().authorization().clone();
    let key_index = set
        .validators()
        .iter()
        .position(|validator| validator.id() == proposer)
        .unwrap();
    let key = SigningKey::from_bytes(&[20 + key_index as u8; 32]);
    let root = ProposalWitnessV0::signing_root_for(
        &header,
        &justify,
        None,
        Some(&authorization),
    )
    .unwrap();
    let witness = ProposalWitnessV0::new(
        &header,
        justify,
        None,
        Some(authorization),
        SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
        set,
        Some(strict.activation().old_validator_set()),
        params,
        strict.activation().terminal_old_header().timestamp_ms(),
    )
    .unwrap();
    let block = Block::new(
        header,
        body.application_payload().try_cev0_bytes().unwrap(),
        Vec::new(),
    )
    .unwrap();
    SignedProposalV0::new(
        block,
        witness,
        set,
        Some(strict.activation().old_validator_set()),
        params,
        strict.activation().terminal_old_header().timestamp_ms(),
    )
    .unwrap()
}

#[test]
fn actual_successor_first_application_persists_executes_and_votes_v10() {
    let (roles, _) = build_actual_attachment_case_v8();
    let (directory, owner, mut key, watermark) = *activate_live_successor_v10(roles);
    let proposal = successor_first_proposal_v10(&owner);
    let block_id = *proposal.block().id().as_bytes();
    let epoch = proposal.block().header().epoch();
    let calls = key.calls;
    let owner = owner.begin_first_application_v10().unwrap();
    let owner = owner.admit_first_proposal_v10(proposal).unwrap();
    assert_eq!(key.calls, calls, "admission must not call the key");
    let (owner, effects) = owner.execute_first_proposal_v10().unwrap();
    assert!(effects.iter().any(|effect| matches!(
        effect,
        trnm_consensus_core::Effect::RequestSignature { .. }
    )));
    assert_eq!(key.calls, calls, "P/D/C must not call the key");
    let (owner, vote) = owner.sign_first_vote_v10(&mut key).unwrap();
    let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else {
        panic!("successor first application returned non-Vote")
    };
    assert_eq!(vote.epoch(), epoch);
    assert_eq!(vote.block_id().as_bytes(), &block_id);
    assert_eq!(key.calls, calls + 1, "exactly one successor Vote enters the key");
    let prepared = owner
        .application()
        .reopen_prepared_epoch_execution_v1(block_id)
        .unwrap();
    let descendants = native_epoch_descendants_v1(
        &prepared.header().unwrap(),
        owner.runtime.driver.config().validator_set(),
        owner.runtime.driver.config().consensus_parameters(),
    );
    let mut headers = vec![prepared.header().unwrap()];
    headers.extend(descendants);
    let strict = owner
        .runtime
        .driver
        .state()
        .epoch_state_v1()
        .unwrap()
        .strict_context()
        .unwrap();
    let proof =
        trnm_native_execution_v0::test_fixtures::epoch_first_finality_from_runtime(
            &strict,
            &headers,
        );
    let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    let mut owner = owner
        .commit_first_finality_v10(&proof, &mut budget)
        .expect("successor first application strict finality commits native K");
    let cut = owner.committed_checkpoint_v10().unwrap();
    assert_eq!(cut.fields().phase, super::EpochCheckpointPhaseV1::Ordinary);
    assert_eq!(cut.fields().application.height, owner.edge().first_application_height());
    assert_eq!(cut.fields().application.block_id, block_id);
    assert_eq!(cut.fields().ordinary.unwrap().sequence, 2);
    assert!(owner.runtime.driver.state().pending_sign().is_none());
    assert_eq!(
        owner.application().confirmed_committed_head_v0().unwrap().block_id().as_bytes(),
        &block_id
    );
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), 2);
    assert!(directory.path().is_dir());
}
