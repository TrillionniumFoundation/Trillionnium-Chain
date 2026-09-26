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
    let confirmed = owner
        .application()
        .confirm_prepared_epoch_execution_v1(&prepared)
        .unwrap();
    assert_eq!(confirmed.commit_sequence(), None, "V10 must stop before native K");
    assert_eq!(owner.runtime.checkpoint.fields().ordinary.unwrap().sequence, 2);
    assert!(owner.runtime.driver.state().pending_sign().is_none());
    assert_ne!(
        owner.application().confirmed_committed_head_v0().unwrap().block_id().as_bytes(),
        &block_id,
        "V10 Vote alone must not manufacture application finality"
    );
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), 2);
    assert!(directory.path().is_dir());
}


type SuccessorFinalityCaseV11 =
    super::SuccessorFinalizationRuntimeV11<Watermark, Watermark, Watermark, Watermark>;

fn successor_child_proposal_v11(owner: &SuccessorFinalityCaseV11) -> SignedProposalV0 {
    successor_application_proposal_v11(owner, None)
}

fn successor_application_proposal_v11(
    owner: &SuccessorFinalityCaseV11,
    commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
) -> SignedProposalV0 {
    use ed25519_dalek::Signer;
    let parent_header = owner
        .prepared_headers_v11()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let set = owner.set_v11();
    let parameters = owner.parameters_v11();
    let parent = owner
        .application_v11()
        .reopen_prepared_epoch_execution_v1(*parent_header.id().as_bytes())
        .unwrap();
    let request = trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
        trnm_native_application::ChainIdV0::new(set.chain_id().as_str()).unwrap(),
        trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
        parent.overlay_parent_head().unwrap(),
        trnm_native_application::HeightV0::new(parent_header.height().get() + 1),
        parent_header.timestamp_ms() + 1,
        trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let preview = owner
        .application_v11()
        .preview_epoch_descendant_v1(&parent, &request)
        .unwrap();
    let view = View::new(parent_header.view().get() + 1);
    let proposer = trnm_consensus_core::leader_for(set, view);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        trnm_consensus_types::Height::new(request.height().get()),
        if commitment.is_some() { BlockKind::EpochCheckpoint } else { BlockKind::Regular },
        parent_header.id(),
        proposer,
        set.id(),
        parameters.hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        request.timestamp_ms(),
        commitment,
    )
    .unwrap();
    let justify = QcReferenceV0::ordinary(first_apply_qc_v2(&parent_header, set));
    let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
    let index = set
        .validators()
        .iter()
        .position(|validator| validator.id() == proposer)
        .unwrap();
    let witness = ProposalWitnessV0::new(
        &header,
        justify,
        None,
        None,
        SignatureBytes::from_array(
            SigningKey::from_bytes(&[20 + index as u8; 32])
                .sign(root.as_bytes())
                .to_bytes(),
        ),
        set,
        None,
        parameters,
        parent_header.timestamp_ms(),
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
        None,
        parameters,
        parent_header.timestamp_ms(),
    )
    .unwrap()
}

type SuccessorCutoffCaseV11 = (
    tempfile::TempDir,
    SuccessorFinalityCaseV11,
    Key,
    Watermark,
);

fn trace_actual_successor_phase_v11(started: std::time::Instant, phase: &str) {
    eprintln!(
        "V11_PHASE phase={phase} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

#[test]
fn actual_successor_core_finalizes_and_applies_first_new_v11() {
    let started = std::time::Instant::now();
    trace_actual_successor_phase_v11(started, "successor.begin");
    let cutoff = successor_settled_cutoff_case_v11();
    trace_actual_successor_phase_v11(started, "successor.cutoff-ready");
    let checkpoint = successor_checkpoint_continuation_v11(cutoff);
    trace_actual_successor_phase_v11(started, "successor.checkpoint-ready");
    successor_seals_continuation_v11(checkpoint);
    trace_actual_successor_phase_v11(started, "successor.complete");
}

#[inline(never)]
fn successor_settled_cutoff_case_v11() -> Box<SuccessorCutoffCaseV11> {
    let stage = std::time::Instant::now();
    trace_actual_successor_phase_v11(stage, "cutoff.begin");
    // V2--V8 have dedicated negative and crash regressions. V11 needs their
    // genuine durable product output, not another replay of every historical
    // negative probe before the second-epoch continuation can start. Reuse
    // the same positive-only construction used by the V8 product test; it
    // still executes every real owner transition, both handoff signatures,
    // the joint attachment and Journal12 activation.
    let (roles, _) = build_actual_attachment_case_v8();
    trace_actual_successor_phase_v11(stage, "cutoff.attachment-ready");
    let (directory, owner, mut key, watermark) = *activate_live_successor_v10(roles);
    trace_actual_successor_phase_v11(stage, "cutoff.successor-active");

    let first_proposal = successor_first_proposal_v10(&owner);
    let first_id = *first_proposal.block().id().as_bytes();
    let owner = owner.begin_first_application_v10().unwrap();
    let owner = owner.admit_first_proposal_v10(first_proposal).unwrap();
    let (owner, _) = owner.execute_first_proposal_v10().unwrap();
    let (owner, vote) = owner.sign_first_vote_v10(&mut key).unwrap();
    assert!(matches!(vote, trnm_consensus_core::OutboundMessage::Vote(_)));

    let mut owner = owner.begin_finalization_v11().unwrap();
    for _ in 0..2 {
        let proposal = successor_child_proposal_v11(&owner);
        owner = owner.execute_ordinary_child_v11(proposal).unwrap();
        let (next, vote) = owner.sign_child_vote_v11(&mut key).unwrap();
        assert!(matches!(vote, trnm_consensus_core::OutboundMessage::Vote(_)));
        owner = next;
    }
    let headers = owner.prepared_headers_v11().unwrap();
    assert_eq!(headers.len(), 3);
    let qc = first_apply_qc_v2(headers.last().unwrap(), owner.set_v11());
    let owner = owner.observe_front_qc_v11(qc).unwrap();
    let mut owner = owner
        .apply_front_v11(&mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap();
    let checkpoint = owner.settled_checkpoint_v11().unwrap();
    trace_actual_successor_phase_v11(stage, "cutoff.first-front-applied");
    assert_eq!(checkpoint.fields().application.block_id, first_id);
    assert_eq!(
        owner
            .application_v11()
            .confirmed_committed_head_v0()
            .unwrap()
            .block_id()
            .as_bytes(),
        &first_id
    );

    // Keep the same live Core/native/Safety/signer owners and slide the real
    // three-P window until the authenticated snapshot cutoff. No synthetic
    // finality bytes or owner reset is allowed between fronts.
    let geometry = trnm_consensus_types::EpochGeometryV0::new(
        owner.set_v11().epoch(),
        owner.parameters_v11(),
    )
    .unwrap();
    let cutoff_height = geometry
        .checkpoint_height()
        .get()
        .checked_sub(owner.parameters_v11().snapshot_lead_blocks())
        .unwrap();
    while owner.settled_checkpoint_v11().unwrap().fields().application.height < cutoff_height {
        let proposal = successor_child_proposal_v11(&owner);
        owner = owner.execute_ordinary_child_v11(proposal).unwrap();
        let (next, vote) = owner.sign_child_vote_v11(&mut key).unwrap();
        assert!(matches!(vote, trnm_consensus_core::OutboundMessage::Vote(_)));
        owner = next;
        let headers = owner.prepared_headers_v11().unwrap();
        let qc = first_apply_qc_v2(headers.last().unwrap(), owner.set_v11());
        owner = owner.observe_front_qc_v11(qc).unwrap();
        owner = owner
            .apply_front_v11(&mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0())
            .unwrap();
    }
    let cutoff = owner.settled_checkpoint_v11().unwrap();
    trace_actual_successor_phase_v11(stage, "cutoff.target-applied");
    assert_eq!(cutoff.fields().application.height, cutoff_height);
    assert_eq!(
        owner.application_v11().confirmed_committed_head_v0().unwrap().height().get(),
        cutoff_height
    );
    let retained = owner.prepared_headers_v11().unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].height().get(), cutoff_height + 1);
    assert_eq!(retained[1].height().get(), cutoff_height + 2);
    let signer_sequence = watermark.0.lock().unwrap().0.unwrap().sequence();
    assert!(signer_sequence >= 6 && signer_sequence.is_multiple_of(2));

    assert!(directory.path().is_dir());
    Box::new((directory, owner, key, watermark))
}

// Keep the full previous-epoch fixture's stack frame out of this stage. The
// complete, original owners move through the heap; the thread stack is unchanged.
#[inline(never)]
fn successor_checkpoint_continuation_v11(case: Box<SuccessorCutoffCaseV11>) -> Box<SuccessorCutoffCaseV11> {
    let stage = std::time::Instant::now();
    let (directory, mut owner, mut key, watermark) = *case;
    trace_actual_successor_phase_v11(stage, "checkpoint.begin");
    let cutoff = owner.settled_checkpoint_v11().unwrap();
    let cutoff_height = cutoff.fields().application.height;
    let retained = owner.prepared_headers_v11().unwrap();
    let signer_sequence = watermark.0.lock().unwrap().0.unwrap().sequence();
    // Continue to the actual next checkpoint without replacing any owner.
    let selection = owner.application_v11()
        .compute_later_epoch_selection_v1(trnm_native_application::HeightV0::new(cutoff_height))
        .unwrap();
    let commitment = selection.next_epoch_commitment().id();
    let bad = successor_application_proposal_v11(
        &owner, Some(trnm_consensus_types::NextEpochCommitmentHash::new([0xd5; 32])),
    );
    let good = successor_application_proposal_v11(&owner, Some(commitment));
    let checkpoint_id = good.block().id();
    let paths = [
        owner.application_v11().path().to_path_buf(),
        owner.inner.runtime.journal.path_v4().to_path_buf(),
        owner.inner.runtime.ordinary.path().to_path_buf(),
        owner.inner.runtime.source.roles.retired.checkpoint_store.database_path().to_path_buf(),
    ];
    let before: Vec<_> = paths.iter().map(|p| sqlite_logical_image_v3(p)).collect();
    trace_actual_successor_phase_v11(stage, "checkpoint.negative-snapshot-ready");
    let calls = key.calls;
    bad.verify(owner.set_v11(), None, owner.parameters_v11(),
        retained.last().unwrap().timestamp_ms(), &trnm_consensus_crypto::StrictEd25519Verifier).unwrap();
    let error = super::confirm_checkpoint_selection_at_active_cut_v4(
        owner.application_v11(), &cutoff, bad.block().header(),
        owner.set_v11(), owner.parameters_v11(),
    ).unwrap_err();
    assert!(error.to_string().contains("checkpoint commitment differs from actual cutoff selection"));
    assert_eq!(key.calls, calls);
    for (path, expected) in paths.iter().zip(before) {
        assert!(sqlite_logical_image_v3(path) == expected, "invalid selection wrote {}", path.display());
    }
    owner = owner.execute_checkpoint_child_v11(good).unwrap();
    trace_actual_successor_phase_v11(stage, "checkpoint.executed");
    assert_eq!(key.calls, calls, "checkpoint P/Valid must not invoke custody");
    let pending = owner.inner.pending_epoch_commit.as_ref().unwrap();
    assert_eq!(pending.prepared.header().unwrap().id(), checkpoint_id);
    assert_eq!(owner.application_v11().confirm_prepared_epoch_execution_v1(&pending.prepared)
        .unwrap().commit_sequence(), None);
    let (owner, vote) = owner.sign_child_vote_v11(&mut key).unwrap();
    let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else { panic!("checkpoint did not vote") };
    assert_eq!(vote.block_id(), checkpoint_id);
    assert_eq!(key.calls, calls + 1);
    assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), signer_sequence + 2);
    let checkpoint = owner.prepared.last().unwrap();
    let confirmed = owner.application_v11().confirm_prepared_epoch_execution_v1(&checkpoint.prepared).unwrap();
    assert_eq!(confirmed.prepared().header().unwrap().block_kind(), BlockKind::EpochCheckpoint);
    assert_eq!(confirmed.commit_sequence(), None, "checkpoint Vote is not finality");
    assert_eq!(owner.application_v11().confirmed_committed_head_v0().unwrap(), *selection.cutoff_head());
    assert_eq!(owner.inner.runtime.driver.state().application_applied(), owner.inner.runtime.driver.state().finalized());
    assert!(directory.path().is_dir());
    Box::new((directory, owner, key, watermark))
}


#[inline(never)]
fn successor_seals_continuation_v11(case: Box<SuccessorCutoffCaseV11>) {
    let stage = std::time::Instant::now();
    let (directory, mut owner, mut key, watermark) = *case;
    trace_actual_successor_phase_v11(stage, "seals.begin");
    let checkpoint = owner.prepared.last().unwrap().prepared.header().unwrap();
    let calls = key.calls;
    let initial_sequence = watermark.0.lock().unwrap().0.unwrap().sequence();
    let paths = [
        owner.application_v11().path().to_path_buf(),
        owner.inner.runtime.journal.path_v4().to_path_buf(),
        owner.inner.runtime.ordinary.path().to_path_buf(),
        owner.inner.runtime.source.roles.retired.checkpoint_store.database_path().to_path_buf(),
    ];
    for index in 0..2 {
        let parent = owner.seals.last().map(|p| p.block().header()).unwrap_or(&checkpoint).clone();
        let kind = if index == 0 { BlockKind::EpochSeal1 } else { BlockKind::EpochSeal2 };
        // Both invalid proposals have real signatures under the current set.
        // Rejection must precede native/Safety mutation and irreversible key use.
        for (nonempty, wrong_state) in [(true, false), (false, true)] {
            let bad = genuine_seal_for_parent_v5(&parent, owner.set_v11(), owner.parameters_v11(),
                kind, nonempty, wrong_state);
            let before: Vec<_> = paths.iter().map(|p| sqlite_logical_image_v3(p)).collect();
            let before_calls = key.calls;
            assert!(owner.verify_next_seal_v11(&bad).is_err());
            assert_eq!(key.calls, before_calls);
            for (path, image) in paths.iter().zip(before) {
                assert!(sqlite_logical_image_v3(path) == image, "invalid seal wrote {}", path.display());
            }
        }
        trace_actual_successor_phase_v11(
            stage,
            if index == 0 {
                "seals.first-negatives-complete"
            } else {
                "seals.second-negatives-complete"
            },
        );
        let proposal = genuine_seal_for_parent_v5(&parent, owner.set_v11(), owner.parameters_v11(),
            kind, false, false);
        let seal_id = proposal.block().id();
        let preceding = owner.prepared[0].prepared.header().unwrap();
        owner = owner.admit_seal_proposal_v11(proposal).unwrap();
        assert_eq!(key.calls, calls + index);
        assert!(owner.inner.runtime.driver.state().pending_sign().is_none());
        assert_eq!(owner.inner.runtime.driver.state().pending_finalization().unwrap()
            .proof().finalized_block().header(), &preceding);
        owner = owner.apply_preceding_seal_front_v11(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()).unwrap();
        assert_eq!(owner.application_v11().confirmed_committed_head_v0().unwrap()
            .block_id().as_bytes(), preceding.id().as_bytes());
        assert!(owner.inner.runtime.driver.state().payload_terminal_fact(seal_id).is_none());
        assert!(owner.inner.runtime.driver.state().payload_validation_completions().iter()
            .all(|p| p.id().block_id() != seal_id));
        assert_eq!(key.calls, calls + index, "seal admission/apply must not use custody");
        let (next, vote) = owner.sign_seal_vote_v11(&mut key).unwrap();
        owner = next;
        let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else { panic!("seal did not Vote") };
        assert_eq!(vote.block_id(), seal_id);
        assert_eq!(key.calls, calls + index + 1);
        assert_eq!(watermark.0.lock().unwrap().0.unwrap().sequence(), initial_sequence + 2 * (index as u64 + 1));
        assert_eq!(owner.prepared.len(), 2 - index);
        assert!(owner.prepared.iter().all(|p| p.prepared.header().unwrap().id() != seal_id));
    }
    let terminal = owner.seals[1].block().header().clone();
    let qc = first_apply_qc_v2(&terminal, owner.set_v11());
    owner = owner.observe_checkpoint_finality_v11(qc).unwrap();
    trace_actual_successor_phase_v11(stage, "seals.checkpoint-finality-observed");
    let pending = owner.inner.runtime.driver.state().pending_finalization().unwrap();
    let original_proof = pending.proof().id();
    assert_eq!(pending.proof().finalized_block().header(), &checkpoint);
    assert_eq!(pending.proof().child().header(), owner.seals[0].block().header());
    assert_eq!(pending.proof().grandchild().header(), &terminal);
    assert!(owner.inner.runtime.driver.state().pending_sign().is_none());
    assert_eq!(key.calls, calls + 2);
    assert_eq!(owner.application_v11().confirmed_committed_head_v0().unwrap().height().get(),
        checkpoint.height().get() - 1);
    let prepared = &owner.prepared[0].prepared;
    assert_eq!(owner.application_v11().confirm_prepared_epoch_execution_v1(prepared)
        .unwrap().commit_sequence(), None, "Core checkpoint proof is not native commit");
    assert!(owner.settled_checkpoint_v11().is_err());
    assert!(owner.confirm_ordinary_apply_phase_v11().is_err(),
        "ordinary apply must not commit a checkpoint or mint retirement");
    let before_calls = key.calls;
    let before_mark = watermark.0.lock().unwrap().0.unwrap();
    // The dedicated product guard rejects a different retained seal order
    // without mutating a database or invoking custody.
    let before: Vec<_> = paths.iter().map(|p| sqlite_logical_image_v3(p)).collect();
    owner.seals.swap(0, 1);
    assert!(owner.confirm_pre_handoff_phase_v11().is_err());
    owner.seals.swap(0, 1);
    assert_eq!(key.calls, before_calls);
    for (path, image) in paths.iter().zip(before) {
        assert!(sqlite_logical_image_v3(path) == image, "invalid commit phase wrote {}", path.display());
    }
    owner = owner.apply_pre_handoff_checkpoint_v11(
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()).unwrap();
    trace_actual_successor_phase_v11(stage, "seals.pre-handoff-applied");
    let joined = owner.settled_pre_handoff_cut_v11().unwrap();
    assert_eq!(joined.fields().application.block_id, *checkpoint.id().as_bytes());
    assert_eq!(joined.fields().application.height, checkpoint.height().get());
    assert_eq!(key.calls, before_calls, "pre-handoff commit must not invoke a signer");
    assert_eq!(watermark.0.lock().unwrap().0.unwrap(), before_mark);
    assert!(owner.prepared.is_empty());
    assert!(owner.inner.runtime.driver.state().pending_sign().is_none());
    assert!(owner.inner.runtime.driver.state().pending_finalize().is_none());
    let recovered = owner.application_v11().recover_later_epoch_pre_handoff_v1(
        *checkpoint.id().as_bytes()).unwrap();
    trace_actual_successor_phase_v11(stage, "seals.pre-handoff-recovered");
    assert_eq!(recovered.header(), &checkpoint);
    assert_eq!(recovered.strict_context().checkpoint_finality_proof_id(), original_proof);
    assert_eq!(recovered.commit_sequence(), joined.fields().application.commit_sequence);
    assert_eq!(recovered.committed_owner_cut_ref_v1(), owner.pre_handoff.as_ref().unwrap().committed_owner_cut_ref_v1());
    assert_eq!(owner.application_v11().confirmed_committed_head_v0().unwrap(), *recovered.head());
    assert!(owner.settled_checkpoint_v11().is_err(), "pre-handoff is not ordinary readiness");
    assert!(owner.confirm_pre_handoff_phase_v11().is_err(), "applied checkpoint cannot be replayed as pending");

    // A correctly linked independent checkpoint is not evidence that its
    // claimed signer watermark actually exists. Advance only that owner,
    // leaving the genuine signer journal and external watermark unchanged.
    let mut ahead = *joined.fields();
    ahead.generation += 1;
    ahead.predecessor_checksum = joined.checksum();
    let ordinary = ahead.ordinary.as_mut().unwrap();
    ordinary.sequence += 2;
    ordinary.chain_checksum[0] ^= 0x40;
    let ahead = EpochNodeCheckpointV1::new(ahead).unwrap();
    ahead.validate_successor_of(&joined).unwrap();
    owner.inner.runtime.source.roles.retired.checkpoint_store
        .compare_and_advance(&joined, &ahead).unwrap();
    owner.inner.runtime.checkpoint = ahead;
    let before_calls = key.calls;
    let before_mark = watermark.0.lock().unwrap().0.unwrap();
    let error = owner.settled_pre_handoff_cut_v11().unwrap_err();
    assert!(error.to_string().contains("successor ordinary custody differs from independent checkpoint"),
        "unexpected rejection: {error:#}");
    assert!(owner.inner.runtime.fenced);
    assert_eq!(key.calls, before_calls);
    assert_eq!(watermark.0.lock().unwrap().0.unwrap(), before_mark);
    assert!(owner.settled_pre_handoff_cut_v11().is_err(), "mismatch must stay fenced");
    assert!(directory.path().is_dir());
}
