// M06 producer acceptance for the M08 bounded mixed-prefix resolver.

#[inline(never)]
fn prepare_repeated_descendant(
    app: &DurableNativeApplicationV0,
    parent: &crate::PreparedNativeEpochExecutionV1,
    parent_header: &BlockHeader,
    set: &ValidatorSet,
    kind: BlockKind,
    commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
) -> (crate::PreparedNativeEpochExecutionV1, BlockHeader) {
    prepare_repeated_descendant_with_transactions(
        app,
        parent,
        parent_header,
        set,
        kind,
        commitment,
        Vec::new(),
    )
}

#[inline(never)]
fn prepare_repeated_descendant_with_transactions(
    app: &DurableNativeApplicationV0,
    parent: &crate::PreparedNativeEpochExecutionV1,
    parent_header: &BlockHeader,
    set: &ValidatorSet,
    kind: BlockKind,
    commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
    transactions: Vec<Vec<u8>>,
) -> (crate::PreparedNativeEpochExecutionV1, BlockHeader) {
    let height = parent_header.height().get() + 1;
    let request = NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(set.chain_id().as_str()).unwrap(),
        GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
        parent.overlay_parent_head().unwrap(),
        HeightV0::new(height),
        height * 1000,
        trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        transactions,
    )
    .unwrap();
    let preview = app.preview_epoch_descendant_v1(parent, &request).unwrap();
    let header = checkpoint_like_header_at_view(
        set,
        kind,
        height,
        parent_header.id(),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        commitment,
        request.timestamp_ms(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        parent_header.view().get() + 1,
    );
    let prepared = app
        .execute_epoch_descendant_v1(
            parent,
            descendant_execution_request(&request, &header),
            &header,
        )
        .unwrap();
    (prepared, header)
}

struct RepeatedCheckpointFixture {
    application: DurableNativeApplicationV0,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    parent: BlockHeader,
    checkpoint: BlockHeader,
    terminal: BlockHeader,
    commitment: Vec<u8>,
    finality: Vec<u8>,
    anchor: Vec<u8>,
    old_checkpoint: BlockId,
    old_binding: [u8; 32],
    c22_header: BlockHeader,
    c22_proof: Vec<u8>,
    c22_sequence: u64,
    trust_anchor: trnm_state_sync_v0::NativeTrustAnchorV1,
    other_trust_anchor: trnm_state_sync_v0::NativeTrustAnchorV1,
}

#[inline(never)]
fn advance_repeated_checkpoint(
    seed: Box<LaterDescendantFixture>,
) -> Box<RepeatedCheckpointFixture> {
    advance_repeated_checkpoint_with_transactions(seed, &[])
}

#[inline(never)]
fn advance_repeated_checkpoint_with_transactions(
    seed: Box<LaterDescendantFixture>,
    c25_transactions: &[Vec<u8>],
) -> Box<RepeatedCheckpointFixture> {
    let LaterDescendantFixture {
        application: app,
        prepared: c22,
        checkpoint_header: old_checkpoint,
        first_header,
        c22_header,
        c23_header,
        c24_header,
        c22_proof,
        validator_set: old_set,
        parameters,
        trust_anchor,
        other_trust_anchor,
        ..
    } = *seed;
    let old_requirements = app
        .inspect_later_epoch_application_edge_requirements_v1(*old_checkpoint.id().as_bytes())
        .unwrap();
    let old_binding = old_requirements.successor_binding();
    let mut headers = std::collections::BTreeMap::from([
        (21, first_header),
        (22, c22_header.clone()),
        (23, c23_header),
        (24, c24_header),
    ]);
    let mut prepared = std::collections::BTreeMap::new();
    prepared.insert(22, c22);
    for height in [23, 24] {
        prepared.insert(
            height,
            app.reopen_prepared_epoch_execution_v1(*headers[&height].id().as_bytes())
                .unwrap(),
        );
    }
    for height in 25..=27 {
        let (p, header) = prepare_repeated_descendant_with_transactions(
            &app,
            &prepared[&(height - 1)],
            &headers[&(height - 1)],
            &old_set,
            BlockKind::Regular,
            None,
            if height == 25 {
                c25_transactions.to_vec()
            } else {
                Vec::new()
            },
        );
        prepared.insert(height, p);
        headers.insert(height, header);
    }
    let mut c22_sequence = 0;
    for height in 22..=25 {
        let proof = ordinary_later_proof(
            &headers[&(height - 1)],
            &[
                headers[&height].clone(),
                headers[&(height + 1)].clone(),
                headers[&(height + 2)].clone(),
            ],
            &old_set,
            &parameters,
        );
        if height == 22 {
            assert_eq!(proof, c22_proof);
        }
        let committed = app
            .commit_epoch_finality_bytes_v1(
                &prepared[&height],
                &proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        if height == 22 {
            c22_sequence = committed.commit_sequence();
        }
    }
    let cutoff = app.read_finalized_by_height_v1(HeightV0::new(25)).unwrap();
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap(),
        cutoff.finalized_head_v1().unwrap(),
    );
    let derived = cutoff.derive_next_epoch_v1(&app).unwrap();
    let new_set = derived.new_validator_set;
    let commitment = derived.commitment;
    assert_eq!(derived.new_parameters, parameters);
    assert_eq!(new_set.epoch(), Epoch::new(3));
    assert_ne!(new_set.id(), old_set.id());
    assert_eq!(commitment.fields().snapshot_cutoff_height, Height::new(25));
    assert_eq!(
        commitment.fields().snapshot_state_root.as_bytes(),
        cutoff.finalized_head_v1().unwrap().state_root().as_bytes(),
    );
    let (_checkpoint_p, checkpoint) = prepare_repeated_descendant(
        &app,
        &prepared[&27],
        &headers[&27],
        &old_set,
        BlockKind::EpochCheckpoint,
        Some(commitment.id()),
    );
    let (payload, receipts, evidence) = empty_roots();
    let seal1 = checkpoint_like_header_at_view(
        &old_set,
        BlockKind::EpochSeal1,
        29,
        checkpoint.id(),
        checkpoint.state_root(),
        Some(commitment.id()),
        29_000,
        payload,
        receipts,
        evidence,
        9,
    );
    let terminal = checkpoint_like_header_at_view(
        &old_set,
        BlockKind::EpochSeal2,
        30,
        seal1.id(),
        checkpoint.state_root(),
        Some(commitment.id()),
        30_000,
        payload,
        receipts,
        evidence,
        10,
    );
    headers.insert(28, checkpoint.clone());
    headers.insert(29, seal1.clone());
    for height in [26, 27] {
        let proof = ordinary_later_proof(
            &headers[&(height - 1)],
            &[
                headers[&height].clone(),
                headers[&(height + 1)].clone(),
                headers[&(height + 2)].clone(),
            ],
            &old_set,
            &parameters,
        );
        let _committed = app
            .commit_epoch_finality_bytes_v1(
                &prepared[&height],
                &proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
    }
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap().height().get(),
        27
    );
    let parent = headers[&27].clone();
    let finality = ordinary_later_proof(
        &parent,
        &[checkpoint.clone(), seal1, terminal.clone()],
        &old_set,
        &parameters,
    );
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old_set.genesis_hash(),
        chain_id: old_set.chain_id(),
        old_epoch: old_set.epoch(),
        new_epoch: new_set.epoch(),
        old_protocol_version: old_set.protocol_version(),
        new_protocol_version: new_set.protocol_version(),
        old_validator_set_hash: old_set.id(),
        new_validator_set_hash: new_set.id(),
        old_consensus_parameters_hash: parameters.hash(),
        new_consensus_parameters_hash: parameters.hash(),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_id: checkpoint.id(),
        checkpoint_state_root: checkpoint.state_root(),
        next_epoch_commitment_digest: commitment.id(),
        terminal_old_height: terminal.height(),
        terminal_old_block_id: terminal.id(),
        terminal_old_qc_digest: qc(&terminal, &old_set).id(),
        terminal_old_view: terminal.view(),
        activation_height: Height::new(31),
        initial_new_view: View::new(1),
    })
    .unwrap();
    let shares = |set: &ValidatorSet, root: trnm_consensus_types::SigningRoot| {
        set.validators()
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, validator)| {
                SignatureShareV0::new(
                    validator.id(),
                    Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect()
    };
    let handoff = HandoffCertificateV0::new(
        descriptor.clone(),
        shares(&old_set, descriptor.old_set_signing_root()),
        shares(&new_set, descriptor.new_set_signing_root()),
        &old_set,
        &new_set,
    )
    .unwrap();
    let anchor = EpochAnchorAuthorizationKernelV0::from_parts_v0(
        terminal.clone(),
        qc(&terminal, &old_set),
        handoff,
        &old_set,
        &new_set,
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap();
    let commitment = commitment.try_cev0_bytes().unwrap();
    let observation = app
        .verify_later_epoch_checkpoint_finality_v1(
            app.inspect_later_epoch_checkpoint_context_v1().unwrap(),
            &parent.try_cev0_bytes().unwrap(),
            &checkpoint.try_cev0_bytes().unwrap(),
            &finality,
            &anchor,
            &commitment,
            &new_set.try_cev0_bytes().unwrap(),
            &parameters.canonical_bytes(),
        )
        .expect("C28 must derive its old epoch from the exact mixed prefix");
    let committed = app
        .commit_later_epoch_checkpoint_finality_v1(&observation)
        .expect("second later checkpoint must commit its own authority");
    assert_eq!(committed.head().height().get(), 28);
    Box::new(RepeatedCheckpointFixture {
        application: app,
        old_set,
        new_set,
        parameters,
        parent,
        checkpoint,
        terminal,
        commitment,
        finality,
        anchor,
        old_checkpoint: old_checkpoint.id(),
        old_binding,
        c22_header,
        c22_proof,
        c22_sequence,
        trust_anchor,
        other_trust_anchor,
    })
}

#[inline(never)]
fn complete_repeated_handoff(path: &std::path::Path, fixture: Box<RepeatedCheckpointFixture>) {
    let RepeatedCheckpointFixture {
        application,
        old_set,
        new_set,
        parameters,
        parent,
        checkpoint,
        terminal,
        commitment,
        finality,
        anchor,
        old_checkpoint,
        old_binding,
        c22_header,
        c22_proof,
        c22_sequence,
        trust_anchor,
        other_trust_anchor,
    } = *fixture;
    drop(application);
    let app = DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1())
        .expect("Installed C28 cold reopen");
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap().height().get(),
        28
    );
    let requirements = app
        .inspect_later_epoch_application_edge_requirements_v1(*checkpoint.id().as_bytes())
        .unwrap();
    assert_eq!(requirements.predecessor_edge(), old_binding);
    let edge = app
        .require_later_epoch_application_edge_v1(&requirements)
        .unwrap();
    let first_request =
        |height: u64, terminal_id: BlockId, active: trnm_consensus_types::ValidatorSetId| {
            NativeEpochBlockPreviewRequestV1::new(
                ChainIdV0::new(new_set.chain_id().as_str()).unwrap(),
                GenesisHashV0::new(*new_set.genesis_hash().as_bytes()).unwrap(),
                edge.application_parent_v1(),
                BlockIdV0::new(*terminal_id.as_bytes()).unwrap(),
                HeightV0::new(30),
                Hash32V0::new(edge.successor_binding()),
                HeightV0::new(height),
                height * 1000,
                trnm_native_application::ValidatorSetIdV0::new(*active.as_bytes()).unwrap(),
                Vec::new(),
            )
        };
    if let Ok(bad_terminal) = first_request(31, checkpoint.id(), new_set.id()) {
        assert!(
            app.preview_later_epoch_block_v1(&edge, &bad_terminal)
                .is_err(),
            "C31 must name the exact authenticated C30 terminal"
        );
    }
    let bad_set = first_request(31, terminal.id(), old_set.id()).unwrap();
    assert!(
        app.preview_later_epoch_block_v1(&edge, &bad_set).is_err(),
        "C31 cannot retain the predecessor target configuration"
    );
    if let Ok(bad_jump) = first_request(32, terminal.id(), new_set.id()) {
        assert!(
            app.preview_later_epoch_block_v1(&edge, &bad_jump).is_err(),
            "first-new height must be exactly C28+3"
        );
    }
    let request = first_request(31, terminal.id(), new_set.id()).unwrap();
    let preview = app.preview_later_epoch_block_v1(&edge, &request).unwrap();
    let h31 = checkpoint_like_header_at_view(
        &new_set,
        BlockKind::EpochHandoff,
        31,
        terminal.id(),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        None,
        31_000,
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        1,
    );
    let p31 = app
        .prepare_later_epoch_first_new_block_v1(
            &edge,
            NativeEpochBlockExecutionRequestV1::new(
                request,
                BlockIdV0::new(*h31.id().as_bytes()).unwrap(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap(),
            &h31,
        )
        .unwrap();
    let (p32, h32) =
        prepare_repeated_descendant(&app, &p31, &h31, &new_set, BlockKind::Regular, None);
    let (p33, h33) =
        prepare_repeated_descendant(&app, &p32, &h32, &new_set, BlockKind::Regular, None);
    let (_p34, h34) =
        prepare_repeated_descendant(&app, &p33, &h33, &new_set, BlockKind::Regular, None);
    let prepared_target = h33.id();
    let first_proof = later_epoch_first_finality(
        &old_set,
        &parameters,
        &old_set.try_cev0_bytes().unwrap(),
        &new_set.try_cev0_bytes().unwrap(),
        &parameters.canonical_bytes(),
        &parent.try_cev0_bytes().unwrap(),
        &finality,
        &anchor,
        &commitment,
        &[h31.clone(), h32.clone(), h33.clone()],
    );
    let committed = app
        .commit_epoch_finality_bytes_v1(
            &p31,
            &first_proof,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .expect("C31 strict first-new finality");
    assert_eq!(committed.head().height().get(), 31);
    drop(app);
    let app = DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1())
        .expect("Consumed C31 cold reopen");
    assert_native_handoff_live_sync(&app, &trust_anchor, old_checkpoint, &h31);
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap().height().get(),
        31
    );
    let p32 = app
        .reopen_prepared_epoch_execution_v1(*h32.id().as_bytes())
        .unwrap();
    let ordinary_proof =
        ordinary_later_proof(&h31, &[h32.clone(), h33, h34], &new_set, &parameters);
    let committed = app
        .commit_epoch_finality_bytes_v1(
            &p32,
            &ordinary_proof,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .expect("C32 strict ordinary finality");
    assert_eq!(committed.head().height().get(), 32);
    drop(app);
    let app = DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1())
        .expect("Progressed C32 cold reopen");
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap().height().get(),
        32
    );
    let historical = app
        .inspect_later_epoch_application_edge_requirements_v1(*old_checkpoint.as_bytes())
        .expect("historical B recovery must cross C31→C28");
    assert_eq!(historical.successor_binding(), old_binding);
    let recovered = app
        .recover_later_epoch_application_edge_v1(&historical)
        .unwrap();
    assert_eq!(recovered.first_application_height(), 21);
    let old_prepared = app
        .reopen_prepared_epoch_execution_v1(*c22_header.id().as_bytes())
        .unwrap();
    let retry = app
        .commit_epoch_finality_bytes_v1(
            &old_prepared,
            &c22_proof,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .expect("exact C22 retry at C32 must retain the old epoch authority");
    assert_eq!(retry.commit_sequence(), c22_sequence);
    assert_eq!(
        app.confirmed_committed_head_v0().unwrap().height().get(),
        32
    );
    let sql = rusqlite::Connection::open(path).unwrap();
    let lineage: Vec<u8> = sql
        .query_row(
            "SELECT edge_lineage FROM native_durable_execution_p_v1 WHERE block_id=?",
            [h32.id().as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(u32::from_be_bytes(lineage[..4].try_into().unwrap()), 3);
    let first_count: i64 = sql
        .query_row(
            "SELECT COUNT(*) FROM native_later_epoch_application_finality_v1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(first_count, 2);
    let retained_first: Vec<u8> = sql
        .query_row(
            "SELECT proof FROM native_later_epoch_application_finality_v1 WHERE block_id=?",
            [h31.id().as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained_first, first_proof);
    let retained: Vec<u8> = sql
        .query_row(
            "SELECT proof FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?",
            [h32.id().as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, ordinary_proof);
    assert_signature_mutant_is_canonical(&ordinary_proof, &h31, &h32, &new_set, &parameters);
    let first_old: Vec<u8> = sql
        .query_row(
            "SELECT proof FROM native_later_epoch_application_finality_v1 WHERE block_id=(SELECT block_id FROM native_durable_execution_p_v1 WHERE target_height=?)",
            [21_u64.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let exported = assert_repeated_finality_exports(
        &app,
        old_checkpoint,
        &h32,
        &checkpoint,
        prepared_target,
        [
            (21, first_old.as_slice()),
            (22, c22_proof.as_slice()),
            (31, first_proof.as_slice()),
            (32, ordinary_proof.as_slice()),
        ],
    );
    assert_eq!(exported.target_commit_sequence, committed.commit_sequence());
    let verified = assert_repeated_finality_consumer(
        &trust_anchor,
        &other_trust_anchor,
        &exported,
        &new_set,
        &parameters,
    );
    let live_bytes = assert_current_native_live_sync(
        &app,
        path,
        &h32,
        old_checkpoint,
        prepared_target,
        &verified,
    );
    let historical_bytes = assert_native_historical_sync(
        &app,
        &trust_anchor,
        &other_trust_anchor,
        &exported,
        &verified,
        &live_bytes,
    );
    drop(app);
    let app = DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1())
        .expect("export must preserve the genuine C32 store");
    assert_eq!(
        app.export_historical_replay_v1(
            BlockIdV0::new(*old_checkpoint.as_bytes()).unwrap(),
            BlockIdV0::new(*h32.id().as_bytes()).unwrap(),
        )
        .unwrap()
        .encode_v1()
        .unwrap(),
        historical_bytes,
        "cold reopen must retain exact historical headers, bodies and authority bytes",
    );
    assert_eq!(
        app.export_current_native_live_v1(BlockIdV0::new(*h32.id().as_bytes()).unwrap())
            .unwrap(),
        live_bytes,
        "cold reopen must export byte-identical current live leaves",
    );
    assert_eq!(
        app.export_epoch_finality_path_v1(
            BlockIdV0::new(*old_checkpoint.as_bytes()).unwrap(),
            BlockIdV0::new(*h32.id().as_bytes()).unwrap(),
        )
        .unwrap(),
        exported,
        "cold reopen must export the same retained canonical bytes"
    );
    drop(app);
    assert_repeated_prefix_mutants(path, &checkpoint, &h31, &h32);
}

#[inline(never)]
fn assert_repeated_finality_exports(
    app: &DurableNativeApplicationV0,
    anchor: BlockId,
    target: &BlockHeader,
    checkpoint: &BlockHeader,
    prepared_target: BlockId,
    proofs: [(u64, &[u8]); 4],
) -> crate::NativeEpochFinalityPathV1 {
    let block = |id: BlockId| BlockIdV0::new(*id.as_bytes()).unwrap();
    let decode = |bytes: &[u8]| trnm_consensus_types::decode_block_header_v0_exact(bytes).unwrap();
    let before = app.confirmed_committed_head_v0().unwrap();
    let exported = app
        .export_epoch_finality_path_v1(block(anchor), block(target.id()))
        .expect("C18→C32 must retain both later handoffs and every ordinary proof");
    assert_eq!(decode(&exported.anchor_header_cev0).id(), anchor);
    assert_eq!(decode(&exported.target_header_cev0), *target);
    assert_eq!(exported.target_schema_version, 10);
    assert_ne!(exported.target_p_digest, [0; 32]);
    let heights: Vec<_> = exported
        .steps
        .iter()
        .map(|step| decode(&step.header_cev0).height().get())
        .collect();
    assert_eq!(heights, [21, 22, 23, 24, 25, 26, 27, 28, 31, 32]);
    for step in &exported.steps {
        let header = decode(&step.header_cev0);
        let parent = decode(&step.consensus_parent_header_cev0);
        assert_eq!(header.parent_id(), parent.id());
        assert_eq!(header.height().get(), parent.height().get() + 1);
        assert_eq!(
            step.epoch_evidence.is_some(),
            matches!(header.height().get(), 21 | 31)
        );
        assert_ne!(step.record_digest, [0; 32]);
        if let Some((_, original)) = proofs
            .iter()
            .find(|(height, _)| *height == header.height().get())
        {
            assert_eq!(step.proof, *original);
        }
    }
    let first = decode(&exported.steps[0].header_cev0);
    let old_ordinary = decode(&exported.steps[1].header_cev0);
    let historical = app
        .export_epoch_finality_path_v1(block(anchor), block(old_ordinary.id()))
        .expect("historical C18→C22 remains available at head C32");
    assert_eq!(historical.steps, exported.steps[..2]);
    let before_second_handoff = app
        .export_epoch_finality_path_v1(block(first.id()), block(checkpoint.id()))
        .expect("historical C21→C28 remains available at head C32");
    assert_eq!(before_second_handoff.steps, exported.steps[1..8]);
    for (from, to) in [
        (anchor, anchor),
        (target.id(), anchor),
        (anchor, prepared_target),
    ] {
        assert!(app
            .export_epoch_finality_path_v1(block(from), block(to))
            .is_err());
    }
    assert_eq!(
        app.export_epoch_finality_path_v1(block(anchor), block(target.id()))
            .unwrap(),
        exported,
        "repeated export preserves original bytes"
    );
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), before);
    exported
}

#[inline(never)]
fn assert_repeated_finality_consumer(
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    other_anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    exported: &crate::NativeEpochFinalityPathV1,
    target_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> trnm_state_sync_v0::VerifiedNativeTrustPathV1 {
    use trnm_poco_node_production_v0::NativeEpochFinalityPathV1;
    use trnm_state_sync_v0::NativeTrustPathLimitsV1;

    let exported = m15_finality_transport_copy(exported);
    let verify = |path: &NativeEpochFinalityPathV1, limits| {
        trnm_poco_node_production_v0::verify_retained_native_finality_path_v1(
            anchor,
            path,
            limits,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
    };
    let verified = verify(&exported, NativeTrustPathLimitsV1::default())
        .expect("M15 must strictly consume the real repeated M08 path from pinned C18");
    assert_eq!(
        verified.terminal_header().try_cev0_bytes().unwrap(),
        exported.target_header_cev0
    );
    assert_eq!(verified.terminal_validator_set(), target_set);
    assert_eq!(verified.terminal_parameters(), parameters);
    assert_ne!(other_anchor.pin(), anchor.pin());
    assert!(
        trnm_poco_node_production_v0::verify_retained_native_finality_path_v1(
            other_anchor,
            &exported,
            NativeTrustPathLimitsV1::default(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err(),
        "a separately pinned genuine C17 anchor cannot authorize a path claiming C18"
    );
    for mutation in [
        "anchor",
        "target",
        "parent",
        "new-configuration",
        "old-configuration",
        "proof",
        "reorder",
        "truncate",
        "missing-epoch-evidence",
        "unexpected-epoch-evidence",
        "schema",
    ] {
        let mut changed = exported.clone();
        match mutation {
            "anchor" => changed.anchor_header_cev0 = changed.steps[0].header_cev0.clone(),
            "target" => changed.target_header_cev0 = changed.steps[8].header_cev0.clone(),
            "parent" => {
                changed.steps[9].consensus_parent_header_cev0 = changed.anchor_header_cev0.clone();
            }
            "new-configuration" => {
                changed.steps[0]
                    .epoch_evidence
                    .as_mut()
                    .unwrap()
                    .new_validator_set = target_set.try_cev0_bytes().unwrap();
            }
            "old-configuration" => {
                changed.steps[0]
                    .epoch_evidence
                    .as_mut()
                    .unwrap()
                    .old_validator_set = target_set.try_cev0_bytes().unwrap();
            }
            "proof" => *changed.steps[9].proof.last_mut().unwrap() ^= 1,
            "reorder" => changed.steps.swap(2, 3),
            "truncate" => {
                changed.steps.pop().unwrap();
            }
            "missing-epoch-evidence" => changed.steps[0].epoch_evidence = None,
            "unexpected-epoch-evidence" => {
                changed.steps[1].epoch_evidence = changed.steps[0].epoch_evidence.clone();
            }
            "schema" => changed.target_schema_version = 9,
            _ => unreachable!(),
        }
        assert!(
            verify(&changed, NativeTrustPathLimitsV1::default()).is_err(),
            "M15 must refuse untrusted path mutant {mutation}"
        );
    }
    for limits in [
        NativeTrustPathLimitsV1 {
            maximum_links: exported.steps.len() - 1,
            ..NativeTrustPathLimitsV1::default()
        },
        NativeTrustPathLimitsV1 {
            maximum_total_bytes: 1,
            ..NativeTrustPathLimitsV1::default()
        },
    ] {
        assert!(verify(&exported, limits).is_err());
    }
    let mut local_metadata = exported.clone();
    local_metadata.target_p_digest = [91; 32];
    local_metadata.target_commit_sequence = 17;
    for step in &mut local_metadata.steps {
        step.record_digest = [92; 32];
    }
    assert_eq!(
        verify(&local_metadata, NativeTrustPathLimitsV1::default())
            .expect("local storage identifiers cannot replace or revoke signed consensus evidence")
            .terminal_header(),
        verified.terminal_header()
    );
    verified
}

fn m15_finality_transport_copy(
    exported: &crate::NativeEpochFinalityPathV1,
) -> trnm_poco_node_production_v0::NativeEpochFinalityPathV1 {
    // The dev dependency compiles the native library separately from its unit
    // test crate. Copy only public transport fields across that type identity;
    // signed bytes and untrusted local metadata remain exactly as exported.
    trnm_poco_node_production_v0::NativeEpochFinalityPathV1 {
        anchor_header_cev0: exported.anchor_header_cev0.clone(),
        target_header_cev0: exported.target_header_cev0.clone(),
        target_schema_version: exported.target_schema_version,
        target_p_digest: exported.target_p_digest,
        target_commit_sequence: exported.target_commit_sequence,
        steps: exported
            .steps
            .iter()
            .map(
                |step| trnm_poco_node_production_v0::NativeEpochFinalityStepV1 {
                    header_cev0: step.header_cev0.clone(),
                    consensus_parent_header_cev0: step.consensus_parent_header_cev0.clone(),
                    proof: step.proof.clone(),
                    record_digest: step.record_digest,
                    epoch_evidence: step.epoch_evidence.clone(),
                },
            )
            .collect(),
    }
}

include!("native_live_sync_tests.rs");
include!("native_historical_sync_tests.rs");
include!("native_historical_replay_tests.rs");

fn rehash_repeated_successor(sql: &rusqlite::Connection, binding: &[u8]) {
    let mut fields: Vec<Vec<u8>> = sql.query_row(
        "SELECT successor_binding,predecessor_edge,checkpoint_block,checkpoint_p_digest,checkpoint_commit_sequence,
         checkpoint_height,checkpoint_root,checkpoint_commit_id,terminal_height,terminal_block,first_height,
         proof_context_digest,successor_context_digest,authority_digest FROM native_later_epoch_edge_v1 WHERE successor_binding=?",
        [binding], |row| (0..14).map(|i| row.get(i)).collect(),
    ).unwrap();
    fields.insert(0, native_checkpoint_fixture_config_v1().store_id().to_vec());
    let digest = trnm_finality_types::hash_domain(
        "trnm.native-application.later-epoch-successor-record.v1",
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    sql.execute(
        "UPDATE native_later_epoch_edge_v1 SET record_digest=? WHERE successor_binding=?",
        rusqlite::params![digest.as_slice(), binding],
    )
    .unwrap();
}

// Recompute the mutated P's local checksums; authenticated cross-row joins and
// the exact prefix must still refuse it. This does not invent replacement proof.
fn rehash_repeated_p(sql: &rusqlite::Connection, block: &[u8]) {
    let mut fields: Vec<Vec<u8>> = sql.query_row(
        "SELECT store_id,p_sequence,artifact_kind,artifact_digest,parent_kind,parent_height,parent_block,parent_root,parent_commit_id,parent_p_digest,
         consensus_parent_height,consensus_parent_block,target_height,lineage_digest,snapshot_digest,replay_commands,replay_nonces,lifecycle,target_set,target_parameters,header
         FROM native_durable_execution_p_v1 WHERE block_id=?",
        [block], |row| {
            (0..21).map(|i| {
                if i == 2 || i == 4 { return Ok(vec![row.get::<_, i64>(i)? as u8]); }
                if i == 9 {
                    return Ok(match row.get::<_, Option<Vec<u8>>>(i)? {
                        None => vec![0], Some(bytes) => [&[1_u8][..], bytes.as_slice()].concat(),
                    });
                }
                row.get(i)
            }).collect()
        },
    ).unwrap();
    for index in [15, 16, 17, 20] {
        fields[index] = sha2::Sha256::digest(&fields[index]).to_vec();
    }
    fields[18] = trnm_consensus_types::decode_validator_set_v0_exact(&fields[18])
        .unwrap()
        .id()
        .as_bytes()
        .to_vec();
    fields[19] = decode_consensus_parameters_v0_exact(&fields[19])
        .unwrap()
        .hash()
        .as_bytes()
        .to_vec();
    let digest = trnm_finality_types::hash_domain(
        "trnm.native-application.durable-p.v1",
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    let commit = trnm_finality_types::hash_domain(
        "trnm.native-application.commit-id.v1",
        &[&digest, block, &fields[14]],
    );
    sql.execute(
        "UPDATE native_durable_execution_p_v1 SET p_digest=?,commit_id=? WHERE block_id=?",
        rusqlite::params![digest.as_slice(), commit.as_slice(), block],
    )
    .unwrap();
}

fn assert_repeated_prefix_mutants(
    source: &std::path::Path,
    checkpoint: &BlockHeader,
    first: &BlockHeader,
    ordinary: &BlockHeader,
) {
    for mutation in [
        "prefix",
        "duplicate",
        "ambiguous",
        "predecessor",
        "cycle",
        "jump",
        "terminal",
        "proof",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mutant.sqlite3");
        copy_later_store(source, &path);
        let sql = rusqlite::Connection::open(&path).unwrap();
        let binding: Vec<u8> = sql
            .query_row(
                "SELECT successor_binding FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?",
                [checkpoint.id().as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        match mutation {
            "prefix" | "duplicate" => {
                let block = if mutation == "prefix" {
                    checkpoint.id()
                } else {
                    ordinary.id()
                };
                let original: Vec<u8> = sql
                    .query_row(
                        "SELECT edge_lineage FROM native_durable_execution_p_v1 WHERE block_id=?",
                        [block.as_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .unwrap();
                let changed = if mutation == "prefix" {
                    // Keep the same last binding B while dropping A: a tail-only
                    // comparison is not an authentication of the checkpoint prefix.
                    [
                        1_u32.to_be_bytes().as_slice(),
                        &original[original.len() - 32..],
                    ]
                    .concat()
                } else {
                    let mut bytes = original.clone();
                    let last = bytes[bytes.len() - 32..].to_vec();
                    bytes[36..68].copy_from_slice(&last);
                    bytes
                };
                assert_eq!(
                    &changed[changed.len() - 32..],
                    &original[original.len() - 32..]
                );
                sql.execute("UPDATE native_durable_execution_p_v1 SET edge_lineage=?,lineage_digest=? WHERE block_id=?", rusqlite::params![changed,sha2::Sha256::digest(&changed).as_slice(),block.as_bytes().as_slice()]).unwrap();
                rehash_repeated_p(&sql, block.as_bytes());
            }
            "ambiguous" => {
                sql.execute("INSERT INTO native_epoch_edge_v1 SELECT ?1,store_id,checkpoint_height,checkpoint_block,checkpoint_root,checkpoint_commit_id,checkpoint_p_digest,checkpoint_commit_sequence,terminal_height,terminal_block,first_height,evidence,evidence_digest,phase,consumed_block,consumed_sequence FROM native_epoch_edge_v1 LIMIT 1", [binding.as_slice()]).unwrap();
                let owners: i64 = sql.query_row("SELECT (SELECT COUNT(*) FROM native_epoch_edge_v1 WHERE binding=?1)+(SELECT COUNT(*) FROM native_later_epoch_edge_v1 WHERE successor_binding=?1)", [binding.as_slice()], |r| r.get(0)).unwrap();
                assert_eq!(owners, 2);
            }
            "predecessor" | "cycle" => {
                let changed = if mutation == "cycle" {
                    binding.clone()
                } else {
                    vec![77; 32]
                };
                sql.execute("UPDATE native_later_epoch_edge_v1 SET predecessor_edge=? WHERE successor_binding=?", rusqlite::params![changed,binding]).unwrap();
                rehash_repeated_successor(&sql, &binding);
            }
            "jump" => {
                sql.execute("UPDATE native_later_epoch_edge_v1 SET first_height=? WHERE successor_binding=?", rusqlite::params![32_u64.to_be_bytes().as_slice(),binding]).unwrap();
                rehash_repeated_successor(&sql, &binding);
            }
            "terminal" => {
                sql.execute("UPDATE native_later_epoch_edge_v1 SET terminal_block=? WHERE successor_binding=?", rusqlite::params![checkpoint.id().as_bytes().as_slice(),binding]).unwrap();
                rehash_repeated_successor(&sql, &binding);
            }
            "proof" => {
                let mut row: [Vec<u8>; 7] = sql.query_row("SELECT block_id,p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?", [ordinary.id().as_bytes().as_slice()], |r| Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?])).unwrap();
                *row[4].last_mut().unwrap() ^= 1;
                row[5] = sha2::Sha256::digest(&row[4]).to_vec();
                row[6] = descendant_record_digest(&row).to_vec();
                write_descendant_record(&sql, ordinary.id().as_bytes(), &row);
            }
            _ => unreachable!(),
        }
        drop(sql);
        assert!(
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err(),
            "repeated prefix mutant {mutation} must fail cold recovery"
        );
    }
    let sql = rusqlite::Connection::open(source).unwrap();
    let retained_first: Vec<u8> = sql
        .query_row(
            "SELECT proof FROM native_later_epoch_application_finality_v1 WHERE block_id=?",
            [first.id().as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!retained_first.is_empty());
    assert!(
        DurableNativeApplicationV0::open(source, native_checkpoint_fixture_config_v1()).is_ok(),
        "all mutants used isolated copies of the genuine C32 seed"
    );
}

#[test]
fn repeated_later_handoffs_c28_c31_c32_recover_exact_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("repeated.sqlite3");
    let seed = build_later_descendant_fixture(&path);
    let checkpoint = advance_repeated_checkpoint(seed);
    complete_repeated_handoff(&path, checkpoint);
}
