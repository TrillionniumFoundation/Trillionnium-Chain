// Genuine third crossing exercises historical prefix/sidecar ownership. It
// starts from the same schema7 seed and never installs state/proofs through SQL.
#[test]
fn schema11_repeated_crossing_c28_c31_c32_preserves_every_consumed_prefix() {
    schema11_checkpoint_fixture(true);
}
fn schema11_reopen_height(
    app: &DurableNativeApplicationV0,
    height: u64,
) -> PreparedNativeIncrementalEpochV2 {
    let c = Connection::open(app.path()).unwrap();
    let mut q = c
        .prepare("SELECT block,digest,header FROM native_incremental_p_v1 ORDER BY block LIMIT 129")
        .unwrap();
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap();
    let row = rows
        .map(|r| r.unwrap())
        .find(|(_, _, h)| header(h).unwrap().height().get() == height)
        .unwrap();
    drop(q);
    drop(c);
    app.reopen_prepared_incremental_epoch_v2(fixed(row.0).unwrap(), fixed(row.1).unwrap())
        .unwrap()
}
fn schema11_retained_rows(path: &Path, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let c = Connection::open(path).unwrap();
    let mut q = c
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let n = q.column_count();
    let rows = q
        .query_map([], |r| {
            (0..n)
                .map(|i| r.get(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows
}
fn schema11_third_crossing(
    path: &Path,
    set: &trnm_consensus_types::ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Vec<u8> {
    let tables = [
        "native_incremental_epoch_edge_v2",
        "native_incremental_epoch_first_commit_v2",
        "native_incremental_epoch_pre_handoff_v2",
        "native_incremental_epoch_ordinary_commit_v2",
    ];
    let before = tables
        .iter()
        .map(|table| schema11_retained_rows(path, table))
        .collect::<Vec<_>>();
    let app =
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    let mut descendants = (22..=24)
        .map(|h| schema11_reopen_height(&app, h))
        .collect::<Vec<_>>();
    for _ in 25..=27 {
        descendants.push(schema11_empty_descendant(
            &app,
            descendants.last().unwrap(),
            set,
            parameters,
        ));
        let i = descendants.len() - 3;
        let proof = schema11_ordinary_proof(
            &[
                descendants[i].header().unwrap(),
                descendants[i + 1].header().unwrap(),
                descendants[i + 2].header().unwrap(),
            ],
            &descendants[i - 1].header().unwrap(),
            set,
            parameters,
        );
        let _ = app
            .commit_incremental_epoch_descendant_finality_bytes_v2(
                &descendants[i],
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
    }
    let selected = app.compute_incremental_epoch_selection_v2().unwrap();
    assert_eq!(selected.cutoff_head().height().get(), 25);
    let parent = descendants.last().unwrap();
    let parent_head = parent.target_head().unwrap();
    let request = NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
        GenesisHashV0::new(app.config.genesis_hash).unwrap(),
        parent_head.clone(),
        HeightV0::new(28),
        28_000,
        ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let preview = app
        .preview_incremental_epoch_descendant_v2(parent, &request)
        .unwrap();
    let h = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(8),
        Height::new(28),
        BlockKind::EpochCheckpoint,
        parent.header().unwrap().id(),
        set.validators()[7 % set.validators().len()].id(),
        set.id(),
        parameters.hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        28_000,
        Some(selected.next_epoch_commitment().id()),
    )
    .unwrap();
    let execution = NativeBlockExecutionRequestV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        parent_head,
        BlockIdV0::new(*h.id().as_bytes()).unwrap(),
        request.height(),
        request.timestamp_ms(),
        request.active_validator_set_id(),
        Vec::new(),
        trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            preview.payload_root(),
            preview.post_state_root(),
            preview.receipts_root(),
            preview.evidence_root(),
        )
        .unwrap(),
    )
    .unwrap();
    let certified = schema11_certified(
        &parent.header().unwrap(),
        &descendants[4].header().unwrap(),
        set,
        parameters,
    );
    let checkpoint = app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution,
            &h,
            &certified,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let proof26 = schema11_ordinary_proof(
        &[
            descendants[4].header().unwrap(),
            descendants[5].header().unwrap(),
            h.clone(),
        ],
        &descendants[3].header().unwrap(),
        set,
        parameters,
    );
    let _ = app
        .commit_incremental_epoch_descendant_finality_bytes_v2(
            &descendants[4],
            &proof26,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let seal = |height, kind, parent| {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(height - 20),
            Height::new(height),
            kind,
            parent,
            set.validators()[(height as usize - 21) % set.validators().len()].id(),
            set.id(),
            parameters.hash(),
            h.payload_root(),
            h.state_root(),
            h.receipts_root(),
            h.evidence_root(),
            height * 1000,
            h.next_epoch_commitment_hash(),
        )
        .unwrap()
    };
    let s29 = seal(29, BlockKind::EpochSeal1, h.id());
    let s30 = seal(30, BlockKind::EpochSeal2, s29.id());
    let proof27 = schema11_ordinary_proof(
        &[descendants[5].header().unwrap(), h.clone(), s29.clone()],
        &descendants[4].header().unwrap(),
        set,
        parameters,
    );
    let _ = app
        .commit_incremental_epoch_descendant_finality_bytes_v2(
            &descendants[5],
            &proof27,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let proof28 = schema11_ordinary_proof(
        &[h.clone(), s29, s30.clone()],
        &parent.header().unwrap(),
        set,
        parameters,
    );
    let descriptor = trnm_consensus_types::HandoffDescriptorV0::new(
        trnm_consensus_types::HandoffDescriptorV0Fields {
            genesis_hash: set.genesis_hash(),
            chain_id: set.chain_id(),
            old_epoch: set.epoch(),
            new_epoch: selected.new_validator_set().epoch(),
            old_protocol_version: set.protocol_version(),
            new_protocol_version: selected.new_validator_set().protocol_version(),
            old_validator_set_hash: set.id(),
            new_validator_set_hash: selected.new_validator_set().id(),
            old_consensus_parameters_hash: parameters.hash(),
            new_consensus_parameters_hash: selected.new_parameters().hash(),
            checkpoint_height: h.height(),
            checkpoint_block_id: h.id(),
            checkpoint_state_root: h.state_root(),
            next_epoch_commitment_digest: selected.next_epoch_commitment().id(),
            terminal_old_height: s30.height(),
            terminal_old_block_id: s30.id(),
            terminal_old_qc_digest: schema11_qc(&s30, set).id(),
            terminal_old_view: s30.view(),
            activation_height: selected.next_epoch_commitment().fields().activation_height,
            initial_new_view: View::new(1),
        },
    )
    .unwrap();
    let descriptor_bytes = descriptor.try_cev0_bytes().unwrap();
    let commitment = selected.next_epoch_commitment().try_cev0_bytes().unwrap();
    let new_set_bytes = selected.new_validator_set().try_cev0_bytes().unwrap();
    let new_parameters_bytes = selected.new_parameters().canonical_bytes();
    let receipt = app
        .commit_incremental_epoch_pre_handoff_v2(
            &checkpoint,
            IncrementalPreHandoffPreimagesV2 {
                checkpoint_finality: &proof28,
                descriptor: &descriptor_bytes,
                next_epoch_commitment: &commitment,
                new_validator_set: &new_set_bytes,
                new_parameters: &new_parameters_bytes,
            },
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(receipt.head().height().get(), 28);
    assert_eq!(receipt.generation(), 16);
    let checkpoint_digest = checkpoint.p_digest();
    drop(app);
    let app =
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    let receipt = app
        .confirm_incremental_epoch_pre_handoff_v2(
            *h.id().as_bytes(),
            checkpoint_digest,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    // The second joint is signed only after actual C28 commit and cold receipt.
    use ed25519_dalek::Signer;
    let shares = |validators: &trnm_consensus_types::ValidatorSet,
                  root: trnm_consensus_types::SigningRoot| {
        validators
            .validators()
            .iter()
            .take(3)
            .map(|v| {
                trnm_consensus_types::SignatureShareV0::new(
                    v.id(),
                    trnm_consensus_types::Signature64::from_array(
                        schema11_key(v).sign(root.as_bytes()).to_bytes(),
                    ),
                )
                .unwrap()
            })
            .collect()
    };
    let joint = trnm_consensus_types::HandoffCertificateV0::new(
        descriptor.clone(),
        shares(set, descriptor.old_set_signing_root()),
        shares(
            selected.new_validator_set(),
            descriptor.new_set_signing_root(),
        ),
        set,
        selected.new_validator_set(),
    )
    .unwrap();
    let kernel = trnm_consensus_types::EpochAnchorAuthorizationKernelV0::from_parts_v0(
        s30.clone(),
        schema11_qc(&s30, set),
        joint,
        set,
        selected.new_validator_set(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap();
    let installed = app
        .attach_incremental_epoch_handoff_v2(
            &receipt,
            &kernel,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(installed.application_parent().height().get(), 28);
    assert_eq!(installed.consensus_parent().height().get(), 30);
    let bytes = schema11_third_first(&app, path, set, &installed, &kernel);
    drop(app);
    let cold =
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    let c = Connection::open(path).unwrap();
    let m = load_metadata_v0(&c, &cold.config).unwrap();
    assert_eq!(m.head.height().get(), 32);
    let (generation,edges,firsts,ni_edges,unconsumed,seals):(Vec<u8>,u64,u64,u64,u64,u64)=c.query_row("SELECT (SELECT generation FROM native_incremental_epoch_owner_v2),(SELECT count(*) FROM native_incremental_epoch_edge_v2),(SELECT count(*) FROM native_incremental_epoch_first_commit_v2),(SELECT count(*) FROM ni_epoch_edge),(SELECT count(*) FROM ni_epoch_edge WHERE phase=0),(SELECT count(*) FROM ni_roots WHERE (version>?1 AND version<?2) OR (version>?3 AND version<?4))",params![18u64.to_be_bytes().as_slice(),21u64.to_be_bytes().as_slice(),28u64.to_be_bytes().as_slice(),31u64.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
    assert_eq!(
        (
            number(generation).unwrap(),
            edges,
            firsts,
            ni_edges,
            unconsumed,
            seals
        ),
        (19, 3, 3, 3, 0, 0)
    );
    drop(c);
    for (table, originals) in tables.iter().zip(before) {
        let fresh = schema11_retained_rows(path, table);
        for old in originals {
            assert!(fresh.contains(&old), "historical row changed in {table}");
        }
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    drop(cold);
    // A locally rehashed three-edge prefix with B/C swapped remains invalid;
    // the cold walker must reconstruct the exact historical order itself.
    let c = Connection::open(path).unwrap();
    let mut row:Vec<rusqlite::types::Value>=c.query_row("SELECT block,p_digest,kind,prefix,cutoff_head,cutoff_p,cutoff_sequence FROM native_incremental_epoch_p_context_v2 WHERE block=(SELECT block FROM native_incremental_epoch_p_v1 WHERE edge=?1)",[installed.binding().as_slice()],|r|(0..7).map(|i|r.get(i)).collect()).unwrap();
    let rusqlite::types::Value::Blob(raw) = &mut row[3] else {
        panic!("expected prefix blob")
    };
    assert_eq!(raw.len(), 100);
    for i in 0..32 {
        raw.swap(36 + i, 68 + i);
    }
    let checksum = schema11_test_row_checksum(
        &c,
        "trnm.native-application.incremental-epoch-p-context.v2",
        &row,
        &[],
        &[4, 5, 6],
    );
    c.execute(
        "UPDATE native_incremental_epoch_p_context_v2 SET prefix=?1,checksum=?2 WHERE block=?3",
        params![row[3], checksum.as_slice(), row[0]],
    )
    .unwrap();
    drop(c);
    let corrupted = std::fs::read(path).unwrap();
    assert!(DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), corrupted);
    std::fs::write(path, &bytes).unwrap();
    DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    bytes
}

fn schema11_third_command(app: &DurableNativeApplicationV0, nonce: u64) -> Vec<u8> {
    let transaction = trnm_protocol::CanonicalTxV1 {
        schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.into(),
        sender: "did:operator:1".into(),
        nonce,
        max_gas: 100_000,
        fee_limit: 100_000,
        command: trnm_protocol::CanonicalCommandV1::Transfer {
            to: "did:recipient:third-epoch".into(),
            amount: 19,
        },
    };
    serde_json::to_vec(
        &trnm_finality_types::SignedCommandEnvelopeV1::sign(
            &app.config.chain_id,
            format!("schema11-third-epoch-{nonce}"),
            "did:operator:1",
            "operator",
            nonce,
            30_000,
            40_000,
            trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
            &serde_json::to_vec(&transaction).unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
        )
        .unwrap(),
    )
    .unwrap()
}
fn schema11_third_first(
    app: &DurableNativeApplicationV0,
    path: &Path,
    old_set: &trnm_consensus_types::ValidatorSet,
    installed: &InstalledIncrementalEpochEdgeV2,
    kernel: &[u8],
) -> Vec<u8> {
    let set = installed.new_validator_set();
    let parameters = installed.new_parameters();
    let before = std::fs::read(path).unwrap();
    let duplicate = installed
        .preview_request(31_000, vec![schema11_third_command(app, 2)])
        .unwrap();
    assert!(app
        .preview_incremental_first_epoch_block_v2(installed, &duplicate)
        .is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
    let request = installed
        .preview_request(31_000, vec![schema11_third_command(app, 13)])
        .unwrap();
    let preview = app
        .preview_incremental_first_epoch_block_v2(installed, &request)
        .unwrap();
    let h = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(1),
        Height::new(31),
        BlockKind::EpochHandoff,
        installed.consensus_parent().id(),
        set.validators()[0].id(),
        set.id(),
        parameters.hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        31_000,
        None,
    )
    .unwrap();
    let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
        preview.payload_root(),
        preview.post_state_root(),
        preview.receipts_root(),
        preview.evidence_root(),
    )
    .unwrap();
    let first = app
        .execute_incremental_first_epoch_block_v2(
            installed,
            NativeEpochBlockExecutionRequestV1::new(
                request,
                BlockIdV0::new(*h.id().as_bytes()).unwrap(),
                expected,
            )
            .unwrap(),
            &h,
        )
        .unwrap();
    let mut descendants: Vec<PreparedNativeIncrementalEpochV2> = Vec::new();
    for height in [32u64, 33] {
        let parent = descendants
            .last()
            .map(|p| p.target_head().unwrap())
            .unwrap_or_else(|| first.target_head().unwrap());
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
            GenesisHashV0::new(app.config.genesis_hash).unwrap(),
            parent.clone(),
            HeightV0::new(height),
            height * 1000,
            ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
            vec![schema11_third_command(app, height - 18)],
        )
        .unwrap();
        let preview = if let Some(previous) = descendants.last() {
            app.preview_incremental_epoch_descendant_v2(previous, &request)
                .unwrap()
        } else {
            app.preview_incremental_first_descendant_v2(&first, &request)
                .unwrap()
        };
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(height - 30),
            Height::new(height),
            BlockKind::Regular,
            trnm_consensus_types::BlockId::new(*parent.block_id().as_bytes()),
            set.validators()[(height as usize - 31) % set.validators().len()].id(),
            set.id(),
            parameters.hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            height * 1000,
            None,
        )
        .unwrap();
        let execution = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            parent,
            BlockIdV0::new(*header.id().as_bytes()).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        descendants.push(if let Some(previous) = descendants.last() {
            app.execute_incremental_epoch_descendant_v2(previous, execution, &header)
                .unwrap()
        } else {
            app.execute_incremental_first_descendant_v2(&first, execution, &header)
                .unwrap()
        });
    }
    let proof = schema11_first_proof(
        &[
            h.clone(),
            descendants[0].header().unwrap(),
            descendants[1].header().unwrap(),
        ],
        old_set,
        set,
        parameters,
        kernel,
    );
    let receipt = app
        .commit_incremental_first_epoch_finality_bytes_v2(
            &first,
            &proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(receipt.head().height().get(), 31);
    assert_eq!(receipt.generation(), 18);
    let c34 = schema11_empty_descendant(app, &descendants[1], set, parameters);
    let proof32 = schema11_ordinary_proof(
        &[
            descendants[0].header().unwrap(),
            descendants[1].header().unwrap(),
            c34.header().unwrap(),
        ],
        &h,
        set,
        parameters,
    );
    let committed = app
        .commit_incremental_epoch_descendant_finality_bytes_v2(
            &descendants[0],
            &proof32,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(committed.head().height().get(), 32);
    assert_eq!(committed.generation(), 19);
    let bytes = std::fs::read(path).unwrap();
    let c = Connection::open(path).unwrap();
    let mut q=c.prepare("SELECT block,p_digest,proof FROM native_incremental_epoch_first_commit_v2 ORDER BY sequence").unwrap();
    let records = q
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    drop(q);
    drop(c);
    assert_eq!(records.len(), 3);
    for (block, digest, proof) in records {
        let p = app
            .reopen_incremental_first_v2(fixed(block).unwrap(), fixed(digest).unwrap())
            .unwrap();
        let retried = app
            .commit_incremental_first_epoch_finality_bytes_v2(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retried.head(), &p.target_head().unwrap());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    bytes
}
