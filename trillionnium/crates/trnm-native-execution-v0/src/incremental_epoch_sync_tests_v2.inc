// Exercise actual M07 original-proof production through the unchanged M13 trust
// verifier and durable snapshot staging. Anchors are provisioned by the fixture
// from its signed source/checkpoint, before reading any exported bytes.
fn schema11_sync_anchor(
    h: &BlockHeader,
    set: &trnm_consensus_types::ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> trnm_state_sync_v0::NativeTrustAnchorV1 {
    let h = h.try_cev0_bytes().unwrap();
    let set = set.try_cev0_bytes().unwrap();
    let parameters = parameters.canonical_bytes();
    let pin = trnm_state_sync_v0::native_trust_anchor_pin_v1(&h, &set, &parameters).unwrap();
    trnm_state_sync_v0::NativeTrustAnchorV1::from_pinned_bytes(&h, &set, &parameters, pin).unwrap()
}
fn schema11_sync_peer(
    path: &crate::NativeIncrementalFinalityPathV2,
) -> trnm_poco_node_production_v0::NativeIncrementalFinalityPathV2 {
    trnm_poco_node_production_v0::NativeIncrementalFinalityPathV2 {
        anchor_header_cev0: path.anchor_header_cev0.clone(),
        target_header_cev0: path.target_header_cev0.clone(),
        steps: path
            .steps
            .iter()
            .map(
                |s| trnm_poco_node_production_v0::NativeIncrementalFinalityStepV2 {
                    header_cev0: s.header_cev0.clone(),
                    consensus_parent_header_cev0: s.consensus_parent_header_cev0.clone(),
                    proof: s.proof.clone(),
                    epoch_evidence: s.epoch_evidence.clone(),
                },
            )
            .collect(),
    }
}
type Schema11SyncExports = (crate::NativeIncrementalFinalityPathV2, Vec<u8>);
#[inline(never)]
fn schema11_public_sync_checks(
    app: &DurableNativeApplicationV0,
    path: &Path,
    anchors: &[trnm_state_sync_v0::NativeTrustAnchorV1],
) -> Schema11SyncExports {
    use trnm_consensus_types::Cev0AdmissionBudgetV0 as Budget;
    use trnm_poco_node_production_v0::verify_incremental_native_finality_path_v2 as verify;
    use trnm_state_sync_v0::NativeTrustPathLimitsV1 as Limits;
    let block = |id: trnm_consensus_types::BlockId| BlockIdV0::new(*id.as_bytes()).unwrap();
    let before = std::fs::read(path).unwrap();
    let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(path);
    let sidecar_before = std::fs::read(&sidecar).unwrap();
    let head = load_metadata_v0(&Connection::open(path).unwrap(), &app.config)
        .unwrap()
        .head;
    let mut meter = Budget::protocol_v0();
    let exported = app
        .export_incremental_epoch_finality_path_v2(
            block(anchors[0].header().id()),
            head.block_id(),
            &mut meter,
        )
        .unwrap();
    assert_eq!(exported.steps.len(), 18);
    assert_eq!(
        exported
            .steps
            .iter()
            .filter(|s| s.epoch_evidence.is_some())
            .count(),
        3
    );
    let work = meter.signature_work();
    assert!(work > 0);
    let mut exact = Budget::new(meter.maximum_root_bytes(), work + 7);
    exact.charge_signature_work(7).unwrap();
    assert_eq!(
        app.export_incremental_epoch_finality_path_v2(
            block(anchors[0].header().id()),
            head.block_id(),
            &mut exact
        )
        .unwrap(),
        exported
    );
    assert_eq!(exact.signature_work(), work + 7);
    let mut insufficient = Budget::new(meter.maximum_root_bytes(), work + 6);
    insufficient.charge_signature_work(7).unwrap();
    assert!(app
        .export_incremental_epoch_finality_path_v2(
            block(anchors[0].header().id()),
            head.block_id(),
            &mut insufficient
        )
        .is_err());
    // Compare all proofs directly to original persisted bytes, not a decoder's
    // re-encoding. Schema11's three event tables cover exactly this path.
    let c = Connection::open(path).unwrap();
    for step in &exported.steps {
        let h = header(&step.header_cev0).unwrap();
        let original: Vec<u8> = c.query_row("SELECT proof FROM native_incremental_epoch_first_commit_v2 WHERE block=?1 UNION ALL SELECT proof FROM native_incremental_epoch_ordinary_commit_v2 WHERE block=?1 UNION ALL SELECT checkpoint_finality FROM native_incremental_epoch_pre_handoff_v2 WHERE checkpoint_block=?1", [h.id().as_bytes().as_slice()], |r|r.get(0)).unwrap();
        assert_eq!(step.proof, original);
        if let Some(e) = &step.epoch_evidence {
            let set =
                trnm_consensus_types::decode_validator_set_v0_exact(&e.new_validator_set).unwrap();
            assert_eq!(set.id(), h.validator_set_id());
            assert_eq!(
                header(&step.consensus_parent_header_cev0)
                    .unwrap()
                    .height()
                    .get()
                    + 1,
                h.height().get()
            );
        }
    }
    schema11_original_evidence(&c, &exported);
    drop(c);
    let peer = schema11_sync_peer(&exported);
    let mut verifier_meter = Budget::protocol_v0();
    let verified = verify(&anchors[0], &peer, Limits::default(), &mut verifier_meter).unwrap();
    assert_eq!(verified.terminal_header().height().get(), 32);
    assert_eq!(
        verified.terminal_header().id().as_bytes(),
        head.block_id().as_bytes()
    );
    let mut exact_verify = Budget::new(
        verifier_meter.maximum_root_bytes(),
        verifier_meter.signature_work() + 7,
    );
    exact_verify.charge_signature_work(7).unwrap();
    verify(&anchors[0], &peer, Limits::default(), &mut exact_verify).unwrap();
    assert_eq!(
        exact_verify.signature_work(),
        verifier_meter.signature_work() + 7
    );
    let mut limited = Budget::new(
        verifier_meter.maximum_root_bytes(),
        verifier_meter.signature_work() + 6,
    );
    limited.charge_signature_work(7).unwrap();
    assert!(verify(&anchors[0], &peer, Limits::default(), &mut limited).is_err());
    // Historical target and later independently pinned checkpoint must select
    // the predecessor epoch's own keys, not the current epoch-three tail.
    let historical = exported
        .steps
        .iter()
        .find(|s| header(&s.header_cev0).unwrap().height().get() == 22)
        .unwrap();
    for (anchor, target, count) in [
        (
            &anchors[0],
            block(header(&historical.header_cev0).unwrap().id()),
            10,
        ),
        (&anchors[1], head.block_id(), 10),
    ] {
        let p = app
            .export_incremental_epoch_finality_path_v2(
                block(anchor.header().id()),
                target,
                &mut Budget::protocol_v0(),
            )
            .unwrap();
        assert_eq!(p.steps.len(), count);
        assert_eq!(
            p.steps
                .iter()
                .filter(|s| s.epoch_evidence.is_some())
                .count(),
            2
        );
        verify(
            anchor,
            &schema11_sync_peer(&p),
            Limits::default(),
            &mut Budget::protocol_v0(),
        )
        .unwrap();
    }
    schema11_public_sync_mutants(&anchors[0], &peer);
    let prepared = schema11_reopen_height(app, 33).header().unwrap();
    for (a, t) in [
        (block(anchors[0].header().id()), block(prepared.id())),
        (head.block_id(), block(anchors[0].header().id())),
        (head.block_id(), head.block_id()),
        (
            block(anchors[0].header().id()),
            BlockIdV0::new([211; 32]).unwrap(),
        ),
    ] {
        assert!(app
            .export_incremental_epoch_finality_path_v2(a, t, &mut Budget::protocol_v0())
            .is_err());
    }
    assert!(app
        .export_epoch_finality_path_v1(block(anchors[0].header().id()), head.block_id())
        .is_err());
    assert!(app
        .export_current_native_live_v1(head.block_id())
        .is_err());
    for invalid in [block(anchors[1].header().id()), block(prepared.id())] {
        assert!(app
            .export_current_incremental_native_live_v2(invalid, &mut Budget::protocol_v0())
            .is_err());
    }
    let mut live_meter = Budget::protocol_v0();
    let live = app
        .export_current_incremental_native_live_v2(head.block_id(), &mut live_meter)
        .unwrap();
    assert_eq!(
        live_meter.signature_work(),
        work + verified.terminal_validator_set().validators().len()
    );
    let mut exact_live = Budget::new(
        live_meter.maximum_root_bytes(),
        live_meter.signature_work() + 7,
    );
    exact_live.charge_signature_work(7).unwrap();
    assert_eq!(
        app.export_current_incremental_native_live_v2(head.block_id(), &mut exact_live)
            .unwrap(),
        live
    );
    assert_eq!(exact_live.signature_work(), live_meter.signature_work() + 7);
    let mut limited = Budget::new(
        live_meter.maximum_root_bytes(),
        live_meter.signature_work() - 1,
    );
    assert!(app
        .export_current_incremental_native_live_v2(head.block_id(), &mut limited)
        .is_err());
    schema11_live_staging(path, &verified, &live);
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read(sidecar).unwrap(), sidecar_before);
    (exported, live)
}
#[inline(never)]
fn schema11_public_sync_mutants(
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    peer: &trnm_poco_node_production_v0::NativeIncrementalFinalityPathV2,
) {
    use trnm_consensus_types::Cev0AdmissionBudgetV0 as Budget;
    use trnm_poco_node_production_v0::verify_incremental_native_finality_path_v2 as verify;
    use trnm_state_sync_v0::NativeTrustPathLimitsV1 as Limits;
    for kind in [
        "anchor",
        "target",
        "parent",
        "proof",
        "old-set",
        "new-set",
        "order",
        "truncate",
        "missing-evidence",
        "unexpected-evidence",
        "intermediate-header",
    ] {
        let mut bad = peer.clone();
        match kind {
            "anchor" => bad.anchor_header_cev0 = bad.target_header_cev0.clone(),
            "target" => bad.target_header_cev0 = bad.steps[1].header_cev0.clone(),
            "intermediate-header" => bad.steps[1].header_cev0 = bad.steps[2].header_cev0.clone(),
            "parent" => bad.steps[1].consensus_parent_header_cev0 = bad.anchor_header_cev0.clone(),
            "proof" => *bad.steps[0].proof.last_mut().unwrap() ^= 1,
            "old-set" => {
                bad.steps[0]
                    .epoch_evidence
                    .as_mut()
                    .unwrap()
                    .old_validator_set = bad.steps[8]
                    .epoch_evidence
                    .as_ref()
                    .unwrap()
                    .old_validator_set
                    .clone()
            }
            "new-set" => {
                bad.steps[0]
                    .epoch_evidence
                    .as_mut()
                    .unwrap()
                    .new_validator_set = bad.steps[8]
                    .epoch_evidence
                    .as_ref()
                    .unwrap()
                    .new_validator_set
                    .clone()
            }
            "order" => bad.steps.swap(0, 1),
            "truncate" => {
                bad.steps.pop();
            }
            "missing-evidence" => bad.steps[0].epoch_evidence = None,
            "unexpected-evidence" => {
                bad.steps[1].epoch_evidence = bad.steps[0].epoch_evidence.clone()
            }
            _ => unreachable!(),
        }
        assert!(
            verify(anchor, &bad, Limits::default(), &mut Budget::protocol_v0()).is_err(),
            "{kind}"
        );
    }
    // Independently bounded application-link and epoch counts refuse before
    // signature work, as do field/total/caller limits.
    for kind in ["links", "epochs", "header", "total", "caller-links"] {
        let mut bad = peer.clone();
        let mut limits = Limits::default();
        match kind {
            "links" => bad.steps = vec![peer.steps[1].clone(); 257],
            "epochs" => bad.steps = vec![peer.steps[0].clone(); 33],
            "header" => bad.steps[0].header_cev0 = vec![1; 4097],
            "total" => limits.maximum_total_bytes = 1,
            "caller-links" => limits.maximum_links = 17,
            _ => unreachable!(),
        }
        let mut meter = Budget::protocol_v0();
        meter.charge_signature_work(7).unwrap();
        assert!(verify(anchor, &bad, limits, &mut meter).is_err(), "{kind}");
        assert_eq!(meter.signature_work(), 7, "{kind}");
    }
}
fn schema11_sync_reframe(
    original: &trnm_poco_node_production_v0::NativeLiveTransferV1,
    bytes: &[u8],
) -> trnm_poco_node_production_v0::NativeLiveTransferV1 {
    use trnm_state_sync_v0::{chunk_merkle_root_v0, SnapshotChunkV0};
    let mut manifest = original.manifest.clone();
    let chunk_size = bytes.len().div_ceil(4);
    manifest.maximum_chunk_bytes = chunk_size as u32;
    manifest.chunk_count = bytes.len().div_ceil(chunk_size) as u32;
    manifest.total_bytes = bytes.len() as u64;
    let binding = manifest.chunk_binding_digest();
    let chunks: Vec<_> = bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, bytes)| SnapshotChunkV0 {
            manifest_digest: binding,
            index: index as u32,
            chunk_digest: SnapshotChunkV0::canonical_digest(binding, index as u32, bytes),
            bytes: bytes.to_vec(),
        })
        .collect();
    manifest.chunk_root =
        chunk_merkle_root_v0(&chunks.iter().map(|c| c.chunk_digest).collect::<Vec<_>>());
    manifest.manifest_digest = manifest.canonical_digest();
    trnm_poco_node_production_v0::NativeLiveTransferV1 { manifest, chunks }
}
#[inline(never)]
fn schema11_live_staging(
    path: &Path,
    verified: &trnm_state_sync_v0::VerifiedNativeTrustPathV1,
    bytes: &[u8],
) {
    use trnm_poco_node_production_v0::{prepare_native_live_transfer_v1, NativeLiveStateSyncV1};
    let transfer = prepare_native_live_transfer_v1(verified, bytes).unwrap();
    let transfer = schema11_sync_reframe(&transfer, bytes);
    assert_eq!(transfer.chunks.len(), 4);
    let path = path.with_file_name("schema11-current-live-staging.sqlite");
    let mut session =
        NativeLiveStateSyncV1::begin(verified.clone(), transfer.manifest.clone()).unwrap();
    let store = session.initialize_durable(&path).unwrap();
    session
        .append_durable(&store, transfer.chunks[0].clone())
        .unwrap();
    let progress = session.readback();
    assert!(session.verify_complete().is_err());
    drop(session);
    drop(store);
    let (store, mut session) =
        NativeLiveStateSyncV1::open_durable(&path, verified.clone(), transfer.manifest.clone())
            .unwrap();
    assert_eq!(session.readback(), progress);
    for chunk in &transfer.chunks[1..] {
        session.append_durable(&store, chunk.clone()).unwrap();
    }
    let complete = session.verify_complete().unwrap();
    assert_eq!(complete.binding().application_version, 32);
    assert_eq!(
        complete.binding().state_root.0,
        *verified.terminal_header().state_root().as_bytes()
    );
    assert!(session.missing_chunks().is_empty());
    drop(session);
    drop(store);
    // All transport checksums are recomputed. Only genuine native root/semantic
    // validation can reject this substituted leaf at completion.
    let mut bad = crate::NativeCurrentLiveExportV1::decode(bytes).unwrap();
    *bad.entries
        .iter_mut()
        .find(|e| !e.value.is_empty())
        .unwrap()
        .value
        .last_mut()
        .unwrap() ^= 1;
    let bad = bad.encode().unwrap();
    assert!(prepare_native_live_transfer_v1(verified, &bad).is_err());
    let mutant = schema11_sync_reframe(&transfer, &bad);
    let mut session = NativeLiveStateSyncV1::begin(verified.clone(), mutant.manifest).unwrap();
    let store = session
        .initialize_durable(path.with_extension("bad.sqlite"))
        .unwrap();
    for chunk in mutant.chunks {
        session.append_durable(&store, chunk).unwrap();
    }
    assert!(session.verify_complete().is_err());
}
#[inline(never)]
fn schema11_public_sync_cold(
    app: &DurableNativeApplicationV0,
    anchors: &[trnm_state_sync_v0::NativeTrustAnchorV1],
    exports: &Schema11SyncExports,
) {
    use trnm_consensus_types::Cev0AdmissionBudgetV0 as Budget;
    let target = BlockIdV0::new(
        *header(&exports.0.target_header_cev0)
            .unwrap()
            .id()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        app.export_incremental_epoch_finality_path_v2(
            BlockIdV0::new(*anchors[0].header().id().as_bytes()).unwrap(),
            target,
            &mut Budget::protocol_v0()
        )
        .unwrap(),
        exports.0
    );
    assert_eq!(
        app.export_current_incremental_native_live_v2(target, &mut Budget::protocol_v0())
            .unwrap(),
        exports.1
    );
}

fn schema11_original_evidence(c: &Connection, path: &crate::NativeIncrementalFinalityPathV2) {
    let source = EpochRecoveryEvidenceV1::decode(&edge_row(c).unwrap().evidence).unwrap();
    let mut previous_set = source.new_set.clone();
    let mut previous_parameters = source.new_parameters.clone();
    let mut ordinal = 0;
    for step in &path.steps {
        let Some(e) = &step.epoch_evidence else {
            continue;
        };
        if ordinal == 0 {
            assert_eq!(e.old_checkpoint_finality, source.checkpoint_finality);
            assert_eq!(e.next_epoch_commitment, source.next_commitment);
            assert_eq!(e.authorization_kernel, source.anchor);
            assert_eq!(e.old_validator_set, source.old_set);
            assert_eq!(e.old_consensus_parameters, source.old_parameters);
            assert_eq!(e.new_validator_set, source.new_set);
            assert_eq!(e.new_consensus_parameters, source.new_parameters);
            assert_eq!(
                e.authenticated_checkpoint_parent_header,
                source.checkpoint_parent
            );
        } else {
            let h = header(&step.header_cev0).unwrap();
            let raw: Vec<u8> = c
                .query_row(
                    "SELECT evidence FROM native_incremental_epoch_edge_v2 WHERE consumed_block=?1",
                    [h.id().as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(&raw[..6], b"NI-EP2");
            let mut at = 6;
            let mut fields = Vec::new();
            for _ in 0..7 {
                let n = u32::from_be_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
                at += 4;
                fields.push(&raw[at..at + n]);
                at += n;
            }
            assert_eq!(at, raw.len());
            assert_eq!(e.old_checkpoint_finality, fields[2]);
            assert_eq!(e.next_epoch_commitment, fields[4]);
            assert_eq!(e.authorization_kernel, fields[3]);
            assert_eq!(e.old_validator_set, previous_set);
            assert_eq!(e.old_consensus_parameters, previous_parameters);
            assert_eq!(e.new_validator_set, fields[5]);
            assert_eq!(e.new_consensus_parameters, fields[6]);
            assert_eq!(e.authenticated_checkpoint_parent_header, fields[0]);
            previous_set = fields[5].to_vec();
            previous_parameters = fields[6].to_vec();
        }
        ordinal += 1;
    }
    assert_eq!(ordinal, 3);
}
