// Genuine M06 fixture acceptance of M01-HISTORY-V1 and M13-HISTORY-V1.
// This transport deliberately has only one terminal proof. Original source
// ledgers remain intact; the new consumer does not receive ancestor P proofs.
#[derive(Clone)]
struct GenuineHistoricalHeaders {
    headers: Vec<Vec<u8>>,
    activations: Vec<trnm_consensus_types::EpochActivationEvidenceBytesV0>,
    terminal_proof: Vec<u8>,
}

#[inline(never)]
fn assert_genuine_historical_export(
    app: &DurableNativeApplicationV0,
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    path: &crate::NativeEpochFinalityPathV1,
) -> (GenuineHistoricalHeaders, Vec<u8>) {
    let expected = historical_headers_from_retained_path(anchor, path);
    let target =
        trnm_consensus_types::decode_block_header_v0_exact(&path.target_header_cev0).unwrap();
    let before = app.confirmed_committed_head_v0().unwrap();
    let exported = app
        .export_historical_replay_v1(
            BlockIdV0::new(*anchor.header().id().as_bytes()).unwrap(),
            BlockIdV0::new(*target.id().as_bytes()).unwrap(),
        )
        .unwrap();
    assert_eq!(exported.anchor_header_cev0, path.anchor_header_cev0);
    assert_eq!(exported.terminal_finality_cev0, expected.terminal_proof);
    assert_eq!(exported.activations, expected.activations);
    assert_eq!(
        exported
            .records
            .iter()
            .map(|r| r.header_cev0().to_vec())
            .collect::<Vec<_>>(),
        expected.headers
    );
    let source = rusqlite::Connection::open_with_flags(
        app.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut application_count = 0;
    for record in &exported.records {
        let header =
            trnm_consensus_types::decode_block_header_v0_exact(record.header_cev0()).unwrap();
        match record {
            crate::NativeHistoricalRecordV1::Application {
                application_payload_cev0,
                ..
            } => {
                application_count += 1;
                assert!(!matches!(
                    header.block_kind(),
                    BlockKind::EpochSeal1 | BlockKind::EpochSeal2
                ));
                let (kind, artifact, status): (i64, Vec<u8>, i64) = source.query_row(
                    "SELECT artifact_kind,artifact,status FROM native_durable_execution_p_v1 WHERE block_id=?",
                    [header.id().as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                ).unwrap();
                assert_eq!(status, 1);
                let original_transactions = match kind {
                    0 => {
                        trnm_native_application::decode_native_executed_block_artifact_v0(&artifact)
                            .unwrap()
                            .request()
                            .transactions()
                            .to_vec()
                    }
                    1 => trnm_native_application::decode_native_executed_epoch_block_artifact_v1(
                        &artifact,
                    )
                    .unwrap()
                    .request()
                    .preview()
                    .transactions()
                    .to_vec(),
                    _ => panic!("unsupported genuine fixture artifact kind"),
                };
                let expected =
                    trnm_consensus_types::ApplicationPayloadV0::new(original_transactions)
                        .unwrap()
                        .try_cev0_bytes()
                        .unwrap();
                assert_eq!(
                    application_payload_cev0, &expected,
                    "history must retain exact source outer transaction bytes and order"
                );
            }
            crate::NativeHistoricalRecordV1::Seal { .. } => {
                assert!(matches!(
                    header.block_kind(),
                    BlockKind::EpochSeal1 | BlockKind::EpochSeal2
                ));
            }
        }
    }
    assert_eq!(application_count, path.steps.len());
    let encoded = exported.encode_v1().unwrap();
    let roundtrip = crate::NativeHistoricalReplayV1::decode_v1(&encoded).unwrap();
    assert_eq!(roundtrip, exported);
    assert_eq!(roundtrip.encode_v1().unwrap(), encoded);
    assert!(crate::NativeHistoricalReplayV1::decode_v1(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(crate::NativeHistoricalReplayV1::decode_v1(&trailing).is_err());
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), before);
    (
        GenuineHistoricalHeaders {
            headers: roundtrip
                .records
                .iter()
                .map(|r| r.header_cev0().to_vec())
                .collect(),
            activations: roundtrip.activations,
            terminal_proof: roundtrip.terminal_finality_cev0,
        },
        encoded,
    )
}

#[inline(never)]
fn historical_headers_from_retained_path(
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    path: &crate::NativeEpochFinalityPathV1,
) -> GenuineHistoricalHeaders {
    assert_eq!(
        path.anchor_header_cev0,
        anchor.header().try_cev0_bytes().unwrap()
    );
    let mut headers = Vec::new();
    let mut activations = Vec::new();
    let mut set = anchor.validator_set().clone();
    let mut parameters = *anchor.parameters();
    for step in &path.steps {
        if let Some(evidence) = &step.epoch_evidence {
            let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
                evidence.as_preimages(),
                &set,
                &parameters,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
            let checkpoint = decoded.old_checkpoint_finality();
            headers.push(checkpoint.child().header().try_cev0_bytes().unwrap());
            headers.push(checkpoint.grandchild().header().try_cev0_bytes().unwrap());
            set = decoded.new_validator_set().clone();
            parameters = *decoded.new_consensus_parameters();
            activations.push(evidence.clone());
        }
        headers.push(step.header_cev0.clone());
    }
    assert_eq!(headers.last().unwrap(), &path.target_header_cev0);
    GenuineHistoricalHeaders {
        headers,
        activations,
        terminal_proof: path.steps.last().unwrap().proof.clone(),
    }
}

fn verify_genuine_historical_path(
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    history: &GenuineHistoricalHeaders,
) -> Result<trnm_state_sync_v0::VerifiedNativeTrustPathV1, trnm_state_sync_v0::NativeTrustErrorV1> {
    trnm_state_sync_v0::verify_native_historical_trust_path_v1(
        anchor,
        &history
            .headers
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        &history
            .activations
            .iter()
            .map(|a| a.as_preimages())
            .collect::<Vec<_>>(),
        &history.terminal_proof,
        trnm_state_sync_v0::HistoricalAncestryLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
}

#[inline(never)]
fn assert_native_historical_sync(
    app: &DurableNativeApplicationV0,
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    other_anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    exported: &crate::NativeEpochFinalityPathV1,
    retained: &trnm_state_sync_v0::VerifiedNativeTrustPathV1,
    live_bytes: &[u8],
) -> Vec<u8> {
    let (history, encoded) = assert_genuine_historical_export(app, anchor, exported);
    assert_eq!(history.headers.len(), 14);
    assert_eq!(history.activations.len(), 2);
    let decoded: Vec<_> = history
        .headers
        .iter()
        .map(|bytes| trnm_consensus_types::decode_block_header_v0_exact(bytes).unwrap())
        .collect();
    assert_eq!(
        decoded.iter().map(|h| h.height().get()).collect::<Vec<_>>(),
        (19..=32).collect::<Vec<_>>()
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|h| matches!(
                h.block_kind(),
                BlockKind::EpochSeal1 | BlockKind::EpochSeal2
            ))
            .count(),
        4
    );
    let historical = verify_genuine_historical_path(anchor, &history)
        .expect("the terminal C32 proof must authenticate all 14 exact ancestor headers");
    assert_eq!(historical.terminal_header(), retained.terminal_header());
    assert_eq!(
        historical.terminal_validator_set(),
        retained.terminal_validator_set()
    );
    assert_eq!(
        historical.terminal_parameters(),
        retained.terminal_parameters()
    );
    assert_eq!(historical.snapshot_trust_path().link_count(), 10);
    assert_historical_native_live_staging(retained, historical, live_bytes);
    assert!(
        verify_genuine_historical_path(other_anchor, &history).is_err(),
        "an independently pinned genuine C17 cannot replace the C18 local trust root"
    );

    // The direct M01 owner and M13 consumer share the same raw bytes. M01 has
    // no dependency on a previously issued M13 token or local P digest.
    let total_bytes = history.terminal_proof.len()
        + history.headers.iter().map(Vec::len).sum::<usize>()
        + history
            .activations
            .iter()
            .map(|a| {
                [
                    &a.old_checkpoint_finality,
                    &a.next_epoch_commitment,
                    &a.authorization_kernel,
                    &a.old_validator_set,
                    &a.old_consensus_parameters,
                    &a.new_validator_set,
                    &a.new_consensus_parameters,
                    &a.authenticated_checkpoint_parent_header,
                ]
                .iter()
                .map(|bytes| bytes.len())
                .sum::<usize>()
            })
            .sum::<usize>();
    let mut successful_budget = Cev0AdmissionBudgetV0::protocol_v0();
    let strict = trnm_consensus_crypto::verify_historical_header_ancestry_v1(
        anchor.header(),
        anchor.validator_set(),
        anchor.parameters(),
        &history
            .headers
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        &history
            .activations
            .iter()
            .map(|a| a.as_preimages())
            .collect::<Vec<_>>(),
        &history.terminal_proof,
        trnm_consensus_crypto::HistoricalAncestryLimitsV1 {
            maximum_headers: 14,
            maximum_transitions: 2,
            maximum_total_bytes: total_bytes,
        },
        &mut successful_budget,
    )
    .expect("M01 must independently verify the identical historical bytes");
    assert_eq!(strict.headers(), decoded);
    assert_eq!(strict.activations().len(), 2);
    assert_eq!(strict.terminal_header(), retained.terminal_header());
    drop(strict);

    for limits in [
        trnm_state_sync_v0::HistoricalAncestryLimitsV1 {
            maximum_headers: 13,
            ..Default::default()
        },
        trnm_state_sync_v0::HistoricalAncestryLimitsV1 {
            maximum_transitions: 1,
            ..Default::default()
        },
        trnm_state_sync_v0::HistoricalAncestryLimitsV1 {
            maximum_total_bytes: total_bytes - 1,
            ..Default::default()
        },
    ] {
        assert!(trnm_state_sync_v0::verify_native_historical_trust_path_v1(
            anchor,
            &history
                .headers
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            &history
                .activations
                .iter()
                .map(|a| a.as_preimages())
                .collect::<Vec<_>>(),
            &history.terminal_proof,
            limits,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    }

    for mutation in [
        "missing-header",
        "reordered-header",
        "duplicate-header",
        "trailing-header",
        "missing-seal",
        "terminal-parent",
        "header-trailing-bytes",
        "missing-activation",
        "reordered-activation",
        "duplicate-activation",
        "old-configuration",
        "checkpoint-parent",
        "activation-signature",
        "terminal-proof",
        "terminal-signature",
    ] {
        let mut changed = history.clone();
        match mutation {
            "missing-header" => {
                changed.headers.remove(4);
            }
            "reordered-header" => changed.headers.swap(4, 5),
            "duplicate-header" => changed.headers[4] = changed.headers[3].clone(),
            "trailing-header" => changed
                .headers
                .push(changed.headers.last().unwrap().clone()),
            "missing-seal" => {
                changed.headers.remove(0);
            }
            "terminal-parent" => {
                let terminal = decoded.last().unwrap();
                changed.headers[13] = checkpoint_like_header_at_view(
                    retained.terminal_validator_set(),
                    BlockKind::Regular,
                    32,
                    anchor.header().id(),
                    terminal.state_root(),
                    None,
                    terminal.timestamp_ms(),
                    terminal.payload_digest(),
                    terminal.receipts_root(),
                    terminal.evidence_root(),
                    terminal.view().get(),
                )
                .try_cev0_bytes()
                .unwrap();
            }
            "header-trailing-bytes" => changed.headers[4].push(0),
            "missing-activation" => {
                changed.activations.remove(0);
            }
            "reordered-activation" => changed.activations.swap(0, 1),
            "duplicate-activation" => changed.activations.push(changed.activations[1].clone()),
            "old-configuration" => {
                changed.activations[0].old_validator_set =
                    retained.terminal_validator_set().try_cev0_bytes().unwrap()
            }
            "checkpoint-parent" => {
                changed.activations[0].authenticated_checkpoint_parent_header =
                    anchor.header().try_cev0_bytes().unwrap()
            }
            "activation-signature" => {
                let mut activation_budget = Cev0AdmissionBudgetV0::protocol_v0();
                let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
                    changed.activations[0].as_preimages(),
                    anchor.validator_set(),
                    anchor.parameters(),
                    &mut activation_budget,
                )
                .unwrap();
                let signature = decoded
                    .authorization_kernel()
                    .handoff_certificate()
                    .old_signatures()[0]
                    .signature()
                    .as_bytes();
                let positions: Vec<_> = changed.activations[0]
                    .authorization_kernel
                    .windows(signature.len())
                    .enumerate()
                    .filter_map(|(offset, bytes)| (bytes == signature).then_some(offset))
                    .collect();
                assert_eq!(positions.len(), 1);
                changed.activations[0].authorization_kernel[positions[0] + signature.len() - 1] ^=
                    1;
                trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
                    changed.activations[0].as_preimages(),
                    anchor.validator_set(),
                    anchor.parameters(),
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .expect("the signature mutant must remain canonical activation evidence");
                let mut failed_budget = Cev0AdmissionBudgetV0::protocol_v0();
                assert!(trnm_state_sync_v0::verify_native_historical_trust_path_v1(
                    anchor,
                    &changed
                        .headers
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>(),
                    &changed
                        .activations
                        .iter()
                        .map(|a| a.as_preimages())
                        .collect::<Vec<_>>(),
                    &changed.terminal_proof,
                    trnm_state_sync_v0::HistoricalAncestryLimitsV1::default(),
                    &mut failed_budget,
                )
                .is_err());
                assert!(failed_budget.signature_work() > 0);
                assert_eq!(failed_budget.signature_work(), activation_budget.signature_work(),
                    "strict handoff-role signature failure must retain the complete activation charge");
            }
            "terminal-proof" => changed.terminal_proof = exported.steps[8].proof.clone(),
            "terminal-signature" => {
                *changed.terminal_proof.last_mut().unwrap() ^= 1;
                let canonical = trnm_consensus_types::decode_finality_proof_v0_exact(
                    &changed.terminal_proof,
                    retained.terminal_validator_set(),
                    retained.terminal_parameters(),
                    decoded[12].timestamp_ms(),
                )
                .expect("terminal signature mutation must remain canonically decodable");
                assert_eq!(canonical.try_cev0_bytes().unwrap(), changed.terminal_proof);
                let mut failed_budget = Cev0AdmissionBudgetV0::protocol_v0();
                assert!(trnm_state_sync_v0::verify_native_historical_trust_path_v1(
                    anchor,
                    &changed
                        .headers
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>(),
                    &changed
                        .activations
                        .iter()
                        .map(|a| a.as_preimages())
                        .collect::<Vec<_>>(),
                    &changed.terminal_proof,
                    trnm_state_sync_v0::HistoricalAncestryLimitsV1::default(),
                    &mut failed_budget,
                )
                .is_err());
                assert!(failed_budget.signature_work() > 0);
                assert_eq!(
                    failed_budget.signature_work(),
                    successful_budget.signature_work(),
                    "strict signature failure cannot refund charged verification work"
                );
            }
            _ => unreachable!(),
        }
        assert!(
            verify_genuine_historical_path(anchor, &changed).is_err(),
            "historical authority must reject {mutation}"
        );
    }
    encoded
}

fn assert_historical_native_live_staging(
    retained: &trnm_state_sync_v0::VerifiedNativeTrustPathV1,
    historical: trnm_state_sync_v0::VerifiedNativeTrustPathV1,
    bytes: &[u8],
) {
    use trnm_poco_node_production_v0::{prepare_native_live_transfer_v1, NativeLiveStateSyncV1};
    assert_ne!(
        retained.snapshot_trust_path().path_digest(),
        historical.snapshot_trust_path().path_digest()
    );
    assert_ne!(
        retained.snapshot_trust_path().terminal().checkpoint_digest,
        historical
            .snapshot_trust_path()
            .terminal()
            .checkpoint_digest
    );
    let old_packet = prepare_native_live_transfer_v1(retained, bytes).unwrap();
    let packet = prepare_native_live_transfer_v1(&historical, bytes).unwrap();
    assert_ne!(
        old_packet.manifest.manifest_digest,
        packet.manifest.manifest_digest
    );
    assert!(
        NativeLiveStateSyncV1::begin(historical.clone(), old_packet.manifest).is_err(),
        "an old per-proof route manifest cannot bind a historical ancestry route"
    );
    let terminal = historical.terminal_header().clone();
    let mut session = NativeLiveStateSyncV1::begin(historical, packet.manifest).unwrap();
    for chunk in packet.chunks {
        session.accept_chunk(chunk).unwrap();
    }
    let staged = session.verify_complete().unwrap();
    assert_eq!(staged.binding().height, terminal.height().get());
    assert_eq!(
        staged.binding().terminal_block_digest.0,
        *terminal.id().as_bytes()
    );
    assert_eq!(
        staged.binding().state_root.0,
        *terminal.state_root().as_bytes()
    );
}
