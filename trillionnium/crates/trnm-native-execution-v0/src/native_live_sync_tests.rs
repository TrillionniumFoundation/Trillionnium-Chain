// Included in the genuine repeated-epoch acceptance fixture. No synthetic root
// recomputer or self-selected trust anchor participates in this test.
#[inline(never)]
fn assert_current_native_live_sync(
    app: &DurableNativeApplicationV0,
    owner_path: &std::path::Path,
    target: &BlockHeader,
    historical: BlockId,
    prepared: BlockId,
    verified: &trnm_state_sync_v0::VerifiedNativeTrustPathV1,
) -> Vec<u8> {
    use trnm_poco_node_production_v0::{prepare_native_live_transfer_v1, NativeLiveStateSyncV1};
    use trnm_state_sync_v0::{Digest32V0, SnapshotChunkV0};

    let block = |id: BlockId| BlockIdV0::new(*id.as_bytes()).unwrap();
    let before = app.confirmed_committed_head_v0().unwrap();
    for invalid in [historical, prepared] {
        assert!(app.export_current_native_live_v1(block(invalid)).is_err());
    }
    let bytes = app
        .export_current_native_live_v1(block(target.id()))
        .unwrap();
    assert_native_live_semantic_mutants(
        &bytes,
        target,
        verified.terminal_validator_set(),
        verified.terminal_parameters(),
    );
    let transfer = prepare_native_live_transfer_v1(verified, &bytes).unwrap();
    let binding_schema = Digest32V0(crate::native_current_live_schema_digest_v1());
    assert_eq!(transfer.manifest.schema_digest, binding_schema);
    assert_eq!(transfer.manifest.height, 32);
    assert_eq!(
        transfer.manifest.state_root.0,
        *target.state_root().as_bytes()
    );

    // Deliberately divide a real small fixture into four chunks to exercise a
    // nonempty, incomplete durable resume. The same schema has no chunk edges.
    let partial = reframe_native_live_transfer(&transfer, &bytes);
    assert_eq!(partial.chunks.len(), 4);
    let store_path = owner_path.with_file_name("native-current-live-sync.sqlite");
    let mut session =
        NativeLiveStateSyncV1::begin(verified.clone(), partial.manifest.clone()).unwrap();
    assert!(session.verify_complete().is_err());
    let store = session.initialize_durable(&store_path).unwrap();
    session
        .append_durable(&store, partial.chunks[0].clone())
        .unwrap();
    let progress = session.readback();
    let binding = session.binding();
    assert_eq!(progress.received_chunk_count, 1);
    assert_eq!(binding.application_version, 32);
    assert_eq!(binding.schema_digest, binding_schema);
    assert!(session.verify_complete().is_err());
    drop(session);
    drop(store);
    let (store, mut resumed) = NativeLiveStateSyncV1::open_durable(
        &store_path,
        verified.clone(),
        partial.manifest.clone(),
    )
    .unwrap();
    assert_eq!(resumed.readback(), progress);
    for chunk in &partial.chunks[1..] {
        resumed.append_durable(&store, chunk.clone()).unwrap();
    }
    assert!(resumed.missing_chunks().is_empty());
    let staged = resumed.verify_complete().unwrap();
    assert_eq!(staged.binding(), binding);
    assert_eq!(
        staged.binding().terminal_block_digest.0,
        *target.id().as_bytes()
    );
    assert_eq!(
        staged.binding().state_root.0,
        *target.state_root().as_bytes()
    );
    // Identical durable append retries preserve exact progress; substitutions
    // cannot replace a retained chunk even when their chunk digest is rehashed.
    let complete = resumed.readback();
    resumed
        .append_durable(&store, partial.chunks[0].clone())
        .unwrap();
    assert_eq!(resumed.readback(), complete);
    let mut changed = partial.chunks[0].clone();
    changed.bytes[0] ^= 1;
    changed.chunk_digest =
        SnapshotChunkV0::canonical_digest(changed.manifest_digest, changed.index, &changed.bytes);
    assert!(resumed.append_durable(&store, changed).is_err());
    assert_eq!(resumed.readback(), complete);

    for kind in [
        "schema",
        "height",
        "root",
        "chunk-limit",
        "count-limit",
        "total-limit",
    ] {
        let mut bad = partial.manifest.clone();
        match kind {
            "schema" => bad.schema_digest = Digest32V0([91; 32]),
            "height" => bad.height += 1,
            "root" => bad.state_root.0[0] ^= 1,
            "chunk-limit" => bad.maximum_chunk_bytes = 1024 * 1024 + 1,
            "count-limit" => bad.chunk_count = 257,
            "total-limit" => bad.total_bytes = 256 * 1024 * 1024 + 1,
            _ => unreachable!(),
        }
        bad.manifest_digest = bad.canonical_digest();
        assert!(
            NativeLiveStateSyncV1::begin(verified.clone(), bad.clone()).is_err(),
            "{kind}"
        );
        assert!(
            NativeLiveStateSyncV1::open_durable(&store_path, verified.clone(), bad).is_err(),
            "{kind}"
        );
    }

    // Attack the native codec while rebuilding every transport checksum. Each
    // packet passes generic framing/chunk admission and fails native completion.
    let ranges = native_live_entry_ranges(&bytes);
    assert!(ranges.len() > 2);
    for kind in [
        "magic",
        "codec",
        "application-version",
        "root",
        "schema",
        "count",
        "length",
        "truncate",
        "trailing",
        "omit",
        "extra",
        "duplicate",
        "reorder",
        "key",
        "value",
    ] {
        let mut bad = bytes.clone();
        match kind {
            "magic" => bad[0] ^= 1,
            "codec" => bad[14] = 2,
            "application-version" => bad[22] ^= 1,
            "root" => bad[23] ^= 1,
            "schema" => bad[55] ^= 1,
            "count" => bad[87..91].copy_from_slice(&u32::MAX.to_be_bytes()),
            "length" => bad[91..95].copy_from_slice(&u32::MAX.to_be_bytes()),
            "truncate" => {
                bad.pop().unwrap();
            }
            "trailing" => bad.push(0),
            "omit" => {
                bad.drain(ranges[0].clone());
                bad[87..91].copy_from_slice(&((ranges.len() - 1) as u32).to_be_bytes());
            }
            "extra" => {
                let last = ranges.last().unwrap();
                let extra = bad[last.clone()].to_vec();
                bad.extend(extra);
                bad[87..91].copy_from_slice(&((ranges.len() + 1) as u32).to_be_bytes());
            }
            "duplicate" => {
                let one = bad[ranges[0].clone()].to_vec();
                bad.splice(ranges[1].clone(), one);
            }
            "reorder" => {
                let mut replacement = bad[ranges[1].clone()].to_vec();
                replacement.extend_from_slice(&bad[ranges[0].clone()]);
                bad.splice(ranges[0].start..ranges[1].end, replacement);
            }
            "key" => bad[ranges[0].start + 4] ^= 1,
            "value" => bad[ranges.last().unwrap().end - 1] ^= 1,
            _ => unreachable!(),
        }
        let packet = reframe_native_live_transfer(&transfer, &bad);
        let mut session = NativeLiveStateSyncV1::begin(verified.clone(), packet.manifest).unwrap();
        for chunk in packet.chunks {
            session.accept_chunk(chunk).unwrap();
        }
        assert!(
            session.verify_complete().is_err(),
            "rehashing transport must not authorize {kind}"
        );
    }
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), before);
    assert_eq!(
        app.export_current_native_live_v1(block(target.id()))
            .unwrap(),
        bytes
    );
    bytes
}

fn native_live_entry_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let count = u32::from_be_bytes(bytes[87..91].try_into().unwrap());
    let mut offset = 91;
    let mut ranges = Vec::new();
    for _ in 0..count {
        let start = offset;
        let key = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + key;
        let value = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + value;
        ranges.push(start..offset);
    }
    assert_eq!(offset, bytes.len());
    ranges
}

fn reframe_native_live_transfer(
    original: &trnm_poco_node_production_v0::NativeLiveTransferV1,
    bytes: &[u8],
) -> trnm_poco_node_production_v0::NativeLiveTransferV1 {
    use trnm_state_sync_v0::{chunk_merkle_root_v0, SnapshotChunkV0};
    let mut manifest = original.manifest.clone();
    let chunk_size = bytes.len().div_ceil(4);
    assert!(chunk_size <= 1024 * 1024);
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

// These are pure M06 semantic-admission tests, not finality fixtures. Rebuild
// each mutant's actual JMT root and put that same root in its untrusted header
// so root inequality cannot accidentally stand in for namespace validation.
fn assert_native_live_semantic_mutants(
    bytes: &[u8],
    target: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) {
    let original = crate::NativeCurrentLiveExportV1::decode(bytes).unwrap();
    let namespace_offset = b"trnm/authenticated-state/v4\0".len();
    for kind in [
        "namespace",
        "object-version",
        "lifecycle-key",
        "lifecycle-chain",
        "validator-power",
        "poco-manifest",
    ] {
        let mut changed = original.clone();
        match kind {
            "namespace" => changed.entries[0].key[namespace_offset] = 255,
            "object-version" => {
                changed.entries.push(crate::NativeCurrentLiveEntryV1 {
                    key: crate::stored_object_key_v0("semantic-test-object").unwrap(),
                    value: crate::AuthenticatedObjectRecordV0::new(
                        "semantic-test-object",
                        target.height().get() + 1,
                        b"{}".to_vec(),
                    )
                    .unwrap()
                    .encode()
                    .unwrap(),
                });
            }
            "lifecycle-key" => {
                changed
                    .entries
                    .iter_mut()
                    .find(|e| e.key[namespace_offset] == 4)
                    .unwrap()
                    .key
                    .push(0);
            }
            "lifecycle-chain" | "validator-power" => {
                let entry = changed
                    .entries
                    .iter_mut()
                    .find(|e| e.key[namespace_offset] == 4)
                    .unwrap();
                let record = crate::AuthenticatedObjectRecordV0::decode(&entry.value).unwrap();
                let mut lifecycle: crate::validator_lifecycle::ValidatorLifecycleStateV1 =
                    serde_json::from_slice(record.value()).unwrap();
                if kind == "lifecycle-chain" {
                    lifecycle.chain_id = "different-chain".to_owned();
                } else {
                    lifecycle.active_validators[0].voting_power += 1;
                }
                entry.value = crate::AuthenticatedObjectRecordV0::new(
                    record.object_type(),
                    record.object_version(),
                    serde_json::to_vec(&lifecycle).unwrap(),
                )
                .unwrap()
                .encode()
                .unwrap();
            }
            "poco-manifest" => {
                // Remove the actual canonical namespace8 manifest while keeping
                // all of its other physical entries and their exact bytes.
                let key = crate::poco_snapshot::poco_snapshot_manifest_key().unwrap();
                let index = changed.entries.iter().position(|e| e.key == key).unwrap();
                changed.entries.remove(index);
            }
            _ => unreachable!(),
        }
        changed.entries.sort_by(|a, b| a.key.cmp(&b.key));
        let mut scratch = crate::InMemoryNativeExecutionStoreV0::new(
            set.chain_id().as_str(),
            vec![crate::AuthorizedSignerV0::new(
                "root-only-test",
                "operator",
                hex::encode(set.validators()[0].consensus_key().as_bytes()),
            )
            .unwrap()],
            *parameters,
        )
        .unwrap();
        let writes = changed
            .entries
            .iter()
            .map(|entry| {
                crate::NativeStateWriteV0::raw(entry.key.clone(), entry.value.clone()).unwrap()
            })
            .collect();
        changed.state_root = scratch.apply_seed_v0(0, writes).unwrap().0;
        let header = checkpoint_like_header_at_view(
            set,
            BlockKind::Regular,
            target.height().get(),
            target.parent_id(),
            StateRoot::new(changed.state_root),
            None,
            target.timestamp_ms(),
            target.payload_root(),
            target.receipts_root(),
            target.evidence_root(),
            target.view().get(),
        );
        let error = crate::recompute_native_current_live_v1(
            &changed.encode().unwrap(),
            &header,
            set,
            parameters,
        )
        .expect_err("a matching JMT root must not hide invalid native leaf semantics");
        let error = format!("{error:#}");
        assert!(
            !error.contains("native live terminal root")
                && !error.contains("native live rebuilt root"),
            "{kind} must be rejected by semantic admission, got {error}"
        );
    }
}

fn assert_native_handoff_live_sync(
    app: &DurableNativeApplicationV0,
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    anchor_block: BlockId,
    target: &BlockHeader,
) {
    use trnm_poco_node_production_v0::{prepare_native_live_transfer_v1, NativeLiveStateSyncV1};
    let path = app
        .export_epoch_finality_path_v1(
            BlockIdV0::new(*anchor_block.as_bytes()).unwrap(),
            BlockIdV0::new(*target.id().as_bytes()).unwrap(),
        )
        .unwrap();
    let retained = trnm_poco_node_production_v0::verify_retained_native_finality_path_v1(
        anchor,
        &m15_finality_transport_copy(&path),
        trnm_state_sync_v0::NativeTrustPathLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(
        retained.terminal_header().block_kind(),
        BlockKind::EpochHandoff
    );
    let bytes = app
        .export_current_native_live_v1(BlockIdV0::new(*target.id().as_bytes()).unwrap())
        .unwrap();
    let transfer = prepare_native_live_transfer_v1(&retained, &bytes).unwrap();
    let mut session = NativeLiveStateSyncV1::begin(retained.clone(), transfer.manifest).unwrap();
    for chunk in transfer.chunks {
        session.accept_chunk(chunk).unwrap();
    }
    assert_eq!(session.verify_complete().unwrap().binding().height, 31);
    let (history, _) = assert_genuine_historical_export(app, anchor, &path);
    assert_eq!(history.headers.len(), 13);
    assert_eq!(history.activations.len(), 2);
    let historical = verify_genuine_historical_path(anchor, &history).unwrap();
    assert_eq!(historical.terminal_header(), target);
    assert_eq!(historical.snapshot_trust_path().link_count(), 9);
    assert_historical_native_live_staging(&retained, historical, &bytes);
}
