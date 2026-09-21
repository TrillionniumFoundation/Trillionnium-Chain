// Genuine schema7 sparse execution is the only source for these migration tests.
// No SQL mutation fabricates a finality receipt or promotes a Prepared row.
fn migration_original_inventory(path: &Path) -> BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    use rusqlite::types::Value;
    let c = Connection::open(path).unwrap();
    let mut q = c.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'native_incremental_epoch_%_v2' ORDER BY name").unwrap();
    let tables = q
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let mut result = BTreeMap::new();
    for name in tables {
        let mut q = c
            .prepare(&format!("SELECT * FROM {name} ORDER BY 1"))
            .unwrap();
        let columns = q.column_count();
        let values = q
            .query_map([], |r| {
                let mut values = (0..columns)
                    .map(|i| r.get::<_, Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if name == "native_application_metadata_v0" {
                    values[1] = Value::Blob(7u64.to_be_bytes().to_vec());
                }
                Ok(values)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        result.insert(name, values);
    }
    result
}
#[test]
fn schema7_to_schema11_migration_preserves_genuine_sparse_history_and_cold_projection() {
    use descendant::IncrementalEpochParentV1 as Parent;
    let directory = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_NATIVE_INCREMENTAL_MIGRATION_SIGKILL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.path().join("native.sqlite3"));
    let (app, edge, first, proof, mut descendants) = setup(&path);
    let unconsumed = std::fs::read(&path).unwrap();
    assert!(app.upgrade_incremental_multi_epoch_schema_v2().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), unconsumed);
    let first_receipt = app
        .commit_incremental_epoch_finality_bytes_v1(
            &first,
            &proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(first_receipt.head(), &first.target_head().unwrap());
    for height in 14..=17 {
        let p = empty_descendant(
            &app,
            &edge,
            Parent::Descendant(descendants.last().unwrap()),
            height * 1000,
        );
        descendants.push(p);
        let i = descendants.len() - 3;
        let parent = if i == 0 {
            first.header().unwrap()
        } else {
            descendants[i - 1].header().unwrap()
        };
        let finality =
            crate::poco_checkpoint::native_checkpoint_fixture_v1::ordinary_epoch_finality(
                &edge,
                &parent,
                &[
                    descendants[i].header().unwrap(),
                    descendants[i + 1].header().unwrap(),
                    descendants[i + 2].header().unwrap(),
                ],
            );
        let receipt = app
            .commit_incremental_epoch_descendant_finality_bytes_v1(
                &descendants[i],
                &finality,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(receipt.head().height().get(), height - 2);
    }
    // Refused migration cannot normalize even an incorrectly checksummed source.
    let c = Connection::open(&path).unwrap();
    let original_digest: Vec<u8> = c
        .query_row(
            "SELECT digest FROM native_incremental_p_v1 WHERE status=0 ORDER BY block LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    c.execute("UPDATE native_incremental_p_v1 SET digest=?1 WHERE block=(SELECT block FROM native_incremental_p_v1 WHERE status=0 ORDER BY block LIMIT 1)", [[0x52;32].as_slice()]).unwrap();
    drop(c);
    let corrupt_source = std::fs::read(&path).unwrap();
    assert!(app.upgrade_incremental_multi_epoch_schema_v2().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), corrupt_source);
    let c = Connection::open(&path).unwrap();
    c.execute("UPDATE native_incremental_p_v1 SET digest=?1 WHERE block=(SELECT block FROM native_incremental_p_v1 WHERE status=0 ORDER BY block LIMIT 1)", [original_digest]).unwrap();
    drop(c);
    // Even a genuine other proof with a fully recomputed legacy row checksum
    // cannot supply the original first-new finalized block.
    let c = Connection::open(&path).unwrap();
    let original_first = load(&c).unwrap().unwrap();
    let mut substituted = original_first.clone();
    substituted.proof = c.query_row("SELECT proof FROM native_incremental_epoch_descendant_commit_v1 ORDER BY block LIMIT 1", [], |r| r.get(0)).unwrap();
    substituted.checksum = substituted.digest(&app.config, &edge_row(&c).unwrap());
    c.execute(
        "UPDATE native_incremental_epoch_commit_v1 SET proof=?1,checksum=?2",
        rusqlite::params![substituted.proof, substituted.checksum.as_slice()],
    )
    .unwrap();
    drop(c);
    let substituted_bytes = std::fs::read(&path).unwrap();
    assert!(app.upgrade_incremental_multi_epoch_schema_v2().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), substituted_bytes);
    let c = Connection::open(&path).unwrap();
    c.execute(
        "UPDATE native_incremental_epoch_commit_v1 SET proof=?1,checksum=?2",
        rusqlite::params![original_first.proof, original_first.checksum.as_slice()],
    )
    .unwrap();
    drop(c);
    // A phantom seal pin is not reachable state, but still violates the closed
    // inventory. It must reject migration instead of being copied or ignored.
    let c = Connection::open(&path).unwrap();
    c.execute("INSERT INTO ni_pin SELECT owner,reason,?1,root,reference_count,release_authority FROM ni_pin ORDER BY owner,reason,version LIMIT 1",[9u64.to_be_bytes().as_slice()]).unwrap();
    drop(c);
    let seal_source = std::fs::read(&path).unwrap();
    assert!(app.upgrade_incremental_multi_epoch_schema_v2().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), seal_source);
    let c = Connection::open(&path).unwrap();
    c.execute(
        "DELETE FROM ni_pin WHERE version=?1",
        [9u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    drop(c);
    let app = if std::env::var_os("TRNM_NATIVE_INCREMENTAL_MIGRATION_SIGKILL_STORE").is_none() {
        let source = std::fs::read(&path).unwrap();
        let mut measured = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
        app.upgrade_incremental_multi_epoch_schema_with_budget_v2(&mut measured)
            .unwrap();
        drop(app);
        std::fs::write(&path, &source).unwrap();
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let mut limited = trnm_consensus_types::Cev0AdmissionBudgetV0::new(
            measured.maximum_root_bytes(),
            measured.signature_work() - 1,
        );
        let refused = app
            .upgrade_incremental_multi_epoch_schema_with_budget_v2(&mut limited)
            .expect_err("migration readback capacity must refuse before CAS");
        assert!(format!("{refused:#}").contains("prospective readback budget"));
        assert!(
            limited.signature_work() > 0
                && limited.signature_work() < limited.maximum_signature_work()
        );
        assert_eq!(std::fs::read(&path).unwrap(), source);
        assert_eq!(
            epoch_durable::schema_version(&Connection::open(&path).unwrap()).unwrap(),
            7
        );
        app
    } else {
        app
    };
    let inventory = migration_original_inventory(&path);
    let old_pin = *app.incremental_migration_pin.lock().unwrap();
    std::fs::copy(&path, path.with_extension("source-before-migration")).unwrap();
    app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    assert_eq!(migration_original_inventory(&path), inventory);
    let c = Connection::open(&path).unwrap();
    assert_eq!(epoch_durable::schema_version(&c).unwrap(), 11);
    let metadata = load_metadata_v0(&c, &app.config).unwrap();
    assert_eq!(metadata.head.height().get(), 15);
    let (contexts, firsts, ordinary, pending, pre_handoff): (usize, usize, usize, usize, usize) = c.query_row("SELECT (SELECT count(*) FROM native_incremental_epoch_p_context_v2),(SELECT count(*) FROM native_incremental_epoch_first_commit_v2),(SELECT count(*) FROM native_incremental_epoch_ordinary_commit_v2),(SELECT count(*) FROM native_incremental_p_v1 WHERE status=0),(SELECT count(*) FROM native_incremental_epoch_pre_handoff_v2)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(
        (contexts, firsts, ordinary, pending, pre_handoff),
        (7, 1, 4, 2, 0)
    );
    let original_proof: Vec<u8> = c
        .query_row(
            "SELECT proof FROM native_incremental_epoch_first_commit_v2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original_proof, proof);
    drop(c);
    let migrated_pin = *app.incremental_migration_pin.lock().unwrap();
    assert_ne!(migrated_pin, old_pin);
    let bytes = std::fs::read(&path).unwrap();
    // Uncertain response recovery may still hold only its original source pin.
    *app.incremental_migration_pin.lock().unwrap() = old_pin;
    app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    assert_eq!(*app.incremental_migration_pin.lock().unwrap(), migrated_pin);
    app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    *app.incremental_migration_pin.lock().unwrap() = Some([0x39; 32]);
    assert!(app.upgrade_incremental_multi_epoch_schema_v2().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    *app.incremental_migration_pin.lock().unwrap() = migrated_pin;
    // Every existing singleton writer/recovery remains fenced from schema11.
    assert!(app.recover_incremental_epoch_edge_v1().is_err());
    assert!(app.ensure_incremental_epoch_commit_owner_v1(&edge).is_err());
    assert!(app
        .reopen_prepared_incremental_epoch_v1(
            *first.header().unwrap().id().as_bytes(),
            first.p_digest()
        )
        .is_err());
    assert!(app
        .reopen_prepared_incremental_epoch_descendant_v1(
            *descendants[0].target_head().unwrap().block_id().as_bytes(),
            descendants[0].p_digest()
        )
        .is_err());
    assert!(app
        .compute_incremental_epoch_selection_v1(HeightV0::new(15))
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    drop(app);
    let reopened =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(
        *reopened.incremental_migration_pin.lock().unwrap(),
        migrated_pin
    );
    reopened
        .upgrade_incremental_multi_epoch_schema_v2()
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    drop(reopened);
    let c = Connection::open(&path).unwrap();
    c.execute("INSERT INTO ni_pin SELECT owner,reason,?1,root,reference_count,release_authority FROM ni_pin ORDER BY owner,reason,version LIMIT 1",[10u64.to_be_bytes().as_slice()]).unwrap();
    drop(c);
    let seal_projection = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), seal_projection);
    std::fs::write(&path, &bytes).unwrap();
    // Local checksum edits cannot authorize different immutable source bytes.
    let c = Connection::open(&path).unwrap();
    let wrong_proof: Vec<u8> = c
        .query_row(
            "SELECT proof FROM native_incremental_epoch_ordinary_commit_v2 ORDER BY block LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut row: Vec<rusqlite::types::Value> = c.query_row("SELECT block,edge,p_digest,sequence,head,proof,proof_digest FROM native_incremental_epoch_first_commit_v2",[],|r|(0..7).map(|i|r.get(i)).collect()).unwrap();
    row[5] = rusqlite::types::Value::Blob(wrong_proof.clone());
    row[6] = rusqlite::types::Value::Blob(sha256_v0(&wrong_proof).to_vec());
    let anchor: Vec<u8> = c
        .query_row(
            "SELECT source_anchor FROM native_incremental_epoch_owner_v2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let config = native_checkpoint_fixture_config_v1();
    let mut fields = vec![config.store_id.to_vec(), anchor];
    for (i, value) in row.iter().enumerate() {
        let rusqlite::types::Value::Blob(bytes) = value else {
            panic!("expected proof blob");
        };
        fields.push(if i == 5 {
            sha256_v0(bytes).to_vec()
        } else {
            bytes.clone()
        });
    }
    let checksum = hash_domain(
        "trnm.native-application.incremental-epoch-first-commit.v2",
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    c.execute(
        "UPDATE native_incremental_epoch_first_commit_v2 SET proof=?1,proof_digest=?2,checksum=?3",
        rusqlite::params![
            wrong_proof,
            sha256_v0(&wrong_proof).as_slice(),
            checksum.as_slice()
        ],
    )
    .unwrap();
    drop(c);
    let corrupted = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    std::fs::write(&path, &bytes).unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute("DELETE FROM native_incremental_epoch_p_context_v2 WHERE kind=0 AND block=(SELECT block FROM native_incremental_epoch_p_context_v2 WHERE kind=0 ORDER BY block LIMIT 1)", []).unwrap();
    drop(c);
    let missing = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), missing);
    std::fs::write(&path, &bytes).unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE unexpected_schema11_state (id INTEGER PRIMARY KEY) STRICT;")
        .unwrap();
    drop(c);
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    std::fs::write(&path, &bytes).unwrap();
    let final_owner =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    final_owner
        .upgrade_incremental_multi_epoch_schema_v2()
        .unwrap();
    assert_eq!(migration_original_inventory(&path), inventory);
}

#[cfg(unix)]
#[test]
fn schema7_to_schema11_sigkill_migration_cuts_keep_complete_source_or_projection() {
    for stage in [
        "incremental_schema11_before_commit",
        "incremental_schema11_after_commit",
        "incremental_schema11_after_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native.sqlite3");
        let marker = directory.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema7_to_schema11_migration_preserves_genuine_sparse_history_and_cold_projection","--nocapture"])
            .env("TRNM_NATIVE_INCREMENTAL_MIGRATION_SIGKILL_STORE",&path)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("migration child did not reach {stage}");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let expected =
            migration_original_inventory(&path.with_extension("source-before-migration"));
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let c = Connection::open(&path).unwrap();
        assert_eq!(
            epoch_durable::schema_version(&c).unwrap(),
            if stage == "incremental_schema11_before_commit" {
                7
            } else {
                11
            }
        );
        assert_eq!(
            load_metadata_v0(&c, &app.config)
                .unwrap()
                .head
                .height()
                .get(),
            15
        );
        drop(c);
        assert_eq!(migration_original_inventory(&path), expected);
        app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(migration_original_inventory(&path), expected);
    }
}

fn empty_descendant_v2(
    app: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    parent: &PreparedNativeIncrementalEpochV2,
    timestamp: u64,
) -> PreparedNativeIncrementalEpochV2 {
    let head = parent.target_head().unwrap();
    let height = head.height().get() + 1;
    let set = edge.new_validator_set();
    let request = NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
        GenesisHashV0::new(app.config.genesis_hash).unwrap(),
        head.clone(),
        HeightV0::new(height),
        timestamp,
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
        View::new(height - 10),
        Height::new(height),
        BlockKind::Regular,
        trnm_consensus_types::BlockId::new(*head.block_id().as_bytes()),
        set.validators()[(height - 11) as usize % set.validators().len()].id(),
        set.id(),
        edge.new_parameters().hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        timestamp,
        None,
    )
    .unwrap();
    let r = NativeBlockExecutionRequestV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        head,
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
    app.execute_incremental_epoch_descendant_v2(parent, r, &h)
        .unwrap()
}

#[test]
fn schema11_current_generations_continue_genuine_execution_preserving_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native.sqlite3");
    let (app, edge, first, proof, old_descendants) = setup(&path);
    let _first = app
        .commit_incremental_epoch_finality_bytes_v1(
            &first,
            &proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    let source = migration_original_inventory(&path);
    let pin = *app.incremental_migration_pin.lock().unwrap();
    let mut descendants = old_descendants
        .iter()
        .map(|p| {
            app.reopen_prepared_incremental_epoch_v2(
                *p.target_head().unwrap().block_id().as_bytes(),
                p.p_digest(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut generation = 0;
    for height in 14..=17 {
        descendants.push(empty_descendant_v2(
            &app,
            &edge,
            descendants.last().unwrap(),
            height * 1000,
        ));
        let i = descendants.len() - 3;
        let parent = if i == 0 {
            first.header().unwrap()
        } else {
            descendants[i - 1].header().unwrap()
        };
        let proof = crate::poco_checkpoint::native_checkpoint_fixture_v1::ordinary_epoch_finality(
            &edge,
            &parent,
            &[
                descendants[i].header().unwrap(),
                descendants[i + 1].header().unwrap(),
                descendants[i + 2].header().unwrap(),
            ],
        );
        let before = std::fs::read(&path).unwrap();
        assert!(app
            .commit_incremental_epoch_descendant_finality_bytes_v2(
                &descendants[i + 1],
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let receipt = app
            .commit_incremental_epoch_descendant_finality_bytes_v2(
                &descendants[i],
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        generation += 1;
        assert_eq!(receipt.generation(), generation);
        assert_eq!(receipt.head().height().get(), height - 2);
        let after = std::fs::read(&path).unwrap();
        let retry = app
            .commit_incremental_epoch_descendant_finality_bytes_v2(
                &descendants[i],
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.commit_sequence(), receipt.commit_sequence());
        assert_eq!(std::fs::read(&path).unwrap(), after);
        assert_eq!(*app.incremental_migration_pin.lock().unwrap(), pin);
    }
    let actual = migration_original_inventory(&path);
    for name in [
        "native_incremental_epoch_edge_v1",
        "native_incremental_epoch_commit_v1",
        "native_incremental_epoch_descendant_commit_v1",
    ] {
        assert_eq!(source.get(name), actual.get(name));
    }
    let block = *descendants[3].target_head().unwrap().block_id().as_bytes();
    let digest = descendants[3].p_digest();
    drop(app);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(*cold.incremental_migration_pin.lock().unwrap(), pin);
    assert!(cold
        .reopen_prepared_incremental_epoch_v2(block, digest)
        .unwrap()
        .commit_sequence()
        .is_some());
    cold.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    assert!(cold.recover_incremental_epoch_edge_v1().is_err());
    drop(cold);
    let clean = std::fs::read(&path).unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute(
        "UPDATE native_incremental_epoch_owner_v2 SET generation=?1",
        [0u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    drop(c);
    let corrupt = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    std::fs::write(&path, clean).unwrap();
    DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
}

#[test]
fn schema11_checkpoint_preparation_and_pre_handoff_close_genuine_causal_inventory() {
    use crate::poco_checkpoint::native_checkpoint_fixture_v1::ordinary_epoch_finality;
    let directory = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_SCHEMA11_PRE_HANDOFF_SIGKILL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| directory.path().join("native.sqlite3"));
    let (app, edge, first, proof, old) = setup(&path);
    let _first = app
        .commit_incremental_epoch_finality_bytes_v1(
            &first,
            &proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    app.upgrade_incremental_multi_epoch_schema_v2().unwrap();
    let mut descendants = old
        .iter()
        .map(|p| {
            app.reopen_prepared_incremental_epoch_v2(
                *p.target_head().unwrap().block_id().as_bytes(),
                p.p_digest(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut last_proof = Vec::new();
    for height in 14..=17 {
        descendants.push(empty_descendant_v2(
            &app,
            &edge,
            descendants.last().unwrap(),
            height * 1000,
        ));
        let i = descendants.len() - 3;
        let parent = if i == 0 {
            first.header().unwrap()
        } else {
            descendants[i - 1].header().unwrap()
        };
        last_proof = ordinary_epoch_finality(
            &edge,
            &parent,
            &[
                descendants[i].header().unwrap(),
                descendants[i + 1].header().unwrap(),
                descendants[i + 2].header().unwrap(),
            ],
        );
        let _ = app
            .commit_incremental_epoch_descendant_finality_bytes_v2(
                &descendants[i],
                &last_proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
    }
    let decoded = trnm_consensus_types::decode_finality_proof_v0_exact(
        &last_proof,
        edge.new_validator_set(),
        edge.new_parameters(),
        14_000,
    )
    .unwrap();
    let parent = descendants.last().unwrap();
    let set = edge.new_validator_set();
    let selected = app.compute_incremental_epoch_selection_v2().unwrap();
    assert_eq!(selected.cutoff_head().height().get(), 15);
    let head = parent.target_head().unwrap();
    let request = NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(app.config.chain_id.clone()).unwrap(),
        GenesisHashV0::new(app.config.genesis_hash).unwrap(),
        head.clone(),
        HeightV0::new(18),
        18_000,
        ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let preview = app
        .preview_incremental_epoch_descendant_v2(parent, &request)
        .unwrap();
    let header_for = |commitment| {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(8),
            Height::new(18),
            BlockKind::EpochCheckpoint,
            trnm_consensus_types::BlockId::new(*head.block_id().as_bytes()),
            set.validators()[7 % set.validators().len()].id(),
            set.id(),
            edge.new_parameters().hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            18_000,
            Some(commitment),
        )
        .unwrap()
    };
    let h = header_for(selected.next_epoch_commitment().id());
    let execution_for = |h: &BlockHeader| {
        NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            head.clone(),
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
        .unwrap()
    };
    let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
    let before = std::fs::read(&path).unwrap();
    let journal_before = std::fs::read(&sidecar).unwrap();
    let wrong = header_for(trnm_consensus_types::NextEpochCommitmentHash::new(
        [0x63; 32],
    ));
    assert!(app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&wrong),
            &wrong,
            decoded.grandchild(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    assert!(app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            decoded.child(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    let mut wrong_signature = last_proof.clone();
    *wrong_signature.last_mut().unwrap() ^= 1;
    let invalid = trnm_consensus_types::decode_finality_proof_v0_exact(
        &wrong_signature,
        set,
        edge.new_parameters(),
        14_000,
    )
    .unwrap();
    let mut parent_failure_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    assert!(app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            invalid.grandchild(),
            &mut parent_failure_budget
        )
        .is_err());
    let mut preparation_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::new(
        parent_failure_budget.maximum_root_bytes(),
        parent_failure_budget.signature_work() + 7,
    );
    preparation_budget.charge_signature_work(7).unwrap();
    let refused = app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            decoded.grandchild(),
            &mut preparation_budget,
        )
        .err()
        .expect("checkpoint readback must fit caller budget before reservation");
    assert!(format!("{refused:#}").contains("prospective readback budget"));
    assert_eq!(
        preparation_budget.signature_work(),
        preparation_budget.maximum_signature_work()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&sidecar).unwrap(), journal_before);
    let checkpoint = app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            decoded.grandchild(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(checkpoint.header().unwrap(), h);
    let c = Connection::open(&path).unwrap();
    assert_eq!(
        load_metadata_v0(&c, &app.config)
            .unwrap()
            .head
            .height()
            .get(),
        15
    );
    let kind: u8 = c
        .query_row(
            "SELECT kind FROM native_incremental_epoch_p_context_v2 WHERE block=?1",
            [h.id().as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, 2);
    drop(c);
    let retry = app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            decoded.grandchild(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(checkpoint.p_digest(), retry.p_digest());
    assert_eq!(checkpoint.preparation_id(), retry.preparation_id());
    let c16proof = ordinary_epoch_finality(
        &edge,
        &descendants[3].header().unwrap(),
        &[
            descendants[4].header().unwrap(),
            descendants[5].header().unwrap(),
            h.clone(),
        ],
    );
    let _ = app
        .commit_incremental_epoch_descendant_finality_bytes_v2(
            &descendants[4],
            &c16proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let seal1 = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(9),
        Height::new(19),
        BlockKind::EpochSeal1,
        h.id(),
        set.validators()[8 % set.validators().len()].id(),
        set.id(),
        edge.new_parameters().hash(),
        h.payload_root(),
        h.state_root(),
        h.receipts_root(),
        h.evidence_root(),
        19_000,
        h.next_epoch_commitment_hash(),
    )
    .unwrap();
    let c17proof = ordinary_epoch_finality(
        &edge,
        &descendants[4].header().unwrap(),
        &[descendants[5].header().unwrap(), h.clone(), seal1.clone()],
    );
    let _ = app
        .commit_incremental_epoch_descendant_finality_bytes_v2(
            &descendants[5],
            &c17proof,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    // Parent status and generation change; the immutable preparation tuple stays exact.
    let retry = app
        .prepare_incremental_epoch_checkpoint_v2(
            parent,
            execution_for(&h),
            &h,
            decoded.grandchild(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(checkpoint.p_digest(), retry.p_digest());
    assert_eq!(checkpoint.preparation_id(), retry.preparation_id());
    drop(app);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let cold_parent = cold
        .reopen_prepared_incremental_epoch_v2(*head.block_id().as_bytes(), parent.p_digest())
        .unwrap();
    let recovered = cold
        .prepare_incremental_epoch_checkpoint_v2(
            &cold_parent,
            execution_for(&h),
            &h,
            decoded.grandchild(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(recovered.p_digest(), checkpoint.p_digest());
    // Only checkpoint/seal consensus signatures exist. Neither B handoff role
    // signs before this native commit and independent cold confirmation.
    let seal2 = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(10),
        Height::new(20),
        BlockKind::EpochSeal2,
        seal1.id(),
        set.validators()[9 % set.validators().len()].id(),
        set.id(),
        edge.new_parameters().hash(),
        h.payload_root(),
        h.state_root(),
        h.receipts_root(),
        h.evidence_root(),
        20_000,
        h.next_epoch_commitment_hash(),
    )
    .unwrap();
    let finality = ordinary_epoch_finality(
        &edge,
        &parent.header().unwrap(),
        &[h.clone(), seal1, seal2.clone()],
    );
    let exact_finality = trnm_consensus_types::decode_finality_proof_v0_exact(
        &finality,
        set,
        edge.new_parameters(),
        17_000,
    )
    .unwrap();
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
            old_consensus_parameters_hash: edge.new_parameters().hash(),
            new_consensus_parameters_hash: selected.new_parameters().hash(),
            checkpoint_height: h.height(),
            checkpoint_block_id: h.id(),
            checkpoint_state_root: h.state_root(),
            next_epoch_commitment_digest: selected.next_epoch_commitment().id(),
            terminal_old_height: seal2.height(),
            terminal_old_block_id: seal2.id(),
            terminal_old_qc_digest: exact_finality.grandchild().certifying_qc().id(),
            terminal_old_view: seal2.view(),
            activation_height: selected.next_epoch_commitment().fields().activation_height,
            initial_new_view: View::new(1),
        },
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap();
    let commitment = selected.next_epoch_commitment().try_cev0_bytes().unwrap();
    let new_set = selected.new_validator_set().try_cev0_bytes().unwrap();
    let new_parameters = selected.new_parameters().canonical_bytes();
    let input = |proof| IncrementalPreHandoffPreimagesV2 {
        checkpoint_finality: proof,
        descriptor: &descriptor,
        next_epoch_commitment: &commitment,
        new_validator_set: &new_set,
        new_parameters: &new_parameters,
    };
    let before = std::fs::read(&path).unwrap();
    let journal_before = std::fs::read(&sidecar).unwrap();
    let mut invalid_finality = finality.clone();
    let signature = exact_finality
        .finalized_block()
        .proposer_signature()
        .as_bytes();
    let signature_offsets = invalid_finality
        .windows(signature.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == signature).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(signature_offsets.len(), 1);
    invalid_finality[signature_offsets[0]] ^= 1;
    let mut audit_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    assert!(cold
        .confirm_incremental_epoch_pre_handoff_v2(
            *h.id().as_bytes(),
            recovered.p_digest(),
            &mut audit_budget
        )
        .is_err());
    let mut failure_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    let failure = cold
        .commit_incremental_epoch_pre_handoff_v2(
            &recovered,
            input(&invalid_finality),
            &mut failure_budget,
        )
        .err()
        .expect("corrupt finality must fail");
    assert!(
        failure_budget.signature_work() > audit_budget.signature_work(),
        "failed incoming finality must retain work beyond the identical current-owner audit: {failure:#} ({} <= {})",
        failure_budget.signature_work(),
        audit_budget.signature_work()
    );
    let mut commit_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::new(
        failure_budget.maximum_root_bytes(),
        failure_budget.signature_work() + 7,
    );
    commit_budget.charge_signature_work(7).unwrap();
    let refused = cold
        .commit_incremental_epoch_pre_handoff_v2(&recovered, input(&finality), &mut commit_budget)
        .err()
        .expect("pre-handoff readback must fit caller budget before state commit");
    assert!(format!("{refused:#}").contains("prospective readback budget"));
    assert_eq!(
        commit_budget.signature_work(),
        commit_budget.maximum_signature_work()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&sidecar).unwrap(), journal_before);
    if std::env::var_os("TRNM_SCHEMA11_PRE_HANDOFF_SIGKILL_STORE").is_some() {
        std::fs::copy(&path, path.with_extension("prehand-source")).unwrap();
        std::fs::write(
            path.with_extension("prehand-input"),
            serde_json::to_vec(&vec![
                finality.clone(),
                descriptor.clone(),
                commitment.clone(),
                new_set.clone(),
                new_parameters.clone(),
                set.try_cev0_bytes().unwrap(),
                edge.new_parameters().canonical_bytes(),
                last_proof.clone(),
                h.try_cev0_bytes().unwrap(),
                checkpoint.p_digest().to_vec(),
            ])
            .unwrap(),
        )
        .unwrap();
    }
    let receipt = cold
        .commit_incremental_epoch_pre_handoff_v2(
            &recovered,
            input(&finality),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(receipt.head().height().get(), 18);
    assert_eq!(receipt.generation(), 7);
    assert!(receipt.belongs_to_application_at_path(&cold, &path));
    let c = Connection::open(&path).unwrap();
    let (pre,edges,ni_edges,ordinary_cp,seal_roots,seal_pins):(u64,u64,u64,u64,u64,u64)=c.query_row("SELECT (SELECT count(*) FROM native_incremental_epoch_pre_handoff_v2),(SELECT count(*) FROM native_incremental_epoch_edge_v2),(SELECT count(*) FROM ni_epoch_edge),(SELECT count(*) FROM native_incremental_epoch_ordinary_commit_v2 WHERE block=?1),(SELECT count(*) FROM ni_roots WHERE version>?2 AND version<?3),(SELECT count(*) FROM ni_pin WHERE version>?2 AND version<?3)",params![h.id().as_bytes().as_slice(),18u64.to_be_bytes().as_slice(),21u64.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
    assert_eq!(
        (pre, edges, ni_edges, ordinary_cp, seal_roots, seal_pins),
        (1, 1, 1, 0, 0, 0)
    );
    drop(c);
    let committed = std::fs::read(&path).unwrap();
    let retry = cold
        .commit_incremental_epoch_pre_handoff_v2(
            &recovered,
            input(&finality),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(retry.commit_sequence(), receipt.commit_sequence());
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    drop(cold);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let fresh = cold
        .confirm_incremental_epoch_pre_handoff_v2(
            *h.id().as_bytes(),
            checkpoint.p_digest(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(fresh.commit_sequence(), receipt.commit_sequence());
    assert_eq!(fresh.strict_binding(), receipt.strict_binding());
    assert!(!receipt.belongs_to_application_at_path(&cold, &path));
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    // Both successor roles sign only after the actual C18 commit and a cold
    // confirmation. This cryptographic fixture does not claim M03 custody.
    use ed25519_dalek::Signer;
    let descriptor_value =
        trnm_consensus_types::decode_handoff_descriptor_v0_exact(&descriptor).unwrap();
    let shares = |validators: &trnm_consensus_types::ValidatorSet,
                  root: trnm_consensus_types::SigningRoot| {
        validators
            .validators()
            .iter()
            .take(3)
            .map(|validator| {
                let key = (0u8..100)
                    .map(|n| ed25519_dalek::SigningKey::from_bytes(&[20 + n; 32]))
                    .find(|key| {
                        key.verifying_key().to_bytes() == *validator.consensus_key().as_bytes()
                    })
                    .unwrap();
                trnm_consensus_types::SignatureShareV0::new(
                    validator.id(),
                    trnm_consensus_types::Signature64::from_array(
                        key.sign(root.as_bytes()).to_bytes(),
                    ),
                )
                .unwrap()
            })
            .collect()
    };
    let joint = trnm_consensus_types::HandoffCertificateV0::new(
        descriptor_value.clone(),
        shares(set, descriptor_value.old_set_signing_root()),
        shares(
            selected.new_validator_set(),
            descriptor_value.new_set_signing_root(),
        ),
        set,
        selected.new_validator_set(),
    )
    .unwrap();
    let kernel = trnm_consensus_types::EpochAnchorAuthorizationKernelV0::from_parts_v0(
        exact_finality.grandchild().header().clone(),
        exact_finality.grandchild().certifying_qc().clone(),
        joint,
        set,
        selected.new_validator_set(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap();
    if std::env::var_os("TRNM_SCHEMA11_PRE_HANDOFF_SIGKILL_STORE").is_some() {
        std::fs::copy(&path, path.with_extension("attachment-source")).unwrap();
        std::fs::write(path.with_extension("attachment-kernel"), &kernel).unwrap();
    }
    let mut invalid_kernel = kernel.clone();
    *invalid_kernel.last_mut().unwrap() ^= 1;
    let mut invalid_budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    assert!(cold
        .attach_incremental_epoch_handoff_v2(&fresh, &invalid_kernel, &mut invalid_budget)
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    assert_eq!(std::fs::read(&sidecar).unwrap(), journal_before);
    let mut limited = trnm_consensus_types::Cev0AdmissionBudgetV0::new(
        invalid_budget.maximum_root_bytes(),
        invalid_budget.signature_work() + 7,
    );
    limited.charge_signature_work(7).unwrap();
    let refused = cold
        .attach_incremental_epoch_handoff_v2(&fresh, &kernel, &mut limited)
        .err()
        .expect("attachment readback budget must fit before mutation");
    assert!(format!("{refused:#}").contains("prospective readback budget"));
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    let installed = cold
        .attach_incremental_epoch_handoff_v2(
            &fresh,
            &kernel,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(installed.application_parent(), fresh.head());
    assert_eq!(installed.consensus_parent().height().get(), 20);
    assert_eq!(installed.new_validator_set(), selected.new_validator_set());
    assert_eq!(installed.original_kernel(), kernel);
    assert_ne!(installed.binding(), edge.authorization_id());
    assert_ne!(installed.binding(), fresh.strict_binding());
    assert!(installed.belongs_to_application_at_path(&cold, &path));
    let attached = std::fs::read(&path).unwrap();
    let retried = cold
        .attach_incremental_epoch_handoff_v2(
            &fresh,
            &kernel,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(retried.binding(), installed.binding());
    assert_eq!(std::fs::read(&path).unwrap(), attached);
    assert_eq!(std::fs::read(&sidecar).unwrap(), journal_before);
    let c = Connection::open(&path).unwrap();
    let (generation, sequence, edges, ni_edges, pre_sequence): (Vec<u8>, Vec<u8>, u64, u64, Vec<u8>) = c.query_row(
        "SELECT (SELECT generation FROM native_incremental_epoch_owner_v2),(SELECT durable_sequence FROM native_application_metadata_v0),(SELECT count(*) FROM native_incremental_epoch_edge_v2),(SELECT count(*) FROM ni_epoch_edge),(SELECT commit_sequence FROM native_incremental_epoch_pre_handoff_v2)",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(
        (
            number(generation).unwrap(),
            number(sequence).unwrap(),
            edges,
            ni_edges,
            number(pre_sequence).unwrap()
        ),
        (8, fresh.commit_sequence(), 2, 1, fresh.commit_sequence())
    );
    drop(c);
    let binding = installed.binding();
    drop(cold);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let restored = cold
        .confirm_incremental_epoch_edge_v2(
            binding,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(restored.binding(), binding);
    assert!(!installed.belongs_to_application_at_path(&cold, &path));
    assert_eq!(std::fs::read(&path).unwrap(), attached);
    // A fresh valid-time command using a consumed old-epoch nonce must still
    // fail against the persisted replay root; expiry cannot explain refusal.
    let command = |app: &DurableNativeApplicationV0, nonce| {
        let transaction = trnm_protocol::CanonicalTxV1 {
            schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.into(),
            sender: "did:operator:1".into(),
            nonce,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: trnm_protocol::CanonicalCommandV1::Transfer {
                to: "did:recipient:second-epoch".into(),
                amount: 17,
            },
        };
        serde_json::to_vec(
            &trnm_finality_types::SignedCommandEnvelopeV1::sign(
                &app.config.chain_id,
                format!("schema11-second-epoch-{nonce}"),
                "did:operator:1",
                "operator",
                nonce,
                20_000,
                30_000,
                trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
                &serde_json::to_vec(&transaction).unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let duplicate = restored
        .preview_request(21_000, vec![command(&cold, 2)])
        .unwrap();
    assert!(cold
        .preview_incremental_first_epoch_block_v2(&restored, &duplicate)
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), attached);
    let first_request = restored
        .preview_request(21_000, vec![command(&cold, 10)])
        .unwrap();
    assert!(cold
        .preview_incremental_first_epoch_block_v2(&installed, &first_request)
        .is_err());
    let first_preview = cold
        .preview_incremental_first_epoch_block_v2(&restored, &first_request)
        .unwrap();
    let new_set = restored.new_validator_set();
    let first_header = BlockHeader::new(
        new_set.genesis_hash(),
        new_set.chain_id(),
        new_set.protocol_version(),
        new_set.epoch(),
        View::new(1),
        Height::new(21),
        BlockKind::EpochHandoff,
        restored.consensus_parent().id(),
        new_set.validators()[0].id(),
        new_set.id(),
        restored.new_parameters().hash(),
        PayloadDigest::new(*first_preview.payload_root().as_bytes()),
        StateRoot::new(*first_preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*first_preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*first_preview.evidence_root().as_bytes()),
        21_000,
        None,
    )
    .unwrap();
    let first_request = NativeEpochBlockExecutionRequestV1::new(
        first_request,
        BlockIdV0::new(*first_header.id().as_bytes()).unwrap(),
        trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            first_preview.payload_root(),
            first_preview.post_state_root(),
            first_preview.receipts_root(),
            first_preview.evidence_root(),
        )
        .unwrap(),
    )
    .unwrap();
    let first_new = cold
        .execute_incremental_first_epoch_block_v2(&restored, first_request.clone(), &first_header)
        .unwrap();
    assert_eq!(first_new.target_head().unwrap().height().get(), 21);
    assert_eq!(
        first_new
            .executed()
            .unwrap()
            .request()
            .preview()
            .transactions()
            .len(),
        1
    );
    assert_eq!(first_new.edge_binding(), binding);
    assert!(first_new.belongs_to_application_at_path(&cold, &path));
    let committed = std::fs::read(&path).unwrap();
    let retried = cold
        .execute_incremental_first_epoch_block_v2(&restored, first_request, &first_header)
        .unwrap();
    assert_eq!(retried.p_digest(), first_new.p_digest());
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    assert_eq!(std::fs::read(&sidecar).unwrap(), journal_before);
    let c = Connection::open(&path).unwrap();
    let m = load_metadata_v0(&c, &cold.config).unwrap();
    assert_eq!(m.head.height().get(), 18);
    assert_eq!(m.durable_sequence, first_new.persist_sequence());
    let (edges,pending,seals):(u64,u64,u64)=c.query_row(
        "SELECT (SELECT count(*) FROM ni_epoch_edge),(SELECT count(*) FROM ni_epoch_edge WHERE phase=0),(SELECT count(*) FROM ni_roots WHERE version>?1 AND version<?2)",
        params![18u64.to_be_bytes().as_slice(),21u64.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!((edges, pending, seals), (2, 1, 0));
    drop(c);
    drop(cold);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let fresh_first = cold
        .reopen_incremental_first_v2(*first_header.id().as_bytes(), first_new.p_digest())
        .unwrap();
    assert_eq!(
        fresh_first.executed().unwrap(),
        first_new.executed().unwrap()
    );
    assert!(!first_new.belongs_to_application_at_path(&cold, &path));
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    let installed = cold
        .confirm_incremental_epoch_edge_v2(
            binding,
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let next_set = installed.new_validator_set();
    let mut next_descendants: Vec<PreparedNativeIncrementalEpochV2> = Vec::new();
    for height in [22u64, 23] {
        let parent = next_descendants
            .last()
            .map(|p| p.target_head().unwrap())
            .unwrap_or_else(|| fresh_first.target_head().unwrap());
        let preview_request = |transactions| {
            NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(cold.config.chain_id.clone()).unwrap(),
                GenesisHashV0::new(cold.config.genesis_hash).unwrap(),
                parent.clone(),
                HeightV0::new(height),
                height * 1000,
                ValidatorSetIdV0::new(*next_set.id().as_bytes()).unwrap(),
                transactions,
            )
            .unwrap()
        };
        if height == 22 {
            let duplicate = preview_request(vec![command(&cold, 10)]);
            assert!(cold
                .preview_incremental_first_descendant_v2(&fresh_first, &duplicate)
                .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), committed);
        }
        let request = preview_request(vec![command(&cold, height - 11)]);
        let preview = if let Some(p) = next_descendants.last() {
            cold.preview_incremental_epoch_descendant_v2(p, &request)
                .unwrap()
        } else {
            cold.preview_incremental_first_descendant_v2(&fresh_first, &request)
                .unwrap()
        };
        let header = BlockHeader::new(
            next_set.genesis_hash(),
            next_set.chain_id(),
            next_set.protocol_version(),
            next_set.epoch(),
            View::new(height - 20),
            Height::new(height),
            BlockKind::Regular,
            trnm_consensus_types::BlockId::new(*parent.block_id().as_bytes()),
            next_set.validators()[(height - 21) as usize % next_set.validators().len()].id(),
            next_set.id(),
            installed.new_parameters().hash(),
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
        next_descendants.push(if let Some(p) = next_descendants.last() {
            cold.execute_incremental_epoch_descendant_v2(p, execution, &header)
                .unwrap()
        } else {
            cold.execute_incremental_first_descendant_v2(&fresh_first, execution, &header)
                .unwrap()
        });
    }
    let committed = std::fs::read(&path).unwrap();
    drop(cold);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    for p in &next_descendants {
        let fresh = cold
            .reopen_prepared_incremental_epoch_v2(
                *p.target_head().unwrap().block_id().as_bytes(),
                p.p_digest(),
            )
            .unwrap();
        assert_eq!(fresh.executed().unwrap(), p.executed().unwrap());
    }
    let c = Connection::open(&path).unwrap();
    assert_eq!(
        load_metadata_v0(&c, &cold.config)
            .unwrap()
            .head
            .height()
            .get(),
        18
    );
    drop(c);
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    drop(cold);
    // A locally rehashed cross-kind replacement cannot substitute the migrated
    // native authorization identity for the full successor activation binding.
    let c = Connection::open(&path).unwrap();
    let mut row:Vec<rusqlite::types::Value>=c.query_row(
        "SELECT binding,ordinal,predecessor,prefix,checkpoint_head,checkpoint_p,checkpoint_sequence,context_digest,evidence_kind,evidence,phase,consumed_block,consumed_p,consumed_sequence FROM native_incremental_epoch_edge_v2 WHERE evidence_kind=1",
        [], |r| (0..14).map(|i| r.get(i)).collect(),
    ).unwrap();
    row[8] = rusqlite::types::Value::Integer(0);
    row[9] = rusqlite::types::Value::Blob(
        c.query_row(
            "SELECT evidence FROM native_incremental_epoch_owner_v1",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    );
    let hash = schema11_test_row_checksum(
        &c,
        "trnm.native-application.incremental-epoch-edge.v2",
        &row,
        &[9],
        &[2, 11, 12, 13],
    );
    c.execute("UPDATE native_incremental_epoch_edge_v2 SET evidence_kind=0,evidence=?1,checksum=?2 WHERE binding=?3",params![row[9],hash.as_slice(),binding.as_slice()]).unwrap();
    drop(c);
    let corrupt = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    std::fs::write(&path, &committed).unwrap();
    // Recomputed local checksums cannot replace the signed original cutoff.
    let c = Connection::open(&path).unwrap();
    let cutoff_block = descendants[3].header().unwrap().id();
    let mut row:Vec<rusqlite::types::Value>=c.query_row("SELECT block,edge,p_digest,sequence,head,proof,proof_digest FROM native_incremental_epoch_ordinary_commit_v2 WHERE block=?1",[cutoff_block.as_bytes().as_slice()],|r|(0..7).map(|i|r.get(i)).collect()).unwrap();
    row[5] = rusqlite::types::Value::Blob(c16proof.clone());
    row[6] = rusqlite::types::Value::Blob(sha256_v0(&c16proof).to_vec());
    let hash = schema11_test_row_checksum(
        &c,
        "trnm.native-application.incremental-epoch-ordinary-commit.v2",
        &row,
        &[5],
        &[],
    );
    c.execute("UPDATE native_incremental_epoch_ordinary_commit_v2 SET proof=?1,proof_digest=?2,checksum=?3 WHERE block=?4",params![c16proof,sha256_v0(&c16proof).as_slice(),hash.as_slice(),cutoff_block.as_bytes().as_slice()]).unwrap();
    drop(c);
    let corrupt = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    std::fs::write(&path, &committed).unwrap();
    // Kind2's actual cutoff tuple is independently rejoined, even with a valid checksum.
    let c = Connection::open(&path).unwrap();
    let mut row:Vec<rusqlite::types::Value>=c.query_row("SELECT block,p_digest,kind,prefix,cutoff_head,cutoff_p,cutoff_sequence FROM native_incremental_epoch_p_context_v2 WHERE block=?1",[h.id().as_bytes().as_slice()],|r|(0..7).map(|i|r.get(i)).collect()).unwrap();
    row[5] = rusqlite::types::Value::Blob([0x31; 32].to_vec());
    let hash = schema11_test_row_checksum(
        &c,
        "trnm.native-application.incremental-epoch-p-context.v2",
        &row,
        &[],
        &[4, 5, 6],
    );
    c.execute(
        "UPDATE native_incremental_epoch_p_context_v2 SET cutoff_p=?1,checksum=?2 WHERE block=?3",
        params![
            [0x31u8; 32].as_slice(),
            hash.as_slice(),
            h.id().as_bytes().as_slice()
        ],
    )
    .unwrap();
    drop(c);
    let corrupt = std::fs::read(&path).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    std::fs::write(&path, &committed).unwrap();
    DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    // An intact native database cannot hide a missing bound sidecar record.
    let c = Connection::open(&sidecar).unwrap();
    c.execute(
        "UPDATE preparations SET phase=0,bound_record=NULL,bound_checksum=NULL WHERE height_be=?1",
        [18u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    drop(c);
    let corrupt_journal = std::fs::read(&sidecar).unwrap();
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), committed);
    assert_eq!(std::fs::read(&sidecar).unwrap(), corrupt_journal);
}
fn schema11_test_row_checksum(
    c: &Connection,
    domain: &str,
    row: &[rusqlite::types::Value],
    hashed: &[usize],
    nullable: &[usize],
) -> [u8; 32] {
    use rusqlite::types::Value;
    let anchor: Vec<u8> = c
        .query_row(
            "SELECT source_anchor FROM native_incremental_epoch_owner_v2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut fields = vec![
        native_checkpoint_fixture_config_v1().store_id.to_vec(),
        anchor,
    ];
    for (i, value) in row.iter().enumerate() {
        let mut bytes = if nullable.contains(&i) {
            vec![u8::from(!matches!(value, Value::Null))]
        } else {
            Vec::new()
        };
        match value {
            Value::Integer(n) => bytes.extend(n.to_be_bytes()),
            Value::Blob(b) if hashed.contains(&i) => bytes.extend(sha256_v0(b)),
            Value::Blob(b) => bytes.extend(b),
            Value::Null => (),
            _ => panic!("invalid row type"),
        };
        fields.push(bytes);
    }
    hash_domain(
        domain,
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
}

#[cfg(unix)]
#[test]
fn schema11_pre_handoff_sigkill_cuts_recover_only_complete_c17_or_c18() {
    for stage in [
        "incremental_schema11_pre_handoff_before_commit",
        "incremental_schema11_pre_handoff_after_commit",
        "incremental_schema11_pre_handoff_after_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native.sqlite3");
        let marker = directory.path().join("ready");
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema11_checkpoint_preparation_and_pre_handoff_close_genuine_causal_inventory","--nocapture"]).env("TRNM_SCHEMA11_PRE_HANDOFF_SIGKILL_STORE",&path).env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage).env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pre-handoff child did not reach {stage}");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let inputs: Vec<Vec<u8>> =
            serde_json::from_slice(&std::fs::read(path.with_extension("prehand-input")).unwrap())
                .unwrap();
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let c = Connection::open(&path).unwrap();
        let m = load_metadata_v0(&c, &app.config).unwrap();
        let h = header(&inputs[8]).unwrap();
        let p = load_p(&c, *h.id().as_bytes()).unwrap().unwrap();
        let before = stage.ends_with("before_commit");
        assert_eq!(m.head.height().get(), if before { 17 } else { 18 });
        let pre: u64 = c
            .query_row(
                "SELECT count(*) FROM native_incremental_epoch_pre_handoff_v2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pre, u64::from(!before));
        let receipt = if before {
            assert_eq!(p.status, 0);
            let parent = load_p(&c, *p.parent.block_id().as_bytes())
                .unwrap()
                .unwrap();
            drop(c);
            let parent = app
                .reopen_prepared_incremental_epoch_v2(parent.block, parent.digest)
                .unwrap();
            let set = trnm_consensus_types::decode_validator_set_v0_exact(&inputs[5]).unwrap();
            let parameters =
                trnm_consensus_types::decode_consensus_parameters_v0_exact(&inputs[6]).unwrap();
            let cutoff = trnm_consensus_types::decode_finality_proof_v0_exact(
                &inputs[7],
                &set,
                &parameters,
                14_000,
            )
            .unwrap();
            let prepared = app
                .prepare_incremental_epoch_checkpoint_v2(
                    &parent,
                    p.executed().unwrap().request().clone(),
                    &h,
                    cutoff.grandchild(),
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            app.commit_incremental_epoch_pre_handoff_v2(
                &prepared,
                IncrementalPreHandoffPreimagesV2 {
                    checkpoint_finality: &inputs[0],
                    descriptor: &inputs[1],
                    next_epoch_commitment: &inputs[2],
                    new_validator_set: &inputs[3],
                    new_parameters: &inputs[4],
                },
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap()
        } else {
            assert_eq!(p.status, 1);
            drop(c);
            app.confirm_incremental_epoch_pre_handoff_v2(
                p.block,
                p.digest,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap()
        };
        assert_eq!(receipt.head().height().get(), 18);
        assert_eq!(receipt.p_digest().as_slice(), inputs[9]);
        let original = migration_original_inventory(&path.with_extension("prehand-source"));
        let current = migration_original_inventory(&path);
        for name in [
            "native_durable_execution_p_v0",
            "native_incremental_epoch_edge_v1",
            "native_incremental_epoch_commit_v1",
            "native_incremental_epoch_descendant_commit_v1",
        ] {
            assert_eq!(original.get(name), current.get(name));
        }
        let exact = std::fs::read(&path).unwrap();
        let repeat = app
            .confirm_incremental_epoch_pre_handoff_v2(
                p.block,
                p.digest,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(repeat.commit_sequence(), receipt.commit_sequence());
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        drop(app);
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn schema11_attachment_sigkill_preserves_checkpoint_and_original_pre_handoff() {
    for stage in [
        "incremental_schema11_attachment_before_commit",
        "incremental_schema11_attachment_after_commit",
        "incremental_schema11_attachment_after_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native.sqlite3");
        let marker = directory.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema11_checkpoint_preparation_and_pre_handoff_close_genuine_causal_inventory", "--nocapture"])
            .env("TRNM_SCHEMA11_PRE_HANDOFF_SIGKILL_STORE", &path)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("attachment child did not reach {stage}");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let inputs: Vec<Vec<u8>> =
            serde_json::from_slice(&std::fs::read(path.with_extension("prehand-input")).unwrap())
                .unwrap();
        let kernel = std::fs::read(path.with_extension("attachment-kernel")).unwrap();
        let source = path.with_extension("attachment-source");
        assert_eq!(
            migration_original_inventory(&path),
            migration_original_inventory(&source)
        );
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let h = header(&inputs[8]).unwrap();
        let c = Connection::open(&path).unwrap();
        let count: u64 = c
            .query_row(
                "SELECT count(*) FROM native_incremental_epoch_edge_v2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count,
            if stage.ends_with("before_commit") {
                1
            } else {
                2
            }
        );
        let head = load_metadata_v0(&c, &app.config).unwrap();
        assert_eq!(head.head.height().get(), 18);
        drop(c);
        let receipt = app
            .confirm_incremental_epoch_pre_handoff_v2(
                *h.id().as_bytes(),
                inputs[9].as_slice().try_into().unwrap(),
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let edge = app
            .attach_incremental_epoch_handoff_v2(
                &receipt,
                &kernel,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(edge.application_parent(), receipt.head());
        assert_eq!(
            migration_original_inventory(&path),
            migration_original_inventory(&source)
        );
        for table in [
            "native_incremental_epoch_p_context_v2",
            "native_incremental_epoch_pre_handoff_v2",
            "native_incremental_epoch_first_commit_v2",
            "native_incremental_epoch_ordinary_commit_v2",
        ] {
            let values = |at: &Path| {
                let c = Connection::open(at).unwrap();
                let mut q = c
                    .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                    .unwrap();
                let count = q.column_count();
                let values = q
                    .query_map([], |r| {
                        (0..count)
                            .map(|i| r.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                values
            };
            assert_eq!(values(&path), values(&source), "attachment changed {table}");
        }
        let exact = std::fs::read(&path).unwrap();
        let retry = app
            .attach_incremental_epoch_handoff_v2(
                &receipt,
                &kernel,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.binding(), edge.binding());
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        let binding = edge.binding();
        drop(app);
        let cold =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let _ = cold
            .confirm_incremental_epoch_edge_v2(
                binding,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), exact);
    }
}
