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
