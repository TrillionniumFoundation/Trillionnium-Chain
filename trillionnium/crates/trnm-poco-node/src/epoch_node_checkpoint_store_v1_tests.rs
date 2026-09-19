use super::*;
use crate::epoch_node_checkpoint_v1::{tests::initial, EpochCheckpointPhaseV1};
use std::os::unix::process::ExitStatusExt;

fn records() -> (
    ExternalNodeCheckpointV0,
    ExternalNodeCheckpointV0,
    EpochNodeCheckpointV1,
) {
    let mut f = *initial().fields();
    let retired = f.retired.unwrap();
    let safety = f.source_safety.unwrap();
    let genesis = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: retired.scope,
        generation: 0,
        predecessor_checksum: [0; 32],
        safety_journal_id: safety.journal_id,
        safety_verifier_profile_ref: safety.context_ref,
        safety_revision: safety.revision,
        safety_state_record_checksum: safety.record_checksum,
        safety_record_chain_checksum: safety.chain_checksum,
        application_host_config_ref: [80; 32],
        application_projection_profile_ref: [81; 32],
        application_safety_binding_manifest_checksum: [82; 32],
        application_committed_head_row_checksum: [83; 32],
        application_recovery_closure_checksum: [84; 32],
        application_block_id: BlockId::new(f.application.block_id),
        application_height: f.application.height,
        application_state_root: StateRoot::new(f.application.state_root),
        application_view: f.application.view,
        application_timestamp_ms: f.application.timestamp_ms,
        signer_journal_id: retired.journal_id,
        signer_profile_checksum: retired.profile_checksum,
        signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
            retired.scope,
            retired.journal_id,
            retired.terminal_sequence,
            retired.terminal_chain_checksum,
        )
        .unwrap(),
    })
    .unwrap();
    let mut old_fields = *genesis.fields();
    old_fields.generation = 1;
    old_fields.predecessor_checksum = genesis.checkpoint_checksum();
    let old = ExternalNodeCheckpointV0::new(old_fields).unwrap();
    f.lineage_id = old.scope();
    f.origin_checksum = epoch_origin_checksum_v1(&old.encode_canonical());
    f.predecessor_checksum = old.checkpoint_checksum();
    (genesis, old, EpochNodeCheckpointV1::new(f).unwrap())
}
fn make_source(
    path: &Path,
) -> (
    SqliteExternalNodeCheckpointStoreV0,
    ExternalNodeCheckpointV0,
    EpochNodeCheckpointV1,
) {
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let (genesis, old, target) = records();
    let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(path).unwrap();
    store.compare_and_advance(None, genesis).unwrap();
    store.compare_and_advance(Some(genesis), old).unwrap();
    (store, old, target)
}
fn next(old: &EpochNodeCheckpointV1) -> EpochNodeCheckpointV1 {
    let mut f = *old.fields();
    f.generation += 1;
    f.predecessor_checksum = old.checksum();
    f.predecessor_kind = EpochCheckpointPredecessorV1::V1;
    f.phase = EpochCheckpointPhaseV1::Ordinary;
    f.target_safety.revision += 1;
    f.target_safety.record_checksum = [f.generation as u8; 32];
    f.target_safety.chain_checksum = [(f.generation + 1) as u8; 32];
    EpochNodeCheckpointV1::new(f).unwrap()
}
#[test]
fn migrate_reopen_prune_origin_and_old_writer_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let (store, old, target) = make_source(&path);
    let mut stale = SqliteExternalNodeCheckpointStoreV0::open_existing(&path).unwrap();
    let mut migrated =
        SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target).unwrap();
    assert_eq!(migrated.load().unwrap(), target);
    let mut old_next_fields = *old.fields();
    old_next_fields.generation += 1;
    old_next_fields.predecessor_checksum = old.checkpoint_checksum();
    assert!(stale
        .compare_and_advance(
            Some(old),
            ExternalNodeCheckpointV0::new(old_next_fields).unwrap()
        )
        .is_err());
    assert!(SqliteExternalNodeCheckpointStoreV0::open_existing(&path).is_err());
    let mut head = target;
    for _ in 0..5 {
        let target = next(&head);
        migrated.compare_and_advance(&head, &target).unwrap();
        migrated.compare_and_advance(&head, &target).unwrap();
        head = target;
    }
    drop(stale);
    drop(migrated);
    let mut reopened = SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &head).unwrap();
    assert_eq!(reopened.load().unwrap(), head);
    let count: i64 = reopened
        .connection
        .as_ref()
        .unwrap()
        .query_row("SELECT count(*) FROM epoch_node_records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    assert!(SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target).is_err());
}
#[test]
fn foreign_source_or_multiple_lineages_never_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let (mut store, old, target) = make_source(&path);
    let mut wrong = *target.fields();
    wrong.source_safety.as_mut().unwrap().chain_checksum = [99; 32];
    let wrong = EpochNodeCheckpointV1::new(wrong).unwrap();
    assert!(SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &wrong).is_err());
    store = SqliteExternalNodeCheckpointStoreV0::open_existing(&path).unwrap();
    assert_eq!(store.load(old.scope()).unwrap(), Some(old));
    let (other, _, _) = records();
    let mut other = *other.fields();
    other.scope = [98; 32];
    other.signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
        other.scope,
        other.signer_journal_id,
        other.signer_exact_watermark.sequence(),
        other.signer_exact_watermark.chain_checksum(),
    )
    .unwrap();
    store
        .compare_and_advance(None, ExternalNodeCheckpointV0::new(other).unwrap())
        .unwrap();
    assert!(matches!(
        SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target),
        Err(EpochNodeStoreErrorV1::MultipleLineagesRequireExplicitMigration)
    ));
    assert!(SqliteExternalNodeCheckpointStoreV0::open_existing(&path).is_ok());
}
#[test]
fn stale_independent_head_and_missing_sidecar_permanently_fence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let (store, old, target) = make_source(&path);
    let mut first =
        SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target).unwrap();
    let mut second = SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target).unwrap();
    let child = next(&target);
    second.compare_and_advance(&target, &child).unwrap();
    assert!(first.confirm_exact(&target).is_err());
    assert!(first.load().is_err());
    fs::remove_file(format!("{}-shm", path.display())).unwrap();
    assert!(second.load().is_err());
    assert!(second.load().is_err());
}
#[test]
fn checksummed_origin_replacement_and_extra_schema_objects_reject() {
    for bad_schema in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        let (store, old, target) = make_source(&path);
        let migrated =
            SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target).unwrap();
        let conn = migrated.connection.as_ref().unwrap();
        if bad_schema {
            conn.execute("CREATE TABLE extra(x INTEGER)", []).unwrap();
        } else {
            conn.execute(
                "UPDATE epoch_node_origin SET original_record=?1",
                params![&records().0.encode_canonical()[..]],
            )
            .unwrap();
        }
        drop(migrated);
        assert!(SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target).is_err());
    }
}
#[test]
fn migration_crash_child() {
    let Ok(path) = std::env::var("TRNM_EPOCH_NODE_CRASH_DB") else {
        return;
    };
    let (_, old, target) = records();
    let source = SqliteExternalNodeCheckpointStoreV0::open_existing(path).unwrap();
    let _ = SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(source, &old, &target).unwrap();
    panic!("crash cut did not run");
}
#[test]
fn actual_sigkill_migration_has_only_exact_source_or_target() {
    for cut_name in [
        "migration-before-commit",
        "migration-after-commit",
        "migration-after-sync",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        let (store, old, target) = make_source(&path);
        drop(store);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "external_node_checkpoint::epoch_node_store_v1::tests::migration_crash_child",
                "--nocapture",
            ])
            .env("TRNM_EPOCH_NODE_CRASH_DB", &path)
            .env("TRNM_EPOCH_NODE_CRASH_CUT", cut_name)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(9), "{cut_name}");
        if cut_name == "migration-before-commit" {
            let mut source = SqliteExternalNodeCheckpointStoreV0::open_existing(&path).unwrap();
            assert_eq!(source.load(old.scope()).unwrap(), Some(old));
            assert!(SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target).is_err());
        } else {
            let mut destination =
                SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target).unwrap();
            assert_eq!(destination.load().unwrap(), target);
            assert!(SqliteExternalNodeCheckpointStoreV0::open_existing(&path).is_err());
        }
    }
}

#[test]
fn cold_reopen_missing_sidecar_rejects_without_recreation() {
    for suffix in ["-wal", "-shm"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.sqlite");
        let (store, old, target) = make_source(&path);
        let migrated =
            SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target).unwrap();
        drop(migrated);
        let missing = PathBuf::from(format!("{}{}", path.display(), suffix));
        assert!(missing.exists());
        fs::remove_file(&missing).unwrap();
        assert!(matches!(
            SqliteEpochNodeCheckpointStoreV1::open_existing(&path, &target),
            Err(EpochNodeStoreErrorV1::OwnerFenced)
        ));
        assert!(!missing.exists());
    }
}

#[test]
fn migration_never_rebinds_replaced_sidecars() {
    for stage in ["migration-before-commit", "migration-after-commit"] {
        for suffix in ["-wal", "-shm"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("checkpoint.sqlite");
            let (store, old, target) = make_source(&path);
            let result = SqliteEpochNodeCheckpointStoreV1::migrate_observed(
                store,
                &old,
                &target,
                |observed| {
                    if observed == stage {
                        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
                        let replaced = sidecar.with_extension("old-sidecar");
                        fs::rename(&sidecar, &replaced).unwrap();
                        fs::copy(&replaced, &sidecar).unwrap();
                        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                    Ok(())
                },
            );
            let expected = if stage == "migration-before-commit" {
                EpochNodeStoreErrorV1::OwnerFenced
            } else {
                EpochNodeStoreErrorV1::CommitUncertain
            };
            assert!(matches!(result,Err(e) if e==expected), "{stage} {suffix}");
        }
    }
}

#[test]
fn oversized_persisted_origin_rejects_and_fences_before_decode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.sqlite");
    let (store, old, target) = make_source(&path);
    let mut migrated =
        SqliteEpochNodeCheckpointStoreV1::migrate_continuing_v0(store, &old, &target).unwrap();
    let injected = Connection::open(&path).unwrap();
    injected.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE epoch_node_origin SET original_record=zeroblob(1048576)").unwrap();
    drop(injected);
    assert!(migrated.load().is_err());
    assert!(migrated.load().is_err());
}
