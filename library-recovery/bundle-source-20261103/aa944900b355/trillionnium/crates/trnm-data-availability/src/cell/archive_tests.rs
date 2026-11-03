use std::io::{Seek, SeekFrom, Write};

use super::*;
use crate::cell::{
    CellCacheConfigV4, CellClosureFileV1, CellContextV1, CellFileRoleV1, CellReleaseClosureV1,
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn config(capacity: u64) -> CellReleaseRetentionConfigV1 {
    CellReleaseRetentionConfigV1 {
        retention: CellRetentionConfigV1 {
            store_id: [21; 32],
            capacity_bytes: capacity,
            maximum_obligations: 32,
        },
        maximum_releases: 16,
    }
}

fn cache(directory: &Path, name: &str) -> CellStoreV1 {
    CellStoreV1::open(
        &directory.join(name),
        CellCacheConfigV4 {
            max_database_bytes: 4 * 1024 * 1024,
            max_logical_bytes: 2 * 1024 * 1024,
            max_chunk_rows: 256,
            max_manifest_rows: 64,
        },
    )
    .unwrap()
}

fn fixture(directory: &Path) -> (CellStoreV1, CellReleaseRetentionContractV1) {
    let cache = cache(directory, "cache.sqlite");
    let context = CellContextV1 {
        family: "release-retention-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let mut files = Vec::new();
    let mut objects = Vec::new();
    for (index, (name, role)) in [
        ("base.bin", CellFileRoleV1::Base),
        ("router.bin", CellFileRoleV1::Router),
        ("tokenizer.json", CellFileRoleV1::Tokenizer),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = vec![index as u8 + 17; 200 + index * 17];
        let path = directory.join(name);
        fs::write(&path, &bytes).unwrap();
        let manifest = cache.pack_file(&path, context.clone(), 16_384).unwrap();
        files.push(CellClosureFileV1 {
            path: name.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: if index == 1 { vec![0, 2] } else { vec![] },
        });
        objects.push(CellRetentionContractV1 {
            operation: [index as u8 + 51; 32],
            funding_operation: [index as u8 + 61; 32],
            manifest,
            retain_from_height: 0,
            retain_until_height: 30,
            maximum_repair_bytes: 8192,
            successor: None,
        });
    }
    objects.sort_by_key(|object| object.manifest.id());
    let closure = CellReleaseClosureV1::new(context, 1, [11; 32], vec![1], files).unwrap();
    let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
    let duty = CellReleaseRetentionContractV1 {
        operation: [31; 32],
        funding_operation: [41; 32],
        responsible_owner: [71; 32],
        failure_domain: [81; 32],
        replica_index: 0,
        required_replicas: 3,
        retain_from_height: 1,
        retain_until_height: 10,
        repair_deadline_height: 9,
        root,
        objects,
    };
    (cache, duty)
}

fn next_duty(first: &CellReleaseRetentionContractV1) -> CellReleaseRetentionContractV1 {
    let closure = first.root.closure();
    let next = CellReleaseClosureV1::new(
        closure.release().context().clone(),
        2,
        closure.loader_profile(),
        closure.roots().to_vec(),
        closure.files().to_vec(),
    )
    .unwrap();
    CellReleaseRetentionContractV1 {
        operation: [32; 32],
        funding_operation: [42; 32],
        retain_until_height: 20,
        repair_deadline_height: 19,
        root: CellModelReleaseRootV1::new(next, vec![first.root.id()]).unwrap(),
        ..first.clone()
    }
}

fn damage_first_object(directory: &Path) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(directory.join("objects/payload.arena"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn lost_release_ack_reconciles_all_targets_without_any_source_or_cache() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(duty.clone(), deadline()).unwrap();
    // Actual members finish, but the process never seals the release ACK.
    for object in &duty.objects {
        store
            .retention
            .acknowledge(object.operation, &source, deadline())
            .unwrap();
    }
    assert_eq!(
        required_row(&store.catalog, &cfg, duty.operation)
            .unwrap()
            .status,
        0
    );
    let before = fs::read(path.join("objects/payload.arena")).unwrap();
    drop(store);
    drop(source);
    fs::remove_file(directory.path().join("cache.sqlite")).unwrap();
    for name in ["base.bin", "router.bin", "tokenizer.json"] {
        fs::remove_file(directory.path().join(name)).unwrap();
    }
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    assert_eq!(store.contract(duty.operation, deadline()).unwrap(), duty);
    let readback = store
        .reconcile_release(duty.operation, deadline(), &mut || Ok(()))
        .unwrap();
    assert!(readback.acknowledged);
    assert!(readback
        .objects
        .iter()
        .all(|object| object.repair_bytes_committed == 0));
    assert_eq!(
        fs::read(path.join("objects/payload.arena")).unwrap(),
        before
    );
}

#[test]
fn complete_closure_is_physically_retained_and_rehydrates_original_cache_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    let pending = store.reserve_release(duty.clone(), deadline()).unwrap();
    assert!(!pending.acknowledged);
    assert_eq!(pending.objects.len(), 3);
    let acknowledged = store
        .acknowledge_release(duty.operation, &source, deadline())
        .unwrap();
    assert!(acknowledged.acknowledged);
    assert!(acknowledged
        .objects
        .iter()
        .all(|object| object.acknowledged));
    assert_eq!(acknowledged.release_root, duty.root.id());
    drop(store);
    drop(source);
    fs::remove_file(directory.path().join("cache.sqlite")).unwrap();
    for name in ["base.bin", "router.bin", "tokenizer.json"] {
        fs::remove_file(directory.path().join(name)).unwrap();
    }
    let target = cache(directory.path(), "target.sqlite");
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    let actual = store
        .populate_cache(duty.operation, &target, deadline())
        .unwrap();
    assert_eq!(actual, acknowledged);
    for object in &duty.objects {
        target
            .verify_complete_until(&object.manifest, deadline())
            .unwrap();
    }
}

#[test]
fn shared_objects_survive_one_history_retirement_and_expiry_requires_explicit_root_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let (source, first) = fixture(directory.path());
    let second = next_duty(&first);
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(first.clone(), deadline()).unwrap();
    let original = store
        .acknowledge_release(first.operation, &source, deadline())
        .unwrap();
    store.reserve_release(second.clone(), deadline()).unwrap();
    let shared = store
        .acknowledge_release(second.operation, &source, deadline())
        .unwrap();
    assert_eq!(
        original.objects, shared.objects,
        "shared manifest duties must not allocate or copy twice"
    );
    assert!(store
        .retire_release(first.operation, 9, deadline())
        .is_err());
    store
        .retire_release(first.operation, 10, deadline())
        .unwrap();
    for object in &first.objects {
        assert!(matches!(
            store.retire_object(object.operation, 1000, None, deadline()),
            Err(CellErrorV1::Invalid(
                "archive object reachable from live duty"
            ))
        ));
    }
    drop(store);
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    // Expiry and reopen do not automatically erase the second root.
    assert!(store
        .retire_object(first.objects[0].operation, 1000, None, deadline())
        .is_err());
    store.verify_release(second.operation, deadline()).unwrap();
    store
        .retire_release(second.operation, 20, deadline())
        .unwrap();
    assert!(store
        .retire_object(first.objects[0].operation, 29, None, deadline())
        .is_err());
    for object in &first.objects {
        assert!(
            store
                .retire_object(object.operation, 30, None, deadline())
                .unwrap()
                .retired
        );
    }
    assert!(
        store.reserve_release(first, deadline()).is_err(),
        "retired history cannot be resurrected"
    );
}

#[test]
fn collected_content_can_be_retained_under_new_funded_operations_without_rewinding_history() {
    let directory = tempfile::tempdir().unwrap();
    let (source, first) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(first.clone(), deadline()).unwrap();
    store
        .acknowledge_release(first.operation, &source, deadline())
        .unwrap();
    store
        .retire_release(first.operation, 30, deadline())
        .unwrap();
    for object in &first.objects {
        store
            .retire_object(object.operation, 30, None, deadline())
            .unwrap();
    }
    let mut next = next_duty(&first);
    next.retain_from_height = 31;
    next.retain_until_height = 40;
    next.repair_deadline_height = 39;
    for object in &mut next.objects {
        object.operation[0] += 100;
        object.funding_operation[0] += 100;
        object.retain_from_height = 31;
        object.retain_until_height = 40;
    }
    store.reserve_release(next.clone(), deadline()).unwrap();
    store
        .acknowledge_release(next.operation, &source, deadline())
        .unwrap();
    assert_eq!(
        required_row(&store.catalog, &cfg, first.operation)
            .unwrap()
            .status,
        2
    );
    drop(store);
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    store.verify_release(next.operation, deadline()).unwrap();
    assert!(store.reserve_release(first, deadline()).is_err());
}

#[test]
fn partial_physical_reservation_keeps_complete_pending_root_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (_, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    // Three short objects fit logically but need three 4-KiB physical slots.
    let cfg = config(8192);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    assert!(store.reserve_release(duty.clone(), deadline()).is_err());
    let row = required_row(&store.catalog, &cfg, duty.operation).unwrap();
    assert_eq!(row.status, 0);
    assert_eq!(row.contract.objects.len(), 3);
    drop(store);
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    assert!(matches!(
        store.retire_release(duty.operation, 1000, deadline()),
        Err(CellErrorV1::Invalid("archive pending duty"))
    ));
    for object in &duty.objects {
        assert!(matches!(
            store.retire_object(object.operation, 1000, None, deadline()),
            Err(CellErrorV1::Invalid(
                "archive object reachable from live duty"
            ))
        ));
    }
}

#[test]
fn lost_initial_copy_keeps_cost_and_requires_distinct_repair_before_release_ack() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let empty = cache(directory.path(), "empty.sqlite");
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(duty.clone(), deadline()).unwrap();
    assert!(store
        .acknowledge_release(duty.operation, &empty, deadline())
        .is_err());
    assert!(store
        .acknowledge_release(duty.operation, &source, deadline())
        .is_err());
    drop(store);
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg).unwrap();
    assert!(store.verify_release(duty.operation, deadline()).is_err());
    let object = &duty.objects[0];
    let repaired = store
        .repair_member(
            duty.operation,
            object.operation,
            [101; 32],
            5,
            &source,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        repaired.initial_copy_bytes_committed,
        object.manifest.size()
    );
    assert_eq!(repaired.repair_bytes_committed, object.manifest.size());
    let ack = store
        .acknowledge_release(duty.operation, &source, deadline())
        .unwrap();
    assert!(ack.acknowledged);
    assert_eq!(
        store
            .repair_member(
                duty.operation,
                object.operation,
                [101; 32],
                5,
                &source,
                deadline(),
                &mut || Ok(())
            )
            .unwrap(),
        repaired
    );
}

#[test]
fn lost_repair_ack_blocks_root_and_physical_gc_until_target_only_reconciliation() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(duty.clone(), deadline()).unwrap();
    store
        .acknowledge_release(duty.operation, &source, deadline())
        .unwrap();
    damage_first_object(&path);
    let object = &duty.objects[0];
    let repair = [101; 32];
    let completed = store
        .repair_member(
            duty.operation,
            object.operation,
            repair,
            5,
            &source,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    // Deterministic crash boundary: payload is fsynced; the exact original
    // repair still has its durable full charge but no completion ACK.
    let mut checksum = Sha256::new();
    checksum.update(b"trnm.cell-retention-repair.v1\0");
    checksum.update(repair);
    checksum.update(object.operation);
    checksum.update(object.manifest.size().to_be_bytes());
    checksum.update([0]);
    Connection::open(path.join("objects/retention.sqlite"))
        .unwrap()
        .execute(
            "UPDATE repairs SET complete=0,checksum=?1 WHERE operation=?2",
            params![checksum.finalize().to_vec(), repair.as_slice()],
        )
        .unwrap();
    let before = fs::read(path.join("objects/payload.arena")).unwrap();
    drop(store);
    drop(source);
    fs::remove_file(directory.path().join("cache.sqlite")).unwrap();
    let mut store = CellReleaseRetentionStoreV1::open(&path, cfg.clone()).unwrap();
    // Availability is real, but the unknown effect must still protect both
    // release reachability and the underlying physical slot.
    store.verify_release(duty.operation, deadline()).unwrap();
    assert!(matches!(
        store.retire_release(duty.operation, 30, deadline()),
        Err(CellErrorV1::Invalid("retention unsettled repair"))
    ));
    assert_eq!(
        required_row(&store.catalog, &cfg, duty.operation)
            .unwrap()
            .status,
        1
    );
    assert!(matches!(
        store
            .retention
            .retire(object.operation, 30, None, deadline()),
        Err(CellErrorV1::Invalid("retention unsettled repair"))
    ));
    assert!(store
        .retire_object(object.operation, 30, None, deadline())
        .is_err());
    let reconciled = store
        .reconcile_repair_member(
            duty.operation,
            object.operation,
            repair,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(reconciled, completed);
    assert_eq!(
        fs::read(path.join("objects/payload.arena")).unwrap(),
        before
    );
    store
        .retire_release(duty.operation, 30, deadline())
        .unwrap();
    for object in &duty.objects {
        assert!(
            store
                .retire_object(object.operation, 30, None, deadline())
                .unwrap()
                .retired
        );
    }
}

#[test]
fn corruption_invalidates_fresh_readback_and_missed_repair_deadline_never_reclaims_duty() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let mut store = CellReleaseRetentionStoreV1::create(&path, config(12_288)).unwrap();
    store.reserve_release(duty.clone(), deadline()).unwrap();
    store
        .acknowledge_release(duty.operation, &source, deadline())
        .unwrap();
    damage_first_object(&path);
    assert!(store.verify_release(duty.operation, deadline()).is_err());
    assert!(matches!(
        store.repair_member(
            duty.operation,
            duty.objects[0].operation,
            [101; 32],
            10,
            &source,
            deadline(),
            &mut || Ok(())
        ),
        Err(CellErrorV1::Invalid("archive repair height deadline"))
    ));
    assert!(store
        .retire_release(duty.operation, 30, deadline())
        .is_err());
    assert!(store
        .retire_object(duty.objects[0].operation, 30, None, deadline())
        .is_err());
}

#[test]
fn contract_identity_freezes_owner_domain_replica_funding_repair_and_root() {
    let directory = tempfile::tempdir().unwrap();
    let (_, duty) = fixture(directory.path());
    let cfg = config(12_288);
    let original = duty.commitment(&cfg).unwrap();
    let mut changed = Vec::new();
    let mut v = duty.clone();
    v.responsible_owner[0] ^= 1;
    changed.push(v);
    let mut v = duty.clone();
    v.failure_domain[0] ^= 1;
    changed.push(v);
    let mut v = duty.clone();
    v.replica_index = 1;
    changed.push(v);
    let mut v = duty.clone();
    v.required_replicas = 4;
    changed.push(v);
    let mut v = duty.clone();
    v.funding_operation[0] ^= 1;
    changed.push(v);
    let mut v = duty.clone();
    v.repair_deadline_height -= 1;
    changed.push(v);
    let mut v = duty.clone();
    v.root = next_duty(&duty).root;
    changed.push(v);
    let mut store =
        CellReleaseRetentionStoreV1::create(&directory.path().join("archive"), cfg.clone())
            .unwrap();
    store.reserve_release(duty, deadline()).unwrap();
    for value in changed {
        assert_ne!(value.commitment(&cfg).unwrap(), original);
        assert!(matches!(
            store.reserve_release(value, deadline()),
            Err(CellErrorV1::Invalid("archive operation contract changed"))
        ));
    }
}

#[test]
fn missing_dependency_wrong_terms_or_shared_operation_alias_refuse_before_new_root_intent() {
    let directory = tempfile::tempdir().unwrap();
    let (_, first) = fixture(directory.path());
    let cfg = config(16_384);
    let mut store =
        CellReleaseRetentionStoreV1::create(&directory.path().join("archive"), cfg.clone())
            .unwrap();
    store.reserve_release(first.clone(), deadline()).unwrap();
    let next = next_duty(&first);
    let mut missing = next.clone();
    missing.objects.pop();
    let mut short = next.clone();
    short.objects[0].retain_until_height = 19;
    let mut alias = next.clone();
    alias.objects[0].operation = [100; 32];
    let mut changed = next.clone();
    changed.objects[0].maximum_repair_bytes += 1;
    for duty in [missing, short, alias, changed] {
        assert!(store.reserve_release(duty, deadline()).is_err());
        assert!(read_row(&store.catalog, &cfg, next.operation)
            .unwrap()
            .is_none());
    }
}

#[test]
fn forged_status_cannot_make_reachable_objects_collectible() {
    let directory = tempfile::tempdir().unwrap();
    let (source, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store.reserve_release(duty.clone(), deadline()).unwrap();
    store
        .acknowledge_release(duty.operation, &source, deadline())
        .unwrap();
    store
        .catalog
        .execute(
            "UPDATE release_duties SET status=2 WHERE operation=?1",
            [duty.operation.as_slice()],
        )
        .unwrap();
    assert!(store
        .retire_object(duty.objects[0].operation, 1000, None, deadline())
        .is_err());
    drop(store);
    assert!(CellReleaseRetentionStoreV1::open(&path, cfg).is_err());
}

#[test]
fn unknown_schema_or_missing_catalog_never_opens_as_empty_archive() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    store
        .catalog
        .execute_batch(
            "CREATE TRIGGER sqliteX_hidden_gc AFTER UPDATE ON release_duties BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(store);
    assert!(CellReleaseRetentionStoreV1::open(&path, cfg.clone()).is_err());
    fs::remove_file(path.join("archive.sqlite")).unwrap();
    assert!(CellReleaseRetentionStoreV1::open(&path, cfg).is_err());
    assert!(!path.join("archive.sqlite").exists());
}

#[test]
fn retired_root_history_still_consumes_capacity_and_cannot_rebind_object_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (source, first) = fixture(directory.path());
    let mut cfg = config(12_288);
    cfg.maximum_releases = 1;
    let mut store =
        CellReleaseRetentionStoreV1::create(&directory.path().join("archive"), cfg).unwrap();
    store.reserve_release(first.clone(), deadline()).unwrap();
    store
        .acknowledge_release(first.operation, &source, deadline())
        .unwrap();
    store
        .retire_release(first.operation, 10, deadline())
        .unwrap();
    assert!(matches!(
        store.reserve_release(next_duty(&first), deadline()),
        Err(CellErrorV1::Invalid("archive root capacity"))
    ));
    assert!(store
        .retire_object([255; 32], 1000, None, deadline())
        .is_err());
}

#[test]
fn codec_rejects_truncation_trailing_data_oversize_and_invalid_replica_before_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let (_, duty) = fixture(directory.path());
    let cfg = config(12_288);
    let wire = duty.encode();
    assert_eq!(
        CellReleaseRetentionContractV1::decode(&wire, &cfg).unwrap(),
        duty
    );
    for length in [0, 3, 4, 132, wire.len() - 1] {
        assert!(CellReleaseRetentionContractV1::decode(&wire[..length], &cfg).is_err());
    }
    let mut extra = wire;
    extra.push(0);
    assert!(CellReleaseRetentionContractV1::decode(&extra, &cfg).is_err());
    assert!(CellReleaseRetentionContractV1::decode(
        &vec![0; MAX_CELL_ARCHIVE_CONTRACT_BYTES_V1 + 1],
        &cfg
    )
    .is_err());
    let mut invalid = duty;
    invalid.replica_index = invalid.required_replicas;
    assert!(invalid.validate(&cfg).is_err());
}

#[test]
fn absolute_deadline_and_original_physical_exclusive_owner_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let (_, duty) = fixture(directory.path());
    let path = directory.path().join("archive");
    let cfg = config(12_288);
    let mut store = CellReleaseRetentionStoreV1::create(&path, cfg.clone()).unwrap();
    assert!(CellReleaseRetentionStoreV1::open(&path, cfg.clone()).is_err());
    let elapsed = Instant::now() - Duration::from_secs(1);
    assert!(store.reserve_release(duty.clone(), elapsed).is_err());
    assert!(read_row(&store.catalog, &cfg, duty.operation)
        .unwrap()
        .is_none());
    store.reserve_release(duty.clone(), deadline()).unwrap();
    assert!(store.retire_release(duty.operation, 1000, elapsed).is_err());
    assert_eq!(
        required_row(&store.catalog, &cfg, duty.operation)
            .unwrap()
            .status,
        0
    );
}
