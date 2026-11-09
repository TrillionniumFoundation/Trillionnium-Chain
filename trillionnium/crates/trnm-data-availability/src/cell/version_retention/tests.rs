use super::*;
use crate::cell::{
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellModelReleaseRootV1, CellReleaseClosureV1,
};
use std::io::{Seek, SeekFrom, Write};

#[path = "tests/residency.rs"]
mod residency;

#[path = "tests/shard_plan.rs"]
mod shard_plan;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn identity(tag: u8, seed: u8) -> CellDigestV1 {
    Sha256::digest([0xc3, tag, seed]).into()
}

fn config(slots: u64) -> CellVersionRetentionConfigV3 {
    CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: [73; 32],
            capacity_bytes: slots * 4096,
            maximum_obligations: 64,
        },
        maximum_versions: 32,
        maximum_metadata_bytes: 64 << 20,
    }
}

fn cache(path: &Path) -> CellStoreV1 {
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 64 << 20,
            max_logical_bytes: 32 << 20,
            max_chunk_rows: 128,
            max_manifest_rows: 64,
        },
    )
    .unwrap()
}

fn make_contract(cache: &CellStoreV1, seed: u8) -> CellVersionRetentionContractV3 {
    let context = |runtime| CellContextV1 {
        family: "durable-version-owner".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    };
    let make = |ctx: CellContextV1, byte: u8| {
        let bytes = vec![byte; 17];
        let digest: CellDigestV1 = Sha256::digest(&bytes).into();
        let manifest = CellManifestV1::new(
            ctx,
            bytes.len() as u64,
            digest,
            16384,
            vec![CellChunkV1 {
                size: bytes.len() as u32,
                sha256: digest,
            }],
        )
        .unwrap();
        cache
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        cache.put_chunk(&manifest.chunks()[0], &bytes).unwrap();
        manifest
    };
    let env = make(context(identity(90, seed)), seed);
    let file = |manifest: &CellManifestV1, name: &str, role| CellClosureFileV1 {
        path: name.into(),
        role,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies: vec![],
    };
    let environment = CellReleaseClosureV1::new(
        env.context().clone(),
        11,
        [51; 32],
        vec![0],
        vec![file(&env, "runtime.bin", CellFileRoleV1::Configuration)],
    )
    .unwrap();
    let model = make(context(environment.id()), seed.wrapping_add(1));
    let closure = CellReleaseClosureV1::new(
        model.context().clone(),
        17,
        [52; 32],
        vec![0],
        vec![file(&model, "base.bin", CellFileRoleV1::Base)],
    )
    .unwrap();
    let pin = |closure: &CellReleaseClosureV1, role| CellVersionLoaderPinV3 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![role],
        max_payload_bytes: 4096,
        max_chunks: 4,
    };
    let model_pin = pin(&closure, CellFileRoleV1::Base);
    let env_pin = pin(&environment, CellFileRoleV1::Configuration);
    let mut manifests = vec![model, env];
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, vec![]).unwrap(),
        environment,
        manifests,
    )
    .unwrap();
    let objects = version
        .manifests()
        .iter()
        .enumerate()
        .map(|(i, manifest)| CellRetentionContractV1 {
            operation: identity(10 + i as u8, seed),
            funding_operation: identity(20 + i as u8, seed),
            manifest: manifest.clone(),
            retain_from_height: 10,
            retain_until_height: 120,
            maximum_repair_bytes: 4 * manifest.size(),
            successor: None,
        })
        .collect();
    CellVersionRetentionContractV3 {
        operation: identity(1, seed),
        funding_operation: identity(2, seed),
        responsible_owner: [41; 32],
        failure_domain: [42; 32],
        replica_index: 0,
        required_replicas: 1,
        retain_from_height: 10,
        retain_until_height: 100,
        repair_deadline_height: 90,
        version,
        model: model_pin,
        environment: env_pin,
        tensor_model: None,
        snapshot: None,
        objects,
    }
}

fn reserve(store: &mut CellVersionRetentionStoreV3, contract: &CellVersionRetentionContractV3) {
    let anchor = store.anchor(deadline()).unwrap();
    store
        .reserve_version(contract.clone(), anchor, deadline())
        .unwrap();
}

fn active(
    store: &mut CellVersionRetentionStoreV3,
    contract: &CellVersionRetentionContractV3,
    cache: &CellStoreV1,
) {
    reserve(store, contract);
    assert!(
        store
            .acknowledge_version(contract.operation, cache, deadline())
            .unwrap()
            .acknowledged
    );
}

fn assert_invalid<T>(result: CellResultV1<T>, expected: &'static str) {
    match result {
        Err(CellErrorV1::Invalid(actual)) => assert_eq!(actual, expected),
        Err(other) => panic!("expected {expected}, got {other}"),
        Ok(_) => panic!("expected {expected}, got success"),
    }
}

#[test]
fn complete_owner_codec_binds_both_independent_generations_and_all_original_terms() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 1);
    let config = config(8);
    assert_ne!(
        contract.model.selected_generation,
        contract.environment.selected_generation
    );
    let wire = contract.encode(&config).unwrap();
    assert_eq!(&wire[..4], b"TCA3");
    assert_eq!(
        CellVersionRetentionContractV3::decode(&wire, &config).unwrap(),
        contract
    );
    let mut wrong = contract.clone();
    wrong.environment.selected_generation += 1;
    assert!(wrong.validate(&config).is_err());
    let mut incomplete = contract.clone();
    incomplete.objects.pop();
    assert_invalid(
        incomplete.validate(&config),
        "version retention complete dependency set",
    );
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_invalid(
        CellVersionRetentionContractV3::decode(&trailing, &config),
        "version retention trailing contract",
    );
    let mut old = wire;
    old[3] = b'2';
    assert_invalid(
        CellVersionRetentionContractV3::decode(&old, &config),
        "version retention contract namespace",
    );
}

#[test]
fn complete_owner_matches_independent_python_wire_and_real_three_transition_anchors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-version-retention-v3.json"
    )))
    .unwrap();
    let wire = hex::decode(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let cfg = config(64);
    let contract = CellVersionRetentionContractV3::decode(&wire, &cfg).unwrap();
    assert_eq!(contract.encode(&cfg).unwrap(), wire);
    assert_eq!(wire.len() as u64, fixture["wire_bytes"].as_u64().unwrap());
    assert_eq!(
        hex::encode(contract.commitment(&cfg).unwrap()),
        fixture["contract_sha256"].as_str().unwrap()
    );
    let (_source_dir, source, version) = crate::cell::version::tests::fixture();
    assert_eq!(contract.version, version);
    assert_eq!(contract.model.selected_generation, 2);
    assert_eq!(contract.environment.selected_generation, 1);
    let directory = tempfile::tempdir().unwrap();
    let mut store =
        CellVersionRetentionStoreV3::create(&directory.path().join("owner"), cfg).unwrap();
    let check = |anchor: CellVersionCatalogAnchorV3, index: usize| {
        assert_eq!(anchor.generation(), index as u64);
        assert_eq!(
            hex::encode(anchor.commitment()),
            fixture["anchors"][index]["commitment"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(anchor.encode()),
            fixture["anchors"][index]["wire_hex"].as_str().unwrap()
        );
        assert_eq!(
            CellVersionCatalogAnchorV3::decode(&anchor.encode()).unwrap(),
            anchor
        );
    };
    check(store.anchor(deadline()).unwrap(), 0);
    reserve(&mut store, &contract);
    check(store.anchor(deadline()).unwrap(), 1);
    store
        .acknowledge_version(contract.operation, &source, deadline())
        .unwrap();
    check(store.anchor(deadline()).unwrap(), 2);
    store
        .retire_version(contract.operation, 150, deadline())
        .unwrap();
    check(store.anchor(deadline()).unwrap(), 3);
}

#[test]
fn complete_owner_model_only_copy_restarts_pending_and_keeps_environment_protected() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 2);
    let path = dir.path().join("owner");
    let cfg = config(8);
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    reserve(&mut store, &contract);
    let model_id = contract.version.model().closure().release().cells()[0];
    let model = contract
        .objects
        .iter()
        .find(|object| object.manifest.id() == model_id)
        .unwrap();
    store
        .acknowledge_member(contract.operation, model.operation, &source, deadline())
        .unwrap();
    let anchor = store.anchor(deadline()).unwrap();
    let before = store.inventory(150, deadline()).unwrap();
    assert_eq!(before.usage.pending_versions, 1);
    assert_eq!(before.usage.expired_unretired_versions, 1);
    assert_eq!(before.usage.initial_copy_bytes_committed, 17);
    drop(store);
    drop(source);
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    let mut store = CellVersionRetentionStoreV3::open(&path, cfg, anchor).unwrap();
    assert!(store
        .reconcile_version(contract.operation, deadline(), &mut || Ok(()))
        .is_err());
    let after = store.inventory(150, deadline()).unwrap();
    assert_eq!(after.usage, before.usage);
    assert_eq!(after.protected[0].contract, contract);
    assert_invalid(
        store.retire_version(contract.operation, 150, deadline()),
        "version retention pending duty",
    );
    for object in &contract.objects {
        assert_invalid(
            store.retire_object(object.operation, 150, None, deadline()),
            "version retention object reachable from protected duty",
        );
    }
}

#[test]
fn complete_owner_lost_catalog_ack_reconciles_actual_targets_after_cache_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 3);
    let path = dir.path().join("owner");
    let cfg = config(8);
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    reserve(&mut store, &contract);
    for object in &contract.objects {
        store
            .acknowledge_member(contract.operation, object.operation, &source, deadline())
            .unwrap();
    }
    let anchor = store.anchor(deadline()).unwrap();
    let before = store.inventory(20, deadline()).unwrap().usage;
    let mut blocker = Connection::open(path.join("versions.sqlite")).unwrap();
    let transaction = blocker
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(store
        .reconcile_version(
            contract.operation,
            Instant::now() + Duration::from_millis(150),
            &mut || Ok(())
        )
        .is_err());
    transaction.rollback().unwrap();
    drop(blocker);
    drop(store);
    drop(source);
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    let mut store = CellVersionRetentionStoreV3::open(&path, cfg, anchor).unwrap();
    let recovered = store
        .reconcile_version(contract.operation, deadline(), &mut || Ok(()))
        .unwrap();
    assert!(recovered.acknowledged);
    assert_eq!(recovered.anchor.generation(), anchor.generation() + 1);
    let repeated = store
        .reconcile_version(contract.operation, deadline(), &mut || Ok(()))
        .unwrap();
    assert_eq!(repeated.anchor, recovered.anchor);
    let after = store.inventory(20, deadline()).unwrap().usage;
    assert_eq!(
        after.initial_copy_bytes_committed,
        before.initial_copy_bytes_committed
    );
    assert_eq!(after.repair_bytes_committed, 0);
    assert_eq!(after.occupied_bytes, before.occupied_bytes);
}

#[test]
fn complete_owner_prior_pending_unallocated_union_cannot_double_promise_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 4);
    let second = make_contract(&source, 5);
    let cfg = config(2);
    let path = dir.path().join("owner");
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    let mut blocker = Connection::open(path.join("objects/retention.sqlite")).unwrap();
    let transaction = blocker
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let initial = store.anchor(deadline()).unwrap();
    assert!(store
        .reserve_version(
            first.clone(),
            initial,
            Instant::now() + Duration::from_secs(3)
        )
        .is_err());
    transaction.rollback().unwrap();
    drop(blocker);
    let before = store.inventory(20, deadline()).unwrap();
    assert_eq!(before.usage.pending_versions, 1);
    assert_eq!(before.usage.occupied_bytes, 0);
    assert_eq!(before.usage.promised_unallocated_bytes, 8192);
    drop(store);
    let mut store = CellVersionRetentionStoreV3::open(&path, cfg, before.anchor).unwrap();
    assert_invalid(
        store.reserve_version(second, before.anchor, deadline()),
        "version retention pending union capacity",
    );
    assert_eq!(store.inventory(20, deadline()).unwrap().usage, before.usage);
    reserve(&mut store, &first);
    let after = store.inventory(20, deadline()).unwrap();
    assert_eq!(after.anchor, before.anchor);
    assert_eq!(after.usage.occupied_bytes, 8192);
    assert_eq!(after.usage.promised_unallocated_bytes, 0);
}

#[test]
fn complete_owner_anchor_accepts_committed_unknown_prefix_and_rejects_old_catalog_restore() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 6);
    let cfg = config(8);
    let path = dir.path().join("owner");
    let backup = dir.path().join("old.sqlite");
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    reserve(&mut store, &contract);
    let pending = store.anchor(deadline()).unwrap();
    store
        .catalog
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    let current = store
        .acknowledge_version(contract.operation, &source, deadline())
        .unwrap()
        .anchor;
    assert!(current.generation() > pending.generation());
    drop(store);
    let store = CellVersionRetentionStoreV3::open(&path, cfg.clone(), pending).unwrap();
    assert_eq!(store.anchor(deadline()).unwrap(), current);
    drop(store);
    fs::copy(&backup, path.join("versions.sqlite")).unwrap();
    assert_invalid(
        CellVersionRetentionStoreV3::open(&path, cfg, current),
        "version retention catalog rollback",
    );
}

#[test]
fn complete_owner_stale_generation_and_changed_original_contract_do_not_mutate_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 7);
    let second = make_contract(&source, 8);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    let old = store.anchor(deadline()).unwrap();
    store
        .reserve_version(first.clone(), old, deadline())
        .unwrap();
    let current = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(second, old, deadline()),
        "version retention stale admission generation",
    );
    let mut changed = first.clone();
    changed.retain_from_height += 1;
    assert_invalid(
        store.reserve_version(changed, current, deadline()),
        "version retention original operation changed/retired",
    );
    assert_eq!(store.anchor(deadline()).unwrap(), current);
    assert_eq!(
        store
            .reserve_version(first, old, deadline())
            .unwrap()
            .anchor,
        current
    );
}

#[test]
fn complete_owner_shared_objects_survive_first_retirement_and_expired_unretired_reference() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 9);
    let mut second = first.clone();
    second.operation = identity(1, 10);
    second.funding_operation = identity(2, 10);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(2)).unwrap();
    active(&mut store, &first, &source);
    active(&mut store, &second, &source);
    assert_eq!(
        store
            .inventory(20, deadline())
            .unwrap()
            .usage
            .initial_copy_bytes_committed,
        34
    );
    store
        .retire_version(first.operation, 150, deadline())
        .unwrap();
    let remaining = store.inventory(150, deadline()).unwrap();
    assert_eq!(remaining.usage.protected_versions, 1);
    assert_eq!(remaining.usage.expired_unretired_versions, 1);
    for object in &first.objects {
        assert_invalid(
            store.retire_object(object.operation, 150, None, deadline()),
            "version retention object reachable from protected duty",
        );
    }
    store
        .retire_version(second.operation, 150, deadline())
        .unwrap();
    let retired = store.inventory(150, deadline()).unwrap();
    assert_eq!(retired.usage.retired_version_occupied_bytes, 8192);
    assert_eq!(retired.usage.occupied_bytes, 8192);
    for object in &first.objects {
        assert!(
            store
                .retire_object(object.operation, 150, None, deadline())
                .unwrap()
                .retired
        );
    }
    let collected = store.inventory(150, deadline()).unwrap().usage;
    assert_eq!(collected.occupied_bytes, 0);
    assert_eq!(collected.historical_objects, 2);
    assert_eq!(collected.historical_versions, 2);
    assert_eq!(collected.initial_copy_bytes_committed, 34);
}

#[test]
fn complete_owner_retired_root_live_slots_stay_charged_until_physical_gc() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 11);
    let next = make_contract(&source, 12);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(2)).unwrap();
    active(&mut store, &first, &source);
    store
        .retire_version(first.operation, 150, deadline())
        .unwrap();
    let before = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(next.clone(), before, deadline()),
        "version retention pending union capacity",
    );
    for object in &first.objects {
        store
            .retire_object(object.operation, 150, None, deadline())
            .unwrap();
    }
    reserve(&mut store, &next);
    assert_eq!(
        store
            .inventory(150, deadline())
            .unwrap()
            .usage
            .occupied_bytes,
        8192
    );
    assert_invalid(
        store.reserve_version(first, before, deadline()),
        "version retention original operation changed/retired",
    );
}

#[test]
fn complete_owner_retired_identity_history_never_reclaims_record_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 13);
    let next = make_contract(&source, 14);
    let mut cfg = config(4);
    cfg.maximum_versions = 1;
    let path = dir.path().join("owner");
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    active(&mut store, &first, &source);
    store
        .retire_version(first.operation, 150, deadline())
        .unwrap();
    for object in &first.objects {
        store
            .retire_object(object.operation, 150, None, deadline())
            .unwrap();
    }
    let anchor = store.anchor(deadline()).unwrap();
    drop(store);
    let mut store = CellVersionRetentionStoreV3::open(&path, cfg, anchor).unwrap();
    assert_invalid(
        store.reserve_version(next, anchor, deadline()),
        "version retention catalog capacity",
    );
    let history = store.audited_duties(deadline()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].state, CellVersionRetentionStateV3::Retired);
}

#[test]
fn complete_owner_unknown_repair_with_fsynced_healthy_target_blocks_gc_until_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 15);
    let cfg = config(8);
    let path = dir.path().join("owner");
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    active(&mut store, &contract, &source);
    let object = &contract.objects[0];
    let offset = store
        .retention
        .catalog_inventory(deadline())
        .unwrap()
        .into_iter()
        .find(|row| row.operation == object.operation)
        .unwrap()
        .offset as usize;
    let arena = path.join("objects/payload.arena");
    let mut file = fs::OpenOptions::new().write(true).open(&arena).unwrap();
    file.seek(SeekFrom::Start(offset as u64)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(store
        .verify_version(contract.operation, deadline())
        .is_err());
    let repair = identity(60, 15);
    let mut healthy_checkpoints = 0;
    let mut checkpoint = || {
        let bytes = fs::read(&arena)?;
        if <CellDigestV1>::from(Sha256::digest(&bytes[offset..offset + 17]))
            == object.manifest.payload_sha256()
        {
            healthy_checkpoints += 1;
            // Real checkpoints follow payload write, whole hash, then fsync.
            if healthy_checkpoints == 3 {
                return Err(CellErrorV1::Invalid("test stopped after target fsync"));
            }
        }
        Ok(())
    };
    assert_invalid(
        store.repair_member(
            contract.operation,
            object.operation,
            repair,
            20,
            &source,
            deadline(),
            &mut checkpoint,
        ),
        "test stopped after target fsync",
    );
    assert_eq!(healthy_checkpoints, 3);
    let raw = Connection::open(path.join("objects/retention.sqlite")).unwrap();
    let pending: (u64, u8) = raw
        .query_row(
            "SELECT amount,complete FROM repairs WHERE operation=?1",
            [repair.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(pending, (17, 0));
    drop(raw);
    store
        .verify_version(contract.operation, deadline())
        .unwrap();
    assert_invalid(
        store.retire_version(contract.operation, 150, deadline()),
        "retention unsettled repair",
    );
    let before_bytes = fs::read(&arena).unwrap();
    let before = store.inventory(150, deadline()).unwrap();
    assert_eq!(before.usage.repair_bytes_committed, 17);
    drop(store);
    drop(source);
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    let mut store = CellVersionRetentionStoreV3::open(&path, cfg, before.anchor).unwrap();
    store
        .reconcile_repair_member(
            contract.operation,
            object.operation,
            repair,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(fs::read(&arena).unwrap(), before_bytes);
    assert_eq!(
        store
            .inventory(150, deadline())
            .unwrap()
            .usage
            .repair_bytes_committed,
        17
    );
    store
        .retire_version(contract.operation, 150, deadline())
        .unwrap();
}

#[test]
fn complete_owner_failed_original_copy_is_not_redispatched_with_a_good_cache() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let empty = cache(&dir.path().join("empty.sqlite"));
    let contract = make_contract(&source, 16);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    reserve(&mut store, &contract);
    assert!(store
        .acknowledge_version(contract.operation, &empty, deadline())
        .is_err());
    let before = store.inventory(20, deadline()).unwrap();
    assert_eq!(before.usage.initial_copy_bytes_committed, 17);
    assert!(store
        .acknowledge_version(contract.operation, &source, deadline())
        .is_err());
    assert_eq!(store.inventory(20, deadline()).unwrap().usage, before.usage);
    store
        .repair_member(
            contract.operation,
            contract.objects[0].operation,
            identity(60, 16),
            20,
            &source,
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(
        store
            .acknowledge_version(contract.operation, &source, deadline())
            .unwrap()
            .acknowledged
    );
    let after = store.inventory(20, deadline()).unwrap().usage;
    assert_eq!(after.initial_copy_bytes_committed, 34);
    assert_eq!(after.repair_bytes_committed, 17);
}

#[test]
fn complete_owner_service_view_cannot_hide_pending_or_expired_members_of_r() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 17);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    reserve(&mut store, &contract);
    assert_invalid(
        store.service_set(20, 90, deadline()),
        "version retention complete service unavailable",
    );
    store
        .acknowledge_version(contract.operation, &source, deadline())
        .unwrap();
    let set = store.service_set(20, 90, deadline()).unwrap();
    assert_eq!(set.referenced_objects().unwrap().len(), 2);
    assert_invalid(
        store.service_set(99, 101, deadline()),
        "version retention complete service unavailable",
    );
    assert_eq!(store.inventory(101, deadline()).unwrap().protected.len(), 1);
}

#[test]
fn complete_owner_expired_corrupt_acknowledged_payload_can_retire_without_refund() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 18);
    let path = dir.path().join("owner");
    let mut store = CellVersionRetentionStoreV3::create(&path, config(8)).unwrap();
    active(&mut store, &contract, &source);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path.join("objects/payload.arena"))
        .unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(store
        .verify_version(contract.operation, deadline())
        .is_err());
    assert_invalid(
        store.retire_version(contract.operation, 99, deadline()),
        "version retention lease not expired",
    );
    assert_invalid(
        store.repair_member(
            contract.operation,
            contract.objects[0].operation,
            identity(60, 18),
            150,
            &source,
            deadline(),
            &mut || Ok(()),
        ),
        "version retention repair height deadline",
    );
    let before = store.inventory(150, deadline()).unwrap().usage;
    store
        .retire_version(contract.operation, 150, deadline())
        .unwrap();
    for object in &contract.objects {
        assert!(
            store
                .retire_object(object.operation, 150, None, deadline())
                .unwrap()
                .retired
        );
    }
    let after = store.inventory(150, deadline()).unwrap().usage;
    assert_eq!(
        after.initial_copy_bytes_committed,
        before.initial_copy_bytes_committed
    );
    assert_eq!(after.repair_bytes_committed, before.repair_bytes_committed);
    assert_eq!(after.historical_objects, 2);
    assert_eq!(after.occupied_bytes, 0);
}

#[test]
fn complete_owner_snapshot_link_requires_real_completed_predecessor_and_unique_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let original = make_contract(&source, 19);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    reserve(&mut store, &original);
    let mut next = original.clone();
    next.operation = identity(1, 20);
    next.funding_operation = identity(2, 20);
    next.snapshot = Some(CellVersionSnapshotLinkV3 {
        schedule: [88; 32],
        ordinal: 1,
        due_height: 50,
        predecessor_operation: original.operation,
        predecessor_contract: store.contract_commitment(&original).unwrap(),
    });
    let anchor = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(next.clone(), anchor, deadline()),
        "version retention snapshot predecessor",
    );
    store
        .acknowledge_version(original.operation, &source, deadline())
        .unwrap();
    let mut wrong = next.clone();
    wrong.snapshot.as_mut().unwrap().predecessor_contract[0] ^= 1;
    let anchor = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(wrong, anchor, deadline()),
        "version retention snapshot predecessor",
    );
    reserve(&mut store, &next);
    assert_eq!(store.audited_duties(deadline()).unwrap().len(), 2);
    let mut duplicate = next.clone();
    duplicate.operation = identity(1, 21);
    duplicate.funding_operation = identity(2, 21);
    let anchor = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(duplicate, anchor, deadline()),
        "version retention snapshot identity replay",
    );
    store
        .reconcile_version(next.operation, deadline(), &mut || Ok(()))
        .unwrap();
    let mut third = next.clone();
    third.operation = identity(1, 22);
    third.funding_operation = identity(2, 22);
    third.snapshot.as_mut().unwrap().ordinal = 2;
    third.snapshot.as_mut().unwrap().due_height = 60;
    let anchor = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(third.clone(), anchor, deadline()),
        "version retention snapshot cursor gap",
    );
    third.snapshot.as_mut().unwrap().predecessor_operation = next.operation;
    third.snapshot.as_mut().unwrap().predecessor_contract =
        store.contract_commitment(&next).unwrap();
    reserve(&mut store, &third);
    assert_eq!(
        store
            .inventory(20, deadline())
            .unwrap()
            .usage
            .initial_copy_bytes_committed,
        34
    );
}

#[test]
fn complete_owner_namespace_or_event_corruption_never_opens_as_empty_history() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 23);
    let cfg = config(8);
    let path = dir.path().join("owner");
    let mut store = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    reserve(&mut store, &contract);
    let anchor = store.anchor(deadline()).unwrap();
    drop(store);
    let raw = Connection::open(path.join("versions.sqlite")).unwrap();
    raw.pragma_update(None, "application_id", 0x5443_4132_i64)
        .unwrap();
    drop(raw);
    assert_invalid(
        CellVersionRetentionStoreV3::open(&path, cfg.clone(), anchor),
        "version retention namespace",
    );
    let raw = Connection::open(path.join("versions.sqlite")).unwrap();
    let count: u64 = raw
        .query_row("SELECT count(*) FROM version_duties", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    raw.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    raw.execute("DELETE FROM version_events", []).unwrap();
    drop(raw);
    assert_invalid(
        CellVersionRetentionStoreV3::open(&path, cfg, anchor),
        "version retention event capacity",
    );
}

#[test]
fn complete_owner_metadata_cap_refuses_before_new_pending_identity() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let first = make_contract(&source, 24);
    let second = make_contract(&source, 25);
    let mut cfg = config(8);
    cfg.maximum_metadata_bytes = first.encode(&cfg).unwrap().len() as u64;
    let mut store = CellVersionRetentionStoreV3::create(&dir.path().join("owner"), cfg).unwrap();
    reserve(&mut store, &first);
    let before = store.inventory(20, deadline()).unwrap();
    assert_invalid(
        store.reserve_version(second, before.anchor, deadline()),
        "version retention catalog capacity",
    );
    assert_eq!(store.inventory(20, deadline()).unwrap().usage, before.usage);
}

#[test]
fn complete_owner_all_pending_versions_count_toward_protected_cap_even_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let template = make_contract(&source, 26);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(2)).unwrap();
    for seed in 30..46 {
        let mut next = template.clone();
        next.operation = identity(1, seed);
        next.funding_operation = identity(2, seed);
        reserve(&mut store, &next);
    }
    let before = store.inventory(150, deadline()).unwrap();
    assert_eq!(before.usage.protected_versions, 16);
    assert_eq!(before.usage.expired_unretired_versions, 16);
    let mut next = template;
    next.operation = identity(1, 46);
    next.funding_operation = identity(2, 46);
    assert_invalid(
        store.reserve_version(next, before.anchor, deadline()),
        "version retention protected capacity",
    );
    assert_eq!(store.anchor(deadline()).unwrap(), before.anchor);
}

#[test]
fn complete_owner_deadline_and_cancellation_never_create_an_admitted_empty_subset() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("cache.sqlite"));
    let contract = make_contract(&source, 27);
    let mut store =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    let empty = store.anchor(deadline()).unwrap();
    assert_invalid(
        store.reserve_version(
            contract.clone(),
            empty,
            Instant::now() - Duration::from_millis(1),
        ),
        "version retention operation deadline",
    );
    assert_eq!(store.anchor(deadline()).unwrap(), empty);
    reserve(&mut store, &contract);
    let before = store.inventory(20, deadline()).unwrap();
    assert_invalid(
        store.reconcile_version(contract.operation, deadline(), &mut || {
            Err(CellErrorV1::Invalid("cancel original task"))
        }),
        "cancel original task",
    );
    assert_eq!(store.inventory(20, deadline()).unwrap().usage, before.usage);
    assert_eq!(store.anchor(deadline()).unwrap(), before.anchor);
}
