use super::*;
use crate::cell::{
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellContextV1, CellFileRoleV1,
    CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1, CellRetentionConfigV1,
    CellRetentionContractV1, CellStoreV1, CellVersionLoaderPinV3, CellVersionManifestV1,
    CellVersionRetentionConfigV3,
};
use std::time::Duration;

#[test]
fn periodic_policy_matches_independent_python_wire_commitment_and_due_heights() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json"
    )))
    .unwrap();
    let expected = &fixture["cps1"];
    let policy = CellPeriodicSnapshotPolicyV1 {
        responsible_owner: [17; 32],
        store_id: [34; 32],
        initial_operation: [51; 32],
        initial_contract: [68; 32],
        first_due_height: 0x0000_0001_0203_0405,
        interval_heights: 0x0001_0203,
        maximum_snapshots: 3,
    };
    let wire = hex::decode(expected["wire_hex"].as_str().unwrap()).unwrap();
    assert_eq!(policy.encode().unwrap(), wire);
    assert_eq!(CellPeriodicSnapshotPolicyV1::decode(&wire).unwrap(), policy);
    assert_eq!(wire.len() as u64, expected["wire_bytes"].as_u64().unwrap());
    assert_eq!(
        hex::encode(policy.commitment().unwrap()),
        expected["commitment"].as_str().unwrap()
    );
    for ordinal in 1..=policy.maximum_snapshots {
        assert_eq!(
            policy.due_height(ordinal).unwrap(),
            expected["due_heights"][ordinal as usize - 1]
                .as_u64()
                .unwrap()
        );
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn identity(tag: u8, seed: u8) -> CellDigestV1 {
    Sha256::digest([0xc5, tag, seed]).into()
}

fn config() -> CellVersionRetentionConfigV3 {
    CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: [73; 32],
            capacity_bytes: 32 * 4096,
            maximum_obligations: 64,
        },
        maximum_versions: 16,
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

fn make_contract(cache: &CellStoreV1, seed: u8, family: &str) -> CellVersionRetentionContractV3 {
    let context = |runtime| CellContextV1 {
        family: family.into(),
        base: [1; 32],
        parent: identity(91, seed),
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    };
    let make = |context: CellContextV1, byte: u8| {
        let bytes = vec![byte; 17];
        let digest: CellDigestV1 = Sha256::digest(&bytes).into();
        let manifest = CellManifestV1::new(
            context,
            bytes.len() as u64,
            digest,
            16_384,
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
    let file = |manifest: &CellManifestV1, path: &str, role| CellClosureFileV1 {
        path: path.into(),
        role,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies: vec![],
    };
    let environment_manifest = make(context(identity(90, seed)), seed);
    let environment = CellReleaseClosureV1::new(
        environment_manifest.context().clone(),
        11,
        [51; 32],
        vec![0],
        vec![file(
            &environment_manifest,
            "runtime.bin",
            CellFileRoleV1::Configuration,
        )],
    )
    .unwrap();
    let model_manifest = make(context(environment.id()), seed.wrapping_add(1));
    let model = CellReleaseClosureV1::new(
        model_manifest.context().clone(),
        17,
        [52; 32],
        vec![0],
        vec![file(&model_manifest, "base.bin", CellFileRoleV1::Base)],
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
    let model_pin = pin(&model, CellFileRoleV1::Base);
    let environment_pin = pin(&environment, CellFileRoleV1::Configuration);
    let mut manifests = vec![model_manifest, environment_manifest];
    manifests.sort_by_key(CellManifestV1::id);
    // Each revision contains its complete materialized model and environment.
    // Neither this fixture nor CPS1 interprets TMR1 parent count as delta depth.
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model, vec![]).unwrap(),
        environment,
        manifests,
    )
    .unwrap();
    let objects = version
        .manifests()
        .iter()
        .enumerate()
        .map(|(index, manifest)| CellRetentionContractV1 {
            operation: identity(10 + index as u8, seed),
            funding_operation: identity(20 + index as u8, seed),
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
        environment: environment_pin,
        tensor_model: None,
        snapshot: None,
        objects,
    }
}

fn assert_invalid<T>(result: CellResultV1<T>, expected: &'static str) {
    match result {
        Err(CellErrorV1::Invalid(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("expected {expected}, got {error}"),
        Ok(_) => panic!("expected {expected}, got success"),
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    config: CellVersionRetentionConfigV3,
    source: CellStoreV1,
    store: CellVersionRetentionStoreV3,
    initial: CellVersionRetentionContractV3,
    policy: CellPeriodicSnapshotPolicyV1,
    scheduler: CellPeriodicSnapshotOwnerV1,
}

impl Fixture {
    fn new(maximum_snapshots: u32) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = cache(&directory.path().join("source.sqlite"));
        let initial = make_contract(&source, 1, "periodic-snapshot-tests");
        let config = config();
        let mut store =
            CellVersionRetentionStoreV3::create(&directory.path().join("owner"), config.clone())
                .unwrap();
        let expected = store.anchor(deadline()).unwrap();
        store
            .reserve_version(initial.clone(), expected, deadline())
            .unwrap();
        store
            .acknowledge_version(initial.operation, &source, deadline())
            .unwrap();
        let policy = CellPeriodicSnapshotPolicyV1 {
            responsible_owner: initial.responsible_owner,
            store_id: store.store_id(),
            initial_operation: initial.operation,
            initial_contract: store.contract_commitment(&initial).unwrap(),
            first_due_height: 20,
            interval_heights: 20,
            maximum_snapshots,
        };
        let scheduler = CellPeriodicSnapshotOwnerV1::create(
            &directory.path().join("schedule"),
            policy.clone(),
            deadline(),
        )
        .unwrap();
        Self {
            directory,
            config,
            source,
            store,
            initial,
            policy,
            scheduler,
        }
    }

    fn due(&self, height: u64) -> CellPeriodicSnapshotDueV1 {
        match self
            .scheduler
            .progress(&self.store, height, deadline())
            .unwrap()
        {
            CellPeriodicSnapshotProgressV1::Due(due) => due,
            state => panic!("expected Due, got {state:?}"),
        }
    }

    fn snapshot(&self, seed: u8, due: CellPeriodicSnapshotDueV1) -> CellVersionRetentionContractV3 {
        let mut contract = make_contract(&self.source, seed, "periodic-snapshot-tests");
        contract.snapshot = Some(CellVersionSnapshotLinkV3 {
            schedule: self.scheduler.commitment(),
            ordinal: u64::from(due.ordinal),
            due_height: due.due_height,
            predecessor_operation: due.predecessor_operation,
            predecessor_contract: due.predecessor_contract,
        });
        contract
    }
}

fn copy_members(
    store: &mut CellVersionRetentionStoreV3,
    contract: &CellVersionRetentionContractV3,
    source: &CellStoreV1,
) {
    for object in &contract.objects {
        let readback = store
            .acknowledge_member(contract.operation, object.operation, source, deadline())
            .unwrap();
        assert!(readback.acknowledged && !readback.retired);
        assert_eq!(
            readback.initial_copy_bytes_committed,
            object.manifest.size()
        );
    }
}

#[test]
fn periodic_snapshot_policy_codec_has_exact_namespace_and_finite_cadence() {
    let fixture = Fixture::new(2);
    let policy = &fixture.policy;
    let wire = policy.encode().unwrap();
    assert_eq!(wire.len(), CELL_PERIODIC_SNAPSHOT_POLICY_BYTES_V1);
    assert_eq!(&wire[..4], b"CPS1");
    assert_eq!(
        CellPeriodicSnapshotPolicyV1::decode(&wire).unwrap(),
        *policy
    );
    assert_eq!(policy.due_height(1).unwrap(), 20);
    assert_eq!(policy.due_height(2).unwrap(), 40);
    assert!(policy.due_height(0).is_err());
    assert!(policy.due_height(3).is_err());
    for size in [0, 151, 153] {
        let mut changed = wire.clone();
        changed.resize(size, 0);
        assert!(CellPeriodicSnapshotPolicyV1::decode(&changed).is_err());
    }
    let mut foreign = wire;
    foreign[..4].copy_from_slice(b"CPS2");
    assert!(CellPeriodicSnapshotPolicyV1::decode(&foreign).is_err());
    for maximum in [0, MAX_CELL_PERIODIC_SNAPSHOTS_V1 + 1] {
        let mut changed = policy.clone();
        changed.maximum_snapshots = maximum;
        assert_invalid(changed.validate(), "periodic snapshot finite cadence");
    }
    let mut overflow = policy.clone();
    overflow.first_due_height = i64::MAX as u64;
    assert_invalid(overflow.validate(), "periodic snapshot cadence overflow");
    overflow.interval_heights = u64::MAX;
    assert_invalid(overflow.validate(), "periodic snapshot cadence overflow");
}

#[test]
fn periodic_snapshot_actual_dual_closure_copy_reopens_target_only_and_keeps_retired_cursor() {
    let mut fixture = Fixture::new(2);
    assert!(
        matches!(fixture.scheduler.progress(&fixture.store, 19, deadline()).unwrap(),
        CellPeriodicSnapshotProgressV1::NotDue(due) if due.ordinal == 1 && due.due_height == 20)
    );
    let first = fixture.snapshot(2, fixture.due(20));
    assert_ne!(
        first.model.selected_generation,
        first.environment.selected_generation
    );
    let before = fixture.store.anchor(deadline()).unwrap();
    let pending = fixture
        .scheduler
        .reserve_due(&mut fixture.store, first.clone(), before, 20, deadline())
        .unwrap();
    assert!(!pending.acknowledged);
    assert_eq!(pending.objects.len(), 2);
    copy_members(&mut fixture.store, &first, &fixture.source);
    let copied = fixture.store.inventory(20, deadline()).unwrap();
    assert_eq!(copied.usage.pending_versions, 1);
    assert_eq!(copied.usage.initial_copy_bytes_committed, 68);
    let expected_policy = fixture.scheduler.commitment();
    let Fixture {
        directory,
        config,
        source,
        store,
        initial,
        policy: _,
        scheduler,
    } = fixture;
    drop(store);
    drop(source);
    drop(scheduler);
    fs::remove_file(directory.path().join("source.sqlite")).unwrap();
    let mut store = CellVersionRetentionStoreV3::open(
        &directory.path().join("owner"),
        config.clone(),
        copied.anchor,
    )
    .unwrap();
    let scheduler = CellPeriodicSnapshotOwnerV1::open(
        &directory.path().join("schedule"),
        expected_policy,
        deadline(),
    )
    .unwrap();
    let recovered = scheduler
        .reconcile_pending(&mut store, 27, deadline(), &mut || Ok(()))
        .unwrap();
    assert_eq!(recovered.operation, first.operation);
    assert_eq!(recovered.version, first.version.commitment());
    assert!(recovered.acknowledged && !recovered.retired);
    assert_eq!(
        recovered.anchor.generation(),
        copied.anchor.generation() + 1
    );
    let after = store.inventory(27, deadline()).unwrap();
    assert_eq!(
        after.usage.initial_copy_bytes_committed,
        copied.usage.initial_copy_bytes_committed
    );
    assert_eq!(after.usage.repair_bytes_committed, 0);

    // Materialize both retained targets into a different empty disposable CAS.
    // The original source is gone; metadata alone cannot satisfy these reads.
    let rebuilt = cache(&directory.path().join("rebuilt.sqlite"));
    store
        .populate_cache(first.operation, &rebuilt, deadline())
        .unwrap();
    let model_id = first.version.model().closure().release().cells()[0];
    let environment_id = first.version.environment().release().cells()[0];
    assert_ne!(model_id, environment_id);
    for object in &first.objects {
        let expected_byte = if object.manifest.id() == model_id {
            3
        } else {
            2
        };
        assert!(object.manifest.id() == model_id || object.manifest.id() == environment_id);
        let actual = rebuilt
            .chunk(object.manifest.chunks()[0].sha256)
            .unwrap()
            .unwrap();
        assert_eq!(actual, vec![expected_byte; 17]);
    }
    let due = match scheduler.progress(&store, 40, deadline()).unwrap() {
        CellPeriodicSnapshotProgressV1::Due(due) => due,
        state => panic!("expected next original Due, got {state:?}"),
    };
    assert_eq!(
        (due.ordinal, due.due_height, due.predecessor_operation),
        (2, 40, first.operation)
    );
    let mut second = make_contract(&rebuilt, 3, "periodic-snapshot-tests");
    second.snapshot = Some(CellVersionSnapshotLinkV3 {
        schedule: expected_policy,
        ordinal: 2,
        due_height: 40,
        predecessor_operation: first.operation,
        predecessor_contract: store.contract_commitment(&first).unwrap(),
    });
    let expected = store.anchor(deadline()).unwrap();
    scheduler
        .reserve_due(&mut store, second.clone(), expected, 40, deadline())
        .unwrap();
    copy_members(&mut store, &second, &rebuilt);
    scheduler
        .reconcile_pending(&mut store, 40, deadline(), &mut || Ok(()))
        .unwrap();
    for contract in [&initial, &first, &second] {
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
    }
    let retired = store.inventory(150, deadline()).unwrap();
    assert!(retired.protected.is_empty());
    assert_eq!(retired.usage.historical_versions, 3);
    assert_eq!(retired.usage.occupied_bytes, 0);
    assert_eq!(retired.usage.initial_copy_bytes_committed, 102);
    drop(store);
    let mut store =
        CellVersionRetentionStoreV3::open(&directory.path().join("owner"), config, retired.anchor)
            .unwrap();
    assert_eq!(
        scheduler.progress(&store, 200, deadline()).unwrap(),
        CellPeriodicSnapshotProgressV1::Complete {
            snapshots: 2,
            last_operation: second.operation
        }
    );
    let mut third = second.clone();
    third.operation = identity(1, 4);
    third.funding_operation = identity(2, 4);
    assert_invalid(
        scheduler.reserve_due(&mut store, third, retired.anchor, 200, deadline()),
        "periodic snapshot not due",
    );
    assert_eq!(store.anchor(deadline()).unwrap(), retired.anchor);
}

#[test]
fn periodic_snapshot_partial_environment_and_missing_cache_keep_same_pending_identity() {
    let mut fixture = Fixture::new(2);
    let contract = fixture.snapshot(2, fixture.due(20));
    let original_anchor = fixture.store.anchor(deadline()).unwrap();
    fixture
        .scheduler
        .reserve_due(
            &mut fixture.store,
            contract.clone(),
            original_anchor,
            20,
            deadline(),
        )
        .unwrap();
    let model_id = contract.version.model().closure().release().cells()[0];
    let model = contract
        .objects
        .iter()
        .find(|object| object.manifest.id() == model_id)
        .unwrap();
    fixture
        .store
        .acknowledge_member(
            contract.operation,
            model.operation,
            &fixture.source,
            deadline(),
        )
        .unwrap();
    let before = fixture.store.inventory(20, deadline()).unwrap();
    assert_eq!(before.usage.initial_copy_bytes_committed, 51);
    let expected_policy = fixture.scheduler.commitment();
    let Fixture {
        directory,
        config,
        source,
        store,
        initial: _,
        policy: _,
        scheduler,
    } = fixture;
    drop(store);
    drop(source);
    drop(scheduler);
    fs::remove_file(directory.path().join("source.sqlite")).unwrap();
    let mut store =
        CellVersionRetentionStoreV3::open(&directory.path().join("owner"), config, before.anchor)
            .unwrap();
    let scheduler = CellPeriodicSnapshotOwnerV1::open(
        &directory.path().join("schedule"),
        expected_policy,
        deadline(),
    )
    .unwrap();
    assert!(scheduler
        .reconcile_pending(&mut store, 30, deadline(), &mut || Ok(()))
        .is_err());
    assert_eq!(store.inventory(30, deadline()).unwrap().usage, before.usage);
    assert!(
        matches!(scheduler.progress(&store, 30, deadline()).unwrap(), CellPeriodicSnapshotProgressV1::Pending { original_operation, due } if original_operation == contract.operation && due.ordinal == 1 && due.due_height == 20 && due.late_by_heights == 10)
    );
    let mut renamed = contract.clone();
    renamed.operation = identity(1, 3);
    renamed.funding_operation = identity(2, 3);
    assert_invalid(
        scheduler.reserve_due(&mut store, renamed, before.anchor, 30, deadline()),
        "periodic snapshot original pending operation",
    );
    let mut changed = contract.clone();
    changed.retain_until_height += 1;
    assert_invalid(
        scheduler.reserve_due(&mut store, changed, before.anchor, 30, deadline()),
        "periodic snapshot original pending operation",
    );
    let replay = scheduler
        .reserve_due(
            &mut store,
            contract.clone(),
            original_anchor,
            30,
            deadline(),
        )
        .unwrap();
    assert_eq!(replay.anchor, before.anchor);
    assert_eq!(
        store.contract(contract.operation, deadline()).unwrap(),
        contract
    );
    assert_eq!(store.inventory(30, deadline()).unwrap().usage, before.usage);
    assert_invalid(
        scheduler.reserve_due(&mut store, contract.clone(), before.anchor, 100, deadline()),
        "periodic snapshot original lease",
    );
    // Expired Unknown recovery still only observes original targets; it cannot
    // fill the missing environment, refund work or dispatch a replacement.
    assert!(scheduler
        .reconcile_pending(&mut store, 100, deadline(), &mut || Ok(()))
        .is_err());
    assert_eq!(store.anchor(deadline()).unwrap(), before.anchor);
}

#[test]
fn periodic_snapshot_disk_policy_tampering_and_wrong_pin_prevent_catalog_mutation() {
    let mut fixture = Fixture::new(2);
    let schedule_path = fixture.directory.path().join("schedule");
    let path = schedule_path.join(POLICY_FILE);
    assert_invalid(
        CellPeriodicSnapshotOwnerV1::open(&schedule_path, [99; 32], deadline()),
        "periodic snapshot independent policy pin",
    );
    let contract = fixture.snapshot(2, fixture.due(20));
    let before = fixture.store.anchor(deadline()).unwrap();
    let original = fs::read(&path).unwrap();
    let mut changed = fixture.policy.clone();
    changed.interval_heights += 1;
    fs::write(&path, changed.encode().unwrap()).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 20, deadline()),
        "periodic snapshot stored policy changed",
    );
    assert_invalid(
        fixture
            .scheduler
            .reserve_due(&mut fixture.store, contract, before, 20, deadline()),
        "periodic snapshot stored policy changed",
    );
    assert_eq!(fixture.store.anchor(deadline()).unwrap(), before);
    assert_eq!(fixture.store.audited_duties(deadline()).unwrap().len(), 1);
    assert_invalid(
        CellPeriodicSnapshotOwnerV1::open(
            &schedule_path,
            fixture.scheduler.commitment(),
            deadline(),
        ),
        "periodic snapshot independent policy pin",
    );
    fs::write(&path, original).unwrap();
    assert!(matches!(
        fixture
            .scheduler
            .progress(&fixture.store, 20, deadline())
            .unwrap(),
        CellPeriodicSnapshotProgressV1::Due(_)
    ));
}

#[cfg(unix)]
#[test]
fn periodic_snapshot_policy_symlink_directory_link_and_hardlink_are_refused() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(2);
    let schedule = fixture.directory.path().join("schedule");
    let path = schedule.join(POLICY_FILE);
    let moved = fixture.directory.path().join("original-policy");
    fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 20, deadline()),
        "periodic snapshot policy file",
    );
    fs::remove_file(&path).unwrap();
    fs::rename(&moved, &path).unwrap();
    let linked = fixture.directory.path().join("linked-policy");
    fs::hard_link(&path, &linked).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 20, deadline()),
        "periodic snapshot policy changed",
    );
    fs::remove_file(linked).unwrap();
    let moved_directory = fixture.directory.path().join("original-schedule");
    fs::rename(&schedule, &moved_directory).unwrap();
    symlink(&moved_directory, &schedule).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 20, deadline()),
        "periodic snapshot directory",
    );
}

#[cfg(unix)]
#[test]
fn periodic_snapshot_regular_policy_reopens_and_preexisting_fifo_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let policy = CellPeriodicSnapshotPolicyV1 {
        responsible_owner: [1; 32],
        store_id: [2; 32],
        initial_operation: [3; 32],
        initial_contract: [4; 32],
        first_due_height: 10,
        interval_heights: 10,
        maximum_snapshots: 2,
    };
    let regular_directory = directory.path().join("regular");
    let owner = CellPeriodicSnapshotOwnerV1::create(&regular_directory, policy.clone(), deadline())
        .unwrap();
    let reopened =
        CellPeriodicSnapshotOwnerV1::open(&regular_directory, owner.commitment(), deadline())
            .unwrap();
    assert_eq!(reopened.policy(), &policy);

    let fifo_directory = directory.path().join("fifo");
    fs::create_dir(&fifo_directory).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        fifo_directory.join(POLICY_FILE),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    // An ordinary nonregular-file refusal, not a reproduction of a path swap.
    assert_invalid(
        CellPeriodicSnapshotOwnerV1::open(&fifo_directory, owner.commitment(), deadline()),
        "periodic snapshot policy file",
    );
    assert_eq!(
        fs::read(regular_directory.join(POLICY_FILE)).unwrap(),
        policy.encode().unwrap()
    );
}

#[test]
fn periodic_snapshot_changed_ordinal_due_predecessor_schedule_and_scope_are_refused() {
    let mut fixture = Fixture::new(2);
    let correct = fixture.snapshot(2, fixture.due(20));
    let original = fixture.store.anchor(deadline()).unwrap();
    let mut cases = Vec::new();
    for field in 0..5 {
        let mut changed = correct.clone();
        let link = changed.snapshot.as_mut().unwrap();
        match field {
            0 => link.ordinal = 2,
            1 => link.due_height += 1,
            2 => link.predecessor_operation = [99; 32],
            3 => link.predecessor_contract = [99; 32],
            _ => link.schedule = [99; 32],
        }
        cases.push(changed);
    }
    let mut missing = correct.clone();
    missing.snapshot = None;
    cases.push(missing);
    for changed in cases {
        assert_invalid(
            fixture
                .scheduler
                .reserve_due(&mut fixture.store, changed, original, 20, deadline()),
            "periodic snapshot exact obligation",
        );
        assert_eq!(fixture.store.anchor(deadline()).unwrap(), original);
    }
    let mut owner_changed = correct.clone();
    owner_changed.responsible_owner = [98; 32];
    owner_changed.validate(&fixture.config).unwrap();
    assert_invalid(
        fixture
            .scheduler
            .reserve_due(&mut fixture.store, owner_changed, original, 20, deadline()),
        "periodic snapshot original owner/model scope",
    );
    let mut foreign_model = make_contract(&fixture.source, 3, "another-model-family");
    foreign_model.snapshot = correct.snapshot;
    foreign_model.validate(&fixture.config).unwrap();
    assert_invalid(
        fixture
            .scheduler
            .reserve_due(&mut fixture.store, foreign_model, original, 20, deadline()),
        "periodic snapshot original owner/model scope",
    );
    assert_eq!(fixture.store.audited_duties(deadline()).unwrap().len(), 1);
}

#[test]
fn periodic_snapshot_direct_history_short_lease_cannot_become_recovery_cursor() {
    let mut fixture = Fixture::new(2);
    let mut contract = fixture.snapshot(2, fixture.due(20));
    contract.retain_until_height = 35;
    contract.repair_deadline_height = 30;
    contract.validate(&fixture.config).unwrap();
    let expected = fixture.store.anchor(deadline()).unwrap();
    // The lower owner legitimately accepts this complete TCA3 contract. CPS1
    // must independently reject its own schedule's missing next-due coverage.
    fixture
        .store
        .reserve_version(contract.clone(), expected, deadline())
        .unwrap();
    let committed = fixture.store.anchor(deadline()).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 20, deadline()),
        "periodic snapshot next coverage",
    );
    assert_invalid(
        fixture
            .scheduler
            .reconcile_pending(&mut fixture.store, 20, deadline(), &mut || Ok(())),
        "periodic snapshot next coverage",
    );
    assert_eq!(fixture.store.anchor(deadline()).unwrap(), committed);
    assert_eq!(
        fixture
            .store
            .contract(contract.operation, deadline())
            .unwrap(),
        contract
    );
}

#[test]
fn periodic_snapshot_direct_history_changed_due_is_not_trusted_as_a_cursor() {
    let mut fixture = Fixture::new(2);
    let mut contract = fixture.snapshot(2, fixture.due(20));
    contract.snapshot.as_mut().unwrap().due_height = 21;
    contract.validate(&fixture.config).unwrap();
    let expected = fixture.store.anchor(deadline()).unwrap();
    fixture
        .store
        .reserve_version(contract, expected, deadline())
        .unwrap();
    let committed = fixture.store.anchor(deadline()).unwrap();
    assert_invalid(
        fixture.scheduler.progress(&fixture.store, 21, deadline()),
        "periodic snapshot original sequence",
    );
    assert_eq!(fixture.store.anchor(deadline()).unwrap(), committed);
}

#[test]
fn periodic_snapshot_late_tick_preserves_original_due_and_expiry() {
    let mut fixture = Fixture::new(2);
    let due = fixture.due(27);
    assert_eq!(
        (due.ordinal, due.due_height, due.late_by_heights),
        (1, 20, 7)
    );
    let contract = fixture.snapshot(2, due);
    let expected = fixture.store.anchor(deadline()).unwrap();
    assert_invalid(
        fixture.scheduler.reserve_due(
            &mut fixture.store,
            contract.clone(),
            expected,
            100,
            deadline(),
        ),
        "periodic snapshot original lease",
    );
    assert_eq!(fixture.store.anchor(deadline()).unwrap(), expected);
    let result = fixture
        .scheduler
        .reserve_due(
            &mut fixture.store,
            contract.clone(),
            expected,
            27,
            deadline(),
        )
        .unwrap();
    assert!(!result.acknowledged);
    assert_eq!(
        fixture
            .store
            .contract(contract.operation, deadline())
            .unwrap()
            .snapshot
            .unwrap()
            .due_height,
        20
    );
    copy_members(&mut fixture.store, &contract, &fixture.source);
    // After the original lease has ended only target-only recovery remains;
    // recording the completed historical effect never renews the old terms.
    let recovered = fixture
        .scheduler
        .reconcile_pending(&mut fixture.store, 105, deadline(), &mut || Ok(()))
        .unwrap();
    assert!(recovered.acknowledged);
    let durable = fixture
        .store
        .contract(contract.operation, deadline())
        .unwrap();
    assert_eq!(durable, contract);
    let next = fixture.due(105);
    assert_eq!(
        (next.ordinal, next.due_height, next.late_by_heights),
        (2, 40, 65)
    );
    assert!(fixture.store.service_set(105, 106, deadline()).is_err());
}

#[test]
fn periodic_snapshot_initial_anchor_store_owner_and_coverage_are_independent_pins() {
    let fixture = Fixture::new(2);
    for field in 0..5 {
        let mut policy = fixture.policy.clone();
        let expected = match field {
            0 => {
                policy.store_id = [99; 32];
                "periodic snapshot original store"
            }
            1 => {
                policy.initial_operation = [99; 32];
                "periodic snapshot initial duty missing"
            }
            2 => {
                policy.initial_contract = [99; 32];
                "periodic snapshot initial complete duty"
            }
            3 => {
                policy.responsible_owner = [99; 32];
                "periodic snapshot initial complete duty"
            }
            _ => {
                policy.first_due_height = fixture.initial.retain_until_height;
                "periodic snapshot initial coverage"
            }
        };
        let owner = CellPeriodicSnapshotOwnerV1::create(
            &fixture
                .directory
                .path()
                .join(format!("wrong-policy-{field}")),
            policy,
            deadline(),
        )
        .unwrap();
        assert_invalid(owner.progress(&fixture.store, 20, deadline()), expected);
    }
    let pending = make_contract(&fixture.source, 8, "periodic-snapshot-tests");
    let mut store = CellVersionRetentionStoreV3::create(
        &fixture.directory.path().join("pending-owner"),
        fixture.config.clone(),
    )
    .unwrap();
    let expected = store.anchor(deadline()).unwrap();
    store
        .reserve_version(pending.clone(), expected, deadline())
        .unwrap();
    let mut policy = fixture.policy.clone();
    policy.initial_operation = pending.operation;
    policy.initial_contract = store.contract_commitment(&pending).unwrap();
    let owner = CellPeriodicSnapshotOwnerV1::create(
        &fixture.directory.path().join("pending-policy"),
        policy,
        deadline(),
    )
    .unwrap();
    assert_invalid(
        owner.progress(&store, 20, deadline()),
        "periodic snapshot initial complete duty",
    );
}

#[test]
fn periodic_snapshot_original_deadline_prevents_creation_or_catalog_work() {
    let mut fixture = Fixture::new(2);
    let path = fixture.directory.path().join("too-late");
    assert_invalid(
        CellPeriodicSnapshotOwnerV1::create(&path, fixture.policy.clone(), Instant::now()),
        "periodic snapshot deadline",
    );
    assert!(!path.exists());
    let contract = fixture.snapshot(2, fixture.due(20));
    let original = fixture.store.anchor(deadline()).unwrap();
    assert_invalid(
        fixture
            .scheduler
            .reserve_due(&mut fixture.store, contract, original, 20, Instant::now()),
        "periodic snapshot deadline",
    );
    assert_eq!(fixture.store.anchor(deadline()).unwrap(), original);
    assert_eq!(fixture.store.audited_duties(deadline()).unwrap().len(), 1);
}
