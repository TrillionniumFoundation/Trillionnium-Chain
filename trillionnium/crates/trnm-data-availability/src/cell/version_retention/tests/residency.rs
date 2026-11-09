//! Independent composition controls: durable TCA3 targets -> disposable CAS ->
//! the complete immutable model/environment working set. These callbacks read
//! real bytes; they do not run a model or mint a Hepta next-task/FinalUse receipt.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::cell::{
    CellResidencyConfigV1, CellResidencyV1, CellResidentVersionViewV1, CellVersionLoaderContextV1,
};

fn joint_limits() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 34,
        max_resident_closures: 2,
        max_chunk_references: 2,
    }
}

fn consume_actual(view: CellResidentVersionViewV1<'_>, seed: u8) -> (CellDigestV1, CellDigestV1) {
    let model = view.model();
    let environment = view.environment();
    assert_eq!(model.files().len(), 1);
    assert_eq!(environment.files().len(), 1);
    let model = &model.files()[0];
    let environment = &environment.files()[0];
    assert_eq!(model.path(), "base.bin");
    assert_eq!(model.role(), CellFileRoleV1::Base);
    assert_eq!(environment.path(), "runtime.bin");
    assert_eq!(environment.role(), CellFileRoleV1::Configuration);
    let model_bytes = model
        .chunks()
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let environment_bytes = environment
        .chunks()
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(model_bytes, vec![seed.wrapping_add(1); 17]);
    assert_eq!(environment_bytes, vec![seed; 17]);
    let model_digest = <CellDigestV1>::from(Sha256::digest(&model_bytes));
    let environment_digest = <CellDigestV1>::from(Sha256::digest(&environment_bytes));
    assert_eq!(model_digest, model.payload_sha256());
    assert_eq!(environment_digest, environment.payload_sha256());
    (model_digest, environment_digest)
}

#[test]
fn retained_complete_targets_cold_rehydrate_both_components_then_feed_two_real_resident_callbacks()
{
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.sqlite");
    let source = cache(&source_path);
    let seed = 31;
    let original = make_contract(&source, seed);
    let path = dir.path().join("owner");
    let cfg = config(8);
    let mut retained = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    active(&mut retained, &original, &source);
    let before = retained.inventory(20, deadline()).unwrap();
    assert_eq!(before.usage.initial_copy_bytes_committed, 34);
    drop(retained);
    drop(source);
    fs::remove_file(source_path).unwrap();

    let restored_path = dir.path().join("restored.sqlite");
    let restored = cache(&restored_path);
    for manifest in original.version.manifests() {
        assert!(restored.manifest(manifest.id()).unwrap().is_none());
    }
    let mut retained = CellVersionRetentionStoreV3::open(&path, cfg, before.anchor).unwrap();
    let persisted = retained.contract(original.operation, deadline()).unwrap();
    assert_eq!(persisted, original);
    let end = deadline();
    let physical = retained
        .populate_cache(original.operation, &restored, end)
        .unwrap();
    assert!(physical.acknowledged && !physical.retired);
    assert_eq!(physical.objects.len(), original.version.manifests().len());
    for manifest in original.version.manifests() {
        restored.verify_complete(manifest).unwrap();
    }
    let model = original.model.loader_context();
    let environment = original.environment.loader_context();
    assert_ne!(model.selected_generation, environment.selected_generation);
    let expected = CellVersionLoaderContextV1 {
        commitment: original.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(joint_limits()).unwrap();
    pool.prepare_cached(
        &restored,
        original.version.model().closure(),
        &model,
        end,
        &cancelled,
    )
    .unwrap();
    // Model residency alone cannot produce a complete task, even with the full
    // persisted metadata and an earlier physical ACK for the entire version.
    assert!(pool
        .admit_local_version(
            identity(70, seed),
            &original.version,
            &expected,
            joint_limits(),
            end,
            &cancelled
        )
        .is_err());
    pool.prepare_cached(
        &restored,
        original.version.environment(),
        &environment,
        end,
        &cancelled,
    )
    .unwrap();
    let task = identity(71, seed);
    let ready = pool
        .admit_local_version(
            task,
            &original.version,
            &expected,
            joint_limits(),
            end,
            &cancelled,
        )
        .unwrap();
    assert_eq!(ready.usage().unique_payload_bytes, 34);
    assert_eq!(ready.usage().resident_closures, 2);
    assert_eq!(ready.usage().chunk_references, 2);
    let first = ready
        .with_local(task, &expected, |view| consume_actual(view, seed))
        .unwrap();
    let after = retained.inventory(20, end).unwrap();
    assert_eq!(after.anchor, before.anchor);
    assert_eq!(after.usage, before.usage);
    drop(retained);
    drop(restored);
    fs::remove_file(restored_path).unwrap();
    // The second independently identified local task receives the same actual
    // complete resident bytes with no source/cache/retention capability in this
    // API. This is a byte-consumer control, not an actual model next-task run.
    let next_task = identity(72, seed);
    let next = pool
        .admit_local_version(
            next_task,
            &original.version,
            &expected,
            joint_limits(),
            end,
            &cancelled,
        )
        .unwrap();
    let second = next
        .with_local(next_task, &expected, |view| consume_actual(view, seed))
        .unwrap();
    assert_eq!(second, first);
}

#[test]
fn retained_environment_damage_cannot_be_recovered_from_complete_metadata_or_a_good_model() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.sqlite");
    let source = cache(&source_path);
    let original = make_contract(&source, 32);
    let path = dir.path().join("owner");
    let cfg = config(8);
    let mut retained = CellVersionRetentionStoreV3::create(&path, cfg.clone()).unwrap();
    active(&mut retained, &original, &source);
    let before = retained.inventory(20, deadline()).unwrap();
    let environment_id = original.version.environment().release().cells()[0];
    let environment = original
        .objects
        .iter()
        .find(|object| object.manifest.id() == environment_id)
        .unwrap();
    let raw = Connection::open(path.join("objects/retention.sqlite")).unwrap();
    let offset: u64 = raw
        .query_row(
            "SELECT position FROM obligations WHERE operation=?1",
            [environment.operation.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    drop(raw);
    drop(retained);
    drop(source);
    fs::remove_file(source_path).unwrap();
    let mut physical = fs::OpenOptions::new()
        .write(true)
        .open(path.join("objects/payload.arena"))
        .unwrap();
    physical.seek(SeekFrom::Start(offset)).unwrap();
    physical.write_all(&[0xff]).unwrap();
    physical.sync_all().unwrap();
    drop(physical);

    let restored = cache(&dir.path().join("restored.sqlite"));
    let mut retained = CellVersionRetentionStoreV3::open(&path, cfg, before.anchor).unwrap();
    assert_eq!(
        retained.contract(original.operation, deadline()).unwrap(),
        original
    );
    assert!(retained
        .populate_cache(original.operation, &restored, deadline())
        .is_err());
    assert!(retained
        .verify_version(original.operation, deadline())
        .is_err());
    assert_eq!(
        retained.inventory(20, deadline()).unwrap().usage,
        before.usage
    );
    let model = original.model.loader_context();
    let environment = original.environment.loader_context();
    let expected = CellVersionLoaderContextV1 {
        commitment: original.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let end = deadline();
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(joint_limits()).unwrap();
    // Depending on canonical manifest order, the successful model copy may be
    // present or the failed environment may precede it. Neither permits use.
    let _ = pool.prepare_cached(
        &restored,
        original.version.model().closure(),
        &model,
        end,
        &cancelled,
    );
    assert!(pool
        .prepare_cached(
            &restored,
            original.version.environment(),
            &environment,
            end,
            &cancelled
        )
        .is_err());
    assert!(pool
        .admit_local_version(
            identity(70, 32),
            &original.version,
            &expected,
            joint_limits(),
            end,
            &cancelled
        )
        .is_err());
}

#[test]
fn retained_joint_task_enforces_full_ram_both_current_contexts_and_latched_cancel_before_callback()
{
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let original = make_contract(&source, 33);
    let mut retained =
        CellVersionRetentionStoreV3::create(&dir.path().join("owner"), config(8)).unwrap();
    active(&mut retained, &original, &source);
    let restored = cache(&dir.path().join("restored.sqlite"));
    let end = deadline();
    retained
        .populate_cache(original.operation, &restored, end)
        .unwrap();
    let model = original.model.loader_context();
    let environment = original.environment.loader_context();
    let expected = CellVersionLoaderContextV1 {
        commitment: original.version.commitment(),
        model: &model,
        environment: &environment,
    };
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(joint_limits()).unwrap();
    pool.prepare_cached(
        &restored,
        original.version.model().closure(),
        &model,
        end,
        &cancelled,
    )
    .unwrap();
    pool.prepare_cached(
        &restored,
        original.version.environment(),
        &environment,
        end,
        &cancelled,
    )
    .unwrap();
    let admitted = pool.usage();
    let task = identity(70, 33);
    let mut too_small = joint_limits();
    too_small.max_resident_bytes = 33;
    assert!(pool
        .admit_local_version(
            task,
            &original.version,
            &expected,
            too_small,
            end,
            &cancelled
        )
        .is_err());
    too_small = joint_limits();
    too_small.max_resident_closures = 1;
    assert!(pool
        .admit_local_version(
            task,
            &original.version,
            &expected,
            too_small,
            end,
            &cancelled
        )
        .is_err());
    assert_eq!(pool.usage(), admitted);
    let ready = pool
        .admit_local_version(
            task,
            &original.version,
            &expected,
            joint_limits(),
            end,
            &cancelled,
        )
        .unwrap();
    let mut changed_environment = environment.clone();
    changed_environment.selected_generation += 1;
    let changed = CellVersionLoaderContextV1 {
        commitment: expected.commitment,
        model: &model,
        environment: &changed_environment,
    };
    let mut calls = 0;
    assert!(ready
        .with_local(task, &changed, |_| {
            calls += 1;
        })
        .is_err());
    let swapped = CellVersionLoaderContextV1 {
        commitment: expected.commitment,
        model: &environment,
        environment: &model,
    };
    assert!(ready
        .with_local(task, &swapped, |_| {
            calls += 1;
        })
        .is_err());
    assert_eq!(calls, 0);
    cancelled.store(true, Ordering::Release);
    assert!(ready
        .with_local(task, &expected, |_| {
            calls += 1;
        })
        .is_err());
    cancelled.store(false, Ordering::Release);
    assert!(ready
        .with_local(task, &expected, |_| {
            calls += 1;
        })
        .is_err());
    assert_eq!(calls, 0);
    assert_eq!(pool.usage(), admitted);
}
