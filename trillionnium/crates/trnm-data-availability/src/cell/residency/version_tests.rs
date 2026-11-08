use std::{cell::Cell, sync::atomic::Ordering, time::Duration};

use sha2::{Digest, Sha256};

use super::*;
use crate::cell::{
    version::tests::{context, fixture, owner},
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellContextV1, CellErrorV1, CellFileRoleV1,
    CellLoaderContextV1, CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1,
    CellReleaseLimitsV1, CellStoreV1,
};

const TASK: CellDigestV1 = [90; 32];

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn limits() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 1_000_000,
        max_resident_closures: 8,
        max_chunk_references: 64,
    }
}

fn prepare(
    pool: &mut CellResidencyV1,
    cache: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
) {
    pool.prepare_cached(
        cache,
        closure,
        expected,
        deadline(),
        &AtomicBool::new(false),
    )
    .unwrap();
}

fn prepare_version(
    pool: &mut CellResidencyV1,
    cache: &CellStoreV1,
    version: &CellVersionManifestV1,
) -> (CellLoaderContextV1, CellLoaderContextV1) {
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    prepare(pool, cache, version.model().closure(), &model);
    prepare(pool, cache, version.environment(), &environment);
    (model, environment)
}

fn expected<'a>(
    version: &CellVersionManifestV1,
    model: &'a CellLoaderContextV1,
    environment: &'a CellLoaderContextV1,
) -> CellVersionLoaderContextV1<'a> {
    CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model,
        environment,
    }
}

fn assert_actual_version(view: CellResidentVersionViewV1<'_>, version: &CellVersionManifestV1) {
    assert_eq!(view.commitment(), version.commitment());
    assert_eq!(view.model_root(), version.model().id());
    assert_eq!(view.model().closure(), version.model().closure());
    assert_eq!(view.environment().closure(), version.environment());
    let mut count = 0;
    for component in [view.model(), view.environment()] {
        for file in component.files() {
            let declared = version
                .manifests()
                .iter()
                .find(|manifest| manifest.id() == file.manifest_id())
                .unwrap();
            let mut hash = Sha256::new();
            let mut length = 0_u64;
            assert_eq!(file.chunks().len(), declared.chunks().len());
            for (bytes, chunk) in file.chunks().zip(declared.chunks()) {
                assert_eq!(bytes.len(), chunk.size as usize);
                assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), chunk.sha256);
                hash.update(bytes);
                length += bytes.len() as u64;
            }
            assert_eq!(length, declared.size());
            assert_eq!(<[u8; 32]>::from(hash.finalize()), declared.payload_sha256());
            count += 1;
        }
    }
    assert_eq!(count, version.manifests().len());
}

#[test]
fn complete_version_next_task_reads_actual_model_and_environment_after_cache_loss() {
    let (directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let usage = pool.usage();
    let selection = pool.selection();
    drop(cache);
    std::fs::remove_dir_all(directory.path()).unwrap();
    let cancelled = AtomicBool::new(false);
    for task in [TASK, [91; 32]] {
        let ready = pool
            .admit_local_version(task, &version, &pins, limits(), deadline(), &cancelled)
            .unwrap();
        assert_eq!(ready.task_id(), task);
        assert_eq!(ready.commitment(), version.commitment());
        assert_eq!(ready.model_root(), version.model().id());
        assert_eq!(ready.usage(), usage);
        assert_eq!(ready.usage().resident_closures, 2);
        assert_eq!(ready.usage().chunk_references, 12);
        ready
            .with_local(task, &pins, |view| assert_actual_version(view, &version))
            .unwrap();
    }
    assert_eq!(pool.usage(), usage);
    assert_eq!(pool.selection(), selection);
}

#[test]
fn complete_disk_bytes_and_model_only_residency_cannot_admit_a_complete_version() {
    let (_directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let pins = expected(&version, &model, &environment);
    // A real complete disk readback still cannot stand in for RAM admission.
    version
        .verify_cached(
            &cache,
            &pins,
            CellReleaseLimitsV1 {
                max_payload_bytes: 1_000_000,
                max_chunks: 64,
                deadline: deadline(),
            },
        )
        .unwrap();
    prepare(&mut pool, &cache, version.model().closure(), &model);
    let usage = pool.usage();
    assert!(matches!(
        pool.admit_local_version(
            TASK,
            &version,
            &pins,
            limits(),
            deadline(),
            &AtomicBool::new(false),
        ),
        Err(CellErrorV1::Unavailable)
    ));
    assert_eq!(pool.usage(), usage);
    assert!(pool.selection().is_none());
}

#[test]
fn environment_only_residency_and_corrupted_missing_environment_never_create_partial_readiness() {
    let (directory, cache, version) = fixture();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let pins = expected(&version, &model, &environment);
    let mut environment_only = CellResidencyV1::new(limits()).unwrap();
    prepare(
        &mut environment_only,
        &cache,
        version.environment(),
        &environment,
    );
    assert!(environment_only
        .admit_local_version(
            TASK,
            &version,
            &pins,
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &cache, version.model().closure(), &model);
    let usage = pool.usage();
    let manifest = version
        .manifests()
        .iter()
        .find(|manifest| manifest.id() == version.environment().files()[0].manifest)
        .unwrap();
    let db = rusqlite::Connection::open(directory.path().join("cache.sqlite")).unwrap();
    db.execute(
        "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
        [manifest.chunks()[0].sha256.as_slice()],
    )
    .unwrap();
    assert!(pool
        .prepare_cached(
            &cache,
            version.environment(),
            &environment,
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert!(pool
        .admit_local_version(
            TASK,
            &version,
            &pins,
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(pool.usage(), usage);
}

#[test]
fn complete_version_task_limits_charge_environment_bytes_references_and_closure() {
    let (_directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let usage = pool.usage();
    for task_limits in [
        CellResidencyConfigV1 {
            max_resident_bytes: usage.unique_payload_bytes - 1,
            ..limits()
        },
        CellResidencyConfigV1 {
            max_chunk_references: usage.chunk_references - 1,
            ..limits()
        },
        CellResidencyConfigV1 {
            max_resident_closures: 1,
            ..limits()
        },
    ] {
        assert!(pool
            .admit_local_version(
                TASK,
                &version,
                &pins,
                task_limits,
                deadline(),
                &AtomicBool::new(false),
            )
            .is_err());
        assert_eq!(pool.usage(), usage);
        assert!(pool.selection().is_none());
    }
    let mut tight_environment = environment.clone();
    tight_environment.max_chunks = 5;
    assert!(pool
        .admit_local_version(
            TASK,
            &version,
            &expected(&version, &model, &tight_environment),
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
}

#[test]
fn complete_version_rejects_another_tmr1_lineage_even_when_all_closures_match() {
    let (_directory, cache, version) = fixture();
    let alternate = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(version.model().closure().clone(), vec![[55; 32]]).unwrap(),
        version.environment().clone(),
        version.manifests().to_vec(),
    )
    .unwrap();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let wrong_pins = expected(&alternate, &model, &environment);
    assert!(pool
        .admit_local_version(
            TASK,
            &version,
            &wrong_pins,
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    let cancelled = AtomicBool::new(false);
    let pins = expected(&version, &model, &environment);
    let ready = pool
        .admit_local_version(TASK, &version, &pins, limits(), deadline(), &cancelled)
        .unwrap();
    let called = Cell::new(false);
    assert!(ready
        .with_local(TASK, &wrong_pins, |_| called.set(true))
        .is_err());
    assert!(!called.get());
}

#[test]
fn paired_lookup_rechecks_task_and_both_current_contexts_before_any_consumer_call() {
    let (_directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let cancelled = AtomicBool::new(false);
    let ready = pool
        .admit_local_version(TASK, &version, &pins, limits(), deadline(), &cancelled)
        .unwrap();
    let called = Cell::new(false);
    assert!(ready
        .with_local([89; 32], &pins, |_| called.set(true))
        .is_err());
    let swapped = expected(&version, &environment, &model);
    assert!(ready
        .with_local(TASK, &swapped, |_| called.set(true))
        .is_err());
    for component in 0..2 {
        for changed_field in 0..6 {
            let mut current_model = model.clone();
            let mut current_environment = environment.clone();
            let current = if component == 0 {
                &mut current_model
            } else {
                &mut current_environment
            };
            match changed_field {
                0 => current.selected_generation += 1,
                1 => current.loader_profile = [71; 32],
                2 => current.context.runtime = [72; 32],
                3 => current.max_payload_bytes = 1,
                4 => current.max_chunks = 1,
                5 => current.required_roles = vec![CellFileRoleV1::Adapter],
                _ => unreachable!(),
            }
            assert!(ready
                .with_local(
                    TASK,
                    &expected(&version, &current_model, &current_environment),
                    |_| called.set(true),
                )
                .is_err());
        }
    }
    assert!(!called.get());
    ready.with_local(TASK, &pins, |_| called.set(true)).unwrap();
    assert!(called.get());
}

#[test]
fn complete_version_cancellation_is_latched_even_on_a_mismatching_lookup() {
    let (_directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let cancelled = AtomicBool::new(false);
    let ready = pool
        .admit_local_version(TASK, &version, &pins, limits(), deadline(), &cancelled)
        .unwrap();
    cancelled.store(true, Ordering::Release);
    let mut wrong = expected(&version, &model, &environment);
    wrong.commitment[0] ^= 1;
    let called = Cell::new(false);
    assert!(ready
        .with_local(TASK, &wrong, |_| called.set(true))
        .is_err());
    cancelled.store(false, Ordering::Release);
    assert!(matches!(
        ready.with_local(TASK, &pins, |_| called.set(true)),
        Err(CellErrorV1::Invalid("resident task stopped"))
    ));
    assert!(!called.get());
}

#[test]
fn complete_version_admission_and_lookup_keep_the_original_task_cutoff() {
    let (_directory, cache, version) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let cancelled = AtomicBool::new(false);
    assert!(pool
        .admit_local_version(TASK, &version, &pins, limits(), Instant::now(), &cancelled)
        .is_err());
    assert!(pool
        .admit_local_version([0; 32], &version, &pins, limits(), deadline(), &cancelled)
        .is_err());
    let cutoff = Instant::now() + Duration::from_secs(1);
    let ready = pool
        .admit_local_version(TASK, &version, &pins, limits(), cutoff, &cancelled)
        .unwrap();
    std::thread::sleep(cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    let called = Cell::new(false);
    assert!(ready.with_local(TASK, &pins, |_| called.set(true)).is_err());
    assert!(matches!(
        ready.with_local(TASK, &pins, |_| called.set(true)),
        Err(CellErrorV1::Invalid("resident task stopped"))
    ));
    assert!(!called.get());
}

fn same_payload_fixture() -> (tempfile::TempDir, CellStoreV1, CellVersionManifestV1) {
    let directory = tempfile::tempdir().unwrap();
    let cache = CellStoreV1::open(
        &directory.path().join("cache.sqlite"),
        CellCacheConfigV4 {
            max_database_bytes: 64 << 20,
            max_logical_bytes: 32 << 20,
            max_chunk_rows: 128,
            max_manifest_rows: 64,
        },
    )
    .unwrap();
    let payload: Vec<u8> = (0..32769).map(|index| (index % 251) as u8).collect();
    let make = |context: CellContextV1, path: &str, role: CellFileRoleV1| {
        let manifest = CellManifestV1::new(
            context,
            payload.len() as u64,
            Sha256::digest(&payload).into(),
            16384,
            payload
                .chunks(16384)
                .map(|part| CellChunkV1 {
                    size: part.len() as u32,
                    sha256: Sha256::digest(part).into(),
                })
                .collect(),
        )
        .unwrap();
        cache
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        for (chunk, part) in manifest.chunks().iter().zip(payload.chunks(16384)) {
            cache.put_chunk(chunk, part).unwrap();
        }
        let file = CellClosureFileV1 {
            path: path.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: vec![],
        };
        (manifest, file)
    };
    let env_context = context([5; 32]);
    let (env_manifest, env_file) = make(
        env_context.clone(),
        "runtime.bin",
        CellFileRoleV1::Configuration,
    );
    let environment =
        CellReleaseClosureV1::new(env_context, 1, [6; 32], vec![0], vec![env_file]).unwrap();
    let model_context = context(environment.id());
    let (model_manifest, model_file) =
        make(model_context.clone(), "base.bin", CellFileRoleV1::Base);
    let model = CellModelReleaseRootV1::new(
        CellReleaseClosureV1::new(model_context, 2, [7; 32], vec![0], vec![model_file]).unwrap(),
        vec![],
    )
    .unwrap();
    let mut manifests = vec![model_manifest, env_manifest];
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(model, environment, manifests).unwrap();
    (directory, cache, version)
}

#[test]
fn complete_version_charges_shared_allocations_once_but_each_context_mapping_separately() {
    let (_directory, cache, version) = same_payload_fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = prepare_version(&mut pool, &cache, &version);
    let pins = expected(&version, &model, &environment);
    let cancelled = AtomicBool::new(false);
    let exact_limits = CellResidencyConfigV1 {
        max_resident_bytes: 32769,
        max_resident_closures: 2,
        max_chunk_references: 6,
    };
    let ready = pool
        .admit_local_version(TASK, &version, &pins, exact_limits, deadline(), &cancelled)
        .unwrap();
    assert_eq!(ready.usage().unique_payload_bytes, 32769);
    assert_eq!(ready.usage().unique_chunks, 3);
    assert_eq!(ready.usage().chunk_references, 6);
    ready
        .with_local(TASK, &pins, |view| {
            assert_actual_version(view, &version);
            let model_chunks: Vec<_> = view.model().files()[0].chunks().collect();
            let env_chunks: Vec<_> = view.environment().files()[0].chunks().collect();
            for (left, right) in model_chunks.iter().zip(env_chunks) {
                assert_eq!(left.as_ptr(), right.as_ptr());
            }
        })
        .unwrap();
    assert!(pool
        .admit_local_version(
            TASK,
            &version,
            &pins,
            CellResidencyConfigV1 {
                max_chunk_references: 5,
                ..exact_limits
            },
            deadline(),
            &cancelled,
        )
        .is_err());
}
