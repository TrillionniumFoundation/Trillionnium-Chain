use super::*;
use crate::cell::{
    release_snapshot::tests::{expected, fixture, owners},
    CellLoaderContextV1, CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1, CellStoreV1,
    CellTensorContractV1, CellTensorModelManifestV1, CellVersionManifestV1,
};
use std::{cell::Cell, sync::atomic::Ordering, time::Duration};

const TASK: CellDigestV1 = [40; 32];

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn limits() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 1 << 20,
        max_resident_closures: 4,
        max_chunk_references: 32,
    }
}

fn prepare_component(
    pool: &mut CellResidencyV1,
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    owner: &CellLoaderContextV1,
) {
    pool.prepare_cached(store, closure, owner, deadline(), &AtomicBool::new(false))
        .unwrap();
}

fn prepare(pool: &mut CellResidencyV1, store: &CellStoreV1, snapshot: &CellReleaseSnapshotV1) {
    let (model, environment) = owners(snapshot);
    prepare_component(pool, store, snapshot.version().model().closure(), &model);
    prepare_component(pool, store, snapshot.version().environment(), &environment);
}

fn select(
    pool: &mut CellResidencyV1,
    snapshot: &CellReleaseSnapshotV1,
) -> CellLocalReleaseSelectionV1 {
    let (model, environment) = owners(snapshot);
    pool.select_local_release_snapshot(
        pool.local_selection(),
        TASK,
        snapshot,
        &expected(snapshot, &model, &environment),
        limits(),
        deadline(),
        &AtomicBool::new(false),
    )
    .unwrap()
}

/// Both generations change, including the model's environment identity, while
/// all actual payload bytes remain shared. This is a new complete version,
/// not a forged ticket or a second pointer to the original model generation.
fn successor(store: &CellStoreV1, previous: &CellReleaseSnapshotV1) -> CellReleaseSnapshotV1 {
    let old_environment = previous.version().environment();
    let environment = CellReleaseClosureV1::new(
        old_environment.release().context().clone(),
        old_environment.selected_generation() + 1,
        old_environment.loader_profile(),
        old_environment.roots().to_vec(),
        old_environment.files().to_vec(),
    )
    .unwrap();
    let old_model = previous.version().model().closure();
    let mut context = old_model.release().context().clone();
    context.runtime = environment.id();
    let mut manifests: Vec<_> = previous
        .version()
        .manifests()
        .iter()
        .filter(|manifest| {
            environment
                .release()
                .cells()
                .binary_search(&manifest.id())
                .is_ok()
        })
        .cloned()
        .collect();
    let mut files = old_model.files().to_vec();
    for file in &mut files {
        let original = previous
            .version()
            .manifests()
            .iter()
            .find(|manifest| manifest.id() == file.manifest)
            .unwrap();
        let manifest = CellManifestV1::new(
            context.clone(),
            original.size(),
            original.payload_sha256(),
            original.chunk_bytes(),
            original.chunks().to_vec(),
        )
        .unwrap();
        store
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        file.manifest = manifest.id();
        manifests.push(manifest);
    }
    manifests.sort_by_key(CellManifestV1::id);
    let model = CellModelReleaseRootV1::new(
        CellReleaseClosureV1::new(
            context,
            old_model.selected_generation() + 1,
            old_model.loader_profile(),
            old_model.roots().to_vec(),
            files,
        )
        .unwrap(),
        vec![],
    )
    .unwrap();
    let tensors = CellTensorModelManifestV1::new(
        model.clone(),
        CellTensorContractV1::new(model.id(), previous.tensors().contract().files().to_vec())
            .unwrap(),
    )
    .unwrap();
    CellReleaseSnapshotV1::new(
        CellVersionManifestV1::new(model, environment, manifests).unwrap(),
        tensors,
        previous.composition_file(),
        previous.composition_profile(),
    )
    .unwrap()
}

#[test]
fn complete_release_switch_pins_both_closures_and_reuses_shared_chunks() {
    let (_dir, store, first) = fixture();
    let second = successor(&store, &first);
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &first);
    let first_usage = pool.usage();
    let old = select(&mut pool, &first);
    assert_eq!(old.snapshot(), first.commitment());
    assert_eq!(old.version(), first.version().commitment());
    assert_eq!(old.revision(), 1);
    assert!(pool.evict(old.model_closure()).is_err());
    assert!(pool.evict(old.environment_closure()).is_err());
    prepare(&mut pool, &store, &second);
    assert_eq!(
        pool.usage().unique_payload_bytes,
        first_usage.unique_payload_bytes
    );
    assert_eq!(pool.usage().unique_chunks, first_usage.unique_chunks);
    assert_eq!(
        pool.usage().chunk_references,
        2 * first_usage.chunk_references
    );
    let current = select(&mut pool, &second);
    assert_eq!(current.revision(), 2);
    assert_eq!(pool.release_selection(), Some(current));
    assert!(pool.evict(current.model_closure()).is_err());
    assert!(pool.evict(current.environment_closure()).is_err());
    pool.evict(old.model_closure()).unwrap();
    pool.evict(old.environment_closure()).unwrap();
    assert_eq!(pool.usage(), first_usage);
    let (model, environment) = owners(&second);
    let pins = expected(&second, &model, &environment);
    let running = AtomicBool::new(false);
    let ready = pool
        .admit_selected_local_release_snapshot(
            current,
            [41; 32],
            &second,
            &pins,
            limits(),
            deadline(),
            &running,
        )
        .unwrap();
    ready
        .with_local([41; 32], &pins, |view| {
            assert_eq!(view.version().model().closure_id(), current.model_closure());
            assert_eq!(
                view.version().environment().closure_id(),
                current.environment_closure()
            );
            assert_eq!(
                view.tensors()
                    .tensor(0, "weight")
                    .unwrap()
                    .read_f32(0)
                    .unwrap(),
                1.25
            );
            assert_eq!(view.composition().path(), "rules.json");
        })
        .unwrap();
}

#[test]
fn complete_release_switch_rejects_stale_aba_and_foreign_tickets() {
    let (_dir, store, first) = fixture();
    let second = successor(&store, &first);
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let mut foreign = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &first);
    prepare(&mut pool, &store, &second);
    prepare(&mut foreign, &store, &first);
    let old = select(&mut pool, &first);
    let foreign_ticket = select(&mut foreign, &first);
    assert_eq!(old.snapshot(), foreign_ticket.snapshot());
    assert_eq!(old.revision(), foreign_ticket.revision());
    assert_ne!(old, foreign_ticket);
    let (model, environment) = owners(&second);
    let pins = expected(&second, &model, &environment);
    for previous in [
        None,
        Some(CellLocalSelectionStateV1::Release(foreign_ticket)),
    ] {
        assert!(pool
            .select_local_release_snapshot(
                previous,
                TASK,
                &second,
                &pins,
                limits(),
                deadline(),
                &AtomicBool::new(false),
            )
            .is_err());
        assert_eq!(pool.release_selection(), Some(old));
    }
    select(&mut pool, &second);
    let returned = select(&mut pool, &first);
    assert_eq!(returned.snapshot(), old.snapshot());
    assert_eq!(returned.revision(), old.revision() + 2);
    assert!(pool
        .select_local_release_snapshot(
            Some(CellLocalSelectionStateV1::Release(old)),
            TASK,
            &second,
            &pins,
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(pool.release_selection(), Some(returned));
    let (model, environment) = owners(&first);
    let pins = expected(&first, &model, &environment);
    for ticket in [old, foreign_ticket] {
        assert!(pool
            .admit_selected_local_release_snapshot(
                ticket,
                TASK,
                &first,
                &pins,
                limits(),
                deadline(),
                &AtomicBool::new(false),
            )
            .is_err());
    }
}

#[test]
fn incomplete_successor_and_actual_tensor_mismatch_preserve_complete_selection() {
    let (_dir, store, first) = fixture();
    let second = successor(&store, &first);
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &first);
    let old = select(&mut pool, &first);
    let (model, environment) = owners(&second);
    prepare_component(
        &mut pool,
        &store,
        second.version().model().closure(),
        &model,
    );
    let usage = pool.usage();
    assert!(pool
        .select_local_release_snapshot(
            pool.local_selection(),
            TASK,
            &second,
            &expected(&second, &model, &environment),
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(pool.release_selection(), Some(old));
    assert_eq!(pool.usage(), usage);
    prepare_component(
        &mut pool,
        &store,
        second.version().environment(),
        &environment,
    );
    let mut files = second.tensors().contract().files().to_vec();
    files[0].tensors[0].shape = vec![1, 2];
    let bad = CellReleaseSnapshotV1::new(
        second.version().clone(),
        CellTensorModelManifestV1::new(
            second.version().model().clone(),
            CellTensorContractV1::new(second.version().model().id(), files).unwrap(),
        )
        .unwrap(),
        second.composition_file(),
        second.composition_profile(),
    )
    .unwrap();
    let usage = pool.usage();
    assert!(pool
        .select_local_release_snapshot(
            pool.local_selection(),
            TASK,
            &bad,
            &expected(&bad, &model, &environment),
            limits(),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(pool.release_selection(), Some(old));
    assert_eq!(pool.usage(), usage);
    assert_eq!(select(&mut pool, &second).snapshot(), second.commitment());
}

#[test]
fn cancelled_expired_and_underbudget_switches_preserve_selected_release() {
    let (_dir, store, first) = fixture();
    let second = successor(&store, &first);
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &first);
    prepare(&mut pool, &store, &second);
    let old = select(&mut pool, &first);
    let usage = pool.usage();
    let (model, environment) = owners(&second);
    let pins = expected(&second, &model, &environment);
    let running = AtomicBool::new(false);
    let cancelled = AtomicBool::new(true);
    let mut too_small = limits();
    too_small.max_resident_bytes = 1;
    for (limit, cutoff, token) in [
        (limits(), Instant::now(), &running),
        (limits(), deadline(), &cancelled),
        (too_small, deadline(), &running),
    ] {
        assert!(pool
            .select_local_release_snapshot(
                pool.local_selection(),
                TASK,
                &second,
                &pins,
                limit,
                cutoff,
                token,
            )
            .is_err());
        assert_eq!(pool.release_selection(), Some(old));
        assert_eq!(pool.usage(), usage);
    }
}

#[test]
fn complete_release_upgrade_is_explicit_and_legacy_selected_paths_refuse() {
    let (_dir, store, snapshot) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &snapshot);
    let (model, environment) = owners(&snapshot);
    let running = AtomicBool::new(false);
    let legacy = pool
        .select_local(None, &model, deadline(), &running)
        .unwrap();
    let pins = expected(&snapshot, &model, &environment);
    assert!(
        pool.select_local_release_snapshot(
            None,
            TASK,
            &snapshot,
            &pins,
            limits(),
            deadline(),
            &running,
        )
        .is_err()
    );
    assert_eq!(pool.selection(), Some(legacy));
    let selected = pool
        .select_local_release_snapshot(
            Some(CellLocalSelectionStateV1::Closure(legacy)),
            TASK,
            &snapshot,
            &pins,
            limits(),
            deadline(),
            &running,
        )
        .unwrap();
    assert_eq!(selected.revision(), legacy.revision() + 1);
    assert!(pool.selection().is_none());
    assert_eq!(
        pool.local_selection(),
        Some(CellLocalSelectionStateV1::Release(selected))
    );
    for previous in [None, Some(legacy)] {
        assert!(pool
            .select_local(previous, &model, deadline(), &running)
            .is_err());
    }
    let called = Cell::new(false);
    assert!(pool
        .with_selected(&model, deadline(), |_| called.set(true))
        .is_err());
    assert!(!called.get());
    assert!(pool
        .admit_selected_tensor_model(
            snapshot.tensors(),
            snapshot.tensors().id(),
            &model,
            deadline(),
            &running
        )
        .is_err());
    assert_eq!(pool.release_selection(), Some(selected));
}

#[test]
fn selected_release_admission_rejects_wrong_complete_pins_and_current_contexts() {
    let (_dir, store, snapshot) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &snapshot);
    let selected = select(&mut pool, &snapshot);
    let (model, environment) = owners(&snapshot);
    let running = AtomicBool::new(false);
    let reject = |pins: &CellReleaseSnapshotLoaderContextV1<'_>| {
        assert!(pool
            .admit_selected_local_release_snapshot(
                selected,
                TASK,
                &snapshot,
                pins,
                limits(),
                deadline(),
                &running,
            )
            .is_err());
    };
    let mut pins = expected(&snapshot, &model, &environment);
    pins.snapshot[0] ^= 1;
    reject(&pins);
    pins = expected(&snapshot, &model, &environment);
    pins.composition_profile[0] ^= 1;
    reject(&pins);
    pins = expected(&snapshot, &model, &environment);
    pins.version.commitment[0] ^= 1;
    reject(&pins);
    let mut wrong = environment.clone();
    wrong.selected_generation += 1;
    reject(&expected(&snapshot, &model, &wrong));
    wrong = environment.clone();
    wrong.max_payload_bytes = 1;
    reject(&expected(&snapshot, &model, &wrong));
    reject(&expected(&snapshot, &environment, &model));
    let other = successor(&store, &snapshot);
    assert!(pool
        .admit_selected_local_release_snapshot(
            selected,
            TASK,
            &other,
            &expected(&snapshot, &model, &environment),
            limits(),
            deadline(),
            &running,
        )
        .is_err());
    assert_eq!(pool.release_selection(), Some(selected));
}

#[test]
fn selected_release_task_cancellation_is_latched_and_old_task_id_refuses() {
    let (_dir, store, snapshot) = fixture();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut pool, &store, &snapshot);
    let selected = select(&mut pool, &snapshot);
    let (model, environment) = owners(&snapshot);
    let pins = expected(&snapshot, &model, &environment);
    let cancelled = AtomicBool::new(false);
    let task = [41; 32];
    let ready = pool
        .admit_selected_local_release_snapshot(
            selected,
            task,
            &snapshot,
            &pins,
            limits(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let called = Cell::new(false);
    assert!(ready.with_local(TASK, &pins, |_| called.set(true)).is_err());
    assert!(!called.get());
    ready.with_local(task, &pins, |_| ()).unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(ready.with_local(task, &pins, |_| called.set(true)).is_err());
    cancelled.store(false, Ordering::Release);
    assert!(ready.with_local(task, &pins, |_| called.set(true)).is_err());
    assert!(!called.get());
}

#[test]
fn restart_rehydrates_bytes_without_restoring_selection_or_old_ticket() {
    let (_dir, store, snapshot) = fixture();
    let mut old = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut old, &store, &snapshot);
    let stale = select(&mut old, &snapshot);
    drop(old);
    let mut reopened = CellResidencyV1::new(limits()).unwrap();
    prepare(&mut reopened, &store, &snapshot);
    assert_eq!(reopened.local_selection(), None);
    let (model, environment) = owners(&snapshot);
    let pins = expected(&snapshot, &model, &environment);
    let running = AtomicBool::new(false);
    assert!(reopened
        .admit_selected_local_release_snapshot(
            stale,
            TASK,
            &snapshot,
            &pins,
            limits(),
            deadline(),
            &running,
        )
        .is_err());
    assert!(reopened
        .select_local_release_snapshot(
            Some(CellLocalSelectionStateV1::Release(stale)),
            TASK,
            &snapshot,
            &pins,
            limits(),
            deadline(),
            &running,
        )
        .is_err());
    let fresh = select(&mut reopened, &snapshot);
    assert_eq!(stale.snapshot(), fresh.snapshot());
    assert_eq!(stale.revision(), fresh.revision());
    assert_ne!(stale, fresh);
}
