use std::{cell::Cell, sync::atomic::Ordering, time::Duration};

use super::*;
use crate::cell::{
    adoption_boundary::tests::{boundary, execution, successor},
    version::tests::{fixture, owner},
    CellAdoptionActionV1 as Action, CellAdoptionPolicyV1, CellCandidateEvidenceV1, CellFileRoleV1,
    CellLoaderContextV1, CellStoreV1,
};

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

fn policy(version: &CellVersionManifestV1, node: u8) -> CellAdoptionPolicyV1 {
    CellAdoptionPolicyV1::new([node; 32], [44; 32], [45; 32], boundary(version)).unwrap()
}

fn private_directory() -> tempfile::TempDir {
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let directory = tempfile::tempdir_in(parent).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn selected_owner(
    path: &std::path::Path,
    policy: &CellAdoptionPolicyV1,
    version: &CellVersionManifestV1,
) -> CellAdoptionOwnerV1 {
    let mut owner = CellAdoptionOwnerV1::create(path, policy).unwrap();
    owner
        .observe_candidate(version, None, CellCandidateEvidenceV1::default())
        .unwrap();
    let initial = owner.snapshot().unwrap();
    assert!(initial.selected().is_none());
    owner
        .decide(
            [1; 32],
            &initial,
            Action::Adopt,
            version.commitment(),
            [61; 64],
        )
        .unwrap();
    owner
}

fn prepare(
    pool: &mut CellResidencyV1,
    cache: &CellStoreV1,
    version: &CellVersionManifestV1,
) -> (CellLoaderContextV1, CellLoaderContextV1) {
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    for (closure, expected) in [
        (version.model().closure(), &model),
        (version.environment(), &environment),
    ] {
        pool.prepare_cached(
            cache,
            closure,
            expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
    }
    (model, environment)
}

fn pins<'a>(
    version: &CellVersionManifestV1,
    contexts: &'a (CellLoaderContextV1, CellLoaderContextV1),
) -> CellVersionLoaderContextV1<'a> {
    CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &contexts.0,
        environment: &contexts.1,
    }
}

#[test]
fn two_nodes_consume_different_actual_bytes_after_adopt_and_defer() {
    let (_directory, cache, parent) = fixture();
    let candidate = successor(&cache, &parent, 81);
    let private = private_directory();
    let mut first = selected_owner(
        &private.path().join("first.db"),
        &policy(&parent, 51),
        &parent,
    );
    let mut second = selected_owner(
        &private.path().join("second.db"),
        &policy(&parent, 52),
        &parent,
    );
    for node in [&mut first, &mut second] {
        let before = node.snapshot().unwrap();
        node.observe_candidate(
            &candidate,
            Some(parent.commitment()),
            CellCandidateEvidenceV1 {
                evaluation: Some([71; 64]),
                chain_observation: Some([72; 64]),
                ..CellCandidateEvidenceV1::default()
            },
        )
        .unwrap();
        assert_eq!(node.snapshot().unwrap(), before);
    }
    let first_before = first.snapshot().unwrap();
    let second_before = second.snapshot().unwrap();
    first
        .decide(
            [2; 32],
            &first_before,
            Action::Adopt,
            candidate.commitment(),
            [62; 64],
        )
        .unwrap();
    second
        .decide(
            [2; 32],
            &second_before,
            Action::Defer,
            candidate.commitment(),
            [63; 64],
        )
        .unwrap();
    let first_choice = first.snapshot().unwrap();
    let second_choice = second.snapshot().unwrap();
    assert_eq!(first_choice.selected(), Some(candidate.commitment()));
    assert_eq!(second_choice.selected(), Some(parent.commitment()));

    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let parent_contexts = prepare(&mut pool, &cache, &parent);
    let candidate_contexts = prepare(&mut pool, &cache, &candidate);
    let cancelled = AtomicBool::new(false);
    let current_execution = execution();
    for (node, choice, version, contexts, expected_first_byte) in [
        (
            &mut first,
            &first_choice,
            &candidate,
            &candidate_contexts,
            81,
        ),
        (&mut second, &second_choice, &parent, &parent_contexts, 21),
    ] {
        let current = pins(version, contexts);
        let ready = pool
            .admit_local_version(
                [91; 32],
                version,
                &current,
                limits(),
                deadline(),
                &cancelled,
            )
            .unwrap();
        let byte = ready
            .with_selected(
                [91; 32],
                &current,
                CellAdoptionUseV1 {
                    owner: node,
                    snapshot: choice,
                    execution: &current_execution,
                },
                |view| {
                    assert_eq!(view.commitment(), version.commitment());
                    assert_eq!(view.environment().closure(), parent.environment());
                    view.model().files()[0].chunks().next().unwrap()[0]
                },
            )
            .unwrap();
        assert_eq!(byte, expected_first_byte);
    }
    let current = pins(&candidate, &candidate_contexts);
    let ready = pool
        .admit_local_version(
            [92; 32],
            &candidate,
            &current,
            limits(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let calls = Cell::new(0);
    assert!(ready
        .with_selected(
            [92; 32],
            &current,
            CellAdoptionUseV1 {
                owner: &mut second,
                snapshot: &second_choice,
                execution: &current_execution
            },
            |_| calls.set(calls.get() + 1),
        )
        .is_err());
    assert_eq!(calls.get(), 0);
}

#[test]
fn rollback_reads_retained_parent_but_never_revives_an_old_selection_snapshot() {
    let (_directory, cache, parent) = fixture();
    let candidate = successor(&cache, &parent, 82);
    let private = private_directory();
    let mut node = selected_owner(
        &private.path().join("owner.db"),
        &policy(&parent, 53),
        &parent,
    );
    let old_parent = node.snapshot().unwrap();
    node.observe_candidate(
        &candidate,
        Some(parent.commitment()),
        CellCandidateEvidenceV1::default(),
    )
    .unwrap();
    node.decide(
        [2; 32],
        &old_parent,
        Action::Adopt,
        candidate.commitment(),
        [62; 64],
    )
    .unwrap();
    let adopted = node.snapshot().unwrap();
    node.decide(
        [3; 32],
        &adopted,
        Action::Rollback,
        parent.commitment(),
        [63; 64],
    )
    .unwrap();
    let rolled_back = node.snapshot().unwrap();
    assert!(rolled_back.revision() > adopted.revision());
    assert_eq!(rolled_back.selected(), old_parent.selected());
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let contexts = prepare(&mut pool, &cache, &parent);
    let current = pins(&parent, &contexts);
    let cancelled = AtomicBool::new(false);
    let ready = pool
        .admit_local_version(
            [93; 32],
            &parent,
            &current,
            limits(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let execution = execution();
    let calls = Cell::new(0);
    for stale in [&old_parent, &adopted] {
        assert!(ready
            .with_selected(
                [93; 32],
                &current,
                CellAdoptionUseV1 {
                    owner: &mut node,
                    snapshot: stale,
                    execution: &execution
                },
                |_| calls.set(calls.get() + 1),
            )
            .is_err());
    }
    assert_eq!(calls.get(), 0);
    let byte = ready
        .with_selected(
            [93; 32],
            &current,
            CellAdoptionUseV1 {
                owner: &mut node,
                snapshot: &rolled_back,
                execution: &execution,
            },
            |view| view.model().files()[0].chunks().next().unwrap()[0],
        )
        .unwrap();
    assert_eq!(byte, 21);
}

#[test]
fn selected_use_holds_writer_fence_through_actual_consumer_callback() {
    let (_directory, cache, parent) = fixture();
    let candidate = successor(&cache, &parent, 83);
    let private = private_directory();
    let path = private.path().join("owner.db");
    let policy = policy(&parent, 54);
    let mut node = selected_owner(&path, &policy, &parent);
    node.observe_candidate(
        &candidate,
        Some(parent.commitment()),
        CellCandidateEvidenceV1::default(),
    )
    .unwrap();
    let selected = node.snapshot().unwrap();
    let mut other = CellAdoptionOwnerV1::open(&path, &policy, &selected).unwrap();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let contexts = prepare(&mut pool, &cache, &parent);
    let current = pins(&parent, &contexts);
    let cancelled = AtomicBool::new(false);
    let ready = pool
        .admit_local_version(
            [94; 32],
            &parent,
            &current,
            limits(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    ready
        .with_selected(
            [94; 32],
            &current,
            CellAdoptionUseV1 {
                owner: &mut node,
                snapshot: &selected,
                execution: &execution(),
            },
            |view| {
                assert!(other
                    .decide(
                        [2; 32],
                        &selected,
                        Action::Adopt,
                        candidate.commitment(),
                        [62; 64]
                    )
                    .is_err());
                assert_eq!(view.commitment(), parent.commitment());
            },
        )
        .unwrap();
    assert_eq!(node.snapshot().unwrap(), selected);
    other
        .decide(
            [2; 32],
            &selected,
            Action::Adopt,
            candidate.commitment(),
            [62; 64],
        )
        .unwrap();
    assert_eq!(
        node.snapshot().unwrap().selected(),
        Some(candidate.commitment())
    );
}

#[test]
fn selected_use_still_requires_live_task_and_unchanged_host_execution_pins() {
    let (_directory, cache, parent) = fixture();
    let private = private_directory();
    let mut node = selected_owner(
        &private.path().join("owner.db"),
        &policy(&parent, 55),
        &parent,
    );
    let selected = node.snapshot().unwrap();
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let contexts = prepare(&mut pool, &cache, &parent);
    let current = pins(&parent, &contexts);
    let cancelled = AtomicBool::new(false);
    let ready = pool
        .admit_local_version(
            [95; 32],
            &parent,
            &current,
            limits(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let calls = Cell::new(0);
    let mut changed = execution();
    changed.root_authority = [99; 32];
    assert!(ready
        .with_selected(
            [95; 32],
            &current,
            CellAdoptionUseV1 {
                owner: &mut node,
                snapshot: &selected,
                execution: &changed
            },
            |_| calls.set(calls.get() + 1),
        )
        .is_err());
    cancelled.store(true, Ordering::Relaxed);
    assert!(ready
        .with_selected(
            [95; 32],
            &current,
            CellAdoptionUseV1 {
                owner: &mut node,
                snapshot: &selected,
                execution: &execution()
            },
            |_| calls.set(calls.get() + 1),
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(node.snapshot().unwrap(), selected);
}
