use super::*;
use crate::cell::{
    adoption_boundary::tests::{boundary, execution, successor},
    version::tests::fixture,
    CellErrorV1, CellResultV1, CellStoreV1, CellVersionManifestV1,
};
use std::{cell::Cell, fs, path::PathBuf};

mod retention;

thread_local! {
    static BEFORE_COMMIT: Cell<bool> = const { Cell::new(false) };
    static AFTER_COMMIT: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn before_decision_commit() -> CellResultV1<()> {
    if BEFORE_COMMIT.replace(false) {
        Err(CellErrorV1::Invalid("adoption injected precommit cut"))
    } else {
        Ok(())
    }
}
pub(super) fn after_decision_commit() -> CellResultV1<()> {
    if AFTER_COMMIT.replace(false) {
        Err(CellErrorV1::Invalid("adoption injected lost commit reply"))
    } else {
        Ok(())
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: CellStoreV1,
    anchor: CellVersionManifestV1,
    candidate: CellVersionManifestV1,
    policy: CellAdoptionPolicyV1,
    owner: CellAdoptionOwnerV1,
}

fn setup() -> Fixture {
    let (directory, store, anchor) = fixture();
    let parent = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // This test owns the temporary namespace; provision the same private
        // parent that the production local-owner API requires.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = parent.join("adoption.sqlite");
    let candidate = successor(&store, &anchor, 81);
    let policy = CellAdoptionPolicyV1::new([1; 32], [2; 32], [3; 32], boundary(&anchor)).unwrap();
    let owner = CellAdoptionOwnerV1::create(&path, &policy).unwrap();
    Fixture {
        _directory: directory,
        path,
        store,
        anchor,
        candidate,
        policy,
        owner,
    }
}

fn bootstrap(f: &mut Fixture) -> CellAdoptionSnapshotV1 {
    f.owner
        .observe_candidate(&f.anchor, None, CellCandidateEvidenceV1::default())
        .unwrap();
    let before = f.owner.snapshot().unwrap();
    assert_eq!((before.revision(), before.selected()), (0, None));
    f.owner
        .decide(
            [1; 32],
            &before,
            CellAdoptionActionV1::Adopt,
            f.anchor.commitment(),
            [71; 64],
        )
        .unwrap()
        .after()
        .clone()
}

fn observe_next(f: &mut Fixture) {
    f.owner
        .observe_candidate(
            &f.candidate,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1 {
                evaluation: Some([11; 64]),
                reproduction: Some([12; 64]),
                chain_observation: Some([13; 64]),
                settlement: None,
            },
        )
        .unwrap();
}

#[test]
fn observations_and_same_candidate_two_node_choices_do_not_force_adoption() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    let second_policy =
        CellAdoptionPolicyV1::new([9; 32], [2; 32], [3; 32], boundary(&f.anchor)).unwrap();
    let second_path = f.path.with_file_name("second.sqlite");
    let mut other = CellAdoptionOwnerV1::create(&second_path, &second_policy).unwrap();
    other
        .observe_candidate(&f.anchor, None, CellCandidateEvidenceV1::default())
        .unwrap();
    let zero = other.snapshot().unwrap();
    let other_first = other
        .decide(
            [1; 32],
            &zero,
            CellAdoptionActionV1::Adopt,
            f.anchor.commitment(),
            [71; 64],
        )
        .unwrap()
        .after()
        .clone();
    observe_next(&mut f);
    other
        .observe_candidate(
            &f.candidate,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    assert_eq!(f.owner.snapshot().unwrap(), first);
    assert_eq!(other.snapshot().unwrap(), other_first);
    let accepted = f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    let deferred = other
        .decide(
            [2; 32],
            &other_first,
            CellAdoptionActionV1::Defer,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    assert_eq!(accepted.after().selected(), Some(f.candidate.commitment()));
    assert_eq!(deferred.after().selected(), Some(f.anchor.commitment()));
    assert_ne!(
        accepted.after().policy_digest(),
        deferred.after().policy_digest()
    );
    let deferred = deferred.after().clone();
    other
        .observe_candidate(
            &f.candidate,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1 {
                evaluation: Some([44; 64]),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(other.snapshot().unwrap(), deferred);
    assert!(other
        .with_selected_guard(&deferred, &f.anchor, &execution(), || Ok(()))
        .is_ok());
}

#[test]
fn all_four_actions_rollback_with_a_new_revision_and_exact_cold_readback() {
    let mut f = setup();
    let initial = bootstrap(&mut f);
    observe_next(&mut f);
    let defer = f
        .owner
        .decide(
            [2; 32],
            &initial,
            CellAdoptionActionV1::Defer,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    let retain = f
        .owner
        .decide(
            [3; 32],
            defer.after(),
            CellAdoptionActionV1::Retain,
            f.anchor.commitment(),
            [73; 64],
        )
        .unwrap();
    let adopt = f
        .owner
        .decide(
            [4; 32],
            retain.after(),
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [74; 64],
        )
        .unwrap();
    let rollback = f
        .owner
        .decide(
            [5; 32],
            adopt.after(),
            CellAdoptionActionV1::Rollback,
            f.anchor.commitment(),
            [75; 64],
        )
        .unwrap();
    assert_eq!(
        (rollback.after().revision(), rollback.after().selected()),
        (5, Some(f.anchor.commitment()))
    );
    let restored = CellAdoptionSnapshotV1::decode(&rollback.after().encode()).unwrap();
    drop(f.owner);
    let mut cold = CellAdoptionOwnerV1::open(&f.path, &f.policy, &restored).unwrap();
    assert_eq!(cold.snapshot().unwrap(), restored);
    let replay = cold
        .decide(
            [4; 32],
            retain.after(),
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [74; 64],
        )
        .unwrap();
    assert_eq!(replay, adopt);
    assert_eq!(cold.snapshot().unwrap(), restored);
    let called = Cell::new(false);
    assert!(cold
        .with_selected_guard(replay.after(), &f.candidate, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}

#[test]
fn stale_snapshot_and_changed_request_bytes_refuse_without_state_effects() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let deferred = f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Defer,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    assert!(f
        .owner
        .decide(
            [3; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [73; 64]
        )
        .is_err());
    assert!(f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Defer,
            f.candidate.commitment(),
            [99; 64]
        )
        .is_err());
    assert!(f
        .owner
        .decide(
            [3; 32],
            deferred.after(),
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [0; 64]
        )
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), *deferred.after());
    let receipt = f
        .owner
        .decide(
            [3; 32],
            deferred.after(),
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [73; 64],
        )
        .unwrap();
    assert_eq!(receipt.after().revision(), 3);
}

#[test]
fn complete_parent_bytes_and_local_selection_history_are_required() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    let grandchild = successor(&f.store, &f.candidate, 82);
    assert!(f
        .owner
        .observe_candidate(
            &grandchild,
            Some(f.candidate.commitment()),
            CellCandidateEvidenceV1::default()
        )
        .is_err());
    assert!(f
        .owner
        .observe_candidate(&f.candidate, None, CellCandidateEvidenceV1::default())
        .is_err());
    observe_next(&mut f);
    assert!(f
        .owner
        .observe_candidate(
            &grandchild,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1::default()
        )
        .is_err());
    f.owner
        .observe_candidate(
            &grandchild,
            Some(f.candidate.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    assert!(f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            grandchild.commitment(),
            [72; 64]
        )
        .is_err());
    assert!(f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Rollback,
            f.candidate.commitment(),
            [72; 64]
        )
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), first);
}

#[test]
fn model_evidence_cannot_change_immutable_policy_or_bootstrap_another_origin() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    let altered =
        CellAdoptionPolicyV1::new([9; 32], [2; 32], [3; 32], boundary(&f.anchor)).unwrap();
    assert!(CellAdoptionOwnerV1::open(&f.path, &altered, &first).is_err());
    assert!(CellAdoptionOwnerV1::open(&f.path, &altered, &altered.initial()).is_err());
    let altered = f.policy.clone().with_limits(2, 2).unwrap();
    assert!(CellAdoptionOwnerV1::open(&f.path, &altered, &altered.initial()).is_err());
    assert!(CellAdoptionOwnerV1::create(&f.path, &f.policy).is_err());
    assert_eq!(f.owner.snapshot().unwrap(), first);
}

#[test]
fn selected_callback_excludes_cooperating_writer_without_wait_or_deadlock() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let mut other = CellAdoptionOwnerV1::open(&f.path, &f.policy, &first).unwrap();
    let candidate = f.candidate.commitment();
    let result = f
        .owner
        .with_selected_guard(&first, &f.anchor, &execution(), || {
            assert!(other
                .decide(
                    [2; 32],
                    &first,
                    CellAdoptionActionV1::Adopt,
                    candidate,
                    [72; 64]
                )
                .is_err());
            Ok(19)
        })
        .unwrap();
    assert_eq!(result, 19);
    assert_eq!(f.owner.snapshot().unwrap(), first);
    let next = other
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            candidate,
            [72; 64],
        )
        .unwrap();
    assert_eq!(next.after().selected(), Some(candidate));
    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_guard(&first, &f.anchor, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}

#[test]
fn execution_boundary_changes_and_unselected_versions_never_enter_consumer() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let calls = Cell::new(0);
    for field in 0..6 {
        let mut changed = execution();
        let pins = [
            &mut changed.network,
            &mut changed.consensus,
            &mut changed.fees,
            &mut changed.root_authority,
            &mut changed.node_software,
            &mut changed.protocol_configuration,
        ];
        *pins.into_iter().nth(field).unwrap() = [90; 32];
        assert!(f
            .owner
            .with_selected_guard(&first, &f.anchor, &changed, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .is_err());
    }
    assert!(f
        .owner
        .with_selected_guard(&first, &f.candidate, &execution(), || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.get(), 0);
    f.owner
        .with_selected_guard(&first, &f.anchor, &execution(), || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
}

#[test]
fn lost_reply_reconciles_the_original_request_and_precommit_cut_rolls_back() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    BEFORE_COMMIT.set(true);
    assert!(f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64]
        )
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), first);
    AFTER_COMMIT.set(true);
    assert!(f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64]
        )
        .is_err());
    drop(f.owner);
    let mut cold = CellAdoptionOwnerV1::open(&f.path, &f.policy, &first).unwrap();
    let receipt = cold
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    assert_eq!(receipt.after().revision(), 2);
    assert_eq!(cold.snapshot().unwrap(), *receipt.after());
    assert_eq!(
        cold.decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64]
        )
        .unwrap(),
        receipt
    );
}

#[test]
fn a_surviving_recovery_floor_rejects_whole_database_restore() {
    let mut f = setup();
    let old = bootstrap(&mut f);
    let image = fs::read(&f.path).unwrap();
    observe_next(&mut f);
    let new = f
        .owner
        .decide(
            [2; 32],
            &old,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap()
        .after()
        .clone();
    drop(f.owner);
    fs::write(&f.path, image).unwrap();
    assert!(CellAdoptionOwnerV1::open(&f.path, &f.policy, &new).is_err());
    // This is a retained limitation control: jointly restoring the floor and
    // database is not detectable by local hashing. Do not claim independence.
    let mut old_owner = CellAdoptionOwnerV1::open(&f.path, &f.policy, &old).unwrap();
    assert_eq!(old_owner.snapshot().unwrap(), old);
}

#[test]
fn schema_history_and_reference_tampering_refuse_before_use() {
    for mutation in [
        "CREATE TABLE foreign_object(v INTEGER)",
        "DELETE FROM adoption_decisions",
        "UPDATE adoption_observations SET material=x'00'",
    ] {
        let mut f = setup();
        let first = bootstrap(&mut f);
        let connection = rusqlite::Connection::open(&f.path).unwrap();
        connection.execute_batch(mutation).unwrap();
        drop(connection);
        let called = Cell::new(false);
        assert!(f
            .owner
            .with_selected_guard(&first, &f.anchor, &execution(), || {
                called.set(true);
                Ok(())
            })
            .is_err());
        assert!(!called.get());
    }
}

#[test]
fn replacement_and_hard_link_alias_refusal_are_latched() {
    for alias in [false, true] {
        let mut f = setup();
        let _first = bootstrap(&mut f);
        let other = f.path.with_file_name("retained.sqlite");
        if alias {
            fs::hard_link(&f.path, &other).unwrap();
        } else {
            fs::rename(&f.path, &other).unwrap();
            fs::copy(&other, &f.path).unwrap();
        }
        assert!(f.owner.snapshot().is_err());
        if alias {
            fs::remove_file(other).unwrap();
        } else {
            fs::remove_file(&f.path).unwrap();
            fs::rename(other, &f.path).unwrap();
        }
        assert!(f.owner.snapshot().is_err());
    }
}

#[test]
fn finite_history_survives_reopen_and_idempotence_never_spends_another_slot() {
    let mut f = setup();
    drop(f.owner);
    fs::remove_file(&f.path).unwrap();
    f.policy = f.policy.with_limits(2, 2).unwrap();
    f.owner = CellAdoptionOwnerV1::create(&f.path, &f.policy).unwrap();
    let first = bootstrap(&mut f);
    observe_next(&mut f);
    let last = f
        .owner
        .decide(
            [2; 32],
            &first,
            CellAdoptionActionV1::Defer,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    assert_eq!(
        f.owner
            .decide(
                [2; 32],
                &first,
                CellAdoptionActionV1::Defer,
                f.candidate.commitment(),
                [72; 64]
            )
            .unwrap(),
        last
    );
    assert!(f
        .owner
        .decide(
            [3; 32],
            last.after(),
            CellAdoptionActionV1::Retain,
            f.anchor.commitment(),
            [73; 64]
        )
        .is_err());
    let third = successor(&f.store, &f.candidate, 82);
    assert!(f
        .owner
        .observe_candidate(
            &third,
            Some(f.candidate.commitment()),
            CellCandidateEvidenceV1::default()
        )
        .is_err());
    drop(f.owner);
    let mut cold = CellAdoptionOwnerV1::open(&f.path, &f.policy, last.after()).unwrap();
    assert_eq!(cold.snapshot().unwrap(), *last.after());
    assert!(cold
        .decide(
            [3; 32],
            last.after(),
            CellAdoptionActionV1::Retain,
            f.anchor.commitment(),
            [73; 64]
        )
        .is_err());
}

#[test]
fn snapshot_roundtrip_is_exact_but_does_not_authenticate_a_floor() {
    let mut f = setup();
    let first = bootstrap(&mut f);
    let mut bytes = first.encode();
    assert_eq!(CellAdoptionSnapshotV1::decode(&bytes).unwrap(), first);
    bytes.push(0);
    assert!(CellAdoptionSnapshotV1::decode(&bytes).is_err());
    let mut forged = first.clone();
    forged.history[0] ^= 1;
    assert!(CellAdoptionOwnerV1::open(&f.path, &f.policy, &forged).is_err());
}

#[test]
fn an_exact_nonorigin_anchor_bootstraps_without_claiming_historical_reverification() {
    let f = setup();
    assert!(!f.candidate.model().lineage().is_empty());
    let policy =
        CellAdoptionPolicyV1::new([81; 32], [82; 32], [83; 32], boundary(&f.candidate)).unwrap();
    let path = f.path.with_file_name("nonorigin.sqlite");
    let mut owner = CellAdoptionOwnerV1::create(&path, &policy).unwrap();
    assert!(owner
        .observe_candidate(&f.anchor, None, CellCandidateEvidenceV1::default())
        .is_err());
    owner
        .observe_candidate(&f.candidate, None, CellCandidateEvidenceV1::default())
        .unwrap();
    let empty = owner.snapshot().unwrap();
    let selected = owner
        .decide(
            [1; 32],
            &empty,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [71; 64],
        )
        .unwrap();
    let next = successor(&f.store, &f.candidate, 84);
    owner
        .observe_candidate(
            &next,
            Some(f.candidate.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    owner
        .decide(
            [2; 32],
            selected.after(),
            CellAdoptionActionV1::Adopt,
            next.commitment(),
            [72; 64],
        )
        .unwrap();
    assert_eq!(
        owner.snapshot().unwrap().selected(),
        Some(next.commitment())
    );
}

#[test]
fn a_retained_child_can_be_explicitly_readopted_after_rollback_at_a_new_revision() {
    let mut f = setup();
    let anchor = bootstrap(&mut f);
    observe_next(&mut f);
    let adopted = f
        .owner
        .decide(
            [2; 32],
            &anchor,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [72; 64],
        )
        .unwrap();
    let rolled_back = f
        .owner
        .decide(
            [3; 32],
            adopted.after(),
            CellAdoptionActionV1::Rollback,
            f.anchor.commitment(),
            [73; 64],
        )
        .unwrap();
    let readopted = f
        .owner
        .decide(
            [4; 32],
            rolled_back.after(),
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [74; 64],
        )
        .unwrap();
    assert_eq!(readopted.candidate(), adopted.candidate());
    assert_eq!(readopted.after().revision(), 4);
    assert_ne!(readopted.request_id(), adopted.request_id());
    assert_ne!(
        readopted.after().history_digest(),
        adopted.after().history_digest()
    );
    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_guard(adopted.after(), &f.candidate, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    f.owner
        .with_selected_guard(readopted.after(), &f.candidate, &execution(), || Ok(()))
        .unwrap();
}

#[test]
fn observed_committed_floor_survives_consumer_and_request_failure() {
    for rejection in 0..3 {
        let mut f = setup();
        let first = bootstrap(&mut f);
        observe_next(&mut f);
        let mut other = CellAdoptionOwnerV1::open(&f.path, &f.policy, &first).unwrap();
        let second = other
            .decide(
                [2; 32],
                &first,
                CellAdoptionActionV1::Adopt,
                f.candidate.commitment(),
                [72; 64],
            )
            .unwrap();
        match rejection {
            0 => {
                let result: CellResultV1<()> =
                    f.owner
                        .with_selected_guard(second.after(), &f.candidate, &execution(), || {
                            Err(CellErrorV1::Invalid(
                                "consumer failed after observing selection",
                            ))
                        });
                assert!(result.is_err());
            }
            1 => assert!(f
                .owner
                .decide(
                    [3; 32],
                    &first,
                    CellAdoptionActionV1::Retain,
                    f.anchor.commitment(),
                    [73; 64],
                )
                .is_err()),
            _ => assert!(f
                .owner
                .observe_candidate(
                    &f.candidate,
                    Some([99; 64]),
                    CellCandidateEvidenceV1::default(),
                )
                .is_err()),
        }
        // Restore a fully self-consistent earlier local decision history in
        // the same file. The newer observation survives only in this owner.
        // This models recovery/tampering, not a supported raw-SQL write API.
        let mut connection = rusqlite::Connection::open(&f.path).unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute("DELETE FROM adoption_decisions WHERE revision>1", [])
            .unwrap();
        transaction
            .execute(
                "UPDATE adoption_state SET snapshot=?1 WHERE singleton=1",
                rusqlite::params![first.encode()],
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);
        assert!(matches!(
            f.owner.snapshot(),
            Err(CellErrorV1::Invalid(
                "adoption state/recovery floor mismatch"
            ))
        ));
    }
}
