//! Real dual-family signatures with a same-host fixture authority. These tests
//! deliberately retain the complete-owner-plus-anchor rollback counterexample.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_root_v3::{RootSignatureV3, VerificationBudgetV3};
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::RootActionV3;

#[test]
fn native_owner_v3_domain_binds_each_independent_identity_without_zero_fallback() {
    let pinned = domain();
    assert_eq!(pinned.network(), [17; 32]);
    assert_eq!(pinned.genesis(), [18; 32]);
    assert_eq!(pinned.owner(), [19; 32]);
    for (network, genesis, owner) in [
        ([0; 32], [18; 32], [19; 32]),
        ([17; 32], [0; 32], [19; 32]),
        ([17; 32], [18; 32], [0; 32]),
    ] {
        assert!(JournalDomainV3::new(network, genesis, owner).is_err());
    }
    for changed in [
        JournalDomainV3::new([20; 32], [18; 32], [19; 32]).unwrap(),
        JournalDomainV3::new([17; 32], [20; 32], [19; 32]).unwrap(),
        JournalDomainV3::new([17; 32], [18; 32], [20; 32]).unwrap(),
        JournalDomainV3::new([18; 32], [17; 32], [19; 32]).unwrap(),
    ] {
        assert_ne!(changed.scope(), pinned.scope());
    }
}

#[test]
fn native_owner_v3_real_signed_append_reopen_and_exact_intent_observation() {
    let h = Harness::new();
    let mut owner = h.create();
    let operation = normal(&state(), 1);
    let committed = owner.apply(&operation, 110, &mut owner_budget()).unwrap();
    assert_eq!(committed.head.version, 1);
    assert_eq!(h.pending(), 0);
    drop(owner);
    let mut reopened = h.open().unwrap();
    let context = reopened.context(&mut owner_budget()).unwrap();
    assert_eq!(context.last_sequence, 1);
    assert_eq!(context.head, committed.head);
    let observed = reopened
        .observe_current_intent(committed.operation_id, 111, &mut owner_budget())
        .unwrap();
    assert!(observed.intent().matches_bytes(
        b"complete bundle",
        b"complete launch contract",
        b"held actual executable"
    ));
    assert!(!observed.intent().matches_bytes(
        b"complete bundle",
        b"changed command",
        b"held actual executable"
    ));
}

#[test]
fn native_owner_v3_replay_preserves_nonce_and_refuses_second_exact_operation() {
    let h = Harness::new();
    let operation = normal(&state(), 2);
    let mut owner = h.create();
    owner.apply(&operation, 110, &mut owner_budget()).unwrap();
    drop(owner);
    let mut reopened = h.open().unwrap();
    let before = h.service.state.borrow().head;
    assert!(reopened
        .apply(&operation, 111, &mut owner_budget())
        .is_err());
    drop(reopened);
    let mut current = state();
    current
        .apply(&operation, 110, &mut VerificationBudgetV3::new(64).unwrap())
        .unwrap();
    let changed = fixtures().root.envelope(
        statement(&current, 2, RootActionV3::Normal { intent: intent(22) }),
        None,
    );
    let error = h
        .open()
        .unwrap()
        .apply(&changed, 111, &mut owner_budget())
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("refused: Nonce"),
        "fresh predecessor and valid new signatures still cannot reuse a persisted nonce: {error}"
    );
    assert_eq!(h.service.state.borrow().head, before);
    assert_eq!(h.pending(), 0);
}

#[test]
fn native_owner_v3_lost_successful_cas_reply_requires_explicit_exact_completion() {
    let h = Harness::new();
    let mut owner = h.create();
    let operation = normal(&state(), 3);
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner.apply(&operation, 110, &mut owner_budget()).is_err());
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    assert!(owner.context(&mut owner_budget()).is_err());
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    assert_eq!(
        h.pending(),
        1,
        "open does not promote pending automatically"
    );
    let calls_before = h.service.state.borrow().cas_calls;
    let head = reopened.resume_pending(&mut owner_budget()).unwrap();
    assert_eq!(head.version, 1);
    assert_eq!(h.pending(), 0);
    assert_eq!(
        h.service.state.borrow().cas_calls,
        calls_before,
        "recovery never resubmits CAS"
    );
    reopened
        .observe_current_intent(
            operation.statement.operation_id().unwrap(),
            111,
            &mut owner_budget(),
        )
        .unwrap();
}

#[test]
fn native_owner_v3_unadvanced_anchor_cannot_clear_pending_or_retry() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::BeforeCas;
    assert!(owner
        .apply(&normal(&state(), 4), 110, &mut owner_budget())
        .is_err());
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 0);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    assert!(h.open().is_err());
    assert_eq!(h.pending(), 1);
    assert!(RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
}

#[test]
fn native_owner_v3_corrupt_pending_state_cannot_promote_even_after_real_cas() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner
        .apply(&normal(&state(), 5), 110, &mut owner_budget())
        .is_err());
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute("UPDATE pending SET state=zeroblob(length(state))", [])
        .unwrap();
    drop(foreign);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    assert!(reopened.resume_pending(&mut owner_budget()).is_err());
    assert_eq!(h.pending(), 1);
}

#[test]
fn native_owner_v3_retained_external_anchor_refuses_whole_local_rollback() {
    let h = Harness::new();
    let mut owner = h.create();
    let before = fs::read(h.path()).unwrap();
    owner
        .apply(&normal(&state(), 6), 110, &mut owner_budget())
        .unwrap();
    drop(owner);
    fs::write(h.path(), before).unwrap();
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().head.version, 1);
}

#[test]
fn native_owner_v3_co_restored_owner_and_anchor_counterexample_remains_accepted() {
    let h = Harness::new();
    let mut owner = h.create();
    let first = normal(&state(), 7);
    let first_commit = owner.apply(&first, 110, &mut owner_budget()).unwrap();
    let snapshot = fs::read(h.path()).unwrap();
    let mut kernel = state();
    kernel
        .apply(&first, 110, &mut VerificationBudgetV3::new(64).unwrap())
        .unwrap();
    owner
        .apply(&normal(&kernel, 8), 111, &mut owner_budget())
        .unwrap();
    drop(owner);
    fs::write(h.path(), snapshot).unwrap();
    h.service.state.borrow_mut().head = first_commit.head;
    let mut restored = h.open().unwrap();
    // Fresh real signatures cannot identify a rollback of every retained source
    // of currentness. This accepted observation is the explicit counterexample.
    assert!(restored
        .observe_current_intent(first_commit.operation_id, 112, &mut owner_budget())
        .is_ok());
}

#[test]
fn native_owner_v3_wrong_enrollment_scope_and_service_aliases_are_refused() {
    let h = Harness::new();
    assert!(JournalEnrollmentV3::new(
        domain(),
        fixtures().writer.policy(),
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone()
    )
    .is_err());
    assert!(JournalEnrollmentV3::new(
        domain(),
        fixtures().root.policy(),
        100,
        fixtures().anchor.roster.clone(),
        fixtures().anchor.roster.clone()
    )
    .is_err());
    let owner = h.create();
    drop(owner);
    let wrong = JournalEnrollmentV3::new(
        JournalDomainV3::new([18; 32], [18; 32], [19; 32]).unwrap(),
        fixtures().root.policy(),
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    let calls = h.service.state.borrow().calls;
    assert!(RootOwnerV3::open_existing(
        &h.path(),
        wrong,
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
    assert_eq!(
        h.service.state.borrow().calls,
        calls,
        "enrollment mismatch rejects before transport"
    );
}

#[test]
fn native_owner_v3_successor_cannot_reuse_an_anchor_or_writer_key() {
    let h = Harness::new();
    let mut owner = h.create();
    let action = RootActionV3::Rotate {
        next: fixtures().anchor.policy(),
    };
    let operation = fixtures()
        .root
        .envelope(statement(&state(), 9, action), Some(&fixtures().anchor));
    assert!(owner.apply(&operation, 110, &mut owner_budget()).is_err());
    assert_eq!(h.pending(), 0);
    assert_eq!(h.service.state.borrow().head.version, 0);
}

#[test]
fn native_owner_v3_last_observation_rechecks_persisted_revocation_and_rotation() {
    for rotate in [false, true] {
        let h = Harness::new();
        let mut owner = h.create();
        let first = normal(&state(), 10);
        let operation = owner
            .apply(&first, 110, &mut owner_budget())
            .unwrap()
            .operation_id;
        let mut current = state();
        current
            .apply(&first, 110, &mut VerificationBudgetV3::new(64).unwrap())
            .unwrap();
        let action = if rotate {
            RootActionV3::Rotate {
                next: fixtures().next.policy(),
            }
        } else {
            RootActionV3::Revoke {
                keys: vec![first.approvals[0].signer],
            }
        };
        let transition = fixtures().root.envelope(
            statement(&current, 11, action),
            rotate.then_some(&fixtures().next),
        );
        owner.apply(&transition, 111, &mut owner_budget()).unwrap();
        drop(owner);
        let mut reopened = h.open().unwrap();
        assert!(reopened
            .observe_current_intent(operation, 112, &mut owner_budget())
            .is_err());
    }
}

#[test]
fn native_owner_v3_authenticated_response_still_must_bind_fresh_challenge() {
    for fault in [Fault::WrongChallenge, Fault::WrongSignature] {
        let h = Harness::new();
        let owner = h.create();
        drop(owner);
        h.service.state.borrow_mut().fault = fault;
        assert!(h.open().is_err());
    }
}

#[test]
fn native_owner_v3_writer_signature_is_verified_before_transport() {
    let h = Harness::new();
    let error = RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: true },
        h.service.clone(),
        &mut owner_budget(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("V3 root signature rejected"));
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_owner_v3_callback_cannot_replace_original_owner_budget() {
    struct ReplacingWriter;
    impl RootWriterSignerV3 for ReplacingWriter {
        fn sign(
            &mut self,
            message: &[u8],
            original: &mut OwnerBudgetV3,
        ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
            let signatures = fixtures().writer.quorum(message);
            *original = owner_budget();
            Ok(signatures)
        }
    }
    let h = Harness::new();
    let error = RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        ReplacingWriter,
        h.service.clone(),
        &mut owner_budget(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("CALLBACK_REPLACED_BUDGET"));
    assert_eq!(h.service.state.borrow().calls, 0);
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::ReplaceBudgetAfterCas;
    let error = owner
        .apply(&normal(&state(), 14), 110, &mut owner_budget())
        .err()
        .unwrap();
    assert!(error.to_string().contains("CALLBACK_REPLACED_BUDGET"));
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    h.open()
        .unwrap()
        .resume_pending(&mut owner_budget())
        .unwrap();
}

#[test]
fn native_owner_v3_same_budget_exhaustion_retains_pending_before_cas() {
    let h = Harness::new();
    let mut owner = h.create();
    let until = Instant::now() + Duration::from_secs(120);
    let mut limited = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(16, until).unwrap(),
        until,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert!(owner
        .apply(&normal(&state(), 12), 110, &mut limited)
        .is_err());
    assert!(limited.attempts() > 16);
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().cas_calls, 0);
}

#[test]
fn native_owner_v3_cancellation_after_external_commit_requires_reconciliation() {
    let observed_signal = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(120);
    let observed_budget = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        observed_signal.clone(),
    )
    .unwrap();
    observed_signal.store(true, Ordering::Release);
    assert!(observed_budget.check().is_err());
    observed_signal.store(false, Ordering::Release);
    assert!(
        observed_budget.check().is_err(),
        "observed cancellation cannot be cleared through the retained external signal"
    );

    let h = Harness::new();
    let mut owner = h.create();
    let external = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(120);
    let mut original = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        external.clone(),
    )
    .unwrap();
    {
        let mut service = h.service.state.borrow_mut();
        service.fault = Fault::CancelAfterCas;
        service.reset_cancellation = Some(external.clone());
    }
    assert!(owner
        .apply(&normal(&state(), 13), 110, &mut original)
        .is_err());
    assert!(
        !external.load(Ordering::Acquire),
        "fixture cleared only its retained external alias"
    );
    assert!(
        original.check().is_err(),
        "explicit cancellation remains latched after the callback clears its alias"
    );
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    reopened.resume_pending(&mut owner_budget()).unwrap();
    assert_eq!(h.pending(), 0);
}

#[test]
fn native_owner_v3_storage_tamper_schema_alias_and_concurrent_open_fail_closed() {
    let h = Harness::new();
    let owner = h.create();
    assert!(h.open().is_err(), "concurrent exclusive owner refused");
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute_batch("CREATE TRIGGER untrusted AFTER UPDATE ON current BEGIN SELECT 1; END")
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
    let alias = h.directory.path().join("alias.sqlite");
    symlink(h.path(), &alias).unwrap();
    assert!(RootOwnerV3::open_existing(
        &alias,
        h.enrollment.clone(),
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
    fs::set_permissions(h.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(h.open().is_err());
}

#[test]
fn native_owner_v3_changed_current_bytes_and_replaced_database_are_not_authority() {
    let h = Harness::new();
    let mut owner = h.create();
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute("UPDATE current SET state=zeroblob(length(state))", [])
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(owner.context(&mut owner_budget()).is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
    drop(owner);
    let h = Harness::new();
    let mut owner = h.create();
    let replacement = h.directory.path().join("replacement.sqlite");
    fs::copy(h.path(), &replacement).unwrap();
    fs::rename(&replacement, h.path()).unwrap();
    assert!(owner.context(&mut owner_budget()).is_err());
}

#[test]
fn native_owner_v3_foreign_sqlite_namespace_is_refused_without_mutating_it() {
    let h = Harness::new();
    let legacy = rusqlite::Connection::open(h.path()).unwrap();
    legacy.execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=1; CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES('retained');").unwrap();
    drop(legacy);
    fs::set_permissions(h.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(h.path()).unwrap();
    let error = h.open().err().unwrap();
    assert!(error.to_string().contains("DATABASE_NAMESPACE"));
    assert_eq!(fs::read(h.path()).unwrap(), before);
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_owner_v3_reopen_reverifies_retained_signature_bytes() {
    let h = Harness::new();
    let mut owner = h.create();
    owner
        .apply(&normal(&state(), 15), 110, &mut owner_budget())
        .unwrap();
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    let mut wire: Vec<u8> = foreign
        .query_row("SELECT envelope FROM events WHERE version=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let last = wire.last_mut().unwrap();
    *last ^= 1;
    foreign
        .execute("UPDATE events SET envelope=? WHERE version=1", [wire])
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
}
