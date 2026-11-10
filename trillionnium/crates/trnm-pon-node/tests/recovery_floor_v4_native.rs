//! Recovery-floor refusal controls with real signatures and local fixtures.
//! These exercise the configured pin, not independence of its custody or age.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{RootActionV3, RootStatementV3};

fn open_with_floor(h: &Harness, floor: RecoveryFloorV4) -> RootOwnerResultV3<RootOwnerV3> {
    RootOwnerV3::open_existing_with_recovery_floor(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: false },
        h.service.clone(),
        floor,
        &mut owner_budget(),
    )
}

fn append(owner: &mut RootOwnerV3, nonce: u8) -> CommittedRootOperationV3 {
    let current = owner.context(&mut owner_budget()).unwrap();
    let envelope = fixtures().root.envelope(
        RootStatementV3 {
            scope: current.scope,
            generation: current.generation,
            sequence: current.last_sequence + 1,
            predecessor: current.predecessor,
            nonce: [nonce; 32],
            valid_from_unix: 100,
            expires_at_unix: 900,
            action: RootActionV3::Normal {
                intent: intent(nonce),
            },
        },
        None,
    );
    owner.apply(&envelope, 110, &mut owner_budget()).unwrap()
}

#[test]
fn native_floor_v4_exact_signed_ancestor_survives_append_and_reopen() {
    let h = Harness::new();
    let mut owner = h.create();
    assert!(owner.recovery_floor().is_none());
    let first = append(&mut owner, 41);
    let floor = RecoveryFloorV4::from_external_pin(&h.enrollment, first.head).unwrap();
    drop(owner);
    let mut protected = open_with_floor(&h, floor.clone()).unwrap();
    assert_eq!(protected.recovery_floor(), Some(&floor));
    let second = append(&mut protected, 42);
    assert_eq!(second.head.version, first.head.version + 1);
    let observed = protected
        .observe_current_intent(second.operation_id, 111, &mut owner_budget())
        .unwrap();
    assert_eq!(observed.observed_head(), second.head);
    drop(protected);
    let mut reopened = open_with_floor(&h, floor.clone()).unwrap();
    assert_eq!(
        reopened.context(&mut owner_budget()).unwrap().head,
        second.head
    );
    assert_eq!(reopened.recovery_floor(), Some(&floor));
}

#[test]
fn native_floor_v4_complete_enrollment_binding_precedes_storage_and_anchor() {
    let h = Harness::new();
    drop(h.create());
    let before = std::fs::read(h.path()).unwrap();
    let calls = h.service.state.borrow().calls;
    let mut different_policy = fixtures().root.policy();
    different_policy.expires_at_unix -= 1;
    let changed = JournalEnrollmentV3::new(
        domain(),
        different_policy,
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    assert_eq!(changed.scope(), h.enrollment.scope());
    let floor =
        RecoveryFloorV4::from_external_pin(&changed, changed.initial_head().unwrap()).unwrap();
    let error = open_with_floor(&h, floor).err().unwrap();
    assert_eq!(error.to_string(), "ROOT_OWNER_RECOVERY_FLOOR_ENROLLMENT");
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    assert_eq!(h.service.state.borrow().calls, calls);
}

#[test]
fn native_floor_v4_higher_counter_cannot_replace_exact_signed_ancestry() {
    let h = Harness::new();
    let mut owner = h.create();
    let first = append(&mut owner, 43);
    append(&mut owner, 44);
    drop(owner);
    let mut unrelated = first.head;
    unrelated.root[0] ^= 1;
    let floor = RecoveryFloorV4::from_external_pin(&h.enrollment, unrelated).unwrap();
    let calls = h.service.state.borrow().calls;
    let error = open_with_floor(&h, floor).err().unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_OWNER_RECOVERY_FLOOR_NOT_IN_SIGNED_HISTORY"
    );
    assert_eq!(h.service.state.borrow().calls, calls);
}

#[test]
fn native_floor_v4_history_below_external_lower_bound_is_refused() {
    let newer = Harness::new();
    let mut advanced = newer.create();
    let completed = append(&mut advanced, 45);
    let floor = RecoveryFloorV4::from_external_pin(&newer.enrollment, completed.head).unwrap();
    let earlier = Harness::new();
    drop(earlier.create());
    let before = std::fs::read(earlier.path()).unwrap();
    let calls = earlier.service.state.borrow().calls;
    let error = open_with_floor(&earlier, floor).err().unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_OWNER_RECOVERY_FLOOR_NOT_IN_SIGNED_HISTORY"
    );
    assert_eq!(std::fs::read(earlier.path()).unwrap(), before);
    assert_eq!(earlier.service.state.borrow().calls, calls);
}

#[test]
fn native_floor_v4_pending_target_needs_signed_replay_and_explicit_completion() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner
        .apply(&normal(&state(), 46), 110, &mut owner_budget())
        .is_err());
    let target = h.service.state.borrow().head;
    let cas_calls = h.service.state.borrow().cas_calls;
    let floor = RecoveryFloorV4::from_external_pin(&h.enrollment, target).unwrap();
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = open_with_floor(&h, floor).unwrap();
    assert_eq!(h.pending(), 1);
    assert_eq!(
        reopened.resume_pending(&mut owner_budget()).unwrap(),
        target
    );
    assert_eq!(h.pending(), 0);
    assert_eq!(h.service.state.borrow().cas_calls, cas_calls);
}

#[test]
fn native_floor_v4_pending_bytes_do_not_become_authority_from_head_match() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner
        .apply(&normal(&state(), 47), 110, &mut owner_budget())
        .is_err());
    let floor =
        RecoveryFloorV4::from_external_pin(&h.enrollment, h.service.state.borrow().head).unwrap();
    drop(owner);
    let db = rusqlite::Connection::open(h.path()).unwrap();
    db.execute("UPDATE pending SET state=zeroblob(length(state))", [])
        .unwrap();
    drop(db);
    h.service.state.borrow_mut().fault = Fault::None;
    let calls = h.service.state.borrow().calls;
    assert!(open_with_floor(&h, floor).is_err());
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().calls, calls);
}

#[test]
fn native_floor_v4_fresh_anchor_authentication_remains_required() {
    let h = Harness::new();
    let mut owner = h.create();
    let operation = append(&mut owner, 48);
    let floor = RecoveryFloorV4::from_external_pin(&h.enrollment, operation.head).unwrap();
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::WrongChallenge;
    let error = open_with_floor(&h, floor).err().unwrap();
    assert_eq!(error.to_string(), "ROOT_ANCHOR_COMPLETE_REQUEST_BINDING");
}

#[test]
fn native_floor_v4_common_restore_contrast_stale_pin_accepts_surviving_pin_rejects() {
    // Control: two real signed operations exist before the local and external
    // anchor histories are both restored to the first signed operation.
    let h = Harness::new();
    let mut owner = h.create();
    let first = append(&mut owner, 49);
    let old_owner_snapshot = std::fs::read(h.path()).unwrap();
    let second = append(&mut owner, 50);
    assert_eq!(second.head.version, first.head.version + 1);
    drop(owner);
    std::fs::write(h.path(), &old_owner_snapshot).unwrap();
    h.service.state.borrow_mut().head = first.head;

    // This pin is replayed from the same old state as the owner and anchor.
    // It has the right enrollment and signed ancestry but is *not* evidence of
    // external provenance or freshness. The old intent is still accepted.
    let stale_floor = RecoveryFloorV4::from_external_pin(&h.enrollment, first.head).unwrap();
    let mut accepted = open_with_floor(&h, stale_floor).unwrap();
    assert_eq!(
        accepted.context(&mut owner_budget()).unwrap().head,
        first.head
    );
    assert!(accepted
        .observe_current_intent(first.operation_id, 112, &mut owner_budget())
        .is_ok());
    drop(accepted);

    // Contrasting only the pin: an actually surviving second head refuses the
    // same common restore before any anchor exchange or file mutation. This
    // test does not authenticate the pin's custody, survival, or age.
    let before = std::fs::read(h.path()).unwrap();
    let calls = h.service.state.borrow().calls;
    let surviving_floor = RecoveryFloorV4::from_external_pin(&h.enrollment, second.head).unwrap();
    let error = open_with_floor(&h, surviving_floor).err().unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_OWNER_RECOVERY_FLOOR_NOT_IN_SIGNED_HISTORY"
    );
    assert_eq!(std::fs::read(h.path()).unwrap(), before);
    assert_eq!(h.service.state.borrow().calls, calls);
}

#[test]
fn native_floor_v4_invalid_pin_shapes_are_refused() {
    let h = Harness::new();
    for head in [
        JournalHeadV3 {
            version: 0,
            root: [0; 64],
        },
        JournalHeadV3 {
            version: MAX_JOURNAL_EVENTS_V3 as u64 + 1,
            root: [1; 64],
        },
    ] {
        assert!(RecoveryFloorV4::from_external_pin(&h.enrollment, head).is_err());
    }
    assert!(!h.path().exists());
}
