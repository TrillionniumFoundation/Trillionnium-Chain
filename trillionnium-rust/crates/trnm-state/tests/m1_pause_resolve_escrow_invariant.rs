use trnm_state::{
    GovParamUpdateOutcome, GovPendingUpdateAction, PendingResolveApprovalSnapshot, StateStore,
};
use trnm_types::{TaskObject, TaskStatus};

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_non_challenged_task_boundary() {
    // L03 boundary hardening: paused rollback/restore must not revive pending resolve quorum
    // onto a task that is no longer challenged, even if task version and authority set still
    // superficially match. Resolve approvals are only valid on the challenged-state boundary.
    let mut st = StateStore::new();

    st.set_gov_param(98_330, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_350, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");
    st.set_gov_param(98_351, 7_999, "emergency_pause".into(), "true".into())
        .expect("emergency pause should enable successfully");
    assert!(st.is_emergency_paused());

    st.put_task_new(TaskObject {
        task_id: 9_937,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 7,
    })
    .expect("non-challenged task should exist before restore attempt");

    st.restore_pending_resolve_approval(
        9_937,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_937), None);
    assert_eq!(st.pending_resolve_first_approver(9_937), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_937), None);
    assert!(st.pending_gov_update("resolve_authority").is_none());
    assert!(st.is_emergency_paused());
}

#[test]
fn resolve_authority_timelock_transition_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: once resolve_authority enters a timelock transition, any
    // previously staged resolve quorum must be scrubbed immediately so stale approvals cannot
    // linger across the governance boundary in paused or unpaused operation.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_300,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_320,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let first = st
        .stage_or_confirm_resolve_approval(9_980, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first authority approval should stage successfully");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_980), Some((true, 1)));
    let root_with_pending = st.state_root();

    let replacement = st
        .set_gov_param(
            98_321,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    assert_eq!(st.pending_resolve_approval(9_980), None);
    assert_eq!(st.pending_resolve_first_approver(9_980), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_980), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "scrubbing stale pending resolve approvals must invalidate cached state root"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
}

#[test]
fn resolve_authority_same_value_replace_preserves_pending_timelock_and_staged_quorum() {
    // L03 boundary hardening: replaying an identical pre-activation resolve_authority replacement
    // must be idempotent. It must not extend the timelock or scrub already staged quorum because
    // the governance boundary itself did not change.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_325,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_345,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let first_replace = st
        .set_gov_param_with_action(
            98_346,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should schedule");
    let activate_at_height = match first_replace {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    let first = st
        .stage_or_confirm_resolve_approval(9_982, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before idempotent replay");
    assert!(!first);
    let pending_before = st
        .pending_resolve_approval_snapshot(9_982)
        .expect("staged quorum should exist before replaying identical replace");
    let root_with_pending = st.state_root();

    let replayed = st
        .set_gov_param_with_action(
            98_347,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("identical replacement replay should be idempotent");
    assert_eq!(
        replayed,
        GovParamUpdateOutcome::Scheduled { activate_at_height }
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_982),
        Some(pending_before),
        "identical replace replay must preserve staged quorum"
    );
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "idempotent replace replay must not perturb state root"
    );
}

#[test]
fn paused_resolve_authority_same_value_replace_preserves_pending_timelock_and_staged_quorum() {
    // L03 paused-boundary idempotence: replaying the exact same pre-activation
    // resolve_authority replacement while emergency_pause is active must not extend the
    // timelock or scrub quorum already staged against the pending authority set.
    let mut st = StateStore::new();

    st.set_gov_param(98_300, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_320, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");

    let activate_at_height = match st
        .set_gov_param_with_action(
            98_340,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should schedule while unpaused")
    {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected scheduled outcome, got {:?}", other),
    };

    st.set_gov_param(98_341, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_984, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval while paused");

    let pending_before = st
        .pending_resolve_approval_snapshot(9_984)
        .expect("staged resolve approval should exist before paused idempotent replay");
    let root_with_pending = st.state_root();

    let replay = st
        .set_gov_param_with_action(
            98_342,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replaying identical paused replacement must be idempotent");

    match replay {
        GovParamUpdateOutcome::Scheduled { activate_at_height: replay_height } => {
            assert_eq!(
                replay_height, activate_at_height,
                "paused idempotent replay must not extend resolve_authority timelock"
            );
        }
        other => panic!("expected scheduled outcome, got {:?}", other),
    }

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority timelock should remain staged while paused");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(st.pending_resolve_approval_snapshot(9_984), Some(pending_before));
    assert!(st.is_emergency_paused());
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "paused idempotent replay must not invalidate cached state root when no boundary changes"
    );
}

#[test]
fn paused_resolve_authority_activation_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: once a timelocked resolve_authority update activates under
    // emergency_pause, any quorum staged against the pending authority set must be scrubbed so
    // stale paused-state approvals cannot survive the authority boundary crossing.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_328,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_348,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_349,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    let activate_at_height = match replacement {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    st.set_gov_param(98_350, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_983, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before activation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_983), Some((true, 1)));
    let root_with_pending = st.state_root();

    let activated = st
        .set_gov_param(
            activate_at_height,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("timelocked resolve_authority should still apply while paused");
    assert!(matches!(activated, GovParamUpdateOutcome::Applied(_)));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-c,authority-d")
    );
    assert_eq!(st.pending_resolve_approval(9_983), None);
    assert_eq!(st.pending_resolve_first_approver(9_983), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_983), None);
    assert!(st.is_emergency_paused());
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "activating resolve_authority under pause must invalidate cached state root when scrubbing staged quorum"
    );
}

#[test]
fn resolve_authority_pending_cancel_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: cancelling a staged resolve_authority timelock is still a
    // governance boundary transition and must scrub any staged resolve quorum immediately.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_330,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_350,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_351,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let first = st
        .stage_or_confirm_resolve_approval(9_981, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before cancellation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_981), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_352,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("pending resolve_authority update should cancel cleanly");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(9_981), None);
    assert_eq!(st.pending_resolve_first_approver(9_981), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_981), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "cancelling a pending resolve_authority boundary must invalidate cached state root"
    );
}

#[test]
fn paused_resolve_authority_pending_cancel_scrubs_pending_resolve_approvals() {
    // L03 paused-boundary hardening: cancelling a staged resolve_authority timelock while
    // emergency_pause is active is still an authority-boundary transition and must scrub any
    // staged resolve quorum without unpausing or mutating the active authority set.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_360,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_380,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_381,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    st.set_gov_param(98_382, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_985, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before paused cancellation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_985), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_383,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("pending resolve_authority update should cancel cleanly while paused");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(9_985), None);
    assert_eq!(st.pending_resolve_first_approver(9_985), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_985), None);
    assert!(st.is_emergency_paused());
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "paused cancellation of a pending resolve_authority boundary must invalidate cached state root"
    );
}

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER: &str = "governance.resolve_authority";

#[test]
fn paused_state_preserves_escrow_and_keeps_resolve_authority_timelocked() {
    // M1 merge-gate invariant: emergency_pause is a safety brake only.
    // It must not mutate custody balances, and must not bypass resolve_authority timelock.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 250);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_100, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let resolve_before = st.gov_param_string("resolve_authority");

    let outcome = st
        .set_gov_param(
            98_101,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("resolve_authority update should be accepted under pause");

    assert!(
        matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }),
        "resolve_authority must remain timelocked while paused"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("resolve_authority update should be staged");
    assert_eq!(pending.key_id, 7_310);
    assert_eq!(pending.value, "authority-a,authority-b");

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        resolve_before,
        "timelocked resolve_authority must not apply immediately under pause"
    );

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_resolve_authority_placeholder_update_without_side_effects() {
    // M1 micro-hardening: the governance entrypoint must keep placeholder authority aliases
    // fail-closed under case drift even while paused, without staging a deferred update or
    // perturbing custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_100);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 778);

    st.set_gov_param(98_159, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,Governance.Resolve_Authority".into(),
        )
        .expect_err("case-variant placeholder member must be rejected at governance entrypoint");
    assert!(
        err.contains("placeholder authority") || err.contains("governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        None,
        "rejected placeholder update must not stage or apply a resolve authority value"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_system_or_treasury_resolve_authority_members_without_side_effects() {
    // M1 boundary hardening: paused governance must keep reserved/system custody identities out
    // of resolve_authority updates so corrupted aliases cannot be smuggled into approval sets.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_101);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 779);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 19);

    st.set_gov_param(98_159, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    for malformed_value in [
        "authority-a,System",
        "authority-a,TREASURY.CHALLENGE_ESCROW",
        "authority-a,treasury.worker_slashes",
    ] {
        let err = st
            .set_gov_param(
                98_160,
                7_310,
                "resolve_authority".into(),
                malformed_value.into(),
            )
            .expect_err("reserved/system members must be rejected at governance entrypoint");
        assert!(
            err.contains("reserved system authority")
                || err.contains("treasury custody accounts")
                || err.contains("governance value"),
            "unexpected error for {malformed_value}: {err}"
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            None,
            "rejected paused governance update must not leave pending residue"
        );
        assert_eq!(st.gov_param_string("resolve_authority"), None);
    }

    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_reserved_system_resolve_approvers_without_side_effects() {
    // M1 boundary hardening: even while paused, staged resolve approvals must reject
    // reserved/system actors as approvers so custody aliases cannot masquerade as quorum votes.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_101);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 779);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 19);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    for forbidden_approver in [
        "system",
        "Governance.Resolve_Authority",
        "TREASURY.CHALLENGE_ESCROW",
        "treasury.worker_slashes",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_810,
                1,
                true,
                forbidden_approver,
                "authority-a,authority-b",
            )
            .expect_err("reserved/system approver must be rejected while paused");
        assert!(
            err.contains("explicit non-system authority")
                || err.contains("single canonical actor id"),
            "unexpected error for {forbidden_approver}: {err}"
        );
        assert_eq!(
            st.pending_resolve_approval(9_810),
            None,
            "rejected approver must not leave staged quorum residue"
        );
        assert_eq!(st.pending_resolve_first_approver(9_810), None);
        assert_eq!(st.pending_resolve_approval_snapshot(9_810), None);
        assert_eq!(st.state_root(), root_before);
    }

    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_resolve_approval_authority_set_drift_without_side_effects() {
    // M1 boundary hardening: once governance has a configured resolve_authority set, staged
    // resolve approvals must match it exactly even while paused so callers cannot smuggle a
    // drifted approval quorum into pending resolve state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_102);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 780);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 20);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(8_182, 3, true, "authority-a", "authority-a,authority-c")
        .expect_err("drifted paused resolve approval authority set must be rejected");
    assert!(err.contains("must match configured governance authority"));

    assert_eq!(st.pending_resolve_approval(8_182), None);
    assert_eq!(st.pending_resolve_first_approver(8_182), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_cancels_pending_resolve_authority_scrubs_staged_approval_without_touching_custody(
) {
    // M1 boundary hardening: emergency_pause must not let a pending resolve_authority cancel
    // preserve stale staged quorum, and must not perturb escrow/treasury custody while the
    // governance boundary is being rolled back.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_103);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 781);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 21);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let replacement = st
        .set_gov_param(
            98_182,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be staged while paused");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let staged = st
        .stage_or_confirm_resolve_approval(
            8_183,
            3,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("pending replacement authority should stage paused resolve approval");
    assert!(!staged);
    assert_eq!(st.pending_resolve_approval(8_183), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_183,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("paused pending resolve_authority update should cancel cleanly");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.is_emergency_paused());
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(8_183), None);
    assert_eq!(st.pending_resolve_first_approver(8_183), None);
    assert_eq!(st.pending_resolve_approval_snapshot(8_183), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "paused resolve_authority cancel must invalidate cached state root when scrubbing staged quorum"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_resolve_approval_against_stale_configured_authority_when_pending_timelock_exists(
) {
    // M1 boundary hardening: once a replacement resolve_authority set is already pending,
    // paused resolve approvals must fail closed against the stale configured quorum instead of
    // letting callers keep staging approvals against the soon-to-be-replaced authority set.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_103);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 781);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 21);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(8_183, 3, true, "authority-a", "authority-a,authority-b")
        .expect_err(
            "stale configured resolve authority must be rejected once a pending replacement exists",
        );
    assert!(err.contains("must match pending governance authority"));

    assert_eq!(st.pending_resolve_approval(8_183), None);
    assert_eq!(st.pending_resolve_first_approver(8_183), None);
    assert!(st.is_emergency_paused());
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rejecting stale approval must not mutate the active configured authority set"
    );
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        escrow_before,
        "rejecting stale approval must not perturb challenge escrow"
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_pending_resolve_authority_conflict_keeps_original_timelock_and_pause_state() {
    // M1 micro-hardening: while paused, conflicting resolve_authority re-submission must fail
    // closed without mutating the already staged timelock entry or pause state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 777);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("initial resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before pause");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_161, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param(
            98_170,
            7_310,
            "resolve_authority".into(),
            "authority-e,authority-f".into(),
        )
        .expect_err("conflicting paused resolve_authority submit must stay blocked by timelock");
    assert!(
        err.contains("pending governance update exists for resolve_authority")
            || err.contains("timelock active"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("conflicting paused submit must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height, pending_before.activate_at_height,
        "paused conflicting submit must not move timelock boundary"
    );
    assert!(
        st.is_emergency_paused(),
        "paused conflicting submit must not unpause state"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused conflicting submit must not apply pending authority set early"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_identical_resolve_authority_replace_replay_preserves_staged_quorum_and_escrow() {
    // M1 micro-hardening: while paused, replaying an identical pre-maturity replace against the
    // same pending resolve_authority boundary must stay idempotent. It must preserve staged
    // quorum, keep escrow balances unchanged, and avoid moving the timelock boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_333);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param_with_action(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should be timelocked");
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_819_0,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    let pending_before = st
        .pending_resolve_approval_snapshot(9_819_0)
        .expect("paused staged quorum should exist before identical replace replay");
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let replayed = st
        .set_gov_param_with_action(
            98_190,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("paused identical replace replay should remain idempotent");
    assert_eq!(
        replayed,
        GovParamUpdateOutcome::Scheduled { activate_at_height }
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should remain staged after replay");
    assert_eq!(pending_after.value, "authority-c,authority-d");
    assert_eq!(pending_after.activate_at_height, activate_at_height);
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_819_0),
        Some(pending_before),
        "paused identical replace replay must preserve staged quorum"
    );
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "paused identical replace replay must not perturb staged quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "paused identical replace replay must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused identical replace replay must not apply pending authority set early"
    );
}

#[test]
fn paused_state_pending_resolve_authority_cancel_scrubs_staged_quorum_without_escrow_drift() {
    // M1 micro-hardening: while paused, cancelling a not-yet-mature resolve_authority
    // timelock is still a governance boundary transition. It must clear any staged quorum
    // bound to that pending authority set, preserve escrow balances, and keep pause enabled.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_333);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_819_1,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    assert_eq!(st.pending_resolve_approval(9_819_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_819_1).as_deref(),
        Some("authority-c")
    );
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let cancelled = st
        .set_gov_param_with_action(
            98_190,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("paused pending resolve_authority update should cancel before maturity");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused pre-maturity cancel must keep configured resolve authority unchanged"
    );
    assert_eq!(st.pending_resolve_approval(9_819_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_819_1), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_819_1), None);
    assert_ne!(
        st.state_root(),
        root_with_pending,
        "paused cancel of pending resolve_authority must invalidate staged pending resolve quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "paused pre-maturity cancel must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_timelock_cannot_be_canceled_instead_of_applied() {
    // M1 micro-hardening: once a paused resolve_authority timelock has matured, governance
    // must not be able to cancel the active pending entry and thereby dodge the apply boundary.
    // The mature pending update, pause state, and custody balances must remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_333);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before mature cancel attempt");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param_with_action(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("mature paused resolve_authority update must not be cancelable");
    assert!(
        err.contains("already active") || err.contains("must be applied"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("mature cancel rejection must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height,
        pending_before.activate_at_height
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature cancel rejection must not change currently applied authority set"
    );
    assert!(
        st.is_emergency_paused(),
        "mature cancel rejection must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_timelock_cannot_be_replaced_instead_of_applied() {
    // M1 micro-hardening: once a paused resolve_authority timelock has matured, governance
    // must not be able to replace the active pending entry and thereby move the apply boundary.
    // The mature pending update, pause state, and custody balances must remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_444);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 904);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before mature replace attempt");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param_with_action(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-e,authority-f".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("mature paused resolve_authority update must not be replaceable");
    assert!(
        err.contains("already active") || err.contains("must be applied"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("mature replace rejection must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height,
        pending_before.activate_at_height
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature replace rejection must not change currently applied authority set"
    );
    assert!(
        st.is_emergency_paused(),
        "mature replace rejection must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_apply_rejects_stale_old_quorum_without_residue() {
    // M1 micro-hardening: once a paused resolve_authority timelock is applied, callers must
    // not be able to keep staging approvals against the stale pre-rotation authority set.
    // The new boundary must fail closed without leaving pending quorum residue or mutating
    // pause / custody state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_444);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 904);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let applied_pending = st
        .set_gov_param(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("mature paused resolve_authority timelock should apply");
    assert!(matches!(applied_pending, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-c,authority-d".into())
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(9_820_0, 5, true, "authority-a", "authority-a,authority-b")
        .expect_err("stale pre-rotation authority set must be rejected after paused apply");
    assert!(err.contains("must match configured governance authority"));

    assert_eq!(st.pending_resolve_approval(9_820_0), None);
    assert_eq!(st.pending_resolve_first_approver(9_820_0), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_820_0), None);
    assert_eq!(st.state_root(), root_before);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_apply_scrubs_staged_pending_quorum() {
    // M1 micro-hardening: when a paused resolve_authority timelock reaches its apply
    // boundary, enforcing the mature value must rotate the configured authority, scrub any
    // staged quorum bound to that pending boundary, and leave pause/escrow state untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_445);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 905);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_820_1,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    assert_eq!(st.pending_resolve_approval(9_820_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_820_1).as_deref(),
        Some("authority-c")
    );
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let applied_pending = st
        .set_gov_param(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("mature paused resolve_authority timelock should apply");
    assert!(matches!(applied_pending, GovParamUpdateOutcome::Applied(_)));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-c,authority-d".into())
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.pending_resolve_approval(9_820_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_820_1), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_820_1), None);
    assert_ne!(
        st.state_root(),
        root_with_pending,
        "applying paused resolve_authority must invalidate staged pending resolve quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "applying mature resolve_authority must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_keeps_multi_party_resolve_quorum_and_escrow_conservation() {
    // M1 merge-gate invariant: emergency pause must not centralize resolve authority.
    // Even under pause, resolve confirmation remains 2-of-N distinct approvers and
    // custody balances stay untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 900);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_110, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert!(
        !first,
        "single approver must not finalize resolve approval while paused"
    );
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("same approver must still be rejected while paused");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize while paused");
    assert!(second, "second distinct approver must finalize");
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 2)));

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_authority_rotation_rejects_second_resolve_approval_without_escrow_drift() {
    // M1 micro-hardening: while paused, a rotated resolve authority set must fail closed,
    // clear the now-stale staged quorum, and leave custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_111);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 901);
    st.set_gov_param(98_111, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_1,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_1).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let rotated_err = st
        .stage_or_confirm_resolve_approval(
            9_901_1,
            1,
            true,
            "authority-c",
            "authority-a,authority-c",
        )
        .expect_err("paused authority rotation must fail closed and clear stale staged approval");
    assert!(
        rotated_err.contains("authority set changed"),
        "unexpected error: {rotated_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "authority rotation failure must not unpause state"
    );
    assert_eq!(st.pending_resolve_approval(9_901_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_901_1), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_resolve_decision_mismatch_without_escrow_or_quorum_mutation() {
    // M1 micro-hardening: while paused, a conflicting slash/no-slash confirmation must fail
    // closed and keep both the staged quorum and custody balances unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_222);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 902);
    st.set_gov_param(98_112, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_2,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_2), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_2).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let mismatch_err = st
        .stage_or_confirm_resolve_approval(
            9_901_2,
            1,
            false,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect_err("paused resolve decision mismatch must fail closed");
    assert!(
        mismatch_err.contains("decision mismatch"),
        "unexpected error: {mismatch_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "decision mismatch must not unpause state"
    );
    assert_eq!(st.pending_resolve_approval(9_901_2), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_2).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_resolve_task_version_drift_and_clears_stale_quorum_without_escrow_drift() {
    // M1 micro-hardening: while paused, a changed challenged-task version must fail closed,
    // clear the stale staged quorum, and leave custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_223);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);
    st.set_gov_param(98_113, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_3,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_3), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_3).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let version_err = st
        .stage_or_confirm_resolve_approval(
            9_901_3,
            2,
            true,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect_err("paused resolve task version drift must fail closed");
    assert!(
        version_err.contains("task version changed"),
        "unexpected error: {version_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "task version drift must not unpause state"
    );
    assert_eq!(
        st.pending_resolve_approval(9_901_3),
        None,
        "task version drift must clear stale staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_901_3),
        None,
        "task version drift must clear stale first-approver audit trail"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_second_resolve_approval_when_live_task_leaves_challenged_boundary() {
    // L03 boundary hardening: once a live task object is no longer Challenged, a previously
    // staged resolve quorum must be scrubbed instead of allowing a second approval to reuse the
    // stale boundary while paused.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_223);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);
    st.set_gov_param(98_117, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.restore_task(
        9_901_4,
        Some(TaskObject {
            task_id: 9_901_4,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(5),
            challenger: Some("challenger-a".into()),
            challenge_bond_forfeited: None,
            version: 1,
        }),
    );

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_4,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed on challenged task");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_901_4), Some((true, 1)));

    st.restore_task(
        9_901_4,
        Some(TaskObject {
            task_id: 9_901_4,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: Some([1u8; 32]),
            result_hash: Some([2u8; 32]),
            reveal_salt: Some([3u8; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(5),
            challenger: Some("challenger-a".into()),
            challenge_bond_forfeited: None,
            version: 1,
        }),
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_901_4,
            1,
            true,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect_err("second approval must fail once task leaves challenged boundary");
    assert!(err.contains("no longer challenged"), "unexpected error: {err}");
    assert!(st.is_emergency_paused());
    assert_eq!(st.pending_resolve_approval(9_901_4), None);
    assert_eq!(st.pending_resolve_first_approver(9_901_4), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_noncanonical_resolve_authority_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency_pause cannot be used to slip malformed
    // authority sets into resolve flow, and any rejection must be side-effect free.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 77_777);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_234);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_120, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let malformed_err = st
        .stage_or_confirm_resolve_approval(
            9_902,
            1,
            true,
            "authority-a",
            "authority-a, authority-b",
        )
        .expect_err("non-canonical authority set must fail closed while paused");
    assert!(malformed_err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_902),
        None,
        "rejected malformed authority set must not stage approvals"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_single_member_resolve_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency_pause cannot degrade resolve approval into
    // a single-party control path. Singleton authority sets must fail closed and keep
    // escrow custody untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_880);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 120);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_125, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let err = st
        .stage_or_confirm_resolve_approval(9_904, 1, true, "authority-a", "authority-a")
        .expect_err("singleton resolve authority set must be rejected while paused");
    assert!(err.contains("at least two members"));

    assert_eq!(
        st.pending_resolve_approval(9_904),
        None,
        "singleton authority set rejection must not stage pending approvals"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn pause_toggle_rejects_wrong_key_id_without_mutating_escrow_or_resolve_state() {
    // M1 merge-gate invariant: emergency_pause has a fixed governance key id boundary.
    // Wrong key-id writes must fail closed and be side-effect free for custody + resolve flow.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_600);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 700);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_130, 7_998, "emergency_pause".into(), "true".into())
        .expect_err("emergency_pause must reject non-canonical key id");
    assert!(err.contains("governance key id mismatch"));
    assert!(!st.is_emergency_paused());

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.pending_resolve_approval(9_903), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn pause_toggle_rejects_non_boolean_value_without_releasing_escrow_or_centralizing_resolve_flow() {
    // M1 merge-gate invariant: emergency_pause is a strict boolean safety boundary.
    // Invalid values must fail closed while preserving custody balances and any staged
    // multi-party resolve approvals.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_900);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 333);

    st.stage_or_confirm_resolve_approval(9_905, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed before malformed pause write");
    assert_eq!(st.pending_resolve_approval(9_905), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_140, 7_999, "emergency_pause".into(), "TRUE".into())
        .expect_err("emergency_pause must reject non-canonical boolean values");
    assert!(err.contains("expected strict bool 'true' or 'false'"));
    assert!(!st.is_emergency_paused());

    assert_eq!(
        st.pending_resolve_approval(9_905),
        Some((true, 1)),
        "invalid pause write must not mutate staged resolve quorum"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_approval_accepts_case_variant_approver_spelling_without_releasing_escrow() {
    // M1 micro-hardening: stored authority-set membership is canonicalized case-insensitively
    // for approver lookup, so an approver spelling variant cannot spuriously fail closed.
    // Custody balances and staged quorum state must still remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 12_345);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 678);

    st.set_gov_param(98_149, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_906,
            1,
            false,
            "Authority-A",
            "authority-a,authority-b",
        )
        .expect("case-variant approver should match configured authority member");
    assert!(!first, "first distinct approver should only stage quorum");
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_906).as_deref(),
        Some("Authority-A"),
        "first approver spelling should be preserved for auditability"
    );

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_approval_rejects_control_or_whitespace_approver_without_mutating_staged_quorum() {
    // M1 micro-hardening: once a quorum stage exists, malformed approver spellings must fail
    // closed without clearing the staged resolve approval or perturbing custody while paused.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 77_700);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 888);

    st.set_gov_param(98_153, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.stage_or_confirm_resolve_approval(9_919, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_919), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_919).as_deref(),
        Some("authority-a")
    );

    for bad_approver in ["authority-b ", "authority-\tb", "authority-b\u{0007}"] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_919,
                1,
                true,
                bad_approver,
                "authority-a,authority-b",
            )
            .expect_err("malformed approver spelling must be rejected while paused");
        assert!(
            err.contains("whitespace") || err.contains("control characters"),
            "unexpected error for {:?}: {}",
            bad_approver,
            err
        );
        assert_eq!(
            st.pending_resolve_approval(9_919),
            Some((true, 1)),
            "rejected malformed approver must preserve staged quorum"
        );
        assert_eq!(
            st.pending_resolve_first_approver(9_919).as_deref(),
            Some("authority-a"),
            "rejected malformed approver must preserve first approver audit trail"
        );
    }

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.is_emergency_paused());
}

#[test]
fn paused_resolve_approval_rejects_delimiter_or_non_ascii_approver_without_mutating_staged_quorum()
{
    // M1 micro-hardening: live resolve approval parsing must reject the same malformed approver
    // spellings that rollback/restore scrubs, so paused mode cannot stage quorum with delimiter
    // smuggling or non-ASCII actor ids.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 66_600);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 333);

    st.set_gov_param(98_154, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.stage_or_confirm_resolve_approval(9_923, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_923), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_923).as_deref(),
        Some("authority-a")
    );

    for bad_approver in ["authority|b", "authority；b", "authority，b", "authorité-b"] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_923,
                1,
                true,
                bad_approver,
                "authority-a,authority-b",
            )
            .expect_err("delimiter/non-ASCII approver must be rejected while paused");
        assert!(
            err.contains("single canonical actor id"),
            "unexpected error for {:?}: {}",
            bad_approver,
            err
        );
        assert_eq!(
            st.pending_resolve_approval(9_923),
            Some((true, 1)),
            "rejected malformed approver must preserve staged quorum"
        );
        assert_eq!(
            st.pending_resolve_first_approver(9_923).as_deref(),
            Some("authority-a"),
            "rejected malformed approver must preserve first approver audit trail"
        );
    }

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.is_emergency_paused());
}

#[test]
fn paused_resolve_approval_keeps_staged_quorum_across_member_reordering() {
    // M1 micro-hardening: a replay that only reorders the same authority members must not
    // clear staged paused resolve quorum or force governance to restart approvals.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_450);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 443);

    st.set_gov_param(98_148, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_905_1,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first approval stage should succeed while paused");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_905_1), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(
            9_905_1,
            1,
            true,
            "authority-b",
            "authority-b,authority-a",
        )
        .expect("member reordering should preserve staged quorum while paused");
    assert!(second, "second distinct approver should finalize quorum");
    assert_eq!(st.pending_resolve_approval(9_905_1), Some((true, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_905_1).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_approval_keeps_staged_quorum_across_case_only_authority_set_drift() {
    // M1 micro-hardening: a replay that only changes authority-set letter case must not
    // erase staged resolve quorum while emergency pause is active.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_500);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 444);

    st.set_gov_param(98_150, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(9_907, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_907), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(9_907, 1, true, "Authority-B", "Authority-A,Authority-B")
        .expect("case-only authority-set drift should preserve staged quorum while paused");
    assert!(second, "second distinct approver should finalize quorum");
    assert_eq!(st.pending_resolve_approval(9_907), Some((true, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_907).as_deref(),
        Some("authority-a"),
        "original first approver audit spelling should remain intact"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_resolve_authority_placeholder_without_side_effects() {
    // M1 micro-hardening: placeholder resolve authority aliases must stay fail-closed
    // under case drift so emergency pause cannot smuggle a deferred placeholder into quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 14_400);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 511);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let placeholder_case_variant = DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER.to_ascii_uppercase();
    let authority_set = format!("authority-a,{placeholder_case_variant}");
    let err = st
        .stage_or_confirm_resolve_approval(9_915, 1, true, "authority-a", &authority_set)
        .expect_err("case-variant placeholder authority must be rejected while paused");
    assert!(err.contains("forbidden member") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_915), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_system_placeholder_approver_without_side_effects() {
    // M1 micro-hardening: emergency pause must not let a system placeholder masquerade as a
    // live resolve approver under case drift. Rejection must remain side-effect free.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 14_880);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 517);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let placeholder_case_variant = DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_917,
            1,
            true,
            &placeholder_case_variant,
            "authority-a,authority-b",
        )
        .expect_err("case-variant system placeholder approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_duplicate_authority_members_without_side_effects() {
    // M1 micro-hardening: duplicate resolve members must stay fail-closed under case drift
    // so emergency pause cannot collapse a nominal 2-of-N approval set into one actor.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 15_050);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 519);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_918, 1, true, "authority-a", "authority-a,Authority-A")
        .expect_err("case-variant duplicate authority members must be rejected while paused");
    assert!(err.contains("duplicate") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_918), None);
    assert_eq!(st.pending_resolve_first_approver(9_918), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_system_member_without_side_effects() {
    // M1 micro-hardening: reserved system authorities remain forbidden under case drift,
    // preventing mixed-case aliases from collapsing multisig resolve control.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 15_500);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 522);

    st.set_gov_param(98_152, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_917,
            1,
            true,
            "authority-a",
            "authority-a,SYSTEM,authority-b",
        )
        .expect_err("reserved system member in middle of authority set must be rejected");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_resolve_first_approver(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_worker_slash_treasury_member_without_side_effects() {
    // M1 micro-hardening: worker slash treasury reservation must stay
    // case-insensitive so mixed-case aliases cannot enter resolve quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_920);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 551);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_worker_slash = WORKER_SLASH_TREASURY_ACCOUNT.to_ascii_uppercase();
    let authority_with_case_variant_worker_slash = format!("authority-a,{mixed_case_worker_slash}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_916,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_worker_slash,
        )
        .expect_err("case-variant worker slash treasury member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_916), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_case_variant_challenge_escrow_treasury_member_without_side_effects() {
    // M1 micro-hardening: the primary challenge escrow account must stay reserved under
    // case drift so paused resolve flow cannot treat custody as a quorum authority member.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_930);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 993);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 553);

    st.set_gov_param(98_212, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeited_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashed_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_challenge_escrow = CHALLENGE_ESCROW_ACCOUNT.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_924,
            1,
            true,
            "authority-a",
            &format!("authority-a,{mixed_case_challenge_escrow}"),
        )
        .expect_err("case-variant challenge escrow treasury member must be rejected while paused");
    assert!(
        err.contains("forbidden member") || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_924), None);
    assert_eq!(st.pending_resolve_first_approver(9_924), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeited_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashed_before);
}

#[test]
fn paused_state_rejects_case_variant_challenge_forfeit_treasury_member_without_side_effects() {
    // M1 micro-hardening: all reserved treasury aliases must stay case-insensitively blocked
    // so paused mode cannot route multi-party resolve approval through custody/system accounts.
    let mut st = StateStore::new();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeited_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashed_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.set_gov_param(98_214, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let mixed_case_forfeit_treasury = CHALLENGE_FORFEIT_TREASURY_ACCOUNT.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_922,
            1,
            true,
            "authority-a",
            &format!("authority-a,{mixed_case_forfeit_treasury}"),
        )
        .expect_err("case-variant challenge forfeit treasury member must be rejected while paused");
    assert!(
        err.contains("forbidden member") || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_922), None);
    assert_eq!(st.pending_resolve_first_approver(9_922), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeited_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashed_before);
}

#[test]
fn paused_state_rejects_post_quorum_resolve_replay_while_paused_without_escrow_drift() {
    // M1 micro-hardening: once a resolve quorum is already finalized, emergency pause must not
    // let replay attempts resurrect or mutate staged resolve approval state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_940);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 994);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 554);

    st.stage_or_confirm_resolve_approval(9_921, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval should stage quorum before pause");
    let finalized = st
        .stage_or_confirm_resolve_approval(9_921, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approval should finalize quorum before pause");
    assert!(finalized);
    assert_eq!(st.pending_resolve_approval(9_921), Some((true, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_921).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(98_213, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let pending_before = st.pending_resolve_approval_snapshot(9_921);

    for (replayed_task_version, replayed_authority_set) in [
        (1, "authority-a,authority-b"),
        (2, "authority-a,authority-b"),
        (1, "authority-a,authority-c"),
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_921,
                replayed_task_version,
                true,
                "authority-b",
                replayed_authority_set,
            )
            .expect_err("post-quorum replay must stay rejected while paused");
        assert!(
            err.contains("already finalized")
                || err.contains("distinct approver")
                || err.contains("configured authority member"),
            "unexpected error for replayed_task_version={replayed_task_version} authority_set={replayed_authority_set}: {err}"
        );

        assert_eq!(st.pending_resolve_approval_snapshot(9_921), pending_before);
        assert_eq!(st.pending_resolve_approval(9_921), Some((true, 2)));
        assert_eq!(
            st.pending_resolve_first_approver(9_921).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.pending_gov_update("resolve_authority"), None);
        assert!(st.is_emergency_paused());
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeits_before
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            worker_slash_before
        );
    }
}

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_approver_without_side_effects() {
    // L03 boundary hardening: the exact canonical emergency_pause placeholder must be rejected
    // on the live paused resolve-approval path too, not only case-drifted aliases or restore.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_929);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 552);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_919,
            1,
            true,
            "governance.emergency_pause",
            "authority-a,authority-b",
        )
        .expect_err("exact emergency_pause placeholder approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_919), None);
    assert_eq!(st.pending_resolve_first_approver(9_919), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_member_without_side_effects() {
    // L03 boundary hardening: the exact canonical emergency_pause placeholder must be rejected
    // when it appears inside the live paused authority set too, not only case-drifted aliases.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_929);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 552);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_920,
            1,
            true,
            "authority-a",
            "authority-a,governance.emergency_pause",
        )
        .expect_err("exact emergency_pause placeholder member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_920), None);
    assert_eq!(st.pending_resolve_first_approver(9_920), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_second_approver_without_clearing_staged_quorum(
) {
    // L03 boundary hardening: once one paused resolve approval is already staged, the exact
    // emergency_pause placeholder must still be rejected as the second approver without
    // clearing the valid staged quorum or perturbing custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_931);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 994);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 554);

    st.set_gov_param(98_213, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_921, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first paused approval should stage quorum before malformed second approver");
    assert_eq!(st.pending_resolve_approval(9_921), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_921).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(
            9_921,
            1,
            true,
            "governance.emergency_pause",
            "authority-a,authority-b",
        )
        .expect_err(
            "exact emergency_pause placeholder second approver must be rejected while paused",
        );
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(
        st.pending_resolve_approval(9_921),
        Some((true, 1)),
        "rejecting malformed second approver must preserve staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_921).as_deref(),
        Some("authority-a"),
        "rejecting malformed second approver must preserve first-approver audit trail"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_921)
            .expect("staged quorum must remain after malformed second approver rejection")
            .confirmations,
        1,
        "rejecting malformed second approver must not fabricate a finalized quorum"
    );
    assert_eq!(st.state_root(), root_before);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_bare_emergency_pause_alias_approver_without_side_effects() {
    // L03 boundary hardening: the bare emergency_pause control-plane alias must stay reserved
    // on the live paused resolve-approval path too, not only the governance-prefixed placeholder.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_932);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 995);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 555);

    st.set_gov_param(98_214, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_922, 1, true, "Emergency_Pause", "authority-a,authority-b")
        .expect_err("bare emergency_pause alias approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_922), None);
    assert_eq!(st.pending_resolve_first_approver(9_922), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_bare_emergency_pause_alias_member_without_side_effects() {
    // L03 boundary hardening: the bare emergency_pause control-plane alias must stay reserved
    // when it appears inside the live paused authority set, not only the governance-prefixed placeholder.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_933);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 996);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 556);

    st.set_gov_param(98_215, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_923,
            1,
            true,
            "authority-a",
            "authority-a,Emergency_Pause",
        )
        .expect_err("bare emergency_pause alias member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_923), None);
    assert_eq!(st.pending_resolve_first_approver(9_923), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_case_variant_emergency_pause_placeholder_member_without_side_effects() {
    // M1 micro-hardening: resolve quorum parsing must keep the emergency pause placeholder
    // reserved under case drift, so paused mode cannot smuggle control-plane aliases into
    // multi-party resolve approval.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_930);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 993);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 553);

    st.set_gov_param(98_212, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_pause_placeholder = "Governance.Emergency_Pause";
    let authority_with_case_variant_pause_placeholder =
        format!("authority-a,{mixed_case_pause_placeholder}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_920,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_pause_placeholder,
        )
        .expect_err(
            "case-variant emergency_pause placeholder member must be rejected while paused",
        );
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_920), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_oversized_resolve_authority_set_without_side_effects() {
    // M1 micro-hardening: paused resolve approval must enforce the same authority-set length
    // boundary as governance storage so oversized authority payloads cannot stage quorum state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_021);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_003);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 503);

    st.set_gov_param(98_217, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let oversized_authority_set = format!("authority-a,{}", "b".repeat(117));
    assert!(oversized_authority_set.len() > 128);

    let err = st
        .stage_or_confirm_resolve_approval(9_928, 1, true, "authority-a", &oversized_authority_set)
        .expect_err("oversized paused resolve authority set must be rejected");
    assert!(
        err.contains("max length") || err.contains("authority set"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_928), None);
    assert_eq!(st.pending_resolve_first_approver(9_928), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_authority_set_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub oversized authority-set snapshots
    // so resolve quorum state cannot bypass the canonical governance length boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_022);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_004);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 504);

    st.set_gov_param(98_218, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let oversized_authority_set = format!("authority-a,{}", "b".repeat(117));
    assert!(oversized_authority_set.len() > 128);

    st.restore_pending_resolve_approval(
        9_929,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: oversized_authority_set,
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_929), None);
    assert_eq!(st.pending_resolve_first_approver(9_929), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_929), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_authority_set_drift_from_configured_governance_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must not revive a pending resolve quorum whose
    // authority set no longer matches the configured resolve_authority governance boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_023);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_005);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 505);

    let bootstrap = st
        .set_gov_param(
            98_218,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_238,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_239, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_929,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-c".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_929), None);
    assert_eq!(st.pending_resolve_first_approver(9_929), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_929), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured governance resolve_authority must remain unchanged"
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_stale_configured_authority_when_pending_replacement_exists(
) {
    // M1 boundary hardening: when a replacement resolve_authority set is already timelocked,
    // paused rollback/restore must fail closed against snapshots that still target the stale
    // configured quorum rather than reviving approvals that would cross the pending boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_024);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_006);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 506);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_930,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_930), None);
    assert_eq!(st.pending_resolve_first_approver(9_930), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_930), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured governance resolve_authority should remain unchanged until the replacement timelock matures"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_accepts_case_and_order_equivalent_governance_authority(
) {
    // M1 micro-hardening: paused rollback/restore must accept semantically identical
    // resolve-authority sets even if snapshot spelling differs by case or member order,
    // otherwise benign replay/restore drift would spuriously erase a valid staged quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_024);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_006);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 506);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_261, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_930,
        Some(TaskObject {
            task_id: 9_930,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_930,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Authority-B".into(),
            authority_set: "Authority-B,Authority-A".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_930), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_930).as_deref(),
        Some("Authority-B"),
        "restore should preserve approver audit spelling while accepting equivalent authority-set semantics"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_930)
            .expect("equivalent snapshot should survive paused restore")
            .authority_set,
        "Authority-B,Authority-A"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into())
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_pending_replacement_resolve_approval_accepts_case_and_order_equivalent_authority_set(
) {
    // L03 boundary hardening: while paused, live resolve approvals must accept authority sets
    // that semantically match a pending resolve_authority replacement even if callers replay
    // the same members with different case or order. Benign representation drift must not
    // force governance to restart quorum staging or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_026);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_932,
            4,
            false,
            "Authority-D",
            "Authority-D,Authority-C",
        )
        .expect("case/order-equivalent pending replacement authority should stage while paused");
    assert!(!first, "single approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_932), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_932).as_deref(),
        Some("Authority-D"),
        "live staging should preserve original approver spelling for auditability"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
}

#[test]
fn paused_state_pending_replacement_resolve_approval_finalizes_with_case_and_order_equivalent_authority_set(
) {
    // L03 boundary hardening: once one paused approval is already staged against a pending
    // resolve_authority replacement, the second distinct approval must still finalize when the
    // caller replays the same pending authority members with case/order-only drift.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_027);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_933,
            4,
            false,
            "Authority-D",
            "Authority-D,Authority-C",
        )
        .expect("first approval should stage against pending replacement authority");
    assert!(!first, "first distinct approver should only stage paused quorum");
    let root_after_first = st.state_root();

    let second = st
        .stage_or_confirm_resolve_approval(
            9_933,
            4,
            false,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("second approval should finalize against equivalent pending replacement authority");
    assert!(second, "second distinct approver should finalize paused quorum");
    assert_eq!(st.pending_resolve_approval(9_933), Some((false, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_933).as_deref(),
        Some("Authority-D"),
        "finalization must preserve the original first approver spelling for auditability"
    );
    assert_ne!(
        st.state_root(),
        root_after_first,
        "second distinct paused approval should advance the staged quorum state root"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_accepts_case_and_order_equivalent_pending_replacement_authority(
) {
    // L03 boundary hardening: once a replacement resolve_authority set is already timelocked,
    // paused rollback/restore must still accept snapshots that semantically match that pending
    // boundary under case/order drift instead of scrubbing a valid staged quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_025);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_931,
        Some(TaskObject {
            task_id: 9_931,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 3,
        }),
    );

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "Authority-D".into(),
            authority_set: "Authority-D,Authority-C".into(),
            task_version: 3,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_931), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_931).as_deref(),
        Some("Authority-D"),
        "restore should preserve approver audit spelling while accepting equivalent pending replacement authority semantics"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_931)
            .expect("equivalent pending replacement snapshot should survive paused restore")
            .authority_set,
        "Authority-D,Authority-C"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured governance resolve_authority should remain unchanged until the replacement timelock matures"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_pending_replacement_live_rejects_exact_emergency_pause_placeholder_second_approver_without_clearing_staged_quorum(
) {
    // L03 boundary hardening: when a replacement resolve_authority set is already timelocked,
    // the live paused approval path must still reject the exact emergency_pause placeholder as
    // a second approver, while preserving the valid staged quorum, pending timelock boundary,
    // and custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_028);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 510);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_936,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("first approval should stage against pending replacement authority");
    assert!(!staged, "single approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_936), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_936).as_deref(),
        Some("authority-c")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(
            9_936,
            4,
            true,
            "governance.emergency_pause",
            "authority-c,authority-d",
        )
        .expect_err(
            "exact emergency_pause placeholder second approver must be rejected against pending replacement authority",
        );
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(
        st.pending_resolve_approval(9_936),
        Some((true, 1)),
        "rejecting malformed second approver must preserve staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_936).as_deref(),
        Some("authority-c"),
        "rejecting malformed second approver must preserve first-approver audit trail"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_936)
            .expect("staged quorum must remain after malformed second approver rejection")
            .confirmations,
        1,
        "rejecting malformed second approver must not fabricate a finalized quorum"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(st.state_root(), root_before);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
}

#[test]
fn paused_state_pending_replacement_restore_scrubs_exact_emergency_pause_placeholder_second_approver_without_touching_pending_timelock(
) {
    // L03 boundary hardening: when a replacement resolve_authority set is already timelocked,
    // paused rollback/restore must still scrub finalized quorum snapshots that smuggle the exact
    // emergency_pause placeholder into the second-approver slot, while preserving the staged
    // governance boundary and custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_028);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 510);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_936,
        Some(TaskObject {
            task_id: 9_936,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 4,
        }),
    );

    let root_before = st.state_root();

    st.restore_pending_resolve_approval(
        9_936,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-c".into(),
            authority_set: "authority-c,authority-d".into(),
            task_version: 4,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_936), None);
    assert_eq!(st.pending_resolve_first_approver(9_936), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_936), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured authority must remain unchanged until the pending replacement matures"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
    assert_eq!(
        st.state_root(),
        root_before,
        "restoring a finalized paused pending-replacement quorum without an encoded second approver must scrub and leave state unchanged"
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_emergency_pause_placeholder_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject control-plane
    // emergency_pause placeholder aliases when they appear as the first approver itself,
    // not only inside authority-set membership or second-approver slots.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_019);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_005);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 505);

    let bootstrap = st
        .set_gov_param(
            98_219,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_239,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_240, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_926,
        Some(TaskObject {
            task_id: 9_926,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_926,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Governance.Emergency_Pause".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_926),
        None,
        "paused restore must scrub emergency_pause placeholder approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_926), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_926), None);
    assert_eq!(st.gov_param_string("resolve_authority"), Some("authority-a,authority-b".into()));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_zero_task_version_boundary() {
    // M1 micro-hardening: paused rollback/restore must reject versionless pending resolve
    // snapshots so governance/resolve flow cannot revive an unversioned approval quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_020);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_002);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 502);

    st.set_gov_param(98_216, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_926, 0, true, "authority-a", "authority-a,authority-b")
        .expect_err("paused live resolve approval must reject zero task version");
    assert!(err.contains("task version"), "unexpected error: {err}");
    assert_eq!(st.pending_resolve_approval(9_926), None);
    assert_eq!(st.pending_resolve_first_approver(9_926), None);

    st.restore_pending_resolve_approval(
        9_927,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 0,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_927),
        None,
        "paused restore must scrub zero-version pending resolve snapshot"
    );
    assert_eq!(st.pending_resolve_first_approver(9_927), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_927), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_member() {
    // M1 micro-hardening: rollback/restore must scrub malformed pending resolve snapshots even
    // while paused, so control-plane placeholder aliases cannot be revived into paused quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_010);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_001);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 501);

    st.set_gov_param(98_215, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_925,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,Governance.Emergency_Pause".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_925),
        None,
        "paused restore must scrub placeholder-tainted pending resolve snapshot"
    );
    assert_eq!(st.pending_resolve_first_approver(9_925), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_925), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_reserved_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject case-variant reserved
    // custody/system aliases when they appear as the first approver itself, not only inside
    // the authority-set membership list.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_030);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_006);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 506);

    st.set_gov_param(98_219, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_930,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Treasury.Challenge_Escrow".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_930),
        None,
        "paused restore must scrub reserved approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_930), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_930), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_approver() {
    // M1 micro-hardening: paused rollback/restore must reject control-plane placeholder aliases
    // when they appear as the first approver itself, not only inside the authority-set list.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_040);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    st.set_gov_param(98_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Governance.Resolve_Authority".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_931),
        None,
        "paused restore must scrub placeholder approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_931), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_931), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_reserved_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject malformed finalized
    // quorum snapshots when the second approver is a reserved custody/system alias under
    // case drift, so 2-of-N resolve history cannot be revived with a forbidden signer.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_932,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_932),
        None,
        "paused restore must scrub reserved second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_932), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is a mixed-case control-plane placeholder alias, so restore
    // cannot revive a forbidden signer into 2-of-N resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_108);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 608);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_934,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_934),
        None,
        "paused restore must scrub placeholder second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_934), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_934), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_exact_placeholder_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is the exact canonical resolve_authority placeholder, not only
    // a case-drifted alias.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_091);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_133);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 633);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_934,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_934),
        None,
        "paused restore must scrub exact placeholder second approver aliases"
    );
    assert_eq!(st.pending_resolve_first_approver(9_934), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_934), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_emergency_pause_placeholder_second_approver(
) {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is a mixed-case emergency_pause control-plane placeholder, so
    // restore cannot revive a forbidden signer into 2-of-N resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_158);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 658);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_935,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_935),
        None,
        "paused restore must scrub emergency_pause placeholder second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_935), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_935), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_exact_emergency_pause_placeholder_approver_slots(
) {
    // M1 micro-hardening: paused rollback/restore must also reject the exact canonical
    // emergency_pause control-plane placeholder when it appears in either approver slot,
    // not only case-drifted aliases.
    for (task_id, confirmations, first_approver, _second_approver) in [
        (9_935, 1, "governance.emergency_pause", None),
        (9_936, 2, "authority-a", Some("governance.emergency_pause")),
    ] {
        let mut st = StateStore::new();
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_142);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_159);
        st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 659);

        st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        st.restore_pending_resolve_approval(
            task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations,
                first_approver: first_approver.into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 1,
            }),
        );

        assert_eq!(
            st.pending_resolve_approval(task_id),
            None,
            "paused restore must scrub exact emergency_pause placeholder approver slots"
        );
        assert_eq!(st.pending_resolve_first_approver(task_id), None);
        assert_eq!(st.pending_resolve_approval_snapshot(task_id), None);
        assert_eq!(st.pending_gov_update("resolve_authority"), None);
        assert!(st.is_emergency_paused());
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeits_before
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            worker_slash_before
        );
    }
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_duplicate_second_approver_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must reject finalized quorum snapshots when
    // the second approver is only a case-variant replay of the first approver, so restore
    // cannot resurrect a nominal 2-of-N resolve history that actually collapses to one actor.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_140);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_157);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 657);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_936,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_936),
        None,
        "paused restore must scrub duplicate second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_936), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_936), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_delimiter_or_non_ascii_second_approver_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must scrub finalized quorum snapshots when
    // the second approver uses delimiter smuggling or non-ASCII spellings, so malformed 2-of-N
    // resolve history cannot be revived through restore.
    for (task_id, _malformed_second_approver) in [
        (9_936, "authority|b"),
        (9_937, "authority；b"),
        (9_938, "authority，b"),
        (9_939, "authorité-b"),
    ] {
        let mut st = StateStore::new();
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_208);
        st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 708);

        st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        st.restore_pending_resolve_approval(
            task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 1,
            }),
        );

        assert_eq!(
            st.pending_resolve_approval(task_id),
            None,
            "paused restore must scrub malformed finalized second approver ids"
        );
        assert_eq!(st.pending_resolve_first_approver(task_id), None);
        assert_eq!(st.pending_resolve_approval_snapshot(task_id), None);
        assert_eq!(st.pending_gov_update("resolve_authority"), None);
        assert!(st.is_emergency_paused());
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeits_before
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            worker_slash_before
        );
    }
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_second_approver_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub finalized quorum snapshots when
    // the second approver breaches the canonical actor-id length boundary, so malformed 2-of-N
    // approvals cannot be revived into paused resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_208);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 708);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let _oversized_second_approver = "b".repeat(129);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_935,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_935),
        None,
        "paused restore must scrub oversized finalized second approver ids"
    );
    assert_eq!(st.pending_resolve_first_approver(9_935), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_935), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_zero_task_id_resolve_approval_without_side_effects() {
    // M1 micro-hardening: paused resolve flow must reject task-id zero so malformed governance
    // or replay envelopes cannot stage quorum state outside the real challenged-task boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_040);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    st.set_gov_param(98_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(0, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("task-id zero must be rejected while paused");
    assert!(
        err.contains("task id must be >= 1"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(0), None);
    assert_eq!(st.pending_resolve_first_approver(0), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_missing_task_boundary() {
    // M1 micro-hardening: paused rollback/restore must not revive pending resolve quorum for a
    // task slot with no live challenged task object, preserving object-scoped state semantics.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_044);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_011);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 511);

    st.set_gov_param(98_224, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    st.restore_pending_resolve_approval(
        9_901,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_901), None);
    assert_eq!(st.pending_resolve_first_approver(9_901), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_901), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "scrubbing missing-task restore input must not perturb paused custody or quorum state"
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_zero_task_id_boundary() {
    // M1 micro-hardening: paused rollback/restore must also fail closed on task-id zero so
    // malformed snapshots cannot revive pending resolve quorum outside a real challenged task.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_043);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 510);

    st.set_gov_param(98_223, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    st.restore_pending_resolve_approval(
        0,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(0), None);
    assert_eq!(st.pending_resolve_first_approver(0), None);
    assert_eq!(st.pending_resolve_approval_snapshot(0), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "scrubbing zero-task restore input must not perturb paused custody or quorum state"
    );
}

#[test]
fn paused_state_rejects_oversized_resolve_approver_without_side_effects() {
    // M1 micro-hardening: paused live resolve approval must enforce a canonical approver-id
    // length boundary so oversized actor ids cannot stage quorum or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_approver = "a".repeat(129);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_932,
            1,
            true,
            &oversized_approver,
            "authority-a,authority-b",
        )
        .expect_err("oversized paused resolve approver must be rejected");
    assert!(
        err.contains("max length") || err.contains("approver"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_rejects_oversized_resolve_authority_member_without_side_effects() {
    // M1 micro-hardening: paused live resolve approval must reject oversized authority-set
    // members just like oversized approvers, so malformed quorum members cannot stage pending
    // resolve state or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_042);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    st.set_gov_param(98_222, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_member = "a".repeat(129);
    let authority_set = format!("authority-a,{}", oversized_member);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_933, 1, true, "authority-a", &authority_set)
        .expect_err("oversized paused resolve authority member must be rejected");
    assert!(
        err.contains("authority set") || err.contains("forbidden member"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_933), None);
    assert_eq!(st.pending_resolve_first_approver(9_933), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_933), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_authority_member_boundary() {
    // M1 micro-hardening: paused rollback/restore must reject oversized authority-set members
    // just like live resolve approval staging, so malformed quorum members cannot bypass the
    // per-member actor-length boundary through snapshot restore.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_member = "a".repeat(129);
    let authority_set = format!("authority-a,{}", oversized_member);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_932,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set,
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_932), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_approver_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub oversized approver ids so
    // malformed quorum snapshots cannot bypass live approver-size validation.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_042);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    st.set_gov_param(98_222, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_approver = "a".repeat(129);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_933,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: oversized_approver,
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_933), None);
    assert_eq!(st.pending_resolve_first_approver(9_933), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_933), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn first_resolve_approval_rejects_non_challenged_task_boundary() {
    // L03 boundary hardening: the first resolve approval must stay bound to challenged-state
    // semantics and reject open tasks before any quorum state is staged.
    let mut st = StateStore::new();
    st.set_gov_param(98_361, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_381, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");
    st.put_task_new(TaskObject {
        task_id: 9_941,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    })
    .expect("open task should exist before resolve-approval attempt");

    let err = st
        .stage_or_confirm_resolve_approval(
            9_941,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect_err("non-challenged task must reject the first resolve approval");

    assert!(
        err.contains("no longer challenged"),
        "unexpected error: {err}"
    );
    assert_eq!(st.pending_resolve_approval(9_941), None);
    assert_eq!(st.pending_resolve_first_approver(9_941), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_941), None);
}
