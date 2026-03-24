use super::*;

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
    assert!(
        err.contains("no longer challenged"),
        "unexpected error: {err}"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.pending_resolve_approval(9_901_4), None);
    assert_eq!(st.pending_resolve_first_approver(9_901_4), None);
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
fn first_resolve_approval_rejects_non_challenged_task_boundary() {
    // L03 boundary hardening: the first resolve approval must stay bound to challenged-state
    // semantics and reject open tasks before any quorum state is staged.
    let mut st = StateStore::new();
    st.set_gov_param(
        98_361,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(
        98_381,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
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
        .stage_or_confirm_resolve_approval(9_941, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("non-challenged task must reject the first resolve approval");

    assert!(
        err.contains("no longer challenged"),
        "unexpected error: {err}"
    );
    assert_eq!(st.pending_resolve_approval(9_941), None);
    assert_eq!(st.pending_resolve_first_approver(9_941), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_941), None);
}
