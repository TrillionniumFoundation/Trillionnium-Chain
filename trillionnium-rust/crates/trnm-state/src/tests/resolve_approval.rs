use super::*;

#[test]
fn resolve_approval_requires_two_distinct_approvers_before_ready() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first, "single approver must not finalize resolve approval");
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("same approver must not satisfy multi-party confirmation");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(
        second,
        "second distinct approver must finalize resolve approval"
    );
    assert_eq!(st.pending_resolve_approval(42), Some((true, 2)));

    st.clear_pending_resolve_approval(42);
    assert!(st.pending_resolve_approval(42).is_none());
}

#[test]
fn resolve_approval_rejects_decision_mismatch_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(7, 1, false, "authority-a", "authority-a,authority-b")
        .expect("initial non-slash approval should stage");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(7), Some((false, 1)));

    let mismatch = st
        .stage_or_confirm_resolve_approval(7, 1, true, "authority-b", "authority-a,authority-b")
        .expect_err("mismatched slash decision must fail closed");
    assert!(mismatch.contains("decision mismatch"));
    assert_eq!(
        st.pending_resolve_approval(7),
        Some((false, 1)),
        "decision mismatch must not mutate staged confirmation"
    );
}

#[test]
fn resolve_approval_rejects_post_quorum_replay_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);

    let second = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(second);
    assert_eq!(st.pending_resolve_approval(88), Some((true, 2)));

    let replay_err = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-c", "authority-a,authority-b")
        .expect_err("post-quorum replay must be rejected");
    assert!(
        replay_err.contains("already finalized")
            || replay_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(88),
        Some((true, 2)),
        "post-quorum replay must not mutate confirmation state"
    );
}

#[test]
fn resolve_approval_rejects_case_drift_duplicate_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(77, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(77), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(77, 1, true, "Authority-A", "authority-a,authority-b")
        .expect_err("case-drift duplicate approver must be rejected");
    assert!(
        dup_err.contains("distinct approver") || dup_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(77),
        Some((true, 1)),
        "case-drift duplicate must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_whitespace_drift_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(78, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(78), Some((true, 1)));

    let whitespace_err = st
        .stage_or_confirm_resolve_approval(78, 1, true, " authority-a ", "authority-a,authority-b")
        .expect_err("whitespace-drift approver must be rejected");
    assert!(whitespace_err.contains("must not contain whitespace"));
    assert_eq!(
        st.pending_resolve_approval(78),
        Some((true, 1)),
        "whitespace-drift approver must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_multiactor_delimited_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(79, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(79), Some((true, 1)));

    for bad_actor in ["authority-a,authority-b", "authority-a;authority-b"] {
        let err = st
            .stage_or_confirm_resolve_approval(79, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("delimited approver id must be rejected");
        assert!(err.contains("single canonical actor id"));
        assert_eq!(
            st.pending_resolve_approval(79),
            Some((true, 1)),
            "invalid approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn resolve_approval_rejects_system_or_treasury_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(80, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(80), Some((true, 1)));

    for bad_actor in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "System",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Forfeits",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(80, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("system/treasury approver must be rejected");
        assert!(err.contains("explicit non-system authority"));
        assert_eq!(
            st.pending_resolve_approval(80),
            Some((true, 1)),
            "reserved approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn resolve_approval_rejects_noncanonical_authority_set_without_mutation() {
    let mut st = StateStore::new();

    for malformed_set in [
        "authority-a",
        "authority-a,",
        "authority-a, authority-b",
        "authority-a;authority-b",
        "authority-a,AUTHORITY-A",
        "authority-a,system",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(8_882, 1, true, "authority-a", malformed_set)
            .expect_err("non-canonical authority set must fail closed");
        assert!(
            err.contains("authority set"),
            "unexpected error for malformed set {malformed_set}: {err}"
        );
        assert_eq!(
            st.pending_resolve_approval(8_882),
            None,
            "malformed authority set must not stage pending approvals"
        );
    }
}

#[test]
fn resolve_approval_clears_stale_stage_on_task_version_change() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(82, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(82), Some((true, 1)));

    let version_err = st
        .stage_or_confirm_resolve_approval(82, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task version change must fail closed and clear stale stage");
    assert!(version_err.contains("task version changed"));
    assert_eq!(st.pending_resolve_approval(82), None);
    assert_eq!(st.pending_resolve_first_approver(82), None);
}

#[test]
fn resolve_approval_task_version_mismatch_invalidates_cached_state_root() {
    let mut st = StateStore::new();

    st.stage_or_confirm_resolve_approval(8_283, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");

    let root_with_pending = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(8_283, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task-version mismatch should clear staged approval");
    assert!(err.contains("task version changed"));

    let root_after_clear = st.state_root();

    let baseline = StateStore::new().state_root();
    assert_eq!(st.pending_resolve_approval(8_283), None);
    assert_ne!(
        root_with_pending, root_after_clear,
        "clearing stale pending resolve approval must invalidate cached state root"
    );
    assert_eq!(
        root_after_clear, baseline,
        "after stale-stage clear, state root should match an empty store"
    );
}

#[test]
fn resolve_approval_clears_stale_stage_on_authority_set_rotation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(81), Some((true, 1)));

    let rotated_err = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-c", "authority-a,authority-c")
        .expect_err("authority set rotation must fail closed and clear stale stage");
    assert!(rotated_err.contains("authority set changed"));
    assert_eq!(st.pending_resolve_approval(81), None);
    assert_eq!(st.pending_resolve_first_approver(81), None);
}

#[test]
fn resolve_approval_preserves_staged_quorum_on_authority_set_case_drift() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(8_181), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "Authority-B", "authority-a,Authority-B")
        .expect("authority set case drift should preserve staged quorum");
    assert!(second, "second distinct approver should finalize quorum");
    assert_eq!(st.pending_resolve_approval(8_181), Some((true, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(8_181).as_deref(),
        Some("authority-a")
    );
}
