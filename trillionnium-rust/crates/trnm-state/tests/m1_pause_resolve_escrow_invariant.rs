use trnm_state::{
    GovParamUpdateOutcome, GovPendingUpdateAction, PendingResolveApprovalSnapshot, StateStore,
};

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
    assert_eq!(pending_after.activate_at_height, pending_before.activate_at_height);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature cancel rejection must not change currently applied authority set"
    );
    assert!(st.is_emergency_paused(), "mature cancel rejection must not unpause state");
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
    assert_eq!(pending_after.activate_at_height, pending_before.activate_at_height);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature replace rejection must not change currently applied authority set"
    );
    assert!(st.is_emergency_paused(), "mature replace rejection must not unpause state");
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
        .stage_or_confirm_resolve_approval(9_901_1, 1, true, "authority-a", "authority-a,authority-b")
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
        .stage_or_confirm_resolve_approval(9_901_1, 1, true, "authority-c", "authority-a,authority-c")
        .expect_err("paused authority rotation must fail closed and clear stale staged approval");
    assert!(rotated_err.contains("authority set changed"), "unexpected error: {rotated_err}");
    assert!(st.is_emergency_paused(), "authority rotation failure must not unpause state");
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
    assert!(st.is_emergency_paused(), "decision mismatch must not unpause state");
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
    assert!(err.contains("max length") || err.contains("authority set"), "unexpected error: {err}");

    assert_eq!(st.pending_resolve_approval(9_928), None);
    assert_eq!(st.pending_resolve_first_approver(9_928), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: None,
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: None,
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: None,
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
            second_approver: None,
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: None,
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: Some("Treasury.Worker_Slash".into()),
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
    assert!(err.contains("max length") || err.contains("approver"), "unexpected error: {err}");

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
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
            second_approver: None,
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
}
