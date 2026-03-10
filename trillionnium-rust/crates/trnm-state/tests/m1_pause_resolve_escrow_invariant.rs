use trnm_state::{GovParamUpdateOutcome, StateStore};

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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
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
        .stage_or_confirm_resolve_approval(
            9_901,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first approval stage should succeed while paused");
    assert!(
        !first,
        "single approver must not finalize resolve approval while paused"
    );
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(
            9_901,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect_err("same approver must still be rejected while paused");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(
            9_901,
            true,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect("second distinct approver should finalize while paused");
    assert!(second, "second distinct approver must finalize");
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 2)));

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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
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
        .stage_or_confirm_resolve_approval(9_904, true, "authority-a", "authority-a")
        .expect_err("singleton resolve authority set must be rejected while paused");
    assert!(err.contains("at least two members"));

    assert_eq!(
        st.pending_resolve_approval(9_904),
        None,
        "singleton authority set rejection must not stage pending approvals"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn pause_toggle_rejects_non_boolean_value_without_releasing_escrow_or_centralizing_resolve_flow() {
    // M1 merge-gate invariant: emergency_pause is a strict boolean safety boundary.
    // Invalid values must fail closed while preserving custody balances and any staged
    // multi-party resolve approvals.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_900);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 333);

    st.stage_or_confirm_resolve_approval(9_905, true, "authority-a", "authority-a,authority-b")
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
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_unpause_rejects_noncanonical_key_id_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: emergency pause exit path must keep canonical key-id guard.
    // A wrong-key unpause attempt must fail closed: pause state, escrow custody, and
    // staged multi-party resolve approvals remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 12_345);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 678);

    st.set_gov_param(98_150, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_906, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_151, 7_998, "emergency_pause".into(), "false".into())
        .expect_err("unpause must reject non-canonical emergency_pause key id");
    assert!(err.contains("governance key id mismatch"));

    assert!(
        st.is_emergency_paused(),
        "wrong-key unpause must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_authority_set_flip_mid_quorum_without_escrow_side_effects() {
    // M1 merge-gate invariant: under emergency pause, resolve quorum remains multi-party
    // and bound to a stable authority set. Mid-flight authority-set flips must fail closed
    // and keep custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_500);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 444);

    st.set_gov_param(98_160, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_907, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_907), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_907, true, "authority-c", "authority-a,authority-c")
        .expect_err("authority-set flip must fail closed and reset stale quorum entry");
    assert!(err.contains("authority set changed"));

    assert_eq!(
        st.pending_resolve_approval(9_907),
        None,
        "authority-set flip rejection must clear stale pending approval"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_unpause_rejects_noncanonical_bool_literal_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: emergency pause exit must enforce strict bool parsing.
    // A malformed unpause value must fail closed: paused state, escrow custody, and
    // staged multi-party resolve approvals remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 4_242);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 242);

    st.set_gov_param(98_170, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_908, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_908), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_171, 7_999, "emergency_pause".into(), "False".into())
        .expect_err("unpause must reject non-canonical bool literals");
    assert!(err.contains("expected strict bool 'true' or 'false'"));

    assert!(
        st.is_emergency_paused(),
        "malformed unpause value must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_908), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_unpause_wrong_key_id_precedes_bool_validation_and_preserves_quorum_and_escrow() {
    // M1 merge-gate invariant: emergency pause key-id boundary must fail closed before
    // value-schema checks, so malformed wrong-key unpause attempts cannot clear pause,
    // mutate staged multi-party quorum, or move escrow custody.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 5_050);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 505);

    st.set_gov_param(98_180, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_909, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_909), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_181, 8_000, "emergency_pause".into(), "False".into())
        .expect_err("wrong-key unpause attempt must reject before bool validation");
    assert!(
        err.contains("key id") && err.contains("7999"),
        "wrong-key path must reject on canonical key boundary first: {err}"
    );

    assert!(
        st.is_emergency_paused(),
        "wrong-key malformed unpause must keep pause state unchanged"
    );
    assert_eq!(st.pending_resolve_approval(9_909), Some((true, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_unpause_rejects_whitespace_bool_literal_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: pause exit must use canonical strict bool values.
    // Whitespace-smuggled bool payloads must fail closed and preserve escrow + quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_060);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 606);

    st.set_gov_param(98_190, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_910, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_910), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_191, 7_999, "emergency_pause".into(), "false ".into())
        .expect_err("whitespace bool literal must be rejected on unpause path");
    assert!(err.contains("expected strict bool 'true' or 'false'"));

    assert!(
        st.is_emergency_paused(),
        "whitespace bool unpause must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_910), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_forfeit_treasury_member_authority_set_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow custody accounts to enter
    // resolve authority quorum. A forfeit-treasury member in the authority set must fail
    // closed and preserve escrow + treasury balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_060);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 909);

    st.set_gov_param(98_190, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let authority_with_forfeits = format!("authority-a,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(9_910, true, "authority-a", &authority_with_forfeits)
        .expect_err("forfeit treasury account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_910),
        None,
        "rejected authority set must not stage approvals"
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_worker_slash_treasury_member_authority_set_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow slash treasury custody
    // accounts to join resolve authority quorum. Rejection must remain fail-closed and
    // preserve escrow + custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_160);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 777);

    st.set_gov_param(98_192, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let authority_with_worker_slash = format!("authority-a,{}", WORKER_SLASH_TREASURY_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(9_911, true, "authority-a", &authority_with_worker_slash)
        .expect_err("worker slash treasury account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_911),
        None,
        "rejected authority set must not stage approvals"
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), worker_slash_before);
}

#[test]
fn paused_state_rejects_challenge_escrow_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: custody escrow account must never join resolve
    // authority quorum, even while emergency pause is active.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 7_170);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 717);

    st.set_gov_param(98_193, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let authority_with_escrow = format!("authority-a,{}", CHALLENGE_ESCROW_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(9_912, true, "authority-a", &authority_with_escrow)
        .expect_err("escrow account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_912), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_reserved_system_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow reserved control-plane
    // identities (e.g., system actor) to enter resolve quorum. Rejection must remain
    // fail-closed and preserve custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 7_270);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 727);

    st.set_gov_param(98_194, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_913, true, "authority-a", "authority-a,system")
        .expect_err("reserved system member in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_913), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_challenge_escrow_as_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow the custody escrow account
    // to become the sole resolver authority (single-party + self-custody collapse).
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_180);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 818);

    st.set_gov_param(98_194, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_913, true, CHALLENGE_ESCROW_ACCOUNT, CHALLENGE_ESCROW_ACCOUNT)
        .expect_err("escrow singleton authority must be rejected while paused");
    assert!(
        err.contains("reserved")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("invalid governance value")
            || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_913), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_reserved_system_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow reserved control-plane
    // identities to become the sole resolve authority.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_280);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 828);

    st.set_gov_param(98_195, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_914, true, "system", "system")
        .expect_err("reserved system singleton authority must be rejected while paused");
    assert!(
        err.contains("reserved")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("explicit non-system authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_914), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_placeholder_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: pause must not permit the default placeholder
    // authority identity to stage resolve approvals or touch custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_380);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 838);

    st.set_gov_param(98_196, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_915,
            true,
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        )
        .expect_err("placeholder singleton authority must be rejected while paused");
    assert!(
        err.contains("placeholder")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("explicit non-system authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_915), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}

#[test]
fn paused_state_rejects_duplicate_multisig_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow a single signer to
    // masquerade as multi-party resolve authority via duplicate members.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_480);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 848);

    st.set_gov_param(98_197, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_916, true, "authority-a", "authority-a,authority-a")
        .expect_err("duplicate multisig members must be rejected while paused");
    assert!(
        err.contains("duplicate")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_916), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), forfeits_before);
}
