use trnm_state::{GovParamUpdateOutcome, StateStore};

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";

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
