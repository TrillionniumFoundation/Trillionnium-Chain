use super::*;

#[test]
fn treasury_balance_address_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    st1.set_balance("treasury.ab", 11);
    st2.set_balance("treasury.a", 11);
    st2.set_balance("b", 0);

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "state_root should length-frame treasury balance addresses so distinct address boundaries cannot hash identically"
    );
}
#[test]
fn treasury_balances_and_monetary_counters_should_affect_state_root_even_when_net_issuance_matches()
{
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    for st in [&mut st1, &mut st2] {
        st.set_gov_param(
            0,
            1,
            "monetary_policy_tick_interval_blocks".to_string(),
            "10".to_string(),
        )
        .unwrap();
        st.set_gov_param(
            0,
            2,
            "monetary_policy_tick_cooldown_blocks".to_string(),
            "1".to_string(),
        )
        .unwrap();
    }

    st1.set_gov_param(
        0,
        3,
        "monetary_base_issuance_per_tick".to_string(),
        "7".to_string(),
    )
    .unwrap();
    st1.set_gov_param(
        0,
        4,
        "monetary_base_burn_per_tick".to_string(),
        "5".to_string(),
    )
    .unwrap();
    st2.set_gov_param(
        0,
        3,
        "monetary_base_issuance_per_tick".to_string(),
        "9".to_string(),
    )
    .unwrap();
    st2.set_gov_param(
        0,
        4,
        "monetary_base_burn_per_tick".to_string(),
        "7".to_string(),
    )
    .unwrap();

    let e1 = st1.policy_tick(10).unwrap();
    let e2 = st2.policy_tick(10).unwrap();
    assert_eq!(e1.net_delta, e2.net_delta, "sanity: net issuance matches");
    assert_ne!(
        e1.total_minted, e2.total_minted,
        "sanity: gross minted amount differs"
    );
    assert_ne!(
        e1.total_burned, e2.total_burned,
        "sanity: gross burned amount differs"
    );

    st1.set_balance("treasury.challenge_forfeits", 11);
    st2.set_balance("treasury.worker_slashes", 11);

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root must include treasury balance placement and full monetary counters, not only net issuance"
    );
}
#[test]
fn monetary_tick_metadata_should_affect_state_root_even_when_issuance_totals_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 1,
        total_minted: 5,
        total_burned: 5,
        net_issuance: 0,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 20,
        tick_count: 2,
        total_minted: 5,
        total_burned: 5,
        net_issuance: 0,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include monetary tick metadata, not only issuance totals or net issuance"
    );
}
#[test]
fn monetary_gross_totals_should_affect_state_root_even_when_tick_metadata_and_net_issuance_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 9,
        net_issuance: 0,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 10,
        total_burned: 10,
        net_issuance: 0,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include gross total_minted and total_burned, not only tick metadata or net_issuance"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 9,
        net_issuance: 0,
    });

    assert_eq!(
        state_b.state_root(),
        state_a.state_root(),
        "restoring the original gross monetary totals should rewind the deterministic root exactly"
    );
}
#[test]
fn monetary_last_tick_height_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 11,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include last_tick_height so same gross/net issuance with different tick anchors cannot hash identically"
    );
}
#[test]
fn monetary_tick_count_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 4,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "state_root must include tick_count so same tick anchor and issuance totals at different monetary progression stages cannot hash identically"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original tick_count should rewind the deterministic root exactly"
    );
}
#[test]
fn monetary_net_issuance_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: -5,
    });

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "state_root must include signed net_issuance so opposite monetary deltas cannot hash identically"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original signed net_issuance snapshot must rewind the deterministic root exactly"
    );
}
