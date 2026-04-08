use trnm_state::StateStore;

use crate::{
    CHALLENGE_ESCROW_ACCOUNT, CHALLENGE_FORFEIT_TREASURY_ACCOUNT, WORKER_SLASH_TREASURY_ACCOUNT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventDelta {
    pub(crate) numeric: Option<i128>,
    pub(crate) text: String,
}

pub(crate) fn treasury_total(st: &StateStore) -> u128 {
    st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        .saturating_add(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT))
        .saturating_add(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT))
}

pub(crate) fn diff_u128_to_i128(after: u128, before: u128) -> Option<i128> {
    let after_i = i128::try_from(after).ok()?;
    let before_i = i128::try_from(before).ok()?;
    Some(after_i - before_i)
}

fn format_delta_fallback(after: u128, before: u128) -> String {
    if after >= before {
        format!("u128:+{}", after - before)
    } else {
        format!("u128:-{}", before - after)
    }
}

pub(crate) fn event_delta_from_balances(after: u128, before: u128) -> EventDelta {
    let numeric = diff_u128_to_i128(after, before);
    let text = numeric
        .map(|v| v.to_string())
        .unwrap_or_else(|| format_delta_fallback(after, before));
    EventDelta { numeric, text }
}

pub(crate) fn balance_deltas_for_transition(
    before: &StateStore,
    after: &StateStore,
    task_id: u64,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_delta = event_delta_from_balances(treasury_total(after), treasury_total(before));
    let challenger_delta = challenger.map(|acct| {
        let before_bal = before.balance_of(acct);
        let after_bal = after.balance_of(acct);
        event_delta_from_balances(after_bal, before_bal)
    });

    // task_id currently reserved for future richer per-task accounting; keep signature explicit.
    let _ = task_id;
    (treasury_delta, challenger_delta)
}
