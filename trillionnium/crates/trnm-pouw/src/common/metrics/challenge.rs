use super::*;

pub(crate) fn ceil_mul_div(value: u128, numerator: u128, denominator: u128) -> u128 {
    if value == 0 || numerator == 0 {
        return 0;
    }
    value
        .saturating_mul(numerator)
        .saturating_add(denominator.saturating_sub(1))
        / denominator
}

pub(crate) fn required_challenge_bond(st: &StateStore, task: &TaskObject) -> u128 {
    let static_floor = st
        .gov_param_u128("challenge_min_bond")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND);

    let bounty_bps = st
        .gov_param_u128("challenge_min_bond_bounty_bps")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND_BOUNTY_BPS);
    let bounty_floor = ceil_mul_div(task.bounty, bounty_bps, BPS_DENOMINATOR);

    let min_worker_stake = st
        .gov_param_u128("min_worker_stake")
        .unwrap_or(DEFAULT_MIN_WORKER_STAKE);
    let worker_stake_bps = st
        .gov_param_u128("challenge_min_bond_worker_stake_bps")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND_WORKER_STAKE_BPS);
    let worker_stake_floor = ceil_mul_div(min_worker_stake, worker_stake_bps, BPS_DENOMINATOR);

    static_floor.max(bounty_floor).max(worker_stake_floor)
}

pub(crate) fn resolve_authority_account(st: &StateStore) -> String {
    st.gov_param_string("resolve_authority")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RESOLVE_AUTHORITY.to_string())
}

pub(crate) fn validate_challenge_accounting_invariants(task: &TaskObject) -> Result<(), PouwError> {
    let has_bond = task.challenge_bond.is_some();
    let has_challenger = task.challenger.is_some();

    if matches!(task.challenge_bond, Some(0)) {
        return Err(PouwError::State(
            "challenge metadata contains zero challenge bond".into(),
        ));
    }

    if let Some(challenger) = task.challenger.as_ref() {
        if challenger.trim().is_empty() {
            return Err(PouwError::State(
                "challenge metadata contains blank challenger identity".into(),
            ));
        }
        require_canonical_actor_id_state(challenger, "challenger identity").map_err(|_| {
            PouwError::State("challenge metadata contains non-canonical challenger identity".into())
        })?;
    }

    if has_bond != has_challenger {
        return Err(PouwError::State(format!(
            "inconsistent challenge fields: status={:?}, challenge_bond_present={}, challenger_present={}",
            task.status, has_bond, has_challenger
        )));
    }

    match task.status {
        TaskStatus::Open | TaskStatus::Assigned | TaskStatus::Committed => {
            if has_bond
                || task.challenge_bond_forfeited.is_some()
                || task.challenge_window_blocks_snapshot.is_some()
                || task.challenged_at_height.is_some()
                || task.challenge_deadline_height.is_some()
                || task.resolve_deadline_height.is_some()
            {
                return Err(PouwError::State(format!(
                    "stale challenge fields for non-challenged status: status={:?}",
                    task.status
                )));
            }
        }
        TaskStatus::Revealed => {
            if has_bond
                || task.challenge_bond_forfeited.is_some()
                || task.challenged_at_height.is_some()
                || task.resolve_deadline_height.is_some()
            {
                return Err(PouwError::State(format!(
                    "stale challenge fields for non-challenged status: status={:?}",
                    task.status
                )));
            }
            let challenge_deadline = task.challenge_deadline_height.ok_or_else(|| {
                PouwError::State("revealed status requires challenge_deadline_height".into())
            })?;
            if challenge_deadline == 0 {
                return Err(PouwError::State(
                    "revealed status has invalid challenge_deadline_height".into(),
                ));
            }
            if task
                .challenge_window_blocks_snapshot
                .is_some_and(|snapshot| snapshot < MIN_CHALLENGE_WINDOW_BLOCKS)
            {
                return Err(PouwError::State(
                    "revealed status has invalid challenge_window_blocks_snapshot".into(),
                ));
            }
        }
        TaskStatus::Challenged => {
            if !has_bond {
                return Err(PouwError::State(
                    "challenged status requires challenge bond fields".into(),
                ));
            }
            let challenge_window_blocks_snapshot =
                task.challenge_window_blocks_snapshot.ok_or_else(|| {
                    PouwError::State(
                        "challenged status requires challenge_window_blocks_snapshot".into(),
                    )
                })?;
            if challenge_window_blocks_snapshot < MIN_CHALLENGE_WINDOW_BLOCKS {
                return Err(PouwError::State(
                    "challenged status has invalid challenge_window_blocks_snapshot".into(),
                ));
            }
            if task.resolve_deadline_height.is_none()
                || task.challenged_at_height.is_none()
                || task.challenge_deadline_height.is_none()
            {
                return Err(PouwError::State(
                    "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
                        .into(),
                ));
            }
            let challenged_at = task.challenged_at_height.expect("checked is_some");
            let challenge_deadline = task.challenge_deadline_height.expect("checked is_some");
            let resolve_deadline = task.resolve_deadline_height.expect("checked is_some");
            if challenged_at > challenge_deadline || challenge_deadline > resolve_deadline {
                return Err(PouwError::State(
                    "challenged status has non-monotonic challenge/resolve deadlines".into(),
                ));
            }
            if task.challenge_bond_forfeited.is_some() {
                return Err(PouwError::State(
                    "challenged task cannot have terminal challenge bond outcome".into(),
                ));
            }
        }
        TaskStatus::Completed | TaskStatus::Slashed => {
            if task.challenge_bond_forfeited.is_some() && !has_bond {
                return Err(PouwError::State(
                    "terminal challenge bond outcome requires challenge bond fields".into(),
                ));
            }
            if has_bond && task.challenge_bond_forfeited.is_none() {
                return Err(PouwError::State(
                    "terminal challenged task missing challenge bond outcome".into(),
                ));
            }
            if has_bond {
                let challenge_window_blocks_snapshot =
                    task.challenge_window_blocks_snapshot.ok_or_else(|| {
                        PouwError::State(
                            "terminal challenged task missing challenge_window_blocks_snapshot"
                                .into(),
                        )
                    })?;
                if challenge_window_blocks_snapshot < MIN_CHALLENGE_WINDOW_BLOCKS {
                    return Err(PouwError::State(
                        "terminal challenged task has invalid challenge_window_blocks_snapshot"
                            .into(),
                    ));
                }
            }
            if has_bond
                && (task.challenge_deadline_height.is_none()
                    || task.challenged_at_height.is_none()
                    || task.resolve_deadline_height.is_none())
            {
                return Err(PouwError::State(
                    "terminal challenged task missing challenge timing metadata".into(),
                ));
            }
            if has_bond {
                let challenged_at = task.challenged_at_height.expect("checked is_some");
                let challenge_deadline = task.challenge_deadline_height.expect("checked is_some");
                let resolve_deadline = task.resolve_deadline_height.expect("checked is_some");
                if challenged_at > challenge_deadline || challenge_deadline > resolve_deadline {
                    return Err(PouwError::State(
                        "terminal challenged task has non-monotonic challenge/resolve deadlines"
                            .into(),
                    ));
                }
            }
            if !has_bond
                && (task.challenged_at_height.is_some()
                    || task.challenge_deadline_height.is_some()
                    || task.resolve_deadline_height.is_some())
            {
                return Err(PouwError::State(
                    "terminal non-challenged task has stale challenge timing fields".into(),
                ));
            }
        }
    }

    Ok(())
}
