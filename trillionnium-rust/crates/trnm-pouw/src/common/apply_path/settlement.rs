use super::*;

pub(crate) fn settle_worker_stake_for_terminal_state(
    st: &mut StateStore,
    task: &TaskObject,
) -> Result<(), PouwError> {
    let Some(worker) = task.worker.as_ref() else {
        return Ok(());
    };

    let _ = validate_task_metering_snapshot(task)?;

    let lock_account = worker_stake_lock_account(task.task_id);
    let locked = st.balance_of(&lock_account);
    if locked == 0 {
        if task.status == TaskStatus::Completed {
            let completion_bonus = llm_meter_worker_completion_bonus(st, task)?;
            if completion_bonus > 0 {
                let treasury_available = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
                let payout = completion_bonus.min(treasury_available);
                if payout > 0 {
                    st.debit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, payout)
                        .map_err(PouwError::State)?;
                    st.credit_balance(worker, payout)
                        .map_err(PouwError::State)?;
                }
            }
        }
        return Ok(());
    }

    st.debit_balance(&lock_account, locked)
        .map_err(PouwError::State)?;
    if task.status == TaskStatus::Slashed {
        let worker_rebate = llm_meter_worker_slash_rebate(st, task, locked)?;
        let treasury_take = locked.saturating_sub(worker_rebate);
        if worker_rebate > 0 {
            st.credit_balance(worker, worker_rebate)
                .map_err(PouwError::State)?;
        }
        if treasury_take > 0 {
            st.credit_balance(WORKER_SLASH_TREASURY_ACCOUNT, treasury_take)
                .map_err(PouwError::State)?;
        }
    } else {
        st.credit_balance(worker, locked)
            .map_err(PouwError::State)?;
        if task.status == TaskStatus::Completed {
            let completion_bonus = llm_meter_worker_completion_bonus(st, task)?;
            if completion_bonus > 0 {
                let treasury_available = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
                let payout = completion_bonus.min(treasury_available);
                if payout > 0 {
                    st.debit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, payout)
                        .map_err(PouwError::State)?;
                    st.credit_balance(worker, payout)
                        .map_err(PouwError::State)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn llm_meter_worker_completion_bonus(
    st: &StateStore,
    task: &TaskObject,
) -> Result<u128, PouwError> {
    if task.status != TaskStatus::Completed {
        return Ok(0);
    }
    let snapshot = validate_task_metering_snapshot(task)?;
    let Some(snapshot_ref) = snapshot.as_ref() else {
        return Ok(0);
    };
    let Some(policy) = llm_token_meter_policy_for_snapshot_or_state(st, Some(snapshot_ref))? else {
        return Ok(0);
    };

    Ok(policy.worker_completion_bonus(snapshot_ref.normalized_work_units))
}

pub(crate) fn llm_meter_worker_slash_rebate(
    st: &StateStore,
    task: &TaskObject,
    locked: u128,
) -> Result<u128, PouwError> {
    if task.status != TaskStatus::Slashed || locked == 0 {
        return Ok(0);
    }
    let snapshot = validate_task_metering_snapshot(task)?;
    let Some(snapshot_ref) = snapshot.as_ref() else {
        return Ok(0);
    };
    let Some(policy) = llm_token_meter_policy_for_snapshot_or_state(st, Some(snapshot_ref))? else {
        return Ok(0);
    };

    Ok(policy.worker_slash_rebate(snapshot_ref.normalized_work_units, locked))
}

pub(crate) fn effective_challenge_success_bounty(
    st: &StateStore,
    task: &TaskObject,
) -> Result<u128, PouwError> {
    let snapshot = validate_task_metering_snapshot(task)?;
    if let Some(snapshot_ref) = snapshot.as_ref() {
        if let Some(policy) = llm_token_meter_policy_for_snapshot_or_state(st, Some(snapshot_ref))?
        {
            return Ok(
                policy.effective_challenge_success_bounty(snapshot_ref.normalized_work_units)
            );
        }
    }

    Ok(st
        .gov_param_u128("challenge_success_bounty")
        .unwrap_or(DEFAULT_CHALLENGE_SUCCESS_BOUNTY))
}

pub(crate) fn maybe_pay_challenge_success_bounty(
    st: &mut StateStore,
    task: &TaskObject,
) -> Result<u128, PouwError> {
    if task.status != TaskStatus::Slashed {
        return Ok(0);
    }
    if task.challenge_bond.is_none()
        || task.challenged_at_height.is_none()
        || !matches!(task.challenge_bond_forfeited, Some(false))
    {
        return Err(PouwError::State(
            "challenge success bounty requires successful challenge settlement metadata".into(),
        ));
    }
    if matches!(task.challenge_bond, Some(0)) {
        return Err(PouwError::State(
            "challenge success bounty requires non-zero challenge bond metadata".into(),
        ));
    }
    validate_challenge_accounting_invariants(task)?;
    let Some(challenger) = task.challenger.as_ref() else {
        return Err(PouwError::State(
            "challenge success bounty requires challenger identity".into(),
        ));
    };
    require_canonical_actor_id_state(challenger, "challenger identity").map_err(|_| {
        PouwError::State("challenge success bounty requires canonical challenger identity".into())
    })?;

    let configured_bounty = effective_challenge_success_bounty(st, task)?;
    if configured_bounty == 0 {
        return Ok(0);
    }

    let min_worker_stake = st
        .gov_param_u128("min_worker_stake")
        .unwrap_or(DEFAULT_MIN_WORKER_STAKE);
    // Economics hardening: challenge-success bounty is paid only from the
    // slashed task-local worker stake lock, so governance must not configure a
    // bounty that can exceed the maximum intended slash principal.
    if configured_bounty > min_worker_stake {
        return Err(PouwError::State(format!(
            "challenge success bounty {} exceeds min_worker_stake {}",
            configured_bounty, min_worker_stake
        )));
    }
    // Tokenomics hardening: challenger upside must remain bounded by the
    // challenged task's own economic envelope instead of outgrowing task bounty.
    if configured_bounty > task.bounty {
        return Err(PouwError::State(format!(
            "challenge success bounty {} exceeds task bounty {}",
            configured_bounty, task.bounty
        )));
    }

    let lock_account = worker_stake_lock_account(task.task_id);
    let lock_available = st.balance_of(&lock_account);
    // Fail closed on underfunded per-task slash principal: challenge-success
    // bounty semantics must remain deterministic and fully task-local instead of
    // silently degrading into a partial payout when governance bounty exceeds the
    // actual slashable stake locked on this challenged task.
    if configured_bounty > lock_available {
        return Err(PouwError::State(format!(
            "challenge success bounty {} exceeds task-local slashable stake {}",
            configured_bounty, lock_available
        )));
    }
    let from_lock = configured_bounty;

    if from_lock > 0 {
        st.debit_balance(&lock_account, from_lock)
            .map_err(PouwError::State)?;
        st.credit_balance(challenger, from_lock)
            .map_err(PouwError::State)?;
    }

    Ok(from_lock)
}
