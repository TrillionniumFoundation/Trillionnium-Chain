use super::*;

pub(crate) fn preflight_challenge_transfer(
    st: &StateStore,
    challenger: &str,
    challenge_bond: u128,
) -> Result<(), PouwError> {
    if st.balance_of(challenger) < challenge_bond {
        return Err(PouwError::InsufficientStake);
    }

    let mut sim = st.clone();
    sim.debit_balance(challenger, challenge_bond)
        .map_err(|_| PouwError::InsufficientStake)?;
    sim.credit_balance(CHALLENGE_ESCROW_ACCOUNT, challenge_bond)
        .map_err(PouwError::State)?;
    Ok(())
}

pub(crate) fn preflight_resolve_transfers(
    st: &StateStore,
    task: &TaskObject,
    slash_worker: bool,
) -> Result<(), PouwError> {
    if task.challenge_bond.is_some() && task.challenger.is_none() {
        return Err(PouwError::State(
            "resolve challenge settlement requested without challenger".into(),
        ));
    }

    let mut sim = st.clone();
    let mut settlement_preview = task.clone();

    if let Some(bond) = task.challenge_bond {
        sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
            .map_err(PouwError::State)?;
        if slash_worker {
            if let Some(ref challenger) = task.challenger {
                sim.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
            settlement_preview.challenge_bond_forfeited = Some(false);
        } else {
            sim.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            settlement_preview.challenge_bond_forfeited = Some(true);
        }
    }

    if slash_worker {
        let _ = maybe_pay_challenge_success_bounty(&mut sim, &settlement_preview)?;
    }

    settle_worker_stake_for_terminal_state(&mut sim, task)?;
    Ok(())
}

pub(crate) fn finalize_verified_reveal_success(
    st: &mut StateStore,
    task_ref: ObjectRef,
    task: TaskObject,
) -> Result<ObjectRef, PouwError> {
    let mut sim = st.clone();
    settle_worker_stake_for_terminal_state(&mut sim, &task)?;

    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;
    settle_worker_stake_for_terminal_state(st, &task)?;
    Ok(next_ref)
}

pub(crate) fn preflight_timeout_transfers(
    st: &StateStore,
    task: &TaskObject,
    forfeit_challenge_bond: bool,
    refund_challenge_bond: bool,
) -> Result<(), PouwError> {
    if forfeit_challenge_bond && refund_challenge_bond {
        return Err(PouwError::State(
            "timeout challenge transfer mode conflict".into(),
        ));
    }
    if (forfeit_challenge_bond || refund_challenge_bond) && task.challenge_bond.is_none() {
        return Err(PouwError::State(
            "timeout challenge transfer requested without posted challenge bond".into(),
        ));
    }

    let validate_timeout_challenger = |challenger: &str| -> Result<(), PouwError> {
        if challenger.trim().is_empty() {
            return Err(PouwError::State(
                "timeout challenge transfer requested with blank challenger identity".into(),
            ));
        }
        require_canonical_actor_id_state(challenger, "challenger identity").map_err(|_| {
            PouwError::State(
                "timeout challenge transfer requested with non-canonical challenger identity"
                    .into(),
            )
        })
    };

    if refund_challenge_bond && task.challenge_bond.is_some() {
        let challenger = task.challenger.as_deref().ok_or_else(|| {
            PouwError::State("timeout challenge refund requested without challenger".into())
        })?;
        validate_timeout_challenger(challenger)?;
    }
    if forfeit_challenge_bond && task.challenge_bond.is_some() {
        let challenger = task.challenger.as_deref().ok_or_else(|| {
            PouwError::State("timeout challenge forfeit requested without challenger".into())
        })?;
        validate_timeout_challenger(challenger)?;
    }

    let mut sim = st.clone();

    if let Some(bond) = task.challenge_bond {
        if forfeit_challenge_bond {
            sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            sim.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
        } else if refund_challenge_bond {
            sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            if let Some(ref challenger) = task.challenger {
                sim.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
        }
    }

    settle_worker_stake_for_terminal_state(&mut sim, task)?;
    Ok(())
}

pub(crate) fn compute_commitment(
    task_id: u64,
    result_hash: &Hash32,
    reveal_salt: &[u8; 32],
    worker: &str,
) -> Hash32 {
    let payload = format!(
        "{}|{}|{}|{}",
        task_id,
        hex::encode(result_hash),
        hex::encode(reveal_salt),
        worker
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}
