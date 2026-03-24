use super::*;

pub fn apply_resolve(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
    resolver: String,
    signer: String,
) -> Result<ObjectRef, PouwError> {
    apply_resolve_at_height(st, task_ref, slash_worker, resolver, signer, 0)
}

pub fn apply_resolve_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
    resolver: String,
    signer: String,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.version != task_ref.version {
        return Err(PouwError::VersionConflict);
    }
    if task.status != TaskStatus::Challenged {
        return Err(PouwError::InvalidTransition);
    }
    // Emergency circuit-breaker boundary: challenged-task resolution is terminal
    // escrow movement and must remain frozen while governance pause is active.
    if st.is_emergency_paused() {
        return Err(PouwError::InvalidTransition);
    }
    validate_challenge_accounting_invariants(&task)?;
    let metering_snapshot = validate_task_metering_snapshot(&task)?;
    enforce_llm_meter_resolve_acceptance_floor(st, metering_snapshot.as_ref(), slash_worker)?;
    let resolve_authority = resolve_authority_account(st);
    // Authorization is bound to authenticated signer context; payload resolver
    // is retained only for backward-compatible event fields.
    // Gate hardening: reject malformed or divergent resolver payloads so canonical
    // signer authorization cannot be paired with spoofed event actor metadata.
    let resolver_trimmed = resolver.as_str();
    // Gate hardening: signer and configured authority must both be canonical
    // non-blank account identifiers (no surrounding whitespace).
    let signer_trimmed = signer.as_str();
    let authority_trimmed = resolve_authority.trim();
    let authority_members: Vec<&str> = authority_trimmed.split(',').collect();
    let authority_has_empty_member = authority_members
        .iter()
        .any(|member| member.trim().is_empty());
    let authority_has_duplicate_member = {
        let mut seen = std::collections::BTreeSet::new();
        authority_members
            .iter()
            .map(|member| member.to_ascii_lowercase())
            .any(|member| !seen.insert(member))
    };
    let resolver_is_canonical = is_canonical_actor_id(resolver_trimmed);
    let signer_is_canonical = is_canonical_actor_id(signer_trimmed);
    let authority_members_are_canonical = authority_members
        .iter()
        .all(|member| is_canonical_actor_id(member));
    let signer_matches_configured_member = authority_members
        .iter()
        .any(|member| *member == signer_trimmed);
    // Decentralization hardening: reserve privileged runtime account ids from
    // governance resolve authority flow; challenge resolution must be executed
    // by explicit governance-designated non-system operators.
    let authority_uses_reserved_system_actor = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case("system"));
    let uses_reserved_system_actor = resolver_trimmed.eq_ignore_ascii_case("system")
        || signer_trimmed.eq_ignore_ascii_case("system")
        || authority_uses_reserved_system_actor;
    // Minimal multi-party control: escrow treasury account must never be reused
    // as resolve authority signer/payload, otherwise custody + adjudication roles
    // collapse into a single privileged actor surface.
    let authority_uses_escrow_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT));
    let uses_escrow_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || authority_uses_escrow_account;
    // Minimal multi-party control: forfeits treasury account receives terminal
    // slashing-path value and must remain custody-only (not an adjudicator).
    let authority_uses_forfeit_treasury_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT));
    let uses_forfeit_treasury_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || authority_uses_forfeit_treasury_account;
    // Minimal multi-party control: worker slash treasury receives terminal
    // slashing-path value and must remain custody-only (not an adjudicator).
    let authority_uses_worker_slash_treasury_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT));
    let uses_worker_slash_treasury_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || authority_uses_worker_slash_treasury_account;
    // Decentralization hardening: unresolved default placeholder must never
    // authorize challenge resolution. Governance must explicitly set a concrete
    // non-placeholder resolve authority before terminal escrow movement can occur.
    let authority_uses_placeholder = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY));
    let uses_unconfigured_placeholder_authority = resolver_trimmed
        .eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY)
        || signer_trimmed.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY)
        || authority_uses_placeholder;
    // Legacy-state hardening: assigned worker identity must remain canonical
    // before resolve authority checks, otherwise malformed worker ids could
    // bypass self-resolution separation gates.
    if let Some(worker) = task.worker.as_ref() {
        require_canonical_actor_id_state(worker, "worker account")?;
    }
    // Minimal multi-party control: assigned worker cannot self-authorize terminal
    // challenge resolution for their own disputed task.
    let resolver_is_assigned_worker = task
        .worker
        .as_deref()
        .map(|worker| worker.eq_ignore_ascii_case(signer_trimmed))
        .unwrap_or(false);
    // Minimal multi-party control: configured resolve-authority sets must remain
    // disjoint from the assigned worker role so adjudication stays external even
    // when a different member signs the final resolve.
    let authority_includes_assigned_worker = task
        .worker
        .as_deref()
        .map(|worker| {
            authority_members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(worker))
        })
        .unwrap_or(false);
    // Minimal multi-party control: challenger (escrow depositor) must stay separate
    // from adjudicator authority to avoid prosecutor+judge role collapse.
    let resolver_is_challenger = task
        .challenger
        .as_deref()
        .map(|challenger| challenger.eq_ignore_ascii_case(signer_trimmed))
        .unwrap_or(false);
    let authority_includes_challenger = task
        .challenger
        .as_deref()
        .map(|challenger| {
            authority_members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(challenger))
        })
        .unwrap_or(false);
    // Minimal multi-party control: task creator (beneficiary of the work result)
    // must stay separate from adjudicator authority to avoid beneficiary+judge
    // role collapse when challenge settlement can decide bounty/slash outcomes.
    let resolver_is_creator = task.creator.eq_ignore_ascii_case(signer_trimmed);
    let authority_includes_creator = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(&task.creator));
    if !resolver_is_canonical
        || !signer_is_canonical
        || authority_trimmed.is_empty()
        || authority_trimmed != resolve_authority
        || !signer_matches_configured_member
        || !authority_members_are_canonical
        || authority_has_empty_member
        || authority_has_duplicate_member
        || resolver_trimmed != signer_trimmed
        || uses_reserved_system_actor
        || uses_escrow_account_as_authority
        || uses_forfeit_treasury_account_as_authority
        || uses_worker_slash_treasury_account_as_authority
        || uses_unconfigured_placeholder_authority
        || resolver_is_assigned_worker
        || authority_includes_assigned_worker
        || resolver_is_challenger
        || authority_includes_challenger
        || resolver_is_creator
        || authority_includes_creator
    {
        return Err(PouwError::Unauthorized);
    }
    reject_if_deadline_exceeded_optional(task.resolve_deadline_height, current_height)?;
    task.status = if slash_worker {
        TaskStatus::Slashed
    } else {
        TaskStatus::Completed
    };
    if let Some(bond) = task.challenge_bond {
        ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
        task.challenge_bond_forfeited = Some(!slash_worker);
    }
    preflight_resolve_transfers(st, &task, slash_worker)?;

    // Minimal multi-party control: if governance downgrades a multisig resolver
    // set to single-authority after a first staged approval, fail closed and
    // clear stale staging so one signer cannot inherit partially-approved state.
    if authority_members.len() <= 1
        && (st.pending_resolve_approval(task_ref.id).is_some()
            || st.pending_resolve_first_approver(task_ref.id).is_some())
    {
        st.clear_pending_resolve_approval(task_ref.id);
        return Err(PouwError::Unauthorized);
    }

    // Minimal multi-party control: when governance configures a resolver set,
    // require two distinct member approvals before terminal escrow settlement.
    if authority_members.len() > 1 {
        // Governance hardening: if resolver membership changes after a first
        // staged approval, fail closed and discard stale staged state so a
        // removed approver cannot be counted toward the current signer set.
        if let Some(first_approver) = st.pending_resolve_first_approver(task_ref.id) {
            let first_still_authorized = authority_members
                .iter()
                .any(|member| *member == first_approver);
            if !first_still_authorized {
                st.clear_pending_resolve_approval(task_ref.id);
                return Err(PouwError::Unauthorized);
            }
        }

        if let Some((pending_slash_worker, _)) = st.pending_resolve_approval(task_ref.id) {
            if pending_slash_worker != slash_worker {
                st.clear_pending_resolve_approval(task_ref.id);
                return Err(PouwError::Unauthorized);
            }
        }

        let approved = st
            .stage_or_confirm_resolve_approval(
                task_ref.id,
                task_ref.version,
                slash_worker,
                signer_trimmed,
                authority_trimmed,
            )
            .map_err(|_| PouwError::Unauthorized)?;
        if !approved {
            return Err(PouwError::ResolveApprovalStaged);
        }
    }

    let task_id = task_ref.id;
    let before_task = task.clone();
    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;

    let settle_result = (|| -> Result<(), PouwError> {
        if let Some(bond) = task.challenge_bond {
            // Funds always flow out of escrow at resolve for auditability.
            st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            if slash_worker {
                // Challenge succeeds: return challenger bond.
                if let Some(ref challenger) = task.challenger {
                    st.credit_balance(challenger, bond)
                        .map_err(PouwError::State)?;
                }
            } else {
                // Challenge fails: forfeit bond into treasury pool.
                st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                    .map_err(PouwError::State)?;
            }
        }

        if slash_worker {
            // Success incentive: pay a fixed minimal bounty to challenger strictly from the
            // task-local slashed worker stake lock. Never fall back to the global worker-slash
            // treasury, which is custody-only and must not subsidize historical challenge payouts.
            let _ = maybe_pay_challenge_success_bounty(st, &task)?;
        }

        settle_worker_stake_for_terminal_state(st, &task)?;
        Ok(())
    })();

    if let Err(err) = settle_result {
        st.update_task(next_ref.clone(), before_task)
            .map_err(map_state_err)?;
        st.clear_pending_resolve_approval(task_id);
        return Err(err);
    }

    st.clear_pending_resolve_approval(task_id);

    Ok(next_ref)
}

pub fn apply_timeout(
    st: &mut StateStore,
    task_ref: ObjectRef,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;

    if matches!(task.status, TaskStatus::Challenged) && st.is_emergency_paused() {
        // Safety boundary: emergency pause must fail-closed before challenged-task
        // invariant/audit checks so timeout settlement cannot leak challenged-state
        // accounting details while escrow movement paths are frozen.
        return Err(PouwError::InvalidTransition);
    }

    validate_challenge_accounting_invariants(&task)?;

    let mut forfeit_challenge_bond = false;
    let mut refund_challenge_bond = false;

    match task.status {
        TaskStatus::Assigned | TaskStatus::Committed => {
            require_deadline_exceeded(task.reveal_deadline_height, current_height)?;
            task.status = TaskStatus::Slashed;
        }
        TaskStatus::Revealed => {
            let challenge_deadline = task.challenge_deadline_height.ok_or_else(|| {
                PouwError::State("revealed task missing challenge_deadline_height".into())
            })?;
            require_deadline_exceeded(Some(challenge_deadline), current_height)?;
            if task.challenged_at_height.is_some() {
                return Err(PouwError::InvalidTransition);
            }
            task.status = TaskStatus::Completed;
            task.challenge_deadline_height = None;
            task.challenged_at_height = None;
            task.resolve_deadline_height = None;
        }
        TaskStatus::Challenged => {
            require_deadline_exceeded(task.resolve_deadline_height, current_height)?;
            if let Some(bond) = task.challenge_bond {
                ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
            }
            if unresolved_challenge_slash_on_timeout(st)? {
                task.status = TaskStatus::Slashed;
                if task.challenge_bond.is_some() {
                    task.challenge_bond_forfeited = Some(false);
                    refund_challenge_bond = true;
                }
            } else {
                task.status = TaskStatus::Completed;
                if task.challenge_bond.is_some() {
                    task.challenge_bond_forfeited = Some(false);
                    refund_challenge_bond = true;
                }
            }
        }
        _ => return Err(PouwError::InvalidTransition),
    }

    if matches!(task.status, TaskStatus::Completed)
        && !matches!(task.challenge_bond_forfeited, Some(false))
    {
        forfeit_challenge_bond = task.challenge_bond.is_some();
    }

    preflight_timeout_transfers(st, &task, forfeit_challenge_bond, refund_challenge_bond)?;

    let task_id = task_ref.id;
    let before_task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;

    let settle_result = (|| -> Result<(), PouwError> {
        if let Some(bond) = task.challenge_bond {
            if forfeit_challenge_bond {
                st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                    .map_err(PouwError::State)?;
                st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                    .map_err(PouwError::State)?;
            } else if refund_challenge_bond {
                st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                    .map_err(PouwError::State)?;
                if let Some(ref challenger) = task.challenger {
                    st.credit_balance(challenger, bond)
                        .map_err(PouwError::State)?;
                }
            }
        }

        settle_worker_stake_for_terminal_state(st, &task)?;
        Ok(())
    })();

    if let Err(err) = settle_result {
        st.update_task(next_ref.clone(), before_task)
            .map_err(map_state_err)?;
        return Err(err);
    }

    // Hygiene boundary: timeout finalization must clear any staged multisig resolve
    // approvals so stale partial authorizations cannot linger after terminal state.
    st.clear_pending_resolve_approval(task_id);

    Ok(next_ref)
}
