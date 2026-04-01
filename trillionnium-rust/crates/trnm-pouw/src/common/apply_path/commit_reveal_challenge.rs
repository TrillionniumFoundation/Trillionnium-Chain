use super::*;

pub fn apply_commit_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    committed_hash: Hash32,
) -> Result<ObjectRef, PouwError> {
    apply_commit_result_at_height(st, task_ref, worker, committed_hash, 0)
}

pub fn apply_commit_result_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    committed_hash: Hash32,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Assigned {
        return Err(PouwError::InvalidTransition);
    }

    let assigned_worker = task.worker.clone().ok_or(PouwError::MissingWorker)?;
    // Fail closed on malformed worker ids before the commit envelope is accepted,
    // so legacy/corrupted Assigned state cannot advance into Committed with a
    // non-canonical actor binding that later stages would have to unwind.
    require_canonical_actor_id_state(&assigned_worker, "worker account")?;
    require_canonical_actor_id(&worker)?;
    if assigned_worker != worker {
        return Err(PouwError::Unauthorized);
    }

    task.status = TaskStatus::Committed;
    task.committed_hash = Some(committed_hash);
    task.committed_at_height = Some(current_height);
    task.reveal_deadline_height = Some(current_height.saturating_add(DEFAULT_REVEAL_WINDOW_BLOCKS));
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_reveal_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
    proof_data: Option<Vec<u8>>,
) -> Result<ObjectRef, PouwError> {
    apply_reveal_result_at_height(st, task_ref, result_hash, reveal_salt, proof_data, 0)
}

pub fn apply_reveal_result_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
    proof_data: Option<Vec<u8>>,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;

    if task.status != TaskStatus::Committed {
        return Err(PouwError::InvalidTransition);
    }
    if let Some(deadline) = task.reveal_deadline_height {
        if current_height > deadline {
            return Err(PouwError::DeadlineExceeded);
        }
    }

    if task.task_id != task_ref.id {
        // Fail closed if legacy/corrupted state breaks the canonical task_id
        // binding between object reference and proof envelope context.
        return Err(PouwError::State("task id binding mismatch".into()));
    }

    let worker = task.worker.clone().ok_or(PouwError::MissingWorker)?;
    // Legacy-state hardening: fail closed on malformed assigned worker ids so
    // commitment/proof envelope worker binding cannot be validated against
    // non-canonical identity strings.
    require_canonical_actor_id_state(&worker, "worker account")?;

    let committed = task.committed_hash.ok_or(PouwError::MissingCommitment)?;
    let expected = compute_commitment(task.task_id, &result_hash, &reveal_salt, &worker);
    if expected != committed {
        return Err(PouwError::CommitmentMismatch);
    }

    if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        if let Some(stored_result_hash) = task.result_hash {
            if stored_result_hash != result_hash {
                // Legacy-state hardening: verifiable envelopes must not proceed when
                // persisted committed state already drifts from the reveal/hash tuple.
                return Err(PouwError::State(
                    "legacy committed result hash drift".into(),
                ));
            }
            // Fail closed even when the legacy prebound hash matches, because verifiable
            // tasks must only persist result_hash after successful proof verification.
            return Err(PouwError::State(
                "legacy committed result hash prebound".into(),
            ));
        }
    }

    // Verify proof if TEE/ZK.
    // For Fraud proofs, we rely on the challenge period (no immediate verification).
    // Fail closed if a proof payload is supplied for a non-verifiable proof type, so
    // legacy/corrupted proof_type drift cannot silently bypass envelope verification.
    if let Some(proof_payload) = proof_data.as_deref() {
        if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
            if proof_payload_is_blank(proof_payload) {
                return Err(PouwError::State(format!(
                    "Proof verification failed: missing proof payload for {:?}",
                    task.proof_type
                )));
            }
        } else {
            if proof_payload_is_blank(proof_payload) {
                return Err(PouwError::State(format!(
                    "unexpected proof payload for non-verifiable proof type: {:?}",
                    task.proof_type
                )));
            }
            let receipt = validate_llm_token_meter_receipt_for_reveal(
                task.proof_type,
                task.task_id,
                &worker,
                &result_hash,
                proof_payload,
            )?;
            let policy = effective_llm_token_meter_policy(st)?;
            let snapshot = build_task_metering_snapshot(&receipt, &policy);
            let metadata = task.metadata.get_or_insert_with(TaskMetadata::default);
            metadata.metering = Some(snapshot);
        }
    }
    if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        let proof_payload = proof_data.as_deref().unwrap_or(&[]);

        let registry = get_default_registry();
        let mut verification_task = task.clone();
        // Rebind canonical envelope context explicitly so verification always
        // evaluates the committed task_id/worker/proof_type/result_hash tuple,
        // even when legacy state carries drift in optional fields.
        verification_task.task_id = task.task_id;
        verification_task.worker = Some(worker.clone());
        verification_task.proof_type = task.proof_type;
        verification_task.result_hash = Some(result_hash);
        let verification = registry.verify(&verification_task, proof_payload);
        let _ = emit_proof_verification_observation(
            &verification_task,
            &verification,
            format!(
                "builtin-{}-verifier",
                verification::proof_type_key(verification_task.proof_type)
            ),
            proof_payload.len(),
        );
        match verification {
            VerificationResult::Valid => {
                // Immediate finality for verifiable execution.
                task.status = TaskStatus::Completed;
                task.result_hash = Some(result_hash);
                task.reveal_salt = Some(reveal_salt);
                // No challenge window needed.
                task.challenge_deadline_height = None;
                task.resolve_deadline_height = None;

                // Immediate finality remains atomic with stake settlement: preflight
                // the unlock on a cloned state, then persist the task before touching balances.
                return finalize_verified_reveal_success(st, task_ref, task);
            }
            VerificationResult::Invalid(reason) => {
                // Return error to reject the transaction, allowing retry with correct proof
                // before deadline. If deadline passes, timeout will slash.
                // Alternatively, we could slash immediately if we consider bad proof as malicious.
                // For now, let's reject to be safe against client errors.
                return Err(PouwError::State(format!(
                    "Proof verification failed: {}",
                    reason
                )));
            }
            VerificationResult::Indeterminate(reason) => {
                return Err(PouwError::State(format!(
                    "Proof verification indeterminate: {}",
                    reason
                )));
            }
        }
    }

    let challenge_window_blocks = sanitize_challenge_window_blocks(
        st.gov_param_u64("challenge_window_blocks")
            .unwrap_or(DEFAULT_CHALLENGE_WINDOW_BLOCKS),
    );

    task.status = TaskStatus::Revealed;
    task.result_hash = Some(result_hash);
    task.reveal_salt = Some(reveal_salt);
    task.challenge_window_blocks_snapshot = Some(challenge_window_blocks);
    task.challenge_deadline_height = Some(current_height.saturating_add(challenge_window_blocks));
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_challenge(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
    signer: String,
) -> Result<ObjectRef, PouwError> {
    apply_challenge_at_height(st, task_ref, challenger, challenge_bond, signer, 0)
}

pub(crate) fn sanitize_challenge_window_blocks(raw: u64) -> u64 {
    raw.max(MIN_CHALLENGE_WINDOW_BLOCKS)
}

pub(crate) fn effective_challenge_window_blocks(st: &StateStore, task: &TaskObject) -> u64 {
    sanitize_challenge_window_blocks(task.challenge_window_blocks_snapshot.unwrap_or_else(|| {
        // Legacy compatibility path for pre-snapshot Revealed tasks.
        // Semantics are explicitly pinned to challenge-time governance value when no snapshot
        // exists (instead of trying to infer reveal-time state that is no longer recoverable).
        st.gov_param_u64("challenge_window_blocks")
            .unwrap_or(DEFAULT_CHALLENGE_WINDOW_BLOCKS)
    }))
}

pub fn apply_challenge_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
    signer: String,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Revealed {
        return Err(PouwError::InvalidTransition);
    }
    validate_challenge_accounting_invariants(&task)?;
    let _ = validate_task_metering_snapshot(&task)?;
    // Safety boundary: emergency pause must also freeze new challenged-state
    // entry because it immediately debits challenger funds into escrow.
    if st.is_emergency_paused() {
        return Err(PouwError::InvalidTransition);
    }
    reject_if_deadline_exceeded(task.challenge_deadline_height, current_height)?;

    let min_bond = required_challenge_bond(st, &task);
    // Safety hardening: challenge escrow must always carry non-zero economic weight,
    // even under permissive or malformed governance parameters.
    if challenge_bond == 0 || challenge_bond < min_bond {
        return Err(PouwError::InsufficientStake);
    }

    // Authorization is bound to authenticated signer context.
    // Harden against blank actor/signer values so malformed payloads cannot
    // bind escrow/accounting updates to an empty account id.
    require_canonical_actor_id(&challenger)?;
    require_canonical_actor_id(&signer)?;
    let challenger_trimmed = challenger.as_str();
    let signer_trimmed = signer.as_str();
    if signer_trimmed != challenger_trimmed {
        return Err(PouwError::Unauthorized);
    }

    if let Some(worker) = task.worker.as_ref() {
        // Legacy-state hardening: reject malformed non-canonical worker ids
        // so self-challenge and accounting gates cannot be bypassed.
        require_canonical_actor_id_state(worker, "worker account")?;
        let worker_trimmed = worker;
        if worker_trimmed == challenger_trimmed {
            // Consensus safety hardening: disallow self-challenge to prevent
            // worker-controlled challenge/reveal loops from gaming resolve paths.
            return Err(PouwError::Unauthorized);
        }
    }

    let challenge_window_blocks = effective_challenge_window_blocks(st, &task);

    preflight_challenge_transfer(st, &challenger, challenge_bond)?;

    task.status = TaskStatus::Challenged;
    if task.challenge_window_blocks_snapshot != Some(challenge_window_blocks) {
        // Legacy hardening: freeze fallback window at first challenge so
        // post-challenge governance updates cannot create audit ambiguity.
        // Also canonicalize malformed preexisting zero/invalid snapshots.
        task.challenge_window_blocks_snapshot = Some(challenge_window_blocks);
    }
    let resolve_deadline_height = current_height
        .checked_add(challenge_window_blocks)
        .ok_or_else(|| PouwError::State("challenge resolve deadline height overflow".into()))?;
    task.challenged_at_height = Some(current_height);
    task.resolve_deadline_height = Some(resolve_deadline_height);
    task.challenge_bond = Some(challenge_bond);
    task.challenger = Some(challenger.clone());
    task.challenge_bond_forfeited = None;
    let next_ref = st.update_task(task_ref, task).map_err(map_state_err)?;

    // Apply corresponding balance movement only after task object commit succeeds.
    st.debit_balance(&challenger, challenge_bond)
        .map_err(|_| PouwError::InsufficientStake)?;
    st.credit_balance(CHALLENGE_ESCROW_ACCOUNT, challenge_bond)
        .map_err(PouwError::State)?;

    Ok(next_ref)
}
