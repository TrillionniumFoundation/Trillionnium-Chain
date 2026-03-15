use anyhow::Result;

use crate::*;
use crate::cli::Command;

pub(crate) fn dispatch_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::PullTask { state } => {
            let task_id = next_task_id(&state)?;
            println!("[agent] pulled task_id={}", task_id);
        }
        Command::Execute {
            task_id,
            worker,
            payload,
        } => {
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            println!("[agent] executed task_id={} worker={}", task_id, worker);
            println!("result_hash={}", result_hash);
            println!("salt_hex={}", salt_hex);
        }
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => {
            let c = commitment(task_id, &result_hash, &salt_hex, &worker);
            println!("[agent] task_id={} worker={}", task_id, worker);
            println!("commit_hash={}", c);
            println!(
                "template_commit=trnm-node tx commit-result {} {} {} {}",
                task_id, worker, c, task_id
            );
            println!(
                "template_reveal=trnm-node tx reveal-result {} {} {}",
                task_id, result_hash, salt_hex
            );
            if submit {
                append_submission(&submit_log, task_id, &worker, &c, &result_hash, &salt_hex)?;
                println!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => {
            let task_id = next_task_id(&state)?;
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            let commit_hash = commitment(task_id, &result_hash, &salt_hex, &worker);
            if submit {
                append_submission(
                    &submit_log,
                    task_id,
                    &worker,
                    &commit_hash,
                    &result_hash,
                    &salt_hex,
                )?;
            }
            let out = RunOnceOutput {
                task_id,
                worker: worker.clone(),
                result_hash: result_hash.clone(),
                salt_hex: salt_hex.clone(),
                commit_hash: commit_hash.clone(),
                template_commit: format!(
                    "trnm-node tx commit-result {} {} {} {}",
                    task_id, worker, commit_hash, task_id
                ),
                template_reveal: format!(
                    "trnm-node tx reveal-result {} {} {}",
                    task_id, result_hash, salt_hex
                ),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            if submit {
                eprintln!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunAssigned {
            worker,
            ingress_file,
            limit,
            submit,
            submit_log,
            llm_adapter_cmd,
            verifier_max_output_chars,
            llm_adapter_max_retries,
            llm_adapter_backoff_ms,
            llm_adapter_timeout_ms,
        } => {
            let llm_policy = resolve_llm_adapter_policy(
                llm_adapter_max_retries,
                llm_adapter_backoff_ms,
                llm_adapter_timeout_ms,
            );
            let proof_adapter_name = env::var(PROOF_ADAPTER_ENV)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_PROOF_ADAPTER.to_string());
            let proof_adapter = build_proof_adapter(&proof_adapter_name).map_err(|e| {
                anyhow!(
                    "invalid {PROOF_ADAPTER_ENV}={proof_adapter_name:?}: {e}; supported={DEFAULT_PROOF_ADAPTER}"
                )
            })?;
            let mut records = load_ingress_records(&ingress_file)?;
            let mut n = 0usize;
            for rec in records.iter_mut() {
                if n >= limit {
                    break;
                }
                if rec.status != RequestStatus::Assigned.as_str() {
                    continue;
                }
                if rec.assigned_worker.as_deref() != Some(worker.as_str()) {
                    continue;
                }

                let llm = match run_llm_adapter_with_retry(
                    &llm_adapter_cmd,
                    &rec.text,
                    llm_policy.retry,
                    Duration::from_millis(llm_policy.timeout_ms),
                    proof_adapter.as_ref(),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let (resolution_code, failure_tag) = classify_adapter_error(&e);
                        rec.status =
                            transition_request_status(&rec.status, RequestStatus::FailedAdapter)?;
                        rec.verifier_status = Some("rejected".to_string());
                        rec.resolution_code = Some(resolution_code.to_string());
                        rec.adapter_error = Some(e.context.clone());
                        rec.reputation_delta = Some(reputation_delta(adapter_error_signal(e.kind)));
                        n += 1;
                        println!(
                            "[assigned] request_id={} task_id={} worker={} status=FAILED_ADAPTER({}) retryable={} error={}",
                            rec.request_id,
                            rec.task_id,
                            worker,
                            failure_tag,
                            matches!(e.kind, AdapterErrorKind::Retriable),
                            e.context
                        );
                        continue;
                    }
                };
                let (verified, resolution_code) =
                    proof_adapter.verify(&llm.output_text, verifier_max_output_chars);
                let v_status = if verified { "accepted" } else { "rejected" };
                attach_llm_provenance(rec, &llm);
                rec.model_output = Some(llm.output_text.clone());
                rec.verifier_status = Some(v_status.to_string());
                rec.resolution_code = Some(resolution_code.to_string());

                if v_status != "accepted" {
                    rec.status = transition_request_status(&rec.status, RequestStatus::Rejected)?;
                    rec.reputation_delta =
                        Some(reputation_delta(ReputationSignal::VerifierRejected));
                    n += 1;
                    println!(
                        "[assigned] request_id={} task_id={} worker={} verifier_status={} resolution_code={}",
                        rec.request_id, rec.task_id, worker, v_status, resolution_code
                    );
                    continue;
                }

                let payload = llm.output_text;
                let (result_hash, salt_hex) = execute_payload(&payload, rec.task_id);
                let commit_hash = commitment(rec.task_id, &result_hash, &salt_hex, &worker);
                rec.result_hash = Some(result_hash.clone());
                if submit {
                    append_submission(
                        &submit_log,
                        rec.task_id,
                        &worker,
                        &commit_hash,
                        &result_hash,
                        &salt_hex,
                    )?;
                }
                rec.status = transition_request_status(&rec.status, RequestStatus::CommitQueued)?;
                rec.reputation_delta = Some(reputation_delta(ReputationSignal::Accepted));
                n += 1;
                println!(
                    "[assigned] request_id={} task_id={} worker={} result_hash={} submit={} provider_request_id={}",
                    rec.request_id,
                    rec.task_id,
                    worker,
                    result_hash,
                    submit,
                    rec.provider_request_id.as_deref().unwrap_or("-")
                );
            }
            save_ingress_records(&ingress_file, &records)?;
            println!(
                "[agent] run-assigned processed={} ingress={} submit_log={} adapter={} adapter_retries={} adapter_backoff_ms={} adapter_timeout_ms={}",
                n,
                ingress_file.display(),
                submit_log.display(),
                llm_adapter_cmd,
                llm_policy.retry.max_retries,
                llm_policy.retry.backoff_ms,
                llm_policy.timeout_ms
            );
        }
        Command::FlushSubmissions {
            submit_log,
            ingress_file,
            update_ingress,
            execute,
            adapter_cmd,
            max_retries,
            backoff_ms,
            ack_log,
            event_log,
            progress_log,
        } => {
            let tx_retry = resolve_tx_retry_policy(max_retries, backoff_ms);
            let event_log = resolve_path_arg_from_env(
                event_log,
                WORKER_EVENT_LOG_ENV,
                "/tmp/trnm-worker-agent-events.jsonl",
            );
            let progress_log = resolve_path_arg_from_env(
                progress_log,
                WORKER_PROGRESS_LOG_ENV,
                "/tmp/trnm-worker-agent-progress.jsonl",
            );
            if !submit_log.exists() {
                println!("[agent] no submit log found: {}", submit_log.display());
                return Ok(());
            }
            let raw = fs::read_to_string(&submit_log)?;
            let mut n = 0usize;
            let mut skipped = 0usize;
            let mut acked = load_acked(&ack_log);
            let run_id = format!("flush-{}-{}", now_ms(), std::process::id());
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let rec: SubmissionRecord = serde_json::from_str(line)?;
                n += 1;

                if acked.contains(&rec.task_id) {
                    skipped += 1;
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "done".to_string(),
                            note: "already_acked_skip".to_string(),
                        },
                    )?;
                    println!("[skip] task_id={} already_acked=true", rec.task_id);
                    continue;
                }

                if !execute {
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "pending".to_string(),
                            note: "dry_run_only".to_string(),
                        },
                    )?;
                    println!(
                        "[dry-run] adapter={} commit {} {} {}",
                        adapter_cmd, rec.task_id, rec.worker, rec.commit_hash
                    );
                    println!(
                        "[dry-run] adapter={} reveal {} {} {}",
                        adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex
                    );
                } else {
                    let Some(_task_lock) = try_acquire_task_lock(&ack_log, rec.task_id)? else {
                        skipped += 1;
                        append_progress(
                            &progress_log,
                            &ProgressRecord {
                                ts_unix_ms: now_ms(),
                                run_id: run_id.clone(),
                                task_id: rec.task_id,
                                state: "pending".to_string(),
                                note: "concurrent_replay_skip".to_string(),
                            },
                        )?;
                        println!("[skip] task_id={} concurrent_replay=true", rec.task_id);
                        continue;
                    };

                    if is_task_acked(&ack_log, rec.task_id) {
                        skipped += 1;
                        acked.insert(rec.task_id);
                        append_progress(
                            &progress_log,
                            &ProgressRecord {
                                ts_unix_ms: now_ms(),
                                run_id: run_id.clone(),
                                task_id: rec.task_id,
                                state: "done".to_string(),
                                note: "already_acked_after_lock".to_string(),
                            },
                        )?;
                        println!(
                            "[skip] task_id={} already_acked_after_lock=true",
                            rec.task_id
                        );
                        continue;
                    }

                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "processing".to_string(),
                            note: format!(
                                "adapter={} retries={} backoff_ms={}",
                                adapter_cmd, tx_retry.max_retries, tx_retry.backoff_ms
                            ),
                        },
                    )?;
                    let nonce = rec.nonce.unwrap_or(rec.task_id);
                    let commit_args = vec![
                        "commit".to_string(),
                        rec.task_id.to_string(),
                        rec.worker.clone(),
                        rec.commit_hash.clone(),
                        nonce.to_string(),
                    ];
                    let reveal_args = vec![
                        "reveal".to_string(),
                        rec.task_id.to_string(),
                        rec.result_hash.clone(),
                        rec.salt_hex.clone(),
                    ];

                    let commit_res = run_adapter_with_retry(
                        &adapter_cmd,
                        &commit_args,
                        tx_retry.max_retries,
                        tx_retry.backoff_ms,
                    )?;
                    let reveal_executed = should_execute_reveal(&commit_res);
                    let reveal_res = if reveal_executed {
                        run_adapter_with_retry(
                            &adapter_cmd,
                            &reveal_args,
                            tx_retry.max_retries,
                            tx_retry.backoff_ms,
                        )?
                    } else {
                        AdapterExecResult {
                            ok: false,
                            rc: RC_SKIPPED,
                            tx_hash: None,
                            terminal: true,
                        }
                    };

                    println!(
                        "[submitted] task_id={} commit_ok={} reveal_ok={} reveal_executed={} commit_rc={} reveal_rc={} commit_tx_hash={} reveal_tx_hash={} adapter={} retries={} backoff_ms={}",
                        rec.task_id,
                        commit_res.ok,
                        reveal_res.ok,
                        reveal_executed,
                        commit_res.rc,
                        reveal_res.rc,
                        commit_res.tx_hash.as_deref().unwrap_or("-"),
                        reveal_res.tx_hash.as_deref().unwrap_or("-"),
                        adapter_cmd,
                        tx_retry.max_retries,
                        tx_retry.backoff_ms
                    );

                    let commit_idempotent_ok = should_execute_reveal(&commit_res);
                    let reveal_idempotent_ok =
                        reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

                    let previous_ack_hashes = persisted_ack_hashes_for_task(&ack_log, rec.task_id);
                    let previous_commit_tx_hash = previous_ack_hashes.commit_tx_hash;
                    let previous_reveal_tx_hash = previous_ack_hashes.reveal_tx_hash;

                    let commit_hash_observed = commit_res.tx_hash.is_some()
                        || (is_idempotent_duplicate_ok(commit_res.rc)
                            && previous_commit_tx_hash.is_some());
                    let reveal_hash_observed = reveal_res.tx_hash.is_some()
                        || (is_idempotent_duplicate_ok(reveal_res.rc)
                            && previous_reveal_tx_hash.is_some());

                    let commit_tx_hash_for_ack =
                        commit_res.tx_hash.clone().or(previous_commit_tx_hash);
                    let reveal_tx_hash_for_ack =
                        reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

                    let (ack_status, reason_code, ack_reason) = if commit_idempotent_ok
                        && reveal_idempotent_ok
                        && commit_hash_observed
                        && reveal_hash_observed
                    {
                        (
                            "accepted",
                            "idempotent_ok",
                            format!(
                                "idempotent-ok commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else if commit_idempotent_ok
                        && reveal_idempotent_ok
                        && (!commit_hash_observed || !reveal_hash_observed)
                    {
                        (
                            "failed",
                            "missing_tx_hash_receipt",
                            format!(
                                "missing-tx-hash-receipt commit_tx_hash_present={} reveal_tx_hash_present={} commit_rc={} reveal_rc={}",
                                commit_hash_observed, reveal_hash_observed, commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else if !commit_idempotent_ok && commit_res.terminal {
                        (
                                "rejected",
                                "commit_rejected_skip_reveal",
                                format!(
                                    "deterministic-commit-rejection-skip-reveal commit_rc={} reveal_rc={}",
                                    commit_res.rc, reveal_res.rc
                                ),
                            )
                    } else if commit_res.terminal || reveal_res.terminal {
                        (
                            "rejected",
                            "deterministic_rejection",
                            format!(
                                "deterministic-rejection commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else {
                        (
                            "failed",
                            "retry_exhausted_or_transient",
                            format!(
                                "transient-or-exhausted-retries commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    };

                    append_ack(
                        &ack_log,
                        rec.task_id,
                        ack_status,
                        commit_tx_hash_for_ack.clone(),
                        reveal_tx_hash_for_ack.clone(),
                        Some(reason_code.to_string()),
                        Some(run_id.clone()),
                    )?;

                    if update_ingress {
                        let mut ingress = load_ingress_records(&ingress_file)?;
                        let mut changed = false;
                        for ir in ingress.iter_mut() {
                            if ir.task_id == rec.task_id {
                                ir.commit_tx_hash = commit_tx_hash_for_ack.clone();
                                ir.reveal_tx_hash = reveal_tx_hash_for_ack.clone();
                                ir.resolution_code = Some(reason_code.to_string());
                                ir.verifier_status = Some(if ack_status == "accepted" {
                                    "accepted".to_string()
                                } else {
                                    "rejected".to_string()
                                });
                                ir.status = match ack_status {
                                    "accepted" => transition_request_status(
                                        &ir.status,
                                        RequestStatus::RevealSubmitted,
                                    )?,
                                    "rejected" => transition_request_status(
                                        &ir.status,
                                        RequestStatus::Rejected,
                                    )?,
                                    _ => transition_request_status(
                                        &ir.status,
                                        RequestStatus::FailedSubmission,
                                    )?,
                                };
                                changed = true;
                            }
                        }
                        if changed {
                            save_ingress_records(&ingress_file, &ingress)?;
                        }
                    }

                    append_event(
                        &event_log,
                        &WorkerEvent {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            event_type: "ack_written".to_string(),
                            task_id: rec.task_id,
                            status: ack_status.to_string(),
                            reason_code: reason_code.to_string(),
                            commit_rc: commit_res.rc,
                            reveal_rc: reveal_res.rc,
                        },
                    )?;

                    let progress_state = match ack_status {
                        "accepted" => "done",
                        "rejected" => "rejected",
                        _ => "failed",
                    };
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: progress_state.to_string(),
                            note: reason_code.to_string(),
                        },
                    )?;

                    if ack_status == "accepted" {
                        acked.insert(rec.task_id);
                    }

                    println!(
                        "[ack] run_id={} task_id={} status={} reason={} reason_code={}",
                        run_id, rec.task_id, ack_status, ack_reason, reason_code
                    );
                }
            }
            println!("[agent] flushed_records={} skipped={} execute={} ack_log={} event_log={} progress_log={} run_id={}", n, skipped, execute, ack_log.display(), event_log.display(), progress_log.display(), run_id);
        }
        Command::ExportAudit {
            ingress_file,
            output_file,
        } => handle_export_audit(ingress_file, output_file)?,
        Command::QueryAudit {
            output_file,
            task_id,
            provenance_fingerprint,
        } => handle_query_audit(output_file, task_id, provenance_fingerprint)?,
    }
    Ok(())
}
