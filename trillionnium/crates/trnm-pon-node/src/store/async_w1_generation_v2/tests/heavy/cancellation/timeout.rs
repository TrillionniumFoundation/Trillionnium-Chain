//! Original-deadline research lifecycle. No extra generation dispatch or
//! target cancellation is authorized by expiry or by branch restoration.
use super::*;

pub(super) fn wait_original_deadline(c: &Value, config_hash: Hash, out: &Path) -> Result<()> {
    let deadline = number(c, "original_deadline_ns")?;
    let started = original(c)?;
    write_new(
        &out.join("owner-timeout-wait-intent.json"),
        &json!({"schema":"TRNM-W1-OWNER-TIMEOUT-WAIT1",
            "config_sha256":hex::encode(config_hash),"started_monotonic_ns":started,
            "original_deadline_ns":deadline,"original_boot_id":text(c,"original_boot_id")?,
            "original_live_prover_already_observed":true,"target_cancel_request_sent":false,
            "deadline_renewed":false,"refund_authorized_by_timeout":false}),
    )?;
    loop {
        let now = now_ns()?;
        if now >= deadline {
            break;
        }
        thread::sleep(Duration::from_nanos((deadline - now).min(50_000_000)));
    }
    check(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            == text(c, "original_boot_id")?
            && sha256(&bytes(Path::new(text(c, "_config_path")?), 131072)?) == config_hash,
        "TIMEOUT_ORIGINAL_CLOCK_CONFIG",
    )?;
    write_new(
        &out.join("owner-timeout-deadline-observed.json"),
        &json!({"schema":"TRNM-W1-OWNER-TIMEOUT-WAIT1",
            "original_deadline_ns":deadline,"observed_monotonic_ns":now_ns()?,
            "target_cancel_request_sent":false,"deadline_renewed":false,
            "target_terminal_state_not_yet_inferred":true}),
    )
}

pub(super) struct Reorg<'a> {
    pub node_path: &'a Path,
    pub out: &'a Path,
    pub configuration: ConfigurationV2,
    pub task: Hash,
    pub id: Hash,
    pub reserve_tip: Hash,
    pub retained: &'a GenerationReadbackV2,
}
impl Reorg<'_> {
    pub(super) fn run<R: OwnedGenerationRuntimeV2>(
        self,
        mut node: Node,
        store: NativeGenerationStoreV2,
        runtime: &mut R,
    ) -> Result<(Node, NativeGenerationStoreV2, Value)> {
        check(
            self.retained.cancellation.is_some()
                && self.retained.verified.is_none()
                && self.retained.settlement.is_none()
                && self.retained.historical_payment.is_none()
                && self.retained.resource_charge == self.retained.statement.resource_cap
                && store.readback(self.id)? == *self.retained,
            "TIMEOUT_REORG_ORIGINAL_VETO_CAP",
        )?;
        let before = observe_native(&node, self.out, self.task)?;
        check(
            before["canonical_cancel_observed"] == true,
            "TIMEOUT_REORG_CANCEL_REQUIRED",
        )?;
        let cancelled_tip = node.active().map_err(owner_error)?.0;
        let provider_before = balance(&node, public(1));
        let owner_after_cancel = balance(&node, public(0));
        let wire_sha256 = sha256(&bytes(&self.out.join("native-cancel-wire.bin"), 4096)?);
        let packet_sha256 = sha256(&bytes(
            &self.out.join("native-cancel-packet.bin"),
            1024 * 1024,
        )?);
        let alternate_two = mine(&mut node, self.reserve_tip, vec![]);
        let alternate_three = mine(&mut node, alternate_two, vec![]);
        check(
            node.active().map_err(owner_error)?.0 == alternate_three,
            "TIMEOUT_REORG_FORK_CHOICE",
        )?;
        let removed = observe_native(&node, self.out, self.task)?;
        check(
            removed["canonical_cancel_observed"] == false
                && removed["refund_claim"] == false
                && removed["funding_row"]["status"] == "reserved"
                && removed["funding_row"]["remaining"] == 1000
                && store.readback(self.id)? == *self.retained,
            "TIMEOUT_REORG_NATIVE_UNDO_ONLY",
        )?;
        let owner_on_removed_branch = balance(&node, public(0));
        // Actually close both owners and reopen the same durable Node/journal
        // while the original Cancel is off the active branch.
        drop(store);
        drop(node);
        let mut node = open(self.node_path, StateBackend::PermanentAccountGrowthV2);
        let mut store = NativeGenerationStoreV2::open(
            &self.out.join("native-generation-v2.sqlite"),
            self.configuration,
        )?;
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut node, runtime)?;
            check(
                matches!(store.begin(&mut owner, self.id)?, DispatchDecisionV2::Done),
                "TIMEOUT_REORG_COLD_REDISPATCH",
            )?;
        }
        check(
            node.active().map_err(owner_error)?.0 == alternate_three
                && store.readback(self.id)? == *self.retained
                && balance(&node, public(1)) == provider_before,
            "TIMEOUT_REORG_COLD_STATE_CHANGED",
        )?;
        let cold = observe_native(&node, self.out, self.task)?;
        check(cold == removed, "TIMEOUT_REORG_COLD_NATIVE_STATE_CHANGED")?;
        // Empty descendant blocks restore the original signed Cancel packet.
        // No second Cancel is constructed, signed, admitted or submitted.
        let restored_three = mine(&mut node, cancelled_tip, vec![]);
        let restored_four = mine(&mut node, restored_three, vec![]);
        check(
            node.active().map_err(owner_error)?.0 == restored_four,
            "TIMEOUT_REORG_RESTORE_FORK",
        )?;
        let restored = observe_native(&node, self.out, self.task)?;
        check(
            restored["canonical_cancel_observed"] == true
                && restored["canonical_inclusion"] == before["canonical_inclusion"]
                && restored["original_operation"] == before["original_operation"]
                && restored["funding_row"]["status"] == "cancelled"
                && restored["funding_row"]["remaining"] == 0
                && balance(&node, public(0)) == owner_after_cancel
                && balance(&node, public(1)) == provider_before
                && sha256(&bytes(&self.out.join("native-cancel-wire.bin"), 4096)?) == wire_sha256
                && sha256(&bytes(
                    &self.out.join("native-cancel-packet.bin"),
                    1024 * 1024,
                )?) == packet_sha256
                && store.readback(self.id)? == *self.retained,
            "TIMEOUT_REORG_ORIGINAL_WIRE_RESTORE",
        )?;
        let result = json!({"schema":"TRNM-W1-OWNER-TIMEOUT-REORG1",
            "statement":hex::encode(self.id),"provider_operation":hex::encode(self.retained.statement.provider_operation),
            "original_cancel_tip":hex::encode(cancelled_tip),"alternate_tip":hex::encode(alternate_three),
            "restored_tip":hex::encode(restored_four),
            "original_cancel_wire_sha256":hex::encode(wire_sha256),"original_cancel_packet_sha256":hex::encode(packet_sha256),
            "before_reorg":before,"cancel_removed":removed,"actual_cold_reopen":cold,"original_cancel_restored":restored,
            "owner_balance_after_cancel":owner_after_cancel,"owner_balance_while_cancel_removed":owner_on_removed_branch,
            "provider_balance_unchanged":true,"new_generation_dispatches":0,"new_target_cancel_requests":0,
            "new_native_cancel_transactions":0,"new_cancel_wire_signed":false,"m12_dispatch_begin":"Done",
            "m12_readback_unchanged":true,"m12_original_resource_cap_retained":true,
            "resource_accounting":"UNKNOWN","all_descendants_reaped":Value::Null,
            "original_deadline_ns":self.retained.statement.original_deadline.deadline_ns,
            "deadline_renewed":false,"public_chain_transactions_sent":false,"production_qualified":false});
        write_new(&self.out.join("owner-timeout-reorg-result.json"), &result)?;
        Ok((node, store, result))
    }
}

// The ordinary full-generation runtime rejects clocks at/after the proof
// deadline. This wrapper permits only terminal observation on the same boot;
// successful generation and verifier methods still use that original fence.
struct TerminalRuntime<'a>(&'a mut LocalRuntime);
impl OwnedGenerationRuntimeV2 for TerminalRuntime<'_> {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        check(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
                == text(&self.0.config, "original_boot_id")?,
            "TIMEOUT_TERMINAL_BOOT",
        )?;
        Ok(ClockCheckpointV2 {
            clock_domain: clock_domain(&self.0.config)?,
            now_ns: now_ns()?,
        })
    }
    fn reconcile_fresh_execution(
        &mut self,
        s: &GenerationStatementV2,
        job: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        self.0.reconcile_fresh_execution(s, job, e)
    }
    fn run_independent_verifier(
        &mut self,
        s: &GenerationStatementV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        self.0.run_independent_verifier(s, e)
    }
}
impl OwnedTerminalGenerationRuntimeV3 for TerminalRuntime<'_> {
    fn reconcile_terminal_execution(
        &mut self,
        s: &GenerationStatementV2,
        job: &ProviderJobV2,
    ) -> Result<OwnedTerminalExecutionV3> {
        let c = &self.0.config;
        let config_raw = bytes(&self.0.config_path, 131072)?;
        check(
            Plan::parse(c)?.deadline_trigger
                && sha256(&config_raw) == self.0.config_hash
                && s.execution_source_commitment == self.0.config_hash,
            "TIMEOUT_TERMINAL_SOURCE",
        )?;
        for key in ["python", "target", "runtime", "owner_cancel_runtime"] {
            pin(&c[key])?;
        }
        let out = PathBuf::from(text(c, "out")?);
        let terminal_raw = bytes(
            &out.join("owner-cancel-reconcile/result.json"),
            8 * 1024 * 1024,
        )?;
        let command_raw = bytes(
            &out.join("owner-cancel-reconcile-command/result.json"),
            8 * 1024 * 1024,
        )?;
        let start_raw = bytes(&out.join("owner-cancel-start/result.json"), 8 * 1024 * 1024)?;
        let request_raw = bytes(&out.join("target-request.json"), 131072)?;
        let v: Value = serde_json::from_slice(&terminal_raw).map_err(owner_error)?;
        let command: Value = serde_json::from_slice(&command_raw).map_err(owner_error)?;
        let start: Value = serde_json::from_slice(&start_raw).map_err(owner_error)?;
        let request: Value = serde_json::from_slice(&request_raw).map_err(owner_error)?;
        let mut normalized = request.clone();
        normalized
            .as_object_mut()
            .ok_or(error("TIMEOUT_REQUEST_SHAPE"))?
            .remove("statement");
        let last = &v["observation"];
        let target = &last["target"];
        let result = &target["result"];
        let worker = &target["worker"];
        let request_digest = sha256(&serde_json::to_vec(&request).map_err(owner_error)?);
        check(
            v["schema"] == "TRNM-W1-OWNER-TIMEOUT-RUNTIME1"
                && v["phase"] == "reconcile"
                && v["phase_observation_complete"] == true
                && v["original_deadline_timeout_observed"] == true
                && v["cancellation_observed"] == false
                && v["original_target_execution_terminal"] == true
                && v["resource_reservation_must_remain"] == true
                && v["gpu_ns"].is_null()
                && json_hash(&v, "config_sha256")? == self.0.config_hash
                && json_hash(&v, "operation")? == job.operation
                && number(&v, "original_deadline_ns")? == s.original_deadline.deadline_ns
                && start["schema"] == "TRNM-W1-OWNER-TIMEOUT-RUNTIME1"
                && start["fresh_generation_started"] == true
                && start["original_job"] == *worker
                && last["original_job"] == *worker
                && json_hash(&start, "config_sha256")? == self.0.config_hash
                && json_hash(&start, "target_request_raw_sha256")? == sha256(&request_raw),
            "TIMEOUT_TERMINAL_OBSERVATION_BINDING",
        )?;
        check(
            job.provider_namespace == s.provider_namespace
                && job.operation == s.provider_operation
                && job.request_digest == s.request_digest
                && text(worker, "job_id")? == job.job_id
                && json_hash(worker, "provider_namespace")? == job.provider_namespace
                && json_hash(worker, "operation")? == job.operation
                && json_hash(worker, "request_sha256")? == request_digest
                && result["provider_job"] == *worker
                && json_hash(result, "request_sha256")? == request_digest
                && json_hash(result, "operation")? == job.operation
                && json_hash(&request, "statement")? == s.id()?
                && json_hash(&request, "execution_source_commitment")? == self.0.config_hash
                && sha256(&serde_json::to_vec(&normalized).map_err(owner_error)?)
                    == job.request_digest,
            "TIMEOUT_TERMINAL_JOB_REQUEST",
        )?;
        check(
            target["state"] == "terminal"
                && target["sticky_cancel"] == false
                && result["sticky_cancel"] == false
                && result["cause"] == "original-deadline"
                && result["error"].is_null()
                && result["exit_code"].as_i64().is_some_and(|code| code != 0)
                && result["command_success"] == false
                && result["all_owned_processes_terminal"] == true
                && result["direct_child_reaped"] == true
                && result["resources"]["gpu_ns"].is_null()
                && last["original_worker"]["execution_terminal"] == true
                && last["child_cgroup"]["recursive_empty"] == true
                && last["owner_scope"]["scope_empty_except_live_caller_ancestors"] == true
                && json_hash(result, "clock_domain")? == s.original_deadline.clock_domain
                && number(result, "original_deadline_monotonic_ns")?
                    == s.original_deadline.deadline_ns
                && number(result, "finished_monotonic_ns")? >= s.original_deadline.deadline_ns,
            "TIMEOUT_TERMINAL_ACTUAL_DEADLINE",
        )?;
        let observed = number(&command, "completed_monotonic_ns")?;
        check(
            command["returncode"] == 0
                && command["timed_out"] == false
                && command["direct_child_waited"] == true
                && number(&command, "original_proof_deadline_ns")?
                    == s.original_deadline.deadline_ns
                && observed >= number(&v, "completed_monotonic_ns")?
                && number(&v, "completed_monotonic_ns")?
                    >= number(result, "finished_monotonic_ns")?,
            "TIMEOUT_TERMINAL_PARENT_EXIT",
        )?;
        let evidence = sha256(
            &[
                b"TRNM-W1-OWNED-TERMINAL-RUNTIME3".as_slice(),
                &sha256(&terminal_raw),
                &sha256(&command_raw),
                &sha256(&start_raw),
                &sha256(&request_raw),
            ]
            .concat(),
        );
        Ok(OwnedTerminalExecutionV3 {
            job: job.clone(),
            execution_source_commitment: self.0.config_hash,
            evidence_digest: evidence,
            reason: TerminalReasonV3::TimedOut,
            resources: None,
            controller_observed: ClockCheckpointV2 {
                clock_domain: s.original_deadline.clock_domain,
                now_ns: observed,
            },
        })
    }
}

pub(super) fn record_terminal_failure(
    node: &mut Node,
    store: &mut NativeGenerationStoreV2,
    runtime: &mut LocalRuntime,
    id: Hash,
) -> Result<()> {
    use trnm_service_settlement::native_generation_budget_v2::FailureKindV2;
    let before = store.readback(id)?;
    check(
        before.failure.is_none() && before.cancellation.is_none(),
        "TIMEOUT_TERMINAL_EVENT_ORDER",
    )?;
    let failure = {
        let mut terminal = TerminalRuntime(&mut *runtime);
        let mut owner = NodeGenerationOwnerV2::new(node, &mut terminal)?;
        owner.reconcile_terminal_failure(store, id)?
    };
    let after = store.readback(id)?;
    check(
        failure.kind == FailureKindV2::Unknown
            && failure.consumed.is_none()
            && after.failure == Some(failure.clone())
            && after.cancellation.is_none()
            && after.resource_charge == before.statement.resource_cap,
        "TIMEOUT_TERMINAL_UNKNOWN_RECORDED",
    )?;
    write_new(
        &PathBuf::from(text(&runtime.config, "out")?).join("m12-terminal-failure-observed.json"),
        &json!({"schema":"TRNM-W1-ACTUAL-TIMEOUT-M12-FAILURE1",
            "statement":hex::encode(id),"operation":hex::encode(before.statement.provider_operation),
            "failure_kind":"Unknown","consumed":Value::Null,
            "evidence_digest":hex::encode(failure.evidence_digest),
            "recorded_before_owner_veto":true,"cancellation_at_failure":Value::Null,
            "m12_resource_cap_retained":true,"native_refund_authorized":false,
            "provider_payment_authorized":false,"recorded_monotonic_ns":now_ns()?}),
    )
}

pub(super) fn replay_terminal_failure(
    node: &mut Node,
    store: &mut NativeGenerationStoreV2,
    runtime: &mut LocalRuntime,
    id: Hash,
) -> Result<()> {
    let before = store.readback(id)?;
    let expected = before
        .failure
        .as_ref()
        .ok_or(error("TIMEOUT_FAILURE_MISSING"))?;
    let mut terminal = TerminalRuntime(&mut *runtime);
    let mut owner = NodeGenerationOwnerV2::new(node, &mut terminal)?;
    check(
        owner.reconcile_terminal_failure(store, id)? == *expected && store.readback(id)? == before,
        "TIMEOUT_FAILURE_COLD_REPLAY_CHANGED",
    )
}
