//! Explicit research-owner intent, real target cancellation, then cold readback.
//! No successful verifier fixture is used. Native tag 3 is a separate ordinary
//! owner-authorized action; it never releases unknown M12 resource reservations.
use super::*;
use crate::Node;
use std::os::unix::process::ExitStatusExt;
use trnm_protocol::pon_wire::Envelope;
use trnm_service_settlement::native_generation_budget_v2::{ConfigurationV2, GenerationReadbackV2};

const RUNTIME_SCHEMA: &str = "TRNM-W1-OWNER-CANCELLATION-RUNTIME1";
const INTENT_SCHEMA: &str = "TRNM-W1-EXPLICIT-OWNER-CANCEL1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Plan {
    reason: Hash,
    cancel_native: bool,
    deadline_trigger: bool,
}
impl Plan {
    pub(super) fn parse(c: &Value) -> Result<Self> {
        let p = c["owner_cancellation"]
            .as_object()
            .ok_or(error("CANCEL_EXPLICIT_PLAN"))?;
        let keys: std::collections::BTreeSet<_> = p.keys().map(String::as_str).collect();
        check(
            keys == [
                "schema",
                "authority",
                "trigger",
                "reason_sha256",
                "native_task_action",
            ]
            .into_iter()
            .collect(),
            "CANCEL_PLAN_FIELDS",
        )?;
        let p = &c["owner_cancellation"];
        check(
            p["authority"] == "development-owner-0" && c["provider"]["kind"] != "kaggle-cli",
            "CANCEL_PLAN_AUTHORITY",
        )?;
        let deadline_trigger = match (text(p, "schema")?, text(p, "trigger")?) {
            ("TRNM-W1-OWNER-CANCEL-PLAN1", "live-first-prove-r0vm") => false,
            ("TRNM-W1-OWNER-TIMEOUT-PLAN1", "original-deadline-after-live-first-prove-r0vm") => {
                true
            }
            _ => return Err(error("CANCEL_PLAN_DOMAIN_TRIGGER")),
        };
        let reason = json_hash(p, "reason_sha256")?;
        check(reason != [0; 32], "CANCEL_REASON")?;
        let cancel_native = match text(p, "native_task_action")? {
            "retain-reserved" => false,
            "cancel-reserved" => true,
            _ => return Err(error("CANCEL_NATIVE_ACTION")),
        };
        check(
            !deadline_trigger || cancel_native,
            "TIMEOUT_RESEARCH_REFUND_PLAN",
        )?;
        Ok(Self {
            reason,
            cancel_native,
            deadline_trigger,
        })
    }
    fn runtime_schema(&self) -> &'static str {
        if self.deadline_trigger {
            "TRNM-W1-OWNER-TIMEOUT-RUNTIME1"
        } else {
            RUNTIME_SCHEMA
        }
    }
    fn intent_schema(&self) -> &'static str {
        if self.deadline_trigger {
            "TRNM-W1-EXPLICIT-OWNER-TIMEOUT1"
        } else {
            INTENT_SCHEMA
        }
    }
}

pub(super) struct Run {
    pub config_path: PathBuf,
    pub config: Value,
    pub config_hash: Hash,
    pub out: PathBuf,
    pub node: Node,
    pub store: NativeGenerationStoreV2,
    pub runtime: LocalRuntime,
    pub configuration: ConfigurationV2,
    pub node_path: PathBuf,
    pub task: Hash,
    pub id: Hash,
    pub statement: GenerationStatementV2,
    pub reserve_tip: Hash,
    pub reserve_nonce: u64,
    pub request_path: PathBuf,
}

fn write_bytes_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    File::open(path.parent().ok_or(error("CANCEL_PARENT"))?)?.sync_all()?;
    Ok(())
}

fn requested_decision(before: &GenerationReadbackV2, owner: Hash, operation: Hash) -> &'static str {
    if before.statement.owner != owner
        || before.statement.provider_operation != operation
        || !before.dispatch_intent
    {
        "UnauthorizedOrUnbound"
    } else if before.settlement.is_some() {
        "TooLate"
    } else if before.cancellation.is_some() {
        "PriorCancellationReconcileOnly"
    } else {
        "MayRequest"
    }
}

fn observed_veto(
    before: &GenerationReadbackV2,
    after: &GenerationReadbackV2,
    reason: Hash,
) -> Result<Value> {
    check(
        before.statement == after.statement
            && after.dispatch_intent
            && after.cancellation == Some(reason)
            && after.settlement.is_none(),
        "CANCEL_COMMITTED_REASON_CHANGED",
    )?;
    check(
        after.resource_charge == before.resource_charge,
        "CANCEL_RESOURCE_RESERVATION_CHANGED",
    )?;
    // The existing M12 API returns unit for both append and Replay. A competing
    // same-reason request may have won the race; this observation never claims
    // a new event. Authority is the current explicit durable owner request plus
    // the original operation's matching retained veto, not presumed newness.
    Ok(
        json!({"decision":"CancellationObserved","accepted_observed":true,
        "new_event_proven":false,"journal_event_new":Value::Null,"target_cancel_authorized":true,
        "reason_sha256":hex::encode(reason),"resource_reservation_released":false}),
    )
}

fn require_existing_dispatch(before: &GenerationReadbackV2) -> Result<()> {
    check(
        before.dispatch_intent,
        "CANCEL_COLD_PREPARED_IS_NOT_DISPATCHED",
    )
}

/// Success here grants only the retained local service veto. It does not signal
/// any process, sign a transaction, or infer refund/resource release.
fn commit_owner_veto(
    store: &mut NativeGenerationStoreV2,
    id: Hash,
    owner: Hash,
    operation: Hash,
    reason: Hash,
) -> Result<Value> {
    let before = store.readback(id)?;
    let decision = requested_decision(&before, owner, operation);
    if decision != "MayRequest" {
        return Ok(
            json!({"decision":decision,"accepted_observed":false,"new_event_proven":false,"target_cancel_authorized":false}),
        );
    }
    match store.cancel(id, reason) {
        Ok(()) => {
            let after = store.readback(id)?;
            observed_veto(&before, &after, reason)
        }
        Err(failure) => Ok(
            json!({"decision":"UnknownOrTooLate","accepted_observed":false,"new_event_proven":false,"target_cancel_authorized":false,
            "error":failure.to_string(),"follow_up":"read original journal/effect only; do not infer acceptance or resend"}),
        ),
    }
}

fn command(
    c: &Value,
    config_hash: Hash,
    directory: &Path,
    argv: &[String],
    bounded_seconds: Option<u64>,
) -> Result<Value> {
    check(
        sha256(&bytes(Path::new(text(c, "_config_path")?), 131072)?) == config_hash,
        "CANCEL_CONFIG_CHANGED",
    )?;
    check(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            == text(c, "original_boot_id")?,
        "CANCEL_BOOT_CHANGED",
    )?;
    fs::create_dir(directory)?;
    let started = now_ns()?;
    let deadline = match bounded_seconds {
        Some(seconds) => started
            .checked_add(seconds * 1_000_000_000)
            .ok_or(error("CANCEL_CLOCK_OVERFLOW"))?,
        None => number(c, "original_deadline_ns")?
            .checked_add(10_000_000_000)
            .ok_or(error("CANCEL_CLOCK_OVERFLOW"))?,
    };
    write_new(
        &directory.join("intent.json"),
        &json!({"schema":"TRNM-W1-OWNER-CANCEL-COMMAND1","argv":argv,
        "started_monotonic_ns":started,"observation_or_cleanup_deadline_ns":deadline,
        "original_proof_deadline_ns":number(c,"original_deadline_ns")?,"proof_deadline_renewed":false}),
    )?;
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(text(c, "repo")?)
        .stdin(Stdio::null())
        .stdout(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("stdout.log"))?,
        )
        .stderr(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("stderr.log"))?,
        )
        .spawn()?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if now_ns()? >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let caller_observed_completion = now_ns()?;
    let result = json!({"schema":"TRNM-W1-OWNER-CANCEL-COMMAND1","argv":argv,"pid":child.id(),
        "returncode":status.code(),"signal":status.signal(),"direct_child_waited":true,"timed_out":timed_out,
        "started_monotonic_ns":started,"completed_monotonic_ns":caller_observed_completion,
        "completion_observed_before_original_proof_deadline":caller_observed_completion<number(c,"original_deadline_ns")?,
        "completion_clock_scope":"actual Rust caller observed helper exit; not helper pre-handoff timestamp",
        "original_proof_deadline_ns":number(c,"original_deadline_ns")?,
        "proof_deadline_renewed":false,"stdout_sha256":hex::encode(sha256(&bytes(&directory.join("stdout.log"),8*1024*1024)?)),
        "stderr_sha256":hex::encode(sha256(&bytes(&directory.join("stderr.log"),8*1024*1024)?)),
        "all_descendants_reaped":Value::Null,"can_authorize_payment":false});
    write_new(&directory.join("result.json"), &result)?;
    Ok(result)
}

fn helper(
    c: &Value,
    config_hash: Hash,
    request: &Path,
    out: &Path,
    phase_name: &str,
    start: Option<&Path>,
) -> Result<Value> {
    let python = pin(&c["python"])?;
    let executable = pin(&c["owner_cancel_runtime"])?;
    let observed = out.join(format!("owner-cancel-{phase_name}"));
    let mut argv = vec![
        python.display().to_string(),
        executable.display().to_string(),
        phase_name.into(),
        "--config".into(),
        text(c, "_config_path")?.into(),
        "--request".into(),
        request.display().to_string(),
        "--out".into(),
        observed.display().to_string(),
    ];
    if let Some(start) = start {
        argv.extend([
            "--start".into(),
            start.display().to_string(),
            "--seconds".into(),
            "10".into(),
        ]);
    }
    let control = command(
        c,
        config_hash,
        &out.join(format!("owner-cancel-{phase_name}-command")),
        &argv,
        (phase_name == "reconcile").then_some(15),
    )?;
    check(
        control["returncode"] == 0 && control["timed_out"] == false,
        "CANCEL_OBSERVATION_COMMAND_FAILED",
    )?;
    pin(&c["owner_cancel_runtime"])?;
    let result = value(&observed.join("result.json"))?;
    check(
        result["schema"] == Plan::parse(c)?.runtime_schema()
            && result["phase"] == phase_name
            && result["phase_observation_complete"] == true
            && result["generation_operation_complete"] == false
            && result["full_proof_verified"] == false
            && result["config_sha256"] == hex::encode(config_hash)
            && result["operation"] == c["provider_operation"]
            && result["original_deadline_ns"] == c["original_deadline_ns"]
            && result["can_authorize_payment"] == false,
        "CANCEL_OBSERVATION_BINDING",
    )?;
    Ok(result)
}

fn native_cancel(
    node: &mut Node,
    out: &Path,
    task: Hash,
    statement: Hash,
    reserve_tip: Hash,
    reserve_nonce: u64,
) -> Result<Hash> {
    check(
        node.active().map_err(owner_error)?.0 == reserve_tip,
        "CANCEL_INTERVENING_NATIVE_OPERATION",
    )?;
    let row = node
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .map_err(owner_error)?
        .row
        .ok_or(error("CANCEL_NATIVE_TASK_ABSENT"))?;
    check(
        row["owner"] == hex::encode(public(0))
            && row["status"] == "reserved"
            && row["remaining"] == 1000,
        "CANCEL_NATIVE_TASK_AUTHORITY",
    )?;
    let nonce = reserve_nonce
        .checked_add(1)
        .ok_or(error("CANCEL_NONCE_RANGE"))?;
    let wire = signed(&node.settings, 0, nonce, 3, task.to_vec());
    let operation = Envelope::decode(&wire)
        .and_then(|tx| tx.id())
        .map_err(|failure| owner_error(format!("{failure:?}")))?;
    let height = node.record(reserve_tip).map_err(owner_error)?.height + 1;
    let packet = node
        .make_growth_consensus_maintenance(
            reserve_tip,
            vec![wire.clone()],
            public(3),
            1 + height * 10,
            4096,
        )
        .map_err(owner_error)?;
    let packet_raw = packet.encode().map_err(owner_error)?;
    write_bytes_new(&out.join("native-cancel-wire.bin"), &wire)?;
    write_bytes_new(&out.join("native-cancel-packet.bin"), &packet_raw)?;
    write_new(
        &out.join("native-cancel-dispatch-intent.json"),
        &json!({"schema":"TRNM-W1-NATIVE-TASK-CANCEL-INTENT1",
        "native_task":hex::encode(task),"generation_statement":hex::encode(statement),"owner":hex::encode(public(0)),
        "original_reserve_tip":hex::encode(reserve_tip),"exact_nonce":nonce,"operation":hex::encode(operation),
        "wire_sha256":hex::encode(sha256(&wire)),"packet_sha256":hex::encode(sha256(&packet_raw)),
        "authority":"explicit research owner request; ordinary NativeTask tag 3 while Reserved",
        "gpu_accounting_is_refund_authority":false,"resource_reservation_released":false,
        "cold_action":"observe only this exact wire/packet on canonical ancestry; never re-sign or resubmit"}),
    )?;
    let tip = node.admit_growth(&packet, 100_000).map_err(owner_error)?;
    node.activate(tip).map_err(owner_error)?;
    write_new(
        &out.join("native-cancel-submission-observed.json"),
        &json!({"schema":"TRNM-W1-NATIVE-TASK-CANCEL-SUBMISSION1",
        "operation":hex::encode(operation),"accepted_block":hex::encode(tip),"public_chain_transaction":false}),
    )?;
    Ok(tip)
}

fn observe_native(node: &Node, out: &Path, task: Hash) -> Result<Value> {
    let funding = node
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .map_err(owner_error)?;
    let intent_path = out.join("native-cancel-dispatch-intent.json");
    if !intent_path.exists() {
        return Ok(
            json!({"native_cancel_attempt_retained":false,"canonical_cancel_observed":false,"funding_row":funding.row,
            "new_transaction_submitted":false,"refund_claim":false}),
        );
    }
    let intent = value(&intent_path)?;
    let raw = bytes(&out.join("native-cancel-packet.bin"), 1024 * 1024)?;
    let wire = bytes(&out.join("native-cancel-wire.bin"), 4096)?;
    check(
        intent["native_task"] == hex::encode(task)
            && json_hash(&intent, "wire_sha256")? == sha256(&wire)
            && json_hash(&intent, "packet_sha256")? == sha256(&raw),
        "CANCEL_ORIGINAL_NATIVE_WIRE_CHANGED",
    )?;
    let envelope =
        Envelope::decode(&wire).map_err(|failure| owner_error(format!("{failure:?}")))?;
    check(
        envelope.tag == 3
            && envelope.sender == public(0)
            && envelope.payload == task
            && envelope
                .id()
                .map_err(|failure| owner_error(format!("{failure:?}")))?
                == json_hash(&intent, "operation")?,
        "CANCEL_ORIGINAL_NATIVE_OPERATION",
    )?;
    let reserve = json_hash(&intent, "original_reserve_tip")?;
    let mut cursor = funding.anchor.block;
    let mut inclusion = None;
    for _ in 0..32 {
        if cursor == node.settings.genesis() || cursor == reserve {
            break;
        }
        let packet = node.growth_packet(cursor).map_err(owner_error)?;
        if packet.encode().map_err(owner_error)? == raw {
            check(
                packet.transactions == vec![wire.clone()],
                "CANCEL_CANONICAL_EXACT_WIRE",
            )?;
            inclusion = Some(cursor);
            break;
        }
        cursor = node
            .record(cursor)
            .map_err(owner_error)?
            .parent
            .ok_or(error("CANCEL_CANONICAL_ANCESTRY"))?;
    }
    let canonical = inclusion.is_some()
        && funding.row.as_ref().is_some_and(|row| {
            row["status"] == "cancelled"
                && row["remaining"] == 0
                && row["owner"] == hex::encode(public(0))
        });
    Ok(
        json!({"native_cancel_attempt_retained":true,"original_operation":intent["operation"],
        "canonical_cancel_observed":canonical,"canonical_inclusion":inclusion.map(hex::encode),"funding_row":funding.row,
        "new_transaction_submitted":false,"refund_claim":canonical,"gross_owner_refund_units":canonical.then_some(1000),
        "refund_basis":"actual original owner-signed tag 3 in canonical ancestry; not provider status or resource accounting",
        "net_account_delta_not_claimed":true}),
    )
}

pub(super) fn run(mut run: Run) -> Result<()> {
    let plan = Plan::parse(&run.config)?;
    run.config["_config_path"] = json!(run.config_path);
    let started = helper(
        &run.config,
        run.config_hash,
        &run.request_path,
        &run.out,
        "start",
        None,
    )?;
    check(
        started["fresh_generation_started"] == true
            && started["owned_generation_still_active"] == true,
        "CANCEL_ACTUAL_EXPENSIVE_START_REQUIRED",
    )?;
    let original_job = &started["original_job"];
    check(
        original_job["operation"] == hex::encode(run.statement.provider_operation)
            && original_job["provider_namespace"] == hex::encode(run.statement.provider_namespace)
            && original_job == &started["target_readback"]["worker"],
        "CANCEL_ORIGINAL_PROVIDER_JOB",
    )?;
    run.store.bind_job(
        run.id,
        ProviderJobV2 {
            provider_namespace: run.statement.provider_namespace,
            operation: run.statement.provider_operation,
            request_digest: run.statement.request_digest,
            job_id: text(original_job, "job_id")?.into(),
        },
    )?;
    original(&run.config)?;
    let funding = run
        .node
        .native_funding_observation(NativeFundingSourceV1::Task(run.task))
        .map_err(owner_error)?;
    let row = funding.row.ok_or(error("CANCEL_NATIVE_OWNER_UNKNOWN"))?;
    check(
        funding.anchor.block == run.reserve_tip
            && row["owner"] == hex::encode(run.statement.owner)
            && run.statement.owner == public(0)
            && row["status"] == "reserved",
        "CANCEL_ACTUAL_RESEARCH_OWNER",
    )?;
    if plan.deadline_trigger {
        timeout::wait_original_deadline(&run.config, run.config_hash, &run.out)?;
    }
    let start_path = run.out.join("owner-cancel-start/result.json");
    let timeout_terminal = if plan.deadline_trigger {
        let observed = helper(
            &run.config,
            run.config_hash,
            &run.request_path,
            &run.out,
            "reconcile",
            Some(&start_path),
        )?;
        timeout::record_terminal_failure(&mut run.node, &mut run.store, &mut run.runtime, run.id)?;
        Some(observed)
    } else {
        None
    };
    write_new(
        &run.out.join("owner-cancel-requested.json"),
        &json!({"schema":plan.intent_schema(),"state":"REQUESTED",
        "owner":hex::encode(run.statement.owner),"native_task":hex::encode(run.task),"statement":hex::encode(run.id),
        "provider_operation":hex::encode(run.statement.provider_operation),"original_job":original_job,
        "reason_sha256":hex::encode(plan.reason),"start_observation_sha256":hex::encode(sha256(&bytes(&start_path,8*1024*1024)?)),
        "original_deadline_ns":number(&run.config,"original_deadline_ns")?,"native_task_action":run.config["owner_cancellation"]["native_task_action"],
        "requested_monotonic_ns":now_ns()?,"request_is_not_acceptance":true,"provider_failure_is_not_owner_authority":true}),
    )?;
    let accepted = commit_owner_veto(
        &mut run.store,
        run.id,
        run.statement.owner,
        run.statement.provider_operation,
        plan.reason,
    )?;
    write_new(&run.out.join("owner-cancel-m12-outcome.json"), &accepted)?;
    check(
        accepted["accepted_observed"] == true && accepted["target_cancel_authorized"] == true,
        "CANCEL_OWNER_REQUEST_NOT_ACCEPTED",
    )?;
    let python = pin(&run.config["python"])?;
    let target = pin(&run.config["target"])?;
    let argv = vec![
        python.display().to_string(),
        target.display().to_string(),
        "cancel".into(),
        "--root".into(),
        text(&run.config, "target_root")?.into(),
        "--target".into(),
        text(&run.config, "target_instance")?.into(),
        "--operation".into(),
        hex::encode(run.statement.provider_operation),
    ];
    let target_command = if plan.deadline_trigger {
        json!({"target_cancel_request_sent":false,"reason":"original deadline owns target termination",
            "original_deadline_ns":run.statement.original_deadline.deadline_ns,"deadline_renewed":false})
    } else {
        command(
            &run.config,
            run.config_hash,
            &run.out.join("owner-target-cancel-command"),
            &argv,
            Some(10),
        )?
    };
    // Even an absent/lost ACK is retained. Reconciliation below never resends.
    let terminal = match timeout_terminal {
        Some(observed) => observed,
        None => helper(
            &run.config,
            run.config_hash,
            &run.request_path,
            &run.out,
            "reconcile",
            Some(&start_path),
        )?,
    };
    check(
        (if plan.deadline_trigger {
            terminal["original_deadline_timeout_observed"] == true
                && terminal["cancellation_observed"] == false
        } else {
            terminal["cancellation_observed"] == true
        }) && terminal["original_target_execution_terminal"] == true
            && terminal["gpu_ns"].is_null()
            && terminal["resource_reservation_must_remain"] == true,
        "CANCEL_TERMINAL_UNKNOWN",
    )?;
    let provider_before = balance(&run.node, public(1));
    if plan.cancel_native {
        native_cancel(
            &mut run.node,
            &run.out,
            run.task,
            run.id,
            run.reserve_tip,
            run.reserve_nonce,
        )?;
    }
    let before = run.store.readback(run.id)?;
    check(
        before.cancellation == Some(plan.reason)
            && before.verified.is_none()
            && before.settlement.is_none()
            && before.historical_payment.is_none()
            && before.resource_charge == run.statement.resource_cap,
        "CANCEL_M12_FULL_RESERVATION_REQUIRED",
    )?;
    drop(run.store);
    drop(run.node);
    let mut node = open(&run.node_path, StateBackend::PermanentAccountGrowthV2);
    let mut store = NativeGenerationStoreV2::open(
        &run.out.join("native-generation-v2.sqlite"),
        run.configuration.clone(),
    )?;
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut run.runtime)?;
        check(
            matches!(store.begin(&mut owner, run.id)?, DispatchDecisionV2::Done),
            "CANCEL_COLD_REDISPATCH",
        )?;
    }
    check(
        store.readback(run.id)? == before && balance(&node, public(1)) == provider_before,
        "CANCEL_COLD_STATE_OR_PAYMENT_CHANGED",
    )?;
    if plan.deadline_trigger {
        timeout::replay_terminal_failure(&mut node, &mut store, &mut run.runtime, run.id)?;
    }
    let reorg = if plan.deadline_trigger {
        let context = timeout::Reorg {
            node_path: &run.node_path,
            out: &run.out,
            configuration: run.configuration,
            task: run.task,
            id: run.id,
            reserve_tip: run.reserve_tip,
            retained: &before,
        };
        let (reopened_node, reopened_store, result) = context.run(node, store, &mut run.runtime)?;
        node = reopened_node;
        store = reopened_store;
        check(
            store.readback(run.id)? == before,
            "TIMEOUT_REORG_FINAL_JOURNAL",
        )?;
        result
    } else {
        Value::Null
    };
    let native = observe_native(&node, &run.out, run.task)?;
    check(
        !plan.cancel_native || native["canonical_cancel_observed"] == true,
        "CANCEL_NATIVE_CANONICAL_UNKNOWN",
    )?;
    write_new(
        &run.out.join("funded-owner-cancellation-result.json"),
        &json!({"schema":if plan.deadline_trigger {"TRNM-W1-FUNDED-OWNER-TIMEOUT-RESULT1"}else{"TRNM-W1-FUNDED-OWNER-CANCEL-RESULT1"},
        "original_deadline_timeout_observed":plan.deadline_trigger,"native_reorg_roundtrip":reorg,
        "explicit_owner_cancel_accepted":true,"real_expensive_generation_started":true,"fresh_generation_attempts":1,
        "new_complete_proofs":0,"full_proof_verified":false,"original_provider_operation":hex::encode(run.statement.provider_operation),
        "target_cancel_command":target_command,"target_terminal_observation":terminal,"native_task":native,
        "m12_cancellation_reason":hex::encode(plan.reason),"m12_failure_kind":before.failure.as_ref().map(|f|format!("{:?}",f.kind)),
        "m12_terminal_failure_recorded_before_owner_veto":plan.deadline_trigger,"m12_cold_begin":"Done","m12_original_resource_cap_retained":true,
        "gpu_accounting":"UNKNOWN","node_positive":false,"provider_payment_observed":false,"public_chain_transactions_sent":false,
        "original_deadline_ns":number(&run.config,"original_deadline_ns")?,"deadline_renewed":false,
        "all_descendants_reaped":Value::Null,"production_qualified":false}),
    )?;
    Ok(())
}

pub(super) fn cold_reconcile(config_path: &Path, output: &Path) -> Result<()> {
    let raw = bytes(config_path, 131072)?;
    let mut c: Value = serde_json::from_slice(&raw).map_err(owner_error)?;
    let plan = Plan::parse(&c)?;
    let original_out = PathBuf::from(text(&c, "out")?);
    let requested = value(&original_out.join("owner-cancel-requested.json"))?;
    check(
        requested["schema"] == plan.intent_schema()
            && requested["state"] == "REQUESTED"
            && json_hash(&requested, "reason_sha256")? == plan.reason,
        "CANCEL_RETAINED_REQUEST_REQUIRED",
    )?;
    let declared = value(&original_out.join("owner-declaration.json"))?;
    check(
        json_hash(&declared, "config_sha256")? == sha256(&raw),
        "CANCEL_ORIGINAL_CONFIG_REQUIRED",
    )?;
    let node_path = PathBuf::from(text(&declared, "research_node_path")?);
    let journal = original_out.join("native-generation-v2.sqlite");
    check(
        node_path.exists() && journal.is_file() && output.is_absolute() && !output.exists(),
        "CANCEL_EXISTING_DURABLE_STATE_REQUIRED",
    )?;
    fs::create_dir(output)?;
    let mut node = open(&node_path, StateBackend::PermanentAccountGrowthV2);
    let mut store = NativeGenerationStoreV2::open(&journal, configuration(&node))?;
    let id = json_hash(&requested, "statement")?;
    let before = store.readback(id)?;
    // This guard precedes begin: a Prepared record must never be advanced by a
    // reader merely to discover that the decision would have been New.
    require_existing_dispatch(&before)?;
    let funded = value(&original_out.join("native-funded-intent.json"))?;
    let request = value(&original_out.join("target-request.json"))?;
    let mut normalized_request = request.clone();
    normalized_request
        .as_object_mut()
        .ok_or(error("CANCEL_COLD_REQUEST_OBJECT"))?
        .remove("statement");
    let bound_job = before
        .job
        .as_ref()
        .ok_or(error("CANCEL_COLD_JOB_REQUIRED"))?;
    let retained_job = &requested["original_job"];
    check(
        before.statement.id()? == id
            && before.statement.execution_source_commitment == sha256(&raw)
            && before.statement.provider_operation == json_hash(&requested, "provider_operation")?
            && before.statement.provider_operation == json_hash(&c, "provider_operation")?
            && before.statement.owner == json_hash(&requested, "owner")?
            && before.statement.task == json_hash(&requested, "native_task")?
            && before.statement.original_deadline.deadline_ns
                == number(&c, "original_deadline_ns")?
            && before.statement.original_deadline.clock_domain == clock_domain(&c)?
            && funded["schema"] == "TRNM-W1-FUNDED-DISPATCH2"
            && json_hash(&funded, "statement")? == id
            && json_hash(&funded, "task")? == before.statement.task
            && json_hash(&funded, "journal_identity")? == store.journal_identity()
            && json_hash(&funded, "normalized_request_digest")? == before.statement.request_digest
            && json_hash(&funded, "target_request_sha256")?
                == sha256(&serde_json::to_vec(&request).map_err(owner_error)?)
            && before.statement.request_digest
                == sha256(&serde_json::to_vec(&normalized_request).map_err(owner_error)?)
            && json_hash(&request, "statement")? == id
            && bound_job.provider_namespace == before.statement.provider_namespace
            && bound_job.operation == before.statement.provider_operation
            && bound_job.request_digest == before.statement.request_digest
            && bound_job.job_id == text(retained_job, "job_id")?
            && json_hash(retained_job, "provider_namespace")? == bound_job.provider_namespace
            && json_hash(retained_job, "operation")? == bound_job.operation,
        "CANCEL_COLD_ORIGINAL_IDENTITY",
    )?;
    let mut runtime = LocalRuntime {
        config_path: config_path.into(),
        config: c.clone(),
        config_hash: sha256(&raw),
        generation: None,
        evidence_digest: [0; 32],
    };
    let replay = {
        let mut owner = NodeGenerationOwnerV2::new(&mut node, &mut runtime)?;
        store.begin(&mut owner, id)?
    };
    check(
        !matches!(replay, DispatchDecisionV2::New) && store.readback(id)? == before,
        "CANCEL_COLD_REDISPATCH",
    )?;
    let replay_label = match replay {
        DispatchDecisionV2::Pending => "Pending",
        DispatchDecisionV2::Done => "Done",
        DispatchDecisionV2::New => return Err(error("CANCEL_COLD_REDISPATCH")),
    };
    let native = observe_native(&node, &original_out, before.statement.task)?;
    // This calls only the target's existing observation endpoint. The returned
    // terminal result is the original worker's retained snapshot; it cannot
    // prove that every historical descendant was wait/reaped by this reader.
    c["_config_path"] = json!(config_path);
    let target_observation = if fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
        == text(&c, "original_boot_id")?
    {
        let python = pin(&c["python"])?;
        let target = pin(&c["target"])?;
        let argv = vec![
            python.display().to_string(),
            target.display().to_string(),
            "reconcile".into(),
            "--root".into(),
            text(&c, "target_root")?.into(),
            "--target".into(),
            text(&c, "target_instance")?.into(),
            "--operation".into(),
            hex::encode(before.statement.provider_operation),
        ];
        let control = command(
            &c,
            sha256(&raw),
            &output.join("target-reconcile"),
            &argv,
            Some(10),
        )?;
        if control["returncode"] == 0 && control["timed_out"] == false {
            let observed = value(&output.join("target-reconcile/stdout.log"))?;
            check(
                observed["operation"] == hex::encode(before.statement.provider_operation)
                    && observed["worker"]["job_id"].as_str()
                        == before.job.as_ref().map(|job| job.job_id.as_str()),
                "CANCEL_COLD_ORIGINAL_TARGET_JOB",
            )?;
            json!({"state":"OBSERVED","retained_target_readback":observed,"actual_command":control,
                "fresh_recursive_process_scope_qualification":false})
        } else {
            json!({"state":"UNKNOWN","actual_command":control,"may_dispatch_again":false})
        }
    } else {
        json!({"state":"UNKNOWN","reason":"original boot changed; no rebasing or target mutation",
            "may_dispatch_again":false})
    };
    write_new(
        &output.join("result.json"),
        &json!({"schema":if plan.deadline_trigger {"TRNM-W1-OWNER-TIMEOUT-COLD-READBACK1"}else{"TRNM-W1-OWNER-CANCEL-COLD-READBACK1"},
        "original_statement":hex::encode(id),"original_operation":hex::encode(before.statement.provider_operation),
        "cancellation":before.cancellation.map(hex::encode),"original_resource_cap_retained":before.resource_charge==before.statement.resource_cap,
        "m12_begin":replay_label,"native_task":native,"new_generation_dispatches":0,"target_cancel_requests_sent":0,
        "native_transactions_submitted":0,"deadline_renewed":false,"original_deadline_ns":number(&c,"original_deadline_ns")?,
        "target_observation":target_observation,
        "target_process_scope_reconciled_by_this_reader":false,"target_scope_qualification":"retained worker result plus current worker identity only; never infer full recursive scope from M12",
        "can_authorize_payment":false,"production_qualified":false}),
    )?;
    Ok(())
}

mod timeout;

#[cfg(test)]
mod tests;
