//! Recovery evidence for one already paid local development service owner.
//!
//! This additive probe never signs a service transaction, pays a second service
//! fee, changes a model or edits an owner database. It uses the original Node
//! fork choice to execute bounded empty maintenance branches. Ordinary protocol
//! block subsidies are retained and reported separately from learning rewards.
//! A persisted phase intent is a once fence: repeat or crash recovery is query
//! only. There is deliberately no reset, resume, force or alternate namespace.
#[path = "learning_service_recovery_binding.rs"]
mod binding;

use binding::{check, decode, digest, field_digest, read, sha, Request, MAX_JSON};
use fs2::FileExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::consensus::Work;
use trnm_pon_node::{development_public, Node, Packet, Result, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::task_operation_v2::{
    NativeTaskOperationBindingV2, NativeTaskOperationSnapshotV2, NativeTaskOperationStoreV2,
};
use trnm_service_settlement::native_budget::{NativeBudgetConfigV1, NativeBudgetResourcesV1};

const SCHEMA: &str = "native-learning-service-recovery-probe-v1";
const ROUND_SCHEMA: &str = "native-learning-service-round-v1";
const DIRECTORY: &str = "recovery-probe-v1";
const CLOCK: u64 = 100_000;
const EPOCH: u64 = 1;

fn owner(error: impl std::fmt::Display) -> trnm_pon_node::Error {
    error.to_string().into()
}

fn settings() -> Result<Settings> {
    Settings::development_with_funded_service_contract_v1(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
}

fn configuration(cfg: &Settings) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: cfg.network(),
        parameters: cfg.parameters(),
        genesis: cfg.genesis(),
        max_records: 4,
    }
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn directory(path: &Path, private: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    check(
        path.is_absolute()
            && path.canonicalize()? == path
            && metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && (!private || metadata.mode() & 0o077 == 0),
        "RECOVERY_ORIGINAL_PRIVATE_DIRECTORY",
    )
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn save_new(path: &Path, value: &Value) -> Result<()> {
    let raw = serde_json::to_vec(value)?;
    check(raw.len() as u64 <= MAX_JSON, "RECOVERY_FILE_BOUND")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&raw)?;
    file.sync_all()?;
    sync_directory(path.parent().ok_or("RECOVERY_PARENT")?)
}

fn original_lock(path: &Path) -> Result<File> {
    directory(path, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("round.lock"))?;
    let metadata = file.metadata()?;
    check(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "RECOVERY_ORIGINAL_LOCK",
    )?;
    FileExt::try_lock_exclusive(&file)?;
    Ok(file)
}

fn model_state(node: &Node) -> Result<Value> {
    let values: Vec<_> = node
        .read_active()?
        .2
        .into_iter()
        .filter(|(key, _)| {
            key == "model:current"
                || key.starts_with("release:")
                || key.starts_with("contribution:")
        })
        .collect();
    Ok(serde_json::to_value(values)?)
}

fn monetary_state(node: &Node) -> Result<Value> {
    let state = node.read_active()?.2;
    let rewards: Vec<_> = state
        .iter()
        .filter(|(key, _)| key.starts_with("reward:"))
        .collect();
    let queued = rewards.iter().try_fold(0_u64, |total, (_, value)| {
        total
            .checked_add(value["amount"].as_u64().ok_or("RECOVERY_REWARD_STATE")?)
            .ok_or("RECOVERY_REWARD_OVERFLOW")
    })?;
    Ok(
        json!({"unit":"development-native-units","meta_issued":state.get("meta:issued"),
        "reward_queue_entries":rewards.len(),"reward_queue_amount":queued,
        "ordinary_protocol_subsidy_preserved":true,"learning_improvement_bonus":0,
        "additional_service_payment":0,"anti_sybil_useful_work_credit":0}),
    )
}

struct Definition {
    request: Request,
    contract: FundedServiceContractV1,
    binding: NativeTaskOperationBindingV2,
    intent: Hash,
    identity: Value,
    baseline: Value,
}

impl Definition {
    fn derive(request_raw: &[u8], plan_raw: &[u8], baseline_raw: &[u8]) -> Result<Self> {
        let plan = decode(plan_raw)?;
        let request = Request::parse(request_raw, &plan)?;
        let baseline = decode(baseline_raw)?;
        let cfg = settings()?;
        let operation = request.native_operation()?;
        let request_id = hash(
            b"native-learning-service-request-v1",
            &[&sha(request_raw), &sha(plan_raw), &sha(baseline_raw)],
        );
        let contract = FundedServiceContractV1 {
            request: request_id,
            provider: development_public(1)?,
            model: field_digest(&plan["parent"], "adapter")?,
            input: field_digest(&plan, "inputs_sha256")?,
            output_spec: hash(b"native-learning-service-output-spec-v1", &[
                b"complete inherited training output and original operation receipt; no gain requirement",
                &sha(plan_raw)]),
            qualified_work: hash(b"native-learning-service-work-v1", &[&operation, &sha(plan_raw)]),
            evaluation_protocol: digest(&request.evaluation_protocol_sha256)?,
            fee_schedule: hash(b"native-learning-base-fee-v1", &[&request.base_fee.to_le_bytes(),
                b"completed commissioned training service; bonus and consensus credit zero"]),
            dispute_policy: hash(b"native-learning-local-arbitration-v1", &[
                b"development same-operator receipt acceptance; no independent customer claim"]),
            arbitrator: development_public(2)?,
            budget: request.base_fee,
            delivery_deadline: 12,
            dispute_deadline: 24,
        };
        contract.validate().map_err(|_| "RECOVERY_CONTRACT")?;
        let task = contract.task_id(cfg.network(), cfg.parameters(), development_public(0)?, 1);
        let contract_digest =
            contract.digest(cfg.network(), cfg.parameters(), development_public(0)?);
        let binding = NativeTaskOperationBindingV2 {
            claim: hash(b"native-learning-service-claim-v1", &[&task, &operation]),
            task,
            contract_digest,
            operation,
            beneficiary: contract.provider,
            target_scope: hash(
                b"native-learning-service-target-v1",
                &[
                    &sha(plan_raw),
                    request.output_directory.as_bytes(),
                    &digest(&request.provider_authority_id)?,
                ],
            ),
            resource_cap: NativeBudgetResourcesV1::Contribution {
                training_cpu_ns: request.training_cpu_cap_ns,
                parameter_bytes: request.parameter_byte_cap,
            },
        };
        let intent = hash(
            b"native-learning-service-intent-v1",
            &[&binding.encode().map_err(owner)?, &request_id],
        );
        let identity = json!({"schema":ROUND_SCHEMA,"request_sha256":hex::encode(sha(request_raw)),
            "plan_sha256":hex::encode(sha(plan_raw)),"baseline_sha256":hex::encode(sha(baseline_raw)),
            "contract":contract,"binding_hex":hex::encode(binding.encode().map_err(owner)?),
            "intent_sha256":hex::encode(intent),"consumer_epoch":EPOCH});
        Ok(Self {
            request,
            contract,
            binding,
            intent,
            identity,
            baseline,
        })
    }
}

struct BoundRound {
    def: Definition,
    pins: Value,
    payment: Packet,
    snapshot: NativeTaskOperationSnapshotV2,
    m12: Value,
}

fn packet_intent(
    raw: &[u8],
    def: &Definition,
    sender: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Packet> {
    let value = decode(raw)?;
    let wire = hex::decode(value["wire_hex"].as_str().ok_or("RECOVERY_WIRE")?).map_err(owner)?;
    let tx = Envelope::decode(&wire).map_err(|_| "RECOVERY_WIRE")?;
    let encoded =
        hex::decode(value["packet_hex"].as_str().ok_or("RECOVERY_PACKET")?).map_err(owner)?;
    let packet = Packet::decode(&encoded)?;
    check(
        value.as_object().is_some_and(|m| m.len() == 7)
            && value["schema"] == "native-learning-service-effect-intent-v1"
            && field_digest(&value, "service_intent_sha256")? == def.intent
            && field_digest(&value, "operation")? == tx.id().map_err(|_| "RECOVERY_WIRE")?
            && field_digest(&value, "packet_sha256")? == sha(&encoded)
            && field_digest(&value, "packet_id")? == packet.id()?
            && packet.encode()? == encoded
            && packet.transactions == vec![wire]
            && tx.network == settings()?.network()
            && tx.sender == development_public(sender)?
            && tx.nonce == 1
            && tx.expiry == 128
            && tx.fee_limit == 1_000_000
            && tx.tag == tag
            && tx.payload == payload,
        "RECOVERY_ORIGINAL_PACKET",
    )?;
    Ok(packet)
}

fn load_round(
    path: &Path,
    identity_sha: Hash,
    intent: Hash,
    operation: &str,
) -> Result<(BoundRound, Node, NativeTaskOperationStoreV2)> {
    let mut raws = BTreeMap::new();
    for name in [
        "identity.json",
        "request.json",
        "execution-plan.json",
        "initial-model-state.json",
        "prepared.json",
        "terminal.json",
        "provider-readback.json",
        "reservation-intent.json",
        "delivery-intent.json",
        "payment-intent.json",
    ] {
        raws.insert(name, read(&path.join(name), MAX_JSON)?);
    }
    check(
        sha(&raws["identity.json"]) == identity_sha,
        "RECOVERY_EXPECTED_IDENTITY",
    )?;
    let def = Definition::derive(
        &raws["request.json"],
        &raws["execution-plan.json"],
        &raws["initial-model-state.json"],
    )?;
    check(
        def.intent == intent
            && def.request.operation_id == operation
            && decode(&raws["identity.json"])? == def.identity,
        "RECOVERY_EXPECTED_OPERATION",
    )?;
    let prepared = decode(&raws["prepared.json"])?;
    check(
        prepared["schema"] == ROUND_SCHEMA
            && prepared["status"] == "PREPARED"
            && prepared["dispatch_allowed"] == true
            && prepared["operation_id"] == operation
            && prepared["provider_authority_id"] == def.request.provider_authority_id
            && field_digest(&prepared, "intent_sha256")? == intent
            && prepared["plan_sha256"] == def.identity["plan_sha256"]
            && prepared["evaluation_profile_sha256"] == def.request.evaluation_protocol_sha256
            && field_digest(&prepared, "claim")? == def.binding.claim
            && field_digest(&prepared, "task")? == def.binding.task
            && field_digest(&prepared, "native_operation")? == def.binding.operation
            && field_digest(&prepared, "contract_digest")? == def.binding.contract_digest
            && prepared["original_contract"] == serde_json::to_value(&def.contract)?,
        "RECOVERY_PREPARED_BINDING",
    )?;
    let terminal = decode(&raws["terminal.json"])?;
    check(
        terminal["schema"] == "native-learning-service-terminal-v1"
            && field_digest(&terminal, "intent_sha256")? == intent
            && terminal["no_update_decided"] == false
            && terminal["independent_evaluation_accepted"] == false,
        "RECOVERY_ORIGINAL_TERMINAL",
    )?;
    let output = field_digest(&terminal, "output")?;
    let receipt = field_digest(&terminal, "target_receipt")?;
    let reservation = packet_intent(
        &raws["reservation-intent.json"],
        &def,
        0,
        2,
        FundedServiceReservationV1 {
            task: def.binding.task,
            contract: def.contract.clone(),
        }
        .encode()
        .map_err(|_| "RECOVERY_CONTRACT_ENCODING")?,
    )?;
    let mut payload = def.binding.task.to_vec();
    payload.extend(output);
    let delivery = packet_intent(&raws["delivery-intent.json"], &def, 1, 4, payload)?;
    let payment = packet_intent(
        &raws["payment-intent.json"],
        &def,
        2,
        5,
        FundedServiceDecisionV1 {
            task: def.binding.task,
            contract_digest: def.binding.contract_digest,
            output,
            evidence: receipt,
            verdict: FundedServiceVerdictV1::PayProvider,
        }
        .encode()
        .map_err(|_| "RECOVERY_CONTRACT_ENCODING")?,
    )?;
    directory(&path.join("native"), false)?;
    // Refuse any missing owner rather than letting open initialize a new one.
    for file in ["native/native.sqlite", "operations.sqlite"] {
        let pathname = path.join(file);
        let metadata = fs::symlink_metadata(&pathname)?;
        check(
            pathname.canonicalize()? == pathname
                && metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw(),
            "RECOVERY_ORIGINAL_OWNER",
        )?;
    }
    let cfg = settings()?;
    let node = Node::open_with_authenticated_state(&path.join("native"), cfg.clone(), 1)?;
    let store =
        NativeTaskOperationStoreV2::open(&path.join("operations.sqlite"), configuration(&cfg))
            .map_err(owner)?;
    for packet in [&reservation, &delivery, &payment] {
        check(
            node.packet(packet.id()?)?.encode()? == packet.encode()?,
            "RECOVERY_ORIGINAL_STORED_PACKET",
        )?;
    }
    let snapshot = store.snapshot(def.binding.claim).map_err(owner)?;
    let completion = snapshot
        .completion
        .as_ref()
        .ok_or("RECOVERY_COMPLETION_REQUIRED")?;
    let paid = snapshot
        .payment
        .as_ref()
        .ok_or("RECOVERY_PAYMENT_REQUIRED")?;
    let delivered = snapshot
        .delivery
        .as_ref()
        .ok_or("RECOVERY_DELIVERY_REQUIRED")?;
    let id = |p: &Packet| -> Result<Hash> {
        Envelope::decode(&p.transactions[0])
            .and_then(|t| t.id())
            .map_err(|_| "RECOVERY_WIRE".into())
    };
    check(
        snapshot.binding == def.binding
            && snapshot.begun.is_some()
            && snapshot.costs.is_some()
            && completion.operation == def.binding.operation
            && completion.output == output
            && completion.target_receipt == receipt
            && delivered.receipt_operation == id(&delivery)?
            && paid.operation == id(&payment)?
            && paid.beneficiary == def.binding.beneficiary
            && paid.subject == output
            && paid.gross_escrow_debit == def.request.base_fee
            && paid.beneficiary_credit == def.request.base_fee,
        "RECOVERY_ORIGINAL_M12",
    )?;
    let m12 = store.report().map_err(owner)?;
    let pins: BTreeMap<_, _> = raws
        .into_iter()
        .map(|(name, raw)| (name, hex::encode(sha(&raw))))
        .collect();
    Ok((
        BoundRound {
            def,
            pins: serde_json::to_value(pins)?,
            payment,
            snapshot,
            m12,
        },
        node,
        store,
    ))
}

fn revoked(path: &Path, def: &Definition) -> Result<bool> {
    let marker = path.join("revoked.json");
    if !exists(&marker)? {
        return Ok(false);
    }
    check(
        decode(&read(&marker, MAX_JSON)?)?
            == json!({
        "schema":"native-learning-service-local-revocation-v1","intent_sha256":hex::encode(def.intent),
        "native_operation":hex::encode(def.binding.operation),"consumer_epoch":EPOCH,
        "provider_cancellation_observed":false}),
        "RECOVERY_REVOCATION_CHANGED",
    )?;
    Ok(true)
}

fn work(value: &Value) -> Result<Work> {
    let bytes: [u8; 64] = hex::decode(value.as_str().ok_or("RECOVERY_WORK")?)
        .map_err(owner)?
        .try_into()
        .map_err(|_| "RECOVERY_WORK")?;
    Ok(Work::from_bytes(bytes))
}

fn observation(
    path: &Path,
    bound: &BoundRound,
    node: &Node,
    store: &NativeTaskOperationStoreV2,
) -> Result<Value> {
    check(
        store.snapshot(bound.def.binding.claim).map_err(owner)? == bound.snapshot
            && store.report().map_err(owner)? == bound.m12,
        "RECOVERY_M12_CHANGED",
    )?;
    check(
        model_state(node)? == bound.def.baseline,
        "RECOVERY_MODEL_STATE_CHANGED",
    )?;
    let (current, error) = match node.observe_current_native_task_operation_v3(
        store,
        &bound.def.binding,
        &bound.def.contract,
        EPOCH,
    ) {
        Ok(value) => (Some(value), None),
        Err(error) if error.to_string() == "TASK_OPERATION_CURRENT_SOURCE_ABSENT_V3" => {
            (None, Some(error.to_string()))
        }
        Err(error) => return Err(error),
    };
    Ok(
        json!({"schema":SCHEMA,"scope":"LOCAL_DEVELOPMENT_SAME_OWNER_EMPTY_MAINTENANCE_RECOVERY",
        "operation_id":bound.def.request.operation_id,"intent_sha256":hex::encode(bound.def.intent),
        "native_operation":hex::encode(bound.def.binding.operation),"task":hex::encode(bound.def.binding.task),
        "claim":hex::encode(bound.def.binding.claim),"provider_authority_id":bound.def.request.provider_authority_id,
        "source_pins":bound.pins,"current_branch_base_fee":if current.is_some(){bound.def.request.base_fee}else{0},
        "historically_observed_base_fee":bound.snapshot.payment.as_ref().ok_or("RECOVERY_PAYMENT_REQUIRED")?.beneficiary_credit,
        "locally_revoked":revoked(path,&bound.def)?,"provider_cancellation_observed":false,
        "current_native_observation":current,"expected_absent_source_error":error,
        "original_payment_packet":node.exact_packet_observation(&bound.payment)?,
        "native":node.stats()?,"m12":bound.m12,"m12_unchanged":true,"model_state_unchanged":true,
        "maintenance_economics":monetary_state(node)?,"extra_service_payment":0,
        "learning_improvement_bonus":0,"anti_sybil_useful_work_credit":0,
        "service_dispatch_allowed":false,"model_execution_performed":false,"provider_receipt_reissued":false,
        "independent_customer_verified":false,"external_budget_origin_verified":false,
        "production_activation":false,"atomic_cross_owner_revocation":false}),
    )
}

fn probe_intent(
    path: &Path,
    bound: &BoundRound,
    node: &Node,
    store: &NativeTaskOperationStoreV2,
) -> Result<Value> {
    let before = observation(path, bound, node, store)?;
    let stats = &before["native"];
    let height = stats["height"].as_u64().ok_or("RECOVERY_HEIGHT")?;
    check(
        before["current_branch_base_fee"] == bound.def.request.base_fee
            && before["locally_revoked"] == false
            && field_digest(stats, "tip")? == bound.payment.id()?
            && (1..=8).contains(&height)
            && stats["stored_blocks"].as_u64() == Some(height + 1),
        "RECOVERY_FRESH_PAID_DEVELOPMENT_OWNER_REQUIRED",
    )?;
    Ok(
        json!({"schema":SCHEMA,"original_round":path,"service_intent_sha256":hex::encode(bound.def.intent),
        "operation_id":bound.def.request.operation_id,"native_operation":hex::encode(bound.def.binding.operation),
        "source_pins":bound.pins,"original_paid_tip":stats["tip"],"original_paid_height":height,
        "original_paid_chainwork_hex":stats["chainwork_hex"],"original_paid_generation":stats["generation"],
        "genesis":hex::encode(settings()?.genesis()),"reorg_empty_blocks":height+1,"restore_empty_blocks":2,
        "maximum_final_height":height+2,"m12":bound.m12,"before":before,
        "same_phase_replay":"QUERY_ONLY_NO_REDISPATCH","ordinary_protocol_subsidy_preserved":true}),
    )
}

fn load_intent(path: &Path, bound: &BoundRound) -> Result<(Value, Hash)> {
    let raw = read(&path.join(DIRECTORY).join("intent.json"), MAX_JSON)?;
    let value = decode(&raw)?;
    let height = value["original_paid_height"]
        .as_u64()
        .ok_or("RECOVERY_HEIGHT")?;
    check(
        value["schema"] == SCHEMA
            && value["original_round"] == path.to_string_lossy().as_ref()
            && field_digest(&value, "service_intent_sha256")? == bound.def.intent
            && value["operation_id"] == bound.def.request.operation_id
            && field_digest(&value, "native_operation")? == bound.def.binding.operation
            && value["source_pins"] == bound.pins
            && value["m12"] == bound.m12
            && field_digest(&value, "original_paid_tip")? == bound.payment.id()?
            && height == bound.payment.header.height
            && field_digest(&value, "genesis")? == settings()?.genesis()
            && (1..=8).contains(&height)
            && value["reorg_empty_blocks"] == height + 1
            && value["restore_empty_blocks"] == 2
            && value["maximum_final_height"] == height + 2,
        "RECOVERY_PROBE_IDENTITY",
    )?;
    Ok((value, sha(&raw)))
}

fn recorded_binding(value: &Value, bound: &BoundRound) -> Result<()> {
    check(
        value["schema"] == SCHEMA
            && value["operation_id"] == bound.def.request.operation_id
            && field_digest(value, "intent_sha256")? == bound.def.intent
            && field_digest(value, "native_operation")? == bound.def.binding.operation
            && field_digest(value, "task")? == bound.def.binding.task
            && field_digest(value, "claim")? == bound.def.binding.claim
            && value["provider_authority_id"] == bound.def.request.provider_authority_id
            && value["source_pins"] == bound.pins
            && value["m12"] == bound.m12
            && value["m12_unchanged"] == true
            && value["model_state_unchanged"] == true
            && value["historically_observed_base_fee"] == bound.def.request.base_fee
            && value["service_dispatch_allowed"] == false
            && value["model_execution_performed"] == false
            && value["provider_receipt_reissued"] == false
            && value["production_activation"] == false
            && field_digest(&value["original_payment_packet"], "block")? == bound.payment.id()?,
        "RECOVERY_RECORDED_OBSERVATION_BINDING",
    )
}

/// Native history validates each anchor against the original activation event.
/// Retaining an off-chain packet or an exported JSON receipt alone is not proof
/// that its branch was ever selected. This read performs no reconciliation.
fn activation_record(
    value: &Value,
    bound: &BoundRound,
    node: &Node,
    store: &NativeTaskOperationStoreV2,
) -> Result<Value> {
    let cfg = settings()?;
    let anchor = json!({"network":cfg.network(),"parameters":cfg.parameters(),"genesis":cfg.genesis(),
        "block":field_digest(&value["native"],"tip")?,
        "state_root":field_digest(&value["native"],"state_root")?,
        "height":value["native"]["height"].as_u64().ok_or("RECOVERY_HEIGHT")?,
        "generation":value["native"]["generation"].as_u64().ok_or("RECOVERY_GENERATION")?});
    let checkpoint = store.checkpoint().map_err(owner)?;
    let checkpoint = json!({"max_records":checkpoint.configuration.max_records,
        "sequence":checkpoint.sequence,"root":checkpoint.root});
    let history = node.native_task_operation_reconciliation_history_v2()?;
    check(
        history["schema"] == "pon-native-task-operation-reconciliation-history-v2",
        "RECOVERY_OWNER_HISTORY",
    )?;
    let binding = hex::encode(bound.def.binding.id().map_err(owner)?);
    history["records"]
        .as_array()
        .ok_or("RECOVERY_OWNER_HISTORY")?
        .iter()
        .find(|record| {
            record["claim"] == hex::encode(bound.def.binding.claim)
                && record["task"] == hex::encode(bound.def.binding.task)
                && record["binding"] == binding
                && record["consumer_epoch"] == EPOCH
                && record["anchor"] == anchor
                && record["checkpoint"] == checkpoint
        })
        .cloned()
        .ok_or_else(|| "RECOVERY_ORIGINAL_ACTIVATION_NOT_RECORDED".into())
}

fn query(
    path: &Path,
    bound: &BoundRound,
    node: &Node,
    store: &NativeTaskOperationStoreV2,
) -> Result<Value> {
    let mut value = observation(path, bound, node, store)?;
    let root = path.join(DIRECTORY);
    value["probe_state"] = "NOT_STARTED".into();
    value["maintenance_dispatch_performed"] = false.into();
    if !exists(&root)? {
        return Ok(value);
    }
    directory(&root, true)?;
    if !exists(&root.join("intent.json"))? {
        value["probe_state"] = "UNKNOWN_EMPTY_PROBE_DIRECTORY_NO_RETRY".into();
        return Ok(value);
    }
    let (intent, pin) = load_intent(path, bound)?;
    check(
        intent["original_paid_chainwork_hex"]
            == value["original_payment_packet"]["block_chainwork_hex"],
        "RECOVERY_ORIGINAL_CHAINWORK",
    )?;
    recorded_binding(&intent["before"], bound)?;
    value["original_paid_activation"] = activation_record(&intent["before"], bound, node, store)?;
    value["probe_intent_sha256"] = hex::encode(pin).into();
    value["original_paid_tip"] = intent["original_paid_tip"].clone();
    value["original_paid_chainwork_hex"] = intent["original_paid_chainwork_hex"].clone();
    value["maintenance_economics_before"] = intent["before"]["maintenance_economics"].clone();
    let mut phases = serde_json::Map::new();
    for phase in ["reorg", "restore"] {
        let maximum = if phase == "reorg" {
            intent["reorg_empty_blocks"]
                .as_u64()
                .ok_or("RECOVERY_COUNT")?
        } else {
            2
        };
        let mut packets = Vec::new();
        let start = if phase == "reorg" {
            "genesis"
        } else {
            "original_paid_tip"
        };
        let mut parent = field_digest(&intent, start)?;
        let start_height = if phase == "reorg" {
            0
        } else {
            intent["original_paid_height"]
                .as_u64()
                .ok_or("RECOVERY_HEIGHT")?
        };
        let mut missing = false;
        let mut last_packet = None;
        for index in 0..maximum {
            let name = root.join(format!("{phase}-{index:02}.json"));
            if !exists(&name)? {
                missing = true;
                continue;
            }
            check(!missing, "RECOVERY_PACKET_SEQUENCE_GAP")?;
            let retained = decode(&read(&name, MAX_JSON)?)?;
            let raw = hex::decode(retained["packet_hex"].as_str().ok_or("RECOVERY_PACKET")?)
                .map_err(owner)?;
            let packet = Packet::decode(&raw)?;
            check(
                retained["schema"] == "native-learning-empty-packet-intent-v1"
                    && field_digest(&retained, "probe_intent_sha256")? == pin
                    && retained["phase"] == phase
                    && retained["index"] == index
                    && field_digest(&retained, "packet_sha256")? == sha(&raw)
                    && field_digest(&retained, "packet_id")? == packet.id()?
                    && field_digest(&retained, "parent")? == parent
                    && packet.header.parent == parent
                    && retained["height"] == start_height + index + 1
                    && packet.header.height == start_height + index + 1
                    && packet.header.timestamp == 1 + 10 * packet.header.height
                    && packet.header.miner == development_public(3)?
                    && retained["transactions"] == 0
                    && retained["retry_allowed"] == false
                    && packet.transactions.is_empty()
                    && packet.encode()? == raw,
                "RECOVERY_RETAINED_PACKET",
            )?;
            packets.push(node.exact_packet_observation(&packet)?);
            parent = packet.id()?;
            last_packet = Some(packet);
        }
        let completed = root.join(format!("{phase}-complete.json"));
        let mut activation = None;
        let complete = if exists(&completed)? {
            let result = decode(&read(&completed, MAX_JSON)?)?;
            check(
                result["schema"] == SCHEMA
                    && result["phase"] == phase
                    && field_digest(&result, "probe_intent_sha256")? == pin
                    && packets.len() as u64 == maximum
                    && packets.iter().all(|packet| packet["stored_exact"] == true)
                    && field_digest(&result, "tip")? == parent,
                "RECOVERY_PHASE_COMPLETION",
            )?;
            let last = packets
                .last()
                .ok_or("RECOVERY_COMPLETION_PACKETS_REQUIRED")?;
            let packet = last_packet
                .as_ref()
                .ok_or("RECOVERY_COMPLETION_PACKETS_REQUIRED")?;
            let after = &result["after"];
            recorded_binding(after, bound)?;
            activation = Some(activation_record(after, bound, node, store)?);
            let expected_fee = if phase == "reorg" {
                0
            } else {
                bound.def.request.base_fee
            };
            check(
                field_digest(&after["native"], "tip")? == parent
                    && after["native"]["height"] == packet.header.height
                    && field_digest(&after["native"], "state_root")? == packet.header.state
                    && after["native"]["chainwork_hex"] == last["block_chainwork_hex"]
                    && work(&last["block_chainwork_hex"])?
                        > work(&intent["original_paid_chainwork_hex"])?
                    && after["current_branch_base_fee"] == expected_fee
                    && after["original_payment_packet"]["active_chain_member"]
                        == (phase == "restore")
                    && after["original_payment_packet"]["active_tip"] == hex::encode(parent),
                "RECOVERY_COMPLETION_ANCHOR",
            )?;
            if phase == "reorg" {
                check(
                    after["current_native_observation"].is_null()
                        && after["expected_absent_source_error"]
                            == "TASK_OPERATION_CURRENT_SOURCE_ABSENT_V3",
                    "RECOVERY_COMPLETION_SOURCE_ABSENCE",
                )?;
            } else {
                let current = &after["current_native_observation"];
                check(
                    current["schema"] == "pon-native-task-operation-current-v3"
                        && field_digest(current, "operation")? == bound.def.binding.operation
                        && field_digest(&current["current_payment"], "operation")?
                            == bound
                                .snapshot
                                .payment
                                .as_ref()
                                .ok_or("RECOVERY_PAYMENT_REQUIRED")?
                                .operation
                        && current["current_payment"]["beneficiary_credit"] == expected_fee
                        && after["expected_absent_source_error"].is_null(),
                    "RECOVERY_COMPLETION_ORIGINAL_PAYMENT",
                )?;
            }
            Some(result)
        } else {
            None
        };
        phases.insert(
            phase.into(),
            json!({"packets":packets,"completion":complete,"original_owner_activation":activation}),
        );
    }
    value["phases"] = phases.into();
    let restore_intent = root.join("restore-intent.json");
    if exists(&restore_intent)? {
        let retained = decode(&read(&restore_intent, MAX_JSON)?)?;
        let reorg = &value["phases"]["reorg"]["completion"];
        check(
            retained["schema"] == SCHEMA
                && retained["phase"] == "restore"
                && field_digest(&retained, "probe_intent_sha256")? == pin
                && field_digest(&retained, "service_intent_sha256")? == bound.def.intent
                && retained["from_original_paid_tip"] == intent["original_paid_tip"]
                && retained["empty_blocks"] == 2
                && reorg.is_object(),
            "RECOVERY_RESTORE_INTENT",
        )?;
        let before = &retained["before"];
        recorded_binding(before, bound)?;
        check(
            before["native"]["tip"] == reorg["tip"]
                && before["native"]["chainwork_hex"] == reorg["after"]["native"]["chainwork_hex"]
                && before["current_branch_base_fee"] == 0
                && before["original_payment_packet"]["active_chain_member"] == false,
            "RECOVERY_RESTORE_START",
        )?;
    } else {
        check(
            value["phases"]["restore"]["packets"]
                .as_array()
                .is_some_and(|packets| packets.is_empty())
                && value["phases"]["restore"]["completion"].is_null(),
            "RECOVERY_RESTORE_INTENT_REQUIRED",
        )?;
    }
    value["probe_state"] = if value["phases"]["restore"]["completion"].is_object() {
        "RESTORE_RECORDED_QUERY_ONLY"
    } else if exists(&root.join("restore-intent.json"))? {
        "RESTORE_ATTEMPTED_QUERY_ONLY"
    } else if value["phases"]["reorg"]["completion"].is_object() {
        "REORG_RECORDED_QUERY_ONLY"
    } else {
        "REORG_ATTEMPTED_QUERY_ONLY"
    }
    .into();
    Ok(value)
}

fn extend_once(
    path: &Path,
    node: &mut Node,
    phase: &str,
    pin: Hash,
    mut parent: Hash,
    count: u64,
) -> Result<Hash> {
    check(count <= 9, "RECOVERY_PACKET_BOUND")?;
    for index in 0..count {
        let height = node
            .parent_height(parent)?
            .checked_add(1)
            .ok_or("RECOVERY_HEIGHT")?;
        check(height <= 10, "RECOVERY_HEIGHT_BOUND")?;
        let packet = node.make_consensus_maintenance(
            parent,
            vec![],
            development_public(3)?,
            1 + 10 * height,
            4096,
        )?;
        let raw = packet.encode()?;
        let id = packet.id()?;
        // Exact packet and phase identity are durable before their one admission.
        save_new(
            &path
                .join(DIRECTORY)
                .join(format!("{phase}-{index:02}.json")),
            &json!({
            "schema":"native-learning-empty-packet-intent-v1","probe_intent_sha256":hex::encode(pin),
            "phase":phase,"index":index,"parent":hex::encode(parent),"height":height,
            "packet_id":hex::encode(id),"packet_sha256":hex::encode(sha(&raw)),"packet_hex":hex::encode(raw),
            "transactions":0,"retry_allowed":false}),
        )?;
        check(node.admit(&packet, CLOCK)? == id, "RECOVERY_ADMITTED_ID")?;
        node.activate(id)?;
        parent = id;
    }
    Ok(parent)
}

fn execute(
    command: &str,
    path: &Path,
    identity_sha: Hash,
    intent_sha: Hash,
    operation: &str,
) -> Result<Value> {
    check(
        matches!(command, "query" | "reorg" | "restore"),
        "RECOVERY_COMMAND",
    )?;
    let _lock = original_lock(path)?;
    let (bound, mut node, store) = load_round(path, identity_sha, intent_sha, operation)?;
    if command == "query" {
        return query(path, &bound, &node, &store);
    }
    let root = path.join(DIRECTORY);
    if command == "reorg" {
        if exists(&root)? {
            return query(path, &bound, &node, &store);
        }
        let intent = probe_intent(path, &bound, &node, &store)?;
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        sync_directory(path)?;
        save_new(&root.join("intent.json"), &intent)?;
        let (_, pin) = load_intent(path, &bound)?;
        let tip = extend_once(
            path,
            &mut node,
            "reorg",
            pin,
            settings()?.genesis(),
            intent["reorg_empty_blocks"]
                .as_u64()
                .ok_or("RECOVERY_COUNT")?,
        )?;
        node.reconcile_native_task_operation_v2(&store, bound.def.binding.claim, EPOCH)?;
        let after = observation(path, &bound, &node, &store)?;
        check(
            node.active()?.0 == tip
                && work(&after["native"]["chainwork_hex"])?
                    > work(&intent["original_paid_chainwork_hex"])?
                && after["current_branch_base_fee"] == 0
                && after["original_payment_packet"]["active_chain_member"] == false,
            "RECOVERY_REORG_NOT_OBSERVED",
        )?;
        save_new(
            &root.join("reorg-complete.json"),
            &json!({"schema":SCHEMA,"phase":"reorg",
            "probe_intent_sha256":hex::encode(pin),"tip":hex::encode(tip),"after":after}),
        )?;
    } else {
        directory(&root, true)?;
        let (intent, pin) = load_intent(path, &bound)?;
        if exists(&root.join("restore-intent.json"))? {
            return query(path, &bound, &node, &store);
        }
        let inspected = query(path, &bound, &node, &store)?;
        let reorg = &inspected["phases"]["reorg"]["completion"];
        check(
            reorg["schema"] == SCHEMA
                && reorg["phase"] == "reorg"
                && field_digest(reorg, "probe_intent_sha256")? == pin
                && node.active()?.0 == field_digest(reorg, "tip")?,
            "RECOVERY_COMPLETED_ORIGINAL_REORG_REQUIRED",
        )?;
        let before = observation(path, &bound, &node, &store)?;
        check(
            before["current_branch_base_fee"] == 0
                && before["original_payment_packet"]["active_chain_member"] == false,
            "RECOVERY_ORPHANED_ORIGINAL_PAYMENT_REQUIRED",
        )?;
        // A local service revocation may now exist. Empty blocks restore the
        // already committed original payment; they never bypass a service gate.
        save_new(
            &root.join("restore-intent.json"),
            &json!({"schema":SCHEMA,"phase":"restore",
            "probe_intent_sha256":hex::encode(pin),"service_intent_sha256":hex::encode(bound.def.intent),
            "from_original_paid_tip":intent["original_paid_tip"],"before":before,"empty_blocks":2}),
        )?;
        let tip = extend_once(
            path,
            &mut node,
            "restore",
            pin,
            field_digest(&intent, "original_paid_tip")?,
            2,
        )?;
        node.reconcile_native_task_operation_v2(&store, bound.def.binding.claim, EPOCH)?;
        let after = observation(path, &bound, &node, &store)?;
        check(
            node.active()?.0 == tip
                && work(&after["native"]["chainwork_hex"])?
                    > work(&before["native"]["chainwork_hex"])?
                && after["current_branch_base_fee"] == bound.def.request.base_fee
                && after["original_payment_packet"]["active_chain_member"] == true,
            "RECOVERY_RESTORE_NOT_OBSERVED",
        )?;
        save_new(
            &root.join("restore-complete.json"),
            &json!({"schema":SCHEMA,"phase":"restore",
            "probe_intent_sha256":hex::encode(pin),"tip":hex::encode(tip),"after":after}),
        )?;
    }
    let mut result = query(path, &bound, &node, &store)?;
    result["maintenance_dispatch_performed"] = true.into();
    Ok(result)
}

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [command, path, identity, intent, operation] = args.as_slice() else {
        return Err("USAGE: learning_service_recovery_probe reorg|restore|query ABS_ROUND IDENTITY_SHA256 SERVICE_INTENT_SHA256 OPERATION_ID".into());
    };
    let result = execute(
        command,
        Path::new(path),
        digest(identity)?,
        digest(intent)?,
        operation,
    )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_service_settlement::native_budget::task_operation_v2::NativeTaskCostBreakdownV2;
    use trnm_service_settlement::native_budget::NativeResourceOutcomeV1;

    // Model hashes here are explicit fixtures, not evidence of neural execution.
    // Funding, delivery, payment, fork choice and recovery use the original Node.
    struct Fixture {
        _root: tempfile::TempDir,
        round: PathBuf,
        identity: Hash,
        intent: Hash,
    }

    fn signed(cfg: &Settings, sender: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
        let mut tx = Envelope {
            network: cfg.network(),
            sender: development_public(sender).unwrap(),
            nonce: 1,
            expiry: 128,
            fee_limit: 1_000_000,
            tag,
            payload,
            signature: [0; 64],
        };
        let key = signing_key_from_hex(&hex::encode(hash(
            b"DEV-ONLY-KEY",
            &[&sender.to_le_bytes()],
        )))
        .unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        tx.encode().unwrap()
    }

    fn effect(round: &Path, node: &mut Node, def: &Definition, name: &str, wire: Vec<u8>) -> Hash {
        let parent = node.active().unwrap().0;
        let packet = node
            .make_consensus_maintenance(
                parent,
                vec![wire.clone()],
                development_public(3).unwrap(),
                1 + 10 * (node.parent_height(parent).unwrap() + 1),
                4096,
            )
            .unwrap();
        let id = Envelope::decode(&wire).unwrap().id().unwrap();
        let raw = packet.encode().unwrap();
        save_new(
            &round.join(name),
            &json!({"schema":"native-learning-service-effect-intent-v1",
            "service_intent_sha256":hex::encode(def.intent),"operation":hex::encode(id),
            "wire_hex":hex::encode(wire),"packet_id":hex::encode(packet.id().unwrap()),
            "packet_sha256":hex::encode(sha(&raw)),"packet_hex":hex::encode(raw)}),
        )
        .unwrap();
        let admitted = node.admit(&packet, CLOCK).unwrap();
        assert_eq!(node.activate(admitted).unwrap(), admitted);
        id
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let round = root.path().join("round");
            fs::DirBuilder::new().mode(0o700).create(&round).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(round.join("round.lock"))
                .unwrap();
            let cfg = settings().unwrap();
            let mut node =
                Node::open_with_authenticated_state(&round.join("native"), cfg.clone(), 1).unwrap();
            let baseline = model_state(&node).unwrap();
            let plan = json!({"schema":"hepta-smollm-inherited-execution-v1","phase":"train","generation":2,
                "operation_id":"recovery-native-fixture","authority":binding::no_authority(),
                "inputs_sha256":hex::encode([11;32]),"source_pins":{"fixture":hex::encode([12;32])},
                "runtime":{"backend":"cpu","threads":1,"training_steps":1},
                "parent":{"schema":"hepta-smollm-parent-material-v1","operation_id":"prior-fixture","generation":1,
                    "adapter":hex::encode([13;32]),"contract":hex::encode([14;32]),"file_sha256":hex::encode([15;32])}});
            let request = json!({"schema":"native-learning-service-request-v1","provider_authority_id":hex::encode([16;32]),
                "operation_id":"recovery-native-fixture","output_directory":root.path().join("fixture-output"),
                "base_fee":2000,"training_cpu_cap_ns":100000,"parameter_byte_cap":4096,
                "evaluation_protocol_sha256":hex::encode([17;32])});
            let def = Definition::derive(
                &serde_json::to_vec(&request).unwrap(),
                &serde_json::to_vec(&plan).unwrap(),
                &serde_json::to_vec(&baseline).unwrap(),
            )
            .unwrap();
            for (name, value) in [
                ("request.json", request),
                ("execution-plan.json", plan),
                ("initial-model-state.json", baseline),
                ("identity.json", def.identity.clone()),
            ] {
                save_new(&round.join(name), &value).unwrap();
            }
            effect(
                &round,
                &mut node,
                &def,
                "reservation-intent.json",
                signed(
                    &cfg,
                    0,
                    2,
                    FundedServiceReservationV1 {
                        task: def.binding.task,
                        contract: def.contract.clone(),
                    }
                    .encode()
                    .unwrap(),
                ),
            );
            let mut store = NativeTaskOperationStoreV2::open(
                &round.join("operations.sqlite"),
                configuration(&cfg),
            )
            .unwrap();
            store.reserve(&mut node, def.binding.clone()).unwrap();
            store.begin(&mut node, def.binding.claim).unwrap();
            save_new(&round.join("prepared.json"),&json!({"schema":ROUND_SCHEMA,"status":"PREPARED","dispatch_allowed":true,
                "operation_id":def.request.operation_id,"provider_authority_id":def.request.provider_authority_id,
                "intent_sha256":hex::encode(def.intent),"plan_sha256":def.identity["plan_sha256"],
                "evaluation_profile_sha256":def.request.evaluation_protocol_sha256,"claim":hex::encode(def.binding.claim),
                "task":hex::encode(def.binding.task),"native_operation":hex::encode(def.binding.operation),
                "contract_digest":hex::encode(def.binding.contract_digest),"original_contract":def.contract})).unwrap();
            let output = [21; 32];
            let receipt = [22; 32];
            store
                .record_costs(
                    def.binding.claim,
                    NativeResourceOutcomeV1::NoGain,
                    NativeBudgetResourcesV1::Contribution {
                        training_cpu_ns: 1000,
                        parameter_bytes: 128,
                    },
                    NativeTaskCostBreakdownV2 {
                        training_units: 1000,
                        evaluation_units: 0,
                        storage_units: 0,
                        serving_units: 0,
                        unit: hash(b"native-learning-cost-unit-v1", &[b"CPU nanoseconds"]),
                        measurement_receipt: [23; 32],
                    },
                )
                .unwrap();
            store
                .complete(def.binding.claim, def.binding.operation, output, receipt)
                .unwrap();
            save_new(&round.join("terminal.json"),&json!({"schema":"native-learning-service-terminal-v1",
                "intent_sha256":hex::encode(def.intent),"output":hex::encode(output),"target_receipt":hex::encode(receipt),
                "artifact":hex::encode([24;32]),"cpu_ns":1000,"artifact_bytes":128,
                "costs":{"scope":"synthetic-runtime-fixture"},"measurement_receipt":hex::encode([23;32]),
                "no_update_decided":false,"independent_evaluation_accepted":false})).unwrap();
            save_new(
                &round.join("provider-readback.json"),
                &json!({"scope":"synthetic-runtime-fixture-not-neural-training"}),
            )
            .unwrap();
            let mut payload = def.binding.task.to_vec();
            payload.extend(output);
            effect(
                &round,
                &mut node,
                &def,
                "delivery-intent.json",
                signed(&cfg, 1, 4, payload),
            );
            store.bind_delivery(&mut node, def.binding.claim).unwrap();
            let payment = effect(
                &round,
                &mut node,
                &def,
                "payment-intent.json",
                signed(
                    &cfg,
                    2,
                    5,
                    FundedServiceDecisionV1 {
                        task: def.binding.task,
                        contract_digest: def.binding.contract_digest,
                        output,
                        evidence: receipt,
                        verdict: FundedServiceVerdictV1::PayProvider,
                    }
                    .encode()
                    .unwrap(),
                ),
            );
            store
                .record_native_payment(&mut node, def.binding.claim, payment)
                .unwrap();
            node.reconcile_native_task_operation_v2(&store, def.binding.claim, EPOCH)
                .unwrap();
            let identity = sha(&read(&round.join("identity.json"), MAX_JSON).unwrap());
            Self {
                _root: root,
                round,
                identity,
                intent: def.intent,
            }
        }

        fn call(&self, command: &str) -> Result<Value> {
            execute(
                command,
                &self.round,
                self.identity,
                self.intent,
                "recovery-native-fixture",
            )
        }
    }

    #[test]
    fn original_payment_reorg_revoke_restore_is_heavier_and_replay_never_redispatches() {
        let f = Fixture::new();
        let before = f.call("query").unwrap();
        assert_eq!(before["current_branch_base_fee"], 2000);
        let rewound = f.call("reorg").unwrap();
        assert_eq!(rewound["current_branch_base_fee"], 0);
        assert_eq!(rewound["historically_observed_base_fee"], 2000);
        assert_eq!(rewound["m12"], before["m12"]);
        assert_eq!(rewound["native"]["height"], 4);
        assert!(
            work(&rewound["native"]["chainwork_hex"]).unwrap()
                > work(&before["native"]["chainwork_hex"]).unwrap()
        );
        assert_eq!(
            rewound["maintenance_economics"]["ordinary_protocol_subsidy_preserved"],
            true
        );
        assert!(
            rewound["maintenance_economics"]["meta_issued"]
                .as_u64()
                .unwrap()
                > before["maintenance_economics"]["meta_issued"]
                    .as_u64()
                    .unwrap()
        );
        let repeated = f.call("reorg").unwrap();
        assert_eq!(repeated["native"], rewound["native"]);
        assert_eq!(repeated["maintenance_dispatch_performed"], false);
        save_new(
            &f.round.join("revoked.json"),
            &json!({"schema":"native-learning-service-local-revocation-v1",
            "intent_sha256":hex::encode(f.intent),"native_operation":before["native_operation"],
            "consumer_epoch":EPOCH,"provider_cancellation_observed":false}),
        )
        .unwrap();
        let restored = f.call("restore").unwrap();
        assert_eq!(restored["current_branch_base_fee"], 2000);
        assert_eq!(restored["historically_observed_base_fee"], 2000);
        assert_eq!(restored["locally_revoked"], true);
        assert_eq!(restored["m12"], before["m12"]);
        assert_eq!(restored["native"]["height"], 5);
        assert_eq!(
            restored["original_payment_packet"]["block"],
            before["original_payment_packet"]["block"]
        );
        assert_eq!(
            restored["current_native_observation"]["current_payment"]["operation"],
            before["current_native_observation"]["current_payment"]["operation"]
        );
        assert_eq!(f.call("restore").unwrap()["native"], restored["native"]);
        assert_eq!(f.call("query").unwrap()["native"], restored["native"]);
    }

    #[test]
    fn wrong_original_identity_operation_or_shared_lock_stops_before_probe() {
        let f = Fixture::new();
        let before = f.call("query").unwrap();
        for (identity, intent, op) in [
            ([90; 32], f.intent, "recovery-native-fixture"),
            (f.identity, [91; 32], "recovery-native-fixture"),
            (f.identity, f.intent, "another-operation"),
        ] {
            assert!(execute("reorg", &f.round, identity, intent, op).is_err());
            assert!(!f.round.join(DIRECTORY).exists());
        }
        let lock = original_lock(&f.round).unwrap();
        assert!(f.call("reorg").is_err());
        assert!(!f.round.join(DIRECTORY).exists());
        drop(lock);
        assert_eq!(f.call("query").unwrap()["native"], before["native"]);
    }

    #[test]
    fn durable_intent_before_admission_is_unknown_query_only_without_resumption() {
        let f = Fixture::new();
        let before = f.call("query").unwrap();
        let (bound, node, store) =
            load_round(&f.round, f.identity, f.intent, "recovery-native-fixture").unwrap();
        let intent = probe_intent(&f.round, &bound, &node, &store).unwrap();
        drop(store);
        drop(node);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(f.round.join(DIRECTORY))
            .unwrap();
        save_new(&f.round.join(DIRECTORY).join("intent.json"), &intent).unwrap();
        let unknown = f.call("reorg").unwrap();
        assert_eq!(unknown["probe_state"], "REORG_ATTEMPTED_QUERY_ONLY");
        assert_eq!(unknown["maintenance_dispatch_performed"], false);
        assert_eq!(unknown["native"], before["native"]);
        assert!(f.call("restore").is_err());
        assert!(!f.round.join(DIRECTORY).join("restore-intent.json").exists());
    }

    #[test]
    fn altered_original_packet_or_missing_owner_is_not_an_unpaid_success() {
        let f = Fixture::new();
        let payment = f.round.join("payment-intent.json");
        let original = read(&payment, MAX_JSON).unwrap();
        let mut changed = decode(&original).unwrap();
        changed["operation"] = hex::encode([99; 32]).into();
        fs::write(&payment, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(f.call("query").is_err());
        assert!(f.call("reorg").is_err());
        assert!(!f.round.join(DIRECTORY).exists());
        fs::write(&payment, original).unwrap();
        fs::rename(
            f.round.join("operations.sqlite"),
            f.round.join("operations.unavailable"),
        )
        .unwrap();
        assert!(f.call("query").is_err());
        assert!(!f.round.join("operations.sqlite").exists());
    }

    #[test]
    fn damaged_probe_receipts_never_become_a_successful_recorded_recovery() {
        let f = Fixture::new();
        f.call("reorg").unwrap();
        let restored = f.call("restore").unwrap();
        for (name, field, wrong) in [
            (
                "restore-intent.json",
                "service_intent_sha256",
                json!(hex::encode([90; 32])),
            ),
            ("restore-complete.json", "tip", json!(hex::encode([91; 32]))),
            ("reorg-01.json", "parent", json!(hex::encode([92; 32]))),
        ] {
            let path = f.round.join(DIRECTORY).join(name);
            let original = read(&path, MAX_JSON).unwrap();
            let mut changed = decode(&original).unwrap();
            changed[field] = wrong;
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(f.call("query").is_err());
            assert!(f.call("restore").is_err());
            fs::write(&path, original).unwrap();
            assert_eq!(f.call("query").unwrap()["native"], restored["native"]);
        }
        let path = f.round.join(DIRECTORY).join("restore-complete.json");
        let original = read(&path, MAX_JSON).unwrap();
        let mut changed = decode(&original).unwrap();
        let generation = changed["after"]["native"]["generation"].as_u64().unwrap();
        changed["after"]["native"]["generation"] = (generation + 1).into();
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        // Exact stored packets and valid chainwork cannot manufacture a past
        // activation generation that the original owner never recorded.
        assert!(f
            .call("query")
            .unwrap_err()
            .to_string()
            .contains("ACTIVATION_NOT_RECORDED"));
        fs::write(&path, original).unwrap();
        assert_eq!(f.call("query").unwrap()["native"], restored["native"]);
    }
}
