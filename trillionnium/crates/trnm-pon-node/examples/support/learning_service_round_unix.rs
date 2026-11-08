//! Connect the inherited model operation to a real, funded native dev contract.
//!
//! prepare NEW_DIR REQUEST_JSON EXECUTION_PLAN_JSON freezes the original task
//! before runtime dispatch. settle DIR READBACK_JSON consumes that operation's
//! exact retained output. query DIR reconciles original native effects only;
//! revoke DIR durably fences new effects without claiming provider cancellation.
//! These commands use development keys and a fresh authenticated Node, never a
//! deployed chain. A completed training service may earn its contracted base fee
//! without a claimed improvement. NoGain here is an economic outcome, not an
//! independent NoUpdate verdict. Model installation, bonuses and consensus credit
//! remain with their original owners and are not granted by this example.
#[path = "learning_service_receipt.rs"]
mod receipt;

use fs2::FileExt;
use receipt::{
    check, decode, digest, field_digest, read, sha, Request, SuccessfulReadback, MAX_JSON,
};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Packet, Result, Settings};
use trnm_protocol::funded_service_task_v1::{
    FundedServiceContractV1, FundedServiceDecisionV1, FundedServiceReservationV1,
    FundedServiceVerdictV1,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
use trnm_service_settlement::native_budget::task_operation_v2::{
    NativeTaskCostBreakdownV2, NativeTaskOperationBindingV2, NativeTaskOperationOwnerV2,
    NativeTaskOperationStoreV2, NativeTaskStatusV2,
};
use trnm_service_settlement::native_budget::{
    NativeBudgetConfigV1, NativeBudgetReplayV1, NativeBudgetResourcesV1, NativeResourceOutcomeV1,
};

const SCHEMA: &str = "native-learning-service-round-v1";
const EPOCH: u64 = 1;
const CLOCK: u64 = 100_000;

fn owner(error: impl std::fmt::Display) -> trnm_pon_node::Error {
    error.to_string().into()
}

fn transaction_id(wire: &[u8]) -> Result<Hash> {
    Envelope::decode(wire)
        .and_then(|tx| tx.id())
        .map_err(|_| "LEARNING_WIRE".into())
}

fn settings() -> Result<Settings> {
    Settings::development_with_funded_service_contract_v1(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
}

fn configuration(settings: &Settings) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
        max_records: 4,
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn save_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    sync_directory(path.parent().ok_or("LEARNING_OUTPUT_PARENT")?)
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn save_exact(path: &Path, raw: &[u8], maximum: u64) -> Result<()> {
    if exists(path)? {
        check(
            read(path, maximum)? == raw,
            "LEARNING_RETAINED_BYTES_CHANGED",
        )
    } else {
        save_new(path, raw)
    }
}

fn make_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    sync_directory(path.parent().ok_or("LEARNING_OUTPUT_PARENT")?)
}

fn lock(path: &Path, create: bool) -> Result<File> {
    check(
        path.is_absolute() && path.canonicalize()? == path,
        "LEARNING_ROUND_PATH",
    )?;
    let metadata = fs::symlink_metadata(path)?;
    check(
        metadata.is_dir() && metadata.mode() & 0o077 == 0,
        "LEARNING_ROUND_PRIVATE",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join("round.lock"))?;
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

struct Definition {
    request: Request,
    plan_raw: Vec<u8>,
    plan: Value,
    baseline: Value,
    contract: FundedServiceContractV1,
    binding: NativeTaskOperationBindingV2,
    intent: Hash,
    identity: Value,
}

impl Definition {
    fn derive(request_raw: &[u8], plan_raw: Vec<u8>, baseline_raw: &[u8]) -> Result<Self> {
        let plan = decode(&plan_raw)?;
        let request = Request::parse(request_raw, &plan)?;
        let baseline = decode(baseline_raw)?;
        let cfg = settings()?;
        let operation = request.native_operation()?;
        let request_id = hash(
            b"native-learning-service-request-v1",
            &[&sha(request_raw), &sha(&plan_raw), &sha(baseline_raw)],
        );
        let contract = FundedServiceContractV1 {
            request: request_id,
            provider: development_public(1)?,
            model: field_digest(&plan["parent"], "adapter")?,
            input: field_digest(&plan, "inputs_sha256")?,
            output_spec: hash(b"native-learning-service-output-spec-v1", &[
                b"complete inherited training output and original operation receipt; no gain requirement",
                &sha(&plan_raw),
            ]),
            // These signed commitments specify a service, not qualified work.
            qualified_work: hash(b"native-learning-service-work-v1", &[&operation, &sha(&plan_raw)]),
            evaluation_protocol: digest(&request.evaluation_protocol_sha256)?,
            fee_schedule: hash(b"native-learning-base-fee-v1", &[&request.base_fee.to_le_bytes(),
                b"completed commissioned training service; bonus and consensus credit zero"]),
            dispute_policy: hash(b"native-learning-local-arbitration-v1", &[
                b"development same-operator receipt acceptance; no independent customer claim",
            ]),
            arbitrator: development_public(2)?,
            budget: request.base_fee,
            delivery_deadline: 12,
            dispute_deadline: 24,
        };
        contract.validate().map_err(|_| "LEARNING_CONTRACT")?;
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
                    &sha(&plan_raw),
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
        let identity = json!({"schema":SCHEMA,"request_sha256":hex::encode(sha(request_raw)),
            "plan_sha256":hex::encode(sha(&plan_raw)),"baseline_sha256":hex::encode(sha(baseline_raw)),
            "contract":contract,"binding_hex":hex::encode(binding.encode().map_err(owner)?),
            "intent_sha256":hex::encode(intent),"consumer_epoch":EPOCH});
        Ok(Self {
            request,
            plan_raw,
            plan,
            baseline,
            contract,
            binding,
            intent,
            identity,
        })
    }

    fn load(path: &Path) -> Result<Self> {
        let value = Self::derive(
            &read(&path.join("request.json"), MAX_JSON)?,
            read(&path.join("execution-plan.json"), MAX_JSON)?,
            &read(&path.join("initial-model-state.json"), MAX_JSON)?,
        )?;
        check(
            decode(&read(&path.join("identity.json"), MAX_JSON)?)? == value.identity,
            "LEARNING_ROUND_IDENTITY",
        )?;
        Ok(value)
    }
}

fn signed(
    settings: &Settings,
    sender: u64,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(sender)?,
        nonce,
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
    .map_err(owner)?;
    tx.signature = hex::decode(sign_hex(
        &key,
        &tx.signing_digest().map_err(|_| "LEARNING_WIRE")?,
    ))
    .map_err(owner)?
    .try_into()
    .map_err(|_| "LEARNING_SIGNATURE")?;
    tx.encode().map_err(|_| "LEARNING_WIRE".into())
}

fn delivery_wire(def: &Definition, output: Hash) -> Result<Vec<u8>> {
    let mut payload = def.binding.task.to_vec();
    payload.extend(output);
    signed(&settings()?, 1, 1, 4, payload)
}

fn payment_wire(def: &Definition, output: Hash, evidence: Hash) -> Result<Vec<u8>> {
    signed(
        &settings()?,
        2,
        1,
        5,
        FundedServiceDecisionV1 {
            task: def.binding.task,
            contract_digest: def.binding.contract_digest,
            output,
            evidence,
            verdict: FundedServiceVerdictV1::PayProvider,
        }
        .encode()
        .map_err(|_| "LEARNING_CONTRACT")?,
    )
}

fn step_intent(node: &Node, def: &Definition, wire: &[u8]) -> Result<(Value, Packet)> {
    let parent = node.active()?.0;
    let timestamp = 1 + 10 * (node.parent_height(parent)? + 1);
    let packet = node.make_consensus_maintenance(
        parent,
        vec![wire.to_vec()],
        development_public(3)?,
        timestamp,
        4096,
    )?;
    let raw = packet.encode()?;
    let intent = json!({"schema":"native-learning-service-effect-intent-v1",
        "service_intent_sha256":hex::encode(def.intent),"operation":hex::encode(transaction_id(wire)?),
        "wire_hex":hex::encode(wire),"packet_id":hex::encode(packet.id()?),
        "packet_sha256":hex::encode(sha(&raw)),"packet_hex":hex::encode(raw)});
    Ok((intent, packet))
}

fn check_step(path: &Path, def: &Definition, wire: &[u8]) -> Result<Value> {
    let value = decode(&read(path, 3 * MAX_JSON)?)?;
    check(
        value.as_object().is_some_and(|m| m.len() == 7)
            && value["schema"] == "native-learning-service-effect-intent-v1"
            && field_digest(&value, "service_intent_sha256")? == def.intent
            && field_digest(&value, "operation")? == transaction_id(wire)?
            && value["wire_hex"] == hex::encode(wire),
        "LEARNING_ORIGINAL_EFFECT_REQUIRED",
    )?;
    let raw = hex::decode(value["packet_hex"].as_str().ok_or("LEARNING_PACKET")?).map_err(owner)?;
    let packet = Packet::decode(&raw)?;
    check(
        sha(&raw) == field_digest(&value, "packet_sha256")?
            && packet.id()? == field_digest(&value, "packet_id")?
            && packet.transactions == vec![wire.to_vec()],
        "LEARNING_ORIGINAL_PACKET_REQUIRED",
    )?;
    Ok(value)
}

fn original_wire(
    path: &Path,
    def: &Definition,
    sender: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let intent = decode(&read(path, MAX_JSON)?)?;
    let wire = hex::decode(intent["wire_hex"].as_str().ok_or("LEARNING_WIRE")?).map_err(owner)?;
    let tx = Envelope::decode(&wire).map_err(|_| "LEARNING_WIRE")?;
    check(
        tx.network == settings()?.network()
            && tx.sender == development_public(sender)?
            && tx.nonce == 1
            && tx.expiry == 128
            && tx.fee_limit == 1_000_000
            && tx.tag == tag
            && tx.payload == payload,
        "LEARNING_ORIGINAL_EFFECT_REQUIRED",
    )?;
    check_step(path, def, &wire)?;
    Ok(wire)
}

fn revocation(def: &Definition) -> Value {
    json!({"schema":"native-learning-service-local-revocation-v1",
        "intent_sha256":hex::encode(def.intent),"native_operation":hex::encode(def.binding.operation),
        "consumer_epoch":EPOCH,"provider_cancellation_observed":false})
}

fn revoked(path: &Path, def: &Definition) -> Result<bool> {
    let marker = path.join("revoked.json");
    if !exists(&marker)? {
        return Ok(false);
    }
    check(
        decode(&read(&marker, MAX_JSON)?)? == revocation(def),
        "LEARNING_REVOCATION_CHANGED",
    )?;
    Ok(true)
}

/// Persist the exact native packet before its sole admission attempt. A retained
/// intent means query-only, including a crash before admission or a chain reorg.
fn dispatch_once(node: &mut Node, path: &Path, def: &Definition, wire: &[u8]) -> Result<bool> {
    check(
        !revoked(path.parent().ok_or("LEARNING_OUTPUT_PARENT")?, def)?,
        "LEARNING_LOCALLY_REVOKED",
    )?;
    if exists(path)? {
        check_step(path, def, wire)?;
        return Ok(false);
    }
    let (intent, packet) = step_intent(node, def, wire)?;
    save_new(path, &serde_json::to_vec(&intent)?)?;
    let admitted = node.admit(&packet, CLOCK)?;
    check(admitted == packet.id()?, "LEARNING_NATIVE_PACKET_ID")?;
    node.activate(admitted)?;
    Ok(true)
}

fn open_existing(path: &Path) -> Result<(Node, NativeTaskOperationStoreV2)> {
    check(
        path.join("native/native.sqlite").is_file() && path.join("operations.sqlite").is_file(),
        "LEARNING_ORIGINAL_OWNER_REQUIRED",
    )?;
    let cfg = settings()?;
    let node = Node::open_with_authenticated_state(&path.join("native"), cfg.clone(), 1)?;
    let store =
        NativeTaskOperationStoreV2::open(&path.join("operations.sqlite"), configuration(&cfg))
            .map_err(owner)?;
    Ok((node, store))
}

fn retain_success(path: &Path, def: &Definition, success: &SuccessfulReadback) -> Result<()> {
    let directory = path.join("retained-runtime");
    if !exists(&directory)? {
        make_directory(&directory)?;
    }
    if !exists(&directory.join("worker"))? {
        make_directory(&directory.join("worker"))?;
    }
    for (name, bytes) in &success.files {
        save_exact(&directory.join(name), bytes, receipt::MAX_ARTIFACT)?;
    }
    save_exact(
        &path.join("provider-readback.json"),
        &success.canonical_readback,
        MAX_JSON,
    )?;
    let terminal = json!({"schema":"native-learning-service-terminal-v1",
        "intent_sha256":hex::encode(def.intent),"output":hex::encode(success.output),
        "target_receipt":hex::encode(success.receipt),"artifact":hex::encode(success.artifact),
        "cpu_ns":success.cpu_ns,"artifact_bytes":success.artifact_bytes,"costs":success.provider_costs,
        "measurement_receipt":hex::encode(success.measurement_receipt),
        "no_update_decided":false,"independent_evaluation_accepted":false});
    save_exact(
        &path.join("terminal.json"),
        &serde_json::to_vec(&terminal)?,
        MAX_JSON,
    )
}

fn record_success(
    store: &mut NativeTaskOperationStoreV2,
    def: &Definition,
    value: &SuccessfulReadback,
) -> Result<()> {
    let cpu_ns = value.cpu_ns.ok_or("LEARNING_COST_OBSERVATION_UNKNOWN")?;
    store
        .record_costs(
            def.binding.claim,
            NativeResourceOutcomeV1::NoGain,
            NativeBudgetResourcesV1::Contribution {
                training_cpu_ns: cpu_ns,
                parameter_bytes: value.artifact_bytes,
            },
            NativeTaskCostBreakdownV2 {
                training_units: cpu_ns,
                evaluation_units: 0,
                storage_units: 0,
                serving_units: 0,
                unit: hash(b"native-learning-cost-unit-v1", &[b"CPU nanoseconds"]),
                measurement_receipt: value.measurement_receipt,
            },
        )
        .map_err(owner)?;
    store
        .complete(
            def.binding.claim,
            def.binding.operation,
            value.output,
            value.receipt,
        )
        .map_err(owner)?;
    Ok(())
}

/// This may append observed facts to M12/Node reconciliation journals. It never
/// signs, admits, activates or retries a native effect or a model operation.
fn current_payment(
    path: &Path,
    def: &Definition,
    node: &mut Node,
    store: &mut NativeTaskOperationStoreV2,
) -> Result<Value> {
    let prior = store.snapshot(def.binding.claim).map_err(owner)?;
    check(prior.binding == def.binding, "LEARNING_ORIGINAL_BINDING")?;
    let completion = prior.completion.ok_or("LEARNING_COMPLETION_NOT_OBSERVED")?;
    let mut payload = def.binding.task.to_vec();
    payload.extend(completion.output);
    let delivery = original_wire(&path.join("delivery-intent.json"), def, 1, 4, payload)?;
    let observed = node.observe_task_delivery_v2(&def.binding).map_err(owner)?;
    check(
        observed.receipt_operation == transaction_id(&delivery)?
            && observed.contract.output == Some(completion.output),
        "LEARNING_ORIGINAL_DELIVERY",
    )?;
    store
        .bind_delivery(node, def.binding.claim)
        .map_err(owner)?;
    let payload = FundedServiceDecisionV1 {
        task: def.binding.task,
        contract_digest: def.binding.contract_digest,
        output: completion.output,
        evidence: completion.target_receipt,
        verdict: FundedServiceVerdictV1::PayProvider,
    }
    .encode()
    .map_err(|_| "LEARNING_CONTRACT")?;
    let payment = original_wire(&path.join("payment-intent.json"), def, 2, 5, payload)?;
    store
        .record_native_payment(node, def.binding.claim, transaction_id(&payment)?)
        .map_err(owner)?;
    store
        .reobserve_native_payment(node, def.binding.claim)
        .map_err(owner)?;
    node.reconcile_native_task_operation_v2(store, def.binding.claim, EPOCH)?;
    node.observe_current_native_task_operation_v3(store, &def.binding, &def.contract, EPOCH)
}

fn report(
    path: &Path,
    def: &Definition,
    node: &mut Node,
    store: &mut NativeTaskOperationStoreV2,
) -> Result<Value> {
    let observed = current_payment(path, def, node, store);
    let (current, error) = match observed {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let snapshot = store.snapshot(def.binding.claim).map_err(owner)?;
    check(snapshot.binding == def.binding, "LEARNING_ORIGINAL_BINDING")?;
    let historical = snapshot
        .payment
        .as_ref()
        .map_or(0, |p| p.beneficiary_credit);
    Ok(
        json!({"schema":SCHEMA,"scope":"LOCAL_DEVELOPMENT_NATIVE_BASE_FEE",
        "status":if current.is_some() { "PAID_CURRENT_BRANCH" } else { "UNKNOWN_OR_UNPAID_CURRENT_BRANCH" },
        "operation_id":def.request.operation_id,"native_operation":hex::encode(def.binding.operation),
        "provider_authority_id":def.request.provider_authority_id,"intent_sha256":hex::encode(def.intent),
        "plan_sha256":hex::encode(sha(&def.plan_raw)),"evaluation_profile_sha256":def.request.evaluation_protocol_sha256,
        "task":hex::encode(def.binding.task),"contract_digest":hex::encode(def.binding.contract_digest),
        "claim":hex::encode(def.binding.claim),"dispatch_allowed":false,
        "locally_revoked":revoked(path, def)?,"provider_cancellation_observed":false,
        "base_fee_contract":def.request.base_fee,"historically_observed_base_fee":historical,
        "current_branch_base_fee":if current.is_some() { def.request.base_fee } else { 0 },
        "improvement_bonus":0,"anti_sybil_consensus_credit":0,"mining_subsidy_separate":true,
        "resource_reservation":if snapshot.costs.is_none() { "RETAINED_FULL_CAP" } else { "ORIGINAL_CONSUMPTION_RECORDED" },
        "no_update_decided":false,"independent_evaluation_accepted":false,
        "model_state_unchanged":model_state(node)? == def.baseline,
        "provider_terminal_retained":exists(&path.join("terminal.json"))?,
        "current_native_observation":current,"current_native_error":error,"m12":store.report().map_err(owner)?,
        "actual_model_execution_attested_by_this_bridge":false,"tensor_semantics_replayed_by_this_bridge":false,
        "independent_customer_verified":false,"external_budget_origin_verified":false,
        "physical_costs_verified_by_this_bridge":false,"installed_parent_verified":false,
        "authority":receipt::no_authority(),"production_activation":false}),
    )
}

fn prepare(path: &Path, request_path: &Path, plan_path: &Path) -> Result<Value> {
    let request_raw = read(request_path, MAX_JSON)?;
    let plan_raw = read(plan_path, MAX_JSON)?;
    let request = Request::parse(&request_raw, &decode(&plan_raw)?)?;
    check(
        !exists(Path::new(&request.output_directory))?,
        "LEARNING_RUNTIME_ALREADY_STARTED",
    )?;
    check(
        path.is_absolute() && !exists(path)?,
        "LEARNING_NEW_ROUND_REQUIRED",
    )?;
    check(
        path.parent()
            .ok_or("LEARNING_OUTPUT_PARENT")?
            .canonicalize()?
            == path.parent().unwrap(),
        "LEARNING_OUTPUT_PARENT",
    )?;
    make_directory(path)?;
    let _lock = lock(path, true)?;
    let cfg = settings()?;
    let mut node = Node::open_with_authenticated_state(&path.join("native"), cfg.clone(), 1)?;
    let baseline_raw = serde_json::to_vec(&model_state(&node)?)?;
    let def = Definition::derive(&request_raw, plan_raw, &baseline_raw)?;
    save_new(&path.join("request.json"), &request_raw)?;
    save_new(&path.join("execution-plan.json"), &def.plan_raw)?;
    save_new(&path.join("initial-model-state.json"), &baseline_raw)?;
    save_new(
        &path.join("identity.json"),
        &serde_json::to_vec(&def.identity)?,
    )?;
    let reservation = signed(
        &cfg,
        0,
        1,
        2,
        FundedServiceReservationV1 {
            task: def.binding.task,
            contract: def.contract.clone(),
        }
        .encode()
        .map_err(|_| "LEARNING_CONTRACT")?,
    )?;
    dispatch_once(
        &mut node,
        &path.join("reservation-intent.json"),
        &def,
        &reservation,
    )?;
    let mut store =
        NativeTaskOperationStoreV2::open(&path.join("operations.sqlite"), configuration(&cfg))
            .map_err(owner)?;
    check(
        store
            .reserve(&mut node, def.binding.clone())
            .map_err(owner)?
            == NativeBudgetReplayV1::New,
        "LEARNING_NEW_NATIVE_RESERVATION",
    )?;
    check(
        store.begin(&mut node, def.binding.claim).map_err(owner)? == NativeBudgetReplayV1::New,
        "LEARNING_NEW_NATIVE_BEGIN",
    )?;
    let mut value = report(path, &def, &mut node, &mut store)?;
    value["status"] = "PREPARED".into();
    value["dispatch_allowed"] = true.into();
    value["original_contract"] = serde_json::to_value(&def.contract)?;
    save_new(&path.join("prepared.json"), &serde_json::to_vec(&value)?)?;
    Ok(value)
}

fn query(path: &Path) -> Result<Value> {
    let _lock = lock(path, false)?;
    let def = Definition::load(path)?;
    let (mut node, mut store) = open_existing(path)?;
    report(path, &def, &mut node, &mut store)
}

fn revoke(path: &Path) -> Result<Value> {
    let _lock = lock(path, false)?;
    let def = Definition::load(path)?;
    let (mut node, mut store) = open_existing(path)?;
    check(
        store.snapshot(def.binding.claim).map_err(owner)?.binding == def.binding,
        "LEARNING_ORIGINAL_BINDING",
    )?;
    save_exact(
        &path.join("revoked.json"),
        &serde_json::to_vec(&revocation(&def))?,
        MAX_JSON,
    )?;
    report(path, &def, &mut node, &mut store)
}

fn settle(path: &Path, readback_path: &Path) -> Result<Value> {
    let _lock = lock(path, false)?;
    let def = Definition::load(path)?;
    let value = decode(&read(readback_path, MAX_JSON)?)?;
    receipt::validate_readback(&value, &def.request, sha(&def.plan_raw), def.intent)?;
    let (mut node, mut store) = open_existing(path)?;
    check(
        store.snapshot(def.binding.claim).map_err(owner)?.binding == def.binding,
        "LEARNING_ORIGINAL_BINDING",
    )?;
    if revoked(path, &def)? {
        let mut result = report(path, &def, &mut node, &mut store)?;
        result["settlement_blocked"] = "LOCAL_REVOKED".into();
        return Ok(result);
    }
    if value["status"] != "SUCCESS" {
        let mut result = report(path, &def, &mut node, &mut store)?;
        result["provider_reported_status"] = value["status"].clone();
        return Ok(result);
    }
    let success = receipt::success(&value, &def.request, &def.plan_raw, &def.plan)?;
    if success.cpu_ns.is_none() {
        let mut result = report(path, &def, &mut node, &mut store)?;
        result["cost_observation"] = "UNKNOWN_RETAIN_FULL_CAP".into();
        return Ok(result);
    }
    check(
        model_state(&node)? == def.baseline,
        "LEARNING_MODEL_STATE_CHANGED",
    )?;
    let native = node
        .reserve_task_operation_v2(&def.binding)
        .map_err(owner)?;
    check(
        matches!(
            native.status,
            NativeTaskStatusV2::Reserved
                | NativeTaskStatusV2::Receipt
                | NativeTaskStatusV2::Settled
        ),
        "LEARNING_NATIVE_SERVICE_REVOKED_OR_EXPIRED",
    )?;
    retain_success(path, &def, &success)?;
    record_success(&mut store, &def, &success)?;
    let delivery = delivery_wire(&def, success.output)?;
    if native.status == NativeTaskStatusV2::Reserved {
        dispatch_once(
            &mut node,
            &path.join("delivery-intent.json"),
            &def,
            &delivery,
        )?;
    }
    check_step(&path.join("delivery-intent.json"), &def, &delivery)?;
    let observed = match node.observe_task_delivery_v2(&def.binding) {
        Ok(observed) => observed,
        Err(_) => return report(path, &def, &mut node, &mut store),
    };
    check(
        observed.receipt_operation == transaction_id(&delivery)?
            && observed.contract.output == Some(success.output),
        "LEARNING_ORIGINAL_DELIVERY",
    )?;
    store
        .bind_delivery(&mut node, def.binding.claim)
        .map_err(owner)?;
    let payment = payment_wire(&def, success.output, success.receipt)?;
    if observed.contract.status == NativeTaskStatusV2::Receipt {
        dispatch_once(&mut node, &path.join("payment-intent.json"), &def, &payment)?;
    }
    report(path, &def, &mut node, &mut store)
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let value = match args.as_slice() {
        [command, directory, request, plan] if command == "prepare" =>
            prepare(Path::new(directory), Path::new(request), Path::new(plan))?,
        [command, directory, readback] if command == "settle" =>
            settle(Path::new(directory), Path::new(readback))?,
        [command, directory] if command == "query" => query(Path::new(directory))?,
        [command, directory] if command == "revoke" => revoke(Path::new(directory))?,
        _ => return Err("USAGE: learning_service_round prepare NEW_DIR REQUEST_JSON EXECUTION_PLAN_JSON | settle DIR READBACK_JSON | query DIR | revoke DIR".into()),
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Runtime documents and factor bytes below are explicit controlled fixtures.
    // Only native funding, transaction execution and owner recovery are real in
    // this suite. A passing test is not evidence that a neural model was trained.
    struct Fixture {
        _directory: tempfile::TempDir,
        round: PathBuf,
        output: PathBuf,
        readback: PathBuf,
        prepared: Value,
        plan: Value,
        target: Vec<u8>,
    }

    fn write(path: &Path, value: &Value) {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn extend_empty(node: &mut Node, mut parent: Hash, count: usize) -> Hash {
        for _ in 0..count {
            let timestamp = 1 + 10 * (node.parent_height(parent).unwrap() + 1);
            let packet = node
                .make_consensus_maintenance(
                    parent,
                    vec![],
                    development_public(3).unwrap(),
                    timestamp,
                    4096,
                )
                .unwrap();
            parent = node.admit(&packet, CLOCK).unwrap();
            node.activate(parent).unwrap();
        }
        parent
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let round = root.join("round");
            let output = root.join("provider-output");
            let target =
                serde_json::to_vec(&json!({"schema":"pon-target-decoder-adapter-contract-v1",
                "scope":"controlled-native-settlement-test-not-neural-execution"}))
                .unwrap();
            let contract = hex::encode(hash(b"target-decoder-adapter-contract-v1", &[&target]));
            let plan = json!({"schema":"hepta-smollm-inherited-execution-v1","operation_id":"training-2",
                "phase":"train","generation":2,"authority":receipt::no_authority(),
                "parent":{"schema":"hepta-smollm-parent-material-v1","generation":1,"operation_id":"training-1",
                    "directory":root.join("prior-parent"),"contract":contract,"adapter":hex::encode([45;32]),
                    "file_sha256":hex::encode([46;32])},
                "inputs_sha256":hex::encode([47;32]),"inputs":{"scope":"controlled-native-test"},
                "source_pins":{"fixture-runtime":hex::encode([48;32])},
                "runtime":{"backend":"cpu","threads":1,"training_steps":1,
                    "training_budget":{"wall_seconds":60,"rss_bytes":1048576}}});
            let request = json!({"schema":receipt::REQUEST_SCHEMA,"provider_authority_id":hex::encode([49;32]),
                "operation_id":"training-2","output_directory":output,"base_fee":2000,
                "training_cpu_cap_ns":100000,"parameter_byte_cap":4096,
                "evaluation_protocol_sha256":hex::encode([50;32])});
            let request_path = root.join("request.json");
            let plan_path = root.join("plan.json");
            write(&request_path, &request);
            write(&plan_path, &plan);
            let prepared = prepare(&round, &request_path, &plan_path).unwrap();
            assert_eq!(prepared["status"], "PREPARED");
            assert_eq!(prepared["dispatch_allowed"], true);
            let readback = root.join("readback.json");
            Self {
                _directory: directory,
                round,
                output,
                readback,
                prepared,
                plan,
                target,
            }
        }

        fn response(&self, observation: Value) -> Value {
            json!({"schema":receipt::READBACK_SCHEMA,"authority_id":hex::encode([49;32]),
                "operation_id":"training-2","intent_sha256":self.prepared["intent_sha256"],
                "status":observation.get("status").cloned().unwrap_or(json!("UNKNOWN")),
                "evaluation_profile_sha256":hex::encode([50;32]),"dispatch_allowed":false,
                "reservation":"RETAINED","original_output":self.output,
                "plan_sha256":self.prepared["plan_sha256"],"observation":observation,
                "no_update_decided":false,"payment_authorized":false,"authority":receipt::no_authority()})
        }

        fn complete(&self) -> Value {
            fs::create_dir(&self.output).unwrap();
            fs::create_dir(self.output.join("worker")).unwrap();
            let plan_raw = read(&self.round.join("execution-plan.json"), MAX_JSON).unwrap();
            fs::write(self.output.join("execution-plan.json"), &plan_raw).unwrap();
            fs::write(
                self.output.join("worker/target-contract.json"),
                &self.target,
            )
            .unwrap();
            let wrapped = json!({"schema":"pon-wrapped-decoder-lora-material-v1",
                "contract":self.plan["parent"]["contract"],"modules":{},
                "material_scope":"factor-bytes-and-insertion-interface-not-functional-equivalence"});
            let wrapped_raw = serde_json::to_vec(&wrapped).unwrap();
            let artifact = hex::encode(hash(b"wrapped-decoder-lora-material-v1", &[&wrapped_raw]));
            fs::write(self.output.join("worker/wrapped-adapter.json"), wrapped_raw).unwrap();
            // A small actual F32 container; its values are not a trained model.
            let header = br#"{"fixture.A":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
            let mut tensors = (header.len() as u64).to_le_bytes().to_vec();
            tensors.extend(header);
            tensors.extend(1_f32.to_le_bytes());
            fs::write(self.output.join("worker/artifact.safetensors"), &tensors).unwrap();
            let parent = json!({"schema":"hepta-smollm-parent-material-v1","generation":2,
                "operation_id":"training-2","directory":self.output.join("worker"),
                "contract":self.plan["parent"]["contract"],"adapter":artifact,"file_sha256":hex::encode(sha(&tensors))});
            let parent_raw = serde_json::to_vec(&parent).unwrap();
            fs::write(self.output.join("worker/parent-material.json"), &parent_raw).unwrap();
            let actual = json!({"schema":"hepta-smollm-inherited-execution-v1",
                "operation_id":"training-2","phase":"train","generation":2,"parent":self.plan["parent"],
                "input_sha256":self.plan["inputs_sha256"],"plan_sha256":hex::encode(sha(&plan_raw)),
                "source_pins":self.plan["source_pins"],"outcome":"success","authority":receipt::no_authority(),
                "actual_backend":"cpu","artifact":artifact,"actual_loaded_parent":self.plan["parent"]["adapter"],
                "contract":self.plan["parent"]["contract"],"parent_material_sha256":hex::encode(sha(&parent_raw)),
                "training":{"steps":1,"loss":["1"],"tokens":8,"supervised_tokens":4}});
            write(&self.output.join("worker/actual-receipt.json"), &actual);
            let costs = json!({"observed_wall_ns":2000,"child_cpu_ns":1000,"observer_cpu_ns":40,
                "waited_child_peak_rss_bytes":4096});
            let mut supervisor = costs.clone();
            for (key, value) in json!({"outcome":"success","exit_code":0,"stop_reason":null,
                "waited_child_reaped":true,"owned_child_reap_resolved":true,"waited_child_observation_error":null,
                "budget":self.plan["runtime"]["training_budget"]}).as_object().unwrap() {
                supervisor[key] = value.clone();
            }
            write(&self.output.join("supervisor.json"), &supervisor);
            let mut pins = serde_json::Map::new();
            for name in [
                "execution-plan.json",
                "supervisor.json",
                "worker/actual-receipt.json",
                "worker/parent-material.json",
                "worker/target-contract.json",
                "worker/wrapped-adapter.json",
                "worker/artifact.safetensors",
            ] {
                let raw = fs::read(self.output.join(name)).unwrap();
                pins.insert(
                    name.into(),
                    json!({"sha256":hex::encode(sha(&raw)),"bytes":raw.len()}),
                );
            }
            let response = self.response(
                json!({"status":"SUCCESS","pins":pins,"costs":costs,"artifact":artifact}),
            );
            write(&self.readback, &response);
            response
        }

        fn success(&self, value: &Value) -> (Definition, SuccessfulReadback) {
            let def = Definition::load(&self.round).unwrap();
            let success = receipt::success(value, &def.request, &def.plan_raw, &def.plan).unwrap();
            (def, success)
        }
    }

    #[test]
    fn original_operation_pays_only_base_fee_and_survives_provider_loss_and_reorg() {
        let f = Fixture::new();
        write(&f.readback, &f.response(Value::Null));
        let pending = settle(&f.round, &f.readback).unwrap();
        assert_eq!(pending["resource_reservation"], "RETAINED_FULL_CAP");
        assert_eq!(pending["current_branch_base_fee"], 0);
        let value = f.complete();
        let def = Definition::load(&f.round).unwrap();
        let (node, store) = open_existing(&f.round).unwrap();
        let reserved = node.active().unwrap().0;
        let checkpoint = store.checkpoint().unwrap();
        drop(store);
        drop(node);
        for (field, wrong) in [
            ("operation_id", json!("another-operation")),
            ("intent_sha256", json!(hex::encode([99; 32]))),
            ("plan_sha256", json!(hex::encode([98; 32]))),
            ("evaluation_profile_sha256", json!(hex::encode([97; 32]))),
            ("payment_authorized", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            write(&f.readback, &changed);
            assert!(settle(&f.round, &f.readback).is_err());
            let (node, store) = open_existing(&f.round).unwrap();
            assert_eq!(store.checkpoint().unwrap(), checkpoint);
            assert_eq!(node.active().unwrap().0, reserved);
        }
        write(&f.readback, &value);
        let paid = settle(&f.round, &f.readback).unwrap();
        assert_eq!(paid["status"], "PAID_CURRENT_BRANCH");
        assert_eq!(paid["current_branch_base_fee"], 2000);
        assert_eq!(paid["improvement_bonus"], 0);
        assert_eq!(paid["anti_sybil_consensus_credit"], 0);
        assert_eq!(paid["no_update_decided"], false);
        assert_eq!(paid["model_state_unchanged"], true);
        assert_eq!(
            paid["current_native_observation"]["declared_costs"]["outcome"],
            "NoGain"
        );
        assert_eq!(
            paid["current_native_observation"]["current_payment"]["beneficiary_credit"],
            2000
        );
        let (node, store) = open_existing(&f.round).unwrap();
        let settled_tip = node.active().unwrap().0;
        let historical = store.snapshot(def.binding.claim).unwrap();
        drop(store);
        drop(node);
        fs::rename(&f.output, f.output.with_file_name("provider-disappeared")).unwrap();
        let cold = query(&f.round).unwrap();
        assert_eq!(cold["status"], "PAID_CURRENT_BRANCH");
        assert_eq!(cold["provider_terminal_retained"], true);
        let (mut node, store) = open_existing(&f.round).unwrap();
        // Original fork choice refuses a lighter ancestor. Execute a genuinely
        // heavier competing branch that excludes both delivery and payment.
        let fork = extend_empty(&mut node, reserved, 3);
        assert_eq!(node.active().unwrap().0, fork);
        assert_eq!(store.snapshot(def.binding.claim).unwrap(), historical);
        assert!(
            !node
                .begin_task_operation_v2(&def.binding)
                .unwrap()
                .new_execution
        );
        drop(store);
        drop(node);
        let rewound = query(&f.round).unwrap();
        assert_eq!(rewound["current_branch_base_fee"], 0);
        assert_eq!(rewound["historically_observed_base_fee"], 2000);
        let (mut node, store) = open_existing(&f.round).unwrap();
        assert_eq!(node.active().unwrap().0, fork);
        let restored = extend_empty(&mut node, settled_tip, 2);
        assert_eq!(node.active().unwrap().0, restored);
        drop(store);
        drop(node);
        assert_eq!(query(&f.round).unwrap()["current_branch_base_fee"], 2000);
    }

    #[test]
    fn lost_payment_ack_recovers_original_wire_without_reexecution() {
        let f = Fixture::new();
        let value = f.complete();
        let (def, success) = f.success(&value);
        let (mut node, mut store) = open_existing(&f.round).unwrap();
        retain_success(&f.round, &def, &success).unwrap();
        record_success(&mut store, &def, &success).unwrap();
        let delivery = delivery_wire(&def, success.output).unwrap();
        dispatch_once(
            &mut node,
            &f.round.join("delivery-intent.json"),
            &def,
            &delivery,
        )
        .unwrap();
        store.bind_delivery(&mut node, def.binding.claim).unwrap();
        let receipted = node.active().unwrap().0;
        let payment = payment_wire(&def, success.output, success.receipt).unwrap();
        dispatch_once(
            &mut node,
            &f.round.join("payment-intent.json"),
            &def,
            &payment,
        )
        .unwrap();
        let paid = node.active().unwrap();
        assert!(store.snapshot(def.binding.claim).unwrap().payment.is_none());
        // Actual debit committed; lose the reply before the M12 observation.
        drop(store);
        drop(node);
        let recovered = query(&f.round).unwrap();
        assert_eq!(recovered["current_branch_base_fee"], 2000);
        let (mut node, store) = open_existing(&f.round).unwrap();
        assert_eq!(node.active().unwrap(), paid);
        assert_eq!(
            store
                .snapshot(def.binding.claim)
                .unwrap()
                .payment
                .unwrap()
                .operation,
            transaction_id(&payment).unwrap()
        );
        let fork = extend_empty(&mut node, receipted, 2);
        assert_eq!(node.active().unwrap().0, fork);
        let before = node.active().unwrap();
        drop(store);
        drop(node);
        let after_reorg = settle(&f.round, &f.readback).unwrap();
        assert_eq!(after_reorg["current_branch_base_fee"], 0);
        let (node, _) = open_existing(&f.round).unwrap();
        assert_eq!(node.active().unwrap(), before);
    }

    #[test]
    fn predispatch_crash_and_local_revocation_never_regrant_effects() {
        let f = Fixture::new();
        let value = f.complete();
        let (def, success) = f.success(&value);
        let (mut node, mut store) = open_existing(&f.round).unwrap();
        retain_success(&f.round, &def, &success).unwrap();
        record_success(&mut store, &def, &success).unwrap();
        let before = node.active().unwrap();
        let wire = delivery_wire(&def, success.output).unwrap();
        let (intent, packet) = step_intent(&node, &def, &wire).unwrap();
        save_new(
            &f.round.join("delivery-intent.json"),
            &serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        assert!(node.packet(packet.id().unwrap()).is_err());
        assert!(
            !node
                .begin_task_operation_v2(&def.binding)
                .unwrap()
                .new_execution
        );
        drop(store);
        drop(node);
        assert_eq!(
            settle(&f.round, &f.readback).unwrap()["current_branch_base_fee"],
            0
        );
        let (node, _) = open_existing(&f.round).unwrap();
        assert_eq!(node.active().unwrap(), before);
        assert!(node.packet(packet.id().unwrap()).is_err());
        drop(node);
        let revoked = revoke(&f.round).unwrap();
        assert_eq!(revoked["locally_revoked"], true);
        assert_eq!(revoked["provider_cancellation_observed"], false);
        let (mut node, store) = open_existing(&f.round).unwrap();
        let fork = extend_empty(&mut node, settings().unwrap().genesis(), 2);
        assert_eq!(node.active().unwrap().0, fork);
        drop(store);
        drop(node);
        assert_eq!(query(&f.round).unwrap()["locally_revoked"], true);
        let (mut node, store) = open_existing(&f.round).unwrap();
        let original_branch = extend_empty(&mut node, before.0, 2);
        assert_eq!(node.active().unwrap().0, original_branch);
        let restored = node.active().unwrap();
        drop(store);
        drop(node);
        let refused = settle(&f.round, &f.readback).unwrap();
        assert_eq!(refused["settlement_blocked"], "LOCAL_REVOKED");
        assert_eq!(refused["current_branch_base_fee"], 0);
        let (node, _) = open_existing(&f.round).unwrap();
        assert_eq!(node.active().unwrap(), restored);
        assert!(node.packet(packet.id().unwrap()).is_err());
    }
}
