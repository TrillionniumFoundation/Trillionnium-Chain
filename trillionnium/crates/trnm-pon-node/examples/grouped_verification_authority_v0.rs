//! Closed-owner loopback research transport. All signing keys are PUBLIC TEST
//! keys. Separate receiver processes share one owner; no Prove operation is
//! exposed by that service. Producers supply proof bytes in the client plan.
//! No independent operators, genuine demand, WAN security or credit is claimed.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::{
    pon_grouped_fresh_seal_v0 as seal, pon_routed_int257_grouped as grouped, public_key_hex,
    sign_hex, signing_key_from_hex, verify_hex_strict,
};
use trnm_pon_node::{
    grouped_fresh_admission_v0 as admission, grouped_verification_authority_v0 as owner,
    sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};

const MAX_FILE: usize = 2 * 1024 * 1024;
const MAX_FRAME: usize = 16 * 1024;
const CONFIG_SCHEMA: &str = "pon-grouped-owner-fixture-config-v0";
type Result<T> = std::result::Result<T, String>;
fn checked<T, E: std::fmt::Debug>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| format!("{e:?}"))
}
fn h(s: &str) -> Result<Hash> {
    if s.len() != 64 || s.bytes().any(|x| !matches!(x,b'0'..=b'9'|b'a'..=b'f')) {
        return Err("CANONICAL_HASH".into());
    }
    checked(checked(hex::decode(s))?.try_into())
}
fn seed(index: u64) -> String {
    hex::encode(hash(b"DEV-ONLY-GROUPED-OWNER-KEY", &[&index.to_be_bytes()]))
}
fn public(index: u64) -> Result<Hash> {
    h(&public_key_hex(&checked(signing_key_from_hex(&seed(
        index,
    )))?))
}
fn sign(index: u64, message: &[u8]) -> Result<Vec<u8>> {
    checked(hex::decode(sign_hex(
        &checked(signing_key_from_hex(&seed(index)))?,
        message,
    )))
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            v => v.clone(),
        }
    }
    checked(serde_json::to_vec(&sorted(value)))
}
fn parse(raw: &[u8]) -> Result<Value> {
    let value: Value = checked(serde_json::from_slice(raw))?;
    if canonical(&value)? != raw {
        return Err("CANONICAL_JSON_REQUIRED".into());
    }
    Ok(value)
}
fn read_file(path: &Path) -> Result<Vec<u8>> {
    let file = checked(File::open(path))?;
    if checked(file.metadata())?.len() > MAX_FILE as u64 {
        return Err("FILE_LIMIT".into());
    }
    let mut raw = Vec::new();
    checked(file.take((MAX_FILE + 1) as u64).read_to_end(&mut raw))?;
    if raw.len() > MAX_FILE {
        return Err("FILE_LIMIT".into());
    }
    Ok(raw)
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut f = checked(OpenOptions::new().write(true).create_new(true).open(path))?;
    checked(f.write_all(raw))?;
    checked(f.sync_all())
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    write_new(path, &canonical(value)?)
}
fn stdout(value: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    checked(out.write_all(&canonical(value)?))?;
    checked(out.write_all(b"\n"))?;
    checked(out.flush())
}
#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Option<u64> {
    None
}
struct Stamp {
    wall: Instant,
    cpu: Option<u64>,
}
impl Stamp {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_ns(),
        }
    }
    fn end(&self) -> Value {
        json!({"wall_ns":u64::try_from(self.wall.elapsed().as_nanos()).ok(),
        "main_thread_cpu_ns":self.cpu.zip(cpu_ns()).and_then(|(a,b)|b.checked_sub(a))})
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireModel {
    r#type: String,
    model_version: String,
    base: Vec<Vec<i32>>,
    router: Vec<Vec<i32>>,
    deltas: Vec<Vec<Vec<i32>>>,
}
fn matrix(v: Vec<Vec<i32>>) -> Result<grouped::Matrix> {
    let rows = v
        .into_iter()
        .map(|r| checked(r.try_into()))
        .collect::<Result<Vec<[i32; grouped::DIM]>>>()?;
    checked(rows.try_into())
}
impl WireModel {
    fn native(self) -> Result<grouped::Model> {
        if self.r#type != "init" {
            return Err("MODEL_TYPE".into());
        }
        Ok(grouped::Model {
            version: h(&self.model_version)?,
            base: matrix(self.base)?,
            router: matrix(self.router)?,
            deltas: checked(
                self.deltas
                    .into_iter()
                    .map(matrix)
                    .collect::<Result<Vec<_>>>()?
                    .try_into(),
            )?,
        })
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    id: String,
    scope: String,
    arrival_ns: u64,
    deadline_ns: u64,
    x: Vec<i32>,
}
impl WireRequest {
    fn native(self) -> Result<grouped::Request> {
        Ok(grouped::Request {
            id: h(&self.id)?,
            scope: h(&self.scope)?,
            arrival_ns: self.arrival_ns,
            deadline_ns: self.deadline_ns,
            x: checked(self.x.try_into())?,
        })
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    model_commitment: String,
    request_precommitment: String,
    batch_id: String,
    authorization_scope: String,
    demand_id: String,
    source_record: String,
    withdrawal_head: String,
    payee: String,
    model_generation: u64,
    timestamp_ms: u64,
    not_before_ns: u64,
    expires_ns: u64,
    available_until_ns: u64,
    nonce_first: u64,
    nonce_count: u64,
    now_ns: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    source_commit: String,
    clock_anchor_unix_ns: u64,
    init: WireModel,
    requests: Vec<WireRequest>,
    freeze: Freeze,
    epoch: String,
    generation: u64,
    aggregate_limit: u64,
    per_candidate_limit: u64,
}
struct Fixture {
    node: Node,
    relation: owner::FrozenRelation,
    policy: owner::BudgetPolicy,
    capsule: Vec<u8>,
    admission_pin: Value,
    now_ns: u64,
    clock_anchor_unix_ns: u64,
    prepare_cost: Value,
    source_commit: String,
    config_sha256: String,
}
// The immutable fixture anchor survives owner restarts. This uses the host's
// wall clock; a trusted cross-host clock or rollback-resistant time is not
// established. Rewind before the anchor and overflow fail expired.
fn fixture_now(base: u64, anchor: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .and_then(|t| t.checked_sub(anchor))
        .and_then(|delta| base.checked_add(delta))
        .unwrap_or(u64::MAX)
}
fn load_fixture(directory: &Path, raw: &[u8]) -> Result<Fixture> {
    let stamp = Stamp::start();
    let _ = parse(raw)?;
    let config: Config = checked(serde_json::from_slice(raw))?;
    if config.schema != CONFIG_SCHEMA
        || config.source_commit.len() != 40
        || config
            .source_commit
            .bytes()
            .any(|x| !matches!(x,b'0'..=b'9'|b'a'..=b'f'))
    {
        return Err("CONFIG_SCHEMA_OR_SOURCE".into());
    }
    let model = config.init.native()?;
    let requests = config
        .requests
        .into_iter()
        .map(WireRequest::native)
        .collect::<Result<Vec<_>>>()?;
    let node = checked(Node::open(
        &directory.join("native-node.sqlite"),
        checked(Settings::development(Some(1_700_000_000)))?,
        1,
    ))?;
    let f = config.freeze;
    let registry = hash(
        b"pon-grouped-owner-fixture-registry-v0",
        &[&h(&f.model_commitment)?, &h(&f.request_precommitment)?],
    );
    let registry_digest = hash(b"pon-grouped-owner-fixture-config-v0", &[raw]);
    let body = checked(admission::CapsuleBody::from_node(
        &node,
        admission::CapsuleIntent {
            registry_id: registry,
            registry_digest,
            previous_registry_digest: [0; 32],
            demand_id: h(&f.demand_id)?,
            source_record: h(&f.source_record)?,
            authorization_scope: h(&f.authorization_scope)?,
            withdrawal_head: h(&f.withdrawal_head)?,
            model_commitment: h(&f.model_commitment)?,
            request_precommitment: h(&f.request_precommitment)?,
            batch_id: h(&f.batch_id)?,
            transactions_commitment: sequence_root("transactions", &[]),
            payee: h(&f.payee)?,
            operation_id: hash(
                b"pon-grouped-owner-fixture-operation-v0",
                &[&registry_digest],
            ),
            registry_sequence: 1,
            model_generation: f.model_generation,
            timestamp_ms: f.timestamp_ms,
            not_before_ns: f.not_before_ns,
            expires_ns: f.expires_ns,
            available_until_ns: f.available_until_ns,
            nonce_first: f.nonce_first,
            nonce_count: f.nonce_count,
        },
    ))?;
    let capsule = admission::signed_capsule(
        &body,
        checked(
            sign(
                40,
                &admission::signing_message(&body, admission::SigningRole::Requester),
            )?
            .try_into(),
        )?,
        checked(
            sign(
                41,
                &admission::signing_message(&body, admission::SigningRole::Source),
            )?
            .try_into(),
        )?,
    );
    let pin = admission::PinnedAuthority {
        requester_key: public(40)?,
        source_key: public(41)?,
        latest_sequence: 1,
        latest_digest: registry_digest,
        expected_capsule_sha256: admission::sha256(&capsule),
        expected: body,
    };
    let current_ns = fixture_now(f.now_ns, config.clock_anchor_unix_ns);
    let verified = checked(admission::verify_capsule(&capsule, &pin, &node, current_ns))?;
    let relation = checked(owner::FrozenRelation::prepare(
        verified, model, requests, &node, current_ns,
    ))?;
    let policy = checked(owner::BudgetPolicy::new(
        public(75)?,
        h(&config.epoch)?,
        config.generation,
        config.aggregate_limit,
        config.per_candidate_limit,
        vec![public(73)?, public(74)?],
        &relation,
    ))?;
    let prepare_cost = json!({"measurement":stamp.end(),"source_input_bytes":raw.len(),
        "prepared_model_instances":1,"cached_model_merge_additions":3*3*257,
        "direct_business_observations":f.nonce_count,"direct_business_macs":f.nonce_count*16*6*257,
        "seal_seed_queries":0,"seal_step_queries":0,
        "scope":"config read is measured by caller; parsing,Node open,signatures,model preparation and one direct observation per candidate measured here"});
    Ok(Fixture {
        node,
        relation,
        policy,
        capsule,
        admission_pin: json!({"body_hex":hex::encode(pin.expected.encode()),"policy_id":hex::encode(pin.policy_id()),
            "requester_key":hex::encode(pin.requester_key),"source_key":hex::encode(pin.source_key),
            "capsule_sha256":hex::encode(pin.expected_capsule_sha256),"native_branch":pin.expected.branch().observation(),
            "fixture_keys_public":true,"independent_operators":false,"external_demand_authenticated":false}),
        now_ns: f.now_ns,
        clock_anchor_unix_ns: config.clock_anchor_unix_ns,
        prepare_cost,
        source_commit: config.source_commit,
        config_sha256: hex::encode(admission::sha256(raw)),
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProduct {
    router_outputs: Vec<[i64; 3]>,
    routes: Vec<usize>,
    groups: [Vec<usize>; 3],
    logits: Vec<[i64; 3]>,
    predictions: Vec<usize>,
    useful_dense_macs: u64,
    padded_macs: u64,
    nonempty_expert_groups: usize,
}
impl WireProduct {
    fn from_native(p: grouped::Product) -> Self {
        Self {
            router_outputs: p.router_outputs,
            routes: p.routes,
            groups: p.groups,
            logits: p.logits,
            predictions: p.predictions,
            useful_dense_macs: p.useful_dense_macs,
            padded_macs: p.padded_macs,
            nonempty_expert_groups: p.nonempty_expert_groups,
        }
    }
    fn native(self) -> grouped::Product {
        grouped::Product {
            router_outputs: self.router_outputs,
            routes: self.routes,
            groups: self.groups,
            logits: self.logits,
            predictions: self.predictions,
            useful_dense_macs: self.useful_dense_macs,
            padded_macs: self.padded_macs,
            nonempty_expert_groups: self.nonempty_expert_groups,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireClaim {
    model_commitment: String,
    input_commitment: String,
    statement_commitment: String,
    product: WireProduct,
}
impl WireClaim {
    fn from_native(o: grouped::Observation) -> Self {
        Self {
            model_commitment: hex::encode(o.model_commitment),
            input_commitment: hex::encode(o.input_commitment),
            statement_commitment: hex::encode(o.statement_commitment),
            product: WireProduct::from_native(o.product),
        }
    }
    fn native(self) -> Result<grouped::Observation> {
        Ok(grouped::Observation {
            model_commitment: h(&self.model_commitment)?,
            input_commitment: h(&self.input_commitment)?,
            statement_commitment: h(&self.statement_commitment)?,
            product: self.product.native(),
        })
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedCommand {
    action: String,
    request_id: String,
    candidate: String,
    claim: WireClaim,
    proof_hex: String,
}
impl UnsignedCommand {
    fn action(&self) -> Result<owner::Action> {
        match self.action.as_str() {
            "reserve" => Ok(owner::Action::Reserve),
            "execute" => Ok(owner::Action::Execute),
            _ => Err("ACTION".into()),
        }
    }
    fn native(self, receiver: Hash, signature: Vec<u8>) -> Result<owner::Submission> {
        if self.proof_hex.len() > 2 * seal::PROOF_BYTES
            || !self.proof_hex.len().is_multiple_of(2)
            || self
                .proof_hex
                .bytes()
                .any(|x| !matches!(x,b'0'..=b'9'|b'a'..=b'f'))
        {
            return Err("PROOF_HEX".into());
        }
        Ok(owner::Submission {
            receiver,
            request_id: h(&self.request_id)?,
            candidate: h(&self.candidate)?,
            claim: self.claim.native()?,
            proof: checked(hex::decode(self.proof_hex))?,
            signature,
        })
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCommand {
    command: UnsignedCommand,
    receiver: String,
    signature_hex: String,
}

/// Explicit local-fixture instrumentation, never a new network wire action.
/// The existing Execute signature still binds the original command only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedCommandV1 {
    schema: String,
    command: UnsignedCommand,
    cancel_after_query: Option<u16>,
    abort_after_query: Option<u16>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    schema: String,
    address: String,
    policy: String,
    authority: String,
    config_sha256: String,
    source_commit: String,
    runner_sha256: String,
    fixture_keys_public: bool,
}
fn runner_sha() -> Result<String> {
    Ok(hex::encode(admission::sha256(&checked(std::fs::read(
        checked(std::env::current_exe())?,
    ))?)))
}
fn response_message(policy: Hash, payload: &Value) -> Result<Hash> {
    Ok(hash(
        b"pon-grouped-owner-response-v0",
        &[&policy, &canonical(payload)?],
    ))
}
fn response(policy: Hash, payload: Value) -> Result<Value> {
    Ok(
        json!({"payload":payload,"authority":hex::encode(public(75)?),
        "signature_hex":hex::encode(sign(75,&response_message(policy,&payload)?)?)}),
    )
}
fn read_frame(stream: &mut TcpStream) -> (Vec<u8>, Result<Value>) {
    let mut raw = Vec::new();
    let result = BufReader::new(stream)
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut raw);
    let parsed = match result {
        Err(e) => Err(format!("WIRE_READ_{:?}", e.kind())),
        Ok(_) => {
            if raw.len() > MAX_FRAME {
                Err("WIRE_LIMIT".into())
            } else if !raw.ends_with(b"\n") {
                Err("UNTERMINATED_WIRE".into())
            } else {
                parse(&raw[..raw.len() - 1])
            }
        }
    };
    (raw, parsed)
}

fn prepare(directory: &Path, config_path: &Path) -> Result<()> {
    let whole = Stamp::start();
    let raw = read_file(config_path)?;
    checked(std::fs::create_dir(directory))?;
    write_new(&directory.join("config.json"), &raw)?;
    let f = load_fixture(directory, &raw)?;
    let authority = checked(owner::VerificationAuthority::create(
        &directory.join("authority.sqlite"),
        f.policy.clone(),
    ))?;
    write_new(&directory.join("capsule.bin"), &f.capsule)?;
    let mut candidates = f.relation.candidates();
    for item in candidates.as_array_mut().ok_or("CANDIDATES")? {
        let id = h(item["candidate"].as_str().ok_or("CANDIDATE")?)?;
        item["claim"] = checked(serde_json::to_value(WireClaim::from_native(checked(
            f.relation.canonical_claim(id),
        )?)))?;
    }
    let report = json!({"schema":"pon-grouped-owner-preparation-v0","policy":f.policy.observation(),
        "admission_pin":f.admission_pin,"candidates":candidates,"prepare_cost":f.prepare_cost,
        "whole_before_manifest_write":whole.end(),"initial_budget":checked(authority.snapshot())?,
        "config_sha256":f.config_sha256,"source_commit":f.source_commit,"runner_sha256":runner_sha()?,
        "producer_seal_queries":0,"no_service_prove_operation":true,"chainwork_awarded":0,
        "production_activation":false});
    write_json(&directory.join("preparation.json"), &report)?;
    stdout(&report)
}

fn execute_observed_v1(
    directory: &Path,
    request_path: &Path,
    output: &Path,
    receiver_fixture_index: u64,
) -> Result<()> {
    if !directory.is_absolute() || !request_path.is_absolute() || !output.is_absolute() {
        return Err("OBSERVED_ABSOLUTE_PATHS_REQUIRED".into());
    }
    let whole = Stamp::start();
    let request_raw = read_file(request_path)?;
    let request: ObservedCommandV1 = checked(serde_json::from_value(parse(&request_raw)?))?;
    if request.schema != "pon-grouped-owner-observed-command-v1"
        || request.command.action != "execute"
        || request.cancel_after_query.is_some_and(|n| n > seal::STEPS)
        || request.abort_after_query.is_some_and(|n| n > seal::STEPS)
        || (request.cancel_after_query.is_some() && request.abort_after_query.is_some())
        || !matches!(receiver_fixture_index, 73 | 74)
    {
        return Err("OBSERVED_FIXTURE_COMMAND".into());
    }
    let name = output
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("OBSERVED_OUTPUT_NAME")?;
    let trace_path = output.with_file_name(format!("{name}.queries.ndjson"));
    // Reserve both create-only destinations before an attempt can begin. An
    // interrupted output may be empty; its durable query prefix remains here.
    let mut output_file = checked(OpenOptions::new().write(true).create_new(true).open(output))?;
    let mut trace_file = checked(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&trace_path),
    )?;
    let raw = read_file(&directory.join("config.json"))?;
    let f = load_fixture(directory, &raw)?;
    let binary_sha = runner_sha()?;
    let mut authority = checked(owner::VerificationAuthority::open(
        &directory.join("authority.sqlite"),
        f.policy.clone(),
    ))?;
    let mut submission = request
        .command
        .clone()
        .native(public(receiver_fixture_index)?, Vec::new())?;
    submission.signature = sign(
        receiver_fixture_index,
        &checked(submission.signing_message(&f.policy, owner::Action::Execute))?,
    )?;
    let signed_request = WireCommand {
        command: request.command,
        receiver: hex::encode(submission.receiver),
        signature_hex: hex::encode(&submission.signature),
    };
    let mut observations = Vec::with_capacity(usize::from(seal::STEPS) + 1);
    let mut capture_error = None;
    let execution = authority.execute_with_query_observer(
        &submission,
        &f.relation,
        &f.node,
        || fixture_now(f.now_ns, f.clock_anchor_unix_ns),
        |_| true,
        |event| {
            if observations.len() > usize::from(seal::STEPS) {
                capture_error = Some("OBSERVED_QUERY_LIMIT".to_owned());
                return false;
            }
            let value = event.observation();
            observations.push(value.clone());
            let persisted = canonical(&value).and_then(|mut raw| {
                raw.push(b'\n');
                checked(trace_file.write_all(&raw))?;
                checked(trace_file.sync_all())
            });
            if let Err(error) = persisted {
                capture_error = Some(error);
                return false;
            }
            if request.abort_after_query == Some(event.ordinal()) {
                let _ = stdout(
                    &json!({"schema":"pon-grouped-owner-observer-interruption-v1",
                    "after_query_ordinal":event.ordinal(),"event_id":hex::encode(event.event_id()),
                    "prefix_fsynced":true,"deliberate_fixture_exit_code":86,
                    "original_started_reservation_must_reconcile_without_reexecution":true}),
                );
                // Controlled test interruption; no unwinding, core dump or
                // artificial journal mutation. The native started fence remains.
                std::process::exit(86);
            }
            request.cancel_after_query != Some(event.ordinal())
        },
    );
    let observed_seed = observations
        .iter()
        .filter(|row| row["kind"] == "seed")
        .count();
    let observed_steps = observations
        .iter()
        .filter(|row| row["kind"] == "step")
        .count();
    let invocation_complete = match &execution {
        Ok(owner::SubmissionState::Complete {
            receipt,
            cached: false,
        }) => {
            capture_error.is_none()
                && observed_seed as u64 == receipt.cost.seed_queries
                && observed_steps as u64 == receipt.cost.step_queries
        }
        Ok(
            owner::SubmissionState::Complete { cached: true, .. }
            | owner::SubmissionState::Unknown { .. },
        ) => observations.is_empty(),
        _ => false,
    };
    let native_result = match &execution {
        Ok(state) => json!({"ok":true,"result":state.observation()}),
        Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
    };
    let snapshot = match authority.snapshot() {
        Ok(value) => json!({"ok":true,"result":value}),
        Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
    };
    let report = json!({"schema":"pon-grouped-owner-execution-observation-v1",
        "source_commit":f.source_commit,"runner_sha256":binary_sha,"config_sha256":f.config_sha256,
        "request_sha256":hex::encode(admission::sha256(&request_raw)),"signed_request":signed_request,
        "policy":f.policy.observation(),"native_result":native_result,"snapshot":snapshot,
        "query_observations":observations,"observed_seed_queries":observed_seed,
        "observed_step_queries":observed_steps,"query_prefix_path":trace_path,
        "this_invocation_trace_complete":invocation_complete,"capture_error":capture_error,
        "startup_prepare_cost":f.prepare_cost,"whole_before_report_write":whole.end(),
        "query_scope":"only this invocation's actual native post-hash seed/step callbacks; seed_hash is separate from the step-oracle denomination",
        "observer_cost_scope":"event framing,metadata hashes,JSON and fsynced prefix writes are real observer overhead inside owner replay wall time; not additional seal-step queries",
        "unknown_cost_scope":"a retained prefix is a subset of the original UNKNOWN upper bound, never an extra charge on top of that bound",
        "historical_trace_reconstructed":false,"public_query_coverage_complete":false,
        "fixture_keys_public":true,"independent_operators":false,"external_demand_authenticated":false,
        "physical_resource_lower_bound_proved":false,"chainwork_awarded":0,"production_activation":false});
    checked(output_file.write_all(&canonical(&report)?))?;
    checked(output_file.sync_all())?;
    stdout(&report)
}

fn serve(directory: &Path, run_directory: &Path, max_connections: usize) -> Result<()> {
    if !(1..=1024).contains(&max_connections) {
        return Err("CONNECTION_LIMIT".into());
    }
    let whole = Stamp::start();
    checked(std::fs::create_dir(run_directory))?;
    checked(std::fs::create_dir(run_directory.join("packets")))?;
    let raw = read_file(&directory.join("config.json"))?;
    let f = load_fixture(directory, &raw)?;
    let mut authority = checked(owner::VerificationAuthority::open(
        &directory.join("authority.sqlite"),
        f.policy.clone(),
    ))?;
    let listener = checked(TcpListener::bind("127.0.0.1:0"))?;
    checked(listener.set_nonblocking(true))?;
    let endpoint = Endpoint {
        schema: "pon-grouped-owner-endpoint-v0".into(),
        address: checked(listener.local_addr())?.to_string(),
        policy: hex::encode(f.policy.id()),
        authority: hex::encode(public(75)?),
        config_sha256: f.config_sha256.clone(),
        source_commit: f.source_commit.clone(),
        runner_sha256: runner_sha()?,
        fixture_keys_public: true,
    };
    let endpoint_value = checked(serde_json::to_value(&endpoint))?;
    write_json(&run_directory.join("endpoint.json"), &endpoint_value)?;
    stdout(&endpoint_value)?;
    let mut events = Vec::new();
    let mut received = 0_u64;
    let mut sent = 0_u64;
    let deadline = Instant::now() + Duration::from_secs(30);
    while events.len() < max_connections && Instant::now() < deadline {
        let (mut stream, peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(e) => return Err(format!("ACCEPT_{:?}", e.kind())),
        };
        if !peer.ip().is_loopback() {
            return Err("NON_LOOPBACK_PEER".into());
        }
        checked(stream.set_read_timeout(Some(Duration::from_secs(1))))?;
        checked(stream.set_write_timeout(Some(Duration::from_secs(1))))?;
        let stamp = Stamp::start();
        let (request_raw, parsed) = read_frame(&mut stream);
        received += request_raw.len() as u64;
        let request_hash = hex::encode(admission::sha256(&request_raw));
        let number = events.len() + 1;
        write_new(
            &run_directory.join(format!("packets/{number:04}.request.json")),
            &request_raw,
        )?;
        let result = parsed.and_then(|value| {
            let wire: WireCommand = checked(serde_json::from_value(value))?;
            let action = wire.command.action()?;
            let submission = wire.command.native(
                h(&wire.receiver)?,
                checked(hex::decode(&wire.signature_hex))?,
            )?;
            let result = match action {
                owner::Action::Reserve => authority.reserve(&submission),
                owner::Action::Execute => authority.execute(
                    &submission,
                    &f.relation,
                    &f.node,
                    || fixture_now(f.now_ns, f.clock_anchor_unix_ns),
                    |_| true,
                ),
            };
            Ok(checked(result)?.observation())
        });
        let body = match result {
            Ok(result) => json!({"ok":true,"result":result}),
            Err(error) => json!({"ok":false,"error":error}),
        };
        let payload = json!({"schema":"pon-grouped-owner-wire-response-v0","policy":endpoint.policy,
            "request_sha256":request_hash,"body":body,"chainwork_awarded":0});
        let signed = response(f.policy.id(), payload)?;
        let mut response_raw = canonical(&signed)?;
        response_raw.push(b'\n');
        write_new(
            &run_directory.join(format!("packets/{number:04}.response.json")),
            &response_raw,
        )?;
        let send = stream.write_all(&response_raw).and_then(|_| stream.flush());
        if send.is_ok() {
            sent += response_raw.len() as u64;
        }
        events.push(json!({"sequence":number,"request_sha256":request_hash,
            "request_bytes":request_raw.len(),"response_sha256":hex::encode(admission::sha256(&response_raw)),
            "response_bytes_written":send.as_ref().ok().map(|_|response_raw.len()),
            "response_bytes_attempted":response_raw.len(),"send_error":send.err().map(|e|format!("{:?}",e.kind())),
            "response":signed,"measurement":stamp.end()}));
    }
    let report = json!({"schema":"pon-grouped-owner-service-run-v0","endpoint":endpoint_value,
        "planned_connections":max_connections,"actual_connections":events.len(),"complete":events.len()==max_connections,
        "startup_prepare_cost":f.prepare_cost,"startup_replays_business_preparation":true,
        "events":events,"snapshot":checked(authority.snapshot())?,"whole_before_report_write":whole.end(),
        "tcp_application_bytes_received":received,"tcp_application_bytes_written_known":sent,
        "byte_counter_scope":"retained one-frame application bytes; a temporary BufReader may prefetch and discard malicious trailing bytes; not all socket/TCP-wire traffic",
        "side_channels_hidden":false,"all_keys_public_fixtures":true,"independent_operators":false,
        "WAN_TLS_measured":false,"no_service_prove_operation":true,"chainwork_awarded":0});
    write_json(&run_directory.join("service-report.json"), &report)?;
    stdout(
        &json!({"complete":report["complete"],"actual_connections":report["actual_connections"],"report":run_directory.join("service-report.json")}),
    )
}

fn client(
    endpoint_path: &Path,
    requests_path: &Path,
    output: &Path,
    receiver_index: u64,
) -> Result<()> {
    let whole = Stamp::start();
    let endpoint_raw = read_file(endpoint_path)?;
    let _ = parse(&endpoint_raw)?;
    let endpoint: Endpoint = checked(serde_json::from_slice(&endpoint_raw))?;
    if endpoint.schema != "pon-grouped-owner-endpoint-v0"
        || h(&endpoint.authority)? != public(75)?
        || !endpoint.fixture_keys_public
    {
        return Err("EXPECTED_OWNER_PIN".into());
    }
    let address: SocketAddr = checked(endpoint.address.parse())?;
    if !address.ip().is_loopback() {
        return Err("LOOPBACK_ONLY".into());
    }
    let policy = h(&endpoint.policy)?;
    let raw = read_file(requests_path)?;
    let _ = parse(&raw)?;
    let commands: Vec<UnsignedCommand> = checked(serde_json::from_slice(&raw))?;
    if commands.is_empty() || commands.len() > 256 {
        return Err("CLIENT_PLAN_LIMIT".into());
    }
    let receiver = public(receiver_index)?;
    let planned = commands.len();
    let mut events = Vec::new();
    for (i, command) in commands.into_iter().enumerate() {
        let stamp = Stamp::start();
        let action = command.action()?;
        let submission = command.clone().native(receiver, Vec::new())?;
        let message = checked(submission.signing_message_for_policy_id(policy, action))?;
        let wire = WireCommand {
            command,
            receiver: hex::encode(receiver),
            signature_hex: hex::encode(sign(receiver_index, &message)?),
        };
        let mut request_raw = canonical(&checked(serde_json::to_value(wire))?)?;
        request_raw.push(b'\n');
        let request_hash = hex::encode(admission::sha256(&request_raw));
        let mut sent = None;
        let mut response_raw = Vec::new();
        let result = (|| -> Result<Value> {
            let mut stream = checked(TcpStream::connect_timeout(&address, Duration::from_secs(3)))?;
            checked(stream.set_read_timeout(Some(Duration::from_secs(3))))?;
            checked(stream.set_write_timeout(Some(Duration::from_secs(3))))?;
            checked(stream.write_all(&request_raw))?;
            checked(stream.flush())?;
            sent = Some(request_raw.len());
            let (raw, parsed) = read_frame(&mut stream);
            response_raw = raw;
            let value = parsed?;
            let object = value.as_object().ok_or("RESPONSE_OBJECT")?;
            if object.len() != 3
                || !object.contains_key("payload")
                || !object.contains_key("authority")
                || !object.contains_key("signature_hex")
            {
                return Err("RESPONSE_FIELDS".into());
            }
            let payload = &value["payload"];
            if value["authority"] != endpoint.authority
                || payload["policy"] != endpoint.policy
                || payload["request_sha256"] != request_hash
            {
                return Err("RESPONSE_BINDING".into());
            }
            checked(verify_hex_strict(
                &endpoint.authority,
                &response_message(policy, payload)?,
                value["signature_hex"].as_str().ok_or("SIGNATURE")?,
            ))?;
            Ok(value)
        })();
        events.push(json!({"planned_index":i,"request_sha256":request_hash,"request_raw_hex":hex::encode(&request_raw),
            "request_bytes_attempted":request_raw.len(),"request_bytes_written":sent,
            "response_raw_hex":hex::encode(&response_raw),"response_bytes":response_raw.len(),
            "authenticated_fixture_response":result.is_ok(),"response":result.as_ref().ok(),"error":result.as_ref().err(),
            "measurement":stamp.end()}));
    }
    let all = events
        .iter()
        .all(|e| e["authenticated_fixture_response"] == true);
    let report = json!({"schema":"pon-grouped-owner-receiver-run-v0","receiver":hex::encode(receiver),
        "pid":std::process::id(),"endpoint":endpoint,"planned_attempts":planned,"actual_attempts":events.len(),
        "all_responses_authenticated_fixture":all,"events":events,"whole_before_report_write":whole.end(),
        "proof_generation_inside_receiver":false,"receiver_seal_queries":0,"fixture_keys_public":true,
        "chainwork_awarded":0,"source_requests_sha256":hex::encode(admission::sha256(&raw))});
    write_json(output, &report)?;
    stdout(
        &json!({"all_responses_authenticated_fixture":all,"actual_attempts":planned,"output":output}),
    )
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode,dir,config] if mode=="prepare"=>prepare(&PathBuf::from(dir),&PathBuf::from(config)),
        [mode,dir,request,out,receiver] if mode=="execute_observed_v1"=>execute_observed_v1(&PathBuf::from(dir),&PathBuf::from(request),&PathBuf::from(out),checked(receiver.parse())?),
        [mode,dir,out,count] if mode=="serve"=>serve(&PathBuf::from(dir),&PathBuf::from(out),checked(count.parse())?),
        [mode,endpoint,requests,out,receiver] if mode=="client"=>client(&PathBuf::from(endpoint),&PathBuf::from(requests),&PathBuf::from(out),checked(receiver.parse())?),
        _=>Err("usage: prepare OWNER_DIR CONFIG_JSON | execute_observed_v1 OWNER_DIR COMMAND_JSON OUTPUT_JSON RECEIVER_FIXTURE_INDEX | serve OWNER_DIR RUN_DIR MAX_CONNECTIONS | client ENDPOINT_JSON REQUESTS_JSON OUTPUT_JSON RECEIVER_FIXTURE_INDEX".into()),
    }
}
