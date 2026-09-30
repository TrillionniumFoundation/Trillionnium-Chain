//! Bounded lifecycle transitions under the existing native ledger owner. This module
//! does not authenticate the main envelope, charge its fee, issue mining rewards,
//! change the work relation, or replace local irrevocable withdrawal/effect history.
use crate::pon_executor::{Config, Result, State};
use serde_json::{json, Value};
use trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_statement;
use trnm_crypto_primitives::{pon_work, qualified_work_task::derive_matrices};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{
            DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2, DEMAND_LEASE_BYTES,
            DEMAND_SLOTS, LIFECYCLE_TASK_BYTES, OPEN_TAG, PROFILE, REGISTER_TAG, RENEW_TAG,
            REVOKE_TAG,
        },
        lifecycle_v3::{AtomicRenewTaskV3, ATOMIC_RENEW_TAG, PROFILE as ATOMIC_PROFILE},
        QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
    },
};

/// Shared bounded codecs; the configured network/parameters distinguish V2 and V3.
pub fn enabled(cfg: &Config) -> bool {
    matches!(cfg.task_profile(), PROFILE | ATOMIC_PROFILE)
}

pub const SLOT_PREFIX: &str = "qualified-demand-slot-v2:";
pub const GENERATION_KEY: &str = "qualified-demand-generation-v2";
pub const RECORD_SCHEMA: &str = "qualified-demand-slot-record-v2";
pub const MAX_RECORD_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct BootstrapLifecycleTask {
    pub state: State,
    pub lease: DemandLeaseV2,
    pub signed: SignedLifecycleTaskV2,
}
/// Explicit public-development genesis fixture. Actual supplied matrix artifacts
/// are checked; this is maintenance with zero useful-output credit, not user demand
/// or private production custody. Returned state contains lifecycle keys only.
pub fn bootstrap_state(cfg: &Config, model: &[u8], input: &[u8]) -> Result<BootstrapLifecycleTask> {
    ensure(enabled(cfg), "WORK_TASK_PROFILE")?;
    let (a, b) = derive_matrices(model, input).map_err(|_| "TASK_MATERIAL")?;
    let source_seed = hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]);
    let requester_seed = hash(b"DEV-ONLY-KEY", &[&1_u64.to_le_bytes()]);
    let source_key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(source_seed))
        .map_err(|_| "TASK_SOURCE")?;
    let requester_key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(requester_seed))
        .map_err(|_| "TASK_REQUESTER")?;
    let model_id = hash(b"artifact", &[model]);
    let input_id = hash(b"qualified-task-input-v1", &[input]);
    let mut current = DemandLeaseV2 {
        slot: 0,
        purpose: TaskPurpose::Maintenance,
        network: cfg.network,
        parameters: cfg.parameters,
        demand_id: [1; 32],
        requester: requester_key.verifying_key().to_bytes(),
        source: source_key.verifying_key().to_bytes(),
        source_record: hash(
            b"qualified-bootstrap-source-record-v2",
            &[
                &cfg.network,
                &cfg.parameters,
                &model_id,
                &input_id,
                b"public-fixture-not-user-demand",
            ],
        ),
        authorization_scope: hash(
            b"qualified-bootstrap-authorization-v2",
            &[
                &cfg.network,
                &cfg.parameters,
                b"development-attestation-not-local-permission",
            ],
        ),
        availability_manifest: hash(
            b"qualified-bootstrap-da-manifest-v2",
            &[&model_id, &input_id],
        ),
        availability_root: hash(
            b"qualified-bootstrap-da-attestation-v2",
            &[&model_id, &input_id],
        ),
        generation: 1,
        revision: 1,
        not_before: 0,
        expires: 1000,
        available_until: 1100,
        cost_class: 1,
    };
    current.demand_id = current.derived_demand_id();
    let mut manifest = QualifiedWorkTask {
        purpose: current.purpose,
        cost_class: 1,
        numeric_encoding: 1,
        hardness_status: 0,
        reuse: 1,
        network: cfg.network,
        parameters: cfg.parameters,
        work_profile: QualifiedWorkTask::profile_id(),
        source: current.source,
        demand_id: current.demand_id,
        source_record: current.bound_source_record().map_err(|_| "TASK_DEMAND")?,
        model: model_id,
        layer: QualifiedWorkTask::layer_id(model_id),
        input: input_id,
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: pon_work::task_id(&a, &b).map_err(|_| "TASK_MATERIAL")?,
        availability_manifest: current.availability_manifest,
        availability_root: current.availability_root,
        authorization_scope: current.authorization_scope,
        withdrawal_head: current.withdrawal_frontier().map_err(|_| "TASK_DEMAND")?,
        output_meter: [1; 32],
        rows: 64,
        inner: 64,
        columns: 64,
        demand_nonce: 1,
        not_before: 0,
        expires: 1000,
        available_until: 1100,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: 0,
    };
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: current.id().map_err(|_| "TASK_DEMAND")?,
        manifest,
        signature: [0; 64],
    };
    signed.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &source_key,
        &signed.signing_message().map_err(|_| "TASK_MANIFEST")?,
    ))
    .map_err(|_| "TASK_SOURCE")?
    .try_into()
    .map_err(|_| "TASK_SOURCE")?;
    let mut state = State::new();
    // Genesis has no transaction fee or account-nonce movement. Consensus commits
    // this explicit fixture; these private helpers are not an unauthenticated RPC.
    let mut fixture = Envelope {
        network: cfg.network,
        sender: current.requester,
        nonce: 0,
        expiry: 0,
        fee_limit: 0,
        tag: OPEN_TAG,
        payload: current.encode().map_err(|_| "TASK_DEMAND")?,
        signature: [0; 64],
    };
    open(&mut state, &fixture, 0, cfg)?;
    fixture.sender = current.source;
    fixture.tag = REGISTER_TAG;
    fixture.payload = signed.encode().map_err(|_| "TASK_MANIFEST")?;
    register(&mut state, &fixture, 0, cfg)?;
    Ok(BootstrapLifecycleTask {
        state,
        lease: current,
        signed,
    })
}

/// The executor's View implements this interface so exact reads and bounded prefix
/// scans participate in its canonical MVCC conflict validation and replay.
pub trait LifecycleState {
    fn get(&mut self, key: &str) -> Option<Value>;
    fn put(&mut self, key: String, value: Value);
    fn scan(&mut self, prefix: &str) -> State;
}
impl LifecycleState for State {
    fn get(&mut self, key: &str) -> Option<Value> {
        State::get(self, key).cloned()
    }
    fn put(&mut self, key: String, value: Value) {
        self.insert(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

fn ensure(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn number(record: &Value, key: &str) -> Result<u64> {
    record
        .get(key)
        .and_then(Value::as_u64)
        .ok_or("TASK_LIFECYCLE_STATE")
}
fn string<'a>(record: &'a Value, key: &str) -> Result<&'a str> {
    record
        .get(key)
        .and_then(Value::as_str)
        .ok_or("TASK_LIFECYCLE_STATE")
}
fn packed(record: &Value, key: &str, bytes: usize) -> Result<Vec<u8>> {
    let value = string(record, key)?;
    ensure(value.len() == bytes * 2, "TASK_LIFECYCLE_STATE")?;
    let decoded = hex::decode(value).map_err(|_| "TASK_LIFECYCLE_STATE")?;
    ensure(hex::encode(&decoded) == value, "TASK_LIFECYCLE_STATE")?;
    Ok(decoded)
}
pub fn slot_key(slot: u8) -> Result<String> {
    ensure(slot < DEMAND_SLOTS, "TASK_SLOT")?;
    Ok(format!("{SLOT_PREFIX}{slot:02}"))
}
fn lease(record: &Value) -> Result<DemandLeaseV2> {
    ensure(record["schema"] == RECORD_SCHEMA, "TASK_LIFECYCLE_STATE")?;
    DemandLeaseV2::decode(&packed(record, "lease", DEMAND_LEASE_BYTES)?)
        .map_err(|_| "TASK_LIFECYCLE_STATE")
}
fn slots(view: &mut impl LifecycleState) -> Result<State> {
    let rows = view.scan(SLOT_PREFIX);
    validate_slots(&rows)?;
    Ok(rows)
}
fn validate_slots(rows: &State) -> Result<()> {
    ensure(rows.len() <= usize::from(DEMAND_SLOTS), "TASK_SLOT_LIMIT")?;
    for (key, record) in rows {
        let current = lease(record)?;
        ensure(*key == slot_key(current.slot)?, "TASK_LIFECYCLE_STATE")?;
        ensure(
            serde_json::to_vec(record)
                .map_err(|_| "TASK_LIFECYCLE_STATE")?
                .len()
                <= MAX_RECORD_BYTES,
            "TASK_SLOT_LIMIT",
        )?;
    }
    Ok(())
}
fn store(view: &mut impl LifecycleState, key: String, record: Value) -> Result<()> {
    ensure(
        serde_json::to_vec(&record)
            .map_err(|_| "TASK_LIFECYCLE_STATE")?
            .len()
            <= MAX_RECORD_BYTES,
        "TASK_SLOT_LIMIT",
    )?;
    view.put(key, record);
    Ok(())
}
fn context(current: &DemandLeaseV2, cfg: &Config) -> Result<()> {
    ensure(
        current.network == cfg.network && current.parameters == cfg.parameters,
        "TASK_CONTEXT",
    )
}
fn open(view: &mut impl LifecycleState, tx: &Envelope, height: u64, cfg: &Config) -> Result<()> {
    let request = DemandLeaseV2::decode(&tx.payload).map_err(|_| "TASK_DEMAND_LEASE")?;
    context(&request, cfg)?;
    ensure(tx.sender == request.requester, "TASK_REQUESTER")?;
    ensure(request.revision == 1, "TASK_REVISION")?;
    ensure(
        request.not_before >= height && request.expires > height,
        "TASK_WINDOW",
    )?;
    let current_generation = view
        .get(GENERATION_KEY)
        .map(|value| value.as_u64().ok_or("TASK_LIFECYCLE_STATE"))
        .transpose()?
        .unwrap_or(0);
    ensure(
        request.generation == current_generation.checked_add(1).ok_or("TASK_GENERATION")?,
        "TASK_GENERATION",
    )?;
    let rows = slots(view)?;
    let key = slot_key(request.slot)?;
    if let Some(previous) = rows.get(&key) {
        ensure(lease(previous)?.available_until < height, "TASK_RETAINED")?;
    }
    let record = json!({
        "schema":RECORD_SCHEMA,"lease":hex::encode(&tx.payload),"status":"active",
        "opened_height":height,"source_sequence":0,"statement":null,
        "statement_id":null,"registered_height":null,"bound_model":null,
        "bound_input":null,"bound_task":null,"bound_meter":null,
        "output_count":0,"output_product":null,"output_height":null
    });
    store(view, key, record)?;
    view.put(GENERATION_KEY.to_owned(), json!(request.generation));
    Ok(())
}
fn renewed_record(
    original: &Value,
    successor: &DemandLeaseV2,
    requester: Hash,
    height: u64,
    cfg: &Config,
) -> Result<Value> {
    context(successor, cfg)?;
    let mut record = original.clone();
    let previous = lease(&record)?;
    ensure(record["status"] == "active", "TASK_REVOKED")?;
    ensure(
        requester == previous.requester && successor.requester == previous.requester,
        "TASK_REQUESTER",
    )?;
    ensure(
        successor.generation == previous.generation
            && successor.demand_id == previous.demand_id
            && successor.source == previous.source
            && successor.purpose == previous.purpose
            && successor.cost_class == previous.cost_class
            && successor.source_record == previous.source_record
            && successor.authorization_scope == previous.authorization_scope
            && successor.availability_manifest == previous.availability_manifest
            && successor.availability_root == previous.availability_root,
        "TASK_RENEW_BINDING",
    )?;
    ensure(
        successor.revision == previous.revision.checked_add(1).ok_or("TASK_REVISION")?,
        "TASK_REVISION",
    )?;
    ensure(
        height <= previous.expires
            && successor.not_before >= height
            && successor.not_before <= previous.expires
            && successor.expires > previous.expires,
        "TASK_WINDOW",
    )?;
    record["lease"] = json!(hex::encode(
        successor.encode().map_err(|_| "TASK_DEMAND_LEASE")?
    ));
    record["renewed_height"] = json!(height);
    Ok(record)
}
fn renew(view: &mut impl LifecycleState, tx: &Envelope, height: u64, cfg: &Config) -> Result<()> {
    let successor = DemandLeaseV2::decode(&tx.payload).map_err(|_| "TASK_DEMAND_LEASE")?;
    let key = slot_key(successor.slot)?;
    let original = view.get(&key).ok_or("TASK_DEMAND")?;
    // V2 preserves its historical two-command behavior; V3 refuses this route.
    let record = renewed_record(&original, &successor, tx.sender, height, cfg)?;
    store(view, key, record)
}

fn revoke(view: &mut impl LifecycleState, tx: &Envelope, height: u64, cfg: &Config) -> Result<()> {
    let request = DemandRevocationV2::decode(&tx.payload).map_err(|_| "TASK_REVOCATION")?;
    ensure(
        request.network == cfg.network && request.parameters == cfg.parameters,
        "TASK_CONTEXT",
    )?;
    let key = slot_key(request.slot)?;
    let mut record = view.get(&key).ok_or("TASK_DEMAND")?;
    let previous = lease(&record)?;
    ensure(
        tx.sender == previous.requester && request.requester == previous.requester,
        "TASK_REQUESTER",
    )?;
    ensure(request.demand_id == previous.demand_id, "TASK_DEMAND")?;
    ensure(
        request.expected_revision == previous.revision,
        "TASK_REVISION",
    )?;
    ensure(record["status"] == "active", "TASK_REVOKED")?;
    record["status"] = json!("revoked");
    record["revoked_height"] = json!(height);
    store(view, key, record)
}
fn registered_record(
    original: &Value,
    key: &str,
    rows: &State,
    raw: &[u8],
    source: Hash,
    height: u64,
    cfg: &Config,
) -> Result<Value> {
    let signed = SignedLifecycleTaskV2::decode(raw).map_err(|_| "TASK_MANIFEST")?;
    let mut record = original.clone();
    let current = lease(&record)?;
    context(&current, cfg)?;
    ensure(record["status"] == "active", "TASK_REVOKED")?;
    ensure(source == current.source, "TASK_SOURCE")?;
    let statement =
        verify_lifecycle_statement(raw, &current, height).map_err(|_| "TASK_STATEMENT")?;
    ensure(
        signed.manifest.demand_nonce
            == number(&record, "source_sequence")?
                .checked_add(1)
                .ok_or("TASK_SOURCE_NONCE")?,
        "TASK_SOURCE_NONCE",
    )?;
    let material_fields = [
        ("bound_model", signed.manifest.model),
        ("bound_input", signed.manifest.input),
        ("bound_task", signed.manifest.matrix_task),
        ("bound_meter", signed.manifest.output_meter),
    ];
    for (field, value) in material_fields {
        if !record[field].is_null() {
            ensure(record[field] == hex::encode(value), "TASK_RENEW_MATERIAL")?;
        }
    }
    for (other_key, other) in rows {
        let other_lease = lease(other)?;
        if other_key != key && other["status"] == "active" && height <= other_lease.expires {
            ensure(
                other["bound_task"] != hex::encode(signed.manifest.matrix_task),
                "TASK_MATRIX_IN_USE",
            )?;
        }
    }
    record["source_sequence"] = json!(signed.manifest.demand_nonce);
    record["statement"] = json!(hex::encode(raw));
    record["statement_id"] = json!(hex::encode(statement.manifest_id()));
    record["registered_height"] = json!(height);
    for (field, value) in material_fields {
        record[field] = json!(hex::encode(value));
    }
    Ok(record)
}

fn register(
    view: &mut impl LifecycleState,
    tx: &Envelope,
    height: u64,
    cfg: &Config,
) -> Result<()> {
    let signed = SignedLifecycleTaskV2::decode(&tx.payload).map_err(|_| "TASK_MANIFEST")?;
    let rows = slots(view)?;
    let (key, original) = rows
        .iter()
        .find(|(_, record)| {
            lease(record).is_ok_and(|current| current.demand_id == signed.manifest.demand_id)
        })
        .ok_or("TASK_DEMAND")?;
    let record = registered_record(original, key, &rows, &tx.payload, tx.sender, height, cfg)?;
    store(view, key.clone(), record)
}
fn atomic_renew(
    view: &mut impl LifecycleState,
    tx: &Envelope,
    height: u64,
    cfg: &Config,
) -> Result<()> {
    let request = AtomicRenewTaskV3::decode(&tx.payload).map_err(|_| "TASK_ATOMIC_RENEW")?;
    let rows = slots(view)?;
    let key = slot_key(request.lease.slot)?;
    let original = rows.get(&key).ok_or("TASK_DEMAND")?;
    let successor = renewed_record(original, &request.lease, tx.sender, height, cfg)?;
    let raw = request.signed.encode().map_err(|_| "TASK_MANIFEST")?;
    // The source is authenticated by its existing strict inner signature. No fake
    // nested ledger envelope is created; only requester ledger nonce/fee advances.
    let record = registered_record(
        &successor,
        &key,
        &rows,
        &raw,
        request.lease.source,
        height,
        cfg,
    )?;
    // No LifecycleState write has occurred until every successor/source check passes.
    store(view, key, record)
}

/// Called only after the existing executor verified the main envelope and performed
/// normal fee/balance/ledger-nonce checks. No wire-supplied qualification flag exists.
pub fn apply_verified_command(
    view: &mut impl LifecycleState,
    tx: &Envelope,
    height: u64,
    cfg: &Config,
) -> Result<()> {
    ensure(enabled(cfg), "WORK_TASK_PROFILE")?;
    ensure(tx.network == cfg.network, "NETWORK")?;
    match tx.tag {
        OPEN_TAG => open(view, tx, height, cfg),
        RENEW_TAG if cfg.task_profile() == PROFILE => renew(view, tx, height, cfg),
        ATOMIC_RENEW_TAG if cfg.task_profile() == ATOMIC_PROFILE => {
            atomic_renew(view, tx, height, cfg)
        }
        REVOKE_TAG => revoke(view, tx, height, cfg),
        REGISTER_TAG => register(view, tx, height, cfg),
        _ => Err("WORK_TASK_PROFILE"),
    }
}

#[derive(Debug, Clone)]
pub struct EligibleLifecycleTask {
    lease: DemandLeaseV2,
    manifest: QualifiedWorkTask,
    statement_id: Hash,
}
impl EligibleLifecycleTask {
    pub fn lease(&self) -> &DemandLeaseV2 {
        &self.lease
    }
    pub fn manifest(&self) -> &QualifiedWorkTask {
        &self.manifest
    }
    pub fn statement_id(&self) -> Hash {
        self.statement_id
    }
}
/// Parent snapshot only: a task cannot authorize its own registration block.
pub fn eligible_task(
    state: &State,
    task: Hash,
    height: u64,
    cfg: &Config,
) -> Result<EligibleLifecycleTask> {
    ensure(enabled(cfg), "WORK_TASK_PROFILE")?;
    let rows: State = state
        .range(SLOT_PREFIX.to_owned()..)
        .take_while(|(key, _)| key.starts_with(SLOT_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    validate_slots(&rows)?;
    let mut eligible = None;
    for record in rows.values() {
        let current = lease(record)?;
        if record["status"] != "active"
            || height < current.not_before
            || height > current.expires
            || record["bound_task"] != hex::encode(task)
        {
            continue;
        }
        context(&current, cfg)?;
        ensure(number(record, "registered_height")? < height, "TASK_PARENT")?;
        let bytes = packed(record, "statement", LIFECYCLE_TASK_BYTES)?;
        let statement =
            verify_lifecycle_statement(&bytes, &current, height).map_err(|_| "TASK_STATEMENT")?;
        ensure(
            record["statement_id"] == hex::encode(statement.manifest_id()),
            "TASK_MANIFEST",
        )?;
        ensure(
            number(record, "source_sequence")? == statement.manifest().demand_nonce,
            "TASK_SOURCE_NONCE",
        )?;
        for (field, value) in [
            ("bound_model", statement.manifest().model),
            ("bound_input", statement.manifest().input),
            ("bound_task", statement.manifest().matrix_task),
            ("bound_meter", statement.manifest().output_meter),
        ] {
            ensure(record[field] == hex::encode(value), "TASK_RENEW_MATERIAL")?;
        }
        ensure(eligible.is_none(), "TASK_MATRIX_IN_USE")?;
        eligible = Some(EligibleLifecycleTask {
            lease: current,
            manifest: statement.manifest().clone(),
            statement_id: statement.manifest_id(),
        });
    }
    eligible.ok_or("TASK")
}

/// Branch-relative arithmetic identity only; this does not issue an additional
/// reward or authorize a model/local effect. The node passes an actually verified
/// product. Revocation in this block suppresses output credit; renewal keeps it.
pub fn consume_output(
    state: &mut State,
    eligible: &EligibleLifecycleTask,
    product: Hash,
    height: u64,
) -> Result<bool> {
    let key = slot_key(eligible.lease.slot)?;
    let record = state.get_mut(&key).ok_or("TASK_DEMAND")?;
    let current = lease(record)?;
    ensure(
        current.demand_id == eligible.lease.demand_id
            && current.generation == eligible.lease.generation,
        "TASK_DEMAND",
    )?;
    if record["status"] != "active" || eligible.manifest.purpose == TaskPurpose::Maintenance {
        return Ok(false);
    }
    ensure(
        record["bound_meter"] == hex::encode(eligible.manifest.output_meter),
        "TASK_OUTPUT_METER",
    )?;
    ensure(
        record["bound_task"] == hex::encode(eligible.manifest.matrix_task),
        "TASK_OUTPUT_METER",
    )?;
    ensure(
        height >= eligible.lease.not_before && height <= eligible.lease.expires,
        "TASK_WINDOW",
    )?;
    match number(record, "output_count")? {
        0 => {
            record["output_count"] = json!(1);
            record["output_product"] = json!(hex::encode(product));
            record["output_height"] = json!(height);
            Ok(true)
        }
        1 => {
            ensure(
                record["output_product"] == hex::encode(product),
                "TASK_OUTPUT_CONFLICT",
            )?;
            Ok(false)
        }
        _ => Err("TASK_LIFECYCLE_STATE"),
    }
}
