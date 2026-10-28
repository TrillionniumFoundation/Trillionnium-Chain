//! NPQ5 task permission owner. Every requester/source key comes from the actual
//! M06 View; codecs and caller-selected source IDs never confer permission.
//! Five bounded witness leaves retain both real signatures without enlarging the
//! original 4096-byte State-value grammar. Legacy task records are not imported.
use super::{
    authorize, canonical, context, require, tasks_v5_enabled, Config, Hash, PreparedCommand,
    Result, State, View,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use trnm_crypto_primitives::qualified_work_task::{
    pq_lifecycle_v5::{self as crypto, ResolvedTaskAuthority, TaskAuthorityContext},
    DevelopmentTaskAdmission, TaskMaterial,
};
pub use trnm_protocol::qualified_work_task::pq_lifecycle_v5::PROFILE;
use trnm_protocol::{
    pq_native_accounts_v2::{AccountProfile, UnverifiedEnvelope},
    qualified_work_task::{
        pq_lifecycle_v5::{
            AtomicRenewTaskV5, DemandLeaseV5, DemandRenewalV5, DemandRevocationV5,
            TaskRegistrationV5, DEMAND_LEASE_BYTES, DEMAND_SLOTS,
        },
        QualifiedWorkTask, TaskPurpose,
    },
};

pub const SLOT_PREFIX: &str = "qualified-demand-slot-pq-v5:";
pub const WITNESS_PREFIX: &str = "qualified-task-witness-pq-v5:";
pub const GENERATION_KEY: &str = "qualified-demand-generation-pq-v5";
pub const REGISTRATION_WIRE_BYTES: usize = 7894;
pub const ATOMIC_RENEW_WIRE_BYTES: usize = 8274;
pub const WITNESS_CHUNKS: usize = 5;
pub const CHUNK_BYTES: usize = 2000;
const SCHEMA: &str = "qualified-demand-slot-record-pq-v5";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    lease: String,
    initial_lease: String,
    signed_lease: String,
    statement_kind: u8,
    opened_height: u64,
    renewed_height: u64,
    status: String,
    source_sequence: u64,
    registered_height: u64,
    admitted_at: u64,
    statement_id: String,
    bound_model: String,
    bound_input: String,
    bound_task: String,
    bound_meter: String,
    output_count: u64,
    output_product: String,
    output_height: u64,
    revoked_height: u64,
}
pub fn slot_key(slot: u8) -> Result<String> {
    require(slot < DEMAND_SLOTS, "PQ5_TASK_SLOT")?;
    Ok(format!("{SLOT_PREFIX}{slot:02}"))
}
fn witness_key(slot: u8, index: usize) -> Result<String> {
    require(
        slot < DEMAND_SLOTS && index < WITNESS_CHUNKS,
        "PQ5_TASK_SLOT",
    )?;
    Ok(format!("{WITNESS_PREFIX}{slot:02}:{index}"))
}
fn packed(text: &str, length: usize) -> Result<Vec<u8>> {
    require(text.len() == length * 2, "PQ5_TASK_STATE")?;
    let raw = hex::decode(text).map_err(|_| "PQ5_TASK_STATE")?;
    require(hex::encode(&raw) == text, "PQ5_TASK_STATE")?;
    Ok(raw)
}
fn hash_value(text: &str) -> Result<Hash> {
    packed(text, 32)?.try_into().map_err(|_| "PQ5_TASK_STATE")
}
fn decode_record(value: Value) -> Result<Record> {
    require(canonical(&value)?.len() <= 4096, "PQ5_TASK_STATE")?;
    let record: Record = serde_json::from_value(value).map_err(|_| "PQ5_TASK_STATE")?;
    require(record.schema == SCHEMA, "PQ5_TASK_STATE")?;
    Ok(record)
}
fn lease(record: &Record) -> Result<DemandLeaseV5> {
    DemandLeaseV5::decode(&packed(&record.lease, DEMAND_LEASE_BYTES)?).map_err(|_| "PQ5_TASK_STATE")
}
fn record(view: &mut View<'_>, slot: u8) -> Result<Record> {
    decode_record(view.get(&slot_key(slot)?).ok_or("PQ5_TASK_DEMAND")?)
}
fn records(view: &mut View<'_>) -> Result<Vec<Record>> {
    let rows = view.scan(SLOT_PREFIX);
    require(
        rows.len() <= usize::from(DEMAND_SLOTS),
        "PQ5_TASK_SLOT_LIMIT",
    )?;
    rows.into_iter()
        .map(|(key, value)| {
            let record = decode_record(value)?;
            require(key == slot_key(lease(&record)?.slot)?, "PQ5_TASK_STATE")?;
            Ok(record)
        })
        .collect()
}
fn find_demand(view: &mut View<'_>, demand: Hash) -> Result<Record> {
    let mut found = None;
    for record in records(view)? {
        if lease(&record)?.demand_id == demand {
            require(found.is_none(), "PQ5_TASK_STATE")?;
            found = Some(record);
        }
    }
    found.ok_or("PQ5_TASK_DEMAND")
}
fn check_context(lease: &DemandLeaseV5, cfg: &Config) -> Result<()> {
    require(tasks_v5_enabled(cfg), "PQ5_PROFILE_REQUIRED")?;
    require(
        lease.network == cfg.network && lease.parameters == cfg.parameters,
        "PQ5_TASK_CONTEXT",
    )
}
fn store(view: &mut View<'_>, slot: u8, record: Record) -> Result<()> {
    let value = serde_json::to_value(record).map_err(|_| "PQ5_TASK_STATE")?;
    require(canonical(&value)?.len() <= 4096, "PQ5_TASK_STATE")?;
    view.put(slot_key(slot)?, value);
    Ok(())
}
fn statement_length(kind: u8) -> Result<usize> {
    match kind {
        0 => Ok(0),
        21 => Ok(REGISTRATION_WIRE_BYTES),
        22 => Ok(ATOMIC_RENEW_WIRE_BYTES),
        _ => Err("PQ5_TASK_WITNESS"),
    }
}
fn raw_statement(view: &mut View<'_>, slot: u8, kind: u8) -> Result<Vec<u8>> {
    let length = statement_length(kind)?;
    let mut raw = Vec::with_capacity(length);
    for index in 0..WITNESS_CHUNKS {
        let value = view
            .get(&witness_key(slot, index)?)
            .ok_or("PQ5_TASK_WITNESS")?;
        let text = value.as_str().ok_or("PQ5_TASK_WITNESS")?;
        let expected = length.saturating_sub(index * CHUNK_BYTES).min(CHUNK_BYTES);
        raw.extend(packed(text, expected)?);
    }
    Ok(raw)
}
fn initial_lease(row: &Record) -> Result<DemandLeaseV5> {
    DemandLeaseV5::decode(&packed(&row.initial_lease, DEMAND_LEASE_BYTES)?)
        .map_err(|_| "PQ5_TASK_STATE")
}
fn signed_lease(row: &Record) -> Result<DemandLeaseV5> {
    DemandLeaseV5::decode(&packed(&row.signed_lease, DEMAND_LEASE_BYTES)?)
        .map_err(|_| "PQ5_TASK_STATE")
}
fn pending_or_active(row: &Record) -> bool {
    matches!(row.status.as_str(), "active" | "awaiting-source")
}
fn renewal_parent(
    view: &mut View<'_>,
    expected: Hash,
    prior: Hash,
    successor: &DemandLeaseV5,
) -> Result<(Record, DemandLeaseV5)> {
    let row = record(view, successor.slot)?;
    let current = lease(&row)?;
    require(
        pending_or_active(&row)
            && expected == current.id().map_err(|_| "PQ5_TASK_STATE")?
            && prior == hash_value(&row.statement_id)?
            && successor.same_scope(&current)
            && current.revision.checked_add(1) == Some(successor.revision),
        "PQ5_TASK_RENEWAL",
    )?;
    Ok((row, current))
}
/// Every leaf is encoded and size checked before the first staged write. The
/// enclosing M06 patch publishes all leaves, fees and nonce together or none.
fn store_statement(view: &mut View<'_>, slot: u8, row: Record, raw: &[u8]) -> Result<()> {
    require(
        raw.len() == statement_length(row.statement_kind)?,
        "PQ5_TASK_WITNESS",
    )?;
    let value = serde_json::to_value(&row).map_err(|_| "PQ5_TASK_STATE")?;
    require(canonical(&value)?.len() <= 4096, "PQ5_TASK_STATE")?;
    let key = slot_key(slot)?;
    let mut leaves = Vec::with_capacity(WITNESS_CHUNKS);
    for index in 0..WITNESS_CHUNKS {
        let start = (index * CHUNK_BYTES).min(raw.len());
        let end = ((index + 1) * CHUNK_BYTES).min(raw.len());
        let chunk = json!(hex::encode(&raw[start..end]));
        require(canonical(&chunk)?.len() <= 4096, "PQ5_TASK_WITNESS")?;
        leaves.push((witness_key(slot, index)?, chunk));
    }
    for (key, chunk) in leaves {
        view.put(key, chunk);
    }
    view.put(key, value);
    Ok(())
}

/// Both authority subjects are resolved from the selected parent's lease. Only
/// OPEN names a new source, and that account must already have actual authority.
pub(super) fn command_owners(
    view: &mut View<'_>,
    tx: &UnverifiedEnvelope<'_>,
    cfg: &Config,
) -> Result<(Hash, Hash, Hash)> {
    let current = match tx.kind {
        18 => DemandLeaseV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?,
        19 => {
            let request = DemandRenewalV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            renewal_parent(
                view,
                request.expected_lease_id,
                request.prior_statement_id,
                &request.successor,
            )?
            .1
        }
        20 => {
            let request =
                DemandRevocationV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            let row = record(view, request.lease.slot)?;
            let current = lease(&row)?;
            require(
                pending_or_active(&row) && request.lease == current,
                "PQ5_TASK_REVOCATION",
            )?;
            current
        }
        22 => {
            let request = AtomicRenewTaskV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            renewal_parent(
                view,
                request.expected_lease_id,
                request.registration.prior_statement_id,
                &request.successor,
            )?
            .1
        }
        21 => {
            let request =
                TaskRegistrationV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            let row = find_demand(view, request.manifest.demand_id)?;
            let current = lease(&row)?;
            require(
                pending_or_active(&row)
                    && request.lease_id == current.id().map_err(|_| "PQ5_TASK_STATE")?
                    && request.manifest.source == current.source,
                "PQ5_TASK_LEASE_BINDING",
            )?;
            current
        }
        _ => return Err("PQ5_TASK_COMMAND"),
    };
    check_context(&current, cfg)?;
    require(tx.common.account == current.requester, "PQ5_TASK_REQUESTER")?;
    authorize(view, current.requester)?;
    authorize(view, current.source)?;
    Ok((current.demand_id, current.requester, current.source))
}

/// Private owner entry. The enclosing M06 path verified both required proofs
/// and re-resolved all State authorities before entering this transition.
pub(super) fn apply(
    view: &mut View<'_>,
    prepared: &PreparedCommand,
    height: u64,
    cfg: &Config,
) -> Result<()> {
    require(tasks_v5_enabled(cfg), "PQ5_PROFILE_REQUIRED")?;
    let tx = super::decode_for_config(&prepared.raw, cfg)?;
    command_owners(view, &tx, cfg)?;
    match prepared.kind {
        18 => {
            let current = DemandLeaseV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            require(
                current.revision == 1 && current.not_before >= height && current.expires > height,
                "PQ5_TASK_WINDOW",
            )?;
            let generation = view
                .get(GENERATION_KEY)
                .and_then(|v| v.as_u64())
                .ok_or("PQ5_TASK_STATE")?;
            require(
                generation.checked_add(1) == Some(current.generation),
                "PQ5_TASK_GENERATION",
            )?;
            if let Some(old) = view.get(&slot_key(current.slot)?) {
                require(
                    lease(&decode_record(old)?)?.available_until < height,
                    "PQ5_TASK_SLOT_BUSY",
                )?;
            }
            let zero = hex::encode([0; 32]);
            store(
                view,
                current.slot,
                Record {
                    schema: SCHEMA.into(),
                    lease: hex::encode(current.encode().map_err(|_| "PQ5_TASK_ENCODING")?),
                    initial_lease: hex::encode(current.encode().map_err(|_| "PQ5_TASK_ENCODING")?),
                    signed_lease: String::new(),
                    statement_kind: 0,
                    opened_height: height,
                    renewed_height: 0,
                    status: "active".into(),
                    source_sequence: 0,
                    registered_height: 0,
                    admitted_at: 0,
                    statement_id: zero.clone(),
                    bound_model: zero.clone(),
                    bound_input: zero.clone(),
                    bound_task: zero.clone(),
                    bound_meter: zero.clone(),
                    output_count: 0,
                    output_product: zero,
                    output_height: 0,
                    revoked_height: 0,
                },
            )?;
            for index in 0..WITNESS_CHUNKS {
                view.put(witness_key(current.slot, index)?, json!(""));
            }
            view.put(GENERATION_KEY.into(), json!(current.generation));
        }
        19 => {
            let request = DemandRenewalV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            let (mut row, previous) = renewal_parent(
                view,
                request.expected_lease_id,
                request.prior_statement_id,
                &request.successor,
            )?;
            request
                .successor
                .validate_successor(&previous, height)
                .map_err(|_| "PQ5_TASK_RENEWAL_WINDOW")?;
            row.lease = hex::encode(
                request
                    .successor
                    .encode()
                    .map_err(|_| "PQ5_TASK_ENCODING")?,
            );
            row.status = "awaiting-source".into();
            row.renewed_height = height;
            store(view, request.successor.slot, row)?;
        }
        20 => {
            let request =
                DemandRevocationV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
            let mut row = record(view, request.lease.slot)?;
            row.status = "revoked".into();
            row.revoked_height = height;
            store(view, request.lease.slot, row)?;
        }
        21 | 22 => {
            require(
                prepared.keys.len() == 2 && prepared.raw.len() == statement_length(prepared.kind)?,
                "PQ5_TASK_SIGNATURES",
            )?;
            let (request, mut row, current) = if prepared.kind == 22 {
                let atomic =
                    AtomicRenewTaskV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
                let (mut row, previous) = renewal_parent(
                    view,
                    atomic.expected_lease_id,
                    atomic.registration.prior_statement_id,
                    &atomic.successor,
                )?;
                atomic
                    .successor
                    .validate_successor(&previous, height)
                    .map_err(|_| "PQ5_TASK_RENEWAL_WINDOW")?;
                row.lease =
                    hex::encode(atomic.successor.encode().map_err(|_| "PQ5_TASK_ENCODING")?);
                row.renewed_height = height;
                (atomic.registration, row, atomic.successor)
            } else {
                let request =
                    TaskRegistrationV5::decode(tx.payload).map_err(|_| "PQ5_TASK_ENCODING")?;
                let row = find_demand(view, request.manifest.demand_id)?;
                let current = lease(&row)?;
                (request, row, current)
            };
            crypto::check_registration_binding(&request, &current, height)
                .map_err(|_| "PQ5_TASK_BINDING")?;
            require(
                request.prior_statement_id == hash_value(&row.statement_id)?
                    && row.source_sequence.checked_add(1) == Some(request.manifest.demand_nonce),
                "PQ5_TASK_SOURCE_NONCE",
            )?;
            require(
                request.manifest.matrix_task != crate::continuity_v1::maintenance_task()?,
                "PQ5_TASK_RESERVED_MAINTENANCE",
            )?;
            for other in records(view)? {
                let other_lease = lease(&other)?;
                require(
                    other_lease.demand_id == current.demand_id
                        || !pending_or_active(&other)
                        || other_lease.expires < height
                        || other.bound_task != hex::encode(request.manifest.matrix_task),
                    "PQ5_TASK_MATRIX_IN_USE",
                )?;
            }
            let bindings = [
                &mut row.bound_model,
                &mut row.bound_input,
                &mut row.bound_task,
                &mut row.bound_meter,
            ];
            for (stored, value) in bindings.into_iter().zip([
                request.manifest.model,
                request.manifest.input,
                request.manifest.matrix_task,
                request.manifest.output_meter,
            ]) {
                require(
                    row.source_sequence == 0 || *stored == hex::encode(value),
                    "PQ5_TASK_MATERIAL_CHANGED",
                )?;
                *stored = hex::encode(value);
            }
            row.status = "active".into();
            row.signed_lease = hex::encode(current.encode().map_err(|_| "PQ5_TASK_ENCODING")?);
            row.statement_kind = prepared.kind;
            row.source_sequence = request.manifest.demand_nonce;
            row.registered_height = height;
            row.admitted_at = prepared.admitted_at;
            row.statement_id =
                hex::encode(crypto::statement_id(&prepared.raw).map_err(|_| "PQ5_TASK_STATEMENT")?);
            store_statement(view, current.slot, row, &prepared.raw)?;
        }
        _ => return Err("PQ5_TASK_COMMAND"),
    }
    Ok(())
}

pub fn validate_state(state: &State, cfg: &Config) -> Result<()> {
    require(tasks_v5_enabled(cfg), "PQ5_PROFILE_REQUIRED")?;
    require(
        !state.keys().any(|k| {
            k.starts_with("qualified-demand-slot-v2:")
                || k == "qualified-demand-generation-v2"
                || k.starts_with("qualified-demand-slot-pq-v4:")
                || k.starts_with("qualified-task-witness-pq-v4:")
                || k == "qualified-demand-generation-pq-v4"
                || k.starts_with("work:")
                || k.starts_with("work-demand")
                || k.starts_with("work-source:")
                || k.starts_with("work-withdrawal:")
        }),
        "PQ5_LEGACY_TASK_STATE",
    )?;
    let mut view = View::new(state, None);
    let all = records(&mut view)?;
    let generation = state
        .get(GENERATION_KEY)
        .and_then(Value::as_u64)
        .ok_or("PQ5_TASK_STATE")?;
    let mut max_generation = 0;
    let mut demands = BTreeSet::new();
    let mut generations = BTreeSet::new();
    let mut witness_keys = BTreeSet::new();
    for row in all {
        let current = lease(&row)?;
        check_context(&current, cfg)?;
        let initial = initial_lease(&row)?;
        require(
            initial.revision == 1
                && current.same_scope(&initial)
                && current.revision >= initial.revision
                && row.opened_height > 0
                && initial.not_before >= row.opened_height
                && current.not_before >= initial.not_before
                && current.expires >= initial.expires
                && ((current.revision == 1 && row.renewed_height == 0 && current == initial)
                    || (current.revision > 1
                        && row.renewed_height >= row.opened_height
                        && row.renewed_height >= current.not_before
                        && row.renewed_height < current.expires))
                && demands.insert(current.demand_id)
                && generations.insert(current.generation),
            "PQ5_TASK_STATE",
        )?;
        max_generation = max_generation.max(current.generation);
        require(
            (pending_or_active(&row)
                && row.revoked_height == 0
                && (row.status != "awaiting-source" || current.revision > 1))
                || (row.status == "revoked"
                    && row.revoked_height > 0
                    && row.revoked_height >= row.registered_height
                    && row.revoked_height >= row.opened_height
                    && row.revoked_height >= row.renewed_height),
            "PQ5_TASK_STATE",
        )?;
        for index in 0..WITNESS_CHUNKS {
            witness_keys.insert(witness_key(current.slot, index)?);
        }
        let raw = raw_statement(&mut view, current.slot, row.statement_kind)?;
        let bindings = [
            hash_value(&row.bound_model)?,
            hash_value(&row.bound_input)?,
            hash_value(&row.bound_task)?,
            hash_value(&row.bound_meter)?,
        ];
        let statement = hash_value(&row.statement_id)?;
        let product = hash_value(&row.output_product)?;
        if row.source_sequence == 0 {
            require(
                row.statement_kind == 0
                    && row.signed_lease.is_empty()
                    && row.registered_height == 0
                    && row.admitted_at == 0
                    && statement == [0; 32]
                    && bindings == [[0; 32]; 4]
                    && row.output_count == 0,
                "PQ5_TASK_STATE",
            )?;
        } else {
            let signed = signed_lease(&row)?;
            require(
                signed.same_scope(&current)
                    && signed.revision <= current.revision
                    && signed.not_before >= initial.not_before
                    && signed.expires <= current.expires
                    && (row.status != "active" || signed == current)
                    && (row.status != "awaiting-source" || signed.revision < current.revision),
                "PQ5_TASK_SIGNED_LEASE",
            )?;
            let tx = UnverifiedEnvelope::decode_for_profile(&raw, AccountProfile::TasksV5)
                .map_err(|_| "PQ5_TASK_WITNESS")?;
            require(
                matches!(tx.kind, 21 | 22)
                    && tx.kind == row.statement_kind
                    && tx.common.context == context(cfg)?
                    && tx.common.account == current.requester
                    && row.registered_height > 0
                    && row.admitted_at > 0
                    && row.admitted_at <= tx.common.expires_at,
                "PQ5_TASK_STATE",
            )?;
            let request = if tx.kind == 22 {
                let atomic =
                    AtomicRenewTaskV5::decode(tx.payload).map_err(|_| "PQ5_TASK_WITNESS")?;
                require(atomic.successor == signed, "PQ5_TASK_SIGNED_LEASE")?;
                atomic.registration
            } else {
                TaskRegistrationV5::decode(tx.payload).map_err(|_| "PQ5_TASK_WITNESS")?
            };
            crypto::check_registration_binding(&request, &signed, row.registered_height)
                .map_err(|_| "PQ5_TASK_BINDING")?;
            require(
                request.manifest.demand_nonce == row.source_sequence
                    && (request.prior_statement_id == [0; 32]) == (row.source_sequence == 1)
                    && request.prior_statement_id != statement
                    && statement == crypto::statement_id(&raw).map_err(|_| "PQ5_TASK_STATEMENT")?
                    && bindings
                        == [
                            request.manifest.model,
                            request.manifest.input,
                            request.manifest.matrix_task,
                            request.manifest.output_meter,
                        ],
                "PQ5_TASK_STATE",
            )?;
        }
        require(
            (row.output_count == 0 && row.output_height == 0 && product == [0; 32])
                || (row.output_count == 1
                    && row.output_height > 0
                    && row.output_height <= current.expires
                    && row.output_height >= initial.not_before
                    && product != [0; 32]
                    && current.purpose != TaskPurpose::Maintenance
                    && row.source_sequence > 0),
            "PQ5_TASK_OUTPUT",
        )?;
    }
    require(
        generation == max_generation
            && state
                .keys()
                .filter(|k| k.starts_with(WITNESS_PREFIX))
                .cloned()
                .collect::<BTreeSet<_>>()
                == witness_keys,
        "PQ5_TASK_WITNESS_COVERAGE",
    )
}

/// Private fields retain the freshly checked parent and both independent roles.
/// This is not permission for a later State or a local side effect.
pub struct EligibleTaskV5 {
    lease: DemandLeaseV5,
    manifest: QualifiedWorkTask,
    statement_id: Hash,
    requester_authority: [u8; 48],
    source_authority: [u8; 48],
}
impl EligibleTaskV5 {
    pub fn lease(&self) -> &DemandLeaseV5 {
        &self.lease
    }
    pub fn manifest(&self) -> &QualifiedWorkTask {
        &self.manifest
    }
    pub fn statement_id(&self) -> Hash {
        self.statement_id
    }
}
pub fn eligible_task(
    state: &State,
    task: Hash,
    height: u64,
    cfg: &Config,
) -> Result<EligibleTaskV5> {
    super::validate_state(state, cfg)?;
    require(tasks_v5_enabled(cfg), "PQ5_PROFILE_REQUIRED")?;
    let mut view = View::new(state, None);
    let mut found = None;
    for row in records(&mut view)? {
        let current = lease(&row)?;
        if row.status != "active"
            || row.bound_task != hex::encode(task)
            || height < current.not_before
            || height > current.expires
        {
            continue;
        }
        require(
            row.source_sequence > 0 && row.registered_height < height,
            "PQ5_TASK_PARENT",
        )?;
        let requester = authorize(&mut view, current.requester)?;
        let source = authorize(&mut view, current.source)?;
        let raw = raw_statement(&mut view, current.slot, row.statement_kind)?;
        let statement = crypto::verify_statement(
            &raw,
            &current,
            &TaskAuthorityContext {
                chain: context(cfg)?,
                requester: ResolvedTaskAuthority {
                    account: current.requester,
                    key_id: requester.key_id,
                    generation: requester.generation,
                    spki: &requester.spki,
                },
                source: ResolvedTaskAuthority {
                    account: current.source,
                    key_id: source.key_id,
                    generation: source.generation,
                    spki: &source.spki,
                },
                admitted_at: row.admitted_at,
                height,
            },
        )
        .map_err(|_| "PQ5_TASK_SIGNATURE")?;
        require(
            statement.manifest_id() == hash_value(&row.statement_id)?
                && statement.manifest().demand_nonce == row.source_sequence
                && found.is_none(),
            "PQ5_TASK_STATEMENT",
        )?;
        found = Some(EligibleTaskV5 {
            lease: current,
            manifest: statement.manifest().clone(),
            statement_id: statement.manifest_id(),
            requester_authority: requester.digest,
            source_authority: source.digest,
        });
    }
    found.ok_or("PQ5_TASK")
}
pub fn admit_material(
    state: &State,
    task: Hash,
    height: u64,
    cfg: &Config,
    material: TaskMaterial<'_>,
) -> Result<(EligibleTaskV5, DevelopmentTaskAdmission)> {
    let eligible = eligible_task(state, task, height, cfg)?;
    let mut view = View::new(state, None);
    let current = eligible.lease();
    let row = record(&mut view, current.slot)?;
    let requester = authorize(&mut view, current.requester)?;
    let source = authorize(&mut view, current.source)?;
    let admission = crypto::verify_admission(
        &raw_statement(&mut view, current.slot, row.statement_kind)?,
        current,
        &TaskAuthorityContext {
            chain: context(cfg)?,
            requester: ResolvedTaskAuthority {
                account: current.requester,
                key_id: requester.key_id,
                generation: requester.generation,
                spki: &requester.spki,
            },
            source: ResolvedTaskAuthority {
                account: current.source,
                key_id: source.key_id,
                generation: source.generation,
                spki: &source.spki,
            },
            admitted_at: row.admitted_at,
            height,
        },
        material,
    )
    .map_err(|_| "PQ5_TASK_MATERIAL")?;
    Ok((eligible, admission))
}

/// Ordinary Node passes the independently verified W1 product. Lease revocation
/// or a valid authority rotation in the successor suppresses output credit.
/// A renewal may retain credit for this already verified parent task, including
/// an awaiting-source successor; it does not grant future task eligibility.
/// Malformed or absent authority State remains an error. No rewards are minted.
pub fn consume_output(
    state: &mut State,
    eligible: &EligibleTaskV5,
    product: Hash,
    height: u64,
    cfg: &Config,
) -> Result<bool> {
    let mut view = View::new(state, None);
    let mut row = record(&mut view, eligible.lease.slot)?;
    let current = lease(&row)?;
    require(
        current.same_scope(&eligible.lease)
            && current.revision >= eligible.lease.revision
            && product != [0; 32],
        "PQ5_TASK_LEASE_BINDING",
    )?;
    if !pending_or_active(&row)
        || current.purpose == TaskPurpose::Maintenance
        || authorize(&mut view, current.requester)?.digest != eligible.requester_authority
        || authorize(&mut view, current.source)?.digest != eligible.source_authority
    {
        return Ok(false);
    }
    require(
        height >= eligible.lease.not_before
            && height <= eligible.lease.expires
            && row.bound_task == hex::encode(eligible.manifest.matrix_task)
            && row.bound_meter == hex::encode(eligible.manifest.output_meter),
        "PQ5_TASK_OUTPUT",
    )?;
    if row.output_count == 1 {
        require(
            row.output_product == hex::encode(product),
            "PQ5_TASK_OUTPUT_CONFLICT",
        )?;
        return Ok(false);
    }
    require(row.output_count == 0, "PQ5_TASK_OUTPUT")?;
    row.output_count = 1;
    row.output_product = hex::encode(product);
    row.output_height = height;
    store(&mut view, current.slot, row)?;
    let writes = view.writes;
    let mut next = state.clone();
    next.extend(writes);
    validate_state(&next, cfg)?;
    *state = next;
    Ok(true)
}
