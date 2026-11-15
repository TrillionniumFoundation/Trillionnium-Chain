//! New local mode3. A TaskView is never an exact-packet Work capability.
//! Complete expected bodies and latest are fixed by the protected outside owner.
//! No consensus/Wire authority, economic balances, density, hardness or fairness.
pub use super::operator_task_policy::PolicyError;
use super::operator_task_policy::{self as base, Allocation, Context, Limits, MaterialInput, Task};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use trnm_crypto_primitives::verify_hex_strict;
type Result<T> = std::result::Result<T, PolicyError>;
pub const MODE: &str = "restricted-owner-node-v3";
const TASK_DOMAIN: &[u8] = b"TRNM-RESTRICTED-MINING-TASKVIEW1";
const OP_DOMAIN: &[u8] = b"TRNM-RESTRICTED-MINING-OP1";
const MAX_BYTES: usize = 64 << 10;
const MAX_CLAIMS: usize = 256;
fn check(ok: bool, e: PolicyError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(e)
    }
}
fn hex_id(v: &str, n: usize) -> Result<()> {
    check(
        v.len() == n * 2
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        PolicyError::Input,
    )
}
fn put_text(out: &mut Vec<u8>, v: &str) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v.as_bytes());
}
fn sha(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
fn io<T>(v: std::io::Result<T>) -> Result<T> {
    v.map_err(|_| PolicyError::Journal)
}
fn allocation_valid(a: &Allocation) -> Result<()> {
    check(
        a.cpu_ns > 0
            && a.material_bytes > 0
            && a.material_bytes <= 512 << 20
            && a.da_bytes >= a.material_bytes
            && a.da_bytes <= 512 << 20
            && a.funding_units > 0,
        PolicyError::Budget,
    )
}
fn within(a: &Allocation, b: &Allocation) -> bool {
    a.cpu_ns <= b.cpu_ns
        && a.material_bytes <= b.material_bytes
        && a.da_bytes <= b.da_bytes
        && a.funding_units <= b.funding_units
        && a.reuse_uses <= b.reuse_uses
}
fn add(a: &Allocation, b: &Allocation) -> Result<Allocation> {
    Ok(Allocation {
        cpu_ns: a.cpu_ns.checked_add(b.cpu_ns).ok_or(PolicyError::Budget)?,
        material_bytes: a
            .material_bytes
            .checked_add(b.material_bytes)
            .ok_or(PolicyError::Budget)?,
        da_bytes: a
            .da_bytes
            .checked_add(b.da_bytes)
            .ok_or(PolicyError::Budget)?,
        funding_units: a
            .funding_units
            .checked_add(b.funding_units)
            .ok_or(PolicyError::Budget)?,
        reuse_uses: a
            .reuse_uses
            .checked_add(b.reuse_uses)
            .ok_or(PolicyError::Budget)?,
    })
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    StartupCatalog,
    Search,
    WinnerValidation,
    Activate,
    ParentReconcile,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SearchIntent {
    pub miner: String,
    pub timestamp: u64,
    pub exact_transactions_sha256: String,
    pub exact_group_ids: Vec<String>,
    pub nonce_first: u64,
    pub nonce_count: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationGrant {
    pub purpose: Purpose,
    pub operation_nonce: String,
    pub operation_id: String,
    pub expected_generation: u64,
    pub payload_sha256: String,
    pub search: Option<SearchIntent>,
    pub related_search_operation: Option<String>,
    pub allocation: Allocation,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskView {
    pub schema: String,
    pub context: Context,
    pub registry_sequence: u64,
    pub registry_digest: String,
    pub registry_previous_digest: Option<String>,
    pub declaration_digest: String,
    pub task: Task,
    pub instance_class: String,
    pub source_class: String,
    pub cost_class: String,
    pub cost_evidence: Option<String>,
    pub preprocessing: String,
    pub prepared_artifact: Option<String>,
    pub setup_record: Option<String>,
    pub funding_commitment: String,
    pub funding_evidence: String,
    pub declared_funding_units: u64,
    pub limits: Limits,
    pub retention_until_ns: u64,
    pub not_before_ns: u64,
    pub expires_ns: u64,
    pub revoked: bool,
    pub allowed_task_commands: Vec<String>,
    pub permissions: Vec<OperationGrant>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ViewEnvelope {
    body: TaskView,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthority {
    pub registry_key: String,
    pub task_key: String,
    pub latest_sequence: u64,
    pub latest_digest: String,
    pub expected_envelope_sha256: String,
    pub expected: TaskView,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub raw_view: Vec<u8>,
    pub authority: ExternalAuthority,
    pub journal_path: PathBuf,
    pub expected_uid: u32,
    pub materials: Vec<MaterialInput>,
}
pub(crate) struct VerifiedView {
    pub(crate) body: TaskView,
    envelope_sha256: String,
    pub(crate) registry_key: String,
    pub(crate) task_key: String,
}
fn signing_message(v: &TaskView, role: u8) -> Result<Vec<u8>> {
    // Struct serde field order is fixed by this new source/domain; never accept
    // old Registry2/Work/Pool domains as a fallback. The expected typed body is exact.
    let bytes = serde_json::to_vec(v).map_err(|_| PolicyError::Input)?;
    let mut out = TASK_DOMAIN.to_vec();
    out.push(role);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(out)
}
fn validate(v: &TaskView) -> Result<()> {
    check(v.schema == MODE, PolicyError::Input)?;
    for h in [
        &v.context.registry_id,
        &v.context.operator_id,
        &v.context.network,
        &v.context.parameters,
        &v.context.node_policy_source,
        &v.context.registry2_package,
        &v.context.actual_parent,
        &v.registry_digest,
        &v.declaration_digest,
        &v.funding_commitment,
        &v.funding_evidence,
    ] {
        hex_id(h, 32)?;
    }
    hex_id(&v.context.source_commit, 20)?;
    check(
        v.registry_sequence > 0
            && v.registry_sequence <= 256
            && (v.registry_sequence == 1) == v.registry_previous_digest.is_none(),
        PolicyError::Input,
    )?;
    if let Some(p) = &v.registry_previous_digest {
        hex_id(p, 32)?;
    }
    let t = &v.task;
    check(
        t.purpose == "maintenance-tag1"
            && t.dimension == 64
            && t.field_modulus == 4294967291
            && t.encoding == "canonical-u32-le",
        PolicyError::Unsupported,
    )?;
    check(
        !t.model_id.is_empty()
            && t.model_id.len() <= 128
            && !t.model_id.chars().any(char::is_control)
            && !t.layer_tensor.is_empty()
            && t.layer_tensor.len() <= 128
            && !t.layer_tensor.chars().any(char::is_control),
        PolicyError::Input,
    )?;
    hex_id(&t.model_revision, 20)?;
    for h in [
        &t.native_task,
        &t.lease_sha256,
        &t.model_material,
        &t.native_model,
        &t.layer_selector,
        &t.input_material,
        &t.native_input,
        &t.a_sha256,
        &t.b_sha256,
        &t.full_material_catalog,
        &t.recipe_sha256,
    ] {
        hex_id(h, 32)?;
    }
    check(
        matches!(v.instance_class.as_str(), "dense" | "structured" | "zero")
            && matches!(
                v.source_class.as_str(),
                "declared-same-operator"
                    | "declared-licensed-external"
                    | "declared-public-artifact"
            ),
        PolicyError::Input,
    )?;
    check(
        matches!(
            v.cost_class.as_str(),
            "unmeasured" | "reported-full-invocation" | "reported-preprocessed-reuse"
        ) && (v.cost_class == "unmeasured") == v.cost_evidence.is_none(),
        PolicyError::Input,
    )?;
    if let Some(e) = &v.cost_evidence {
        hex_id(e, 32)?;
    }
    allocation_valid(&v.limits.allocation)?;
    check(
        v.limits.operations > 0
            && v.limits.operations <= 256
            && v.declared_funding_units >= v.limits.allocation.funding_units,
        PolicyError::Budget,
    )?;
    match v.preprocessing.as_str() {
        "forbidden" => check(
            v.prepared_artifact.is_none()
                && v.setup_record.is_none()
                && v.limits.allocation.reuse_uses == 0,
            PolicyError::Input,
        )?,
        "exact-task-input-only" => {
            hex_id(
                v.prepared_artifact.as_deref().ok_or(PolicyError::Input)?,
                32,
            )?;
            hex_id(v.setup_record.as_deref().ok_or(PolicyError::Input)?, 32)?;
            check(v.limits.allocation.reuse_uses > 0, PolicyError::Input)?;
        }
        _ => return Err(PolicyError::Input),
    }
    check(
        v.not_before_ns > 0
            && v.expires_ns
                .checked_sub(v.not_before_ns)
                .is_some_and(|d| d > 0 && d <= 86400000000000)
            && v.retention_until_ns >= v.expires_ns,
        PolicyError::Window,
    )?;
    check(
        v.allowed_task_commands.len() <= 16
            && v.allowed_task_commands.windows(2).all(|p| p[0] < p[1])
            && v.permissions.len() <= 64,
        PolicyError::Input,
    )?;
    for h in &v.allowed_task_commands {
        hex_id(h, 32)?;
    }
    for (i, p) in v.permissions.iter().enumerate() {
        hex_id(&p.operation_nonce, 32)?;
        hex_id(&p.operation_id, 32)?;
        hex_id(&p.payload_sha256, 32)?;
        allocation_valid(&p.allocation)?;
        check(
            within(&p.allocation, &v.limits.allocation)
                && p.operation_id
                    == operation_id(
                        &v.context,
                        &p.purpose,
                        &p.operation_nonce,
                        &p.payload_sha256,
                    )?,
            PolicyError::ExternalContext,
        )?;
        check(
            !v.permissions[..i].iter().any(|q| {
                q.operation_id == p.operation_id
                    || (q.purpose == p.purpose && q.payload_sha256 == p.payload_sha256)
            }),
            PolicyError::Input,
        )?;
        if v.preprocessing == "forbidden" {
            check(p.allocation.reuse_uses == 0, PolicyError::Input)?;
        }
        match p.purpose {
            Purpose::Search => {
                let s = p.search.as_ref().ok_or(PolicyError::Input)?;
                hex_id(&s.miner, 32)?;
                hex_id(&s.exact_transactions_sha256, 32)?;
                check(
                    s.timestamp > 0
                        && s.nonce_first > 0
                        && (1..=4096).contains(&s.nonce_count)
                        && s.nonce_first.checked_add(s.nonce_count - 1).is_some()
                        && s.exact_group_ids.len() <= 256
                        && s.exact_group_ids.windows(2).all(|g| g[0] < g[1])
                        && p.related_search_operation.is_none(),
                    PolicyError::Input,
                )?;
                for h in &s.exact_group_ids {
                    hex_id(h, 32)?;
                }
                check(
                    p.payload_sha256 == search_payload_sha256(s)?,
                    PolicyError::NativeBinding,
                )?;
            }
            Purpose::WinnerValidation | Purpose::Activate => {
                check(p.search.is_none(), PolicyError::Input)?;
                hex_id(
                    p.related_search_operation
                        .as_deref()
                        .ok_or(PolicyError::Input)?,
                    32,
                )?;
            }
            Purpose::StartupCatalog => check(
                p.search.is_none()
                    && p.related_search_operation.is_none()
                    && p.payload_sha256 == v.task.full_material_catalog,
                PolicyError::Input,
            )?,
            Purpose::ParentReconcile => check(
                p.search.is_none()
                    && p.related_search_operation.is_none()
                    && p.payload_sha256 == v.context.actual_parent,
                PolicyError::Input,
            )?,
        }
    }
    Ok(())
}
fn task_binding_sha256(v: &TaskView) -> Result<String> {
    let mut bytes = b"TRNM-RESTRICTED-MINING-DECLARED-TASK1".to_vec();
    bytes.extend_from_slice(
        &serde_json::to_vec(&(
            &v.task,
            &v.instance_class,
            &v.source_class,
            &v.cost_class,
            &v.cost_evidence,
            &v.preprocessing,
            &v.prepared_artifact,
            &v.setup_record,
            &v.allowed_task_commands,
        ))
        .map_err(|_| PolicyError::Input)?,
    );
    Ok(sha(&bytes))
}
/// Bytes for the outside registry/task signer. This validates a new typed body
/// but neither signs it nor authenticates the signer, task or Native result.
pub fn task_view_signing_bytes(v: &TaskView, role: u8) -> Result<Vec<u8>> {
    check(matches!(role, 1 | 2), PolicyError::Input)?;
    validate(v)?;
    signing_message(v, role)
}
/// The historical field name is retained in this new schema: entries are the
/// SHA256 of complete signed ordinary transaction bytes, not command tag names.
/// Exact ordered-batch binding is independently mandatory in SearchIntent.
pub(crate) fn check_allowed_transactions(v: &TaskView, raws: &[Vec<u8>]) -> Result<()> {
    transactions_sha256(raws)?;
    check(
        raws.iter()
            .all(|raw| v.allowed_task_commands.binary_search(&sha(raw)).is_ok()),
        PolicyError::NativeBinding,
    )
}
pub fn operation_id(c: &Context, p: &Purpose, nonce: &str, payload: &str) -> Result<String> {
    hex_id(nonce, 32)?;
    hex_id(payload, 32)?;
    let mut bytes = OP_DOMAIN.to_vec();
    for s in [
        &c.registry_id,
        &c.operator_id,
        &c.network,
        &c.parameters,
        &c.actual_parent,
        nonce,
        payload,
    ] {
        hex_id(s, 32)?;
        bytes.extend_from_slice(&(s.len() as u32).to_le_bytes());
        bytes.extend_from_slice(s.as_bytes());
    }
    bytes.extend_from_slice(&serde_json::to_vec(p).map_err(|_| PolicyError::Input)?);
    Ok(sha(&bytes))
}
pub fn transactions_sha256(raws: &[Vec<u8>]) -> Result<String> {
    check(raws.len() <= 256, PolicyError::Capacity)?;
    let mut sum = 0usize;
    let mut h = Sha256::new();
    h.update(b"TRNM-RESTRICTED-MINING-ORDERED-TX1");
    h.update((raws.len() as u32).to_le_bytes());
    for raw in raws {
        sum = sum.checked_add(raw.len()).ok_or(PolicyError::Capacity)?;
        check(
            (159..=2048).contains(&raw.len()) && sum <= 524288,
            PolicyError::Capacity,
        )?;
        h.update((raw.len() as u32).to_le_bytes());
        h.update(raw);
    }
    Ok(hex::encode(h.finalize()))
}
pub fn search_payload_sha256(s: &SearchIntent) -> Result<String> {
    let mut b = b"TRNM-RESTRICTED-MINING-SEARCH1".to_vec();
    b.extend_from_slice(&serde_json::to_vec(s).map_err(|_| PolicyError::Input)?);
    Ok(sha(&b))
}
pub(crate) fn authenticate(raw: &[u8], e: &ExternalAuthority, now: u64) -> Result<VerifiedView> {
    check(
        !raw.is_empty() && raw.len() <= MAX_BYTES,
        PolicyError::Input,
    )?;
    for h in [
        &e.registry_key,
        &e.task_key,
        &e.latest_digest,
        &e.expected_envelope_sha256,
    ] {
        hex_id(h, 32)?;
    }
    check(e.registry_key != e.task_key, PolicyError::ExternalContext)?;
    let env: ViewEnvelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    validate(&env.body)?;
    validate(&e.expected)?;
    check(
        env.body == e.expected
            && env.body.registry_sequence == e.latest_sequence
            && env.body.registry_digest == e.latest_digest
            && sha(raw) == e.expected_envelope_sha256,
        PolicyError::ExternalContext,
    )?;
    check(
        env.body.not_before_ns <= now && now < env.body.expires_ns,
        PolicyError::Window,
    )?;
    verify_hex_strict(
        &e.registry_key,
        &signing_message(&env.body, 1)?,
        &env.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(
        &e.task_key,
        &signing_message(&env.body, 2)?,
        &env.task_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedView {
        body: env.body,
        envelope_sha256: sha(raw),
        registry_key: e.registry_key.clone(),
        task_key: e.task_key.clone(),
    })
}
/// The launch/refresh file is Root-owned, not a public request or candidate plan.
/// The three outside source pins are mandatory before Settings/material loading.
/// This check issues no Work, State, packet or Pool capability.
pub fn validate_protected_inputs(
    inputs: &Inputs,
    source_commit: &str,
    node_policy_source: &str,
    registry2_package: &str,
) -> Result<()> {
    hex_id(source_commit, 20)?;
    hex_id(node_policy_source, 32)?;
    hex_id(registry2_package, 32)?;
    let view = authenticate(&inputs.raw_view, &inputs.authority, base::now_ns()?)?;
    check(
        inputs.expected_uid == rustix::process::geteuid().as_raw()
            && inputs.journal_path.is_absolute()
            && view.body.context.source_commit == source_commit
            && view.body.context.node_policy_source == node_policy_source
            && view.body.context.registry2_package == registry2_package,
        PolicyError::ExternalContext,
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeFacts {
    pub(crate) context: Context,
    pub(crate) task: Task,
    pub(crate) generation: u64,
    pub(crate) purpose: Purpose,
    pub(crate) payload_sha256: String,
}
impl VerifiedView {
    pub(crate) fn check_window(&self, now: u64) -> Result<()> {
        check(!self.body.revoked, PolicyError::Revoked)?;
        check(
            self.body.not_before_ns <= now && now < self.body.expires_ns,
            PolicyError::Window,
        )
    }
    pub(crate) fn permission(&self, purpose: &Purpose, payload: &str) -> Result<&OperationGrant> {
        self.body
            .permissions
            .iter()
            .find(|p| &p.purpose == purpose && p.payload_sha256 == payload)
            .ok_or(PolicyError::ExternalContext)
    }
    pub(crate) fn check(&self, f: &NativeFacts, now: u64) -> Result<&OperationGrant> {
        self.check_window(now)?;
        check(
            f.context == self.body.context && f.task == self.body.task,
            PolicyError::NativeBinding,
        )?;
        let p = self.permission(&f.purpose, &f.payload_sha256)?;
        check(
            p.expected_generation == f.generation,
            PolicyError::NativeBinding,
        )?;
        Ok(p)
    }
    pub(crate) fn next_view_of(&self, old: &Self) -> bool {
        old.body.registry_sequence.checked_add(1) == Some(self.body.registry_sequence)
            && self.body.registry_previous_digest.as_deref()
                == Some(old.body.registry_digest.as_str())
    }
    pub(crate) fn marker(&self, journal: &Path) -> Result<Vec<u8>> {
        check(journal.is_absolute(), PolicyError::Input)?;
        serde_json::to_vec(&serde_json::json!({"schema":MODE,"registry":self.body.context.registry_id,"operator":self.body.context.operator_id,"network":self.body.context.network,"parameters":self.body.context.parameters,"journal":journal.to_str().ok_or(PolicyError::Input)?,"source":self.body.context.source_commit,"node_policy":self.body.context.node_policy_source,"registry2_package":self.body.context.registry2_package,"registry_key":self.registry_key,"task_key":self.task_key})).map_err(|_|PolicyError::Input)
    }
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    schema: String,
    registry: String,
    operator: String,
    network: String,
    parameters: String,
    source: String,
    node_policy: String,
    registry2_package: String,
    registry_key: String,
    task_key: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    sequence: u64,
    digest: String,
    previous: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    schema: String,
    operation: String,
    operation_nonce: String,
    parent: String,
    generation: u64,
    purpose: Purpose,
    payload: String,
    declaration: String,
    view: String,
    sequence: u64,
    registry_digest: String,
    native_task: String,
    instance_class: String,
    task_binding_sha256: String,
    allocation: Allocation,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchResult {
    schema: String,
    operation: String,
    parent: String,
    generation: u64,
    packet_sha256: Option<String>,
    trials: u64,
}
pub(crate) struct Journal {
    path: PathBuf,
    directory: File,
    lock: File,
    uid: u32,
    identity: Identity,
    anchors: Vec<Anchor>,
    claims: Vec<Claim>,
    results: Vec<SearchResult>,
    unavailable: bool,
}
pub(crate) struct Reservation {
    pub(crate) operation: String,
    view: String,
    sequence: u64,
    registry_digest: String,
    purpose: Purpose,
    payload: String,
}
/// Independent held-directory sink survives a Node open failure without
/// borrowing Node, RefCell or SQL. It records no claimed Native success.
pub(crate) struct JournalFaultSink {
    path: PathBuf,
    directory: File,
    uid: u32,
}
impl JournalFaultSink {
    pub(crate) fn persist(&self) -> Result<()> {
        let a = io(fs::symlink_metadata(&self.path))?;
        let held = io(self.directory.metadata())?;
        check(
            a.is_dir()
                && !a.file_type().is_symlink()
                && a.uid() == self.uid
                && a.mode() & 0o7777 == 0o700
                && a.dev() == held.dev()
                && a.ino() == held.ino(),
            PolicyError::Journal,
        )?;
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/unavailable.json",
            self.directory.as_raw_fd()
        ));
        let value = serde_json::json!({"schema":"restricted-mining-accounting-fault-v1","label":"CPU_ACCOUNTING_UNKNOWN"});
        if fs::symlink_metadata(&path).is_ok() {
            check(
                read::<serde_json::Value>(&path, self.uid)? == value,
                PolicyError::Journal,
            )?;
            io(self.directory.sync_all())
        } else {
            save(&path, &value, &self.directory)
        }
    }
}
/// If an operation exits without an explicit finish, CPU5 Drop latches unknown
/// in its service epoch. This independent guard also retains a durable local
/// fault marker, including panic/unwind and initialization failure paths.
pub(crate) struct UnfinishedOperationFault {
    sink: JournalFaultSink,
    unavailable: Arc<AtomicBool>,
    armed: bool,
}
impl UnfinishedOperationFault {
    pub(crate) fn persist_unknown(&self) -> Result<()> {
        self.unavailable.store(true, Ordering::Release);
        self.sink.persist()
    }
    pub(crate) fn finished(&mut self) {
        self.armed = false;
    }
}
impl Drop for UnfinishedOperationFault {
    fn drop(&mut self) {
        if self.armed && self.persist_unknown().is_err() {
            eprintln!("OWNER_MINING_UNFINISHED_FAULT_PERSISTENCE_FAILED");
        }
    }
}
fn same_meta(m: &fs::Metadata) -> HeldMaterialIdentity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn held(path: &Path, uid: u32) -> Result<File> {
    let a = io(fs::symlink_metadata(path))?;
    check(
        a.is_file() && a.nlink() == 1 && a.uid() == uid && a.mode() & 0o7777 == 0o600,
        PolicyError::Journal,
    )?;
    let f = io(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path))?;
    check(
        same_meta(&a) == same_meta(&io(f.metadata())?),
        PolicyError::Journal,
    )?;
    Ok(f)
}
fn read<T: serde::de::DeserializeOwned>(path: &Path, uid: u32) -> Result<T> {
    let mut f = held(path, uid)?;
    let a = io(f.metadata())?;
    check(
        a.len() > 0 && a.len() <= MAX_BYTES as u64,
        PolicyError::Journal,
    )?;
    let mut b = Vec::new();
    io((&mut f).take(MAX_BYTES as u64 + 1).read_to_end(&mut b))?;
    check(
        b.len() as u64 == a.len()
            && same_meta(&a) == same_meta(&io(f.metadata())?)
            && same_meta(&a) == same_meta(&io(fs::symlink_metadata(path))?),
        PolicyError::Journal,
    )?;
    serde_json::from_slice(&b).map_err(|_| PolicyError::Journal)
}
fn save<T: Serialize>(path: &Path, v: &T, dir: &File) -> Result<()> {
    let b = serde_json::to_vec(v).map_err(|_| PolicyError::Journal)?;
    check(!b.is_empty() && b.len() <= MAX_BYTES, PolicyError::Journal)?;
    let mut f = io(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path))?;
    io(f.write_all(&b))?;
    io(f.sync_all())?;
    io(dir.sync_all())
}
impl Journal {
    pub(crate) fn open(path: &Path, uid: u32, view: &VerifiedView) -> Result<Self> {
        check(
            cfg!(target_os = "linux") && path.is_absolute(),
            PolicyError::Unsupported,
        )?;
        let a = io(fs::symlink_metadata(path))?;
        check(
            a.is_dir()
                && !a.file_type().is_symlink()
                && a.uid() == uid
                && a.mode() & 0o7777 == 0o700,
            PolicyError::Journal,
        )?;
        let directory = io(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path))?;
        let m = io(directory.metadata())?;
        check(
            a.dev() == m.dev() && a.ino() == m.ino(),
            PolicyError::Journal,
        )?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let lp = pinned.join("owner.lock");
        let lock = if fs::symlink_metadata(&lp).is_err() {
            let f = io(OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lp))?;
            io(f.sync_all())?;
            io(directory.sync_all())?;
            f
        } else {
            held(&lp, uid)?
        };
        lock.try_lock_exclusive().map_err(|_| PolicyError::Busy)?;
        let c = &view.body.context;
        let identity = Identity {
            schema: "restricted-owner-node-journal-v3".into(),
            registry: c.registry_id.clone(),
            operator: c.operator_id.clone(),
            network: c.network.clone(),
            parameters: c.parameters.clone(),
            source: c.source_commit.clone(),
            node_policy: c.node_policy_source.clone(),
            registry2_package: c.registry2_package.clone(),
            registry_key: view.registry_key.clone(),
            task_key: view.task_key.clone(),
        };
        let ip = pinned.join("identity.json");
        if fs::symlink_metadata(&ip).is_err() {
            let names = io(fs::read_dir(&pinned))?
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| PolicyError::Journal)?;
            check(
                names.len() == 1 && names[0].file_name() == "owner.lock",
                PolicyError::Journal,
            )?;
            save(&ip, &identity, &directory)?;
        } else {
            check(
                read::<Identity>(&ip, uid)? == identity,
                PolicyError::Journal,
            )?;
        }
        let mut anchors = Vec::new();
        let mut claims: Vec<Claim> = Vec::new();
        let mut results: Vec<SearchResult> = Vec::new();
        let mut n = 0;
        for row in io(fs::read_dir(&pinned))? {
            n += 1;
            check(n <= MAX_CLAIMS * 3 + 2, PolicyError::Capacity)?;
            let row = io(row)?;
            let name = row
                .file_name()
                .into_string()
                .map_err(|_| PolicyError::Journal)?;
            if name == "owner.lock" || name == "identity.json" {
                continue;
            }
            if let Some(seq) = name
                .strip_prefix("view-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let a: Anchor = read(&pinned.join(&name), uid)?;
                check(
                    seq == format!("{:020}", a.sequence) && a.sequence > 0,
                    PolicyError::Journal,
                )?;
                hex_id(&a.digest, 32)?;
                if let Some(p) = &a.previous {
                    hex_id(p, 32)?;
                }
                anchors.push(a);
            } else if let Some(id) = name
                .strip_prefix("claim-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let c: Claim = read(&pinned.join(&name), uid)?;
                check(
                    c.schema == "restricted-mining-reservation-v1"
                        && id == c.operation
                        && c.sequence > 0,
                    PolicyError::Journal,
                )?;
                for h in [
                    &c.operation,
                    &c.operation_nonce,
                    &c.parent,
                    &c.payload,
                    &c.declaration,
                    &c.view,
                    &c.registry_digest,
                    &c.native_task,
                    &c.task_binding_sha256,
                ] {
                    hex_id(h, 32)?;
                }
                check(
                    matches!(c.instance_class.as_str(), "dense" | "structured" | "zero"),
                    PolicyError::Journal,
                )?;
                allocation_valid(&c.allocation)?;
                let ctx = Context {
                    registry_id: identity.registry.clone(),
                    operator_id: identity.operator.clone(),
                    network: identity.network.clone(),
                    parameters: identity.parameters.clone(),
                    source_commit: String::new(),
                    node_policy_source: String::new(),
                    registry2_package: String::new(),
                    actual_parent: c.parent.clone(),
                };
                check(
                    c.operation == operation_id(&ctx, &c.purpose, &c.operation_nonce, &c.payload)?,
                    PolicyError::Journal,
                )?;
                claims.push(c);
            } else if let Some(id) = name
                .strip_prefix("result-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let r: SearchResult = read(&pinned.join(&name), uid)?;
                check(
                    r.schema == "restricted-mining-search-result-v1"
                        && id == r.operation
                        && r.trials <= 4096,
                    PolicyError::Journal,
                )?;
                hex_id(&r.operation, 32)?;
                hex_id(&r.parent, 32)?;
                if let Some(p) = &r.packet_sha256 {
                    hex_id(p, 32)?;
                    check(r.trials > 0, PolicyError::Journal)?;
                }
                results.push(r);
            } else {
                return Err(PolicyError::Journal);
            }
        }
        check(
            anchors.len() <= 256 && claims.len() <= 256 && results.len() <= 256,
            PolicyError::Capacity,
        )?;
        anchors.sort_by_key(|a| a.sequence);
        let mut last = None;
        for (i, a) in anchors.iter().enumerate() {
            check(
                a.sequence == i as u64 + 1 && a.previous == last,
                PolicyError::Journal,
            )?;
            last = Some(a.digest.clone());
        }
        for c in &claims {
            check(
                anchors
                    .get((c.sequence - 1) as usize)
                    .is_some_and(|a| a.digest == c.registry_digest),
                PolicyError::Journal,
            )?;
        }
        for r in &results {
            check(
                claims.iter().any(|c| {
                    c.operation == r.operation
                        && c.purpose == Purpose::Search
                        && c.parent == r.parent
                        && c.generation == r.generation
                }),
                PolicyError::Journal,
            )?;
        }
        let mut j = Self {
            path: path.to_owned(),
            directory,
            lock,
            uid,
            identity,
            anchors,
            claims,
            results,
            unavailable: false,
        };
        j.advance(view)?;
        Ok(j)
    }
    fn pinned(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    fn ready(&self) -> Result<()> {
        check(!self.unavailable, PolicyError::Journal)?;
        let a = io(fs::symlink_metadata(&self.path))?;
        let b = io(self.directory.metadata())?;
        let l = io(self.lock.metadata())?;
        let v = io(fs::symlink_metadata(self.pinned().join("owner.lock")))?;
        check(
            a.is_dir()
                && !a.file_type().is_symlink()
                && a.dev() == b.dev()
                && a.ino() == b.ino()
                && a.uid() == self.uid
                && a.mode() & 0o7777 == 0o700
                && l.is_file()
                && l.uid() == self.uid
                && l.nlink() == 1
                && l.mode() & 0o7777 == 0o600
                && l.dev() == v.dev()
                && l.ino() == v.ino(),
            PolicyError::Journal,
        )
    }
    pub(crate) fn advance(&mut self, v: &VerifiedView) -> Result<()> {
        self.ready()?;
        let c = &v.body.context;
        check(
            c.registry_id == self.identity.registry
                && c.operator_id == self.identity.operator
                && c.network == self.identity.network
                && c.parameters == self.identity.parameters
                && c.source_commit == self.identity.source
                && c.node_policy_source == self.identity.node_policy
                && c.registry2_package == self.identity.registry2_package
                && v.registry_key == self.identity.registry_key
                && v.task_key == self.identity.task_key,
            PolicyError::ExternalContext,
        )?;
        if let Some(a) = self.anchors.last() {
            if v.body.registry_sequence == a.sequence {
                return check(
                    v.body.registry_digest == a.digest,
                    PolicyError::ExternalContext,
                );
            }
        }
        let old = self.anchors.last();
        check(
            v.body.registry_sequence == old.map_or(1, |a| a.sequence + 1)
                && v.body.registry_previous_digest == old.map(|a| a.digest.clone())
                && self.anchors.len() < 256,
            PolicyError::ExternalContext,
        )?;
        let a = Anchor {
            sequence: v.body.registry_sequence,
            digest: v.body.registry_digest.clone(),
            previous: v.body.registry_previous_digest.clone(),
        };
        if save(
            &self.pinned().join(format!("view-{:020}.json", a.sequence)),
            &a,
            &self.directory,
        )
        .is_err()
        {
            self.unavailable = true;
            return Err(PolicyError::Journal);
        }
        self.anchors.push(a);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn claim_count(&self) -> usize {
        self.claims.len()
    }
    pub(crate) fn fault_sink(&self) -> Result<JournalFaultSink> {
        self.ready()?;
        Ok(JournalFaultSink {
            path: self.path.clone(),
            directory: io(self.directory.try_clone())?,
            uid: self.uid,
        })
    }
    pub(crate) fn unfinished_fault(
        &self,
        unavailable: Arc<AtomicBool>,
    ) -> Result<UnfinishedOperationFault> {
        Ok(UnfinishedOperationFault {
            sink: self.fault_sink()?,
            unavailable,
            armed: true,
        })
    }
    pub(crate) fn used(&self, id: &str) -> bool {
        self.claims.iter().any(|c| c.operation == id)
    }
    pub(crate) fn reserve(
        &mut self,
        v: &VerifiedView,
        f: &NativeFacts,
        now: u64,
    ) -> Result<Reservation> {
        self.ready()?;
        let p = v.check(f, now)?;
        self.advance(v)?;
        check(!self.used(&p.operation_id), PolicyError::Replay)?;
        check(self.claims.len() < MAX_CLAIMS, PolicyError::Capacity)?;
        // Two independent accumulated histories. Changing an outside declared
        // class must not reset a task, and changing a task must not reset a class.
        // Both use this view's signed declared ceiling; neither proves funds or
        // enforces an economic balance. All purposes consume the same histories.
        for rows in [
            self.claims
                .iter()
                .filter(|c| c.native_task == v.body.task.native_task)
                .collect::<Vec<_>>(),
            self.claims
                .iter()
                .filter(|c| c.instance_class == v.body.instance_class)
                .collect::<Vec<_>>(),
        ] {
            let mut usage = Allocation {
                cpu_ns: 0,
                material_bytes: 0,
                da_bytes: 0,
                funding_units: 0,
                reuse_uses: 0,
            };
            for row in &rows {
                usage = add(&usage, &row.allocation)?;
            }
            usage = add(&usage, &p.allocation)?;
            check(
                (rows.len() as u64) < v.body.limits.operations
                    && within(&usage, &v.body.limits.allocation),
                PolicyError::Budget,
            )?;
        }

        if matches!(p.purpose, Purpose::WinnerValidation | Purpose::Activate) {
            let id = p
                .related_search_operation
                .as_ref()
                .ok_or(PolicyError::NativeBinding)?;
            let binding = task_binding_sha256(&v.body)?;
            check(
                self.claims.iter().any(|c| {
                    &c.operation == id
                        && c.purpose == Purpose::Search
                        && c.native_task == v.body.task.native_task
                        && c.instance_class == v.body.instance_class
                        && c.task_binding_sha256 == binding
                        && c.parent == f.context.actual_parent
                        && c.generation == f.generation
                }) && self.results.iter().any(|r| {
                    &r.operation == id
                        && r.parent == f.context.actual_parent
                        && r.generation == f.generation
                        && r.packet_sha256.as_deref() == Some(f.payload_sha256.as_str())
                }),
                PolicyError::NativeBinding,
            )?;
        }
        let c = Claim {
            schema: "restricted-mining-reservation-v1".into(),
            operation: p.operation_id.clone(),
            operation_nonce: p.operation_nonce.clone(),
            parent: f.context.actual_parent.clone(),
            generation: f.generation,
            purpose: p.purpose.clone(),
            payload: p.payload_sha256.clone(),
            declaration: v.body.declaration_digest.clone(),
            view: v.envelope_sha256.clone(),
            sequence: v.body.registry_sequence,
            registry_digest: v.body.registry_digest.clone(),
            native_task: v.body.task.native_task.clone(),
            instance_class: v.body.instance_class.clone(),
            task_binding_sha256: task_binding_sha256(&v.body)?,
            allocation: p.allocation.clone(),
        };
        if save(
            &self.pinned().join(format!("claim-{}.json", c.operation)),
            &c,
            &self.directory,
        )
        .is_err()
        {
            self.unavailable = true;
            return Err(PolicyError::Journal);
        }
        let r = Reservation {
            operation: c.operation.clone(),
            view: c.view.clone(),
            sequence: c.sequence,
            registry_digest: c.registry_digest.clone(),
            purpose: c.purpose.clone(),
            payload: c.payload.clone(),
        };
        self.claims.push(c);
        Ok(r)
    }
    pub(crate) fn recheck(
        &self,
        v: &VerifiedView,
        r: &Reservation,
        f: &NativeFacts,
        now: u64,
    ) -> Result<()> {
        self.ready()?;
        let p = v.check(f, now)?;
        check(
            self.anchors
                .last()
                .is_some_and(|a| a.sequence == r.sequence && a.digest == r.registry_digest)
                && r.view == v.envelope_sha256
                && r.operation == p.operation_id
                && r.purpose == f.purpose
                && r.payload == f.payload_sha256,
            PolicyError::ExternalContext,
        )
    }
    pub(crate) fn record_search(
        &mut self,
        v: &VerifiedView,
        r: &Reservation,
        f: &NativeFacts,
        packet: Option<&[u8]>,
        trials: u64,
    ) -> Result<()> {
        if packet.is_some() {
            self.recheck(v, r, f, base::now_ns()?)?;
        } else {
            self.ready()?;
        }
        let p = v.permission(&Purpose::Search, &f.payload_sha256)?;
        check(
            self.claims.iter().any(|c| {
                c.operation == r.operation
                    && c.view == r.view
                    && c.sequence == r.sequence
                    && c.registry_digest == r.registry_digest
                    && c.parent == f.context.actual_parent
                    && c.generation == f.generation
            }),
            PolicyError::Journal,
        )?;
        let search = p.search.as_ref().ok_or(PolicyError::NativeBinding)?;
        check(
            r.purpose == Purpose::Search
                && trials <= search.nonce_count
                && !self.results.iter().any(|s| s.operation == r.operation),
            PolicyError::Replay,
        )?;
        if let Some(raw) = packet {
            let decoded = crate::Packet::decode(raw).map_err(|_| PolicyError::NativeBinding)?;
            check(
                trials > 0
                    && decoded.header.nonce
                        == search
                            .nonce_first
                            .checked_add(trials - 1)
                            .ok_or(PolicyError::Input)?
                    && hex::encode(decoded.header.parent) == f.context.actual_parent
                    && decoded.header.timestamp == search.timestamp
                    && hex::encode(decoded.header.miner) == search.miner
                    && transactions_sha256(&decoded.transactions)?
                        == search.exact_transactions_sha256,
                PolicyError::NativeBinding,
            )?;
        }
        let result = SearchResult {
            schema: "restricted-mining-search-result-v1".into(),
            operation: r.operation.clone(),
            parent: f.context.actual_parent.clone(),
            generation: f.generation,
            packet_sha256: packet.map(sha),
            trials,
        };
        if save(
            &self.pinned().join(format!("result-{}.json", r.operation)),
            &result,
            &self.directory,
        )
        .is_err()
        {
            self.unavailable = true;
            return Err(PolicyError::Journal);
        }
        self.results.push(result);
        Ok(())
    }
    pub(crate) fn mark_unavailable(&mut self) -> Result<()> {
        let sink = self.fault_sink()?;
        self.unavailable = true;
        sink.persist()
    }
}
/// Immutable operation grant across math only. It owns no State or SQL lock.
pub(crate) struct Permit {
    pub(crate) view: Arc<VerifiedView>,
    pub(crate) facts: NativeFacts,
    pub(crate) reservation: Reservation,
    pub(crate) epoch: Arc<AtomicU64>,
    pub(crate) expected_epoch: u64,
    pub(crate) unavailable: Arc<AtomicBool>,
}
impl Permit {
    pub(crate) fn progress(&self) -> Result<()> {
        check(
            !self.unavailable.load(Ordering::Acquire),
            PolicyError::CpuUnknown,
        )?;
        check(
            self.epoch.load(Ordering::Acquire) == self.expected_epoch,
            PolicyError::ExternalContext,
        )?;
        self.view.check(&self.facts, base::now_ns()?)?;
        Ok(())
    }
}
type HeldMaterialIdentity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);
type HeldMaterialRow = (PathBuf, File, HeldMaterialIdentity);
pub(crate) struct HeldCatalog {
    rows: Vec<HeldMaterialRow>,
    roles: Vec<String>,
    catalog_sha256: String,
}
impl HeldCatalog {
    pub(crate) fn path_role(&self, role: &str) -> Result<PathBuf> {
        self.ready()?;
        let index = self
            .roles
            .iter()
            .position(|r| r == role)
            .ok_or(PolicyError::NativeBinding)?;
        Ok(self.rows[index].0.clone())
    }
    pub(crate) fn read_role(
        &self,
        role: &str,
        limit: u64,
        progress: &impl Fn() -> crate::Result<()>,
    ) -> Result<Vec<u8>> {
        self.ready()?;
        let index = self
            .roles
            .iter()
            .position(|r| r == role)
            .ok_or(PolicyError::NativeBinding)?;
        let (_, file, identity) = &self.rows[index];
        check(identity.2 <= limit, PolicyError::Capacity)?;
        let mut clone = io(file.try_clone())?;
        io(clone.seek(SeekFrom::Start(0)))?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 65536];
        loop {
            progress().map_err(|_| PolicyError::CpuUnknown)?;
            let n = io(clone.read(&mut buffer))?;
            if n == 0 {
                break;
            }
            check(
                bytes
                    .len()
                    .checked_add(n)
                    .is_some_and(|n| n as u64 <= identity.2),
                PolicyError::Capacity,
            )?;
            bytes.extend_from_slice(&buffer[..n]);
        }
        self.ready()?;
        check(bytes.len() as u64 == identity.2, PolicyError::NativeBinding)?;
        Ok(bytes)
    }
    pub(crate) fn ready(&self) -> Result<()> {
        for (path, file, identity) in &self.rows {
            check(
                same_meta(&io(file.metadata())?) == *identity
                    && same_meta(&io(fs::symlink_metadata(path))?) == *identity,
                PolicyError::NativeBinding,
            )?;
        }
        Ok(())
    }
    pub(crate) fn recheck(&self, inputs: &Inputs, view: &VerifiedView) -> Result<()> {
        check(
            self.catalog_sha256 == view.body.task.full_material_catalog
                && inputs.materials.len() == self.rows.len(),
            PolicyError::NativeBinding,
        )?;
        let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
        for (row, (path, file, identity)) in inputs.materials.iter().zip(&self.rows) {
            check(
                &row.path == path
                    && row.bytes == identity.2
                    && same_meta(&io(file.metadata())?) == *identity
                    && same_meta(&io(fs::symlink_metadata(path))?) == *identity,
                PolicyError::NativeBinding,
            )?;
            put_text(&mut catalog, &row.role);
            catalog.extend_from_slice(&row.bytes.to_le_bytes());
            put_text(&mut catalog, &row.sha256);
        }
        check(
            sha(&catalog) == self.catalog_sha256,
            PolicyError::NativeBinding,
        )
    }
}
pub(crate) fn verify_catalog(
    inputs: &Inputs,
    permit: &Permit,
    progress: &impl Fn() -> Result<()>,
) -> Result<HeldCatalog> {
    permit.progress()?;
    check(
        permit.facts.purpose == Purpose::StartupCatalog,
        PolicyError::ExternalContext,
    )?;
    let permission = permit.view.check(&permit.facts, base::now_ns()?)?;
    const ROLES: [&str; 6] = [
        "activation",
        "bootstrap",
        "checkpoint",
        "input",
        "model",
        "spec",
    ];
    check(
        inputs.materials.len() == ROLES.len(),
        PolicyError::NativeBinding,
    )?;
    let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
    let mut total = 0u64;
    let mut held_rows = Vec::new();
    for (row, role) in inputs.materials.iter().zip(ROLES) {
        check(
            row.role == role && row.path.is_absolute() && row.bytes > 0,
            PolicyError::NativeBinding,
        )?;
        hex_id(&row.sha256, 32)?;
        total = total.checked_add(row.bytes).ok_or(PolicyError::Budget)?;
        check(
            total <= 512 << 20
                && total <= permission.allocation.material_bytes
                && total <= permission.allocation.da_bytes,
            PolicyError::Budget,
        )?;
        let before = io(fs::symlink_metadata(&row.path))?;
        check(
            before.is_file()
                && before.nlink() == 1
                && before.uid() == inputs.expected_uid
                && before.mode() & 0o022 == 0
                && before.len() == row.bytes,
            PolicyError::NativeBinding,
        )?;
        let mut file = io(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&row.path))?;
        let held = io(file.metadata())?;
        check(
            before.dev() == held.dev() && before.ino() == held.ino(),
            PolicyError::NativeBinding,
        )?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65_536];
        let mut count = 0u64;
        loop {
            permit.progress()?;
            progress()?;
            let n = io(file.read(&mut buffer))?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).ok_or(PolicyError::Budget)?;
            check(count <= row.bytes, PolicyError::NativeBinding)?;
            digest.update(&buffer[..n]);
        }
        let after = io(file.metadata())?;
        let visible = io(fs::symlink_metadata(&row.path))?;
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.mode(),
                m.uid(),
                m.nlink(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        check(
            identity(&before) == identity(&after)
                && identity(&after) == identity(&visible)
                && count == row.bytes
                && hex::encode(digest.finalize()) == row.sha256,
            PolicyError::NativeBinding,
        )?;
        if role == "model" {
            check(
                row.sha256 == permit.view.body.task.model_material,
                PolicyError::NativeBinding,
            )?;
        }
        if role == "input" {
            check(
                row.sha256 == permit.view.body.task.input_material,
                PolicyError::NativeBinding,
            )?;
        }
        put_text(&mut catalog, role);
        catalog.extend_from_slice(&row.bytes.to_le_bytes());
        put_text(&mut catalog, &row.sha256);
        held_rows.push((row.path.clone(), file, same_meta(&before)));
    }
    check(
        sha(&catalog) == permit.view.body.task.full_material_catalog,
        PolicyError::NativeBinding,
    )?;
    Ok(HeldCatalog {
        rows: held_rows,
        roles: ROLES.iter().map(|r| (*r).to_owned()).collect(),
        catalog_sha256: sha(&catalog),
    })
}
#[cfg(test)]
#[path = "operator_mining_policy_tests.rs"]
pub(crate) mod tests;
