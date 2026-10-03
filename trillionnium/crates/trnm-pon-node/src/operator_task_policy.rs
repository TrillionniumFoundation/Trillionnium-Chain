//! Source candidate for an explicitly restricted, operator-owned Node mode.
//! Node integration source candidate, uncompiled, not a consensus authorization rule.
//! The issuer must independently validate Registry2 before issuing this new domain.
//! No Registry2 signature is interpreted as this module's signature.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use trnm_crypto_primitives::verify_hex_strict;

pub const MODE: &str = "restricted-owner-node-v2";
#[path = "operator_pool_policy.rs"]
pub mod pool;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-NODE-GRANT2";
const MAX_POLICY_BYTES: usize = 64 << 10;
const MAX_FILES: usize = 256;
const MAX_WINDOW_NS: u64 = 86_400_000_000_000;
const Q: u64 = 4_294_967_291;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    Input,
    Signature,
    ExternalContext,
    Window,
    Revoked,
    NativeBinding,
    Budget,
    CpuUnknown,
    CpuRegressed,
    Replay,
    Capacity,
    Journal,
    Busy,
    Unsupported,
}
type Result<T> = std::result::Result<T, PolicyError>;
fn require(ok: bool, error: PolicyError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn hash_hex(value: &str, bytes: usize) -> Result<()> {
    require(
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        PolicyError::Input,
    )
}
fn text(value: &str) -> Result<()> {
    require(
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        PolicyError::Input,
    )
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub registry_id: String,
    pub operator_id: String,
    pub network: String,
    pub parameters: String,
    pub source_commit: String,
    pub node_policy_source: String,
    pub registry2_package: String,
    pub actual_parent: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub(crate) purpose: String,
    pub(crate) native_task: String,
    pub(crate) lease_sha256: String,
    pub(crate) model_id: String,
    pub(crate) model_revision: String,
    pub(crate) model_material: String,
    pub(crate) native_model: String,
    pub(crate) layer_tensor: String,
    pub(crate) layer_index: u16,
    pub(crate) layer_selector: String,
    pub(crate) input_material: String,
    pub(crate) native_input: String,
    pub(crate) dimension: u32,
    pub(crate) field_modulus: u64,
    pub(crate) encoding: String,
    pub(crate) a_sha256: String,
    pub(crate) b_sha256: String,
    pub(crate) full_material_catalog: String,
    pub(crate) recipe_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub(crate) cpu_ns: u64,
    pub(crate) material_bytes: u64,
    pub(crate) da_bytes: u64,
    pub(crate) funding_units: u64,
    pub(crate) reuse_uses: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub(crate) operations: u64,
    pub(crate) allocation: Allocation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub(crate) schema: String,
    pub(crate) context: Context,
    pub(crate) registry_sequence: u64,
    pub(crate) registry_digest: String,
    pub(crate) registry_previous_digest: Option<String>,
    pub(crate) declaration_digest: String,
    pub(crate) exact_packet_sha256: String,
    pub(crate) operation_id: String,
    pub(crate) task: Task,
    pub(crate) instance_class: String,
    pub(crate) nonce_first: u64,
    pub(crate) nonce_last: u64,
    pub(crate) source_class: String,
    pub(crate) cost_class: String,
    pub(crate) cost_evidence: Option<String>,
    pub(crate) preprocessing: String,
    pub(crate) prepared_artifact: Option<String>,
    pub(crate) setup_record: Option<String>,
    pub(crate) funding_commitment: String,
    pub(crate) funding_evidence: String,
    pub(crate) declared_funding_units: u64,
    pub(crate) retention_until_ns: u64,
    pub(crate) allocation: Allocation,
    pub(crate) limits: Limits,
    pub(crate) not_before_ns: u64,
    pub(crate) expires_ns: u64,
    pub(crate) revoked: bool,
    pub(crate) allowed_task_commands: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: Grant,
    registry_signature: String,
    task_signature: String,
}

/// Loaded from the node operator's protected configuration, never a Request.
/// Every field is mandatory. Full expected body equality prevents the candidate
/// grant from choosing its own parent, class, funding claim, budget, or source.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthority {
    pub registry_key: String,
    pub task_key: String,
    pub latest_sequence: u64,
    pub latest_digest: String,
    pub expected_envelope_sha256: String,
    pub expected: Grant,
}
pub(crate) struct VerifiedPolicy {
    body: Grant,
    envelope_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialInput {
    pub role: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedNodeInputs {
    pub pool_permissions: Vec<pool::PoolExternalPermission>,
    pub raw_policy: Vec<u8>,
    pub authority: ExternalAuthority,
    pub journal_path: PathBuf,
    pub expected_uid: u32,
    pub materials: Vec<MaterialInput>,
}
/// Entire fixed catalog is streamed before Native startup, after authorization.
/// This certifies observed bytes, not model/layer origin, costs, or physical use.
pub(crate) fn verify_catalog(inputs: &RestrictedNodeInputs, policy: &VerifiedPolicy) -> Result<()> {
    const ROLES: [&str; 6] = [
        "activation",
        "bootstrap",
        "checkpoint",
        "input",
        "model",
        "spec",
    ];
    require(
        inputs.materials.len() == ROLES.len(),
        PolicyError::NativeBinding,
    )?;
    let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
    let mut total = 0u64;
    for (row, role) in inputs.materials.iter().zip(ROLES) {
        require(
            row.role == role && row.path.is_absolute() && row.bytes > 0,
            PolicyError::NativeBinding,
        )?;
        hash_hex(&row.sha256, 32)?;
        total = total.checked_add(row.bytes).ok_or(PolicyError::Budget)?;
        require(
            total <= 512 << 20
                && total <= policy.body.allocation.material_bytes
                && total <= policy.body.allocation.da_bytes,
            PolicyError::Budget,
        )?;
        let before = io(fs::symlink_metadata(&row.path))?;
        require(
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
        require(
            before.dev() == held.dev() && before.ino() == held.ino(),
            PolicyError::NativeBinding,
        )?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65_536];
        let mut count = 0u64;
        loop {
            let n = io(file.read(&mut buffer))?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).ok_or(PolicyError::Budget)?;
            require(count <= row.bytes, PolicyError::NativeBinding)?;
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
        require(
            identity(&before) == identity(&after)
                && identity(&after) == identity(&visible)
                && count == row.bytes
                && hex::encode(digest.finalize()) == row.sha256,
            PolicyError::NativeBinding,
        )?;
        if role == "model" {
            require(
                row.sha256 == policy.body.task.model_material,
                PolicyError::NativeBinding,
            )?;
        }
        if role == "input" {
            require(
                row.sha256 == policy.body.task.input_material,
                PolicyError::NativeBinding,
            )?;
        }
        put_text(&mut catalog, role);
        catalog.extend_from_slice(&row.bytes.to_le_bytes());
        put_text(&mut catalog, &row.sha256);
    }
    require(
        sha(&catalog) == policy.body.task.full_material_catalog,
        PolicyError::NativeBinding,
    )
}
pub(crate) fn now_ns() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PolicyError::Window)?;
    u64::try_from(duration.as_nanos()).map_err(|_| PolicyError::Window)
}
pub(crate) fn digest_bytes(raw: &[u8]) -> String {
    sha(raw)
}
/// CLI calls this before Settings can read model/checkpoint files. Expected
/// source labels are independently supplied operator parameters, not runtime
/// source attestation; the later external build guardian must bind their bytes.
pub fn validate_protected_inputs(
    inputs: &RestrictedNodeInputs,
    commit: &str,
    policy_source: &str,
    registry2_package: &str,
) -> Result<()> {
    hash_hex(commit, 20)?;
    hash_hex(policy_source, 32)?;
    hash_hex(registry2_package, 32)?;
    let context = &inputs.authority.expected.context;
    require(
        context.source_commit == commit
            && context.node_policy_source == policy_source
            && context.registry2_package == registry2_package,
        PolicyError::ExternalContext,
    )?;
    let now = now_ns()?;
    let policy = authenticate(&inputs.raw_policy, &inputs.authority, now)?;
    require(inputs.pool_permissions.len() <= 64, PolicyError::Capacity)?;
    for permission in &inputs.pool_permissions {
        pool::authenticate_pool(permission, &inputs.authority, &policy, now)?;
    }
    Ok(())
}
pub enum SigningRole {
    Registry,
    Task,
}
/// Public fixed bytes for an outside issuer. No signing/key generation occurs.
pub fn operator_signing_bytes(body: &Grant, role: SigningRole) -> Result<Vec<u8>> {
    validate(body)?;
    Ok(message(
        body,
        match role {
            SigningRole::Registry => 1,
            SigningRole::Task => 2,
        },
    ))
}

fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn put_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}
fn put_optional(out: &mut Vec<u8>, value: &Option<String>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        put_text(out, value);
    }
}
fn put_allocation(out: &mut Vec<u8>, value: &Allocation) {
    for n in [
        value.cpu_ns,
        value.material_bytes,
        value.da_bytes,
        value.funding_units,
        value.reuse_uses,
    ] {
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// A fresh fixed-order binary signing payload. JSON ordering is not a signature
/// convention here; Unicode is length-prefixed UTF-8. This is not Registry2's
/// strict canonical JSON/domain, and never accepts the old domain as a fallback.
fn message(body: &Grant, role: u8) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.push(role);
    let c = &body.context;
    for s in [
        &body.schema,
        &c.registry_id,
        &c.operator_id,
        &c.network,
        &c.parameters,
        &c.source_commit,
        &c.node_policy_source,
        &c.registry2_package,
        &c.actual_parent,
    ] {
        put_text(&mut out, s);
    }
    out.extend_from_slice(&body.registry_sequence.to_le_bytes());
    put_text(&mut out, &body.registry_digest);
    put_optional(&mut out, &body.registry_previous_digest);
    put_text(&mut out, &body.declaration_digest);
    put_text(&mut out, &body.exact_packet_sha256);
    put_text(&mut out, &body.operation_id);
    let t = &body.task;
    for s in [
        &t.purpose,
        &t.native_task,
        &t.lease_sha256,
        &t.model_id,
        &t.model_revision,
        &t.model_material,
        &t.native_model,
        &t.layer_tensor,
    ] {
        put_text(&mut out, s);
    }
    out.extend_from_slice(&t.layer_index.to_le_bytes());
    for s in [&t.layer_selector, &t.input_material, &t.native_input] {
        put_text(&mut out, s);
    }
    out.extend_from_slice(&t.dimension.to_le_bytes());
    out.extend_from_slice(&t.field_modulus.to_le_bytes());
    for s in [
        &t.encoding,
        &t.a_sha256,
        &t.b_sha256,
        &t.full_material_catalog,
        &t.recipe_sha256,
        &body.instance_class,
    ] {
        put_text(&mut out, s);
    }
    out.extend_from_slice(&body.nonce_first.to_le_bytes());
    out.extend_from_slice(&body.nonce_last.to_le_bytes());
    for s in [&body.source_class, &body.cost_class] {
        put_text(&mut out, s);
    }
    put_optional(&mut out, &body.cost_evidence);
    put_text(&mut out, &body.preprocessing);
    put_optional(&mut out, &body.prepared_artifact);
    put_optional(&mut out, &body.setup_record);
    put_text(&mut out, &body.funding_commitment);
    put_text(&mut out, &body.funding_evidence);
    for n in [body.declared_funding_units, body.retention_until_ns] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    put_allocation(&mut out, &body.allocation);
    out.extend_from_slice(&body.limits.operations.to_le_bytes());
    put_allocation(&mut out, &body.limits.allocation);
    for n in [body.not_before_ns, body.expires_ns] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.push(u8::from(body.revoked));
    out.extend_from_slice(&(body.allowed_task_commands.len() as u32).to_le_bytes());
    for digest in &body.allowed_task_commands {
        put_text(&mut out, digest);
    }
    out
}

fn validate_allocation(a: &Allocation) -> Result<()> {
    require(
        a.cpu_ns > 0 && a.material_bytes > 0 && a.da_bytes > 0 && a.funding_units > 0,
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
fn validate(body: &Grant) -> Result<()> {
    require(body.schema == MODE, PolicyError::Input)?;
    let c = &body.context;
    for h in [
        &c.registry_id,
        &c.operator_id,
        &c.network,
        &c.parameters,
        &c.node_policy_source,
        &c.registry2_package,
        &c.actual_parent,
        &body.registry_digest,
        &body.declaration_digest,
        &body.exact_packet_sha256,
        &body.operation_id,
    ] {
        hash_hex(h, 32)?;
    }
    hash_hex(&c.source_commit, 20)?;
    require(
        body.operation_id == operator_operation_id(c, &body.exact_packet_sha256)?,
        PolicyError::NativeBinding,
    )?;
    require(
        body.registry_sequence > 0
            && (body.registry_sequence == 1) == body.registry_previous_digest.is_none(),
        PolicyError::Input,
    )?;
    if let Some(h) = &body.registry_previous_digest {
        hash_hex(h, 32)?;
    }
    let t = &body.task;
    require(
        matches!(t.purpose.as_str(), "maintenance-tag1" | "checkpoint-tag22")
            && t.dimension == 64
            && t.field_modulus == Q
            && t.encoding == "canonical-u32-le",
        PolicyError::NativeBinding,
    )?;
    text(&t.model_id)?;
    text(&t.layer_tensor)?;
    hash_hex(&t.model_revision, 20)?;
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
        hash_hex(h, 32)?;
    }
    require(
        matches!(
            body.instance_class.as_str(),
            "dense" | "structured" | "zero"
        ) && body.nonce_first > 0
            && body.nonce_last >= body.nonce_first,
        PolicyError::Input,
    )?;
    require(
        matches!(
            body.source_class.as_str(),
            "declared-same-operator" | "declared-licensed-external" | "declared-public-artifact"
        ),
        PolicyError::Input,
    )?;
    require(
        matches!(
            body.cost_class.as_str(),
            "unmeasured" | "reported-full-invocation" | "reported-preprocessed-reuse"
        ),
        PolicyError::Input,
    )?;
    require(
        (body.cost_class == "unmeasured") == body.cost_evidence.is_none(),
        PolicyError::Input,
    )?;
    if let Some(h) = &body.cost_evidence {
        hash_hex(h, 32)?;
    }
    match body.preprocessing.as_str() {
        "forbidden" => require(
            body.prepared_artifact.is_none()
                && body.setup_record.is_none()
                && body.allocation.reuse_uses == 0
                && body.limits.allocation.reuse_uses == 0,
            PolicyError::Input,
        )?,
        "exact-task-input-only" => {
            hash_hex(
                body.prepared_artifact
                    .as_deref()
                    .ok_or(PolicyError::Input)?,
                32,
            )?;
            hash_hex(body.setup_record.as_deref().ok_or(PolicyError::Input)?, 32)?;
            require(body.allocation.reuse_uses > 0, PolicyError::Input)?;
        }
        _ => return Err(PolicyError::Input),
    }
    hash_hex(&body.funding_commitment, 32)?;
    hash_hex(&body.funding_evidence, 32)?;
    validate_allocation(&body.allocation)?;
    validate_allocation(&body.limits.allocation)?;
    require(
        body.limits.operations > 0
            && body.limits.operations <= MAX_FILES as u64
            && within(&body.allocation, &body.limits.allocation)
            && body.declared_funding_units >= body.limits.allocation.funding_units,
        PolicyError::Budget,
    )?;
    require(
        body.allowed_task_commands.len() <= 16
            && body
                .allowed_task_commands
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        PolicyError::Input,
    )?;
    for h in &body.allowed_task_commands {
        hash_hex(h, 32)?;
    }
    let window = body
        .expires_ns
        .checked_sub(body.not_before_ns)
        .ok_or(PolicyError::Window)?;
    require(
        body.not_before_ns > 0
            && window > 0
            && window <= MAX_WINDOW_NS
            && body.retention_until_ns >= body.expires_ns,
        PolicyError::Window,
    )
}

pub(crate) fn authenticate(
    raw: &[u8],
    external: &ExternalAuthority,
    observed_ns: u64,
) -> Result<VerifiedPolicy> {
    require(
        !raw.is_empty() && raw.len() <= MAX_POLICY_BYTES,
        PolicyError::Input,
    )?;
    hash_hex(&external.registry_key, 32)?;
    hash_hex(&external.task_key, 32)?;
    hash_hex(&external.latest_digest, 32)?;
    hash_hex(&external.expected_envelope_sha256, 32)?;
    require(
        external.registry_key != external.task_key,
        PolicyError::ExternalContext,
    )?;
    let envelope: Envelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    validate(&envelope.body)?;
    validate(&external.expected)?;
    require(
        envelope.body == external.expected
            && envelope.body.registry_sequence == external.latest_sequence
            && envelope.body.registry_digest == external.latest_digest
            && sha(raw) == external.expected_envelope_sha256,
        PolicyError::ExternalContext,
    )?;
    // Authenticate a revoked view so its higher anchor can be persisted. Only
    // check/reserve reject it; treating it as an invalid signature would lose
    // the durable revocation high-water mark on a restart.
    require(
        envelope.body.not_before_ns <= observed_ns && observed_ns < envelope.body.expires_ns,
        PolicyError::Window,
    )?;
    verify_hex_strict(
        &external.registry_key,
        &message(&envelope.body, 1),
        &envelope.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(
        &external.task_key,
        &message(&envelope.body, 2),
        &envelope.task_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedPolicy {
        body: envelope.body,
        envelope_sha256: sha(raw),
    })
}

/// These facts must be constructed inside Node from its Settings, actual parent
/// and full lease, installed material binding, and the exact decoded packet.
/// A public handler or candidate sidecar must not construct or select them.
#[derive(Clone)]
pub(crate) struct NativeFacts {
    pub(crate) network: String,
    pub(crate) parameters: String,
    pub(crate) parent: String,
    pub(crate) task: Task,
    pub(crate) packet_sha256: String,
    pub(crate) header_nonce: u64,
}
impl VerifiedPolicy {
    pub(crate) fn task(&self) -> &Task {
        &self.body.task
    }
    pub(crate) fn context(&self) -> &Context {
        &self.body.context
    }
    pub(crate) fn next_view_of(&self, old: &Self) -> bool {
        old.body.registry_sequence.checked_add(1) == Some(self.body.registry_sequence)
            && self.body.registry_previous_digest.as_deref()
                == Some(old.body.registry_digest.as_str())
    }
    pub(crate) fn marker(&self, journal: &Path) -> Result<Vec<u8>> {
        require(journal.is_absolute(), PolicyError::Input)?;
        let value = serde_json::json!({"schema": MODE, "registry": self.body.context.registry_id,
            "operator": self.body.context.operator_id, "network": self.body.context.network,
            "parameters": self.body.context.parameters, "journal": journal.to_str().ok_or(PolicyError::Input)?});
        serde_json::to_vec(&value).map_err(|_| PolicyError::Input)
    }
    pub(crate) fn check_commands(&self, transactions: &[Vec<u8>]) -> Result<()> {
        for raw in transactions {
            let envelope = trnm_protocol::pon_wire::Envelope::decode(raw)
                .map_err(|_| PolicyError::NativeBinding)?;
            if envelope.tag == 12 {
                return Err(PolicyError::NativeBinding);
            }
            if matches!(envelope.tag, 13 | 18..=22) {
                require(
                    self.body
                        .allowed_task_commands
                        .binary_search(&sha(raw))
                        .is_ok(),
                    PolicyError::ExternalContext,
                )?;
            }
        }
        Ok(())
    }
    /// Full packet identity is signed, not merely public A/B/task/nonce shape.
    /// Call before any reservation, Work replay, or per-request material loading.
    pub(crate) fn check_packet(&self, packet_sha256: &str) -> Result<()> {
        hash_hex(packet_sha256, 32)?;
        require(
            packet_sha256 == self.body.exact_packet_sha256,
            PolicyError::NativeBinding,
        )
    }
    pub(crate) fn check_window(&self, observed_ns: u64) -> Result<()> {
        require(!self.body.revoked, PolicyError::Revoked)?;
        require(
            self.body.not_before_ns <= observed_ns && observed_ns < self.body.expires_ns,
            PolicyError::Window,
        )
    }
    pub(crate) fn check(&self, facts: &NativeFacts, observed_ns: u64) -> Result<()> {
        self.check_window(observed_ns)?;
        self.check_packet(&facts.packet_sha256)?;
        require(
            facts.network == self.body.context.network
                && facts.parameters == self.body.context.parameters
                && facts.parent == self.body.context.actual_parent
                && facts.task == self.body.task
                && facts.header_nonce >= self.body.nonce_first
                && facts.header_nonce <= self.body.nonce_last,
            PolicyError::NativeBinding,
        )
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalIdentity {
    schema: String,
    registry: String,
    operator: String,
    network: String,
    parameters: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    sequence: u64,
    digest: String,
    previous: Option<String>,
}
#[derive(Serialize)]
struct Fault {
    schema: &'static str,
    label: &'static str,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    schema: String,
    operation: String,
    packet_sha256: String,
    declaration: String,
    policy_sha256: String,
    sequence: u64,
    registry_digest: String,
    native_task: String,
    instance_class: String,
    allocation: Allocation,
}

/// Exclusive private owner for local reservation history, independent of chain
/// rollback. No API refunds, deletes, overwrites, prunes or chooses a latest view.
/// Linux only until another held-directory implementation is explicitly supplied.
pub struct Journal {
    path: PathBuf,
    directory: File,
    owner_lock: File,
    uid: u32,
    identity: JournalIdentity,
    anchor_sequence: u64,
    anchor_digest: String,
    claims: Vec<Claim>,
    pool_claims: Vec<pool::PoolClaim>,
    unavailable: bool,
}
pub(crate) struct Reservation {
    operation: String,
    packet_sha256: String,
    policy_sha256: String,
    sequence: u64,
    registry_digest: String,
}

fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| PolicyError::Journal)
}
fn open_held(path: &Path, uid: u32) -> Result<File> {
    let before = io(fs::symlink_metadata(path))?;
    require(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600,
        PolicyError::Journal,
    )?;
    let file = io(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path))?;
    let held = io(file.metadata())?;
    require(
        held.dev() == before.dev()
            && held.ino() == before.ino()
            && held.len() == before.len()
            && held.mode() == before.mode()
            && held.nlink() == 1,
        PolicyError::Journal,
    )?;
    Ok(file)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, uid: u32) -> Result<T> {
    let mut file = open_held(path, uid)?;
    let before = io(file.metadata())?;
    require(
        before.len() > 0 && before.len() <= MAX_POLICY_BYTES as u64,
        PolicyError::Journal,
    )?;
    let mut raw = Vec::new();
    io((&mut file)
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut raw))?;
    let after = io(file.metadata())?;
    let visible = io(fs::symlink_metadata(path))?;
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
    require(
        raw.len() as u64 == before.len()
            && identity(&before) == identity(&after)
            && identity(&after) == identity(&visible),
        PolicyError::Journal,
    )?;
    serde_json::from_slice(&raw).map_err(|_| PolicyError::Journal)
}
fn save_new<T: Serialize>(path: &Path, value: &T, directory: &File) -> Result<()> {
    let raw = serde_json::to_vec(value).map_err(|_| PolicyError::Journal)?;
    require(
        !raw.is_empty() && raw.len() <= MAX_POLICY_BYTES,
        PolicyError::Journal,
    )?;
    let mut file = io(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path))?;
    // Any failure retains the partial file and disables the owner. No unlink retry.
    io(file.write_all(&raw))?;
    io(file.sync_all())?;
    io(directory.sync_all())
}

impl Journal {
    pub(crate) fn open(path: &Path, uid: u32, policy: &VerifiedPolicy) -> Result<Self> {
        require(
            cfg!(target_os = "linux") && path.is_absolute(),
            PolicyError::Unsupported,
        )?;
        let visible = io(fs::symlink_metadata(path))?;
        require(
            visible.is_dir() && visible.uid() == uid && visible.mode() & 0o7777 == 0o700,
            PolicyError::Journal,
        )?;
        let directory = io(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path))?;
        let held = io(directory.metadata())?;
        require(
            visible.dev() == held.dev() && visible.ino() == held.ino(),
            PolicyError::Journal,
        )?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let lock_path = pinned.join("owner.lock");
        let owner_lock = if fs::symlink_metadata(&lock_path).is_err() {
            let f = io(OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path))?;
            io(f.sync_all())?;
            io(directory.sync_all())?;
            f
        } else {
            open_held(&lock_path, uid)?
        };
        owner_lock
            .try_lock_exclusive()
            .map_err(|_| PolicyError::Busy)?;
        let c = &policy.body.context;
        let identity = JournalIdentity {
            schema: "restricted-owner-node-journal-v2".into(),
            registry: c.registry_id.clone(),
            operator: c.operator_id.clone(),
            network: c.network.clone(),
            parameters: c.parameters.clone(),
        };
        let identity_path = pinned.join("identity.json");
        if fs::symlink_metadata(&identity_path).is_err() {
            // Only a genuinely empty fresh owner namespace can acquire identity.
            let mut names = io(fs::read_dir(&pinned))?;
            let first = io(names.next().ok_or(PolicyError::Journal)?)?;
            require(
                first.file_name() == "owner.lock" && names.next().is_none(),
                PolicyError::Journal,
            )?;
            save_new(&identity_path, &identity, &directory)?;
        } else {
            require(
                read_json::<JournalIdentity>(&identity_path, uid)? == identity,
                PolicyError::Journal,
            )?;
        }
        let mut anchors = Vec::new();
        let mut claims = Vec::new();
        let mut pool_claims = Vec::new();
        let mut entries = 0;
        for entry in io(fs::read_dir(&pinned))? {
            entries += 1;
            require(entries <= MAX_FILES * 2 + 2, PolicyError::Capacity)?;
            let entry = io(entry)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PolicyError::Journal)?;
            if name == "owner.lock" || name == "identity.json" {
                continue;
            }
            // No automatic recovery from uncertain accounting. The operator
            // must inspect the retained Native fact and issue a new explicit
            // recovery design; this source never deletes the fault or history.
            if name == "unavailable.json" {
                return Err(PolicyError::Journal);
            }
            if let Some(suffix) = name
                .strip_prefix("view-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let anchor: Anchor = read_json(&pinned.join(&name), uid)?;
                require(
                    suffix == format!("{:020}", anchor.sequence),
                    PolicyError::Journal,
                )?;
                hash_hex(&anchor.digest, 32)?;
                if let Some(h) = &anchor.previous {
                    hash_hex(h, 32)?;
                }
                anchors.push(anchor);
            } else if let Some(suffix) = name
                .strip_prefix("pool-claim-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let claim: pool::PoolClaim = read_json(&pinned.join(&name), uid)?;
                pool::validate_retained_claim(&claim, &identity)?;
                require(suffix == claim.operation, PolicyError::Journal)?;
                pool_claims.push(claim);
            } else if let Some(suffix) = name
                .strip_prefix("claim-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let claim: Claim = read_json(&pinned.join(&name), uid)?;
                require(
                    suffix == claim.operation
                        && claim.schema == "restricted-node-reservation-v1"
                        && claim.sequence > 0,
                    PolicyError::Journal,
                )?;
                for h in [
                    &claim.operation,
                    &claim.packet_sha256,
                    &claim.declaration,
                    &claim.policy_sha256,
                    &claim.registry_digest,
                    &claim.native_task,
                ] {
                    hash_hex(h, 32)?;
                }
                require(
                    matches!(
                        claim.instance_class.as_str(),
                        "dense" | "structured" | "zero"
                    ),
                    PolicyError::Journal,
                )?;
                require(
                    claim.operation == operation(&identity, &claim.packet_sha256),
                    PolicyError::Journal,
                )?;
                validate_allocation(&claim.allocation)?;
                claims.push(claim);
            } else {
                return Err(PolicyError::Journal);
            }
        }
        require(
            anchors.len() <= MAX_FILES && claims.len() + pool_claims.len() <= MAX_FILES,
            PolicyError::Capacity,
        )?;
        anchors.sort_by_key(|a| a.sequence);
        let mut prior = None;
        for (index, anchor) in anchors.iter().enumerate() {
            require(
                anchor.sequence == index as u64 + 1 && anchor.previous == prior,
                PolicyError::Journal,
            )?;
            prior = Some(anchor.digest.clone());
        }
        for claim in &claims {
            let anchor = anchors
                .get((claim.sequence - 1) as usize)
                .ok_or(PolicyError::Journal)?;
            require(anchor.digest == claim.registry_digest, PolicyError::Journal)?;
        }
        for claim in &pool_claims {
            let anchor = anchors
                .get((claim.sequence - 1) as usize)
                .ok_or(PolicyError::Journal)?;
            require(anchor.digest == claim.registry_digest, PolicyError::Journal)?;
        }
        let last = anchors.last();
        let mut owner = Self {
            path: path.to_owned(),
            directory,
            owner_lock,
            uid,
            identity,
            anchor_sequence: last.map_or(0, |a| a.sequence),
            anchor_digest: last.map_or_else(String::new, |a| a.digest.clone()),
            claims,
            pool_claims,
            unavailable: false,
        };
        owner.advance(policy)?;
        Ok(owner)
    }
    fn pinned(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    fn ready(&self) -> Result<()> {
        require(!self.unavailable, PolicyError::Journal)?;
        let visible = io(fs::symlink_metadata(&self.path))?;
        let held = io(self.directory.metadata())?;
        let lock = io(self.owner_lock.metadata())?;
        let visible_lock = io(fs::symlink_metadata(self.pinned().join("owner.lock")))?;
        require(
            visible.is_dir()
                && visible.dev() == held.dev()
                && visible.ino() == held.ino()
                && visible.uid() == self.uid
                && visible.mode() & 0o7777 == 0o700
                && lock.is_file()
                && lock.uid() == self.uid
                && lock.nlink() == 1
                && lock.mode() & 0o7777 == 0o600
                && visible_lock.is_file()
                && visible_lock.dev() == lock.dev()
                && visible_lock.ino() == lock.ino(),
            PolicyError::Journal,
        )
    }
    pub(crate) fn advance(&mut self, policy: &VerifiedPolicy) -> Result<()> {
        self.ready()?;
        let g = &policy.body;
        let c = &g.context;
        require(
            c.registry_id == self.identity.registry
                && c.operator_id == self.identity.operator
                && c.network == self.identity.network
                && c.parameters == self.identity.parameters,
            PolicyError::ExternalContext,
        )?;
        if g.registry_sequence == self.anchor_sequence {
            return require(
                g.registry_digest == self.anchor_digest,
                PolicyError::ExternalContext,
            );
        }
        require(
            g.registry_sequence
                == self
                    .anchor_sequence
                    .checked_add(1)
                    .ok_or(PolicyError::Capacity)?
                && g.registry_sequence <= MAX_FILES as u64
                && g.registry_previous_digest
                    == if self.anchor_sequence == 0 {
                        None
                    } else {
                        Some(self.anchor_digest.clone())
                    },
            PolicyError::ExternalContext,
        )?;
        let anchor = Anchor {
            sequence: g.registry_sequence,
            digest: g.registry_digest.clone(),
            previous: g.registry_previous_digest.clone(),
        };
        let result = save_new(
            &self
                .pinned()
                .join(format!("view-{:020}.json", g.registry_sequence)),
            &anchor,
            &self.directory,
        );
        if result.is_err() {
            self.unavailable = true;
            return result;
        }
        self.anchor_sequence = g.registry_sequence;
        self.anchor_digest = g.registry_digest.clone();
        Ok(())
    }
    pub(crate) fn work_operation_is_used(&self, policy: &VerifiedPolicy) -> bool {
        self.claims
            .iter()
            .any(|claim| claim.operation == policy.body.operation_id)
    }
    pub(crate) fn reserve(
        &mut self,
        policy: &VerifiedPolicy,
        facts: &NativeFacts,
        observed_ns: u64,
    ) -> Result<Reservation> {
        self.ready()?;
        policy.check(facts, observed_ns)?;
        self.advance(policy)?;
        let id = operation(&self.identity, &facts.packet_sha256);
        require(id == policy.body.operation_id, PolicyError::NativeBinding)?;
        require(
            !self.claims.iter().any(|c| c.operation == id),
            PolicyError::Replay,
        )?;
        require(
            self.claims.len() + self.pool_claims.len() < MAX_FILES,
            PolicyError::Capacity,
        )?;
        // Aggregate by registered Native task and declared class, rather than by
        // declaration/view/source epoch. A new envelope cannot reset its usage.
        let rows: Vec<_> = self
            .claims
            .iter()
            .filter(|c| {
                c.native_task == policy.body.task.native_task
                    && c.instance_class == policy.body.instance_class
            })
            .collect();
        let mut usage = Allocation {
            cpu_ns: 0,
            material_bytes: 0,
            da_bytes: 0,
            funding_units: 0,
            reuse_uses: 0,
        };
        let pool_rows: Vec<_> = self
            .pool_claims
            .iter()
            .filter(|c| {
                c.native_task == policy.body.task.native_task
                    && c.instance_class == policy.body.instance_class
            })
            .collect();
        for claim in &rows {
            usage = add(&usage, &claim.allocation)?;
        }
        for claim in &pool_rows {
            usage = add(&usage, &claim.allocation)?;
        }
        usage = add(&usage, &policy.body.allocation)?;
        require(
            ((rows.len() + pool_rows.len()) as u64) < policy.body.limits.operations
                && within(&usage, &policy.body.limits.allocation),
            PolicyError::Budget,
        )?;
        let claim = Claim {
            schema: "restricted-node-reservation-v1".into(),
            operation: id.clone(),
            packet_sha256: facts.packet_sha256.clone(),
            declaration: policy.body.declaration_digest.clone(),
            policy_sha256: policy.envelope_sha256.clone(),
            sequence: policy.body.registry_sequence,
            registry_digest: policy.body.registry_digest.clone(),
            native_task: policy.body.task.native_task.clone(),
            instance_class: policy.body.instance_class.clone(),
            allocation: policy.body.allocation.clone(),
        };
        let result = save_new(
            &self.pinned().join(format!("claim-{id}.json")),
            &claim,
            &self.directory,
        );
        if result.is_err() {
            self.unavailable = true;
            return Err(PolicyError::Journal);
        }
        self.claims.push(claim);
        Ok(Reservation {
            operation: id,
            packet_sha256: facts.packet_sha256.clone(),
            policy_sha256: policy.envelope_sha256.clone(),
            sequence: policy.body.registry_sequence,
            registry_digest: policy.body.registry_digest.clone(),
        })
    }
    /// Call after the real r9 sampler reports unknown/overflow/regression. This
    /// sticky refusal is separate from the already committed Native result.
    pub fn mark_unavailable(&mut self) -> Result<()> {
        self.unavailable = true;
        save_new(
            &self.pinned().join("unavailable.json"),
            &Fault {
                schema: "restricted-node-accounting-fault-v1",
                label: "CPU_ACCOUNTING_UNKNOWN",
            },
            &self.directory,
        )
    }
    /// Called before every existing M06/SQL cancellation fence, before tx.commit.
    /// The operator's current authenticated policy must be supplied by the owner,
    /// never the client. A reload cancels the old request; no postcommit gate exists.
    pub(crate) fn recheck_before_commit(
        &self,
        policy: &VerifiedPolicy,
        reservation: &Reservation,
        facts: &NativeFacts,
        observed_ns: u64,
    ) -> Result<()> {
        self.ready()?;
        policy.check(facts, observed_ns)?;
        require(
            reservation.packet_sha256 == facts.packet_sha256
                && reservation.operation == operation(&self.identity, &facts.packet_sha256)
                && reservation.policy_sha256 == policy.envelope_sha256
                && reservation.sequence == self.anchor_sequence
                && reservation.registry_digest == self.anchor_digest
                && reservation.sequence == policy.body.registry_sequence
                && reservation.registry_digest == policy.body.registry_digest,
            PolicyError::ExternalContext,
        )
    }
}
/// Outside Registry2 request.operation_id and this grant must use this same ID.
/// This does not authenticate Registry2 itself; the protected issuer supplies
/// the already checked complete Registry2 declaration/view context.
pub fn operator_operation_id(context: &Context, packet_sha256: &str) -> Result<String> {
    for h in [
        &context.registry_id,
        &context.operator_id,
        &context.network,
        &context.parameters,
        packet_sha256,
    ] {
        hash_hex(h, 32)?;
    }
    Ok(operation(
        &JournalIdentity {
            schema: MODE.into(),
            registry: context.registry_id.clone(),
            operator: context.operator_id.clone(),
            network: context.network.clone(),
            parameters: context.parameters.clone(),
        },
        packet_sha256,
    ))
}
fn operation(identity: &JournalIdentity, packet_sha256: &str) -> String {
    let mut raw = b"TRNM-RESTRICTED-NODE-OP1".to_vec();
    for value in [
        &identity.registry,
        &identity.operator,
        &identity.network,
        &identity.parameters,
        packet_sha256,
    ] {
        put_text(&mut raw, value);
    }
    // Declaration/view/source epoch deliberately omitted: changing an envelope
    // must not make the same packet eligible for another expensive invocation.
    sha(&raw)
}
fn add(a: &Allocation, b: &Allocation) -> Result<Allocation> {
    let plus = |x: u64, y: u64| x.checked_add(y).ok_or(PolicyError::Budget);
    Ok(Allocation {
        cpu_ns: plus(a.cpu_ns, b.cpu_ns)?,
        material_bytes: plus(a.material_bytes, b.material_bytes)?,
        da_bytes: plus(a.da_bytes, b.da_bytes)?,
        funding_units: plus(a.funding_units, b.funding_units)?,
        reuse_uses: plus(a.reuse_uses, b.reuse_uses)?,
    })
}

#[cfg(test)]
#[path = "operator_task_policy_tests.rs"]
pub(crate) mod tests;
