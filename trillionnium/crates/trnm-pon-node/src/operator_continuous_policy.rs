//! Fresh mode4; a signed view selects already independently signed allocations.
//! No migration, legacy permit, Registry2 per-operation or consensus fallback.
use crate::operator_continuous_history::{Anchor, BumpAuthority, Identity};
use crate::operator_continuous_recipient::{
    self as recipient, Authority, DeclaredBinding, VerifiedAllocation,
};
use crate::operator_mining_policy::SearchIntent;
use crate::operator_task_policy::{MaterialInput, PolicyError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use trnm_crypto_primitives::verify_hex_strict;
type Result<T> = std::result::Result<T, PolicyError>;
pub const MODE: &str = "restricted-owner-node-v4";
const VIEW_DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-TASKVIEW1";
const MAX_BYTES: usize = 65536;
fn check(v: bool, e: PolicyError) -> Result<()> {
    if v {
        Ok(())
    } else {
        Err(e)
    }
}
fn sha(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
fn io<T>(v: std::io::Result<T>) -> Result<T> {
    v.map_err(|_| PolicyError::Journal)
}
fn hex_id(v: &str, n: usize) -> Result<()> {
    check(
        v.len() == 2 * n
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        PolicyError::Input,
    )
}
fn put_text(out: &mut Vec<u8>, v: &str) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v.as_bytes());
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SearchBinding {
    pub operation: String,
    pub intent: SearchIntent,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskView {
    pub schema: String,
    pub identity: Identity,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub actual_parent: String,
    pub actual_generation: u64,
    pub declared_binding: DeclaredBinding,
    pub allocation_envelopes: Vec<String>,
    pub searches: Vec<SearchBinding>,
    pub allowed_transactions: Vec<String>,
    pub issued_ns: u64,
    pub expires_ns: u64,
    pub revoked: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewEnvelope {
    body: TaskView,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewAuthority {
    pub identity: Identity,
    pub expected: TaskView,
    pub envelope_sha256: String,
    pub latest_sequence: u64,
    pub latest_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedAllocationInput {
    pub raw: Vec<u8>,
    pub authority: Authority,
}
/// Only an outside protected configuration can construct these inputs. No
/// anonymous request discovers latest, keys, paths, budget or a view.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub(crate) raw_view: Vec<u8>,
    pub(crate) view_authority: ViewAuthority,
    pub(crate) raw_budget: Option<Vec<u8>>,
    pub(crate) budget_authority: Option<BumpAuthority>,
    pub(crate) allocations: Vec<SignedAllocationInput>,
    pub(crate) journal_path: PathBuf,
    pub(crate) expected_uid: u32,
    pub(crate) expected_journal: Anchor,
    pub(crate) materials: Vec<MaterialInput>,
}
pub(crate) struct VerifiedView {
    pub body: TaskView,
    pub digest: String,
    pub allocations: Vec<Arc<VerifiedAllocation>>,
}
fn message(v: &TaskView, role: u8) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(v).map_err(|_| PolicyError::Input)?;
    check(raw.len() <= MAX_BYTES, PolicyError::Capacity)?;
    let mut out = VIEW_DOMAIN.to_vec();
    out.push(role);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&raw);
    Ok(out)
}
pub(crate) fn authenticate(inputs: &Inputs, now: u64) -> Result<VerifiedView> {
    let raw = &inputs.raw_view;
    let e = &inputs.view_authority;
    check(
        !raw.is_empty()
            && raw.len() <= MAX_BYTES
            && !inputs.allocations.is_empty()
            && inputs.allocations.len() <= 32,
        PolicyError::Capacity,
    )?;
    e.identity.validate()?;
    for h in [&e.envelope_sha256, &e.latest_digest] {
        hex_id(h, 32)?;
    }
    let v: ViewEnvelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    let b = &v.body;
    check(
        b.schema == "restricted-continuous-task-view-v1"
            && b.identity == e.identity
            && *b == e.expected
            && sha(raw) == e.envelope_sha256
            && b.sequence == e.latest_sequence
            && sha(&message(b, 0)?) == e.latest_digest
            && b.sequence > 0
            && b.sequence <= 32768
            && (b.sequence == 1) == b.previous_digest.is_none(),
        PolicyError::ExternalContext,
    )?;
    hex_id(&b.actual_parent, 32)?;
    if let Some(h) = &b.previous_digest {
        hex_id(h, 32)?;
    }
    check(
        !b.revoked
            && b.issued_ns <= now
            && now < b.expires_ns
            && b.expires_ns - b.issued_ns <= 86_400_000_000_000,
        PolicyError::Window,
    )?;
    recipient::declared_binding_digest(&b.declared_binding)?;
    check(
        b.allocation_envelopes.len() == inputs.allocations.len()
            && b.allocation_envelopes.len() <= 32
            && b.allocation_envelopes.windows(2).all(|p| p[0] < p[1])
            && b.allowed_transactions.len() <= 256
            && b.allowed_transactions.windows(2).all(|p| p[0] < p[1])
            && b.searches.len() <= 32,
        PolicyError::Input,
    )?;
    for h in b.allocation_envelopes.iter().chain(&b.allowed_transactions) {
        hex_id(h, 32)?;
    }
    let mut allocations = Vec::new();
    let mut total = 0usize;
    for input in &inputs.allocations {
        total = total
            .checked_add(input.raw.len())
            .ok_or(PolicyError::Capacity)?;
        check(total <= 524288, PolicyError::Capacity)?;
        let permission = recipient::authenticate(&input.raw, &input.authority, now)?;
        let p = permission.body();
        let c = &p.claim;
        check(
            p.identity == b.identity
                && p.declared_binding == b.declared_binding
                && c.parent == b.actual_parent
                && c.generation == b.actual_generation
                && b.issued_ns >= p.issued_ns
                && b.expires_ns <= p.expires_ns
                && b.allocation_envelopes
                    .binary_search(&sha(&input.raw))
                    .is_ok(),
            PolicyError::NativeBinding,
        )?;
        check(
            !allocations.iter().any(|old: &Arc<VerifiedAllocation>| {
                old.claim().operation == c.operation
                    || (old.claim().purpose == c.purpose && old.claim().payload == c.payload)
            }),
            PolicyError::Replay,
        )?;
        allocations.push(Arc::new(permission));
    }
    for (i, s) in b.searches.iter().enumerate() {
        hex_id(&s.operation, 32)?;
        let c = allocations
            .iter()
            .find(|a| a.claim().operation == s.operation && a.claim().purpose == "search")
            .ok_or(PolicyError::NativeBinding)?
            .claim();
        let intent = &s.intent;
        hex_id(&intent.miner, 32)?;
        hex_id(&intent.exact_transactions_sha256, 32)?;
        check(
            intent.exact_group_ids.is_empty()
                && intent.nonce_first > 0
                && intent.nonce_count > 0
                && intent.nonce_count <= 4096
                && intent
                    .nonce_first
                    .checked_add(intent.nonce_count - 1)
                    .is_some()
                && c.payload == crate::operator_mining_policy::search_payload_sha256(intent)?
                && !b.searches[..i]
                    .iter()
                    .any(|old| old.operation == s.operation),
            PolicyError::NativeBinding,
        )?;
    }
    check(
        allocations
            .iter()
            .filter(|a| a.claim().purpose == "search")
            .count()
            == b.searches.len(),
        PolicyError::NativeBinding,
    )?;
    verify_hex_strict(
        &b.identity.registry_key,
        &message(b, 1)?,
        &v.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(&b.identity.task_key, &message(b, 2)?, &v.task_signature)
        .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedView {
        body: v.body,
        digest: e.latest_digest.clone(),
        allocations,
    })
}
impl VerifiedView {
    pub fn permission(&self, purpose: &str, payload: &str) -> Result<Arc<VerifiedAllocation>> {
        self.allocations
            .iter()
            .find(|a| a.claim().purpose == purpose && a.claim().payload == payload)
            .cloned()
            .ok_or(PolicyError::NativeBinding)
    }
    pub fn check_window(&self, now: u64) -> Result<()> {
        check(
            !self.body.revoked && self.body.issued_ns <= now && now < self.body.expires_ns,
            PolicyError::Window,
        )
    }
    pub fn marker(&self, journal: &Path) -> Result<Vec<u8>> {
        check(journal.is_absolute(), PolicyError::Input)?;
        serde_json::to_vec(&(
            MODE,
            &self.body.identity,
            journal.to_string_lossy().as_ref(),
        ))
        .map_err(|_| PolicyError::Input)
    }
    pub fn next(&self, old: &Self) -> bool {
        self.body.identity == old.body.identity
            && self.body.declared_binding == old.body.declared_binding
            && self.body.sequence == old.body.sequence.checked_add(1).unwrap_or(0)
            && self.body.previous_digest.as_deref() == Some(old.digest.as_str())
    }
    pub fn check_transactions(&self, raws: &[Vec<u8>]) -> Result<()> {
        crate::operator_mining_policy::transactions_sha256(raws)?;
        check(
            raws.iter().all(|raw| {
                self.body
                    .allowed_transactions
                    .binary_search(&sha(raw))
                    .is_ok()
            }),
            PolicyError::NativeBinding,
        )
    }
}
#[derive(Clone)]
pub(crate) struct Permit {
    pub view: Arc<VerifiedView>,
    pub allocation: Arc<VerifiedAllocation>,
    pub epoch: Arc<AtomicU64>,
    pub expected_epoch: u64,
    pub unavailable: Arc<AtomicBool>,
}
impl Permit {
    pub fn progress(&self) -> Result<()> {
        check(
            !self.unavailable.load(Ordering::Acquire)
                && self.epoch.load(Ordering::Acquire) == self.expected_epoch,
            PolicyError::CpuUnknown,
        )?;
        let now = crate::operator_task_policy::now_ns()?;
        self.view.check_window(now)?;
        check(
            now >= self.allocation.body().issued_ns && now < self.allocation.body().expires_ns,
            PolicyError::Window,
        )
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
                same_meta_continuous(&io(file.metadata())?) == *identity
                    && same_meta_continuous(&io(fs::symlink_metadata(path))?) == *identity,
                PolicyError::NativeBinding,
            )?;
        }
        Ok(())
    }
    pub(crate) fn recheck(&self, inputs: &Inputs, view: &VerifiedView) -> Result<()> {
        check(
            self.catalog_sha256 == view.body.declared_binding.task.full_material_catalog
                && inputs.materials.len() == self.rows.len(),
            PolicyError::NativeBinding,
        )?;
        let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
        for (row, (path, file, identity)) in inputs.materials.iter().zip(&self.rows) {
            check(
                &row.path == path
                    && row.bytes == identity.2
                    && same_meta_continuous(&io(file.metadata())?) == *identity
                    && same_meta_continuous(&io(fs::symlink_metadata(path))?) == *identity,
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
        permit.allocation.claim().purpose == "startup-catalog",
        PolicyError::ExternalContext,
    )?;
    let permission = permit.allocation.claim();
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
                row.sha256 == permit.view.body.declared_binding.task.model_material,
                PolicyError::NativeBinding,
            )?;
        }
        if role == "input" {
            check(
                row.sha256 == permit.view.body.declared_binding.task.input_material,
                PolicyError::NativeBinding,
            )?;
        }
        put_text(&mut catalog, role);
        catalog.extend_from_slice(&row.bytes.to_le_bytes());
        put_text(&mut catalog, &row.sha256);
        held_rows.push((row.path.clone(), file, same_meta_continuous(&before)));
    }
    check(
        sha(&catalog) == permit.view.body.declared_binding.task.full_material_catalog,
        PolicyError::NativeBinding,
    )?;
    Ok(HeldCatalog {
        rows: held_rows,
        roles: ROLES.iter().map(|r| (*r).to_owned()).collect(),
        catalog_sha256: sha(&catalog),
    })
}

fn same_meta_continuous(m: &fs::Metadata) -> HeldMaterialIdentity {
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

pub(crate) fn validate_protected_inputs(
    inputs: &Inputs,
    registry_key: &str,
    task_key: &str,
    source_commit: &str,
    node_policy_source: &str,
    registry2_package: &str,
) -> Result<()> {
    let identity = &inputs.view_authority.identity;
    identity.validate()?;
    check(
        identity.registry_key == registry_key
            && identity.task_key == task_key
            && identity.source_commit == source_commit
            && identity.node_policy_source == node_policy_source
            && identity.registry2_package == registry2_package,
        PolicyError::ExternalContext,
    )?;
    check(
        inputs.view_authority.expected.identity == *identity
            && inputs.expected_uid == rustix::process::geteuid().as_raw()
            && inputs.journal_path.is_absolute(),
        PolicyError::ExternalContext,
    )?;
    if let Some(authority) = &inputs.budget_authority {
        check(
            authority.identity == *identity && authority.expected.identity == *identity,
            PolicyError::ExternalContext,
        )?;
    }
    check(
        inputs.allocations.iter().all(|input| {
            input.authority.identity == *identity && input.authority.expected.identity == *identity
        }),
        PolicyError::ExternalContext,
    )
}

#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_policy_tests.rs"]
pub(crate) mod tests;
