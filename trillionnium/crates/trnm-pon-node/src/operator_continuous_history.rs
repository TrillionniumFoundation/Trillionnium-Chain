//! Candidate mode4 retained owner history. No Work/State/ledger capability.
//! Same-operator declarations are not balances, source truth or mining hardness.
use crate::operator_task_policy::{Allocation, PolicyError};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use trnm_crypto_primitives::verify_hex_strict;
type Result<T> = std::result::Result<T, PolicyError>;
pub(crate) const MAX_CLAIMS: usize = 32768;
pub(crate) const MAX_ROWS: usize = 131072;
pub(crate) const MAX_JOURNAL_BYTES: u64 = 192 * 1024 * 1024;
const MAX_ROW_BYTES: u64 = 65536;
const MAX_BUDGET_KEYS: usize = 256;
const FAULT_HEADROOM_BYTES: u64 = 1024;
const BUMP_DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-BUDGET1";
fn check(ok: bool, error: PolicyError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn io<T>(v: std::io::Result<T>) -> Result<T> {
    v.map_err(|_| PolicyError::Journal)
}
fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn id(value: &str) -> Result<()> {
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        PolicyError::Input,
    )
}
fn zero_allocation() -> Allocation {
    Allocation {
        cpu_ns: 0,
        material_bytes: 0,
        da_bytes: 0,
        funding_units: 0,
        reuse_uses: 0,
    }
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
fn within(a: &Allocation, b: &Allocation) -> bool {
    a.cpu_ns <= b.cpu_ns
        && a.material_bytes <= b.material_bytes
        && a.da_bytes <= b.da_bytes
        && a.funding_units <= b.funding_units
        && a.reuse_uses <= b.reuse_uses
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub schema: String,
    pub registry: String,
    pub operator: String,
    pub network: String,
    pub parameters: String,
    pub source_commit: String,
    pub node_policy_source: String,
    pub registry2_package: String,
    pub registry_key: String,
    pub task_key: String,
    pub recipient_node: String,
    pub global_allocator: String,
}
impl Identity {
    pub(crate) fn validate(&self) -> Result<()> {
        check(
            self.schema == "restricted-continuous-identity-v1",
            PolicyError::Input,
        )?;
        for v in [
            &self.registry,
            &self.operator,
            &self.network,
            &self.parameters,
            &self.node_policy_source,
            &self.registry2_package,
            &self.registry_key,
            &self.task_key,
            &self.recipient_node,
            &self.global_allocator,
        ] {
            id(v)?;
        }
        check(
            self.source_commit.len() == 40
                && self
                    .source_commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && self.registry_key != self.task_key,
            PolicyError::ExternalContext,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Anchor {
    pub sequence: u64,
    pub digest: String,
}
impl Anchor {
    pub(crate) fn empty() -> Self {
        Self {
            sequence: 0,
            digest: "00".repeat(32),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Usage {
    pub operations: u64,
    pub allocation: Allocation,
    pub actual_cpu_ns: u64,
}
impl Usage {
    fn zero() -> Self {
        Self {
            operations: 0,
            allocation: zero_allocation(),
            actual_cpu_ns: 0,
        }
    }
    fn claim(&self, a: &Allocation) -> Result<Self> {
        Ok(Self {
            operations: self.operations.checked_add(1).ok_or(PolicyError::Budget)?,
            allocation: add(&self.allocation, a)?,
            actual_cpu_ns: self.actual_cpu_ns,
        })
    }
    fn cpu(&self, n: u64) -> Result<Self> {
        let mut out = self.clone();
        out.actual_cpu_ns = out
            .actual_cpu_ns
            .checked_add(n)
            .ok_or(PolicyError::CpuUnknown)?;
        Ok(out)
    }
    fn within(&self, limit: &Self) -> bool {
        self.operations <= limit.operations
            && within(&self.allocation, &limit.allocation)
            && self.actual_cpu_ns <= limit.actual_cpu_ns
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ceilings {
    pub global: Usage,
    pub tasks: BTreeMap<String, Usage>,
    pub classes: BTreeMap<String, Usage>,
}
impl Ceilings {
    pub(crate) fn validate(&self) -> Result<()> {
        check(
            self.tasks.len() <= MAX_BUDGET_KEYS
                && !self.tasks.is_empty()
                && self.classes.len() <= 3
                && !self.classes.is_empty(),
            PolicyError::Capacity,
        )?;
        for (k, v) in &self.tasks {
            id(k)?;
            check(v.operations > 0 && v.actual_cpu_ns > 0, PolicyError::Budget)?;
        }
        for (k, v) in &self.classes {
            check(
                matches!(k.as_str(), "dense" | "structured" | "zero")
                    && v.operations > 0
                    && v.actual_cpu_ns > 0,
                PolicyError::Budget,
            )?;
        }
        check(
            self.global.operations > 0 && self.global.actual_cpu_ns > 0,
            PolicyError::Budget,
        )
    }
    fn grows(&self, old: &Self) -> bool {
        old.global.within(&self.global)
            && old
                .tasks
                .iter()
                .all(|(k, v)| self.tasks.get(k).is_some_and(|n| v.within(n)))
            && old
                .classes
                .iter()
                .all(|(k, v)| self.classes.get(k).is_some_and(|n| v.within(n)))
    }
}
/// Projection of the FULL original Registry2 context, never an issuer-selected
/// partial context. Original admission/claim occurs outside, once per budget.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryContext {
    pub registry_id: String,
    pub operator_id: String,
    pub network: String,
    pub parameters: String,
    pub source_commit: String,
    pub consumer_source_package: String,
    pub native_admitter_source: String,
    pub actual_parent: String,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryBudget {
    pub max_operations: u64,
    pub max_cpu_ns: u64,
    pub max_material_bytes: u64,
    pub max_da_bytes: u64,
    pub max_funding_units: u64,
    pub max_reuse_uses: u64,
}
/// New-domain delegation. These hashes bind Root's independently closed complete
/// original admission and durable claim. Rust does not pretend to rerun that
/// Python admission, authenticate balances or grant original per-op permission.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryDelegation {
    pub schema: String,
    pub registry2_admission_package_sha256: String,
    pub registry2_admission_receipt_sha256: String,
    pub registry2_view_sequence: u64,
    pub registry2_view_digest: String,
    pub registry2_declaration_digest: String,
    pub registry2_request_digest: String,
    pub registry2_claim_sha256: String,
    pub registry2_operation: String,
    pub context: RegistryContext,
    pub declared_binding: crate::operator_continuous_recipient::DeclaredBinding,
    pub allowed_purposes: Vec<String>,
    pub recipient_nodes: Vec<String>,
    pub global_allocator: String,
    pub allocator_latest: Anchor,
    pub nonce_first: u64,
    pub nonce_last: u64,
    pub not_before_ns: u64,
    pub expires_ns: u64,
    pub budget: RegistryBudget,
    pub admitted_allocation: Allocation,
}
impl RegistryDelegation {
    fn validate(&self, identity: &Identity, body: &BudgetIncrease) -> Result<()> {
        check(
            self.schema == "restricted-continuous-registry2-budget-delegation-v1",
            PolicyError::Input,
        )?;
        for h in [
            &self.registry2_admission_package_sha256,
            &self.registry2_admission_receipt_sha256,
            &self.registry2_view_digest,
            &self.registry2_declaration_digest,
            &self.registry2_request_digest,
            &self.registry2_claim_sha256,
            &self.registry2_operation,
            &self.global_allocator,
            &self.allocator_latest.digest,
        ] {
            id(h)?;
        }
        let c = &self.context;
        for h in [
            &c.registry_id,
            &c.operator_id,
            &c.network,
            &c.parameters,
            &c.consumer_source_package,
            &c.native_admitter_source,
            &c.actual_parent,
        ] {
            id(h)?;
        }
        check(
            c.consumer_source_package == identity.registry2_package
                && self.registry2_admission_package_sha256 == identity.registry2_package
                && c.registry_id == identity.registry
                && c.operator_id == identity.operator
                && c.network == identity.network
                && c.parameters == identity.parameters
                && c.source_commit == identity.source_commit
                && c.native_admitter_source == identity.node_policy_source
                && c.scope == "same-operator-declared-task-permission-no-consensus-or-reward-v1"
                && self.global_allocator == identity.global_allocator
                && self.registry2_view_sequence > 0,
            PolicyError::ExternalContext,
        )?;
        crate::operator_continuous_recipient::declared_binding_digest(&self.declared_binding)?;
        check(
            !self.allowed_purposes.is_empty()
                && self.allowed_purposes.len() <= 7
                && self.allowed_purposes.windows(2).all(|p| p[0] < p[1])
                && self.allowed_purposes.iter().all(|p| {
                    matches!(
                        p.as_str(),
                        "startup-catalog"
                            | "parent-reconcile"
                            | "search"
                            | "winner-validation"
                            | "activate"
                            | "receiver-validation"
                            | "receiver-activate"
                    )
                }),
            PolicyError::Input,
        )?;
        check(
            !self.recipient_nodes.is_empty()
                && self.recipient_nodes.len() <= 3
                && self.recipient_nodes.windows(2).all(|p| p[0] < p[1])
                && self
                    .recipient_nodes
                    .iter()
                    .any(|p| p == &identity.recipient_node),
            PolicyError::ExternalContext,
        )?;
        for h in &self.recipient_nodes {
            id(h)?;
        }
        check(
            self.nonce_first > 0
                && self.nonce_first <= self.nonce_last
                && self.not_before_ns <= body.issued_ns
                && body.expires_ns <= self.expires_ns
                && self.not_before_ns < self.expires_ns,
            PolicyError::Window,
        )?;
        let b = &self.budget;
        let authorized = Allocation {
            cpu_ns: b.max_cpu_ns,
            material_bytes: b.max_material_bytes,
            da_bytes: b.max_da_bytes,
            funding_units: b.max_funding_units,
            reuse_uses: b.max_reuse_uses,
        };
        check(
            b.max_operations > 0
                && body.ceilings.global.operations <= b.max_operations
                && within(&body.ceilings.global.allocation, &authorized)
                && body.ceilings.global.actual_cpu_ns <= b.max_cpu_ns
                && within(&self.admitted_allocation, &authorized),
            PolicyError::Budget,
        )?;
        check(
            self.declared_binding.preprocessing != "forbidden" || b.max_reuse_uses == 0,
            PolicyError::Budget,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BudgetIncrease {
    pub schema: String,
    pub identity: Identity,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub exact_prior_journal: Anchor,
    pub exact_usage_digest: String,
    pub ceilings: Ceilings,
    pub issued_ns: u64,
    pub expires_ns: u64,
    pub revoked: bool,
    pub delegation: RegistryDelegation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BumpEnvelope {
    body: BudgetIncrease,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BumpAuthority {
    pub identity: Identity,
    pub expected: BudgetIncrease,
    pub envelope_sha256: String,
    pub latest_sequence: u64,
    pub latest_digest: String,
}
pub(crate) struct VerifiedBump {
    body: BudgetIncrease,
    digest: String,
}
fn bump_message(v: &BudgetIncrease, role: u8) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(v).map_err(|_| PolicyError::Input)?;
    check(raw.len() <= MAX_ROW_BYTES as usize, PolicyError::Capacity)?;
    let mut out = BUMP_DOMAIN.to_vec();
    out.push(role);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&raw);
    Ok(out)
}
pub(crate) fn authenticate_bump(
    raw: &[u8],
    outside: &BumpAuthority,
    now: u64,
) -> Result<VerifiedBump> {
    check(
        !raw.is_empty() && raw.len() <= MAX_ROW_BYTES as usize,
        PolicyError::Capacity,
    )?;
    outside.identity.validate()?;
    id(&outside.envelope_sha256)?;
    id(&outside.latest_digest)?;
    let e: BumpEnvelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    check(
        e.body.schema == "restricted-continuous-budget-increase-v1"
            && e.body == outside.expected
            && e.body.identity == outside.identity
            && digest(raw) == outside.envelope_sha256
            && e.body.sequence == outside.latest_sequence
            && digest(&bump_message(&e.body, 0)?) == outside.latest_digest,
        PolicyError::ExternalContext,
    )?;
    check(
        e.body.sequence > 0
            && e.body.issued_ns <= now
            && now < e.body.expires_ns
            && e.body.expires_ns - e.body.issued_ns <= 86_400_000_000_000,
        PolicyError::Window,
    )?;
    check(
        (e.body.sequence == 1) == e.body.previous_digest.is_none(),
        PolicyError::Input,
    )?;
    if let Some(h) = &e.body.previous_digest {
        id(h)?;
    }
    id(&e.body.exact_usage_digest)?;
    id(&e.body.exact_prior_journal.digest)?;
    e.body.ceilings.validate()?;
    e.body.delegation.validate(&outside.identity, &e.body)?;
    verify_hex_strict(
        &outside.identity.registry_key,
        &bump_message(&e.body, 1)?,
        &e.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(
        &outside.identity.task_key,
        &bump_message(&e.body, 2)?,
        &e.task_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedBump {
        body: e.body,
        digest: outside.latest_digest.clone(),
    })
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    pub operation: String,
    pub operation_nonce: String,
    pub purpose: String,
    pub payload: String,
    pub parent: String,
    pub generation: u64,
    pub native_task: String,
    pub instance_class: String,
    pub task_binding: String,
    pub allocation: Allocation,
    pub global_allocation_id: String,
    pub global_allocation_sequence: u64,
}
impl Claim {
    pub(crate) fn validate(&self) -> Result<()> {
        for v in [
            &self.operation,
            &self.operation_nonce,
            &self.payload,
            &self.parent,
            &self.native_task,
            &self.task_binding,
            &self.global_allocation_id,
        ] {
            id(v)?;
        }
        check(
            matches!(
                self.instance_class.as_str(),
                "dense" | "structured" | "zero"
            ) && matches!(
                self.purpose.as_str(),
                "startup-catalog"
                    | "parent-reconcile"
                    | "search"
                    | "winner-validation"
                    | "activate"
                    | "receiver-validation"
                    | "receiver-activate"
            ) && self.global_allocation_sequence > 0
                && self.allocation.cpu_ns > 0
                && self.allocation.material_bytes > 0
                && self.allocation.material_bytes <= 512 << 20
                && self.allocation.da_bytes >= self.allocation.material_bytes
                && self.allocation.da_bytes <= 512 << 20
                && self.allocation.funding_units > 0,
            PolicyError::Input,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Budget {
        body: Box<BudgetIncrease>,
        digest: String,
    },
    Claim {
        body: Box<Claim>,
    },
    View {
        sequence: u64,
        digest: String,
        previous: Option<String>,
        parent: String,
        generation: u64,
    },
    SearchResult {
        operation: String,
        packet: Option<String>,
        parent: String,
        generation: u64,
        trials: u64,
    },
    CpuStarted {
        scope: String,
        operation: String,
        task: String,
        class: String,
    },
    CpuLinked {
        scope: String,
        operation: String,
    },
    CpuSettled {
        scope: String,
        owner_cpu_ns: u64,
        scoped_cpu_ns: u64,
        total_cpu_ns: u64,
        live_paid_ns: u64,
        residual_ns: u64,
        spawned: u64,
        started: u64,
        finished: u64,
        known: u64,
    },
    ControlFrame {
        sha256: String,
    },
    CleanClose {
        parent: String,
        generation: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    sequence: u64,
    previous: String,
    event: Event,
}
#[derive(Clone)]
struct Scope {
    task: String,
    class: String,
    operations: Vec<String>,
    started_record_sha256: String,
    settlement: Option<ScopeTotals>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ScopeTotals {
    settled_record_sha256: String,
    owner_cpu_ns: u64,
    scoped_worker_cpu_ns: u64,
    total_cpu_ns: u64,
    live_paid_cpu_ns: u64,
    residual_cpu_ns: u64,
    spawned: u64,
    started: u64,
    finished: u64,
    known: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeReceipt {
    pub schema: String,
    pub identity: Identity,
    pub scope: String,
    pub native_task: String,
    pub instance_class: String,
    pub linked_operations: Vec<String>,
    pub started_record_sha256: String,
    pub settled_record_sha256: String,
    pub owner_cpu_ns: u64,
    pub scoped_worker_cpu_ns: u64,
    pub total_cpu_ns: u64,
    pub live_paid_cpu_ns: u64,
    pub residual_cpu_ns: u64,
    pub spawned: u64,
    pub started: u64,
    pub finished: u64,
    pub known: u64,
    pub journal_head: Anchor,
}
#[derive(Default)]
struct Index {
    claims: HashMap<String, Claim>,
    scopes: HashMap<String, Scope>,
    operation_scopes: HashMap<String, String>,
    pending_scopes: usize,
    results: HashMap<String, (Option<String>, String, u64)>,
    tasks: HashMap<String, Usage>,
    classes: HashMap<String, Usage>,
    global: Option<Usage>,
    ceilings: Option<Ceilings>,
    budget_sequence: u64,
    budget_digest: Option<String>,
    revoked: bool,
    view_sequence: u64,
    view_digest: Option<String>,
    last_clean: bool,
    control_frames: u64,
    delegation: Option<RegistryDelegation>,
}
// Only a small pending mutation is built. No full-index clone/full-history scan per operation.
enum Update {
    Budget(Ceilings, u64, String, bool, Box<RegistryDelegation>),
    Claim(Claim, Usage, Usage, Usage),
    View(u64, String),
    Result(String, Option<String>, String, u64),
    Started(String, Scope),
    Linked(String, String),
    Settled(String, Usage, Usage, Usage, ScopeTotals),
    Frame,
    Closed,
}
impl Index {
    fn usage_digest(&self) -> Result<String> {
        let tasks: BTreeMap<_, _> = self.tasks.iter().collect();
        let classes: BTreeMap<_, _> = self.classes.iter().collect();
        let raw = serde_json::to_vec(&(
            self.global.clone().unwrap_or_else(Usage::zero),
            tasks,
            classes,
        ))
        .map_err(|_| PolicyError::Journal)?;
        Ok(digest(&raw))
    }
    fn ready(&self) -> Result<()> {
        check(!self.revoked, PolicyError::Revoked)?;
        check(self.ceilings.is_some(), PolicyError::Budget)
    }
    fn totals(&self, task: &str, class: &str) -> (Usage, Usage, Usage) {
        (
            self.global.clone().unwrap_or_else(Usage::zero),
            self.tasks.get(task).cloned().unwrap_or_else(Usage::zero),
            self.classes.get(class).cloned().unwrap_or_else(Usage::zero),
        )
    }
    fn prepare(&self, event: &Event, anchor: &Anchor, identity: &Identity) -> Result<Update> {
        match event {
            Event::Budget { body, digest: h } => {
                check(
                    !self.revoked
                        && body.identity == *identity
                        && body.exact_prior_journal == *anchor
                        && body.exact_usage_digest == self.usage_digest()?
                        && body.sequence
                            == self
                                .budget_sequence
                                .checked_add(1)
                                .ok_or(PolicyError::Capacity)?
                        && body.previous_digest == self.budget_digest,
                    PolicyError::ExternalContext,
                )?;
                body.ceilings.validate()?;
                body.delegation.validate(identity, body)?;
                id(h)?;
                if let Some(old) = &self.ceilings {
                    check(body.ceilings.grows(old), PolicyError::Budget)?;
                    let old_delegation = self
                        .delegation
                        .as_ref()
                        .ok_or(PolicyError::ExternalContext)?;
                    check(
                        body.delegation.context == old_delegation.context
                            && body.delegation.declared_binding == old_delegation.declared_binding
                            && body.delegation.global_allocator == old_delegation.global_allocator
                            && body.delegation.recipient_nodes == old_delegation.recipient_nodes
                            && body.delegation.allowed_purposes == old_delegation.allowed_purposes
                            && body.delegation.registry2_declaration_digest
                                == old_delegation.registry2_declaration_digest
                            && body.delegation.registry2_operation
                                != old_delegation.registry2_operation
                            && body.delegation.registry2_claim_sha256
                                != old_delegation.registry2_claim_sha256,
                        PolicyError::ExternalContext,
                    )?;
                    let prior = &old.global.allocation;
                    let next = &body.ceilings.global.allocation;
                    let delta = Allocation {
                        cpu_ns: next
                            .cpu_ns
                            .checked_sub(prior.cpu_ns)
                            .ok_or(PolicyError::Budget)?,
                        material_bytes: next
                            .material_bytes
                            .checked_sub(prior.material_bytes)
                            .ok_or(PolicyError::Budget)?,
                        da_bytes: next
                            .da_bytes
                            .checked_sub(prior.da_bytes)
                            .ok_or(PolicyError::Budget)?,
                        funding_units: next
                            .funding_units
                            .checked_sub(prior.funding_units)
                            .ok_or(PolicyError::Budget)?,
                        reuse_uses: next
                            .reuse_uses
                            .checked_sub(prior.reuse_uses)
                            .ok_or(PolicyError::Budget)?,
                    };
                    check(
                        within(&delta, &body.delegation.admitted_allocation),
                        PolicyError::Budget,
                    )?;
                } else {
                    check(
                        within(
                            &body.ceilings.global.allocation,
                            &body.delegation.admitted_allocation,
                        ),
                        PolicyError::Budget,
                    )?;
                }
                check(
                    self.global
                        .clone()
                        .unwrap_or_else(Usage::zero)
                        .within(&body.ceilings.global)
                        && self
                            .tasks
                            .iter()
                            .all(|(k, v)| body.ceilings.tasks.get(k).is_some_and(|n| v.within(n)))
                        && self.classes.iter().all(|(k, v)| {
                            body.ceilings.classes.get(k).is_some_and(|n| v.within(n))
                        }),
                    PolicyError::Budget,
                )?;
                Ok(Update::Budget(
                    body.ceilings.clone(),
                    body.sequence,
                    h.clone(),
                    body.revoked,
                    Box::new(body.delegation.clone()),
                ))
            }
            Event::Claim { body: c } => {
                self.ready()?;
                c.validate()?;
                let d = self
                    .delegation
                    .as_ref()
                    .ok_or(PolicyError::ExternalContext)?;
                check(
                    c.native_task == d.declared_binding.task.native_task
                        && c.instance_class == d.declared_binding.instance_class
                        && c.task_binding
                            == crate::operator_continuous_recipient::declared_binding_digest(
                                &d.declared_binding,
                            )?
                        && d.allowed_purposes.iter().any(|p| p == &c.purpose),
                    PolicyError::NativeBinding,
                )?;
                check(
                    c.operation == crate::operator_continuous_recipient::operation_id(identity, c)?,
                    PolicyError::NativeBinding,
                )?;
                check(self.claims.len() < MAX_CLAIMS, PolicyError::Capacity)?;
                check(!self.claims.contains_key(&c.operation), PolicyError::Replay)?;
                let (g, t, k) = self.totals(&c.native_task, &c.instance_class);
                let (g, t, k) = (
                    g.claim(&c.allocation)?,
                    t.claim(&c.allocation)?,
                    k.claim(&c.allocation)?,
                );
                let lim = self.ceilings.as_ref().ok_or(PolicyError::Budget)?;
                check(
                    g.within(&lim.global)
                        && lim.tasks.get(&c.native_task).is_some_and(|n| t.within(n))
                        && lim
                            .classes
                            .get(&c.instance_class)
                            .is_some_and(|n| k.within(n)),
                    PolicyError::Budget,
                )?;
                Ok(Update::Claim((**c).clone(), g, t, k))
            }
            Event::View {
                sequence,
                digest: h,
                previous,
                parent,
                generation: _,
            } => {
                self.ready()?;
                id(h)?;
                id(parent)?;
                check(
                    *sequence <= MAX_CLAIMS as u64
                        && *sequence
                            == self
                                .view_sequence
                                .checked_add(1)
                                .ok_or(PolicyError::Capacity)?
                        && *previous == self.view_digest,
                    PolicyError::ExternalContext,
                )?;
                Ok(Update::View(*sequence, h.clone()))
            }
            Event::SearchResult {
                operation,
                packet,
                parent,
                generation,
                trials,
            } => {
                check(
                    *trials <= 4096
                        && self.results.len() < MAX_CLAIMS
                        && !self.results.contains_key(operation),
                    PolicyError::Capacity,
                )?;
                let c = self
                    .claims
                    .get(operation)
                    .ok_or(PolicyError::NativeBinding)?;
                check(
                    c.purpose == "search" && c.parent == *parent && c.generation == *generation,
                    PolicyError::NativeBinding,
                )?;
                if let Some(h) = packet {
                    id(h)?;
                    check(*trials > 0, PolicyError::Input)?;
                }
                Ok(Update::Result(
                    operation.clone(),
                    packet.clone(),
                    parent.clone(),
                    *generation,
                ))
            }
            Event::CpuStarted {
                scope,
                operation,
                task,
                class,
            } => {
                self.ready()?;
                id(scope)?;
                check(
                    self.scopes.len() < MAX_CLAIMS && !self.scopes.contains_key(scope),
                    PolicyError::Replay,
                )?;
                let c = self
                    .claims
                    .get(operation)
                    .ok_or(PolicyError::NativeBinding)?;
                check(
                    c.native_task == *task
                        && c.instance_class == *class
                        && !self.operation_scopes.contains_key(operation),
                    PolicyError::NativeBinding,
                )?;
                Ok(Update::Started(
                    scope.clone(),
                    Scope {
                        task: task.clone(),
                        class: class.clone(),
                        operations: vec![operation.clone()],
                        started_record_sha256: String::new(),
                        settlement: None,
                    },
                ))
            }
            Event::CpuLinked { scope, operation } => {
                let s = self.scopes.get(scope).ok_or(PolicyError::Journal)?;
                let c = self
                    .claims
                    .get(operation)
                    .ok_or(PolicyError::NativeBinding)?;
                check(
                    s.settlement.is_none()
                        && s.operations.len() == 1
                        && c.native_task == s.task
                        && c.instance_class == s.class
                        && self.claims.get(&s.operations[0]).is_some_and(|old| {
                            ((old.purpose == "startup-catalog" && c.purpose == "parent-reconcile")
                                || (old.purpose == "receiver-validation"
                                    && c.purpose == "receiver-activate"))
                                && old.parent == c.parent
                                && old.generation == c.generation
                                && old.native_task == c.native_task
                                && old.task_binding == c.task_binding
                                && (old.purpose == "startup-catalog" || old.payload == c.payload)
                        })
                        && !self.operation_scopes.contains_key(operation),
                    PolicyError::NativeBinding,
                )?;
                Ok(Update::Linked(scope.clone(), operation.clone()))
            }
            Event::CpuSettled {
                scope,
                owner_cpu_ns,
                scoped_cpu_ns,
                total_cpu_ns,
                live_paid_ns,
                residual_ns,
                spawned,
                started,
                finished,
                known,
            } => {
                let s = self.scopes.get(scope).ok_or(PolicyError::Journal)?;
                check(
                    s.settlement.is_none()
                        && owner_cpu_ns.checked_add(*scoped_cpu_ns) == Some(*total_cpu_ns)
                        && live_paid_ns.checked_add(*residual_ns) == Some(*total_cpu_ns)
                        && spawned == started
                        && started == finished
                        && finished == known,
                    PolicyError::CpuUnknown,
                )?;
                let (g, t, k) = self.totals(&s.task, &s.class);
                // Preserve the real known total even if it crossed its ceiling: later claims fail.
                Ok(Update::Settled(
                    scope.clone(),
                    g.cpu(*total_cpu_ns)?,
                    t.cpu(*total_cpu_ns)?,
                    k.cpu(*total_cpu_ns)?,
                    ScopeTotals {
                        settled_record_sha256: String::new(),
                        owner_cpu_ns: *owner_cpu_ns,
                        scoped_worker_cpu_ns: *scoped_cpu_ns,
                        total_cpu_ns: *total_cpu_ns,
                        live_paid_cpu_ns: *live_paid_ns,
                        residual_cpu_ns: *residual_ns,
                        spawned: *spawned,
                        started: *started,
                        finished: *finished,
                        known: *known,
                    },
                ))
            }
            Event::ControlFrame { sha256 } => {
                id(sha256)?;
                check(self.control_frames < 65536, PolicyError::Capacity)?;
                Ok(Update::Frame)
            }
            Event::CleanClose {
                parent,
                generation: _,
            } => {
                id(parent)?;
                check(self.pending_scopes == 0, PolicyError::CpuUnknown)?;
                Ok(Update::Closed)
            }
        }
    }
    fn apply(&mut self, u: Update, record_sha256: &str) {
        self.last_clean = false;
        match u {
            Update::Budget(c, n, h, revoked, d) => {
                self.ceilings = Some(c);
                self.budget_sequence = n;
                self.budget_digest = Some(h);
                self.revoked = revoked;
                self.delegation = Some(*d);
            }
            Update::Claim(c, g, t, k) => {
                self.tasks.insert(c.native_task.clone(), t);
                self.classes.insert(c.instance_class.clone(), k);
                self.global = Some(g);
                self.claims.insert(c.operation.clone(), c);
            }
            Update::View(n, h) => {
                self.view_sequence = n;
                self.view_digest = Some(h);
            }
            Update::Result(op, p, parent, generation) => {
                self.results.insert(op, (p, parent, generation));
            }
            Update::Started(scope, mut s) => {
                s.started_record_sha256 = record_sha256.to_owned();
                self.operation_scopes
                    .insert(s.operations[0].clone(), scope.clone());
                self.pending_scopes += 1;
                self.scopes.insert(scope, s);
            }
            Update::Linked(scope, op) => {
                self.operation_scopes.insert(op.clone(), scope.clone());
                if let Some(s) = self.scopes.get_mut(&scope) {
                    s.operations.push(op);
                }
            }
            Update::Settled(scope, g, t, k, mut totals) => {
                totals.settled_record_sha256 = record_sha256.to_owned();
                if let Some(s) = self.scopes.get_mut(&scope) {
                    self.tasks.insert(s.task.clone(), t);
                    self.classes.insert(s.class.clone(), k);
                    self.global = Some(g);
                    s.settlement = Some(totals);
                    self.pending_scopes -= 1;
                }
            }
            Update::Frame => self.control_frames += 1,
            Update::Closed => self.last_clean = true,
        }
    }
}
fn metadata(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
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
fn read_held(path: &Path, uid: u32) -> Result<Vec<u8>> {
    let before = io(fs::symlink_metadata(path))?;
    check(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == uid
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600
            && before.len() > 0
            && before.len() <= MAX_ROW_BYTES,
        PolicyError::Journal,
    )?;
    let mut f = io(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path))?;
    let mut raw = Vec::new();
    io((&mut f).take(MAX_ROW_BYTES + 1).read_to_end(&mut raw))?;
    check(
        metadata(&before) == metadata(&io(f.metadata())?)
            && metadata(&before) == metadata(&io(fs::symlink_metadata(path))?)
            && raw.len() as u64 == before.len(),
        PolicyError::Journal,
    )?;
    Ok(raw)
}
fn write_exclusive(path: &Path, raw: &[u8], dir: &File) -> Result<()> {
    check(
        !raw.is_empty() && raw.len() <= MAX_ROW_BYTES as usize,
        PolicyError::Capacity,
    )?;
    let mut f = io(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path))?;
    io(f.write_all(raw))?;
    io(f.sync_all())?;
    let a = io(f.metadata())?;
    let b = io(fs::symlink_metadata(path))?;
    check(
        a.is_file()
            && a.nlink() == 1
            && a.mode() & 0o7777 == 0o600
            && a.len() == raw.len() as u64
            && metadata(&a) == metadata(&b),
        PolicyError::Journal,
    )?;
    io(dir.sync_all())
}
pub(crate) struct Journal {
    path: PathBuf,
    directory: File,
    lock: File,
    uid: u32,
    identity: Identity,
    anchor: Anchor,
    bytes: u64,
    index: Index,
    unavailable: Arc<AtomicBool>,
    clean_restart_issued: bool,
}
impl Journal {
    pub(crate) fn open(
        path: &Path,
        uid: u32,
        outside_identity: &Identity,
        expected_latest: &Anchor,
    ) -> Result<Self> {
        outside_identity.validate()?;
        id(&expected_latest.digest)?;
        check(
            cfg!(target_os = "linux") && path.is_absolute(),
            PolicyError::Unsupported,
        )?;
        let visible = io(fs::symlink_metadata(path))?;
        check(
            visible.is_dir()
                && !visible.file_type().is_symlink()
                && visible.uid() == uid
                && visible.mode() & 0o7777 == 0o700,
            PolicyError::Journal,
        )?;
        let directory = io(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path))?;
        let held = io(directory.metadata())?;
        check(
            visible.dev() == held.dev() && visible.ino() == held.ino(),
            PolicyError::Journal,
        )?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let lock_path = pinned.join("owner.lock");
        let lock = if fs::symlink_metadata(&lock_path).is_ok() {
            let m = io(fs::symlink_metadata(&lock_path))?;
            check(
                m.is_file() && m.nlink() == 1 && m.mode() & 0o7777 == 0o600 && m.uid() == uid,
                PolicyError::Journal,
            )?;
            io(OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path))?
        } else {
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
        };
        lock.try_lock_exclusive().map_err(|_| PolicyError::Busy)?;
        let mut names = io(fs::read_dir(&pinned))?
            .map(|r| r.map(|v| v.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| PolicyError::Journal)?;
        check(names.len() <= MAX_ROWS + 3, PolicyError::Capacity)?;
        let identity_path = pinned.join("identity.json");
        if fs::symlink_metadata(&identity_path).is_err() {
            check(
                names.len() == 1 && names[0] == "owner.lock" && *expected_latest == Anchor::empty(),
                PolicyError::ExternalContext,
            )?;
            let raw = serde_json::to_vec(outside_identity).map_err(|_| PolicyError::Input)?;
            write_exclusive(&identity_path, &raw, &directory)?;
            names.push("identity.json".into());
        }
        let identity_raw = read_held(&identity_path, uid)?;
        let identity: Identity =
            serde_json::from_slice(&identity_raw).map_err(|_| PolicyError::Journal)?;
        check(identity == *outside_identity, PolicyError::ExternalContext)?;
        names.sort();
        let mut index = Index::default();
        let mut anchor = Anchor::empty();
        let mut bytes = identity_raw.len() as u64;
        for name in names {
            let name = name.into_string().map_err(|_| PolicyError::Journal)?;
            if name == "owner.lock" || name == "identity.json" {
                continue;
            }
            check(name != "unavailable.json", PolicyError::CpuUnknown)?;
            check(
                name == format!("entry-{:020}.json", anchor.sequence + 1),
                PolicyError::Journal,
            )?;
            let raw = read_held(&pinned.join(&name), uid)?;
            bytes = bytes
                .checked_add(raw.len() as u64)
                .ok_or(PolicyError::Capacity)?;
            check(
                bytes <= MAX_JOURNAL_BYTES - FAULT_HEADROOM_BYTES,
                PolicyError::Capacity,
            )?;
            let r: Record = serde_json::from_slice(&raw).map_err(|_| PolicyError::Journal)?;
            check(
                r.schema == "restricted-continuous-journal-row-v1"
                    && r.sequence == anchor.sequence + 1
                    && r.previous == anchor.digest,
                PolicyError::Journal,
            )?;
            let update = index.prepare(&r.event, &anchor, &identity)?;
            index.apply(update, &digest(&raw));
            anchor = Anchor {
                sequence: r.sequence,
                digest: digest(&raw),
            };
        }
        check(
            anchor == *expected_latest
                && anchor.sequence <= MAX_ROWS as u64
                && index.pending_scopes == 0,
            PolicyError::ExternalContext,
        )?;
        Ok(Self {
            path: path.to_owned(),
            directory,
            lock,
            uid,
            identity,
            anchor,
            bytes,
            index,
            unavailable: Arc::new(AtomicBool::new(false)),
            clean_restart_issued: false,
        })
    }
    fn pinned(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    fn ready(&self) -> Result<()> {
        check(
            !self.unavailable.load(Ordering::Acquire),
            PolicyError::CpuUnknown,
        )?;
        let a = io(fs::symlink_metadata(&self.path))?;
        let held = io(self.directory.metadata())?;
        let l = io(self.lock.metadata())?;
        let shown = io(fs::symlink_metadata(self.pinned().join("owner.lock")))?;
        check(
            a.is_dir()
                && !a.file_type().is_symlink()
                && a.mode() & 0o7777 == 0o700
                && a.uid() == self.uid
                && a.dev() == held.dev()
                && a.ino() == held.ino()
                && l.is_file()
                && l.nlink() == 1
                && l.uid() == self.uid
                && l.mode() & 0o7777 == 0o600
                && l.dev() == shown.dev()
                && l.ino() == shown.ino(),
            PolicyError::Journal,
        )
    }
    fn append(&mut self, event: Event) -> Result<()> {
        self.ready()?;
        let update = self.index.prepare(&event, &self.anchor, &self.identity)?;
        let sequence = self
            .anchor
            .sequence
            .checked_add(1)
            .ok_or(PolicyError::Capacity)?;
        check(sequence <= MAX_ROWS as u64, PolicyError::Capacity)?;
        let record = Record {
            schema: "restricted-continuous-journal-row-v1".into(),
            sequence,
            previous: self.anchor.digest.clone(),
            event,
        };
        let raw = serde_json::to_vec(&record).map_err(|_| PolicyError::Journal)?;
        let bytes = self
            .bytes
            .checked_add(raw.len() as u64)
            .ok_or(PolicyError::Capacity)?;
        check(
            bytes <= MAX_JOURNAL_BYTES - FAULT_HEADROOM_BYTES,
            PolicyError::Capacity,
        )?;
        if write_exclusive(
            &self.pinned().join(format!("entry-{sequence:020}.json")),
            &raw,
            &self.directory,
        )
        .is_err()
        {
            let _ = self.mark_unknown();
            return Err(PolicyError::Journal);
        }
        self.index.apply(update, &digest(&raw));
        self.bytes = bytes;
        self.anchor = Anchor {
            sequence,
            digest: digest(&raw),
        };
        Ok(())
    }
    pub(crate) fn cpu_allowance(
        &self,
        operation: &str,
        linked: Option<&str>,
    ) -> Result<CpuAllowance> {
        self.ready()?;
        self.index.ready()?;
        let c = self
            .index
            .claims
            .get(operation)
            .ok_or(PolicyError::NativeBinding)?;
        let mut operation_ceiling = c.allocation.cpu_ns;
        if let Some(linked) = linked {
            let next = self
                .index
                .claims
                .get(linked)
                .ok_or(PolicyError::NativeBinding)?;
            check(
                c.native_task == next.native_task
                    && c.instance_class == next.instance_class
                    && c.parent == next.parent
                    && c.generation == next.generation
                    && ((c.purpose == "startup-catalog" && next.purpose == "parent-reconcile")
                        || (c.purpose == "receiver-validation"
                            && next.purpose == "receiver-activate"
                            && c.payload == next.payload)),
                PolicyError::NativeBinding,
            )?;
            operation_ceiling = operation_ceiling
                .checked_add(next.allocation.cpu_ns)
                .ok_or(PolicyError::Budget)?;
        }
        let task = c.native_task.as_str();
        let class = c.instance_class.as_str();
        let (g, t, k) = self.index.totals(task, class);
        let limits = self.index.ceilings.as_ref().ok_or(PolicyError::Budget)?;
        let task_limit = limits.tasks.get(task).ok_or(PolicyError::Budget)?;
        let class_limit = limits.classes.get(class).ok_or(PolicyError::Budget)?;
        Ok(CpuAllowance {
            base: [g.actual_cpu_ns, t.actual_cpu_ns, k.actual_cpu_ns, 0],
            ceilings: [
                limits.global.actual_cpu_ns,
                task_limit.actual_cpu_ns,
                class_limit.actual_cpu_ns,
                operation_ceiling,
            ],
        })
    }
    pub(crate) fn scope_receipt(&self, scope: &str) -> Result<ScopeReceipt> {
        self.ready()?;
        let s = self
            .index
            .scopes
            .get(scope)
            .ok_or(PolicyError::NativeBinding)?;
        let t = s.settlement.as_ref().ok_or(PolicyError::CpuUnknown)?;
        Ok(ScopeReceipt {
            schema: "restricted-continuous-closed-scope-receipt-v1".into(),
            identity: self.identity.clone(),
            scope: scope.to_owned(),
            native_task: s.task.clone(),
            instance_class: s.class.clone(),
            linked_operations: s.operations.clone(),
            started_record_sha256: s.started_record_sha256.clone(),
            settled_record_sha256: t.settled_record_sha256.clone(),
            owner_cpu_ns: t.owner_cpu_ns,
            scoped_worker_cpu_ns: t.scoped_worker_cpu_ns,
            total_cpu_ns: t.total_cpu_ns,
            live_paid_cpu_ns: t.live_paid_cpu_ns,
            residual_cpu_ns: t.residual_cpu_ns,
            spawned: t.spawned,
            started: t.started,
            finished: t.finished,
            known: t.known,
            journal_head: self.anchor(),
        })
    }
    pub(crate) fn claim(&self, op: &str) -> Result<&Claim> {
        self.ready()?;
        self.index.claims.get(op).ok_or(PolicyError::NativeBinding)
    }
    pub(crate) fn result(&self, op: &str) -> Result<&(Option<String>, String, u64)> {
        self.ready()?;
        self.index.results.get(op).ok_or(PolicyError::NativeBinding)
    }
    pub(crate) fn operation_used(&self, op: &str) -> bool {
        self.index.claims.contains_key(op)
    }
    pub(crate) fn unavailable_handle(&self) -> Arc<AtomicBool> {
        self.unavailable.clone()
    }
    pub(crate) fn pristine(&self) -> bool {
        self.anchor.sequence == 0
    }
    pub(crate) fn check_nonce_window(&self, first: u64, last: u64) -> Result<()> {
        self.ready()?;
        let d = self.index.delegation.as_ref().ok_or(PolicyError::Budget)?;
        check(
            first >= d.nonce_first && last <= d.nonce_last && first <= last,
            PolicyError::NativeBinding,
        )
    }
    pub(crate) fn anchor(&self) -> Anchor {
        self.anchor.clone()
    }
    pub(crate) fn usage_digest(&self) -> Result<String> {
        self.index.usage_digest()
    }
    pub(crate) fn increase(&mut self, v: &VerifiedBump) -> Result<()> {
        self.append(Event::Budget {
            body: Box::new(v.body.clone()),
            digest: v.digest.clone(),
        })
    }
    // Receiver/global-allocator authentication must call this only with its opaque verified receipt.
    // This crate-private raw helper does not grant permission and is not a public Node entry.
    fn record_authenticated_claim(&mut self, c: Claim) -> Result<()> {
        self.append(Event::Claim { body: Box::new(c) })
    }
    pub(crate) fn reserve_allocation(
        &mut self,
        v: &crate::operator_continuous_recipient::VerifiedAllocation,
    ) -> Result<()> {
        self.ready()?;
        let (sequence, h) = v.local_budget();
        check(
            v.identity() == &self.identity
                && sequence == self.index.budget_sequence
                && Some(h) == self.index.budget_digest.as_deref(),
            PolicyError::ExternalContext,
        )?;
        let d = self
            .index
            .delegation
            .as_ref()
            .ok_or(PolicyError::ExternalContext)?;
        v.check_delegation(d, crate::operator_task_policy::now_ns()?)?;
        self.record_authenticated_claim(v.claim().clone())
    }
    pub(crate) fn view(
        &mut self,
        sequence: u64,
        h: String,
        previous: Option<String>,
        parent: String,
        generation: u64,
    ) -> Result<()> {
        self.append(Event::View {
            sequence,
            digest: h,
            previous,
            parent,
            generation,
        })
    }
    pub(crate) fn search_result(
        &mut self,
        operation: String,
        packet: Option<String>,
        parent: String,
        generation: u64,
        trials: u64,
    ) -> Result<()> {
        self.append(Event::SearchResult {
            operation,
            packet,
            parent,
            generation,
            trials,
        })
    }
    pub(crate) fn start_cpu(
        &mut self,
        scope: String,
        operation: String,
        task: String,
        class: String,
    ) -> Result<()> {
        // Reserve room for the terminal row before Native starts; count/bytes are never reset.
        check(
            self.anchor
                .sequence
                .checked_add(5)
                .is_some_and(|n| n <= MAX_ROWS as u64)
                && self
                    .bytes
                    .checked_add(5 * MAX_ROW_BYTES)
                    .is_some_and(|n| n <= MAX_JOURNAL_BYTES - FAULT_HEADROOM_BYTES),
            PolicyError::Capacity,
        )?;
        self.append(Event::CpuStarted {
            scope,
            operation,
            task,
            class,
        })
    }
    pub(crate) fn link_startup_claim(&mut self, scope: String, operation: String) -> Result<()> {
        self.append(Event::CpuLinked { scope, operation })
    }
    pub(crate) fn settle_cpu(
        &mut self,
        scope: String,
        v: &crate::ingress::public_v3::ServiceMutationCpuSettlement,
    ) -> Result<()> {
        if v.accounting_unavailable {
            self.mark_unknown()?;
            return Err(PolicyError::CpuUnknown);
        }
        let known = |v: Option<u64>| v.ok_or(PolicyError::CpuUnknown);
        let event: Result<Event> = (|| {
            Ok(Event::CpuSettled {
                scope,
                owner_cpu_ns: known(v.owner_cpu_ns)?,
                scoped_cpu_ns: known(v.scoped_worker_cpu_ns)?,
                total_cpu_ns: known(v.total_cpu_ns)?,
                live_paid_ns: known(v.live_paid_cpu_ns)?,
                residual_ns: known(v.residual_cpu_ns)?,
                spawned: v.spawned_workers,
                started: v.started_workers,
                finished: v.finished_workers,
                known: v.known_workers,
            })
        })();
        match event {
            Ok(event) => {
                let result = self.append(event);
                if result.is_err() {
                    self.mark_unknown()?;
                }
                result
            }
            Err(error) => {
                self.mark_unknown()?;
                Err(error)
            }
        }
    }
    pub(crate) fn control_frame_capacity(&self) -> Result<()> {
        self.ready()?;
        check(
            self.index.control_frames < 65536
                && self
                    .anchor
                    .sequence
                    .checked_add(6)
                    .is_some_and(|n| n <= MAX_ROWS as u64)
                && self
                    .bytes
                    .checked_add(6 * MAX_ROW_BYTES)
                    .is_some_and(|n| n <= MAX_JOURNAL_BYTES - FAULT_HEADROOM_BYTES),
            PolicyError::Capacity,
        )
    }
    pub(crate) fn control_frame(&mut self, raw: &[u8]) -> Result<()> {
        check(
            !raw.is_empty() && raw.len() <= 4 * 1024 * 1024,
            PolicyError::Capacity,
        )?;
        self.append(Event::ControlFrame {
            sha256: digest(raw),
        })
    }
    pub(crate) fn close_clean(&mut self, parent: String, generation: u64) -> Result<()> {
        self.append(Event::CleanClose { parent, generation })
    }
    pub(crate) fn clean_restart_verified(&self) -> bool {
        !self.unavailable.load(Ordering::Acquire)
            && self.index.last_clean
            && self.index.pending_scopes == 0
    }
    pub(crate) fn fault_sink(&self) -> Result<FaultSink> {
        self.ready()?;
        Ok(FaultSink {
            path: self.path.clone(),
            directory: io(self.directory.try_clone())?,
            uid: self.uid,
            unavailable: self.unavailable.clone(),
        })
    }
    pub(crate) fn issue_clean_restart(&mut self) -> Result<VerifiedCleanRestart> {
        self.ready()?;
        check(
            self.clean_restart_verified() && !self.clean_restart_issued,
            PolicyError::CpuUnknown,
        )?;
        self.clean_restart_issued = true;
        Ok(VerifiedCleanRestart { _private: () })
    }
    pub(crate) fn mark_unknown(&mut self) -> Result<()> {
        let sink = FaultSink {
            path: self.path.clone(),
            directory: io(self.directory.try_clone())?,
            uid: self.uid,
            unavailable: self.unavailable.clone(),
        };
        sink.persist_unknown()
    }
}
/// Only complete outside-pinned cold-open + known clean close can issue this token.
/// It carries no balance and must be consumed by a zero-credit constructor.
pub(crate) struct VerifiedCleanRestart {
    _private: (),
}
/// Fixed for one exclusive Node owner scope, never holds a journal/SQL lock.
#[derive(Clone)]
pub(crate) struct CpuAllowance {
    base: [u64; 4],
    ceilings: [u64; 4],
}
impl CpuAllowance {
    pub(crate) fn checkpoint(&self, actual_live_ns: u64) -> Result<()> {
        for (base, ceiling) in self.base.iter().zip(self.ceilings) {
            check(
                base.checked_add(actual_live_ns)
                    .is_some_and(|total| total <= ceiling),
                PolicyError::Budget,
            )?;
        }
        Ok(())
    }
}
pub(crate) struct FaultSink {
    path: PathBuf,
    directory: File,
    uid: u32,
    unavailable: Arc<AtomicBool>,
}
impl FaultSink {
    pub(crate) fn persist_unknown(&self) -> Result<()> {
        self.unavailable.store(true, Ordering::Release);
        let visible = io(fs::symlink_metadata(&self.path))?;
        let held = io(self.directory.metadata())?;
        check(
            visible.is_dir()
                && !visible.file_type().is_symlink()
                && visible.uid() == self.uid
                && visible.mode() & 0o7777 == 0o700
                && visible.dev() == held.dev()
                && visible.ino() == held.ino(),
            PolicyError::Journal,
        )?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        let raw=b"{\"schema\":\"restricted-continuous-accounting-fault-v1\",\"label\":\"CPU_OR_JOURNAL_UNKNOWN\"}";
        let p = pinned.join("unavailable.json");
        if fs::symlink_metadata(&p).is_ok() {
            check(read_held(&p, self.uid)? == raw, PolicyError::Journal)?;
            io(self.directory.sync_all())
        } else {
            write_exclusive(&p, raw, &self.directory)
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_history_tests.rs"]
pub(crate) mod tests;
