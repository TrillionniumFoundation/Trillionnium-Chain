//! New mode4 owner. No legacy permit, migration or automatic best-tip advance.
use super::*;
use crate::ingress::public_v3::{ServiceMutationCpuCheckpoint, ServiceMutationCpuDomain};
use crate::{
    operator_continuous_cpu::{ContinuousCheckpoint, DurableOperation, ObservedOperation, Start},
    operator_continuous_history as history, operator_continuous_policy as policy, PoolBatch,
    PoolLimits,
};
use policy::{Permit, VerifiedView};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use trnm_protocol::pon_wire::Envelope;
fn continuous_error(e: crate::operator_task_policy::PolicyError) -> Error {
    Error::from(format!("OWNER_CONTINUOUS:{e:?}"))
}
#[derive(Clone)]
pub(super) struct ContinuousOwner {
    pub marker: Vec<u8>,
    view: Arc<VerifiedView>,
    journal: Arc<Mutex<history::Journal>>,
    cpu: ServiceMutationCpuDomain,
    catalog: Arc<policy::HeldCatalog>,
    epoch: Arc<AtomicU64>,
    view_epoch: u64,
    unavailable: Arc<AtomicBool>,
    active: Arc<Mutex<Option<Active>>>,
    startup_scope: String,
    sink: Arc<history::FaultSink>,
}
#[derive(Clone)]
struct Active {
    permit: Arc<Permit>,
    paired_activate: Option<Arc<Permit>>,
    cpu: ContinuousCheckpoint,
    tx: Option<String>,
    miner: Option<Hash>,
    height: Option<u64>,
    pool: Option<Arc<crate::operator_continuous_pool::VerifiedSelection>>,
}
#[derive(Clone)]
pub(crate) struct ContinuousScopeCheckpoint(Active);
impl ContinuousScopeCheckpoint {
    pub fn check(&self) -> Result<()> {
        self.0.permit.progress().map_err(continuous_error)?;
        if let Some(p) = &self.0.paired_activate {
            p.progress().map_err(continuous_error)?;
        }
        self.0.cpu.checkpoint()
    }
}
#[derive(Clone)]
pub(super) struct ContinuousPoolCheckpoint(Active);
impl ContinuousPoolCheckpoint {
    pub(super) fn check(&self) -> Result<()> {
        ContinuousScopeCheckpoint(self.0.clone()).check()
    }
    pub(super) fn check_prefix(&self, raws: &[Vec<u8>]) -> Result<()> {
        self.check()?;
        self.0
            .pool
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?
            .check_prefix(raws)
            .map_err(continuous_error)
    }
    pub(super) fn check_retained(&self, raws: &[Vec<u8>]) -> Result<()> {
        self.check()?;
        self.0
            .pool
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?
            .check_bound_group(raws)
            .map_err(continuous_error)
    }
}
struct Reset(Arc<Mutex<Option<Active>>>);
impl Drop for Reset {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.lock() {
            *active = None;
        }
    }
}
pub(crate) struct PublicContinuousScope {
    observed: Option<ObservedOperation>,
    _reset: Reset,
}
impl PublicContinuousScope {
    pub fn checkpoint(&self) -> Result<ContinuousScopeCheckpoint> {
        self._reset
            .0
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_SCOPE_UNKNOWN")?
            .as_ref()
            .cloned()
            .map(ContinuousScopeCheckpoint)
            .ok_or_else(|| "OWNER_CONTINUOUS_SCOPE_UNKNOWN".into())
    }
    pub fn finish(
        mut self,
        actual: &crate::ingress::public_v3::ServiceMutationCpuSettlement,
    ) -> bool {
        self.observed
            .take()
            .is_some_and(|scope| scope.finish(actual))
    }
}
fn scope_id(operation: &str) -> String {
    crate::operator_task_policy::digest_bytes(
        format!("TRNM-RESTRICTED-CONTINUOUS-CPU-SCOPE1:{operation}").as_bytes(),
    )
}
struct Binding {
    tx: Option<String>,
    miner: Option<Hash>,
    height: Option<u64>,
    pool: Option<Arc<crate::operator_continuous_pool::VerifiedSelection>>,
}
impl Binding {
    fn none() -> Self {
        Self {
            tx: None,
            miner: None,
            height: None,
            pool: None,
        }
    }
    fn packet(packet: &Packet) -> Result<Self> {
        Ok(Self {
            tx: Some(
                crate::operator_mining_policy::transactions_sha256(&packet.transactions)
                    .map_err(continuous_error)?,
            ),
            miner: Some(packet.header.miner),
            height: Some(packet.header.height),
            pool: None,
        })
    }
}
impl ContinuousOwner {
    fn slot(&self) -> Result<Option<Active>> {
        Ok(self
            .active
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_SCOPE_UNKNOWN")?
            .clone())
    }
    fn enter(
        &self,
        permit: Arc<Permit>,
        paired_activate: Option<Arc<Permit>>,
        cpu: ContinuousCheckpoint,
        b: Binding,
    ) -> Result<Reset> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_SCOPE_UNKNOWN")?;
        ensure(active.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        *active = Some(Active {
            permit,
            paired_activate,
            cpu,
            tx: b.tx,
            miner: b.miner,
            height: b.height,
            pool: b.pool,
        });
        drop(active);
        Ok(Reset(self.active.clone()))
    }
    fn permission(&self, purpose: &str, payload: &str) -> Result<Arc<Permit>> {
        ensure(
            self.epoch.load(Ordering::Acquire) == self.view_epoch
                && !self.unavailable.load(Ordering::Acquire),
            "OWNER_CONTINUOUS_NEXT_VIEW_REQUIRED",
        )?;
        self.view
            .check_window(crate::operator_task_policy::now_ns().map_err(continuous_error)?)
            .map_err(continuous_error)?;
        let allocation = self
            .view
            .permission(purpose, payload)
            .map_err(continuous_error)?;
        self.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .reserve_allocation(&allocation)
            .map_err(continuous_error)?;
        Ok(Arc::new(Permit {
            view: self.view.clone(),
            allocation,
            epoch: self.epoch.clone(),
            expected_epoch: self.view_epoch,
            unavailable: self.unavailable.clone(),
        }))
    }
    fn operation(&self, p: &Permit, linked: Option<&Permit>) -> Result<DurableOperation> {
        let c = p.allocation.claim();
        DurableOperation::begin(
            self.journal.clone(),
            &self.cpu,
            Start {
                scope: scope_id(&c.operation),
                operation: c.operation.clone(),
                linked_startup: linked.map(|v| v.allocation.claim().operation.clone()),
                task: c.native_task.clone(),
                class: c.instance_class.clone(),
            },
            self.sink.clone(),
        )
        .map_err(continuous_error)
    }
    fn ready(&self) -> Result<()> {
        ensure(
            !self.unavailable.load(Ordering::Acquire),
            "OWNER_CONTINUOUS_UNKNOWN",
        )?;
        self.catalog.ready().map_err(continuous_error)
    }
}
pub(crate) struct ContinuousControlFrame {
    journal: Arc<Mutex<history::Journal>>,
    sink: Arc<history::FaultSink>,
    finished: bool,
}
impl ContinuousControlFrame {
    pub(crate) fn finish(mut self, raw: &[u8]) -> bool {
        let persisted = self
            .journal
            .lock()
            .ok()
            .is_some_and(|mut journal| journal.control_frame(raw).is_ok());
        if !persisted {
            let _fault = self.sink.persist_unknown();
        }
        self.finished = true;
        persisted
    }
}
impl Drop for ContinuousControlFrame {
    fn drop(&mut self) {
        if !self.finished {
            let _fault = self.sink.persist_unknown();
        }
    }
}
pub struct ContinuousSearchRequest<'a> {
    pub operation_id: &'a str,
    pub transactions: Vec<Vec<u8>>,
    pub model: &'a [u8],
    pub input: &'a [u8],
    pub stop: &'a AtomicBool,
    pub deadline: std::time::Instant,
}
fn check_actual_task_fields(
    task: &crate::operator_task_policy::Task,
    purpose: TaskPurpose,
    model: Hash,
    input: Hash,
    lease: &[u8],
    proof: &[u8],
) -> Result<()> {
    let size = pon_work::CELLS * 4;
    ensure(
        proof.len() == pon_work::PROOF_BYTES && proof.get(..4) == Some(b"PNW1"),
        "OWNER_CONTINUOUS_PROOF",
    )?;
    ensure(
        purpose == TaskPurpose::Maintenance
            && hex::encode(model) == task.native_model
            && hex::encode(input) == task.native_input
            && crate::operator_task_policy::digest_bytes(lease) == task.lease_sha256
            && crate::operator_task_policy::digest_bytes(&proof[4..4 + size]) == task.a_sha256
            && crate::operator_task_policy::digest_bytes(&proof[4 + size..4 + 2 * size])
                == task.b_sha256,
        "OWNER_CONTINUOUS_NATIVE_BINDING",
    )
}
impl Node {
    pub fn continuous_cpu_domain(&self) -> Result<ServiceMutationCpuDomain> {
        Ok(self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .cpu
            .clone())
    }
    pub(crate) fn continuous_domain_matches(&self, cpu: &ServiceMutationCpuDomain) -> bool {
        self.continuous_owner
            .as_ref()
            .is_none_or(|o| o.cpu.shares_domain_with(cpu))
    }
    pub(crate) fn is_continuous(&self) -> bool {
        self.continuous_owner.is_some()
    }
    /// Material load follows actual reservations, and all errors settle before
    /// choosing their Native result. New persistent mode4 namespace only.
    pub fn open_operator_continuous_checkpoint(
        path: &Path,
        inputs: policy::Inputs,
        deadline: std::time::Instant,
    ) -> Result<(Self, Vec<u8>, Vec<u8>)> {
        let now = crate::operator_task_policy::now_ns().map_err(continuous_error)?;
        let view = Arc::new(policy::authenticate(&inputs, now).map_err(continuous_error)?);
        let mut journal = history::Journal::open(
            &inputs.journal_path,
            inputs.expected_uid,
            &view.body.identity,
            &inputs.expected_journal,
        )
        .map_err(continuous_error)?;
        if journal.pristine() {
            ensure(
                inputs.lease_transition.is_none(),
                "OWNER_CONTINUOUS_LEASE_NOT_FRESH",
            )?;
        } else {
            let old = journal.declared_binding().map_err(continuous_error)?;
            if let Some(reference) = &inputs.lease_transition {
                reference
                    .edge
                    .check_declarations(old, &view.body.declared_binding)
                    .map_err(continuous_error)?;
                journal
                    .check_lease_witness(&reference.operation, &reference.edge)
                    .map_err(continuous_error)?;
                let budget = inputs
                    .budget_authority
                    .as_ref()
                    .ok_or("OWNER_CONTINUOUS_LEASE_BUDGET_REQUIRED")?;
                ensure(
                    inputs.raw_budget.is_some()
                        && budget.expected.delegation.declared_binding
                            == view.body.declared_binding
                        && budget.expected.delegation.registry2_declaration_digest
                            == reference.edge.new_registry2_declaration_digest
                        && budget.expected.delegation.context.actual_parent
                            == reference.edge.actual_parent,
                    "OWNER_CONTINUOUS_LEASE_NEW_DECLARATION",
                )?;
            } else {
                ensure(
                    *old == view.body.declared_binding,
                    "OWNER_CONTINUOUS_EXPLICIT_LEASE_EDGE_REQUIRED",
                )?;
            }
        }
        let recovery = inputs
            .known_unclean_restart
            .as_ref()
            .map(|input| {
                crate::operator_continuous_recovery::authenticate(input, &view.body.identity, now)
            })
            .transpose()
            .map_err(continuous_error)?;
        let cpu = if journal.pristine() {
            ensure(recovery.is_none(), "OWNER_CONTINUOUS_RECOVERY_NOT_FRESH")?;
            ServiceMutationCpuDomain::standalone()
        } else if let Some(verified) = &recovery {
            ensure(
                verified.body.actual_parent == view.body.actual_parent
                    && verified.body.actual_generation == view.body.actual_generation,
                "OWNER_CONTINUOUS_RECOVERY_ACTUAL_PAIR",
            )?;
            ServiceMutationCpuDomain::from_known_unclean_continuous_restart(
                journal
                    .issue_known_unclean_restart(verified)
                    .map_err(continuous_error)?,
            )
        } else {
            ServiceMutationCpuDomain::from_clean_continuous_restart(
                journal.issue_clean_restart().map_err(continuous_error)?,
            )
        };
        match (&inputs.raw_budget, &inputs.budget_authority) {
            (Some(raw), Some(authority)) => journal
                .increase(
                    &history::authenticate_bump(raw, authority, now).map_err(continuous_error)?,
                )
                .map_err(continuous_error)?,
            (None, None) => {}
            _ => return Err("OWNER_CONTINUOUS_COMPLETE_BUDGET_REQUIRED".into()),
        }
        journal
            .view(
                view.body.sequence,
                view.digest.clone(),
                view.body.previous_digest.clone(),
                view.body.actual_parent.clone(),
                view.body.actual_generation,
            )
            .map_err(continuous_error)?;
        let unavailable = journal.unavailable_handle();
        let sink = Arc::new(journal.fault_sink().map_err(continuous_error)?);
        let marker = view
            .marker(&inputs.journal_path)
            .map_err(continuous_error)?;
        let journal = Arc::new(Mutex::new(journal));
        let epoch = Arc::new(AtomicU64::new(1));
        let reserve = |purpose: &str, payload: &str| -> Result<Arc<Permit>> {
            let allocation = view
                .permission(purpose, payload)
                .map_err(continuous_error)?;
            journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .reserve_allocation(&allocation)
                .map_err(continuous_error)?;
            Ok(Arc::new(Permit {
                view: view.clone(),
                allocation,
                epoch: epoch.clone(),
                expected_epoch: 1,
                unavailable: unavailable.clone(),
            }))
        };
        let startup = reserve(
            "startup-catalog",
            &view.body.declared_binding.task.full_material_catalog,
        )?;
        let reconcile = reserve("parent-reconcile", &view.body.actual_parent)?;
        let c = startup.allocation.claim();
        cpu.await_startup_credit(deadline)?;
        let operation = DurableOperation::begin(
            journal.clone(),
            &cpu,
            Start {
                scope: scope_id(&c.operation),
                operation: c.operation.clone(),
                linked_startup: Some(reconcile.allocation.claim().operation.clone()),
                task: c.native_task.clone(),
                class: c.instance_class.clone(),
            },
            sink.clone(),
        )
        .map_err(continuous_error)?;
        let progress = || {
            ensure(
                std::time::Instant::now() < deadline,
                "OWNER_CONTINUOUS_STARTUP_DEADLINE",
            )?;
            startup.progress().map_err(continuous_error)?;
            reconcile.progress().map_err(continuous_error)?;
            operation
                .checkpoint_handle()
                .map_err(continuous_error)?
                .checkpoint()
        };
        let built = (|| -> Result<(policy::HeldCatalog, Settings, Vec<u8>, Vec<u8>)> {
            let catalog = policy::verify_catalog(&inputs, &startup, &|| {
                progress().map_err(|_| crate::operator_task_policy::PolicyError::CpuUnknown)
            })
            .map_err(continuous_error)?;
            let model = catalog
                .read_role("model", 16384, &progress)
                .map_err(continuous_error)?;
            let input = catalog
                .read_role("input", 16384, &progress)
                .map_err(continuous_error)?;
            let spec_raw = catalog
                .read_role(
                    "spec",
                    crate::operator_checkpoint_tile::SPEC_BYTES as u64,
                    &progress,
                )
                .map_err(continuous_error)?;
            let spec =
                crate::operator_checkpoint_tile::OperatorCheckpointTileSpecV1::decode(&spec_raw)?;
            let bootstrap = catalog
                .read_role("bootstrap", 8192, &progress)
                .map_err(continuous_error)?;
            let bundle = crate::operator_deployment::decode(&bootstrap)?;
            let paths = crate::operator_checkpoint_tile::CheckpointTileRuntimePaths::new(
                catalog.path_role("checkpoint").map_err(continuous_error)?,
                catalog.path_role("activation").map_err(continuous_error)?,
            );
            let settings = Settings::development_with_operator_checkpoint_tile(
                &spec, &bundle, &model, &input, paths,
            )?;
            progress()?;
            ensure(
                view.body.identity.network == hex::encode(settings.network())
                    && view.body.identity.parameters == hex::encode(settings.parameters()),
                "OWNER_CONTINUOUS_SETTINGS_CONTEXT",
            )?;
            Ok((catalog, settings, model, input))
        })();
        let (catalog, settings, model, input) = match built {
            Ok(v) => v,
            Err(error) => {
                let _actual = operation.finish().map_err(continuous_error)?;
                return Err(error);
            }
        };
        let owner = ContinuousOwner {
            marker,
            view,
            journal,
            cpu,
            catalog: Arc::new(catalog),
            epoch,
            view_epoch: 1,
            unavailable,
            active: Arc::new(Mutex::new(None)),
            startup_scope: operation.scope().to_owned(),
            sink,
        };
        let _scope = owner.enter(
            reconcile,
            None,
            operation.checkpoint_handle().map_err(continuous_error)?,
            Binding::none(),
        )?;
        Self::install_mining_marker(path, inputs.expected_uid, &owner.marker)?;
        let opened = Self::open_inner(path, settings, 1, None, None, None, Some(owner));
        let settled = operation.finish().map_err(continuous_error)?;
        let node = opened?;
        ensure(
            settled.accounting_record_persisted
                && !settled.actual.accounting_unavailable
                && !settled.actual.live_refused,
            "OWNER_CONTINUOUS_STARTUP_ACCOUNTING",
        )?;
        let (tip, generation) = node.active()?;
        let owner = node
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        ensure(
            hex::encode(tip) == owner.view.body.actual_parent
                && generation == owner.view.body.actual_generation,
            "OWNER_CONTINUOUS_STARTUP_PAIR",
        )?;
        owner.ready()?;
        Ok((node, model, input))
    }
    pub fn refresh_operator_continuous_view(&mut self, inputs: policy::Inputs) -> Result<()> {
        ensure(
            inputs.known_unclean_restart.is_none(),
            "OWNER_CONTINUOUS_RECOVERY_STARTUP_ONLY",
        )?;
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        ensure(owner.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        ensure(
            owner.marker
                == owner
                    .view
                    .marker(&inputs.journal_path)
                    .map_err(continuous_error)?
                && inputs.expected_journal
                    == owner
                        .journal
                        .lock()
                        .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                        .anchor(),
            "OWNER_CONTINUOUS_EXTERNAL_JOURNAL_HEAD",
        )?;
        let now = crate::operator_task_policy::now_ns().map_err(continuous_error)?;
        let next = policy::authenticate(&inputs, now).map_err(continuous_error)?;
        let (parent, generation) = self.active()?;
        ensure(
            next.next(&owner.view)
                && next.body.actual_parent == hex::encode(parent)
                && next.body.actual_generation == generation,
            "OWNER_CONTINUOUS_LINKED_NEXT_VIEW",
        )?;
        owner
            .catalog
            .recheck(&inputs, &next)
            .map_err(continuous_error)?;
        // A changed lease refers to an already paid and known-settled old-budget
        // operation with actual State/tag22 evidence. This read-only gate
        // cannot invalidate the externally signed exact prior journal head.
        self.check_continuous_lease_transition(&owner, &inputs, &next)?;
        let epoch = owner
            .epoch
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("OWNER_CONTINUOUS_EPOCH_OVERFLOW")?;
        let changed = (|| -> Result<()> {
            let mut journal = owner
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
            match (&inputs.raw_budget, &inputs.budget_authority) {
                (Some(raw), Some(authority)) => journal
                    .increase(
                        &history::authenticate_bump(raw, authority, now)
                            .map_err(continuous_error)?,
                    )
                    .map_err(continuous_error)?,
                (None, None) => {}
                _ => return Err("OWNER_CONTINUOUS_COMPLETE_BUDGET_REQUIRED".into()),
            };
            journal
                .view(
                    next.body.sequence,
                    next.digest.clone(),
                    next.body.previous_digest.clone(),
                    hex::encode(parent),
                    generation,
                )
                .map_err(continuous_error)
        })();
        if let Err(error) = changed {
            let _ = owner
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .mark_unknown();
            return Err(error);
        }
        owner.epoch.store(epoch, Ordering::Release);
        let live = self
            .continuous_owner
            .as_mut()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        live.view = Arc::new(next);
        live.view_epoch = epoch;
        Ok(())
    }
    pub fn cancel_continuous_epoch(&self) -> Result<bool> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        let next = o
            .view_epoch
            .checked_add(1)
            .ok_or("OWNER_CONTINUOUS_EPOCH_OVERFLOW")?;
        Ok(o.epoch
            .compare_exchange(o.view_epoch, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    pub fn close_continuous_checkpoint(&self) -> Result<serde_json::Value> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let (p, g) = self.active()?;
        let mut journal = o
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
        journal
            .close_clean(hex::encode(p), g)
            .map_err(continuous_error)?;
        Ok(
            serde_json::json!({"schema":"restricted-continuous-clean-checkpoint-v2","journal_head":journal.anchor(),"usage_digest":journal.usage_digest().map_err(continuous_error)?,"parent":hex::encode(p),"generation":g,"public_network_ready":false}),
        )
    }
    pub fn continuous_scope_receipt(&self, operation: &str) -> Result<serde_json::Value> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        Ok(serde_json::to_value(
            o.journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .scope_receipt(&scope_id(operation))
                .map_err(continuous_error)?,
        )?)
    }
    pub(crate) fn begin_continuous_control_frame(&self) -> Result<ContinuousControlFrame> {
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        owner
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .control_frame_capacity()
            .map_err(continuous_error)?;
        Ok(ContinuousControlFrame {
            journal: owner.journal.clone(),
            sink: owner.sink.clone(),
            finished: false,
        })
    }
    pub(crate) fn mark_continuous_metadata_unknown(&self) {
        if let Some(owner) = &self.continuous_owner {
            let _fault = owner.sink.persist_unknown();
        }
    }
    pub fn continuous_journal_head(&self) -> Result<serde_json::Value> {
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        let head = owner
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .anchor();
        Ok(serde_json::to_value(head)?)
    }
    pub fn continuous_startup_receipt(&self) -> Result<serde_json::Value> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        Ok(serde_json::to_value(
            o.journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .scope_receipt(&o.startup_scope)
                .map_err(continuous_error)?,
        )?)
    }
    pub(super) fn continuous_recovery_unchanged(&self) -> Result<Option<Hash>> {
        let Some(o) = &self.continuous_owner else {
            return Ok(None);
        };
        let a = o
            .slot()?
            .ok_or("OWNER_CONTINUOUS_RECONCILE_PURPOSE_REQUIRED")?;
        ensure(
            a.permit.allocation.claim().purpose == "parent-reconcile",
            "OWNER_CONTINUOUS_RECONCILE_PURPOSE_REQUIRED",
        )?;
        ContinuousScopeCheckpoint(a.clone()).check()?;
        let (tip, generation) = self.active()?;
        ensure(
            a.permit.allocation.claim().parent == hex::encode(tip)
                && a.permit.allocation.claim().generation == generation,
            "OWNER_CONTINUOUS_RECONCILE_PAIR",
        )?;
        let pending: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM reorg WHERE done=0", [], |r| r.get(0))?;
        ensure(pending == 0, "OWNER_CONTINUOUS_RECOVERY_INTENT_HOLD")?;
        let best: Vec<u8> = self.db.query_row(
            "SELECT id FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            bytes32(best)? == tip,
            "OWNER_CONTINUOUS_RECOVERY_ADVANCE_HOLD",
        )?;
        self.namespace()?;
        ContinuousScopeCheckpoint(a).check()?;
        Ok(Some(tip))
    }
    pub(super) fn continuous_packet_gate(&self, packet: &Packet) -> Result<()> {
        let Some(o) = &self.continuous_owner else {
            return Ok(());
        };
        o.ready()?;
        let encoded = packet.encode()?;
        let sha = crate::operator_task_policy::digest_bytes(&encoded);
        ensure(
            hex::encode(packet.header.work_task) == o.view.body.declared_binding.task.native_task,
            "OWNER_CONTINUOUS_PACKET_TASK",
        )?;
        if let Some(a) = o.slot()? {
            let c = a.permit.allocation.claim();
            ensure(
                matches!(
                    c.purpose.as_str(),
                    "winner-validation" | "receiver-validation"
                ) && c.payload == sha,
                "OWNER_CONTINUOUS_VALIDATION_PURPOSE_REQUIRED",
            )?;
            ContinuousScopeCheckpoint(a).check()?;
            return Ok(());
        }
        // Only identical durable bytes may be returned without NEW Work. No
        // State, eligible task, lease or history traversal precedes this branch.
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [packet.id()?.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        ensure(
            raw.as_deref() == Some(encoded.as_slice()),
            "OWNER_CONTINUOUS_EXPLICIT_SCOPE_REQUIRED",
        )?;
        Ok(())
    }
    pub(super) fn continuous_preview_gate(&self) -> Result<()> {
        if let Some(o) = &self.continuous_owner {
            let a = o
                .slot()?
                .ok_or("OWNER_CONTINUOUS_SEARCH_PURPOSE_REQUIRED")?;
            ensure(
                a.permit.allocation.claim().purpose == "search" || a.pool.is_some(),
                "OWNER_CONTINUOUS_SEARCH_PURPOSE_REQUIRED",
            )?;
            ContinuousScopeCheckpoint(a).check()?;
        }
        Ok(())
    }
    pub(super) fn continuous_execution_gate(&self, b: &ExecutionRequest<'_>) -> Result<()> {
        if let Some(o) = &self.continuous_owner {
            let a = o
                .slot()?
                .ok_or("OWNER_CONTINUOUS_NATIVE_PURPOSE_REQUIRED")?;
            let c = a.permit.allocation.claim();
            if let Some(pool) = &a.pool {
                ensure(
                    c.parent == hex::encode(b.parent_id)
                        && a.miner == Some(b.miner)
                        && a.height == Some(b.height),
                    "OWNER_CONTINUOUS_POOL_NATIVE_BINDING",
                )?;
                pool.check_prefix(b.transactions)
                    .map_err(continuous_error)?;
                return ContinuousScopeCheckpoint(a).check();
            }
            ensure(
                matches!(
                    c.purpose.as_str(),
                    "search" | "winner-validation" | "receiver-validation"
                ) && c.parent == hex::encode(b.parent_id)
                    && a.tx.as_deref()
                        == Some(
                            crate::operator_mining_policy::transactions_sha256(b.transactions)
                                .map_err(continuous_error)?
                                .as_str(),
                        )
                    && a.miner == Some(b.miner)
                    && a.height == Some(b.height),
                "OWNER_CONTINUOUS_NATIVE_BINDING",
            )?;
            ContinuousScopeCheckpoint(a).check()?;
        }
        Ok(())
    }
    pub(super) fn continuous_activation_gate(&self, target: Hash) -> Result<()> {
        if let Some(o) = &self.continuous_owner {
            if self.active()?.0 == target {
                return Ok(());
            }
            let a = o
                .slot()?
                .ok_or("OWNER_CONTINUOUS_ACTIVATE_PURPOSE_REQUIRED")?;
            let p = a.paired_activate.as_ref().unwrap_or(&a.permit);
            ensure(
                matches!(
                    p.allocation.claim().purpose.as_str(),
                    "activate" | "receiver-activate"
                ),
                "OWNER_CONTINUOUS_ACTIVATE_PURPOSE_REQUIRED",
            )?;
            let raw: Vec<u8> = self.db.query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [target.as_slice()],
                |r| r.get(0),
            )?;
            ensure(
                p.allocation.claim().payload == crate::operator_task_policy::digest_bytes(&raw),
                "OWNER_CONTINUOUS_ACTIVATE_PACKET",
            )?;
            ContinuousScopeCheckpoint(a).check()?;
        }
        Ok(())
    }
    pub(super) fn continuous_scope_checkpoint(&self) -> Result<()> {
        if let Some(a) = self
            .continuous_owner
            .as_ref()
            .map(|o| o.slot())
            .transpose()?
            .flatten()
        {
            ContinuousScopeCheckpoint(a).check()?;
        }
        Ok(())
    }
    pub(super) fn continuous_progress_snapshot(&self) -> Result<Option<ContinuousScopeCheckpoint>> {
        Ok(self
            .continuous_owner
            .as_ref()
            .map(|o| o.slot())
            .transpose()?
            .flatten()
            .map(ContinuousScopeCheckpoint))
    }
    /// Node shared public Submit: claims before full State/context/M05, using the
    /// ALREADY acquired original public scalar interval, never another begin.
    pub(crate) fn begin_continuous_public_scope(
        &self,
        packet: &Packet,
        cpu: ServiceMutationCpuCheckpoint,
    ) -> Result<Option<PublicContinuousScope>> {
        let Some(o) = &self.continuous_owner else {
            return Ok(None);
        };
        o.ready()?;
        let encoded = packet.encode()?;
        let prior: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [packet.id()?.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if prior.as_deref() == Some(encoded.as_slice()) {
            return Ok(None);
        }
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let sha = crate::operator_task_policy::digest_bytes(&packet.encode()?);
        let (parent, generation) = self.active()?;
        let v = o
            .view
            .permission("receiver-validation", &sha)
            .map_err(continuous_error)?;
        v.check_exact_receiver_packet(packet, parent, generation)
            .map_err(continuous_error)?;
        let activate = o
            .view
            .permission("receiver-activate", &sha)
            .map_err(continuous_error)?;
        ensure(
            v.claim().parent == activate.claim().parent
                && v.claim().generation == activate.claim().generation
                && v.claim().task_binding == activate.claim().task_binding,
            "OWNER_CONTINUOUS_RECEIVER_PAIR",
        )?;
        ensure(
            !o.journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .operation_used(&v.claim().operation),
            "OWNER_CONTINUOUS_OPERATION_USED",
        )?;
        o.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .check_nonce_window(packet.header.nonce, packet.header.nonce)
            .map_err(continuous_error)?;
        let validation = o.permission("receiver-validation", &sha)?;
        let activation = match o.permission("receiver-activate", &sha) {
            Ok(value) => value,
            Err(error) => {
                let _ = o.sink.persist_unknown();
                return Err(error);
            }
        };
        let c = validation.allocation.claim();
        let observed = ObservedOperation::begin(
            o.journal.clone(),
            Start {
                scope: scope_id(&c.operation),
                operation: c.operation.clone(),
                linked_startup: Some(activation.allocation.claim().operation.clone()),
                task: c.native_task.clone(),
                class: c.instance_class.clone(),
            },
            cpu,
            o.sink.clone(),
        )
        .map_err(continuous_error)?;
        let reset = match o.enter(
            validation,
            Some(activation),
            observed.checkpoint_handle(),
            Binding::packet(packet)?,
        ) {
            Ok(value) => value,
            Err(error) => {
                drop(observed);
                return Err(error);
            }
        };
        Ok(Some(PublicContinuousScope {
            observed: Some(observed),
            _reset: reset,
        }))
    }
    pub(crate) fn check_continuous_public_packet_binding(&self, packet: &Packet) -> Result<()> {
        let Some(o) = &self.continuous_owner else {
            return Ok(());
        };
        let active = o
            .slot()?
            .ok_or("OWNER_CONTINUOUS_EXPLICIT_SCOPE_REQUIRED")?;
        self.continuous_actual_packet_binding(&active.permit, packet)
    }
    fn continuous_actual_packet_binding(&self, p: &Permit, packet: &Packet) -> Result<()> {
        let c = p.allocation.claim();
        let t = &p.view.body.declared_binding.task;
        ensure(
            packet.header.parent
                == bytes32(hex::decode(&c.parent).map_err(|_| "OWNER_CONTINUOUS_PARENT_HEX")?)?
                && hex::encode(packet.header.work_task) == t.native_task,
            "OWNER_CONTINUOUS_PACKET_TASK",
        )?;
        let manifest = self
            .eligible_work_task(
                packet.header.parent,
                packet.header.work_task,
                packet.header.height,
            )?
            .ok_or("OWNER_CONTINUOUS_COMPLETE_REGISTRATION_REQUIRED")?;
        let lease = self
            .lifecycle_task_lease(
                packet.header.parent,
                packet.header.work_task,
                packet.header.height,
            )?
            .encode()
            .map_err(|_| "OWNER_CONTINUOUS_LEASE")?;
        check_actual_task_fields(
            t,
            manifest.purpose,
            manifest.model,
            manifest.input,
            &lease,
            &packet.proof,
        )?;
        p.progress().map_err(continuous_error)
    }
    fn continuous_task_binding(&self, p: &Permit, model: &[u8], input: &[u8]) -> Result<()> {
        let c = p.allocation.claim();
        let t = &p.view.body.declared_binding.task;
        let parent = bytes32(hex::decode(&c.parent).map_err(|_| "OWNER_CONTINUOUS_PARENT_HEX")?)?;
        let task = bytes32(hex::decode(&c.native_task).map_err(|_| "OWNER_CONTINUOUS_TASK_HEX")?)?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let manifest = self
            .eligible_work_task(parent, task, height)?
            .ok_or("OWNER_CONTINUOUS_COMPLETE_REGISTRATION_REQUIRED")?;
        let lease = self
            .lifecycle_task_lease(parent, task, height)?
            .encode()
            .map_err(|_| "OWNER_CONTINUOUS_LEASE")?;
        let (a, b) = derive_matrices(model, input).map_err(|_| "OWNER_CONTINUOUS_MATERIAL")?;
        let ab: Vec<u8> = a.iter().flat_map(|v| v.to_le_bytes()).collect();
        let bb: Vec<u8> = b.iter().flat_map(|v| v.to_le_bytes()).collect();
        ensure(
            manifest.purpose == TaskPurpose::Maintenance
                && crate::operator_task_policy::digest_bytes(&lease) == t.lease_sha256
                && hex::encode(manifest.model) == t.native_model
                && hex::encode(manifest.input) == t.native_input
                && crate::operator_task_policy::digest_bytes(model) == t.model_material
                && crate::operator_task_policy::digest_bytes(input) == t.input_material
                && crate::operator_task_policy::digest_bytes(&ab) == t.a_sha256
                && crate::operator_task_policy::digest_bytes(&bb) == t.b_sha256,
            "OWNER_CONTINUOUS_NATIVE_TASK_BINDING",
        )?;
        p.progress().map_err(continuous_error)
    }
    fn continuous_pair(
        &self,
        o: &ContinuousOwner,
        purpose: &str,
        payload: &str,
    ) -> Result<Arc<Permit>> {
        let (parent, generation) = self.active()?;
        ensure(
            o.view.body.actual_parent == hex::encode(parent)
                && o.view.body.actual_generation == generation,
            "OWNER_CONTINUOUS_PARENT_CHANGED",
        )?;
        o.permission(purpose, payload)
    }
    pub fn search_owned_continuous_window(
        &self,
        request: ContinuousSearchRequest<'_>,
    ) -> Result<OwnedSearchResult> {
        let ContinuousSearchRequest {
            operation_id,
            transactions: raws,
            model,
            input,
            stop,
            deadline,
        } = request;
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        o.ready()?;
        let search_binding = o
            .view
            .body
            .searches
            .iter()
            .find(|v| v.operation == operation_id)
            .ok_or("OWNER_CONTINUOUS_EXACT_SEARCH_REQUIRED")?
            .clone();
        let intent = search_binding.intent;
        let payload = crate::operator_mining_policy::search_payload_sha256(&intent)
            .map_err(continuous_error)?;
        ensure(
            intent.exact_transactions_sha256
                == crate::operator_mining_policy::transactions_sha256(&raws)
                    .map_err(continuous_error)?,
            "OWNER_CONTINUOUS_BATCH",
        )?;
        o.view.check_transactions(&raws).map_err(continuous_error)?;
        if let Some(validation) = &search_binding.pool_validation_operation {
            o.journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .check_pool_search(
                    validation,
                    &o.view.body.actual_parent,
                    o.view.body.actual_generation,
                    &o.view.body.declared_binding,
                    &intent.exact_transactions_sha256,
                    &intent.exact_group_ids,
                )
                .map_err(continuous_error)?;
        }
        o.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .check_nonce_window(
                intent.nonce_first,
                intent
                    .nonce_first
                    .checked_add(intent.nonce_count - 1)
                    .ok_or("NONCE")?,
            )
            .map_err(continuous_error)?;
        let permit = self.continuous_pair(&o, "search", &payload)?;
        ensure(
            permit.allocation.claim().operation == operation_id,
            "OWNER_CONTINUOUS_EXACT_OPERATION",
        )?;
        let operation = o.operation(&permit, None)?;
        let miner = bytes32(hex::decode(&intent.miner).map_err(|_| "OWNER_CONTINUOUS_MINER_HEX")?)?;
        let parent = bytes32(
            hex::decode(&permit.allocation.claim().parent)
                .map_err(|_| "OWNER_CONTINUOUS_PARENT_HEX")?,
        )?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let _scope = o.enter(
            permit.clone(),
            None,
            checkpoint.clone(),
            Binding {
                tx: Some(intent.exact_transactions_sha256.clone()),
                miner: Some(miner),
                height: Some(height),
                pool: None,
            },
        )?;
        let progress = || {
            ensure(
                !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline,
                "OWNER_CONTINUOUS_STOPPED",
            )?;
            permit.progress().map_err(continuous_error)?;
            checkpoint.checkpoint()
        };
        let on_progress = |_| progress();
        let control = ExecutionControl::new(
            &on_progress,
            operation.worker_accounting().map_err(continuous_error)?,
        );
        let result = (|| -> Result<crate::mining::OwnedWindowTrace> {
            progress()?;
            if search_binding.pool_validation_operation.is_some() {
                let (_, limits) = self.continuous_pool_configuration()?;
                ensure(
                    self.continuous_pool_selected_raws(&limits, &intent.exact_group_ids)? == raws,
                    "OWNER_CONTINUOUS_POOL_SEARCH_RAW_BINDING",
                )?;
            }
            self.continuous_task_binding(&permit, model, input)?;
            let prepared = self.prepare_registered_material_controlled(
                parent,
                raws,
                miner,
                intent.timestamp,
                intent.nonce_count,
                model,
                input,
                &control,
            )?;
            let mut trace =
                prepared.search_owned_window(intent.nonce_first, intent.nonce_count, &progress)?;
            if let Err(e) = o.ready() {
                trace.packet = None;
                trace.stopped = true;
                trace.error = Some(e.to_string());
            }
            Ok(trace)
        })();
        // All real scoped workers have joined in original executor before finish.
        let settled = operation.finish().map_err(continuous_error)?;
        let trace = match result {
            Ok(v) => v,
            Err(e) => crate::mining::OwnedWindowTrace {
                packet: None,
                trials: Vec::new(),
                stopped: true,
                error: Some(e.to_string()),
            },
        };
        let trials = trace.trials.len() as u64;
        let complete = trace.trials.iter().filter(|t| t.complete_proof).count() as u64;
        let raw = trace.packet.as_ref().map(Packet::encode).transpose()?;
        let packet_hash = raw
            .as_deref()
            .map(crate::operator_task_policy::digest_bytes);
        let published = o
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .search_result(
                operation_id.to_owned(),
                packet_hash.clone(),
                hex::encode(parent),
                permit.allocation.claim().generation,
                trials,
            )
            .map_err(continuous_error);
        let error = trace
            .error
            .or_else(|| published.err().map(|e| e.to_string()));
        let packet = if error.is_none()
            && settled.accounting_record_persisted
            && !settled.actual.accounting_unavailable
        {
            trace.packet
        } else {
            None
        };
        Ok(OwnedSearchResult {
            schema: "restricted-owner-continuous-search-v1",
            operation_id: operation_id.to_owned(),
            actual_trials: trials,
            complete_proofs: complete,
            nonce_trials: trace.trials,
            native_error: error,
            accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
            last_nonce: if trials == 0 {
                None
            } else {
                intent.nonce_first.checked_add(trials - 1)
            },
            packet,
            packet_sha256: packet_hash,
            stopped: trace.stopped,
            cpu: settled.actual,
            stage_preemption: false,
            public_network_ready: false,
        })
    }
    /// Local winner must link a real local Search claim, full task/class and
    /// result, unlike a separately authenticated receiver-origin attestation.
    pub fn validate_owned_continuous_winner(
        &mut self,
        packet: Packet,
        search_operation: &str,
        observed_now: u64,
    ) -> Result<OwnedMutationResult> {
        self.continuous_validate(
            packet,
            Some(search_operation),
            "winner-validation",
            observed_now,
        )
    }
    pub fn receive_owned_continuous_packet(
        &mut self,
        packet: Packet,
        observed_now: u64,
    ) -> Result<OwnedMutationResult> {
        self.continuous_validate(packet, None, "receiver-validation", observed_now)
    }
    fn continuous_validate(
        &mut self,
        packet: Packet,
        search: Option<&str>,
        purpose: &str,
        observed_now: u64,
    ) -> Result<OwnedMutationResult> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        o.ready()?;
        let digest = crate::operator_task_policy::digest_bytes(&packet.encode()?);
        let raw_permission = o
            .view
            .permission(purpose, &digest)
            .map_err(continuous_error)?;
        ensure(
            hex::encode(packet.header.work_task) == raw_permission.claim().native_task,
            "OWNER_CONTINUOUS_PACKET_TASK",
        )?;
        if let Some(search) = search {
            let journal = o
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
            let c = journal.claim(search).map_err(continuous_error)?;
            let result = journal.result(search).map_err(continuous_error)?;
            ensure(
                c.purpose == "search"
                    && c.native_task == raw_permission.claim().native_task
                    && c.instance_class == raw_permission.claim().instance_class
                    && c.task_binding == raw_permission.claim().task_binding
                    && result.0.as_deref() == Some(digest.as_str())
                    && result.1 == raw_permission.claim().parent
                    && result.2 == raw_permission.claim().generation,
                "OWNER_CONTINUOUS_RETAINED_SEARCH_REQUIRED",
            )?;
        }
        let permit = self.continuous_pair(&o, purpose, &digest)?;
        let operation = o.operation(&permit, None)?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let _scope = o.enter(
            permit.clone(),
            None,
            checkpoint.clone(),
            Binding::packet(&packet)?,
        )?;
        let progress = || {
            permit.progress().map_err(continuous_error)?;
            checkpoint.checkpoint()
        };
        let on_progress = |_| progress();
        let control = ExecutionControl::new(
            &on_progress,
            operation.worker_accounting().map_err(continuous_error)?,
        );
        let result = (|| {
            progress()?;
            self.continuous_actual_packet_binding(&permit, &packet)?;
            if let Some(id) = self.check_admission_context(&packet, observed_now)? {
                return Ok(id);
            }
            let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |_| progress())?;
            self.admit_work_checked_with_control(checked, observed_now, &control)
        })();
        let settled = operation.finish().map_err(continuous_error)?;
        Ok(OwnedMutationResult {
            schema: "restricted-owner-continuous-validation-v1",
            native_id: result.as_ref().ok().copied(),
            native_error: result.err().map(|e: Error| e.to_string()),
            cpu: settled.actual,
            durable_result_preserved: true,
            accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
            public_network_ready: false,
        })
    }
    pub fn activate_owned_continuous_packet(
        &mut self,
        tip: Hash,
        receiver: bool,
        observed_now: u64,
    ) -> Result<OwnedMutationResult> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        o.ready()?;
        let raw: Vec<u8> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [tip.as_slice()],
            |r| r.get(0),
        )?;
        let packet = Packet::decode(&raw)?;
        ensure(
            hex::encode(packet.header.work_task) == o.view.body.declared_binding.task.native_task,
            "OWNER_CONTINUOUS_PACKET_TASK",
        )?;
        let permit = self.continuous_pair(
            &o,
            if receiver {
                "receiver-activate"
            } else {
                "activate"
            },
            &crate::operator_task_policy::digest_bytes(&raw),
        )?;
        let operation = o.operation(&permit, None)?;
        let _scope = o.enter(
            permit,
            None,
            operation.checkpoint_handle().map_err(continuous_error)?,
            Binding::none(),
        )?;
        let result = (|| {
            operation
                .checkpoint_handle()
                .map_err(continuous_error)?
                .checkpoint()?;
            self.activate_observed(tip, observed_now)
        })();
        let settled = operation.finish().map_err(continuous_error)?;
        Ok(OwnedMutationResult {
            schema: "restricted-owner-continuous-activation-v1",
            native_id: result.as_ref().ok().copied(),
            native_error: result.err().map(|e: Error| e.to_string()),
            cpu: settled.actual,
            durable_result_preserved: true,
            accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
            public_network_ready: false,
        })
    }
}

/// Original Native queue outcome is separate from the final durable CPU record.
/// A late accounting fault cannot retract an already committed group.
#[derive(serde::Serialize)]
pub struct OwnedContinuousPoolResult {
    pub schema: &'static str,
    pub operation_id: String,
    pub native_result: Option<serde_json::Value>,
    pub native_error: Option<String>,
    pub cpu: crate::ingress::public_v3::ServiceMutationCpuSettlement,
    pub accounting_record_persisted: bool,
    pub accounting_fault_persistence_failed: bool,
    pub durable_result_preserved: bool,
    pub public_network_ready: bool,
}

#[derive(serde::Serialize)]
pub struct OwnedContinuousLeaseResult {
    pub schema: &'static str,
    pub operation_id: String,
    pub native_result: Option<serde_json::Value>,
    pub native_error: Option<String>,
    pub cpu: crate::ingress::public_v3::ServiceMutationCpuSettlement,
    pub accounting_record_persisted: bool,
    pub accounting_fault_persistence_failed: bool,
    pub durable_result_preserved: bool,
    pub public_network_ready: bool,
}

impl Node {
    /// Protected Root metadata read, in SQL group ordinal/row position order.
    /// It neither reconciles nor previews M06 and issues no operation permit.
    /// Terminal groups are retained; outside cannot omit them from Selection.
    pub fn continuous_pool_snapshot(&self) -> Result<serde_json::Value> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        o.ready()?;
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let (parent, generation) = self.active()?;
        let (context, limits) = self.continuous_pool_configuration()?;
        let groups = self.continuous_pool_group_snapshot(&limits)?;
        let mut rows = Vec::new();
        let mut records = 0usize;
        let mut bytes = 0usize;
        let journal = o
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
        for (ordinal, group) in groups.into_iter().enumerate() {
            let admission = journal
                .pool_admission(&hex::encode(group.id))
                .map_err(continuous_error)?;
            let raw_digest = crate::operator_mining_policy::transactions_sha256(&group.raws)
                .map_err(continuous_error)?;
            ensure(
                admission.transactions_sha256 == raw_digest,
                "OWNER_CONTINUOUS_POOL_SNAPSHOT_BINDING",
            )?;
            let row_bytes = group.raws.iter().try_fold(0usize, |sum, raw| {
                sum.checked_add(raw.len())
                    .ok_or("OWNER_CONTINUOUS_POOL_SNAPSHOT_BYTES")
            })?;
            records = records
                .checked_add(group.raws.len())
                .ok_or("OWNER_CONTINUOUS_POOL_SNAPSHOT_COUNT")?;
            bytes = bytes
                .checked_add(row_bytes)
                .ok_or("OWNER_CONTINUOUS_POOL_SNAPSHOT_BYTES")?;
            rows.push(
                serde_json::json!({"ordinal":ordinal,"group":hex::encode(group.id),
                "original_admission_operation":admission.operation,
                "exact_transactions_sha256":raw_digest,
                "ordered_raw_sha256":group.raws.iter().map(|raw|
                    crate::operator_task_policy::digest_bytes(raw)).collect::<Vec<_>>(),
                "state":group.state,"reason":group.reason,"raw_bytes":row_bytes,
                "native_task":admission.native_task,"instance_class":admission.instance_class,
                "admission_task_binding":admission.task_binding}),
            );
        }
        let head = journal.anchor();
        drop(journal);
        ensure(
            self.active()? == (parent, generation),
            "OWNER_CONTINUOUS_POOL_SNAPSHOT_PAIR",
        )?;
        let result = serde_json::json!({"schema":"restricted-continuous-pool-snapshot-v1",
            "identity":o.view.body.identity,"parent":hex::encode(parent),"generation":generation,
            "pool_context":hex::encode(context),"limits":limits,
            "limits_sha256":crate::operator_task_policy::digest_bytes(&serde_json::to_vec(&limits)?),
            "retained_records":records,"retained_raw_bytes":bytes,"groups":rows,
            "journal_head":head,"work_capability_issued":false,"classification_current":false,
            "scope":"same-operator-read-only-retained-sql-and-fsynced-admission-facts"});
        ensure(
            serde_json::to_vec(&result)?.len() <= 262144,
            "OWNER_CONTINUOUS_POOL_SNAPSHOT_LIMIT",
        )?;
        Ok(result)
    }
    pub fn continuous_process_cpu_snapshot(&self) -> Result<serde_json::Value> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        o.ready()?;
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        o.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .process_cpu_snapshot()
            .map_err(continuous_error)
    }
    /// This gate is read-only: no CPU row or claim can be appended between the
    /// externally signed prior journal and BudgetIncrease::increase.
    fn check_continuous_lease_transition(
        &self,
        o: &ContinuousOwner,
        inputs: &policy::Inputs,
        next: &VerifiedView,
    ) -> Result<()> {
        let Some(reference) = &inputs.lease_transition else {
            ensure(
                next.body.declared_binding == o.view.body.declared_binding,
                "OWNER_CONTINUOUS_EXPLICIT_LEASE_EDGE_REQUIRED",
            )?;
            return Ok(());
        };
        let edge = &reference.edge;
        edge.check_declarations(&o.view.body.declared_binding, &next.body.declared_binding)
            .map_err(continuous_error)?;
        let (parent, generation) = self.active()?;
        ensure(
            edge.actual_parent == hex::encode(parent)
                && edge.actual_generation == generation
                && next.body.lease_transition_operation.as_deref()
                    == Some(reference.operation.as_str()),
            "OWNER_CONTINUOUS_LEASE_SETTLED_PAIR",
        )?;
        let budget = inputs
            .budget_authority
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_LEASE_BUDGET_REQUIRED")?;
        ensure(
            inputs.raw_budget.is_some()
                && budget.expected.delegation.declared_binding == next.body.declared_binding
                && budget.expected.delegation.registry2_declaration_digest
                    == edge.new_registry2_declaration_digest
                && budget.expected.delegation.context.actual_parent == edge.actual_parent,
            "OWNER_CONTINUOUS_LEASE_NEW_DECLARATION",
        )?;
        o.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .check_lease_witness(&reference.operation, edge)
            .map_err(continuous_error)
    }
    /// A distinct old-budget operation. Outside must observe its actual
    /// settled head BEFORE signing the next budget and TaskView. This is not a
    /// packet admission, refund or new lease declaration by the Node.
    pub fn reconcile_owned_continuous_lease(
        &self,
        input: policy::LeaseTransitionInput,
    ) -> Result<OwnedContinuousLeaseResult> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        o.ready()?;
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let now = crate::operator_task_policy::now_ns().map_err(continuous_error)?;
        let edge = &input.edge;
        let mut new_binding = o.view.body.declared_binding.clone();
        let raw =
            hex::decode(&edge.new_complete_lease).map_err(|_| "OWNER_CONTINUOUS_LEASE_HEX")?;
        new_binding.task.lease_sha256 = crate::operator_task_policy::digest_bytes(&raw);
        edge.check_declarations(&o.view.body.declared_binding, &new_binding)
            .map_err(continuous_error)?;
        ensure(
            input.permission.authority.identity == o.view.body.identity
                && input.permission.authority.expected.identity == o.view.body.identity,
            "OWNER_CONTINUOUS_LEASE_OUTSIDE_IDENTITY",
        )?;
        let allocation = Arc::new(
            crate::operator_continuous_recipient::authenticate(
                &input.permission.raw,
                &input.permission.authority,
                now,
            )
            .map_err(continuous_error)?,
        );
        let (parent, generation) = self.active()?;
        let c = allocation.claim();
        ensure(
            allocation.body().identity == o.view.body.identity
                && allocation.body().declared_binding == o.view.body.declared_binding
                && c.purpose == "lease-reconcile"
                && c.payload == edge.payload().map_err(continuous_error)?
                && c.parent == hex::encode(parent)
                && c.generation == generation,
            "OWNER_CONTINUOUS_LEASE_PERMISSION",
        )?;
        let operation_id = c.operation.clone();
        o.journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .reserve_allocation(&allocation)
            .map_err(continuous_error)?;
        let permit = Arc::new(Permit {
            view: o.view.clone(),
            allocation,
            epoch: o.epoch.clone(),
            expected_epoch: o.view_epoch,
            unavailable: o.unavailable.clone(),
        });
        let operation = o.operation(&permit, None)?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let _reset = o.enter(permit.clone(), None, checkpoint.clone(), Binding::none())?;
        let actual = (|| -> Result<serde_json::Value> {
            checkpoint.checkpoint()?;
            let packet = self.packet(parent)?;
            let task = crate::digest(&edge.native_task)?;
            ensure(
                packet.header.work_task == task,
                "OWNER_CONTINUOUS_LEASE_PACKET_TASK",
            )?;
            let next_height = packet.header.height.checked_add(1).ok_or("HEIGHT")?;
            let old = self
                .lifecycle_task_lease(packet.header.parent, task, packet.header.height)?
                .encode()
                .map_err(|_| "OWNER_CONTINUOUS_LEASE")?;
            checkpoint.checkpoint()?;
            let new = self
                .lifecycle_task_lease(parent, task, next_height)?
                .encode()
                .map_err(|_| "OWNER_CONTINUOUS_LEASE")?;
            let mut found = 0u64;
            for raw in &packet.transactions {
                checkpoint.checkpoint()?;
                let envelope =
                    Envelope::decode(raw).map_err(|_| "OWNER_CONTINUOUS_LEASE_ENVELOPE")?;
                if envelope.tag == 22 {
                    let renewal=trnm_protocol::qualified_work_task::lifecycle_v3::AtomicRenewTaskV3::decode(&envelope.payload)
                        .map_err(|_|"OWNER_CONTINUOUS_LEASE_RENEWAL")?;
                    let encoded = renewal
                        .lease
                        .encode()
                        .map_err(|_| "OWNER_CONTINUOUS_LEASE")?;
                    if encoded == new {
                        found = found.checked_add(1).ok_or("OWNER_CONTINUOUS_LEASE_COUNT")?;
                    }
                }
            }
            ensure(found == 1, "OWNER_CONTINUOUS_EXACT_RENEWAL_REQUIRED")?;
            edge.check_actual(parent, generation, &old, &new, &packet.encode()?)
                .map_err(continuous_error)?;
            let manifest = self
                .eligible_work_task(parent, task, next_height)?
                .ok_or("OWNER_CONTINUOUS_COMPLETE_REGISTRATION_REQUIRED")?;
            ensure(
                manifest.purpose == TaskPurpose::Maintenance
                    && hex::encode(manifest.model) == new_binding.task.native_model
                    && hex::encode(manifest.input) == new_binding.task.native_input,
                "OWNER_CONTINUOUS_LEASE_FULL_TASK",
            )?;
            permit.progress().map_err(continuous_error)?;
            checkpoint.checkpoint()?;
            let recorded = o
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .record_lease_witness(operation_id.clone(), edge.clone())
                .map_err(continuous_error);
            if recorded.is_err() {
                let _fault = o.sink.persist_unknown();
            }
            Ok(
                serde_json::json!({"lease_witness_recorded":recorded.is_ok(),
                "actual_parent":hex::encode(parent),"actual_generation":generation,
                "actual_renewal_packet_sha256":edge.renewal_packet_sha256,
                "work_capability_issued":false,"new_budget_installed":false}),
            )
        })();
        let settled = operation.finish().map_err(continuous_error)?;
        Ok(OwnedContinuousLeaseResult {
            schema: "restricted-owner-continuous-lease-reconcile-result-v1",
            operation_id,
            native_result: actual.as_ref().ok().cloned(),
            native_error: actual.err().map(|e| e.to_string()),
            cpu: settled.actual,
            accounting_record_persisted: settled.accounting_record_persisted,
            accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
            durable_result_preserved: true,
            public_network_ready: false,
        })
    }
    fn record_continuous_pool_validation(
        &self,
        operation: &str,
        batch: &PoolBatch,
    ) -> Result<bool> {
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        let body = history::PoolValidation {
            operation: operation.to_owned(),
            parent: hex::encode(batch.parent),
            generation: batch.generation,
            native_task: o.view.body.declared_binding.task.native_task.clone(),
            instance_class: o.view.body.declared_binding.instance_class.clone(),
            task_binding: crate::operator_continuous_recipient::declared_binding_digest(
                &o.view.body.declared_binding,
            )
            .map_err(continuous_error)?,
            pool_context: hex::encode(batch.context),
            transactions_sha256: crate::operator_mining_policy::transactions_sha256(
                &batch.transactions,
            )
            .map_err(continuous_error)?,
            groups: batch.groups.iter().map(hex::encode).collect(),
        };
        let recorded = o
            .journal
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
            .record_pool_validation(body)
            .map_err(continuous_error);
        if recorded.is_err() {
            let _fault = o.sink.persist_unknown();
        }
        Ok(recorded.is_ok())
    }
    /// The original public interval is the only debit. Exact whole new bundle
    /// is selected cheaply before State/lease/M06 or a persistent claim.
    pub(crate) fn begin_continuous_public_pool_scope(
        &self,
        raws: &[Vec<u8>],
        context: Hash,
        cpu: ServiceMutationCpuCheckpoint,
    ) -> Result<Option<PublicContinuousScope>> {
        let Some(o) = &self.continuous_owner else {
            return Ok(None);
        };
        o.ready()?;
        ensure(o.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        let digest =
            crate::operator_mining_policy::transactions_sha256(raws).map_err(continuous_error)?;
        let matches: Vec<_> = o
            .view
            .pool_selections
            .iter()
            .filter(|s| {
                s.body().purpose == crate::operator_continuous_pool::Purpose::SubmitBundle
                    && s.body().exact_new_transactions_sha256 == digest
                    && s.body().pool_context == hex::encode(context)
            })
            .collect();
        ensure(
            matches.len() == 1,
            "OWNER_CONTINUOUS_EXACT_POOL_OPERATION_REQUIRED",
        )?;
        let selection = matches[0].clone();
        let (parent, generation) = self.active()?;
        selection
            .check_actual_parent(parent, generation, context)
            .map_err(continuous_error)?;
        let payload = selection
            .body()
            .payload_sha256()
            .map_err(continuous_error)?;
        let permit = self.continuous_pair(o, "pool-submit-bundle", &payload)?;
        let c = permit.allocation.claim();
        let observed = ObservedOperation::begin(
            o.journal.clone(),
            Start {
                scope: scope_id(&c.operation),
                operation: c.operation.clone(),
                linked_startup: None,
                task: c.native_task.clone(),
                class: c.instance_class.clone(),
            },
            cpu,
            o.sink.clone(),
        )
        .map_err(continuous_error)?;
        let (actual_context, limits) = self.continuous_pool_configuration()?;
        ensure(actual_context == context, "OWNER_CONTINUOUS_POOL_CONTEXT")?;
        let selection = self.continuous_bind_pool_selection(selection, &limits, raws)?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let reset = o.enter(
            permit,
            None,
            observed.checkpoint_handle(),
            Binding {
                tx: None,
                miner: Some(limits.preview_miner),
                height: Some(height),
                pool: Some(Arc::new(selection)),
            },
        )?;
        Ok(Some(PublicContinuousScope {
            observed: Some(observed),
            _reset: reset,
        }))
    }
    pub(crate) fn check_continuous_public_pool_binding(&self) -> Result<()> {
        let Some(o) = &self.continuous_owner else {
            return Ok(());
        };
        let active = o.slot()?.ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        let selected = active
            .pool
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        let (_, limits) = self.continuous_pool_configuration()?;
        self.continuous_pool_binding(&active.permit, selected, &limits)
    }
    pub(super) fn continuous_pool_configured(&self) -> Result<()> {
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        owner.ready()?;
        let active = owner
            .slot()?
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        ensure(
            active.pool.is_some(),
            "OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED",
        )?;
        ContinuousScopeCheckpoint(active).check()
    }
    /// Internal operations borrow the *already paid* private exact command.
    /// They never discover a grant from an anonymous body or start another CPU scope.
    pub(super) fn begin_continuous_pool_command(
        &self,
        command: &str,
        raws: &[Vec<u8>],
        context: Hash,
    ) -> Result<OwnerPoolPermit> {
        self.continuous_pool_configured()?;
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        let active = owner
            .slot()?
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        let selected = active
            .pool
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        selected
            .check_internal_command(command, raws)
            .map_err(continuous_error)?;
        let (parent, generation) = self.active()?;
        selected
            .check_actual_parent(parent, generation, context)
            .map_err(continuous_error)?;
        let task = &active.permit.view.body.declared_binding.task;
        let facts = crate::operator_task_policy::pool::PoolFacts {
            parent: hex::encode(parent),
            generation,
            pool_context: hex::encode(context),
            registered_task: task.native_task.clone(),
            lease_sha256: task.lease_sha256.clone(),
            command: command.to_owned(),
            payload_sha256: selected.body().payload_sha256().map_err(continuous_error)?,
        };
        Ok(OwnerPoolPermit {
            facts,
            authentication: OwnerPoolAuthentication::Continuous(ContinuousPoolCheckpoint(active)),
        })
    }
    pub(super) fn continuous_pool_validation_permit(&self) -> Result<Option<OwnerPoolPermit>> {
        let Some(owner) = &self.continuous_owner else {
            return Ok(None);
        };
        let active = owner
            .slot()?
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        let selected = active
            .pool
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
        let (context, _) = self.continuous_pool_configuration()?;
        selected
            .check_actual_parent(self.active()?.0, self.active()?.1, context)
            .map_err(continuous_error)?;
        let task = &active.permit.view.body.declared_binding.task;
        let facts = crate::operator_task_policy::pool::PoolFacts {
            parent: selected.body().parent.clone(),
            generation: selected.body().generation,
            pool_context: hex::encode(context),
            registered_task: task.native_task.clone(),
            lease_sha256: task.lease_sha256.clone(),
            command: selected.body().purpose.claim_purpose().to_owned(),
            payload_sha256: selected.body().payload_sha256().map_err(continuous_error)?,
        };
        Ok(Some(OwnerPoolPermit {
            facts,
            authentication: OwnerPoolAuthentication::Continuous(ContinuousPoolCheckpoint(active)),
        }))
    }
    fn continuous_selected_pool(
        &self,
        operation: &str,
    ) -> Result<crate::operator_continuous_pool::VerifiedSelection> {
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        ensure(owner.slot()?.is_none(), "OWNER_CONTINUOUS_SCOPE_BUSY")?;
        owner.ready()?;
        owner
            .view
            .pool_selections
            .iter()
            .find(|s| s.body().operation == operation)
            .cloned()
            .ok_or_else(|| "OWNER_CONTINUOUS_EXACT_POOL_OPERATION_REQUIRED".into())
    }
    /// Actual SQL group bytes and the fsynced original admission operation are
    /// both mandatory. The signed retained list must be complete, including
    /// terminal groups; it cannot authorize just a chosen scratch subset.
    fn continuous_bind_pool_selection(
        &self,
        mut selected: crate::operator_continuous_pool::VerifiedSelection,
        limits: &PoolLimits,
        new_raws: &[Vec<u8>],
    ) -> Result<crate::operator_continuous_pool::VerifiedSelection> {
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        selected.bind_new(new_raws).map_err(continuous_error)?;
        let groups = self.continuous_pool_actual_groups(limits)?;
        for (group, raws) in &groups {
            let record = {
                let journal = owner
                    .journal
                    .lock()
                    .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?;
                journal
                    .pool_admission(&hex::encode(group))
                    .map_err(continuous_error)?
                    .clone()
            };
            ensure(
                record.native_task == selected.body().native_task
                    && record.instance_class == owner.view.body.declared_binding.instance_class
                    && record.transactions_sha256
                        == crate::operator_mining_policy::transactions_sha256(raws)
                            .map_err(continuous_error)?,
                "OWNER_CONTINUOUS_RETAINED_TASK_CLASS",
            )?;
            selected
                .bind_retained(*group, &record.operation, raws)
                .map_err(continuous_error)?;
        }
        selected.all_retained_bound().map_err(continuous_error)?;
        Ok(selected)
    }
    fn continuous_pool_binding(
        &self,
        permit: &Permit,
        selected: &crate::operator_continuous_pool::VerifiedSelection,
        limits: &PoolLimits,
    ) -> Result<()> {
        let (parent, generation) = self.active()?;
        selected
            .check_actual_parent(
                parent,
                generation,
                crate::digest(&selected.body().pool_context)?,
            )
            .map_err(continuous_error)?;
        ensure(
            crate::operator_task_policy::digest_bytes(&serde_json::to_vec(limits)?)
                == selected.body().limits_sha256,
            "OWNER_CONTINUOUS_POOL_LIMITS",
        )?;
        let checkpoint = self
            .continuous_progress_snapshot()?
            .ok_or("OWNER_CONTINUOUS_SCOPE_REQUIRED")?;
        let progress = || checkpoint.check();
        let owner = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?;
        let model = owner
            .catalog
            .read_role("model", 16384, &progress)
            .map_err(continuous_error)?;
        let input = owner
            .catalog
            .read_role("input", 16384, &progress)
            .map_err(continuous_error)?;
        self.continuous_task_binding(permit, &model, &input)
    }
    pub(super) fn record_continuous_pool_commit(&self, group: Hash, raws: &[Vec<u8>]) {
        let Some(owner) = &self.continuous_owner else {
            return;
        };
        let recorded = (|| -> Result<()> {
            let active = owner
                .slot()?
                .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
            let selection = active
                .pool
                .as_ref()
                .ok_or("OWNER_CONTINUOUS_POOL_PURPOSE_REQUIRED")?;
            ensure(
                selection.body().purpose == crate::operator_continuous_pool::Purpose::SubmitBundle,
                "OWNER_CONTINUOUS_POOL_SUBMIT_PURPOSE",
            )?;
            selection.check_new_bundle(raws).map_err(continuous_error)?;
            owner
                .journal
                .lock()
                .map_err(|_| "OWNER_CONTINUOUS_JOURNAL_UNKNOWN")?
                .record_pool_admission(
                    &active.permit.allocation.claim().operation,
                    hex::encode(group),
                    crate::operator_mining_policy::transactions_sha256(raws)
                        .map_err(continuous_error)?,
                )
                .map_err(continuous_error)
        })();
        if recorded.is_err() {
            let _fault = owner.sink.persist_unknown();
        }
    }
    pub fn operate_owned_continuous_pool(
        &mut self,
        operation_id: &str,
        command: crate::operator_continuous_pool::Command,
    ) -> Result<OwnedContinuousPoolResult> {
        use crate::operator_continuous_pool::{BatchInput, Command};
        let o = self
            .continuous_owner
            .as_ref()
            .ok_or("OWNER_CONTINUOUS_MODE_REQUIRED")?
            .clone();
        let selection = self.continuous_selected_pool(operation_id)?;
        command.check_selection(selection.body())?;
        let new_raws = command.new_bundle()?;
        let (context, limits) = match &command {
            Command::Enable { limits } => {
                let raw = serde_json::to_vec(limits)?;
                (
                    hash(
                        b"native-local-queued-pnx1-v2",
                        &[
                            &self.settings.network(),
                            &self.settings.parameters(),
                            &self.settings.genesis(),
                            &raw,
                        ],
                    ),
                    (**limits).clone(),
                )
            }
            _ => self.continuous_pool_configuration()?,
        };
        let (parent, generation) = self.active()?;
        limits.validate()?;
        selection
            .check_actual_parent(parent, generation, context)
            .map_err(continuous_error)?;
        let payload = selection
            .body()
            .payload_sha256()
            .map_err(continuous_error)?;
        let permit =
            self.continuous_pair(&o, selection.body().purpose.claim_purpose(), &payload)?;
        ensure(
            permit.allocation.claim().operation == operation_id,
            "OWNER_CONTINUOUS_EXACT_OPERATION",
        )?;
        let operation = o.operation(&permit, None)?;
        let checkpoint = operation.checkpoint_handle().map_err(continuous_error)?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        // Bound SQL loading happens after the original CPU interval starts. No
        // owner/global mutex is held during group decode, State or execution.
        let selected = self.continuous_bind_pool_selection(selection, &limits, &new_raws)?;
        let _reset = o.enter(
            permit.clone(),
            None,
            checkpoint.clone(),
            Binding {
                tx: None,
                miner: Some(limits.preview_miner),
                height: Some(height),
                pool: Some(Arc::new(selected.clone())),
            },
        )?;
        let progress = |_| checkpoint.checkpoint();
        let control = ExecutionControl::new(
            &progress,
            operation.worker_accounting().map_err(continuous_error)?,
        );
        let native = (|| -> Result<serde_json::Value> {
            self.continuous_pool_binding(&permit, &selected, &limits)?;
            Ok(match command {
                Command::Enable { limits } => {
                    serde_json::json!({"context":hex::encode(self.enable_local_mempool(*limits)?)})
                }
                Command::Reconcile {} => serde_json::to_value(self.pool_reconcile()?)?,
                Command::SubmitBundle { .. } => {
                    serde_json::to_value(self.pool_submit_bundle_with_control(new_raws, &control)?)?
                }
                Command::Status {} => serde_json::to_value(self.pool_status()?)?,
                Command::MiningBatch {
                    max_records,
                    max_bytes,
                } => serde_json::to_value(BatchInput::from_actual(self.pool_mining_batch(
                    parent,
                    generation,
                    max_records as usize,
                    max_bytes as usize,
                )?))?,
                Command::ValidateBatch { batch } => {
                    let actual = batch.actual()?;
                    let count = self.pool_validate_batch(&actual)?;
                    let recorded = self.record_continuous_pool_validation(operation_id, &actual)?;
                    serde_json::json!({"typed_gate_admissions":count,"batch_validated":true,"validation_recorded":recorded})
                }
                Command::Prune { group } => {
                    self.pool_prune_terminal(crate::digest(&group)?)?;
                    serde_json::json!({"pruned":group})
                }
            })
        })();
        let settled = operation.finish().map_err(continuous_error)?;
        Ok(OwnedContinuousPoolResult {
            schema: "restricted-owner-continuous-pool-result-v1",
            operation_id: operation_id.to_owned(),
            native_result: native.as_ref().ok().cloned(),
            native_error: native.err().map(|e| e.to_string()),
            cpu: settled.actual,
            accounting_record_persisted: settled.accounting_record_persisted,
            accounting_fault_persistence_failed: settled.accounting_fault_persistence_failed,
            durable_result_preserved: true,
            public_network_ready: false,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_owner_tests.rs"]
mod tests;
