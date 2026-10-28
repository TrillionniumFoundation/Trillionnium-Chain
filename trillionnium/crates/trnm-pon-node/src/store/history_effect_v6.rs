//! Explicit research namespace for irreversible History predebits and atomic
//! effect markers. It does not reinterpret V5, authorize consensus or expose a
//! general Node. Only authenticated local envelopes can select native effects.
use super::*;
use crate::ingress::public_v3::{
    ServiceMutationCpuCheckpoint, ServiceMutationCpuDomain, ServiceMutationCpuOperation,
    ServiceMutationCpuSettlement,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

mod epoch_recovery_v1;
mod journal;
mod policy;
mod recovery;
mod storage;
#[cfg(all(test, target_os = "linux"))]
mod tests;
pub use epoch_recovery_v1::{
    prepare_history_settled_epoch_v1_recovery, repair_history_settled_epoch_v1_publication,
    ProtectedHistorySettledEpochV1Input,
};
pub use journal::publication::{
    repair_history_journal_publication_v1, ProtectedHistoryJournalPublicationV1Input,
};
use policy::{EffectMarker, Frontier, Purpose};
pub use policy::{
    ProtectedHistoryV6BudgetInput, ProtectedHistoryV6Input, ProtectedHistoryV6RecoveryInput,
};
pub use recovery::prepare_history_effect_v6_recovery;

pub(super) const DDL: &str = "CREATE TABLE history_effect_v6(operation TEXT PRIMARY KEY NOT NULL CHECK(length(operation)=64),intent BLOB UNIQUE NOT NULL CHECK(length(intent)=32),marker BLOB NOT NULL CHECK(length(marker)>0 AND length(marker)<=16384));";

/// Only this module can create a token after exact outside-anchor validation
/// and a durable startup predebit. It carries no measured CPU receipt.
pub(crate) struct VerifiedEpoch {
    _sealed: (),
}

/// Installs only a separately signed finite budget. The returned local anchor
/// is an observation: an outside authority must independently pin/sign it in a
/// later startup claim. This API never creates a startup operation or Node.
pub fn prepare_history_effect_v6_budget(input: ProtectedHistoryV6BudgetInput) -> Result<Value> {
    let c = input.config;
    let mut journal = journal::Journal::open(
        &c.journal_path,
        input.expected_uid,
        &c.identity,
        &c.outside_latest_anchor,
    )?;
    journal.install_budget(&c.signed_budget)?;
    Ok(journal.observation())
}

#[derive(Clone)]
struct Active {
    pending: journal::Pending,
    checkpoint: ServiceMutationCpuCheckpoint,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl Active {
    fn check(&self) -> Result<()> {
        ensure(
            !self.cancelled.load(Ordering::Acquire),
            "HISTORY_V6_CANCELLED",
        )?;
        ensure(Instant::now() < self.deadline, "HISTORY_V6_DEADLINE")?;
        let at = policy::now()?;
        ensure(
            self.pending.operation.issued_ns <= at
                && at < self.pending.operation.expires_ns
                && at < self.pending.budget_expires_ns,
            "HISTORY_V6_OPERATION_EXPIRED",
        )?;
        self.checkpoint.checkpoint()?;
        ensure(
            self.checkpoint.actual_live_paid_cpu_ns()? <= self.pending.operation.allowance.cpu_ns,
            "HISTORY_V6_OPERATION_CPU_LIMIT",
        )
    }
}
#[derive(Clone)]
pub(super) struct Owner {
    pub(super) marker: Vec<u8>,
    identity: policy::Identity,
    journal: Arc<Mutex<journal::Journal>>,
    cpu: ServiceMutationCpuDomain,
    catalog: Arc<crate::operator_continuous_policy::HeldCatalog>,
    binding: crate::operator_continuous_recipient::DeclaredBinding,
    active: Arc<Mutex<Option<Active>>>,
    unavailable: Arc<AtomicBool>,
}
impl Owner {
    fn journal(&self) -> Result<std::sync::MutexGuard<'_, journal::Journal>> {
        self.journal
            .lock()
            .map_err(|_| "HISTORY_V6_JOURNAL_UNKNOWN".into())
    }
    fn slot(&self) -> Result<Option<Active>> {
        Ok(self
            .active
            .lock()
            .map_err(|_| "HISTORY_V6_SCOPE_UNKNOWN")?
            .clone())
    }
    pub(super) fn checkpoint(&self) -> Result<()> {
        ensure(
            !self.unavailable.load(Ordering::Acquire),
            "HISTORY_V6_UNAVAILABLE",
        )?;
        let active = self
            .slot()?
            .ok_or("HISTORY_V6_EXPLICIT_PAID_SCOPE_REQUIRED")?;
        active.check()?;
        self.catalog
            .ready()
            .map_err(|_| "HISTORY_V6_CATALOG_CHANGED")?;
        Ok(())
    }
    fn start(&self, raw: &[u8], expected: Purpose, deadline: Instant) -> Result<Running> {
        ensure(
            !self.unavailable.load(Ordering::Acquire) && self.slot()?.is_none(),
            "HISTORY_V6_UNAVAILABLE",
        )?;
        let verified = policy::operation(raw, &self.identity, policy::now()?)?;
        ensure(
            verified.body.purpose == expected
                && verified.body.binding.as_ref() == Some(&self.binding),
            "HISTORY_V6_PURPOSE_OR_TASK",
        )?;
        // Reserve synchronously BEFORE the CPU interval, JSON Page or packet.
        // Request fields and a syntax-valid envelope confer no permission.
        let pending = self.journal()?.reserve(raw)?;
        let cpu = match self.cpu.begin() {
            Ok(cpu) => cpu,
            Err(error) => {
                if !self.cpu.accounting_available() {
                    self.unavailable.store(true, Ordering::Release);
                }
                self.journal()?
                    .not_started(&pending.operation.operation_id, &error)?;
                return Err(error);
            }
        };
        self.enter(pending, cpu, deadline)
    }
    fn enter(
        &self,
        pending: journal::Pending,
        cpu: ServiceMutationCpuOperation,
        deadline: Instant,
    ) -> Result<Running> {
        let active = Active {
            pending,
            checkpoint: cpu.checkpoint_handle(),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline,
        };
        let mut slot = self.active.lock().map_err(|_| "HISTORY_V6_SCOPE_UNKNOWN")?;
        ensure(slot.is_none(), "HISTORY_V6_SCOPE_BUSY")?;
        *slot = Some(active.clone());
        Ok(Running {
            owner: self.clone(),
            active,
            cpu: Some(cpu),
            settled: false,
        })
    }
}
struct Running {
    owner: Owner,
    active: Active,
    cpu: Option<ServiceMutationCpuOperation>,
    settled: bool,
}
impl Running {
    fn checkpoint(&self) -> Result<()> {
        self.active.check()
    }
    fn worker_accounting(
        &self,
    ) -> Result<&dyn trnm_mvcc_fee::pon_executor::ExecutionWorkerAccounting> {
        Ok(self
            .cpu
            .as_ref()
            .ok_or("HISTORY_V6_SCOPE_UNKNOWN")?
            .worker_accounting())
    }
    fn finish(
        mut self,
        native: Result<Hash>,
        marker_readback: Result<Option<EffectMarker>>,
        boundary: Option<String>,
    ) -> Result<HistoryEffectV6Result> {
        // All native children have already joined on success, failure and
        // cancellation. The ORIGINAL shared operation is settled exactly once.
        let cpu = self.cpu.take().ok_or("HISTORY_V6_SCOPE_UNKNOWN")?.finish();
        // Once the native call and original CPU finish have returned, no late
        // journal/readback/lock error may discard either actual observation.
        let mut errors = Vec::new();
        let (marker, effect_readback_known) = match marker_readback {
            Ok(marker) => (marker, true),
            Err(error) => {
                errors.push(format!("HISTORY_V6_MARKER_READBACK:{error}"));
                (None, false)
            }
        };
        let (persisted, operation_closed, observation) = match self.owner.journal() {
            Ok(mut journal) => {
                let persisted = journal.settle(
                    &self.active.pending.operation.operation_id,
                    &native,
                    &cpu,
                    marker.clone(),
                    effect_readback_known,
                );
                let ok = persisted.is_ok();
                if let Err(error) = persisted {
                    errors.push(error.to_string());
                }
                (ok, ok && journal.pending().is_none(), journal.observation())
            }
            Err(error) => {
                errors.push(error.to_string());
                (
                    false,
                    false,
                    serde_json::json!({
                        "schema":"restricted-history-effect-journal-unavailable-v6",
                        "observed_anchor":null,"accounting_available":false
                    }),
                )
            }
        };
        let known = journal::CpuReceipt::from(&cpu).known()
            && cpu
                .total_cpu_ns
                .is_some_and(|v| v <= self.active.pending.operation.allowance.cpu_ns);
        match self.owner.active.lock() {
            Ok(mut slot) => *slot = None,
            Err(_) => errors.push("HISTORY_V6_SCOPE_UNKNOWN".into()),
        }
        if !operation_closed || !known || !errors.is_empty() {
            self.owner.unavailable.store(true, Ordering::Release);
        }
        self.settled = true;
        Ok(HistoryEffectV6Result {
            schema: "restricted-history-effect-result-v6",
            operation_id: self.active.pending.operation.operation_id.clone(),
            requested_target: self.active.pending.operation.target.clone(),
            native_id: native.as_ref().ok().map(hex::encode),
            native_error: native.err().map(|e| e.to_string()),
            cpu,
            accounting_record_persisted: persisted,
            operation_closed,
            within_original_allowance: known,
            accounting_error: (!errors.is_empty()).then(|| errors.join(";")),
            terminal_boundary_error: boundary,
            marker,
            journal: observation,
            production_qualified: false,
        })
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if !self.settled {
            // The durable intent and complete predebit already exist. Drop is
            // not a receipt and cannot turn pending worker CPU into zero.
            self.owner.unavailable.store(true, Ordering::Release);
            if let Ok(mut slot) = self.owner.active.lock() {
                *slot = None;
            }
        }
    }
}

#[derive(Serialize)]
pub struct HistoryEffectV6Result {
    pub schema: &'static str,
    pub operation_id: String,
    pub requested_target: String,
    pub native_id: Option<String>,
    pub native_error: Option<String>,
    pub cpu: ServiceMutationCpuSettlement,
    pub accounting_record_persisted: bool,
    pub operation_closed: bool,
    pub within_original_allowance: bool,
    pub accounting_error: Option<String>,
    pub terminal_boundary_error: Option<String>,
    marker: Option<EffectMarker>,
    pub journal: Value,
    pub production_qualified: bool,
}
impl HistoryEffectV6Result {
    pub fn known_success(&self) -> bool {
        self.native_id.as_ref() == Some(&self.requested_target)
            && self.native_error.is_none()
            && self.accounting_record_persisted
            && self.operation_closed
            && self.accounting_error.is_none()
            && self.within_original_allowance
            && !self.cpu.accounting_unavailable
            && !self.cpu.live_refused
            && self.terminal_boundary_error.is_none()
    }
}

/// There is no Node getter, Deref, background service or generic recovery. Even
/// after successful reconciliation, each effect still needs a fresh V6 claim.
pub struct HistoryEffectV6 {
    node: Node,
    owner: Owner,
    startup_result: HistoryEffectV6Result,
    initial_cpu: crate::ingress::public_v3::scalar_cpu::ServiceMutationCpuObservation,
}
/// This handle can only request cancellation of the named currently running
/// operation. It grants no scope, CPU credit, signature or reusable permission.
#[derive(Clone)]
pub struct HistoryEffectV6Cancellation {
    operation_id: String,
    active: Arc<Mutex<Option<Active>>>,
}
impl HistoryEffectV6Cancellation {
    pub fn cancel(&self) -> Result<bool> {
        let active = self.active.lock().map_err(|_| "HISTORY_V6_SCOPE_UNKNOWN")?;
        let Some(active) = active.as_ref() else {
            return Ok(false);
        };
        if active.pending.operation.operation_id != self.operation_id {
            return Ok(false);
        }
        active.cancelled.store(true, Ordering::Release);
        Ok(true)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    Decode,
    Context,
    Work(pon_work::VerificationProgress),
    Execution(ExecutionProgress),
    Activation,
    BeforeSettlement,
}

impl HistoryEffectV6 {
    pub fn open(
        path: &Path,
        input: ProtectedHistoryV6Input,
        workers: usize,
        deadline: Instant,
    ) -> Result<Self> {
        ensure([1, 2, 4, 8].contains(&workers), "WORKERS")?;
        let config = &input.config;
        let mut journal = journal::Journal::open(
            &config.journal_path,
            input.expected_uid,
            &config.identity,
            &config.outside_latest_anchor,
        )?;
        ensure(journal.pending().is_none(), "HISTORY_V6_PENDING_DEBT")?;
        journal.install_budget(&config.signed_budget)?;
        let startup = policy::operation(&config.signed_startup, &config.identity, policy::now()?)?;
        ensure(
            startup.body.purpose == Purpose::Startup,
            "HISTORY_V6_STARTUP_REQUIRED",
        )?;
        let pending = journal.reserve(&config.signed_startup)?;
        let cpu =
            ServiceMutationCpuDomain::from_history_effect_v6_epoch(VerifiedEpoch { _sealed: () });
        let initial_cpu = cpu.observe()?;
        ensure(
            initial_cpu.stored_credit_ns == 0 && initial_cpu.in_flight == 0,
            "HISTORY_V6_COLD_CREDIT",
        )?;
        cpu.await_startup_credit(deadline)?;
        let operation = match cpu.begin() {
            Ok(op) => op,
            Err(error) => {
                journal.not_started(&pending.operation.operation_id, &error)?;
                return Err(error);
            }
        };
        let binding = pending
            .operation
            .binding
            .as_ref()
            .ok_or("HISTORY_V6_TASK")?
            .clone();
        let progress = || {
            ensure(Instant::now() < deadline, "HISTORY_V6_DEADLINE")?;
            let at = policy::now()?;
            ensure(
                at < pending.operation.expires_ns && at < pending.budget_expires_ns,
                "HISTORY_V6_OPERATION_EXPIRED",
            )?;
            operation.checkpoint()?;
            ensure(
                operation.checkpoint_handle().actual_live_paid_cpu_ns()?
                    <= pending.operation.allowance.cpu_ns,
                "HISTORY_V6_OPERATION_CPU_LIMIT",
            )
        };
        let built = (|| -> Result<_> {
            let catalog = crate::operator_continuous_policy::verify_catalog_bound(
                &config.materials,
                input.expected_uid,
                &binding,
                pending.operation.allowance.material_bytes,
                pending.operation.allowance.received_bytes,
                &|| progress().map_err(|_| crate::operator_task_policy::PolicyError::CpuUnknown),
            )
            .map_err(|_| "HISTORY_V6_CATALOG")?;
            let read = |role, cap| {
                catalog
                    .read_role(role, cap, &progress)
                    .map_err(|_| Error::from("HISTORY_V6_CATALOG"))
            };
            let model = read("model", 16384)?;
            let input = read("input", 16384)?;
            let spec = crate::operator_checkpoint_tile::OperatorCheckpointTileSpecV1::decode(
                &read("spec", crate::operator_checkpoint_tile::SPEC_BYTES as u64)?,
            )?;
            let bundle = crate::operator_deployment::decode(&read("bootstrap", 8192)?)?;
            let paths = crate::operator_checkpoint_tile::CheckpointTileRuntimePaths::new(
                catalog
                    .path_role("checkpoint")
                    .map_err(|_| "HISTORY_V6_CATALOG")?,
                catalog
                    .path_role("activation")
                    .map_err(|_| "HISTORY_V6_CATALOG")?,
            );
            let settings = Settings::development_with_operator_checkpoint_tile(
                &spec, &bundle, &model, &input, paths,
            )?;
            ensure(
                config.identity.network == hex::encode(settings.network())
                    && config.identity.parameters == hex::encode(settings.parameters())
                    && config.identity.genesis == hex::encode(settings.genesis()),
                "HISTORY_V6_SETTINGS_CONTEXT",
            )?;
            progress()?;
            Ok((catalog, settings))
        })();
        let (catalog, settings) = match built {
            Ok(value) => value,
            Err(error) => {
                let native = Err(error);
                let cpu = operation.finish();
                journal.settle(&pending.operation.operation_id, &native, &cpu, None, true)?;
                return native.map(|_| unreachable!());
            }
        };
        let marker = storage::owner_marker(&config.identity, &config.journal_path)?;
        let owner = Owner {
            marker,
            identity: config.identity.clone(),
            journal: Arc::new(Mutex::new(journal)),
            cpu,
            catalog: Arc::new(catalog),
            binding,
            active: Arc::new(Mutex::new(None)),
            unavailable: Arc::new(AtomicBool::new(false)),
        };
        let running = owner.enter(pending, operation, deadline)?;
        let opened = (|| -> Result<Node> {
            running.checkpoint()?;
            if !path.join("native.sqlite").exists() {
                ensure(
                    running.active.pending.operation.owner_frontier
                        == Frontier {
                            block: hex::encode(settings.genesis()),
                            root: hex::encode(settings.state_root(&settings.initial)?),
                            generation: 0,
                        },
                    "HISTORY_V6_INITIAL_FRONTIER",
                )?;
            }
            Node::install_mining_marker(path, input.expected_uid, &owner.marker)?;
            let node = Node::open_selected(
                path,
                settings,
                workers,
                None,
                NativeOwners {
                    policy: None,
                    mining: None,
                    continuous: None,
                    history_effect: Some(owner.clone()),
                },
                StateBackend::HistoryEffectV6,
                false,
            )?;
            let frontier = storage::frontier(&node.db)?;
            ensure(
                frontier == running.active.pending.operation.owner_frontier,
                "HISTORY_V6_OWNER_FRONTIER",
            )?;
            // Partial reorg requires its own explicitly bound continuation.
            // This first prototype does not allow startup to resume it.
            storage::no_pending_reorg(&node.db)?;
            storage::verify_known_markers(&node.db, &*owner.journal()?, None)?;
            running.checkpoint()?;
            Ok(node)
        })();
        let native = opened
            .as_ref()
            .map(|node| node.active().map(|v| v.0))
            .map_err(|e| Error::from(e.to_string()))
            .and_then(|v| v);
        let startup_result = running.finish(native, Ok(None), None)?;
        let node = opened?;
        ensure(
            startup_result.known_success(),
            "HISTORY_V6_STARTUP_ACCOUNTING",
        )?;
        Ok(Self {
            node,
            owner,
            startup_result,
            initial_cpu,
        })
    }
    pub fn observation(&self) -> Result<Value> {
        Ok(
            serde_json::json!({"schema":"restricted-history-effect-owner-observation-v6",
            "journal":self.owner.journal()?.observation(), "initial_cpu":self.initial_cpu,
            "current_cpu":self.owner.cpu.observe()?, "startup":self.startup_result,
            "opaque_owner":true,"production_qualified":false}),
        )
    }
    pub fn cancellation_for(&self, operation_id: &str) -> Result<HistoryEffectV6Cancellation> {
        policy::id(operation_id, 32)?;
        Ok(HistoryEffectV6Cancellation {
            operation_id: operation_id.to_owned(),
            active: self.owner.active.clone(),
        })
    }
    /// Network input retains the ORIGINAL fixed Host permit, including a local
    /// proxy. A signed operation does not remove this source/resource boundary.
    pub fn receive_from(
        &mut self,
        source: std::net::SocketAddr,
        signed: &[u8],
        raw_page: &[u8],
        observed_now: u64,
        deadline: Instant,
    ) -> Result<HistoryEffectV6Result> {
        let kernel = crate::host_kernel_parent::require_host_kernel_budget(
            source,
            Some(crate::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
        )?
        .ok_or("PUBLIC_HOST_KERNEL_REQUIRED")?;
        kernel.verify()?;
        self.receive_with_progress(signed, raw_page, observed_now, deadline, &|_| {
            kernel.verify()
        })
    }
    pub fn activate_from(
        &mut self,
        source: std::net::SocketAddr,
        signed: &[u8],
        observed_now: u64,
        deadline: Instant,
    ) -> Result<HistoryEffectV6Result> {
        let kernel = crate::host_kernel_parent::require_host_kernel_budget(
            source,
            Some(crate::host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT),
        )?
        .ok_or("PUBLIC_HOST_KERNEL_REQUIRED")?;
        kernel.verify()?;
        self.activate_with_progress(signed, observed_now, deadline, &|_| kernel.verify())
    }
    pub(crate) fn receive_with_progress(
        &mut self,
        signed: &[u8],
        raw_page: &[u8],
        observed_now: u64,
        deadline: Instant,
        resource: &(dyn Fn(Progress) -> Result<()> + Sync),
    ) -> Result<HistoryEffectV6Result> {
        ensure(
            !raw_page.is_empty() && raw_page.len() <= 2 * 1024 * 1024,
            "PAGE_LIMIT",
        )?;
        let running = self.owner.start(signed, Purpose::Validation, deadline)?;
        let op = &running.active.pending.operation;
        let fence = |point| {
            resource(point)?;
            running.checkpoint()
        };
        let native = (|| -> Result<Hash> {
            fence(Progress::Decode)?;
            ensure(
                raw_page.len() as u64 <= op.allowance.received_bytes,
                "HISTORY_V6_RECEIVED_LIMIT",
            )?;
            let page: crate::ingress::Page = serde_json::from_slice(raw_page)?;
            let parent = op.execution_parent.as_ref().ok_or("HISTORY_V6_PARENT")?;
            ensure(
                page.schema == "pon-native-history-v1"
                    && page.network == op.identity.network
                    && page.parameters == op.identity.parameters
                    && page.genesis == op.identity.genesis
                    && page.tip == op.target
                    && page.after == parent.block
                    && page.next == page.tip
                    && page.complete
                    && page.packets.len() == 1,
                "HISTORY_V6_PAGE_BINDING",
            )?;
            let raw = hex::decode(&page.packets[0]).map_err(|_| "PACKET_HEX")?;
            ensure(
                Some(policy::digest(&raw)) == op.packet_sha256,
                "HISTORY_V6_PACKET_DIGEST",
            )?;
            let packet = Packet::decode(&raw)?;
            ensure(packet.encode()? == raw, "HISTORY_V6_CANONICAL_PACKET")?;
            fence(Progress::Context)?;
            self.node
                .history_effect_packet_binding(op, &packet, &mut || fence(Progress::Context))?;
            if let Some(id) = self.node.check_admission_context_with_progress(
                &packet,
                observed_now,
                &mut || fence(Progress::Context),
            )? {
                // An already admitted exact packet still receives a fresh
                // explicitly marked reuse transaction; no Work is invented.
                self.node.history_effect_reuse_marker(&packet)?;
                return Ok(id);
            }
            let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |point| {
                running.checkpoint()?;
                if crate::ingress::history_kernel_work_checkpoint(point) {
                    fence(Progress::Work(point))?;
                }
                Ok(())
            })?;
            let progress = |point| fence(Progress::Execution(point));
            let control = ExecutionControl::new(&progress, running.worker_accounting()?);
            self.node
                .admit_work_checked_with_control(checked, observed_now, &control)
        })();
        let marker = storage::read_marker(&self.node.db, &op.operation_id);
        let boundary = resource(Progress::BeforeSettlement)
            .err()
            .map(|e| e.to_string());
        running.finish(native, marker, boundary)
    }
    pub(crate) fn activate_with_progress(
        &mut self,
        signed: &[u8],
        observed_now: u64,
        deadline: Instant,
        resource: &(dyn Fn(Progress) -> Result<()> + Sync),
    ) -> Result<HistoryEffectV6Result> {
        let running = self.owner.start(signed, Purpose::Activation, deadline)?;
        let op = &running.active.pending.operation;
        let native = (|| -> Result<Hash> {
            running.checkpoint()?;
            let target = bytes32(hex::decode(&op.target).map_err(|_| "HISTORY_V6_ID")?)?;
            let packet = self.node.packet(target)?;
            self.node
                .history_effect_packet_binding(op, &packet, &mut || {
                    resource(Progress::Context)?;
                    running.checkpoint()
                })?;
            storage::require_validation_marker(&self.node.db, &*self.owner.journal()?, op)?;
            self.node
                .activate_observed_with_progress(target, observed_now, &mut || {
                    resource(Progress::Activation)?;
                    running.checkpoint()
                })
        })();
        let marker = storage::read_marker(&self.node.db, &op.operation_id);
        let boundary = resource(Progress::BeforeSettlement)
            .err()
            .map(|e| e.to_string());
        running.finish(native, marker, boundary)
    }
    /// The final complete State/readback is another paid, signed operation;
    /// only then can a clean close permit a later zero-credit epoch.
    pub fn close(&mut self, signed: &[u8], deadline: Instant) -> Result<Value> {
        let running = self.owner.start(signed, Purpose::Close, deadline)?;
        let expected = running.active.pending.operation.owner_frontier.clone();
        let native = (|| -> Result<Hash> {
            let (tip, _, _) = self
                .node
                .read_active_with_progress(&mut || running.checkpoint())?;
            ensure(
                storage::frontier(&self.node.db)? == expected,
                "HISTORY_V6_OWNER_FRONTIER",
            )?;
            storage::no_pending_reorg(&self.node.db)?;
            storage::verify_known_markers(&self.node.db, &*self.owner.journal()?, None)?;
            self.node.db.execute_batch("PRAGMA wal_checkpoint(FULL)")?;
            running.checkpoint()?;
            Ok(tip)
        })();
        let result = running.finish(native, Ok(None), None)?;
        ensure(result.known_success(), "HISTORY_V6_CLOSE_ACCOUNTING")?;
        let actual = self.owner.cpu.observe()?;
        ensure(
            actual.in_flight == 0 && actual.stored_credit_ns >= 0 && !actual.accounting_unavailable,
            "HISTORY_V6_CLOSE_CPU_DEBT",
        )?;
        self.owner.journal()?.close(expected)?;
        self.owner.unavailable.store(true, Ordering::Release);
        Ok(
            serde_json::json!({"schema":"restricted-history-effect-close-v6", "result":result,
            "journal":self.owner.journal()?.observation(),"cpu":actual,"production_qualified":false}),
        )
    }
}
