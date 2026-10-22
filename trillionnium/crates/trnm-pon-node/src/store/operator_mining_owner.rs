//! Private mode3 scope. No untrusted request can manufacture this Node capability.
use super::*;
use crate::ingress::public_v3::scalar_cpu::ServiceMutationCpuCheckpoint;
use crate::{
    ingress::public_v3::{
        ServiceMutationCpuDomain, ServiceMutationCpuOperation, ServiceMutationCpuSettlement,
    },
    operator_mining_policy as policy,
};
use policy::{NativeFacts, Permit, Purpose, VerifiedView};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
/// A Root-held cancellation handle has no permission issuance or Node access.
/// It invalidates this one actual epoch; the next operation requires a complete
/// outside next-view refresh. Existing durable Native outcomes are not changed.
#[derive(Clone)]
pub struct MiningEpochCancellation {
    epoch: Arc<AtomicU64>,
    unavailable: Arc<AtomicBool>,
    expected: u64,
}
impl MiningEpochCancellation {
    pub fn cancel(&self) -> bool {
        let Some(next) = self.expected.checked_add(1) else {
            self.unavailable.store(true, Ordering::Release);
            return false;
        };
        self.epoch
            .compare_exchange(self.expected, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}
pub(super) struct MiningOwner {
    pub(super) view: Arc<VerifiedView>,
    pub(super) marker: Vec<u8>,
    pub(super) journal: RefCell<policy::Journal>,
    keys: (String, String),
    epoch: Arc<AtomicU64>,
    view_epoch: u64,
    unavailable: Arc<AtomicBool>,
    active: Arc<Mutex<Option<ActiveScope>>>,
    catalog: Option<policy::HeldCatalog>,
    cpu: ServiceMutationCpuDomain,
    startup_cpu: Option<ServiceMutationCpuSettlement>,
}
#[derive(Clone)]
struct ActiveScope {
    permit: Arc<Permit>,
    cpu: ServiceMutationCpuCheckpoint,
    transactions_sha256: Option<String>,
    miner: Option<Hash>,
    height: Option<u64>,
}
#[derive(Clone)]
pub(super) struct MiningScopeCheckpoint(ActiveScope);
impl MiningScopeCheckpoint {
    pub(super) fn check(&self) -> Result<()> {
        self.0.permit.progress().map_err(mining_error)?;
        self.0.cpu.checkpoint()
    }
}
struct ScopeReset(Arc<Mutex<Option<ActiveScope>>>);
impl Drop for ScopeReset {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.lock() {
            *active = None;
        }
    }
}
#[derive(Serialize)]
pub struct OwnedSearchResult {
    pub schema: &'static str,
    pub operation_id: String,
    pub actual_trials: u64,
    pub complete_proofs: u64,
    pub nonce_trials: Vec<crate::mining::OwnedNonceTrial>,
    pub native_error: Option<String>,
    pub accounting_fault_persistence_failed: bool,
    pub last_nonce: Option<u64>,
    #[serde(skip_serializing)]
    pub packet: Option<Packet>,
    pub packet_sha256: Option<String>,
    pub stopped: bool,
    pub cpu: ServiceMutationCpuSettlement,
    pub stage_preemption: bool,
    pub public_network_ready: bool,
}
#[derive(Serialize)]
pub struct OwnedMutationResult {
    pub schema: &'static str,
    pub native_id: Option<Hash>,
    pub native_error: Option<String>,
    pub cpu: ServiceMutationCpuSettlement,
    pub durable_result_preserved: bool,
    pub accounting_fault_persistence_failed: bool,
    pub public_network_ready: bool,
}
fn mining_error(e: policy::PolicyError) -> Error {
    Error::from(format!("OWNER_MINING_POLICY:{e:?}"))
}
impl MiningOwner {
    fn slot(&self) -> Result<Option<ActiveScope>> {
        Ok(self
            .active
            .lock()
            .map_err(|_| "OWNER_MINING_SCOPE_UNAVAILABLE")?
            .clone())
    }
    fn enter(
        &self,
        p: Arc<Permit>,
        cpu: ServiceMutationCpuCheckpoint,
        tx: Option<String>,
        miner: Option<Hash>,
        height: Option<u64>,
    ) -> Result<ScopeReset> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "OWNER_MINING_SCOPE_UNAVAILABLE")?;
        ensure(active.is_none(), "OWNER_MINING_SCOPE_BUSY")?;
        *active = Some(ActiveScope {
            permit: p,
            cpu,
            transactions_sha256: tx,
            miner,
            height,
        });
        drop(active);
        Ok(ScopeReset(self.active.clone()))
    }
    fn permission(
        &self,
        purpose: Purpose,
        payload: String,
        generation: u64,
    ) -> Result<Arc<Permit>> {
        ensure(
            !self.unavailable.load(Ordering::Acquire),
            "OWNER_MINING_UNAVAILABLE",
        )?;
        ensure(
            self.epoch.load(Ordering::Acquire) == self.view_epoch,
            "OWNER_MINING_NEXT_VIEW_REQUIRED",
        )?;
        let facts = NativeFacts {
            context: self.view.body.context.clone(),
            task: self.view.body.task.clone(),
            generation,
            purpose,
            payload_sha256: payload,
        };
        let reservation = self
            .journal
            .borrow_mut()
            .reserve(
                &self.view,
                &facts,
                crate::operator_task_policy::now_ns().map_err(mining_error)?,
            )
            .map_err(mining_error)?;
        Ok(Arc::new(Permit {
            view: self.view.clone(),
            facts,
            reservation,
            epoch: self.epoch.clone(),
            expected_epoch: self.view_epoch,
            unavailable: self.unavailable.clone(),
        }))
    }
    fn unknown(&self) -> Result<()> {
        self.unavailable.store(true, Ordering::Release);
        self.journal
            .borrow_mut()
            .mark_unavailable()
            .map_err(mining_error)
    }
    fn begin_cpu(&self, cpu: &ServiceMutationCpuDomain) -> Result<ServiceMutationCpuOperation> {
        match cpu.begin() {
            Ok(operation) => Ok(operation),
            Err(error) => {
                if !cpu.accounting_available() && self.unknown().is_err() {
                    return Err(Error::from(format!(
                        "{error}; OWNER_MINING_FAULT_PERSISTENCE_FAILED"
                    )));
                }
                Err(error)
            }
        }
    }
    fn unfinished_fault(&self) -> Result<policy::UnfinishedOperationFault> {
        self.journal
            .borrow()
            .unfinished_fault(self.unavailable.clone())
            .map_err(mining_error)
    }
}
impl Node {
    pub fn take_mining_startup_cpu(&mut self) -> Result<ServiceMutationCpuSettlement> {
        self.mining_owner
            .as_mut()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?
            .startup_cpu
            .take()
            .ok_or_else(|| Error::from("OWNER_MINING_STARTUP_RECEIPT_ALREADY_TAKEN"))
    }
    pub fn mining_epoch_cancellation(&self) -> Result<MiningEpochCancellation> {
        let owner = self
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        Ok(MiningEpochCancellation {
            epoch: owner.epoch.clone(),
            unavailable: owner.unavailable.clone(),
            expected: owner.view_epoch,
        })
    }
    fn prepare_mining_owner(
        inputs: &policy::Inputs,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<(
        MiningOwner,
        Arc<Permit>,
        ServiceMutationCpuOperation,
        policy::UnfinishedOperationFault,
    )> {
        let view = policy::authenticate(
            &inputs.raw_view,
            &inputs.authority,
            crate::operator_task_policy::now_ns().map_err(mining_error)?,
        )
        .map_err(mining_error)?;
        let marker = view.marker(&inputs.journal_path).map_err(mining_error)?;
        let journal = policy::Journal::open(&inputs.journal_path, inputs.expected_uid, &view)
            .map_err(mining_error)?;
        let mut owner = MiningOwner {
            view: Arc::new(view),
            marker,
            journal: RefCell::new(journal),
            keys: (
                inputs.authority.registry_key.clone(),
                inputs.authority.task_key.clone(),
            ),
            epoch: Arc::new(AtomicU64::new(1)),
            view_epoch: 1,
            unavailable: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(None)),
            catalog: None,
            cpu: cpu.clone(),
            startup_cpu: None,
        };
        let permission = owner
            .view
            .permission(
                &Purpose::StartupCatalog,
                &owner.view.body.task.full_material_catalog,
            )
            .map_err(mining_error)?;
        let permit = owner.permission(
            Purpose::StartupCatalog,
            permission.payload_sha256.clone(),
            permission.expected_generation,
        )?;
        let operation = owner.begin_cpu(cpu)?;
        let mut fault = owner.unfinished_fault()?;
        let catalog = policy::verify_catalog(inputs, &permit, &|| {
            operation
                .checkpoint()
                .map_err(|_| policy::PolicyError::CpuUnknown)
        });
        match catalog {
            Ok(catalog) => owner.catalog = Some(catalog),
            Err(error) => {
                let measured = operation.finish();
                let failed = measured.accounting_unavailable && fault.persist_unknown().is_err();
                fault.finished();
                if failed {
                    return Err(Error::from(format!(
                        "{}; OWNER_MINING_FAULT_PERSISTENCE_FAILED",
                        mining_error(error)
                    )));
                }
                return Err(mining_error(error));
            }
        }
        Ok((owner, permit, operation, fault))
    }
    #[allow(clippy::too_many_arguments)]
    fn finish_mining_open(
        path: &Path,
        settings: Settings,
        workers: usize,
        inputs: &policy::Inputs,
        owner: MiningOwner,
        permit: Arc<Permit>,
        operation: ServiceMutationCpuOperation,
        mut fault: policy::UnfinishedOperationFault,
    ) -> Result<Self> {
        // Initialization is serial in this profile; subsequent real M06 worker
        // intervals use the controlled accounting path. No untracked parallel
        // initialization is reported as O+C.
        ensure(workers == 1, "OWNER_MINING_INITIAL_PROFILE_SERIAL")?;
        ensure(
            owner.view.body.context.network == hex::encode(settings.network())
                && owner.view.body.context.parameters == hex::encode(settings.parameters()),
            "OWNER_MINING_CONTEXT",
        )?;
        permit.progress().map_err(mining_error)?;
        operation.checkpoint()?;
        let reconcile = owner
            .view
            .permission(
                &Purpose::ParentReconcile,
                &owner.view.body.context.actual_parent,
            )
            .map_err(mining_error)?;
        let reconcile_permit = owner.permission(
            Purpose::ParentReconcile,
            reconcile.payload_sha256.clone(),
            reconcile.expected_generation,
        )?;
        ensure(
            reconcile_permit.facts.generation == permit.facts.generation,
            "OWNER_MINING_STARTUP_GENERATION",
        )?;
        let _startup_scope = owner.enter(
            reconcile_permit,
            operation.checkpoint_handle(),
            None,
            None,
            None,
        )?;
        Self::install_mining_marker(path, inputs.expected_uid, &owner.marker)?;
        let result = Self::open_inner(path, settings, workers, None, None, Some(owner), None);
        let measured = operation.finish();
        let persistence_failed =
            measured.accounting_unavailable && fault.persist_unknown().is_err();
        fault.finished();
        let mut node = match result {
            Ok(node) => node,
            Err(error) => {
                if persistence_failed {
                    return Err(Error::from(format!(
                        "{error}; OWNER_MINING_FAULT_PERSISTENCE_FAILED"
                    )));
                }
                return Err(error);
            }
        };
        let owner = node
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        ensure(!persistence_failed, "OWNER_MINING_FAULT_PERSISTENCE_FAILED")?;
        ensure(
            !measured.accounting_unavailable && !measured.live_refused,
            "OWNER_MINING_STARTUP_ACCOUNTING",
        )?;
        owner
            .catalog
            .as_ref()
            .ok_or("OWNER_MINING_CATALOG_REQUIRED")?
            .ready()
            .map_err(mining_error)?;
        let (active, generation) = node.active()?;
        ensure(
            owner.view.body.context.actual_parent == hex::encode(active)
                && permit.facts.generation == generation,
            "OWNER_MINING_PARENT_CHANGED",
        )?;
        node.mining_owner
            .as_mut()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?
            .startup_cpu = Some(measured);
        Ok(node)
    }
    /// Library caller supplies already constructed exact Settings. Only the
    /// protected checkpoint opener below covers settings/material construction.
    pub fn open_with_operator_mining_task_view(
        path: &Path,
        settings: Settings,
        workers: usize,
        inputs: policy::Inputs,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<Self> {
        let (owner, permit, operation, fault) = Self::prepare_mining_owner(&inputs, cpu)?;
        Self::finish_mining_open(
            path, settings, workers, &inputs, owner, permit, operation, fault,
        )
    }
    /// Protected finite controller: signatures/latest and a durable startup
    /// reservation precede every complete source material read or Settings replay.
    /// Exact original bootstrap/tile Settings methods are used without adapters.
    pub fn open_operator_mining_checkpoint(
        path: &Path,
        inputs: policy::Inputs,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<(Self, Vec<u8>, Vec<u8>)> {
        let (owner, permit, operation, mut fault) = Self::prepare_mining_owner(&inputs, cpu)?;
        let build = (|| -> Result<(Settings, Vec<u8>, Vec<u8>)> {
            let catalog = owner
                .catalog
                .as_ref()
                .ok_or("OWNER_MINING_CATALOG_REQUIRED")?;
            let progress = || -> Result<()> {
                permit.progress().map_err(mining_error)?;
                operation.checkpoint()?;
                catalog.ready().map_err(mining_error)
            };
            progress()?;
            let model = catalog
                .read_role("model", 16384, &progress)
                .map_err(mining_error)?;
            let input = catalog
                .read_role("input", 16384, &progress)
                .map_err(mining_error)?;
            let spec_raw = catalog
                .read_role(
                    "spec",
                    crate::operator_checkpoint_tile::SPEC_BYTES as u64,
                    &progress,
                )
                .map_err(mining_error)?;
            let spec =
                crate::operator_checkpoint_tile::OperatorCheckpointTileSpecV1::decode(&spec_raw)?;
            let bundle_raw = catalog
                .read_role("bootstrap", 8192, &progress)
                .map_err(mining_error)?;
            let bundle = crate::operator_deployment::decode(&bundle_raw)?;
            let paths = crate::operator_checkpoint_tile::CheckpointTileRuntimePaths::new(
                catalog.path_role("checkpoint").map_err(mining_error)?,
                catalog.path_role("activation").map_err(mining_error)?,
            );
            progress()?;
            let settings = Settings::development_with_operator_checkpoint_tile(
                &spec, &bundle, &model, &input, paths,
            )?;
            progress()?;
            Ok((settings, model, input))
        })();
        let (settings, model, input) = match build {
            Ok(result) => result,
            Err(error) => {
                let measured = operation.finish();
                let failed = measured.accounting_unavailable && fault.persist_unknown().is_err();
                fault.finished();
                if failed {
                    return Err(Error::from(format!(
                        "{error}; OWNER_MINING_FAULT_PERSISTENCE_FAILED"
                    )));
                }
                return Err(error);
            }
        };
        let node =
            Self::finish_mining_open(path, settings, 1, &inputs, owner, permit, operation, fault)?;
        Ok((node, model, input))
    }
    pub(super) fn install_mining_marker(path: &Path, uid: u32, expected: &[u8]) -> Result<()> {
        if !path.try_exists()? {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let m = fs::symlink_metadata(path)?;
        ensure(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.uid() == uid
                && m.mode() & 0o7777 == 0o700,
            "OWNER_MINING_NAMESPACE",
        )?;
        let marker = path.join("owner-task-policy.required");
        if marker.try_exists()? {
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&marker)?;
            let a = f.metadata()?;
            ensure(
                a.is_file()
                    && a.nlink() == 1
                    && a.uid() == uid
                    && a.mode() & 0o7777 == 0o600
                    && a.len() == expected.len() as u64,
                "OWNER_MINING_NAMESPACE",
            )?;
            let mut b = Vec::new();
            std::io::Read::take(&mut f, expected.len() as u64 + 1).read_to_end(&mut b)?;
            let z = f.metadata()?;
            let visible = fs::symlink_metadata(&marker)?;
            ensure(
                b == expected
                    && (
                        a.dev(),
                        a.ino(),
                        a.len(),
                        a.mtime(),
                        a.mtime_nsec(),
                        a.ctime(),
                        a.ctime_nsec(),
                    ) == (
                        z.dev(),
                        z.ino(),
                        z.len(),
                        z.mtime(),
                        z.mtime_nsec(),
                        z.ctime(),
                        z.ctime_nsec(),
                    )
                    && (z.dev(), z.ino()) == (visible.dev(), visible.ino()),
                "OWNER_MINING_NAMESPACE",
            )?;
        } else {
            ensure(
                fs::read_dir(path)?.next().is_none(),
                "OWNER_MINING_FRESH_NAMESPACE_REQUIRED",
            )?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&marker)?;
            f.write_all(expected)?;
            f.sync_all()?;
            sync_dir(path)?;
        }
        Ok(())
    }
    /// Same outside keys and source epoch, linked next latest. A parent change
    /// requires this complete new signed view, never a cached successor State.
    pub fn refresh_operator_mining_task_view(
        &mut self,
        inputs: policy::Inputs,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<()> {
        let owner = self
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        ensure(
            owner.cpu.shares_domain_with(cpu),
            "OWNER_MINING_CPU_EPOCH_CHANGED",
        )?;
        ensure(owner.slot()?.is_none(), "OWNER_MINING_SCOPE_BUSY")?;
        ensure(
            (
                inputs.authority.registry_key.as_str(),
                inputs.authority.task_key.as_str(),
            ) == (owner.keys.0.as_str(), owner.keys.1.as_str()),
            "OWNER_MINING_KEYS_CHANGED",
        )?;
        let v = policy::authenticate(
            &inputs.raw_view,
            &inputs.authority,
            crate::operator_task_policy::now_ns().map_err(mining_error)?,
        )
        .map_err(mining_error)?;
        ensure(
            v.next_view_of(&owner.view)
                && v.marker(&inputs.journal_path).map_err(mining_error)? == owner.marker
                && v.body.context.source_commit == owner.view.body.context.source_commit
                && v.body.context.node_policy_source == owner.view.body.context.node_policy_source
                && v.body.context.registry2_package == owner.view.body.context.registry2_package,
            "OWNER_MINING_NEXT_VIEW",
        )?;
        let (parent, generation) = self.active()?;
        ensure(
            v.body.context.actual_parent == hex::encode(parent),
            "OWNER_MINING_PARENT",
        )?;
        let epoch = owner
            .epoch
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("OWNER_MINING_EPOCH_OVERFLOW")?;
        if let Err(e) = owner.journal.borrow_mut().advance(&v) {
            owner.unavailable.store(true, Ordering::Release);
            return Err(mining_error(e));
        }
        owner.epoch.store(epoch, Ordering::Release);
        let owner = self
            .mining_owner
            .as_mut()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        owner.view = Arc::new(v);
        owner.view_epoch = epoch;
        // Retain only the full verified source FDs, not State, roots, outputs or
        // preprocessed products. Each refresh must match all descriptors and
        // unchanged held identity. A different catalog requires a fresh epoch.
        if let Err(e) = owner
            .catalog
            .as_ref()
            .ok_or("OWNER_MINING_CATALOG_REQUIRED")?
            .recheck(&inputs, &owner.view)
        {
            owner.unavailable.store(true, Ordering::Release);
            owner
                .journal
                .borrow_mut()
                .mark_unavailable()
                .map_err(mining_error)?;
            return Err(mining_error(e));
        }
        let _ = (generation, cpu); // refresh itself grants no Native or CPU lease
        Ok(())
    }
    /// Startup/history recovery does not mint a Work/Activate capability.
    /// Only the unchanged actual active pair and absence of an unfinished reorg
    /// can reopen. Any automatic best-tip advance is explicitly HOLD.
    pub(super) fn mining_recovery_unchanged(&self) -> Result<Option<Hash>> {
        let Some(owner) = &self.mining_owner else {
            return Ok(None);
        };
        let active = owner
            .slot()?
            .ok_or("OWNER_MINING_RECONCILE_PURPOSE_REQUIRED")?;
        ensure(
            active.permit.facts.purpose == Purpose::ParentReconcile,
            "OWNER_MINING_RECONCILE_PURPOSE_REQUIRED",
        )?;
        active.permit.progress().map_err(mining_error)?;
        active.cpu.checkpoint()?;
        let (tip, generation) = self.active()?;
        ensure(
            hex::encode(tip) == active.permit.facts.context.actual_parent
                && generation == active.permit.facts.generation,
            "OWNER_MINING_RECONCILE_PAIR",
        )?;
        let pending: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM reorg WHERE done=0", [], |r| r.get(0))?;
        ensure(pending == 0, "OWNER_MINING_RECOVERY_INTENT_HOLD")?;
        let best: Vec<u8> = self.db.query_row(
            "SELECT id FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        ensure(bytes32(best)? == tip, "OWNER_MINING_RECOVERY_ADVANCE_HOLD")?;
        self.namespace()?;
        active.permit.progress().map_err(mining_error)?;
        Ok(Some(tip))
    }
    pub(super) fn mining_preview_gate(&self) -> Result<()> {
        if let Some(owner) = &self.mining_owner {
            let active = owner
                .slot()?
                .ok_or("OWNER_MINING_SEARCH_PURPOSE_REQUIRED")?;
            ensure(
                active.permit.facts.purpose == Purpose::Search,
                "OWNER_MINING_SEARCH_PURPOSE_REQUIRED",
            )?;
            active.permit.progress().map_err(mining_error)?;
        }
        Ok(())
    }
    pub(super) fn mining_execution_gate(&self, block: &ExecutionRequest<'_>) -> Result<()> {
        if let Some(owner) = &self.mining_owner {
            let active = owner
                .slot()?
                .ok_or("OWNER_MINING_NATIVE_PURPOSE_REQUIRED")?;
            ensure(
                matches!(
                    active.permit.facts.purpose,
                    Purpose::Search | Purpose::WinnerValidation
                ) && active.permit.facts.context.actual_parent == hex::encode(block.parent_id)
                    && active.transactions_sha256.as_deref()
                        == Some(
                            policy::transactions_sha256(block.transactions)
                                .map_err(mining_error)?
                                .as_str(),
                        )
                    && active.miner == Some(block.miner)
                    && active.height == Some(block.height),
                "OWNER_MINING_NATIVE_BINDING",
            )?;
            active.permit.progress().map_err(mining_error)?;
        }
        Ok(())
    }
    pub(super) fn mining_packet_gate(&self, packet: &Packet) -> Result<()> {
        if let Some(owner) = &self.mining_owner {
            let digest = crate::operator_task_policy::digest_bytes(&packet.encode()?);
            ensure(
                hex::encode(packet.header.work_task) == owner.view.body.task.native_task,
                "OWNER_MINING_PACKET_TASK",
            )?;
            owner
                .view
                .check_window(crate::operator_task_policy::now_ns().map_err(mining_error)?)
                .map_err(mining_error)?;
            owner
                .view
                .permission(&Purpose::WinnerValidation, &digest)
                .map_err(mining_error)?;
            if let Some(active) = owner.slot()? {
                ensure(
                    active.permit.facts.purpose == Purpose::WinnerValidation
                        && active.permit.facts.payload_sha256 == digest,
                    "OWNER_MINING_WINNER_PURPOSE_REQUIRED",
                )?;
                active.permit.progress().map_err(mining_error)?;
            } else {
                let prior: Option<Vec<u8>> = self
                    .db
                    .query_row(
                        "SELECT packet FROM blocks WHERE id=?",
                        [packet.id()?.as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                ensure(
                    prior.as_deref() == Some(packet.encode()?.as_slice()),
                    "OWNER_MINING_EXPLICIT_VALIDATION_REQUIRED",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn mining_activation_gate(&self, target: Hash) -> Result<()> {
        if let Some(owner) = &self.mining_owner {
            let active = owner
                .slot()?
                .ok_or("OWNER_MINING_ACTIVATE_PURPOSE_REQUIRED")?;
            ensure(
                active.permit.facts.purpose == Purpose::Activate,
                "OWNER_MINING_ACTIVATE_PURPOSE_REQUIRED",
            )?;
            let raw: Vec<u8> = self.db.query_row(
                "SELECT packet FROM blocks WHERE id=?",
                [target.as_slice()],
                |r| r.get(0),
            )?;
            ensure(
                active.permit.facts.payload_sha256
                    == crate::operator_task_policy::digest_bytes(&raw),
                "OWNER_MINING_ACTIVATE_PACKET",
            )?;
            active.permit.progress().map_err(mining_error)?;
        }
        Ok(())
    }
    pub(super) fn mining_progress_snapshot(&self) -> Result<Option<MiningScopeCheckpoint>> {
        self.mining_owner
            .as_ref()
            .map(|o| o.slot())
            .transpose()
            .map(|p| p.flatten().map(MiningScopeCheckpoint))
    }
    pub(super) fn mining_scope_checkpoint(&self) -> Result<()> {
        if let Some(owner) = &self.mining_owner {
            if let Some(active) = owner.slot()? {
                active.permit.progress().map_err(mining_error)?;
                active.cpu.checkpoint()?;
            }
        }
        Ok(())
    }
    fn mining_actual_task_binding(
        &self,
        permit: &Permit,
        model: &[u8],
        input: &[u8],
    ) -> Result<()> {
        let parent = bytes32(
            hex::decode(&permit.facts.context.actual_parent)
                .map_err(|_| "OWNER_MINING_PARENT_HEX")?,
        )?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let task = bytes32(
            hex::decode(&permit.view.body.task.native_task).map_err(|_| "OWNER_MINING_TASK_HEX")?,
        )?;
        let manifest = self
            .eligible_work_task(parent, task, height)?
            .ok_or("OWNER_MINING_COMPLETE_REGISTRATION_REQUIRED")?;
        ensure(
            manifest.purpose == TaskPurpose::Maintenance,
            "OWNER_MINING_MAINTENANCE_ONLY",
        )?;
        let lease = self
            .lifecycle_task_lease(parent, task, height)?
            .encode()
            .map_err(|_| "OWNER_MINING_LEASE")?;
        let (a, b) = derive_matrices(model, input).map_err(|_| "OWNER_MINING_MATERIAL")?;
        let ab: Vec<u8> = a.iter().flat_map(|v| v.to_le_bytes()).collect();
        let bb: Vec<u8> = b.iter().flat_map(|v| v.to_le_bytes()).collect();
        let t = &permit.view.body.task;
        ensure(
            crate::operator_task_policy::digest_bytes(&lease) == t.lease_sha256
                && hex::encode(manifest.model) == t.native_model
                && hex::encode(manifest.input) == t.native_input
                && crate::operator_task_policy::digest_bytes(model) == t.model_material
                && crate::operator_task_policy::digest_bytes(input) == t.input_material
                && crate::operator_task_policy::digest_bytes(&ab) == t.a_sha256
                && crate::operator_task_policy::digest_bytes(&bb) == t.b_sha256
                && t.dimension == 64
                && t.field_modulus == 4294967291
                && t.encoding == "canonical-u32-le",
            "OWNER_MINING_NATIVE_BINDING",
        )?;
        permit.progress().map_err(mining_error)
    }
    /// A finite exact outside-issued ordinary batch. Automatic pool status,
    /// pruning/selection and submit grants are not silently borrowed. They remain
    /// HOLD in mode3 until a distinct complete purpose is implemented.
    #[allow(clippy::too_many_arguments)]
    pub fn search_owned_mining_window(
        &self,
        operation_id: &str,
        raws: Vec<Vec<u8>>,
        model: &[u8],
        input: &[u8],
        cpu: &ServiceMutationCpuDomain,
        stop: &AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<OwnedSearchResult> {
        let owner = self
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        ensure(
            owner.cpu.shares_domain_with(cpu),
            "OWNER_MINING_CPU_EPOCH_CHANGED",
        )?;
        let p = owner
            .view
            .body
            .permissions
            .iter()
            .find(|p| p.purpose == Purpose::Search && p.operation_id == operation_id)
            .ok_or("OWNER_MINING_EXACT_SEARCH_REQUIRED")?;
        let search = p
            .search
            .as_ref()
            .ok_or("OWNER_MINING_SEARCH_SHAPE")?
            .clone();
        ensure(
            search.exact_transactions_sha256
                == policy::transactions_sha256(&raws).map_err(mining_error)?
                && search.exact_group_ids.is_empty(),
            "OWNER_MINING_EXACT_BATCH",
        )?;
        policy::check_allowed_transactions(&owner.view.body, &raws).map_err(mining_error)?;
        let (parent, generation) = self.active()?;
        ensure(
            owner.view.body.context.actual_parent == hex::encode(parent)
                && generation == p.expected_generation,
            "OWNER_MINING_PARENT_CHANGED",
        )?;
        let permit = owner.permission(Purpose::Search, p.payload_sha256.clone(), generation)?;
        let operation = owner.begin_cpu(cpu)?;
        let mut fault = owner.unfinished_fault()?;
        let miner = bytes32(hex::decode(&search.miner).map_err(|_| "OWNER_MINING_MINER_HEX")?)?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let _scope = owner.enter(
            permit.clone(),
            operation.checkpoint_handle(),
            Some(search.exact_transactions_sha256.clone()),
            Some(miner),
            Some(height),
        )?;
        owner
            .catalog
            .as_ref()
            .ok_or("OWNER_MINING_CATALOG_REQUIRED")?
            .ready()
            .map_err(mining_error)?;
        let progress = || -> Result<()> {
            ensure(
                !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline,
                "OWNER_MINING_STOPPED",
            )?;
            permit.progress().map_err(mining_error)?;
            operation.checkpoint()
        };
        let on_progress = |_| progress();
        let control = ExecutionControl::new(&on_progress, operation.worker_accounting());
        let result = (|| -> Result<crate::mining::OwnedWindowTrace> {
            progress()?;
            self.mining_actual_task_binding(&permit, model, input)?;
            let prepared = self.prepare_registered_material_controlled(
                parent,
                raws,
                miner,
                search.timestamp,
                search.nonce_count,
                model,
                input,
                &control,
            )?;
            let mut result =
                prepared.search_owned_window(search.nonce_first, search.nonce_count, &progress)?;
            if let Err(error) = owner
                .catalog
                .as_ref()
                .ok_or("OWNER_MINING_CATALOG_REQUIRED")?
                .ready()
            {
                result.packet = None;
                result.stopped = true;
                result.error = Some(format!("OWNER_MINING_CATALOG:{error:?}"));
            }
            Ok(result)
        })();
        let measured = operation.finish();
        let fault_failed = measured.accounting_unavailable && fault.persist_unknown().is_err();
        fault.finished();
        let trace = match result {
            Ok(trace) => trace,
            Err(error) => crate::mining::OwnedWindowTrace {
                packet: None,
                trials: Vec::new(),
                stopped: true,
                error: Some(error.to_string()),
            },
        };
        let trials = trace.trials.len() as u64;
        let complete_proofs = trace.trials.iter().filter(|t| t.complete_proof).count() as u64;
        let raw = trace.packet.as_ref().map(Packet::encode).transpose()?;
        // A persistence failure is an explicit result. No claim is deleted or
        // retried; a winner is not a validation capability until this record is
        // successfully durable and an outside next-view exact grant is supplied.
        let publication = owner.journal.borrow_mut().record_search(
            &owner.view,
            &permit.reservation,
            &permit.facts,
            raw.as_deref(),
            trials,
        );
        let native_error = trace.error.or_else(|| {
            publication
                .err()
                .map(|e| format!("OWNER_MINING_RESULT:{e:?}"))
        });
        let valid_packet = if native_error.is_none() && !measured.accounting_unavailable {
            trace.packet
        } else {
            None
        };
        Ok(OwnedSearchResult {
            schema: "restricted-owner-finite-search-v1",
            operation_id: permit.reservation.operation.clone(),
            actual_trials: trials,
            complete_proofs,
            nonce_trials: trace.trials,
            native_error,
            accounting_fault_persistence_failed: fault_failed,
            last_nonce: if trials == 0 {
                None
            } else {
                search.nonce_first.checked_add(trials - 1)
            },
            packet_sha256: raw
                .as_deref()
                .map(crate::operator_task_policy::digest_bytes),
            packet: valid_packet,
            stopped: trace.stopped,
            cpu: measured,
            stage_preemption: false,
            public_network_ready: false,
        })
    }

    /// Exact winner has a linked next-view validation grant and a retained real
    /// search result. Original M05 and all M06/SQL predicates remain mandatory.
    pub fn validate_owned_mining_winner(
        &mut self,
        packet: Packet,
        observed_now: u64,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<OwnedMutationResult> {
        let owner = self
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        ensure(
            owner.cpu.shares_domain_with(cpu),
            "OWNER_MINING_CPU_EPOCH_CHANGED",
        )?;
        let digest = crate::operator_task_policy::digest_bytes(&packet.encode()?);
        let (parent, generation) = self.active()?;
        ensure(
            packet.header.parent == parent
                && owner.view.body.context.actual_parent == hex::encode(parent),
            "OWNER_MINING_PARENT_CHANGED",
        )?;
        ensure(
            hex::encode(packet.header.work_task) == owner.view.body.task.native_task,
            "OWNER_MINING_PACKET_TASK",
        )?;
        let permit = owner.permission(Purpose::WinnerValidation, digest, generation)?;
        let operation = owner.begin_cpu(cpu)?;
        let mut fault = owner.unfinished_fault()?;
        let _scope = owner.enter(
            permit.clone(),
            operation.checkpoint_handle(),
            Some(policy::transactions_sha256(&packet.transactions).map_err(mining_error)?),
            Some(packet.header.miner),
            Some(packet.header.height),
        )?;
        let progress = || -> Result<()> {
            permit.progress().map_err(mining_error)?;
            operation.checkpoint()
        };
        let on_progress = |_| progress();
        let control = ExecutionControl::new(&on_progress, operation.worker_accounting());
        let result = (|| {
            progress()?;
            self.check_admission_context(&packet, observed_now)?;
            let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |_| progress())?;
            self.admit_work_checked_with_control(checked, observed_now, &control)
        })();
        let measured = operation.finish();
        let fault_failed = measured.accounting_unavailable && fault.persist_unknown().is_err();
        fault.finished();
        Ok(OwnedMutationResult {
            schema: "restricted-owner-winner-validation-v1",
            native_id: result.as_ref().ok().copied(),
            native_error: result.err().map(|e: Error| e.to_string()),
            cpu: measured,
            durable_result_preserved: true,
            accounting_fault_persistence_failed: fault_failed,
            public_network_ready: false,
        })
    }
    pub fn activate_owned_mining_winner(
        &mut self,
        tip: Hash,
        observed_now: u64,
        cpu: &ServiceMutationCpuDomain,
    ) -> Result<OwnedMutationResult> {
        let owner = self
            .mining_owner
            .as_ref()
            .ok_or("OWNER_MINING_MODE_REQUIRED")?;
        ensure(
            owner.cpu.shares_domain_with(cpu),
            "OWNER_MINING_CPU_EPOCH_CHANGED",
        )?;
        let raw: Vec<u8> = self.db.query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [tip.as_slice()],
            |r| r.get(0),
        )?;
        let decoded = Packet::decode(&raw)?;
        ensure(
            hex::encode(decoded.header.work_task) == owner.view.body.task.native_task,
            "OWNER_MINING_PACKET_TASK",
        )?;
        let (parent, generation) = self.active()?;
        ensure(
            owner.view.body.context.actual_parent == hex::encode(parent),
            "OWNER_MINING_PARENT_CHANGED",
        )?;
        let permit = owner.permission(
            Purpose::Activate,
            crate::operator_task_policy::digest_bytes(&raw),
            generation,
        )?;
        let operation = owner.begin_cpu(cpu)?;
        let mut fault = owner.unfinished_fault()?;
        let _scope = owner.enter(permit, operation.checkpoint_handle(), None, None, None)?;
        let result = (|| {
            operation.checkpoint()?;
            self.activate_observed(tip, observed_now)
        })();
        let measured = operation.finish();
        let fault_failed = measured.accounting_unavailable && fault.persist_unknown().is_err();
        fault.finished();
        Ok(OwnedMutationResult {
            schema: "restricted-owner-winner-activation-v1",
            native_id: result.as_ref().ok().copied(),
            native_error: result.err().map(|e: Error| e.to_string()),
            cpu: measured,
            durable_result_preserved: true,
            accounting_fault_persistence_failed: fault_failed,
            public_network_ready: false,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::operator_mining_policy::tests::{verified, view};
    fn attach_owner(node: &mut Node, journal: &Path) -> Result<()> {
        attach_owner_with_view(node, journal, view())
    }
    fn attach_owner_with_view(
        node: &mut Node,
        journal: &Path,
        mut body: policy::TaskView,
    ) -> Result<()> {
        body.context.network = hex::encode(node.settings.network());
        body.context.parameters = hex::encode(node.settings.parameters());
        body.context.actual_parent = hex::encode(node.active()?.0);
        for permission in &mut body.permissions {
            if permission.purpose == Purpose::ParentReconcile {
                permission.payload_sha256 = body.context.actual_parent.clone();
            }
            permission.operation_id = policy::operation_id(
                &body.context,
                &permission.purpose,
                &permission.operation_nonce,
                &permission.payload_sha256,
            )
            .unwrap();
        }
        let view = verified(body);
        let uid = rustix::process::geteuid().as_raw();
        let marker = view.marker(journal).map_err(mining_error)?;
        let keys = (view.registry_key.clone(), view.task_key.clone());
        let j = policy::Journal::open(journal, uid, &view).map_err(mining_error)?;
        node.mining_owner = Some(MiningOwner {
            view: Arc::new(view),
            marker,
            journal: RefCell::new(j),
            keys,
            epoch: Arc::new(AtomicU64::new(1)),
            view_epoch: 1,
            unavailable: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(None)),
            catalog: None,
            cpu: ServiceMutationCpuDomain::standalone(),
            startup_cpu: None,
        });
        Ok(())
    }
    fn node() -> (tempfile::TempDir, tempfile::TempDir, Node) {
        let root = tempfile::tempdir().unwrap();
        let journal = tempfile::tempdir().unwrap();
        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
        let mut node = Node::open(&root.path().join("native"), settings, 1).unwrap();
        attach_owner(&mut node, journal.path()).unwrap();
        (root, journal, node)
    }
    #[test]
    fn cancelling_installed_epoch_cannot_start_an_unused_old_view_permission() {
        let (_root, _journal, node) = node();
        let owner = node.mining_owner.as_ref().unwrap();
        let permission = &owner.view.body.permissions[0];
        let cancellation = node.mining_epoch_cancellation().unwrap();
        assert!(cancellation.cancel());
        assert!(!cancellation.cancel());
        assert!(owner
            .permission(Purpose::Search, permission.payload_sha256.clone(), 0)
            .is_err());
        assert_eq!(owner.journal.borrow().claim_count(), 0);
    }
    #[test]
    fn mode3_search_never_borrows_pool_reconcile_or_unscoped_activation() {
        let (_root, _journal, mut node) = node();
        let before = node.active().unwrap();
        assert!(node.pool_reconcile().is_err());
        assert!(node.activate(before.0).is_err());
        assert!(node.recover().is_err());
        assert_eq!(node.active().unwrap(), before);
    }
    #[test]
    fn opaque_search_intent_is_not_a_private_winner_validation_scope() {
        let (_root, _journal, node) = node();
        let owner = node.mining_owner.as_ref().unwrap();
        let p = &owner.view.body.permissions[0];
        let permit = owner
            .permission(Purpose::Search, p.payload_sha256.clone(), 0)
            .unwrap();
        let cpu = owner.cpu.begin().unwrap();
        let _scope = owner
            .enter(permit, cpu.checkpoint_handle(), None, None, None)
            .unwrap();
        assert!(node.mining_preview_gate().is_ok());
        assert!(node
            .mining_activation_gate(node.settings.genesis())
            .is_err());
        assert!(node.mining_recovery_unchanged().is_err());
        let measured = cpu.finish();
        assert!(!measured.accounting_unavailable);
    }
    #[test]
    fn fresh_cpu_domain_cannot_restart_the_same_nodes_live_budget() {
        let (_root, _journal, node) = node();
        let owner = node.mining_owner.as_ref().unwrap();
        let operation = &owner.view.body.permissions[0].operation_id;
        let fresh = ServiceMutationCpuDomain::standalone();
        let result = node.search_owned_mining_window(
            operation,
            Vec::new(),
            &[],
            &[],
            &fresh,
            &AtomicBool::new(false),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert_eq!(owner.journal.borrow().claim_count(), 0);
    }
    #[test]
    fn signed_parent_reconcile_reopens_only_unchanged_actual_pair() {
        let root = tempfile::tempdir().unwrap();
        let journal = tempfile::tempdir().unwrap();
        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
        let mut node = Node::open(&root.path().join("native"), settings, 1).unwrap();
        let mut body = view();
        let p = &mut body.permissions[0];
        p.purpose = Purpose::ParentReconcile;
        p.search = None;
        attach_owner_with_view(&mut node, journal.path(), body).unwrap();
        let before = node.active().unwrap();
        let owner = node.mining_owner.as_ref().unwrap();
        let permit = owner
            .permission(Purpose::ParentReconcile, hex::encode(before.0), before.1)
            .unwrap();
        let cpu = owner.cpu.begin().unwrap();
        let _scope = owner
            .enter(permit, cpu.checkpoint_handle(), None, None, None)
            .unwrap();
        assert_eq!(node.mining_recovery_unchanged().unwrap(), Some(before.0));
        assert_eq!(node.active().unwrap(), before);
        // An actual SQL generation change is not absorbed by the original grant.
        node.db
            .execute(
                "UPDATE active SET generation=generation+1 WHERE singleton=1",
                [],
            )
            .unwrap();
        assert!(node.mining_recovery_unchanged().is_err());
        assert_eq!(node.active().unwrap().0, before.0);
        let measured = cpu.finish();
        assert!(!measured.accounting_unavailable);
    }
}
