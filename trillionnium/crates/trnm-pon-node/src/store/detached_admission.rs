//! Ordinary-owner M06 outside the Node mutex. Neither a copied State nor a
//! public StagedOutput is commit authority: only this module constructs the
//! single-use result, and the original Node rechecks it before the unchanged
//! transactional publication/readback path. Restricted/continuous/growth and
//! opt-in ROOT-cache owners retain their existing held-owner entrypoints.
use super::*;
use std::sync::{atomic::Ordering, Arc};

// This bounds retained detached material, not allocator overhead or RSS.
// A larger valid parent explicitly keeps the original checked held schedule;
// it is neither invalid PoN work nor a new service/consensus State limit.
// Reuse the existing commitment material ceiling; do not silently retain one
// full State for every public CPU reservation after releasing the writer.
const MAX_SNAPSHOT_PAYLOAD: usize = pon_commitment::MAX_CACHE_PAYLOAD_BYTES;

/// A single original-Node capacity slot, not CPU credit. Private fields prevent
/// duplication; Drop releases ordinary returns/unwinds. Deliberately leaking
/// the private capability leaves its slot busy, never grants a second slot.
pub(crate) struct DetachedExecutionLease {
    owner: Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for DetachedExecutionLease {
    fn drop(&mut self) {
        self.owner.store(false, Ordering::Release);
    }
}

struct Pin {
    lease: DetachedExecutionLease,
    directory: PathBuf,
    directory_id: (u64, u64),
    database_id: (u64, u64),
    owner_id: (u64, u64),
    backend: StateBackend,
    network: Hash,
    parameters: Hash,
    genesis: Hash,
    epoch: AdmissionStateEpoch,
}

/// Constructed only after this artifact's fresh parent/context validation.
/// The original publication transaction validates it after BEGIN IMMEDIATE,
/// closing the foreign-writer gap between the last read and the first write.
pub(super) struct CommitFence {
    epoch: AdmissionStateEpoch,
    observed_now: u64,
}
impl CommitFence {
    pub(super) fn validate(self, node: &Node, packet: &Packet) -> Result<()> {
        node.namespace()?;
        node.storage_context()?;
        ensure(
            !node.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        ensure(
            node.admission_state_epoch()? == self.epoch,
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
        ensure(
            node.check_admission_header_context(packet, self.observed_now, None)?
                .is_none(),
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )
    }
}

pub(crate) enum PreparedSharedAdmission {
    Existing(Hash),
    Execute(Box<PreparedExecution>),
    HeldForSnapshotCapacity {
        checked: Box<HeldPreparedAdmission>,
        observed_payload_bytes: usize,
    },
}

/// Single-use held-owner continuation. The full State remains inside the
/// original capacity fallback; a foreign Node or changed SQLite epoch cannot
/// reuse its validation. It never authorizes detached execution.
pub(crate) struct HeldPreparedAdmission {
    checked: WorkCheckedPacket,
    parent: CheckedAdmissionParent,
    owner: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
enum SnapshotPayload {
    Fits(usize),
    HeldRequired { observed_bytes: usize },
}

/// No Clone, Deserialize, public fields or arbitrary-output constructor.
pub(crate) struct PreparedExecution {
    pin: Pin,
    checked: WorkCheckedPacket,
    parent: Record,
    prior: State,
    eligibility: ParentTaskEligibility,
    app: trnm_mvcc_fee::pon_executor::Config,
    workers: usize,
    predecessor: Option<CheckedCommitment>,
    active_candidate: bool,
    historical_candidate: bool,
    _admission_measurement: Option<native_authenticated::StageObservation>,
    execution_measurement: Option<native_authenticated::StageObservation>,
    binding_measurement: Option<native_authenticated::StageObservation>,
    #[cfg(test)]
    snapshot_payload_bytes: usize,
}

/// An owned result can be made only by executing the exact private preparation.
/// Public pon_commitment::StagedOutput never crosses the admission API.
pub(crate) struct ExecutedSharedAdmission {
    pin: Pin,
    admission: AdmissionPersistence,
    _measurement: Option<native_authenticated::StageObservation>,
}

fn payload_bytes(state: &State, control: &ExecutionControl<'_, Error>) -> Result<SnapshotPayload> {
    let mut total = 0usize;
    for (index, (key, value)) in state.iter().enumerate() {
        if index.is_multiple_of(256) {
            (control.progress)(ExecutionProgress::BeforeParentBinding)?;
        }
        // Each canonical cell is already bounded by the original native State
        // reader. Do not allocate a second serialized full-State buffer.
        let cell = canonical(value)?;
        total = total
            .checked_add(key.len())
            .and_then(|sum| sum.checked_add(cell.len()))
            .ok_or("PUBLIC_EXECUTION_SNAPSHOT_CAPACITY")?;
        if total > MAX_SNAPSHOT_PAYLOAD {
            return Ok(SnapshotPayload::HeldRequired {
                observed_bytes: total,
            });
        }
    }
    Ok(SnapshotPayload::Fits(total))
}

impl Node {
    pub(crate) fn detached_execution_supported(&self) -> bool {
        self.owner_policy.is_none()
            && self.mining_owner.is_none()
            && self.continuous_owner.is_none()
            && self.state_backend != StateBackend::PermanentAccountGrowthV2
            && !growth_profile_v2::enabled(&self.settings.app)
            && self.root_rejection_cache.borrow().is_none()
    }

    pub(crate) fn reserve_detached_execution(&self) -> Result<DetachedExecutionLease> {
        ensure(
            self.detached_execution_supported(),
            "OWNER_DETACHED_EXECUTION_UNSUPPORTED",
        )?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        self.detached_execution
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::new(crate::ErrorCode::PublicQueueBusy))?;
        Ok(DetachedExecutionLease {
            owner: Arc::clone(&self.detached_execution),
        })
    }

    pub(crate) fn prepare_shared_admission(
        &self,
        checked: WorkCheckedPacket,
        lease: DetachedExecutionLease,
        observed_now: u64,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<PreparedSharedAdmission> {
        ensure(
            self.detached_execution_supported(),
            "OWNER_DETACHED_EXECUTION_UNSUPPORTED",
        )?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        ensure(
            Arc::ptr_eq(&self.detached_execution, &lease.owner),
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )?;
        ensure(checked.owner_permit.is_none(), "OWNER_TASK_PERMIT_REQUIRED")?;
        (control.progress)(ExecutionProgress::BeforeParentBinding)?;
        self.namespace()?;
        self.storage_context()?;
        let measurement = (self.state_backend == StateBackend::AuthenticatedV1).then(|| {
            self.authenticated_arithmetic
                .history
                .observe(native_authenticated::HistoryStage::Admission)
        });
        let before = self.admission_state_epoch()?;
        let parent = match self.check_admission_context_for_permit(
            &checked.packet,
            observed_now,
            None,
            &mut || (control.progress)(ExecutionProgress::BeforeParentBinding),
        )? {
            CheckedAdmissionContext::Existing(id) => {
                return Ok(PreparedSharedAdmission::Existing(id))
            }
            CheckedAdmissionContext::Parent(parent) => parent,
        };
        ensure(
            parent.epoch == Some(before),
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )?;
        let snapshot_payload_bytes = match payload_bytes(&parent.state, control)? {
            SnapshotPayload::Fits(bytes) => bytes,
            SnapshotPayload::HeldRequired { observed_bytes } => {
                // No M06 ran. Preserve the private parent checked in this
                // original owner operation instead of discarding it and doing
                // the same full-State reconstruction again. Reuse requires the
                // same Node, current namespace, complete header and SQL epoch;
                // the original held executor and publication fences remain.
                return Ok(PreparedSharedAdmission::HeldForSnapshotCapacity {
                    checked: Box::new(HeldPreparedAdmission {
                        checked,
                        parent,
                        owner: Arc::clone(&self.detached_execution),
                    }),
                    observed_payload_bytes: observed_bytes,
                });
            }
        };
        // The same connection and actual owner must remain stable throughout
        // preparation. A diagnostic/foreign writer cannot create a trusted pin.
        ensure(
            self.admission_state_epoch()? == before,
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )?;
        let CheckedAdmissionParent {
            state: prior,
            eligibility,
            ..
        } = parent;
        let parent = self.record(checked.packet.header.parent)?;
        let active_prior = self.cached_parent(checked.packet.header.parent)?;
        let historical_prior = (self.state_backend == StateBackend::AuthenticatedV1
            && active_prior.is_none())
        .then(|| {
            self.historical_commitment_cache
                .borrow()
                .candidate(checked.packet.header.parent, parent.root)
        })
        .flatten();
        let owner = self.owner.metadata()?;
        let pin = Pin {
            lease,
            directory: self.directory.clone(),
            directory_id: self.directory_id,
            database_id: self.database_id,
            owner_id: (owner.dev(), owner.ino()),
            backend: self.state_backend,
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
            epoch: before,
        };
        #[cfg(not(test))]
        let _ = snapshot_payload_bytes;
        Ok(PreparedSharedAdmission::Execute(Box::new(
            PreparedExecution {
                pin,
                checked,
                parent,
                prior,
                eligibility,
                app: self.settings.app.clone(),
                workers: self.workers,
                active_candidate: active_prior.is_some(),
                historical_candidate: historical_prior.is_some(),
                predecessor: active_prior.or(historical_prior),
                _admission_measurement: measurement,
                execution_measurement: (self.state_backend == StateBackend::AuthenticatedV1).then(
                    || {
                        self.authenticated_arithmetic
                            .history
                            .observe(native_authenticated::HistoryStage::Execute)
                    },
                ),
                binding_measurement: (self.state_backend == StateBackend::AuthenticatedV1).then(
                    || {
                        self.authenticated_arithmetic
                            .history
                            .observe(native_authenticated::HistoryStage::ExecutionParentBinding)
                    },
                ),
                #[cfg(test)]
                snapshot_payload_bytes,
            },
        )))
    }

    pub(crate) fn admit_held_prepared(
        &mut self,
        prepared: HeldPreparedAdmission,
        observed_now: u64,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<Hash> {
        ensure(
            self.detached_execution_supported()
                && Arc::ptr_eq(&self.detached_execution, &prepared.owner),
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )?;
        self.namespace()?;
        self.storage_context()?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        self.admit_work_checked_with_parent(
            prepared.checked,
            observed_now,
            control,
            Some(prepared.parent),
        )
    }

    pub(crate) fn commit_shared_admission(
        &mut self,
        executed: ExecutedSharedAdmission,
        observed_now: u64,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<Hash> {
        let ExecutedSharedAdmission {
            pin,
            admission,
            _measurement,
        } = executed;
        (control.progress)(ExecutionProgress::BeforeParentBinding)?;
        ensure(
            self.detached_execution_supported(),
            "OWNER_DETACHED_EXECUTION_UNSUPPORTED",
        )?;
        ensure(
            !self.public_service_epoch_unknown,
            "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH",
        )?;
        self.namespace()?;
        self.storage_context()?;
        let owner = self.owner.metadata()?;
        ensure(
            Arc::ptr_eq(&self.detached_execution, &pin.lease.owner)
                && self.directory == pin.directory
                && self.directory_id == pin.directory_id
                && self.database_id == pin.database_id
                && (owner.dev(), owner.ino()) == pin.owner_id
                && self.state_backend == pin.backend
                && self.settings.network() == pin.network
                && self.settings.parameters() == pin.parameters
                && self.settings.genesis() == pin.genesis,
            "OWNER_DETACHED_EXECUTION_CONTEXT",
        )?;
        let current = self.admission_state_epoch()?;
        // This is the SAME original SQLite connection's counter. Even a foreign
        // write-and-restore is not continuity of the prepared owner operation.
        ensure(
            current.data_version == pin.epoch.data_version,
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
        // Recheck current clock/target/namespace/duplicate/parent header context
        // after reacquisition. A prepared clock or active tip is no authority.
        if let Some(id) =
            self.check_admission_header_context(&admission.packet, observed_now, None)?
        {
            return Ok(id);
        }
        let fresh_parent = self.record(admission.packet.header.parent)?;
        ensure(
            fresh_parent.parent == admission.parent.parent
                && fresh_parent.height == admission.parent.height
                && fresh_parent.root == admission.parent.root
                && fresh_parent.work.bytes() == admission.parent.work.bytes(),
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
        if current.total_changes != pin.epoch.total_changes {
            // A legal append/reorg can change the active branch while this
            // candidate's immutable parent remains valid. Fully recheck that
            // parent/task/material rather than rejecting every competing fork.
            let fresh = self.check_admission_parent(&admission.packet, &mut || {
                (control.progress)(ExecutionProgress::BeforeParentBinding)
            })?;
            ensure(fresh.state == admission.prior, "STORAGE_CONTEXT")
                .map_err(Error::local_integrity)?;
        }
        ensure(self.admission_state_epoch()? == current, "STORAGE_CONTEXT")
            .map_err(Error::local_integrity)?;
        (control.progress)(ExecutionProgress::BeforePersistence)?;
        *self.commitment_observation.borrow_mut() = Some(admission.commitment.observation.clone());
        // No cache, snapshot, CAS equality or native result replaces the original
        // SQL transaction and complete post-write parent/successor revalidation.
        let result = self.persist_admission_execution(
            admission,
            control,
            Some(CommitFence {
                epoch: current,
                observed_now,
            }),
        );
        drop(pin); // release capacity only after all execution/publication work
        result
    }
}

impl PreparedExecution {
    pub(crate) fn execute(
        self: Box<Self>,
        control: &ExecutionControl<'_, Error>,
    ) -> Result<ExecutedSharedAdmission> {
        let mut prepared = *self;
        let h = &prepared.checked.packet.header;
        (control.progress)(ExecutionProgress::BeforeParentBinding)?;
        let (bound, observation) = pon_commitment::CheckedExecutionParent::check_and_bind(
            &prepared.prior,
            prepared.parent.root,
            prepared.predecessor.as_ref(),
            CacheLimits::default(),
        )
        .map_err(|error| {
            Error::from(if error == "COMMITMENT_ROOT" {
                "ROOT"
            } else {
                error
            })
            .local_integrity()
        })?;
        if let Some(measurement) = &prepared.binding_measurement {
            // Count the real completed binding even if M06 later refuses ROOT
            // or is cancelled. This does not reacquire the Node writer.
            measurement.parent_binding(
                prepared.active_candidate,
                prepared.historical_candidate,
                observation.method,
            );
        }
        drop(prepared.binding_measurement.take());
        // Preserve both original cooperative parent-binding boundaries.
        (control.progress)(ExecutionProgress::BeforeParentBinding)?;
        let mut staged = bound
            .execute_with_control(
                ExecutionRequest {
                    transactions: &prepared.checked.packet.transactions,
                    height: h.height,
                    miner: h.miner,
                    parent_id: h.parent,
                    workers: prepared.workers,
                },
                &prepared.app,
                control,
            )
            .map_err(local_execution_error)?;
        drop(bound);
        if prepared.eligibility.manifest().is_some() {
            let product: Vec<u8> = prepared
                .checked
                .work
                .product()
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            if record_eligible_output(
                h.height,
                &mut staged.output.state,
                &prepared.eligibility,
                &product,
            )? {
                staged.commitment = pon_commitment::derive_snapshot(
                    &staged.output.state,
                    staged.commitment.snapshot.as_ref(),
                    CacheLimits::default(),
                )?;
                staged.output.root = staged.commitment.root;
            }
        }
        (control.progress)(ExecutionProgress::BeforeOutput)?;
        ensure(
            h.state == staged.output.root
                && h.receipts == sequence_root("receipts", &staged.output.receipts),
            "ROOT",
        )?;
        drop(prepared.execution_measurement.take());
        let bytes = prepared.checked.packet.encode()?;
        Ok(ExecutedSharedAdmission {
            pin: prepared.pin,
            admission: AdmissionPersistence {
                packet: prepared.checked.packet,
                bytes,
                parent: prepared.parent,
                prior: prepared.prior,
                output: staged.output,
                commitment: staged.commitment,
            },
            _measurement: prepared._admission_measurement,
        })
    }
}

#[cfg(test)]
mod tests;
