//! Native task funding -> M12 physical-effect journal -> M09 retained bytes.
//!
//! This composition verifies current native task funding before new work. It
//! neither locks native coins against cancellation/reorg nor pays a provider.
//! A completed initial copy proves bytes at readback, not future byte-blocks,
//! independent custody, release qualification or production activation.

use std::time::Instant;

use super::Node;
use crate::{ensure, Error, Result};
use trnm_data_availability::cell::{
    CellErrorV1, CellResultV1, CellRetentionContractV1, CellRetentionReadbackV1,
    CellRetentionStoreV1, CellStoreV1,
};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_service_settlement::native_budget::{
    NativeBudgetClaimV1, NativeBudgetPolicyV1, NativeBudgetReplayV1, NativeBudgetResourcesV1,
    NativeBudgetStoreV1, NativeFundingSourceV1,
};

#[derive(Clone, Debug)]
pub struct NativeCellRetentionRequestV1 {
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub contract: CellRetentionContractV1,
}

#[derive(Clone, Debug)]
pub struct NativeCellRepairRequestV1 {
    /// A separate native task and Repair lane, never the original storage job.
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub obligation: Hash,
    pub repair_operation: Hash,
}

#[derive(Clone, Debug)]
pub struct NativeCellEffectReadbackV1 {
    pub target: CellRetentionReadbackV1,
    pub effect: Hash,
    pub target_receipt: Hash,
    /// Pending/Done are readback-only; neither permits another physical write.
    pub replay: NativeBudgetReplayV1,
    /// This invocation only. Recovery cannot reconstruct an earlier attempt's
    /// CPU use, and this observation does not refund its original reservation.
    pub repair_cpu_observation: Option<NativeCellRepairCpuObservationV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCellRepairCpuObservationV1 {
    pub observed_ns: u64,
    pub ceiling_ns: u64,
    pub original_attempt: bool,
}

// A synchronous owner scope, bound to one real thread and an absolute wall
// deadline. Missing, regressed or cross-thread measurements fail closed. Each
// M09 chunk/SQL/filesystem interval is cooperative, not kernel-preempted.
struct RepairCpuOwner {
    thread: std::thread::ThreadId,
    started_ns: u64,
    last_ns: u64,
    ceiling_ns: u64,
    deadline: Instant,
    stopped: bool,
}
impl RepairCpuOwner {
    fn start(ceiling_ns: u64, deadline: Instant) -> CellResultV1<Self> {
        if ceiling_ns == 0 || Instant::now() >= deadline {
            return Err(CellErrorV1::Invalid("native repair CPU or wall budget"));
        }
        let now = repair_thread_cpu_ns()
            .ok_or(CellErrorV1::Invalid("native repair CPU clock unavailable"))?;
        Ok(Self {
            thread: std::thread::current().id(),
            started_ns: now,
            last_ns: now,
            ceiling_ns,
            deadline,
            stopped: false,
        })
    }
    fn check(&mut self) -> CellResultV1<()> {
        let accepted = !self.stopped
            && self.thread == std::thread::current().id()
            && Instant::now() < self.deadline;
        let sampled = if accepted {
            repair_thread_cpu_ns()
        } else {
            None
        };
        if let Some(now) = sampled.filter(|now| *now >= self.last_ns) {
            self.last_ns = now;
            if now
                .checked_sub(self.started_ns)
                .is_some_and(|used| used <= self.ceiling_ns)
            {
                return Ok(());
            }
        }
        self.stopped = true;
        Err(CellErrorV1::Invalid(
            "native repair CPU or wall budget exhausted",
        ))
    }
    fn finish(mut self, original_attempt: bool) -> CellResultV1<NativeCellRepairCpuObservationV1> {
        self.check()?;
        Ok(NativeCellRepairCpuObservationV1 {
            observed_ns: self.last_ns - self.started_ns,
            ceiling_ns: self.ceiling_ns,
            original_attempt,
        })
    }
}
#[cfg(target_os = "linux")]
fn repair_thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let sec = u64::try_from(stamp.tv_sec).ok()?;
    let ns = u64::try_from(stamp.tv_nsec).ok()?;
    if ns >= 1_000_000_000 {
        return None;
    }
    sec.checked_mul(1_000_000_000)?.checked_add(ns)
}
#[cfg(not(target_os = "linux"))]
fn repair_thread_cpu_ns() -> Option<u64> {
    None
}

/// The ordinary native task output must be this exact immutable target.
pub fn native_cell_repair_subject_v1(
    store: &CellRetentionStoreV1,
    contract: &CellRetentionContractV1,
    repair_operation: Hash,
    repair_claim: Hash,
) -> Hash {
    hash(
        b"trnm.native-cell-repair-subject.v1\0",
        &[
            &contract.commitment(store.store_id()),
            &repair_operation,
            &repair_claim,
        ],
    )
}

fn owner_error(error: impl std::fmt::Display) -> Error {
    format!("NATIVE_CELL_OWNER: {error}").into()
}

fn task_policy(policy: &NativeBudgetPolicyV1, claim: &NativeBudgetClaimV1) -> Result<()> {
    ensure(
        matches!(policy.source, NativeFundingSourceV1::Task(_)) && policy.budget == claim.budget,
        "NATIVE_CELL_TASK_BUDGET_REQUIRED",
    )
}

impl Node {
    pub fn retain_native_cell(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        retention: &mut CellRetentionStoreV1,
        cache: &CellStoreV1,
        request: NativeCellRetentionRequestV1,
        deadline: Instant,
    ) -> Result<NativeCellEffectReadbackV1> {
        let NativeCellRetentionRequestV1 {
            policy,
            claim,
            contract,
        } = request;
        task_policy(&policy, &claim)?;
        let effect = contract.commitment(retention.store_id());
        let span = contract
            .retain_until_height
            .checked_sub(contract.retain_from_height)
            .filter(|span| *span > 0)
            .ok_or("NATIVE_CELL_RETENTION_SPAN")?;
        let required = contract
            .manifest
            .size()
            .checked_mul(span)
            .ok_or("NATIVE_CELL_BYTE_BLOCK_OVERFLOW")?;
        ensure(
            contract.funding_operation == claim.claim
                && claim.subject == effect
                && contract.retain_until_height <= policy.deadline
                && matches!(claim.resource_reservation,
                    NativeBudgetResourcesV1::Storage { retained_bytes, retained_byte_blocks }
                    if retained_bytes >= contract.manifest.size() && retained_byte_blocks >= required),
            "NATIVE_CELL_STORAGE_BINDING",
        )?;
        budgets
            .open_budget(self, policy.clone())
            .map_err(owner_error)?;
        budgets.reserve(self, claim.clone()).map_err(owner_error)?;
        // Physical capacity is reserved before the intent. A failure consumes
        // the original local monetary hold until native expiry; no refund is
        // invented from an unavailable destination or a changed branch.
        let reserved = retention.reserve(contract.clone()).map_err(owner_error)?;
        ensure(!reserved.retired, "NATIVE_CELL_RETIRED")?;
        let replay = budgets
            .begin_effect_in_window(
                self,
                claim.claim,
                contract.operation,
                effect,
                contract.retain_from_height,
                contract.retain_until_height,
            )
            .map_err(owner_error)?;
        let target = match replay {
            NativeBudgetReplayV1::New => retention
                .acknowledge(contract.operation, cache, deadline)
                .map_err(owner_error)?,
            NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => {
                // Never dispatch the initial copy again after an unknown
                // effect. A new separately funded repair can complete bytes.
                retention
                    .reconcile_acknowledgement(contract.operation, deadline)
                    .map_err(owner_error)?
            }
        };
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_TARGET_ACK",
        )?;
        let target_receipt = hash(b"trnm.native-cell-initial-readback.v1\0", &[&effect]);
        budgets
            .complete_effect(claim.claim, contract.operation, target_receipt)
            .map_err(owner_error)?;
        // Future retention has not happened. Keep the original reservation
        // charged; no Positive outcome, resource refund or payment is issued.
        Ok(NativeCellEffectReadbackV1 {
            target,
            effect,
            target_receipt,
            replay,
            repair_cpu_observation: None,
        })
    }

    pub fn repair_native_cell(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        retention: &mut CellRetentionStoreV1,
        cache: &CellStoreV1,
        request: NativeCellRepairRequestV1,
        deadline: Instant,
    ) -> Result<NativeCellEffectReadbackV1> {
        let NativeCellRepairRequestV1 {
            policy,
            claim,
            obligation,
            repair_operation,
        } = request;
        task_policy(&policy, &claim)?;
        let cpu_ns = match claim.resource_reservation {
            NativeBudgetResourcesV1::Repair { cpu_ns, .. } if cpu_ns > 0 => cpu_ns,
            _ => return Err("NATIVE_CELL_REPAIR_CPU_REQUIRED".into()),
        };
        let mut cpu = RepairCpuOwner::start(cpu_ns, deadline).map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let contract = retention.contract(obligation).map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let effect =
            native_cell_repair_subject_v1(retention, &contract, repair_operation, claim.claim);
        ensure(
            claim.claim != contract.funding_operation
                && claim.subject == effect
                && repair_operation != obligation
                && repair_operation != [0; 32]
                && matches!(claim.resource_reservation,
                    NativeBudgetResourcesV1::Repair { download_bytes, attempts, .. }
                    if download_bytes >= contract.manifest.size() && attempts >= 1),
            "NATIVE_CELL_REPAIR_BINDING",
        )?;
        budgets
            .open_budget(self, policy.clone())
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        budgets.reserve(self, claim.clone()).map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let replay = budgets
            .begin_effect_in_window(
                self,
                claim.claim,
                repair_operation,
                effect,
                contract.retain_from_height,
                contract.retain_until_height,
            )
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let target = match replay {
            NativeBudgetReplayV1::New => retention
                .repair_controlled(obligation, repair_operation, cache, deadline, &mut || {
                    cpu.check()
                })
                .map_err(owner_error)?,
            NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => retention
                .reconcile_repair_controlled(obligation, repair_operation, deadline, &mut || {
                    cpu.check()
                })
                .map_err(owner_error)?,
        };
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_TARGET_ACK",
        )?;
        let target_receipt = hash(b"trnm.native-cell-repair-readback.v1\0", &[&effect]);
        budgets
            .complete_effect(claim.claim, repair_operation, target_receipt)
            .map_err(owner_error)?;
        let repair_cpu_observation = Some(
            cpu.finish(replay == NativeBudgetReplayV1::New)
                .map_err(owner_error)?,
        );
        // This is an invocation observation, not a durable whole-lifecycle
        // receipt. Keep the full reservation on success, unknown and recovery;
        // do not infer network bytes, aggregate retry cost or Positive payment.
        Ok(NativeCellEffectReadbackV1 {
            target,
            effect,
            target_receipt,
            replay,
            repair_cpu_observation,
        })
    }

    /// Only the current native chain height can release this local obligation.
    /// Caller-supplied heights and old receipts do not free physical capacity.
    pub fn retire_native_cell(
        &self,
        retention: &mut CellRetentionStoreV1,
        operation: Hash,
        successor: Option<&mut CellRetentionStoreV1>,
        deadline: Instant,
    ) -> Result<CellRetentionReadbackV1> {
        // The absent task lookup is used only to obtain an authenticated
        // current anchor through the same owner path on every backend.
        let current = self.native_funding_observation(NativeFundingSourceV1::Task([0; 32]))?;
        retention
            .retire(operation, current.anchor.height, successor, deadline)
            .map_err(owner_error)
    }
}

#[cfg(test)]
mod tests;
