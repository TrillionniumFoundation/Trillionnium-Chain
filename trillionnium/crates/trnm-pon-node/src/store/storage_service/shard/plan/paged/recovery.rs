//! Complete CRR2 recovery under one cumulative budget and one CPU owner.
//!
//! No source-cache/catalog payload fallback, generated repair identities or
//! background service is provided. New repair tasks are individually supplied
//! and authenticated before work; Pending/Done only reconcile their targets.

use super::*;
use trnm_data_availability::cell::{
    CellErrorV1, CellPagedRetainedShardPlanV2, CellRs46StoredShardV1,
    MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
};

#[path = "recovery/execute.rs"]
mod execute;
#[path = "recovery/preflight.rs"]
mod preflight;

/// Caller-held, non-clone, cumulative admission. Logical target/codec inputs
/// and potential repair bytes are reservations, not measured disk/network
/// traffic or a new payment ledger. Failures never refund this original owner.
#[derive(Debug)]
pub struct NativeCellPagedShardRecoveryBudgetV2 {
    limits: NativeCellShardRecoveryLimitsV1,
    usage: NativeCellShardRecoveryUsageV1,
    codec: CellRs46RepairBudgetV1,
}

impl NativeCellPagedShardRecoveryBudgetV2 {
    pub fn new(limits: NativeCellShardRecoveryLimitsV1) -> Result<Self> {
        ensure(
            limits.maximum_plan_attempts > 0
                && limits.cpu_ns_per_attempt > 0
                && limits.cpu_ns_per_attempt <= limits.maximum_cpu_ns,
            "NATIVE_CELL_PAGED_SHARD_RECOVERY_LIMITS",
        )?;
        let codec_attempts = limits
            .maximum_plan_attempts
            .checked_mul(3 * MAX_CELL_PAGED_RETAINED_CHUNKS_V2 as u32)
            .ok_or("NATIVE_CELL_PAGED_SHARD_RECOVERY_LIMITS")?;
        Ok(Self {
            limits,
            usage: NativeCellShardRecoveryUsageV1::default(),
            codec: CellRs46RepairBudgetV1::new(
                limits.deadline,
                codec_attempts,
                limits.maximum_input_bytes,
                limits.maximum_reconstruction_bytes,
            ),
        })
    }
    pub fn usage(&self) -> NativeCellShardRecoveryUsageV1 {
        self.usage
    }
    pub fn codec_usage(&self) -> CellRs46RepairUsageV1 {
        self.codec.usage()
    }

    fn projection(&self, cost: RecoveryCost) -> Result<NativeCellShardRecoveryUsageV1> {
        storage_deadline(self.limits.deadline)?;
        let add = |left: u64, right: u64| {
            left.checked_add(right)
                .ok_or("NATIVE_CELL_PAGED_SHARD_RECOVERY_BUDGET")
        };
        let next = NativeCellShardRecoveryUsageV1 {
            plan_attempts_committed: self
                .usage
                .plan_attempts_committed
                .checked_add(1)
                .ok_or("NATIVE_CELL_PAGED_SHARD_RECOVERY_BUDGET")?,
            provider_reads_committed: add(
                self.usage.provider_reads_committed,
                cost.provider_reads,
            )?,
            input_bytes_committed: add(self.usage.input_bytes_committed, cost.input_bytes)?,
            reconstruction_bytes_committed: add(
                self.usage.reconstruction_bytes_committed,
                cost.reconstruction_bytes,
            )?,
            repairs_committed: add(self.usage.repairs_committed, cost.repairs)?,
            repair_bytes_committed: add(self.usage.repair_bytes_committed, cost.repair_bytes)?,
            cpu_ns_committed: add(self.usage.cpu_ns_committed, self.limits.cpu_ns_per_attempt)?,
        };
        ensure(
            next.plan_attempts_committed <= self.limits.maximum_plan_attempts
                && next.provider_reads_committed <= self.limits.maximum_provider_reads
                && next.input_bytes_committed <= self.limits.maximum_input_bytes
                && next.reconstruction_bytes_committed <= self.limits.maximum_reconstruction_bytes
                && next.repairs_committed <= self.limits.maximum_repairs
                && next.repair_bytes_committed <= self.limits.maximum_repair_bytes
                && next.cpu_ns_committed <= self.limits.maximum_cpu_ns,
            "NATIVE_CELL_PAGED_SHARD_RECOVERY_BUDGET",
        )?;
        Ok(next)
    }
}

#[derive(Clone, Debug)]
pub struct NativeCellPagedShardRecoveryReadbackV2 {
    pub plan: Hash,
    pub catalog: CellVersionCatalogAnchorV3,
    pub retained: [u8; 64],
    pub observed_at: NativeBudgetAnchorV1,
    pub pages: Vec<NativeCellRetainedShardPageReadbackV2>,
    pub slots: Vec<NativeCellRetainedShardSlotReadbackV1>,
    pub detected_damage: Vec<NativeCellShardDamageV1>,
    pub actions: Vec<NativeCellShardRecoveryActionV1>,
    pub usage: NativeCellShardRecoveryUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
    pub cpu: NativeCellShardRecoveryCpuV1,
}

#[derive(Clone, Copy)]
struct RecoveryCost {
    provider_reads: u64,
    input_bytes: u64,
    reconstruction_bytes: u64,
    repairs: u64,
    repair_bytes: u64,
}
struct PreparedRecovery {
    plan: CellPagedRetainedShardPlanV2,
    current: NativeBudgetAnchorV1,
    repair_replays: Vec<Option<NativeBudgetReplayV1>>,
    cost: RecoveryCost,
}

impl Node {
    /// Detect and repair one complete immutable local plan using actual original
    /// provider bytes. There is no source/catalog fallback and no generated
    /// repair identity. Pending/Done retain their target-only M12 semantics.
    /// The CPU receipt covers admitted execution across every page and final
    /// readback. Bounded metadata/funding preflight precedes that CPU owner and
    /// retains the original wall deadline; it is not included in this receipt.
    pub fn recover_native_cell_paged_shard_plan(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellPagedRetainedShardPlanTargetsV2<'_>,
        request: NativeCellShardRecoveryRequestV1,
        budget: &mut NativeCellPagedShardRecoveryBudgetV2,
    ) -> std::result::Result<
        NativeCellPagedShardRecoveryReadbackV2,
        Box<NativeCellShardRecoveryFailureV1>,
    > {
        let mut damage = Vec::new();
        let mut actions = Vec::new();
        let mut cpu_observation = None;
        let result = (|| -> Result<NativeCellPagedShardRecoveryReadbackV2> {
            let prepared =
                preflight::prepare(self, budgets, &targets, &request, budget.limits.deadline)?;
            let next = budget.projection(prepared.cost)?;
            // The original allowance survives all admitted failures, including
            // inability to start/measure CPU, a late missing target or Unknown.
            budget.usage = next;
            let mut cpu =
                RepairCpuOwner::start(budget.limits.cpu_ns_per_attempt, budget.limits.deadline)
                    .map_err(owner_error)?;
            let outcome = execute::Execution {
                node: self,
                budgets,
                targets,
                request: &request,
                prepared: &prepared,
                budget,
                cpu: &mut cpu,
                damage: &mut damage,
                actions: &mut actions,
            }
            .run();
            let measured = cpu
                .finish(true)
                .map(|observed| NativeCellShardRecoveryCpuV1 {
                    observed_ns: observed.observed_ns,
                    ceiling_ns: observed.ceiling_ns,
                })
                .map_err(owner_error);
            if let Ok(observed) = &measured {
                cpu_observation = Some(*observed);
            }
            let (slots, observed_at, pages) = outcome?;
            let cpu = measured?;
            Ok(NativeCellPagedShardRecoveryReadbackV2 {
                plan: prepared.plan.commitment(),
                catalog: prepared.plan.catalog_anchor(),
                retained: prepared.plan.retained_commitment(),
                observed_at,
                pages,
                slots,
                detected_damage: damage.clone(),
                actions: actions.clone(),
                usage: budget.usage(),
                codec_usage: budget.codec_usage(),
                cpu,
            })
        })();
        result.map_err(|error| {
            Box::new(NativeCellShardRecoveryFailureV1 {
                error,
                usage: budget.usage(),
                codec_usage: budget.codec_usage(),
                detected_damage: damage,
                completed_actions: actions,
                cpu: cpu_observation,
            })
        })
    }
}
