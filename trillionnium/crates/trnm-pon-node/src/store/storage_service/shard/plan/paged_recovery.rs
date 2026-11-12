//! Complete CRR2/CRG2 recovery using the original native and physical owners.
//! Census, repairs and final observation share one caller-held allowance.

use super::*;
use trnm_data_availability::cell::{
    CellPagedRetainedShardPlanV2, CellRetainedShardChunkV1, MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
};

#[path = "paged_recovery/execute.rs"]
mod execute;
#[path = "paged_recovery/preflight.rs"]
mod preflight;

#[derive(Clone, Debug)]
pub struct NativeCellPagedShardRecoveryRequestV2 {
    /// Every original storage claim, in the root's canonical chunk/slot order.
    /// Recovery requires its M12 intent to exist; it cannot initiate storage.
    pub storage: NativeCellRetainedShardPlanRequestV1,
    /// Same exact whole-root coverage. None grants no repair authority. Each
    /// Some keeps its independently funded operation and original replay state.
    pub repairs: Vec<Option<NativeCellShardRepairRequestV1>>,
}

/// Explicit V2 capacity, with the same non-clone cumulative owner as V1. Page
/// boundaries never construct a fresh allowance. Three whole-root passes and
/// up to three codec admissions per chunk are reserved before the census.
/// This logical observation allowance is not a physical or payment ledger.
#[derive(Debug)]
pub struct NativeCellPagedShardRecoveryBudgetV2 {
    inner: NativeCellShardRecoveryBudgetV1,
}

impl NativeCellPagedShardRecoveryBudgetV2 {
    pub fn new(limits: NativeCellShardRecoveryLimitsV1) -> Result<Self> {
        ensure(
            limits.maximum_plan_attempts > 0
                && limits.cpu_ns_per_attempt > 0
                && limits.cpu_ns_per_attempt <= limits.maximum_cpu_ns,
            "NATIVE_CELL_PAGED_RECOVERY_LIMITS",
        )?;
        let codec_attempts = limits
            .maximum_plan_attempts
            .checked_mul(3 * MAX_CELL_PAGED_RETAINED_CHUNKS_V2 as u32)
            .ok_or("NATIVE_CELL_PAGED_RECOVERY_LIMITS")?;
        Ok(Self {
            inner: NativeCellShardRecoveryBudgetV1 {
                limits,
                usage: NativeCellShardRecoveryUsageV1::default(),
                codec: CellRs46RepairBudgetV1::new(
                    limits.deadline,
                    codec_attempts,
                    limits.maximum_input_bytes,
                    limits.maximum_reconstruction_bytes,
                ),
            },
        })
    }

    pub fn usage(&self) -> NativeCellShardRecoveryUsageV1 {
        self.inner.usage()
    }

    pub fn codec_usage(&self) -> CellRs46RepairUsageV1 {
        self.inner.codec_usage()
    }
}

/// Sequential verified observations of the whole root, never a new authority
/// journal. Return requires every original storage intent to read back Done
/// after the final complete target scan. A slot that reconciled Pending during
/// that scan truthfully retains Pending as its admission/replay observation.
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

struct PreparedPagedRecovery {
    plan: CellPagedRetainedShardPlanV2,
    current: NativeBudgetAnchorV1,
    repair_replays: Vec<Option<NativeBudgetReplayV1>>,
    cost: RecoveryCost,
}

impl Node {
    /// Recover a complete immutable paged root only from actual verified
    /// original provider targets. All funding, identity, capacity and quorum
    /// checks cover the whole root before any new repair. Catalog/source bytes
    /// are never staged. Pending/Done retain their original target-only path.
    pub fn recover_native_cell_paged_shard_plan(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellPagedRetainedShardPlanTargetsV2<'_>,
        request: NativeCellPagedShardRecoveryRequestV2,
        budget: &mut NativeCellPagedShardRecoveryBudgetV2,
    ) -> std::result::Result<
        NativeCellPagedShardRecoveryReadbackV2,
        Box<NativeCellShardRecoveryFailureV1>,
    > {
        let mut damage = Vec::new();
        let mut actions = Vec::new();
        let mut cpu_observation = None;
        let result = (|| -> Result<NativeCellPagedShardRecoveryReadbackV2> {
            let prepared = preflight::prepare(
                self,
                budgets,
                &targets,
                &request,
                budget.inner.limits.deadline,
            )?;
            let next = budget.inner.projection(prepared.cost)?;
            // Every admitted failure keeps this original complete reservation,
            // including late-page damage, exhausted history and unknown CPU.
            budget.inner.usage = next;
            let mut cpu = RepairCpuOwner::start(
                budget.inner.limits.cpu_ns_per_attempt,
                budget.inner.limits.deadline,
            )
            .map_err(owner_error)?;
            let outcome = execute::Execution {
                node: self,
                budgets,
                targets,
                request: &request,
                prepared: &prepared,
                budget: &mut budget.inner,
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
            let (pages, slots, observed_at) = outcome?;
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
