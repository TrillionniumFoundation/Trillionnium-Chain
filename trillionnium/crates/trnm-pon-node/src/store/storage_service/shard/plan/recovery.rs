//! Explicit complete-plan local detection/recovery under original M12 owners.
//!
//! No source-cache/catalog payload fallback, generated repair identities or
//! background service is provided. New repair tasks are individually supplied
//! and authenticated before work; Pending/Done only reconcile their targets.

use super::*;
use trnm_data_availability::cell::{
    CellErrorV1, CellRetainedShardPlanV1, CellRs46StoredShardV1, MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
};

#[path = "recovery/execute.rs"]
mod execute;

#[derive(Clone, Debug)]
pub struct NativeCellShardRecoveryRequestV1 {
    /// Complete original storage claims; their original M12 intents must exist.
    pub storage: NativeCellRetainedShardPlanRequestV1,
    /// Exact canonical coverage. None grants no repair authority. Every Some
    /// preserves one independently authorized task/claim/operation for its slot.
    pub repairs: Vec<Option<NativeCellShardRepairRequestV1>>,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeCellShardRecoveryLimitsV1 {
    pub deadline: Instant,
    pub maximum_plan_attempts: u32,
    pub maximum_provider_reads: u64,
    pub maximum_input_bytes: u64,
    pub maximum_reconstruction_bytes: u64,
    pub maximum_repairs: u64,
    pub maximum_repair_bytes: u64,
    pub maximum_cpu_ns: u64,
    /// Full ceiling reserved per admission, including failure. Actual thread
    /// CPU is reported separately when the original owner can observe it.
    pub cpu_ns_per_attempt: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeCellShardRecoveryUsageV1 {
    pub plan_attempts_committed: u32,
    pub provider_reads_committed: u64,
    pub input_bytes_committed: u64,
    pub reconstruction_bytes_committed: u64,
    pub repairs_committed: u64,
    pub repair_bytes_committed: u64,
    pub cpu_ns_committed: u64,
}

/// Caller-held, non-clone, cumulative admission. Logical target/codec inputs
/// and potential repair bytes are reservations, not measured disk/network
/// traffic or a new payment ledger. Failures never refund this original owner.
#[derive(Debug)]
pub struct NativeCellShardRecoveryBudgetV1 {
    limits: NativeCellShardRecoveryLimitsV1,
    usage: NativeCellShardRecoveryUsageV1,
    codec: CellRs46RepairBudgetV1,
}

impl NativeCellShardRecoveryBudgetV1 {
    pub fn new(limits: NativeCellShardRecoveryLimitsV1) -> Result<Self> {
        ensure(
            limits.maximum_plan_attempts > 0
                && limits.cpu_ns_per_attempt > 0
                && limits.cpu_ns_per_attempt <= limits.maximum_cpu_ns,
            "NATIVE_CELL_SHARD_RECOVERY_LIMITS",
        )?;
        let codec_attempts = limits
            .maximum_plan_attempts
            .checked_mul(2 * MAX_CELL_RETAINED_SHARD_CHUNKS_V1 as u32)
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_LIMITS")?;
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
                .ok_or("NATIVE_CELL_SHARD_RECOVERY_BUDGET")
        };
        let next = NativeCellShardRecoveryUsageV1 {
            plan_attempts_committed: self
                .usage
                .plan_attempts_committed
                .checked_add(1)
                .ok_or("NATIVE_CELL_SHARD_RECOVERY_BUDGET")?,
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
            "NATIVE_CELL_SHARD_RECOVERY_BUDGET",
        )?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCellShardRecoveryCpuV1 {
    pub observed_ns: u64,
    pub ceiling_ns: u64,
}

#[derive(Clone, Debug)]
pub struct NativeCellShardDamageV1 {
    pub operation: Hash,
    pub provider_store: Hash,
    pub reason: &'static str,
}

#[derive(Clone, Debug)]
pub struct NativeCellShardRecoveryActionV1 {
    pub operation: Hash,
    pub repair_operation: Hash,
    /// New admission is not a claim that the target actually required a copy.
    pub native: NativeCellEffectReadbackV1,
}

#[derive(Debug)]
pub struct NativeCellShardRecoveryFailureV1 {
    pub error: Error,
    pub usage: NativeCellShardRecoveryUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
    pub detected_damage: Vec<NativeCellShardDamageV1>,
    pub completed_actions: Vec<NativeCellShardRecoveryActionV1>,
    /// None is unknown, not zero; the original CPU ceiling remains committed.
    pub cpu: Option<NativeCellShardRecoveryCpuV1>,
}
impl std::fmt::Display for NativeCellShardRecoveryFailureV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, out)
    }
}
impl std::error::Error for NativeCellShardRecoveryFailureV1 {}

#[derive(Clone, Debug)]
pub struct NativeCellShardRecoveryReadbackV1 {
    pub plan: Hash,
    pub catalog: CellVersionCatalogAnchorV3,
    pub retained: [u8; 64],
    pub observed_at: NativeBudgetAnchorV1,
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
    plan: CellRetainedShardPlanV1,
    current: NativeBudgetAnchorV1,
    repair_replays: Vec<Option<NativeBudgetReplayV1>>,
    cost: RecoveryCost,
}

fn preflight(
    node: &mut Node,
    budgets: &NativeBudgetStoreV1,
    targets: &NativeCellRetainedShardPlanTargetsV1<'_>,
    request: &NativeCellShardRecoveryRequestV1,
    deadline: Instant,
) -> Result<PreparedRecovery> {
    storage_deadline(deadline)?;
    let plan = targets.plan_file.read(deadline).map_err(owner_error)?;
    let slot_count = plan.chunks().len() * 6;
    ensure(
        slot_count > 0
            && request.storage.slots.len() == slot_count
            && request.repairs.len() == slot_count,
        "NATIVE_CELL_SHARD_RECOVERY_EXACT_COVERAGE",
    )?;
    let mut identities = BTreeSet::from([plan.operation()]);
    let mut sources = BTreeSet::new();
    let mut checks = Vec::with_capacity(2 * slot_count);
    let mut wire_bytes = 0_u64;
    for (index, (entry, expected)) in request
        .storage
        .slots
        .iter()
        .zip(plan.chunks().iter().flat_map(|chunk| chunk.slots()))
        .enumerate()
    {
        storage_deadline(deadline)?;
        ensure(
            entry.contract == *expected,
            "NATIVE_CELL_SHARD_RECOVERY_EXACT_COVERAGE",
        )?;
        for identity in [
            entry.contract.operation(),
            entry.claim.claim,
            entry.policy.budget,
        ] {
            ensure(
                identity != [0; 32] && identities.insert(identity),
                "NATIVE_CELL_SHARD_RECOVERY_IDENTITY_ALIAS",
            )?;
        }
        ensure(
            sources.insert(entry.policy.source),
            "NATIVE_CELL_SHARD_RECOVERY_TASK_ALIAS",
        )?;
        checks.push(shard_storage_check(&targets.providers[index % 6], entry)?);
        wire_bytes = wire_bytes
            .checked_add(entry.contract.manifest().size())
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?;
    }
    let mut authorized_indices = Vec::new();
    let mut authorized_bytes = 0_u64;
    for (index, repair) in request.repairs.iter().enumerate() {
        let Some(repair) = repair else { continue };
        storage_deadline(deadline)?;
        let contract = &request.storage.slots[index].contract;
        let provider = &targets.providers[index % 6];
        let owner = contract.owner();
        let placement = &contract.placement().placements[usize::from(owner.slot)];
        task_policy(&repair.policy, &repair.claim)?;
        let effect = native_cell_shard_repair_subject_v1(
            provider,
            contract,
            repair.repair_operation,
            repair.claim.claim,
        );
        ensure(
            repair.binding == *contract.binding()
                && repair.operation == contract.operation()
                && repair.claim.subject == effect
                && repair.claim.beneficiary == placement.repair_owner
                && matches!(repair.claim.resource_reservation,
                NativeBudgetResourcesV1::Repair { cpu_ns, download_bytes, upload_bytes, attempts }
                if cpu_ns > 0 && download_bytes >= contract.manifest().size()
                    && upload_bytes >= contract.manifest().size() && attempts >= 1),
            "NATIVE_CELL_SHARD_RECOVERY_REPAIR_BINDING",
        )?;
        for identity in [
            repair.repair_operation,
            repair.claim.claim,
            repair.policy.budget,
        ] {
            ensure(
                identity != [0; 32] && identities.insert(identity),
                "NATIVE_CELL_SHARD_RECOVERY_IDENTITY_ALIAS",
            )?;
        }
        ensure(
            sources.insert(repair.policy.source),
            "NATIVE_CELL_SHARD_RECOVERY_TASK_ALIAS",
        )?;
        checks.push(NativeBudgetEffectCheckV1 {
            policy: &repair.policy,
            claim: &repair.claim,
            operation: repair.repair_operation,
            effect,
            window: Some((owner.retain_from_height, owner.retain_until_height)),
        });
        authorized_indices.push(index);
        authorized_bytes = authorized_bytes
            .checked_add(contract.manifest().size())
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?;
    }
    let replays = budgets.check_effects(node, &checks).map_err(owner_error)?;
    ensure(
        replays[..slot_count]
            .iter()
            .all(|replay| *replay != NativeBudgetReplayV1::New),
        "NATIVE_CELL_SHARD_RECOVERY_ORIGINAL_INTENT_REQUIRED",
    )?;
    let mut repair_replays = vec![None; slot_count];
    let mut repairs = 0_u64;
    let mut repair_bytes = 0_u64;
    for (index, replay) in authorized_indices.iter().zip(&replays[slot_count..]) {
        repair_replays[*index] = Some(*replay);
        if *replay == NativeBudgetReplayV1::New {
            repairs += 1;
            repair_bytes = repair_bytes
                .checked_add(request.storage.slots[*index].contract.manifest().size())
                .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?;
        }
    }
    storage_deadline(deadline)?;
    let current = node
        .native_funding_observation(request.storage.slots[0].policy.source)?
        .anchor;
    targets
        .plan_file
        .read_current(targets.catalog, current.height, deadline)
        .map_err(owner_error)?;
    storage_deadline(deadline)?;
    let source_bytes = plan.chunks().iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(u64::from(chunk.binding().source_bytes()))
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")
    })?;
    // Two complete target scans, up to one original repair call per authorized
    // slot and two complete codec admissions per chunk. Logical wire bounds
    // conservatively cover failed work; filesystem amplification is not claimed.
    let cost = RecoveryCost {
        provider_reads: (slot_count as u64)
            .checked_mul(2)
            .and_then(|count| count.checked_add(authorized_indices.len() as u64))
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?,
        input_bytes: wire_bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(authorized_bytes))
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?,
        reconstruction_bytes: wire_bytes
            .checked_add(source_bytes)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or("NATIVE_CELL_SHARD_RECOVERY_SIZE")?,
        repairs,
        repair_bytes,
    };
    Ok(PreparedRecovery {
        plan,
        current,
        repair_replays,
        cost,
    })
}

impl Node {
    /// Detect and repair one complete immutable local plan using actual original
    /// provider bytes. There is no source/catalog fallback and no generated
    /// repair identity. Pending/Done retain their target-only M12 semantics.
    pub fn recover_native_cell_shard_plan(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellRetainedShardPlanTargetsV1<'_>,
        request: NativeCellShardRecoveryRequestV1,
        budget: &mut NativeCellShardRecoveryBudgetV1,
    ) -> std::result::Result<NativeCellShardRecoveryReadbackV1, Box<NativeCellShardRecoveryFailureV1>>
    {
        let mut damage = Vec::new();
        let mut actions = Vec::new();
        let mut cpu_observation = None;
        let result = (|| -> Result<NativeCellShardRecoveryReadbackV1> {
            let prepared = preflight(self, budgets, &targets, &request, budget.limits.deadline)?;
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
            let (slots, observed_at) = outcome?;
            let cpu = measured?;
            Ok(NativeCellShardRecoveryReadbackV1 {
                plan: prepared.plan.commitment(),
                catalog: prepared.plan.catalog_anchor(),
                retained: prepared.plan.retained_commitment(),
                observed_at,
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
