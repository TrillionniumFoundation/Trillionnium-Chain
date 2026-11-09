//! Ordinary M12 funding and current-chain ownership for physical CSP1 slots.
//!
//! New admits exactly the original target copy. Pending and Done inspect only
//! that target and retain the original debit even when their source vanished.
//! Declared provider identities do not establish independent WAN custody or a
//! positive payment. RS reconstruction keeps its separate original budget.

use super::*;
use trnm_data_availability::cell::{
    CellRs46ChunkBindingV1, CellRs46ShardContractV1, CellRs46ShardProviderV1,
    CellRs46ShardRepairRequestV1, CellRs46StoredShardV1,
};
use trnm_service_settlement::native_budget::NativeBudgetEffectCheckV1;

#[path = "shard/plan.rs"]
mod plan;
pub use plan::{
    NativeCellRetainedShardPlanReadbackV1, NativeCellRetainedShardPlanRequestV1,
    NativeCellRetainedShardPlanTargetsV1, NativeCellRetainedShardSlotReadbackV1,
    NativeCellRetainedShardVerificationBudgetV1, NativeCellShardDamageV1,
    NativeCellShardRecoveryActionV1, NativeCellShardRecoveryBudgetV1, NativeCellShardRecoveryCpuV1,
    NativeCellShardRecoveryFailureV1, NativeCellShardRecoveryLimitsV1,
    NativeCellShardRecoveryReadbackV1, NativeCellShardRecoveryRequestV1,
    NativeCellShardRecoveryUsageV1,
};

#[derive(Clone, Debug)]
pub struct NativeCellShardRetentionRequestV1 {
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub contract: CellRs46ShardContractV1,
}

#[derive(Clone, Debug)]
pub struct NativeCellShardRepairRequestV1 {
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub binding: CellRs46ChunkBindingV1,
    pub operation: Hash,
    pub repair_operation: Hash,
}

#[derive(Clone, Debug)]
pub struct NativeCellShardEffectReadbackV1 {
    pub native: NativeCellEffectReadbackV1,
    /// Sealed by reading the actual acknowledged provider arena, including CRS1
    /// and the complete CRC1/placement/original-operation descriptor bindings.
    pub stored: CellRs46StoredShardV1,
}

fn shard_initial_receipt(effect: Hash) -> Hash {
    hash(b"trnm.native-cell-shard-initial-readback.v1\0", &[&effect])
}

pub fn native_cell_shard_repair_subject_v1(
    provider: &CellRs46ShardProviderV1,
    contract: &CellRs46ShardContractV1,
    repair_operation: Hash,
    repair_claim: Hash,
) -> Hash {
    let original = contract
        .retention_contract()
        .commitment(provider.store_id());
    hash(
        b"trnm.native-cell-shard-repair-subject.v1\0",
        &[&original, &repair_operation, &repair_claim],
    )
}

fn shard_storage_check<'a>(
    provider: &CellRs46ShardProviderV1,
    request: &'a NativeCellShardRetentionRequestV1,
) -> Result<NativeBudgetEffectCheckV1<'a>> {
    let contract = &request.contract;
    let owner = contract.owner();
    let config = provider.configuration();
    let physical = contract.retention_contract();
    let effect = physical.commitment(provider.store_id());
    task_policy(&request.policy, &request.claim)?;
    // Decode against its independent original binding before indexing or
    // writing. Public constructors also validate, and fields remain private.
    let decoded = CellRs46ShardContractV1::decode_pinned(
        &contract.encode(),
        contract.binding(),
        contract.operation(),
    )
    .map_err(owner_error)?;
    ensure(decoded == *contract, "NATIVE_CELL_SHARD_DESCRIPTOR")?;
    let placement = &contract.placement().placements[usize::from(owner.slot)];
    let byte_blocks = owner
        .retain_until_height
        .checked_sub(owner.retain_from_height)
        .filter(|span| *span > 0)
        .and_then(|span| physical.manifest.size().checked_mul(span))
        .ok_or("NATIVE_CELL_SHARD_BYTE_BLOCK_OVERFLOW")?;
    ensure(
        owner.provider_store == provider.store_id()
            && owner.owner_generation == config.owner_generation
            && *placement == config.placement
            && request.claim.claim == owner.funding_operation
            && request.claim.subject == effect
            && request.claim.beneficiary == placement.responsible_owner
            && owner.retain_until_height <= request.policy.deadline
            && matches!(request.claim.resource_reservation,
                NativeBudgetResourcesV1::Storage { retained_bytes, retained_byte_blocks }
                if retained_bytes >= physical.manifest.size()
                    && retained_byte_blocks >= byte_blocks),
        "NATIVE_CELL_SHARD_STORAGE_BINDING",
    )?;
    Ok(NativeBudgetEffectCheckV1 {
        policy: &request.policy,
        claim: &request.claim,
        operation: contract.operation(),
        effect,
        window: Some((owner.retain_from_height, owner.retain_until_height)),
    })
}

impl Node {
    pub fn retain_native_cell_shard(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        provider: &mut CellRs46ShardProviderV1,
        cache: &CellStoreV1,
        request: NativeCellShardRetentionRequestV1,
        deadline: Instant,
    ) -> Result<NativeCellShardEffectReadbackV1> {
        storage_deadline(deadline)?;
        let check = shard_storage_check(provider, &request)?;
        let effect = check.effect;
        budgets.check_effects(self, &[check]).map_err(owner_error)?;
        storage_deadline(deadline)?;
        budgets
            .open_budget(self, request.policy.clone())
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        budgets
            .reserve(self, request.claim.clone())
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        let operation = request.contract.operation();
        let target = provider
            .reserve(&request.contract, operation, deadline)
            .map_err(owner_error)?;
        ensure(!target.retired, "NATIVE_CELL_TARGET_RETIRED")?;
        storage_deadline(deadline)?;
        let owner = request.contract.owner();
        let replay = budgets
            .begin_effect_in_window(
                self,
                request.claim.claim,
                operation,
                effect,
                owner.retain_from_height,
                owner.retain_until_height,
            )
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        let (target, stored) = match replay {
            NativeBudgetReplayV1::New => provider
                .publish(&request.contract, operation, cache, deadline)
                .map_err(owner_error)?,
            NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => provider
                .reconcile_acknowledgement(
                    request.contract.binding(),
                    operation,
                    deadline,
                    &mut || Ok(()),
                )
                .map_err(owner_error)?,
        };
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_TARGET_ACK",
        )?;
        let target_receipt = shard_initial_receipt(effect);
        storage_deadline(deadline)?;
        budgets
            .complete_effect(request.claim.claim, operation, target_receipt)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(NativeCellShardEffectReadbackV1 {
            native: NativeCellEffectReadbackV1 {
                target,
                effect,
                target_receipt,
                replay,
                repair_cpu_observation: None,
            },
            stored,
        })
    }

    pub fn repair_native_cell_shard(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        provider: &mut CellRs46ShardProviderV1,
        cache: &CellStoreV1,
        request: NativeCellShardRepairRequestV1,
        deadline: Instant,
    ) -> Result<NativeCellShardEffectReadbackV1> {
        task_policy(&request.policy, &request.claim)?;
        let cpu_ns = match request.claim.resource_reservation {
            NativeBudgetResourcesV1::Repair { cpu_ns, .. } if cpu_ns > 0 => cpu_ns,
            _ => return Err("NATIVE_CELL_REPAIR_CPU_REQUIRED".into()),
        };
        let mut cpu = RepairCpuOwner::start(cpu_ns, deadline).map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let contract = provider
            .descriptor(&request.binding, request.operation, deadline)
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let owner = contract.owner();
        let placement = &contract.placement().placements[usize::from(owner.slot)];
        let effect = native_cell_shard_repair_subject_v1(
            provider,
            &contract,
            request.repair_operation,
            request.claim.claim,
        );
        ensure(
            request.claim.claim != [0; 32]
                && request.claim.claim != owner.funding_operation
                && request.claim.claim != request.repair_operation
                && request.claim.claim != request.operation
                && request.claim.subject == effect
                && request.claim.beneficiary == placement.repair_owner
                && request.repair_operation != request.operation
                && request.repair_operation != owner.funding_operation
                && request.repair_operation != owner.original_operation
                && request.repair_operation != [0; 32]
                && matches!(request.claim.resource_reservation,
                    NativeBudgetResourcesV1::Repair { download_bytes, attempts, .. }
                    if download_bytes >= contract.manifest().size() && attempts >= 1),
            "NATIVE_CELL_SHARD_REPAIR_BINDING",
        )?;
        cpu.check().map_err(owner_error)?;
        budgets
            .check_effects(
                self,
                &[NativeBudgetEffectCheckV1 {
                    policy: &request.policy,
                    claim: &request.claim,
                    operation: request.repair_operation,
                    effect,
                    window: Some((owner.retain_from_height, owner.retain_until_height)),
                }],
            )
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        budgets
            .open_budget(self, request.policy.clone())
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        budgets
            .reserve(self, request.claim.clone())
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let replay = budgets
            .begin_effect_in_window(
                self,
                request.claim.claim,
                request.repair_operation,
                effect,
                owner.retain_from_height,
                owner.retain_until_height,
            )
            .map_err(owner_error)?;
        cpu.check().map_err(owner_error)?;
        let (target, stored) = match replay {
            NativeBudgetReplayV1::New => provider
                .repair(
                    CellRs46ShardRepairRequestV1 {
                        binding: &request.binding,
                        operation: request.operation,
                        repair_operation: request.repair_operation,
                        cache,
                        deadline,
                    },
                    &mut || cpu.check(),
                )
                .map_err(owner_error)?,
            NativeBudgetReplayV1::Pending | NativeBudgetReplayV1::Done => provider
                .reconcile_repair(
                    &request.binding,
                    request.operation,
                    request.repair_operation,
                    deadline,
                    &mut || cpu.check(),
                )
                .map_err(owner_error)?,
        };
        ensure(
            target.acknowledged && !target.retired,
            "NATIVE_CELL_TARGET_ACK",
        )?;
        let target_receipt = hash(b"trnm.native-cell-shard-repair-readback.v1\0", &[&effect]);
        cpu.check().map_err(owner_error)?;
        budgets
            .complete_effect(
                request.claim.claim,
                request.repair_operation,
                target_receipt,
            )
            .map_err(owner_error)?;
        let repair_cpu_observation = Some(
            cpu.finish(replay == NativeBudgetReplayV1::New)
                .map_err(owner_error)?,
        );
        Ok(NativeCellShardEffectReadbackV1 {
            native: NativeCellEffectReadbackV1 {
                target,
                effect,
                target_receipt,
                replay,
                repair_cpu_observation,
            },
            stored,
        })
    }

    /// Retire only under the current anchor of the original completed native
    /// effect. This does not delete its immutable CSP1 or its debit history.
    pub fn retire_native_cell_shard(
        &mut self,
        budgets: &NativeBudgetStoreV1,
        provider: &mut CellRs46ShardProviderV1,
        binding: &CellRs46ChunkBindingV1,
        operation: Hash,
        deadline: Instant,
    ) -> Result<CellRetentionReadbackV1> {
        storage_deadline(deadline)?;
        let contract = provider
            .descriptor(binding, operation, deadline)
            .map_err(owner_error)?;
        let physical = contract.retention_contract();
        let effect = physical.commitment(provider.store_id());
        storage_deadline(deadline)?;
        let current = budgets
            .reobserve_completed_effect(
                self,
                physical.funding_operation,
                operation,
                effect,
                Some((physical.retain_from_height, physical.retain_until_height)),
                shard_initial_receipt(effect),
            )
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        provider
            .retire(binding, operation, current.height, deadline, &mut || Ok(()))
            .map_err(owner_error)
    }
}
