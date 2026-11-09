//! Complete local execution of the immutable owner-selected CRP1 plan.

use std::collections::BTreeSet;

use super::*;
use trnm_data_availability::cell::{
    CellRetainedShardPlanFileV1, CellRs46RepairBudgetV1, CellRs46RepairUsageV1,
    CellRs46ShardInputV1, CellVersionCatalogAnchorV3, CellVersionRetentionStoreV3,
};
use trnm_service_settlement::native_budget::NativeBudgetAnchorV1;

#[path = "plan/paged.rs"]
mod paged;
#[path = "plan/recovery.rs"]
mod recovery;
pub use paged::{
    NativeCellPagedRetainedShardPlanReadbackV2, NativeCellPagedRetainedShardPlanTargetsV2,
    NativeCellPagedShardRecoveryBudgetV2, NativeCellPagedShardRecoveryReadbackV2,
    NativeCellRetainedShardPageReadbackV2,
};
pub use recovery::{
    NativeCellShardDamageV1, NativeCellShardRecoveryActionV1, NativeCellShardRecoveryBudgetV1,
    NativeCellShardRecoveryCpuV1, NativeCellShardRecoveryFailureV1,
    NativeCellShardRecoveryLimitsV1, NativeCellShardRecoveryReadbackV1,
    NativeCellShardRecoveryRequestV1, NativeCellShardRecoveryUsageV1,
};

#[derive(Clone, Debug)]
pub struct NativeCellRetainedShardPlanRequestV1 {
    /// Exact canonical chunk-major, then slot-major coverage. Each descriptor,
    /// claim, budget and real native task keeps its original identity.
    pub slots: Vec<NativeCellShardRetentionRequestV1>,
}

pub struct NativeCellRetainedShardPlanTargetsV1<'a> {
    pub catalog: &'a CellVersionRetentionStoreV3,
    pub plan_file: &'a CellRetainedShardPlanFileV1,
    pub providers: &'a mut [CellRs46ShardProviderV1; 6],
    pub cache: &'a CellStoreV1,
}

/// Explicit non-clone, cumulative logical read/verification allowance. A whole
/// plan is conservatively committed before its first provider operation and is
/// retained on failure. Input bytes count original CRS1 payload admission, not
/// filesystem/SQL amplification, actual network traffic or measured CPU. This
/// in-process observation budget is not the durable physical/payment ledger.
#[derive(Debug)]
pub struct NativeCellRetainedShardVerificationBudgetV1 {
    deadline: Instant,
    attempts: u32,
    input_bytes: u64,
    reconstruction_bytes: u64,
    committed: CellRs46RepairUsageV1,
    inner: CellRs46RepairBudgetV1,
}

impl NativeCellRetainedShardVerificationBudgetV1 {
    pub fn new(
        deadline: Instant,
        attempts: u32,
        input_bytes: u64,
        reconstruction_bytes: u64,
    ) -> Self {
        Self {
            deadline,
            attempts,
            input_bytes,
            reconstruction_bytes,
            committed: CellRs46RepairUsageV1::default(),
            inner: CellRs46RepairBudgetV1::new(
                deadline,
                attempts,
                input_bytes,
                reconstruction_bytes,
            ),
        }
    }
    pub fn usage(&self) -> CellRs46RepairUsageV1 {
        self.committed
    }
    /// Separately observed codec admissions. A failed target collection can
    /// consume a full plan reservation without reaching the codec at all.
    pub fn codec_usage(&self) -> CellRs46RepairUsageV1 {
        self.inner.usage()
    }
}

#[derive(Clone, Debug)]
pub struct NativeCellRetainedShardSlotReadbackV1 {
    pub operation: Hash,
    pub provider_store: Hash,
    pub shard: Hash,
    pub native: NativeCellEffectReadbackV1,
}

#[derive(Clone, Debug)]
pub struct NativeCellRetainedShardPlanReadbackV1 {
    pub plan: Hash,
    pub catalog: CellVersionCatalogAnchorV3,
    pub retained: [u8; 64],
    pub observed_at: NativeBudgetAnchorV1,
    /// Sequential actual arena readbacks, not simultaneous uptime or durable
    /// payment/future-custody evidence. Every slot is present on success.
    pub slots: Vec<NativeCellRetainedShardSlotReadbackV1>,
    pub verification_usage: CellRs46RepairUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
}

impl Node {
    /// Preflight the complete real catalog, immutable file, provider roster and
    /// every original native claim before the first physical reservation. A
    /// partial failure leaves M12/CSP1 effects intact. Repeating the same plan
    /// reconciles Pending/Done targets and never replays their source writes.
    pub fn retain_native_cell_shard_plan(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellRetainedShardPlanTargetsV1<'_>,
        request: NativeCellRetainedShardPlanRequestV1,
        verification: &mut NativeCellRetainedShardVerificationBudgetV1,
    ) -> Result<NativeCellRetainedShardPlanReadbackV1> {
        let NativeCellRetainedShardPlanTargetsV1 {
            catalog,
            plan_file,
            providers,
            cache,
        } = targets;
        let deadline = verification.deadline;
        storage_deadline(deadline)?;
        let plan = plan_file.read(deadline).map_err(owner_error)?;
        ensure(
            request.slots.len() == plan.chunks().len() * 6 && !request.slots.is_empty(),
            "NATIVE_CELL_SHARD_PLAN_EXACT_COVERAGE",
        )?;
        let input_bytes = plan.chunks().iter().try_fold(0_u64, |total, chunk| {
            chunk.slots().iter().try_fold(total, |total, slot| {
                total
                    .checked_add(slot.manifest().size())
                    .ok_or("NATIVE_CELL_SHARD_PLAN_SIZE")
            })
        })?;
        let reconstruction_bytes = plan.chunks().iter().try_fold(input_bytes, |total, chunk| {
            total
                .checked_add(u64::from(chunk.binding().source_bytes()))
                .ok_or("NATIVE_CELL_SHARD_PLAN_SIZE")
        })?;
        let usage = verification.usage();
        ensure(
            usage
                .attempts_committed
                .checked_add(plan.chunks().len() as u32)
                .is_some_and(|value| value <= verification.attempts)
                && usage
                    .input_bytes_committed
                    .checked_add(input_bytes)
                    .is_some_and(|value| value <= verification.input_bytes)
                && usage
                    .reconstruction_bytes_committed
                    .checked_add(reconstruction_bytes)
                    .is_some_and(|value| value <= verification.reconstruction_bytes),
            "NATIVE_CELL_SHARD_PLAN_VERIFICATION_RESERVATION",
        )?;
        let mut identities = BTreeSet::from([plan.operation()]);
        let mut sources = BTreeSet::new();
        let mut checks = Vec::with_capacity(request.slots.len());
        for (index, (entry, expected)) in request
            .slots
            .iter()
            .zip(plan.chunks().iter().flat_map(|chunk| chunk.slots()))
            .enumerate()
        {
            storage_deadline(deadline)?;
            ensure(
                entry.contract == *expected,
                "NATIVE_CELL_SHARD_PLAN_EXACT_COVERAGE",
            )?;
            for identity in [
                entry.contract.operation(),
                entry.claim.claim,
                entry.policy.budget,
            ] {
                ensure(
                    identity != [0; 32] && identities.insert(identity),
                    "NATIVE_CELL_SHARD_PLAN_IDENTITY_ALIAS",
                )?;
            }
            ensure(
                sources.insert(entry.policy.source),
                "NATIVE_CELL_SHARD_PLAN_TASK_ALIAS",
            )?;
            checks.push(shard_storage_check(&providers[index % 6], entry)?);
        }
        budgets.check_effects(self, &checks).map_err(owner_error)?;
        storage_deadline(deadline)?;
        let source = request.slots[0].policy.source;
        let observed = self.native_funding_observation(source)?.anchor;
        plan_file
            .read_current(catalog, observed.height, deadline)
            .map_err(owner_error)?;
        drop(checks);
        storage_deadline(deadline)?;
        // Commit the entire admitted target-read/verification allowance before
        // the first provider call. Missing/corrupt later slots must not make
        // earlier successful reads free to repeat through the same allowance.
        verification.committed = CellRs46RepairUsageV1 {
            attempts_committed: usage
                .attempts_committed
                .checked_add(plan.chunks().len() as u32)
                .ok_or("NATIVE_CELL_SHARD_PLAN_SIZE")?,
            input_bytes_committed: usage
                .input_bytes_committed
                .checked_add(input_bytes)
                .ok_or("NATIVE_CELL_SHARD_PLAN_SIZE")?,
            reconstruction_bytes_committed: usage
                .reconstruction_bytes_committed
                .checked_add(reconstruction_bytes)
                .ok_or("NATIVE_CELL_SHARD_PLAN_SIZE")?,
            cache_bytes_committed: 0,
        };
        let mut slots = Vec::with_capacity(request.slots.len());
        let mut entries = request.slots.into_iter();
        for chunk in plan.chunks() {
            let mut actual = Vec::with_capacity(6);
            for provider in providers.iter_mut() {
                storage_deadline(deadline)?;
                let entry = entries
                    .next()
                    .ok_or("NATIVE_CELL_SHARD_PLAN_EXACT_COVERAGE")?;
                actual.push(
                    self.retain_native_cell_shard(budgets, provider, cache, entry, deadline)?,
                );
            }
            // Keep only this one bounded codeword's payloads resident. Require
            // all six actual bytes to belong to the original complete codeword,
            // including reconstruction to the original TCM1 chunk hash.
            let wires: Vec<_> = actual
                .iter()
                .map(|row| row.stored.shard().encode())
                .collect();
            let inputs: Vec<_> = wires
                .iter()
                .enumerate()
                .map(|(slot, wire)| CellRs46ShardInputV1 {
                    index: slot as u8,
                    wire,
                })
                .collect();
            let original = &chunk.slots()[0];
            storage_deadline(deadline)?;
            let reconstructed = original
                .codeword()
                .repair_chunk(
                    chunk.binding(),
                    original.codeword().id(),
                    &inputs,
                    &mut verification.inner,
                )
                .map_err(owner_error)?;
            ensure(
                reconstructed.verified_slots().len() == 6
                    && reconstructed.rejected_slots().is_empty()
                    && reconstructed.missing_slots().is_empty(),
                "NATIVE_CELL_SHARD_PLAN_COMPLETE_CODEWORD",
            )?;
            storage_deadline(deadline)?;
            slots.extend(
                actual
                    .into_iter()
                    .map(|row| NativeCellRetainedShardSlotReadbackV1 {
                        operation: row.stored.operation(),
                        provider_store: row.stored.provider_store(),
                        shard: row.stored.shard().id(),
                        native: row.native,
                    }),
            );
        }
        storage_deadline(deadline)?;
        let current = self.native_funding_observation(source)?.anchor;
        ensure(
            current == observed,
            "NATIVE_CELL_SHARD_PLAN_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_current(catalog, current.height, deadline)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(NativeCellRetainedShardPlanReadbackV1 {
            plan: plan_file.commitment(),
            catalog: plan.catalog_anchor(),
            retained: plan.retained_commitment(),
            observed_at: current,
            slots,
            verification_usage: verification.usage(),
            codec_usage: verification.codec_usage(),
        })
    }
}
