//! CRP2 execution with global admission and fresh complete target readback.
//! Page metadata grants no settlement, retirement or model execution authority.

use super::*;
use trnm_data_availability::cell::{CellPagedRetainedShardPlanFileV2, CellRetainedShardChunkV1};

#[path = "paged/recovery.rs"]
mod recovery;
pub use recovery::{NativeCellPagedShardRecoveryBudgetV2, NativeCellPagedShardRecoveryReadbackV2};

pub struct NativeCellPagedRetainedShardPlanTargetsV2<'a> {
    pub catalog: &'a mut CellVersionRetentionStoreV3,
    pub plan_file: &'a CellPagedRetainedShardPlanFileV2,
    pub providers: &'a mut [CellRs46ShardProviderV1; 6],
    /// Dedicated writable disposable delivery cache. Verified codewords and
    /// prior Done residue are removed before staging the next chunk. Remaining
    /// cached manifests retain shared chunks, so unrelated owners must use a
    /// separate cache when the caller needs the exact six-row staging bound.
    /// Contents grant no custody, repair funding or execution authority.
    pub cache: &'a CellStoreV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCellRetainedShardPageReadbackV2 {
    pub index: usize,
    pub commitment: Hash,
    pub start_chunk: usize,
    pub chunk_count: usize,
}

/// Sequential observations, not authority or a claim of future availability.
/// No API accepts a caller-constructed value as completion authority.
#[derive(Clone, Debug)]
pub struct NativeCellPagedRetainedShardPlanReadbackV2 {
    pub plan: Hash,
    pub catalog: CellVersionCatalogAnchorV3,
    pub retained: [u8; 64],
    pub observed_at: NativeBudgetAnchorV1,
    pub pages: Vec<NativeCellRetainedShardPageReadbackV2>,
    /// Final-pass observations are Done even on a first successful execution.
    pub slots: Vec<NativeCellRetainedShardSlotReadbackV1>,
    pub verification_usage: CellRs46RepairUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
}

impl Node {
    /// Admit every original claim before effects; reserve both complete passes.
    pub fn retain_native_cell_paged_shard_plan(
        &mut self,
        budgets: &mut NativeBudgetStoreV1,
        targets: NativeCellPagedRetainedShardPlanTargetsV2<'_>,
        request: NativeCellRetainedShardPlanRequestV1,
        verification: &mut NativeCellRetainedShardVerificationBudgetV1,
    ) -> Result<NativeCellPagedRetainedShardPlanReadbackV2> {
        let NativeCellPagedRetainedShardPlanTargetsV2 {
            catalog,
            plan_file,
            providers,
            cache,
        } = targets;
        let deadline = verification.deadline;
        storage_deadline(deadline)?;
        cache
            .check_delivery_cache_until(deadline)
            .map_err(owner_error)?;
        ensure(
            !request.slots.is_empty() && request.slots.len() == plan_file.plan().chunk_count() * 6,
            "NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE",
        )?;
        let source = request.slots[0].policy.source;
        let observed = self.native_funding_observation(source)?.anchor;
        let plan = plan_file
            .read_complete_current(catalog, observed.height, deadline)
            .map_err(owner_error)?;
        let mut identities = BTreeSet::from([plan.operation()]);
        identities.extend(plan.original_identities());
        let mut sources = BTreeSet::new();
        let mut checks = Vec::with_capacity(request.slots.len());
        let mut input_bytes = 0_u64;
        let mut original_bytes = 0_u64;
        let mut covered = 0_usize;
        for page_index in 0..plan.page_count() {
            let page = plan_file
                .read_page(page_index, deadline)
                .map_err(owner_error)?;
            ensure(
                page.index() == page_index && page.start_chunk() == covered,
                "NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE",
            )?;
            for chunk in page.chunks() {
                original_bytes = original_bytes
                    .checked_add(u64::from(chunk.binding().source_bytes()))
                    .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?;
                for (slot, expected) in chunk.slots().iter().enumerate() {
                    storage_deadline(deadline)?;
                    let entry = request
                        .slots
                        .get(covered * 6 + slot)
                        .ok_or("NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE")?;
                    ensure(
                        entry.contract == *expected,
                        "NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE",
                    )?;
                    for identity in [
                        entry.contract.operation(),
                        entry.claim.claim,
                        entry.policy.budget,
                    ] {
                        ensure(
                            identity != [0; 32] && identities.insert(identity),
                            "NATIVE_CELL_PAGED_PLAN_IDENTITY_ALIAS",
                        )?;
                    }
                    ensure(
                        sources.insert(entry.policy.source),
                        "NATIVE_CELL_PAGED_PLAN_TASK_ALIAS",
                    )?;
                    input_bytes = input_bytes
                        .checked_add(expected.manifest().size())
                        .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?;
                    checks.push(shard_storage_check(&providers[slot], entry)?);
                }
                covered += 1;
            }
        }
        ensure(
            covered == plan.chunk_count(),
            "NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE",
        )?;
        let reservation = reserve_verification(verification, covered, input_bytes, original_bytes)?;
        let replays = budgets.check_effects(self, &checks).map_err(owner_error)?;
        for (slot, provider) in providers.iter().enumerate() {
            let contracts: Vec<_> = request
                .slots
                .iter()
                .skip(slot)
                .step_by(6)
                .map(|entry| &entry.contract)
                .collect();
            provider
                .check_reservations(&contracts, deadline)
                .map_err(owner_error)?;
        }
        storage_deadline(deadline)?;
        ensure(
            self.native_funding_observation(source)?.anchor == observed,
            "NATIVE_CELL_PAGED_PLAN_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_current(catalog, observed.height, deadline)
            .map_err(owner_error)?;
        verification.committed = reservation;
        for page_index in 0..plan.page_count() {
            let page = plan_file
                .read_page(page_index, deadline)
                .map_err(owner_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let start = (page.start_chunk() + local_index) * 6;
                if replays[start..start + 6].contains(&NativeBudgetReplayV1::New) {
                    plan_file
                        .stage_chunk_from_catalog(
                            page_index,
                            local_index,
                            catalog,
                            cache,
                            observed.height,
                            deadline,
                        )
                        .map_err(owner_error)?;
                }
                let mut actual = Vec::with_capacity(6);
                for (slot, provider) in providers.iter_mut().enumerate() {
                    actual.push(self.retain_native_cell_shard(
                        budgets,
                        provider,
                        cache,
                        request.slots[start + slot].clone(),
                        deadline,
                    )?);
                }
                verify_codeword(chunk, &actual, verification)?;
                // Clean this exact delivery set, including residue after a
                // prior Done result. Other manifest owners keep shared chunks.
                // No source copy, original intent or funding is replayed.
                for contract in chunk.slots() {
                    cache
                        .discard_manifest_until(contract.manifest(), deadline)
                        .map_err(owner_error)?;
                }
            }
        }
        // Earlier page receipts cannot establish whole-version completion.
        let final_replays = budgets.check_effects(self, &checks).map_err(owner_error)?;
        ensure(
            final_replays
                .iter()
                .all(|replay| *replay == NativeBudgetReplayV1::Done),
            "NATIVE_CELL_PAGED_PLAN_ORIGINAL_INTENT_INCOMPLETE",
        )?;
        let mut pages = Vec::with_capacity(plan.page_count());
        let mut slots = Vec::with_capacity(request.slots.len());
        for page_index in 0..plan.page_count() {
            let page = plan_file
                .read_page(page_index, deadline)
                .map_err(owner_error)?;
            for (local_index, chunk) in page.chunks().iter().enumerate() {
                let start = (page.start_chunk() + local_index) * 6;
                let mut actual = Vec::with_capacity(6);
                for (slot, provider) in providers.iter_mut().enumerate() {
                    let row = self.retain_native_cell_shard(
                        budgets,
                        provider,
                        cache,
                        request.slots[start + slot].clone(),
                        deadline,
                    )?;
                    ensure(
                        row.native.replay == NativeBudgetReplayV1::Done,
                        "NATIVE_CELL_PAGED_PLAN_ORIGINAL_INTENT_INCOMPLETE",
                    )?;
                    actual.push(row);
                }
                verify_codeword(chunk, &actual, verification)?;
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
            pages.push(NativeCellRetainedShardPageReadbackV2 {
                index: page.index(),
                commitment: page.commitment(),
                start_chunk: page.start_chunk(),
                chunk_count: page.chunks().len(),
            });
        }
        storage_deadline(deadline)?;
        let current = self.native_funding_observation(source)?.anchor;
        ensure(
            current == observed,
            "NATIVE_CELL_PAGED_PLAN_CURRENT_ANCHOR_CHANGED",
        )?;
        plan_file
            .read_complete_current(catalog, current.height, deadline)
            .map_err(owner_error)?;
        storage_deadline(deadline)?;
        Ok(NativeCellPagedRetainedShardPlanReadbackV2 {
            plan: plan_file.commitment(),
            catalog: plan.catalog_anchor(),
            retained: plan.retained_commitment(),
            observed_at: current,
            pages,
            slots,
            verification_usage: verification.usage(),
            codec_usage: verification.codec_usage(),
        })
    }
}

fn reserve_verification(
    verification: &NativeCellRetainedShardVerificationBudgetV1,
    chunks: usize,
    input_bytes: u64,
    original_bytes: u64,
) -> Result<CellRs46RepairUsageV1> {
    let attempts = u32::try_from(chunks)
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?;
    let reconstruction_bytes = input_bytes
        .checked_add(original_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?;
    let input_bytes = input_bytes
        .checked_mul(2)
        .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?;
    let used = verification.usage();
    let reservation = CellRs46RepairUsageV1 {
        attempts_committed: used
            .attempts_committed
            .checked_add(attempts)
            .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?,
        input_bytes_committed: used
            .input_bytes_committed
            .checked_add(input_bytes)
            .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?,
        reconstruction_bytes_committed: used
            .reconstruction_bytes_committed
            .checked_add(reconstruction_bytes)
            .ok_or("NATIVE_CELL_PAGED_PLAN_SIZE")?,
        cache_bytes_committed: used.cache_bytes_committed,
    };
    ensure(
        reservation.attempts_committed <= verification.attempts
            && reservation.input_bytes_committed <= verification.input_bytes
            && reservation.reconstruction_bytes_committed <= verification.reconstruction_bytes,
        "NATIVE_CELL_PAGED_PLAN_VERIFICATION_RESERVATION",
    )?;
    Ok(reservation)
}

fn verify_codeword(
    chunk: &CellRetainedShardChunkV1,
    actual: &[NativeCellShardEffectReadbackV1],
    verification: &mut NativeCellRetainedShardVerificationBudgetV1,
) -> Result<()> {
    storage_deadline(verification.deadline)?;
    ensure(actual.len() == 6, "NATIVE_CELL_PAGED_PLAN_EXACT_COVERAGE")?;
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
        "NATIVE_CELL_PAGED_PLAN_COMPLETE_CODEWORD",
    )?;
    storage_deadline(verification.deadline)
}
