//! V3 parent claims require independent durable child history and full readback.
use super::*;
use std::{collections::BTreeMap, time::Instant};
use trnm_data_availability::cell::{
    CellErrorV1, CellPagedRetainedShardPlanFileV2, CellRs46RepairBudgetV1, CellRs46RepairUsageV1,
    CellRs46ShardContractV1, CellRs46ShardInputV1, CellRs46ShardProviderV1, CellRs46StoredShardV1,
    CellVersionRetentionStoreV3,
};
use trnm_service_settlement::native_budget::{NativeBudgetAnchorV1, NativeBudgetEffectCheckV1};
mod engine;
mod journal;
mod recovery;
mod types;
use journal::ChildStateV3;
pub use journal::{NativeCellShardGroupJournalConfigV3, NativeCellShardGroupJournalV3};
pub use recovery::{
    NativeCellGroupedChildCpuV3, NativeCellGroupedShardRecoveryBudgetV3,
    NativeCellGroupedShardRecoveryFailureV3, NativeCellGroupedShardRecoveryReadbackV3,
};
pub use types::{
    native_cell_shard_parent_group_subject_v3, NativeCellGroupedShardRepairRequestV3,
    NativeCellGroupedShardStorageRequestV3, NativeCellShardGroupChildV3,
    NativeCellShardGroupKindV3, NativeCellShardParentGroupV3,
    NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3,
};
const MAX_GROUPED_CHUNKS_V3: usize = 128;
#[derive(Clone, Debug)]
pub struct NativeCellShardParentGroupReadbackV3 {
    pub operation: Hash,
    pub claim: Hash,
    pub receipt: Hash,
    pub replay: NativeBudgetReplayV1,
}
#[derive(Clone, Debug)]
pub struct NativeCellGroupedShardPlanReadbackV3 {
    pub plan: Hash,
    pub observed_at: NativeBudgetAnchorV1,
    pub parents: Vec<NativeCellShardParentGroupReadbackV3>,
    pub children: usize,
    pub verification_usage: CellRs46RepairUsageV1,
    pub codec_usage: CellRs46RepairUsageV1,
}
fn load_contracts(
    file: &CellPagedRetainedShardPlanFileV2,
    catalog: &mut CellVersionRetentionStoreV3,
    height: u64,
    deadline: Instant,
) -> Result<Vec<[CellRs46ShardContractV1; 6]>> {
    storage_deadline(deadline)?;
    let plan = file
        .read_complete_current(catalog, height, deadline)
        .map_err(owner_error)?;
    ensure(
        (1..=MAX_GROUPED_CHUNKS_V3).contains(&plan.chunk_count()) && plan.manifests().len() <= 128,
        "NATIVE_CELL_GROUPED_PROFILE_BOUNDS",
    )?;
    let mut contracts = Vec::with_capacity(plan.chunk_count());
    for index in 0..plan.page_count() {
        let page = file.read_page(index, deadline).map_err(owner_error)?;
        ensure(
            page.start_chunk() == contracts.len(),
            "NATIVE_CELL_GROUPED_COVERAGE",
        )?;
        contracts.extend(page.chunks().iter().map(|chunk| chunk.slots().clone()));
    }
    ensure(
        contracts.len() == plan.chunk_count(),
        "NATIVE_CELL_GROUPED_COVERAGE",
    )?;
    file.read_complete_current(catalog, height, deadline)
        .map_err(owner_error)?;
    storage_deadline(deadline)?;
    Ok(contracts)
}
// Slot zero is the canonical provider epoch. The complete plan pin additionally
// commits every other provider's independently retained generation.
fn journal_context(node: &Node, plan: Hash, epoch: u64) -> NativeCellShardGroupJournalConfigV3 {
    NativeCellShardGroupJournalConfigV3 {
        network: node.settings().network(),
        parameters: node.settings().parameters(),
        genesis: node.settings().genesis(),
        plan,
        owner_generation: epoch,
    }
}
fn logical_operation(
    kind: NativeCellShardGroupKindV3,
    child: &NativeCellShardGroupChildV3,
) -> Result<Hash> {
    match kind {
        NativeCellShardGroupKindV3::Storage => Ok(child.contract.operation()),
        NativeCellShardGroupKindV3::Repair => child
            .repair_operation
            .ok_or_else(|| "NATIVE_CELL_GROUP_REPAIR_OPERATION".into()),
    }
}
fn original_bytes(contracts: &[[CellRs46ShardContractV1; 6]]) -> Result<(u64, u64)> {
    let mut source = 0_u64;
    let mut wire = 0_u64;
    for chunk in contracts {
        source = source
            .checked_add(u64::from(chunk[0].binding().source_bytes()))
            .ok_or("NATIVE_CELL_GROUPED_SIZE")?;
        for slot in chunk {
            wire = wire
                .checked_add(slot.manifest().size())
                .ok_or("NATIVE_CELL_GROUPED_SIZE")?;
        }
    }
    Ok((source, wire))
}
fn observe_original(
    provider: &mut CellRs46ShardProviderV1,
    contract: &CellRs46ShardContractV1,
    deadline: Instant,
    checkpoint: &mut impl FnMut() -> trnm_data_availability::cell::CellResultV1<()>,
) -> Result<CellRs46StoredShardV1> {
    let (target, stored) = provider
        .reconcile_acknowledgement(
            contract.binding(),
            contract.operation(),
            deadline,
            checkpoint,
        )
        .map_err(owner_error)?;
    ensure(
        target.acknowledged && !target.retired,
        "NATIVE_CELL_GROUPED_TARGET_ACK",
    )?;
    Ok(stored)
}
fn verify_actual_codeword(
    contracts: &[CellRs46ShardContractV1; 6],
    actual: &[CellRs46StoredShardV1],
    codec: &mut CellRs46RepairBudgetV1,
) -> Result<()> {
    ensure(actual.len() == 6, "NATIVE_CELL_GROUPED_COMPLETE_CODEWORD")?;
    let wires: Vec<_> = actual.iter().map(|s| s.shard().encode()).collect();
    let inputs: Vec<_> = wires
        .iter()
        .enumerate()
        .map(|(index, wire)| CellRs46ShardInputV1 {
            index: index as u8,
            wire,
        })
        .collect();
    let original = &contracts[0];
    let recovered = original
        .codeword()
        .repair_chunk(original.binding(), original.codeword().id(), &inputs, codec)
        .map_err(owner_error)?;
    ensure(
        recovered.verified_slots().len() == 6
            && recovered.rejected_slots().is_empty()
            && recovered.missing_slots().is_empty(),
        "NATIVE_CELL_GROUPED_COMPLETE_CODEWORD",
    )
}
