//! Closed development research request builder for the V3 parent-group owner.
//! This constructs metadata only. The original native funding owner, complete
//! grouped preflight and durable child journal still authorize every effect.

use super::*;
use std::time::Instant;
use trnm_pon_node::{
    development_public, native_cell_shard_parent_group_subject_v3,
    native_cell_shard_repair_subject_v1, NativeCellGroupedShardRepairRequestV3,
    NativeCellGroupedShardStorageRequestV3, NativeCellShardGroupChildV3,
    NativeCellShardGroupKindV3, NativeCellShardParentGroupV3,
};

const WIDTH: usize = 16;
const CHILD_MONEY: u64 = 100;
const CHILD_REPAIR_CPU_NS: u64 = 5_000_000_000;

fn require(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}

fn check_deadline(deadline: Instant) -> Result<()> {
    require(
        Instant::now() < deadline,
        "original grouped research request deadline",
    )
}

fn dimensions(member_count: usize, chunks: usize) -> Result<(usize, usize)> {
    require(
        (1..=128).contains(&member_count) && (1..=128).contains(&chunks),
        "bounded grouped research manifest and original chunk roster",
    )?;
    let groups = chunks.div_ceil(WIDTH);
    let sources = member_count
        .checked_add(1)
        .and_then(|count| {
            groups
                .checked_mul(8)
                .and_then(|extra| count.checked_add(extra))
        })
        .ok_or("grouped research source-count overflow")?;
    require(sources <= 256, "original native pending-task admission")?;
    Ok((groups, sources))
}

pub(super) fn funding_grants(member_count: usize, chunks: usize) -> Result<Vec<(Hash, u64)>> {
    let (groups, count) = dimensions(member_count, chunks)?;
    let owner = development_public(1)?;
    let mut grants = vec![(owner, CHILD_MONEY); member_count + 1];
    for slot in 0_u64..6 {
        for ordinal in 0..groups {
            let first = ordinal * WIDTH;
            let children = (chunks - first).min(WIDTH);
            grants.push((
                development_public(slot + 1)?,
                CHILD_MONEY
                    .checked_mul(children as u64)
                    .ok_or("grouped research monetary overflow")?,
            ));
        }
    }
    for slot in [4_u64, 5] {
        for ordinal in 0..groups {
            let first = ordinal * WIDTH;
            let children = (chunks - first).min(WIDTH);
            grants.push((
                development_public(slot + 1)?,
                CHILD_MONEY
                    .checked_mul(children as u64)
                    .ok_or("grouped research monetary overflow")?,
            ));
        }
    }
    require(
        grants.len() == count,
        "complete grouped research funding roster",
    )?;
    Ok(grants)
}

fn contracts(
    file: &CellPagedRetainedShardPlanFileV2,
    member_count: usize,
    deadline: Instant,
) -> Result<Vec<[CellRs46ShardContractV1; 6]>> {
    check_deadline(deadline)?;
    let plan = file.read(deadline)?;
    let chunks = plan.chunk_count();
    dimensions(member_count, chunks)?;
    require(
        plan.manifests().len() == member_count && plan.commitment() == file.commitment(),
        "same complete grouped research catalog inventory",
    )?;
    let mut result = Vec::with_capacity(chunks);
    for index in 0..plan.page_count() {
        check_deadline(deadline)?;
        let page = file.read_page(index, deadline)?;
        require(
            page.index() == index && page.start_chunk() == result.len(),
            "canonical grouped research page coverage",
        )?;
        for chunk in page.chunks() {
            result.push(std::array::from_fn(|slot| chunk.slots()[slot].clone()));
        }
    }
    require(
        result.len() == chunks,
        "complete grouped research original chunk coverage",
    )?;
    check_deadline(deadline)?;
    Ok(result)
}

fn source_at(sources: &[NativeFundingSourceV1], offset: usize) -> Result<NativeFundingSourceV1> {
    let source = *sources
        .get(offset)
        .ok_or("complete grouped research native source coverage")?;
    require(
        matches!(source, NativeFundingSourceV1::Task(task) if task != [0; 32]),
        "actual grouped research Task source required",
    )?;
    Ok(source)
}

fn sum_resources(
    kind: NativeCellShardGroupKindV3,
    children: &[NativeCellShardGroupChildV3],
) -> Result<(u64, NativeBudgetResourcesV1)> {
    let mut money = 0_u64;
    let mut total = [0_u64; 4];
    for child in children {
        money = money
            .checked_add(child.claim.monetary_reservation)
            .ok_or("grouped research monetary overflow")?;
        let values = match (kind, &child.claim.resource_reservation) {
            (
                NativeCellShardGroupKindV3::Storage,
                NativeBudgetResourcesV1::Storage {
                    retained_bytes,
                    retained_byte_blocks,
                },
            ) => [*retained_bytes, *retained_byte_blocks, 0, 0],
            (
                NativeCellShardGroupKindV3::Repair,
                NativeBudgetResourcesV1::Repair {
                    cpu_ns,
                    download_bytes,
                    upload_bytes,
                    attempts,
                },
            ) => [*cpu_ns, *download_bytes, *upload_bytes, *attempts],
            _ => return Err("same grouped research resource lane".into()),
        };
        for (sum, value) in total.iter_mut().zip(values) {
            *sum = sum
                .checked_add(value)
                .ok_or("grouped research resource overflow")?;
        }
    }
    let resources = match kind {
        NativeCellShardGroupKindV3::Storage => NativeBudgetResourcesV1::Storage {
            retained_bytes: total[0],
            retained_byte_blocks: total[1],
        },
        NativeCellShardGroupKindV3::Repair => NativeBudgetResourcesV1::Repair {
            cpu_ns: total[0],
            download_bytes: total[1],
            upload_bytes: total[2],
            attempts: total[3],
        },
    };
    Ok((money, resources))
}

struct ParentSpec {
    operation: Hash,
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    slot: u8,
    first_chunk: usize,
    index: usize,
    source: NativeFundingSourceV1,
    budget: Hash,
    beneficiary: Hash,
    children: Vec<NativeCellShardGroupChildV3>,
}

fn parent(spec: ParentSpec) -> Result<NativeCellShardParentGroupV3> {
    let ParentSpec {
        operation,
        plan,
        kind,
        slot,
        first_chunk,
        index,
        source,
        budget,
        beneficiary,
        children,
    } = spec;
    let (money, resources) = sum_resources(kind, &children)?;
    let (operation_label, claim_label) = match kind {
        NativeCellShardGroupKindV3::Storage => (
            b"grouped-storage-parent-operation-v3".as_slice(),
            b"grouped-storage-parent-claim-v3".as_slice(),
        ),
        NativeCellShardGroupKindV3::Repair => (
            b"grouped-repair-parent-operation-v3".as_slice(),
            b"grouped-repair-parent-claim-v3".as_slice(),
        ),
    };
    let mut group = NativeCellShardParentGroupV3 {
        slot,
        first_chunk,
        operation: identity(operation, operation_label, index),
        policy: NativeBudgetPolicyV1 {
            budget,
            source,
            monetary_cap: money,
            deadline: super::funding::RETAIN_UNTIL,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: identity(operation, claim_label, index),
            budget,
            subject: [0; 32],
            beneficiary,
            monetary_reservation: money,
            resource_reservation: resources,
        },
        children,
    };
    group.claim.subject = native_cell_shard_parent_group_subject_v3(plan, kind, &group)?;
    Ok(group)
}

pub(super) fn storage(
    operation: Hash,
    file: &CellPagedRetainedShardPlanFileV2,
    sources: &[NativeFundingSourceV1],
    member_count: usize,
    deadline: Instant,
) -> Result<NativeCellGroupedShardStorageRequestV3> {
    let contracts = contracts(file, member_count, deadline)?;
    let (per_provider, expected_sources) = dimensions(member_count, contracts.len())?;
    require(
        sources.len() == expected_sources,
        "complete grouped research native source coverage",
    )?;
    let mut groups = Vec::with_capacity(6 * per_provider);
    for slot in 0..6 {
        for ordinal in 0..per_provider {
            check_deadline(deadline)?;
            let first = ordinal * WIDTH;
            let count = (contracts.len() - first).min(WIDTH);
            let index = groups.len();
            let budget = identity(operation, b"grouped-storage-budget-v3", index);
            let beneficiary = development_public(slot as u64 + 1)?;
            let mut children = Vec::with_capacity(count);
            for entries in &contracts[first..first + count] {
                let contract = entries[slot].clone();
                let owner = contract.owner();
                require(
                    contract.placement().placements[slot].responsible_owner == beneficiary,
                    "fixed grouped research storage provider roster",
                )?;
                let resources = storage_resources(
                    contract.manifest().size(),
                    owner.retain_from_height,
                    owner.retain_until_height,
                )?;
                let claim = NativeBudgetClaimV1 {
                    claim: owner.funding_operation,
                    budget,
                    subject: contract
                        .retention_contract()
                        .commitment(owner.provider_store),
                    beneficiary,
                    monetary_reservation: CHILD_MONEY,
                    resource_reservation: resources,
                };
                children.push(NativeCellShardGroupChildV3 {
                    contract,
                    claim,
                    repair_operation: None,
                });
            }
            groups.push(parent(ParentSpec {
                operation,
                plan: file.commitment(),
                kind: NativeCellShardGroupKindV3::Storage,
                slot: slot as u8,
                first_chunk: first,
                index,
                source: source_at(sources, member_count + 1 + index)?,
                budget,
                beneficiary,
                children,
            })?);
        }
    }
    check_deadline(deadline)?;
    Ok(NativeCellGroupedShardStorageRequestV3 { groups })
}

pub(super) fn repair(
    operation: Hash,
    file: &CellPagedRetainedShardPlanFileV2,
    storage: NativeCellGroupedShardStorageRequestV3,
    sources: &[NativeFundingSourceV1],
    member_count: usize,
    providers: &[CellRs46ShardProviderV1; 6],
    deadline: Instant,
) -> Result<NativeCellGroupedShardRepairRequestV3> {
    let contracts = contracts(file, member_count, deadline)?;
    let (per_provider, expected_sources) = dimensions(member_count, contracts.len())?;
    require(
        sources.len() == expected_sources && storage.groups.len() == 6 * per_provider,
        "complete grouped research native storage and source coverage",
    )?;
    let source_start = member_count + 1 + storage.groups.len();
    let mut groups = Vec::with_capacity(2 * per_provider);
    for slot in [4, 5] {
        for ordinal in 0..per_provider {
            check_deadline(deadline)?;
            let first = ordinal * WIDTH;
            let count = (contracts.len() - first).min(WIDTH);
            let group_index = groups.len();
            let budget = identity(operation, b"grouped-repair-budget-v3", group_index);
            let beneficiary = providers[slot].configuration().placement.repair_owner;
            require(
                beneficiary == development_public(slot as u64 + 1)?,
                "fixed grouped research repair provider roster",
            )?;
            let mut children = Vec::with_capacity(count);
            for (local, entries) in contracts[first..first + count].iter().enumerate() {
                let contract = entries[slot].clone();
                let index = (first + local) * 6 + slot;
                let repair_operation = identity(operation, b"grouped-repair-operation-v3", index);
                let claim_id = identity(operation, b"grouped-repair-claim-v3", index);
                let resources = NativeBudgetResourcesV1::Repair {
                    cpu_ns: CHILD_REPAIR_CPU_NS,
                    download_bytes: contract.manifest().size(),
                    upload_bytes: contract.manifest().size(),
                    attempts: 1,
                };
                let claim = NativeBudgetClaimV1 {
                    claim: claim_id,
                    budget,
                    subject: native_cell_shard_repair_subject_v1(
                        &providers[slot],
                        &contract,
                        repair_operation,
                        claim_id,
                    ),
                    beneficiary,
                    monetary_reservation: CHILD_MONEY,
                    resource_reservation: resources,
                };
                children.push(NativeCellShardGroupChildV3 {
                    contract,
                    claim,
                    repair_operation: Some(repair_operation),
                });
            }
            groups.push(parent(ParentSpec {
                operation,
                plan: file.commitment(),
                kind: NativeCellShardGroupKindV3::Repair,
                slot: slot as u8,
                first_chunk: first,
                index: group_index,
                source: source_at(sources, source_start + group_index)?,
                budget,
                beneficiary,
                children,
            })?);
        }
    }
    check_deadline(deadline)?;
    Ok(NativeCellGroupedShardRepairRequestV3 {
        storage,
        repair_slots: vec![4, 5],
        groups,
    })
}
