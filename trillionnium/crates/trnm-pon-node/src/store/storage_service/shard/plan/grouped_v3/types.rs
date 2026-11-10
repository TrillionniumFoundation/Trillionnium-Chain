//! Typed, canonical parent groups for the explicit V3 child-journal profile.
//!
//! Each parent remains one indivisible original M12 Task claim. Children are
//! V3 logical intents, never individual M12 reservations or payment receipts.
//! These metadata checks grant no dispatch, payment, Positive or FinalUse.

use std::collections::BTreeSet;

use crate::{ensure, Result};
use trnm_data_availability::cell::{CellRs46ShardContractV1, CellRs46ShardProviderV1};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_service_settlement::native_budget::{
    NativeBudgetClaimV1, NativeBudgetPolicyV1, NativeBudgetResourcesV1, NativeFundingSourceV1,
};

use super::journal::ChildBindingV3;

pub const NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3: usize = 16;
const MAX_GROUP_CHUNKS: usize = 128;
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const GROUP_DOMAIN: &[u8] = b"trnm.native-cell-shard-parent-group.v3\0";

#[derive(Clone, Debug)]
pub struct NativeCellShardGroupChildV3 {
    pub contract: CellRs46ShardContractV1,
    pub claim: NativeBudgetClaimV1,
    pub repair_operation: Option<Hash>,
}

#[derive(Clone, Debug)]
pub struct NativeCellShardParentGroupV3 {
    pub slot: u8,
    pub first_chunk: usize,
    pub operation: Hash,
    pub policy: NativeBudgetPolicyV1,
    pub claim: NativeBudgetClaimV1,
    pub children: Vec<NativeCellShardGroupChildV3>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCellShardGroupKindV3 {
    Storage,
    Repair,
}

#[derive(Clone, Debug)]
pub struct NativeCellGroupedShardStorageRequestV3 {
    pub groups: Vec<NativeCellShardParentGroupV3>,
}

/// The bounded V3 recovery profile restores all chunks at one or two explicitly
/// selected original provider slots. Sparse repair remains a separate profile.
#[derive(Clone, Debug)]
pub struct NativeCellGroupedShardRepairRequestV3 {
    pub storage: NativeCellGroupedShardStorageRequestV3,
    pub repair_slots: Vec<u8>,
    pub groups: Vec<NativeCellShardParentGroupV3>,
}

impl NativeCellShardGroupKindV3 {
    fn tag(self) -> u8 {
        match self {
            Self::Storage => 1,
            Self::Repair => 2,
        }
    }
}

/// The complete new-domain descriptor excludes only the self-referential parent
/// claim subject. A subject is metadata; the native owner and durable child
/// journal still perform every admission and actual target readback.
pub fn native_cell_shard_parent_group_subject_v3(
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    group: &NativeCellShardParentGroupV3,
) -> Result<Hash> {
    let bytes = descriptor(plan, kind, group)?;
    Ok(hash(GROUP_DOMAIN, &[&bytes]))
}

pub(super) fn descriptor(
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    group: &NativeCellShardParentGroupV3,
) -> Result<Vec<u8>> {
    ensure(
        plan != [0; 32]
            && group.slot < 6
            && group.first_chunk < MAX_GROUP_CHUNKS
            && (1..=NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3).contains(&group.children.len()),
        "NATIVE_CELL_GROUP_DESCRIPTOR_BOUNDS",
    )?;
    let mut bytes = b"CPG3".to_vec();
    bytes.push(kind.tag());
    bytes.extend_from_slice(&plan);
    bytes.push(group.slot);
    bytes.extend_from_slice(
        &u32::try_from(group.first_chunk)
            .map_err(|_| "NATIVE_CELL_GROUP_DESCRIPTOR_BOUNDS")?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&group.operation);
    bytes.extend_from_slice(&group.policy.budget);
    let NativeFundingSourceV1::Task(source) = group.policy.source else {
        return Err("NATIVE_CELL_GROUP_TASK_SOURCE".into());
    };
    ensure(source != [0; 32], "NATIVE_CELL_GROUP_TASK_SOURCE")?;
    bytes.extend_from_slice(b"TASK");
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&group.policy.monetary_cap.to_be_bytes());
    bytes.extend_from_slice(&group.policy.deadline.to_be_bytes());
    put_resources(&mut bytes, &group.policy.resource_cap)?;
    bytes.extend_from_slice(&group.policy.max_inflight.to_be_bytes());
    put_claim(&mut bytes, &group.claim, false)?;
    bytes.extend_from_slice(&(group.children.len() as u16).to_be_bytes());
    for child in &group.children {
        let wire = child.contract.encode();
        ensure(wire.len() <= 4096, "NATIVE_CELL_GROUP_CONTRACT_SIZE")?;
        bytes.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&wire);
        put_claim(&mut bytes, &child.claim, true)?;
        match child.repair_operation {
            None => bytes.push(0),
            Some(operation) => {
                bytes.push(1);
                bytes.extend_from_slice(&operation);
            }
        }
    }
    ensure(
        bytes.len() <= MAX_DESCRIPTOR_BYTES,
        "NATIVE_CELL_GROUP_DESCRIPTOR_SIZE",
    )?;
    Ok(bytes)
}

fn put_claim(bytes: &mut Vec<u8>, claim: &NativeBudgetClaimV1, subject: bool) -> Result<()> {
    bytes.extend_from_slice(&claim.claim);
    bytes.extend_from_slice(&claim.budget);
    if subject {
        bytes.extend_from_slice(&claim.subject);
    }
    bytes.extend_from_slice(&claim.beneficiary);
    bytes.extend_from_slice(&claim.monetary_reservation.to_be_bytes());
    put_resources(bytes, &claim.resource_reservation)
}

fn put_resources(bytes: &mut Vec<u8>, resources: &NativeBudgetResourcesV1) -> Result<()> {
    match resources {
        NativeBudgetResourcesV1::Storage {
            retained_bytes,
            retained_byte_blocks,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&retained_bytes.to_be_bytes());
            bytes.extend_from_slice(&retained_byte_blocks.to_be_bytes());
        }
        NativeBudgetResourcesV1::Repair {
            cpu_ns,
            download_bytes,
            upload_bytes,
            attempts,
        } => {
            bytes.push(2);
            for value in [cpu_ns, download_bytes, upload_bytes, attempts] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        _ => return Err("NATIVE_CELL_GROUP_RESOURCE_LANE".into()),
    }
    Ok(())
}

pub(super) fn bindings(
    kind: NativeCellShardGroupKindV3,
    group: &NativeCellShardParentGroupV3,
) -> Result<Vec<ChildBindingV3>> {
    ensure(
        group.slot < 6
            && (1..=NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3).contains(&group.children.len()),
        "NATIVE_CELL_GROUP_DESCRIPTOR_BOUNDS",
    )?;
    group
        .children
        .iter()
        .map(|child| {
            let operation = match (kind, child.repair_operation) {
                (NativeCellShardGroupKindV3::Storage, None) => child.contract.operation(),
                (NativeCellShardGroupKindV3::Repair, Some(operation)) => operation,
                _ => return Err("NATIVE_CELL_GROUP_CHILD_KIND".into()),
            };
            let owner = child.contract.owner();
            ensure(
                operation != [0; 32]
                    && child.claim.subject != [0; 32]
                    && owner.retain_from_height < owner.retain_until_height,
                "NATIVE_CELL_GROUP_CHILD_BINDING",
            )?;
            Ok(ChildBindingV3 {
                operation,
                effect: child.claim.subject,
                from: owner.retain_from_height,
                until: owner.retain_until_height,
            })
        })
        .collect()
}

/// Publicly shaped inputs remain untrusted. Require the exact provider-major
/// partition of the complete independently read CRR2/CRG2 contract inventory.
pub(super) fn validate_groups(
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    groups: &[NativeCellShardParentGroupV3],
    selected_slots: &[u8],
    contracts: &[[CellRs46ShardContractV1; 6]],
    providers: &[CellRs46ShardProviderV1; 6],
) -> Result<()> {
    ensure(
        plan != [0; 32]
            && (1..=MAX_GROUP_CHUNKS).contains(&contracts.len())
            && !selected_slots.is_empty()
            && selected_slots.iter().all(|slot| *slot < 6)
            && selected_slots.windows(2).all(|pair| pair[0] < pair[1]),
        "NATIVE_CELL_GROUP_CANONICAL_ROSTER",
    )?;
    match kind {
        NativeCellShardGroupKindV3::Storage => ensure(
            selected_slots == [0, 1, 2, 3, 4, 5],
            "NATIVE_CELL_GROUP_COMPLETE_STORAGE",
        )?,
        NativeCellShardGroupKindV3::Repair => ensure(
            selected_slots.len() <= 2,
            "NATIVE_CELL_GROUP_REPAIR_PROVIDER_BOUND",
        )?,
    }
    let per_provider = contracts
        .len()
        .div_ceil(NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3);
    ensure(
        groups.len() == per_provider * selected_slots.len(),
        "NATIVE_CELL_GROUP_EXACT_COVERAGE",
    )?;
    for (provider_index, slot) in selected_slots.iter().copied().enumerate() {
        for ordinal in 0..per_provider {
            let first = ordinal * NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3;
            let count = (contracts.len() - first).min(NATIVE_CELL_SHARD_PARENT_GROUP_WIDTH_V3);
            let group = &groups[provider_index * per_provider + ordinal];
            ensure(
                group.slot == slot && group.first_chunk == first && group.children.len() == count,
                "NATIVE_CELL_GROUP_EXACT_COVERAGE",
            )?;
            validate_group(
                plan,
                kind,
                group,
                &contracts[first..first + count],
                &providers[usize::from(slot)],
            )?;
        }
    }
    let identities: Vec<_> = groups.iter().map(|group| (kind, group)).collect();
    validate_identity_union(&identities)
}

fn validate_group(
    plan: Hash,
    kind: NativeCellShardGroupKindV3,
    group: &NativeCellShardParentGroupV3,
    contracts: &[[CellRs46ShardContractV1; 6]],
    provider: &CellRs46ShardProviderV1,
) -> Result<()> {
    ensure(
        group.policy.budget == group.claim.budget
            && matches!(group.policy.source, NativeFundingSourceV1::Task(_))
            && group.policy.max_inflight == 1,
        "NATIVE_CELL_GROUP_PARENT_POLICY",
    )?;
    let mut money = 0_u64;
    let mut resources = [0_u64; 4];
    let mut window = None;
    let configuration = provider.configuration();
    for (child, expected) in group.children.iter().zip(contracts) {
        let contract = &child.contract;
        ensure(
            contract == &expected[usize::from(group.slot)],
            "NATIVE_CELL_GROUP_FOREIGN_CHILD",
        )?;
        let decoded = CellRs46ShardContractV1::decode_pinned(
            &contract.encode(),
            contract.binding(),
            contract.operation(),
        )
        .map_err(|error| format!("NATIVE_CELL_GROUP_CHILD_DESCRIPTOR: {error}"))?;
        let owner = contract.owner();
        let placement = &contract.placement().placements[usize::from(group.slot)];
        ensure(
            decoded == *contract
                && owner.slot == group.slot
                && owner.provider_store == provider.store_id()
                && owner.owner_generation == configuration.owner_generation
                && *placement == configuration.placement
                && owner.retain_from_height < owner.retain_until_height
                && owner.retain_until_height <= group.policy.deadline
                && child.claim.budget == group.policy.budget
                && child.claim.monetary_reservation > 0,
            "NATIVE_CELL_GROUP_CHILD_OWNER",
        )?;
        let current_window = (owner.retain_from_height, owner.retain_until_height);
        ensure(
            window.is_none_or(|expected| expected == current_window),
            "NATIVE_CELL_GROUP_COMMON_WINDOW",
        )?;
        window = Some(current_window);
        let wire_bytes = contract.manifest().size();
        let (expected_beneficiary, expected_subject, vector) = match kind {
            NativeCellShardGroupKindV3::Storage => {
                ensure(
                    child.repair_operation.is_none()
                        && child.claim.claim == owner.funding_operation,
                    "NATIVE_CELL_GROUP_STORAGE_IDENTITY",
                )?;
                let blocks = wire_bytes
                    .checked_mul(owner.retain_until_height - owner.retain_from_height)
                    .ok_or("NATIVE_CELL_GROUP_RESOURCE_OVERFLOW")?;
                ensure(
                    child.claim.resource_reservation
                        == NativeBudgetResourcesV1::Storage {
                            retained_bytes: wire_bytes,
                            retained_byte_blocks: blocks,
                        },
                    "NATIVE_CELL_GROUP_STORAGE_RESOURCES",
                )?;
                (
                    placement.responsible_owner,
                    contract
                        .retention_contract()
                        .commitment(provider.store_id()),
                    [wire_bytes, blocks, 0, 0],
                )
            }
            NativeCellShardGroupKindV3::Repair => {
                let operation = child
                    .repair_operation
                    .ok_or("NATIVE_CELL_GROUP_REPAIR_IDENTITY")?;
                ensure(
                    operation != [0; 32]
                        && operation != contract.operation()
                        && operation != owner.original_operation
                        && operation != owner.funding_operation
                        && child.claim.claim != owner.funding_operation,
                    "NATIVE_CELL_GROUP_REPAIR_IDENTITY",
                )?;
                let NativeBudgetResourcesV1::Repair {
                    cpu_ns,
                    download_bytes,
                    upload_bytes,
                    attempts,
                } = &child.claim.resource_reservation
                else {
                    return Err("NATIVE_CELL_GROUP_REPAIR_RESOURCES".into());
                };
                ensure(
                    *cpu_ns > 0
                        && *download_bytes == wire_bytes
                        && *upload_bytes == wire_bytes
                        && *attempts == 1,
                    "NATIVE_CELL_GROUP_REPAIR_RESOURCES",
                )?;
                (
                    placement.repair_owner,
                    crate::native_cell_shard_repair_subject_v1(
                        provider,
                        contract,
                        operation,
                        child.claim.claim,
                    ),
                    [*cpu_ns, *download_bytes, *upload_bytes, *attempts],
                )
            }
        };
        ensure(
            child.claim.beneficiary == expected_beneficiary
                && group.claim.beneficiary == expected_beneficiary
                && child.claim.subject == expected_subject,
            "NATIVE_CELL_GROUP_CHILD_SUBJECT_OR_PAYEE",
        )?;
        money = money
            .checked_add(child.claim.monetary_reservation)
            .ok_or("NATIVE_CELL_GROUP_MONETARY_OVERFLOW")?;
        for (total, value) in resources.iter_mut().zip(vector) {
            *total = total
                .checked_add(value)
                .ok_or("NATIVE_CELL_GROUP_RESOURCE_OVERFLOW")?;
        }
    }
    let aggregate = match kind {
        NativeCellShardGroupKindV3::Storage => NativeBudgetResourcesV1::Storage {
            retained_bytes: resources[0],
            retained_byte_blocks: resources[1],
        },
        NativeCellShardGroupKindV3::Repair => NativeBudgetResourcesV1::Repair {
            cpu_ns: resources[0],
            download_bytes: resources[1],
            upload_bytes: resources[2],
            attempts: resources[3],
        },
    };
    ensure(
        money > 0
            && group.policy.monetary_cap == money
            && group.claim.monetary_reservation == money
            && group.policy.resource_cap == aggregate
            && group.claim.resource_reservation == aggregate
            && group.claim.subject == native_cell_shard_parent_group_subject_v3(plan, kind, group)?,
        "NATIVE_CELL_GROUP_EXACT_PARENT_SUM",
    )
}

/// Check storage and repair together as well as separately. A source/budget is
/// shared only inside its single parent, never across two groups. Referenced
/// original storage operations inside repair descriptors are not new operations.
pub(super) fn validate_identity_union(
    groups: &[(NativeCellShardGroupKindV3, &NativeCellShardParentGroupV3)],
) -> Result<()> {
    ensure(
        (1..=64).contains(&groups.len()),
        "NATIVE_CELL_GROUP_PARENT_COUNT",
    )?;
    let mut identities = BTreeSet::new();
    let mut effects = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for (kind, group) in groups {
        let NativeFundingSourceV1::Task(source) = group.policy.source else {
            return Err("NATIVE_CELL_GROUP_TASK_SOURCE".into());
        };
        ensure(
            source != [0; 32] && sources.insert(group.policy.source),
            "NATIVE_CELL_GROUP_SOURCE_ALIAS",
        )?;
        for identity in [
            source,
            group.operation,
            group.policy.budget,
            group.claim.claim,
        ] {
            ensure(
                identity != [0; 32] && identities.insert(identity),
                "NATIVE_CELL_GROUP_IDENTITY_ALIAS",
            )?;
        }
        ensure(
            group.claim.subject != [0; 32] && effects.insert(group.claim.subject),
            "NATIVE_CELL_GROUP_SUBJECT_ALIAS",
        )?;
        for child in &group.children {
            let operation = match (*kind, child.repair_operation) {
                (NativeCellShardGroupKindV3::Storage, None) => child.contract.operation(),
                (NativeCellShardGroupKindV3::Repair, Some(operation)) => operation,
                _ => return Err("NATIVE_CELL_GROUP_CHILD_KIND".into()),
            };
            for identity in [operation, child.claim.claim] {
                ensure(
                    identity != [0; 32] && identities.insert(identity),
                    "NATIVE_CELL_GROUP_IDENTITY_ALIAS",
                )?;
            }
            ensure(
                child.claim.subject != [0; 32] && effects.insert(child.claim.subject),
                "NATIVE_CELL_GROUP_SUBJECT_ALIAS",
            )?;
        }
    }
    Ok(())
}
