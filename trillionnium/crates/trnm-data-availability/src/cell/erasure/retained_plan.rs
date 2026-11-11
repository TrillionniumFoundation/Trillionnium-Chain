//! CRP1: one immutable, complete local retained-set shard plan.
//!
//! The real TCA3 catalog selects every protected root. Its exact anchor, the
//! complete canonical original manifest/chunk union, and six original CSP1
//! descriptors per chunk are persisted together before provider execution.
//! M12 and the provider arenas remain the only effect/debit authorities. This
//! bounded local plan neither supplies funding nor proves independent domains.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::provider::{
    CellRs46ShardContractV1, CellRs46ShardOwnerV1, CellRs46ShardProviderConfigV1,
    CellRs46ShardProviderV1,
};
use super::{CellRs46ChunkBindingV1, CellRs46CodewordV1, CellRs46PlacementPolicyV1};
use crate::cell::{
    require, CellDigestV1, CellErrorV1, CellManifestV1, CellResultV1, CellStoreV1,
    CellVersionCatalogAnchorV3, CellVersionCommitmentV1, CellVersionRetentionStateV3,
    CellVersionRetentionStoreV3,
};

mod codec;
mod file;
mod paged;
pub use file::CellRetainedShardPlanFileV1;
pub use paged::{
    restore_cell_paged_version_to_cache_controlled_v2, restore_cell_paged_version_to_cache_v2,
    CellPagedRetainedShardPlanFileV2, CellPagedRetainedShardPlanRequestV2,
    CellPagedRetainedShardPlanV2, CellPagedShardRestoreBudgetV2, CellPagedShardRestoreLimitsV2,
    CellPagedShardRestoreReadbackV2, CellPagedShardRestoreRequestV2, CellPagedShardRestoreUsageV2,
    CellRetainedShardPagePinV2, CellRetainedShardPageV2, MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
    MAX_CELL_RETAINED_SHARD_PAGES_V2, MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2,
};

// Initial published CRP1 profile: complete model/environment unions remain
// bounded by 128 chunks, 64 roots and the independent 2 MiB metadata ceiling.
pub const MAX_CELL_RETAINED_SHARD_CHUNKS_V1: usize = 128;
pub const MAX_CELL_RETAINED_SHARD_ROOTS_V1: usize = 64;
pub const MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1: usize = 2 * 1024 * 1024;

/// The funding owner allocates exactly six distinct original claim identities
/// per canonical chunk. No caller-supplied manifest list or subset is accepted.
#[derive(Clone, Debug)]
pub struct CellRetainedShardPlanRequestV1 {
    pub operation: CellDigestV1,
    pub expected_catalog: CellVersionCatalogAnchorV3,
    pub current_height: u64,
    pub required_until_height: u64,
    pub providers: [CellRs46ShardProviderConfigV1; 6],
    pub funding_operations: Vec<[CellDigestV1; 6]>,
    /// A finite original cumulative target-copy cap; never a funded repair task.
    pub maximum_repairs_per_slot: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedShardRootV1 {
    operation: CellDigestV1,
    contract: CellDigestV1,
    version: CellVersionCommitmentV1,
}

impl CellRetainedShardRootV1 {
    pub fn operation(&self) -> CellDigestV1 {
        self.operation
    }
    pub fn contract_commitment(&self) -> CellDigestV1 {
        self.contract
    }
    pub fn version(&self) -> CellVersionCommitmentV1 {
        self.version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedShardChunkV1 {
    manifest: CellDigestV1,
    index: u32,
    slots: [CellRs46ShardContractV1; 6],
}

impl CellRetainedShardChunkV1 {
    pub fn manifest(&self) -> CellDigestV1 {
        self.manifest
    }
    pub fn chunk_index(&self) -> u32 {
        self.index
    }
    pub fn binding(&self) -> &CellRs46ChunkBindingV1 {
        self.slots[0].binding()
    }
    pub fn slots(&self) -> &[CellRs46ShardContractV1; 6] {
        &self.slots
    }
}

/// The public value is immutable and cannot be created from caller summaries.
/// Execution accepts its file owner and rereads that file and the real catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedShardPlanV1 {
    operation: CellDigestV1,
    store: CellDigestV1,
    catalog: CellVersionCatalogAnchorV3,
    retained: CellVersionCommitmentV1,
    from: u64,
    until: u64,
    roots: Vec<CellRetainedShardRootV1>,
    manifests: Vec<CellManifestV1>,
    chunks: Vec<CellRetainedShardChunkV1>,
}

struct SourceView {
    anchor: CellVersionCatalogAnchorV3,
    retained: CellVersionCommitmentV1,
    roots: Vec<CellRetainedShardRootV1>,
    manifests: Vec<CellManifestV1>,
    original_identities: BTreeSet<CellDigestV1>,
    chunks: usize,
}

impl CellRetainedShardPlanV1 {
    pub fn operation(&self) -> CellDigestV1 {
        self.operation
    }
    pub fn catalog_store(&self) -> CellDigestV1 {
        self.store
    }
    pub fn catalog_anchor(&self) -> CellVersionCatalogAnchorV3 {
        self.catalog
    }
    pub fn retained_commitment(&self) -> CellVersionCommitmentV1 {
        self.retained
    }
    pub fn retain_from_height(&self) -> u64 {
        self.from
    }
    pub fn retain_until_height(&self) -> u64 {
        self.until
    }
    pub fn roots(&self) -> &[CellRetainedShardRootV1] {
        &self.roots
    }
    pub fn manifests(&self) -> &[CellManifestV1] {
        &self.manifests
    }
    pub fn chunks(&self) -> &[CellRetainedShardChunkV1] {
        &self.chunks
    }
    pub fn commitment(&self) -> CellDigestV1 {
        commitment(&self.encode())
    }

    /// Rejects extra, missing, Pending, retired or expired roots through the
    /// actual owner inventory. A stale complete-set claim is not rescued by a
    /// caller-supplied list or by one still-readable subset of providers.
    pub fn verify_current_catalog(
        &self,
        catalog: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        self.validate(deadline)?;
        require(
            self.from <= current_height
                && current_height < self.until
                && catalog.store_id() == self.store,
            "retained shard plan current owner/window",
        )?;
        let actual = source_view(catalog, self.from, self.until, deadline)?;
        require(
            actual.anchor == self.catalog
                && actual.retained == self.retained
                && actual.roots == self.roots
                && actual.manifests == self.manifests
                && actual.chunks == self.chunks.len(),
            "retained shard plan complete catalog changed",
        )?;
        require(
            !actual.original_identities.contains(&self.operation),
            "retained shard plan original identity alias",
        )?;
        for slot in self.chunks.iter().flat_map(|chunk| &chunk.slots) {
            require(
                !actual
                    .original_identities
                    .contains(&slot.owner().funding_operation)
                    && !actual.original_identities.contains(&slot.operation()),
                "retained shard plan original identity alias",
            )?;
        }
        check(deadline)
    }

    /// Reload original complete model/environment bytes from the actual TCA3
    /// arena and stage precisely this plan's CRS1 bytes in the bounded CAS.
    /// This prepares sources only. It does not admit or ACK any provider slot.
    pub fn stage_from_catalog(
        &self,
        catalog: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.verify_current_catalog(catalog, current_height, deadline)?;
        for root in &self.roots {
            check(deadline)?;
            catalog.populate_cache(root.operation, cache, deadline)?;
        }
        for chunk in &self.chunks {
            check(deadline)?;
            let manifest = self
                .manifests
                .binary_search_by_key(&chunk.manifest, CellManifestV1::id)
                .map_err(|_| CellErrorV1::Invalid("retained shard plan manifest absent"))?;
            let source = cache
                .chunk_with_deadline(
                    self.manifests[manifest].chunks()[chunk.index as usize].sha256,
                    Some(deadline),
                )?
                .ok_or(CellErrorV1::Unavailable)?;
            let shards = chunk.binding().encode_chunk(&source)?;
            for (contract, shard) in chunk.slots.iter().zip(shards) {
                check(deadline)?;
                CellRs46ShardProviderV1::cache_shard(
                    contract,
                    contract.operation(),
                    &shard.encode(),
                    cache,
                    deadline,
                )?;
            }
        }
        self.verify_current_catalog(catalog, current_height, deadline)
    }

    fn build(
        catalog: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        request: CellRetainedShardPlanRequestV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        require(
            request.operation != [0; 32] && (1..=16).contains(&request.maximum_repairs_per_slot),
            "retained shard plan original identity/repair cap",
        )?;
        let source = source_view(
            catalog,
            request.current_height,
            request.required_until_height,
            deadline,
        )?;
        require(
            source.anchor == request.expected_catalog,
            "retained shard plan catalog anchor",
        )?;
        require(
            request.funding_operations.len() == source.chunks,
            "retained shard plan exact funding coverage",
        )?;
        let mut identities = source.original_identities;
        require(
            identities.insert(request.operation),
            "retained shard plan identity alias",
        )?;
        let mut stores = BTreeSet::new();
        for provider in &request.providers {
            require(
                stores.insert(provider.store_id()?),
                "retained shard plan provider alias",
            )?;
            require(
                provider.maximum_obligations as usize >= source.chunks,
                "retained shard plan provider history capacity",
            )?;
        }
        for chunk in &request.funding_operations {
            for funding in chunk {
                require(
                    *funding != [0; 32] && identities.insert(*funding),
                    "retained shard plan original funding alias",
                )?;
            }
        }
        // Bound the entire union before any complete payload read or RS work.
        let required_capacity = source.manifests.iter().try_fold(0_u64, |total, manifest| {
            manifest.chunks().iter().try_fold(total, |total, chunk| {
                let bytes = super::SHARD_HEADER_BYTES as u64 + u64::from(chunk.size).div_ceil(4);
                total
                    .checked_add(bytes.div_ceil(4096) * 4096)
                    .ok_or(CellErrorV1::Invalid(
                        "retained shard plan capacity overflow",
                    ))
            })
        })?;
        for provider in &request.providers {
            require(
                required_capacity <= provider.capacity_bytes,
                "retained shard plan provider physical capacity",
            )?;
        }
        for root in &source.roots {
            check(deadline)?;
            catalog.populate_cache(root.operation, cache, deadline)?;
        }
        let mut chunks = Vec::with_capacity(source.chunks);
        for manifest in &source.manifests {
            for (index, chunk) in manifest.chunks().iter().enumerate() {
                check(deadline)?;
                let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                    manifest,
                    manifest.id(),
                    manifest.context(),
                    index as u32,
                )?;
                let bytes = cache
                    .chunk_with_deadline(chunk.sha256, Some(deadline))?
                    .ok_or(CellErrorV1::Unavailable)?;
                let codeword = CellRs46CodewordV1::from_verified_chunk(&binding, &bytes)?;
                let placement = CellRs46PlacementPolicyV1 {
                    codeword: codeword.id(),
                    placements: std::array::from_fn(|slot| {
                        request.providers[slot].placement.clone()
                    }),
                };
                let placement_id = placement.id()?;
                let wires = binding.encode_chunk(&bytes)?.map(|shard| shard.encode());
                let mut slots = Vec::with_capacity(6);
                for (slot, wire) in wires.into_iter().enumerate() {
                    check(deadline)?;
                    let provider = &request.providers[slot];
                    let contract = CellRs46ShardContractV1::from_verified_shard(
                        CellRs46ShardOwnerV1 {
                            original_operation: request.operation,
                            provider_store: provider.store_id()?,
                            owner_generation: provider.owner_generation,
                            funding_operation: request.funding_operations[chunks.len()][slot],
                            codeword: codeword.id(),
                            placement: placement_id,
                            slot: slot as u8,
                            context: manifest.context().clone(),
                            retain_from_height: request.current_height,
                            retain_until_height: request.required_until_height,
                            maximum_repair_bytes: (wire.len() as u64)
                                .checked_mul(u64::from(request.maximum_repairs_per_slot))
                                .ok_or(CellErrorV1::Invalid(
                                    "retained shard plan repair overflow",
                                ))?,
                        },
                        &binding,
                        &codeword,
                        &placement,
                        &wire,
                    )?;
                    CellRs46ShardProviderV1::cache_shard(
                        &contract,
                        contract.operation(),
                        &wire,
                        cache,
                        deadline,
                    )?;
                    slots.push(contract);
                }
                chunks.push(CellRetainedShardChunkV1 {
                    manifest: manifest.id(),
                    index: index as u32,
                    slots: slots
                        .try_into()
                        .map_err(|_| CellErrorV1::Invalid("retained shard plan slots"))?,
                });
            }
        }
        let value = Self {
            operation: request.operation,
            store: catalog.store_id(),
            catalog: source.anchor,
            retained: source.retained,
            from: request.current_height,
            until: request.required_until_height,
            roots: source.roots,
            manifests: source.manifests,
            chunks,
        };
        value.verify_current_catalog(catalog, request.current_height, deadline)?;
        require(
            value.encode().len() <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1,
            "retained shard plan metadata capacity",
        )?;
        Ok(value)
    }

    fn validate(&self, deadline: Instant) -> CellResultV1<()> {
        check(deadline)?;
        require(
            self.operation != [0; 32]
                && self.store != [0; 32]
                && self.retained != [0; 64]
                && self.catalog.generation() > 0
                && self.from < self.until
                && self.until <= i64::MAX as u64
                && !self.roots.is_empty()
                && self.roots.len() <= MAX_CELL_RETAINED_SHARD_ROOTS_V1
                && !self.manifests.is_empty()
                && self.manifests.len() <= MAX_CELL_RETAINED_SHARD_CHUNKS_V1
                && !self.chunks.is_empty()
                && self.chunks.len() <= MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
            "retained shard plan bounds",
        )?;
        let mut previous_root = None;
        for root in &self.roots {
            require(
                root.operation != [0; 32]
                    && root.contract != [0; 32]
                    && root.version != [0; 64]
                    && previous_root.is_none_or(|old| old < root.operation),
                "retained shard plan canonical roots",
            )?;
            previous_root = Some(root.operation);
        }
        let mut previous_manifest = None;
        let mut offset = 0;
        let mut identities = BTreeSet::from([self.operation]);
        let mut providers = None;
        for manifest in &self.manifests {
            check(deadline)?;
            let id = manifest.id();
            require(
                previous_manifest.is_none_or(|old| old < id),
                "retained shard plan canonical manifests",
            )?;
            previous_manifest = Some(id);
            for index in 0..manifest.chunks().len() {
                check(deadline)?;
                let chunk = self
                    .chunks
                    .get(offset)
                    .ok_or(CellErrorV1::Invalid("retained shard plan omitted chunk"))?;
                require(
                    chunk.manifest == id && chunk.index as usize == index,
                    "retained shard plan canonical chunk coverage",
                )?;
                let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                    manifest,
                    id,
                    manifest.context(),
                    index as u32,
                )?;
                let mut current_providers = Vec::with_capacity(6);
                for (slot, contract) in chunk.slots.iter().enumerate() {
                    let owner = contract.owner();
                    let actual = CellRs46ShardContractV1::decode_pinned(
                        &contract.encode(),
                        &binding,
                        contract.operation(),
                    )?;
                    require(
                        actual == *contract
                            && owner.original_operation == self.operation
                            && owner.slot as usize == slot
                            && owner.context == *manifest.context()
                            && owner.retain_from_height == self.from
                            && owner.retain_until_height == self.until
                            && identities.insert(owner.funding_operation)
                            && identities.insert(contract.operation())
                            && contract.codeword() == chunk.slots[0].codeword()
                            && contract.placement() == chunk.slots[0].placement(),
                        "retained shard plan original slot binding",
                    )?;
                    let config = CellRs46ShardProviderConfigV1 {
                        placement: contract.placement().placements[slot].clone(),
                        owner_generation: owner.owner_generation,
                        capacity_bytes: 0,
                        maximum_obligations: 0,
                    };
                    require(
                        config.store_id()? == owner.provider_store,
                        "retained shard plan provider store identity",
                    )?;
                    current_providers.push((
                        owner.provider_store,
                        owner.owner_generation,
                        config.placement,
                    ));
                }
                if let Some(expected) = &providers {
                    require(
                        *expected == current_providers,
                        "retained shard plan provider roster changed",
                    )?;
                } else {
                    providers = Some(current_providers);
                }
                offset += 1;
            }
        }
        require(
            offset == self.chunks.len(),
            "retained shard plan extra chunk",
        )?;
        check(deadline)
    }
}

fn source_view(
    catalog: &CellVersionRetentionStoreV3,
    from: u64,
    until: u64,
    deadline: Instant,
) -> CellResultV1<SourceView> {
    source_view_bounded(
        catalog,
        from,
        until,
        MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
        deadline,
    )
}

fn source_view_bounded(
    catalog: &CellVersionRetentionStoreV3,
    from: u64,
    until: u64,
    maximum_chunks: usize,
    deadline: Instant,
) -> CellResultV1<SourceView> {
    check(deadline)?;
    require(
        from < until && until <= i64::MAX as u64,
        "retained shard plan service horizon",
    )?;
    let inventory = catalog.inventory(from, deadline)?;
    require(
        !inventory.protected.is_empty()
            && inventory.protected.len() <= MAX_CELL_RETAINED_SHARD_ROOTS_V1,
        "retained shard plan protected roots capacity",
    )?;
    let set = catalog.service_set(from, until, deadline)?;
    let mut roots = Vec::with_capacity(inventory.protected.len());
    let mut manifests = BTreeMap::new();
    let mut original_identities = BTreeSet::new();
    for duty in inventory.protected {
        check(deadline)?;
        require(
            duty.state == CellVersionRetentionStateV3::Active
                && duty.contract.retain_from_height <= from
                && until <= duty.contract.retain_until_height,
            "retained shard plan complete service unavailable",
        )?;
        let contract = duty.contract;
        roots.push(CellRetainedShardRootV1 {
            operation: contract.operation,
            contract: catalog.contract_commitment(&contract)?,
            version: contract.version.commitment(),
        });
        original_identities.insert(contract.operation);
        original_identities.insert(contract.funding_operation);
        for object in &contract.objects {
            original_identities.insert(object.operation);
            original_identities.insert(object.funding_operation);
        }
        for manifest in contract.version.manifests() {
            if let Some(old) = manifests.insert(manifest.id(), manifest.clone()) {
                require(old == *manifest, "retained shard plan manifest collision")?;
            }
        }
    }
    roots.sort_by_key(|root| root.operation);
    let chunks = manifests.values().try_fold(0_usize, |total, manifest| {
        total
            .checked_add(manifest.chunks().len())
            .ok_or(CellErrorV1::Invalid("retained shard plan chunk overflow"))
    })?;
    require(
        chunks > 0 && chunks <= maximum_chunks,
        "retained shard plan complete chunk capacity",
    )?;
    require(
        catalog.anchor(deadline)? == inventory.anchor,
        "retained shard plan catalog changed during observation",
    )?;
    check(deadline)?;
    Ok(SourceView {
        anchor: inventory.anchor,
        retained: set.commitment(),
        roots,
        manifests: manifests.into_values().collect(),
        original_identities,
        chunks,
    })
}

fn check(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "retained shard plan deadline")
}

fn commitment(wire: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-retained-shard-plan.v1\0");
    hash.update(wire);
    hash.finalize().into()
}
