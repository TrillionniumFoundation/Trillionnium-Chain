//! CRR2/CRG2: one complete catalog snapshot with bounded shard-plan pages.
//!
//! The root binds every original version, manifest, funding identity and page.
//! Pages divide the canonical union, never the version or its responsibility.
//! M12 and CSP1 remain the only durable effect/funding owners. Coverage is read
//! from those original targets; no page receipt or mutable completion flag here
//! can stand in for complete current readback.

use super::*;

mod codec;
mod file;
pub use file::CellPagedRetainedShardPlanFileV2;

/// The existing TCR1/CSP1 history limit remains a whole-plan admission limit.
pub const MAX_CELL_PAGED_RETAINED_CHUNKS_V2: usize = 4096;
pub const MAX_CELL_RETAINED_SHARD_PAGES_V2: usize = 256;
pub const MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2: usize = 2 * 1024 * 1024;
const MAX_ORIGINAL_IDENTITIES: usize =
    2 * MAX_CELL_PAGED_RETAINED_CHUNKS_V2 + 2 * MAX_CELL_RETAINED_SHARD_ROOTS_V1;

#[derive(Clone, Debug)]
pub struct CellPagedRetainedShardPlanRequestV2 {
    pub operation: CellDigestV1,
    pub expected_catalog: CellVersionCatalogAnchorV3,
    pub current_height: u64,
    pub required_until_height: u64,
    pub providers: [CellRs46ShardProviderConfigV1; 6],
    /// Exactly six original funding identities per canonical union chunk.
    pub funding_operations: Vec<[CellDigestV1; 6]>,
    pub maximum_repairs_per_slot: u32,
    /// Between one and 128; the resulting page count is separately bounded.
    pub chunks_per_page: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedShardPagePinV2 {
    index: u32,
    start: u32,
    chunks: u16,
    commitment: CellDigestV1,
}

impl CellRetainedShardPagePinV2 {
    pub fn index(&self) -> usize {
        self.index as usize
    }
    pub fn start_chunk(&self) -> usize {
        self.start as usize
    }
    pub fn chunk_count(&self) -> usize {
        usize::from(self.chunks)
    }
    pub fn commitment(&self) -> CellDigestV1 {
        self.commitment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPagedRetainedShardPlanV2 {
    operation: CellDigestV1,
    store: CellDigestV1,
    catalog: CellVersionCatalogAnchorV3,
    retained: CellVersionCommitmentV1,
    from: u64,
    until: u64,
    roots: Vec<CellRetainedShardRootV1>,
    manifests: Vec<CellManifestV1>,
    original_identities: BTreeSet<CellDigestV1>,
    providers: [CellRs46ShardProviderConfigV1; 6],
    funding: Vec<[CellDigestV1; 6]>,
    maximum_repairs_per_slot: u32,
    chunks_per_page: u16,
    pages: Vec<CellRetainedShardPagePinV2>,
}

/// A bounded page is meaningful only with its independently pinned complete
/// root. It is deliberately not a CRP1 complete-catalog claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedShardPageV2 {
    scope: CellDigestV1,
    index: u32,
    start: u32,
    chunks: Vec<CellRetainedShardChunkV1>,
}

impl CellRetainedShardPageV2 {
    pub fn index(&self) -> usize {
        self.index as usize
    }
    pub fn start_chunk(&self) -> usize {
        self.start as usize
    }
    pub fn chunks(&self) -> &[CellRetainedShardChunkV1] {
        &self.chunks
    }
    pub fn commitment(&self) -> CellDigestV1 {
        hash(b"trnm.cell-retained-shard-page.v2\0", &self.encode())
    }

    fn validate_for(
        &self,
        root: &CellPagedRetainedShardPlanV2,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        let expected = root
            .pages
            .get(self.index())
            .ok_or(CellErrorV1::Invalid("paged shard page index"))?;
        require(
            self.scope == root.scope()
                && self.start == expected.start
                && self.chunks.len() == expected.chunk_count()
                && !self.chunks.is_empty()
                && self.chunks.len() <= MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
            "paged shard exact page coverage",
        )?;
        let mut identities = root.reserved_identities()?;
        for (local, chunk) in self.chunks.iter().enumerate() {
            check(deadline)?;
            let global = self.start_chunk() + local;
            let (manifest, index) = root.chunk_at(global)?;
            let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                manifest,
                manifest.id(),
                manifest.context(),
                index,
            )?;
            require(
                chunk.manifest == manifest.id() && chunk.index == index,
                "paged shard canonical chunk coverage",
            )?;
            for (slot, contract) in chunk.slots.iter().enumerate() {
                check(deadline)?;
                let owner = contract.owner();
                let actual = CellRs46ShardContractV1::decode_pinned(
                    &contract.encode(),
                    &binding,
                    contract.operation(),
                )?;
                let expected_repair = contract
                    .manifest()
                    .size()
                    .checked_mul(u64::from(root.maximum_repairs_per_slot))
                    .ok_or(CellErrorV1::Invalid("paged shard repair overflow"))?;
                let provider = &root.providers[slot];
                require(
                    actual == *contract
                        && owner.original_operation == root.operation
                        && owner.provider_store == provider.store_id()?
                        && owner.owner_generation == provider.owner_generation
                        && owner.funding_operation == root.funding[global][slot]
                        && owner.slot as usize == slot
                        && owner.context == *manifest.context()
                        && owner.retain_from_height == root.from
                        && owner.retain_until_height == root.until
                        && owner.maximum_repair_bytes == expected_repair
                        && contract.placement().placements[slot] == provider.placement
                        && contract.codeword() == chunk.slots[0].codeword()
                        && contract.placement() == chunk.slots[0].placement()
                        && identities.insert(contract.operation()),
                    "paged shard original slot binding",
                )?;
            }
        }
        require(
            self.encode().len() <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1,
            "paged shard page metadata capacity",
        )?;
        check(deadline)
    }
}

impl CellPagedRetainedShardPlanV2 {
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
    pub fn pages(&self) -> &[CellRetainedShardPagePinV2] {
        &self.pages
    }
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
    pub fn chunk_count(&self) -> usize {
        self.funding.len()
    }
    pub fn commitment(&self) -> CellDigestV1 {
        hash(b"trnm.cell-paged-retained-shard-root.v2\0", &self.encode())
    }

    fn scope(&self) -> CellDigestV1 {
        // Page hashes are excluded to avoid a circular hash dependency. The
        // independent final root commits these same fields plus every page hash.
        hash(
            b"trnm.cell-paged-retained-shard-scope.v2\0",
            &self.encode_common(),
        )
    }

    pub fn verify_current_catalog(
        &self,
        catalog: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.validate(true, deadline)?;
        require(
            catalog.store_id() == self.store
                && self.from <= current_height
                && current_height < self.until,
            "paged shard current owner/window",
        )?;
        let actual = source_view_bounded(
            catalog,
            self.from,
            self.until,
            MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
            deadline,
        )?;
        require(
            actual.anchor == self.catalog
                && actual.retained == self.retained
                && actual.roots == self.roots
                && actual.manifests == self.manifests
                && actual.original_identities == self.original_identities
                && actual.chunks == self.chunk_count(),
            "paged shard complete catalog changed",
        )?;
        check(deadline)
    }

    fn prepare(
        catalog: &CellVersionRetentionStoreV3,
        request: CellPagedRetainedShardPlanRequestV2,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        require(
            (1..=MAX_CELL_RETAINED_SHARD_CHUNKS_V1).contains(&usize::from(request.chunks_per_page))
                && request.funding_operations.len() <= MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
            "paged shard request bounds",
        )?;
        let source = source_view_bounded(
            catalog,
            request.current_height,
            request.required_until_height,
            MAX_CELL_PAGED_RETAINED_CHUNKS_V2,
            deadline,
        )?;
        require(
            source.anchor == request.expected_catalog,
            "paged shard catalog anchor",
        )?;
        require(
            request.funding_operations.len() == source.chunks,
            "paged shard exact funding coverage",
        )?;
        let width = usize::from(request.chunks_per_page);
        let count = source.chunks.div_ceil(width);
        require(
            count <= MAX_CELL_RETAINED_SHARD_PAGES_V2,
            "paged shard page count",
        )?;
        let pages = (0..count)
            .map(|index| CellRetainedShardPagePinV2 {
                index: index as u32,
                start: (index * width) as u32,
                chunks: (source.chunks - index * width).min(width) as u16,
                commitment: [0; 32],
            })
            .collect();
        let value = Self {
            operation: request.operation,
            store: catalog.store_id(),
            catalog: source.anchor,
            retained: source.retained,
            from: request.current_height,
            until: request.required_until_height,
            roots: source.roots,
            manifests: source.manifests,
            original_identities: source.original_identities,
            providers: request.providers,
            funding: request.funding_operations,
            maximum_repairs_per_slot: request.maximum_repairs_per_slot,
            chunks_per_page: request.chunks_per_page,
            pages,
        };
        value.validate(false, deadline)?;
        Ok(value)
    }

    fn reserved_identities(&self) -> CellResultV1<BTreeSet<CellDigestV1>> {
        let mut identities = self.original_identities.clone();
        require(
            self.operation != [0; 32] && identities.insert(self.operation),
            "paged shard original operation alias",
        )?;
        for funding in self.funding.iter().flatten() {
            require(
                *funding != [0; 32] && identities.insert(*funding),
                "paged shard original funding alias",
            )?;
        }
        Ok(identities)
    }

    fn validate(&self, complete: bool, deadline: Instant) -> CellResultV1<()> {
        check(deadline)?;
        require(
            self.store != [0; 32]
                && self.retained != [0; 64]
                && self.catalog.generation() > 0
                && self.from < self.until
                && self.until <= i64::MAX as u64
                && !self.roots.is_empty()
                && self.roots.len() <= MAX_CELL_RETAINED_SHARD_ROOTS_V1
                && !self.manifests.is_empty()
                && self.manifests.len() <= MAX_CELL_PAGED_RETAINED_CHUNKS_V2
                && !self.funding.is_empty()
                && self.funding.len() <= MAX_CELL_PAGED_RETAINED_CHUNKS_V2
                && (1..=16).contains(&self.maximum_repairs_per_slot)
                && (1..=MAX_CELL_RETAINED_SHARD_CHUNKS_V1)
                    .contains(&usize::from(self.chunks_per_page))
                && !self.original_identities.is_empty()
                && self.original_identities.len() <= MAX_ORIGINAL_IDENTITIES
                && !self.original_identities.contains(&[0; 32]),
            "paged shard root bounds",
        )?;
        let mut previous_root = None;
        for root in &self.roots {
            require(
                root.operation != [0; 32]
                    && root.contract != [0; 32]
                    && root.version != [0; 64]
                    && previous_root.is_none_or(|old| old < root.operation)
                    && self.original_identities.contains(&root.operation),
                "paged shard canonical roots",
            )?;
            previous_root = Some(root.operation);
        }
        let mut previous = None;
        let mut chunks = 0_usize;
        let mut capacity = 0_u64;
        for manifest in &self.manifests {
            check(deadline)?;
            manifest.validate()?;
            let id = manifest.id();
            require(
                previous.is_none_or(|old| old < id),
                "paged shard canonical manifests",
            )?;
            previous = Some(id);
            chunks = chunks
                .checked_add(manifest.chunks().len())
                .ok_or(CellErrorV1::Invalid("paged shard chunk overflow"))?;
            for chunk in manifest.chunks() {
                let bytes =
                    super::super::SHARD_HEADER_BYTES as u64 + u64::from(chunk.size).div_ceil(4);
                capacity = capacity
                    .checked_add(bytes.div_ceil(4096) * 4096)
                    .ok_or(CellErrorV1::Invalid("paged shard capacity overflow"))?;
            }
        }
        require(
            chunks == self.chunk_count(),
            "paged shard complete chunk coverage",
        )?;
        let mut stores = BTreeSet::new();
        for provider in &self.providers {
            let store = provider.store_id()?;
            crate::cell::retention::validate_config(&crate::cell::CellRetentionConfigV1 {
                store_id: store,
                capacity_bytes: provider.capacity_bytes,
                maximum_obligations: provider.maximum_obligations,
            })?;
            require(
                stores.insert(store)
                    && provider.maximum_obligations as usize >= chunks
                    && provider.capacity_bytes >= capacity,
                "paged shard whole provider capacity",
            )?;
        }
        self.reserved_identities()?;
        let width = usize::from(self.chunks_per_page);
        require(
            self.pages.len() == chunks.div_ceil(width)
                && self.pages.len() <= MAX_CELL_RETAINED_SHARD_PAGES_V2,
            "paged shard page count",
        )?;
        for (index, page) in self.pages.iter().enumerate() {
            require(
                page.index() == index
                    && page.start_chunk() == index * width
                    && page.chunk_count() == (chunks - index * width).min(width)
                    && (!complete || page.commitment != [0; 32]),
                "paged shard exact page partition",
            )?;
        }
        require(
            self.encode().len() <= MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2,
            "paged shard root metadata capacity",
        )?;
        check(deadline)
    }

    fn chunk_at(&self, global: usize) -> CellResultV1<(&CellManifestV1, u32)> {
        let mut offset = global;
        for manifest in &self.manifests {
            if offset < manifest.chunks().len() {
                return Ok((manifest, offset as u32));
            }
            offset -= manifest.chunks().len();
        }
        Err(CellErrorV1::Invalid("paged shard chunk index"))
    }

    fn read_source_chunk(
        &self,
        catalog: &mut CellVersionRetentionStoreV3,
        manifest: &CellManifestV1,
        index: u32,
        deadline: Instant,
    ) -> CellResultV1<Vec<u8>> {
        for root in &self.roots {
            check(deadline)?;
            let contract = catalog.contract(root.operation, deadline)?;
            if contract
                .version
                .manifests()
                .iter()
                .any(|item| item == manifest)
            {
                return catalog.read_chunk_for_plan(
                    root.operation,
                    manifest.id(),
                    index,
                    self.catalog,
                    deadline,
                );
            }
        }
        Err(CellErrorV1::Invalid("paged shard source member"))
    }

    fn build_page(
        &self,
        index: usize,
        catalog: &mut CellVersionRetentionStoreV3,
        deadline: Instant,
    ) -> CellResultV1<CellRetainedShardPageV2> {
        check(deadline)?;
        let page = self
            .pages
            .get(index)
            .ok_or(CellErrorV1::Invalid("paged shard page index"))?;
        let mut chunks = Vec::with_capacity(page.chunk_count());
        for global in page.start_chunk()..page.start_chunk() + page.chunk_count() {
            let (manifest, index) = self.chunk_at(global)?;
            let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                manifest,
                manifest.id(),
                manifest.context(),
                index,
            )?;
            let bytes = self.read_source_chunk(catalog, manifest, index, deadline)?;
            let codeword = CellRs46CodewordV1::from_verified_chunk(&binding, &bytes)?;
            let placement = CellRs46PlacementPolicyV1 {
                codeword: codeword.id(),
                placements: std::array::from_fn(|slot| self.providers[slot].placement.clone()),
            };
            let placement_id = placement.id()?;
            let shards = binding.encode_chunk(&bytes)?;
            let mut slots = Vec::with_capacity(6);
            for (slot, shard) in shards.into_iter().enumerate() {
                check(deadline)?;
                let wire = shard.encode();
                let provider = &self.providers[slot];
                slots.push(CellRs46ShardContractV1::from_verified_shard(
                    CellRs46ShardOwnerV1 {
                        original_operation: self.operation,
                        provider_store: provider.store_id()?,
                        owner_generation: provider.owner_generation,
                        funding_operation: self.funding[global][slot],
                        codeword: codeword.id(),
                        placement: placement_id,
                        slot: slot as u8,
                        context: manifest.context().clone(),
                        retain_from_height: self.from,
                        retain_until_height: self.until,
                        maximum_repair_bytes: (wire.len() as u64)
                            .checked_mul(u64::from(self.maximum_repairs_per_slot))
                            .ok_or(CellErrorV1::Invalid("paged shard repair overflow"))?,
                    },
                    &binding,
                    &codeword,
                    &placement,
                    &wire,
                )?);
            }
            chunks.push(CellRetainedShardChunkV1 {
                manifest: manifest.id(),
                index,
                slots: slots
                    .try_into()
                    .map_err(|_| CellErrorV1::Invalid("paged shard slots"))?,
            });
        }
        let value = CellRetainedShardPageV2 {
            scope: self.scope(),
            index: page.index,
            start: page.start,
            chunks,
        };
        value.validate_for(self, deadline)?;
        Ok(value)
    }
}

fn hash(domain: &[u8], bytes: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
