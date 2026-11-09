use super::*;
use crate::cell::CellRs46ShardPlacementV1;

impl CellPagedRetainedShardPlanV2 {
    pub(super) fn encode_common(&self) -> Vec<u8> {
        let mut out = b"CRR2".to_vec();
        out.extend(self.operation);
        out.extend(self.store);
        out.extend(self.catalog.encode());
        out.extend(self.retained);
        out.extend(self.from.to_be_bytes());
        out.extend(self.until.to_be_bytes());
        out.extend(self.maximum_repairs_per_slot.to_be_bytes());
        out.extend(self.chunks_per_page.to_be_bytes());
        out.extend((self.roots.len() as u16).to_be_bytes());
        for root in &self.roots {
            out.extend(root.operation);
            out.extend(root.contract);
            out.extend(root.version);
        }
        out.extend((self.manifests.len() as u16).to_be_bytes());
        for manifest in &self.manifests {
            let bytes = manifest.encode();
            out.extend((bytes.len() as u32).to_be_bytes());
            out.extend(bytes);
        }
        out.extend((self.original_identities.len() as u32).to_be_bytes());
        for identity in &self.original_identities {
            out.extend(identity);
        }
        for provider in &self.providers {
            let placement = &provider.placement;
            for identity in [
                placement.provider_id,
                placement.responsible_owner,
                placement.administrator,
                placement.failure_domain,
                placement.domain_evidence,
                placement.repair_owner,
            ] {
                out.extend(identity);
            }
            out.extend(provider.owner_generation.to_be_bytes());
            out.extend(provider.capacity_bytes.to_be_bytes());
            out.extend(provider.maximum_obligations.to_be_bytes());
        }
        out.extend((self.funding.len() as u32).to_be_bytes());
        for chunk in &self.funding {
            for funding in chunk {
                out.extend(funding);
            }
        }
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_common();
        out.extend((self.pages.len() as u16).to_be_bytes());
        for page in &self.pages {
            out.extend(page.index.to_be_bytes());
            out.extend(page.start.to_be_bytes());
            out.extend(page.chunks.to_be_bytes());
            out.extend(page.commitment);
        }
        out
    }

    /// The root pin is independently retained by the owner. Decoding grants no
    /// funding, availability, page completion or current-catalog authority.
    pub fn decode_pinned(
        wire: &[u8],
        expected: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        require(
            wire.len() <= MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2
                && expected != [0; 32]
                && hash(b"trnm.cell-paged-retained-shard-root.v2\0", wire) == expected,
            "paged shard root independent pin/size",
        )?;
        let mut input = Input(wire);
        require(
            input.array::<4>()? == *b"CRR2",
            "paged shard root namespace",
        )?;
        let operation = input.array()?;
        let store = input.array()?;
        let catalog = CellVersionCatalogAnchorV3::decode(input.take(44)?)?;
        let retained = input.array()?;
        let from = input.u64()?;
        let until = input.u64()?;
        let maximum_repairs_per_slot = input.u32()?;
        let chunks_per_page = input.u16()?;
        let root_count = usize::from(input.u16()?);
        require(
            (1..=MAX_CELL_RETAINED_SHARD_ROOTS_V1).contains(&root_count),
            "paged shard root count",
        )?;
        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            roots.push(CellRetainedShardRootV1 {
                operation: input.array()?,
                contract: input.array()?,
                version: input.array()?,
            });
        }
        let manifest_count = usize::from(input.u16()?);
        require(
            (1..=MAX_CELL_PAGED_RETAINED_CHUNKS_V2).contains(&manifest_count),
            "paged shard manifest count",
        )?;
        let mut manifests = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            check(deadline)?;
            manifests.push(CellManifestV1::decode(input.framed()?)?);
        }
        let identity_count = input.u32()? as usize;
        require(
            (1..=MAX_ORIGINAL_IDENTITIES).contains(&identity_count),
            "paged shard identity count",
        )?;
        let mut original_identities = BTreeSet::new();
        let mut previous = None;
        for _ in 0..identity_count {
            let value = input.array()?;
            require(
                previous.is_none_or(|old| old < value),
                "paged shard canonical identities",
            )?;
            original_identities.insert(value);
            previous = Some(value);
        }
        let mut providers = Vec::with_capacity(6);
        for _ in 0..6 {
            providers.push(CellRs46ShardProviderConfigV1 {
                placement: CellRs46ShardPlacementV1 {
                    provider_id: input.array()?,
                    responsible_owner: input.array()?,
                    administrator: input.array()?,
                    failure_domain: input.array()?,
                    domain_evidence: input.array()?,
                    repair_owner: input.array()?,
                },
                owner_generation: input.u64()?,
                capacity_bytes: input.u64()?,
                maximum_obligations: input.u32()?,
            });
        }
        let funding_count = input.u32()? as usize;
        require(
            (1..=MAX_CELL_PAGED_RETAINED_CHUNKS_V2).contains(&funding_count),
            "paged shard funding count",
        )?;
        let mut funding = Vec::with_capacity(funding_count);
        for _ in 0..funding_count {
            check(deadline)?;
            funding.push([
                input.array()?,
                input.array()?,
                input.array()?,
                input.array()?,
                input.array()?,
                input.array()?,
            ]);
        }
        let page_count = usize::from(input.u16()?);
        require(
            (1..=MAX_CELL_RETAINED_SHARD_PAGES_V2).contains(&page_count),
            "paged shard page count",
        )?;
        let mut pages = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(CellRetainedShardPagePinV2 {
                index: input.u32()?,
                start: input.u32()?,
                chunks: input.u16()?,
                commitment: input.array()?,
            });
        }
        require(input.0.is_empty(), "paged shard root trailing bytes")?;
        let value = Self {
            operation,
            store,
            catalog,
            retained,
            from,
            until,
            roots,
            manifests,
            original_identities,
            providers: providers
                .try_into()
                .map_err(|_| CellErrorV1::Invalid("paged shard providers"))?,
            funding,
            maximum_repairs_per_slot,
            chunks_per_page,
            pages,
        };
        value.validate(true, deadline)?;
        require(
            value.encode() == wire,
            "paged shard root canonical encoding",
        )?;
        check(deadline)?;
        Ok(value)
    }
}

impl CellRetainedShardPageV2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"CRG2".to_vec();
        out.extend(self.scope);
        out.extend(self.index.to_be_bytes());
        out.extend(self.start.to_be_bytes());
        out.extend((self.chunks.len() as u16).to_be_bytes());
        for chunk in &self.chunks {
            out.extend(chunk.manifest);
            out.extend(chunk.index.to_be_bytes());
            for slot in &chunk.slots {
                let wire = slot.encode();
                out.extend(slot.operation());
                out.extend((wire.len() as u32).to_be_bytes());
                out.extend(wire);
            }
        }
        out
    }

    pub fn decode_pinned(
        wire: &[u8],
        root: &CellPagedRetainedShardPlanV2,
        index: usize,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        root.validate(true, deadline)?;
        let expected = root
            .pages
            .get(index)
            .ok_or(CellErrorV1::Invalid("paged shard page index"))?;
        require(
            wire.len() <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1
                && hash(b"trnm.cell-retained-shard-page.v2\0", wire) == expected.commitment,
            "paged shard page independent pin/size",
        )?;
        let mut input = Input(wire);
        require(
            input.array::<4>()? == *b"CRG2",
            "paged shard page namespace",
        )?;
        let scope = input.array()?;
        let actual_index = input.u32()?;
        let start = input.u32()?;
        let count = usize::from(input.u16()?);
        require(
            scope == root.scope()
                && actual_index as usize == index
                && start == expected.start
                && count == expected.chunk_count(),
            "paged shard exact page coverage",
        )?;
        let mut chunks = Vec::with_capacity(count);
        for local in 0..count {
            check(deadline)?;
            let manifest = input.array()?;
            let chunk_index = input.u32()?;
            let (original, expected_index) = root.chunk_at(expected.start_chunk() + local)?;
            require(
                manifest == original.id() && chunk_index == expected_index,
                "paged shard canonical chunk coverage",
            )?;
            let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                original,
                manifest,
                original.context(),
                chunk_index,
            )?;
            let mut slots = Vec::with_capacity(6);
            for _ in 0..6 {
                let operation = input.array()?;
                slots.push(CellRs46ShardContractV1::decode_pinned(
                    input.framed()?,
                    &binding,
                    operation,
                )?);
            }
            chunks.push(CellRetainedShardChunkV1 {
                manifest,
                index: chunk_index,
                slots: slots
                    .try_into()
                    .map_err(|_| CellErrorV1::Invalid("paged shard slots"))?,
            });
        }
        require(input.0.is_empty(), "paged shard page trailing bytes")?;
        let value = Self {
            scope,
            index: actual_index,
            start,
            chunks,
        };
        value.validate_for(root, deadline)?;
        require(
            value.encode() == wire,
            "paged shard page canonical encoding",
        )?;
        check(deadline)?;
        Ok(value)
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, size: usize) -> CellResultV1<&'a [u8]> {
        require(size <= self.0.len(), "paged shard truncated bytes")?;
        let (head, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("paged shard field"))
    }
    fn u16(&mut self) -> CellResultV1<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> CellResultV1<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> CellResultV1<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn framed(&mut self) -> CellResultV1<&'a [u8]> {
        let size = self.u32()? as usize;
        self.take(size)
    }
}
