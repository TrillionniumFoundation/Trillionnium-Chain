use super::*;

impl CellRetainedShardPlanV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut wire = b"CRP1".to_vec();
        wire.extend(self.operation);
        wire.extend(self.store);
        wire.extend(self.catalog.encode());
        wire.extend(self.retained);
        wire.extend(self.from.to_be_bytes());
        wire.extend(self.until.to_be_bytes());
        wire.extend((self.roots.len() as u16).to_be_bytes());
        for root in &self.roots {
            wire.extend(root.operation);
            wire.extend(root.contract);
            wire.extend(root.version);
        }
        wire.extend((self.manifests.len() as u16).to_be_bytes());
        for manifest in &self.manifests {
            let bytes = manifest.encode();
            wire.extend((bytes.len() as u32).to_be_bytes());
            wire.extend(bytes);
        }
        wire.extend((self.chunks.len() as u16).to_be_bytes());
        for chunk in &self.chunks {
            wire.extend(chunk.manifest);
            wire.extend(chunk.index.to_be_bytes());
            for slot in &chunk.slots {
                let bytes = slot.encode();
                wire.extend(slot.operation());
                wire.extend((bytes.len() as u32).to_be_bytes());
                wire.extend(bytes);
            }
        }
        wire
    }

    /// An independent original commitment is mandatory. Full-set freshness
    /// additionally requires verify_current_catalog on the actual TCA3 owner.
    pub fn decode_pinned(
        wire: &[u8],
        expected: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        require(
            wire.len() <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1
                && expected != [0; 32]
                && commitment(wire) == expected,
            "retained shard plan independent pin/size",
        )?;
        let mut input = Input(wire);
        require(
            input.array::<4>()? == *b"CRP1",
            "retained shard plan namespace",
        )?;
        let operation = input.array()?;
        let store = input.array()?;
        let catalog = CellVersionCatalogAnchorV3::decode(input.take(44)?)?;
        let retained = input.array()?;
        let from = u64::from_be_bytes(input.array()?);
        let until = u64::from_be_bytes(input.array()?);
        let root_count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            root_count > 0 && root_count <= MAX_CELL_RETAINED_SHARD_ROOTS_V1,
            "retained shard plan root count",
        )?;
        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            check(deadline)?;
            roots.push(CellRetainedShardRootV1 {
                operation: input.array()?,
                contract: input.array()?,
                version: input.array()?,
            });
        }
        let manifest_count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            manifest_count > 0 && manifest_count <= MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
            "retained shard plan manifest count",
        )?;
        let mut manifests = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            check(deadline)?;
            let length = u32::from_be_bytes(input.array()?) as usize;
            manifests.push(CellManifestV1::decode(input.take(length)?)?);
        }
        let chunk_count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            chunk_count > 0 && chunk_count <= MAX_CELL_RETAINED_SHARD_CHUNKS_V1,
            "retained shard plan chunk count",
        )?;
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            check(deadline)?;
            let manifest = input.array()?;
            let index = u32::from_be_bytes(input.array()?);
            let original = manifests
                .iter()
                .find(|entry| entry.id() == manifest)
                .ok_or(CellErrorV1::Invalid("retained shard plan manifest absent"))?;
            let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                original,
                manifest,
                original.context(),
                index,
            )?;
            let mut slots = Vec::with_capacity(6);
            for _ in 0..6 {
                check(deadline)?;
                let operation = input.array()?;
                let length = u32::from_be_bytes(input.array()?) as usize;
                slots.push(CellRs46ShardContractV1::decode_pinned(
                    input.take(length)?,
                    &binding,
                    operation,
                )?);
            }
            chunks.push(CellRetainedShardChunkV1 {
                manifest,
                index,
                slots: slots
                    .try_into()
                    .map_err(|_| CellErrorV1::Invalid("retained shard plan slots"))?,
            });
        }
        require(input.0.is_empty(), "retained shard plan trailing bytes")?;
        let value = Self {
            operation,
            store,
            catalog,
            retained,
            from,
            until,
            roots,
            manifests,
            chunks,
        };
        value.validate(deadline)?;
        require(
            value.encode() == wire,
            "retained shard plan canonical bytes",
        )?;
        check(deadline)?;
        Ok(value)
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, size: usize) -> CellResultV1<&'a [u8]> {
        require(size <= self.0.len(), "retained shard plan truncated bytes")?;
        let (head, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("retained shard plan field"))
    }
}
