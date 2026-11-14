//! Canonical metadata for one physical CRS1 slot. This is a new namespace;
//! neither its SHA-256 identity nor a placement declaration is an authorization.

use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};

use super::*;
use crate::cell::{CellChunkV1, CellContextV1, CellManifestV1, MAX_CHUNK_BYTES};

pub const MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1: usize = 4096;

/// Independently admitted identities and retention terms for one slot.
/// `funding_operation` must be supplied by the actual funding owner. Deriving
/// another digest from an already-paid operation does not fund another slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ShardOwnerV1 {
    pub original_operation: CellDigestV1,
    pub provider_store: CellDigestV1,
    pub owner_generation: u64,
    pub funding_operation: CellDigestV1,
    pub codeword: CellDigestV1,
    pub placement: CellDigestV1,
    pub slot: u8,
    /// The original caller-pinned context, unchanged. The stored payload is
    /// explicitly CRS1 wire, not a model release or an environment closure.
    pub context: CellContextV1,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    pub maximum_repair_bytes: u64,
}

/// CSP1 holds the entire CRC1, all six declared placements, the physical TCM1
/// and immutable operation terms. Its operation identity commits all of them.
/// The original source binding and operation pin remain independent inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ShardContractV1 {
    owner: CellRs46ShardOwnerV1,
    binding: CellRs46ChunkBindingV1,
    codeword: CellRs46CodewordV1,
    placement: CellRs46PlacementPolicyV1,
    manifest: CellManifestV1,
}

impl CellRs46ShardContractV1 {
    pub fn from_verified_shard(
        owner: CellRs46ShardOwnerV1,
        binding: &CellRs46ChunkBindingV1,
        codeword: &CellRs46CodewordV1,
        placement: &CellRs46PlacementPolicyV1,
        wire: &[u8],
    ) -> CellResultV1<Self> {
        validate_owner(&owner)?;
        let codeword =
            CellRs46CodewordV1::decode_pinned(&codeword.encode(), binding, owner.codeword)?;
        placement.verify_pin(owner.placement, owner.codeword)?;
        verify_shard(binding, &codeword, owner.slot, wire)?;
        let digest = Sha256::digest(wire).into();
        let manifest = CellManifestV1::new(
            owner.context.clone(),
            wire.len() as u64,
            digest,
            MAX_CHUNK_BYTES,
            vec![CellChunkV1 {
                size: wire.len() as u32,
                sha256: digest,
            }],
        )?;
        let value = Self {
            owner,
            binding: binding.clone(),
            codeword,
            placement: placement.clone(),
            manifest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn owner(&self) -> &CellRs46ShardOwnerV1 {
        &self.owner
    }

    pub fn binding(&self) -> &CellRs46ChunkBindingV1 {
        &self.binding
    }

    pub fn codeword(&self) -> &CellRs46CodewordV1 {
        &self.codeword
    }

    pub fn placement(&self) -> &CellRs46PlacementPolicyV1 {
        &self.placement
    }

    pub fn manifest(&self) -> &CellManifestV1 {
        &self.manifest
    }

    pub fn operation(&self) -> CellDigestV1 {
        operation_id(&self.encode())
    }

    pub fn retention_contract(&self) -> CellRetentionContractV1 {
        CellRetentionContractV1 {
            operation: self.operation(),
            funding_operation: self.owner.funding_operation,
            manifest: self.manifest.clone(),
            retain_from_height: self.owner.retain_from_height,
            retain_until_height: self.owner.retain_until_height,
            maximum_repair_bytes: self.owner.maximum_repair_bytes,
            // Provider migration requires a separately admitted successor plan;
            // this slot owner never silently adds one to an existing obligation.
            successor: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(2048);
        wire.extend_from_slice(b"CSP1");
        wire.extend_from_slice(&self.owner.original_operation);
        wire.extend_from_slice(&self.owner.provider_store);
        wire.extend_from_slice(&self.owner.owner_generation.to_be_bytes());
        wire.extend_from_slice(&self.owner.funding_operation);
        wire.extend_from_slice(&self.owner.retain_from_height.to_be_bytes());
        wire.extend_from_slice(&self.owner.retain_until_height.to_be_bytes());
        wire.extend_from_slice(&self.owner.maximum_repair_bytes.to_be_bytes());
        wire.push(self.owner.slot);
        wire.extend_from_slice(&self.codeword.encode());
        for placement in &self.placement.placements {
            for identity in placement_identities(placement) {
                wire.extend_from_slice(&identity);
            }
        }
        let manifest = self.manifest.encode();
        wire.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        wire.extend_from_slice(&manifest);
        wire
    }

    pub fn decode_pinned(
        wire: &[u8],
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
    ) -> CellResultV1<Self> {
        require(
            wire.len() <= MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1,
            "RS46 provider descriptor size",
        )?;
        require(
            expected_operation != [0; 32] && operation_id(wire) == expected_operation,
            "RS46 provider operation pin",
        )?;
        let mut input = Cursor::new(wire);
        require(
            take::<4>(&mut input)? == *b"CSP1",
            "RS46 provider descriptor version",
        )?;
        let original_operation = take(&mut input)?;
        let provider_store = take(&mut input)?;
        let owner_generation = u64::from_be_bytes(take(&mut input)?);
        let funding_operation = take(&mut input)?;
        let retain_from_height = u64::from_be_bytes(take(&mut input)?);
        let retain_until_height = u64::from_be_bytes(take(&mut input)?);
        let maximum_repair_bytes = u64::from_be_bytes(take(&mut input)?);
        let slot = take::<1>(&mut input)?[0];
        let codeword_wire = take::<CELL_RS46_CODEWORD_WIRE_BYTES_V1>(&mut input)?;
        let codeword_pin = {
            let mut h = Sha256::new();
            h.update(b"trnm.cell-rs46-codeword.v1\0");
            h.update(codeword_wire);
            h.finalize().into()
        };
        // The independent operation pin authenticates the descriptor's CRC1;
        // the separate binding still authenticates its original TCM1 identity.
        let codeword = CellRs46CodewordV1::decode_pinned(&codeword_wire, binding, codeword_pin)?;
        let mut placements = Vec::with_capacity(CELL_RS46_TOTAL_SHARDS_V1);
        for _ in 0..CELL_RS46_TOTAL_SHARDS_V1 {
            placements.push(CellRs46ShardPlacementV1 {
                provider_id: take(&mut input)?,
                responsible_owner: take(&mut input)?,
                administrator: take(&mut input)?,
                failure_domain: take(&mut input)?,
                domain_evidence: take(&mut input)?,
                repair_owner: take(&mut input)?,
            });
        }
        let placement = CellRs46PlacementPolicyV1 {
            codeword: codeword_pin,
            placements: placements
                .try_into()
                .map_err(|_| CellErrorV1::Invalid("RS46 provider placement count"))?,
        };
        let manifest_len = u32::from_be_bytes(take(&mut input)?) as usize;
        require(manifest_len <= 512, "RS46 provider manifest size")?;
        let position = input.position() as usize;
        require(
            position.checked_add(manifest_len) == Some(wire.len()),
            "RS46 provider descriptor trailing bytes",
        )?;
        let manifest = CellManifestV1::decode(&wire[position..])?;
        let owner = CellRs46ShardOwnerV1 {
            original_operation,
            provider_store,
            owner_generation,
            funding_operation,
            codeword: codeword_pin,
            placement: placement.id()?,
            slot,
            context: manifest.context().clone(),
            retain_from_height,
            retain_until_height,
            maximum_repair_bytes,
        };
        let value = Self {
            owner,
            binding: binding.clone(),
            codeword,
            placement,
            manifest,
        };
        value.validate()?;
        require(
            value.encode() == wire,
            "RS46 provider descriptor canonical bytes",
        )?;
        Ok(value)
    }

    pub(super) fn verify_pin(&self, expected: CellDigestV1) -> CellResultV1<()> {
        self.validate()?;
        require(self.operation() == expected, "RS46 provider operation pin")
    }

    pub(super) fn verify_wire(&self, wire: &[u8]) -> CellResultV1<CellRs46ShardV1> {
        require(
            wire.len() as u64 == self.manifest.size()
                && <[u8; 32]>::from(Sha256::digest(wire)) == self.manifest.payload_sha256(),
            "RS46 provider payload pin",
        )?;
        verify_shard(&self.binding, &self.codeword, self.owner.slot, wire)
    }

    fn validate(&self) -> CellResultV1<()> {
        validate_owner(&self.owner)?;
        CellRs46CodewordV1::decode_pinned(
            &self.codeword.encode(),
            &self.binding,
            self.owner.codeword,
        )?;
        self.placement
            .verify_pin(self.owner.placement, self.owner.codeword)?;
        self.manifest.validate()?;
        require(
            self.manifest.context() == &self.owner.context
                && self.manifest.size() == (SHARD_HEADER_BYTES + self.binding.shard_bytes()) as u64
                && self.manifest.chunk_bytes() == MAX_CHUNK_BYTES
                && self.manifest.chunks().len() == 1
                && self.manifest.chunks()[0].sha256 == self.manifest.payload_sha256(),
            "RS46 provider manifest binding",
        )?;
        require(
            self.encode().len() <= MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1,
            "RS46 provider descriptor size",
        )
    }
}

fn validate_owner(owner: &CellRs46ShardOwnerV1) -> CellResultV1<()> {
    owner.context.validate()?;
    require(
        owner.original_operation != [0; 32]
            && owner.provider_store != [0; 32]
            && owner.owner_generation > 0
            && owner.funding_operation != [0; 32]
            && owner.codeword != [0; 32]
            && owner.placement != [0; 32]
            && usize::from(owner.slot) < CELL_RS46_TOTAL_SHARDS_V1
            && owner.retain_from_height < owner.retain_until_height
            && owner.retain_until_height <= i64::MAX as u64
            && owner.maximum_repair_bytes <= i64::MAX as u64,
        "RS46 provider owner terms",
    )
}

fn verify_shard(
    binding: &CellRs46ChunkBindingV1,
    codeword: &CellRs46CodewordV1,
    slot: u8,
    wire: &[u8],
) -> CellResultV1<CellRs46ShardV1> {
    require(
        usize::from(slot) < CELL_RS46_TOTAL_SHARDS_V1,
        "RS46 provider slot",
    )?;
    let shard = CellRs46ShardV1::decode(wire)?;
    require(
        shard.index == slot
            && shard.manifest == binding.manifest
            && shard.chunk_index == binding.index
            && shard.source_size == binding.chunk.size
            && shard.source_sha256 == binding.chunk.sha256
            && shard.id() == codeword.shard_ids()[usize::from(slot)],
        "RS46 provider committed shard",
    )?;
    Ok(shard)
}

pub(super) fn placement_identities(placement: &CellRs46ShardPlacementV1) -> [CellDigestV1; 6] {
    [
        placement.provider_id,
        placement.responsible_owner,
        placement.administrator,
        placement.failure_domain,
        placement.domain_evidence,
        placement.repair_owner,
    ]
}

fn operation_id(wire: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-rs46-provider-slot.v1\0");
    hash.update(wire);
    hash.finalize().into()
}

fn take<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
