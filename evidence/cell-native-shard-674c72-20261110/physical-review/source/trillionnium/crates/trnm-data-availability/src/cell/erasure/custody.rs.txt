//! Owner-pinned codewords and bounded repair of damaged CRS1 readbacks.
//!
//! A codeword is derived from verified original bytes. Its fresh CRC1 wire and
//! digest bind all six exact shards; they are not a signature. Cold recovery
//! requires both the independently approved codeword digest and the original
//! TCM1 binding. Optional CAS publication also checks an independently pinned
//! TCV2 before writing and after actual readback. A placement policy only checks
//! distinct declared identities. This module does not authenticate providers,
//! prove physical independence, pay for service or create a persistent ledger.

use std::{collections::BTreeSet, time::Instant};

use sha2::{Digest, Sha256};

use super::{
    CellRs46ChunkBindingV1, CellRs46ShardV1, CELL_RS46_TOTAL_SHARDS_V1,
    MAX_CELL_RS46_SHARD_WIRE_BYTES_V1, SHARD_HEADER_BYTES,
};
use crate::cell::{
    require, CellDigestV1, CellErrorV1, CellResultV1, CellStoreV1, PinnedCellVersionContentV2,
};

/// CRC1 fixes the existing RS(6,4)/CRS1 profile. All integer fields are big-endian:
/// magic, original manifest, chunk index, source length/SHA-256, six CRS1 IDs.
pub const CELL_RS46_CODEWORD_WIRE_BYTES_V1: usize = 76 + 32 * CELL_RS46_TOTAL_SHARDS_V1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46CodewordV1 {
    binding: CellRs46ChunkBindingV1,
    shards: [CellDigestV1; CELL_RS46_TOTAL_SHARDS_V1],
}

impl CellRs46CodewordV1 {
    pub fn from_verified_chunk(
        binding: &CellRs46ChunkBindingV1,
        bytes: &[u8],
    ) -> CellResultV1<Self> {
        let shards = binding.encode_chunk(bytes)?;
        let value = Self {
            binding: binding.clone(),
            shards: shards.each_ref().map(CellRs46ShardV1::id),
        };
        value.validate_ids()?;
        Ok(value)
    }

    pub fn shard_ids(&self) -> &[CellDigestV1; CELL_RS46_TOTAL_SHARDS_V1] {
        &self.shards
    }

    pub fn encode(&self) -> [u8; CELL_RS46_CODEWORD_WIRE_BYTES_V1] {
        let mut bytes = [0; CELL_RS46_CODEWORD_WIRE_BYTES_V1];
        bytes[..4].copy_from_slice(b"CRC1");
        bytes[4..36].copy_from_slice(&self.binding.manifest);
        bytes[36..40].copy_from_slice(&self.binding.index.to_be_bytes());
        bytes[40..44].copy_from_slice(&self.binding.chunk.size.to_be_bytes());
        bytes[44..76].copy_from_slice(&self.binding.chunk.sha256);
        for (index, id) in self.shards.iter().enumerate() {
            bytes[76 + 32 * index..108 + 32 * index].copy_from_slice(id);
        }
        bytes
    }

    pub fn id(&self) -> CellDigestV1 {
        codeword_id(&self.encode())
    }

    /// Exact-length decode with two independent pins. A descriptor cannot
    /// substitute its source identity for the release owner's TCM1 binding.
    pub fn decode_pinned(
        bytes: &[u8],
        binding: &CellRs46ChunkBindingV1,
        expected_codeword: CellDigestV1,
    ) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_RS46_CODEWORD_WIRE_BYTES_V1,
            "RS46 codeword wire size",
        )?;
        require(&bytes[..4] == b"CRC1", "RS46 codeword version")?;
        require(codeword_id(bytes) == expected_codeword, "RS46 codeword pin")?;
        require(
            bytes[4..36] == binding.manifest
                && bytes[36..40] == binding.index.to_be_bytes()
                && bytes[40..44] == binding.chunk.size.to_be_bytes()
                && bytes[44..76] == binding.chunk.sha256,
            "RS46 codeword original chunk pin",
        )?;
        let value = Self {
            binding: binding.clone(),
            shards: std::array::from_fn(|index| {
                bytes[76 + 32 * index..108 + 32 * index].try_into().unwrap()
            }),
        };
        value.validate_ids()?;
        Ok(value)
    }

    fn validate_ids(&self) -> CellResultV1<()> {
        let mut unique = BTreeSet::new();
        require(
            self.shards
                .iter()
                .all(|id| *id != [0; 32] && unique.insert(*id)),
            "RS46 codeword shard identities",
        )
    }

    fn verify_input(&self, input: &CellRs46ShardInputV1<'_>) -> CellResultV1<CellRs46ShardV1> {
        let shard = CellRs46ShardV1::decode(input.wire)?;
        require(
            shard.index == input.index
                && shard.manifest == self.binding.manifest
                && shard.chunk_index == self.binding.index
                && shard.source_size == self.binding.chunk.size
                && shard.source_sha256 == self.binding.chunk.sha256
                && shard.id() == self.shards[usize::from(input.index)],
            "RS46 committed shard readback",
        )?;
        Ok(shard)
    }

    /// Screen every supplied readback against its original committed slot.
    /// Damaged, malformed and wrong-slot bytes are retained as rejected slots,
    /// never searched through as alternate decoding subsets. At least four
    /// committed shards are required. The existing original-payload verifier
    /// and all six re-encoded IDs must pass before any repaired bytes return.
    ///
    /// Fixed descriptor/pin and shape checks precede reservation. Admitted
    /// reservations precede untrusted shard decoding/hashing and remain spent
    /// on failure. The original deadline is checked between bounded work and
    /// before return; this is not a preemptive timeout or a WAN SLA.
    pub fn repair_chunk(
        &self,
        binding: &CellRs46ChunkBindingV1,
        expected_codeword: CellDigestV1,
        inputs: &[CellRs46ShardInputV1<'_>],
        budget: &mut CellRs46RepairBudgetV1,
    ) -> CellResultV1<CellRs46RepairV1> {
        require(self.id() == expected_codeword, "RS46 codeword pin")?;
        require(self.binding == *binding, "RS46 codeword original chunk pin")?;
        require(
            (4..=CELL_RS46_TOTAL_SHARDS_V1).contains(&inputs.len()),
            "RS46 repair input count",
        )?;
        require(
            inputs
                .iter()
                .all(|input| usize::from(input.index) < CELL_RS46_TOTAL_SHARDS_V1)
                && inputs.windows(2).all(|pair| pair[0].index < pair[1].index),
            "RS46 repair input order/duplicates",
        )?;
        require(
            inputs
                .iter()
                .all(|input| input.wire.len() <= MAX_CELL_RS46_SHARD_WIRE_BYTES_V1),
            "RS46 repair input wire bound",
        )?;
        // All summands are bounded above before this arithmetic or any copies.
        let input_bytes = inputs.iter().map(|input| input.wire.len() as u64).sum();
        let reconstruction_bytes = u64::from(binding.source_bytes())
            + CELL_RS46_TOTAL_SHARDS_V1 as u64
                * (SHARD_HEADER_BYTES + binding.shard_bytes()) as u64;
        let usage_before = budget.usage();
        budget.reserve(input_bytes, reconstruction_bytes)?;
        let mut verified = Vec::new();
        let mut rejected = Vec::new();
        for input in inputs {
            budget.check_deadline()?;
            match self.verify_input(input) {
                Ok(shard) => verified.push(shard),
                Err(_) => rejected.push(input.index),
            }
        }
        require(
            verified.len() >= 4,
            "RS46 repair requires four committed shards",
        )?;
        budget.check_deadline()?;
        let source = binding.recover_chunk(&verified)?;
        budget.check_deadline()?;
        let codeword = binding.encode_chunk(&source)?;
        for (index, shard) in codeword.iter().enumerate() {
            budget.check_deadline()?;
            require(
                shard.id() == self.shards[index],
                "RS46 repaired codeword pin",
            )?;
        }
        let verified: Vec<_> = verified.iter().map(CellRs46ShardV1::index).collect();
        let missing = (0..CELL_RS46_TOTAL_SHARDS_V1 as u8)
            .filter(|index| inputs.iter().all(|input| input.index != *index))
            .collect();
        let repaired = codeword
            .into_iter()
            .filter(|shard| !verified.contains(&shard.index()))
            .collect();
        budget.check_deadline()?;
        Ok(CellRs46RepairV1 {
            codeword: expected_codeword,
            source,
            verified,
            rejected,
            missing,
            repaired,
            cache_readback_observed: false,
            usage_before,
            usage_after: budget.usage(),
        })
    }

    /// Repair, verify the original chunk against the owner's strong TCV2 pin,
    /// write it through the existing quota-controlled CAS, then read actual CAS
    /// bytes and verify them again. All steps share the original repair budget
    /// and absolute deadline. A separate cache allowance reserves one full
    /// potential write plus read before either storage operation; failed strong
    /// checks, writes and readbacks retain all admitted debits.
    ///
    /// A late or failed readback can follow a committed valid cache write. It
    /// never returns a successful observation or rolls back other cache data.
    /// This publishes one chunk, not a complete manifest, replica or lease.
    pub fn repair_chunk_to_cache(
        &self,
        binding: &CellRs46ChunkBindingV1,
        expected_codeword: CellDigestV1,
        inputs: &[CellRs46ShardInputV1<'_>],
        target: CellRs46CacheTargetV1<'_>,
        budget: &mut CellRs46RepairBudgetV1,
    ) -> CellResultV1<CellRs46RepairV1> {
        let deadline = budget.deadline;
        let mut repair = self.repair_chunk(binding, expected_codeword, inputs, budget)?;
        budget.reserve_cache(2 * u64::from(binding.source_bytes()))?;
        target.content.verify_chunk(
            binding.manifest_id(),
            binding.chunk_index() as usize,
            &repair.source,
        )?;
        budget.check_deadline()?;
        target
            .store
            .put_chunk_with_deadline(&binding.chunk, &repair.source, Some(deadline))?;
        let readback = target
            .store
            .chunk_with_deadline(binding.chunk.sha256, Some(deadline))?
            .ok_or(CellErrorV1::Unavailable)?;
        budget.check_deadline()?;
        target.content.verify_chunk(
            binding.manifest_id(),
            binding.chunk_index() as usize,
            &readback,
        )?;
        require(readback == repair.source, "RS46 cache exact readback")?;
        budget.check_deadline()?;
        repair.cache_readback_observed = true;
        repair.usage_after = budget.usage();
        Ok(repair)
    }
}

fn codeword_id(bytes: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-rs46-codeword.v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

/// The request owner's slot is separate from the untrusted CRS1 header.
#[derive(Clone, Copy, Debug)]
pub struct CellRs46ShardInputV1<'a> {
    pub index: u8,
    pub wire: &'a [u8],
}

/// An existing local CAS and independently owner-pinned strong chunk checks.
/// Constructing this target does not authorize complete-version execution.
pub struct CellRs46CacheTargetV1<'a> {
    pub store: &'a CellStoreV1,
    pub content: &'a PinnedCellVersionContentV2<'a>,
}

/// No cloning/reset API: retry through the same admitted owner reservation.
/// These are potential logical bytes, including full CRS1 headers and the
/// recovered source plus all six reconstructed shards. They are not measured
/// network traffic, peak allocations, durable debits or storage payments.
#[derive(Debug)]
pub struct CellRs46RepairBudgetV1 {
    deadline: Instant,
    maximum_attempts: u32,
    maximum_input_bytes: u64,
    maximum_reconstruction_bytes: u64,
    maximum_cache_bytes: u64,
    usage: CellRs46RepairUsageV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellRs46RepairUsageV1 {
    pub attempts_committed: u32,
    pub input_bytes_committed: u64,
    pub reconstruction_bytes_committed: u64,
    /// Reserved payload bytes for potential CAS write plus actual readback;
    /// excludes database pages, WAL/SHM, keys and other storage overhead.
    pub cache_bytes_committed: u64,
}

impl CellRs46RepairBudgetV1 {
    pub fn new(
        deadline: Instant,
        maximum_attempts: u32,
        maximum_input_bytes: u64,
        maximum_reconstruction_bytes: u64,
    ) -> Self {
        Self::new_with_cache(
            deadline,
            maximum_attempts,
            maximum_input_bytes,
            maximum_reconstruction_bytes,
            0,
        )
    }

    /// Explicit cumulative CAS allowance. Each admitted publication needs at
    /// least twice the source chunk length; the ordinary constructor allows no
    /// cache publication. The allowance is potential logical payload I/O, not
    /// physical storage measurement, payment or a persistent debit ledger.
    pub fn new_with_cache(
        deadline: Instant,
        maximum_attempts: u32,
        maximum_input_bytes: u64,
        maximum_reconstruction_bytes: u64,
        maximum_cache_bytes: u64,
    ) -> Self {
        Self {
            deadline,
            maximum_attempts,
            maximum_input_bytes,
            maximum_reconstruction_bytes,
            maximum_cache_bytes,
            usage: CellRs46RepairUsageV1::default(),
        }
    }

    pub fn usage(&self) -> CellRs46RepairUsageV1 {
        self.usage
    }

    fn check_deadline(&self) -> CellResultV1<()> {
        require(
            Instant::now() < self.deadline,
            "RS46 repair original deadline",
        )
    }

    fn reserve(&mut self, input_bytes: u64, reconstruction_bytes: u64) -> CellResultV1<()> {
        self.check_deadline()?;
        let next = CellRs46RepairUsageV1 {
            attempts_committed: self
                .usage
                .attempts_committed
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("RS46 repair attempt overflow"))?,
            input_bytes_committed: self
                .usage
                .input_bytes_committed
                .checked_add(input_bytes)
                .ok_or(CellErrorV1::Invalid("RS46 repair input overflow"))?,
            reconstruction_bytes_committed: self
                .usage
                .reconstruction_bytes_committed
                .checked_add(reconstruction_bytes)
                .ok_or(CellErrorV1::Invalid("RS46 repair reconstruction overflow"))?,
            cache_bytes_committed: self.usage.cache_bytes_committed,
        };
        require(
            next.attempts_committed <= self.maximum_attempts
                && next.input_bytes_committed <= self.maximum_input_bytes
                && next.reconstruction_bytes_committed <= self.maximum_reconstruction_bytes,
            "RS46 repair budget exhausted",
        )?;
        self.usage = next;
        Ok(())
    }

    fn reserve_cache(&mut self, bytes: u64) -> CellResultV1<()> {
        self.check_deadline()?;
        let next = self
            .usage
            .cache_bytes_committed
            .checked_add(bytes)
            .ok_or(CellErrorV1::Invalid("RS46 repair cache overflow"))?;
        require(
            next <= self.maximum_cache_bytes,
            "RS46 repair cache budget exhausted",
        )?;
        self.usage.cache_bytes_committed = next;
        Ok(())
    }
}

/// Verified bytes and exact slot observations from one admitted repair only.
/// Repaired CRS1 shards still need an external storage write and fresh readback.
/// Optional CAS publication observes the recovered original chunk only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46RepairV1 {
    codeword: CellDigestV1,
    source: Vec<u8>,
    verified: Vec<u8>,
    rejected: Vec<u8>,
    missing: Vec<u8>,
    repaired: Vec<CellRs46ShardV1>,
    cache_readback_observed: bool,
    usage_before: CellRs46RepairUsageV1,
    usage_after: CellRs46RepairUsageV1,
}

impl CellRs46RepairV1 {
    pub fn codeword(&self) -> CellDigestV1 {
        self.codeword
    }
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    pub fn verified_slots(&self) -> &[u8] {
        &self.verified
    }
    pub fn rejected_slots(&self) -> &[u8] {
        &self.rejected
    }
    pub fn missing_slots(&self) -> &[u8] {
        &self.missing
    }
    pub fn repaired_shards(&self) -> &[CellRs46ShardV1] {
        &self.repaired
    }
    /// A historical strong check of actual local CAS bytes, not a guarantee
    /// about future bytes, full-version availability or independent custody.
    pub fn cache_readback_observed(&self) -> bool {
        self.cache_readback_observed
    }
    pub fn usage_before(&self) -> CellRs46RepairUsageV1 {
        self.usage_before
    }
    pub fn usage_after(&self) -> CellRs46RepairUsageV1 {
        self.usage_after
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ShardPlacementV1 {
    pub provider_id: CellDigestV1,
    pub responsible_owner: CellDigestV1,
    pub administrator: CellDigestV1,
    pub failure_domain: CellDigestV1,
    pub domain_evidence: CellDigestV1,
    pub repair_owner: CellDigestV1,
}

/// Six fixed slots in canonical index order. Distinct digests are declarations,
/// not evidence that hosts, administrators or operators are truly independent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46PlacementPolicyV1 {
    pub codeword: CellDigestV1,
    pub placements: [CellRs46ShardPlacementV1; CELL_RS46_TOTAL_SHARDS_V1],
}

impl CellRs46PlacementPolicyV1 {
    pub fn id(&self) -> CellResultV1<CellDigestV1> {
        require(self.codeword != [0; 32], "RS46 placement codeword identity")?;
        let mut providers = BTreeSet::new();
        let mut owners = BTreeSet::new();
        let mut administrators = BTreeSet::new();
        let mut domains = BTreeSet::new();
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-rs46-placement-policy.v1\0");
        hash.update(self.codeword);
        for (index, placement) in self.placements.iter().enumerate() {
            let identities = [
                placement.provider_id,
                placement.responsible_owner,
                placement.administrator,
                placement.failure_domain,
                placement.domain_evidence,
                placement.repair_owner,
            ];
            require(
                identities.iter().all(|identity| *identity != [0; 32]),
                "RS46 placement identity",
            )?;
            require(
                providers.insert(placement.provider_id)
                    && owners.insert(placement.responsible_owner)
                    && administrators.insert(placement.administrator)
                    && domains.insert(placement.failure_domain),
                "RS46 placement duplicate provider/owner/domain",
            )?;
            hash.update([index as u8]);
            for identity in identities {
                hash.update(identity);
            }
        }
        Ok(hash.finalize().into())
    }

    pub fn verify_pin(
        &self,
        expected_policy: CellDigestV1,
        expected_codeword: CellDigestV1,
    ) -> CellResultV1<()> {
        require(
            self.codeword == expected_codeword,
            "RS46 placement codeword pin",
        )?;
        require(self.id()? == expected_policy, "RS46 placement policy pin")
    }
}

#[cfg(test)]
mod tests;
