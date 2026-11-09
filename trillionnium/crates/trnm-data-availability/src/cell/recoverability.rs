//! Streaming verified RS recovery of the exact retained-version object union.
//!
//! Supplied shard bytes are untrusted until original chunk reconstruction and
//! codeword comparison succeed. Provider labels remain independently pinned
//! declarations: this API does not authenticate a network endpoint or prove
//! that a claimed independent provider currently stores the supplied bytes.

use std::{collections::BTreeMap, time::Instant};

use sha2::{Digest, Sha256, Sha512};

use super::{
    evaluate_recovery_placement, require, CellDigestV1, CellErrorV1, CellRecoveryFaultAxisV1,
    CellRecoveryFaultPolicyV1, CellRecoveryPartV1, CellRecoveryPlacementReportV1,
    CellRecoveryPlacementV1, CellRecoveryProviderPinV1, CellResultV1, CellRetainedSetOwnerV1,
    CellRetainedVersionSetV1, CellRs46ManifestBindingV1, CellRs46ShardV1, CellVersionCommitmentV1,
    MAX_CELL_RECOVERY_PROVIDERS_V1,
};

pub const MAX_CELL_RS46_RECOVERY_CHUNKS_V1: u64 = 65_536;

/// The owner pins the complete provider-to-fault-domain mapping and the exact
/// typed fault model. Six distinct labels are not evidence of independence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRecoveryPlacementPolicyV1 {
    providers: Vec<CellRecoveryProviderPinV1>,
    faults: CellRecoveryFaultPolicyV1,
    evaluation_steps_per_chunk: u64,
}

impl CellRecoveryPlacementPolicyV1 {
    pub fn new(
        providers: Vec<CellRecoveryProviderPinV1>,
        faults: CellRecoveryFaultPolicyV1,
    ) -> CellResultV1<Self> {
        let evaluation_steps_per_chunk =
            evaluate_recovery_placement(&providers, &[], &faults, u64::MAX)?.steps();
        Ok(Self {
            providers,
            faults,
            evaluation_steps_per_chunk,
        })
    }

    pub fn providers(&self) -> &[CellRecoveryProviderPinV1] {
        &self.providers
    }
    pub fn faults(&self) -> &CellRecoveryFaultPolicyV1 {
        &self.faults
    }

    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/RecoveryPlacement/v1\0");
        hash.update((self.providers.len() as u16).to_be_bytes());
        for pin in &self.providers {
            for id in [
                pin.provider_id,
                pin.operator,
                pin.administrator,
                pin.failure_domain,
                pin.domain_evidence,
            ] {
                hash.update(id);
            }
        }
        hash.update([
            self.faults.maximum_lost_events,
            self.faults.axes.len() as u8,
        ]);
        for axis in &self.faults.axes {
            hash.update([match axis {
                CellRecoveryFaultAxisV1::Operator => 1,
                CellRecoveryFaultAxisV1::Administrator => 2,
                CellRecoveryFaultAxisV1::FailureDomain => 3,
            }]);
        }
        hash.finalize().into()
    }

    fn work_per_chunk(&self) -> u64 {
        self.evaluation_steps_per_chunk
    }
}

/// Untrusted bytes and claimed supplying provider. No `verified` flag exists.
#[derive(Clone, Debug)]
pub struct CellRs46ProviderShardV1 {
    pub provider_id: CellDigestV1,
    pub shard: CellRs46ShardV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellRecoveryChunkKeyV1 {
    pub manifest: CellDigestV1,
    pub chunk_index: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellRs46RecoveryUsageV1 {
    pub attempts_committed: u32,
    pub chunks_committed: u64,
    pub source_bytes_committed: u64,
    pub evaluation_steps_committed: u64,
    /// All supplied CRS1 bytes, including corrupt and duplicate copies.
    pub shard_wire_bytes_committed: u64,
}

/// One original in-process reservation across sessions and failed attempts.
/// Decoding is chunk-bounded; this is not CPU preemption or a durable ledger.
#[derive(Debug)]
pub struct CellRs46RecoveryBudgetV1 {
    deadline: Instant,
    maximum_attempts: u32,
    maximum_chunks: u64,
    maximum_source_bytes: u64,
    maximum_evaluation_steps: u64,
    maximum_shard_wire_bytes: u64,
    usage: CellRs46RecoveryUsageV1,
}

impl CellRs46RecoveryBudgetV1 {
    pub fn new(
        deadline: Instant,
        maximum_attempts: u32,
        maximum_chunks: u64,
        maximum_source_bytes: u64,
        maximum_evaluation_steps: u64,
        maximum_shard_wire_bytes: u64,
    ) -> Self {
        Self {
            deadline,
            maximum_attempts,
            maximum_chunks,
            maximum_source_bytes,
            maximum_evaluation_steps,
            maximum_shard_wire_bytes,
            usage: CellRs46RecoveryUsageV1::default(),
        }
    }

    pub fn usage(&self) -> CellRs46RecoveryUsageV1 {
        self.usage
    }

    fn reserve_plan(&mut self, chunks: u64, bytes: u64, work: u64) -> CellResultV1<()> {
        self.check_deadline()?;
        let usage = CellRs46RecoveryUsageV1 {
            attempts_committed: self
                .usage
                .attempts_committed
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("RS46 recovery attempt overflow"))?,
            chunks_committed: self
                .usage
                .chunks_committed
                .checked_add(chunks)
                .ok_or(CellErrorV1::Invalid("RS46 recovery chunk overflow"))?,
            source_bytes_committed: self
                .usage
                .source_bytes_committed
                .checked_add(bytes)
                .ok_or(CellErrorV1::Invalid("RS46 recovery source overflow"))?,
            evaluation_steps_committed: self
                .usage
                .evaluation_steps_committed
                .checked_add(work)
                .ok_or(CellErrorV1::Invalid("RS46 recovery evaluation overflow"))?,
            shard_wire_bytes_committed: self.usage.shard_wire_bytes_committed,
        };
        require(
            usage.attempts_committed <= self.maximum_attempts
                && usage.chunks_committed <= self.maximum_chunks
                && usage.source_bytes_committed <= self.maximum_source_bytes
                && usage.evaluation_steps_committed <= self.maximum_evaluation_steps,
            "RS46 original complete-set reservation exhausted",
        )?;
        self.usage = usage;
        Ok(())
    }

    fn reserve_wire(&mut self, bytes: u64) -> CellResultV1<()> {
        let next = self
            .usage
            .shard_wire_bytes_committed
            .checked_add(bytes)
            .ok_or(CellErrorV1::Invalid("RS46 recovery wire overflow"))?;
        require(
            next <= self.maximum_shard_wire_bytes,
            "RS46 original wire reservation",
        )?;
        self.usage.shard_wire_bytes_committed = next;
        Ok(())
    }

    fn check_deadline(&self) -> CellResultV1<()> {
        require(
            Instant::now() < self.deadline,
            "RS46 recovery original deadline",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRecoveryChunkDeficitV1 {
    pub chunk: CellRecoveryChunkKeyV1,
    pub placement: CellRecoveryPlacementReportV1,
}

/// All original chunks and whole files were reconstructed. Fault tolerance is
/// conditional on the pinned provider declarations, not physical qualification.
#[derive(Debug)]
pub struct CellRetainedRs46ObservationV1 {
    retained_set: CellVersionCommitmentV1,
    placement_policy: CellVersionCommitmentV1,
    manifests: usize,
    chunks: u64,
    source_bytes: u64,
    deficits: Vec<CellRecoveryChunkDeficitV1>,
    started: Instant,
    finished: Instant,
}

impl CellRetainedRs46ObservationV1 {
    pub fn retained_set(&self) -> CellVersionCommitmentV1 {
        self.retained_set
    }
    pub fn placement_policy(&self) -> CellVersionCommitmentV1 {
        self.placement_policy
    }
    pub fn manifests(&self) -> usize {
        self.manifests
    }
    pub fn chunks(&self) -> u64 {
        self.chunks
    }
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    pub fn survives_declared_faults(&self) -> bool {
        self.deficits.is_empty()
    }
    pub fn deficits(&self) -> &[CellRecoveryChunkDeficitV1] {
        &self.deficits
    }
    pub fn observation_window(&self) -> (Instant, Instant) {
        (self.started, self.finished)
    }
}

/// Streaming complete-set verifier. The next required chunk is chosen by the
/// original manifest roster, never by a peer. Any refusal latches the session;
/// it cannot discard a bad chunk or replace its deadline and later finish.
/// Returned chunks may be staged in the existing cache, but only `finish`
/// establishes complete original payload hashes for the entire retained set.
pub struct CellRetainedRs46RecoveryV1<'a, 'b> {
    retained_set: CellVersionCommitmentV1,
    manifests: Vec<CellRs46ManifestBindingV1<'a>>,
    policy: &'a CellRecoveryPlacementPolicyV1,
    budget: &'b mut CellRs46RecoveryBudgetV1,
    position: usize,
    chunk_index: u32,
    payload_hash: Sha256,
    expected_chunks: u64,
    expected_source_bytes: u64,
    work_per_chunk: u64,
    failed: bool,
    deficits: Vec<CellRecoveryChunkDeficitV1>,
    started: Instant,
}

impl<'a, 'b> CellRetainedRs46RecoveryV1<'a, 'b> {
    pub fn new(
        retained: &'a CellRetainedVersionSetV1,
        owner: &CellRetainedSetOwnerV1<'_>,
        policy: &'a CellRecoveryPlacementPolicyV1,
        expected_policy: CellVersionCommitmentV1,
        budget: &'b mut CellRs46RecoveryBudgetV1,
    ) -> CellResultV1<Self> {
        let started = Instant::now();
        budget.check_deadline()?;
        retained.verify_for_owner(owner)?;
        require(
            policy.commitment() == expected_policy,
            "RS46 owner placement policy",
        )?;
        let work_per_chunk = policy.work_per_chunk();
        let mut manifests = BTreeMap::new();
        for entry in retained.entries() {
            for manifest in entry.version.manifests() {
                if let Some(previous) = manifests.insert(manifest.id(), manifest) {
                    require(previous == manifest, "RS46 shared manifest changed")?;
                }
            }
        }
        let (chunks, bytes) = manifests.values().try_fold((0u64, 0u64), |(n, b), m| {
            Ok::<_, CellErrorV1>((
                n.checked_add(m.chunks().len() as u64)
                    .ok_or(CellErrorV1::Invalid("RS46 recovery chunk overflow"))?,
                b.checked_add(m.size())
                    .ok_or(CellErrorV1::Invalid("RS46 recovery source overflow"))?,
            ))
        })?;
        require(
            chunks <= MAX_CELL_RS46_RECOVERY_CHUNKS_V1,
            "RS46 complete recovery chunk bound",
        )?;
        let work = chunks
            .checked_mul(work_per_chunk)
            .ok_or(CellErrorV1::Invalid("RS46 recovery evaluation overflow"))?;
        budget.reserve_plan(chunks, bytes, work)?;
        let bindings = manifests
            .into_iter()
            .map(|(id, manifest)| CellRs46ManifestBindingV1::new(manifest, id, manifest.context()))
            .collect::<CellResultV1<Vec<_>>>()?;
        budget.check_deadline()?;
        Ok(Self {
            retained_set: owner.commitment,
            manifests: bindings,
            policy,
            budget,
            position: 0,
            chunk_index: 0,
            payload_hash: Sha256::new(),
            expected_chunks: chunks,
            expected_source_bytes: bytes,
            work_per_chunk,
            failed: false,
            deficits: Vec::new(),
            started,
        })
    }

    pub fn next_chunk(&self) -> Option<CellRecoveryChunkKeyV1> {
        self.manifests
            .get(self.position)
            .map(|binding| CellRecoveryChunkKeyV1 {
                manifest: binding.manifest_id(),
                chunk_index: self.chunk_index,
            })
    }

    pub fn recover_next(&mut self, supplied: &[CellRs46ProviderShardV1]) -> CellResultV1<Vec<u8>> {
        let result = self.recover_inner(supplied);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn recover_inner(&mut self, supplied: &[CellRs46ProviderShardV1]) -> CellResultV1<Vec<u8>> {
        self.budget.check_deadline()?;
        require(!self.failed, "RS46 recovery already refused")?;
        require(
            (4..=6 * MAX_CELL_RECOVERY_PROVIDERS_V1).contains(&supplied.len()),
            "RS46 observed share count",
        )?;
        let manifest_binding = *self
            .manifests
            .get(self.position)
            .ok_or(CellErrorV1::Invalid("RS46 recovery unexpected extra chunk"))?;
        let manifest = manifest_binding.manifest();
        let key = CellRecoveryChunkKeyV1 {
            manifest: manifest_binding.manifest_id(),
            chunk_index: self.chunk_index,
        };
        let wire_bytes = supplied.iter().try_fold(0u64, |n, s| {
            n.checked_add(81 + s.shard.payload().len() as u64)
                .ok_or(CellErrorV1::Invalid("RS46 recovery wire overflow"))
        })?;
        self.budget.reserve_wire(wire_bytes)?;
        let placements: Vec<_> = supplied
            .iter()
            .map(|share| CellRecoveryPlacementV1 {
                provider_id: share.provider_id,
                part: CellRecoveryPartV1::Rs46(share.shard.index()),
            })
            .collect();
        let report = evaluate_recovery_placement(
            &self.policy.providers,
            &placements,
            &self.policy.faults,
            self.work_per_chunk,
        )?;
        let mut distinct = BTreeMap::new();
        for share in supplied {
            if let Some(old) = distinct.insert(share.shard.index(), &share.shard) {
                require(old == &share.shard, "RS46 conflicting copies of one shard")?;
            }
        }
        let shards: Vec<_> = distinct.into_values().cloned().collect();
        let binding = manifest_binding.chunk(key.chunk_index)?;
        let bytes = binding.recover_chunk(&shards)?;
        // Reconstruct one canonical codeword and check *every* observed copy,
        // including duplicate indices assigned to other provider declarations.
        let canonical = binding.encode_chunk(&bytes)?;
        for share in supplied {
            require(
                canonical[usize::from(share.shard.index())] == share.shard,
                "RS46 observed copy outside verified codeword",
            )?;
        }
        self.payload_hash.update(&bytes);
        if self.chunk_index as usize + 1 == manifest.chunks().len() {
            let actual: CellDigestV1 = self.payload_hash.clone().finalize().into();
            require(
                actual == manifest.payload_sha256(),
                "RS46 recovered whole payload",
            )?;
            self.position += 1;
            self.chunk_index = 0;
            self.payload_hash = Sha256::new();
        } else {
            self.chunk_index += 1;
        }
        if !report.survives_declared_faults() {
            self.deficits.push(CellRecoveryChunkDeficitV1 {
                chunk: key,
                placement: report,
            });
        }
        self.budget.check_deadline()?;
        Ok(bytes)
    }

    pub fn finish(self) -> CellResultV1<CellRetainedRs46ObservationV1> {
        self.budget.check_deadline()?;
        require(
            !self.failed && self.position == self.manifests.len() && self.chunk_index == 0,
            "RS46 complete retained closure not recovered",
        )?;
        let report = CellRetainedRs46ObservationV1 {
            retained_set: self.retained_set,
            placement_policy: self.policy.commitment(),
            manifests: self.manifests.len(),
            chunks: self.expected_chunks,
            source_bytes: self.expected_source_bytes,
            deficits: self.deficits,
            started: self.started,
            finished: Instant::now(),
        };
        self.budget.check_deadline()?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
