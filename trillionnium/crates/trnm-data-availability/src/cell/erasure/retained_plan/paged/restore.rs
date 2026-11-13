//! Complete selected-version reconstruction from CRR2/CRG2 committed shards.
//!
//! This consumer path writes only its quota-controlled CAS. It never repairs a
//! provider, reads catalog payload, settles a lease or grants execution rights.
//! Completion is a sequential current observation, not an atomic snapshot.

use std::{cell::Cell, collections::BTreeSet, time::Instant};

use super::{CellPagedRetainedShardPlanFileV2, MAX_CELL_PAGED_RETAINED_CHUNKS_V2};
use crate::cell::{
    require, CellContentDigestV2, CellContentReadSessionV2, CellContentReadUsageV2, CellDigestV1,
    CellErrorV1, CellReleaseLimitsV1, CellResultV1, CellRs46CacheTargetV1, CellRs46RepairBudgetV1,
    CellRs46RepairUsageV1, CellRs46ShardContractV1, CellRs46ShardInputV1, CellStoreV1,
    CellVersionCatalogAnchorV3, CellVersionCommitmentV1, CellVersionContentV2,
    CellVersionLoaderContextV1, CellVersionRetentionStoreV3, MAX_CELL_RS46_SHARD_WIRE_BYTES_V1,
};

/// Independent caller pins and the original complete-catalog file owner.
/// Exactly one complete version is restored; other protected versions remain
/// part of root/catalog integrity checks, not a claim of consumer delivery.
pub struct CellPagedShardRestoreRequestV2<'a, 'owner> {
    pub plan_file: &'a CellPagedRetainedShardPlanFileV2,
    pub catalog: &'a CellVersionRetentionStoreV3,
    pub current_height: u64,
    pub original_root_operation: CellDigestV1,
    pub content: &'a CellVersionContentV2,
    pub expected: &'a CellVersionLoaderContextV1<'owner>,
    pub content_pin: CellContentDigestV2,
    pub target: &'a CellStoreV1,
}

#[derive(Clone, Copy, Debug)]
pub struct CellPagedShardRestoreLimitsV2 {
    pub deadline: Instant,
    pub maximum_attempts: u32,
    pub maximum_chunks: u64,
    pub maximum_provider_reads: u64,
    pub maximum_input_bytes: u64,
    pub maximum_reconstruction_bytes: u64,
    pub maximum_cache_bytes: u64,
    pub maximum_readback_payload_bytes: u64,
    pub maximum_readback_chunks: u64,
}

/// Whole-attempt potential reservations retained after admitted failure. These
/// are not measured traffic, physical storage, CPU, payment debits or evidence
/// of independent failure domains.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellPagedShardRestoreUsageV2 {
    pub attempts_committed: u32,
    pub chunks_committed: u64,
    pub provider_reads_committed: u64,
    pub input_bytes_committed: u64,
    pub reconstruction_bytes_committed: u64,
    pub cache_bytes_committed: u64,
    pub readback_payload_bytes_committed: u64,
    pub readback_chunks_committed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    plan: CellDigestV1,
    catalog: CellVersionCatalogAnchorV3,
    root: CellDigestV1,
    version: CellVersionCommitmentV1,
    content: CellContentDigestV2,
}

/// One non-cloneable original deadline and allowance across failures/retries.
/// The first admitted attempt also binds the original plan/root/content scope.
pub struct CellPagedShardRestoreBudgetV2 {
    limits: CellPagedShardRestoreLimitsV2,
    usage: CellPagedShardRestoreUsageV2,
    scope: Option<Scope>,
    control_stopped: bool,
    codec: CellRs46RepairBudgetV1,
    readback: CellContentReadSessionV2,
}

impl CellPagedShardRestoreBudgetV2 {
    pub fn new(limits: CellPagedShardRestoreLimitsV2) -> CellResultV1<Self> {
        require(
            (1..=1024).contains(&limits.maximum_attempts),
            "paged restore finite attempts",
        )?;
        let codec_attempts = limits
            .maximum_attempts
            .checked_mul(MAX_CELL_PAGED_RETAINED_CHUNKS_V2 as u32)
            .ok_or(CellErrorV1::Invalid("paged restore attempt overflow"))?;
        let readback = CellContentReadSessionV2::new(
            CellReleaseLimitsV1 {
                max_payload_bytes: limits.maximum_readback_payload_bytes,
                max_chunks: limits.maximum_readback_chunks,
                deadline: limits.deadline,
            },
            limits.maximum_attempts,
        )?;
        Ok(Self {
            limits,
            usage: CellPagedShardRestoreUsageV2::default(),
            scope: None,
            control_stopped: false,
            codec: CellRs46RepairBudgetV1::new_with_cache(
                limits.deadline,
                codec_attempts,
                limits.maximum_input_bytes,
                limits.maximum_reconstruction_bytes,
                limits.maximum_cache_bytes,
            ),
            readback,
        })
    }

    pub fn usage(&self) -> CellPagedShardRestoreUsageV2 {
        self.usage
    }

    pub fn codec_usage(&self) -> CellRs46RepairUsageV1 {
        self.codec.usage()
    }

    pub fn readback_usage(&self) -> CellContentReadUsageV2 {
        self.readback.usage()
    }

    pub fn deadline(&self) -> Instant {
        self.limits.deadline
    }

    fn admit(&mut self, scope: Scope, cost: CellPagedShardRestoreUsageV2) -> CellResultV1<()> {
        check(self.limits.deadline)?;
        require(
            self.scope
                .as_ref()
                .is_none_or(|original| original == &scope),
            "paged restore original scope changed",
        )?;
        let add = |left: u64, right: u64| {
            left.checked_add(right)
                .ok_or(CellErrorV1::Invalid("paged restore budget overflow"))
        };
        let next = CellPagedShardRestoreUsageV2 {
            attempts_committed: self
                .usage
                .attempts_committed
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("paged restore budget overflow"))?,
            chunks_committed: add(self.usage.chunks_committed, cost.chunks_committed)?,
            provider_reads_committed: add(
                self.usage.provider_reads_committed,
                cost.provider_reads_committed,
            )?,
            input_bytes_committed: add(
                self.usage.input_bytes_committed,
                cost.input_bytes_committed,
            )?,
            reconstruction_bytes_committed: add(
                self.usage.reconstruction_bytes_committed,
                cost.reconstruction_bytes_committed,
            )?,
            cache_bytes_committed: add(
                self.usage.cache_bytes_committed,
                cost.cache_bytes_committed,
            )?,
            readback_payload_bytes_committed: add(
                self.usage.readback_payload_bytes_committed,
                cost.readback_payload_bytes_committed,
            )?,
            readback_chunks_committed: add(
                self.usage.readback_chunks_committed,
                cost.readback_chunks_committed,
            )?,
        };
        require(
            next.attempts_committed <= self.limits.maximum_attempts
                && next.chunks_committed <= self.limits.maximum_chunks
                && next.provider_reads_committed <= self.limits.maximum_provider_reads
                && next.input_bytes_committed <= self.limits.maximum_input_bytes
                && next.reconstruction_bytes_committed <= self.limits.maximum_reconstruction_bytes
                && next.cache_bytes_committed <= self.limits.maximum_cache_bytes
                && next.readback_payload_bytes_committed
                    <= self.limits.maximum_readback_payload_bytes
                && next.readback_chunks_committed <= self.limits.maximum_readback_chunks,
            "paged restore whole attempt budget",
        )?;
        self.scope = Some(scope);
        self.usage = next;
        Ok(())
    }
}

/// Actual complete selected-version CAS readback, not whole-catalog custody,
/// native settlement, future availability or execution rights.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CellPagedShardRestoreReadbackV2 {
    pub plan: CellDigestV1,
    pub catalog: CellVersionCatalogAnchorV3,
    pub original_root_operation: CellDigestV1,
    pub version: CellVersionCommitmentV1,
    pub content: CellContentDigestV2,
    pub manifests: usize,
    pub chunks: u64,
    pub payload_bytes: u64,
    pub verified_shards: u64,
    pub rejected_shards: u64,
    pub missing_shards: u64,
    pub usage: CellPagedShardRestoreUsageV2,
    pub codec_usage: CellRs46RepairUsageV1,
    pub readback_usage: CellContentReadUsageV2,
}

/// Reconstruct every selected-version chunk from original committed CRS1 bytes.
/// `None` records an unavailable slot; an error is preserved as a read failure.
/// All six callbacks share the supplied original absolute deadline. Callback I/O
/// is cooperative and must enforce its own transport/allocation bounds; this
/// function caps each returned wire before decoding and never uses CAS/catalog
/// payload as a recovery source. Its own live payload work is one codeword.
///
/// A failed attempt may leave valid quota-controlled cache entries. It neither
/// returns complete readback nor rolls back those entries or original duties.
pub fn restore_cell_paged_version_to_cache_v2(
    request: CellPagedShardRestoreRequestV2<'_, '_>,
    budget: &mut CellPagedShardRestoreBudgetV2,
    read: impl FnMut(&CellRs46ShardContractV1, Instant) -> CellResultV1<Option<Vec<u8>>>,
) -> CellResultV1<CellPagedShardRestoreReadbackV2> {
    restore_cell_paged_version_to_cache_controlled_v2(request, budget, read, &mut || Ok(()))
}

/// Carry the execution owner's original cancellation/resource checkpoint
/// through provider callbacks, codec work, CAS writes and complete readback.
/// A checkpoint refusal permanently stops this reservation, including calls
/// through the compatibility entry point; data/read failures retain the
/// original bounded retry allowance. No admitted debit or committed cache
/// entry is rolled back. The owner callback grants no new execution, funding
/// or custody authority, and cannot preempt a blocking I/O or codec operation.
pub fn restore_cell_paged_version_to_cache_controlled_v2(
    request: CellPagedShardRestoreRequestV2<'_, '_>,
    budget: &mut CellPagedShardRestoreBudgetV2,
    read: impl FnMut(&CellRs46ShardContractV1, Instant) -> CellResultV1<Option<Vec<u8>>>,
    checkpoint: &mut impl FnMut() -> CellResultV1<()>,
) -> CellResultV1<CellPagedShardRestoreReadbackV2> {
    require(!budget.control_stopped, "paged restore control stopped")?;
    let deadline = budget.deadline();
    let stopped = Cell::new(false);
    let mut control = || {
        require(!stopped.get(), "paged restore control stopped")?;
        let result = check(deadline)
            .and_then(|()| checkpoint())
            .and_then(|()| check(deadline));
        stopped.set(result.is_err());
        result
    };
    let result = restore_controlled(request, budget, read, &mut control);
    // A failed read/codec/storage operation may coincide with owner cancellation
    // before its normal post-work checkpoint. Observe that refusal as well so
    // an early `?` cannot reopen this reservation through the compatibility API.
    // Keep the original operation error; the final control only locks its owner.
    let final_control = if stopped.get() { Ok(()) } else { control() };
    budget.control_stopped |= stopped.get();
    match result {
        Ok(readback) => final_control.map(|()| readback),
        Err(error) => Err(error),
    }
}

fn restore_controlled(
    request: CellPagedShardRestoreRequestV2<'_, '_>,
    budget: &mut CellPagedShardRestoreBudgetV2,
    mut read: impl FnMut(&CellRs46ShardContractV1, Instant) -> CellResultV1<Option<Vec<u8>>>,
    checkpoint: &mut impl FnMut() -> CellResultV1<()>,
) -> CellResultV1<CellPagedShardRestoreReadbackV2> {
    let CellPagedShardRestoreRequestV2 {
        plan_file,
        catalog,
        current_height,
        original_root_operation,
        content,
        expected,
        content_pin,
        target,
    } = request;
    let deadline = budget.deadline();
    checkpoint()?;
    let plan = plan_file.read_complete_current(catalog, current_height, deadline)?;
    checkpoint()?;
    let pinned = content.pin_for_owner(expected, content_pin)?;
    checkpoint()?;
    require(
        original_root_operation != [0; 32]
            && plan.roots().iter().any(|root| {
                root.operation() == original_root_operation && root.version() == expected.commitment
            }),
        "paged restore original complete version root",
    )?;
    let mut selected = BTreeSet::new();
    let mut cost = CellPagedShardRestoreUsageV2::default();
    for manifest in content.version().manifests() {
        checkpoint()?;
        pinned.verify_manifest(manifest)?;
        let id = manifest.id();
        let position = plan
            .manifests()
            .binary_search_by_key(&id, |value| value.id())
            .map_err(|_| CellErrorV1::Invalid("paged restore manifest absent from root"))?;
        require(
            plan.manifests()[position] == *manifest && selected.insert(id),
            "paged restore exact selected manifest",
        )?;
        for chunk in manifest.chunks() {
            // Exact members of the bounded root union: at most 4,096 chunks
            // of at most 4 MiB enter these sums, including repeated references.
            let source = u64::from(chunk.size);
            let wire = super::super::super::SHARD_HEADER_BYTES as u64 + source.div_ceil(4);
            cost.chunks_committed += 1;
            cost.provider_reads_committed += 6;
            cost.input_bytes_committed += 6 * wire;
            cost.reconstruction_bytes_committed += source + 6 * wire;
            cost.cache_bytes_committed += 2 * source;
            cost.readback_payload_bytes_committed += source;
            cost.readback_chunks_committed += 1;
        }
    }
    require(
        cost.chunks_committed > 0
            && cost.chunks_committed <= MAX_CELL_PAGED_RETAINED_CHUNKS_V2 as u64,
        "paged restore selected chunk bound",
    )?;
    let scope = Scope {
        plan: plan.commitment(),
        catalog: plan.catalog_anchor(),
        root: original_root_operation,
        version: expected.commitment,
        content: content_pin,
    };
    // Reserve all potential work and final readback before callbacks or writes.
    // Failed reads/codec/publication never refund this original allowance.
    checkpoint()?;
    budget.admit(scope.clone(), cost)?;
    checkpoint()?;
    let mut chunks = 0_u64;
    let mut verified_shards = 0_u64;
    let mut rejected_shards = 0_u64;
    let mut missing_shards = 0_u64;
    for page_index in 0..plan.page_count() {
        checkpoint()?;
        let page = plan_file.read_page(page_index, deadline)?;
        checkpoint()?;
        for chunk in page.chunks() {
            if !selected.contains(&chunk.manifest()) {
                continue;
            }
            checkpoint()?;
            let mut wires = Vec::with_capacity(6);
            for (slot, contract) in chunk.slots().iter().enumerate() {
                checkpoint()?;
                if let Some(wire) = read(contract, deadline)? {
                    checkpoint()?;
                    require(
                        wire.len() <= MAX_CELL_RS46_SHARD_WIRE_BYTES_V1
                            && wire.len() as u64 <= contract.manifest().size(),
                        "paged restore shard wire bound",
                    )?;
                    wires.push((slot as u8, wire));
                }
                checkpoint()?;
            }
            let inputs: Vec<_> = wires
                .iter()
                .map(|(index, wire)| CellRs46ShardInputV1 {
                    index: *index,
                    wire,
                })
                .collect();
            let codeword = chunk.slots()[0].codeword();
            let repair = codeword.repair_chunk_to_cache_controlled(
                chunk.binding(),
                codeword.id(),
                &inputs,
                CellRs46CacheTargetV1 {
                    store: target,
                    content: &pinned,
                },
                &mut budget.codec,
                checkpoint,
            )?;
            require(
                repair.cache_readback_observed(),
                "paged restore actual chunk cache readback",
            )?;
            chunks += 1;
            verified_shards += repair.verified_slots().len() as u64;
            rejected_shards += repair.rejected_slots().len() as u64;
            missing_shards += repair.missing_slots().len() as u64;
            checkpoint()?;
        }
    }
    require(
        chunks == cost.chunks_committed,
        "paged restore complete selected chunk coverage",
    )?;
    for manifest in content.version().manifests() {
        checkpoint()?;
        target.put_manifest_with_deadline(manifest.id(), &manifest.encode(), Some(deadline))?;
        checkpoint()?;
    }
    // Scan complete ordered actual target bytes, checking original full SHA-256
    // and independently pinned TCV2 SHA-512 payload and chunk commitments.
    let observed = content.verify_cached_controlled(
        target,
        expected,
        content_pin,
        &mut budget.readback,
        checkpoint,
    )?;
    checkpoint()?;
    require(
        plan_file.read_complete_current(catalog, current_height, deadline)? == plan,
        "paged restore final complete root changed",
    )?;
    checkpoint()?;
    Ok(CellPagedShardRestoreReadbackV2 {
        plan: scope.plan,
        catalog: scope.catalog,
        original_root_operation,
        version: scope.version,
        content: scope.content,
        manifests: selected.len(),
        chunks,
        payload_bytes: cost.readback_payload_bytes_committed,
        verified_shards,
        rejected_shards,
        missing_shards,
        usage: budget.usage(),
        codec_usage: budget.codec_usage(),
        readback_usage: observed.usage(),
    })
}

fn check(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "paged restore original deadline")
}

#[cfg(test)]
mod tests;
