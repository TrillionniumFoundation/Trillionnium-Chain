//! Task-scoped borrowed RAM readiness with no cold-miss or device fallback.
//!
//! The caller prepares exact closures before admitting this set. A set is a
//! bounded byte view, not an expert ABI, an installed VRAM buffer, CURRENT or a
//! FinalUse token. The real owner must hold its current authority/resource
//! guard across use and provide its independently current context every time.

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use super::{
    checkpoint, CellResidencyConfigV1, CellResidencyUsageV1, CellResidencyV1, CellResidentViewV1,
};
use crate::cell::{require, CellDigestV1, CellLoaderContextV1, CellResultV1};

/// All declared closures are already in immutable RAM under the caller's
/// explicit per-task limits. Borrowing this handle keeps the pool borrowed, so
/// safe Rust cannot evict or switch it while the task still holds these views.
/// No store, path, peer or device handle is retained. Missing members refuse
/// the entire admission; a hot lookup has no network or disk fallback.
///
/// Every lookup checks the original absolute deadline and cancellation flag.
/// Once this handle observes cancellation or expiry, resetting the external
/// flag cannot revive it. The deadline bounds lookup admission, not preemption
/// of the caller's computation. Public bytes already copied by a consumer
/// cannot be recalled or made secret by cancellation or permission revocation.
///
/// ```compile_fail
/// use std::{sync::atomic::AtomicBool, time::Instant};
/// use trnm_data_availability::cell::*;
/// fn evict_task_bytes(
///     pool: &mut CellResidencyV1, task: CellDigestV1,
///     expected: &[CellLoaderContextV1], limits: CellResidencyConfigV1,
///     deadline: Instant, cancelled: &AtomicBool,
/// ) {
///     let ready = pool.admit_local_working_set(
///         task, expected, limits, deadline, cancelled,
///     ).unwrap();
///     pool.evict(expected[0].closure_id).unwrap();
///     let _ = ready.usage();
/// }
/// ```
pub struct CellResidentWorkingSetV1<'a> {
    task_id: CellDigestV1,
    members: Vec<CellResidentViewV1<'a>>,
    usage: CellResidencyUsageV1,
    deadline: Instant,
    cancelled: &'a AtomicBool,
    stopped: AtomicBool,
}

impl<'a> CellResidentWorkingSetV1<'a> {
    pub fn task_id(&self) -> CellDigestV1 {
        self.task_id
    }

    /// Immutable payload/reference accounting, not allocator overhead, process
    /// RSS, an NVMe block reservation or VRAM/device residency evidence.
    pub fn usage(&self) -> CellResidencyUsageV1 {
        self.usage
    }

    /// Look up one already admitted member using the caller's current pins.
    /// This equality check does not authenticate a caller-supplied context or
    /// replace the owner's withdrawal, generation, resource or FinalUse guard.
    /// There is no new deadline parameter and no transport capability here.
    pub fn with_local<T>(
        &self,
        task_id: CellDigestV1,
        current: &CellLoaderContextV1,
        consume: impl FnOnce(CellResidentViewV1<'a>) -> T,
    ) -> CellResultV1<T> {
        self.checkpoint()?;
        require(task_id == self.task_id, "resident task identity")?;
        let index = self
            .members
            .binary_search_by_key(&current.closure_id, |view| view.closure_id())
            .map_err(|_| crate::cell::CellErrorV1::Unavailable)?;
        let view = self.members[index];
        view.resident.verify_expected(current)?;
        self.checkpoint()?;
        Ok(consume(view))
    }

    fn checkpoint(&self) -> CellResultV1<()> {
        require(
            !self.stopped.load(Ordering::Acquire),
            "resident task stopped",
        )?;
        if let Err(error) = checkpoint(self.deadline, self.cancelled) {
            self.stopped.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
}

impl CellResidencyV1 {
    /// Admit the complete canonical task working set from RAM only, after
    /// explicit prefetch/preparation. Each context must be independently pinned
    /// by the existing loader owner and sorted by its distinct closure ID.
    /// Shared live chunk buffers are charged once; file references are charged
    /// for every mapping. No selected version or hot pin is changed on failure.
    pub fn admit_local_working_set<'a>(
        &'a self,
        task_id: CellDigestV1,
        expected: &[CellLoaderContextV1],
        limits: CellResidencyConfigV1,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> CellResultV1<CellResidentWorkingSetV1<'a>> {
        checkpoint(deadline, cancelled)?;
        limits.validate()?;
        require(task_id != [0; 32], "resident task identity")?;
        require(
            !expected.is_empty() && expected.len() <= limits.max_resident_closures,
            "resident task closure budget",
        )?;
        require(
            expected
                .windows(2)
                .all(|pair| pair[0].closure_id < pair[1].closure_id),
            "resident task canonical closures",
        )?;
        let mut members = Vec::with_capacity(expected.len());
        let mut usage = CellResidencyUsageV1::default();
        // Compare live allocation identity only, never hash payload again in a
        // hot lookup. Every chunk is nonempty, immutable and owned by this pool;
        // these addresses cannot escape as an identity or permission record.
        let mut unique = BTreeSet::new();
        for context in expected {
            checkpoint(deadline, cancelled)?;
            let resident = self.resident(context)?;
            usage.chunk_references = usage
                .chunk_references
                .checked_add(resident.chunk_references)
                .ok_or(crate::cell::CellErrorV1::Invalid(
                    "resident task reference budget",
                ))?;
            require(
                usage.chunk_references <= limits.max_chunk_references,
                "resident task reference budget",
            )?;
            for file in &resident.files {
                for bytes in &file.chunks {
                    checkpoint(deadline, cancelled)?;
                    if unique.insert(bytes.as_ptr()) {
                        usage.unique_payload_bytes = usage
                            .unique_payload_bytes
                            .checked_add(bytes.len() as u64)
                            .ok_or(crate::cell::CellErrorV1::Invalid(
                                "resident task byte budget",
                            ))?;
                        require(
                            usage.unique_payload_bytes <= limits.max_resident_bytes,
                            "resident task byte budget",
                        )?;
                    }
                }
            }
            members.push(CellResidentViewV1 { resident });
        }
        usage.unique_chunks = unique.len();
        usage.resident_closures = members.len();
        checkpoint(deadline, cancelled)?;
        Ok(CellResidentWorkingSetV1 {
            task_id,
            members,
            usage,
            deadline,
            cancelled,
            stopped: AtomicBool::new(false),
        })
    }
}
