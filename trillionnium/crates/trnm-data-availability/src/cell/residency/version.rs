//! Complete TCV1 task admission over the existing immutable resident pool.
//!
//! Both declared components must already be present. A model-only working set
//! cannot satisfy this entry point, and an environment reference never requests
//! execution of an image, dynamic loading, a device allocation or FinalUse.

use std::{sync::atomic::AtomicBool, time::Instant};

use super::{
    checkpoint, CellResidencyConfigV1, CellResidencyUsageV1, CellResidencyV1, CellResidentViewV1,
    CellResidentWorkingSetV1,
};
use crate::cell::{
    require, CellDigestV1, CellResultV1, CellVersionCommitmentV1, CellVersionLoaderContextV1,
    CellVersionManifestV1,
};

/// One task's complete, independently pinned TCV1 model/environment byte set.
/// This borrows the existing pool and retains only metadata and borrowed views;
/// it neither clones payload buffers nor creates a cache/network capability.
/// The original task limits, deadline and latched cancellation belong to the
/// one underlying working set. Both current component contexts are rechecked
/// before the caller receives either component through `with_local`.
///
/// The existing execution owner must still authenticate its current pins and
/// hold its withdrawal, resource and FinalUse guard throughout actual use. The
/// environment inventory covers declared bytes, not an attestation of the host
/// executable, dynamic-library resolution, hardware or an omitted dependency.
/// A lookup cutoff cannot preempt consumer computation, revoke a previously
/// borrowed view or recall copied public bytes.
///
/// ```compile_fail
/// use std::{sync::atomic::AtomicBool, time::Instant};
/// use trnm_data_availability::cell::*;
/// fn evict_version_bytes(
///     pool: &mut CellResidencyV1, task: CellDigestV1,
///     version: &CellVersionManifestV1, expected: &CellVersionLoaderContextV1<'_>,
///     limits: CellResidencyConfigV1, deadline: Instant, cancelled: &AtomicBool,
/// ) {
///     let ready = pool.admit_local_version(
///         task, version, expected, limits, deadline, cancelled,
///     ).unwrap();
///     pool.evict(expected.environment.closure_id).unwrap();
///     let _ = ready.usage();
/// }
/// ```
pub struct CellResidentVersionV1<'a> {
    commitment: CellVersionCommitmentV1,
    model_root: CellDigestV1,
    model_closure: CellDigestV1,
    environment_closure: CellDigestV1,
    working_set: CellResidentWorkingSetV1<'a>,
}

/// A paired view delivered only after the complete version and both current
/// loader contexts have passed. All exposed chunks are the actual immutable
/// allocations admitted by the pool, including the environment's file bytes.
#[derive(Clone, Copy)]
pub struct CellResidentVersionViewV1<'a> {
    commitment: CellVersionCommitmentV1,
    model_root: CellDigestV1,
    model: CellResidentViewV1<'a>,
    environment: CellResidentViewV1<'a>,
}

impl<'a> CellResidentVersionViewV1<'a> {
    pub fn commitment(self) -> CellVersionCommitmentV1 {
        self.commitment
    }

    pub fn model_root(self) -> CellDigestV1 {
        self.model_root
    }

    pub fn model(self) -> CellResidentViewV1<'a> {
        self.model
    }

    pub fn environment(self) -> CellResidentViewV1<'a> {
        self.environment
    }
}

impl<'a> CellResidentVersionV1<'a> {
    pub fn task_id(&self) -> CellDigestV1 {
        self.working_set.task_id()
    }

    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        self.commitment
    }

    pub fn model_root(&self) -> CellDigestV1 {
        self.model_root
    }

    /// Counts the complete union of resident chunk allocations once and every
    /// file mapping reference. This is not process RSS or device memory.
    pub fn usage(&self) -> CellResidencyUsageV1 {
        self.working_set.usage()
    }

    /// Validate the original task and complete version, including both current
    /// component contexts, before invoking `consume` exactly once. A context
    /// that swaps model/environment, names a new version using the same model,
    /// tightens either component's byte/chunk limit below its real usage, or
    /// changes its generation/profile refuses without a partial callback.
    /// No caller-provided deadline or transport is accepted on this hot path.
    pub fn with_local<T>(
        &self,
        task_id: CellDigestV1,
        current: &CellVersionLoaderContextV1<'_>,
        consume: impl FnOnce(CellResidentVersionViewV1<'a>) -> T,
    ) -> CellResultV1<T> {
        // Enter the original working set before checking additional pins so
        // observed cancellation/expiry is latched even on a mismatching call.
        self.working_set
            .with_local(task_id, current.model, |model| {
                require(
                    current.commitment == self.commitment
                        && current.model.closure_id == self.model_closure
                        && current.environment.closure_id == self.environment_closure,
                    "resident complete version context",
                )?;
                self.working_set
                    .with_local(task_id, current.environment, |environment| {
                        consume(CellResidentVersionViewV1 {
                            commitment: self.commitment,
                            model_root: self.model_root,
                            model,
                            environment,
                        })
                    })
            })?
    }
}

impl CellResidencyV1 {
    /// Bind one TCV1 to the complete already-resident model/environment union.
    /// The independent complete commitment and both loader contexts are checked
    /// before the one task working-set admission. Full chunks and ordered file
    /// hashes were verified by the existing preparation owner before its private
    /// immutable allocations became resident; metadata/markers alone cannot
    /// create a resident component. No file is downloaded or prepared here.
    ///
    /// All task accounting includes the environment. Equal content allocations
    /// are charged once, while distinct closure mappings retain their separate
    /// reference charges. Failure changes no residency, selection or hot pin.
    pub fn admit_local_version<'a>(
        &'a self,
        task_id: CellDigestV1,
        version: &CellVersionManifestV1,
        expected: &CellVersionLoaderContextV1<'_>,
        limits: CellResidencyConfigV1,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> CellResultV1<CellResidentVersionV1<'a>> {
        checkpoint(deadline, cancelled)?;
        version.verify_for_loader(expected)?;
        checkpoint(deadline, cancelled)?;
        // Verify the full immutable closure objects, including roles, paths,
        // dependency edges and the model's environment identity. A pair of
        // arbitrary resident closure IDs is not a complete-version admission.
        require(
            &self.resident(expected.model)?.closure == version.model().closure()
                && &self.resident(expected.environment)?.closure == version.environment(),
            "resident complete version closures",
        )?;
        let model_root = version.model().id();
        let mut contexts = vec![expected.model.clone(), expected.environment.clone()];
        contexts.sort_by_key(|context| context.closure_id);
        // Both role-specific owner views have already been independently
        // verified. A possible equal closure occupies one working-set member.
        contexts.dedup_by_key(|context| context.closure_id);
        let working_set =
            self.admit_local_working_set(task_id, &contexts, limits, deadline, cancelled)?;
        Ok(CellResidentVersionV1 {
            commitment: expected.commitment,
            model_root,
            model_closure: expected.model.closure_id,
            environment_closure: expected.environment.closure_id,
            working_set,
        })
    }
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;
