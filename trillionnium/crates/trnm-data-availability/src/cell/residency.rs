//! Bounded immutable byte residency between the existing cache and its loader.
//!
//! Preparation may use transport. Local views and local selection cannot: they
//! have neither a store nor a peer argument. Selection is a process-local byte
//! routing hint, never CURRENT, a tensor installation or FinalUse authority.
//! The existing owner supplies fresh pins and guards its actual use/switch.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    release::fetch_closure_for_residency, require, CellClosureFetchReportV1, CellDigestV1,
    CellErrorV1, CellFileRoleV1, CellLoaderContextV1, CellManifestV1, CellReleaseClosureV1,
    CellReleaseFetchLimitsV1, CellResultV1, CellStoreV1, MAX_CELL_BYTES,
};

mod release_selection;
#[cfg(target_os = "linux")]
mod sealed_loader;
mod tensor;
mod version;
mod working_set;
pub use release_selection::{CellLocalReleaseSelectionV1, CellLocalSelectionStateV1};
#[cfg(target_os = "linux")]
pub use sealed_loader::{
    CellSealedLoaderBundleV1, CellSealedLoaderFileV1, CellSealedLoaderLimitsV1,
};
pub use tensor::{CellResidentTensorFileV1, CellResidentTensorModelV1, CellResidentTensorV1};
pub use version::{CellResidentVersionV1, CellResidentVersionViewV1};
pub use working_set::CellResidentWorkingSetV1;

static RESIDENCY_OWNER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Retained byte/metadata limits, independent of disk, transport and device
/// reservations. This is not a bound on allocator overhead or total process RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellResidencyConfigV1 {
    pub max_resident_bytes: u64,
    pub max_resident_closures: usize,
    pub max_chunk_references: usize,
}

impl CellResidencyConfigV1 {
    fn validate(self) -> CellResultV1<()> {
        require(
            (1..=MAX_CELL_BYTES).contains(&self.max_resident_bytes)
                && (1..=4096).contains(&self.max_resident_closures)
                && (1..=1_048_576).contains(&self.max_chunk_references),
            "finite residency configuration",
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellResidencyUsageV1 {
    pub unique_payload_bytes: u64,
    pub unique_chunks: usize,
    pub resident_closures: usize,
    pub chunk_references: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellResidencyPrepareReportV1 {
    pub closure_id: CellDigestV1,
    /// None means an exact resident hit: no disk read, weight-hash pass or peer work.
    pub fetch: Option<CellClosureFetchReportV1>,
    pub usage: CellResidencyUsageV1,
}

/// CAS ticket for this manager's local byte selection only. The revision stops
/// A -> B -> A from accepting an old A ticket. Never persist as an authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellLocalSelectionV1 {
    owner: u64,
    revision: u64,
    closure_id: CellDigestV1,
}

impl CellLocalSelectionV1 {
    pub fn closure_id(self) -> CellDigestV1 {
        self.closure_id
    }

    pub fn revision(self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ChunkKey {
    digest: CellDigestV1,
    size: u32,
}

struct CachedAdmissionPlan {
    manifests: Vec<CellManifestV1>,
    missing: BTreeSet<ChunkKey>,
    references: usize,
    payload_bytes: u64,
    additional_bytes: u64,
}

/// Ordered immutable chunks of one TCD1 file. Arc ownership stays private so
/// eviction cannot incorrectly refund memory still held by an external clone.
pub struct CellResidentFileV1 {
    path: String,
    role: CellFileRoleV1,
    manifest_id: CellDigestV1,
    payload_sha256: CellDigestV1,
    chunks: Vec<Arc<[u8]>>,
}

impl CellResidentFileV1 {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn role(&self) -> CellFileRoleV1 {
        self.role
    }
    pub fn manifest_id(&self) -> CellDigestV1 {
        self.manifest_id
    }
    pub fn payload_sha256(&self) -> CellDigestV1 {
        self.payload_sha256
    }
    pub fn chunks(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.chunks.iter().map(AsRef::as_ref)
    }
}

struct ResidentClosure {
    closure: CellReleaseClosureV1,
    id: CellDigestV1,
    files: Vec<CellResidentFileV1>,
    payload_bytes: u64,
    chunk_references: usize,
    hot: bool,
}

impl ResidentClosure {
    /// The exact immutable closure was validated once before admission. A hot
    /// lookup checks all independently supplied owner constraints without
    /// serializing the closure or hashing/reading its weight payload again.
    fn verify_expected(&self, expected: &CellLoaderContextV1) -> CellResultV1<()> {
        require(
            self.id == expected.closure_id
                && self.closure.release().context() == &expected.context
                && self.closure.selected_generation() == expected.selected_generation
                && self.closure.loader_profile() == expected.loader_profile,
            "resident loader context",
        )?;
        require(
            expected.max_payload_bytes > 0 && expected.max_chunks > 0,
            "resident loader budget",
        )?;
        require(
            !expected.required_roles.is_empty()
                && expected.required_roles.len() <= 6
                && expected.required_roles.iter().enumerate().all(|(i, role)| {
                    !expected.required_roles[..i].contains(role)
                        && self.files.iter().any(|file| file.role == *role)
                }),
            "resident required roles",
        )?;
        require(
            self.payload_bytes <= expected.max_payload_bytes
                && self.chunk_references as u64 <= expected.max_chunks,
            "resident loader budget",
        )
    }
}

/// Borrowing a view keeps the manager borrowed, so safe Rust cannot mutate,
/// switch or evict it while the consumer uses its bytes. No owned Arc escapes.
#[derive(Clone, Copy)]
pub struct CellResidentViewV1<'a> {
    resident: &'a ResidentClosure,
}

impl<'a> CellResidentViewV1<'a> {
    pub fn closure_id(self) -> CellDigestV1 {
        self.resident.id
    }
    pub fn closure(self) -> &'a CellReleaseClosureV1 {
        &self.resident.closure
    }
    pub fn files(self) -> &'a [CellResidentFileV1] {
        &self.resident.files
    }
}

/// One loader owner's finite resident pool. All admissions are explicit; it
/// never evicts a hot/current version to speculate about a future route.
pub struct CellResidencyV1 {
    owner: u64,
    config: CellResidencyConfigV1,
    chunks: BTreeMap<ChunkKey, Arc<[u8]>>,
    residents: BTreeMap<CellDigestV1, ResidentClosure>,
    usage: CellResidencyUsageV1,
    selection: Option<CellLocalSelectionStateV1>,
}

impl CellResidencyV1 {
    pub fn new(config: CellResidencyConfigV1) -> CellResultV1<Self> {
        config.validate()?;
        let owner = RESIDENCY_OWNER_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CellErrorV1::Invalid("resident owner sequence exhausted"))?;
        Ok(Self {
            owner,
            config,
            chunks: BTreeMap::new(),
            residents: BTreeMap::new(),
            usage: CellResidencyUsageV1::default(),
            selection: None,
        })
    }

    pub fn usage(&self) -> CellResidencyUsageV1 {
        self.usage
    }

    /// Legacy single-closure selection only. Complete-release mode returns
    /// None here; use `local_selection` to distinguish its selected profile.
    pub fn selection(&self) -> Option<CellLocalSelectionV1> {
        match self.selection {
            Some(CellLocalSelectionStateV1::Closure(selected)) => Some(selected),
            _ => None,
        }
    }

    /// Explicit routing prediction or cold-load preparation. A caller chooses
    /// the pinned closure; this method cannot substitute a peer's version.
    /// One original download deadline includes fetch, verification and staging.
    /// Cancellation shares the existing fetch owner and local staging
    /// checkpoints. Fetch retains its original absolute deadline and budgets;
    /// cancellation does not undo already verified disposable cache writes.
    pub fn prefetch(
        &mut self,
        store: &CellStoreV1,
        closure: &CellReleaseClosureV1,
        expected: &CellLoaderContextV1,
        peers: &[SocketAddr],
        mut limits: CellReleaseFetchLimitsV1,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellResidencyPrepareReportV1> {
        limits.peer.validate()?;
        limits.release.deadline = limits.release.deadline.min(
            Instant::now()
                .checked_add(limits.peer.overall_timeout)
                .ok_or(CellErrorV1::Invalid("residency deadline overflow"))?,
        );
        checkpoint(limits.release.deadline, cancelled)?;
        let mut bounded = expected.clone();
        bounded.max_payload_bytes = bounded
            .max_payload_bytes
            .min(limits.release.max_payload_bytes);
        bounded.max_chunks = bounded.max_chunks.min(limits.release.max_chunks);
        closure.verify_for_loader(&bounded)?;
        if let Some(resident) = self.residents.get(&bounded.closure_id) {
            resident.verify_expected(&bounded)?;
            checkpoint(limits.release.deadline, cancelled)?;
            return Ok(CellResidencyPrepareReportV1 {
                closure_id: bounded.closure_id,
                fetch: None,
                usage: self.usage,
            });
        }
        self.check_slot()?;
        let fetch = fetch_closure_for_residency(
            store,
            closure,
            &bounded,
            peers,
            limits,
            (self, cancelled),
        )?;
        self.prepare_cached(store, closure, &bounded, limits.release.deadline, cancelled)?;
        Ok(CellResidencyPrepareReportV1 {
            closure_id: bounded.closure_id,
            fetch: Some(fetch),
            usage: self.usage,
        })
    }

    /// Reconstruct a complete immutable mapping from the fixed-version disk
    /// cache, including after process restart. Missing/corrupt bytes refuse;
    /// there is no network fallback. A failed admission changes no resident or
    /// selection. Verified disposable disk chunks can remain after a failure.
    pub fn prepare_cached(
        &mut self,
        store: &CellStoreV1,
        closure: &CellReleaseClosureV1,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<()> {
        checkpoint(deadline, cancelled)?;
        closure.verify_for_loader(expected)?;
        if let Some(resident) = self.residents.get(&expected.closure_id) {
            resident.verify_expected(expected)?;
            return checkpoint(deadline, cancelled);
        }
        self.check_slot()?;
        let CachedAdmissionPlan {
            manifests,
            missing,
            references,
            payload_bytes,
            additional_bytes,
        } = self.cached_admission_plan(store, closure, expected, deadline, cancelled)?;
        let mut added = BTreeMap::<ChunkKey, Arc<[u8]>>::new();
        let mut files = Vec::with_capacity(closure.files().len());
        for (file, manifest) in closure.files().iter().zip(manifests) {
            let mut full = Sha256::new();
            let mut chunks = Vec::with_capacity(manifest.chunks().len());
            for chunk in manifest.chunks() {
                checkpoint(deadline, cancelled)?;
                let key = ChunkKey {
                    digest: chunk.sha256,
                    size: chunk.size,
                };
                let bytes = if let Some(bytes) = self.chunks.get(&key).or_else(|| added.get(&key)) {
                    Arc::clone(bytes)
                } else {
                    let bytes = store
                        .chunk_with_deadline(chunk.sha256, Some(deadline))?
                        .ok_or(CellErrorV1::Unavailable)?;
                    super::store::verify_chunk_length(chunk, &bytes)?;
                    // The store has just verified the actual chunk hash. The
                    // temporary Vec -> Arc conversion can use one extra chunk
                    // buffer; it is not counted as retained payload or GPU RAM.
                    let bytes: Arc<[u8]> = bytes.into();
                    added.insert(key, Arc::clone(&bytes));
                    bytes
                };
                full.update(&bytes);
                chunks.push(bytes);
            }
            require(
                <[u8; 32]>::from(full.finalize()) == manifest.payload_sha256(),
                "resident complete payload digest",
            )?;
            files.push(CellResidentFileV1 {
                path: file.path.clone(),
                role: file.role,
                manifest_id: file.manifest,
                payload_sha256: file.payload_sha256,
                chunks,
            });
        }
        checkpoint(deadline, cancelled)?;
        let resident = ResidentClosure {
            closure: closure.clone(),
            id: expected.closure_id,
            files,
            payload_bytes,
            chunk_references: references,
            hot: false,
        };
        resident.verify_expected(expected)?;
        checkpoint(deadline, cancelled)?;
        self.chunks.extend(added);
        #[cfg(test)]
        tests::after_index_merge(deadline);
        // An unusually large index merge is still preparation, not publication.
        // On an observed timeout/cancellation remove only this attempt's new
        // keys; all old mappings, usage and local selection stay unchanged.
        if let Err(error) = checkpoint(deadline, cancelled) {
            for key in missing {
                self.chunks.remove(&key);
            }
            return Err(error);
        }
        self.residents.insert(expected.closure_id, resident);
        self.usage.unique_payload_bytes += additional_bytes;
        self.usage.unique_chunks = self.chunks.len();
        self.usage.resident_closures += 1;
        self.usage.chunk_references += references;
        Ok(())
    }

    pub fn pin_hot(&mut self, expected: &CellLoaderContextV1) -> CellResultV1<()> {
        let resident = self
            .residents
            .get_mut(&expected.closure_id)
            .ok_or(CellErrorV1::Unavailable)?;
        resident.verify_expected(expected)?;
        resident.hot = true;
        Ok(())
    }

    pub fn unpin_hot(&mut self, id: CellDigestV1) -> CellResultV1<()> {
        self.residents
            .get_mut(&id)
            .ok_or(CellErrorV1::Unavailable)?
            .hot = false;
        Ok(())
    }

    /// Explicit cache policy only. Borrowed views prevent mutable access to the
    /// manager; hot and locally selected mappings additionally refuse eviction.
    pub fn evict(&mut self, id: CellDigestV1) -> CellResultV1<()> {
        let resident = self.residents.get(&id).ok_or(CellErrorV1::Unavailable)?;
        require(!resident.hot, "resident hot pin")?;
        require(
            self.selection.is_none_or(|selected| !selected.protects(id)),
            "resident local selection pinned",
        )?;
        self.usage.chunk_references -= resident.chunk_references;
        self.residents.remove(&id);
        self.chunks.retain(|_, bytes| Arc::strong_count(bytes) > 1);
        self.usage.unique_payload_bytes = self.chunks.keys().map(|key| u64::from(key.size)).sum();
        self.usage.unique_chunks = self.chunks.len();
        self.usage.resident_closures -= 1;
        Ok(())
    }

    /// Atomically replace only this process's byte-selection hint. The existing
    /// Hepta owner must separately enforce CURRENT, generation/withdrawal,
    /// resource admission, tensor readback and FinalUse under its real guard.
    /// A complete-release selection cannot be downgraded through this API.
    /// No slow operation or user callback runs after the final checkpoint.
    pub fn select_local(
        &mut self,
        expected_previous: Option<CellLocalSelectionV1>,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellLocalSelectionV1> {
        checkpoint(deadline, cancelled)?;
        require(
            self.selection == expected_previous.map(CellLocalSelectionStateV1::Closure),
            "resident selection conflict",
        )?;
        self.resident(expected)?;
        let revision = self
            .selection
            .map_or(0, CellLocalSelectionStateV1::revision)
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid(
                "resident selection revision exhausted",
            ))?;
        let selected = CellLocalSelectionV1 {
            owner: self.owner,
            revision,
            closure_id: expected.closure_id,
        };
        checkpoint(deadline, cancelled)?;
        self.selection = Some(CellLocalSelectionStateV1::Closure(selected));
        Ok(selected)
    }

    /// Exact pinned read, with no store/transport capability and no cold miss
    /// fallback. The callback may borrow bytes for local parsing or computation;
    /// its execution, allocations and authority are owned by the caller. The
    /// deadline bounds lookup admission, not preemption of the caller's work.
    pub fn with_local<'a, T>(
        &'a self,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        consume: impl FnOnce(CellResidentViewV1<'a>) -> T,
    ) -> CellResultV1<T> {
        require(Instant::now() < deadline, "resident lookup deadline")?;
        let resident = self.resident(expected)?;
        require(Instant::now() < deadline, "resident lookup deadline")?;
        Ok(consume(CellResidentViewV1 { resident }))
    }

    pub fn with_selected<'a, T>(
        &'a self,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        consume: impl FnOnce(CellResidentViewV1<'a>) -> T,
    ) -> CellResultV1<T> {
        require(
            self.selection()
                .is_some_and(|selected| selected.closure_id == expected.closure_id),
            "resident local selection mismatch",
        )?;
        self.with_local(expected, deadline, consume)
    }

    fn resident(&self, expected: &CellLoaderContextV1) -> CellResultV1<&ResidentClosure> {
        let resident = self
            .residents
            .get(&expected.closure_id)
            .ok_or(CellErrorV1::Unavailable)?;
        resident.verify_expected(expected)?;
        Ok(resident)
    }

    fn check_slot(&self) -> CellResultV1<()> {
        require(
            self.residents.len() < self.config.max_resident_closures,
            "resident closure budget",
        )
    }

    /// Called only by the existing closure transport owner after every manifest
    /// has passed its first metadata pass and before any payload request. It
    /// reads bounded cached metadata and checks exact incremental RAM/reference
    /// needs without admitting residents, selecting a version or issuing use.
    pub(super) fn verify_prefetch_capacity(
        &self,
        store: &CellStoreV1,
        closure: &CellReleaseClosureV1,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<()> {
        checkpoint(deadline, cancelled)?;
        closure.verify_for_loader(expected)?;
        self.check_slot()?;
        self.cached_admission_plan(store, closure, expected, deadline, cancelled)?;
        checkpoint(deadline, cancelled)
    }

    fn cached_admission_plan(
        &self,
        store: &CellStoreV1,
        closure: &CellReleaseClosureV1,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CachedAdmissionPlan> {
        // Inspect every pinned manifest and the complete incremental reservation
        // before downloading or allocating weight payload. Metadata is bounded
        // by TCD1 and the manager's aggregate reference limit. The final staging
        // pass repeats this check; a cache mutation is never trusted by a plan.
        let mut manifests = Vec::with_capacity(closure.files().len());
        let mut missing = BTreeSet::new();
        let mut references = 0usize;
        let mut payload_bytes = 0u64;
        for file in closure.files() {
            checkpoint(deadline, cancelled)?;
            let manifest = store
                .manifest_with_deadline(file.manifest, Some(deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            closure.verify_manifest(&manifest)?;
            references = references
                .checked_add(manifest.chunks().len())
                .ok_or(CellErrorV1::Invalid("resident reference budget"))?;
            require(
                references <= self.config.max_chunk_references - self.usage.chunk_references
                    && references as u64 <= expected.max_chunks,
                "resident reference budget",
            )?;
            payload_bytes = payload_bytes
                .checked_add(manifest.size())
                .ok_or(CellErrorV1::Invalid("resident payload budget"))?;
            for chunk in manifest.chunks() {
                let key = ChunkKey {
                    digest: chunk.sha256,
                    size: chunk.size,
                };
                if !self.chunks.contains_key(&key) {
                    missing.insert(key);
                }
            }
            manifests.push(manifest);
        }
        let additional_bytes = missing.iter().try_fold(0u64, |total, chunk| {
            total
                .checked_add(u64::from(chunk.size))
                .ok_or(CellErrorV1::Invalid("resident byte budget"))
        })?;
        require(
            additional_bytes <= self.config.max_resident_bytes - self.usage.unique_payload_bytes,
            "resident byte budget",
        )?;
        require(
            payload_bytes <= expected.max_payload_bytes,
            "resident payload budget",
        )?;
        checkpoint(deadline, cancelled)?;
        Ok(CachedAdmissionPlan {
            manifests,
            missing,
            references,
            payload_bytes,
            additional_bytes,
        })
    }
}

fn checkpoint(deadline: Instant, cancelled: &AtomicBool) -> CellResultV1<()> {
    require(
        !cancelled.load(Ordering::Acquire),
        "resident operation cancelled",
    )?;
    require(Instant::now() < deadline, "resident operation deadline")
}

#[cfg(test)]
#[path = "residency_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "residency/budget_task_tests.rs"]
mod budget_task_tests;
