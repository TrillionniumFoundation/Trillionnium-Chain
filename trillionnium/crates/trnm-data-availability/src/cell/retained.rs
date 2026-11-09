//! Exact owner-pinned set of currently retained complete versions.
//!
//! A historical archive is not a composition. Each entry keeps its original
//! TCV1 model, router and environment. This finite observation does not create
//! a funded duty, select CURRENT, authorize GC, or establish a fresh owner view.

use std::{collections::BTreeMap, fmt, net::SocketAddr, sync::atomic::AtomicBool, time::Instant};

use sha2::{Digest, Sha512};

use super::{
    network::NetworkFetchSession, require, CellDigestV1, CellErrorV1, CellManifestV1,
    CellReleaseFetchOptionsV2, CellResultV1, CellStoreV1, CellVersionCommitmentV1,
    CellVersionLoaderContextV1, CellVersionManifestV1,
};

pub const MAX_CELL_RETAINED_VERSIONS_V1: usize = 16;
pub const MAX_CELL_RETAINED_SET_BYTES_V1: usize = 32 * 1024 * 1024;

/// Immutable original service window, inclusive start and exclusive end.
/// These supplied terms are not a native funding or durable catalog receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedVersionEntryV1 {
    pub version: CellVersionManifestV1,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
}

/// Canonical complete set selected by the retention owner, not by providers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedVersionSetV1 {
    epoch: u64,
    entries: Vec<CellRetainedVersionEntryV1>,
}

/// The real owner supplies current epoch, height and exact set commitment.
/// Replaying an old view is not detected by hashing it; anti-rollback custody
/// remains with that owner. The whole ordered owner roster must match the set.
pub struct CellRetainedSetOwnerV1<'a> {
    pub commitment: CellVersionCommitmentV1,
    pub epoch: u64,
    pub current_height: u64,
    /// Exclusive end of the interval the caller requires to remain promised.
    pub required_until_height: u64,
    pub versions: &'a [CellVersionLoaderContextV1<'a>],
}

/// Per-manifest references retain version identities; this is not a GC permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetainedObjectV1 {
    pub manifest: CellDigestV1,
    pub payload_bytes: u64,
    pub chunks: u64,
    pub versions: Vec<CellVersionCommitmentV1>,
}

/// Original finite read reservation. Failed reads do not refund admission.
/// It is in-process accounting, not the durable resource or payment owner.
#[derive(Debug)]
pub struct CellRetainedReadBudgetV1 {
    deadline: Instant,
    maximum_attempts: u32,
    maximum_manifests: u64,
    maximum_payload_bytes: u64,
    maximum_chunks: u64,
    usage: CellRetainedReadUsageV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellRetainedReadUsageV1 {
    pub attempts_committed: u32,
    pub manifests_committed: u64,
    pub payload_bytes_committed: u64,
    pub chunks_committed: u64,
}

impl CellRetainedReadBudgetV1 {
    pub fn new(
        deadline: Instant,
        maximum_attempts: u32,
        maximum_manifests: u64,
        maximum_payload_bytes: u64,
        maximum_chunks: u64,
    ) -> Self {
        Self {
            deadline,
            maximum_attempts,
            maximum_manifests,
            maximum_payload_bytes,
            maximum_chunks,
            usage: CellRetainedReadUsageV1::default(),
        }
    }

    pub fn usage(&self) -> CellRetainedReadUsageV1 {
        self.usage
    }

    fn reserve(&mut self, objects: &BTreeMap<CellDigestV1, &CellManifestV1>) -> CellResultV1<()> {
        check_deadline(self.deadline)?;
        let (bytes, chunks) = totals(objects)?;
        let usage = CellRetainedReadUsageV1 {
            attempts_committed: self
                .usage
                .attempts_committed
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("retained attempt overflow"))?,
            manifests_committed: self
                .usage
                .manifests_committed
                .checked_add(objects.len() as u64)
                .ok_or(CellErrorV1::Invalid("retained manifest overflow"))?,
            payload_bytes_committed: self
                .usage
                .payload_bytes_committed
                .checked_add(bytes)
                .ok_or(CellErrorV1::Invalid("retained byte overflow"))?,
            chunks_committed: self
                .usage
                .chunks_committed
                .checked_add(chunks)
                .ok_or(CellErrorV1::Invalid("retained chunk overflow"))?,
        };
        require(
            usage.attempts_committed <= self.maximum_attempts
                && usage.manifests_committed <= self.maximum_manifests
                && usage.payload_bytes_committed <= self.maximum_payload_bytes
                && usage.chunks_committed <= self.maximum_chunks,
            "retained original read reservation exhausted",
        )?;
        self.usage = usage;
        Ok(())
    }
}

/// Constructed only after actual complete-byte readback. This is a sequential
/// sample over [started, finished], not simultaneous uptime or future service.
#[derive(Debug)]
pub struct CellRetainedSetReadbackV1 {
    commitment: CellVersionCommitmentV1,
    epoch: u64,
    current_height: u64,
    versions: Vec<CellVersionCommitmentV1>,
    manifests: usize,
    payload_bytes: u64,
    chunks: u64,
    started: Instant,
    finished: Instant,
}

impl CellRetainedSetReadbackV1 {
    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        self.commitment
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn current_height(&self) -> u64 {
        self.current_height
    }
    pub fn versions(&self) -> &[CellVersionCommitmentV1] {
        &self.versions
    }
    pub fn manifests(&self) -> usize {
        self.manifests
    }
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
    pub fn chunks(&self) -> u64 {
        self.chunks
    }
    pub fn observation_window(&self) -> (Instant, Instant) {
        (self.started, self.finished)
    }
}

/// Transport usage also accompanies failure. Missing response accounting is
/// Unknown and can never be interpreted as zero network cost.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellRetainedFetchUsageV1 {
    pub connection_attempts: u64,
    pub request_attempts: u64,
    pub received_response_bytes: Option<u64>,
    /// Completed member calls only; bytes in a refused partial member remain
    /// charged by the session's response counter, not inferred from this count.
    pub completed_manifests: usize,
    pub downloaded_chunks: usize,
    pub cached_chunks: usize,
}

#[derive(Debug)]
pub struct CellRetainedFetchFailureV1 {
    pub error: CellErrorV1,
    pub usage: CellRetainedFetchUsageV1,
}

impl fmt::Display for CellRetainedFetchFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for CellRetainedFetchFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub struct CellRetainedFetchObservationV1 {
    readback: CellRetainedSetReadbackV1,
    usage: CellRetainedFetchUsageV1,
}

impl CellRetainedFetchObservationV1 {
    pub fn readback(&self) -> &CellRetainedSetReadbackV1 {
        &self.readback
    }
    pub fn usage(&self) -> CellRetainedFetchUsageV1 {
        self.usage
    }
    pub fn cache_only(&self) -> bool {
        self.usage.connection_attempts == 0
            && self.usage.request_attempts == 0
            && self.usage.received_response_bytes == Some(0)
    }
}

impl CellRetainedVersionSetV1 {
    /// Entries must be in strictly increasing complete-version commitment
    /// order. Neither duplicates nor an empty set can claim all-version success.
    pub fn new(epoch: u64, entries: Vec<CellRetainedVersionEntryV1>) -> CellResultV1<Self> {
        let value = Self { epoch, entries };
        value.validate()?;
        Ok(value)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn entries(&self) -> &[CellRetainedVersionEntryV1] {
        &self.entries
    }

    pub fn validate(&self) -> CellResultV1<()> {
        require(
            self.epoch > 0
                && !self.entries.is_empty()
                && self.entries.len() <= MAX_CELL_RETAINED_VERSIONS_V1,
            "retained set bounds",
        )?;
        let mut previous = None;
        let mut metadata_bytes = 0usize;
        for entry in &self.entries {
            entry.version.validate()?;
            let id = entry.version.commitment();
            require(
                previous.is_none_or(|old| old < id),
                "retained canonical versions",
            )?;
            previous = Some(id);
            require(
                entry.retain_from_height < entry.retain_until_height
                    && entry.retain_until_height <= i64::MAX as u64,
                "retained original interval",
            )?;
            metadata_bytes = metadata_bytes
                .checked_add(entry.version.encode().len())
                .ok_or(CellErrorV1::Invalid("retained metadata overflow"))?;
            require(
                metadata_bytes <= MAX_CELL_RETAINED_SET_BYTES_V1,
                "retained aggregate metadata bound",
            )?;
        }
        self.objects()?;
        Ok(())
    }

    /// Fresh domain: version commitments, original intervals and epoch. There
    /// is no reinterpretation of TCV1 or of existing signed/durable namespaces.
    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/RetainedVersions/v1\0");
        hash.update(self.epoch.to_be_bytes());
        hash.update((self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            hash.update(entry.version.commitment());
            hash.update(entry.retain_from_height.to_be_bytes());
            hash.update(entry.retain_until_height.to_be_bytes());
        }
        hash.finalize().into()
    }

    pub fn verify_for_owner(&self, owner: &CellRetainedSetOwnerV1<'_>) -> CellResultV1<()> {
        self.validate()?;
        require(
            self.commitment() == owner.commitment && self.epoch == owner.epoch,
            "retained current owner set/epoch",
        )?;
        require(
            owner.current_height < owner.required_until_height
                && owner.required_until_height <= i64::MAX as u64
                && owner.versions.len() == self.entries.len(),
            "retained exact owner roster/horizon",
        )?;
        for (entry, expected) in self.entries.iter().zip(owner.versions) {
            require(
                entry.retain_from_height <= owner.current_height
                    && owner.required_until_height <= entry.retain_until_height,
                "retained current promise window",
            )?;
            entry.version.verify_for_loader(expected)?;
        }
        Ok(())
    }

    /// Exact deduplicated object union, with the versions still referencing
    /// each object. A returned list never permits deleting a catalog root.
    pub fn referenced_objects(&self) -> CellResultV1<Vec<CellRetainedObjectV1>> {
        self.validate()?;
        let mut values: BTreeMap<_, CellRetainedObjectV1> = BTreeMap::new();
        for entry in &self.entries {
            let version = entry.version.commitment();
            for manifest in entry.version.manifests() {
                values
                    .entry(manifest.id())
                    .or_insert_with(|| CellRetainedObjectV1 {
                        manifest: manifest.id(),
                        payload_bytes: manifest.size(),
                        chunks: manifest.chunks().len() as u64,
                        versions: Vec::new(),
                    })
                    .versions
                    .push(version);
            }
        }
        Ok(values.into_values().collect())
    }

    pub fn verify_cached(
        &self,
        store: &CellStoreV1,
        owner: &CellRetainedSetOwnerV1<'_>,
        budget: &mut CellRetainedReadBudgetV1,
    ) -> CellResultV1<CellRetainedSetReadbackV1> {
        let started = Instant::now();
        check_deadline(budget.deadline)?;
        self.verify_for_owner(owner)?;
        let objects = self.objects()?;
        budget.reserve(&objects)?;
        self.readback(store, owner, &objects, budget.deadline, started)
    }

    fn objects(&self) -> CellResultV1<BTreeMap<CellDigestV1, &CellManifestV1>> {
        let mut objects = BTreeMap::new();
        for entry in &self.entries {
            for manifest in entry.version.manifests() {
                if let Some(previous) = objects.insert(manifest.id(), manifest) {
                    require(previous == manifest, "retained shared manifest changed")?;
                }
            }
        }
        totals(&objects)?;
        Ok(objects)
    }

    fn readback(
        &self,
        store: &CellStoreV1,
        owner: &CellRetainedSetOwnerV1<'_>,
        objects: &BTreeMap<CellDigestV1, &CellManifestV1>,
        deadline: Instant,
        started: Instant,
    ) -> CellResultV1<CellRetainedSetReadbackV1> {
        for (id, expected) in objects {
            check_deadline(deadline)?;
            let actual = store
                .manifest_with_deadline(*id, Some(deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            require(actual == **expected, "retained actual manifest")?;
            store.verify_complete_until(&actual, deadline)?;
        }
        let (payload_bytes, chunks) = totals(objects)?;
        let report = CellRetainedSetReadbackV1 {
            commitment: self.commitment(),
            epoch: self.epoch,
            current_height: owner.current_height,
            versions: self
                .entries
                .iter()
                .map(|e| e.version.commitment())
                .collect(),
            manifests: objects.len(),
            payload_bytes,
            chunks,
            started,
            finished: Instant::now(),
        };
        check_deadline(deadline)?;
        Ok(report)
    }
}

/// Recover the exact retained set through one original network session. The
/// complete owner roster and aggregate unique-object budget are admitted before
/// any cache/network effect; every version shares connections, frames, rejected
/// responses, deadline and cancellation. Warm cache bytes are reported as such.
pub fn fetch_retained_version_set(
    store: &CellStoreV1,
    retained: &CellRetainedVersionSetV1,
    owner: &CellRetainedSetOwnerV1<'_>,
    peers: &[SocketAddr],
    options: CellReleaseFetchOptionsV2,
    cancelled: Option<&AtomicBool>,
) -> Result<CellRetainedFetchObservationV1, CellRetainedFetchFailureV1> {
    let started = Instant::now();
    let mut usage = CellRetainedFetchUsageV1 {
        received_response_bytes: Some(0),
        ..CellRetainedFetchUsageV1::default()
    };
    let preflight = (|| {
        options.validate()?;
        let deadline = options
            .limits
            .release
            .deadline
            .min(started + options.limits.peer.overall_timeout);
        check_deadline(deadline)?;
        retained.verify_for_owner(owner)?;
        let objects = retained.objects()?;
        for manifest in objects.values() {
            require(
                manifest.size() <= options.limits.peer.max_cell_bytes,
                "cell exceeds byte budget",
            )?;
        }
        let (bytes, chunks) = totals(&objects)?;
        require(
            bytes <= options.limits.release.max_payload_bytes
                && chunks <= options.limits.release.max_chunks,
            "retained aggregate fetch budget",
        )?;
        let session = NetworkFetchSession::new(
            peers,
            options.limits.peer,
            options.transport,
            deadline,
            cancelled,
        )?;
        Ok::<_, CellErrorV1>((objects, deadline, session))
    })();
    let (objects, deadline, session) = match preflight {
        Ok(value) => value,
        Err(error) => return Err(CellRetainedFetchFailureV1 { error, usage }),
    };
    let result = (|| {
        // Complete metadata preflight before fetching any payload; all original
        // contexts stay attached to their own TCV1 rather than being unioned.
        for (id, expected) in &objects {
            session.check_cancelled()?;
            check_deadline(deadline)?;
            let (actual, _) = session.manifest(store, *id)?;
            require(actual == **expected, "retained fetched manifest")?;
        }
        for id in objects.keys() {
            session.check_cancelled()?;
            check_deadline(deadline)?;
            let (_, member) = session.cell(store, *id)?;
            usage.completed_manifests += 1;
            usage.downloaded_chunks += member.downloaded_chunks;
            usage.cached_chunks += member.cached_chunks;
        }
        let readback = retained.readback(store, owner, &objects, deadline, started)?;
        session.check_cancelled()?;
        check_deadline(deadline)?;
        Ok(readback)
    })();
    usage.connection_attempts = session.connection_attempts();
    usage.request_attempts = session.request_attempts();
    usage.received_response_bytes = session.received_response_bytes().ok();
    match result {
        Ok(readback) if usage.received_response_bytes.is_some() => {
            if let Err(error) = session
                .check_cancelled()
                .and_then(|()| check_deadline(deadline))
            {
                return Err(CellRetainedFetchFailureV1 { error, usage });
            }
            Ok(CellRetainedFetchObservationV1 { readback, usage })
        }
        Ok(_) => Err(CellRetainedFetchFailureV1 {
            error: CellErrorV1::Invalid("retained response accounting unavailable"),
            usage,
        }),
        Err(error) => Err(CellRetainedFetchFailureV1 { error, usage }),
    }
}

fn totals(objects: &BTreeMap<CellDigestV1, &CellManifestV1>) -> CellResultV1<(u64, u64)> {
    objects
        .values()
        .try_fold((0u64, 0u64), |(bytes, chunks), object| {
            Ok((
                bytes
                    .checked_add(object.size())
                    .ok_or(CellErrorV1::Invalid("retained byte overflow"))?,
                chunks
                    .checked_add(object.chunks().len() as u64)
                    .ok_or(CellErrorV1::Invalid("retained chunk overflow"))?,
            ))
        })
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "retained original deadline")
}

#[cfg(test)]
mod tests;
