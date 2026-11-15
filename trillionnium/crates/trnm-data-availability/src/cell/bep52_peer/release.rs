//! One complete-version BEP52 reservation. V1's constructor is unchanged.
//! The V2 owner admits a separately bounded release workload, then retains one
//! accounting/cancellation/refusal owner across every member and retry.

use super::*;
use crate::cell::{
    fetch_cell_bep52_storage_v2, CellBep52StorageBindingV2, CellBep52StorageFetchReportV2,
    CellBep52StorageSeedV2, CellReleaseLimitsV1, CellVersionLoaderContextV1, CellVersionManifestV1,
    CellVersionReadbackV1,
};

pub const CELL_BEP52_RELEASE_PROFILE_V2: &str = "cell-bep52-complete-release-tcp-v2";
pub const MAX_CELL_BEP52_RELEASE_PAYLOAD_V2: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_CELL_BEP52_RELEASE_CHUNKS_V2: u64 = 4096;
const MAX_CONNECTIONS: u64 = 1024;
const MAX_MESSAGES: u64 = 8_500_000;
const MAX_WIRE_BYTES: u64 = 2 * MAX_CELL_BEP52_RELEASE_PAYLOAD_V2 + 64 * 1024 * 1024;

/// The actual complete TCV1 union plus every storage-to-BEP52 mapping.
/// The owner obtains the returned commitment independently of a peer's hints.
/// Possession of this data does not grant selection, funding or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52ReleasePlanV2 {
    version: CellVersionManifestV1,
    bindings: Vec<CellBep52StorageBindingV2>,
    payload_bytes: u64,
    chunks: u64,
}

impl CellBep52ReleasePlanV2 {
    pub fn new(
        version: CellVersionManifestV1,
        expected: &CellVersionLoaderContextV1<'_>,
        mut bindings: Vec<CellBep52StorageBindingV2>,
    ) -> CellResultV1<Self> {
        version.verify_for_loader(expected)?;
        require(
            bindings.len() == version.manifests().len(),
            "BEP52 release complete member count",
        )?;
        bindings.sort_by_key(CellBep52StorageBindingV2::manifest_id);
        let mut payload_bytes = 0u64;
        let mut chunks = 0u64;
        for (manifest, binding) in version.manifests().iter().zip(&bindings) {
            require(
                manifest == binding.manifest(),
                "BEP52 release exact canonical membership",
            )?;
            payload_bytes = payload_bytes
                .checked_add(manifest.size())
                .ok_or(CellErrorV1::Invalid("BEP52 release payload overflow"))?;
            chunks = chunks
                .checked_add(manifest.chunks().len() as u64)
                .ok_or(CellErrorV1::Invalid("BEP52 release chunk overflow"))?;
        }
        require(
            payload_bytes <= MAX_CELL_BEP52_RELEASE_PAYLOAD_V2
                && chunks <= MAX_CELL_BEP52_RELEASE_CHUNKS_V2,
            "BEP52 complete release profile bound",
        )?;
        Ok(Self {
            version,
            bindings,
            payload_bytes,
            chunks,
        })
    }

    pub fn version(&self) -> &CellVersionManifestV1 {
        &self.version
    }
    pub fn bindings(&self) -> &[CellBep52StorageBindingV2] {
        &self.bindings
    }
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Binds the complete immutable version and the mapping/infohash for every
    /// canonical member. Inner TCM1 hashes retain their existing meaning.
    pub fn commitment(&self) -> [u8; 64] {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/Bep52CompleteRelease/v2\0");
        hash.update(self.version.commitment());
        hash.update((self.bindings.len() as u32).to_be_bytes());
        for binding in &self.bindings {
            hash.update(binding.manifest_id());
            hash.update(binding.mapping_id());
            hash.update(binding.info_hash());
        }
        hash.finalize().into()
    }
}

/// Explicit V2 workload admission, not an increase to the V1 profile.
/// Wire bytes include rejected/partial data; TCP/IP overhead is not counted.
#[derive(Clone, Copy, Debug)]
pub struct CellBep52ReleaseLimitsV2 {
    pub deadline: Instant,
    pub request_timeout: Duration,
    pub max_connections: u64,
    pub max_received_bytes: u64,
    pub max_sent_bytes: u64,
    pub max_messages: u64,
    /// Shared across final complete-byte readbacks, including failed attempts.
    pub max_readback_bytes: u64,
    pub max_readback_chunks: u64,
    pub max_readback_attempts: u64,
}

impl CellBep52ReleaseLimitsV2 {
    fn validate(&self) -> CellResultV1<()> {
        let now = Instant::now();
        require(
            self.deadline > now && self.deadline.duration_since(now) <= Duration::from_secs(86_400),
            "BEP52 release original deadline",
        )?;
        require(
            (Duration::from_millis(10)..=Duration::from_secs(30)).contains(&self.request_timeout)
                && (1..=MAX_CONNECTIONS).contains(&self.max_connections)
                && (1..=MAX_MESSAGES).contains(&self.max_messages)
                && (1..=MAX_WIRE_BYTES).contains(&self.max_received_bytes)
                && (1..=MAX_WIRE_BYTES).contains(&self.max_sent_bytes),
            "BEP52 release transport reservation",
        )?;
        require(
            (1..=8).contains(&self.max_readback_attempts)
                && self.max_readback_bytes <= 8 * MAX_CELL_BEP52_RELEASE_PAYLOAD_V2
                && self.max_readback_chunks <= 8 * MAX_CELL_BEP52_RELEASE_CHUNKS_V2,
            "BEP52 release readback reservation",
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellBep52ReleaseReadUsageV2 {
    pub reserved_bytes: u64,
    pub reserved_chunks: u64,
    pub attempts: u64,
    pub completed: u64,
}

/// Non-cloneable owner. No member call or error path resets its absolute
/// deadline, attempts, socket counters, refusals, or cancellation latch.
pub struct CellBep52ReleaseSessionV2<'a> {
    plan: &'a CellBep52ReleasePlanV2,
    commitment: [u8; 64],
    limits: CellBep52ReleaseLimitsV2,
    session: CellBep52PeerSessionV1,
    readback: CellBep52ReleaseReadUsageV2,
}

impl<'a> CellBep52ReleaseSessionV2<'a> {
    pub fn new(
        operation: CellDigestV1,
        plan: &'a CellBep52ReleasePlanV2,
        expected_plan: [u8; 64],
        expected: &CellVersionLoaderContextV1<'_>,
        limits: CellBep52ReleaseLimitsV2,
    ) -> CellResultV1<Self> {
        require(operation != [0; 32], "BEP52 release operation")?;
        plan.version.verify_for_loader(expected)?;
        require(
            plan.commitment() == expected_plan,
            "BEP52 release independent mapping pin",
        )?;
        limits.validate()?;
        require(
            limits.max_readback_bytes >= plan.payload_bytes
                && limits.max_readback_chunks >= plan.chunks,
            "BEP52 release complete readback admission",
        )?;
        // These limits were admitted by the explicit V2 profile above. The
        // shared I/O accounting engine has no per-file allocation or reset.
        // Public CellBep52PeerSessionV1::new still enforces its original caps.
        let session = CellBep52PeerSessionV1 {
            operation_id: operation,
            limits: CellBep52PeerLimitsV1 {
                deadline: limits.deadline,
                request_timeout: limits.request_timeout,
                max_connections: limits.max_connections,
                max_received_bytes: limits.max_received_bytes,
                max_sent_bytes: limits.max_sent_bytes,
                max_messages: limits.max_messages,
            },
            usage: CellBep52PeerUsageV1::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            cancellation_latched: false,
            refused: BTreeSet::new(),
            refusals: Vec::new(),
            dht_transactions: BTreeSet::new(),
        };
        Ok(Self {
            plan,
            commitment: expected_plan,
            limits,
            session,
            readback: CellBep52ReleaseReadUsageV2::default(),
        })
    }

    pub fn usage(&self) -> &CellBep52PeerUsageV1 {
        self.session.usage()
    }
    pub fn readback_usage(&self) -> &CellBep52ReleaseReadUsageV2 {
        &self.readback
    }
    pub fn operation_id(&self) -> CellDigestV1 {
        self.session.operation_id()
    }
    pub fn deadline(&self) -> Instant {
        self.limits.deadline
    }
    pub fn cancellation_handle(&self) -> Arc<AtomicBool> {
        self.session.cancellation_handle()
    }
    pub fn refusals(&self) -> &[(SocketAddr, String)] {
        self.session.refusals()
    }

    fn current(
        &mut self,
        pin: [u8; 64],
        expected: &CellVersionLoaderContextV1<'_>,
    ) -> CellResultV1<()> {
        self.session.check(self.limits.deadline)?;
        require(pin == self.commitment, "BEP52 release current plan pin")?;
        self.plan.version.verify_for_loader(expected)
    }

    pub fn fetch_member(
        &mut self,
        store: &CellStoreV1,
        index: usize,
        expected_plan: [u8; 64],
        expected: &CellVersionLoaderContextV1<'_>,
        peers: &[SocketAddr],
        local_peer_id: [u8; 20],
    ) -> CellResultV1<CellBep52StorageFetchReportV2> {
        self.current(expected_plan, expected)?;
        let binding = self
            .plan
            .bindings
            .get(index)
            .ok_or(CellErrorV1::Invalid("BEP52 release member index"))?;
        fetch_cell_bep52_storage_v2(store, binding, peers, local_peer_id, &mut self.session)
    }

    /// Caller owns and selects each accepted socket; no listener is created.
    /// Its connection reservation precedes source preparation and is retained
    /// when that preparation fails. Source reads are not network-byte counters.
    pub fn serve_member(
        &mut self,
        store: &CellStoreV1,
        index: usize,
        expected_plan: [u8; 64],
        expected: &CellVersionLoaderContextV1<'_>,
        stream: TcpStream,
        local_peer_id: [u8; 20],
    ) -> CellResultV1<()> {
        self.current(expected_plan, expected)?;
        let binding = self
            .plan
            .bindings
            .get(index)
            .ok_or(CellErrorV1::Invalid("BEP52 release member index"))?;
        self.session.connection()?;
        let seed = match CellBep52StorageSeedV2::prepare(
            store,
            binding,
            CellReleaseLimitsV1 {
                max_payload_bytes: binding.manifest().size(),
                max_chunks: binding.manifest().chunks().len() as u64,
                deadline: self.limits.deadline,
            },
        ) {
            Ok(seed) => seed,
            Err(error) => {
                self.session
                    .record_connection_refusal(stream.peer_addr().ok(), &error);
                return Err(error);
            }
        };
        seed.serve_admitted_connection(stream, local_peer_id, &mut self.session)
    }

    /// Final observation re-reads all actual original chunks, after reserving
    /// the complete cost once. Failed/partial observations retain that charge.
    /// It observes content; it does not replace the later typed loader owner.
    pub fn verify_complete(
        &mut self,
        store: &CellStoreV1,
        expected_plan: [u8; 64],
        expected: &CellVersionLoaderContextV1<'_>,
    ) -> CellResultV1<CellVersionReadbackV1> {
        self.current(expected_plan, expected)?;
        require(
            self.readback.attempts < self.limits.max_readback_attempts
                && self.plan.payload_bytes
                    <= self.limits.max_readback_bytes - self.readback.reserved_bytes
                && self.plan.chunks
                    <= self.limits.max_readback_chunks - self.readback.reserved_chunks,
            "BEP52 release remaining full readback budget",
        )?;
        self.readback.attempts += 1;
        self.readback.reserved_bytes += self.plan.payload_bytes;
        self.readback.reserved_chunks += self.plan.chunks;
        for binding in &self.plan.bindings {
            self.session.check(self.limits.deadline)?;
            let declared = binding.manifest();
            let actual = store
                .manifest_with_deadline(declared.id(), Some(self.limits.deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            require(actual == *declared, "BEP52 release actual manifest")?;
            let mut full = Sha256::new();
            for (index, chunk) in declared.chunks().iter().enumerate() {
                self.session.check(self.limits.deadline)?;
                let bytes = store
                    .chunk_with_deadline(chunk.sha256, Some(self.limits.deadline))?
                    .ok_or(CellErrorV1::Unavailable)?;
                binding.verify_storage_chunk(index as u32, &bytes)?;
                full.update(&bytes);
                self.session.check(self.limits.deadline)?;
            }
            require(
                <[u8; 32]>::from(full.finalize()) == declared.payload_sha256(),
                "BEP52 release full payload hash",
            )?;
        }
        self.current(expected_plan, expected)?;
        self.readback.completed += 1;
        Ok(CellVersionReadbackV1 {
            commitment: self.plan.version.commitment(),
            model_root: self.plan.version.model().id(),
            environment_closure: self.plan.version.environment().id(),
            manifests: self.plan.bindings.len(),
            payload_bytes: self.plan.payload_bytes,
            chunks: self.plan.chunks,
        })
    }
}

#[cfg(test)]
mod tests;
