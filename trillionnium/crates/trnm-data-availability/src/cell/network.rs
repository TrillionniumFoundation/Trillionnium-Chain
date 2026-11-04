use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    manifest::MAX_MANIFEST_BYTES,
    require,
    store::{verify_chunk_length, verify_chunk_with_deadline, MAX_CHUNK_COMMIT_BATCH},
    CellChunkV1, CellDigestV1, CellErrorV1, CellManifestV1, CellResultV1, CellStoreV1,
    MAX_CELL_BYTES, MAX_CHUNK_BYTES,
};

mod availability;
mod persistent;
mod serving;
pub use persistent::{
    fetch_cell_persistent, fetch_cell_persistent_to_file, serve_cells_persistent,
    CellPersistentFetchReportV2, CellPersistentPeerLimitsV2, CellPersistentServeLimitsV2,
    CellPersistentServeReportV2,
};
pub use serving::{
    serve_cells_bounded, serve_cells_bounded_with_availability, CellServeLimitsV1,
    CellServeReportV1,
};

/// Explicit finite limits for this configured-peer pilot. There is no peer
/// discovery, authority from advertisements, or unbounded retry queue.
#[derive(Clone, Copy, Debug)]
pub struct CellPeerLimitsV1 {
    pub request_timeout: Duration,
    pub overall_timeout: Duration,
    pub max_cell_bytes: u64,
    pub parallelism: usize,
    pub max_connections: u64,
    /// Application response bytes actually read across all peers and retries,
    /// including headers and rejected bodies. Zero permits cache-only fetches.
    pub max_response_bytes: u64,
}

impl CellPeerLimitsV1 {
    /// Finite CLI default: two payloads, two maximum manifests and one response
    /// header per permitted connection. Callers may select a different budget.
    pub fn default_response_byte_budget(
        max_cell_bytes: u64,
        max_connections: u64,
    ) -> CellResultV1<u64> {
        require(
            (1..=MAX_CELL_BYTES).contains(&max_cell_bytes),
            "cell byte budget",
        )?;
        require(
            (1..=100_000).contains(&max_connections),
            "connection budget",
        )?;
        max_cell_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * MAX_MANIFEST_BYTES as u64))
            .and_then(|bytes| {
                max_connections
                    .checked_mul(9)
                    .and_then(|headers| bytes.checked_add(headers))
            })
            .ok_or(CellErrorV1::Invalid("response byte budget overflow"))
    }

    /// Check the existing finite bounds before an explicit caller opens local
    /// stores. This does not start or renew any network session or deadline.
    pub fn validate(self) -> CellResultV1<()> {
        require(
            self.request_timeout >= Duration::from_millis(10)
                && self.request_timeout <= Duration::from_secs(30),
            "request deadline",
        )?;
        require(
            self.overall_timeout >= self.request_timeout
                && self.overall_timeout <= Duration::from_secs(86_400),
            "overall deadline",
        )?;
        require(
            (1..=MAX_CELL_BYTES).contains(&self.max_cell_bytes),
            "cell byte budget",
        )?;
        require((1..=4).contains(&self.parallelism), "parallelism")?;
        require(
            (1..=100_000).contains(&self.max_connections),
            "connection budget",
        )?;
        require(
            self.max_response_bytes
                <= 8 * MAX_CELL_BYTES + 8 * MAX_MANIFEST_BYTES as u64 + 9 * 100_000,
            "response byte budget",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellFetchReportV1 {
    pub manifest_id: CellDigestV1,
    pub payload_sha256: CellDigestV1,
    pub payload_bytes: u64,
    /// Manifest positions satisfied by verified content in the initial cache.
    pub cached_chunks: usize,
    /// Manifest positions covered by downloaded and committed content. Repeated
    /// positions reuse one object without a second request; this count retains
    /// the existing cached_chunks + downloaded_chunks == payload positions rule.
    pub downloaded_chunks: usize,
    /// Bytes of those verified, committed objects, counted once per digest.
    /// The ordered payload may be larger when it repeats a shared chunk.
    pub downloaded_bytes: u64,
    /// Actual application response bytes read, even when subsequently rejected.
    /// Excludes requests, TCP/IP overhead, retransmissions and unread socket data.
    pub received_response_bytes: u64,
    pub connection_attempts: u64,
    /// Failed attempts, including transient transport refusals. This is not a
    /// cryptographic fraud finding or a custody/reward decision.
    pub rejected_responses: usize,
    pub supplying_peers: BTreeSet<SocketAddr>,
}

/// Retrieve an authority-pinned manifest and repair missing/corrupt chunks.
/// Success includes a fresh ordered full-payload hash check of the cache.
pub fn fetch_cell(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    fetch_cell_inner(store, pinned, peers, limits, None, false)
}

/// Explicit TCI1/TIS1 availability hints followed by rarest-observed-first
/// scheduling in the same downloader. Hints confer no byte integrity or use
/// authority; every chunk and the full ordered payload are still verified.
/// Probes, failed replies and payloads consume one original reservation.
pub fn fetch_cell_rarest_first(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    fetch_cell_inner(store, pinned, peers, limits, None, true)
}

/// Fetch, verify and create-only publish using one original absolute deadline.
/// Checks are cooperative: blocking filesystem calls cannot be preempted. The
/// last deadline check precedes the no-replace hard link; directory durability
/// and cleanup finish after publication without removing the complete output.
pub fn fetch_cell_to_file(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    fetch_cell_inner(store, pinned, peers, limits, Some(output), false)
}

/// The explicit availability profile with the original create-only materializer.
pub fn fetch_cell_rarest_first_to_file(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    fetch_cell_inner(store, pinned, peers, limits, Some(output), true)
}

fn fetch_cell_inner(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    output: Option<&Path>,
    rarest_first: bool,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    limits.validate()?;
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "configured peer count/duplicates",
    )?;
    let deadline = Instant::now() + limits.overall_timeout;
    #[cfg(test)]
    super::tests::observe_fetch_deadline(deadline);
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.request_timeout,
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
    };
    fetch_cell_with_schedule(
        store,
        pinned,
        peers,
        limits,
        &transport,
        output,
        FetchSchedule {
            rarest_first,
            requests: None,
        },
    )
}

/// Reuse the caller's original connection, response-byte and time reservation.
/// Only this module's single-cell wrapper or the release fetcher may create it.
pub(super) fn fetch_cell_in_session(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    transport: &RequestContext<'_>,
    output: Option<&Path>,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    fetch_cell_with_schedule(
        store,
        pinned,
        peers,
        limits,
        transport,
        output,
        FetchSchedule {
            rarest_first: false,
            requests: None,
        },
    )
}

// Each explicit transport reuses the same cache validation, bounded commit
// batches and complete ordered payload verification. Only object requests differ.
trait ObjectRequests: Sync {
    fn request(
        &self,
        peer: SocketAddr,
        kind: u8,
        digest: CellDigestV1,
        maximum: usize,
        transport: &RequestContext<'_>,
    ) -> (CellResultV1<Vec<u8>>, usize);
}

struct SingleRequestV1;

impl ObjectRequests for SingleRequestV1 {
    fn request(
        &self,
        peer: SocketAddr,
        kind: u8,
        digest: CellDigestV1,
        maximum: usize,
        transport: &RequestContext<'_>,
    ) -> (CellResultV1<Vec<u8>>, usize) {
        request_with_retry(peer, kind, digest, maximum, transport)
    }
}

struct FetchSchedule<'a> {
    rarest_first: bool,
    requests: Option<&'a dyn ObjectRequests>,
}

/// Explicit acquisition strategy. The variants cannot silently combine an
/// unsupported inventory protocol with persistent V2 framing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CellFetchTransportV2 {
    #[default]
    OrderedV1,
    RarestFirstV1,
    PersistentV2 {
        max_requests: u64,
        max_requests_per_connection: u64,
    },
}

impl CellFetchTransportV2 {
    pub fn validate(self, peer: CellPeerLimitsV1) -> CellResultV1<()> {
        peer.validate()?;
        if let Self::PersistentV2 {
            max_requests,
            max_requests_per_connection,
        } = self
        {
            CellPersistentPeerLimitsV2 {
                peer,
                max_requests,
                max_requests_per_connection,
            }
            .validate()?;
        }
        Ok(())
    }
}

/// One owned reservation and connection pool for an entire release closure.
/// Member calls borrow this state; they cannot renew any counter or deadline.
pub(super) struct NetworkFetchSession {
    peers: Vec<SocketAddr>,
    limits: CellPeerLimitsV1,
    profile: CellFetchTransportV2,
    deadline: Instant,
    connections_left: AtomicU64,
    responses: ResponseBudget,
    pool: Option<persistent::ConnectionPool>,
}

impl NetworkFetchSession {
    pub(super) fn new(
        peers: &[SocketAddr],
        limits: CellPeerLimitsV1,
        profile: CellFetchTransportV2,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        profile.validate(limits)?;
        require(
            peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
            "configured peer count/duplicates",
        )?;
        remaining(deadline)?;
        let pool = match profile {
            CellFetchTransportV2::PersistentV2 {
                max_requests,
                max_requests_per_connection,
            } => Some(persistent::ConnectionPool::new(
                peers,
                CellPersistentPeerLimitsV2 {
                    peer: limits,
                    max_requests,
                    max_requests_per_connection,
                },
            )),
            _ => None,
        };
        Ok(Self {
            peers: peers.to_vec(),
            limits,
            profile,
            deadline,
            connections_left: AtomicU64::new(limits.max_connections),
            responses: ResponseBudget::new(limits.max_response_bytes),
            pool,
        })
    }

    fn context(&self) -> RequestContext<'_> {
        RequestContext {
            timeout: self.limits.request_timeout,
            overall: self.deadline,
            requests_left: &self.connections_left,
            responses: &self.responses,
        }
    }

    pub(super) fn manifest(
        &self,
        store: &CellStoreV1,
        pinned: CellDigestV1,
    ) -> CellResultV1<(CellManifestV1, usize)> {
        let transport = self.context();
        match &self.pool {
            Some(pool) => {
                let (manifest, rejected, _) =
                    fetch_manifest_via(store, pinned, &self.peers, self.limits, &transport, pool)?;
                Ok((manifest, rejected))
            }
            None => fetch_manifest(store, pinned, &self.peers, self.limits, &transport),
        }
    }

    pub(super) fn cell(
        &self,
        store: &CellStoreV1,
        pinned: CellDigestV1,
    ) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
        fetch_cell_with_schedule(
            store,
            pinned,
            &self.peers,
            self.limits,
            &self.context(),
            None,
            FetchSchedule {
                rarest_first: self.profile == CellFetchTransportV2::RarestFirstV1,
                requests: self.pool.as_ref().map(|pool| pool as &dyn ObjectRequests),
            },
        )
    }

    pub(super) fn connection_attempts(&self) -> u64 {
        self.limits.max_connections - self.connections_left.load(Ordering::Relaxed)
    }

    pub(super) fn request_attempts(&self) -> u64 {
        match (&self.pool, self.profile) {
            (Some(pool), CellFetchTransportV2::PersistentV2 { max_requests, .. }) => {
                max_requests - pool.requests_left.load(Ordering::Relaxed)
            }
            _ => self.connection_attempts(),
        }
    }

    pub(super) fn received_response_bytes(&self) -> CellResultV1<u64> {
        Ok(self.responses.received()?)
    }
}

fn fetch_cell_with_schedule(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    transport: &RequestContext<'_>,
    output: Option<&Path>,
    schedule: FetchSchedule<'_>,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    let deadline = transport.overall;
    let requests_left = transport.requests_left;
    let responses = transport.responses;
    let (manifest, rejected) = match schedule.requests {
        Some(requests) => {
            let (manifest, rejected, _) =
                fetch_manifest_via(store, pinned, peers, limits, transport, requests)?;
            (manifest, rejected)
        }
        None => fetch_manifest(store, pinned, peers, limits, transport)?,
    };
    let mut missing = Vec::new();
    let mut report = CellFetchReportV1 {
        manifest_id: pinned,
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        cached_chunks: 0,
        downloaded_chunks: 0,
        downloaded_bytes: 0,
        received_response_bytes: 0,
        connection_attempts: 0,
        rejected_responses: rejected,
        supplying_peers: BTreeSet::new(),
    };
    // The manifest remains an ordered list of payload positions. The bounded
    // work queue contains each missing content object once, so repeated chunks
    // neither multiply TCP requests nor spend response bytes a second time.
    // Remember the validated length as well: equal hashes with conflicting
    // declared lengths must not be hidden by the deduplication.
    let mut seen: BTreeMap<CellDigestV1, (u32, bool, usize)> = BTreeMap::new();
    for (index, expected) in manifest.chunks().iter().enumerate() {
        require(Instant::now() <= deadline, "cache scan deadline")?;
        if let Some((size, cached, positions)) = seen.get_mut(&expected.sha256) {
            require(*size == expected.size, "chunk digest length conflict")?;
            report.cached_chunks += usize::from(*cached);
            *positions += 1;
            continue;
        }
        match store.chunk_with_deadline(expected.sha256, Some(deadline))? {
            Some(bytes) => {
                // chunk() already hashes the actual cache buffer on every read.
                verify_chunk_length(expected, &bytes)?;
                report.cached_chunks += 1;
                seen.insert(expected.sha256, (expected.size, true, 1));
            }
            None => {
                seen.insert(expected.sha256, (expected.size, false, 1));
                missing.push((index, expected.clone()));
            }
        }
    }
    let availability = if schedule.rarest_first && !missing.is_empty() {
        let (available, rejected) = availability::observe(&manifest, &missing, peers, transport)?;
        report.rejected_responses += rejected;
        // An unavailable/stale hint cannot prevent an ordinary fallback fetch.
        // Unknown chunks run after positively observed chunks, in stable order.
        missing.sort_by_key(|(index, _)| {
            let copies = available[*index].count_ones();
            (if copies == 0 { u32::MAX } else { copies }, *index)
        });
        Some(available)
    } else {
        None
    };
    let next = AtomicUsize::new(0);
    let cancelled = AtomicBool::new(false);
    thread::scope(|scope| -> CellResultV1<()> {
        let (sender, receiver) = mpsc::sync_channel(limits.parallelism);
        for _ in 0..limits.parallelism.min(missing.len()) {
            let sender = sender.clone();
            let missing = &missing;
            let next = &next;
            let cancelled = &cancelled;
            let availability = availability.as_deref();
            let requests = schedule.requests;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((order, chunk)) = missing.get(index) else {
                        break;
                    };
                    let preferred = availability.map(|available| available[*order]).unwrap_or(0);
                    let result = match requests {
                        Some(requests) => {
                            download_chunk_via(chunk, *order, peers, transport, preferred, requests)
                        }
                        None if preferred == 0 => download_chunk(chunk, *order, peers, transport),
                        None => {
                            download_chunk_preferred(chunk, *order, peers, transport, preferred)
                        }
                    };
                    if sender.send((chunk, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        let mut failure = None;
        let mut pending: Vec<(&CellChunkV1, Vec<u8>, SocketAddr, usize)> =
            Vec::with_capacity(MAX_CHUNK_COMMIT_BATCH);
        let mut flush = |pending: &mut Vec<(&CellChunkV1, Vec<u8>, SocketAddr, usize)>| {
            require(Instant::now() <= deadline, "chunk persistence deadline")?;
            let chunks: Vec<_> = pending
                .iter()
                .map(|(chunk, bytes, _, _)| (*chunk, bytes.as_slice()))
                .collect();
            store.put_chunk_batch_with_deadline(&chunks, Some(deadline))?;
            for (chunk, bytes, peer, rejected) in pending.drain(..) {
                report.downloaded_bytes += bytes.len() as u64;
                report.downloaded_chunks += seen[&chunk.sha256].2;
                report.rejected_responses += rejected;
                report.supplying_peers.insert(peer);
            }
            require(Instant::now() <= deadline, "chunk persistence deadline")
        };
        for (chunk, result) in receiver {
            let written = match result {
                Ok((bytes, peer, rejected)) => {
                    pending.push((chunk, bytes, peer, rejected));
                    if pending.len() == MAX_CHUNK_COMMIT_BATCH {
                        flush(&mut pending)
                    } else {
                        Ok(())
                    }
                }
                Err(error) => Err(error),
            };
            if let Err(error) = written {
                cancelled.store(true, Ordering::Relaxed);
                failure.get_or_insert(error);
            }
            // Failed batches must not accumulate beyond the fixed memory cap.
            if pending.len() == MAX_CHUNK_COMMIT_BATCH {
                pending.clear();
            }
        }
        if !pending.is_empty() {
            // Keep the final verified prefix on a connection/byte-budget error
            // too, while respecting the original absolute time bound.
            if let Err(error) = flush(&mut pending) {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })
    .map_err(|error| match error {
        // All workers have joined: keep the existing aggregate byte-budget
        // classification even if a different request failed slightly earlier.
        CellErrorV1::Io(error) => unavailable_with_transport_cause(transport, Some(error)),
        error => responses.annotate_error(error),
    })?;
    require(Instant::now() <= deadline, "fetch deadline")?;
    if let Some(output) = output {
        // Materialization itself freshly hashes every cached chunk, verifies
        // the ordered full payload, syncs, and checks this same deadline before
        // create-only publication. A preceding sink pass duplicates that work.
        store.materialize_until(&manifest, output, deadline)?;
    } else {
        store.verify_complete_until(&manifest, deadline)?;
        require(Instant::now() <= deadline, "fetch deadline")?;
    }
    report.connection_attempts = limits.max_connections - requests_left.load(Ordering::Relaxed);
    report.received_response_bytes = responses.received()?;
    Ok((manifest, report))
}

pub(super) fn fetch_manifest(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    transport: &RequestContext<'_>,
) -> CellResultV1<(CellManifestV1, usize)> {
    let (manifest, rejected, _) = fetch_manifest_observed(store, pinned, peers, limits, transport)?;
    Ok((manifest, rejected))
}

// Capture the result of the actual first cache read, without a separate probe
// or additional network request. Existing callers retain their original API.
pub(super) fn fetch_manifest_observed(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    transport: &RequestContext<'_>,
) -> CellResultV1<(CellManifestV1, usize, bool)> {
    fetch_manifest_via(store, pinned, peers, limits, transport, &SingleRequestV1)
}

fn fetch_manifest_via(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    transport: &RequestContext<'_>,
    requests: &dyn ObjectRequests,
) -> CellResultV1<(CellManifestV1, usize, bool)> {
    let mut rejected = 0;
    let cached = store.manifest_with_deadline(pinned, Some(transport.overall))?;
    let (manifest, initial_cache_hit) = match cached {
        Some(manifest) => (manifest, true),
        None => {
            let mut received = None;
            let mut last_io = None;
            for peer in peers {
                if transport.responses.is_quarantined(*peer)? {
                    continue;
                }
                let (candidate, attempts) =
                    requests.request(*peer, 1, pinned, MAX_MANIFEST_BYTES, transport);
                rejected += attempts - 1;
                let candidate = candidate.and_then(|wire| {
                    remaining(transport.overall)?;
                    // A complete supplied object failed its pinned contract.
                    // This is distinct from missing bytes or interrupted I/O.
                    let manifest = CellManifestV1::decode(&wire).and_then(|manifest| {
                        require(manifest.id() == pinned, "manifest digest")?;
                        Ok(manifest)
                    });
                    let manifest = match manifest {
                        Ok(manifest) => manifest,
                        Err(error) => {
                            transport.responses.quarantine(*peer)?;
                            return Err(error);
                        }
                    };
                    remaining(transport.overall)?;
                    require(
                        manifest.size() <= limits.max_cell_bytes,
                        "cell exceeds byte budget",
                    )?;
                    Ok(wire)
                });
                match candidate {
                    Ok(wire) => {
                        // A valid response cannot turn a local persistence
                        // failure into peer unavailability or budget exhaustion.
                        received = Some(store.put_manifest_with_deadline(
                            pinned,
                            &wire,
                            Some(transport.overall),
                        )?);
                        break;
                    }
                    Err(error) => {
                        rejected += 1;
                        if let CellErrorV1::Io(error) = error {
                            last_io = Some(error);
                        }
                    }
                }
            }
            (
                received.ok_or_else(|| unavailable_with_transport_cause(transport, last_io))?,
                false,
            )
        }
    };
    require(
        manifest.size() <= limits.max_cell_bytes,
        "cell exceeds byte budget",
    )?;
    Ok((manifest, rejected, initial_cache_hit))
}

fn download_chunk(
    chunk: &CellChunkV1,
    order: usize,
    peers: &[SocketAddr],
    transport: &RequestContext<'_>,
) -> CellResultV1<(Vec<u8>, SocketAddr, usize)> {
    download_chunk_preferred(chunk, order, peers, transport, 0)
}

fn download_chunk_preferred(
    chunk: &CellChunkV1,
    order: usize,
    peers: &[SocketAddr],
    transport: &RequestContext<'_>,
    preferred: u8,
) -> CellResultV1<(Vec<u8>, SocketAddr, usize)> {
    download_chunk_via(chunk, order, peers, transport, preferred, &SingleRequestV1)
}

fn download_chunk_via(
    chunk: &CellChunkV1,
    order: usize,
    peers: &[SocketAddr],
    transport: &RequestContext<'_>,
    preferred: u8,
    requests: &dyn ObjectRequests,
) -> CellResultV1<(Vec<u8>, SocketAddr, usize)> {
    let mut last_io = None;
    let mut rejected = 0;
    let mut indices: Vec<_> = (0..peers.len())
        .map(|offset| (order + offset) % peers.len())
        .collect();
    indices.sort_by_key(|index| preferred & (1_u8 << *index) == 0);
    for index in indices {
        let peer = peers[index];
        if transport.responses.is_quarantined(peer)? {
            continue;
        }
        let (candidate, attempts) =
            requests.request(peer, 2, chunk.sha256, chunk.size as usize, transport);
        rejected += attempts - 1;
        let candidate = candidate.and_then(|bytes| {
            if let Err(error) = verify_chunk_with_deadline(chunk, &bytes, Some(transport.overall)) {
                // Local work expiry is not evidence that the peer supplied bad
                // bytes. Keep quarantine tied to the pinned chunk contract.
                if matches!(
                    &error,
                    CellErrorV1::Invalid("chunk length" | "chunk digest")
                ) {
                    transport.responses.quarantine(peer)?;
                }
                return Err(error);
            }
            Ok(bytes)
        });
        match candidate {
            Ok(bytes) => return Ok((bytes, peer, rejected)),
            Err(CellErrorV1::Io(error)) => last_io = Some(error),
            Err(_) => (),
        }
        rejected += 1;
    }
    Err(unavailable_with_transport_cause(transport, last_io))
}

// Keep the existing unavailable/byte-budget semantics for absent or malformed
// bytes. When all configured peers fail, retain the last real transport cause
// instead of hiding a timeout/reset behind generic unavailability. The one
// bounded transport retry adds no telemetry API, peer list or error history.
fn unavailable_with_transport_cause(
    transport: &RequestContext<'_>,
    last_io: Option<io::Error>,
) -> CellErrorV1 {
    match transport.responses.annotate_error(CellErrorV1::Unavailable) {
        CellErrorV1::Unavailable => last_io
            .map(CellErrorV1::Io)
            .unwrap_or(CellErrorV1::Unavailable),
        error => error,
    }
}

/// A finite configured-peer server. No model code is executed and no CURRENT
/// or Chain state is read or changed. One connection has an absolute deadline.
pub fn serve_cells(
    listener: &TcpListener,
    store: &CellStoreV1,
    shutdown: &AtomicBool,
    limits: CellPeerLimitsV1,
) -> CellResultV1<u64> {
    limits.validate()?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + limits.overall_timeout;
    let mut connections = 0;
    while !shutdown.load(Ordering::Relaxed)
        && connections < limits.max_connections
        && Instant::now() < deadline
    {
        match listener.accept() {
            Ok((mut stream, _)) => {
                connections += 1;
                let request_deadline = deadline.min(Instant::now() + limits.request_timeout);
                // Malformed or stalled peers lose this bounded connection only.
                let _ = serve_one(&mut stream, store, request_deadline);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(connections)
}

fn serve_one(stream: &mut TcpStream, store: &CellStoreV1, deadline: Instant) -> CellResultV1<()> {
    serve_one_budgeted(stream, store, deadline, None)
}

fn serve_one_budgeted(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    deadline: Instant,
    responses: Option<&ResponseBudget>,
) -> CellResultV1<()> {
    serve_one_profile(stream, store, deadline, responses, false)
}

fn serve_one_profile(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    deadline: Instant,
    responses: Option<&ResponseBudget>,
    allow_availability: bool,
) -> CellResultV1<()> {
    serve_one_wire(
        stream,
        store,
        deadline,
        responses,
        allow_availability,
        b"TCQ1",
        b"TCS1",
    )
}

fn serve_one_wire(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    deadline: Instant,
    responses: Option<&ResponseBudget>,
    allow_availability: bool,
    request_magic: &[u8; 4],
    response_magic: &[u8; 4],
) -> CellResultV1<()> {
    let mut query = [0; 37];
    read_deadline(stream, &mut query, deadline, None)?;
    let inventory = &query[..4] == b"TCI1" && allow_availability;
    require(&query[..4] == request_magic || inventory, "request version")?;
    let digest = query[5..]
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("request digest"))?;
    // Actual exhausted egress cannot authorize another cache read or hash.
    // Temporary in-flight reservations are not permanent exhaustion.
    if let Some(responses) = responses {
        responses.require_remaining()?;
    }
    let bytes = if inventory {
        require(query[4] == 1, "availability request type")?;
        availability::serve_page(stream, store, digest, deadline)?
    } else {
        match query[4] {
            1 => store
                .manifest_with_deadline(digest, Some(deadline))?
                .map(|m| m.encode()),
            2 => store.chunk_with_deadline(digest, Some(deadline))?,
            _ => return Err(CellErrorV1::Invalid("request type")),
        }
    };
    let mut header = [0; 9];
    header[..4].copy_from_slice(if inventory { b"TIS1" } else { response_magic });
    header[4] = u8::from(bytes.is_none());
    if let Some(bytes) = &bytes {
        header[5..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    let mut write = |mut bytes: &[u8]| -> io::Result<()> {
        if let Some(responses) = responses {
            while !bytes.is_empty() {
                let reserved = responses.reserve(bytes.len(), deadline)?;
                let result = (|| {
                    stream.set_write_timeout(Some(remaining(deadline)?))?;
                    stream.write(&bytes[..reserved])
                })();
                responses.complete(reserved, result.as_ref().copied().unwrap_or(0))?;
                let count = result?;
                if count == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                bytes = &bytes[count..];
            }
            Ok(())
        } else {
            write_deadline(stream, bytes, deadline)
        }
    };
    write(&header)?;
    if let Some(bytes) = bytes {
        write(&bytes)?;
    }
    Ok(())
}

pub(super) struct RequestContext<'a> {
    pub(super) timeout: Duration,
    pub(super) overall: Instant,
    pub(super) requests_left: &'a AtomicU64,
    pub(super) responses: &'a ResponseBudget,
}

pub(super) struct ResponseBudget {
    maximum: u64,
    state: Mutex<ResponseBytes>,
    returned: Condvar,
}

struct ResponseBytes {
    available: u64,
    reserved: u64,
    received: u64,
    // This object already spans the entire original fetch session, including
    // discovery and every release member. Keep refusals with that reservation
    // instead of allowing each member/retry to forget the same corrupt peer.
    // Existing callers admit at most eight distinct payload peers.
    quarantined: BTreeSet<SocketAddr>,
}

impl ResponseBudget {
    pub(super) fn new(maximum: u64) -> Self {
        Self {
            maximum,
            state: Mutex::new(ResponseBytes {
                available: maximum,
                reserved: 0,
                received: 0,
                quarantined: BTreeSet::new(),
            }),
            returned: Condvar::new(),
        }
    }

    pub(super) fn received(&self) -> io::Result<u64> {
        self.state
            .lock()
            .map(|state| state.received)
            .map_err(|_| io::Error::other("cell response budget poisoned"))
    }

    fn require_remaining(&self) -> io::Result<()> {
        if self.received()? == self.maximum {
            return Err(io::Error::other("CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED"));
        }
        Ok(())
    }

    fn is_quarantined(&self, peer: SocketAddr) -> CellResultV1<bool> {
        self.state
            .lock()
            .map(|state| state.quarantined.contains(&peer))
            .map_err(|_| CellErrorV1::Invalid("cell peer state poisoned"))
    }

    fn quarantine(&self, peer: SocketAddr) -> CellResultV1<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CellErrorV1::Invalid("cell peer state poisoned"))?;
        require(
            state.quarantined.contains(&peer) || state.quarantined.len() < 8,
            "cell peer quarantine bound",
        )?;
        state.quarantined.insert(peer);
        Ok(())
    }

    fn annotate_error(&self, error: CellErrorV1) -> CellErrorV1 {
        if !matches!(error, CellErrorV1::Unavailable) {
            return error;
        }
        match self.received() {
            Ok(received_response_bytes) if received_response_bytes == self.maximum => {
                CellErrorV1::ResponseByteBudgetExhausted {
                    received_response_bytes,
                    max_response_bytes: self.maximum,
                }
            }
            _ => error,
        }
    }

    fn reserve(&self, maximum: usize, deadline: Instant) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("cell response budget poisoned"))?;
        loop {
            let count = state.available.min(maximum as u64);
            if count != 0 {
                state.available -= count;
                state.reserved += count;
                return Ok(count as usize);
            }
            if state.reserved == 0 {
                return Err(io::Error::other("CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED"));
            }
            // Another read may return fewer bytes than it reserved. Wait for
            // that refund within this request's original absolute deadline;
            // temporary reservations are not proof of actual exhaustion.
            state = self
                .returned
                .wait_timeout(state, remaining(deadline)?)
                .map_err(|_| io::Error::other("cell response budget poisoned"))?
                .0;
        }
    }

    fn complete(&self, reserved: usize, received: usize) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("cell response budget poisoned"))?;
        state.reserved -= reserved as u64;
        state.received += received as u64;
        state.available += (reserved - received) as u64;
        self.returned.notify_all();
        Ok(())
    }

    pub(super) fn read(
        &self,
        stream: &mut TcpStream,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> io::Result<usize> {
        let reserved = self.reserve(bytes.len(), deadline)?;
        // No mutex is held during blocking socket I/O. Limit the actual read
        // buffer before receiving bytes, so concurrent workers cannot overshoot.
        // Always refund unused capacity, including EOF, Interrupted and errors.
        let result = (|| {
            stream.set_read_timeout(Some(remaining(deadline)?))?;
            stream.read(&mut bytes[..reserved])
        })();
        self.complete(reserved, result.as_ref().copied().unwrap_or(0))?;
        result
    }
}

/// A bounded server may finish its last write before its worker is reaped. A
/// fast client can therefore encounter a transient reset at the next request
/// even when its parallelism does not exceed the server's worker count.
///
/// Retry that transport failure once, after a finite pause, using the SAME
/// original deadline, connection allowance and response-byte accounting. No
/// complete malformed frame, unavailable response, digest failure, response-body
/// failure or timeout is retried. Partial headers still spend actual byte budget.
/// Persistent overload still fails closed; this is not an availability promise.
fn request_with_retry(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    transport: &RequestContext<'_>,
) -> (CellResultV1<Vec<u8>>, usize) {
    const BACKOFF: Duration = Duration::from_millis(20);
    let mut phase = "budget";
    let first = request_with_phase(peer, kind, digest, maximum, transport, &mut phase);
    let transient = phase != "response-body"
        && matches!(&first, Err(CellErrorV1::Io(error)) if matches!(error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof));
    if !transient
        || transport.requests_left.load(Ordering::Relaxed) == 0
        || transport.overall.saturating_duration_since(Instant::now()) <= BACKOFF
    {
        return (first, 1);
    }
    thread::sleep(BACKOFF);
    // request independently rechecks the shared atomic allowance and absolute
    // deadline after the pause; another worker cannot grant extra capacity.
    (request(peer, kind, digest, maximum, transport), 2)
}

fn request(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    transport: &RequestContext<'_>,
) -> CellResultV1<Vec<u8>> {
    let mut phase = "budget";
    request_with_phase(peer, kind, digest, maximum, transport, &mut phase)
}

fn request_with_phase(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    transport: &RequestContext<'_>,
    phase: &mut &'static str,
) -> CellResultV1<Vec<u8>> {
    let started = Instant::now();
    request_in_phase(peer, kind, digest, maximum, transport, phase).map_err(|error| {
        if let CellErrorV1::Io(error) = error {
            let detail: String = error.to_string().chars().take(192).collect();
            CellErrorV1::Io(io::Error::new(
                error.kind(),
                format!(
                    "cell request peer={peer} kind={kind} phase={phase} elapsed_ms={} os={:?}: {detail}",
                    started.elapsed().as_millis(),
                    error.raw_os_error(),
                ),
            ))
        } else {
            error
        }
    })
}

fn request_in_phase(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    transport: &RequestContext<'_>,
    phase: &mut &'static str,
) -> CellResultV1<Vec<u8>> {
    let mut query = [0; 37];
    query[..4].copy_from_slice(b"TCQ1");
    query[4] = kind;
    query[5..].copy_from_slice(&digest);
    request_frame(peer, &query, b"TCS1", maximum, transport, phase)
}

// Both explicit profiles share the original byte/connection/time admission.
// A complete unavailable response is ordinary absence. Only a complete
// malformed frame or a later invalid pinned object quarantines the peer.
fn request_frame(
    peer: SocketAddr,
    query: &[u8],
    response_magic: &[u8; 4],
    maximum: usize,
    transport: &RequestContext<'_>,
    phase: &mut &'static str,
) -> CellResultV1<Vec<u8>> {
    require(
        !transport.responses.is_quarantined(peer)?,
        "cell peer quarantined",
    )?;
    if transport.responses.received()? == transport.responses.maximum {
        return Err(io::Error::other("CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED").into());
    }
    transport
        .requests_left
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
    let deadline = transport.overall.min(Instant::now() + transport.timeout);
    *phase = "connect";
    let mut stream = TcpStream::connect_timeout(&peer, remaining(deadline)?)?;
    exchange_frame(
        &mut stream,
        ObjectFrame {
            peer,
            query,
            response_magic,
            maximum,
        },
        deadline,
        transport,
        phase,
    )
}

struct ObjectFrame<'a> {
    peer: SocketAddr,
    query: &'a [u8],
    response_magic: &'a [u8; 4],
    maximum: usize,
}

// Request admission and connection ownership belong to the explicit profile;
// frame integrity, byte accounting and corrupt-peer quarantine stay identical.
fn exchange_frame(
    stream: &mut TcpStream,
    frame: ObjectFrame<'_>,
    deadline: Instant,
    transport: &RequestContext<'_>,
    phase: &mut &'static str,
) -> CellResultV1<Vec<u8>> {
    let ObjectFrame {
        peer,
        query,
        response_magic,
        maximum,
    } = frame;
    *phase = "request-write";
    write_deadline(stream, query, deadline)?;
    let mut header = [0; 9];
    *phase = "response-header";
    read_deadline(stream, &mut header, deadline, Some(transport.responses))?;
    let length = u32::from_be_bytes(
        header[5..]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("response length"))?,
    ) as usize;
    if &header[..4] != response_magic || header[4] > 1 || (header[4] == 1 && length != 0) {
        transport.responses.quarantine(peer)?;
        return Err(CellErrorV1::Invalid("invalid peer response frame"));
    }
    if header[4] == 1 {
        return Err(CellErrorV1::Unavailable);
    }
    if length == 0 || length > maximum || length > MAX_CHUNK_BYTES as usize {
        transport.responses.quarantine(peer)?;
        return Err(CellErrorV1::Invalid("response byte bound"));
    }
    let mut bytes = vec![0; length];
    *phase = "response-body";
    read_deadline(stream, &mut bytes, deadline, Some(transport.responses))?;
    Ok(bytes)
}

pub(super) fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "cell absolute deadline"))
}

pub(super) fn read_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    budget: Option<&ResponseBudget>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let read = match budget {
            Some(budget) => budget.read(stream, bytes, deadline),
            None => stream.read(bytes),
        };
        match read {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "cell response truncated",
                ))
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn write_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "cell response stalled",
                ))
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod dedup_tests;

#[cfg(test)]
mod budget_tests {
    use super::*;

    /// A real socket peer serving only the listed manifest/chunk responses.
    /// Each expected operation must arrive before the helper's finite deadline.
    fn fixed_responses(
        responses: Vec<(u8, CellDigestV1, Vec<u8>)>,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (kind, digest, bytes) in responses {
                let mut stream = accept_before_test_deadline(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut query = [0; 37];
                stream.read_exact(&mut query).unwrap();
                assert_eq!(&query[..5], &[b'T', b'C', b'Q', b'1', kind]);
                assert_eq!(&query[5..], &digest);
                let mut wire = b"TCS1\0".to_vec();
                wire.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                wire.extend_from_slice(&bytes);
                stream.write_all(&wire).unwrap();
            }
        });
        (address, server)
    }

    #[test]
    fn chunk_deadline_expiry_does_not_quarantine_peer_but_invalid_bytes_do() {
        use sha2::{Digest, Sha256};

        struct AfterActualReply {
            expire: bool,
        }
        impl ObjectRequests for AfterActualReply {
            fn request(
                &self,
                peer: SocketAddr,
                kind: u8,
                digest: CellDigestV1,
                maximum: usize,
                transport: &RequestContext<'_>,
            ) -> (CellResultV1<Vec<u8>>, usize) {
                let result = SingleRequestV1.request(peer, kind, digest, maximum, transport);
                assert!(result.0.is_ok(), "the original TCP response must complete");
                if self.expire {
                    // Keep the actual response, byte accounting and original
                    // deadline. Delay only the verification continuation.
                    while Instant::now() < transport.overall {
                        thread::sleep(transport.overall.saturating_duration_since(Instant::now()));
                    }
                }
                result
            }
        }

        let payload = b"real-cell-response-before-local-expiry".to_vec();
        let expected = CellChunkV1 {
            size: payload.len() as u32,
            sha256: Sha256::digest(&payload).into(),
        };
        for (expire, corrupt) in [(false, false), (false, true), (true, true)] {
            let supplied = if corrupt {
                vec![0; payload.len()]
            } else {
                payload.clone()
            };
            let (peer, server) = fixed_responses(vec![(2, expected.sha256, supplied)]);
            let responses = ResponseBudget::new(1024);
            let requests_left = AtomicU64::new(2);
            let transport = RequestContext {
                timeout: Duration::from_secs(1),
                overall: Instant::now() + Duration::from_secs(2),
                requests_left: &requests_left,
                responses: &responses,
            };
            let requests = AfterActualReply { expire };
            let result = download_chunk_via(&expected, 0, &[peer], &transport, 0, &requests);
            server.join().unwrap();
            assert_eq!(requests_left.load(Ordering::Relaxed), 1);
            assert_eq!(responses.received().unwrap(), 9 + payload.len() as u64);
            assert_eq!(responses.is_quarantined(peer).unwrap(), corrupt && !expire);
            if expire {
                assert!(matches!(
                    result,
                    Err(CellErrorV1::Io(error)) if error.kind() == io::ErrorKind::TimedOut
                ));
            } else if corrupt {
                assert!(matches!(result, Err(CellErrorV1::Unavailable)));
                // A proven bad peer stays refused for this same reservation.
                // No second TCP request or response byte is spent.
                assert!(matches!(
                    download_chunk_via(&expected, 0, &[peer], &transport, 0, &requests),
                    Err(CellErrorV1::Unavailable)
                ));
                assert_eq!(requests_left.load(Ordering::Relaxed), 1);
                assert_eq!(responses.received().unwrap(), 9 + payload.len() as u64);
            } else {
                let (actual, supplied_by, rejected) = result.unwrap();
                assert_eq!(actual, payload);
                assert_eq!(supplied_by, peer);
                assert_eq!(rejected, 0);
            }
        }
    }

    #[test]
    fn fetch_persistence_and_corrupt_cache_repair_keep_original_deadline_under_writer_lock() {
        use crate::cell::{cache_wal, CellCacheConfigV4, CellContextV1};
        use rusqlite::{params, Connection, OptionalExtension};
        use sha2::{Digest, Sha256};
        use std::fs::{self, OpenOptions};

        // Exercise manifest persistence, the final bounded chunk batch, and
        // corrupt-cache deletion. All three previously restarted a five-second
        // writer wait after the original fetch deadline had been established.
        let mut renewed_deadlines = Vec::new();
        for phase in ["manifest", "batch", "repair"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("cache.sqlite");
            let cache = CellStoreV1::open(
                &path,
                CellCacheConfigV4 {
                    max_database_bytes: 1_048_576,
                    max_logical_bytes: 1_048_576,
                    max_chunk_rows: 16,
                    max_manifest_rows: 16,
                },
            )
            .unwrap();
            let payload = b"original-cell-fetch-deadline".to_vec();
            let chunk = CellChunkV1 {
                size: payload.len() as u32,
                sha256: Sha256::digest(&payload).into(),
            };
            let manifest = CellManifestV1::new(
                CellContextV1 {
                    family: "writer-deadline".into(),
                    base: [1; 32],
                    parent: [2; 32],
                    tokenizer: [3; 32],
                    layout: [4; 32],
                    runtime: [5; 32],
                },
                payload.len() as u64,
                chunk.sha256,
                16_384,
                vec![chunk.clone()],
            )
            .unwrap();
            if phase != "manifest" {
                cache
                    .put_manifest(manifest.id(), &manifest.encode())
                    .unwrap();
            }
            let corrupt = vec![0; payload.len()];
            if phase == "repair" {
                cache.put_chunk(&chunk, &payload).unwrap();
                Connection::open(&path)
                    .unwrap()
                    .execute(
                        "UPDATE cell_chunks_v1 SET bytes=?2 WHERE hash=?1",
                        params![chunk.sha256.as_slice(), &corrupt],
                    )
                    .unwrap();
            }
            let usage_before = cache.cache_usage().unwrap();
            let held = OpenOptions::new()
                .read(true)
                .write(true)
                .open(cache_wal::sidecar(&path, "-writer-lock-v4"))
                .unwrap();
            held.lock().unwrap();
            let response = match phase {
                "manifest" => Some((1, manifest.id(), manifest.encode())),
                "batch" => Some((2, chunk.sha256, payload.clone())),
                _ => None,
            };
            let peer = response.map(|response| fixed_responses(vec![response]));
            let peers: Vec<_> = peer
                .as_ref()
                .map(|(address, _)| *address)
                .into_iter()
                .collect();
            let limits = CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(250),
                overall_timeout: Duration::from_millis(250),
                max_cell_bytes: 16_384,
                parallelism: 1,
                max_connections: 2,
                max_response_bytes: 4096,
            };
            let output = dir.path().join("complete.weights");
            let pinned = manifest.id();
            let (cache, result, elapsed, finished_while_locked) = thread::scope(|scope| {
                let (done, completed) = mpsc::channel();
                let output = &output;
                let worker = scope.spawn(move || {
                    let started = Instant::now();
                    let result = fetch_cell_to_file(&cache, pinned, &peers, limits, output);
                    let elapsed = started.elapsed();
                    let _ = done.send(());
                    (cache, result, elapsed)
                });
                // Always release before joining/asserting. A regression cannot
                // strand the test; it demonstrably waits for our release instead.
                let finished = completed.recv_timeout(Duration::from_secs(2)).is_ok();
                held.unlock().unwrap();
                let (cache, result, elapsed) = worker.join().unwrap();
                (cache, result, elapsed, finished)
            });
            if let Some((_, server)) = peer {
                server.join().unwrap();
            }
            let usage_after = cache.cache_usage().unwrap();
            eprintln!(
                "CELL_PERSISTENCE_DEADLINE_OBSERVATION phase={phase} original_budget_ms={} elapsed_ns={} finished_while_locked={finished_while_locked} output_exists={} before={usage_before:?} after={usage_after:?} outcome={:?}",
                limits.overall_timeout.as_millis(),
                elapsed.as_nanos(),
                output.exists(),
                result.as_ref().map(|_| ())
            );
            if !finished_while_locked {
                // Keep every failing phase when the unchanged control is run
                // against the original source. The aggregate assertion below
                // still fails; no late result is credited as a successful retry.
                renewed_deadlines.push(phase);
                continue;
            }
            assert!(
                matches!(result, Err(CellErrorV1::CacheWriterBusy)),
                "{phase}: {result:?}"
            );
            assert!(
                !output.exists(),
                "failed {phase} published a complete output"
            );
            assert_eq!(usage_after, usage_before);
            assert_eq!(
                cache.manifest(pinned).unwrap().is_some(),
                phase != "manifest"
            );
            let stored: Option<Vec<u8>> = Connection::open(&path)
                .unwrap()
                .query_row(
                    "SELECT bytes FROM cell_chunks_v1 WHERE hash=?1",
                    [chunk.sha256.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            assert_eq!(stored, (phase == "repair").then_some(corrupt));

            // A distinct later invocation may retry after contention clears.
            // It must receive/verify actual bytes and create the complete file.
            let mut replies = Vec::new();
            if phase == "manifest" {
                replies.push((1, pinned, manifest.encode()));
            }
            replies.push((2, chunk.sha256, payload.clone()));
            let (address, server) = fixed_responses(replies);
            let (actual, report) = fetch_cell_to_file(
                &cache,
                pinned,
                &[address],
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_secs(1),
                    overall_timeout: Duration::from_secs(2),
                    ..limits
                },
                &output,
            )
            .unwrap();
            server.join().unwrap();
            assert_eq!(actual, manifest);
            assert_eq!(report.downloaded_chunks, 1);
            assert_eq!(report.downloaded_bytes, payload.len() as u64);
            assert_eq!(
                report.connection_attempts,
                if phase == "manifest" { 2 } else { 1 }
            );
            assert_eq!(fs::read(&output).unwrap(), payload);
        }
        assert!(
            renewed_deadlines.is_empty(),
            "cache phases renewed the original fetch deadline: {renewed_deadlines:?}"
        );
    }

    fn accept_before_test_deadline(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                result => panic!("expected bounded actual TCP request: {result:?}"),
            }
        }
    }

    #[test]
    fn writable_serving_cache_repair_keeps_original_request_deadline() {
        use crate::cell::{cache_wal, CellCacheConfigV4};
        use rusqlite::{params, Connection};
        use sha2::{Digest, Sha256};
        use std::fs::OpenOptions;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serving.sqlite");
        let cache = CellStoreV1::open(
            &path,
            CellCacheConfigV4 {
                max_database_bytes: 1_048_576,
                max_logical_bytes: 1_048_576,
                max_chunk_rows: 16,
                max_manifest_rows: 16,
            },
        )
        .unwrap();
        let payload = vec![7; 64];
        let chunk = CellChunkV1 {
            size: payload.len() as u32,
            sha256: Sha256::digest(&payload).into(),
        };
        cache.put_chunk(&chunk, &payload).unwrap();
        let corrupt = vec![0; payload.len()];
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE cell_chunks_v1 SET bytes=?2 WHERE hash=?1",
                params![chunk.sha256.as_slice(), &corrupt],
            )
            .unwrap();
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(cache_wal::sidecar(&path, "-writer-lock-v4"))
            .unwrap();
        held.lock().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (cache, result, elapsed, finished) = thread::scope(|scope| {
            let (done, completed) = mpsc::channel();
            let worker = scope.spawn(move || {
                let mut stream = accept_before_test_deadline(&listener);
                let started = Instant::now();
                let response_budget = ResponseBudget::new(4096);
                let result = serve_one_budgeted(
                    &mut stream,
                    &cache,
                    started + Duration::from_millis(250),
                    Some(&response_budget),
                );
                let elapsed = started.elapsed();
                assert_eq!(response_budget.received().unwrap(), 0);
                let _ = done.send(());
                (cache, result, elapsed)
            });
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut query = b"TCQ1\x02".to_vec();
            query.extend_from_slice(&chunk.sha256);
            client.write_all(&query).unwrap();
            let finished = completed.recv_timeout(Duration::from_secs(2)).is_ok();
            held.unlock().unwrap();
            let (cache, result, elapsed) = worker.join().unwrap();
            (cache, result, elapsed, finished)
        });
        eprintln!(
            "CELL_SERVING_CACHE_DEADLINE_OBSERVATION original_budget_ms=250 elapsed_ns={} finished_while_locked={finished} outcome={result:?}",
            elapsed.as_nanos()
        );
        assert!(
            finished,
            "serving cache cleanup renewed its request deadline"
        );
        assert!(matches!(result, Err(CellErrorV1::CacheWriterBusy)));
        let stored: Vec<u8> = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT bytes FROM cell_chunks_v1 WHERE hash=?1",
                [chunk.sha256.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, corrupt);
        // A fresh ordinary cache operation may repair after the held lock is
        // released. The failed request neither served bad bytes nor deleted them.
        assert!(cache.chunk(chunk.sha256).unwrap().is_none());
        cache.put_chunk(&chunk, &payload).unwrap();
        assert_eq!(cache.chunk(chunk.sha256).unwrap(), Some(payload));
    }

    #[test]
    fn transient_retry_keeps_original_connection_and_deadline_limits() {
        for (connections, window) in [(1, Duration::from_secs(1)), (2, Duration::from_millis(20))] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let mut stream = accept_before_test_deadline(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut query = [0; 37];
                stream.read_exact(&mut query).unwrap();
                // Actual early EOF, not a synthetic success or error result.
            });
            let responses = ResponseBudget::new(64);
            let requests_left = AtomicU64::new(connections);
            let transport = RequestContext {
                timeout: Duration::from_secs(1),
                overall: Instant::now() + window,
                requests_left: &requests_left,
                responses: &responses,
            };
            let (result, attempts) = request_with_retry(address, 2, [0; 32], 64, &transport);
            server.join().unwrap();
            assert!(result.is_err());
            assert_eq!(attempts, 1);
            assert_eq!(requests_left.load(Ordering::Relaxed), connections - 1);
            assert_eq!(responses.received().unwrap(), 0);
        }
    }

    #[test]
    fn transient_retry_counts_partial_bytes_and_one_byte_short_cutoff() {
        for maximum in [14, 13] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                for attempt in 0..2 {
                    let mut stream = accept_before_test_deadline(&listener);
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut query = [0; 37];
                    stream.read_exact(&mut query).unwrap();
                    let bytes: &[u8] = if attempt == 0 {
                        b"TCS1"
                    } else {
                        b"TCS1\0\0\0\0\x01x"
                    };
                    stream.write_all(bytes).unwrap();
                }
            });
            let responses = ResponseBudget::new(maximum);
            let requests_left = AtomicU64::new(2);
            let transport = RequestContext {
                timeout: Duration::from_secs(1),
                overall: Instant::now() + Duration::from_secs(2),
                requests_left: &requests_left,
                responses: &responses,
            };
            let (result, attempts) = request_with_retry(address, 2, [0; 32], 1, &transport);
            server.join().unwrap();
            assert_eq!(attempts, 2);
            assert_eq!(requests_left.load(Ordering::Relaxed), 0);
            assert_eq!(responses.received().unwrap(), maximum);
            if maximum == 14 {
                assert_eq!(result.unwrap(), b"x");
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn transient_retry_does_not_repeat_invalid_frame_or_bad_chunk_digest() {
        for malformed_frame in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let mut stream = accept_before_test_deadline(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut query = [0; 37];
                stream.read_exact(&mut query).unwrap();
                let bytes: &[u8] = if malformed_frame {
                    b"BAD1\0\0\0\0\x01x"
                } else {
                    b"TCS1\0\0\0\0\x01x"
                };
                stream.write_all(bytes).unwrap();
            });
            let responses = ResponseBudget::new(64);
            let requests_left = AtomicU64::new(2);
            let transport = RequestContext {
                timeout: Duration::from_secs(1),
                overall: Instant::now() + Duration::from_secs(2),
                requests_left: &requests_left,
                responses: &responses,
            };
            let expected = CellChunkV1 {
                size: 1,
                sha256: [0; 32],
            };
            assert!(download_chunk(&expected, 0, &[address], &transport).is_err());
            server.join().unwrap();
            assert_eq!(requests_left.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn transient_retry_stops_after_two_real_early_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let mut stream = accept_before_test_deadline(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut query = [0; 37];
                stream.read_exact(&mut query).unwrap();
            }
        });
        let responses = ResponseBudget::new(64);
        let requests_left = AtomicU64::new(10);
        let transport = RequestContext {
            timeout: Duration::from_secs(1),
            overall: Instant::now() + Duration::from_secs(2),
            requests_left: &requests_left,
            responses: &responses,
        };
        let (result, attempts) = request_with_retry(address, 2, [0; 32], 64, &transport);
        server.join().unwrap();
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        assert_eq!(requests_left.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn concurrent_socket_reads_never_exceed_shared_budget() {
        for deficit in [0, 1] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                thread::scope(|scope| {
                    let (ready, arrivals) = mpsc::sync_channel(4);
                    let mut releases = Vec::new();
                    for _ in 0..4 {
                        let (mut stream, _) = listener.accept().unwrap();
                        let ready = ready.clone();
                        let (release, start) = mpsc::sync_channel(0);
                        releases.push(release);
                        scope.spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut query = [0; 37];
                            stream.read_exact(&mut query).unwrap();
                            ready.send(()).unwrap();
                            start.recv_timeout(Duration::from_secs(2)).unwrap();
                            let mut response = b"TCS1\0".to_vec();
                            response.extend_from_slice(&64_u32.to_be_bytes());
                            response.extend_from_slice(&[7; 64]);
                            let _ = stream.write_all(&response);
                        });
                    }
                    for _ in 0..4 {
                        arrivals.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                    for release in releases {
                        release.send(()).unwrap();
                    }
                });
            });
            let maximum = 4 * (64 + 9) - deficit;
            let responses = ResponseBudget::new(maximum);
            let requests_left = AtomicU64::new(4);
            let transport = RequestContext {
                timeout: Duration::from_secs(2),
                overall: Instant::now() + Duration::from_secs(5),
                requests_left: &requests_left,
                responses: &responses,
            };
            let succeeded = thread::scope(|scope| {
                let clients: Vec<_> = (0..4)
                    .map(|_| {
                        let transport = &transport;
                        scope.spawn(move || request(address, 2, [0; 32], 64, transport))
                    })
                    .collect();
                clients
                    .into_iter()
                    .map(|client| match client.join().unwrap() {
                        Ok(bytes) => {
                            assert_eq!(bytes, [7; 64]);
                            true
                        }
                        Err(_) => false,
                    })
                    .filter(|succeeded| *succeeded)
                    .count()
            });
            server.join().unwrap();
            assert_eq!(responses.received().unwrap(), maximum);
            if deficit == 0 {
                assert_eq!(succeeded, 4);
            } else {
                assert!(succeeded < 4);
            }
        }
    }
}
