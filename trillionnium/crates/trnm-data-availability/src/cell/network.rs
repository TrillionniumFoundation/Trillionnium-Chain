use std::{
    collections::BTreeSet,
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
    store::{verify_chunk, verify_chunk_length, MAX_CHUNK_COMMIT_BATCH},
    CellChunkV1, CellDigestV1, CellErrorV1, CellManifestV1, CellResultV1, CellStoreV1,
    MAX_CELL_BYTES, MAX_CHUNK_BYTES,
};

mod serving;
pub use serving::{serve_cells_bounded, CellServeLimitsV1, CellServeReportV1};

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
    pub cached_chunks: usize,
    pub downloaded_chunks: usize,
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
    fetch_cell_inner(store, pinned, peers, limits, None)
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
    fetch_cell_inner(store, pinned, peers, limits, Some(output))
}

fn fetch_cell_inner(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPeerLimitsV1,
    output: Option<&Path>,
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
    fetch_cell_in_session(store, pinned, peers, limits, &transport, output)
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
    let deadline = transport.overall;
    let requests_left = transport.requests_left;
    let responses = transport.responses;
    let (manifest, rejected) = fetch_manifest(store, pinned, peers, limits, transport)?;
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
    for (index, expected) in manifest.chunks().iter().enumerate() {
        require(Instant::now() <= deadline, "cache scan deadline")?;
        match store.chunk_with_deadline(expected.sha256, Some(deadline))? {
            Some(bytes) => {
                // chunk() already hashes the actual cache buffer on every read.
                verify_chunk_length(expected, &bytes)?;
                report.cached_chunks += 1;
            }
            None => missing.push((index, expected.clone())),
        }
    }
    let next = AtomicUsize::new(0);
    let cancelled = AtomicBool::new(false);
    thread::scope(|scope| -> CellResultV1<()> {
        let (sender, receiver) = mpsc::sync_channel(limits.parallelism);
        for _ in 0..limits.parallelism.min(missing.len()) {
            let sender = sender.clone();
            let missing = &missing;
            let next = &next;
            let cancelled = &cancelled;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((order, chunk)) = missing.get(index) else {
                        break;
                    };
                    let result = download_chunk(chunk, *order, peers, transport);
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
            for (_, bytes, peer, rejected) in pending.drain(..) {
                report.downloaded_bytes += bytes.len() as u64;
                report.downloaded_chunks += 1;
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
    let mut rejected = 0;
    let (manifest, initial_cache_hit) = match store.manifest(pinned)? {
        Some(manifest) => (manifest, true),
        None => {
            let mut received = None;
            let mut last_io = None;
            for peer in peers {
                let (candidate, attempts) =
                    request_with_retry(*peer, 1, pinned, MAX_MANIFEST_BYTES, transport);
                rejected += attempts - 1;
                let candidate = candidate.and_then(|wire| {
                    let manifest = CellManifestV1::decode(&wire)?;
                    require(manifest.id() == pinned, "manifest digest")?;
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
    let mut last_io = None;
    let mut rejected = 0;
    for offset in 0..peers.len() {
        let peer = peers[(order + offset) % peers.len()];
        let (candidate, attempts) =
            request_with_retry(peer, 2, chunk.sha256, chunk.size as usize, transport);
        rejected += attempts - 1;
        let candidate = candidate.and_then(|bytes| {
            verify_chunk(chunk, &bytes)?;
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
    let mut query = [0; 37];
    read_deadline(stream, &mut query, deadline, None)?;
    require(&query[..4] == b"TCQ1", "request version")?;
    let digest = query[5..]
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("request digest"))?;
    let bytes = match query[4] {
        1 => store.manifest(digest)?.map(|m| m.encode()),
        2 => store.chunk_with_deadline(digest, Some(deadline))?,
        _ => return Err(CellErrorV1::Invalid("request type")),
    };
    let mut header = [0; 9];
    header[..4].copy_from_slice(b"TCS1");
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
}

impl ResponseBudget {
    pub(super) fn new(maximum: u64) -> Self {
        Self {
            maximum,
            state: Mutex::new(ResponseBytes {
                available: maximum,
                reserved: 0,
                received: 0,
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
    let mut query = [0; 37];
    query[..4].copy_from_slice(b"TCQ1");
    query[4] = kind;
    query[5..].copy_from_slice(&digest);
    *phase = "request-write";
    write_deadline(&mut stream, &query, deadline)?;
    let mut header = [0; 9];
    *phase = "response-header";
    read_deadline(
        &mut stream,
        &mut header,
        deadline,
        Some(transport.responses),
    )?;
    require(
        &header[..4] == b"TCS1" && header[4] == 0,
        "peer has no bytes or invalid response",
    )?;
    let length = u32::from_be_bytes(
        header[5..]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("response length"))?,
    ) as usize;
    require(
        length > 0 && length <= maximum && length <= MAX_CHUNK_BYTES as usize,
        "response byte bound",
    )?;
    let mut bytes = vec![0; length];
    *phase = "response-body";
    read_deadline(&mut stream, &mut bytes, deadline, Some(transport.responses))?;
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
