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
    manifest::MAX_MANIFEST_BYTES, require, store::verify_chunk, CellChunkV1, CellDigestV1,
    CellErrorV1, CellManifestV1, CellResultV1, CellStoreV1, MAX_CELL_BYTES, MAX_CHUNK_BYTES,
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

    fn validate(self) -> CellResultV1<()> {
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
    let mut rejected = 0;
    let manifest = match store.manifest(pinned)? {
        Some(manifest) => manifest,
        None => {
            let mut received = None;
            for peer in peers {
                let candidate =
                    request(*peer, 1, pinned, MAX_MANIFEST_BYTES, &transport).and_then(|wire| {
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
                        received = Some(store.put_manifest(pinned, &wire)?);
                        break;
                    }
                    Err(_) => rejected += 1,
                }
            }
            received.ok_or_else(|| responses.annotate_error(CellErrorV1::Unavailable))?
        }
    };
    require(
        manifest.size() <= limits.max_cell_bytes,
        "cell exceeds byte budget",
    )?;
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
        match store.chunk(expected.sha256)? {
            Some(bytes) => {
                verify_chunk(expected, &bytes)?;
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
            let transport = &transport;
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
        for (chunk, result) in receiver {
            let written = result.and_then(|(bytes, peer, rejected)| {
                store.put_chunk(chunk, &bytes)?;
                report.downloaded_bytes += bytes.len() as u64;
                report.downloaded_chunks += 1;
                report.rejected_responses += rejected;
                report.supplying_peers.insert(peer);
                Ok(())
            });
            if let Err(error) = written {
                cancelled.store(true, Ordering::Relaxed);
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })
    .map_err(|error| responses.annotate_error(error))?;
    require(Instant::now() <= deadline, "fetch deadline")?;
    store.verify_complete_until(&manifest, deadline)?;
    require(Instant::now() <= deadline, "fetch deadline")?;
    report.connection_attempts = limits.max_connections - requests_left.load(Ordering::Relaxed);
    report.received_response_bytes = responses.received()?;
    if let Some(output) = output {
        store.materialize_until(&manifest, output, deadline)?;
    }
    Ok((manifest, report))
}

fn download_chunk(
    chunk: &CellChunkV1,
    order: usize,
    peers: &[SocketAddr],
    transport: &RequestContext<'_>,
) -> CellResultV1<(Vec<u8>, SocketAddr, usize)> {
    for offset in 0..peers.len() {
        let peer = peers[(order + offset) % peers.len()];
        let candidate =
            request(peer, 2, chunk.sha256, chunk.size as usize, transport).and_then(|bytes| {
                verify_chunk(chunk, &bytes)?;
                Ok(bytes)
            });
        if let Ok(bytes) = candidate {
            return Ok((bytes, peer, offset));
        }
    }
    Err(CellErrorV1::Unavailable)
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
    let mut query = [0; 37];
    read_deadline(stream, &mut query, deadline, None)?;
    require(&query[..4] == b"TCQ1", "request version")?;
    let digest = query[5..]
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("request digest"))?;
    let bytes = match query[4] {
        1 => store.manifest(digest)?.map(|m| m.encode()),
        2 => store.chunk(digest)?,
        _ => return Err(CellErrorV1::Invalid("request type")),
    };
    let mut header = [0; 9];
    header[..4].copy_from_slice(b"TCS1");
    header[4] = u8::from(bytes.is_none());
    if let Some(bytes) = &bytes {
        header[5..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    write_deadline(stream, &header, deadline)?;
    if let Some(bytes) = bytes {
        write_deadline(stream, &bytes, deadline)?;
    }
    Ok(())
}

struct RequestContext<'a> {
    timeout: Duration,
    overall: Instant,
    requests_left: &'a AtomicU64,
    responses: &'a ResponseBudget,
}

struct ResponseBudget {
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
    fn new(maximum: u64) -> Self {
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

    fn received(&self) -> io::Result<u64> {
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

    fn read(
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

fn request(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    transport: &RequestContext<'_>,
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
    let mut stream = TcpStream::connect_timeout(&peer, remaining(deadline)?)?;
    let mut query = [0; 37];
    query[..4].copy_from_slice(b"TCQ1");
    query[4] = kind;
    query[5..].copy_from_slice(&digest);
    write_deadline(&mut stream, &query, deadline)?;
    let mut header = [0; 9];
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
    read_deadline(&mut stream, &mut bytes, deadline, Some(transport.responses))?;
    Ok(bytes)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "cell absolute deadline"))
}

fn read_deadline(
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

fn write_deadline(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
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
