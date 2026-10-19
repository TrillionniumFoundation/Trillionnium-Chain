use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
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
}

impl CellPeerLimitsV1 {
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
    limits.validate()?;
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "configured peer count/duplicates",
    )?;
    let deadline = Instant::now() + limits.overall_timeout;
    let requests_left = AtomicU64::new(limits.max_connections);
    let mut rejected = 0;
    let manifest = match store.manifest(pinned)? {
        Some(manifest) => manifest,
        None => {
            let mut received = None;
            for peer in peers {
                let candidate = request(
                    *peer,
                    1,
                    pinned,
                    MAX_MANIFEST_BYTES,
                    limits.request_timeout,
                    deadline,
                    &requests_left,
                )
                .and_then(|wire| {
                    let manifest = CellManifestV1::decode(&wire)?;
                    require(manifest.id() == pinned, "manifest digest")?;
                    require(
                        manifest.size() <= limits.max_cell_bytes,
                        "cell exceeds byte budget",
                    )?;
                    store.put_manifest(pinned, &wire)
                });
                match candidate {
                    Ok(value) => {
                        received = Some(value);
                        break;
                    }
                    Err(_) => rejected += 1,
                }
            }
            received.ok_or(CellErrorV1::Unavailable)?
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
            let requests_left = &requests_left;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((order, chunk)) = missing.get(index) else {
                        break;
                    };
                    let result = download_chunk(
                        chunk,
                        *order,
                        peers,
                        limits.request_timeout,
                        deadline,
                        requests_left,
                    );
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
    })?;
    require(Instant::now() <= deadline, "fetch deadline")?;
    store.verify_complete_until(&manifest, deadline)?;
    require(Instant::now() <= deadline, "fetch deadline")?;
    report.connection_attempts = limits.max_connections - requests_left.load(Ordering::Relaxed);
    Ok((manifest, report))
}

fn download_chunk(
    chunk: &CellChunkV1,
    order: usize,
    peers: &[SocketAddr],
    timeout: Duration,
    deadline: Instant,
    requests_left: &AtomicU64,
) -> CellResultV1<(Vec<u8>, SocketAddr, usize)> {
    for offset in 0..peers.len() {
        let peer = peers[(order + offset) % peers.len()];
        let candidate = request(
            peer,
            2,
            chunk.sha256,
            chunk.size as usize,
            timeout,
            deadline,
            requests_left,
        )
        .and_then(|bytes| {
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
    read_deadline(stream, &mut query, deadline)?;
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

fn request(
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    timeout: Duration,
    overall: Instant,
    requests_left: &AtomicU64,
) -> CellResultV1<Vec<u8>> {
    requests_left
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
    let deadline = overall.min(Instant::now() + timeout);
    let mut stream = TcpStream::connect_timeout(&peer, remaining(deadline)?)?;
    let mut query = [0; 37];
    query[..4].copy_from_slice(b"TCQ1");
    query[4] = kind;
    query[5..].copy_from_slice(&digest);
    write_deadline(&mut stream, &query, deadline)?;
    let mut header = [0; 9];
    read_deadline(&mut stream, &mut header, deadline)?;
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
    read_deadline(&mut stream, &mut bytes, deadline)?;
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
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
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
