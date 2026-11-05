//! Explicit sequential connection reuse under a separate TCQ2/TCS2 profile.
//!
//! Each request is `TCQ2 || kind:u8 || pinned_digest:32`; each response is
//! `TCS2 || status:u8 || length:u32be || bytes`. Kinds and object bytes retain
//! their TCM1/chunk meaning. V1 and inventory magic are rejected, never retried
//! under another namespace. There is no multiplexing or implicit activation.
//! Every connection has one fixed absolute deadline established at dial/accept.
//! A failed or partial frame discards that connection without retrying the frame.

use super::*;
use std::sync::{MutexGuard, TryLockError};

const MAX_REQUESTS: u64 = 100_000;

#[derive(Clone, Copy, Debug)]
pub struct CellPersistentPeerLimitsV2 {
    /// Original session bounds. `max_connections` counts actual dial attempts;
    /// `request_timeout` also caps a connection's lifetime, without renewal.
    pub peer: CellPeerLimitsV1,
    /// Reserved frame attempts, including failed frames and bounded lock waits.
    pub max_requests: u64,
    pub max_requests_per_connection: u64,
}

impl CellPersistentPeerLimitsV2 {
    pub fn validate(self) -> CellResultV1<()> {
        self.peer.validate()?;
        validate_requests(self.max_requests, self.max_requests_per_connection)
    }
}

fn validate_requests(total: u64, per_connection: u64) -> CellResultV1<()> {
    require(
        (1..=MAX_REQUESTS).contains(&total) && (1..=total).contains(&per_connection),
        "persistent request bounds",
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPersistentFetchReportV2 {
    pub request_attempts: u64,
    /// Original byte, content, cache and actual connection observations.
    pub fetch: CellFetchReportV1,
}

pub fn fetch_cell_persistent(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    fetch(store, pinned, peers, limits, None)
}

pub fn fetch_cell_persistent_to_file(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    fetch(store, pinned, peers, limits, Some(output))
}

fn fetch(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
    output: Option<&Path>,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    limits.validate()?;
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "configured peer count/duplicates",
    )?;
    let overall = Instant::now() + limits.peer.overall_timeout;
    let requests_left = AtomicU64::new(limits.peer.max_connections);
    let responses = ResponseBudget::new(limits.peer.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.peer.request_timeout,
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let pool = ConnectionPool::new(peers, limits);
    let (manifest, fetch) = fetch_cell_with_schedule(
        store,
        pinned,
        peers,
        limits.peer,
        &transport,
        output,
        FetchSchedule {
            rarest_first: false,
            requests: Some(&pool),
        },
    )?;
    Ok((
        manifest,
        CellPersistentFetchReportV2 {
            request_attempts: limits.max_requests - pool.requests_left.load(Ordering::Relaxed),
            fetch,
        },
    ))
}

struct PersistentConnection {
    stream: TcpStream,
    deadline: Instant,
    requests: u64,
}

pub(super) struct ConnectionPool {
    peers: Vec<(SocketAddr, Mutex<Option<PersistentConnection>>)>,
    pub(super) requests_left: AtomicU64,
    per_connection: u64,
}

struct PinnedRequest {
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
}

impl ConnectionPool {
    pub(super) fn new(peers: &[SocketAddr], limits: CellPersistentPeerLimitsV2) -> Self {
        Self {
            peers: peers.iter().map(|peer| (*peer, Mutex::new(None))).collect(),
            requests_left: AtomicU64::new(limits.max_requests),
            per_connection: limits.max_requests_per_connection,
        }
    }

    fn request_inner(
        &self,
        request: PinnedRequest,
        transport: &RequestContext<'_>,
        deadline: Instant,
        phase: &mut &'static str,
    ) -> CellResultV1<Vec<u8>> {
        let PinnedRequest {
            peer,
            kind,
            digest,
            maximum,
        } = request;
        remaining(deadline)?;
        require(
            !transport.responses.is_quarantined(peer)?,
            "cell peer quarantined",
        )?;
        if transport.responses.received()? == transport.responses.maximum {
            return Err(io::Error::other("CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED").into());
        }
        self.requests_left
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .map_err(|_| io::Error::other("CELL_PERSISTENT_REQUEST_BUDGET_EXHAUSTED"))?;
        let (_, connection) = self
            .peers
            .iter()
            .find(|(address, _)| *address == peer)
            .ok_or(CellErrorV1::Invalid("persistent unconfigured peer"))?;
        *phase = "connection-wait";
        let mut slot = lock_before(connection, deadline)?;
        // A different completed request may have quarantined this peer while
        // this worker waited. A denied peer receives no further request bytes.
        require(
            !transport.responses.is_quarantined(peer)?,
            "cell peer quarantined",
        )?;
        // Other frames share the original release reservation and can finish
        // while this request waits for its peer connection. Actual exhaustion
        // must refuse before either dialing or sending another reused frame.
        // Keep the already charged request attempt; an in-flight reservation
        // alone is not exhaustion and may still return unused capacity.
        transport.responses.require_remaining()?;
        if slot.as_ref().is_some_and(|connection| {
            connection.requests >= self.per_connection || Instant::now() >= connection.deadline
        }) {
            *slot = None;
        }
        if slot.is_none() {
            remaining(deadline)?;
            transport
                .requests_left
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
            *phase = "connect";
            let stream = TcpStream::connect_timeout(&peer, remaining(deadline)?)?;
            *slot = Some(PersistentConnection {
                stream,
                // The attempt's original deadline precedes its mutex wait and
                // dial. Reuse cannot reset it after either activity.
                deadline,
                requests: 0,
            });
        }
        let connection = slot.as_mut().unwrap();
        connection.requests += 1;
        let deadline = deadline.min(connection.deadline);
        let mut query = [0; 37];
        query[..4].copy_from_slice(b"TCQ2");
        query[4] = kind;
        query[5..].copy_from_slice(&digest);
        let result = exchange_frame(
            &mut connection.stream,
            ObjectFrame {
                peer,
                query: &query,
                response_magic: b"TCS2",
                maximum,
            },
            deadline,
            transport,
            phase,
        );
        if result.is_err() || connection.requests == self.per_connection {
            // Never reuse a stream with an incomplete/unconsumed frame. A
            // subsequent explicit request must reserve its own frame and dial.
            *slot = None;
        }
        result
    }
}

impl ObjectRequests for ConnectionPool {
    fn request(
        &self,
        peer: SocketAddr,
        kind: u8,
        digest: CellDigestV1,
        maximum: usize,
        transport: &RequestContext<'_>,
    ) -> (CellResultV1<Vec<u8>>, usize) {
        let started = Instant::now();
        let deadline = transport.overall.min(started + transport.timeout);
        let mut phase = "request-budget";
        let result = self.request_inner(
            PinnedRequest { peer, kind, digest, maximum },
            transport,
            deadline,
            &mut phase,
        ).map_err(|error| match error {
            CellErrorV1::Io(error) => {
                let detail: String = error.to_string().chars().take(192).collect();
                CellErrorV1::Io(io::Error::new(error.kind(), format!(
                    "cell persistent request peer={peer} kind={kind} phase={phase} elapsed_ms={} os={:?}: {detail}",
                    started.elapsed().as_millis(), error.raw_os_error(),
                )))
            }
            error => error,
        });
        // Unlike V1, this profile never retries a failed frame implicitly.
        (result, 1)
    }
}

fn lock_before(
    connection: &Mutex<Option<PersistentConnection>>,
    deadline: Instant,
) -> CellResultV1<MutexGuard<'_, Option<PersistentConnection>>> {
    loop {
        let wait = remaining(deadline)?;
        match connection.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => {
                thread::sleep(Duration::from_millis(1).min(wait));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(CellErrorV1::Invalid("persistent connection poisoned"));
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CellPersistentServeLimitsV2 {
    /// `request_timeout` is the lifetime of an accepted connection, shared by
    /// all its requests. The independent service deadline is never extended.
    pub serving: CellServeLimitsV1,
    /// Read slots admitted across all connections, including incomplete input.
    pub max_requests: u64,
    pub max_requests_per_connection: u64,
}

impl CellPersistentServeLimitsV2 {
    pub fn validate(self) -> CellResultV1<()> {
        self.serving.validate()?;
        validate_requests(self.max_requests, self.max_requests_per_connection)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellPersistentServeReportV2 {
    /// Admitted reads, charged before waiting for a frame. Includes idle/partial
    /// frames; `serving.completed_requests` counts only complete responses.
    pub request_attempts: u64,
    pub serving: CellServeReportV1,
}

type Worker<'scope> = thread::ScopedJoinHandle<'scope, (CellStoreV1, u64)>;

fn join(
    worker: Worker<'_>,
    report: &mut CellServeReportV1,
    failure: &mut Option<CellErrorV1>,
) -> Option<CellStoreV1> {
    match worker.join() {
        Ok((store, complete)) => {
            report.completed_requests += complete;
            Some(store)
        }
        Err(_) => {
            failure.get_or_insert(CellErrorV1::Invalid(
                "persistent cell serving worker panicked",
            ));
            None
        }
    }
}

fn serve_connection(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    shutdown: &AtomicBool,
    deadline: Instant,
    max_requests: u64,
    requests_left: &AtomicU64,
    responses: &ResponseBudget,
) -> u64 {
    let mut completed = 0;
    for _ in 0..max_requests {
        // A fully spent egress quota cannot admit another read slot. Only
        // actual writes spend it; other workers' reservations may be refunded.
        if Instant::now() >= deadline
            || shutdown.load(Ordering::Relaxed)
            || responses.require_remaining().is_err()
        {
            break;
        }
        if requests_left
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_err()
        {
            break;
        }
        if serve_one_wire(
            stream,
            store,
            deadline,
            Some(responses),
            false,
            b"TCQ2",
            b"TCS2",
        )
        .is_err()
        {
            break;
        }
        completed += 1;
    }
    completed
}

/// Explicit bounded V2 service. One reader and at most one in-flight frame per
/// active connection; no admission queue and no socket namespace fallback.
/// Shutdown stops intake and joins existing connections within their fixed
/// deadline. Actual egress exhaustion also stops new connections and frames,
/// while already admitted work is still joined without refunding its attempts.
/// Filesystem/hash calls retain the existing cooperative semantics.
pub fn serve_cells_persistent(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellPersistentServeLimitsV2,
) -> CellResultV1<CellPersistentServeReportV2> {
    limits.validate()?;
    let deadline = Instant::now() + limits.serving.overall_timeout;
    let mut readers = (0..limits.serving.max_workers)
        .map(|_| CellStoreV1::open_read_only(cache).map(Some))
        .collect::<CellResultV1<Vec<_>>>()?;
    listener.set_nonblocking(true)?;
    let responses = ResponseBudget::new(limits.serving.max_response_bytes);
    let requests_left = AtomicU64::new(limits.max_requests);
    let mut report = CellServeReportV1::default();
    thread::scope(|scope| -> CellResultV1<()> {
        let mut active: Vec<Option<Worker<'_>>> =
            (0..limits.serving.max_workers).map(|_| None).collect();
        let mut failure = None;
        while !shutdown.load(Ordering::Relaxed)
            && report.accepted_connections < limits.serving.max_connections
            && requests_left.load(Ordering::Relaxed) > 0
            && responses.received()? < limits.serving.max_response_bytes
            && Instant::now() < deadline
        {
            for (slot, reader) in active.iter_mut().zip(&mut readers) {
                if slot.as_ref().is_some_and(|worker| worker.is_finished()) {
                    *reader = join(slot.take().unwrap(), &mut report, &mut failure);
                }
            }
            if failure.is_some() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    report.accepted_connections += 1;
                    let Some(index) = readers.iter().position(Option::is_some) else {
                        report.overloaded_connections += 1;
                        drop(stream);
                        continue;
                    };
                    let store = readers[index].take().unwrap();
                    let connection_deadline =
                        deadline.min(Instant::now() + limits.serving.request_timeout);
                    let responses = &responses;
                    let requests_left = &requests_left;
                    match thread::Builder::new()
                        .name("cell-persistent-serve".into())
                        .spawn_scoped(scope, move || {
                            let completed = serve_connection(
                                &mut stream,
                                &store,
                                shutdown,
                                connection_deadline,
                                limits.max_requests_per_connection,
                                requests_left,
                                responses,
                            );
                            (store, completed)
                        }) {
                        Ok(worker) => active[index] = Some(worker),
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    }
                    report.peak_active_workers = report
                        .peak_active_workers
                        .max(active.iter().filter(|worker| worker.is_some()).count());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match serving::wait_for_listener(listener, deadline) {
                        Ok(_) => (),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => {
                    failure = Some(error.into());
                    break;
                }
            }
        }
        for worker in active.into_iter().flatten() {
            drop(join(worker, &mut report, &mut failure));
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })?;
    report.sent_response_bytes = responses.received()?;
    Ok(CellPersistentServeReportV2 {
        request_attempts: limits.max_requests - requests_left.load(Ordering::Relaxed),
        serving: report,
    })
}

#[cfg(test)]
mod tests;
