//! Explicit sequential connection reuse under separate V2 and V3 profiles.
//!
//! Each request is `TCQ2 || kind:u8 || pinned_digest:32`; each response is
//! `TCS2 || status:u8 || length:u32be || bytes`. Kinds and object bytes retain
//! their TCM1/chunk meaning. V1 and inventory magic are rejected, never retried
//! under another namespace. There is no multiplexing or implicit activation.
//! Every connection has one fixed absolute deadline established at dial/accept.
//! A failed or partial frame discards that connection without retrying the frame.
//! V3 uses TCQ3/TCS3 only, with the same object kinds plus kind 3 for inventory:
//! pinned TCM1 ID, start:u32be, count:u16be (1..=256), and the canonical bitfield.
//! Inventory, objects and every release member share the original reservation.

use super::*;
use std::sync::{MutexGuard, TryLockError};

const MAX_REQUESTS: u64 = 100_000;

#[derive(Clone, Copy, Eq, PartialEq)]
enum WireProfile {
    OrderedV2,
    RarestFirstV3,
}

impl WireProfile {
    fn request_magic(self) -> &'static [u8; 4] {
        match self {
            Self::OrderedV2 => b"TCQ2",
            Self::RarestFirstV3 => b"TCQ3",
        }
    }

    fn response_magic(self) -> &'static [u8; 4] {
        match self {
            Self::OrderedV2 => b"TCS2",
            Self::RarestFirstV3 => b"TCS3",
        }
    }
}

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
    fetch(store, pinned, peers, limits, None, WireProfile::OrderedV2)
}

pub fn fetch_cell_persistent_to_file(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    fetch(
        store,
        pinned,
        peers,
        limits,
        Some(output),
        WireProfile::OrderedV2,
    )
}

/// Explicit TCQ3/TCS3 inventory and verified object requests on the same pool.
/// Inventory remains a scheduling hint; complete payload verification is required.
pub fn fetch_cell_persistent_rarest_first(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    fetch(
        store,
        pinned,
        peers,
        limits,
        None,
        WireProfile::RarestFirstV3,
    )
}

/// The explicit V3 profile with the original create-only publication boundary.
pub fn fetch_cell_persistent_rarest_first_to_file(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellPersistentFetchReportV2)> {
    fetch(
        store,
        pinned,
        peers,
        limits,
        Some(output),
        WireProfile::RarestFirstV3,
    )
}

fn fetch(
    store: &CellStoreV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellPersistentPeerLimitsV2,
    output: Option<&Path>,
    profile: WireProfile,
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
        cancelled: None,
        timeout: limits.peer.request_timeout,
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let pool = ConnectionPool::with_profile(peers, limits, profile);
    let (manifest, fetch) = fetch_cell_with_schedule(
        store,
        pinned,
        peers,
        limits.peer,
        &transport,
        output,
        FetchSchedule {
            rarest_first: profile == WireProfile::RarestFirstV3,
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
    profile: WireProfile,
}

struct PinnedRequest {
    peer: SocketAddr,
    kind: u8,
    digest: CellDigestV1,
    maximum: usize,
    page: Option<(u32, u16)>,
}

impl ConnectionPool {
    pub(super) fn new(peers: &[SocketAddr], limits: CellPersistentPeerLimitsV2) -> Self {
        Self::with_profile(peers, limits, WireProfile::OrderedV2)
    }

    pub(super) fn new_rarest_first(
        peers: &[SocketAddr],
        limits: CellPersistentPeerLimitsV2,
    ) -> Self {
        Self::with_profile(peers, limits, WireProfile::RarestFirstV3)
    }

    fn with_profile(
        peers: &[SocketAddr],
        limits: CellPersistentPeerLimitsV2,
        profile: WireProfile,
    ) -> Self {
        Self {
            peers: peers.iter().map(|peer| (*peer, Mutex::new(None))).collect(),
            requests_left: AtomicU64::new(limits.max_requests),
            per_connection: limits.max_requests_per_connection,
            profile,
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
            page,
        } = request;
        transport.check_cancelled()?;
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
        let mut slot = lock_before(connection, deadline, transport)?;
        transport.check_cancelled()?;
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
            transport.check_cancelled()?;
            remaining(deadline)?;
            transport
                .requests_left
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
            *phase = "connect";
            let stream = TcpStream::connect_timeout(&peer, remaining(deadline)?)?;
            transport.check_cancelled()?;
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
        let mut query = [0; 43];
        query[..4].copy_from_slice(self.profile.request_magic());
        query[4] = kind;
        query[5..37].copy_from_slice(&digest);
        let query_length = if let Some((start, count)) = page {
            query[37..41].copy_from_slice(&start.to_be_bytes());
            query[41..43].copy_from_slice(&count.to_be_bytes());
            43
        } else {
            37
        };
        let result = exchange_frame(
            &mut connection.stream,
            ObjectFrame {
                peer,
                query: &query[..query_length],
                response_magic: self.profile.response_magic(),
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

    fn request_observed(
        &self,
        request: PinnedRequest,
        transport: &RequestContext<'_>,
    ) -> (CellResultV1<Vec<u8>>, usize) {
        let peer = request.peer;
        let kind = request.kind;
        let started = Instant::now();
        let deadline = transport.overall.min(started + transport.timeout);
        let mut phase = "request-budget";
        let result = self.request_inner(request, transport, deadline, &mut phase).map_err(|error| match error {
            CellErrorV1::Io(error) => {
                let detail: String = error.to_string().chars().take(192).collect();
                CellErrorV1::Io(io::Error::new(error.kind(), format!(
                    "cell persistent request peer={peer} kind={kind} phase={phase} elapsed_ms={} os={:?}: {detail}",
                    started.elapsed().as_millis(), error.raw_os_error(),
                )))
            }
            error => error,
        });
        // Both profiles refuse implicit retries or alternate wire namespaces.
        (result, 1)
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
        self.request_observed(
            PinnedRequest {
                peer,
                kind,
                digest,
                maximum,
                page: None,
            },
            transport,
        )
    }

    fn inventory_page(
        &self,
        peer: SocketAddr,
        manifest: CellDigestV1,
        start: usize,
        count: usize,
        transport: &RequestContext<'_>,
    ) -> CellResultV1<Vec<u8>> {
        require(
            self.profile == WireProfile::RarestFirstV3,
            "persistent inventory profile",
        )?;
        require(
            (1..=availability::MAX_PAGE_CHUNKS).contains(&count) && start <= u32::MAX as usize,
            "availability page bound",
        )?;
        let (bytes, _) = self.request_observed(
            PinnedRequest {
                peer,
                kind: 3,
                digest: manifest,
                maximum: count.div_ceil(8),
                page: Some((start as u32, count as u16)),
            },
            transport,
        );
        availability::validate_page(peer, count, bytes?, transport)
    }
}

fn lock_before<'a>(
    connection: &'a Mutex<Option<PersistentConnection>>,
    deadline: Instant,
    transport: &RequestContext<'_>,
) -> CellResultV1<MutexGuard<'a, Option<PersistentConnection>>> {
    loop {
        transport.check_cancelled()?;
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
    serve_connection_profile(
        stream,
        store,
        shutdown,
        deadline,
        (max_requests, WireProfile::OrderedV2),
        requests_left,
        responses,
    )
}

fn serve_connection_profile(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    shutdown: &AtomicBool,
    deadline: Instant,
    request_profile: (u64, WireProfile),
    requests_left: &AtomicU64,
    responses: &ResponseBudget,
) -> u64 {
    let (max_requests, profile) = request_profile;
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
            profile.request_magic(),
            profile.response_magic(),
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
    serve_cells_persistent_inner(
        listener,
        cache,
        shutdown,
        limits,
        None,
        WireProfile::OrderedV2,
    )
}

/// Announce only after all bounded readers and the listener are usable.
/// Startup and the observation share the original service deadline; no probe
/// socket or frame is charged to the peer's connection/request reservations.
pub fn serve_cells_persistent_with_ready(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellPersistentServeLimitsV2,
    ready: &dyn Fn() -> CellResultV1<()>,
) -> CellResultV1<CellPersistentServeReportV2> {
    serve_cells_persistent_inner(
        listener,
        cache,
        shutdown,
        limits,
        Some(ready),
        WireProfile::OrderedV2,
    )
}

/// Explicit TCQ3/TCS3 service. Bounded inventory and object reads share the
/// same worker, connection lifetime, frame reservation and actual egress quota.
/// V1, V2 and TCI1 requests are rejected without a namespace fallback.
pub fn serve_cells_persistent_rarest_first(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellPersistentServeLimitsV2,
) -> CellResultV1<CellPersistentServeReportV2> {
    serve_cells_persistent_inner(
        listener,
        cache,
        shutdown,
        limits,
        None,
        WireProfile::RarestFirstV3,
    )
}

/// V3 Ready is observed under the original service budget without a probe dial.
pub fn serve_cells_persistent_rarest_first_with_ready(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellPersistentServeLimitsV2,
    ready: &dyn Fn() -> CellResultV1<()>,
) -> CellResultV1<CellPersistentServeReportV2> {
    serve_cells_persistent_inner(
        listener,
        cache,
        shutdown,
        limits,
        Some(ready),
        WireProfile::RarestFirstV3,
    )
}

fn serve_cells_persistent_inner(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellPersistentServeLimitsV2,
    ready: Option<&dyn Fn() -> CellResultV1<()>>,
    profile: WireProfile,
) -> CellResultV1<CellPersistentServeReportV2> {
    limits.validate()?;
    let deadline = Instant::now() + limits.serving.overall_timeout;
    let mut readers = (0..limits.serving.max_workers)
        .map(|_| CellStoreV1::open_read_only(cache).map(Some))
        .collect::<CellResultV1<Vec<_>>>()?;
    listener.set_nonblocking(true)?;
    serving::announce_service_ready(ready, shutdown, deadline, limits.serving.max_response_bytes)?;
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
                            let completed = match profile {
                                WireProfile::OrderedV2 => serve_connection(
                                    &mut stream,
                                    &store,
                                    shutdown,
                                    connection_deadline,
                                    limits.max_requests_per_connection,
                                    requests_left,
                                    responses,
                                ),
                                WireProfile::RarestFirstV3 => serve_connection_profile(
                                    &mut stream,
                                    &store,
                                    shutdown,
                                    connection_deadline,
                                    (limits.max_requests_per_connection, profile),
                                    requests_left,
                                    responses,
                                ),
                            };
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

#[cfg(test)]
mod rarest_tests;
