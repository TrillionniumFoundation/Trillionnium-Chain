//! Explicit, bounded TCP transport for the pinned Cell BEP52 profile.
//!
//! TCP endpoints are caller-approved inputs. Discovery hints are never dialled
//! as TCP peers automatically; an opt-in bounded DHT client can follow admitted
//! UDP node hints. No listener, advertisement or background job is opened.
//! The transport is plaintext and provides neither peer identity nor FinalUse.

use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256, Sha512};

use super::{
    require, store::verify_chunk_with_deadline, CellBep52BindingV1, CellDigestV1, CellErrorV1,
    CellResultV1, CellStoreV1, PinnedCellVersionContentV2, MAX_CELL_BEP52_INFO_BYTES_V1,
};

mod bencode;
mod dht;
mod release;
pub use dht::{
    lookup_cell_bep52_dht_peers, query_cell_bep52_dht_peers, CellBep52DhtEndpointPolicyV1,
    CellBep52DhtHintsV1, CellBep52DhtLookupReportV1, CellBep52DhtLookupStopV1,
    CellBep52DhtNodeHintV1, MAX_CELL_BEP52_DHT_RESPONSE_BYTES_V1,
};
pub use release::{
    CellBep52ReleaseLimitsV2, CellBep52ReleasePlanV2, CellBep52ReleaseReadUsageV2,
    CellBep52ReleaseSessionV2, CELL_BEP52_RELEASE_PROFILE_V2, MAX_CELL_BEP52_RELEASE_CHUNKS_V2,
    MAX_CELL_BEP52_RELEASE_PAYLOAD_V2,
};
#[cfg(test)]
mod tests;

use bencode::{decode, Value};

pub const CELL_BEP52_PEER_PROFILE_V1: &str = "cell-bep52-pinned-tcp-v1";
pub const MAX_CELL_BEP52_PEER_FRAME_BYTES_V1: usize = 17_408;
const OUR_METADATA_ID: u8 = 1;
const MAX_SESSION_BYTES: u64 = 8 * 268_435_456 + 8 * 1_048_576;
const IO_POLL: Duration = Duration::from_millis(25);

/// One caller-owned reservation. `deadline` is absolute and is never renewed
/// for a new peer, piece, metadata reply, cache write or final readback.
#[derive(Clone, Copy, Debug)]
pub struct CellBep52PeerLimitsV1 {
    pub deadline: Instant,
    pub request_timeout: Duration,
    pub max_connections: u64,
    pub max_received_bytes: u64,
    pub max_sent_bytes: u64,
    /// Combined incoming/outgoing frames; keepalives count too.
    pub max_messages: u64,
}

impl CellBep52PeerLimitsV1 {
    fn validate(self) -> CellResultV1<()> {
        require(
            (Duration::from_millis(10)..=Duration::from_secs(30)).contains(&self.request_timeout),
            "BEP52 request timeout",
        )?;
        require(
            (1..=8).contains(&self.max_connections),
            "BEP52 connection bound",
        )?;
        require(
            self.max_received_bytes <= MAX_SESSION_BYTES,
            "BEP52 receive byte bound",
        )?;
        require(
            self.max_sent_bytes <= MAX_SESSION_BYTES,
            "BEP52 send byte bound",
        )?;
        require(
            (1..=100_000).contains(&self.max_messages),
            "BEP52 message bound",
        )?;
        let now = Instant::now();
        require(
            self.deadline > now && self.deadline.duration_since(now) <= Duration::from_secs(86_400),
            "BEP52 original deadline",
        )
    }
}

/// Observable after both success and failure. Byte counters are actual socket
/// bytes, including rejected/partial messages, excluding TCP/IP overhead.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellBep52PeerUsageV1 {
    pub connection_attempts: u64,
    pub dht_query_attempts: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub received_messages: u64,
    pub sent_messages: u64,
    pub refused_connections: u64,
    pub refused_dht_queries: u64,
    pub completed_fetches: u64,
}

/// Mutable, non-cloneable accounting owner. Reuse it on a continuation; creating
/// another session is a separate caller-authorized reservation, not a retry.
pub struct CellBep52PeerSessionV1 {
    operation_id: CellDigestV1,
    limits: CellBep52PeerLimitsV1,
    usage: CellBep52PeerUsageV1,
    cancelled: Arc<AtomicBool>,
    cancellation_latched: bool,
    refused: BTreeSet<SocketAddr>,
    refusals: Vec<(SocketAddr, String)>,
    dht_transactions: BTreeSet<[u8; 8]>,
}

impl CellBep52PeerSessionV1 {
    pub fn new(operation_id: CellDigestV1, limits: CellBep52PeerLimitsV1) -> CellResultV1<Self> {
        require(operation_id != [0; 32], "BEP52 operation identity")?;
        limits.validate()?;
        Ok(Self {
            operation_id,
            limits,
            usage: CellBep52PeerUsageV1::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            cancellation_latched: false,
            refused: BTreeSet::new(),
            refusals: Vec::new(),
            dht_transactions: BTreeSet::new(),
        })
    }

    pub fn operation_id(&self) -> CellDigestV1 {
        self.operation_id
    }
    pub fn usage(&self) -> &CellBep52PeerUsageV1 {
        &self.usage
    }
    pub fn deadline(&self) -> Instant {
        self.limits.deadline
    }
    pub fn cancellation_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
    /// At most eight original failure descriptions, each capped at 256 chars.
    /// A refusal includes transport or local-store failure, not a fraud verdict.
    pub fn refusals(&self) -> &[(SocketAddr, String)] {
        &self.refusals
    }

    pub(super) fn refused_peer(&self, peer: SocketAddr) -> bool {
        self.refused.contains(&peer)
    }

    pub(super) fn record_peer_refusal(&mut self, peer: SocketAddr, error: &CellErrorV1) {
        self.record_connection_refusal(Some(peer), error);
    }

    pub(super) fn record_connection_refusal(
        &mut self,
        peer: Option<SocketAddr>,
        error: &CellErrorV1,
    ) {
        self.usage.refused_connections += 1;
        if let Some(peer) = peer {
            self.refused.insert(peer);
            self.refusals
                .push((peer, error.to_string().chars().take(256).collect()));
        }
    }

    pub(super) fn record_completed_fetch(&mut self) -> CellResultV1<()> {
        self.usage.completed_fetches = self
            .usage
            .completed_fetches
            .checked_add(1)
            .ok_or(CellErrorV1::Invalid("BEP52 completed fetch counter"))?;
        Ok(())
    }

    pub(super) fn check(&mut self, deadline: Instant) -> CellResultV1<()> {
        self.cancellation_latched |= self.cancelled.load(Ordering::Acquire);
        require(!self.cancellation_latched, "BEP52 operation cancelled")?;
        require(
            Instant::now() < deadline.min(self.limits.deadline),
            "BEP52 original deadline",
        )
    }

    pub(super) fn request_deadline(&mut self) -> CellResultV1<Instant> {
        self.check(self.limits.deadline)?;
        Ok((Instant::now() + self.limits.request_timeout).min(self.limits.deadline))
    }

    pub(super) fn connection(&mut self) -> CellResultV1<()> {
        self.check(self.limits.deadline)?;
        require(
            self.usage.received_bytes < self.limits.max_received_bytes
                && self.usage.sent_bytes < self.limits.max_sent_bytes,
            "BEP52 connection byte reservation",
        )?;
        require(
            self.usage.connection_attempts + self.usage.dht_query_attempts
                < self.limits.max_connections,
            "BEP52 connection budget",
        )?;
        self.usage.connection_attempts += 1;
        Ok(())
    }

    fn frame(&mut self, outgoing: bool) -> CellResultV1<()> {
        require(
            self.usage.received_messages + self.usage.sent_messages < self.limits.max_messages,
            "BEP52 message budget",
        )?;
        if outgoing {
            self.usage.sent_messages += 1;
        } else {
            self.usage.received_messages += 1;
        }
        Ok(())
    }

    pub(super) fn read_exact(
        &mut self,
        stream: &mut TcpStream,
        bytes: &mut [u8],
        deadline: Instant,
        eof: bool,
    ) -> CellResultV1<bool> {
        let mut filled = 0;
        while filled < bytes.len() {
            self.check(deadline)?;
            let allowance = (self.limits.max_received_bytes - self.usage.received_bytes)
                .min((bytes.len() - filled) as u64) as usize;
            require(allowance > 0, "BEP52 receive byte budget")?;
            stream.set_read_timeout(Some(
                IO_POLL
                    .min(deadline.saturating_duration_since(Instant::now()))
                    .max(Duration::from_micros(1)),
            ))?;
            match stream.read(&mut bytes[filled..filled + allowance]) {
                Ok(0) if filled == 0 && eof => return Ok(false),
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "BEP52 partial frame").into(),
                    )
                }
                Ok(count) => {
                    self.usage.received_bytes += count as u64;
                    filled += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.check(deadline)?;
        Ok(true)
    }

    pub(super) fn write_all(
        &mut self,
        stream: &mut TcpStream,
        bytes: &[u8],
        deadline: Instant,
    ) -> CellResultV1<()> {
        let mut written = 0;
        while written < bytes.len() {
            self.check(deadline)?;
            let allowance = (self.limits.max_sent_bytes - self.usage.sent_bytes)
                .min((bytes.len() - written) as u64) as usize;
            require(allowance > 0, "BEP52 send byte budget")?;
            stream.set_write_timeout(Some(
                IO_POLL
                    .min(deadline.saturating_duration_since(Instant::now()))
                    .max(Duration::from_micros(1)),
            ))?;
            match stream.write(&bytes[written..written + allowance]) {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "BEP52 write stopped").into(),
                    )
                }
                Ok(count) => {
                    self.usage.sent_bytes += count as u64;
                    written += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.check(deadline)
    }

    pub(super) fn read_frame(
        &mut self,
        stream: &mut TcpStream,
        deadline: Instant,
        eof: bool,
    ) -> CellResultV1<Option<Vec<u8>>> {
        self.frame(false)?;
        let mut header = [0; 4];
        if !self.read_exact(stream, &mut header, deadline, eof)? {
            return Ok(None);
        }
        let length = u32::from_be_bytes(header) as usize;
        require(
            length <= MAX_CELL_BEP52_PEER_FRAME_BYTES_V1,
            "BEP52 frame size",
        )?;
        require(
            length as u64 <= self.limits.max_received_bytes - self.usage.received_bytes,
            "BEP52 receive byte budget",
        )?;
        let mut body = vec![0; length];
        self.read_exact(stream, &mut body, deadline, false)?;
        Ok(Some(body))
    }

    pub(super) fn send_frame(
        &mut self,
        stream: &mut TcpStream,
        body: &[u8],
        deadline: Instant,
    ) -> CellResultV1<()> {
        require(
            body.len() <= MAX_CELL_BEP52_PEER_FRAME_BYTES_V1,
            "BEP52 frame size",
        )?;
        self.frame(true)?;
        self.write_all(stream, &(body.len() as u32).to_be_bytes(), deadline)?;
        self.write_all(stream, body, deadline)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52FetchReportV1 {
    pub manifest_id: CellDigestV1,
    pub info_hash: CellDigestV1,
    pub payload_sha256: CellDigestV1,
    pub payload_bytes: u64,
    pub cached_chunks: usize,
    pub downloaded_chunks: usize,
    pub downloaded_bytes: u64,
    pub supplying_peers: BTreeSet<SocketAddr>,
}

/// Fetch using explicit endpoints, retaining already verified chunks on failure.
/// Only the independently constructed `binding` selects content/context. Success
/// requires a fresh complete ordered payload readback from the ordinary CAS.
pub fn fetch_cell_bep52(
    store: &CellStoreV1,
    binding: &CellBep52BindingV1,
    peers: &[SocketAddr],
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52FetchReportV1> {
    fetch_pinned(
        store,
        FetchPlan {
            binding,
            content: None,
        },
        peers,
        local_peer_id,
        session,
    )
}

/// Fetch one declared manifest under an independently pinned TCV2 content view.
/// Exact full manifest membership is checked before cache or socket activity.
/// Cache hits and received chunks must satisfy their strong commitment before
/// publication, and one final ordered scan checks both full payload digests.
/// This remains a single-manifest observation, not complete-version approval,
/// publisher authentication, current permission or a FinalUse grant.
pub fn fetch_cell_bep52_with_content(
    store: &CellStoreV1,
    binding: &CellBep52BindingV1,
    content: &PinnedCellVersionContentV2<'_>,
    peers: &[SocketAddr],
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52FetchReportV1> {
    fetch_pinned(
        store,
        FetchPlan {
            binding,
            content: Some(content),
        },
        peers,
        local_peer_id,
        session,
    )
}

#[derive(Clone, Copy)]
struct FetchPlan<'a, 'content> {
    binding: &'a CellBep52BindingV1,
    content: Option<&'a PinnedCellVersionContentV2<'content>>,
}

impl FetchPlan<'_, '_> {
    fn verify_chunk(&self, index: usize, bytes: &[u8], deadline: Instant) -> CellResultV1<()> {
        if let Some(content) = self.content {
            content.verify_chunk(self.binding.manifest_id(), index, bytes)?;
        } else {
            verify_chunk_with_deadline(
                &self.binding.manifest().chunks()[index],
                bytes,
                Some(deadline),
            )?;
        }
        require(Instant::now() < deadline, "BEP52 original deadline")
    }

    fn verify_complete(
        &self,
        store: &CellStoreV1,
        session: &mut CellBep52PeerSessionV1,
    ) -> CellResultV1<()> {
        let manifest = self.binding.manifest();
        let Some(content) = self.content else {
            return store.verify_complete_until(manifest, session.limits.deadline);
        };
        let expected = content.payload_sha512(self.binding.manifest_id())?;
        let mut legacy = Sha256::new();
        let mut strong = Sha512::new();
        strong.update(b"TRNM/Cell/PayloadContent/v2\0");
        strong.update(manifest.size().to_be_bytes());
        let mut total = 0_u64;
        // One scan of the actual ordered CAS bytes, retaining the original
        // complete-payload SHA-256 check alongside the independently pinned
        // SHA-512 check. No successful marker or prior buffer substitutes.
        for (index, chunk) in manifest.chunks().iter().enumerate() {
            session.check(session.limits.deadline)?;
            let bytes = store
                .chunk_with_deadline(chunk.sha256, Some(session.limits.deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            self.verify_chunk(index, &bytes, session.limits.deadline)?;
            legacy.update(&bytes);
            strong.update(&bytes);
            total += bytes.len() as u64;
            session.check(session.limits.deadline)?;
        }
        require(
            total == manifest.size()
                && <[u8; 32]>::from(legacy.finalize()) == manifest.payload_sha256(),
            "BEP52 complete payload digest",
        )?;
        require(
            <[u8; 64]>::from(strong.finalize()) == expected,
            "BEP52 complete strong payload digest",
        )?;
        session.check(session.limits.deadline)
    }
}

fn fetch_pinned(
    store: &CellStoreV1,
    plan: FetchPlan<'_, '_>,
    peers: &[SocketAddr],
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52FetchReportV1> {
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "BEP52 endpoint count/duplicates",
    )?;
    require(
        peers.iter().all(|peer| {
            peer.port() != 0 && !peer.ip().is_unspecified() && !peer.ip().is_multicast()
        }),
        "BEP52 explicit endpoint",
    )?;
    session.check(session.limits.deadline)?;
    let binding = plan.binding;
    let manifest = binding.manifest();
    if let Some(content) = plan.content {
        content.verify_manifest(manifest)?;
        session.check(session.limits.deadline)?;
    }
    let mut missing = BTreeSet::new();
    let mut report = CellBep52FetchReportV1 {
        manifest_id: binding.manifest_id(),
        info_hash: binding.info_hash(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        cached_chunks: 0,
        downloaded_chunks: 0,
        downloaded_bytes: 0,
        supplying_peers: BTreeSet::new(),
    };
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        session.check(session.limits.deadline)?;
        if let Some(bytes) =
            store.chunk_with_deadline(chunk.sha256, Some(session.limits.deadline))?
        {
            plan.verify_chunk(index, &bytes, session.limits.deadline)?;
            session.check(session.limits.deadline)?;
            report.cached_chunks += 1;
        } else {
            missing.insert(chunk.sha256);
        }
    }
    store.put_manifest_with_deadline(
        binding.manifest_id(),
        &manifest.encode(),
        Some(session.limits.deadline),
    )?;
    for peer in peers {
        if missing.is_empty() {
            break;
        }
        session.check(session.limits.deadline)?;
        if session.refused.contains(peer) {
            continue;
        }
        session.connection()?;
        let result = fetch_peer(
            store,
            plan,
            *peer,
            local_peer_id,
            session,
            &mut missing,
            &mut report,
        );
        if let Err(error) = result {
            session.usage.refused_connections += 1;
            session.refused.insert(*peer);
            session
                .refusals
                .push((*peer, error.to_string().chars().take(256).collect()));
        }
        // Local failure/cancellation/expiry remains visible through usage and
        // cannot be erased by successful data from another peer.
        session.check(session.limits.deadline)?;
    }
    require(missing.is_empty(), "BEP52 pinned chunks unavailable")?;
    plan.verify_complete(store, session)?;
    session.check(session.limits.deadline)?;
    report.downloaded_chunks = manifest.chunks().len() - report.cached_chunks;
    session.usage.completed_fetches += 1;
    Ok(report)
}

fn fetch_peer(
    store: &CellStoreV1,
    plan: FetchPlan<'_, '_>,
    peer: SocketAddr,
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
    missing: &mut BTreeSet<CellDigestV1>,
    report: &mut CellBep52FetchReportV1,
) -> CellResultV1<()> {
    let binding = plan.binding;
    let deadline = session.request_deadline()?;
    let mut stream = TcpStream::connect_timeout(
        &peer,
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_micros(1)),
    )?;
    stream.set_nodelay(true)?;
    session.write_all(&mut stream, &handshake(binding, local_peer_id), deadline)?;
    receive_handshake(&mut stream, binding, session, deadline)?;
    session.send_frame(&mut stream, &extension_handshake(None), deadline)?;
    let mut state = PeerState::new(binding.manifest().chunks().len());
    let metadata_id = loop {
        let body = session.read_frame(&mut stream, deadline, false)?.unwrap();
        if body.starts_with(&[20, 0]) {
            let (id, size) = parse_extension_handshake(&body[2..])?;
            require(
                size == Some(binding.info_bytes().len() as u64),
                "BEP52 metadata size pin",
            )?;
            break id.ok_or(CellErrorV1::Invalid("BEP52 metadata extension absent"))?;
        }
        state.control(&body)?;
    };
    let deadline = session.request_deadline()?;
    session.send_frame(
        &mut stream,
        &metadata_message(metadata_id, 0, 0, None, &[]),
        deadline,
    )?;
    loop {
        let body = session.read_frame(&mut stream, deadline, false)?.unwrap();
        if body.starts_with(&[20, OUR_METADATA_ID]) {
            let (message, used) = decode(&body[2..])?;
            let kind = message.number(b"msg_type")?;
            if kind > 2 {
                continue;
            }
            require(
                message.number(b"piece")? == 0,
                "BEP52 metadata piece correlation",
            )?;
            require(kind == 1, "BEP52 metadata refused")?;
            require(
                message.number(b"total_size")? == binding.info_bytes().len() as u64,
                "BEP52 metadata total size",
            )?;
            let metadata = &body[2 + used..];
            require(
                metadata.len() <= MAX_CELL_BEP52_INFO_BYTES_V1,
                "BEP52 metadata bound",
            )?;
            require(
                <[u8; 32]>::from(Sha256::digest(metadata)) == binding.info_hash(),
                "BEP52 full metadata infohash",
            )?;
            binding.verify_info_bytes(metadata)?;
            break;
        }
        state.control(&body)?;
    }
    let deadline = session.request_deadline()?;
    session.send_frame(&mut stream, &[2], deadline)?;
    for (index, chunk) in binding.manifest().chunks().iter().enumerate() {
        if !missing.contains(&chunk.sha256) || state.known_absent(index) {
            continue;
        }
        let deadline = session.request_deadline()?;
        while state.choked {
            state.control(&session.read_frame(&mut stream, deadline, false)?.unwrap())?;
        }
        let request = block_request(6, index as u32, 0, chunk.size);
        session.send_frame(&mut stream, &request, deadline)?;
        loop {
            let body = session.read_frame(&mut stream, deadline, false)?.unwrap();
            if body.first() == Some(&7) {
                require(
                    body.len() == 9 + chunk.size as usize,
                    "BEP52 piece response length",
                )?;
                require(
                    read_u32(&body[1..5]) == index as u32 && read_u32(&body[5..9]) == 0,
                    "BEP52 piece correlation",
                )?;
                plan.verify_chunk(index, &body[9..], session.limits.deadline)?;
                session.check(deadline)?;
                store.put_chunk_with_deadline(chunk, &body[9..], Some(session.limits.deadline))?;
                missing.remove(&chunk.sha256);
                report.downloaded_bytes += chunk.size as u64;
                report.supplying_peers.insert(peer);
                break;
            }
            if body.first() == Some(&16) {
                require(
                    body.len() == request.len() && body[1..] == request[1..],
                    "BEP52 reject correlation",
                )?;
                break;
            }
            state.control(&body)?;
        }
    }
    let deadline = session.request_deadline()?;
    session.send_frame(&mut stream, &[3], deadline)?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

/// Prepared actual complete CAS readback. Preparation does not bind a listener
/// or advertise. Each served chunk is read and hashed again, so stale preparation
/// cannot turn changed local bytes into an accepted response.
pub struct CellBep52SeedV1<'a> {
    store: &'a CellStoreV1,
    binding: &'a CellBep52BindingV1,
    levels: Vec<Vec<CellDigestV1>>,
}

impl<'a> CellBep52SeedV1<'a> {
    pub fn prepare(
        store: &'a CellStoreV1,
        binding: &'a CellBep52BindingV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        store.verify_complete_until(binding.manifest(), deadline)?;
        let mut leaves: Vec<_> = binding
            .manifest()
            .chunks()
            .iter()
            .map(|chunk| chunk.sha256)
            .collect();
        leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            require(Instant::now() < deadline, "BEP52 seed preparation deadline")?;
            let parent = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let mut hash = Sha256::new();
                    hash.update(pair[0]);
                    hash.update(pair[1]);
                    hash.finalize().into()
                })
                .collect();
            levels.push(parent);
        }
        require(Instant::now() < deadline, "BEP52 seed preparation deadline")?;
        require(
            levels.last().unwrap()[0] == binding.pieces_root(),
            "BEP52 seed root",
        )?;
        Ok(Self {
            store,
            binding,
            levels,
        })
    }

    /// Serve one already accepted TCP connection in the owner's same finite
    /// reservation. There is no accept loop, detached worker or automatic retry.
    pub fn serve_connection(
        &self,
        mut stream: TcpStream,
        local_peer_id: [u8; 20],
        session: &mut CellBep52PeerSessionV1,
    ) -> CellResultV1<()> {
        session.connection()?;
        let result = self.serve_inner(&mut stream, local_peer_id, session);
        if let Err(error) = &result {
            session.usage.refused_connections += 1;
            if let Ok(peer) = stream.peer_addr() {
                session
                    .refusals
                    .push((peer, error.to_string().chars().take(256).collect()));
            }
        }
        result
    }

    fn serve_inner(
        &self,
        stream: &mut TcpStream,
        local_peer_id: [u8; 20],
        session: &mut CellBep52PeerSessionV1,
    ) -> CellResultV1<()> {
        stream.set_nodelay(true)?;
        let deadline = session.request_deadline()?;
        receive_handshake(stream, self.binding, session, deadline)?;
        session.write_all(stream, &handshake(self.binding, local_peer_id), deadline)?;
        session.send_frame(
            stream,
            &extension_handshake(Some(self.binding.info_bytes().len())),
            deadline,
        )?;
        let count = self.binding.manifest().chunks().len();
        let mut bitfield = vec![0xff; 1 + count.div_ceil(8)];
        bitfield[0] = 5;
        if !count.is_multiple_of(8) {
            *bitfield.last_mut().unwrap() <<= 8 - count % 8;
        }
        session.send_frame(stream, &bitfield, deadline)?;
        let mut their_metadata_id = None;
        let mut have_extension = false;
        let mut interested = false;
        let mut state = PeerState::new(count);
        loop {
            let deadline = session.request_deadline()?;
            let Some(body) = session.read_frame(stream, deadline, true)? else {
                return Ok(());
            };
            match body.first().copied() {
                None => (),
                Some(20) if body.get(1) == Some(&0) => {
                    if !have_extension {
                        (their_metadata_id, _) = parse_extension_handshake(&body[2..])?;
                        have_extension = true;
                    }
                    // BEP10 permits ignoring later capability handshakes. The
                    // negotiated identifiers remain fixed for this connection.
                }
                Some(20) if body.get(1) == Some(&OUR_METADATA_ID) => {
                    require(have_extension, "BEP52 metadata before negotiation")?;
                    let (message, used) = decode(&body[2..])?;
                    let kind = message.number(b"msg_type")?;
                    if kind > 2 {
                        continue;
                    }
                    require(
                        kind == 0 && used + 2 == body.len(),
                        "BEP52 metadata request",
                    )?;
                    let piece = message.number(b"piece")?;
                    let remote = their_metadata_id.ok_or(CellErrorV1::Invalid(
                        "BEP52 return metadata extension absent",
                    ))?;
                    let info = self.binding.info_bytes();
                    let response = if piece == 0 {
                        metadata_message(remote, 1, piece, Some(info.len()), &info)
                    } else {
                        metadata_message(remote, 2, piece, None, &[])
                    };
                    session.send_frame(stream, &response, deadline)?;
                }
                Some(2 | 3) => {
                    require(body.len() == 1, "BEP52 interest length")?;
                    interested = body[0] == 2;
                    if interested {
                        session.send_frame(stream, &[1], deadline)?;
                    }
                }
                Some(6) => {
                    let (index, begin, length) = parse_block_request(&body)?;
                    let chunk = self.binding.manifest().chunks().get(index as usize);
                    let valid = interested
                        && chunk.is_some_and(|chunk| {
                            length > 0
                                && length <= 16_384
                                && begin
                                    .checked_add(length)
                                    .is_some_and(|end| end <= chunk.size)
                        });
                    if !valid {
                        let mut rejection = body;
                        rejection[0] = 16;
                        session.send_frame(stream, &rejection, deadline)?;
                        continue;
                    }
                    let chunk = chunk.unwrap();
                    let Some(bytes) = self
                        .store
                        .chunk_with_deadline(chunk.sha256, Some(session.limits.deadline))?
                    else {
                        let mut rejection = body;
                        rejection[0] = 16;
                        session.send_frame(stream, &rejection, deadline)?;
                        continue;
                    };
                    verify_chunk_with_deadline(chunk, &bytes, Some(session.limits.deadline))?;
                    let mut response = Vec::with_capacity(9 + length as usize);
                    response.push(7);
                    response.extend_from_slice(&index.to_be_bytes());
                    response.extend_from_slice(&begin.to_be_bytes());
                    response.extend_from_slice(&bytes[begin as usize..(begin + length) as usize]);
                    session.send_frame(stream, &response, deadline)?;
                }
                Some(8) => {
                    parse_block_request(&body)?;
                }
                Some(21) => {
                    require(body.len() == 49, "BEP52 hash request length")?;
                    session.send_frame(stream, &self.hash_reply(&body), deadline)?;
                }
                _ => state.control(&body)?,
            }
        }
    }

    fn hash_reply(&self, request: &[u8]) -> Vec<u8> {
        let base = read_u32(&request[33..37]);
        let index = read_u32(&request[37..41]) as usize;
        let length = read_u32(&request[41..45]) as usize;
        let proofs = read_u32(&request[45..49]) as usize;
        let depth = self.levels.len() - 1;
        let valid = request[1..33] == self.binding.pieces_root()
            && base == 0
            && (2..=512).contains(&length)
            && length.is_power_of_two()
            && index.is_multiple_of(length)
            && index
                .checked_add(length)
                .is_some_and(|end| end <= self.levels[0].len())
            && proofs < depth;
        let mut response = request.to_vec();
        if !valid {
            response[0] = 23;
            return response;
        }
        response[0] = 22;
        for hash in &self.levels[0][index..index + length] {
            response.extend_from_slice(hash);
        }
        let implied = length.trailing_zeros() as usize;
        for height in implied..=proofs {
            response.extend_from_slice(&self.levels[height][(index >> height) ^ 1]);
        }
        response
    }
}

fn handshake(binding: &CellBep52BindingV1, peer_id: [u8; 20]) -> [u8; 68] {
    let mut bytes = [0; 68];
    bytes[0] = 19;
    bytes[1..20].copy_from_slice(b"BitTorrent protocol");
    bytes[25] = 0x10; // BEP10 only. No DHT or fast-extension claim.
    bytes[28..48].copy_from_slice(&binding.info_hash()[..20]);
    bytes[48..].copy_from_slice(&peer_id);
    bytes
}

fn receive_handshake(
    stream: &mut TcpStream,
    binding: &CellBep52BindingV1,
    session: &mut CellBep52PeerSessionV1,
    deadline: Instant,
) -> CellResultV1<()> {
    let mut bytes = [0; 68];
    session.read_exact(stream, &mut bytes, deadline, false)?;
    require(
        bytes[0] == 19 && &bytes[1..20] == b"BitTorrent protocol",
        "BEP52 protocol handshake",
    )?;
    require(bytes[25] & 0x10 != 0, "BEP52 extension protocol required")?;
    require(
        bytes[28..48] == binding.info_hash()[..20],
        "BEP52 handshake infohash prefix",
    )
}

pub(super) fn extension_handshake(size: Option<usize>) -> Vec<u8> {
    let mut bytes = vec![20, 0];
    bytes.extend_from_slice(b"d1:md11:ut_metadatai1ee");
    if let Some(size) = size {
        bytes.extend_from_slice(format!("13:metadata_sizei{size}e").as_bytes());
    }
    bytes.push(b'e');
    bytes
}

pub(super) fn parse_extension_handshake(bytes: &[u8]) -> CellResultV1<(Option<u8>, Option<u64>)> {
    require(bytes.len() <= 4096, "BEP52 extension handshake bound")?;
    let (value, used) = decode(bytes)?;
    require(
        used == bytes.len(),
        "BEP52 extension handshake trailing bytes",
    )?;
    let mut metadata = None;
    if let Some(messages) = value.optional(b"m")? {
        let mut identifiers = BTreeSet::new();
        for (name, value) in messages.dictionary()? {
            let number = value.integer()?;
            require(number <= u8::MAX as u64, "BEP52 extension ID range")?;
            if number != 0 {
                require(identifiers.insert(number), "BEP52 extension ID collision")?;
            }
            if *name == b"ut_metadata" && number != 0 {
                metadata = Some(number as u8);
            }
        }
    }
    let size = value
        .optional(b"metadata_size")?
        .map(Value::integer)
        .transpose()?;
    Ok((metadata, size))
}

/// Bounded parser shared by the explicit storage-piece profile. The original
/// V1 entry points retain their existing parsing and admission behavior.
pub(super) fn parse_metadata_body(bytes: &[u8]) -> CellResultV1<(u64, u64, Option<u64>, &[u8])> {
    let (value, used) = decode(bytes)?;
    let kind = value.number(b"msg_type")?;
    let piece = if kind <= 2 {
        value.number(b"piece")?
    } else {
        0
    };
    let size = value
        .optional(b"total_size")?
        .map(Value::integer)
        .transpose()?;
    Ok((kind, piece, size, &bytes[used..]))
}

pub(super) fn metadata_message(
    id: u8,
    kind: u64,
    piece: u64,
    size: Option<usize>,
    data: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![20, id];
    bytes.extend_from_slice(format!("d8:msg_typei{kind}e5:piecei{piece}e").as_bytes());
    if let Some(size) = size {
        bytes.extend_from_slice(format!("10:total_sizei{size}e").as_bytes());
    }
    bytes.push(b'e');
    bytes.extend_from_slice(data);
    bytes
}

pub(super) fn block_request(kind: u8, index: u32, begin: u32, length: u32) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&begin.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes
}

pub(super) fn parse_block_request(bytes: &[u8]) -> CellResultV1<(u32, u32, u32)> {
    require(bytes.len() == 13, "BEP52 block request length")?;
    Ok((
        read_u32(&bytes[1..5]),
        read_u32(&bytes[5..9]),
        read_u32(&bytes[9..13]),
    ))
}

pub(super) fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}

pub(super) struct PeerState {
    pub(super) choked: bool,
    pieces: usize,
    bitfield: Option<Vec<u8>>,
    have: BTreeSet<usize>,
}

impl PeerState {
    pub(super) fn new(pieces: usize) -> Self {
        Self {
            choked: true,
            pieces,
            bitfield: None,
            have: BTreeSet::new(),
        }
    }
    pub(super) fn known_absent(&self, index: usize) -> bool {
        !self.have.contains(&index)
            && self
                .bitfield
                .as_ref()
                .is_some_and(|bits| bits[index / 8] & (0x80 >> (index % 8)) == 0)
    }
    pub(super) fn control(&mut self, body: &[u8]) -> CellResultV1<()> {
        match body.first().copied() {
            None => Ok(()),
            Some(0 | 1) => {
                require(body.len() == 1, "BEP52 choke length")?;
                self.choked = body[0] == 0;
                Ok(())
            }
            Some(2 | 3) => require(body.len() == 1, "BEP52 interest length"),
            Some(4) => {
                require(body.len() == 5, "BEP52 have length")?;
                let index = read_u32(&body[1..]) as usize;
                require(index < self.pieces, "BEP52 have range")?;
                self.have.insert(index);
                Ok(())
            }
            Some(5) => {
                require(
                    self.bitfield.is_none() && body.len() == 1 + self.pieces.div_ceil(8),
                    "BEP52 bitfield shape",
                )?;
                if !self.pieces.is_multiple_of(8) {
                    require(
                        body.last().unwrap() & ((1 << (8 - self.pieces % 8)) - 1) == 0,
                        "BEP52 bitfield spare bits",
                    )?;
                }
                self.bitfield = Some(body[1..].to_vec());
                Ok(())
            }
            Some(9) => require(body.len() == 3, "BEP52 ignored DHT port length"),
            Some(20) => {
                require(body.len() >= 2, "BEP52 extended frame length")?;
                Ok(())
            }
            _ => Err(CellErrorV1::Invalid(
                "BEP52 unsolicited/unsupported message",
            )),
        }
    }
}
