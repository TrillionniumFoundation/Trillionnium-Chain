//! Native BEP52 TCP transport for independently pinned storage-piece mappings.
//! Requests still transfer at most 16 KiB. An acquired logical piece remains
//! private until both its ordinary TCM1 SHA-256 and BEP52 subtree root pass.
//! The caller owns the single session across files, peers and continuations.

use std::{
    collections::BTreeSet,
    net::{Shutdown, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::{
    check_deadline, subtree_width, zero_subtree, CellBep52StorageBindingV2,
    CELL_BEP52_LEAF_BYTES_V2, MAX_CELL_BEP52_STORAGE_INFO_BYTES_V2,
};
use crate::cell::{
    bep52_peer::{
        block_request, extension_handshake, metadata_message, parse_block_request,
        parse_extension_handshake, parse_metadata_body, read_u32, PeerState,
    },
    require, CellBep52PeerSessionV1, CellDigestV1, CellErrorV1, CellReleaseLimitsV1, CellResultV1,
    CellStoreV1,
};

/// Native BitTorrent handshake/extension wire, distinct from the historical
/// custom Cell framing that used `cell-bep52-storage-pinned-tcp-v2`.
/// The V2 storage binding and its pinned metainfo remain unchanged.
pub const CELL_BEP52_STORAGE_PEER_PROFILE_V2: &str = "cell-bep52-storage-native-wire-v2";
const OUR_METADATA_ID: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52StorageFetchReportV2 {
    pub manifest_id: CellDigestV1,
    pub mapping_id: CellDigestV1,
    pub info_hash: CellDigestV1,
    pub payload_sha256: CellDigestV1,
    pub payload_bytes: u64,
    /// Original manifest references already cached and verified at entry.
    /// Repeated references to the same cached object each count once here.
    pub cached_chunks: usize,
    /// Distinct original objects actually received, verified and written by
    /// this fetch. Repeated manifest references do not create extra downloads.
    pub downloaded_chunks: usize,
    /// Newly published original storage bytes; failed/partial wire bytes remain
    /// charged in the same session's usage even when this function returns Err.
    pub downloaded_bytes: u64,
    pub supplying_peers: BTreeSet<SocketAddr>,
}

/// Acquire one exact original manifest. The binding's manifest/context/mapping
/// pins must originate from the release owner; discovery is only a location
/// hint. This function never creates a new reservation or grants execution.
pub fn fetch_cell_bep52_storage_v2(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    peers: &[SocketAddr],
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52StorageFetchReportV2> {
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "BEP52 storage endpoint count/duplicates",
    )?;
    require(
        peers.iter().all(|peer| {
            peer.port() != 0 && !peer.ip().is_unspecified() && !peer.ip().is_multicast()
        }),
        "BEP52 storage explicit endpoint",
    )?;
    session.check(session.deadline())?;
    let manifest = binding.manifest();
    let mut missing = BTreeSet::new();
    let mut report = CellBep52StorageFetchReportV2 {
        manifest_id: binding.manifest_id(),
        mapping_id: binding.mapping_id(),
        info_hash: binding.info_hash(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        cached_chunks: 0,
        downloaded_chunks: 0,
        downloaded_bytes: 0,
        supplying_peers: BTreeSet::new(),
    };
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        session.check(session.deadline())?;
        if let Some(bytes) = store.chunk_with_deadline(chunk.sha256, Some(session.deadline()))? {
            binding.verify_storage_chunk_until(index as u32, &bytes, Some(session.deadline()))?;
            session.check(session.deadline())?;
            report.cached_chunks += 1;
        } else {
            missing.insert(chunk.sha256);
        }
    }
    store.put_manifest_with_deadline(
        binding.manifest_id(),
        &manifest.encode(),
        Some(session.deadline()),
    )?;
    for peer in peers {
        if missing.is_empty() {
            break;
        }
        session.check(session.deadline())?;
        if session.refused_peer(*peer) {
            continue;
        }
        session.connection()?;
        if let Err(error) = fetch_peer(
            store,
            binding,
            *peer,
            local_peer_id,
            session,
            &mut missing,
            &mut report,
        ) {
            session.record_peer_refusal(*peer, &error);
        }
        session.check(session.deadline())?;
    }
    require(
        missing.is_empty(),
        "BEP52 storage pinned chunks unavailable",
    )?;
    verify_complete(store, binding, session)?;
    session.record_completed_fetch()?;
    Ok(report)
}

fn verify_complete(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<()> {
    let mut full = Sha256::new();
    let mut length = 0_u64;
    for (index, chunk) in binding.manifest().chunks().iter().enumerate() {
        session.check(session.deadline())?;
        let bytes = store
            .chunk_with_deadline(chunk.sha256, Some(session.deadline()))?
            .ok_or(CellErrorV1::Unavailable)?;
        binding.verify_storage_chunk_until(index as u32, &bytes, Some(session.deadline()))?;
        full.update(&bytes);
        length += bytes.len() as u64;
    }
    require(
        length == binding.manifest().size()
            && <CellDigestV1>::from(full.finalize()) == binding.manifest().payload_sha256(),
        "BEP52 storage complete payload digest",
    )?;
    session.check(session.deadline())
}

fn fetch_peer(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    peer: SocketAddr,
    local_peer_id: [u8; 20],
    session: &mut CellBep52PeerSessionV1,
    missing: &mut BTreeSet<CellDigestV1>,
    report: &mut CellBep52StorageFetchReportV2,
) -> CellResultV1<()> {
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
                "BEP52 storage metadata size pin",
            )?;
            break id.ok_or(CellErrorV1::Invalid(
                "BEP52 storage metadata extension absent",
            ))?;
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
            let (kind, piece, size, metadata) = parse_metadata_body(&body[2..])?;
            if kind > 2 {
                continue;
            }
            require(
                piece == 0 && kind == 1,
                "BEP52 storage metadata correlation/refusal",
            )?;
            require(
                size == Some(binding.info_bytes().len() as u64)
                    && metadata.len() <= MAX_CELL_BEP52_STORAGE_INFO_BYTES_V2,
                "BEP52 storage metadata total size",
            )?;
            require(
                <CellDigestV1>::from(Sha256::digest(metadata)) == binding.info_hash(),
                "BEP52 storage full metadata infohash",
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
        // A single original chunk is the only payload staging buffer. Leaves
        // are not independently published or turned into new CRP records.
        let mut bytes = Vec::with_capacity(chunk.size as usize);
        let mut rejected = false;
        while bytes.len() < chunk.size as usize {
            let deadline = session.request_deadline()?;
            while state.choked {
                state.control(&session.read_frame(&mut stream, deadline, false)?.unwrap())?;
            }
            let begin = bytes.len() as u32;
            let length = (chunk.size - begin).min(CELL_BEP52_LEAF_BYTES_V2);
            let request = block_request(6, index as u32, begin, length);
            session.send_frame(&mut stream, &request, deadline)?;
            loop {
                let body = session.read_frame(&mut stream, deadline, false)?.unwrap();
                if body.first() == Some(&7) {
                    require(
                        body.len() == 9 + length as usize
                            && read_u32(&body[1..5]) == index as u32
                            && read_u32(&body[5..9]) == begin,
                        "BEP52 storage piece correlation/length",
                    )?;
                    bytes.extend_from_slice(&body[9..]);
                    break;
                }
                if body.first() == Some(&16) {
                    require(
                        body.len() == request.len() && body[1..] == request[1..],
                        "BEP52 storage reject correlation",
                    )?;
                    rejected = true;
                    break;
                }
                state.control(&body)?;
            }
            if rejected {
                break;
            }
        }
        if rejected {
            continue;
        }
        binding.verify_storage_chunk_until(index as u32, &bytes, Some(session.deadline()))?;
        session.check(session.deadline())?;
        store.put_chunk_with_deadline(chunk, &bytes, Some(session.deadline()))?;
        missing.remove(&chunk.sha256);
        report.downloaded_chunks += 1;
        report.downloaded_bytes += bytes.len() as u64;
        report.supplying_peers.insert(peer);
    }
    let deadline = session.request_deadline()?;
    session.send_frame(&mut stream, &[3], deadline)?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

/// Actual complete source readback, followed by bounded one-chunk serving.
/// Preparation does not bind a listener or advertise. Each newly served source
/// chunk is re-read and validated; its immutable bytes are retained only while
/// serving that one storage piece, at most 4 MiB plus a small Merkle tree.
pub struct CellBep52StorageSeedV2<'a> {
    store: &'a CellStoreV1,
    binding: &'a CellBep52StorageBindingV2,
}

struct SourceChunk {
    index: usize,
    bytes: Vec<u8>,
    levels: Vec<Vec<CellDigestV1>>,
}

impl<'a> CellBep52StorageSeedV2<'a> {
    pub fn prepare(
        store: &'a CellStoreV1,
        binding: &'a CellBep52StorageBindingV2,
        limits: CellReleaseLimitsV1,
    ) -> CellResultV1<Self> {
        let observed = CellBep52StorageBindingV2::from_pinned_store(
            binding.manifest(),
            binding.manifest_id(),
            binding.manifest().context(),
            store,
            limits,
        )?;
        require(observed == *binding, "BEP52 storage seed actual mapping")?;
        check_deadline(limits.deadline)?;
        Ok(Self { store, binding })
    }

    pub fn serve_connection(
        &self,
        stream: TcpStream,
        local_peer_id: [u8; 20],
        session: &mut CellBep52PeerSessionV1,
    ) -> CellResultV1<()> {
        session.connection()?;
        self.serve_admitted_connection(stream, local_peer_id, session)
    }

    /// The complete-release owner reserves the accepted connection before
    /// reading source bytes. This entry point must not reserve it a second time.
    pub(in crate::cell) fn serve_admitted_connection(
        &self,
        mut stream: TcpStream,
        local_peer_id: [u8; 20],
        session: &mut CellBep52PeerSessionV1,
    ) -> CellResultV1<()> {
        let result = self.serve_inner(&mut stream, local_peer_id, session);
        if let Err(error) = &result {
            session.record_connection_refusal(stream.peer_addr().ok(), error);
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
        let mut source = None;
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
                }
                Some(20) if body.get(1) == Some(&OUR_METADATA_ID) => {
                    require(have_extension, "BEP52 storage metadata before negotiation")?;
                    let (kind, piece, size, payload) = parse_metadata_body(&body[2..])?;
                    if kind > 2 {
                        continue;
                    }
                    require(
                        kind == 0 && size.is_none() && payload.is_empty(),
                        "BEP52 storage metadata request",
                    )?;
                    let remote = their_metadata_id.ok_or(CellErrorV1::Invalid(
                        "BEP52 storage return metadata extension absent",
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
                    require(body.len() == 1, "BEP52 storage interest length")?;
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
                                && length <= CELL_BEP52_LEAF_BYTES_V2
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
                    let chunk = self.load_chunk(index as usize, &mut source, session.deadline())?;
                    session.check(deadline)?;
                    let mut response = Vec::with_capacity(9 + length as usize);
                    response.push(7);
                    response.extend_from_slice(&index.to_be_bytes());
                    response.extend_from_slice(&begin.to_be_bytes());
                    response
                        .extend_from_slice(&chunk.bytes[begin as usize..(begin + length) as usize]);
                    session.send_frame(stream, &response, deadline)?;
                }
                Some(8) => {
                    parse_block_request(&body)?;
                }
                Some(21) => {
                    require(body.len() == 49, "BEP52 storage hash request length")?;
                    let response = self.hash_reply(&body, &mut source, session.deadline())?;
                    session.check(deadline)?;
                    session.send_frame(stream, &response, deadline)?;
                }
                _ => state.control(&body)?,
            }
        }
    }

    fn load_chunk<'b>(
        &self,
        index: usize,
        source: &'b mut Option<SourceChunk>,
        deadline: Instant,
    ) -> CellResultV1<&'b SourceChunk> {
        check_deadline(deadline)?;
        if source.as_ref().is_none_or(|chunk| chunk.index != index) {
            // Release the previous payload before allocating the next one.
            // The owner keeps at most one 4-MiB storage chunk, including while
            // switching pieces or satisfying a hash request across pieces.
            *source = None;
            let expected = self
                .binding
                .manifest()
                .chunks()
                .get(index)
                .ok_or(CellErrorV1::Invalid("BEP52 storage seed chunk index"))?;
            let bytes = self
                .store
                .chunk_with_deadline(expected.sha256, Some(deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            let levels = self
                .binding
                .checked_chunk_levels(index as u32, &bytes, Some(deadline))?;
            *source = Some(SourceChunk {
                index,
                bytes,
                levels,
            });
        }
        Ok(source.as_ref().unwrap())
    }

    fn hash_at(
        &self,
        height: u32,
        index: usize,
        source: &mut Option<SourceChunk>,
        deadline: Instant,
    ) -> CellResultV1<CellDigestV1> {
        let piece_height = subtree_width(self.binding.manifest()).trailing_zeros();
        if height >= piece_height {
            return self
                .binding
                .levels
                .get((height - piece_height) as usize)
                .and_then(|level| level.get(index))
                .copied()
                .ok_or(CellErrorV1::Invalid("BEP52 storage hash coordinate"));
        }
        let nodes_per_piece = 1usize << (piece_height - height);
        let piece = index / nodes_per_piece;
        if piece >= self.binding.manifest().chunks().len() {
            return Ok(zero_subtree(height));
        }
        let chunk = self.load_chunk(piece, source, deadline)?;
        Ok(chunk.levels[height as usize][index % nodes_per_piece])
    }

    /// Serve standard leaf- and logical-piece-layer hash requests, including
    /// zero padding and the requested uncle path. CBL2 is never sent on TCP.
    fn hash_reply(
        &self,
        request: &[u8],
        source: &mut Option<SourceChunk>,
        deadline: Instant,
    ) -> CellResultV1<Vec<u8>> {
        let base = read_u32(&request[33..37]);
        let index = read_u32(&request[37..41]) as usize;
        let length = read_u32(&request[41..45]) as usize;
        let proofs = read_u32(&request[45..49]);
        let depth = self
            .binding
            .leaf_count()
            .next_power_of_two()
            .trailing_zeros();
        let piece_layer =
            (self.binding.manifest().chunk_bytes() / CELL_BEP52_LEAF_BYTES_V2).trailing_zeros();
        let valid = request[1..33] == self.binding.pieces_root()
            && (base == 0 || base == piece_layer)
            && base <= depth
            && (2..=512).contains(&length)
            && length.is_power_of_two()
            && index.is_multiple_of(length)
            && index
                .checked_add(length)
                .is_some_and(|end| end <= (1usize << (depth - base)))
            && proofs < depth - base;
        let mut response = request.to_vec();
        if !valid {
            response[0] = 23;
            return Ok(response);
        }
        response[0] = 22;
        for offset in index..index + length {
            check_deadline(deadline)?;
            response.extend_from_slice(&self.hash_at(base, offset, source, deadline)?);
        }
        let implied = length.trailing_zeros();
        for height in implied..=proofs {
            check_deadline(deadline)?;
            response.extend_from_slice(&self.hash_at(
                base + height,
                (index >> height) ^ 1,
                source,
                deadline,
            )?);
        }
        Ok(response)
    }
}

fn handshake(binding: &CellBep52StorageBindingV2, peer_id: [u8; 20]) -> [u8; 68] {
    let mut bytes = [0; 68];
    bytes[0] = 19;
    bytes[1..20].copy_from_slice(b"BitTorrent protocol");
    bytes[25] = 0x10;
    bytes[28..48].copy_from_slice(&binding.info_hash()[..20]);
    bytes[48..].copy_from_slice(&peer_id);
    bytes
}

fn receive_handshake(
    stream: &mut TcpStream,
    binding: &CellBep52StorageBindingV2,
    session: &mut CellBep52PeerSessionV1,
    deadline: Instant,
) -> CellResultV1<()> {
    let mut bytes = [0; 68];
    session.read_exact(stream, &mut bytes, deadline, false)?;
    require(
        bytes[0] == 19 && &bytes[1..20] == b"BitTorrent protocol",
        "BEP52 storage protocol handshake",
    )?;
    require(bytes[25] & 0x10 != 0, "BEP52 storage extension required")?;
    require(
        bytes[28..48] == binding.info_hash()[..20],
        "BEP52 storage handshake infohash prefix",
    )
}

#[cfg(test)]
mod tests;
