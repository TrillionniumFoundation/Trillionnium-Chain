//! Bounded, explicitly selected Cell TCP transport for CBM2/CBL2 storage mapping.
//!
//! This is a new Cell framing profile, not the BitTorrent peer `hashes` wire.
//! Callers supply approved endpoints and an independently owner-pinned mapping.
//! No peer-supplied mapping, discovery hint, listener or background task is
//! adopted here. Plaintext transport provides neither peer identity nor use
//! authority. A fetch completes only after the original full payload readback.

use std::{
    collections::BTreeSet,
    net::{Shutdown, SocketAddr, TcpStream},
};

use super::{
    require, CellBep52LeafProofV2, CellBep52StorageBindingV2, CellDigestV1, CellErrorV1,
    CellResultV1, CellStoreV1, CELL_BEP52_LEAF_BYTES_V2, MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2,
};

mod io;
pub use io::{
    CellBep52StoragePeerLimitsV2, CellBep52StoragePeerSessionV2, CellBep52StoragePeerUsageV2,
};

pub const CELL_BEP52_STORAGE_PEER_PROFILE_V2: &str = "cell-bep52-storage-pinned-tcp-v2";
pub const MAX_CELL_BEP52_STORAGE_FRAME_BYTES_V2: usize =
    6 + MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2 + CELL_BEP52_LEAF_BYTES_V2 as usize;
const HELLO_BYTES: usize = 132;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52StorageFetchReportV2 {
    pub operation_id: CellDigestV1,
    pub manifest_id: CellDigestV1,
    pub mapping_id: CellDigestV1,
    pub info_hash: CellDigestV1,
    pub payload_sha256: CellDigestV1,
    pub payload_bytes: u64,
    pub storage_positions: usize,
    /// Actual newly committed chunks, excluding existing or reused byte objects.
    pub downloaded_chunks: usize,
    pub downloaded_leaves: u64,
    pub downloaded_bytes: u64,
    pub supplying_peers: BTreeSet<SocketAddr>,
}

/// Download under one original operation, scope and cumulative reservation.
/// The binding must be constructed from owner pins before this call; this
/// protocol never accepts a peer's CBM2 as its own authenticity evidence.
/// A failed peer leaves only fully verified original storage chunks in cache.
/// Reusing the session preserves all failed-attempt bytes, frames and deadline.
pub fn fetch_cell_bep52_storage(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    peers: &[SocketAddr],
    session: &mut CellBep52StoragePeerSessionV2,
) -> CellResultV1<CellBep52StorageFetchReportV2> {
    session.bind(binding)?;
    require(
        peers.len() <= 8 && peers.iter().copied().collect::<BTreeSet<_>>().len() == peers.len(),
        "CBL2 explicit peer set",
    )?;
    store.put_manifest_with_deadline(
        binding.manifest_id(),
        &binding.manifest().encode(),
        Some(session.deadline()),
    )?;
    let mut report = CellBep52StorageFetchReportV2 {
        operation_id: session.operation_id(),
        manifest_id: binding.manifest_id(),
        mapping_id: binding.mapping_id(),
        info_hash: binding.info_hash(),
        payload_sha256: binding.manifest().payload_sha256(),
        payload_bytes: binding.manifest().size(),
        storage_positions: binding.manifest().chunks().len(),
        downloaded_chunks: 0,
        downloaded_leaves: 0,
        downloaded_bytes: 0,
        supplying_peers: BTreeSet::new(),
    };
    let mut last_error = None;
    if !all_chunks_present(store, binding, session)? {
        for peer in peers {
            session.check(session.deadline())?;
            match fetch_peer(store, binding, *peer, session, &mut report) {
                Ok(()) => break,
                Err(error) => {
                    session.failed_connection();
                    last_error = Some(error);
                }
            }
        }
    }
    session.check(session.deadline())?;
    if !all_chunks_present(store, binding, session)? {
        return Err(last_error.unwrap_or(CellErrorV1::Unavailable));
    }
    // Chunk equality alone cannot establish the ordered full-payload digest.
    store.verify_complete_until(binding.manifest(), session.deadline())?;
    session.check(session.deadline())?;
    session.completed_fetch();
    Ok(report)
}

fn all_chunks_present(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    session: &mut CellBep52StoragePeerSessionV2,
) -> CellResultV1<bool> {
    for index in 0..binding.manifest().chunks().len() {
        if !chunk_present(store, binding, index, session)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn chunk_present(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    index: usize,
    session: &mut CellBep52StoragePeerSessionV2,
) -> CellResultV1<bool> {
    session.check(session.deadline())?;
    let chunk = &binding.manifest().chunks()[index];
    let Some(bytes) = store.chunk_with_deadline(chunk.sha256, Some(session.deadline()))? else {
        return Ok(false);
    };
    binding.verify_storage_chunk(index as u32, &bytes)?;
    session.check(session.deadline())?;
    Ok(true)
}

fn fetch_peer(
    store: &CellStoreV1,
    binding: &CellBep52StorageBindingV2,
    peer: SocketAddr,
    session: &mut CellBep52StoragePeerSessionV2,
    report: &mut CellBep52StorageFetchReportV2,
) -> CellResultV1<()> {
    session.connection()?;
    let deadline = session.request_deadline()?;
    let mut stream = TcpStream::connect_timeout(&peer, session.remaining(deadline)?)?;
    stream.set_nodelay(true)?;
    session.send_frame(
        &mut stream,
        &hello(b"CBS2", binding, session.operation_id()),
        deadline,
    )?;
    let response = session.required_frame(&mut stream, deadline)?;
    require(
        response == hello(b"CBA2", binding, session.operation_id()),
        "CBL2 peer scope echo",
    )?;
    for index in 0..binding.manifest().chunks().len() {
        if chunk_present(store, binding, index, session)? {
            continue;
        }
        // One storage-chunk request produces bounded, separately authenticated
        // leaf frames. The request's deadline is not renewed for each leaf.
        let request_deadline = session.request_deadline()?;
        let mut request = b"CBR2".to_vec();
        request.extend_from_slice(&(index as u32).to_be_bytes());
        session.send_frame(&mut stream, &request, request_deadline)?;
        let chunk = &binding.manifest().chunks()[index];
        let mut assembler = binding.begin_storage_chunk(index as u32, session.deadline())?;
        let leaves = chunk.size.div_ceil(CELL_BEP52_LEAF_BYTES_V2);
        let first_leaf =
            index as u32 * (binding.manifest().chunk_bytes() / CELL_BEP52_LEAF_BYTES_V2);
        for expected_index in first_leaf..first_leaf + leaves {
            let response = session.required_frame(&mut stream, request_deadline)?;
            require(
                response.len() >= 6 && &response[..4] == b"CBD2",
                "CBL2 leaf frame",
            )?;
            let proof_bytes = u16::from_be_bytes(response[4..6].try_into().unwrap()) as usize;
            require(
                proof_bytes <= MAX_CELL_BEP52_LEAF_PROOF_BYTES_V2
                    && 6 + proof_bytes < response.len(),
                "CBL2 leaf frame coverage",
            )?;
            let proof = CellBep52LeafProofV2::decode(&response[6..6 + proof_bytes])?;
            require(proof.index() == expected_index, "CBL2 requested leaf index")?;
            assembler.push(&proof, &response[6 + proof_bytes..])?;
            session.check(request_deadline)?;
            report.downloaded_leaves += 1;
        }
        // No leaf frame is exposed as a cache chunk. Original TCM1 hash,
        // complete storage size and subtree all pass before this publication.
        assembler.finish_into_store(store)?;
        session.check(session.deadline())?;
        report.downloaded_chunks += 1;
        report.downloaded_bytes += u64::from(chunk.size);
        report.supplying_peers.insert(peer);
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52StorageServeReportV2 {
    /// Echoed requester identity, not authenticated user/provider authority.
    pub requester_operation_id: CellDigestV1,
    pub chunk_requests: u64,
    pub served_leaves: u64,
    pub served_payload_bytes: u64,
}

/// Single pinned seed. The caller owns listener admission, endpoint approval
/// and the lifetime of each accepted stream; this type spawns no background job.
pub struct CellBep52StorageSeedV2<'a> {
    store: &'a CellStoreV1,
    binding: &'a CellBep52StorageBindingV2,
}

impl<'a> CellBep52StorageSeedV2<'a> {
    pub fn new(store: &'a CellStoreV1, binding: &'a CellBep52StorageBindingV2) -> Self {
        Self { store, binding }
    }

    /// Serve one already accepted connection under the caller's original
    /// non-cloneable accounting owner. Failures leave its actual usage visible.
    pub fn serve_connection(
        &self,
        mut stream: TcpStream,
        session: &mut CellBep52StoragePeerSessionV2,
    ) -> CellResultV1<CellBep52StorageServeReportV2> {
        session.bind(self.binding)?;
        session.connection()?;
        stream.set_nodelay(true)?;
        let deadline = session.request_deadline()?;
        let request = session.required_frame(&mut stream, deadline)?;
        require(request.len() == HELLO_BYTES, "CBL2 hello length")?;
        let requester_operation_id: CellDigestV1 = request[4..36].try_into().unwrap();
        require(requester_operation_id != [0; 32], "CBL2 requester identity")?;
        require(
            request == hello(b"CBS2", self.binding, requester_operation_id),
            "CBL2 requested scope",
        )?;
        session.send_frame(
            &mut stream,
            &hello(b"CBA2", self.binding, requester_operation_id),
            deadline,
        )?;
        let mut report = CellBep52StorageServeReportV2 {
            requester_operation_id,
            chunk_requests: 0,
            served_leaves: 0,
            served_payload_bytes: 0,
        };
        loop {
            let deadline = session.request_deadline()?;
            let Some(request) = session.read_frame(&mut stream, deadline, true)? else {
                return Ok(report);
            };
            require(
                request.len() == 8 && &request[..4] == b"CBR2",
                "CBL2 storage request",
            )?;
            let index = u32::from_be_bytes(request[4..8].try_into().unwrap());
            let chunk = self
                .binding
                .manifest()
                .chunks()
                .get(index as usize)
                .ok_or(CellErrorV1::Invalid("CBL2 requested storage index"))?;
            let bytes = self
                .store
                .chunk_with_deadline(chunk.sha256, Some(deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            let served = self.binding.verified_storage_chunk(index, &bytes)?;
            session.check(deadline)?;
            report.chunk_requests += 1;
            for leaf_index in
                served.first_leaf_index()..served.first_leaf_index() + served.leaf_count()
            {
                let proof = served.leaf_proof(leaf_index)?.encode();
                let leaf = served.leaf_bytes(leaf_index)?;
                let mut response = Vec::with_capacity(6 + proof.len() + leaf.len());
                response.extend_from_slice(b"CBD2");
                response.extend_from_slice(&(proof.len() as u16).to_be_bytes());
                response.extend_from_slice(&proof);
                response.extend_from_slice(leaf);
                session.send_frame(&mut stream, &response, deadline)?;
                report.served_leaves += 1;
                report.served_payload_bytes += leaf.len() as u64;
            }
        }
    }
}

fn hello(
    magic: &[u8; 4],
    binding: &CellBep52StorageBindingV2,
    operation_id: CellDigestV1,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_BYTES);
    out.extend_from_slice(magic);
    out.extend_from_slice(&operation_id);
    out.extend_from_slice(&binding.manifest_id());
    out.extend_from_slice(&binding.mapping_id());
    out.extend_from_slice(&binding.info_hash());
    out
}

#[cfg(test)]
mod tests;
