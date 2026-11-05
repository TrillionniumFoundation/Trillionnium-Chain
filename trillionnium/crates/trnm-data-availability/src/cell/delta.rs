//! Canonical chunk reuse over the original CAS. No executable patch format,
//! tensor arithmetic or second byte store is introduced.

use std::{
    collections::BTreeMap, net::SocketAddr, path::Path, sync::atomic::AtomicU64, time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    manifest::MAX_MANIFEST_BYTES,
    network::{fetch_cell_in_session, RequestContext, ResponseBudget},
    require, CellDigestV1, CellErrorV1, CellFetchReportV1, CellManifestV1,
    CellReleaseFetchLimitsV1, CellResultV1, CellStoreV1,
};

const NEW_CHUNK: u32 = u32::MAX;
pub const MAX_CELL_DELTA_BYTES_V1: usize = 4 + 32 + 4 + MAX_MANIFEST_BYTES + 4 + 16_384 * 4;

/// TCX1: exact base manifest, complete target manifest and one base index per
/// target chunk. u32::MAX denotes a new CAS chunk. The first matching base
/// index is mandatory, so one base/target pair has exactly one valid recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellChunkDeltaV1 {
    base: CellDigestV1,
    target: CellManifestV1,
    sources: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellDeltaPlanV1 {
    pub reused_chunks: u64,
    pub reused_bytes: u64,
    pub new_chunks: u64,
    pub new_bytes: u64,
}

impl CellChunkDeltaV1 {
    pub fn between(base: &CellManifestV1, target: &CellManifestV1) -> CellResultV1<Self> {
        base.validate()?;
        target.validate()?;
        let mut indices = BTreeMap::new();
        for (index, chunk) in base.chunks().iter().enumerate() {
            indices
                .entry((chunk.sha256, chunk.size))
                .or_insert(index as u32);
        }
        Ok(Self {
            base: base.id(),
            target: target.clone(),
            sources: target
                .chunks()
                .iter()
                .map(|chunk| {
                    indices
                        .get(&(chunk.sha256, chunk.size))
                        .copied()
                        .unwrap_or(NEW_CHUNK)
                })
                .collect(),
        })
    }

    pub fn base(&self) -> CellDigestV1 {
        self.base
    }
    pub fn target(&self) -> &CellManifestV1 {
        &self.target
    }

    pub fn verify(&self, base: &CellManifestV1) -> CellResultV1<CellDeltaPlanV1> {
        require(base.id() == self.base, "delta base pin")?;
        let canonical = Self::between(base, &self.target)?;
        require(
            self.sources == canonical.sources,
            "delta canonical source coverage",
        )?;
        let mut plan = CellDeltaPlanV1 {
            reused_chunks: 0,
            reused_bytes: 0,
            new_chunks: 0,
            new_bytes: 0,
        };
        for (source, chunk) in self.sources.iter().zip(self.target.chunks()) {
            if *source == NEW_CHUNK {
                plan.new_chunks += 1;
                plan.new_bytes += u64::from(chunk.size);
            } else {
                plan.reused_chunks += 1;
                plan.reused_bytes += u64::from(chunk.size);
            }
        }
        Ok(plan)
    }

    pub fn encode(&self) -> Vec<u8> {
        let target = self.target.encode();
        let mut bytes = Vec::with_capacity(44 + target.len() + self.sources.len() * 4);
        bytes.extend_from_slice(b"TCX1");
        bytes.extend_from_slice(&self.base);
        bytes.extend_from_slice(&(target.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&target);
        bytes.extend_from_slice(&(self.sources.len() as u32).to_be_bytes());
        for source in &self.sources {
            bytes.extend_from_slice(&source.to_be_bytes());
        }
        bytes
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-chunk-delta.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            (44..=MAX_CELL_DELTA_BYTES_V1).contains(&bytes.len()),
            "delta length",
        )?;
        require(&bytes[..4] == b"TCX1", "delta version")?;
        let base = bytes[4..36]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("delta base"))?;
        require(base != [0; 32], "delta base")?;
        let target_len = u32::from_be_bytes(bytes[36..40].try_into().unwrap()) as usize;
        require(
            target_len <= MAX_MANIFEST_BYTES && target_len <= bytes.len() - 44,
            "delta target length",
        )?;
        let target = CellManifestV1::decode(&bytes[40..40 + target_len])?;
        let count = u32::from_be_bytes(bytes[40 + target_len..44 + target_len].try_into().unwrap())
            as usize;
        require(
            count == target.chunks().len() && bytes.len() - 44 - target_len == count * 4,
            "delta source length",
        )?;
        let mut sources = Vec::with_capacity(count);
        for chunk in bytes[44 + target_len..].chunks_exact(4) {
            let index = u32::from_be_bytes(chunk.try_into().unwrap());
            require(index == NEW_CHUNK || index < 16_384, "delta source index")?;
            sources.push(index);
        }
        Ok(Self {
            base,
            target,
            sources,
        })
    }
}

/// Verify the actual base bytes, then acquire only absent target chunks with
/// the original downloader. Both payloads and all retries share one initial
/// deadline and finite aggregate payload/chunk/response/connection reservation.
/// The independent base, target and delta pins are supplied by the owner.
pub fn fetch_delta_to_file(
    store: &CellStoreV1,
    delta: &CellChunkDeltaV1,
    expected: (CellDigestV1, CellDigestV1, CellDigestV1),
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<(CellDeltaPlanV1, CellFetchReportV1)> {
    limits.peer.validate()?;
    require(
        delta.id() == expected.0 && delta.base == expected.1 && delta.target.id() == expected.2,
        "delta owner pins",
    )?;
    require(
        peers.len() <= 8
            && peers
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == peers.len(),
        "configured peer count/duplicates",
    )?;
    let deadline = limits
        .release
        .deadline
        .min(Instant::now() + limits.peer.overall_timeout);
    require(Instant::now() <= deadline, "delta deadline")?;
    let base = store
        .manifest_with_deadline(delta.base, Some(deadline))?
        .ok_or(CellErrorV1::Unavailable)?;
    let plan = delta.verify(&base)?;
    require(
        base.size()
            .checked_add(delta.target.size())
            .is_some_and(|size| size <= limits.release.max_payload_bytes),
        "delta payload budget",
    )?;
    require(
        (base.chunks().len() as u64)
            .checked_add(delta.target.chunks().len() as u64)
            .is_some_and(|count| count <= limits.release.max_chunks),
        "delta chunk budget",
    )?;
    require(
        base.size() <= limits.peer.max_cell_bytes
            && delta.target.size() <= limits.peer.max_cell_bytes,
        "cell exceeds byte budget",
    )?;
    match std::fs::symlink_metadata(output) {
        Ok(_) => return Err(CellErrorV1::Invalid("delta output exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    store.verify_complete_until(&base, deadline)?;
    require(Instant::now() <= deadline, "delta deadline")?;
    // Local writer contention spends the same caller reservation as the base
    // verification and the later transfer, never a new standalone allowance.
    store.put_manifest_with_deadline(delta.target.id(), &delta.target.encode(), Some(deadline))?;
    let requests_left = AtomicU64::new(limits.peer.max_connections);
    let responses = ResponseBudget::new(limits.peer.max_response_bytes);
    let transport = RequestContext {
        cancelled: None,
        timeout: limits.peer.request_timeout,
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
    };
    let (_, report) = fetch_cell_in_session(
        store,
        delta.target.id(),
        peers,
        limits.peer,
        &transport,
        Some(output),
    )?;
    Ok((plan, report))
}
