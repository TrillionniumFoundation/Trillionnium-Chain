//! Explicit bounded inventory hints for the existing downloader and server.
//!
//! TCI1: magic, operation=1, pinned TCM1 ID, start:u32be, count:u16be.
//! TIS1: magic, status (0=present response, 1=unknown manifest), length:u32be,
//! then exactly ceil(count/8) bytes with least-significant-bit-first presence.
//! Unused high bits are zero. Each request covers at most 256 chunk slots.
//! A hint never skips the actual chunk or ordered payload hash verification.

use super::*;

const MAX_PAGE_CHUNKS: usize = 256;

pub(super) fn observe(
    manifest: &CellManifestV1,
    missing: &[(usize, CellChunkV1)],
    peers: &[SocketAddr],
    transport: &RequestContext<'_>,
) -> CellResultV1<(Vec<u8>, usize)> {
    require(peers.len() <= 8, "availability peer bound")?;
    let pages: BTreeSet<_> = missing
        .iter()
        .map(|(index, _)| index / MAX_PAGE_CHUNKS * MAX_PAGE_CHUNKS)
        .collect();
    // One byte per already bounded manifest chunk: at most eight hint bits.
    let mut available = vec![0_u8; manifest.chunks().len()];
    let mut rejected = 0;
    for (peer_index, peer) in peers.iter().copied().enumerate() {
        if transport.responses.is_quarantined(peer)? {
            continue;
        }
        for start in &pages {
            remaining(transport.overall)?;
            let count = MAX_PAGE_CHUNKS.min(manifest.chunks().len() - start);
            let result = request_page(peer, manifest.id(), *start, count, transport);
            match result {
                Ok(bits) => {
                    for offset in 0..count {
                        if bits[offset / 8] & (1_u8 << (offset % 8)) != 0 {
                            available[start + offset] |= 1_u8 << peer_index;
                        }
                    }
                }
                Err(_) => {
                    rejected += 1;
                    // An unsupported/absent/slow inventory endpoint is still
                    // eligible for ordinary bytes unless it supplied a complete
                    // malformed frame. Never loop through all of its pages.
                    break;
                }
            }
        }
    }
    remaining(transport.overall)?;
    Ok((available, rejected))
}

fn request_page(
    peer: SocketAddr,
    manifest: CellDigestV1,
    start: usize,
    count: usize,
    transport: &RequestContext<'_>,
) -> CellResultV1<Vec<u8>> {
    require(
        (1..=MAX_PAGE_CHUNKS).contains(&count) && start <= u32::MAX as usize,
        "availability page bound",
    )?;
    let mut query = [0; 43];
    query[..4].copy_from_slice(b"TCI1");
    query[4] = 1;
    query[5..37].copy_from_slice(&manifest);
    query[37..41].copy_from_slice(&(start as u32).to_be_bytes());
    query[41..43].copy_from_slice(&(count as u16).to_be_bytes());
    let mut phase = "budget";
    let bytes = request_frame(
        peer,
        &query,
        b"TIS1",
        count.div_ceil(8),
        transport,
        &mut phase,
    )?;
    let trailing_bits = count % 8;
    if bytes.len() != count.div_ceil(8)
        || (trailing_bits != 0
            && bytes
                .last()
                .is_some_and(|last| *last & !((1_u8 << trailing_bits) - 1) != 0))
    {
        transport.responses.quarantine(peer)?;
        return Err(CellErrorV1::Invalid("availability canonical bitfield"));
    }
    Ok(bytes)
}

pub(super) fn serve_page(
    stream: &mut TcpStream,
    store: &CellStoreV1,
    manifest_id: CellDigestV1,
    deadline: Instant,
) -> CellResultV1<Option<Vec<u8>>> {
    let mut page = [0; 6];
    read_deadline(stream, &mut page, deadline, None)?;
    let start = u32::from_be_bytes(page[..4].try_into().unwrap()) as usize;
    let count = usize::from(u16::from_be_bytes(page[4..].try_into().unwrap()));
    require(
        (1..=MAX_PAGE_CHUNKS).contains(&count),
        "availability page bound",
    )?;
    remaining(deadline)?;
    let Some(manifest) = store.manifest(manifest_id)? else {
        return Ok(None);
    };
    let end = start
        .checked_add(count)
        .ok_or(CellErrorV1::Invalid("availability page range"))?;
    require(end <= manifest.chunks().len(), "availability page range")?;
    let mut bits = vec![0; count.div_ceil(8)];
    for (offset, chunk) in manifest.chunks()[start..end].iter().enumerate() {
        remaining(deadline)?;
        if store.chunk_present(chunk)? {
            bits[offset / 8] |= 1_u8 << (offset % 8);
        }
    }
    remaining(deadline)?;
    Ok(Some(bits))
}

#[cfg(test)]
mod tests;
