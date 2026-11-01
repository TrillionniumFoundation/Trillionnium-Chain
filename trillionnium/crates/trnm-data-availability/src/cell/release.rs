//! Bounded acquisition of an owner-declared set. The completion marker records
//! a successful cache check; it grants no release selection or model use.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use super::{
    manifest::MAX_MANIFEST_BYTES,
    network::{fetch_cell_in_session, fetch_manifest, RequestContext, ResponseBudget},
    require, CellDigestV1, CellErrorV1, CellLoaderContextV1, CellPeerLimitsV1,
    CellReleaseClosureV1, CellReleaseLimitsV1, CellReleaseManifestV1, CellResultV1, CellStoreV1,
};

static MARKER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One reservation for all members, including failed peer responses and retries.
/// The earlier of the two declared deadlines applies to the entire operation.
#[derive(Clone, Copy, Debug)]
pub struct CellReleaseFetchLimitsV1 {
    pub peer: CellPeerLimitsV1,
    pub release: CellReleaseLimitsV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseFetchReportV1 {
    pub release_id: CellDigestV1,
    pub cells: usize,
    pub payload_bytes: u64,
    pub chunks: u64,
    pub cached_chunks: usize,
    pub downloaded_chunks: usize,
    pub downloaded_bytes: u64,
    pub received_response_bytes: u64,
    pub connection_attempts: u64,
    pub rejected_responses: usize,
    pub supplying_peers: BTreeSet<SocketAddr>,
}

/// Complete declared bytes, not an installation or a storage duty receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellClosureFetchReportV1 {
    pub closure_id: CellDigestV1,
    pub selected_generation: u64,
    pub release: CellReleaseFetchReportV1,
}

/// Fetch an owner-pinned dependency plan through the original TCR1/TCL4 path.
/// Every TCM1 is checked against its file mapping before payload acquisition.
/// One original transport reservation covers all manifests, chunks and retries.
/// The published marker contains canonical TCD1 bytes, never CURRENT/FinalUse.
pub fn fetch_closure_to_file(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    mut limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<CellClosureFetchReportV1> {
    closure.verify_for_loader(expected)?;
    limits.release.max_payload_bytes = limits
        .release
        .max_payload_bytes
        .min(expected.max_payload_bytes);
    limits.release.max_chunks = limits.release.max_chunks.min(expected.max_chunks);
    let release = fetch_release_checked(
        store,
        closure.release(),
        closure.release().id(),
        peers,
        limits,
        output,
        Some(closure),
    )?;
    Ok(CellClosureFetchReportV1 {
        closure_id: closure.id(),
        selected_generation: closure.selected_generation(),
        release,
    })
}

/// Read an externally supplied TCR1 object, bounded before allocation, then
/// compare its complete content address to the release owner's pinned identity.
/// The local input path must be caller-controlled. These size checks do not
/// defend against a hostile process replacing local paths; blocking filesystem
/// calls are cooperative, not preemptible by an operation deadline.
pub fn read_pinned_release(
    path: &Path,
    pinned: CellDigestV1,
) -> CellResultV1<CellReleaseManifestV1> {
    let metadata = fs::metadata(path)?;
    require(
        metadata.is_file() && metadata.len() <= MAX_MANIFEST_BYTES as u64,
        "release input size/type",
    )?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    require(
        metadata.is_file() && metadata.len() <= MAX_MANIFEST_BYTES as u64,
        "release input size/type",
    )?;
    let mut wire = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut wire)?;
    let release = CellReleaseManifestV1::decode(&wire)?;
    require(release.id() == pinned, "release manifest digest")?;
    Ok(release)
}

/// Retrieve every declared member under one original reservation and publish
/// the exact TCR1 bytes with create-only semantics only after full verification.
///
/// The root is supplied by the existing release owner, not discovered from a
/// peer. Failure before publication leaves no completion marker and may retain
/// verified disposable cache chunks. After the no-replace link, a directory
/// sync or cleanup error can coexist with a complete marker: reconcile it by
/// pinned identity, never overwrite it. Consumers must verify the cache again
/// before use: a marker is neither a durable storage lease nor CURRENT/FinalUse.
pub fn fetch_release_to_file(
    store: &CellStoreV1,
    release: &CellReleaseManifestV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<CellReleaseFetchReportV1> {
    fetch_release_checked(store, release, pinned, peers, limits, output, None)
}

fn fetch_release_checked(
    store: &CellStoreV1,
    release: &CellReleaseManifestV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
    closure: Option<&CellReleaseClosureV1>,
) -> CellResultV1<CellReleaseFetchReportV1> {
    release.validate()?;
    require(release.id() == pinned, "release manifest digest")?;
    limits.peer.validate()?;
    require(
        limits.release.max_payload_bytes > 0,
        "release payload budget",
    )?;
    require(limits.release.max_chunks > 0, "release chunk budget")?;
    require(
        peers.len() <= 8 && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "configured peer count/duplicates",
    )?;
    // Refuse an existing file, directory or dangling symlink before any peer
    // work. The final no-replace hard link also closes a later creation race.
    match fs::symlink_metadata(output) {
        Ok(_) => return Err(CellErrorV1::Invalid("release marker exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let deadline = limits
        .release
        .deadline
        .min(Instant::now() + limits.peer.overall_timeout);
    check_deadline(deadline)?;
    let requests_left = AtomicU64::new(limits.peer.max_connections);
    let responses = ResponseBudget::new(limits.peer.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.peer.request_timeout,
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut report = CellReleaseFetchReportV1 {
        release_id: pinned,
        cells: release.cells().len(),
        payload_bytes: 0,
        chunks: 0,
        cached_chunks: 0,
        downloaded_chunks: 0,
        downloaded_bytes: 0,
        received_response_bytes: 0,
        connection_attempts: 0,
        rejected_responses: 0,
        supplying_peers: BTreeSet::new(),
    };
    // Persist bounded pinned manifests, but fetch no payload until every
    // member's compatibility and aggregate payload/chunk limits are known.
    // Re-read by content address instead of retaining all decoded manifests.
    for digest in release.cells() {
        check_deadline(deadline)?;
        let (manifest, rejected) = fetch_manifest(store, *digest, peers, limits.peer, &transport)?;
        require(
            manifest.context() == release.context(),
            "release cell context",
        )?;
        if let Some(closure) = closure {
            closure.verify_manifest(&manifest)?;
        }
        report.rejected_responses += rejected;
        report.payload_bytes = report
            .payload_bytes
            .checked_add(manifest.size())
            .ok_or(CellErrorV1::Invalid("release payload budget"))?;
        require(
            report.payload_bytes <= limits.release.max_payload_bytes,
            "release payload budget",
        )?;
        report.chunks = report
            .chunks
            .checked_add(manifest.chunks().len() as u64)
            .ok_or(CellErrorV1::Invalid("release chunk budget"))?;
        require(
            report.chunks <= limits.release.max_chunks,
            "release chunk budget",
        )?;
    }
    for digest in release.cells() {
        check_deadline(deadline)?;
        let (_, member) =
            fetch_cell_in_session(store, *digest, peers, limits.peer, &transport, None)?;
        report.cached_chunks += member.cached_chunks;
        report.downloaded_chunks += member.downloaded_chunks;
        report.downloaded_bytes += member.downloaded_bytes;
        report.rejected_responses += member.rejected_responses;
        report.supplying_peers.extend(member.supplying_peers);
    }
    store.verify_release_complete(
        release,
        CellReleaseLimitsV1 {
            deadline,
            ..limits.release
        },
    )?;
    report.connection_attempts =
        limits.peer.max_connections - requests_left.load(Ordering::Relaxed);
    report.received_response_bytes = responses.received()?;
    let marker = closure.map_or_else(|| release.encode(), CellReleaseClosureV1::encode);
    publish_marker(&marker, output, deadline)?;
    Ok(report)
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() <= deadline, "release fetch deadline")
}

fn publish_marker(wire: &[u8], output: &Path, deadline: Instant) -> CellResultV1<()> {
    check_deadline(deadline)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let sequence = MARKER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".trnm-release-{}-{sequence}.partial",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result: CellResultV1<()> = (|| {
        file.write_all(wire)?;
        file.sync_all()?;
        #[cfg(test)]
        super::release_tests::before_marker_publication(deadline);
        check_deadline(deadline)?;
        fs::hard_link(&temporary, output)?;
        #[cfg(test)]
        super::release_tests::after_marker_link()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    drop(file);
    let cleanup = fs::remove_file(&temporary);
    result?;
    cleanup?;
    Ok(())
}
