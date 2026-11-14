//! Bounded acquisition of an owner-declared set. The completion marker records
//! a successful cache check; it grants no release selection or model use.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

use super::{
    manifest::MAX_MANIFEST_BYTES, network::NetworkFetchSession, require, CellDigestV1, CellErrorV1,
    CellLoaderContextV1, CellModelReleaseRootV1, CellPeerLimitsV1, CellReleaseClosureV1,
    CellReleaseLimitsV1, CellReleaseManifestV1, CellResidencyV1, CellResultV1, CellStoreV1,
    CellTensorModelManifestV1,
};

pub use super::network::CellFetchTransportV2;

#[cfg(test)]
mod transport_tests;

static MARKER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One reservation for all members, including failed peer responses and retries.
/// The earlier of the two declared deadlines applies to the entire operation.
#[derive(Clone, Copy, Debug)]
pub struct CellReleaseFetchLimitsV1 {
    pub peer: CellPeerLimitsV1,
    pub release: CellReleaseLimitsV1,
}

impl CellReleaseFetchLimitsV1 {
    // Clamp once at every public entry, before metadata validation or encoding.
    // Nested calls may tighten this absolute deadline but never renew it.
    fn start(&mut self) -> CellResultV1<()> {
        let started = Instant::now();
        self.peer.validate()?;
        self.release.deadline = self
            .release
            .deadline
            .min(started + self.peer.overall_timeout);
        check_deadline(self.release.deadline)
    }
}

/// Explicit transport choice for the complete TCR1/TCD1/TMR1/TMA1 operation.
/// The options do not alter any content identifier or authorization profile.
#[derive(Clone, Copy, Debug)]
pub struct CellReleaseFetchOptionsV2 {
    pub limits: CellReleaseFetchLimitsV1,
    pub transport: CellFetchTransportV2,
}

impl CellReleaseFetchOptionsV2 {
    pub fn validate(self) -> CellResultV1<()> {
        self.transport.validate(self.limits.peer)?;
        require(
            self.limits.release.max_payload_bytes > 0,
            "release payload budget",
        )?;
        require(self.limits.release.max_chunks > 0, "release chunk budget")?;
        check_deadline(self.limits.release.deadline)
    }

    fn start(&mut self) -> CellResultV1<()> {
        self.limits.start()?;
        self.validate()
    }
}

impl From<CellReleaseFetchLimitsV1> for CellReleaseFetchOptionsV2 {
    fn from(limits: CellReleaseFetchLimitsV1) -> Self {
        Self {
            limits,
            transport: CellFetchTransportV2::OrderedV1,
        }
    }
}

/// Transport observations wrap the unchanged content/closure report. V1 counts
/// one attempted query per dial; persistent V2 counts reserved frame attempts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTransportFetchReportV2<T> {
    pub request_attempts: u64,
    pub report: T,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellModelReleaseFetchReportV1 {
    pub model_root: CellDigestV1,
    pub closure_id: CellDigestV1,
    pub release: CellReleaseFetchReportV1,
}

struct ClosureMarker<'a> {
    closure: &'a CellReleaseClosureV1,
    wire: &'a [u8],
    tensor_model: Option<&'a CellTensorModelManifestV1>,
    readiness: ClosureReadiness<'a>,
}

/// Internal preparation controls only. The residency branch is a typed
/// capacity check over already pinned metadata, not a caller-supplied callback
/// or an execution-authority hook. All branches keep the original session.
#[derive(Clone, Copy, Default)]
enum ClosureReadiness<'a> {
    #[default]
    None,
    Cancellable(&'a AtomicBool),
    ResidentCapacity {
        owner: &'a CellResidencyV1,
        expected: &'a CellLoaderContextV1,
        cancelled: &'a AtomicBool,
    },
}

impl<'a> ClosureReadiness<'a> {
    fn cancelled(self) -> Option<&'a AtomicBool> {
        match self {
            Self::None => None,
            Self::Cancellable(cancelled) | Self::ResidentCapacity { cancelled, .. } => {
                Some(cancelled)
            }
        }
    }
}

/// A complete declared byte set and strict dense tensor metadata observation.
/// It carries no CURRENT, publisher, architecture or execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorModelFetchReportV1 {
    pub manifest_id: CellDigestV1,
    pub model_root: CellDigestV1,
    pub tensor_contract: CellDigestV1,
    pub tensor_files: usize,
    pub release: CellReleaseFetchReportV1,
}

pub fn fetch_tensor_model_to_file(
    store: &CellStoreV1,
    model: &CellTensorModelManifestV1,
    expected: (CellDigestV1, &CellLoaderContextV1),
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<CellTensorModelFetchReportV1> {
    fetch_tensor_model_with_options_to_file(store, model, expected, peers, limits.into(), output)
        .map(|result| result.report)
}

pub fn fetch_tensor_model_with_options_to_file(
    store: &CellStoreV1,
    model: &CellTensorModelManifestV1,
    expected: (CellDigestV1, &CellLoaderContextV1),
    peers: &[SocketAddr],
    mut options: CellReleaseFetchOptionsV2,
    output: &Path,
) -> CellResultV1<CellTransportFetchReportV2<CellTensorModelFetchReportV1>> {
    options.start()?;
    let mut limits = options.limits;
    model.validate()?;
    require(model.id() == expected.0, "tensor model manifest pin")?;
    let root = model.root();
    root.verify_for_loader(root.id(), expected.1)?;
    limits.release.max_payload_bytes = limits
        .release
        .max_payload_bytes
        .min(expected.1.max_payload_bytes);
    limits.release.max_chunks = limits.release.max_chunks.min(expected.1.max_chunks);
    let wire = model.encode();
    let closure = root.closure();
    let release = fetch_release_checked(
        store,
        closure.release(),
        closure.release().id(),
        peers,
        CellReleaseFetchOptionsV2 { limits, ..options },
        Some(output),
        Some(ClosureMarker {
            closure,
            wire: &wire,
            tensor_model: Some(model),
            readiness: ClosureReadiness::None,
        }),
    )?;
    Ok(CellTransportFetchReportV2 {
        request_attempts: release.request_attempts,
        report: CellTensorModelFetchReportV1 {
            manifest_id: model.id(),
            model_root: root.id(),
            tensor_contract: model.contract().id(),
            tensor_files: model.contract().files().len(),
            release: release.report,
        },
    })
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
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<CellClosureFetchReportV1> {
    fetch_closure_with_options_to_file(store, closure, expected, peers, limits.into(), output)
        .map(|result| result.report)
}

pub fn fetch_closure_with_options_to_file(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    options: CellReleaseFetchOptionsV2,
    output: &Path,
) -> CellResultV1<CellTransportFetchReportV2<CellClosureFetchReportV1>> {
    fetch_closure_checked(
        store,
        closure,
        expected,
        peers,
        options,
        Some(output),
        ClosureReadiness::None,
    )
}

/// Prefetch one owner-pinned closure into the disposable cache without creating
/// a completion marker or changing a selected release. This uses the same full
/// manifest, membership, payload and aggregate-budget checks as
/// `fetch_closure_to_file`. A fully warm cache needs no peer connections.
///
/// The receipt is a byte-availability observation only. Residency, safe format
/// parsing, CURRENT and fresh FinalUse checks remain with the loader owner.
pub fn fetch_closure(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
) -> CellResultV1<CellClosureFetchReportV1> {
    fetch_closure_checked(
        store,
        closure,
        expected,
        peers,
        limits.into(),
        None,
        ClosureReadiness::None,
    )
    .map(|result| result.report)
}

/// The original marker-free prefetch with cooperative caller cancellation.
/// Once any worker observes the flag, this transport reservation remains
/// cancelled even if the caller clears it. Verified disposable cache bytes
/// may remain, but no successful closure or resident admission is returned.
pub fn fetch_closure_cancellable(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    cancelled: &AtomicBool,
) -> CellResultV1<CellClosureFetchReportV1> {
    fetch_closure_checked(
        store,
        closure,
        expected,
        peers,
        limits.into(),
        None,
        ClosureReadiness::Cancellable(cancelled),
    )
    .map(|result| result.report)
}

/// The same closure operation with an internal RAM/reference preflight between
/// its complete metadata pass and its first payload request. It neither starts
/// a second transport session nor refunds failed metadata work.
pub(super) fn fetch_closure_for_residency(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    (owner, cancelled): (&CellResidencyV1, &AtomicBool),
) -> CellResultV1<CellClosureFetchReportV1> {
    fetch_closure_checked(
        store,
        closure,
        expected,
        peers,
        limits.into(),
        None,
        ClosureReadiness::ResidentCapacity {
            owner,
            expected,
            cancelled,
        },
    )
    .map(|result| result.report)
}

fn fetch_closure_checked(
    store: &CellStoreV1,
    closure: &CellReleaseClosureV1,
    expected: &CellLoaderContextV1,
    peers: &[SocketAddr],
    mut options: CellReleaseFetchOptionsV2,
    output: Option<&Path>,
    readiness: ClosureReadiness<'_>,
) -> CellResultV1<CellTransportFetchReportV2<CellClosureFetchReportV1>> {
    options.start()?;
    let mut limits = options.limits;
    closure.verify_for_loader(expected)?;
    limits.release.max_payload_bytes = limits
        .release
        .max_payload_bytes
        .min(expected.max_payload_bytes);
    limits.release.max_chunks = limits.release.max_chunks.min(expected.max_chunks);
    let wire = closure.encode();
    let release = fetch_release_checked(
        store,
        closure.release(),
        closure.release().id(),
        peers,
        CellReleaseFetchOptionsV2 { limits, ..options },
        output,
        Some(ClosureMarker {
            closure,
            wire: &wire,
            tensor_model: None,
            readiness,
        }),
    )?;
    Ok(CellTransportFetchReportV2 {
        request_attempts: release.request_attempts,
        report: CellClosureFetchReportV1 {
            closure_id: closure.id(),
            selected_generation: closure.selected_generation(),
            release: release.report,
        },
    })
}

/// Acquire an independently pinned TMR1 model root using the same TCD1
/// preflight, transport reservations, cache and create-only publication owner.
/// The TMR1 marker grants no CURRENT selection, parser admission or FinalUse.
pub fn fetch_model_release_to_file(
    store: &CellStoreV1,
    root: &CellModelReleaseRootV1,
    expected: (CellDigestV1, &CellLoaderContextV1),
    peers: &[SocketAddr],
    limits: CellReleaseFetchLimitsV1,
    output: &Path,
) -> CellResultV1<CellModelReleaseFetchReportV1> {
    fetch_model_release_with_options_to_file(store, root, expected, peers, limits.into(), output)
        .map(|result| result.report)
}

pub fn fetch_model_release_with_options_to_file(
    store: &CellStoreV1,
    root: &CellModelReleaseRootV1,
    expected: (CellDigestV1, &CellLoaderContextV1),
    peers: &[SocketAddr],
    mut options: CellReleaseFetchOptionsV2,
    output: &Path,
) -> CellResultV1<CellTransportFetchReportV2<CellModelReleaseFetchReportV1>> {
    options.start()?;
    let mut limits = options.limits;
    root.verify_for_loader(expected.0, expected.1)?;
    limits.release.max_payload_bytes = limits
        .release
        .max_payload_bytes
        .min(expected.1.max_payload_bytes);
    limits.release.max_chunks = limits.release.max_chunks.min(expected.1.max_chunks);
    let wire = root.encode();
    let closure = root.closure();
    let release = fetch_release_checked(
        store,
        closure.release(),
        closure.release().id(),
        peers,
        CellReleaseFetchOptionsV2 { limits, ..options },
        Some(output),
        Some(ClosureMarker {
            closure,
            wire: &wire,
            tensor_model: None,
            readiness: ClosureReadiness::None,
        }),
    )?;
    Ok(CellTransportFetchReportV2 {
        request_attempts: release.request_attempts,
        report: CellModelReleaseFetchReportV1 {
            model_root: root.id(),
            closure_id: closure.id(),
            release: release.report,
        },
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
    fetch_release_with_options_to_file(store, release, pinned, peers, limits.into(), output)
        .map(|result| result.report)
}

pub fn fetch_release_with_options_to_file(
    store: &CellStoreV1,
    release: &CellReleaseManifestV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    options: CellReleaseFetchOptionsV2,
    output: &Path,
) -> CellResultV1<CellTransportFetchReportV2<CellReleaseFetchReportV1>> {
    fetch_release_checked(store, release, pinned, peers, options, Some(output), None)
}

fn fetch_release_checked(
    store: &CellStoreV1,
    release: &CellReleaseManifestV1,
    pinned: CellDigestV1,
    peers: &[SocketAddr],
    mut options: CellReleaseFetchOptionsV2,
    output: Option<&Path>,
    closure: Option<ClosureMarker<'_>>,
) -> CellResultV1<CellTransportFetchReportV2<CellReleaseFetchReportV1>> {
    options.start()?;
    let limits = options.limits;
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
    if let Some(output) = output {
        match fs::symlink_metadata(output) {
            Ok(_) => return Err(CellErrorV1::Invalid("release marker exists")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let deadline = limits
        .release
        .deadline
        .min(Instant::now() + limits.peer.overall_timeout);
    check_deadline(deadline)?;
    // This owner survives both metadata passes and every member. A persistent
    // connection, quarantine or exhausted quota is never reset at a file edge.
    let session = NetworkFetchSession::new(
        peers,
        limits.peer,
        options.transport,
        deadline,
        closure
            .as_ref()
            .and_then(|marker| marker.readiness.cancelled()),
    )?;
    session.check_cancelled()?;
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
        session.check_cancelled()?;
        check_deadline(deadline)?;
        let (manifest, rejected) = session.manifest(store, *digest)?;
        require(
            manifest.context() == release.context(),
            "release cell context",
        )?;
        if let Some(marker) = &closure {
            marker.closure.verify_manifest(&manifest)?;
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
    if let Some(marker) = &closure {
        if let ClosureReadiness::ResidentCapacity {
            owner,
            expected,
            cancelled,
        } = marker.readiness
        {
            // No payload has been requested yet. The same immutable owner
            // remains borrowed throughout fetch; the final staging pass still
            // rechecks every actual payload and the complete reservation.
            owner.verify_prefetch_capacity(store, marker.closure, expected, deadline, cancelled)?;
        }
    }
    session.check_cancelled()?;
    check_deadline(deadline)?;
    for digest in release.cells() {
        session.check_cancelled()?;
        check_deadline(deadline)?;
        let (_, member) = session.cell(store, *digest)?;
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
    session.check_cancelled()?;
    report.connection_attempts = session.connection_attempts();
    report.received_response_bytes = session.received_response_bytes()?;
    if let Some(model) = closure.as_ref().and_then(|marker| marker.tensor_model) {
        let root = model.root();
        for file in model.contract().files() {
            check_deadline(deadline)?;
            let member = &root.closure().files()[usize::from(file.file_index)];
            let manifest = store
                .manifest(member.manifest)?
                .ok_or(CellErrorV1::Unavailable)?;
            root.closure().verify_manifest(&manifest)?;
            let mut reader =
                super::tensor_reader::CachePayloadReader::new(store, manifest, deadline)?;
            model.contract().verify_reader(
                root,
                model.contract().id(),
                file.file_index,
                &mut reader,
                deadline,
            )?;
        }
    }
    // The no-marker path must retain the same last deadline checkpoint as the
    // publication path; a late cache verification is not a successful prefetch.
    check_deadline(deadline)?;
    session.check_cancelled()?;
    if let Some(output) = output {
        let marker = closure.map_or_else(|| release.encode(), |marker| marker.wire.to_vec());
        publish_marker(&marker, output, deadline)?;
    }
    Ok(CellTransportFetchReportV2 {
        request_attempts: session.request_attempts(),
        report,
    })
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
    // Publication may have completed while a blocking filesystem operation
    // crossed the original deadline. Finish durability and owned cleanup, then
    // refuse a late success. The exact published marker remains available for
    // reconciliation; an expired acknowledgement cannot undo that fact.
    check_deadline(deadline)
}
