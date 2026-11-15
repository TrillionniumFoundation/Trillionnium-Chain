//! Acquisition of one complete declared model/environment closure. The same
//! transport reservation survives every file and both contexts. A successful
//! cache readback is an observation, not CURRENT, FinalUse or a custody receipt.

use std::{collections::BTreeSet, fmt, net::SocketAddr, sync::atomic::AtomicBool, time::Instant};

use super::{CellVersionLoaderContextV1, CellVersionManifestV1, CellVersionReadbackV1};
use crate::cell::{
    network::NetworkFetchSession, require, CellErrorV1, CellFetchTransportV2, CellManifestV1,
    CellReleaseFetchLimitsV1, CellReleaseFetchOptionsV2, CellResultV1, CellStoreV1,
};

/// Actual attempts and application response bytes in the original session,
/// including failed frames and retries. These are plain transport metadata,
/// not independent availability, storage or use evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionFetchTransportReportV1 {
    pub profile: CellFetchTransportV2,
    pub connection_attempts: u64,
    /// V1 counts one query per dial; persistent profiles count reserved frames.
    pub request_attempts: u64,
    /// `None` preserves an unavailable accounting observation on failure. A
    /// successful fetch always has `Some(actual_bytes)`, including `Some(0)`
    /// for an entirely warm cache. Requests and TCP/IP overhead are excluded.
    pub received_response_bytes: Option<u64>,
}

impl CellVersionFetchTransportReportV1 {
    fn unstarted(profile: CellFetchTransportV2) -> Self {
        Self {
            profile,
            connection_attempts: 0,
            request_attempts: 0,
            received_response_bytes: Some(0),
        }
    }

    fn observed(session: &NetworkFetchSession<'_>, profile: CellFetchTransportV2) -> Self {
        Self {
            profile,
            connection_attempts: session.connection_attempts(),
            request_attempts: session.request_attempts(),
            received_response_bytes: session.received_response_bytes().ok(),
        }
    }
}

/// Preserves the original refusal and the consumed session counters. Retrying
/// this API is a new caller reservation; this value never refunds the failed
/// attempt or asserts that a partially populated cache is a complete version.
#[derive(Debug)]
pub struct CellVersionFetchFailureV1 {
    error: CellErrorV1,
    transport: CellVersionFetchTransportReportV1,
}

impl CellVersionFetchFailureV1 {
    pub fn error(&self) -> &CellErrorV1 {
        &self.error
    }

    pub fn transport(&self) -> &CellVersionFetchTransportReportV1 {
        &self.transport
    }

    pub fn into_parts(self) -> (CellErrorV1, CellVersionFetchTransportReportV1) {
        (self.error, self.transport)
    }

    /// Explicitly discard the transport observation when only the cause is
    /// needed. No implicit conversion drops failed-attempt accounting.
    pub fn into_error(self) -> CellErrorV1 {
        self.error
    }
}

impl fmt::Display for CellVersionFetchFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for CellVersionFetchFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Created only after every exact declared TCM1 and its complete payload have
/// passed a fresh `CellVersionManifestV1::verify_cached` under the original
/// deadline and independent owner contexts. Fields are private so a caller
/// cannot manufacture a successful checked observation from transport counts.
///
/// Reads are sequential observations of a disposable cache. This does not
/// establish simultaneous remote availability, physical independence, future
/// retention, executable ABI compatibility or permission to load the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionFetchObservationV1 {
    readback: CellVersionReadbackV1,
    transport: CellVersionFetchTransportReportV1,
    progress: CellManifestSetFetchProgressV1,
    started_at: Instant,
    completed_at: Instant,
    deadline: Instant,
}

impl CellVersionFetchObservationV1 {
    pub fn readback(&self) -> &CellVersionReadbackV1 {
        &self.readback
    }

    pub fn transport(&self) -> &CellVersionFetchTransportReportV1 {
        &self.transport
    }

    /// Positions satisfied from verified cache bytes when each member starts.
    /// A later member can reuse an object downloaded by an earlier member.
    pub fn cached_chunks(&self) -> usize {
        self.progress.cached_chunks
    }

    /// Positions covered by verified, committed downloads in this session.
    pub fn downloaded_chunks(&self) -> usize {
        self.progress.downloaded_chunks
    }

    /// Committed object bytes, counted once per digest within each member.
    /// Shared objects already cached for a later member are not downloaded
    /// again unless the disposable cache evicts them in between.
    pub fn downloaded_bytes(&self) -> u64 {
        self.progress.downloaded_bytes
    }

    pub fn rejected_responses(&self) -> usize {
        self.progress.rejected_responses
    }

    /// Peers that supplied verified payload objects, excluding metadata-only
    /// replies. These addresses do not attest independent operators or domains.
    pub fn supplying_peers(&self) -> &BTreeSet<SocketAddr> {
        &self.progress.supplying_peers
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// No connection or request was attempted. Such a readback provides no
    /// fresh network evidence. A false value also does not imply that all
    /// dependencies came from peers: any subset may already have been cached.
    pub fn cache_only(&self) -> bool {
        self.transport.connection_attempts == 0
            && self.transport.request_attempts == 0
            && self.transport.received_response_bytes == Some(0)
    }
}

/// Fetch the exact TCV1 model/environment union without creating a marker or
/// changing release selection. All owner pins, contexts, declared manifests
/// and aggregate payload/chunk budgets are checked before any network work.
/// Every actual manifest is checked before requesting any payload.
///
/// One session owns the original absolute deadline, cancellation, connection,
/// request and response-byte quotas across both contexts. Cancellation and
/// filesystem deadlines are cooperative; blocking storage calls are not
/// preemptible. Safe runtime loading and current FinalUse remain separate.
pub fn fetch_complete_version(
    store: &CellStoreV1,
    version: &CellVersionManifestV1,
    expected: &CellVersionLoaderContextV1<'_>,
    peers: &[SocketAddr],
    mut options: CellReleaseFetchOptionsV2,
    cancelled: Option<&AtomicBool>,
) -> Result<CellVersionFetchObservationV1, CellVersionFetchFailureV1> {
    let started_at = Instant::now();
    let session = (|| {
        options.transport.validate(options.limits.peer)?;
        options.limits.release.deadline = options
            .limits
            .release
            .deadline
            .min(started_at + options.limits.peer.overall_timeout);
        options.validate()?;
        NetworkFetchSession::new(
            peers,
            options.limits.peer,
            options.transport,
            options.limits.release.deadline,
            cancelled,
        )
    })()
    .map_err(|error| CellVersionFetchFailureV1 {
        error,
        transport: CellVersionFetchTransportReportV1::unstarted(options.transport),
    })?;
    let deadline = options.limits.release.deadline;
    (|| {
        checkpoint(&session, deadline)?;
        version.verify_for_loader(expected)?;
        let manifests: Vec<_> = version.manifests().iter().collect();
        let progress = fetch_manifest_set_in_session(store, &manifests, &session, options.limits)?;
        checkpoint(&session, deadline)?;
        let readback = version.verify_cached(store, expected, options.limits.release)?;
        let transport = CellVersionFetchTransportReportV1 {
            profile: options.transport,
            connection_attempts: session.connection_attempts(),
            request_attempts: session.request_attempts(),
            received_response_bytes: Some(session.received_response_bytes()?),
        };
        checkpoint(&session, deadline)?;
        let completed_at = Instant::now();
        require(completed_at < deadline, "version fetch deadline")?;
        Ok(CellVersionFetchObservationV1 {
            readback,
            transport,
            progress,
            started_at,
            completed_at,
            deadline,
        })
    })()
    .map_err(|error| CellVersionFetchFailureV1 {
        error,
        transport: CellVersionFetchTransportReportV1::observed(&session, options.transport),
    })
}

/// Internal acquisition progress, deliberately not a checked version receipt.
/// The caller still must verify its entire version/set after this returns.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(in crate::cell) struct CellManifestSetFetchProgressV1 {
    pub(in crate::cell) cached_chunks: usize,
    pub(in crate::cell) downloaded_chunks: usize,
    pub(in crate::cell) downloaded_bytes: u64,
    pub(in crate::cell) rejected_responses: usize,
    pub(in crate::cell) supplying_peers: BTreeSet<SocketAddr>,
}

/// Reuse an existing session for a bounded, canonical manifest union. The
/// caller admits its independent version/set pins first and supplies the
/// session's original limits. This helper neither creates nor renews a budget.
/// Unlike TCR1, the union can contain distinct model/environment contexts.
pub(in crate::cell) fn fetch_manifest_set_in_session(
    store: &CellStoreV1,
    manifests: &[&CellManifestV1],
    session: &NetworkFetchSession<'_>,
    limits: CellReleaseFetchLimitsV1,
) -> CellResultV1<CellManifestSetFetchProgressV1> {
    let deadline = limits.release.deadline;
    checkpoint(session, deadline)?;
    require(!manifests.is_empty(), "version fetch manifest count")?;
    limits.peer.validate()?;
    let mut previous = None;
    let mut payload_bytes = 0u64;
    let mut chunks = 0u64;
    // Complete aggregate admission precedes manifest cache writes and every
    // request. No late member can reveal an over-budget dependency afterward.
    for manifest in manifests {
        checkpoint(session, deadline)?;
        manifest.validate()?;
        let id = manifest.id();
        require(
            previous.is_none_or(|previous| previous < id),
            "version fetch canonical manifests",
        )?;
        previous = Some(id);
        require(
            manifest.size() <= limits.peer.max_cell_bytes,
            "cell exceeds byte budget",
        )?;
        payload_bytes = payload_bytes
            .checked_add(manifest.size())
            .ok_or(CellErrorV1::Invalid("version byte overflow"))?;
        chunks = chunks
            .checked_add(manifest.chunks().len() as u64)
            .ok_or(CellErrorV1::Invalid("version chunk overflow"))?;
        require(
            payload_bytes <= limits.release.max_payload_bytes
                && chunks <= limits.release.max_chunks,
            "version aggregate read budget",
        )?;
    }
    let mut progress = CellManifestSetFetchProgressV1::default();
    for declared in manifests {
        checkpoint(session, deadline)?;
        let (actual, rejected) = session.manifest(store, declared.id())?;
        require(actual == **declared, "version actual manifest")?;
        progress.rejected_responses += rejected;
    }
    for declared in manifests {
        checkpoint(session, deadline)?;
        let (actual, member) = session.cell(store, declared.id())?;
        require(actual == **declared, "version actual manifest")?;
        progress.cached_chunks += member.cached_chunks;
        progress.downloaded_chunks += member.downloaded_chunks;
        progress.downloaded_bytes = progress
            .downloaded_bytes
            .checked_add(member.downloaded_bytes)
            .ok_or(CellErrorV1::Invalid("version downloaded byte overflow"))?;
        progress.rejected_responses += member.rejected_responses;
        progress.supplying_peers.extend(member.supplying_peers);
    }
    checkpoint(session, deadline)?;
    Ok(progress)
}

fn checkpoint(session: &NetworkFetchSession<'_>, deadline: Instant) -> CellResultV1<()> {
    session.check_cancelled()?;
    super::deadline(deadline)
}

#[cfg(test)]
mod tests;
