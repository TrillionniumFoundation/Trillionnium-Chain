use super::super::selection;
use super::auth::{self, BootstrapQueryV3, MAX_REPLY_BYTES, RESPONSE_HEADER_BYTES};
use super::*;
use crate::cell::{
    network::{self, RequestContext, ResponseBudget},
    CellFetchReportV1, CellManifestV1, CellPeerLimitsV1, CellStoreV1,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const MAX_SERVER_CONNECTIONS: u64 = 64;

#[derive(Clone, Debug)]
pub struct CellDiscoveryOptionsV3 {
    pub request: CellDiscoveryRequestV1,
    pub bootstraps: Vec<CellBootstrapPinV3>,
    /// Host-supplied bootstrap authority, separate from provider advertising keys.
    pub bootstrap_keys: CellPqKeyPinsV2,
    pub addresses: CellDiscoveryAddressPolicyV1,
}
impl CellDiscoveryOptionsV3 {
    fn validate(&self) -> CellResultV1<()> {
        self.request.validate()?;
        self.addresses.validate()?;
        require(
            !self.bootstraps.is_empty()
                && self.bootstraps.len() <= MAX_DISCOVERY_BOOTSTRAPS
                && self
                    .bootstraps
                    .iter()
                    .map(|pin| pin.endpoint)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.bootstraps.len()
                && self
                    .bootstraps
                    .iter()
                    .map(|pin| pin.key_id)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.bootstraps.len(),
            "discovery bootstrap count/duplicates",
        )?;
        for peer in &self.bootstraps {
            peer.validate()?;
            self.addresses.check(peer.endpoint)?;
            let authority = self
                .bootstrap_keys
                .pins()
                .find(|pin| pin.key_id == peer.key_id)
                .ok_or(CellErrorV1::Invalid("PQ bootstrap unknown key"))?;
            require(
                authority.generation == peer.generation,
                "PQ bootstrap key generation",
            )?;
            authority.live_at(wall_now()?.as_secs())?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellDiscoveryObservationV3 {
    pub connection_attempts: u64,
    pub received_response_bytes: u64,
    /// Each reserves at most one pure ML-DSA-65 verification, including cheap
    /// invalid-record rejections. This is not a CPU-duration measurement.
    pub record_validation_attempts: usize,
    /// Native bootstrap verifications, charged against the same 64-operation cap.
    pub bootstrap_validation_attempts: usize,
    pub authenticated_bootstrap_responses: usize,
    pub rejected_records: usize,
    pub capacity_rejections: usize,
    pub rejected_bootstraps: usize,
}
/// Failed operations retain their actual denominator, including consumed bytes
/// and connections. Callers must not discard this observation when aggregating runs.
#[derive(Debug)]
pub struct CellDiscoveryFailureV3 {
    pub cause: CellErrorV1,
    pub discovery: CellDiscoveryObservationV3,
    /// Original shared Cell session, including failed manifest/chunk operations.
    pub total_connection_attempts: u64,
    /// None only if the shared byte-accounting mutex itself became unavailable.
    pub total_received_response_bytes: Option<u64>,
}
impl std::fmt::Display for CellDiscoveryFailureV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, f)
    }
}
impl std::error::Error for CellDiscoveryFailureV3 {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellDiscoveryFetchReportV3 {
    pub discovery: CellDiscoveryObservationV3,
    pub discovered_providers: Vec<SocketAddr>,
    /// Result of the first actual manifest-cache read, before any network
    /// manifest is persisted and the common Cell fetch rechecks that cache.
    pub manifest_initial_cache_hit: bool,
    /// Its connection/received-byte totals include discovery, without double
    /// adding the separate discovery breakdown above.
    pub fetch: CellFetchReportV1,
}

/// Only actual bootstrap replies produce the bounded candidate list. The local
/// directory is replay protection, not an alternate preconfigured peer list.
/// Discovery and all subsequent manifest/chunk reads share these same counters
/// and the earlier of the caller's original deadline and declared timeout.
pub fn fetch_discovered_cell_to_file_pq_v3(
    store: &CellStoreV1,
    directory: &CellProviderDirectoryV3,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    output: &Path,
) -> Result<(CellManifestV1, CellDiscoveryFetchReportV3), Box<CellDiscoveryFailureV3>> {
    let mut observation = CellDiscoveryObservationV3::default();
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let result = (|| -> CellResultV1<_> {
        options.validate()?;
        limits.validate()?;
        let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(overall)?;
        let transport = RequestContext {
            cancelled: None,
            timeout: limits.request_timeout,
            overall,
            requests_left: &requests_left,
            responses: &responses,
        };
        let (peers, expires) = discover(directory, options, &transport, &mut observation)?;
        let transport = RequestContext {
            overall: overall.min(expires),
            ..transport
        };
        check_deadline(transport.overall)?;
        // Validate the owner-pinned context before any create-only output is
        // published. The second access rechecks the actual content-addressed cache.
        let (manifest, manifest_rejected, manifest_initial_cache_hit) =
            network::fetch_manifest_observed(
                store,
                options.request.manifest,
                &peers,
                limits,
                &transport,
            )?;
        require(
            cell_discovery_context_digest(manifest.context())? == options.request.cell_context,
            "discovered cell context",
        )?;
        let (manifest, mut fetch) = network::fetch_cell_in_session(
            store,
            options.request.manifest,
            &peers,
            limits,
            &transport,
            Some(output),
        )?;
        // The shared counters already include the first manifest request; only its
        // separately returned rejection count needs carrying across the cache hit.
        fetch.rejected_responses += manifest_rejected;
        Ok((
            manifest,
            CellDiscoveryFetchReportV3 {
                discovery: observation.clone(),
                discovered_providers: peers,
                manifest_initial_cache_hit,
                fetch,
            },
        ))
    })();
    result.map_err(|cause| {
        Box::new(CellDiscoveryFailureV3 {
            cause,
            discovery: observation,
            total_connection_attempts: limits.max_connections
                - requests_left.load(Ordering::Relaxed),
            total_received_response_bytes: responses.received().ok(),
        })
    })
}

pub(super) struct ObservedAdvertisement {
    pub(super) record: CellProviderRecordV3,
    // Fixed when this exact record was actually received. Equal-record retries
    // cannot renew its monotonic lease; a higher sequence replaces the record.
    pub(super) expires: Instant,
    pub(super) expires_unix_seconds: u64,
    // Actual bootstrap positions for this exact current statement, not claims
    // supplied by an advertiser or inherited from a superseded sequence.
    pub(super) sources: u8,
}

pub(super) fn discover(
    directory: &CellProviderDirectoryV3,
    options: &CellDiscoveryOptionsV3,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<(Vec<SocketAddr>, Instant)> {
    // Scope is one pinned manifest. Identity is its advertising owner, not the
    // endpoint: the same owner can revoke an old address or shorten its TTL.
    // Both maps are bounded by the unchanged 64 actual validation slots; the
    // persistent current-epoch replay quota permits at most 64 identities.
    let mut observed: BTreeMap<CellDigestV1, ObservedAdvertisement> = BTreeMap::new();
    // Remember all eligible, strictly verified statements from this operation,
    // including historical sequences. A -> C(higher seq) -> B(conflicting old
    // seq) must not hide equivocation behind the persistent replay rejection.
    // This fixed per-operation history has at most the original 64 validation
    // slots; no eviction, clock reset, extra signature or network attempt.
    let mut verified_statements: BTreeMap<(CellDigestV1, u64, u64), CellDigestV1> = BTreeMap::new();
    let mut equivocated = BTreeSet::new();
    // The local directory is replay protection only. These rows are discarded
    // and cannot manufacture a candidate when no bootstrap supplies one.
    directory.records(options.request, wall_now()?.as_secs(), transport.overall)?;
    for _round in 0..2 {
        // Apply source fairness before the current-epoch replay quota, not
        // only when selecting already-admitted endpoints. Retain at most one
        // bounded round of four MAX_REPLY_BYTES frames; original connection,
        // byte, signature and deadline allowances remain unchanged.
        let mut replies = Vec::with_capacity(MAX_DISCOVERY_BOOTSTRAPS);
        for (source, bootstrap) in options.bootstraps.iter().enumerate() {
            // Do not stop at eight temporary endpoints: a later bootstrap in
            // this same bounded round may carry their newer signed high water.
            let response = exchange(
                *bootstrap,
                &options.bootstrap_keys,
                1,
                &options.request.encode(),
                MAX_REPLY_BYTES,
                transport,
                observation,
            );
            let reply = match response {
                Ok(value) => value,
                Err(_) => {
                    observation.rejected_bootstraps += 1;
                    continue;
                }
            };
            let wire = reply.body;
            if wire.is_empty()
                || usize::from(wire[0]) > MAX_DISCOVERED_PROVIDERS
                || wire.len() != 1 + usize::from(wire[0]) * CELL_PROVIDER_RECORD_BYTES_V3
            {
                observation.rejected_bootstraps += 1;
                continue;
            }
            let received_at = Instant::now();
            let wall = wall_now()?;
            directory.records(options.request, wall.as_secs(), transport.overall)?;
            replies.push((
                source,
                *bootstrap,
                wire,
                received_at,
                wall,
                reply.expires,
                reply.expires_unix_seconds,
            ));
        }
        for slot in 0..MAX_DISCOVERED_PROVIDERS {
            for (
                source,
                bootstrap,
                wire,
                received_at,
                received_wall,
                origin_expiry,
                origin_unix_expiry,
            ) in &replies
            {
                let start = 1 + slot * CELL_PROVIDER_RECORD_BYTES_V3;
                let Some(raw) = wire.get(start..start + CELL_PROVIDER_RECORD_BYTES_V3) else {
                    continue;
                };
                check_deadline(transport.overall)?;
                require(
                    observation.record_validation_attempts
                        + observation.bootstrap_validation_attempts
                        < MAX_DISCOVERY_RECORDS,
                    "discovery signature budget",
                )?;
                observation.record_validation_attempts += 1;
                let checked = (|| -> CellResultV1<_> {
                    let record = CellProviderRecordV3::decode(raw)?;
                    // A later slow reply cannot erase a signed conflict that
                    // was eligible when its original bytes were received.
                    let valid_until = record.verify_at(
                        options.request,
                        received_wall.as_secs(),
                        &options.addresses,
                        directory.keys(),
                    )?;
                    let remaining = Duration::from_secs(valid_until)
                        .checked_sub(*received_wall)
                        .ok_or(CellErrorV1::Invalid("discovery expiry"))?;
                    Ok((
                        record,
                        (*received_at + remaining).min(*origin_expiry),
                        valid_until.min(*origin_unix_expiry),
                    ))
                })();
                let (record, expiry, valid_until) = match checked {
                    Ok(value) => value,
                    Err(_) => {
                        observation.rejected_records += 1;
                        continue;
                    }
                };
                let owner = record.statement.owner;
                let lease_epoch = record.statement.lease_epoch;
                if !remember_verified_statement(
                    &mut verified_statements,
                    &mut equivocated,
                    &mut observed,
                    &record,
                )? {
                    observation.rejected_records += 1;
                    continue;
                }
                // Historical signature evidence is not current availability.
                // Enforce both the original record/key expiry and the current
                // wall clock before writing the durable directory; no second
                // signature verification or new reservation is performed.
                let wall = wall_now()?;
                if record.live_at(wall.as_secs()).is_err()
                    || wall.as_secs() >= valid_until
                    || Instant::now() >= expiry
                {
                    observation.rejected_records += 1;
                    continue;
                }
                match directory.accept_verified(
                    &record,
                    bootstrap.endpoint.ip(),
                    wall.as_secs(),
                    transport.overall.min(expiry),
                ) {
                    Ok(()) => (),
                    Err(CellErrorV1::Invalid("discovery identity capacity")) => {
                        observation.capacity_rejections += 1;
                        observation.rejected_records += 1;
                        continue;
                    }
                    Err(CellErrorV1::Invalid("discovery sequence equivocation")) => {
                        // A verified equal-sequence conflict disqualifies this
                        // identity for this operation, including its first hint.
                        equivocated.insert((owner, lease_epoch));
                        if observed
                            .get(&owner)
                            .is_some_and(|seen| seen.record.statement.lease_epoch == lease_epoch)
                        {
                            observed.remove(&owner);
                        }
                        observation.rejected_records += 1;
                        continue;
                    }
                    Err(CellErrorV1::Invalid(
                        "discovery sequence replay" | "discovery immutable pin",
                    )) => {
                        observation.rejected_records += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                if equivocated.contains(&(owner, lease_epoch)) {
                    observation.rejected_records += 1;
                    continue;
                }
                check_deadline(expiry)?;
                if !retain_observed(&mut observed, record, expiry, valid_until, 1_u8 << *source)? {
                    observation.rejected_records += 1;
                }
            }
        }
        if !observed.is_empty() {
            break;
        }
    }
    // Reconcile against the current complete high-water snapshot. A concurrent
    // operation may have advanced a key while we queried another bootstrap;
    // its newer local row is never imported as an unobserved provider.
    let sampled_at = Instant::now();
    let wall = wall_now()?;
    let current: BTreeMap<_, _> = directory
        .records(options.request, wall.as_secs(), transport.overall)?
        .into_iter()
        .map(|record| (record.statement.owner, record))
        .collect();
    let mut candidates = Vec::new();
    for (owner, seen) in observed {
        if current.get(&owner) != Some(&seen.record)
            || seen.record.statement.withdrawn
            || seen.record.live_at(wall.as_secs()).is_err()
            || wall.as_secs() >= seen.expires_unix_seconds
        {
            continue;
        }
        let Some(remaining) =
            Duration::from_secs(seen.record.statement.expires_unix_seconds).checked_sub(wall)
        else {
            continue;
        };
        let expiry = (sampled_at + remaining)
            .min(seen.expires)
            .min(transport.overall);
        if Instant::now() >= expiry {
            continue;
        }
        // Defer the eight-endpoint limit until every eligible current identity
        // has competed across observed sources and advertised network prefixes.
        candidates.push(selection::Candidate {
            owner,
            endpoint: seen.record.statement.endpoint,
            sources: seen.sources,
            expires: expiry,
        });
    }
    let candidates = selection::select(candidates)?;
    if candidates.is_empty() && observation.capacity_rejections > 0 {
        return Err(CellErrorV1::Invalid("discovery identity capacity"));
    }
    require(
        !candidates.is_empty(),
        "discovery has no admissible provider",
    )?;
    let expires = candidates
        .iter()
        .map(|(_, expiry)| *expiry)
        .min()
        .unwrap_or(transport.overall);
    Ok((
        candidates.into_iter().map(|(peer, _)| peer).collect(),
        expires,
    ))
}

/// Publish one pre-signed record to one host-pinned rendezvous. The native
/// signed ACK binds the exact advertisement and fresh query after durable readback.
pub fn announce_cell_provider_pq_v3(
    record: &CellProviderRecordV3,
    bootstrap_index: usize,
    provider_keys: &CellPqKeyPinsV2,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
) -> Result<CellDiscoveryObservationV3, Box<CellDiscoveryFailureV3>> {
    let mut observation = CellDiscoveryObservationV3::default();
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let result = (|| -> CellResultV1<()> {
        options.validate()?;
        limits.validate()?;
        let bootstrap = *options
            .bootstraps
            .get(bootstrap_index)
            .ok_or(CellErrorV1::Invalid("PQ bootstrap index"))?;
        let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(overall)?;
        observation.record_validation_attempts += 1;
        let sampled = Instant::now();
        let wall = wall_now()?;
        let valid_until = record.verify_at(
            options.request,
            wall.as_secs(),
            &options.addresses,
            provider_keys,
        )?;
        let remaining = Duration::from_secs(valid_until)
            .checked_sub(wall)
            .ok_or(CellErrorV1::Invalid("discovery expiry"))?;
        let overall = overall.min(sampled + remaining);
        check_deadline(overall)?;
        require_current_authority(record, wall_now()?.as_secs(), provider_keys)?;
        let transport = RequestContext {
            cancelled: None,
            timeout: limits.request_timeout,
            overall,
            requests_left: &requests_left,
            responses: &responses,
        };
        let ack = exchange(
            bootstrap,
            &options.bootstrap_keys,
            2,
            &record.encode(),
            32,
            &transport,
            &mut observation,
        )?;
        require(
            ack.body == record.digest(),
            "discovery durable ACK identity",
        )?;
        let current_wall = wall_now()?.as_secs();
        require_current_authority(record, current_wall, provider_keys)?;
        require(
            current_wall < ack.expires_unix_seconds,
            "PQ bootstrap response expired",
        )?;
        check_deadline(overall.min(ack.expires))
    })();
    match result {
        Ok(()) => Ok(observation),
        Err(cause) => {
            if observation.connection_attempts > 0 {
                observation.rejected_bootstraps += 1;
            } else if observation.record_validation_attempts > 0 {
                observation.rejected_records += 1;
            }
            Err(Box::new(CellDiscoveryFailureV3 {
                cause,
                discovery: observation,
                total_connection_attempts: limits.max_connections
                    - requests_left.load(Ordering::Relaxed),
                total_received_response_bytes: responses.received().ok(),
            }))
        }
    }
}

pub(super) struct ReceivedReply {
    pub(super) body: Vec<u8>,
    pub(super) expires: Instant,
    pub(super) expires_unix_seconds: u64,
}

pub(super) fn exchange(
    bootstrap: CellBootstrapPinV3,
    keys: &CellPqKeyPinsV2,
    kind: u8,
    body: &[u8],
    maximum: usize,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<ReceivedReply> {
    check_deadline(transport.overall)?;
    require(
        observation.connection_attempts < MAX_DISCOVERY_CONNECTIONS,
        "discovery connection budget",
    )?;
    require(
        observation.received_response_bytes < MAX_DISCOVERY_RESPONSE_BYTES_V3,
        "discovery response budget",
    )?;
    require(
        observation.record_validation_attempts + observation.bootstrap_validation_attempts
            < MAX_DISCOVERY_RECORDS,
        "discovery signature budget",
    )?;
    transport.responses.require_remaining()?;
    // Each actual attempt receives a fresh OS nonce before network side effects.
    // The API never lets a caller resume or replay an old query identity.
    let query = BootstrapQueryV3::fresh(kind, bootstrap, body)?;
    transport
        .requests_left
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
    observation.connection_attempts += 1;
    let deadline = transport.overall.min(Instant::now() + transport.timeout);
    let mut stream =
        TcpStream::connect_timeout(&bootstrap.endpoint, network::remaining(deadline)?)?;
    network::write_deadline(&mut stream, &query.encode(), deadline)?;
    let mut header = [0; RESPONSE_HEADER_BYTES];
    read_response(
        &mut stream,
        &mut header,
        deadline,
        transport.responses,
        observation,
    )?;
    let length = auth::response_length(&header, maximum)?;
    let mut wire = vec![0; RESPONSE_HEADER_BYTES + length];
    wire[..RESPONSE_HEADER_BYTES].copy_from_slice(&header);
    read_response(
        &mut stream,
        &mut wire[RESPONSE_HEADER_BYTES..],
        deadline,
        transport.responses,
        observation,
    )?;
    observation.bootstrap_validation_attempts += 1;
    let sampled = Instant::now();
    let wall = wall_now()?;
    let response = auth::verify_response(&query, &wire, maximum, wall.as_secs(), keys)?;
    check_deadline(deadline)?;
    observation.authenticated_bootstrap_responses += 1;
    let remaining = Duration::from_secs(response.expires_unix_seconds)
        .checked_sub(wall)
        .ok_or(CellErrorV1::Invalid("PQ bootstrap response expired"))?;
    let expires = (sampled + remaining).min(transport.overall);
    check_deadline(expires)?;
    require(
        wall_now()?.as_secs() < response.expires_unix_seconds,
        "PQ bootstrap response expired",
    )?;
    if response.status == 2 {
        observation.capacity_rejections += 1;
        return Err(CellErrorV1::Invalid("discovery identity capacity"));
    }
    require(response.status == 0, "discovery denied reply")?;
    Ok(ReceivedReply {
        body: response.body,
        expires,
        expires_unix_seconds: response.expires_unix_seconds,
    })
}
fn read_response(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    parent: &ResponseBudget,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<()> {
    while !bytes.is_empty() {
        let available = MAX_DISCOVERY_RESPONSE_BYTES_V3 - observation.received_response_bytes;
        require(available > 0, "discovery response byte budget exhausted")?;
        let count = bytes.len().min(available as usize);
        match parent.read(stream, &mut bytes[..count], deadline) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "discovery truncated reply",
                )
                .into())
            }
            Ok(read) => {
                observation.received_response_bytes += read as u64;
                bytes = &mut bytes[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct CellRendezvousLimitsV3 {
    pub request_timeout: Duration,
    pub lifetime: Duration,
    pub max_connections: u64,
}
impl CellRendezvousLimitsV3 {
    /// Validate the finite service allowance before publishing listener readiness.
    pub fn validate(self) -> CellResultV1<()> {
        require(
            self.request_timeout >= Duration::from_millis(10)
                && self.request_timeout <= Duration::from_secs(30)
                && self.lifetime >= self.request_timeout
                && self.lifetime <= Duration::from_secs(3600)
                && (1..=MAX_SERVER_CONNECTIONS).contains(&self.max_connections),
            "discovery server bounds",
        )
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellRendezvousReportV3 {
    pub connections: u64,
    pub rejected_requests: u64,
    pub record_validation_attempts: usize,
    /// Each reserves two native operations: signing and the signer's mandatory
    /// self-verification. Rejected attempts never refund these reservations.
    pub response_signing_attempts: usize,
}

/// Finite native TCP service. Provider verifications and response signatures
/// including each signer's mandatory self-verification consume one 64-operation cap. The pinned address must be the
/// actual bound listener. Keys identify sources; they do not prove independent operators.
pub fn serve_cell_rendezvous_pq_v3(
    listener: &TcpListener,
    directory: &CellProviderDirectoryV3,
    signer: &CellBootstrapSignerV3,
    addresses: &CellDiscoveryAddressPolicyV1,
    shutdown: &AtomicBool,
    limits: CellRendezvousLimitsV3,
) -> CellResultV1<CellRendezvousReportV3> {
    limits.validate()?;
    addresses.validate()?;
    require(
        signer.identity().endpoint == listener.local_addr()?,
        "PQ bootstrap listener pin",
    )?;
    addresses.check(signer.identity().endpoint)?;
    listener.set_nonblocking(true)?;
    let overall = Instant::now() + limits.lifetime;
    let mut report = CellRendezvousReportV3::default();
    while !shutdown.load(Ordering::Relaxed)
        && report.connections < limits.max_connections
        && report.record_validation_attempts + 2 * report.response_signing_attempts + 2
            <= MAX_DISCOVERY_RECORDS
        && Instant::now() < overall
    {
        match listener.accept() {
            Ok((mut stream, source)) => {
                report.connections += 1;
                let deadline = overall.min(Instant::now() + limits.request_timeout);
                if !matches!(
                    serve_one(
                        &mut stream,
                        source,
                        directory,
                        signer,
                        addresses,
                        deadline,
                        &mut report
                    ),
                    Ok(false)
                ) {
                    report.rejected_requests += 1;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(report)
}

fn serve_one(
    stream: &mut TcpStream,
    source: SocketAddr,
    directory: &CellProviderDirectoryV3,
    signer: &CellBootstrapSignerV3,
    addresses: &CellDiscoveryAddressPolicyV1,
    deadline: Instant,
    report: &mut CellRendezvousReportV3,
) -> CellResultV1<bool> {
    let mut header = [0; auth::QUERY_HEADER_BYTES];
    network::read_deadline(stream, &mut header, deadline, None)?;
    let length = auth::query_length(&header)?;
    let mut wire = vec![0; auth::QUERY_HEADER_BYTES + length];
    wire[..auth::QUERY_HEADER_BYTES].copy_from_slice(&header);
    network::read_deadline(
        stream,
        &mut wire[auth::QUERY_HEADER_BYTES..],
        deadline,
        None,
    )?;
    let query = BootstrapQueryV3::decode(&wire)?;
    require(
        query.pin == signer.identity(),
        "PQ bootstrap request target",
    )?;
    // Reserve signing BEFORE processing. Every completed or denied valid query
    // is authenticated; malformed requests simply close without unsigned fallbacks.
    require(
        report.record_validation_attempts + 2 * report.response_signing_attempts + 2
            <= MAX_DISCOVERY_RECORDS,
        "discovery server signature budget",
    )?;
    report.response_signing_attempts += 1;
    let response = serve_body(&query, source, directory, addresses, deadline, report);
    let (status, body) = match response {
        Ok(body) => (0, body),
        Err(CellErrorV1::Invalid("discovery identity capacity")) => (2, Vec::new()),
        Err(_) => (1, Vec::new()),
    };
    check_deadline(deadline)?;
    let frame = signer.sign_response(&query, status, &body, wall_now()?.as_secs())?;
    check_deadline(deadline)?;
    network::write_deadline(stream, &frame, deadline)?;
    Ok(status != 0)
}

fn serve_body(
    query: &BootstrapQueryV3,
    source: SocketAddr,
    directory: &CellProviderDirectoryV3,
    addresses: &CellDiscoveryAddressPolicyV1,
    deadline: Instant,
    report: &mut CellRendezvousReportV3,
) -> CellResultV1<Vec<u8>> {
    let now = wall_now()?.as_secs();
    if query.kind == 2 {
        require(
            report.record_validation_attempts + 2 * report.response_signing_attempts
                < MAX_DISCOVERY_RECORDS,
            "discovery server signature budget",
        )?;
        report.record_validation_attempts += 1;
        let record = CellProviderRecordV3::decode(&query.body)?;
        record.verify_at(record.statement.request, now, addresses, directory.keys())?;
        let committed_at = wall_now()?.as_secs();
        require_current_authority(&record, committed_at, directory.keys())?;
        directory.accept_verified(&record, source.ip(), committed_at, deadline)?;
        // Expiry after a successful commit does not rewind durable high water.
        // It does prevent an acknowledgement from claiming current acceptance.
        require_current_authority(&record, wall_now()?.as_secs(), directory.keys())?;
        Ok(record.digest().to_vec())
    } else {
        let request = CellDiscoveryRequestV1::decode(&query.body)?;
        let mut records = directory.records(request, now, deadline)?;
        // Replay high water includes inactive leases. Give active providers
        // priority in the finite reply, then use remaining slots for live
        // withdrawals. This neither evicts history nor guarantees that every
        // withdrawal is propagated when eight active providers fill the reply.
        // Stable sorting preserves the directory's order within each class.
        records.sort_by_key(|record| record.statement.withdrawn);
        let mut body = vec![0];
        for record in records {
            if body[0] as usize == MAX_DISCOVERED_PROVIDERS {
                break;
            }
            // A retained statement can outlive its pinned key. Filter that
            // inactive high water before spending a native verification slot;
            // it must not turn other valid records into an all-or-nothing denial.
            if record.statement.request != request
                || require_current_authority(&record, now, directory.keys()).is_err()
            {
                continue;
            }
            require(
                report.record_validation_attempts + 2 * report.response_signing_attempts
                    < MAX_DISCOVERY_RECORDS,
                "discovery server signature budget",
            )?;
            report.record_validation_attempts += 1;
            record.verify_at(request, now, addresses, directory.keys())?;
            body.extend(record.encode());
            body[0] += 1;
        }
        check_deadline(deadline)?;
        Ok(body)
    }
}

fn require_current_authority(
    record: &CellProviderRecordV3,
    now: u64,
    keys: &CellPqKeyPinsV2,
) -> CellResultV1<()> {
    record.live_at(now)?;
    let pin = keys
        .pins()
        .find(|pin| pin.key_id == record.statement.owner)
        .ok_or(CellErrorV1::Invalid("PQ Cell unknown key"))?;
    require(
        pin.generation == record.statement.owner_generation,
        "PQ Cell key generation",
    )?;
    pin.live_at(now)
}

/// Epoch is part of replay identity. A conflict in a retired epoch cannot erase
/// a separately observed current-epoch lease for the same advertising owner.
pub(super) fn remember_verified_statement(
    statements: &mut BTreeMap<(CellDigestV1, u64, u64), CellDigestV1>,
    equivocated: &mut BTreeSet<(CellDigestV1, u64)>,
    observed: &mut BTreeMap<CellDigestV1, ObservedAdvertisement>,
    record: &CellProviderRecordV3,
) -> CellResultV1<bool> {
    let owner = record.statement.owner;
    let epoch = record.statement.lease_epoch;
    let identity = (owner, epoch, record.statement.sequence);
    let digest = record.digest();
    if let Some(prior) = statements.get(&identity) {
        if *prior != digest {
            equivocated.insert((owner, epoch));
            if observed
                .get(&owner)
                .is_some_and(|seen| seen.record.statement.lease_epoch == epoch)
            {
                observed.remove(&owner);
            }
        }
    } else {
        require(
            statements.len() < MAX_DISCOVERY_RECORDS,
            "discovery verified-statement budget",
        )?;
        statements.insert(identity, digest);
    }
    Ok(!equivocated.contains(&(owner, epoch)))
}

pub(super) fn retain_observed(
    observed: &mut BTreeMap<CellDigestV1, ObservedAdvertisement>,
    record: CellProviderRecordV3,
    mut expiry: Instant,
    mut expires_unix_seconds: u64,
    mut sources: u8,
) -> CellResultV1<bool> {
    let owner = record.statement.owner;
    if let Some(prior) = observed.get(&owner) {
        let ordering = (record.statement.lease_epoch, record.statement.sequence);
        let old = (
            prior.record.statement.lease_epoch,
            prior.record.statement.sequence,
        );
        if ordering < old {
            return Ok(false);
        }
        if ordering == old {
            require(
                record == prior.record,
                "discovery observed identity conflict",
            )?;
            expiry = expiry.min(prior.expires);
            expires_unix_seconds = expires_unix_seconds.min(prior.expires_unix_seconds);
            sources |= prior.sources;
        }
    } else {
        require(
            observed.len() < MAX_DISCOVERY_RECORDS,
            "discovery observed identity budget",
        )?;
    }
    observed.insert(
        owner,
        ObservedAdvertisement {
            record,
            expires: expiry,
            expires_unix_seconds,
            sources,
        },
    );
    Ok(true)
}
