use super::super::{
    network::{self, RequestContext, ResponseBudget},
    CellFetchReportV1, CellManifestV1, CellPeerLimitsV1, CellStoreV1,
};
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const MAX_REPLY_BYTES: usize = 1 + MAX_DISCOVERED_PROVIDERS * CELL_PROVIDER_RECORD_BYTES_V1;
const MAX_SERVER_CONNECTIONS: u64 = 64;

#[derive(Clone, Debug)]
pub struct CellDiscoveryOptionsV1 {
    pub request: CellDiscoveryRequestV1,
    pub bootstraps: Vec<SocketAddr>,
    pub addresses: CellDiscoveryAddressPolicyV1,
}
impl CellDiscoveryOptionsV1 {
    fn validate(&self) -> CellResultV1<()> {
        self.request.validate()?;
        self.addresses.validate()?;
        require(
            !self.bootstraps.is_empty()
                && self.bootstraps.len() <= MAX_DISCOVERY_BOOTSTRAPS
                && self.bootstraps.iter().collect::<BTreeSet<_>>().len() == self.bootstraps.len(),
            "discovery bootstrap count/duplicates",
        )?;
        for peer in &self.bootstraps {
            self.addresses.check(*peer)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellDiscoveryObservationV1 {
    pub connection_attempts: u64,
    pub received_response_bytes: u64,
    /// Each reserves at most one strict Ed25519 verification, including cheap
    /// invalid-record rejections. This is not a CPU-duration measurement.
    pub record_validation_attempts: usize,
    pub rejected_records: usize,
    pub capacity_rejections: usize,
    pub rejected_bootstraps: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellDiscoveryFetchReportV1 {
    pub discovery: CellDiscoveryObservationV1,
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
pub fn fetch_discovered_cell_to_file(
    store: &CellStoreV1,
    directory: &CellProviderDirectoryV1,
    options: &CellDiscoveryOptionsV1,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellDiscoveryFetchReportV1)> {
    options.validate()?;
    limits.validate()?;
    let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
    check_deadline(overall)?;
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.request_timeout,
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV1::default();
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
        CellDiscoveryFetchReportV1 {
            discovery: observation,
            discovered_providers: peers,
            manifest_initial_cache_hit,
            fetch,
        },
    ))
}

struct ObservedAdvertisement {
    record: CellProviderRecordV1,
    // Fixed when this exact record was actually received. Equal-record retries
    // cannot renew its monotonic lease; a higher sequence replaces the record.
    expires: Instant,
}

pub(super) fn discover(
    directory: &CellProviderDirectoryV1,
    options: &CellDiscoveryOptionsV1,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV1,
) -> CellResultV1<(Vec<SocketAddr>, Instant)> {
    // Scope is one pinned manifest. Identity is its advertising owner, not the
    // endpoint: the same owner can revoke an old address or shorten its TTL.
    // Both maps are bounded by the unchanged 64 actual validation slots; the
    // persistent per-manifest quota additionally permits only 16 identities.
    let mut observed: BTreeMap<CellDigestV1, ObservedAdvertisement> = BTreeMap::new();
    // Remember all eligible, strictly verified statements from this operation,
    // including historical sequences. A -> C(higher seq) -> B(conflicting old
    // seq) must not hide equivocation behind the persistent replay rejection.
    // This fixed per-operation history has at most the original 64 validation
    // slots; no eviction, clock reset, extra signature or network attempt.
    let mut verified_statements: BTreeMap<(CellDigestV1, u64), CellDigestV1> = BTreeMap::new();
    let mut equivocated = BTreeSet::new();
    // The local directory is replay protection only. These rows are discarded
    // and cannot manufacture a candidate when no bootstrap supplies one.
    directory.records(options.request, wall_now()?.as_secs(), transport.overall)?;
    for _round in 0..2 {
        for bootstrap in &options.bootstraps {
            // Do not stop at eight temporary endpoints: a later bootstrap in
            // this same bounded round may carry their newer signed high water.
            let response = exchange(
                *bootstrap,
                1,
                &options.request.encode(),
                MAX_REPLY_BYTES,
                transport,
                observation,
            );
            let wire = match response {
                Ok(value) => value,
                Err(_) => {
                    observation.rejected_bootstraps += 1;
                    continue;
                }
            };
            if wire.is_empty()
                || usize::from(wire[0]) > MAX_DISCOVERED_PROVIDERS
                || wire.len() != 1 + usize::from(wire[0]) * CELL_PROVIDER_RECORD_BYTES_V1
            {
                observation.rejected_bootstraps += 1;
                continue;
            }
            let received_at = Instant::now();
            let wall = wall_now()?;
            directory.records(options.request, wall.as_secs(), transport.overall)?;
            for raw in wire[1..].chunks_exact(CELL_PROVIDER_RECORD_BYTES_V1) {
                check_deadline(transport.overall)?;
                require(
                    observation.record_validation_attempts < MAX_DISCOVERY_RECORDS,
                    "discovery signature budget",
                )?;
                observation.record_validation_attempts += 1;
                let checked = (|| -> CellResultV1<_> {
                    let record = CellProviderRecordV1::decode(raw)?;
                    record.verify_at(options.request, wall.as_secs(), &options.addresses)?;
                    let remaining = Duration::from_secs(record.statement.expires_unix_seconds)
                        .checked_sub(wall)
                        .ok_or(CellErrorV1::Invalid("discovery expiry"))?;
                    Ok((record, received_at + remaining))
                })();
                let (record, mut expiry) = match checked {
                    Ok(value) => value,
                    Err(_) => {
                        observation.rejected_records += 1;
                        continue;
                    }
                };
                let owner = record.statement.owner;
                let identity = (owner, record.statement.sequence);
                let digest = record.digest();
                if let Some(prior) = verified_statements.get(&identity) {
                    if *prior != digest {
                        equivocated.insert(owner);
                        observed.remove(&owner);
                        observation.rejected_records += 1;
                        continue;
                    }
                } else {
                    require(
                        verified_statements.len() < MAX_DISCOVERY_RECORDS,
                        "discovery verified-statement budget",
                    )?;
                    verified_statements.insert(identity, digest);
                }
                match directory.accept_verified(
                    &record,
                    bootstrap.ip(),
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
                        equivocated.insert(owner);
                        observed.remove(&owner);
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
                if equivocated.contains(&owner) {
                    observation.rejected_records += 1;
                    continue;
                }
                check_deadline(expiry)?;
                if let Some(prior) = observed.get(&owner) {
                    if record.statement.sequence < prior.record.statement.sequence {
                        observation.rejected_records += 1;
                        continue;
                    }
                    if record.statement.sequence == prior.record.statement.sequence {
                        require(
                            record == prior.record,
                            "discovery observed identity conflict",
                        )?;
                        expiry = expiry.min(prior.expires);
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
                    },
                );
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
    let mut candidates: Vec<(SocketAddr, Instant)> = Vec::new();
    for (owner, seen) in observed {
        if current.get(&owner) != Some(&seen.record) || seen.record.live_at(wall.as_secs()).is_err()
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
        let endpoint = seen.record.statement.endpoint;
        if let Some((_, existing)) = candidates.iter_mut().find(|(peer, _)| *peer == endpoint) {
            // Distinct current owners may independently advertise one address.
            // One live current hint suffices: use their latest eligible expiry,
            // never a superseded record from any one identity.
            *existing = (*existing).max(expiry);
        } else if candidates.len() < MAX_DISCOVERED_PROVIDERS {
            candidates.push((endpoint, expiry));
        }
    }
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

/// Publish one pre-signed record to one explicitly scoped rendezvous. Its ACK
/// binds exact record bytes and follows durable high-water readback; it still
/// says nothing about the endpoint's bytes or service.
pub fn announce_cell_provider(
    record: &CellProviderRecordV1,
    bootstrap: SocketAddr,
    addresses: &CellDiscoveryAddressPolicyV1,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
) -> CellResultV1<CellDiscoveryObservationV1> {
    limits.validate()?;
    addresses.check(bootstrap)?;
    let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
    check_deadline(overall)?;
    record.verify_at(record.statement.request, wall_now()?.as_secs(), addresses)?;
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.request_timeout,
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV1 {
        record_validation_attempts: 1,
        ..Default::default()
    };
    let ack = exchange(
        bootstrap,
        2,
        &record.encode(),
        32,
        &transport,
        &mut observation,
    )?;
    require(ack == record.digest(), "discovery durable ACK identity")?;
    Ok(observation)
}

pub(super) fn exchange(
    peer: SocketAddr,
    kind: u8,
    body: &[u8],
    maximum: usize,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV1,
) -> CellResultV1<Vec<u8>> {
    check_deadline(transport.overall)?;
    require(
        observation.connection_attempts < MAX_DISCOVERY_CONNECTIONS,
        "discovery connection budget",
    )?;
    require(
        observation.received_response_bytes < MAX_DISCOVERY_RESPONSE_BYTES,
        "discovery response budget",
    )?;
    transport
        .requests_left
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
    observation.connection_attempts += 1;
    let deadline = transport.overall.min(Instant::now() + transport.timeout);
    let mut stream = TcpStream::connect_timeout(&peer, network::remaining(deadline)?)?;
    let mut query = b"CDQ1".to_vec();
    query.push(kind);
    query.extend((body.len() as u16).to_be_bytes());
    query.extend(body);
    network::write_deadline(&mut stream, &query, deadline)?;
    let mut header = [0; 9];
    read_response(
        &mut stream,
        &mut header,
        deadline,
        transport.responses,
        observation,
    )?;
    require(&header[..4] == b"CDS1", "discovery invalid reply")?;
    if header[4] == 2 {
        return Err(CellErrorV1::Invalid("discovery identity capacity"));
    }
    require(header[4] == 0, "discovery denied reply")?;
    let length = u32::from_be_bytes(
        header[5..]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("discovery reply length"))?,
    ) as usize;
    require(
        length > 0 && length <= maximum && length <= MAX_REPLY_BYTES,
        "discovery reply bound",
    )?;
    let mut wire = vec![0; length];
    read_response(
        &mut stream,
        &mut wire,
        deadline,
        transport.responses,
        observation,
    )?;
    Ok(wire)
}
fn read_response(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    parent: &ResponseBudget,
    observation: &mut CellDiscoveryObservationV1,
) -> CellResultV1<()> {
    while !bytes.is_empty() {
        let available = MAX_DISCOVERY_RESPONSE_BYTES - observation.received_response_bytes;
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
pub struct CellRendezvousLimitsV1 {
    pub request_timeout: Duration,
    pub lifetime: Duration,
    pub max_connections: u64,
}
impl CellRendezvousLimitsV1 {
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
pub struct CellRendezvousReportV1 {
    pub connections: u64,
    pub rejected_requests: u64,
    pub record_validation_attempts: usize,
}

/// Finite one-request-per-connection server. At most 64 connections and 64
/// record-validation slots per invocation; request body <=335B, reply <=2681B.
/// Directory transactions finish before writing a response. No reverse dial.
pub fn serve_cell_rendezvous(
    listener: &TcpListener,
    directory: &CellProviderDirectoryV1,
    addresses: &CellDiscoveryAddressPolicyV1,
    shutdown: &AtomicBool,
    limits: CellRendezvousLimitsV1,
) -> CellResultV1<CellRendezvousReportV1> {
    limits.validate()?;
    addresses.validate()?;
    listener.set_nonblocking(true)?;
    let overall = Instant::now() + limits.lifetime;
    let mut report = CellRendezvousReportV1::default();
    while !shutdown.load(Ordering::Relaxed)
        && report.connections < limits.max_connections
        && report.record_validation_attempts < MAX_DISCOVERY_RECORDS
        && Instant::now() < overall
    {
        match listener.accept() {
            Ok((mut stream, source)) => {
                report.connections += 1;
                let deadline = overall.min(Instant::now() + limits.request_timeout);
                let response = serve_one(
                    &mut stream,
                    source,
                    directory,
                    addresses,
                    deadline,
                    &mut report,
                );
                let (status, body) = match response {
                    Ok(body) => (0, body),
                    Err(CellErrorV1::Invalid("discovery identity capacity")) => {
                        report.rejected_requests += 1;
                        (2, Vec::new())
                    }
                    Err(_) => {
                        report.rejected_requests += 1;
                        (1, Vec::new())
                    }
                };
                let mut frame = b"CDS1".to_vec();
                frame.push(status);
                frame.extend((body.len() as u32).to_be_bytes());
                frame.extend(body);
                let _ = network::write_deadline(&mut stream, &frame, deadline);
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
    directory: &CellProviderDirectoryV1,
    addresses: &CellDiscoveryAddressPolicyV1,
    deadline: Instant,
    report: &mut CellRendezvousReportV1,
) -> CellResultV1<Vec<u8>> {
    let mut header = [0; 7];
    network::read_deadline(stream, &mut header, deadline, None)?;
    require(&header[..4] == b"CDQ1", "discovery request version")?;
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    require(
        (header[4] == 1 && length == 192)
            || (header[4] == 2 && length == CELL_PROVIDER_RECORD_BYTES_V1),
        "discovery request bound",
    )?;
    let mut body = vec![0; length];
    network::read_deadline(stream, &mut body, deadline, None)?;
    let now = wall_now()?.as_secs();
    if header[4] == 2 {
        require(
            report.record_validation_attempts < MAX_DISCOVERY_RECORDS,
            "discovery server signature budget",
        )?;
        report.record_validation_attempts += 1;
        let record = CellProviderRecordV1::decode(&body)?;
        record.verify_at(record.statement.request, now, addresses)?;
        directory.accept_verified(&record, source.ip(), now, deadline)?;
        Ok(record.digest().to_vec())
    } else {
        let request = CellDiscoveryRequestV1::decode(&body)?;
        let records = directory.records(request, now, deadline)?;
        let mut body = vec![0];
        for record in records {
            if body[0] as usize == MAX_DISCOVERED_PROVIDERS {
                break;
            }
            if record.statement.request != request || record.live_at(now).is_err() {
                continue;
            }
            require(
                report.record_validation_attempts < MAX_DISCOVERY_RECORDS,
                "discovery server signature budget",
            )?;
            report.record_validation_attempts += 1;
            record.verify_at(request, now, addresses)?;
            body.extend(record.encode());
            body[0] += 1;
        }
        check_deadline(deadline)?;
        Ok(body)
    }
}
