//! Query-bound, host-pinned PQ rendezvous in an explicit V3 wire namespace.
//! Provider hints and bootstrap replies have separate signatures. Neither grants
//! model authority, proves endpoint possession, or establishes independent owners.

use super::super::{
    canonical_endpoint, check_deadline, decode_endpoint, endpoint_bytes, selection, wall_now,
    CellDiscoveryAddressPolicyV1, MAX_DISCOVERED_PROVIDERS, MAX_DISCOVERY_BOOTSTRAPS,
    MAX_DISCOVERY_CONNECTIONS, MAX_DISCOVERY_RECORDS,
};
use super::{
    CellDiscoveryRequestV3, CellDiscoverySourcePinV3, CellDiscoverySourcePinsV3,
    CellDiscoverySourceV3, CellDiscoveryTimeV3, CellProviderDirectoryV3, CellProviderRecordV3,
    CellRendezvousLimitsV2, CELL_PROVIDER_RECORD_BYTES_V3, MAX_DISCOVERY_RESPONSE_BYTES_V2,
};
use crate::cell::{
    discovery::cell_discovery_context_digest,
    network::{self, RequestContext, ResponseBudget},
    pq::{CellPqKeyPinV2, CellPqKeyPinsV2},
    require, CellDigestV1, CellErrorV1, CellFetchReportV1, CellManifestV1, CellPeerLimitsV1,
    CellResultV1, CellStoreV1,
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
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

pub const CELL_DISCOVERY_AUTH_PROFILE_V3: &str = "cell-provider-discovery-auth-pq-v3";
const QUERY_BYTES: usize = 319;
const RESPONSE_HEADER_BYTES: usize = 28;
const MAX_REPLY_BYTES: usize = 1 + MAX_DISCOVERED_PROVIDERS * CELL_PROVIDER_RECORD_BYTES_V3;
const MAX_QUERY_BYTES: usize =
    QUERY_BYTES + CELL_PROVIDER_RECORD_BYTES_V3 + ML_DSA_65_SIGNATURE_BYTES;
const MAX_QUERY_LIFETIME_SECONDS: u64 = 300;
const FUTURE_SKEW_SECONDS: u64 = 5;
const REPLY_DOMAIN: &[u8] = b"TRNM/Cell/Discovery/Reply/ML-DSA-65/v3\0";
const ANNOUNCE_DOMAIN: &[u8] = b"TRNM/Cell/Discovery/Announce/ML-DSA-65/v3\0";

/// A locally configured bootstrap. The response cannot supply or replace this
/// key, generation, address or the corresponding independent authority roster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellBootstrapPinV3 {
    pub endpoint: SocketAddr,
    pub key_id: CellDigestV1,
    pub generation: u64,
}
impl CellBootstrapPinV3 {
    fn validate(self) -> CellResultV1<()> {
        require(
            canonical_endpoint(self.endpoint)
                && self.endpoint.port() != 0
                && self.key_id != [0; 32]
                && self.generation > 0,
            "authenticated discovery bootstrap pin",
        )
    }
    fn source(self) -> CellDiscoverySourceV3 {
        CellDiscoverySourceV3 {
            authenticated_key_id: self.key_id,
            generation: self.generation,
            ip: self.endpoint.ip(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CellDiscoveryOptionsV3 {
    pub request: CellDiscoveryRequestV3,
    pub bootstraps: Vec<CellBootstrapPinV3>,
    pub bootstrap_keys: CellPqKeyPinsV2,
    pub addresses: CellDiscoveryAddressPolicyV1,
}
impl CellDiscoveryOptionsV3 {
    /// Derive the persistent source roster from the same owner-supplied pins.
    /// Reopening a directory with a different roster is an explicit refusal.
    pub fn source_pins(&self) -> CellResultV1<CellDiscoverySourcePinsV3> {
        self.validate_shape()?;
        CellDiscoverySourcePinsV3::new(
            self.bootstraps
                .iter()
                .map(|pin| CellDiscoverySourcePinV3 {
                    authenticated_key_id: pin.key_id,
                    generation: pin.generation,
                    ip: pin.endpoint.ip(),
                })
                .collect(),
        )
    }
    fn validate_shape(&self) -> CellResultV1<()> {
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
                    .map(|pin| (pin.key_id, pin.generation))
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.bootstraps.len(),
            "authenticated discovery bootstrap count/duplicates",
        )?;
        for pin in &self.bootstraps {
            pin.validate()?;
            self.addresses.check(pin.endpoint)?;
            let authority = self
                .bootstrap_keys
                .pins()
                .find(|authority| authority.key_id == pin.key_id)
                .ok_or(CellErrorV1::Invalid(
                    "authenticated discovery unknown bootstrap",
                ))?;
            require(
                authority.generation == pin.generation,
                "authenticated discovery bootstrap generation",
            )?;
        }
        Ok(())
    }
    fn validate_at(&self, now: u64) -> CellResultV1<()> {
        self.validate_shape()?;
        self.request.validate_at(now)
    }
}

fn authority_for(
    keys: &CellPqKeyPinsV2,
    bootstrap: CellBootstrapPinV3,
) -> CellResultV1<&CellPqKeyPinV2> {
    let key = keys
        .pins()
        .find(|key| key.key_id == bootstrap.key_id && key.generation == bootstrap.generation)
        .ok_or(CellErrorV1::Invalid(
            "authenticated discovery bootstrap authority",
        ))?;
    Ok(key)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellDiscoveryObservationV3 {
    pub connection_attempts: u64,
    pub received_response_bytes: u64,
    pub record_validation_attempts: usize,
    pub bootstrap_validation_attempts: usize,
    /// Pure signing verifies its own result. Reserve that verification here too.
    pub announcement_signature_attempts: usize,
    pub rejected_records: usize,
    pub capacity_rejections: usize,
    pub rejected_bootstraps: usize,
    /// A subset of source refusals rejected by local authority policy before
    /// dialing. These never count as actual connection attempts or bytes.
    pub ineligible_bootstraps: usize,
}
impl CellDiscoveryObservationV3 {
    /// Reserved verification attempts, including signing calls' self-checks.
    /// Failed attempts retain their slots; this is not measured CPU time.
    pub fn verification_attempts(&self) -> usize {
        self.record_validation_attempts
            .saturating_add(self.bootstrap_validation_attempts)
            .saturating_add(self.announcement_signature_attempts)
    }
    /// Signing computations reserved in addition to the verification slots.
    /// Each corresponding self-check is already in `verification_attempts`.
    pub fn signing_attempts(&self) -> usize {
        self.announcement_signature_attempts
    }
    /// Compatibility name for the original 64-verification-slot accounting.
    pub fn signature_attempts(&self) -> usize {
        self.verification_attempts()
    }
    fn reserve(&mut self, kind: SignatureKind) -> CellResultV1<()> {
        require(
            self.signature_attempts() < MAX_DISCOVERY_RECORDS,
            "authenticated discovery combined signature budget",
        )?;
        match kind {
            SignatureKind::Record => self.record_validation_attempts += 1,
            SignatureKind::Bootstrap => self.bootstrap_validation_attempts += 1,
            SignatureKind::Announcement => self.announcement_signature_attempts += 1,
        }
        Ok(())
    }
}
enum SignatureKind {
    Record,
    Bootstrap,
    Announcement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellDiscoveryFetchReportV3 {
    pub discovery: CellDiscoveryObservationV3,
    pub discovered_providers: Vec<SocketAddr>,
    pub manifest_initial_cache_hit: bool,
    /// Includes discovery response bytes/connections exactly once.
    pub fetch: CellFetchReportV1,
}

/// A failed operation's actual, original shared Cell-session denominator.
/// Discovery is a breakdown of the totals and must not be added to them again.
#[derive(Debug)]
pub struct CellDiscoveryFailureV3 {
    pub cause: CellErrorV1,
    pub discovery: CellDiscoveryObservationV3,
    pub total_connection_attempts: u64,
    /// None only when the shared response-accounting mutex is unavailable.
    pub total_received_response_bytes: Option<u64>,
}
impl std::fmt::Display for CellDiscoveryFailureV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}
impl std::error::Error for CellDiscoveryFailureV3 {}

fn observed_failure(
    cause: CellErrorV1,
    discovery: CellDiscoveryObservationV3,
    maximum_connections: u64,
    requests_left: &AtomicU64,
    responses: &ResponseBudget,
) -> Box<CellDiscoveryFailureV3> {
    Box::new(CellDiscoveryFailureV3 {
        cause,
        discovery,
        total_connection_attempts: maximum_connections - requests_left.load(Ordering::Relaxed),
        total_received_response_bytes: responses.received().ok(),
    })
}

/// Authenticate each queried source, then verify all actual Cell bytes using
/// the original operation's network reservation and absolute deadline.
pub fn fetch_authenticated_discovered_cell_to_file_pq(
    store: &CellStoreV1,
    directory: &CellProviderDirectoryV3,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellDiscoveryFetchReportV3)> {
    fetch_authenticated_discovered_cell_to_file_pq_observed(
        store,
        directory,
        options,
        limits,
        original_deadline,
        output,
    )
    .map_err(|failure| failure.cause)
}

/// The same wire, authority checks and original budgets as the compatible
/// entry point, with actual discovery/manifest/chunk costs retained on failure.
pub fn fetch_authenticated_discovered_cell_to_file_pq_observed(
    store: &CellStoreV1,
    directory: &CellProviderDirectoryV3,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    output: &Path,
) -> Result<(CellManifestV1, CellDiscoveryFetchReportV3), Box<CellDiscoveryFailureV3>> {
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let mut observation = CellDiscoveryObservationV3::default();
    let result = (|| -> CellResultV1<_> {
        limits.validate()?;
        let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(overall)?;
        options.validate_at(wall_now()?.as_secs())?;
        require(
            options.source_pins()?.digest() == directory.source_pins().digest(),
            "authenticated discovery source roster",
        )?;
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
        let (manifest, manifest_rejected, manifest_initial_cache_hit) =
            network::fetch_manifest_observed(
                store,
                options.request.base.manifest,
                &peers,
                limits,
                &transport,
            )?;
        require(
            cell_discovery_context_digest(manifest.context())? == options.request.base.cell_context,
            "authenticated discovered cell context",
        )?;
        // Original authorization time, epoch and network deadlines remain live
        // at materialization; no cached advertisement is a fallback source.
        options.validate_at(wall_now()?.as_secs())?;
        check_deadline(transport.overall)?;
        let (manifest, mut fetch) = network::fetch_cell_in_session(
            store,
            options.request.base.manifest,
            &peers,
            limits,
            &transport,
            Some(output),
        )?;
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
        observed_failure(
            cause,
            observation,
            limits.max_connections,
            &requests_left,
            &responses,
        )
    })
}

struct ObservedAdvertisement {
    record: CellProviderRecordV3,
    expires: Instant,
    sources: u8,
}

fn discover(
    directory: &CellProviderDirectoryV3,
    options: &CellDiscoveryOptionsV3,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<(Vec<SocketAddr>, Instant)> {
    let mut observed: BTreeMap<CellDigestV1, ObservedAdvertisement> = BTreeMap::new();
    let mut verified_statements: BTreeMap<(CellDigestV1, u64), CellDigestV1> = BTreeMap::new();
    // This operation's highest authenticated sequence is independent of whether
    // its record is still live or can enter the bounded durable directory. Keep
    // it across both rounds using the same at-most-64 verification observations.
    // It is a local selection veto, never a durable high-water receipt or ACK.
    let mut highest_verified: BTreeMap<CellDigestV1, u64> = BTreeMap::new();
    let mut equivocated = BTreeSet::new();
    directory.records(options.request, wall_now()?.as_secs(), transport.overall)?;
    for _round in 0..2 {
        // At most four bounded bodies. Authenticate all source replies before
        // fair admission; receiving later sources never refreshes earlier TTLs.
        let mut replies = Vec::with_capacity(MAX_DISCOVERY_BOOTSTRAPS);
        for (source, bootstrap) in options.bootstraps.iter().enumerate() {
            if authority_for(&options.bootstrap_keys, *bootstrap)
                .and_then(|pin| pin.live_at(wall_now()?.as_secs()))
                .is_err()
            {
                observation.ineligible_bootstraps += 1;
                observation.rejected_bootstraps += 1;
                continue;
            }
            let query = Query::fresh(options.request, *bootstrap, transport, Vec::new())?;
            let reply = match exchange(&query, &options.bootstrap_keys, transport, observation) {
                Ok(reply) => reply,
                Err(_) => {
                    observation.rejected_bootstraps += 1;
                    continue;
                }
            };
            if reply.body.is_empty()
                || usize::from(reply.body[0]) > MAX_DISCOVERED_PROVIDERS
                || reply.body.len()
                    != 1 + usize::from(reply.body[0]) * CELL_PROVIDER_RECORD_BYTES_V3
            {
                observation.rejected_bootstraps += 1;
                continue;
            }
            directory.records(options.request, wall_now()?.as_secs(), transport.overall)?;
            replies.push((source, *bootstrap, reply));
        }
        for slot in 0..MAX_DISCOVERED_PROVIDERS {
            for (source, bootstrap, reply) in &replies {
                let start = 1 + slot * CELL_PROVIDER_RECORD_BYTES_V3;
                let Some(raw) = reply.body.get(start..start + CELL_PROVIDER_RECORD_BYTES_V3) else {
                    continue;
                };
                check_deadline(transport.overall)?;
                observation.reserve(SignatureKind::Record)?;
                let receipt = match CellProviderRecordV3::decode(raw).and_then(|record| {
                    record.verify_at(
                        options.request,
                        reply.received_time,
                        &options.addresses,
                        directory.keys(),
                    )
                }) {
                    Ok(receipt) => receipt,
                    Err(_) => {
                        observation.rejected_records += 1;
                        continue;
                    }
                };
                let record = receipt.record();
                let statement = record.statement();
                let owner = statement.owner;
                let identity = (owner, statement.sequence);
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
                        "authenticated discovery statement budget",
                    )?;
                    verified_statements.insert(identity, digest);
                }
                // Record historical same-sequence conflicts above BEFORE this
                // lower-sequence filter. Expiry, withdrawal, a full source quota
                // or a later reply cannot revive an older signed endpoint.
                match highest_verified.get(&owner).copied() {
                    Some(highest) if statement.sequence < highest => {
                        observation.rejected_records += 1;
                        continue;
                    }
                    Some(highest) if statement.sequence > highest => {
                        highest_verified.insert(owner, statement.sequence);
                        observed.remove(&owner);
                    }
                    Some(_) => (),
                    None => {
                        require(
                            highest_verified.len() < MAX_DISCOVERY_RECORDS,
                            "authenticated discovery highest-sequence budget",
                        )?;
                        highest_verified.insert(owner, statement.sequence);
                    }
                }
                let Some(remaining) =
                    Duration::from_secs(receipt.valid_until()).checked_sub(reply.received_wall)
                else {
                    observation.rejected_records += 1;
                    continue;
                };
                let mut expiry = (reply.received_at + remaining)
                    .min(reply.expires)
                    .min(receipt.monotonic_expiry());
                let wall = wall_now()?;
                if record.live_at(wall.as_secs()).is_err()
                    || wall.as_secs() >= receipt.valid_until()
                    || Instant::now() >= expiry
                {
                    observation.rejected_records += 1;
                    continue;
                }
                match directory.accept_verified(
                    &receipt,
                    bootstrap.source(),
                    wall.as_secs(),
                    transport.overall.min(expiry),
                ) {
                    Ok(()) => (),
                    Err(CellErrorV1::Invalid(
                        "discovery identity capacity"
                        | "discovery active capacity"
                        | "discovery replay capacity",
                    )) => {
                        observation.capacity_rejections += 1;
                        observation.rejected_records += 1;
                        continue;
                    }
                    Err(CellErrorV1::Invalid("discovery sequence equivocation")) => {
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
                let mut sources = 1_u8 << *source;
                if let Some(prior) = observed.get(&owner) {
                    if statement.sequence < prior.record.statement().sequence {
                        observation.rejected_records += 1;
                        continue;
                    }
                    if statement.sequence == prior.record.statement().sequence {
                        require(
                            *record == prior.record,
                            "authenticated discovery observed conflict",
                        )?;
                        expiry = expiry.min(prior.expires);
                        sources |= prior.sources;
                    }
                } else {
                    require(
                        observed.len() < MAX_DISCOVERY_RECORDS,
                        "authenticated discovery observed budget",
                    )?;
                }
                observed.insert(
                    owner,
                    ObservedAdvertisement {
                        record: record.clone(),
                        expires: expiry,
                        sources,
                    },
                );
            }
        }
        if !observed.is_empty() {
            break;
        }
    }
    let sampled_at = Instant::now();
    let wall = wall_now()?;
    let current: BTreeMap<_, _> = directory
        .records(options.request, wall.as_secs(), transport.overall)?
        .into_iter()
        .map(|record| (record.statement().owner, record))
        .collect();
    let mut candidates = Vec::new();
    for (owner, seen) in observed {
        let statement = seen.record.statement();
        if highest_verified.get(&owner) != Some(&statement.sequence)
            || current.get(&owner) != Some(&seen.record)
            || equivocated.contains(&owner)
            || statement.withdrawn
            || seen.record.live_at(wall.as_secs()).is_err()
        {
            continue;
        }
        let Some(remaining) = Duration::from_secs(statement.expires_unix_seconds).checked_sub(wall)
        else {
            continue;
        };
        let expiry = (sampled_at + remaining)
            .min(seen.expires)
            .min(transport.overall);
        if Instant::now() < expiry {
            candidates.push(selection::Candidate {
                owner,
                endpoint: statement.endpoint,
                sources: seen.sources,
                expires: expiry,
            });
        }
    }
    let candidates = selection::select(candidates)?;
    if candidates.is_empty() && observation.capacity_rejections > 0 {
        return Err(CellErrorV1::Invalid("discovery identity capacity"));
    }
    require(
        !candidates.is_empty(),
        "authenticated discovery has no admissible provider",
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

/// Publish an epoch-bound provider statement with a second signature binding
/// this complete query to its intended bootstrap. A copied provider record by
/// itself is insufficient to authenticate the incoming publication source.
pub fn announce_authenticated_cell_provider_pq(
    record: &CellProviderRecordV3,
    signing_key: &PqNativeSigningKey,
    provider_keys: &CellPqKeyPinsV2,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
) -> CellResultV1<CellDiscoveryObservationV3> {
    announce_authenticated_cell_provider_pq_observed(
        record,
        signing_key,
        provider_keys,
        options,
        limits,
        original_deadline,
    )
    .map_err(|failure| failure.cause)
}

/// Publish with the same explicit V3 possession proof, preserving consumed
/// verification slots and actual shared-session bytes/connections on refusal.
pub fn announce_authenticated_cell_provider_pq_observed(
    record: &CellProviderRecordV3,
    signing_key: &PqNativeSigningKey,
    provider_keys: &CellPqKeyPinsV2,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
) -> Result<CellDiscoveryObservationV3, Box<CellDiscoveryFailureV3>> {
    announce_observed_with_time(
        record,
        signing_key,
        provider_keys,
        options,
        limits,
        original_deadline,
        CellDiscoveryTimeV3::sample,
    )
}

// The public entry point always captures its own sealed clock sample. This
// private seam permits a deterministic stale-monotonic observation control
// without changing the host clock, query wire or any public caller capability.
fn announce_observed_with_time(
    record: &CellProviderRecordV3,
    signing_key: &PqNativeSigningKey,
    provider_keys: &CellPqKeyPinsV2,
    options: &CellDiscoveryOptionsV3,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    sample: impl FnOnce() -> CellResultV1<CellDiscoveryTimeV3>,
) -> Result<CellDiscoveryObservationV3, Box<CellDiscoveryFailureV3>> {
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let mut observation = CellDiscoveryObservationV3::default();
    let result = (|| -> CellResultV1<_> {
        limits.validate()?;
        let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(overall)?;
        let sampled = sample()?;
        let now = sampled.unix_seconds();
        options.validate_at(now)?;
        require(
            options.bootstraps.len() == 1,
            "authenticated announcement bootstrap count",
        )?;
        authority_for(&options.bootstrap_keys, options.bootstraps[0])?.live_at(now)?;
        require(
            record.statement().owner == signing_key.public_key_id(),
            "authenticated announcement signing owner",
        )?;
        observation.reserve(SignatureKind::Record)?;
        let receipt =
            record.verify_at(options.request, sampled, &options.addresses, provider_keys)?;
        let transport = RequestContext {
            cancelled: None,
            timeout: limits.request_timeout,
            // Wall-clock validity cannot renew this earlier verified receipt's
            // original lease while signing, dialing, waiting or accepting ACK.
            overall: overall.min(receipt.monotonic_expiry()),
            requests_left: &requests_left,
            responses: &responses,
        };
        check_deadline(transport.overall)?;
        let mut query = Query::fresh(
            options.request,
            options.bootstraps[0],
            &transport,
            record.encode(),
        )?;
        query.expires_at = query.expires_at.min(receipt.valid_until());
        query.validate_at(wall_now()?.as_secs())?;
        observation.reserve(SignatureKind::Announcement)?;
        query.signature = signing_key
            .sign_exact_message(&query.announcement_message())
            .map_err(|_| CellErrorV1::Invalid("authenticated announcement signing"))?;
        check_deadline(transport.overall)?;
        require(
            wall_now()?.as_secs() < receipt.valid_until(),
            "authenticated announcement authority expired",
        )?;
        let reply = exchange(
            &query,
            &options.bootstrap_keys,
            &transport,
            &mut observation,
        )?;
        require(
            reply.body == record.digest(),
            "authenticated discovery durable ACK identity",
        )?;
        check_deadline(transport.overall)?;
        Ok(observation.clone())
    })();
    result.map_err(|cause| {
        observed_failure(
            cause,
            observation,
            limits.max_connections,
            &requests_left,
            &responses,
        )
    })
}

#[derive(Clone)]
struct Query {
    nonce: [u8; 32],
    request: CellDiscoveryRequestV3,
    bootstrap: CellBootstrapPinV3,
    issued_at: u64,
    expires_at: u64,
    record: Vec<u8>,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl Query {
    fn fresh(
        request: CellDiscoveryRequestV3,
        bootstrap: CellBootstrapPinV3,
        transport: &RequestContext<'_>,
        record: Vec<u8>,
    ) -> CellResultV1<Self> {
        Self::fresh_with_nonce(request, bootstrap, transport, record, |nonce| {
            getrandom::getrandom(nonce)
                .map_err(|_| CellErrorV1::Invalid("authenticated discovery nonce source"))
        })
    }
    fn fresh_with_nonce(
        request: CellDiscoveryRequestV3,
        bootstrap: CellBootstrapPinV3,
        transport: &RequestContext<'_>,
        record: Vec<u8>,
        random: impl FnOnce(&mut [u8; 32]) -> CellResultV1<()>,
    ) -> CellResultV1<Self> {
        check_deadline(transport.overall)?;
        let mut nonce = [0; 32];
        random(&mut nonce)?;
        check_deadline(transport.overall)?;
        let now = wall_now()?.as_secs();
        request.validate_at(now)?;
        let timeout = network::remaining(transport.overall)?;
        let lifetime = timeout
            .as_secs()
            .saturating_add(1)
            .min(MAX_QUERY_LIFETIME_SECONDS);
        let expires_at = now
            .checked_add(lifetime)
            .ok_or(CellErrorV1::Invalid(
                "authenticated discovery query time overflow",
            ))?
            .min(request.epoch_bounds()?.1);
        let query = Self {
            nonce,
            request,
            bootstrap,
            issued_at: now,
            expires_at,
            record,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        query.validate_at(now)?;
        Ok(query)
    }
    fn kind(&self) -> u8 {
        if self.record.is_empty() {
            1
        } else {
            2
        }
    }
    fn unsigned(&self) -> Vec<u8> {
        let payload_len = if self.record.is_empty() {
            0
        } else {
            self.record.len() + ML_DSA_65_SIGNATURE_BYTES
        };
        let mut wire = vec![b'C', b'D', b'Q', b'3', 3, 0x65, self.kind(), 0];
        wire.extend((payload_len as u32).to_be_bytes());
        wire.extend(self.nonce);
        wire.extend(self.request.encode());
        wire.extend(endpoint_bytes(self.bootstrap.endpoint));
        wire.extend(self.bootstrap.key_id);
        wire.extend(self.bootstrap.generation.to_be_bytes());
        wire.extend(self.issued_at.to_be_bytes());
        wire.extend(self.expires_at.to_be_bytes());
        wire.extend(&self.record);
        wire
    }
    fn encode(&self) -> Vec<u8> {
        let mut wire = self.unsigned();
        if !self.record.is_empty() {
            wire.extend(self.signature);
        }
        wire
    }
    fn announcement_message(&self) -> Vec<u8> {
        let mut message = ANNOUNCE_DOMAIN.to_vec();
        message.extend(self.unsigned());
        message
    }
    fn validate_shape(&self) -> CellResultV1<()> {
        self.bootstrap.validate()?;
        require(self.nonce != [0; 32], "authenticated discovery zero nonce")?;
        require(
            self.record.is_empty() || self.record.len() == CELL_PROVIDER_RECORD_BYTES_V3,
            "authenticated discovery query record size",
        )?;
        require(
            self.expires_at
                .checked_sub(self.issued_at)
                .is_some_and(|ttl| (1..=MAX_QUERY_LIFETIME_SECONDS).contains(&ttl))
                && self.expires_at <= self.request.epoch_bounds()?.1,
            "authenticated discovery query TTL",
        )
    }
    fn validate_at(&self, now: u64) -> CellResultV1<()> {
        self.validate_shape()?;
        self.request.validate_at(now)?;
        require(
            self.issued_at <= now.saturating_add(FUTURE_SKEW_SECONDS) && now < self.expires_at,
            "authenticated discovery expired/future query",
        )
    }
    fn decode(wire: &[u8]) -> CellResultV1<Self> {
        require(
            wire.len() >= QUERY_BYTES && wire.len() <= MAX_QUERY_BYTES,
            "authenticated discovery query size",
        )?;
        require(
            wire[..6] == [b'C', b'D', b'Q', b'3', 3, 0x65]
                && (wire[6] == 1 || wire[6] == 2)
                && wire[7] == 0,
            "authenticated discovery query version/algorithm",
        )?;
        let payload = u32::from_be_bytes(
            wire[8..12]
                .try_into()
                .map_err(|_| CellErrorV1::Invalid("authenticated discovery query length"))?,
        ) as usize;
        require(
            ((wire[6] == 1 && payload == 0)
                || (wire[6] == 2
                    && payload == CELL_PROVIDER_RECORD_BYTES_V3 + ML_DSA_65_SIGNATURE_BYTES))
                && wire.len() == QUERY_BYTES + payload,
            "authenticated discovery query payload bound",
        )?;
        let mut input = Input(&wire[12..]);
        let nonce = input.take()?;
        let request = CellDiscoveryRequestV3::decode(&input.take::<200>()?)?;
        let bootstrap = CellBootstrapPinV3 {
            endpoint: decode_endpoint(input.take()?)?,
            key_id: input.take()?,
            generation: u64::from_be_bytes(input.take()?),
        };
        let issued_at = u64::from_be_bytes(input.take()?);
        let expires_at = u64::from_be_bytes(input.take()?);
        let (record, signature) = if wire[6] == 2 {
            (
                input.take::<CELL_PROVIDER_RECORD_BYTES_V3>()?.to_vec(),
                input.take()?,
            )
        } else {
            (Vec::new(), [0; ML_DSA_65_SIGNATURE_BYTES])
        };
        let query = Self {
            nonce,
            request,
            bootstrap,
            issued_at,
            expires_at,
            record,
            signature,
        };
        query.validate_shape()?;
        require(
            query.encode() == wire,
            "authenticated discovery canonical query",
        )?;
        Ok(query)
    }
}

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        require(self.0.len() >= N, "authenticated discovery truncated field")?;
        let result = self.0[..N]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery field"))?;
        self.0 = &self.0[N..];
        Ok(result)
    }
}

struct Reply {
    body: Vec<u8>,
    received_at: Instant,
    received_wall: Duration,
    received_time: CellDiscoveryTimeV3,
    expires: Instant,
}

fn response_unsigned(
    query: &Query,
    status: u8,
    body: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> CellResultV1<Vec<u8>> {
    require(
        status <= 2
            && ((status != 0 && body.is_empty())
                || (status == 0
                    && query.kind() == 1
                    && (1..=MAX_REPLY_BYTES).contains(&body.len()))
                || (status == 0 && query.kind() == 2 && body.len() == 32)),
        "authenticated discovery response body/status",
    )?;
    require(
        issued_at < expires_at
            && expires_at - issued_at <= MAX_QUERY_LIFETIME_SECONDS
            && expires_at <= query.expires_at,
        "authenticated discovery response TTL",
    )?;
    let mut wire = vec![b'C', b'D', b'S', b'3', 3, 0x65, status, 0];
    wire.extend(issued_at.to_be_bytes());
    wire.extend(expires_at.to_be_bytes());
    wire.extend((body.len() as u32).to_be_bytes());
    wire.extend(body);
    Ok(wire)
}

fn response_message(query: &Query, unsigned: &[u8]) -> Vec<u8> {
    let mut message = REPLY_DOMAIN.to_vec();
    message.extend(query.encode());
    message.extend(unsigned);
    message
}

fn signed_response(
    query: &Query,
    status: u8,
    body: &[u8],
    issued_at: u64,
    expires_at: u64,
    key: &PqNativeSigningKey,
) -> CellResultV1<Vec<u8>> {
    require(
        key.public_key_id() == query.bootstrap.key_id,
        "authenticated discovery reply signer",
    )?;
    let mut wire = response_unsigned(query, status, body, issued_at, expires_at)?;
    let signature = key
        .sign_exact_message(&response_message(query, &wire))
        .map_err(|_| CellErrorV1::Invalid("authenticated discovery response signing"))?;
    wire.extend(signature);
    Ok(wire)
}

fn exchange(
    query: &Query,
    keys: &CellPqKeyPinsV2,
    transport: &RequestContext<'_>,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<Reply> {
    check_deadline(transport.overall)?;
    let now = wall_now()?.as_secs();
    query.validate_at(now)?;
    authority_for(keys, query.bootstrap)?.live_at(now)?;
    require(
        observation.connection_attempts < MAX_DISCOVERY_CONNECTIONS,
        "discovery connection budget",
    )?;
    require(
        observation.received_response_bytes < MAX_DISCOVERY_RESPONSE_BYTES_V2,
        "discovery response budget",
    )?;
    transport.responses.require_remaining()?;
    require(
        transport.requests_left.load(Ordering::Relaxed) > 0,
        "connection budget exhausted",
    )?;
    // Reserve before dialing: even a cheap malformed or unsigned response
    // cannot create an extra signature allowance or a free follow-up attempt.
    observation.reserve(SignatureKind::Bootstrap)?;
    transport
        .requests_left
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .map_err(|_| CellErrorV1::Invalid("connection budget exhausted"))?;
    observation.connection_attempts += 1;
    let deadline = transport.overall.min(Instant::now() + transport.timeout);
    let mut stream =
        TcpStream::connect_timeout(&query.bootstrap.endpoint, network::remaining(deadline)?)?;
    network::write_deadline(&mut stream, &query.encode(), deadline)?;
    let mut header = [0; RESPONSE_HEADER_BYTES];
    read_response(
        &mut stream,
        &mut header,
        deadline,
        transport.responses,
        observation,
    )?;
    require(
        header[..6] == [b'C', b'D', b'S', b'3', 3, 0x65] && header[6] <= 2 && header[7] == 0,
        "authenticated discovery response version/algorithm",
    )?;
    let length = u32::from_be_bytes(
        header[24..28]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery response length"))?,
    ) as usize;
    require(
        length <= MAX_REPLY_BYTES,
        "authenticated discovery reply bound",
    )?;
    let mut body_and_signature = vec![0; length + ML_DSA_65_SIGNATURE_BYTES];
    read_response(
        &mut stream,
        &mut body_and_signature,
        deadline,
        transport.responses,
        observation,
    )?;
    let received_time = CellDiscoveryTimeV3::sample()?;
    verify_response(
        query,
        keys,
        ReceivedResponse {
            header: &header,
            body_and_signature: &body_and_signature,
            time: received_time,
        },
        deadline,
        transport.overall,
        observation,
    )
}

struct ReceivedResponse<'a> {
    header: &'a [u8; RESPONSE_HEADER_BYTES],
    body_and_signature: &'a [u8],
    time: CellDiscoveryTimeV3,
}

fn verify_response(
    query: &Query,
    keys: &CellPqKeyPinsV2,
    received: ReceivedResponse<'_>,
    deadline: Instant,
    overall: Instant,
    observation: &mut CellDiscoveryObservationV3,
) -> CellResultV1<Reply> {
    let ReceivedResponse {
        header,
        body_and_signature,
        time: received_time,
    } = received;
    let received_at = received_time.monotonic();
    let received_wall = received_time.unix_time();
    check_deadline(deadline)?;
    query.validate_at(received_wall.as_secs())?;
    let status = header[6];
    let issued_at = u64::from_be_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery response time"))?,
    );
    let expires_at = u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery response time"))?,
    );
    let length = u32::from_be_bytes(
        header[24..28]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery response length"))?,
    ) as usize;
    require(
        length <= MAX_REPLY_BYTES && body_and_signature.len() == length + ML_DSA_65_SIGNATURE_BYTES,
        "authenticated discovery signature length",
    )?;
    let (body, signature) = body_and_signature.split_at(length);
    let unsigned = response_unsigned(query, status, body, issued_at, expires_at)?;
    require(
        unsigned[..RESPONSE_HEADER_BYTES] == header[..],
        "authenticated discovery canonical response",
    )?;
    require(
        issued_at <= received_wall.as_secs().saturating_add(FUTURE_SKEW_SECONDS)
            && issued_at.saturating_add(FUTURE_SKEW_SECONDS) >= query.issued_at
            && received_wall.as_secs() < expires_at,
        "authenticated discovery expired/future response",
    )?;
    let authority_expiry = keys.verify(
        query.bootstrap.key_id,
        query.bootstrap.generation,
        received_wall.as_secs(),
        &response_message(query, &unsigned),
        signature,
    )?;
    let valid_until = expires_at.min(authority_expiry);
    let remaining = Duration::from_secs(valid_until)
        .checked_sub(received_wall)
        .ok_or(CellErrorV1::Invalid(
            "authenticated discovery response expiry",
        ))?;
    let expires = (received_at + remaining).min(overall);
    check_deadline(deadline)?;
    check_deadline(expires)?;
    let current_wall = wall_now()?.as_secs();
    require(
        current_wall >= received_wall.as_secs() && current_wall < valid_until,
        "authenticated discovery current response lifetime",
    )?;
    if status == 2 {
        observation.capacity_rejections += 1;
        return Err(CellErrorV1::Invalid("discovery identity capacity"));
    }
    require(status == 0, "authenticated discovery denied reply")?;
    Ok(Reply {
        body: body.to_vec(),
        received_at,
        received_wall,
        received_time,
        expires,
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
        let available =
            MAX_DISCOVERY_RESPONSE_BYTES_V2.saturating_sub(observation.received_response_bytes);
        require(available > 0, "discovery response byte budget exhausted")?;
        let count = bytes.len().min(available as usize);
        match parent.read(stream, &mut bytes[..count], deadline) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "authenticated discovery truncated reply",
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

/// The bootstrap's locally owned signing key and current host-supplied pin.
/// This API never provisions keys or loads authority from incoming traffic.
pub struct CellRendezvousIdentityV3<'a> {
    pub bootstrap: CellBootstrapPinV3,
    pub key: &'a PqNativeSigningKey,
    pub authority: &'a CellPqKeyPinV2,
}
impl CellRendezvousIdentityV3<'_> {
    fn validate_at(&self, now: u64) -> CellResultV1<()> {
        self.bootstrap.validate()?;
        self.authority.validate()?;
        self.authority.live_at(now)?;
        require(
            self.bootstrap.key_id == self.authority.key_id
                && self.bootstrap.generation == self.authority.generation
                && self.key.public_key_id() == self.authority.key_id
                && self.key.public_spki() == &self.authority.spki,
            "authenticated rendezvous signing authority",
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellRendezvousReportV3 {
    pub connections: u64,
    pub rejected_requests: u64,
    pub rejected_records: usize,
    pub record_validation_attempts: usize,
    pub announcement_validation_attempts: usize,
    /// Each signing call verifies its result inside the native signer.
    pub reply_signature_attempts: usize,
}
impl CellRendezvousReportV3 {
    /// Original 64-slot verification allowance, including reply self-checks.
    pub fn verification_attempts(&self) -> usize {
        self.record_validation_attempts
            .saturating_add(self.announcement_validation_attempts)
            .saturating_add(self.reply_signature_attempts)
    }
    /// Additional reply-signing computations; their self-checks are already
    /// included in `verification_attempts`. Neither count measures CPU time.
    pub fn signing_attempts(&self) -> usize {
        self.reply_signature_attempts
    }
    /// Compatibility name; preserves the existing V3 verification-slot unit.
    pub fn signature_attempts(&self) -> usize {
        self.verification_attempts()
    }
    fn reserve_validation(&mut self, announcement: bool) -> CellResultV1<()> {
        // Keep the last slot for the response's own verification. A full record
        // batch cannot consume all validation slots and then sign for free.
        require(
            self.signature_attempts().saturating_add(1) < MAX_DISCOVERY_RECORDS,
            "authenticated rendezvous combined signature budget",
        )?;
        if announcement {
            self.announcement_validation_attempts += 1;
        } else {
            self.record_validation_attempts += 1;
        }
        Ok(())
    }
    fn reserve_reply(&mut self) -> CellResultV1<()> {
        require(
            self.signature_attempts() < MAX_DISCOVERY_RECORDS,
            "authenticated rendezvous combined signature budget",
        )?;
        self.reply_signature_attempts += 1;
        Ok(())
    }
}

/// Finite explicit V3 server. Unauthenticated publication requests and old
/// wire versions never enter the epoch directory. Lookups have query-bound
/// signed replies, including empty, denied and capacity replies. A response
/// is signed only while the original request and server deadlines remain live.
pub fn serve_authenticated_cell_rendezvous_pq(
    listener: &TcpListener,
    directory: &CellProviderDirectoryV3,
    addresses: &CellDiscoveryAddressPolicyV1,
    identity: &CellRendezvousIdentityV3<'_>,
    shutdown: &AtomicBool,
    limits: CellRendezvousLimitsV2,
) -> CellResultV1<CellRendezvousReportV3> {
    limits.validate()?;
    let overall = Instant::now() + limits.lifetime;
    addresses.validate()?;
    addresses.check(identity.bootstrap.endpoint)?;
    identity.validate_at(wall_now()?.as_secs())?;
    check_deadline(overall)?;
    listener.set_nonblocking(true)?;
    let mut report = CellRendezvousReportV3::default();
    while !shutdown.load(Ordering::Relaxed)
        && report.connections < limits.max_connections
        && report.signature_attempts() < MAX_DISCOVERY_RECORDS
        && Instant::now() < overall
    {
        match listener.accept() {
            Ok((mut stream, source)) => {
                report.connections += 1;
                let deadline = overall.min(Instant::now() + limits.request_timeout);
                let query = match read_query(&mut stream, deadline) {
                    Ok(query) => query,
                    Err(_) => {
                        report.rejected_requests += 1;
                        continue;
                    }
                };
                // The public endpoint is an explicit identity pin and can be a
                // deployed NAT address. It is not inferred from listener.local_addr().
                if query.bootstrap != identity.bootstrap {
                    report.rejected_requests += 1;
                    continue;
                }
                let mut response_deadline = deadline;
                let result = (|| {
                    check_deadline(deadline)?;
                    let sampled_at = Instant::now();
                    let wall = wall_now()?;
                    let now = wall.as_secs();
                    identity.validate_at(now)?;
                    query.validate_at(now)?;
                    let valid_until = query
                        .expires_at
                        .min(identity.authority.expires_at)
                        .min(identity.authority.revoked_at.unwrap_or(u64::MAX));
                    let remaining = Duration::from_secs(valid_until).checked_sub(wall).ok_or(
                        CellErrorV1::Invalid("authenticated rendezvous current expiry"),
                    )?;
                    response_deadline = deadline.min(sampled_at + remaining);
                    serve_query(
                        &query,
                        source,
                        directory,
                        addresses,
                        response_deadline,
                        &mut report,
                    )
                })();
                let (status, body) = match result {
                    Ok(body) => (0, body),
                    Err(CellErrorV1::Invalid(
                        "discovery identity capacity"
                        | "discovery active capacity"
                        | "discovery replay capacity",
                    )) => {
                        report.rejected_requests += 1;
                        (2, Vec::new())
                    }
                    Err(_) => {
                        report.rejected_requests += 1;
                        (1, Vec::new())
                    }
                };
                let publication = (|| -> CellResultV1<()> {
                    check_deadline(response_deadline)?;
                    let now = wall_now()?.as_secs();
                    identity.validate_at(now)?;
                    query.validate_at(now)?;
                    let expires_at = query
                        .expires_at
                        .min(identity.authority.expires_at)
                        .min(identity.authority.revoked_at.unwrap_or(u64::MAX));
                    report.reserve_reply()?;
                    let frame =
                        signed_response(&query, status, &body, now, expires_at, identity.key)?;
                    check_deadline(response_deadline)?;
                    let current = wall_now()?.as_secs();
                    require(
                        current >= now && current < expires_at,
                        "authenticated rendezvous reply expired",
                    )?;
                    identity.authority.live_at(current)?;
                    network::write_deadline(&mut stream, &frame, response_deadline)?;
                    Ok(())
                })();
                if publication.is_err() {
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

fn read_query(stream: &mut TcpStream, deadline: Instant) -> CellResultV1<Query> {
    let mut header = [0; 12];
    network::read_deadline(stream, &mut header, deadline, None)?;
    require(
        header[..6] == [b'C', b'D', b'Q', b'3', 3, 0x65]
            && (header[6] == 1 || header[6] == 2)
            && header[7] == 0,
        "authenticated discovery request version/algorithm",
    )?;
    let payload = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("authenticated discovery request length"))?,
    ) as usize;
    require(
        (header[6] == 1 && payload == 0)
            || (header[6] == 2
                && payload == CELL_PROVIDER_RECORD_BYTES_V3 + ML_DSA_65_SIGNATURE_BYTES),
        "authenticated discovery request bound",
    )?;
    let mut wire = vec![0; QUERY_BYTES + payload];
    wire[..12].copy_from_slice(&header);
    network::read_deadline(stream, &mut wire[12..], deadline, None)?;
    Query::decode(&wire)
}

fn serve_query(
    query: &Query,
    source: SocketAddr,
    directory: &CellProviderDirectoryV3,
    addresses: &CellDiscoveryAddressPolicyV1,
    deadline: Instant,
    report: &mut CellRendezvousReportV3,
) -> CellResultV1<Vec<u8>> {
    let sampled = CellDiscoveryTimeV3::sample()?;
    let sampled_at = sampled.monotonic();
    let wall = sampled.unix_time();
    let now = wall.as_secs();
    if query.kind() == 2 {
        report.reserve_validation(false)?;
        let record = CellProviderRecordV3::decode(&query.record)?;
        let receipt = record.verify_at(query.request, sampled, addresses, directory.keys())?;
        report.reserve_validation(true)?;
        let statement = record.statement();
        let query_authority_expiry = directory.keys().verify(
            statement.owner,
            statement.owner_generation,
            now,
            &query.announcement_message(),
            &query.signature,
        )?;
        check_deadline(deadline)?;
        let current = wall_now()?.as_secs();
        query.validate_at(current)?;
        require(
            current >= now && current < query_authority_expiry,
            "authenticated announcement authority lifetime",
        )?;
        // The identity is the verified signer of this exact publication query;
        // the IP comes from accept(), and both must match the durable host roster.
        let authenticated_source = CellDiscoverySourceV3 {
            authenticated_key_id: statement.owner,
            generation: statement.owner_generation,
            ip: source.ip(),
        };
        let valid_until = receipt
            .valid_until()
            .min(query_authority_expiry)
            .min(query.expires_at);
        let remaining =
            Duration::from_secs(valid_until)
                .checked_sub(wall)
                .ok_or(CellErrorV1::Invalid(
                    "authenticated announcement current expiry",
                ))?;
        let admission_deadline = deadline
            .min(sampled_at + remaining)
            .min(receipt.monotonic_expiry());
        directory.accept_verified(&receipt, authenticated_source, current, admission_deadline)?;
        Ok(record.digest().to_vec())
    } else {
        let mut records = directory.records(query.request, now, deadline)?;
        // Preserve all durable high water. Active advertisements compete for
        // the finite reply first; live withdrawals occupy remaining positions.
        records.sort_by_key(|record| record.statement().withdrawn);
        let mut body = vec![0];
        for record in records {
            if body[0] as usize == MAX_DISCOVERED_PROVIDERS {
                break;
            }
            if record.statement().request != query.request || record.live_at(now).is_err() {
                continue;
            }
            // This complete retained snapshot may outlive a provider key.
            // Its known-ineligible authority must not consume a verification
            // slot or hide later live providers. Incoming frames still reserve
            // their original slots before verification as before.
            let statement = record.statement();
            let eligible_authority = directory.keys().pins().any(|pin| {
                pin.key_id == statement.owner
                    && pin.generation == statement.owner_generation
                    && pin.live_at(now).is_ok()
            });
            if !eligible_authority {
                continue;
            }
            report.reserve_validation(false)?;
            if record
                .verify_at(query.request, sampled, addresses, directory.keys())
                .is_err()
            {
                report.rejected_records += 1;
                continue;
            }
            body.extend(record.encode());
            body[0] += 1;
        }
        check_deadline(deadline)?;
        Ok(body)
    }
}

#[cfg(all(test, unix))]
#[path = "auth_tests.rs"]
mod tests;
