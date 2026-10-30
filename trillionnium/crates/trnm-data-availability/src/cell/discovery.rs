//! Explicit, finite development rendezvous. An advertisement is only a signed
//! location hint. It proves no bytes, retention, endpoint control, payment,
//! independent custody, release selection or permission to install/use a model.
//! No referrals, DNS, DHT routing or automatic namespace reset exist here.

use super::{require, CellContextV1, CellDigestV1, CellErrorV1, CellResultV1};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod directory;
mod transport;
pub use directory::{CellProviderDirectoryUsageV1, CellProviderDirectoryV1};
pub use transport::{
    announce_cell_provider, fetch_discovered_cell_to_file, serve_cell_rendezvous,
    CellDiscoveryFetchReportV1, CellDiscoveryObservationV1, CellDiscoveryOptionsV1,
    CellRendezvousLimitsV1, CellRendezvousReportV1,
};

pub const CELL_DISCOVERY_PROFILE_V1: &str = "cell-provider-discovery-dev-v1";
pub const CELL_PROVIDER_RECORD_BYTES_V1: usize = 335;
pub const MAX_DISCOVERY_BOOTSTRAPS: usize = 4;
pub const MAX_DISCOVERY_CONNECTIONS: u64 = 8;
pub const MAX_DISCOVERY_RECORDS: usize = 64;
pub const MAX_DISCOVERED_PROVIDERS: usize = 8;
pub const MAX_DISCOVERY_RESPONSE_BYTES: u64 = 32 * 1024;
const MAX_TTL_SECONDS: u64 = 300;
const FUTURE_SKEW_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellDiscoveryContextV1 {
    /// Explicit operator-selected fresh, nonzero development namespace.
    pub namespace: CellDigestV1,
    pub network: CellDigestV1,
    pub parameters: CellDigestV1,
    pub genesis: CellDigestV1,
}
impl CellDiscoveryContextV1 {
    fn validate(self) -> CellResultV1<()> {
        require(
            [self.namespace, self.network, self.parameters, self.genesis]
                .iter()
                .all(|v| *v != [0; 32]),
            "discovery context",
        )
    }
    fn encode(self) -> Vec<u8> {
        [self.namespace, self.network, self.parameters, self.genesis].concat()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellDiscoveryRequestV1 {
    pub context: CellDiscoveryContextV1,
    /// Digest of the context pinned by the existing owner, never a peer choice.
    pub cell_context: CellDigestV1,
    pub manifest: CellDigestV1,
}
impl CellDiscoveryRequestV1 {
    fn validate(self) -> CellResultV1<()> {
        self.context.validate()?;
        require(
            self.cell_context != [0; 32] && self.manifest != [0; 32],
            "discovery pin",
        )
    }
    fn encode(self) -> Vec<u8> {
        let mut out = self.context.encode();
        out.extend(self.cell_context);
        out.extend(self.manifest);
        out
    }
    fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(bytes.len() == 192, "discovery query length")?;
        let mut input = Input(bytes);
        let value = Self {
            context: CellDiscoveryContextV1 {
                namespace: input.take()?,
                network: input.take()?,
                parameters: input.take()?,
                genesis: input.take()?,
            },
            cell_context: input.take()?,
            manifest: input.take()?,
        };
        value.validate()?;
        Ok(value)
    }
}

pub fn cell_discovery_context_digest(context: &CellContextV1) -> CellResultV1<CellDigestV1> {
    context.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-discovery-context.dev.v1\0");
    hash.update([context.family.len() as u8]);
    hash.update(context.family.as_bytes());
    for value in [
        context.base,
        context.parent,
        context.tokenizer,
        context.layout,
        context.runtime,
    ] {
        hash.update(value);
    }
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderStatementV1 {
    pub request: CellDiscoveryRequestV1,
    /// The advertising key, not a chain funds owner or an endpoint attestation.
    pub owner: CellDigestV1,
    pub endpoint: SocketAddr,
    pub sequence: u64,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderRecordV1 {
    statement: CellProviderStatementV1,
    signature: [u8; 64],
}
impl CellProviderRecordV1 {
    pub fn sign(statement: CellProviderStatementV1, key: &SigningKey) -> CellResultV1<Self> {
        require(
            statement.owner == key.verifying_key().to_bytes(),
            "discovery signing owner",
        )?;
        let mut record = Self {
            statement,
            signature: [0; 64],
        };
        record.shape()?;
        record.signature = key.sign(&record.message()).to_bytes();
        Ok(record)
    }
    pub fn statement(&self) -> &CellProviderStatementV1 {
        &self.statement
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"CDP1".to_vec();
        out.extend(self.statement.request.encode());
        out.extend(self.statement.owner);
        out.extend(endpoint_bytes(self.statement.endpoint));
        for value in [
            self.statement.sequence,
            self.statement.issued_unix_seconds,
            self.statement.expires_unix_seconds,
        ] {
            out.extend(value.to_be_bytes());
        }
        out.extend(self.signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PROVIDER_RECORD_BYTES_V1,
            "discovery record length",
        )?;
        let mut input = Input(bytes);
        require(input.take::<4>()? == *b"CDP1", "discovery record version")?;
        let request = CellDiscoveryRequestV1::decode(&input.take::<192>()?)?;
        let owner = input.take()?;
        let endpoint = decode_endpoint(input.take()?)?;
        let statement = CellProviderStatementV1 {
            request,
            owner,
            endpoint,
            sequence: u64::from_be_bytes(input.take()?),
            issued_unix_seconds: u64::from_be_bytes(input.take()?),
            expires_unix_seconds: u64::from_be_bytes(input.take()?),
        };
        let record = Self {
            statement,
            signature: input.take()?,
        };
        record.shape()?;
        require(record.encode() == bytes, "discovery canonical record")?;
        Ok(record)
    }
    fn message(&self) -> CellDigestV1 {
        let bytes = self.encode();
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-provider-discovery.dev.v1\0");
        hash.update(&bytes[..CELL_PROVIDER_RECORD_BYTES_V1 - 64]);
        hash.finalize().into()
    }
    fn digest(&self) -> CellDigestV1 {
        Sha256::digest(self.encode()).into()
    }
    fn shape(&self) -> CellResultV1<()> {
        let s = &self.statement;
        s.request.validate()?;
        require(
            s.sequence > 0 && s.endpoint.port() != 0 && canonical_endpoint(s.endpoint),
            "discovery sequence/endpoint",
        )?;
        require(
            s.expires_unix_seconds
                .checked_sub(s.issued_unix_seconds)
                .is_some_and(|ttl| (1..=MAX_TTL_SECONDS).contains(&ttl)),
            "discovery TTL",
        )?;
        require(canonical_point(&s.owner), "discovery canonical public key")
    }
    fn verify_signature(&self) -> CellResultV1<()> {
        self.shape()?;
        let r: [u8; 32] = self.signature[..32]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("discovery R"))?;
        require(canonical_point(&r), "discovery canonical signature R")?;
        crate::types::verify_strict(&self.statement.owner, &self.message(), &self.signature)
            .map_err(|_| CellErrorV1::Invalid("discovery signature"))
    }
    fn verify_at(
        &self,
        expected: CellDiscoveryRequestV1,
        now: u64,
        policy: &CellDiscoveryAddressPolicyV1,
    ) -> CellResultV1<()> {
        require(
            self.statement.request == expected,
            "discovery pinned context",
        )?;
        self.live_at(now)?;
        policy.check(self.statement.endpoint)?;
        self.verify_signature()
    }
    fn live_at(&self, now: u64) -> CellResultV1<()> {
        require(
            self.statement.issued_unix_seconds <= now.saturating_add(FUTURE_SKEW_SECONDS)
                && now < self.statement.expires_unix_seconds,
            "discovery expired/future record",
        )
    }
}

// Same RFC8032 canonical encoding boundary as M01. Membership, small-order and
// scalar/signature validation remain in the existing strict Ed25519 primitive.
fn canonical_point(bytes: &[u8; 32]) -> bool {
    let sign = bytes[31] >> 7;
    let mut y = *bytes;
    y[31] &= 127;
    let mut p = [255; 32];
    p[0] = 237;
    p[31] = 127;
    if y.iter().rev().cmp(p.iter().rev()).is_ge() {
        return false;
    }
    let mut one = [0; 32];
    one[0] = 1;
    let mut minus_one = p;
    minus_one[0] -= 1;
    !(sign == 1 && (y == one || y == minus_one))
}
fn canonical_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v) => {
            v.flowinfo() == 0 && v.scope_id() == 0 && v.ip().to_ipv4_mapped().is_none()
        }
    }
}
fn ip_bytes(ip: IpAddr) -> [u8; 17] {
    let mut out = [0; 17];
    match ip {
        IpAddr::V4(ip) => {
            out[0] = 4;
            out[13..].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out[0] = 6;
            out[1..].copy_from_slice(&ip.octets());
        }
    }
    out
}
fn endpoint_bytes(endpoint: SocketAddr) -> [u8; 19] {
    let mut out = [0; 19];
    out[..17].copy_from_slice(&ip_bytes(endpoint.ip()));
    out[17..].copy_from_slice(&endpoint.port().to_be_bytes());
    out
}
fn decode_endpoint(bytes: [u8; 19]) -> CellResultV1<SocketAddr> {
    let ip = match bytes[0] {
        4 => {
            require(bytes[1..13] == [0; 12], "discovery canonical IPv4")?;
            IpAddr::V4(Ipv4Addr::new(bytes[13], bytes[14], bytes[15], bytes[16]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[1..17])
                .map_err(|_| CellErrorV1::Invalid("discovery IPv6"))?,
        )),
        _ => return Err(CellErrorV1::Invalid("discovery IP family")),
    };
    let endpoint = SocketAddr::new(ip, u16::from_be_bytes([bytes[17], bytes[18]]));
    require(canonical_endpoint(endpoint), "discovery canonical endpoint")?;
    Ok(endpoint)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellDiscoveryCidrV1 {
    network: IpAddr,
    prefix: u8,
}
impl CellDiscoveryCidrV1 {
    pub fn new(network: IpAddr, prefix: u8) -> CellResultV1<Self> {
        let bits = if network.is_ipv4() { 32 } else { 128 };
        require(prefix > 0 && prefix <= bits, "discovery CIDR prefix")?;
        let value = Self { network, prefix };
        require(
            value.masked(network) == Some(network),
            "discovery CIDR host bits",
        )?;
        Ok(value)
    }
    fn masked(&self, ip: IpAddr) -> Option<IpAddr> {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(v)) => Some(IpAddr::V4(Ipv4Addr::from(
                u32::from(v) & (u32::MAX << (32 - self.prefix)),
            ))),
            (IpAddr::V6(_), IpAddr::V6(v)) => Some(IpAddr::V6(Ipv6Addr::from(
                u128::from(v) & (u128::MAX << (128 - self.prefix)),
            ))),
            _ => None,
        }
    }
}
#[derive(Clone, Debug)]
pub enum CellDiscoveryAddressPolicyV1 {
    /// Explicit test/development opt-in, still restricted to finite ports.
    LoopbackDevOnly { ports: Vec<u16> },
    /// No DNS or implicit Internet/private-network permission. The operator
    /// selects at most eight canonical CIDRs and sixteen service ports.
    ScopedDeployment {
        cidrs: Vec<CellDiscoveryCidrV1>,
        ports: Vec<u16>,
    },
}
impl CellDiscoveryAddressPolicyV1 {
    pub fn validate(&self) -> CellResultV1<()> {
        let ports = match self {
            Self::LoopbackDevOnly { ports } => ports,
            Self::ScopedDeployment { cidrs, ports } => {
                require(
                    !cidrs.is_empty() && cidrs.len() <= 8,
                    "discovery CIDR count",
                )?;
                for cidr in cidrs {
                    CellDiscoveryCidrV1::new(cidr.network, cidr.prefix)?;
                }
                ports
            }
        };
        require(
            !ports.is_empty()
                && ports.len() <= 16
                && ports.iter().all(|port| *port != 0)
                && ports
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == ports.len(),
            "discovery service ports",
        )
    }
    pub fn check(&self, endpoint: SocketAddr) -> CellResultV1<()> {
        self.validate()?;
        require(canonical_endpoint(endpoint), "discovery endpoint scope")?;
        let ip = endpoint.ip();
        let accepted = match self {
            Self::LoopbackDevOnly { ports } => ip.is_loopback() && ports.contains(&endpoint.port()),
            Self::ScopedDeployment { cidrs, ports } => {
                let special = ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || match ip {
                        IpAddr::V4(v) => v.is_link_local() || v.is_broadcast(),
                        IpAddr::V6(v) => {
                            v.segments()[0] & 0xffc0 == 0xfe80 || v.to_ipv4_mapped().is_some()
                        }
                    };
                !special
                    && ports.contains(&endpoint.port())
                    && cidrs
                        .iter()
                        .any(|cidr| cidr.masked(ip) == Some(cidr.network))
            }
        };
        require(accepted, "discovery outbound address denied")
    }
}

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        require(self.0.len() >= N, "discovery truncated field")?;
        let value = self.0[..N]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("discovery field"))?;
        self.0 = &self.0[N..];
        Ok(value)
    }
}
fn wall_now() -> CellResultV1<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CellErrorV1::Invalid("discovery wall clock"))
}
fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "discovery absolute deadline")
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
mod vectors;

#[cfg(all(test, not(unix)))]
mod platform_tests;

#[cfg(all(test, unix))]
mod sequence_tests;

#[cfg(all(test, unix))]
mod equivocation_history_tests;

// PCP2-only bounded research receiver. CDP1, CDP2 and any opportunistic
// classic/PQ fallback are intentionally never accepted by this interface.
pub mod pq_reply_v2 {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use trnm_crypto_primitives::pq_cell_provider::{
        pq_cell_provider_key_id_v2, PqCellProviderExpectationV2, SignedPqCellProviderRecordV2,
        PQ_CELL_PROVIDER_RECORD_V2_BYTES,
    };

    /// Both the key and replay floor MUST come from independent trusted policy,
    /// NOT a record or a locally replayable provider database.
    pub struct PqPinnedProviderV2<'a> {
        pub signer_key_id: [u8; 32],
        pub trusted_ml_dsa65_public_key: &'a [u8],
        pub external_sequence_floor: u64,
    }

    // The caller's roster is an authority input, not an untrusted reply field.
    // Its cheap shape, key-ID binding and uniqueness must be checked BEFORE
    // opening any PCP2 TCP connection (including a silent malicious bootstrap).
    // This cannot establish external custody, revocation or durable replay.
    fn preflight_pq_owner_roster_v2(pinned_owners: &[PqPinnedProviderV2<'_>]) -> CellResultV1<()> {
        require(
            !pinned_owners.is_empty() && pinned_owners.len() <= MAX_DISCOVERED_PROVIDERS,
            "PQ bounded independent roster",
        )?;
        let mut seen = BTreeSet::new();
        for owner in pinned_owners {
            let computed = pq_cell_provider_key_id_v2(owner.trusted_ml_dsa65_public_key)
                .map_err(|_| CellErrorV1::Invalid("PQ pinned public key"))?;
            require(
                computed == owner.signer_key_id && seen.insert(owner.signer_key_id),
                "PQ duplicate/mismatched pinned owner",
            )?;
        }
        Ok(())
    }

    /// A hint, not a capability to install, release, serve or execute anything.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct VerifiedPqDiscoveryProviderV2 {
        signer_key_id: [u8; 32],
        endpoint: SocketAddr,
        sequence: u64,
        expires_unix_seconds: u64,
    }
    impl VerifiedPqDiscoveryProviderV2 {
        pub fn signer_key_id(&self) -> [u8; 32] {
            self.signer_key_id
        }
        pub fn endpoint(&self) -> SocketAddr {
            self.endpoint
        }
        pub fn sequence(&self) -> u64 {
            self.sequence
        }
        pub fn expires_unix_seconds(&self) -> u64 {
            self.expires_unix_seconds
        }
    }

    /// Whole-reply fail-closed, with *all* inexpensive checks performed before
    /// the first ML-DSA verification. Eight PCP2 records fit the original 32KiB
    /// response ceiling (28641 bytes including the count). Not wired into
    /// ordinary transport, directory persistence, FinalUse or network custody.
    pub fn verify_pq_provider_reply_v2(
        response: &[u8],
        expected_request: CellDiscoveryRequestV1,
        pinned_owners: &[PqPinnedProviderV2<'_>],
        now_unix_seconds: u64,
        addresses: &CellDiscoveryAddressPolicyV1,
    ) -> CellResultV1<Vec<VerifiedPqDiscoveryProviderV2>> {
        expected_request.validate()?;
        addresses.validate()?;
        require(
            !response.is_empty() && response.len() <= MAX_DISCOVERY_RESPONSE_BYTES as usize,
            "PQ bounded reply",
        )?;
        let count = usize::from(response[0]);
        require(
            (1..=MAX_DISCOVERED_PROVIDERS).contains(&count)
                && response.len() == 1 + count * PQ_CELL_PROVIDER_RECORD_V2_BYTES,
            "PQ PCP2-only reply count/length",
        )?;
        require(
            !pinned_owners.is_empty() && pinned_owners.len() <= MAX_DISCOVERED_PROVIDERS,
            "PQ bounded independent roster",
        )?;
        let encoded = expected_request.encode();
        let request_pin: [u8; 192] = encoded
            .as_slice()
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("PQ request bytes"))?;

        let mut trusted = BTreeMap::new();
        for owner in pinned_owners {
            let computed = pq_cell_provider_key_id_v2(owner.trusted_ml_dsa65_public_key)
                .map_err(|_| CellErrorV1::Invalid("PQ pinned public key"))?;
            require(
                computed == owner.signer_key_id
                    && trusted.insert(owner.signer_key_id, owner).is_none(),
                "PQ duplicate/mismatched pinned owner",
            )?;
        }

        let mut seen = BTreeSet::new();
        let mut pending = Vec::with_capacity(count);
        for bytes in response[1..].chunks_exact(PQ_CELL_PROVIDER_RECORD_V2_BYTES) {
            let record = SignedPqCellProviderRecordV2::from_wire(bytes)
                .map_err(|_| CellErrorV1::Invalid("PQ malformed PCP2"))?;
            require(
                record.statement.pinned_request == request_pin,
                "PQ different request",
            )?;
            let owner = *trusted
                .get(&record.signer_key_id)
                .ok_or(CellErrorV1::Invalid("PQ unknown signer"))?;
            require(
                seen.insert(record.signer_key_id),
                "PQ duplicate reply owner",
            )?;
            // Preserve the PCP2 primitive's exact five-second future skew,
            // but check every record's replay/time *before any expensive*
            // ML-DSA verification. The primitive repeats these checks as the
            // authoritative final authentication boundary.
            require(
                record.statement.sequence > owner.external_sequence_floor,
                "PQ batch stale external replay floor",
            )?;
            require(
                record.statement.issued_unix_seconds <= now_unix_seconds.saturating_add(5)
                    && now_unix_seconds < record.statement.expires_unix_seconds,
                "PQ batch expired/future record",
            )?;
            let endpoint = decode_endpoint(record.statement.endpoint)?;
            addresses.check(endpoint)?;
            pending.push((record, owner, endpoint));
        }

        let mut result = Vec::with_capacity(count);
        for (record, owner, endpoint) in pending {
            let expected = PqCellProviderExpectationV2 {
                pinned_request: &request_pin,
                trusted_ml_dsa65_public_key: owner.trusted_ml_dsa65_public_key,
                last_accepted_sequence: owner.external_sequence_floor,
                now_unix_seconds,
            };
            let verified = record
                .verify_for_pinned_context(&expected)
                .map_err(|_| CellErrorV1::Invalid("PQ signature/replay/time"))?;
            result.push(VerifiedPqDiscoveryProviderV2 {
                signer_key_id: record.signer_key_id,
                endpoint,
                sequence: verified.sequence(),
                expires_unix_seconds: verified.expires_unix_seconds(),
            });
        }
        Ok(result)
    }

    /// One explicitly configured bootstrap, distinct PCP2 frame, original
    /// caller deadline and shared received-byte accounting. The external
    /// replay frontier remains caller-owned: this probe does not publish Cell
    /// custody, select a release, persist a roster or install a Hepta model.
    pub fn query_pq_provider_from_bootstrap_v2(
        bootstrap: SocketAddr,
        expected_request: CellDiscoveryRequestV1,
        pinned_owners: &[PqPinnedProviderV2<'_>],
        addresses: &CellDiscoveryAddressPolicyV1,
        limits: super::super::CellPeerLimitsV1,
        original_deadline: Instant,
    ) -> CellResultV1<(
        Vec<VerifiedPqDiscoveryProviderV2>,
        CellDiscoveryObservationV1,
    )> {
        expected_request.validate()?;
        addresses.validate()?;
        addresses.check(bootstrap)?;
        preflight_pq_owner_roster_v2(pinned_owners)?;
        limits.validate()?;
        let overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(overall)?;
        let requests_left = std::sync::atomic::AtomicU64::new(1);
        let responses = super::super::network::ResponseBudget::new(
            limits.max_response_bytes.min(MAX_DISCOVERY_RESPONSE_BYTES),
        );
        let context = super::super::network::RequestContext {
            timeout: limits.request_timeout,
            overall,
            requests_left: &requests_left,
            responses: &responses,
            peer_failures: Default::default(),
        };
        let mut observation = CellDiscoveryObservationV1::default();
        let reply = super::transport::exchange_pq_v2(
            bootstrap,
            &expected_request.encode(),
            &context,
            &mut observation,
        )?;
        check_deadline(overall)?;
        let providers = verify_pq_provider_reply_v2(
            &reply,
            expected_request,
            pinned_owners,
            wall_now()?.as_secs(),
            addresses,
        )?;
        // A successful PCP2 reply verified exactly one real ML-DSA signature
        // per returned record. Do not return a misleading zero cost count.
        // Failed calls still return Err and need separate failure telemetry.
        observation.record_validation_attempts = providers.len();
        check_deadline(overall)?;
        Ok((providers, observation))
    }

    /// A received PCP2 provider hint is only a routing hint; even a completely
    /// retrieved, hashed Cell cannot authorize release, installation or FinalUse.
    /// The independent Control owner must durably advance the returned provider
    /// sequence frontier before any operation that depends on its freshness.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PqDiscoveredCellFetchReportV2 {
        pub discovery: CellDiscoveryObservationV1,
        pub verified_providers: Vec<VerifiedPqDiscoveryProviderV2>,
        pub manifest_initial_cache_hit: bool,
        pub fetch: super::super::CellFetchReportV1,
    }

    /// Research-only PCQ2/PCS2 -> pinned ML-DSA PCP2 -> real manifest/chunks
    /// -> create-only full Cell materialization, with one ORIGINAL allocation.
    ///
    /// Unlike separately calling query_pq_provider_from_bootstrap_v2 and a Cell
    /// fetch API, this cannot silently reset connection, response-byte or
    /// overall-time budgets between discovery and content retrieval. It never
    /// falls back to CDQ1/CDP1 or the competing CDP2 research format.
    ///
    /// The caller supplies the independently trusted owner roster, replay
    /// floors, Cell request and network address policy. This API does NOT
    /// provide externally durable replay protection, provider custody proofs,
    /// TLS identity, deployment selection, or Hepta FinalUse authorization.
    pub fn fetch_pq_discovered_cell_to_file_v2(
        store: &super::super::CellStoreV1,
        options: &CellDiscoveryOptionsV1,
        pinned_owners: &[PqPinnedProviderV2<'_>],
        limits: super::super::CellPeerLimitsV1,
        original_deadline: Instant,
        output: &std::path::Path,
    ) -> CellResultV1<(super::super::CellManifestV1, PqDiscoveredCellFetchReportV2)> {
        let expected_request = options.request;
        let addresses = &options.addresses;
        expected_request.validate()?;
        addresses.validate()?;
        require(
            options.bootstraps.len() == 1,
            "PQ exactly one independent bootstrap",
        )?;
        let bootstrap = options.bootstraps[0];
        addresses.check(bootstrap)?;
        preflight_pq_owner_roster_v2(pinned_owners)?;
        limits.validate()?;
        let original_overall = original_deadline.min(Instant::now() + limits.overall_timeout);
        check_deadline(original_overall)?;

        let requests_left = std::sync::atomic::AtomicU64::new(limits.max_connections);
        let responses = super::super::network::ResponseBudget::new(limits.max_response_bytes);
        let transport = super::super::network::RequestContext {
            timeout: limits.request_timeout,
            overall: original_overall,
            requests_left: &requests_left,
            responses: &responses,
            peer_failures: Default::default(),
        };
        let mut discovery = CellDiscoveryObservationV1::default();
        let response = super::transport::exchange_pq_v2(
            bootstrap,
            &expected_request.encode(),
            &transport,
            &mut discovery,
        )?;
        check_deadline(original_overall)?;

        // Compute an Instant lease from the actual observed wall clock,
        // including subsecond time. Never restart the original budget.
        let sampled_at = Instant::now();
        let wall = wall_now()?;
        let verified_providers = verify_pq_provider_reply_v2(
            &response,
            expected_request,
            pinned_owners,
            wall.as_secs(),
            addresses,
        )?;
        // Count the actual ML-DSA verifications in the complete fetch path,
        // just as the standalone PCP2 query reports its authentication cost.
        discovery.record_validation_attempts = verified_providers.len();
        let mut expiry = original_overall;
        let mut peers = Vec::with_capacity(verified_providers.len());
        for provider in &verified_providers {
            let remaining = std::time::Duration::from_secs(provider.expires_unix_seconds())
                .checked_sub(wall)
                .ok_or(CellErrorV1::Invalid("PQ provider lease expired"))?;
            require(!remaining.is_zero(), "PQ provider lease expired")?;
            expiry = expiry.min(sampled_at + remaining);
            peers.push(provider.endpoint());
        }
        require(
            !peers.is_empty() && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
            "PQ duplicate or missing provider endpoint",
        )?;
        check_deadline(expiry)?;
        let transport = super::super::network::RequestContext {
            overall: expiry,
            ..transport
        };

        // The first real network/cache read is observed, not simulated. Its
        // original request/byte consumption is shared with the final fetch.
        let (manifest, initial_rejected, manifest_initial_cache_hit) =
            super::super::network::fetch_manifest_observed(
                store,
                expected_request.manifest,
                &peers,
                limits,
                &transport,
            )?;
        require(
            cell_discovery_context_digest(manifest.context())? == expected_request.cell_context,
            "PQ discovered Cell context mismatch",
        )?;
        let (manifest, mut fetch) = super::super::network::fetch_cell_in_session(
            store,
            expected_request.manifest,
            &peers,
            limits,
            &transport,
            Some(output),
        )?;
        // The common fetch observes the second manifest cache read; preserve
        // the rejected responses of the first read without double-counting
        // bytes or connections.
        fetch.rejected_responses += initial_rejected;
        // fetch_cell_in_session already enforces this original deadline for
        // every network/cache operation and at the LAST pre-publication check.
        // Its durable create-only file may legitimately finish directory sync
        // and cleanup after that checkpoint. Rechecking here would return a
        // timeout *after* publishing the complete file, making the result
        // disagree with the materialized terminal fact.
        Ok((
            manifest,
            PqDiscoveredCellFetchReportV2 {
                discovery,
                verified_providers,
                manifest_initial_cache_hit,
                fetch,
            },
        ))
    }

    /// Experimental, in-memory PCP2-only service. All source records must have
    /// been signed beforehand; this function authenticates them against an
    /// independently supplied roster *before* accepting any network clients.
    /// It does not register owners, durably record nonce/replay floors, serve
    /// Cell bytes, bind TLS identities or authorize model installation.
    ///
    /// After starting, changed external roster or witness state is not observed
    /// automatically. Deployments MUST revalidate/restart on any revocation.
    pub fn serve_pq_cell_rendezvous_v2(
        listener: &std::net::TcpListener,
        expected_request: CellDiscoveryRequestV1,
        signed_reply: &[u8],
        pinned_owners: &[PqPinnedProviderV2<'_>],
        addresses: &CellDiscoveryAddressPolicyV1,
        shutdown: &std::sync::atomic::AtomicBool,
        limits: CellRendezvousLimitsV1,
    ) -> CellResultV1<CellRendezvousReportV1> {
        limits.validate()?;
        addresses.validate()?;
        let verified = verify_pq_provider_reply_v2(
            signed_reply,
            expected_request,
            pinned_owners,
            wall_now()?.as_secs(),
            addresses,
        )?;
        let expires = verified
            .iter()
            .map(VerifiedPqDiscoveryProviderV2::expires_unix_seconds)
            .min()
            .ok_or(CellErrorV1::Invalid("PQ no signed providers"))?;
        let encoded_request = expected_request.encode();
        let pin: [u8; 192] = encoded_request
            .as_slice()
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("PQ request length"))?;
        let mut report = super::transport::serve_pq_reply_bytes_v2(
            listener,
            pin,
            signed_reply,
            expires,
            shutdown,
            limits,
        )?;
        // The entire signed roster was genuinely ML-DSA verified once before
        // listening. Count that original work even if clients were denied.
        report.record_validation_attempts = verified.len();
        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ml_dsa::{KeyExport, KeyInit, Keypair, MlDsa65, SigningKey};
        use trnm_crypto_primitives::pq_cell_provider::PqCellProviderStatementV2;

        fn request() -> CellDiscoveryRequestV1 {
            CellDiscoveryRequestV1 {
                context: CellDiscoveryContextV1 {
                    namespace: [1; 32],
                    network: [2; 32],
                    parameters: [3; 32],
                    genesis: [4; 32],
                },
                cell_context: [5; 32],
                manifest: [6; 32],
            }
        }
        fn addresses() -> CellDiscoveryAddressPolicyV1 {
            CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31415] }
        }
        fn signed(seed: u8) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
            let key = SigningKey::<MlDsa65>::new_from_slice(&[seed; 32]).unwrap();
            let pk = key.verifying_key().to_bytes().to_vec();
            let id = pq_cell_provider_key_id_v2(&pk).unwrap();
            let statement = PqCellProviderStatementV2 {
                pinned_request: request().encode().try_into().unwrap(),
                endpoint: endpoint_bytes("127.0.0.1:31415".parse().unwrap()),
                sequence: 7,
                issued_unix_seconds: 100,
                expires_unix_seconds: 200,
            };
            let wire = SignedPqCellProviderRecordV2::sign(statement, &key)
                .unwrap()
                .to_wire();
            (wire, pk, id)
        }
        fn reply(records: &[&[u8]]) -> Vec<u8> {
            let mut output = vec![records.len() as u8];
            for record in records {
                output.extend_from_slice(record);
            }
            output
        }

        #[test]
        fn actual_ml_dsa_positive_and_fail_closed_downgrade() {
            let (wire, pk, id) = signed(42);
            let pin = || PqPinnedProviderV2 {
                signer_key_id: id,
                trusted_ml_dsa65_public_key: &pk,
                external_sequence_floor: 6,
            };
            let evaluate = |bytes: &[u8]| {
                verify_pq_provider_reply_v2(bytes, request(), &[pin()], 150, &addresses())
            };
            let accepted = evaluate(&reply(&[&wire])).unwrap();
            assert_eq!(accepted.len(), 1);
            assert_eq!(accepted[0].signer_key_id(), id);
            assert_eq!(accepted[0].sequence(), 7);
            assert_eq!(accepted[0].expires_unix_seconds(), 200);
            assert_eq!(
                accepted[0].endpoint(),
                "127.0.0.1:31415".parse::<SocketAddr>().unwrap()
            );
            assert!(evaluate(&reply(&[&vec![0; 335]])).is_err());
            assert!(evaluate(&reply(&[&vec![0; 5532]])).is_err());
            let mut other_magic = wire.clone();
            other_magic[..4].copy_from_slice(b"CDP2");
            assert!(evaluate(&reply(&[&other_magic])).is_err());
            let mut corrupted = wire.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            assert!(evaluate(&reply(&[&corrupted])).is_err());
            assert!(evaluate(&reply(&[&wire, &wire])).is_err());
            assert!(evaluate(&reply(&[wire.as_slice(); 9])).is_err());
            assert!(evaluate(&[]).is_err());
            assert_eq!(1 + 8 * PQ_CELL_PROVIDER_RECORD_V2_BYTES, 28641);
            assert!(8 * PQ_CELL_PROVIDER_RECORD_V2_BYTES < MAX_DISCOVERY_RESPONSE_BYTES as usize);
        }

        #[test]
        fn mixed_valid_and_invalid_providers_reject_whole_reply() {
            let (first, pk1, id1) = signed(42);
            let (second, pk2, id2) = signed(43);
            let pins = || {
                [
                    PqPinnedProviderV2 {
                        signer_key_id: id1,
                        trusted_ml_dsa65_public_key: &pk1,
                        external_sequence_floor: 6,
                    },
                    PqPinnedProviderV2 {
                        signer_key_id: id2,
                        trusted_ml_dsa65_public_key: &pk2,
                        external_sequence_floor: 6,
                    },
                ]
            };
            let good = reply(&[&first, &second]);
            assert_eq!(
                verify_pq_provider_reply_v2(&good, request(), &pins(), 150, &addresses())
                    .unwrap()
                    .len(),
                2
            );
            let mut invalid = second.clone();
            *invalid.last_mut().unwrap() ^= 1;
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&first, &invalid]),
                request(),
                &pins(),
                150,
                &addresses()
            )
            .is_err());
            let mut wrong_request = request();
            wrong_request.context.genesis[0] ^= 1;
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&first]),
                wrong_request,
                &pins(),
                150,
                &addresses()
            )
            .is_err());
            let bad_addresses =
                CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31416] };
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&first]),
                request(),
                &pins(),
                150,
                &bad_addresses
            )
            .is_err());
        }

        #[test]
        fn late_stale_or_expired_record_preflights_before_early_bad_signature() {
            let (mut first, pk1, id1) = signed(42);
            let (second, pk2, id2) = signed(43);
            *first.last_mut().unwrap() ^= 1;
            let stale_roster = [
                PqPinnedProviderV2 {
                    signer_key_id: id1,
                    trusted_ml_dsa65_public_key: &pk1,
                    external_sequence_floor: 6,
                },
                PqPinnedProviderV2 {
                    signer_key_id: id2,
                    trusted_ml_dsa65_public_key: &pk2,
                    external_sequence_floor: 7,
                },
            ];
            let stale = verify_pq_provider_reply_v2(
                &reply(&[&first, &second]),
                request(),
                &stale_roster,
                150,
                &addresses(),
            );
            assert!(matches!(
                stale,
                Err(CellErrorV1::Invalid("PQ batch stale external replay floor"))
            ));

            let mut expired = second.clone();
            // PCP2 fixed expires field, 263..271. The signature becomes
            // invalid, so this control also proves priority over ML-DSA.
            expired[263..271].copy_from_slice(&140u64.to_be_bytes());
            let current_roster = [
                PqPinnedProviderV2 {
                    signer_key_id: id1,
                    trusted_ml_dsa65_public_key: &pk1,
                    external_sequence_floor: 6,
                },
                PqPinnedProviderV2 {
                    signer_key_id: id2,
                    trusted_ml_dsa65_public_key: &pk2,
                    external_sequence_floor: 6,
                },
            ];
            let expired_result = verify_pq_provider_reply_v2(
                &reply(&[&first, &expired]),
                request(),
                &current_roster,
                150,
                &addresses(),
            );
            assert!(matches!(
                expired_result,
                Err(CellErrorV1::Invalid("PQ batch expired/future record"))
            ));
        }

        #[test]
        fn actual_tcp_pcp2_probe_authenticates_while_classical_frame_fails() {
            use std::io::{Read, Write};
            use std::net::TcpListener;
            use std::thread;
            use std::time::Duration;

            let now = wall_now().unwrap().as_secs();
            let key = SigningKey::<MlDsa65>::new_from_slice(&[71; 32]).unwrap();
            let pk = key.verifying_key().to_bytes().to_vec();
            let id = pq_cell_provider_key_id_v2(&pk).unwrap();
            let record = SignedPqCellProviderRecordV2::sign(
                PqCellProviderStatementV2 {
                    pinned_request: request().encode().try_into().unwrap(),
                    endpoint: endpoint_bytes("127.0.0.1:31415".parse().unwrap()),
                    sequence: 7,
                    issued_unix_seconds: now - 1,
                    expires_unix_seconds: now + 120,
                },
                &key,
            )
            .unwrap()
            .to_wire();
            let wire = reply(&[&record]);
            let limits = super::super::super::CellPeerLimitsV1 {
                request_timeout: Duration::from_secs(3),
                overall_timeout: Duration::from_secs(5),
                max_cell_bytes: 1024,
                parallelism: 1,
                max_connections: 1,
                max_response_bytes: MAX_DISCOVERY_RESPONSE_BYTES,
            };
            let pin = [PqPinnedProviderV2 {
                signer_key_id: id,
                trusted_ml_dsa65_public_key: &pk,
                external_sequence_floor: 6,
            }];

            for (response_magic, should_pass) in [(*b"PCS2", true), (*b"CDS1", false)] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let peer = listener.local_addr().unwrap();
                let mut ports = vec![31415, peer.port()];
                ports.sort_unstable();
                ports.dedup();
                let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports };
                let actual_reply = wire.clone();
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut frame = [0; 7];
                    stream.read_exact(&mut frame).unwrap();
                    assert_eq!(&frame[..4], b"PCQ2");
                    assert_eq!(frame[4], 1);
                    assert_eq!(u16::from_be_bytes([frame[5], frame[6]]), 192);
                    let mut request_bytes = [0; 192];
                    stream.read_exact(&mut request_bytes).unwrap();
                    assert_eq!(request_bytes.as_slice(), request().encode());
                    let mut response = response_magic.to_vec();
                    response.push(0);
                    response.extend((actual_reply.len() as u32).to_be_bytes());
                    response.extend(actual_reply);
                    stream.write_all(&response).unwrap();
                });
                let answer = query_pq_provider_from_bootstrap_v2(
                    peer,
                    request(),
                    &pin,
                    &policy,
                    limits,
                    Instant::now() + Duration::from_secs(6),
                );
                server.join().unwrap();
                if should_pass {
                    let (verified, observed) = answer.unwrap();
                    assert_eq!(verified.len(), 1);
                    assert_eq!(verified[0].signer_key_id(), id);
                    assert_eq!(observed.connection_attempts, 1);
                    assert_eq!(observed.record_validation_attempts, 1);
                    assert_eq!(observed.received_response_bytes, (wire.len() + 9) as u64);
                } else {
                    assert!(answer.is_err(), "classical CDS1 response downgraded PCP2");
                }
            }
        }

        #[test]
        fn actual_readonly_pq_rendezvous_accepts_pinned_proof_and_refuses_cdq1() {
            use std::io::{Read, Write};
            use std::net::{TcpListener, TcpStream};
            use std::sync::atomic::AtomicBool;
            use std::thread;
            use std::time::Duration;

            let now = wall_now().unwrap().as_secs();
            let key = SigningKey::<MlDsa65>::new_from_slice(&[73; 32]).unwrap();
            let pk = key.verifying_key().to_bytes().to_vec();
            let signer_id = pq_cell_provider_key_id_v2(&pk).unwrap();
            let wire = SignedPqCellProviderRecordV2::sign(
                PqCellProviderStatementV2 {
                    pinned_request: request().encode().try_into().unwrap(),
                    endpoint: endpoint_bytes("127.0.0.1:31415".parse().unwrap()),
                    sequence: 11,
                    issued_unix_seconds: now - 1,
                    expires_unix_seconds: now + 60,
                },
                &key,
            )
            .unwrap()
            .to_wire();
            let response = reply(&[&wire]);

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bootstrap = listener.local_addr().unwrap();
            let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
                ports: vec![bootstrap.port(), 31415],
            };
            let server_policy = policy.clone();
            let server_pk = pk.clone();
            let serve_limits = CellRendezvousLimitsV1 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::from_secs(6),
                max_connections: 2,
            };
            let expected_response = response.clone();
            let server = thread::spawn(move || {
                let pinned = [PqPinnedProviderV2 {
                    signer_key_id: signer_id,
                    trusted_ml_dsa65_public_key: &server_pk,
                    external_sequence_floor: 10,
                }];
                let shutdown = AtomicBool::new(false);
                serve_pq_cell_rendezvous_v2(
                    &listener,
                    request(),
                    &expected_response,
                    &pinned,
                    &server_policy,
                    &shutdown,
                    serve_limits,
                )
                .unwrap()
            });

            let pinned = [PqPinnedProviderV2 {
                signer_key_id: signer_id,
                trusted_ml_dsa65_public_key: &pk,
                external_sequence_floor: 10,
            }];
            let fetch_limits = super::super::super::CellPeerLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(4),
                max_cell_bytes: 1024,
                parallelism: 1,
                max_connections: 2,
                max_response_bytes: MAX_DISCOVERY_RESPONSE_BYTES,
            };
            let (providers, observation) = query_pq_provider_from_bootstrap_v2(
                bootstrap,
                request(),
                &pinned,
                &policy,
                fetch_limits,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(providers.len(), 1);
            assert_eq!(providers[0].sequence(), 11);
            assert_eq!(observation.connection_attempts, 1);
            assert_eq!(observation.record_validation_attempts, 1);
            assert_eq!(
                observation.received_response_bytes,
                (response.len() + 9) as u64
            );

            let mut legacy = TcpStream::connect(bootstrap).unwrap();
            legacy
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut query = b"CDQ1".to_vec();
            query.push(1);
            query.extend(192u16.to_be_bytes());
            query.extend(request().encode());
            legacy.write_all(&query).unwrap();
            let mut header = [0; 9];
            // A server may reset a refused classical connection while the
            // unconsumed legacy request body is still in its TCP receive queue.
            // Explicit PCS2 denial *or* connection reset/EOF is a rejection.
            match legacy.read_exact(&mut header) {
                Ok(()) => {
                    assert_eq!(&header[..4], b"PCS2");
                    assert_eq!(header[4], 1);
                    assert_eq!(&header[5..], &[0; 4]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) => panic!("unexpected legacy refusal error: {error}"),
            }

            let served = server.join().unwrap();
            assert_eq!(served.connections, 2);
            assert_eq!(served.rejected_requests, 1);
            assert_eq!(served.record_validation_attempts, 1);
        }

        #[test]
        fn stale_key_substitution_and_expiry_never_fall_back() {
            let (wire, pk, id) = signed(42);
            let pin = PqPinnedProviderV2 {
                signer_key_id: id,
                trusted_ml_dsa65_public_key: &pk,
                external_sequence_floor: 7,
            };
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&wire]),
                request(),
                &[pin],
                150,
                &addresses()
            )
            .is_err());
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&wire]),
                request(),
                &[],
                150,
                &addresses()
            )
            .is_err());
            let pin = PqPinnedProviderV2 {
                signer_key_id: id,
                trusted_ml_dsa65_public_key: &pk,
                external_sequence_floor: 6,
            };
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&wire]),
                request(),
                &[pin],
                200,
                &addresses()
            )
            .is_err());
            let wrong = [PqPinnedProviderV2 {
                signer_key_id: id,
                trusted_ml_dsa65_public_key: &[0; 1952],
                external_sequence_floor: 6,
            }];
            assert!(verify_pq_provider_reply_v2(
                &reply(&[&wire]),
                request(),
                &wrong,
                150,
                &addresses()
            )
            .is_err());
        }
        #[test]
        fn pq_rendezvous_and_real_cell_fetch_share_one_original_budget() {
            use crate::cell::{
                serve_cells, CellCacheConfigV4, CellContextV1, CellPeerLimitsV1, CellStoreV1,
            };
            use std::{
                cell::Cell,
                fs,
                net::TcpListener,
                rc::Rc,
                sync::{
                    atomic::{AtomicBool, Ordering},
                    Arc,
                },
                thread,
                time::Duration,
            };

            fn config() -> CellCacheConfigV4 {
                CellCacheConfigV4 {
                    max_database_bytes: 128 * 1024 * 1024,
                    max_logical_bytes: 64 * 1024 * 1024,
                    max_chunk_rows: 4096,
                    max_manifest_rows: 256,
                }
            }
            fn limits(connections: u64) -> CellPeerLimitsV1 {
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_secs(2),
                    overall_timeout: Duration::from_secs(10),
                    max_cell_bytes: 1_048_576,
                    parallelism: 2,
                    max_connections: connections,
                    max_response_bytes: 4 * 1_048_576,
                }
            }

            let dir = tempfile::tempdir().unwrap();
            let source_path = dir.path().join("pq-source.sqlite");
            let source = CellStoreV1::open(&source_path, config()).unwrap();
            let original = dir.path().join("pq-model-source");
            let bytes = vec![0xA5u8; 40_000];
            fs::write(&original, &bytes).unwrap();
            let manifest = source
                .pack_file(
                    &original,
                    CellContextV1 {
                        family: "pcp2-one-budget-e2e-v1".into(),
                        base: [51; 32],
                        parent: [52; 32],
                        tokenizer: [53; 32],
                        layout: [54; 32],
                        runtime: [55; 32],
                    },
                    16_384,
                )
                .unwrap();

            let cell_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let cell_endpoint = cell_listener.local_addr().unwrap();
            let bootstrap_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bootstrap = bootstrap_listener.local_addr().unwrap();
            let mut ports = vec![cell_endpoint.port(), bootstrap.port()];
            ports.sort_unstable();
            ports.dedup();
            let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports };
            let expected_request = CellDiscoveryRequestV1 {
                context: CellDiscoveryContextV1 {
                    namespace: [1; 32],
                    network: [2; 32],
                    parameters: [3; 32],
                    genesis: [4; 32],
                },
                cell_context: cell_discovery_context_digest(manifest.context()).unwrap(),
                manifest: manifest.id(),
            };

            let signer = SigningKey::<MlDsa65>::new_from_slice(&[76; 32]).unwrap();
            let trusted_key = signer.verifying_key().to_bytes().to_vec();
            let key_id = pq_cell_provider_key_id_v2(&trusted_key).unwrap();
            let now = wall_now().unwrap().as_secs();
            let record = SignedPqCellProviderRecordV2::sign(
                PqCellProviderStatementV2 {
                    pinned_request: expected_request.encode().try_into().unwrap(),
                    endpoint: endpoint_bytes(cell_endpoint),
                    sequence: 12,
                    issued_unix_seconds: now.saturating_sub(1),
                    expires_unix_seconds: now + 90,
                },
                &signer,
            )
            .unwrap();
            let signed_bytes = record.to_wire();
            let packet = reply(&[&signed_bytes]);
            let shutdown_cell = Arc::new(AtomicBool::new(false));
            let cell_stop = shutdown_cell.clone();
            let source_name = source_path.clone();
            let cell_thread = thread::spawn(move || {
                let owner = CellStoreV1::open(&source_name, config()).unwrap();
                serve_cells(&cell_listener, &owner, &cell_stop, limits(64)).unwrap()
            });

            let shutdown_bootstrap = Arc::new(AtomicBool::new(false));
            let bootstrap_stop = shutdown_bootstrap.clone();
            let server_key = trusted_key.clone();
            let server_policy = addresses.clone();
            let rendezvous_thread = thread::spawn(move || {
                let approved = [PqPinnedProviderV2 {
                    signer_key_id: key_id,
                    trusted_ml_dsa65_public_key: &server_key,
                    external_sequence_floor: 11,
                }];
                serve_pq_cell_rendezvous_v2(
                    &bootstrap_listener,
                    expected_request,
                    &packet,
                    &approved,
                    &server_policy,
                    &bootstrap_stop,
                    CellRendezvousLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        lifetime: Duration::from_secs(10),
                        max_connections: 4,
                    },
                )
                .unwrap()
            });

            let consumer_path = dir.path().join("pq-consumer.sqlite");
            let consumer = CellStoreV1::open(&consumer_path, config()).unwrap();
            let output = dir.path().join("pq-complete-model");
            let options = CellDiscoveryOptionsV1 {
                request: expected_request,
                bootstraps: vec![bootstrap],
                addresses: addresses.clone(),
            };
            let current = [PqPinnedProviderV2 {
                signer_key_id: key_id,
                trusted_ml_dsa65_public_key: &trusted_key,
                external_sequence_floor: 11,
            }];
            // An absent external PQ roster MUST fail before opening even a
            // TCP connection. This listener intentionally has no responder:
            // before the fix, the request times out instead of failing on
            // independently pinned authority, consuming the caller budget.
            let silent_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let silent_bootstrap = silent_listener.local_addr().unwrap();
            let silent_policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
                ports: vec![silent_bootstrap.port()],
            };
            let silent_options = CellDiscoveryOptionsV1 {
                request: expected_request,
                bootstraps: vec![silent_bootstrap],
                addresses: silent_policy.clone(),
            };
            assert!(matches!(
                query_pq_provider_from_bootstrap_v2(
                    silent_bootstrap,
                    expected_request,
                    &[],
                    &silent_policy,
                    limits(64),
                    Instant::now() + Duration::from_secs(10),
                ),
                Err(CellErrorV1::Invalid("PQ bounded independent roster"))
            ));
            assert!(matches!(
                fetch_pq_discovered_cell_to_file_v2(
                    &consumer,
                    &silent_options,
                    &[],
                    limits(64),
                    Instant::now() + Duration::from_secs(10),
                    &output,
                ),
                Err(CellErrorV1::Invalid("PQ bounded independent roster"))
            ));
            assert!(!output.exists());

            // Even a nonempty caller roster is unusable if its independently
            // pinned key is malformed, its key-ID does not match that key, or
            // an identity is duplicated. Refuse these before dialing the
            // silent bootstrap; an error from TCP timeout is NOT acceptable.
            let wrong_id = [PqPinnedProviderV2 {
                signer_key_id: [0; 32],
                trusted_ml_dsa65_public_key: &trusted_key,
                external_sequence_floor: 11,
            }];
            let short_key = [9u8; 7];
            let wrong_length = [PqPinnedProviderV2 {
                signer_key_id: key_id,
                trusted_ml_dsa65_public_key: &short_key,
                external_sequence_floor: 11,
            }];
            let duplicated = [
                PqPinnedProviderV2 {
                    signer_key_id: key_id,
                    trusted_ml_dsa65_public_key: &trusted_key,
                    external_sequence_floor: 11,
                },
                PqPinnedProviderV2 {
                    signer_key_id: key_id,
                    trusted_ml_dsa65_public_key: &trusted_key,
                    external_sequence_floor: 11,
                },
            ];
            for (roster, expected_error) in [
                (&wrong_id[..], "PQ duplicate/mismatched pinned owner"),
                (&wrong_length[..], "PQ pinned public key"),
                (&duplicated[..], "PQ duplicate/mismatched pinned owner"),
            ] {
                assert!(matches!(
                    query_pq_provider_from_bootstrap_v2(
                        silent_bootstrap,
                        expected_request,
                        roster,
                        &silent_policy,
                        limits(64),
                        Instant::now() + Duration::from_secs(10),
                    ),
                    Err(CellErrorV1::Invalid(reason)) if reason == expected_error
                ));
                assert!(matches!(
                    fetch_pq_discovered_cell_to_file_v2(
                        &consumer,
                        &silent_options,
                        roster,
                        limits(64),
                        Instant::now() + Duration::from_secs(10),
                        &output,
                    ),
                    Err(CellErrorV1::Invalid(reason)) if reason == expected_error
                ));
                assert!(!output.exists());
            }

            // One permitted connection is consumed by PCQ2. A second Cell
            // request MUST fail; accidentally composing two independent
            // sessions would instead reset the allowance and succeed.
            assert!(fetch_pq_discovered_cell_to_file_v2(
                &consumer,
                &options,
                &current,
                limits(1),
                Instant::now() + Duration::from_secs(10),
                &output,
            )
            .is_err());
            assert!(!output.exists());

            let stale = [PqPinnedProviderV2 {
                signer_key_id: key_id,
                trusted_ml_dsa65_public_key: &trusted_key,
                external_sequence_floor: 12,
            }];
            assert!(fetch_pq_discovered_cell_to_file_v2(
                &consumer,
                &options,
                &stale,
                limits(64),
                Instant::now() + Duration::from_secs(10),
                &output,
            )
            .is_err());
            assert!(!output.exists());

            let (completed, observation) = fetch_pq_discovered_cell_to_file_v2(
                &consumer,
                &options,
                &current,
                limits(64),
                Instant::now() + Duration::from_secs(10),
                &output,
            )
            .unwrap();
            assert_eq!(completed, manifest);
            assert_eq!(fs::read(&output).unwrap(), bytes);
            assert!(!observation.manifest_initial_cache_hit);
            assert_eq!(observation.discovery.connection_attempts, 1);
            assert_eq!(observation.discovery.record_validation_attempts, 1);
            assert!(observation.fetch.connection_attempts > 1);
            assert_eq!(observation.fetch.downloaded_bytes, bytes.len() as u64);
            assert_eq!(observation.verified_providers.len(), 1);
            assert_eq!(observation.verified_providers[0].sequence(), 12);
            assert!(
                observation.fetch.received_response_bytes
                    > observation.discovery.received_response_bytes
            );

            // A verified Cell can finish the non-preemptible directory sync
            // after the original deadline. The last mandatory time check is
            // BEFORE the hard link, not after publishing the terminal file.
            // The original code returned Err("...deadline") here despite the
            // complete output already being visible, a false failure.
            let late_output = dir.path().join("pq-complete-after-link");
            let observed = Rc::new(Cell::new(false));
            let signal = observed.clone();
            let hook_output = late_output.clone();
            let hook_bytes = bytes.clone();
            let original_deadline = Instant::now() + Duration::from_secs(3);
            let (late_manifest, late_report) = crate::cell::tests::with_post_publication_hook(
                Box::new(move |deadline| {
                    assert_eq!(deadline, Some(original_deadline));
                    assert_eq!(fs::read(&hook_output).unwrap(), hook_bytes);
                    signal.set(true);
                    let remaining = original_deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining + Duration::from_millis(5));
                    assert!(Instant::now() > original_deadline);
                }),
                || {
                    fetch_pq_discovered_cell_to_file_v2(
                        &consumer,
                        &options,
                        &current,
                        limits(64),
                        original_deadline,
                        &late_output,
                    )
                },
            )
            .unwrap();
            assert!(observed.get(), "the post-link deadline case was not executed");
            assert_eq!(late_manifest, manifest);
            assert_eq!(fs::read(&late_output).unwrap(), bytes);
            assert_eq!(late_report.verified_providers[0].sequence(), 12);
            assert_eq!(late_report.discovery.record_validation_attempts, 1);

            shutdown_bootstrap.store(true, Ordering::Relaxed);
            shutdown_cell.store(true, Ordering::Relaxed);
            assert!(rendezvous_thread.join().unwrap().connections >= 4);
            assert!(cell_thread.join().unwrap() > 0);
        }
    }
}
