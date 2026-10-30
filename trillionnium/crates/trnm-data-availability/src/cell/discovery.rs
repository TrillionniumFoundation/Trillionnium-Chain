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
mod pq_v2;
mod transport;
pub use directory::{CellProviderDirectoryUsageV1, CellProviderDirectoryV1};
pub use pq_v2::{
    fetch_pcp2_authenticated_cell_to_file, verify_pcp2_provider_hint_v2,
    PqCellProviderExpectationM09V2, VerifiedPqCellProviderHintM09V2,
};
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
