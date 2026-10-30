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
            assert!(evaluate(&reply(&[&wire; 9])).is_err());
            assert!(evaluate(&[]).is_err());
            assert_eq!(1 + 8 * PQ_CELL_PROVIDER_RECORD_V2_BYTES, 28641);
            assert!(
                1 + 8 * PQ_CELL_PROVIDER_RECORD_V2_BYTES <= MAX_DISCOVERY_RESPONSE_BYTES as usize
            );
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
    }
}
