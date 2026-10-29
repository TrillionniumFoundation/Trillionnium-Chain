//! Native ML-DSA-65 location hints in a fresh wire and durable namespace.
//! The externally pinned authority roster is immutable for this namespace.
//! A hint grants neither custody nor installation/FinalUse authority.
use super::{
    canonical_endpoint, cell_discovery_context_digest, check_deadline, decode_endpoint,
    endpoint_bytes, ip_bytes, wall_now, CellDiscoveryAddressPolicyV1, CellDiscoveryContextV1,
    CellDiscoveryRequestV1, FUTURE_SKEW_SECONDS, MAX_DISCOVERED_PROVIDERS,
    MAX_DISCOVERY_BOOTSTRAPS, MAX_DISCOVERY_CONNECTIONS, MAX_DISCOVERY_RECORDS, MAX_TTL_SECONDS,
};
use crate::cell::{
    pq::{CellPqKeyPinsV2, PqInput},
    require, CellDigestV1, CellErrorV1, CellResultV1,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

mod directory;
mod transport;
pub use directory::{CellProviderDirectoryUsageV2, CellProviderDirectoryV2};
pub use transport::{
    announce_cell_provider_pq, fetch_discovered_cell_to_file_pq, serve_cell_rendezvous_pq,
    CellDiscoveryFetchReportV2, CellDiscoveryObservationV2, CellDiscoveryOptionsV2,
    CellRendezvousLimitsV2, CellRendezvousReportV2,
};

pub const CELL_DISCOVERY_PROFILE_V2: &str = "cell-provider-discovery-pq-v2";
pub const CELL_PROVIDER_RECORD_BYTES_V2: usize = 283 + ML_DSA_65_SIGNATURE_BYTES;
/// All replies, including rejected and truncated ones, consume this allowance.
pub const MAX_DISCOVERY_RESPONSE_BYTES_V2: u64 = 256 * 1024;
const SIGN_DOMAIN: &[u8] = b"TRNM/Cell/Provider/ML-DSA-65/v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderStatementV2 {
    pub request: CellDiscoveryRequestV1,
    pub owner: CellDigestV1,
    pub owner_generation: u64,
    pub endpoint: SocketAddr,
    pub sequence: u64,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
    pub withdrawn: bool,
}
#[derive(Clone, Debug)]
pub struct CellProviderRecordV2 {
    statement: CellProviderStatementV2,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
// ML-DSA signatures may be randomized. Two valid signatures of one statement
// are the same authorization; their different bytes are not equivocation.
// This equality is used only AFTER the network has verified each signature.
impl PartialEq for CellProviderRecordV2 {
    fn eq(&self, other: &Self) -> bool {
        self.statement == other.statement
    }
}
impl Eq for CellProviderRecordV2 {}
impl CellProviderRecordV2 {
    pub fn sign(
        statement: CellProviderStatementV2,
        key: &PqNativeSigningKey,
    ) -> CellResultV1<Self> {
        require(
            statement.owner == key.public_key_id(),
            "PQ discovery signing owner",
        )?;
        let mut record = Self {
            statement,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        record.shape()?;
        record.signature = key
            .sign_exact_message(&record.message())
            .map_err(|_| CellErrorV1::Invalid("PQ discovery signing"))?;
        Ok(record)
    }
    pub fn statement(&self) -> &CellProviderStatementV2 {
        &self.statement
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut out = vec![
            b'C',
            b'D',
            b'P',
            b'2',
            2,
            0x65,
            u8::from(self.statement.withdrawn),
            0,
        ];
        out.extend(self.statement.request.encode());
        out.extend(self.statement.owner);
        out.extend(self.statement.owner_generation.to_be_bytes());
        out.extend(endpoint_bytes(self.statement.endpoint));
        out.extend(self.statement.sequence.to_be_bytes());
        out.extend(self.statement.issued_unix_seconds.to_be_bytes());
        out.extend(self.statement.expires_unix_seconds.to_be_bytes());
        out
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.unsigned();
        out.extend(self.signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PROVIDER_RECORD_BYTES_V2,
            "PQ discovery record length",
        )?;
        require(
            bytes[..6] == [b'C', b'D', b'P', b'2', 2, 0x65] && bytes[6] <= 1 && bytes[7] == 0,
            "PQ discovery version/algorithm",
        )?;
        let mut input = PqInput(&bytes[8..]);
        let request = CellDiscoveryRequestV1::decode(&input.take::<192>()?)?;
        let owner = input.take()?;
        let owner_generation = u64::from_be_bytes(input.take()?);
        let endpoint = decode_endpoint(input.take()?)?;
        let record = Self {
            statement: CellProviderStatementV2 {
                request,
                owner,
                owner_generation,
                endpoint,
                sequence: u64::from_be_bytes(input.take()?),
                issued_unix_seconds: u64::from_be_bytes(input.take()?),
                expires_unix_seconds: u64::from_be_bytes(input.take()?),
                withdrawn: bytes[6] == 1,
            },
            signature: input.take()?,
        };
        record.shape()?;
        require(record.encode() == bytes, "PQ discovery canonical record")?;
        Ok(record)
    }
    fn message(&self) -> Vec<u8> {
        let mut out = SIGN_DOMAIN.to_vec();
        out.extend(self.unsigned());
        out
    }
    fn digest(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/Provider/Statement/v2\0");
        hash.update(self.unsigned());
        hash.finalize().into()
    }
    fn shape(&self) -> CellResultV1<()> {
        let s = &self.statement;
        s.request.validate()?;
        require(
            s.owner != [0; 32]
                && s.owner_generation > 0
                && s.sequence > 0
                && s.endpoint.port() != 0
                && canonical_endpoint(s.endpoint),
            "discovery sequence/endpoint",
        )?;
        require(
            s.expires_unix_seconds
                .checked_sub(s.issued_unix_seconds)
                .is_some_and(|ttl| (1..=MAX_TTL_SECONDS).contains(&ttl)),
            "discovery TTL",
        )
    }
    /// Returns the earlier signature/authority expiry. The caller reserves one
    /// validation slot before invoking this method; no classic verifier exists.
    pub fn verify_at(
        &self,
        expected: CellDiscoveryRequestV1,
        now: u64,
        policy: &CellDiscoveryAddressPolicyV1,
        keys: &CellPqKeyPinsV2,
    ) -> CellResultV1<u64> {
        self.shape()?;
        require(
            self.statement.request == expected,
            "discovery pinned context",
        )?;
        self.live_at(now)?;
        policy.check(self.statement.endpoint)?;
        let key_expiry = keys.verify(
            self.statement.owner,
            self.statement.owner_generation,
            now,
            &self.message(),
            &self.signature,
        )?;
        Ok(key_expiry.min(self.statement.expires_unix_seconds))
    }
    fn live_at(&self, now: u64) -> CellResultV1<()> {
        require(
            self.statement.issued_unix_seconds <= now.saturating_add(FUTURE_SKEW_SECONDS)
                && now < self.statement.expires_unix_seconds,
            "discovery expired/future record",
        )
    }
}

#[cfg(test)]
mod tests;
