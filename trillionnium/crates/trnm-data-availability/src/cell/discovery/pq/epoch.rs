//! Explicit, signed epoch scope for finite replay retention. V1 and V2 records
//! cannot enter this profile, and a closed epoch cannot be reopened by a signer.
use super::*;

pub const CELL_DISCOVERY_PROFILE_V3: &str = "cell-provider-discovery-epoch-pq-v3";
pub const CELL_DISCOVERY_EPOCH_SECONDS_V3: u64 = 300;
pub const CELL_DISCOVERY_REQUEST_BYTES_V3: usize = 200;
pub const CELL_PROVIDER_RECORD_BYTES_V3: usize = 291 + ML_DSA_65_SIGNATURE_BYTES;
const SIGN_DOMAIN_V3: &[u8] = b"TRNM/Cell/Provider/Epoch/ML-DSA-65/v3\0";

/// A paired clock sample. Capturing the monotonic clock before the wall clock
/// makes the resulting lease conservative even if sampling is delayed. Passing
/// an older sample to verification cannot renew its original monotonic lease.
///
/// ```compile_fail
/// use trnm_data_availability::cell::discovery::pq::CellDiscoveryTimeV3;
/// let _ = CellDiscoveryTimeV3 {
///     wall: std::time::Duration::ZERO,
///     monotonic: std::time::Instant::now(),
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct CellDiscoveryTimeV3 {
    wall: std::time::Duration,
    monotonic: std::time::Instant,
}
impl CellDiscoveryTimeV3 {
    pub fn sample() -> CellResultV1<Self> {
        let monotonic = std::time::Instant::now();
        let wall = wall_now()?;
        Ok(Self { wall, monotonic })
    }
    pub fn unix_seconds(&self) -> u64 {
        self.wall.as_secs()
    }
    pub fn unix_time(&self) -> std::time::Duration {
        self.wall
    }
    pub fn monotonic(&self) -> std::time::Instant {
        self.monotonic
    }
    #[cfg(test)]
    pub(super) fn for_test(wall: std::time::Duration, monotonic: std::time::Instant) -> Self {
        Self { wall, monotonic }
    }
}

/// The epoch is an owner-signed sequence namespace, not a receiver-chosen cache
/// eviction generation. Sequence monotonicity is scoped to this exact request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellDiscoveryRequestV3 {
    pub base: CellDiscoveryRequestV1,
    pub epoch: u64,
}
impl CellDiscoveryRequestV3 {
    pub fn epoch_at(now: u64) -> u64 {
        now / CELL_DISCOVERY_EPOCH_SECONDS_V3
    }
    pub fn epoch_bounds(&self) -> CellResultV1<(u64, u64)> {
        let start = self
            .epoch
            .checked_mul(CELL_DISCOVERY_EPOCH_SECONDS_V3)
            .ok_or(CellErrorV1::Invalid("discovery epoch overflow"))?;
        let end = start
            .checked_add(CELL_DISCOVERY_EPOCH_SECONDS_V3)
            .ok_or(CellErrorV1::Invalid("discovery epoch overflow"))?;
        Ok((start, end))
    }
    pub(super) fn validate(&self) -> CellResultV1<()> {
        self.base.validate()?;
        self.epoch_bounds()?;
        Ok(())
    }
    pub fn validate_at(&self, now: u64) -> CellResultV1<()> {
        self.validate()?;
        require(
            self.epoch == Self::epoch_at(now),
            "discovery closed/future epoch",
        )
    }
    pub fn encode(&self) -> [u8; CELL_DISCOVERY_REQUEST_BYTES_V3] {
        let mut wire = [0; CELL_DISCOVERY_REQUEST_BYTES_V3];
        wire[..192].copy_from_slice(&self.base.encode());
        wire[192..].copy_from_slice(&self.epoch.to_be_bytes());
        wire
    }
    pub fn decode(wire: &[u8]) -> CellResultV1<Self> {
        require(
            wire.len() == CELL_DISCOVERY_REQUEST_BYTES_V3,
            "discovery epoch request length",
        )?;
        let mut input = PqInput(wire);
        let value = Self {
            base: CellDiscoveryRequestV1::decode(&input.take::<192>()?)?,
            epoch: u64::from_be_bytes(input.take()?),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellProviderStatementV3 {
    pub request: CellDiscoveryRequestV3,
    pub owner: CellDigestV1,
    pub owner_generation: u64,
    pub endpoint: SocketAddr,
    pub sequence: u64,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
    pub withdrawn: bool,
}
#[derive(Clone, Debug)]
pub struct CellProviderRecordV3 {
    statement: CellProviderStatementV3,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
// Equivalence is about the signed statement. Consumers must verify every
// incoming signature before using this comparison for replay/equivocation.
impl PartialEq for CellProviderRecordV3 {
    fn eq(&self, other: &Self) -> bool {
        self.statement == other.statement
    }
}
impl Eq for CellProviderRecordV3 {}

/// A receipt for one actual ML-DSA verification under one immutable authority
/// roster. It cannot be manufactured from a decoded wire or a claimed owner.
/// Its time and authority constraints must be rechecked at durable admission.
///
/// ```compile_fail
/// use trnm_data_availability::cell::discovery::pq::{
///     CellProviderRecordV3, CellVerifiedProviderRecordV3,
/// };
/// fn forge(record: CellProviderRecordV3) -> CellVerifiedProviderRecordV3 {
///     CellVerifiedProviderRecordV3 {
///         record,
///         verified_at: 0,
///         valid_until: u64::MAX,
///         authority: [1; 32],
///         monotonic_expiry: std::time::Instant::now() + std::time::Duration::from_secs(300),
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CellVerifiedProviderRecordV3 {
    record: CellProviderRecordV3,
    verified_at: u64,
    valid_until: u64,
    authority: CellDigestV1,
    monotonic_expiry: std::time::Instant,
}
impl CellVerifiedProviderRecordV3 {
    pub fn record(&self) -> &CellProviderRecordV3 {
        &self.record
    }
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn monotonic_expiry(&self) -> std::time::Instant {
        self.monotonic_expiry
    }
    pub(super) fn check_at(
        &self,
        now: u64,
        authority: CellDigestV1,
    ) -> CellResultV1<&CellProviderRecordV3> {
        check_deadline(self.monotonic_expiry)?;
        require(
            authority == self.authority,
            "discovery verification authority",
        )?;
        require(
            self.verified_at <= now && now < self.valid_until,
            "discovery verification expired/clock rollback",
        )?;
        self.record.live_at(now)?;
        Ok(&self.record)
    }
}

impl CellProviderRecordV3 {
    pub fn sign(
        statement: CellProviderStatementV3,
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
    pub fn statement(&self) -> &CellProviderStatementV3 {
        &self.statement
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut out = vec![
            b'C',
            b'D',
            b'P',
            b'3',
            3,
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
            bytes.len() == CELL_PROVIDER_RECORD_BYTES_V3,
            "PQ discovery epoch record length",
        )?;
        require(
            bytes[..6] == [b'C', b'D', b'P', b'3', 3, 0x65] && bytes[6] <= 1 && bytes[7] == 0,
            "PQ discovery epoch version/algorithm",
        )?;
        let mut input = PqInput(&bytes[8..]);
        let request =
            CellDiscoveryRequestV3::decode(&input.take::<CELL_DISCOVERY_REQUEST_BYTES_V3>()?)?;
        let owner = input.take()?;
        let owner_generation = u64::from_be_bytes(input.take()?);
        let endpoint = decode_endpoint(input.take()?)?;
        let record = Self {
            statement: CellProviderStatementV3 {
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
        require(
            record.encode() == bytes,
            "PQ discovery epoch canonical record",
        )?;
        Ok(record)
    }
    fn message(&self) -> Vec<u8> {
        let mut out = SIGN_DOMAIN_V3.to_vec();
        out.extend(self.unsigned());
        out
    }
    pub(super) fn digest(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/Provider/Epoch/Statement/v3\0");
        hash.update(self.unsigned());
        hash.finalize().into()
    }
    pub(super) fn shape(&self) -> CellResultV1<()> {
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
        let (start, end) = s.request.epoch_bounds()?;
        require(
            s.issued_unix_seconds >= start
                && s.expires_unix_seconds <= end
                && s.expires_unix_seconds
                    .checked_sub(s.issued_unix_seconds)
                    .is_some_and(|ttl| (1..=MAX_TTL_SECONDS).contains(&ttl)),
            "discovery epoch TTL",
        )
    }
    /// Verifies the signed fact at the paired observation time. A later-expired
    /// fact still participates in equivocation detection; this method does not
    /// renew its lease or assert current eligibility. The caller debits one
    /// shared verification slot, and durable admission rechecks the receipt.
    pub fn verify_at(
        &self,
        expected: CellDiscoveryRequestV3,
        time: CellDiscoveryTimeV3,
        policy: &CellDiscoveryAddressPolicyV1,
        keys: &CellPqKeyPinsV2,
    ) -> CellResultV1<CellVerifiedProviderRecordV3> {
        let now = time.unix_seconds();
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
        let valid_until = key_expiry.min(self.statement.expires_unix_seconds);
        let remaining = std::time::Duration::from_secs(valid_until)
            .checked_sub(time.unix_time())
            .ok_or(CellErrorV1::Invalid("discovery verification expiry"))?;
        let monotonic_expiry = time.monotonic() + remaining;
        Ok(CellVerifiedProviderRecordV3 {
            record: self.clone(),
            verified_at: now,
            valid_until,
            authority: keys.digest(),
            monotonic_expiry,
        })
    }
    pub(super) fn live_at(&self, now: u64) -> CellResultV1<()> {
        self.statement.request.validate_at(now)?;
        require(
            self.statement.issued_unix_seconds <= now.saturating_add(FUTURE_SKEW_SECONDS)
                && now < self.statement.expires_unix_seconds,
            "discovery expired/future record",
        )
    }
}

#[cfg(test)]
#[path = "epoch_tests.rs"]
mod tests;
