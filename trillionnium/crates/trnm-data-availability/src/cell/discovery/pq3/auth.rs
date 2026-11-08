//! Bootstrap response authority is separately pinned by the caller. A valid
//! response binds the exact original request, nonce, endpoint and complete result.
//! It authenticates a key, not an independently operated or available service.
use super::*;
use std::io::Read;

pub(super) const QUERY_HEADER_BYTES: usize = 9;
pub(super) const RESPONSE_HEADER_BYTES: usize = 11;
pub(super) const QUERY_PREFIX_BYTES: usize = 91;
pub(super) const RESPONSE_PREFIX_BYTES: usize = 88;
pub(super) const RESPONSE_OVERHEAD: usize =
    RESPONSE_HEADER_BYTES + RESPONSE_PREFIX_BYTES + ML_DSA_65_SIGNATURE_BYTES;
pub(super) const MAX_REPLY_BYTES: usize =
    1 + MAX_DISCOVERED_PROVIDERS * CELL_PROVIDER_RECORD_BYTES_V3;
const RESPONSE_TTL_SECONDS: u64 = 30;
const RESPONSE_DOMAIN: &[u8] = b"TRNM/Cell/Bootstrap/ML-DSA-65/v3\0";

/// The complete source identity comes from host policy, never from its reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CellBootstrapPinV3 {
    pub endpoint: SocketAddr,
    pub key_id: CellDigestV1,
    pub generation: u64,
}
impl CellBootstrapPinV3 {
    pub(super) fn validate(&self) -> CellResultV1<()> {
        require(canonical_endpoint(self.endpoint), "PQ bootstrap endpoint")?;
        require(
            self.key_id != [0; 32] && self.generation > 0,
            "PQ bootstrap identity",
        )
    }
}

/// A local native signer and its independently configured public authority.
/// Secret material is never received in queries or emitted in observations.
pub struct CellBootstrapSignerV3 {
    pin: CellBootstrapPinV3,
    key: PqNativeSigningKey,
    keys: CellPqKeyPinsV2,
}
impl CellBootstrapSignerV3 {
    pub fn new(
        pin: CellBootstrapPinV3,
        key: PqNativeSigningKey,
        keys: CellPqKeyPinsV2,
    ) -> CellResultV1<Self> {
        pin.validate()?;
        require(
            pin.key_id == key.public_key_id(),
            "PQ bootstrap signing key",
        )?;
        let authority = keys
            .pins()
            .find(|item| item.key_id == pin.key_id)
            .ok_or(CellErrorV1::Invalid("PQ bootstrap unknown key"))?;
        require(
            authority.generation == pin.generation && &authority.spki == key.public_spki(),
            "PQ bootstrap signing authority",
        )?;
        authority.live_at(wall_now()?.as_secs())?;
        Ok(Self { pin, key, keys })
    }
    pub fn identity(&self) -> CellBootstrapPinV3 {
        self.pin
    }
    pub(super) fn sign_response(
        &self,
        query: &BootstrapQueryV3,
        status: u8,
        body: &[u8],
        now: u64,
    ) -> CellResultV1<Vec<u8>> {
        require(query.pin == self.pin, "PQ bootstrap request target")?;
        response_shape(query.kind, status, body)?;
        let authority = self
            .keys
            .pins()
            .find(|item| item.key_id == self.pin.key_id)
            .ok_or(CellErrorV1::Invalid("PQ bootstrap unknown key"))?;
        authority.live_at(now)?;
        let expires = now
            .checked_add(RESPONSE_TTL_SECONDS)
            .ok_or(CellErrorV1::Invalid("PQ bootstrap response clock"))?
            .min(authority.expires_at)
            .min(authority.revoked_at.unwrap_or(u64::MAX));
        require(expires > now, "PQ bootstrap response expiry")?;
        let length = RESPONSE_OVERHEAD - RESPONSE_HEADER_BYTES + body.len();
        let mut unsigned = vec![b'C', b'D', b'S', b'3', 3, 0x65, status];
        unsigned.extend((length as u32).to_be_bytes());
        unsigned.extend(query.nonce);
        unsigned.extend(self.pin.key_id);
        unsigned.extend(self.pin.generation.to_be_bytes());
        unsigned.extend(now.to_be_bytes());
        unsigned.extend(expires.to_be_bytes());
        unsigned.extend(body);
        let signature = self
            .key
            .sign_exact_message(&response_message(&query.encode(), &unsigned))
            .map_err(|_| CellErrorV1::Invalid("PQ bootstrap signing"))?;
        unsigned.extend(signature);
        Ok(unsigned)
    }
}

pub(super) struct BootstrapQueryV3 {
    pub kind: u8,
    pub pin: CellBootstrapPinV3,
    pub nonce: [u8; 32],
    pub body: Vec<u8>,
}
impl BootstrapQueryV3 {
    pub fn fresh(kind: u8, pin: CellBootstrapPinV3, body: &[u8]) -> CellResultV1<Self> {
        let nonce = fresh_nonce()?;
        let value = Self {
            kind,
            pin,
            nonce,
            body: body.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> CellResultV1<()> {
        self.pin.validate()?;
        require(self.nonce != [0; 32], "PQ bootstrap nonce")?;
        query_body_length(self.kind, self.body.len())?;
        // Complete context validation precedes signing or accepting a reply.
        if self.kind == 1 {
            CellDiscoveryRequestV1::decode(&self.body)?;
        } else {
            CellProviderRecordV3::decode(&self.body)?;
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![b'C', b'D', b'Q', b'3', 3, 0x65, self.kind];
        out.extend(((QUERY_PREFIX_BYTES + self.body.len()) as u16).to_be_bytes());
        out.extend(self.pin.key_id);
        out.extend(self.pin.generation.to_be_bytes());
        out.extend(endpoint_bytes(self.pin.endpoint));
        out.extend(self.nonce);
        out.extend(&self.body);
        out
    }
    pub fn decode(wire: &[u8]) -> CellResultV1<Self> {
        require(
            wire.len() >= QUERY_HEADER_BYTES,
            "PQ bootstrap request header",
        )?;
        let length = query_length(&wire[..QUERY_HEADER_BYTES])?;
        require(
            wire.len() == QUERY_HEADER_BYTES + length,
            "PQ bootstrap request length",
        )?;
        let mut input = PqInput(&wire[QUERY_HEADER_BYTES..]);
        let key_id = input.take()?;
        let generation = u64::from_be_bytes(input.take()?);
        let endpoint = decode_endpoint(input.take()?)?;
        let nonce = input.take()?;
        let value = Self {
            kind: wire[6],
            pin: CellBootstrapPinV3 {
                endpoint,
                key_id,
                generation,
            },
            nonce,
            body: wire[QUERY_HEADER_BYTES + QUERY_PREFIX_BYTES..].to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}

pub(super) fn query_length(header: &[u8]) -> CellResultV1<usize> {
    require(
        header.len() == QUERY_HEADER_BYTES && header[..6] == [b'C', b'D', b'Q', b'3', 3, 0x65],
        "PQ bootstrap request version/algorithm",
    )?;
    let length = usize::from(u16::from_be_bytes([header[7], header[8]]));
    let body = length
        .checked_sub(QUERY_PREFIX_BYTES)
        .ok_or(CellErrorV1::Invalid("PQ bootstrap request bound"))?;
    query_body_length(header[6], body)?;
    Ok(length)
}
fn query_body_length(kind: u8, length: usize) -> CellResultV1<()> {
    require(
        (kind == 1 && length == 192) || (kind == 2 && length == CELL_PROVIDER_RECORD_BYTES_V3),
        "PQ bootstrap request bound",
    )
}

/// No portable entropy fallback: unsupported OS entropy fails before connecting.
fn fresh_nonce() -> CellResultV1<[u8; 32]> {
    #[cfg(unix)]
    {
        let mut nonce = [0; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        require(nonce != [0; 32], "PQ bootstrap entropy")?;
        Ok(nonce)
    }
    #[cfg(not(unix))]
    {
        Err(CellErrorV1::Invalid("PQ bootstrap OS entropy unavailable"))
    }
}

fn response_shape(kind: u8, status: u8, body: &[u8]) -> CellResultV1<()> {
    if status == 0 && kind == 1 {
        require(
            !body.is_empty()
                && usize::from(body[0]) <= MAX_DISCOVERED_PROVIDERS
                && body.len() == 1 + usize::from(body[0]) * CELL_PROVIDER_RECORD_BYTES_V3,
            "PQ bootstrap lookup body",
        )
    } else {
        require(
            (status == 0 && kind == 2 && body.len() == 32)
                || ((status == 1 || status == 2) && body.is_empty()),
            "PQ bootstrap response status/body",
        )
    }
}
fn response_message(query: &[u8], response: &[u8]) -> Vec<u8> {
    let mut out = RESPONSE_DOMAIN.to_vec();
    out.extend((query.len() as u32).to_be_bytes());
    out.extend(query);
    out.extend((response.len() as u32).to_be_bytes());
    out.extend(response);
    out
}

pub(super) struct VerifiedBootstrapReplyV3 {
    pub status: u8,
    pub body: Vec<u8>,
    pub expires_unix_seconds: u64,
}

/// Parse only the fixed header before bounded allocation. Status is interpreted
/// only after native signature verification of this complete frame.
pub(super) fn response_length(header: &[u8], maximum: usize) -> CellResultV1<usize> {
    require(
        header.len() == RESPONSE_HEADER_BYTES && header[..6] == [b'C', b'D', b'S', b'3', 3, 0x65],
        "PQ bootstrap response version/algorithm",
    )?;
    let length = u32::from_be_bytes(
        header[7..11]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("PQ bootstrap response length"))?,
    ) as usize;
    require(
        length >= RESPONSE_PREFIX_BYTES + ML_DSA_65_SIGNATURE_BYTES
            && length <= RESPONSE_PREFIX_BYTES + ML_DSA_65_SIGNATURE_BYTES + maximum
            && length <= RESPONSE_PREFIX_BYTES + ML_DSA_65_SIGNATURE_BYTES + MAX_REPLY_BYTES,
        "PQ bootstrap response bound",
    )?;
    Ok(length)
}

pub(super) fn verify_response(
    query: &BootstrapQueryV3,
    wire: &[u8],
    maximum: usize,
    now: u64,
    keys: &CellPqKeyPinsV2,
) -> CellResultV1<VerifiedBootstrapReplyV3> {
    require(
        wire.len() >= RESPONSE_HEADER_BYTES,
        "PQ bootstrap response header",
    )?;
    let length = response_length(&wire[..RESPONSE_HEADER_BYTES], maximum)?;
    require(
        wire.len() == RESPONSE_HEADER_BYTES + length,
        "PQ bootstrap response length",
    )?;
    let unsigned_end = wire.len() - ML_DSA_65_SIGNATURE_BYTES;
    let mut input = PqInput(&wire[RESPONSE_HEADER_BYTES..]);
    let nonce: [u8; 32] = input.take()?;
    let key_id = input.take()?;
    let generation = u64::from_be_bytes(input.take()?);
    let issued = u64::from_be_bytes(input.take()?);
    let expires = u64::from_be_bytes(input.take()?);
    require(
        nonce == query.nonce && key_id == query.pin.key_id && generation == query.pin.generation,
        "PQ bootstrap response origin/nonce",
    )?;
    require(
        issued <= now.saturating_add(FUTURE_SKEW_SECONDS)
            && issued < expires
            && expires > now
            && expires.saturating_sub(issued) <= RESPONSE_TTL_SECONDS,
        "PQ bootstrap response lifetime",
    )?;
    let key_expiry = keys.verify(
        key_id,
        generation,
        now,
        &response_message(&query.encode(), &wire[..unsigned_end]),
        &wire[unsigned_end..],
    )?;
    let body = &wire[RESPONSE_HEADER_BYTES + RESPONSE_PREFIX_BYTES..unsigned_end];
    response_shape(query.kind, wire[6], body)?;
    Ok(VerifiedBootstrapReplyV3 {
        status: wire[6],
        body: body.to_vec(),
        expires_unix_seconds: expires.min(key_expiry),
    })
}
