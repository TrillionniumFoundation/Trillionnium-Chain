use std::{fmt, io};

/// Maximum accepted Unix-frame payload.  Lease requests are intentionally
/// tiny; this bound prevents a peer or a local client from turning the
/// authority socket into an unbounded allocation surface.
pub const MAX_FRAME_BYTES_V1: usize = 16 * 1024;

/// Wire schema version for the external peer-lease authority.
pub const PEER_LEASE_SCHEMA_V1: u8 = 1;

const FRAME_MAGIC_V1: [u8; 4] = *b"TPLS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolErrorV1 {
    ZeroIdentity,
    SelfPeer,
    ZeroSession,
    ZeroGeneration,
    ZeroRecordHash,
}

impl fmt::Display for ProtocolErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroIdentity => "lease identity is zero",
            Self::SelfPeer => "lease local and remote identities are equal",
            Self::ZeroSession => "lease session is zero",
            Self::ZeroGeneration => "lease generation is zero",
            Self::ZeroRecordHash => "lease record hash is zero",
        })
    }
}

impl std::error::Error for ProtocolErrorV1 {}

/// Direction of a peer lease. Direction is explicit rather than inferred
/// from local/remote IDs so independently commissioned channels cannot alias
/// the same durable key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PeerLeaseDirectionV1 {
    Outbound = 1,
    Inbound = 2,
}

impl PeerLeaseDirectionV1 {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Outbound),
            2 => Some(Self::Inbound),
            _ => None,
        }
    }
}

/// The identity/context a lease is fencing.  The validator-set digest is
/// deliberately carried alongside the epoch: an epoch number by itself is
/// not sufficient to prevent a stale committee from reconnecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerLeaseScopeV1 {
    local_id: [u8; 32],
    remote_id: [u8; 32],
    direction: PeerLeaseDirectionV1,
    epoch: u64,
    validator_set_id: [u8; 32],
}

impl PeerLeaseScopeV1 {
    pub fn new(
        local_id: [u8; 32],
        remote_id: [u8; 32],
        direction: PeerLeaseDirectionV1,
        epoch: u64,
        validator_set_id: [u8; 32],
    ) -> Result<Self, ProtocolErrorV1> {
        if local_id == [0; 32] || remote_id == [0; 32] || validator_set_id == [0; 32] {
            return Err(ProtocolErrorV1::ZeroIdentity);
        }
        if local_id == remote_id {
            return Err(ProtocolErrorV1::SelfPeer);
        }
        Ok(Self {
            local_id,
            remote_id,
            direction,
            epoch,
            validator_set_id,
        })
    }

    pub const fn local_id(self) -> [u8; 32] {
        self.local_id
    }

    pub const fn remote_id(self) -> [u8; 32] {
        self.remote_id
    }

    pub const fn direction(self) -> PeerLeaseDirectionV1 {
        self.direction
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }
}

/// Opaque authority token.  A token is bound to every scope field, session,
/// generation and expiry.  A renewed lease returns a new token; callers must
/// not keep using an older token after renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLeaseTokenV1 {
    scope: PeerLeaseScopeV1,
    session_id: [u8; 32],
    generation: u64,
    expires_at_ms: u64,
    record_hash: [u8; 32],
}

impl PeerLeaseTokenV1 {
    pub(crate) const fn new(
        scope: PeerLeaseScopeV1,
        session_id: [u8; 32],
        generation: u64,
        expires_at_ms: u64,
        record_hash: [u8; 32],
    ) -> Self {
        Self {
            scope,
            session_id,
            generation,
            expires_at_ms,
            record_hash,
        }
    }

    /// Reconstruct a token received from an adapter or persisted transport
    /// state. Possession of a reconstructed token grants no authority until
    /// the daemon accepts `revalidate`.
    pub fn from_parts(
        scope: PeerLeaseScopeV1,
        session_id: [u8; 32],
        generation: u64,
        expires_at_ms: u64,
        record_hash: [u8; 32],
    ) -> Result<Self, ProtocolErrorV1> {
        if session_id == [0; 32] {
            return Err(ProtocolErrorV1::ZeroSession);
        }
        if generation == 0 {
            return Err(ProtocolErrorV1::ZeroGeneration);
        }
        if record_hash == [0; 32] {
            return Err(ProtocolErrorV1::ZeroRecordHash);
        }
        Ok(Self::new(
            scope,
            session_id,
            generation,
            expires_at_ms,
            record_hash,
        ))
    }

    pub const fn scope(self) -> PeerLeaseScopeV1 {
        self.scope
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn expires_at_ms(self) -> u64 {
        self.expires_at_ms
    }

    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRejectCodeV1 {
    InvalidRequest = 1,
    AlreadyLeased = 2,
    StaleGeneration = 3,
    LeaseNotFound = 4,
    LeaseExpired = 5,
    Fenced = 6,
    ContextMismatch = 7,
    AuthorityUnavailable = 8,
    ClockRollback = 9,
    AuthorityCorrupt = 10,
    Unsupported = 11,
    UnauthorizedPeer = 12,
}

impl LeaseRejectCodeV1 {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::InvalidRequest,
            2 => Self::AlreadyLeased,
            3 => Self::StaleGeneration,
            4 => Self::LeaseNotFound,
            5 => Self::LeaseExpired,
            6 => Self::Fenced,
            7 => Self::ContextMismatch,
            8 => Self::AuthorityUnavailable,
            9 => Self::ClockRollback,
            10 => Self::AuthorityCorrupt,
            11 => Self::Unsupported,
            12 => Self::UnauthorizedPeer,
            _ => return None,
        })
    }
}

impl fmt::Display for LeaseRejectCodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid lease request",
            Self::AlreadyLeased => "peer already has a live lease",
            Self::StaleGeneration => "lease generation is stale",
            Self::LeaseNotFound => "lease is not present",
            Self::LeaseExpired => "lease expired",
            Self::Fenced => "lease was fenced by a newer generation",
            Self::ContextMismatch => "lease context mismatch",
            Self::AuthorityUnavailable => "lease authority unavailable",
            Self::ClockRollback => "authority clock moved backwards",
            Self::AuthorityCorrupt => "authority journal is corrupt",
            Self::Unsupported => "operation is unsupported",
            Self::UnauthorizedPeer => "peer credentials are not authorized",
        })
    }
}

/// Errors shared by the durable store and the Unix client.
#[derive(Debug)]
pub enum PeerLeaseErrorV1 {
    InvalidRequest(&'static str),
    Io(io::Error),
    Protocol(&'static str),
    Rejected(LeaseRejectCodeV1),
}

impl fmt::Display for PeerLeaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Protocol(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "peer lease I/O error: {error}"),
            Self::Rejected(code) => code.fmt(formatter),
        }
    }
}

impl std::error::Error for PeerLeaseErrorV1 {}

impl From<io::Error> for PeerLeaseErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseOperationV1 {
    Acquire,
    Renew,
    Revalidate,
    Release,
}

impl LeaseOperationV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Acquire => 1,
            Self::Renew => 2,
            Self::Revalidate => 3,
            Self::Release => 4,
        }
    }

    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Acquire,
            2 => Self::Renew,
            3 => Self::Revalidate,
            4 => Self::Release,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeaseRequestV1 {
    pub operation: LeaseOperationV1,
    pub scope: PeerLeaseScopeV1,
    pub session_id: [u8; 32],
    pub generation: u64,
    pub expires_at_ms: u64,
    pub ttl_ms: u64,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseResponseV1 {
    Token(PeerLeaseTokenV1),
    Rejected(LeaseRejectCodeV1),
}

pub(crate) fn encode_request(request: LeaseRequestV1) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 32 + 32 + 8 + 32 + 32 + 8 * 3 + 32);
    body.push(PEER_LEASE_SCHEMA_V1);
    body.push(request.operation.tag());
    encode_scope(&mut body, request.scope);
    body.extend_from_slice(&request.session_id);
    put_u64(&mut body, request.generation);
    put_u64(&mut body, request.expires_at_ms);
    put_u64(&mut body, request.ttl_ms);
    body.extend_from_slice(&request.record_hash);
    frame(body)
}

pub(crate) fn decode_request(frame_bytes: &[u8]) -> Result<LeaseRequestV1, PeerLeaseErrorV1> {
    let body = unframe(frame_bytes)?;
    let mut cursor = Cursor::new(body);
    let version = cursor.take_u8()?;
    if version != PEER_LEASE_SCHEMA_V1 {
        return Err(PeerLeaseErrorV1::Protocol("unsupported peer-lease schema"));
    }
    let operation = LeaseOperationV1::from_tag(cursor.take_u8()?)
        .ok_or(PeerLeaseErrorV1::Protocol("unknown lease operation"))?;
    let scope = decode_scope(&mut cursor)?;
    let session_id = cursor.take_array()?;
    let generation = cursor.take_u64()?;
    let expires_at_ms = cursor.take_u64()?;
    let ttl_ms = cursor.take_u64()?;
    let record_hash = cursor.take_array()?;
    cursor.finish()?;
    Ok(LeaseRequestV1 {
        operation,
        scope,
        session_id,
        generation,
        expires_at_ms,
        ttl_ms,
        record_hash,
    })
}

pub(crate) fn encode_response(response: LeaseResponseV1) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 32 * 4 + 8 * 2);
    body.push(PEER_LEASE_SCHEMA_V1);
    match response {
        LeaseResponseV1::Token(token) => {
            body.push(0);
            encode_token(&mut body, token);
        }
        LeaseResponseV1::Rejected(code) => {
            body.push(1);
            body.push(code as u8);
        }
    }
    frame(body)
}

pub(crate) fn decode_response(frame_bytes: &[u8]) -> Result<LeaseResponseV1, PeerLeaseErrorV1> {
    let body = unframe(frame_bytes)?;
    let mut cursor = Cursor::new(body);
    let version = cursor.take_u8()?;
    if version != PEER_LEASE_SCHEMA_V1 {
        return Err(PeerLeaseErrorV1::Protocol(
            "unsupported peer-lease response schema",
        ));
    }
    match cursor.take_u8()? {
        0 => {
            let token = decode_token(&mut cursor)?;
            cursor.finish()?;
            Ok(LeaseResponseV1::Token(token))
        }
        1 => {
            let code = LeaseRejectCodeV1::from_u8(cursor.take_u8()?)
                .ok_or(PeerLeaseErrorV1::Protocol("unknown lease rejection code"))?;
            cursor.finish()?;
            Ok(LeaseResponseV1::Rejected(code))
        }
        _ => Err(PeerLeaseErrorV1::Protocol(
            "unknown peer-lease response kind",
        )),
    }
}

fn encode_token(output: &mut Vec<u8>, token: PeerLeaseTokenV1) {
    encode_scope(output, token.scope);
    output.extend_from_slice(&token.session_id);
    put_u64(output, token.generation);
    put_u64(output, token.expires_at_ms);
    output.extend_from_slice(&token.record_hash);
}

fn decode_token(cursor: &mut Cursor<'_>) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
    Ok(PeerLeaseTokenV1::new(
        decode_scope(cursor)?,
        cursor.take_array()?,
        cursor.take_u64()?,
        cursor.take_u64()?,
        cursor.take_array()?,
    ))
}

fn encode_scope(output: &mut Vec<u8>, scope: PeerLeaseScopeV1) {
    output.extend_from_slice(&scope.local_id);
    output.extend_from_slice(&scope.remote_id);
    output.push(scope.direction as u8);
    put_u64(output, scope.epoch);
    output.extend_from_slice(&scope.validator_set_id);
}

fn decode_scope(cursor: &mut Cursor<'_>) -> Result<PeerLeaseScopeV1, PeerLeaseErrorV1> {
    PeerLeaseScopeV1::new(
        cursor.take_array()?,
        cursor.take_array()?,
        PeerLeaseDirectionV1::from_u8(cursor.take_u8()?)
            .ok_or(PeerLeaseErrorV1::InvalidRequest("invalid lease direction"))?,
        cursor.take_u64()?,
        cursor.take_array()?,
    )
    .map_err(|_| PeerLeaseErrorV1::InvalidRequest("invalid lease scope"))
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn frame(body: Vec<u8>) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 + body.len());
    output.extend_from_slice(&FRAME_MAGIC_V1);
    output.extend_from_slice(&(body.len() as u32).to_le_bytes());
    output.extend_from_slice(&body);
    output
}

fn unframe(frame_bytes: &[u8]) -> Result<&[u8], PeerLeaseErrorV1> {
    if frame_bytes.len() < 8 || frame_bytes[..4] != FRAME_MAGIC_V1 {
        return Err(PeerLeaseErrorV1::Protocol("invalid peer-lease frame"));
    }
    let body_len = u32::from_le_bytes(frame_bytes[4..8].try_into().unwrap()) as usize;
    if body_len > MAX_FRAME_BYTES_V1 || frame_bytes.len() != body_len + 8 {
        return Err(PeerLeaseErrorV1::Protocol(
            "peer-lease frame length mismatch",
        ));
    }
    Ok(&frame_bytes[8..])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PeerLeaseErrorV1> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PeerLeaseErrorV1::Protocol("peer-lease cursor overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PeerLeaseErrorV1::Protocol("truncated peer-lease frame"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn take_u8(&mut self) -> Result<u8, PeerLeaseErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn take_u64(&mut self) -> Result<u64, PeerLeaseErrorV1> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn take_array(&mut self) -> Result<[u8; 32], PeerLeaseErrorV1> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn finish(self) -> Result<(), PeerLeaseErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PeerLeaseErrorV1::Protocol(
                "trailing peer-lease frame bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> PeerLeaseScopeV1 {
        PeerLeaseScopeV1::new([1; 32], [2; 32], PeerLeaseDirectionV1::Outbound, 7, [3; 32]).unwrap()
    }

    #[test]
    fn request_and_response_round_trip_are_exact() {
        let request = LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope: scope(),
            session_id: [4; 32],
            generation: 8,
            expires_at_ms: 0,
            ttl_ms: 10_000,
            record_hash: [0; 32],
        };
        let encoded = encode_request(request);
        assert_eq!(decode_request(&encoded).unwrap(), request);

        let token = PeerLeaseTokenV1::new(scope(), [4; 32], 8, 10_007, [5; 32]);
        let response = encode_response(LeaseResponseV1::Token(token));
        assert_eq!(
            decode_response(&response).unwrap(),
            LeaseResponseV1::Token(token)
        );
    }

    #[test]
    fn malformed_and_partial_frames_fail_closed() {
        assert!(decode_request(&[0; 8]).is_err());
        let request = LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope: scope(),
            session_id: [4; 32],
            generation: 0,
            expires_at_ms: 0,
            ttl_ms: 1_000,
            record_hash: [0; 32],
        };
        let mut encoded = encode_request(request);
        encoded.pop();
        assert!(decode_request(&encoded).is_err());
    }

    #[test]
    fn unauthorized_peer_rejection_round_trips() {
        let response = encode_response(LeaseResponseV1::Rejected(
            LeaseRejectCodeV1::UnauthorizedPeer,
        ));
        assert_eq!(
            decode_response(&response).unwrap(),
            LeaseResponseV1::Rejected(LeaseRejectCodeV1::UnauthorizedPeer)
        );
    }
}
