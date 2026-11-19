//! Byte transport around the unchanged original private lease wire methods.
use std::io::{self, Read, Write};

#[path = "../../../trillionnium/crates/trnm-peer-lease/src/protocol.rs"]
mod protocol;
use protocol::*;

fn word(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn scope(raw: &[u8]) -> Option<PeerLeaseScopeV1> {
    PeerLeaseScopeV1::new(
        raw[..32].try_into().ok()?,
        raw[32..64].try_into().ok()?,
        PeerLeaseDirectionV1::from_u8(raw[64])?,
        word(raw, 65),
        raw[73..105].try_into().ok()?,
    )
    .ok()
}

fn scope_bytes(value: PeerLeaseScopeV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(value.local_id());
    out.extend(value.remote_id());
    out.push(value.direction() as u8);
    out.extend(value.epoch().to_le_bytes());
    out.extend(value.peer_scope_id());
    out
}

fn token_bytes(value: PeerLeaseTokenV1) -> Vec<u8> {
    let mut out = scope_bytes(value.scope());
    out.extend(value.session_id());
    out.extend(value.generation().to_le_bytes());
    out.extend(value.expires_at_ms().to_le_bytes());
    out.extend(value.record_hash());
    out
}

fn error(error: PeerLeaseErrorV1) -> u64 {
    match error {
        PeerLeaseErrorV1::Protocol("invalid peer-lease frame") => 1,
        PeerLeaseErrorV1::Protocol("peer-lease frame length mismatch") => 2,
        PeerLeaseErrorV1::Protocol("truncated peer-lease frame") => 3,
        PeerLeaseErrorV1::Protocol("unsupported peer-lease schema") => 4,
        PeerLeaseErrorV1::Protocol("unknown lease operation") => 5,
        PeerLeaseErrorV1::Protocol("trailing peer-lease frame bytes") => 6,
        PeerLeaseErrorV1::Protocol("unsupported peer-lease response schema") => 9,
        PeerLeaseErrorV1::Protocol("unknown peer-lease response kind") => 10,
        PeerLeaseErrorV1::InvalidRequest("invalid lease direction") => 11,
        PeerLeaseErrorV1::InvalidRequest("invalid lease scope") => 12,
        PeerLeaseErrorV1::Protocol("invalid peer-lease token") => 13,
        PeerLeaseErrorV1::Protocol("unknown lease rejection code") => 14,
        other => panic!("unmapped unchanged original error: {other:?}"),
    }
}

fn execute(raw: &[u8]) -> Result<Vec<u8>, u64> {
    if raw.len() < 8 {
        return Err(100);
    }
    let operation = word(raw, 0);
    let raw = &raw[8..];
    match operation {
        1 => {
            let request = decode_request(raw).map_err(error)?;
            let mut out = (request.operation.tag() as u64).to_le_bytes().to_vec();
            out.extend(scope_bytes(request.scope));
            out.extend(request.session_id);
            out.extend(request.generation.to_le_bytes());
            out.extend(request.expires_at_ms.to_le_bytes());
            out.extend(request.ttl_ms.to_le_bytes());
            out.extend(request.record_hash);
            Ok(out)
        }
        2 => {
            if raw.len() != 201 || !(1..=4).contains(&word(raw, 0)) {
                return Err(100);
            }
            Ok(encode_request(LeaseRequestV1 {
                operation: LeaseOperationV1::from_tag(word(raw, 0) as u8).unwrap(),
                scope: scope(&raw[8..113]).ok_or(100u64)?,
                session_id: raw[113..145].try_into().unwrap(),
                generation: word(raw, 145),
                expires_at_ms: word(raw, 153),
                ttl_ms: word(raw, 161),
                record_hash: raw[169..201].try_into().unwrap(),
            }))
        }
        3 => match decode_response(raw).map_err(error)? {
            LeaseResponseV1::Token(token) => {
                let mut out = 0u64.to_le_bytes().to_vec();
                out.extend(token_bytes(token));
                Ok(out)
            }
            LeaseResponseV1::Rejected(code) => {
                let mut out = 1u64.to_le_bytes().to_vec();
                out.extend((code as u64).to_le_bytes());
                Ok(out)
            }
        },
        4 => {
            if raw.len() < 8 {
                return Err(100);
            }
            match word(raw, 0) {
                0 if raw.len() == 193 => {
                    let token = &raw[8..];
                    // The original crate-private constructor is deliberately
                    // weaker than the public decoder/from_parts constructor.
                    let token = PeerLeaseTokenV1::new(
                        scope(&token[..105]).ok_or(100u64)?,
                        token[105..137].try_into().unwrap(),
                        word(token, 137),
                        word(token, 145),
                        token[153..185].try_into().unwrap(),
                    );
                    Ok(encode_response(LeaseResponseV1::Token(token)))
                }
                1 if raw.len() == 16 && (1..=12).contains(&word(raw, 8)) => {
                    let code = LeaseRejectCodeV1::from_u8(word(raw, 8) as u8).unwrap();
                    Ok(encode_response(LeaseResponseV1::Rejected(code)))
                }
                _ => Err(100),
            }
        }
        _ => Err(100),
    }
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut first = [0u8; 1];
        if input.read(&mut first)? == 0 {
            return Ok(());
        }
        let mut size = [0u8; 4];
        size[0] = first[0];
        input.read_exact(&mut size[1..])?;
        let size = u32::from_le_bytes(size) as usize;
        if size > 1 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "observer extent",
            ));
        }
        let mut raw = vec![0; size];
        input.read_exact(&mut raw)?;
        let (code, bytes) = match execute(&raw) {
            Ok(bytes) => (0u64, bytes),
            Err(code) => (code, Vec::new()),
        };
        output.write_all(&code.to_le_bytes())?;
        output.write_all(&(bytes.len() as u64).to_le_bytes())?;
        output.write_all(&bytes)?;
        output.flush()?;
    }
}
