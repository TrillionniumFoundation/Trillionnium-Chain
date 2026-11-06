//! Independent M15 clock/frontier protocol; no PNQ2/Node checkpoint projection.
use super::frontier::{hash, invalid, Digest32, Frontier, Result, Validity};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

pub(super) const MAX_FRAME: usize = 65536;
pub(super) const REQUEST: &[u8] = b"TRNM/M15/ProtectedOwner/Request/v1\0";
pub(super) const CLOCK_REPLY: &[u8] = b"TRNM/M15/ProtectedClock/Reply/v1\0";
pub(super) const FRONTIER_REPLY: &[u8] = b"TRNM/M15/ProtectedFrontier/Reply/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Operation {
    Clock,
    Load,
    CompareAndSet,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub schema_version: u32,
    pub operation: Operation,
    pub binding: Digest32,
    pub namespace: Digest32,
    pub challenge: Digest32,
    pub expected: Option<Frontier>,
    pub next: Option<Frontier>,
    pub validity: Option<Validity>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub schema_version: u32,
    pub request: Digest32,
    pub challenge: Digest32,
    pub operation: Operation,
    pub namespace: Digest32,
    pub now_seconds: u64,
    pub accepted: bool,
    pub frontier: Option<Frontier>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signed<T> {
    pub body: T,
    pub signature: Vec<u8>,
}

pub(super) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(io::Error::other)?;
    if raw.is_empty() || raw.len() > MAX_FRAME {
        return Err(invalid("M15 signed frame bound"));
    }
    Ok(raw)
}

pub(super) fn decode<T: Serialize + DeserializeOwned>(raw: &[u8]) -> Result<T> {
    if raw.is_empty() || raw.len() > MAX_FRAME {
        return Err(invalid("M15 signed frame bound"));
    }
    let value = serde_json::from_slice(raw).map_err(io::Error::other)?;
    if canonical(&value)? != raw {
        return Err(invalid("M15 signed frame is not canonical"));
    }
    Ok(value)
}

pub(super) fn message<T: Serialize>(domain: &[u8], body: &T) -> Result<Vec<u8>> {
    let raw = canonical(body)?;
    let mut result = domain.to_vec();
    result.extend_from_slice(&(raw.len() as u64).to_be_bytes());
    result.extend_from_slice(&raw);
    Ok(result)
}

pub(super) fn sign<T: Serialize>(
    domain: &[u8],
    body: T,
    key: &PqNativeSigningKey,
) -> Result<Vec<u8>> {
    let signature = key
        .sign_exact_message(&message(domain, &body)?)
        .map_err(io::Error::other)?
        .to_vec();
    canonical(&Signed { body, signature })
}

pub(super) fn verify<T: Serialize + DeserializeOwned>(
    domain: &[u8],
    raw: &[u8],
    key: &PqNativeVerifier,
) -> Result<T> {
    let value: Signed<T> = decode(raw)?;
    key.verify_exact_message(&message(domain, &value.body)?, &value.signature)
        .map_err(io::Error::other)?;
    Ok(value.body)
}

pub(super) fn request_digest(raw: &[u8]) -> Digest32 {
    hash(b"TRNM/M15/ProtectedOwner/ExactRequest/v1\0", raw)
}
