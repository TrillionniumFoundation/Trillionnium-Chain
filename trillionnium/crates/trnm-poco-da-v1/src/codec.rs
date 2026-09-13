use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{error, DaErrorCodeV1, DaResultV1},
    types::Hash32V1,
};

pub(crate) fn canonical_bytes<T: BorshSerialize>(value: &T) -> DaResultV1<Vec<u8>> {
    borsh::to_vec(value).map_err(|cause| error(DaErrorCodeV1::NonCanonical, cause.to_string()))
}

pub(crate) fn strict_decode<T>(bytes: &[u8]) -> DaResultV1<T>
where
    T: BorshDeserialize + BorshSerialize,
{
    let value = borsh::from_slice(bytes)
        .map_err(|cause| error(DaErrorCodeV1::NonCanonical, cause.to_string()))?;
    if canonical_bytes(&value)? != bytes {
        return Err(error(
            DaErrorCodeV1::NonCanonical,
            "candidate CEV1 bytes do not round-trip exactly",
        ));
    }
    Ok(value)
}

pub(crate) fn digest_value<T: BorshSerialize>(domain: &str, value: &T) -> DaResultV1<Hash32V1> {
    digest_encoded(domain, &canonical_bytes(value)?)
}

pub(crate) fn digest_bytes_value(domain: &str, bytes: &[u8]) -> DaResultV1<Hash32V1> {
    digest_value(domain, &bytes.to_vec())
}

pub(crate) fn digest_encoded(domain: &str, encoded: &[u8]) -> DaResultV1<Hash32V1> {
    if domain.is_empty() || !domain.is_ascii() {
        return Err(error(
            DaErrorCodeV1::InvalidBounds,
            "digest domain must be nonempty ASCII",
        ));
    }
    let domain_len = u32::try_from(domain.len()).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "digest domain exceeds u32",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(encoded);
    Ok(Hash32V1(hasher.finalize().into()))
}

pub(crate) fn checksum(parts: &[&[u8]]) -> Hash32V1 {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-ai.da-store-checksum.candidate.v1");
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    Hash32V1(hasher.finalize().into())
}
