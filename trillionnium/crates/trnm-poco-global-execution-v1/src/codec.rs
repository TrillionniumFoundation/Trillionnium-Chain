use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{error, GlobalExecutionErrorCodeV1, GlobalExecutionResultV1},
    Hash32V1,
};

pub(crate) fn canonical_bytes<T: BorshSerialize>(value: &T) -> GlobalExecutionResultV1<Vec<u8>> {
    borsh::to_vec(value).map_err(|cause| {
        error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            cause.to_string(),
        )
    })
}

pub(crate) fn strict_decode<T>(bytes: &[u8]) -> GlobalExecutionResultV1<T>
where
    T: BorshDeserialize + BorshSerialize,
{
    let value = borsh::from_slice(bytes).map_err(|cause| {
        error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            cause.to_string(),
        )
    })?;
    if canonical_bytes(&value)? != bytes {
        return Err(error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            "candidate batch does not round-trip exactly",
        ));
    }
    Ok(value)
}

pub(crate) fn digest_value<T: BorshSerialize>(
    domain: &str,
    value: &T,
) -> GlobalExecutionResultV1<Hash32V1> {
    if domain.is_empty() || !domain.is_ascii() {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidBounds,
            "digest domain must be nonempty ASCII",
        ));
    }
    let domain_len = u32::try_from(domain.len()).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "digest domain exceeds u32",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(canonical_bytes(value)?);
    Ok(Hash32V1(hasher.finalize().into()))
}
