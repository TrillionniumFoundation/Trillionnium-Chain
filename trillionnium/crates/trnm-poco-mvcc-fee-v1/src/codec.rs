use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{error, MvccFeeErrorCodeV1, MvccFeeResultV1},
    Hash32V1,
};

pub(crate) fn canonical_bytes<T: BorshSerialize>(value: &T) -> MvccFeeResultV1<Vec<u8>> {
    borsh::to_vec(value).map_err(|cause| error(MvccFeeErrorCodeV1::NonCanonical, cause.to_string()))
}

pub(crate) fn strict_decode<T>(bytes: &[u8]) -> MvccFeeResultV1<T>
where
    T: BorshDeserialize + BorshSerialize,
{
    let value = borsh::from_slice(bytes)
        .map_err(|cause| error(MvccFeeErrorCodeV1::NonCanonical, cause.to_string()))?;
    if canonical_bytes(&value)? != bytes {
        return Err(error(
            MvccFeeErrorCodeV1::NonCanonical,
            "bytes do not round-trip canonically",
        ));
    }
    Ok(value)
}

pub(crate) fn digest_value<T: BorshSerialize>(
    domain: &str,
    value: &T,
) -> MvccFeeResultV1<Hash32V1> {
    let bytes = canonical_bytes(value)?;
    digest_bytes(domain, &bytes)
}

pub(crate) fn digest_bytes(domain: &str, bytes: &[u8]) -> MvccFeeResultV1<Hash32V1> {
    if domain.is_empty() || !domain.is_ascii() {
        return Err(error(
            MvccFeeErrorCodeV1::InvalidBounds,
            "digest domain must be nonempty ASCII",
        ));
    }
    let len = u32::try_from(domain.len()).map_err(|_| {
        error(
            MvccFeeErrorCodeV1::ArithmeticOverflow,
            "domain length overflow",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(len.to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    Ok(Hash32V1(hasher.finalize().into()))
}

pub(crate) fn checksum(parts: &[&[u8]]) -> Hash32V1 {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-ai.mvcc-fee-store-checksum.candidate.v1");
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    Hash32V1(hasher.finalize().into())
}
