use borsh::BorshSerialize;
use sha2::{Digest, Sha256};

use crate::{
    error::{error, CrossPlaneReadbackErrorCodeV1, CrossPlaneReadbackResultV1},
    types::Hash32V1,
};

pub(crate) fn canonical_bytes<T: BorshSerialize>(value: &T) -> CrossPlaneReadbackResultV1<Vec<u8>> {
    borsh::to_vec(value).map_err(|cause| {
        error(
            CrossPlaneReadbackErrorCodeV1::NonCanonical,
            cause.to_string(),
        )
    })
}

pub(crate) fn digest_value<T: BorshSerialize>(
    domain: &str,
    value: &T,
) -> CrossPlaneReadbackResultV1<Hash32V1> {
    if domain.is_empty() || !domain.is_ascii() {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::InvalidBounds,
            "digest domain must be nonempty ASCII",
        ));
    }
    let encoded = canonical_bytes(value)?;
    let domain_len = u32::try_from(domain.len()).map_err(|_| {
        error(
            CrossPlaneReadbackErrorCodeV1::ArithmeticOverflow,
            "digest domain exceeds u32",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(encoded);
    Ok(Hash32V1(hasher.finalize().into()))
}
