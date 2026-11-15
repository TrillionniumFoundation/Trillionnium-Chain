use super::frontier::{invalid, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::io;

pub(super) fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("M15 canonical object bound"));
    }
    Ok(bytes)
}

pub(super) fn decode<T: Serialize + DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("M15 canonical object bound"));
    }
    let value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if encode(&value, maximum)? != bytes {
        return Err(invalid("M15 noncanonical object"));
    }
    Ok(value)
}
