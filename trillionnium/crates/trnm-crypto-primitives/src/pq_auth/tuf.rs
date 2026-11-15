//! Narrow TAP 21 v1 adapter for the existing ML-DSA-65 primitive.
//!
//! The caller supplies the parsed `signed` value and scheme from its trusted
//! TUF metadata. This adapter reconstructs the OLPC canonical representation,
//! hashes it with SHA-512, and uses pure ML-DSA with an empty context over
//! `b"tuf\x01" || digest`. It never accepts a caller-provided digest or prefix.
//! It does not implement a TUF client, threshold roles, root rotation, freshness,
//! or activation. The caller must reject duplicate JSON fields when parsing.
//! This bounded project profile accepts i64/u64 JSON integers and ML-DSA-65 only;
//! it is not the complete three-parameter-set TAP 21 implementation.

use super::{PqNativeError, PqNativeSigningKey, PqNativeVerifier};
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::fmt;
use trnm_protocol::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

pub const TUF_ML_DSA_65_V1_SCHEME: &str = "ml-dsa-65/1";
pub const TUF_MAX_CANONICAL_BYTES_V1: usize = 1_048_576;
pub const TUF_MAX_DEPTH_V1: usize = 64;
pub const TUF_MAX_VALUES_V1: usize = 65_536;

#[derive(Debug)]
pub enum TufMldsa65ErrorV1 {
    Scheme,
    MetadataObject,
    Integer,
    Limit,
    Crypto(PqNativeError),
}
impl fmt::Display for TufMldsa65ErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => f.write_str("trusted TUF scheme must be exactly ml-dsa-65/1"),
            Self::MetadataObject => f.write_str("TUF signed metadata must be an object"),
            Self::Integer => f.write_str("TUF canonical JSON permits only i64/u64 integers here"),
            Self::Limit => f.write_str("TUF canonical metadata resource limit exceeded"),
            Self::Crypto(error) => write!(f, "TUF ML-DSA-65 verification/signing: {error}"),
        }
    }
}
impl std::error::Error for TufMldsa65ErrorV1 {}
impl From<PqNativeError> for TufMldsa65ErrorV1 {
    fn from(value: PqNativeError) -> Self {
        Self::Crypto(value)
    }
}

struct CanonicalHash {
    hash: Sha512,
    bytes: usize,
    values: usize,
}
impl CanonicalHash {
    fn append(&mut self, bytes: &[u8]) -> Result<(), TufMldsa65ErrorV1> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(TufMldsa65ErrorV1::Limit)?;
        if self.bytes > TUF_MAX_CANONICAL_BYTES_V1 {
            return Err(TufMldsa65ErrorV1::Limit);
        }
        self.hash.update(bytes);
        Ok(())
    }
    fn string(&mut self, value: &str) -> Result<(), TufMldsa65ErrorV1> {
        if value.len() > TUF_MAX_CANONICAL_BYTES_V1.saturating_sub(self.bytes) {
            return Err(TufMldsa65ErrorV1::Limit);
        }
        self.append(b"\"")?;
        // OLPC canonical JSON escapes only quote and backslash, including when
        // the parsed string contains a control character or non-ASCII UTF-8.
        let mut start = 0;
        for (index, byte) in value.bytes().enumerate() {
            if byte == b'"' || byte == b'\\' {
                self.append(&value.as_bytes()[start..index])?;
                self.append(b"\\")?;
                self.append(&[byte])?;
                start = index + 1;
            }
        }
        self.append(&value.as_bytes()[start..])?;
        self.append(b"\"")
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), TufMldsa65ErrorV1> {
        self.values += 1;
        if depth > TUF_MAX_DEPTH_V1 || self.values > TUF_MAX_VALUES_V1 {
            return Err(TufMldsa65ErrorV1::Limit);
        }
        match value {
            Value::Null => self.append(b"null"),
            Value::Bool(true) => self.append(b"true"),
            Value::Bool(false) => self.append(b"false"),
            Value::Number(number) => {
                if !number.is_i64() && !number.is_u64() {
                    return Err(TufMldsa65ErrorV1::Integer);
                }
                self.append(number.to_string().as_bytes())
            }
            Value::String(value) => self.string(value),
            Value::Array(values) => {
                if values.len() > TUF_MAX_VALUES_V1.saturating_sub(self.values) {
                    return Err(TufMldsa65ErrorV1::Limit);
                }
                self.append(b"[")?;
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        self.append(b",")?;
                    }
                    self.value(value, depth + 1)?;
                }
                self.append(b"]")
            }
            Value::Object(values) => {
                if values.len() > TUF_MAX_VALUES_V1.saturating_sub(self.values) {
                    return Err(TufMldsa65ErrorV1::Limit);
                }
                // Explicit ordering keeps the format stable if another crate
                // enables serde_json's preserve_order feature in the workspace.
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                self.append(b"{")?;
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        self.append(b",")?;
                    }
                    self.string(key)?;
                    self.append(b":")?;
                    self.value(&values[key], depth + 1)?;
                }
                self.append(b"}")
            }
        }
    }
}

fn presigning_message(trusted_scheme: &str, signed: &Value) -> Result<[u8; 68], TufMldsa65ErrorV1> {
    if trusted_scheme != TUF_ML_DSA_65_V1_SCHEME {
        return Err(TufMldsa65ErrorV1::Scheme);
    }
    if !signed.is_object() {
        return Err(TufMldsa65ErrorV1::MetadataObject);
    }
    let mut canonical = CanonicalHash {
        hash: Sha512::new(),
        bytes: 0,
        values: 0,
    };
    canonical.value(signed, 0)?;
    let mut message = [0; 68];
    message[..4].copy_from_slice(b"tuf\x01");
    message[4..].copy_from_slice(&canonical.hash.finalize());
    Ok(message)
}

/// A signature observation only. It carries no root, release or FinalUse role.
/// Only cryptographic verification can construct it.
pub struct VerifiedTufMetadataV1<'a> {
    signed: &'a Value,
    signer_key_id: [u8; 32],
}
impl<'a> VerifiedTufMetadataV1<'a> {
    pub fn signed_value(&self) -> &'a Value {
        self.signed
    }
    pub fn signer_key_id(&self) -> [u8; 32] {
        self.signer_key_id
    }
}

pub fn verify_tuf_mldsa65_v1<'a>(
    verifier: &PqNativeVerifier,
    trusted_scheme: &str,
    signed: &'a Value,
    signature: &[u8],
) -> Result<VerifiedTufMetadataV1<'a>, TufMldsa65ErrorV1> {
    let message = presigning_message(trusted_scheme, signed)?;
    verifier.verify_exact_message(&message, signature)?;
    Ok(VerifiedTufMetadataV1 {
        signed,
        signer_key_id: verifier.public_key_id(),
    })
}

pub fn sign_tuf_mldsa65_v1(
    key: &PqNativeSigningKey,
    trusted_scheme: &str,
    signed: &Value,
) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], TufMldsa65ErrorV1> {
    let message = presigning_message(trusted_scheme, signed)?;
    key.sign_exact_message(&message).map_err(Into::into)
}
