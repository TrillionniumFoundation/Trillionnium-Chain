//! Authentication selected by the independently pinned continuous-owner identity.
//! The journal, allocations, CPU debt and recovery remain their original owners.
use crate::operator_task_policy::PolicyError;
use serde::Serialize;
use trnm_crypto_primitives::{pq_auth::PqNativeVerifier, verify_hex_strict};
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES,
};

type Result<T> = std::result::Result<T, PolicyError>;
pub(crate) const PQ_IDENTITY: &str = "restricted-continuous-identity-pq-v3";
pub(crate) const PQ_MODE: &str = "restricted-owner-node-pq-v6";
/// One view, at most 32 allocations, a budget and a recovery authorization.
/// This is a count bound, not a measured CPU-duration claim.
pub(crate) const MAX_OWNER_SIGNATURES: u16 = 70;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    ClassicalV2,
    PqV3,
}
impl Profile {
    pub(crate) fn from_identity_schema(schema: &str) -> Result<Self> {
        match schema {
            "restricted-continuous-identity-v2" => Ok(Self::ClassicalV2),
            PQ_IDENTITY => Ok(Self::PqV3),
            _ => Err(PolicyError::Input),
        }
    }
    pub(crate) fn schema<'a>(self, classic: &'a str, pq: &'a str) -> &'a str {
        match self {
            Self::ClassicalV2 => classic,
            Self::PqV3 => pq,
        }
    }
    pub(crate) fn validate_key(self, key: &str) -> Result<()> {
        match self {
            Self::ClassicalV2 => {
                exact_lower_hex(key, 32)?;
            }
            Self::PqV3 => {
                let raw = exact_lower_hex(key, ML_DSA_65_SPKI_BYTES)?;
                ml_dsa_65_key_id_from_spki(&raw).map_err(|_| PolicyError::Signature)?;
            }
        }
        Ok(())
    }
    pub(crate) fn message<T: Serialize>(
        self,
        classic_domain: &[u8],
        pq_domain: &[u8],
        body: &T,
        role: u8,
    ) -> Result<Vec<u8>> {
        let raw = serde_json::to_vec(body).map_err(|_| PolicyError::Input)?;
        let domain = match self {
            Self::ClassicalV2 => classic_domain,
            Self::PqV3 => pq_domain,
        };
        let size = domain
            .len()
            .checked_add(5)
            .and_then(|n| n.checked_add(raw.len()));
        let bounded = match self {
            Self::ClassicalV2 => raw.len() <= 65_536 && size.is_some(),
            Self::PqV3 => size.is_some_and(|n| n <= 65_536),
        };
        if !bounded {
            return Err(PolicyError::Capacity);
        }
        let mut out = Vec::with_capacity(size.ok_or(PolicyError::Capacity)?);
        out.extend_from_slice(domain);
        out.push(role);
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&raw);
        Ok(out)
    }
    pub(crate) fn verify(
        self,
        pinned_key: &str,
        message: &[u8],
        signature: &str,
        budget: &mut SignatureBudget,
    ) -> Result<()> {
        // Reserve before signature parsing/key expansion, including every failure.
        budget.reserve()?;
        match self {
            Self::ClassicalV2 => verify_hex_strict(pinned_key, message, signature)
                .map_err(|_| PolicyError::Signature),
            Self::PqV3 => {
                let key = exact_lower_hex(pinned_key, ML_DSA_65_SPKI_BYTES)?;
                let signature = exact_lower_hex(signature, ML_DSA_65_SIGNATURE_BYTES)?;
                let id = ml_dsa_65_key_id_from_spki(&key).map_err(|_| PolicyError::Signature)?;
                PqNativeVerifier::from_pinned_spki(&key, id)
                    .map_err(|_| PolicyError::Signature)?
                    .verify_exact_message(message, &signature)
                    .map_err(|_| PolicyError::Signature)?;
                Ok(())
            }
        }
    }
}

fn exact_lower_hex(value: &str, bytes: usize) -> Result<Vec<u8>> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PolicyError::Signature);
    }
    hex::decode(value).map_err(|_| PolicyError::Signature)
}

pub(crate) struct SignatureBudget {
    remaining: u16,
}
impl SignatureBudget {
    pub(crate) fn batch() -> Self {
        Self {
            remaining: MAX_OWNER_SIGNATURES,
        }
    }
    pub(crate) fn pair() -> Self {
        Self { remaining: 2 }
    }
    fn reserve(&mut self) -> Result<()> {
        self.remaining = self.remaining.checked_sub(1).ok_or(PolicyError::Capacity)?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "operator_pq_auth_tests.rs"]
mod tests;
