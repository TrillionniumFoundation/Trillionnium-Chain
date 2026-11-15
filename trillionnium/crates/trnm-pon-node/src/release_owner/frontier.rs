//! Independent M15 owner domain. These records are not Node/M03 checkpoints.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub(super) type Result<T> = io::Result<T>;
pub(super) type Digest32 = [u8; 32];
pub(super) const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PENDING_BYTES: usize = 6 * MAX_INDEX_BYTES + 65536;

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

pub(super) fn index_digest(bytes: &[u8]) -> Digest32 {
    hash(b"TRNM/M15/OwnerIndex/v1\0", bytes)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frontier {
    pub schema_version: u32,
    pub namespace: Digest32,
    pub generation: u64,
    pub previous: Digest32,
    pub index: Digest32,
}

impl Frontier {
    pub fn validate(&self, namespace: Digest32) -> Result<()> {
        if self.schema_version != 1
            || namespace == [0; 32]
            || self.namespace != namespace
            || self.generation == 0
            || self.index == [0; 32]
            || (self.generation == 1) != (self.previous == [0; 32])
        {
            return Err(invalid("invalid M15 owner frontier"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest32> {
        self.validate(self.namespace)?;
        let raw = serde_json::to_vec(self).map_err(io::Error::other)?;
        Ok(hash(b"TRNM/M15/OwnerFrontier/v1\0", &raw))
    }

    pub fn successor(namespace: Digest32, old: Option<&Self>, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_INDEX_BYTES {
            return Err(invalid("M15 owner index bound"));
        }
        let (generation, previous) = match old {
            Some(old) => {
                old.validate(namespace)?;
                (
                    old.generation
                        .checked_add(1)
                        .ok_or_else(|| invalid("M15 generation exhausted"))?,
                    old.digest()?,
                )
            }
            None => (1, [0; 32]),
        };
        let next = Self {
            schema_version: 1,
            namespace,
            generation,
            previous,
            index: index_digest(bytes),
        };
        next.validate(namespace)?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Validity {
    pub not_before: u64,
    pub expires_at: u64,
}

impl Validity {
    pub fn check(self, now: u64) -> Result<()> {
        if self.not_before >= self.expires_at || now < self.not_before || now >= self.expires_at {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "M15 decision outside its exact validity window",
            ));
        }
        Ok(())
    }
}

/// The production implementation authenticates each response with a fresh
/// challenge and independent pins. A timeout/CAS error is never non-execution.
/// CAS must enforce this exact window at its own trusted-time linearization.
// Crate-private trust seam. Ordinary CLI construction uses only the authenticated
// signed client; in-memory or caller-clock implementations belong to cfg(test).
// Implementing this trait is not itself production qualification.
pub(super) trait ExternalM15Authority {
    fn now_seconds(&mut self) -> Result<u64>;
    fn load(&mut self, namespace: Digest32) -> Result<Option<Frontier>>;
    fn compare_and_set(
        &mut self,
        expected: Option<&Frontier>,
        next: &Frontier,
        validity: Validity,
    ) -> Result<()>;
}
