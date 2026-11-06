//! Content-addressed proof records. The external typed frontier commits the index.
use super::execution_wire::{Claim, Installation, LaunchAttempt, MAX_LAUNCH_RECORDS};
use super::files::Files;
use super::frontier::{hash, invalid, Digest32, Result, MAX_INDEX_BYTES};
use super::proof_wire::ObservedPublication;
use serde::{Deserialize, Serialize};

// Preserve the kernel's 100,000-package and 100,000-build-input bounds. The
// binary launch profile has a separate 512-MiB executable limit.
pub(super) const MAX_RECORD_BYTES: usize = 512 * 1024 * 1024;
pub(super) const MAX_RECORDS: usize =
    trnm_release_bundle::pq_release::MAX_RECOVERY_EVENTS_V1 + 3 * MAX_LAUNCH_RECORDS;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "record", deny_unknown_fields)]
pub(super) enum Record {
    Publication(ObservedPublication),
    Installation(Installation),
    LaunchAttempt(Box<LaunchAttempt>),
    Claim(Claim),
}

impl Record {
    pub fn observed_at(&self) -> u64 {
        match self {
            Self::Publication(v) => v.observed_at,
            Self::Installation(v) => v.observed_at,
            Self::LaunchAttempt(v) => v.observed_at,
            Self::Claim(v) => v.observed_at,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        super::codec::encode(self, MAX_RECORD_BYTES)
    }

    pub fn digest(&self) -> Result<Digest32> {
        Ok(hash(b"TRNM/M15/OwnerProofRecord/v1\0", &self.encode()?))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Index {
    pub schema_version: u32,
    pub namespace: Digest32,
    pub trust_configuration_sha256: Digest32,
    pub initial_root_file_sha256: Digest32,
    pub initial_root_digest: Digest32,
    pub initialized_at: u64,
    pub records: Vec<Digest32>,
    pub kernel_checkpoint: Digest32,
    pub time_floor: u64,
}

impl Index {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.records.len() > MAX_RECORDS {
            return Err(invalid("M15 retained history full"));
        }
        super::codec::encode(self, MAX_INDEX_BYTES)
    }
}

fn name(digest: Digest32) -> Result<String> {
    if digest == [0; 32] {
        return Err(invalid("zero M15 record digest"));
    }
    Ok(format!("proof-{}.json", hex::encode(digest)))
}

pub(super) fn read(files: &Files, digest: Digest32) -> Result<Record> {
    let raw = files
        .read(&name(digest)?, MAX_RECORD_BYTES)?
        .ok_or_else(|| invalid("missing retained M15 proof record"))?;
    if hash(b"TRNM/M15/OwnerProofRecord/v1\0", &raw) != digest {
        return Err(invalid(
            "M15 proof record bytes differ from the protected index",
        ));
    }
    super::codec::decode(&raw, MAX_RECORD_BYTES)
}

pub(super) fn put(files: &Files, record: &Record) -> Result<Digest32> {
    let raw = record.encode()?;
    let digest = hash(b"TRNM/M15/OwnerProofRecord/v1\0", &raw);
    files.put_immutable(&name(digest)?, &raw)?;
    Ok(digest)
}
