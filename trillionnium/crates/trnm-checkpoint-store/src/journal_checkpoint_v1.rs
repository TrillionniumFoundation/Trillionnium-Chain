//! Full-journal recovery pins. This is a separate export format, never the
//! sibling V2 crash-recovery head and never evidence of its own freshness.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::ExternalCheckpointAuthorityErrorV2;

const MAGIC_V1: &[u8; 8] = b"TRNMCPX1";
const DOMAIN_V1: &[u8] = b"trnm.external-node-checkpoint.journal-export.v1\0";
const BODY_BYTES_V1: usize = 8 + 1 + 3 + 8 + 32;
pub const EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1: usize = BODY_BYTES_V1 + 32;

// A separate read-only protocol leaves the existing V2 CAS wire unchanged.
pub(crate) const REQUEST_V1: &[u8; 8] = b"CJ1R\x01\x01\0\0";
const RESPONSE_V1: &[u8; 8] = b"CJ1S\x01\x01\0\0";

/// Read-only checkpoint of every scope in an append-only V2 journal.
///
/// The private fields prevent confusing a per-scope generation with the full
/// journal count. Canonical decoding checks shape and integrity, not freshness
/// or provenance. The recovery authority must retain this exact value outside
/// the failure domain of the journal and its sibling head. Rolling all copies
/// back together cannot be detected by this component.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExternalJournalCheckpointV1 {
    record_count: u64,
    root: [u8; 32],
}

impl ExternalJournalCheckpointV1 {
    pub(crate) const fn from_verified_journal(record_count: u64, root: [u8; 32]) -> Self {
        Self { record_count, root }
    }

    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    pub const fn root(self) -> [u8; 32] {
        self.root
    }

    pub fn encode_canonical(self) -> [u8; EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1] {
        let mut bytes = [0; EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC_V1);
        bytes[8] = 1;
        bytes[12..20].copy_from_slice(&self.record_count.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.root);
        let checksum = checksum_v1(&bytes[..BODY_BYTES_V1]);
        bytes[BODY_BYTES_V1..].copy_from_slice(&checksum);
        bytes
    }

    pub fn decode_canonical_exact(
        bytes: &[u8],
    ) -> Result<Self, ExternalCheckpointAuthorityErrorV2> {
        if bytes.len() != EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1
            || &bytes[..8] != MAGIC_V1
            || bytes[8] != 1
            || bytes[9..12] != [0; 3]
            || bytes[BODY_BYTES_V1..] != checksum_v1(&bytes[..BODY_BYTES_V1])
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "external journal checkpoint encoding",
            ));
        }
        let record_count = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed count"));
        let root: [u8; 32] = bytes[20..52].try_into().expect("fixed root");
        if (record_count == 0) != (root == [0; 32]) {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "external journal checkpoint empty shape",
            ));
        }
        Ok(Self { record_count, root })
    }
}

fn checksum_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V1);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Read an explicitly supplied recovery pin. This never reads the journal's
/// sibling head or derives an expected value from the state being recovered.
/// The caller is responsible for independently retained, authenticated input.
pub fn read_external_journal_checkpoint_v1(
    path: impl AsRef<Path>,
) -> Result<ExternalJournalCheckpointV1, ExternalCheckpointAuthorityErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "open external journal checkpoint",
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "stat external journal checkpoint",
            source,
        })?;
    if !metadata.is_file() || metadata.len() != EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1 as u64 {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "external journal checkpoint file length or type",
        ));
    }
    let mut bytes = Vec::with_capacity(EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1 + 1);
    file.take((EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1 + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "read external journal checkpoint",
            source,
        })?;
    ExternalJournalCheckpointV1::decode_canonical_exact(&bytes)
}

/// Export a pin to a new file chosen by the external recovery custodian.
/// Never overwrites an older pin. A successful local file write does not
/// establish independent fault-domain retention or make the pin fresh later.
pub fn write_new_external_journal_checkpoint_v1(
    path: impl AsRef<Path>,
    checkpoint: ExternalJournalCheckpointV1,
) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
    let path = path.as_ref();
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
            "external journal checkpoint export path must be absolute",
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "create external journal checkpoint export",
            source,
        })?;
    file.write_all(&checkpoint.encode_canonical())
        .and_then(|()| file.sync_all())
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "persist external journal checkpoint export",
            source,
        })?;
    File::open(path.parent().expect("absolute export path has a parent"))
        .and_then(|parent| parent.sync_all())
        .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
            stage: "sync external journal checkpoint export directory",
            source,
        })
}

pub(crate) fn encode_response_v1(checkpoint: ExternalJournalCheckpointV1) -> Vec<u8> {
    let mut response = RESPONSE_V1.to_vec();
    response.extend(checkpoint.encode_canonical());
    response
}

pub(crate) fn decode_response_v1(
    bytes: &[u8],
) -> Result<ExternalJournalCheckpointV1, ExternalCheckpointAuthorityErrorV2> {
    if bytes.len() != RESPONSE_V1.len() + EXTERNAL_JOURNAL_CHECKPOINT_BYTES_V1
        || &bytes[..RESPONSE_V1.len()] != RESPONSE_V1
    {
        return Err(ExternalCheckpointAuthorityErrorV2::Protocol(
            "external journal checkpoint response",
        ));
    }
    ExternalJournalCheckpointV1::decode_canonical_exact(&bytes[RESPONSE_V1.len()..])
}
