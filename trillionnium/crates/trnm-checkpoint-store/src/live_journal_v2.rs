//! Validate durable bytes before a cached checkpoint is used as an authority.
//!
//! Path identity alone does not detect truncation or an in-place rewrite of an
//! already-open file. The complete prefix is checked with one fixed-size record
//! buffer, against the root retained by this owner. This is O(journal records),
//! not a constant-time or production-throughput claim. Cold-start freshness still
//! comes from the independently supplied checkpoint; no disk field supplies it.

use std::{fs::Metadata, os::unix::fs::FileExt, os::unix::fs::MetadataExt};

use crate::{
    decode_anchor_v2, decode_log_record_v2, digest_record_v2, read_anchor_v2,
    ExternalCheckpointAuthorityErrorV2, ExternalCheckpointAuthorityV2, LOG_RECORD_BYTES_V2,
};

impl ExternalCheckpointAuthorityV2 {
    pub(crate) fn validate_live_journal_v2(
        &self,
    ) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        let expected_length = self
            .record_count
            .checked_mul(LOG_RECORD_BYTES_V2 as u64)
            .ok_or(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "live journal length overflow",
            ))?;
        let before =
            self.log
                .metadata()
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "stat live checkpoint journal",
                    source,
                })?;
        if before.len() != expected_length {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "live journal differs from retained checkpoint",
            ));
        }
        let mut previous_hash = [0; 32];
        let mut bytes = [0; LOG_RECORD_BYTES_V2];
        for index in 0..self.record_count {
            // Positional reads preserve the append descriptor's cursor. A
            // cloned File would share that cursor with the live writer.
            self.log
                .read_exact_at(&mut bytes, index * LOG_RECORD_BYTES_V2 as u64)
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "read live checkpoint journal",
                    source,
                })?;
            let record = decode_log_record_v2(&bytes)?;
            if record.sequence != index + 1
                || record.previous_hash != previous_hash
                || record.record_hash
                    != digest_record_v2(
                        record.sequence,
                        record.scope,
                        record.expected,
                        record.target,
                        record.previous_hash,
                    )
            {
                return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                    "live journal hash chain changed",
                ));
            }
            previous_hash = record.record_hash;
        }
        if previous_hash != self.head_hash {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "live journal differs from retained checkpoint",
            ));
        }
        let after =
            self.log
                .metadata()
                .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                    stage: "restat live checkpoint journal",
                    source,
                })?;
        if modification_state(&before) != modification_state(&after) {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "live journal changed during verification",
            ));
        }
        let (anchor, identity) = read_anchor_v2(&self.anchor_path)?;
        if self.anchor_identity != Some(identity)
            || decode_anchor_v2(&anchor)? != (self.record_count, self.head_hash)
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "live head differs from retained checkpoint",
            ));
        }
        self.revalidate_bound_endpoints_v2()
    }
}

// These fields only detect an observed concurrent edit; the cryptographic
// prefix check above establishes integrity. Access time is intentionally absent.
fn modification_state(metadata: &Metadata) -> (u64, i64, i64, i64, i64) {
    (
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
