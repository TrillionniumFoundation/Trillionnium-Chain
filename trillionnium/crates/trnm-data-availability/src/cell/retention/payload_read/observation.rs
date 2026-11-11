//! Typed data-plane failures for recovery; control and metadata failures remain fatal.
//!
//! The original V1 read is unchanged. This successor never converts a callback,
//! deadline, allocation, layout, schema, row or arena-identity error into an
//! erasure. Only the named physical I/O and payload-integrity stages below may
//! produce a rejected observation, after the original fences have run again.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CellRetentionPayloadFaultStageV2 {
    Seek,
    Read,
    ChunkDigest,
    PayloadDigest,
}

#[derive(Debug)]
pub(crate) struct CellRetentionPayloadFaultV2 {
    pub stage: CellRetentionPayloadFaultStageV2,
    pub expected_bytes: u64,
    pub read_bytes_lower_bound: u64,
    pub read_bytes_upper_bound: u64,
    pub original: CellErrorV1,
}

#[derive(Debug)]
pub(crate) enum CellRetentionPayloadObservationV2 {
    Verified(Vec<u8>),
    Rejected(CellRetentionPayloadFaultV2),
}

impl CellRetentionStoreV1 {
    pub(crate) fn observe_payload_controlled_v2(
        &mut self,
        operation: CellDigestV1,
        max_bytes: u64,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionPayloadObservationV2> {
        let mut control = OperationControl {
            deadline,
            checkpoint,
            stopped: false,
        };
        control.check()?;
        validate_schema(&self.connection)?;
        self.check_arena_controlled(&mut control)?;
        let rows =
            Self::audit_layout_from(&self.connection, &self.config, &mut || control.check())?;
        let row = rows
            .into_iter()
            .find(|row| row.contract.operation == operation)
            .ok_or(CellErrorV1::Invalid("retention unknown obligation"))?;
        require(row.status == 1, "retention unavailable")?;
        let length = row.contract.manifest.size();
        require(length <= max_bytes, "retention read allocation limit")?;
        let size = usize::try_from(length)
            .map_err(|_| CellErrorV1::Invalid("retention read allocation limit"))?;
        control.check()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| CellErrorV1::Invalid("retention read allocation failure"))?;
        bytes.resize(size, 0);
        control.check()?;
        let mut fault = self
            .arena
            .seek(SeekFrom::Start(row.offset))
            .err()
            .map(|error| CellRetentionPayloadFaultV2 {
                stage: CellRetentionPayloadFaultStageV2::Seek,
                expected_bytes: length,
                read_bytes_lower_bound: 0,
                read_bytes_upper_bound: 0,
                original: error.into(),
            });
        control.check()?;
        let mut complete = Sha256::new();
        let mut offset = 0_usize;
        if fault.is_none() {
            for chunk in row.contract.manifest.chunks() {
                control.check()?;
                let end = offset
                    .checked_add(chunk.size as usize)
                    .filter(|end| *end <= bytes.len())
                    .ok_or(CellErrorV1::Invalid("retention read coverage"))?;
                let actual = &mut bytes[offset..end];
                if let Err(error) = self.arena.read_exact(actual) {
                    fault = Some(CellRetentionPayloadFaultV2 {
                        stage: CellRetentionPayloadFaultStageV2::Read,
                        expected_bytes: length,
                        read_bytes_lower_bound: offset as u64,
                        // read_exact does not expose partial progress on error.
                        read_bytes_upper_bound: end as u64,
                        original: error.into(),
                    });
                    break;
                }
                control.check()?;
                if let Err(error) = verify_chunk(chunk, actual) {
                    fault = Some(CellRetentionPayloadFaultV2 {
                        stage: CellRetentionPayloadFaultStageV2::ChunkDigest,
                        expected_bytes: length,
                        read_bytes_lower_bound: end as u64,
                        read_bytes_upper_bound: end as u64,
                        original: error,
                    });
                    break;
                }
                control.check()?;
                complete.update(actual);
                offset = end;
            }
        }
        if fault.is_none() {
            require(offset == size, "retention read coverage")?;
            if <[u8; 32]>::from(complete.finalize()) != row.contract.manifest.payload_sha256() {
                fault = Some(CellRetentionPayloadFaultV2 {
                    stage: CellRetentionPayloadFaultStageV2::PayloadDigest,
                    expected_bytes: length,
                    read_bytes_lower_bound: length,
                    read_bytes_upper_bound: length,
                    original: CellErrorV1::Invalid("retention payload digest"),
                });
            }
        }
        control.check()?;
        self.check_arena_controlled(&mut control)?;
        validate_schema(&self.connection)?;
        control.check()?;
        require(
            row_checksum(&self.required_row(operation)?) == row_checksum(&row),
            "retention read metadata changed",
        )?;
        control.check()?;
        Ok(match fault {
            Some(fault) => CellRetentionPayloadObservationV2::Rejected(fault),
            None => CellRetentionPayloadObservationV2::Verified(bytes),
        })
    }
}
