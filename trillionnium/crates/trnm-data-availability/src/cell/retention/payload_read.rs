//! Bounded reads of the actual retained arena, checked on the returned buffer.
//!
//! This is deliberately separate from cache population: a prior verification
//! followed by a second unchecked copy does not authenticate the returned bytes.

use super::*;

mod observation;
pub(crate) use observation::{CellRetentionPayloadFaultStageV2, CellRetentionPayloadObservationV2};

impl CellRetentionStoreV1 {
    /// Read only one original, independently pinned TCM1 chunk from the actual
    /// acknowledged arena. The returned bytes are checked, and the original
    /// row and arena FD are fenced again after the read. This is not a fresh
    /// verification of the complete payload digest or any other chunk.
    pub(crate) fn read_chunk_controlled(
        &mut self,
        operation: CellDigestV1,
        expected_manifest: CellDigestV1,
        index: u32,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<Vec<u8>> {
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
        let manifest = &row.contract.manifest;
        require(
            manifest.id() == expected_manifest,
            "retention chunk manifest pin",
        )?;
        let chunk = manifest
            .chunks()
            .get(index as usize)
            .ok_or(CellErrorV1::Invalid("retention chunk index"))?;
        let relative =
            manifest.chunks()[..index as usize]
                .iter()
                .try_fold(0_u64, |total, item| {
                    total
                        .checked_add(u64::from(item.size))
                        .ok_or(CellErrorV1::Invalid("retention chunk range"))
                })?;
        require(
            relative
                .checked_add(u64::from(chunk.size))
                .is_some_and(|end| end <= manifest.size()),
            "retention chunk range",
        )?;
        let position = row
            .offset
            .checked_add(relative)
            .ok_or(CellErrorV1::Invalid("retention chunk range"))?;
        control.check()?;
        let mut bytes = vec![0; chunk.size as usize];
        self.arena.seek(SeekFrom::Start(position))?;
        control.check()?;
        self.arena.read_exact(&mut bytes)?;
        control.check()?;
        verify_chunk(chunk, &bytes)?;
        self.check_arena_controlled(&mut control)?;
        validate_schema(&self.connection)?;
        require(
            row_checksum(&self.required_row(operation)?) == row_checksum(&row),
            "retention read metadata changed",
        )?;
        control.check()?;
        Ok(bytes)
    }

    /// Read one acknowledged obligation under the caller's original admission.
    /// `max_bytes` is a caller-owned allocation limit, not a new memory lease.
    /// No metadata, initial-copy debit or repair debit changes on this path.
    pub(crate) fn read_payload_controlled(
        &mut self,
        operation: CellDigestV1,
        max_bytes: u64,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<Vec<u8>> {
        let mut control = OperationControl {
            deadline,
            checkpoint,
            stopped: false,
        };
        control.check()?;
        validate_schema(&self.connection)?;
        control.check()?;
        self.check_arena_controlled(&mut control)?;
        let rows =
            Self::audit_layout_from(&self.connection, &self.config, &mut || control.check())?;
        let row = rows
            .into_iter()
            .find(|row| row.contract.operation == operation)
            .ok_or(CellErrorV1::Invalid("retention unknown obligation"))?;
        require(row.status == 1, "retention unavailable")?;
        let size = row.contract.manifest.size();
        require(size <= max_bytes, "retention read allocation limit")?;
        let size = usize::try_from(size)
            .map_err(|_| CellErrorV1::Invalid("retention read allocation limit"))?;
        control.check()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| CellErrorV1::Invalid("retention read allocation failure"))?;
        bytes.resize(size, 0);
        control.check()?;
        self.arena.seek(SeekFrom::Start(row.offset))?;
        control.check()?;
        let mut complete = Sha256::new();
        let mut offset = 0_usize;
        for chunk in row.contract.manifest.chunks() {
            control.check()?;
            let end = offset
                .checked_add(chunk.size as usize)
                .filter(|end| *end <= bytes.len())
                .ok_or(CellErrorV1::Invalid("retention read coverage"))?;
            let actual = &mut bytes[offset..end];
            self.arena.read_exact(actual)?;
            control.check()?;
            verify_chunk(chunk, actual)?;
            control.check()?;
            complete.update(actual);
            offset = end;
            control.check()?;
        }
        require(offset == size, "retention read coverage")?;
        require(
            <[u8; 32]>::from(complete.finalize()) == row.contract.manifest.payload_sha256(),
            "retention payload digest",
        )?;
        control.check()?;
        // A callback or external fault cannot replace the path or metadata and
        // have the original FD bytes misreported as the replacement obligation.
        self.check_arena_controlled(&mut control)?;
        validate_schema(&self.connection)?;
        control.check()?;
        let current = self.required_row(operation)?;
        require(
            row_checksum(&current) == row_checksum(&row),
            "retention read metadata changed",
        )?;
        control.check()?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
