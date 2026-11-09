//! Bounded reads of the actual retained arena, checked on the returned buffer.
//!
//! This is deliberately separate from cache population: a prior verification
//! followed by a second unchecked copy does not authenticate the returned bytes.

use super::*;

impl CellRetentionStoreV1 {
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
