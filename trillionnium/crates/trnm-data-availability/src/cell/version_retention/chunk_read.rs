//! Original, acknowledged arena chunks for a catalog-pinned storage plan.
//! This read conveys neither a new custody acknowledgement nor execution rights.

use super::*;

impl CellVersionRetentionStoreV3 {
    pub(crate) fn read_chunk_for_plan(
        &mut self,
        operation: CellDigestV1,
        manifest: CellDigestV1,
        index: u32,
        expected: CellVersionCatalogAnchorV3,
        deadline: Instant,
    ) -> CellResultV1<Vec<u8>> {
        require(
            self.check(deadline)?.anchor == expected,
            "paged shard source catalog changed",
        )?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status == 1, "paged shard source unavailable")?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.manifest.id() == manifest)
            .ok_or(CellErrorV1::Invalid("paged shard source member"))?;
        require(
            self.retention.contract(object.operation)? == *object,
            "paged shard source original contract changed",
        )?;
        let bytes = self.retention.read_chunk_controlled(
            object.operation,
            manifest,
            index,
            deadline,
            &mut || Ok(()),
        )?;
        require(
            self.check(deadline)?.anchor == expected,
            "paged shard source catalog changed",
        )?;
        let current = required_row(&self.catalog, &self.config, operation)?;
        require(
            current.status == 1 && current.contract == row.contract,
            "paged shard source duty changed",
        )?;
        check_deadline(deadline)?;
        Ok(bytes)
    }
}
