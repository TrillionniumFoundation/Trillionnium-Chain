//! Read-only physical accounting for a catalog that owns complete Pending sets.
//! These rows describe reservations and committed charges, not healthy bytes.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct CellRetentionCatalogObjectV1 {
    pub operation: CellDigestV1,
    pub funding_operation: CellDigestV1,
    pub manifest: CellDigestV1,
    pub contract_commitment: CellDigestV1,
    pub offset: u64,
    pub reserved_bytes: u64,
    pub acknowledged: bool,
    pub retired: bool,
    pub initial_copy_bytes_committed: u64,
    pub repair_bytes_committed: u64,
}

impl CellRetentionStoreV1 {
    pub(crate) fn catalog_inventory(
        &self,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellRetentionCatalogObjectV1>> {
        let mut checkpoint = || Ok(());
        let mut control = OperationControl {
            deadline,
            checkpoint: &mut checkpoint,
            stopped: false,
        };
        control.check()?;
        self.check_arena_controlled(&mut control)?;
        let original_ms: u64 = self
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
        let original = Duration::from_millis(original_ms);
        self.connection
            .busy_timeout(original.min(deadline.saturating_duration_since(Instant::now())))?;
        let result = (|| {
            control.check()?;
            let read = self.connection.unchecked_transaction()?;
            validate_schema(&read)?;
            let rows = Self::audit_layout_from(&read, &self.config, &mut || control.check())?;
            let mut result = Vec::with_capacity(rows.len());
            for row in rows {
                control.check()?;
                result.push(CellRetentionCatalogObjectV1 {
                    operation: row.contract.operation,
                    funding_operation: row.contract.funding_operation,
                    manifest: row.contract.manifest.id(),
                    contract_commitment: row.contract.commitment(self.config.store_id),
                    offset: row.offset,
                    reserved_bytes: row.reserved,
                    acknowledged: row.status == 1,
                    retired: row.status == 2,
                    initial_copy_bytes_committed: row.initial_bytes,
                    repair_bytes_committed: row.repair_bytes,
                });
            }
            read.rollback()?;
            self.check_arena_controlled(&mut control)?;
            control.check()?;
            Ok(result)
        })();
        self.connection.busy_timeout(original)?;
        result
    }
}
