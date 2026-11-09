//! Explicit disposal of named delivery-cache contents, not retained storage.

use super::{check_data_deadline, require, CellManifestV1, CellResultV1, CellStoreV1, Instant};
use crate::cell::cache_budget;

#[cfg(test)]
mod tests;

impl CellStoreV1 {
    /// Discard this manifest ID and all chunk hashes named by the supplied
    /// manifest in one ordinary TCL4 writer transaction. Missing rows are fine;
    /// the existing DELETE triggers reclaim logical byte and row allowance.
    /// Database pages become reusable, but file length need not decrease.
    ///
    /// Chunk hashes are shared across the entire disposable cache. This method
    /// deliberately does not preserve them for other cached manifests: those
    /// manifests can become incomplete and must reacquire and verify their
    /// missing bytes normally. Use a dedicated delivery staging cache when
    /// disposing codewords between chunks; this is not automatic eviction.
    ///
    /// The caller supplies the exact deletion scope even if its manifest row is
    /// already absent. No retained arena, funding, lease, repair or retirement
    /// record is changed. The original deadline also bounds writer admission
    /// and commit; an observed expiry before commit rolls back the whole batch.
    pub fn discard_manifest_until(
        &self,
        manifest: &CellManifestV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check_data_deadline(Some(deadline))?;
        manifest.validate()?;
        let id = manifest.id();
        check_data_deadline(Some(deadline))?;
        self.write_with_deadline(Some(deadline), |connection| {
            let application: i64 =
                connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
            let version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            require(
                application == cache_budget::APPLICATION_ID && version == 4,
                "cache namespace",
            )?;
            cache_budget::audit(connection, Some(self.config))?;
            check_data_deadline(Some(deadline))?;
            connection.execute(
                "DELETE FROM cell_manifests_v1 WHERE id = ?1",
                [id.as_slice()],
            )?;
            {
                let mut delete =
                    connection.prepare("DELETE FROM cell_chunks_v1 WHERE hash = ?1")?;
                for chunk in manifest.chunks() {
                    check_data_deadline(Some(deadline))?;
                    // Repeated hashes have only one row. A later DELETE finds
                    // no row and therefore never decrements the counters twice.
                    delete.execute([chunk.sha256.as_slice()])?;
                }
            }
            cache_budget::audit(connection, Some(self.config))?;
            check_data_deadline(Some(deadline))?;
            Ok(())
        })
    }
}
