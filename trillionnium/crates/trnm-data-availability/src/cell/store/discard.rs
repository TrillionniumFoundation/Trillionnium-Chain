//! Explicit disposal of named delivery-cache contents, not retained storage.

use super::{check_data_deadline, require, CellManifestV1, CellResultV1, CellStoreV1, Instant};
use super::{CellErrorV1, MAX_MANIFEST_BYTES};
use crate::cell::cache_budget;
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

impl CellStoreV1 {
    /// Check a caller-owned writable delivery cache before admitting effects.
    /// This is only a local namespace/quota observation; each actual writer
    /// still rechecks its bounded transaction. No row or allowance is changed.
    pub fn check_delivery_cache_until(&self, deadline: Instant) -> CellResultV1<()> {
        check_data_deadline(Some(deadline))?;
        require(!self.read_only, "read-only cache")?;
        cache_budget::audit(&self.connection, Some(self.config))?;
        check_data_deadline(Some(deadline))
    }

    /// Discard this manifest ID and its now-unreferenced chunks in one ordinary
    /// TCL4 writer transaction. Missing rows are fine;
    /// the existing DELETE triggers reclaim logical byte and row allowance.
    /// Database pages become reusable, but file length need not decrease.
    ///
    /// Chunk hashes are shared across the entire disposable cache. Remaining
    /// canonical manifests retain their referenced chunks. The reference scan
    /// and deletion share the same writer transaction, so a concurrent normal
    /// publisher cannot lose a referenced CAS row. Unrelated manifests are not
    /// discarded. Use a dedicated writable delivery cache to guarantee bounded
    /// codeword reuse; a shared owner can legitimately keep space occupied.
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
            let mut unreferenced: BTreeSet<_> =
                manifest.chunks().iter().map(|chunk| chunk.sha256).collect();
            {
                let mut remaining = connection.prepare(
                    "SELECT id, CASE WHEN length(wire) <= ?1 THEN wire ELSE NULL END
                     FROM cell_manifests_v1",
                )?;
                let mut rows = remaining.query([MAX_MANIFEST_BYTES as i64])?;
                while let Some(row) = rows.next()? {
                    check_data_deadline(Some(deadline))?;
                    let id: Vec<u8> = row.get(0)?;
                    let wire: Option<Vec<u8>> = row.get(1)?;
                    let wire = wire.ok_or(CellErrorV1::Invalid("cached manifest length"))?;
                    let owner = CellManifestV1::decode(&wire)?;
                    require(
                        owner.id().as_slice() == id.as_slice(),
                        "cached manifest digest",
                    )?;
                    for chunk in owner.chunks() {
                        check_data_deadline(Some(deadline))?;
                        unreferenced.remove(&chunk.sha256);
                    }
                }
            }
            {
                let mut delete =
                    connection.prepare("DELETE FROM cell_chunks_v1 WHERE hash = ?1")?;
                for hash in unreferenced {
                    check_data_deadline(Some(deadline))?;
                    // Repeated references are a single CAS row and a single
                    // deletion. Missing original residue is also idempotent.
                    delete.execute([hash.as_slice()])?;
                }
            }
            cache_budget::audit(connection, Some(self.config))?;
            check_data_deadline(Some(deadline))?;
            Ok(())
        })
    }
}
