//! Same-transaction graph readback, ported from the existing c165 owner.
//! No receipt survives its original writer, connection, SQL epoch or schema.
use super::Record;
use crate::{Error, Result, Settings};
use rusqlite::Connection;
use std::collections::BTreeMap;
use trnm_protocol::pon_wire::Hash;
use trnm_sqlite_io_boundary::TransactionScope;

type ReadbackSchema = Vec<(String, String, String, String, i64, Option<String>)>;

fn readback_schema(db: &Connection) -> Result<Option<ReadbackSchema>> {
    // A configuration change is not necessarily an executed write: SQLite
    // applies some PRAGMAs at prepare time. Never qualify writable catalog mode.
    let writable: bool = db.query_row("PRAGMA writable_schema", [], |row| row.get(0))?;
    if writable {
        return Ok(None);
    }
    let mut databases = db.prepare("PRAGMA database_list")?;
    let mut rows = databases.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name != "main" && name != "temp" {
            return Ok(None);
        }
    }
    let temp_objects: u64 = db.query_row("SELECT COUNT(*) FROM temp.sqlite_master", [], |row| {
        row.get(0)
    })?;
    if temp_objects != 0 {
        return Ok(None);
    }
    let mut statement = db.prepare(
        "SELECT 'main',type,name,tbl_name,rootpage,sql FROM main.sqlite_master UNION ALL SELECT 'temp',type,name,tbl_name,rootpage,sql FROM temp.sqlite_master ORDER BY 1,2,3",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    Ok(Some(rows.collect::<rusqlite::Result<_>>()?))
}

/// At most four named graph and history results inside one ordinary
/// authenticated admission or reorganization WRITE transaction: child, genesis,
/// that verified child's parent and the actual active tip nominated by the
/// existing Node reader.
/// Nomination is not proof.
/// This is never retained by Node, serialized, cloned or used as commit/recovery
/// authority. Every graph use still loads current SQL State/records/deltas and
/// runs the ORIGINAL complete(settings, current State) comparison. History
/// suffixes become reusable only after the complete original path to genesis
/// and its full State/graph check succeed in this same unchanged writer. The
/// next use rereads and verifies its actual anchor Record/deltas before matching.
/// Its Record binds the full State commitment, not just an account root. Writes
/// disable both kinds of reuse for the remainder of this local scope. The first
/// history traversal still costs O(H); no cross-transaction prefix is retained.
pub(in crate::store) struct PostWriteReadback<'db> {
    db: &'db Connection,
    scope: TransactionScope<'db>,
    context: [Hash; 3],
    schema: ReadbackSchema,
    ids: [Option<Hash>; 4],
    graphs: [Option<Record>; 4],
    histories: [Option<Record>; 4],
    enabled: bool,
    pub(super) consumed: bool,
    #[cfg(test)]
    pub(super) hits: usize,
    #[cfg(test)]
    pub(super) history_hits: usize,
    #[cfg(test)]
    history_match_epoch_checks: usize,
}

impl<'db> PostWriteReadback<'db> {
    pub(in crate::store) fn new(
        db: &'db Connection,
        settings: &Settings,
        child: Hash,
        original_owner: &TransactionScope<'_>,
        expected_schema: &BTreeMap<String, String>,
    ) -> Result<Option<Self>> {
        // The first scope predates all callbacks/writes in THIS transaction. Its
        // write count may differ, but its actual connection/transaction cannot.
        original_owner
            .same_write_snapshot(db)
            .map_err(readback_scope_error)?;
        if readback_schema(db)?.is_none() || super::super::schema(db)? != *expected_schema {
            return Ok(None);
        }
        // A prior writable_schema edit can leave the parsed schema and cached
        // SELECTs on an old rootpage while sqlite_master already reports a new
        // one. Comparing catalog rows alone would wrongly certify that split.
        // In pinned SQLite 3.51.3 RESET clears parsed schemas at prepare time;
        // executing its OP_Expire through DONE also expires all cached VMs.
        // Normalize BEFORE the first full graph and the new write baseline.
        // No catalog bytes change. A later prepare-only RESET can then only
        // reload the SAME catalog while the original writer and no-write epoch
        // hold. This applies only to the original ordinary-table Node schema,
        // not arbitrary views, virtual tables, UDFs or attached databases.
        db.execute_batch("PRAGMA writable_schema=RESET")
            .map_err(|error| Error::from(error).local_integrity())?;
        let scope = TransactionScope::capture(db).map_err(readback_scope_error)?;
        let schema = readback_schema(db)?;
        original_owner
            .same_write_snapshot(db)
            .map_err(readback_scope_error)?;
        if !scope
            .same_write_snapshot(db)
            .map_err(readback_scope_error)?
            || super::super::schema(db)? != *expected_schema
        {
            return Ok(None);
        }
        let Some(schema) = schema else {
            return Ok(None);
        };
        Ok(Some(Self {
            db,
            scope,
            context: [
                settings.network(),
                settings.parameters(),
                settings.genesis(),
            ],
            schema,
            ids: [Some(child), Some(settings.genesis()), None, None],
            graphs: [None, None, None, None],
            histories: [None, None, None, None],
            enabled: true,
            consumed: false,
            #[cfg(test)]
            hits: 0,
            #[cfg(test)]
            history_hits: 0,
            #[cfg(test)]
            history_match_epoch_checks: 0,
        }))
    }

    pub(super) fn current(&mut self, db: &Connection) -> Result<bool> {
        let same = self
            .scope
            .same_write_snapshot(db)
            .map_err(readback_scope_error)?;
        if self.consumed && !self.enabled {
            return Err(Error::from("NATIVE_POST_WRITE_CHANGED").local_integrity());
        }
        if !same || self.enabled && readback_schema(db)?.as_ref() != Some(&self.schema) {
            self.enabled = false;
            self.graphs = [None, None, None, None];
            self.histories = [None, None, None, None];
            // A previous caller already consumed a successful graph/history hit.
            // Merely disabling FUTURE hits cannot validate its result after a
            // later outer callback writes. The owning transaction must refuse.
            if self.consumed {
                return Err(Error::from("NATIVE_POST_WRITE_CHANGED").local_integrity());
            }
        }
        Ok(self.enabled)
    }

    pub(in crate::store) fn validate_consumed(&mut self, db: &Connection) -> Result<()> {
        self.current(db).map(|_| ())
    }

    /// A reorganization tail has no legitimate writes left. Unlike admission's
    /// consumed-hit fence, any disabled epoch refuses this tail, including a
    /// callback write before the first hit. Never clear or re-stamp this scope.
    pub(in crate::store) fn require_unchanged_after_last_write(
        &mut self,
        db: &Connection,
    ) -> Result<()> {
        crate::ensure(self.current(db)?, "NATIVE_POST_WRITE_CHANGED")
            .map_err(Error::local_integrity)
    }

    /// Only the original Node active reader supplies this already-read tip.
    /// The slot is immutable after its first nomination and receives no graph
    /// until the ORIGINAL complete-State/record/graph verification succeeds.
    pub(in crate::store) fn nominate_active(&mut self, db: &Connection, block: Hash) -> Result<()> {
        if self.current(db)? && self.ids[3].is_none() {
            self.ids[3] = Some(block);
        }
        Ok(())
    }

    pub(super) fn matches(
        &mut self,
        db: &Connection,
        settings: &Settings,
        record: &Record,
    ) -> Result<bool> {
        if !self.current(db)?
            || self.context
                != [
                    settings.network(),
                    settings.parameters(),
                    settings.genesis(),
                ]
        {
            return Ok(false);
        }
        Ok(self
            .ids
            .iter()
            .position(|id| *id == Some(record.block))
            .is_some_and(|index| self.graphs[index].as_ref() == Some(record)))
    }

    pub(super) fn remember(&mut self, db: &Connection, record: Record) -> Result<()> {
        // Called only AFTER the original successful graph, its Exit and the
        // final caller callback. A mutation during that validation mints none.
        if self.current(db)? {
            // Nominate the parent only from the fully verified child Record.
            // This introduces no earlier SQL read, validation or error order.
            if self.ids[0] == Some(record.block) && self.ids[2].is_none() {
                self.ids[2] = record.parent;
            }
            for (id, graph) in self.ids.iter().zip(&mut self.graphs) {
                if *id == Some(record.block) {
                    *graph = Some(record.clone());
                }
            }
        }
        Ok(())
    }

    /// Candidate anchors are bounded nominations, not successful history facts.
    /// The caller can publish them only after the COMPLETE original traversal
    /// reaches a verified genesis or an already verified suffix in this scope.
    pub(super) fn nominate_history_candidate(
        &self,
        record: &Record,
        candidates: &mut [Option<Record>; 4],
    ) {
        for (id, candidate) in self.ids.iter().zip(candidates) {
            if *id == Some(record.block) {
                *candidate = Some(record.clone());
            }
        }
    }

    pub(super) fn history_matches(
        &mut self,
        db: &Connection,
        settings: &Settings,
        record: &Record,
    ) -> Result<bool> {
        if self.context
            != [
                settings.network(),
                settings.parameters(),
                settings.genesis(),
            ]
        {
            return Ok(false);
        }
        let matches = self
            .ids
            .iter()
            .position(|id| *id == Some(record.block))
            .is_some_and(|index| self.histories[index].as_ref() == Some(record));
        // A miss supplies no fact: avoid a schema query at every record of the
        // mandatory first O(H) scan. A possible hit still checks the actual
        // writer/SQL/schema epoch before it can omit any original traversal.
        if matches {
            #[cfg(test)]
            {
                // Counts only this actual current() call. Final publication,
                // graph and owner fences remain separate; this is not total SQL.
                self.history_match_epoch_checks += 1;
            }
            self.current(db)
        } else {
            Ok(false)
        }
    }

    /// Recheck AFTER the hit's last actual caller checkpoint, then mark that a
    /// result depended on the stable suffix. Any later write must refuse the
    /// enclosing transaction through its existing consumed-result fence.
    pub(super) fn consume_history(
        &mut self,
        db: &Connection,
        settings: &Settings,
        record: &Record,
    ) -> Result<bool> {
        if !self.history_matches(db, settings, record)? {
            return Ok(false);
        }
        self.consumed = true;
        #[cfg(test)]
        {
            self.history_hits += 1;
        }
        Ok(true)
    }

    pub(super) fn remember_histories(
        &mut self,
        db: &Connection,
        candidates: [Option<Record>; 4],
    ) -> Result<()> {
        // This follows the original successful final genesis check or the
        // suffix hit's last checkpoint. No partial/error/cancelled traversal can
        // supply a result, and a callback write cannot re-stamp the epoch.
        if self.current(db)? {
            for ((id, retained), candidate) in
                self.ids.iter().zip(&mut self.histories).zip(candidates)
            {
                if let Some(record) = candidate.filter(|record| *id == Some(record.block)) {
                    *retained = Some(record);
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        // Even a native cancellation/error cannot hide a replaced transaction.
        match self.scope.same_write_snapshot(self.db) {
            Ok(_) => result,
            Err(error) => Err(match result {
                Ok(_) => readback_scope_error(error),
                Err(first) => Error::local_replay_source("NATIVE_POST_WRITE_SCOPE", first),
            }),
        }
    }
}

pub(in crate::store) fn readback_scope_error(
    error: trnm_sqlite_io_boundary::BoundaryError,
) -> Error {
    Error::local_replay_source("NATIVE_POST_WRITE_SCOPE", error)
}

#[cfg(test)]
mod history_readback_tests;
#[cfg(test)]
mod tests;
