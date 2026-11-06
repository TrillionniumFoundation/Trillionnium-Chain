//! Same-transaction graph/history readback, ported from the existing c165 owner.
//! No receipt survives its original writer, connection, SQL epoch or schema.
use super::{CurrentAccountGraph, Record};
use crate::account_archive_prototype::native_store::{scoped_readback::Frontier, Root};
use crate::{Error, Result, Settings};
use rusqlite::Connection;
use std::collections::BTreeMap;
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::Hash;
use trnm_sqlite_io_boundary::TransactionScope;

type ReadbackSchema = Vec<(String, String, String, String, i64, Option<String>)>;

/// Only this original writer issues access, and only for one of its original
/// four nominated records after the private complete-State comparison. Pending
/// frontiers have no constructor for this loan and cannot consume themselves.
pub(crate) struct GraphAccess<'input, 'scope> {
    db: &'scope Connection,
    binding: CurrentAccountGraph<'input>,
    frontier: Option<&'scope Frontier>,
}

impl GraphAccess<'_, '_> {
    pub(crate) fn connection(&self) -> &Connection {
        self.db
    }

    pub(crate) fn root(&self) -> &Root {
        &self.binding.record.accounts
    }

    pub(crate) fn state(&self) -> &State {
        self.binding.state
    }

    pub(crate) fn record_id(&self) -> Hash {
        self.binding.record.id
    }

    pub(crate) fn frontier(&self) -> Option<&Frontier> {
        self.frontier
    }
}

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
    // Cache only the SQL program, never catalog rows or a scope verdict.
    // Keep both PRAGMAs freshly prepared: database_list may bind attachment
    // observations at prepare time. Each SELECT still steps current catalog
    // rows, and SQLite invalidates its VM after ordinary DDL or schema RESET.
    let mut statement = db.prepare_cached(
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

/// At most four named graph results inside one ordinary authenticated admission
/// or reorganization WRITE transaction: child, genesis, that verified child's
/// parent and the actual active tip nominated by the existing Node reader.
/// Nomination is not proof.
/// This is never retained by Node, serialized, cloned or used as commit/recovery
/// authority. Every use still loads current SQL State/records/deltas and runs
/// the ORIGINAL complete(settings, current State) comparison before this graph
/// result can match. Named records may share a successfully checked account
/// graph only when its entire Root (node, digest, count and balance) matches in
/// this unchanged writer. The current complete-State check uses the SAME account
/// parser as graph verification, including nonce and zero-balance accounts; no
/// working state, Record binding or database read is supplied by the receipt.
/// A completed tip-to-genesis history check may also retain the verified suffix
/// of these same four named records. Only that history path may skip an already
/// checked suffix, after freshly verifying its starting Record/block/deltas and
/// checking the original immutable Settings borrow and no-write epoch again.
/// Writes disable reuse for the remainder of this local scope.
pub(in crate::store) struct PostWriteReadback<'db> {
    db: &'db Connection,
    settings: &'db Settings,
    scope: TransactionScope<'db>,
    context: [Hash; 3],
    schema: ReadbackSchema,
    ids: [Option<Hash>; 4],
    graphs: [Option<Record>; 4],
    histories: [Option<Record>; 4],
    frontier: Option<Frontier>,
    enabled: bool,
    pub(super) consumed: bool,
    #[cfg(test)]
    pub(super) hits: usize,
    #[cfg(test)]
    pub(super) history_hits: usize,
    #[cfg(test)]
    pub(super) partial_uses: usize,
    #[cfg(test)]
    pub(super) subtree_hits: usize,
}

impl<'db> PostWriteReadback<'db> {
    pub(in crate::store) fn new(
        db: &'db Connection,
        settings: &'db Settings,
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
            settings,
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
            frontier: None,
            enabled: true,
            consumed: false,
            #[cfg(test)]
            hits: 0,
            #[cfg(test)]
            history_hits: 0,
            #[cfg(test)]
            partial_uses: 0,
            #[cfg(test)]
            subtree_hits: 0,
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
            self.frontier = None;
            // A previous caller has already consumed a successful graph hit.
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
        // Eligibility remains limited to the original four named records. A
        // fifth block cannot borrow a graph even when its account Root matches.
        // Each candidate has already passed the CURRENT complete-State and
        // Record checks at the caller. A prior graph proves only this exact
        // content-addressed account Root in the same no-write SQL epoch: empty
        // confirmation blocks can have different working state but share it.
        Ok(self.ids.contains(&Some(record.block))
            && self
                .graphs
                .iter()
                .flatten()
                .any(|verified| verified.accounts == record.accounts))
    }

    pub(super) fn history_matches(
        &mut self,
        db: &Connection,
        settings: &Settings,
        record: &Record,
    ) -> Result<bool> {
        // The three context hashes alone do not bind Settings.initial. Holding
        // the original immutable borrow also excludes a foreign Settings clone
        // with changed initial bytes but unchanged network/parameters/genesis.
        // A miss needs the ordinary full traversal, not another schema query.
        if !std::ptr::eq(self.settings, settings)
            || !self.ids.contains(&Some(record.block))
            || !self
                .histories
                .iter()
                .flatten()
                .any(|verified| verified == record)
        {
            return Ok(false);
        }
        self.current(db)
    }

    pub(super) fn stage_history_record(&self, record: &Record, pending: &mut [Option<Record>; 4]) {
        // These bounded operation-local candidates cannot authorize a hit.
        // The caller must finish EVERY ancestor and genesis check first.
        if self.enabled {
            for (id, candidate) in self.ids.iter().zip(pending) {
                if *id == Some(record.block) {
                    *candidate = Some(record.clone());
                }
            }
        }
    }

    pub(super) fn remember_history(
        &mut self,
        db: &Connection,
        settings: &Settings,
        pending: [Option<Record>; 4],
    ) -> Result<()> {
        // Called only after full tip-to-genesis validation, including the
        // canonical genesis snapshot, initial-State equality and the original
        // genesis state/graph verifier's final callback. No partial/error path
        // publishes these candidates, and no write can re-stamp their epoch.
        if std::ptr::eq(self.settings, settings) && self.current(db)? {
            for ((id, history), candidate) in self.ids.iter().zip(&mut self.histories).zip(pending)
            {
                if let Some(record) = candidate {
                    if *id == Some(record.block) {
                        *history = Some(record);
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn graph_access<'input>(
        &mut self,
        db: &Connection,
        settings: &Settings,
        binding: CurrentAccountGraph<'input>,
    ) -> Result<Option<GraphAccess<'input, '_>>> {
        if !self.current(db)?
            || self.context
                != [
                    settings.network(),
                    settings.parameters(),
                    settings.genesis(),
                ]
            || !self.ids.contains(&Some(binding.record.block))
        {
            return Ok(None);
        }
        Ok(Some(GraphAccess {
            db: self.db,
            binding,
            frontier: self.frontier.as_ref(),
        }))
    }

    pub(super) fn frontier_current(
        &mut self,
        db: &Connection,
        settings: &Settings,
        record: &Record,
        source: Hash,
    ) -> Result<bool> {
        Ok(self.current(db)?
            && self.context
                == [
                    settings.network(),
                    settings.parameters(),
                    settings.genesis(),
                ]
            && self.ids.contains(&Some(record.block))
            && self
                .frontier
                .as_ref()
                .is_some_and(|frontier| frontier.source_record() == source))
    }

    pub(super) fn remember(
        &mut self,
        db: &Connection,
        record: Record,
        pending: Option<Frontier>,
    ) -> Result<()> {
        // Called only AFTER the original successful graph, its Exit and the
        // final caller callback. A mutation during that validation mints none.
        if self.current(db)? {
            // Only an original named Record's COMPLETE successful graph can
            // seal the unique fixed-size frontier, after the final callback.
            // Fifth records and partial graphs cannot supply or replace it.
            if self.frontier.is_none() && self.ids.contains(&Some(record.block)) {
                if let Some(pending) = pending {
                    crate::ensure(
                        pending.is_for(record.id, &record.accounts),
                        "NATIVE_ACCOUNT_FRONTIER",
                    )
                    .map_err(Error::local_integrity)?;
                    self.frontier = Some(pending);
                }
            }
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
mod tests;

#[cfg(test)]
mod history_tests;
