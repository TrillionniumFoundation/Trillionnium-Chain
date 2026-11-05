//! One prepared SELECT for one complete graph traversal, with no retained rows.
//!
//! Each load still executes the original bounded query. The borrowed Blob is
//! decoded before query_row returns; its Row/Rows cursor is then dropped and
//! reset before any caller progress callback or later load can run. Holding the
//! prepared statement therefore does not hold a read snapshot between nodes.
use super::super::{ArchiveError, Node, Result, NODE_SELECT};
use super::LiftCache;
use rusqlite::types::ValueRef;
use rusqlite::{CachedStatement, Connection, OptionalExtension};
use trnm_protocol::pon_wire::Hash;

pub(super) struct NodeReader<'db> {
    db: &'db Connection,
    // Lazy preparation preserves the original empty-root path, which performs
    // no archive_nodes SELECT at all. SQLite may retain its last ID binding;
    // every load replaces it and executes again. No row or verdict is cached.
    statement: Option<CachedStatement<'db>>,
}

impl<'db> NodeReader<'db> {
    pub(super) fn new(db: &'db Connection) -> Self {
        Self {
            db,
            statement: None,
        }
    }

    pub(super) fn load(&mut self, id: Hash, lifts: Option<&LiftCache>) -> Result<Node> {
        // Move the statement without checking it back into the connection's
        // cache between nodes. query_row resets its cursor on both success and
        // error; retaining this prepared code never retains a previous result.
        let mut statement = match self.statement.take() {
            Some(statement) => statement,
            None => self.db.prepare_cached(NODE_SELECT)?,
        };
        let result = statement
            .query_row([id.as_slice()], |row| {
                let value = row.get_ref(0)?;
                match value {
                    ValueRef::Blob(bytes) => Ok(lifts.map_or_else(
                        || Node::decode(id, bytes),
                        |cache| cache.1.decode(id, bytes),
                    )),
                    // Vec<u8>::FromSql accepts only Blob. Preserve row.get's
                    // exact typed error, including the real expression name;
                    // do not coerce Text/Integer/Real/Null into byte strings.
                    other => Err(rusqlite::Error::InvalidColumnType(
                        0,
                        row.as_ref().column_name(0)?.to_owned(),
                        other.data_type(),
                    )),
                }
            })
            .optional();
        self.statement = Some(statement);
        result?.ok_or(ArchiveError::DataUnavailable)?
    }
}

#[cfg(test)]
#[path = "native_node_reader_tests.rs"]
mod tests;
