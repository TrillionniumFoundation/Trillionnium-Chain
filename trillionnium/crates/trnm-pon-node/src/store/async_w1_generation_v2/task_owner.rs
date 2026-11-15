//! Service-specific monotonic task assignment. Not native branch state and not
//! a balance ledger. The path is derived from Node's actual SQLite main file,
//! so another generation journal cannot silently choose another assignment DB.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::PathBuf, time::Duration};
type StoredAssignment = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
const APP: i64 = 0x504e_4f32;
const META:&str="CREATE TABLE w1_generation_owner_meta_v2(singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=32)) STRICT";
const TASKS:&str="CREATE TABLE w1_generation_owner_tasks_v2(task BLOB PRIMARY KEY CHECK(length(task)=32),statement BLOB NOT NULL CHECK(length(statement)=32),journal BLOB NOT NULL CHECK(length(journal)=32),operation BLOB UNIQUE NOT NULL CHECK(length(operation)=32),request BLOB NOT NULL CHECK(length(request)=32)) STRICT";
pub(super) struct TaskOwnerV2 {
    connection: Connection,
    context: Hash,
}
impl TaskOwnerV2 {
    pub(super) fn open(node: &Node) -> Result<Self> {
        let raw: String = node
            .db
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name='main'",
                [],
                |r| r.get(0),
            )
            .map_err(owner_error)?;
        check(!raw.is_empty(), "GENERATION_OWNER_DURABLE_NODE_REQUIRED")?;
        let main = std::fs::canonicalize(PathBuf::from(raw)).map_err(owner_error)?;
        let filename = main
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or(error("GENERATION_OWNER_PATH"))?;
        let path = main.with_file_name(format!("{filename}.w1-generation-owner-v2.sqlite"));
        if let Ok(m) = path.symlink_metadata() {
            check(
                m.is_file() && !m.file_type().is_symlink(),
                "GENERATION_OWNER_FILE",
            )?;
        }
        let context = trnm_protocol::pon_wire::hash(
            b"node-w1-generation-owner-v2",
            &[
                &node.settings.network(),
                &node.settings.parameters(),
                &node.settings.genesis(),
                main.to_str()
                    .ok_or(error("GENERATION_OWNER_PATH"))?
                    .as_bytes(),
            ],
        );
        let mut connection = Connection::open(path).map_err(owner_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(owner_error)?;
        connection
            .pragma_update(None, "trusted_schema", false)
            .map_err(owner_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(owner_error)?;
        let app: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(owner_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(owner_error)?;
        if app == 0 && version == 0 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(owner_error)?;
            let count: u64 = tx
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                    [],
                    |r| r.get(0),
                )
                .map_err(owner_error)?;
            check(count == 0, "GENERATION_OWNER_FOREIGN_DATABASE")?;
            tx.execute_batch(META).map_err(owner_error)?;
            tx.execute_batch(TASKS).map_err(owner_error)?;
            check(
                tx.execute(
                    "INSERT INTO w1_generation_owner_meta_v2 VALUES(1,?1)",
                    [context.as_slice()],
                )
                .map_err(owner_error)?
                    == 1,
                "GENERATION_OWNER_WRITE",
            )?;
            tx.pragma_update(None, "application_id", APP)
                .map_err(owner_error)?;
            tx.pragma_update(None, "user_version", 2)
                .map_err(owner_error)?;
            tx.commit().map_err(owner_error)?;
        }
        Self::check_schema(&connection, context)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(owner_error)?;
        Ok(Self {
            connection,
            context,
        })
    }
    fn check_schema(c: &Connection, context: Hash) -> Result<()> {
        let app: i64 = c
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(owner_error)?;
        let version: i64 = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(owner_error)?;
        check(
            app == APP && version == 2,
            "GENERATION_OWNER_FOREIGN_DATABASE",
        )?;
        for (name, expected) in [
            ("w1_generation_owner_meta_v2", META),
            ("w1_generation_owner_tasks_v2", TASKS),
        ] {
            let actual: Option<String> = c
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |r| r.get(0),
                )
                .optional()
                .map_err(owner_error)?;
            check(
                actual.as_deref() == Some(expected),
                "GENERATION_OWNER_SCHEMA",
            )?;
        }
        let count: u64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                [],
                |r| r.get(0),
            )
            .map_err(owner_error)?;
        let actual: Vec<u8> = c
            .query_row(
                "SELECT context FROM w1_generation_owner_meta_v2 WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(owner_error)?;
        check(
            count == 2 && actual.as_slice() == context,
            "GENERATION_OWNER_CONTEXT",
        )
    }
    fn row(c: &Connection, task: Hash) -> Result<Option<StoredAssignment>> {
        c.query_row("SELECT statement,journal,operation,request FROM w1_generation_owner_tasks_v2 WHERE task=?1",
            [task.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(owner_error)
    }
    pub(super) fn claim(&mut self, s: &GenerationStatementV2, journal: Hash) -> Result<()> {
        let expected = (
            s.id()?.to_vec(),
            journal.to_vec(),
            s.provider_operation.to_vec(),
            s.request_digest.to_vec(),
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(owner_error)?;
        Self::check_schema(&tx, self.context)?;
        if let Some(previous) = Self::row(&tx, s.task)? {
            check(
                previous == expected,
                "GENERATION_TASK_OWNED_BY_ANOTHER_JOURNAL",
            )?;
        } else {
            check(
                tx.execute(
                    "INSERT INTO w1_generation_owner_tasks_v2 VALUES(?1,?2,?3,?4,?5)",
                    params![
                        s.task.as_slice(),
                        expected.0,
                        expected.1,
                        expected.2,
                        expected.3
                    ],
                )
                .map_err(owner_error)?
                    == 1,
                "GENERATION_OWNER_WRITE",
            )?;
        }
        check(
            Self::row(&tx, s.task)?.as_ref() == Some(&expected),
            "GENERATION_OWNER_READBACK",
        )?;
        tx.commit().map_err(owner_error)?;
        // A failed committed readback returns uncertainty; there is no rollback
        // deletion and no alternative-journal retry that would redispatch.
        let read = self
            .connection
            .unchecked_transaction()
            .map_err(owner_error)?;
        Self::check_schema(&read, self.context)?;
        check(
            Self::row(&read, s.task)?.as_ref() == Some(&expected),
            "GENERATION_OWNER_READBACK",
        )?;
        read.commit().map_err(owner_error)?;
        Ok(())
    }
}
