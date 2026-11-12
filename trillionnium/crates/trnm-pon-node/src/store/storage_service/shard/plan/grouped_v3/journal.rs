//! Persistent V3 child history. It grants no effect, payment or positive verdict.
//! The caller independently binds this history to the original M12 parent.
//! Coherent rollback of both stores is outside this journal's freshness scope.
use crate::{ensure, Result};
use fs2::FileExt as LockFileExt;
use rusqlite::{
    config::DbConfig, params, Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{FileExt as UnixFileExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::Instant,
};
use trnm_protocol::pon_wire::Hash;

const APP: i32 = 0x4347_4a33;
const VERSION: i32 = 3;
const MAX_GROUPS: usize = 64;
const MAX_CHILDREN: usize = 1024;
const MAX_GROUP_CHILDREN: usize = 16;
const MAX_DESCRIPTOR: usize = 1024 * 1024;
const MAX_EVENTS: usize = MAX_GROUPS + 2 * MAX_CHILDREN;
const MAX_EVENT_BYTES: usize = 2 * MAX_DESCRIPTOR + 64 * 1024;
const MAX_HISTORY_BYTES: usize = MAX_GROUPS * MAX_EVENT_BYTES + 2 * MAX_CHILDREN * 4096;
const META_SQL:&str="CREATE TABLE journal_context(singleton INTEGER PRIMARY KEY CHECK(singleton=1), context BLOB NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), root BLOB NOT NULL CHECK(typeof(root)='blob' AND length(root)=32))";
const GROUP_SQL:&str="CREATE TABLE groups(group_id BLOB PRIMARY KEY CHECK(typeof(group_id)='blob' AND length(group_id)=32), descriptor BLOB NOT NULL, descriptor_hash BLOB NOT NULL CHECK(typeof(descriptor_hash)='blob' AND length(descriptor_hash)=32), child_count INTEGER NOT NULL CHECK(child_count BETWEEN 1 AND 16))";
const CHILD_SQL:&str="CREATE TABLE children(group_id BLOB NOT NULL REFERENCES groups(group_id), ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15), operation BLOB NOT NULL UNIQUE CHECK(typeof(operation)='blob' AND length(operation)=32), effect BLOB NOT NULL UNIQUE CHECK(typeof(effect)='blob' AND length(effect)=32), from_height INTEGER NOT NULL CHECK(from_height>=0), until_height INTEGER NOT NULL CHECK(until_height>from_height), state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2), receipt BLOB, PRIMARY KEY(group_id,ordinal), CHECK((state IN (0,1) AND receipt IS NULL) OR (state=2 AND typeof(receipt)='blob' AND length(receipt)=32)))";
const EVENT_SQL:&str="CREATE TABLE events(sequence INTEGER PRIMARY KEY CHECK(sequence>0), previous BLOB NOT NULL CHECK(typeof(previous)='blob' AND length(previous)=32), payload BLOB NOT NULL, digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32))";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCellShardGroupJournalConfigV3 {
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
    pub plan: Hash,
    pub owner_generation: u64,
}

impl State {
    fn child(&self, group: Hash, index: usize) -> Result<&ChildRecord> {
        self.groups
            .get(&group)
            .and_then(|g| g.children.get(index))
            .ok_or_else(|| "NATIVE_CELL_GROUP_JOURNAL_CHILD_ABSENT".into())
    }
    fn apply(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Register {
                group,
                descriptor_hex,
                children,
            } => {
                ensure(
                    descriptor_hex.len() <= 2 * MAX_DESCRIPTOR,
                    "NATIVE_CELL_GROUP_JOURNAL_DESCRIPTOR_CAPACITY",
                )?;
                let descriptor = hex::decode(descriptor_hex)
                    .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_DESCRIPTOR_ENCODING")?;
                ensure(
                    hex::encode(&descriptor) == *descriptor_hex,
                    "NATIVE_CELL_GROUP_JOURNAL_DESCRIPTOR_ENCODING",
                )?;
                validate_roster(*group, &descriptor, children)?;
                ensure(
                    self.groups.len() < MAX_GROUPS
                        && !self.groups.contains_key(group)
                        && self
                            .groups
                            .values()
                            .map(|g| g.children.len())
                            .sum::<usize>()
                            + children.len()
                            <= MAX_CHILDREN,
                    "NATIVE_CELL_GROUP_JOURNAL_ROSTER_CAPACITY",
                )?;
                let mut operations: BTreeSet<Hash> = self.groups.keys().copied().collect();
                let mut effects = BTreeSet::new();
                for child in self.groups.values().flat_map(|g| &g.children) {
                    ensure(
                        operations.insert(child.binding.operation)
                            && effects.insert(child.binding.effect),
                        "NATIVE_CELL_GROUP_JOURNAL_STORED_ALIAS",
                    )?;
                }
                ensure(
                    operations.insert(*group),
                    "NATIVE_CELL_GROUP_JOURNAL_GROUP_ALIAS",
                )?;
                for child in children {
                    ensure(
                        operations.insert(child.operation) && effects.insert(child.effect),
                        "NATIVE_CELL_GROUP_JOURNAL_CHILD_ALIAS",
                    )?;
                }
                self.groups.insert(
                    *group,
                    GroupRecord {
                        descriptor,
                        children: children
                            .iter()
                            .cloned()
                            .map(|binding| ChildRecord {
                                binding,
                                state: ChildStateV3::Unstarted,
                            })
                            .collect(),
                    },
                );
            }
            Event::Begin { group, index } => {
                let child = self
                    .groups
                    .get_mut(group)
                    .and_then(|g| g.children.get_mut(*index))
                    .ok_or("NATIVE_CELL_GROUP_JOURNAL_CHILD_ABSENT")?;
                ensure(
                    child.state == ChildStateV3::Unstarted,
                    "NATIVE_CELL_GROUP_JOURNAL_CHILD_ALREADY_STARTED",
                )?;
                child.state = ChildStateV3::Pending;
            }
            Event::Complete {
                group,
                index,
                receipt,
            } => {
                ensure(
                    *receipt != [0; 32],
                    "NATIVE_CELL_GROUP_JOURNAL_ZERO_RECEIPT",
                )?;
                let child = self
                    .groups
                    .get_mut(group)
                    .and_then(|g| g.children.get_mut(*index))
                    .ok_or("NATIVE_CELL_GROUP_JOURNAL_CHILD_ABSENT")?;
                ensure(
                    child.state == ChildStateV3::Pending,
                    "NATIVE_CELL_GROUP_JOURNAL_EVENT_TRANSITION",
                )?;
                child.state = ChildStateV3::Done(*receipt);
            }
        }
        Ok(())
    }
}
fn validate_roster(group: Hash, descriptor: &[u8], children: &[ChildBindingV3]) -> Result<()> {
    ensure(
        group != [0; 32]
            && !descriptor.is_empty()
            && descriptor.len() <= MAX_DESCRIPTOR
            && (1..=MAX_GROUP_CHILDREN).contains(&children.len()),
        "NATIVE_CELL_GROUP_JOURNAL_ROSTER",
    )?;
    let mut operations = BTreeSet::from([group]);
    let mut effects = BTreeSet::new();
    for child in children {
        ensure(
            child.operation != [0; 32]
                && child.effect != [0; 32]
                && child.from < child.until
                && child.until <= i64::MAX as u64
                && operations.insert(child.operation)
                && effects.insert(child.effect),
            "NATIVE_CELL_GROUP_JOURNAL_CHILD_BINDING",
        )?;
    }
    Ok(())
}
fn require_record(
    record: &GroupRecord,
    descriptor: &[u8],
    children: &[ChildBindingV3],
) -> Result<()> {
    ensure(
        record.descriptor == descriptor
            && record
                .children
                .iter()
                .map(|c| &c.binding)
                .eq(children.iter()),
        "NATIVE_CELL_GROUP_JOURNAL_ROSTER_CHANGED",
    )
}
fn context_bytes(config: &NativeCellShardGroupJournalConfigV3) -> Result<Vec<u8>> {
    ensure(
        config.network != [0; 32]
            && config.parameters != [0; 32]
            && config.genesis != [0; 32]
            && config.plan != [0; 32]
            && config.owner_generation > 0,
        "NATIVE_CELL_GROUP_JOURNAL_CONTEXT",
    )?;
    let mut context = b"CGJ3\0".to_vec();
    context.extend_from_slice(&serde_json::to_vec(config)?);
    Ok(context)
}
fn paths_and_context(
    path: &Path,
    config: &NativeCellShardGroupJournalConfigV3,
) -> Result<(PathBuf, PathBuf, File, Vec<u8>, Hash)> {
    ensure(
        path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "NATIVE_CELL_GROUP_JOURNAL_PATH",
    )?;
    let parent_path = path.parent().ok_or("NATIVE_CELL_GROUP_JOURNAL_PARENT")?;
    ensure(
        fs::symlink_metadata(parent_path)?.file_type().is_dir()
            && parent_path.canonicalize()? == parent_path,
        "NATIVE_CELL_GROUP_JOURNAL_PARENT",
    )?;
    let parent = File::open(parent_path)?;
    let context = context_bytes(config)?;
    let context_hash = digest(b"trnm.native-cell-group-child-context.v3\0", &context);
    Ok((
        path.to_path_buf(),
        parent_path.to_path_buf(),
        parent,
        context,
        context_hash,
    ))
}
fn private_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .mode(0o600);
    if create {
        options.create_new(true);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure(
        metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0,
        "NATIVE_CELL_GROUP_JOURNAL_PRIVATE_FILE",
    )?;
    Ok(file)
}
fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("NATIVE_CELL_GROUP_JOURNAL_CREATE_EXISTS".into()),
    }
}
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn check_private_path(path: &Path, expected: (u64, u64)) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && identity(&metadata) == expected,
        "NATIVE_CELL_GROUP_JOURNAL_FILE_REPLACED",
    )
}
fn check_lock_bytes(file: &File, expected: Hash) -> Result<()> {
    ensure(
        file.metadata()?.len() == 32,
        "NATIVE_CELL_GROUP_JOURNAL_LOCK_CONTEXT",
    )?;
    let mut bytes = [0; 32];
    UnixFileExt::read_exact_at(file, &mut bytes, 0)?;
    ensure(bytes == expected, "NATIVE_CELL_GROUP_JOURNAL_LOCK_CONTEXT")
}
fn prevent_close_checkpoint(connection: &Connection) -> Result<()> {
    ensure(
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?,
        "NATIVE_CELL_GROUP_JOURNAL_CLOSE_POLICY",
    )?;
    ensure(
        connection.db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)?,
        "NATIVE_CELL_GROUP_JOURNAL_CLOSE_POLICY",
    )
}
fn open_connection(path: &Path, read_only: bool) -> Result<Connection> {
    let access = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let connection = Connection::open_with_flags(path, access | OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
    // Configure close before schema-sensitive PRAGMAs, including refusal paths.
    prevent_close_checkpoint(&connection)?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    if read_only {
        connection.pragma_update(None, "query_only", true)?;
    }
    Ok(connection)
}
fn configure_verified_writer(connection: &Connection) -> Result<()> {
    let mode: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    ensure(mode == "wal", "NATIVE_CELL_GROUP_JOURNAL_MODE")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    ensure(
        connection.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))? == 2,
        "NATIVE_CELL_GROUP_JOURNAL_SYNC",
    )
}
fn check_schema(connection: &Connection) -> Result<()> {
    let app: i32 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    ensure(
        app == APP && version == VERSION,
        "NATIVE_CELL_GROUP_JOURNAL_NAMESPACE",
    )?;
    let expected = BTreeMap::from([
        ("journal_context", META_SQL),
        ("groups", GROUP_SQL),
        ("children", CHILD_SQL),
        ("events", EVENT_SQL),
    ]);
    let indexes = BTreeSet::from([
        "sqlite_autoindex_groups_1",
        "sqlite_autoindex_children_1",
        "sqlite_autoindex_children_2",
        "sqlite_autoindex_children_3",
    ]);
    ensure(
        connection.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })? == (expected.len() + indexes.len()) as i64,
        "NATIVE_CELL_GROUP_JOURNAL_SCHEMA_COUNT",
    )?;
    let mut seen = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();
    let mut statement=connection.prepare(
  "SELECT CASE WHEN typeof(type)='text' AND length(CAST(type AS BLOB))<=16 THEN type ELSE NULL END,CASE WHEN typeof(name)='text' AND length(CAST(name AS BLOB))<=128 THEN name ELSE NULL END,CASE WHEN typeof(tbl_name)='text' AND length(CAST(tbl_name AS BLOB))<=128 THEN tbl_name ELSE NULL END,CASE WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=4096 THEN sql ELSE NULL END,(sql IS NULL OR (typeof(sql)='text' AND length(CAST(sql AS BLOB))<=4096)) FROM sqlite_master")?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, bool>(4)?,
        ))
    })?;
    for row in rows {
        let (kind, name, table, sql, sql_shape) = row?;
        ensure(sql_shape, "NATIVE_CELL_GROUP_JOURNAL_SCHEMA_SQL_SHAPE")?;
        let kind = kind.ok_or("NATIVE_CELL_GROUP_JOURNAL_SCHEMA_TYPE")?;
        let name = name.ok_or("NATIVE_CELL_GROUP_JOURNAL_SCHEMA_NAME")?;
        let table = table.ok_or("NATIVE_CELL_GROUP_JOURNAL_SCHEMA_TABLE")?;
        if indexes.contains(name.as_str()) {
            ensure(
                kind == "index"
                    && matches!(table.as_str(), "groups" | "children")
                    && sql.is_none()
                    && seen_indexes.insert(name),
                "NATIVE_CELL_GROUP_JOURNAL_SCHEMA",
            )?;
            continue;
        }
        let expected_sql = expected
            .get(name.as_str())
            .ok_or("NATIVE_CELL_GROUP_JOURNAL_FOREIGN_SCHEMA")?;
        ensure(
            kind == "table"
                && name == table
                && normalize_sql(sql.as_deref().ok_or("NATIVE_CELL_GROUP_JOURNAL_SCHEMA")?)
                    == normalize_sql(expected_sql)
                && seen.insert(name),
            "NATIVE_CELL_GROUP_JOURNAL_SCHEMA",
        )?;
    }
    ensure(
        seen.len() == expected.len() && seen_indexes.len() == indexes.len(),
        "NATIVE_CELL_GROUP_JOURNAL_SCHEMA",
    )
}
fn normalize_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
fn read_head(connection: &Connection, context: &[u8]) -> Result<(usize, Hash)> {
    ensure(
        connection.query_row("SELECT count(*) FROM journal_context", [], |r| {
            r.get::<_, i64>(0)
        })? == 1,
        "NATIVE_CELL_GROUP_JOURNAL_CONTEXT",
    )?;
    let shape:(String,i64,String,i64,i64)=connection.query_row(
  "SELECT typeof(context),length(context),typeof(root),length(root),sequence FROM journal_context WHERE singleton=1",
  [],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    ensure(
        shape.0 == "blob"
            && shape.1 == context.len() as i64
            && shape.2 == "blob"
            && shape.3 == 32
            && (0..=MAX_EVENTS as i64).contains(&shape.4),
        "NATIVE_CELL_GROUP_JOURNAL_HEAD",
    )?;
    let (actual, root): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT context,root FROM journal_context WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(
        actual == context,
        "NATIVE_CELL_GROUP_JOURNAL_CONTEXT_CHANGED",
    )?;
    Ok((
        shape.4 as usize,
        root.try_into()
            .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_HEAD")?,
    ))
}
fn read_records(connection: &Connection) -> Result<Vec<Record>> {
    let(count,bytes,hash_bytes):(i64,i64,i64)=connection.query_row(
  "SELECT count(*),coalesce(sum(length(payload)),0),coalesce(sum(length(previous)+length(digest)),0) FROM events",
  [],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    ensure(
        (0..=MAX_EVENTS as i64).contains(&count)
            && (0..=MAX_HISTORY_BYTES as i64).contains(&bytes)
            && hash_bytes == 64 * count,
        "NATIVE_CELL_GROUP_JOURNAL_EVENT_CAPACITY",
    )?;
    let mut statement=connection.prepare(
  "SELECT sequence,CASE WHEN typeof(previous)='blob' AND length(previous)=32 THEN previous ELSE NULL END,CASE WHEN typeof(payload)='blob' AND length(payload)<=?1 THEN payload ELSE NULL END,CASE WHEN typeof(digest)='blob' AND length(digest)=32 THEN digest ELSE NULL END FROM events ORDER BY sequence")?;
    let rows = statement.query_map([MAX_EVENT_BYTES as i64], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<Vec<u8>>>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
        ))
    })?;
    let mut records = Vec::with_capacity(count as usize);
    for row in rows {
        let (sequence, previous, payload, digest) = row?;
        ensure(
            sequence == records.len() as i64 + 1,
            "NATIVE_CELL_GROUP_JOURNAL_SEQUENCE",
        )?;
        records.push(Record {
            previous: previous
                .ok_or("NATIVE_CELL_GROUP_JOURNAL_CHAIN")?
                .try_into()
                .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_CHAIN")?,
            payload: payload.ok_or("NATIVE_CELL_GROUP_JOURNAL_EVENT_CAPACITY")?,
            digest: digest
                .ok_or("NATIVE_CELL_GROUP_JOURNAL_CHAIN")?
                .try_into()
                .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_CHAIN")?,
        });
    }
    Ok(records)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChildBindingV3 {
    pub operation: Hash,
    pub effect: Hash,
    pub from: u64,
    pub until: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildStateV3 {
    Unstarted,
    Pending,
    Done(Hash),
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ChildRecord {
    binding: ChildBindingV3,
    state: ChildStateV3,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupRecord {
    descriptor: Vec<u8>,
    children: Vec<ChildRecord>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct State {
    groups: BTreeMap<Hash, GroupRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Register {
        group: Hash,
        descriptor_hex: String,
        children: Vec<ChildBindingV3>,
    },
    Begin {
        group: Hash,
        index: usize,
    },
    Complete {
        group: Hash,
        index: usize,
        receipt: Hash,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    previous: Hash,
    payload: Vec<u8>,
    digest: Hash,
}

/// Exclusive non-clone owner. Existing parent history is never inferred here.
pub struct NativeCellShardGroupJournalV3 {
    path: PathBuf,
    lock_path: PathBuf,
    parent_path: PathBuf,
    database_identity: (u64, u64),
    lock_identity: (u64, u64),
    parent_identity: (u64, u64),
    parent: File,
    owner_lock: File,
    connection: Connection,
    context: Vec<u8>,
    context_hash: Hash,
    state: State,
    records: Vec<Record>,
    root: Hash,
}
impl NativeCellShardGroupJournalV3 {
    pub fn create(path: &Path, config: NativeCellShardGroupJournalConfigV3) -> Result<Self> {
        let (path, parent_path, parent, context, context_hash) = paths_and_context(path, &config)?;
        let lock_path = path.with_extension("owner-v3.lock");
        ensure_absent(&path)?;
        ensure_absent(&lock_path)?;
        let mut owner_lock = private_file(&lock_path, true)?;
        LockFileExt::try_lock_exclusive(&owner_lock)?;
        owner_lock.write_all(&context_hash)?;
        owner_lock.sync_all()?;
        let database = private_file(&path, true)?;
        database.sync_all()?;
        let database_identity = identity(&database.metadata()?);
        let lock_identity = identity(&owner_lock.metadata()?);
        let parent_identity = identity(&parent.metadata()?);
        let mut connection = open_connection(&path, false)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "application_id", APP)?;
        connection.pragma_update(None, "user_version", VERSION)?;
        let root = genesis_root(&context);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for statement in [META_SQL, GROUP_SQL, CHILD_SQL, EVENT_SQL] {
            transaction.execute_batch(statement)?;
        }
        transaction.execute(
            "INSERT INTO journal_context(singleton,context,sequence,root) VALUES(1,?1,0,?2)",
            params![&context, root.as_slice()],
        )?;
        transaction.commit()?;
        parent.sync_all()?;
        let value = Self {
            path,
            lock_path,
            parent_path,
            database_identity,
            lock_identity,
            parent_identity,
            parent,
            owner_lock,
            connection,
            context,
            context_hash,
            state: State::default(),
            records: Vec::new(),
            root,
        };
        // This create-only namespace and its entire empty state are valid before
        // the first persistent WAL-mode change. Existing databases never take it.
        value.verify_storage()?;
        value
            .connection
            .pragma_update(None, "journal_mode", "WAL")?;
        configure_verified_writer(&value.connection)?;
        value.verify_storage()?;
        Ok(value)
    }
    pub fn open(path: &Path, config: NativeCellShardGroupJournalConfigV3) -> Result<Self> {
        let (path, parent_path, parent, context, context_hash) = paths_and_context(path, &config)?;
        let lock_path = path.with_extension("owner-v3.lock");
        let owner_lock = private_file(&lock_path, false)?;
        LockFileExt::try_lock_exclusive(&owner_lock)?;
        check_lock_bytes(&owner_lock, context_hash)?;
        let database = private_file(&path, false)?;
        let database_identity = identity(&database.metadata()?);
        let lock_identity = identity(&owner_lock.metadata()?);
        let parent_identity = identity(&parent.metadata()?);
        let reader = open_connection(&path, true)?;
        let transaction = reader.unchecked_transaction()?;
        check_schema(&transaction)?;
        let (sequence, root) = read_head(&transaction, &context)?;
        let records = read_records(&transaction)?;
        ensure(
            sequence == records.len(),
            "NATIVE_CELL_GROUP_JOURNAL_SEQUENCE",
        )?;
        let mut state = State::default();
        let mut previous = genesis_root(&context);
        for (index, record) in records.iter().enumerate() {
            ensure(
                record.previous == previous
                    && record.digest
                        == event_digest(context_hash, index + 1, previous, &record.payload),
                "NATIVE_CELL_GROUP_JOURNAL_CHAIN",
            )?;
            let event: Event = serde_json::from_slice(&record.payload)?;
            ensure(
                serde_json::to_vec(&event)? == record.payload,
                "NATIVE_CELL_GROUP_JOURNAL_CANONICAL_EVENT",
            )?;
            state.apply(&event)?;
            previous = record.digest;
        }
        ensure(previous == root, "NATIVE_CELL_GROUP_JOURNAL_ROOT")?;
        check_snapshot(&transaction, &state)?;
        let mode: String = transaction.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        ensure(mode == "wal", "NATIVE_CELL_GROUP_JOURNAL_MODE")?;
        transaction.commit()?;
        drop(reader);
        check_private_path(&path, database_identity)?;
        check_private_path(&lock_path, lock_identity)?;
        let connection = open_connection(&path, false)?;
        let value = Self {
            path,
            lock_path,
            parent_path,
            database_identity,
            lock_identity,
            parent_identity,
            parent,
            owner_lock,
            connection,
            context,
            context_hash,
            state,
            records,
            root,
        };
        // Audit the RW handle again before writer configuration. Its early close
        // policy covers all namespace/schema/context/history refusal paths too.
        value.verify_storage()?;
        configure_verified_writer(&value.connection)?;
        value.verify_storage()?;
        Ok(value)
    }
    pub(super) fn verify_context(
        &self,
        expected: &NativeCellShardGroupJournalConfigV3,
        deadline: Instant,
    ) -> Result<()> {
        self.guard(deadline)?;
        ensure(
            context_bytes(expected)? == self.context,
            "NATIVE_CELL_GROUP_JOURNAL_OWNER_CONTEXT",
        )?;
        check_deadline(deadline)
    }
    #[cfg(test)]
    pub(crate) fn test_register_group_v3(
        &mut self,
        plan: Hash,
        kind: super::types::NativeCellShardGroupKindV3,
        group: &super::types::NativeCellShardParentGroupV3,
        deadline: Instant,
    ) -> Result<()> {
        self.register(
            group.operation,
            &super::types::descriptor(plan, kind, group)?,
            &super::types::bindings(kind, group)?,
            true,
            deadline,
        )
    }
    #[cfg(test)]
    pub(crate) fn test_begin_child_v3(
        &mut self,
        group: Hash,
        index: usize,
        deadline: Instant,
    ) -> Result<()> {
        self.begin_child(group, index, deadline)
    }
    pub(super) fn register(
        &mut self,
        group: Hash,
        descriptor: &[u8],
        children: &[ChildBindingV3],
        allow_create: bool,
        deadline: Instant,
    ) -> Result<()> {
        self.guard(deadline)?;
        validate_roster(group, descriptor, children)?;
        if let Some(previous) = self.state.groups.get(&group) {
            require_record(previous, descriptor, children)?;
            return check_deadline(deadline);
        }
        ensure(allow_create, "NATIVE_CELL_GROUP_JOURNAL_MISSING_GROUP")?;
        self.append(
            Event::Register {
                group,
                descriptor_hex: hex::encode(descriptor),
                children: children.to_vec(),
            },
            deadline,
        )
    }
    pub(super) fn require_roster(
        &self,
        group: Hash,
        descriptor: &[u8],
        children: &[ChildBindingV3],
        deadline: Instant,
    ) -> Result<()> {
        self.guard(deadline)?;
        validate_roster(group, descriptor, children)?;
        let record = self
            .state
            .groups
            .get(&group)
            .ok_or("NATIVE_CELL_GROUP_JOURNAL_MISSING_GROUP")?;
        require_record(record, descriptor, children)?;
        check_deadline(deadline)
    }
    pub(super) fn state(
        &self,
        group: Hash,
        index: usize,
        deadline: Instant,
    ) -> Result<ChildStateV3> {
        self.guard(deadline)?;
        let state = self.state.child(group, index)?.state;
        check_deadline(deadline)?;
        Ok(state)
    }
    pub(super) fn begin_child(
        &mut self,
        group: Hash,
        index: usize,
        deadline: Instant,
    ) -> Result<()> {
        self.guard(deadline)?;
        ensure(
            self.state.child(group, index)?.state == ChildStateV3::Unstarted,
            "NATIVE_CELL_GROUP_JOURNAL_CHILD_ALREADY_STARTED",
        )?;
        self.append(Event::Begin { group, index }, deadline)
    }
    pub(super) fn complete_child(
        &mut self,
        group: Hash,
        index: usize,
        receipt: Hash,
        deadline: Instant,
    ) -> Result<()> {
        self.guard(deadline)?;
        ensure(receipt != [0; 32], "NATIVE_CELL_GROUP_JOURNAL_ZERO_RECEIPT")?;
        match self.state.child(group, index)?.state {
            ChildStateV3::Done(previous) => {
                ensure(
                    previous == receipt,
                    "NATIVE_CELL_GROUP_JOURNAL_RECEIPT_CHANGED",
                )?;
                check_deadline(deadline)
            }
            ChildStateV3::Pending => self.append(
                Event::Complete {
                    group,
                    index,
                    receipt,
                },
                deadline,
            ),
            ChildStateV3::Unstarted => Err("NATIVE_CELL_GROUP_JOURNAL_UNSTARTED_COMPLETION".into()),
        }
    }
    pub fn report(&self, deadline: Instant) -> Result<Value> {
        self.guard(deadline)?;
        let (mut unstarted, mut pending, mut done) = (0usize, 0usize, 0usize);
        for child in self.state.groups.values().flat_map(|g| &g.children) {
            match child.state {
                ChildStateV3::Unstarted => unstarted += 1,
                ChildStateV3::Pending => pending += 1,
                ChildStateV3::Done(_) => done += 1,
            }
        }
        let report = json!({"schema":"trnm.native-cell-group-child-journal.v3","context_sha256":hex::encode(self.context_hash),
   "groups":self.state.groups.len(),"children":unstarted+pending+done,"unstarted":unstarted,
   "pending":pending,"done":done,"events":self.records.len(),"root":hex::encode(self.root),
   "effect_dispatch_authority":false,"payment_or_positive_verdict":false});
        check_deadline(deadline)?;
        Ok(report)
    }
    fn guard(&self, deadline: Instant) -> Result<()> {
        check_deadline(deadline)?;
        self.verify_storage()?;
        check_deadline(deadline)
    }
    fn verify_storage(&self) -> Result<()> {
        check_private_path(&self.path, self.database_identity)?;
        check_private_path(&self.lock_path, self.lock_identity)?;
        let parent = fs::symlink_metadata(&self.parent_path)?;
        ensure(
            parent.file_type().is_dir()
                && identity(&parent) == self.parent_identity
                && identity(&self.parent.metadata()?) == self.parent_identity,
            "NATIVE_CELL_GROUP_JOURNAL_PARENT_REPLACED",
        )?;
        ensure(
            identity(&self.owner_lock.metadata()?) == self.lock_identity,
            "NATIVE_CELL_GROUP_JOURNAL_LOCK_REPLACED",
        )?;
        check_lock_bytes(&self.owner_lock, self.context_hash)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.audit_cached(&transaction)?;
        transaction.commit()?;
        Ok(())
    }
    fn audit_cached(&self, connection: &Connection) -> Result<()> {
        check_schema(connection)?;
        let (sequence, root) = read_head(connection, &self.context)?;
        ensure(
            sequence == self.records.len() && root == self.root,
            "NATIVE_CELL_GROUP_JOURNAL_HEAD_CHANGED",
        )?;
        // These exact cached records were validated by cold replay or append. A full
        // byte comparison detects old-history mutations without reparsing descriptors.
        ensure(
            read_records(connection)? == self.records,
            "NATIVE_CELL_GROUP_JOURNAL_HISTORY_CHANGED",
        )?;
        check_snapshot(connection, &self.state)
    }
    fn append(&mut self, event: Event, deadline: Instant) -> Result<()> {
        self.guard(deadline)?;
        let mut state = self.state.clone();
        state.apply(&event)?;
        let payload = serde_json::to_vec(&event)?;
        ensure(
            payload.len() <= MAX_EVENT_BYTES && self.records.len() < MAX_EVENTS,
            "NATIVE_CELL_GROUP_JOURNAL_EVENT_CAPACITY",
        )?;
        let sequence = self.records.len() + 1;
        let digest = event_digest(self.context_hash, sequence, self.root, &payload);
        let record = Record {
            previous: self.root,
            payload,
            digest,
        };
        let transaction =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_cached(&transaction)?;
        apply_sql(&transaction, &event)?;
        transaction.execute(
            "INSERT INTO events(sequence,previous,payload,digest) VALUES(?1,?2,?3,?4)",
            params![
                sequence as i64,
                self.root.as_slice(),
                &record.payload,
                digest.as_slice()
            ],
        )?;
        ensure(transaction.execute("UPDATE journal_context SET sequence=?1,root=?2 WHERE singleton=1 AND sequence=?3 AND root=?4",
   params![sequence as i64,digest.as_slice(),self.records.len() as i64,self.root.as_slice()])?==1,
   "NATIVE_CELL_GROUP_JOURNAL_HEAD_RACE")?;
        check_snapshot(&transaction, &state)?;
        check_deadline(deadline)?;
        transaction.commit()?;
        // Uncertain commit/readback never becomes a successful grant. A stale owner
        // refuses further work and must be dropped/reopened to inspect durable truth.
        self.state = state;
        self.records.push(record);
        self.root = digest;
        self.guard(deadline)
    }
}

fn check_snapshot(connection: &Connection, state: &State) -> Result<()> {
    let group_count: i64 = connection.query_row("SELECT count(*) FROM groups", [], |r| r.get(0))?;
    let child_count: i64 =
        connection.query_row("SELECT count(*) FROM children", [], |r| r.get(0))?;
    ensure(
        group_count == state.groups.len() as i64
            && child_count
                == state
                    .groups
                    .values()
                    .map(|g| g.children.len())
                    .sum::<usize>() as i64,
        "NATIVE_CELL_GROUP_JOURNAL_SNAPSHOT_COUNT",
    )?;
    for (group, expected) in &state.groups {
        let row:Option<(Vec<u8>,Option<Vec<u8>>,i64)>=connection.query_row(
   "SELECT CASE WHEN typeof(descriptor)='blob' AND length(descriptor)<=?2 THEN descriptor ELSE NULL END,CASE WHEN typeof(descriptor_hash)='blob' AND length(descriptor_hash)=32 THEN descriptor_hash ELSE NULL END,child_count FROM groups WHERE group_id=?1",
   params![group.as_slice(),MAX_DESCRIPTOR as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (descriptor, descriptor_hash, count) =
            row.ok_or("NATIVE_CELL_GROUP_JOURNAL_GROUP_ABSENT")?;
        ensure(
            descriptor == expected.descriptor
                && descriptor_hash
                    .ok_or("NATIVE_CELL_GROUP_JOURNAL_SNAPSHOT_ROSTER")?
                    .as_slice()
                    == digest(b"trnm.native-cell-group-child-descriptor.v3\0", &descriptor)
                        .as_slice()
                && count == expected.children.len() as i64,
            "NATIVE_CELL_GROUP_JOURNAL_SNAPSHOT_ROSTER",
        )?;
        let mut statement=connection.prepare(
   "SELECT ordinal,CASE WHEN typeof(operation)='blob' AND length(operation)=32 THEN operation ELSE NULL END,CASE WHEN typeof(effect)='blob' AND length(effect)=32 THEN effect ELSE NULL END,from_height,until_height,state,CASE WHEN typeof(receipt)='blob' AND length(receipt)=32 THEN receipt ELSE NULL END,(receipt IS NULL OR (typeof(receipt)='blob' AND length(receipt)=32)) FROM children WHERE group_id=?1 ORDER BY ordinal")?;
        let rows = statement.query_map([group.as_slice()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, bool>(7)?,
            ))
        })?;
        let mut seen = 0usize;
        for row in rows {
            let (ordinal, operation, effect, from, until, status, receipt, receipt_shape) = row?;
            ensure(receipt_shape, "NATIVE_CELL_GROUP_JOURNAL_RECEIPT")?;
            let operation = operation.ok_or("NATIVE_CELL_GROUP_JOURNAL_OPERATION")?;
            let effect = effect.ok_or("NATIVE_CELL_GROUP_JOURNAL_EFFECT")?;
            let child = expected
                .children
                .get(seen)
                .ok_or("NATIVE_CELL_GROUP_JOURNAL_CHILD_COUNT")?;
            let actual = match (status, receipt) {
                (0, None) => ChildStateV3::Unstarted,
                (1, None) => ChildStateV3::Pending,
                (2, Some(receipt)) => ChildStateV3::Done(
                    receipt
                        .try_into()
                        .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_RECEIPT")?,
                ),
                _ => return Err("NATIVE_CELL_GROUP_JOURNAL_CHILD_STATE".into()),
            };
            ensure(
                ordinal == seen as i64
                    && operation == child.binding.operation
                    && effect == child.binding.effect
                    && from == child.binding.from as i64
                    && until == child.binding.until as i64
                    && actual == child.state,
                "NATIVE_CELL_GROUP_JOURNAL_SNAPSHOT_CHILD",
            )?;
            seen += 1;
        }
        ensure(
            seen == expected.children.len(),
            "NATIVE_CELL_GROUP_JOURNAL_CHILD_COUNT",
        )?;
    }
    Ok(())
}
fn apply_sql(connection: &Connection, event: &Event) -> Result<()> {
    match event {
        Event::Register {
            group,
            descriptor_hex,
            children,
        } => {
            let descriptor = hex::decode(descriptor_hex)
                .map_err(|_| "NATIVE_CELL_GROUP_JOURNAL_DESCRIPTOR_ENCODING")?;
            let hash = digest(b"trnm.native-cell-group-child-descriptor.v3\0", &descriptor);
            connection.execute("INSERT INTO groups(group_id,descriptor,descriptor_hash,child_count) VALUES(?1,?2,?3,?4)",
    params![group.as_slice(),descriptor,hash.as_slice(),children.len()as i64])?;
            for (index, child) in children.iter().enumerate() {
                connection.execute("INSERT INTO children(group_id,ordinal,operation,effect,from_height,until_height,state,receipt) VALUES(?1,?2,?3,?4,?5,?6,0,NULL)",
     params![group.as_slice(),index as i64,child.operation.as_slice(),child.effect.as_slice(),
      child.from as i64,child.until as i64])?;
            }
        }
        Event::Begin { group, index } => {
            ensure(connection.execute(
    "UPDATE children SET state=1 WHERE group_id=?1 AND ordinal=?2 AND state=0 AND receipt IS NULL",
    params![group.as_slice(),*index as i64])?==1,"NATIVE_CELL_GROUP_JOURNAL_TRANSITION_RACE")?;
        }
        Event::Complete {
            group,
            index,
            receipt,
        } => {
            ensure(connection.execute(
    "UPDATE children SET state=2,receipt=?3 WHERE group_id=?1 AND ordinal=?2 AND state=1 AND receipt IS NULL",
    params![group.as_slice(),*index as i64,receipt.as_slice()])?==1,"NATIVE_CELL_GROUP_JOURNAL_TRANSITION_RACE")?;
        }
    }
    Ok(())
}
fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
fn genesis_root(context: &[u8]) -> Hash {
    digest(b"trnm.native-cell-group-child-genesis.v3\0", context)
}
fn event_digest(context: Hash, sequence: usize, previous: Hash, payload: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"trnm.native-cell-group-child-event.v3\0");
    hash.update(context);
    hash.update((sequence as u64).to_be_bytes());
    hash.update(previous);
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}
fn check_deadline(deadline: Instant) -> Result<()> {
    ensure(
        Instant::now() < deadline,
        "NATIVE_CELL_GROUP_JOURNAL_DEADLINE",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn config() -> NativeCellShardGroupJournalConfigV3 {
        NativeCellShardGroupJournalConfigV3 {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            plan: [4; 32],
            owner_generation: 1,
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn children() -> Vec<ChildBindingV3> {
        vec![
            ChildBindingV3 {
                operation: [11; 32],
                effect: [12; 32],
                from: 1,
                until: 10,
            },
            ChildBindingV3 {
                operation: [13; 32],
                effect: [14; 32],
                from: 1,
                until: 10,
            },
        ]
    }
    #[test]
    fn group_child_journal_cold_open_retains_real_pending_and_done() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let group = [21; 32];
        let mut store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        store
            .register(group, b"original descriptor", &children(), true, deadline())
            .unwrap();
        assert!(store
            .complete_child(group, 0, [31; 32], deadline())
            .is_err());
        store.begin_child(group, 0, deadline()).unwrap();
        store
            .complete_child(group, 0, [31; 32], deadline())
            .unwrap();
        store.begin_child(group, 1, deadline()).unwrap();
        let before = store.report(deadline()).unwrap();
        drop(store);
        let mut opened = NativeCellShardGroupJournalV3::open(&path, config()).unwrap();
        assert_eq!(opened.report(deadline()).unwrap(), before);
        assert_eq!(
            opened.state(group, 0, deadline()).unwrap(),
            ChildStateV3::Done([31; 32])
        );
        assert_eq!(
            opened.state(group, 1, deadline()).unwrap(),
            ChildStateV3::Pending
        );
        assert!(opened.begin_child(group, 1, deadline()).is_err());
        opened
            .complete_child(group, 1, [32; 32], deadline())
            .unwrap();
        let before = opened.report(deadline()).unwrap();
        opened
            .complete_child(group, 1, [32; 32], deadline())
            .unwrap();
        assert_eq!(opened.report(deadline()).unwrap(), before);
        assert!(opened
            .complete_child(group, 1, [33; 32], deadline())
            .is_err());
    }
    #[test]
    fn group_child_journal_missing_changed_and_foreign_rosters_refuse_without_new_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let group = [21; 32];
        let mut store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        assert!(store
            .register(group, b"descriptor", &children(), false, deadline())
            .is_err());
        assert_eq!(store.report(deadline()).unwrap()["groups"], 0);
        store
            .register(group, b"descriptor", &children(), true, deadline())
            .unwrap();
        let before = store.report(deadline()).unwrap();
        assert!(store
            .register(group, b"changed", &children(), true, deadline())
            .is_err());
        let mut changed = children();
        changed.swap(0, 1);
        assert!(store
            .require_roster(group, b"descriptor", &changed, deadline())
            .is_err());
        assert_eq!(store.report(deadline()).unwrap(), before);
        assert!(store
            .register([22; 32], b"second", &children(), true, deadline())
            .is_err());
        let aliases = vec![ChildBindingV3 {
            operation: group,
            effect: [55; 32],
            from: 1,
            until: 10,
        }];
        assert!(store
            .register([23; 32], b"third", &aliases, true, deadline())
            .is_err());
        assert_eq!(store.report(deadline()).unwrap(), before);
    }
    #[test]
    fn group_child_journal_foreign_snapshot_history_and_context_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let group = [21; 32];
        let mut store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        store
            .register(group, b"descriptor", &children(), true, deadline())
            .unwrap();
        let foreign = Connection::open(&path).unwrap();
        foreign
            .execute("UPDATE children SET state=1 WHERE ordinal=0", [])
            .unwrap();
        assert!(store.state(group, 0, deadline()).is_err());
        drop(foreign);
        drop(store);
        assert!(NativeCellShardGroupJournalV3::open(&path, config()).is_err());
        let other = dir.path().join("other.sqlite");
        let mut store = NativeCellShardGroupJournalV3::create(&other, config()).unwrap();
        store
            .register(group, b"descriptor", &children(), true, deadline())
            .unwrap();
        let mut changed = config();
        changed.owner_generation += 1;
        assert!(store.verify_context(&changed, deadline()).is_err());
        drop(store);
        assert!(NativeCellShardGroupJournalV3::open(&other, changed).is_err());
        let connection = Connection::open(&other).unwrap();
        connection
            .execute(
                "UPDATE events SET payload=zeroblob(length(payload)) WHERE sequence=1",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(NativeCellShardGroupJournalV3::open(&other, config()).is_err());
    }
    #[test]
    fn group_child_journal_exclusive_owner_and_replaced_path_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        assert!(NativeCellShardGroupJournalV3::open(&path, config()).is_err());
        let replacement = dir.path().join("replacement");
        fs::copy(&path, &replacement).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(store.report(deadline()).is_err());
    }
    #[test]
    fn group_child_journal_expiry_and_structural_bounds_cannot_start_children() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let group = [21; 32];
        let mut store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(store
            .register(group, b"descriptor", &children(), true, past)
            .is_err());
        assert_eq!(store.report(deadline()).unwrap()["events"], 0);
        let mut duplicate = children();
        duplicate.push(duplicate[0].clone());
        assert!(store
            .register(group, b"descriptor", &duplicate, true, deadline())
            .is_err());
        assert!(store
            .register(
                group,
                &vec![1; MAX_DESCRIPTOR + 1],
                &children(),
                true,
                deadline()
            )
            .is_err());
        store
            .register(group, b"descriptor", &children(), true, deadline())
            .unwrap();
        assert!(store.begin_child(group, 0, past).is_err());
        assert_eq!(
            store.state(group, 0, deadline()).unwrap(),
            ChildStateV3::Unstarted
        );
    }
    #[test]
    fn group_child_journal_bounds_full_64_group_1024_child_roster() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("children.sqlite");
        let mut store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
        for group in 0..MAX_GROUPS {
            let children: Vec<_> = (0..MAX_GROUP_CHILDREN)
                .map(|index| {
                    let ordinal = (group * MAX_GROUP_CHILDREN + index) as u64;
                    ChildBindingV3 {
                        operation: digest(b"test-child", &ordinal.to_be_bytes()),
                        effect: digest(b"test-effect", &ordinal.to_be_bytes()),
                        from: 1,
                        until: 10,
                    }
                })
                .collect();
            store
                .register(
                    digest(b"test-group", &(group as u64).to_be_bytes()),
                    b"x",
                    &children,
                    true,
                    deadline(),
                )
                .unwrap();
        }
        let before = store.report(deadline()).unwrap();
        assert_eq!(before["groups"], MAX_GROUPS);
        assert_eq!(before["children"], MAX_CHILDREN);
        let foreign = vec![ChildBindingV3 {
            operation: [99; 32],
            effect: [100; 32],
            from: 1,
            until: 10,
        }];
        assert!(store
            .register([101; 32], b"x", &foreign, true, deadline())
            .is_err());
        assert_eq!(store.report(deadline()).unwrap(), before);
    }
    fn durable_database_bytes(path: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        ["", "-wal"]
            .into_iter()
            .map(|suffix| {
                let name = format!("{}{suffix}", path.to_str().unwrap());
                (suffix.to_string(), fs::read(name).ok())
            })
            .collect()
    }
    #[test]
    fn group_child_journal_refusal_preserves_foreign_and_old_database_bytes() {
        let dir = tempfile::tempdir().unwrap();
        for (name, mode, application, version) in [
            ("foreign-delete", "delete", APP - 1, VERSION),
            ("old-delete", "delete", APP, VERSION - 1),
            ("foreign-wal", "wal", APP - 1, VERSION),
            ("wrong-schema", "delete", APP, VERSION),
        ] {
            let path = dir.path().join(format!("{name}.sqlite"));
            let database = private_file(&path, true).unwrap();
            drop(database);
            let context = context_bytes(&config()).unwrap();
            let mut lock = private_file(&path.with_extension("owner-v3.lock"), true).unwrap();
            lock.write_all(&digest(
                b"trnm.native-cell-group-child-context.v3\0",
                &context,
            ))
            .unwrap();
            lock.sync_all().unwrap();
            drop(lock);
            let foreign = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .unwrap();
            // Independent fixture setup retains committed WAL frames after closing.
            // The probe must neither switch DELETE mode nor checkpoint an existing WAL.
            assert!(foreign
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .unwrap());
            foreign.pragma_update(None, "journal_mode", mode).unwrap();
            foreign
                .pragma_update(None, "application_id", application)
                .unwrap();
            foreign
                .pragma_update(None, "user_version", version)
                .unwrap();
            foreign.execute_batch("CREATE TABLE foreign_payload(value BLOB); INSERT INTO foreign_payload VALUES(zeroblob(32768));").unwrap();
            drop(foreign);
            let before = durable_database_bytes(&path);
            if mode == "wal" {
                assert!(before[1].1.as_ref().is_some_and(|bytes| !bytes.is_empty()));
            }
            assert!(
                NativeCellShardGroupJournalV3::open(&path, config()).is_err(),
                "{name}"
            );
            assert_eq!(
                durable_database_bytes(&path),
                before,
                "refusal changed {name}"
            );
        }
    }
    #[test]
    fn group_child_journal_readonly_refusal_preserves_corrupt_context_chain_and_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        for (name, damage) in [
            (
                "context",
                "UPDATE journal_context SET context=zeroblob(length(context)) WHERE singleton=1",
            ),
            (
                "chain",
                "UPDATE events SET payload=zeroblob(length(payload)) WHERE sequence=1",
            ),
            ("snapshot", "UPDATE children SET state=1 WHERE ordinal=1"),
        ] {
            let path = dir.path().join(format!("{name}.sqlite"));
            let mut original = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
            original
                .register([21; 32], b"original", &children(), true, deadline())
                .unwrap();
            original.begin_child([21; 32], 0, deadline()).unwrap();
            drop(original);
            let foreign = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .unwrap();
            assert!(foreign
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .unwrap());
            foreign.execute(damage, []).unwrap();
            drop(foreign);
            let before = durable_database_bytes(&path);
            assert!(before[1].1.as_ref().is_some_and(|bytes| !bytes.is_empty()));
            assert!(
                NativeCellShardGroupJournalV3::open(&path, config()).is_err(),
                "{name}"
            );
            assert_eq!(
                durable_database_bytes(&path),
                before,
                "refusal changed {name}"
            );
        }
    }
    #[test]
    fn group_child_journal_schema_caps_and_oversized_non_null_sql_are_not_null() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["extra-object", "oversized-index-sql"] {
            let path = dir.path().join(format!("{name}.sqlite"));
            let store = NativeCellShardGroupJournalV3::create(&path, config()).unwrap();
            let foreign = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .unwrap();
            assert!(foreign
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .unwrap());
            let expected = if name == "extra-object" {
                foreign
                    .execute_batch("CREATE TABLE foreign_extra(value BLOB);")
                    .unwrap();
                "NATIVE_CELL_GROUP_JOURNAL_SCHEMA_COUNT"
            } else {
                foreign
                    .pragma_update(None, "writable_schema", true)
                    .unwrap();
                foreign
                    .execute(
                        "UPDATE sqlite_master SET sql=?1 WHERE name='sqlite_autoindex_children_2'",
                        ["x".repeat(8192)],
                    )
                    .unwrap();
                foreign
                    .pragma_update(None, "writable_schema", false)
                    .unwrap();
                "NATIVE_CELL_GROUP_JOURNAL_SCHEMA_SQL_SHAPE"
            };
            drop(foreign);
            let before = durable_database_bytes(&path);
            assert_eq!(store.report(deadline()).unwrap_err().to_string(), expected);
            assert_eq!(
                durable_database_bytes(&path),
                before,
                "schema refusal changed {name}"
            );
        }
    }
}
