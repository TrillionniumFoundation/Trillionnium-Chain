//! Private schema2 storage underneath the actual epoch runtime owner.
//! No scalar migration or decoded comparison record grants activation.
use super::*;
use crate::epoch_node_checkpoint_v1::{
    epoch_origin_checksum_v1, EpochCheckpointPredecessorV1, EpochNodeCheckpointV1,
};
use rusqlite::{limits::Limit, types::ValueRef};

const MAX_FILE: u64 = 8 * 1024 * 1024;
const MAX_SHM: u64 = 64 * 1024;
const CREATE_ORIGIN: &str = "CREATE TABLE epoch_node_origin (lineage_id BLOB NOT NULL PRIMARY KEY CHECK(length(lineage_id)=32), origin_checksum BLOB NOT NULL CHECK(length(origin_checksum)=32), predecessor_kind INTEGER NOT NULL CHECK(predecessor_kind BETWEEN 0 AND 2), original_record BLOB NOT NULL CHECK(length(original_record) BETWEEN 1 AND 8192)) STRICT, WITHOUT ROWID";
const CREATE_RECORDS: &str = "CREATE TABLE epoch_node_records (lineage_id BLOB NOT NULL CHECK(length(lineage_id)=32), generation BLOB NOT NULL CHECK(length(generation)=8), predecessor_checksum BLOB NOT NULL CHECK(length(predecessor_checksum)=32), checksum BLOB NOT NULL CHECK(length(checksum)=32), record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 8192), PRIMARY KEY(lineage_id,generation)) STRICT, WITHOUT ROWID";
const CREATE_HEAD: &str = "CREATE TABLE epoch_node_head (lineage_id BLOB NOT NULL PRIMARY KEY CHECK(length(lineage_id)=32), generation BLOB NOT NULL CHECK(length(generation)=8), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT, WITHOUT ROWID";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochNodeStoreErrorV1 {
    OwnerFenced,
    InvalidState,
    CompareFailed,
    MultipleLineagesRequireExplicitMigration,
    CommitUncertain,
}
impl fmt::Display for EpochNodeStoreErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch node store: {self:?}")
    }
}
impl Error for EpochNodeStoreErrorV1 {}
type Result<T> = std::result::Result<T, EpochNodeStoreErrorV1>;
fn sql(_: rusqlite::Error) -> EpochNodeStoreErrorV1 {
    EpochNodeStoreErrorV1::InvalidState
}
fn owner(_: ExternalNodeCheckpointStoreErrorV0) -> EpochNodeStoreErrorV1 {
    EpochNodeStoreErrorV1::OwnerFenced
}

/// Independent comparison store. Only the concrete epoch runtime can migrate
/// or append; opening and reading this store cannot produce a Core or signer.
pub struct SqliteEpochNodeCheckpointStoreV1 {
    path: PathBuf,
    identity: SqliteCheckpointPathIdentityV0,
    sidecars: [Option<SqliteCheckpointPathIdentityV0>; 2],
    connection: Option<Connection>,
    lineage: [u8; 32],
    origin: [u8; 32],
}
impl SqliteEpochNodeCheckpointStoreV1 {
    pub fn open_existing(path: impl AsRef<Path>, expected: &EpochNodeCheckpointV1) -> Result<Self> {
        let path = validate_sqlite_database_path_v0(path.as_ref()).map_err(owner)?;
        let identity = inspect_sqlite_path_identity_v0(&path).map_err(owner)?;
        let before_sidecars = check_files(&path, identity)?;
        if before_sidecars.iter().any(Option::is_none) {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        let connection = open_sqlite_checkpoint_connection_v0(&path).map_err(owner)?;
        configure(&connection)?;
        let actual = audit(
            &connection,
            expected.fields().lineage_id,
            expected.fields().origin_checksum,
        )?;
        if actual != *expected {
            return Err(EpochNodeStoreErrorV1::CompareFailed);
        }
        validate_sqlite_path_identity_v0(&path, identity).map_err(owner)?;
        let sidecars = check_files(&path, identity)?;
        if sidecars != before_sidecars {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        let mut store = Self {
            path,
            identity,
            sidecars,
            connection: Some(connection),
            lineage: expected.fields().lineage_id,
            origin: expected.fields().origin_checksum,
        };
        store.confirm_exact(expected)?;
        Ok(store)
    }
    pub(crate) fn original_v0(
        &mut self,
        expected: &EpochNodeCheckpointV1,
    ) -> Result<ExternalNodeCheckpointV0> {
        self.confirm_exact(expected)?;
        let connection = self
            .connection
            .as_ref()
            .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?;
        let mut statement = connection
            .prepare("SELECT original_record FROM epoch_node_origin LIMIT 2")
            .map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        let row = rows
            .next()
            .map_err(sql)?
            .ok_or(EpochNodeStoreErrorV1::InvalidState)?;
        let bytes = blob(row, 0, 1, 8192)?;
        if epoch_origin_checksum_v1(bytes) != self.origin {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        let record = ExternalNodeCheckpointV0::decode_canonical_exact(bytes)
            .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?;
        if rows.next().map_err(sql)?.is_some() {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        self.check_owner()?;
        Ok(record)
    }
    pub fn database_path(&self) -> &Path {
        &self.path
    }
    pub fn load(&mut self) -> Result<EpochNodeCheckpointV1> {
        let result = self.load_inner();
        if result.is_err() {
            self.connection.take();
        }
        result
    }
    fn load_inner(&self) -> Result<EpochNodeCheckpointV1> {
        self.check_owner()?;
        let connection = self
            .connection
            .as_ref()
            .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?;
        // One SQLite read transaction prevents mixing origins/records/head from
        // different concurrent CAS cuts. Every SELECT has a bounded row count.
        let transaction = connection.unchecked_transaction().map_err(sql)?;
        let current = audit(&transaction, self.lineage, self.origin)?;
        transaction.commit().map_err(sql)?;
        self.check_owner()?;
        Ok(current)
    }
    fn check_owner(&self) -> Result<()> {
        if self.connection.is_none() {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        validate_sqlite_path_identity_v0(&self.path, self.identity).map_err(owner)?;
        if check_files(&self.path, self.identity)? != self.sidecars {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        Ok(())
    }
    pub(crate) fn confirm_exact(&mut self, expected: &EpochNodeCheckpointV1) -> Result<()> {
        let result = (|| {
            if self.load_inner()? != *expected {
                return Err(EpochNodeStoreErrorV1::CompareFailed);
            }
            self.sync()?;
            if self.load_inner()? != *expected {
                return Err(EpochNodeStoreErrorV1::CompareFailed);
            }
            Ok(())
        })();
        if result.is_err() {
            self.connection.take();
        }
        result
    }
    fn sync(&self) -> Result<()> {
        self.check_owner()?;
        self.connection
            .as_ref()
            .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
            .map_err(sql)?;
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
            let before = inspect_sqlite_path_identity_v0(&path).map_err(owner)?;
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|_| EpochNodeStoreErrorV1::OwnerFenced)?;
            if inspect_sqlite_file_identity_v0(&file).map_err(owner)? != before {
                return Err(EpochNodeStoreErrorV1::OwnerFenced);
            }
            file.sync_all()
                .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
            validate_sqlite_path_identity_v0(&path, before).map_err(owner)?;
        }
        File::open(
            self.path
                .parent()
                .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?,
        )
        .and_then(|f| f.sync_all())
        .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        self.check_owner()
    }
    /// Consumes the real V0 owner; the caller has already joined the actual
    /// Safety/native/retired/new-custody owners. This cannot be called externally.
    pub(crate) fn migrate_continuing_v0(
        old: SqliteExternalNodeCheckpointStoreV0,
        expected: &ExternalNodeCheckpointV0,
        target: &EpochNodeCheckpointV1,
    ) -> Result<Self> {
        Self::migrate_observed(old, expected, target, |_| Ok(()))
    }
    fn migrate_observed(
        mut old: SqliteExternalNodeCheckpointStoreV0,
        expected: &ExternalNodeCheckpointV0,
        target: &EpochNodeCheckpointV1,
        mut observe: impl FnMut(&str) -> Result<()>,
    ) -> Result<Self> {
        target
            .validate_first_continuing_v0(expected)
            .map_err(|_| EpochNodeStoreErrorV1::CompareFailed)?;
        old.confirm_exact_durable_v1(*expected).map_err(owner)?;
        let source_sidecars = check_files(&old.database_path, old.path_identity)?;
        if source_sidecars.iter().any(Option::is_none) {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        let mut connection = old
            .connection
            .take()
            .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?;
        configure(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        validate_sqlite_checkpoint_schema_v0(&transaction).map_err(owner)?;
        let count: usize = transaction
            .query_row(
                "SELECT count(*) FROM (SELECT 1 FROM trnm_external_node_checkpoint_v0 LIMIT 2)",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if count != 1 {
            return Err(EpochNodeStoreErrorV1::MultipleLineagesRequireExplicitMigration);
        }
        if load_sqlite_checkpoint_row_v0(&transaction, expected.scope()).map_err(owner)?
            != Some(*expected)
        {
            return Err(EpochNodeStoreErrorV1::CompareFailed);
        }
        for schema in [CREATE_ORIGIN, CREATE_RECORDS, CREATE_HEAD] {
            transaction.execute(schema, []).map_err(sql)?;
        }
        transaction
            .execute(
                "INSERT INTO epoch_node_origin VALUES (?1,?2,0,?3)",
                params![
                    &target.fields().lineage_id,
                    &target.fields().origin_checksum,
                    &expected.encode_canonical()[..]
                ],
            )
            .map_err(sql)?;
        insert_record(&transaction, target)?;
        transaction
            .execute(
                "INSERT INTO epoch_node_head VALUES (?1,?2,?3)",
                params![
                    &target.fields().lineage_id,
                    &target.fields().generation.to_be_bytes(),
                    &target.checksum()
                ],
            )
            .map_err(sql)?;
        transaction
            .execute("DROP TABLE trnm_external_node_checkpoint_v0", [])
            .map_err(sql)?;
        transaction
            .pragma_update(None, "user_version", 2)
            .map_err(sql)?;
        if audit(
            &transaction,
            target.fields().lineage_id,
            target.fields().origin_checksum,
        )? != *target
        {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        observe("migration-before-commit")?;
        if check_files(&old.database_path, old.path_identity)? != source_sidecars {
            return Err(EpochNodeStoreErrorV1::OwnerFenced);
        }
        cut("migration-before-commit");
        transaction
            .commit()
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        cut("migration-after-commit");
        observe("migration-after-commit").map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        let sidecars = check_files(&old.database_path, old.path_identity)
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        if sidecars != source_sidecars {
            return Err(EpochNodeStoreErrorV1::CommitUncertain);
        }
        let mut store = Self {
            path: old.database_path,
            identity: old.path_identity,
            sidecars,
            connection: Some(connection),
            lineage: target.fields().lineage_id,
            origin: target.fields().origin_checksum,
        };
        store
            .sync()
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        cut("migration-after-sync");
        store
            .confirm_exact(target)
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        Ok(store)
    }
    pub(crate) fn compare_and_advance(
        &mut self,
        expected: &EpochNodeCheckpointV1,
        target: &EpochNodeCheckpointV1,
    ) -> Result<()> {
        let result = self.advance_inner(expected, target);
        if result.is_err() {
            self.connection.take();
        }
        result
    }
    fn advance_inner(
        &mut self,
        expected: &EpochNodeCheckpointV1,
        target: &EpochNodeCheckpointV1,
    ) -> Result<()> {
        target
            .validate_successor_of(expected)
            .map_err(|_| EpochNodeStoreErrorV1::CompareFailed)?;
        self.check_owner()?;
        let transaction = self
            .connection
            .as_mut()
            .ok_or(EpochNodeStoreErrorV1::OwnerFenced)?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let actual = audit(&transaction, self.lineage, self.origin)?;
        if actual == *target {
            transaction.commit().map_err(sql)?;
            return self.confirm_exact(target);
        }
        if actual != *expected {
            return Err(EpochNodeStoreErrorV1::CompareFailed);
        }
        insert_record(&transaction, target)?;
        let changed=transaction.execute("UPDATE epoch_node_head SET generation=?1,checksum=?2 WHERE lineage_id=?3 AND generation=?4 AND checksum=?5",params![&target.fields().generation.to_be_bytes(),&target.checksum(),&self.lineage,&expected.fields().generation.to_be_bytes(),&expected.checksum()]).map_err(sql)?;
        if changed != 1 {
            return Err(EpochNodeStoreErrorV1::CompareFailed);
        }
        transaction.execute("DELETE FROM epoch_node_records WHERE lineage_id=?1 AND generation<>?2 AND generation<>?3",params![&self.lineage,&expected.fields().generation.to_be_bytes(),&target.fields().generation.to_be_bytes()]).map_err(sql)?;
        if audit(&transaction, self.lineage, self.origin)? != *target {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        transaction
            .commit()
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)?;
        self.confirm_exact(target)
            .map_err(|_| EpochNodeStoreErrorV1::CommitUncertain)
    }
}
fn insert_record(connection: &Connection, value: &EpochNodeCheckpointV1) -> Result<()> {
    connection
        .execute(
            "INSERT INTO epoch_node_records VALUES (?1,?2,?3,?4,?5)",
            params![
                &value.fields().lineage_id,
                &value.fields().generation.to_be_bytes(),
                &value.fields().predecessor_checksum,
                &value.checksum(),
                &value.encode_canonical()
            ],
        )
        .map_err(sql)?;
    Ok(())
}
fn configure(connection: &Connection) -> Result<()> {
    // Use SQLite's safe configuration API: retain WAL/SHM on owner close.
    // Explicit sync below handles durability; a cold reopen must never create
    // an absent sidecar in place of the independently pinned namespace.
    connection
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .map_err(sql)?;
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 12 * 1024);
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024);
    connection
        .busy_timeout(Duration::from_millis(100))
        .map_err(sql)?;
    connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA recursive_triggers=OFF; PRAGMA cache_size=-256; PRAGMA max_page_count=2048; PRAGMA journal_size_limit=8388608; PRAGMA wal_autocheckpoint=32;").map_err(sql)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(sql)?;
    let page: i64 = connection
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(sql)?;
    if mode != "wal" || page != 4096 {
        return Err(EpochNodeStoreErrorV1::InvalidState);
    }
    Ok(())
}
fn check_files(
    path: &Path,
    identity: SqliteCheckpointPathIdentityV0,
) -> Result<[Option<SqliteCheckpointPathIdentityV0>; 2]> {
    validate_sqlite_path_identity_v0(path, identity).map_err(owner)?;
    if fs::metadata(path)
        .map_err(|_| EpochNodeStoreErrorV1::OwnerFenced)?
        .len()
        > MAX_FILE
    {
        return Err(EpochNodeStoreErrorV1::InvalidState);
    }
    let mut out = [None, None];
    for (i, suffix) in ["-wal", "-shm"].iter().enumerate() {
        let side = PathBuf::from(format!("{}{}", path.display(), suffix));
        match fs::symlink_metadata(&side) {
            Ok(meta) => {
                let pin = inspect_sqlite_path_identity_v0(&side).map_err(owner)?;
                #[cfg(unix)]
                if pin.owner != identity.owner {
                    return Err(EpochNodeStoreErrorV1::OwnerFenced);
                }
                if meta.len() > if i == 0 { MAX_FILE } else { MAX_SHM } {
                    return Err(EpochNodeStoreErrorV1::InvalidState);
                }
                out[i] = Some(pin);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(EpochNodeStoreErrorV1::OwnerFenced),
        }
    }
    Ok(out)
}
fn blob<'a>(row: &'a rusqlite::Row<'_>, index: usize, min: usize, max: usize) -> Result<&'a [u8]> {
    match row.get_ref(index).map_err(sql)? {
        ValueRef::Blob(v) if (min..=max).contains(&v.len()) => Ok(v),
        _ => Err(EpochNodeStoreErrorV1::InvalidState),
    }
}
fn array<const N: usize>(row: &rusqlite::Row<'_>, index: usize) -> Result<[u8; N]> {
    blob(row, index, N, N)?
        .try_into()
        .map_err(|_| EpochNodeStoreErrorV1::InvalidState)
}
fn schema(connection: &Connection) -> Result<()> {
    let app: i64 = connection
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(sql)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(sql)?;
    if app != SQLITE_APPLICATION_ID_V0 || version != 2 {
        return Err(EpochNodeStoreErrorV1::InvalidState);
    }
    let mut statement = connection
        .prepare("SELECT type,name,sql FROM sqlite_schema LIMIT 4")
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    let mut seen = Vec::new();
    while let Some(row) = rows.next().map_err(sql)? {
        let mut fields = Vec::new();
        for i in 0..3 {
            match row.get_ref(i).map_err(sql)? {
                ValueRef::Text(v) if v.len() <= 4096 => fields.push(v.to_vec()),
                _ => return Err(EpochNodeStoreErrorV1::InvalidState),
            }
        }
        seen.push(fields);
    }
    let mut expected = vec![
        vec![
            b"table".to_vec(),
            b"epoch_node_origin".to_vec(),
            CREATE_ORIGIN.as_bytes().to_vec(),
        ],
        vec![
            b"table".to_vec(),
            b"epoch_node_records".to_vec(),
            CREATE_RECORDS.as_bytes().to_vec(),
        ],
        vec![
            b"table".to_vec(),
            b"epoch_node_head".to_vec(),
            CREATE_HEAD.as_bytes().to_vec(),
        ],
    ];
    seen.sort();
    expected.sort();
    if seen != expected {
        return Err(EpochNodeStoreErrorV1::InvalidState);
    }
    Ok(())
}
fn audit(
    connection: &Connection,
    lineage: [u8; 32],
    origin: [u8; 32],
) -> Result<EpochNodeCheckpointV1> {
    schema(connection)?;
    let original = {
        let mut statement=connection.prepare("SELECT lineage_id,origin_checksum,predecessor_kind,original_record FROM epoch_node_origin LIMIT 2").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        let row = rows
            .next()
            .map_err(sql)?
            .ok_or(EpochNodeStoreErrorV1::InvalidState)?;
        if array::<32>(row, 0)? != lineage
            || array::<32>(row, 1)? != origin
            || row.get_ref(2).map_err(sql)? != ValueRef::Integer(0)
        {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        let bytes = blob(row, 3, 1, 8192)?;
        if epoch_origin_checksum_v1(bytes) != origin {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        let value = ExternalNodeCheckpointV0::decode_canonical_exact(bytes)
            .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?;
        if value.scope() != lineage || rows.next().map_err(sql)?.is_some() {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        value
    };
    let (generation, checksum) = {
        let mut statement = connection
            .prepare("SELECT lineage_id,generation,checksum FROM epoch_node_head LIMIT 2")
            .map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        let row = rows
            .next()
            .map_err(sql)?
            .ok_or(EpochNodeStoreErrorV1::InvalidState)?;
        if array::<32>(row, 0)? != lineage {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        let out = (u64::from_be_bytes(array(row, 1)?), array::<32>(row, 2)?);
        if rows.next().map_err(sql)?.is_some() {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        out
    };
    let mut records = Vec::with_capacity(3);
    let mut statement=connection.prepare("SELECT lineage_id,generation,predecessor_checksum,checksum,record FROM epoch_node_records LIMIT 3").map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let value = EpochNodeCheckpointV1::decode_canonical_exact(blob(row, 4, 1, 8192)?)
            .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?;
        if array::<32>(row, 0)? != lineage
            || value.fields().lineage_id != lineage
            || value.fields().origin_checksum != origin
            || u64::from_be_bytes(array(row, 1)?) != value.fields().generation
            || array::<32>(row, 2)? != value.fields().predecessor_checksum
            || array::<32>(row, 3)? != value.checksum()
        {
            return Err(EpochNodeStoreErrorV1::InvalidState);
        }
        records.push(value);
    }
    records.sort_by_key(|r| r.fields().generation);
    let current = *records.last().ok_or(EpochNodeStoreErrorV1::InvalidState)?;
    if current.fields().generation != generation || current.checksum() != checksum {
        return Err(EpochNodeStoreErrorV1::InvalidState);
    }
    match records.as_slice() {
        [first] => first
            .validate_first_continuing_v0(&original)
            .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?,
        [previous, current] => {
            current
                .validate_successor_of(previous)
                .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?;
            if previous.fields().predecessor_kind == EpochCheckpointPredecessorV1::TerminalV0 {
                previous
                    .validate_first_continuing_v0(&original)
                    .map_err(|_| EpochNodeStoreErrorV1::InvalidState)?;
            } else if previous.fields().predecessor_kind != EpochCheckpointPredecessorV1::V1
                || previous.fields().generation
                    <= original
                        .generation()
                        .checked_add(1)
                        .ok_or(EpochNodeStoreErrorV1::InvalidState)?
            {
                return Err(EpochNodeStoreErrorV1::InvalidState);
            }
        }
        _ => return Err(EpochNodeStoreErrorV1::InvalidState),
    }
    Ok(current)
}
#[cfg(not(test))]
fn cut(_: &str) {}
#[cfg(test)]
fn cut(name: &str) {
    if std::env::var("TRNM_EPOCH_NODE_CRASH_CUT").ok().as_deref() == Some(name) {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &std::process::id().to_string()])
            .status();
        panic!("SIGKILL failed");
    }
}
#[cfg(test)]
#[path = "epoch_node_checkpoint_store_v1_tests.rs"]
mod tests;
