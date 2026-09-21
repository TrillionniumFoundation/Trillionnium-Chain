//! Private physical journal machinery. No Core state, codec, source trust,
//! persistence affinity or acknowledgement is interpreted by this module.
use crate::epoch_preparation_sqlite_v1 as fs_owner;
use fs_owner::{EpochPreparationStoreErrorV1, PinnedFileV1};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{io::Write, path::Path};

#[derive(Debug)]
pub(crate) enum PhysicalJournalErrorV2 {
    Namespace(EpochPreparationStoreErrorV1),
    Sqlite(rusqlite::Error),
    Invalid(&'static str),
    Fenced,
}
impl From<EpochPreparationStoreErrorV1> for PhysicalJournalErrorV2 {
    fn from(error: EpochPreparationStoreErrorV1) -> Self {
        Self::Namespace(error)
    }
}
impl From<rusqlite::Error> for PhysicalJournalErrorV2 {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
type Result<T> = std::result::Result<T, PhysicalJournalErrorV2>;
fn invalid<T>(why: &'static str) -> Result<T> {
    Err(PhysicalJournalErrorV2::Invalid(why))
}
fn io(stage: &'static str, error: std::io::Error) -> PhysicalJournalErrorV2 {
    EpochPreparationStoreErrorV1::Io { stage, error }.into()
}

/// Closed physical layouts. Callers cannot supply a schema, lock marker or
/// application ID which would reinterpret a different journal namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalLayoutV2 {
    Codec1,
    Codec2,
    Codec2PrefixOnce,
}
impl JournalLayoutV2 {
    fn sql(self) -> &'static str {
        match self {
            Self::Codec1 => include_str!("epoch_journal_v1.sql"),
            Self::Codec2 => include_str!("epoch_journal_v2.sql"),
            Self::Codec2PrefixOnce => include_str!("epoch_journal_v3.sql"),
        }
    }
    fn application_id(self) -> i64 {
        match self {
            Self::Codec1 => 0x54524539,
            Self::Codec2 => 0x54524541,
            Self::Codec2PrefixOnce => 0x54524542,
        }
    }
    fn version(self) -> i64 {
        match self {
            Self::Codec1 => 9,
            Self::Codec2 => 10,
            Self::Codec2PrefixOnce => 11,
        }
    }
    fn lock_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Codec1 => b"TRNMJ9EP",
            Self::Codec2 => b"TRNMJ10E",
            Self::Codec2PrefixOnce => b"TRNMJ11E",
        }
    }
    fn stage(self, codec1: &'static str, codec2: &'static str) -> &'static str {
        match self {
            Self::Codec1 => codec1,
            Self::Codec2 => codec2,
            Self::Codec2PrefixOnce => "journal11 physical operation",
        }
    }
    pub(crate) fn initialize_schema(self, connection: &Connection) -> Result<()> {
        connection.execute_batch(self.sql())?;
        connection.pragma_update(None, "application_id", self.application_id())?;
        connection.pragma_update(None, "user_version", self.version())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct JournalBoundsV2 {
    /// Maximum record plus transition; fs_owner adds the fixed 4096-byte
    /// overhead to SQLite's whole-row limit, exactly as journal9 did.
    pub(crate) max_row: usize,
    pub(crate) max_db: u64,
}
impl JournalBoundsV2 {
    fn validate(self) -> Result<()> {
        self.max_row
            .checked_add(4096)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or(PhysicalJournalErrorV2::Invalid("SQLite row capacity"))?;
        if self.max_db < 4096 || self.max_db.checked_mul(2).is_none() {
            return invalid("database capacity");
        }
        Ok(())
    }
}

pub(crate) struct PhysicalJournalV2 {
    // Drop the connection before any inode pin, including on failed writes.
    connection: Option<Connection>,
    database: PinnedFileV1,
    lock: PinnedFileV1,
    wal: Option<PinnedFileV1>,
    shm: Option<PinnedFileV1>,
    directory: PinnedFileV1,
    layout: JournalLayoutV2,
    bounds: JournalBoundsV2,
    profile_ref: [u8; 32],
    journal_id: [u8; 32],
    pid: u32,
    fenced: bool,
}
impl PhysicalJournalV2 {
    pub(crate) fn create_new(
        path: &Path,
        layout: JournalLayoutV2,
        profile_ref: [u8; 32],
        bounds: JournalBoundsV2,
        forbidden_source_path: Option<&Path>,
    ) -> Result<Self> {
        fs_owner::require_linux()?;
        bounds.validate()?;
        let (path, directory) = fs_owner::pin_namespace(path)?;
        if forbidden_source_path.is_some_and(|source| source == path)
            || path.to_string_lossy().ends_with(".epoch.lock")
        {
            return invalid("destination namespace collision");
        }
        let lock_path = fs_owner::auxiliary_path(&path, ".epoch.lock");
        for candidate in [
            &path,
            &lock_path,
            &fs_owner::auxiliary_path(&path, "-wal"),
            &fs_owner::auxiliary_path(&path, "-shm"),
            &fs_owner::auxiliary_path(&path, "-journal"),
        ] {
            fs_owner::require_absent(candidate)?;
        }
        let mut journal_id = [0; 32];
        getrandom::getrandom(&mut journal_id)
            .map_err(|_| PhysicalJournalErrorV2::Invalid("journal identity entropy"))?;
        if journal_id == [0; 32] {
            return invalid("zero journal identity");
        }
        let mut lock_file = fs_owner::private_file(&lock_path, true)?;
        fs_owner::lock_exclusive(&lock_file)?;
        lock_file
            .write_all(layout.lock_magic())
            .and_then(|_| lock_file.write_all(&journal_id))
            .and_then(|_| lock_file.write_all(&profile_ref))
            .map_err(|error| {
                io(
                    layout.stage("write journal9 lock", "write journal10 lock"),
                    error,
                )
            })?;
        lock_file.sync_all().map_err(|error| {
            io(
                layout.stage("sync journal9 lock", "sync journal10 lock"),
                error,
            )
        })?;
        let lock = PinnedFileV1::new(lock_path, lock_file, false, 72)?;
        let database_file = fs_owner::private_file(&path, true)?;
        fs_owner::lock_exclusive(&database_file)?;
        let database = PinnedFileV1::new(path.clone(), database_file, false, bounds.max_db)?;
        directory.file.sync_all().map_err(|error| {
            io(
                layout.stage("sync journal9 namespace", "sync journal10 namespace"),
                error,
            )
        })?;
        let connection = fs_owner::open_connection(&path, false)?;
        fs_owner::configure_connection(&connection, true, bounds.max_row, bounds.max_db)?;
        Ok(Self {
            connection: Some(connection),
            database,
            lock,
            wal: None,
            shm: None,
            directory,
            layout,
            bounds,
            profile_ref,
            journal_id,
            pid: std::process::id(),
            fenced: false,
        })
    }

    pub(crate) fn open_existing(
        path: &Path,
        layout: JournalLayoutV2,
        profile_ref: [u8; 32],
        bounds: JournalBoundsV2,
        journal_id: [u8; 32],
    ) -> Result<Self> {
        fs_owner::require_linux()?;
        bounds.validate()?;
        let (path, directory) = fs_owner::pin_namespace(path)?;
        let lock = fs_owner::pin_existing(&fs_owner::auxiliary_path(&path, ".epoch.lock"), 72)?;
        fs_owner::lock_exclusive(&lock.file)?;
        let database = fs_owner::pin_existing(&path, bounds.max_db)?;
        fs_owner::lock_exclusive(&database.file)?;
        let wal = Some(fs_owner::pin_existing(
            &fs_owner::auxiliary_path(&path, "-wal"),
            bounds.max_db * 2,
        )?);
        let shm = Some(fs_owner::pin_existing(
            &fs_owner::auxiliary_path(&path, "-shm"),
            65_536,
        )?);
        fs_owner::require_absent(&fs_owner::auxiliary_path(&path, "-journal"))?;
        Ok(Self {
            connection: None,
            database,
            lock,
            wal,
            shm,
            directory,
            layout,
            bounds,
            profile_ref,
            journal_id,
            pid: std::process::id(),
            fenced: false,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.database.path
    }
    pub(crate) const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }
    pub(crate) fn require_namespace(&self) -> Result<()> {
        if self.fenced {
            return Err(PhysicalJournalErrorV2::Fenced);
        }
        if std::process::id() != self.pid {
            return invalid("owner process changed");
        }
        for pin in [&self.database, &self.lock, &self.directory] {
            pin.require_unchanged()?;
        }
        if let Some(pin) = &self.wal {
            pin.require_unchanged()?;
        }
        if let Some(pin) = &self.shm {
            pin.require_unchanged()?;
        }
        if self
            .lock
            .file
            .metadata()
            .map_err(|error| io("stat lock", error))?
            .len()
            != 72
        {
            return invalid("lock size");
        }
        let mut bytes = [0; 72];
        let file = &self.lock.file;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            file.read_exact_at(&mut bytes, 0)
                .map_err(|error| io("read lock", error))?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut file = file;
            file.read_exact(&mut bytes)
                .map_err(|error| io("read lock", error))?;
        }
        if &bytes[..8] != self.layout.lock_magic()
            || bytes[8..40] != self.journal_id
            || bytes[40..] != self.profile_ref
        {
            return invalid("lock binding");
        }
        Ok(())
    }
    pub(crate) fn open_read_connection(&self) -> Result<Connection> {
        self.require_namespace()?;
        let connection = fs_owner::open_connection(self.path(), true)?;
        fs_owner::configure_connection(
            &connection,
            false,
            self.bounds.max_row,
            self.bounds.max_db,
        )?;
        Ok(connection)
    }
    pub(crate) fn close_read_connection(&self, connection: Connection) -> Result<()> {
        connection
            .close()
            .map_err(|(_, error)| PhysicalJournalErrorV2::Sqlite(error))?;
        self.require_namespace()
    }
    pub(crate) fn open_writer(&mut self) -> Result<()> {
        self.require_namespace()?;
        if self.connection.is_some() {
            return invalid("writer already open");
        }
        let connection = fs_owner::open_connection(self.path(), false)?;
        fs_owner::configure_connection(
            &connection,
            false,
            self.bounds.max_row,
            self.bounds.max_db,
        )?;
        connection.execute_batch("PRAGMA query_only=OFF; PRAGMA wal_autocheckpoint=0;")?;
        connection.pragma_update(None, "max_page_count", self.bounds.max_db / 4096)?;
        self.connection = Some(connection);
        Ok(())
    }
    /// An initialization already owns its writer. A later append first calls
    /// open_writer. Sidecars are pinned after BEGIN, as in journal9's original
    /// initialization, without exposing file handles or mutable pin state.
    pub(crate) fn immediate_transaction(&mut self) -> Result<Transaction<'_>> {
        self.require_namespace()?;
        let tx = self
            .connection
            .as_mut()
            .ok_or(PhysicalJournalErrorV2::Invalid("missing writer"))?
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.wal.is_none() {
            self.wal = Some(fs_owner::pin_existing(
                &fs_owner::auxiliary_path(&self.database.path, "-wal"),
                self.bounds.max_db * 2,
            )?);
        }
        if self.shm.is_none() {
            self.shm = Some(fs_owner::pin_existing(
                &fs_owner::auxiliary_path(&self.database.path, "-shm"),
                65_536,
            )?);
        }
        Ok(tx)
    }
    fn close_connection(&mut self) -> Result<()> {
        if let Some(connection) = self.connection.take() {
            connection
                .close()
                .map_err(|(_, error)| PhysicalJournalErrorV2::Sqlite(error))?;
        }
        Ok(())
    }
    pub(crate) fn close_and_sync(&mut self) -> Result<()> {
        self.require_namespace()?;
        self.close_connection()?;
        self.require_namespace()?;
        for file in [
            &self.database.file,
            &self.lock.file,
            &self
                .wal
                .as_ref()
                .ok_or(PhysicalJournalErrorV2::Invalid("missing WAL"))?
                .file,
            &self
                .shm
                .as_ref()
                .ok_or(PhysicalJournalErrorV2::Invalid("missing SHM"))?
                .file,
            &self.directory.file,
        ] {
            file.sync_all()
                .map_err(|error| io(self.layout.stage("sync journal9", "sync journal10"), error))?;
        }
        self.require_namespace()
    }
    pub(crate) fn fence(&mut self) {
        self.fenced = true;
        let _ = self.close_connection();
    }
    pub(crate) fn check_schema(&self, connection: &Connection) -> Result<()> {
        let app: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if app != self.layout.application_id() || version != self.layout.version() {
            return invalid(self.layout.stage(
                "journal9 application ID/schema",
                "journal10 application ID/schema",
            ));
        }
        let reference = Connection::open_in_memory()?;
        reference.execute_batch(self.layout.sql())?;
        let inventory_limit = if self.layout == JournalLayoutV2::Codec2PrefixOnce {
            5
        } else {
            4
        };
        if schema_inventory(connection, inventory_limit)?
            != schema_inventory(&reference, inventory_limit)?
        {
            return invalid(self.layout.stage(
                "journal9 closed schema inventory",
                "journal10 closed schema inventory",
            ));
        }
        let metadata: i64 =
            connection.query_row("SELECT count(*) FROM epoch_metadata", [], |row| row.get(0))?;
        let heads: i64 =
            connection.query_row("SELECT count(*) FROM epoch_head", [], |row| row.get(0))?;
        if metadata != 1 || heads != 1 {
            return invalid(self.layout.stage(
                "journal9 singleton inventory",
                "journal10 singleton inventory",
            ));
        }
        Ok(())
    }
}

fn schema_inventory(
    connection: &Connection,
    inventory_limit: usize,
) -> rusqlite::Result<Vec<(String, String, String, String)>> {
    let mut rows = connection
        .prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema LIMIT ?1")?
        .query_map([inventory_limit], |row| {
            let mut fields = Vec::with_capacity(4);
            for (index, bound) in [16, 64, 64, 4096].into_iter().enumerate() {
                let value = row.get_ref(index)?.as_str()?;
                if value.len() > bound {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                fields.push(value.to_owned());
            }
            Ok((
                fields.remove(0),
                fields.remove(0),
                fields.remove(0),
                fields.remove(0),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.sort();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn journal9_physical_layout_bytes_are_unchanged() {
        assert_eq!(JournalLayoutV2::Codec1.application_id(), 0x54524539);
        assert_eq!(JournalLayoutV2::Codec1.version(), 9);
        assert_eq!(JournalLayoutV2::Codec1.lock_magic(), b"TRNMJ9EP");
        // The complete pre-extraction DDL, including its whitespace, is pinned.
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(JournalLayoutV2::Codec1.sql().as_bytes())
            ),
            "3c5b9059dc8a8b33b8a07628f80fcd2d0061315e919f219bd6c6567cdbdf5b8d"
        );
        let expected_v2 = JournalLayoutV2::Codec1.sql().replacen(
            " profile BLOB NOT NULL CHECK(length(profile)=32),\n",
            " profile BLOB NOT NULL CHECK(length(profile)=32),\n source_kind INTEGER NOT NULL CHECK(source_kind BETWEEN 0 AND 2),\n",
            1,
        );
        assert_eq!(JournalLayoutV2::Codec2.sql(), expected_v2);
    }

    #[test]
    fn journal11_layout_is_distinct_and_fifth_schema_object_is_rejected() {
        let layout = JournalLayoutV2::Codec2PrefixOnce;
        assert_eq!(layout.application_id(), 0x54524542);
        assert_eq!(layout.version(), 11);
        assert_eq!(layout.lock_magic(), b"TRNMJ11E");
        let c = Connection::open_in_memory().unwrap();
        layout.initialize_schema(&c).unwrap();
        let expected = schema_inventory(&c, 5).unwrap();
        assert_eq!(expected.len(), 4);
        c.execute_batch("CREATE TABLE fifth(x INTEGER) STRICT")
            .unwrap();
        let actual = schema_inventory(&c, 5).unwrap();
        assert_eq!(actual.len(), 5);
        assert_ne!(actual, expected);
        assert!(c
            .execute("INSERT INTO epoch_provenance VALUES(1,'not a blob')", [])
            .is_err());
        assert!(c
            .execute(
                "INSERT INTO epoch_provenance VALUES(1,zeroblob(67108865))",
                []
            )
            .is_err());
    }

    #[test]
    fn journal10_physical_schema_rejects_unknown_source_kind() {
        let connection = Connection::open_in_memory().unwrap();
        JournalLayoutV2::Codec2
            .initialize_schema(&connection)
            .unwrap();
        for kind in [-1, 3] {
            assert!(connection.execute(
                "INSERT INTO epoch_metadata VALUES(1,zeroblob(32),zeroblob(32),?1,zeroblob(32),zeroblob(32),x'01',x'01',zeroblob(32),1)",
                [kind],
            ).is_err());
        }
        let count: i64 = connection
            .query_row("SELECT count(*) FROM epoch_metadata", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_journal_reopen_preserves_lock_binding_and_fencing() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let bounds = JournalBoundsV2 {
            max_row: 8192,
            max_db: 8 * 1024 * 1024,
        };
        let profile = [0x31; 32];
        for layout in [
            JournalLayoutV2::Codec1,
            JournalLayoutV2::Codec2,
            JournalLayoutV2::Codec2PrefixOnce,
        ] {
            let path = directory
                .path()
                .join(format!("journal{}.sqlite", layout.version()));
            let mut owner =
                PhysicalJournalV2::create_new(&path, layout, profile, bounds, None).unwrap();
            let journal_id = owner.journal_id();
            {
                let tx = owner.immediate_transaction().unwrap();
                layout.initialize_schema(&tx).unwrap();
                // These deliberately inert one-byte records exercise only
                // physical SQL/namespace behavior. No codec accepts them and
                // this backend cannot return Core or source-owner authority.
                let metadata = match layout {
                    JournalLayoutV2::Codec1 => "INSERT INTO epoch_metadata VALUES(1,?1,?2,zeroblob(32),zeroblob(32),x'01',x'01',zeroblob(32),1)",
                    JournalLayoutV2::Codec2 | JournalLayoutV2::Codec2PrefixOnce => "INSERT INTO epoch_metadata VALUES(1,?1,?2,0,zeroblob(32),zeroblob(32),x'01',x'01',zeroblob(32),1)",
                };
                tx.execute(
                    metadata,
                    rusqlite::params![journal_id.as_slice(), profile.as_slice()],
                )
                .unwrap();
                tx.execute("INSERT INTO epoch_head VALUES(1,1,zeroblob(32))", [])
                    .unwrap();
                tx.commit().unwrap();
            }
            owner.close_and_sync().unwrap();
            let mut lock_bytes = Vec::from(layout.lock_magic().as_slice());
            lock_bytes.extend_from_slice(&journal_id);
            lock_bytes.extend_from_slice(&profile);
            let lock_path = fs_owner::auxiliary_path(&path, ".epoch.lock");
            assert_eq!(std::fs::read(&lock_path).unwrap(), lock_bytes);
            drop(owner);

            let wrong_layout = match layout {
                JournalLayoutV2::Codec1 => JournalLayoutV2::Codec2,
                JournalLayoutV2::Codec2 | JournalLayoutV2::Codec2PrefixOnce => {
                    JournalLayoutV2::Codec1
                }
            };
            let wrong =
                PhysicalJournalV2::open_existing(&path, wrong_layout, profile, bounds, journal_id)
                    .unwrap();
            assert!(matches!(
                wrong.open_read_connection(),
                Err(PhysicalJournalErrorV2::Invalid("lock binding"))
            ));
            drop(wrong);
            assert_eq!(std::fs::read(&lock_path).unwrap(), lock_bytes);

            let mut reopened =
                PhysicalJournalV2::open_existing(&path, layout, profile, bounds, journal_id)
                    .unwrap();
            let connection = reopened.open_read_connection().unwrap();
            reopened.check_schema(&connection).unwrap();
            reopened.close_read_connection(connection).unwrap();
            reopened.fence();
            assert!(matches!(
                reopened.open_read_connection(),
                Err(PhysicalJournalErrorV2::Fenced)
            ));
        }
    }
}
