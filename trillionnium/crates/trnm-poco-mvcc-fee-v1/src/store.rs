use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    engine::{execute_block, state_root, validate_genesis, ObjectMapV1},
    error::{error, MvccFeeErrorCodeV1, MvccFeeResultV1},
    Hash32V1, MvccBlockReceiptV1, MvccBlockV1, MvccCommitFaultV1, MvccFeeGenesisV1, ObjectStateV1,
    ProtocolContextV1,
};

const JOURNAL_SCHEMA_VERSION: u16 = 1;
const META_SQL: &str = "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,genesis BLOB NOT NULL,height INTEGER NOT NULL,block_id BLOB NOT NULL,state_root BLOB NOT NULL,journal_root BLOB NOT NULL,fenced INTEGER NOT NULL CHECK(fenced IN(0,1)),checksum BLOB NOT NULL) STRICT";
const OBJECT_SQL: &str = "CREATE TABLE objects(object_key BLOB PRIMARY KEY,body BLOB NOT NULL,checksum BLOB NOT NULL) STRICT";
const BLOCK_SQL: &str = "CREATE TABLE blocks(height INTEGER PRIMARY KEY,block_id BLOB NOT NULL UNIQUE,block BLOB NOT NULL,receipt BLOB NOT NULL,checksum BLOB NOT NULL) STRICT";

#[derive(Debug)]
pub struct ConfirmedMvccBlockV1 {
    receipt: MvccBlockReceiptV1,
}

impl ConfirmedMvccBlockV1 {
    pub fn receipt(&self) -> &MvccBlockReceiptV1 {
        &self.receipt
    }
}

/// Exact local MVCC head observed through a fresh authenticated reopen.
///
/// The readback is deliberately non-forgeable and does not itself prove
/// order finality, whole-node monotonicity, or cross-store atomicity.
#[derive(Debug, Eq, PartialEq)]
pub struct MvccFeeFreshReadbackV1 {
    context: ProtocolContextV1,
    store_schema_version: u16,
    store_id: Hash32V1,
    height: u64,
    block_id: Hash32V1,
    durable_state_root: Hash32V1,
    durable_journal_root: Hash32V1,
}

/// Immutable execution result for one candidate block before an Order Vote.
///
/// This carries the bounded MVCC kernel root only.  It does not claim the
/// draft protocol JMT root or Order finality.
#[derive(Debug)]
pub struct MvccFeePreVotePreviewV1 {
    source_height: u64,
    source_state_root: Hash32V1,
    source_journal_root: Hash32V1,
    candidate_receipt: MvccBlockReceiptV1,
}

impl MvccFeePreVotePreviewV1 {
    pub const fn source_height(&self) -> u64 {
        self.source_height
    }

    pub const fn source_state_root(&self) -> Hash32V1 {
        self.source_state_root
    }

    pub const fn source_journal_root(&self) -> Hash32V1 {
        self.source_journal_root
    }

    pub const fn candidate_post_state_root(&self) -> Hash32V1 {
        self.candidate_receipt.final_state_root
    }

    pub const fn candidate_receipt(&self) -> &MvccBlockReceiptV1 {
        &self.candidate_receipt
    }
}

impl MvccFeeFreshReadbackV1 {
    pub const fn context(&self) -> &ProtocolContextV1 {
        &self.context
    }

    pub const fn store_schema_version(&self) -> u16 {
        self.store_schema_version
    }

    pub const fn store_id(&self) -> Hash32V1 {
        self.store_id
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_id(&self) -> Hash32V1 {
        self.block_id
    }

    pub const fn durable_state_root(&self) -> Hash32V1 {
        self.durable_state_root
    }

    pub const fn durable_journal_root(&self) -> Hash32V1 {
        self.durable_journal_root
    }
}

#[derive(Debug)]
pub struct MvccBlockOutcomeV1 {
    pub confirmed: ConfirmedMvccBlockV1,
    pub replay: bool,
}

#[derive(Debug)]
pub struct MvccFeeStoreV1 {
    path: PathBuf,
    genesis: MvccFeeGenesisV1,
}

impl MvccFeeStoreV1 {
    pub fn open(path: impl Into<PathBuf>, genesis: MvccFeeGenesisV1) -> MvccFeeResultV1<Self> {
        validate_genesis(&genesis)?;
        let path = path.into();
        reject_sidecars(&path)?;
        if path.exists() {
            let connection = open_ro(&path)?;
            verify_schema(&connection)?;
            audit(&connection, &genesis)?;
            if load_metadata(&connection, &genesis)?.4 {
                return Err(error(
                    MvccFeeErrorCodeV1::ThirdStateFenced,
                    "store is permanently fenced",
                ));
            }
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|cause| error(MvccFeeErrorCodeV1::StoreFailure, cause.to_string()))?;
            }
            let mut connection = open_rw(&path, true)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(OBJECT_SQL)?;
            transaction.execute_batch(BLOCK_SQL)?;
            let mut objects = ObjectMapV1::new();
            for object in &genesis.initial_objects {
                objects.insert(object.object_id, object.clone());
            }
            write_objects(&transaction, &objects)?;
            write_metadata(
                &transaction,
                &genesis,
                genesis.initial_height,
                genesis.initial_block_id,
                state_root(&objects)?,
                block_journal_root(&transaction)?,
                false,
            )?;
            transaction.commit()?;
            drop(connection);
            let connection = open_ro(&path)?;
            verify_schema(&connection)?;
            audit(&connection, &genesis)?;
        }
        Ok(Self { path, genesis })
    }

    /// Open and fully audit an already-created store without creating a
    /// parent directory, database, schema, migration, or writable SQLite
    /// handle.
    ///
    /// The path must name a regular file directly. Missing paths, symlinks
    /// and non-regular filesystem objects are rejected before SQLite is
    /// opened.
    pub fn open_existing(
        path: impl Into<PathBuf>,
        genesis: MvccFeeGenesisV1,
    ) -> MvccFeeResultV1<Self> {
        validate_genesis(&genesis)?;
        let path = path.into();
        require_existing_regular_store(&path)?;
        reject_sidecars(&path)?;
        let connection = open_ro(&path)?;
        verify_schema(&connection)?;
        audit(&connection, &genesis)?;
        if load_metadata(&connection, &genesis)?.4 {
            return Err(error(
                MvccFeeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        drop(connection);
        require_existing_regular_store(&path)?;
        reject_sidecars(&path)?;
        Ok(Self { path, genesis })
    }

    pub fn execute_block(&self, block: &MvccBlockV1) -> MvccFeeResultV1<MvccBlockOutcomeV1> {
        self.execute_inner(block, None)
    }

    /// Execute one candidate block from the exact fresh durable parent without
    /// changing the linear MVCC store.
    pub fn preview_before_vote_v1(
        &self,
        expected_parent: &MvccFeeFreshReadbackV1,
        block: &MvccBlockV1,
    ) -> MvccFeeResultV1<MvccFeePreVotePreviewV1> {
        let before = self.fresh_readback()?;
        if &before != expected_parent
            || block.expected_parent_height != before.height
            || block.expected_parent_block_id != before.block_id
            || block.expected_parent_state_root != before.durable_state_root
            || block.height
                != before.height.checked_add(1).ok_or_else(|| {
                    error(
                        MvccFeeErrorCodeV1::ArithmeticOverflow,
                        "candidate height overflows",
                    )
                })?
        {
            return Err(error(
                MvccFeeErrorCodeV1::StaleParent,
                "pre-vote block does not extend the exact fresh parent",
            ));
        }
        let parent: ObjectMapV1 = self
            .objects()?
            .into_iter()
            .map(|object| (object.object_id, object))
            .collect();
        let (_, receipt) = execute_block(&self.genesis, &parent, block)?;
        let after = self.fresh_readback()?;
        if after != before {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "MVCC/Fee source changed during read-only preview",
            ));
        }
        Ok(MvccFeePreVotePreviewV1 {
            source_height: before.height,
            source_state_root: before.durable_state_root,
            source_journal_root: before.durable_journal_root,
            candidate_receipt: receipt,
        })
    }

    #[cfg(test)]
    pub(crate) fn execute_with_fault(
        &self,
        block: &MvccBlockV1,
        fault: MvccCommitFaultV1,
    ) -> MvccFeeResultV1<MvccBlockOutcomeV1> {
        self.execute_inner(block, Some(fault))
    }

    fn execute_inner(
        &self,
        block: &MvccBlockV1,
        fault: Option<MvccCommitFaultV1>,
    ) -> MvccFeeResultV1<MvccBlockOutcomeV1> {
        reject_sidecars(&self.path)?;
        let read_only = open_ro(&self.path)?;
        verify_schema(&read_only)?;
        audit(&read_only, &self.genesis)?;
        drop(read_only);
        let mut connection = open_rw(&self.path, false)?;
        verify_schema(&connection)?;
        audit(&connection, &self.genesis)?;
        if let Some((stored_block, receipt)) = load_block(&connection, block.block_id)? {
            if stored_block != *block {
                return Err(error(
                    MvccFeeErrorCodeV1::IdentifierMismatch,
                    "block ID replays different bytes",
                ));
            }
            drop(connection);
            return Ok(MvccBlockOutcomeV1 {
                confirmed: self.fresh_confirm(&receipt)?,
                replay: true,
            });
        }
        let (height, block_id, durable_root, _, fenced) =
            load_metadata(&connection, &self.genesis)?;
        if fenced {
            return Err(error(
                MvccFeeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        if height != block.expected_parent_height
            || block_id != block.expected_parent_block_id
            || durable_root != block.expected_parent_state_root
        {
            return Err(error(
                MvccFeeErrorCodeV1::StaleParent,
                "block parent does not match durable head",
            ));
        }
        let next_height = height
            .checked_add(1)
            .ok_or_else(|| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "height overflow"))?;
        if block.height != next_height {
            return Err(error(
                MvccFeeErrorCodeV1::StaleParent,
                "block height is not parent plus one",
            ));
        }
        if matches!(fault, Some(MvccCommitFaultV1::NotAppliedAckLost)) {
            return Err(error(
                MvccFeeErrorCodeV1::CommitUncertain,
                "block not applied before acknowledgement loss",
            ));
        }
        let parent = load_objects(&connection)?;
        let (post, receipt) = execute_block(&self.genesis, &parent, block)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (tx_height, tx_block_id, tx_root, _, tx_fenced) =
            load_metadata(&transaction, &self.genesis)?;
        if (tx_height, tx_block_id, tx_root, tx_fenced) != (height, block_id, durable_root, false) {
            return Err(error(
                MvccFeeErrorCodeV1::StaleParent,
                "head changed before block transaction",
            ));
        }
        if matches!(fault, Some(MvccCommitFaultV1::ThirdState)) {
            write_metadata(
                &transaction,
                &self.genesis,
                height,
                block_id,
                durable_root,
                block_journal_root(&transaction)?,
                true,
            )?;
            transaction.commit()?;
            return Err(error(
                MvccFeeErrorCodeV1::ThirdStateFenced,
                "commit resolved to neither source nor target",
            ));
        }
        write_objects(&transaction, &post)?;
        insert_block(&transaction, block, &receipt)?;
        write_metadata(
            &transaction,
            &self.genesis,
            block.height,
            block.block_id,
            receipt.final_state_root,
            block_journal_root(&transaction)?,
            false,
        )?;
        transaction.commit()?;
        drop(connection);
        if matches!(fault, Some(MvccCommitFaultV1::AppliedAckLost)) {
            return Err(error(
                MvccFeeErrorCodeV1::CommitUncertain,
                "block applied before acknowledgement loss",
            ));
        }
        Ok(MvccBlockOutcomeV1 {
            confirmed: self.fresh_confirm(&receipt)?,
            replay: false,
        })
    }

    pub fn fresh_confirm(
        &self,
        expected: &MvccBlockReceiptV1,
    ) -> MvccFeeResultV1<ConfirmedMvccBlockV1> {
        if expected.store_id != self.genesis.store_id {
            return Err(error(
                MvccFeeErrorCodeV1::InvalidContext,
                "receipt belongs to another store",
            ));
        }
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.genesis)?;
        let (_, actual) = load_block(&connection, expected.block_id)?
            .ok_or_else(|| error(MvccFeeErrorCodeV1::NotFound, "block receipt absent"))?;
        if &actual != expected {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "durable block receipt differs",
            ));
        }
        Ok(ConfirmedMvccBlockV1 { receipt: actual })
    }

    /// Reopen and authenticate the current durable MVCC head.
    pub fn fresh_readback(&self) -> MvccFeeResultV1<MvccFeeFreshReadbackV1> {
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.genesis)?;
        let (height, block_id, state_root, journal_root, fenced) =
            load_metadata(&connection, &self.genesis)?;
        if fenced {
            return Err(error(
                MvccFeeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        Ok(MvccFeeFreshReadbackV1 {
            context: self.genesis.context.clone(),
            store_schema_version: JOURNAL_SCHEMA_VERSION,
            store_id: self.genesis.store_id,
            height,
            block_id,
            durable_state_root: state_root,
            durable_journal_root: journal_root,
        })
    }

    pub fn objects(&self) -> MvccFeeResultV1<Vec<ObjectStateV1>> {
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.genesis)?;
        Ok(load_objects(&connection)?.into_values().collect())
    }
}

fn open_rw(path: &Path, allow_create: bool) -> MvccFeeResultV1<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if allow_create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn open_ro(path: &Path) -> MvccFeeResultV1<Connection> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn reject_sidecars(path: &Path) -> MvccFeeResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar: OsString = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if Path::new(&sidecar).exists() {
            return Err(error(
                MvccFeeErrorCodeV1::SidecarPresent,
                "SQLite sidecar present",
            ));
        }
    }
    Ok(())
}

fn require_existing_regular_store(path: &Path) -> MvccFeeResultV1<()> {
    let metadata = fs::symlink_metadata(path).map_err(|cause| {
        error(
            MvccFeeErrorCodeV1::StoreFailure,
            format!("existing MVCC/Fee store is unavailable: {cause}"),
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(error(
            MvccFeeErrorCodeV1::StoreFailure,
            "existing MVCC/Fee store path must not be a symlink",
        ));
    }
    if !file_type.is_file() {
        return Err(error(
            MvccFeeErrorCodeV1::StoreFailure,
            "existing MVCC/Fee store path is not a regular file",
        ));
    }
    Ok(())
}

fn verify_schema(connection: &Connection) -> MvccFeeResultV1<()> {
    let mut statement = connection.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        ("blocks".to_owned(), BLOCK_SQL.to_owned()),
        ("metadata".to_owned(), META_SQL.to_owned()),
        ("objects".to_owned(), OBJECT_SQL.to_owned()),
    ];
    if rows != expected {
        return Err(error(
            MvccFeeErrorCodeV1::SchemaMismatch,
            "schema v1 differs or automatic migration would be required",
        ));
    }
    let triggers: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    if triggers != 0 {
        return Err(error(
            MvccFeeErrorCodeV1::SchemaMismatch,
            "triggers are forbidden",
        ));
    }
    Ok(())
}

fn write_objects(connection: &Connection, objects: &ObjectMapV1) -> MvccFeeResultV1<()> {
    connection.execute("DELETE FROM objects", [])?;
    for (id, object) in objects {
        let key = canonical_bytes(id)?;
        let body = canonical_bytes(object)?;
        let sum = checksum(&[&key, &body]);
        connection.execute(
            "INSERT INTO objects(object_key,body,checksum) VALUES(?1,?2,?3)",
            params![key, body, sum.0.to_vec()],
        )?;
    }
    Ok(())
}

fn load_objects(connection: &Connection) -> MvccFeeResultV1<ObjectMapV1> {
    let mut statement =
        connection.prepare("SELECT object_key,body,checksum FROM objects ORDER BY object_key")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = ObjectMapV1::new();
    for (key, body, stored_sum) in rows {
        if stored_sum != checksum(&[&key, &body]).0 {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "object checksum mismatch",
            ));
        }
        let id = strict_decode(&key)?;
        let object: ObjectStateV1 = strict_decode(&body)?;
        if object.object_id != id
            || object.schema_version != 1
            || output.insert(id, object).is_some()
        {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "object key/body mismatch",
            ));
        }
    }
    Ok(output)
}

fn insert_block(
    connection: &Connection,
    block: &MvccBlockV1,
    receipt: &MvccBlockReceiptV1,
) -> MvccFeeResultV1<()> {
    let block_bytes = canonical_bytes(block)?;
    let receipt_bytes = canonical_bytes(receipt)?;
    let sum = checksum(&[
        &block.height.to_le_bytes(),
        &block.block_id.0,
        &block_bytes,
        &receipt_bytes,
    ]);
    connection.execute(
        "INSERT INTO blocks(height,block_id,block,receipt,checksum) VALUES(?1,?2,?3,?4,?5)",
        params![
            i64::try_from(block.height).map_err(|_| error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "height exceeds SQLite"
            ))?,
            block.block_id.0.to_vec(),
            block_bytes,
            receipt_bytes,
            sum.0.to_vec()
        ],
    )?;
    Ok(())
}

fn load_block(
    connection: &Connection,
    id: Hash32V1,
) -> MvccFeeResultV1<Option<(MvccBlockV1, MvccBlockReceiptV1)>> {
    let row = connection
        .query_row(
            "SELECT height,block_id,block,receipt,checksum FROM blocks WHERE block_id=?1",
            [id.0.to_vec()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((height, id_bytes, block_bytes, receipt_bytes, stored_sum)) = row else {
        return Ok(None);
    };
    let height_u64 = u64::try_from(height)
        .map_err(|_| error(MvccFeeErrorCodeV1::TamperDetected, "negative block height"))?;
    if id_bytes.as_slice() != id.0
        || stored_sum
            != checksum(&[
                &height_u64.to_le_bytes(),
                &id_bytes,
                &block_bytes,
                &receipt_bytes,
            ])
            .0
    {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "block row checksum mismatch",
        ));
    }
    let block: MvccBlockV1 = strict_decode(&block_bytes)?;
    let receipt: MvccBlockReceiptV1 = strict_decode(&receipt_bytes)?;
    if block.block_id != id
        || receipt.block_id != id
        || block.height != height_u64
        || receipt.height != height_u64
    {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "block row identity mismatch",
        ));
    }
    Ok(Some((block, receipt)))
}

fn block_journal_root(connection: &Connection) -> MvccFeeResultV1<Hash32V1> {
    let mut statement = connection.prepare("SELECT receipt FROM blocks ORDER BY height")?;
    let receipts = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    digest_value(
        "trnm.poco-ai.mvcc-block-journal-root.candidate.v1",
        &receipts,
    )
}

fn write_metadata(
    connection: &Connection,
    genesis: &MvccFeeGenesisV1,
    height: u64,
    block_id: Hash32V1,
    state: Hash32V1,
    journal: Hash32V1,
    fenced: bool,
) -> MvccFeeResultV1<()> {
    let genesis_bytes = canonical_bytes(genesis)?;
    let height_bytes = height.to_le_bytes();
    let fenced_byte = [u8::from(fenced)];
    let sum = checksum(&[
        &JOURNAL_SCHEMA_VERSION.to_le_bytes(),
        &genesis_bytes,
        &height_bytes,
        &block_id.0,
        &state.0,
        &journal.0,
        &fenced_byte,
    ]);
    connection.execute("INSERT INTO metadata(singleton,schema_version,genesis,height,block_id,state_root,journal_root,fenced,checksum) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,genesis=excluded.genesis,height=excluded.height,block_id=excluded.block_id,state_root=excluded.state_root,journal_root=excluded.journal_root,fenced=excluded.fenced,checksum=excluded.checksum", params![i64::from(JOURNAL_SCHEMA_VERSION), genesis_bytes, i64::try_from(height).map_err(|_| error(MvccFeeErrorCodeV1::ArithmeticOverflow, "height exceeds SQLite"))?, block_id.0.to_vec(), state.0.to_vec(), journal.0.to_vec(), i64::from(fenced), sum.0.to_vec()])?;
    Ok(())
}

fn load_metadata(
    connection: &Connection,
    genesis: &MvccFeeGenesisV1,
) -> MvccFeeResultV1<(u64, Hash32V1, Hash32V1, Hash32V1, bool)> {
    let row = connection.query_row("SELECT schema_version,genesis,height,block_id,state_root,journal_root,fenced,checksum FROM metadata WHERE singleton=1", [], |row| Ok((row.get::<_, i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?,row.get::<_,i64>(6)?,row.get::<_,Vec<u8>>(7)?)))?;
    let (schema, genesis_bytes, height, block, state, journal, fenced, stored_sum) = row;
    if schema != i64::from(JOURNAL_SCHEMA_VERSION)
        || strict_decode::<MvccFeeGenesisV1>(&genesis_bytes)? != *genesis
        || !matches!(fenced, 0 | 1)
    {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "metadata trust binding mismatch",
        ));
    }
    let height_u64 = u64::try_from(height)
        .map_err(|_| error(MvccFeeErrorCodeV1::TamperDetected, "negative height"))?;
    let block: [u8; 32] = block
        .try_into()
        .map_err(|_| error(MvccFeeErrorCodeV1::TamperDetected, "bad block ID length"))?;
    let state: [u8; 32] = state
        .try_into()
        .map_err(|_| error(MvccFeeErrorCodeV1::TamperDetected, "bad state root length"))?;
    let journal: [u8; 32] = journal.try_into().map_err(|_| {
        error(
            MvccFeeErrorCodeV1::TamperDetected,
            "bad journal root length",
        )
    })?;
    let sum = checksum(&[
        &JOURNAL_SCHEMA_VERSION.to_le_bytes(),
        &genesis_bytes,
        &height_u64.to_le_bytes(),
        &block,
        &state,
        &journal,
        &[u8::try_from(fenced).unwrap_or(u8::MAX)],
    ]);
    if stored_sum != sum.0 {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "metadata checksum mismatch",
        ));
    }
    Ok((
        height_u64,
        Hash32V1(block),
        Hash32V1(state),
        Hash32V1(journal),
        fenced == 1,
    ))
}

fn audit(connection: &Connection, genesis: &MvccFeeGenesisV1) -> MvccFeeResultV1<()> {
    let (height, block_id, durable_state, durable_journal, _) = load_metadata(connection, genesis)?;
    let objects = load_objects(connection)?;
    if state_root(&objects)? != durable_state || block_journal_root(connection)? != durable_journal
    {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "durable root mismatch",
        ));
    }
    let mut statement = connection
        .prepare("SELECT block_id,block,receipt,checksum,height FROM blocks ORDER BY height")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected_height = genesis.initial_height;
    let mut expected_block = genesis.initial_block_id;
    let mut replay_objects: ObjectMapV1 = genesis
        .initial_objects
        .iter()
        .cloned()
        .map(|value| (value.object_id, value))
        .collect();
    let mut expected_parent_root = state_root(&replay_objects)?;
    for (id_bytes, block_bytes, receipt_bytes, stored_sum, row_height) in rows {
        expected_height = expected_height.checked_add(1).ok_or_else(|| {
            error(
                MvccFeeErrorCodeV1::ArithmeticOverflow,
                "audit height overflow",
            )
        })?;
        if row_height
            != i64::try_from(expected_height).map_err(|_| {
                error(
                    MvccFeeErrorCodeV1::ArithmeticOverflow,
                    "audit height exceeds SQLite",
                )
            })?
        {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "block journal height gap",
            ));
        }
        let id: [u8; 32] = id_bytes
            .clone()
            .try_into()
            .map_err(|_| error(MvccFeeErrorCodeV1::TamperDetected, "bad journal block ID"))?;
        if stored_sum
            != checksum(&[
                &expected_height.to_le_bytes(),
                &id_bytes,
                &block_bytes,
                &receipt_bytes,
            ])
            .0
        {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "journal row checksum mismatch",
            ));
        }
        let block: MvccBlockV1 = strict_decode(&block_bytes)?;
        let receipt: MvccBlockReceiptV1 = strict_decode(&receipt_bytes)?;
        if block.block_id != Hash32V1(id)
            || receipt.block_id != Hash32V1(id)
            || block.height != expected_height
            || receipt.height != expected_height
            || block.expected_parent_block_id != expected_block
            || block.expected_parent_state_root != expected_parent_root
            || receipt.parent_state_root != expected_parent_root
        {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "journal lineage mismatch",
            ));
        }
        let (next_objects, expected_receipt) = execute_block(genesis, &replay_objects, &block)
            .map_err(|cause| {
                error(
                    MvccFeeErrorCodeV1::TamperDetected,
                    format!("journal block fails deterministic replay: {cause}"),
                )
            })?;
        if receipt != expected_receipt {
            return Err(error(
                MvccFeeErrorCodeV1::TamperDetected,
                "journal receipt differs from deterministic replay",
            ));
        }
        replay_objects = next_objects;
        expected_block = Hash32V1(id);
        expected_parent_root = receipt.final_state_root;
    }
    if (expected_height, expected_block, expected_parent_root) != (height, block_id, durable_state)
    {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "metadata head differs from journal",
        ));
    }
    if replay_objects != objects {
        return Err(error(
            MvccFeeErrorCodeV1::TamperDetected,
            "durable object rows differ from deterministic journal replay",
        ));
    }
    Ok(())
}
