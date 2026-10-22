//! Durable local byte obligations. This owner is separate from the disposable
//! cache and never authenticates money, grants a release, or proves independent
//! custody. The native M12 adapter must admit the funding operation first.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{
    require, store::verify_chunk, CellDigestV1, CellErrorV1, CellManifestV1, CellResultV1,
    CellStoreV1, MAX_CELL_BYTES,
};

const APPLICATION_ID: i64 = 0x5443_5231;
const ALIGNMENT: u64 = 4096;
const MAX_RECORDS: u32 = 4096;
// This fresh namespace has not been released. Old in-development layouts are
// rejected exactly; opening never migrates or resets an obligation journal.
const META_SQL: &str = "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(length(store_id)=32),capacity INTEGER NOT NULL,maximum_obligations INTEGER NOT NULL) STRICT";
const OBLIGATIONS_SQL: &str = "CREATE TABLE obligations (operation BLOB PRIMARY KEY CHECK(length(operation)=32),funding BLOB NOT NULL UNIQUE CHECK(length(funding)=32),manifest BLOB NOT NULL CHECK(length(manifest) BETWEEN 1 AND 1048576),retain_from INTEGER NOT NULL CHECK(retain_from>=0),retain_until INTEGER NOT NULL CHECK(retain_until>retain_from),repair_limit INTEGER NOT NULL CHECK(repair_limit>=0),successor_store BLOB,successor_operation BLOB,position INTEGER NOT NULL CHECK(position>=0),reserved INTEGER NOT NULL CHECK(reserved>0),status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 2),initial_bytes INTEGER NOT NULL CHECK(initial_bytes>=0),repair_bytes INTEGER NOT NULL CHECK(repair_bytes>=0),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";
const REPAIRS_SQL: &str = "CREATE TABLE repairs (operation BLOB PRIMARY KEY CHECK(length(operation)=32),obligation BLOB NOT NULL CHECK(length(obligation)=32),amount INTEGER NOT NULL CHECK(amount>=0),complete INTEGER NOT NULL CHECK(complete IN (0,1)),checksum BLOB NOT NULL CHECK(length(checksum)=32),CHECK(amount>0 OR complete=1)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetentionConfigV1 {
    pub store_id: CellDigestV1,
    /// Actual allocated payload arena, excluding bounded SQLite metadata/WAL.
    pub capacity_bytes: u64,
    /// Includes retired records: retirement never erases replay identities.
    pub maximum_obligations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetentionContractV1 {
    pub operation: CellDigestV1,
    /// The exact admitted M12 job, not a claim that this module verified funds.
    pub funding_operation: CellDigestV1,
    pub manifest: CellManifestV1,
    /// The full immutable service interval, never shortened on a retry.
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    /// Real rewritten payload bytes; interrupted attempts still consume budget.
    pub maximum_repair_bytes: u64,
    /// A mandatory successor's exact store and operation, frozen before ACK.
    pub successor: Option<(CellDigestV1, CellDigestV1)>,
}

impl CellRetentionContractV1 {
    /// Commits every immutable term, including the physical target identity.
    /// This is an identity, not a proof of funding, custody or future service.
    pub fn commitment(&self, store_id: CellDigestV1) -> CellDigestV1 {
        let mut h = Sha256::new();
        h.update(b"trnm.cell-retention-contract.v1\0");
        h.update(store_id);
        h.update(self.operation);
        h.update(self.funding_operation);
        h.update(self.manifest.id());
        for value in [
            self.retain_from_height,
            self.retain_until_height,
            self.maximum_repair_bytes,
        ] {
            h.update(value.to_be_bytes());
        }
        if let Some((store, operation)) = self.successor {
            h.update([1]);
            h.update(store);
            h.update(operation);
        } else {
            h.update([0]);
        }
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRetentionReadbackV1 {
    pub store_id: CellDigestV1,
    pub operation: CellDigestV1,
    pub funding_operation: CellDigestV1,
    pub manifest: CellDigestV1,
    pub payload_bytes: u64,
    pub reserved_bytes: u64,
    pub physical_arena_bytes: u64,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    /// The whole initial attempt is charged before its first payload write.
    pub initial_copy_bytes_committed: u64,
    pub repair_bytes_committed: u64,
    pub acknowledged: bool,
    pub retired: bool,
}

struct Row {
    contract: CellRetentionContractV1,
    offset: u64,
    reserved: u64,
    status: u8,
    initial_bytes: u64,
    repair_bytes: u64,
}

// The caller owns any thread binding, real CPU clock and CPU allowance. This
// adapter combines that checkpoint with its absolute wall deadline. A rejected
// checkpoint is sticky for this invocation, including corruption-probe paths.
struct OperationControl<'a, C: FnMut() -> CellResultV1<()>> {
    deadline: Instant,
    checkpoint: &'a mut C,
    stopped: bool,
}
impl<C: FnMut() -> CellResultV1<()>> OperationControl<'_, C> {
    fn check(&mut self) -> CellResultV1<()> {
        require(!self.stopped, "retention control stopped")?;
        if let Err(error) = check_deadline(self.deadline).and_then(|()| (self.checkpoint)()) {
            self.stopped = true;
            return Err(error);
        }
        Ok(())
    }
}

/// Single local retention owner with a preallocated, fsynced payload arena.
/// SQLite records and physical repair consumption do not rewind with the chain.
pub struct CellRetentionStoreV1 {
    directory: PathBuf,
    config: CellRetentionConfigV1,
    connection: Connection,
    arena: File,
}

impl CellRetentionStoreV1 {
    /// Create a new namespace. Allocation failure leaves no acknowledged duty;
    /// the partial directory is retained for explicit operator reconciliation.
    pub fn create(directory: &Path, config: CellRetentionConfigV1) -> CellResultV1<Self> {
        validate_config(&config)?;
        fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let arena = open_arena(&directory.join("payload.arena"), true)?;
        FileExt::try_lock_exclusive(&arena)?;
        // Unlike set_len, allocate requires real filesystem capacity. Refuse
        // filesystems that cannot report backing for the declared reservation.
        FileExt::allocate(&arena, config.capacity_bytes)?;
        arena.set_len(config.capacity_bytes)?;
        arena.sync_all()?;
        require(
            FileExt::allocated_size(&arena)? >= config.capacity_bytes,
            "retention physical capacity",
        )?;
        let mut connection = Connection::open_with_flags(
            directory.join("retention.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&connection)?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute_batch(META_SQL)?;
        transaction.execute_batch(OBLIGATIONS_SQL)?;
        transaction.execute_batch(REPAIRS_SQL)?;
        transaction.execute(
            "INSERT INTO metadata VALUES (1,?1,?2,?3)",
            params![
                config.store_id.as_slice(),
                config.capacity_bytes as i64,
                config.maximum_obligations
            ],
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", 1)?;
        transaction.commit()?;
        File::open(directory)?.sync_all()?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            config,
            connection,
            arena,
        })
    }

    /// Reopen without creating, migrating, removing or expiring any obligation.
    pub fn open(directory: &Path, config: CellRetentionConfigV1) -> CellResultV1<Self> {
        validate_config(&config)?;
        require(
            fs::symlink_metadata(directory)?.is_dir(),
            "retention directory",
        )?;
        let arena = open_arena(&directory.join("payload.arena"), false)?;
        FileExt::try_lock_exclusive(&arena)?;
        require(
            arena.metadata()?.len() == config.capacity_bytes
                && FileExt::allocated_size(&arena)? >= config.capacity_bytes,
            "retention physical capacity",
        )?;
        require(
            fs::symlink_metadata(directory.join("retention.sqlite"))?.is_file(),
            "retention database",
        )?;
        let connection = Connection::open_with_flags(
            directory.join("retention.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        require(
            application == APPLICATION_ID && version == 1,
            "retention namespace",
        )?;
        validate_schema(&connection)?;
        let pinned = connection.query_row(
            "SELECT store_id,capacity,maximum_obligations FROM metadata WHERE singleton=1",
            [],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )?;
        require(
            pinned
                == (
                    config.store_id.to_vec(),
                    config.capacity_bytes as i64,
                    i64::from(config.maximum_obligations),
                ),
            "retention capacity repin",
        )?;
        configure(&connection)?;
        let store = Self {
            directory: directory.to_path_buf(),
            config,
            connection,
            arena,
        };
        store.audit_layout()?;
        Ok(store)
    }

    pub fn store_id(&self) -> CellDigestV1 {
        self.config.store_id
    }

    pub fn contract(&self, operation: CellDigestV1) -> CellResultV1<CellRetentionContractV1> {
        Ok(self.required_row(operation)?.contract)
    }

    /// Reserve real already-allocated space before accepting bytes or ACKing.
    /// Exact retry keeps the original budget and identity, including retirement.
    pub fn reserve(
        &mut self,
        contract: CellRetentionContractV1,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        validate_contract(&contract, &self.config)?;
        if let Some(row) = self.row(contract.operation)? {
            require(row.contract == contract, "retention operation changed")?;
            return self.readback(&row);
        }
        let rows = self.audit_layout()?;
        require(
            rows.len() < self.config.maximum_obligations as usize,
            "retention record capacity",
        )?;
        require(
            rows.iter()
                .all(|r| r.contract.funding_operation != contract.funding_operation),
            "retention funding alias",
        )?;
        let reserved = aligned(contract.manifest.size())?;
        let mut offset = 0;
        for row in rows.iter().filter(|r| r.status != 2) {
            if offset + reserved <= row.offset {
                break;
            }
            offset = row.offset + row.reserved;
        }
        require(
            offset
                .checked_add(reserved)
                .is_some_and(|n| n <= self.config.capacity_bytes),
            "retention capacity exhausted",
        )?;
        let row = Row {
            contract,
            offset,
            reserved,
            status: 0,
            initial_bytes: 0,
            repair_bytes: 0,
        };
        self.write_row(&row, true)?;
        self.readback(&row)
    }

    /// Copy at most once under the original obligation identity. The entire
    /// initial byte charge is durable before writing; an uncertain prior attempt
    /// may only be reconciled, never automatically dispatched again.
    pub fn acknowledge(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let mut row = self.required_row(operation)?;
        require(row.status != 2, "retention retired")?;
        if row.status == 1 {
            self.verify_payload(&row, deadline)?;
            return self.readback(&row);
        }
        // Payload might already be fsynced after a lost ACK. Read it first.
        if self.verify_payload(&row, deadline).is_ok() {
            row.status = 1;
            self.write_row(&row, false)?;
            return self.readback(&row);
        }
        check_deadline(deadline)?;
        require(
            row.initial_bytes == 0,
            "retention initial copy requires reconciliation",
        )?;
        row.initial_bytes = row.contract.manifest.size();
        self.write_row(&row, false)?;
        self.copy_payload(&row, cache, deadline)?;
        row.status = 1;
        self.write_row(&row, false)?;
        self.readback(&row)
    }

    /// Uncontrolled local CPU interface; still obeys the wall deadline. Use
    /// reconcile_acknowledgement_controlled for a caller-enforced CPU budget.
    pub fn reconcile_acknowledgement(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.reconcile_acknowledgement_controlled(operation, deadline, &mut || Ok(()))
    }

    /// Resolve an existing intent only from the actual target. No source/cache
    /// parameter exists. Checkpoints run before/after each complete chunk and
    /// metadata/commit boundary; they do not provide kernel preemption.
    pub fn reconcile_acknowledgement_controlled(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let mut control = OperationControl {
            deadline,
            checkpoint,
            stopped: false,
        };
        control.check()?;
        let mut row = self.required_row(operation)?;
        control.check()?;
        require(row.status != 2, "retention retired")?;
        self.verify_payload_controlled(&row, &mut control)?;
        if row.status == 0 {
            row.status = 1;
            self.write_row_controlled(&row, false, &mut control)?;
        }
        control.check()?;
        let readback = self.readback(&row)?;
        control.check()?;
        Ok(readback)
    }

    /// Uncontrolled local CPU interface; it retains the absolute wall deadline
    /// and durable identity/cost rules. Funded callers use repair_controlled.
    pub fn repair(
        &mut self,
        operation: CellDigestV1,
        repair_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.repair_controlled(operation, repair_operation, cache, deadline, &mut || Ok(()))
    }

    /// Cooperative real-resource control. The caller's checkpoint must verify
    /// its original thread and actual CPU allowance; M09 also checks the same
    /// absolute wall deadline throughout. Checks surround each complete chunk,
    /// bounded metadata step and each synchronous SQLite/commit operation.
    /// A running chunk, filesystem or SQLite call is not preempted: one such
    /// interval may overrun before the next checkpoint observes exhaustion.
    /// Any already committed intent/whole-byte charge survives that refusal.
    pub fn repair_controlled(
        &mut self,
        operation: CellDigestV1,
        repair_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let mut control = OperationControl {
            deadline,
            checkpoint,
            stopped: false,
        };
        control.check()?;
        let mut row = self.required_row(operation)?;
        control.check()?;
        require(row.status != 2, "retention retired")?;
        require(
            repair_operation != [0; 32] && repair_operation != operation,
            "retention repair identity",
        )?;
        let previous = self.repair_row(repair_operation)?;
        control.check()?;
        if let Some((obligation, amount, complete)) = previous {
            require(
                obligation == operation
                    && (amount == row.contract.manifest.size() || (amount == 0 && complete)),
                "retention repair alias",
            )?;
            // Preserve checkpoint errors rather than misreporting CPU/wall
            // exhaustion as evidence that a new payload write is allowed.
            match self.verify_payload_controlled(&row, &mut control) {
                Ok(()) => {}
                Err(error) if control.stopped => return Err(error),
                Err(_) => {
                    return Err(CellErrorV1::Invalid(
                        "retention repair requires reconciliation",
                    ))
                }
            }
            if !complete {
                self.complete_repair_controlled(repair_operation, operation, amount, &mut control)?;
            }
            if row.status == 0 {
                row.status = 1;
                self.write_row_controlled(&row, false, &mut control)?;
            }
            control.check()?;
            let readback = self.readback(&row)?;
            control.check()?;
            return Ok(readback);
        }
        let already_complete = match self.verify_payload_controlled(&row, &mut control) {
            Ok(()) => true,
            Err(error) if control.stopped => return Err(error),
            Err(_) => false,
        };
        control.check()?;
        let count: u64 = self
            .connection
            .query_row("SELECT count(*) FROM repairs", [], |r| r.get(0))?;
        control.check()?;
        require(
            count < u64::from(self.config.maximum_obligations),
            "retention repair record capacity",
        )?;
        let amount = if already_complete {
            0
        } else {
            row.contract.manifest.size()
        };
        let prior_row_digest = row_checksum(&row);
        row.repair_bytes = row
            .repair_bytes
            .checked_add(amount)
            .ok_or(CellErrorV1::Invalid("retention repair overflow"))?;
        require(
            row.repair_bytes <= row.contract.maximum_repair_bytes,
            "retention repair capacity exhausted",
        )?;
        self.check_arena_controlled(&mut control)?;
        let row_digest = row_checksum(&row);
        let repair_digest = repair_checksum(repair_operation, operation, amount, already_complete);
        control.check()?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        control.check()?;
        validate_schema(&transaction)?;
        let prior = Self::row_from(&transaction, &self.config, operation)?
            .ok_or(CellErrorV1::Invalid("retention missing repair obligation"))?;
        require(
            row_checksum(&prior) == prior_row_digest,
            "retention repair prior changed",
        )?;
        require(
            Self::repair_row_from(&transaction, repair_operation)?.is_none(),
            "retention repair identity changed",
        )?;
        control.check()?;
        let inserted = transaction.execute(
            "INSERT INTO repairs VALUES (?1,?2,?3,?4,?5)",
            params![
                repair_operation.as_slice(),
                operation.as_slice(),
                amount as i64,
                already_complete,
                repair_digest
            ],
        )?;
        control.check()?;
        require(inserted == 1, "retention repair intent write")?;
        let charged = transaction.execute(
            "UPDATE obligations SET repair_bytes=?2,checksum=?3 WHERE operation=?1",
            params![operation.as_slice(), row.repair_bytes as i64, row_digest],
        )?;
        control.check()?;
        require(charged == 1, "retention repair charge write")?;
        // The complete actual rows must survive every SQLite write/trigger while
        // rollback can still remove the transaction. A successful execute count
        // alone is not a durable intent or proof that the byte charge persisted.
        Self::check_repair_seal(
            &transaction,
            &self.config,
            repair_operation,
            &row,
            amount,
            already_complete,
        )?;
        control.check()?;
        transaction.commit()?;
        control.check()?;
        // Commit succeeded; re-read the exact durable intent and whole charge
        // before any arena write. This is an operation-local write boundary,
        // not an authority cache or protection against complete host rollback.
        Self::check_repair_seal(
            &self.connection,
            &self.config,
            repair_operation,
            &row,
            amount,
            already_complete,
        )?;
        control.check()?;
        if !already_complete {
            self.copy_payload_controlled(&row, cache, &mut control)?;
            self.complete_repair_controlled(repair_operation, operation, amount, &mut control)?;
        }
        if row.status == 0 {
            row.status = 1;
            self.write_row_controlled(&row, false, &mut control)?;
        }
        control.check()?;
        let readback = self.readback(&row)?;
        control.check()?;
        Ok(readback)
    }

    /// Uncontrolled local CPU interface. It never copies a payload. Funded
    /// recovery calls reconcile_repair_controlled with the original CPU owner.
    pub fn reconcile_repair(
        &mut self,
        operation: CellDigestV1,
        repair_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.reconcile_repair_controlled(operation, repair_operation, deadline, &mut || Ok(()))
    }

    /// Target-only recovery under the same checkpoints as a new repair. A
    /// missing intent can seal a zero-byte identity only if the target already
    /// verifies completely; neither CPU exhaustion nor corruption dispatches.
    pub fn reconcile_repair_controlled(
        &mut self,
        operation: CellDigestV1,
        repair_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let mut control = OperationControl {
            deadline,
            checkpoint,
            stopped: false,
        };
        control.check()?;
        let mut row = self.required_row(operation)?;
        control.check()?;
        require(row.status != 2, "retention retired")?;
        require(
            repair_operation != [0; 32] && repair_operation != operation,
            "retention repair identity",
        )?;
        let previous = self.repair_row(repair_operation)?;
        control.check()?;
        if let Some((obligation, amount, complete)) = previous {
            require(
                obligation == operation
                    && (amount == row.contract.manifest.size() || (amount == 0 && complete)),
                "retention repair alias",
            )?;
        }
        self.verify_payload_controlled(&row, &mut control)?;
        match previous {
            Some((obligation, amount, false)) => {
                self.complete_repair_controlled(repair_operation, obligation, amount, &mut control)?
            }
            Some((_, _, true)) => {}
            None => {
                control.check()?;
                let count: u64 =
                    self.connection
                        .query_row("SELECT count(*) FROM repairs", [], |r| r.get(0))?;
                control.check()?;
                require(
                    count < u64::from(self.config.maximum_obligations),
                    "retention repair record capacity",
                )?;
                let transaction = self
                    .connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                control.check()?;
                validate_schema(&transaction)?;
                let inserted = transaction.execute(
                    "INSERT INTO repairs VALUES (?1,?2,0,1,?3)",
                    params![
                        repair_operation.as_slice(),
                        operation.as_slice(),
                        repair_checksum(repair_operation, operation, 0, true)
                    ],
                )?;
                control.check()?;
                require(inserted == 1, "retention repair reconciliation write")?;
                Self::check_repair_seal(
                    &transaction,
                    &self.config,
                    repair_operation,
                    &row,
                    0,
                    true,
                )?;
                control.check()?;
                transaction.commit()?;
                control.check()?;
                Self::check_repair_seal(
                    &self.connection,
                    &self.config,
                    repair_operation,
                    &row,
                    0,
                    true,
                )?;
                control.check()?;
            }
        }
        if row.status == 0 {
            row.status = 1;
            self.write_row_controlled(&row, false, &mut control)?;
        }
        control.check()?;
        let readback = self.readback(&row)?;
        control.check()?;
        Ok(readback)
    }

    /// Rehydrate the ordinary cache from freshly verified retained bytes. The
    /// existing peer server/fetcher can then use its unchanged chunk protocol.
    pub fn populate_cache(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let row = self.required_row(operation)?;
        require(row.status == 1, "retention unavailable")?;
        self.verify_payload(&row, deadline)?;
        cache.put_manifest(row.contract.manifest.id(), &row.contract.manifest.encode())?;
        self.arena.seek(SeekFrom::Start(row.offset))?;
        for chunk in row.contract.manifest.chunks() {
            check_deadline(deadline)?;
            let mut bytes = vec![0; chunk.size as usize];
            self.arena.read_exact(&mut bytes)?;
            cache.put_chunk(chunk, &bytes)?;
        }
        cache.verify_complete_until(&row.contract.manifest, deadline)?;
        self.readback(&row)
    }

    pub fn verify(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        let row = self.required_row(operation)?;
        require(row.status == 1, "retention unavailable")?;
        self.verify_payload(&row, deadline)?;
        self.readback(&row)
    }

    /// The caller supplies its current locally verified chain height. Reorgs do
    /// not undo retirement or other physical facts. A required successor must
    /// be opened and freshly read here; a supplied receipt cannot satisfy it.
    /// This local handoff establishes no independent-operator/WAN qualification.
    pub fn retire(
        &mut self,
        operation: CellDigestV1,
        current_height: u64,
        successor: Option<&mut CellRetentionStoreV1>,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        check_deadline(deadline)?;
        let mut row = self.required_row(operation)?;
        if row.status == 2 {
            return self.readback(&row);
        }
        require(
            current_height >= row.contract.retain_until_height,
            "retention not expired",
        )?;
        require(row.status == 1, "retention pending duty")?;
        if let Some((store_id, successor_operation)) = row.contract.successor {
            let successor =
                successor.ok_or(CellErrorV1::Invalid("retention successor required"))?;
            require(
                successor.config.store_id == store_id && store_id != self.config.store_id,
                "retention successor store",
            )?;
            let next = successor.verify(successor_operation, deadline)?;
            require(
                next.manifest == row.contract.manifest.id()
                    && next.retain_from_height <= current_height
                    && next.retain_until_height > current_height
                    && !next.retired,
                "retention successor coverage",
            )?;
        }
        check_deadline(deadline)?;
        row.status = 2;
        self.write_row(&row, false)?;
        self.readback(&row)
    }

    fn copy_payload(
        &mut self,
        row: &Row,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        let mut checkpoint = || Ok(());
        self.copy_payload_controlled(
            row,
            cache,
            &mut OperationControl {
                deadline,
                checkpoint: &mut checkpoint,
                stopped: false,
            },
        )
    }

    fn copy_payload_controlled(
        &mut self,
        row: &Row,
        cache: &CellStoreV1,
        control: &mut OperationControl<'_, impl FnMut() -> CellResultV1<()>>,
    ) -> CellResultV1<()> {
        control.check()?;
        self.arena.seek(SeekFrom::Start(row.offset))?;
        control.check()?;
        let mut complete = Sha256::new();
        for expected in row.contract.manifest.chunks() {
            control.check()?;
            let bytes = cache.chunk(expected.sha256);
            control.check()?;
            let bytes = bytes?.ok_or(CellErrorV1::Unavailable)?;
            let verified = verify_chunk(expected, &bytes);
            control.check()?;
            verified?;
            self.arena.write_all(&bytes)?;
            complete.update(bytes);
            control.check()?;
        }
        require(
            <[u8; 32]>::from(complete.finalize()) == row.contract.manifest.payload_sha256(),
            "retention complete digest",
        )?;
        control.check()?;
        self.arena.sync_all()?;
        control.check()?;
        self.verify_payload_controlled(row, control)
    }

    fn verify_payload(&mut self, row: &Row, deadline: Instant) -> CellResultV1<()> {
        let mut checkpoint = || Ok(());
        self.verify_payload_controlled(
            row,
            &mut OperationControl {
                deadline,
                checkpoint: &mut checkpoint,
                stopped: false,
            },
        )
    }

    fn verify_payload_controlled(
        &mut self,
        row: &Row,
        control: &mut OperationControl<'_, impl FnMut() -> CellResultV1<()>>,
    ) -> CellResultV1<()> {
        control.check()?;
        self.check_arena_controlled(control)?;
        self.arena.seek(SeekFrom::Start(row.offset))?;
        control.check()?;
        let mut full = Sha256::new();
        for expected in row.contract.manifest.chunks() {
            control.check()?;
            let mut bytes = vec![0; expected.size as usize];
            self.arena.read_exact(&mut bytes)?;
            control.check()?;
            let verified = verify_chunk(expected, &bytes);
            control.check()?;
            verified?;
            full.update(bytes);
            control.check()?;
        }
        require(
            <[u8; 32]>::from(full.finalize()) == row.contract.manifest.payload_sha256(),
            "retention payload digest",
        )?;
        control.check()
    }

    fn check_arena_controlled(
        &self,
        control: &mut OperationControl<'_, impl FnMut() -> CellResultV1<()>>,
    ) -> CellResultV1<()> {
        control.check()?;
        let path = fs::symlink_metadata(self.directory.join("payload.arena"))?;
        control.check()?;
        let fd = self.arena.metadata()?;
        control.check()?;
        let allocated = FileExt::allocated_size(&self.arena)?;
        control.check()?;
        require(
            path.is_file()
                && fd.is_file()
                && fd.len() == self.config.capacity_bytes
                && allocated >= self.config.capacity_bytes,
            "retention physical capacity",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                path.ino() == fd.ino() && path.dev() == fd.dev() && fd.nlink() == 1,
                "retention arena identity",
            )?;
        }
        Ok(())
    }

    fn check_arena(&self) -> CellResultV1<()> {
        let path = fs::symlink_metadata(self.directory.join("payload.arena"))?;
        let fd = self.arena.metadata()?;
        require(
            path.is_file()
                && fd.is_file()
                && fd.len() == self.config.capacity_bytes
                && FileExt::allocated_size(&self.arena)? >= self.config.capacity_bytes,
            "retention physical capacity",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                path.ino() == fd.ino() && path.dev() == fd.dev() && fd.nlink() == 1,
                "retention arena identity",
            )?;
        }
        Ok(())
    }

    fn readback(&self, row: &Row) -> CellResultV1<CellRetentionReadbackV1> {
        self.check_arena()?;
        Ok(CellRetentionReadbackV1 {
            store_id: self.config.store_id,
            operation: row.contract.operation,
            funding_operation: row.contract.funding_operation,
            manifest: row.contract.manifest.id(),
            payload_bytes: row.contract.manifest.size(),
            reserved_bytes: row.reserved,
            physical_arena_bytes: FileExt::allocated_size(&self.arena)?,
            retain_from_height: row.contract.retain_from_height,
            retain_until_height: row.contract.retain_until_height,
            initial_copy_bytes_committed: row.initial_bytes,
            repair_bytes_committed: row.repair_bytes,
            acknowledged: row.status == 1,
            retired: row.status == 2,
        })
    }

    fn required_row(&self, operation: CellDigestV1) -> CellResultV1<Row> {
        self.row(operation)?
            .ok_or(CellErrorV1::Invalid("retention unknown obligation"))
    }

    fn row(&self, operation: CellDigestV1) -> CellResultV1<Option<Row>> {
        Self::row_from(&self.connection, &self.config, operation)
    }

    fn row_from(
        connection: &Connection,
        config: &CellRetentionConfigV1,
        operation: CellDigestV1,
    ) -> CellResultV1<Option<Row>> {
        let raw = connection.query_row(
            "SELECT funding,CASE WHEN length(manifest)<=1048576 THEN manifest ELSE NULL END,
             retain_from,retain_until,repair_limit,successor_store,successor_operation,position,reserved,status,initial_bytes,repair_bytes,checksum
             FROM obligations WHERE operation=?1", [operation.as_slice()], |r| {
                Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Option<Vec<u8>>>(1)?,r.get::<_,u64>(2)?,
                    r.get::<_,u64>(3)?,r.get::<_,u64>(4)?,r.get::<_,Option<Vec<u8>>>(5)?,r.get::<_,Option<Vec<u8>>>(6)?,
                    r.get::<_,u64>(7)?,r.get::<_,u64>(8)?,r.get::<_,u8>(9)?,r.get::<_,u64>(10)?,r.get::<_,u64>(11)?,r.get::<_,Vec<u8>>(12)?))
            }).optional()?;
        let Some((
            funding,
            wire,
            from,
            until,
            repair_limit,
            next_store,
            next_operation,
            offset,
            reserved,
            status,
            initial_bytes,
            repair_bytes,
            checksum,
        )) = raw
        else {
            return Ok(None);
        };
        let successor = match (next_store, next_operation) {
            (None, None) => None,
            (Some(a), Some(b)) => Some((digest(a)?, digest(b)?)),
            _ => return Err(CellErrorV1::Invalid("retention successor encoding")),
        };
        let row = Row {
            contract: CellRetentionContractV1 {
                operation,
                funding_operation: digest(funding)?,
                manifest: CellManifestV1::decode(
                    &wire.ok_or(CellErrorV1::Invalid("retention manifest size"))?,
                )?,
                retain_from_height: from,
                retain_until_height: until,
                maximum_repair_bytes: repair_limit,
                successor,
            },
            offset,
            reserved,
            status,
            initial_bytes,
            repair_bytes,
        };
        validate_contract(&row.contract, config)?;
        require(
            status <= 2
                && reserved == aligned(row.contract.manifest.size())?
                && offset.is_multiple_of(ALIGNMENT)
                && offset
                    .checked_add(reserved)
                    .is_some_and(|end| end <= config.capacity_bytes)
                && (initial_bytes == 0 || initial_bytes == row.contract.manifest.size())
                && repair_bytes <= repair_limit
                && checksum == row_checksum(&row),
            "retention row integrity",
        )?;
        Ok(Some(row))
    }

    fn audit_layout(&self) -> CellResultV1<Vec<Row>> {
        self.check_arena()?;
        let count: u64 =
            self.connection
                .query_row("SELECT count(*) FROM obligations", [], |r| r.get(0))?;
        require(
            count <= u64::from(self.config.maximum_obligations),
            "retention record capacity",
        )?;
        let mut stmt = self
            .connection
            .prepare("SELECT operation FROM obligations ORDER BY position,operation")?;
        let mut ids = stmt.query([])?;
        let mut rows = Vec::with_capacity(count as usize);
        let mut end = 0;
        while let Some(id) = ids.next()? {
            let row = self.required_row(digest(id.get(0)?)?)?;
            if row.status != 2 {
                require(row.offset >= end, "retention overlapping duties")?;
                end = row.offset + row.reserved;
            }
            rows.push(row);
        }
        let repair_count: u64 =
            self.connection
                .query_row("SELECT count(*) FROM repairs", [], |r| r.get(0))?;
        require(
            repair_count <= u64::from(self.config.maximum_obligations),
            "retention repair record capacity",
        )?;
        let mut totals = std::collections::BTreeMap::<CellDigestV1, u64>::new();
        let mut stmt = self
            .connection
            .prepare("SELECT operation FROM repairs ORDER BY operation")?;
        let mut ids = stmt.query([])?;
        while let Some(id) = ids.next()? {
            let (obligation, amount, complete) = self
                .repair_row(digest(id.get(0)?)?)?
                .ok_or(CellErrorV1::Invalid("retention missing repair"))?;
            let original = rows
                .iter()
                .find(|row| row.contract.operation == obligation)
                .ok_or(CellErrorV1::Invalid("retention orphaned repair"))?;
            require(
                amount == original.contract.manifest.size() || (amount == 0 && complete),
                "retention repair amount",
            )?;
            let total = totals.entry(obligation).or_default();
            *total = total
                .checked_add(amount)
                .ok_or(CellErrorV1::Invalid("retention repair overflow"))?;
        }
        for row in &rows {
            require(
                row.repair_bytes == totals.get(&row.contract.operation).copied().unwrap_or(0),
                "retention repair conservation",
            )?;
        }
        Ok(rows)
    }

    fn repair_row(
        &self,
        operation: CellDigestV1,
    ) -> CellResultV1<Option<(CellDigestV1, u64, bool)>> {
        Self::repair_row_from(&self.connection, operation)
    }

    fn repair_row_from(
        connection: &Connection,
        operation: CellDigestV1,
    ) -> CellResultV1<Option<(CellDigestV1, u64, bool)>> {
        let raw = connection
            .query_row(
                "SELECT obligation,amount,complete,checksum FROM repairs WHERE operation=?1",
                [operation.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((obligation, amount, complete, checksum)) = raw else {
            return Ok(None);
        };
        let obligation = digest(obligation)?;
        require(
            operation != [0; 32]
                && operation != obligation
                && (amount > 0 || complete)
                && checksum == repair_checksum(operation, obligation, amount, complete),
            "retention repair integrity",
        )?;
        Ok(Some((obligation, amount, complete)))
    }

    fn check_repair_seal(
        connection: &Connection,
        config: &CellRetentionConfigV1,
        operation: CellDigestV1,
        row: &Row,
        amount: u64,
        complete: bool,
    ) -> CellResultV1<()> {
        validate_schema(connection)?;
        let stored = Self::row_from(connection, config, row.contract.operation)?
            .ok_or(CellErrorV1::Invalid("retention missing repair obligation"))?;
        require(
            row_checksum(&stored) == row_checksum(row),
            "retention repair charge readback",
        )?;
        require(
            Self::repair_row_from(connection, operation)?
                == Some((row.contract.operation, amount, complete)),
            "retention repair intent readback",
        )
    }

    fn complete_repair_controlled(
        &mut self,
        operation: CellDigestV1,
        obligation: CellDigestV1,
        amount: u64,
        control: &mut OperationControl<'_, impl FnMut() -> CellResultV1<()>>,
    ) -> CellResultV1<()> {
        control.check()?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        control.check()?;
        validate_schema(&transaction)?;
        require(
            Self::repair_row_from(&transaction, operation)? == Some((obligation, amount, false)),
            "retention repair completion prior",
        )?;
        control.check()?;
        let count = transaction.execute(
            "UPDATE repairs SET complete=1,checksum=?2 WHERE operation=?1",
            params![
                operation.as_slice(),
                repair_checksum(operation, obligation, amount, true)
            ],
        )?;
        control.check()?;
        require(count == 1, "retention missing repair completion")?;
        require(
            Self::repair_row_from(&transaction, operation)? == Some((obligation, amount, true)),
            "retention repair completion readback",
        )?;
        control.check()?;
        transaction.commit()?;
        control.check()?;
        validate_schema(&self.connection)?;
        require(
            self.repair_row(operation)? == Some((obligation, amount, true)),
            "retention repair completion readback",
        )?;
        control.check()
    }

    fn write_row_controlled(
        &mut self,
        row: &Row,
        insert: bool,
        control: &mut OperationControl<'_, impl FnMut() -> CellResultV1<()>>,
    ) -> CellResultV1<()> {
        self.check_arena_controlled(control)?;
        let checksum = row_checksum(row);
        control.check()?;
        let (next_store, next_operation) = row
            .contract
            .successor
            .map_or((None, None), |(a, b)| (Some(a.to_vec()), Some(b.to_vec())));
        if insert {
            self.connection.execute(
                "INSERT INTO obligations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    row.contract.operation.as_slice(),
                    row.contract.funding_operation.as_slice(),
                    row.contract.manifest.encode(),
                    row.contract.retain_from_height as i64,
                    row.contract.retain_until_height as i64,
                    row.contract.maximum_repair_bytes as i64,
                    next_store,
                    next_operation,
                    row.offset as i64,
                    row.reserved as i64,
                    row.status,
                    row.initial_bytes as i64,
                    row.repair_bytes as i64,
                    checksum
                ],
            )?;
        } else {
            let count=self.connection.execute("UPDATE obligations SET status=?2,initial_bytes=?3,repair_bytes=?4,checksum=?5 WHERE operation=?1",
                params![row.contract.operation.as_slice(),row.status,row.initial_bytes as i64,row.repair_bytes as i64,checksum])?;
            control.check()?;
            require(count == 1, "retention missing update")?;
        }
        control.check()?;
        let reread = self.required_row(row.contract.operation)?;
        control.check()?;
        require(
            row_checksum(&reread) == row_checksum(row),
            "retention commit readback",
        )?;
        control.check()
    }

    fn write_row(&mut self, row: &Row, insert: bool) -> CellResultV1<()> {
        self.check_arena()?;
        let checksum = row_checksum(row);
        let (next_store, next_operation) = row
            .contract
            .successor
            .map_or((None, None), |(a, b)| (Some(a.to_vec()), Some(b.to_vec())));
        if insert {
            self.connection.execute(
                "INSERT INTO obligations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    row.contract.operation.as_slice(),
                    row.contract.funding_operation.as_slice(),
                    row.contract.manifest.encode(),
                    row.contract.retain_from_height as i64,
                    row.contract.retain_until_height as i64,
                    row.contract.maximum_repair_bytes as i64,
                    next_store,
                    next_operation,
                    row.offset as i64,
                    row.reserved as i64,
                    row.status,
                    row.initial_bytes as i64,
                    row.repair_bytes as i64,
                    checksum
                ],
            )?;
        } else {
            let changed=self.connection.execute("UPDATE obligations SET status=?2,initial_bytes=?3,repair_bytes=?4,checksum=?5 WHERE operation=?1",
                params![row.contract.operation.as_slice(),row.status,row.initial_bytes as i64,row.repair_bytes as i64,checksum])?;
            require(changed == 1, "retention missing update")?;
        }
        // FULL WAL commit makes every ACK/budget debit durable before return.
        let reread = self.required_row(row.contract.operation)?;
        require(
            row_checksum(&reread) == row_checksum(row),
            "retention commit readback",
        )
    }
}

impl Drop for CellRetentionStoreV1 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.arena);
    }
}

fn validate_schema(connection: &Connection) -> CellResultV1<()> {
    for (name, expected) in [
        ("metadata", META_SQL),
        ("obligations", OBLIGATIONS_SQL),
        ("repairs", REPAIRS_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        require(actual.as_deref() == Some(expected), "retention schema")?;
    }
    let objects: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    require(objects == 3, "retention schema")
}

fn configure(connection: &Connection) -> CellResultV1<()> {
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn open_arena(path: &Path, create: bool) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    require(file.metadata()?.is_file(), "retention regular arena")?;
    Ok(file)
}

fn validate_config(config: &CellRetentionConfigV1) -> CellResultV1<()> {
    require(
        config.store_id != [0; 32]
            && (ALIGNMENT..=MAX_CELL_BYTES).contains(&config.capacity_bytes)
            && config.capacity_bytes.is_multiple_of(ALIGNMENT)
            && (1..=MAX_RECORDS).contains(&config.maximum_obligations),
        "retention configuration",
    )
}

fn validate_contract(
    contract: &CellRetentionContractV1,
    config: &CellRetentionConfigV1,
) -> CellResultV1<()> {
    contract.manifest.validate()?;
    require(
        contract.operation != [0; 32]
            && contract.funding_operation != [0; 32]
            && contract.retain_from_height < contract.retain_until_height
            && contract.retain_until_height <= i64::MAX as u64
            && contract.maximum_repair_bytes <= i64::MAX as u64,
        "retention contract",
    )?;
    if let Some((store, operation)) = contract.successor {
        require(
            store != [0; 32] && store != config.store_id && operation != [0; 32],
            "retention successor",
        )?;
    }
    Ok(())
}

fn aligned(size: u64) -> CellResultV1<u64> {
    size.checked_add(ALIGNMENT - 1)
        .map(|v| v / ALIGNMENT * ALIGNMENT)
        .ok_or(CellErrorV1::Invalid("retention size overflow"))
}

fn digest(value: Vec<u8>) -> CellResultV1<CellDigestV1> {
    value
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("retention digest"))
}

fn row_checksum(row: &Row) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"trnm.cell-retention-obligation.v1\0");
    h.update(row.contract.operation);
    h.update(row.contract.funding_operation);
    h.update(row.contract.manifest.id());
    for value in [
        row.contract.retain_from_height,
        row.contract.retain_until_height,
        row.contract.maximum_repair_bytes,
        row.offset,
        row.reserved,
        row.initial_bytes,
        row.repair_bytes,
    ] {
        h.update(value.to_be_bytes());
    }
    h.update([row.status]);
    if let Some((store, operation)) = row.contract.successor {
        h.update([1]);
        h.update(store);
        h.update(operation);
    } else {
        h.update([0]);
    }
    h.finalize().to_vec()
}

fn repair_checksum(
    operation: CellDigestV1,
    obligation: CellDigestV1,
    amount: u64,
    complete: bool,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"trnm.cell-retention-repair.v1\0");
    h.update(operation);
    h.update(obligation);
    h.update(amount.to_be_bytes());
    h.update([u8::from(complete)]);
    h.finalize().to_vec()
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() <= deadline, "retention deadline")
}

#[cfg(test)]
mod tests;
