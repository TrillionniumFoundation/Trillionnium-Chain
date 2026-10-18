use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    engine::{
        apply_transition, initial_state, operation_id, state_root, validate_execution_static,
        validate_trust_bundle,
    },
    error::{error, ConsumptionSettlementErrorCodeV1, ConsumptionSettlementResultV1},
    *,
};

const JOURNAL_SCHEMA_VERSION_V1: u16 = 2;
const META_SQL: &str = "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,config BLOB NOT NULL,sequence INTEGER NOT NULL,height INTEGER NOT NULL,block_id BLOB NOT NULL,state BLOB NOT NULL,state_root BLOB NOT NULL,journal_root BLOB NOT NULL,fenced INTEGER NOT NULL CHECK(fenced IN(0,1)),checksum BLOB NOT NULL) STRICT";
const OP_SQL: &str = "CREATE TABLE operations(sequence INTEGER PRIMARY KEY,operation_id BLOB NOT NULL UNIQUE,execution BLOB NOT NULL,command BLOB NOT NULL,receipt BLOB NOT NULL,checksum BLOB NOT NULL) STRICT";
const COMMITTED_BLOCKS_SQL: &str = "CREATE TABLE committed_blocks(marker_sequence INTEGER PRIMARY KEY,order_height INTEGER NOT NULL,order_block_id BLOB NOT NULL UNIQUE CHECK(length(order_block_id)=32),parent_order_height INTEGER NOT NULL,parent_order_block_id BLOB NOT NULL CHECK(length(parent_order_block_id)=32),source_operation_sequence INTEGER NOT NULL,target_operation_sequence INTEGER NOT NULL,source_state_root BLOB NOT NULL CHECK(length(source_state_root)=32),target_state_root BLOB NOT NULL CHECK(length(target_state_root)=32),source_operation_root BLOB NOT NULL CHECK(length(source_operation_root)=32),target_operation_root BLOB NOT NULL CHECK(length(target_operation_root)=32),previous_marker_checksum BLOB NOT NULL CHECK(length(previous_marker_checksum)=32),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";

#[derive(Clone, Debug)]
pub struct ConsumptionSettlementStoreConfigV1 {
    pub path: PathBuf,
    pub store_id: Hash32V1,
    pub trust_bundle: ConsumptionSettlementFreshGenesisTrustBundleV1,
}

#[derive(Debug)]
pub struct ConfirmedConsumptionTransitionV1 {
    receipt: ConsumptionTransitionReceiptV1,
}

impl ConfirmedConsumptionTransitionV1 {
    pub const fn receipt(&self) -> &ConsumptionTransitionReceiptV1 {
        &self.receipt
    }
}

/// Exact local settlement head observed through a fresh read-only reopen.
///
/// This carrier is not a cross-store checkpoint or anti-rollback authority.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsumptionSettlementFreshReadbackV1 {
    context: ProtocolContextV1,
    store_schema_version: u16,
    store_id: Hash32V1,
    sequence: u64,
    order_height: u64,
    order_block_id: Hash32V1,
    durable_state_root: Hash32V1,
    durable_journal_root: Hash32V1,
    durable_committed_block_root: Hash32V1,
}

#[derive(Clone, Copy, Debug)]
struct CommittedBlockMarkerV1 {
    marker_sequence: u64,
    order_height: u64,
    order_block_id: Hash32V1,
    parent_order_height: u64,
    parent_order_block_id: Hash32V1,
    source_operation_sequence: u64,
    target_operation_sequence: u64,
    source_state_root: Hash32V1,
    target_state_root: Hash32V1,
    source_operation_root: Hash32V1,
    target_operation_root: Hash32V1,
    previous_marker_checksum: Hash32V1,
    checksum: Hash32V1,
}

/// Read-only candidate transition result for a prospective Order block.
///
/// The candidate root is local to this bounded settlement kernel; it is not a
/// normative application/JMT root and carries no confirmation claim.
#[derive(Debug)]
pub struct ConsumptionSettlementExecutionPreviewV1 {
    source_sequence: u64,
    source_state_root: Hash32V1,
    source_journal_root: Hash32V1,
    candidate_post_state_root: Hash32V1,
    candidate_receipts: Vec<ConsumptionTransitionReceiptV1>,
}

impl ConsumptionSettlementExecutionPreviewV1 {
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub const fn source_state_root(&self) -> Hash32V1 {
        self.source_state_root
    }

    pub const fn source_journal_root(&self) -> Hash32V1 {
        self.source_journal_root
    }

    pub const fn candidate_post_state_root(&self) -> Hash32V1 {
        self.candidate_post_state_root
    }

    pub fn candidate_receipts(&self) -> &[ConsumptionTransitionReceiptV1] {
        &self.candidate_receipts
    }
}

impl ConsumptionSettlementFreshReadbackV1 {
    pub const fn context(&self) -> &ProtocolContextV1 {
        &self.context
    }

    pub const fn store_schema_version(&self) -> u16 {
        self.store_schema_version
    }

    pub const fn store_id(&self) -> Hash32V1 {
        self.store_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn order_height(&self) -> u64 {
        self.order_height
    }

    pub const fn order_block_id(&self) -> Hash32V1 {
        self.order_block_id
    }

    pub const fn durable_state_root(&self) -> Hash32V1 {
        self.durable_state_root
    }

    pub const fn durable_journal_root(&self) -> Hash32V1 {
        self.durable_journal_root
    }

    pub const fn durable_committed_block_root(&self) -> Hash32V1 {
        self.durable_committed_block_root
    }
}

#[derive(Debug)]
pub struct ConsumptionSettlementOutcomeV1 {
    pub confirmed: ConfirmedConsumptionTransitionV1,
    pub replay: bool,
}

impl ConsumptionSettlementOutcomeV1 {
    pub const fn receipt(&self) -> &ConsumptionTransitionReceiptV1 {
        self.confirmed.receipt()
    }

    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

#[derive(Clone, Debug)]
pub struct ConsumptionSettlementStoreV1 {
    config: ConsumptionSettlementStoreConfigV1,
}

impl ConsumptionSettlementStoreV1 {
    pub fn open(config: ConsumptionSettlementStoreConfigV1) -> ConsumptionSettlementResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        reject_sidecars(&config.path)?;
        if config.path.exists() {
            let connection = open_read_snapshot(&config.path)?;
            verify_schema(&connection)?;
            audit(&connection, &config)?;
            if load_metadata(&connection, &config)?.5 {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                    "store is permanently fenced",
                ));
            }
        } else {
            // Reject unsupported fresh configuration before creating any path.
            // Existing stores retain their ordinary audit/compatibility checks.
            to_sqlite(
                config.trust_bundle.initial_order_height,
                "initial Order height",
            )?;
            if let Some(parent) = config.path.parent() {
                fs::create_dir_all(parent).map_err(|cause| {
                    error(
                        ConsumptionSettlementErrorCodeV1::StoreFailure,
                        cause.to_string(),
                    )
                })?;
            }
            let mut connection = open_rw(&config.path, true)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(COMMITTED_BLOCKS_SQL)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(OP_SQL)?;
            let state = initial_state(&config.trust_bundle);
            let journal_root = operation_journal_root(&transaction)?;
            insert_anchor_committed_block_marker(
                &transaction,
                &config,
                state_root(&state)?,
                journal_root,
            )?;
            write_metadata(
                &transaction,
                &config,
                0,
                config.trust_bundle.initial_order_height,
                config.trust_bundle.initial_order_block_id,
                &state,
                journal_root,
                false,
            )?;
            transaction.commit()?;
            drop(connection);
            let connection = open_read_snapshot(&config.path)?;
            verify_schema(&connection)?;
            audit(&connection, &config)?;
        }
        Ok(Self { config })
    }

    /// Open and fully audit an already-created store without creating a
    /// parent directory, database, schema, migration, or writable SQLite
    /// handle.
    ///
    /// The path must name a regular file directly. Missing paths, symlinks
    /// and non-regular filesystem objects are rejected before SQLite is
    /// opened.
    pub fn open_existing(
        config: ConsumptionSettlementStoreConfigV1,
    ) -> ConsumptionSettlementResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        let connection = open_read_snapshot(&config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &config)?;
        if load_metadata(&connection, &config)?.5 {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        drop(connection);
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        Ok(Self { config })
    }

    pub fn execute_committed_execution(
        &self,
        execution: &ConsumptionCommittedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        self.execute_inner(execution, command, None)
    }

    /// Advance one committed Order block with no settlement commands.
    ///
    /// The direct-successor Order tip is the only changed fact.  State,
    /// sequence and journal roots remain byte-exact, and a fresh observation
    /// of the target resolves an exact retry after acknowledgement loss.
    pub fn advance_empty_committed_execution_v1(
        &self,
        execution: &ConsumptionCommittedExecutionContextV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_static(&self.config.trust_bundle, execution)?;
        if execution.expected_order_height.checked_add(1) != Some(execution.order_height) {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidContext,
                "empty committed batch is not the direct Order successor",
            ));
        }

        let snapshot = open_read_snapshot(&self.config.path)?;
        let before = self.readback_from_snapshot(&snapshot)?;
        if before.order_height == execution.order_height
            && before.order_block_id == execution.order_block_id
        {
            let markers = load_committed_block_markers(&snapshot, &self.config)?;
            let tail = markers.last().expect("audited marker journal is nonempty");
            if tail.marker_sequence == 0
                || (tail.parent_order_height, tail.parent_order_block_id)
                    != (
                        execution.expected_order_height,
                        execution.expected_order_block_id,
                    )
                || tail.source_operation_sequence != tail.target_operation_sequence
            {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::Conflict,
                    "empty committed batch retry differs from durable marker",
                ));
            }
            return Ok(before);
        }
        drop(snapshot);
        if before.order_height != execution.expected_order_height
            || before.order_block_id != execution.expected_order_block_id
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::StaleVersion,
                "empty committed batch parent differs from durable head",
            ));
        }

        let mut connection = open_rw(&self.config.path, false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_schema(&transaction)?;
        audit(&transaction, &self.config)?;
        let (sequence, height, block_id, state, journal_root, fenced) =
            load_metadata(&transaction, &self.config)?;
        if fenced {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        validate_execution_cas(execution, height, block_id)?;
        let durable_state_root = state_root(&state)?;
        advance_committed_block_marker(
            &transaction,
            &self.config,
            execution,
            sequence,
            sequence,
            durable_state_root,
            durable_state_root,
            journal_root,
            journal_root,
        )?;
        write_metadata(
            &transaction,
            &self.config,
            sequence,
            execution.order_height,
            execution.order_block_id,
            &state,
            journal_root,
            false,
        )?;
        transaction.commit()?;
        drop(connection);

        let after = self.fresh_readback()?;
        if after.sequence != before.sequence
            || after.order_height != execution.order_height
            || after.order_block_id != execution.order_block_id
            || after.durable_state_root != before.durable_state_root
            || after.durable_journal_root != before.durable_journal_root
            || after.durable_committed_block_root == before.durable_committed_block_root
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "empty committed batch readback differs from its exact target",
            ));
        }
        Ok(after)
    }

    /// Execute settlement commands from one exact authenticated parent in
    /// memory.  The source database is freshly authenticated before and after
    /// the preview and is never opened for writing.
    pub fn preview_before_vote_v1(
        &self,
        expected_parent: &ConsumptionSettlementFreshReadbackV1,
        candidate_height: u64,
        candidate_block_id: Hash32V1,
        commands: &[ConsumptionSettlementCommandV1],
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementExecutionPreviewV1> {
        let connection = open_read_snapshot(&self.config.path)?;
        let before = self.readback_from_snapshot(&connection)?;
        if &before != expected_parent
            || candidate_height
                != before.order_height.checked_add(1).ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "candidate height overflows",
                    )
                })?
            || candidate_block_id == Hash32V1([0; 32])
            || candidate_block_id == before.order_block_id
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidContext,
                "pre-commit candidate does not extend the exact fresh parent",
            ));
        }
        validate_preview_sqlite_bounds(candidate_height, before.sequence, commands.len())?;
        let recorded_block_id: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM committed_blocks WHERE order_block_id=?1)",
            params![candidate_block_id.0.to_vec()],
            |row| row.get(0),
        )?;
        if recorded_block_id {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidContext,
                "pre-commit candidate block ID is already recorded",
            ));
        }
        let mut state = load_metadata(&connection, &self.config)?.3;
        let mut operation_ids = BTreeSet::new();
        let mut receipts = Vec::with_capacity(commands.len());
        for (offset, command) in commands.iter().enumerate() {
            let id = operation_id(command)?;
            if !operation_ids.insert(id) || load_operation(&connection, id)?.is_some() {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::Conflict,
                    "pre-commit batch repeats a Consumption/Settlement operation",
                ));
            }
            let (next_state, settlement_id) = apply_new_store_transition(
                &self.config.trust_bundle,
                &state,
                candidate_height,
                command,
            )?;
            state = next_state;
            let offset = u64::try_from(offset).map_err(|_| {
                error(
                    ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                    "pre-commit operation index exceeds u64",
                )
            })?;
            let next = before
                .sequence
                .checked_add(offset)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "pre-commit sequence overflows",
                    )
                })?;
            receipts.push(ConsumptionTransitionReceiptV1 {
                schema_version: SCHEMA_VERSION_V1,
                store_id: self.config.store_id,
                sequence: next,
                operation_id: id,
                operation_kind: command.operation_kind(),
                order_height: candidate_height,
                order_block_id: candidate_block_id,
                post_state_root: state_root(&state)?,
                settlement_id,
            });
        }
        drop(connection);
        let candidate_post_state_root = state_root(&state)?;
        let after = self.fresh_readback()?;
        if after != before {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "Consumption/Settlement source changed during read-only preview",
            ));
        }
        Ok(ConsumptionSettlementExecutionPreviewV1 {
            source_sequence: before.sequence,
            source_state_root: before.durable_state_root,
            source_journal_root: before.durable_journal_root,
            candidate_post_state_root,
            candidate_receipts: receipts,
        })
    }

    #[cfg(test)]
    pub(crate) fn execute_with_fault(
        &self,
        execution: &ConsumptionCommittedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
        fault: ConsumptionCommitFaultV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        self.execute_inner(execution, command, Some(fault))
    }

    fn execute_inner(
        &self,
        execution: &ConsumptionCommittedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
        fault: Option<ConsumptionCommitFaultV1>,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_static(&self.config.trust_bundle, execution)?;
        let command_bytes = canonical_bytes(command)?;
        let execution_bytes = canonical_bytes(execution)?;
        let id = operation_id(command)?;

        let read_only = open_read_snapshot(&self.config.path)?;
        verify_schema(&read_only)?;
        audit(&read_only, &self.config)?;
        drop(read_only);
        #[cfg(test)]
        snapshot_tests::wait_before_writer();

        let mut connection = open_rw(&self.config.path, false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_schema(&transaction)?;
        audit(&transaction, &self.config)?;
        let (sequence, height, block_id, state, journal_root, fenced) =
            load_metadata(&transaction, &self.config)?;
        if fenced {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        if let Some((stored_execution, stored_command, stored_receipt)) =
            load_operation(&transaction, id)?
        {
            if stored_execution != *execution || stored_command != *command {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::Conflict,
                    "operation ID replay differs from durable bytes",
                ));
            }
            drop(transaction);
            drop(connection);
            return Ok(ConsumptionSettlementOutcomeV1 {
                confirmed: self.fresh_confirm(&stored_receipt)?,
                replay: true,
            });
        }
        validate_execution_cas(execution, height, block_id)?;
        if matches!(fault, Some(ConsumptionCommitFaultV1::NotAppliedAckLost)) {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::CommitUncertain,
                "operation was not applied before acknowledgement loss",
            ));
        }

        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "operation sequence overflow",
            )
        })?;
        let (next_state, settlement_id) = apply_new_store_transition(
            &self.config.trust_bundle,
            &state,
            execution.order_height,
            command,
        )?;
        let receipt = ConsumptionTransitionReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence: next_sequence,
            operation_id: id,
            operation_kind: command.operation_kind(),
            order_height: execution.order_height,
            order_block_id: execution.order_block_id,
            post_state_root: state_root(&next_state)?,
            settlement_id,
        };

        if matches!(fault, Some(ConsumptionCommitFaultV1::ThirdState)) {
            write_metadata(
                &transaction,
                &self.config,
                sequence,
                height,
                block_id,
                &state,
                operation_journal_root(&transaction)?,
                true,
            )?;
            transaction.commit()?;
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "commit resolved to neither exact source nor target",
            ));
        }
        insert_operation(
            &transaction,
            next_sequence,
            id,
            &execution_bytes,
            &command_bytes,
            &receipt,
        )?;
        let target_journal_root = operation_journal_root(&transaction)?;
        advance_committed_block_marker(
            &transaction,
            &self.config,
            execution,
            sequence,
            next_sequence,
            state_root(&state)?,
            receipt.post_state_root,
            journal_root,
            target_journal_root,
        )?;
        write_metadata(
            &transaction,
            &self.config,
            next_sequence,
            execution.order_height,
            execution.order_block_id,
            &next_state,
            target_journal_root,
            false,
        )?;
        #[cfg(test)]
        snapshot_tests::pause_for_process_death("before-commit");
        transaction.commit()?;
        drop(connection);
        #[cfg(test)]
        snapshot_tests::pause_for_process_death("after-commit");
        if matches!(fault, Some(ConsumptionCommitFaultV1::AppliedAckLost)) {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::CommitUncertain,
                "operation was applied before acknowledgement loss",
            ));
        }
        Ok(ConsumptionSettlementOutcomeV1 {
            confirmed: self.fresh_confirm(&receipt)?,
            replay: false,
        })
    }

    pub fn confirm_receipt(
        &self,
        expected: &ConsumptionTransitionReceiptV1,
    ) -> ConsumptionSettlementResultV1<ConfirmedConsumptionTransitionV1> {
        self.fresh_confirm(expected)
    }

    /// Reopen and authenticate the exact durable store head.
    pub fn fresh_readback(
        &self,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        let connection = open_read_snapshot(&self.config.path)?;
        self.readback_from_snapshot(&connection)
    }

    fn readback_from_snapshot(
        &self,
        connection: &Connection,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementFreshReadbackV1> {
        verify_schema(connection)?;
        audit(connection, &self.config)?;
        let (sequence, order_height, order_block_id, state, journal_root, fenced) =
            load_metadata(connection, &self.config)?;
        if fenced {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        Ok(ConsumptionSettlementFreshReadbackV1 {
            context: self.config.trust_bundle.context.clone(),
            store_schema_version: JOURNAL_SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence,
            order_height,
            order_block_id,
            durable_state_root: state_root(&state)?,
            durable_journal_root: journal_root,
            durable_committed_block_root: committed_block_journal_root(connection, &self.config)?,
        })
    }

    fn fresh_confirm(
        &self,
        expected: &ConsumptionTransitionReceiptV1,
    ) -> ConsumptionSettlementResultV1<ConfirmedConsumptionTransitionV1> {
        if expected.store_id != self.config.store_id {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::Unauthorized,
                "transition receipt belongs to another store",
            ));
        }
        reject_sidecars(&self.config.path)?;
        let connection = open_read_snapshot(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        if load_metadata(&connection, &self.config)?.5 {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        let (_, _, actual) =
            load_operation(&connection, expected.operation_id)?.ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::NotFound,
                    "durable transition receipt is absent",
                )
            })?;
        if &actual != expected {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "durable transition receipt differs",
            ));
        }
        Ok(ConfirmedConsumptionTransitionV1 { receipt: actual })
    }

    pub fn state(&self) -> ConsumptionSettlementResultV1<ConsumptionSettlementKernelStateV1> {
        reject_sidecars(&self.config.path)?;
        let connection = open_read_snapshot(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let (_, _, _, state, _, fenced) = load_metadata(&connection, &self.config)?;
        if fenced {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        Ok(state)
    }
}

fn open_rw(path: &Path, allow_create: bool) -> ConsumptionSettlementResultV1<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if allow_create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn open_read_snapshot(path: &Path) -> ConsumptionSettlementResultV1<Connection> {
    // WAL-mode read-only opens can create sidecars. Reject that format before
    // SQLite opens the file; never change its journal mode or recover it here.
    reject_sidecars(path)?;
    let mut header = [0_u8; 20];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|cause| {
            error(
                ConsumptionSettlementErrorCodeV1::StoreFailure,
                cause.to_string(),
            )
        })?;
    if header[18] == 2 || header[19] == 2 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::SchemaMismatch,
            "WAL database format is not supported by read-only store snapshots",
        ));
    }
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    // Keep schema checks, replay audit, fencing and returned facts in one
    // locking snapshot. Dropping the connection releases this read transaction.
    connection.execute_batch("BEGIN DEFERRED")?;
    Ok(connection)
}

fn reject_sidecars(path: &Path) -> ConsumptionSettlementResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar: OsString = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if Path::new(&sidecar).exists() {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::SidecarPresent,
                "SQLite sidecar is present",
            ));
        }
    }
    Ok(())
}

fn require_existing_regular_store(path: &Path) -> ConsumptionSettlementResultV1<()> {
    let metadata = fs::symlink_metadata(path).map_err(|cause| {
        error(
            ConsumptionSettlementErrorCodeV1::StoreFailure,
            format!("existing Consumption/Settlement store is unavailable: {cause}"),
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StoreFailure,
            "existing Consumption/Settlement store path must not be a symlink",
        ));
    }
    if !file_type.is_file() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StoreFailure,
            "existing Consumption/Settlement store path is not a regular file",
        ));
    }
    Ok(())
}

fn verify_schema(connection: &Connection) -> ConsumptionSettlementResultV1<()> {
    let mut statement = connection.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "committed_blocks".to_owned(),
            COMMITTED_BLOCKS_SQL.to_owned(),
        ),
        ("metadata".to_owned(), META_SQL.to_owned()),
        ("operations".to_owned(), OP_SQL.to_owned()),
    ];
    if rows != expected {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::SchemaMismatch,
            "schema v2 differs or automatic migration would be required",
        ));
    }
    let trigger_count: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 0 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::SchemaMismatch,
            "triggers are forbidden",
        ));
    }
    Ok(())
}

fn config_bytes(
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Vec<u8>> {
    canonical_bytes(&(config.store_id, &config.trust_bundle))
}

#[allow(clippy::too_many_arguments)]
fn write_metadata(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    sequence: u64,
    height: u64,
    block_id: Hash32V1,
    state: &ConsumptionSettlementKernelStateV1,
    journal_root: Hash32V1,
    fenced: bool,
) -> ConsumptionSettlementResultV1<()> {
    let config = config_bytes(config)?;
    let state_bytes = canonical_bytes(state)?;
    let root = state_root(state)?;
    let sum = metadata_checksum(
        &config,
        sequence,
        height,
        block_id,
        &state_bytes,
        root,
        journal_root,
        fenced,
    );
    connection.execute(
        "INSERT INTO metadata(singleton,schema_version,config,sequence,height,block_id,state,state_root,journal_root,fenced,checksum) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,config=excluded.config,sequence=excluded.sequence,height=excluded.height,block_id=excluded.block_id,state=excluded.state,state_root=excluded.state_root,journal_root=excluded.journal_root,fenced=excluded.fenced,checksum=excluded.checksum",
        params![
            i64::from(JOURNAL_SCHEMA_VERSION_V1),
            config,
            to_sqlite(sequence, "sequence")?,
            to_sqlite(height, "height")?,
            block_id.0.to_vec(),
            state_bytes,
            root.0.to_vec(),
            journal_root.0.to_vec(),
            i64::from(fenced),
            sum.0.to_vec(),
        ],
    )?;
    Ok(())
}

type Metadata = (
    u64,
    u64,
    Hash32V1,
    ConsumptionSettlementKernelStateV1,
    Hash32V1,
    bool,
);

fn load_metadata(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Metadata> {
    let row = connection.query_row("SELECT schema_version,config,sequence,height,block_id,state,state_root,journal_root,fenced,checksum FROM metadata WHERE singleton=1", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?,row.get::<_,Vec<u8>>(6)?,row.get::<_,Vec<u8>>(7)?,row.get::<_,i64>(8)?,row.get::<_,Vec<u8>>(9)?)))?;
    let (
        schema,
        stored_config,
        sequence,
        height,
        block,
        state_bytes,
        state_root_bytes,
        journal_bytes,
        fenced,
        stored_sum,
    ) = row;
    if schema != i64::from(JOURNAL_SCHEMA_VERSION_V1)
        || stored_config != config_bytes(config)?
        || !matches!(fenced, 0 | 1)
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "metadata trust binding differs",
        ));
    }
    let sequence = from_sqlite(sequence, "sequence")?;
    let height = from_sqlite(height, "height")?;
    let block_id = Hash32V1(array32(block, "block ID")?);
    let state: ConsumptionSettlementKernelStateV1 = strict_decode(&state_bytes)?;
    let stored_state_root = Hash32V1(array32(state_root_bytes, "state root")?);
    let journal_root = Hash32V1(array32(journal_bytes, "journal root")?);
    let fenced = fenced == 1;
    let expected_sum = metadata_checksum(
        &stored_config,
        sequence,
        height,
        block_id,
        &state_bytes,
        stored_state_root,
        journal_root,
        fenced,
    );
    if stored_sum != expected_sum.0 || state_root(&state)? != stored_state_root {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "metadata checksum or state root differs",
        ));
    }
    Ok((sequence, height, block_id, state, journal_root, fenced))
}

#[allow(clippy::too_many_arguments)]
fn metadata_checksum(
    config: &[u8],
    sequence: u64,
    height: u64,
    block_id: Hash32V1,
    state: &[u8],
    state_root: Hash32V1,
    journal_root: Hash32V1,
    fenced: bool,
) -> Hash32V1 {
    checksum(&[
        &JOURNAL_SCHEMA_VERSION_V1.to_le_bytes(),
        config,
        &sequence.to_le_bytes(),
        &height.to_le_bytes(),
        &block_id.0,
        state,
        &state_root.0,
        &journal_root.0,
        &[u8::from(fenced)],
    ])
}

fn insert_operation(
    connection: &Connection,
    sequence: u64,
    id: ConsumptionOperationIdV1,
    execution: &[u8],
    command: &[u8],
    receipt: &ConsumptionTransitionReceiptV1,
) -> ConsumptionSettlementResultV1<()> {
    let receipt_bytes = canonical_bytes(receipt)?;
    let sum = operation_checksum(sequence, id, execution, command, &receipt_bytes);
    connection.execute(
        "INSERT INTO operations(sequence,operation_id,execution,command,receipt,checksum) VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            to_sqlite(sequence, "sequence")?,
            id.0.to_vec(),
            execution,
            command,
            receipt_bytes,
            sum.0.to_vec(),
        ],
    )?;
    Ok(())
}

fn load_operation(
    connection: &Connection,
    id: ConsumptionOperationIdV1,
) -> ConsumptionSettlementResultV1<
    Option<(
        ConsumptionCommittedExecutionContextV1,
        ConsumptionSettlementCommandV1,
        ConsumptionTransitionReceiptV1,
    )>,
> {
    let row = connection
        .query_row(
            "SELECT sequence,operation_id,execution,command,receipt,checksum FROM operations WHERE operation_id=?1",
            [id.0.to_vec()],
            |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?)),
        )
        .optional()?;
    let Some((sequence, id_bytes, execution_bytes, command_bytes, receipt_bytes, sum)) = row else {
        return Ok(None);
    };
    let sequence = from_sqlite(sequence, "sequence")?;
    if id_bytes != id.0
        || sum
            != operation_checksum(
                sequence,
                id,
                &execution_bytes,
                &command_bytes,
                &receipt_bytes,
            )
            .0
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "operation row checksum differs",
        ));
    }
    let execution = strict_decode(&execution_bytes)?;
    let command: ConsumptionSettlementCommandV1 = strict_decode(&command_bytes)?;
    let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt_bytes)?;
    if operation_id(&command)? != id
        || receipt.operation_id != id
        || receipt.sequence != sequence
        || receipt.operation_kind != command.operation_kind()
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "operation row identity differs",
        ));
    }
    Ok(Some((execution, command, receipt)))
}

fn operation_checksum(
    sequence: u64,
    id: ConsumptionOperationIdV1,
    execution: &[u8],
    command: &[u8],
    receipt: &[u8],
) -> Hash32V1 {
    checksum(&[&sequence.to_le_bytes(), &id.0, execution, command, receipt])
}

fn operation_journal_root(connection: &Connection) -> ConsumptionSettlementResultV1<Hash32V1> {
    operation_journal_root_through(connection, u64::MAX)
}

fn operation_journal_root_through(
    connection: &Connection,
    maximum_sequence: u64,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    let maximum_sequence = to_sqlite(maximum_sequence.min(i64::MAX as u64), "maximum sequence")?;
    let mut statement = connection
        .prepare("SELECT receipt FROM operations WHERE sequence<=?1 ORDER BY sequence")?;
    let receipts = statement
        .query_map([maximum_sequence], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    digest_value(
        "trnm.portable.v2.consumption-settlement-journal-root.candidate.v1",
        &receipts,
    )
}

fn marker_predecessor_checksum(
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    let config = config_bytes(config)?;
    Ok(checksum(&[
        b"trnm.portable.v2.consumption-settlement-committed-block-anchor.candidate.v1",
        &config,
    ]))
}

fn committed_block_marker_checksum(
    config: &ConsumptionSettlementStoreConfigV1,
    marker: &CommittedBlockMarkerV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    let config = config_bytes(config)?;
    Ok(checksum(&[
        &JOURNAL_SCHEMA_VERSION_V1.to_le_bytes(),
        &config,
        &marker.marker_sequence.to_le_bytes(),
        &marker.order_height.to_le_bytes(),
        &marker.order_block_id.0,
        &marker.parent_order_height.to_le_bytes(),
        &marker.parent_order_block_id.0,
        &marker.source_operation_sequence.to_le_bytes(),
        &marker.target_operation_sequence.to_le_bytes(),
        &marker.source_state_root.0,
        &marker.target_state_root.0,
        &marker.source_operation_root.0,
        &marker.target_operation_root.0,
        &marker.previous_marker_checksum.0,
    ]))
}

fn insert_committed_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    mut marker: CommittedBlockMarkerV1,
) -> ConsumptionSettlementResultV1<CommittedBlockMarkerV1> {
    marker.checksum = committed_block_marker_checksum(config, &marker)?;
    let changed = connection.execute(
        "INSERT INTO committed_blocks(marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,checksum) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            to_sqlite(marker.marker_sequence, "marker sequence")?,
            to_sqlite(marker.order_height, "marker Order height")?,
            marker.order_block_id.0.to_vec(),
            to_sqlite(marker.parent_order_height, "marker parent Order height")?,
            marker.parent_order_block_id.0.to_vec(),
            to_sqlite(marker.source_operation_sequence, "marker source sequence")?,
            to_sqlite(marker.target_operation_sequence, "marker target sequence")?,
            marker.source_state_root.0.to_vec(),
            marker.target_state_root.0.to_vec(),
            marker.source_operation_root.0.to_vec(),
            marker.target_operation_root.0.to_vec(),
            marker.previous_marker_checksum.0.to_vec(),
            marker.checksum.0.to_vec(),
        ],
    )?;
    if changed != 1 {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StoreFailure,
            "committed-block marker insert changed an unexpected row count",
        ));
    }
    Ok(marker)
}

fn insert_anchor_committed_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    state_root: Hash32V1,
    operation_root: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    insert_committed_block_marker(
        connection,
        config,
        CommittedBlockMarkerV1 {
            marker_sequence: 0,
            order_height: config.trust_bundle.initial_order_height,
            order_block_id: config.trust_bundle.initial_order_block_id,
            parent_order_height: config.trust_bundle.initial_order_height,
            parent_order_block_id: config.trust_bundle.initial_order_block_id,
            source_operation_sequence: 0,
            target_operation_sequence: 0,
            source_state_root: state_root,
            target_state_root: state_root,
            source_operation_root: operation_root,
            target_operation_root: operation_root,
            previous_marker_checksum: marker_predecessor_checksum(config)?,
            checksum: Hash32V1([0; 32]),
        },
    )?;
    Ok(())
}

fn load_committed_block_markers(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Vec<CommittedBlockMarkerV1>> {
    let mut statement = connection.prepare("SELECT marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,checksum FROM committed_blocks")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut markers = Vec::with_capacity(rows.len());
    for row in rows {
        let marker = CommittedBlockMarkerV1 {
            marker_sequence: from_sqlite(row.0, "marker sequence")?,
            order_height: from_sqlite(row.1, "marker Order height")?,
            order_block_id: Hash32V1(array32(row.2, "marker Order block ID")?),
            parent_order_height: from_sqlite(row.3, "marker parent Order height")?,
            parent_order_block_id: Hash32V1(array32(row.4, "marker parent Order block ID")?),
            source_operation_sequence: from_sqlite(row.5, "marker source sequence")?,
            target_operation_sequence: from_sqlite(row.6, "marker target sequence")?,
            source_state_root: Hash32V1(array32(row.7, "marker source state root")?),
            target_state_root: Hash32V1(array32(row.8, "marker target state root")?),
            source_operation_root: Hash32V1(array32(row.9, "marker source operation root")?),
            target_operation_root: Hash32V1(array32(row.10, "marker target operation root")?),
            previous_marker_checksum: Hash32V1(array32(row.11, "previous marker checksum")?),
            checksum: Hash32V1(array32(row.12, "marker checksum")?),
        };
        if marker.checksum != committed_block_marker_checksum(config, &marker)? {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block marker checksum differs",
            ));
        }
        markers.push(marker);
    }
    markers.sort_by_key(|marker| marker.marker_sequence);
    if markers.is_empty() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "committed-block journal is empty",
        ));
    }
    Ok(markers)
}

#[allow(clippy::too_many_arguments)]
fn advance_committed_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    execution: &ConsumptionCommittedExecutionContextV1,
    source_sequence: u64,
    target_sequence: u64,
    source_state_root: Hash32V1,
    target_state_root: Hash32V1,
    source_operation_root: Hash32V1,
    target_operation_root: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    let markers = load_committed_block_markers(connection, config)?;
    let tail = *markers.last().expect("nonempty marker journal was checked");
    if source_sequence != tail.target_operation_sequence
        || source_state_root != tail.target_state_root
        || source_operation_root != tail.target_operation_root
        || target_sequence < source_sequence
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "committed-block marker source differs from durable tail",
        ));
    }
    if (execution.order_height, execution.order_block_id)
        == (tail.order_height, tail.order_block_id)
    {
        if (
            execution.expected_order_height,
            execution.expected_order_block_id,
        ) != (tail.order_height, tail.order_block_id)
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::StaleVersion,
                "same-block marker extension does not expect the exact block",
            ));
        }
        // An empty successor marker already records a block with no commands.
        // Its first operation would need to expect the marker's parent during
        // replay, but a same-block call expects the current block. Reject that
        // inconsistent history inside the transaction, before it can commit.
        // The genesis anchor is different: its parent is itself.
        if tail.source_operation_sequence == tail.target_operation_sequence
            && (tail.parent_order_height, tail.parent_order_block_id)
                != (tail.order_height, tail.order_block_id)
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidContext,
                "cannot append the first command to an already committed empty block",
            ));
        }
        let mut updated = tail;
        updated.target_operation_sequence = target_sequence;
        updated.target_state_root = target_state_root;
        updated.target_operation_root = target_operation_root;
        updated.checksum = committed_block_marker_checksum(config, &updated)?;
        let changed = connection.execute(
            "UPDATE committed_blocks SET target_operation_sequence=?1,target_state_root=?2,target_operation_root=?3,checksum=?4 WHERE marker_sequence=?5 AND checksum=?6",
            params![
                to_sqlite(updated.target_operation_sequence, "marker target sequence")?,
                updated.target_state_root.0.to_vec(),
                updated.target_operation_root.0.to_vec(),
                updated.checksum.0.to_vec(),
                to_sqlite(updated.marker_sequence, "marker sequence")?,
                tail.checksum.0.to_vec(),
            ],
        )?;
        if changed != 1 {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::StaleVersion,
                "committed-block marker changed before same-block extension",
            ));
        }
        return Ok(());
    }
    if (
        execution.expected_order_height,
        execution.expected_order_block_id,
    ) != (tail.order_height, tail.order_block_id)
        || tail.order_height.checked_add(1) != Some(execution.order_height)
        || execution.order_block_id == tail.order_block_id
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::InvalidContext,
            "committed-block marker target is not the direct Order successor",
        ));
    }
    insert_committed_block_marker(
        connection,
        config,
        CommittedBlockMarkerV1 {
            marker_sequence: tail.marker_sequence.checked_add(1).ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                    "committed-block marker sequence overflows",
                )
            })?,
            order_height: execution.order_height,
            order_block_id: execution.order_block_id,
            parent_order_height: tail.order_height,
            parent_order_block_id: tail.order_block_id,
            source_operation_sequence: source_sequence,
            target_operation_sequence: target_sequence,
            source_state_root,
            target_state_root,
            source_operation_root,
            target_operation_root,
            previous_marker_checksum: tail.checksum,
            checksum: Hash32V1([0; 32]),
        },
    )?;
    Ok(())
}

fn audit(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<()> {
    let (sequence, _, _, durable_state, durable_journal, _) = load_metadata(connection, config)?;
    if operation_journal_root(connection)? != durable_journal {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "operation journal root differs",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT sequence,operation_id,execution,command,receipt,checksum FROM operations ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut replay_state = initial_state(&config.trust_bundle);
    let mut replay_sequence = 0_u64;
    for (row_sequence, id_bytes, execution_bytes, command_bytes, receipt_bytes, sum) in rows {
        replay_sequence = replay_sequence.checked_add(1).ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                "audit sequence overflow",
            )
        })?;
        if from_sqlite(row_sequence, "sequence")? != replay_sequence {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "operation journal has a sequence gap",
            ));
        }
        let id = ConsumptionOperationIdV1(array32(id_bytes.clone(), "operation ID")?);
        if sum
            != operation_checksum(
                replay_sequence,
                id,
                &execution_bytes,
                &command_bytes,
                &receipt_bytes,
            )
            .0
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "journal row checksum differs",
            ));
        }
        let execution: ConsumptionCommittedExecutionContextV1 = strict_decode(&execution_bytes)?;
        let command: ConsumptionSettlementCommandV1 = strict_decode(&command_bytes)?;
        let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt_bytes)?;
        validate_execution_static(&config.trust_bundle, &execution).map_err(|cause| {
            error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                format!("journal execution context is invalid: {cause}"),
            )
        })?;
        if operation_id(&command)? != id {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "journal operation ID differs",
            ));
        }
        let (next_state, settlement_id) = apply_transition(
            &config.trust_bundle,
            &replay_state,
            execution.order_height,
            &command,
        )
        .map_err(|cause| {
            error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                format!("journal command fails deterministic replay: {cause}"),
            )
        })?;
        let expected_receipt = ConsumptionTransitionReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            store_id: config.store_id,
            sequence: replay_sequence,
            operation_id: id,
            operation_kind: command.operation_kind(),
            order_height: execution.order_height,
            order_block_id: execution.order_block_id,
            post_state_root: state_root(&next_state)?,
            settlement_id,
        };
        if receipt != expected_receipt {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "journal receipt differs from deterministic replay",
            ));
        }
        replay_state = next_state;
    }
    if (replay_sequence, replay_state) != (sequence, durable_state) {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "metadata state differs from deterministic journal replay",
        ));
    }
    audit_committed_block_journal(connection, config)
}

fn audit_committed_block_journal(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<()> {
    let markers = load_committed_block_markers(connection, config)?;
    let mut operations = BTreeMap::new();
    let mut statement = connection.prepare("SELECT sequence,execution,receipt FROM operations")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (sequence, execution, receipt) in rows {
        let sequence = from_sqlite(sequence, "block-journal operation sequence")?;
        let execution: ConsumptionCommittedExecutionContextV1 = strict_decode(&execution)?;
        let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt)?;
        if receipt.sequence != sequence
            || operations.insert(sequence, (execution, receipt)).is_some()
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block journal operation mapping is duplicate",
            ));
        }
    }

    let genesis_state_root = state_root(&initial_state(&config.trust_bundle))?;
    let genesis_operation_root = operation_journal_root_through(connection, 0)?;
    let mut previous = None;
    for (index, marker) in markers.iter().enumerate() {
        if marker.marker_sequence
            != u64::try_from(index).map_err(|_| {
                error(
                    ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                    "committed-block audit index overflows",
                )
            })?
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block marker sequence has a gap or reorder",
            ));
        }
        match previous {
            None => {
                if marker.order_height != config.trust_bundle.initial_order_height
                    || marker.order_block_id != config.trust_bundle.initial_order_block_id
                    || marker.parent_order_height != marker.order_height
                    || marker.parent_order_block_id != marker.order_block_id
                    || marker.source_operation_sequence != 0
                    || marker.source_state_root != genesis_state_root
                    || marker.source_operation_root != genesis_operation_root
                    || marker.previous_marker_checksum != marker_predecessor_checksum(config)?
                {
                    return Err(error(
                        ConsumptionSettlementErrorCodeV1::TamperDetected,
                        "committed-block anchor marker differs from fresh genesis",
                    ));
                }
            }
            Some(parent) => {
                let parent: CommittedBlockMarkerV1 = parent;
                if parent.marker_sequence.checked_add(1) != Some(marker.marker_sequence)
                    || parent.order_height.checked_add(1) != Some(marker.order_height)
                    || marker.parent_order_height != parent.order_height
                    || marker.parent_order_block_id != parent.order_block_id
                    || marker.order_block_id == parent.order_block_id
                    || marker.source_operation_sequence != parent.target_operation_sequence
                    || marker.source_state_root != parent.target_state_root
                    || marker.source_operation_root != parent.target_operation_root
                    || marker.previous_marker_checksum != parent.checksum
                {
                    return Err(error(
                        ConsumptionSettlementErrorCodeV1::TamperDetected,
                        "committed-block marker is not the exact direct successor",
                    ));
                }
            }
        }
        if marker.target_operation_sequence < marker.source_operation_sequence
            || marker.source_operation_root
                != operation_journal_root_through(connection, marker.source_operation_sequence)?
            || marker.target_operation_root
                != operation_journal_root_through(connection, marker.target_operation_sequence)?
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block marker operation roots or range regress",
            ));
        }
        let mut expected_target_state = marker.source_state_root;
        for sequence in
            marker.source_operation_sequence.saturating_add(1)..=marker.target_operation_sequence
        {
            let (execution, receipt) = operations.get(&sequence).ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::TamperDetected,
                    "committed-block marker operation range has a gap",
                )
            })?;
            let expected_parent = if sequence == marker.source_operation_sequence.saturating_add(1)
            {
                (marker.parent_order_height, marker.parent_order_block_id)
            } else {
                (marker.order_height, marker.order_block_id)
            };
            if (
                execution.expected_order_height,
                execution.expected_order_block_id,
            ) != expected_parent
                || (execution.order_height, execution.order_block_id)
                    != (marker.order_height, marker.order_block_id)
                || (receipt.order_height, receipt.order_block_id)
                    != (marker.order_height, marker.order_block_id)
            {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::TamperDetected,
                    "operation execution context belongs to a different committed-block marker",
                ));
            }
            expected_target_state = receipt.post_state_root;
        }
        if marker.target_state_root != expected_target_state {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block marker target state differs from its operation range",
            ));
        }
        previous = Some(*marker);
    }

    let tail = previous.expect("nonempty marker journal was checked");
    let (sequence, height, block_id, state, journal_root, _) = load_metadata(connection, config)?;
    if (height, block_id) != (tail.order_height, tail.order_block_id)
        || sequence != tail.target_operation_sequence
        || state_root(&state)? != tail.target_state_root
        || journal_root != tail.target_operation_root
        || u64::try_from(operations.len()).ok() != Some(sequence)
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "metadata head differs from committed-block journal tail",
        ));
    }
    Ok(())
}

fn committed_block_journal_root(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    audit_committed_block_journal(connection, config)?;
    load_committed_block_markers(connection, config)?
        .last()
        .map(|marker| marker.checksum)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "committed-block journal root is absent",
            )
        })
}

fn validate_execution_cas(
    execution: &ConsumptionCommittedExecutionContextV1,
    height: u64,
    block_id: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    if execution.expected_order_height != height || execution.expected_order_block_id != block_id {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "order-confirmation expected tip does not match durable tip",
        ));
    }
    Ok(())
}

// Admission-only backend check. Historical audit/replay keeps using the generic
// transition, and exact durable operation retries return before this path.
fn apply_new_store_transition(
    trust: &ConsumptionSettlementFreshGenesisTrustBundleV1,
    state: &ConsumptionSettlementKernelStateV1,
    order_height: u64,
    command: &ConsumptionSettlementCommandV1,
) -> ConsumptionSettlementResultV1<(ConsumptionSettlementKernelStateV1, Option<SettlementIdV1>)> {
    let (next, settlement_id) = apply_transition(trust, state, order_height, command)?;
    if matches!(command, ConsumptionSettlementCommandV1::AdmitRollup { .. }) {
        let rollup = next.rollup.as_ref().ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::NotFound,
                "new rollup is absent after admission",
            )
        })?;
        let earliest_settlement =
            rollup
                .challenge_close_height
                .checked_add(1)
                .ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "rollup settlement successor height overflows",
                    )
                })?;
        to_sqlite(earliest_settlement, "rollup settlement successor height")?;
    }
    Ok((next, settlement_id))
}

// Preview must stay within the same integer domain as the durable backend,
// including empty batches and the final sequence of a multi-command batch.
fn validate_preview_sqlite_bounds(
    candidate_height: u64,
    source_sequence: u64,
    command_count: usize,
) -> ConsumptionSettlementResultV1<()> {
    to_sqlite(candidate_height, "pre-commit candidate height")?;
    let command_count = u64::try_from(command_count).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "pre-commit command count exceeds u64",
        )
    })?;
    let target_sequence = source_sequence.checked_add(command_count).ok_or_else(|| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            "pre-commit target sequence overflows",
        )
    })?;
    to_sqlite(target_sequence, "pre-commit target sequence")?;
    Ok(())
}

fn to_sqlite(value: u64, label: &str) -> ConsumptionSettlementResultV1<i64> {
    i64::try_from(value).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
            format!("{label} exceeds SQLite signed range"),
        )
    })
}

fn from_sqlite(value: i64, label: &str) -> ConsumptionSettlementResultV1<u64> {
    u64::try_from(value).map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            format!("{label} is negative"),
        )
    })
}

fn array32(value: Vec<u8>, label: &str) -> ConsumptionSettlementResultV1<[u8; 32]> {
    value.try_into().map_err(|_| {
        error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            format!("{label} length is invalid"),
        )
    })
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    thread_local! {
        static PROCESS_DEATH_STAGE: std::cell::RefCell<Option<(String, PathBuf)>> = const { std::cell::RefCell::new(None) };
    }

    pub(super) fn pause_for_process_death(stage: &str) {
        let marker = PROCESS_DEATH_STAGE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|(expected, _)| expected == stage) {
                slot.take().map(|(_, marker)| marker)
            } else {
                None
            }
        });
        if let Some(marker) = marker {
            fs::write(marker, stage).expect("signal reached process-death stage");
            // The parent kills this owned child. Bound its lifetime if the parent dies.
            std::thread::sleep(Duration::from_secs(30));
            panic!("parent did not terminate process-death fixture");
        }
    }

    struct OwnedTestChild(std::process::Child);

    type ProcessDeathRequest = (
        Hash32V1,
        ConsumptionSettlementFreshGenesisTrustBundleV1,
        ConsumptionCommittedExecutionContextV1,
        ConsumptionSettlementCommandV1,
    );

    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            // Also runs when readiness checks or assertions panic.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "child fixture explicitly executed by process_death_preserves_fail_closed_and_exact_retry"]
    fn process_death_child_fixture() {
        let path =
            std::env::var_os("TRNM_SETTLEMENT_DEATH_DB").expect("parent-owned database path");
        let marker =
            std::env::var_os("TRNM_SETTLEMENT_DEATH_MARKER").expect("parent-owned stage marker");
        let stage = std::env::var("TRNM_SETTLEMENT_DEATH_STAGE").expect("parent-selected stage");
        assert!(matches!(stage.as_str(), "before-commit" | "after-commit"));
        let path = PathBuf::from(path);
        let (store_id, trust_bundle, execution, command): ProcessDeathRequest =
            strict_decode(&fs::read(path.with_extension("request")).unwrap()).unwrap();
        let config = ConsumptionSettlementStoreConfigV1 {
            path,
            store_id,
            trust_bundle,
        };
        let store = ConsumptionSettlementStoreV1::open_existing(config).unwrap();
        PROCESS_DEATH_STAGE.with(|slot| *slot.borrow_mut() = Some((stage, PathBuf::from(marker))));
        store
            .execute_committed_execution(&execution, &command)
            .unwrap();
        panic!("child unexpectedly returned an acknowledgment");
    }

    #[test]
    fn process_death_preserves_fail_closed_and_exact_retry() {
        for stage in ["before-commit", "after-commit"] {
            let harness = crate::tests::Harness::new();
            let config = harness.config();
            let store = ConsumptionSettlementStoreV1::open(config.clone()).unwrap();
            let before = store.fresh_readback().unwrap();
            let execution = harness.execution(9, before.order_block_id(), 10);
            let command = ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: harness.receipt(None, 10, 100),
            };
            let preview = store
                .preview_before_vote_v1(
                    &before,
                    10,
                    execution.order_block_id,
                    std::slice::from_ref(&command),
                )
                .unwrap();
            let expected_receipt = &preview.candidate_receipts()[0];
            let marker = config.path.with_extension("stage");
            fs::write(
                config.path.with_extension("request"),
                canonical_bytes(&(config.store_id, &config.trust_bundle, &execution, &command))
                    .unwrap(),
            )
            .unwrap();
            let mut child = OwnedTestChild(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "store::snapshot_tests::process_death_child_fixture",
                        "--nocapture",
                    ])
                    .env("TRNM_SETTLEMENT_DEATH_DB", &config.path)
                    .env("TRNM_SETTLEMENT_DEATH_MARKER", &marker)
                    .env("TRNM_SETTLEMENT_DEATH_STAGE", stage)
                    .spawn()
                    .expect("spawn owned process-death fixture"),
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if fs::read(&marker).ok().as_deref() == Some(stage.as_bytes()) {
                    break;
                }
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "child exited before {stage}"
                );
                assert!(
                    std::time::Instant::now() < deadline,
                    "child did not reach {stage}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut journal_path = config.path.as_os_str().to_os_string();
            journal_path.push("-journal");
            let journal_path = PathBuf::from(journal_path);
            let paused_database = fs::read(&config.path).unwrap();
            let paused_journal = if stage == "before-commit" {
                let bytes = fs::read(&journal_path)
                    .expect("real rollback journal after transactional writes");
                assert!(!bytes.is_empty());
                Some(bytes)
            } else {
                reject_sidecars(&config.path).expect("commit removed rollback journal");
                None
            };
            child.0.kill().expect("terminate only owned child");
            assert!(!child.0.wait().unwrap().success());
            assert_eq!(fs::read(&config.path).unwrap(), paused_database);
            if let Some(journal_bytes) = paused_journal {
                assert_eq!(fs::read(&journal_path).unwrap(), journal_bytes);
                let codes = [
                    ConsumptionSettlementStoreV1::open(config.clone())
                        .unwrap_err()
                        .code(),
                    ConsumptionSettlementStoreV1::open_existing(config.clone())
                        .unwrap_err()
                        .code(),
                    store.fresh_readback().unwrap_err().code(),
                    store.state().unwrap_err().code(),
                    store.confirm_receipt(expected_receipt).unwrap_err().code(),
                    store
                        .preview_before_vote_v1(
                            &before,
                            10,
                            execution.order_block_id,
                            std::slice::from_ref(&command),
                        )
                        .unwrap_err()
                        .code(),
                    store
                        .execute_committed_execution(&execution, &command)
                        .unwrap_err()
                        .code(),
                    store
                        .advance_empty_committed_execution_v1(&execution)
                        .unwrap_err()
                        .code(),
                ];
                assert!(
                    codes
                        .iter()
                        .all(|code| *code == ConsumptionSettlementErrorCodeV1::SidecarPresent),
                    "{codes:?}"
                );
                assert_eq!(fs::read(&config.path).unwrap(), paused_database);
                assert_eq!(fs::read(&journal_path).unwrap(), journal_bytes);
                // No writable reopen, journal removal, or recovery attempt occurs.
            } else {
                let cold = ConsumptionSettlementStoreV1::open_existing(config.clone()).unwrap();
                let head = cold.fresh_readback().unwrap();
                let state = cold.state().unwrap();
                assert_eq!(head.sequence(), 1);
                assert_eq!(head.order_block_id(), execution.order_block_id);
                assert_eq!(
                    head.durable_state_root(),
                    preview.candidate_post_state_root()
                );
                let snapshot = open_read_snapshot(&config.path).unwrap();
                let rows: u64 = snapshot
                    .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(rows, 1);
                drop(snapshot);
                let retry = cold
                    .execute_committed_execution(&execution, &command)
                    .unwrap();
                assert!(retry.is_replay());
                assert_eq!(retry.receipt(), expected_receipt);
                assert_eq!(
                    cold.confirm_receipt(expected_receipt).unwrap().receipt(),
                    expected_receipt
                );
                assert_eq!(cold.fresh_readback().unwrap(), head);
                assert_eq!(cold.state().unwrap(), state);
                assert_eq!(fs::read(&config.path).unwrap(), paused_database);
                reject_sidecars(&config.path).unwrap();
            }
            eprintln!("process-death stage {stage}: supported contract verified");
        }
    }

    thread_local! {
        static WRITER_RENDEZVOUS: std::cell::RefCell<Option<(
            std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>
        )>> = const { std::cell::RefCell::new(None) };
    }

    pub(super) fn wait_before_writer() {
        if let Some((ready, release)) = WRITER_RENDEZVOUS.with(|slot| slot.borrow_mut().take()) {
            ready.send(()).expect("notify writer preflight complete");
            release
                .recv_timeout(Duration::from_secs(10))
                .expect("release writer after both preflights");
        }
    }

    #[test]
    fn concurrent_writers_serialize_exact_retry_and_stale_parent() {
        for same_operation in [true, false] {
            let harness = crate::tests::Harness::new();
            let config = harness.config();
            let store = ConsumptionSettlementStoreV1::open(config.clone()).unwrap();
            let before = store.fresh_readback().unwrap();
            let first_execution =
                harness.execution(before.order_height(), before.order_block_id(), 10);
            let mut second_execution = first_execution.clone();
            if !same_operation {
                second_execution.order_block_id = Hash32V1([61; 32]);
            }
            let first_command = ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: harness.receipt(None, 10, 100),
            };
            let second_command = if same_operation {
                first_command.clone()
            } else {
                ConsumptionSettlementCommandV1::AdmitReceipt {
                    receipt: harness.receipt(None, 10, 101),
                }
            };
            let executions = [first_execution, second_execution];
            let commands = [first_command, second_command];
            let previews: Vec<_> = (0..2)
                .map(|index| {
                    store
                        .preview_before_vote_v1(
                            &before,
                            10,
                            executions[index].order_block_id,
                            std::slice::from_ref(&commands[index]),
                        )
                        .unwrap()
                })
                .collect();
            let handles = [
                ConsumptionSettlementStoreV1::open_existing(config.clone()).unwrap(),
                ConsumptionSettlementStoreV1::open_existing(config.clone()).unwrap(),
            ];
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let outcomes = std::thread::scope(|scope| {
                let mut workers = Vec::new();
                let mut releases = Vec::new();
                for (index, handle) in handles.into_iter().enumerate() {
                    let (release_tx, release_rx) = std::sync::mpsc::channel();
                    releases.push(release_tx);
                    let ready = ready_tx.clone();
                    let execution = &executions[index];
                    let command = &commands[index];
                    workers.push(scope.spawn(move || {
                        WRITER_RENDEZVOUS
                            .with(|slot| *slot.borrow_mut() = Some((ready, release_rx)));
                        handle.execute_committed_execution(execution, command)
                    }));
                }
                // Both preflight snapshots are dropped before either writer starts.
                for _ in 0..2 {
                    ready_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("both writer preflights");
                }
                for release in releases {
                    release.send(()).unwrap();
                }
                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .collect::<Vec<_>>()
            });
            let initial_statuses: Vec<_> = outcomes
                .iter()
                .map(|outcome| {
                    outcome
                        .as_ref()
                        .map(|outcome| outcome.is_replay())
                        .map_err(|error| error.code())
                })
                .collect();
            eprintln!(
                "same_operation={same_operation}, initial replay statuses={initial_statuses:?}"
            );
            if same_operation {
                assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
                assert_eq!(
                    outcomes
                        .iter()
                        .filter(|outcome| outcome.as_ref().unwrap().is_replay())
                        .count(),
                    1
                );
                assert_eq!(
                    outcomes[0].as_ref().unwrap().receipt(),
                    outcomes[1].as_ref().unwrap().receipt()
                );
            } else {
                assert_eq!(
                    outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
                    1,
                    "{outcomes:?}"
                );
                assert_eq!(
                    outcomes
                        .iter()
                        .filter(|outcome| outcome
                            .as_ref()
                            .is_err_and(|error| error.code()
                                == ConsumptionSettlementErrorCodeV1::StaleVersion))
                        .count(),
                    1,
                    "{outcomes:?}"
                );
            }
            let head = store.fresh_readback().unwrap();
            let winner = executions
                .iter()
                .position(|execution| execution.order_block_id == head.order_block_id())
                .unwrap();
            if !same_operation {
                assert!(!outcomes[winner].as_ref().unwrap().is_replay());
            }
            let snapshot = open_read_snapshot(&config.path).unwrap();
            let (_, _, receipt) =
                load_operation(&snapshot, operation_id(&commands[winner]).unwrap())
                    .unwrap()
                    .unwrap();
            for outcome in outcomes.iter().filter_map(|outcome| outcome.as_ref().ok()) {
                assert_eq!(outcome.receipt(), &receipt);
            }
            assert_eq!(
                receipt.post_state_root,
                previews[winner].candidate_post_state_root()
            );
            assert_eq!(head.sequence(), 1);
            assert_eq!(head.order_block_id(), executions[winner].order_block_id);
            assert_eq!(head.durable_state_root(), receipt.post_state_root);
            let state = store.state().unwrap();
            let rows: u64 = snapshot
                .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 1);
            drop(snapshot);
            let bytes = fs::read(&config.path).unwrap();
            drop(store);
            let cold = ConsumptionSettlementStoreV1::open_existing(config.clone()).unwrap();
            assert_eq!(cold.fresh_readback().unwrap(), head);
            assert_eq!(cold.state().unwrap(), state);
            for index in 0..2 {
                let retry = cold.execute_committed_execution(&executions[index], &commands[index]);
                if same_operation || index == winner {
                    let retry = retry.unwrap();
                    assert!(retry.is_replay());
                    assert_eq!(retry.receipt(), &receipt);
                } else {
                    assert_eq!(
                        retry.unwrap_err().code(),
                        ConsumptionSettlementErrorCodeV1::StaleVersion
                    );
                }
            }
            assert_eq!(cold.fresh_readback().unwrap(), head);
            assert_eq!(cold.state().unwrap(), state);
            assert_eq!(fs::read(&config.path).unwrap(), bytes);
        }
    }

    #[test]
    fn preview_rejects_historical_block_id_reuse_without_mutation() {
        for (with_command, nonempty_history) in [(false, false), (true, false), (false, true)] {
            let harness = crate::tests::Harness::new();
            let config = harness.config();
            let store = ConsumptionSettlementStoreV1::open(config.clone()).unwrap();
            let anchor = store.fresh_readback().unwrap();
            let first = harness.execution(anchor.order_height(), anchor.order_block_id(), 10);
            let first_head = if nonempty_history {
                store
                    .execute_committed_execution(
                        &first,
                        &ConsumptionSettlementCommandV1::AdmitReceipt {
                            receipt: harness.receipt(None, 10, 100),
                        },
                    )
                    .unwrap();
                store.fresh_readback().unwrap()
            } else {
                store.advance_empty_committed_execution_v1(&first).unwrap()
            };
            let second =
                harness.execution(first_head.order_height(), first_head.order_block_id(), 11);
            let before = store.advance_empty_committed_execution_v1(&second).unwrap();
            let state = store.state().unwrap();
            let bytes = fs::read(&config.path).unwrap();
            let commands = if with_command {
                vec![ConsumptionSettlementCommandV1::AdmitReceipt {
                    receipt: harness.receipt(None, 12, 100),
                }]
            } else {
                Vec::new()
            };
            for reused_id in [anchor.order_block_id(), first_head.order_block_id()] {
                let preview = store.preview_before_vote_v1(&before, 12, reused_id, &commands);
                let mut execution = harness.execution(11, before.order_block_id(), 12);
                execution.order_block_id = reused_id;
                if with_command {
                    assert!(store
                        .execute_committed_execution(&execution, &commands[0])
                        .is_err());
                } else {
                    assert!(store
                        .advance_empty_committed_execution_v1(&execution)
                        .is_err());
                }
                assert_eq!(store.fresh_readback().unwrap(), before);
                assert_eq!(store.state().unwrap(), state);
                assert_eq!(fs::read(&config.path).unwrap(), bytes);
                let reopened = ConsumptionSettlementStoreV1::open_existing(config.clone()).unwrap();
                assert_eq!(reopened.fresh_readback().unwrap(), before);
                assert_eq!(reopened.state().unwrap(), state);
                assert_eq!(
                    preview
                        .expect_err("preview cannot propose an already recorded block ID")
                        .code(),
                    ConsumptionSettlementErrorCodeV1::InvalidContext
                );
                assert_eq!(
                    reopened
                        .preview_before_vote_v1(&before, 12, reused_id, &commands)
                        .unwrap_err()
                        .code(),
                    ConsumptionSettlementErrorCodeV1::InvalidContext
                );
                assert_eq!(fs::read(&config.path).unwrap(), bytes);
            }
            let valid = harness.execution(11, before.order_block_id(), 12);
            let preview = store
                .preview_before_vote_v1(&before, 12, valid.order_block_id, &commands)
                .unwrap();
            if with_command {
                let committed = store
                    .execute_committed_execution(&valid, &commands[0])
                    .unwrap();
                assert_eq!(
                    committed.receipt().post_state_root,
                    preview.candidate_post_state_root()
                );
            } else {
                let committed = store.advance_empty_committed_execution_v1(&valid).unwrap();
                assert_eq!(
                    committed.durable_state_root(),
                    preview.candidate_post_state_root()
                );
            }
            ConsumptionSettlementStoreV1::open_existing(config).unwrap();
        }
    }

    #[test]
    fn invalid_fresh_height_preserves_missing_path_and_corrected_retry() {
        let harness = crate::tests::Harness::new();
        let mut config = harness.config();
        config.path = config
            .path
            .parent()
            .unwrap()
            .join("missing/nested/store.sqlite");
        let missing_parent = config.path.parent().unwrap().to_path_buf();
        config.trust_bundle.initial_order_height = i64::MAX as u64 + 1;
        assert_eq!(
            ConsumptionSettlementStoreV1::open(config.clone())
                .expect_err("unrepresentable initial height")
                .code(),
            ConsumptionSettlementErrorCodeV1::ArithmeticOverflow
        );
        let path_created = config.path.exists();
        let parent_created = missing_parent.exists();
        config.trust_bundle.initial_order_height = i64::MAX as u64;
        let corrected = ConsumptionSettlementStoreV1::open(config.clone());
        assert!(
            !path_created && !parent_created && corrected.is_ok(),
            "invalid initialization created file={path_created}, parent={parent_created}; corrected retry={corrected:?}"
        );
        let store = corrected.expect("corrected retry");
        assert_eq!(
            store.fresh_readback().unwrap().order_height(),
            i64::MAX as u64
        );
        drop(store);
        ConsumptionSettlementStoreV1::open_existing(config).expect("cold reopen at maximum height");
    }

    #[test]
    fn maximum_fresh_height_is_representable() {
        let harness = crate::tests::Harness::new();
        let mut config = harness.config();
        config.trust_bundle.initial_order_height = i64::MAX as u64;
        let store =
            ConsumptionSettlementStoreV1::open(config.clone()).expect("maximum initial height");
        assert_eq!(
            store.fresh_readback().unwrap().order_height(),
            i64::MAX as u64
        );
        drop(store);
        ConsumptionSettlementStoreV1::open_existing(config).expect("cold reopen maximum height");
    }

    #[test]
    fn legacy_unfinishable_rollup_journal_reopens_and_replays_without_repair() {
        for close_height in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let mut harness = crate::tests::Harness::new();
            harness
                .trust
                .settlement_policy
                .minimum_rollup_challenge_blocks = close_height - 11;
            let config = harness.config();
            let store = ConsumptionSettlementStoreV1::open(config.clone()).expect("fresh fixture");
            let first_execution =
                harness.execution(9, config.trust_bundle.initial_order_block_id, 10);
            store
                .execute_committed_execution(
                    &first_execution,
                    &ConsumptionSettlementCommandV1::AdmitReceipt {
                        receipt: harness.receipt(None, 10, 100),
                    },
                )
                .expect("ordinary receipt");
            let source = store.state().expect("source state");
            let before = store.fresh_readback().expect("source head");
            let execution = harness.execution(10, first_execution.order_block_id, 11);
            let command = ConsumptionSettlementCommandV1::AdmitRollup {
                rollup: harness.rollup(&source, 11),
                receipts: source
                    .receipts
                    .iter()
                    .map(|item| item.receipt.clone())
                    .collect(),
            };
            assert_eq!(
                store
                    .execute_committed_execution(&execution, &command)
                    .expect_err("new unfinishable rollup is rejected")
                    .code(),
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow
            );
            assert_eq!(
                store.fresh_readback().expect("rejection preserves head"),
                before
            );
            drop(store);

            // Reproduce the preceding implementation's durable bytes, using its
            // generic transition and unchanged canonical/checksum/journal writers.
            // This fixture path exists only in cfg(test), never in admission.
            let (legacy_state, settlement_id) =
                apply_transition(&config.trust_bundle, &source, 11, &command)
                    .expect("legacy generic transition");
            assert_eq!(
                legacy_state
                    .rollup
                    .as_ref()
                    .expect("legacy rollup")
                    .challenge_close_height,
                close_height
            );
            let id = operation_id(&command).expect("legacy operation ID");
            let receipt = ConsumptionTransitionReceiptV1 {
                schema_version: SCHEMA_VERSION_V1,
                store_id: config.store_id,
                sequence: before.sequence() + 1,
                operation_id: id,
                operation_kind: command.operation_kind(),
                order_height: execution.order_height,
                order_block_id: execution.order_block_id,
                post_state_root: state_root(&legacy_state).expect("legacy state root"),
                settlement_id,
            };
            let mut connection = open_rw(&config.path, false).expect("fixture writer");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("fixture transaction");
            insert_operation(
                &transaction,
                receipt.sequence,
                id,
                &canonical_bytes(&execution).expect("execution bytes"),
                &canonical_bytes(&command).expect("command bytes"),
                &receipt,
            )
            .expect("legacy journal row");
            let target_journal = operation_journal_root(&transaction).expect("legacy journal root");
            advance_committed_block_marker(
                &transaction,
                &config,
                &execution,
                before.sequence(),
                receipt.sequence,
                before.durable_state_root(),
                receipt.post_state_root,
                before.durable_journal_root(),
                target_journal,
            )
            .expect("legacy block marker");
            write_metadata(
                &transaction,
                &config,
                receipt.sequence,
                execution.order_height,
                execution.order_block_id,
                &legacy_state,
                target_journal,
                false,
            )
            .expect("legacy metadata");
            transaction.commit().expect("persist legacy fixture");
            drop(connection);
            let original_bytes = fs::read(&config.path).expect("persisted legacy bytes");

            let reopened = ConsumptionSettlementStoreV1::open_existing(config.clone())
                .expect("legacy journal passes cold schema and replay audit");
            let legacy_head = reopened.fresh_readback().expect("legacy head");
            assert_eq!(legacy_head.sequence(), receipt.sequence);
            assert_eq!(legacy_head.durable_state_root(), receipt.post_state_root);
            assert_eq!(legacy_head.durable_journal_root(), target_journal);
            assert_eq!(reopened.state().expect("legacy state"), legacy_state);
            let replay = reopened
                .execute_committed_execution(&execution, &command)
                .expect("exact historical retry bypasses new-admission guard");
            assert!(replay.is_replay());
            assert_eq!(replay.receipt(), &receipt);
            assert_eq!(
                reopened.fresh_readback().expect("replay preserves head"),
                legacy_head
            );
            assert_eq!(
                reopened.state().expect("replay preserves state"),
                legacy_state
            );
            // Readability is not repair: maturity still cannot fit this backend.
            assert!(
                legacy_state.rollup.as_ref().unwrap().challenge_close_height >= i64::MAX as u64
            );
            assert!(legacy_state.settlement.is_none());
            drop(reopened);
            assert_eq!(
                fs::read(&config.path).expect("unchanged legacy bytes"),
                original_bytes
            );
            reject_sidecars(&config.path).expect("no leftover sidecars");
            ConsumptionSettlementStoreV1::open_existing(config).expect("repeat cold reopen");
        }
    }

    #[test]
    fn preview_sqlite_sequence_bounds_cover_empty_and_multi_command_batches() {
        let maximum = i64::MAX as u64;
        for (source, count) in [(maximum, 0), (maximum - 1, 1), (maximum - 2, 2)] {
            validate_preview_sqlite_bounds(maximum, source, count)
                .expect("last representable target sequence");
        }
        for (source, count) in [(maximum, 1), (maximum - 1, 2), (u64::MAX, 1)] {
            assert_eq!(
                validate_preview_sqlite_bounds(maximum, source, count)
                    .expect_err("unrepresentable target sequence")
                    .code(),
                ConsumptionSettlementErrorCodeV1::ArithmeticOverflow
            );
        }
    }

    #[test]
    fn wal_header_is_rejected_without_creating_sidecars() {
        let harness = crate::tests::Harness::new();
        let config = harness.config();
        drop(ConsumptionSettlementStoreV1::open(config.clone()).expect("create store"));
        let connection = open_rw(&config.path, false).expect("fixture writer");
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("create WAL-mode fixture");
        assert_eq!(mode, "wal");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint fixture");
        drop(connection);
        reject_sidecars(&config.path).expect("closed WAL fixture has no sidecars");
        let before = fs::read(&config.path).expect("fixture bytes");
        assert_eq!((before[18], before[19]), (2, 2));
        assert_eq!(
            ConsumptionSettlementStoreV1::open_existing(config.clone())
                .expect_err("WAL format unsupported")
                .code(),
            ConsumptionSettlementErrorCodeV1::SchemaMismatch
        );
        assert_eq!(
            ConsumptionSettlementStoreV1::open(config.clone())
                .expect_err("ordinary reopen also rejects WAL")
                .code(),
            ConsumptionSettlementErrorCodeV1::SchemaMismatch
        );
        assert_eq!(fs::read(&config.path).expect("unchanged fixture"), before);
        reject_sidecars(&config.path).expect("rejected reads did not create sidecars");
    }

    #[test]
    fn read_snapshot_blocks_fence_commit_until_release() {
        let harness = crate::tests::Harness::new();
        let config = harness.config();
        let store = ConsumptionSettlementStoreV1::open(config.clone()).expect("create store");
        let reader = open_read_snapshot(&config.path).expect("read snapshot");
        verify_schema(&reader).expect("snapshot schema");
        audit(&reader, &config).expect("snapshot audit");
        let (sequence, height, block, state, journal, fenced) =
            load_metadata(&reader, &config).expect("snapshot metadata");
        assert!(!fenced);

        let writer = open_rw(&config.path, false).expect("second connection");
        writer
            .busy_timeout(Duration::ZERO)
            .expect("nonblocking commit");
        writer
            .execute_batch("BEGIN IMMEDIATE")
            .expect("writer transaction");
        write_metadata(
            &writer, &config, sequence, height, block, &state, journal, true,
        )
        .expect("stage valid permanent fence");
        let error = writer
            .execute_batch("COMMIT")
            .expect_err("reader must block commit");
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        audit(&reader, &config).expect("old snapshot remains coherent");
        assert_eq!(
            load_metadata(&reader, &config).expect("same snapshot"),
            (sequence, height, block, state, journal, false)
        );
        drop(reader);
        writer
            .execute_batch("COMMIT")
            .expect("commit after reader release");
        drop(writer);
        reject_sidecars(&config.path).expect("no sidecars after commit");
        assert_eq!(
            store
                .fresh_readback()
                .expect_err("fresh read sees fence")
                .code(),
            ConsumptionSettlementErrorCodeV1::ThirdStateFenced
        );
        assert_eq!(
            ConsumptionSettlementStoreV1::open_existing(config)
                .expect_err("cold reopen sees fence")
                .code(),
            ConsumptionSettlementErrorCodeV1::ThirdStateFenced
        );
    }
}
