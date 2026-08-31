use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
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
const FINALIZED_BLOCKS_SQL: &str = "CREATE TABLE finalized_blocks(marker_sequence INTEGER PRIMARY KEY,order_height INTEGER NOT NULL,order_block_id BLOB NOT NULL UNIQUE CHECK(length(order_block_id)=32),parent_order_height INTEGER NOT NULL,parent_order_block_id BLOB NOT NULL CHECK(length(parent_order_block_id)=32),source_operation_sequence INTEGER NOT NULL,target_operation_sequence INTEGER NOT NULL,source_state_root BLOB NOT NULL CHECK(length(source_state_root)=32),target_state_root BLOB NOT NULL CHECK(length(target_state_root)=32),source_operation_root BLOB NOT NULL CHECK(length(source_operation_root)=32),target_operation_root BLOB NOT NULL CHECK(length(target_operation_root)=32),previous_marker_checksum BLOB NOT NULL CHECK(length(previous_marker_checksum)=32),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";

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
    durable_finalized_block_root: Hash32V1,
}

#[derive(Clone, Copy, Debug)]
struct FinalizedBlockMarkerV1 {
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
/// normative application/JMT root and carries no finality claim.
#[derive(Debug)]
pub struct ConsumptionSettlementPreVotePreviewV1 {
    source_sequence: u64,
    source_state_root: Hash32V1,
    source_journal_root: Hash32V1,
    candidate_post_state_root: Hash32V1,
    candidate_receipts: Vec<ConsumptionTransitionReceiptV1>,
}

impl ConsumptionSettlementPreVotePreviewV1 {
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

    pub const fn durable_finalized_block_root(&self) -> Hash32V1 {
        self.durable_finalized_block_root
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
            let connection = open_ro(&config.path)?;
            verify_schema(&connection)?;
            audit(&connection, &config)?;
            if load_metadata(&connection, &config)?.5 {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                    "store is permanently fenced",
                ));
            }
        } else {
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
            transaction.execute_batch(FINALIZED_BLOCKS_SQL)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(OP_SQL)?;
            let state = initial_state(&config.trust_bundle);
            let journal_root = operation_journal_root(&transaction)?;
            insert_anchor_finalized_block_marker(
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
            let connection = open_ro(&config.path)?;
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
        let connection = open_ro(&config.path)?;
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

    pub fn execute_order_finalized(
        &self,
        execution: &ConsumptionOrderFinalizedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        self.execute_inner(execution, command, None)
    }

    /// Advance one finalized Order block with no settlement commands.
    ///
    /// The direct-successor Order tip is the only changed fact.  State,
    /// sequence and journal roots remain byte-exact, and a fresh observation
    /// of the target resolves an exact retry after acknowledgement loss.
    pub fn advance_empty_order_finalized_v1(
        &self,
        execution: &ConsumptionOrderFinalizedExecutionContextV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_static(&self.config.trust_bundle, execution)?;
        if execution.expected_order_height.checked_add(1) != Some(execution.order_height) {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::InvalidContext,
                "empty finalized batch is not the direct Order successor",
            ));
        }

        let before = self.fresh_readback()?;
        if before.order_height == execution.order_height
            && before.order_block_id == execution.order_block_id
        {
            return Ok(before);
        }
        if before.order_height != execution.expected_order_height
            || before.order_block_id != execution.expected_order_block_id
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::StaleVersion,
                "empty finalized batch parent differs from durable head",
            ));
        }

        let mut connection = open_rw(&self.config.path, false)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        advance_finalized_block_marker(
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
            || after.durable_finalized_block_root == before.durable_finalized_block_root
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "empty finalized batch readback differs from its exact target",
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
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementPreVotePreviewV1> {
        let before = self.fresh_readback()?;
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
                "pre-vote candidate does not extend the exact fresh parent",
            ));
        }
        let mut state = self.state()?;
        let mut operation_ids = BTreeSet::new();
        let mut receipts = Vec::with_capacity(commands.len());
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        for (offset, command) in commands.iter().enumerate() {
            let id = operation_id(command)?;
            if !operation_ids.insert(id) || load_operation(&connection, id)?.is_some() {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::Conflict,
                    "pre-vote batch repeats a Consumption/Settlement operation",
                ));
            }
            let (next_state, settlement_id) =
                apply_transition(&self.config.trust_bundle, &state, candidate_height, command)?;
            state = next_state;
            let offset = u64::try_from(offset).map_err(|_| {
                error(
                    ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                    "pre-vote operation index exceeds u64",
                )
            })?;
            let next = before
                .sequence
                .checked_add(offset)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    error(
                        ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                        "pre-vote sequence overflows",
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
        Ok(ConsumptionSettlementPreVotePreviewV1 {
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
        execution: &ConsumptionOrderFinalizedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
        fault: ConsumptionCommitFaultV1,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        self.execute_inner(execution, command, Some(fault))
    }

    fn execute_inner(
        &self,
        execution: &ConsumptionOrderFinalizedExecutionContextV1,
        command: &ConsumptionSettlementCommandV1,
        fault: Option<ConsumptionCommitFaultV1>,
    ) -> ConsumptionSettlementResultV1<ConsumptionSettlementOutcomeV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_static(&self.config.trust_bundle, execution)?;
        let command_bytes = canonical_bytes(command)?;
        let execution_bytes = canonical_bytes(execution)?;
        let id = operation_id(command)?;

        let read_only = open_ro(&self.config.path)?;
        verify_schema(&read_only)?;
        audit(&read_only, &self.config)?;
        drop(read_only);

        let mut connection = open_rw(&self.config.path, false)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let (sequence, height, block_id, state, journal_root, fenced) =
            load_metadata(&connection, &self.config)?;
        if fenced {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        if let Some((stored_execution, stored_command, stored_receipt)) =
            load_operation(&connection, id)?
        {
            if stored_execution != *execution || stored_command != *command {
                return Err(error(
                    ConsumptionSettlementErrorCodeV1::Conflict,
                    "operation ID replay differs from durable bytes",
                ));
            }
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
        let (next_state, settlement_id) = apply_transition(
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

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (tx_sequence, tx_height, tx_block, tx_state, tx_journal_root, tx_fenced) =
            load_metadata(&transaction, &self.config)?;
        if (
            tx_sequence,
            tx_height,
            tx_block,
            &tx_state,
            tx_journal_root,
            tx_fenced,
        ) != (sequence, height, block_id, &state, journal_root, false)
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::StaleVersion,
                "store changed before atomic transition",
            ));
        }
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
        advance_finalized_block_marker(
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
        transaction.commit()?;
        drop(connection);
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
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let (sequence, order_height, order_block_id, state, journal_root, fenced) =
            load_metadata(&connection, &self.config)?;
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
            durable_finalized_block_root: finalized_block_journal_root(&connection, &self.config)?,
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
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
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
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        Ok(load_metadata(&connection, &self.config)?.3)
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

fn open_ro(path: &Path) -> ConsumptionSettlementResultV1<Connection> {
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
            "finalized_blocks".to_owned(),
            FINALIZED_BLOCKS_SQL.to_owned(),
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
        ConsumptionOrderFinalizedExecutionContextV1,
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
        "trnm.poco-ai.consumption-settlement-journal-root.candidate.v1",
        &receipts,
    )
}

fn marker_predecessor_checksum(
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    let config = config_bytes(config)?;
    Ok(checksum(&[
        b"trnm.poco-ai.consumption-settlement-finalized-block-anchor.candidate.v1",
        &config,
    ]))
}

fn finalized_block_marker_checksum(
    config: &ConsumptionSettlementStoreConfigV1,
    marker: &FinalizedBlockMarkerV1,
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

fn insert_finalized_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    mut marker: FinalizedBlockMarkerV1,
) -> ConsumptionSettlementResultV1<FinalizedBlockMarkerV1> {
    marker.checksum = finalized_block_marker_checksum(config, &marker)?;
    let changed = connection.execute(
        "INSERT INTO finalized_blocks(marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,checksum) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
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
            "finalized-block marker insert changed an unexpected row count",
        ));
    }
    Ok(marker)
}

fn insert_anchor_finalized_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    state_root: Hash32V1,
    operation_root: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    insert_finalized_block_marker(
        connection,
        config,
        FinalizedBlockMarkerV1 {
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

fn load_finalized_block_markers(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Vec<FinalizedBlockMarkerV1>> {
    let mut statement = connection.prepare("SELECT marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,checksum FROM finalized_blocks")?;
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
        let marker = FinalizedBlockMarkerV1 {
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
        if marker.checksum != finalized_block_marker_checksum(config, &marker)? {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "finalized-block marker checksum differs",
            ));
        }
        markers.push(marker);
    }
    markers.sort_by_key(|marker| marker.marker_sequence);
    if markers.is_empty() {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::TamperDetected,
            "finalized-block journal is empty",
        ));
    }
    Ok(markers)
}

#[allow(clippy::too_many_arguments)]
fn advance_finalized_block_marker(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
    execution: &ConsumptionOrderFinalizedExecutionContextV1,
    source_sequence: u64,
    target_sequence: u64,
    source_state_root: Hash32V1,
    target_state_root: Hash32V1,
    source_operation_root: Hash32V1,
    target_operation_root: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
    let tail = *markers.last().expect("nonempty marker journal was checked");
    if source_sequence != tail.target_operation_sequence
        || source_state_root != tail.target_state_root
        || source_operation_root != tail.target_operation_root
        || target_sequence < source_sequence
    {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "finalized-block marker source differs from durable tail",
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
        let mut updated = tail;
        updated.target_operation_sequence = target_sequence;
        updated.target_state_root = target_state_root;
        updated.target_operation_root = target_operation_root;
        updated.checksum = finalized_block_marker_checksum(config, &updated)?;
        let changed = connection.execute(
            "UPDATE finalized_blocks SET target_operation_sequence=?1,target_state_root=?2,target_operation_root=?3,checksum=?4 WHERE marker_sequence=?5 AND checksum=?6",
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
                "finalized-block marker changed before same-block extension",
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
            "finalized-block marker target is not the direct Order successor",
        ));
    }
    insert_finalized_block_marker(
        connection,
        config,
        FinalizedBlockMarkerV1 {
            marker_sequence: tail.marker_sequence.checked_add(1).ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::ArithmeticOverflow,
                    "finalized-block marker sequence overflows",
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
        let execution: ConsumptionOrderFinalizedExecutionContextV1 =
            strict_decode(&execution_bytes)?;
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
    audit_finalized_block_journal(connection, config)
}

fn audit_finalized_block_journal(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
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
        let execution: ConsumptionOrderFinalizedExecutionContextV1 = strict_decode(&execution)?;
        let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt)?;
        if receipt.sequence != sequence
            || operations.insert(sequence, (execution, receipt)).is_some()
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "finalized-block journal operation mapping is duplicate",
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
                    "finalized-block audit index overflows",
                )
            })?
        {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "finalized-block marker sequence has a gap or reorder",
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
                        "finalized-block anchor marker differs from fresh genesis",
                    ));
                }
            }
            Some(parent) => {
                let parent: FinalizedBlockMarkerV1 = parent;
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
                        "finalized-block marker is not the exact direct successor",
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
                "finalized-block marker operation roots or range regress",
            ));
        }
        let mut expected_target_state = marker.source_state_root;
        for sequence in
            marker.source_operation_sequence.saturating_add(1)..=marker.target_operation_sequence
        {
            let (execution, receipt) = operations.get(&sequence).ok_or_else(|| {
                error(
                    ConsumptionSettlementErrorCodeV1::TamperDetected,
                    "finalized-block marker operation range has a gap",
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
                    "operation execution context belongs to a different finalized-block marker",
                ));
            }
            expected_target_state = receipt.post_state_root;
        }
        if marker.target_state_root != expected_target_state {
            return Err(error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "finalized-block marker target state differs from its operation range",
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
            "metadata head differs from finalized-block journal tail",
        ));
    }
    Ok(())
}

fn finalized_block_journal_root(
    connection: &Connection,
    config: &ConsumptionSettlementStoreConfigV1,
) -> ConsumptionSettlementResultV1<Hash32V1> {
    audit_finalized_block_journal(connection, config)?;
    load_finalized_block_markers(connection, config)?
        .last()
        .map(|marker| marker.checksum)
        .ok_or_else(|| {
            error(
                ConsumptionSettlementErrorCodeV1::TamperDetected,
                "finalized-block journal root is absent",
            )
        })
}

fn validate_execution_cas(
    execution: &ConsumptionOrderFinalizedExecutionContextV1,
    height: u64,
    block_id: Hash32V1,
) -> ConsumptionSettlementResultV1<()> {
    if execution.expected_order_height != height || execution.expected_order_block_id != block_id {
        return Err(error(
            ConsumptionSettlementErrorCodeV1::StaleVersion,
            "order-finality expected tip does not match durable tip",
        ));
    }
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
