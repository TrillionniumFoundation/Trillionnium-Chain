//! SQLite-backed candidate kernel for a bounded Agent/Market lifecycle.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    error::{error, AgentMarketErrorCodeV1, AgentMarketResultV1},
    *,
};

const STORE_SCHEMA_VERSION_V1: u16 = 3;

const META_SQL: &str = "CREATE TABLE agent_market_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), schema_version INTEGER NOT NULL, store_id BLOB NOT NULL CHECK (length(store_id) = 32), config_hash BLOB NOT NULL CHECK (length(config_hash) = 32), sequence BLOB NOT NULL CHECK (length(sequence) = 8), order_height BLOB NOT NULL CHECK (length(order_height) = 8), order_block_id BLOB NOT NULL CHECK (length(order_block_id) = 32), durable_state_root BLOB NOT NULL CHECK (length(durable_state_root) = 32), durable_journal_root BLOB NOT NULL CHECK (length(durable_journal_root) = 32), fenced INTEGER NOT NULL CHECK (fenced IN (0,1)), row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32))";
const OBJECTS_SQL: &str = "CREATE TABLE agent_market_objects_v1 (object_kind INTEGER NOT NULL, object_id BLOB NOT NULL CHECK (length(object_id) = 32), object_version BLOB NOT NULL CHECK (length(object_version) = 8), immutable_body BLOB NOT NULL, mutable_state BLOB NOT NULL, row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32), PRIMARY KEY (object_kind, object_id)) WITHOUT ROWID";
const OPERATIONS_SQL: &str = "CREATE TABLE agent_market_operations_v1 (operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 32), sequence BLOB NOT NULL CHECK (length(sequence) = 8), operation_kind INTEGER NOT NULL, command BLOB NOT NULL, receipt BLOB NOT NULL, row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32)) WITHOUT ROWID";
const FINALIZED_BLOCKS_SQL: &str = "CREATE TABLE agent_market_finalized_blocks_v1 (marker_sequence BLOB PRIMARY KEY CHECK (length(marker_sequence) = 8), order_height BLOB NOT NULL CHECK (length(order_height) = 8), order_block_id BLOB NOT NULL UNIQUE CHECK (length(order_block_id) = 32), parent_order_height BLOB NOT NULL CHECK (length(parent_order_height) = 8), parent_order_block_id BLOB NOT NULL CHECK (length(parent_order_block_id) = 32), source_operation_sequence BLOB NOT NULL CHECK (length(source_operation_sequence) = 8), target_operation_sequence BLOB NOT NULL CHECK (length(target_operation_sequence) = 8), source_state_root BLOB NOT NULL CHECK (length(source_state_root) = 32), target_state_root BLOB NOT NULL CHECK (length(target_state_root) = 32), source_operation_root BLOB NOT NULL CHECK (length(source_operation_root) = 32), target_operation_root BLOB NOT NULL CHECK (length(target_operation_root) = 32), previous_marker_checksum BLOB NOT NULL CHECK (length(previous_marker_checksum) = 32), row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32)) WITHOUT ROWID";

type MetadataRecordV1 = (
    u16,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    u8,
    Vec<u8>,
);

#[derive(Clone, Debug)]
pub struct AgentMarketStoreConfigV1 {
    pub path: PathBuf,
    pub store_id: Hash32V1,
    pub trust_bundle: AgentMarketFreshGenesisTrustBundleV1,
}

impl AgentMarketStoreConfigV1 {
    fn config_hash(&self) -> AgentMarketResultV1<Hash32V1> {
        digest_value(
            "trnm.poco-ai.agent-market-store-config.candidate.v1",
            &(self.store_id, &self.trust_bundle),
        )
    }
}

#[derive(Debug)]
pub struct ConfirmedKernelReceiptV1 {
    receipt: KernelTransitionReceiptV1,
}

impl ConfirmedKernelReceiptV1 {
    pub const fn receipt(&self) -> &KernelTransitionReceiptV1 {
        &self.receipt
    }
}

/// Exact read-only head observed after a fresh immutable SQLite reopen.
///
/// This is a local consistency fact, not an order-finality proof, a
/// whole-node checkpoint, or an anti-rollback authority.  Its fields remain
/// private so another crate cannot forge a store observation.
#[derive(Debug, Eq, PartialEq)]
pub struct AgentMarketFreshReadbackV1 {
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

/// Read-only execution result for one candidate proposal.
///
/// This is deliberately not an Order-finality receipt and it is not a JMT
/// root.  The candidate post-state root uses this crate's local object-root
/// domain.  The preview is returned only after the store's complete logical
/// row inventory and authenticated head are freshly proven unchanged across
/// the rolled-back SQLite transaction.
#[derive(Debug)]
pub struct AgentMarketPreVotePreviewV1 {
    source_sequence: u64,
    source_state_root: Hash32V1,
    source_journal_root: Hash32V1,
    candidate_post_state_root: Hash32V1,
    candidate_receipts: Vec<KernelTransitionReceiptV1>,
    unchanged_row_inventory_digest: Hash32V1,
}

impl AgentMarketPreVotePreviewV1 {
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

    pub fn candidate_receipts(&self) -> &[KernelTransitionReceiptV1] {
        &self.candidate_receipts
    }

    pub const fn unchanged_row_inventory_digest(&self) -> Hash32V1 {
        self.unchanged_row_inventory_digest
    }
}

impl AgentMarketFreshReadbackV1 {
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

    /// Checksum-chain root of the freshly audited finalized-Order block
    /// journal. This is local durability evidence, not Order finality.
    pub const fn durable_finalized_block_root(&self) -> Hash32V1 {
        self.durable_finalized_block_root
    }
}

#[derive(Debug)]
pub enum KernelExecutionOutcomeV1 {
    Applied(ConfirmedKernelReceiptV1),
    Replayed(ConfirmedKernelReceiptV1),
}

impl KernelExecutionOutcomeV1 {
    pub const fn receipt(&self) -> &KernelTransitionReceiptV1 {
        match self {
            Self::Applied(confirmed) | Self::Replayed(confirmed) => confirmed.receipt(),
        }
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

#[derive(Clone, Debug)]
pub struct PocoAgentMarketStoreV1 {
    config: AgentMarketStoreConfigV1,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitFaultV1 {
    NotAppliedAckLost,
    AppliedAckLost,
    ThirdState,
}

struct AuthorizationSnapshotV1 {
    lane_body: NonceLaneKeyBodyV1,
    lane_state: NonceLaneStateV1,
    capability: Option<(CapabilityGrantBodyV1, CapabilityStateV1)>,
    session: Option<(SessionKeyGrantBodyV1, SessionKeyGrantStateV1)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    row_checksum: Hash32V1,
}

impl PocoAgentMarketStoreV1 {
    pub fn open(config: AgentMarketStoreConfigV1) -> AgentMarketResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        reject_sidecars(&config.path)?;
        if config.path.exists() {
            let read_only = open_ro_raw(&config.path)?;
            verify_schema(&read_only)?;
            verify_metadata(&read_only, &config)?;
            audit_store(&read_only, &config)?;
            drop(read_only);

            let connection = open_rw_raw(&config.path, false)?;
            verify_schema(&connection)?;
            verify_metadata(&connection, &config)?;
            audit_store(&connection, &config)?;
        } else {
            if let Some(parent) = config.path.parent() {
                fs::create_dir_all(parent).map_err(|cause| {
                    error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string())
                })?;
            }
            let connection = open_rw_raw(&config.path, true)?;
            create_schema(&connection, &config)?;
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
    pub fn open_existing(config: AgentMarketStoreConfigV1) -> AgentMarketResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        let connection = open_ro_raw(&config.path)?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &config)?;
        audit_store(&connection, &config)?;
        drop(connection);
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        Ok(Self { config })
    }

    pub fn execute_order_finalized(
        &self,
        execution: &OrderFinalizedExecutionContextV1,
        command: &KernelCommandV1,
    ) -> AgentMarketResultV1<KernelExecutionOutcomeV1> {
        self.execute_inner(execution, command, CommitFaultInternalV1::None)
    }

    /// Advance one finalized Order block that contains no Agent/Market
    /// commands while preserving the exact state, sequence and journal roots.
    ///
    /// This is the empty-batch counterpart to [`Self::execute_order_finalized`].
    /// The target must be the direct successor of the caller's exact durable
    /// parent.  An exact target readback is idempotent, which lets a
    /// whole-node recovery owner resolve acknowledgement loss without
    /// manufacturing a synthetic operation receipt.
    pub fn advance_empty_order_finalized_v1(
        &self,
        execution: &OrderFinalizedExecutionContextV1,
    ) -> AgentMarketResultV1<AgentMarketFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_context_static(&self.config, execution)?;
        if execution.expected_order_height.checked_add(1) != Some(execution.order_height) {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidContext,
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
                AgentMarketErrorCodeV1::StaleVersion,
                "empty finalized batch parent differs from durable head",
            ));
        }

        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_execution_context_cas(&transaction, execution)?;
        advance_finalized_block_marker(
            &transaction,
            &self.config,
            execution,
            before.sequence,
            before.sequence,
            before.durable_state_root,
            before.durable_state_root,
            before.durable_journal_root,
            before.durable_journal_root,
        )?;
        update_metadata_progress(
            &transaction,
            &self.config,
            before.sequence,
            execution.order_height,
            execution.order_block_id,
            before.durable_state_root,
            before.durable_journal_root,
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
                AgentMarketErrorCodeV1::ThirdStateFenced,
                "empty finalized batch readback differs from its exact target",
            ));
        }
        Ok(after)
    }

    /// Execute a bounded candidate proposal against the exact fresh durable
    /// parent, then roll every SQLite mutation back before returning.
    ///
    /// This path reuses the same signature, capability, nonce, version,
    /// resource, fee and conservation checks as durable execution.  It never
    /// advances the local Order-finalized tip.  A later whole-node owner must
    /// bind this preview before a Vote can be requested.
    pub fn preview_before_vote_v1(
        &self,
        expected_parent: &AgentMarketFreshReadbackV1,
        candidate_height: u64,
        candidate_block_id: Hash32V1,
        commands: &[KernelCommandV1],
    ) -> AgentMarketResultV1<AgentMarketPreVotePreviewV1> {
        reject_sidecars(&self.config.path)?;
        let before = self.fresh_readback()?;
        if &before != expected_parent
            || candidate_height
                != before.order_height.checked_add(1).ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "candidate height overflows",
                    )
                })?
            || candidate_block_id == Hash32V1::default()
            || candidate_block_id == before.order_block_id
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidContext,
                "pre-vote candidate does not extend the exact fresh parent",
            ));
        }
        let before_inventory = self.logical_row_inventory_digest_v1()?;
        let mut connection = self.open_rw_verified()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (tip_height, tip_block_id) = load_order_tip(&transaction)?;
        if tip_height != before.order_height || tip_block_id != before.order_block_id {
            return Err(error(
                AgentMarketErrorCodeV1::StaleVersion,
                "Agent/Market parent changed before preview",
            ));
        }

        let mut operation_ids = BTreeSet::new();
        let mut receipts = Vec::with_capacity(commands.len());
        for (offset, command) in commands.iter().enumerate() {
            verify_command_envelope(&self.config, candidate_height, command)?;
            let command_bytes = canonical_bytes(command)?;
            let operation_id = command.operation_id()?;
            if !operation_ids.insert(operation_id)
                || load_operation(&transaction, operation_id, &command_bytes)?.is_some()
            {
                return Err(error(
                    AgentMarketErrorCodeV1::Conflict,
                    "pre-vote batch repeats an Agent/Market operation",
                ));
            }
            let authorization = authorize(&transaction, &self.config, candidate_height, command)?;
            apply_command(&transaction, &self.config, candidate_height, command)?;
            consume_authorization(
                &transaction,
                &self.config,
                candidate_height,
                command,
                authorization,
            )?;
            let offset = u64::try_from(offset).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "pre-vote operation index exceeds u64",
                )
            })?;
            let sequence = before
                .sequence
                .checked_add(offset)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "pre-vote sequence overflows",
                    )
                })?;
            let receipt = KernelTransitionReceiptV1 {
                schema_version: SCHEMA_VERSION_V1,
                store_id: self.config.store_id,
                sequence,
                operation_id,
                operation_kind: command.operation_kind(),
                operation_digest: command.operation_digest()?,
                order_height: candidate_height,
                order_block_id: candidate_block_id,
                post_state_root: compute_state_root(&transaction)?,
            };
            insert_operation(&transaction, command, &command_bytes, &receipt)?;
            receipts.push(receipt);
        }
        let candidate_post_state_root = compute_state_root(&transaction)?;
        transaction.rollback()?;
        drop(connection);

        let after = self.fresh_readback()?;
        let after_inventory = self.logical_row_inventory_digest_v1()?;
        if after != before || after_inventory != before_inventory {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "Agent/Market preview changed a durable row or sequence",
            ));
        }
        Ok(AgentMarketPreVotePreviewV1 {
            source_sequence: before.sequence,
            source_state_root: before.durable_state_root,
            source_journal_root: before.durable_journal_root,
            candidate_post_state_root,
            candidate_receipts: receipts,
            unchanged_row_inventory_digest: before_inventory,
        })
    }

    #[cfg(test)]
    pub(crate) fn execute(
        &self,
        command: &KernelCommandV1,
    ) -> AgentMarketResultV1<KernelExecutionOutcomeV1> {
        let execution = self.current_test_execution_context()?;
        self.execute_inner(&execution, command, CommitFaultInternalV1::None)
    }

    #[cfg(test)]
    pub(crate) fn execute_at_height_for_test(
        &self,
        order_height: u64,
        order_block_id: Hash32V1,
        command: &KernelCommandV1,
    ) -> AgentMarketResultV1<KernelExecutionOutcomeV1> {
        let (expected_order_height, expected_order_block_id) = self.current_order_tip()?;
        let execution = OrderFinalizedExecutionContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.config.trust_bundle.context.clone(),
            expected_order_height,
            expected_order_block_id,
            order_height,
            order_block_id,
        };
        self.execute_inner(&execution, command, CommitFaultInternalV1::None)
    }

    #[cfg(test)]
    pub(crate) fn execute_with_fault(
        &self,
        command: &KernelCommandV1,
        fault: CommitFaultV1,
    ) -> AgentMarketResultV1<KernelExecutionOutcomeV1> {
        let internal = match fault {
            CommitFaultV1::NotAppliedAckLost => CommitFaultInternalV1::NotAppliedAckLost,
            CommitFaultV1::AppliedAckLost => CommitFaultInternalV1::AppliedAckLost,
            CommitFaultV1::ThirdState => CommitFaultInternalV1::ThirdState,
        };
        let execution = self.current_test_execution_context()?;
        self.execute_inner(&execution, command, internal)
    }

    fn execute_inner(
        &self,
        execution: &OrderFinalizedExecutionContextV1,
        command: &KernelCommandV1,
        fault: CommitFaultInternalV1,
    ) -> AgentMarketResultV1<KernelExecutionOutcomeV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_context_static(&self.config, execution)?;
        verify_command_envelope(&self.config, execution.order_height, command)?;
        let command_bytes = canonical_bytes(command)?;
        let operation_id = command.operation_id()?;

        let mut connection = self.open_rw_verified()?;
        if let Some(receipt) = load_operation(&connection, operation_id, &command_bytes)? {
            if (execution.order_height, execution.order_block_id)
                != (receipt.order_height, receipt.order_block_id)
                || load_order_tip(&connection)? != (receipt.order_height, receipt.order_block_id)
            {
                return Err(error(
                    AgentMarketErrorCodeV1::StaleVersion,
                    "exact replay target differs from the current finalized block",
                ));
            }
            drop(connection);
            return Ok(KernelExecutionOutcomeV1::Replayed(
                self.fresh_confirm_receipt(&receipt)?,
            ));
        }
        validate_execution_context_cas(&connection, execution)?;

        match fault {
            CommitFaultInternalV1::NotAppliedAckLost => {
                return Err(error(
                    AgentMarketErrorCodeV1::CommitUncertain,
                    "simulated not-applied acknowledgement loss",
                ));
            }
            CommitFaultInternalV1::ThirdState => {
                fence_store(&mut connection, &self.config)?;
                return Err(error(
                    AgentMarketErrorCodeV1::ThirdStateFenced,
                    "simulated third state permanently fenced the store",
                ));
            }
            CommitFaultInternalV1::None | CommitFaultInternalV1::AppliedAckLost => {}
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_execution_context_cas(&transaction, execution)?;
        let authorization = authorize(&transaction, &self.config, execution.order_height, command)?;
        apply_command(&transaction, &self.config, execution.order_height, command)?;
        consume_authorization(
            &transaction,
            &self.config,
            execution.order_height,
            command,
            authorization,
        )?;

        let current_sequence = load_sequence(&transaction)?;
        let sequence = current_sequence.checked_add(1).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "operation sequence overflow",
            )
        })?;
        let post_state_root = compute_state_root(&transaction)?;
        let receipt = KernelTransitionReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence,
            operation_id,
            operation_kind: command.operation_kind(),
            operation_digest: command.operation_digest()?,
            order_height: execution.order_height,
            order_block_id: execution.order_block_id,
            post_state_root,
        };
        insert_operation(&transaction, command, &command_bytes, &receipt)?;
        let durable_journal_root = compute_operation_journal_root(&transaction)?;
        advance_finalized_block_marker(
            &transaction,
            &self.config,
            execution,
            current_sequence,
            sequence,
            load_durable_state_root(&transaction)?,
            post_state_root,
            load_durable_journal_root(&transaction)?,
            durable_journal_root,
        )?;
        update_metadata_progress(
            &transaction,
            &self.config,
            sequence,
            execution.order_height,
            execution.order_block_id,
            post_state_root,
            durable_journal_root,
            false,
        )?;
        transaction.commit()?;
        drop(connection);

        if fault == CommitFaultInternalV1::AppliedAckLost {
            return Err(error(
                AgentMarketErrorCodeV1::CommitUncertain,
                "simulated applied-but-acknowledgement-lost commit",
            ));
        }
        Ok(KernelExecutionOutcomeV1::Applied(
            self.fresh_confirm_receipt(&receipt)?,
        ))
    }

    pub fn confirm_receipt(
        &self,
        receipt: &KernelTransitionReceiptV1,
    ) -> AgentMarketResultV1<ConfirmedKernelReceiptV1> {
        self.fresh_confirm_receipt(receipt)
    }

    /// Reopen and authenticate the exact durable head without mutating it.
    pub fn fresh_readback(&self) -> AgentMarketResultV1<AgentMarketFreshReadbackV1> {
        let connection = self.open_ro_verified()?;
        let sequence = load_sequence(&connection)?;
        let (order_height, order_block_id) = load_order_tip(&connection)?;
        Ok(AgentMarketFreshReadbackV1 {
            context: self.config.trust_bundle.context.clone(),
            store_schema_version: STORE_SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence,
            order_height,
            order_block_id,
            durable_state_root: load_durable_state_root(&connection)?,
            durable_journal_root: load_durable_journal_root(&connection)?,
            durable_finalized_block_root: finalized_block_journal_root(&connection, &self.config)?,
        })
    }

    fn logical_row_inventory_digest_v1(&self) -> AgentMarketResultV1<Hash32V1> {
        let connection = self.open_ro_verified_with_operation_root_check()?;
        let mut encoded = Vec::new();
        for query in [
            "SELECT singleton,schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,row_checksum FROM agent_market_metadata_v1 ORDER BY singleton",
            "SELECT object_kind,object_id,object_version,immutable_body,mutable_state,row_checksum FROM agent_market_objects_v1 ORDER BY object_kind,object_id",
            "SELECT operation_id,sequence,operation_kind,command,receipt,row_checksum FROM agent_market_operations_v1 ORDER BY operation_id",
            "SELECT marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum FROM agent_market_finalized_blocks_v1 ORDER BY marker_sequence",
        ] {
            let mut statement = connection.prepare(query)?;
            let column_count = statement.column_count();
            let mut rows = statement.query([])?;
            let mut row_count = 0u64;
            while let Some(row) = rows.next()? {
                row_count = row_count.checked_add(1).ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "logical row count overflows",
                    )
                })?;
                for index in 0..column_count {
                    let value = row.get_ref(index)?;
                    use rusqlite::types::ValueRef;
                    match value {
                        ValueRef::Null => encoded.push(0),
                        ValueRef::Integer(value) => {
                            encoded.push(1);
                            encoded.extend_from_slice(&value.to_le_bytes());
                        }
                        ValueRef::Real(value) => {
                            encoded.push(2);
                            encoded.extend_from_slice(&value.to_bits().to_le_bytes());
                        }
                        ValueRef::Text(value) => {
                            encoded.push(3);
                            encoded.extend_from_slice(
                                &u64::try_from(value.len())
                                    .map_err(|_| {
                                        error(
                                            AgentMarketErrorCodeV1::ArithmeticOverflow,
                                            "logical text length overflows",
                                        )
                                    })?
                                    .to_le_bytes(),
                            );
                            encoded.extend_from_slice(value);
                        }
                        ValueRef::Blob(value) => {
                            encoded.push(4);
                            encoded.extend_from_slice(
                                &u64::try_from(value.len())
                                    .map_err(|_| {
                                        error(
                                            AgentMarketErrorCodeV1::ArithmeticOverflow,
                                            "logical blob length overflows",
                                        )
                                    })?
                                    .to_le_bytes(),
                            );
                            encoded.extend_from_slice(value);
                        }
                    }
                }
            }
            encoded.extend_from_slice(&row_count.to_le_bytes());
        }
        crate::codec::digest_encoded(
            "trnm.poco-ai.agent-market-logical-row-inventory.candidate.v1",
            &encoded,
        )
    }

    fn fresh_confirm_receipt(
        &self,
        receipt: &KernelTransitionReceiptV1,
    ) -> AgentMarketResultV1<ConfirmedKernelReceiptV1> {
        if receipt.store_id != self.config.store_id {
            return Err(error(
                AgentMarketErrorCodeV1::Unauthorized,
                "receipt belongs to another store",
            ));
        }
        let connection = self.open_ro_verified_with_operation_root_check()?;
        let stored: Option<Vec<u8>> = connection
            .query_row(
                "SELECT receipt FROM agent_market_operations_v1 WHERE operation_id=?1",
                params![&receipt.operation_id.0[..]],
                |row| row.get(0),
            )
            .optional()?;
        let stored = stored.ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::NotFound,
                "receipt operation is absent",
            )
        })?;
        let decoded: KernelTransitionReceiptV1 = strict_decode(&stored)?;
        if decoded != *receipt || canonical_bytes(receipt)? != stored {
            return Err(error(
                AgentMarketErrorCodeV1::Conflict,
                "receipt does not match exact durable bytes",
            ));
        }
        Ok(ConfirmedKernelReceiptV1 { receipt: decoded })
    }

    pub fn capability_state(&self, id: CapabilityIdV1) -> AgentMarketResultV1<CapabilityStateV1> {
        self.read_state(ObjectKindV1::Capability, &id.0)
    }

    pub fn session_state(
        &self,
        id: SessionKeyGrantIdV1,
    ) -> AgentMarketResultV1<SessionKeyGrantStateV1> {
        self.read_state(ObjectKindV1::SessionGrant, &id.0)
    }

    pub fn nonce_lane_state(&self, id: NonceLaneIdV1) -> AgentMarketResultV1<NonceLaneStateV1> {
        self.read_state(ObjectKindV1::NonceLane, &id.0)
    }

    pub fn task_state(&self, id: TaskIdV1) -> AgentMarketResultV1<TaskStateV1> {
        self.read_state(ObjectKindV1::Task, &id.0)
    }

    pub fn bid_state(&self, id: BidIdV1) -> AgentMarketResultV1<BidStateV1> {
        self.read_state(ObjectKindV1::Bid, &id.0)
    }

    pub fn lease_state(&self, id: LeaseIdV1) -> AgentMarketResultV1<TaskLeaseStateV1> {
        self.read_state(ObjectKindV1::Lease, &id.0)
    }

    pub fn escrow_state(&self, id: EscrowIdV1) -> AgentMarketResultV1<EscrowStateV1> {
        self.read_state(ObjectKindV1::Escrow, &id.0)
    }

    pub fn account_state(&self, id: AccountIdV1) -> AgentMarketResultV1<AccountStateV1> {
        self.read_state(ObjectKindV1::Account, &id.0)
    }

    pub fn bond_state(&self, id: BondIdV1) -> AgentMarketResultV1<BondStateV1> {
        self.read_state(ObjectKindV1::Bond, &id.0)
    }

    fn read_state<T>(&self, kind: ObjectKindV1, id: &[u8; 32]) -> AgentMarketResultV1<T>
    where
        T: BorshDeserialize + BorshSerialize,
    {
        let connection = self.open_ro_verified()?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT mutable_state FROM agent_market_objects_v1 WHERE object_kind=?1 AND object_id=?2",
                params![kind as u16, &id[..]],
                |row| row.get(0),
            )
            .optional()?;
        strict_decode(
            &bytes
                .ok_or_else(|| error(AgentMarketErrorCodeV1::NotFound, "object state is absent"))?,
        )
    }

    fn open_rw_verified(&self) -> AgentMarketResultV1<Connection> {
        reject_sidecars(&self.config.path)?;
        let read_only = open_ro_raw(&self.config.path)?;
        verify_schema(&read_only)?;
        verify_metadata(&read_only, &self.config)?;
        audit_store(&read_only, &self.config)?;
        drop(read_only);
        let connection = open_rw_raw(&self.config.path, false)?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &self.config)?;
        audit_store(&connection, &self.config)?;
        Ok(connection)
    }

    fn open_ro_verified(&self) -> AgentMarketResultV1<Connection> {
        reject_sidecars(&self.config.path)?;
        let connection = open_ro_raw(&self.config.path)?;
        verify_schema(&connection)?;
        verify_metadata(&connection, &self.config)?;
        audit_store(&connection, &self.config)?;
        Ok(connection)
    }

    fn open_ro_verified_with_operation_root_check(&self) -> AgentMarketResultV1<Connection> {
        let connection = self.open_ro_verified()?;
        Ok(connection)
    }

    #[cfg(test)]
    fn current_test_execution_context(
        &self,
    ) -> AgentMarketResultV1<OrderFinalizedExecutionContextV1> {
        let (height, block_id) = self.current_order_tip()?;
        Ok(OrderFinalizedExecutionContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.config.trust_bundle.context.clone(),
            expected_order_height: height,
            expected_order_block_id: block_id,
            order_height: height,
            order_block_id: block_id,
        })
    }

    #[cfg(test)]
    fn current_order_tip(&self) -> AgentMarketResultV1<(u64, Hash32V1)> {
        let connection = self.open_ro_verified()?;
        load_order_tip(&connection)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum CommitFaultInternalV1 {
    None,
    NotAppliedAckLost,
    AppliedAckLost,
    ThirdState,
}

fn validate_trust_bundle(bundle: &AgentMarketFreshGenesisTrustBundleV1) -> AgentMarketResultV1<()> {
    if bundle.schema_version != SCHEMA_VERSION_V1
        || bundle.context.protocol_version != PROTOCOL_VERSION_V1
        || bundle.context.chain_id.is_empty()
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "invalid fresh-genesis trust bundle context",
        ));
    }
    let agent_ids = [bundle.requester.agent_id.0, bundle.provider.agent_id.0];
    let key_ids = [
        bundle.requester.controller_key_id.0,
        bundle.requester.session_key_id.0,
        bundle.provider.controller_key_id.0,
        bundle.provider.session_key_id.0,
    ];
    let public_keys = [
        bundle.requester.controller_public_key,
        bundle.requester.session_public_key,
        bundle.provider.controller_public_key,
        bundle.provider.session_public_key,
    ];
    if bundle.initial_order_block_id == Hash32V1::default()
        || agent_ids.contains(&[0; 32])
        || key_ids.contains(&[0; 32])
        || agent_ids[0] == agent_ids[1]
        || !all_unique(&key_ids)
        || !all_unique(&public_keys)
        || bundle.requester_account_body.account_id()? != bundle.requester_account_id
        || bundle.provider_bond_body.bond_id()? != bundle.provider_bond_id
        || bundle.requester_account_body.context != bundle.context
        || bundle.provider_bond_body.context != bundle.context
        || bundle.requester_account_body.owner_agent_id != bundle.requester.agent_id
        || bundle.provider_bond_body.owner_agent_id != bundle.provider.agent_id
        || bundle.requester_account_funding == 0
        || bundle.provider_bond_hold == 0
        || bundle.provider_bond_hold > bundle.provider_bond_funding
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "fresh-genesis trust bundle identities/economic objects are inconsistent",
        ));
    }
    VerifyingKey::from_bytes(&bundle.requester.controller_public_key).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "invalid requester controller public key",
        )
    })?;
    VerifyingKey::from_bytes(&bundle.requester.session_public_key).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "invalid requester session public key",
        )
    })?;
    VerifyingKey::from_bytes(&bundle.provider.controller_public_key).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "invalid provider controller public key",
        )
    })?;
    VerifyingKey::from_bytes(&bundle.provider.session_public_key).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "invalid provider session public key",
        )
    })?;
    Ok(())
}

fn all_unique<const N: usize>(values: &[[u8; 32]; N]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn validate_execution_context_static(
    config: &AgentMarketStoreConfigV1,
    execution: &OrderFinalizedExecutionContextV1,
) -> AgentMarketResultV1<()> {
    if execution.schema_version != SCHEMA_VERSION_V1
        || execution.context != config.trust_bundle.context
        || execution.order_height < execution.expected_order_height
        || execution.expected_order_block_id == Hash32V1::default()
        || execution.order_block_id == Hash32V1::default()
        || (execution.order_height == execution.expected_order_height
            && execution.order_block_id != execution.expected_order_block_id)
        || (execution.order_height > execution.expected_order_height
            && execution.order_block_id == execution.expected_order_block_id)
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "order-finalized execution context is malformed or non-monotonic",
        ));
    }
    Ok(())
}

fn validate_execution_context_cas(
    connection: &Connection,
    execution: &OrderFinalizedExecutionContextV1,
) -> AgentMarketResultV1<()> {
    let (height, block_id) = load_order_tip(connection)?;
    if height != execution.expected_order_height || block_id != execution.expected_order_block_id {
        return Err(error(
            AgentMarketErrorCodeV1::StaleVersion,
            "order-finalized execution context does not match durable tip",
        ));
    }
    Ok(())
}

fn verify_command_envelope(
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<()> {
    let statement = &command.authorization().statement;
    if statement.schema_version != SCHEMA_VERSION_V1
        || statement.context != config.trust_bundle.context
        || statement.operation_kind != command.operation_kind()
        || statement.operation_digest != command.operation_digest()?
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "authorization statement does not bind exact command/context",
        ));
    }
    if statement.valid_after_height > execution_height
        || execution_height > statement.expires_after_height
    {
        return Err(error(
            AgentMarketErrorCodeV1::Expired,
            "authorization statement is outside its height interval",
        ));
    }
    if command.authorization().signature.len() != 64 {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "strict Ed25519 signature must be 64 bytes",
        ));
    }
    verify_authorization_signature(config, command)
}

fn verify_authorization_signature(
    config: &AgentMarketStoreConfigV1,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<()> {
    let authorization = command.authorization();
    let agent = bootstrap_agent(
        &config.trust_bundle,
        authorization.statement.sender_agent_id,
    )?;
    let (expected_key_id, public_key) = if command.operation_kind() <= 3 {
        (agent.controller_key_id, agent.controller_public_key)
    } else {
        (agent.session_key_id, agent.session_public_key)
    };
    if authorization.signer_key_id != expected_key_id {
        return Err(error(
            AgentMarketErrorCodeV1::Unauthorized,
            "wrong signing key role for operation",
        ));
    }
    let domain = match command.operation_kind() {
        2 => "trnm.poco-ai.capability-grant-kernel-signature.candidate.v1",
        3 => "trnm.poco-ai.session-grant-kernel-signature.candidate.v1",
        4 => "trnm.poco-ai.task-offer-kernel-signature.candidate.v1",
        5 => "trnm.poco-ai.bid-kernel-signature.candidate.v1",
        6 => "trnm.poco-ai.lease-requester-kernel-signature.candidate.v1",
        7 => "trnm.poco-ai.lease-provider-kernel-signature.candidate.v1",
        _ => {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "unknown candidate operation kind",
            ));
        }
    };
    let message = digest_value(domain, &authorization.statement)?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "invalid committed Ed25519 public key",
        )
    })?;
    let signature = Signature::from_slice(&authorization.signature).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "malformed strict Ed25519 signature",
        )
    })?;
    key.verify_strict(&message.0, &signature).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::InvalidSignature,
            "strict Ed25519 verification failed",
        )
    })
}

fn bootstrap_agent(
    bundle: &AgentMarketFreshGenesisTrustBundleV1,
    agent_id: AgentIdV1,
) -> AgentMarketResultV1<&BootstrapAgentV1> {
    if bundle.requester.agent_id == agent_id {
        Ok(&bundle.requester)
    } else if bundle.provider.agent_id == agent_id {
        Ok(&bundle.provider)
    } else {
        Err(error(
            AgentMarketErrorCodeV1::Unauthorized,
            "agent is absent from fresh-genesis trust bundle",
        ))
    }
}

fn authorize(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<AuthorizationSnapshotV1> {
    let statement = &command.authorization().statement;
    let controller = command.operation_kind() <= 3;
    if controller {
        if statement.authorizing_key_id != CONTROLLER_SENTINEL_KEY_V1
            || statement.capability_id.is_some()
            || statement.live_capability_generation != 0
            || statement.session_key_grant_id.is_some()
            || statement.session_generation != 0
            || statement.nonce_lane != CONTROLLER_LANE_V1
        {
            return Err(error(
                AgentMarketErrorCodeV1::Unauthorized,
                "controller command does not use the exact lane-0 namespace",
            ));
        }
    } else if statement.authorizing_key_id == CONTROLLER_SENTINEL_KEY_V1
        || statement.capability_id.is_none()
        || statement.session_key_grant_id.is_none()
        || statement.session_generation == 0
        || statement.nonce_lane == CONTROLLER_LANE_V1
    {
        return Err(error(
            AgentMarketErrorCodeV1::Unauthorized,
            "session command does not use the exact nonzero session namespace",
        ));
    }

    let lane_body = NonceLaneKeyBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        agent_id: statement.sender_agent_id,
        authorizing_key_id: statement.authorizing_key_id,
        capability_id: statement.capability_id,
        session_generation: statement.session_generation,
        lane: statement.nonce_lane,
    };
    let lane_id = lane_body.nonce_lane_id()?;
    let (stored_lane_body, lane_state): (NonceLaneKeyBodyV1, NonceLaneStateV1) =
        load_object(transaction, ObjectKindV1::NonceLane, &lane_id.0)?;
    if stored_lane_body != lane_body
        || lane_state.nonce_lane_id != lane_id
        || lane_state.status != 0
        || lane_state.state_version != statement.expected_lane_version
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidNonceLane,
            "nonce lane identity/status/version mismatch",
        ));
    }
    if statement.nonce < lane_state.next_nonce {
        return Err(error(
            AgentMarketErrorCodeV1::NonceReplay,
            "nonce is lower than exact next nonce",
        ));
    }
    if statement.nonce > lane_state.next_nonce {
        return Err(error(
            AgentMarketErrorCodeV1::NonceGap,
            "nonce is higher than exact next nonce",
        ));
    }

    if controller {
        return Ok(AuthorizationSnapshotV1 {
            lane_body,
            lane_state,
            capability: None,
            session: None,
        });
    }

    let capability_id = statement.capability_id.expect("checked above");
    let session_id = statement.session_key_grant_id.expect("checked above");
    let (capability_body, capability_state): (CapabilityGrantBodyV1, CapabilityStateV1) =
        load_object(transaction, ObjectKindV1::Capability, &capability_id.0)?;
    let (session_body, session_state): (SessionKeyGrantBodyV1, SessionKeyGrantStateV1) =
        load_object(transaction, ObjectKindV1::SessionGrant, &session_id.0)?;
    let height = execution_height;
    if capability_state.status != 0
        || capability_state.live_revocation_generation != statement.live_capability_generation
        || capability_body.revocation_generation != statement.live_capability_generation
        || capability_body.delegate_agent_id != statement.sender_agent_id
        || height < capability_body.valid_from_height
        || height > capability_body.expires_after_height
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidCapability,
            "capability is inactive, expired, or generation-mismatched",
        ));
    }
    if session_state.status != 0
        || session_state.session_generation != statement.session_generation
        || session_state.bound_capability_generation != statement.live_capability_generation
        || session_body.session_generation != statement.session_generation
        || session_body.capability_id != capability_id
        || session_body.agent_id != statement.sender_agent_id
        || session_body.session_key_id != statement.authorizing_key_id
        || session_body.session_key_grant_id()? != session_id
        || height < session_body.valid_from_height
        || height > session_body.expires_after_height
        || !session_body
            .allowed_nonce_lanes
            .contains(&statement.nonce_lane)
        || session_state.operations_spent >= session_body.max_total_operations
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidSession,
            "session grant is inactive, expired, exhausted, or namespace-mismatched",
        ));
    }
    validate_operation_scope(transaction, &capability_body, command)?;
    Ok(AuthorizationSnapshotV1 {
        lane_body,
        lane_state,
        capability: Some((capability_body, capability_state)),
        session: Some((session_body, session_state)),
    })
}

fn validate_operation_scope(
    transaction: &Transaction<'_>,
    capability: &CapabilityGrantBodyV1,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<()> {
    let kind = command.operation_kind();
    let scope = capability
        .operation_scopes
        .iter()
        .find(|scope| scope.operation_kind == kind)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::InvalidCapability,
                "capability does not authorize operation kind",
            )
        })?;
    let resolved = resolve_operation_scope(transaction, command)?;
    if scope
        .task_id
        .is_some_and(|required| required != resolved.task_id)
        || scope
            .model_commitment
            .is_some_and(|required| required != resolved.task.model_scope_commitment)
        || scope
            .tool_commitment
            .is_some_and(|required| required != resolved.task.tool_scope_commitment)
        || scope.verification_profile.as_ref().is_some_and(|required| {
            required.profile_id != resolved.task.verification_profile_id
                || required.profile_version != resolved.task.verification_profile_version
                || required.profile_hash != resolved.task.verification_profile_hash
        })
        || scope
            .privacy_lane
            .is_some_and(|required| required != resolved.task.privacy_lane)
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidCapability,
            "operation falls outside exact task/model/tool/profile/privacy scope",
        ));
    }
    if scope.market_id.is_some() || scope.endpoint_commitment.is_some() {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidCapability,
            "candidate command has no independently verifiable market/endpoint carrier",
        ));
    }
    if let Some(maximum) = scope.maximum_unit_price {
        let price = resolved.maximum_unit_price.ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::InvalidCapability,
                "candidate command has no independently verifiable unit price",
            )
        })?;
        if price > maximum {
            return Err(error(
                AgentMarketErrorCodeV1::BudgetExceeded,
                "operation price exceeds capability unit-price scope",
            ));
        }
    }
    let resource_scope = capability
        .resource_scopes
        .iter()
        .find(|candidate| candidate.resource_kind == 1)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::InvalidCapability,
                "resource-limit scope is absent",
            )
        })?;
    if resource_scope.scope_mode != 0
        || !resource_scope
            .allowed_ids
            .contains(&resolved.task.resource_limit_hash)
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidCapability,
            "task resource-limit commitment is outside exact resource scope",
        ));
    }
    Ok(())
}

struct ResolvedOperationScopeV1 {
    task_id: TaskIdV1,
    task: TaskOfferBodyV1,
    maximum_unit_price: Option<u128>,
}

fn resolve_operation_scope(
    transaction: &Transaction<'_>,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<ResolvedOperationScopeV1> {
    match command {
        KernelCommandV1::TaskCreate { body, .. } => Ok(ResolvedOperationScopeV1 {
            task_id: body.task_offer_body.task_id()?,
            task: body.task_offer_body.clone(),
            maximum_unit_price: None,
        }),
        KernelCommandV1::Bid { body, .. } => {
            let (task, _): (TaskOfferBodyV1, TaskStateV1) =
                load_object(transaction, ObjectKindV1::Task, &body.task_id.0)?;
            Ok(ResolvedOperationScopeV1 {
                task_id: body.task_id,
                task,
                maximum_unit_price: Some(body.maximum_price),
            })
        }
        KernelCommandV1::LeaseAccept { body, .. } => {
            let (task, _): (TaskOfferBodyV1, TaskStateV1) =
                load_object(transaction, ObjectKindV1::Task, &body.task_id.0)?;
            let (bid, _): (BidBodyV1, BidStateV1) =
                load_object(transaction, ObjectKindV1::Bid, &body.accepted_bid_id.0)?;
            Ok(ResolvedOperationScopeV1 {
                task_id: body.task_id,
                task,
                maximum_unit_price: Some(bid.maximum_price),
            })
        }
        KernelCommandV1::ProviderAccept { body, .. } => {
            let (lease, _): (TaskLeaseBodyV1, TaskLeaseStateV1) =
                load_object(transaction, ObjectKindV1::Lease, &body.lease_id.0)?;
            let (task, _): (TaskOfferBodyV1, TaskStateV1) =
                load_object(transaction, ObjectKindV1::Task, &lease.task_id.0)?;
            let (bid, _): (BidBodyV1, BidStateV1) =
                load_object(transaction, ObjectKindV1::Bid, &lease.accepted_bid_id.0)?;
            Ok(ResolvedOperationScopeV1 {
                task_id: lease.task_id,
                task,
                maximum_unit_price: Some(bid.maximum_price),
            })
        }
        KernelCommandV1::CapabilityGrant { .. } | KernelCommandV1::SessionGrant { .. } => {
            Err(error(
                AgentMarketErrorCodeV1::InvalidCapability,
                "controller command cannot consume a delegated operation scope",
            ))
        }
    }
}

fn apply_command(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    command: &KernelCommandV1,
) -> AgentMarketResultV1<()> {
    match command {
        KernelCommandV1::CapabilityGrant {
            body,
            authorization,
        } => apply_capability_grant(transaction, config, execution_height, body, authorization),
        KernelCommandV1::SessionGrant {
            body,
            authorization,
        } => apply_session_grant(transaction, config, execution_height, body, authorization),
        KernelCommandV1::TaskCreate {
            body,
            authorization,
            ..
        } => apply_task_create(transaction, config, execution_height, body, authorization),
        KernelCommandV1::Bid {
            body,
            authorization,
            ..
        } => apply_bid(transaction, config, execution_height, body, authorization),
        KernelCommandV1::LeaseAccept {
            body,
            expected_bid_version,
            expected_escrow_version,
            expected_bond_version,
            authorization,
            ..
        } => apply_lease_accept(
            transaction,
            config,
            execution_height,
            body,
            *expected_bid_version,
            *expected_escrow_version,
            *expected_bond_version,
            authorization,
        ),
        KernelCommandV1::ProviderAccept {
            body,
            expected_lease_revision,
            authorization,
            ..
        } => apply_provider_accept(
            transaction,
            config,
            execution_height,
            body,
            *expected_lease_revision,
            authorization,
        ),
    }
}

fn apply_capability_grant(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &CapabilityGrantBodyV1,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    validate_body_context(
        config,
        body.schema_version,
        body.genesis_hash,
        &body.chain_id,
        body.protocol_version,
        body.stack_profile_hash,
    )?;
    let agent = bootstrap_agent(
        &config.trust_bundle,
        authorization.statement.sender_agent_id,
    )?;
    if body.issuer_agent_id != agent.agent_id
        || body.delegate_agent_id != agent.agent_id
        || body.issuer_key_id != CONTROLLER_SENTINEL_KEY_V1
        || body.delegate_key_id != Some(agent.session_key_id)
        || body.parent_capability_id.is_some()
        || body.valid_from_height > execution_height
        || body.expires_after_height < execution_height
        || body.valid_from_height > body.expires_after_height
        || body.rate_window_blocks == 0
        || body.rate_max_operations == 0
        || body.max_total_operations == 0
        || body.operation_scopes.is_empty()
        || body.resource_scopes.is_empty()
        || body.allowed_nonce_lanes.is_empty()
        || body.allowed_nonce_lanes.contains(&0)
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidCapability,
            "bounded root capability fields are invalid",
        ));
    }
    require_strictly_sorted_unique(&body.operation_scopes, "operation scopes")?;
    require_strictly_sorted_unique(&body.resource_scopes, "resource scopes")?;
    require_strictly_sorted_unique(&body.spend_limits, "spend limits")?;
    require_strictly_sorted_unique(&body.allowed_nonce_lanes, "allowed nonce lanes")?;
    require_unique_key(
        &body.operation_scopes,
        |scope| scope.operation_kind,
        "operation-scope kind",
    )?;
    require_unique_key(
        &body.resource_scopes,
        |scope| scope.resource_kind,
        "resource-scope kind",
    )?;
    require_unique_key(
        &body.spend_limits,
        |limit| limit.asset_id,
        "spend-limit asset",
    )?;
    for scope in &body.resource_scopes {
        let exact = scope.scope_mode == 0
            && !scope.allowed_ids.is_empty()
            && scope.allowlist_commitment.is_none();
        if !exact || scope.resource_kind != 1 {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidCapability,
                "candidate supports only exact resource-limit lists; committed/unknown scopes require an absent verifier",
            ));
        }
        require_strictly_sorted_unique(&scope.allowed_ids, "resource allowlist")?;
    }
    let capability_id = body.capability_id()?;
    let budget = CapabilityBudgetStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        capability_id,
        budget_version: 0,
        revocation_generation: body.revocation_generation,
        asset_counters: body
            .spend_limits
            .iter()
            .map(|limit| AssetBudgetCounterV1 {
                asset_id: limit.asset_id,
                limit: limit.maximum_amount,
                spent: 0,
                reserved: 0,
            })
            .collect(),
        fee_limit: body.fee_limit,
        fee_spent: 0,
        fee_reserved: 0,
        gas_limit: body.gas_limit,
        gas_spent: 0,
        gas_reserved: 0,
        da_byte_limit: body.da_byte_limit,
        da_bytes_spent: 0,
        da_bytes_reserved: 0,
        retention_limit: body.artifact_retention_limit,
        retention_spent: 0,
        retention_reserved: 0,
        operation_limit: body.max_total_operations,
        operations_spent: 0,
        operations_reserved: 0,
        rate_window_start_height: execution_height,
        rate_window_operations: 0,
    };
    let state = CapabilityStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        capability_id,
        state_version: 0,
        status: 0,
        live_revocation_generation: body.revocation_generation,
        accepted_height: execution_height,
        status_changed_height: execution_height,
        revoked_at_height: None,
        budget,
    };
    insert_object(
        transaction,
        ObjectKindV1::Capability,
        &capability_id.0,
        0,
        body,
        &state,
    )
}

fn apply_session_grant(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &SessionKeyGrantBodyV1,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    validate_body_context(
        config,
        body.schema_version,
        body.genesis_hash,
        &body.chain_id,
        body.protocol_version,
        body.stack_profile_hash,
    )?;
    let agent = bootstrap_agent(
        &config.trust_bundle,
        authorization.statement.sender_agent_id,
    )?;
    let (capability_body, capability_state): (CapabilityGrantBodyV1, CapabilityStateV1) =
        load_object(transaction, ObjectKindV1::Capability, &body.capability_id.0)?;
    if body.agent_id != agent.agent_id
        || body.session_key_id != agent.session_key_id
        || body.session_generation != 1
        || body.allowed_nonce_lanes.is_empty()
        || body.allowed_nonce_lanes.contains(&0)
        || body.valid_from_height < capability_body.valid_from_height
        || body.expires_after_height > capability_body.expires_after_height
        || body.valid_from_height > body.expires_after_height
        || body.max_total_operations == 0
        || body.max_total_operations > capability_body.max_total_operations
        || capability_state.status != 0
        || !body
            .allowed_nonce_lanes
            .iter()
            .all(|lane| capability_body.allowed_nonce_lanes.contains(lane))
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidSession,
            "session grant is not an exact attenuation of active capability",
        ));
    }
    require_strictly_sorted_unique(&body.allowed_nonce_lanes, "session nonce lanes")?;
    let session_id = body.session_key_grant_id()?;
    let state = SessionKeyGrantStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        session_key_grant_id: session_id,
        state_version: 0,
        status: 0,
        session_generation: body.session_generation,
        bound_capability_generation: capability_state.live_revocation_generation,
        operations_spent: 0,
        accepted_height: execution_height,
        status_changed_height: execution_height,
        revoked_at_height: None,
    };
    insert_object(
        transaction,
        ObjectKindV1::SessionGrant,
        &session_id.0,
        0,
        body,
        &state,
    )?;
    for lane in &body.allowed_nonce_lanes {
        let lane_body = NonceLaneKeyBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: config.trust_bundle.context.clone(),
            agent_id: body.agent_id,
            authorizing_key_id: body.session_key_id,
            capability_id: Some(body.capability_id),
            session_generation: body.session_generation,
            lane: *lane,
        };
        insert_nonce_lane(transaction, &lane_body)?;
    }
    Ok(())
}

fn apply_task_create(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &TaskCreationOperationBodyV1,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    let offer = &body.task_offer_body;
    validate_body_context(
        config,
        offer.schema_version,
        offer.genesis_hash,
        &offer.chain_id,
        offer.protocol_version,
        offer.stack_profile_hash,
    )?;
    let statement = &authorization.statement;
    if offer.requester_agent_id != statement.sender_agent_id
        || offer.requester_key_id != statement.authorizing_key_id
        || offer.requester_capability_id != statement.capability_id
        || offer.requester_session_generation != statement.session_generation
        || offer.request_nonce_lane != statement.nonce_lane
        || offer.request_nonce != statement.nonce
        || offer.task_kind.is_empty()
        || offer.offer_expiry_height < execution_height
        || !(offer.offer_expiry_height <= offer.start_deadline_height
            && offer.start_deadline_height <= offer.result_deadline_height
            && offer.result_deadline_height <= offer.settlement_deadline_height)
        || body.escrow_terms.schema_version != SCHEMA_VERSION_V1
        || body.escrow_terms.refund_beneficiary != statement.sender_agent_id
        || offer.escrow_terms_hash
            != digest_value("trnm.poco-ai.escrow-terms.v1", &body.escrow_terms)?
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "task offer/escrow terms do not bind exact requester authorization",
        ));
    }
    let allocated = body
        .escrow_terms
        .provider_payment_cap
        .checked_add(body.escrow_terms.order_fee_reserve)
        .and_then(|value| value.checked_add(body.escrow_terms.transaction_da_fee_reserve))
        .and_then(|value| value.checked_add(body.escrow_terms.artifact_da_fee_reserve))
        .and_then(|value| value.checked_add(body.escrow_terms.verification_fee_reserve))
        .and_then(|value| value.checked_add(body.escrow_terms.challenge_reserve))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "escrow allocation sum overflow",
            )
        })?;
    if allocated > body.escrow_terms.funded_amount {
        return Err(error(
            AgentMarketErrorCodeV1::ConservationViolation,
            "escrow reserves exceed funded amount",
        ));
    }
    let (account_body, mut account_state): (AccountBodyV1, AccountStateV1) = load_object(
        transaction,
        ObjectKindV1::Account,
        &body.funding_account_id.0,
    )?;
    if account_state.version != body.expected_funding_account_version
        || account_state.closed
        || account_body.owner_agent_id != statement.sender_agent_id
        || account_body.asset_id != body.escrow_terms.asset_id
        || account_state.available < body.escrow_terms.funded_amount
    {
        return Err(error(
            AgentMarketErrorCodeV1::InsufficientFunds,
            "funding account is stale, closed, wrong-asset, or underfunded",
        ));
    }
    let before_total = account_total(&account_state)?;
    account_state.available -= body.escrow_terms.funded_amount;
    account_state.spent = account_state
        .spent
        .checked_add(body.escrow_terms.funded_amount)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "account spent overflow",
            )
        })?;
    account_state.version = account_state.version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "account version overflow",
        )
    })?;
    if account_total(&account_state)? != before_total {
        return Err(error(
            AgentMarketErrorCodeV1::ConservationViolation,
            "account conservation failed",
        ));
    }
    update_object(
        transaction,
        ObjectKindV1::Account,
        &body.funding_account_id.0,
        body.expected_funding_account_version,
        account_state.version,
        &account_body,
        &account_state,
    )?;

    let task_id = offer.task_id()?;
    let escrow_body = EscrowBodyV1 {
        schema_version: SCHEMA_VERSION_V1,
        genesis_hash: offer.genesis_hash,
        chain_id: offer.chain_id.clone(),
        protocol_version: offer.protocol_version,
        stack_profile_hash: offer.stack_profile_hash,
        task_id,
        requester_agent_id: offer.requester_agent_id,
        asset_id: body.escrow_terms.asset_id,
        funded_amount: body.escrow_terms.funded_amount,
        provider_payment_cap: body.escrow_terms.provider_payment_cap,
        order_fee_reserve: body.escrow_terms.order_fee_reserve,
        transaction_da_fee_reserve: body.escrow_terms.transaction_da_fee_reserve,
        artifact_da_fee_reserve: body.escrow_terms.artifact_da_fee_reserve,
        verification_fee_reserve: body.escrow_terms.verification_fee_reserve,
        challenge_reserve: body.escrow_terms.challenge_reserve,
        refund_beneficiary: body.escrow_terms.refund_beneficiary,
        settlement_policy_hash: body.escrow_terms.settlement_policy_hash,
        escrow_nonce: body.escrow_nonce,
    };
    let escrow_id = escrow_body.escrow_id()?;
    let empty_reservations: Vec<EscrowReservationEntryV1> = Vec::new();
    let escrow_state = EscrowStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        escrow_id,
        version: 0,
        available: escrow_body.funded_amount,
        reserved: 0,
        disbursed: 0,
        refunded: 0,
        forfeited: 0,
        active_reservation_root: digest_value(
            "trnm.poco-ai.escrow-active-reservations-root.v1",
            &empty_reservations,
        )?,
        active_reservations: empty_reservations,
        last_settlement_id: None,
        closed: false,
    };
    let task_state = TaskStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        task_id,
        revision: 0,
        attempt: 0,
        status: 0,
        active_lease_id: None,
        latest_checkpoint_id: None,
        active_result_id: None,
        escrow_id,
        active_deadline_kind: 0,
        active_deadline_height: offer.offer_expiry_height,
    };
    insert_object(
        transaction,
        ObjectKindV1::Task,
        &task_id.0,
        0,
        offer,
        &task_state,
    )?;
    insert_object(
        transaction,
        ObjectKindV1::Escrow,
        &escrow_id.0,
        0,
        &escrow_body,
        &escrow_state,
    )
}

fn apply_bid(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &BidBodyV1,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    validate_body_context(
        config,
        body.schema_version,
        body.genesis_hash,
        &body.chain_id,
        body.protocol_version,
        body.stack_profile_hash,
    )?;
    let statement = &authorization.statement;
    let (task_body, task_state): (TaskOfferBodyV1, TaskStateV1) =
        load_object(transaction, ObjectKindV1::Task, &body.task_id.0)?;
    let (escrow_body, _): (EscrowBodyV1, EscrowStateV1) =
        load_object(transaction, ObjectKindV1::Escrow, &task_state.escrow_id.0)?;
    let (bond_body, bond_state): (BondBodyV1, BondStateV1) =
        load_object(transaction, ObjectKindV1::Bond, &body.provider_bond_id.0)?;
    if body.provider_agent_id != statement.sender_agent_id
        || body.provider_key_id != statement.authorizing_key_id
        || body.provider_capability_id != statement.capability_id
        || body.provider_session_generation != statement.session_generation
        || body.provider_nonce_lane != statement.nonce_lane
        || body.provider_nonce != statement.nonce
        || task_state.status != 0
        || task_state.revision != body.task_revision
        || body.bid_expiry_height < execution_height
        || body.price_asset_id != escrow_body.asset_id
        || body.maximum_price == 0
        || body.maximum_price > escrow_body.provider_payment_cap
        || bond_body.owner_agent_id != statement.sender_agent_id
        || bond_state.closed
        || bond_state.available < config.trust_bundle.provider_bond_hold
        || task_body.offer_expiry_height < execution_height
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "bid does not bind exact open task/provider/bond/price state",
        ));
    }
    let bid_id = body.bid_id()?;
    let state = BidStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        bid_id,
        state_version: 0,
        status: 0,
        accepted_lease_id: None,
        accepted_height: None,
        terminal_height: None,
    };
    insert_object(transaction, ObjectKindV1::Bid, &bid_id.0, 0, body, &state)
}

#[allow(clippy::too_many_arguments)]
fn apply_lease_accept(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &TaskLeaseBodyV1,
    expected_bid_version: u64,
    expected_escrow_version: u64,
    expected_bond_version: u64,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    validate_body_context(
        config,
        body.schema_version,
        body.genesis_hash,
        &body.chain_id,
        body.protocol_version,
        body.stack_profile_hash,
    )?;
    let statement = &authorization.statement;
    let (task_body, mut task_state): (TaskOfferBodyV1, TaskStateV1) =
        load_object(transaction, ObjectKindV1::Task, &body.task_id.0)?;
    let (bid_body, mut bid_state): (BidBodyV1, BidStateV1) =
        load_object(transaction, ObjectKindV1::Bid, &body.accepted_bid_id.0)?;
    let (escrow_body, mut escrow_state): (EscrowBodyV1, EscrowStateV1) =
        load_object(transaction, ObjectKindV1::Escrow, &body.escrow_id.0)?;
    let (bond_body, mut bond_state): (BondBodyV1, BondStateV1) =
        load_object(transaction, ObjectKindV1::Bond, &body.provider_bond_id.0)?;
    let lease_id = body.lease_id()?;
    if statement.sender_agent_id != body.requester_agent_id
        || body.requester_agent_id != task_body.requester_agent_id
        || body.provider_agent_id != bid_body.provider_agent_id
        || body.accepted_bid_id != bid_state.bid_id
        || body.base_task_revision != task_state.revision
        || body.base_task_revision != bid_body.task_revision
        || task_state.revision != 0
        || task_state.status != 0
        || task_state.active_lease_id.is_some()
        || body.attempt != task_state.attempt
        || bid_state.state_version != expected_bid_version
        || bid_state.status != 0
        || bid_body.bid_expiry_height < execution_height
        || escrow_state.version != expected_escrow_version
        || escrow_state.closed
        || bond_state.version != expected_bond_version
        || bond_state.closed
        || body.escrow_id != task_state.escrow_id
        || body.provider_bond_id != bid_body.provider_bond_id
        || body.execution_environment_hash != bid_body.execution_environment_hash
        || body.pricing_terms_hash != bid_body.pricing_terms_hash
        || body.checkpoint_terms_hash != bid_body.checkpoint_terms_hash
        || body.availability_terms_hash != bid_body.availability_terms_hash
        || body.verification_profile_id != task_body.verification_profile_id
        || body.verification_profile_version != task_body.verification_profile_version
        || body.verification_profile_hash != task_body.verification_profile_hash
        || body.start_deadline_height != task_body.start_deadline_height
        || body.result_deadline_height != task_body.result_deadline_height
        || body.checkpoint_deadline_height < body.start_deadline_height
        || body.checkpoint_deadline_height > body.result_deadline_height
        || bid_body.maximum_price > escrow_body.provider_payment_cap
        || escrow_state.available < bid_body.maximum_price
        || bond_body.owner_agent_id != body.provider_agent_id
        || bond_state.available < config.trust_bundle.provider_bond_hold
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "lease acceptance preconditions are not the exact active task/bid/escrow/bond state",
        ));
    }

    let reservation = EscrowReservationEntryV1 {
        reservation_kind: 0,
        source_object_kind: ObjectKindV1::Lease as u16,
        source_object_id: Hash32V1(lease_id.0),
        asset_id: escrow_body.asset_id,
        amount: bid_body.maximum_price,
        created_height: execution_height,
        release_condition_hash: escrow_body.settlement_policy_hash,
    };
    if !escrow_state.active_reservations.is_empty() {
        return Err(error(
            AgentMarketErrorCodeV1::Conflict,
            "task attempt already has an escrow reservation",
        ));
    }
    escrow_state.available -= bid_body.maximum_price;
    escrow_state.reserved = escrow_state
        .reserved
        .checked_add(bid_body.maximum_price)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "escrow reserve overflow",
            )
        })?;
    escrow_state.active_reservations.push(reservation);
    escrow_state.active_reservation_root = digest_value(
        "trnm.poco-ai.escrow-active-reservations-root.v1",
        &escrow_state.active_reservations,
    )?;
    escrow_state.version = escrow_state.version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "escrow version overflow",
        )
    })?;
    validate_escrow_conservation(&escrow_body, &escrow_state)?;

    bond_state.available -= config.trust_bundle.provider_bond_hold;
    bond_state.held = bond_state
        .held
        .checked_add(config.trust_bundle.provider_bond_hold)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "bond hold overflow",
            )
        })?;
    bond_state.version = bond_state.version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "bond version overflow",
        )
    })?;
    validate_bond_conservation(config, &bond_state)?;

    task_state.revision = task_state.revision.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "task revision overflow",
        )
    })?;
    task_state.status = 1;
    task_state.active_lease_id = Some(lease_id);
    task_state.active_deadline_kind = 1;
    task_state.active_deadline_height = body.start_deadline_height;

    bid_state.state_version = bid_state.state_version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "bid version overflow",
        )
    })?;
    bid_state.status = 1;
    bid_state.accepted_lease_id = Some(lease_id);
    bid_state.accepted_height = Some(execution_height);

    let lease_state = TaskLeaseStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        lease_id,
        revision: 0,
        attempt: body.attempt,
        status: 0,
        accepted_height: None,
        started_height: None,
        terminal_height: None,
        latest_checkpoint_id: None,
    };

    update_object(
        transaction,
        ObjectKindV1::Task,
        &body.task_id.0,
        body.base_task_revision,
        task_state.revision,
        &task_body,
        &task_state,
    )?;
    update_object(
        transaction,
        ObjectKindV1::Bid,
        &body.accepted_bid_id.0,
        expected_bid_version,
        bid_state.state_version,
        &bid_body,
        &bid_state,
    )?;
    update_object(
        transaction,
        ObjectKindV1::Escrow,
        &body.escrow_id.0,
        expected_escrow_version,
        escrow_state.version,
        &escrow_body,
        &escrow_state,
    )?;
    update_object(
        transaction,
        ObjectKindV1::Bond,
        &body.provider_bond_id.0,
        expected_bond_version,
        bond_state.version,
        &bond_body,
        &bond_state,
    )?;
    insert_object(
        transaction,
        ObjectKindV1::Lease,
        &lease_id.0,
        0,
        body,
        &lease_state,
    )
}

fn apply_provider_accept(
    transaction: &Transaction<'_>,
    config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    body: &LeaseProviderAcceptanceBodyV1,
    expected_lease_revision: u64,
    authorization: &KernelAuthorizationV1,
) -> AgentMarketResultV1<()> {
    if body.schema_version != SCHEMA_VERSION_V1 || body.context != config.trust_bundle.context {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "provider acceptance context mismatch",
        ));
    }
    let (lease_body, mut lease_state): (TaskLeaseBodyV1, TaskLeaseStateV1) =
        load_object(transaction, ObjectKindV1::Lease, &body.lease_id.0)?;
    let (_task_body, task_state): (TaskOfferBodyV1, TaskStateV1) =
        load_object(transaction, ObjectKindV1::Task, &lease_body.task_id.0)?;
    if body.provider_agent_id != authorization.statement.sender_agent_id
        || body.provider_agent_id != lease_body.provider_agent_id
        || body.expected_task_revision != task_state.revision
        || task_state.status != 1
        || task_state.active_lease_id != Some(body.lease_id)
        || lease_state.revision != expected_lease_revision
        || lease_state.status != 0
        || lease_state.attempt != lease_body.attempt
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "provider acceptance does not bind exact offered lease/task revision",
        ));
    }
    lease_state.revision = lease_state.revision.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "lease revision overflow",
        )
    })?;
    lease_state.status = 1;
    lease_state.accepted_height = Some(execution_height);
    update_object(
        transaction,
        ObjectKindV1::Lease,
        &body.lease_id.0,
        expected_lease_revision,
        lease_state.revision,
        &lease_body,
        &lease_state,
    )
}

fn consume_authorization(
    transaction: &Transaction<'_>,
    _config: &AgentMarketStoreConfigV1,
    execution_height: u64,
    command: &KernelCommandV1,
    mut snapshot: AuthorizationSnapshotV1,
) -> AgentMarketResultV1<()> {
    let statement = &command.authorization().statement;
    snapshot.lane_state.state_version = snapshot
        .lane_state
        .state_version
        .checked_add(1)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "lane version overflow",
            )
        })?;
    snapshot.lane_state.next_nonce = snapshot
        .lane_state
        .next_nonce
        .checked_add(1)
        .ok_or_else(|| error(AgentMarketErrorCodeV1::ArithmeticOverflow, "nonce overflow"))?;
    snapshot.lane_state.last_operation_digest = Some(statement.operation_digest);
    update_object(
        transaction,
        ObjectKindV1::NonceLane,
        &snapshot.lane_state.nonce_lane_id.0,
        statement.expected_lane_version,
        snapshot.lane_state.state_version,
        &snapshot.lane_body,
        &snapshot.lane_state,
    )?;

    if let (
        Some((capability_body, mut capability_state)),
        Some((session_body, mut session_state)),
    ) = (snapshot.capability, snapshot.session)
    {
        let charge = match command {
            KernelCommandV1::TaskCreate { charge, body, .. } => {
                if charge.asset_charges
                    != vec![AssetChargeV1 {
                        asset_id: body.escrow_terms.asset_id,
                        amount: body.escrow_terms.funded_amount,
                    }]
                {
                    return Err(error(
                        AgentMarketErrorCodeV1::BudgetExceeded,
                        "task charge must equal exact funded escrow asset/amount",
                    ));
                }
                charge
            }
            KernelCommandV1::Bid { charge, .. }
            | KernelCommandV1::LeaseAccept { charge, .. }
            | KernelCommandV1::ProviderAccept { charge, .. } => charge,
            KernelCommandV1::CapabilityGrant { .. } | KernelCommandV1::SessionGrant { .. } => {
                unreachable!("controller commands have no capability snapshot")
            }
        };
        apply_budget(
            execution_height,
            &capability_body,
            &mut capability_state,
            charge,
        )?;
        session_state.operations_spent = session_state
            .operations_spent
            .checked_add(charge.operations)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "session operation counter overflow",
                )
            })?;
        if session_state.operations_spent > session_body.max_total_operations {
            return Err(error(
                AgentMarketErrorCodeV1::BudgetExceeded,
                "session operation limit exceeded",
            ));
        }
        session_state.state_version =
            session_state.state_version.checked_add(1).ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "session version overflow",
                )
            })?;
        update_object(
            transaction,
            ObjectKindV1::Capability,
            &capability_state.capability_id.0,
            capability_state.state_version - 1,
            capability_state.state_version,
            &capability_body,
            &capability_state,
        )?;
        update_object(
            transaction,
            ObjectKindV1::SessionGrant,
            &session_state.session_key_grant_id.0,
            session_state.state_version - 1,
            session_state.state_version,
            &session_body,
            &session_state,
        )?;
    }
    Ok(())
}

fn apply_budget(
    execution_height: u64,
    capability_body: &CapabilityGrantBodyV1,
    state: &mut CapabilityStateV1,
    charge: &KernelResourceChargeV1,
) -> AgentMarketResultV1<()> {
    if charge.operations != 1 {
        return Err(error(
            AgentMarketErrorCodeV1::BudgetExceeded,
            "candidate command consumes exactly one operation",
        ));
    }
    require_strictly_sorted_unique(&charge.asset_charges, "asset charges")?;
    require_unique_key(
        &charge.asset_charges,
        |charge| charge.asset_id,
        "asset-charge asset",
    )?;
    for requested in &charge.asset_charges {
        let counter = state
            .budget
            .asset_counters
            .iter_mut()
            .find(|counter| counter.asset_id == requested.asset_id)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::BudgetExceeded,
                    "asset is outside capability spend limits",
                )
            })?;
        let next = counter
            .spent
            .checked_add(counter.reserved)
            .and_then(|value| value.checked_add(requested.amount))
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "asset budget arithmetic overflow",
                )
            })?;
        if next > counter.limit {
            return Err(error(
                AgentMarketErrorCodeV1::BudgetExceeded,
                "asset budget exceeded",
            ));
        }
        counter.spent = counter.spent.checked_add(requested.amount).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "asset spent overflow",
            )
        })?;
    }
    checked_budget_add_u128(
        &mut state.budget.fee_spent,
        state.budget.fee_reserved,
        charge.fee,
        state.budget.fee_limit,
        "fee",
    )?;
    checked_budget_add_u64(
        &mut state.budget.gas_spent,
        state.budget.gas_reserved,
        charge.gas,
        state.budget.gas_limit,
        "gas",
    )?;
    checked_budget_add_u64(
        &mut state.budget.da_bytes_spent,
        state.budget.da_bytes_reserved,
        charge.da_bytes,
        state.budget.da_byte_limit,
        "DA byte",
    )?;
    checked_budget_add_u64(
        &mut state.budget.retention_spent,
        state.budget.retention_reserved,
        charge.retention,
        state.budget.retention_limit,
        "retention",
    )?;
    checked_budget_add_u64(
        &mut state.budget.operations_spent,
        state.budget.operations_reserved,
        charge.operations,
        state.budget.operation_limit,
        "operation",
    )?;
    let height = execution_height;
    let window_end = state
        .budget
        .rate_window_start_height
        .checked_add(capability_body.rate_window_blocks)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "rate window overflow",
            )
        })?;
    if height >= window_end {
        state.budget.rate_window_start_height = height;
        state.budget.rate_window_operations = 0;
    }
    state.budget.rate_window_operations = state
        .budget
        .rate_window_operations
        .checked_add(charge.operations)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "rate counter overflow",
            )
        })?;
    if state.budget.rate_window_operations > capability_body.rate_max_operations {
        return Err(error(
            AgentMarketErrorCodeV1::RateExceeded,
            "capability rate window exceeded",
        ));
    }
    state.budget.budget_version = state.budget.budget_version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "budget version overflow",
        )
    })?;
    state.state_version = state.state_version.checked_add(1).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "capability version overflow",
        )
    })?;
    Ok(())
}

fn checked_budget_add_u128(
    spent: &mut u128,
    reserved: u128,
    requested: u128,
    limit: u128,
    label: &str,
) -> AgentMarketResultV1<()> {
    let total = spent
        .checked_add(reserved)
        .and_then(|value| value.checked_add(requested))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                format!("{label} budget overflow"),
            )
        })?;
    if total > limit {
        return Err(error(
            AgentMarketErrorCodeV1::BudgetExceeded,
            format!("{label} budget exceeded"),
        ));
    }
    *spent = spent.checked_add(requested).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            format!("{label} spent overflow"),
        )
    })?;
    Ok(())
}

fn checked_budget_add_u64(
    spent: &mut u64,
    reserved: u64,
    requested: u64,
    limit: u64,
    label: &str,
) -> AgentMarketResultV1<()> {
    let total = spent
        .checked_add(reserved)
        .and_then(|value| value.checked_add(requested))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                format!("{label} budget overflow"),
            )
        })?;
    if total > limit {
        return Err(error(
            AgentMarketErrorCodeV1::BudgetExceeded,
            format!("{label} budget exceeded"),
        ));
    }
    *spent = spent.checked_add(requested).ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            format!("{label} spent overflow"),
        )
    })?;
    Ok(())
}

fn validate_body_context(
    config: &AgentMarketStoreConfigV1,
    schema: u16,
    genesis_hash: Hash32V1,
    chain_id: &str,
    protocol_version: u32,
    stack_profile_hash: Hash32V1,
) -> AgentMarketResultV1<()> {
    let context = &config.trust_bundle.context;
    if schema != SCHEMA_VERSION_V1
        || genesis_hash != context.genesis_hash
        || chain_id != context.chain_id
        || protocol_version != context.protocol_version
        || stack_profile_hash != context.stack_profile_hash
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidContext,
            "object context differs from committed protocol context",
        ));
    }
    Ok(())
}

fn require_strictly_sorted_unique<T: Ord>(values: &[T], label: &str) -> AgentMarketResultV1<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(error(
            AgentMarketErrorCodeV1::NonCanonical,
            format!("{label} must be strictly sorted and duplicate-free"),
        ));
    }
    Ok(())
}

fn require_unique_key<T, K: Eq>(
    values: &[T],
    mut key: impl FnMut(&T) -> K,
    label: &str,
) -> AgentMarketResultV1<()> {
    if values
        .windows(2)
        .any(|window| key(&window[0]) == key(&window[1]))
    {
        return Err(error(
            AgentMarketErrorCodeV1::NonCanonical,
            format!("{label} must be unique"),
        ));
    }
    Ok(())
}

fn account_total(state: &AccountStateV1) -> AgentMarketResultV1<u128> {
    state
        .available
        .checked_add(state.reserved)
        .and_then(|value| value.checked_add(state.spent))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "account total overflow",
            )
        })
}

fn validate_escrow_conservation(
    body: &EscrowBodyV1,
    state: &EscrowStateV1,
) -> AgentMarketResultV1<()> {
    let total = state
        .available
        .checked_add(state.reserved)
        .and_then(|value| value.checked_add(state.disbursed))
        .and_then(|value| value.checked_add(state.refunded))
        .and_then(|value| value.checked_add(state.forfeited))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "escrow total overflow",
            )
        })?;
    let reservation_sum = state
        .active_reservations
        .iter()
        .try_fold(0u128, |sum, entry| sum.checked_add(entry.amount))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "escrow reservation sum overflow",
            )
        })?;
    if total != body.funded_amount
        || reservation_sum != state.reserved
        || state.active_reservation_root
            != digest_value(
                "trnm.poco-ai.escrow-active-reservations-root.v1",
                &state.active_reservations,
            )?
    {
        return Err(error(
            AgentMarketErrorCodeV1::ConservationViolation,
            "escrow conservation/reservation root mismatch",
        ));
    }
    Ok(())
}

fn validate_bond_conservation(
    config: &AgentMarketStoreConfigV1,
    state: &BondStateV1,
) -> AgentMarketResultV1<()> {
    let total = state
        .available
        .checked_add(state.held)
        .and_then(|value| value.checked_add(state.released))
        .and_then(|value| value.checked_add(state.slashed))
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "bond total overflow",
            )
        })?;
    if total != config.trust_bundle.provider_bond_funding {
        return Err(error(
            AgentMarketErrorCodeV1::ConservationViolation,
            "provider bond conservation mismatch",
        ));
    }
    Ok(())
}

fn insert_nonce_lane(
    transaction: &Transaction<'_>,
    body: &NonceLaneKeyBodyV1,
) -> AgentMarketResultV1<()> {
    let id = body.nonce_lane_id()?;
    let state = NonceLaneStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: body.context.clone(),
        nonce_lane_id: id,
        state_version: 0,
        agent_id: body.agent_id,
        authorizing_key_id: body.authorizing_key_id,
        capability_id: body.capability_id,
        session_generation: body.session_generation,
        lane: body.lane,
        next_nonce: 0,
        last_operation_digest: None,
        status: 0,
    };
    insert_object(transaction, ObjectKindV1::NonceLane, &id.0, 0, body, &state)
}

fn create_schema(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(META_SQL, [])?;
    transaction.execute(OBJECTS_SQL, [])?;
    transaction.execute(OPERATIONS_SQL, [])?;
    transaction.execute(FINALIZED_BLOCKS_SQL, [])?;
    for agent in [
        &config.trust_bundle.requester,
        &config.trust_bundle.provider,
    ] {
        let lane = NonceLaneKeyBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: config.trust_bundle.context.clone(),
            agent_id: agent.agent_id,
            authorizing_key_id: CONTROLLER_SENTINEL_KEY_V1,
            capability_id: None,
            session_generation: 0,
            lane: 0,
        };
        insert_nonce_lane(&transaction, &lane)?;
    }
    let account_state = AccountStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        account_id: config.trust_bundle.requester_account_id,
        version: 0,
        available: config.trust_bundle.requester_account_funding,
        reserved: 0,
        spent: 0,
        closed: false,
    };
    insert_object(
        &transaction,
        ObjectKindV1::Account,
        &config.trust_bundle.requester_account_id.0,
        0,
        &config.trust_bundle.requester_account_body,
        &account_state,
    )?;
    let bond_state = BondStateV1 {
        schema_version: SCHEMA_VERSION_V1,
        context: config.trust_bundle.context.clone(),
        bond_id: config.trust_bundle.provider_bond_id,
        version: 0,
        available: config.trust_bundle.provider_bond_funding,
        held: 0,
        released: 0,
        slashed: 0,
        closed: false,
    };
    insert_object(
        &transaction,
        ObjectKindV1::Bond,
        &config.trust_bundle.provider_bond_id.0,
        0,
        &config.trust_bundle.provider_bond_body,
        &bond_state,
    )?;
    let initial_state_root = compute_state_root(&transaction)?;
    let initial_journal_root = compute_operation_journal_root(&transaction)?;
    insert_anchor_finalized_block_marker(
        &transaction,
        config,
        initial_state_root,
        initial_journal_root,
    )?;
    update_metadata_progress(
        &transaction,
        config,
        0,
        config.trust_bundle.initial_order_height,
        config.trust_bundle.initial_order_block_id,
        initial_state_root,
        initial_journal_root,
        false,
    )?;
    transaction.commit()?;
    verify_schema(connection)?;
    verify_metadata(connection, config)?;
    audit_store(connection, config)
}

fn insert_object<B: BorshSerialize, S: BorshSerialize>(
    transaction: &Transaction<'_>,
    kind: ObjectKindV1,
    id: &[u8; 32],
    version: u64,
    body: &B,
    state: &S,
) -> AgentMarketResultV1<()> {
    let body_bytes = canonical_bytes(body)?;
    let state_bytes = canonical_bytes(state)?;
    let version_bytes = version.to_le_bytes();
    let kind_bytes = (kind as u16).to_le_bytes();
    let row_checksum = checksum(&[&kind_bytes, id, &version_bytes, &body_bytes, &state_bytes]);
    transaction
        .execute(
            "INSERT INTO agent_market_objects_v1 (object_kind, object_id, object_version, immutable_body, mutable_state, row_checksum) VALUES (?1,?2,?3,?4,?5,?6)",
            params![kind as u16, &id[..], &version_bytes[..], body_bytes, state_bytes, &row_checksum.0[..]],
        )
        .map_err(|cause| {
            if matches!(cause, rusqlite::Error::SqliteFailure(_, _)) {
                error(AgentMarketErrorCodeV1::Conflict, "object already exists")
            } else {
                cause.into()
            }
        })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_object<B: BorshSerialize, S: BorshSerialize>(
    transaction: &Transaction<'_>,
    kind: ObjectKindV1,
    id: &[u8; 32],
    expected_version: u64,
    successor_version: u64,
    body: &B,
    state: &S,
) -> AgentMarketResultV1<()> {
    if successor_version
        != expected_version.checked_add(1).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "object version overflow",
            )
        })?
    {
        return Err(error(
            AgentMarketErrorCodeV1::StaleVersion,
            "successor object version is not predecessor + 1",
        ));
    }
    let body_bytes = canonical_bytes(body)?;
    let state_bytes = canonical_bytes(state)?;
    let version_bytes = successor_version.to_le_bytes();
    let expected_bytes = expected_version.to_le_bytes();
    let kind_bytes = (kind as u16).to_le_bytes();
    let row_checksum = checksum(&[&kind_bytes, id, &version_bytes, &body_bytes, &state_bytes]);
    let changed = transaction.execute(
        "UPDATE agent_market_objects_v1 SET object_version=?1, immutable_body=?2, mutable_state=?3, row_checksum=?4 WHERE object_kind=?5 AND object_id=?6 AND object_version=?7",
        params![&version_bytes[..], body_bytes, state_bytes, &row_checksum.0[..], kind as u16, &id[..], &expected_bytes[..]],
    )?;
    if changed != 1 {
        return Err(error(
            AgentMarketErrorCodeV1::StaleVersion,
            "object expected version is stale",
        ));
    }
    Ok(())
}

fn load_object<B, S>(
    transaction: &Transaction<'_>,
    kind: ObjectKindV1,
    id: &[u8; 32],
) -> AgentMarketResultV1<(B, S)>
where
    B: BorshDeserialize + BorshSerialize,
    S: BorshDeserialize + BorshSerialize,
{
    let record: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT immutable_body, mutable_state FROM agent_market_objects_v1 WHERE object_kind=?1 AND object_id=?2",
            params![kind as u16, &id[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (body, state) = record.ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::NotFound,
            "required object is absent",
        )
    })?;
    Ok((strict_decode(&body)?, strict_decode(&state)?))
}

fn insert_operation(
    transaction: &Transaction<'_>,
    command: &KernelCommandV1,
    command_bytes: &[u8],
    receipt: &KernelTransitionReceiptV1,
) -> AgentMarketResultV1<()> {
    let receipt_bytes = canonical_bytes(receipt)?;
    let sequence_bytes = receipt.sequence.to_le_bytes();
    let kind_bytes = command.operation_kind().to_le_bytes();
    let row_checksum = checksum(&[
        &receipt.operation_id.0,
        &sequence_bytes,
        &kind_bytes,
        command_bytes,
        &receipt_bytes,
    ]);
    transaction.execute(
        "INSERT INTO agent_market_operations_v1 (operation_id, sequence, operation_kind, command, receipt, row_checksum) VALUES (?1,?2,?3,?4,?5,?6)",
        params![&receipt.operation_id.0[..], &sequence_bytes[..], command.operation_kind(), command_bytes, receipt_bytes, &row_checksum.0[..]],
    )?;
    Ok(())
}

fn load_operation(
    connection: &Connection,
    operation_id: KernelOperationIdV1,
    command_bytes: &[u8],
) -> AgentMarketResultV1<Option<KernelTransitionReceiptV1>> {
    let record: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT command, receipt FROM agent_market_operations_v1 WHERE operation_id=?1",
            params![&operation_id.0[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match record {
        None => Ok(None),
        Some((stored_command, receipt)) => {
            if stored_command != command_bytes {
                return Err(error(
                    AgentMarketErrorCodeV1::Conflict,
                    "operation ID collides with different command bytes",
                ));
            }
            Ok(Some(strict_decode(&receipt)?))
        }
    }
}

fn compute_state_root(connection: &Connection) -> AgentMarketResultV1<Hash32V1> {
    let mut statement = connection.prepare(
        "SELECT object_kind, object_id, object_version, immutable_body, mutable_state, row_checksum FROM agent_market_objects_v1 ORDER BY object_kind, object_id",
    )?;
    let mut rows = statement.query([])?;
    let mut encoded = Vec::new();
    while let Some(row) = rows.next()? {
        let kind: u16 = row.get(0)?;
        let id: Vec<u8> = row.get(1)?;
        let version: Vec<u8> = row.get(2)?;
        let body: Vec<u8> = row.get(3)?;
        let state: Vec<u8> = row.get(4)?;
        let row_checksum: Vec<u8> = row.get(5)?;
        encoded.extend_from_slice(&kind.to_le_bytes());
        for bytes in [id, version, body, state, row_checksum] {
            let len = u64::try_from(bytes.len()).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "state-root component length overflow",
                )
            })?;
            encoded.extend_from_slice(&len.to_le_bytes());
            encoded.extend_from_slice(&bytes);
        }
    }
    crate::codec::digest_encoded(
        "trnm.poco-ai.agent-market-kernel-state-root.candidate.v1",
        &encoded,
    )
}

fn compute_operation_journal_root(connection: &Connection) -> AgentMarketResultV1<Hash32V1> {
    compute_operation_journal_root_through(connection, u64::MAX)
}

fn compute_operation_journal_root_through(
    connection: &Connection,
    maximum_sequence: u64,
) -> AgentMarketResultV1<Hash32V1> {
    let mut statement = connection.prepare(
        "SELECT operation_id,sequence,operation_kind,command,receipt,row_checksum FROM agent_market_operations_v1",
    )?;
    let mut rows = statement.query([])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let operation_id: Vec<u8> = row.get(0)?;
        let sequence: Vec<u8> = row.get(1)?;
        let kind: u16 = row.get(2)?;
        let command: Vec<u8> = row.get(3)?;
        let receipt: Vec<u8> = row.get(4)?;
        let row_checksum: Vec<u8> = row.get(5)?;
        let sequence_value = decode_u64(&sequence, "journal-root operation sequence")?;
        if sequence_value <= maximum_sequence {
            records.push((
                sequence_value,
                operation_id,
                sequence,
                kind,
                command,
                receipt,
                row_checksum,
            ));
        }
    }
    records.sort_by_key(|record| record.0);
    let mut encoded = Vec::new();
    for (_, operation_id, sequence, kind, command, receipt, row_checksum) in records {
        encoded.extend_from_slice(&kind.to_le_bytes());
        for bytes in [operation_id, sequence, command, receipt, row_checksum] {
            let len = u64::try_from(bytes.len()).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "journal-root component length overflow",
                )
            })?;
            encoded.extend_from_slice(&len.to_le_bytes());
            encoded.extend_from_slice(&bytes);
        }
    }
    crate::codec::digest_encoded(
        "trnm.poco-ai.agent-market-operation-journal-root.candidate.v1",
        &encoded,
    )
}

fn marker_predecessor_checksum(config: &AgentMarketStoreConfigV1) -> AgentMarketResultV1<Hash32V1> {
    let config_hash = config.config_hash()?;
    Ok(checksum(&[
        b"trnm.poco-ai.agent-market-finalized-block-anchor.candidate.v1",
        &config.store_id.0,
        &config_hash.0,
        &config.trust_bundle.initial_order_height.to_le_bytes(),
        &config.trust_bundle.initial_order_block_id.0,
    ]))
}

fn finalized_block_marker_checksum(
    config: &AgentMarketStoreConfigV1,
    marker: &FinalizedBlockMarkerV1,
) -> AgentMarketResultV1<Hash32V1> {
    let config_hash = config.config_hash()?;
    Ok(checksum(&[
        &STORE_SCHEMA_VERSION_V1.to_le_bytes(),
        &config.store_id.0,
        &config_hash.0,
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
    config: &AgentMarketStoreConfigV1,
    mut marker: FinalizedBlockMarkerV1,
) -> AgentMarketResultV1<FinalizedBlockMarkerV1> {
    marker.row_checksum = finalized_block_marker_checksum(config, &marker)?;
    let changed = connection.execute(
        "INSERT INTO agent_market_finalized_blocks_v1 (marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            marker.marker_sequence.to_le_bytes().as_slice(),
            marker.order_height.to_le_bytes().as_slice(),
            &marker.order_block_id.0[..],
            marker.parent_order_height.to_le_bytes().as_slice(),
            &marker.parent_order_block_id.0[..],
            marker.source_operation_sequence.to_le_bytes().as_slice(),
            marker.target_operation_sequence.to_le_bytes().as_slice(),
            &marker.source_state_root.0[..],
            &marker.target_state_root.0[..],
            &marker.source_operation_root.0[..],
            &marker.target_operation_root.0[..],
            &marker.previous_marker_checksum.0[..],
            &marker.row_checksum.0[..],
        ],
    )?;
    if changed != 1 {
        return Err(error(
            AgentMarketErrorCodeV1::StoreFailure,
            "finalized-block marker insert changed an unexpected row count",
        ));
    }
    Ok(marker)
}

fn insert_anchor_finalized_block_marker(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
    state_root: Hash32V1,
    operation_root: Hash32V1,
) -> AgentMarketResultV1<()> {
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
            row_checksum: Hash32V1::default(),
        },
    )?;
    Ok(())
}

fn decode_marker_hash(bytes: Vec<u8>, label: &str) -> AgentMarketResultV1<Hash32V1> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            format!("{label} is not exactly 32 bytes"),
        )
    })?;
    Ok(Hash32V1(value))
}

fn load_finalized_block_markers(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<Vec<FinalizedBlockMarkerV1>> {
    let mut statement = connection.prepare("SELECT marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum FROM agent_market_finalized_blocks_v1")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
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
            marker_sequence: decode_u64(&row.0, "marker sequence")?,
            order_height: decode_u64(&row.1, "marker Order height")?,
            order_block_id: decode_marker_hash(row.2, "marker Order block ID")?,
            parent_order_height: decode_u64(&row.3, "marker parent Order height")?,
            parent_order_block_id: decode_marker_hash(row.4, "marker parent Order block ID")?,
            source_operation_sequence: decode_u64(&row.5, "marker source sequence")?,
            target_operation_sequence: decode_u64(&row.6, "marker target sequence")?,
            source_state_root: decode_marker_hash(row.7, "marker source state root")?,
            target_state_root: decode_marker_hash(row.8, "marker target state root")?,
            source_operation_root: decode_marker_hash(row.9, "marker source operation root")?,
            target_operation_root: decode_marker_hash(row.10, "marker target operation root")?,
            previous_marker_checksum: decode_marker_hash(row.11, "previous marker checksum")?,
            row_checksum: decode_marker_hash(row.12, "marker row checksum")?,
        };
        if marker.row_checksum != finalized_block_marker_checksum(config, &marker)? {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block marker checksum differs",
            ));
        }
        markers.push(marker);
    }
    markers.sort_by_key(|marker| marker.marker_sequence);
    if markers.is_empty() {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "finalized-block journal is empty",
        ));
    }
    Ok(markers)
}

#[allow(clippy::too_many_arguments)]
fn advance_finalized_block_marker(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
    execution: &OrderFinalizedExecutionContextV1,
    source_sequence: u64,
    target_sequence: u64,
    source_state_root: Hash32V1,
    target_state_root: Hash32V1,
    source_operation_root: Hash32V1,
    target_operation_root: Hash32V1,
) -> AgentMarketResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
    let tail = *markers.last().expect("nonempty marker journal was checked");
    if source_sequence != tail.target_operation_sequence
        || source_state_root != tail.target_state_root
        || source_operation_root != tail.target_operation_root
        || target_sequence < source_sequence
    {
        return Err(error(
            AgentMarketErrorCodeV1::StaleVersion,
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
                AgentMarketErrorCodeV1::StaleVersion,
                "same-block marker extension does not expect the exact block",
            ));
        }
        let mut updated = tail;
        updated.target_operation_sequence = target_sequence;
        updated.target_state_root = target_state_root;
        updated.target_operation_root = target_operation_root;
        updated.row_checksum = finalized_block_marker_checksum(config, &updated)?;
        let changed = connection.execute(
            "UPDATE agent_market_finalized_blocks_v1 SET target_operation_sequence=?1,target_state_root=?2,target_operation_root=?3,row_checksum=?4 WHERE marker_sequence=?5 AND row_checksum=?6",
            params![
                updated.target_operation_sequence.to_le_bytes().as_slice(),
                &updated.target_state_root.0[..],
                &updated.target_operation_root.0[..],
                &updated.row_checksum.0[..],
                updated.marker_sequence.to_le_bytes().as_slice(),
                &tail.row_checksum.0[..],
            ],
        )?;
        if changed != 1 {
            return Err(error(
                AgentMarketErrorCodeV1::StaleVersion,
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
            AgentMarketErrorCodeV1::InvalidContext,
            "finalized-block marker target is not the direct Order successor",
        ));
    }
    insert_finalized_block_marker(
        connection,
        config,
        FinalizedBlockMarkerV1 {
            marker_sequence: tail.marker_sequence.checked_add(1).ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
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
            previous_marker_checksum: tail.row_checksum,
            row_checksum: Hash32V1::default(),
        },
    )?;
    Ok(())
}

fn load_sequence(connection: &Connection) -> AgentMarketResultV1<u64> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT sequence FROM agent_market_metadata_v1 WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    decode_u64(&bytes, "metadata sequence")
}

fn load_order_tip(connection: &Connection) -> AgentMarketResultV1<(u64, Hash32V1)> {
    let (height, block_id): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT order_height,order_block_id FROM agent_market_metadata_v1 WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let block_id: [u8; 32] = block_id.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata order block ID is not 32 bytes",
        )
    })?;
    Ok((
        decode_u64(&height, "metadata order height")?,
        Hash32V1(block_id),
    ))
}

fn load_durable_state_root(connection: &Connection) -> AgentMarketResultV1<Hash32V1> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT durable_state_root FROM agent_market_metadata_v1 WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let root: [u8; 32] = bytes.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata durable state root is not 32 bytes",
        )
    })?;
    Ok(Hash32V1(root))
}

fn load_durable_journal_root(connection: &Connection) -> AgentMarketResultV1<Hash32V1> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT durable_journal_root FROM agent_market_metadata_v1 WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let root: [u8; 32] = bytes.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata durable journal root is not 32 bytes",
        )
    })?;
    Ok(Hash32V1(root))
}

#[allow(clippy::too_many_arguments)]
fn update_metadata_progress(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
    sequence: u64,
    order_height: u64,
    order_block_id: Hash32V1,
    durable_state_root: Hash32V1,
    durable_journal_root: Hash32V1,
    fenced: bool,
) -> AgentMarketResultV1<()> {
    let config_hash = config.config_hash()?;
    let sequence_bytes = sequence.to_le_bytes();
    let order_height_bytes = order_height.to_le_bytes();
    let schema_bytes = STORE_SCHEMA_VERSION_V1.to_le_bytes();
    let fenced_byte = [u8::from(fenced)];
    let row_checksum = checksum(&[
        &schema_bytes,
        &config.store_id.0,
        &config_hash.0,
        &sequence_bytes,
        &order_height_bytes,
        &order_block_id.0,
        &durable_state_root.0,
        &durable_journal_root.0,
        &fenced_byte,
    ]);
    connection.execute(
        "INSERT INTO agent_market_metadata_v1 (singleton,schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,row_checksum) VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,store_id=excluded.store_id,config_hash=excluded.config_hash,sequence=excluded.sequence,order_height=excluded.order_height,order_block_id=excluded.order_block_id,durable_state_root=excluded.durable_state_root,durable_journal_root=excluded.durable_journal_root,fenced=excluded.fenced,row_checksum=excluded.row_checksum",
        params![STORE_SCHEMA_VERSION_V1, &config.store_id.0[..], &config_hash.0[..], &sequence_bytes[..], &order_height_bytes[..], &order_block_id.0[..], &durable_state_root.0[..], &durable_journal_root.0[..], u8::from(fenced), &row_checksum.0[..]],
    )?;
    Ok(())
}

fn fence_store(
    connection: &mut Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let sequence = load_sequence(&transaction)?;
    let (order_height, order_block_id) = load_order_tip(&transaction)?;
    let durable_state_root = load_durable_state_root(&transaction)?;
    let durable_journal_root = load_durable_journal_root(&transaction)?;
    update_metadata_progress(
        &transaction,
        config,
        sequence,
        order_height,
        order_block_id,
        durable_state_root,
        durable_journal_root,
        true,
    )?;
    transaction.commit()?;
    Ok(())
}

fn verify_metadata(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let record: MetadataRecordV1 = connection.query_row(
        "SELECT schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,row_checksum FROM agent_market_metadata_v1 WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
    )?;
    let (
        schema,
        store_id,
        config_hash,
        sequence,
        order_height,
        order_block_id,
        durable_state_root,
        durable_journal_root,
        fenced,
        actual_checksum,
    ) = record;
    let expected_config_hash = config.config_hash()?;
    let schema_bytes = schema.to_le_bytes();
    let fenced_byte = [fenced];
    let expected_checksum = checksum(&[
        &schema_bytes,
        &store_id,
        &config_hash,
        &sequence,
        &order_height,
        &order_block_id,
        &durable_state_root,
        &durable_journal_root,
        &fenced_byte,
    ]);
    if schema != STORE_SCHEMA_VERSION_V1
        || store_id.as_slice() != config.store_id.0
        || config_hash.as_slice() != expected_config_hash.0
        || sequence.len() != 8
        || order_height.len() != 8
        || order_block_id.len() != 32
        || durable_state_root.len() != 32
        || durable_journal_root.len() != 32
        || fenced > 1
        || actual_checksum.as_slice() != expected_checksum.0
    {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata/config/checksum mismatch",
        ));
    }
    let decoded_order_height = decode_u64(&order_height, "metadata order height")?;
    if decoded_order_height < config.trust_bundle.initial_order_height
        || order_block_id.as_slice() == [0; 32]
        || (decoded_order_height == config.trust_bundle.initial_order_height
            && order_block_id.as_slice() != config.trust_bundle.initial_order_block_id.0)
    {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata order tip regressed below or conflicts with genesis anchor",
        ));
    }
    if durable_state_root.as_slice() != compute_state_root(connection)?.0 {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata durable state root differs from current object state",
        ));
    }
    if durable_journal_root.as_slice() != compute_operation_journal_root(connection)?.0 {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata durable journal root differs from current operation journal",
        ));
    }
    if fenced == 1 {
        return Err(error(
            AgentMarketErrorCodeV1::ThirdStateFenced,
            "store is permanently fenced after an ambiguous third state",
        ));
    }
    Ok(())
}

fn audit_store(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    audit_objects(connection, config)?;
    audit_operations(connection, config)?;
    audit_operation_tail_root(connection)?;
    audit_finalized_block_journal(connection, config)
}

fn audit_objects(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT object_kind,object_id,object_version,immutable_body,mutable_state,row_checksum FROM agent_market_objects_v1 ORDER BY object_kind,object_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let kind: u16 = row.get(0)?;
        let id: Vec<u8> = row.get(1)?;
        let version: Vec<u8> = row.get(2)?;
        let body: Vec<u8> = row.get(3)?;
        let state: Vec<u8> = row.get(4)?;
        let actual_checksum: Vec<u8> = row.get(5)?;
        if id.len() != 32 || version.len() != 8 {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "object key/version width mismatch",
            ));
        }
        let expected_checksum = checksum(&[&kind.to_le_bytes(), &id, &version, &body, &state]);
        if actual_checksum.as_slice() != expected_checksum.0 {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "object row checksum mismatch",
            ));
        }
        let version_value = decode_u64(&version, "object version")?;
        validate_object_record(kind, &id, version_value, &body, &state, config)?;
    }
    Ok(())
}

fn validate_object_record(
    kind: u16,
    id: &[u8],
    version: u64,
    body: &[u8],
    state: &[u8],
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let id32: [u8; 32] = id.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            "object ID is not 32 bytes",
        )
    })?;
    macro_rules! validate {
        ($body_ty:ty, $state_ty:ty, $id_method:ident, $state_id:ident, $state_version:ident) => {{
            let decoded_body: $body_ty = strict_decode(body)?;
            let decoded_state: $state_ty = strict_decode(state)?;
            if decoded_body.$id_method()?.0 != id32
                || decoded_state.$state_id.0 != id32
                || decoded_state.$state_version != version
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "object ID/state version mismatch",
                ));
            }
        }};
    }
    match kind {
        2 => validate!(
            CapabilityGrantBodyV1,
            CapabilityStateV1,
            capability_id,
            capability_id,
            state_version
        ),
        3 => validate!(
            SessionKeyGrantBodyV1,
            SessionKeyGrantStateV1,
            session_key_grant_id,
            session_key_grant_id,
            state_version
        ),
        4 => validate!(TaskOfferBodyV1, TaskStateV1, task_id, task_id, revision),
        5 => validate!(BidBodyV1, BidStateV1, bid_id, bid_id, state_version),
        6 => validate!(
            TaskLeaseBodyV1,
            TaskLeaseStateV1,
            lease_id,
            lease_id,
            revision
        ),
        7 => {
            let decoded_body: EscrowBodyV1 = strict_decode(body)?;
            let decoded_state: EscrowStateV1 = strict_decode(state)?;
            if decoded_body.escrow_id()?.0 != id32
                || decoded_state.escrow_id.0 != id32
                || decoded_state.version != version
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "escrow ID/version mismatch",
                ));
            }
            validate_escrow_conservation(&decoded_body, &decoded_state)?;
        }
        44 => validate!(
            NonceLaneKeyBodyV1,
            NonceLaneStateV1,
            nonce_lane_id,
            nonce_lane_id,
            state_version
        ),
        45 => validate!(
            AccountBodyV1,
            AccountStateV1,
            account_id,
            account_id,
            version
        ),
        47 => {
            let decoded_body: BondBodyV1 = strict_decode(body)?;
            let decoded_state: BondStateV1 = strict_decode(state)?;
            if decoded_body.bond_id()?.0 != id32
                || decoded_state.bond_id.0 != id32
                || decoded_state.version != version
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "bond ID/version mismatch",
                ));
            }
            validate_bond_conservation(config, &decoded_state)?;
        }
        _ => {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "unknown object kind in candidate store",
            ));
        }
    }
    Ok(())
}

fn audit_operations(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT operation_id,sequence,operation_kind,command,receipt,row_checksum FROM agent_market_operations_v1",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let sequence_value = decode_u64(&row.1, "operation sequence")?;
        records.push((sequence_value, row));
    }
    records.sort_by_key(|record| record.0);
    let mut expected_sequence = 1u64;
    let mut previous_order_height = config.trust_bundle.initial_order_height;
    let mut previous_order_block_id = config.trust_bundle.initial_order_block_id;
    for (
        sequence_value,
        (operation_id, sequence, kind, command_bytes, receipt_bytes, actual_checksum),
    ) in records
    {
        if sequence_value != expected_sequence {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "operation journal sequence has a gap/reorder",
            ));
        }
        let expected_checksum = checksum(&[
            &operation_id,
            &sequence,
            &kind.to_le_bytes(),
            &command_bytes,
            &receipt_bytes,
        ]);
        if actual_checksum.as_slice() != expected_checksum.0 {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "operation journal row checksum mismatch",
            ));
        }
        let command: KernelCommandV1 = strict_decode(&command_bytes)?;
        let receipt: KernelTransitionReceiptV1 = strict_decode(&receipt_bytes)?;
        if operation_id.as_slice() != command.operation_id()?.0
            || receipt.schema_version != SCHEMA_VERSION_V1
            || receipt.operation_id != command.operation_id()?
            || receipt.store_id != config.store_id
            || receipt.sequence != sequence_value
            || receipt.operation_kind != kind
            || kind != command.operation_kind()
            || receipt.operation_digest != command.operation_digest()?
            || receipt.order_height < previous_order_height
            || (receipt.order_height == previous_order_height
                && receipt.order_block_id != previous_order_block_id)
            || (receipt.order_height > previous_order_height
                && receipt.order_block_id == previous_order_block_id)
        {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "operation journal command/receipt binding mismatch",
            ));
        }
        previous_order_height = receipt.order_height;
        previous_order_block_id = receipt.order_block_id;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "operation audit sequence overflow",
            )
        })?;
    }
    let metadata_sequence = load_sequence(connection)?;
    if metadata_sequence != expected_sequence - 1 {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata high-watermark differs from operation journal tail",
        ));
    }
    Ok(())
}

fn audit_operation_tail_root(connection: &Connection) -> AgentMarketResultV1<()> {
    let mut statement =
        connection.prepare("SELECT sequence,receipt FROM agent_market_operations_v1")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut tail = None;
    for (sequence, receipt) in rows {
        let sequence = decode_u64(&sequence, "operation-tail sequence")?;
        if tail
            .as_ref()
            .map(|(tail_sequence, _)| sequence > *tail_sequence)
            .unwrap_or(true)
        {
            tail = Some((sequence, receipt));
        }
    }
    if let Some((_, bytes)) = tail {
        let receipt: KernelTransitionReceiptV1 = strict_decode(&bytes)?;
        if receipt.post_state_root != compute_state_root(connection)? {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "current state root differs from durable operation tail",
            ));
        }
    }
    Ok(())
}

fn audit_finalized_block_journal(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
    let mut receipts = BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT sequence,receipt FROM agent_market_operations_v1")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (sequence, receipt) in rows {
        let sequence = decode_u64(&sequence, "block-journal operation sequence")?;
        let receipt: KernelTransitionReceiptV1 = strict_decode(&receipt)?;
        if receipt.sequence != sequence || receipts.insert(sequence, receipt).is_some() {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block journal operation mapping is duplicate",
            ));
        }
    }

    let mut previous = None;
    for (index, marker) in markers.iter().enumerate() {
        if marker.marker_sequence
            != u64::try_from(index).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "finalized-block audit index overflows",
                )
            })?
        {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block marker sequence has a gap or reorder",
            ));
        }
        match previous {
            None => {
                if marker.marker_sequence != 0
                    || marker.order_height != config.trust_bundle.initial_order_height
                    || marker.order_block_id != config.trust_bundle.initial_order_block_id
                    || marker.parent_order_height != marker.order_height
                    || marker.parent_order_block_id != marker.order_block_id
                    || marker.source_operation_sequence != 0
                    || marker.previous_marker_checksum != marker_predecessor_checksum(config)?
                {
                    return Err(error(
                        AgentMarketErrorCodeV1::TamperDetected,
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
                    || marker.previous_marker_checksum != parent.row_checksum
                {
                    return Err(error(
                        AgentMarketErrorCodeV1::TamperDetected,
                        "finalized-block marker is not the exact direct successor",
                    ));
                }
            }
        }
        if marker.target_operation_sequence < marker.source_operation_sequence
            || marker.source_operation_root
                != compute_operation_journal_root_through(
                    connection,
                    marker.source_operation_sequence,
                )?
            || marker.target_operation_root
                != compute_operation_journal_root_through(
                    connection,
                    marker.target_operation_sequence,
                )?
        {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block marker operation roots or range regress",
            ));
        }
        let mut expected_target_state = marker.source_state_root;
        for sequence in
            marker.source_operation_sequence.saturating_add(1)..=marker.target_operation_sequence
        {
            let receipt = receipts.get(&sequence).ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "finalized-block marker operation range has a gap",
                )
            })?;
            if receipt.order_height != marker.order_height
                || receipt.order_block_id != marker.order_block_id
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "operation receipt belongs to a different finalized-block marker",
                ));
            }
            expected_target_state = receipt.post_state_root;
        }
        if marker.target_state_root != expected_target_state {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block marker target state differs from its operation range",
            ));
        }
        previous = Some(*marker);
    }
    let tail = previous.expect("nonempty marker journal was checked");
    let metadata_sequence = load_sequence(connection)?;
    let metadata_state_root = load_durable_state_root(connection)?;
    let metadata_operation_root = load_durable_journal_root(connection)?;
    if load_order_tip(connection)? != (tail.order_height, tail.order_block_id)
        || metadata_sequence != tail.target_operation_sequence
        || metadata_state_root != tail.target_state_root
        || metadata_operation_root != tail.target_operation_root
        || u64::try_from(receipts.len()).ok() != Some(metadata_sequence)
    {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "metadata head differs from finalized-block journal tail",
        ));
    }
    Ok(())
}

fn finalized_block_journal_root(
    connection: &Connection,
    config: &AgentMarketStoreConfigV1,
) -> AgentMarketResultV1<Hash32V1> {
    audit_finalized_block_journal(connection, config)?;
    load_finalized_block_markers(connection, config)?
        .last()
        .map(|marker| marker.row_checksum)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::TamperDetected,
                "finalized-block journal root is absent",
            )
        })
}

fn verify_schema(connection: &Connection) -> AgentMarketResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "agent_market_finalized_blocks_v1".to_owned(),
            FINALIZED_BLOCKS_SQL.to_owned(),
        ),
        ("agent_market_metadata_v1".to_owned(), META_SQL.to_owned()),
        ("agent_market_objects_v1".to_owned(), OBJECTS_SQL.to_owned()),
        (
            "agent_market_operations_v1".to_owned(),
            OPERATIONS_SQL.to_owned(),
        ),
    ];
    if rows != expected {
        return Err(error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "SQLite schema differs from frozen candidate schema v3",
        ));
    }
    let trigger_count: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    if trigger_count != 0 {
        return Err(error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "candidate store forbids SQLite triggers",
        ));
    }
    Ok(())
}

fn open_rw_raw(path: &Path, allow_create: bool) -> AgentMarketResultV1<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if allow_create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    Ok(connection)
}

fn open_ro_raw(path: &Path) -> AgentMarketResultV1<Connection> {
    // Existing stores must be authenticated without causing SQLite to create,
    // replay, checkpoint, or otherwise consult mutable journal state.  The
    // caller rejects WAL/SHM/rollback-journal sidecars before reaching here;
    // immutable mode then guarantees that preflight itself has no write path.
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_encoded_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'.' | b'_' | b'~' => {
                uri.push(char::from(*byte));
            }
            value => {
                use std::fmt::Write as _;
                write!(&mut uri, "%{value:02X}").expect("writing to String cannot fail");
            }
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        Path::new(&uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(connection)
}

fn reject_sidecars(path: &Path) -> AgentMarketResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar_name = path.as_os_str().to_os_string();
        sidecar_name.push(suffix);
        let sidecar = PathBuf::from(sidecar_name);
        if sidecar.exists() {
            return Err(error(
                AgentMarketErrorCodeV1::SidecarPresent,
                format!(
                    "unresolved SQLite sidecar is fail-closed: {}",
                    sidecar.display()
                ),
            ));
        }
    }
    Ok(())
}

fn require_existing_regular_store(path: &Path) -> AgentMarketResultV1<()> {
    let metadata = fs::symlink_metadata(path).map_err(|cause| {
        error(
            AgentMarketErrorCodeV1::StoreFailure,
            format!("existing Agent/Market store is unavailable: {cause}"),
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(error(
            AgentMarketErrorCodeV1::StoreFailure,
            "existing Agent/Market store path must not be a symlink",
        ));
    }
    if !file_type.is_file() {
        return Err(error(
            AgentMarketErrorCodeV1::StoreFailure,
            "existing Agent/Market store path is not a regular file",
        ));
    }
    Ok(())
}

fn decode_u64(bytes: &[u8], label: &str) -> AgentMarketResultV1<u64> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| {
        error(
            AgentMarketErrorCodeV1::TamperDetected,
            format!("{label} is not exactly eight bytes"),
        )
    })?;
    Ok(u64::from_le_bytes(array))
}
