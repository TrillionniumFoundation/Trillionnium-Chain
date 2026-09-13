//! SQLite-backed bounded Verify/Challenge candidate kernel.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use trnm_poco_agent_market_v1::{Hash32V1, ProtocolContextV1};

use crate::{
    codec::{canonical_bytes, checksum, digest_value, strict_decode},
    error::{error, VerifyChallengeErrorCodeV1, VerifyChallengeResultV1},
    *,
};

const STORE_SCHEMA_VERSION_V1: u16 = 3;
const REQUIRED_VERIFIER_COUNT_V1: usize = 4;
const MAX_EVIDENCE_ENTRIES_V1: usize = 64;
const META_SQL: &str = "CREATE TABLE verify_challenge_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, store_id BLOB NOT NULL CHECK(length(store_id)=32), config_hash BLOB NOT NULL CHECK(length(config_hash)=32), sequence BLOB NOT NULL CHECK(length(sequence)=8), order_height BLOB NOT NULL CHECK(length(order_height)=8), order_block_id BLOB NOT NULL CHECK(length(order_block_id)=32), durable_state_root BLOB NOT NULL CHECK(length(durable_state_root)=32), durable_journal_root BLOB NOT NULL CHECK(length(durable_journal_root)=32), fenced INTEGER NOT NULL CHECK(fenced IN(0,1)), state BLOB NOT NULL, row_checksum BLOB NOT NULL CHECK(length(row_checksum)=32))";
const OPERATIONS_SQL: &str = "CREATE TABLE verify_challenge_operations_v1 (operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32), sequence BLOB NOT NULL CHECK(length(sequence)=8), command BLOB NOT NULL, receipt BLOB NOT NULL, row_checksum BLOB NOT NULL CHECK(length(row_checksum)=32)) WITHOUT ROWID";
const FINALIZED_BLOCKS_SQL: &str = "CREATE TABLE verify_challenge_finalized_blocks_v1 (marker_sequence BLOB PRIMARY KEY CHECK(length(marker_sequence)=8), order_height BLOB NOT NULL CHECK(length(order_height)=8), order_block_id BLOB NOT NULL UNIQUE CHECK(length(order_block_id)=32), parent_order_height BLOB NOT NULL CHECK(length(parent_order_height)=8), parent_order_block_id BLOB NOT NULL CHECK(length(parent_order_block_id)=32), source_operation_sequence BLOB NOT NULL CHECK(length(source_operation_sequence)=8), target_operation_sequence BLOB NOT NULL CHECK(length(target_operation_sequence)=8), source_state_root BLOB NOT NULL CHECK(length(source_state_root)=32), target_state_root BLOB NOT NULL CHECK(length(target_state_root)=32), source_operation_root BLOB NOT NULL CHECK(length(source_operation_root)=32), target_operation_root BLOB NOT NULL CHECK(length(target_operation_root)=32), previous_marker_checksum BLOB NOT NULL CHECK(length(previous_marker_checksum)=32), row_checksum BLOB NOT NULL CHECK(length(row_checksum)=32)) WITHOUT ROWID";

#[derive(Clone, Debug)]
pub struct VerifyChallengeStoreConfigV1 {
    pub path: PathBuf,
    pub store_id: Hash32V1,
    pub trust_bundle: VerifyChallengeFreshGenesisTrustBundleV1,
}

impl VerifyChallengeStoreConfigV1 {
    fn config_hash(&self) -> VerifyChallengeResultV1<Hash32V1> {
        digest_value(
            "trnm.poco-ai.verify-challenge-config.candidate.v1",
            &(self.store_id, &self.trust_bundle),
        )
    }
}

#[derive(Debug)]
pub struct ConfirmedVerifyReceiptV1 {
    receipt: VerifyTransitionReceiptV1,
}
impl ConfirmedVerifyReceiptV1 {
    pub const fn receipt(&self) -> &VerifyTransitionReceiptV1 {
        &self.receipt
    }
}

/// Exact local head observed through a fresh authenticated read-only reopen.
///
/// The carrier is intentionally non-`Clone` and has no public constructor. It
/// does not prove global order finality or prevent whole-store rollback.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifyChallengeFreshReadbackV1 {
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
    row_checksum: Hash32V1,
}

/// Immutable candidate execution result used only before an Order Vote.
///
/// Its root is the Verify/Challenge candidate-kernel state root, not the
/// protocol application's normative JMT root.  No durable row is written by
/// this path.
#[derive(Debug)]
pub struct VerifyChallengePreVotePreviewV1 {
    source_sequence: u64,
    source_state_root: Hash32V1,
    source_journal_root: Hash32V1,
    candidate_post_state_root: Hash32V1,
    candidate_receipts: Vec<VerifyTransitionReceiptV1>,
}

impl VerifyChallengePreVotePreviewV1 {
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

    pub fn candidate_receipts(&self) -> &[VerifyTransitionReceiptV1] {
        &self.candidate_receipts
    }
}

impl VerifyChallengeFreshReadbackV1 {
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
pub struct VerifyChallengeExecutionOutcomeV1 {
    confirmed: ConfirmedVerifyReceiptV1,
    replay: bool,
}
impl VerifyChallengeExecutionOutcomeV1 {
    pub const fn receipt(&self) -> &VerifyTransitionReceiptV1 {
        self.confirmed.receipt()
    }
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

#[derive(Clone, Debug)]
pub struct VerifyChallengeStoreV1 {
    config: VerifyChallengeStoreConfigV1,
}

impl VerifyChallengeStoreV1 {
    pub fn open(config: VerifyChallengeStoreConfigV1) -> VerifyChallengeResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        reject_sidecars(&config.path)?;
        if config.path.exists() {
            let connection = open_ro(&config.path)?;
            verify_schema(&connection)?;
            audit(&connection, &config)?;
            if load_metadata(&connection, &config)?.1 {
                return Err(error(
                    VerifyChallengeErrorCodeV1::ThirdStateFenced,
                    "store is permanently fenced",
                ));
            }
        } else {
            if let Some(parent) = config.path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| error(VerifyChallengeErrorCodeV1::StoreFailure, e.to_string()))?;
            }
            let mut connection = open_rw(&config.path, true)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(FINALIZED_BLOCKS_SQL)?;
            transaction.execute_batch(META_SQL)?;
            transaction.execute_batch(OPERATIONS_SQL)?;
            let state = fresh_genesis_state(&config);
            let state_root = state_root(&state)?;
            let journal_root = operation_journal_root(&transaction)?;
            insert_anchor_finalized_block_marker(&transaction, &config, state_root, journal_root)?;
            write_metadata(
                &transaction,
                &config,
                0,
                config.trust_bundle.initial_order_height,
                config.trust_bundle.initial_order_block_id,
                state_root,
                journal_root,
                false,
                &state,
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
    pub fn open_existing(config: VerifyChallengeStoreConfigV1) -> VerifyChallengeResultV1<Self> {
        validate_trust_bundle(&config.trust_bundle)?;
        require_existing_regular_store(&config.path)?;
        reject_sidecars(&config.path)?;
        let connection = open_ro(&config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &config)?;
        if load_metadata(&connection, &config)?.1 {
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
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
        execution: &VerifyOrderFinalizedExecutionContextV1,
        command: &VerifyCommandV1,
    ) -> VerifyChallengeResultV1<VerifyChallengeExecutionOutcomeV1> {
        self.execute_inner(execution, command, None)
    }

    /// Advance one finalized Order block with no Verify/Challenge commands.
    ///
    /// No receipt or state mutation is invented: only the direct-successor
    /// Order tip changes, under the same authenticated SQLite transaction and
    /// mandatory fresh readback used by ordinary transitions.  Re-observing
    /// the exact target is an idempotent recovery outcome.
    pub fn advance_empty_order_finalized_v1(
        &self,
        execution: &VerifyOrderFinalizedExecutionContextV1,
    ) -> VerifyChallengeResultV1<VerifyChallengeFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_context_static(&self.config, execution)?;
        if execution.expected_order_height.checked_add(1) != Some(execution.order_height) {
            return Err(error(
                VerifyChallengeErrorCodeV1::InvalidContext,
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
                VerifyChallengeErrorCodeV1::StaleRevision,
                "empty finalized batch parent differs from durable head",
            ));
        }

        let mut connection = open_rw(&self.config.path, false)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_execution_context_cas(&transaction, execution)?;
        let (sequence, fenced, state) = load_metadata(&transaction, &self.config)?;
        if fenced {
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        advance_finalized_block_marker(
            &transaction,
            &self.config,
            execution,
            sequence,
            sequence,
            before.durable_state_root,
            before.durable_state_root,
            before.durable_journal_root,
            before.durable_journal_root,
        )?;
        write_metadata(
            &transaction,
            &self.config,
            sequence,
            execution.order_height,
            execution.order_block_id,
            before.durable_state_root,
            before.durable_journal_root,
            false,
            &state,
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
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "empty finalized batch readback differs from its exact target",
            ));
        }
        Ok(after)
    }

    /// Execute commands against one authenticated durable parent without
    /// writing the Verify/Challenge SQLite store.
    pub fn preview_before_vote_v1(
        &self,
        expected_parent: &VerifyChallengeFreshReadbackV1,
        candidate_height: u64,
        candidate_block_id: Hash32V1,
        commands: &[VerifyCommandV1],
    ) -> VerifyChallengeResultV1<VerifyChallengePreVotePreviewV1> {
        let before = self.fresh_readback()?;
        if &before != expected_parent
            || candidate_height
                != before.order_height.checked_add(1).ok_or_else(|| {
                    error(
                        VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                        "candidate height overflows",
                    )
                })?
            || candidate_block_id == Hash32V1([0; 32])
            || candidate_block_id == before.order_block_id
        {
            return Err(error(
                VerifyChallengeErrorCodeV1::InvalidContext,
                "pre-vote candidate does not extend the exact fresh parent",
            ));
        }
        reject_sidecars(&self.config.path)?;
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let (sequence, fenced, mut state) = load_metadata(&connection, &self.config)?;
        if fenced {
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        let mut operation_ids = BTreeSet::new();
        let mut receipts = Vec::with_capacity(commands.len());
        for (offset, command) in commands.iter().enumerate() {
            let operation_id = command.operation_id()?;
            if !operation_ids.insert(operation_id)
                || load_receipt(&connection, operation_id)?.is_some()
            {
                return Err(error(
                    VerifyChallengeErrorCodeV1::Conflict,
                    "pre-vote batch repeats a Verify/Challenge operation",
                ));
            }
            apply_command(&self.config, candidate_height, &mut state, command)?;
            let offset = u64::try_from(offset).map_err(|_| {
                error(
                    VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                    "pre-vote operation index exceeds u64",
                )
            })?;
            let next = sequence
                .checked_add(offset)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    error(
                        VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                        "pre-vote sequence overflows",
                    )
                })?;
            receipts.push(VerifyTransitionReceiptV1 {
                schema_version: SCHEMA_VERSION_V1,
                store_id: self.config.store_id,
                sequence: next,
                operation_id,
                operation_kind: command.operation_kind(),
                order_height: candidate_height,
                order_block_id: candidate_block_id,
                post_state_root: state_root(&state)?,
            });
        }
        let candidate_post_state_root = state_root(&state)?;
        drop(connection);
        let after = self.fresh_readback()?;
        if after != before {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "Verify/Challenge source changed during read-only preview",
            ));
        }
        Ok(VerifyChallengePreVotePreviewV1 {
            source_sequence: before.sequence,
            source_state_root: before.durable_state_root,
            source_journal_root: before.durable_journal_root,
            candidate_post_state_root,
            candidate_receipts: receipts,
        })
    }

    #[cfg(test)]
    pub(crate) fn execute(
        &self,
        command: &VerifyCommandV1,
    ) -> VerifyChallengeResultV1<VerifyChallengeExecutionOutcomeV1> {
        let execution = self.current_test_execution_context()?;
        self.execute_inner(&execution, command, None)
    }

    #[cfg(test)]
    pub(crate) fn execute_at_height_for_test(
        &self,
        order_height: u64,
        order_block_id: Hash32V1,
        command: &VerifyCommandV1,
    ) -> VerifyChallengeResultV1<VerifyChallengeExecutionOutcomeV1> {
        let (expected_order_height, expected_order_block_id) = self.current_order_tip()?;
        let execution = VerifyOrderFinalizedExecutionContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.config.trust_bundle.context.clone(),
            expected_order_height,
            expected_order_block_id,
            order_height,
            order_block_id,
        };
        self.execute_inner(&execution, command, None)
    }

    #[cfg(test)]
    pub(crate) fn execute_with_fault(
        &self,
        command: &VerifyCommandV1,
        fault: VerifyCommitFaultV1,
    ) -> VerifyChallengeResultV1<VerifyChallengeExecutionOutcomeV1> {
        let execution = self.current_test_execution_context()?;
        self.execute_inner(&execution, command, Some(fault))
    }

    fn execute_inner(
        &self,
        execution: &VerifyOrderFinalizedExecutionContextV1,
        command: &VerifyCommandV1,
        fault: Option<VerifyCommitFaultV1>,
    ) -> VerifyChallengeResultV1<VerifyChallengeExecutionOutcomeV1> {
        reject_sidecars(&self.config.path)?;
        validate_execution_context_static(&self.config, execution)?;
        let read_only = open_ro(&self.config.path)?;
        verify_schema(&read_only)?;
        audit(&read_only, &self.config)?;
        drop(read_only);
        let mut connection = open_rw(&self.config.path, false)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let operation_id = command.operation_id()?;
        if let Some(receipt) = load_receipt(&connection, operation_id)? {
            if (receipt.order_height, receipt.order_block_id)
                != (execution.order_height, execution.order_block_id)
                || load_order_tip(&connection)?
                    != (execution.order_height, execution.order_block_id)
            {
                return Err(error(
                    VerifyChallengeErrorCodeV1::StaleRevision,
                    "exact replay target differs from the durable order tip",
                ));
            }
            return Ok(VerifyChallengeExecutionOutcomeV1 {
                confirmed: ConfirmedVerifyReceiptV1 { receipt },
                replay: true,
            });
        }
        validate_execution_context_cas(&connection, execution)?;
        if matches!(fault, Some(VerifyCommitFaultV1::NotAppliedAckLost)) {
            return Err(error(
                VerifyChallengeErrorCodeV1::CommitUncertain,
                "transaction not applied before acknowledgement loss",
            ));
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_execution_context_cas(&transaction, execution)?;
        let (sequence, fenced, mut state) = load_metadata(&transaction, &self.config)?;
        if fenced {
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        let source_state_root = state_root(&state)?;
        let source_journal_root = operation_journal_root(&transaction)?;
        if matches!(fault, Some(VerifyCommitFaultV1::ThirdState)) {
            write_metadata(
                &transaction,
                &self.config,
                sequence,
                execution.expected_order_height,
                execution.expected_order_block_id,
                source_state_root,
                source_journal_root,
                true,
                &state,
            )?;
            transaction.commit()?;
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "commit resolved to neither source nor target",
            ));
        }
        apply_command(&self.config, execution.order_height, &mut state, command)?;
        let next = sequence.checked_add(1).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "sequence overflow",
            )
        })?;
        let receipt = VerifyTransitionReceiptV1 {
            schema_version: SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence: next,
            operation_id,
            operation_kind: command.operation_kind(),
            order_height: execution.order_height,
            order_block_id: execution.order_block_id,
            post_state_root: state_root(&state)?,
        };
        insert_operation(&transaction, next, command, &receipt)?;
        let journal_root = operation_journal_root(&transaction)?;
        advance_finalized_block_marker(
            &transaction,
            &self.config,
            execution,
            sequence,
            next,
            source_state_root,
            receipt.post_state_root,
            source_journal_root,
            journal_root,
        )?;
        write_metadata(
            &transaction,
            &self.config,
            next,
            execution.order_height,
            execution.order_block_id,
            receipt.post_state_root,
            journal_root,
            false,
            &state,
        )?;
        transaction.commit()?;
        drop(connection);
        if matches!(fault, Some(VerifyCommitFaultV1::AppliedAckLost)) {
            return Err(error(
                VerifyChallengeErrorCodeV1::CommitUncertain,
                "transaction applied before acknowledgement loss",
            ));
        }
        let confirmed = self.fresh_confirm_receipt(&receipt)?;
        Ok(VerifyChallengeExecutionOutcomeV1 {
            confirmed,
            replay: false,
        })
    }

    pub fn fresh_confirm_receipt(
        &self,
        expected: &VerifyTransitionReceiptV1,
    ) -> VerifyChallengeResultV1<ConfirmedVerifyReceiptV1> {
        if expected.store_id != self.config.store_id {
            return Err(error(
                VerifyChallengeErrorCodeV1::Unauthorized,
                "receipt belongs to another store",
            ));
        }
        reject_sidecars(&self.config.path)?;
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let actual = load_receipt(&connection, expected.operation_id)?
            .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "receipt absent"))?;
        if &actual != expected {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "receipt differs from durable row",
            ));
        }
        Ok(ConfirmedVerifyReceiptV1 { receipt: actual })
    }

    /// Reopen and authenticate the current durable store head.
    pub fn fresh_readback(&self) -> VerifyChallengeResultV1<VerifyChallengeFreshReadbackV1> {
        reject_sidecars(&self.config.path)?;
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        let (sequence, fenced, state) = load_metadata(&connection, &self.config)?;
        if fenced {
            return Err(error(
                VerifyChallengeErrorCodeV1::ThirdStateFenced,
                "store is permanently fenced",
            ));
        }
        let (order_height, order_block_id) = load_order_tip(&connection)?;
        Ok(VerifyChallengeFreshReadbackV1 {
            context: self.config.trust_bundle.context.clone(),
            store_schema_version: STORE_SCHEMA_VERSION_V1,
            store_id: self.config.store_id,
            sequence,
            order_height,
            order_block_id,
            durable_state_root: state_root(&state)?,
            durable_journal_root: operation_journal_root(&connection)?,
            durable_finalized_block_root: finalized_block_journal_root(&connection, &self.config)?,
        })
    }

    pub fn state(&self) -> VerifyChallengeResultV1<VerifyKernelStateV1> {
        reject_sidecars(&self.config.path)?;
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        Ok(load_metadata(&connection, &self.config)?.2)
    }

    #[cfg(test)]
    fn current_test_execution_context(
        &self,
    ) -> VerifyChallengeResultV1<VerifyOrderFinalizedExecutionContextV1> {
        let (height, block_id) = self.current_order_tip()?;
        Ok(VerifyOrderFinalizedExecutionContextV1 {
            schema_version: SCHEMA_VERSION_V1,
            context: self.config.trust_bundle.context.clone(),
            expected_order_height: height,
            expected_order_block_id: block_id,
            order_height: height,
            order_block_id: block_id,
        })
    }

    #[cfg(test)]
    fn current_order_tip(&self) -> VerifyChallengeResultV1<(u64, Hash32V1)> {
        reject_sidecars(&self.config.path)?;
        let connection = open_ro(&self.config.path)?;
        verify_schema(&connection)?;
        audit(&connection, &self.config)?;
        load_order_tip(&connection)
    }
}

fn validate_trust_bundle(
    bundle: &VerifyChallengeFreshGenesisTrustBundleV1,
) -> VerifyChallengeResultV1<()> {
    if bundle.schema_version != 1
        || bundle.context.protocol_version != 1
        || bundle.context.chain_id.is_empty()
        || bundle.initial_order_height == 0
        || bundle.initial_order_block_id == Hash32V1([0; 32])
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidContext,
            "invalid trust context",
        ));
    }
    if bundle.provider.agent_id == bundle.challenger.agent_id
        || bundle.provider.agent_id.0 == [0; 32]
        || bundle.challenger.agent_id.0 == [0; 32]
        || bundle.provider.key_id.0 == [0; 32]
        || bundle.challenger.key_id.0 == [0; 32]
        || bundle.verifiers.len() != REQUIRED_VERIFIER_COUNT_V1
        || bundle.profile.threshold_weight == 0
        || bundle.profile.minimum_unique_signers == 0
        || bundle.profile.minimum_challenge_blocks == 0
        || bundle.profile.challenge_bond_amount == 0
        || bundle.profile.challenge_bond_amount > bundle.challenge_bond_funding
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidBounds,
            "invalid bounded actors/profile/bond",
        ));
    }
    if bundle
        .verifiers
        .windows(2)
        .any(|window| window[0].verifier_id >= window[1].verifier_id)
        || bundle
            .verifiers
            .iter()
            .any(|v| v.weight == 0 || v.verifier_id == [0; 32] || v.key_id == [0; 32])
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::NonCanonical,
            "verifiers must be strictly sorted, unique, positive-weight",
        ));
    }
    let total = bundle.verifiers.iter().try_fold(0u128, |sum, verifier| {
        sum.checked_add(verifier.weight).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "verifier weight overflow",
            )
        })
    })?;
    if bundle.profile.threshold_weight > total
        || usize::try_from(bundle.profile.minimum_unique_signers).unwrap_or(usize::MAX)
            > bundle.verifiers.len()
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidBounds,
            "quorum exceeds verifier set",
        ));
    }
    let mut key_ids = vec![bundle.provider.key_id.0, bundle.challenger.key_id.0];
    let mut public_keys = vec![bundle.provider.public_key, bundle.challenger.public_key];
    key_ids.extend(bundle.verifiers.iter().map(|verifier| verifier.key_id));
    public_keys.extend(bundle.verifiers.iter().map(|verifier| verifier.public_key));
    if !all_unique(&key_ids)
        || !all_unique(&public_keys)
        || bundle.profile.verifier_set_hash
            != digest_value("trnm.poco-ai.verifier-set.candidate.v1", &bundle.verifiers)?
        || bundle.profile.profile_hash != expected_profile_hash(&bundle.profile)?
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::NonCanonical,
            "duplicate trust key or non-canonical committed verifier/profile hash",
        ));
    }
    for key in [bundle.provider.public_key, bundle.challenger.public_key] {
        VerifyingKey::from_bytes(&key).map_err(|_| {
            error(
                VerifyChallengeErrorCodeV1::InvalidSignature,
                "invalid actor key",
            )
        })?;
    }
    for verifier in &bundle.verifiers {
        VerifyingKey::from_bytes(&verifier.public_key).map_err(|_| {
            error(
                VerifyChallengeErrorCodeV1::InvalidSignature,
                "invalid verifier key",
            )
        })?;
    }
    Ok(())
}

fn all_unique(values: &[[u8; 32]]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn expected_profile_hash(profile: &StakeQuorumProfileV1) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.stake-quorum-profile.candidate.v1",
        &(
            &profile.profile_id,
            profile.profile_version,
            profile.verifier_set_hash,
            profile.threshold_weight,
            profile.minimum_unique_signers,
            profile.minimum_challenge_blocks,
            profile.required_da_policy_hash,
            profile.challenge_policy_hash,
            profile.settlement_policy_hash,
            profile.challenge_bond_asset_id,
            profile.challenge_bond_amount,
        ),
    )
}

fn validate_execution_context_static(
    config: &VerifyChallengeStoreConfigV1,
    execution: &VerifyOrderFinalizedExecutionContextV1,
) -> VerifyChallengeResultV1<()> {
    if execution.schema_version != SCHEMA_VERSION_V1
        || execution.context != config.trust_bundle.context
        || execution.order_height < execution.expected_order_height
        || execution.expected_order_block_id == Hash32V1([0; 32])
        || execution.order_block_id == Hash32V1([0; 32])
        || (execution.order_height == execution.expected_order_height
            && execution.order_block_id != execution.expected_order_block_id)
        || (execution.order_height > execution.expected_order_height
            && execution.order_block_id == execution.expected_order_block_id)
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidContext,
            "order-finalized execution context is malformed or non-monotonic",
        ));
    }
    Ok(())
}

fn validate_execution_context_cas(
    connection: &Connection,
    execution: &VerifyOrderFinalizedExecutionContextV1,
) -> VerifyChallengeResultV1<()> {
    let (height, block_id) = load_order_tip(connection)?;
    if height != execution.expected_order_height || block_id != execution.expected_order_block_id {
        return Err(error(
            VerifyChallengeErrorCodeV1::StaleRevision,
            "order-finalized execution context does not match durable tip",
        ));
    }
    Ok(())
}

fn apply_command(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    command: &VerifyCommandV1,
) -> VerifyChallengeResultV1<()> {
    match command {
        VerifyCommandV1::AdmitReceipt { receipt } => {
            apply_receipt(config, execution_height, state, receipt)
        }
        VerifyCommandV1::Evaluate {
            result_id,
            expected_result_revision,
            decision_round,
            accepted_claims,
            decision,
            decision_nonce,
        } => apply_evaluation(
            config,
            execution_height,
            state,
            *result_id,
            *expected_result_revision,
            *decision_round,
            accepted_claims,
            *decision,
            *decision_nonce,
        ),
        VerifyCommandV1::OpenChallenge {
            expected_result_revision,
            body,
            authorization,
        } => apply_open(
            config,
            execution_height,
            state,
            *expected_result_revision,
            body,
            authorization,
        ),
        VerifyCommandV1::AddEvidence {
            challenge_id,
            expected_challenge_revision,
            expected_result_revision,
            evidence_artifact_id,
            availability_certificate_id,
            authorization,
        } => apply_evidence(
            config,
            execution_height,
            state,
            *challenge_id,
            *expected_challenge_revision,
            *expected_result_revision,
            *evidence_artifact_id,
            *availability_certificate_id,
            authorization,
        ),
        VerifyCommandV1::Respond {
            challenge_id,
            expected_challenge_revision,
            expected_result_revision,
            response_statement_digest,
            authorization,
        } => apply_response(
            config,
            execution_height,
            state,
            *challenge_id,
            *expected_challenge_revision,
            *expected_result_revision,
            *response_statement_digest,
            authorization,
        ),
        VerifyCommandV1::Adjudicate {
            challenge_id,
            expected_challenge_revision,
            expected_result_revision,
            decision_round,
            accepted_claims,
            decision,
            decision_nonce,
        } => apply_adjudication(
            config,
            execution_height,
            state,
            *challenge_id,
            *expected_challenge_revision,
            *expected_result_revision,
            *decision_round,
            accepted_claims,
            *decision,
            *decision_nonce,
        ),
    }
}

fn verify_signature(
    public_key: [u8; 32],
    domain: &str,
    value: &impl borsh::BorshSerialize,
    signature: &[u8],
) -> VerifyChallengeResultV1<()> {
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::InvalidSignature,
            "invalid committed key",
        )
    })?;
    let signature = Signature::from_slice(signature).map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::InvalidSignature,
            "strict Ed25519 signature must be 64 bytes",
        )
    })?;
    let root = digest_value(domain, value)?;
    key.verify_strict(&root.0, &signature).map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::InvalidSignature,
            "strict Ed25519 verification failed",
        )
    })
}

fn apply_receipt(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    signed: &SignedExecutionReceiptV1,
) -> VerifyChallengeResultV1<()> {
    let body = &signed.body;
    if signed.receipt_id != body.receipt_id()? {
        return Err(error(
            VerifyChallengeErrorCodeV1::IdentifierMismatch,
            "receipt ID mismatch",
        ));
    }
    if body.schema_version != 1
        || body.context != config.trust_bundle.context
        || body.task_id != config.trust_bundle.task_id
        || body.task_revision != config.trust_bundle.task_revision
        || body.lease_id != config.trust_bundle.lease_id
        || body.attempt != config.trust_bundle.attempt
        || body.provider_agent_id != config.trust_bundle.provider.agent_id
        || body.provider_key_id != config.trust_bundle.provider.key_id
        || body.execution_environment_hash != config.trust_bundle.execution_environment_hash
        || body.verification_profile_id != config.trust_bundle.profile.profile_id
        || body.verification_profile_version != config.trust_bundle.profile.profile_version
        || body.verification_profile_hash != config.trust_bundle.profile.profile_hash
        || body.submitted_height_upper_bound < execution_height
        || body.execution_outcome > 2
        || (body.execution_outcome == 0) == body.failure_code.is_some()
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidReceipt,
            "receipt does not bind exact active lease/profile/outcome",
        ));
    }
    verify_signature(
        config.trust_bundle.provider.public_key,
        "trnm.poco-ai.execution-receipt-signature.v1",
        &signed.receipt_id,
        &signed.signature,
    )?;
    if let Some(existing) = &state.receipt {
        if existing == signed {
            return Ok(());
        }
        return Err(error(
            VerifyChallengeErrorCodeV1::Conflict,
            "one lease/attempt already has a different canonical receipt",
        ));
    }
    let result_id: ResultIdV1 = digest_value(
        "trnm.poco-ai.result.v1",
        &(
            signed.receipt_id,
            body.execution_outcome,
            body.output_commitment,
            config.trust_bundle.profile.profile_hash,
            config.trust_bundle.profile.required_da_policy_hash,
            config.trust_bundle.profile.challenge_policy_hash,
            config.trust_bundle.profile.settlement_policy_hash,
        ),
    )?
    .into();
    state.receipt = Some(signed.clone());
    state.result = Some(ResultStateV1 {
        result_id,
        execution_receipt_id: signed.receipt_id,
        revision: 0,
        status: 0,
        accepted_height: execution_height,
        challenge_close_height: None,
        verification_statement_digest: None,
        verification_evidence_root: None,
        required_da_policy_hash: config.trust_bundle.profile.required_da_policy_hash,
        transition_history: Vec::new(),
        challenge_id: None,
        open_challenge_count: 0,
    });
    Ok(())
}

fn verify_claims(
    config: &VerifyChallengeStoreConfigV1,
    result_id: ResultIdV1,
    receipt_id: ExecutionReceiptIdV1,
    round: u32,
    claims: &[SignedVerificationClaimV1],
    required_verdict: u8,
    expected_evidence_root: Hash32V1,
) -> VerifyChallengeResultV1<VerifiedClaimSetV1> {
    if claims.is_empty() {
        return Err(error(
            VerifyChallengeErrorCodeV1::UnderQuorum,
            "empty claim set",
        ));
    }
    let claim_sequence = u64::from(round);
    let expected_statement = expected_claim_statement(
        config,
        result_id,
        receipt_id,
        round,
        required_verdict,
        expected_evidence_root,
        claim_sequence,
    )?;
    let mut weight = 0u128;
    let mut ids = Vec::with_capacity(claims.len());
    let mut previous_identity: Option<([u8; 32], [u8; 32])> = None;
    for claim in claims {
        if claim.claim_id != claim.body.claim_id()?
            || claim.body.schema_version != 1
            || claim.body.context != config.trust_bundle.context
            || claim.body.result_id != result_id
            || claim.body.execution_receipt_id != receipt_id
            || claim.body.verification_profile_id != config.trust_bundle.profile.profile_id
            || claim.body.verification_profile_version
                != config.trust_bundle.profile.profile_version
            || claim.body.verification_profile_hash != config.trust_bundle.profile.profile_hash
            || claim.body.decision_round != round
            || claim.body.verdict != required_verdict
            || claim.body.statement_digest != expected_statement
            || claim.body.evidence_root != expected_evidence_root
            || claim.body.claim_sequence != claim_sequence
        {
            return Err(error(
                VerifyChallengeErrorCodeV1::InvalidClaim,
                "claim does not bind exact result/receipt/profile/round/verdict/evidence/sequence",
            ));
        }
        let identity = (claim.body.verifier_id, claim.body.verifier_key_id);
        if previous_identity.is_some_and(|previous| previous >= identity) {
            return Err(error(
                VerifyChallengeErrorCodeV1::NonCanonical,
                "claim verifier identities must be strictly sorted and unique",
            ));
        }
        previous_identity = Some(identity);
        let verifier = config
            .trust_bundle
            .verifiers
            .iter()
            .find(|v| {
                v.verifier_id == claim.body.verifier_id && v.key_id == claim.body.verifier_key_id
            })
            .ok_or_else(|| {
                error(
                    VerifyChallengeErrorCodeV1::Unauthorized,
                    "verifier absent from committed set",
                )
            })?;
        verify_signature(
            verifier.public_key,
            "trnm.poco-ai.verification-claim-signature.v1",
            &claim.claim_id,
            &claim.signature,
        )?;
        ids.push(claim.claim_id);
        weight = weight.checked_add(verifier.weight).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "claim weight overflow",
            )
        })?;
    }
    if weight < config.trust_bundle.profile.threshold_weight
        || claims.len()
            < usize::try_from(config.trust_bundle.profile.minimum_unique_signers)
                .unwrap_or(usize::MAX)
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::UnderQuorum,
            "verified unique signer weight below threshold",
        ));
    }
    Ok(VerifiedClaimSetV1 {
        weight,
        ids,
        statement_digest: expected_statement,
        evidence_root: expected_evidence_root,
        claim_sequence,
    })
}

struct VerifiedClaimSetV1 {
    weight: u128,
    ids: Vec<VerificationClaimIdV1>,
    statement_digest: Hash32V1,
    evidence_root: Hash32V1,
    claim_sequence: u64,
}

fn expected_claim_statement(
    config: &VerifyChallengeStoreConfigV1,
    result_id: ResultIdV1,
    receipt_id: ExecutionReceiptIdV1,
    round: u32,
    verdict: u8,
    evidence_root: Hash32V1,
    claim_sequence: u64,
) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.verification-claim-statement.candidate.v1",
        &(
            result_id,
            receipt_id,
            config.trust_bundle.profile.profile_hash,
            config.trust_bundle.profile.required_da_policy_hash,
            config.trust_bundle.profile.challenge_policy_hash,
            round,
            verdict,
            evidence_root,
            claim_sequence,
        ),
    )
}

fn evaluation_evidence_root(
    receipt: &SignedExecutionReceiptV1,
) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.evaluation-evidence-root.candidate.v1",
        &(
            receipt.receipt_id,
            receipt.body.output_commitment,
            receipt.body.meter_root,
            receipt.body.execution_environment_hash,
            receipt.body.verification_profile_hash,
        ),
    )
}

fn adjudication_evidence_root(
    config: &VerifyChallengeStoreConfigV1,
    challenge: &ChallengeStateV1,
) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.adjudication-evidence-root.candidate.v1",
        &(
            challenge.challenge_id,
            challenge.result_id,
            &challenge.evidence_entries,
            &challenge.response_statements,
            challenge.last_transition_hash,
            config.trust_bundle.profile.challenge_policy_hash,
        ),
    )
}

fn transition_hash(
    label: &str,
    result: &ResultStateV1,
    next_revision: u64,
    next_status: u8,
    authorizer: Hash32V1,
    height: u64,
) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        label,
        &(
            result.result_id,
            result.revision,
            next_revision,
            result.status,
            next_status,
            authorizer,
            height,
            result.transition_history.last().copied(),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_evaluation(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    result_id: ResultIdV1,
    expected: u64,
    round: u32,
    claims: &[SignedVerificationClaimV1],
    decision: u8,
    nonce: Hash32V1,
) -> VerifyChallengeResultV1<()> {
    if decision > 2 {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidBounds,
            "unknown evaluation decision",
        ));
    }
    let evidence_root = evaluation_evidence_root(
        state
            .receipt
            .as_ref()
            .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "receipt absent"))?,
    )?;
    let result = state
        .result
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "result absent"))?;
    if result.result_id != result_id || result.revision != expected || result.status != 0 {
        return Err(error(
            VerifyChallengeErrorCodeV1::StaleRevision,
            "evaluation requires exact Submitted revision",
        ));
    }
    let verdict = decision;
    let verified = verify_claims(
        config,
        result_id,
        result.execution_receipt_id,
        round,
        claims,
        verdict,
        evidence_root,
    )?;
    let decision_id: VerificationDecisionIdV1 = digest_value(
        "trnm.poco-ai.verification-decision.v1",
        &(
            result_id,
            expected,
            round,
            verified.weight,
            &verified.ids,
            verified.statement_digest,
            verified.evidence_root,
            verified.claim_sequence,
            decision,
            nonce,
        ),
    )?
    .into();
    let begin_revision = expected.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "evaluation begin revision overflow",
        )
    })?;
    let decision_revision = expected.checked_add(2).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "evaluation decision revision overflow",
        )
    })?;
    let begin = transition_hash(
        "trnm.poco-ai.result-transition-begin-evaluation.candidate.v1",
        result,
        begin_revision,
        1,
        Hash32V1(result.execution_receipt_id.0),
        execution_height,
    )?;
    result.transition_history.push(begin);
    result.revision = begin_revision;
    result.status = 1;
    let next_status = match decision {
        0 => 2,
        1 => 5,
        2 => 6,
        _ => unreachable!(),
    };
    let decision_hash = transition_hash(
        "trnm.poco-ai.result-transition-evaluation-decision.candidate.v1",
        result,
        decision_revision,
        next_status,
        Hash32V1(decision_id.0),
        execution_height,
    )?;
    result.transition_history.push(decision_hash);
    result.revision = decision_revision;
    result.status = next_status;
    result.verification_statement_digest = Some(verified.statement_digest);
    result.verification_evidence_root = Some(verified.evidence_root);
    result.challenge_close_height = if next_status == 2 {
        Some(
            execution_height
                .checked_add(config.trust_bundle.profile.minimum_challenge_blocks)
                .ok_or_else(|| {
                    error(
                        VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                        "challenge close overflow",
                    )
                })?,
        )
    } else {
        Some(execution_height)
    };
    Ok(())
}

fn verify_actor(
    _config: &VerifyChallengeStoreConfigV1,
    expected: &RegisteredActorV1,
    domain: &str,
    action: &impl borsh::BorshSerialize,
    authorization: &ActorAuthorizationV1,
) -> VerifyChallengeResultV1<()> {
    let digest = digest_value(domain, action)?;
    if authorization.actor_agent_id != expected.agent_id
        || authorization.actor_key_id != expected.key_id
        || authorization.action_digest != digest
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::Unauthorized,
            "actor authorization does not bind exact actor/action",
        ));
    }
    verify_signature(
        expected.public_key,
        domain,
        &authorization.action_digest,
        &authorization.signature,
    )
}

fn check_bond(state: &VerifyKernelStateV1) -> VerifyChallengeResultV1<()> {
    let bond = &state.bond;
    let total = bond
        .available
        .checked_add(bond.held)
        .and_then(|v| v.checked_add(bond.released))
        .and_then(|v| v.checked_add(bond.slashed))
        .ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "bond total overflow",
            )
        })?;
    if total != bond.funded {
        return Err(error(
            VerifyChallengeErrorCodeV1::ConservationViolation,
            "challenge bond conservation failed",
        ));
    }
    Ok(())
}

fn apply_open(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    expected: u64,
    body: &ChallengeOpenBodyV1,
    authorization: &ActorAuthorizationV1,
) -> VerifyChallengeResultV1<()> {
    let result = state
        .result
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "result absent"))?;
    if result.result_id != body.result_id
        || result.execution_receipt_id != body.execution_receipt_id
        || result.revision != expected
        || result.status != 2
        || state.challenge.is_some()
        || result.challenge_id.is_some()
        || result.challenge_close_height.is_none()
        || execution_height > result.challenge_close_height.unwrap()
        || body.schema_version != 1
        || body.context != config.trust_bundle.context
        || body.challenger_agent_id != config.trust_bundle.challenger.agent_id
        || body.challenger_key_id != config.trust_bundle.challenger.key_id
        || body.challenged_statement_digest
            != result.verification_statement_digest.unwrap_or_default()
        || result.verification_evidence_root.is_none()
        || result.required_da_policy_hash != config.trust_bundle.profile.required_da_policy_hash
        || body.challenge_bond_id != config.trust_bundle.challenge_bond_id
        || body.challenge_bond_asset_id != config.trust_bundle.profile.challenge_bond_asset_id
        || body.challenge_bond_amount != config.trust_bundle.profile.challenge_bond_amount
        || !(execution_height <= body.evidence_deadline_height
            && body.evidence_deadline_height <= body.response_deadline_height
            && body.response_deadline_height <= body.decision_deadline_height)
        || state.bond.available < body.challenge_bond_amount
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidState,
            "challenge opening preconditions mismatch",
        ));
    }
    verify_actor(
        config,
        &config.trust_bundle.challenger,
        "trnm.poco-ai.challenge-signature.v1",
        body,
        authorization,
    )?;
    let challenge_id = body.challenge_id()?;
    state.bond.available = state
        .bond
        .available
        .checked_sub(body.challenge_bond_amount)
        .ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ConservationViolation,
                "challenge bond available underflow",
            )
        })?;
    state.bond.held = state
        .bond
        .held
        .checked_add(body.challenge_bond_amount)
        .ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "challenge bond held overflow",
            )
        })?;
    state.bond.version = state.bond.version.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "challenge bond version overflow",
        )
    })?;
    let next_result_revision = result.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "challenge-open result revision overflow",
        )
    })?;
    let transition = transition_hash(
        "trnm.poco-ai.result-transition-challenge-opened.candidate.v1",
        result,
        next_result_revision,
        3,
        Hash32V1(challenge_id.0),
        execution_height,
    )?;
    result.transition_history.push(transition);
    result.revision = next_result_revision;
    result.status = 3;
    result.challenge_id = Some(challenge_id);
    result.open_challenge_count = 1;
    state.challenge = Some(ChallengeStateV1 {
        challenge_id,
        result_id: body.result_id,
        revision: 0,
        status: 0,
        opened_height: execution_height,
        evidence_deadline_height: body.evidence_deadline_height,
        response_deadline_height: body.response_deadline_height,
        decision_deadline_height: body.decision_deadline_height,
        evidence_entries: Vec::new(),
        response_statements: Vec::new(),
        decision_claim_ids: Vec::new(),
        last_transition_hash: digest_value(
            "trnm.poco-ai.challenge-open-transition.candidate.v1",
            &(challenge_id, transition),
        )?,
        terminal_height: None,
    });
    check_bond(state)
}

#[allow(clippy::too_many_arguments)]
fn apply_evidence(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    challenge_id: ChallengeIdV1,
    expected_challenge: u64,
    expected_result: u64,
    artifact: Hash32V1,
    certificate: Hash32V1,
    authorization: &ActorAuthorizationV1,
) -> VerifyChallengeResultV1<()> {
    let action = (
        challenge_id,
        expected_challenge,
        expected_result,
        artifact,
        certificate,
    );
    verify_actor(
        config,
        &config.trust_bundle.challenger,
        "trnm.poco-ai.challenge-add-evidence-signature.candidate.v1",
        &action,
        authorization,
    )?;
    let result = state
        .result
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "result absent"))?;
    let challenge = state
        .challenge
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "challenge absent"))?;
    if challenge.challenge_id != challenge_id
        || challenge.revision != expected_challenge
        || !matches!(challenge.status, 0 | 1)
        || result.revision != expected_result
        || result.status != 3
        || execution_height > challenge.evidence_deadline_height
        || artifact == Hash32V1([0; 32])
        || certificate == Hash32V1([0; 32])
        || challenge.evidence_entries.len() >= MAX_EVIDENCE_ENTRIES_V1
        || challenge
            .evidence_entries
            .last()
            .is_some_and(|last| *last >= (artifact, certificate))
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidState,
            "evidence action preconditions/canonical order mismatch",
        ));
    }
    let next_challenge_revision = challenge.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "evidence challenge revision overflow",
        )
    })?;
    let next_result_revision = result.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "evidence result revision overflow",
        )
    })?;
    challenge.evidence_entries.push((artifact, certificate));
    challenge.revision = next_challenge_revision;
    challenge.status = 1;
    challenge.last_transition_hash = digest_value(
        "trnm.poco-ai.challenge-evidence-transition.candidate.v1",
        &(
            challenge.last_transition_hash,
            &challenge.evidence_entries,
            challenge.revision,
        ),
    )?;
    result.revision = next_result_revision;
    result.transition_history.push(digest_value(
        "trnm.poco-ai.result-transition-challenge-updated.candidate.v1",
        &(
            result.result_id,
            result.revision,
            challenge.last_transition_hash,
        ),
    )?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_response(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    challenge_id: ChallengeIdV1,
    expected_challenge: u64,
    expected_result: u64,
    statement: Hash32V1,
    authorization: &ActorAuthorizationV1,
) -> VerifyChallengeResultV1<()> {
    let action = (challenge_id, expected_challenge, expected_result, statement);
    verify_actor(
        config,
        &config.trust_bundle.provider,
        "trnm.poco-ai.challenge-response-signature.candidate.v1",
        &action,
        authorization,
    )?;
    let result = state
        .result
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "result absent"))?;
    let challenge = state
        .challenge
        .as_mut()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "challenge absent"))?;
    if challenge.challenge_id != challenge_id
        || challenge.revision != expected_challenge
        || challenge.status != 1
        || challenge.evidence_entries.is_empty()
        || result.revision != expected_result
        || result.status != 3
        || execution_height > challenge.response_deadline_height
        || statement == Hash32V1([0; 32])
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidState,
            "response preconditions mismatch",
        ));
    }
    let next_challenge_revision = challenge.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "response challenge revision overflow",
        )
    })?;
    let next_result_revision = result.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "response result revision overflow",
        )
    })?;
    challenge.response_statements.push(statement);
    challenge.revision = next_challenge_revision;
    challenge.status = 2;
    challenge.last_transition_hash = digest_value(
        "trnm.poco-ai.challenge-response-transition.candidate.v1",
        &(
            challenge.last_transition_hash,
            &challenge.response_statements,
            challenge.revision,
        ),
    )?;
    result.revision = next_result_revision;
    result.transition_history.push(digest_value(
        "trnm.poco-ai.result-transition-challenge-updated.candidate.v1",
        &(
            result.result_id,
            result.revision,
            challenge.last_transition_hash,
        ),
    )?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_adjudication(
    config: &VerifyChallengeStoreConfigV1,
    execution_height: u64,
    state: &mut VerifyKernelStateV1,
    challenge_id: ChallengeIdV1,
    expected_challenge: u64,
    expected_result: u64,
    round: u32,
    claims: &[SignedVerificationClaimV1],
    decision: u8,
    nonce: Hash32V1,
) -> VerifyChallengeResultV1<()> {
    if decision > 1 {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidBounds,
            "unknown adjudication decision",
        ));
    }
    let result_snapshot = state
        .result
        .as_ref()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "result absent"))?
        .clone();
    let challenge_snapshot = state
        .challenge
        .as_ref()
        .ok_or_else(|| error(VerifyChallengeErrorCodeV1::NotFound, "challenge absent"))?
        .clone();
    if challenge_snapshot.challenge_id != challenge_id
        || challenge_snapshot.revision != expected_challenge
        || challenge_snapshot.status != 2
        || result_snapshot.revision != expected_result
        || result_snapshot.status != 3
        || execution_height > challenge_snapshot.decision_deadline_height
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::InvalidState,
            "adjudication preconditions mismatch",
        ));
    }
    let required_verdict = if decision == 0 { 1 } else { 0 };
    let evidence_root = adjudication_evidence_root(config, &challenge_snapshot)?;
    let verified = verify_claims(
        config,
        result_snapshot.result_id,
        result_snapshot.execution_receipt_id,
        round,
        claims,
        required_verdict,
        evidence_root,
    )?;
    let authority = digest_value(
        "trnm.poco-ai.challenge-decision.candidate.v1",
        &(
            challenge_id,
            round,
            verified.weight,
            &verified.ids,
            verified.statement_digest,
            verified.evidence_root,
            verified.claim_sequence,
            decision,
            nonce,
        ),
    )?;
    let result = state.result.as_mut().expect("checked");
    let challenge = state.challenge.as_mut().expect("checked");
    let next_challenge_revision = challenge.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "adjudication challenge revision overflow",
        )
    })?;
    let next_result_revision = result.revision.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "adjudication result revision overflow",
        )
    })?;
    challenge.decision_claim_ids = verified.ids;
    challenge.revision = next_challenge_revision;
    challenge.status = if decision == 0 { 3 } else { 4 };
    challenge.terminal_height = Some(execution_height);
    challenge.last_transition_hash = digest_value(
        "trnm.poco-ai.challenge-decision-transition.candidate.v1",
        &(
            challenge.last_transition_hash,
            authority,
            challenge.revision,
            challenge.status,
        ),
    )?;
    result.revision = next_result_revision;
    result.status = if decision == 0 { 5 } else { 2 };
    result.verification_statement_digest = Some(verified.statement_digest);
    result.verification_evidence_root = Some(verified.evidence_root);
    result.open_challenge_count = 0;
    result.transition_history.push(digest_value(
        "trnm.poco-ai.result-transition-challenge-resolved.candidate.v1",
        &(
            result.result_id,
            result.revision,
            result.status,
            challenge.last_transition_hash,
        ),
    )?);
    let amount = config.trust_bundle.profile.challenge_bond_amount;
    state.bond.held = state.bond.held.checked_sub(amount).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ConservationViolation,
            "challenge bond held underflow",
        )
    })?;
    if decision == 0 {
        state.bond.released = state.bond.released.checked_add(amount).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "challenge bond release overflow",
            )
        })?;
    } else {
        state.bond.slashed = state.bond.slashed.checked_add(amount).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "challenge bond slash overflow",
            )
        })?;
    }
    state.bond.version = state.bond.version.checked_add(1).ok_or_else(|| {
        error(
            VerifyChallengeErrorCodeV1::ArithmeticOverflow,
            "challenge bond version overflow",
        )
    })?;
    check_bond(state)
}

fn open_rw(path: &Path, allow_create: bool) -> VerifyChallengeResultV1<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if allow_create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(connection)
}
fn open_ro(path: &Path) -> VerifyChallengeResultV1<Connection> {
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
fn reject_sidecars(path: &Path) -> VerifyChallengeResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar_name = path.as_os_str().to_os_string();
        sidecar_name.push(suffix);
        if PathBuf::from(sidecar_name).exists() {
            return Err(error(
                VerifyChallengeErrorCodeV1::SidecarPresent,
                "unresolved SQLite sidecar",
            ));
        }
    }
    Ok(())
}
fn require_existing_regular_store(path: &Path) -> VerifyChallengeResultV1<()> {
    let metadata = fs::symlink_metadata(path).map_err(|cause| {
        error(
            VerifyChallengeErrorCodeV1::StoreFailure,
            format!("existing Verify/Challenge store is unavailable: {cause}"),
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(error(
            VerifyChallengeErrorCodeV1::StoreFailure,
            "existing Verify/Challenge store path must not be a symlink",
        ));
    }
    if !file_type.is_file() {
        return Err(error(
            VerifyChallengeErrorCodeV1::StoreFailure,
            "existing Verify/Challenge store path is not a regular file",
        ));
    }
    Ok(())
}
fn verify_schema(connection: &Connection) -> VerifyChallengeResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows: Vec<(String, String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let expected = vec![
        (
            "verify_challenge_finalized_blocks_v1".to_owned(),
            "table".to_owned(),
            FINALIZED_BLOCKS_SQL.to_owned(),
        ),
        (
            "verify_challenge_metadata_v1".to_owned(),
            "table".to_owned(),
            META_SQL.to_owned(),
        ),
        (
            "verify_challenge_operations_v1".to_owned(),
            "table".to_owned(),
            OPERATIONS_SQL.to_owned(),
        ),
    ];
    if rows != expected {
        return Err(error(
            VerifyChallengeErrorCodeV1::SchemaMismatch,
            "exact schema v3 mismatch; migration forbidden",
        ));
    }
    Ok(())
}
fn u64_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}
fn parse_u64(bytes: &[u8]) -> VerifyChallengeResultV1<u64> {
    bytes.try_into().map(u64::from_be_bytes).map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "u64 width mismatch",
        )
    })
}

fn state_root(state: &VerifyKernelStateV1) -> VerifyChallengeResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.verify-challenge-state-root.candidate.v1",
        state,
    )
}

fn fresh_genesis_state(config: &VerifyChallengeStoreConfigV1) -> VerifyKernelStateV1 {
    VerifyKernelStateV1 {
        receipt: None,
        result: None,
        challenge: None,
        bond: ChallengeBondStateV1 {
            bond_id: config.trust_bundle.challenge_bond_id,
            funded: config.trust_bundle.challenge_bond_funding,
            available: config.trust_bundle.challenge_bond_funding,
            held: 0,
            released: 0,
            slashed: 0,
            version: 0,
        },
    }
}

fn operation_journal_root(connection: &Connection) -> VerifyChallengeResultV1<Hash32V1> {
    operation_journal_root_through(connection, u64::MAX)
}

fn operation_journal_root_through(
    connection: &Connection,
    maximum_sequence: u64,
) -> VerifyChallengeResultV1<Hash32V1> {
    let mut statement = connection.prepare(
        "SELECT operation_id,sequence,command,receipt,row_checksum FROM verify_challenge_operations_v1",
    )?;
    let mut rows = statement.query([])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let operation_id = row.get::<_, Vec<u8>>(0)?;
        let sequence = row.get::<_, Vec<u8>>(1)?;
        let command = row.get::<_, Vec<u8>>(2)?;
        let receipt = row.get::<_, Vec<u8>>(3)?;
        let row_checksum = row.get::<_, Vec<u8>>(4)?;
        let sequence_value = parse_u64(&sequence)?;
        if sequence_value <= maximum_sequence {
            records.push((
                sequence_value,
                operation_id,
                sequence,
                command,
                receipt,
                row_checksum,
            ));
        }
    }
    records.sort_by_key(|record| record.0);
    let mut encoded = Vec::new();
    for (_, operation_id, sequence, command, receipt, row_checksum) in records {
        for bytes in [operation_id, sequence, command, receipt, row_checksum] {
            let len = u64::try_from(bytes.len()).map_err(|_| {
                error(
                    VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                    "operation journal component length overflow",
                )
            })?;
            encoded.extend_from_slice(&len.to_be_bytes());
            encoded.extend_from_slice(&bytes);
        }
    }
    crate::codec::digest_encoded(
        "trnm.poco-ai.verify-challenge-operation-journal-root.candidate.v1",
        &encoded,
    )
}

fn marker_predecessor_checksum(
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<Hash32V1> {
    let config_hash = config.config_hash()?;
    Ok(checksum(&[
        b"trnm.poco-ai.verify-challenge-finalized-block-anchor.candidate.v1",
        &config.store_id.0,
        &config_hash.0,
        &config.trust_bundle.initial_order_height.to_be_bytes(),
        &config.trust_bundle.initial_order_block_id.0,
    ]))
}

fn finalized_block_marker_checksum(
    config: &VerifyChallengeStoreConfigV1,
    marker: &FinalizedBlockMarkerV1,
) -> VerifyChallengeResultV1<Hash32V1> {
    let config_hash = config.config_hash()?;
    Ok(checksum(&[
        &STORE_SCHEMA_VERSION_V1.to_be_bytes(),
        &config.store_id.0,
        &config_hash.0,
        &marker.marker_sequence.to_be_bytes(),
        &marker.order_height.to_be_bytes(),
        &marker.order_block_id.0,
        &marker.parent_order_height.to_be_bytes(),
        &marker.parent_order_block_id.0,
        &marker.source_operation_sequence.to_be_bytes(),
        &marker.target_operation_sequence.to_be_bytes(),
        &marker.source_state_root.0,
        &marker.target_state_root.0,
        &marker.source_operation_root.0,
        &marker.target_operation_root.0,
        &marker.previous_marker_checksum.0,
    ]))
}

fn insert_finalized_block_marker(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
    mut marker: FinalizedBlockMarkerV1,
) -> VerifyChallengeResultV1<FinalizedBlockMarkerV1> {
    marker.row_checksum = finalized_block_marker_checksum(config, &marker)?;
    let marker_sequence = marker.marker_sequence.to_be_bytes();
    let order_height = marker.order_height.to_be_bytes();
    let parent_order_height = marker.parent_order_height.to_be_bytes();
    let source_operation_sequence = marker.source_operation_sequence.to_be_bytes();
    let target_operation_sequence = marker.target_operation_sequence.to_be_bytes();
    let changed = connection.execute(
        "INSERT INTO verify_challenge_finalized_blocks_v1 (marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            marker_sequence.as_slice(),
            order_height.as_slice(),
            marker.order_block_id.0.as_slice(),
            parent_order_height.as_slice(),
            marker.parent_order_block_id.0.as_slice(),
            source_operation_sequence.as_slice(),
            target_operation_sequence.as_slice(),
            marker.source_state_root.0.as_slice(),
            marker.target_state_root.0.as_slice(),
            marker.source_operation_root.0.as_slice(),
            marker.target_operation_root.0.as_slice(),
            marker.previous_marker_checksum.0.as_slice(),
            marker.row_checksum.0.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(error(
            VerifyChallengeErrorCodeV1::StoreFailure,
            "finalized-block marker insert changed an unexpected row count",
        ));
    }
    Ok(marker)
}

fn insert_anchor_finalized_block_marker(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
    state_root: Hash32V1,
    operation_root: Hash32V1,
) -> VerifyChallengeResultV1<()> {
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
            row_checksum: Hash32V1([0; 32]),
        },
    )?;
    Ok(())
}

fn decode_marker_hash(bytes: Vec<u8>, label: &str) -> VerifyChallengeResultV1<Hash32V1> {
    bytes.try_into().map(Hash32V1).map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            format!("{label} is not exactly 32 bytes"),
        )
    })
}

fn load_finalized_block_markers(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<Vec<FinalizedBlockMarkerV1>> {
    let mut statement = connection.prepare("SELECT marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum FROM verify_challenge_finalized_blocks_v1")?;
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
            marker_sequence: parse_u64(&row.0)?,
            order_height: parse_u64(&row.1)?,
            order_block_id: decode_marker_hash(row.2, "marker Order block ID")?,
            parent_order_height: parse_u64(&row.3)?,
            parent_order_block_id: decode_marker_hash(row.4, "marker parent Order block ID")?,
            source_operation_sequence: parse_u64(&row.5)?,
            target_operation_sequence: parse_u64(&row.6)?,
            source_state_root: decode_marker_hash(row.7, "marker source state root")?,
            target_state_root: decode_marker_hash(row.8, "marker target state root")?,
            source_operation_root: decode_marker_hash(row.9, "marker source operation root")?,
            target_operation_root: decode_marker_hash(row.10, "marker target operation root")?,
            previous_marker_checksum: decode_marker_hash(row.11, "previous marker checksum")?,
            row_checksum: decode_marker_hash(row.12, "marker row checksum")?,
        };
        if marker.row_checksum != finalized_block_marker_checksum(config, &marker)? {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "finalized-block marker checksum differs",
            ));
        }
        markers.push(marker);
    }
    markers.sort_by_key(|marker| marker.marker_sequence);
    if markers.is_empty() {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "finalized-block journal is empty",
        ));
    }
    Ok(markers)
}

#[allow(clippy::too_many_arguments)]
fn advance_finalized_block_marker(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
    execution: &VerifyOrderFinalizedExecutionContextV1,
    source_sequence: u64,
    target_sequence: u64,
    source_state_root: Hash32V1,
    target_state_root: Hash32V1,
    source_operation_root: Hash32V1,
    target_operation_root: Hash32V1,
) -> VerifyChallengeResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
    let tail = *markers.last().expect("nonempty marker journal was checked");
    if source_sequence != tail.target_operation_sequence
        || source_state_root != tail.target_state_root
        || source_operation_root != tail.target_operation_root
        || target_sequence < source_sequence
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::StaleRevision,
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
                VerifyChallengeErrorCodeV1::StaleRevision,
                "same-block marker extension does not expect the exact block",
            ));
        }
        let mut updated = tail;
        updated.target_operation_sequence = target_sequence;
        updated.target_state_root = target_state_root;
        updated.target_operation_root = target_operation_root;
        updated.row_checksum = finalized_block_marker_checksum(config, &updated)?;
        let target_operation_sequence = updated.target_operation_sequence.to_be_bytes();
        let marker_sequence = updated.marker_sequence.to_be_bytes();
        let changed = connection.execute(
            "UPDATE verify_challenge_finalized_blocks_v1 SET target_operation_sequence=?1,target_state_root=?2,target_operation_root=?3,row_checksum=?4 WHERE marker_sequence=?5 AND row_checksum=?6",
            params![
                target_operation_sequence.as_slice(),
                updated.target_state_root.0.as_slice(),
                updated.target_operation_root.0.as_slice(),
                updated.row_checksum.0.as_slice(),
                marker_sequence.as_slice(),
                tail.row_checksum.0.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(error(
                VerifyChallengeErrorCodeV1::StaleRevision,
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
            VerifyChallengeErrorCodeV1::InvalidContext,
            "finalized-block marker target is not the direct Order successor",
        ));
    }
    insert_finalized_block_marker(
        connection,
        config,
        FinalizedBlockMarkerV1 {
            marker_sequence: tail.marker_sequence.checked_add(1).ok_or_else(|| {
                error(
                    VerifyChallengeErrorCodeV1::ArithmeticOverflow,
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
            row_checksum: Hash32V1([0; 32]),
        },
    )?;
    Ok(())
}

fn load_order_tip(connection: &Connection) -> VerifyChallengeResultV1<(u64, Hash32V1)> {
    let (height, block_id): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT order_height,order_block_id FROM verify_challenge_metadata_v1 WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let block_id: [u8; 32] = block_id.try_into().map_err(|_| {
        error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "metadata order block ID width mismatch",
        )
    })?;
    Ok((parse_u64(&height)?, Hash32V1(block_id)))
}

#[allow(clippy::too_many_arguments)]
fn write_metadata(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
    sequence: u64,
    order_height: u64,
    order_block_id: Hash32V1,
    durable_state_root: Hash32V1,
    durable_journal_root: Hash32V1,
    fenced: bool,
    state: &VerifyKernelStateV1,
) -> VerifyChallengeResultV1<()> {
    let config_hash = config.config_hash()?;
    let sequence_bytes = u64_bytes(sequence);
    let order_height_bytes = u64_bytes(order_height);
    let state_bytes = canonical_bytes(state)?;
    let schema = STORE_SCHEMA_VERSION_V1.to_be_bytes();
    let fenced_byte = [u8::from(fenced)];
    let row_checksum = checksum(&[
        &schema,
        &config.store_id.0,
        &config_hash.0,
        &sequence_bytes,
        &order_height_bytes,
        &order_block_id.0,
        &durable_state_root.0,
        &durable_journal_root.0,
        &fenced_byte,
        &state_bytes,
    ]);
    connection.execute("INSERT OR REPLACE INTO verify_challenge_metadata_v1 (singleton,schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,state,row_checksum) VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![STORE_SCHEMA_VERSION_V1,config.store_id.0.as_slice(),config_hash.0.as_slice(),sequence_bytes.as_slice(),order_height_bytes.as_slice(),order_block_id.0.as_slice(),durable_state_root.0.as_slice(),durable_journal_root.0.as_slice(),i64::from(fenced),state_bytes,row_checksum.0.as_slice()])?;
    Ok(())
}
fn load_metadata(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<(u64, bool, VerifyKernelStateV1)> {
    type MetadataRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
    );
    let row: MetadataRow=connection.query_row("SELECT schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,state,row_checksum FROM verify_challenge_metadata_v1 WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?)))?;
    let config_hash = config.config_hash()?;
    let sequence = parse_u64(&row.3)?;
    let order_height = parse_u64(&row.4)?;
    let schema = STORE_SCHEMA_VERSION_V1.to_be_bytes();
    let fenced_byte = [u8::from(row.8 != 0)];
    let expected = checksum(&[
        &schema,
        &row.1,
        &row.2,
        &row.3,
        &row.4,
        &row.5,
        &row.6,
        &row.7,
        &fenced_byte,
        &row.9,
    ]);
    if row.0 != i64::from(STORE_SCHEMA_VERSION_V1)
        || row.1 != config.store_id.0
        || row.2 != config_hash.0
        || row.5.len() != 32
        || row.6.len() != 32
        || row.7.len() != 32
        || row.8 > 1
        || row.10 != expected.0
        || order_height < config.trust_bundle.initial_order_height
        || row.5 == [0; 32]
        || (order_height == config.trust_bundle.initial_order_height
            && row.5 != config.trust_bundle.initial_order_block_id.0)
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "metadata identity/checksum/order/state/journal root mismatch",
        ));
    }
    let state: VerifyKernelStateV1 = strict_decode(&row.9).map_err(|cause| {
        error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            format!("metadata state is not strict canonical bytes: {cause}"),
        )
    })?;
    if row.6 != state_root(&state)?.0 || row.7 != operation_journal_root(connection)?.0 {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "metadata durable state/journal root mismatch",
        ));
    }
    Ok((sequence, row.8 != 0, state))
}
fn insert_operation(
    connection: &Connection,
    sequence: u64,
    command: &VerifyCommandV1,
    receipt: &VerifyTransitionReceiptV1,
) -> VerifyChallengeResultV1<()> {
    let id = command.operation_id()?;
    let seq = u64_bytes(sequence);
    let command_bytes = canonical_bytes(command)?;
    let receipt_bytes = canonical_bytes(receipt)?;
    let check = checksum(&[&id.0, &seq, &command_bytes, &receipt_bytes]);
    connection.execute("INSERT INTO verify_challenge_operations_v1 (operation_id,sequence,command,receipt,row_checksum) VALUES (?1,?2,?3,?4,?5)",params![id.0.as_slice(),seq.as_slice(),command_bytes,receipt_bytes,check.0.as_slice()])?;
    Ok(())
}
fn load_receipt(
    connection: &Connection,
    id: VerifyOperationIdV1,
) -> VerifyChallengeResultV1<Option<VerifyTransitionReceiptV1>> {
    type OperationRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let row:Option<OperationRow>=connection.query_row("SELECT sequence,command,receipt,row_checksum FROM verify_challenge_operations_v1 WHERE operation_id=?1",params![id.0.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((sequence, command, receipt, check)) = row else {
        return Ok(None);
    };
    let expected = checksum(&[&id.0, &sequence, &command, &receipt]);
    if check != expected.0 {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "operation checksum mismatch",
        ));
    }
    let decoded: VerifyCommandV1 = strict_decode(&command)?;
    if decoded.operation_id()? != id {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "operation ID mismatch",
        ));
    }
    Ok(Some(strict_decode(&receipt)?))
}
fn audit(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<()> {
    let (sequence, _, state) = load_metadata(connection, config)?;
    check_bond(&state)?;
    let mut stmt=connection.prepare("SELECT operation_id,sequence,command,receipt,row_checksum FROM verify_challenge_operations_v1 ORDER BY sequence")?;
    let mut rows = stmt.query([])?;
    let mut expected_sequence = 1u64;
    let mut previous_order_height = config.trust_bundle.initial_order_height;
    let mut previous_order_block_id = config.trust_bundle.initial_order_block_id;
    let mut tail_state_root = None;
    let mut last_sequence = 0u64;
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let seq: Vec<u8> = row.get(1)?;
        let command: Vec<u8> = row.get(2)?;
        let receipt: Vec<u8> = row.get(3)?;
        let check: Vec<u8> = row.get(4)?;
        if id.len() != 32
            || parse_u64(&seq)? != expected_sequence
            || check != checksum(&[&id, &seq, &command, &receipt]).0
        {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "operation journal gap/checksum mismatch",
            ));
        }
        let command_value: VerifyCommandV1 = strict_decode(&command)?;
        let receipt_value: VerifyTransitionReceiptV1 = strict_decode(&receipt)?;
        if command_value.operation_id()?.0.as_slice() != id
            || receipt_value.schema_version != SCHEMA_VERSION_V1
            || receipt_value.store_id != config.store_id
            || receipt_value.sequence != expected_sequence
            || receipt_value.operation_id.0.as_slice() != id
            || receipt_value.operation_kind != command_value.operation_kind()
            || receipt_value.order_height < previous_order_height
            || (receipt_value.order_height == previous_order_height
                && receipt_value.order_block_id != previous_order_block_id)
            || (receipt_value.order_height > previous_order_height
                && receipt_value.order_block_id == previous_order_block_id)
        {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "operation journal semantic mismatch",
            ));
        }
        previous_order_height = receipt_value.order_height;
        previous_order_block_id = receipt_value.order_block_id;
        tail_state_root = Some(receipt_value.post_state_root);
        last_sequence = expected_sequence;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                "operation audit sequence overflow",
            )
        })?;
    }
    if last_sequence != sequence {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "metadata sequence differs from journal",
        ));
    }
    if sequence > 0 && tail_state_root != Some(state_root(&state)?) {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "operation tail does not bind current state",
        ));
    }
    audit_finalized_block_journal(connection, config)
}

fn audit_finalized_block_journal(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<()> {
    let markers = load_finalized_block_markers(connection, config)?;
    let mut receipts = BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT sequence,receipt FROM verify_challenge_operations_v1")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (sequence, receipt) in rows {
        let sequence = parse_u64(&sequence)?;
        let receipt: VerifyTransitionReceiptV1 = strict_decode(&receipt)?;
        if receipt.sequence != sequence || receipts.insert(sequence, receipt).is_some() {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "finalized-block journal operation mapping is duplicate",
            ));
        }
    }

    let genesis_state_root = state_root(&fresh_genesis_state(config))?;
    let genesis_operation_root = operation_journal_root_through(connection, 0)?;
    let mut previous = None;
    for (index, marker) in markers.iter().enumerate() {
        if marker.marker_sequence
            != u64::try_from(index).map_err(|_| {
                error(
                    VerifyChallengeErrorCodeV1::ArithmeticOverflow,
                    "finalized-block audit index overflows",
                )
            })?
        {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
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
                        VerifyChallengeErrorCodeV1::TamperDetected,
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
                        VerifyChallengeErrorCodeV1::TamperDetected,
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
                VerifyChallengeErrorCodeV1::TamperDetected,
                "finalized-block marker operation roots or range regress",
            ));
        }
        let mut expected_target_state = marker.source_state_root;
        for sequence in
            marker.source_operation_sequence.saturating_add(1)..=marker.target_operation_sequence
        {
            let receipt = receipts.get(&sequence).ok_or_else(|| {
                error(
                    VerifyChallengeErrorCodeV1::TamperDetected,
                    "finalized-block marker operation range has a gap",
                )
            })?;
            if receipt.order_height != marker.order_height
                || receipt.order_block_id != marker.order_block_id
            {
                return Err(error(
                    VerifyChallengeErrorCodeV1::TamperDetected,
                    "operation receipt belongs to a different finalized-block marker",
                ));
            }
            expected_target_state = receipt.post_state_root;
        }
        if marker.target_state_root != expected_target_state {
            return Err(error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "finalized-block marker target state differs from its operation range",
            ));
        }
        previous = Some(*marker);
    }

    let tail = previous.expect("nonempty marker journal was checked");
    let (sequence, _, state) = load_metadata(connection, config)?;
    if load_order_tip(connection)? != (tail.order_height, tail.order_block_id)
        || sequence != tail.target_operation_sequence
        || state_root(&state)? != tail.target_state_root
        || operation_journal_root(connection)? != tail.target_operation_root
        || u64::try_from(receipts.len()).ok() != Some(sequence)
    {
        return Err(error(
            VerifyChallengeErrorCodeV1::TamperDetected,
            "metadata head differs from finalized-block journal tail",
        ));
    }
    Ok(())
}

fn finalized_block_journal_root(
    connection: &Connection,
    config: &VerifyChallengeStoreConfigV1,
) -> VerifyChallengeResultV1<Hash32V1> {
    audit_finalized_block_journal(connection, config)?;
    load_finalized_block_markers(connection, config)?
        .last()
        .map(|marker| marker.row_checksum)
        .ok_or_else(|| {
            error(
                VerifyChallengeErrorCodeV1::TamperDetected,
                "finalized-block journal root is absent",
            )
        })
}
