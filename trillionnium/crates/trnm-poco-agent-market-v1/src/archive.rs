//! Bounded, proof-preserving TaskV1 terminal-history archive policy.
//!
//! The archive planner is deliberately candidate-only. It consumes already
//! authenticated terminal-task facts, produces a deterministic pruning plan,
//! and binds every pruned record into a chained Merkle seal. It does not grant
//! terminality, finality, storage-deletion, or production activation authority.

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    codec::digest_value,
    error::{error, AgentMarketErrorCodeV1, AgentMarketResultV1},
    Hash32V1, ProtocolContextV1, TaskIdV1,
};

pub const TASK_ARCHIVE_SCHEMA_VERSION_V1: u16 = 1;
pub const MAX_TASK_ARCHIVE_BATCH_RECORDS_V1: u32 = 4_096;
pub const MAX_TASK_ARCHIVE_PROOF_DEPTH_V1: usize = 12;

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskArchivePolicyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    /// Mandatory on-ledger retention after the terminal height.
    pub minimum_terminal_retention_blocks: u64,
    /// Maximum terminal records that may remain in the live store.
    pub maximum_live_terminal_records: u32,
    /// Maximum encoded terminal-record bytes that may remain in the live store.
    pub maximum_live_terminal_bytes: u64,
    /// Hard limit for one deterministic archive batch.
    pub maximum_archive_batch_records: u32,
    /// Hard encoded-byte limit for one deterministic archive batch.
    pub maximum_archive_batch_bytes: u64,
    /// Required prepaid charge per encoded byte per retained block.
    pub retention_charge_units_per_byte_block: u64,
}

impl TaskArchivePolicyV1 {
    pub fn policy_hash(&self) -> AgentMarketResultV1<Hash32V1> {
        self.validate()?;
        digest_value("trnm.poco-ai.task-archive-policy.candidate.v1", self)
    }

    fn validate(&self) -> AgentMarketResultV1<()> {
        if self.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "unsupported TaskV1 archive policy schema",
            ));
        }
        if self.minimum_terminal_retention_blocks == 0
            || self.maximum_live_terminal_records == 0
            || self.maximum_live_terminal_bytes == 0
            || self.maximum_archive_batch_records == 0
            || self.maximum_archive_batch_bytes == 0
            || self.retention_charge_units_per_byte_block == 0
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "TaskV1 archive policy bounds and charge rate must be positive",
            ));
        }
        if self.maximum_archive_batch_records > MAX_TASK_ARCHIVE_BATCH_RECORDS_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "TaskV1 archive batch record limit exceeds the hard protocol bound",
            ));
        }
        Ok(())
    }
}

/// Inert terminal-task fact supplied by an authority outside this planner.
///
/// `retention_paid_through_height` is inclusive. The record cannot be selected
/// for pruning until the following block, even when the mandatory minimum
/// retention window has already elapsed.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TerminalTaskArchiveRecordV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub task_id: TaskIdV1,
    pub terminal_height: u64,
    pub task_revision: u64,
    pub terminal_state_digest: Hash32V1,
    pub terminal_receipt_digest: Hash32V1,
    pub evidence_root: Hash32V1,
    pub encoded_bytes: u64,
    pub retention_paid_through_height: u64,
    pub retention_charge_paid: u128,
}

impl TerminalTaskArchiveRecordV1 {
    pub fn record_hash(&self) -> AgentMarketResultV1<Hash32V1> {
        if self.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "unsupported terminal TaskV1 archive record schema",
            ));
        }
        digest_value("trnm.poco-ai.task-archive-record.candidate.v1", self)
    }

    fn validate_against(
        &self,
        policy: &TaskArchivePolicyV1,
        current_height: u64,
    ) -> AgentMarketResultV1<()> {
        if self.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "unsupported terminal TaskV1 archive record schema",
            ));
        }
        if self.context != policy.context {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidContext,
                "terminal TaskV1 archive record context differs from policy",
            ));
        }
        if self.terminal_height > current_height || self.encoded_bytes == 0 {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "terminal TaskV1 archive record height/size is invalid",
            ));
        }

        let minimum_paid_through = self
            .terminal_height
            .checked_add(policy.minimum_terminal_retention_blocks - 1)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 mandatory retention height overflow",
                )
            })?;
        if self.retention_paid_through_height < minimum_paid_through {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "terminal TaskV1 record did not prepay the mandatory retention window",
            ));
        }

        let charged_blocks = self
            .retention_paid_through_height
            .checked_sub(self.terminal_height)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 retention block count overflow",
                )
            })?;
        let required_charge = u128::from(self.encoded_bytes)
            .checked_mul(u128::from(charged_blocks))
            .and_then(|value| {
                value.checked_mul(u128::from(policy.retention_charge_units_per_byte_block))
            })
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 retention charge overflow",
                )
            })?;
        if self.retention_charge_paid < required_charge {
            return Err(error(
                AgentMarketErrorCodeV1::ConservationViolation,
                "terminal TaskV1 retention charge is underfunded",
            ));
        }
        Ok(())
    }

    fn first_prunable_height(&self) -> AgentMarketResultV1<u64> {
        self.retention_paid_through_height
            .checked_add(1)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 first-prunable height overflow",
                )
            })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskArchiveSealV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub policy_hash: Hash32V1,
    pub archive_height: u64,
    pub batch_sequence: u64,
    pub previous_seal_hash: Hash32V1,
    pub first_terminal_height: u64,
    pub last_terminal_height: u64,
    pub first_task_id: TaskIdV1,
    pub last_task_id: TaskIdV1,
    pub record_count: u32,
    pub total_encoded_bytes: u64,
    pub total_retention_charge: u128,
    pub records_root: Hash32V1,
}

impl TaskArchiveSealV1 {
    pub fn seal_hash(&self) -> AgentMarketResultV1<Hash32V1> {
        if self.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1 || self.record_count == 0 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "invalid TaskV1 archive seal schema/count",
            ));
        }
        digest_value("trnm.poco-ai.task-archive-seal.candidate.v1", self)
    }
}

/// Exportable archive artifact. The live store may retain only `seal`; the
/// records can live in a separately replicated archive while remaining
/// independently provable against `records_root`.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskArchiveBatchV1 {
    pub seal: TaskArchiveSealV1,
    pub records: Vec<TerminalTaskArchiveRecordV1>,
}

impl TaskArchiveBatchV1 {
    /// Validate bounded, unique, retention-eligible records before proof production.
    pub fn validate(&self, policy: &TaskArchivePolicyV1) -> AgentMarketResultV1<()> {
        policy.validate()?;
        if self.records.is_empty()
            || self.records.len()
                > usize::try_from(policy.maximum_archive_batch_records).map_err(|_| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "TaskV1 archive record limit conversion overflow",
                    )
                })?
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidBounds,
                "TaskV1 archive batch record count is outside policy",
            ));
        }
        if self.seal.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1
            || self.seal.context != policy.context
            || self.seal.policy_hash != policy.policy_hash()?
            || self.seal.batch_sequence == 0
            || self.seal.record_count
                != u32::try_from(self.records.len()).map_err(|_| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "TaskV1 archive record count conversion overflow",
                    )
                })?
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidState,
                "TaskV1 archive seal does not bind policy/context/count",
            ));
        }

        let mut previous_key: Option<(u64, TaskIdV1)> = None;
        let mut task_ids = BTreeSet::new();
        let mut total_bytes = 0_u64;
        let mut total_charge = 0_u128;
        let mut hashes = Vec::with_capacity(self.records.len());
        for record in &self.records {
            record.validate_against(policy, self.seal.archive_height)?;
            if self.seal.archive_height < record.first_prunable_height()? {
                return Err(error(
                    AgentMarketErrorCodeV1::InvalidState,
                    "TaskV1 archive artifact violates prepaid retention",
                ));
            }
            if !task_ids.insert(record.task_id) {
                return Err(error(
                    AgentMarketErrorCodeV1::NonCanonical,
                    "duplicate TaskV1 terminal record in archive batch",
                ));
            }
            let key = (record.terminal_height, record.task_id);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(error(
                    AgentMarketErrorCodeV1::NonCanonical,
                    "TaskV1 archive records are not strictly ordered and unique",
                ));
            }
            previous_key = Some(key);
            total_bytes = total_bytes
                .checked_add(record.encoded_bytes)
                .ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "TaskV1 archive byte total overflow",
                    )
                })?;
            total_charge = total_charge
                .checked_add(record.retention_charge_paid)
                .ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::ArithmeticOverflow,
                        "TaskV1 archive charge total overflow",
                    )
                })?;
            hashes.push(record.record_hash()?);
        }
        if total_bytes > policy.maximum_archive_batch_bytes
            || total_bytes != self.seal.total_encoded_bytes
            || total_charge != self.seal.total_retention_charge
            || merkle_root_v1(&hashes)? != self.seal.records_root
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidState,
                "TaskV1 archive batch totals/root differ from its seal",
            ));
        }

        let first = self.records.first().ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::InvalidState,
                "TaskV1 archive batch unexpectedly empty",
            )
        })?;
        let last = self.records.last().ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::InvalidState,
                "TaskV1 archive batch unexpectedly empty",
            )
        })?;
        if self.seal.first_terminal_height != first.terminal_height
            || self.seal.last_terminal_height != last.terminal_height
            || self.seal.first_task_id != first.task_id
            || self.seal.last_task_id != last.task_id
        {
            return Err(error(
                AgentMarketErrorCodeV1::InvalidState,
                "TaskV1 archive seal range differs from canonical records",
            ));
        }
        Ok(())
    }

    pub fn inclusion_proof(
        &self,
        policy: &TaskArchivePolicyV1,
        task_id: TaskIdV1,
    ) -> AgentMarketResultV1<TaskArchiveInclusionProofV1> {
        self.validate(policy)?;
        let index = self
            .records
            .iter()
            .position(|record| record.task_id == task_id)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::NotFound,
                    "TaskV1 not in archive batch",
                )
            })?;
        let hashes = self
            .records
            .iter()
            .map(TerminalTaskArchiveRecordV1::record_hash)
            .collect::<AgentMarketResultV1<Vec<_>>>()?;
        let siblings = merkle_proof_v1(&hashes, index)?;
        Ok(TaskArchiveInclusionProofV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            seal_hash: self.seal.seal_hash()?,
            leaf_index: u32::try_from(index).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 archive proof index conversion overflow",
                )
            })?,
            siblings,
        })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskArchiveInclusionProofV1 {
    pub schema_version: u16,
    pub seal_hash: Hash32V1,
    pub leaf_index: u32,
    pub siblings: Vec<Hash32V1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskArchivePlanV1 {
    retained_records: Vec<TerminalTaskArchiveRecordV1>,
    archive_batch: Option<TaskArchiveBatchV1>,
}

impl TaskArchivePlanV1 {
    pub fn retained_records(&self) -> &[TerminalTaskArchiveRecordV1] {
        &self.retained_records
    }

    pub const fn archive_batch(&self) -> Option<&TaskArchiveBatchV1> {
        self.archive_batch.as_ref()
    }
}

pub fn plan_task_archive_pruning_v1(
    policy: &TaskArchivePolicyV1,
    records: &[TerminalTaskArchiveRecordV1],
    legal_holds: &BTreeSet<TaskIdV1>,
    current_height: u64,
    batch_sequence: u64,
    previous_seal_hash: Hash32V1,
) -> AgentMarketResultV1<TaskArchivePlanV1> {
    policy.validate()?;
    let mut canonical = records.to_vec();
    canonical.sort_by_key(|record| (record.terminal_height, record.task_id));

    let mut seen = BTreeSet::new();
    let mut live_bytes = 0_u64;
    for record in &canonical {
        record.validate_against(policy, current_height)?;
        if !seen.insert(record.task_id) {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "duplicate TaskV1 terminal record",
            ));
        }
        live_bytes = live_bytes
            .checked_add(record.encoded_bytes)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 live terminal byte total overflow",
                )
            })?;
    }
    if !legal_holds.is_subset(&seen) {
        return Err(error(
            AgentMarketErrorCodeV1::NotFound,
            "TaskV1 legal hold references a record outside the candidate set",
        ));
    }

    let maximum_live_count =
        usize::try_from(policy.maximum_live_terminal_records).map_err(|_| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 live record limit conversion overflow",
            )
        })?;
    if canonical.len() <= maximum_live_count && live_bytes <= policy.maximum_live_terminal_bytes {
        return Ok(TaskArchivePlanV1 {
            retained_records: canonical,
            archive_batch: None,
        });
    }
    if batch_sequence == 0 {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "TaskV1 archive batch sequence must be positive",
        ));
    }

    let maximum_batch_count =
        usize::try_from(policy.maximum_archive_batch_records).map_err(|_| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 archive batch limit conversion overflow",
            )
        })?;
    let mut selected = Vec::new();
    let mut selected_ids = BTreeSet::new();
    let mut selected_bytes = 0_u64;
    let mut remaining_count = canonical.len();
    let mut remaining_bytes = live_bytes;

    for record in &canonical {
        if remaining_count <= maximum_live_count
            && remaining_bytes <= policy.maximum_live_terminal_bytes
        {
            break;
        }
        if legal_holds.contains(&record.task_id)
            || current_height < record.first_prunable_height()?
        {
            continue;
        }
        if selected.len() == maximum_batch_count {
            break;
        }
        let next_selected_bytes = selected_bytes
            .checked_add(record.encoded_bytes)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 selected archive byte total overflow",
                )
            })?;
        if next_selected_bytes > policy.maximum_archive_batch_bytes {
            continue;
        }
        selected_bytes = next_selected_bytes;
        remaining_count = remaining_count.checked_sub(1).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 remaining record count underflow",
            )
        })?;
        remaining_bytes = remaining_bytes
            .checked_sub(record.encoded_bytes)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 remaining byte total underflow",
                )
            })?;
        selected_ids.insert(record.task_id);
        selected.push(record.clone());
    }

    if remaining_count > maximum_live_count || remaining_bytes > policy.maximum_live_terminal_bytes
    {
        return Err(error(
            AgentMarketErrorCodeV1::Conflict,
            "TaskV1 live archive capacity cannot be restored without violating retention, hold, or batch bounds",
        ));
    }

    let hashes = selected
        .iter()
        .map(TerminalTaskArchiveRecordV1::record_hash)
        .collect::<AgentMarketResultV1<Vec<_>>>()?;
    let total_charge = selected.iter().try_fold(0_u128, |total, record| {
        total
            .checked_add(record.retention_charge_paid)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 selected archive charge total overflow",
                )
            })
    })?;
    let first = selected.first().ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::Conflict,
            "TaskV1 archive pressure exists but no record is prunable",
        )
    })?;
    let last = selected.last().ok_or_else(|| {
        error(
            AgentMarketErrorCodeV1::Conflict,
            "TaskV1 archive pressure exists but no record is prunable",
        )
    })?;
    let seal = TaskArchiveSealV1 {
        schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
        context: policy.context.clone(),
        policy_hash: policy.policy_hash()?,
        archive_height: current_height,
        batch_sequence,
        previous_seal_hash,
        first_terminal_height: first.terminal_height,
        last_terminal_height: last.terminal_height,
        first_task_id: first.task_id,
        last_task_id: last.task_id,
        record_count: u32::try_from(selected.len()).map_err(|_| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 selected archive count conversion overflow",
            )
        })?,
        total_encoded_bytes: selected_bytes,
        total_retention_charge: total_charge,
        records_root: merkle_root_v1(&hashes)?,
    };
    let batch = TaskArchiveBatchV1 {
        seal,
        records: selected,
    };
    batch.validate(policy)?;

    let retained_records = canonical
        .into_iter()
        .filter(|record| !selected_ids.contains(&record.task_id))
        .collect();
    Ok(TaskArchivePlanV1 {
        retained_records,
        archive_batch: Some(batch),
    })
}

pub fn verify_task_archive_inclusion_v1(
    seal: &TaskArchiveSealV1,
    record: &TerminalTaskArchiveRecordV1,
    proof: &TaskArchiveInclusionProofV1,
) -> AgentMarketResultV1<()> {
    if proof.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1
        || seal.schema_version != TASK_ARCHIVE_SCHEMA_VERSION_V1
        || proof.seal_hash != seal.seal_hash()?
        || record.context != seal.context
        || proof.leaf_index >= seal.record_count
        || proof.siblings.len() != expected_proof_depth_v1(seal.record_count)?
        || proof.siblings.len() > MAX_TASK_ARCHIVE_PROOF_DEPTH_V1
    {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "TaskV1 archive inclusion proof header is invalid",
        ));
    }

    let mut index = usize::try_from(proof.leaf_index).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "TaskV1 archive proof index conversion overflow",
        )
    })?;
    let mut current = record.record_hash()?;
    for sibling in &proof.siblings {
        current = if index.is_multiple_of(2) {
            merkle_parent_v1(current, *sibling)?
        } else {
            merkle_parent_v1(*sibling, current)?
        };
        index /= 2;
    }
    if current != seal.records_root {
        return Err(error(
            AgentMarketErrorCodeV1::TamperDetected,
            "TaskV1 archive inclusion proof does not reach the sealed root",
        ));
    }
    Ok(())
}

fn merkle_root_v1(leaves: &[Hash32V1]) -> AgentMarketResultV1<Hash32V1> {
    if leaves.is_empty() {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "TaskV1 archive Merkle tree cannot be empty",
        ));
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(merkle_parent_v1(pair[0], right)?);
        }
        level = next;
    }
    Ok(level[0])
}

fn merkle_proof_v1(leaves: &[Hash32V1], leaf_index: usize) -> AgentMarketResultV1<Vec<Hash32V1>> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "TaskV1 archive proof index is outside the Merkle tree",
        ));
    }
    let mut level = leaves.to_vec();
    let mut index = leaf_index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if index.is_multiple_of(2) {
            level.get(index + 1).copied().unwrap_or(level[index])
        } else {
            level[index - 1]
        };
        siblings.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(merkle_parent_v1(pair[0], right)?);
        }
        level = next;
        index /= 2;
    }
    if siblings.len() > MAX_TASK_ARCHIVE_PROOF_DEPTH_V1 {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "TaskV1 archive proof exceeds the hard depth bound",
        ));
    }
    Ok(siblings)
}

fn merkle_parent_v1(left: Hash32V1, right: Hash32V1) -> AgentMarketResultV1<Hash32V1> {
    digest_value(
        "trnm.poco-ai.task-archive-merkle-node.candidate.v1",
        &(left, right),
    )
}

fn expected_proof_depth_v1(record_count: u32) -> AgentMarketResultV1<usize> {
    if record_count == 0 || record_count > MAX_TASK_ARCHIVE_BATCH_RECORDS_V1 {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidBounds,
            "TaskV1 archive seal count is outside the hard bound",
        ));
    }
    let mut width = usize::try_from(record_count).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "TaskV1 archive count conversion overflow",
        )
    })?;
    let mut depth = 0_usize;
    while width > 1 {
        width = width.div_ceil(2);
        depth += 1;
    }
    Ok(depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            genesis_hash: Hash32V1([1; 32]),
            chain_id: "trnm-archive-test".to_string(),
            protocol_version: 1,
            stack_profile_hash: Hash32V1([2; 32]),
        }
    }

    fn policy(maximum_live_terminal_records: u32) -> TaskArchivePolicyV1 {
        TaskArchivePolicyV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            context: context(),
            minimum_terminal_retention_blocks: 5,
            maximum_live_terminal_records,
            maximum_live_terminal_bytes: u64::from(maximum_live_terminal_records) * 100,
            maximum_archive_batch_records: 8,
            maximum_archive_batch_bytes: 800,
            retention_charge_units_per_byte_block: 2,
        }
    }

    fn record(id: u8, terminal_height: u64) -> TerminalTaskArchiveRecordV1 {
        let paid_through = terminal_height + 4;
        TerminalTaskArchiveRecordV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            context: context(),
            task_id: TaskIdV1([id; 32]),
            terminal_height,
            task_revision: u64::from(id),
            terminal_state_digest: Hash32V1([id.wrapping_add(1); 32]),
            terminal_receipt_digest: Hash32V1([id.wrapping_add(2); 32]),
            evidence_root: Hash32V1([id.wrapping_add(3); 32]),
            encoded_bytes: 100,
            retention_paid_through_height: paid_through,
            retention_charge_paid: 1_000,
        }
    }

    #[test]
    fn oldest_eligible_records_are_selected_deterministically() {
        let policy = policy(2);
        let records = vec![record(4, 4), record(2, 2), record(3, 3), record(1, 1)];
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("plan");
        let batch = plan.archive_batch().expect("archive pressure");
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[0].task_id, TaskIdV1([1; 32]));
        assert_eq!(batch.records[1].task_id, TaskIdV1([2; 32]));
        assert_eq!(plan.retained_records().len(), 2);

        let mut reversed = records;
        reversed.reverse();
        let replay = plan_task_archive_pruning_v1(
            &policy,
            &reversed,
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("deterministic replay");
        assert_eq!(replay.archive_batch(), plan.archive_batch());
        assert_eq!(replay.retained_records(), plan.retained_records());
    }

    #[test]
    fn legal_holds_and_prepaid_extensions_fail_closed_under_pressure() {
        let policy = policy(1);
        let mut records = vec![record(1, 1), record(2, 2), record(3, 3)];
        records[1].retention_paid_through_height = 30;
        records[1].retention_charge_paid = 5_800;
        records[2].retention_paid_through_height = 30;
        records[2].retention_charge_paid = 5_600;
        let holds = BTreeSet::from([TaskIdV1([1; 32])]);
        let failure =
            plan_task_archive_pruning_v1(&policy, &records, &holds, 20, 1, Hash32V1([0; 32]))
                .expect_err("capacity cannot be restored");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::Conflict);
    }

    #[test]
    fn inclusion_proof_survives_pruning_and_rejects_mutation() {
        let policy = policy(1);
        let records = vec![record(1, 1), record(2, 2), record(3, 3), record(4, 4)];
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            9,
            Hash32V1([7; 32]),
        )
        .expect("plan");
        let batch = plan.archive_batch().expect("batch");
        let archived = &batch.records[1];
        let proof = batch
            .inclusion_proof(&policy, archived.task_id)
            .expect("proof");
        verify_task_archive_inclusion_v1(&batch.seal, archived, &proof).expect("valid proof");

        let mut mutated = archived.clone();
        mutated.terminal_state_digest.0[0] ^= 1;
        let failure = verify_task_archive_inclusion_v1(&batch.seal, &mutated, &proof)
            .expect_err("mutated record must fail");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::TamperDetected);
    }

    #[test]
    fn underfunded_retention_charge_is_rejected() {
        let policy = policy(1);
        let mut underfunded = record(1, 1);
        underfunded.retention_charge_paid -= 1;
        let failure = plan_task_archive_pruning_v1(
            &policy,
            &[underfunded, record(2, 2)],
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect_err("underfunded retention");
        assert_eq!(
            failure.code(),
            AgentMarketErrorCodeV1::ConservationViolation
        );
    }

    #[test]
    fn no_archive_batch_is_created_without_capacity_pressure() {
        let policy = policy(2);
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &[record(2, 2), record(1, 1)],
            &BTreeSet::new(),
            20,
            0,
            Hash32V1([0; 32]),
        )
        .expect("no pressure");
        assert!(plan.archive_batch().is_none());
        assert_eq!(plan.retained_records()[0].task_id, TaskIdV1([1; 32]));
    }

    fn two_record_batch(policy: &TaskArchivePolicyV1) -> TaskArchiveBatchV1 {
        plan_task_archive_pruning_v1(
            policy,
            &[record(1, 1), record(2, 2), record(3, 3)],
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("valid archive plan")
        .archive_batch()
        .expect("two archived records")
        .clone()
    }

    #[test]
    fn direct_batch_and_proof_admission_enforce_inclusive_retention() {
        let policy = policy(1);
        let mut batch = two_record_batch(&policy);
        batch.validate(&policy).expect("positive control");
        let records_root = batch.seal.records_root;
        for archive_height in 2..=6 {
            batch.seal.archive_height = archive_height;
            let failure = batch
                .validate(&policy)
                .expect_err("direct admission may not bypass prepaid retention");
            assert_eq!(failure.code(), AgentMarketErrorCodeV1::InvalidState);
            assert!(batch
                .inclusion_proof(&policy, batch.records[0].task_id)
                .is_err());
            assert_eq!(batch.seal.records_root, records_root);
        }
        batch.seal.archive_height = 7;
        batch.validate(&policy).expect("first eligible height");
        let proof = batch
            .inclusion_proof(&policy, batch.records[0].task_id)
            .expect("proof after retention expires");
        crate::verify_task_archive_inclusion_v1(&batch.seal, &batch.records[0], &proof)
            .expect("public inclusion after retention expires");
    }

    #[test]
    fn duplicate_task_id_at_distinct_heights_is_rejected_with_a_matching_root() {
        let policy = policy(1);
        let mut batch = two_record_batch(&policy);
        batch.validate(&policy).expect("positive control");
        batch.records[1].task_id = batch.records[0].task_id;
        batch.seal.last_task_id = batch.records[1].task_id;
        let hashes = batch
            .records
            .iter()
            .map(TerminalTaskArchiveRecordV1::record_hash)
            .collect::<AgentMarketResultV1<Vec<_>>>()
            .expect("mutant hashes");
        batch.seal.records_root = merkle_root_v1(&hashes).expect("matching mutant root");
        assert!(batch.records[0].terminal_height < batch.records[1].terminal_height);
        let failure = batch
            .validate(&policy)
            .expect_err("height ordering does not establish task identity uniqueness");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::NonCanonical);
        assert!(batch
            .inclusion_proof(&policy, batch.records[0].task_id)
            .is_err());
        assert!(crate::verify_task_archive_batch_v1(&policy, &batch).is_err());
    }

    #[test]
    fn maximum_prepaid_height_never_wraps_into_archive_eligibility() {
        let mut policy = policy(1);
        policy.minimum_terminal_retention_blocks = 1;
        let mut batch = two_record_batch(&policy);
        batch.records.truncate(1);
        let terminal = &mut batch.records[0];
        terminal.terminal_height = u64::MAX - 1;
        terminal.retention_paid_through_height = u64::MAX - 1;
        terminal.retention_charge_paid = 200;
        batch.seal.policy_hash = policy.policy_hash().expect("policy hash");
        batch.seal.archive_height = u64::MAX;
        batch.seal.record_count = 1;
        batch.seal.first_terminal_height = terminal.terminal_height;
        batch.seal.last_terminal_height = terminal.terminal_height;
        batch.seal.first_task_id = terminal.task_id;
        batch.seal.last_task_id = terminal.task_id;
        batch.seal.total_encoded_bytes = terminal.encoded_bytes;
        batch.seal.total_retention_charge = terminal.retention_charge_paid;
        batch.seal.records_root = terminal.record_hash().expect("single-leaf root");
        batch
            .validate(&policy)
            .expect("maximum representable first-prunable height");

        batch.records[0].retention_paid_through_height = u64::MAX;
        batch.records[0].retention_charge_paid = 400;
        batch.seal.total_retention_charge = 400;
        batch.seal.records_root = batch.records[0].record_hash().expect("mutant leaf root");
        let failure = batch
            .validate(&policy)
            .expect_err("expiry cannot wrap to zero");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::ArithmeticOverflow);
        assert!(batch
            .inclusion_proof(&policy, batch.records[0].task_id)
            .is_err());
    }
}
