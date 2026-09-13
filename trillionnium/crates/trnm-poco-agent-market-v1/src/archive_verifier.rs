//! Independent fail-closed verification for TaskV1 archive artifacts.
//!
//! The planner already refuses to select records before prepaid retention has
//! elapsed. Direct batch admission now enforces the same invariant; these
//! wrappers retain an additional public verification check. Neither path grants
//! storage-deletion authority or resolves externally supplied hold obligations.

use crate::{
    archive::{
        self, TaskArchiveBatchV1, TaskArchiveInclusionProofV1, TaskArchivePolicyV1,
        TaskArchiveSealV1, TerminalTaskArchiveRecordV1,
    },
    error::{error, AgentMarketErrorCodeV1, AgentMarketResultV1},
};

/// Verify the complete archive batch, including policy, charge, Merkle, range,
/// ordering, and prepaid-retention expiry.
pub fn verify_task_archive_batch_v1(
    policy: &TaskArchivePolicyV1,
    batch: &TaskArchiveBatchV1,
) -> AgentMarketResultV1<()> {
    batch.validate(policy)?;
    for record in &batch.records {
        verify_retention_elapsed_v1(batch.seal.archive_height, record)?;
    }
    Ok(())
}

/// Verify one proof and independently reject a record archived before its
/// inclusive prepaid-retention height has elapsed.
pub fn verify_task_archive_inclusion_v1(
    seal: &TaskArchiveSealV1,
    record: &TerminalTaskArchiveRecordV1,
    proof: &TaskArchiveInclusionProofV1,
) -> AgentMarketResultV1<()> {
    verify_retention_elapsed_v1(seal.archive_height, record)?;
    archive::verify_task_archive_inclusion_v1(seal, record, proof)
}

fn verify_retention_elapsed_v1(
    archive_height: u64,
    record: &TerminalTaskArchiveRecordV1,
) -> AgentMarketResultV1<()> {
    let first_prunable_height = record
        .retention_paid_through_height
        .checked_add(1)
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 first-prunable height overflow at archive verification",
            )
        })?;
    if archive_height < first_prunable_height {
        return Err(error(
            AgentMarketErrorCodeV1::InvalidState,
            "TaskV1 archive artifact violates prepaid retention",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        archive::{plan_task_archive_pruning_v1, TASK_ARCHIVE_SCHEMA_VERSION_V1},
        Hash32V1, ProtocolContextV1, TaskIdV1,
    };

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            genesis_hash: Hash32V1([1; 32]),
            chain_id: "trnm-archive-verifier-test".to_string(),
            protocol_version: 1,
            stack_profile_hash: Hash32V1([2; 32]),
        }
    }

    fn policy() -> TaskArchivePolicyV1 {
        TaskArchivePolicyV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            context: context(),
            minimum_terminal_retention_blocks: 5,
            maximum_live_terminal_records: 1,
            maximum_live_terminal_bytes: 100,
            maximum_archive_batch_records: 8,
            maximum_archive_batch_bytes: 800,
            retention_charge_units_per_byte_block: 2,
        }
    }

    fn record(id: u8, terminal_height: u64) -> TerminalTaskArchiveRecordV1 {
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
            retention_paid_through_height: terminal_height + 4,
            retention_charge_paid: 1_000,
        }
    }

    #[test]
    fn public_batch_verifier_rejects_a_valid_root_before_retention_expires() {
        let policy = policy();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &[record(1, 1), record(2, 2), record(3, 3)],
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("valid plan");
        let mut batch = plan.archive_batch().expect("archive batch").clone();
        batch.validate(&policy).expect("positive direct admission");
        verify_task_archive_batch_v1(&policy, &batch).expect("positive public admission");
        batch.seal.archive_height = 3;

        let direct = batch
            .validate(&policy)
            .expect_err("direct admission must enforce prepaid retention too");
        assert_eq!(direct.code(), AgentMarketErrorCodeV1::InvalidState);
        assert!(batch
            .inclusion_proof(&policy, batch.records[0].task_id)
            .is_err());
        let failure = verify_task_archive_batch_v1(&policy, &batch)
            .expect_err("public verifier must enforce prepaid retention");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::InvalidState);
    }

    #[test]
    fn public_inclusion_verifier_rejects_early_archive_height() {
        let policy = policy();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &[record(1, 1), record(2, 2), record(3, 3)],
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("valid plan");
        let batch = plan.archive_batch().expect("archive batch");
        let record = &batch.records[0];
        let proof = batch
            .inclusion_proof(&policy, record.task_id)
            .expect("proof");
        let mut early_seal = batch.seal.clone();
        early_seal.archive_height = record.retention_paid_through_height;
        let mut rebound_proof = proof;
        rebound_proof.seal_hash = early_seal.seal_hash().expect("early seal hash");

        let failure = verify_task_archive_inclusion_v1(&early_seal, record, &rebound_proof)
            .expect_err("early archive proof must fail");
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::InvalidState);
    }

    #[test]
    fn public_verifiers_accept_a_planner_generated_batch() {
        let policy = policy();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &[record(1, 1), record(2, 2), record(3, 3)],
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .expect("valid plan");
        let batch = plan.archive_batch().expect("archive batch");
        verify_task_archive_batch_v1(&policy, batch).expect("batch verifies");
        let record = &batch.records[0];
        let proof = batch
            .inclusion_proof(&policy, record.task_id)
            .expect("proof");
        verify_task_archive_inclusion_v1(&batch.seal, record, &proof).expect("inclusion verifies");
    }
}
